//! Reusable high-level operations for CLI and GUI frontends.

use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use axml_parser::AXMLPrinter;
pub use dex_decompiler::DecompilationMode;
use dex_decompiler::{Decompiler, DecompilerOptions, parse_dex};
use rayon::prelude::*;

use crate::{
    apk::{ApkSession, DexEntry},
    descriptor_to_java,
    dex::{Dex, Query},
    format_class_name,
    minidex::{MinimalDexStats, extract_minimal_dex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStage {
    Loading,
    Indexing,
    Extracting,
    Decompiling,
    Searching,
    Manifest,
}

#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub stage: OperationStage,
    pub completed: usize,
    pub total: usize,
    pub item: Option<String>,
}

/// Frontends can implement this trait to receive progress and cancel work at
/// stable service boundaries. Callbacks may arrive from worker threads.
pub trait OperationObserver: Sync {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn on_progress(&self, _event: &ProgressEvent) {}
}

struct NoopObserver;

impl OperationObserver for NoopObserver {}

fn check_cancelled(observer: &dyn OperationObserver) -> Result<()> {
    if observer.is_cancelled() {
        bail!("operation cancelled");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecompileTimings {
    pub locate_ms: f64,
    pub extract_ms: f64,
    pub decompile_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct DecompileResult {
    pub source: String,
    pub descriptor: String,
    pub dex_name: String,
    pub minimal_stats: MinimalDexStats,
    pub timings: DecompileTimings,
}

#[derive(Debug, Clone)]
pub struct ReferenceLocation {
    pub dex_name: String,
    pub caller_index: u32,
    pub caller_method: String,
    pub code_unit_offset: u32,
    pub target_index: u32,
    pub target_symbol: String,
}

#[derive(Debug, Clone)]
pub struct DexSearchSummary {
    pub dex_name: String,
    pub classes: usize,
    pub methods: usize,
    pub matched_targets: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SearchTimings {
    pub load_ms: f64,
    pub scan_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct ReferenceSearchResult {
    pub references: Vec<ReferenceLocation>,
    pub dexes: Vec<DexSearchSummary>,
    pub timings: SearchTimings,
}

pub struct AscSession {
    apk: ApkSession,
}

impl AscSession {
    pub fn open(apk_path: impl AsRef<Path>, threads: usize) -> Result<Self> {
        Ok(Self {
            apk: ApkSession::open(apk_path, threads)?,
        })
    }

    pub fn open_with_cache_limit(
        apk_path: impl AsRef<Path>,
        threads: usize,
        max_cached_bytes: usize,
    ) -> Result<Self> {
        Ok(Self {
            apk: ApkSession::open_with_cache_limit(apk_path, threads, max_cached_bytes)?,
        })
    }

    pub fn apk(&self) -> &ApkSession {
        &self.apk
    }

    pub fn decode_manifest(&self, pretty: bool) -> Result<String> {
        decode_manifest_with_observer(self.apk.path(), pretty, &NoopObserver)
    }

    pub fn decode_manifest_with_observer(
        &self,
        pretty: bool,
        observer: &dyn OperationObserver,
    ) -> Result<String> {
        decode_manifest_with_observer(self.apk.path(), pretty, observer)
    }

    pub fn decompile_class(
        &self,
        class_name: &str,
        mode: DecompilationMode,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_observer(class_name, mode, &NoopObserver)
    }

    pub fn decompile_class_with_observer(
        &self,
        class_name: &str,
        mode: DecompilationMode,
        observer: &dyn OperationObserver,
    ) -> Result<DecompileResult> {
        let started = Instant::now();
        let descriptor = format_class_name(class_name)?;
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Indexing,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: Some(descriptor.clone()),
        });
        let entry = self
            .apk
            .find_class_with(&descriptor, |index, name| {
                check_cancelled(observer)?;
                observer.on_progress(&ProgressEvent {
                    stage: OperationStage::Indexing,
                    completed: index,
                    total: self.apk.dex_info().len(),
                    item: Some(name.to_owned()),
                });
                Ok(())
            })?
            .with_context(|| format!("class {descriptor} not found in APK"))?;
        let located = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Extracting,
            completed: 0,
            total: 1,
            item: Some(entry.name.clone()),
        });
        let minimal = extract_minimal_dex(&entry.data, &descriptor)
            .with_context(|| format!("failed to extract {descriptor} from {}", entry.name))?;
        let extracted = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Decompiling,
            completed: 0,
            total: 1,
            item: Some(descriptor.clone()),
        });
        let source = decompile_minimal(&entry, &minimal.bytes, &descriptor, mode)?;
        let finished = Instant::now();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Decompiling,
            completed: 1,
            total: 1,
            item: Some(descriptor.clone()),
        });
        Ok(DecompileResult {
            source,
            descriptor,
            dex_name: entry.name,
            minimal_stats: minimal.stats,
            timings: DecompileTimings {
                locate_ms: (located - started).as_secs_f64() * 1000.0,
                extract_ms: (extracted - located).as_secs_f64() * 1000.0,
                decompile_ms: (finished - extracted).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }

    pub fn find_references(&self, query: &Query) -> Result<ReferenceSearchResult> {
        self.find_references_with_observer(query, &NoopObserver)
    }

    pub fn find_references_with_observer(
        &self,
        query: &Query,
        observer: &dyn OperationObserver,
    ) -> Result<ReferenceSearchResult> {
        let started = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: None,
        });
        let entries = self.apk.load_all_dexes()?;
        let loaded = Instant::now();
        let total = entries.len();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: total,
            total,
            item: None,
        });
        let completed = AtomicUsize::new(0);
        let batches: Vec<Result<(DexSearchSummary, Vec<ReferenceLocation>)>> =
            self.apk.install(|| {
                entries
                    .par_iter()
                    .map(|entry| {
                        check_cancelled(observer)?;
                        let dex = Dex::parse(&entry.data)
                            .with_context(|| format!("failed to parse {}", entry.name))?;
                        let matched = dex.matching_indices(query);
                        let sites = dex.scan_reference_sites(query.kind(), &matched)?;
                        let references = sites
                            .into_iter()
                            .map(|site| {
                                Ok(ReferenceLocation {
                                    dex_name: entry.name.clone(),
                                    caller_index: site.caller_index,
                                    caller_method: dex.try_format_method(site.caller_index)?,
                                    code_unit_offset: site.code_unit_offset,
                                    target_index: site.target_index,
                                    target_symbol: dex
                                        .try_format_match(query.kind(), site.target_index)?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        observer.on_progress(&ProgressEvent {
                            stage: OperationStage::Searching,
                            completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                            total,
                            item: Some(entry.name.clone()),
                        });
                        Ok((
                            DexSearchSummary {
                                dex_name: entry.name.clone(),
                                classes: dex.class_count(),
                                methods: dex.method_count(),
                                matched_targets: matched.len(),
                            },
                            references,
                        ))
                    })
                    .collect()
            });
        let mut summaries = Vec::with_capacity(batches.len());
        let mut references = Vec::new();
        for batch in batches {
            let (summary, mut locations) = batch?;
            summaries.push(summary);
            references.append(&mut locations);
        }
        check_cancelled(observer)?;
        let finished = Instant::now();
        Ok(ReferenceSearchResult {
            references,
            dexes: summaries,
            timings: SearchTimings {
                load_ms: (loaded - started).as_secs_f64() * 1000.0,
                scan_ms: (finished - loaded).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }
}

pub fn decode_manifest(apk_path: impl AsRef<Path>, pretty: bool) -> Result<String> {
    decode_manifest_with_observer(apk_path, pretty, &NoopObserver)
}

pub fn decode_manifest_with_observer(
    apk_path: impl AsRef<Path>,
    pretty: bool,
    observer: &dyn OperationObserver,
) -> Result<String> {
    check_cancelled(observer)?;
    observer.on_progress(&ProgressEvent {
        stage: OperationStage::Manifest,
        completed: 0,
        total: 1,
        item: Some("AndroidManifest.xml".to_owned()),
    });
    let data = crate::apk::read_entry(apk_path.as_ref(), "AndroidManifest.xml")?;
    let printer = AXMLPrinter::new(&data);
    anyhow::ensure!(
        printer.is_valid(),
        "AndroidManifest.xml is not valid binary AXML"
    );
    let xml = String::from_utf8(printer.get_xml(pretty))
        .context("decoded AndroidManifest.xml is not UTF-8")?;
    check_cancelled(observer)?;
    observer.on_progress(&ProgressEvent {
        stage: OperationStage::Manifest,
        completed: 1,
        total: 1,
        item: Some("AndroidManifest.xml".to_owned()),
    });
    Ok(xml)
}

fn decompile_minimal(
    entry: &DexEntry,
    bytes: &[u8],
    descriptor: &str,
    mode: DecompilationMode,
) -> Result<String> {
    let parsed = parse_dex(bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("Androguard dex-parser rejected rebuilt {}", entry.name))?;
    for class_def in parsed.class_defs() {
        let class_def = class_def
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("failed to read class definition")?;
        let class_type = parsed
            .get_type(class_def.class_idx)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("failed to resolve class descriptor")?;
        if class_type != descriptor {
            continue;
        }
        let options = DecompilerOptions {
            mode,
            resource_map: Some(Default::default()),
            ..DecompilerOptions::default()
        };
        let decompiler = Decompiler::with_options(&parsed, options);
        let mut source = decompiler
            .decompile_class(&class_def)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("failed to decompile {}", descriptor_to_java(descriptor)))?;

        if let Some(class_data) = parsed
            .get_class_data(&class_def)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
        {
            let class_name = descriptor_to_java(descriptor);
            let simple_name = class_name.rsplit('.').next().unwrap_or(&class_name);
            let mut restored = String::new();
            for method in class_data
                .direct_methods
                .iter()
                .chain(class_data.virtual_methods.iter())
            {
                let info = parsed
                    .get_method_info(method.method_idx)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let hidden = method.access_flags & 0x40 != 0
                    || (info.name.starts_with("access$") && method.access_flags & 0x1000 != 0)
                    || info.name.starts_with("$r8$lambda$");
                if hidden {
                    restored.push_str(
                        &decompiler
                            .decompile_method(method, Some(simple_name), Some(&class_name))
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                    );
                }
            }
            if !restored.is_empty() {
                let insert_at = source.rfind("\n}").unwrap_or(source.len());
                restored.insert(0, '\n');
                source.insert_str(insert_at, &restored);
            }
        }
        return Ok(repair_double_encoded_utf8(source));
    }
    bail!("class {descriptor} was located but dex-decompiler could not resolve it")
}

fn repair_double_encoded_utf8(mut text: String) -> String {
    for _ in 0..2 {
        let suspicious_before = text
            .chars()
            .filter(|ch| ('\u{80}'..='\u{ff}').contains(ch))
            .count();
        if suspicious_before == 0 || !text.chars().all(|ch| u32::from(ch) <= 0xff) {
            break;
        }
        let bytes: Vec<u8> = text.chars().map(|ch| ch as u8).collect();
        let Ok(candidate) = String::from_utf8(bytes) else {
            break;
        };
        let suspicious_after = candidate
            .chars()
            .filter(|ch| ('\u{80}'..='\u{ff}').contains(ch))
            .count();
        if suspicious_after >= suspicious_before {
            break;
        }
        text = candidate;
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cancelled;

    impl OperationObserver for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_is_checked_before_io() {
        let error = decode_manifest_with_observer("missing.apk", true, &Cancelled).unwrap_err();
        assert_eq!(error.to_string(), "operation cancelled");
    }
}
