//! Reusable high-level operations for CLI and GUI frontends.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
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
    dex::{Query, ReferenceKind, StringBatchMatcher},
    format_class_name,
    minidex::{MinimalDexStats, extract_minimal_dex_at},
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
    pub engine: DecompilationEngine,
    pub minimal_stats: MinimalDexStats,
    pub timings: DecompileTimings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DecompilationEngine {
    /// The in-process, pure-Rust `dex-decompiler` backend.
    #[default]
    Builtin,
    /// The external JADX command-line backend.
    Jadx,
}

impl DecompilationEngine {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Builtin => "built-in Rust",
            Self::Jadx => "JADX",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecompileOptions {
    pub engine: DecompilationEngine,
    pub mode: DecompilationMode,
    /// Optional JADX executable or launcher path. When omitted, ASC-RS searches
    /// PATH for the platform's usual `jadx` launchers.
    pub jadx_executable: Option<PathBuf>,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self {
            engine: DecompilationEngine::Builtin,
            mode: DecompilationMode::Simple,
            jadx_executable: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct StringReferenceGroup {
    pub pattern: String,
    pub references: Vec<ReferenceLocation>,
}

#[derive(Debug, Clone)]
pub struct BatchDexSearchSummary {
    pub dex_name: String,
    pub classes: usize,
    pub methods: usize,
    /// Number of matching string-table entries for each input pattern.
    pub matched_targets: Vec<usize>,
}

#[derive(Debug)]
pub struct BatchReferenceSearchResult {
    pub groups: Vec<StringReferenceGroup>,
    pub dexes: Vec<BatchDexSearchSummary>,
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
        self.decompile_class_with_options(
            class_name,
            &DecompileOptions {
                mode,
                ..DecompileOptions::default()
            },
        )
    }

    pub fn decompile_class_with_observer(
        &self,
        class_name: &str,
        mode: DecompilationMode,
        observer: &dyn OperationObserver,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_options_and_observer(
            class_name,
            &DecompileOptions {
                mode,
                ..DecompileOptions::default()
            },
            observer,
        )
    }

    pub fn decompile_class_with_options(
        &self,
        class_name: &str,
        options: &DecompileOptions,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_options_and_observer(class_name, options, &NoopObserver)
    }

    pub fn decompile_class_with_options_and_observer(
        &self,
        class_name: &str,
        options: &DecompileOptions,
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
        let minimal = extract_minimal_dex_at(&entry.data, entry.header_offset, &descriptor)
            .with_context(|| format!("failed to extract {descriptor} from {}", entry.name))?;
        let extracted = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Decompiling,
            completed: 0,
            total: 1,
            item: Some(descriptor.clone()),
        });
        let source = decompile_minimal(&entry, &minimal.bytes, &descriptor, options)?;
        let finished = Instant::now();
        check_cancelled(observer)?;
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
            engine: options.engine,
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
        let entries = self.apk.load_all_parsed_dexes()?;
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
                        let dex = &entry.dex;
                        let matched = dex.matching_indices_sorted(query);
                        let sites = dex.scan_reference_sites_sorted(query.kind(), &matched)?;
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

    /// Find references for several string patterns in one pass over each DEX
    /// string table. Results remain grouped in the same order as `patterns`.
    pub fn find_string_references_batch(
        &self,
        patterns: &[String],
    ) -> Result<BatchReferenceSearchResult> {
        self.find_string_references_batch_with_observer(patterns, &NoopObserver)
    }

    pub fn find_string_references_batch_with_observer(
        &self,
        patterns: &[String],
        observer: &dyn OperationObserver,
    ) -> Result<BatchReferenceSearchResult> {
        if patterns.is_empty() {
            bail!("batch string query needs at least one value");
        }
        let started = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: None,
        });
        let entries = self.apk.load_all_parsed_dexes()?;
        let loaded = Instant::now();
        let matcher = StringBatchMatcher::new(patterns)?;
        let total = entries.len();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: total,
            total,
            item: None,
        });
        let completed = AtomicUsize::new(0);
        type DexBatch = (BatchDexSearchSummary, Vec<Vec<ReferenceLocation>>);
        let batches: Vec<Result<DexBatch>> = self.apk.install(|| {
            entries
                .par_iter()
                .map(|entry| {
                    check_cancelled(observer)?;
                    let dex = &entry.dex;
                    let matched = dex.matching_string_indices_batch(&matcher);
                    let mut reference_groups = Vec::with_capacity(matched.len());
                    for targets in &matched {
                        let sites =
                            dex.scan_reference_sites_sorted(ReferenceKind::String, targets)?;
                        let references = sites
                            .into_iter()
                            .map(|site| {
                                Ok(ReferenceLocation {
                                    dex_name: entry.name.clone(),
                                    caller_index: site.caller_index,
                                    caller_method: dex.try_format_method(site.caller_index)?,
                                    code_unit_offset: site.code_unit_offset,
                                    target_index: site.target_index,
                                    target_symbol: dex.try_format_match(
                                        ReferenceKind::String,
                                        site.target_index,
                                    )?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        reference_groups.push(references);
                    }
                    observer.on_progress(&ProgressEvent {
                        stage: OperationStage::Searching,
                        completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                        total,
                        item: Some(entry.name.clone()),
                    });
                    Ok((
                        BatchDexSearchSummary {
                            dex_name: entry.name.clone(),
                            classes: dex.class_count(),
                            methods: dex.method_count(),
                            matched_targets: matched.iter().map(Vec::len).collect(),
                        },
                        reference_groups,
                    ))
                })
                .collect()
        });

        let mut groups = patterns
            .iter()
            .map(|pattern| StringReferenceGroup {
                pattern: pattern.clone(),
                references: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut summaries = Vec::with_capacity(batches.len());
        for batch in batches {
            let (summary, reference_groups) = batch?;
            summaries.push(summary);
            for (group, mut references) in groups.iter_mut().zip(reference_groups) {
                group.references.append(&mut references);
            }
        }
        check_cancelled(observer)?;
        let finished = Instant::now();
        Ok(BatchReferenceSearchResult {
            groups,
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
    options: &DecompileOptions,
) -> Result<String> {
    match options.engine {
        DecompilationEngine::Builtin => {
            decompile_minimal_builtin(entry, bytes, descriptor, options.mode)
        }
        DecompilationEngine::Jadx => decompile_minimal_jadx(
            bytes,
            descriptor,
            options.mode,
            options.jadx_executable.as_deref(),
        ),
    }
}

fn decompile_minimal_builtin(
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

fn decompile_minimal_jadx(
    bytes: &[u8],
    descriptor: &str,
    mode: DecompilationMode,
    executable: Option<&Path>,
) -> Result<String> {
    let workspace = tempfile::tempdir().context("failed to create temporary JADX workspace")?;
    let dex_path = workspace.path().join("class.dex");
    let source_path = workspace.path().join("class.java");
    fs::write(&dex_path, bytes).context("failed to write temporary minimal DEX for JADX")?;

    let class_name = descriptor_to_java(descriptor);
    let arguments = [
        "--single-class".as_ref(),
        class_name.as_ref(),
        "--single-class-output".as_ref(),
        source_path.as_os_str(),
        "--decompilation-mode".as_ref(),
        decompilation_mode_name(mode).as_ref(),
        "--threads-count".as_ref(),
        "1".as_ref(),
        "--no-res".as_ref(),
        "--quiet".as_ref(),
        dex_path.as_os_str(),
    ];
    let output = run_jadx(executable, &arguments).with_context(|| {
        let requested = executable
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "jadx (from PATH)".to_owned());
        format!("failed to launch JADX via {requested}; install JADX or pass --jadx-path <PATH>")
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let diagnostic = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        bail!(
            "JADX exited with {} while decompiling {class_name}: {}",
            output.status,
            tail(diagnostic, 8 * 1024)
        );
    }
    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("JADX did not produce source for {class_name}"))?;
    Ok(source.trim_start_matches('\u{feff}').to_owned())
}

fn decompilation_mode_name(mode: DecompilationMode) -> &'static str {
    match mode {
        DecompilationMode::Restructure => "restructure",
        DecompilationMode::Simple => "simple",
        DecompilationMode::Fallback => "fallback",
    }
}

fn run_jadx(executable: Option<&Path>, arguments: &[&std::ffi::OsStr]) -> std::io::Result<Output> {
    if let Some(executable) = executable {
        return Command::new(executable).args(arguments).output();
    }

    #[cfg(windows)]
    let candidates = ["jadx.exe", "jadx.cmd", "jadx.bat", "jadx"];
    #[cfg(not(windows))]
    let candidates = ["jadx"];

    let mut last_error = None;
    for candidate in candidates {
        match Command::new(candidate).args(arguments).output() {
            Ok(output) => return Ok(output),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "JADX executable not found")
    }))
}

fn tail(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut start = text.len() - max_bytes;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
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
