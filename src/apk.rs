use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use rayon::{ThreadPool, prelude::*};
use zip::ZipArchive;

use crate::dex::class_descriptors;

#[derive(Debug, Clone)]
pub struct DexEntry {
    pub name: String,
    pub data: Arc<[u8]>,
}

#[derive(Debug, Clone)]
pub struct DexInfo {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Debug, Default)]
struct ClassIndex {
    by_descriptor: HashMap<String, usize>,
    indexed_dexes: HashSet<usize>,
}

#[derive(Debug)]
struct DexCache {
    entries: HashMap<usize, Arc<[u8]>>,
    insertion_order: VecDeque<usize>,
    bytes: usize,
    max_bytes: usize,
}

impl DexCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn insert(&mut self, index: usize, data: Arc<[u8]>) -> Arc<[u8]> {
        if let Some(existing) = self.entries.get(&index) {
            return existing.clone();
        }
        self.bytes = self.bytes.saturating_add(data.len());
        self.insertion_order.push_back(index);
        self.entries.insert(index, data.clone());
        while self.bytes > self.max_bytes && self.entries.len() > 1 {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.len());
            }
        }
        data
    }
}

/// Reusable APK state for CLI, GUI, or other long-lived frontends.
pub struct ApkSession {
    path: PathBuf,
    dexes: Vec<DexInfo>,
    pool: ThreadPool,
    cache: Mutex<DexCache>,
    class_index: RwLock<ClassIndex>,
}

fn is_root_dex(name: &str) -> bool {
    if name.contains('/') || name.contains('\\') || !name.ends_with(".dex") {
        return false;
    }
    let stem = &name[..name.len() - 4];
    stem == "classes"
        || stem
            .strip_prefix("classes")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

fn dex_ordinal(name: &str) -> u32 {
    let stem = name.strip_suffix(".dex").unwrap_or(name);
    match stem.strip_prefix("classes") {
        Some("") | None => 1,
        Some(number) => number.parse().unwrap_or(u32::MAX),
    }
}

fn dex_metadata(apk_path: &Path) -> Result<Vec<DexInfo>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to open APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if is_root_dex(entry.name()) {
            entries.push(DexInfo {
                name: entry.name().to_owned(),
                compressed_size: entry.compressed_size(),
                uncompressed_size: entry.size(),
            });
        }
    }
    entries.sort_by_key(|entry| dex_ordinal(&entry.name));
    if entries.is_empty() {
        bail!("APK contains no root classes*.dex entries");
    }
    Ok(entries)
}

fn read_one(apk_path: &Path, info: &DexInfo) -> Result<Arc<[u8]>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to reopen APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entry = archive
        .by_name(&info.name)
        .with_context(|| format!("DEX entry {} disappeared from APK", info.name))?;
    let capacity = usize::try_from(info.uncompressed_size).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("failed to inflate {}", info.name))?;
    Ok(data.into())
}

impl ApkSession {
    pub fn open(apk_path: impl AsRef<Path>, threads: usize) -> Result<Self> {
        Self::open_with_cache_limit(apk_path, threads, 512 * 1024 * 1024)
    }

    /// Open an APK with an explicit upper bound for session-owned decompressed
    /// DEX data. A single DEX larger than the limit is retained while in use.
    pub fn open_with_cache_limit(
        apk_path: impl AsRef<Path>,
        threads: usize,
        max_cached_bytes: usize,
    ) -> Result<Self> {
        ensure!(threads > 0, "worker count must be at least 1");
        let path = apk_path.as_ref().to_owned();
        ensure!(path.is_file(), "APK does not exist: {}", path.display());
        let dexes = dex_metadata(&path)?;
        let workers = threads.min(dexes.len().max(1));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("failed to create DEX worker pool")?;
        Ok(Self {
            path,
            dexes,
            pool,
            cache: Mutex::new(DexCache::new(max_cached_bytes)),
            class_index: RwLock::new(ClassIndex::default()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dex_info(&self) -> &[DexInfo] {
        &self.dexes
    }

    pub fn cached_dex_count(&self) -> usize {
        self.cache
            .lock()
            .map(|cache| cache.entries.len())
            .unwrap_or(0)
    }

    pub fn cached_dex_bytes(&self) -> usize {
        self.cache.lock().map(|cache| cache.bytes).unwrap_or(0)
    }

    pub fn clear_dex_cache(&self) -> Result<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?;
        let max_bytes = cache.max_bytes;
        *cache = DexCache::new(max_bytes);
        Ok(())
    }

    fn load_dex_index(&self, index: usize) -> Result<DexEntry> {
        let info = self
            .dexes
            .get(index)
            .with_context(|| format!("invalid DEX entry index {index}"))?;
        if let Some(data) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .entries
            .get(&index)
            .cloned()
        {
            return Ok(DexEntry {
                name: info.name.clone(),
                data,
            });
        }

        let loaded = read_one(&self.path, info)?;
        let data = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .insert(index, loaded);
        Ok(DexEntry {
            name: info.name.clone(),
            data,
        })
    }

    pub fn load_dex(&self, name: &str) -> Result<DexEntry> {
        let index = self
            .dexes
            .iter()
            .position(|entry| entry.name == name)
            .with_context(|| format!("APK has no root DEX entry named {name}"))?;
        self.load_dex_index(index)
    }

    pub fn load_all_dexes(&self) -> Result<Vec<DexEntry>> {
        let entries: Vec<Result<DexEntry>> = self.pool.install(|| {
            (0..self.dexes.len())
                .into_par_iter()
                .map(|index| self.load_dex_index(index))
                .collect()
        });
        entries.into_iter().collect()
    }

    /// Locate one class without parsing code items from unrelated DEX files.
    /// Subsequent lookups reuse every decompressed and indexed entry.
    pub fn find_class(&self, descriptor: &str) -> Result<Option<DexEntry>> {
        self.find_class_with(descriptor, |_, _| Ok(()))
    }

    pub(crate) fn find_class_with(
        &self,
        descriptor: &str,
        mut indexed: impl FnMut(usize, &str) -> Result<()>,
    ) -> Result<Option<DexEntry>> {
        if let Some(index) = self
            .class_index
            .read()
            .map_err(|_| anyhow!("class index lock was poisoned"))?
            .by_descriptor
            .get(descriptor)
            .copied()
        {
            return self.load_dex_index(index).map(Some);
        }

        for index in 0..self.dexes.len() {
            indexed(index, &self.dexes[index].name)?;
            let already_indexed = self
                .class_index
                .read()
                .map_err(|_| anyhow!("class index lock was poisoned"))?
                .indexed_dexes
                .contains(&index);
            if already_indexed {
                continue;
            }

            let entry = self.load_dex_index(index)?;
            let descriptors = class_descriptors(&entry.data)
                .with_context(|| format!("failed to index {}", entry.name))?;
            let found = descriptors.iter().any(|value| value == descriptor);
            let mut class_index = self
                .class_index
                .write()
                .map_err(|_| anyhow!("class index lock was poisoned"))?;
            for value in descriptors {
                class_index.by_descriptor.entry(value).or_insert(index);
            }
            class_index.indexed_dexes.insert(index);
            if found {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    pub(crate) fn install<R: Send>(&self, operation: impl FnOnce() -> R + Send) -> R {
        self.pool.install(operation)
    }
}

pub fn read_entry(apk_path: &Path, name: &str) -> Result<Vec<u8>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to open APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entry = archive
        .by_name(name)
        .with_context(|| format!("APK has no {name} entry"))?;
    let capacity = usize::try_from(entry.size()).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("failed to inflate {name}"))?;
    Ok(data)
}

/// Compatibility helper for one-shot callers. Long-lived clients should keep
/// an `ApkSession` so decompressed bytes and class indexes can be reused.
pub fn load_dexes(apk_path: &Path, threads: usize) -> Result<Vec<DexEntry>> {
    ApkSession::open(apk_path, threads)?.load_all_dexes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_root_dex_names() {
        assert!(is_root_dex("classes.dex"));
        assert!(is_root_dex("classes2.dex"));
        assert!(!is_root_dex("assets/classes.dex"));
        assert!(!is_root_dex("classesx.dex"));
    }

    #[test]
    fn bounds_session_owned_dex_cache() {
        let mut cache = DexCache::new(6);
        let first: Arc<[u8]> = vec![1; 4].into();
        let second: Arc<[u8]> = vec![2; 4].into();
        cache.insert(0, first);
        cache.insert(1, second);
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.entries.contains_key(&1));
        assert_eq!(cache.bytes, 4);
    }
}
