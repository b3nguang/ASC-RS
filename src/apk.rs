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

use crate::dex::{Dex, class_descriptors};

#[derive(Debug, Clone)]
pub struct DexEntry {
    pub name: String,
    pub data: Arc<[u8]>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedDexEntry {
    pub name: String,
    pub dex: Arc<Dex>,
}

#[derive(Debug, Clone)]
pub struct DexInfo {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkEntryInfo {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkClassInfo {
    pub dex_name: String,
    pub descriptor: String,
}

#[derive(Debug, Default)]
struct ClassIndex {
    by_descriptor: HashMap<String, usize>,
    indexed_dexes: HashSet<usize>,
}

#[derive(Debug)]
struct CachedDex {
    data: Arc<[u8]>,
    parsed: Option<Arc<Dex>>,
}

#[derive(Debug)]
struct DexCache {
    entries: HashMap<usize, CachedDex>,
    lru_order: VecDeque<usize>,
    bytes: usize,
    max_bytes: usize,
}

impl DexCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn touch(&mut self, index: usize) {
        self.lru_order.retain(|&cached| cached != index);
        self.lru_order.push_back(index);
    }

    fn get_data(&mut self, index: usize) -> Option<Arc<[u8]>> {
        let data = self.entries.get(&index)?.data.clone();
        self.touch(index);
        Some(data)
    }

    fn get_parsed(&mut self, index: usize) -> Option<Arc<Dex>> {
        let parsed = self.entries.get(&index)?.parsed.clone()?;
        self.touch(index);
        Some(parsed)
    }

    fn insert_data(&mut self, index: usize, data: Arc<[u8]>) -> Arc<[u8]> {
        if let Some(existing) = self.entries.get(&index).map(|entry| entry.data.clone()) {
            self.touch(index);
            return existing;
        }
        self.bytes = self.bytes.saturating_add(data.len());
        self.touch(index);
        self.entries.insert(
            index,
            CachedDex {
                data: data.clone(),
                parsed: None,
            },
        );
        while self.bytes > self.max_bytes && self.entries.len() > 1 {
            let Some(oldest) = self.lru_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.data.len());
            }
        }
        data
    }

    fn insert_parsed(&mut self, index: usize, data: Arc<[u8]>, parsed: Arc<Dex>) -> Arc<Dex> {
        self.insert_data(index, data);
        if let Some(existing) = self.entries[&index].parsed.clone() {
            return existing;
        }
        self.entries
            .get_mut(&index)
            .expect("newly inserted DEX must remain cached")
            .parsed = Some(parsed.clone());
        parsed
    }
}

/// Reusable APK state for CLI, GUI, or other long-lived frontends.
pub struct ApkSession {
    path: PathBuf,
    dexes: Vec<DexInfo>,
    pool: ThreadPool,
    cache: Mutex<DexCache>,
    load_locks: Vec<Mutex<()>>,
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
        let load_locks = (0..dexes.len()).map(|_| Mutex::new(())).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("failed to create DEX worker pool")?;
        Ok(Self {
            path,
            dexes,
            pool,
            cache: Mutex::new(DexCache::new(max_cached_bytes)),
            load_locks,
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

    pub fn cached_parsed_dex_count(&self) -> usize {
        self.cache
            .lock()
            .map(|cache| {
                cache
                    .entries
                    .values()
                    .filter(|entry| entry.parsed.is_some())
                    .count()
            })
            .unwrap_or(0)
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
            .get_data(index)
        {
            return Ok(DexEntry {
                name: info.name.clone(),
                data,
            });
        }

        let _load_guard = self.load_locks[index]
            .lock()
            .map_err(|_| anyhow!("DEX load lock was poisoned"))?;
        if let Some(data) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .get_data(index)
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
            .insert_data(index, loaded);
        Ok(DexEntry {
            name: info.name.clone(),
            data,
        })
    }

    fn load_parsed_dex_index(&self, index: usize) -> Result<ParsedDexEntry> {
        let info = self
            .dexes
            .get(index)
            .with_context(|| format!("invalid DEX entry index {index}"))?;
        if let Some(dex) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .get_parsed(index)
        {
            return Ok(ParsedDexEntry {
                name: info.name.clone(),
                dex,
            });
        }

        // The per-entry barrier prevents concurrent UI/service queries from
        // inflating and parsing the same DEX more than once.
        let _load_guard = self.load_locks[index]
            .lock()
            .map_err(|_| anyhow!("DEX load lock was poisoned"))?;
        if let Some(dex) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .get_parsed(index)
        {
            return Ok(ParsedDexEntry {
                name: info.name.clone(),
                dex,
            });
        }

        let cached_data = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("DEX cache lock was poisoned"))?;
            cache.get_data(index)
        };
        let data = match cached_data {
            Some(data) => data,
            None => {
                let loaded = read_one(&self.path, info)?;
                self.cache
                    .lock()
                    .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
                    .insert_data(index, loaded)
            }
        };
        let parsed = Arc::new(
            Dex::parse_shared(data.clone())
                .with_context(|| format!("failed to parse {}", info.name))?,
        );
        let dex = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .insert_parsed(index, data, parsed);
        Ok(ParsedDexEntry {
            name: info.name.clone(),
            dex,
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

    /// List every class definition across root `classes*.dex` entries while
    /// preserving DEX and class-table order.
    pub fn list_classes(&self) -> Result<Vec<ApkClassInfo>> {
        let entries = self.load_all_dexes()?;
        let batches: Vec<Result<Vec<ApkClassInfo>>> = self.pool.install(|| {
            entries
                .par_iter()
                .map(|entry| {
                    class_descriptors(&entry.data)
                        .with_context(|| format!("failed to list classes in {}", entry.name))
                        .map(|descriptors| {
                            descriptors
                                .into_iter()
                                .map(|descriptor| ApkClassInfo {
                                    dex_name: entry.name.clone(),
                                    descriptor,
                                })
                                .collect()
                        })
                })
                .collect()
        });
        let mut classes = Vec::new();
        for batch in batches {
            classes.extend(batch?);
        }
        Ok(classes)
    }

    pub(crate) fn load_all_parsed_dexes(&self) -> Result<Vec<ParsedDexEntry>> {
        let entries: Vec<Result<ParsedDexEntry>> = self.pool.install(|| {
            (0..self.dexes.len())
                .into_par_iter()
                .map(|index| self.load_parsed_dex_index(index))
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

/// List all ZIP entries in deterministic name order without inflating them.
pub fn list_entries(apk_path: &Path) -> Result<Vec<ApkEntryInfo>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to open APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        entries.push(ApkEntryInfo {
            name: entry.name().to_owned(),
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            is_directory: entry.is_dir(),
        });
    }
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

pub fn read_entry(apk_path: &Path, name: &str) -> Result<Vec<u8>> {
    read_entry_range(apk_path, name, 0, None)
}

/// Inflate a bounded byte range from one APK entry. Offset and length are
/// measured in uncompressed bytes.
pub fn read_entry_range(
    apk_path: &Path,
    name: &str,
    offset: u64,
    length: Option<u64>,
) -> Result<Vec<u8>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to open APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entry = archive
        .by_name(name)
        .with_context(|| format!("APK has no {name} entry"))?;
    let entry_size = entry.size();
    ensure!(
        offset <= entry_size,
        "entry range starts at {offset}, past the {entry_size}-byte end of {name}"
    );
    let available = entry_size - offset;
    let selected = length.unwrap_or(available);
    ensure!(
        selected <= available,
        "entry range length {selected} exceeds the {available} bytes available at offset {offset} in {name}"
    );

    let mut remaining = offset;
    let mut discard = [0u8; 16 * 1024];
    while remaining > 0 {
        let chunk = usize::try_from(remaining.min(discard.len() as u64)).unwrap();
        let read = entry
            .read(&mut discard[..chunk])
            .with_context(|| format!("failed to seek to byte {offset} in {name}"))?;
        ensure!(read > 0, "unexpected end of {name} before byte {offset}");
        remaining -= read as u64;
    }

    let capacity = usize::try_from(selected).context("selected APK entry range is too large")?;
    let mut data = Vec::with_capacity(capacity);
    entry
        .take(selected)
        .read_to_end(&mut data)
        .with_context(|| format!("failed to inflate bytes {offset}.. from {name}"))?;
    ensure!(
        data.len() as u64 == selected,
        "unexpected end of {name} while reading {selected} bytes at offset {offset}"
    );
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
    use std::{
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TempApk(PathBuf);

    impl Drop for TempApk {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn empty_dex_apk() -> TempApk {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "asc-rs-cache-test-{}-{unique}.apk",
            std::process::id()
        ));
        let file = File::create(&path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("classes.dex", zip::write::FileOptions::default())
            .unwrap();
        let mut dex = vec![0; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        archive.write_all(&dex).unwrap();
        archive
            .start_file("assets/sample.bin", zip::write::FileOptions::default())
            .unwrap();
        archive.write_all(b"0123456789").unwrap();
        archive.finish().unwrap();
        TempApk(path)
    }

    #[test]
    fn recognizes_root_dex_names() {
        assert!(is_root_dex("classes.dex"));
        assert!(is_root_dex("classes2.dex"));
        assert!(!is_root_dex("assets/classes.dex"));
        assert!(!is_root_dex("classesx.dex"));
    }

    #[test]
    fn lists_and_reads_bounded_apk_entries() {
        let apk = empty_dex_apk();
        assert_eq!(
            list_entries(&apk.0)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            vec!["assets/sample.bin", "classes.dex"]
        );
        assert_eq!(
            read_entry_range(&apk.0, "assets/sample.bin", 3, Some(4)).unwrap(),
            b"3456"
        );
        assert!(
            read_entry_range(&apk.0, "assets/sample.bin", 8, Some(3))
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn bounds_session_owned_dex_cache() {
        let mut cache = DexCache::new(6);
        let first: Arc<[u8]> = vec![1; 4].into();
        let second: Arc<[u8]> = vec![2; 4].into();
        cache.insert_data(0, first);
        cache.insert_data(1, second);
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.entries.contains_key(&1));
        assert_eq!(cache.bytes, 4);
    }

    #[test]
    fn dex_cache_evicts_the_least_recently_used_entry() {
        let mut cache = DexCache::new(6);
        cache.insert_data(0, vec![0; 3].into());
        cache.insert_data(1, vec![1; 3].into());
        assert!(cache.get_data(0).is_some());
        cache.insert_data(2, vec![2; 3].into());
        assert!(cache.entries.contains_key(&0));
        assert!(!cache.entries.contains_key(&1));
        assert!(cache.entries.contains_key(&2));
    }

    #[test]
    fn concurrent_queries_share_one_parsed_dex() {
        let apk = empty_dex_apk();
        let session = ApkSession::open(&apk.0, 4).unwrap();
        let parsed = std::thread::scope(|scope| {
            let handles = (0..4)
                .map(|_| scope.spawn(|| session.load_all_parsed_dexes().unwrap().remove(0).dex))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(parsed[1..].iter().all(|dex| Arc::ptr_eq(&parsed[0], dex)));
        assert_eq!(session.cached_parsed_dex_count(), 1);
    }
}
