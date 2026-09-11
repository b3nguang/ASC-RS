use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::read::DeflateDecoder;
use memmap2::{Mmap, MmapOptions};
use rayon::{ThreadPool, prelude::*};
use zip::{CompressionMethod, ZipArchive};

use crate::{
    dex::{Dex, class_descriptors_at, dex_defines_class_at},
    dex_container::logical_dexes,
};

#[derive(Debug, Clone)]
pub struct DexEntry {
    pub name: String,
    pub data: Arc<[u8]>,
    /// Offset of this logical DEX header in `data`. This is zero for ordinary
    /// DEX files and may be non-zero for a DEX 041 container.
    pub header_offset: usize,
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
    data_start: u64,
    compression: CompressionMethod,
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
    by_descriptor: HashMap<String, LogicalDexLocation>,
}

#[derive(Debug, Clone, Copy)]
struct LogicalDexLocation {
    physical_index: usize,
    header_offset: usize,
}

#[derive(Debug)]
struct CachedDex {
    data: Arc<[u8]>,
    parsed: Option<Arc<[ParsedDexEntry]>>,
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

    fn get_parsed(&mut self, index: usize) -> Option<Arc<[ParsedDexEntry]>> {
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

    fn insert_parsed(
        &mut self,
        index: usize,
        data: Arc<[u8]>,
        parsed: Arc<[ParsedDexEntry]>,
    ) -> Arc<[ParsedDexEntry]> {
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
    apk_data: Arc<Mmap>,
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

const CENTRAL_DIRECTORY_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const LOCAL_HEADER_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const EOCD_SIZE: usize = 22;
const MAX_ZIP_COMMENT_SIZE: usize = u16::MAX as usize;

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(EOCD_SIZE + MAX_ZIP_COMMENT_SIZE);
    let latest_start = data.len().checked_sub(EOCD_SIZE)?;
    (search_start..=latest_start).rev().find(|&offset| {
        data.get(offset..offset + 4) == Some(EOCD_SIGNATURE)
            && read_u16(data, offset + 20).is_some_and(|comment_size| {
                offset.checked_add(EOCD_SIZE + usize::from(comment_size)) == Some(data.len())
            })
    })
}

/// Read root DEX metadata directly from the mapped ZIP central directory.
/// `None` requests the ZipArchive fallback for ZIP64 metadata.
fn dex_metadata_from_mmap(apk_data: &[u8]) -> Result<Option<Vec<DexInfo>>> {
    let eocd = find_eocd(apk_data).context("ZIP end-of-central-directory record not found")?;
    let disk = read_u16(apk_data, eocd + 4).context("truncated ZIP end record")?;
    let central_disk = read_u16(apk_data, eocd + 6).context("truncated ZIP end record")?;
    ensure!(
        disk == 0 && central_disk == 0,
        "multi-disk ZIP/APK archives are not supported"
    );

    let disk_entries = read_u16(apk_data, eocd + 8).context("truncated ZIP end record")?;
    let total_entries = read_u16(apk_data, eocd + 10).context("truncated ZIP end record")?;
    let central_size = read_u32(apk_data, eocd + 12).context("truncated ZIP end record")?;
    let central_offset = read_u32(apk_data, eocd + 16).context("truncated ZIP end record")?;
    if disk_entries == u16::MAX
        || total_entries == u16::MAX
        || central_size == u32::MAX
        || central_offset == u32::MAX
    {
        return Ok(None);
    }
    ensure!(
        disk_entries == total_entries,
        "split ZIP central directories are not supported"
    );

    let central_start = usize::try_from(central_offset).unwrap();
    let central_end = central_start
        .checked_add(usize::try_from(central_size).unwrap())
        .context("ZIP central-directory range overflow")?;
    ensure!(
        central_end <= eocd && central_end <= apk_data.len(),
        "ZIP central directory is outside the APK"
    );

    let mut entries = Vec::new();
    let mut seen_names = HashSet::new();
    let mut cursor = central_start;
    for _ in 0..total_entries {
        ensure!(
            apk_data.get(cursor..cursor + 4) == Some(CENTRAL_DIRECTORY_SIGNATURE),
            "bad ZIP central-directory signature at offset {cursor}"
        );
        ensure!(
            cursor.checked_add(46).is_some_and(|end| end <= central_end),
            "truncated ZIP central-directory entry at offset {cursor}"
        );

        let name_size = usize::from(read_u16(apk_data, cursor + 28).unwrap());
        let extra_size = usize::from(read_u16(apk_data, cursor + 30).unwrap());
        let comment_size = usize::from(read_u16(apk_data, cursor + 32).unwrap());
        let name_start = cursor + 46;
        let name_end = name_start
            .checked_add(name_size)
            .context("ZIP entry-name range overflow")?;
        let entry_end = name_end
            .checked_add(extra_size)
            .and_then(|end| end.checked_add(comment_size))
            .context("ZIP central-directory entry range overflow")?;
        ensure!(
            entry_end <= central_end,
            "ZIP central-directory entry exceeds its declared size"
        );

        let name_bytes = &apk_data[name_start..name_end];
        let name = std::str::from_utf8(name_bytes).unwrap_or_default();
        if is_root_dex(name) && seen_names.insert(name.to_owned()) {
            let compressed_size = read_u32(apk_data, cursor + 20).unwrap();
            let uncompressed_size = read_u32(apk_data, cursor + 24).unwrap();
            let local_offset = read_u32(apk_data, cursor + 42).unwrap();
            if compressed_size == u32::MAX
                || uncompressed_size == u32::MAX
                || local_offset == u32::MAX
            {
                return Ok(None);
            }

            let local_offset = usize::try_from(local_offset).unwrap();
            ensure!(
                apk_data.get(local_offset..local_offset + 4) == Some(LOCAL_HEADER_SIGNATURE),
                "bad local ZIP header signature for {name}"
            );
            ensure!(
                local_offset
                    .checked_add(30)
                    .is_some_and(|end| end <= apk_data.len()),
                "truncated local ZIP header for {name}"
            );
            let local_name_size = usize::from(read_u16(apk_data, local_offset + 26).unwrap());
            let local_extra_size = usize::from(read_u16(apk_data, local_offset + 28).unwrap());
            let data_start = local_offset
                .checked_add(30)
                .and_then(|start| start.checked_add(local_name_size))
                .and_then(|start| start.checked_add(local_extra_size))
                .context("local ZIP entry range overflow")?;
            let data_end = data_start
                .checked_add(usize::try_from(compressed_size).unwrap())
                .context("compressed DEX range overflow")?;
            ensure!(
                data_end <= apk_data.len(),
                "compressed data for {name} is outside the APK"
            );

            #[allow(deprecated)]
            let compression = CompressionMethod::from_u16(read_u16(apk_data, cursor + 10).unwrap());
            entries.push(DexInfo {
                name: name.to_owned(),
                compressed_size: u64::from(compressed_size),
                uncompressed_size: u64::from(uncompressed_size),
                data_start: data_start as u64,
                compression,
            });
        }
        cursor = entry_end;
    }
    entries.sort_by_key(|entry| dex_ordinal(&entry.name));
    ensure!(
        !entries.is_empty(),
        "APK contains no root classes*.dex entries"
    );
    Ok(Some(entries))
}

fn dex_metadata_with_zip(apk_path: &Path) -> Result<Vec<DexInfo>> {
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
                data_start: entry.data_start(),
                compression: entry.compression(),
            });
        }
    }
    entries.sort_by_key(|entry| dex_ordinal(&entry.name));
    if entries.is_empty() {
        bail!("APK contains no root classes*.dex entries");
    }
    Ok(entries)
}

fn dex_metadata(apk_path: &Path, apk_data: &[u8]) -> Result<Vec<DexInfo>> {
    dex_metadata_from_mmap(apk_data)?.map_or_else(|| dex_metadata_with_zip(apk_path), Ok)
}

fn read_one(
    apk_data: &[u8],
    info: &DexInfo,
    stop: Option<&AtomicBool>,
) -> Result<Option<Arc<[u8]>>> {
    if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Ok(None);
    }
    let data_start = usize::try_from(info.data_start).context("DEX data offset is too large")?;
    let compressed_size =
        usize::try_from(info.compressed_size).context("compressed DEX is too large")?;
    let data_end = data_start
        .checked_add(compressed_size)
        .context("compressed DEX range overflow")?;
    let compressed = apk_data
        .get(data_start..data_end)
        .with_context(|| format!("compressed data for {} is outside the APK", info.name))?;
    let capacity = usize::try_from(info.uncompressed_size).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    match info.compression {
        CompressionMethod::Stored => data.extend_from_slice(compressed),
        CompressionMethod::Deflated => {
            let mut decoder = DeflateDecoder::new(compressed);
            let mut chunk = vec![0u8; 1 << 19];
            loop {
                if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    return Ok(None);
                }
                let count = decoder
                    .read(&mut chunk)
                    .with_context(|| format!("failed to inflate {}", info.name))?;
                if count == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..count]);
            }
        }
        method => bail!(
            "unsupported compression method {method:?} for {}",
            info.name
        ),
    }
    ensure!(
        data.len() as u64 == info.uncompressed_size,
        "inflated size mismatch for {}: expected {}, got {}",
        info.name,
        info.uncompressed_size,
        data.len()
    );
    Ok(Some(data.into()))
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
        let apk_file =
            File::open(&path).with_context(|| format!("failed to open APK {}", path.display()))?;
        // SAFETY: the mapping is read-only and retained for the session's
        // lifetime. This mirrors the original ASC ApkHandler's read-only mmap.
        let apk_data = unsafe { MmapOptions::new().map(&apk_file) }
            .with_context(|| format!("failed to memory-map APK {}", path.display()))?;
        let dexes = dex_metadata(&path, &apk_data)?;
        let workers = threads.min(dexes.len().max(1));
        let load_locks = (0..dexes.len()).map(|_| Mutex::new(())).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("failed to create DEX worker pool")?;
        Ok(Self {
            path,
            apk_data: Arc::new(apk_data),
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
                    .filter_map(|entry| entry.parsed.as_ref())
                    .map(|entries| entries.len())
                    .sum()
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
        Ok(self
            .load_dex_index_with_stop(index, None)?
            .expect("uncancelled DEX inflation must return an entry"))
    }

    fn load_dex_index_with_stop(
        &self,
        index: usize,
        stop: Option<&AtomicBool>,
    ) -> Result<Option<DexEntry>> {
        let info = self
            .dexes
            .get(index)
            .with_context(|| format!("invalid DEX entry index {index}"))?;
        if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Ok(None);
        }
        if let Some(data) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .get_data(index)
        {
            return Ok(Some(DexEntry {
                name: info.name.clone(),
                data,
                header_offset: 0,
            }));
        }

        let _load_guard = self.load_locks[index]
            .lock()
            .map_err(|_| anyhow!("DEX load lock was poisoned"))?;
        if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Ok(None);
        }
        if let Some(data) = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .get_data(index)
        {
            return Ok(Some(DexEntry {
                name: info.name.clone(),
                data,
                header_offset: 0,
            }));
        }
        let Some(loaded) = read_one(&self.apk_data, info, stop)? else {
            return Ok(None);
        };
        let data = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .insert_data(index, loaded);
        Ok(Some(DexEntry {
            name: info.name.clone(),
            data,
            header_offset: 0,
        }))
    }

    fn load_parsed_dex_index(&self, index: usize) -> Result<Arc<[ParsedDexEntry]>> {
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
            return Ok(dex);
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
            return Ok(dex);
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
                let loaded = read_one(&self.apk_data, info, None)?
                    .expect("uncancelled DEX inflation must return data");
                self.cache
                    .lock()
                    .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
                    .insert_data(index, loaded)
            }
        };
        let parsed = logical_dexes(&info.name, &data)?
            .into_iter()
            .map(|logical| {
                Ok(ParsedDexEntry {
                    name: logical.name,
                    dex: Arc::new(
                        Dex::parse_shared_at(data.clone(), logical.header_offset)
                            .with_context(|| format!("failed to parse {}", info.name))?,
                    ),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let dexes = self
            .cache
            .lock()
            .map_err(|_| anyhow!("DEX cache lock was poisoned"))?
            .insert_parsed(index, data, parsed.into());
        Ok(dexes)
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
                    let mut classes = Vec::new();
                    for logical in logical_dexes(&entry.name, &entry.data)? {
                        let descriptors = class_descriptors_at(&entry.data, logical.header_offset)
                            .with_context(|| {
                                format!("failed to list classes in {}", logical.name)
                            })?;
                        classes.extend(descriptors.into_iter().map(|descriptor| ApkClassInfo {
                            dex_name: logical.name.clone(),
                            descriptor,
                        }));
                    }
                    Ok(classes)
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
        let mut order = (0..self.dexes.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|&index| self.dexes[index].compressed_size);
        let entries: Vec<Result<Arc<[ParsedDexEntry]>>> = self.pool.install(|| {
            order
                .into_par_iter()
                .map(|index| self.load_parsed_dex_index(index))
                .collect()
        });
        let mut logical_entries = Vec::new();
        for entry in entries {
            logical_entries.extend(entry?.iter().cloned());
        }
        Ok(logical_entries)
    }

    /// Locate one class without parsing code items from unrelated DEX files.
    /// Subsequent lookups reuse decompressed entries and successful locations.
    pub fn find_class(&self, descriptor: &str) -> Result<Option<DexEntry>> {
        self.find_class_with(descriptor, |_, _| Ok(()))
    }

    pub(crate) fn find_class_with(
        &self,
        descriptor: &str,
        indexed: impl Fn(usize, &str) -> Result<()> + Sync,
    ) -> Result<Option<DexEntry>> {
        if let Some(location) = self
            .class_index
            .read()
            .map_err(|_| anyhow!("class index lock was poisoned"))?
            .by_descriptor
            .get(descriptor)
            .copied()
        {
            let entry = self.load_dex_index(location.physical_index)?;
            let logical = logical_dexes(&entry.name, &entry.data)?
                .into_iter()
                .find(|logical| logical.header_offset == location.header_offset)
                .context("cached logical DEX is no longer present")?;
            return Ok(Some(DexEntry {
                name: logical.name,
                data: entry.data,
                header_offset: logical.header_offset,
            }));
        }

        let mut order = (0..self.dexes.len()).collect::<Vec<_>>();
        // Original ASC probes smaller compressed entries first so a class in a
        // late multidex shard is not forced to wait for every earlier shard.
        order.sort_unstable_by_key(|&index| self.dexes[index].compressed_size);

        let stop = AtomicBool::new(false);
        let outcome = Mutex::new(None::<Result<DexEntry>>);
        // Original ASC submits at most 12 class probes at once even when a
        // larger worker count is requested.
        let max_inflight = self.pool.current_num_threads().min(12).min(order.len());
        let active = (Mutex::new(0usize), Condvar::new());
        self.pool.install(|| {
            order.par_iter().enumerate().for_each(|(position, &index)| {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let (active_count, active_changed) = &active;
                let mut count = active_count
                    .lock()
                    .expect("class-probe concurrency lock was poisoned");
                while *count >= max_inflight && !stop.load(Ordering::Acquire) {
                    count = active_changed
                        .wait(count)
                        .expect("class-probe concurrency lock was poisoned");
                }
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                *count += 1;
                drop(count);

                let scan = (|| -> Result<Option<DexEntry>> {
                    indexed(position, &self.dexes[index].name)?;
                    let Some(entry) = self.load_dex_index_with_stop(index, Some(&stop))? else {
                        return Ok(None);
                    };
                    if stop.load(Ordering::Relaxed) {
                        return Ok(None);
                    }
                    let logical_dexes = logical_dexes(&entry.name, &entry.data)?;
                    let mut found = None;
                    for logical in logical_dexes {
                        if dex_defines_class_at(&entry.data, logical.header_offset, descriptor)
                            .with_context(|| format!("failed to probe {}", logical.name))?
                        {
                            found = Some((logical.name.clone(), logical.header_offset));
                            break;
                        }
                    }
                    if let Some((_, header_offset)) = found.as_ref() {
                        self.class_index
                            .write()
                            .map_err(|_| anyhow!("class index lock was poisoned"))?
                            .by_descriptor
                            .entry(descriptor.to_owned())
                            .or_insert(LogicalDexLocation {
                                physical_index: index,
                                header_offset: *header_offset,
                            });
                    }
                    Ok(found.map(|(name, header_offset)| DexEntry {
                        name,
                        data: entry.data,
                        header_offset,
                    }))
                })();
                let mut count = active_count
                    .lock()
                    .expect("class-probe concurrency lock was poisoned");
                *count -= 1;
                active_changed.notify_one();
                drop(count);

                match scan {
                    Ok(None) => {}
                    Ok(Some(entry)) => {
                        let mut slot = outcome.lock().expect("class outcome lock was poisoned");
                        if slot.is_none() {
                            *slot = Some(Ok(entry));
                            stop.store(true, Ordering::Release);
                            active_changed.notify_all();
                        }
                    }
                    Err(error) => {
                        let mut slot = outcome.lock().expect("class outcome lock was poisoned");
                        if slot.is_none() {
                            *slot = Some(Err(error));
                            stop.store(true, Ordering::Release);
                            active_changed.notify_all();
                        }
                    }
                }
            });
        });
        outcome
            .into_inner()
            .map_err(|_| anyhow!("class outcome lock was poisoned"))?
            .transpose()
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
/// an `ApkSession` so decompressed bytes and successful class locations can be reused.
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
            .start_file(
                "classes.dex",
                zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
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

    fn empty_dex041_apk() -> TempApk {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "asc-rs-container-test-{}-{unique}.apk",
            std::process::id()
        ));
        let first_size = 0x78u32;
        let second_header_offset = first_size;
        let string_ids_off = 0xf0u32;
        let type_ids_off = 0xf4u32;
        let class_defs_off = 0xf8u32;
        let string_data_off = 0x118u32;
        let descriptor = b"LSecond;";
        let container_size = string_data_off + 1 + descriptor.len() as u32 + 1;
        let second_size = container_size - second_header_offset;
        let mut container = Vec::with_capacity(container_size as usize);
        for (header_offset, logical_size) in [(0, first_size), (second_header_offset, second_size)]
        {
            let mut dex = vec![0; 0x78];
            dex[..8].copy_from_slice(b"dex\n041\0");
            dex[0x20..0x24].copy_from_slice(&logical_size.to_le_bytes());
            dex[0x24..0x28].copy_from_slice(&0x78u32.to_le_bytes());
            dex[0x70..0x74].copy_from_slice(&container_size.to_le_bytes());
            dex[0x74..0x78].copy_from_slice(&header_offset.to_le_bytes());
            container.extend(dex);
        }
        container[second_header_offset as usize + 0x38..second_header_offset as usize + 0x3c]
            .copy_from_slice(&1u32.to_le_bytes());
        container[second_header_offset as usize + 0x3c..second_header_offset as usize + 0x40]
            .copy_from_slice(&string_ids_off.to_le_bytes());
        container[second_header_offset as usize + 0x40..second_header_offset as usize + 0x44]
            .copy_from_slice(&1u32.to_le_bytes());
        container[second_header_offset as usize + 0x44..second_header_offset as usize + 0x48]
            .copy_from_slice(&type_ids_off.to_le_bytes());
        container[second_header_offset as usize + 0x60..second_header_offset as usize + 0x64]
            .copy_from_slice(&1u32.to_le_bytes());
        container[second_header_offset as usize + 0x64..second_header_offset as usize + 0x68]
            .copy_from_slice(&class_defs_off.to_le_bytes());
        container.extend(string_data_off.to_le_bytes());
        container.extend(0u32.to_le_bytes());
        let mut class_def = [0u8; 32];
        class_def[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        class_def[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        container.extend(class_def);
        container.push(descriptor.len() as u8);
        container.extend(descriptor);
        container.push(0);
        assert_eq!(container.len(), container_size as usize);

        let file = File::create(&path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "classes.dex",
                zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        archive.write_all(&container).unwrap();
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
    fn cancelled_inflation_does_not_populate_the_cache() {
        let apk = empty_dex_apk();
        let session = ApkSession::open(&apk.0, 2).unwrap();
        let stop = AtomicBool::new(true);

        assert!(
            session
                .load_dex_index_with_stop(0, Some(&stop))
                .unwrap()
                .is_none()
        );
        assert_eq!(session.cached_dex_count(), 0);
    }

    #[test]
    fn parses_each_logical_dex_in_a_041_container() {
        let apk = empty_dex041_apk();
        let session = ApkSession::open(&apk.0, 2).unwrap();
        let entries = session.load_all_parsed_dexes().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["classes.dex!classes1.dex", "classes.dex!classes2.dex"]
        );
        assert_eq!(session.cached_parsed_dex_count(), 2);
        assert_eq!(entries[1].dex.class_count(), 1);

        let found = session.find_class("LSecond;").unwrap().unwrap();
        assert_eq!(found.name, "classes.dex!classes2.dex");
        assert_eq!(found.header_offset, 0x78);
        let minimal =
            crate::minidex::extract_minimal_dex_at(&found.data, found.header_offset, "LSecond;")
                .unwrap();
        crate::minidex::validate_minimal_dex(&minimal.bytes).unwrap();
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
