use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use zip::ZipArchive;

#[derive(Debug)]
pub struct DexEntry {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug)]
struct DexMeta {
    name: String,
    compressed_size: u64,
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

fn dex_metadata(apk_path: &Path) -> Result<Vec<DexMeta>> {
    let file = File::open(apk_path)
        .with_context(|| format!("failed to open APK {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP/APK", apk_path.display()))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if is_root_dex(entry.name()) {
            entries.push(DexMeta {
                name: entry.name().to_owned(),
                compressed_size: entry.compressed_size(),
            });
        }
    }
    entries.sort_by_key(|entry| (dex_ordinal(&entry.name), entry.compressed_size));
    if entries.is_empty() {
        bail!("APK contains no root classes*.dex entries");
    }
    Ok(entries)
}

fn read_one(apk_path: &Path, name: &str) -> Result<DexEntry> {
    let file = File::open(apk_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut entry = archive
        .by_name(name)
        .with_context(|| format!("DEX entry {name} disappeared from APK"))?;
    let capacity = usize::try_from(entry.size()).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("failed to inflate {name}"))?;
    Ok(DexEntry {
        name: name.to_owned(),
        data,
    })
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

pub fn load_dexes(apk_path: &Path, threads: usize) -> Result<Vec<DexEntry>> {
    let metadata = dex_metadata(apk_path)?;
    let path: PathBuf = apk_path.to_owned();
    let workers = threads.max(1).min(metadata.len().max(1));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .context("failed to create DEX worker pool")?;

    let entries: Vec<Result<DexEntry>> = pool.install(|| {
        metadata
            .par_iter()
            .map(|entry| read_one(&path, &entry.name))
            .collect()
    });
    entries.into_iter().collect()
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
}
