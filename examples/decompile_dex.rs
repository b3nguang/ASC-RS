use std::{env, fs, path::Path, time::Instant};

use anyhow::{Context, Result, bail};
use asc_rs::apk::load_dexes;
use dex_decompiler::{DecompilationMode, Decompiler, DecompilerOptions, parse_dex};

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .context("usage: decompile_dex FILE.dex DESCRIPTOR")?;
    let descriptor = args.next().context("missing class descriptor")?;
    let descriptor = descriptor.to_string_lossy();
    let path = Path::new(&path);
    let started = Instant::now();
    let data = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
    {
        load_dexes(path, 8)?.remove(0).data
    } else {
        fs::read(path)?
    };
    let loaded = Instant::now();
    let dex = parse_dex(&data).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let parsed = Instant::now();
    for class_def in dex.class_defs() {
        let class_def = class_def.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let name = dex
            .get_type(class_def.class_idx)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if name == descriptor {
            let options = DecompilerOptions {
                mode: DecompilationMode::Simple,
                resource_map: Some(Default::default()),
                ..Default::default()
            };
            let source = Decompiler::with_options(&dex, options)
                .decompile_class(&class_def)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let finished = Instant::now();
            eprintln!(
                "load_ms={:.3} parse_ms={:.3} decompile_ms={:.3} total_ms={:.3}",
                (loaded - started).as_secs_f64() * 1000.0,
                (parsed - loaded).as_secs_f64() * 1000.0,
                (finished - parsed).as_secs_f64() * 1000.0,
                (finished - started).as_secs_f64() * 1000.0,
            );
            print!("{source}");
            return Ok(());
        }
    }
    bail!("class {descriptor} not found")
}
