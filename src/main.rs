use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use asc_rs::{
    apk::{DexEntry, load_dexes, read_entry},
    descriptor_to_java,
    dex::{Dex, MemberQuery, Query},
    format_class_name,
    minidex::{MinimalDexStats, extract_minimal_dex},
};
use axml_parser::AXMLPrinter;
use clap::{Args, Parser, Subcommand, ValueEnum};
use dex_decompiler::{DecompilationMode, Decompiler, DecompilerOptions, parse_dex};

#[derive(Debug, Parser)]
#[command(
    name = "asc-rs",
    version,
    about = "Fast, on-demand APK/DEX query tool rewritten in Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Locate and decompile one class from an APK.
    Getclass(GetClassArgs),
    /// Find bytecode references across every classes*.dex in an APK.
    Findrefs(FindRefsArgs),
    /// Decode the binary AndroidManifest.xml using Androguard's Rust AXML parser.
    Manifest(ManifestArgs),
}

#[derive(Debug, Args)]
struct ManifestArgs {
    /// Also write decoded XML to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Do not pretty-print the XML.
    #[arg(long)]
    compact: bool,
    /// Input APK path.
    apk_path: PathBuf,
}

#[derive(Debug, Args)]
struct CommonArgs {
    /// Enable timing and DEX diagnostics.
    #[arg(long)]
    debug: bool,
    /// Worker count used to inflate DEX entries.
    #[arg(long, alias = "thread", default_value_t = 8)]
    threads: usize,
}

#[derive(Debug, Args)]
struct GetClassArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Also write decompiled source to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Pure-Rust decompilation strategy.
    #[arg(short = 'm', long, value_enum, default_value_t = ModeArg::Simple)]
    decompilation_mode: ModeArg,
    /// Input APK path.
    apk_path: PathBuf,
    /// Dalvik descriptor or Java class name.
    dalvik_class: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Restructure,
    Simple,
    Fallback,
}

impl From<ModeArg> for DecompilationMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Restructure => Self::Restructure,
            ModeArg::Simple => Self::Simple,
            ModeArg::Fallback => Self::Fallback,
        }
    }
}

#[derive(Debug, Args)]
struct FindRefsArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Also write the search results to this path.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
    /// Input APK path.
    apk_path: PathBuf,
    #[command(subcommand)]
    query: FindQuery,
}

#[derive(Debug, Subcommand)]
enum FindQuery {
    /// Find references to strings containing this value.
    String { value: String },
    /// Find references to type descriptors containing this value.
    Type { value: String },
    /// Find references to matching methods.
    Method(MemberArgs),
    /// Find references to matching fields.
    Field(MemberArgs),
}

#[derive(Debug, Args)]
struct MemberArgs {
    /// Fuzzy member name; omit it to match all members in --class.
    name: Option<String>,
    /// Exact Java/Dalvik class name, unless --fuzzy-class is set.
    #[arg(long = "class")]
    class_name: Option<String>,
    /// Treat --class as a descriptor substring.
    #[arg(long)]
    fuzzy_class: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Getclass(args) => getclass(args),
        Commands::Findrefs(args) => findrefs(args),
        Commands::Manifest(args) => manifest(args),
    }
}

fn manifest(args: ManifestArgs) -> Result<()> {
    check_apk(&args.apk_path)?;
    let data = read_entry(&args.apk_path, "AndroidManifest.xml")?;
    let printer = AXMLPrinter::new(&data);
    ensure!(
        printer.is_valid(),
        "AndroidManifest.xml is not valid binary AXML"
    );
    let xml = String::from_utf8(printer.get_xml(!args.compact))
        .context("decoded AndroidManifest.xml is not UTF-8")?;
    if let Some(output) = &args.output {
        fs::write(output, xml.as_bytes())
            .with_context(|| format!("failed to write {}", output.display()))?;
    }
    print!("{xml}");
    if !xml.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn check_apk(path: &Path) -> Result<()> {
    ensure!(path.is_file(), "APK does not exist: {}", path.display());
    Ok(())
}

fn getclass(args: GetClassArgs) -> Result<()> {
    check_apk(&args.apk_path)?;
    ensure!(args.common.threads > 0, "--threads must be at least 1");
    let started = Instant::now();
    let descriptor = format_class_name(&args.dalvik_class)?;
    let entries = load_dexes(&args.apk_path, args.common.threads)?;
    let scan_finished = Instant::now();

    let hit = find_class_entry(&entries, &descriptor)?
        .with_context(|| format!("class {descriptor} not found in APK"))?;
    let (source, minimal_stats, extract_ms, decompile_ms) =
        decompile_in_rust(hit, &descriptor, args.decompilation_mode.into())?;
    let finished = Instant::now();

    if let Some(output) = &args.output {
        fs::write(output, source.as_bytes())
            .with_context(|| format!("failed to write {}", output.display()))?;
    }
    print!("{source}");
    if !source.ends_with('\n') {
        println!();
    }

    if args.common.debug {
        eprintln!("[DEBUG] Hit DEX: {}", hit.name);
        eprintln!(
            "[DEBUG] Minimal DEX: {} -> {} bytes ({:.1}x smaller), strings={} types={} protos={} fields={} methods={}",
            minimal_stats.input_bytes,
            minimal_stats.output_bytes,
            minimal_stats.input_bytes as f64 / minimal_stats.output_bytes as f64,
            minimal_stats.strings,
            minimal_stats.types,
            minimal_stats.protos,
            minimal_stats.fields,
            minimal_stats.methods
        );
        eprintln!(
            "[DEBUG] APK scan: {:.3} ms",
            (scan_finished - started).as_secs_f64() * 1000.0
        );
        eprintln!("[DEBUG] Extract/rebuild: {extract_ms:.3} ms");
        eprintln!("[DEBUG] Rust decompile: {decompile_ms:.3} ms");
        eprintln!(
            "[DEBUG] Total: {:.3} ms",
            (finished - started).as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

fn find_class_entry<'a>(entries: &'a [DexEntry], descriptor: &str) -> Result<Option<&'a DexEntry>> {
    for entry in entries {
        let dex =
            Dex::parse(&entry.data).with_context(|| format!("failed to parse {}", entry.name))?;
        if dex.defines_class(descriptor) {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn decompile_in_rust(
    entry: &DexEntry,
    descriptor: &str,
    mode: DecompilationMode,
) -> Result<(String, MinimalDexStats, f64, f64)> {
    let extract_started = Instant::now();
    let minimal = extract_minimal_dex(&entry.data, descriptor)
        .with_context(|| format!("failed to extract {descriptor} from {}", entry.name))?;
    let extract_finished = Instant::now();
    let parsed = parse_dex(&minimal.bytes)
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
            // getclass only has DEX bytes, not resources.arsc. Supplying an
            // empty map avoids an expensive full-DEX R-class discovery pass.
            resource_map: Some(Default::default()),
            ..DecompilerOptions::default()
        };
        let decompiler = Decompiler::with_options(&parsed, options);
        let mut source = decompiler
            .decompile_class(&class_def)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("failed to decompile {}", descriptor_to_java(descriptor)))?;
        // dex-decompiler intentionally hides bridge/accessor/R8 shim methods.
        // ASC's DAD output includes them, so restore those methods for parity.
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
        let decompile_finished = Instant::now();
        return Ok((
            repair_double_encoded_utf8(source),
            minimal.stats,
            (extract_finished - extract_started).as_secs_f64() * 1000.0,
            (decompile_finished - extract_finished).as_secs_f64() * 1000.0,
        ));
    }
    bail!("class {descriptor} was located but dex-decompiler could not resolve it")
}

/// Some current dex-parser strings arrive as UTF-8 bytes decoded through
/// Latin-1 one or two times. Repair only when a lossless Latin-1 -> UTF-8 pass
/// strictly reduces the number of suspicious Latin-1 code points.
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

fn member_query(args: MemberArgs) -> Result<MemberQuery> {
    if args.name.as_deref().is_none_or(str::is_empty)
        && args.class_name.as_deref().is_none_or(str::is_empty)
    {
        bail!("member query needs at least a name or --class");
    }
    let class = match args.class_name {
        Some(value) if args.fuzzy_class => Some(value.replace('.', "/")),
        Some(value) => Some(format_class_name(&value)?),
        None => None,
    };
    Ok(MemberQuery {
        class,
        fuzzy_class: args.fuzzy_class,
        name: args.name.filter(|value| !value.is_empty()),
    })
}

fn findrefs(args: FindRefsArgs) -> Result<()> {
    check_apk(&args.apk_path)?;
    ensure!(args.common.threads > 0, "--threads must be at least 1");
    let query = match args.query {
        FindQuery::String { value } => Query::String(value),
        FindQuery::Type { value } => Query::Type(value.replace('.', "/")),
        FindQuery::Method(member) => Query::Method(member_query(member)?),
        FindQuery::Field(member) => Query::Field(member_query(member)?),
    };
    let started = Instant::now();
    let entries = load_dexes(&args.apk_path, args.common.threads)?;
    let inflated = Instant::now();
    let mut lines = Vec::new();

    for entry in &entries {
        let dex =
            Dex::parse(&entry.data).with_context(|| format!("failed to parse {}", entry.name))?;
        let matched = dex.matching_indices(&query);
        let references = dex.scan_references(query.kind(), &matched)?;
        for (caller_idx, target_idxs) in references {
            let matches = target_idxs
                .into_iter()
                .map(|index| dex.format_match(query.kind(), index))
                .collect::<Vec<_>>()
                .join("; ");
            lines.push(format!(
                "{} | {} | matched=({matches})",
                entry.name,
                dex.format_method(caller_idx)
            ));
        }
        if args.common.debug {
            eprintln!(
                "[DEBUG] {} classes={} methods={} matched={}",
                entry.name,
                dex.class_count(),
                dex.method_count(),
                matched.len()
            );
        }
    }

    let text = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    print!("{text}");
    if let Some(output) = &args.output {
        fs::write(output, text.as_bytes())
            .with_context(|| format!("failed to write {}", output.display()))?;
    }
    if args.common.debug {
        let finished = Instant::now();
        eprintln!(
            "[DEBUG] DEX inflate: {:.3} ms",
            (inflated - started).as_secs_f64() * 1000.0
        );
        eprintln!(
            "[DEBUG] Total: {:.3} ms",
            (finished - started).as_secs_f64() * 1000.0
        );
        eprintln!("[DEBUG] Results: {}", lines.len());
    }
    Ok(())
}
