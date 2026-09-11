use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use asc_rs::{
    dex::{MemberQuery, Query},
    format_class_name,
    service::{AscSession, DecompilationMode, decode_manifest},
};
use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Worker count used to inflate and scan DEX entries.
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
    let xml = decode_manifest(&args.apk_path, !args.compact)?;
    write_and_print(&xml, args.output.as_ref())
}

fn getclass(args: GetClassArgs) -> Result<()> {
    let session = AscSession::open(&args.apk_path, args.common.threads)?;
    let result = session.decompile_class(&args.dalvik_class, args.decompilation_mode.into())?;
    write_and_print(&result.source, args.output.as_ref())?;

    if args.common.debug {
        let stats = result.minimal_stats;
        eprintln!("[DEBUG] Hit DEX: {}", result.dex_name);
        eprintln!(
            "[DEBUG] Minimal DEX: {} -> {} bytes ({:.1}x smaller), strings={} types={} protos={} fields={} methods={}",
            stats.input_bytes,
            stats.output_bytes,
            stats.input_bytes as f64 / stats.output_bytes as f64,
            stats.strings,
            stats.types,
            stats.protos,
            stats.fields,
            stats.methods
        );
        eprintln!(
            "[DEBUG] APK locate/index: {:.3} ms",
            result.timings.locate_ms
        );
        eprintln!(
            "[DEBUG] Extract/rebuild: {:.3} ms",
            result.timings.extract_ms
        );
        eprintln!(
            "[DEBUG] Rust decompile: {:.3} ms",
            result.timings.decompile_ms
        );
        eprintln!("[DEBUG] Total: {:.3} ms", result.timings.total_ms);
    }
    Ok(())
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
    let query = match args.query {
        FindQuery::String { value } => Query::String(value),
        FindQuery::Type { value } => Query::Type(value.replace('.', "/")),
        FindQuery::Method(member) => Query::Method(member_query(member)?),
        FindQuery::Field(member) => Query::Field(member_query(member)?),
    };
    let session = AscSession::open(&args.apk_path, args.common.threads)?;
    let result = session.find_references(&query)?;

    let mut grouped = BTreeMap::<(String, u32, String), BTreeSet<String>>::new();
    for reference in &result.references {
        grouped
            .entry((
                reference.dex_name.clone(),
                reference.caller_index,
                reference.caller_method.clone(),
            ))
            .or_default()
            .insert(reference.target_symbol.clone());
    }
    let lines = grouped
        .into_iter()
        .map(|((dex_name, _, caller), matches)| {
            format!(
                "{dex_name} | {caller} | matched=({})",
                matches.into_iter().collect::<Vec<_>>().join("; ")
            )
        })
        .collect::<Vec<_>>();
    let text = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    write_and_print(&text, args.output.as_ref())?;

    if args.common.debug {
        for dex in &result.dexes {
            eprintln!(
                "[DEBUG] {} classes={} methods={} matched={}",
                dex.dex_name, dex.classes, dex.methods, dex.matched_targets
            );
        }
        eprintln!("[DEBUG] DEX load/parse: {:.3} ms", result.timings.load_ms);
        eprintln!("[DEBUG] DEX scan: {:.3} ms", result.timings.scan_ms);
        eprintln!("[DEBUG] Total: {:.3} ms", result.timings.total_ms);
        eprintln!("[DEBUG] Results: {}", lines.len());
    }
    Ok(())
}

fn write_and_print(text: &str, output: Option<&PathBuf>) -> Result<()> {
    if let Some(output) = output {
        fs::write(output, text.as_bytes())
            .with_context(|| format!("failed to write {}", output.display()))?;
    }
    print!("{text}");
    if !text.is_empty() && !text.ends_with('\n') {
        println!();
    }
    Ok(())
}
