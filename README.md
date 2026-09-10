# ASC-RS

ASC-RS is a Rust rewrite of the command-line core of
[Droid ASC](https://github.com/MG1937/ASC). It opens `classes*.dex` entries
directly from an APK, parses DEX metadata without Python, locates classes, and
scans bytecode references to strings, types, methods, and fields.

Java source rendering is provided by Androguard's pure-Rust `dex-decompiler`,
which builds on its Rust `dex-parser` and `dex-bytecode` projects. Binary
Android manifests are decoded by Androguard's Rust `axml-parser`. There is no
Python, JVM, JADX, or other external runtime dependency.

`getclass` follows ASC's on-demand pipeline rather than decompiling the whole
DEX:

1. Read root DEX metadata once, then index class tables only until the requested
   class is found.
2. Walk only that class's instructions and collect string/type/field/method
   dependencies.
3. Preserve its interfaces, annotations, static values, debug metadata, and
   try/catch handlers.
4. Canonically sort and deduplicate every referenced ID table, then rewrite all
   instruction and metadata operands.
5. Build and validate a one-class DEX in memory, including section layout,
   SHA-1 signature, and Adler-32 checksum.
6. Pass that small DEX to the pure-Rust decompiler.

The parser primitives used by reference search and minimal-DEX extraction live
in one shared format layer. A reusable `AscSession` owns APK metadata, a bounded
DEX cache, the lazy class index, and its worker pool. This keeps CLI startup
small while allowing a GUI or other long-lived client to reuse previous work.

## Build

```powershell
cargo build --release
```

The executable is `target/release/asc-rs.exe` on Windows.

## Usage

```powershell
asc-rs getclass app.apk com.example.Main -o Main.java
asc-rs findrefs app.apk string Authorization
asc-rs findrefs app.apk type com.example.Main
asc-rs findrefs app.apk method onCreate --class com.example.Main
asc-rs findrefs app.apk method notify --class openclaw --fuzzy-class
asc-rs findrefs app.apk field token --class com.example.Main
asc-rs manifest app.apk -o AndroidManifest.xml
```

Use `--debug` for per-DEX counts and timings, and `--threads N` to choose the
number of DEX inflation and search workers. `getclass` defaults to the fast `simple`
decompilation strategy; use `-m restructure` for more structured output or
`-m fallback` for a linear representation of difficult bytecode.

Reference results include complete Dalvik method and field signatures. The
library's structured results additionally retain the caller and target indexes
and the exact code-unit offset for navigation.

## Library API

Frontends can keep one session open and receive structured results:

```rust
use asc_rs::{
    dex::Query,
    service::{AscSession, DecompilationMode},
};

let session = AscSession::open("app.apk", 8)?;
let class = session.decompile_class(
    "com.example.Main",
    DecompilationMode::Simple,
)?;
let references = session.find_references(
    &Query::String("Authorization".to_owned()),
)?;
# Ok::<(), anyhow::Error>(())
```

`OperationObserver` provides thread-safe progress and cancellation callbacks.
The default session cache owns at most 512 MiB of decompressed DEX data; use
`AscSession::open_with_cache_limit` to choose another bound.

See [`BENCHMARK.md`](BENCHMARK.md) for the speed and result-set comparison
against the original Python ASC on the supplied demo APK.
