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

1. Locate the DEX containing the requested class.
2. Walk only that class's instructions and collect string/type/field/method
   dependencies.
3. Preserve its interfaces, annotations, static values, debug metadata, and
   try/catch handlers.
4. Remap all referenced IDs to dense tables and rewrite instruction operands.
5. Build a valid one-class DEX in memory, including SHA-1 signature and Adler-32
   checksum.
6. Pass that small DEX to the pure-Rust decompiler.

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
number of DEX inflation workers. `getclass` defaults to the fast `simple`
decompilation strategy; use `-m restructure` for more structured output or
`-m fallback` for a linear representation of difficult bytecode.

See [`BENCHMARK.md`](BENCHMARK.md) for the speed and result-set comparison
against the original Python ASC on the supplied demo APK.
