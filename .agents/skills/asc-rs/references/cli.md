# ASC-RS CLI reference

## Resolve the executable

When working in the ASC-RS source repository, use the release binary if it is
current:

- Windows: `.\target\release\asc-rs.exe`
- Linux/macOS: `./target/release/asc-rs`

Run `cargo build --release` when the binary is missing or the task requires the
current source changes. Outside the repository, use `asc-rs` from `PATH` or a
user-provided executable path. Never invent an executable or APK path.

In the forms below, replace `<asc>` with the resolved executable and quote all
paths or values that contain spaces or shell metacharacters. Put `getclass` and
`findrefs` parent options before the APK path; in particular, a trailing
`--debug` after a `findrefs` query is parsed as a query argument.

## Decompile one class

```text
<asc> getclass [--debug] [--threads N] [-o FILE] \
  [--engine builtin|jadx] [--jadx-path PATH] \
  [-m restructure|simple|fallback] APK CLASS
```

`CLASS` accepts `com.example.Main` or `Lcom/example/Main;`.

- `builtin` is the default engine and defaults to `simple` mode.
- `jadx` defaults to `restructure`. It searches common `jadx` launchers on
  `PATH`; use `--jadx-path` only with this engine.
- `-o` writes the source and the command also prints it to stdout.
- `--threads` controls APK/DEX work; external JADX decompiles the rebuilt
  one-class DEX with one worker.

Examples:

```powershell
<asc> getclass app.apk com.example.Main
<asc> getclass --engine builtin -m restructure -o Main.java app.apk com.example.Main
<asc> getclass --engine jadx -o Main.java app.apk com.example.Main
<asc> getclass --engine jadx --jadx-path C:\tools\jadx\bin\jadx.bat app.apk com.example.Main
```

## Find bytecode references

Parent options are `--debug`, `--threads N`, and `-o FILE`:

```text
<asc> findrefs [--debug] [--threads N] [-o FILE] APK string VALUE
<asc> findrefs [--debug] [--threads N] [-o FILE] APK strings VALUE...
<asc> findrefs [--debug] [--threads N] [-o FILE] APK type VALUE
<asc> findrefs [--debug] [--threads N] [-o FILE] APK method [NAME] [--class CLASS] [--fuzzy-class]
<asc> findrefs [--debug] [--threads N] [-o FILE] APK field [NAME] [--class CLASS] [--fuzzy-class]
```

Semantics:

- `string` and `strings` match substrings of DEX string constants.
- `type` matches a descriptor substring; Java dots in the query are normalized
  to slashes.
- Method and field `NAME` values are substring matches. At least `NAME` or
  `--class` is required.
- `--class` is an exact Java name or Dalvik descriptor by default.
  `--fuzzy-class` changes it to descriptor-substring matching.
- Each output line identifies the DEX, the complete caller method signature,
  and the matched target symbols. Batched string output also starts with its
  `query=` group.
- `--debug` writes DEX counts and timings to stderr, leaving results on stdout.

Examples:

```powershell
<asc> findrefs app.apk string Authorization
<asc> findrefs app.apk strings Authorization token api.example.com
<asc> findrefs app.apk type com.example.Main
<asc> findrefs app.apk method onCreate --class com.example.Main
<asc> findrefs app.apk method notify --class openclaw --fuzzy-class
<asc> findrefs app.apk field INSTANCE --class com.example.Store
```

## Decode the manifest

```text
<asc> manifest [--compact] [-o FILE] APK
```

The default is pretty-printed XML. Use `--compact` only when compact output is
specifically useful.

## Failures and follow-up

- A missing class means the name or descriptor was not defined in any root
  `classes*.dex`; verify the name rather than widening the operation blindly.
- If JADX cannot launch, report its diagnostic and either accept an explicit
  `--jadx-path` from the user or use `builtin` when engine choice is flexible.
- If structured output is incomplete, retry the same engine with `simple` or
  `fallback` before claiming the class has no relevant behavior.
- A successful decompilation can still contain inaccurate types, variable
  names, or control flow. Base findings on exact constants, calls, fields, and
  signatures where possible.
