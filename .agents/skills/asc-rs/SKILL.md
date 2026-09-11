---
name: asc-rs
description: Analyze user-provided Android APK files with ASC-RS by listing classes or archive entries, reading bounded entry ranges, decompiling a known class, locating bytecode references, or decoding AndroidManifest.xml. Use for focused local APK inspection; do not use for whole-app bulk decompilation or extraction, APK modification, signing, or installation.
---

# ASC-RS APK analysis

Use ASC-RS as a focused, read-only APK query tool. It searches every root
`classes*.dex`, reconstructs only the requested class when decompiling, and can
retain a warm session through its Rust library API.

## Route the request

- For a known Java class name or Dalvik descriptor, use `getclass`.
- For callers that reference a value or symbol, use `findrefs` with the most
  specific available kind: `string`, `type`, `method`, or `field`.
- For two or more string patterns, prefer the batched `strings` form so the DEX
  string table is traversed once and results remain grouped by query.
- For package, component, permission, SDK, or application metadata, decode the
  manifest with `manifest` and inspect the XML.
- To discover a class name without scanning references, use `classes` with a
  narrow `--contains` filter.
- To inspect packaged files, use `entries` first, then `entry` for the exact
  file and smallest useful uncompressed byte range. Prefer UTF-8 for known text
  and hex for unknown data; write raw bytes only when an output artifact helps.
- If the user has a keyword but not a class name, find references first, take
  the caller class from the full Dalvik signature, then decompile that class.
- If the user requests broad browsing of all application code or APK changes,
  explain that ASC-RS is not the right operation and use an appropriate tool
  only if that broader work is authorized.

When composing or running a command, read [references/cli.md](references/cli.md)
for exact syntax and query semantics.

## Choose the decompiler deliberately

- Keep `builtin` for low startup latency, a pure-Rust workflow, or when JADX is
  unavailable. Its default mode is `simple`.
- Use `jadx` when readable, higher-level Java reconstruction matters more than
  startup latency. It requires a local JADX CLI and Java; its default mode is
  `restructure`.
- Honor an explicitly requested engine. Do not silently fall back to another
  engine because output structure and inferred code can differ.
- Use `restructure` for readable control flow, `simple` for a faster linearized
  view, and `fallback` for difficult bytecode or diagnostics.
- Do not install or download JADX merely because it is missing. Report the
  dependency and offer the built-in engine unless installation was requested.

## Execute and report

Confirm the APK path and requested class/query from available context, then run
the narrowest command that answers the request. Quote paths and query values.
Write an output file only when the user requests one or the result needs to be
handed off as an artifact.

Use `--format json` when the result will feed another command or program. Keep
the default text form for direct inspection and user-facing excerpts.

Treat decompiled Java as an analysis aid, not guaranteed buildable source.
Clearly distinguish tool output from conclusions inferred from it. Report the
engine used, the matching caller signatures or manifest facts that answer the
request, and any incomplete or failed decompilation. Use `--debug` only when
timings or DEX diagnostics help the task.
