# RESX Analysis Surfaces

This page summarizes the analysis surfaces added around function discovery, recursive CFG reconstruction, exception metadata, typed reconstruction, indirect control flow, corpus scanning, and the `resx-palace` test corpus.

## Function Discovery

RESX discovers callable targets from several sources and keeps the source visible in reports:

- Export tables provide named entry points and ordinal-backed targets.
- PDB symbols provide internal functions, sizes, and prototype/type text when symbols are available.
- PE startup metadata contributes entry point, TLS callbacks, and startup handoff candidates.
- Disassembly contributes direct `CALL` and tail `JMP` targets.
- Import tables identify external API edges and IAT-backed call sites.
- Switch-dispatch recovery contributes jump-table targets where the dispatcher can be statically recovered.

Use `resx dump <image> <function> --funcs` for a local call map. Use `--funcs-depth <n>` to recurse into internal callees up to levels `1` through `5`.

## Recursive CFG

`resx reconstruct-cfg <image>` builds a bounded startup/TLS-to-exit graph. The graph starts from PE entry and startup roots, follows intra-image call and jump targets, annotates import edges, and nests recovered children until `--depth` or `--max-total` stops expansion.

Useful controls:

- `--depth <n>` limits recursive expansion depth.
- `--max-total <n>` caps the total number of expanded functions.
- `--thread-filter <term>` focuses text output on thread-related paths.
- `--api-filter <term>` focuses text output on matching APIs or functions.
- `--json` emits the structured `reconstruct_cfg` report.

Each function node reports name, kind, RVA/VA, section, symbol source/category, PDB prototype text when present, decode bound, status, return sites, and outgoing edges.

## Unwind And EH

RESX reads x64 `.pdata` / `UNWIND_INFO` where available:

- `dump --json` can include `data.unwind[]` entries with runtime-function ranges, unwind-info RVA, prolog size, unwind code count, flags, and exception-handler RVA.
- `dump --recomp` emits a `.pdata` comment above reconstructed C-like output.
- `reconstruct-cfg` follows executable exception-handler RVAs as `exception-handler` edges tagged with `try-except` and `unwind`.

Language-specific scope tables are not fully expanded; exception edges are best-effort static edges from unwind metadata.

## Typed IR And Reconstruction

The current typed reconstruction surface is PDB-backed and C-like:

- `resx types <image> --pdb <file>` inventories PDB type records, members, and symbol references.
- `dump --recomp` uses PDB function type text when available to recover return type, calling convention, and parameters.
- `dump --recomp` also uses unwind metadata to annotate frame and handler state.
- Without PDB types, reconstruction falls back to architecture defaults and observed argument-register usage.

This is not a full decompiler IR contract. Treat it as a typed pseudo-C and typed-IR reporting surface for review, triage, and agent consumption.

## Indirect Control Flow

Indirect-control-flow visibility appears in disassembly, call maps, CFG output, and JSON:

- IAT-backed memory calls are resolved to imported DLL/function names when possible.
- Register-indirect calls and jumps are traced backward through nearby register assignments.
- `--hostile` enables more aggressive reverse-index and indirect-JMP emission paths for hostile or obfuscated samples.
- API call JSON includes `is_indirect`, `indirect_method`, and `switch_cases` fields.
- `reconstruct-cfg` counts indirect edges and tags unresolved or partially resolved indirect calls.

Static recovery may miss data-dependent dispatch, generated code, or targets materialized outside the local decode window.

## Fuzz Target Output

`resx scan <path>` recursively inventories PE corpora and ranks fuzz-target candidates. It emits JSON by default and JSON Lines with `--jsonl`.

Candidate scoring uses:

- Image kind, including driver detection.
- Entry point and exported function names.
- Risk imports such as IOCTL, parser, decompression, crypto, network, file, registry, and kernel buffer APIs.
- Section anomalies and header corruption.
- Driver and WDF-style naming patterns.

Each candidate includes `name`, `rva`, `source`, `score`, `reasons`, `input_surface`, `harness_kind`, `suggested_invocation`, and `confidence`. Scores are triage hints, not exploitability claims.

## resx-palace Test Corpus

`resx-palace/` is the local corpus root for exercising these surfaces against controlled fixtures. It contains Windows C sources, a local build script, and generated DLL/EXE samples under `resx-palace/build/` when compiled.

Use it for fixtures that need to stress:

- Export and PDB-backed function discovery.
- Recursive direct-call and tail-call CFG expansion.
- x64 unwind and exception-handler edges.
- PDB type/prototype-backed reconstruction.
- IAT, register-indirect, and switch-dispatch control flow.
- Scan output and fuzz-candidate ranking.

The current corpus builds `resx_palace.dll` and `resx_palace_probe.exe`. The DLL exports `ResxParsePacket`, `ResxDeviceIoctlDispatch`, `ResxThreadCallbackEntry`, `ResxSwitchJumpTableDispatch`, and `ResxIndirectCallMessage`; the integration suite uses RESX itself to verify PE metadata, exports, dumps, CFG output, recursive reconstruction, and scan/fuzz-candidate output.

Keep generated binaries, source fixtures, and runner scripts isolated under `resx-palace/` so docs and schema expectations can describe the intended test surface without mixing fixture code into RESX source.
