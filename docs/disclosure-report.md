# RESX Diamond Integration Disclosure And Review Report

## Scope

Diamond was a separate untracked Rust crate that duplicated the RESX source tree and added two command families that RESX did not expose:

- `reconstruct-cfg`: startup/TLS-to-exit flow reconstruction with intra-image calls, imports, recovered thread/workpool callbacks, and unwind exception-handler edges.
- `scan`: recursive PE corpus inventory with risk imports, anomalies, and ranked fuzz-target candidates.

Those capabilities are now integrated into the `resx` crate and exposed as RESX commands.

## Documented Analysis Surfaces

- Function discovery from exports, PDB symbols, startup roots, direct calls, imports, IAT slots, and switch-dispatch recovery.
- Recursive CFG reconstruction from PE entry/TLS/startup roots with bounded nested child expansion.
- x64 unwind and exception-handler reporting through dump metadata, reconstruction comments, and `reconstruct-cfg` exception edges.
- Typed reconstruction via PDB-backed function prototypes, `types` inventory output, and pseudo-C emission.
- Indirect-control-flow reporting for IAT memory calls, register-indirect calls/jumps, unresolved indirect paths, and switch-dispatch cases.
- Fuzz target output from recursive corpus scanning with risk imports, anomalies, candidate scores, and candidate reasons.
- JSON schema notes for `dump`, `reconstruct_cfg`, `scan`, and `types`.
- `resx-palace/` test corpus with controlled DLL/EXE fixtures covering these analysis surfaces.

## Task Split

- Core RESX integration: command routing, config flags, analysis modules, dump JSON surfaces, PE unwind metadata, and Diamond removal.
- Sample corpus and tests: `resx-palace/` fixture sources, local build script, and Windows integration test coverage.
- Documentation and schemas: command docs, analysis-surface notes, JSON field notes, and this disclosure/review report.
- VS Code extension: command-palette entries, runner wiring, and webview rendering for reconstruct-CFG and scan output.

## Integrated Into RESX

- Added `resx/src/analysis/reconstruct.rs`.
- Added `resx/src/commands/reconstruct_cfg.rs`.
- Added `resx/src/commands/scan.rs`.
- Registered the new modules in `resx/src/analysis/mod.rs` and `resx/src/commands/mod.rs`.
- Added CLI/config support for:
  - `resx reconstruct-cfg <image>`
  - `resx <image> --reconstruct-cfg`
  - `--thread-filter <term>`
  - `--api-filter <term>`
  - `resx scan <path>`
  - `--jsonl`
  - `--extensions <list>`
  - `--max-files <n>`
  - `--max-file-mb <mb>`
  - `--max-candidates <n>`
- Updated help routing so the shorthand commands rewrite to RESX-native flags.
- Updated scan JSON metadata from `tool: "diamond"` to `tool: "resx"`.
- Updated README, CLI docs, and command reference to disclose the new RESX command surface.
- Added docs for analysis surfaces and JSON schema expectations.

## JSON Schema Surface

- Versioned command JSON uses `schema_version: 1`.
- `reconstruct-cfg --json` reports image identity, PDB status, root flow functions, nested edges, statistics, and static-analysis notes under `reconstruct_cfg`.
- `scan --json` reports a `tool: "resx"` envelope with root, file counts, and image results; `scan --jsonl` emits one image report per line.
- `dump --json` exposes function discovery, recursive CFG, typed IR, indirect-flow metadata, indirect call metadata through `api_calls[]`, and unwind/EH metadata through `data.unwind[]`.
- `types --json` exposes PDB type entries, members, and symbol references for typed analysis consumers.

## resx-palace Corpus

- `resx-palace/` is a local test corpus with source fixtures, a Windows build script, and generated binaries under `resx-palace/build/`.
- The corpus builds `resx_palace.dll` and `resx_palace_probe.exe` with exported parser, IOCTL, callback/thread, switch/jump-table, and indirect-call functions.
- The corpus coverage is export function discovery, recursive direct/tail-call CFG, unwind/EH metadata, typed reconstruction output, indirect control flow, and scan/fuzz-candidate output.
- The corpus is separate from RESX Rust and VS Code source so fixtures can evolve without changing the analyzer implementation.

## Removed Diamond

- Removed `diamond` from the workspace members.
- Changed the workspace default member from `diamond` to `resx`.
- Deleted all Diamond crate source files.
- Deleted the old `docs/diamond.md` planning document.
- Verified that no Diamond source files remain with `rg --files diamond`.
- Verified that user-facing RESX/docs references no longer contain Diamond branding outside this disclosure report.

## Verification

- `git diff --check` completed without whitespace errors; Git only reported CRLF normalization warnings.
- `cargo fmt -p resx -- --check`
- `cargo check -p resx --locked`
- `cargo test -p resx --locked`
- `npx tsc -p .\tsconfig.webview.json --noEmit`
- `npx tsc -p .\tsconfig.json --noEmit`
- `resx-palace/scripts/build.ps1`
- `cargo run -p resx --locked -- peinfo resx-palace\build\resx_palace.dll --json --quiet --no-color`
- `cargo run -p resx --locked -- eat resx-palace\build\resx_palace.dll --json --quiet --no-color`
- `cargo run -p resx --locked -- dump resx-palace\build\resx_palace.dll ResxParsePacket --json --quiet --no-color --funcs --cfg text`
- `cargo run -p resx --locked -- cfg resx-palace\build\resx_palace.dll ResxSwitchJumpTableDispatch --quiet --no-color`
- `cargo run -p resx --locked -- reconstruct-cfg resx-palace\build\resx_palace.dll --json --quiet --no-color --depth 3 --max-total 80`
- `cargo run -p resx --locked -- scan resx-palace\build --json --quiet --no-color --max-files 10`

Cargo was run with an external `CARGO_TARGET_DIR` because the repository `target` directory is not writable under the current sandbox ACLs.

## Sample Test Results

- `peinfo` identified `resx_palace.dll` as an x64 DLL with 5 exports, 69 imports, startup roots, and x64 runtime/unwind metadata.
- `eat` resolved all intended exports: `ResxDeviceIoctlDispatch`, `ResxIndirectCallMessage`, `ResxParsePacket`, `ResxSwitchJumpTableDispatch`, and `ResxThreadCallbackEntry`.
- `dump --json` for `ResxParsePacket` emitted instructions, CFG data, function discovery, recursive CFG, typed IR, indirect-flow data, and unwind metadata.
- `cfg` for `ResxSwitchJumpTableDispatch` produced a graph with switch-dispatch control flow and an unresolved register-indirect jump annotation.
- `reconstruct-cfg --json` reported startup roots, nested internal call expansion, import edges, indirect edges, exception edges, and truncation statistics under the `reconstruct_cfg` envelope.
- `scan --json` reported both corpus binaries and ranked the intended DLL exports as fuzz candidates, including IOCTL, structured-input, callback/thread, switch-dispatch, and message/indirect-call surfaces.

## Residual Limitations

- `reconstruct-cfg` is static best-effort analysis. Runtime dispatch, data-dependent branches, generated code, and unresolved indirect calls may be incomplete.
- `scan` uses PE metadata, import names, export names, and section heuristics. Candidate ranking is triage-oriented, not a proof of exploitability.
- PDB-backed names, prototypes, and size bounds are used when available, but the command continues with reduced fidelity when symbols are unavailable.
- Typed IR is a lightweight reporting layer for review and automation, not a full SSA/decompiler contract.
- The legacy text CFG renderer can still linearize adjacent table bytes in some switch fixtures; the recursive CFG and indirect-flow JSON now expose the dispatch surface, but perfect jump-table block exclusion remains future hardening.
- Win32K syscall target resolution depends on available exports or PDB symbols in the local `win32k*` images; RESX still reports the user-mode stub and service number when kernel symbols are unavailable.
