# COMMANDS

## Identity

- Name: `RESX`
- Author: `RYFTENIUS`
- Version: `resx version` or `resx --version`

## Core

- `resx dump <dll> <function>`
- `resx dump <dll> --at <rva>`
- `resx dump <dll> --ordinal <n>`
- `resx cfg <dll> <function>`
- `resx cfg <dll> --at <rva>`
- `resx cfg <dll> --ordinal <n>`
- `resx reconstruct-cfg <dll>`
- `resx intelli <dll> [function]`
- `resx peinfo <dll>`
- `resx sections <dll>`
- `resx eat <dll>`
- `resx iat <dll>`
- `resx syms <dll>`
- `resx pechk <dll>`
- `resx priority`
- `resx callers <dll> <function>`
- `resx locate <name>`
- `resx locate-sym <name>`
- `resx explain <name>`
- `resx scan <path>`
- `resx yara <dll> <rule.yar>`
- `resx update`

## Dump And Analysis Flags

- `--at <rva>`
- `--ordinal <n>`
- `--recomp`
- `--c-out <file>`
- `--cfg text`
- `--reconstruct-cfg`
- `--thread-filter <term>`
- `--api-filter <term>`
- `--funcs`
- `--funcs-depth <n>`
- `--explain`
- `--prefix`
- `--api`
- `--xrefs`
- `--strings`
- `--edrchk`
- `--unsafe-map-image`
- `--hookchk`
- `--intelli`
- `--hostile`
- `--follow-jmp`
- `--no-follow-jmp`
- `--rebase <addr>`

## Intelli

- `resx intelli <dll>` runs triage against an image quickly.
- `resx intelli <dll> <function>` narrows the triage to a specific target while still allowing dump-side options like `--hookchk`, `--cfg text`, `--strings`, and `--json`.
- `intelli` is a command alias for the dump pipeline with `--intelli` enabled.

## Explain

- `resx explain <name>` explains a prefix or API-style symbol using the built-in glossary.
- `--prefix` forces prefix-mode interpretation.
- `--api` forces API/symbol-mode interpretation.
- `dump --explain` reuses the same explanation engine inline for the current target.

## Reconstruct CFG

- `resx reconstruct-cfg <dll>` builds a bounded startup/TLS-to-exit graph.
- The graph follows intra-image calls, tail jumps, import edges, indirect-call annotations, recovered thread/workpool callbacks, and x64 unwind exception-handler edges.
- PDB symbols are used when available for names, prototypes, and size-backed decode bounds.
- `--thread-filter <term>` and `--api-filter <term>` focus the text output for non-interactive review.
- `--json` emits a versioned `reconstruct_cfg` report with roots, nested edge children, PDB status, statistics, and static-analysis notes.

## Scan

- `resx scan <path>` inventories `.exe`, `.dll`, and `.sys` files under a root.
- `--jsonl` emits one JSON object per image for agent and corpus workflows.
- `--extensions <list>`, `--max-files <n>`, `--max-file-mb <mb>`, and `--max-candidates <n>` control scan scope and output size.
- Results include image metadata, risk imports, anomalies, and ranked fuzz-target candidates.
- Candidate entries include `name`, `rva`, `source`, `score`, `reasons`, `input_surface`, `harness_kind`, `suggested_invocation`, and `confidence`; scores are triage hints, not exploitability claims.

## JSON Output

- JSON output uses `schema_version: 1`.
- Most commands emit `{ "schema_version": 1, "kind": "<command>", "<command>": ... }`.
- `scan --json` emits `{ "tool": "resx", "schema_version": 1, "kind": "scan", "results": [...] }`.
- `scan --jsonl` emits one image report per line without the outer scan envelope.
- See [docs/json-schemas.md](docs/json-schemas.md) for field-level notes.

## Symbol Flags

- `--pdb <file>`
- `--sym-path <path>`
- `--sym-server <url>`
- `--reload`
- `--no-pdb`

## Caller Tracing Flags

- `--depth <n>`
- `--max-callers <n>`
- `--max-total <n>`
- `--format tree|flat|list`
- `--show-rva`
- `--show-site`
- `--filter-dll <text>`
- `--include-dir <dir>`
- `--include-image <dll>`
- `--scan-exe`
- `--include <glob>`
- `--scope-file <glob>` / `--include-file <glob>`
- `--exclude <glob>`
- `--max-dll-size <mb>`
- `--workers <n>`

## Global Flags

- `--path <dir>`
- `--priority`
- `--no-system`
- `--no-cwd`
- `--no-path`
- `--arch <auto|x86|x64>`
- `--bytes`
- `--no-bytes`
- `--show-offsets`
- `--intel`
- `--att`
- `--json`
- `--out <file>`
- `--color`
- `--no-color`
- `--verbose`
- `--quiet`
- `--example`

## Newer Output Areas

- `dump --cfg text` can recover and render `Switch Map` sections for jump-table dispatchers.
- `cfg` supports function names, `--at <rva>`, and `--ordinal <n>` just like `dump`.
- `cfg` and `dump` use the same instruction and API/symbol highlighting path for call targets and comments.
- `dump --funcs` discovers direct, import, IAT-indirect, register-indirect, and switch-dispatch call targets.
- `dump --recomp` emits corrected bit-test branches and better local-call placeholders.
- `dump --recomp` uses PDB prototype text and x64 unwind metadata when available.
- `dump --funcs-depth <n>` expands nested API call depth and accepts levels `1` through `5`.
- `syms --verbose` can show exact PDB identity/load diagnostics, including RSDS-derived kernel PDB names.
- `dump` can resolve internal names from enumerated PDB symbols when exports do not contain the target.
- `dump` can surface syscall service numbers and kernel targets for `Nt*`, `Zw*`, and Win32K GUI syscall stubs.
- Extensionless system image lookup supports `.dll`, `.exe`, and `.sys`, including `user32`, `win32u`, `win32k`, `win32kbase`, `win32kfull`, and `ntoskrnl`.
- `locate` and `locate-sym` search only the priority set by default.
- `callers` uses the priority set by default.
- `--include-dir` and `--include-image` widen the scan beyond the priority set for `locate` and `callers`.
- `callers --include-dir` will scan `.dll` and `.sys` images by default, and `.exe` as well when `--scan-exe` is set.
- `--include` filters the entire callers scan list; `--scope-file` only filters files discovered through `--include-dir`.
- `priority` opens the generated priority config JSON where you can edit directories, exact names, prefixes, and regexes.
- `reconstruct-cfg` reconstructs startup flow using PE entry/TLS/startup roots, direct calls, import calls, recovered callbacks, and unwind exception edges.
- `scan` inventories PE corpora and ranks fuzz-target candidates from exports, startup paths, risky imports, and section anomalies.
- `resx-palace/` is the local controlled fixture corpus that exercises discovery, recursive CFG, EH, typed reconstruction, indirect control flow, and scan output.

## Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx reconstruct-cfg suspicious.dll --depth 6 --max-total 300
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx dump win32u NtUserGetMessage --funcs
resx peinfo win32kfull
resx syms ntoskrnl.exe --verbose
resx callers blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx callers ntoskrnl.exe NtOpenProcess --include-dir C:\Work\Drivers --depth 2
resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
resx priority
resx locate NtOpenProcess
resx locate NtOpenProcess --include-dir C:\Work\Drivers
resx locate-sym NtWriteVirtualMemory --include-image .\mydriver.sys
resx explain NtQuerySystemInformation --api
resx scan C:\Windows\System32\drivers --jsonl --max-files 200
resx update
```
