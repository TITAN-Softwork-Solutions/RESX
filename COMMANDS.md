# COMMANDS

## Core

- `resx dump <dll> <function>`
- `resx dump <dll> --at <rva>`
- `resx dump <dll> --ordinal <n>`
- `resx cfg <dll> <function>`
- `resx peinfo <dll>`
- `resx sections <dll>`
- `resx eat <dll>`
- `resx iat <dll>`
- `resx syms <dll>`
- `resx pechk <dll>`
- `resx callers <dll> <function>`
- `resx locate <name>`
- `resx locate-all <name>`
- `resx locate-sym <name>`
- `resx locate-all-sym <name>`
- `resx yara <dll> <rule.yar>`

## Common Flags

- `--recomp`
- `--c-out <file>`
- `--cfg text`
- `--intelli`
- `--hookchk`
- `--edrchk`
- `--xrefs`
- `--strings`
- `--follow-jmp`
- `--pdb <file>`
- `--sym-path <path>`
- `--sym-server <url>`
- `--json`
- `--out <file>`
- `--verbose`
- `--quiet`

## Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx dump suspicious.dll --intelli
resx dump suspicious.dll WinMain --intelli --hookchk --cfg text --strings --xrefs
resx callers blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub
resx locate-all-sym NtWriteVirtualMemory
```
