# RESX JSON Schemas

RESX JSON output is versioned with `schema_version: 1`. Most commands use a top-level envelope with the command kind as the payload key, for example `dump`, `peinfo`, `reconstruct_cfg`, `types`, or `explain`.

## Common Envelope

```json
{
  "schema_version": 1,
  "kind": "dump",
  "dump": {}
}
```

List-style commands use the item key directly:

```json
{
  "schema_version": 1,
  "kind": "types",
  "types": []
}
```

## Dump

`resx dump <image> <function> --json` emits:

- Image identity: `dll`, `dll_path`, `image_base`, `arch`, `entry_point`, `size_of_image`.
- Function identity: `function`, `rva`, `va`, `rebased_va`, `size_bytes`, `insn_count`.
- Analysis arrays: `instructions`, `xrefs`, `strings`, `api_calls`, `hook_indicators`, `intelli_findings`.
- Optional surfaces: `data`, `recomp`, `cfg`, `api_call_tree`, `current_syscall`, `edrchk`, `explain`, `function_discovery`, `recursive_cfg`, `typed_ir`, and `indirect_flow`.

`api_calls[]` includes `rva`, `kind`, `target_rva`, `label`, `dll`, `is_import`, `is_indirect`, optional `indirect_method`, optional `switch_cases`, and optional `syscall`.

`data.unwind[]` includes `begin_rva`, `end_rva`, `unwind_info_rva`, `prolog_size`, `unwind_codes`, `flags`, parsed unwind operations, saved registers, stack allocation size, chained parent metadata, epilog scopes, and optional `exception_handler_rva` / `handler_data_rva`.

## Reconstruct CFG

`resx reconstruct-cfg <image> --json` emits:

```json
{
  "schema_version": 1,
  "kind": "reconstruct_cfg",
  "reconstruct_cfg": {
    "image": "",
    "path": "",
    "arch": "x64",
    "image_base": "0x0000000000000000",
    "entry_point": "0x00000000",
    "pdb": {},
    "roots": [],
    "stats": {},
    "notes": []
  }
}
```

Function nodes in `roots[]` and child edges contain:

- Function fields: `name`, `kind`, `rva`, `va`, `section`, `symbol_source`, `symbol_category`, `symbol_size`, `prototype`, `decode_bound`, `thread_lane`, `note`, `status`, `returns`, `edges`.
- Edge fields: `site_rva`, `kind`, `target`, `target_rva`, `target_va`, `target_source`, `target_category`, `thread_lane`, `tags`, `detail`, `relation`, and optional `child`.
- Stats: `roots`, `functions_expanded`, `call_edges`, `import_edges`, `indirect_edges`, `thread_edges`, `workpool_edges`, `thread_api_edges`, `exception_edges`, `cycle_edges`, `truncated_edges`, `decode_errors`.

## Scan

`resx scan <path> --json` emits:

```json
{
  "tool": "resx",
  "schema_version": 1,
  "kind": "scan",
  "root": "",
  "files_seen": 0,
  "files_reported": 0,
  "results": []
}
```

Each `results[]` item contains `path`, `name`, `kind`, `arch`, `size_bytes`, `entry_point`, export/import/runtime-function counts, discovered-function counts, function-source counts, indirect edge/table counts, input-surface tags, a fuzz manifest, `risk_score`, `risk_imports`, `candidates`, `anomalies`, and `pdb_name`.

Each `candidates[]` item contains `name`, `rva`, `source`, `score`, `reasons`, `input_surface`, `harness_kind`, `suggested_invocation`, and `confidence`.

`--jsonl` emits one image report per line without the outer scan envelope. Each line has the same shape as an item from `results[]`.

## Types

`resx types <image> --json` emits `types[]` entries with:

- Type identity: `type_id`, `name`, `kind`, `size`.
- Reference counts: `symbol_count`, `function_count`, `data_count`.
- Structure data: `members[]` with `name`, `offset`, `type_id`, `type_name`, `size`.
- Symbol references: `refs[]` with `name`, `kind`, `rva`, `size`, `type_id`.

## Compatibility Notes

- Hexadecimal addresses are serialized as strings to avoid width loss.
- Optional fields are often omitted when empty.
- `schema_version` is the compatibility key; consumers should ignore unknown fields and require only the fields they use.
