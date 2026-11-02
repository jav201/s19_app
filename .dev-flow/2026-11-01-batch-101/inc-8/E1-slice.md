# Inc 8 — E1 slice: every file and function to change, counted and mapped

Base `e266395`. Line numbers are on the base tree. Graph: `codewire/graph-inc8.md` (7 changed or new nodes, 7 context nodes).

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/operations/crc.py` | 1 changed: `crc32_stream` (`:155`, seed at `:211`) | R-CRC-ENGINE-001.1, R-CRC-ENGINE-002.2 |
| `s19_app/tui/operations/crc_config.py` | 2 changed: `_build_config` (`:448`), `_build_group` (`:537`); 2 new: `_required_field`, `_number_field`; 1 new constant: `DESIGNER_TEMPLATE_RULE` | R-CRC-CONFIG-001.10, .11, .16; R-FLOW-CRC.4 |
| `s19_app/tui/services/flow_execution_service.py` | 1 changed: `run_flow` (`:186`); 1 new: `_resolve_block_ref` | R-FLOW-EXT.2, .9, .10, .11; R-FLOW-CRC.1, .3, .4 |

**Totals:** 3 source files (cap 4); 4 changed functions, 3 new functions, 1 new constant. Unchanged and only called: `parse_crc_config`, `check_regions`, `inject_crcs`, `crc_kernel.crc_stream` / `crc_lut`, `_resolve_manifest_entry`, `place_into_workarea` / `copy_into_workarea`, `emit_template`.

## 2. Function map

| Function | File:line (base) | Change | Rows |
|---|---|---|---|
| `crc32_stream` | `crc.py:155-224` | seed `reg = init & _MASK32` for both values of `reverse` (base: `_reflect(init, 32)` when `reverse`); the byte and output reflection and the zlib fast path stay | R-CRC-ENGINE-001.1, 002.2 |
| `_build_config` | `crc_config.py:448-534` | (1) first statement: a Designer template shape raises `ValueError(DESIGNER_TEMPLATE_RULE)`; (2) `reverse`, the region fields and `polynomial` / `init` / `final_xor` read through `_required_field` / `_number_field`; the check order is otherwise unchanged | R-CRC-CONFIG-001.10, .11, .16 |
| `_build_group` | `crc_config.py:537-650` | `regions` read through `_required_field`; span `start` / `end` and `output_address` through `_number_field`; `output_bytes` keeps its own rule text | R-CRC-CONFIG-001.10, .11 |
| `_required_field` (new) | `crc_config.py` | `(container: dict, key: str) -> Any`; a missing key raises `ValueError(f"field '{key}' is missing")` | R-CRC-CONFIG-001.10 |
| `_number_field` (new) | `crc_config.py` | `(container: dict, key: str) -> int`; `_required_field` then `_parse_int`; a `ValueError` from `_parse_int` becomes `ValueError(f"field '{key}' is not a number: {json.dumps(value)}")` | R-CRC-CONFIG-001.10, .11 |
| `DESIGNER_TEMPLATE_RULE` (new constant) | `crc_config.py` | `"a CRC Designer template is not a CRC config - it has no regions or groups"` | R-CRC-CONFIG-001.16 |
| `run_flow` | `flow_execution_service.py:186-1240` | (1) a per-run `rebinds: dict[str, Path]`; (2) the 7 `_resolve_manifest_entry` calls of the block branches (`:315`, `:345`, `:427`, `:448`, `:734`, `:798`, `:942`) go through `_resolve_block_ref`; (3) PATCH branch: `change_doc_ref` of each `FlowChangeRecord` / `FlowRefusal` (`:502`, `:519`) is the copy's file name when the ref was read in place, else the block's ref as typed; (4) external-step branch: a relative `source_path` is joined under `ctx.project_dir` (`:1092`); after the copy, `rebinds[normcase(<copy folder>/<output file name>)] = copied` | R-FLOW-EXT.2, .9, .10, .11; R-FLOW-CRC.1, .3, .4 (paths unchanged, cited) |
| `_resolve_block_ref` (new) | `flow_execution_service.py` | `(project_dir, ref, label, issues, rebinds) -> tuple[Optional[Path], bool]`: `_resolve_manifest_entry`, then the rebind map; `True` only when the copy is another file | R-FLOW-EXT.9, .10 |

Not changed, by decision: `workspace.place_into_workarea` (D-2), `variant_execution_service._resolve_manifest_entry` (no Inc 4 dependency), `crc_designer_model` (D-4), `_chain_inputs` (`:1695`, chain bindings resolve before the run; no external copy exists yet).

## 3. Callers read (rule 8: read before you write)

- `crc32_stream` ← `compute_region_crc` (`crc.py:335`), `compute_group_crc` (`:544`) ← `check_regions` (`:830`) ← `CrcOperation` (Operations check / write, `crc.py:1567`), `write_crc_image` (`:1375`), `run_flow` CRC branch (`flow_execution_service.py:835`). No other caller in `s19_app/` (grep `crc32_stream`).
- `parse_crc_config` ← `read_crc_config` (`crc_config.py:292`), the Operations dialog (config editor text), `run_flow` CRC branch (`:810`). Its `except (KeyError, TypeError, ValueError)` already formats `CRC config is structurally invalid: {exc}`, so the new texts need no change there.
- `_resolve_manifest_entry` returns a resolved absolute path or `None` (`variant_execution_service.py:823-…`); `place_into_workarea` returns `resolved_destination / <claimed or reused name>` (`workspace.py:1223`, `:1339`): both resolved, so one `os.path.normcase(str(...))` key compares them.
- `FlowChangeRecord.change_doc_ref` is read by the flow report, the chain-set report (`flow_execution_service.py:1983`) and the flow-A2B change census (`diff_report_service.py:1166`, `:1190`, `:1243`, `:2192`, `:2220`).

## 4. Nodes touched (existing test node names)

**None renamed, none expected to change.** Census on the base tree:
- No test asserts the base texts `'reverse'`, `invalid literal for int()`, `expected an integer, got a boolean` for a CRC config (grep over `tests/`; the only `invalid literal` assert is the Patch Editor's, `test_tui_memory_patch.py:103`, another reader).
- `tests/test_crc_config.py::test_at044d_parse_rejections_one_named_error` (all parameters) asserts group rule fragments that keep their text; `output_bytes_nonint` / `output_bytes_bool` keep the `output_bytes` rule.
- No test or fixture uses `reverse: true` with an init that is not bit-symmetric (inits in `tests/`: 0x0, 0x0000, 0xFFFF, 0xFFFFFFFF; `test_crc_kernel.py:132` is the Designer engine): no CRC value pinned by an existing test changes.
- `tests/test_flow_external_step_b96.py::test_tc1804_confirmed_run_copies_output_into_session` and `::test_tc1804_fx_lane_pause_confirm_rerun` use absolute outputs and one run: unchanged.
- `tests/test_flow_crc_block.py::test_at126_malformed_config_fails_closed` asserts statuses only: unchanged.

## 5. New tests (E4 proposal)

Two new files, one per E4 group: `tests/test_b101_crc_model_and_reasons.py` (G1, the CRC rows) and `tests/test_b101_flow_ext_copy.py` (G2, the flow rows). `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` grows by 2, re-measured at integration. Test names start `test_r_<row id>_…` so `trace_check.py` binds them.
