# Inc 8 — E1 slice: every file and function to change, counted and mapped

Base `e266395`. Line numbers are on the base tree. Graph: `codewire/graph-inc8.md` (12 changed or new nodes, 7 context nodes after E3 round 1). E3 round 1 changes are marked with the finding id in brackets.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/operations/crc.py` | 1 changed: `crc32_stream` (`:155`, seed at `:211`) | R-CRC-ENGINE-001.1, R-CRC-ENGINE-002.2 |
| `s19_app/tui/operations/crc_config.py` | 3 changed: `_build_config` (`:448`), `_build_group` (`:537`), `parse_crc_config` (`:385`, [S-6]); 2 new: `_required_field`, `_number_field`; 2 new constants: `DESIGNER_TEMPLATE_RULE`, `VALUE_CLIP = 64` [S-1] | R-CRC-CONFIG-001.10, .11, .16, .17; R-FLOW-CRC.4 |
| `s19_app/tui/services/flow_execution_service.py` | 4 changed: `run_flow` (`:186`), `run_chain_set` (its nested `_run_one`, `:1825`) [S-2], `compose_chain_set_report` (Input provenance, `:1946`) [S-2], `ChainRunOutcome` (one field, `:1587`) [S-2]; 1 new: `_resolve_block_ref` | R-FLOW-EXT.2, .9, .10, .11, .12, .13, .14; R-FLOW-CRC.1, .3, .4, .9 |
| `s19_app/tui/services/flow_model.py` [S-2] | 1 changed: `FlowRunResult` (one field, `:748`) | R-FLOW-EXT.12, .13 |

**Totals:** **4 source files — at the cap** (E3 round 1 added `flow_model.py`: the chain-set report needs the run's in-place reads, and `FlowRunResult` lives there; no other increment of the plan owns it). 7 changed functions or classes, 3 new functions, 3 new constants or fields. Unchanged and only called: `read_crc_config_text` (now called by the Flow CRC block, [S-5]), `check_regions`, `inject_crcs`, `write_crc_image`, `crc_kernel.crc_stream` / `crc_lut`, `_resolve_manifest_entry`, `place_into_workarea` / `copy_into_workarea`, `emit_template`.

## 2. Function map

| Function | File:line (base) | Change | Rows |
|---|---|---|---|
| `crc32_stream` | `crc.py:155-224` | seed `reg = init & _MASK32` for both values of `reverse` (base: `_reflect(init, 32)` when `reverse`); the byte and output reflection and the zlib fast path stay | R-CRC-ENGINE-001.1, 002.2 |
| `_build_config` | `crc_config.py:448-534` | (1) first statement: a Designer template shape raises `ValueError(DESIGNER_TEMPLATE_RULE)`; (2) `reverse`, the region fields and `polynomial` / `init` / `final_xor` read through `_required_field` / `_number_field`; the check order is otherwise unchanged | R-CRC-CONFIG-001.10, .11, .16 |
| `_build_group` | `crc_config.py:537-650` | `regions` read through `_required_field`; span `start` / `end` and `output_address` through `_number_field`; `output_bytes` keeps its own rule text | R-CRC-CONFIG-001.10, .11 |
| `_required_field` (new) | `crc_config.py` | `(container: dict, key: str) -> Any`; a missing key raises `ValueError(f"field '{key}' is missing")` | R-CRC-CONFIG-001.10 |
| `_number_field` (new) | `crc_config.py` | `(container: dict, key: str) -> int`; `_required_field` then `_parse_int`; a `ValueError` from `_parse_int` becomes `ValueError(f"field '{key}' is not a number: {clip}")`, where `clip` = `json.dumps(value)` cut to its first `VALUE_CLIP` (64) characters + `…` when longer [S-1] | R-CRC-CONFIG-001.10, .11 |
| `DESIGNER_TEMPLATE_RULE` (new constant) | `crc_config.py` | `"a CRC Designer template is not a CRC config - it has no regions or groups"` | R-CRC-CONFIG-001.16 |
| `parse_crc_config` [S-6] | `crc_config.py:432-435` | the `json.loads` except also catches `RecursionError` → `CRC config is not valid JSON: nesting too deep` | R-CRC-CONFIG-001.17 |
| `run_flow` | `flow_execution_service.py:186-1240` | (1) a per-run `rebinds: dict[str, Path]`; (2) the 7 `_resolve_manifest_entry` calls of the block branches (`:315`, `:345`, `:427`, `:448`, `:734`, `:798`, `:942`) go through `_resolve_block_ref`, and each in-place read is appended to `result.in_place_reads` as `(block index, label, ref, copy)` [S-2]; (3) PATCH branch: `change_doc_ref` of each `FlowChangeRecord` / `FlowRefusal` (`:502`, `:519`) is the copy's file name when the document was read in place, else the block's ref as typed; `a2l_ref` likewise for the effective A2L (the PATCH's own, or the LOAD's `source_a2l_ref` set at `:366`) [A-1]; (4) external-step branch: a relative log or output path that climbs above the project folder stops the block (R-FLOW-EXT.14) [S-3]; else a relative `source_path` is joined under `ctx.project_dir` (`:1092`); after the copy, `rebinds[normcase(<copy folder>/<output file name>)] = copied`; (5) CRC branch: the config is read with `read_crc_config_text(str(path), ctx.project_dir)` in place of `path.read_text` (`:810-812`); its error goes the R-FLOW-CRC.4 way [S-5]; (6) after each block, whatever path it ended by (also `continue` and the per-block `except`), the block's `BlockResult.summary` gets one read suffix per entry of `result.in_place_reads` for that block, in read order [A-1, A-2, S-2] | R-FLOW-EXT.2, .9, .10, .11, .12, .14; R-FLOW-CRC.1, .3, .4, .9 |
| `_resolve_block_ref` (new) | `flow_execution_service.py` | `(project_dir, ref, label, issues, rebinds) -> tuple[Optional[Path], bool]`: `_resolve_manifest_entry` on the typed ref **first**; then the rebind map; a copy found is passed through `_resolve_manifest_entry(project_dir, copy.name, label, issues)` (the same per-read link check) [S-4]; `True` only when the copy is another file | R-FLOW-EXT.9, .10, .12 |
| `run_chain_set._run_one` [S-2] | `flow_execution_service.py:1825-1864` | after `execute`, each LOAD input whose block has an `in_place_reads` entry with label `SourceBlock.image_ref` gets `(ref, str(copy))` in `inputs` and `in_place_inputs[j] = copy.name` (1-based input index) | R-FLOW-EXT.13 |
| `ChainRunOutcome` [S-2] | `flow_execution_service.py:1587` | new field `in_place_inputs: Dict[int, str] = {}` (default empty; `inputs` keeps its 2-tuples, which `tests/test_flow_chainset_b94.py:212`, `:298` unpack) | R-FLOW-EXT.13 |
| `compose_chain_set_report` [S-2] | `flow_execution_service.py:1946-1953` | an Input provenance line whose index is in `in_place_inputs` ends with ` · read <copy> in place of <ref>` (both through `md_safe`) | R-FLOW-EXT.13 |
| `FlowRunResult` [S-2] | `flow_model.py:748` | new field `in_place_reads: List[Tuple[int, str, str, Path]] = []` (block index, resolution label, typed ref, copy) | R-FLOW-EXT.12, .13 |

Not changed, by decision: `workspace.place_into_workarea` (D-2), `variant_execution_service._resolve_manifest_entry` (no Inc 4 dependency), `crc_designer_model` (D-4), `_chain_inputs` (`:1695`, still resolves before the run; `_run_one` corrects the rebound entries after it, [S-2]), `read_crc_config_text` (a decode error still raises inside the Flow CRC block's `try`, caught by per-block isolation; backlog BL-I8-5 keeps the decode half).

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
- [S-2] `tests/test_flow_chainset_b94.py::test_tc_b94_30_chain_set_report_provenance_lines`, `::test_tc_b94_30_compose_is_deterministic_and_md_safe` and the tests that unpack `outcome.inputs` (`:212`, `:251`, `:298`): no input is read in place there, `inputs` keeps its 2-tuples and the line form is unchanged for an unbound input.
- [A-1, S-2] The read suffix appears only when a copy is read in place; no existing confirmed run lands its copy on another name (architect E3 §4), so no existing summary assertion changes.

## 5. New tests (E4 proposal)

Two new files, one per E4 group: `tests/test_b101_crc_model_and_reasons.py` (G1, the CRC rows) and `tests/test_b101_flow_ext_copy.py` (G2, the flow rows). `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` grows by 2, re-measured at integration. Test names start `test_r_<row id>_…` so `trace_check.py` binds them.
