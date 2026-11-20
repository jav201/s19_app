# Unit FA-D10 — one shared bulk describe for both pickers [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`<sha after FA-2>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed diagnosis and design (DX-F4, R5-F6, operator D10; re-checked in code)
- `s19_app/tui/app/file_load.py:1098-1099` (`_prepare_a2l_attach_snapshot_inner`) runs `describe_definitions(names, a2l_data)` twice with identical input: once for the Check picker, once for the Patch picker.
- `Definition` is a frozen dataclass (`a2l_definition.py:168`), and both results are wrapped in `MappingProxyType`, so one result can back both snapshots.
- All three routes (direct attach, image+A2L, project) use this producer (`file_load.py:956,1757`, `project_load.py:1610`).
- Measured cost: 16–19 s of the 55 s case_06 attach.
- **Operator D10:** one bulk describe per generation, shared read-only by both pickers (R-A2L-REFRESH.037 amended in `E4R/01-requirements.md`; R-PICKER-CORRECT.018 read as "at most one per picker").

## Files you may edit
`s19_app/tui/app/file_load.py`, `tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py`.

## Rows
| row | change | negative control (scratch copy) |
|---|---|---|
| 1 | In `_prepare_a2l_attach_snapshot_inner`, call `definitions = describe_definitions(names, a2l_data)` once, build one `MappingProxyType(definitions)`, and pass that same object to both `A2LPickerSnapshot(..., definitions=...)`. Update the docstring of `_prepare_a2l_attach_snapshot` ("describe_definitions runs twice…" → once, shared read-only; cite R-A2L-REFRESH.037 E4R / D10). | Restore the second describe → rows 2–5 RED |
| 2 | `tests/test_alp_inc2_a2l_attach.py`: every worker-describe count asserting 2 per accepted generation becomes 1. Grep `== 2` near `describe` (at ca5ed3bc: ~915 `names.count("describe") == 2` in `test_r029_worker_snapshot`; ~1955, 1979, 2058, 2081, 2092 in `test_r037_picker_snapshot_reuse`; ~2645, 2666 in `test_at_alp_i2_3_same_path_picker_generations`; FA-2 may shift them by a few lines) and verify each one counts the producer's bulk describes, not something else. Update the docstrings that say "once per picker" (~1946 in `test_r037_picker_snapshot_reuse`, ~2619 in `test_at_alp_i2_2_case06_keys_and_progress`) to "one shared describe per generation". | as row 1 |
| 3 | `tests/test_alp_inc3_snapshot_parity.py`: the same at ~546, 566, 589, 612 (`len(constructions["describe"]) == 2`), after checking each counts the producer's describes. (The `names.count("describe") == 2` line is the attach file's ~915, row 2.) | as row 1 |
| 4 | In `test_r037_picker_snapshot_reuse` (initial-population arm), add the assertion `snapshots["check"].definitions is snapshots["patch"].definitions` (read how the test reaches the accepted snapshots). | Scratch: build two separate `MappingProxyType(dict(definitions))` → RED |
| 5 | In the same arm, add a `_describe_one` build counter (reuse the spy pattern of `_install_counters` in `tests/test_alp_a2l_occupancy.py`): exactly 1 build per requested name for one accepted attach (2 today). | as row 1 |

## Report extras
For rows 2–3, list each changed line with one sentence on what it counts. If a `== 2` counts something other than the producer's bulk describes, leave it and say why.

## Nodes you may run (`timeout 300`)
- `-n 4 -m "not serial_timing and not slow"` on `tests/test_alp_inc2_a2l_attach.py` and `tests/test_alp_inc3_snapshot_parity.py`;
- `-n 0`: `tests/test_alp_inc2_a2l_attach.py -k "r029 or r037 or at_alp_i2_3"` and `tests/test_alp_inc3_snapshot_parity.py -k "describe"` (if that selects 0 nodes, name the nodes you changed explicitly);
- `tests/test_b103_picker_model.py tests/test_b103_picker_editor.py` (`-n 4`; picker regression, no edits).
