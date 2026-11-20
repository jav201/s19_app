# Unit FA-IDX1 — D2: unresolved array-like records are open-ended [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`ec8e7bd4`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed diagnosis (R5-F1, re-checked by the architect) and design (operator D2)
- **The code contradicts its own ruling.** `_build_occupancy_index` (`s19_app/tui/a2l_definition.py` ~3923-3941) reads the upper end from `entry_cache`, then `definitions_by_position`, and otherwise from **`entry[4]`, the parser's provisional tag length**. It only marks `last = None` when that length is `None` or below 1.
  - Ruling D-4 (`inc-1/E1-rulings.md:20`), the graph example R-A2L-DEF.140/11 and the function's own docstring require an unresolved array-like or AXIS_PTS record to be open-ended.
  - If the describer's final length ever exceeds the provisional one, a real overlap is pruned and `encode` can write into another object's bytes.
- **Design.** Reorder the branches:
  1. cached final;
  2. requested definition;
  3. `entry[2] == "AXIS_PTS" or is_array_entry(entry)` ⇒ `last = None`;
  4. otherwise `entry[4]` (≥ 1 → `first + len − 1`, else the point `first`).

  Keep the known-final-`None` → point rule for (1)/(2). Nothing else changes; FA-IDX2 changes the traversal later.

## Files you may edit
`s19_app/tui/a2l_definition.py` (only `_build_occupancy_index` and its docstring), `tests/test_alp_a2l_occupancy.py`.

## Rows
| row | change | negative control (scratch) |
|---|---|---|
| 1 | The branch reorder above, with the docstring made consistent (it already describes the intended rule). | restore the old order → rows 2 and 3 RED |
| 2 | New test `test_r_a2l_def_166_1_unresolved_array_is_open_ended`: call `_build_occupancy_index` directly with synthetic entries, as the `.157` tests do (`_assert_single_interval`). Use an array-like CHARACTERISTIC with provisional length 4 (with `is_array_entry` → True for it) and assert its record's upper end `is None`. The same entry requested (in `definitions_by_position`, final length 8) gets `first + 7`; a scalar keeps `first + len − 1`; an AXIS_PTS with no cache gets `None`. Cites R-A2L-DEF.166 (E4R; graph example .140/11). | as row 1 |
| 3 | New test `test_r_a2l_def_166_2_equivalence_with_global_scan`:<br>- **Population:** 4,000 seeded trials (`random.Random(0xA21)`), each with up to 40 synthetic entries mixing CHARACTERISTIC/MEASUREMENT/AXIS_PTS/BLOB. Lengths come from {None, 0, 1, 2, 4, 16, 64, 1,048,577}; addresses include 0 and 0xFFFFFFFF; add same-span aliases, homonyms, and array-like entries whose **final** length (given by an injected `materialize`) exceeds the provisional one.<br>- **Under test:** `_shared_with(definition, index, own_position, mask_of, materialize)` with the product index.<br>- **Reference:** extend the file's `_reference_next_overlap` to use the final lengths, walk order, own position excluded, mask exemption.<br>- Assert 0 differences and print the query count. Cites R-A2L-DEF.166. | as row 1 (expect differences > 0) |
| 4 | **Reachability attempt (R5's case):** a CURVE or MAP whose `COM_AXIS` refers to a real AXIS_PTS, plus a standing `DATA_SIZE`/`LENGTH` smaller than the describer's final span, and a VALUE `V` inside the final span but beyond the standing size (helpers `curve`, `axis`, `axis_pts`, `rl`, `inline` in `tests/support/b103_a2l_arrays.py`). Parse it, then compare the tag length with `describe_definition(curve).byte_length`.<br>- If final > tag length, the case is REACHABLE: add `test_r_a2l_def_166_3_write_safety_curve_com_axis`, asserting `describe_definition("V", a2l).shared_with == <curve>` and the encode refusal `A2L-DEF-OVERLAP` (see how `.140` tests encode).<br>- If not, the case is UNREACHABLE: add no test, and paste the two lengths and the A2L text into REPORT.md. | REACHABLE: old order → RED |
| 5 | **Measurement only (no test):** in `../scratch/narrow.py`, parse case_06 and run `describe_definitions([last_name], a2l)` with the `_install_counters` counters. Record materializations, builds and seconds before (the HEAD copy) and after your change, with the load (`uptime`). | — |

## Nodes you may run (`timeout 300`)
- `tests/test_alp_a2l_occupancy.py -n 4`;
- `tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"`;
- `tests/test_b103_a2l_definition_arrays_write.py -k "138 or 139 or 140" -n 4`;
- `tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"`;
- the scratch script of row 5 (one run each).

STOP and report if any existing node turns RED: D2 changes candidate sets, and the architect rules each such RED; never loosen it.
