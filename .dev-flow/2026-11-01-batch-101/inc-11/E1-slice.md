# Inc 11 — E1 slice: every file and function to change, counted and mapped

Base `b7b77c4`. Line numbers are on the base tree. Graph: `codewire/graph-inc11.md`. `app.py` entries depend on OR-1 (and the sort on OR-2), `E1-rulings.md` §4.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/validation/rules.py` | 1 changed constant: `RECOGNIZED_A2L_BLOCKS` (`:9-25`, 15 → 61 names); 1 new constant `INTERFACE_DATA_BLOCK = "IF_DATA"`; 2 changed: `_iter_sections` (`:400-409`), `validate_a2l_structure` (`:412-509`, the section loop `:482-509`) | R-VAL-032.1, .2, .3 |
| `s19_app/tui/issues_view.py` | 5 removed: `CURATED_STANDARD_A2L_BLOCKS` (`:121-159`), `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` (`:161-169`), `_UNRECOGNIZED_BLOCK_RE` (`:171-177`), `a2l_reclassified_severity` (`:180-241`), `adjust_counts_for_a2l_triage` (`:244-301`); 1 changed: `GroupedIssuesPanel.render_groups` (`:575-678`); module docstring paragraph (`:21-38`) and the imports left unused (`re`, `replace`, `Iterable`; `Optional` stays, `:468-478` use it) | R-TUI-042b.1, .2, .4, .6; R-TUI-025.6 |
| `s19_app/tui/a2l.py` | 2 changed: `extract_memory_segments` (`:931-983`), `render_curve_description` (`:3199-3296`); 2 new constants `PROGRAM_TYPE_WORDS`, `MEMORY_TYPE_WORDS`; 1 new helper `_memory_segment_record_words` | R-A2L-036.1 … .4, .6 … .12; R-A2L-034 (through `extract_a2l_tags`, unchanged); R-SEG-SRC.6 (through `_a2l_rows`, unchanged); R-A2L-120 … 123 |
| `s19_app/tui/app.py` **[OR-1]** | import block (`:142-148`, drop `adjust_counts_for_a2l_triage`); 2 changed: `update_validation_issues_view` (`:16489`, the wrapper at `:16539`, docstring `:16494-16497`, comment `:16531-16538`), `_render_validation_issues_groups` (`:16606`, the wrapper at `:16658`, comment `:16655-16657`); **[OR-2]** 1 changed: `_filtered_validation_issues` (`:16372-16378`) | R-TUI-025.2, R-TUI-042b.2; R-TUI-042b.5 [OR-2] |

**Totals:** 4 source files (at the cap; 3 without OR-1). Changed: 7 functions/methods + 1 constant (+1 with OR-2); new: 1 helper + 3 constants; removed: 2 functions + 3 constants. Graph nodes: 11 changed or new, 7 context.

Unchanged and only called or read: `parse_a2l_file` / `_parse_a2l_sections` (`a2l.py:149-250`, the section tree: `name`, `meta`, `start_line`, `lines`, `children`), `_strip_a2l_comments` (`:353`), `_split_line_respecting_quotes` (`:319`), `classify_address` (`:986`), `extract_a2l_tags` (`:2431`, `:2620`), `describe_curve_tag` (`:2845`, keeps `x_note` per point), `SplitJoinWindow._a2l_rows` (`segment_split_view.py:1559-1586`), `build_validation_report` (`services/validation_service.py:251`), `css_class_for_severity`, `IssueGroupHeader`, `IssueRow`, `_issues_page_size` (40).

## 2. Function map

| Function | File:line (base) | Change | Rows |
|---|---|---|---|
| `RECOGNIZED_A2L_BLOCKS` | `rules.py:9-25` | the 61 ASAM block names of `01-requirements.md` Definitions (a superset of the 15) | R-VAL-032.2 |
| `INTERFACE_DATA_BLOCK` (new) | `rules.py` | `"IF_DATA"` | R-VAL-032.3 |
| `_iter_sections` | `rules.py:400-409` | returns `list[tuple[dict, bool]]`: each section in the same pre-order with `inside_if_data` = any enclosing section's upper-case name is `IF_DATA` (the IF_DATA section itself: `False`). Only caller: `validate_a2l_structure` | R-VAL-032.3 |
| `validate_a2l_structure` | `rules.py:482-509` | the loop unpacks `(section, inside_if_data)`; the unknown-block issue is raised only when `not inside_if_data and section_name not in RECOGNIZED_A2L_BLOCKS`; message, severity, line number and the GROUP/FUNCTION reference pass unchanged | R-VAL-032.1, .2, .3 |
| `CURATED_STANDARD_A2L_BLOCKS`, `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION`, `_UNRECOGNIZED_BLOCK_RE`, `a2l_reclassified_severity`, `adjust_counts_for_a2l_triage` | `issues_view.py:121-301` | **removed** (D3-12). Callers: `render_groups` (same file), `app.py:146/16539/16658` [OR-1], `tests/test_tui_issues_triage_b94.py` (rewritten, §4) | R-TUI-042b.1, .2, .4, .6; R-TUI-025.2, .6 |
| `GroupedIssuesPanel.render_groups` | `issues_view.py:575-678` | group `window_issues` by `issue.severity` as given (no classification, no `dataclasses.replace`), never mount the justification `Static`; docstring loses the Inc-004 paragraph. Header counts stay `group_counts` verbatim | R-TUI-042b.1, .2, .4, .6 |
| `update_validation_issues_view` [OR-1] | `app.py:16489-16604` | `severity_counts` = the plain per-severity dict of `self._validation_issues` (no wrapper); docstring and comment lose the Inc-004 sentences | R-TUI-025.2 |
| `_render_validation_issues_groups` [OR-1] | `app.py:16606-16680` | `group_counts` = the plain per-severity dict of `filtered` (no wrapper) | R-TUI-042b.2 |
| `_filtered_validation_issues` [OR-2] | `app.py:16372-16378` | the returned list is `sorted(..., key=severity rank)` (stable; rank ERROR 0, WARNING 1, INFO 2) for every filter mode | R-TUI-042b.5 |
| `PROGRAM_TYPE_WORDS`, `MEMORY_TYPE_WORDS` (new) | `a2l.py`, beside `extract_memory_segments` | frozensets of the 8 and 7 words of the Definitions | R-A2L-036.8 … .11 |
| `_memory_segment_record_words` (new) | `a2l.py` | `(sec: dict) -> tuple[list[tuple[str, int]], list[str]]`: `texts` = `_strip_a2l_comments("\n".join([meta, *lines])).split("\n")`; returns the words of each text through `_split_line_respecting_quotes`, each with its text index, and `texts` | R-A2L-036.1 … .7 |
| `extract_memory_segments` | `a2l.py:931-983` | per MEMORY_SEGMENT: words from the helper; `block_name` = first word or `None`; the first `k ≥ 1` with words `k`, `k+1` both numbers (`int(w, 0)`, `ValueError` = not a number) gives `base`, `size`, `raw_first_line` = `texts[line of word k].strip()`, `offset` = word `k+2` as a number or `None`; `usage` / `kind` = the last program-type / memory-type word among words `1 … k-1`, else `None`; no pair → base, size, offset, usage, kind `None`, `raw_first_line` `""`. Entry keys and order unchanged; the recursive walk unchanged | R-A2L-036.1 … .4, .6 … .12; R-A2L-034; R-SEG-SRC.6 |
| `render_curve_description` | `a2l.py:3199-3296` | in the `points` branch: `all_index` = every point has `x_note`; if `all_index`, append `"  x: point index (axis points unavailable)"` before the header line and print no row suffix; otherwise keep the per-row suffix `   (<x_note>)` (mixed case) | R-A2L-120 … 123 |

## 3. Callers read (rule 8)

- `validate_a2l_structure` ← `validate_a2l_internal_issues` (`a2l.py:3563`) ← `build_validation_report` (`services/validation_service.py:336`), `tests/test_synth_release_case.py`; `validate_artifact_consistency` (`validation/engine.py`). `_iter_sections` has no other caller (grep).
- `RECOGNIZED_A2L_BLOCKS` is read only by `validate_a2l_structure` (grep `s19_app/`, `tests/`: one comment in `test_synth_release_case.py:124`).
- `adjust_counts_for_a2l_triage` ← `app.py:16539`, `:16658`; `a2l_reclassified_severity` ← `adjust_counts_for_a2l_triage`, `render_groups`; `CURATED_STANDARD_A2L_BLOCKS` / the justification ← `tests/test_tui_issues_triage_b94.py:48-49`. CSS class `issue-reclassify-note` has no rule in any `.tcss` (grep).
- `_filtered_validation_issues` ← `update_validation_issues_view` (`:16527`), `_render_validation_issues_groups` (`:16645`), `action_validation_issues_page_next` (`:16776`); tests `test_tui_app.py:655`, `test_tui_a2l_issue_recolor.py:218`, `test_validation_service_supplemental.py:212` (lengths and an error-mode first element: unaffected by a stable sort).
- `extract_memory_segments` ← `extract_a2l_tags` (`a2l.py:2431`; `memory_region` at `:2620` via `classify_address`), `parse_a2l_file` (`:2694`, the log's segment distribution), `segment_split_view._a2l_rows` (`:1576`; filters `base`/`size` `None`, names by `block_name or segment_<ii>`), re-export `a2l_parse.py:7`. `raw_first_line` is read only by `tests/test_a2l_enriched.py:216`.
- `render_curve_description` ← the description window (`d` on the A2L Explorer, `screens` modal with `markup=False`), `tests/test_a2l_curve_description.py`.

## 4. Nodes touched (existing test node names; none renamed)

| Node | What happens | Why |
|---|---|---|
| `tests/test_tui_issues_triage_b94.py::test_at_b94_14_fixture_triage_through_surface` | body rewritten: `software_a.a2l` through the surface shows 0 `A2L_UNRECOGNIZED_BLOCK`, `info=0`, no INFO header from A2L blocks; a planted `FROBNICATE` stays one WARNING row | the triage it pinned is removed (D3-12) |
| `tests/test_tui_issues_triage_b94.py::test_tc_b94_18_curated_set_and_engine_freeze` | body rewritten: each of the 21 former curated names gives no issue through the engine (as an ASAM name or inside IF_DATA); freeze arm kept as is → RED on the branch, GREEN after merge (OR-3) | the view constant is removed; the names' guarantee moves to the engine |
| `tests/test_tui_issues_triage_b94.py::test_tc_b94_19_panel_reclassification_matrix` | body rewritten: a curated-name WARNING renders under WARNINGS (`sev-warning`), no note, counts verbatim, hostile name literal (C-17 arm kept) | as above |
| module imports of `tests/test_tui_issues_triage_b94.py` (`:47-53`) | drop the two removed names | they no longer exist |
| `tests/test_synth_release_case.py::test_a2l_zero_issues` | `assert issues == []` replaces the all-unrecognized assertion; comment updated | the clean demo now has 0 A2L issues (the old assertion would pass vacuously) |
| `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` | body unchanged; the `_ENGINE_PATHS` comment gains the Inc 11 unfreeze note; RED on the branch, GREEN after merge (OR-3) | engine files change by plan |

Must stay GREEN unchanged (re-run at E5): `tests/test_a2l_enriched.py` TC-682 ×4 (P: 9/9 standard segments identical; `raw_first_line.split()[0]` still `DATA` for V161/V171), `tests/test_a2l_curve_description.py` (TC-1820: the new line contains `index (axis points unavailable)`), `tests/test_validation_a2l.py` ×2 (`UNKNOWN_BLOCK` still raised), `tests/test_tui_directionb.py::test_at_039b_groups_render_in_error_warning_info_order` and the `test_tc024_issues_*` family, `tests/test_tui_app.py` (filter test `:655`), `tests/test_tui_issues_view.py`, `tests/test_tui_snapshot.py` (Issues snapshot: 9 issues, one page — the stable sort does not change a one-page render), `tests/test_segment_split_window.py`, `tests/test_tui_a2l_issue_recolor.py`, `tests/test_validation_service_supplemental.py`, `tests/test_b100_session_reset.py`. The E4 tester re-runs the 7 files that seed `_validation_issues` (`test_tui_app.py`, `test_tui_directionb.py`, `test_tui_issues_view.py`, `test_tui_snapshot.py`, `test_validation_service_supplemental.py`, `test_b100_session_reset.py`, `test_tui_issues_triage_b94.py`) for the sort [OR-2].

## 5. New test files (proposed; names fixed at E4)

| Group | File | Covers |
|---|---|---|
| G1 engine (`rules.py`, `a2l.py`) | `tests/test_b101_a2l_blocks_and_segments.py` | R-VAL-032.1 … .3; R-A2L-036.*; R-A2L-034; R-A2L-120 … 123 |
| G2 Issues view (`issues_view.py`, `app.py`) | `tests/test_b101_issues_severity_view.py` | R-TUI-042b.1, .2, .4, .5, .6; R-TUI-025.2, .6 |
| G3 acceptance (cross-group, black-box) | `tests/test_b101_inc11_acceptance.py` | AT-I11-1 … AT-I11-5 (release demo generated into `tmp_path` by `tools/synth/make_release_case.py`, seed 20260001, 10 MB, as `tests/test_synth_release_case.py` does) |

`tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` is re-measured at integration (3 new files).
