# Inc 7 E4 - tester T7 hand-back (G-T-L, G-T-V, G-T-AT, retargets R1-R3)

Tree `s19_app-b103-inc7-tests`, branch `b103-inc7-tests`, base `63791549` (b103-base2 `9ffe019d` + Inc 7 records; no source change). One writer, no push. Tests only: the implementation does not exist at base, so no test has ever run GREEN here (see "What this does not prove").

## Files

| Group | File | Tests | Cases covered |
|---|---|---|---|
| G-T-L | `tests/test_b103_label_list.py` | 111 | 105 / 105 case ids + 6 extra (4 I-7 interface checks, the `.069` U+0007 control, the `.077/1` similar-line half) |
| G-T-V | `tests/test_b103_a2l_list_view.py` | 116 | 116 / 116 |
| G-T-AT | `tests/test_b103_a2l_list_at.py` | 10 | 10 / 10 |
| shared | `tests/support/b103_label_list.py` | helpers (each <= 40 lines) | oracle of the summary lines, held-seam helper `Hold`, `run_a2l` driver, case 08 builder |
| R1 | `tests/test_b103_clipboard_core.py`, `tests/test_b103_clipboard_windows.py` | retarget | Box A -> `#a2l_tag_find_input` (35 + 14 sites), census by OsClipboardInput kind |
| R2 | `tests/test_b103_clipboard_matrix.py`, `tests/test_b103_copy_paste_matrix.py`, `tests/test_b102_clipboard.py` | retarget | box maps; **`test_b103_clipboard_tail.py` NOT retargeted, see finding F-T7-5** |
| R3 | `tests/test_b100_session_reset.py`, `tests/test_tui_snapshot.py`, `tests/test_id_registry.py` | edit | 2 `SNAPSHOT_EXCLUSIONS`; live `_batch103_inc7_a2l_drift_marks` (F-R11-1); `EXPECTED_SCANNED_TEST_FILES` 312 -> 316 (3 test modules + 1 support module, counted) |

`02-test-cases-T.md` lists every test with its case id and the requirement's negative control (237 rows). The controls were not run (no implementation to mutate; HT-09: mutants on copies at integration/E5). `serial_timing` is on `.078/3` and `.035/1` only (section 6.4). Test names carry the case id; no markup is parsed from fixtures (hostile names are invented). No test reads or writes the OS clipboard (`read_os_clipboard` patched, the app clipboard is the seam). Writes: LF, 0 CR in every touched file.

## trace_check (from the repository root)

```
python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-7/01-requirements.md --tests tests --ids "R-A2L-LIST.*" "R-A2L-007.*" "R-PASTE.1" "R-PASTE.29" "R-TUI-043.4" "R-TUI-042a.4" "R-TUI-037.*" "R-TUI-069.*"
trace_check: 96 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```

## RED on base 63791549 (rtx, HT-02 env, `-n 2`, `timeout 300` per run, HOME basename `runner_iso`)

First line of every transcript: `s19_app.__file__ = <runner-home>/work/zq-e4-7-t7/tree/s19_app/__init__.py` (the base tree). Host load during the V run: `load average: 8.91, 8.78, 7.66` (shared host; the two timing arms were not decided there).

| File | Result on base | Reading |
|---|---|---|
| `test_b103_label_list.py` (111) | `1 failed, 2 passed, 108 errors in 20.43s` | 108 ERROR at setup: `ModuleNotFoundError: s19_app.tui.a2l_label_list` (the module is new; an import error proves nothing, so the module is imported inside the fixture, not at collection). 1 FAILED: `test_r_paste_1_1` (the I-1 hook `_take_paste` does not exist). 2 PASSED by design: `test_r_tui_043_4_1`, `test_r_paste_29_1` (the Load box on base already takes the first line; they need no new module). |
| `test_b103_a2l_list_view.py` (116) | 5 chunks of 24, total 108 RED (failed or error), 8 PASSED | PASSED by design (behaviour exists and is kept): `test_r_tui_037_1_{1,2,3}`, `test_r_tui_037_2_{1,2,3}` (R-TUI-037.1/.2 kept for the short body: 42/54/77 and 32/42/59 are base widths), `test_r_a2l_list_082_{1,2}` (base caps the card at 5 lines at every size). Every other node fails on a missing id (`#a2l_list_chips`, `#a2l_filter_mode_tag`, ...), on a base summary text, or on the missing list mode. |
| `test_b103_a2l_list_at.py` (10) | `10 failed in 96.09s` | all RED |

Chunk lines of the V run (`-q --tb=no`): `8 failed, 16 errors in 84.03s` / `12 failed, 12 errors in 135.78s` / `24 failed in 220.52s` / `16 failed, 8 passed in 241.17s` / `20 failed in 142.18s`.

Vacuity found and fixed before the final run: `test_r_a2l_list_031_4` (enter on a missing row) passed on base because base has no list mode - it now first asserts 12 list rows with `✗ MAP_0024` at #7; `test_r_tui_069_6_1` passed on base (ceiling 8, base cap 5) - it now shows a 7-line card and requires height 6..8; `.083/1-3` now assert list mode first; the text-mode canon rows `R-A2L-007.1/.6/.7/.8` now also assert the scope change (a list typed in the same mode is list mode, rows kept) so they cannot pass on base.

## Retargets: results on base

| Node set | Result on base | Reading |
|---|---|---|
| `test_b103_clipboard_core.py`, whole file (retargeted: `_box_a` + 34 inline sites, census) | `60 passed` + `25 passed, 2 skipped` | GREEN by design: `#a2l_tag_find_input` is a stock `OsClipboardInput` on base. The 13 nodes of E1-slice 5.1 (rows 1-8) are among them; the census (rows 6, 7) is GREEN at 40 on base and stays 40 after the filter box becomes a `ListAwareFilterInput` because the census now counts subclasses of OsClipboardInput as that kind. |
| `test_b103_clipboard_matrix.py::...walk_single_line_round_trip[a2l]` | `1 passed` | GREEN by design |
| `test_b103_copy_paste_matrix.py` cells `AT-I1b-{1,2,3,6,7}/1-T1-P1` | `5 passed` | GREEN by design |
| `test_b102_clipboard.py` (TC-B102-01 box map) | `20 passed` | GREEN by design |
| `test_b103_clipboard_windows.py` (`_box_a` + 14 WinCI-only sites) | not runnable on Linux (all skip) | **unverified**; see F-T7-5 |
| `test_b103_clipboard_tail.py` | original file: 3 nodes pass; with `:472` / `:2702` retargeted: 3 nodes FAIL on base | **not retargeted**, F-T7-5 |
| `test_b100_session_reset.py` TC-B100-09 | 2 failed, 3 passed - the SAME 2 fail with the unedited base file (`_right_gesture` unclassified, `_quit_pending` census) | pre-existing on base, not caused by Inc 7 (F-T7-6) |
| `test_id_registry.py` (TC-607) | 12 passed (316 scanned = 312 + 4) | RED without the bump |
| `test_tui_snapshot.py` six `a2l-*` cells | 6 xfailed with the new live mark | the cells fail off the canonical CI (HT-09); the mark keeps them non-fatal until the CI regen; retire it then |
| `test_b103_a2l_filter_teardown.py` | `1 passed` | GREEN, must stay so (V10 guard) |

No assertion was weakened: each retargeted file's diff is a pure `a2l_tags_filter_input` -> `a2l_tag_find_input` substitution (every removed line has its twin added, checked with the id normalised) plus, in the core file only, the census change (a class-hierarchy pass added to the AST census; the asserted counts 40 / 0 / 7 / 0 are unchanged). The laws `test_suite_hygiene.py` (70 passed; the one failure is an artefact of the partial tree shipped to the runner), `test_deps_seam_law.py`, `test_no_private_tokens.py` pass with the new files.

## Findings (requirement vs graph/case disagreements and gaps)

- **F-T7-1 (R-A2L-LIST.076).** The threshold puts U+0085 into a name that a PASTE surface shows (preview row, similar line). `parse_parameter_list` splits on `str.split()`, and U+0085 is whitespace, so a pasted name can never hold it; only a tag name from the A2L can. Tests use the full name (3 U+FFFD) where the entry is built directly (row, card, missing line, dropdown row) and a name without U+0085 (2 U+FFFD) for the preview and similar lines.
- **F-T7-2 (R-A2L-LIST.025/3).** "the same text with mode All, so nothing matches" is contradictory if the fixture tag is named by that text (mode All matches it). The test renames the fixture tag before the mode-All check.
- **F-T7-3 (census, E3A-01 rows 6/7).** The rows say 40 boxes. The paste window adds an add line (an OsClipboardInput kind, 41 if constructed as a separate call) and a `CappedTextArea` (a multi-line box, so `test_r_paste_18_8` would count 8, not 7). That test is not in E3's retarget list. The retargeted census keeps 40 / 7 as written; the integrator decides the counts when the module exists.
- **F-T7-4 (law guard).** I-3 obligation 5 says to extend "the markup AST guard's file list" to `a2l_label_list.py`; no test with such a list was found in `tests/` (`git grep` for `label_match.py` finds only `test_id_registry.py`). No edit made; a guard may need to be written.
- **F-T7-5 (HIGH, retarget).** Retargeting the tail's two Box A sites (`test_b103_clipboard_tail.py` `_show_box` `:472`, `_unrelated_view_box_observation.drive` `:2702`) to `#a2l_tag_find_input` turns `test_r_copy_08_2`, `test_r_copy_07_7`, `test_r_copy_25_2` RED on base (`clipboard arm failures: input-right` / `input`); the original file passes them. Likely cause: the find box sits in the filter row's second line and its content region is 3 lines (P3: `#a2l_tags_filters` region 4, content 3), so a real hit-test on it can miss. E3R2 keeps that row, so the same may hold after Inc 7, and the 14 WinCI-only windows sites may share it (not runnable on Linux). Left on the filter box in the tail; the orchestrator must rule: another Box A, or a layout that keeps the find box clickable.
- **F-T7-6 (base).** `test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` and `..._twelve_b_adds_exactly_the_quit_flag` fail on the unedited base file (`_right_gesture` not classified in `SNAPSHOT_EXCLUSIONS`). Not touched.

## What this does not prove (open gaps, fail loud)

- No test has met an implementation: every one is RED or GREEN-by-design on base only. Assumptions read from the graph and not pinned by I-7: the ribbon shares `#a2l_list_counts` with the counts (no own id in I-7); `#a2l_list_chips` is one Static whose text lines are the chips lines; the dropdown paints title, rows, key line, rank line as separate lines in that order; `#a2l_filter_all` gets class `-on`; the paste window's debounce goes through the screen's own `set_timer` (`.086`); `.064` reads the highlight as a Content span style. A wrong assumption shows as a RED at integration to be ruled finding by finding, never by weakening a test.
- Partial by construction: `.010/1` reads the table's rendered line of the fixed columns, not every row; `.036/3-5` drive `_refresh_a2l_values_after_write` after changing an image byte (the route's function, not the Save project dialog); `.056/1` attaches a copy of case 08's A2L with one MEASUREMENT block cloned as `MAP_0024`; the negative arms of `.084-.086` wait 0.6 s after releasing the held worker (an absent-guard run shows as a worker error, `app._exception`, or a painted result).
- The R-A2L-LIST.035/.078 timing arms ran only as RED on a host at load 9; their time bounds were not decided.
- Mutation controls: not run.

Scratch on rtx (`~/work/zq-e4-7-t7/`) deleted at the end (PF-04).
