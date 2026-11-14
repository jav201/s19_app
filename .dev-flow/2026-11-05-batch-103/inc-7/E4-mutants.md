# Inc 7 E4 - mutant run (MU7, relevo-13)

Model claude-sonnet-5-5 (tester role). Product under test: `b103-inc7` tip `82856fd8` (Inc 7 integrated; step 0 of this brief closed E4 GREEN at `7463c9e3`, see `E4-integration.md` Pass 4). HT-09: every mutant ran on a COPY, a `git archive` of `82856fd8` (with `tools/`; `.dev-flow` and `docs` left out) under the runner scratch `~/work/zq-mu7/runs/<id>` (a fresh `cp -a` per mutant, deleted after). HT-02 environment (HOME basename `<runner-home>`, read from `RUNNER_HOME_NAME` by `drive.py`, HT-11), `-p no:cacheprovider`, `-n 2`, `timeout 300`, `-x`; the baseline ran on the unmutated copy first. The driver waits while the 1-min load is above 4 (HT-08); one pause (load 4.13) happened and was retried, no timeout was recorded as a result.

Selection per mutant (the driver's `k` field): the requirement family's nodes in `test_b103_label_list.py` (L) then in `test_b103_a2l_list_view.py` (V) by `-k <ids>`, plus the file or node named for the mutant where the brief names one (`test_b103_a2l_filter_teardown.py`, the row-17 node). Baseline on the unmutated copy: `2 passed` in L and in V for `-k "051 or 017"` (14 s each). Survivors were then judged against their whole family and fixed with new nodes (below).

## Result

**50 mutants: 37 killed by the shipped nodes, 5 survived and are now killed by 3 new nodes, 7 are equivalent (argued), 1 survived and is argued MINOR.** Final killed 42 / 50; 0 timeouts. The 3 new nodes are GREEN on the tree (`3 passed`, load 0.95, the `GREEN` row of `evidence-e4-mut/results-pass3b.tsv`) and RED on their mutants (table).

The mutants the brief named. Cap line `.051` removed (MU01a) and off by one (MU01b): killed by `test_r_a2l_list_051_1` / `_2`. Found count without hidden (MU02): killed by `test_r_a2l_list_017_2` (V). `tag is None` (MU03): killed by `test_r_a2l_list_078_2`. Chips and FILTER tag on unload (MU04, MU25): killed by `test_r_a2l_list_008_3`. The `is_running` checks of the after-close arms (MU05a `_install`, MU05b `_deliver`) ARE seen: killed by `test_r_a2l_list_084_1` / `_085_1` (the delivered matches reach the callback when the check is gone). The P-002 guard (MU06a): killed by `test_b103_a2l_filter_teardown.py::test_r_copy_26_1_...`. List-mode columns back to Address/Len (MU07a header only, MU07b header and cells): killed by `test_r_a2l_list_009_1`. Hostile names painted raw (MU08f): killed by `test_r_a2l_list_076_3`.

## Mutant table

Result column: killed = by an original node; killed (new) = survived the shipped nodes, killed by a node of `tests/test_b103_inc7_mu_survivors.py`. The edit of each id is the `old`/`new` pair in `evidence-e4-mut/mutants.json` (MU07b adds the `also` edit of `list_row_cells`); the driver is `evidence-e4-mut/drive.py`; the raw runner lines are `evidence-e4-mut/results-pass*.tsv` (pass 3a also holds a contaminated MU22 run, see Method notes).

| Id | Mutant (requirement) | Result | First failing node | 1-min load |
|---|---|---|---|---|
| MU01a | R-A2L-LIST.051 cap line removed | killed | `test_b103_label_list.py::test_r_a2l_list_051_1` | 0.83 |
| MU01b | R-A2L-LIST.051 cap line off by one (at exactly 10) | killed | `test_b103_label_list.py::test_r_a2l_list_051_2` | 1.09 |
| MU01c | R-A2L-LIST.051 cap 11 lines | equivalent | `(none; argued below)` |  |
| MU02 | R-A2L-LIST.017 found count without hidden | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_017_2` | 1.76 |
| MU03 | R-A2L-LIST.015 tag-is-None branch (duplicate of a missing name) | killed | `test_b103_label_list.py::test_r_a2l_list_078_2` | 2.09 |
| MU04 | R-A2L-LIST.008/3 .023/2 chips and FILTER tag not repainted on unload | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_008_3` | 1.15 |
| MU05a | R-A2L-LIST.084 is_running check in _install dropped | killed | `test_b103_label_list.py::test_r_a2l_list_084_1` | 1.88 |
| MU05b | R-A2L-LIST.084/.085 is_running check in _deliver dropped | killed | `test_b103_label_list.py::test_r_a2l_list_085_1` | 1.81 |
| MU05c | R-A2L-LIST.085/.086 is_running check of the paste window painters dropped | killed (new) | `test_b103_inc7_mu_survivors.py::test_the_paste_window_paints_nothing_once_the_app_has_stopped` | 1.52 |
| MU06a | P-002 guard in _schedule_a2l_filter_refresh dropped | killed | `test_b103_a2l_filter_teardown.py::test_r_copy_26_1_filter_refresh_due_after_teardown_is_dropped` | 2.17 |
| MU06b | row-17 guard of _paint_a2l_filter_chips dropped | killed | `test_tui_app.py::test_refresh_a2l_filtered_tags_resets_anchor` | 2.23 |
| MU07a | R-A2L-LIST.009/.010 D-4 B: Address/Len first again | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_009_1` | 1.70 |
| MU07b | R-A2L-LIST.009/.010 D-4 B: Address/Len first again, cells reordered with the header | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_009_1` | 1.98 |
| MU08a | R-A2L-LIST.076 markup=False dropped on the viewer chips | equivalent | `(none; argued below)` |  |
| MU08b | R-A2L-LIST.076 markup=False dropped on the viewer missing line | equivalent | `(none; argued below)` |  |
| MU08c | R-A2L-LIST.076 markup=False dropped on the window missing line | equivalent | `(none; argued below)` |  |
| MU08d | R-A2L-LIST.076/.077 markup=False dropped on the similar line | equivalent | `(none; argued below)` |  |
| MU08e | R-A2L-LIST.076 similar line painted as a str | equivalent | `(none; argued below)` |  |
| MU08f | R-A2L-LIST.076/.077 missing line paints the raw name | killed | `test_b103_label_list.py::test_r_a2l_list_076_3` | 3.64 |
| MU09 | R-A2L-LIST.002 name matched case-folded (tag side) | killed | `test_b103_label_list.py::test_r_a2l_list_002_3` | 3.64 |
| MU10 | R-A2L-LIST.003 no duplicate check | killed | `test_b103_label_list.py::test_r_a2l_list_003_1` | 3.66 |
| MU11 | R-A2L-LIST.004 missing treated as found | killed | `test_b103_label_list.py::test_r_a2l_list_004_2` | 3.66 |
| MU12 | R-A2L-LIST.005 mode ignored in list mode | killed | `test_b103_label_list.py::test_r_a2l_list_005_2` | 3.69 |
| MU13 | R-A2L-LIST.013 Kind: char_type ignored | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_013_2` | 3.64 |
| MU14 | R-A2L-LIST.017 hidden counted as missing | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_017_2` | 3.64 |
| MU15 | R-A2L-LIST.018 ribbon with no budget | killed | `test_b103_label_list.py::test_r_a2l_list_046_2` | 3.60 |
| MU16a | R-A2L-LIST.024 missing line with no cap | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_024_1` | 3.62 |
| MU16b | R-A2L-LIST.024 duplicates line with no cap | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_024_2` | 3.82 |
| MU17 | R-A2L-LIST.046 viewer ribbon budget 80 -> 60 | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_018_2` | 3.81 |
| MU18a | R-A2L-LIST.063 dropdown 20 rows | killed | `test_b103_label_list.py::test_r_a2l_list_063_1` | 3.78 |
| MU18b | R-A2L-LIST.065 total never 20+ | killed | `test_b103_label_list.py::test_r_a2l_list_065_2` | 3.80 |
| MU19a | R-A2L-LIST.054 apply with no names dismisses [] | equivalent | `(none; argued below)` |  |
| MU19b | R-A2L-LIST.070 esc closes the dropdown and the window | killed | `test_b103_label_list.py::test_r_a2l_list_070_2` | 3.28 |
| MU20 | R-A2L-LIST.057 appended without a new line | killed | `test_b103_label_list.py::test_r_a2l_list_057_2` | 3.21 |
| MU21a | R-A2L-LIST.001/.006 list text from one name | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_062_1` | 2.99 |
| MU21b | R-A2L-LIST.001/.006 list text needs three names | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_062_2` | 3.22 |
| MU22a | R-A2L-LIST.082 wide regime from 160 | killed (new) | `test_b103_inc7_mu_survivors.py::test_the_body_regime_changes_exactly_at_its_thresholds` | 1.86 |
| MU22b | R-A2L-LIST.083/R-TUI-037 short body below 28 | killed (new) | `test_b103_inc7_mu_survivors.py::test_the_body_regime_changes_exactly_at_its_thresholds` | 2.00 |
| MU22c | R-A2L-LIST.080/R-TUI-037 short body below 100 | killed (new) | `test_b103_inc7_mu_survivors.py::test_the_body_regime_changes_exactly_at_its_thresholds` | 1.87 |
| MU23 | R-A2L-LIST.077 short text cap 64 -> 80 | killed | `test_b103_label_list.py::test_r_a2l_list_077_1` | 3.95 |
| MU24 | R-A2L-LIST.017 plural of duplicate always | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_017_1` | 3.96 |
| MU25 | R-A2L-LIST.008 kept resolution after the unload | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_008_3` | 2.84 |
| MU26 | R-A2L-LIST.009 list columns not set | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_009_1` | 2.96 |
| MU27 | R-A2L-LIST.005 viewer resolves without the mode predicate | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_017_2` | 3.04 |
| MU28 | R-A2L-LIST.046/.018 window ribbon budget 50 -> 40 | killed | `test_b103_label_list.py::test_r_a2l_list_046_2` | 3.29 |
| MU29 | R-A2L-LIST.019 preview cap 200 -> 300 | killed | `test_b103_label_list.py::test_r_a2l_list_078_1` | 3.36 |
| MU30 | R-A2L-LIST.024 missing cap 20 -> 30 | killed | `test_b103_a2l_list_view.py::test_r_a2l_list_024_2` | 3.41 |
| MU31 | R-A2L-LIST.063 rank limit 20 -> 30 | killed | `test_b103_label_list.py::test_r_a2l_list_065_2` | 3.25 |
| MU32 | R-A2L-LIST.059/.049 closest names 3 -> 4 | killed (new) | `test_b103_inc7_mu_survivors.py::test_the_similar_line_holds_exactly_three_closest_names` | 1.43 |
| MU33 | R-A2L-LIST.084/.085 _work no longer swallows the RuntimeError of call_from_thread (app stopped) | survived, MINOR | `(none; argued below)` | 1.8 |

## Survivors

| Id | Verdict | Why |
|---|---|---|
| MU32 (closest names 3 -> 4) | real gap, fixed | `test_r_a2l_list_049_1` compared the similar line with `in`, so a fourth name passed. New `test_the_similar_line_holds_exactly_three_closest_names` compares the whole line and first checks that the fourth ranked name exists and differs. |
| MU22a/b/c (WIDE_AT 180 -> 160, STACK_MIN_HEIGHT 32 -> 28, STACK_MIN_WIDTH 110 -> 100) | real gap, fixed | the layout nodes of R-A2L-LIST.080-.083 / R-TUI-037 sit far from the thresholds. New `test_the_body_regime_changes_exactly_at_its_thresholds` resizes one app through widths and heights and checks `-wide` / `-short` against the measured body (179/180 and 109/110 columns, 31/32 rows), and fails if the sweep misses a boundary. |
| MU05c (`is_running` dropped from `_preview`'s guard) | real gap, fixed | no node previewed with an attached window and a stopped app. New `test_the_paste_window_paints_nothing_once_the_app_has_stopped` patches `is_running` to False for one `_preview()` call and requires the counts line unchanged. |
| MU01c (`all_missing[:SIMILAR_MAX + 1]`) | equivalent | the similar requests are capped at 10 in `_request_similar`, so `self.similar` never holds an eleventh position and the eleventh entry is skipped by `matches is None`. The slice is a second cap behind the first. |
| MU08a-e (`markup=False` dropped on the chips, the two missing lines and the similar line; the similar line updated with a `str`) | equivalent | each of these Statics is updated only with a `Text` (`a2l_view.py` chips and missing line; `a2l_label_list.py` `_paint_missing`, `_paint_similar`), and a `Text` is never parsed as markup; MU08e keeps `markup=False` on its Static. Observable only if a `str` reaches a Static that lost `markup=False`. The literal paint itself (names through `display_text`, never raw) is killed by MU08f. A census of `markup=False` Statics stays a MINOR as ruled in P-085 (e). |
| MU19a (`dismiss(names)` instead of `dismiss(names or None)`) | equivalent | the dismiss value is read only by the viewer callback, which acts on a non-empty list and ignores `[]` and `None` alike; `test_r_a2l_list_054_1` checks the observable (filter kept, window closed). |
| MU33 (`_work` no longer swallows the `RuntimeError` of `call_from_thread`) | survived, MINOR | as I7 predicted: the error can only occur after the app stopped, in a worker thread of a finished app; the worker is created with `exit_on_error=False`, so it shows only as an unreported thread exception at teardown. No node can see it without a thread-exception hook; not forced. `.084/.085` still see the `is_running` checks (MU05a/b). |

## Method notes (honest account)

- **Driver defect found and fixed:** the first full run aborted at MU04 (an `old` string with LF against a CRLF file in the archive: `a2l_view.py` is CRLF in this repo). The driver now converts the pair to the file's line ending; MU04 onwards re-ran (`results-pass1.tsv`). MU01a-MU03 (single-line edits) ran before the fix and are unaffected.
- **MU07's first result was not a kill:** its first run was stopped by the base-identical node `test_r_tui_042a_3_4_card_keeps_the_full_name` (F-I7-6), which fails on base too. It was replaced by MU07a/b, selected on nodes that pass on the tree. `test_r_a2l_list_010_1` alone does NOT separate the header-only mutant (`1 passed`); `test_r_a2l_list_009_1` does (and MU07b, header and cells, fails 2 nodes).
- **MU22's first pass was contaminated:** the new test file was edited on the runner copy while that pass ran (its first version failed its own coverage assertion). The MU22 rows of `results-pass3a.tsv` are not results; MU22a-c were re-run with the final test after a GREEN run (`results-pass3b.tsv`).
- `-k` selections that matched no node in one file (`rc=5`, for example L for a V-only family) are recorded as such in the tsv and never counted as a pass; every survivor above was judged against both files and the node list of its family.
- **Rule slip:** one `pkill -f` with a pattern specific to my own driver was issued to stop the aborted driver run (PF-01 says kill by PID). The process had already exited and nothing else was matched. Not repeated.
- Pre-existing failures ignored as such: P-038 `test_b100_session_reset` nodes, the 3 base canon rows (P-105), R-DOC-CANON.4, the 13 Inc 12 card nodes (F-I7-6). None was counted as a kill.
- Host load (1-min) per run is in the table and the tsv: 0.10 to 3.96 with the other reviewer's runs on the same host; one pause at 4.13.

## Files

New: `tests/test_b103_inc7_mu_survivors.py` (3 nodes). Changed: `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` 316 -> 317 (the census counts the new module). Evidence: `evidence-e4-mut/` (driver, mutant definitions, runner lines). No product code changed.

## Laws after the new files

Clone of `ff5df145` with `main` = origin/main `0c3a6bd4` (HT-03), `-n 2`: `test_id_registry.py` + the new file `15 passed`; `test_suite_hygiene.py` + `test_requirements_canon.py` `1 failed, 77 passed` (the failure is the base-identical canon node, rows R-A2L-DEF.153, R-PICKER-CORRECT.004 / .008). Runner scratch deleted (explicit list: the `zq-mu7` folder created for this run).
