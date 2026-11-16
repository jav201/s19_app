# Inc 7 — validation (E5)

**Verdict: PASS-WITH-NOTES.** Reviewer X7 (claude-opus-5-5), one pass, code + security (`E5-review.md`). Base `63791549`; reviewed `11bdeb98`; fixes `876ea4e3` (WinCI census), `ab454a8e` (F-X7-1), `5a737033` (F-X7-3); captures `710a6fc7` (`E5-captures.md`). Runner `<runner>`, clone of `710a6fc7` with `main` = origin/main `0c3a6bd4` (HT-03), HT-02 environment (HOME basename `<runner-home>`), `-p no:cacheprovider`, `-n 2` (timing `-n 0`), `timeout 300`; `s19_app.__file__` is the first line of every transcript (`evidence/e5/logs/`, home path redacted to `~`).

**D-2 … D-12 and CV-1 … CV-11 are provisional, awaiting the operator's confirmation on the final page (P-059)**: `E5-review.md` § "Operator items".

## Runs

First battery on the clone of `710a6fc7` (1-min load 1.5-2.6, another worker's pytest on the host; nothing timed was decided from it). Transcripts: `evidence/e5/logs/repo-*.txt`.

| Run | Result | Note |
|---|---|---|
| `test_b103_label_list.py` (L, 111 + 3 F-X7-3 nodes) | 114 passed | |
| `test_b103_a2l_list_view.py` (V, 5 chunks) | 24 + 24 + 24 + 24 + 20 = 116 passed | .083 nodes count rows inside the scrollbars (F-X7-1) |
| `test_b103_a2l_list_at.py` (AT) | 10 passed | |
| `test_b103_inc7_mu_survivors.py` + `test_b103_a2l_filter_teardown.py` | 4 passed | P-002 guard kept |
| R1 `test_b103_clipboard_core.py` | 85 passed, 2 skipped | census 41 / 8 |
| R1 `test_b103_clipboard_windows.py` | 77 skipped | WinCI only |
| R2 `test_b103_clipboard_matrix.py` + `test_b102_clipboard.py` with `-k a2l` | 2 passed | the whole `test_b102_clipboard.py` re-run below |
| R2 `test_b103_copy_paste_matrix.py` cells AT-I1b-{1,2,3,6,7}/1 | 5 passed | |
| `test_b103_clipboard_tail.py` | 27 passed, 8 skipped | |
| R3 `test_b100_session_reset.py` + `test_tui_snapshot.py -k "a2l or …"` | 3 failed, 18 passed, 6 xfailed | the 3 = `tc_b100_08`, `_09_domain…`, `_09_twelve_b` (P-038, base-identical, E4 pass 3) |
| `test_b103_copy_quit_dialog.py -k "dlg_14 or copy_16_4"` | 2 passed | the census node skips on Linux; its census part checked by AST (WinCI section) |
| `test_tui_app.py -k a2l` | 17 passed | |
| `test_tui_directionb.py -k "tc019 or tc020 or tc031"` | 10 passed | engine-frozen guard tc031 included |
| `test_b103_inc12_tag_table.py` (3 chunks) | 14 failed, 98 passed | 13 = F-I7-6 card nodes, base-identical; 1 = `test_r_tui_042a_5_3_64_bit_page` (*w* 31 ≠ 29 at 118×30 after F-X7-1): case value updated `4e6cbb4f`, re-run below |
| Laws: `test_suite_hygiene.py` | 67 passed | |
| Laws: `test_b101_help_legend_docs.py`, `test_requirements_canon.py`, `test_tui_report_seam.py` | 1 failed, 109 passed | the failure = `test_canon_rows_hold_the_obligation_word_once`: R-A2L-DEF.153, R-PICKER-CORRECT.004, .008 (base-identical, P-105) |
| Laws: `test_b101_doc_hygiene`, `test_batch91_registry_hygiene`, `test_deps_seam_law`, `test_docs_canon`, `test_id_registry`, `test_no_private_tokens`, `test_legend_n8`, `test_tui_legend`, `test_engine_unchanged` | 122 passed | `EXPECTED_SCANNED_TEST_FILES` 317 holds |

Re-runs on a fresh clone of `6aaf4040` (`repo2`; the first clone had one test file copied in during its law runs, an HT-03 slip, so every law was re-run here):

| Run | Result | Load (1-min, start → end) |
|---|---|---|
| `test_b103_inc12_tag_table.py::test_r_tui_042a_5_3_64_bit_page` | 1 passed | 2.59 |
| `test_b102_clipboard.py` (whole file) | 20 passed | 2.70 |
| Laws: `test_suite_hygiene.py` | 67 passed | 3.02 |
| Laws: help-legend + canon + report-seam | 1 failed, 109 passed (the 3 base canon rows) | 3.45 |
| Laws: the other 9 files | 122 passed | 3.36 |

Expected base failures seen and only those: the 13 Inc 12 card nodes (F-I7-6), the 3 canon rows (P-105), the 3 session-reset nodes (P-038).

## WinCI (clipboard-windows)

Run **43602226000** (push of `82856fd8`): 260 nodes, **1 failed** / 215 passed / 44 skipped; gate `obligations_passed=108/108 at_passed=28/28`; artifact safety FAIL (`CONTROL_CANARY id=seed` in transcript and JUnit). Per node against the Inc 1b family run **43524411142** (`b103-inc1b`, 260 nodes, 1 failed / 215 / 44; obligations 107/108; safety PASS):

| Node | 43524411142 | 43602226000 |
|---|---|---|
| `test_b103_copy_quit_dialog.py::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener` | PASSED | **FAILED** (`assert 23 == 22`: Inc 7's `LabelListPasteModal` is the 23rd dialog) |
| `test_b103_clipboard_tail.py::test_r_paste_13_101_held_row_copy_warns_within_bound` | FAILED (P-001 family, fixed later on Inc 1b `b2d6eb25`) | PASSED |
| the other 258 nodes | same outcome in both runs | |

No clipboard node failed in the Inc 7 run. The seed canary leaked only through the failing node's traceback locals (`clipboard = _ClipboardRecorder(os_value='SEED-1b', …)`); the 1b run's failing node printed no seed and its safety step passed. Fix `876ea4e3`: the census counts 23 and names `LabelListPasteModal` (runner, AST: 23 dialogs, `dialogs_without_opener == []`, openers `A2LExplorerBody.action_paste_list` and the button; R-DLG.14 holds). The node is WinCI-only (skipped on Linux); its GREEN is due on the re-push. **READY FOR WINCI RE-PUSH** at the tip named in the last commit of this stage.

## Mutant score

MU7: 50 mutants, 42 killed (5 by 3 new nodes), 7 equivalent (accepted), 1 MINOR (MU33, ruled in `E5-review.md`). No survivor unruled.

## Timing (HT-08)

Run with `-n 0`, one node per run, after the other worker's `serial_timing` runs had ended (process list checked):

| Node | Result | 1-min load start → end | Verdict |
|---|---|---|---|
| `test_b103_label_list.py::test_r_a2l_list_078_3` (R-A2L-LIST.078/3) | 1 passed in 13.14 s | 1.62 → 1.67 | **PASS** (decided, load < 2) |
| `test_b103_a2l_list_view.py::test_r_a2l_list_035_1` (R-A2L-LIST.035) | 1 passed in 11.13 s | 1.67 → 1.97 | **PASS** (decided, load < 2) |
| `test_b101_inplace_views.py::test_qc_tm_10b_1_a2l_refresh_cost_on_the_largest_a2l` | `timeout 300` (RC 124), no verdict | 1.97 → 2.68 | **not decided** (the node does not finish in the 300 s budget at `-n 0`; MD-07: a timeout is no result) |

The two Inc 7 arms also passed inside the first battery (load ~2), not counted.

## Review

One pass: 2 MAJOR found and fixed test-first (F-X7-1 layout, F-X7-3 security), 5 MINOR to PENDING (F-X7-2, F-X7-4, F-X7-5, F-X7-6, MU33), the WinCI census fixed. No BLOCKER or MAJOR open. Captures: 50 PNG + sidecars, of which 4 retaken and 3 added after the fixes (`E5-captures.md`); 2 captures contradicted a requirement (F-X7-1 at 120×30; F-X7-6, the found card, MINOR).

## trace_check

```
python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-7/01-requirements.md --base 63791549 --src s19_app
trace_check: 4 US, 96 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
(The first run gave `SLICE s19_app/tui/window_help.py changed since 63791549 and no requirement file names it` — F-I7-5's help edit; closed by the `Files` paragraph.)

## Not run

- P-1 real-key pilot (D-11): no OS key injection on the operator's desktop.
- `test_b103_a2l_refresh.py`, `test_b102_a2l_refresh.py`, `test_b101_inplace_views.py` (except its QC-TM node): unchanged by this pass's fixes and green in E4 pass 3; not re-run.
- `test_b103_clipboard_windows.py` and the census node: WinCI only (skip on Linux); due on the re-push.
