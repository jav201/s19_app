# Inc 12 — validation (E5)

**Verdict: PASS-WITH-NOTES.** Every dialog, action and Check Editor widget is now reachable and every dialog opens from an operator path: the census shows 21 dialogs each with an opener and 80 actions each with a reach, and the Check Editor walk shows every one of its 51 ids shown in a named state — the dead `VariantHelpScreen` dialog, the four dead aliases (`action_view_main`, `action_view_alt`, `action_view_mac`, `action_a2l_tag_find_next`), the D3-7 jump trio and the hidden `Addendum preview` button are gone with no visible change. Escape now closes the Reports dialog as Close does from all 12 focus places and on the empty dialog, with an open dropdown list closing first and choosing nothing. The mutant battery killed 17/17 on the final tree (M14, the focus-clear mutant, included), the corrective's stronger focus/highlight/status oracles were each shown RED under their mutant before the final GREEN, and the review chain closed green. No HIGH or MAJOR is open: the one MEDIUM (R-1, the requirements ledger) and the LOW/NIT findings were applied by the corrective, and the two MINOR audit findings (QA-1, QA-2) were closed by the mutant run. The notes are records-only: the six open backlog rows (BL-I12-1 … BL-I12-6) and the merge-time full suite. Branch `b101-inc12` at `3f207a75` plus the uncommitted E5 close records, this file and the increment packet. Platform: the LAN Linux host 2 for every run; the Windows PC ran nothing (no Windows-only arm in this increment).

## Runs

| Run | Result | Evidence |
|---|---|---|
| E1 pilot + census on base `2d1e2b1` (product `e07fb00`) | F-33, F-34, F-35, F-51 reproduced: 1 of 22 dialogs without an opener (`VariantHelpScreen`), 2 of 83 actions with no reach (`view_main`, `view_mac`) plus `view_alt` reached only by a dead call, 1 + 5 + 1 widgets never shown, Escape closes Reports from 0 of 10 focus places and on the empty dialog | `evidence-e1/i12e1-pilot-transcript.txt`, `evidence-e1/i12e1-census-transcript.txt` |
| Testers' RED on base `6f1743c` (G-T1) | **20 failed, 194 passed, 1 xfailed**; the two censuses name the base's dead entries (`VariantHelpScreen`, the 4 of 83), R-DLG.2/1 … /11 and AT-I12-1 with the dialog still on the stack after Escape, R-DLG.15/1 at its second Escape, passages 12/13, the two `_FIXED` nodes, TC-706's binding census | `../evidence/inc-12/red-01-g-t1-base.txt` |
| Testers' RED on base (G-T2) | **1 failed, 1 passed**; the walk lists `check_preview_toggle_button`; AT-I12-3 holds (declared standing guard) | `../evidence/inc-12/red-01-g-t2-base.txt` |
| Integration int-00 … int-08, LAN Linux host 2, tree `d1713533…` on `6f1743c` | **GREEN for the right reasons**: int-00-grep the pinned I-3 grep returns exactly the 3 `window_help.py` lines (base 39); int-01 `432 passed, 1 xfailed` (TC-065.a), 0 failed, 0 skipped (the 2 new + 7 edited test modules); int-02 `1517 passed, 27 skipped, 1 xfailed, 2 failed` (QC-BC 43 files, the 2 known failures); int-03 `1603 passed, 131 skipped, 2 failed` (51 importers, the 2 known snapshots); int-04 `220 passed` (7 law guards); int-05 `58 passed, 2 skipped, 3865 deselected` (serial_timing, QC-TM 84 bounds, 0 under 20 %); int-06 the census re-measured 21 dialogs / 0 and 80 actions / 0, walk 51 ids / 0 (base 22/1, 83/4, 52/1); int-07-base 2 failed (the same known text); int-08 the redaction gate 1 passed | `../evidence/inc-12/int-00-grep.txt` … `../evidence/inc-12/int-08.txt` |
| Mutants M1 … M17, LAN Linux host 2, one at a time in a copy | **17 / 17 killed**; M1 … M5 the real restores (each names its restored item), M6 the hidden toggle, M7 the binding removed, M8 Escape runs Generate's path, M9 `priority=True`, M10 the open list applies the highlight, M11/M12 the doc rows, M13 the F-51 mark, M14 the focus cleared, M15 no hex-pane call, M16 the tab branch removed, M17 the help window also pops the dialog | `../evidence/inc-12/mut-01.txt` … `../evidence/inc-12/mut-17.txt` |
| Corrective e5c-02 … e5c-15, LAN Linux host 2, tree `de2521d3…` on `6f1743c` | e5c-02/e5c-03 M14 RED on the new / earlier nodes (R-DLG.2/1, AT-I12-1); e5c-04 the `down` removed RED; e5c-05/e5c-06/e5c-11 the status / Generate / stray-file mutants RED; e5c-07/e5c-08 the late pop RED; e5c-09/e5c-10 M14b (focus back on the startup widget) 2 failed on the new nodes / 2 passed on the earlier ones; **e5c-12 `444 passed, 1 xfailed`** (the 10 files); e5c-13 the 7 law guards `221 passed`; e5c-14 `4 passed, 445 deselected` (serial, QC-TM 4 bounds, 0 under 20 %); e5c-15 the pinned I-3 grep = exactly the 3 lines | `../evidence/inc-12/e5c-02-qa1-m14.txt` … `../evidence/inc-12/e5c-15-grep.txt` |
| Windows PC | not run — no Windows-only arm in this increment; nothing imports `s19_app` on the Windows PC (operator rule) | n/a |

Every integration transcript prints the base commit, the staged tree and `s19_app.__file__` (the detached clone); the corrective and mutant transcripts print the same plus the exact command line, with the mutant copies verified by their diff and then deleted. The one `e5c-04` … `e5c-11` failures are the corrective's own mutants (each target clause turned RED before the final GREEN); none is a product failure.

## Per requirement

| Row | Verdict | Cases | Evidence — Linux | Evidence — Windows | Residual |
|---|---|---|---|---|---|
| R-DLG.14 (US-I12-1) | met — 1/1 | 14/1 | int-01, e5c-12, e5c-13, e5c-14; base RED names `VariantHelpScreen`; int-06 21 / 0; M1 killed | n/a (no Windows-only arm) | — |
| R-SHELL-KEYS.3 (US-I12-1) | met — 1/1 | 3/1 | int-01, e5c-12, e5c-13, e5c-14; base RED the 4 of 83; int-06 80 / 0; M2, M3, M5 killed (M4 the in-node unbound `action_copy`); the six clipboard overrides reached through the toolkit | n/a (no Windows-only arm) | — |
| R-CHKED-058 (US-I12-2) | met — 1/1 | 058/1, AT-I12-3 | int-01, e5c-12, e5c-13, e5c-14; base RED names the toggle; int-06 51 / 0; M6 killed | n/a (no Windows-only arm) | — |
| R-DLG.2 (US-I12-3, changed) | met — 12/12 (Reports dialog) | /1 … /12, AT-I12-1 | int-01, e5c-12, e5c-13, e5c-14; base RED /1 … /11 and AT-I12-1; M7, M8, M14 killed; M14b (startup-widget focus) RED on the new focus oracle | n/a (no Windows-only arm) | BL-I12-2, BL-I12-5, BL-I12-6 |
| R-DLG.15 (US-I12-3) | met — 2/2 | /1, /2, AT-I12-1 | int-01, e5c-12, e5c-13, e5c-14; first half holds on base, /1 RED at its second Escape; M9, M10 killed | n/a (no Windows-only arm) | — |

**22 cases: 22 `full`, 0 `partial`, 0 `gap`.** The two cited rows are also met: R-DOC-GUIDE.1/13, /14 (the ch16 Close row and the ch18 `esc` sentence) with M11, M12 killed, and R-DOC-GUIDE.2 (`_FIXED` 13 → 17) with M13 killed. R-DLG.2's fold records `Partly` (E3A-06): Reports answers Escape, seven dialogs still do not (D7-20, BL-I12-5).

## Mutant score

**17 / 17 killed** on the final tree, one mutant at a time in a copy whose `s19_app.__file__` prints from inside the copy. DeepSeek M1 … M17, all killed; no survivor. The two censuses carry their synthetic mutants inside their nodes (orphan and dead-only dialogs; the dead chain alias, the lone alias, the unbound `action_copy`, the id-and-comparison-only name), each with a positive control per reach arm, so neither census can pass by flagging nothing or everything. M14 (the focus cleared before the dismiss) is killed by the new `#sections_list` focus oracle added at the corrective (QA-1); M14b (the focus put back on the startup widget) is RED on the new nodes and GREEN on the earlier ones, which is exactly the gap QA-1 named. Details: `E5-mutants.md`, `E5-corrective-notes.md` §1; transcripts `../evidence/inc-12/mut-01.txt` … `../evidence/inc-12/mut-17.txt`, `../evidence/inc-12/e5c-02-qa1-m14.txt`, `../evidence/inc-12/e5c-03-qa1-m14-old-tests.txt`, `../evidence/inc-12/e5c-09-qa1-m14b-new.txt`, `../evidence/inc-12/e5c-10-qa1-m14b-old-tests.txt`.

## Reviews

- **E3 design (code-free):** `architect` **FAIL** (1 MAJOR E3A-01, 7 MINOR E3A-02 … E3A-08) → round 2 **FAIL** (1 MAJOR E3A-R2-1, the dead `action_a2l_tag_find_next`) → the orchestrator's PDR of the round-2 correction closed E3; `security-reviewer` **PASS-WITH-NOTES** (3 MINOR S-1, S-2, S-3) → round 2 **PASS-WITH-NOTES** (S2-1, S2-2 LOW); `ux-reviewer` **PASS-WITH-NOTES** (1 MEDIUM U-1, 3 LOW U-2 … U-4, 3 INFO U-6 … U-8). `E3-architect.md`, `E3-security.md`, `E3-ux.md`, `E3-rulings.md`. The split (D-5 B) moved the Flow Builder / Flow Execution half to Inc 12b.
- **E5 code review:** `code-reviewer` (code + security lens) **PASS-WITH-NOTES** (0 HIGH; R-1 MEDIUM, R-2 … R-7 LOW). `E5-review.md`. The corrective applied every finding and its verdicts are GREEN (`e5c-12` … `e5c-15`).
- **E5 security review:** in the same pass as the code review — **PASS-WITH-NOTES** (0 HIGH). None of the removed items was a guard, a confirmation, a containment check or the only way to clear state, and Escape cannot land between Generate's post and its dismiss. `E5-review.md` checks 9, 10.
- **Coverage audit:** first audit **PASS-WITH-NOTES** (QA-1, QA-2 MINOR; QA-3 … QA-8 NIT; 22 `full`, 0 `partial`, 0 `gap`). QA-1 (the focus oracle may not tell "restored" from "re-landed") was closed by M14 / M14b; QA-2 (seven mutants with no run) by the mutant table; QA-3/QA-4/QA-5 oracles and QA-8 record hygiene by the corrective. `E5-coverage-audit.md`.

## Admitted visible changes

- **Escape closes the Reports dialog** (F-51): a plain, non-priority `escape` binding on `ReportViewerScreen` and a new `action_close_reports` that logs a fixed string and calls `dismiss(None)` — exactly what Close does, posting nothing, so no report is written and no typed filter path is applied. An open dropdown list's own Escape closes only that list and chooses nothing, and the help window over the dialog keeps its own Escape.
- **The dead surface is gone with no visible change** (F-33, F-34, F-35): `VariantHelpScreen` and `VARIANT_HELP_TEXT` (no opener), the aliases `action_view_main`, `action_view_alt`, `action_view_mac`, `action_a2l_tag_find_next` and the D3-7 jump trio (`_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line`) (no reach), and the hidden Check Editor `Addendum preview` button (`#check_preview_toggle_button`) — its function stays on the Addendum tab chip. The rail keys `1`/`2`/`3` and the A2L Explorer's Find-next button keep their behaviour.

## Owed

Open residuals, one backlog id each (`E1-rulings.md` §6, `E5-rulings.md`):

- **BL-I12-1** (D-6): `window_help.py:12`, `:627`, `:661` name the removed `VariantHelpScreen` as the pattern of the window help modal; a docstring fix for the next increment that touches `window_help.py`.
- **BL-I12-2** (observation): the Reports dialog of a project with no report opens with the focus on its `?` chip; no canon row decides where it should land.
- **BL-I12-3** (D-9, with D7-31; widened U-8): nothing in the app shows that `esc` closes the Reports dialog — the Close button shows no key (R-DLG.11) and the Reports help section has no keys block and no step that says how to close.
- **BL-I12-4** (D-2 B or C only): **moot** — D-2 A was taken, so the jump trio is removed and no dead route remains.
- **BL-I12-5** (E3A-06, with D7-20): seven dialogs still ignore Escape — Select variant, Save flow, Load flow, Discard unsaved flow edits?, Edit entry JSON, the CRC write confirmation, Operations; R-DLG.2 stays `Partly` until they answer it.
- **BL-I12-6** (E5 R-7; pre-existing, toolkit-wide): a dismissing handler should return early when its screen is no longer active. A Generate press already in flight when Escape lands, or a double click on Generate, runs the handler on a popped dialog: it posts `GenerateRequested` (a report is written) and then its `dismiss` raises `ScreenStackError` (`screens.py:3404-3427`). Flag for the review page with D7-20's remaining dialogs.

- **Merge-time full suite:** this increment ran its slice, the QC-BC set, the other importers, the law guards and the serial lane on LAN Linux host 2, but not all nodes in one lane; the batch-end battery runs the full suite once.

## Trace

`trace_check.py --req 01-requirements.md --base 6f1743c --src s19_app` at close: `trace_check: 3 US, 5 active requirements (0 withdrawn), 0 gap(s)`. Every evidence citation in this record is a full committed path under the batch's evidence home.
