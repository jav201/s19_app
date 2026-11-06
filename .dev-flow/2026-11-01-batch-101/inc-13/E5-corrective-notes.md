# Inc 13 — E5 corrective notes

Corrective agent (model opus), batch-101 increment 13, branch `b101-inc13` (head `a086fa5` before this pass). Rulings: `E5-rulings.md` C-1 … C-8 and its "Routed" table. Every run was on the LAN Linux host (the laptop; LAN host 2 is down), env `s19ci` (Python 3.11.18), in an own detached worktree at `origin/main` `f9f3cb09` (no `s19_app/` or `tests/` drift from `b7b77c4`) plus `git diff b7b77c4 -- s19_app tests` of the local branch, re-synced after each local edit. Each transcript prints `s19_app.__file__` (inside that worktree) and a tree fingerprint (sha256 of the full-index diff) at its start and end. The final runs all carry fingerprint `e7d6e2ef3b63a343`, which equals the committed tree's. Nothing ran on the Windows PC. Transcripts: `../evidence/inc-13/e5c-*.txt`, redacted (home → `<HOME>`, account → `<USER>`, host → `<LAN-HOST>`).

## Verdict

**All eight rulings done; the three routed items are in `BACKLOG-CODE.md`.**
- Product changes, in two slice files:
  - `segment_split_view.py` `SplitJoinWindow._state_text` (C-1, the one function the rulings added to the slice);
  - `crc_designer_view.py` (C-8: E5-CR-3 and E5-CR-5).
- Final lane: **818 passed, 1 failed, 16 skipped**. The one failure is `test_tc_b97_69_page_keys_do_nothing_where_disabled`, the known "A2L loaded did not settle" flake, under host load 11–12; it passed 3/3 alone right after (`e5c-b97-69-r1..r3`) and is routed (below).
- Serial lane: **4 timing arms × 5 runs, 20/20 pass, 0 margins under 20 %**.
- Cases: **52** (39 + 13 new): covered 51, partial 1, gap 0.

## Ruling → change

| Ruling | Change | Evidence |
|---|---|---|
| C-1 (E4-F1 / E5-CR-1, D17-27 state-line half) | `_state_text` tests `plan.conflicts` before `plan.guard`; docstring order updated. Texts, styles and the returned flag of every branch unchanged; both callers discard the flag, and `action_export` already refused on conflicts first. Graph: new node `SplitJoinWindow._state_text`, G2 row. New direct nodes `test_r_seg_prev_7_f23_scene_state_line_is_the_clobber_line` (F-23 scene) and `test_r_seg_prev_7_8_state_line_priority_conflict_over_guard` (guard + conflict → the clobber line; guard alone → the GUARD chip). The R-SEG-PREV.20/1 arm now asserts the canon line `⚠ <fmtB(conflicts)> would clobber source — abort on export`. R-SEG-PREV.7/1 is runnable and passes. The R-SEG-PREV.7 negative control that was N/A was run and KILLED. | RED `e5c-c1-red`, GREEN `e5c-c1-green` (108 passed: band file, `test_segment_split_window.py`, `test_b97_key_bar.py`), control `e5c-mut-NC-SEG-PREV-7` |
| C-2 (E5-CR-2) | `test_r_seg_prev_2_sweep_hand_examples_skip_empty_inverted_and_outside_marks`: the graph's three `_sweep` examples, exact block lists, each also equal to `reference_sweep`. Removing `if cs >= ce: continue` turns it RED. | `e5c-c1-green`, `e5c-mut-NC-C2` |
| C-3 (timing) | The four arms ran 5 times alone in the serial lane (times below). The 20 % margin is a reported QC-TM value, not an assertion. R-SEG-PREV.7/1 and .20/1 Results follow the new runs. | `e5c-serial-r1` … `-r5`, `e5c-lane1` |
| C-4 (audit marks) | Four nodes reworked or added: (1) 007.2/1 switches Reflection in and out off first (each recompute waited) and asserts the start form differs from the template in all nine asserted fields; (2) 007.3/1 asserts the start Width/Polynomial/Init and then `16` / `0x8005` / `0xFFFF`; (3) new `test_r_crc_preview_001_1_no_image_at_start_exact_note_on_both_surfaces` (`==` on both surfaces); (4) the three substring-only nodes in 001.5/1 and 001.8/1 marked `partial` in `02-test-cases.md`, because D-2 forbids editing them. | `e5c-lane1` |
| C-5 (M-12) | M-12 dropped from R-SEG-PREV.2/2's controls (`01-requirements.md` row R-SEG-PREV.2, the `02-test-cases.md` mutant table, the graph's M-12 example) with the reason: `_sweep` merges adjacent equal blocks, so no plan field differs. Addendum in `E5-mutants.md`. | — (records) |
| C-6 (stale values) | Cap 16777216 everywhere it was stale: graph I-9, `_COVERAGE_CAP_BYTES`, the `_compute_coverage`, `_coverage_preview_text` and `_render_coverage_window` examples; `E1-slice.md` row 18; `E1-rulings.md` M-0. The test was widened to the stated threshold: new `test_crc_kernel.py::test_r_crc_designer_001_1_lut_matches_oracle_200_vectors_and_widths_9_to_63`. Row 001.1 and case 001.1/1 now state exactly what runs. The swapped base times in `E4-integration-notes.md` are corrected (002.3 = 531.7 s, 002.4 = 60.3 s, checked against `red-01-tester-base.txt`). | `e5c-lane1` |
| C-7 (audit sections 4 and 5) | Uncovered clauses: (1) a case for "every result surface"; (2) four cases for the load / project load / unload routes; (3) and (5) not-testable rulings with reasons; (4) covered since C-1 (listed under `02-test-cases.md`). All 7 black-box ATs added; none is partial (table below). | `e5c-lane1`, `e5c-cr3-green-and-ats`, `e5c-split-join-ats`, `e5c-mut-NC-AT-M2`, `e5c-mut-NC-AT-M7`, `e5c-mut-NC-SIX-SURFACES` |
| C-8 (NITs, F-2) | CR-3: `_coverage_preview_text` returns `Cannot preview: <crc_error>` before the three lines; direct node (RED before: `TypeError`). CR-4: `_is_snapshot` strips only `recomputes_before = designer_recomputes()`; control node (RED with the name test removed). CR-5: `run = self._compute_coverage(algo)` moved to just before the coverage updates (no observable difference; no node). Security F-2 recorded as accepted in `E5-rulings.md`. | `e5c-cr3-red`, `e5c-cr3-green-and-ats`, `e5c-mut-NC-CR4`, `e5c-ast` |

### Black-box ATs (C-7, audit section 5)

| Audit AT | Node | Route | Case |
|---|---|---|---|
| 1 typing burst | `test_r_crc_designer_at_typing_burst_by_keys_recomputes_once` | XOR out focused, `end`, 10 × `backspace`, `0x0` (13 edits) | 007.1/2 |
| 2 preset by keys | `test_r_crc_designer_at_preset_and_coverage_dropdowns_by_keys` | Preset focused, `enter`, `up`, `up`, `enter` | 007.3/2 |
| 3 template load | `test_r_crc_designer_at_template_load_by_keys_recomputes_once` | Load path typed; Load button focused, `enter` | 007.2/2 |
| 4 load / project load / unload | `test_r_crc_preview_at_image_load_and_unload_through_the_shipped_routes`, `test_r_crc_preview_at_project_load_through_the_dialog_recomputes_once` | `l` dialog while hidden then `0`; `U`; `ctrl+l` dialog while displayed; `p`, row, `#load_ok`, `esc` | 002.5/2, 001.1/3, 002.1/4, 002.1/5 |
| 5 coverage dropdowns by keys | same node as AT 2 | On conflict, then Join gaps: `enter`, `down`, `enter` | 001.2.1/3 |
| 6 Split/Join by palette and keys | `test_r_seg_prev_at_f23_scene_by_palette_and_keys_refuses_export` | `ctrl+k`, the name, `enter`; `space`/`down` ticks; `m`, `g` | 20/2 |
| 7 `e` in the F-23 scene; guard scene | same node; `test_r_seg_prev_at_guard_scene_e_asks_disarms_and_confirms_by_keys` | `e` (refused, nothing written); guard: `e` arms, `f` disarms, `e` `e` writes | 7/4; E5 check (canon R-SEG-PREV.8) |

Focus is set with `widget.focus()` (a click can miss a widget the panel has scrolled out of view); every change after it is driven by keys. Two test-side faults were found and fixed during the build; both are visible in `e5c-cr3-red`:
- `ctrl+a` in a Textual 8.2.8 `Input` moves to the start of the line (it does not select all). The field is now cleared with `end` and `backspace`.
- A dirty-gap Join gaps pick under abort is refused, as designed. The dropdown node now picks On conflict first.

## RED / GREEN

- **C-1 RED** (before the `_state_text` change, `e5c-c1-red`):
  ```
  E   assert '⚠ GUARD  9.2... — e will ask' == '⚠ 2.77 MiB w...ort on export'
  E     - ⚠ 2.77 MiB would clobber source — abort on export
  E     + ⚠ GUARD  9.20 MiB span — e will ask
  E   AssertionError: ['packed 128 B  ·  span 1.00 MiB  ·  fill 99.99%', '⚠ GUARD  1.00 MiB span — e will ask']
  2 failed, 1 passed
  ```
  **GREEN** after it: `e5c-c1-green`, 108 passed.
- **CR-3 RED** (`e5c-cr3-red`): `E   TypeError: unsupported format string passed to NoneType.__format__`. **GREEN**: `e5c-cr3-green-and-ats`, 4 passed.
- **Negative controls** run on the corrective worktree. Each mutant was copied over one file and restored by re-sync, and the fingerprint was re-checked.

| Control | Mutation | Result |
|---|---|---|
| NC-SEG-PREV-7 (R-SEG-PREV.7's own, N/A at E5) | census = count of conflict blocks | KILLED: F-23 clobber node, priority node, TC-710 |
| NC-C2 | `_sweep` without the empty/inverted skip | KILLED: hand-examples node |
| NC-CR4 | `_is_snapshot` without the name test | KILLED: snapshot control node |
| NC-SIX-SURFACES | `warnings.update` dropped from `_recompute` | KILLED: six-surface node |
| NC-AT-M7 | the `current_file` watch not registered | KILLED: both load-route ATs |
| NC-AT-M2 | `on_input_changed` recomputes at once | KILLED: typing AT (13 recomputes) |

  Under NC-AT-M2 the template-by-keys AT stays GREEN. That is not its control: it counts the Load's recompute only, and its control is the fill's change events (M-5).

## Counts

- **Final lane** (`e5c-lane1`, `-n 4 -m "not serial_timing"`): 818 passed, 1 failed (`test_tc_b97_69`, the flake above), 16 skipped. The skips are Windows-only arms outside the slice; none is in an Inc 13 file.
- **What the lane covered:**
  - the 3 new test files;
  - `test_crc_designer_view.py` with the AST check;
  - `test_crc_kernel.py` and `test_b101_crc_model_and_reasons.py`;
  - every module that imports `crc_designer_view`, `segment_split_view` or `crc_kernel` (12 more);
  - `test_id_registry.py` and `test_suite_hygiene.py`;
  - the law guards of `CLAUDE.md`: `test_engine_unchanged.py`, `test_tui_directionb.py`, `test_requirements_canon.py`, `test_id_registry.py`. There is no `AGENTS.md`.
- **D-2 AST check** (`e5c-ast`, `-rA`): 3 PASSED, not skipped (N-5).
- **New test nodes: 15.**
  - Designer file, 9: the snapshot control, the exact empty state, six surfaces, CR-3, typing, the dropdowns, template by keys, load/unload, project load.
  - Band file, 5: the hand examples, the F-23 clobber line, the priority, palette and keys, the guard by keys.
  - Kernel file, 1.
  - Plus 2 existing nodes strengthened (007.2/1, 007.3/1) and 1 assertion flipped to canon (R-SEG-PREV.20/1).
  - No test was renamed or deleted, and no assertion was weakened.
  - `EXPECTED_SCANNED_TEST_FILES` is unchanged: no new test file.
- **Cases (`02-test-cases.md`): 52.**
  - Coverage: covered 51, partial 1 (R-CRC-DESIGNER-001.2.2/3: it reads the constant, not the wall clock), gap 0.
  - Result: 52 pass. The 4 timing cases are 5/5.

## Measured times (serial lane, alone among this session's runs; `report_margin`)

The host was not quiet. Another session's `-n 4` lane ran on it throughout: load 3.7–4.6 at the start of each run (8 cores). The serial runner waited 45 min for it to finish, then went ahead. The margins hold anyway.

| Case | Bound | r1 | r2 | r3 | r4 | r5 | Worst margin |
|---|---|---|---|---|---|---|---|
| R-CRC-PREVIEW-002.2/1 (Join gaps change) | 3.0 s | 1.839 | 1.630 | 1.870 | 1.634 | 1.391 | 37.7 % |
| R-CRC-PREVIEW-002.3/1 (template load) | 3.0 s | 1.060 | 1.053 | 1.269 | 1.049 | 1.657 | 44.8 % |
| R-CRC-PREVIEW-002.4/1 (Ranges edit, after the quiet time) | 3.0 s | 1.401 | 1.671 | 1.208 | 1.200 | 1.213 | 44.3 % |
| R-SEG-PREV.20/1 (`g`, F-23 Split/Join scene) | 2.5 s | 0.884 | 0.946 | 0.794 | 0.689 | 0.772 | 62.2 % |

Each run: `QC-TM: 4 bounds, 0 under 20 % margin`, 4 passed. These times are higher than E4's 3 runs on LAN host 2 (16 cores, `int-serial-r1..r3`), which fits a slower host under load.

## Routed (appended to `.dev-flow/BACKLOG-CODE.md`, batch-101 bullets)

- Security F-1 (LOW, with SEC-7): `_conflict_marks` takes 3.6 s against base's 2.2 s on the alternating 16 MiB image.
- Security F-3 (INFO, pre-existing): a Textual `Input` keeps a pasted ESC character raw.
- `test_tc_b97_69` flake: "A2L loaded did not settle". It failed again here once, under load 11–12 with two other sessions' lanes, and passed 3/3 alone. The cause is still not established.

## Not done / open

- The D17-27 notice half (R-SEG-EXP.3) stays open, as E5-CR-1 says. `docs/requirements/review/S17-ears-strict.md:279` ("Partly: a guard file hides it") and `CODE-CHANGES.md` D17-27 still describe the old state-line order. Both are outside this pass's write scope; they are for the requirements session.
- The serial runs were not on a quiet host (above).
- Nothing was pushed.
