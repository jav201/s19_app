# Inc 15 — E5 corrective notes (rulings C-1 … C-10)

Corrective pass: one Opus agent, tests and records only. **0 files under `s19_app/` change.** Base `c2cba35`; head before this pass `5054743`. Rulings: `E5-rulings.md`. Transcripts: `../evidence/inc-15/e5c-NN.txt` (redacted). Helper scripts: `../evidence/inc-15/probes/i15c-e5-*` (shell) and `i15c_e5_*` (Python plugin and mutator; a `-p` plugin needs an importable name, so the prefix takes `_`).

## 1. Sites per ruling (enumerated before the first edit)

Line numbers are at `5054743`.

| Ruling | Sites to edit | Kind |
|---|---|---|
| C-1 | `02-test-cases.md`: the Coverage and Result cells of all 26 rows (`gap` / `not_run` → the audited values); the Tests cell of 153/1 and 155/1 only if C-6 / C-7 do not close their gaps; the closing Count line | record |
| C-2 | `tests/test_suite_hygiene.py`: `_INC15_WAIT_SITES` (`:2119-2176`, a sixth column: each wait's predicate as `ast.unparse`); its comment (`:2115-2118`); the two tuple unpackings (`:2303`, `:2314`); a new helper beside `_settled_description` (`:2223-2241`) that returns the predicate argument; the site loop's new assert (after `:2331`); the test docstring (`:2294-2299`). Control: a copy with D6's predicate → `lambda: True` → guard RED (also the reviewer's case (b): D7's predicate → D6's sign → RED) | test + run |
| C-3 | `E1-rulings.md` §4 D-6 cell (`:61`): `while` loops that call `pilot.pause()` join the census backlog row | record |
| C-4 | `tests/test_suite_hygiene.py`: `from collections import Counter` moves from `:2300` to the module imports (`:31-48`); `E1-rulings.md` §4 D-3 cell (`:58`): "beside rule 2" → rule 7, after rule 6 | test + record |
| C-5 | `E1-rulings.md` §4 D-6 cell (`:61`): add "retire the module-local `_settled` of `tests/test_tui_patch_editor_v2.py` (`:3039`) onto `tests.b97_probes.settled`" | record |
| C-6 | `tests/test_tui_flow_execution_b94.py`: the import line (`:30`, add `painted_rows`); the paint read (`:539`, `panel.lane_paint_plain(1)` → lane B's painted rows read off the compositor, cropped to the part of lane B its scroll area shows); the arm docstring (`:482-490`). Records: `02-test-cases.md` 153/1 Expected; `E1-slice.md` §2 TC-B94-27 note on the asserted values | test + record |
| C-7 | `tests/test_suite_hygiene.py`: the per-arm ban (`:2343-2346`) covers `_wait_for` as well as `_settled`; the test docstring. Records: `02-test-cases.md` 155/1 Expected widened to the requirement's words; `E1-slice.md` §2 guard bullet. Control: a copy with a `_wait_for` call added to TC-B94-27 → guard RED | test + record + run |
| C-8 | `02-test-cases.md`: 157/1 → the serial half (`verified`); new row 157/2, the parallel lane (`-n 8 -m "not serial_timing"` over the changed files on the LAN Linux host, this pass; the batch merge's full suite re-confirms it). Count line | record + run |
| C-9 | `02-test-cases.md` 154/1 Expected: drop "and in order"; 163/1: the no-skip clause gets a run (a copy with `_confirm_with` renamed → the guard fails, 0 skipped) | record + run |
| C-10 | `tests/test_tui_flow_execution_b94.py` (`:501-502`): after the second `await _import_stem(app, pilot, "base")`, the `await pilot.pause()` becomes `await settled(...)` D9 on the panel's import result (lanes `base`, `base_2` and lane B's box on screen); the docstring. `tests/test_suite_hygiene.py`: a ninth `_INC15_WAIT_SITES` row; the trigger lookup keys a repeated trigger on its **last** occurrence in the block (the arm imports `base` twice; the reads follow the second). Records: `01-requirements.md` table D (`:28-37`) gains D9; the counts that table D drives (R-TST-153's threshold names D9 for its "before" reads, `:53`; "8/8" → "9/9" in R-TST-154, 155, 163, `:75-77`; the scope note `:79`); `E1-slice.md` §1, §2 and §5 for D9; `02-test-cases.md` 153/1, 154/1, 154/2, 155/1, 163/1 and a new robustness row 153/3 (D9's hold). Runs: a new hold mode `fx_import` (defers `FlowExecutionPanel.add_lane` 1.5 s at class level); fixed form 3/3 GREEN, base form (the arm at `5054743`) 2/2 RED at the read D9 guards; D9 never-settles once; Windows: tc_b94_27 serially | test + record + run |

Not edited: any file under `s19_app/`; `tests/test_tui_patch_editor_v2.py` (no ruling needs it: C-5 is a backlog row only); `docs/engineering-rules.md`.
