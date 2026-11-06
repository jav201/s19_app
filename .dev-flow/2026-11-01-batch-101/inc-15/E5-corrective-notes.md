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

## 2. What each ruling got

Test commit `5edcb3f` (tests + probes + §1 of these notes); the records and the transcripts follow in the next commit. `git diff --stat c2cba35 5edcb3f -- s19_app` is empty.

| Ruling | Done | How | Evidence |
|---|---|---|---|
| C-1 | yes | All 28 rows of `02-test-cases.md` carry Coverage `covered` and Result `verified`, each Result cell naming its runs (`int-NN` at `77f4553`, `e5c-NN` at `5edcb3f`); closing paragraph with the totals | §4 below |
| C-2 | yes | `_INC15_WAIT_SITES` gains a sixth column, each wait's predicate as `ast.unparse`; new helper `_settled_predicate`; the site loop asserts it after the description. The unparse text is the same under Python 3.11.18, 3.12.7 and 3.14.9 (CI runs 3.11) | e5c-20 RED (D6 → `lambda: True`), e5c-21 RED (D7 polls D6's sign, the reviewer's case (b)); the guard at `5054743` stays GREEN on the D6 edit (e5c-25); e5c-27 (unparse, three interpreters) |
| C-3 | yes | D-6 cell: the census also counts `while` loops whose body calls `pilot.pause()` | `E1-rulings.md` §4 |
| C-4 | yes | `from collections import Counter` at the module imports; D-3 cell now says rule 7, after rule 6 | `5edcb3f`; `E1-rulings.md` §4 |
| C-5 | yes | D-6 cell: retire the module-local `_settled` of the patch-editor module onto `tests.b97_probes.settled` | `E1-rulings.md` §4 |
| C-6 | yes, local | Lane B's paint is read off the compositor with the suite's C-32 helper `tests.b97_probes.painted_rows`, cropped to `find_widget(lane_b).region ∩ .clip`. Lane B sits in the scroll area `#fx_lanes_scroll`; at 120 × 30 its head, card tops and box row show (screen rows 13–15); uncropped, rows 16–18 belong to the scroll area's edge, `#fx_log` and `#fx_legend`. 153/1 → `full` | e5c-03…05, e5c-31…50 GREEN |
| C-7 | yes | The per-arm ban loops over `("_settled", "_wait_for")`. 155/1 Expected widened to the requirement's words → `full` | e5c-22 RED `uses the module-local _wait_for`; the guard at `5054743` stays GREEN on the same edit (e5c-26) |
| C-8 | yes | 157/1 is the serial half; new 157/2 is the parallel lane, run now over the three changed files with `-n 8 -m "not serial_timing"`: 129 passed (the four nodes are not `serial_timing`; the files' one `serial_timing` test is the hygiene arm `test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock`, e5c-02). The batch merge verification re-runs the whole-suite lane | e5c-01, e5c-02; serial half e5c-03…05 |
| C-9 | yes | 154/1: "and in order" dropped. 163/1: run made: `_confirm_with` renamed in a copy → the guard fails `nested _confirm_with missing`, 1 failed, 0 skipped | e5c-23 |
| C-10 | yes | D9 after the second `await _import_stem(app, pilot, "base")`: `settled` until the lane names read `["base", "base_2"]` and lane B's box `#fx_in_1_0` is mounted with a non-empty screen region. Records: table D, R-TST-153's threshold and negative control (c), the 8 → 9 counts of R-TST-154, 155, 163 and the scope note; slice §1, §2, §5; case 153/3. The guard keys a repeated trigger on its last occurrence (`max(..., default=None)`). New hold `fx_import`: `FlowExecutionPanel.add_lane` runs 1.5 s after the picker closes | e5c-07…09 GREEN 3/3 under the hold; e5c-10, 11 RED `KeyError: 'base_2'` (the arm at `5054743`); e5c-17 D9 never settles → its own text; e5c-24 RED (D9 removed); Windows e5c-31…50 20/20 |

## 3. Runs

LAN Linux host: a fresh worktree `~/work/s19_i15c` at `m4snap-main` (= `c2cba35`) with `git diff --binary c2cba35 5edcb3f -- tests docs` applied (sha256 `15df472e…`); interpreter `s19ci` (Python 3.11.18, Textual 8.2.8); `NO_COLOR` unset; the probe `i15c_e5_guard.py` blocks the OS clipboard writers in every run. Controls, holds and mutants ran in rsync copies under `/tmp/i15c/trees/`, never in the worktree. Script `probes/i15c-e5-battery.sh`; index `e5c-index-linux.txt`.

| Runs | What | Result |
|---|---|---|
| e5c-01 | the 3 changed test files, `-n 8 -m "not serial_timing"` (C-8) | 129 passed |
| e5c-02 | the same files, `-m serial_timing` | 1 passed, 129 deselected |
| e5c-03…05 | the 4 nodes, serial, 3 reps | 12/12 passed |
| e5c-06 | the static guard + the 7 conventions parameters, `-v` | 8 passed |
| e5c-07…09 / 10, 11 | D9 hold `fx_import`: the arm / the arm at `5054743` | GREEN 3/3 / RED 2/2 `KeyError: 'base_2'` |
| e5c-12…14 | D3 + D4 hold `fx_bind` on the changed arm | GREEN 3/3 |
| e5c-15, 16 | mutant 153 (b); mutant 152 + `fx_bind` hold; on the changed arm | RED on lane B; RED at the no-op assertion |
| e5c-17…19 | D9, D3, D4 forced never to settle (3 s bound) | each RED with its own `did not settle: …` text |
| e5c-20…24 | guard controls C-2 (a), C-2 (b), C-7, C-9, C-10 | 5/5 RED, each naming its site |
| e5c-25, 26 | the guard at `5054743` on the C-2 (a) and C-7 edits | GREEN (the holes the fixes close) |
| e5c-27 | `ast.unparse` of the 9 sites vs the guard table: 3.11.18, 3.14.9 (LAN), 3.12.7 (Windows; no pytest, no `s19_app` import) | 9/9 each |

e5c-01 and e5c-02 were first run with `-q`, which prints no report header (same results: 129 passed; 1 passed, 129 deselected). They were re-run without `-q` so the transcripts carry the commit and `s19_app.__file__`. The LAN worktree was removed after the runs.

Windows host (TC-B94-27 only; this pass changed no other arm's file): 20 serial runs, `probes/i15c-e5-win.sh`, interpreter `s19env` (Python 3.11.15, Textual 8.2.8), cwd the worktree at `5edcb3f`, `s19_app.__file__` in the worktree in every header (the runner aborts otherwise). Each run gets fresh `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERPROFILE`, `HOME` and `--basetemp` under the job's `tmp/i15c-win/e5c-NN/`; `NO_COLOR` unset; the clipboard writers replaced by a raising guard, which never fired. Result: **20/20 passed** (e5c-31…50). The brief asked for 16; 20 also meet R-TST-156's 20 per node, as E4 did. Index `e5c-index-windows.txt`.

Transcripts are redacted (`<HOME>`, `<USER>`, `<HOST>`, `<LAN-LAPTOP>`). A scan of every `e5c-*` file and probe for home paths, account and host names, LAN addresses, mail addresses and kernel strings found 0 hits.

## 4. Marks after this pass

28 cases over 14 requirements (26 + R-TST-157/2 + R-TST-153/3); 14 normal, 14 robustness. Tests `full` 28. Coverage `covered` 28. Result `verified` 28, `failed` 0, `not_run` 0. `trace_check.py --req inc-15/01-requirements.md --base c2cba35 --src s19_app`: 2 US, 14 requirements, 1 gap (EVID: no `04-validation.md`, owed by the E5 gate, as before).

## 5. Decisions taken here (for the re-audit)

1. **D9 is traced to R-TST-153**, as the wait before its "before" reads of lane B (threshold and negative control (c)), not to a new row. A strict EARS reading (one trigger per row) would give the import its own row (for example R-TST-164); that adds a requirement, outside the record scope the brief names. The re-audit may rule otherwise.
2. **D9's sign includes "lane B's box has a screen region"**, not only the lane names, because the C-6 read is a compositor read and needs lane B laid out.
3. **Repeated trigger → last occurrence.** The arm imports `base` twice and reads after the second; the lookup takes the last match. D1 … D8 triggers are unique in their blocks, so their lookup is unchanged.
4. **C-8 cites int-01 for the serial half**, but int-01 is the `-n 6` parallel run. The serial half is int-03…05 (and e5c-03…05), and that is what the record cites.
5. **Re-confirmation runs beyond the brief** (e5c-12…19, 25, 26, 27): the TC-B94-27 arm changed, so its D3/D4 hold, its two mutants and its never-settle sites were re-run on the new form; 25 and 26 show the controls discriminate. Each ran in a copy on the LAN host.

## Evidence checklist

- [x] Tests and checks: LAN e5c-01…27 as tabled (every GREEN run passed; every control RED or GREEN as expected); Windows e5c-31…50 20/20.
- [x] No secrets: redaction scan 0 hits (§3).
- [x] No destructive command without approval: `rm -rf` only on this pass's own scratch (`/tmp/i15c/trees/*`, `/tmp/i15c/runs/*`, the job's `tmp/i15c-win/e5c-NN/`); the LAN worktree removed with `git worktree remove`.
- [x] File count: 0 source files; 2 test files (`tests/test_tui_flow_execution_b94.py`, `tests/test_suite_hygiene.py`); records and evidence.
- [x] Review packet: this file.
