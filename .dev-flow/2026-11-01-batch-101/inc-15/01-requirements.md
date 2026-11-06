# Inc 15 — Windows-only failures: requirements (E1)

Batch 2026-11-01-batch-101, increment 15. Base: `c2cba35` (branch `b101-inc15` = local main, Incs 1, 2, 3, 4, 7, 8, 11, 13, 14 merged). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Subject of every row: the test suite or the test conventions (Inc 2's family, `../inc-2/01-requirements.md`). **0 files under `s19_app/` change**: the diagnosis found no product defect (`E1-rulings.md` §2).
Cause, evidence, scope and decisions: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Transcripts: `evidence-e1/` (redacted).

Sources: `../PLAN.md` Inc 15 row; the requirements session's Windows runs at `e279c8b` (`s19w/test-cases/evidence/run-e279c8b-win-serial.log`, `run-e279c8b-win-chunk-10.log`); the E1 reproduction runs of this increment.

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`), O = optional (`Where`). Canon rows the arms verify are cited by their `REQUIREMENTS.md` ids. New ids R-TST-150 … R-TST-158 were checked absent from the canon and from every batch-101 increment folder at `c2cba35` (Inc 2 holds R-TST-001 … 091, Inc 3 holds R-TST-110 … 113). "Base" = what `c2cba35` does.

## User stories

### US-TST-15 — a Windows run reports the product, not the host's clock
As the operator, I want the Patch Editor and Flow Execution arms that check what a button press left to wait until the app has handled that press, so that a serial run on the Windows host gives the same verdict as the Linux gate. (TC-331 failed 5 of 16 runs on the Windows host at `c2cba35`; TC-B94-27 failed 2 of 2 Windows runs at `e279c8b`; both pass on Linux.)

### US-TST-16 — a no-op arm proves the press was handled
As the reviewer of a later increment, I want an arm that asserts that a press changed nothing to prove first that the app handled the press, so that the arm cannot pass when the handler never ran. (TC-B94-27's rebind-to-same arm passes today with its handler held back 1.5 s, `evidence-e1/lin/lin-hold-fxbind-1.txt`.)

## Definitions

- **One-pause read.** A read of app state taken after a button press or a posted panel action with only fixed `pilot.pause()` calls in between. On the Windows host `pilot.pause()` can return before the press is handled: Textual 8.2.8 ends the pause when `time.process_time()` advances by less than 1 ms over a 20 ms sleep, and on Windows that clock advances in 15.625 ms steps (`evidence-e1/win/clock-probe.txt`: 5 ms of busy work reads 0.0 ms in 14 of 20 samples).
- **Handled press.** For Load and Parse pasted: the app's change document holds the result of the action (the document is replaced and the Edit JSON guard is set in the same synchronous handler, `s19_app/tui/app.py:4811-4834`, `:4928`). For Bind: the Flow Execution panel's bind step has returned for that press, observed by a recorder the arm wraps around the panel's bind step; the recorder counts calls only, every asserted value is read from the product.
- **Shared wait.** `settled(pilot, predicate, description)` of `tests/b97_probes.py`: polls every 0.05 s, bounded at 60 s of wall time, fails with `did not settle: <description>` (Inc 2: R-TST-020, R-TST-021, R-TST-024, wait W3).
- **Windows host.** The operator's Windows PC, interpreter `s19env` (Python 3.11.15, Textual 8.2.8), run serially with `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERPROFILE` and `HOME` pointed at a fresh scratch folder and the OS clipboard writers replaced by a raising guard (`evidence-e1/probes/i15_guard.py`, `i15-run.sh`).
- **Held-handler probe.** `I15_HOLD=fx_bind|patch_action` of `evidence-e1/probes/i15_guard.py`: the press reaches its unchanged handler 1.5 s later (`set_timer`), the forced slow step of the Post-press rule (`docs/engineering-rules.md:200`). It runs from outside the tree and changes no file.
- **Wait descriptions (table D).** The `<description>` each new wait passes to `settled`:

| Wait | Description |
|---|---|
| D1 TC-331, after the load | `TC-331: the load of f.json reached the change document` |
| D2 TC-331, after the paste | `TC-331: the parsed paste reached the change document` |
| D3 TC-B94-27, after the rebind to the same ref | `TC-B94-27: the panel handled the Bind to the same ref` |
| D4 TC-B94-27, after the rebind to variant_b.hex | `TC-B94-27: the panel handled the Bind to variant_b.hex` |

## Requirements

### TC-331 — the Edit JSON guard arm (verifies R-TUI-053.5) (US-TST-15)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-150 | E | When the TC-331 arm requests the load of a change file, the test suite shall read the state of Edit JSON only after the change document's source path names that file. | 1/1 wait (D1) between the load request and the read; the arm passes under the held-handler probe (`patch_action`, 1.5 s) 3/3 on the LAN Linux host | (a) the base one-pause form under the same probe → RED 2/2 (`evidence-e1/lin/lin-hold-patch-1.txt`, `-2.txt`); (b) product mutant: `panel.set_edit_json_enabled(...)` removed from the action handler → the arm RED at the load step | US-TST-15 | No: one pause (`tests/test_tui_patch_editor_v2.py:3534-3536`) |
| R-TST-151 | E | When the TC-331 arm presses Parse pasted, the test suite shall read the state of Edit JSON only after the change document holds the pasted entry and no source path. | 1/1 wait (D2) between the press and the read; the arm passes under the held-handler probe 3/3 | (a) the base one-pause form on the Windows host → fails with `NoMatches … '#patch_editor_panel'` or `a subsequent paste … re-enabled` (5 of 16 runs at `c2cba35`); (b) product mutant: the guard set with the inverted condition → RED | US-TST-15 | No: one pause (`:3538-3540`) |

### TC-B94-27 — lane binding isolation and the no-op rebind (verifies R-FX-LANE.7, R-FX-LANE.8, R-FX-LANE.10) (US-TST-15, US-TST-16)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-152 | E | When the TC-B94-27 arm presses Bind with the ref lane A already reads, the test suite shall read lane A's bindings only after the panel has handled that press. | 1/1 wait (D3) on the recorder count reaching 1 before the read; bindings `{}` | product mutant "a rebind to the same ref writes the record" (the early return of the bind step removed) **with** the held-handler probe (`fx_bind`, 1.5 s) → RED; the base form passes this pair (vacuous: it reads before the handler) | US-TST-16 | No: one pause (`tests/test_tui_flow_execution_b94.py:502-504`); the no-op assertion passes with the handler held (`lin-hold-fxbind-1.txt`) |
| R-TST-153 | E | When the TC-B94-27 arm presses Bind with `variant_b.hex` on lane A, the test suite shall read both lanes' bindings, lane B's box and lane B's painted cards only after the panel has handled that press. | 1/1 wait (D4) on the recorder count reaching 2 before the reads; lane A `{0: 'variant_b.hex'}`, lane B `{}` before and after, lane B's box `base.s19`; the arm passes under the held-handler probe 3/3 | (a) the base one-pause form under the probe → `assert {} == {0: 'variant_b.hex'}` 2/2 (`lin-hold-fxbind-1.txt`, `-2.txt`), the failure the Windows runs reported at `e279c8b`; (b) product mutant: the bind writes every lane's record → RED on lane B | US-TST-15 | No: one pause (`:507-512`) |

### The waits (US-TST-15, US-TST-16)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-154 | N | If the app has not handled the press within the shared wait's bound, then the test suite shall fail the arm with the text `did not settle: <description>`, the description from table D. | 4/4 waits pass their table-D description verbatim (static check); the text form is Inc 2's W3, verified by R-TST-024's case | description changed in one wait → the static check RED | US-TST-15 | n/a (no wait) |
| R-TST-155 | U | The test suite shall make each wait of R-TST-150 … R-TST-153 through the shared wait. | 4/4 waits call `tests.b97_probes.settled`; 0 `for … in range(…)` pause loops and 0 module-local wait helpers added to the two arms | a local `for _ in range(50): await pilot.pause()` loop in one arm → the static check RED | US-TST-15 | No |

### Runs (US-TST-15)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-156 | E | When the TC-331 and TC-B94-27 nodes run 20 times serially on the Windows host at the Inc 15 tree, the test suite shall report 0 failures. | 0 of 40 node runs failed (20 per node) | the base tree under the same run → ≥ 1 TC-331 failure in 20 (measured base rate 5 of 16) | US-TST-15 | No: TC-331 5 of 16 runs failed (`evidence-e1/win/run-04.txt`, `run-05-1.txt`, `run-05-3.txt`, `run-06-1.txt`, `run-06-3.txt`) |
| R-TST-157 | E | When the TC-331 and TC-B94-27 nodes run on the LAN Linux host at the Inc 15 tree, the test suite shall report 0 failures in 3 serial runs and in the release gate's parallel lane. | 0 of 6 serial node runs failed; both nodes pass in the parallel lane `pytest -n 8 -m "not serial_timing"` | the new wait calls `settled` with a predicate that never holds → both nodes RED with `did not settle: …` | US-TST-15 | Yes: 0 of 10 runs failed (`evidence-e1/lin/lin-native-*.txt`, `lin-quantized-*.txt`, `lin-trace-1.txt`) |

### Test conventions (US-TST-16) [D-3]

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-158 | U | The test conventions shall state the handled-press rule: `An arm that checks the state a button press or a posted panel action leaves waits through a shared wait for a sign that the app handled it, also when it asserts that nothing changed; it never reads after fixed pauses alone.` | 1/1 sentence verbatim in `docs/engineering-rules.md`, beside rule 2 (Post-press) | sentence deleted → the conventions guard (`test_r_tst_007_conventions_hold_each_test_rule`, parametrized) RED | US-TST-16 | No: rule 2 covers only a press "while a real worker runs" (`docs/engineering-rules.md:200`) |

## Trace

| US | Requirements |
|---|---|
| US-TST-15 | R-TST-150, R-TST-151, R-TST-153, R-TST-154, R-TST-155, R-TST-156, R-TST-157 |
| US-TST-16 | R-TST-152, R-TST-158 |

Count: 9 requirements (R-TST-150 … R-TST-158); 2 user stories. The held-handler runs are thresholds of R-TST-150 … 153, not rows of their own. R-TST-160 … 169 are held for the sibling arms if D-1 is ruled yes (`E1-rulings.md` §4).
