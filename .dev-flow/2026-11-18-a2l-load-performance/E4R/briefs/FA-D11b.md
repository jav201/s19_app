# Unit FA-D11b — Inc 3 lane split, tick window per Q1, small same-oracle PR arms [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`44986981`** (FA-REQ carries R-A2L-REFRESH.050; chain A complete; launched while FA-TICK diagnoses — this unit edits tests only, so a later FA-TICK product fix does not overlap it; speculative, P-202 O2) (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`.

**Q1 at launch** (filled by the orchestrator, relevo-23): `Q1 = A`. Under D-GC = A the install's one full collection (about 1.1–1.4 s on case_06, logged as `A2L load GC: …`) runs after dispatch, so it falls inside the held step that `install_worst_stall` records, not inside the asserted window.
- A: the tick window runs from preparation entry until installation is dispatched; install/publication is a held step and its worst stall is recorded.
- B: the window runs until the final publication.

## Fixed diagnosis and design (operator D11, R4-F1, FA-DESIGN §3.7)
- **Today's instrument.** `tests/test_alp_inc3_load_responsiveness.py` runs 4 case_06 nodes (`test_r040…`, `test_r041…[/1,/2]`, `test_r042…`), 3 runs each, minutes per node.
  - Its `TickTimer` (`:135-161` at 44986981) is an app `set_timer` started before submit.
  - `_gate_summary` (`:267-275`) counts every observation as a tick failure, not only the observations inside the required window.
- **Operator D11.** These heavy arms leave the PR lane; a small version with the same oracle runs in PR.
- **R-A2L-REFRESH.050 (E4R)** now carries the tick obligation, which moves out of `.040`–`.042`.

## Files you may edit
`tests/test_alp_inc3_load_responsiveness.py`, `tests/test_alp_a2l_occupancy_at.py`.

## Rows
| row | change | negative control (scratch) → RED |
|---|---|---|
| 1 | Add `@pytest.mark.slow` to the 4 Inc 3 nodes, keeping `serial_timing`. In `test_alp_a2l_occupancy_at.py`, add `slow` to `test_at_alp_i1_1_full_case06_public_describe` and `test_at_alp_i1_2_narrow_public_describe_stays_lazy`. | collect-only lists before/after for `-m "serial_timing and not slow"` and `-m "not slow and not serial_timing"` |
| 2 | Window. Record the time preparation is entered (the `TimedGate` wrapper already sees the producer call) and the time installation is dispatched (the existing `dispatches` recorder). `tick_failures` counts only observations whose due time lies inside the Q1 window. Under A, add `install_worst_stall` (the max lateness after dispatch) to the run dict and to the QC-TM line, recorded but not asserted. | Scratch: block the UI thread 0.3 s inside the window (monkeypatch a UI-thread callback the route always calls during preparation, e.g. `step_busy`) → RED |
| 3 | Re-cite: the tick, gate and window asserts cite R-A2L-REFRESH.050 (E4R); the duration budget keeps `.040`–`.042`; the module docstring names both. | n/a |
| 4 | New `test_r_a2l_refresh_050_small_routes_same_oracle`, parametrized `["image", "project-pair", "a2l-only"]`, `@pytest.mark.serial_timing` (not `slow`).<br>- Fixture: a generated 8,000-object pairwise-disjoint A2L (`characteristic` + `inline`-style text written to `tmp_path`, as in `tests/test_alp_a2l_occupancy.py::test_r_a2l_def_161_1`), plus an S19 covering those addresses (conftest `make_large_s19`, or the file's helper), plus project folders (`_seed_project`).<br>- Oracle as in the case_06 runs: `TickTimer`, `TimedGate` 0.20 s, ≥ 3 gate ticks, 0 tick failures in the Q1 window, exactly one fan-out, the success outcome, generations +1. No duration budget. One run per param. | Scratch: make the producer run on the UI thread (wrap `_prepare_a2l_attach_snapshot` so it is invoked through `app.call_from_thread` and blocks) → RED |
| 5 | QC-TM line of every run: add `host_load` (the 1-minute value of `os.getloadavg()`; note `_host_line` at `:121` does NOT read the load today, so add the call, guarded with `hasattr(os, "getloadavg")`) and the window bounds. | n/a |

## Nodes you may run (`timeout 300`)
- `-n 0`: the three params of row 4 (small, about 10–30 s each; indicative only);
- `--collect-only -q` with the marker expressions;
- the row-2 negative control on **one** small param (not on case_06).

Never run the 4 case_06 nodes: the orchestrator runs them in M2.

## Orchestrator after integration
- Run the 4 case_06 nodes ×1 (quiet) to confirm the window logic.
- Run mutants 040/041 (re-run) and one new mutant for `.042`: producer on the UI thread, applied only to the A2L-only route.
- Run the small arms on `main` `3afebf90` as a behavioural RED-before (expected RED: UI-thread quadratic describe), only if the arm needs no alp-only seam. Otherwise record "RED-before = row-4 negative control".
