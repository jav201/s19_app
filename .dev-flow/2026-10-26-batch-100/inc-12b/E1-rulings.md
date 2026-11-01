# Inc 12b — E1 orchestrator rulings

The operator delegated every 9b–12b decision to the orchestrator's recommendation (2026-10-31). Rule: remove a feature rather than guard it, and stay within the 4-file cap.

| Id | Ruling | Why |
|---|---|---|
| Q1 | **As recommended.** Re-derive the image on the main thread before the Save worker starts, and adopt it only after the save commits. | This keeps the tested F4 rule and LLR-177.2. The old "apply before" text contradicted them. |
| Q2 | **As recommended.** Only the four session-writing actions trigger the busy refusal. Reports keep overlapping. | This is 12a ruling Q3. Reports write no session state. |
| Q3 | **As recommended.** Refuse every Patch Editor change while one of those four actions runs. | Otherwise the save's commit would mark unsaved edits as saved, which is silent loss. |
| Q4 | **As recommended.** A non-OSError in the Save worker is rolled back and reported, not re-raised. Re-pin the SEC-7 test. | P12b-2 shows that an exception escaping a worker ends the app. |
| Q5 | **As recommended.** A data file picked from the work area moves onto the existing file-load worker. The copy step of a typed load stays on the main thread. | The pick reuses a worker that already exists. The copy is short and outside HLR-177. |
| Q6 | **As recommended.** Workers on every route, plus one wait helper (`wait_for_complete()` and 2 pauses). Edit the 4 helpers once each, convert the 11 tests that run with no app, and re-pin the 2 timing tests and the SEC-7 test. No synchronous test-only entry points. | A test-only production branch is dead code. The re-pin is mechanical. |
| Q7 | **As recommended.** 12b touches `app.py` and `a2l.py` only. Correct the PLAN row at the 12b close. | — |

**Constraints carried into E2:**
- The busy refusal is a state check, not an exclusive group (P12b-1).
- Every worker body catches its own failures (P12b-2).
- A confirmed quit exits from the action's end handler, never by waiting on the main thread (P12b-3).
- A worker reads only an immutable request (LLR-177.1e). This covers the MAC-merge-into-the-previous-image hazard.

**Sequencing.** E2 runs after 12a's E2 fixes the `begin_busy` / `step_busy` / `end_busy` seam, and after 11's E2 fixes the `_prepare_project_save` / commit split.

**Size watch.** 26–28 nodes across 3 sequential groups in `app.py` plus `a2l.py`, and a 15–25 file test re-pin. This is the second-largest increment after 11.
