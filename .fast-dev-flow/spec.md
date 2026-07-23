# Quick Spec — s19_app · N5 progress feedback for report generation

> Minimal spec for `/fast-dev-flow`. Observable acceptance criteria only.

- **Date:** 2026-07-23
- **Batch:** n5-progress-indicators
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** autonomous end-to-end + self-merge (operator-granted this batch, per-batch).
- **Status:** CLOSED 2026-07-23. Report-gen progress shipped; load-progress finding recorded; before/after+diff+CRC+A2L carried.
- **Branch:** `fix/n5-progress-indicators` off `main` `d1d0285` (RC-1 verified HEAD == origin/main tip).

---

## 0. Phase-A finding that reshaped this spec (honest scoping)

The initial premise ("long-running actions have NO progress bar") is **partly false**: the file **load** path ALREADY drives a persistent `ProgressBar(id="progress_bar")` in `#workspace_status_bar` via `set_progress(10→50→100)` (`load_from_path` / load worker / error handler). A load `LoadingIndicator` would be **redundant**. The genuine gap is **report generation**: `_trigger_generate_report` → `_start_generate_report_worker` (`@work`, off-thread, genuinely slow) → `_finish_generate_report` use only `set_status` (text) and **never `set_progress`** — so the bar shows no activity during a report and sits at its last value (e.g. `100` left over from the previous load), reading as "done" while a report is actually running. N5 fills that gap by reusing the existing bar.

---

## 1. Objective (1 line)

Drive the existing `#progress_bar` during **project-report generation** so a slow, off-thread report shows visible progress (start → done) and resets on failure — the user can tell a report is advancing and is never misled by a stale `100`.

---

## 2. User stories (Connextra)

- As an engineer generating a project report over many variants, I want the progress bar to move while the report is being built, so I know it is working and not hung.
- As an engineer, I want a **failed** report to reset the bar (not leave it mid-fill), so the bar's state never lies about what happened.

---

## 3. Acceptance criteria (observable)

- [ ] **AC-1 (kickoff shows activity):** When `_trigger_generate_report` starts a report, the system shall set the progress bar to an in-progress value (>0 and <100) before the worker completes.
- [ ] **AC-2 (advances in the worker):** The `_start_generate_report_worker` shall drive `set_progress` (via `call_from_thread`) to a mid value before the heavy `generate_project_report` call.
- [ ] **AC-3 (completes at 100):** When `_finish_generate_report` runs on success, the system shall set the progress bar to `100`.
- [ ] **AC-4 (resets on failure):** When report generation is rejected (`ValueError`) or crashes (worker `except`), the system shall reset the progress bar to `0` — never leave it stuck mid-fill.
- [ ] **AC-5 (no regression to load progress):** The load path's existing `set_progress(10/50/100)` behaviour is unchanged.

---

## 4. Validation strategy

Unit + `App.run_test()` Pilot in `tests/`. (a) **AC-1/AC-3/AC-4** unit-ish: instantiate `S19TuiApp`, mount, and call the three seams directly — a small `_set_report_progress(value)` helper (or the direct `set_progress` calls) — asserting `query_one("#progress_bar", ProgressBar).progress` after each; AC-4 asserts reset to 0 on the reject/crash paths. (b) **AC-2** driven: drive a real project report through the worker with a Pilot, `pilot.pause()` to completion, and assert the bar reached 100 (end state) — the worker's mid-drive is covered by the seam unit test (threads make the mid-value racy to observe live). (c) **AC-5** regression: the existing load tests stay green; a load still drives 10/50/100. Each AC maps to a named test; RED shown pre-fix (the report worker has no `set_progress` today → the bar stays at its prior value across a report). Manual smoke: generate a report, watch the bar move 0→100.

---

## 5. Non-goals (OUT — carried to BACKLOG as N5 follow-ups)

- **Before/after** and **diff** report progress, **CRC** compute progress, **A2L** enrichment/validation progress — same `set_progress` pattern, separate fast-flow follow-ups (kept out to hold this batch fast + ≤5 files).
- A distinct **indeterminate** activity spinner / an "active vs idle" visual state for the bar — the bar is determinate; N5 drives it with discrete report steps (mirrors the load path's 10/50/100), not a new widget.
- Re-homing the bar to idle after any op — the bar reflects the last op's terminal state (0 on failure, 100 on success), consistent with the load path.
- No change to report content, the worker threading model, or load semantics.

---

## 6. Detected security flags

> Scanned sections 1-4.

- [ ] Auth / identity · [ ] Secrets / config · [ ] External integrations · [ ] Sensitive data · [ ] Destructive DB · [ ] Input / attack surface · [ ] Network / exposure

**`security_required`:** `false`

The change drives an existing progress widget from the existing report-generation call sites. No input surface, no external/network/secret path, no engine-frozen module. No pattern fires.

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | A |
| Started | 2026-07-23 |
| Closed | - |
| Promoted to /dev-flow | no |
| Notes | Pivoted after the disk finding (§0): load already has progress; report-gen is the real gap. Before/after + diff + CRC + A2L carried. |

---

## 8. Close (filled in phase C)

### What changed
Report generation now drives the persistent `#progress_bar` (reusing the existing `set_progress`): kickoff `_trigger_generate_report` → 15; worker `_start_generate_report_worker` → 55 (via `call_from_thread`) before the heavy `generate_project_report`; success `_finish_generate_report` → 100; rejection (`ValueError`) or crash (worker `except`) → reset to 0. No new widget — the same determinate bar the load path uses. Load progress (10/50/100) is untouched.

### How it was tested
`tests/test_report_progress.py` (4): AC-2/3 driven (real report through the report-seam surface → bar 100); AC-4 driven (monkeypatched `generate_project_report` raises → bar reset to 0, no crash); AC-1 (worker stubbed → kickoff leaves bar 0<p<100); AC-3 unit (`_finish_generate_report` → 100). RED-verified: with the success seam disabled the driven + unit tests fail (bar never reaches 100). Regression: `test_tui_report_seam.py` + `test_report_logging.py` (share the worker) green.

### Open risks / pending
- Report **before/after** + **diff**, **CRC** compute, **A2L** enrichment/validation still lack progress feedback — carried to BACKLOG as N5 follow-ups (same `set_progress` pattern).
- The bar is determinate but the report has no true percent signal; 15/55/100 are coarse activity steps (mirrors the load path's 10/50/100), not a measured fraction.

### Security flags — handling
None fired (`security_required: false`) — a visibility drive of an existing widget from existing call sites.

### Suggested commit message
```
feat(tui): drive #progress_bar during report generation (N5)

Report generation was silent on the progress bar (only set_status); the
off-thread worker left the bar at its prior value (e.g. 100 from the last
load), reading as "done" while a report ran. Drive set_progress at the four
report seams — kickoff 15, worker-mid 55, success 100, failure 0 — reusing
the bar the load path already uses. Load progress unchanged.
```
