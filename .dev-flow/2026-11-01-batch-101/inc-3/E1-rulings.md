# Inc 3 — E1 rulings: scope, canon changes, decisions

Batch 2026-11-01-batch-101, increment 3, base `e266395`. Rows: `01-requirements.md`. Evidence: `E1-profile.md`.

## 1. Scope

In scope:
1. **R1-P1** — Save project at the T2 composition: profiled first (`E1-profile.md` §1). The profile shows an avoidable cost, so the requirement is an optimisation with a measurable target (R-PROJ-001.13: < 1 s, target ≤ 0.8 s alone), not a re-ruled bound. Design: the gather's composition limb checks each distinct name once (R-PROJ-GATHER.12) and tests `is_file()` on the joined path without `resolve()` first; the one behaviour this changes (a link loop at a composition name) is its own row (R-PROJ-GATHER.13).
2. **The painted ~1 s step** (routed from Inc 2, ruling R-3): diagnosed as the test clock (`E1-profile.md` §2). The requirement follows the diagnosis: R-TST-110 … 113, test-only. The `sec6_5 appended` arm, named in the same routed item, gets the same clock correction (R-TST-112).
3. **OBS-F2-1 / D11-72** — a deleted open-project folder: the sync refuses with the existing line (canon R-PROJ-002.12, .13, unchanged text) and creates no folder (R-PROJ-002.14, new). Plan ruling of 2026-11-01 applied as written.

Out of scope (with where it goes):
- The variant append's own margin at the SEC6-5 folder ceiling (stamped 0.59–0.96 s, `E1-profile.md` §2.3) — decision D-4.
- The manifest-reader memo (about 0.06 s more on R-PROJ-001.13) — decision D-2.
- The 12b worker hand-off cost (`E1-profile.md` §1.4): smaller than the cut taken; not split further.
- No UI change: every painted text is a canon text already shipped. No screen changes.

## 2. Changes to existing canon rows

None. R-PROJ-002.12 and R-PROJ-002.13 are kept word for word; their "or no longer exists" alternative was false at `e266395` (the sync's `mkdir(parents=True, exist_ok=True)` re-created the folder before the read, so the read succeeded on an empty folder) and becomes true here. The "create no folder" response is a second response, so it is a new row (R-PROJ-002.14) rather than a clause added to .12/.13 (rule E2: one shall, one response).

New rows: R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13, R-PROJ-002.14 (S11); R-TST-110 … 113 (S0, the test suite's process rows that Inc 2 opened). Each id was checked absent from `REQUIREMENTS.md` and from Inc 2's `01-requirements.md`.

Reasons for the new rows' shape:
- **R-PROJ-001.13** names the T2 composition in a definition, not in the row, so the row stays one sentence; the bound is the existing 1 s of TC-B100-20 (SEC7-R2-2), never written in the canon before (the plan asked for "a new S11 row for the Save bound"). The 0.8 s target is a margin rule (QC-TM), so it sits in the threshold column, not in the requirement.
- **R-PROJ-GATHER.12** is stated as a count of checks, as SEC6-5's "each name is checked once per read" arms already do (`test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read`); it is what a spy can observe without naming a function.
- **R-PROJ-GATHER.13** is the failure path the optimisation changes; R-PROJ-GATHER.9 covers only a "used file" (the session document or template), not a composition document, so it does not already cover it.
- **R-TST-110 / 111** split the clock's start and stop: two responses, and each has its own negative control (start: the `max` rule; stop: the poll).
- **R-TST-113** pins the 1 s bounds so the clock fix cannot be replaced by a raised bound.

## 3. Decisions taken at E1 (with reasons)

- **E1-D1 — optimisation, not re-rule.** The profile's largest cost (2 000 `resolve()` calls, 0.65 s of 1.48 s profiled) is not a floor: half are duplicates and none is needed to answer "is this name a file in the project". With gather + isfile the real node measures 0.65–0.74 s (5/5) on a loaded host.
- **E1-D2 — the once-per-name rule lives in the gather, not in its caller.** `app.py` builds `composition_names` as batch + assignments (`app.py:11836`); de-duplicating there would also work, but the gather is the function that owns "check each name" and the isfile change sits in the same loop, so one file holds both and the caller does not change.
- **E1-D3 — duplicate findings collapse.** With the once-per-name rule, a composition name that is missing and appears twice gives one `GATHER-SOURCE-MISSING` finding instead of two. These findings are logged only (`app.py:11860`), never painted; no canon row counts them. Accepted.
- **E1-D4 — the A2L "no longer exists" case is reached only mid-attach.** The A2L attach's request-time guard (`load_a2l_from_path`, `app.py:15202-15217`) already refuses a deleted folder with `A2L NOT loaded: …`, so R-PROJ-002.13's deleted alternative is reached only when the folder goes between the request and the install. The test deletes it from inside the attach worker (a wrapper of the copy step). Checked: the guard reads `validate_project_files`, which raises `FileNotFoundError` on a missing folder.
- **E1-D5 — the refusal comes from the existing read.** With the `mkdir` gone, `validate_project_files(project_dir)` raises `FileNotFoundError` (`project_dir.iterdir()`, `workspace.py:1911`) inside the existing `try` and the existing `except OSError` paints the canon line; a regular file in the folder's place raises `NotADirectoryError`, as today. No new branch, no new text.
- **E1-D6 — the panel paint stamp uses public Textual API only.** The stop stamp is the first publish of the pushed panel screen's `screen_layout_refresh_signal` at which `#result_summary` has a height, subscribed by the app (a running node) from a test wrapper of `push_screen`. Subscribing the screen itself fails (`SignalError: Node must be running`, seen at E1). No product code changes for the stamp; no private Textual method is wrapped by the tests (the E1 script wrapped `_refresh_layout` and `_compositor_refresh` only to diagnose).
- **E1-D7 — no new test file.** New nodes go into `tests/test_project_gather.py`, `tests/test_b100_workers.py` and `tests/test_b100_project_check.py`, so `tests/test_id_registry.py`'s `EXPECTED_SCANNED_TEST_FILES` needs no re-measure.

## 4. Decisions for the orchestrator

- **D-1 — add `s19_app/tui/services/project_gather_service.py` to Inc 3's files.** The plan row lists `tui/app.py` only; the R1-P1 cut is in `gather_project_artifacts`. No other increment of the plan lists that file. Inc 3 then changes 2 source files (cap 4). Recommendation: approve.
- **D-2 — the manifest-reader memo is not taken.** It would add about 0.06 s of margin to R-PROJ-001.13 (0.52–0.70 s instead of 0.65–0.74 s) but changes `variant_execution_service.py`'s SEC6-5 entry reader, which Inc 4 edits next and which carries security rows. Recommendation: not in this batch; a backlog note if R-PROJ-001.13's margin falls under 20 % on the LAN host at E5.
- **D-3 — the R-TST rows are this increment's.** They extend Inc 2's S0 family (R-TST) with 110 … 113. If the requirements session prefers another number range, the ids change before E3; the content does not.
- **D-4 — the variant append's margin at the folder ceiling.** Stamped, the `sec6_5 appended` arm takes 0.59–0.96 s on the E1 host (4/6 runs under 20 % margin); its sync re-reads a 6 000-entry hostile manifest and lists the project folder twice (`E1-profile.md` §2.3). It is not in the plan row. Options: (a) a backlog row now, re-measured at E5 on the LAN host (recommended: the stamp alone removes 0.1–0.4 s and R-TST-008 is judged on the LAN host); (b) extend Inc 3 with the second folder listing (one more function in `app.py`, `_activate_project_file`, and its own profile). The operator's QC-TM rule makes any arm under 20 % a gate finding, so (a) means E5 may report it.

## 5. Observations

- **O-1** — the E1 host was slower than batch-100's (base `4dfb5a1` measured 0.95–1.03 s today against 0.71–0.79 s then). Timing evidence counts only for its host and day; E5 re-measures base and head side by side.
- **O-2** — Save project's worker step runs about 0.1 s slower while the waiter keeps waking the app's loop (`E1-profile.md` §1.4). A test-harness effect on the measured interval, also present in the product while Textual repaints; no row.

## Orchestrator rulings after E1/E2 (2026-11-02)

- D-1 approved: s19_app/tui/services/project_gather_service.py joins Inc 3 (2 source files with app.py).
- D-2 accepted: no manifest-reader memo (it would edit Inc 4's variant_execution_service.py); revisit only if the LAN-host margin at E5 is under 20 %.
- D-3: the R-TST-110..113 ids stand; forwarded to the requirements session.
- D-4: (a) — a backlog row for the variant-append margin at the folder ceiling (second folder listing in _activate_project_file); re-measure base vs head at E5 on the LAN host.
- Inc 3 rebases onto main after Inc 2 (PR #212) merges and before E4: Inc 2 wrapped the same tests/test_b100_project_check.py arms with report_margin/serial_timing; the re-pinned clocks build on those wraps.
