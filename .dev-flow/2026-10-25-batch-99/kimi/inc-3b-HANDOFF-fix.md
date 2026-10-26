# HANDOFF — batch-99 Increment 3b · review round 1 fixes (F1–F4)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc3b` (branch `b99-inc3b`, base
`f1ba70c`, uncommitted — orchestrator commits). Interpreter check:
`import s19_app` prints a path inside this worktree (proven at session
start).

## What the round changed

- **F1 [HIGH]** — `s19_app/tui/services/project_gather_service.py`:
  `_gather_copy` no longer compares only against `<name>`. New helper
  `_same_artifact_name` (the `stem(_N)?suffix` shape, symlinks/foreign
  stems excluded) + a sibling byte-compare scan: an unchanged re-save after
  a drift reuses the placed `_<N>` copy (`copied=False`) instead of
  stacking `_2`, `_3`, … (LLR-138.4). Module + function docstrings updated.
- **F2 [MEDIUM]** — `s19_app/tui/app.py`:
  `on_flow_execution_panel_run_requested` now paints a refused set's
  outcome-first diagnostic on the status line (`#log_line_4` via
  `set_status`) when the record has no outcomes and diagnostics (D7 / empty
  set). The confirm re-run handler drives one lane and cannot be refused,
  so it needs no paint (documented in the code comment). Handler docstring
  updated; the packet §6 "app.py was NOT edited" claim corrected.
- **F3 [MEDIUM]** — packet-only: `green-census-b97.txt` →
  `3024393a…` and `green-census-batch3.txt` → `96acb69e…` recomputed (the
  other 21 digests verified unchanged); batch 3 re-described as the FULL run
  it is (5 failed, 500 passed in 2459.16s); the 5 failures classified
  against the main-checkout PLAN.md baseline ledger (`a293213`): one
  pre-existing base-RED (`test_at031b…`, in the ledger), four long-run
  load/ordering flakes with green isolated re-runs already on disk.
- **F4 [LOW]** —
  (a) the LLR-155.3 census in `tests/test_b99_staging.py` now also flags
  `write_text` (RED probe `red-f4a-census.txt` enumerates the 7 sites);
  4 writers allow-listed (diff reports M-5 counter names, A2L dump export,
  split/join export, CRC designer template save); `save_flow_json` (:1032)
  and `save_chain_set` (:1506) pinned as **declared exceptions** (house
  exists()+counter dedup — backlog, NOT fixed, recorded in packet §6);
  (b) the UX-C10 D7 test rewritten as a painted-text pilot drive (imports
  both lanes through `#fx_import`, runs `#fx_run`, asserts the painted
  `#fx_log` — hostile lane name verbatim in `.plain`, 0 style spans;
  no `safe_text` call in the test; note: a lane name is a file stem, so the
  hostile literal is `[red]x[red]` — a `/` cannot ride a filename);
  (c) the `test_flow_chainset_b94.py:565` comment's wrong "D7's placement"
  attribution corrected to HLR-155's placement (LLR-155.3).

## Verification (all transcripts under
`.dev-flow/2026-10-25-batch-99/evidence/inc-3b/`)

- RED first: F1 arm (`red-f1-gather-reuse.txt`), F2 AT arm
  (`red-f2-at04-status.txt`), F4a probe (`red-f4a-census.txt`).
- Mutation (C-40): LLR-138.4 sibling-scan-disabled → KILLED
  (`mut-LLR-138.4.txt`), drift control stayed GREEN; revert proven by hash
  `8e4f018c…` (`post-f1-hash.txt`). No mutant left in place.
- Required files: staging+address-census+id-registry **68 passed**;
  project-gather+chainset-b94 **23 passed**; b94-TUI+b97 **85 passed + 1
  long-run flake** (`test_tc_b94_27_lane_binding_isolation_and_noop` —
  pilot timing, not in the baseline ledger, absent from this increment's
  source paths); file-level re-run **11 passed** (`green-fix-b94-rerun.txt`).
- AT-B99-04 run **8 times: 8 passed** (`green-at04-x8.txt`).
- CRLF preserved on every edited file (packet included); no commits made.
- Packet `.dev-flow/2026-10-25-batch-99/03-increments/increment-003b.md`
  updated: new §1a (review round 1 fixes), §2 amendment table (SOURCE
  3/4), §4 fix-round results + 14 new evidence rows (37 total, all hashed),
  mutation-verdicts row, ledger `32 = 23 − 0 + 9`, §6 corrections. §4b left
  `pending — orchestrator`.

## Open items for the orchestrator

- §4b independent review (this round's fixes) — orchestrator assigns.
- Backlog (recorded in packet §6): `save_flow_json` / `save_chain_set`
  conversion to HLR-155 placement (F4a declared exceptions).
- The load-flaky nodes (`test_tc_b94_27…`, `test_tc_b97_64…`) and the
  pre-existing `test_at031b…` base-RED are NOT caused by this increment;
  left for the orchestrator's suite-level decision.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/services/project_gather_service.py, s19_app/tui/app.py, tests/test_b99_staging.py, tests/test_flow_chainset_b94.py (plus packet/evidence docs) — SOURCE 3/4.
Tests added: 1 new node (`test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`); AT-B99-04 duplicate arm extended with status-line assertions; census extended with the write_text limb + 2 positive controls; UX-C10 D7 rewritten as a painted-text pilot drive.
RED/GREEN: RED transcripts 3 (F1 arm, F2 AT arm, F4a probe) + 1 probe isolation; GREEN 68 + 23 + 85(+1 flake, isolated re-run 11 passed) + AT-B99-04 ×8 = 8/8.
Mutations run: 1 (LLR-138.4, sibling scan disabled) — KILLED, drift control GREEN, revert hash-proven; Inc-3a's three mutations untouched, files restored to their Inc-3a post-state hashes.
Open questions: §4b review assignment; backlog conversion of the two declared-exception writers; suite-level triage of the long-run flakes and the pre-existing at031b base-RED.
