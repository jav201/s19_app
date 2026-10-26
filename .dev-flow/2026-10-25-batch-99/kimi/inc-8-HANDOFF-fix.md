# HANDOFF — batch-99 Increment 8 · review round 1 fixes (F1–F5)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc8` (branch `b99-inc8`, base
`c62c842`). Interpreter: `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe`.
Import provenance: `python -c "import s19_app; print(s19_app.__file__)"` →
`C:\Users\jjgh8\Github\s19_app-b99-inc8\s19_app\__init__.py` (this worktree).

## What the fix round did

- **F1** — `tests/test_tui_flow_execution_b94.py`: the three provenance
  censuses (:596, :816, :981) now filter `startswith("- Chain ") and
  " input " in ln` (the `test_flow_chainset_b94.py` idiom) — the new
  Written/Not-applied/Refusals report lines no longer inflate the count.
  Re-pins recorded in the packet as old → new → LLR-156.3. Widened census:
  every report-reading test file was identified by grep and run together.
- **F2** — `tests/test_b99_patch_truth.py`: AT-B99-06/07 rewritten fully
  black-box (project staged on disk; Load project dialog via rail key `p` +
  `#project_ok`; Flow Execution via rail key `]`; `#fx_import` / picker /
  `#flow_load_ok` clicks; `pilot.click("#fx_run")`; waits on painted lane
  heads). No `_handle_load_project`, `action_show_screen`, `Button.press()`
  or attribute reads. AT-B99-06 now also asserts the mix lane PATCH card
  paints `notices` (PDR-ux row 97). 8 consecutive runs of both ATs: 16/16.
- **F3** — `s19_app/tui/services/flow_execution_service.py`: `_record_error`
  gained a `detail` parameter; all three PATCH error arms pass per-entry
  (`0x<ADDR> <disposition>`) and per-refusal (`[CODE] message`) detail lines;
  the `notices` arm extends the block diagnostics with every non-applied
  address. Cause stays LAST (UX-C2); lane terminal line unchanged (UX-C1).
  New TC arm `test_tc_b99_17_diagnostics_name_every_non_applied_address`
  (3 non-applied entries), RED-proven (`red-f3-arm.txt`).
- **F4** — new PQ-7 painted-sink mutant: `Text.from_markup(...)` at the lane
  terminal line's failure-detail sink kills AT-B99-07 with
  `MissingStyle: '@click app.quit'` at render (`mut-f4-painted.txt`);
  reverted. Packet §5 text corrected.
- **F5** — `_FX_BLOCK_STYLE` constant-map assertion dropped from TC-B99-18
  (painted-cell coverage is AT-B99-06's); the `-> Path` mis-annotation went
  away with the F2 helper rewrite; unused `flow_screens` import removed.
- **Registry** — `tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES`
  199 → 205 (MEASURED; the guard already scanned 204 at `c62c842` — five
  earlier batch-99 modules were never bumped on this base — plus this
  increment's new module).

## Verification (all transcripts under
`.dev-flow/2026-10-25-batch-99/evidence/inc-8/`)

- F1 RED: `red-f1-b94.txt` (AT-B94-20/23 `assert 8 == 2`).
- Re-pinned file GREEN: `green-f1-b94.txt` (11 passed).
- Widened census (9 files, every report-reading test):
  `green-full.txt` — **236 passed, EXIT=0** (test_b99_patch_truth,
  test_tui_flow_execution_b94, test_flow_chainset_b94, test_b97_flow_execution,
  test_flow_report_service, test_flow_report_wire,
  test_changes_symbol_entries, test_flow_report_ac6_golden,
  test_address_census).
- AT stability: `green-at-8x.txt` — 8 runs × (AT-B99-06 + AT-B99-07), 16/16.
- Registry: `green-id-registry.txt` — 13 passed.
- Mutations (5/5 KILLED, all reverted; no `MUTANT` strings remain; CRLF
  preserved in every edited file): `mut-LLR-156.1.txt` (3 failed),
  `mut-LLR-156.2.txt`, `mut-LLR-156.4.txt`, `mut-PQ7.txt`,
  `mut-f4-painted.txt`.
- Packet: `03-increments/increment-008.md` gained §8 "Review round 1 fixes"
  with the re-pin records, the widened-census list, the mutation re-runs and
  the evidence table (sha256 per transcript); §5 F4 risk text corrected;
  gate-checklist node count 17 → 18.

## Files changed in this fix round

- `s19_app/tui/services/flow_execution_service.py` (F3; SOURCE #1 of the
  increment)
- `tests/test_b99_patch_truth.py` (F2, F3 arm, F5)
- `tests/test_tui_flow_execution_b94.py` (F1)
- `tests/test_id_registry.py` (registry bump)
- Packet + evidence under `.dev-flow/2026-10-25-batch-99/` only.

No commits made (orchestrator commits). No files outside this worktree
touched. No new `TC-B99-NN` / `AT-B99-NN` numbers invented — the F3 arm is a
sub-node of TC-B99-17.

## Open questions

- The registry bound 205 absorbs five modules from earlier batch-99
  increments that were never bumped on base `c62c842`; the orchestrator may
  want those increments' packets to note the shared bump.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/services/flow_execution_service.py (F3 detail lines), tests/test_b99_patch_truth.py (F2 black-box rewrite + F3 arm + F5), tests/test_tui_flow_execution_b94.py (F1 re-pins), tests/test_id_registry.py (bound 199→205), packet §8 + HANDOFF-fix.md.
Tests added: 1 — test_tc_b99_17_diagnostics_name_every_non_applied_address (3 non-applied entries; RED-proven); AT-B99-06 gained the painted-`notices` card assertion.
RED/GREEN: RED 4 (AT-B94-20, AT-B94-23, the F3 arm, plus 16/16 mutation kills); GREEN — census 236 passed, re-pinned file 11 passed, AT-06/07 8× 16/16, registry 13 passed.
Mutations run: 5/5 KILLED and reverted (LLR-156.1, LLR-156.2, LLR-156.4, PQ-7 report sink, PQ-7 painted sink).
Open questions: the registry bump to 205 absorbs five unbumped modules from earlier batch-99 increments on base c62c842 — flagged for the orchestrator.
