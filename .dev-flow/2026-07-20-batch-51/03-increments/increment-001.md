# Increment 001 — engine/model keel (headless)

**Status:** APPROVED (self-approved autonomous, 2026-07-20). Independent code-review APPROVE-WITH-NITS → all MEDIUM fixes applied.

## 1. What changed
The Inc-1 engine keel (no Textual): LLR-085.1–.3, 086.1–.5, 087.1–.3.
- `flow_model.py`: `BLOCK_CHECK`, frozen `CheckBlock(check_doc_ref, gating=advisory)`, gating constants `CHECK_GATING_ADVISORY`/`CHECK_GATING_BLOCK_OWN`, `BLOCK_STATUS_NOTICES`, `FLOW_STATUS_ISSUES="completed-with-issues"`, `Finding(severity, message)` + `FINDING_WARN="warn"`, `BlockResult.findings` (additive), `CheckBlock` in `FlowBlock` union.
- `flow_execution_service.py`: LOAD surfaces `LoadedFile.errors` as `Finding(WARN)` → block `notices` (STOP path unchanged); CHECK branch (read-only, reuses `run_check_document`/`read_change_document`/`_resolve_manifest_entry`), gating per the LLR-086.4 4-case matrix, **never sets `aborted`**; 3-way roll-up (LLR-087.2) — FAILED keyed on `aborted` alone, ISSUES on notices/non-aborting-error, else CLEAN.

## 2. Files modified (4, ≤5 cap; 0 frozen)
`flow_model.py` · `flow_execution_service.py` · `tests/test_flow_model.py` (new) · `tests/test_flow_execution_service.py` (new).

## 3. Independent code-review (code-reviewer, before gate)
Verdict **APPROVE-WITH-NITS, no HIGH**. AT-086c confirmed **non-vacuous** (drives the same unreadable-doc under advisory vs block-own-op, asserts status differs + WRITE-OUT in both; RED against a flag-ignoring or downstream-skipping mutation). Roll-up correct; pass-through real; frozen 0-diff independently confirmed. Fixes applied:
- **F1 (structural chain-never-blocked):** widened the CHECK inner `try` to enclose the whole branch body → any exception routes to the non-aborting `_record_check_own_op`, never the outer `aborted=True`. **TC-086.6** (bad-aggregate `KeyError` → assert non-aborting, downstream produces) makes the invariant structural, not contract-conditional.
- **F2:** removed unused `FINDING_STOP` (speculative).
- **F3:** `test_at085a` now pins the C-9 message (`^line \d+: ` AND no raw record payload).
- **F4:** `_load_error_message` drops the unsafe `err.get("line")` raw-content fallback.
- **F6:** test docstring reworded to match its assertion.

## 4. Test results (one run, C-19)
`pytest -q test_flow_execution_service.py test_flow_model.py test_flow_execution.py test_engine_unchanged.py` → **23 passed in 0.55s**. Ruff `All checks passed!`. Frozen `git diff` over the 7 paths = empty (0 diffs). RED counterfactuals captured: import-RED (pre-symbols) → behavioral RED (`10 failed/7 passed`, model-in/engine-out, failing for the right reason incl. AT-086c) → GREEN.

## 5. Test-count ledger
Base tracer guards `test_flow_execution.py` = 4 (untouched). New: `test_flow_model.py` 4 + `test_flow_execution_service.py` 14 (incl. TC-086.6) = 18. Evidence run total 23 (incl. frozen guard).

## 6. Gate decision (axis check)
- **Coverage:** every Inc-1 LLR has a TC; AT-085a/b, 086a/b/c, 087a/b all present at the run_flow surface. ✓
- **Certainty:** AT-086c non-vacuous (counterfactual shown); TC-086.6 makes chain-never-blocked structural; C-9 message pinned. ✓
- **Evidence:** one-run tail cited; frozen 0-diff; RED→GREEN captured. ✓
None unmet → **APPROVE**. Advance to Inc-2 (Direction A render).

## 7. Pending → Inc-2
Direction A render (LLR-088.1–.7): status→`sev-*` map (in `screens_directionb.py`, not frozen `color_policy.py`), vertical nodes, block separators, twin ribbon, CLEAN/ISSUES/FAILED banner, C-17 markup-sink sweep (AT-088b per-sink), CHECK/LOAD in the add dropdown, gating UI decision. Re-observe AT-085a/086a/087a through `render_result` (Pilot). Pilot-measure ribbon geometry at 80×24 (C-13/C-23/C-29).
