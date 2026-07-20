# Review — s19_app — Batch 2026-07-20-batch-51 (Phase-2 cross-agent review)

**Verdict:** ITERATE (1 blocker + 2 major) → all folded into `01-requirements.md` (§6.4 REC-4/5/6/7) → re-gate PASS → Phase 3.
Three reviewers ran in parallel over `01-requirements.md`: `architect` (completeness/derivation/normatives), `qa-reviewer` (testability/AT non-vacuity), `security-reviewer` (untrusted-input/attack surface).

## Findings (classified)

### BLOCKER (converged — architect B-1 ≡ qa B1)
- **AT-086c incoherent with LLR-086.1/086.4.** The Phase-1 fold of qa's gating-coverage concern authored AT-086c against a **phantom** gating value `"block"` and a **phantom** status `"blocked"`, on a **false-failing** trigger (entries-absent). The model defines only `CHECK_GATING_ADVISORY`/`CHECK_GATING_BLOCK_OWN` and statuses `ok/notices/error/skipped`; per LLR-086.4 a readable-but-failing check never flips the status → AT-086c(a) would go RED against a *correct* implementation. **Both reviewers independently re-derived the identical blocker.**
  - **Disposition (REC-4):** reauthored AT-086c to drive the SAME unreadable-doc input under both real tokens, asserting status differs (`notices` vs `error`) + WRITE-OUT produces in both — the true C-10 observed-change. → seeded the global control **C-36** (fold-against-defined-vocabulary).

### MAJOR
- **M-1 (architect): LLR-086.4 gating matrix un-tabulated** — threshold said "per the matrix above" but only prose existed (the root cause enabling B-1). **Disposition (REC-5):** tabulated the explicit 4-cell truth table.
- **M1/F2 (qa + security): markup-sink sweep hand-enumerated** — LLR-088.6/AT-088b listed 4 example sinks + tested "a node", risking an unswept sink (the batch-33/43/48 pattern). **Disposition (REC-6):** widened to a CODE-DERIVED sink set (incl. diagnostics), each sink hostile-tested `plain` verbatim + `spans==[]`; banner/ribbon excluded as non-file-derived (security F1).

### MINOR (REC-7 — folded or Phase-3/4 notes)
- qa m2: US-087 §5.2 to cross-ref AT-088a as the banner observer (folded).
- qa m1 (AT-086a fixture: derive an absent address from outside seeded ranges), qa m3 (AT-085a exactly-one-error boundary), qa m4 + architect m-1 (off-by-one citations; provisional test-file name `test_flow_execution_service.py` vs existing `test_flow_execution.py`) → Phase-3 authoring / Phase-4 reconciliation notes (V-5).

## Verified sound (no action)
- **Roll-up supersession (LLR-087.2)** genuinely replaces the 2-way collapse (`flow_execution_service.py:210-213`); complete for all block-status × `aborted` combos.
- **Chain-never-blocked (LLR-086.4/086.5):** no CHECK path sets `aborted=True`.
- **Frozen-file claim HOLDS** — no LLR implicates any frozen module; status→`sev-*` map lives in `screens_directionb.py`, not frozen `color_policy.py`.
- **Normative discipline clean** — no modal `should` inside any HLR/LLR.
- **Draft-time citations real** (spot-checked: `run_check_document` `check.py:194`, `build_loaded_*`/`LoadedFile.errors`, `.sev-*` classes, render seam `:2187`, `$rule:30`).
- **Security:** no new untrusted-file loader (reuses hardened `run_check_document`); path resolution reuses the existing `_resolve_manifest_entry` containment guard (not a fork); no new write/exec/network surface; C-17 markup-safety correctly required. **OK to ship.**

## Evidence checklist
- ✓ architect / qa / security ran in parallel; findings classified blocker/major/minor.
- ✓ Both traceability chains complete; every output-producing requirement names its observable deliverable.
- ✓ All blockers/majors folded body-first, recorded in §6.4 with parent-HLR re-read.
- ✓ Re-gate: reauthored AT-086c self-verified coherent vs LLR-086.1/086.4/086.5 (convergent-prescription fix; re-dispatch deemed unnecessary — recorded).
