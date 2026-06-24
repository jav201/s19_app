# Increment 3 — Traceability close (US-016, LLR-016.2)

> Phase 3, batch-15. Docs-only (1 file, `REQUIREMENTS.md`). Completes Phase 3.

## 1. What changed
Added the repo-wide living-doc traceability for US-016: a new `REQUIREMENTS.md` §20 "A↔B Compare Load-Failure Honesty (batch-15)" with the `R-DIFF-LOADFAIL-001` row, mirroring the batch-13 §19 convention (references-not-inlines; points at the batch-15 dev-flow docs for the EARS statements). Added the §20 TOC line.

## 2. Files modified
- `REQUIREMENTS.md` (+65 lines, +1 TOC line). 1 file.

## 3. How to test
- Inspection: `grep R-DIFF-LOADFAIL-001 REQUIREMENTS.md`; confirm the 4 referenced AT test names exist in `tests/test_tui_diff_compare_realpath.py`.

## 4. Test results
- §20 header + `R-DIFF-LOADFAIL-001` + TOC line all present (lines 44 / 2425 / 2451).
- All 4 referenced test names verified to EXIST on disk (`test_at_016_1..._4`) — not fabricated.
- 0 mojibake; `git diff --stat` shows only `REQUIREMENTS.md` for this increment.
- No code change → no test/lint run needed; the 4 ATs already GREEN from Inc 2.

## 5. Risks
- None material. Living-doc traceability row; the full traceability-matrix + functional docs land in Phase 6. The §20 validation status references `04-validation.md` for the per-node verdict (finalized in Phase 4).

## 6. Pending items
- Phase 4 validation: run both layers (Layer A white-box + Layer B black-box ATs), the bidirectional surface-reachability matrix, and **capture the AT-016.2 pre-fix-RED vs post-fix-GREEN contrast** as the escaped-bug evidence (it was captured live in Inc 1/Inc 2; Phase 4 formalizes it).
- US-015 deferred (own batch). Pre-existing app.py ruff F401/F402 (tracked, out of scope).

## 7. Suggested next task
Phase 4 — Validation (qa-reviewer executes both layers + the escaped-bug regression evidence).

## Ledger
collection 898 (D0 / A0 — docs-only). Phase 3 complete on Inc-3 approval: Inc1 (red test, +4 ATs) / Inc2 (fix, AT-016.2 RED→GREEN) / Inc3 (traceability). 894→898 net (+4).
