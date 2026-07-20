# Increment 001 — F841 dead-store cleanup (US-F841 / R-A2L-010)

**BLUF:** Deleted the dead `header` local at `a2l.py:942`; ruff F841 is now clean and the demo parse is provably unchanged. Independent `code-reviewer`: **APPROVE, 0 findings**. All guards green. Gate SELF-APPROVED (autonomous). This is the only Phase-3 increment of PR-A; P-2 re-freeze follows as PR-B post-merge.

## 1. What changed
- `s19_app/tui/a2l.py` — removed the dead store `header = header_meas or header_char` (former :942) inside the `extract_a2l_tags` walk closure (LLR-F841.1). Only bare-`header` occurrence in the walk; RHS is side-effect-free; `header_meas`/`header_char` are consumed directly (:975/:981/:1055/:1058).
- `tests/test_a2l_f841_cleanup.py` — NEW (non-frozen sibling; NOT the tc032-frozen `test_tui_a2l.py`). TC-094 (ruff F841=0) + AT-094 (demo-parse behavior parity).

## 2. Files modified (2 + 0 consequence)
- `s19_app/tui/a2l.py` (−1 line)
- `tests/test_a2l_f841_cleanup.py` (NEW, +106)

## 3. How to test
```
python -m ruff check --select F841 s19_app/tui/a2l.py
python -m pytest -q tests/test_a2l_f841_cleanup.py tests/test_a2l_record_layout_length.py tests/test_a2l_missing_length_fix.py tests/test_a2l_enriched.py tests/test_tui_a2l.py
python -m pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py
```

## 4. Test results (evidence — read from each run's own output, C-19)
- **TC-094** `ruff --select F841 s19_app/tui/a2l.py` → `All checks passed!` rc=0. **Counterfactual:** pre-fix ruff reported exactly **1** F841 error at a2l.py:942 (captured at Phase-0 recon) → RED-on-pre-fix.
- **AT-094 + TC-094** `tests/test_a2l_f841_cleanup.py` → **2 passed** (both, not skipped). Pinned literals independently re-derived by the reviewer: tags 75 · MEAS 25 · CHAR 50 · MEAS-with-length 24 (all with datatype) · `ASAM.C.VIRTUAL.ASCII` char_type ASCII / length 100.
- a2l regression suites (record-layout-length, missing-length-fix, enriched, tui-a2l) → **39 passed / 2 pre-existing skips**.
- Frozen guards `tc031/tc032/tc027` → **10 passed** (a2l.py correctly still UNFROZEN → sanctioned edit does not trip; P-2 re-freeze is PR-B).
- **C-34 full guard-host** `test_tui_directionb.py` → **174 passed** (179.84s, exit 0); no escape (contrast batch-49 Inc-1 markup-guard escape).
- `test_engine_unchanged.py` → 1 passed.

## 5. Independent review
`code-reviewer` (independent of author) → **APPROVE**. Verified: delete genuinely dead (grep clean; RHS pure; compiles/parses); AT-094 non-vacuous and loud (C-10/rule-9); TC-094 honest (skips, not silent-pass, when ruff absent); convention-clean; proportionate (no bloat). No HIGH/MEDIUM/LOW.

## 6. Risks
- None new. Security-neutral dead-store removal (security-reviewer F6). a2l.py remains unfrozen until PR-B (P-2). The reviewer's non-blocking note (confirm P-2 sequencing accounts for this batch's diff) is already the design: PR-B is guard-files-only off *merged* main.

## 7. Pending / next
- Phase 3 COMPLETE (single increment). → Phase 4 validation (orchestrator-owned gate suite, C-25).
- P-2 re-freeze = PR-B, post-merge follow-up (LLR-P2.1/P2.2, AT-095).
- Gate axis check: Coverage (AT-094+TC-094 both green, LLR-F841.1 covered) / Certainty (AT-094 through-surface + non-vacuous, counterfactual = pre-fix 1 F841 error) / Evidence (every item cited with run output) — none unmet → **APPROVE**.
