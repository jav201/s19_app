# Traceability matrix — batch-50 (a2l.py F841 cleanup + re-freeze)

**Active scope (PR-A):** US-F841 / R-A2L-010. **Follow-up (PR-B, post-merge):** US-P2 / R-A2L-009. **Deferred (future batch):** US-P1b / R-A2L-008.

| US | HLR | LLR | AT (black-box) | TC (white-box) | Collected node | Status |
|----|-----|-----|----------------|----------------|----------------|--------|
| US-F841 | HLR-F841 (`R-A2L-010`) | LLR-F841.1 (delete `a2l.py:942`) | AT-094 (demo-parse parity via `parse_a2l_file`) | TC-094 (`ruff --select F841` = 0) | `tests/test_a2l_f841_cleanup.py::test_at094_demo_parse_stable_after_dead_store_removal` · `::test_tc094_no_f841_finding_in_a2l` | ✅ PASS |
| US-P2 | HLR-P2 (`R-A2L-009`) | LLR-P2.1 (re-add to both `_ENGINE_PATHS`); LLR-P2.2 (tc032 stays green) | AT-095 (guards green + empty `git diff main -- a2l.py`) | TC-095, TC-096 | `test_tc031_*` / `test_tc032_*` (`test_tui_directionb.py`), `test_tc027_*` (`test_engine_unchanged.py`) | ⏳ DEFERRED → PR-B (post-merge) |
| US-P1b | HLR-P1b (`R-A2L-008`) | LLR-P1b.1–4 | AT-090..093 | TC-090..093 | — (retired) | ⏸ DEFERRED → future batch (seed: `01-requirements.md §7`) |

**Coverage:** active-scope US-F841 → 1 AT + 1 TC, both collected & green, exactly one on-disk node each (C-18). No orphan tests; no requirement without a verifier. P-2 verifiers exist and are gated on PR-A merge (a same-PR run self-trips the vs-`main` guard).
