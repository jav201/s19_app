# Traceability matrix — batch-54 (Multi-line A2L header parsing)

| US | HLR | LLR | AT (black-box) | TC (white-box) | Collected node(s) | Status |
|----|-----|-----|----------------|----------------|-------------------|--------|
| US-ML1 | HLR-ML1-1 (`R-A2L-011`) | LLR-ML1-1.1/1.2/1.3/1.4/1.6 | AT-096 (golden), AT-097 (50/50 universal) | TC-097/098/099 | `tests/test_a2l_multiline_headers.py` (30 nodes) | ✅ PASS |
| US-ML1 (no-reg) | HLR-ML1-2 (`R-A2L-011`) | LLR-ML1-2.1 | AT-098 (single-line), AT-099 (MEAS+synthetic, count-guarded) | — | same + `test_a2l_f841_cleanup.py` census | ✅ PASS |
| US-ML2 | HLR-ML2-1 (`R-A2L-012`) | LLR-ML2-1.1 | AT-100 (MaxAxisPoints+external) | TC-100 | same | ✅ PASS |
| SAFE | HLR-SAFE-1 (`R-A2L-013`, C-17) | LLR-SAFE-1.1 | AT-101 (hostile+positive+`@slow` DoS) | TC-097/101 | same | ✅ PASS |
| scope | — | — | AT-102 (length None), AT-103 (render C-17) | — | same | ✅ PASS |
| freeze | — | LLR-ML1-2.2 | — | TC-102 | `test_engine_unchanged.py` / `test_tui_directionb.py` (a2l.py UNFROZEN) | ✅ (re-freeze = PR-B) |

**Coverage:** every US → ≥1 black-box AT through `parse_a2l_file`; every LLR → TC/inspection. C-18: each gate-blocking AT (096/097/098/099/100/101/102) reconciles to exactly one on-disk node (Phase-4 `--collect-only` verified). Gate 1652 passed / 0 failed / 29 snapshots 0 drift. **a2l.py re-freeze deferred to post-merge PR-B; MEASUREMENT multi-line deferred (no-regression AT-099); array length = batch-55.**
