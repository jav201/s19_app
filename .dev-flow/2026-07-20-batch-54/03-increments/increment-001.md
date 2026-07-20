# Increment 001 — Unfreeze a2l.py (enabling guard, LLR-ML1-2.2)

**BLUF:** Removed `s19_app/tui/a2l.py` from the C-27 dual-guard frozen set (both guard files) so batch-54's sanctioned parser edits don't trip the guard. Inverse of batch-50 P-2. Re-freeze = post-merge follow-up PR.

## 1. What changed
- `tests/test_engine_unchanged.py` — removed `"s19_app/tui/a2l.py"` from `_ENGINE_PATHS`; `# UNFROZEN batch-54` marker.
- `tests/test_tui_directionb.py` — same for the tc031 `_ENGINE_PATHS` tuple.

## 2. Files (2)
`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py`.

## 3–4. Test results
`pytest -k "tc031 or tc032 or tc027 or engine"` → **11 passed** (a2l.py no longer checked; other engine modules — core/hexfile/range_index/validation/mac/color_policy — stay frozen and unchanged).

## 5. Risks / 6. Pending / 7. Next
Risk: none (guard-list-only). a2l.py source unchanged in this increment. Re-freeze tracked as post-merge PR-B. Next: Inc-2 parser edits.
Gate axis: Coverage/Certainty/Evidence met → APPROVE (autonomous).
