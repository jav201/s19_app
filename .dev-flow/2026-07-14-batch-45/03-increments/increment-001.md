# Increment 1 — entropy-band style foundation (R-TUI-060 / LLR-045A.1)

1. **What changed:** NEW non-frozen band→style source for the entropy map.
2. **Files (3):** NEW `s19_app/tui/entropy_style.py` (`ENTROPY_BAND_CLASS`/`_GLYPH`/`_MEANING` +
   `band_style()` fall-through to high/random, Textual-free, derives labels from
   `entropy_service.ENTROPY_BANDS`); EDIT `s19_app/tui/styles.tcss` (`.band-constant/low/medium/high`
   colours); NEW `tests/test_entropy_style.py` (census/distinctness/CSS-safe/fall-through + non-empty
   glyph guard).
3. **How to test:** `pytest tests/test_entropy_style.py -q`; `ruff check`; C-27 guards.
4. **Results:** ruff clean; **8 passed** (7 + F1 non-empty guard); C-27 dual-guard 2 passed (0 frozen
   diffs). Ledger +8.
5. **Risks:** transient dup `ENTROPY_BAND_MEANING` vs the modal copy in screens.py (deleted Inc-5);
   colour token↔tcss binding not auto-linked (census guards token presence/distinctness).
6. **Pending:** Inc-5 must delete the screens.py `ENTROPY_BAND_MEANING` + its TC-326 (not the new
   one); confirm dropping the modal's numeric-threshold meanings is intended (F3).
7. **Next:** Inc-2 — compute-on-load (LoadedFile.entropy_windows in build_loaded_*) + band bar +
   region list + RED-first AT-069/070/071.

Code-review: APPROVE-WITH-NITS, 0 HIGH; F1 (MEDIUM) applied; F2/F3 LOW → Inc-5 heads-ups. Security:
none (pure data). Axis check clean → APPROVE.
