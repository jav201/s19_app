# Increment C — HLR-029 (D-2 skipped-line count)

> Malformed/invalid region lines now produce a visible count-only notify. 2 files. **code-reviewer: APPROVE** (0 HIGH/MED). Phase 3 COMPLETE.

## 1. What changed
`_parse_declared_regions` returns `(regions, skipped_count)`, counting the two skip sites (wrong-arity + `except ValueError`) but NOT blank lines. `on_button_pressed` unpacks, posts `GenerateRequested` with regions only, and when `skipped >= 1` raises a **count-only** `self.notify(f"{skipped} region line(s) skipped")`; silent when 0.

## 2. Files modified (2 of ≤5)
- `s19_app/tui/screens.py` (LLR-029.1/.2/.3)
- `tests/test_tui_report_seam.py` (ported `_notices`, rewrote TC-024.5, new ATs/TCs, updated AT-028b/TC-028.2 for the new return shape)

| LLR | Landing |
|---|---|
| LLR-029.1 return `(regions, skipped)` | `screens.py:543` (return :587); counts wrong-arity + ValueError, blank excluded |
| LLR-029.2 caller unpack | `screens.py:804` `regions, skipped = _parse_declared_regions(...)` |
| LLR-029.3 count-only notify + zero-suppress | `screens.py:807-813` `if skipped >= 1: self.notify(f"{skipped} region line(s) skipped")` |
| LLR-029.4 rewrite batch-19 TC-024.5 | `tests/test_tui_report_seam.py:380` unpack + `skipped == 3` |

## 3. How to test
```
python -m pytest tests/test_tui_report_seam.py -q
python -m pytest -q -m "not slow"
python -m ruff check s19_app/tui/screens.py tests/test_tui_report_seam.py
```

## 4. Test results
- New green: AT-029a (malformed `\b1\b`), AT-029b (invalid start>end `\b1\b`), AT-029c (mixed `\b2\b` + negative `not \b3\b`, blank excluded), AT-029d (all-valid + empty ⇒ ABSENCE), TC-029.1 (parse count values), TC-029.2 (zero-suppression). Rewritten TC-024.5 green. Target file 22 passed.
- Full non-slow: **968 → 974 collected (+6)**; 942 passed / 0 failed. (TC-024.5 rewritten-in-place = net 0; +6 = 4 AT + 2 TC.)
- **Counterfactual RED (QC-2):** guard → `if skipped >= 0` ⇒ spurious `'0 region line(s) skipped'` ⇒ AT-029d + TC-029.2 RED. Restored → re-green.
- ruff clean. Frozen-engine diff **0** (engine-guard tests 10 passed).

## 5. Independent review
- **code-reviewer: APPROVE.** Count correct at 2 mutually-exclusive sites (no double-count), blank not counted; **C-P3b held** (notify is count-only, no line-text interpolation — batch-19 injection surface NOT reintroduced); zero-suppression `>= 1` guarded; all 8 `_parse_declared_regions` callers unpack the 2-tuple; AT-028a (Inc-B gate) asserts a literal `.text`, doesn't call the parser → unaffected. 1 LOW cosmetic ("line(s)" plural — leave as-is). Frozen 0.
- **Carries honored:** C-P3a (`_notices` ported, installed before Generate press) + C-P3b (count-only).

## 6. Risks
- Comma-in-name now produces a visible skip-count (was silent) — known, scoped out §6.3, no security impact.
- TC-029.2 asserts zero notify on clean Generate (success path uses `set_status`, not `notify`) — intended fail-loud if a future success-path notify is added.

## 7. Pending / next
- Phase 3 COMPLETE (A+B+C). Next: Phase 4 validation (reconcile AT/TC ids to real collected nodes per V-5, bidirectional matrix).
