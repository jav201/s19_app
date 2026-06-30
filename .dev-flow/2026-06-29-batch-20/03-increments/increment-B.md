# Increment B — HLR-028 (D-1 LOAD)

> Declared regions pre-fill the Reports dialog on project-load — completes the D-1 round-trip. 3 files. **code-reviewer: APPROVE** (0 HIGH/MED).

## 1. What changed
On `_handle_load_project`, `manifest.declared_regions` are adopted into `self._declared_regions` (Inc-A's attribute); legacy/no-manifest loads RESET to `()` (no leak across projects). `action_view_reports` threads that state into `ReportViewerScreen`, whose `compose` seeds the `#report_declared_regions` TextArea with `name,start,end` lines (decimal) — exact inverse of `_parse_declared_regions`.

## 2. Files modified (3 of ≤5)
- `s19_app/tui/app.py` (LLR-028.1, LLR-028.2)
- `s19_app/tui/screens.py` (LLR-028.3, LLR-028.4)
- `tests/test_tui_report_seam.py` (4 tests)

| LLR | Landing |
|---|---|
| LLR-028.1 load→state (+ `else ()` reset) | `app.py:3977` (after `read_project_manifest`, after early-return guards) |
| LLR-028.2 thread into viewer | `app.py:1874` `declared_regions=self._declared_regions` |
| LLR-028.3 ctor param | `screens.py:667` `declared_regions: Tuple[DeclaredRegion, ...] = ()` |
| LLR-028.4 seed TextArea | `screens.py:691-698` `TextArea("\n".join(f"{r.name},{r.start},{r.end}"...), id=...)` |

## 3. How to test
```
python -m pytest tests/test_tui_report_seam.py -q
python -m pytest -q -m "not slow"
python -m ruff check s19_app/tui/app.py s19_app/tui/screens.py tests/test_tui_report_seam.py
```

## 4. Test results
- New green: **AT-028a** (GATE, C-12 full round-trip → TextArea `.text` == literal `"bootblk,4096,4351\ncal,32768,33023"`), **AT-028b** (guard, hand-written project.json), TC-028.1 (load sets state), TC-028.2 (seed↔parse idempotence). Module 12→16 passed.
- Full non-slow: **964 → 968 collected (+4)**; 936 passed / 0 failed. No regression.
- **Counterfactual RED (QC-2):** seed→`TextArea("")` ⇒ AT-028a `'' != 'bootblk,4096,4351\ncal,32768,33023'`. Restored → re-green.
- ruff clean. Frozen-engine diff **0**.

## 5. Independent review
- **code-reviewer: APPROVE.** No-stale-leak verified (`else ()` resets unconditionally on every successful load, placed after failed-load guards). AT-028a non-vacuous (literal independent of production). Seed = exact parser inverse; empty tuple → empty TextArea (no stray newline). 2 LOW notes-only (don't factor the seed helper — would couple gate to production; `⇒` glyph is existing house style). Frozen 0.
- **Security:** LOAD reads already-scrubbed manifest values; re-scrub on read via `DeclaredRegion` ctor. No new surface.

## 6. Risks
- Comma-in-name lossy round-trip (scoped out §6.3; D-2 will surface as a skip-count). No injection (scrub strips newlines).

## 7. Pending / next
- **Increment C (HLR-029 D-2):** `_parse_declared_regions` → `(regions, skipped)`; count-only `self.notify`; update batch-19 TC-024.5. Carries C-P3a (port `_notices`) + C-P3b (count-only).
