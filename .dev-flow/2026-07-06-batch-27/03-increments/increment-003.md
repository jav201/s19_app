# Increment 003 (final) — US-037 stats strip + reflow, closes R-TUI-041

**BLUF:** `#map_stats` coverage strip (7 metrics) + two-regime detail reflow + `map-80x24` snapshot cell + R-TUI-041 entry. LLR-041.8/.9/.10. `code-reviewer`: **OK to advance, 0 HIGH.** Ledger 1052→1058. Closes Phase 3.

## 1. What changed
- `CoverageStats` dataclass + pure `coverage_stats()` — coverage % (`covered/span*100`, `span>0` guarded), bytes covered, valid/invalid counts, gap count, largest gap, total issues; `build_stats_text` renders markup-safe into `#map_stats_body`.
- Reflow: grid+detail wrapped in `#map_body` — horizontal (detail fixed 36-col right column beside `1fr` grid) at ≥120; vertical (detail stacked below full-width grid) under `#workspace_body.width-narrow`. Reuses existing breakpoint; header + stats full-width both regimes.
- `map-comfortable-80x24` snapshot cell (xfail-until-baseline); both map cells xfail; scaffold 28→29.
- REQUIREMENTS.md: new **R-TUI-041**; **R-TUI-026** → `Superseded by R-TUI-041` (statement preserved).

## 2. Files (5) — screens_directionb.py, styles.tcss, test_tui_directionb.py, test_tui_snapshot.py, REQUIREMENTS.md. (app.py shows Inc-1/2 changes only, untouched Inc 3.)

## 3/4. Tests
- Ledger 1052→**1058** (+6: TC-041.8 + 8-boundary + TC-041.9 + TC-041.10 + AT-037 + CARRY-F2).
- 6 new pass; directionb + engine guard **122 passed**; snapshot **30 passed / 2 xfailed** (map 120x30 + 80x24); ruff clean (authored); mypy 0 new; **0 engine-frozen diffs**.
- **C-13 measured live:** 120×30 detail BESIDE grid (grid 50 @x26, detail 36 @x78, same y) — 62-col budget honored; 100×30 + 80×24 detail STACKED below. No clip.
- **case_02 exact literals:** span 0x80010140, covered 93 B, coverage 0.000004%, gaps 3, largest gap 2,147,549,173 B, valid 4, invalid 0, issues 0.

## Code-review verdict (independent)
**OK to advance — 0 HIGH.** Stats math re-derived correct (divide guarded, gaps ordered + `gap>0`, no phantom before-first/after-last); reflow scoped to `#map_body`, CV-04 workspace tests green; REQUIREMENTS.md correct (mirrors R-TUI-028 supersession); CARRY-F2 lock = genuine trip-wire (128 cells @120x30).
- **F2 (MEDIUM, judgment flag):** coverage-% `.6f` → case_02 shows `0.000004%` (value CORRECT; a coarser `.1f` would collapse to a misleading `0.0%`). Trailing zeros on dense images (`87.500000%`). **Gate decision: keep `.6f` or polish to adaptive precision (`%g`) later.**
- F1 (LOW): stats use bare `Text.append` not `safe_text` — numeric-only, no security exposure. F3 (LOW): short-validity guard defaults valid (unreachable per aligned-lists contract).

## 5. Risks / carries
- **Snapshot baselines NOT yet generated** — both map cells xfail; regen in canonical CI (`snapshot-regen.yml`, pinned textual 8.2.8) post-merge, then retire xfails. Local regen FORBIDDEN.
- CARRY-F2 `_EXPECTED_MAP_CELLS_120x30=128` must update in lockstep with any future layout change + baseline regen (documented trip-wire).
- F2 `.6f` display — operator decision.

## 6. Pending (post-Phase-3)
Phase 4 validation (reconcile AT/TC per V-5); Phase 5 post-mortem; Phase 6 docs + batch close; baseline regen (canonical CI) + xfail retire; PR + rebase onto origin/main 4452f31 (batch-26; benign overlap).

## 7. Phase 3 COMPLETE (US-035/036/037 all shipped). Next: Phase 4 validation.
