# Increment 001 — US-001 full scope (MAC proportional+floor layout) — batch-06

**Date:** 2026-06-09 · **Agent:** software-dev (orchestrator-verified) · **LLRs:** 001.1–001.6 · **TCs:** TC-002..TC-007, TC-021′, 2 superseded-test rewrites

## 1. What changed

**`s19_app/tui/styles.tcss`** — the CSS change per §6.2 of the requirements:
- `#mac_records_pane`: `width: 1fr` → `width: 4fr` (LLR-001.2).
- `#mac_hex_pane`: `width: 82` → `width: 3fr; min-width: 82` (LLR-001.1 + LLR-001.3).
- Deleted both `width-narrow #mac_*` blocks (the retired `35%` regime, LLR-001.4).
- Rewrote the informative MAC comment block to describe the proportional+floor model, including the note that `width-narrow` still toggles for the activity rail (unrelated to MAC sizing). 0 stale `35%`/`width: 40`/`width: 82`/`fixed-width` references remain in the MAC region (m-1 closed; remaining grep hits are `#ws_right` (other pane, untouched), the A2L comment (untouched), and the new `min-width: 82` itself).

**`tests/test_tui_mac_layout.py`** — module docstring updated to the batch-06 model; 4 new tests reusing `_mac_layout_dims`:
- `test_mac_hex_pane_proportional_at_wide_terminal` (TC-002): at 250×40, `hex_w > 86` and hex 43%±6 of body.
- `test_mac_records_pane_proportional_at_wide_terminal` (TC-003): at 250×40, records 57%±6 and `records_w > hex_w`.
- `test_mac_hex_pane_floor_at_120` (TC-004): at 120×30, `80 ≤ hex_w ≤ 86` AND hex_w NOT within ±3 of `round(3/7·body_w)` (floor, not share, in effect).
- `test_mac_hex_floor_holds_across_retired_breakpoint` (TC-005): at 121×30 and 119×30, both floored (80–86); docstring documents the residual rail body-jump as out of scope.
- DELETED `test_mac_hex_pane_narrow_regime_unchanged` (asserted the retired `hex_w < 82` at 119; TC-005 is its intent-preserving replacement, per the §5.2 corrected disposition).
- Survivors untouched: `test_mac_hex_pane_width_at_wide_terminal`, `test_mac_hex_scroll_fills_pane_height`, `test_mac_records_pane_positive_width_at_wide_terminal` (= TC-006).

**`tests/test_tui_directionb.py`** —
- TC-021′: `test_tc021_mac_two_panes_fixed_regime` re-banded `80 ≤ hex ≤ 84` → `80 ≤ hex ≤ 86`, docstring updated to the floor model (runs at 120×30 + 160×40, both floored).
- `test_tc021_mac_two_panes_proportional_regime` → re-purposed as `test_tc021_mac_two_panes_floor_below_minimum`: at 80×24 asserts the floor (80–86) instead of the retired 35% band; documents graceful records clipping below the 120-col minimum (no records assertion there).
- Survivors untouched: `test_tc021_mac_pane_order_table_then_hex`, all `test_tc019_a2l_*` / `test_tc020_a2l_*`.

## 2. Files modified
1. `s19_app/tui/styles.tcss`
2. `tests/test_tui_mac_layout.py`
3. `tests/test_tui_directionb.py`

(3 files — under the 5-file budget. `.dev-flow/state.json` also changed, but that is orchestrator workflow state, not increment code.)

## 3. How to test
```bash
pytest -q tests/test_tui_mac_layout.py tests/test_tui_directionb.py
pytest -q -m "not slow"
git diff main -- s19_app/tui/styles.tcss s19_app/tui/app.py   # A2L + app.py untouched
grep -n "width-narrow #mac" s19_app/tui/styles.tcss            # expect 0
```

## 4. Test results (verbatim, run by orchestrator)
- Targeted suites: `108 passed in 61.71s`
- Lean suite: `775 passed, 29 skipped, 19 deselected, 3 xfailed in 156.30s` — **0 failures**; xfails pre-existing; 775 vs batch-05's 772 = +3 net (4 new − 1 deleted ✓).
- `git diff --stat`: only the 3 increment files (+ `.dev-flow/state.json` orchestration state).
- A2L invariance: `git diff` shows **0 changed lines** touching any `a2l` selector (byte-identical, authoritative check per LLR-001.6).
- `grep "width-narrow #mac"` → 0 matches. Stale-token grep → 0 in MAC region.
- `app.py`, `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `models.py`: 0 changes.

## 5. Risks
- The floor keeps MAC hex at 82 for terminals 120–215 cols (operator-accepted M-1 tradeoff); proportional growth is only observable ≥~216 cols — TC-002 covers it at 250.
- Local run on Python 3.14.x; CI 3.11 is the authoritative gate (and `tui-ci.yml` only triggers on PRs to `main-tui`, not `main` — same caveat as batch-05).
- No SVG snapshot baseline touched (verified — no snapshot test exercises MAC pane widths).

## 6. Pending items / deviations
- **No spec deviations.** All thresholds implemented exactly as §5.2; the `:139` rewrite chose the spec's preferred option (delete + TC-005 replacement); the `:1399` rewrite chose the spec's preferred option (re-purpose, renamed `test_tc021_mac_two_panes_floor_below_minimum`).
- Phase-6 doc debt (already planned): update REQUIREMENTS.md `R-TUI-039` to the proportional+floor model.

## 7. Suggested next task
Phase 3 is complete with this single increment (all 6 LLRs covered). Advance to **Phase 4 — Validation** (qa-reviewer executes the §5.2 TC matrix + inspections and fills `04-validation.md`).
