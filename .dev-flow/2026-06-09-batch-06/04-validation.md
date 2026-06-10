# Validation — s19_app — Batch 2026-06-09-batch-06

**Date:** 2026-06-09 · **Executed by:** qa-reviewer (targeted TCs + inspections) + orchestrator (full suites, re-verified independently) · **Environment:** local Python **3.14.4** (CI 3.11 is the authoritative gate — see §5 caveats)

## 1. Executive verdict

**PASS** — all 8 §5.2 matrix rows pass, all 6 §5.3 batch acceptance criteria are met, 0 blocker fails, 0 regressions. The validation re-ran every test and re-captured every inspection independently of the increment packet's claims. The single increment covers all 6 LLRs; no Phase-3 iteration required.

## 2. Per-requirement results

| Requirement | TC | Method | Evidence (verbatim) | Result |
|---|---|---|---|---|
| HLR-001 | TC-001 (roll-up) | test+inspection | `pytest -q tests/test_tui_mac_layout.py tests/test_tui_directionb.py` → `108 passed in 76.79s` (qa run); orchestrator re-run earlier: `108 passed in 61.71s` | **PASS** |
| LLR-001.1 (`#mac_hex_pane 3fr`) | TC-002 | test (integration) | `test_mac_hex_pane_proportional_at_wide_terminal PASSED` (at 250×40: hex grows past 86, ~43% of body); inspection: `width: 3fr` present, 0 standalone `width: 82` | **PASS** |
| LLR-001.2 (`#mac_records_pane 4fr`) | TC-003 | test (integration) | `test_mac_records_pane_proportional_at_wide_terminal PASSED` (records ~57% of body, records > hex) | **PASS** |
| LLR-001.3 (`min-width: 82` floor) | TC-004 | test (integration) | `test_mac_hex_pane_floor_at_120 PASSED` (80 ≤ hex ≤ 86 at 120×30; hex NOT within ±3 of round(3/7·body) — floor, not share, in effect) | **PASS** |
| LLR-001.4 (width-narrow MAC removed) | TC-005 | test+inspection | `test_mac_hex_floor_holds_across_retired_breakpoint PASSED` (121 & 119 both floored); `grep "width-narrow #mac" styles.tcss` → **0 matches** | **PASS** |
| LLR-001.5 (records ≥1 at 120) | TC-006 | test (integration) | `test_mac_records_pane_positive_width_at_wide_terminal PASSED` (existing test, unchanged) | **PASS** |
| LLR-001.6 (CSS-only, diff confined) | TC-007 | inspection + guard | `git diff main -- app.py core.py hexfile.py range_index.py validation/ models.py` → **0 lines**; `git diff main --stat -- s19_app/ tests/` → only the 3 increment files; A2L blocks **byte-identical** (0 `a2l` lines in diff — authoritative); guard `pytest -q tests/test_tui_directionb.py -k a2l` → `8 passed, 93 deselected in 6.47s`; MAC comment: 0 stale `35%`/`width: 40`/`width: 82`/`fixed-width` tokens (expected non-MAC hits documented: `#ws_right width: 40` other pane, A2L comment, the new `min-width: 82` itself) | **PASS** |
| (re-band) | TC-021′ | test (integration) | `test_tc021_mac_two_panes_fixed_regime PASSED` (floor band 80–86 at 120×30 + 160×40); `test_tc021_mac_two_panes_floor_below_minimum PASSED` (80×24 floored) — individual run: `7 passed in 5.12s` (TC-002..006 + both TC-021 tests) | **PASS** |

## 3. §5.3 Batch acceptance criteria

| Criterion | Evidence | Met |
|---|---|---|
| LLR coverage = 100% (every LLR ≥1 passing TC) | Table above — 6/6 LLRs + HLR roll-up pass | ✅ |
| 0 regressions in `pytest -q -m "not slow"` | `775 passed, 29 skipped, 19 deselected, 3 xfailed in 174.64s` — 0 failures; xfails pre-existing; 775 = batch-05's 772 + 3 net new (4 added − 1 deleted) | ✅ |
| Superseded tests resolved (0 asserting retired 35%/`hex≤84` cap) | `:139` deleted (TC-005 replacement); `:1399` re-purposed (`floor_below_minimum`); `:1355` re-banded 80–86; survivors `:82`/`:102`/`:171`/`:1438` pass unchanged | ✅ |
| A2L parity guarantee (byte-identical + guard green) | 0 `a2l` lines in `git diff`; `-k a2l` guard 8 passed | ✅ |
| Diff confinement | `git diff main --stat -- s19_app/ tests/`: exactly `styles.tcss` + 2 test files; engine/parser/model/app.py = 0 lines | ✅ |
| No SVG snapshot baseline created/regenerated | `git diff main --stat -- tests/` shows only the 2 `.py` test files; no `.svg`/snapshot dirs | ✅ |

## 4. Suite summary lines (verbatim)

```
targeted : 108 passed in 76.79s                                        (qa-reviewer run)
targeted : 108 passed in 61.71s                                        (orchestrator run)
per-TC   : 7 passed in 5.12s                                           (TC-002..006 + TC-021 pair)
a2l guard: 8 passed, 93 deselected in 6.47s
lean     : 775 passed, 29 skipped, 19 deselected, 3 xfailed in 174.64s (0:02:54)
slow     : 19 passed, 807 deselected in 523.59s (0:08:43)
```

## 5. Gaps / notes / caveats

- **No gaps.** All matrix rows executed; no TC skipped or deferred.
- **Python version caveat:** validation ran on local Python 3.14.4. CI (`tui-ci.yml`) runs Python 3.11 and is the authoritative gate — but it only triggers on PRs to `main-tui`, not `main` (same caveat recorded in batch-05; PRs #6–#9 merged the same way with local validation as the de-facto gate).
- **Design-tradeoff reminder (operator-accepted M-1):** the floor keeps MAC hex at 82 for terminals 120–215 cols; proportional growth is observable only ≥~216 cols (validated at 250 by TC-002/TC-003).
- **Phase-6 doc debt (planned):** update living `REQUIREMENTS.md` `R-TUI-039` to the proportional+floor model and repoint its file/test pointers.
