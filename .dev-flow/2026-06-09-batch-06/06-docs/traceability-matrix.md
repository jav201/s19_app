# Traceability Matrix — s19_app — Batch 2026-06-09-batch-06

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Completed at batch close (phase 6). Every row is complete; there are **0 coverage gaps** (all 6 LLRs map to ≥1 passing TC).
> Validation status is taken verbatim from `04-validation.md` (Phase 4, qa-reviewer + orchestrator independent re-runs: targeted suites **108 passed / 0 failed**, lean suite **775 passed / 0 failed**, slow **19/19**, A2L guard **8 passed**).
> `File:line` references are grep-verified against the worktree at batch close (post-increment line numbers; the pre-change anchors in `01-requirements.md` §6.4 shifted by the CSS edit — e.g. `#mac_hex_pane` moved from `styles.tcss:282-285` to `styles.tcss:287-291`).

---

## 1. Master table

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-001 | HLR-001 | (roll-up of 001.1–001.6) | TC-001 | `tests/test_tui_mac_layout.py` + `tests/test_tui_directionb.py` (full targeted run) | pass | `108 passed` (qa 76.79s; orchestrator 61.71s — independent runs) |
| US-001 | HLR-001 | LLR-001.1 (`#mac_hex_pane` → `3fr`) | TC-002 | impl `s19_app/tui/styles.tcss:288` (`width: 3fr;`) · test `tests/test_tui_mac_layout.py:154` (`test_mac_hex_pane_proportional_at_wide_terminal`) | pass | At 250×40: hex grows past 86, ~43% of body; inspection: 0 standalone `width: 82` in file |
| US-001 | HLR-001 | LLR-001.2 (`#mac_records_pane` → `4fr`) | TC-003 | impl `s19_app/tui/styles.tcss:283` (`width: 4fr;`) · test `tests/test_tui_mac_layout.py:177` (`test_mac_records_pane_proportional_at_wide_terminal`) | pass | At 250×40: records ~57% of body and `records_w > hex_w` |
| US-001 | HLR-001 | LLR-001.3 (`min-width: 82` floor) | TC-004 | impl `s19_app/tui/styles.tcss:289` (`min-width: 82;`) · test `tests/test_tui_mac_layout.py:199` (`test_mac_hex_pane_floor_at_120`) | pass | At 120×30: `80 ≤ hex_w ≤ 86` AND not within ±3 of `round(3/7·body_w)` — floor, not share, in effect |
| US-001 | HLR-001 | LLR-001.4 (width-narrow MAC rules removed) | TC-005 | impl: both `width-narrow #mac_*` blocks deleted from `s19_app/tui/styles.tcss` (grep `width-narrow #mac` → 0 matches) · test `tests/test_tui_mac_layout.py:223` (`test_mac_hex_floor_holds_across_retired_breakpoint`) | pass | 121×30 and 119×30 both floored (80–86); residual body jump at 120 is the activity rail's (out of scope, documented in test docstring) |
| US-001 | HLR-001 | LLR-001.5 (records ≥1 cell at 120 cols) | TC-006 | test `tests/test_tui_mac_layout.py:244` (`test_mac_records_pane_positive_width_at_wide_terminal`, batch-05 test reused unchanged) | pass | Carry-forward of batch-05 LLR-002.4; records = 14 cells at 120 (`body_w 96 − 82`) |
| US-001 | HLR-001 | LLR-001.6 (CSS-only; A2L + `app.py` untouched) | TC-007 | inspection: `git diff main -- s19_app/tui/styles.tcss s19_app/tui/app.py` (`app.py` 0 lines; `#a2l_*` byte-identical — authoritative) · guard tests `tests/test_tui_directionb.py:1239,1281,1317` (`test_tc019_a2l_*`, `-k a2l` → 8 passed) · comment block `s19_app/tui/styles.tcss:264-274` (0 stale `35%`/`width: 40`/`width: 82`/`fixed-width` tokens) | pass | 0 engine/parser/model files in diff; expected benign grep hits documented in `04-validation.md` §2 |
| US-001 | HLR-001 | (re-band of superseded batch-05 band) | TC-021′ | test `tests/test_tui_directionb.py:1355` (`test_tc021_mac_two_panes_fixed_regime`, band 80–84 → 80–86) · companion `tests/test_tui_directionb.py:1397` (`test_tc021_mac_two_panes_floor_below_minimum`, re-purposed from the retired 35%-regime test) | pass | Green at 120×30, 160×40 (fixed_regime) and 80×24 (floor_below_minimum); per-TC run `7 passed in 5.12s` |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories (active) | 1 (US-001; US-002..US-005 deferred to batch-07) |
| Covered user stories | 1 (100%) |
| Total HLR | 1 |
| Implemented HLR | 1 (100%) |
| Total LLR | 6 |
| Implemented LLR | 6 (100%) |
| Test cases | 7 (TC-001 roll-up + TC-002..TC-007) + TC-021′ re-band |
| TC pass | 8 (100% — all 7 TCs + TC-021′) |
| TC fail | 0 |
| TC pending | 0 |

> Test-function delta this batch: 4 added, 1 deleted, 1 re-purposed, 1 re-banded, 4 survivors untouched — net +3 (lean suite 772 → 775), reconciling exactly with the Phase-4 suite counts.

---

## 3. Detected gaps

> No incomplete rows, no LLR without a passing TC, no TC without a code/test mapping. **0 blocking gaps.**

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **None blocking.** All 6 LLRs map to ≥1 passing TC; HLR-001 covered by the TC-001 roll-up. | — |

### 3.1 Non-gap items (accepted, informational)

| Item | Status | Disposition |
|------|--------|-------------|
| No test at the ~216-col knee where the proportional share overtakes the floor (TC-002 jumps 160→250) | accepted, LOW (post-mortem §6.6) | Not a coverage gap: the `min-width`-over-`fr` clamp is structurally guaranteed and was empirically confirmed twice in Phase-2 review; TC-002/TC-003 validate the proportional regime at 250 and TC-004 the floored regime at 120. **Batch-07 recommendation (A-9):** add one parametrized TC-002 width (~218×40) asserting non-decreasing hex width across the knee — opportunistic hardening; becomes MUST only if batch-07 touches MAC selectors. |
| Python 3.11 CI confirmation | outstanding (recurring since batch-05) | Local validation on 3.14.4; `tui-ci.yml` triggers only on `main-tui` PRs, so the 3.11 gate does not fire on `main` merges. Post-mortem A-3 (High): add `main` to the workflow trigger before/with the batch-06 merge. |

---

## 4. Changes from previous batch (batch-05 → batch-06)

| Type | Item | Detail |
|------|------|--------|
| supersede | R-TUI-039 (batch-05 fixed-82 model) | `#mac_hex_pane { width: 82 }` + two-regime `width-narrow 35%` replaced by A2L-parity proportional `4fr:3fr` + `min-width: 82` floor (single regime at all widths). Phase-6 doc debt: update the living `REQUIREMENTS.md` R-TUI-039 row + repoint its file/test pointers (post-mortem A-2). |
| deleted (test) | `test_mac_hex_pane_narrow_regime_unchanged` (was `tests/test_tui_mac_layout.py:139`) | Asserted the retired `hex_w < 82` at 119 cols; TC-005 (`test_mac_hex_floor_holds_across_retired_breakpoint`, `:223`) is its intent-preserving replacement per §5.2 corrected disposition. |
| re-purposed (test) | `test_tc021_mac_two_panes_proportional_regime` → `test_tc021_mac_two_panes_floor_below_minimum` (`tests/test_tui_directionb.py:1397`) | Asserted the retired 35% band at 80×24; now asserts the floor (80–86) there and documents graceful records clipping below the 120-col minimum. |
| re-banded (test) | `test_tc021_mac_two_panes_fixed_regime` (`tests/test_tui_directionb.py:1355`) | Absolute band `80 ≤ hex ≤ 84` → floor band `80 ≤ hex ≤ 86` (= TC-021′); docstring updated to the floor model. |
| survivors (tests, unchanged) | `test_mac_hex_pane_width_at_wide_terminal` (`tests/test_tui_mac_layout.py:97`), `test_mac_hex_scroll_fills_pane_height` (`:117`), `test_mac_records_pane_positive_width_at_wide_terminal` (`:244` = TC-006), `test_tc021_mac_pane_order_table_then_hex` (`tests/test_tui_directionb.py:1435`) | All four pass unchanged under the new model — their assertions (`hex_w ≥ 82`, scroll fills height, records ≥ 1, pane order) are floor-compatible. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-001** → HLR-001 → LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4, LLR-001.5, LLR-001.6 → TC-001 (roll-up), TC-002, TC-003, TC-004, TC-005, TC-006, TC-007, TC-021′

### 5.2 By code file
- `s19_app/tui/styles.tcss` → LLR-001.1 (`width: 3fr` @288), LLR-001.2 (`width: 4fr` @283), LLR-001.3 (`min-width: 82` @289), LLR-001.4 (both `width-narrow #mac_*` blocks deleted; grep → 0), LLR-001.6 (MAC comment block @264-274 rewritten to the proportional+floor model; `#a2l_*` @246-262 and `#mac_hex_scroll` @296-299 byte-identical)
- `s19_app/tui/app.py` → **0 lines changed** (LLR-001.6 negative invariant; `_compose_screen_mac` untouched)

### 5.3 By test file
- `tests/test_tui_mac_layout.py` → TC-002 (`:154`), TC-003 (`:177`), TC-004 (`:199`), TC-005 (`:223`), TC-006 (`:244`, survivor); survivors `:97`, `:117`; shared helper `_mac_layout_dims` (`:43`)
- `tests/test_tui_directionb.py` → TC-021′ (`:1355`), floor-below-minimum companion (`:1397`), pane-order survivor (`:1435`), A2L invariance guard for TC-007 (`test_tc019_a2l_*` @ `:1239`, `:1281`, `:1317`)

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-06-09-batch-06 |
| Closing date | 2026-06-10 |
| Total iterations (sum of phases) | 6 (P1=2, P2=1, P3=1, P4=1, P5=1, P6=1) |
| Total LLRs / covered | 6 / 6 (100%) |
| TCs | 7 + TC-021′ — all pass, 0 fail, 0 pending |
| Validation passed | yes (Phase-4 verdict **PASS**; lean 775/0, slow 19/19, A2L guard 8/8) |
| Synced to Obsidian | no (pending dev-flow-sync after PR merge — post-mortem A-8) |
