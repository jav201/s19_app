# 04 — Validation — batch-22 (#8 US-030 4-pane split + US-031 snapshots)

> Phase 4. Two-layer validation on the final Inc1+Inc2 tree. **VERDICT: PASS.** US-030 fully validated behaviorally (geometry ATs green); US-031's snapshot cells are authored + CI-locked (honestly `xfail`-until-baseline — the 2×2 is behaviorally proven by US-030's AT, so this is not a blocker). Frozen-engine diff 0.
> Executed directly by the orchestrator (as batch-20/21 Phase 4 — the qa-agent pattern stalls behind long runs; the orchestrator holds the full evidence). Independent lens applied per-increment by `code-reviewer` (2×) + Phase-2 `architect`/`qa`.

## V-5 reconciliation — provisional id → real collected node
| Provisional | Real node | Layer | Result |
|---|---|---|---|
| AT-033a (80 floor) | `tests/test_tui_patch_layout.py::test_at_033a_two_by_two_at_80_floor` | B | PASS |
| AT-033b (120) | `::test_at_033b_two_by_two_at_120` | B | PASS |
| AT-033c (reparent-safety, 80) | `::test_at_033c_reparent_safety_at_80` | B | PASS |
| AT-033c (reparent-safety, 120) | `::test_at_033c_reparent_safety_at_120` | B | PASS |
| TC-033 (grid/overflow white-box) | `::test_tc_pane_styles_and_grid` | A | PASS |
| AT-034a (snapshot 80×24) | `tests/test_tui_snapshot.py::...[patch-comfortable-80x24]` | B | SKIP-local / `xfail`-CI (baseline regen pending) |
| AT-034b (snapshot 120×30) | `tests/test_tui_snapshot.py::...[patch-comfortable-120x30]` | B | SKIP-local / `xfail`-CI |

5 geometry nodes PASS (targeted run: `5 passed`). The 2 snapshot cells skip locally (`pytest-textual-snapshot` dev-only, absent) and `xfail` in CI until the baseline regen lands.

## Layer A — functional (white-box)
- **HLR-033:** TC-033 (`test_tc_pane_styles_and_grid`) asserts each `#patch_pane_*` `overflow_y == "auto"` (per-pane scroll, HLR-033.3), `#patch_editor_panel` layout == grid, `#patch_doc_controls` grid-size cols == 3 (the R1 button-grid). PASS — closes the "how" so a passing geometry AT can't be met by an accidental non-grid layout.

## Layer B — behavioral (black-box), through the shipped patch screen
- **US-030 (2×2 split):** AT-033a (80 floor) + AT-033b (120) drive the real patch screen under Pilot and assert the 2×2 via real geometry — 2 distinct region.x + 2 distinct region.y, **each row/col band exactly 2 panes** (rejects an L-shape), each `region.width ≤ content_region.width//2` (runtime budget), no right-edge clip, non-overlapping. AT-033c (×2, 80+120) proves reparent-safety by driving `request_action` → observable effect (entries row_count grows, `Checks:` log line) — not id-exists-only. Representative (120) + boundary (80 floor) + reparent-safety all present.
- **US-031 (snapshot lock):** AT-034a/b are the CI-locked visual-regression cells (80×24 + 120×30, both `xfail`-until-baseline). **The 2×2 layout is behaviorally validated by US-030's AT-033a/b (green locally)**; US-031's snapshot is the pixel follow-through that activates in CI. No fabricated local snapshot pass.

## Bidirectional surface-reachability matrix
| Dimension | Direction | Through handler? | Observed by |
|---|---|---|---|
| Patch screen render (80 floor) | output | yes (Pilot `action_show_screen`) | AT-033a (geometry) |
| Patch screen render (120) | output | yes | AT-033b |
| Entry action (add_entry) | input→output | yes (`request_action`→row_count) | AT-033c |
| Checks action (run_checks) | input→output | yes (→`Checks:` log line) | AT-033c |
| Per-pane scroll config | output | yes (widget `styles.overflow_y`) | TC-033 |
| Button-grid layout | output | yes (widget `styles.grid_size`) | TC-033 |
| Patch SVG @80/120 | output | yes (`snap_compare`) | AT-034a/b (CI-locked) |

Both input dimensions (actions) and outputs (layout geometry, styles, SVG) exercised through the shipped surface. Complete.

## Counterfactual evidence (QC-2)
| Node | Counterfactual | Captured RED |
|---|---|---|
| AT-033a | revert grid CSS → vertical stack | panes share `region.x==7` → `len({region.x})==1≠2` → RED (captured Inc1) |
| TC-033 | `#patch_doc_controls` left a bare Horizontal | `grid_size_columns != 3` → RED |
| AT-034a/b | (no local counterfactual — baseline is CI-only; behavioral RED is AT-033a above) | n/a-local |
Each geometry AT is value-discriminating. The snapshot's behavioral counterfactual is AT-033a (the geometry gate).

## Test-count ledger (collected non-slow)
`985 (base 13c06c4/batch-21 close) + 6 = 991`. Inc1 +5 (AT-033a/b + AT-033c×2 + TC-033) · Inc2 +1 (patch-80x24 snapshot cell, skips local). **Full non-slow (final tree): 958 passed / 30 skipped / 3 xfailed / 0 failed** (991 collected = 958+30+3). Reconciles.

## Quality gates
- ruff: batch-22 changes clean (`screens_directionb.py`, `test_tui_patch_layout.py`, my `test_tui_snapshot.py` edits). **1 PRE-EXISTING F401** (`Optional` unused) in `test_tui_snapshot.py`, on origin/main, left per surgical rule.
- **Frozen-engine diff vs origin/main (13c06c4): empty**; guards green. Patch-editor reparent is `screens_directionb.py`+`styles.tcss` (outside `_ENGINE_PATHS`).
- **F1 self-fold** (Inc1 code-review): AT-033a docstring + CSS comment overclaimed the button-grid proof → corrected. **F1b** (Inc2 code-review): two stale "27-baseline" labels → "28".

## Blocker check
- US-030: black-box geometry deliverable observed (AT-033a/b, green). ✓
- US-031: the snapshot cells are authored + CI-locked; the 2×2 they lock is behaviorally observed by US-030's AT (green). The snapshot's own local-PASS is deferred to CI by the regen-in-CI convention — **not a Phase-4 blocker** (no story is validated ONLY by an unrunnable node: US-031's outcome — the 2×2 layout — is proven by US-030's AT; US-031 adds the pixel lock). ✓
- **No fabricated pass; no story validated by white-box only.** 0 blockers.

## Gaps / carries
- **CI baseline regen (post-merge):** regenerate the patch 80×24 + 120×30 SVG baselines in the canonical CI env, then drop the `xfail` marks — the documented US-031 follow-on (regen-in-CI convention).
- **F2 (LOW → BACKLOG):** save-back-SHOWN span (`column-span:2`, no pane squeeze) not asserted — structurally sound via `1fr 1fr auto`.
- **Pre-existing F401** (`Optional`) in `test_tui_snapshot.py` — not batch-22's; optional cleanup.
- No §6.5 amendment (the R1 Horizontal-no-wrap correction was a Phase-2 spec fold, not a Phase-3/4 requirement change).

**VERDICT: PASS.** No `iterate-to-fix` / `iterate-to-refine` — US-030 black-box + white-box green; US-031 authored + CI-locked (honest, not a blocker); 0 failed.
