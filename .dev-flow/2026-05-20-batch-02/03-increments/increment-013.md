# Increment 013 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 13 — A2L Explorer hex pane widened to a flat 3/7 ratio (review feedback)
**Phase:** 3 — Implementation (post-Phase-4 review-feedback increment)
**Date:** 2026-05-21
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs touched:** LLR-009.1 (A2L Explorer layout) — amended. · **TC touched:** TC-019.

---

## 1. What changed

The user reviewed the running app and reported that the A2L Explorer hex
viewer pane was too narrow — its content was not shown correctly. Increments
1-12 gave the A2L Explorer a two-regime width layout shared with the MAC View:
a fixed-40-column hex pane at terminal widths `>= 120` columns and a `35%`
proportional hex pane below 120 columns.

This increment widens the A2L hex pane to a **flat 3 : 4 ratio** that holds at
**every terminal width** — `#a2l_hex_pane { width: 3fr }` and
`#a2l_tags_pane { width: 4fr }` — so the hex pane is exactly **3/7 (≈42.9%)**
of the A2L content width regardless of terminal size. Because the `3fr : 4fr`
ratio is already proportional and width-responsive, the A2L panes no longer
need the `width-narrow` two-regime rule, so the A2L part of that rule was
removed.

The change is **A2L-only**. The shared `styles.tcss` rule was split: the
**MAC View** panes (`#mac_hex_pane` fixed-40, `#mac_records_pane` `1fr`, plus
the `width-narrow` `35%` proportional regime) are left **byte-for-byte
unchanged** — LLR-010.1 / MAC View still carries the iteration-3 two-regime
layout. No engine, service, renderer, parser, composition or data-processing
code was touched; `_compose_screen_a2l` already mounts `#a2l_tags_pane` and
`#a2l_hex_pane` so only their CSS widths changed.

`LLR-009.1` in `01-requirements.md` was amended from a two-regime requirement
to a flat 3/7 hex : 4/7 tags proportional ratio (`shall` EARS statement
preserved), with a supersession note recording that the iteration-3 pinned
`40 ±2 / 35% ±3` two-regime A2L split is superseded *for A2L only*, and the
reason (review feedback — 40-column hex pane too narrow). `LLR-010.1` is
explicitly called out as unchanged. AC-B9 was amended with a matching
increment-13 note. The §5.2 traceability-table row for LLR-009.1 was
reconciled to the flat ratio. TC-019's two width tests were updated to assert
the 3/7 : 4/7 ratio (±3 points for integer rounding) at 80×24, 120×30 and
160×40. The six `a2l-*` `pytest-textual-snapshot` baselines, now stale, were
regenerated; the workspace / mac / issues / map / patch / diff baselines were
not regenerated.

## 2. Files modified

**Hand-edited (3 — within the increment scope):**

1. `s19_app/tui/styles.tcss` — split the shared A2L/MAC pane rule. A2L:
   `#a2l_panes` horizontal; `#a2l_hex_pane { width: 3fr }`,
   `#a2l_tags_pane { width: 4fr }`; the A2L part of the `width-narrow` rule
   removed. MAC (unchanged): `#mac_panes` horizontal; `#mac_hex_pane` fixed-40,
   `#mac_records_pane` `1fr`; `width-narrow` `35%` MAC regime kept.
2. `.dev-flow/2026-05-20-batch-02/01-requirements.md` — amended **LLR-009.1**
   (two-regime → flat 3/7 : 4/7 proportional ratio; `shall` statement kept;
   supersession note + reason added; LLR-010.1 noted unchanged); amended
   **AC-B9** with an increment-13 note; reconciled the §5.2 LLR-009.1
   traceability-table row.
3. `tests/test_tui_directionb.py` — updated **TC-019**: the increment-6 header
   comment; `test_tc019_a2l_two_panes_fixed_regime` →
   `test_tc019_a2l_hex_pane_three_sevenths_at_wide_sizes` (asserts hex pane
   3/7 ±3 points at 120×30 / 160×40); `test_tc019_a2l_two_panes_proportional_regime`
   → `test_tc019_a2l_hex_pane_three_sevenths_at_min_size` (asserts hex pane
   3/7 ±3 points at 80×24). `test_tc019_a2l_pane_order_table_then_hex` left
   unchanged (pane order is unaffected).

**Mechanically regenerated (6 — `pytest-textual-snapshot --snapshot-update`):**

4-9. `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-{compact,comfortable}-{80x24,120x30,160x40}].svg`
— the six A2L baselines, stale because the A2L layout changed. Regenerated
via `pytest -m snapshot -k a2l --snapshot-update`. The other 21 baselines
(workspace / mac / issues / map / patch / diff) were **not** regenerated.

No other file touched. `s19_app/tui/app.py` has zero changes. `.dev-flow/state.json`
shows an unrelated pre-existing modification not produced by this increment.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed — py_compile substituted)
python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. TC-019 only
python -m pytest -q -k tc019

# 4. All 27 snapshots (the 6 A2L now match the regenerated baselines)
python -m pytest -q -m snapshot

# 5. Full suite — must hold 419 passed / 2 skipped / 3 xfailed / 0 failed
python -m pytest -q
```

## 4. Test results

**`python -m py_compile ...`** — actual output:
```
(no output — exit 0)
```
`ruff` is not installed in this environment; per the increment instructions
`python -m py_compile` was substituted and passes.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT OK
```

**TC-019** — `python -m pytest -q -k tc019` — actual output:
```
...                                                                      [100%]
3 passed, 421 deselected in 1.85s
```
The three TC-019 tests pass: the two regenerated width tests assert the hex
pane is 3/7 ±3 points of the A2L content width at 120×30 / 160×40 and at the
80×24 minimum; the pane-order test is unchanged.

**Snapshots** — `python -m pytest -q -m snapshot` — actual output (tail):
```
--------------------------- snapshot report summary ---------------------------
27 snapshots passed.
27 passed, 397 deselected in 24.20s
```
All 27 snapshots match — the 6 regenerated A2L baselines match the new A2L
layout; the 21 non-A2L baselines still match their unchanged baselines.

**A2L baseline regeneration** — `pytest -m snapshot -k a2l --snapshot-update`
— actual output (tail):
```
--------------------------- snapshot report summary ---------------------------
6 snapshots updated.
6 passed, 418 deselected in 5.02s
```
Exactly the 6 `a2l-*` baselines were updated. A `git diff --name-only` over
the working tree confirms the regenerated SVGs are exactly the 6 `a2l-*`
files — no workspace / mac / issues / map / patch / diff baseline changed.
A forbidden-path grep (`case_0[1-6]`, `professional_validation`, `C:\`,
`/home/`, `client`) over all 6 regenerated `a2l-*` SVGs returned **0 matches**
— the regenerated baselines contain only synthetic data from the
`tests/conftest.py` public generators (`make_large_s19/a2l/mac`), satisfying
LLR-007.2.

**Full suite** — `python -m pytest -q` — actual output (tail):
```
--------------------------- snapshot report summary ---------------------------
27 snapshots passed.
419 passed, 2 skipped, 3 xfailed in 181.09s (0:03:01)
```
Baseline carried into this increment was **419 passed / 2 skipped / 3 xfailed
/ 0 failed, 27 snapshots**. The post-increment result is **identical** — no
regression, no new test count drift (TC-019's two width tests were updated
in place, not added), 0 failed.

## 5. Risks

- **A2L hex pane is now wider than the MAC hex pane at the same size.** The
  A2L hex pane is 3/7 (≈42.9%) of the A2L content width; the MAC hex pane is
  the unchanged fixed-40 / `35%`. At wide terminals the two screens' hex panes
  are deliberately different widths. This is the intended outcome of the
  review feedback (the A2L hex pane needed to be wider) and a deliberate
  divergence, not a regression — LLR-009.1 and LLR-010.1 are now separate
  layout requirements.
- **TC-019 width tolerance is ±3 percentage points.** A `3fr : 4fr` flexbox
  split rounds to integer columns against the A2L content width after the
  pane borders are subtracted; 3/7 of a small content width rounds coarsely.
  The ±3-point band (39.9–45.9%) still firmly rejects the old layout — a
  fixed-40 pane at a 120-column body would read far outside the band — and a
  `3fr`/`4fr` swap (which would read ≈57%). Verified at all three sizes.
- **At 80×24 the A2L hex pane is now ≈3/7 of a small body.** The flat ratio
  gives the hex pane a *larger* share at the minimum size than the old `35%`
  regime did, so the symbol table is correspondingly narrower at 80×24. The
  table still receives a strictly-positive `4fr` remainder (asserted by
  TC-019) and the hex renderer (`render_hex_view_text`, `MAX_HEX_*` caps) is
  untouched, so this is a layout-share tradeoff, not a defect. The snapshot
  baseline `a2l-*-80x24` captures the new proportions for drift detection.
- **No visual / interactive verification.** All checks are headless
  (`pytest`, `pytest-textual-snapshot`). The widened hex pane was not eyeballed
  in a real terminal. The 6 regenerated SVG baselines are the layout record;
  a manual TUI pass confirming the hex content now renders correctly is
  advisable (see Pending items).

## 6. Pending items

- **Manual TUI confirmation of the fix** — launch `s19tui --load examples/case_01_basic_valid/firmware.s19`,
  switch to the A2L Explorer (key `2`), and confirm the widened hex pane now
  shows the hex content correctly across the 120-column breakpoint. This is
  the user-facing acceptance check for the review feedback; deferred to a
  Phase-4 re-validation touch.
- **Phase-4 validation artifacts** — `04-validation.md` records TC-019 as a
  two-regime verdict and AC-B7 / AC-B9 against the pre-increment layout. The
  validation document was **not** edited in this increment (out of the 3-file
  hand-edit scope). It should be refreshed in a Phase-4 re-validation pass to
  cite the flat 3/7 : 4/7 A2L ratio and the regenerated A2L baselines.
- **`02-review.md` / traceability-matrix.md** — neither was updated; if the
  batch docs are re-synced they should pick up the LLR-009.1 amendment.

## 7. Suggested next task

**Phase-4 re-validation touch for the A2L layout change.** Re-run the Phase-4
validation flow for the LLR-009.1 / TC-019 / AC-B7 / AC-B9 rows only: confirm
the flat 3/7 A2L ratio against the running app, update `04-validation.md`'s
TC-019 verdict and the AC-B7 / AC-B9 entries to the flat-ratio layout, and
record the 6 regenerated A2L baselines as the approved layout record. Pair
with the manual TUI confirmation above so the review feedback is closed with
an observed before/after.

**Do not start the next task — this increment (13) is complete and stops here.**
