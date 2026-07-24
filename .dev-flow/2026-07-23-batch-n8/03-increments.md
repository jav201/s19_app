# 03 — Phase-3 increments · batch-n8 (comprehensive per-view Legend)

**BLUF:** 3 increments, all green, ≤5 files each, committed on `feat/n8-comprehensive-legend`.
Inc-1 code-reviewed inline (0 blockers); Inc-2/Inc-3 self-approved under the resume
authorization (autonomous + self-merge). Full-suite validation in 04-validation.md.

## Inc-1 — data layer (`legend.py`) · commit `b83eed9` (with Inc-2)
- **What:** `LEGEND_EXAMPLES` role-tagged card content per view; `build_band_key_rows()`
  derived from `ENTROPY_BANDS` via `band_style`; `format_cutoff()` single-source display
  transform; `LegendLine`/`BandKeyRow` NamedTuples; derived glyph helpers;
  `BAND_DOMAIN_NOTE`/`BAND_GAP_HATCH_NOTE`.
- **Tests:** `tests/test_legend_n8.py` 30 TC-N8-* incl **TC-N8-11** (markup round-trip).
- **Files (2):** `s19_app/tui/legend.py`, `tests/test_legend_n8.py`.
- **Result:** 30 passed, RED-verified (move-aside C-20), 0 regressions, ruff clean.
- **Gate:** code-reviewed INLINE (independent of the software-dev author; C-33 avoids a
  delegated-review hang). 0 blockers / 0 majors / 2 cosmetic minors (private `_*_lines()`
  lack full docstrings = trivial-return exception; `_map_band_bar_sample` hardcodes stable
  band-label keys). Operator ruling: **Aprobar → Inc-2**.

## Inc-2 — render + mapping (`screens.py`, `app.py`) · commit `b83eed9`
- **What:** `LegendScreen(view_key=)` + `_render_card`/`_render_key`. Card lines are
  `Static` (wrap not truncate — HLR-N8-6/AMD-5); map view renders the entropy band key
  (`markup=False` for the literal `[lo,hi)` bracket) with both Hex overlays in the card
  (AMD-6); MAC reconciliation sample painted `[orange3]` via `_MAC_WARNING_SAMPLE_STYLE`
  + id `#legend_mac_warning_sample` (AMD-7/AMD-11). `app._SCREEN_LEGEND_SECTIONS`
  `workspace=()` + `map=()`; `action_show_legend` passes `view_key`.
- **Tests:** AT-N8-01..05 (Pilot); N1 amendments AMD-4 (map→`Entropy bands` header,
  workspace example-only, **full-table fallback re-pointed to the genuinely-unmapped
  `flow` screen**); `test_tui_legend` `_modal_meanings` `Label`→`Static` + 4 full-table
  tests re-pointed to `flow`.
- **Files (5):** `screens.py`, `app.py`, `test_legend_n8.py`, `test_legend_scope_and_logwidth.py`,
  `test_tui_legend.py` (within the ≤5 cap; PLAN said 3 — the Label→Static widget swap
  forced the two existing legend test files, recorded).
- **Result:** full suite 1866 passed / 0 regressions (19 pre-existing tc016s snapshot
  failures **stash-verified identical on base `f56cf48`**); ruff clean on new code
  (`app.py` `F821 Dict` pre-existing on main). **Gate: self-approved (axis-check OK).**

## Inc-3 — card CSS + fold-in ATs (`styles.tcss`, `test_legend_n8.py`) · commit `6ec2a42`
- **What:** `.legend-card-sub`/`.legend-card-line`/`.legend-card-caption` — weight/dim/layout
  only, no `sev-*`/`band-*` colour (LLR-N8-6.2).
- **Tests:** **AT-N8-06** (AMD-5 — the 148-char Issues "Errors" meaning renders as a
  `Static` that WRAPS: `type(row) is Static AND size.height>=2` at 120 cols); **AT-N8-07**
  (AMD-7/AMD-11 — `#legend_mac_warning_sample` Content span carries the SAME style as
  `app._SEVERITY_TO_RICH_STYLE[WARNING]`, coupled to the live value, read off `render().spans`
  because the widget's own `render_line` is pre-compositor); **TC-N8-04** (AMD-8 — C-31
  live-column oracle: every live `#a2l_tags_list` column label has a legend line).
- **Files (2):** `styles.tcss`, `test_legend_n8.py`.
- **Result:** test_legend_n8 38 passed; all 3 legend surfaces 58 passed; ruff clean.
  **Gate: self-approved (axis-check OK).**

## Design-default rulings (autonomy, logged)
- **R-a:** full-table fallback re-pointed to `flow` (the sole screen still absent from
  `_SCREEN_LEGEND_SECTIONS`) rather than retired — AMD-4 "re-point if one remains".
- **R-b:** map/band key rows rendered `markup=False` so the literal `[lo,hi)` bracket
  round-trips safely (extends the AMD-9 markup-safety intent to the band range strings).
- **R-c:** the MAC orange is coupled to `app._SEVERITY_TO_RICH_STYLE[WARNING]` via AT-N8-07,
  not a screens.py import (app imports screens → circular); screens holds a
  `_MAC_WARNING_SAMPLE_STYLE` mirror the AT pins to the live value.
- **R-d:** `_modal_meanings` query `Label`→`Static` (Label⊂Static) to keep the 3 existing
  legend tests meaningful after the widget swap.
