# Functionality — s19_app — Batch 2026-06-26-batch-18

> Phase 6 artifact. Audience: technical stakeholder / maintainer. Feature #11 — classification legend (Q1 report + Q2 in-app).

## 🔑 At a glance
Operators reading a colour-coded view or a generated report no longer need external docs to interpret row colours. The same documented colour→meaning key (A2L / MAC / Issues, per REQUIREMENTS.md §3) now appears in two places, both fed from one source: a **Legend section in the generated project report** (Q1) and an **in-app Legend modal** reachable from each colour-coded view (Q2).

## Operator walkthrough

### Q1 — legend in the report (US-022)
- Generate a project report as before. It now carries a `## Legend` section (after the consolidated overview) listing, per artifact, each classification and its meaning — e.g. *Red — schema/structural failure*, *Green — memory-checked + present*, *Orange — MAC warning: overlap/alias/symbol-only*.
- The legend is **on by default**. A caller can suppress it with `ReportOptions(include_legend=False)` (e.g. for a minimal report).

### Q2 — in-app Legend modal (US-023)
- **MAC view** and **Issues view:** press the new **"Legend"** button in the controls row.
- **A2L explorer:** press the **`k`** key (shown in the footer as "Legend"). The A2L filter row is already full, so there is no button there — the key is the affordance (see C-13 below).
- A modal opens listing every A2L / MAC / Issues classification, **colourized with the same `sev-*` colours the views use** (red/green/amber/cyan/grey; "White" rows render in the default foreground). It is the same content regardless of which view opened it. Press **Close** to dismiss.
- The legend is static: it opens and shows the full key even with **no file loaded**.

## Maintainer seams

| Concern | Where | Notes |
|---------|-------|-------|
| **Single source of truth** | `s19_app/tui/legend.py::LEGEND_TABLE` | `artifact → {classification: (colour, meaning)}`. Edit here to change legend content; both report and modal follow. |
| **Engine-frozen constraint** | NOT `color_policy.py` | `color_policy.py` is git-frozen (`test_tui_directionb.py::_ENGINE_PATHS`). The legend table lives in the new non-frozen `legend.py`; `color_policy.css_class_for_severity` is only READ. |
| **Anti-drift to the engine** | `legend.py::COLOUR_SEVERITY` | Maps each legend colour → `ValidationSeverity`. `TC-S1` fails if a new `SEVERITY_CLASS_MAP` severity has no legend colour. |
| **Report rendering** | `report_service.py::_legend_lines` (`:923`), gated by `ReportOptions.include_legend` (`:192`) | Reads `LEGEND_TABLE`; no duplicated literal. |
| **Modal rendering** | `screens.py::LegendScreen` (`:474`) | `ModalScreen[None]`; iterates `LEGEND_TABLE`; self-handled Close. |
| **In-app entry points** | `app.py::action_show_legend` (`:3059`) | Reached by the `k` binding (`:563`) and the MAC/Issues button ids via `on_button_pressed` (`:7511`). |
| **Q1/Q2 anti-drift** | `TC-S2` (`test_tc_s2_report_and_modal_render_same_rows`) | Compares the rendered row-sets of report vs modal; fails on divergence. |

## C-13 geometry note (why A2L differs)
The A2L filter row (`#a2l_tags_filters`) is a horizontal row of 9 widgets in a half-width pane; it already overflows. Draft-time measurement showed a 10th "Legend" button renders off-screen at both 80 and 120 cols, so A2L uses the `k` key instead of a button. MAC (2 widgets) and Issues (3) have budget and keep visible buttons. Recorded as §6.5 amendment A1.

## Validation
Full non-slow suite 908 passed / 0 failed. Both stories covered black-box (AT) + white-box (TC); engine-frozen untouched (`color_policy.py` diff=0). SVG snapshot baselines for the three views regenerate in canonical CI at PR.
