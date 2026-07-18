# fast-dev-flow spec — Discoverability: help panel + A2L Legend button

- **Date:** 2026-07-18
- **Batch:** discoverability-help-panel (prior backlog — the field-audit discoverability gap)
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** Autonomous through self-merge (operator-authorized for the prior-backlog run; approach + scope explicitly confirmed). Surface any HIGH finding / scope creep.
- **Status:** Phase A — spec

---

## 1. Objective

Make the app's keyboard bindings discoverable. Today **24 of 27 app bindings are footer-invisible**
(`show=False`) and there is **no help surface** — a user cannot learn most keys from the UI.

## 2. Root cause / opportunity (grounded)

`S19TuiApp.BINDINGS` has 24 `show=False` vs 3 `show=True`; the rail screen keys (1–8), save/load
project, dump-json, before/after report, undo/redo, paging keys, etc. never appear on the Footer.
Textual 8.2.8 ships a **free built-in help panel** — `App.action_show_help_panel` /
`action_hide_help_panel` + the `HelpPanel` widget — that renders **every** active binding (key +
description) in a dockable panel. It is currently unbound.

The A2L screen also lacks the on-screen **Legend** button that MAC (`#mac_legend_button`) and Issues
(`#issues_legend_button`) both have; A2L relies only on the `k` key (`action_show_legend`).

## 3. The change (additive — no existing layout altered; honours the v1-redesign rejection)

- **Inc 1 — Help panel.** Add one footer-*visible* binding
  `Binding("question_mark", "show_help_panel", "Help", show=True)` to `S19TuiApp.BINDINGS`. It calls
  Textual's built-in `action_show_help_panel`, which lists all bindings — so all 24 invisible keys
  become discoverable in one place, and future bindings are auto-included. No new action method, no
  layout change.
- **Inc 2 — A2L Legend button.** Add `Button("Legend", id="a2l_legend_button")` to the A2L filter
  button row in `_compose_screen_a2l`, and route `#a2l_legend_button` in `on_button_pressed` to the
  existing `action_show_legend` (exactly as the MAC/Issues buttons do).

## 4. Acceptance criteria (observable)

- **AC-1** — A `Binding` for `question_mark → show_help_panel` with `show=True` is present in
  `S19TuiApp.BINDINGS` (Footer advertises "Help").
- **AC-2** — Pressing `?` mounts Textual's `HelpPanel` (a `HelpPanel` widget is present in the DOM
  after the key); pressing it again / the panel's close removes it. (Driven through real key
  dispatch.)
- **AC-3** — The A2L screen renders a visible `#a2l_legend_button`, and pressing it pushes a
  `LegendScreen` (same outcome as the `k` key and the MAC/Issues Legend buttons).
- **AC-4** — Full gate `pytest -q -m "not slow"` green **except** the expected Footer SVG drift (see
  §6); no engine module or frozen test file modified.

## 5. Security flags

Scanned. No auth/secrets/external/PII/destructive-DB/network patterns. `security_required: **false**`.
Both changes are read-only UI affordances over existing actions.

## 6. Snapshot drift (expected, handled)

A footer-*visible* binding renders on the Footer of **every** screen, so the wide-cell `tc016s` SVG
baselines drift (batch-45 FOOTER-DRIFT precedent). Adding the A2L Legend button also drifts the A2L
screen cells. Per the snapshot-regen policy these regenerate **only in canonical CI** (textual==8.2.8),
not locally. Handling: mark the expected-drift cells (a `_discoverability_drift_marks` xfail set, tight
per-cell, 0 xpassed) so the PR gate is honest, then a **canonical-CI snapshot-regen** follow-up clears
them (the batch-45/48 pattern).

## 7. Files (blast radius)

**Increment 1 (2 files):**
1. `s19_app/tui/app.py` — the `?` Help binding.
2. `tests/test_tui_directionb.py` (or a new test file) — AC-1/AC-2 (binding present + `?` mounts HelpPanel).

**Increment 2 (2 files):**
3. `s19_app/tui/app.py` — the A2L Legend button + `on_button_pressed` route (same file, one increment later).
4. `tests/…` — AC-3 (button present + pushes LegendScreen).

**Increment 3 — snapshot drift marks + docs (2 files):**
5. `tests/test_tui_snapshot.py` — the expected Footer/A2L drift xfail marks.
6. `REQUIREMENTS.md` — note the help-panel discoverability affordance + A2L Legend parity.

## 8. Deferred (rest of the discoverability gap — separate items)

- Footer mid-word truncation at 120 cols · settings-menu surfacing (palette-only today) · CRC-write
  2-deep modal chain · the 14/30 A2L tag fields dropped from the table.

## 9. Batch status

| Current phase | Phase A — spec written |
