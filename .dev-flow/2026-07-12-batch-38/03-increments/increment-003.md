# Increment 003 — US-067 (B-18) — Variant-selector info/help popup

**Story:** US-067 / HLR-067 (R-TUI-056) · LLR-067.1 + LLR-067.2 + LLR-067.3
**Tests:** AT-067a (black-box, C-16 real click) + TC-336/TC-337 (white-box) + geometry pilot-measure (C-23)
**Base:** `claude/stat-batch-38-dev-flow-2d7ba9` @ `5a6c45b` (batch-38 base; Inc-1/Inc-2 applied in the working tree)
**Type:** first GEOMETRY increment — new info button + new help `ModalScreen`, pilot-measured (no fr-math)

---

## 1. What changed

Added an **info/help affordance** to the Patch Editor's variant selector and a new
help modal explaining what the selector does.

1. **Info button (LLR-067.1)** — `screens_directionb.py`: the variant pane's
   `#patch_variant_row` now wraps `Select#patch_variant_select` + a new
   `Button("?", id="patch_variant_info_button")` in a `Horizontal`
   (`id="patch_variant_select_row"`). The Select is `1fr`, the "?" button
   auto-width, so both share the row. The button is **always rendered** and
   unconditionally enabled (Phase-2 M-b: not gated on ≥2 variants), so its click
   target always exists. The `#patch_variant_select` id is **unchanged** —
   `set_variants` / `on_select_changed` still find it (`query_one` walks
   descendants), confirmed by the passing sibling census tests.

2. **Message + routing (LLR-067.2)** — `screens_directionb.py`: new payload-free
   `PatchEditorPanel.VariantHelpRequested` message; `on_button_pressed` posts it
   for `#patch_variant_info_button` (mirrors the batch-37
   `EditJsonRequested` idiom). `app.py`: new handler
   `on_patch_editor_panel_variant_help_requested` → `push_screen(VariantHelpScreen())`.

3. **Help modal (LLR-067.3)** — `screens.py`: new `VariantHelpScreen(ModalScreen[None])`
   (alongside `ChangeSetJsonScreen`), rendering the static `VARIANT_HELP_TEXT`
   constant through a `markup=False` `Static` (`#variant_help_body`) + a Close
   button (`#variant_help_close`), on the shared `.modal-dialog` box model
   (`height: auto` — no new CSS rule). Self-dismisses on Close (the `LegendScreen`
   idiom). Static text, no untrusted interpolation → no markup/style leak (C-17).

New ids/symbols are all DISTINCT (C-26): `#patch_variant_info_button`,
`#patch_variant_select_row`, `VariantHelpRequested`, `VariantHelpScreen`,
`VARIANT_HELP_TEXT`, `#variant_help_dialog/_body/_close/_buttons`. No existing
id reused or renamed.

## 2. Files modified (5 source/test files; state.json is orchestrator-owned)

- `s19_app/tui/screens.py` — new `VARIANT_HELP_TEXT` constant + `VariantHelpScreen`.
- `s19_app/tui/screens_directionb.py` — `VariantHelpRequested` message, the info
  button in the variant-pane compose, and the `on_button_pressed` branch.
- `s19_app/tui/app.py` — import `VariantHelpScreen` + the push handler.
- `tests/test_tui_variants.py` — `+3` nodes:
  `test_at067a_variant_info_button_opens_help_modal` (AT-067a, real click),
  `test_tc336_tc337_help_message_pushes_modal_with_content` (TC-336/337),
  `test_variant_help_modal_fits_at_both_sizes` (C-23 geometry inspection),
  plus the `_open_patch_with_two_variants` helper + `_VARIANT_HELP_TOKENS`.
- `tests/test_tui_snapshot.py` — extended the `_batch38_drift_marks` reason to
  name the US-067 info button (the mark already covers both `patch` cells).

Frozen set untouched (§7).

## 3. How to test

```bash
# AT-067a + TC-336/337 + geometry (the increment's tests)
python -m pytest tests/test_tui_variants.py -k "at067a or tc336 or fits" -q

# Full variant + patch-editor regression sweep
python -m pytest tests/test_tui_variants.py tests/test_tui_patch_variant.py \
  tests/test_tui_patch_layout.py tests/test_tui_patch_editor_v2.py -q

# Snapshot patch cells (expected xfail drift, non-gating)
python -m pytest tests/test_tui_snapshot.py -k patch -q

# Lint + frozen guard
python -m ruff check s19_app/tui/screens.py s19_app/tui/screens_directionb.py \
  s19_app/tui/app.py tests/test_tui_variants.py tests/test_tui_snapshot.py
python -m pytest tests/test_engine_unchanged.py -q
```

## 4. Test results

| Check | Result | Evidence |
|-------|--------|----------|
| AT-067a + TC-336/337 + geometry | **3 passed** | `3 passed in 6.15s` |
| RED-first counterfactual (pre-wire) | **1 failed as designed** | `NoMatches: No nodes match '#patch_variant_info_button' on Screen` (the real click has no target) |
| Full `tests/test_tui_variants.py` + `test_tui_patch_editor_v2.py` | **55 passed** | `55 passed in 63.96s` |
| Sibling census: `test_tui_patch_variant.py` + `test_tui_patch_layout.py` | **18 passed** | `18 passed in 34.26s` (variant-pane child census `["patch_variant_row","patch_execute_row"]` intact) |
| Snapshot patch cells | **2 xfailed** (expected drift) | `32 deselected, 2 xfailed` |
| ruff (5 touched files) | **clean** | `All checks passed!` |
| Ledger (collected, `-m "not slow"`) | **1372 → 1375 (+3)** | live collect: `1375/1395 tests collected`; A=3, D=0 |
| Frozen-file guard | **0 frozen diffs** | `tests/test_engine_unchanged.py` 1 passed; `git diff --name-only` → none in frozen set |

**RED → GREEN evidence (AT-067a, C-16 REAL click):**
- **RED (pre-wire):** `await pilot.click("#patch_variant_info_button")` →
  `textual.css.query.NoMatches: No nodes match '#patch_variant_info_button' on
  Screen(id='_default')` — the click target does not exist on `main`/pre-wire.
  The AT drives a **real pointer** `pilot.click` (not `.focus()`, not a direct
  `push_screen`), so the RED is "no click target", exactly the counterfactual.
- **GREEN (post-wire):** the same real click makes `app.screen` a
  `VariantHelpScreen`; the body renders the three required content tokens; Close
  dismisses back to the prior screen. `3 passed in 6.15s`.

## 5. Geometry — pilot-measured (C-23, no fr-math)

The modal size is measured on the running app after a real click, at both sizes.
Both fit fully on-screen with body + Close visible:

| Size | Dialog region (x,y,w,h → right,bottom) | Fits? | Body | Close |
|------|----------------------------------------|-------|------|-------|
| **80×24** (tight floor) | x=12 y=1 w=53 h=23 → right=65, bottom=24 | **yes** (right 65 ≤ 80, bottom 24 ≤ 24) | 47×13 visible | 16×3 visible |
| **120×30** (comfortable) | x=19 y=5 w=82 h=19 → right=101, bottom=24 | **yes** (right 101 ≤ 120, bottom 24 ≤ 30) | 76×9 visible | 16×3 visible |

Measured via `dialog.region` / `body.region` / `close.region` under
`App.run_test(size=...)`; asserted in `test_variant_help_modal_fits_at_both_sizes`.
This is an inspection **additive to AT-067a**, not a gating fr-derived size.

## 6. Risks

- **Low.** Additive UI: one always-enabled button + one static help modal. No
  variant-selection behavior touched; no engine file touched.
- **Snapshot drift (R-D, expected):** the two `patch-comfortable-{80x24,120x30}`
  SVG cells re-render because the variant pane now shows the "?" button (on top of
  the Inc-1 copy drift). Both were **already** marked `xfail(strict=False)` by
  `_batch38_drift_marks` (keyed on `screen == "patch"`), so no new cell needed
  adding — only the reason string was extended to name US-067. Baseline regen is
  **canonical-CI only** (snapshot-regen.yml, pinned textual==8.2.8); a follow-up
  PR drops the xfail once the baselines land.
- **Layout (C-23):** wrapping the Select in a `Horizontal` shrinks its width by
  the "?" button (~4 cols). The sibling geometry census
  (`test_tc_035_2_variant_group_above_execute_row`) still passes at both sizes —
  the Select's first row stays visible and un-clipped.

## 7. Evidence checklist (C-26 census + frozen guard)

- **C-26 reverse census:** reverse-grepped `patch_variant_info_button`,
  `patch_variant_select_row`, `VariantHelpRequested`, `VariantHelpScreen`,
  `variant_help_*` across `tests/` — all confined to the new `test_tui_variants.py`
  nodes; **0** pre-existing tests reference them. **Sibling sweep (batch-37 TC-319
  lesson):** the variant-pane's structural/census tests
  (`test_tui_patch_variant.py:392/429` pins `#patch_pane_variant`.children ==
  `["patch_variant_row","patch_execute_row"]`; `test_tui_patch_layout.py`) were
  RUN and **pass** — the new `Horizontal` sits INSIDE `#patch_variant_row`, so the
  pane's direct-child census is unchanged and **no panel-child/census test needed
  the new button added**. Existing `#patch_variant_select` refs
  (`test_tui_patch_variant.py`, `test_tui_patch_editor_v2.py`, `test_tui_snapshot.py`)
  all survive. New-id collision check in `s19_app/`: each new id appears only in
  the new code.
- **Frozen files:** `git diff --name-only` shows Inc-3 touched
  `s19_app/tui/{app,screens,screens_directionb}.py`,
  `tests/test_tui_variants.py`, `tests/test_tui_snapshot.py` — **0** in the frozen
  set (`core.py`/`hexfile.py`/`range_index.py`/`validation/*`/`tui/a2l.py`/
  `tui/mac.py`/`tui/color_policy.py`). `test_engine_unchanged.py` passes.
- **File cap:** 5 source/test files edited (≤5). ✓
- **No secrets, no destructive commands.** ✓
- **Docstrings + type hints** on the new `VariantHelpScreen`, the handler, the
  message class, and the test helpers (7-section order where non-trivial). ✓
- **Ledger:** base 1372 → post 1375 (A=3, D=0). ✓

## 8. Suggested next task

Increment 4 — **US-068a (B-19a)**: patch-editor change-set undo/redo — bounded
deep-copy history in `ChangeService` (`_undo_stack`/`_redo_stack`, `_HISTORY_MAX`),
`undo()`/`redo()` restore semantics, Undo/Redo buttons wired via real click, and
the **A-01 disable-guard** (controls DISABLED when `source_path is not None`,
LLR-068a.4). AT-068a + TC-338/339/340/344.
