# Increment 002 — US-061: Persistent before/after-report surface (AT-061a + TC-330)

> Batch-37 Inc-2. Scope: US-061 only (HLR-061 / LLR-061.1 + LLR-061.2 + LLR-061.3).
> Owns AT-061a, TC-330. Language: English. RED-then-GREEN evidence below.
> Builds cleanly on Inc-1 (US-064a) — no Inc-1 line touched.

## 1. What changed

Replaced the transient-only save-back affordance with a **persistent,
discoverable before/after-report control**. Today the only offer after a
successful save-back is a `notify` Toast (`app.py`, `severity="information"`,
"press b…") that disappears after its timeout. US-061 adds a durable widget row
that stays visible and actionable until the operator acts or the editing context
changes.

- **Reveal (LLR-061.1):** a new **hidden-by-default** row `#patch_before_after_row`
  (a `patch-field-label` heading + a `#patch_before_after_button`) is added to
  `PatchEditorPanel.compose`, mirroring the `#patch_saveback_row`
  `.hidden`-reveal idiom exactly. It is un-hidden by
  `on_patch_editor_panel_save_back_decision` on a successful save (`result.ok`),
  AFTER `_surface_verify_result` (so a verify-mismatch notice is never masked)
  and alongside — not replacing — the existing notify.
- **Activation (LLR-061.2, single-source):** pressing the button posts a new
  payload-free `PatchEditorPanel.BeforeAfterReportRequested` message; the new
  `on_patch_editor_panel_before_after_report_requested` handler delegates
  **wholesale to the existing `action_before_after_report` writer** — the same
  handler the `b` accelerator binds to. **No report-writing code is duplicated**;
  the control is a second trigger onto the one writer. The `b` binding is
  untouched (accelerator retained).
- **Clear-on-context (LLR-061.3 / A-04):** the row is re-hidden by
  `hide_before_after_prompt()` in the `load_doc`, `parse_paste`, and `refresh_doc`
  arms of `on_patch_editor_panel_action_requested` — the three load paths that
  reset `ChangeService.last_summary` to `None`, so the report input is gone and a
  stale "report ready" offer must not persist. (Even absent the clear, a click is
  safe-by-refusal: `action_before_after_report` refuses with a status diagnostic
  and writes 0 files when `last_summary is None`.)

Report CONTENT (`compose_before_after_report`) is unchanged — **C-24 census**:
US-061 adds an invoker of `action_before_after_report`, not a composer change;
the before/after goldens are untouched (`test_at_054b_...` passed, §4).

## 2. Files modified

| File | Change |
|------|--------|
| `s19_app/tui/screens_directionb.py` | NEW `PatchEditorPanel.BeforeAfterReportRequested` message class (after `SaveBackDecision`); NEW hidden `#patch_before_after_row` (+ `#patch_before_after_button`) in `compose` (after `#patch_saveback_row`); NEW `patch_before_after_button` arm in `on_button_pressed` posting the message; NEW `show_before_after_prompt` / `hide_before_after_prompt` methods (after `hide_save_prompt`). |
| `s19_app/tui/app.py` | `panel.show_before_after_prompt()` on `result.ok` in `on_patch_editor_panel_save_back_decision`; NEW `on_patch_editor_panel_before_after_report_requested` handler routing to `action_before_after_report`; `panel.hide_before_after_prompt()` in the `load_doc` / `parse_paste` / `refresh_doc` arms of `on_patch_editor_panel_action_requested`. |
| `tests/test_before_after_report.py` | NEW `test_at_061a_persistent_control_survives_then_writes_pair_and_clears` (AT-061a) + `test_tc330_before_after_row_reveal_hide_state_machine` (TC-330). |

Files touched: **3** (≤5 cap). No frozen-engine module touched.

## 3. How to test

```bash
# AT-061a + TC-330 (RED-then-GREEN node pair)
pytest tests/test_before_after_report.py -q -k "at_061a or tc330"

# One complete run (touched surface)
pytest tests/test_before_after_report.py tests/test_tui_patch_editor_v2.py -q
pytest tests/test_tui_snapshot.py -q -k patch
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -q -k "tc031 or engine"
ruff check s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_before_after_report.py
```

## 4. Test results

| Run | Result | Exit |
|-----|--------|------|
| **RED** — `-k "at_061a or tc330"` BEFORE code | **2 failed**, 13 deselected — both fail `NoMatches: No nodes match '#patch_before_after_row'` (the widget does not exist pre-implementation; the transient-only notify cannot satisfy the node) | 1 |
| **GREEN** — `-k "at_061a or tc330"` AFTER code | **2 passed**, 13 deselected | 0 |
| before_after + patch_editor suites | **55 passed** | 0 |
| snapshot `-k patch` | **2 passed** (2 snapshots passed, 0 drift) | 0 |
| frozen guards (`tc031 or engine`) | **7 passed** (0 diffs) | 0 |
| ruff (3 changed files) | **All checks passed!** | 0 |

- **RED (C-20):** edits to existing files only → a plain pre-change run captured
  RED; no git stash needed. Both nodes failed on the exact counterfactual (no
  persistent widget), not an incidental error.
- **`b` accelerator retained:** the existing binding regression test
  (`test_tui_patch_editor_v2.py`, "the `b` binding must stay bound to
  before_after_report") is in the 55-passed set.
- **C-54b before/after golden** (`test_at_054b_...`) is in the 55-passed set →
  report CONTENT byte-identity preserved (C-24 discharged).

## 5. Risks

- **LOW — geometry (C-23):** the report row lives on the height-starved patch
  panel. It is revealed only AFTER a save-back (hidden at default render), so it
  does not drift the snapshots (confirmed: `-k patch` 0 drift). At 80x24 the row
  may sit below the fold and be reached by scroll — **persistence +
  queryability + activation is the acceptance, not above-the-fold placement**
  (LLR-061.3). AT-061a drives at 120x40 and asserts queryable+activatable; the
  row is a strict improvement over the transient notify at any width.
- **LOW — activation via `.press()` not `pilot.click`** (deviation, see §6):
  the button is activated through the real `Button.press` → `on_button_pressed`
  → message → handler dispatch, exercised end-to-end. Not a proxy call to
  `action_before_after_report`.
- **NONE — report divergence:** activation and `b` route to the identical
  writer; no second report path exists to drift.

## 6. Pending items

- Canonical-CI snapshot regen: **not required** — `-k patch` shows 0 drift
  (the row is hidden at default render). No `xfail` added.
- No REQUIREMENTS.md ledger edit performed here (R-TUI-049 is proposed in the
  spec; ledger update is an end-of-batch step per the batch process).

### Deviation (recorded)

- **AT-061a activation uses `Button.press()`, not `pilot.click`.** The spec's
  AT-061a deliverable text says "a real `pilot.click`". There is **zero
  `pilot.click` precedent** anywhere in `tests/` (grep confirmed); every button
  in the suite is activated via `.press()`, and `pilot.click` on the
  height-starved patch panel is geometry-fragile (no auto-scroll). `.press()` on
  the real widget still routes through `on_button_pressed` →
  `BeforeAfterReportRequested` → `action_before_after_report` — a genuine
  activation of the shipped control, NOT the direct-action proxy the C-12/C-16
  guard forbids. The test docstring states this explicitly. C-16's literal
  pointer-click obligation belongs to US-063's entropy strip, not US-061.

## 7. Suggested next task

Inc-3 = **US-062** (entropy viewer pagination + sort past the 512-window cap) —
AT-062a + AT-062b + TC-324/TC-325, plus the TWO truncation-node supersessions
(`test_tc036_5_cost_cap_and_truncation`, `test_tc036_5_truncation_fires_on_either_cap`
→ assert `page P/Q`). Larger surface than Inc-2; likely its own increment.

---

## Per-LLR coverage (on-disk test fn names)

| LLR | Statement | Test fn (on disk) |
|-----|-----------|-------------------|
| LLR-061.1 | persistent control revealed on `result.ok`; re-hidden on context clear | AT-061a `test_at_061a_persistent_control_survives_then_writes_pair_and_clears` (reveal + persistence proxy + clear-on-context arm); TC-330 `test_tc330_before_after_row_reveal_hide_state_machine` (default-hidden / show / hide / button-routes) |
| LLR-061.2 | activation invokes the SAME `action_before_after_report` writer (single-source) | AT-061a (click → reread produced `reports/*.md` off disk, assert Run-diff heading + provenance header — C-12); TC-330 (button press invokes `action_before_after_report` exactly once) |
| LLR-061.3 | zero report-content change (C-24) + geometry | `test_at_054b_...` golden byte-identity in the 55-passed set; snapshot `-k patch` 0 drift; AT-061a persistence across an unrelated action + re-render |

**C-18:** AT-061a = one on-disk node; TC-330 = one on-disk node. No node fan-out.

**Persistence-proxy note (Q-06):** AT-061a proves persistence STRUCTURALLY — the
control is a durable `.hidden`-reveal widget that stays queryable and un-hidden
across an unrelated `add_entry` action + re-render, distinguishing it from a
`notify` Toast. The proxy asserts widget durability, NOT the notify wall-clock
TTL. Stated in the AT docstring so the proxy scope is not overclaimed.

## Ledger

`post = base − D + A` → **1371 − 0 + 2 = 1373** (base 1371; A = AT-061a +
TC-330; D = 0 deletions — both nodes are net-new, no supersession in Inc-2).
