# Increment 004 — US-068a (B-19a) — Patch-editor change-set undo/redo

**Story:** US-068a / HLR-068a (R-TUI-057) · LLR-068a.1 + LLR-068a.2 + LLR-068a.3 + LLR-068a.4 (A-01 guard)
**Tests:** AT-068a (black-box, C-16 real click) + TC-338/TC-339 (unit) + TC-344 (A-01 pilot)
**Base:** `claude/stat-batch-38-dev-flow-2d7ba9` @ `5a6c45b` (batch-38 base; Inc-1/2/3 applied in the working tree)
**Type:** new service capability (bounded deep-copy history) + 2 new UI controls + A-01 disable-guard

---

## 1. What changed

Added **change-set-level undo/redo** to the Patch Editor: a bounded, deep-copy
history in `ChangeService`, two new Undo/Redo buttons wired via real click, and
the A-01 data-loss disable-guard.

1. **Bounded deep-copy history (LLR-068a.1)** — `services/change_service.py`:
   `ChangeService` gains `_undo_stack` / `_redo_stack` (lists of
   `ChangeDocument`), a module constant `_HISTORY_MAX = 20`, and a private
   `_push_history()` that `copy.deepcopy`s the current document onto the undo
   stack, evicts the oldest snapshot past `_HISTORY_MAX`, and clears the redo
   stack. `_push_history()` is called immediately before each of the five
   document-mutating operations — `add_entry`, `edit_entry`, `remove_entry`,
   `load`, `load_text` — placed **after** input validation / index lookup so a
   rejected input pushes no no-op snapshot.

2. **undo() / redo() restore semantics (LLR-068a.2)** —
   `services/change_service.py`: `undo()` pushes the live document onto the redo
   stack and pops the top undo snapshot as the new live document (`last_summary`
   reset — a restored change-set has no matching apply); `redo()` is its mirror.
   Each is a no-op returning the unchanged document when its source stack is
   empty.

3. **Undo/Redo controls wired to the surface (LLR-068a.3)** —
   `screens_directionb.py`: two payload-free messages `UndoRequested` /
   `RedoRequested`; a new `Horizontal(Button("Undo", id="patch_undo_button"),
   Button("Redo", id="patch_redo_button"), id="patch_history_controls")` placed
   inside `#patch_doc_entry_inputs` (below the Add/Edit/Remove row);
   `on_button_pressed` branches posting the two messages. `app.py`: handlers
   `on_patch_editor_panel_undo_requested` / `..._redo_requested` call
   `ChangeService.undo()`/`redo()` then re-render via the new shared
   `_refresh_patch_history_view()` (mirrors the action-handler tail:
   `refresh_entries` / `refresh_issues` / enable-sync).

4. **A-01 data-loss guard (LLR-068a.4, security M4)** — `screens_directionb.py`:
   `set_undo_redo_enabled(enabled)` disables both buttons together (mirrors the
   batch-37 `set_edit_json_enabled`). `app.py`: called with
   `service.document.source_path is None` at every re-render site (the action
   handler tail, the change-file-selected tail, and `_refresh_patch_history_view`)
   so a **file-backed** document (`source_path is not None`) disables Undo/Redo —
   a file-backed change document can never be silently mutated/replaced through
   the history path. Paste-authored / empty docs (`source_path is None`) keep the
   controls enabled.

New ids/symbols are all DISTINCT (C-26): `#patch_undo_button`,
`#patch_redo_button`, `#patch_history_controls`, `UndoRequested`,
`RedoRequested`, `set_undo_redo_enabled`, `_undo_stack`, `_redo_stack`,
`_HISTORY_MAX`, `_push_history`, `undo`, `redo`, `_refresh_patch_history_view`.
No existing id reused or renamed.

## 2. Files modified (5; state.json is orchestrator-owned)

- `s19_app/tui/services/change_service.py` — `import copy`, `_HISTORY_MAX`,
  history stacks in `__init__`, `_push_history` / `undo` / `redo`, and the five
  `_push_history()` call-sites.
- `s19_app/tui/screens_directionb.py` — `UndoRequested` / `RedoRequested`
  messages, the `#patch_history_controls` row, the two `on_button_pressed`
  branches, and `set_undo_redo_enabled`.
- `s19_app/tui/app.py` — `_refresh_patch_history_view`, the two undo/redo
  handlers, and `set_undo_redo_enabled` calls at the two existing enable-sync
  sites.
- `tests/test_change_service.py` — **+2** unit nodes:
  `test_tc338_history_bounded_and_deep_copy_no_alias`,
  `test_tc339_undo_redo_restore_semantics_and_empty_noop`.
- `tests/test_tui_patch_editor_v2.py` — **+2** pilot nodes:
  `test_at068a_undo_redo_roundtrip_through_surface` (AT-068a),
  `test_tc344_undo_redo_disabled_for_file_backed_document` (TC-344), plus the
  `_entry_addr_values` helper.

**Frozen set untouched** (§7). Snapshot marks file NOT edited — the drifting
`patch` cells are already `xfail(strict=False)` under `_batch38_drift_marks`
(see §6).

## 3. How to test

```bash
# The increment's own nodes (unit + pilot)
python -m pytest tests/test_change_service.py -k "tc338 or tc339" \
  tests/test_tui_patch_editor_v2.py -k "at068a or tc344" -q

# C-26 SIBLING CENSUS sweep (the batch-37 escape surface)
python -m pytest tests/test_tui_patch_layout.py tests/test_tui_patch_variant.py -q

# Full patch-editor + service + frozen guard
python -m pytest tests/test_tui_patch_editor_v2.py tests/test_change_service.py \
  tests/test_engine_unchanged.py -q

# Snapshot patch cells (expected xfail drift, non-gating)
python -m pytest tests/test_tui_snapshot.py -k patch -q

# Lint
python -m ruff check s19_app/tui/services/change_service.py \
  s19_app/tui/screens_directionb.py s19_app/tui/app.py \
  tests/test_change_service.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results

| Check | Result | Evidence |
|-------|--------|----------|
| Increment nodes (2 unit + 2 pilot) | **passed** | AT-068a + TC-344 + tc338/tc339 GREEN (`26 passed` with full test_change_service) |
| RED-first counterfactual (AT-068a pre-wire) | **1 failed as designed** | `NoMatches: No nodes match '#patch_undo_button' on Screen` — the real click has no target |
| C-26 sibling census | **18 passed** | `test_tui_patch_layout.py` + `test_tui_patch_variant.py` — `#patch_doc_controls` 5-button census + grid-3 pin + variant census all intact |
| Full `test_tui_patch_editor_v2` + `test_change_service` + frozen guard | **71 passed** | `71 passed in 53.38s` |
| Snapshot patch cells | **2 xfailed** (expected drift) | `32 deselected, 2 xfailed` — no NEW cell drifts |
| ruff (5 touched files) | **clean** | `All checks passed!` |
| Ledger (`-m "not slow"`) | **1375 → 1379 (+4)** | `1379/1399 tests collected`; A=4, D=0 |
| Frozen-file guard | **0 frozen diffs** | `test_engine_unchanged.py` passed; `git diff --name-only` → 0 in frozen set |

**RED → GREEN (AT-068a, C-16 real click, C-10 content assertion):**
- **RED (pre-wire):** `await pilot.click("#patch_undo_button")` →
  `textual.css.query.NoMatches: No nodes match '#patch_undo_button' on
  Screen(id='_default')` — the click target does not exist on `main`/pre-wire.
- **GREEN (post-wire):** a paste-authored one-entry doc (`0x200='REV_A'`) → real
  Add of `0x300='DE AD'` (`after_add == ["0x200","0x300"]`) → real **Undo** click
  restores the pre-add change-set **byte/field-for-field**:
  `after_undo == [("0x200","REV_A")]` (address AND value, not "table
  re-rendered") → real **Redo** click re-applies: `after_redo ==
  ["0x200","0x300"]`. Empty-history Undo on a fresh doc is a no-op
  (`empty_undo_rows == []`).

**A-01 guard evidence (TC-344, file-loaded → disabled):** after a FILE load
(`source_path is not None`) `#patch_undo_button.disabled` and
`#patch_redo_button.disabled` are both **True**; after a subsequent paste
(`source_path is None`) both are **False** — the two states asserted in ONE node
(C-10 discriminator, batch-37 AT-064c precedent).

**Deep-copy / no-alias + bound (TC-338):** after `_HISTORY_MAX + 5` `add_entry`
calls, `len(_undo_stack) == _HISTORY_MAX` (oldest evicted); the top snapshot's
`entries` list is a distinct object (`is not document.entries`) and clearing +
re-appending to the live `document.entries` leaves the stored snapshot's length
and first address unchanged — a true `copy.deepcopy`, no aliasing (risk R-B).
**Restore semantics + empty no-op (TC-339):** empty-stack `undo()`/`redo()`
return the unchanged document object; mutate→undo restores the empty prior doc;
redo re-applies (`value == "REV_A"`); a fresh mutation after undo clears the redo
stack.

**Real-click note (C-16):** `pilot.click` is used for Undo/Redo/Add. Because the
entries pane is the grid's 1fr (smallest) cell and its inputs+control rows
overflow the cell, the control row is clipped below the cell's viewport; the AT
scrolls the pane (`#patch_pane_entries.scroll_end(animate=False)`) so the target
is on-screen, then `pilot.click` delivers a genuine pointer mouse event to the
button (no `.focus()`, no direct handler / service call). Verified: Add→append,
Undo→restore, Redo→re-apply all land through the real event path.

## 5. C-26 sibling-census sweep result

**Placement chosen to minimize census churn:** the Undo/Redo buttons live in a
NEW dedicated `#patch_history_controls` row inside `#patch_doc_entry_inputs` —
**NOT** in `#patch_doc_controls`. This is deliberate: `#patch_doc_controls`'s
child list is pinned as EXACTLY `[Load, Refresh, Validate, Apply, Save]` by two
census tests, and its grid-size:3 geometry by a third — joining it would have
tripped all three (the exact batch-37 escape).

**Census tests found (grep `patch_doc_controls|patch_doc_refresh_button|
patch_doc_apply_button` across `tests/`):**
- `tests/test_tui_patch_layout.py::test_tc319_regroup_section_structure_census`
  — pins `#patch_doc_controls` == `[load, refresh, validate, apply, save]`.
- `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` — pins
  `#patch_doc_controls` grid-size 3.
- `tests/test_tui_patch_editor_v2.py::test_at057a_two_labeled_sections_ids_and_parentage`
  (`~:2345`) — pins the same 5-button controls list.
- `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent`
  — pane/id census across the reparent.
- `tests/test_tui_patch_variant.py` — pins `#patch_pane_variant` children.

**Sweep result:** because the new row sits in `#patch_doc_entry_inputs` (which no
test censuses) and NOT in `#patch_doc_controls`, **all census tests pass
unmodified** — `test_tui_patch_layout.py` + `test_tui_patch_variant.py` = **18
passed**, and the two `test_tui_patch_editor_v2.py` census nodes above are GREEN
inside the 71-passed run. No census file needed editing (contrast batch-37 TC-319,
which required editing the sibling census). Reverse-grep of every new id/symbol
(`patch_undo_button`, `patch_redo_button`, `patch_history_controls`,
`UndoRequested`, `RedoRequested`, `set_undo_redo_enabled`, `_undo_stack`,
`_redo_stack`, `_HISTORY_MAX`, `_refresh_patch_history_view`) across `tests/` →
confined to the two new test files; `patch_history_controls` referenced by 0 tests.

## 6. Risks

- **Low.** Additive: two new buttons + one service capability. No existing
  mutator signature/return changed (the forward path is untouched; `_push_history`
  is prepended). No engine file touched.
- **Snapshot drift (R-D, expected):** the two `patch-comfortable-{80x24,120x30}`
  SVG cells re-render because the entries pane now shows the Undo/Redo row (on
  top of the Inc-1 copy + Inc-3 info-button drift). Both are **already** marked
  `xfail(strict=False)` by `_batch38_drift_marks` (keyed on `screen == "patch"`),
  so **no new cell drifts and no snapshot edit is required** — result `2 xfailed`.
  The mark's reason string names US-065/US-067; US-068a is folded into the same
  patch-cell drift (left unedited to hold the ≤5-file cap; a cosmetic reason
  extension can ride the canonical-CI regen follow-up PR). Baseline regen is
  **canonical-CI only** (snapshot-regen.yml, pinned textual==8.2.8).
- **`_HISTORY_MAX = 20` (assumed, flag kept):** change-set-level (not
  keystroke-level) depth; ample for interactive editing and bounds memory
  (deep-copy snapshots). Documented in the constant's docstring.

## 7. Evidence checklist

- [x] Tests/type checks/lint pass — 71 passed (patch+service+frozen); ruff `All
  checks passed!` on the 5 touched files.
- [x] No secrets in code or output — history is in-memory `ChangeDocument`
  snapshots only; no I/O added.
- [x] No destructive commands run without approval — none.
- [x] File count within cap — **5** source/test files (change_service.py,
  screens_directionb.py, app.py, test_change_service.py, test_tui_patch_editor_v2.py).
- [x] Review packet attached — this file.
- **C-26 reverse census:** clean (see §5) — new row avoids all pinned censuses;
  18/18 sibling-census tests pass unmodified.
- **Frozen files:** `git diff --name-only` shows 0 frozen-set files
  (`core.py`/`hexfile.py`/`range_index.py`/`validation/*`/`tui/a2l.py`/
  `tui/mac.py`/`tui/color_policy.py`); `test_engine_unchanged.py` passed.
- **Docstrings + type hints** on `_push_history`, `undo`, `redo`,
  `set_undo_redo_enabled`, `_refresh_patch_history_view`, the two handlers, the
  two messages, and the two test helpers (7-section order where non-trivial).
- **Ledger:** base 1375 → post 1379 (A=4, D=0).

## 8. Suggested next task

Increment 5 — **US-068b (B-19b)**: per-entry JSON edit popup — a new
`#patch_entry_edit_json_button` scoped to the selected `#patch_doc_entries_table`
row, a new `EntryJsonScreen(ModalScreen)` mirroring `ChangeSetJsonScreen` seeded
with one entry's JSON, a `ChangeService.edit_entry_json(index, text)` apply method
(history-eligible — integrates with this increment's `_push_history`), and the
A-01 disable-guard on the new control. AT-068b + TC-341/342/343/345.
