# Increment 005 — US-068b (B-19b) — Per-entry JSON edit popup (FINAL)

**Story:** US-068b / HLR-068b (R-TUI-058) · LLR-068b.1 + LLR-068b.2 + LLR-068b.3 + LLR-068b.4 (A-01 guard)
**Tests:** AT-068b (black-box, C-16 real click) + TC-341/342/343 (white-box) + TC-345 (A-01 pilot)
**Base:** `claude/stat-batch-38-dev-flow-2d7ba9` @ `5a6c45b` (batch-38 base; Inc-1..4 applied in the working tree)
**Type:** new per-entry JSON modal + new service seed/apply methods + new distinct control + A-01 disable-guard

---

## 1. What changed

Added a **per-entry JSON edit popup** to the Patch Editor — distinct from
batch-37's whole-set popup: a new control that opens a modal seeded with only
the SELECTED entry's JSON, whose Confirm edits that one entry through the
validated parse path, with the A-01 file-loaded disable-guard.

1. **Per-entry JSON modal (LLR-068b.2)** — `screens.py`: new
   `EntryJsonScreen(ModalScreen[Optional[str]])` mirroring `ChangeSetJsonScreen`
   but with its own TextArea id `#entry_json_text` and buttons
   `#entry_json_confirm` / `#entry_json_cancel`, title `"Edit entry JSON:"`.
   Seeded with a SINGLE entry's wire-form JSON (no document header / `entries`
   array), reuses the shared `.modal-dialog` CSS class (no new CSS). Returns the
   edited text on Confirm, `None` on Cancel.

2. **Service seed + apply (LLR-068b.2/.3)** — `services/change_service.py`
   (`import json`, `serialize_change_document` added to the `..changes` import):
   - `entry_seed_json(index)` — serializes the entry at `index` to canonical
     wire form and extracts the sole `entries[0]` object (via the canonical
     `serialize_change_document` writer, so no entry-encoding logic is
     duplicated) → the single-entry seed.
   - `edit_entry_json(index, text)` — routes the edited single-entry text
     through the EXISTING validated `parse_change_document` seam by splicing it
     into a one-entry envelope built from the live document's header, then
     replaces ONLY `entries[index]` (siblings are the identical objects). A
     malformed / rejected entry is collected (`MF-JSON-PARSE`, non-`ok` result)
     with NO mutation. History-eligible: snapshots via `_push_history` before
     the in-place replace (integrates with Inc-4's undo/redo).

3. **New distinct control + message (LLR-068b.1)** — `screens_directionb.py`:
   `Button("Edit JSON", id="patch_entry_edit_json_button")` added to the
   per-entry buttons row `#patch_doc_entry_buttons` (after Remove), a new
   payload message `EntryEditJsonRequested(index)`, and an `on_button_pressed`
   branch that reads `#patch_doc_entries_table.cursor_row` and posts the message
   (empty table → no-op, no selection). This is distinct from the whole-set
   `#patch_edit_json_button` and the field-populate `#patch_entry_edit_button`
   (`edit_entry` action) — neither is reused or hijacked.

4. **Routing + apply (LLR-068b.3)** — `app.py` (`EntryJsonScreen` import):
   `on_patch_editor_panel_entry_edit_json_requested` re-checks the A-01 guard
   defensively, bounds-checks the index, seeds the popup via
   `service.entry_seed_json`, and pushes it with an index-bound callback;
   `_apply_entry_json_edit(index, edited)` routes Confirm to
   `service.edit_entry_json`, surfaces the result, and re-renders via the shared
   `_refresh_patch_history_view` tail.

5. **A-01 data-loss guard (LLR-068b.4, security M4)** — `screens_directionb.py`:
   `set_entry_edit_json_enabled(enabled)` disables `#patch_entry_edit_json_button`
   (mirrors `set_edit_json_enabled` / `set_undo_redo_enabled`). `app.py`: called
   with `service.document.source_path is None` at all THREE enable-sync sites
   Inc-4 pairs — the action-handler tail (`~:1751`), the change-file-selected
   tail (`~:3392`), and `_refresh_patch_history_view` (`~:1943`) — so a
   file-backed document (`source_path is not None`) disables the per-entry edit;
   paste-authored / empty docs keep it enabled.

New ids/symbols are DISTINCT (C-26): `#patch_entry_edit_json_button`,
`EntryEditJsonRequested`, `EntryJsonScreen`, `#entry_json_text`,
`#entry_json_confirm`, `#entry_json_cancel`, `entry_seed_json`,
`edit_entry_json`, `set_entry_edit_json_enabled`,
`on_patch_editor_panel_entry_edit_json_requested`, `_apply_entry_json_edit`. No
existing id reused or renamed.

## 2. Files modified (5)

- `s19_app/tui/screens.py` — `EntryJsonScreen`.
- `s19_app/tui/services/change_service.py` — `import json`,
  `serialize_change_document` import, `entry_seed_json`, `edit_entry_json`.
- `s19_app/tui/screens_directionb.py` — `EntryEditJsonRequested`, the new
  button in `#patch_doc_entry_buttons`, the `on_button_pressed` branch,
  `set_entry_edit_json_enabled`.
- `s19_app/tui/app.py` — `EntryJsonScreen` import, the request handler +
  `_apply_entry_json_edit`, and `set_entry_edit_json_enabled` at the three
  enable-sync sites.
- `tests/test_tui_patch_editor_v2.py` — **+5** nodes: AT-068b, TC-341, TC-342,
  TC-343, TC-345 (+ the `_make_paste_service` helper).

**Frozen source set untouched** (§7). `state.json` is orchestrator-owned.
Snapshot marks file NOT edited — the drifting `patch` cells are already
`xfail(strict=False)` under `_batch38_drift_marks` (§6).

## 3. How to test

```bash
# The increment's own nodes (pilot + white-box)
python -m pytest tests/test_tui_patch_editor_v2.py -k "at068b or tc341 or tc342 or tc343 or tc345" -q

# C-26 SIBLING CENSUS sweep + frozen-source guard
python -m pytest tests/test_tui_patch_layout.py tests/test_tui_patch_variant.py tests/test_engine_unchanged.py -q

# Full patch-editor + service
python -m pytest tests/test_tui_patch_editor_v2.py tests/test_change_service.py -q

# Snapshot patch cells (expected xfail drift, non-gating)
python -m pytest tests/test_tui_snapshot.py -k patch -q

# Lint
python -m ruff check s19_app/tui/services/change_service.py s19_app/tui/screens.py \
  s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results

| Check | Result | Evidence |
|-------|--------|----------|
| Increment nodes (AT-068b + TC-341/342/343/345) | **5 passed** | `5 passed, 46 deselected in 2.21s` |
| RED-first counterfactual (AT-068b pre-wire) | **1 failed as designed** | `ImportError: cannot import name 'EntryJsonScreen'` — the per-entry popup class (and `#patch_entry_edit_json_button` click target) do not exist on `main`/pre-wire |
| C-26 sibling census + frozen-source guard | **19 passed** | `test_tui_patch_layout.py` + `test_tui_patch_variant.py` + `test_engine_unchanged.py` |
| Full `test_tui_patch_editor_v2` + `test_change_service` | **75 passed** | `75 passed in 55.06s` |
| Snapshot patch cells | **2 xfailed** (expected drift) | `32 deselected, 2 xfailed` — no NEW cell drifts |
| Engine-SOURCE freeze (tc031 ×3 + engine_unchanged) | **3 passed** | `3 passed, 163 deselected` — 0 frozen-source diffs |
| ruff (5 touched files) | **clean** | `All checks passed!` |
| Ledger (`-m "not slow"`) | **1379 → 1384 (+5)** | `1384/1404 tests collected`; A=5, D=0 |

**RED → GREEN (AT-068b, C-16 real click, single-entry-seed proof, siblings byte-identical):**
- **RED (pre-wire):** `from s19_app.tui.screens import EntryJsonScreen` →
  `ImportError` — the per-entry popup class does not exist; the new click target
  `#patch_entry_edit_json_button` likewise did not exist on `main`.
- **GREEN (post-wire):** a paste-authored 3-entry doc
  (`0x200='REV_A'`, `0x300` bytes `DE AD`, `0x400='REV_C'`) → select the MIDDLE
  entry `table.move_cursor(row=1)` (i≠0 proves scoping) → real
  `await pilot.click("#patch_entry_edit_json_button")` opens the popup.
  **Single-entry-seed proof:** the popup's `#entry_json_text` seed parses to a
  `dict` with **no `entries` key** and `address == "0x300"` — a SINGLE entry,
  distinct from batch-37's whole-set `ChangeSetJsonScreen`. Edit to `BE EF`,
  Confirm → the entries table (the CONSUMER the real handler produced) shows
  `after[1] == ("0x300", "BE EF")`, **`after[0] == before[0]`** (`0x200='REV_A'`)
  and **`after[2] == before[2]`** (`0x400='REV_C'`) — **siblings byte-identical**.

**A-01 guard evidence (TC-345, file-loaded → disabled):** after a FILE load
(`source_path is not None`) `#patch_entry_edit_json_button.disabled` is **True**;
after a subsequent paste (`source_path is None`) it is **False** — both states
asserted in ONE node (C-10 discriminator, batch-37 AT-064c precedent). The
handler ALSO re-checks the guard defensively (refuses to push the popup when
`source_path is not None`).

**Validated parse route (TC-343, no eval/pickle):** `edit_entry_json` routes the
edited text through `parse_change_document` (stdlib `json.loads` internally) by
splicing it into a one-entry envelope — malformed input (`'{"type": ...'`) →
non-`ok` result carrying `MF-JSON-PARSE`, document untouched (entries 0 and 1 are
the identical objects). A markup-bearing string value (`[red]x[/red]`) edits
successfully and is stored VERBATIM (C-17, no interpretation, no crash). NO
`eval` / `pickle` / `exec`; no new clipboard/ingress surface (reuses the
`TextArea` widget class).

**Scoping + isolation (TC-341/342):** `entry_seed_json(0/1/2)` seeds the matching
entry address (`0x200`/`0x300`/`0x400`) as a single object; `edit_entry_json(1)`
replaces only entry 1 — `after[0] is before[0]` and `after[2] is before[2]`
(same objects, not merely equal).

## 5. C-26 sibling-census sweep result

The new `#patch_entry_edit_json_button` **joins the per-entry buttons row
`#patch_doc_entry_buttons`** (Add/Edit/Remove → +Edit JSON), the natural home
for a per-entry operation.

**Census tests found (grep `patch_doc_entry_buttons|patch_entry_add_button|
patch_entry_edit_button|patch_entry_remove_button` across `tests/`):** the ONLY
reference is `tests/test_tui_patch_editor_v2.py:3172` — a `#patch_entry_add_button`
**click target** in AT-068a, NOT a child-list census. **No test pins the exact
child list of `#patch_doc_entry_buttons`.** The pinned censuses target OTHER
rows:
- `test_tui_patch_layout.py::test_tc319_regroup_section_structure_census` pins
  `#patch_doc_controls` (Load/Refresh/Validate/Apply/Save) and
  `#patch_checks_controls` — not the entry-buttons row.
- `test_tui_patch_editor_v2.py::test_at057a_...` / `test_at058b_...` use
  presence/`count==1` id lists (`_PRESERVED_REGROUP_IDS` / `_PATCH_PRESERVED_IDS`)
  — neither includes an entry-buttons child list, and neither forbids extra ids.
- `test_panel_composition` (`NEW_WIDGET_IDS`) asserts the listed ids are present,
  not that no others exist.

**Sweep result:** adding the 4th button to `#patch_doc_entry_buttons` breaks NO
census — `test_tui_patch_layout.py` + `test_tui_patch_variant.py` = **19 passed
unmodified** (with `test_engine_unchanged`), and the two `test_tui_patch_editor_v2`
census nodes are GREEN inside the 75-passed run. **No census file needed
editing** (contrast batch-37 TC-319). Reverse-grep of every new id/symbol
(`patch_entry_edit_json_button`, `EntryEditJsonRequested`, `EntryJsonScreen`,
`entry_edit_json`, `edit_entry_json`, `entry_seed_json`, `entry_json_text`,
`entry_json_confirm`, `entry_json_cancel`, `set_entry_edit_json_enabled`) across
`tests/` → confined to the new test nodes in `test_tui_patch_editor_v2.py`.

## 6. Risks

- **Low.** Additive: one new button + one new modal + two new service methods.
  No existing mutator / signature changed; the per-entry apply reuses the
  validated `parse_change_document` seam.
- **BATCH-LEVEL FINDING (not Inc-5) — `test_tc032` RED, pre-existing:**
  `tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main`
  fails because **`tests/test_tui_a2l.py`** (in the engine-test-freeze set
  `_ENGINE_TEST_FILES`) was modified — by **Increment 2 (US-066)**, NOT by
  Inc-5. It was already `M tests/test_tui_a2l.py` in the git status at Inc-5
  start. Per LLR-014.2 / AC-B2 the engine/parser/validation test files must be
  byte-identical to `main`; US-066's oversized-address tests were meant to land
  in `test_validation_service.py` / `test_tui_directionb.py` (§5.2), not the
  frozen `test_tui_a2l.py`. **Surfaced for the orchestrator / Inc-2** — out of
  Inc-5's story + 5-file scope; fixing it would edit a file outside this
  increment. Inc-5's own SOURCE-freeze guards (tc031 ×3 + engine_unchanged) are
  GREEN.
- **Snapshot drift (R-D, expected):** the new per-entry button re-renders the
  two `patch` SVG cells (on top of Inc-1 copy / Inc-3 info-button / Inc-4
  undo/redo drift). Both are ALREADY `xfail(strict=False)` under
  `_batch38_drift_marks` (keyed on `screen == "patch"`), so **no new cell drifts
  and no snapshot edit is required** — `2 xfailed`. Baseline regen is
  canonical-CI only (snapshot-regen.yml, pinned textual==8.2.8).

## 7. Evidence checklist

- [x] Tests/type checks/lint pass — 5/5 increment nodes GREEN; 75 passed
  (patch+service); ruff `All checks passed!` on the 5 touched files. (The
  `test_tc032` RED is a pre-existing Inc-2 `test_tui_a2l.py` edit, surfaced in
  §6 — not this increment.)
- [x] No secrets in code or output — in-memory `ChangeDocument` edits only; no
  I/O added; no `eval`/`pickle`/`exec` (validated `json.loads` via
  `parse_change_document`).
- [x] No destructive commands run without approval — none.
- [x] File count within cap — **5** files (screens.py, change_service.py,
  screens_directionb.py, app.py, test_tui_patch_editor_v2.py).
- [x] Review packet attached — this file.
- **C-26 reverse census:** clean (§5) — no census pins the entry-buttons row;
  19/19 sibling-census tests pass unmodified; new symbols confined to the new
  test nodes.
- **Frozen SOURCE files:** `git diff --name-only` shows 0 frozen-set SOURCE
  files (`core.py`/`hexfile.py`/`range_index.py`/`validation/*`/`tui/a2l.py`/
  `tui/mac.py`/`tui/color_policy.py`); `test_engine_unchanged.py` + tc031 ×3
  passed.
- **Docstrings + type hints** on `EntryJsonScreen`, `entry_seed_json`,
  `edit_entry_json`, `EntryEditJsonRequested`, `set_entry_edit_json_enabled`,
  the request handler, `_apply_entry_json_edit`, and the `_make_paste_service`
  helper (7-section order where non-trivial).
- **Ledger:** base 1379 → post 1384 (A=5, D=0).

## 8. Suggested next task

Batch-38 implementation is COMPLETE (Inc-1..5 cover US-065/066/067/068a/068b).
Next: **Phase-4 validation gate** (orchestrator-owned, C-25) + resolve the
batch-level `test_tc032` finding (Inc-2's `test_tui_a2l.py` edit — relocate the
US-066 oversized-address tests out of the engine-frozen `test_tui_a2l.py` into
`test_validation_service.py` / `test_tui_directionb.py` per §5.2, restoring the
byte-identical freeze) before the gate run. Snapshot canonical-CI regen for the
2 xfail patch cells rides the follow-up PR (like #67/#69).
