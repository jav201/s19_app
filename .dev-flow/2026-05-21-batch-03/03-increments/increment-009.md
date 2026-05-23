# Increment 009 — Functional Patch Editor screen

> **Phase 3 · batch-03 · Increment 9.** Replaces the inert batch-02
> `PatchEditorPanel` shell (`R-TUI-027` / LLR-012.2) with a functional Patch
> Editor: a change-list table, wired add / edit / remove inputs, save / load
> actions and an empty state, orchestrated by a new `cdfx_service`. Spec:
> increment-plan §A.4 — Increment 9; requirements LLR-007.1..LLR-007.6;
> TC-025, TC-026, TC-028, TC-027a (integration arm). Branch:
> `dev-flow/batch-02-direction-b-restyle`.
> **qa-reviewer hand-off requested — see §5 / §7.**

## 1. What changed

The Patch Editor rail screen became a working tool. A new
`s19_app/tui/services/cdfx_service.py` orchestrates every app↔`cdfx`-package
call — it owns one `ChangeList`, sequences `resolve_against_a2l` /
`format_value` for display, and calls `write_cdfx_to_workarea` / `read_cdfx`
for save / load. The `PatchEditorPanel` in `screens_directionb.py` was rebuilt
from the inert before/after hex-pane shell into a functional editor: a
change-list `DataTable`, parameter-name / array-index / value `Input`s, add /
edit / remove and save / load `Button`s, a `.cdfx` path `Input`, and a neutral
empty-state line. The widget stays presentational — a control press posts a
`PatchEditorPanel.ActionRequested` message; `app.py` routes that message to
`CdfxService` and re-renders the table from the resolved rows. `app.py` gained
only UI-state wiring (the service instance, the message handler, a status
helper) — it parses no XML and calls no `cdfx`-package read/write function
directly (constraint C-8 / LLR-007.5). The batch-02 inert-shell tests in
`test_tui_directionb.py` were rewritten to the functional-screen contract
(a requirement-driven test change, not a regression), and the new
`test_tui_patch_editor.py` verdicts the increment.

The empty-array-index field maps to a `None`-index scalar entry and a typed
integer to an array element — the `Optional[int]` UX surface the increment-5
migration created (TC-025).

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/services/cdfx_service.py` | **new** | The CDFX orchestration service — owns the `ChangeList`, exposes `add_entry` / `edit_entry` / `remove_entry` (HLR-001), `rows` (resolve + `format_value` for display), `save` / `load` (`write_cdfx_to_workarea` / `read_cdfx`), plus the `parse_array_index` (blank→`None`) and `parse_value` (int/float/str) input-mapping helpers. Mirrors the `a2l_service` pattern. |
| `s19_app/tui/screens_directionb.py` | **modified** | `PatchEditorPanel` rebuilt: change-list `DataTable`, name/index/value inputs, add/edit/remove + save/load buttons, path input, empty-state line; `ActionRequested` message; `refresh_rows` to repopulate the table; `on_button_pressed` → `request_action`. Module docstring updated. `EmptyStatePanel` / `ScreenScaffold` / `MemoryMapPanel` / `BookmarksPlaceholder` / `AbDiffPanel` untouched. |
| `s19_app/tui/app.py` | **modified** | UI wiring only: import + instantiate `CdfxService` (`self._cdfx_service`); `on_patch_editor_panel_action_requested` routes the message to the service and re-renders the table; `_report_cdfx_result` surfaces save/load issues on the status path; `_compose_screen_patch` docstring updated. No XML / model logic added. |
| `tests/test_tui_patch_editor.py` | **new** | 21 tests — TC-025 (render/edit/empty-state, blank-index→scalar, bad-index reported), TC-026 (save under workarea, save→load round-trip, screen load populates rows, write issues surfaced), TC-027a integration arm (billion-laughs load rejected), TC-028 (no XML logic in `app.py`; handler routes through the service), service-helper unit checks. |
| `tests/test_tui_directionb.py` | **modified** | The 4 batch-02 inert-shell Patch Editor tests rewritten to the functional contract (table renders, name/index/value inputs present, panel is presentational, empty-state shown); `test_tc028_every_scaffold_screen_activates_without_error` and the keyboard-focus test updated for the new widget ids. Requirement-driven (LLR-007.1 supersedes LLR-012.2), not a regression. |

**File count: 5 — exactly at the cap.** See §5 for the snapshot-baseline
boundary item.

## 3. How to test

```bash
# The new increment-9 test file
pytest -q tests/test_tui_patch_editor.py

# The updated Direction-B suite (batch-02 inert-shell tests rewritten)
pytest -q tests/test_tui_directionb.py

# Full suite
pytest -q

# Import + compile (ruff not installed — py_compile substitute)
python -c "import s19_app.tui"
python -m py_compile s19_app/tui/services/cdfx_service.py \
  s19_app/tui/screens_directionb.py s19_app/tui/app.py \
  tests/test_tui_patch_editor.py tests/test_tui_directionb.py
```

`App.run_test()` smoke: open the Patch Editor (`action_show_screen("patch")`),
set the name/value inputs, `panel.request_action("add")`, `"save"`, then
`"load"` the written path — verified inline (see §4).

## 4. Test results

**New increment-9 file — `tests/test_tui_patch_editor.py`:** `21 passed in
3.44s`.

**Updated Direction-B suite — `tests/test_tui_directionb.py`:** `101 passed in
54.92s` (the 4 rewritten Patch Editor tests + the 2 updated scaffold tests all
green; the other 95 unchanged).

**Full suite — `pytest -q`:**

```
1 failed, 590 passed, 2 skipped, 3 xfailed, 1 warning in 175.08s
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]
```

Baseline was **570 passed / 2 skipped / 3 xfailed / 0 failed**. After this
increment: **590 passed** (+20 net — the new file adds 21, one batch-02 test
was removed when the 4 inert-shell tests were consolidated into 4 functional
ones, and the rest is the increment-9 file), **2 skipped / 3 xfailed
unchanged**, and **1 snapshot cell failed** — `patch-comfortable-120x30`.

**The single snapshot failure is the expected, requirement-driven layout
change**, not a defect: that SVG cell is the frozen image of the *inert*
Patch Editor shell, and this increment deliberately replaces that screen's
visual layout. It is the snapshot analogue of the rewritten inert-shell unit
tests. **Its baseline `.svg` was not regenerated** — see §5 / §6.

**`py_compile` (all 5 changed files):** `PY_COMPILE OK`.
**`python -c "import s19_app.tui"`:** `IMPORT s19_app.tui OK`.

**`App.run_test()` smoke (actual output):**

```
after add: rows = 1
saved file: patchset.cdfx
after load: rows = 0
SMOKE OK
```

The `after load: rows = 0` is **correct, not a bug**: the smoke ran with no
A2L loaded, so the added entry is `unresolved-no-a2l`, the writer excludes it
(`W-INSTANCE-EXCLUDED`, LLR-004.5) and emits a backbone-only `.cdfx`; loading
that file back yields zero entries. The save→load round-trip with *resolved*
entries (the meaningful case) is verified by
`test_tc026_save_then_load_round_trips_the_changelist`, which resolves against
synthetic A2L tags and asserts the recovered key set is exactly
`{(IGN_ADVANCE_BASE, None, 23), (FUEL_TRIM, 0, 11), (FUEL_TRIM, 1, 22)}` —
the `None`-scalar + coalesced `VAL_BLK` shape.

## 5. Risks

- **Snapshot baseline `patch-comfortable-120x30` is stale and was not
  regenerated.** Regenerating it (`pytest --snapshot-update` for that cell)
  would touch a 6th file (the committed `.svg` baseline). The increment-9
  plan's risk note explicitly says: *"If `app.py` + `screens_directionb.py`
  wiring proves to need a 6th file, stop and request approval rather than
  splitting silently."* The snapshot SVG is a generated test artifact, not
  source, but it is committed — so this is a genuine boundary call.
  **Surfaced for your decision** (§7): the one snapshot cell needs its
  baseline accepted, which is a one-command regeneration but a 6th touched
  file. The full suite is otherwise green.
- **Save with no A2L produces an empty `.cdfx`.** Without a loaded A2L every
  entry is `unresolved-no-a2l` and is excluded on write (LLR-004.5) — the
  saved file is backbone-only. This is correct per the writer contract but is
  a UX sharp edge: the engineer must load an A2L before a save is meaningful.
  The save surfaces `W-INSTANCE-EXCLUDED` + `W-EMPTY-CHANGELIST` on the status
  path, so it is *visible*, not silent — but it is worth a manual-test-plan
  note for `qa-reviewer`.
- **`format_value` of an unresolved entry falls back to plain decimal**
  (LLR-003.2). With no A2L, the table's Value column shows the raw value, not
  a type-driven form — expected, not a defect.
- **The index input accepts only a non-negative integer or blank.** A typed
  negative or non-integer index is reported on the status path and the entry
  is *not* added (`test_tc025_bad_index_is_reported_not_raised`). The
  resolver's range check (LLR-002.3) is the second gate once an A2L is loaded.
- **`CdfxService.load` replaces the owned `ChangeList`.** A load discards the
  current in-progress change-list. This matches "load a `.cdfx` to review or
  continue editing" (US-005) and there is no undo this batch (out of scope) —
  but it is a destructive action with no confirmation prompt. Recorded for
  the manual test plan.

## 6. Pending items

- **Snapshot baseline regeneration for `patch-comfortable-120x30`** — deferred
  pending approval (the 6th-file boundary, §5). One command:
  `pytest --snapshot-update -k "patch-comfortable-120x30"`. Until then the
  full suite shows that one cell red; every other test (590) is green.
- **Integration-depth save/load + work-area containment UI tests** — these are
  **increment 11's** scope (TC-026 integration depth, TC-036 containment /
  dedup / reparse-point through the screen, TC-027a Patch-Editor-load
  integration arm). Increment 9 ships the unit/seam arm; increment 11 deepens
  it through `App.run_test()`. Not pending *for this increment* — planned next.
- **No demo script** — HLR-007's `demo` corroboration is produced in Phase 6,
  not here.

## 7. Suggested next task

**Increment 10 — Round-trip + adversarial-float hardening.** Add
`tests/test_cdfx_roundtrip.py` (TC-024: a `None`-scalar + `None`-ASCII +
*N*-element array change-list plus the three adversarial IEEE floats written
then read, asserting exact `==` structural equality and the `Optional[int]`
key shape) and relocate/extend `change_list_factory` into `tests/conftest.py`.
2 files, no new LLR — it deepens the LLR-004.8/004.9/005.6 round-trip verdict.

**Before that, two hand-offs from this increment:**
- **Approval call** — regenerate the one stale snapshot baseline
  (`patch-comfortable-120x30`)? It is the requirement-driven layout change of
  this increment but a 6th touched file (§5). Recommend: yes, accept the
  baseline — it is the snapshot analogue of the already-rewritten inert-shell
  unit tests.
- **qa-reviewer** — this increment ships the functional Patch Editor (a new
  feature surface). Proposed acceptance criteria: TC-025 (render / edit /
  blank-index→scalar / empty-state), TC-026 (save under `.s19tool/workarea/` +
  save→load round-trip), TC-028 (no XML/model logic in `app.py`). Manual test
  plan should cover: the no-A2L empty-save sharp edge (§5), the
  load-replaces-change-list destructive action (§5), and the increment-6
  `W-ARRAY-SPARSE` fail-loud behavior surfacing on the status path.
