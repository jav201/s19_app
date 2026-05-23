# Increment 8 — Patch Editor UI extension — Review Packet

**Batch:** 2026-05-21-batch-04 — memory-field change kind + unified change-set + selective export
**Phase:** 3 — Implementation
**Increment:** 8 of 9 — Patch Editor UI extension
**LLRs covered:** LLR-009.1, LLR-009.2, LLR-009.3
**TCs covered:** TC-032, TC-033, TC-034 (integration); finalizes the TC-027 `app.py`-clean input
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Baseline entering increment:** 733 passed / 2 skipped / 3 xfailed / 0 failed

---

## 1. What changed

The Patch Editor was extended so it manages **memory-field changes alongside the
batch-03 parameter changes** in the same screen. `CdfxService` was migrated from
owning a bare `ChangeList` to owning a `UnifiedChangeSet` (parameter half +
memory-field half) and gained the batch-04 orchestration calls: memory-change
add / edit / remove, memory-row rendering (validate-against-image + hex display),
unified-file save / load, and selective export. `PatchEditorPanel` gained a
second `DataTable` for memory changes plus address / new-bytes inputs, memory
add / edit / remove buttons, and a unified save / load / export control row —
all presentational, posting `ActionRequested` messages. `app.py` got UI-state
wiring only: the action handler routes the new actions to `CdfxService` and
re-renders both tables; a new `_report_export_result` surfaces the
per-half-tagged export issues on the existing status path. The batch-03
parameter controls and their tests are unchanged and still pass. No `cdfx`
package module, no engine module and no `workspace.py` was modified — they are
consumed, not changed.

The migration kept full backward compatibility: `CdfxService.change_list` is now
a property aliasing `unified.parameters`, so every batch-03 caller and test that
reads `service.change_list` keeps working unchanged.

---

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/services/cdfx_service.py` | edit | `CdfxService` now owns a `UnifiedChangeSet`; `change_list` becomes a property alias; new `add_memory_change` / `edit_memory_change` / `remove_memory_change`, `memory_rows` / `memory_validation_issues` / `memory_is_empty`, `save_unified` / `load_unified` / `export_selective`; new `MemoryPatchRow` dataclass and `parse_address` / `parse_new_bytes` field parsers. |
| 2 | `s19_app/tui/screens_directionb.py` | edit | `PatchEditorPanel` gains a memory `DataTable` + empty-state line, address / new-bytes inputs, memory add/edit/remove buttons, unified save/load/export buttons; `ActionRequested` extended with `address_text` / `bytes_text` / `unified_path_text`; `compose` / `on_mount` / `request_action` / `on_button_pressed` extended; new `refresh_memory_rows`. Presentational only — posts messages. |
| 3 | `s19_app/tui/app.py` | edit | `on_patch_editor_panel_action_requested` extended to route `add_memory` / `edit_memory` / `remove_memory` / `save_unified` / `load_unified` / `export` to `CdfxService` and re-render both tables; new `_report_export_result`; `ExportResult` type imported for the reporter signature. UI-state wiring only — no JSON/model logic. |
| 4 | `s19_app/tui/styles.tcss` | edit | Layout rules for the new widget ids — `#patch_memory_table`, `#patch_memory_empty_state`, `.patch-section-title`, `#patch_mem_inputs` / `#patch_unified_row`, the memory button rows, and the three new `Input`s. **6th-file note — see §5.** |
| 5 | `tests/test_tui_memory_patch.py` | new | TC-032 / TC-033 / TC-034 integration tests driven via `App.run_test()` + Textual `pilot`, plus the memory-field service-helper unit checks. |

Also regenerated (not a logic change): the snapshot baseline
`tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg`
— stale because the Patch Editor screen layout changed; regenerated with
`--snapshot-update` for that one cell only.

---

## 3. How to test

```bash
# Full suite (baseline 733 + 16 new = 749 expected)
python -m pytest -q

# Increment-8 integration + unit tests only
python -m pytest -q tests/test_tui_memory_patch.py

# Regression check — batch-03 Patch Editor + services unchanged
python -m pytest -q tests/test_tui_patch_editor.py tests/test_tui_patch_containment.py \
                    tests/test_tui_services.py tests/test_tui_public_api.py

# Snapshot — the regenerated patch baseline
python -m pytest -q "tests/test_tui_snapshot.py" -k patch

# Compile + import smoke (ruff not installed -> py_compile substitute)
python -m py_compile s19_app/tui/services/cdfx_service.py \
                     s19_app/tui/screens_directionb.py s19_app/tui/app.py
python -c "import s19_app.tui"
```

`App.run_test()` smoke — open the Patch Editor, add a memory change, save a
unified file, load it back, run a selective export — is automated as
`test_tc033_unified_save_then_load_round_trips_both_halves` and
`test_tc034_export_writes_cdfx_and_memory_field_files` in the new test file, and
was additionally run as an ad-hoc script (see §4).

---

## 4. Test results (actual output)

**Full suite:**
```
27 snapshots passed.
749 passed, 2 skipped, 3 xfailed in 200.72s (0:03:20)
```
733 baseline + 16 new increment-8 tests = 749. 0 failed.

**Increment-8 tests only:**
```
16 passed in 7.12s
```

**Batch-03 regression set:**
```
42 passed, 1 xfailed in 10.01s
```

**Patch snapshot (after baseline regeneration):**
```
1 snapshot updated.   (regeneration step)
1 passed              (re-run verifies)
```

**Compile + import:**
```
PY_COMPILE OK
IMPORT s19_app.tui OK
```

**`App.run_test()` smoke (ad-hoc script):**
```
after add_memory, memory entries: 1
unified file written: ['patchset.json']
after load_unified, counts: (0, 1)
export produced .cdfx: ['export.cdfx']
export produced memory json: ['export-memory.json']
last status lines:
  Patch Editor: Loaded 0 parameter + 1 memory change
  Patch Editor: export - CDFX <path>...
  Patch Editor [MF-EXPORT-NO-A2L] info (param-half): ...
  Patch Editor [W-EMPTY-CHANGELIST] warning (param-half): ...
```
The full add-memory -> save-unified -> load-unified -> export flow worked. (The
ad-hoc script's `TemporaryDirectory` cleanup raised a Windows `WinError 32` on
the still-open `s19tui.log` handle — a temp-dir teardown race in the throwaway
script only, not a product fault; the 16 pytest cases use `tmp_path` and have no
such issue.)

---

## 5. Risks

- **File-cap — 5 files of code/tests + 1 regenerated snapshot baseline.** The
  five edited/created files are within the cap. `styles.tcss` is the same kind
  of 4th/5th-file inclusion the batch-03 increment-9 plan anticipated for new
  widget ids; the increment plan §C/§D explicitly allowed including it and
  flagging it. The regenerated `.svg` baseline is not new logic — it is the
  mechanical re-snapshot of a layout change, regenerated for the single
  affected cell only (`patch-comfortable-120x30`). **Flagged here for review.**
- **`CdfxService` ownership migration.** Switching the owned model from
  `ChangeList` to `UnifiedChangeSet` is the riskiest change — the batch-03
  callers read `service.change_list`. Mitigated by a property + setter alias to
  `unified.parameters`; the full batch-03 Patch Editor / services / public-API
  test sets (42 tests) pass unchanged, confirming no behavioural drift.
- **RK-5 — Patch Editor screen growth.** The screen now hosts two `DataTable`s
  and three control rows. TC-032 explicitly asserts both kinds coexist and the
  parameter rows survive. The screen needs more vertical space; the integration
  tests run at `size=(120, 40)` (batch-03 used 30) so both tables render — a
  real terminal scrolls. Not a defect, but worth noting for the demo.
- **`app.py` C-7 cleanliness.** The handler only routes messages and reports
  results; the `from .cdfx import ExportResult` import is a type-only import for
  the reporter signature. The existing TC-028 inspection test (forbids
  `write_cdfx` / `read_cdfx` / `validate_w_rules` / `ElementTree` in `app.py`)
  still passes — no format-handler call was added to `app.py`.
- **Edge cases not covered here:** memory-change validation against a *loaded
  image* through the UI (status `inside`/`partial`/`outside`) is exercised at
  unit level in increment 2's tests; the increment-8 integration tests run with
  no image loaded (status `unvalidated-no-image`) since wiring a real
  `LoadedFile` into the pilot is heavier than this increment's scope. The
  service path that feeds `current_file.ranges` into `memory_rows` is wired and
  exercised; the loaded-image-status UI path is left as a demo/QA observation.

---

## 6. Pending items

- **Increment 9** (not started — increment boundary): TC-025 round-trip,
  TC-027 inspection checklist, final suite-green confirmation.
- **QA hand-off:** per the cross-functional rule and the plan §D, propose the
  TC-032/033/034 manual test plan + acceptance criteria to `qa-reviewer` now
  that the functional screen is shipped.
- **Demo note for `presentation-builder` / `docs-writer`:** the loaded-image
  memory-status path (a memory change validated `inside`/`partial`/`outside`
  against a real firmware image in the running TUI) is a good demo beat and is
  the HLR-009 `test+demo` corroboration; the automated tests cover the
  no-image path.

---

## 7. Suggested next task

**Increment 9 — Round-trip + integration hardening.** Add
`tests/test_unified_roundtrip.py` (TC-025: build a `UnifiedChangeSet` via
`unified_changeset_factory`, write -> read, assert exact `==` on parameter
values and exact ordered byte sequences on memory entries) and
`tests/test_cdfx_unchanged.py` (TC-027: the §5.6 inspection checklist as an
executable test — `changelist.py` / `reader.py` / `writer.py` byte-unchanged via
file-hash, `app.py` JSON/model-clean via static assertion, `pyproject.toml` /
`requirements.txt` unchanged). Then the final full-suite green confirmation
closes Phase 3.
