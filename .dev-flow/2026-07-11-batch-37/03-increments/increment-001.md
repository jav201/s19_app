# Increment 001 — US-064a: Patch-editor Refresh (AT-064a + TC-328)

> Batch-37 Inc-1. Scope: US-064a only (HLR-064a / LLR-064a.1 + LLR-064a.2).
> Owns AT-064a, TC-328. Language: English. RED-then-GREEN evidence below.

## 1. What changed

Added a one-action **Refresh** control to the Patch Editor that re-reads the
CURRENTLY-LOADED change/check document from disk and re-renders the entries
table + issue lines — so external edits to the loaded file appear without
re-typing the path or reloading the app.

- New `#patch_doc_refresh_button` ("Refresh") in the patch-script controls row
  (`#patch_doc_controls`, after Load), wired in `on_button_pressed` to a NEW
  routed action `"refresh_doc"`.
- New dispatch branch in `on_patch_editor_panel_action_requested`: refresh
  re-invokes the SAME validated `ChangeService.load(...)` seam over
  **`ChangeService.document.source_path`** (A-03 pin — the file the document
  was loaded from, NOT the live `#patch_doc_path_input` value), then the
  existing tail `refresh_entries` / `refresh_issues` renderers reflect the
  new content. When `document.source_path is None` (paste-authored / nothing
  loaded) it surfaces the existing load guard ("enter a change-file path to
  load"), a safe no-op — no crash.
- `refresh_doc` added to `PATCH_ACTIONS_V2`.

Refresh mechanism confirmed: **source = `service.document.source_path`**
(`app.py`, new `elif event.action == "refresh_doc"` branch), reusing
`ChangeService.load` (size-cap + `resolve_input_path` + collect-don't-abort
guards — not bypassed). No new file-read code; no schema/apply-engine change.

Two pre-existing census/pin tests updated in-place (rewrite-in-place,
censused) to track the additive action + button — see §5.

## 2. Files modified

| File | Change |
|------|--------|
| `s19_app/tui/app.py` | `refresh_doc` added to `PATCH_ACTIONS_V2` (:143); new `refresh_doc` dispatch branch re-invoking `ChangeService.load` over `document.source_path` with `source_path is None` guard (:1663); handler docstring count ten→eleven (:1583). |
| `s19_app/tui/screens_directionb.py` | `#patch_doc_refresh_button` added to `#patch_doc_controls` after Load (:1879); `"patch_doc_refresh_button": "refresh_doc"` added to `on_button_pressed` actions map (:2137). |
| `tests/test_tui_patch_editor_v2.py` | NEW `test_at064a_refresh_rereads_edited_file_into_editor` (AT-064a) + `test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded` (TC-328) + `_entry_addresses` helper; supersession updates to `test_action_routing_pins_exactly_eleven_v2_actions` (renamed from `_ten_`) and `test_at057a_...` controls-button-id pin. |

Code files touched: **3** (within the ≤5 cap). No frozen-engine file touched.
(`.dev-flow/state.json` shows modified in `git status` — orchestration tooling,
not this increment.)

## 3. How to test

```bash
# New nodes (AT-064a + TC-328)
pytest "tests/test_tui_patch_editor_v2.py::test_at064a_refresh_rereads_edited_file_into_editor" \
       "tests/test_tui_patch_editor_v2.py::test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded" -q

# Full patch-editor suite (regression + supersessions)
pytest tests/test_tui_patch_editor_v2.py -q

# Snapshot patch cells (drift check)
pytest tests/test_tui_snapshot.py -q -k patch

# Engine-frozen guards (0 diffs — no frozen file touched)
pytest tests/test_engine_unchanged.py \
  tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main \
  tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main \
  tests/test_tui_directionb.py::test_tc031_engine_imports_still_resolve -q

ruff check s19_app/tui/app.py s19_app/tui/screens_directionb.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results

**RED counterfactual (C-20, captured BEFORE the wiring):**
```
tests/test_tui_patch_editor_v2.py::test_at064a_... FAILED
tests/test_tui_patch_editor_v2.py::test_tc328_...  FAILED
E   textual.css.query.NoMatches: No nodes match '#patch_doc_refresh_button' on Screen(id='_default')
2 failed in 1.65s
```
Both new nodes fail because no refresh control exists yet — the editor cannot
re-read on demand. (Edits to existing files only, so a plain pre-change run
captures RED; no git stash.)

**GREEN (after implementation):**
| Run | Result | Exit |
|-----|--------|------|
| Two new nodes (AT-064a + TC-328) | `2 passed in 1.70s` | 0 |
| Full `test_tui_patch_editor_v2.py` | `40 passed in 32.64s` (38 baseline + 2 new) | 0 |
| Snapshot patch cells `-k patch` | `2 snapshots passed. 2 passed, 32 deselected` | 0 |
| Engine-frozen (`test_engine_unchanged` + tc031 ×3) | `4 passed in 0.30s` (0 diffs) | 0 |
| ruff on 3 changed files | `All checks passed!` | 0 |
| Full-suite `--collect-only` | `1371 tests collected` | 0 |

**Per-LLR coverage (on-disk test fn names):**
- **LLR-064a.1** (refresh re-invokes `ChangeService.load` over `document.source_path`;
  `source_path is None` guard) →
  `test_at064a_refresh_rereads_edited_file_into_editor` (external-edit → real
  Refresh press → entries table shows the NEW `0x555` entry — C-10 content,
  C-12 reads the consumer surface the real handler produced) +
  `test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded`
  (A-03: path input pointed at a DIFFERENT file → refresh still re-reads the
  `source_path` file, other file's `0xABC` never appears; `source_path is None`
  → guard line surfaced, table empty, no crash).
- **LLR-064a.2** (zero behaviour change + id preservation; adds one new id) →
  full `test_tui_patch_editor_v2.py` green (40/40); `test_at057a_...` pins the
  controls row as Load/**Refresh**/Validate/Apply/Save (existing ids + order
  preserved, one additive id).

**C-18 note:** AT-064a is exactly ONE on-disk node
(`test_at064a_refresh_rereads_edited_file_into_editor`). TC-328 is its unit
companion (one node). No AT split across nodes.

**Snapshot disposition (C-22):** NO patch cell drifted — both
`patch-comfortable-80x24` and `patch-comfortable-120x30` PASSED unchanged
after adding the visible Refresh button. No `xfail` mark needed; no local
baseline regeneration.

## 5. Risks

- **Supersession of two pin/census tests (LOW).** Adding a routed action +
  button necessarily broke two pins: `test_action_routing_pins_exactly_ten_v2_actions`
  (froze the action set at ten) and `test_at057a_...` (froze the controls row
  at 4 buttons). Both were rewritten in place to encode the intended new state
  (`refresh_doc` is a valid routed action; Refresh sits after Load) — not
  weakened. The former was renamed `_ten_`→`_eleven_` for honesty (net-0 node
  count: −1 old name +1 new name). This is a behaviour-tracking supersession,
  documented, not a silent assertion edit.
- **A-03 correctness (mitigated).** The failure mode would be refresh reading
  the widget path instead of `source_path`; TC-328 asserts the opposite
  directly (other-file entry must NOT appear).
- **Path re-resolution (LOW).** `load(str(source_path), base_dir)` re-runs
  `resolve_input_path`; if the file was deleted between load and refresh the
  existing collect-don't-abort read fault surfaces as a status diagnostic
  (spec boundary), no crash — covered by the reuse of the `load` seam.

## 6. Pending items

- US-064a boundary arms named in AT-064a's catalog beyond the two shipped
  (0-entry refresh, malformed-JSON refresh, deleted-file refresh) are covered
  structurally by reusing the `load` seam but are not each a dedicated node
  this increment — the core external-edit + A-03 + None-guard paths are pinned.
- Snapshot: no drift this increment, so no canonical-CI regen needed for
  Inc-1. (End-of-batch regen still applies for any later drifting increment.)
- REQUIREMENTS.md R-TUI-052 row: proposed in the spec; not added here (Inc-1
  file scope was screens + app + one test). Suggest folding at batch close or
  the docs phase.

## 7. Suggested next task

**Inc-2 · US-061 (persistent before/after-report surface)** — reveal a durable
`#patch_before_after_row` on successful save-back that routes to the existing
`action_before_after_report` writer (C-24 census: 0 report-content change),
per the §6.6 increment cut.

## Evidence checklist

- [x] Tests/type checks/lint pass — patch suite 40/40 exit 0; snapshot 2/2;
  frozen 4/4 (0 diffs); ruff `All checks passed!` exit 0.
- [x] No secrets in code or output — additive UI wiring + tests only.
- [x] No destructive commands run — read/edit/pytest/ruff only.
- [x] File count within cap — 3 code files (≤5).
- [x] Review packet attached — this file.
