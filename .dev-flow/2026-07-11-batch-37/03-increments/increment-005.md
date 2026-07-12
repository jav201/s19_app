# Increment 005 — US-064b (B-14) JSON popup change-set editor + A-01 disable-guard

> Batch-37 · Inc-5 (final) · Scope = **US-064b only** (HLR-064b / LLR-064b.1/.2/.3/.4).
> Base = batch-37 working tree carrying Inc-1 + Inc-2 + Inc-3 + Inc-4 (untouched).
> Ledger base = 1381 → post = 1385 (+4 AT/TC, 0 deletions).

## 1. What changed

Added a full-size JSON popup editor for the Patch Editor's change-set, plus the
**A-01 data-loss disable-guard** that gates it — built together as one
indivisible safety unit (AT-064c + LLR-064b.4 ride WITH the popup, never
separately).

- **JSON popup modal (LLR-064b.1/.2/.3):** a new `ChangeSetJsonScreen(ModalScreen[Optional[str]])`
  opened from a new **"Edit JSON"** control (`#patch_edit_json_button`) beside the
  inline "Parse pasted" button. The popup is a `.modal-dialog` with a large
  editable `TextArea` (`#changeset_json_text`, `height: 1fr`) that **seeds from
  the `#patch_paste_text` buffer** (Q-07 — the editable source of truth for a
  paste-authored document) plus Confirm / Cancel buttons. On **Confirm** it
  dismisses with the edited text; the app writes it back to `#patch_paste_text`
  and **routes it through the EXISTING `parse_paste` → `ChangeService.load_text`
  seam** by re-posting the panel's own `ActionRequested(parse_paste)` — the SAME
  message the inline button posts, so **no new parse/apply path** and no
  `json`/`eval` bypass. On **Cancel** the document and buffer are unchanged.

- **A-01 DISABLE-GUARD (LLR-064b.4) — the safety fix:** the "Edit JSON" control
  is **DISABLED whenever `ChangeService.document.source_path is not None`** (a
  file-backed document). The app syncs the state after every action via a new
  `PatchEditorPanel.set_edit_json_enabled(source_path is None)`. Rationale:
  `ChangeService` has NO document→JSON serializer, so with a file loaded the
  popup would seed from the STALE `DUMMY_CHANGESET_TEXT` buffer and Confirm would
  `load_text`-REPLACE the loaded document = silent DATA LOSS. The guard closes
  the footgun at its trigger. **Defense-in-depth:** the app handler re-checks the
  `source_path is not None` predicate before pushing the popup, so even a
  directly-posted `EditJsonRequested` cannot open the popup / clobber.

- **S-01 (no second clipboard ingress):** `#changeset_json_text` is a plain
  `TextArea` — the IDENTICAL widget class to `#patch_paste_text` — so it inherits
  exactly the same paste mechanism and adds **no new / uncapped clipboard
  ingress**. (See §5 deviation on the spec's `os_clipboard_input` phrasing.)

## 2. Files modified (5 — at the ≤5 cap)

| File | Change |
|------|--------|
| `s19_app/tui/screens.py` | New `ChangeSetJsonScreen(ModalScreen[Optional[str]])` — seeded `TextArea` + Confirm/Cancel; `AUTO_FOCUS` on the editor; dismiss-with-text / dismiss-`None`. |
| `s19_app/tui/screens_directionb.py` | `#patch_edit_json_button` in the paste controls row; `EditJsonRequested` message (carries the paste buffer); `on_button_pressed` arm; `set_edit_json_enabled(bool)` method. |
| `s19_app/tui/app.py` | Import `ChangeSetJsonScreen`; import `TextArea`; `on_patch_editor_panel_edit_json_requested` handler (A-01 guard + push); `_apply_changeset_json_edit` callback (write-back + re-post `parse_paste`); `set_edit_json_enabled(...)` sync at the two document-change tails. |
| `s19_app/tui/styles.tcss` | `#changeset_json_dialog { height: 90% }` + `#changeset_json_text { height: 1fr }` (reuses `.modal-dialog`). |
| `tests/test_tui_patch_editor_v2.py` | +4 nodes: AT-064b, AT-064c, TC-329, TC-331 (+ 2 module-local helpers `_changeset_text`, `_seed_via_paste`). |

No frozen-engine file touched.

## 3. How to test

```bash
pytest tests/test_tui_patch_editor_v2.py -q -k "064b or 064c or tc329 or tc331"
pytest tests/test_tui_patch_editor_v2.py -q          # full file (Inc-4 064a nodes included)
pytest tests/test_tui_snapshot.py -q -k patch        # drift check
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -q -k "engine or tc031"
ruff check s19_app/tui/screens.py s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results (RED-then-GREEN, C-19/C-20)

- **RED (pre-code, C-20):** the 4 new nodes were added to a tracked file and run
  before the implementation — all 4 FAILED cleanly (`NoMatches: '#patch_edit_json_button'`),
  no collection error (the `ChangeSetJsonScreen` import is function-local, so a
  plain run captures per-node RED — no move-aside needed).
  `4 failed, 40 deselected`.
- **GREEN:** `pytest tests/test_tui_patch_editor_v2.py -q` → **44 passed** (40
  pre-existing incl. Inc-4 AT-064a/TC-328 + 4 new).
- **Snapshot (C-22):** `-k patch` → **2 snapshots passed** — the "Edit JSON"
  button did NOT drift `patch-comfortable-80x24` / `-120x30` (the paste-controls
  row sits below the fold in those cells, like Inc-1's Refresh button). **No
  `_batch37_patch_drift_marks` helper needed; no xfail; no local baseline regen.**
  The popup modal itself is matrix-absent (no snapshot cell).
- **Frozen guards:** `test_engine_unchanged` (1 passed) + `tc031` engine-unchanged
  set (6 passed) → **0 diffs** (no frozen file in this increment).
- **Inc-1/2/3 regression:** `test_tui_entropy_viewer.py` + `test_before_after_report.py`
  → **36 passed**. Inc-4 nodes green inside the 44 above.
- **ruff:** All checks passed on the 4 changed source/test files.
- **Ledger:** full-suite `--collect-only` = **1385** (= 1381 base − 0 + 4).

### Per-node coverage (C-18 — every AT → exactly one on-disk node)

| Node | LLR | What it proves |
|------|-----|----------------|
| `test_at064b_json_popup_edit_confirm_cancel_and_geometry` | 064b.1/.2/.3 | AT-064b (ONE node): paste-seed → open → edit JSON → **Confirm** → the entries table (CONSUMER the real `load_text` produced) shows the new `0x777` entry (C-10/C-12); **Cancel** arm leaves the doc `["0x100"]`; **geometry** arm measures N_80/N_120 at both widths. |
| `test_at064c_edit_json_disabled_for_file_backed_document` | 064b.4 | AT-064c (ONE node): file-loaded → button `disabled`, a directly-posted `EditJsonRequested` does NOT push the popup and does NOT mutate entries (no clobber); paste-authored → button `enabled` + popup opens. Both `source_path` states in one node. |
| `test_tc329_popup_seed_and_load_text_apply_seam` | 064b.1/.2 | Seed == buffer; Confirm routes through `load_text` **exactly once** with the edited text (spy) + writes it back to the buffer; Cancel → 0 `load_text` calls + buffer unchanged. |
| `test_tc331_disable_guard_predicate_tracks_source_path` | 064b.4 | The disabled state tracks `source_path` live: fresh None→enabled, file load→disabled, paste→re-enabled. |

## 5. Risks

- **LOW — spec phrasing on S-01.** LLR-064b.1 says paste routes through "the
  `os_clipboard_input` 65 536-char funnel — the SAME `#patch_paste_text` uses".
  In fact `#patch_paste_text` is a plain `TextArea` (not an `OsClipboardInput`);
  it uses Textual's native bracketed-paste path, not `os_clipboard_input`. I
  mirrored `#patch_paste_text` EXACTLY (plain `TextArea`), which is the faithful
  discharge of the normative intent — **no new / second uncapped clipboard
  ingress is added.** Flagged as a deviation, not silently reconciled.
- **LOW — Confirm applies a fault-carrying document, never crashes.** Malformed
  JSON on Confirm flows through the same collect-don't-abort `load_text`
  (`MF-JSON-PARSE` finding), identical to the inline "Parse pasted" button
  (LLR-064b.2 invalid boundary). Not separately asserted here — it is the exact
  existing `parse_paste` behavior already covered by the paste-path tests; the
  popup adds no new parse path to fault.
- **NONE — data-loss guard.** A-01 is closed at two layers (disabled button +
  handler predicate re-check); AT-064c proves a guarded open causes 0 mutation.

## 6. Pending items

- None for US-064b. The **file-loaded round-trip** (editing a file-backed doc's
  JSON in the popup) remains explicitly OUT of MVP scope — it needs a
  `document → JSON` serializer on `ChangeService` (a separate future LLR), which
  the A-01 guard makes unreachable-and-safe rather than half-built.
- Batch-37 is complete after this increment (Inc-1..5 = US-061/062/063/064a/064b).

## 7. Suggested next task

Batch-37 Phase-4 gate run (C-25 — orchestrator owns it): full `pytest -q`,
`--collect-only` ledger re-confirm (expect 1385), the three code reviews
(APPROVE / 0 HIGH), frozen-guard sweep, then the canonical-CI snapshot regen
decision — **no patch-cell drift this increment**, so the only batch-37 snapshot
work is Inc-3's `_batch37_entropy_drift_marks` cells (entropy strip → per-cell
widgets), which await the canonical-env baseline regen as already recorded.

---

### C-23 geometry — PILOT-MEASURED (not fr-math)

Driven via `App.run_test(size=...)`, reading `#changeset_json_text.size.height`
after Confirm/Cancel dock:

| Width | Measured visible editable lines (N_w) |
|-------|----------------------------------------|
| 80×24 | **7** |
| 120×30 | **13** |

Both far exceed the ~0-1 in-viewport lines the height-starved in-panel
`#patch_paste_text` box gives at 80×24 (batch-36 F-01) — the popup is the
readable multi-line surface that F-01 deferred. Because the modal is
full-screen-ish it IS readable even at 80 (contrast batch-36 F-01, where the
in-place panel could not be). The test pins `lines_80 >= 7` and `lines_120 >= 13`.

### Evidence checklist

- [✓] Tests/type checks/lint pass — 44 passed (file); ruff "All checks passed".
- [✓] No secrets in code or output.
- [✓] No destructive commands run.
- [✓] File count within cap — 5 files (at cap).
- [✓] Review packet attached (this file).
