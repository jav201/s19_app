# Inc 5 — E4 implementation notes (unit A: app + designer hook)

Unit A of batch-101 Inc 5, design-first flow. Files: `s19_app/tui/app.py`,
`s19_app/tui/crc_designer_view.py`. Graph nodes owned (per
`codewire/graph-inc5.md` groups G1 + G2):
`S19TuiApp._note_image_bytes_written` (#1),
`S19TuiApp.on_patch_editor_panel_action_requested` (#2),
`S19TuiApp.on_patch_editor_panel_save_back_decision` (#3),
`S19TuiApp._on_project_saved` (#4),
`S19TuiApp.on_check_editor_panel_spec_file_selected` (#5),
`S19TuiApp._check_items_to_document` (#6),
`CrcDesignerPanel.note_image_bytes_written` (#7).

## Functions changed per file

`s19_app/tui/app.py`:

- `S19TuiApp._note_image_bytes_written` — new (#1). `try: panel =
  self.query_one(CrcDesignerPanel)` / `except Exception: return` around the
  query only, then, outside the `try`, `panel.note_image_bytes_written()` so a
  fault inside the panel is not swallowed. No-op when the designer tree is not
  mounted (matching `watch_current_file`). Never calls `refresh_window` and
  never moves focus (the graph interface note for Inc 10).
- `S19TuiApp.on_patch_editor_panel_action_requested` — changed (#2): right after
  the `try`/`except` and before the panel refresh,
  `if event.action == "apply_doc": self._note_image_bytes_written()`. Runs on
  both outcomes (success and the `Patch Editor: <exc>` path); never gated on
  `counts["applied"] > 0` (R-CRC-PREVIEW-002.5/6, /8).
- `S19TuiApp.on_patch_editor_panel_save_back_decision` — changed (#3):
  `self._note_image_bytes_written()` immediately after `save_patched` returns and
  before `_report_change_result`, whatever `result.ok` (R-CRC-PREVIEW-002.5/7).
  The declined and no-image paths are unchanged (no write, no notice).
- `S19TuiApp._on_project_saved` — changed (#4):
  `self._note_image_bytes_written()` right after `adopt_rederived`, inside the
  same `if request.image is not None:` block (only when the commit wrote the
  image; R-CRC-PREVIEW-002.1/6, -002.5/5).
- `S19TuiApp.on_check_editor_panel_spec_file_selected` — changed (#5): each item
  now also carries `"expected": tuple(entry.encoded_bytes)` and
  `"symbol": entry.symbol` (I-3). Status text and field count unchanged.
- `S19TuiApp._check_items_to_document` — changed (#6): when
  `item.get("expected")` is a tuple of exactly `size` ints, those are the
  expected bytes and the image is not read (a field loaded from a spec is
  declared without the image); otherwise the base image-read path. The skipped
  count and the `outside the loaded image` status are unchanged.

`s19_app/tui/crc_designer_view.py`:

- `CrcDesignerPanel.note_image_bytes_written` — new, public (#7, I-1). One
  statement: `self._on_image_changed()`. No argument, returns `None`, never
  computes synchronously. Delegates to Inc 13's `_on_image_changed` (schedule
  while displayed, mark stale while hidden).

## Deviation from the graph

None. All seven nodes are implemented exactly as the graph states them,
including:

- the apply hook runs on both outcomes and is not gated on `applied > 0`;
- the save-back hook runs whatever `result.ok`;
- the project-save hook sits inside the `request.image is not None` block;
- `_check_items_to_document` takes spec bytes only when the tuple length equals
  `size` (the E1-D6 backstop falls through to the image path);
- the hook never calls `refresh_window` and never moves focus.

## py_compile result

`python -m py_compile s19_app/tui/app.py s19_app/tui/crc_designer_view.py` →
OK (exit 0, no output). CRLF line endings preserved in both files (verified by
byte scan: every new line added is CRLF-terminated).
