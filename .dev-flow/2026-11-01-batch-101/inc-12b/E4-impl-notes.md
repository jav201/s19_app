# Inc 12b — E4 implementation notes (G4 Flow)

Batch 2026-11-01-batch-101, increment 12b. Implementer G4 Flow (E4). Files touched: `s19_app/tui/flow_screens.py` (only).

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| s19_app/tui/flow_screens.py | module docstring "fb_a doctrine" paragraph | [Doc: flow_screens docstrings] | rewritten to the shipped surface (kind chips, pipeline of cards, add form) |
| s19_app/tui/flow_screens.py | `_flow_block_label` | `_flow_block_label` | removed (with `_blocks_text`) |
| s19_app/tui/flow_screens.py | `_CANVAS_COLS`, `_BLOCK_W`, `_EXT_BLOCK_W`, `_block_width`, `_short_ext`, `_S_WIRE`, `_S_LABEL`, `_S_VALUE`, `_S_HEAD`, `_Grid`, `_plc_block`, `_chip`, `_wire_bend`, `_wire_drop` | [Code: canvas grid helpers] | removed (14 names) |
| s19_app/tui/flow_screens.py | `KindChip` docstring | [Doc: flow_screens docstrings] | "the panel's kind set" replaces "``#flow_kind`` set" |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel` docstring | [Doc: flow_screens docstrings] | drops the hidden canvas/list sentence |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.__init__` | `FlowBuilderPanel.__init__` | + `self._kind: str = BLOCK_SOURCE` (commented, I-2) |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.set_session_dir` | `FlowBuilderPanel.set_session_dir` | drops the `#flow_ext_session` update; ribbon only |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.compose` | `FlowBuilderPanel.compose` | drops `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind`, `#flow_ext_session` |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel._block_rows` | `FlowBuilderPanel._block_rows` | removed |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel._layout` | `FlowBuilderPanel._layout` | removed |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel._canvas_text` | `FlowBuilderPanel._canvas_text` | removed |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel._blocks_text` | `FlowBuilderPanel._blocks_text` | removed |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel._refresh_blocks` | `FlowBuilderPanel._refresh_blocks` | drops the two hidden repaints + docstring sentence |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.on_button_pressed` | `FlowBuilderPanel.on_button_pressed` | chip branch stores `self._kind` only when `kind` is a value of `_KIND_OPTIONS` (S-1); `+ Add` reads `self._kind` |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.on_mount` | `FlowBuilderPanel.on_mount` | no hide loop; first sync reads `self._kind` |
| s19_app/tui/flow_screens.py | `FlowBuilderPanel.on_select_changed` | `FlowBuilderPanel.on_select_changed` | `flow_ext_mode` branch only |
| s19_app/tui/flow_screens.py | `FlowExecutionPanel.compose` | `FlowExecutionPanel.compose` | drops `#fx_help` |
| s19_app/tui/flow_screens.py | `FlowExecutionPanel.on_mount` | `FlowExecutionPanel.on_mount` | drops the `#fx_help` hide line |
| s19_app/tui/flow_screens.py | import block | [Code: canvas grid helpers] | `LABEL` removed (left unused by the removals) |

## 2. Deviations from the graph (each with its reason)

- Minor comment corrections beyond the enumerated `[Doc: flow_screens docstrings]` hunks: (a) the `batch-97 Inc-5 — the pipeline rail` section header still said "both stay mounted and repainted, not displayed — LLR-146.1"; (b) the `FlowBuilderPanel` Data Flow bullet said "pipeline, ribbon and legend repaint (the hidden canvas and list too)". Both are now false after the removals, so I rewrote them to match the shipped surface. Comment-only, no behaviour; they spell no removed id or family name, so I-3 is unaffected.
- `dict(self._KIND_OPTIONS).values()` is used for the S-1 membership guard (the graph pins "only with a value of `_KIND_OPTIONS`" but not the literal idiom). `_KIND_OPTIONS` is a list of `(label, kind)` 2-tuples, so `dict(...).values()` yields exactly the seven kind values.

## 3. Open questions for the integrator — or "none"

none

## 4. Checks

py_compile (operator rule: never run pytest / import `s19_app` here):

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/flow_screens.py
```
Output: (no output; exit code 0).

Pinned I-3 grep of the graph, run on the source tree (the test tree is the testers'; test hits are expected until they re-point):

(1) `git grep -n -w -e flow_help -e flow_canvas -e flow_blocks -e flow_kind -e flow_ext_session -e fx_help -e _flow_block_label -e _blocks_text -e _canvas_text -e _block_rows -e _Grid -e _plc_block -e _chip -e _wire_bend -e _wire_drop -e _block_width -e _short_ext -e _CANVAS_COLS -e _BLOCK_W -e _EXT_BLOCK_W -e _S_WIRE -e _S_LABEL -e _S_VALUE -e _S_HEAD -- s19_app`
Output: empty (exit 1). No source line spells a removed id or family name.

(2a) `git grep -n -e 'def _layout(' -e 'self\._layout(' -- s19_app/tui/flow_screens.py`
Output: empty (exit 1) — the removed `FlowBuilderPanel._layout` method is gone; no `FlowExecutionPanel` `_layout` attribute site is matched by this narrowed command.

(2b) `git grep -n -e '\._layout(' -- tests`
Output: empty (exit 1).

For reference, the full-tree form of (1) (`-- s19_app tests`) still returns 33 lines, all in `tests/` (the 13 G-T3 files plus `test_b101_flow_names_ui.py`); expected — G-T3/G-T4 re-point those, and the merged-tree integration re-runs the two pinned commands with the test tree in place.
