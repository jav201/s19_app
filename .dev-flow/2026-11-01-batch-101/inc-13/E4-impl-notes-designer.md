# Inc 13 — E4 implementation notes (G1 designer)

Unit: G1 — `s19_app/tui/crc_designer_view.py`. Implementer unit of batch-101 Inc 13, design-first flow. Graph nodes owned: `CRC_RECOMPUTE_S`, `_COVERAGE_CAP_BYTES`, `_CoverageRun`, `CrcDesignerPanel.__init__`, `.on_mount`, `._on_image_changed`, `.on_show`, `.on_input_changed`, `._schedule_recompute`, `.on_select_changed`, `._apply_template`, `._recompute`, `._compute_coverage`, `._coverage_preview_text`, `._render_coverage_window`.

## Functions / constants changed

`s19_app/tui/crc_designer_view.py`:

- imports — `dataclass` added to the existing `dataclasses` import; `Optional`
  added from `typing`; `Timer` added from `textual.timer`; `TargetEvaluation`
  added to the `crc_designer_model` import (the type of `_CoverageRun.evaluation`).
- `CRC_RECOMPUTE_S` — new module constant, `0.150` (seconds). The quiet time,
  read at schedule time in `_schedule_recompute` so tests can inject it.
- `_COVERAGE_CAP_BYTES` — new module constant, `16 * 1024 * 1024` (16777216,
  16 MiB). Read at each `_compute_coverage` call so tests can inject it.
- `_CoverageRun` — new frozen dataclass, module level, fields
  `target` / `invalid` / `evaluation` / `eval_error` / `concat_crc` / `fill_crc`
  / `crc_error` / `size_cap`, all `Optional`. Only ever a local of `_recompute`,
  never stored on the panel.
- `CrcDesignerPanel.__init__` — changed: adds `self._pending_recompute:
  Optional[Timer] = None` and `self._coverage_dirty = False`.
- `CrcDesignerPanel.on_mount` — changed: keeps the first `_recompute()`, then
  `self.watch(self.app, "current_file", self._on_image_changed, init=False)`.
- `CrcDesignerPanel._on_image_changed` — new: the `current_file` watcher. If
  `self.is_on_screen` → `_schedule_recompute()`; else `self._coverage_dirty = True`.
- `CrcDesignerPanel.on_show` — new: if `_coverage_dirty`, `_schedule_recompute()`;
  a clean display does nothing.
- `CrcDesignerPanel.on_input_changed` — changed: `_recompute()` → `_schedule_recompute()`.
- `CrcDesignerPanel._schedule_recompute` — new: stops a pending timer, then
  `self._pending_recompute = self.set_timer(CRC_RECOMPUTE_S, self._recompute)`
  (the constant read now).
- `CrcDesignerPanel.on_select_changed` — changed: the `_apply_algorithm(algo)`
  call now runs inside `with self.prevent(Input.Changed, Switch.Changed):`; the
  `NoMatches` return and the final `_recompute()` are unchanged.
- `CrcDesignerPanel._apply_template` — changed: the three fills run inside
  `with self.prevent(Input.Changed, Switch.Changed):`; then one `_recompute()`.
- `CrcDesignerPanel._compute_coverage` — new: `None` without an image; builds
  the target (`invalid` on a build fault); refuses a coverage whose size
  (`sum(range sizes) + sum(positive forward gaps)`) exceeds `_COVERAGE_CAP_BYTES`
  before any window read (`size_cap`); evaluates once; computes only the other
  policy's CRC (both when the evaluation refuses). ≤ 2 window reads.
- `CrcDesignerPanel._coverage_preview_text` — changed signature: `(algo)` →
  `(run: Optional[_CoverageRun])`; renders the shared run with the same texts,
  adding the `size_cap` → `Cannot preview: coverage exceeds <cap> bytes` branch.
- `CrcDesignerPanel._render_coverage_window` — changed signature: `(algo)` →
  `(run: Optional[_CoverageRun])`; line 1 scaled to the whole span (min start to
  max end), each run `max(1, round(size / bytes_per_glyph))` with no per-run
  glyph cap; `size_cap` → cap notice as line 2; `crc_error` → `Cannot compute:
  <reason>` as line 2; otherwise the concat/fill hexes, store word (or abort
  refusal) and diagnostics.
- `CrcDesignerPanel._recompute` — changed: stays argument-less; its first
  statement is `pending, self._pending_recompute = self._pending_recompute, None`,
  then stops `pending` and clears `_coverage_dirty`; computes `run =
  self._compute_coverage(algo)` once (a local) and passes it to both coverage
  renderers; the parameter-fault path and the other surfaces are unchanged.
- `CrcDesignerPanel._build_coverage_target` — docstring only (Raises / Used-by
  now name `_compute_coverage`); the body is unchanged.

Unchanged, by decision: `on_switch_changed` (recomputes at once),
`_apply_algorithm`, `_build_coverage_target` body, every other renderer.

## Deviation from the graph

One, per the binding E3 round-2 addendum (`E3-rulings.md` round 2, SEC-2):

- `_COVERAGE_CAP_BYTES` is `16 * 1024 * 1024` = 16777216 (16 MiB), not the
  graph's / E1-slice's `64 * 1024 * 1024` (64 MiB). The graph (I-9 and the
  `_COVERAGE_CAP_BYTES` entity) and `E1-slice.md` item 18 predate the round-2
  ruling, which sets the cap at 16 777 216 bytes and says "Row 001.11 text and
  its case use 16777216". The rendered text is dynamic —
  `Cannot preview: coverage exceeds {run.size_cap} bytes` — so it reads
  `… exceeds 16777216 bytes` with the shipped constant and `… exceeds 23 bytes`
  when the constant is injected as 23.

Also, per round-2 addendum N-4 ("the per-run glyph cap is dropped"), the
`_render_coverage_window` glyph runs apply no `min(_COVERAGE_WINDOW_GLYPHS, …)`
cap; only the min/max span scale of SEC-1 remains.

## py_compile result

`python -m py_compile s19_app/tui/crc_designer_view.py` — exit 0 (OK).

## Notes

- Only `s19_app/tui/crc_designer_view.py` was edited.
- Line endings preserved: the file stays CRLF (1541 CRLF, 0 LF-not-preceded-by-CR).
- No test file, REQUIREMENTS.md, AT-TC-REGISTRY.jsonl, or tests/test_id_registry.py
  was touched. No pytest run, no `s19_app` import (operator rule).
