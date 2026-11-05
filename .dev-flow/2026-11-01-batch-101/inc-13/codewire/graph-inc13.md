# Code-Wire graph — Inc 13 (CRC Designer and Split/Join responsive at 10 MB), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `b7b77c4`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Unchanged nodes are context: a changed node calls them, or they call it.
- Example sources are the test-case ids of `02-test-cases.md` (`R-CRC-DESIGNER-007.1/1`); `B` = what the base code does, read at E1 (no run on the E1 host). Every example states the Inc 13 target unless it says "base:".
- "fixture" = `_fixture_mem()` of `tests/test_crc_designer_view.py` with the first-shown Ranges `0x00008000-0x00008008, 0x00008010-0x00008018` (concat `0x9C5BCBBD`, fill(0xFF) `0x2A8A3950`, CRC-32/ISO-HDLC); "dirty" = the fixture plus `0x800B = 0x99`; "demo" = the demo image of `../01-requirements.md` Definitions; "Q" = `CRC_RECOMPUTE_S`.

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns nodes |
|---|---|---|
| G1 designer | `s19_app/tui/crc_designer_view.py` | `CRC_RECOMPUTE_S`, `_CoverageRun`, `CrcDesignerPanel.__init__`, `.on_mount`, `._on_image_changed`, `.on_input_changed`, `._schedule_recompute`, `.on_select_changed`, `._apply_template`, `._recompute`, `._compute_coverage`, `._coverage_preview_text`, `._render_coverage_window` |
| G2 split/join | `s19_app/tui/segment_split_view.py` | `_sweep`, `_conflict_marks` |
| G3 kernel | `s19_app/tui/operations/crc_kernel.py` | `_REFLECT8`, `crc_lut` |
| T-A designer tests | `tests/test_b101_designer_recompute.py`, `tests/support/b101_designer.py`, the waits in `tests/test_crc_designer_view.py` (`../E1-slice.md` §3) | the R-CRC-DESIGNER-001.2.x / 007.x, R-CRC-PREVIEW-001.x / 002.1 / 002.2/2 nodes |
| T-B band tests | `tests/test_b101_split_join_band.py`, `tests/support/b101_inc13_reference.py`, `tests/support/b101_demo_image.py` | the R-SEG-PREV.2 nodes |
| T-C timing arms | `tests/test_b101_inc13_perf.py` | R-CRC-PREVIEW-002.2/1, 002.3/1, R-SEG-PREV.20/1 (all `serial_timing`) |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the quiet time | `CRC_RECOMPUTE_S: float = 0.150` at module level of `crc_designer_view.py`; read at each `_schedule_recompute` call (so `monkeypatch.setattr(crc_designer_view, "CRC_RECOMPUTE_S", 0.6)` takes effect) | G1 → T-A, T-C |
| I-2 the recompute observable | `CrcDesignerPanel._recompute(self) -> None`: name and arity stable; the timer and every handler call it through `self._recompute` (so a class-level wrapper counts every call); `CrcDesignerPanel._pending_recompute: Optional[Timer]`, `None` exactly when no recompute is pending | G1 → T-A (`RecomputeCounter`, `wait_designer_recompute`), T-C |
| I-3 the clock stamps | widget ids `#crc_coverage_window` and `#sje_stats` (unchanged); the arms wrap that widget instance's `update` | G1, G2 → T-C |
| I-4 the band functions | `_sweep(lo: int, hi: int, marks: List[Tuple[int, int, str]]) -> List[Block]` and `_conflict_marks(mem_map: Dict[int, int], src: List[Tuple[int, int]], picked_spans: List[Tuple[int, int]], pad_byte: int) -> List[Tuple[int, int, str]]`: signatures unchanged; module-level names stable (`build_plan` looks them up at call time, so T-B can patch the base references in) | G2 → T-B |
| I-5 the reference oracle | `tests/support/b101_inc13_reference.py`: `reference_sweep`, `reference_conflict_marks`, verbatim bodies of `b7b77c4:s19_app/tui/segment_split_view.py:288-351`, header naming the commit and lines | T-B internal |
| I-6 the demo image | `tests/support/b101_demo_image.py`: `demo_regions() -> dict[str, tuple[int, bytearray]]` (`compute_region_sizes(10)` then `build_objects(regions, random.Random(20260001))`), `demo_loaded_file() -> LoadedFile` (path `firmware.s19`, `file_type="s19"`, `mem_map` from the regions, `ranges` = the four `(base, base + len)`), both cached per process | T-B → T-C |
| I-7 the kernel | `crc_lut(data: bytes, *, width, poly, init, refin, refout, xorout) -> int` unchanged; `_REFLECT8: bytes`, length 256, `_REFLECT8[b] == reflect(b, 8)` | G3 → G1 (through `CrcAlgorithm.compute`), `tests/test_crc_kernel.py` |
| I-8 the image reactive (not changed here) | `S19TuiApp.current_file: reactive[Optional[LoadedFile]]` (`app.py:2748`), assigned on install, project-load reset and unload | app → G1 |

Order inside E4: G1, G2, G3 in parallel (no interface between them except I-7, unchanged in form); T-B writes I-5 and I-6 first (T-C imports I-6); every tester proves RED on base first (M-1 profiles before the build, `../E1-rulings.md` §5).

## Entities

CRC_RECOMPUTE_S
func: new. Module constant of `crc_designer_view.py`, `0.150` (seconds): the quiet time. Mirrors `screens.SAVE_RECOMPUTE_S`.
module: s19_app/tui/crc_designer_view.py
note: R-CRC-DESIGNER-001.2.2/3 reads it: `== 0.150`.

_CoverageRun
func: new. `@dataclass(frozen=True)` at module level. Fields: `target: Optional[CrcTarget] = None`; `invalid: Optional[str] = None` (the `str(exc)` of a target-build fault); `evaluation: Optional[TargetEvaluation] = None`; `eval_error: Optional[str] = None` (the `str(exc)` of a `ValueError` from `evaluate_target`); `concat_crc: Optional[int] = None`; `fill_crc: Optional[int] = None`; `crc_error: Optional[str] = None` (the `str(exc)` of any CRC fault the window must show). Invariants: `invalid` set ⇒ every other field `None`; `eval_error` set ⇒ `crc_error == eval_error`; `crc_error is None` and `invalid is None` ⇒ `concat_crc` and `fill_crc` are ints.
module: s19_app/tui/crc_designer_view.py

_REFLECT8
func: new. Module constant of `crc_kernel.py`, defined after `reflect`: `bytes(reflect(b, 8) for b in range(256))`.
module: s19_app/tui/operations/crc_kernel.py
examples: (R-CRC-DESIGNER-001.1/1) `len(_REFLECT8) == 256`; `_REFLECT8[0x01] == 0x80`; `_REFLECT8[0xF0] == 0x0F`; `_REFLECT8[0xA5] == 0xA5`

S19TuiApp.current_file
func: unchanged. Textual `reactive(None)` (`app.py:2748`); a global watcher registered with `DOMNode.watch` runs synchronously inside the assignment.
module: s19_app/tui/app.py
note: assigned at `app.py:13434` (`None`, project-load reset), `:17189` (unload), `:17954` (install). An in-place `mem_map` change (change apply) does not assign it (`../E1-rulings.md` §1, out of scope).

F-23 scenes
note: the F-23 CRC scene, the F-23 template and the F-23 Split/Join scene are defined in `../01-requirements.md` Definitions; the demo image's join gap of the Split/Join scene is `[0x10000, 0x800000)`, holding the app range `[0x40000, 0x309FA0)` (2.79 MiB of source).

## Nodes — CRC Designer (G1)

CrcDesignerPanel.__init__
req: R-CRC-DESIGNER-001.2.2
in: —
out: None
func: changed. was: `super().__init__(id="crc_designer_panel", classes="crc-designer-form")`. / now: the same, then `self._pending_recompute: Optional[Timer] = None`.
module: s19_app/tui/crc_designer_view.py
examples: (R-CRC-DESIGNER-001.2.2/1) a fresh panel → `_pending_recompute is None`

CrcDesignerPanel.on_mount
req: R-CRC-PREVIEW-002.1, R-CRC-PRESET-001.2
in: —
out: None
func: changed. was: `self._recompute()`. / now: `self._recompute()` (the first-shown state, as today), then `self.watch(self.app, "current_file", self._on_image_changed, init=False)`.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._recompute, DOMNode.watch
examples: (R-CRC-PREVIEW-001.1/1) app start with no image, key `0` → preview `Load an image to preview coverage CRCs over real bytes.`; verdict `✓ MATCH` (holds on base)
examples: (R-CRC-PREVIEW-002.1/1) after mount, `app.current_file = fixture` → `_on_image_changed` called once (base: never)

CrcDesignerPanel._on_image_changed
req: R-CRC-PREVIEW-002.1, R-CRC-DESIGNER-001.2.2
in: —
out: None
func: new. The `current_file` watcher: `self._schedule_recompute()`. No compute here: it runs inside the app's assignment (the loader's handler), so the load paints its own status first and a project load that assigns twice (reset to `None`, then the image) recomputes once.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._schedule_recompute
examples: (R-CRC-PREVIEW-002.1/1) `current_file = fixture`, key `0` → within 1 s preview `Active policy: join=concat` / `concat: 0x9C5BCBBD` / `fill:   0x2A8A3950` (base: the empty-state note until a field changes, F-24)
examples: (R-CRC-PREVIEW-002.1/2) then `current_file = None` → within 1 s both surfaces `Load an image to preview coverage CRCs over real bytes.` (base: the fixture's CRCs stay)
examples: (R-CRC-PREVIEW-002.1/3) then `current_file = fixture with 0x8000 = 0xAA` → within 1 s preview line 2 `concat: 0x<zlib.crc32(b"\xaa" + bytes(range(1, 8)) + bytes(range(0x10, 0x18))) as 8 uppercase hex digits>`
examples: (R-CRC-DESIGNER-001.2.2/2) Q = 0.6, `current_file = fixture` at t0 → at t0 + 0.3 s still the empty-state note; by t0 + 1.5 s the three lines; 1 recompute

CrcDesignerPanel.on_input_changed
req: R-CRC-DESIGNER-001.2.2, R-CRC-DESIGNER-007.1
in: Input.Changed event
out: None
func: changed. was: `self._recompute()` on every text-field event. / now: `self._schedule_recompute()`.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._schedule_recompute
examples: (R-CRC-DESIGNER-001.2.2/1) Q = 0.6, XOR out := `0x00000000` at t0 → recomputes at t0 + 0.3 s: 0, verdict `✓ MATCH`; by t0 + 1.5 s: 1, verdict `✗ MISMATCH` (base: 1 at once)
examples: (R-CRC-DESIGNER-007.1/1) Q = 0.6, 5 XOR out edits 50 ms apart ending `0x00000000` → 1 recompute 1.5 s after the last, verdict `✗ MISMATCH` (base: 5)
examples: (B) with the F-23 CRC scene, typing the 21 characters of a range at base costs one ≈ 10 s recompute per keystroke; now one recompute after the last keystroke

CrcDesignerPanel._schedule_recompute
req: R-CRC-DESIGNER-001.2.2, R-CRC-DESIGNER-007.1
in: —
out: None
func: new. If `self._pending_recompute is not None`: `.stop()` it. Then `self._pending_recompute = self.set_timer(CRC_RECOMPUTE_S, self._recompute)` (the module constant read now, I-1). The Save dialog's shape (`screens.py:1322-1340`).
module: s19_app/tui/crc_designer_view.py
calls: Widget.set_timer, Timer.stop
examples: (R-CRC-DESIGNER-007.1/1) 5 calls 50 ms apart with Q = 0.6 → 4 timers stopped, 1 fires, `_recompute` called once
examples: (R-CRC-DESIGNER-001.2.2/1) after the timer fires → `_pending_recompute is None` (set by `_recompute`)

CrcDesignerPanel.on_switch_changed
req: R-CRC-DESIGNER-001.2.1
in: Switch.Changed event
out: None
func: unchanged. `self._recompute()` at once.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._recompute
examples: (R-CRC-DESIGNER-001.2.1/2) Q = 10, Reflection in on → off from the first-shown form → after one pause verdict `✗ MISMATCH`, 1 recompute (holds on base)

CrcDesignerPanel.on_select_changed
req: R-CRC-DESIGNER-001.2.1, R-CRC-DESIGNER-007.3, R-CRC-PRESET-001.3
in: Select.Changed event
out: None
func: changed. was: on `#crc_preset_select` with a known preset, `self._apply_algorithm(algo)` (a `NoMatches` at mount returns), each widget it changes posting its own `Input.Changed` / `Switch.Changed`; then `self._recompute()` for every select. / now: the `_apply_algorithm(algo)` call runs inside `with self.prevent(Input.Changed, Switch.Changed):`; the `NoMatches` return and the final `self._recompute()` stay.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._apply_algorithm, MessagePump.prevent, CrcDesignerPanel._recompute
examples: (R-CRC-DESIGNER-007.3/1) Q = 0.6, Preset := `CRC-16/MODBUS` from the first-shown form → 1 recompute in the next 1.5 s, verdict `✓ MATCH` (base: 1 + one per changed widget ≈ 9)
examples: (R-CRC-DESIGNER-001.2.1/1) Q = 10, fixture loaded, Join gaps `concat` → `fill` → after one pause preview line 1 `Active policy: join=fill`, 1 recompute (holds on base)
examples: (R-CRC-PRESET-001.3) the preset's fields are filled exactly as on base (width `16`, poly `0x8005`, …)

CrcDesignerPanel._apply_algorithm
req: R-CRC-PRESET-001.3 … .6
in: CrcAlgorithm algo
out: None
func: unchanged. Sets name, aliases `""`, width, poly, init, refin, refout, xorout, check, store width from `algo`. Its callers now wrap it in `prevent`.
module: s19_app/tui/crc_designer_view.py

CrcDesignerPanel._apply_template
req: R-CRC-DESIGNER-007.2, R-CRC-PREVIEW-002.3, R-CRC-TEMPLATE-001.10
in: CrcTemplate template
out: None
func: changed. was: `_apply_algorithm(template.algorithm)`, Name := `template.algorithm.name`, Aliases := `", ".join(template.aliases)`, each changed widget posting its change event (one recompute each), then `self._recompute()`. / now: the three fills run inside `with self.prevent(Input.Changed, Switch.Changed):`; then one `self._recompute()` (which also stops a pending timer).
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._apply_algorithm, MessagePump.prevent, CrcDesignerPanel._recompute
examples: (R-CRC-DESIGNER-007.2/1) Q = 0.6, the F-23 template from the first-shown form → 1 recompute; Width `16`, Polynomial `0x8005`, Init `0xFFFF`, in/out on, XOR out `0x0000`, Check `0x4B37`, Name `demo-modbus`, Aliases `a, b`; status `Loaded template from file.` (base: ≈ 11 recomputes)
examples: (R-CRC-PREVIEW-002.3/1) the F-23 CRC scene, Load → the window's last update ≤ 3 s after the press, 1 recompute (base: ≈ 2 min, DOSSIER F-23)
examples: (R-CRC-TEMPLATE-001.16) a load that fails never reaches this node: the form is unchanged and 0 recomputes (holds on base)

CrcDesignerPanel._load_template
req: R-CRC-TEMPLATE-001.10 … .16
func: unchanged. Reads the file; on success calls `_apply_template`, records the template, sets the status.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._apply_template

CrcDesignerPanel._recompute
req: R-CRC-DESIGNER-001.2.1, R-CRC-DESIGNER-001.2.2, R-CRC-DESIGNER-007.1, R-CRC-DESIGNER-007.2, R-CRC-DESIGNER-007.3, R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.2, R-CRC-PREVIEW-002.3
in: —
out: None
func: changed. was: resolve the six surfaces by `_RECOMPUTE_SURFACE_IDS` (`NoMatches` → return); build the template (fault → `Invalid parameters: <exc>` on five surfaces, `—` on the custom-vector CRC); update verdict, custom vector, JSON, warnings, then `_coverage_preview_text(algo)` and `_render_coverage_window(algo)`, each building, evaluating and computing on its own (6 window reads). / now: first, if `self._pending_recompute is not None`, stop it and set `None`; surfaces and the parameter-fault path unchanged; then `run = self._compute_coverage(algo)` once; `coverage.update(self._coverage_preview_text(run))`; `window.update(self._render_coverage_window(run))`.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._current_template, ._verdict_text, ._custom_vector_text, ._preview_text, ._live_warnings_text, ._compute_coverage, ._coverage_preview_text, ._render_coverage_window
examples: (R-CRC-PREVIEW-002.2/2) fixture, join `fill`, each On conflict, fixture and dirty → `gather_target` called ≤ 2 times per `_recompute` (base: 6, or 2 when the preview refuses)
examples: (R-CRC-PREVIEW-002.2/1) the F-23 CRC scene, Join gaps → `fill` → the window updated ≤ 3 s after the trigger; line 2 `concat <zlib.crc32(concat window)>   fill <zlib.crc32(fill window)>` (guide: `0x6CD65EAE`, `0xA7B4C7F5`) (base: ≈ 10 s)
examples: (R-CRC-DESIGNER-002.5) Width `zz` → verdict, JSON, preview, window `Invalid parameters: invalid literal for int() with base 10: 'zz'` (holds on base; D13-31 open)
examples: (B, estimate) F-23 CRC scene: base digests ≈ 12.8 MB per recompute (3 × 1.2 MiB concat + 2 × ≈ 4 MiB fill, + one more of the active policy); now ≈ 5.2 MB (one concat, one fill)

CrcDesignerPanel._compute_coverage
req: R-CRC-PREVIEW-002.2, R-CRC-PREVIEW-001.2, R-CRC-PREVIEW-001.3, R-CRC-PREVIEW-001.4, R-CRC-PREVIEW-001.5, R-CRC-PREVIEW-001.6, R-CRC-PREVIEW-001.7, R-CRC-PREVIEW-001.8
in: CrcAlgorithm algo
out: Optional[_CoverageRun]
func: new. `mem_map = current_file.mem_map` if an image is loaded; falsy → return `None`. `try target = self._build_coverage_target()` except `(ValueError, KeyError)` as exc → `_CoverageRun(invalid=str(exc))`. `try evaluation = evaluate_target(mem_map, algo, target)` except `ValueError` as exc → `_CoverageRun(target=target, eval_error=str(exc), crc_error=str(exc))`. Then, in one `try` (except `ValueError` as exc → `_CoverageRun(target=target, evaluation=evaluation, crc_error=str(exc))`): if `evaluation.refused` → `concat = compute_target_crc(mem_map, algo, replace(target, join="concat"))`, `fill = compute_target_crc(…, join="fill")`; elif `target.join == "concat"` → `concat = evaluation.crc`, `fill = compute_target_crc(…, join="fill")`; else → `fill = evaluation.crc`, `concat = compute_target_crc(…, join="concat")`. Return `_CoverageRun(target, evaluation=evaluation, concat_crc=concat, fill_crc=fill)`. Reads `mem_map` only (R-CRC-PREVIEW-001.9).
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._build_coverage_target, evaluate_target, compute_target_crc
examples: (R-CRC-PREVIEW-001.2/2) fixture, join `concat`, abort → `concat_crc = 0x9C5BCBBD` (from the evaluation), `fill_crc = 0x2A8A3950` (computed), 2 `gather_target` calls
examples: (R-CRC-PREVIEW-001.4/1) dirty, join `fill`, abort → `evaluation.refused`, `evaluation.conflicts == (0x800B,)`, `concat_crc = 0x9C5BCBBD`, `fill_crc = 0x2A8A3950`, 2 calls
examples: (R-CRC-PREVIEW-001.6/1) dirty, join `fill`, warn → `fill_crc = evaluation.crc = 0x2A8A3950`, `evaluation.diagnostics == ("gap-safety: 1 present byte(s) at 0x800B in a filled gap differ from pad_byte 0xFF — proceeding (on_gap_conflict=warn)",)`
examples: (R-CRC-PREVIEW-001.3/2) fixture, Width `4`, join `concat` → `eval_error == crc_error == "width 4 out of range [8, 64]"`, crcs `None`
examples: (R-CRC-PREVIEW-001.3/2) dirty, Width `4`, join `fill`, abort → `evaluation.refused`, `eval_error is None`, `crc_error == "width 4 out of range [8, 64]"`
examples: (R-CRC-PREVIEW-001.8/1) Ranges `0x8008-0x8000` → `invalid` = the `_build_target` rule text; 0 `gather_target` calls
examples: (R-CRC-PREVIEW-001.1/1) no image → `None`

CrcDesignerPanel._coverage_preview_text
req: R-CRC-PREVIEW-001.1, R-CRC-PREVIEW-001.2, R-CRC-PREVIEW-001.4, R-CRC-PREVIEW-001.6, R-CRC-PREVIEW-001.7, R-CRC-PREVIEW-001.8
in: Optional[_CoverageRun] run
out: str
func: changed. was: `(algo)`, read the image, build, evaluate and compute itself. / now: `(run)`: `None` → `_COVERAGE_EMPTY_STATE`; `run.invalid` → `f"Invalid coverage: {run.invalid}"`; `run.eval_error` → `f"Cannot preview: {run.eval_error}"`; `run.evaluation.refused` → the refusal text exactly as today from `run.evaluation.conflicts`; else `Active policy: join=<run.target.join>`, `concat: <_format_hex(run.concat_crc, store_width)>`, `fill:   <_format_hex(run.fill_crc, store_width)>`, then `run.evaluation.diagnostics`, joined by `\n`. Every text unchanged.
module: s19_app/tui/crc_designer_view.py
examples: (R-CRC-PREVIEW-001.2/2) fixture, concat, abort → `"Active policy: join=concat\nconcat: 0x9C5BCBBD\nfill:   0x2A8A3950"`
examples: (R-CRC-PREVIEW-001.4/1) dirty, fill, abort → `"Preview refused (on_gap_conflict=abort): 1 present byte(s) at 0x800B conflict with a filled gap; no CRC shown."`
examples: (R-CRC-PREVIEW-001.6/1) dirty, fill, warn → the three lines + `"gap-safety: 1 present byte(s) at 0x800B in a filled gap differ from pad_byte 0xFF — proceeding (on_gap_conflict=warn)"`
examples: (R-CRC-PREVIEW-001.7/1) dirty, fill, ignore → the three lines only
examples: (R-CRC-PREVIEW-001.2/2) fixture, Width `4`, concat → `"Cannot preview: width 4 out of range [8, 64]"`
examples: (R-CRC-PREVIEW-001.8/1) `0x8008-0x8000` → starts `"Invalid coverage: "`
examples: (R-CRC-PREVIEW-001.1/1) `None` → `"Load an image to preview coverage CRCs over real bytes."`

CrcDesignerPanel._render_coverage_window
req: R-CRC-PREVIEW-001.1, R-CRC-PREVIEW-001.3, R-CRC-PREVIEW-001.5, R-CRC-PREVIEW-001.6, R-CRC-PREVIEW-001.8
in: Optional[_CoverageRun] run
out: rich.text.Text
func: changed. was: `(algo)`, read the image, build, compute concat, fill and evaluate itself. / now: `(run)`: `None` → `Text(_COVERAGE_EMPTY_STATE)`; `run.invalid` → `Text(f"Invalid coverage: {run.invalid}")`; line 1, the glyph runs from `run.target` exactly as today; `run.crc_error` → append `f"Cannot compute: {run.crc_error}"` (DGRAY) and return; line 2 `concat <hex>   fill <hex>` from `run.concat_crc` / `run.fill_crc` with today's styles; line 3 `store — refused (on_gap_conflict=abort)` when `run.evaluation.refused`, else `store <store_word(run.evaluation.crc, run.target) as uppercase hex pairs>` then each diagnostic on its own line. Still `Text.append` only (C-17).
module: s19_app/tui/crc_designer_view.py
calls: store_word, _format_hex
examples: (R-CRC-PREVIEW-001.3/1) fixture, concat, abort → line 2 `concat 0x9C5BCBBD   fill 0x2A8A3950`, line 3 `store BD CB 5B 9C` (little, 4 bytes)
examples: (R-CRC-PREVIEW-001.5/1) dirty, fill, abort → line 2 `concat 0x9C5BCBBD   fill 0x2A8A3950`, line 3 `store — refused (on_gap_conflict=abort)`
examples: (R-CRC-PREVIEW-001.6/1) dirty, fill, warn → line 3 `store 50 39 8A 2A`, line 4 the gap-safety diagnostic
examples: (R-CRC-PREVIEW-001.3/2) Width `4`, any state → line 2 `Cannot compute: width 4 out of range [8, 64]` (holds on base)
examples: (R-CRC-PREVIEW-001.1/2) `None` → plain `"Load an image to preview coverage CRCs over real bytes."`

CrcDesignerPanel._build_coverage_target
req: R-CRC-PREVIEW-001.8
func: unchanged. Parses Ranges, Pad byte, the dropdowns and the store placement; validates through `_build_target`.
module: s19_app/tui/crc_designer_view.py

## Nodes — CRC model and kernel (context; G3 owns `crc_lut`)

evaluate_target
req: R-CRC-PREVIEW-001.4 … .7
func: unchanged. `gap_conflict` → abort refuses with no CRC; otherwise `compute_target_crc` of the target as given (its own join).
module: s19_app/tui/operations/crc_designer_model.py
examples: (R-CRC-PREVIEW-002.2/2) not refused → exactly 1 `gather_target` call; refused → 0

compute_target_crc
func: unchanged. `algorithm.compute(gather_target(mem_map, target))`.
module: s19_app/tui/operations/crc_designer_model.py

gather_target
func: unchanged. Per range `_gather_range` (a per-byte dict walk), pads between ranges for `join="fill"`.
module: s19_app/tui/operations/crc_designer_model.py
note: the counting point of R-CRC-PREVIEW-002.2/2 (`crc_designer_model.gather_target` wrapped; `compute_target_crc` resolves it at call time).

crc_lut
req: R-CRC-DESIGNER-001.1, R-CRC-PREVIEW-002.2
in: bytes data; int width; int poly; int init; bool refin; bool refout; int xorout
out: int
func: changed. was: width check; `table = make_crc_table(width, poly)`; `for byte in data: if refin: byte = reflect(byte, 8)` then the table step; `refout` → `reflect(reg, width)`; `^ xorout`. / now: the width check and the table as today; `if refin: data = bytes(data).translate(_REFLECT8)` once; `for byte in data:` the same table step with no branch; `refout` and `xorout` as today.
module: s19_app/tui/operations/crc_kernel.py
calls: make_crc_table, reflect
examples: (R-CRC-DESIGNER-001.1/1) CRC-32/ISO-HDLC over `b"123456789"` → `0xCBF43926` (holds on base)
examples: (R-CRC-DESIGNER-001.1/1) every preset over 200 random vectors → equals `crc_stream` (the bit-by-bit engine) (holds on base)
examples: (R-CRC-DESIGNER-001.1/1) refin true, refout false, width 16, poly `0x1021`, init `0xFFFF`, xorout 0 over `b"\x01\x80"` → equals `crc_stream` with the same parameters
examples: (B, estimate) per input byte with refin: base ≈ 1 µs (a Python call with an 8-step loop), now ≈ 0.15–0.25 µs (the table step alone)

reflect
func: unchanged. Reverses the low `width` bits.
module: s19_app/tui/operations/crc_kernel.py

## Nodes — Split/Join (G2)

_sweep
req: R-SEG-PREV.2, R-SEG-PREV.20
in: int lo; int hi; List[Tuple[int, int, str]] marks
out: List[Block]
func: changed. was: `cuts` = `{lo, hi}` ∪ each mark's ends clamped to `[lo, hi]`; for each pair of consecutive cuts `[a, b)`, scan every mark for the highest-priority class (data 4 > conflict 3 > fill 2 > ctx 1) with `s < b and e > a`, `"none"` if none; append or merge equal neighbours. O(intervals × marks). / now: the same cuts; each mark with `max(lo, min(s, hi)) < max(lo, min(e, hi))` adds its class at its clamped start and removes it at its clamped end (marks with `s >= e`, or wholly outside `[lo, hi]`, never cover an interval on base and add nothing now); walk the sorted cuts once, applying the removals and additions at each cut, keeping a count per class; the interval's class is the highest-priority class with a count above 0, else `"none"`; append or merge exactly as today. O(m log m).
module: s19_app/tui/segment_split_view.py
examples: (R-SEG-PREV.2/4) `_sweep(0, 10, [(0, 10, "ctx"), (2, 8, "fill"), (4, 5, "conflict"), (3, 6, "data")])` → `[Block("ctx", 2), Block("fill", 1), Block("data", 3), Block("fill", 2), Block("ctx", 2)]` (holds on base)
examples: (R-SEG-PREV.2/4) `_sweep(0, 4, [(1, 2, "data")])` → `[Block("none", 1), Block("data", 1), Block("none", 2)]` (holds on base)
examples: (R-SEG-PREV.2/4) `_sweep(0, 4, [(-5, 1, "fill"), (3, 9, "conflict"), (2, 2, "data"), (3, 1, "data")])` → `[Block("fill", 1), Block("none", 2), Block("conflict", 1)]` (an empty and an inverted mark add nothing; holds on base)
examples: (R-SEG-PREV.2/4) 5 000 random marks over `[0, 1 000 000)`, seed 7 → equals `reference_sweep` (base: ≈ 10⁷–10⁸ steps; now ≈ 10⁴ log)
examples: (R-SEG-PREV.20/1) the F-23 Split/Join scene's union sweep (thousands of conflict marks) → well under a second (base: the dominant share of ≈ 25 s, to be confirmed by M-1)

_conflict_marks
req: R-SEG-PREV.2, R-SEG-PREV.7, R-SEG-PREV.20
in: Dict[int, int] mem_map; List[Tuple[int, int]] src; List[Tuple[int, int]] picked_spans; int pad_byte
out: List[Tuple[int, int, str]]
func: changed. was: merge the sorted picked spans; for each gap between merged spans and each source range in `src` order, `for addr in range(lo, hi)` with `addr in mem_map and mem_map[addr] != pad_byte` → extend the last mark when it ends at `addr`, else append `(addr, addr + 1, "conflict")`. / now: the same merge and the same gap × source order; for each non-empty `[lo, hi)`: `window = bytes(map(mem_map.get, range(lo, hi), repeat(pad_byte, hi - lo)))` (an absent address reads as the pad, so both "absent" and "equal to the pad" are non-conflict, exactly the base predicate); for each match of the compiled `rb"[^\x%02x]+" % pad_byte` in `window`: `a, b = lo + m.start(), lo + m.end()`; extend the last mark to `b` when it ends at `a`, else append `(a, b, "conflict")`. The docstring's claim that a test pins the equivalence is replaced by the names of R-SEG-PREV.2/2–/3's nodes. Preconditions as on base: image values and `pad_byte` in 0 … 255.
module: s19_app/tui/segment_split_view.py
examples: (R-SEG-PREV.2/2) mem `{0:1, 1:2, 2:0, 3:5, 4:0, 5:0, 6:7, 7:8}`, src `[(0, 8)]`, picked `[(0, 1), (7, 8)]`, pad `0x00` → `[(1, 2, "conflict"), (3, 4, "conflict"), (6, 7, "conflict")]` (holds on base)
examples: (R-SEG-PREV.2/2) the same with pad `0xFF` → `[(1, 7, "conflict")]` (holds on base)
examples: (R-SEG-PREV.2/2) the same mem, src `[(0, 4), (4, 8)]` (touching), pad `0xFF` → `[(1, 7, "conflict")]`: the run of `[1, 4)` and the run of `[4, 7)` merge (holds on base; mutant M-12 gives two marks)
examples: (R-SEG-PREV.2/2) mem `{2: 0x00}` only, src `[(0, 8)]`, picked `[(0, 1), (7, 8)]`, pad `0x00` → `[]` (absent and pad-valued both clean)
examples: (R-SEG-PREV.2/3) demo, src = the four ranges, picked `[(0x0, 0x10000), (0x800000, 0x931FC0)]`, pad `0x00` → equals `reference_conflict_marks(...)` as a list; `sum(e - s) == len(gap_conflict(...))` (≈ 2.77 MiB, guide ch14.7)
examples: (R-SEG-PREV.7/2) `prg.s19`, ticks {0, 1, 2, 5, 6, 7}, pad `0x00` → 5 conflict bytes (holds on base, TC-710)

build_plan
req: R-SEG-PREV.2, R-SEG-PREV.7
func: unchanged. Calls `_conflict_marks` (join fill) and `_sweep` (union band and per-file bands); the plan's `conflicts` = the ▒ cells of the union band.
module: s19_app/tui/segment_split_view.py
calls: _conflict_marks, _sweep
examples: (R-SEG-PREV.2/2) 220 seeded images × 4 modes → the plan equals the plan built with `reference_sweep` / `reference_conflict_marks` patched in (I-4, I-5)
examples: (R-SEG-PREV.2/1) join fill → the union band equals the per-address CTX-SJE-BAND classifier's run-length

SplitJoinWindow._sync / SplitJoinWindow.action_cycle_gap
req: R-SEG-PREV.1, R-SEG-PREV.20
func: unchanged. `g` → `action_cycle_gap` → `_bump` → `_sync` → `_plan` → `build_plan`; `#sje_stats` is updated once per sync.
module: s19_app/tui/segment_split_view.py
examples: (R-SEG-PREV.20/1) the F-23 Split/Join scene, `g` → `#sje_stats` updated ≤ 2.5 s after the press with `packed 1.26 MiB  ·  span 9.20 MiB  ·  fill <pct>%` and `⚠ <fmtB(conflict count)> would clobber source — abort on export` (base: ≈ 25 s, the same text)

## Coverage of the requirements by examples

Every active row of `../01-requirements.md` has at least one example above: R-CRC-DESIGNER-001.2.1 (`on_select_changed`, `on_switch_changed`), -001.2.2 (`on_input_changed`, `_schedule_recompute`, `_on_image_changed`, `__init__`), -007.1 (`on_input_changed`, `_schedule_recompute`), -007.2 (`_apply_template`), -007.3 (`on_select_changed`), -001.1 (`_REFLECT8`, `crc_lut`); R-CRC-PREVIEW-002.1 (`_on_image_changed`, `on_mount`), -002.2 (`_recompute`, `evaluate_target`, `crc_lut`), -002.3 (`_apply_template`), -001.1 … .8 (`_compute_coverage`, `_coverage_preview_text`, `_render_coverage_window`); R-SEG-PREV.20 (`_sweep`, `action_cycle_gap`), .2 (`_sweep`, `_conflict_marks`, `build_plan`), .7 (`_conflict_marks`, `build_plan`).
