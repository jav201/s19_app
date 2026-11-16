# Inc 8 E4 — impl-s1 (group S1: `s19_app/tui/definition_sheet.py`)

Model claude-sonnet-5-5. One new file, 917 lines. Interfaces: I-8.1 `StagedOverlay`, I-8.5 `KindOps` / `_KIND_OPS` / `_FALLBACK_OPS` / `ops_for`, as pinned.
Examples run on the runner (load average 3.4, `uptime` at start), scratch `~/work/zq-e4-8-impl-s1`, tree copied from the working tree; `s19_app.__file__` = `<runner>/work/zq-e4-8-impl-s1/tree/s19_app/__init__.py`.
Command: `env -i … PYTHONPATH=. python -B run_s1.py <scratch>` (script `s19-relevo8-work/s1/run_s1.py`, not in the repo). Full output below (trimmed: the EX-T1.4096 line's value text, 4,096 `A`).

## Examples (held / did not hold)

| Example | Output | Result |
|---|---|---|
| EX-W1 widths 96/118/200 | `(2,16,0,14,12,0,41,10)`, `(2,18,9,18,13,7,34,16)`, `(2,24,10,44,20,8,64,22)` | held |
| header W118 / W96 | starts `[2,20,29,47,60,67,101]`; no Kind, no Unit at 96 | held |
| short numbers | `-40 150 65.3 655k 4.29G` | held |
| EX-D1/D2/D3/D3b current | `1 IDLE`, `143.5`, `174 (0xAE)`, `1 (0x01)` | held |
| definition lines (D1, D2, D3), enum detail, bit strip | text equal to the graph (`... default "UNKNOWN_STATE"`, `↔ choose · enter stage`, `bit 15…0 0001101011100111   word 1A E7 → 1A E7`) | held |
| EX-P1 preview, Δ, ruler | `Encoded(0x800020, 00 33)`, `25.5`; Δ `-118.0 (-62.1%)` / `-118.0 staged`; ● on cell 19, ◆ on cell 8 | held |
| EX-P1 tail 120 / 100 | exact strings of the graph | held |
| EX-D4 tail and ruler | contains `▲ DISPLAY_0001: 175 is outside …`; `▶` on the right end | held |
| EX-P3 / P4 / P7 | `✗ DISPLAY_0001: 'abc' is not a number`; tail length 100 ending `…`; Δ `✗ refused` | held |
| EX-P2 / P5 / P6 | `2 RUN`, Δ `1 → 2`, `(●) 2 RUN`; `+81`, strip `1A E7 → 1F F7`; `10 chars`, `3/42 chars · NUL-padded  enter stage ↓` | held |
| EX-O1 overlay | MASK_BIT `0` over the staged word → `1F F6`; `KeyError` on a missing byte; `len`, `iter` | held |
| EX-R6 | no image → `Refusal A2L-DEF-BYTES`, `--` | held |
| EX-R9 / R9b | `24 values`, staged True, tail `edit VALUE objects in the Inspector tab`, fill `""`; `--` | held |
| EX-R10 | `5 … 5` / `9 … 1`, Δ `-118.0` both | held |
| EX-R11 | `... RL_U16 · 0x00800020 · 2 B` | held |
| EX-W3 | Parameter cell `温度温度温度温度…` (17 cells) | held (the Unit cell was not asserted by cell in this run) |
| plain / name_echo / clip | `A�[2J`, `%�`, `A[/x]B`, 257 chars, `ASAM.C.ASCII.UBYT…` | held |
| EX-K4 / EX-K6 row_window | `(22,1) (22,1) (21,1) (0,3) (2,3) (3,2) (10,7)` | held |
| EX-V1 / K5 / T1 | `"Hello ASAM"`, 3 rows, fill `Hello ASAM`, label `text =`; widened spans 65/4096/4097/1 MiB → 6 detail lines, cut `… 1 / 4032 / 4033 / 1048512 more B`, editor at ≤ 4,096 only, 1 MiB value `1048576 B`, staged True after **42 image lookups** | held |

Not run: the 200-row timing (EX-C1, EX-T3 medians) — it belongs to the sheet's `show_page` (group S2) and the testers; `delta`/`limits` for enum rows beyond the examples; Inc 9 keys.

## Deviations and notes

1. **`submit` is lazy** (orchestrator ruling on impl-s2 F-1): `_submit_stage` imports `StagingSheet` inside the function body; the module has no toolkit import. (`import s19_app.tui` itself loads textual through the package `__init__`, so "no textual in `sys.modules`" cannot be asserted for any `tui` module.)
2. **Module size**: 917 lines, over the 300-line guide; the graph pins one file for group S1 (D-5 A). A split (cells and ruler / detail lines / kind table) is possible without an interface change. No function over 40 lines except the class `StagedOverlay` (48).
3. `SheetRow` carries `is_staged` plus `image` and `overlay` (the sources it was built over; `compare=False`). The detail and the tail read the span's bytes from them at paint time, so `build_row` does no byte read beyond the decode and the fallback staged pass (this keeps EX-T3's "42 image lookups").
4. `_DATATYPE_FORMATS` is copied from `a2l_parameter_picker` (that module imports the toolkit; a pure module cannot).
5. Coverage choices where the text is silent: Δ for a row with a refused current value is empty; the idle tail (no preview) is `<unit>  (<lower> … <upper>)` for scalars and empty for text; the enum ruler's bounds are the table's raw values; a `row_line` `pending` equal to a text row's base text is not pending (the sheet passes `""` for unset). Definition line with a mask and a LINEAR method follows the literal substitution (`phys = 0.5*(word & 0x0FF0) >> 4`).
6. Added optional parameters: `clip(text, width, clean=False)`, `row_line(..., state=None)`, `detail_lines(..., state=None, room=None)`.
7. `StagedOverlay.written_in(start, end)` is an extra public method (the fallback's staged pass reads it).

## Findings (requirement vs code)

None against the requirements. Open point for E3/E5: R-PE-DEF.40 does not say what the tail shows before any text is typed (the idle tail above).
