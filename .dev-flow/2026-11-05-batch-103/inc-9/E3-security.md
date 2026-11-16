# Inc 9 — E3 code-free design review: security

Batch `2026-11-05-batch-103`, increment 9. Branch `b103-inc9`, records HEAD `16593dba`, product tree = `a95d0ea9`. Reviewer: agent K (Opus 5.5), the single E3 reviewer (DF-03), security lens, one pass, independent of the E1/E2 author. Scope, reads and the Inc 8 final records are as listed in `E3-architect.md`. Probe: §Evidence below (`<runner>`, scratch `~/work/zq-e3-9/`, HOME basename `<runner-home>`, `-B -I`, `< /dev/null`, `timeout 300`, `uptime` beside each run; deleted after the run).

## Verdict: FAIL

4 MAJOR, 2 MEDIUM, 2 MINOR, 1 INFO.

**What holds:**
- The operator-text path: the op input is Inc 8's `OsClipboardInput(max_length=4096)`; markup is off (R-PE-BENCH.90); control characters are replaced (.91); echoes are capped (.92); the op line is cut (.93).
- The record write: the whole record over the staged overlay (.70, .71), with partial overlaps refused (.81).
- I-2's handling of malformed layouts and axes (§INFO).

**What fails is Inc 9's own arithmetic and job model:**
- Non-finite values (an erased FLOAT32 cell decodes to NaN) and non-finite operands crash the paint or the apply, as the probe shows.
- The grid geometry divides by zero at small widths, as the probe shows.
- Uncancellable worker threads pile up, one per selection change, about 190 MiB each for a 1,048,576-element object.

## Findings

| Id | Sev | Tag | About (file:line) | Defect | Fix |
|---|---|---|---|---|---|
| E3S-01 | MAJOR | design-gap | CTX *cell look* `t = (v − lo)/(hi − lo)`, step `round(t × 11)`; *chart look*; *array row cells* level `1 + round(t × 7)` (`01-requirements.md:50-58`, `:98-103`); nodes `summary_strip`, `grid_canvas`, `chart_canvas`, `legend_line`, `apply_tool` (`graph-inc9.md:277-391`); I-2 R-A2L-DEF.39 (a non-finite value shows `nan`, `inf`, `-inf`; `REQUIREMENTS.md:1204`) | **A NaN or infinite element crashes the bench's paint.** I-2 decodes an erased FLOAT32 cell (`FF FF FF FF`, the erased-flash pattern) as `Decoded(nan, 'nan')`, with no refusal (probe `NAN.decode`). Python's `min`/`max` over such values depend on order (`nan nan` with NaN first, probe `LOHI.*`), and `round(nan × 11)` raises `ValueError` (probe `RAMP.nan`). With an `inf` element, `t` becomes `inf/inf` = NaN, so the same error follows (probe `RAMP.inf`). The paint runs on the UI thread, so the app stops on a file the operator did not write. The tools likewise turn a NaN cell into a NaN result. CTX defines `t`, `lo` and `hi` only for finite values, and R-PE-BENCH.64 covers only refused elements. | Make CTX non-finite-safe. `lo` and `hi` are taken over the finite shown values only (none → `t = 0`, the lo = hi form). A non-finite cell gets no ramp step: its value text (`nan`, `inf`) is shown plainly, and the chart draws no bar but a `?` on the base line. The strip and the legend skip it. Widen R-PE-BENCH.64 to "a cell with no value **or a value that is not finite**", with the same status. Add cases: a FLOAT32 VAL_BLK `3F800000 FFFFFFFF 40400000` (values `1`, `nan`, `3`) → the grid, strip, chart and legend paint without an exception; +Δ 1 over (1,) → the no-value status. Negative control: compute `lo` over every value → `ValueError` RED. |
| E3S-02 | MAJOR | design-gap | CTX *operand* grammar "digits … an optional exponent" with no bound (`01-requirements.md:73-75`); *result*, *result text* "15 significant digits, then rounded half away from zero" (`:76-87`); R-PE-BENCH.62 (`:205`); nodes `parse_operand`, `apply_tool`, `result_text` (`graph-inc9.md:269-299`); the pilot's oracle `Decimal(…).quantize` (`evidence-e1/pilot_inc9.py:62-70`) | **A finite-looking operand gives an infinite result, and the result text is undefined for it.** `1e999` and 400 × `9` both match the grammar and convert to `inf` (probe `OPERAND.*`). Every +Δ or ×% result is then `inf`, and so is ×% on a large FLOAT64 cell (`1.7e308 × 2`, probe `RESULT.mul`). The pilot's result-text rule raises `decimal.InvalidOperation` on `inf` (probe `RESULT_TEXT.inf`). An E4 implementer copying it gets an unhandled exception on the UI thread when Enter is pressed in the op input. The grammar accepts the operand, so R-PE-BENCH.62 does not fire. | Bound both ends. R-PE-BENCH.62: "If the operand of +Δ or ×% is not a number text **or its number is not finite**, …" (same status). New row R-PE-BENCH.67 (If): "If a tool's result for a cell is not finite, then the system shall show the status `Patch Editor: <tool label> gives a value that is not finite for <element name echo>.` and keep the bench edit." Cases: `1e999`, 400 × `9`, ×% `100` on a FLOAT64 cell holding `1.7e308`. Negative control: drop the finite check → `InvalidOperation` RED. |
| E3S-03 | MAJOR | design-gap | R-PE-BENCH.20 (a decode per selection), .22 (the result is discarded, the job is not stopped), .66 (a preview encode per apply) (`01-requirements.md:152-154`, `:209`); `_run_job` "a thread worker (textual, thread=True)" (`graph-inc9.md:573-580`); R-PE-BENCH.26 "retained after gc" (`:158`); I-2 cost ≈ 11 s and ≈ 200 MiB per 1,048,576 elements (`../inc-3/codewire/graph-inc3.md:158`, [B1]) | **Bench jobs are not bounded in number, so memory is not bounded.** A Textual thread worker cannot be interrupted, and I-2's `decode_values` does not poll for cancellation. A generation change only drops the result after the decode has run to the end. Key repeat over a page of large rows therefore starts one full decode per row passed, and repeated Enter in the op input starts one full preview encode (a decode inside `encode_values`) per press. All of them run at once. Probe: 4 concurrent decodes of 262,144 elements peak at +173 MiB against +47 MiB for one (`DEC.*`, ×3.7). At 1,048,576 elements that is ≈ 190 MiB per job ([B1]). R-PE-BENCH.26 measures only what is retained, so it cannot see this. | One bench worker at a time. Add a row (U): "The system shall run at most one bench decode or encode at a time; a request made while one runs replaces any request still waiting." In the graph, `_run_job` keeps a single waiting slot: the running job finishes and its result is dropped if stale, then the newest waiting request runs. The summary decodes (≤ 4,096 elements, D-4 A) queue behind the selected row's job. Add an AT measuring memory, not timing (HT-08 safe): a page of 20 LARGE rows, 20 × `down` at key repeat → peak RSS above the idle sheet ≤ 64 MiB + one decode's peak (≈ 256 MiB at [B1]'s 216 B per element). Negative control: one worker per selection → peak ≈ 20 × 190 MiB RED. |
| E3S-04 | MEDIUM | design-gap | E1-rulings §5.1 threads note "each job takes a snapshot of the overlay's entries and a load/document generation" (`E1-rulings.md:134`); R-PE-BENCH.78 (the document changes during the encode) (`01-requirements.md:223`); the image the workers read = the source view (`app/patch.py:1001-1034`) = `ChangeService.source_image_view` → the live dict itself, or `_SourceOverlayMap` over the live dict **and the live journal** (`services/change_service.py:1885-1928`); Apply / save-back write the dict and swap the journal in place (`:1846`, `:2364-2366`); I-8.2 stage seam `_refuse_if_busy()` first (`../inc-8/codewire/graph-inc8.md:51-53`) | **The worker's image is not a snapshot, and the stage's guards are checked only at the start of an ≈ 11 s encode.** An Apply or Save-back during a decode or a record-stage encode writes `mem_map[address]` and replaces the journal on the UI thread while the worker reads the same objects. The record's unchanged cells can then come from a half-applied view. That is stale bits in the bytes the stage writes, for addresses inside the span that no entry covers. An Apply changes the image, not the document, so R-PE-BENCH.78's document generation does not drop that result. A session action that starts during the encode (a project load, Write file) is not re-checked before `_record_stage_done` writes, against R-PE-110. | Use one sheet generation, bumped by every `ArrayBenchSheet.set_document`. Inc 8 calls it for every document change and every image push (`refresh_entries`, `set_image_mem_map`, `graph-inc8.md:653-669`), and Apply ends with that push. Every job carries it, and `_job_done` / `_record_stage_done` drop a result from an older generation. Widen R-PE-BENCH.78's condition and status to "the change document or the image changed while <name> was encoding — stage it again." `_record_stage_done` calls `_refuse_if_busy()` again before the write (the busy line; document and bench edit unchanged). Cases: an Apply during a held record-stage encode → the changed status, document unchanged; a session action started during a held encode → the busy line. |
| E3S-05 | MAJOR | design-gap | CTX *grid geometry* `nc = min(nx, ⌊(W − 6)/6⌋)`, `cw = max(5, min(20, ⌊(W − 6)/nc⌋ − 1))`, rows shown `⌊room/2⌋` or `room` (`01-requirements.md:45-49`); *chart look* `h = max(4, min(16, room − 4))` (`:55`); `window_for` "the least move … that keeps the cursor inside the shown rows" (`graph-inc9.md:241-249`); Inc 8's room = visible − 1 can be 0 or −1 (`graph-inc8.md:83-85`) | **The geometry divides by zero at small widths and has no answer for zero shown rows.** At content widths W 6 … 11, `nc = 0` and `cw` raises `ZeroDivisionError`. Below 6, `nc` is negative (probe `GEOM.*`). A resize passes through these widths, and the paint runs on the UI thread. With room ≤ 3 the chart's 4 rows exceed the room (probe `CHART.*`), and with 0 rows shown, `window_for`'s "least move" has no solution, so a loop on it never ends. R-PE-BENCH.5 tests 80, 118 and 220 columns only. | Clamp in CTX: `nc = max(1, min(nx, ⌊(W − 6)/6⌋))`; rows shown and columns shown ≥ 1; `h = max(1, min(16, room − 4))`. `bench_detail` cuts its lines to `room`, and with `room < 1` paints nothing. `window_for` with fewer than 1 row shown returns the cursor's own row. Add a case to R-PE-BENCH.5: W 10 and W 0, room 0 and 1, for MAP_DEF_0001 and LARGE → no exception and every line ≤ W. Negative control: the unclamped `nc` → `ZeroDivisionError` RED. |
| E3S-06 | MEDIUM | design-gap | `bytes_line(definition, image_record, preview, width)`: who builds `image_record` is unstated (`graph-inc9.md:407-417`); *cell look* lo/hi "the least and greatest shown values of the object" (`01-requirements.md:50-51`); `axis_labels` returns every point's label (`graph-inc9.md:370-379`); Inc 8's fallback `staged` = one pass over the document's entry bytes inside the span, on every `set_document` (`graph-inc8.md:125`, `:343`) | **The design leaves O(element count) work in every paint of a large object, and no budget row covers it.** For LARGE with an edit, each key press repaints the bench, which re-reads the record over the overlay to diff it. One read+diff of 1 MiB from a plain dict took 0.105 s at load 2.5 (probe `BYTES.*`, indicative only, HT-08); a Python `Mapping.__getitem__` overlay is several times slower. The same paint re-merges 1,048,576 shown values for lo/hi and builds a label per axis point. After a 1 MiB record stage, Inc 8's `staged` rule walks the 1 MiB entry on every `set_document`. R-PE-BENCH.20 and .82 bound the key only *while* a job runs. | Do the whole-object work once, in the job. `_job_done` stores in `BenchState` the diff runs (offset, old, new) of the preview, the finite lo/hi of the shown values, and the strip. An apply updates lo/hi incrementally from the edit (cells only). `bytes_line` formats stored runs. `axis_labels` and the canvases take the window. Add a budget row: "LARGE with a previewed 4,096-cell edit: a `right` key press is handled within 0.5 s" (AT, quiet host, `uptime` recorded). Ask the orchestrator to check Inc 8's `staged` cost on a 1 MiB entry (a 1 MiB record is Inc 9's normal output). |
| E3S-07 | MINOR | design-gap | R-PE-BENCH.70, .71 (`01-requirements.md:215-216`); I-2 accepts masked arrays (R-A2L-DEF.81; `graph-inc3.md:454`, `:471`) and encodes each element over "the image under the record so far" (`:835`); `Encoded.data` = the whole record (`:146`) | **Masked arrays and the span contract have no case.** The record stage writes every byte of a masked VAL_BLK. The design keeps the bits outside the mask only because I-2 reads them over the staged overlay, and no Inc 9 case shows it. Nothing in `stage_values` checks that the `Encoded` it hands to I-8.2 is exactly the definition's span. | Add a robustness case (the EX-O3 analog of Inc 8): a UWORD VAL_BLK `MATRIX_DIM 2` with `BIT_MASK 0x0FF0`, a raw equal-span entry, Apply then Remove, then a bench Set on (0,) and a record stage → the bits outside the mask equal the source view's (negative control: the live map → the applied bits return). In the UI-thread stage (E3A-03's `stage_record`), refuse when `encoded.address != definition.address` or `len(encoded.data) != definition.byte_length`, with status `Patch Editor: <name echo> encoded outside its span — nothing staged.` and a mutant case. |
| E3S-08 | MINOR | impl | A2 / A3 nodes (`graph-inc9.md:604-622`); Inc 8's A3 "logs nothing of the formula text (E3S-09)" (`graph-inc8.md:752`) | The record-stage handler, the apply handler and the workers have no logging rule. An operand or edit text in the log would carry calibration values into a file the operator may share. | State in A2, A3, `on_array_bench_sheet_bench_apply_requested` and `_run_job`: "logs nothing of the operand, the edit or the values; at most the object name echo and the job kind." Add a case with `caplog`: an apply and a stage of operand `12345` → `12345` is in no log record. |
| E3S-09 | INFO | — | the brief's remaining security list | **Checked and holding.** See the list below the table. | — |

E3S-09, the items checked and holding:
1. **Operator text.** The op input is Inc 8's formula input: `OsClipboardInput(max_length=4096)`, and a paste over the cap leaves the text unchanged (R-PE-DEF.42, Inc 8 E3S-06). Markup is off for every element text, label, name, unit, message and notice (R-PE-BENCH.90), and the bar's name is set as `Text` (Inc 8 E3S-07). Controls become U+FFFD (.91). Names, element names and operands are echoed at 256 characters (.92), and I-2's own messages are capped by R-A2L-DEF.151. The op line is cut (.93), and so is the bytes line (.39).
2. **Malformed A2L.**
   - A partial axis count is refused (R-A2L-DEF.116.2 / .117.2), so the point count equals the dimension.
   - An axis with no points gives `points None`, shown as index labels (R-PE-BENCH.33).
   - FIX points never outnumber the element count, which R-A2L-DEF.7.2 bounds at 1,048,576.
   - I-2 refuses an unreadable layout before decode.
   Inc 9's own geometry and arithmetic are the gaps (E3S-01, E3S-02, E3S-05).
3. **No write outside the span.** The record is one entry (D-8 A). An equal span replaces it, no intersection appends it, and a partial overlap is refused (.81, I-8.2). The encode runs over the staged overlay of the source view (.71, Inc 8 E3S-01).
4. **No path or private data in the visible texts.** Every bench text is an A2L word, a value or a fixed template; none names a file or a host.

## Questions the records route to E3

- **"Inc 9 takes operator text (the operand, through Inc 8's formula input)"** (`E1-rulings.md:130`). Bounded and plain (E3S-09), but not bounded to finite numbers (E3S-02).
- **"Threads: … a result is applied on the UI thread only if both generations still match"** (`E1-rulings.md:134`). It drops stale results, but it bounds neither the number of running jobs (E3S-03) nor what the image is (E3S-04). And I-9.2 as pinned writes from the worker (`E3-architect.md` E3A-03).
- **"Memory: … the peak during one I-2 decode of 1,048,576 elements is still ≈ 200 MiB"** (`E1-rulings.md:132`). True per job. The open part is how many jobs run at once (E3S-03).

## Evidence (probe on `<runner>`, pasted; host paths redacted to `~`)

Scripts: `probe_e3_9.py` and `probe_nan.py`, written by this reviewer, run from a `git archive a95d0ea9 s19_app tests/support tests/__init__.py tools/synth` copy in `~/work/zq-e3-9/clone`. The env was isolated per HT-02 (`env -i`, HOME `…/home/<runner-home>`, `PYTHONDONTWRITEBYTECODE=1`), with `-B -I`, `timeout 300` and `< /dev/null`. Timings are indicative only (HT-08), so no verdict rests on them. Memory deltas are `ru_maxrss` per process.

```text
 15:21:49 up 1 day, 10 min,  4 users,  load average: 2.48, 1.45, 1.23      (16 cores)
GEOM.W0 = nc -1, cw 5
GEOM.W5 = nc -1, cw 5
GEOM.W6 = ZeroDivisionError(integer division or modulo by zero)
GEOM.W8 = ZeroDivisionError(integer division or modulo by zero)
GEOM.W11 = ZeroDivisionError(integer division or modulo by zero)
GEOM.W12 = nc 1, cw 5
GEOM.W76 = nc 11, cw 5
GEOM.W114 = nc 16, cw 5
CHART.room0 = h 4 (lines > room: True)
CHART.room3 = h 4 (lines > room: True)
CHART.room8 = h 4 (lines > room: False)
s19_app.__file__ = ~/work/zq-e3-9/clone/s19_app/__init__.py
DEC.refusal = None element_count = 262144
DEC.n262144.threads1 = values [262144], maxrss before 77 MiB, peak 124 MiB, delta 47 MiB, wall 5.44 s
DEC.n262144.threads4 = values [262144, 262144, 262144, 262144], maxrss before 77 MiB, peak 250 MiB, delta 173 MiB, wall 25.46 s
BYTES.n1048576 = 16384 differing bytes, one read+diff 0.105 s (indicative, HT-08)
 15:22:22 up 1 day, 11 min,  4 users,  load average: 3.52, 1.83, 1.36
OPERAND.1e999 = inf
OPERAND.400x9 = inf
RESULT.add = inf inf
RESULT_TEXT.inf = InvalidOperation
RESULT.mul = inf
FLOAT32.ffffffff = nan
LOHI.nan_first = nan nan
LOHI.nan_middle = 1.0 3.0
RAMP.nan = ValueError cannot convert float NaN to integer
T.inf = 0.0 0
RAMP.inf = ValueError cannot convert float NaN to integer
 15:26:27 up 1 day, 15 min,  6 users,  load average: 4.57, 3.40, 2.13
NAN.describe.refusal = None kind array shape (3,)
NAN.decode = [(1.0, '1', 'Decoded'), (nan, 'nan', 'Decoded'), (3.0, '3', 'Decoded')]
exit=0 (every run)
```

The `GEOM`, `CHART`, `RAMP`, `LOHI`, `OPERAND`, `RESULT` lines evaluate the CTX-PE-BENCH formulas as written, and the pilot's result-text rule, in plain Python. They are not product code, because no Inc 9 code exists. `NAN.decode` and `DEC.*` run I-2 from the product tree. The scripts and transcript lived in the orchestrator's work folder and on `<runner>`, and were deleted after this record was written (PF-04). The pasted lines above are the evidence.

## Checks not run, and why

- **No Textual run.** No Inc 8 or Inc 9 widget exists. The crash paths are shown on the CTX formulas and on I-2's real decode, not in a painted widget.
- **No measurement of the concurrent peak at 1,048,576 elements.** It was measured at 262,144 elements and scaled by [B1]'s per-element cost, which kept the probe under the shared host's limits.
- **No timing decided.** `BYTES.*` is indicative only (HT-08, load 2.5–4.6).
- **No check of Inc 8's `staged` rule cost on a 1 MiB entry.** That is Inc 8's node; it is routed to the orchestrator in E3S-06.
