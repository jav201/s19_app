# Unit FA-TICK2u — the S19 reader reads the file once; the test gate holds with GC disabled [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`7f2286db`** (FA-TICKac and FA-TICKb integrated) (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`. **Append to `../REPORT.md` after EACH row** (the last two units timed out with no report: a row not in REPORT.md does not exist).

## Fixed diagnosis (FA-TICK2 report, measured on the quiet reference host; facts re-grepped, HT-13)
- **(a)** `mac_view.py:620` `_compute_mac_view_payload` builds `S19File(str(primary_file.path))` on the load worker to get the overlap set. `S19File._load` (`s19_app/core.py:289`, loop at :312-313: `with open(self.path, 'r') as f:` / `for line_number, line in enumerate(f, 1):`) reads the text file line by line: 185 raw `readinto` calls on the 1.5 MB small image. During that 0.19–0.20 s parse the UI thread does not get the GIL back; its 50 ms tick fires 0.14–0.20 s late (R-A2L-REFRESH.050 window). Reading the whole text once and iterating it in memory removed the stall (0.14–0.23 s → 0.007 s, N=3) with identical records.
  - `_load`'s `except FileNotFoundError: … raise` and `except Exception: … raise` re-raise, so a decode error still aborts the constructor as today; nothing else changes.
- **(b)** `TimedGate` (`tests/test_alp_inc3_load_responsiveness.py`, class at :171, `_wrap` at :183) holds the worker at producer entry for 0.20 s *before* calling the real `_prepare_a2l_attach_snapshot`, whose first statement is `gc.disable()` (D-13, `file_load.py` :1065). So a main-thread gen2 collection (0.10–0.11 s) can land inside the window during the hold. In production nothing runs between the producer's entry and its `gc.disable()`: this is a test-instrument artifact. Ruling (orchestrator): fix it in the gate, not in the product; the window start (`gate_started`) does not move.

## Requirement rows
- R-A2L-REFRESH.050 ("While the system performs post-parse preparation for an image+A2L or project load, the system shall fire each due 50 ms UI timer tick no more than 100 ms late.").
- LLR-154.1 (S19 line semantics: trailing records after the terminator counted, never parsed; damaged data lines tallied).

## Files you may edit
`s19_app/core.py`, `tests/test_alp_inc3_load_responsiveness.py`, new file `tests/test_alp_s19_read_once.py`.

## Rows
| row | change | negative control (scratch copy) → RED |
|---|---|---|
| 1 | `core.py`: `import io` (top imports). In `_load`, inside the same `with open(self.path, 'r') as f:`, iterate `enumerate(io.StringIO(f.read()), 1)` instead of `enumerate(f, 1)`. One comment line: read the text once, then split in memory, so the worker does not hand the GIL back and forth per read while the UI waits (R-A2L-REFRESH.050, FA-TICK2). Nothing else in `_load` changes. | revert to `enumerate(f, 1)` → row 2 RED |
| 2 | New file `tests/test_alp_s19_read_once.py`, `test_r_a2l_refresh_050_s19_reader_reads_the_file_once`: write a ≥ 1 MB S19 with `make_large_s19` (conftest; or the `_small_image` recipe of `tests/test_alp_inc3_load_responsiveness.py`); monkeypatch `s19_app.core.open` (`monkeypatch.setattr(core, "open", counting_open, raising=False)`) with a wrapper whose binary layer counts raw read calls (e.g. open with `buffering=0`-style `io.FileIO` subclass counting `read`/`readinto`/`readall`, wrapped in `io.TextIOWrapper(io.BufferedReader(...))`); assert ≤ 2 raw reads, and records equal (type, address, data, valid per record) to `S19File` built without the patch. Module docstring: why (FA-TICK2, the line-by-line read starved the UI tick on the image route). | row 1 control (today: ~185 raw reads on 1.5 MB) |
| 3 | Same file, `test_llr_154_1_s19_reader_line_semantics_unchanged`: a small S19 text with CRLF lines, one lone-CR line ending, blank lines, a damaged `S1` line, an S5 count, records after an S9 terminator. Pin the expected `records` (types/addresses), `load_errors` (`line_number`, `segment`, error prefix) and the trailing/terminator notices to the values that the **base tree** produces: build them once by running the same input through `S19File` in a scratch base clone (`git clone -q -b alp-e4r ~/work/zq-fa/fa.bundle ../scratch/base`), paste them as literals, and say so in REPORT.md. | revert row 1 in a scratch copy: this test must still be GREEN (it is a semantics pin, not a RED oracle); record that |
| 4 | `TimedGate._wrap`: on the first call, call `gc.disable()` immediately before `gate.gate_started = time.perf_counter()`; if `gate.release.wait(120)` times out, call `gc.enable()` before raising. Comment (≤ 3 lines): the real producer's first statement is `gc.disable()` (D-13); the gate holds at producer entry, so it holds with the collector disabled as production does; the window start is unchanged. Do not change anything else in the gate. | remove the `gc.disable()` → in a scratch copy run `test_r_a2l_refresh_050_small_routes_same_oracle[project-pair]` 1× (indicative; it may or may not go RED on rtx; record what happens) |
| 5 | No code. Run `test_r_a2l_refresh_050_small_routes_same_oracle[image]`, `[project-pair]`, `[a2l-only]` once each (`-n 0`), and record the three QC-TM lines as "indicative, not decided (shared host)". | — |

## Nodes you may run (`timeout 300`)
- `-n 0`: rows 2–3 nodes; the row 4/5 small-route params; `tests/test_alp_inc3_load_responsiveness.py -k "small or gate"` collection (`--collect-only -q`);
- `-n 4`: `tests/test_core_srecord_validation.py tests/test_b99_truncation.py tests/test_b99_s0.py tests/test_validation_engine.py` (S19 reader regression; FA-TICK2 saw 0 failures there);
- `-n 4`: `tests/test_synth_release_case.py` (3 failures are inherited: `test_a2l_zero_issues`, `test_addresses_inside_image`, `test_a2l_issues_reported`; any other failure is yours to report);
- `-n 0`: `tests/test_suite_hygiene.py -k "040 or 041 or 002"`.
- Never run a `slow` node.
