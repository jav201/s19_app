# Inc 9b E4 — roster (P9b)

Base for every E4 worker: `b103-inc9b` at the P9b roster commit (merged base `e4485817` + records). Implementers work in `C:\Users\<user>\Github\s19_app-b103-inc9b`; testers in `C:\Users\<user>\Github\s19_app-b103-inc9b-tests` (branch `b103-inc9b-tests`, same commit). Groups as `E1-slice.md` §1, confirmed by P9b; the design fixes the pilots forced are in `E4-pilots.md` (F-9b-4 … F-9b-6) and in the graph. Cases: `02-test-cases.md` (Group column; counted by script over the table: W 21, S 5, AT 10 = 36).

| Worker | Group | Files (source, or the test file it owns) | Requirement rows | Cases |
|---|---|---|---|---|
| C9b-W (implementer) | W | `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py`; `s19_app/tui/definition_bench_view.py` | R-PE-BENCH.94 … .97, .100 … .105 | nodes `busy_job`, `ArrayBenchSheet.on_mount`, `._enqueue`, `._job_done`, `.record_done`, `._busy_tick`, `busy_title` |
| C9b-S (implementer) | S | `s19_app/tui/app/patch.py`; `s19_app/tui/screens_directionb/patch_editor/panel.py` | R-PE-BENCH.98, .99, .101 (write refusals), .106; .100/3 | nodes `PatchMixin.on_array_bench_sheet_record_stage_requested`, `._stage_bench_record`, `._refresh_patch_history_view`, `._patch_refresh_steps`, `._patch_refresh_tail`, `._run_refresh_steps`, `._patch_document_token`, `._note_image_bytes_written`, `PatchEditorPanel.refresh_entries`, `.refresh_sheet_document` |
| T9b-W (tester) | W | `tests/test_b103_inc9b_w.py` | .94, .95, .96, .97, .100, .101, .102, .103, .104, .105 | 94/4, 95/1, 95/2, 96/1, 96/2, 96/3, 97/2, 100/1, 100/2, 101/1, 101/6, 102/1, 102/2, 103/1, 103/2, 104/1, 104/2, 105/1, 105/2, 105/3, 105/4 (21) |
| T9b-S (tester) | S | `tests/test_b103_inc9b_s.py` | .98, .101, .106 | 98/2, 101/3, 101/4, 106/1, 106/2 (5) |
| T9b-AT (tester, black box: keys and the painted screen) | AT | `tests/test_b103_inc9b_at.py` | .94, .97, .98, .99, .100, .101 | 94/1, 94/2, 94/3, 97/1, 97/3, 98/1, 99/1, 100/3, 101/2, 101/5 (10; timing cases T decided on the quiet host only, HT-08) |

Lines for these workers (from P9b):
- Room B is the window's content width − 4: 66 / 106 / 190 at 80 / 118 / 220 columns (measured, `E4-pilots.md` P3); never 76.
- The busy colour is `#f5c26b` = `Style.parse(definition_bench_view.EDIT).color`; `EDIT` itself is `"bold #f5c26b"`, not a colour.
- Read the painted border from the compositor (`tests/b97_probes.painted_rows` / `painted_style`), never from `styles` alone: a cleared inline rule shows the stylesheet value in `styles` while the screen still paints amber until a refresh (P2).
- `call_after_refresh` and `set_timer(0, …)` are not step gaps (P1); a tester's negative control for R-PE-BENCH.98 / .99 can be "steps chained by `call_after_refresh`" (the key then waits for the chain's end).
- Timing base for `E1-slice.md` §6 is the merge `e4485817`, not `09001bbc` (E3-8b-08). `trace_check.py` runs with `--base e4485817`; with `09001bbc` it lists Inc 8b's files as SLICE gaps.
