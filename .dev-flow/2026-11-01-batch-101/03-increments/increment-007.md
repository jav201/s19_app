# Increment 007 — Inc 7 · R-CMP-003/004/005, R-BEFORE-AFTER-REPORT-001 · diff and before/after reports: uncapped hex windows, atomic writes, escaping, provenance

Flow: dev-flow-v3-beta. Records live in `.dev-flow/2026-11-01-batch-101/inc-7/`: `01-requirements.md` (US-BAR-1, US-HEXWIN-1, US-MDESC-1; 20 canon rows), `02-test-cases.md` (61 cases), `E1-rulings.md`, `E1-slice.md`, `E3-*.md`, `E4-*.md`, `E5-*.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc7.md`.

Models per stage (from `steps.log`): Opus — E1 to E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration, the E5 code and security reviews, the coverage audit and the E5 corrective pass; Sonnet — the E4 implementer and the independent tester, the E5 mutant run, and this record (Kimi weekly quota exhausted).

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `007` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-CMP-003.2 · R-CMP-004.1, .5, .8, .9 (9.1, 9.2), .14, .15 · R-CMP-005.16, .17 · R-BEFORE-AFTER-REPORT-001.11, .21, .22, .24, .32, .33, .34, .35 |
| Acceptance | black-box through the shipped keys: key `b` and the Diff screen Report control (key `7`) cases of `02-test-cases.md`; AT-053b, AT-054b, AT-B94-18 · white-box R-CMP-005.16/1 … /6 and the census guards · unit nodes of `tests/test_diff_report_service.py` |
| Agent | `software-dev` (Sonnet) |
| Date | `2026-11-05` |

---

## 1 · What changed

A diff report and a before/after report are now complete, safe to open and whole-or-nothing. The Markdown file writes every hex window whole (no 512-row cap) and the HTML file agrees with it. Every file-derived name, path, symbol, linkage and refusal message is written once as report-safe text, so no live markup or link survives in either file (the flow-A2B arm no longer pre-escapes, so nothing is escaped twice). Each report file is written to `<name>.<16 random hex>.part` by an exclusive create and moved into place, so a failed write leaves no file and no `.part`, a stale `.part` is never touched, and a link planted at a guessable name is never followed (security finding S5-1). If the HTML twin fails or is refused, the Markdown file written a moment earlier is removed. The before/after report names itself (`# Before/after report`, `<title>`, `<h1>`) and carries the loaded A2L and MAC (key `b` gathers them on the UI thread); a plain diff report keeps `# Diff report`. The no-project reason reads `(key 7)`.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

`git diff --stat main...HEAD` (85 files, +9,648 / −129) plus the uncommitted E5 close (the `e5d-*` transcripts, the RA-1/RA-2 test and cases, the two re-review sections, `04-validation.md`, this packet).

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/diff_report_service.py` | source | US-HEXWIN-1 · US-MDESC-1 · US-BAR-1 | R-CMP-004.1/.5/.8/.9/.14/.15, R-CMP-005.16: `_md_text`/`_md_path` escaping at every Markdown sink, `_strip_ctl` = shared visible text, uncapped `_window_rows`, title from provenance, `_write_report` (exclusive random `.part` + `os.replace`) |
| `s19_app/tui/services/before_after_service.py` | source | US-BAR-1 | R-BEFORE-AFTER-REPORT-001.11/.24/.35, R-CMP-005.17: composer forwards A2L and MAC, `(key 7)` reason text, `_remove_orphan_markdown` on an HTML failure or refusal |
| `s19_app/tui/app.py` | source | US-BAR-1 · US-HEXWIN-1 | R-CMP-003.2, R-BEFORE-AFTER-REPORT-001.24/.35, R-CMP-005.17: key `b` gathers A2L/MAC on the UI thread (`None` when no MAC), A↔B worker removes the orphan Markdown file, OSError logged by type |
| `s19_app/tui/services/flow_execution_service.py` | source | US-MDESC-1 | R-CMP-004.9.1/9: the flow-A2B arm passes raw label and path (no pre-escape), so the report escapes once |
| `tests/test_diff_report_service.py` | test | US-HEXWIN-1 · US-MDESC-1 | About 30 new and re-pinned nodes (R-CMP-004.*, R-CMP-005.16/.17, C-1 link and staging-name nodes; the close adds `…_16_4_stale_part_file_survives_failed_write` and `…_16_6_staging_name_is_random_per_write`) |
| `tests/test_before_after_report.py` | test | US-BAR-1 | Composer and key `b` nodes for R-BEFORE-AFTER-REPORT-001.11/.21/.22/.24/.32-.35, failed-write and orphan cases, loaded-MAC AT |
| `tests/test_report_field_census.py` | test | US-MDESC-1 | Mode-B-in-a-cell AST guard extended to `diff_report_service.py`, plus its planted counterfactual |
| `tests/test_b99_staging.py` | test | US-MDESC-1 | SR-1: LLR-155.3 allow-list gains `_write_report`, `_remove_orphan_markdown`, `_drop_orphan_md`, each with its reason |
| `tests/test_tui_report_filter_surface.py` | test | US-MDESC-1 · US-BAR-1 | AT-053b/054a/056a re-pinned: Markdown filter name escaped, HTML literal; title lines `Before/after report` |
| `tests/test_changes_symbol_entries.py` | test | US-MDESC-1 | TC-717 refusal line re-pinned to the report-safe `c2\.json` |
| `tests/test_flow_a2b_b94.py` | test | US-MDESC-1 | TB94-24 Image A line re-pinned to `patch\.out` |
| `tests/test_tui_flow_builder_b94.py` | test | US-MDESC-1 | AT-B94-18: whole flow Image A line pinned, no double backslash (E5 C-5) |
| `tests/goldens/batch35/at054b-before-after-report.md` | fixture | US-BAR-1 · US-MDESC-1 | Title `# Before/after report` and the two escaped image labels |
| `tests/goldens/batch35/at054b-before-after-report.html` | fixture | US-BAR-1 | `<title>` and `<h1>` read `Before/after report` |
| `.dev-flow/2026-11-01-batch-101/inc-7/01-requirements.md` | doc |  | EARS requirements for the 20 canon rows in scope (R-CMP-003.2, R-CMP-004.1/.5/.8/.9/.14/.15, R-CMP-005.16/.17, R-BEFORE-AFTER-REPORT-001.11/.21/.22/.24/.32-.35) and the three stories |
| `.dev-flow/2026-11-01-batch-101/inc-7/02-test-cases.md` | doc |  | 61 ISO 29119-3 cases; E5 corrective and close edits: 8 + 1 new rows, node labels, Result cells, mutant table M1 to M29 |
| `.dev-flow/2026-11-01-batch-101/inc-7/E1-rulings.md` | doc |  | E1 rulings D-1 … D-8, orchestrator rulings, observations OBS-7-1 … OBS-7-6 |
| `.dev-flow/2026-11-01-batch-101/inc-7/E1-slice.md` | doc |  | E1 implementation slice: touched functions, nodes to re-pin (section 4) |
| `.dev-flow/2026-11-01-batch-101/inc-7/E3-architect.md` | doc |  | E3 design review, architect lens, round 1: PASS-WITH-NOTES, 3 MAJOR (F-E3-1 … 3) |
| `.dev-flow/2026-11-01-batch-101/inc-7/E3-security.md` | doc |  | E3 design security review, round 1: PASS-WITH-NOTES, 3 MAJOR (S-1 … S-3) |
| `.dev-flow/2026-11-01-batch-101/inc-7/E3-rulings.md` | doc |  | E3 round 1 rulings, how each MAJOR was applied, E4 addenda A-1 … A-8 |
| `.dev-flow/2026-11-01-batch-101/inc-7/E3-r2.md` | doc |  | E3 round 2 re-review of the six MAJORs: PASS-WITH-NOTES, 6 of 6 closed |
| `.dev-flow/2026-11-01-batch-101/inc-7/E4-impl-notes.md` | doc |  | E4 implementer notes (4 source files, deviations, smoke run) |
| `.dev-flow/2026-11-01-batch-101/inc-7/E4-tester-notes.md` | doc |  | Independent tester notes: files, case mapping, ambiguities, RED on base |
| `.dev-flow/2026-11-01-batch-101/inc-7/E4-integration-notes.md` | doc |  | E4 integration: GREEN verdict, seams SR-1 and SR-2, A-6 numbers, counts per transcript |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-mutants.md` | doc |  | E5 mutant table: run 1 23 of 24 (M22 survived), corrective re-run 28 of 28 |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-code-review.md` | doc |  | E5 independent code review: PASS-WITH-NOTES, CR-1 … CR-6, A-6 ruling |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, S5-1 … S5-4; re-review: S5-1 closed, S5-5, S5-6 |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-coverage-audit.md` | doc |  | E5 coverage audit 8 of 52 changed; re-audit of the 19 corrective cases; RA-1, RA-2 (closed in the E5 close, 02-test-cases.md) |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-rulings.md` | doc |  | Orchestrator E5 rulings C-1 … C-8 and the routed backlog rows |
| `.dev-flow/2026-11-01-batch-101/inc-7/E5-corrective-notes.md` | doc |  | E5 corrective pass notes: what C-1 … C-8 changed |
| `.dev-flow/2026-11-01-batch-101/inc-7/codewire/graph-inc7.md` | doc |  | Code-Wire graph G1 … G4 and interfaces I-1 … I-6 (design, no code) |
| `.dev-flow/2026-11-01-batch-101/inc-7/steps.log` | doc |  | Stage log with UTC stamps and model per stage |
| `.dev-flow/2026-11-01-batch-101/inc-7/04-validation.md` | doc |  | This increment's validation record (new, uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-007.md` | doc |  | This packet (new, uncommitted) |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | Six batch-101 Inc 7 rows at the KF-101 block (S5-3 + CR-1, S5-2, CR-2 … CR-5, OBS-E5-1; the close adds OBS-7-1/2/5/6 with the public visible_text alias, and the two known failures) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-case-nodes.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | LAN Linux host: the 66 cited case nodes at the E5 corrective final tree, 66 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-a.txt` | generated | US-MDESC-1 | LAN Linux host: parallel battery (22 files) at the corrective final tree, 603 passed, 1 failed (056e, known) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-b-serial.txt` | generated | US-HEXWIN-1 | LAN Linux host: serial_timing arms, 2 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-c-tc031.txt` | generated | US-HEXWIN-1 | LAN Linux host: TC-031 engine guards, 3 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-d-guards.txt` | generated | US-MDESC-1 | LAN Linux host: guard files (registry, canon, hygiene, census), 119 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-e-before-after.txt` | generated | US-BAR-1 | LAN Linux host: before/after report file, 34 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-windows-c1.txt` | generated | US-MDESC-1 | Windows: the C-1 nodes after the fix, 6 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-green-c1-windows.txt` | generated | US-MDESC-1 | Windows: C-1 GREEN run, 5 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M22.txt` | generated | US-MDESC-1 · US-BAR-1 | LAN Linux host: M22 re-run, _md_cell stops escaping the pipe (re-run with the new C-2 node): KILLED by the new node |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M24.txt` | generated | US-MDESC-1 · US-BAR-1 | LAN Linux host: M24 re-run, composer drops mac_records from compare_images: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M25.txt` | generated | US-MDESC-1 · US-BAR-1 | LAN Linux host: M25 re-run, composer drops mac_records from the generator kwargs: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M26.txt` | generated | US-MDESC-1 · US-BAR-1 | LAN Linux host: M26 re-run, the app never forwards the loaded MAC (report_mac_records = None): KILLED by `.35/3` |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M27.txt` | generated | US-MDESC-1 · US-BAR-1 | LAN Linux host: M27 re-run, _write_report back to the fixed <name>.part staging name: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-red-c1-windows.txt` | generated | US-MDESC-1 | Windows: C-1 RED on head 90ea8ae, 2 failed (the planted link was followed) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-final-linux.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | LAN Linux host: final run of 10 files (-n 8, not serial_timing), 327 passed, 1 failed (056e, known) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-green-new-nodes.txt` | generated | US-MDESC-1 | LAN Linux host: the two new nodes plus the two C-1 nodes on the tree, 4 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-tmp-part.txt` | generated | US-MDESC-1 | LAN Linux host: mutant M28 (staging name fixed to <name>.tmp.part), RED: 1 failed, 3 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-unlink-all-part.txt` | generated | US-MDESC-1 | LAN Linux host: mutant M29 (cleanup unlinks every *.part), RED: 1 failed, 1 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/impl-smoke.txt` | generated | US-BAR-1 | E4 implementer smoke run: import ok; 19 failed (the expected re-pinned nodes and 056e), 397 passed, 1 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-01-touched-files.txt` | generated | US-BAR-1 | Windows: the touched test files at 9508239, 204 passed, 1 failed (056e) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02-green-set-single-run-timeout.txt` | generated | US-BAR-1 | Windows: whole GREEN set in one process, killed at 1,800 s (exit 124), no summary |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02a-green-chunk-a.txt` | generated | US-BAR-1 | Windows: chunk A (11 files), 336 passed, 1 skipped, 4 failed (F-1, F-2 seams) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02b-green-chunk-b.txt` | generated | US-BAR-1 | Windows: chunk B (13 files), 439 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02c-green-chunk-c-timeout.txt` | generated | US-BAR-1 | Windows: chunk C in one process, killed at 1,800 s (exit 124), no summary |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02d-green-per-file-rerun.txt` | generated | US-BAR-1 | Windows: chunk C file by file plus the F-1/F-2 files, 561 passed, 2 failed (056e, b78_03; both pre-existing) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-03-base-preexisting.txt` | generated | US-BAR-1 | Windows: base 9f9f6af, the 056e failure reproduced (pre-existing) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-04-final-case-nodes.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: final integration run, 547 passed, 1 skipped, 1 failed (056e) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-05-a6-worst-case.txt` | generated | US-HEXWIN-1 | Windows: A-6 worst case, two 4 MiB images fully changed (5,157 MiB peak, 1.13 GiB HTML) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/int-06-a8-no-mutation-grep.txt` | generated | US-BAR-1 | A-8 grep: 0 in-place mutations of MAC/A2L data; worker-join check |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M1.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M1 transcript, _window_rows back to render_hex_view(..., max_rows=MAX_HEX_ROWS): KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M10.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M10 transcript, HTML sinks (from _html_header down) left on a C0-only strip: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M11.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M11 transcript, _image_line path through _md_text: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M12.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M12 transcript, flow_execution_service keeps its pre-escape (md_safe / md_code): KILLED by `test_at_b94_18` only |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M13.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M13 transcript, _md_text used for the image label in _html_header: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M14.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M14 transcript, flow_change_census_complete compares through _md_cell while emission …: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M15.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M15 transcript, refusal message left on _md_cell: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M16.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M16 transcript, _write_report writes the final name directly: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M17a.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M17a transcript, composer keeps the Markdown file after an HTML failure/refusal: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M17b.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M17b transcript, A-to-B worker _drop_orphan_md made a no-op: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M18.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M18 transcript, reason left at (screen 7): KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M19.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M19 transcript, _window_rows writes chr(b) for every b >= 0x20: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M2.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M2 transcript, _window_rows via render_hex_view(..., max_rows=len(row_bases)): KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M20.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M20 transcript, symbol membership by extent (an A2L tag's length expands to every cov…: KILLED by 004_5_1 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M21.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M21 transcript, HTML linkage symbol written from the raw value (one file keeps the co…: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M22.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M22 transcript, _md_cell stops escaping the pipe: SURVIVED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M22b.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M22 transcript, _md_cell stops escaping the pipe, both whole test files: SURVIVED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M23.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M23 transcript, _md_path returns the raw path (backtick not replaced): KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M3.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M3 transcript, title constant Diff report in both generators: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M4.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M4 transcript, title Before/after report for every report: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M5.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M5 transcript, title chosen by linkage_entries is not None: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M6.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M6 transcript, composer drops a2l_data from compare_images: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M7.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M7 transcript, app forwards loaded.mac_records unconditionally: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M8.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M8 transcript, composer drops a2l_records from the generator kwargs: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M9.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Windows: M9 transcript, Runs Symbols cell written raw: KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-7/red-01-tester-base.txt` | generated | US-BAR-1 · US-HEXWIN-1 · US-MDESC-1 | Tester RED on base 9f9f6af: 64 nodes, 54 failed, 10 passed |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 8 test files + 2 goldens (uncapped) |
| Doc files | 22 (outside the count) |
| Generated | 55 evidence transcripts |

- ⚠ **At exactly 4 source files: this increment could not be cut smaller.** The two generators and their shared writer are one file; the composer and the app are where the loaded A2L/MAC reach the report and where the orphan Markdown file is removed; `flow_execution_service.py` must stop pre-escaping or the report would escape twice. A fifth file (a public alias of `_normalise` in `markdown_safety`) was avoided by a documented private import (E3 round 2, A-1); the alias is a backlog row.

---

## 3 · How to test

```bash
# LAN Linux host (never run pytest on the Windows PC for this record); inside a clean worktree of the base plus this diff
env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m pytest -q -p no:cacheprovider -n 8 -m "not serial_timing" \
  tests/test_diff_report_service.py tests/test_before_after_report.py tests/test_report_field_census.py \
  tests/test_tui_report_filter_surface.py tests/test_changes_symbol_entries.py tests/test_flow_a2b_b94.py \
  tests/test_tui_flow_builder_b94.py tests/test_b99_staging.py tests/test_suite_hygiene.py tests/test_id_registry.py
# the close's new nodes
python -m pytest -q tests/test_diff_report_service.py -k "16_4_stale_part_file_survives or 16_6_staging_name"
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `_md_text`, `_md_path`, `_run_symbol_names`, `_window_rows` (differential 0x00 … 0xFF against `render_hex_view`), `_write_report` nodes in `tests/test_diff_report_service.py` | part of 327 passed, 1 failed (known 056e), `e5d-final-linux.txt` (LAN Linux host) |
| **A · white-box** `TC` ↔ LLR | `core` · `full` | R-CMP-005.16/1 … /6, R-CMP-005.17/1 … /3, census guards in `tests/test_report_field_census.py`, LLR-155.3 guard in `tests/test_b99_staging.py` | 66 of 66 cited case nodes passed at the corrective final tree (`e5c-final-case-nodes.txt`); the 2 close nodes passed (`e5d-green-new-nodes.txt`) |
| **B · black-box** `AT` ↔ story | `core` · `full` | key `b` with A2L and MAC loaded, key `7` and the Diff screen Report control with a failing write, key `b` with a failing HTML generator, AT-053b, AT-054b, AT-B94-18 | passed in the same runs (status text asserted exactly, painted lines read) |

The only failure in every final run is `test_at_056e_a2b_diff_report_byte_identical_despite_selection`, which fails the same way on base `9f9f6af` (`int-03-base-preexisting.txt`). Details: `.dev-flow/2026-11-01-batch-101/inc-7/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | `diff_report_service.py:342` — the staging name `f"{target.name}.{secrets.token_hex(8)}.part"` replaced by `f"{target.name}.tmp.part"` (a fixed name) |
| Instrument | a `sed` substitution by hand on the LAN Linux host, in a detached worktree of base `9f9f6af` plus this diff |
| Where it ran | LAN Linux host, a scratch worktree (removed afterwards); the author ran it |
| Transcript | `.dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-tmp-part.txt` — `AssertionError: ['…diff-report.md.tmp.part', '…diff-report.md.tmp.part']` |
| Restore proven by | SHA-256 of `diff_report_service.py` before and after: `8a0f4f4c02dc4b6c4bf6cb21a04b968839625eaa2b94fda39dfeaaec78aebc0b`, identical |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 4 (asserted: `4 passed` in `e5d-green-new-nodes.txt`) |
| Verdict granularity | per node id: only `…_16_6_staging_name_is_random_per_write` failed |
| Arms that stayed GREEN | the other 3 (`…_16_3_stale_part…`, `…_16_4_stale_part_file_survives…`, `…_16_5_planted_link…`) — the gap RA-1 named |

| Field | Value |
|---|---|
| **RED counterfactual** | M28: `{target.name}.{secrets.token_hex(8)}.part` to `{target.name}.tmp.part` at `diff_report_service.py:342` makes the new `…_16_6_staging_name_is_random_per_write` fail; transcript `e5d-red-mutant-tmp-part.txt`; digest `8a0f4f4c…aebc0b` returned. Also M29 (cleanup unlinks every `*.part`) fails the new `…_16_4_stale_part_file_survives_failed_write` (`e5d-red-mutant-unlink-all-part.txt`). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 30 mutants, **30 killed** after the corrective pass and the close. Run 1 (Windows, `mut-M1.txt` … `mut-M23.txt`): 23 of 24, M22 SURVIVED (`_md_cell` without the pipe escape; the node planted its pipe in a cell `_md_text` writes; `mut-M22.txt`, `mut-M22b.txt`). Corrective (LAN Linux): M22 KILLED by the new C-2 node (`e5c-mut-M22.txt`); M24, M25, M26, M27 KILLED (`e5c-mut-M24.txt` … `e5c-mut-M27.txt`). Close: M28, M29 KILLED. Arms that stayed GREEN: M12 (`test_tc_b94_24`), M20 (`test_symbol_annotation_only_intersecting_run`), M22 (old node), M26 (`test_r_cmp_003_2_1`, the no-MAC arm, correct). Restore: `git diff --quiet` clean after each of the 24, `cmp` clean for 5 of 5 (corrective), digest above (close). Mutant ids M1 … M29 are listed in `02-test-cases.md`. |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the tester's new nodes | the base tree `9f9f6af` (no fix) | 54 failed, 10 passed (`red-01-tester-base.txt`) |
| `…_16_5_planted_link_at_part_name_is_not_followed` | head `90ea8ae`, fixed staging name, dangling link planted | 2 failed: the link target was created (`e5c-red-c1-windows.txt`, Windows) |
| `…_16_6_staging_name_is_random_per_write` | mutant M28, fixed name `.tmp.part` | `AssertionError` listing the two equal names (`e5d-red-mutant-tmp-part.txt`) |
| reader-level census 9.1/11 | the same payload parsed unescaped with the same markdown-it configuration | live `html_inline` and `link_open` tokens appear (`E4-integration-notes.md`, section 4) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| before/after report, Markdown and HTML pair | `test_at_054b_no_filter_bkey_report_pair_byte_identical_to…` against the re-pinned goldens `at054b-before-after-report.md` / `.html` | passed (66 of 66, `e5c-final-case-nodes.txt`) |
| the staging file name | the new `…_16_6_…` spies the mode-`"x"` open and fullmatches `<name>.[0-9a-f]{16}.part` on the emitted name | passed on the tree, RED on M28 |
| the report folder after a failed write | `_folder_names(reports) == []` read from disk after the injected half write | passed (`…_16_1`, `…_16_2` nodes) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-05 at the close. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-7/`.

| Evidence artifact | Path — repo-relative, under the home `.dev-flow/2026-11-01-batch-101/evidence/` | SHA-256 |
|---|---|---|
| e5c-final-case-nodes.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-case-nodes.txt | 08a312b773d355da9681e1c42c37a306b5508774e028cf32f0dfacd7c5bf80c1 |
| e5c-final-linux-a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-a.txt | 9d424401529ed6ab99680906682f482cb26824a467f67b49db2b8df62cbf138e |
| e5c-final-linux-b-serial.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-b-serial.txt | f9f3b8f174224a2a1977253622374fc78d4c85cf1d9d3abb73e394128b7d31bb |
| e5c-final-linux-c-tc031.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-c-tc031.txt | 3f934f3a121b9c6d03965478c65b365b341c82cd050a1358d4e813c184839988 |
| e5c-final-linux-d-guards.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-d-guards.txt | 4cfa11a0ed12b8cd55c1c562a9881ffa9450cf7fe1e43a83463cf708eec6caf2 |
| e5c-final-linux-e-before-after.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-linux-e-before-after.txt | 19b6f0c0c7bf2c43f3b1aad952c45494be3ba2d63c8b70928aefbe7ca2fda13e |
| e5c-final-windows-c1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-final-windows-c1.txt | 2722c016c74a148a400972f11e2802ffccca410d189d5d054628fc70699551aa |
| e5c-green-c1-windows.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-green-c1-windows.txt | 974c25932fdddb0d7b6cc6e10275f3bb44d3d1c4dd1438632ae54df19b839138 |
| e5c-mut-M22.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M22.txt | d508d07dd58cbc398768a377e7e9fd19fe19da80cc276cd157600f132be72123 |
| e5c-mut-M24.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M24.txt | 4dcf384d0a4f81ac149b6796bf93d9347495c2f99dab291621cdcf5006ac8b60 |
| e5c-mut-M25.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M25.txt | abfb47e85e92819dd3f1c954f61573f3baa8244f53467784301e39ea78fccbdf |
| e5c-mut-M26.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M26.txt | ab716f9c7c378510b7fcc92bb39fb4171b3276491436c2e79b7113d56dc78df4 |
| e5c-mut-M27.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-mut-M27.txt | 2e18ec6b41e764f0e2c3ff434697659280b327c93cf1598aa6a34b9be8dbe102 |
| e5c-red-c1-windows.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5c-red-c1-windows.txt | bfb848cc6b0c51f6d24ca03f34a5deb93a4817429d3de9efb4dea3bc854d81b5 |
| e5d-final-linux.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-final-linux.txt | 5edb7140ab01d31ba6fbf69a6b410c643099ed6cb95a299ddf2fb5fb9eb8b436 |
| e5d-green-new-nodes.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-green-new-nodes.txt | cdffac79a32715fd28abee727dd9dc88354aa9ce1edccd182e4e4365a65314ab |
| e5d-red-mutant-tmp-part.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-tmp-part.txt | cb34c30da62d93b22b263ffe41a4c10a598b1ab27f3adca039685d5d9d5c3fcd |
| e5d-red-mutant-unlink-all-part.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/e5d-red-mutant-unlink-all-part.txt | 522abd24235e1c33873a596f19763efb5acb59b12fe733550d4fa83855da8920 |
| impl-smoke.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/impl-smoke.txt | 28452f39755e8d41c69bda4f3bc69ec677a20614cfb0be46aba8303cf456a727 |
| int-01-touched-files.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-01-touched-files.txt | cda4cec1a224f2948ae3a221ee8a9bf7754d567538bbb03e56a9e8a556c09157 |
| int-02-green-set-single-run-timeout.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02-green-set-single-run-timeout.txt | 8fa09ccd5476c47e7bfaf747192f5a8bddd68172ee79d4639d4960db8a53deaf |
| int-02a-green-chunk-a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02a-green-chunk-a.txt | 066e2a7860b81f031efe296ae6d086ddce68a3820d21dc109c005f2c31180962 |
| int-02b-green-chunk-b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02b-green-chunk-b.txt | 886c557f509cc1b50b19bb6731b5d37671be807227df28a1aeec65cc7313a5e4 |
| int-02c-green-chunk-c-timeout.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02c-green-chunk-c-timeout.txt | 903ed33a034921c36f0dd772cd9e49c86672eaaf32e7eb4aa4a35923edf83b42 |
| int-02d-green-per-file-rerun.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-02d-green-per-file-rerun.txt | 4a30f9ae62f568e57ac216d9fd524faba280b831db30cc9ff98e3674d8eee73a |
| int-03-base-preexisting.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-03-base-preexisting.txt | 4d1a197720c1b298bad922ada601c4c0b98766010fb9d9fcfb4819c1d809bd44 |
| int-04-final-case-nodes.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-04-final-case-nodes.txt | fee1c80b91b10b26411e60681153187378ee3f4c827a70afc9013ab48e84c8f6 |
| int-05-a6-worst-case.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-05-a6-worst-case.txt | 1a81afe63d5a8fa4c60ec43a51c62e6a1d96b022921ef290b18a5e48cb29b117 |
| int-06-a8-no-mutation-grep.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/int-06-a8-no-mutation-grep.txt | 8608cda6221b3cbb3540c8d3d379f4f1319b5a6b95a333e062928ca265f47bf9 |
| mut-M1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M1.txt | e2ded622b070d4d00128f90632bb2a4bcedbc0c2704541c80d89bdd02bb8634c |
| mut-M10.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M10.txt | a1c98170117b284ac00d466d7459e5524097a9cd11d85e0456c31dd259c8e0dd |
| mut-M11.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M11.txt | 7a33e7e27c1a9511c27a974f9b0830f20187490b1fee9c9fb7bbef59e2baebb2 |
| mut-M12.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M12.txt | 8a3fb597a594d48d723313f676bd7c167de2289ff9deae8cf1215189fd4ea0a2 |
| mut-M13.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M13.txt | 25abe3c23a93d313f46f80f462295fd887a3c5b6fec7b06c964cd00d41f1b67b |
| mut-M14.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M14.txt | 991dbc44ae2b7e25818eef6d48bc152b02b79fe6f2127bc9e5ce9fe94e9d2dee |
| mut-M15.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M15.txt | 9f208106ded96f74c8d4f31a37592a2b07ab8a6c1fe20e941faa8b3a170e9821 |
| mut-M16.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M16.txt | 67f473040405839e926f737bdacb1b3cf89a527130ef81a7a0948f21ec431b86 |
| mut-M17a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M17a.txt | 34e01c97411e55160d66d2ed2c1de284a8fb934fa1ad535f77b78ab6f9ffd486 |
| mut-M17b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M17b.txt | 624660b085066ffb10b4a3a1829d7681eb0535b1b1d9556959e7463aad59cdcd |
| mut-M18.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M18.txt | 9ee30e02ce91d2a09c91972898bf399761e5eba25761227aef2119268ff8d5ad |
| mut-M19.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M19.txt | 0d68dc268cef3a1b928109b9221f36a2105c4a6f3aa75bb1f0a26199faec0338 |
| mut-M2.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M2.txt | b05a9a3bdb2726f6593cd0dff7d23a714b5249f6ffafd3cf618574ea8ab47b67 |
| mut-M20.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M20.txt | 09ac1b7452db2c48dd02c246cb71c9ba087a957db33fb03b75c6c57178027d57 |
| mut-M21.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M21.txt | 1846646d4006819537c06ec07ce06dde1bc6691d6e2f75bc3a299adf98eb1043 |
| mut-M22.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M22.txt | 6140ea501a3e3c5352c52d93d6bb310ca2393cd275de4a84bf29b793ec564021 |
| mut-M22b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M22b.txt | 4e368416c6f91023b9f7bb59f4b0e2b294ce7b5d03027719edd13a7252aa59a0 |
| mut-M23.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M23.txt | 45b860b675c7496726cc95de5627c85d0fe093331e550cd43e88192cfe61eb69 |
| mut-M3.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M3.txt | e45263ab1d132251b25c2903aa40d5f96f4c29add9ac58a132df7628f83c757d |
| mut-M4.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M4.txt | 3ce7ee039623815119a5e41331a2370b89aa81efb28fd47a0cd89585e820d166 |
| mut-M5.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M5.txt | 277deaa917dbb860a52f3f8a01fc77c20468f7064c299955baf6b9974e16b3f6 |
| mut-M6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M6.txt | 43ce51b2c0d17feb445fa1da3cfcc2a9058bfa395087b8d86c3e5ee2bb0dd023 |
| mut-M7.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M7.txt | 54a9dccd285212268b7c539bc72bc65e872bd7c9db7b775f52c6521c387e6422 |
| mut-M8.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M8.txt | 754224086051cfae5d5c41e64d0ae7e6d796e4b669c27c8931c89ef8c19ed6e4 |
| mut-M9.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/mut-M9.txt | 8e1e30793f652529e261e3cf54934da11317710647e83f2e48a6bee49b377ec9 |
| red-01-tester-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-7/red-01-tester-base.txt | 23ba4f6d230e0ecdab63c04bd039c097c450150ef71b0baba1dffbc9f7ea9597 |

| Field | Value |
|---|---|
| **Evidence files** | 55 transcripts, each at the home `artifact_homes.evidence` names and cited with the digest of its stored bytes |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: 0 `.part` files and 0 report files after a failed write; 0 in-place mutations of `mac_records`, `_a2l_enriched_tags`, `current_a2l_data` in `s19_app/` (A-8) |
| If the result is an ABSENCE, what made the search wide enough | the folder listing is read whole (`_folder_names`), and the grep covers every `.py` under `s19_app/` with 5 names and every mutating form (`int-06-a8-no-mutation-grep.txt`) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_cmp_005_16_1_failed_markdown_write_leaves_no_file`, `…_16_2_…`, `test_r_cmp_005_17_1_ab_html_failure_removes_markdown` (asserts `reports/` is a directory before the emptiness check, C-7) |
| Conjunctive criteria: one mutation per conjunct | M16 (final name written directly), M17a/M17b (orphan kept), M27, M28 (fixed name) and M29 (cleanup too wide) each remove one conjunct of R-CMP-005.16/.17 |
| Synthetic instance of the absent case | the failure-injection helper writes half the text then raises; the test asserts the injection was reached (`hit`), so it cannot pass vacuously |
| **Positive control for every probe that returned an ABSENCE** | the A-8 grep lists the rebinding assignments of the same names (non-empty output from the same probe); M16 turns the folder listing non-empty (3 of 3 nodes RED) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "_strip_ctl\|_md_cell\|_write_report" tests/` | the Inc 7 test files, `tests/test_report_field_census.py` and `tests/test_b99_staging.py` (SR-1 allow-list); each passed in the final run |
| B2 file moved on disk | none moved | no readers to find |
| B3 byte-identical golden captures this source | `grep -rl "Diff report" tests/goldens/` | `at054b-before-after-report.md/.html` re-pinned; 054b passes |
| B4 artifact produced here is consumed elsewhere | report folder readers (`list_diff_reports` reads `*.md`) | `*.md.part` is not listed (code review, check 2) |
| A3 interface consumed by another module changed | `compose_before_after_report` and `_start_before_after_worker` signatures | consumed only by `app.py` and the tests; updated in this diff |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 · B2 · B3 · B4 · A3), 0 unexpected hits |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| every negative on a file-derived name asserts both spellings (A-4) | negatives in the report test files | diff read in E4 (E3 round 1, F-E3-2) | 5 sites | 5 | none |
| every Markdown sink of a file-derived value uses `_md_text`/`_md_path` | Markdown sinks of the two generators | sink map of `E3-security.md` and the reader-level census test | 14 sink kinds | 14 | system tokens (linkage Type, Disposition, Applied UTC) stay on `_md_cell` by D-7 |

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, each enumerated before its first site was edited |

### Signed-balance test ledger

Not tracked as a count for this increment: tests were added and re-pinned, none deleted or renamed (`git diff --stat`: the 8 test files only grow or change lines). ✓

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES**, 0 BLOCKER / 0 MAJOR / 1 MINOR (CR-1, A-6, accepted pre-existing, routed) / 5 NIT (CR-2 … CR-6; CR-6 fixed by C-7, the rest routed) — `inc-7/E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES**, 0 HIGH — S5-1 LOW fixed by C-1 and **closed on re-review** (RR-1 … RR-6); S5-5 LOW (staging name not pinned) closed by the close's case R-CMP-005.16/6; S5-2 LOW and S5-3 MEDIUM routed; S5-6 INFO — `inc-7/E5-security.md`. **Design reviews (E3, code-free):** `architect` and `security-reviewer` round 1 PASS-WITH-NOTES (3 MAJOR each), round 2 PASS-WITH-NOTES with 6 of 6 closed — `E3-architect.md`, `E3-security.md`, `E3-r2.md`. **Independent tester (E4):** wrote the tests from the design only; RED on base 54 of 64 — `E4-tester-notes.md`. **Coverage audit by `qa-reviewer` (E5):** 8 of 52 cases changed; re-audit 1 of 19 plus 1 clause (RA-1, RA-2), both written at the close; totals 61 covered, 0 partial, 0 gap — `E5-coverage-audit.md`. **There WAS a re-review (E3 round 2, the E5 security re-review and the coverage re-audit); the close's own edits (RA-1, RA-2) have not been re-read by those reviewers.** |

---

## 5 · Risks

- **Report size and memory (S5-3 + CR-1, MEDIUM, pre-existing):** two 4 MiB images that differ at every byte need about 5.2 GB peak and write a 1.13 GiB HTML file; a larger input can end in `MemoryError`, which surfaces as `Diff report failed: MemoryError` and leaves no file. Not fixed here.
- The flow-A2B report is built on the UI thread (OBS-7-5), so a large input freezes the screen (about 1.3 s per MiB of windowed bytes).
- Between the close of the `.part` file and `os.replace` its name is visible; a local writer with delete rights in `reports/` could swap it for a link (S5-6, INFO, no new capability).
- A same-stem, same-second race between two writers can let one report replace the other (CR-3, NIT; the same race existed with `write_text`).
- The full suite has not run on this branch; the touched files and guards pass (known failure 056e excepted).
- The close's edits (RA-1, RA-2 test and case rows) were proven by two mutants but not re-read by the auditor.

---

## 6 · Pending items / spec deviations

- **S5-3 + CR-1** report size and memory: a new increment (an up-front refusal above an estimated size, then line-by-line writes). BACKLOG-CODE.
- **S5-2** only the LLR-155.3 census limits the callers of `_write_report`. BACKLOG-CODE.
- **CR-2 … CR-5** four NITs (original error lost when `unlink` also fails, same-stem race, shared title helper, raw U+202E in test source). BACKLOG-CODE.
- **OBS-E5-1** `test_tc024_report_trigger_surfaces_paths` flakes on base and head. BACKLOG-CODE.
- **OBS-7-1, OBS-7-2, OBS-7-5 (D16-15), OBS-7-6 and a public `visible_text` alias** of `_normalise` (E3 round 2, condition 3). BACKLOG-CODE (row added at the close).
- **Known failures** `test_at_056e…` and `test_at_b78_03…`, both failing on base. BACKLOG-CODE (row added at the close).
- **Full suite** at the batch end.
- The guide chapter text for the escaped names (US-MDESC-1 raw-text search consequence) goes to the docs increment (Inc 14).
- The uncommitted E5 records and transcripts are to be committed by the orchestrator; nothing here is committed by this record.

---

## 7 · Suggested next task

Run the full suite on the LAN Linux host and commit this branch, then open the increment for S5-3 + CR-1 (the up-front size refusal and line-by-line writes), which also closes OBS-7-4.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 / 4, reason in section 2 |
| 2 | Tests written in this same increment | all | ✓ | 8 test files, 61 cases (`02-test-cases.md`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | section 4, Layer 0 row; differential hex test passed |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | M28, `e5d-red-mutant-tmp-part.txt`, digest returned |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | five probes, section 4 |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | PASS-WITH-NOTES, section 4b |
| 7 | No file from another lane touched | all | ✓ | single lane |
| 8 | Frozen interfaces untouched | all | ✓ | only the composer and worker signatures changed, both consumed inside this diff |
| 9 | Coverage claims verified on disk | all | ✓ | 66 of 66 and 2 of 2 nodes collected and passed (`e5c-final-case-nodes.txt`, `e5d-green-new-nodes.txt`) |
| 10 | Load-bearing emptiness declared | all | ✓ | section 4 |
| 11 | **Mutation verdicts** declared | all | ✓ | 30 of 30, section 4 |
| 12 | **Instrument RED-proof** declared | all | ✓ | 4 instruments, section 4 |
| 13 | **Correction population** declared | all | ✓ | 2 corrections, section 4 |
| 14 | **Emitted-form assertion** declared | all | ✓ | 3 artifacts, section 4 |
| 15 | **Independent review** names somebody | all | ✓ | section 4b |
| 16 | **Evidence files** declared | all | ✓ | 55 transcripts with digests |
