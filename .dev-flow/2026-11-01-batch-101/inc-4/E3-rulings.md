# Inc 4 — E3 rulings (orchestrator, 2026-11-05)

Inputs: E3-architect.md (PASS-WITH-NOTES, A-1 HIGH, A-2…A-4 MAJOR, A-5…A-9 MINOR), E3-security.md (PASS-WITH-NOTES, S4-1, S4-2 LOW, S4-3…S4-9 INFO). Both verdicts pass, so there is no round 2: every item below is folded into the records now (targeted edits) and binds E4 as an addendum.

| Id | Ruling |
|---|---|
| A-1 (HIGH) | D-1 stands. The integration drops `tests/test_checks_engine.py::test_headless_project_run` from TC-023's `nodes` in `AT-TC-REGISTRY.jsonl` (the other 10 stay) and adds `tests/test_id_registry.py` to the E4 targeted run. The registry edit is forwarded to the requirements/test-case session. Slice §3 names it. |
| A-2 (MAJOR) | The name index is built lazily: on the first entry with a string symbol, at most once per read; a document with no symbol entries builds none. Graph node and R-CHG-SYM.13's control updated; new case arm: no-symbol document → 0 index builds (call counter). |
| A-3 (MAJOR) + S4-3, S4-9 | R-CHG-SYM.13 is sized on the repo's large A2L (case_06, 220 040 tags) and 1 000 symbol entries. Primary check: index built once per read (call counter). Wall-clock is the ceiling, measured on the LAN Linux host at E4, bound = measured × ≥ 2 (projection 1.0 s), through `report_margin` and the `serial_timing` lane. No Windows timing requirement. |
| A-4 (MAJOR) | The project report run (`app.py:6566`, `execute_project_variants`) is a second surface of R-CHG-SYM.11: E1 rulings list it and a case R-CHG-SYM.11/3 covers it (report with a symbol change document writes `<variant>-patched.s19` and reports the applied entry). |
| A-5 | R-TUI-058.9/3 gains the negative arm: with an A2L loaded, a symbol containing the I-1 text gives no R-TUI-058.9 line. |
| A-6 | Fix the "Base" column of R-CHG-SYM.9: `load`, `load_text` and the io readers already take the A2L parameter; only `edit_entry_json` lacks it. |
| A-7 | E4 times the whole-document Edit JSON confirm (two reads) on the LAN host; no design change unless it exceeds the bound. |
| A-8 | D-1 leftovers: the `test_no_textual_in_static_import_graph` docstring is updated (text only), and the records close BACKLOG T-03 as superseded by D9-7 (the `declarado` ruling still governs T-04) and mark CODE-CHANGES D9-7 done at integration (forwarded). |
| A-9 | Interface I-3 for Inc 5: Inc 5 uses `entry.symbol` when set, looks up by address only for address-only entries, and adds no third index. Recorded in the graph's interface list. |
| S4-1 (LOW) | Definition note on "the project's A2L file": a regular file; a link in the project folder is not refused today. BACKLOG row routed with Inc 9 (S8-1/S8-2): `validate_project_files` refuses a link or reparse point (`lstat`) with a test. No code change in Inc 4. |
| S4-2 (LOW) | R-CHG-SYM.11/2 gains an arm that unloads the session A2L before Execute scope: the run still applies (project A2L, not session A2L). Optional converse arm on R-CHG-SYM.12/1. |
| S4-4…S4-8 | Recorded as INFO in the rulings; S4-6 binds E4: any new paint of `ChangeEntry.symbol` goes through the existing escapers; S4-8 forwarded to Inc 14 docs. |

E4 runs: all tests and timings on the LAN Linux host (operator rule).
