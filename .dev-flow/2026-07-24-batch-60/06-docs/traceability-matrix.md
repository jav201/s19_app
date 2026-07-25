# Traceability matrix · batch-60 (FB-P1b flow-run report generation)

## User stories → coverage
| US | Statement (abbrev) | Shipped surface | AT | Status |
|----|--------------------|-----------------|----|--------|
| US-001 | A REPORT-bearing flow writes a durable markdown record of the run | `run_flow` REPORT branch → `write_flow_report` | AT-001, AT-005, AT-006, AT-007, AT-009 | Covered |
| US-002 | The flow report appears in the existing reports list/viewer | `report_service.list_project_reports` / `ReportViewerScreen` | AT-002 | Covered |
| US-003 | File-derived text in the report is inert | `_md_safe` + `_hardened_markdown_parser` | AT-003, AT-011 | Covered |

## Operator decisions → discriminating test
| Decision | Test that fails if the opposite were implemented |
|---|---|
| D-1 explicit trigger (only with a REPORT block) | AT-006 — a flow without one writes nothing |
| D-2 positional (state up to the block) | AT-005 — a later WRITE-OUT must NOT appear; AT-007 prefix assert |
| D-3 reuse `<ts>-report.md` (shipped viewer sees it) | AT-002 — `list_project_reports` includes it; name matches `REPORT_FILENAME_REGEX` |
| D-4 N report blocks, each independent | AT-007 — two files, different content, #2 strictly longer, #1 a prefix |
| D-5 the written path shows in the panel ledger | AT-004 — the REPORT node's own summary names the file |
| D-6 an aborted run still writes | AT-009 — report exists, labelled FAILED, later blocks still skip |

## LLR → test
| LLR | Behaviour | Test |
|-----|-----------|------|
| LLR-001.1 | composer structure / sections in order / determinism | `test_tc001u_sections_present_in_order`, `..._one_ledger_row_per_block_derived`, `..._composition_is_deterministic` |
| LLR-001.2 (AMD-4) | status rollup keyed on the EXPLICIT `aborted` flag; 9 abort sites → FAILED, 2 non-aborting → ISSUES | `test_tc013a_record_error_shaped_abort_is_failed`, `test_tc013b_non_aborting_error_is_issues_not_failed`, `test_tc013_clean_and_issues_labels` |
| LLR-001.3 (AMD-1/2/5) | `_md_safe` against gfm-like+linkify; backticks removed; token-stream oracle | `test_tc004_hostile_payload_injects_no_live_structure` (11 per-branch payloads), `..._ledger_row_column_count_preserved...`, `test_tc006_benign_text_stays_readable`, `test_tc014_*` |
| LLR-001.1 (AMD-7) | byte budget + cell cap boundary pair + findings cap | `test_tc015_cell_truncation_boundary_pair`, `..._findings_cap_suppresses...`, `..._large_run_stays_within_the_viewer_cap` |
| LLR-001.1 (AMD-8) | written paths render relative, never absolute | `test_tc016_written_paths_render_relative_not_absolute` |
| LLR-002.1 | write under `reports/`, `_report_filename` reuse, no overwrite | AT-002, AT-007 |
| LLR-003.1 | wire: compose from state so far; degrade-not-abort | AT-001, AT-005, AT-008 |
| LLR-003.2 | the ledger surfaces the written path | AT-004 |
| LLR-003.3 (AMD-3) | REPORT exempt from the abort skip guard; does not clear `aborted` | AT-009 |
| — (AMD-9) | footprint reads the LOCAL threaded ranges; pre-CRC asymmetry | AT-010, `test_footprint_omits_before_crc_until_a_crc_has_run`, `test_footprint_none_when_no_image` |
| — (AMD-11) | the report path is not an image output | AT-007 (written-files section assert) |
| — (AMD-13) | render-side hardened parser | AT-011 (behaviour + construction pin) |

**Coverage: 3/3 US, 6/6 operator decisions, 11 ATs, 41 new tests.**

## Increment ownership (C-21, remapped per AMD-14)
| Increment | Commit | Owns |
|---|---|---|
| Inc-1 composer | `e0521cb` | TC-001u, TC-004, TC-006, TC-013a/b, TC-014, TC-015, TC-016 + footprint/unicode/empty cases |
| Inc-2 wire | `3c2f80f` | AT-001, AT-002, AT-005, AT-006, AT-007, AT-008, AT-009, AT-010 |
| Inc-3 UI + parser | `e8ef802` | AT-004, AT-011 |
