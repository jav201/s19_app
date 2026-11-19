# T4b — guard tests that verify product modules: issue-list tag source, verify-on-save refusal (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: `TA2b-X-rulings.tsv` KEEP-NEWREQ DESIGN rows 52-54. TA2b filed them as design guards; read at 2a8ab75f they verify what shipped product functions do (`s19_app/tui/services/validation_service.py:298-301` chooses the tag list the A2L checks read; `s19_app/tui/changes/verify.py:112-116` refuses a format it cannot re-read), so they get rows in their own modules (S3, S8) instead of S0 process rows (design decision, DF-02).

## Files
- By hand: `REQUIREMENTS.md` only.
- By `apply_recite.py` (`../in/T4b-map.tsv`, 3 ADD rows): `tests/test_tui_services.py` (2 tests), `tests/test_verify_on_save.py::test_unsupported_file_type_raises`. Docstrings only.
- No product file.

## Rows to write (copy each line verbatim; insert it directly after its anchor line)
- Rows 1 and 2 (in this order), after the line starting `| R-VAL-018 |` (S3.1, :2075).
- Row 3, after the line starting `| R-HEX-VERIFY-001.6 |` (S8.8, :4447).
```text
| R-VAL-055 | When | When the system builds the issue list for an A2L that has an enriched tag list, the system shall check the tags of that enriched list. |
| R-VAL-056 | If | If the system builds the issue list for an A2L that has no enriched tag list, then the system shall check the A2L's parsed tags. |
| R-HEX-VERIFY-001.7 | If | If the system is asked to verify a save-back file whose format is neither S19 nor Intel HEX, then the system shall raise an error instead of marking the save. |
```
Ids free at 2a8ab75f. Map: `R-VAL-055` <- `test_build_validation_report_keeps_explicit_empty_enriched_tags` (an empty enriched list is still the enriched list: the boundary case); `R-VAL-056` <- `test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none`; `R-HEX-VERIFY-001.7` <- `test_unsupported_file_type_raises`.

## Steps (append to `../REPORT.md` after each)
1. Header; tool regression (19 passed); N0; reverse_trace before.
2. Rows 1-3 into `REQUIREMENTS.md`; lint (`bad: 0`).
3. Script dry run, then `--apply` -> `ADD rows: 3 (applied=3, already=0)`.
4. Run the 3 nodes -> GREEN.
5. Negative controls (own copy each):
   - R-VAL-055: `validation_service.py:301` -> `        tags_for_validation = a2l_enriched_tags or (a2l_data or {}).get("tags", [])` -> `test_build_validation_report_keeps_explicit_empty_enriched_tags` RED.
   - R-VAL-056: `validation_service.py:299` -> `        tags_for_validation = []` -> `test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none` RED.
   - R-HEX-VERIFY-001.7: `verify.py:116` -> `    return {}` -> `test_unsupported_file_type_raises` RED (`DID NOT RAISE`).
6. After: N0 unchanged; reverse_trace after: `X 265`, `U 2`; none of the 3 tests in class X. End per TA2-common.

## For the checker
Laws on the unit tree: no new RED. Planted control: R-VAL-056 sentence without `then` on a copy -> `test_canon_rows_open_with_their_form` RED naming it. Diff: 3 row lines and 3 `Traces:` lines only.
