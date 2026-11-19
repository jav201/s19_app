# T3a — GAP rows: MAC and A2L log lines, report determinism (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: `TA2b-X-rulings.tsv` KEEP-NEWREQ group GAP (rows 9, 10, 42, 49); orchestrator decision P-173 "T3 write the GAP rows" (DF-02).

## Files
- By hand: `REQUIREMENTS.md`, `tests/test_tui_mac.py`, `tests/test_tui_a2l.py` (one assert each, made exact).
- By `apply_recite.py` (`../in/T3a-map.tsv`, 4 ADD rows): docstrings of `tests/test_tui_mac.py::test_parse_mac_file_emits_summary_log`, `tests/test_tui_a2l.py::test_parse_a2l_file_emits_stage_logs`, `tests/test_diff_report_service.py::test_generation_is_deterministic_fixed_clock`, `tests/test_flow_report_service.py::test_tc001u_composition_is_deterministic`.
- No product file.

## Rows to write (copy each line verbatim; insert it directly after its anchor line)
- Row 1, after the line starting `| R-MAC-011 |` (S2.6, :1544).
- Rows 2 and 3 (in this order), after the line starting `| R-A2L-READ.70 |` (S2.1, :1276).
- Row 4, after the line starting `| R-CMP-004.15 |` (S14.7, :8025).
- Row 5, after the line starting `| R-FLOW-RPT.12 |` (S15.10, :8399).
```text
| R-MAC-012 | When | When the system has read a MAC file, the system shall write the INFO log line `MAC parse summary: path=<path> rows=<n> parse_ok=<k> diagnostics=<d> valid_addresses=<a>`. |
| R-A2L-READ.71 | When | When the system has built the sections of an A2L file, the system shall write the INFO log line `A2L section tree built: path=<path> lines=<n> root_sections=<s> errors=<e>`. |
| R-A2L-READ.72 | When | When the system has parsed an A2L file, the system shall write the INFO log line `A2L parse stages: path=<path> total_seconds=<t> tag_extract_seconds=<x> tags=<n> measurement=<m> characteristic=<c> errors=<e>`. |
| R-CMP-004.16 | When | When the system writes the diff report of the same compare twice with the same clock reading, the system shall write the same Markdown text both times. |
| R-FLOW-RPT.15 | When | When the system composes the flow report of the same run state twice at the same instant, the system shall produce the same report text both times. |
```
Ids checked free at 2a8ab75f (`git grep` over the whole tree, also in `r_..._` spelling): 0 hits each.

## Assert edits (exact; before the script runs)
- `tests/test_tui_mac.py` and `tests/test_tui_a2l.py`: insert `import re` as a new line directly above `from pathlib import Path` (line 7 in both).
- `tests/test_tui_mac.py:22` — replace `    assert any("MAC parse summary:" in message for message in caplog.messages)` with:
```python
    summary = re.compile(
        r"MAC parse summary: path=.+ rows=2 parse_ok=\d+ diagnostics=\d+ valid_addresses=\d+"
    )
    assert any(summary.fullmatch(message) for message in caplog.messages), caplog.messages
```
- `tests/test_tui_a2l.py:177-178` — replace the two `assert any(... in message ...)` lines with:
```python
    tree_line = re.compile(r"A2L section tree built: path=.+ lines=\d+ root_sections=\d+ errors=\d+")
    stages_line = re.compile(
        r"A2L parse stages: path=.+ total_seconds=\d+\.\d{3} tag_extract_seconds=\d+\.\d{3}"
        r" tags=\d+ measurement=\d+ characteristic=\d+ errors=\d+"
    )
    assert any(tree_line.fullmatch(message) for message in caplog.messages), caplog.messages
    assert any(stages_line.fullmatch(message) for message in caplog.messages), caplog.messages
```
Why: the rows fix the whole line (canon rule E5); the old asserts read only the prefix, so a renamed field could not turn them RED.

## Steps (append to `../REPORT.md` after each)
1. Header; tool regression (`test_apply_recite.py`, 19 passed); `--collect-only -q tests` -> N0; reverse_trace before.
2. Rows 1-5 into `REQUIREMENTS.md`; lint (`bad: 0`).
3. Assert edits; run the 2 log nodes -> GREEN.
4. Script dry run, then `--apply` -> `ADD rows: 4 (applied=4, already=0)`.
5. **NC-tool (once):** on `cp -a` of the tree as it was before step 4, run the repo's own `.dev-flow/2026-11-05-batch-103/fix-round/ta/apply_recite.py --apply` with the same map -> it must exit 3 naming `tests/test_flow_report_service.py` ("does not compile"); write nothing. Paste the line. (It proves the units2 fix matters.)
6. Negative controls, one per row (each in its own copy, only the named node):
   - R-MAC-012: `s19_app/tui/mac.py:156` `rows=%d` -> `records=%d` -> `test_parse_mac_file_emits_summary_log` RED.
   - R-A2L-READ.71: `s19_app/tui/a2l.py:1065` `lines=%d` -> `line_count=%d` -> `test_parse_a2l_file_emits_stage_logs` RED (first assert).
   - R-A2L-READ.72: `s19_app/tui/a2l.py:4069` ` tags=%d` -> ` tag_count=%d` -> same node RED (second assert).
   - R-CMP-004.16: `s19_app/tui/services/diff_report_service.py:1805` -> `    clock = _default_now` -> `test_generation_is_deterministic_fixed_clock` RED (the `- Generated (UTC): <isoformat>` line of :1039 differs).
   - R-FLOW-RPT.15: `s19_app/tui/services/flow_report_service.py:427` -> `            f"- **Generated:** {datetime.now().isoformat()}",` -> `test_tc001u_composition_is_deterministic` RED.
7. After: the 4 nodes GREEN; `--collect-only` = N0; reverse_trace after: `X 264`, `U 2`, and none of the 4 tests in class X or U. End per TA2-common.

## For the checker
Laws (six files) on the unit tree: no new RED vs the 2a8ab75f transcript. Planted control: a second `shall` in R-MAC-012 on a copy -> `test_canon_rows_hold_the_obligation_word_once` RED naming it. Diff: only the 5 row lines, 2 imports, 2 assert blocks and 4 `Traces:` lines.
