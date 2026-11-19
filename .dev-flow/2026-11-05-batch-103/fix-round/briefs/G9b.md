# Unit G9b — AT-056e: drive the compare to the typed files, then wait for the report worker (finish G9 row 1)
Your tree is a COPY of G9's tree: fix-round tip **2a8ab75f** (FB-common's "HEAD = main 3afebf90" line does not apply) + G9's row-2 edit in `tests/test_b100_project_check.py`, uncommitted. Keep that edit; do not touch that file. Read `../G9-REPORT.md` (G9's report, copied next to this brief) first: its row-1 deviation D1 is the fact base.

## Orchestrator ruling on G9's STOP (2026-11-19, DF-02 / DF-04 a)
- The product follows the canon. R-CMP-006.2: "When the A2B Diff is shown, the system shall select the first entry of each variant list." With a project loaded, both selects therefore start on the first variant (`a`). The BUG B7 same-file refusal (`_diff_sources_identical`, `s19_app/tui/app/checks_diff.py`) is approved product behaviour.
- The test is the defect. `test_at_056e_a2b_diff_report_byte_identical_despite_selection` types `a.s19`/`b.s19` into `#diff_path_a`/`#diff_path_b` but leaves both selects on variant `a`, so the typed paths never reach the compare. Before B7 it compared `a` against `a` and passed vacuously; since B7 the compare is refused and no report is written (`baseline wrote []`).
- Fix to the test's stated intent (compare the two typed files, then Report): before typing the paths, set `#diff_select_a` and `#diff_select_b` to `AbDiffPanel._EXTERNAL_OPTION` (the "external path" entry; `s19_app/tui/screens_directionb/ab_diff.py:149`), then pause. After the Report press, wait for the report worker: a bounded poll (bound stated in a comment, ≤ 60 s) until both `_DIFF_MD_NAME` and `_DIFF_HTML_NAME` exist in the project's report folder (use the same folder `_reports(project_dir)` reads), or `await app.workers.wait_for_complete()` followed by `_flush`. Assertions unchanged. Add one docstring line: `Drives both variant selects to the external-path entry (R-CMP-006.2 selects the first variant; BUG B7 refuses a same-file compare).`
- Also check, after the Compare press, that `#diff_status` does not start with `Compare refused` (assert with a message naming the status), so a future refusal fails with its cause instead of `baseline wrote []`.

Files you may edit: `tests/test_tui_report_filter_surface.py` (this one test only).

## Negative controls (scratch copies `../scratch/nc-<n>`, paste the RED line, delete after)
1. In the scratch copy, make the A2B diff report leak the selection: in the code path that writes the diff report (start from `_start_diff_report_worker`, `s19_app/tui/app/reports.py:1420`; find the writer it calls), append the line `Report filter applied` to the written markdown when a report filter is selected (or apply the selected filter there). The node must go RED on the byte-identity or the `"Report filter applied" not in` assertion. Paste the line.
2. In the scratch copy, remove the two select lines you added → RED with the new `Compare refused` message.

## Nodes (`-n 0`, `timeout 300`)
- `tests/test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection` — run it 3 times after the fix (GREEN 3/3).
- The whole `tests/test_tui_report_filter_surface.py` (`-n 0`, `timeout 600`).
- `tests/test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` once (G9's row stays GREEN).

## Rules repeated
No git writes of any kind (no `checkout --`, no stash, no reset: G9 broke this once). To undo an edit, edit the file back by hand.
