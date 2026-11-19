# F2b — test cases for the rows the fold integrated (DeepSeek v4-pro)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md`. Tree 2a8ab75f. Source: operator ruling P-173 ("integrate the left-out rows … generate their verification and validation test cases"); fold commit b5ca5b72 (F2a/F2a-2); P-181 ("trace_check +34 TEST gaps = rows awaiting F2b").

## Scope (measured on the PC at 2a8ab75f)
The fold added or changed 293 rows with a form cell (`git show b5ca5b72 -- REQUIREMENTS.md`). `trace_check` TEST over them: **20 rows are named by no file under `tests/`** (`../in/f2b-fold-ids.txt` = the 292 that stay rows after row 2 below). The other 272 are named by tests their batches wrote with V&V cases in each increment's `02-test-cases.md`. Disposition of the 20 (+ R-DOC-ARCHIVE.2):
- **16 already verified, the name is missing** -> row 1 (trace only): R-A2L-DEF.153.2; R-B102-BULK-003.1, .003.2, .004.1, .004.2, .005.1, .005.2, .005.3, .006.1, .006.2, .007.1, .007.2 (the split children of rows the tests cite as parents); R-TUI-068.4; R-TST-014, R-TST-032, R-TST-045 (hidden in names like `test_r_tst_043_045_…`).
- **R-DOC-ARCHIVE.2** is not a standing row -> row 2 (retire as increment-local).
- **R-CHKED-001** (changed by F2a-2 for paging) has no test of its every-parameter half -> row 3 (two new tests).
- **R-TUI-062.10.2, R-TUI-062.10.3** -> unit `U-MM`. **R-TST-009** (75-min LAN release gate) -> no node by batch-101 decision D-15 (`.dev-flow/2026-11-01-batch-101/inc-2/02-test-cases.md:24`: "gate transcripts (full); no pytest node"); owed at the next release gate.

## Files
- By hand: `REQUIREMENTS.md` (row 2), `tests/test_b102_parameter_picker.py` (row 3, append only).
- By `apply_recite.py` (`../in/F2b-map.tsv`, 13 ADD rows, 5 files): `tests/test_b103_a2l_definition_arrays_write.py`, `tests/test_b102_bulk_add.py` (7 tests), `tests/test_b102_a2l_refresh.py`, `tests/test_suite_hygiene.py` (3 tests), `tests/test_b97_flow_execution.py`. Docstrings only.
- No product file.

## Row 1 — trace the 16 rows (map)
Which test verifies which child, read at 2a8ab75f (the map's `new_ids`): `test_r_a2l_def_153_1_scalar_values_through_encode_values` asserts the `(1,)` refusal `A2L-DEF-INDEX` (-> .153.2); `test_tc_b102_bulk_03_inclusion_semantics_and_duplicate_controls` (-> 003.1, 003.2, 004.1, 004.2); `…_03_unique_name_counts` ("Gamma\nGamma" with no match -> `not found 1 — first missing: Gamma`: 003.2, 004.1, 005.3); `…_04_summary_with_first_missing` (004.1, 004.2); `…_04_summary_contained_at_80x24` (004.2); `…_05_no_match_arm` (005.1, 005.2); `…_06_hostile_pasted_names_render_literally` (006.1, 006.2); `…_07_close_and_apply_do_not_rebuild_the_ledger` (007.1, 007.2); `test_tc_b102_a2l_04_no_match_filter_names_filter` (`No A2L tags match '<filter>'.` -> R-TUI-068.4); `test_r_tst_013_014_…` (R-TST-013, -014); `test_r_tst_031_032_…` and `test_tc_b97_64_a_new_set_run_restarts_the_dwell` (R-TST-032, the static and the runtime arm, batch-101 `E5-mutants.md:51`); `test_r_tst_043_045_…` (R-TST-043, -045).
Steps: dry run, `--apply` -> `ADD rows: 13 (applied=13, already=0)`. Run the 13 nodes -> GREEN.
Controls: **NC-a** idempotent: rerun `--apply` -> 13 `already`, diff unchanged. **NC-b** intent (R-B102-BULK-005.3, the one child read off an indirect assert): `s19_app/tui/screens.py:1049` `if summary["not_found"]:` -> `if summary["not_found"] and summary["included"]:` -> `test_tc_b102_bulk_03_unique_name_counts` RED.

## Row 2 — R-DOC-ARCHIVE.2 leaves the canon (DF-04)
Why: batch-101 ruled it local to Inc 16, not a standing row (`.dev-flow/2026-11-01-batch-101/inc-16/E1-rulings.md:99`: "R-DOC-ARCHIVE.2 stays local to this increment … a one-off archive move is not a standing property"), and verified it there (`03-increments/increment-016.md:143`, E5 transcripts 4/4 PASS). The hand-over listed it without a decision (`close/FORWARD-requirements-session.md:142`), so the fold copied it in. No test cites it.
Edit: delete the line starting `| R-DOC-ARCHIVE.2 |` (S0.10, :502); then directly after the line starting `| R-DOC-ARCHIVE.4 |` insert one empty line and this line (the canon's form for a retired row, as `R-TUI-029.5 … is retired` in S5.6):
```text
R-DOC-ARCHIVE.2 (keep in the architecture archive each line that batch-101 Inc 16 removed from §10 and §11 of `docs/architecture.md`) is retired: batch-101 kept it local to that increment (`.dev-flow/2026-11-01-batch-101/inc-16/E1-rulings.md:99`, D-1) and verified it there (`.dev-flow/2026-11-01-batch-101/03-increments/increment-016.md:143`); the fix-round fold had copied it in from the hand-over.
```
Control: **NC-c** a one-row map with `new_ids` = `R-DOC-ARCHIVE.2` -> `apply_recite.py` dry run exits 2 (`non-canon new_ids`).

## Row 3 — R-CHKED-001: two new tests (verification + validation)
Append at the end of `tests/test_b102_parameter_picker.py` exactly this (it reuses the file's `run`, `need`, `settled_delay`, `synthetic_rows`, `write_wide_a2l`, `page_tuple`, `table_rows`, `SIZE`, `PAGE_SIZE`; ledger rows are keyed by name, `s19_app/tui/a2l_parameter_picker.py:925`):
```python


# --------------------------------------------------------------------------- #
# R-CHKED-001 — every parameter of the loaded A2L, one row each, across pages
# --------------------------------------------------------------------------- #


def _ledger_names(panel) -> list:
    """The parameter names the ledger shows, in row order (rows are keyed by name)."""
    table = panel.query_one("#check_param_table", DataTable)
    return [row.key.value for row in table.ordered_rows]


async def _names_on_both_pages(panel, pilot) -> tuple:
    first = _ledger_names(panel)
    need(panel, "#check_param_page_next_button", Button).press()
    await settled_delay(
        pilot,
        lambda: page_tuple(panel) == (2, 2) and table_rows(panel) == 50,
        "the second page settles with its 50 rows",
    )
    return first, _ledger_names(panel)


def test_r_chked_001_1_every_parameter_once_across_the_pages(tmp_path: Path) -> None:
    """R-CHKED-001/1 (verification): 250 parameters on 200-row pages. Page 1 shows
    200 rows and page 2 shows 50; together they hold every parameter exactly once.

    Why: the fold reworded R-CHKED-001 to "in the ledger's pages" because
    R-B102-SEL-001 caps a page at 200 rows; the every-parameter half must still
    hold. Mutant: a page slice one row short drops a parameter -> RED.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(250))
        await settle(pilot, 2)
        return await _names_on_both_pages(panel, pilot)

    first, second = run(tmp_path, SIZE, body, a2l=None)
    assert (len(first), len(second)) == (PAGE_SIZE, 50), (len(first), len(second))
    assert sorted(first + second) == [f"P{i:05d}" for i in range(250)], "a parameter is missing or shown twice"


def test_r_chked_001_2_a_loaded_a2l_lists_every_parameter_once(tmp_path: Path) -> None:
    """R-CHKED-001/2 (validation, black box): the operator loads an A2L with 250
    CHARACTERISTICs and opens the Check Editor from the rail; paging through the
    ledger shows each of the 250 parameters exactly once.

    Mutant: as R-CHKED-001/1 -> RED.
    """
    a2l = write_wide_a2l(tmp_path, 250)

    async def body(app, pilot, panel):
        await settled_delay(pilot, lambda: table_rows(panel) == PAGE_SIZE, "the first page shows 200 rows")
        return await _names_on_both_pages(panel, pilot)

    first, second = run(tmp_path, SIZE, body, a2l=a2l)
    assert (len(first), len(second)) == (PAGE_SIZE, 50), (len(first), len(second))
    assert sorted(first + second) == sorted(f"P{i:03d}" for i in range(250)), "a parameter is missing or shown twice"
```
If `DataTable.ordered_rows` does not exist in the installed Textual (8.2.8 is expected to have it), replace that one line by `return [table.coordinate_to_cell_key(Coordinate(r, 0)).row_key.value for r in range(table.row_count)]` with `from textual.coordinate import Coordinate` inside the helper, and record it as a deviation.
Control: **NC-d** `s19_app/tui/a2l_parameter_picker.py:921` -> `        page = names[start : start + self._page_size - 1]` -> both new tests RED.

## Oracle and end
- `--collect-only -q tests`: N0 + 2.
- `python -I -B ../in/trace_check.py --req REQUIREMENTS.md --ids $(cat ../in/f2b-fold-ids.txt)`: TEST lines before = 20, after = exactly 3 (`R-TST-009`, `R-TUI-062.10.2`, `R-TUI-062.10.3`); ignore the one `CASE` line.
- reverse_trace after: `tests: 6961`, `O 1558` (`test_tc_b102_a2l_04_…` and `test_tc_b97_64_…` leave O), `X 268`, `U 2`.
- End per TA2-common.

## For the checker
Laws on the unit tree: no new RED; R-DOC-CANON.10 stays GREEN (no review file names a removed test). Planted control: on a copy restore the R-DOC-ARCHIVE.2 row line -> `trace_check.py --req REQUIREMENTS.md --ids R-DOC-ARCHIVE.2` reports it as an active row with a TEST gap again (on the unit tree it exits 2, no match); laws stay GREEN either way (a retired note is not a row): record both. Intent: read the 13 `Traces:` lines against the per-test list above.
