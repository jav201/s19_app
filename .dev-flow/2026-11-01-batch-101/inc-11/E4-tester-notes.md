# Inc 11 — E4 tester notes

Independent tester, evidence state `executed` (RED on base only; GREEN is the integrator's). Base = `origin/main` (4648972c; no difference from `b7b77c4` in `validation/`, `tui/a2l.py`, `tui/issues_view.py`). All runs on the LAN Linux host (Python 3.11, Textual 8.2.8), never on Windows. Transcript: `evidence/inc-11/red-01-tester-base.txt`.

## Test files

| File | Group | Covers |
|---|---|---|
| `tests/test_b101_a2l_blocks_and_segments.py` (new) | G1 | R-VAL-032.1 .. .3, R-A2L-036.*, R-A2L-034, R-A2L-120 .. 123, D-9 pin over the 37-file corpus |
| `tests/test_b101_issues_severity_view.py` (new) | G2 | R-TUI-042b.1, .2, .4, .5, .6, R-TUI-025.2, .6, R-SEG-SRC.6/2 |
| `tests/test_b101_inc11_acceptance.py` (new) | G3 | AT-I11-1 .. 6 through `p` (Load dialog), `5`, `2`, `d`, PgDn |
| `tests/test_tui_issues_triage_b94.py` (re-pinned; 3 names unchanged) | G2 | AT-B94-14, TC-B94-18 (engine arm + freeze arm unchanged), TC-B94-19 |
| `tests/test_synth_release_case.py::test_a2l_zero_issues` | G1 | R-VAL-032.2/2 |
| `tests/test_segment_split_window.py` fixtures `DEMO_A2L_SECTIONS`, `PrgCode` | G1 | E3 A-2 (record shape only) |
| `tests/test_engine_unchanged.py` | — | comment only (Inc 11 unfreeze note) |

## Case mapping (full unless stated)

All rows of `02-test-cases.md` map to the names in its Tests column (updated there for: `..._unknown_block_warns_nested`, `..._036_4_no_base[<case>-begin-line|own-line]`, the 37 corpus ids). Cases that stay `covered` by unchanged tests: R-A2L-036.1/1, /4, 036.2/1, 036.3/1, 036.6/1, /2, R-A2L-120/1.

Partial or not fully expressible:
- R-A2L-036.7/1: the "Split / Join lists no row" half is not asserted (name/base/size None only).
- R-A2L-036.8/1, 036.9/1: V161 / V171 / `memorysegment.a2l` halves are the unchanged TC-682 tests; the new test covers `software_a.a2l`.
- R-SEG-SRC.6/2 reads the painted base values plus `window._a2l_rows()` (name, base, size); painted names are truncated by the table tier.
- AT-I11-4: the window is opened with `app.action_open_split_join_export()` (the palette's own action), not by typing in the command palette.
- AT-I11-5: the cursor is placed on the first CURVE row with `DataTable.move_cursor` after PgDn to the page that holds one (the demo lists 208 VALUE tags first).
- AT-I11-3: the Warnings button is pressed with `Button.press()` (a focus+Enter or click did not reach it after the project load).
- R-TUI-042b.5/2, /4: read `app._filtered_validation_issues()` (white-box on the method the row names).
- R-VAL-032.2/3 (corpus) walks the section tree with its own IF_DATA-aware walker, independent of the engine.

## RED summary (base)

See the transcript for counts. Behavioural reasons: unknown-block issues for ASAM names / IF_DATA children (G1 032.2, 032.3, corpus 37/37); `UNKNOWN` names, `None` base for name-first and `/begin`-line records, wrong `usage`/`kind`, over-4-GiB bound missing (G1 036.*, 034); the note on every CURVE row (121/122); header/strip/summary counts and row classes moved to INFO (G2 042b.1/.2/.4/.6, 025.2/.6); unsorted filtered list (042b.5); `a2l(0)` (R-SEG-SRC.6); AT-I11-1/2/3/6 counts `total=364/387`, `info=102`, `rows 1-40/379`, Region `unknown`.
GREEN on base by design (pins, not RED): R-VAL-032.1 (5 cases), 15 of the 62 ASAM names, the 036.4 records that the base reader skips on the `/begin` line, the 036.2/4 comment case, R-TUI-042b.1/1 (reverse list order), `test_tc027`, all 56 nodes of `test_segment_split_window.py` (the rewritten fixtures read the same on the base reader).

## Ambiguities (not resolved by reading the implementation)

1. R-A2L-121 indent: the requirement says the line `x: point index (axis points unavailable)` once above the header; D-6 gives it a two-space indent. Tests compare the stripped line.
2. AT-I11-5 assumes the first CURVE of the demo has no axis values (E1 says so; on base the note is on its rows).
3. R-VAL-032.1/1 .. .4 and 032.3/1 .. /3 assert "exactly 1" / "0 issues" over the whole issue list of a small PROJECT/MODULE file, as the cases say; no other structure issue is expected on base (confirmed for the base cases).
4. AT-I11-1/2 numbers (`262`, `285`, `7`/`8` pages) are the E1 model values; base gives 364 / 387 (102 INFO) as E1 recorded, the GREEN values are unverified.
5. TC-B94-18 freeze arm and `test_tc027` are RED on the Inc 11 branch by plan (OR-3); on this base they pass.

## Environment limits

The LAN host was oversubscribed (load 11 on 8 cores) during the runs. The acceptance file therefore uses its own `wait_until`/`_press` that ride out Textual's 30 s `WaitForScreenTimeout` (deadline 300 s). Nothing was run on Windows. GREEN not run (implementer tree is in flux).
