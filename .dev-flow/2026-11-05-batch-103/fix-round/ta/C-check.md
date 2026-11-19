# C-check — mechanical check of U1-recite (C1) and U2-retire (C2) (DeepSeek, a session that did not write the unit)

Appended after `frontB/CHK-ds.md`. Where they differ, this addendum wins. Never edit anything under `~/.claude/skills`; no git writes; copies only under `~/work/zq-ta/chk-<UNIT>/`, deleted at the end by explicit path.

## Overrides of CHK-ds
- Paths: `~/work/zq-fb/` -> `~/work/zq-ta/`. Base clone `~/work/zq-ta/base` = **b5ca5b72** (not 3afebf90). C1's "before" tree is the base; C2's "before" tree is the U1 tree.
- Step 4 (laws): "no new RED" is against `~/work/zq-ta/baseline/laws-b5ca5b72.txt` (U0), not the 3afebf90 list.
- Step 2 is replaced by the unit-specific steps below; steps 1, 4, 5, 6 stand.
- Measuring tool: `~/miniconda3/envs/s19ci/bin/python -I -B ~/work/zq-ta/in/reverse_trace.py --repo <tree> --out <dir> --tmp <dir> --ta2` (stdlib, AST only; it never imports s19_app).

## C1 — U1-recite
1. **Only docstrings/comments changed.** Write your own `~/work/zq-ta/chk-U1/ast_same.py` (do not reuse the worker's script): for each changed `.py`, `ast.dump` of base and U1 module with every docstring blanked must be equal. Paste the per-file result; any mismatch = MECH-NO-GO. Files changed must be a subset of the 65 files named by applied rows of `recite-map.tsv` (read with `quoting=csv.QUOTE_NONE`).
2. **Rows really applied.** Pick 20 REPLACE rows and 20 ADD tests at random (print the seed): at a REPLACE line the old token (regex of the brief, P3) is gone and every new id is present; an ADD test's own docstring has one `Traces:` line equal to the ordered union of its rows' `new_ids`. The 4 NEEDS-RULING rows (seq 349, 351, 389, 390) left their lines unchanged.
3. **Trace classes.** reverse_trace on base and U1: base `tests: 6966 … X 484, U 40`; U1 `6966 … X 278, U 7`. Join U1's `TA2-matrix.tsv` with `scope-before.tsv`: every scope test without a NEEDS-RULING row has a class other than X and U.
4. **NC-c (the tool catches a bad id).** In a copy of U1, replace the first `Traces:` line of `tests/test_hexfile.py` with `Traces: R-NOPE-999.1.`; reverse_trace on the copy classes that test **U**. **NC-d (which law catches what).** In the same copy add ` TC-99999` to that docstring: `tests/test_id_registry.py` (`test_tc602_g3…`) goes RED naming TC-99999. With only `R-NOPE-999.1` planted, record that all six law files keep their U0 result: no law checks R-/US- citations in tests (law gap, already stated in EXEC-PLAN).
5. `--collect-only -q tests`: base and U1 node counts equal.

## C2 — U2-retire
1. **Exactly 13 tests gone.** `def test_` names removed in the U1->U2 diff = the 13 names of `retire-list.tsv` rows 1-13; other removed definitions: only `_shipped_surface_files`, `_TUI_DIR`, imports of the allowlist. Files changed = the 10 of the brief.
2. **Registry.** Exactly 5 lines differ (TC-011, TC-017, TC-628, TC-638, TC-678), every line parses as JSON; node counts 13 / 8 / 4 / 31; TC-678 is `RETIRED` with `retired_reason`, no `nodes`; `test_validate_mac_records_reports_parse_and_empty_fields` is still a TC-628 node and still defined.
3. `--collect-only -q tests`: U1 count minus U2 count = **13** exactly.
4. reverse_trace on U2: `tests: 6953 … X 269, U 3`; none of the 13 names in `TA2-matrix.tsv`.
5. **Law-based negative controls**, each on its own `cp -a` copy of U2, running only the named law file (`-n 0`): **NC-e** re-add `tests/test_tui_helpers.py::test_find_repo_root_detects_marker` to TC-638 `nodes` -> `test_tc601_g2…` RED naming it; **NC-f** restore the old S10-ears-strict.md:375 text -> `test_review_files_name_only_existing_tests` RED naming `test_at_b94_08_variant_machinery_retired`; **NC-g** set TC-678 back to `LIVE` with its node and statement -> `test_tc601_g2…` RED. Paste each RED line. A control that stays GREEN = MECH-NO-GO.
6. Laws on U2 (six files, serial): no new RED vs U0.

Write `~/work/zq-ta/<UNIT>/CHECK.md` as CHK-ds says; last line `CHECK_DONE <UNIT> <MECH-GO|MECH-NO-GO>`. The orchestrator does the intent review separately.
