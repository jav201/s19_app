# U1-recite — apply `recite-map.tsv` with one mechanical script (DeepSeek v4-pro)

Appended after `frontB/FB-common.md`. Where this brief and FB-common differ, this brief wins; the overrides are listed first.

## Overrides of FB-common
- **Tree:** `~/work/zq-ta/U1/repo`, a clone on branch `b103-fix-round`, HEAD = **b5ca5b72**. The unit folder is `..` (`REPORT.md`, `scratch/`, `state/`, inputs in `../in/`).
- **Files you write (exactly 2, outside the repo):** `../apply_recite.py` and `../test_apply_recite.py`. You never edit a repo file by hand. The script edits the 65 test files that `../in/recite-map.tsv` names, docstrings and comments only.
- **Rule 6 (product mutation per row) does not apply:** no product code and no assertion changes. The negative controls are NC-a and NC-b below.
- Rules 2, 3, 7 and 8 stand: no git writes, never rename a test or parametrize id, never edit anything under `~/.claude/skills`, no user/host names in records.
- You may run `--collect-only` over `tests` (collection, not a run). You never run the suite or the law files.

## Input — `../in/recite-map.tsv`
TAB-separated, one header row. Read it with `csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE)`: cells contain `"` characters, so the default quoting corrupts rows (390 rows; check the count).
Columns: `seq, class, file, test, old_id, new_ids` (`;`-separated), `action` (`REPLACE` | `ADD` | `NEEDS-RULING`), `old_where`, `edit_at` (`file:line` at b5ca5b72), `source_row`, `note`, `line_excerpt`.

## `apply_recite.py` — fixed spec
CLI: `python -I -B ../apply_recite.py --repo . --map ../in/recite-map.tsv [--apply] --result ../scratch/recite-result.tsv`. Without `--apply` it is a dry run: every check below runs, nothing is written. Stdlib only. Function ≤ 40 lines, file ≤ 300 lines.
- **P1 canon preflight.** Canon rows = first cell of every `REQUIREMENTS.md` line matching `^\| ((?:R|US)-[^ |]+) \|`, except lines between the heading that starts with `#### S0.2 ` and the next line that starts with `#### ` (S0.2 holds retired pointers, not rows). Every id in `new_ids` of a non-`NEEDS-RULING` row must be a canon row. Otherwise exit 2, list each `(seq, id)`, write nothing.
- **P2 locate.** The file exists and parses; the function named `test` (drop a `[...]` suffix; it may sit in a class) exists. Otherwise exit 2.
- **P3 REPLACE.** Line L of `edit_at` must lie in the test's own docstring, or be a comment line between the first line of the contiguous comment block directly above the first decorator and the function's `end_lineno`, or (`old_where == banner`) a comment line at most 30 lines above the first decorator. `line.strip()` must start with `line_excerpt[:40]` (drift check). Token regex: `(?<![A-Za-z0-9_.-])` + `re.escape(old_id)` + `(?![A-Za-z0-9_]|[.-][A-Za-z0-9]|/)`. At least one match on L; a match followed by `/` is a case id: exit 2. Replace every match on L with `", ".join(new_ids)`.
- **P4 ADD.** Group ADD rows by `(file, test)`; ids = ordered union of their `new_ids`. One line `Traces: <id>, <id>.` goes into the test's OWN docstring. If that docstring already has a line starting with `Traces:` -> exit 2. Cases: (a) closing quotes alone on the last line -> insert before it a blank line (unless the line above is blank) and `<indent>Traces: ….`, indent = that closing line's indent; (b) closing quotes end a text line -> keep the text without the quotes, then a blank line, `<indent>Traces: ….`, `<indent>"""`, indent = the docstring statement's `col_offset`; (c) one-line docstring -> same as (b); (d) no docstring -> insert `<c>"""Traces: …."""` before the first body statement, c = its `col_offset`; exit 2 if that statement starts on the `def` line. Keep the quote style (`"""`/`'''`) and any `r` prefix. A non-plain-str docstring (f-string, bytes) -> exit 2.
- **P5 order.** Per file: all REPLACE first (no line shift), then ADD insertions from the bottom of the file upward.
- **P6 code cannot change.** Per file, `ast.dump` of the module with every docstring (first-statement str constant of module, class, function) blanked must be identical before and after; `compile()` must pass. All new texts are built in memory; files are written only if every file passes (otherwise exit 3, nothing written).
- **P7 bytes.** Read/write UTF-8 with `newline=""`; a target file holding `\r` -> exit 2; keep the trailing newline; no BOM.
- **P8 idempotent.** On an applied tree: REPLACE row whose line lacks the old token and holds every new id -> `already`; ADD whose `Traces:` line equals the planned one -> `already`. Exit 0.
- **P9** `NEEDS-RULING` rows are skipped and listed (expect 4: seq 349, 351, 389, 390).
- Result TSV: `seq, status (applied|already|skipped), file:line_after`. Print counts per action and per status.

## `test_apply_recite.py` — fixed cases (pytest, synthetic tmp repo, never imports s19_app)
Fixture: `REQUIREMENTS.md` with `#### S0.1`, `#### S0.2 · x` holding `| R-OLD-1 | **retired** | x |`, `#### S1 · x` holding `| R-NEW-1 | U | x |` and `| R-NEW-2 | U | x |`; `tests/test_f.py` with a module docstring citing `HLR-9`, and tests covering every P3/P4 case plus a comment citation. One test per case: T1 REPLACE; T2-T5 ADD (a)…(d); T6 preflight rejects `R-OLD-1` and `R-NOPE-1` (exit 2, file bytes unchanged); T7 excerpt mismatch -> exit 2; T8 case id `LLR-1.1/1` -> exit 2; T9 a row pointing at a non-docstring string literal -> non-zero exit, nothing written; T10 second run all `already`, bytes unchanged; T11 dry run writes nothing. Each test names in its docstring the rule it guards and why (a test that cannot fail when the rule breaks is wrong).

## Steps (append to `../REPORT.md` after each)
1. Header (unit `U1-recite`, `git rev-parse HEAD` must print b5ca5b72…, `date`). Run `pytest -q ../test_apply_recite.py` (env line of FB-common; `-p no:cacheprovider`); paste the summary.
2. Base collection: `--collect-only -q tests` -> node count N0 (last summary line). Base trace: `~/miniconda3/envs/s19ci/bin/python -I -B ../in/reverse_trace.py --repo . --out ../state/rt-before --tmp ../state/rt-tmp --ta2`; paste its `tests:` line (expect `6966 … 'X': 484, 'U': 40`).
3. Dry run, then `--apply`. Paste the counts (expect 144 REPLACE + 242 ADD rows applied = 386, 4 skipped; 65 files).
4. **NC-a (bad id refused):** `cp ../in/recite-map.tsv ../scratch/nc-map.tsv`; set `new_ids` of seq 368 (T5) to `R-NOPE-999.1`; dry run on a fresh `cp -a` of the base tree -> exit 2 naming seq 368. **NC-b (idempotent):** rerun `--apply` on the applied tree -> all `already`, `git diff --stat` identical before/after. Delete `../scratch/nc-*`.
5. After: `--collect-only` count must equal N0 (delta 0). Trace after into `../state/rt-after`; paste the `tests:` line (expect `6966`, `X 278`, `U 7`). Join `../state/rt-after/TA2-matrix.tsv` with `../in/scope-before.tsv` on `(file, test)` and list every scope test whose class is still X or U: only the 4 NEEDS-RULING tests may appear (2 U, the TR-01 test X, `test_tc_b102_pe_06_empty_states_mirror_check` is O).
6. End per FB-common (`git diff --stat`, CR count 0, `UNIT_DONE U1-recite`). Deviations need evidence; never "fix" a map row — report it.
