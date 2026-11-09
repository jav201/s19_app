# Inc 11 E5: complete AT-B103-I11-2 and AT-B103-I11-3 through the real app (DeepSeek)

Worktree `C:\Users\<user>\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`, base commit `c351ed7b`. You are an independent acceptance tester. Do not commit.

## Scope

Edit only `tests/test_b103_a2l_reader.py`. Replace the two partial acceptance tests at the end of that file with full application-level tests:

- `test_at_b103_i11_2_commented_old_copy_changes_nothing`
- `test_at_b103_i11_3_v171_loads_clean`

Do not edit product code, other tests, requirements, records or evidence content by hand. If the current product cannot meet an acceptance case, stop and report the defect; do not fix product code.

## Required observable chains

Read `inc-11/02-test-cases.md`, rows AT-B103-I11-2 and AT-B103-I11-3, and reuse existing real-app test patterns and settled/wait helpers in the repository.

### AT-B103-I11-2

Use a real `S19TuiApp` driven through `App.run_test`/Pilot. Load an image with a byte at address 0x1234 and an A2L containing the RP-B28 shape: a commented-out old `MEASUREMENT X` at 0x9999 followed by the live `MEASUREMENT X` at 0x1234. Drive the app's actual load actions.

Assert through real widgets or painted application output:

- the A2L Explorer shows exactly one row for X with address 0x1234;
- the Issues screen contains no `A2L_DUPLICATE_SYMBOL` for X;
- the Workspace A2L summary reports one tag.

Do not call `validate_a2l_structure` as the acceptance evidence and do not substitute parser dictionaries for the UI.

### AT-B103-I11-3

Use a real `S19TuiApp` driven through `App.run_test`/Pilot and its actual A2L load action for `examples/case_00_public/ASAP2_Demo_V171.a2l`.

Assert:

- the application status says `A2L loaded: ASAP2_Demo_V171.a2l` and reports no parse errors;
- the Workspace A2L summary visibly contains `A2L Sections:` and `A2L Tags:`.

Do not call `parse_a2l_file` or `render_a2l_view` directly as the acceptance evidence.

Use product observables and the repository's settled/wait helpers, not arbitrary fixed sleeps. Keep the two tests independent and deterministic. Do not write the OS clipboard.

## RED and GREEN evidence

On this PC run only `python -m py_compile tests/test_b103_a2l_reader.py`. All pytest runs happen on the Linux runner with the absolute s19ci Python, `PYTHONDONTWRITEBYTECODE=1`, closed stdin and HOME/XDG/LOCALAPPDATA isolated under `/tmp/b103-e5-11-at/<user>` (never a path whose final component is `home`). Start every transcript with `s19_app.__file__` and include the pytest exit code.

Create fresh full Git clones/worktrees as needed under `/tmp/b103-e5-11-at`; never use the stale `~/work/b103-int11`.

1. **Behavioral RED on `e07fb00`:** copy the final test file into a clean base checkout and run exactly the two AT node ids. The base already tolerates collection through the guarded `_extract_declared_spans` import. Both tests must execute and fail for the old reader behavior (the commented-out object becomes live and/or V171 reports unclosed sections), not for missing fixtures, imports or test bugs.
2. **GREEN on the final current tree:** run exactly the two AT node ids.
3. **Regression:** run the whole `tests/test_b103_a2l_reader.py` without `serial_timing`.
4. **Laws:** run `tests/test_id_registry.py` and `tests/test_suite_hygiene.py`.

Copy complete transcripts into `inc-11/evidence-e5/` as:

- `at-i11-2-3-red-base.txt`
- `at-i11-2-3-green.txt`
- `at-i11-reader-green.txt`
- `at-i11-laws-green.txt`

Do not claim full coverage if any assertion still bypasses the real application. Do not change the `02-test-cases.md` result cells; the orchestrator will update them from the verified evidence.

## Report

Report the exact app routes and observable assertions used, RED/GREEN counts and exit codes, diff summary, and any remaining limitation. Remove only your `/tmp/b103-e5-11-at*` scratch paths after the transcripts have landed. Do not push, merge or commit.
