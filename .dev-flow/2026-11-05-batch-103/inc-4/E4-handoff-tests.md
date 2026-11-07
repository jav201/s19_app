# E4 handoff — Inc 4 tester (independent of the implementer)

## Role
You write the tests of **Inc 4 — Label similarity matcher** from the approved design, in parallel with an implementer you never talk to. You do not write product code. Process: `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` stage E4 (read it whole): write the test cases' tests, prove them RED on base, mark each test `full` or `partial` honestly.

## Where you work
- Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc4-tests` (branch `b103-inc4-tests`). Work only there.
- You own: `tests/test_b103_label_match.py` (behaviour), `tests/test_b103_label_match_perf.py` (the `serial_timing` bounds R-A2L-MATCH.35, .36, .37, .40), fixture data under `tests/fixtures/b103_label_match/` if you need any, and the constant `EXPECTED_SCANNED_TEST_FILES` in `tests/test_id_registry.py` (+2 for your two files). Nothing else: never `s19_app/`, never the records except the Tests / Coverage / Result columns of `inc-4/02-test-cases.md` at the end.

## Read
1. `.dev-flow/2026-11-05-batch-103/inc-4/02-test-cases.md` — one test (or parametrised case) per coverage item; each test asserts the case's exact expected result.
2. `inc-4/01-requirements.md` (rows .1 … .40 with thresholds and negative controls), `inc-4/codewire/graph-inc4.md` (I-3 signatures and the examples — use them as test inputs), `inc-4/E3-rulings.md` (addenda A-1 … A-4 change .24, .36 and add .40).
3. How the repo writes tests: `CLAUDE.md`, `PROJECT_RULES.md`, `tests/conftest.py`, an existing services test (e.g. `tests/test_project_gather.py`), how `serial_timing` is marked, and the requirement-id docstring convention the trace checker reads (`C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\trace_check.py`; `tests/test_id_registry.py`).

## Rules
- Import only the public I-3 names (`build_label_index`, `rank`, and the result type) from `s19_app.tui.services.label_match`. A test that needs a private helper is `partial` — prefer black-box.
- Each test's docstring names its case id(s) (`R-A2L-MATCH.<n>/<k>`) as the trace convention requires.
- Reference lists: REF (the 50,000-name list of the E1/E2 pilots — rebuild it with the pilot's generator, `inc-4/evidence-e1/` and `inc-4/codewire/i4e2-pilot4.py`, deterministically) and REF6 (the first 50,000 names of `examples/case_06_large_nested_a2l/firmware.a2l`, parsed with the repo's A2L reader).
- **Never run pytest or any script that imports `s19_app` on this PC.** Run on the Linux runner `cachyos-rtx`: copy your files with `tar c <files> | ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc 'mkdir -p /tmp/b103-e4-4-tests && tar x -C /tmp/b103-e4-4-tests'"`; the runner has a base checkout you may create once as a separate worktree: `ssh … "bash -lc 'git -C ~/work/s19_app worktree add --detach ~/work/b103-inc4-base e07fb00'"` (never touch `~/work/s19_app` itself), copy your test files into it, and run `cd ~/work/b103-inc4-base && ~/miniconda3/envs/s19ci/bin/python -m pytest -q -p no:cacheprovider <your files>` with `HOME`/`XDG_*`/`LOCALAPPDATA` set to a temp dir. Start every transcript with `python -c "import s19_app; print(s19_app.__file__)"` (it must point into `~/work/b103-inc4-base`). Login shell is fish: always `bash -lc`.
- **RED on base:** the module does not exist on base, so collection fails with `ModuleNotFoundError` — record that transcript as the RED evidence (state it plainly; behavioural sensitivity is proven by the E5 mutant table). Also check your tests collect and fail for the right reason against a stub you write **only on the runner** under `/tmp` (a module whose functions return empty results) — never commit that stub.
- Save every transcript as a file (tool output, never typed): `inc-4/evidence-e4/tests-red-*.txt` in your worktree.
- Never push, merge or force. Commit locally on `b103-inc4-tests` at the end, one commit: `batch-103 Inc 4 E4: tests (independent tester)` with a `Co-Authored-By` line naming your model. Never write the operator's name anywhere.

## Report (≤ 300 words)
Tests written (count per file), cases covered `full` / `partial` / not covered (and why), the RED transcripts and what failed, the runner commands with exit codes, anything in the design you could not test, time.
