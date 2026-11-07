# E4 handoff — Inc 2a tester (independent of the implementer)

## Role
You write the tests of **Inc 2a — A2L definition model, read side** (describe, decode, display; the synth `--case definitions` and the case-08 hash pin) from the approved design, in parallel with an implementer you never talk to. You do not write product code. Process: `C:\Users\<user>\.claude\skills\dev-flow-v3-beta\SKILL.md` stage E4 (read it whole).

## Where you work
- Worktree `C:\Users\<user>\Github\s19_app-b103-inc2a-tests` (branch `b103-inc2a-tests`). Only there.
- You own: `tests/test_b103_a2l_definition.py` (the model's 2a cases), `tests/test_b103_a2l_definition_perf.py` (R-A2L-DEF.136 and any other timing row of 2a, `serial_timing`), `tests/test_b103_synth_definitions.py` (the `--case definitions` rows and the case-08 pin R-A2L-DEF.59 with .59/3), fixtures under `tests/fixtures/b103_a2l_definition/` if needed, the constant `EXPECTED_SCANNED_TEST_FILES` in `tests/test_id_registry.py` (+ your new files), and the Tests / Coverage / Result columns of `inc-2/02-test-cases.md` for 2a cases. Nothing else.

## Read
1. `.dev-flow/2026-11-05-batch-103/inc-2/02-test-cases.md` — test **only the 2a cases** (its "Split (amendment A2)" section); the 21 cases that hold an encode part: test their decode / describe part, mark the case `partial` and say the encode part waits for 2b.
2. `inc-2/01-requirements.md` (rows, definitions, the split), `inc-2/codewire/graph-inc2.md` (I-2 2a signatures and examples — use them as inputs), `inc-2/E3-rulings.md` (every section; the E4 addenda E3A-27 for .59/3 and E3A-29 (b)).
3. The repo's test conventions: `CLAUDE.md`, `PROJECT_RULES.md`, `tests/conftest.py`, `tests/test_synth_release_case.py`, and the requirement-id docstring convention `C:\Users\<user>\.claude\skills\dev-flow-v3-beta\trace_check.py` reads.

## Rules
- Import only I-2's 2a public names from `s19_app.tui.a2l_definition`; a test that needs a private helper is `partial` (prefer black-box). Fixtures: the tracked `.a2l` files under `examples/` and `tests/`, release case 08 generated with `tools/synth/make_release_case.py` (seed 20260001) into a temp dir, INLINE A2L text in the test where a case gives it.
- **R-A2L-DEF.59/3 (E3A-27):** take the digest on a clean base tree before any edit — on the runner's base worktree (below), record it with its transcript, and pin that value in the test.
- **Never run pytest or any script that imports `s19_app` on this PC.** Run on the Linux runner `<runner>`: `ssh -o BatchMode=yes <user>@<runner-ip> "bash -lc '…'"` (fish login shell — always `bash -lc`). Create once a base worktree there: `git -C ~/work/s19_app worktree add --detach ~/work/b103-inc2a-base e07fb00` (never touch `~/work/s19_app` itself); copy your test files in with `tar c <files> | ssh … "bash -lc 'tar x -C ~/work/b103-inc2a-base'"`; run `~/miniconda3/envs/s19ci/bin/python -m pytest -q -p no:cacheprovider <files>` with `PYTHONDONTWRITEBYTECODE=1` and `HOME`/`XDG_*`/`LOCALAPPDATA` in a fresh dir **whose basename is not `home`** (e.g. `/tmp/b103-e4-2a-tests/<user>`). Start every transcript with `python -c "import s19_app; print(s19_app.__file__)"`.
- **RED on base:** the module does not exist on base → `ModuleNotFoundError` at collection: record it. Also run against a runner-only stub (functions returning empty / refusing everything) under `/tmp` — never committed — to show the tests fail for behavioural reasons. The synth tests: RED because `--case definitions` does not exist on base; the case-08 pin passes on base (that is its point — say so).
- Save every transcript as a file in `inc-2/evidence-e4/tests-*.txt`. Commit locally on `b103-inc2a-tests` at the end, one commit: `batch-103 Inc 2a E4: tests (independent tester)` with a `Co-Authored-By` line naming your model. Never push; never write the operator's name; never touch any clipboard.

## Report (≤ 300 words)
Tests per file, cases `full` / `partial` / not covered (why), the RED transcripts and what failed, runner commands with exit codes, anything you could not test, time.
