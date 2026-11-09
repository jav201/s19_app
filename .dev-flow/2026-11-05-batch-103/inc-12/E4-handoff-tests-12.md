# E4 handoff — Inc 12 independent tester (DeepSeek v4 Pro)

## Role and ownership

Write independent tests for **Inc 12 — A2L tag table: no glued or cut values** from the approved requirements, cases and graph. You do not write product code and do not read the implementer's branch.

You are in worktree branch `b103-inc12-tests`, cut from `batch-103` at the current session start. Own only:
- new `tests/test_b103_inc12_tag_table.py` (all 33 requirement cases plus AT-B103-I12-1);
- the existing tests expressly listed in graph finding E2-6 that require column-order or safe-text re-pointing;
- `tests/test_id_registry.py` only if its measured scanned-file bound must change;
- `.dev-flow/2026-11-05-batch-103/inc-12/02-test-cases.md` Tests/Coverage cells (Result stays `not_run` until the orchestrator's Linux runs).

Do not edit `app.py`, snapshots, requirements, graph, rulings, steps.log, or unrelated tests.

## Read first

1. `.dev-flow/2026-11-05-batch-103/inc-12/02-test-cases.md` — implement every case and AT-B103-I12-1; AT-B103-I12-2 remains the operator's real-terminal gate.
2. `inc-12/01-requirements.md`, `inc-12/codewire/graph-inc12.md`, and every round of `inc-12/E3-rulings.md`.
3. Graph E2-6 for the complete existing-test re-point list, including AT-069b/AT-069c and batch-101 Inc 10b's seven Tag-index readers.
4. `inc-12/codewire/evidence-e2/i12e2-probe.py` and Inc 11's `evidence-e3/corr2-e3c2-fixedcols.py` for synthetic fixture shapes and painted-cell measurement. These are design instruments, not oracles to copy blindly.
5. `tests/support/b100_projects.py`, `tests/test_b101_inplace_views.py`, `tests/test_tui_a2l_detail.py`, `tests/conftest.py`, `CLAUDE.md`, `PROJECT_RULES.md`, and the trace_check docstring convention.

## Test obligations

- Drive the real app through `run_test`/the project's `run_app` helpers and real loading/paging/write routes. Assert exact emitted cell text **and painted geometry** where required; a pre-layout `render()` proxy is not full coverage.
- Build SYNMAP, LONGMAP, PAGE64, PAGE64W and MANY synthetically. No proprietary text and no copied public-corpus text.
- Cover all widths/scroll positions, resize without keys, Save-project write repaint with the table shown, both page-change fits, hostile tails under 1 second, every detail-card field, break runs, the Name line, and AT-B103-I12-1's declared-address census.
- Compute *w* and cell spans from actual table geometry, not only terminal width. Expected shortened strings and declared addresses are pinned independently in the test; do not derive expectations by calling the product helper under test.
- Preserve and re-point existing behavior tests as E2-6 directs: find Tag by its column label; find rows by row-key tag rather than painted name; AT-069b checks the card's safe projection; AT-069c stays on the Tag cell with the new U+FFFD/middle-cut projection and correct `_a2l_filtered_tags` call shape.
- Do not regenerate snapshots locally. Do not weaken or delete an existing assertion to make the new design pass; port its oracle and name the Inc 12 row in a comment/docstring where useful.
- Fill each ledger case with concrete on-disk test node ids and honest `full`/`partial`/`gap` coverage. One acceptance case needs one distinct full-chain node. Leave Result `not_run`.

## Rules

- On this Windows PC run **only** `python -m py_compile` on files you edited. Never import `s19_app`, run pytest, the app, or probes here. The orchestrator runs RED/GREEN and all law guards on Linux.
- No clipboard, secrets, push, merge, rebase, reset, branch deletion, or source edits.
- Commit your tests/ledger changes on `b103-inc12-tests` as `batch-103 Inc 12 E4: independent tests (DeepSeek)` with `Co-Authored-By: DeepSeek V4 Pro`. Do not commit caches or generated output.

## Report (concise)

Test files and node counts, case coverage full/partial/gap, existing tests re-pointed, commands/exit codes, commit id, and any case you could not implement faithfully. Do not claim RED/GREEN without an executed Linux transcript.
