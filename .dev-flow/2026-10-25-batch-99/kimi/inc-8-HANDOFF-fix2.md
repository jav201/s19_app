# HANDOFF — batch-99 Increment 8 · review round 2 fix (N1)

Date: 2026-10-25 · Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc8` (branch b99-inc8) · Interpreter: `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe` (3.11)

## Worktree proof

```
python -c "import s19_app; print(s19_app.__file__)"
-> C:\Users\jjgh8\Github\s19_app-b99-inc8\s19_app\__init__.py
```

## What the finding was

A PATCH block with `notices` painted red in Flow Builder: the notices arm put
its not-applied lines in `diagnostics`, and Flow Builder paints block
diagnostics as `sev-error`. Brief: `.dev-flow/2026-10-25-batch-99/kimi/BRIEF-inc-8-fix2.md`.

## What changed

- `s19_app/tui/services/flow_execution_service.py` (SOURCE, 1 file): the
  `notices` PATCH arm's not-applied lines now ride `findings` as `FINDING_WARN`
  (the funnel arm's idiom). `diagnostics` stays the `error` arm's channel with
  its cause LAST (UX-C2). CRLF preserved (1893 `\r\n`, 0 bare LF).
- `tests/test_b99_patch_truth.py` (test, uncapped): new TC-B99-17 sub-node
  `test_tc_b99_17_notices_lines_paint_warning`; re-pin of
  `test_tc_b99_17_diagnostics_name_every_non_applied_address` (notices-arm
  needles now read from `findings`, `diagnostics == []`, `FINDING_WARN`
  severities; error arm unchanged).
- `.dev-flow/2026-10-25-batch-99/03-increments/increment-008.md`: new §9
  "Review round 2 fix (N1)".
- Evidence (`.dev-flow/2026-10-25-batch-99/evidence/inc-8/`):
  `red-n1-notices-lines.txt` (2 failed on the unmodified tree),
  `green-n1-patch-truth.txt` (19 passed), `green-n1-affected.txt` (122 passed,
  EXIT=0), `mut-N1.txt` (mutant KILLED, 2 failed). Digests appended to
  `SHA256SUMS.txt`.

## Reader verification (LLR-156.1/156.3/156.4, UX-C1)

No reader took the notices-arm lines from `diagnostics` alone, so no reader
change was needed: the chain-set report enumerates `change_records`/`refusals`,
the lane log line reads the change records, and the flow/fused reports render
both `findings` and `diagnostics`. Proven by the unchanged GREEN runs of
`test_tui_flow_execution_b94.py`, `test_flow_chainset_b94.py`,
`test_b97_flow_builder.py`, `test_flow_builder_render.py` and
`test_address_census.py` (122 passed).

## RED / mutation ledger

- RED baseline: both N1 arms failed on the unmodified tree (transcript kept).
- Mutation (N1): lines put back into `diagnostics` → both arms FAILED
  (`mut-N1.txt`); reverted, restore proven by SHA-256 `fbdbc0bf…` (matches the
  post-fix file exactly). Post-restore sanity re-run: 2 passed.
- Signed balance: 19 = 18 − 0 + 1 nodes in `tests/test_b99_patch_truth.py`.
  No new test module → `EXPECTED_SCANNED_TEST_FILES` unchanged.

## Not done / open

- §4b independent review stays `pending — orchestrator` (gate items 6/15).
- One evidence run was invalidated: the first affected-suite run hit the 300 s
  background cap mid-suite (63 dots, no summary); it was re-run without a
  timeout and only `green-n1-affected.txt` (122 passed, EXIT=0) stands.
- No commit made, per instructions; changes are in the working tree.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/services/flow_execution_service.py (notices PATCH lines → FINDING_WARN findings), tests/test_b99_patch_truth.py (1 new TC-B99-17 paint arm + 1 re-pin), packet §9 + SHA256SUMS.
Tests added: 1 node (test_tc_b99_17_notices_lines_paint_warning); file now 19 nodes.
RED/GREEN: RED 2 failed on unmodified tree; GREEN 19 passed (patch truth) + 122 passed (b94/chainset/Flow Builder/census suites).
Mutations: 1 run — lines back in diagnostics, KILLED (2 failed), reverted with SHA-256 proof fbdbc0bf….
Open questions: §4b independent review pending the orchestrator; one capped evidence run superseded by the no-timeout re-run.
