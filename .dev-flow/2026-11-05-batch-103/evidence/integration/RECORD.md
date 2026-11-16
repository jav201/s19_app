# Batch-103 final local integration record

## Scope and verdict

Built branch `b103-final-integration` in a new worktree from `origin/main` `0c3a6bd4674c3f2df90a7399898fc98429f5a200`. The five P-012 stages are complete in the requested order. No push was performed. The dirty batch-103 worktree and its untracked Inc 12 files were not used or modified.

The five integrated source stages end at commit `15fed9cb60abda65429126e90d2158fcb90adfc1`. This record and its transcripts are added by one following evidence-only commit; that commit changes no path outside `.dev-flow/2026-11-05-batch-103/evidence/integration/`.

## Stage commits

| Stage | Source content | Squash commit | Parent | Private-token law on Linux rtx |
|---|---|---|---|---|
| 1 | `b103-inc1b-push` / `origin/b103-inc1b` `caae1bf9a0b97266731753fc9dc0a38f3762f222` | `3b01fc023d3be595534d64c8e2c3e5afa358ae02` | `0c3a6bd4674c3f2df90a7399898fc98429f5a200` | `2 passed` — `stage-1-private-tokens.txt` |
| 2 | Resolved `b103-base2` `9ffe019dc9fbd83ca1ff56f958bcb4f01242677e`, including modular `2dbd7d5a` and PE split `a95d0ea9` content | `aae4f445365ffcb75e1702f064ece38bff44c575` | `3b01fc023d3be595534d64c8e2c3e5afa358ae02` | `2 passed` — `stage-2-private-tokens.txt` |
| 3 | `b103-inc7` `9defd2ab73d033db708362162fa7cf91371028a2` | `6d33c6c946c059976ba87fce13aa9a2a17f737c1` | `aae4f445365ffcb75e1702f064ece38bff44c575` | `2 passed` — `stage-3-private-tokens.txt` |
| 4 | `b103-inc9b` `5054a27d597dcb282a2c0c2fdc0aa3fc8a0a376f` (Inc 8, 9, 8b and 9b) | `359b9b73118c285e838423dbacb972cff1df7816` | `6d33c6c946c059976ba87fce13aa9a2a17f737c1` | `2 passed` — `stage-4-private-tokens.txt` |
| 5 | `b103-inc10` `1c9a4c33731b6fc86cf69ce4834a85ae80cb3bee` | `15fed9cb60abda65429126e90d2158fcb90adfc1` | `359b9b73118c285e838423dbacb972cff1df7816` | `2 passed` — `stage-5-private-tokens.txt` |

Every stage commit has exactly one parent. None of `b103-inc1b-push`, `b103-base2`, `b103-inc7`, `b103-inc9b`, `b103-inc10`, `b103-proto8`, or `b103-wci-2` is ancestral to the integrated stage-5 commit. No proto8 or WCI merge was made.

## Test method

Each required law run used a fresh `git archive` of the exact stage commit, extracted under `~/work/zq-b103-integrate/<stage>/tree`. A local Git index was initialized in the extracted copy so `git ls-files` enumerates exactly those archived files. HT-02 isolation used fresh HOME, XDG, LOCALAPPDATA, and TMPDIR paths under `~/work/zq-b103-integrate`; no `/tmp` path was used. Runs used Python 3.11.18, `PYTHONDONTWRITEBYTECODE=1`, UTF-8, `-p no:cacheprovider`, `-n 0`, closed stdin, and `timeout 300`.

The required command in each exact copy was:

```text
<s19ci-python> -m pytest -p no:cacheprovider -n 0 -q tests/test_no_private_tokens.py
```

The initial stage-1 bare-archive attempt is preserved as `stage-1-private-tokens-archive-no-index.txt`: it produced `1 passed, 1 skipped` because the tracked-file scanner could not run `git ls-files` without an index. It is not accepted as gate evidence. The rerun of the identical files with an index produced the required `2 passed`.

## Conflict and content decisions

### Stage 1 — Inc 1b

`git merge --squash b103-inc1b-push` completed without conflicts. No conflict resolution was needed; the main candidate's redacted records were retained. Checks: no unmerged paths, AST parsing of 42 changed Python files, and scoped `git diff --cached --check -- s19_app tests` passed. A whole-tree whitespace check was not used as a gate because imported historical transcripts intentionally contain trailing whitespace.

### Stage 2 — modular and PE split

Verified that `b103-base2` contains the final Inc1b, modular, and PE-split inputs and their resolutions. Materialized the `b103-base2` tree without making its history ancestral. The stage-2 commit tree is byte-for-byte the `b103-base2` tree. The source/test/tool diff check passed and 117 changed Python files present in `b103-base2` parsed by AST. No new conflict resolution was needed.

### Stage 3 — Inc 7

The ordinary squash reported six conflicts:

- `s19_app/tui/app/a2l_view.py`
- `s19_app/tui/app/compose_screens.py`
- `tests/test_b103_clipboard_tail.py`
- `tests/test_b103_copy_paste_matrix.py`
- `tests/test_b103_copy_quit_dialog.py`
- `tests/test_id_registry.py`

Verified `b103-base2` is ancestral to `b103-inc7`; therefore the Inc 7 versions contain the resolved stage-2 base and were retained for all six. The resulting stage-3 tree exactly equals the `b103-inc7` tree. AST parsing of 34 changed Python files and the scoped diff check passed. TC-607 was reconciled to the measured 317-file population, not merely copied from the conflict text.

Targeted evidence on the exact stage-3 copy:

- `stage-3-id-registry.txt`: `12 passed`, including TC-607 at the measured bound.
- `stage-3-a2l-focused.txt`: `12 passed` (the two named Inc 7 regression nodes plus the 10 A2L acceptance nodes).
- `stage-3-clipboard-focused.txt`: `2 passed, 5 skipped`; the five platform-specific paste cells did not execute on Linux and are not claimed as passes. The changed drag helper and quit-dialog regression executed and passed.
- `stage-3-targeted.txt`, `stage-3-a2l-targeted.txt`, and `stage-3-clipboard-targeted.txt`: broad combined runs reached the 300-second timeout (RC 124). They are retained as non-verdict transcripts, not green evidence.

### Stage 4 — Inc 8, 9, 8b and 9b

The ordinary squash used `origin/main` as its ancestor because earlier stages are squashed, producing 25 mostly artificial add/add conflicts. A content-only three-way merge with the real shared content base `a95d0ea93340d26d8fe55025e9e7c21bef2d4f79` reduced these to two genuine conflicts. The resulting tree was materialized without adding source-branch ancestry.

- `tests/test_id_registry.py`: retained both branch histories and set TC-607 to the measured merged population of 358, rather than either branch's 317 or 352.
- `tests/test_tui_snapshot.py`: retained both the Inc 7 A2L drift helper and the Inc 8 Patch Editor drift helper, together with their respective mark applications.
- The already-redacted Inc1b records and modular steps record were verified unchanged by this content merge.

Checks: AST parsing of 152 changed Python files, scoped diff check, no conflict markers in product/tests/tools, and measured population 358. Targeted evidence on the exact stage-4 copy:

- `stage-4-id-registry.txt`: `12 passed`.
- `stage-4-snapshot-targeted.txt`: `1 passed, 24 deselected, 8 xfailed`. All eight mismatches are the intentional drift-marked A2L/Patch cells; there was no unexpected failure. Local runner paths in this transcript were replaced with `~` before committing it.

### Stage 5 — Inc 10

The actual shared content base of Inc 9b and Inc 10 is Inc 8 final `6c4fd21f8147da23cc2f397544584f1514b8fca1`. An exploratory merge-tree call using the older PE-split base produced artificial Inc 8 add/add conflicts; that tree was never materialized or committed. Recomputing from `6c4fd21f` left only `tests/test_id_registry.py` in conflict.

Retained both registry histories and set TC-607 to the measured final population of 366 (`358 + 8`), rather than either branch bound. All other content auto-merged. Checks: AST parsing of 37 changed Python files, scoped diff check, unchanged redacted Inc1b/modular records, and measured population 366.

Targeted evidence on the exact stage-5 copy:

- `stage-5-id-registry.txt`: `12 passed`, including TC-607 at 366.

## Exact final integrated product tree

- Final stage-5 commit: `15fed9cb60abda65429126e90d2158fcb90adfc1`
- Git tree: `a161f0607eb08736debd025bb393b8b81188741a`
- Deterministic `git archive --format=tar` SHA-256: `0a7f4bc478c13ca1d0c52a156b3dbef145dd0b3c2abbf75f206b8569bed91e4a`
- Final measured scanned test population: `366`
- Changed paths relative to `origin/main`: 3230 files; 220 changed Python paths under `s19_app`, `tests`, and `tools`.
- Tracked worktree and index diffs were empty after stage 5; only this integration evidence directory was untracked before the evidence-only commit.

## Not run / open limitations

The full suite was intentionally not run, per the local-integration instruction. Windows-only paste cells remain unexecuted on Linux. The eight snapshot cells remain under their existing non-strict drift marks pending their canonical baseline regeneration. No unresolved merge or private-token-law blocker remains at stage 5.
