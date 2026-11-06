# E2 brief — rules common to every batch-103 E2 agent (2026-11-06)

You write the E2 record (the Code-Wire graph prototype) of ONE increment of s19_app batch-103 under `dev-flow-v3-beta`. The prototype is the graph only.

## Read first

1. `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` — E2 and E3 (and E4, so your examples become failing tests).
2. Code-Wire v3.1.0, local clone `C:\Users\jjgh8\Github\code-wire` (check `git -C … describe --tags` = `v3.1.0`, commit `e436a08`): `README.md`, then `docs/Metodologia.md`, then `docs/Notation-Grammar.md` (the exact line format). Use the core only: (a) one node per function the change adds or touches, its examples taken from the requirements, never from the code; (b) `tools/codewire_extract.py` lists the real callers of each existing function and exits 1 on drift; (c) each example must be writable as a test that fails before the change and passes after. `codewire_lint.py` only lists lines the parser does not read — a record, not a gate. Recordings are not used.
3. Your increment's E1 records: `inc-<N>/01-requirements.md`, `02-test-cases.md`, `E1-rulings.md` (read the "Orchestrator rulings" section at its end — it overrides the PROPOSED rows above it), `E1-slice.md`.
4. `.dev-flow/2026-11-05-batch-103/PLAN.md` — shared interfaces I-1..I-5 and amendment A1.
5. Format example (latest batch, same flow): `git show b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/codewire/graph-inc12.md`. Copy the layout, not the content.

## Where you work

- Worktree `C:\Users\jjgh8\Github\s19_app-b103` (`batch-103`, product tree = `main` `e07fb00`). Read-only everywhere except your folder.
- Write ONLY in `.dev-flow/2026-11-05-batch-103/inc-<N>/codewire/` plus one start and one end line in `inc-<N>/steps.log`. No git command that writes.
- **No stubs, marks or declarations in the source.** Extractor `# node:` marks go only in a throwaway copy outside the worktree (e.g. `git worktree add` is NOT allowed; copy files to a temp dir under your scratch or on cachyos-rtx `/tmp/b103-e2-<N>/`).

## Output (`inc-<N>/codewire/graph-inc<N>.md`)

- **Baseline:** the current code in scope (existing functions the increment reuses or changes), with real callers from the extractor (`file:line`).
- **Prototype:** only the differences — each new or changed node: signature, contract (inputs, outputs, errors as values or exceptions), the requirement ids it serves, and ≥ 1 concrete example per requirement (input → exact output), taken from the requirement's threshold or test cases.
- **Interfaces:** the shared interfaces this increment produces or consumes (PLAN I-1..I-5), pinned to exact names and types; mark any change you need to a pinned interface as PROPOSED — never change one alone.
- **Coverage table:** every requirement id of the increment → the node(s) and example(s) that cover it. Every requirement has at least one concrete example; list any you cannot cover and why.
- Node count; if the slice exceeds about 40 nodes, stop and propose a split.

## Platform and safety rules

Same as `design/E1-brief-common.md` "Platform and safety rules": on this PC only read, grep, `python -m py_compile` and `codewire_extract.py`; anything that imports `s19_app` runs on cachyos-rtx (`ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"`, `~/miniconda3/envs/s19ci/bin/python`, clone `~/work/s19_app` read-only at `e07fb00`, scratch `/tmp/b103-e2-<N>/`, isolated HOME/XDG/LOCALAPPDATA). Never touch any clipboard. Never write the operator's name. English.

## Stop and report (≤ 250 words)

Node count (new / changed / removed), interfaces pinned or PROPOSED, requirements without an example, deviations from the E1 slice, evidence files, time spent.
