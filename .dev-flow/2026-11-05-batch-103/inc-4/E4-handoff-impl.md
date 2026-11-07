# E4 handoff — Inc 4 implementer (DeepSeek v4 Pro)

## 1. Reference (dev-flow v3 + Code-Wire v3.1; latest as of 2026-11-06)

You are working on s19_app (Textual 8.2.8 / rich 15) under the operator's dev-flow, batch `batch-103`, records under `.dev-flow/2026-11-05-batch-103/` (start with `PLAN.md`). Use only these versions:
- **dev-flow v3 beta:** `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` (skills-repo commit `d858a9a`). Read stage E4 whole. Not the public `jav201/dev-flow`, not `skills\dev-flow\`.
- **Code-Wire v3.1.0:** local clone `C:\Users\jjgh8\Github\code-wire`, tag `v3.1.0` = commit `e436a08`. Core only: the graph's examples come from the requirements; `tools/codewire_extract.py` lists real callers and exits 1 on drift; each example becomes a test that fails before and passes after (testers write those, not you).
- **tui-design:** not used (pure module).

## 2. Your role

**E4 implementer: implement the approved graph; do not write tests.** An independent tester writes the tests in parallel in another worktree, from the same graph.

## 3. Where you work

- Worktree: `C:\Users\jjgh8\Github\s19_app-b103-inc4-code` (branch `b103-inc4-code`). Work only there.
- You own exactly one source file: **`s19_app/tui/services/label_match.py`** (new). Touch nothing else — no test, no record, no other source file. If the graph needs another file, stop and write it down as a deviation.

## 4. Read, in this order

1. `.dev-flow/2026-11-05-batch-103/inc-4/codewire/graph-inc4.md` — **the design you implement**: every node's signature, contract and examples; interface I-3 (`build_label_index(names)` + `rank(query, index, limit)`, results with rule and spans) is pinned — never change it.
2. `.dev-flow/2026-11-05-batch-103/inc-4/01-requirements.md` — the rows R-A2L-MATCH.1 … .40 the code must meet (definitions: tokenisation, folding A–Z only, code-point comparisons, edit bands, rule order, ties, caps).
3. `.dev-flow/2026-11-05-batch-103/inc-4/E3-rulings.md` — every ruling, including the round-2 addenda A-1 … A-4 (substring case-exactness anywhere; duplicate query tokens collapsed; banded `_prefix_distance`; R-A2L-MATCH.38 256-character cap; .39 1,024-character names; .40 any query ≤ 256 characters within 1.0 s).
4. `.dev-flow/2026-11-05-batch-103/inc-4/E1-slice.md` — the node list mapped to rows.
5. Reference pilots (behaviour the graph was measured against; do not copy blindly, follow the graph): `inc-4/codewire/i4e2-pilot4.py` and `inc-4/evidence-e3/addenda-*` / `arch-r2-*`.
6. `CLAUDE.md` and `PROJECT_RULES.md` at the repo root (style, docstrings, no markup in strings).

## 5. Rules

- Code, comments and docstrings in English, matching the repo's docstring style (Summary / Args / Returns / Raises / Data Flow / Dependencies sections as the services already use).
- Standard library only (`array`, `bisect`, `dataclasses`, …). No new dependency.
- Pure module: no Textual import, no I/O, no global mutable state; deterministic (no `hash()`-dependent order).
- **Do not run pytest, the app or any script that imports `s19_app` on this PC.** You may run only `python -m py_compile s19_app/tui/services/label_match.py` and `python C:\Users\jjgh8\Github\code-wire\tools\codewire_extract.py` on the graph. The orchestrator runs every test on the Linux runner.
- Never push, merge, force, `reset --hard` or delete a branch. Commit locally on `b103-inc4-code` at the end, one commit, message `batch-103 Inc 4 E4: label_match implementation (DeepSeek)` plus a `Co-Authored-By` line naming your model.
- Never write the operator's name in any file. No secrets.
- If the graph or a requirement looks wrong, write it down as a deviation. Never change a requirement or the interface to match your code.

## 6. Stop and report

Stop when the file is written, compiles, and is committed. Report (≤ 300 words):
- what you implemented (node → function, one line each);
- the file changed and its line count;
- the commands you ran, with exit codes;
- deviations from the graph (node, what, why);
- open questions.
