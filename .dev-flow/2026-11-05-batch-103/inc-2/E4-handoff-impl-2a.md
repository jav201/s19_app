# E4 handoff — Inc 2a implementer (DeepSeek v4 Pro): A2L definition model, read side

## 1. Reference (dev-flow v3 + Code-Wire v3.1; latest as of 2026-11-07)
s19_app (Textual 8.2.8 / rich 15), batch `batch-103`, records under `.dev-flow/2026-11-05-batch-103/` (start with `PLAN.md`, amendment A2). Versions: **dev-flow v3 beta** `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` (commit `d858a9a`; read stage E4 whole); **Code-Wire v3.1.0** `C:\Users\jjgh8\Github\code-wire` tag `v3.1.0` = `e436a08` (core only: examples from the requirements; `tools/codewire_extract.py` finds callers and drift; testers turn examples into failing tests). **tui-design:** not used.

## 2. Role
**E4 implementer: implement the approved graph's 2a side; do not write tests.** An independent tester writes the tests in parallel in another worktree.

## 3. Where you work
- Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code` (branch `b103-inc2a-code`). Only there.
- Your unit's files (the orchestrator tells you which unit you are, A or B):
  - **Unit A:** `s19_app/tui/a2l_definition.py` (new) — the 2a nodes only.
  - **Unit B:** `tools/synth/make_release_case.py` — the `--case definitions` option and its 3 new functions (case 08 byte-identical).
- Touch nothing else: no test, no record, no other source. `s19_app/tui/a2l.py` is **frozen** for Inc 2 (Inc 11 changes it later) — import its helpers as the graph says, never edit it. If the graph needs another file, stop and write it down as a deviation.
- **Do not commit** (another unit works in the same worktree; the orchestrator commits both).

## 4. Read, in this order
1. `.dev-flow/2026-11-05-batch-103/inc-2/codewire/graph-inc2.md` — the design. Its section "Split (amendment A2)" says which nodes are 2a. **Implement only 2a nodes**; I-2's 2b names (`encode_definition`, `Encoded`, `shared_with`, the merge node, the write guards) are not written now — do not stub them.
2. `inc-2/01-requirements.md` — rows and definitions; its "Split (amendment A2)" section lists the 2a rows (and the .19 clauses that stay in 2a).
3. `inc-2/E3-rulings.md` — every section (E3 rounds 1–5, the census and split rulings). Where a ruling and the graph disagree, the ruling wins; write the deviation down.
4. `inc-2/E1-slice.md` (2a functions), `inc-2/E1-rulings.md` (D-1 … D-13 with the orchestrator's rulings), `inc-2/E2-rulings.md`.
5. Base code you call: `s19_app/tui/a2l.py` (`encode_physical_to_raw_bytes` is 2b — not used now; the private helpers the graph lists; `MAX_A2L_DECODE_BYTES`; `parse_begin_meta`), `s19_app/tui/a2l_parameter_picker.py` `parse_parameter_list`; for unit B `tools/synth/make_release_case.py` and `tests/test_synth_release_case.py` (read only).
6. `CLAUDE.md`, `PROJECT_RULES.md` (style, docstrings with Summary / Args / Returns / Raises / Data Flow / Dependencies).

## 5. Rules
- English code, comments, docstrings; match the repo's style. Standard library only. Unit A is pure: no Textual import, no I/O beyond the `a2l_data` and image it is given, no global mutable state, deterministic.
- **On this PC you may run only** `python -m py_compile <your file>` and `python C:\Users\jjgh8\Github\code-wire\tools\codewire_extract.py`. **Do not run pytest, the app, or any Python that imports or loads your module or `s19_app`** (not even through `importlib`; a previous run did that and it was a rule breach). The orchestrator runs every test on the Linux runner.
- Never push, merge, force, `reset --hard`, delete a branch, or commit. Never write the operator's name. No secrets.
- If the graph or a requirement looks wrong, write it down as a deviation. Never change a requirement or a pinned interface to match your code.

## 6. Stop and report (≤ 300 words)
What you implemented (node → function, one line each); the file and its line count; commands run with exit codes; deviations (node, what, why); open questions.
