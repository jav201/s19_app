# E5 gap fix — Inc 2a code

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code` (branch `b103-inc2a-code`). Rules: `.dev-flow/2026-11-05-batch-103/inc-2/E4-handoff-impl-2a.md` sections 1, 3 (unit A: only `s19_app/tui/a2l_definition.py`), 4 and 5 — **on this PC only `python -m py_compile` and `codewire_extract.py`; no pytest, no Python that imports or loads the module or `s19_app`**. Authority: the last section of `inc-2/E3-rulings.md` ("Inc 2a E5 — known design gaps"). Design: `inc-2/codewire/graph-inc2.md` as updated (the `reads` map per walk, immutable values), `inc-2/01-requirements.md` R-A2L-DEF.149, the model `inc-2/evidence-e5/gap-*`.

Implement exactly that; keep every other behaviour (the 182 behaviour tests must stay GREEN). Run the extractor on a throwaway copy with marks outside the worktree (exit 0; transcript to `inc-2/evidence-e5/gap-extract.txt`). Do not commit (a tester edits tests in the same worktree).

Report (≤ 150 words): changes (function, line), line count, commands with exit codes, deviations.
