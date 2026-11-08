# E5 corrective 2 — Inc 4 code (DeepSeek v4 Pro)

Worktree `C:\Users\<user>\Github\s19_app-b103-inc4-code` (branch `b103-inc4-code`). Rules: `.dev-flow/2026-11-05-batch-103/inc-4/E4-handoff-impl.md` sections 1, 4 and 5 (one file `s19_app/tui/services/label_match.py`; no tests; **no Python that imports or loads the module on this PC** — only `python -m py_compile` and `codewire_extract.py`). Authority: the last two sections of `inc-4/E3-rulings.md` ("E5 round-2 rulings", "E5 round-2 design rulings"). Design: `inc-4/codewire/graph-inc4.md` as corrected (range tables for the map path, C-level totals — one `collections.Counter` per weight —, the cap: more than 20 distinct query tokens leaves the fuzzy rule out, the compact build for .37), `inc-4/01-requirements.md` (.37, .40, .41), and the measured pilots `inc-4/evidence-e5/d2-*` (follow the graph, use the pilots as reference behaviour).

Implement exactly that; keep every other behaviour (the 129 behaviour tests and the existing perf tests must stay GREEN). Run the extractor on a throwaway copy with marks outside the worktree (exit 0; transcript to `inc-4/evidence-e5/corrective2-extract.txt`). Do not commit.

Report (≤ 200 words): changes (function, line), line count, commands with exit codes, deviations.
