# E5 mutant unit A (round 3, on the corrected code, sha256 8f396c15) — Inc 4, rows R-A2L-MATCH.1 … .20 (DeepSeek v4 Pro)

Rules: `.dev-flow/2026-11-05-batch-103/design/E5-brief-common.md` (N = `4`, role `mutA`). Read it first.

**Task.** For each requirement row R-A2L-MATCH.1 … .20 of `inc-4/01-requirements.md`, take its **Negative control** cell (and, where E3-rulings name a second control, both): it describes a mutation of the product. Apply that mutation to a copy of `s19_app/tui/services/label_match.py` and run the row's tests; the mutant is **killed** if at least one of the row's tests fails, **survived** if all pass.

**How (all on cachyos-rtx; never on this PC):**
1. Once: `cp -a /home/javiergr/work/b103-int4 /tmp/b103-e5-4-mutr3A/base` (never edit `~/work/b103-int4`).
2. Per mutant `M-<row>` (e.g. `M-07`; a second control `M-07b`): `cp -a /tmp/b103-e5-4-mutr3A/base /tmp/b103-e5-4-mutr3A/M-<row>`, edit only `s19_app/tui/services/label_match.py` there (the smallest edit that realises the control; keep a unified diff `git -C … diff`), then run `cd /tmp/b103-e5-4-mutr3A/M-<row> && <python> -m pytest -q -p no:cacheprovider tests/test_b103_label_match.py -k "<the row's test ids>"` (perf rows .35/.36/.37/.40: `tests/test_b103_label_match_perf.py`, run serially, print `uptime` before and after). Find each row's tests by the case ids in their docstrings / pytest ids (`R-A2L-MATCH.<n>/<k>`).
3. Save per mutant: the diff and the pytest tail in `/tmp/b103-e5-4-mutr3A/out/M-<row>.txt`; at the end copy all of `out/` back to `inc-4/evidence-e5/mutants-r3-A/` in this worktree (`ssh … "bash -lc 'tar c -C /tmp/b103-e5-4-mutr3A out'" | tar x -C <local dir>`).
4. Write `inc-4/evidence-e5/mutant-table-r3-A.md`: one row per mutant — id, requirement row, the control as written, the edit made (one line), tests run, result (killed / survived), the failing test id(s). A control that cannot be realised as written: say so (`not realisable: <why>`), never invent another.

Do not change any test or record. One start and one end line in `inc-4/steps.log`. Report (≤ 150 words): killed / survived / not realisable counts, the survivors with one line each, time.
