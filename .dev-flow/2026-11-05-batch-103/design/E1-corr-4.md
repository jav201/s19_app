# E1 correction pass — Inc 4 (records only)

You apply the orchestrator's E1 rulings to the Inc 4 records of s19_app batch-103. Worktree: `C:\Users\jjgh8\Github\s19_app-b103`. Records folder: `.dev-flow/2026-11-05-batch-103/inc-4/`. Read the ruling table at the end of `inc-4/E1-rulings.md` ("Orchestrator rulings") first.

## Rules
- Edit ONLY `inc-4/01-requirements.md`, `inc-4/02-test-cases.md`, `inc-4/E1-slice.md`, and append one line to `inc-4/steps.log`. Nothing else, no source files, no git command that writes.
- Targeted edits only: never rewrite a file. Keep every table's column count and pipes intact. English.
- Before and after, record each file's line count (`wc -l`) in your report.

## Edits
1. **S2.7 → S2.8.** In the three files, every mention of the proposed canon subsection `S2.7` becomes `S2.8` (Inc 2 takes S2.7). Use `grep -n "S2\.7"` to find them all; report each. Do not edit `E1-rulings.md`.
2. **New row R-A2L-MATCH.37**, inserted right after the R-A2L-MATCH.36 row in `01-requirements.md`, same columns as .35/.36; copy the US cell of the R-A2L-MATCH.35 row:
   `| R-A2L-MATCH.37 | E | When the system prepares a name list of 50,000 names for ranking, the system shall hold the prepared list in at most 64 MiB. | the tracemalloc peak during the preparation of the reference list (fixture REF, 50,000 names) ≤ 67,108,864 bytes (64 MiB), on cachyos-rtx, Python 3.11.18; the peak printed in the transcript | the pilot's dict trie (about 137 MiB) → RED | <US of .35> | new (D-12 A + D, orchestrator ruling) | No (B: the pilot v3 index took about 137 MiB) |`
   In `02-test-cases.md`, right after the R-A2L-MATCH.36 cases, add one case in the same column layout: `R-A2L-MATCH.37/1` — objective "Verify that the prepared reference list stays within 64 MiB"; class normal; precondition fixture REF (50,000 names), cachyos-rtx; input the preparation of REF under tracemalloc; expected peak ≤ 67,108,864 bytes; Tests empty, Coverage `gap`, Result `not_run`.
   In `E1-slice.md`, map R-A2L-MATCH.37 to the same preparation node(s) that R-A2L-MATCH.35 maps to.
3. **Counts.** `grep -n` every count line in the three files and update consistently: rows 36 → 37, `R-A2L-MATCH.1` … `.36` ranges → `.37`, cases 109 → 110, coverage items 107 → 108. Change nothing else.
4. Append to `inc-4/steps.log`: `<ISO timestamp> E1 correction — model deepseek-v4-pro via pi — orchestrator rulings D-10 (S2.8) and D-12 (new R-A2L-MATCH.37 memory row, counts) applied`.

## Report (≤ 200 words)
Each edit made (file:line), line counts before/after, anything you could not apply and why.
