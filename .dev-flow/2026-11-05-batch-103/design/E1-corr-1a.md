# E1 correction pass — Inc 1a (records only)

You apply the orchestrator's E1 rulings to the Inc 1a records of s19_app batch-103. Worktree: `C:\Users\jjgh8\Github\s19_app-b103`. Records folder: `.dev-flow/2026-11-05-batch-103/inc-1a/`. Read the ruling table at the end of `inc-1a/E1-rulings.md` ("Orchestrator rulings") first.

## Rules
- Edit ONLY `inc-1a/01-requirements.md`, `inc-1a/02-test-cases.md`, `inc-1a/E1-slice.md`, and append one line to `inc-1a/steps.log`. Nothing else, no source files, no git command that writes.
- Targeted edits only: never rewrite a file. Keep every table's column count and pipes intact. English.
- Before and after, record each file's line count (`wc -l`) in your report.

## Edits
1. **R-PASTE.20** (`01-requirements.md`, the row starting `| R-PASTE.20 |`):
   - Requirement text becomes: `When a push or a pull request changes the clipboard source files, their tests or the clipboard workflow file, or the operator starts the clipboard workflow by hand, the system shall run the OS clipboard tests on a GitHub-hosted Windows runner.`
   - In the Threshold cell replace `triggered on \`pull_request\` and \`push\` to \`main\` and \`main-tui\` (and \`workflow_dispatch\`, D-6 B)` with `in the separate workflow \`.github/workflows/clipboard-windows.yml\`, triggered on \`workflow_dispatch\` and on \`push\` and \`pull_request\` with a \`paths\` filter that names \`s19_app/tui/os_clipboard_input.py\`, \`s19_app/tui/capped_text_area.py\`, the OS clipboard test files and the workflow file itself, with no branch filter; \`tui-ci.yml\` unchanged`.
   - In the Negative control cell append `; the \`push\` trigger removed → the static guard RED`.
   - Status cell: `new (D-6 B as ruled, D-8)`.
   - Make case `R-PASTE.20/1` in `02-test-cases.md` match (input: the workflow file `.github/workflows/clipboard-windows.yml` read as text; expected: the triggers and filter above, `runs-on: windows-latest`).
   - In `E1-slice.md` (the config row near line 11) delete the alternative "— or, under D-6 A, a third job in `.github/workflows/tui-ci.yml`" and state the triggers above.
2. **R-PASTE.22**: Status cell becomes `new (D-7 B, ruled)`. No other change.
3. **New row R-PASTE.23**, inserted right after the R-PASTE.22 row, same columns:
   `| R-PASTE.23 | I | If the hosted runner's OS clipboard fails the clipboard probe, then the system shall report the clipboard probe test as failed with the message \`runner clipboard unusable: <probe result>\`. | 2/2: a probe that fails (the read differs from the nonce) → the probe test's outcome is \`failed\` with that exact message and the job's conclusion is \`failure\`; a probe that passes → the probe test passes | the probe test skipped, or passed, on a failed probe → RED (a green job whose OS clipboard tests were all skipped) | US-103-01 | new (D-7 B made loud, orchestrator ruling) | No (R: no probe) |`
   In `02-test-cases.md`, right after the R-PASTE.22 cases, add two cases in the same column layout:
   - `R-PASTE.23/1` — objective "Verify that a failed probe fails the probe test with the message"; class robustness; precondition LinuxH; input a probe result stand-in that reports a read differing from the nonce; expected the probe test's outcome is `failed` with `runner clipboard unusable: <probe result>`; Tests empty, Coverage `gap`, Result `not_run`.
   - `R-PASTE.23/2` — objective "Verify that a passing probe passes the probe test"; class normal; precondition LinuxH; input a probe result stand-in that reports a read equal to the nonce; expected the probe test passes; Tests empty, Coverage `gap`, Result `not_run`.
   In `E1-slice.md`, wherever the probe (R-PASTE.22) is mapped (e.g. the support row near line 102), add R-PASTE.23 beside it.
4. **Counts.** `grep -n` every count line in the three files and update consistently: new rows 22 → 23, active rows 25 → 26, `R-PASTE.1` … `.22` ranges → `.23`, cases 111 → 113, coverage items 101 → 103. Change nothing else.
5. Remove the word `PROPOSED` from the Status cells of R-PASTE rows that cite D-6 or D-7 (they are ruled). Leave `E1-rulings.md` untouched.
6. Append to `inc-1a/steps.log`: `<ISO timestamp> E1 correction — model deepseek-v4-pro via pi — orchestrator rulings D-6/D-7 applied (R-PASTE.20 triggers, R-PASTE.22 status, new R-PASTE.23, counts)`.

## Report (≤ 200 words)
Each edit made (file:line), line counts before/after, anything you could not apply and why.
