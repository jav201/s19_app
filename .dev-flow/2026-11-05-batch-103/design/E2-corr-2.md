# E2 case-correction pass — Inc 2 (records only)

Apply the orchestrator's accepted E2 case fixes to the Inc 2 records of s19_app batch-103. Worktree `C:\Users\<user>\Github\s19_app-b103`; folder `.dev-flow/2026-11-05-batch-103/inc-2/`. Read `inc-2/E2-rulings.md` first, then the findings E2-1 and E2-4 … E2-8 in `inc-2/codewire/graph-inc2.md` (`grep -n "E2-[1-8]\b"`): each one names the case(s) that cannot pass and gives the corrected input, checked on the LAN host.

## Rules
- Edit ONLY `inc-2/02-test-cases.md` and, for E2-1 only, `inc-2/01-requirements.md` (where it lists cited canon rows: add R-A2L-014 as a cited row if it is not there), and append one line to `inc-2/steps.log`. No other file, no source, no git command that writes.
- Targeted edits only, never rewrite a file; keep each table's column count. English.
- Change exactly the cases the findings name (input, precondition or expected result as the graph gives them). If a finding's correction is unclear, change nothing for it and report it.
- Record `wc -l` of each edited file before and after.

## Steps
1. For each of E2-1, E2-4, E2-5, E2-6, E2-7, E2-8: locate the named cases (`grep -n "<case id>" inc-2/02-test-cases.md`) and apply the graph's corrected values. For AT-B103-I2-1 (E2-8, overlapping masks 0x0FF0 / 0x0010) use the graph's corrected expectation.
2. Update any count line only if a case is added or removed (none should be).
3. Append to `inc-2/steps.log`: `<ISO timestamp> E2 case corrections — model deepseek-v4-pro via pi — E2-1, E2-4..E2-8 applied (<n> cases)`.

## Report (≤ 200 words)
Each case changed (id, file:line, old → new in a few words), line counts, anything not applied and why.
