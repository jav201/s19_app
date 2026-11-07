# E3 correction pass — Inc 2 — rules for every unit

- Worktree `C:\Users\jjgh8\Github\s19_app-b103`; folder `.dev-flow/2026-11-05-batch-103/inc-2/`. Read `inc-2/E3-rulings.md` first (it is the authority), then the "fix" column of each finding it cites in `inc-2/E3-architect.md` and `inc-2/E3-security.md` (`grep -n "^| E3A-NN \|^| E3S-NN "`).
- Edit ONLY the file your unit names, plus one appended line in `inc-2/steps.log`. No source file, no other record, no git command that writes. English.
- Targeted edits only: never rewrite a file or a whole section; keep every table's column count. Record `wc -l` before and after.
- New ids for this pass: **R-A2L-DEF.136** and **R-A2L-DEF.137** only (Inc 3 owns .64–.135). Splits keep the parent id with `.1`, `.2`.
- Every row keeps the canon form (strict EARS, one `shall`, subject "the system", a numeric threshold, a negative control). If a ruling cannot be applied as written, apply nothing for it and report it.
- Report (≤ 200 words): each finding id → what you changed (file:line), line counts, anything not applied and why.
