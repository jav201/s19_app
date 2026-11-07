# E3 correction pass — rules for every unit (Inc 1a, Inc 4 and later)

- Worktree `C:\Users\<user>\Github\s19_app-b103`; your increment folder `.dev-flow/2026-11-05-batch-103/inc-<N>/` (your unit brief gives N). Read `inc-<N>/E3-rulings.md` first — it is the authority — then the "fix" column of each finding it cites in `inc-<N>/E3-architect.md` and `inc-<N>/E3-security.md` (`grep -n "^| E3A-NN \|^| E3S-NN "`).
- Edit ONLY the file(s) your unit names, plus one appended line in `inc-<N>/steps.log`. No source file, no other record, no git command that writes. English.
- Targeted edits only: never rewrite a file or a whole section; keep every table's column count. Record `wc -l` before and after.
- New row ids: only those `E3-rulings.md` fixes. Splits keep the parent id with `.1`, `.2`.
- Every row keeps the canon form (strict EARS, one `shall`, subject "the system", a numeric threshold, a negative control). Every threshold N/N equals its row's case count after your edits; update count lines.
- If a ruling cannot be applied as written, apply nothing for it and report it.
- Report (≤ 200 words): each finding id → what you changed (file:line), line counts, anything not applied and why.
