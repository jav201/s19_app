# E3 round-2 correction unit R — Inc 2 rows and cases (`inc-2/01-requirements.md`, `inc-2/02-test-cases.md`)

Rules: `design/E3-corr-2-common.md` (read it first; it applies here, except: this unit edits BOTH files named above, and adds no new row id).

Authority: the section "## Round 2 rulings" at the end of `inc-2/E3-rulings.md`. Then the "## Round 2" sections of `inc-2/E3-architect.md` and `inc-2/E3-security.md`: for each finding the rulings accept, apply its fix column to the rows and cases (`grep -n "^| E3A-2[1-9] \|^| E3A-3[0-2] \|^| E3S-1[4-9] \|^| E3S-2[0-1] "`).

## Apply (rows and cases only — the graph is another unit's)
- E3S-14: R-A2L-DEF.19's condition (the keyword clause) and cases .19/7, .19/8; E3A-24's SBYTE `0xFF` case becomes **.19/9**; .19's threshold N/N equals its case count.
- E3A-25 / E3S-19: R-A2L-DEF.137's scope: "the display text of a decoded value and every refusal message and notice".
- E3S-15 / E3A-26: .40/9 and .52/2 expect U+FFFD as the fix columns say.
- E3A-21 (.55 threshold and negative control), E3A-23 (.37 narrowed), E3A-24 (.35/5, .35/6 and the SBYTE case as .19/9), E3A-28 (.24/4 and the mask's place in the order), E3A-30 (cited-row count 29), E3A-31 (span boundary case and the `<address>` placeholder rule), E3S-16 (.26/4), E3S-17 (.58.2/16, .58.2/17 and the "integral" pin in the definitions), E3S-18 (the span row's last-byte wording, the boundary case), E3S-20 (at most one notice), E3S-21 (case texts aligned, .19/6 text).
- Every threshold N/N equals the number of cases of its row after your edits; update the count lines.
- Append to `inc-2/steps.log`: `<ISO timestamp> E3 round-2 correction unit R (rows, cases) — deepseek-v4-pro via pi — <n> findings applied`.
