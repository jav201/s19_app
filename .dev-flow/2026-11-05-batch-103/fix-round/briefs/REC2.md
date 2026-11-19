# Unit REC2 — finish REC row 1 (law `test_r_tst_070_2`), after redacting the fix round's own records
Your tree is a COPY of REC's tree (b103-fix-round c46ac195 + REC's row 2 record edits in `evidence/full-suite/RESULT.md` and `fix-round/RECORD.md`). Keep REC's edits. Read `../../REC/BRIEF.md` (row 1 design) and `../../REC/REPORT.md` (why row 1 stopped) first.

The REC worker found 5 hits beyond the base set, all in records this fix round wrote itself today (not inherited; rule HT-11: records never name the runner HOME basename):
- `.dev-flow/2026-11-05-batch-103/fix-round/briefs/FB-common.md`: the worker run command spells the runner home basename twice. Replace that path segment, in both places, with `<runner-home>` (e.g. `HOME=$S/home/<runner-home>`), and replace any `mkdir -p $S/home/…` segment the same way. Change nothing else in that file.
- `.dev-flow/2026-11-05-batch-103/fix-round/checks/check-G3a.md`: the prose "no sleep / home / LAN tokens" → "no sleep, home-path or LAN tokens". Change nothing else.
Then apply REC row 1 exactly as designed in REC's brief (the three additions in `tests/test_suite_hygiene.py` + `test_r_tst_070_2_reviewed_exemptions_stay_narrow`). Do NOT add `<runner-home>`, `LAN` or anything else to the exemptions: after the two record fixes the remaining hits must be exactly the inherited ones the design covers. If any other hit remains, STOP and paste it.
Files you may edit: `tests/test_suite_hygiene.py`, `.dev-flow/2026-11-05-batch-103/fix-round/briefs/FB-common.md`, `.dev-flow/2026-11-05-batch-103/fix-round/checks/check-G3a.md` (plus REC's two edited files, unchanged).
Negative controls: as in REC's brief (planted forms still reported; delete your three additions in a scratch copy → the law RED on the real tree, paste the first hit); plus put the runner home basename back in the scratch copy's FB-common.md → RED naming it.
Nodes (`-n 0`): `tests/test_suite_hygiene.py -k "070"`, then the whole `tests/test_suite_hygiene.py`.
Your own REPORT.md must not spell the runner home basename either: write `<runner-home>`.
