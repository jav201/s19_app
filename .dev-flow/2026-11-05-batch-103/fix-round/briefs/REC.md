# Unit REC — records of the operator's verdicts + fix-forward of the redaction law for inherited evidence
Your tree HEAD is `b103-fix-round` (main 3afebf90 + fix-round units), not 3afebf90. Rule PP-06: NEVER edit an inherited record or evidence file to make a law pass; fix forward in the law with a recorded, reviewed decision.

## Row 1 — law `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` (base RED)
Base hits (`~/work/zq-fb/baseline/laws.txt`) are all non-identities: (a) redaction markers written by the batch's own redaction (`pytest-of-REDACTED_ACCOUNT`, `hostname="REDACTED_HOST"`, `C:\\Users\\REDACTED_ACCOUNT`); (b) the public GitHub-hosted Windows runner image: account `runneradmin`, host `runnervm<id>` (the law already allows the Linux image's `runner`); (c) prose: `/home/Python` in `evidence/full-suite/b103-g3-recents/RESULT` ("repository/output/home/Python paths") and `/home/end` (the Home/End keys, quoted in inc-8b/inc-9b law transcripts and records).
Fixed design (orchestrator decision 2026-11-19, fix round):
1. `_PLACEHOLDER` (~:1916): add the alternative `redacted_[a-z_]+` (case-insensitive as the regex already is), with a one-line comment: redaction markers written by the batch's own redaction step.
2. Add next to it `_PUBLIC_RUNNER = re.compile(r"runneradmin|runnervm[a-z0-9]+", re.IGNORECASE)` with a comment (public GitHub-hosted Windows runner image account and host names, like the Linux image's `runner`; reviewed 2026-11-19 fix round), and make `_is_placeholder` also return True when the WHOLE value fullmatches `_PUBLIC_RUNNER`.
3. Add `_REVIEWED_NOT_ACCOUNTS = frozenset({"end", "python"})` with a comment (reviewed 2026-11-19 fix round: `home/Python` is prose in `b103-g3-recents/RESULT`; `/home/end` quotes the Home/End keys in inc-8b/inc-9b law transcripts) and apply it ONLY to the label `posix home path outside the runner image`: such a hit whose name lower-cased is in the set is not reported. Every other form is unchanged.
4. Do not change `_REDACTION_PATTERNS`, the roots, or any record/evidence file.
Negative controls (mandatory, in the existing planted-leak style — read `_PLANTED_LEAKS` ~:2056 and its test): extend the planted set or add one test (name it `test_r_tst_070_2_reviewed_exemptions_stay_narrow`) proving that `pytest-of-alice`, `hostname="build-host-7"`, `C:\Users\alice`, `/home/<alice>`, `/home/<endgame>` and `runneradmin2x`… — pick the forms the patterns produce — are STILL reported, while `pytest-of-REDACTED_ACCOUNT`, `hostname="runnervmm7ud1"`, `/home/end`, `/home/Python` are not. Mutation check: delete your three additions in a scratch copy → the law node RED again on the real tree (paste the first hit line).

## Row 2 — records (fixed text; write exactly, LF)
(a) `.dev-flow/2026-11-05-batch-103/evidence/full-suite/RESULT.md`: insert ABOVE its current first line (do not edit any existing line):
```
**STATE 2026-11-19 (operator decision D9, fix round): G3 BLOCKED.** The PASS-WITH-NOTES state recorded below is superseded: the independent review of 2026-11-19 found G3 defects (fix round: `../../fix-round/RECORD.md`). G3 stays BLOCKED until the close suite runs once after the fix round, on the reference Linux host.

```
(b) `.dev-flow/2026-11-05-batch-103/fix-round/RECORD.md`: append at the end:
```

## Operator decisions recorded (2026-11-19, decision page of the review)
| Id | Decision | Effect |
|---|---|---|
| D6 | Supersession recorded: batch-94 HLR-003 (AT-B94-03: table and editor visible together at 120×30) and batch-97 AC-1, AC-3, AC-5 (the editor grows when there is room) are superseded by the Inc 8 tabs R-TUI-063.3 … .5 and the fixed 9-row lower panel R-PE-DEF.1.1 (approved 2026-11-14, P-125) | Their tests re-trace to those rows; the JSON growth tests (space injected with `styles.height = 60`) verify a built state, not a reachable one (trace-audit step) |
| D7 | Real captures of Inc 8b (11 groups) and Inc 9b (11 groups): verdict ok | Closes review finding R1-F5 for the captures |
| D9 | G3 relabelled BLOCKED until the post-fix-round close suite | `evidence/full-suite/RESULT.md` top line |
| Law | `test_r_tst_070_2` fixed forward (unit REC): redaction markers, the public Windows runner image identities and two reviewed prose words are not identities; inherited evidence untouched (PP-06) | Law GREEN without editing inherited records |
```
Files you may edit: `tests/test_suite_hygiene.py`, the two record files above.
Nodes (`-n 0`): `tests/test_suite_hygiene.py -k "070"`, then the whole `tests/test_suite_hygiene.py`.
