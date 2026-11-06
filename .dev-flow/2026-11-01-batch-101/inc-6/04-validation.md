# Inc 6 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The Patch Editor document lifecycle is fixed end to end: the before/after offer shows only with a project, the replaced-document hides (control and save-back prompt) run on all eight replacement routes and never on Save project, the three lists (Patch Editor File, Check Editor Spec, A2B Diff check-spec) show the project's `checks/<n>` / `patches/<n>` then the common `library/<n>`, every Write lands in the project home and names it, and the Checks tab and Checks screen reset after loads and in-place writes. The mutant battery killed 39/41 (M10, M35 equivalent under every buildable route; M27 the expected E3A-16 survivor), M43 and M44 killed in the corrective, and the review chain closed green. No BLOCKER / HIGH / MAJOR is open. The notes are records-only: the C-10 backlog (a pre-existing dangling-`workarea/patches` crash outside the slice) and the merge-time full suite. Branch `b101-inc6` at `18420f6c` plus the uncommitted E5 records, this file and the increment packet. Platform: the LAN Linux host for every run; the Windows PC ran only the 10 junction / file-link arms once (`e5c-08`) with isolated app-state folders and no clipboard (operator rule).

## Runs

| Run | Result | Evidence |
|---|---|---|
| E1 pilot on base `9bb0e3a` | F-05, D10-30, F-06 (+ D9-15, D14-17), F-40 reproduced; F-47 not reproduced (0 refusals after start and project load; only `b` reaches the action) | `.dev-flow/2026-11-01-batch-101/inc-6/evidence-e1/i6e1-pilot-transcript.txt` |
| Testers' RED on base `823d0c93` (lifecycle) | **38 failed, 8 passed** (165 s), every failure behavioural, the 8 passes declared standing guards | `../evidence/inc-6/red-01-tester1-base.txt` |
| Testers' RED on base (document homes / lists) | **34 failed, 9 passed**, the 9 passes declared standing guards | `../evidence/inc-6/red-01-tester2-base.txt` |
| Integration int-00…int-08, LAN Linux host 2, tree `4d71b9b7…` on `98d94d7` | **GREEN for the right reasons**: int-01 `215 passed, 0 skipped` (the 6 files); int-02 `2701 passed, 4 failed, 173 skipped, 1 xfailed` (QC-BC 61 files; one test defect I-D9 plus 3 known); int-03 `518 passed, 1 failed` (26 importers; 1 known); int-04 `217 passed, 1 failed` (law guards; I-D10); int-05 `54 passed, 2 skipped` (serial_timing, `QC-TM 80 bounds, 0 under 20 %`); int-06 `4 passed` (E3A-16 mutant copy — the mutant survives, I-D3); int-07 `261 passed` (final tree); int-08 `29 passed, 4 failed` on pristine `98d94d7` (the 4 known failures identical on base) | `../evidence/inc-6/int-00.txt` … `../evidence/inc-6/int-08.txt` |
| Corrective e5c-01…e5c-08, LAN Linux host 2, tree `2dedfdeb…` on `98d94d7` | e5c-01 `15 failed, 3 passed` (pristine base + the two new test files: every failure behavioural; the 3 passes are the declared standing guards); e5c-02 `158 passed, 0 skipped`; e5c-03 `218 passed` (law guards); e5c-04 `20 passed ×3` (3/3, the 20 rewritten key/dialog nodes); e5c-05 M43 KILLED; e5c-06 M44 KILLED (3 RED, `no-project` GREEN by design); e5c-07 `2 passed, 294 deselected` (serial_timing, `QC-TM 10 bounds, 0 under 20 %`); **e5c-08 Windows PC: `10 passed, 0 skipped`** (the 10 junction / file-link arms once each, isolated app-state folders, no clipboard; the file links were created and the folder links ran as junctions) | `../evidence/inc-6/e5c-01.txt` … `../evidence/inc-6/e5c-08.txt` |

Every integration transcript prints the base commit, the staged tree and `s19_app.__file__` (the detached worktree); the corrective transcripts print the same plus the landed diff. The four `int-08` failures and the one `int-03` failure are the batch's known failures, identical on base.

## Mutant score

**39 / 41 killed** (DeepSeek battery M1…M42; raw 39/42 = 92.9 %). M10 (`_reset_project_session` hide) and M35 (`_reset_project_session` Checks-tab refresh) are **equivalent under every buildable project load** — the variant install and the reopen tail also hide and repaint — so the redundant calls stay (C-2). M27 is the **expected E3A-16 survivor** (I-D3; M28 is its effective control). The corrective pass (Opus) added M43 (drop the `.` refusal, C-7) and M44 (status back to the bare name, C-9): **both KILLED** (`e5c-05`, `e5c-06`). Details: `E5-mutants.md`, `E5-corrective-notes.md` §4; transcripts `../evidence/inc-6/mut-01.txt` … `../evidence/inc-6/mut-42.txt`, `e5c-05.txt`, `e5c-06.txt`.

## Reviews

- **E3 design (code-free):** `architect` **FAIL** (4 MAJOR, 11 MINOR) and `security-reviewer` **PASS-WITH-NOTES** (2 MAJOR, 4 MINOR, 1 LOW). Round 2 re-check after the targeted correction: `architect` **PASS-WITH-NOTES** and `security-reviewer` **PASS-WITH-NOTES**; E3 closed (`E3-architect.md`, `E3-security.md`, `E3-rulings.md`). The two security MAJORs (S-1 image-load hide, S-2 the stranded library) folded into the design; D-3 was revised at E3 to list the library as `library/<n>` in all three lists.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES** (0 HIGH — F1–F3 MINOR, F4–F6 NIT; F3 the vacuous "no file written" clause, F4 the `.` name, C-7). `E5-code-review.md`.
- **E5 security review:** `security-reviewer` **PASS-WITH-NOTES** (0 HIGH — E5-1, E5-2 LOW; E5-3…E5-6 INFO). Every E3 mitigation executed and approved by a mutant; the two new findings are E5-1 (pre-existing dangling-link crash, C-10 backlog) and E5-2 (Write status names the home, C-9). `E5-security.md`.
- **Coverage audit:** first audit changed **17 of 81 marks (21 %)** — 15 rows to `partial` (the 12 route holes: project-load and Save-project through the private handler, and button presses in hidden tab panes) plus 2 secondary-node marks. The corrective re-drove all 12 routes through `p`, `ctrl+s` and the owning tab (C-3), made the 3 weak oracles exact (C-4), and removed the vacuous clause (C-5); the re-audit at `2260d4d` rules **85 covered, 0 partial, 0 gap** (81 + R-CHKED-032/1…/4) with 3 secondary `partial` marks after RA-3. `E5-coverage-audit.md`.

## Admitted visible changes

- **D-3 revised list form:** with a project the three lists show `checks/<n>` / `patches/<n>` then `library/<n>` (was: bare common-folder names, library hidden).
- **Write status names the home** (C-9 = SEC E5-2): `Check Editor: wrote checks/<name> …` in a project, the bare name without one.
- **The offer only with a project** (F-05): no before/after offer without a project; the control stays and still gives the `.11` refusal.

## Owed

- **C-10 backlog** (SEC E5-1, pre-existing, outside the slice): a dangling `workarea/patches` link ends the app on Check Editor Write (`FileExistsError` through `changes/io.py:1648`); nothing is written, fails closed.
- **Merge-time full suite:** this increment ran its slice, every importer, the QC-BC set, the law guards and the serial lane on the LAN Linux host, but not all nodes in one lane. The batch-end battery also re-runs the 10 Windows junction / file-link arms with node ids (RA-4) and the mutant table against the re-driven nodes.

## Trace

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base 98d94d7 --src s19_app` at close: `trace_check: 4 US, 28 active requirements (1 withdrawn), 0 gap(s)`. Every evidence citation in this record is a full committed path under the batch's evidence home.
