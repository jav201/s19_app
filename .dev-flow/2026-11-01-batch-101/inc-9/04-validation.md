# Inc 9 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The flow and chain-set save path is fixed end to end: a confirm re-run writes a chain-set report of that lane alone with `- **Mode:** confirm re-run`; a saved flow and chain-set file hold the file stem they are saved under (cut to 64 characters), also after Clear and on a name clash; and a flow or chain-set save refuses a `flows/` / `flowsets/` home that passes through a link or lies outside the work area, never writes a byte through a link that carries the file's own name (a dangling link included), and paints the exact refusal status. The mutant battery killed 31/32 on the final tree (M14 the one survivor, an equivalent mutant), the corrective's M14b / M22…M31 all killed on their target nodes, and the review chain closed green. No BLOCKER / HIGH / MAJOR is open. The notes are records-only: the nine open backlog rows (BL-I9-1, BL-I9-3 … BL-I9-10; BL-I9-2 closed at E3) and the merge-time full suite. Branch `b101-inc9` at `286405a` plus the uncommitted E5 records, this file and the increment packet. Platform: the LAN Linux hosts for every run; the Windows PC ran only the Windows-only arms twice (`win-01`, `win-02`) with isolated app-state folders and no clipboard (operator rule).

## Runs

| Run | Result | Evidence |
|---|---|---|
| E1 pilot on base `98d94d7` | F-45, F-46, D15-18 reproduced; the shared guard refuses both linked homes; a dangling `flows/z.json` link makes the save create the outside target | `.dev-flow/2026-11-01-batch-101/inc-9/evidence-e1/i9e1-pilot-transcript.txt` |
| Testers' RED on base `e07fb00` (flow saves) | **20 failed, 4 passed**; the 4 passes declared standing guards; the five home rows failed by `TypeError`, shown behaviourally in int-06 | `../evidence/inc-9/red-01-tester1-base.txt` |
| Testers' RED on base (flow names / UI) | **9 failed, 1 passed**; the pass (`19/1`) a declared standing guard | `../evidence/inc-9/red-01-tester2-base.txt` |
| Integration int-01…int-08, LAN Linux host 2, trees `e222dd27…` / `7e6ba8ff…` on `e07fb00` | **GREEN for the right reasons**: int-01 `134 passed, 0 skipped` (the 4 files); int-02 `1254 passed, 147 skipped, 1 xfailed` (QC-BC 24 files); int-03 `761 passed, 10 skipped` (21 other importers); int-04 `218 passed, 0 skipped` (law guards); int-05 `46 passed, 2 skipped, 2456 deselected` (serial_timing, `QC-TM 65 bounds, 0 under 20 %`); int-06 `5 failed` (guard-removed mutant — the behavioural RED of the five home rows, each file at its link's target); int-07 `283 passed, 0 skipped` (final tree); int-08 the mode probe `0o755` vs `0o644` (I-D9, stopped) | `../evidence/inc-9/int-01.txt` … `../evidence/inc-9/int-08.txt` |
| E4-R3 follow-up int-09, LAN Linux host 2, tree `d1b3f7dd…` | `158 passed` (`test_b101_flow_saves`, `test_b99_staging`, `test_address_census`, `test_suite_hygiene`, `test_id_registry`); negative control (mode argument deleted) → the two new ids RED | `../evidence/inc-9/int-09-e4r3.txt` |
| Corrective e5c-01…e5c-07, LAN Linux laptop, tree `608f5e91…` on `e07fb00` | e5c-01 setup + pre-check `70 passed`; e5c-02 every mutant M14b / M22…M29 / M31 RED on its target nodes; e5c-03 M30 RED at the new 0-lines line; e5c-04 `296 passed, 1 failed` (TC-027 against the clone's stale local `main`, decision E-6); e5c-05 serial `1 passed, 297 deselected`; e5c-06 the saves file `38 passed ×3`; **e5c-07 `297 passed, 0 failed, 0 skipped`** (the gate set in an isolated clone whose `main` is `e07fb00`) | `../evidence/inc-9/e5c-01.txt` … `../evidence/inc-9/e5c-07.txt` |
| Windows PC win-01 (head `b204c7d4`) | `34 passed, 2 skipped` (the POSIX-mode nodes); junction and file-link arms run, node ids in the transcript; the account holds the symlink privilege | `../evidence/inc-9/win-01.txt` |
| Windows PC win-02 (head `3f8b9e98`, the final tree) | `46 passed, 2 skipped`; the 9 corrective cases and `_link_points_at` run on Windows | `../evidence/inc-9/win-02.txt` |
| Security probe (Windows, stdlib only, no `s19_app` import) | P0…P10 — P3/P4 content outside under a double swap / hard link (SE5-1), P9 the cleanup deletes a file outside (SE5-2), P1/P5 a junction at the free name never followed | `../evidence/inc-9/e5s-probe.txt`, `../evidence/inc-9/e5s-probe.py.txt` |

Every integration transcript prints the base commit, the staged tree and `s19_app.__file__` (the detached worktree); the corrective transcripts print the same plus the landed diff and the exact command line. The one `e5c-04` failure (TC-027) is the laptop clone's stale local `main`, not a product failure — `e5c-07` re-ran the same set against `main` = `e07fb00` and passed.

## Per requirement

| Row | Verdict | Cases | Evidence — Linux | Evidence — Windows | Residual |
|---|---|---|---|---|---|
| R-FLOW-CHAIN.19 (US-I9-1) | met — 1/1 | 19/1, AT-I9-1 | int-01, int-07, e5c-07; base RED | win-02 | — (the unguarded `reports/` home is BL-I9-7) |
| R-FLOW-CHAIN.20 (US-I9-1) | met — 2/2 + 1/1 | 20/1, 20/2, AT-I9-1 | int-01, int-07, e5c-07; base RED; M1, M2, M30 killed | win-02 | — |
| R-FLOW-FILE.12 (US-I9-2) | met — 5/5 | 12/1 … 12/5, AT-I9-2 | int-01, int-07, int-09, e5c-07; base RED; M4 killed | win-02 | BL-I9-1, BL-I9-5, BL-I9-9 |
| R-FLOW-FILE.13 (US-I9-2) | met — 2/2 | 13/1, 13/2 | int-09, e5c-07; base RED; M5 killed | win-02 | BL-I9-9 |
| R-FLOW-SET.9 (US-I9-2) | met — 2/2 | 9/1, 9/2, AT-I9-2 | int-09, e5c-07; base RED; M6 killed | win-02 | — |
| R-FLOW-SET.10 (US-I9-2) | met — 1/1 | 10/1, AT-I9-2 | int-09, e5c-07; base RED; M7 killed | win-02 | BL-I9-9 |
| R-FLOW-FILE.11 (US-I9-3) | met — 3/3 + control | 11/1 … 11/3, AT-I9-3 | int-09, e5c-07; behavioural RED in int-06 | win-02 | — |
| R-FLOW-SET.7 (US-I9-3) | met — 2/2 + control | 7/1, 7/2, AT-I9-3 | int-09, e5c-07; int-06 | win-02 | — |
| R-FLOW-FILE.14 (US-I9-3) | met — 4/4 (E1 cases) + /5 … /11 | 14/1 … 14/11 | int-09, e5c-07; base RED; M10 … M14b, M21 … M31 killed | win-02 | BL-I9-4, BL-I9-10 |
| R-FLOW-SET.8 (US-I9-3) | met — 4/4 + /5 … /9 | 8/1 … 8/9 | int-09, e5c-07; base RED; same mutants | win-02 | BL-I9-4, BL-I9-10 |
| R-FB-SAVE.8 (US-I9-3) | met — 1/1 | FB-SAVE.8/1, AT-I9-3 | int-01, int-07, e5c-07; base RED; M16, M17 killed | win-02 | — |
| R-FX-SET.15 (US-I9-3) | met — 1/1 | FX-SET.15/1, AT-I9-3 | int-01, int-07, e5c-07; base RED; M18 killed | win-02 | — |
| R-FB-RUN.8 — **withdrawn** (D-2 = no, E3A-01) | — | FB-RUN.8/1, /2 withdrawn | — | — | BL-I9-5 |

**43 cases: 43 `full`, 0 `partial`, 0 `gap`.** R-FLOW-CHAIN.20/2 is `full` again (the QA-2 0-lines clause is asserted and M30 kills it). The five home rows (R-FLOW-FILE.11/x, R-FLOW-SET.7/x) failed on base by `TypeError`; int-06 shows their behavioural failure (each file lands at its link's target with the guard removed).

## Mutant score

**31 / 32 killed** on the final tree (the one survivor is M14, equivalent). DeepSeek M1…M21 (pre-corrective tree `d1b3f7dd` = `b204c7d`): **21 / 21 killed**; the corrective pass (Opus) added M14b and M22…M31, **11 / 11 killed** (`e5c-02`, `e5c-03`). M11 … M14 and M21 (the old step (d)) were re-expressed against the final code and re-run: M11, M12, M13, M21 killed, **M14 survived as an equivalent mutant** — the corrective's /14/10 + /8/8 (M22, the `samestat` clause alone) and /14/11 + /8/9 (M23, the one-link clause alone) each isolate the two clauses M14 drops, and `S_ISREG` is subsumed by `samestat`; the orchestrator's re-run `mut-r-14b.txt` covers the samestat half of M14. The unchanged rows (M1…M10, M15…M20) carry their killed verdicts over unchanged. Details: `E5-mutants.md`, `E5-corrective-notes.md` §4; transcripts `../evidence/inc-9/mut-01.txt` … `../evidence/inc-9/mut-21.txt`, `../evidence/inc-9/mut-r-11.txt`, `../evidence/inc-9/mut-r-12.txt`, `../evidence/inc-9/mut-r-13.txt`, `../evidence/inc-9/mut-r-14.txt`, `../evidence/inc-9/mut-r-21.txt`, `../evidence/inc-9/e5c-02.txt`, `../evidence/inc-9/e5c-03.txt`.

## Reviews

- **E3 design (code-free):** `architect` **FAIL** (1 HIGH E3A-01, 1 MAJOR E3A-02, 8 MINOR) and `security-reviewer` **FAIL** (2 MAJOR S-1, S-2, 4 MINOR). Round 2 re-check after the targeted correction: `architect` **PASS-WITH-NOTES** and `security-reviewer` **PASS-WITH-NOTES**; E3 closed (`E3-architect.md`, `E3-security.md`, `E3-rulings.md`). The two security MAJORs (S-1 the claim-then-check form, S-2 one negative control per defence) folded into the design.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES** (0 HIGH — CR-01 … CR-10 MINOR). Re-review of the corrective: **PASS-WITH-NOTES** (0 HIGH — RR-1 LOW records, RR-2 LOW carried volume, RR-3 LOW test strength, RR-4 INFO records). `E5-code-review.md`.
- **E5 security review:** `security-reviewer` **PASS-WITH-NOTES** (0 HIGH — SE5-1, SE5-2, SE5-3 LOW; SE5-4 … SE5-6 INFO). Every E3 mitigation executed and approved by a mutant; the three LOWs are the claim-TOCTOU race (SE5-1), the cleanup-by-name race (SE5-2) and the residual wording (SE5-3). `E5-security.md`.
- **Coverage audit:** first audit found 33 `full`, 1 `partial` (R-FLOW-CHAIN.20/2, QA-2) and four MINOR gaps (QA-1 … QA-4); the corrective closed them and the re-audit rules **43 covered, 0 partial, 0 gap**. `E5-coverage-audit.md`.

## Admitted visible changes

- **The confirm re-run reports its own mode** (F-45): `- **Mode:** confirm re-run`, `- **Chains:** 1`, one ledger row naming the confirmed lane (was `- **Mode:** sequential`).
- **A saved file holds the stem it is saved under** (F-46): the flow and chain-set file `name` is the file stem, cut to 64 characters (was the display name / typed text, which Load Set could refuse).
- **A save refuses a linked or outside home with the exact status** (D15-18): `Flow not saved - the project's flows folder is a link or is outside the work area.` and `Chain set not saved - the project's flowsets folder is a link or is outside the work area.`

## Owed

Open residuals, one backlog id each (`E1-rulings.md` §6, `E5-rulings.md`):

- **BL-I9-1** (D-4, widened by E3 S-5): a flow file renamed on disk, written by hand, or saved before Inc 9 titles a Flow Execution lane's report with its embedded `name`, not the file it ran.
- **BL-I9-3** (D-7): the Load, Import… and Load Set lists and loads read through a linked `flows/` or `flowsets/`.
- **BL-I9-4** (E3 S-1, restated SE5-3 / CR-10): the save claim is the house TOCTOU class — never an overwrite, and with no concurrent writer nothing lands outside; under a race a file link at the free name (Windows) or one home swap leaves an empty file, and a project folder swapped before the `mkdir` an empty `flows/` / `flowsets/` folder holding the empty claim; content only under a double swap (BL-I9-10).
- **BL-I9-5** (D-2 = no, E3A-01): after Clear the ribbon, the Save dialog's suggestion and the load question keep the cleared flow's name (with the UI rows of the KF-101 family).
- **BL-I9-6** (E3 S-6, pre-existing): `sanitize_project_name` admits Windows device stems and has no length cap; a long stem raises an `OSError` the two handlers do not catch.
- **BL-I9-7** (E3A-10): the chain-set and flow reports are written into `<project>/reports/` with no destination guard.
- **BL-I9-8** (SE5-4, renumbered from the E4 duplicate): `_keep_previous_manifest` (`app.py:11464`) keeps the default `0o777` claim mode.
- **BL-I9-9** (E5 CR-01): a stem longer than 62 characters that clashes can store another saved file's stem as its `name` (`<"C"×64>_2` holds `"C"×64`); the same for chain sets.
- **BL-I9-10** (E5 SE5-1, the half not taken): bind the check after the claim and the cleanup to the descriptor's own final path (`/proc/self/fd`, `GetFinalPathNameByHandleW`), closing the double home swap (P3) and the cleanup's last window (P9).

- **BL-I9-2** (D-5) — **closed at E3** by ruling E3A-04 (R-FLOW-SET.9, .10).

- **Merge-time full suite:** this increment ran its slice, every importer, the QC-BC set, the law guards and the serial lane on the LAN Linux hosts, but not all nodes in one lane; the batch-end battery runs the full suite once.

## Trace

`trace_check.py --req 01-requirements.md --base e07fb00 --src s19_app` at close: `trace_check: 3 US, 12 active requirements (1 withdrawn), 0 gap(s)`. Every evidence citation in this record is a full committed path under the batch's evidence home.
