# Inc 10a — validation (E5)

**Verdict: PASS-WITH-NOTES.** The hex navigation, unload state and focus fixes hold end to end: a jump shows the target row as the second hex row (or the first, when the target is the first view row), scrolled to the top-left edge; a failed go-to removes the `> ` marker, and paging, a new search, a new target and a load clear it; A2L / MAC jumps to an absent target snap to the next present row and MAC-added rows count in the pages; a load shows the first hex page. An unload paints `Unloaded primary image.` / `Unloaded MAC.` / `Unloaded A2L.` / `Unloaded all artifacts.` as the file status (and `Nothing to unload.` when nothing is loaded), drops the unloaded image's diagnostics, scrubs Cc / Cf / Zl / Zp from every painted file name, and a saved project (a save as included) and the load question name no unloaded image. After a rail key, a window switch or an unload the focus lands on the shown window's focus target (the A2L `?` chip, the MAC Page Prev button), a hidden Split / Join window runs none of its keys, and the deferred load steps do nothing once the app is exiting. The mutant battery killed 35/38 on the pre-corrective tree; the corrective killed the M23 and M28 survivors (each given a node), and M-L was shown equivalent on every reachable route by probe. No BLOCKER / HIGH / MAJOR is open; the review chain closed green. The notes are records-only: four open backlog rows (BL-I10-1 … BL-I10-4), the S-6 scope note (with its SE5-6 addition) and the merge-time full suite. Branch `b101-inc10` at head `079696d4` (base `09b4808`), plus the uncommitted E5 records, this file and the increment packet. Platform: the LAN Linux laptop for every run; the Windows PC ran only the security probe (stdlib only, no `s19_app` import) — no case has a Windows-only arm.

## Runs

| Run | Result | Evidence |
|---|---|---|
| E1 pilot on base `98d94d7` | D-4 (a)/(b), F-07, F-13, F-14, D4-6, D5-17, D5-19, D5-27, SE5-12a-2 reproduced; F-18 not reproduced | `.dev-flow/2026-11-01-batch-101/inc-10/evidence-e1/i10e1-pilot-transcript.txt` |
| Testers' RED on base (H) | **36 failed, 4 standing guards, 1 skip** | `../evidence/inc-10/red-01-tester-h-base.txt` |
| Testers' RED on base (F) | **41 failed, 5 standing guards** | `../evidence/inc-10/red-01-tester-f-base.txt` |
| E4 integration int-01 … int-23, LAN Linux laptop, trees `b3b7935e…` / `c9513e1c…` / `ba8da175…` on `2f54c7d` then `09b4808` | int-10 `294 passed, 1 skipped, 12 failed` (R-SHELL-FOCUS.4/1 + I-D14 ×10 + known `at_b78_03`); int-12 `307 passed, 1 skipped, 1 failed` (known); int-16 `3442 passed, 187 skipped, 2 xfailed, 2 failed` (known); int-21 `309 passed, 1 skipped, 1 failed` (known); int-22 `218 passed`; int-23 `2 passed` | `../evidence/inc-10/int-01.txt` … `../evidence/inc-10/int-23.txt` |
| DeepSeek mutant battery mut-01 … mut-38 on the pre-corrective tree `54a0eb2` | **35 killed / 3 survived** (M23, M-L, M28) | `../evidence/inc-10/mut-01.txt` … `../evidence/inc-10/mut-38.txt` |
| Corrective e5c-01 … e5c-16, final tree `6cb142f1…` | e5c-11 / e5c-12 / e5c-13 `120 passed, 1 skipped` each (the gate set ×3); e5c-14a–c `2 passed` each (HLR-177c ×3); e5c-15 `492 passed, 1 failed` (known); e5c-16 `6 passed`; every corrective mutant RED on its target except M-L | `../evidence/inc-10/e5c-01-setup.txt` … `../evidence/inc-10/e5c-16.txt`, `../evidence/inc-10/mut-c-01.txt` … `../evidence/inc-10/mut-c-23.txt` |
| Re-review e5c-rr-01 … e5c-rr-05, final tree `d5beaa3e…` | rr-02 `1 failed, 4 passed` (R-WS-LOADED.19/5 RED under the old condition); rr-03 `5 passed`; rr-04 `103 passed, 1 skipped` (H + F); rr-05 `219 passed` (the 7 law guards) | `../evidence/inc-10/e5c-rr-01-setup.txt` … `../evidence/inc-10/e5c-rr-05.txt` |
| Security probe (Windows PC, stdlib only, no `s19_app` import) | SE5-1's helper rule: with the old condition the copy list carries `unloaded_primary.s19`; with the widened condition it is empty | `../evidence/inc-10/e5s-probe.txt`, `../evidence/inc-10/e5s-probe.py.txt` |

Every transcript prints the base commit, the staged tree, `s19_app.__file__` and the exact command line; the corrective and re-review transcripts print the same plus the clone's `main`. The one `int-21` failure and the one `e5c-15` failure are both `test_at_b78_03_…` (known, allowed), not product failures; the `e5c-11/12/13` skip is the 80 × 24 main arm (BL-I10-2).

## Per requirement

| Row | Verdict | Cases | Evidence — Linux | Evidence — Windows | Residual |
|---|---|---|---|---|---|
| R-TUI-018.1 (US-HEXNAV-1) | met — 12/12 | 1 … 4, 6 … 13 | int-21, e5c-11..13; base RED; M1, M6 killed | not-run — no Windows-only arm | BL-I10-2, BL-I10-4 |
| R-TUI-018.2 (US-HEXNAV-1) | met — 3/3 | 1 … 3 | int-21, e5c-11..13; base RED; M2, M3 killed | not-run — no Windows-only arm | — |
| R-TUI-018.3 (US-HEXNAV-1) | met — 2/2 (main arm n/a) | 2, 3 | int-21, e5c-11..13; base RED; M4 killed | not-run — no Windows-only arm | BL-I10-4 |
| R-TUI-018.4 (US-HEXNAV-1) | met — 1/1 | 1 | int-21, e5c-11..13; M5 killed | not-run — no Windows-only arm | — |
| R-TUI-040.4 (US-HEXNAV-1) | met — 3/3 | 1 … 3 | int-21, e5c-11..13; base RED; M1 killed | not-run — no Windows-only arm | — |
| R-TUI-040.8 (US-HEXNAV-1) | met — 4/4 | 1 … 4 | int-21, e5c-11..13; M9, M9b, M-W killed | not-run — no Windows-only arm | — |
| R-TUI-040.11 (US-HEXNAV-1) | met — 9/9 | 1 … 9 | int-21, e5c-11..13; base RED; M7, M8a–f killed | not-run — no Windows-only arm | — |
| R-TUI-040.12 (US-HEXNAV-1) | met — 5/5 + /7 partial | 1, 3 … 6; 7 (unit) | int-21, e5c-11..13; base RED; M10, M11 killed | not-run — no Windows-only arm | — |
| R-TUI-007.3 (US-HEXNAV-1) | met — 1/1 + /2 partial | 1; 2 (unit) | int-21, e5c-11..13 | not-run — no Windows-only arm | — |
| R-TUI-007.5 (US-HEXNAV-1) | met — 1/1 | 1 | int-21, e5c-11..13; M-P killed | not-run — no Windows-only arm | — |
| R-TUI-007.8 (US-HEXNAV-1) | met — 1/1 | 1 | int-21, e5c-11..13; M6, M12 killed | not-run — no Windows-only arm | BL-I10-1 |
| R-TUI-007.9 (US-HEXNAV-1) | met — 1/1 | 1 | int-12, int-21, e5c-11..13; M-R1 killed | not-run — no Windows-only arm | BL-I10-1 |
| R-WS-LOADED.18 (US-UNLOAD-1) | met — 4/4 | 1 … 4 | int-21, e5c-11..13; base RED; M13 killed | not-run — no Windows-only arm | — |
| R-WS-LOADED.13 (US-UNLOAD-1) | met — 1/1 | 1 | int-21, e5c-11..13; M14 killed | not-run — no Windows-only arm | — |
| R-WS-LOADED.14 (US-UNLOAD-1) | met — 2/2 | 1, 2 | int-21, e5c-11..13; base RED; M15 killed | not-run — no Windows-only arm | — |
| R-WS-LOADED.16 (US-UNLOAD-1) | met — 3/3 | 1 … 3 | int-21, e5c-11..13; base RED; M16 killed | not-run — no Windows-only arm | — |
| R-WS-LOADED.19 (US-UNLOAD-1) | met — 5/5 | 1 … 5 | int-21, e5c-11..13, e5c-rr-03; base RED; M17, mut-c-01 killed; e5c-rr-02 RED under the old condition | e5s-probe (stdlib); cases not-run | — |
| R-WS-LOADED.20 (US-UNLOAD-1) | met — 1/1 | 1 | int-21, e5c-11..13; M17 killed | not-run — no Windows-only arm | — |
| R-TUI-012L.8 (US-UNLOAD-1) | met — 5/5 | 1 … 5 | int-21, e5c-11..13; base RED; M18, M19, mut-c-19, mut-c-20 killed | not-run — no Windows-only arm | S-6 |
| R-SHELL-STATUS.7 (US-UNLOAD-1) | met — 2/2 | 1, 2 | int-21, e5c-11..13; base RED; M20 killed | not-run — no Windows-only arm | S-6 |
| R-SHELL-FOCUS.2 (US-FOCUS-2) | met — 8/8 | 1 … 8 | int-20e, int-21, e5c-11..13; base RED; M21, M22, M23, M-R4, M-R6 killed | not-run — no Windows-only arm | — |
| R-SHELL-FOCUS.3 (US-FOCUS-2) | met — 3/3 | 1 … 3 | int-21, e5c-11..13; base RED; M24, mut-c-03 killed | not-run — no Windows-only arm | — |
| R-SHELL-FOCUS.4 (US-FOCUS-2) | met — 2/2 | 1, 2 | int-21, e5c-11..13; base RED; M25, mut-c-15 killed | not-run — no Windows-only arm | — |
| R-SHELL-FOCUS.5 (US-FOCUS-2) | met — 1/1 | 1 | int-21, e5c-11..13; M26 killed | not-run — no Windows-only arm | — |
| R-SEG-OPEN.6 (US-FOCUS-2) | met — 5/5 | 1 … 5 | int-21, e5c-11..13; M27 killed | not-run — no Windows-only arm | — |
| R-SEG-OPEN.7 (US-FOCUS-2) | met — 4/4 | 1 … 4 | int-21, e5c-11..13; base RED; M28, M29 killed | not-run — no Windows-only arm | BL-I10-3 |
| R-SEG-OPEN.1 (US-FOCUS-2) | met — 1/1 | 1 | int-21, e5c-11..13; M30 killed | not-run — no Windows-only arm | — |

**92 cases: 90 `full`, 2 `partial` (R-TUI-040.12/7, R-TUI-007.3/2 — unit nodes reading a field), 0 `gap`.** Three cases are withdrawn by id (Inc 12 D-2, no product route runs the issue jump): R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2. R-TUI-018.3's main arm is `n/a` — no shipped main-view jump has a target without a present row. R-TUI-040.11 is 9/9 arms after QA-3 (each A2L / MAC failure branch parametrised and killed by its own mutant); R-TUI-012L.8's `+MAC:` and integrity-notice arms assert the full newest message line after QA-4.

## Mutant score

**35 / 38 killed** on the pre-corrective tree (`54a0eb2`), the three survivors closed by the corrective. DeepSeek M1…M30, M-P, M-W, M-L, M-R1, M-R3…M-R6: M23 (the stale-switch return removed) survived as the expected equivalent, then **killed** by the corrective's R-SHELL-FOCUS.2/8 (`mut-c-13`); M28 (`check_action` removed) survived as a coverage gap, then **killed** by the strengthened R-SEG-OPEN.7/3 (`mut-c-04`); M-L (`layout_waits` default 0) survived and was shown **equivalent on every reachable route** — the one state it changes, a window switch made while a dialog is current, has no product route (probes `e5c-06`, `e5c-08` / `mut-c-22`, `e5c-09` / `mut-c-23`, `e5c-10`). The corrective's own mutants (mut-c-01 … mut-c-23) are RED on their target nodes except M-L. With the equivalent set aside, the score is 35/37 on the pre-corrective tree, and every survivor is closed by the corrective. Details: `E5-mutants.md`, `E5-corrective-notes.md` §1; transcripts `../evidence/inc-10/mut-01.txt` … `../evidence/inc-10/mut-38.txt`, `../evidence/inc-10/mut-c-01.txt` … `../evidence/inc-10/mut-c-23.txt`.

## Reviews

- **E3 design (code-free):** `architect` **FAIL** (1 HIGH, 3 MAJOR, 10 MINOR) and `security-reviewer` **FAIL — BLOCK-UNTIL S-1, S-2, S-3** (3 HIGH, 2 MAJOR, 3 MINOR). The split into 10a / 10b followed; rounds 2–3 closed the blocking findings: 10a **PASS-WITH-NOTES**, the R3-1 case fixed by the orchestrator. `E3-architect.md`, `E3-security.md`, `E3-rulings.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES** (0 HIGH — CR-1, CR-2 MEDIUM; CR-3 … CR-9 LOW). `E5-code-review.md`.
- **E5 security review:** `security-reviewer` **FAIL** (0 HIGH — SE5-1 MEDIUM; SE5-2 LOW; SE5-3 … SE5-6 INFO). SE5-1 (a save as after a primary unload still writes the unloaded image) ruled fix (a) and fixed; SE5-2 strengthened /7/3 so M28 dies. `E5-security.md`.
- **Coverage audit:** `qa-reviewer` **PASS-WITH-NOTES** (QA-1 … QA-4 MINOR, QA-5 … QA-10 NIT) — first audit found R-TUI-040.11 5/9 arms, R-TUI-012L.8 two arms short, and 3/3 runs unmet; the corrective closed them (89 full, 2 partial, 0 gap before the re-review's /19/5). `E5-coverage-audit.md`.
- **Re-review of the corrective (code + security):** **FAIL** on RR-1 MEDIUM (the save-as filter covered the MAC remainder only, leaving the A2L-only remainder), RR-2, RR-3 LOW. The rr-fixes pass widened the filter and R-WS-LOADED.19's text, narrowed the wording to top-level files, and fixed the nine CR-9 doc items; **GREEN** on `d5beaa3e`. `E5-code-review.md` "Re-review of the corrective", `E5-rulings.md` "Re-review rulings".

## Admitted visible changes

- **A jump shows its target near the top** (F-07, D4-2, D4-6): the target row is the second hex row (the first, when it is the first view row), the pane is scrolled to its top-left, and near the image end the window may hold fewer rows than a page.
- **A failed go-to removes the `> ` marker** (D4-6): also after an empty box or an invalid address, in each of the three views.
- **The file status describes the unload** (F-13, D5-17, D5-27): `Unloaded primary image.`, `Unloaded MAC.`, `Unloaded A2L.`, `Unloaded all artifacts.`, and `Nothing to unload.` when nothing was loaded; file names painted in it lose Cc / Cf / Zl / Zp characters (SE5-12a-2, S-5).
- **An unload drops the unloaded image** (S-2): the primary's diagnostics and integrity notices go, and a saved project (a save as included) and the load question name no unloaded file (R-WS-LOADED.19, .20).
- **The focus lands on the shown window** (F-14, D17-38, D6-21): after a rail key, a window switch or an unload the ring sits on the window's focus target — the A2L `?` chip, the MAC Page Prev button, the window's own target elsewhere — and a hidden Split / Join window runs no key and exports nothing.

## Owed

Open residuals, one backlog id each (`E1-rulings.md` §9–§11):

- **BL-I10-1** (AR2-5 re-anchor half, narrowed at E4-R1): a MAC load or unload with records outside the image shifts the stored main-window index by the MAC-only rows before it (the index counts view rows). The load half (a new image resets the window, R-TUI-007.9) is fixed in Inc 10a; the MAC re-anchor half stays.
- **BL-I10-2** (tester H F-1): at 80 × 24 the Workspace main hex pane is 1 line high, so no jump target can be the second row there; R-TUI-018.1/13's main arm runs at 100 × 30.
- **BL-I10-3** (E5 CR-5, with SE5-3): with the focus forced onto the hidden Split / Join table, the table's own up / down / `k` / `j` bindings still move the hidden window's cursor. Nothing is written (the export sink is guarded, SR2-1), and no product route puts the focus there.
- **BL-I10-4** (E5 CR-8): on a MAC-only spine a MAC record jump finds no present row and centres with 64 context rows; R-TUI-018.1's second row and R-TUI-018.3's target are undefined without present rows.
- **S-6** (E3; addition SE5-6): format characters remain in the Loaded panel slot rows, the Save project `(variant '…')` line, the activity log, and the Split / Join export status and toast (the D-12 scrub covers the file status only).

- **Merge-time full suite:** this increment ran its slice, the edited files, the two HLR-177c nodes, the law guards and the serial lane on the LAN Linux laptop, but not the QC-BC set or the other importers in one lane; the batch-end battery runs the full suite once.

## Trace

`trace_check.py --req 01-requirements.md --base 09b4808 --src s19_app` at close: `trace_check: 3 US, 27 active requirements (0 withdrawn), 0 gap(s)`. Every evidence citation in this record is a full committed path under the batch's evidence home.
