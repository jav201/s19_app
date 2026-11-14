# Inc 1b — Clipboard: copy from every view: validation record (E5)

Batch 2026-11-05-batch-103, increment 1b. Branch `b103-inc1b-push`, base of the increment `dc44b364`, tree at this write `290d80ae` plus the records of this commit. Written by the close-out worker (relevo-9, P-003). Every outcome below cites a committed record; none is typed from memory.

**Verdict: OPEN.** Two sections are PENDING and the orchestrator fills them (see "PENDING" below). Everything else here is final.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| E4 GREEN on the Linux host | **122 passed, 19 skipped**, 141 nodes (112 cases + 28 acceptance cells + AT-I1b-8); the 19 skips are not counted as coverage | `evidence-e4/green-final-e8f8e3d1.txt` |
| E5 pre-CI GREEN (Linux) | **122 passed, 19 skipped in 1319.05 s** | `evidence-e5/pre-ci-green.txt` |
| E5 final targeted (Linux) | **246 passed, 2 skipped in 143.84 s** | `evidence-e5/final-targeted.txt` |
| E5 six families (Linux) | **160 passed, 96 skipped in 1480.54 s** (the WinCI-only nodes skip on Linux) | `evidence-e5/full-six-families-final.txt` |
| E5 law guards (Linux) | **6 failed, 671 passed, 3 skipped in 1665.99 s** (serial battery); the base before E4 (`e2e93548`) had 5 failed and the corrected tree rechecked at 5 failed / 1 passed; the 6th, TC-B97-69, was seen once, ruled not an Inc 1b regression and not labelled flaky (20/20 isolated on head and base), an open intermittent of the law battery (`E5-law-rulings.md`, `E5-b97-69-ruling.md`) | `evidence-e5/laws-final.txt` |
| PowerShell static check | **1 passed** | `evidence-e5/powershell-static-green.txt` |
| Linux mutants on `287b9dc3` | 69 L mutants: **67 KILLED, 1 SURVIVED (GA-A11, equivalent), 1 blocked by design (GC-C14)**; GT-T06 survived run 3 and was KILLED in run 4 after the manifest selection was corrected | `evidence-e5/mutants/VALIDATION.md` |
| WinCI N=10 on `7804b500` | R-PASTE.14/101 /102 /103 and C1[key\|right\|row] **0/10 failures**; R-PASTE.13/101 failed 1/10; C2 (control) failed 7/10 (it asserted then) | `E5-winci-7804b500-n10.md` |
| WinCI N=10 on `3c064348` | gated R-PASTE.14 nodes **0/10**; 8 success, 2 failure; R-PASTE.13/101 **2/10**; C2 report-only, lateness over 0.200 s in 6/10, each with one gen-2 GC; `at_passed=28/28` in every run | `E5-winci-3c064348-n10.md` |
| WinCI N=10 on `53bd5fc8` (test-only diagnostic) | 9 valid runs all green (216 passed, 108/108 obligations, `at_passed=28/28`); run 43540344655 is infrastructure (runner clipboard probe `powershell-read-exception`), not a test result; the diagnostic caught no failing run, so the cause of R-PASTE.13/101 stays open | `E5-winci-53bd5fc8-n10.md`, `E5-winci-r13-101-diagnostic.md` |
| WinCI earlier rounds | run 43438310100: 4 failed, 208 passed, 44 skipped (three test defects, no product change); run 43460552606: 6 failed, 206 passed, 44 skipped (P-002 teardown race, fixed in `051d5897`); run 43505344381 (round 4): every failing R-PASTE.14 node stalls in one gen-2 GC on the loop thread, a harness cost | `E5-winci-43438310100-diagnosis.md`, `E5-winci-43460552606-round2.md`, `E5-winci-43505344381-round4.md` |
| Real Windows Terminal captures (HT-10) | 8 PNGs, 4 surfaces at 118x54 and 220x60, truecolor, all sidecars `surface=ready` | `evidence-e5/captures/` |

## Ledger

The case ledger (`02-test-cases.md`) was updated in place with the executed WinCI results and a section "E5 ledger update: WinCI executed results" lists every changed cell with its source record. Summary: R-PASTE.14/101 ... /103 are `covered` / `verified (WinCI)`; the 14 P2 acceptance cells are `verified (WinCI)` (`at_passed=28/28`); R-PASTE.13/101 is `partial` / `intermittent`, **not verified**; the 74 `partial` rows stay `partial` because the WinCI manifest carries no per-row mapping; AT-I1b-8 stays manual and `not_run` (PENDING P-004). The requirements canon (`REQUIREMENTS.md`) holds no R-COPY row yet: the fold is a batch-end step, so the CANON check of the trace is not run here.

## Operator decisions this record rests on

The quit-dialog wording and the question variants were fixed by the operator's G2 round 2 verdict (`q3_body=B`, `q4_q=B`): `../evidence/G2/veredicto-b103-r2.json`. The captures below show that wording.

## Real captures (HT-10)

Real Windows Terminal windows on the work PC, `python -I -B`, truecolor (`COLORTERM=truecolor`, `NO_COLOR` removed), `PrintWindow` only, each window closed after its shot, scratch removed. State is isolated: `HOME`, `XDG_*` and `LOCALAPPDATA` point at a scratch folder. The operator's OS clipboard is never read or written: the driver replaces `write_os_clipboard` with a fixed True/False stub and the toolkit `App.copy_to_clipboard` with a mirror-only stub (so no OSC 52 request reaches the terminal). Everything above those two stubs is the product code. The copy entry is called directly with the third row's full tag name (the call a valid right-click on a row makes), not through a posted right-click; that is a declared deviation. Fixture: the tracked public `examples/case_00_public/prg.s19` and `ASAP2_Demo_V171.a2l`. A prototype render is not used here (HT-10).

| Surface | What it shows | 118x54 | 220x60 |
|---|---|---|---|
| copy-notice | OS write succeeds: information notice `Copied 1 line to the clipboard.` (R-COPY.7) | `evidence-e5/captures/copy-notice.118x54.png` | `evidence-e5/captures/copy-notice.220x60.png` |
| write-fail | OS write fails: warning `Clipboard write failed - copied inside the app only.` (R-PASTE.9) | `evidence-e5/captures/write-fail.118x54.png` | `evidence-e5/captures/write-fail.220x60.png` |
| nul-refusal | payload holds U+0000: warning `Clipboard copy refused - NUL cannot be represented in the Windows text clipboard.`, no write (R-COPY.25) | `evidence-e5/captures/nul-refusal.118x54.png` | `evidence-e5/captures/nul-refusal.220x60.png` |
| quit-dialog | Ctrl+C with nothing selected opens `Quit?` / `Quit the app? Nothing is selected to copy.` with `Quit (y)` and the emphasised `Stay (n)` (R-COPY.16, R-COPY.18) | `evidence-e5/captures/quit-dialog.118x54.png` | `evidence-e5/captures/quit-dialog.220x60.png` |

Each PNG has a sidecar `<name>.png.txt` (notices read from the app, top screen, count and length of stubbed OS writes). The driver and wrapper are `evidence-e5/captures/capture_i1b_driver.py` and `capture_i1b.ps1` (adapted from `inc-12/capture_windows.ps1`). Not shown: the mouse-driven right-click and drag themselves (a still image cannot show a gesture) and AT-I1b-8, which is the operator's manual check (PENDING P-004).

## Trace

See "Trace check" at the end of this record (the output of the skill's `trace_check.py`).

## PENDING: WinCI round 53bd5fc8 N=10 #2 (runs 43548669695...43548717495)

PENDING. The orchestrator fills this section from the tally of those runs. No outcome is written here.

## PENDING: P-101 re-review verdict

PENDING. The final code/security re-review and independent coverage on the final tree (reviewer record `E5-rereview-final.md`), then `redact_e5.py`, `redact_e5.py --check` and `evidence-e5/refresh_manifests.py --check` (DF-06). The orchestrator fills this section. No verdict is written here.

## Other open items (not this record's to close)

P-001 (R-PASTE.13/101 intermittent, cause open), P-004 (AT-I1b-8, the operator's), P-005 (GW-W01 ... 04 WinCI-only mutants; GC-C14 blocked by design), P-103 does not belong to Inc 1b.

## Trace check

Command, run on the PC under `python -I -B` (the checker imports no app code; HT-01), from the repository root, with the Inc 1b files staged:

```text
python -I -B ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-1b/01-requirements.md --base dc44b364 --src s19_app
TEST   R-COPY.3 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-COPY.5 is named by no file under tests, and neither is a TC/AT id it lists
trace_check: 1 US, 26 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 2 gap(s)
exit=1
```

Reading: US, CASE, SLICE and EVID pass. The two TEST gaps are R-COPY.3 and R-COPY.5, which the E1 addendum withdrew by striking the rows through (`~~`); the checker only honours a "— Withdrawn" mark, so it counts them as active (26 active = 24 + these 2). They are withdrawn rows with withdrawn cases (`02-test-cases.md`), not missing tests. `01-requirements.md` is not edited to silence the checker (PP-06). CANON is not run: the canon fold is a batch-end step.
