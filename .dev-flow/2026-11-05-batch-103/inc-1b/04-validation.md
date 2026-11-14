# Inc 1b — Clipboard: copy from every view: validation record (E5)

Batch 2026-11-05-batch-103, increment 1b. Branch `b103-inc1b-push`, base of the increment `dc44b364`, tree at this write `290d80ae` plus the records of this commit. Written by the close-out worker (relevo-9, P-003). Every outcome below cites a committed record; none is typed from memory.

**Verdict: PASS-WITH-NOTES.** WinCI round #3 on `b2d6eb25`: R-PASTE.13/101 0/10 and every gated node 0/10; re-review PASS-WITH-NOTES; DF-06 checks PASS after the residual was cleared (section below); trace 0 gaps. Visible items (the 8 captures; AT-I1b-8) are decided provisionally on the final review page (P-059).

_Superseded verdict (Z1, 22:37):_ **Verdict: OPEN.** Reason: `redact_e5.py --check` on the current tree FAILS (residual 1: the synthetic payload `VISIBLE<NUL>SECRET-SUFFIX` in `evidence-e5/captures/capture_i1b_driver.py`, added after 53bd5fc8). Everything else passes: WinCI round #3 on `b2d6eb25` shows R-PASTE.13/101 0/10 and every gated node 0/10, the re-review is PASS-WITH-NOTES, the manifest check passes and the trace has 0 gaps. It becomes PASS-WITH-NOTES when that one residual is cleared and the check is re-run. Visible items (the 8 captures; AT-I1b-8) are awaiting the operator's verdict on the final review page.

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

## WinCI rounds #2 (53bd5fc8) and #3 (b2d6eb25)

**Round #2, 53bd5fc8, N=10** (runs 43548669695...43548717495; record `E5-winci-53bd5fc8-n10-2.md`, commit 0dd75cd3): 10 valid runs, every gated node 0/10 except **R-PASTE.13/101, 2/10** (runs 43548702062, 43548712365; obligations 107/108). RR-1 **confirmed** (hypothesis H5): in both failing captures `notify` had returned but `Notifications.add` ran 0.266 s and 0.593 s later, after the first snapshot (`raw_count=0`, `queue_size=2`); the notice appeared only at the settled snapshot. A test-side race, not a product defect. Pre-fix rate over all diagnosed or undiagnosed sets: 5/39.

**Round #3, b2d6eb25, N=10** (runs 43553568285 push, 43553575808, 43553577902, 43553579975, 43553582313, 43553584805, 43553586953, 43553589381, 43553591762, 43553594052; record `E5-winci-b2d6eb25-n10.md`): the base carries the test-only RR-1 fix (a bounded wait for the queued notice, bound/text/severity unchanged). All 10 runs `success`, `WINCI_GATE_RESULT PASS violations=0`, 216 passed / 44 skipped, obligations 108/108, acceptance 28/28, artifact-safety PASS.
- **R-PASTE.13/101: 0/10** after the fix (reported on its own; the fix changes the test). Every other gated node 0/10.
- `r13_101_diag` in all ten: `notice_wait_s` 0.0 to 0.093 s (9 runs 0.0, 1 run 0.093 s); notify-to-add delay 0 in all ten; the first read came after the add in all ten (15 to 93 ms). The 0.27 to 0.59 s lag of round #2 did not recur, so the wait was exercised only to 0.093 s on WinCI; its absorption of larger lags rests on the Linux-seam controls (`E5-rereview-final.md` section 7).
- C2 (report-only) exceeded 0.200 s in 8 of 10 runs (0.247 to 0.419 s), as in round #2; nothing is asserted on it.
- PP-04 against round #2: R-PASTE.13/101 gone (2 -> 0); no new failing node.
- With a pre-fix rate near 0.13, P(0 in 10) is about 0.25 without any effect of the fix, so 0/10 alone does not prove it; the evidence is the confirmed mechanism, the controls and this clean round (HT-07).

## P-101 re-review verdict

Record `E5-rereview-final.md` (code-reviewer, one pass, commit 265df693): **PASS-WITH-NOTES**, no HIGH. DF-06 checks PASS at 53bd5fc8 (`REDACTION_CHECK PASS files=295 residual=0 exceptions=8`; `MANIFEST_VERIFY_RESULT PASS manifests=6 files=83`). RR-1 (MEDIUM) was confirmed by round #2 and fixed test-only in b2d6eb25 (section 7 of that record; controls on the Linux seam: drop-notify FAIL, +3.5 s FAIL, unmutated PASS, +0.5 s PASS). RR-2, RR-3, RR-4 (LOW) stay open items (below).

**DF-06 re-run on the current tree** (records changed after 53bd5fc8; `python -I -B` on the PC, read-only `--check` modes, the E4 refresh script not run), at tip 11610b70:

```text
PRE_RULE canary_prefix hits=1
PENDING captures/capture_i1b_driver.py replacements=1
EXCEPTION matrix/contract_probe.py retained=5
EXCEPTION quit/validate_routes.py retained=2
EXCEPTION legacy/redaction_runtime_probe.py retained=1
REDACTION_CHECK FAIL files=305 residual=1 exceptions=8
MANIFEST_VERIFY_RESULT PASS manifests=6 files=83
```

Reading: the `files` count grew 295 -> 305 because the close-out commit c66f467f added `evidence-e5/captures/` (8 PNG, 8 sidecars, driver, wrapper). The one residual is the string `VISIBLE<NUL>SECRET-SUFFIX` at `capture_i1b_driver.py:110`, a synthetic test payload that matches rule `canary_prefix` (`SECRET-[A-Z0-9-]+`). It is not a leak (it is the copy-with-NUL test input), but the check is a gate and it fails. This record does not edit the driver (it produced the committed captures; changing it is a decision for the orchestrator: reword the payload and note it, or add the file to the exceptions with a reason). The manifests pass.

## Other open items (not this record's to close)

- **P-001** (R-PASTE.13/101): cause found (test-side race, H5), fixed in b2d6eb25, post-fix rate 0/10 (`E5-winci-b2d6eb25-n10.md`); pre-fix 5/39.
- **RR-2** (LOW): no Linux test pins the `[t_start, t_end]` tick window; narrowing it is caught only on WinCI by the >= 10 ticks rule.
- **RR-3** (LOW): `raise AssertionError(...) from None` in the R-PASTE.13/101 wrappers drops the original traceback (the message stays unique).
- **RR-4** (LOW, records): `steps.log` entries of 2026-11-13 06:31 and 06:32 say `files=304`; the committed tree reports `files=295` (the earlier count included untracked files). Correction by this note only; `steps.log` is append-only and the lines are not edited (PP-06).
- **P-004** (AT-I1b-8, the operator's), **P-005** (GW-W01 ... 04 WinCI-only mutants; GC-C14 blocked by design), canon fold at batch end. P-103 does not belong to Inc 1b.
- ~~New: the DF-06 residual above~~ — cleared. Orchestrator ruling (relevo-11, DF-04 a): the driver's tail was renamed to `HIDDEN-TAIL` with an in-file note (the refusal depends only on the NUL; the payload text appears in no capture or sidecar). Not an exception in `redact_e5.py`: that file is pinned in `evidence-e5/SHA256SUMS.txt`. Re-run: `REDACTION_CHECK PASS files=305 residual=0 exceptions=8`; `MANIFEST_VERIFY_RESULT PASS manifests=6 files=83`.

## Trace check

Command, run on the PC under `python -I -B` (the checker imports no app code; HT-01), from the repository root, after the E5 close-out reworded R-COPY.3/.5 as "Withdrawn" (commit 03c59d62):

```text
python -I -B ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-1b/01-requirements.md --base dc44b364 --src s19_app
trace_check: 1 US, 24 active requirements (2 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
exit=0
```

CANON is not run: the canon fold is a batch-end step.
