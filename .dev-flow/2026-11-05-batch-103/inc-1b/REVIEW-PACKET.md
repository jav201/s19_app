# Inc 1b — Review packet (7 sections)

Batch 2026-11-05-batch-103, increment 1b: copy from every view (US-103-01). Branch `b103-inc1b-push`, base of the increment `dc44b364`, tree `290d80ae` plus the records of the close-out commit. Draft by the close-out worker (relevo-9, P-003). The validation record is `04-validation.md`; the requirements, `01-requirements.md`; the cases and ledger, `02-test-cases.md`.

**Status: OPEN.** Reason: `redact_e5.py --check` on the current tree fails with residual 1 (a synthetic payload in `evidence-e5/captures/capture_i1b_driver.py`, added after 53bd5fc8). Everything else passes: WinCI round #3 on `b2d6eb25` R-PASTE.13/101 0/10 and every gated node 0/10; re-review PASS-WITH-NOTES; trace 0 gaps. The status becomes PASS-WITH-NOTES when that residual is cleared and the check is re-run. The 8 captures and AT-I1b-8 await the operator's verdict on the final review page.

## 1. What changed

- A copy outside a text box now reaches the OS clipboard and the app clipboard, and sends one OSC 52 request: Ctrl+C on a view selection, a right-click on a view selection, a right-click on a row of the A2L tag table or the MAC table (the row's full name, not the painted cell). 24 active requirements (R-COPY.1 ... .26, minus the withdrawn .3 and .5).
- One notice per copy (`Copied <n> line(s) to the clipboard.`); a copy longer than 65,536 characters is cut with the cut notice; a payload with NUL is refused with a warning and leaves both clipboards unchanged.
- Ctrl+C with nothing selected opens a quit dialog (`Quit?`, `Stay (n)` emphasised); `q` opens the same dialog; Ctrl+Q and the palette Quit exit at once; with a session action running, the busy quit question is shown instead.
- A valid right-click on a table row highlights it and leaves the hex views alone; empty, cancelled and dragged right-button gestures change nothing and show nothing.
- E5 corrections after the first WinCI runs: three test defects fixed (`bf43ec2f`), a teardown guard in the A2L filter refresh (`051d5897`, R-COPY.26, P-002), the R-PASTE.14 responsiveness test made sleep-poll with `gc.freeze` (`7804b500`), C1/C2 controls (`da92a0c5`, `5d2da968`), a test-only diagnostic for R-PASTE.13/101 (`53bd5fc8`), and the test-only RR-1 fix (`b2d6eb25`: R-PASTE.13/101 waits for the queued notice).
- This close-out: real captures, ledger update, trace, trailing whitespace of two manifests (P-104).

## 2. Files modified

Product (Inc 1b squashed in `541a3d50`, plus the E5 guard `051d5897`): `s19_app/tui/app.py`, `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`, and the dialog code; the exact list is `git diff --stat dc44b364 HEAD -- s19_app`. Tests: `tests/test_b103_copy_views.py`, `tests/test_b103_clipboard_tail.py`, `tests/test_b103_copy_quit_dialog.py`, `tests/test_b103_copy_paste_matrix.py`, `tests/support/b103_winci_manifest.json`, the WinCI workflow. Records of this close-out commit: `02-test-cases.md`, `04-validation.md`, this file, `evidence-e4/{matrix,tail}/SHA256SUMS`, `evidence-e5/captures/` (8 PNG, 8 sidecars, driver, wrapper), `steps.log`. The source-file count against the 4-file cap was declared at E1/E4 and is not re-opened here.

## 3. How to test

- Linux (the LAN host, isolated env): the four files `test_b103_copy_views.py`, `test_b103_clipboard_tail.py`, `test_b103_copy_quit_dialog.py`, `test_b103_copy_paste_matrix.py`; expected `122 passed, 19 skipped` (`evidence-e4/green-final-e8f8e3d1.txt`). The 19 skips are the WinCI-only nodes, the P2 cells and AT-I1b-8.
- WinCI: the `clipboard-windows` job; its gate line is `WINCI_GATE tests=260 passed=216 failed=0 errors=0 skipped=44 obligations_passed=108/108 at_passed=28/28`.
- Visual: the 8 PNGs in `evidence-e5/captures/`; to regenerate, run `capture_i1b.ps1` (needs Windows Terminal and the `s19env` Python); it isolates state and never touches the clipboard.
- Operator (manual, not run): AT-I1b-8, six Windows Terminal steps (PENDING P-004).

## 4. Test results

State words per `/dev-flow`: `executed`, `not-run`, `blocked`, `planned`.

| Check | State | Record |
|---|---|---|
| Linux GREEN, 141 nodes | executed: 122 passed, 19 skipped | `evidence-e4/green-final-e8f8e3d1.txt`, `evidence-e5/pre-ci-green.txt` |
| Final targeted selection | executed: 246 passed, 2 skipped | `evidence-e5/final-targeted.txt` |
| Six families | executed: 160 passed, 96 skipped | `evidence-e5/full-six-families-final.txt` |
| Law guards | executed: 6 failed, 671 passed (5 failed on the base; the 6th, TC-B97-69, is an open intermittent outside Inc 1b) | `evidence-e5/laws-final.txt`, `E5-b97-69-ruling.md` |
| Linux mutants | executed: 67 KILLED / 1 SURVIVED (equivalent) / 1 blocked, of 69 | `evidence-e5/mutants/VALIDATION.md` |
| WinCI N=10 on `7804b500`, `3c064348`, `53bd5fc8` (N=9 valid) | executed; gated R-PASTE.14 nodes 0 failures in 29 valid runs; R-PASTE.13/101 failed 1/10, 2/10, 0/9 | `E5-winci-7804b500-n10.md`, `E5-winci-3c064348-n10.md`, `E5-winci-53bd5fc8-n10.md` |
| Real captures, 4 surfaces x 2 sizes | executed: 8/8 `surface=ready` | `evidence-e5/captures/*.png.txt` |
| WinCI round #2, `53bd5fc8` N=10 | executed; R-PASTE.13/101 2/10 (43548702062, 43548712365), every other gated node 0/10; RR-1 confirmed (H5) | `E5-winci-53bd5fc8-n10-2.md` |
| WinCI round #3, `b2d6eb25` N=10 (post-fix) | executed; **R-PASTE.13/101 0/10**, every gated node 0/10, 10/10 PASS 108/108; `notice_wait_s` 0.0 to 0.093 s | `E5-winci-b2d6eb25-n10.md` |
| P-101 re-review | executed: PASS-WITH-NOTES, no HIGH; RR-1 MEDIUM fixed, RR-2..RR-4 LOW open | `E5-rereview-final.md` |
| DF-06 at 53bd5fc8 | executed: `redact_e5 --check` PASS files=295 residual=0; manifests PASS 6/83 | `E5-rereview-final.md` section 4 |
| DF-06 on the current tree | executed: `redact_e5 --check` **FAIL** files=305 residual=1; `refresh_manifests --check` PASS 6/83 | `04-validation.md` |
| Trace check | executed: 0 gaps (24 active, 2 withdrawn) | `04-validation.md` |
| AT-I1b-8 (operator) | not-run; awaiting the operator | PENDING P-004 |
| GW-W01 ... 04 mutants (WinCI-only) | not-run | PENDING P-005 |

## 5. Risks

- **R-PASTE.13/101**: cause found (test-side race, H5: the test read the notices before the app handled the queued Notify), fixed test-only in `b2d6eb25`; post-fix 0/10 on WinCI (pre-fix 5/39). With a pre-fix rate near 0.13, 0/10 alone is not proof (P(0 in 10) about 0.25 with no effect); the mechanism and the Linux-seam controls carry the argument. The lag of round #2 (0.27 to 0.59 s) did not recur in round #3, so a larger lag was not exercised on WinCI. Stays `partial` in the ledger until the operator and the batch end decide. Not called flaky (HT-07).
- The 74 `partial` ledger rows keep `partial`: the WinCI manifest has no per-row mapping, so the aggregate 108/108 cannot be split by row without inference.
- The R-PASTE.14 bound is held by `gc.freeze` plus a sleep-poll wait; control C2 shows the stall is a gen-2 GC on the loop thread (a test-harness cost). Holding the bound without that workaround is an operator decision (DF-04).
- Captures stub the OS write and OSC 52 and call the copy entry directly; a still cannot show a right-click gesture. The real gesture is AT-I1b-8, which the operator runs.
- **DF-06 residual**: `redact_e5.py --check` fails on one synthetic payload (`VISIBLE<NUL>SECRET-SUFFIX`, `capture_i1b_driver.py:110`); not a leak, but a failing gate until the payload is reworded or the file is made an exception.
- Run 43540344655 failed on runner infrastructure (clipboard probe); it is excluded from the tallies, not counted as a pass.
- B97-69 (open intermittent in the serial law battery) and the inherited law failures are outside this increment.

## 6. Pending items

- **DF-06 residual** (new): clear `capture_i1b_driver.py:110` (reword the payload with a note, or add an exception with a reason), re-run `redact_e5.py --check`, then set the verdict.
- **P-001**: cause found (H5), fixed in `b2d6eb25`, post-fix rate 0/10 (`E5-winci-b2d6eb25-n10.md`).
- **RR-2** (LOW): no Linux test pins the `[t_start, t_end]` tick window. **RR-3** (LOW): `from None` drops the traceback. **RR-4** (LOW, records): `steps.log` 06:31 and 06:32 say `files=304`, the tree says 295; `steps.log` is append-only, corrected by the note in `04-validation.md`.
- **P-004** (AT-I1b-8, the operator's); **P-005** (GW-W01 ... 04 WinCI-only mutants); canon fold at batch end.
- Visible items (the 8 captures; AT-I1b-8): awaiting the operator's verdict on the final review page.

## 7. Suggested next task

Clear the DF-06 residual and re-run `redact_e5.py --check`; if it passes, set the verdict of `04-validation.md` to PASS-WITH-NOTES. Then ask the operator for the AT-I1b-8 run (P-004) and the capture verdicts on the final review page, and decide the push (PP-01); next increment per `PLAN.md`.
