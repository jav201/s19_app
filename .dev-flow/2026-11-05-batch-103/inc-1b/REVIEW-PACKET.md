# Inc 1b — Review packet (7 sections)

Batch 2026-11-05-batch-103, increment 1b: copy from every view (US-103-01). _Previous close-out, historical:_ branch `b103-inc1b-push`, base `dc44b364`, tree `290d80ae` plus its records (relevo-9, P-003). **Documentary close:** branch `b103-inc1b-close` from published `caae1bf9`; the tested P-001 WinCI tree is `b2d6eb25`, while mutant executors ran at `db4a8ebc` and `0271fe71`. This documentary commit is not a newly tested product tree. The validation record is `04-validation.md`; the requirements, `01-requirements.md`; the cases and ledger, `02-test-cases.md`.

**Status: PASS-WITH-NOTES.** WinCI round #3 on `b2d6eb25` R-PASTE.13/101 0/10 and every gated node 0/10; re-review PASS-WITH-NOTES; DF-06 CLEARED after the historical residual fix; trace 0 gaps. P-005 executed **4/4 KILLED**, bringing the final total to **71 KILLED / 1 equivalent SURVIVED / 1 BAD by design**. **P-059 and all 8 captures are APPROVED by the operator** after review of the explorer and packet/captures («Aprobados.»). AT-I1b-8 stays manual `not_run`; no full-release acceptance is declared.

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

- Linux E4 historical baseline (the LAN host, isolated env): the four files `test_b103_copy_views.py`, `test_b103_clipboard_tail.py`, `test_b103_copy_quit_dialog.py`, `test_b103_copy_paste_matrix.py`; **141 = 122 passed + 19 skipped** (`evidence-e4/green-final-e8f8e3d1.txt`). This is not the later mutant baseline.
- Linux later mutant admission baseline: **142 = 123 passed + 19 skipped**, after the GT-T06 selector correction; see `evidence-e5/mutants/VALIDATION.md`. The 19 skips are not coverage.
- WinCI: the `clipboard-windows` job; its gate line is `WINCI_GATE tests=260 passed=216 failed=0 errors=0 skipped=44 obligations_passed=108/108 at_passed=28/28`.
- Visual: the 8 PNGs in `evidence-e5/captures/`; to regenerate, run `capture_i1b.ps1` (needs Windows Terminal and the `s19env` Python); it isolates state and never touches the clipboard.
- Operator (manual, not run): AT-I1b-8, six Windows Terminal steps (PENDING P-004).

## 4. Test results

State words per `/dev-flow`: `executed`, `not-run`, `blocked`, `planned`.

| Check | State | Record |
|---|---|---|
| Linux E4 GREEN, historical 141 nodes | executed: 122 passed, 19 skipped | `evidence-e4/green-final-e8f8e3d1.txt`, `evidence-e5/pre-ci-green.txt` |
| Linux later mutant baseline, 142 nodes | executed: 123 passed, 19 skipped | `evidence-e5/mutants/VALIDATION.md` |
| Final targeted selection | executed: 246 passed, 2 skipped | `evidence-e5/final-targeted.txt` |
| Six families | executed: 160 passed, 96 skipped | `evidence-e5/full-six-families-final.txt` |
| Law guards | executed: 6 failed, 671 passed (5 failed on the base; the 6th, TC-B97-69, is an open intermittent outside Inc 1b) | `evidence-e5/laws-final.txt`, `E5-b97-69-ruling.md` |
| Linux mutants | executed: 67 KILLED / 1 SURVIVED (equivalent) / 1 blocked, of 69 | `evidence-e5/mutants/VALIDATION.md` |
| WinCI P-005 mutants | executed: **4/4 KILLED**; final total 71 KILLED / 1 equivalent SURVIVED / 1 BAD by design | `evidence-e5/mutants/VALIDATION.md`; runs 43911226514 and 43912736749 |
| WinCI N=10 on `7804b500`, `3c064348`, `53bd5fc8` (N=9 valid) | executed; gated R-PASTE.14 nodes 0 failures in 29 valid runs; R-PASTE.13/101 failed 1/10, 2/10, 0/9 | `E5-winci-7804b500-n10.md`, `E5-winci-3c064348-n10.md`, `E5-winci-53bd5fc8-n10.md` |
| Real captures, 4 surfaces x 2 sizes | executed: 8/8 `surface=ready`; **operator APPROVED P-059 and all 8 captures** («Aprobados.») | `evidence-e5/captures/*.png.txt` |
| WinCI round #2, `53bd5fc8` N=10 | executed; R-PASTE.13/101 2/10 (43548702062, 43548712365), every other gated node 0/10; RR-1 confirmed (H5) | `E5-winci-53bd5fc8-n10-2.md` |
| WinCI round #3, `b2d6eb25` N=10 (post-fix) | executed; **R-PASTE.13/101 0/10**, every gated node 0/10, 10/10 PASS 108/108; `notice_wait_s` 0.0 to 0.093 s | `E5-winci-b2d6eb25-n10.md` |
| P-101 re-review | executed: PASS-WITH-NOTES, no HIGH; RR-1 MEDIUM fixed, RR-2..RR-4 LOW open | `E5-rereview-final.md` |
| DF-06 at 53bd5fc8 | executed: `redact_e5 --check` PASS files=295 residual=0; manifests PASS 6/83 | `E5-rereview-final.md` section 4 |
| DF-06 pre-fix historical output | executed then: FAIL files=305 residual=1; subsequently CLEARED after the driver rename, PASS files=305 residual=0 exceptions=8; manifests PASS 6/83 | `04-validation.md` |
| Trace check | executed: 0 gaps (24 active, 2 withdrawn) | `04-validation.md` |
| AT-I1b-8 (operator) | not-run; awaiting the operator | PENDING P-004 |

## 5. Risks

- **R-PASTE.13/101**: cause found (test-side race, H5: the test read the notices before the app handled the queued Notify), fixed test-only in `b2d6eb25`; diagnosed pre-fix 2/10 and post-fix 0/10 on WinCI. The 0/10 round is not a zero-rate claim; the mechanism and Linux-seam controls carry the argument. The conservative `partial` / `intermittent` ledger state is not a current failure. Not called flaky (HT-07).
- The 74 `partial` ledger rows keep `partial`: the WinCI manifest has no per-row mapping, so the aggregate 108/108 cannot be split by row without inference.
- The R-PASTE.14 bound is held by `gc.freeze` plus a sleep-poll wait; control C2 shows the stall is a gen-2 GC on the loop thread (a test-harness cost). Holding the bound without that workaround is an operator decision (DF-04).
- Captures stub the OS write and OSC 52 and call the copy entry directly; a still cannot show a right-click gesture. The real gesture is AT-I1b-8, which the operator runs.
- **DF-06 historical residual, now CLEARED**: the pre-fix `redact_e5.py --check` failed on one synthetic payload (`VISIBLE<NUL>SECRET-SUFFIX`, `capture_i1b_driver.py:110`). The rename to `HIDDEN-TAIL` cleared it; the old FAIL is not a current gate result.
- Run 43540344655 failed on runner infrastructure (clipboard probe); it is excluded from the tallies, not counted as a pass.
- B97-69 (open intermittent in the serial law battery) and the inherited law failures are outside this increment.

## 6. Pending items

- **P-004** (AT-I1b-8, the operator's) remains manual `not_run`. **P-059 and all 8 captures are APPROVED by the operator** («Aprobados.») after review of the explorer and packet/captures. Canon fold and the separate G3 batch-end gate remain pending; no full-release acceptance is declared.
- **P-005 is closed as executed**: 4/4 KILLED. GC-C14 remains BAD/blocked by design, and GA-A11 remains an equivalent SURVIVED.
- **P-001**: cause found (H5), fixed in `b2d6eb25`, diagnosed pre-fix 2/10 and post-fix 0/10; conservative partial/intermittent status is retained.
- **RR-2** (LOW): no Linux test pins the `[t_start, t_end]` tick window. **RR-3** (LOW): `from None` drops the traceback. **RR-4** (LOW, records): `steps.log` 06:31 and 06:32 say `files=304`, the tree says 295; `steps.log` is append-only, corrected by the note in `04-validation.md`.
- **DF-06 residual**: CLEARED. Historical pre-fix FAIL was followed by `REDACTION_CHECK PASS files=305 residual=0 exceptions=8`; `MANIFEST_VERIFY_RESULT PASS manifests=6 files=83`.

## 7. Suggested next task

Obtain only the operator's six-step manual AT-I1b-8 acceptance (P-004), which remains `not_run`; after that acceptance, evaluate the separate G3 batch-end gate. Do not start G3 as part of this P-059 visual approval.
