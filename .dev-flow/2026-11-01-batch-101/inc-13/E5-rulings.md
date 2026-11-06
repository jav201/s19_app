# Inc 13 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES; E5-CR-1 = E4-F1 MAJOR design-gap; CR-2 MINOR; CR-3…CR-5 NIT), E5-security.md (PASS-WITH-NOTES; F-1, F-2 LOW; F-3…F-5 INFO), E5-coverage-audit.md (17/39 changed), E5-mutants.md (DeepSeek: 24/25 killed, M-12 equivalent, one control N/A pending E4-F1).

## Corrective pass (binding)

| Id | Ruling |
|---|---|
| C-1 | E4-F1 / E5-CR-1 (D17-27): `segment_split_view._state_text` is added to the slice (same file). The conflict check comes before the guard check, per canon R-SEG-PREV.7/.8. RED first with a direct test node (F-23 Split/Join scene → the "would clobber source" line), then GREEN; flip R-SEG-PREV.20/1's state-line assertion to the canon line; R-SEG-PREV.7/1 becomes runnable; run the R-SEG-PREV.7 negative control that was N/A. Existing GUARD tests (scenes without conflict bytes) stay GREEN. |
| C-2 | E5-CR-2: `_sweep`'s skip of empty/inverted marks gets the graph's three hand examples as a direct test. |
| C-3 | Audit results: R-SEG-PREV.7/1 and .20/1 results follow the new run; the four timing rows get 5/5 runs on the LAN host (serial lane, quiet host) — record each time; the 20 % margin stays a reported value (QC-TM), not an assertion. |
| C-4 | Audit marks: 007.3/1 and 007.2/1 start from a form that differs from the target in the asserted fields (or stay partial with the reason); 001.1/1 asserts the full values on both surfaces (or partial); the three substring-only tests inside 001.5/1, 001.8/1 tightened or marked. |
| C-5 | M-12 is equivalent (the sweep already coalesces adjacent equal blocks): drop it from R-SEG-PREV.2/2's controls and record why. |
| C-6 | Stale values: the cap 16777216 everywhere (graph lines, E1-slice row 18, E1-rulings M-0); 001.1/1 states 45 vectors and widths 12 and 24 as run (or the test widens to the stated 200 / 8–64); the integration notes' swapped base times corrected. |
| C-7 | Audit: the 5 uncovered clauses get a case or a not-testable ruling; the 7 owed black-box ATs (Designer and Split/Join through keys/dialogs) are added, or partial with the reason where no key route exists. |
| C-8 | CR-3…CR-5 NITs as cheap fixes; security F-2 (coverage line bounded per range, not total) recorded in the rulings as accepted (each range is bounded; total is ranges × bound). |

## Routed to BACKLOG-CODE (append, batch-101 style)

| Id | Item |
|---|---|
| Security F-1 (LOW) | `_conflict_marks` on a hostile alternating pad/non-pad 16 MiB image: 3.6 s vs 2.2 s base; output identical (with SEC-7). |
| Security F-3 (INFO, pre-existing) | Textual Input renders a pasted ESC raw. |
| `test_tc_b97_69` | Flake under `-n 12` ("A2L loaded did not settle"); cause not established. |

Runs: the LAN Linux host (the laptop; fish login shell → `bash -lc`); LAN host 2 is not answering ssh. (Account and address redacted at the corrective pass.)

## Recorded at the corrective pass (2026-11-06)

- **Security F-2 (LOW, accepted, C-8).** Line 1 of the coverage window is bounded per range and per forward gap (at most about 48 glyphs each), not in total: the total is ranges × that bound, linear in the Ranges text the operator types (3000 full-space ranges drew 144 000 glyphs in 0.47 s and were refused by the cap). No MemoryError path exists. Accepted as is; no row or backlog item.
- Outcomes of C-1 … C-8: `E5-corrective-notes.md`.
