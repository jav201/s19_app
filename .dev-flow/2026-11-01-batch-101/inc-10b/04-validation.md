# Inc 10b — validation (E5)

**Verdict: PASS-WITH-NOTES.** The in-place write hook is fixed end to end: after an apply, a save-back or a Save project commit, the A2L tag table's Raw and Physical cells show the written values while the table's scroll, cursor, listed tags and page are kept (no `clear`); the main, A2L and MAC hex panes show the written bytes with their shown window, scroll and `> ` marker kept; a displayed Split / Join preview re-plans its band, stats and state line with the focus kept; and an armed export confirm is disarmed by every in-place write (`— e will ask`). The per-write A2L refresh was measured on `examples/case_06_large_nested_a2l` (220,040 tags): the E4 full refresh ran 3.952 s against the 1 s bound and failed, the corrective's partial recompute (only the tags whose bytes the write changed) ran 0.350 s / 1.000 s with 65.0 % margin on the final serial lane (re-review 0.360 s / 1.000 s, 64.0 %), and its enriched list is asserted equal to a full recompute. The mutant battery killed 15/15 on the pre-corrective tree (DeepSeek M1 … M8 plus the reused E4 controls M-A … M-F) and 11/11 on the final tree (the corrective's M-c02 … M-c12); the A10-08 arm is declared an equivalent mutant on every shipped route (QA-3). The review chain closed green: the E5 code+security review FAILed on R-1 (MAJOR, the unmeasured large-A2L cost), the corrective discharged it, and the re-review returned PASS-WITH-NOTES (RR-1 MINOR, RR-2 … RR-5 NIT). No BLOCKER / HIGH / MAJOR is open. The notes are records-only: two backlog rows (BL-I10b-1, BL-I10b-2) and the merge-time full suite. Branch `b101-inc10` at `68e9a084` plus the uncommitted E5 close records, this file and the increment packet. Platform: the LAN Linux hosts and laptop for every run; the Windows PC ran nothing that imports `s19_app` (no case of this increment has a Windows-only arm, so all 21 cases are `not_run` on Windows by the operator's rule).

## Runs

| Run | Result | Evidence |
|---|---|---|
| Tester W RED on base `09b4808` + Inc 10a (red-01) | **18 failed, 1 passed** in run 1 (the pass is R-SEG-PREV.21/2, the declared standing guard); run 2 (serial) **1 failed** (the QC-TM node on the missing method) | `../evidence/inc-10b/red-01-tester-w-base.txt` |
| E4 integration int-01a … int-07, LAN Linux laptop, trees `298f77fe…` / `5a4fdd38…` / `9cf01b02…` | **GREEN for the right reasons** on 10/10 rows: int-01 `460 passed, 1 xfailed` (12 files); int-01b `3 passed` (the corrected R-SEG-PREV.22/1); int-02 `1903 passed, 115 skipped, 2 xfailed, 2 failed` (both on the batch's known list); int-03 `31 passed`; int-04 `218 passed`; int-05 `24 passed, 1 skipped, 2720 deselected` (`QC-TM: 24 bounds, 0 under 20 % margin`, QC-TM-10b-1 0.023 s / 1 s at 462 tags); int-06 / int-06a / int-06b each repaint-sign control RED (M-A, M-B, M-C1 … M-C3, M-D, M-F — 0 survivors); int-07 `31 passed` | `../evidence/inc-10b/int-01.txt` … `../evidence/inc-10b/int-07.txt` |
| E5 corrective e5c-01 … e5c-14, LAN Linux laptop, final tree `43e7fcaf…` | e5c-02 the full refresh on case_06 `3.952 s / 1.000 s` (RED, −295.2 %); e5c-03 the partial recompute `0.370 s / 1.000 s` (63.0 %); e5c-04 the /4 precondition; e5c-05 `/4 + /5`; e5c-06 / e5c-07 / e5c-08 **W 21 passed ×3** (fresh process each); e5c-09 / e5c-10 / e5c-11 R-SEG-OPEN.6/3 (Inc 10a's case) `1 passed ×3`; e5c-12 the 7 law guards `218 passed`; e5c-13 serial `2 passed, 297 deselected`, QC-TM-10b-1 `0.350 s / 1.000 s, 65.0 %`; e5c-14 superseded (the law guard caught the QC-TM node's two-statement form) | `../evidence/inc-10b/e5c-01.txt` … `../evidence/inc-10b/e5c-14.txt` |
| E5 re-review RR-1 … RR-5, LAN Linux laptop, final tree `3e432888…` | e5c-rr-01 M-c05 RED (the filter lists 0 rows); e5c-rr-02 the row key `a2l:{i}` RED (Raw `47629`); e5c-rr-03 / -04 / -05 **W 21 passed ×3**; e5c-rr-06 the 7 law guards `218 passed`; e5c-rr-07 serial QC-TM-10b-1 `0.360 s / 1.000 s, 64.0 %` | `../evidence/inc-10b/e5c-rr-01.txt` … `../evidence/inc-10b/e5c-rr-07.txt` |
| Mutants | DeepSeek M1 … M8 fresh plus the reused M-A, M-B, M-C1 … M-C3, M-D, M-F: **15/15 killed** on the pre-corrective tree; corrective M-c02 … M-c12: **11/11 killed** on the final tree (one at a time); M-c01 is the base RED of the corrected bodies (not a mutant) | `../evidence/inc-10b/mut-01.txt` … `../evidence/inc-10b/mut-08.txt`, `../evidence/inc-10b/mut-c-01.txt` … `../evidence/inc-10b/mut-c-12.txt` |

Every integration and corrective transcript prints the base commit, the staged tree, `s19_app.__file__` (the clone or the mutant copy) and the exact command line; the mutant transcripts print the mutation diff as well. No run happened on the Windows PC (operator rule; no Windows-only arm).

## Per requirement

| Row | Verdict | Cases | Evidence — Linux | Evidence — Windows | Residual |
|---|---|---|---|---|---|
| R-A2L-048 (US-FRESH-3) | met — 5/5 | 048/1 … 048/5 | int-01, int-07, e5c-06/07/08; base RED (red-01, mut-c-01 for /4, /5); M-c04, M-c10, M-c11, M-c06, M-c03, M-c07 | — (no Windows-only arm; not_run, operator rule) | — |
| R-A2L-049 (US-FRESH-3) | met — 2/2 | 049/1, 049/2 | int-01, int-07, e5c-06/07/08; M-A (int-06), M-c04, M-c12 | — | — |
| R-A2L-105 (US-FRESH-3) | met — 1/1 | 105/1 | int-01, int-07, e5c-06/07/08; M-A (int-06), M-c04 | — | — |
| R-A2L-106 (US-FRESH-3) | met — 1/1 | 106/1 | int-01, int-07, e5c-06/07/08; M-F (int-06), M-c04, M-c12 | — | — |
| R-TUI-004.7 (US-FRESH-3) | met — 3/3 | 004.7/1 … /3 | int-01, int-07, e5c-06/07/08; M1 (mut-01), M-c10, M-c11 | — | — |
| R-TUI-004.8 (US-FRESH-3) | met — 3/3 | 004.8/1 … /3 | int-01, int-07, e5c-06/07/08; M-B (int-06), M8 (mut-08), M-c08, M-c09 | — | — |
| R-TUI-004.9 (US-FRESH-3) | met — 1/1 | 004.9/1 | int-01, int-07, e5c-06/07/08; M-C1, M-C2, M-C3 (int-06, one per view) | — | — |
| R-SEG-PREV.21 (US-FRESH-3) | met — 2/2 | PREV.21/1, /2 | int-01b, int-07, e5c-06/07/08; M3 (mut-03), M-c11; /2 a declared standing guard (red-01) | — | — |
| R-SEG-PREV.22 (US-FRESH-3) | met — 1/1 | PREV.22/1 | int-01b, int-07, e5c-06/07/08; M-D (int-06b; int-06a shows the delivered body passing, I-D5), M-c11, base RED of the corrected body (mut-c-01) | — | — |
| R-SEG-EXP.15 (US-FRESH-3) | met — 2/2 | EXP.15/1, /2 | int-01, int-07, e5c-06/07/08; M5 (mut-05), M6 (mut-06), M-c11 | — | — |

**21 cases: 21 `full`, 0 `partial`, 0 `gap`.** R-A2L-048/4 and /5 were added at E5 (QA-2 and R-4), so 19 cases grew to 21; both are `full` and 3/3. R-SEG-OPEN.6/3 (Inc 10a's case, re-run at 10b's E5 per `E1-rulings.md` §1) is 3/3 on the final tree (e5c-09 … e5c-11) but belongs to Inc 10a, not to this increment's 21. QC-TM-10b-1 is a measurement, not a coverage item: E4 462 tags 0.023 s / 1 s (97.7 %), then re-pointed to case_06's 220,040 tags — 3.952 s full (RED) → 0.370 s / 0.350 s partial, equal to a full recompute.

## Mutant score

**DeepSeek M1 … M8 (pre-corrective tree, base `6f1743c` + the diff): 8/8 killed, plus the 7 E4 controls reused (M-A, M-B, M-C1, M-C2, M-C3, M-D, M-F) → 15/15 killed (100 %).** Each mutation was applied one at a time in a fresh copy and killed at the clause it targets; M8 kills only the A2L and MAC arms of R-TUI-004.8, its `[main]` arm staying GREEN on 10a's no-focus clamp (not a gap — the two halves of the "shown window" are each pinned alone). **Corrective M-c02 … M-c12 (final tree `43e7fcaf…`, one at a time): 11/11 killed** — M-c02 the full refresh at every write (3.926 s, RED at the bound), M-c03 the first-byte-only changed-byte test (58 tags differ), M-c04 no tag recomputed (9 A2L nodes RED), M-c05 the recomputed list not installed, M-c06 `tags[i]`, M-c07 `update_width=False` (= M-W), M-c08 `_hex_window_start = 0` (= M-B2 main), M-c09 `start_row=None` (= M-B2 A2L/MAC), M-c10 the save-back hook call removed, M-c11 the commit hook call removed, M-c12 the listing replaced by every tag. The re-review re-ran M-c05 and the row key `a2l:{i}` against the new RR-1 / RR-4 assertions — both RED (e5c-rr-01, e5c-rr-02). **A10-08 (the Check Editor block back to `except Exception: return`) is declared an equivalent mutant on every shipped route** (the panel is composed at startup, `app.py:4779`; `App.query_one` searches the default screen, Textual 8.2.8 `app.py:941-943`) — QA-3, no node. Details: `E5-mutants.md`, `E5-corrective-notes.md` §3; transcripts `../evidence/inc-10b/mut-01.txt` … `mut-08.txt`, `mut-c-01.txt` … `mut-c-12.txt`, `e5c-rr-01.txt`, `e5c-rr-02.txt`.

## Reviews

- **E3 design (code-free, split from Inc 10):** 10b's rows were ruled in `../inc-10/E3-rulings.md` (S-1, A10-04, S-7 / A10-09, A10-08, A10-12, S-8). Architect round 2 **10b PASS-WITH-NOTES**; security round 2 **10b PASS**; round 3 closed SR2-1 / SR2-2 and **E3 closed for 10a and 10b** (`../inc-10/E3-rulings.md`). AR2-7 (the `update_width=True` widening and the local `Coordinate` import) folded into 10b.
- **E5 code + security review (one agent, Opus):** **FAIL — BLOCK-UNTIL R-1** (R-1 MAJOR the large-A2L refresh cost unmeasured; R-2 … R-6 MINOR). The product code was found correct on every write route; no HIGH. `E5-review.md`.
- **E5 coverage audit (qa-reviewer):** **PASS-WITH-NOTES** (QA-1 MAJOR the owed 3/3 runs; QA-2 MINOR the R2-7 widening case; QA-3 … QA-8 NIT). 19 `full`, 0 `partial`, 0 `gap`, no mark changed. `E5-coverage-audit.md`.
- **E5 corrective (Opus):** R-1 measured then built (the partial recompute), R-2 / R-4 / R-6 / QA-2 / QA-4 applied, R-3 and R-5 backlogged. `E5-corrective-notes.md`.
- **Re-review of the corrective (code-reviewer, independent of the corrective's author):** **PASS-WITH-NOTES** (RR-1 MINOR the cache install guarded only by the serial QC-TM node; RR-2 … RR-5 NIT). R-1 discharged by reading (the partial set equals a full recompute on the three write routes) and by measurement (3.952 s → 0.350 s, equal to a full recompute, mut-c-02 / -03 / -05 RED). `E5-review.md` re-review section.

## Admitted visible changes

- **The A2L tag table follows the write in place** (D-4 (a), A10-04): the Raw and Physical cells of the shown page are repainted from the recomputed tags (`update_cell_at(..., update_width=True)`), the row keys re-pointed, the summary label recomputed; no `clear()`, so the first shown row, the cursor, the listed tags and the page stay (R-A2L-048, -049, -105, -106).
- **The three hex panes follow the write** (S-1): the main view re-renders with no focus (one clamp keeps its window, scroll and `> ` marker); the A2L and MAC views re-render at the index of their first shown row; no scroll reset, no marker change (R-TUI-004.7, .8, .9).
- **A displayed Split / Join preview re-plans and its confirm disarms** (S-7 / A10-09): the band, stats and state lines show the written bytes, the focus stays, and an armed `e` becomes `— e will ask` (R-SEG-PREV.21, .22, R-SEG-EXP.15).

## Owed

Open residuals, one backlog id each (`E1-rulings.md` §4, `E5-rulings.md`):

- **BL-I10b-1** (E5 R-3, flagged for the batch-end review page): the Issues and Checks "Hex Peek" panes (`#issues_hex_pane`, `#checks_hex_pane`) keep the pre-write bytes after an in-place write until their row is selected again. The three hex views, the A2L values and Split / Join follow the write; nothing exports these panes. Fold into Inc 12 only if its integrator can do it without touching another file, otherwise the next batch.
- **BL-I10b-2** (E5 R-5): `_repaint_a2l_tag_cells` copies `update_a2l_tags_view`'s page bounds, row styling and summary text; share them (for example `_a2l_tags_summary_text(...)` and `_styled_a2l_cells(...)`) so the two painters cannot drift. Refactor, next batch.

- **Merge-time full suite:** this increment ran its slice, the QC-BC set, the other importers, the law guards and the serial lane on the LAN Linux hosts/laptop, but not all nodes in one lane; the batch-end battery runs the full suite once.

## Trace

`trace_check.py --req 01-requirements.md --base 569e446 --src s19_app` at close: `trace_check: 1 US, 10 active requirements (0 withdrawn), 0 gap(s)`. Every evidence citation in this record is a full committed path under the batch's evidence home.
