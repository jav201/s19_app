# Inc 8b — E3 rulings (orchestrator)

Pre-rulings 1–11 are in `codewire/interfaces-8b.md`. Round 1: architect FAIL (A3-1, A3-2, A3-3 MAJOR; A3-4…A3-17), security FAIL (S3-1 MAJOR; S3-2…S3-10).

## Round 1 rulings
- **R1 (S3-1):** the plan refuses a save as whose copy list exceeds 2 000 files or whose tree is deeper than 32 path components — before any folder exists, naming the count; new requirement LLR-171.1j (unwanted form) with threshold + mutant. A background copy with progress and cancel stays with Inc 12a.
- **R2 (A3-1):** the sub-folder copy runs right after the target folder is created, before the first home placement (the rows loop) and before the gather. Pre-ruling 8 reads "before the first home placement and before the gather".
- **R3 (A3-2):** a save as also copies every top-level regular file of P that the save does not write itself (not the image / MAC / A2L rows, not `project.json`, not a link) — Q is the whole project and its carried `batch` / `assignments` name files Q holds. LLR-171.1 statement and threshold updated; the copy list includes them; the free-space total counts them.
- **R4 (A3-3, C-7 confirmed):** for every target (new, open project, merge, save as), `batch` and `assignments` are the dialog's selection when non-empty, otherwise the carried value; the gather list is fed from the same resolved `batch`. One requirement arm (Load P → Save P → `batch` unchanged; → Save as Q → Q's `batch` = P's).
- **R5 (S3-3):** one `lstat` + size check (the placement cap) before `_load_a2l_data_with_cache`, for both the A2L-only branch and the data+A2L branch: a link or an over-cap A2L → refusal in user terms.
- **R6 (S3-4):** every painted list of names from P's tree shows at most 10 names then "and K more", each clipped to 120 characters, with control, bidi and zero-width characters removed; the copy catches its own errors and paints row 11 in user terms (no exception text).
- **R7 (S3-9):** the free-space total rounds each file up to 4 KiB and adds 64 KiB for `project.json` and the folders.
- **R8 (A3-5, S3-2):** an unreadable sub-folder or an entry the walk cannot classify is a plan refusal before any folder exists, naming it (R6 rules apply).
- **R9 (A3-11):** after a save as, the session follows Q: the flow panels' session folder is republished, and a Patch Editor document whose file is inside P is rebound to its copy in Q.
- **Accepted as written by the reviewers:** A3-4 (align names/types/text to the pre-rulings), A3-6 (R-8), A3-7 (one wording per token row; row 8's next step must be true), A3-8, A3-9, A3-10 (AT-09 removes `P/flows/f1.json` after the save), A3-12, A3-13 (refusal precedence stated), A3-14, A3-16; S3-5, S3-6, S3-7, S3-8, S3-10.
- **Backlog:** A3-15 (Execute next step on an A2L-only project), A3-17 (a MAC appearing mid-save).

## After design pass 1 (orchestrator)
- **R10 (F-7):** when the session saves its own MAC or A2L, every other MAC / A2L file of P is left out of the copy (Q never holds two). `project.json.previous-*` files are NOT copied (they are P's backups, not project content).
- **R11 (F-8):** the sub-folder copy runs right after `mkdir`, before the rows loop (the document lives in a home); the TOP-LEVEL copy runs after the rows loop and before the gather, so the image row never reuses a byte-identical variant of P. The plan predicts top-level landings in that order.
- **R12 (F-9):** the 2 000-file ceiling stays; E4 measures a 2 000-file save-as and records the time (background copy stays with Inc 12a).
- Pending for design pass 2: §5.3 TC rows for the new LLRs; LLR-167.6's threshold names the "carried" top-level rows.

## E3 round 2 (orchestrator)
Architect FAIL on text only (A3R2-1 MAJOR: R11 not written; A3R2-2…6), security PASS-WITH-NOTES (S3R2-1…6). All fixes accepted as the reviewers wrote them, plus:
- **R13 (S3R2-1):** an entry ceiling of 10 000 walked entries (folders, links, unreadable entries and files), read at call time, stops the walk before it sorts a folder; over it → plan refusal before any folder exists; new arm in LLR-171.1j.
- After design pass 2 the architect re-checks only the A3R2 lines; the security minors are verified at E5.

## E3 round 3 — design approved (PDR); addenda for E4 (orchestrator)
Architect r3 PASS-WITH-NOTES (A3R3-1 MINOR, A3R3-2 LOW); security r2 PASS-WITH-NOTES (minors applied in pass 2, verified at E5).
- **R14 (A3R3-1):** `SavePlan.total_bytes` leaves the carried rows out of the row sum (each top-level copy counts once, from `copies`); E4 adds a top-level-copy arm and a mutant to the total.
- **R15 (A3R3-2):** the step-12b mismatch line names files through `painted_names` (R6 / LLR-171.7).
- **R16 (timing arm of the entry ceiling):** the arm uses a NESTED fixture (folders opened, not only listed); its bound is 5 s on the main thread (the background copy is Inc 12a). E4 records the measured time.
