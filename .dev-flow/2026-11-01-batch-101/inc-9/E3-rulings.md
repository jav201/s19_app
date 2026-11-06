# Inc 9 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` **FAIL** (1 HIGH, 1 MAJOR, 8 MINOR); `E3-security.md` **FAIL** (2 MAJOR, 4 MINOR). The design stands; the blockers are record defects. Rulings under the operator's standing commission:

| Finding | Ruling | Why |
|---|---|---|
| E3A-01 (HIGH) = S-4 | Accept: withdraw R-FB-RUN.8 (D-2 = no) and align every dependent record: US-I9-2, cases R-FB-RUN.8/1–/2, AT-I9-2's after-Clear assertions, the slice's Clear branch, graph I-4 and the ribbon entity, the counts. | A ruling the records do not follow cannot be built or reviewed. |
| E3A-02 (MAJOR) | Accept: add a case that loads a REPORT-bearing flow, saves it under another name and runs it as a lane; the lane report's title is the new stem (the only reader of the saved `name`, `flow_execution_service.py:2028`, `:1257`). | The fix must be proven at its only observable reader. |
| S-1 (MAJOR) = E3A-03 | Accept the security form and credit it correctly: build the payload first; claim the name with the exclusive create; then, before writing any byte, check that the new entry is a regular file and not a link, that it is the same file as the open handle, and that its real path is inside the home the guard approved — otherwise remove our entry, write nothing and raise `WorkareaContainmentError`. This is `place_into_workarea`'s post-claim idiom (not Inc 6's). BL-I9-4 states the residual: a race can leave an empty file outside, never content. | On Windows the exclusive create follows a dangling link (house finding S-F1); only the post-claim check closes it. |
| S-2 (MAJOR) | Accept: one negative control per defence — a spy proving no create is attempted on a name that already exists (the `lexists` check), and an emulated Windows link-follow proving 0 bytes land outside (the post-claim check). | Each defence needs a test that fails without it on the Linux test host. |
| S-3 (MINOR) | Accept: payload built before the claim; on a write failure after the claim, remove our own file. | No empty file takes the name. |
| S-5 (MINOR) | Backlog: widen BL-I9-1 (a file renamed on disk or written by hand keeps its stored `name` in lane report titles). | Out of the save path this increment fixes. |
| S-6 (MINOR, pre-existing) | Backlog: the name sanitiser accepts device names and has no length cap. | Pre-existing; separate fix. |
| E3A-04 | **Take the change:** a chain set saved by Save Set carries its file's stem as its name, capped like flow names (same 64-character rule as D-3), so Load Set never refuses a file Save Set wrote. | Consistency with F-46; the typed-text form writes files the loader refuses. |
| E3A-05 … E3A-07, E3A-09 (MINOR) | Fold: R-FLOW-FILE.13 and the examples say "the next free name" instead of pinning `_2` (keep one concrete example); widen the "passes through a link" definition to what the guard checks and add the "between" case; R-FLOW-CHAIN.20 in E form and the mode docstrings listed; E4 updates the TC-B99-13 exceptions for the two save functions. | One-line edits. |
| E3A-08 | The Windows junction arms run at E5 on this PC under the Windows-only-arm rule (isolated app-state folders, never the clipboard), as Inc 15's did; until then they are `not_run`. | Junctions need no privilege on Windows; CI and the LAN hosts are Linux. |
| E3A-10 | Backlog row beside D14-11: `reports/` writes are not guarded. | Outside the four files. |

Correction: one design-correction agent, targeted edits only. Round 2: the security reviewer re-checks S-1, S-2; the architect re-checks E3A-01, E3A-02, E3A-04.

## Round 2 (2026-11-06)

Security **PASS-WITH-NOTES** (S-1, S-2, S-3 closed; the TC-B99-13 census change is exact and tighter: a revert to `write_text` turns it RED). Architect **PASS-WITH-NOTES** (E3A-01, E3A-02, E3A-04 closed; 4 source files, 18 nodes). E3 closed. Addenda to E4:

- **R2-1 (MINOR):** add a case for the real-path (home-swap) arm of the post-claim check; drop "Windows-only" from the wording where the check also runs on Linux.
- **R2-2 (MINOR):** state the two error paths in the row or the graph: an `lstat` failure inside the check (treated as a failed check: remove, raise) and the best-effort unlink after close.
- **N-1:** AT-I9-2 asserts `1 chain(s) restored` (`app.py:4645`), since "mounts lane `rep_b`" also holds on base.
- **Order:** Inc 9's E4 starts after Inc 6 merges (one `app.py` writer at a time, P0 mitigation), although the two `app.py` slices do not overlap.
