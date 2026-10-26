# Kimi brief — batch-100 Increment 1 · corrective pass 1

The same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc1`, already holds your Inc 1 changes, uncommitted. Keep them. `BRIEF-COMMON.md` still applies.

**Read first, from the MAIN checkout (absolute paths; your worktree copies are older):**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-001.md`, the code-reviewer's findings F1–F11.
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\01-requirements.md`, the amended LLR-163.1 (grep `### LLR-163.1`), and `01-requirements-ledger.md` LED .49.

**SOURCE files are now 4 (⚠ at cap, LED .49):** `workspace.py`, `segment_split_view.py`, `app.py`, and `s19_app/tui/services/project_gather_service.py`. Packet §2 states why the increment cannot be smaller: the gather is a writer that resolves its destination before the guard, so the guard has to see that destination unresolved.

**Fix all of these** (the review gives the evidence and the suggested fix for each):
- **F1 (HIGH):**
  - Add one shared destination guard in `workspace.py`, used by BOTH placement kinds (`place_into_workarea` and `place_group_into_workarea`).
  - It takes the work-area root from the destination **as given, before any resolution**: the nearest `.s19tool/workarea` ancestor of the unresolved path, or an explicit root an app-level caller passes. Then it resolves both and compares them (this also closes F2).
  - The export passes the UNRESOLVED `dest_dir`.
  - Save project's `_gather_copy` passes its destination unresolved, through the guard.
  - Add the three TC-B100-62 junction arms (export, group, gather). Each one RED-first, by reverting just that caller's change, then GREEN with 0 bytes outside.
- **F2:** mutant check. Removing the containment refusal must now turn a test RED. Run it and save `mut-F2.txt`.
- **F3:** add the LLR-163.1 boundary arms, each with a mutant that kills it:
  - an upper-case `_2` name on Windows (case-folding off → RED);
  - `_1` deleted beside an identical `_2`;
  - a link at a `_<N>` name;
  - a 0-byte `_<N>`.
- **F4:** `predict_placement` returns the same path FORM that `place_into_workarea` returns, i.e. resolved. Add an arm with a relative destination where predicted == placed.
- **F5:**
  - TC-B100-57's census counts every byte-identity rule in the package by behaviour, not only by the name `find_identical`. Declare the group's frozen rule (R30) and the gather's sibling scan as the known, named others.
  - The group's status word comes from the placement it performed. Declare in the packet how it is computed.
- **F6–F11 (MINOR):**
  - F6: replace the self-confirming assertion in the TC-68 forced-claim test.
  - F7: the AST threshold is now "1 claim loop per placement kind (2)".
  - F8: decide 8.3 short names and the case of the `.s19tool\workarea` form. Accept a case-insensitive ancestor match on Windows, and don't refuse forms the base accepted unless they escape.
  - F9: restore `copy_into_workarea`'s `Summary:/Args:/Returns:` docstring, remove the unreachable block, and fix the "Appended variant" log line on reuse.
  - F10: take `copy_into_workarea` off the staging allow-list.
  - F11: make the packet accurate. Fix the artifact count and reconcile the test ledger. Each census transcript names its files on its first line. Leave `HANDOFF.md` out of anything committed; the orchestrator excludes it.

**Re-run:** every affected test file, the guards (`guards.txt`, `guards-census.txt`) and the mutants. Update the packet: §1, §2 (4 files ⚠ with the reason, `Traces to` for the new rows), §4 (new RED/GREEN/mutation rows with SHA-256), and the §5 note about `place_group_into_workarea`, which is now resolved. Keep §4b `pending — orchestrator`.

Finish by appending to `HANDOFF.md` a "Fix pass 1" section that ends with `__KIMI_UNIT_DONE__` and a 5-line summary.
