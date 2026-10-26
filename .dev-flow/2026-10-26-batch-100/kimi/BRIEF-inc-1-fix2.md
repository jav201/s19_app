# Kimi brief — batch-100 Increment 1 · corrective pass 2

Work in the same worktree as before, `C:\Users\jjgh8\Github\s19_app-b100-inc1`. It holds your Inc 1 changes and fix pass 1, uncommitted; keep them. `BRIEF-COMMON.md` still applies. The SOURCE files stay at 4: `workspace.py`, `segment_split_view.py`, `app.py`, `services/project_gather_service.py`.

**Read first.** Use the MAIN checkout, absolute paths:
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\security-increment-001.md`: SEC-1 (HIGH), SEC-2 and SEC-3, with the security probe that escaped. The probes are in the orchestrator's scratchpad, `...\scratchpad\probes\sec_inc1_probe*.py`, and you can copy their shapes.
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-001.md`, "Round 2": N1 (MAJOR) and N2–N5.
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\01-requirements-ledger.md`, LED .50. This is the ruling for this pass, and amended LLR-163.1 in `01-requirements.md` reflects it.

**Fix (LED .50):**
1. **App paths stay unresolved.**
   - `current_project_dir` is stored as the path under `self.workarea`, not `project_dir.resolve()` (`app.py` ≈8506).
   - Save project builds its target with no `.resolve()` (`app.py` ≈8135).
   - Re-validate every reader of `current_project_dir` for a comparison that relied on the resolved form. Use `grep -n "current_project_dir" s19_app/tui/app.py`. Equality checks must compare consistently, e.g. both sides resolved at the comparison point, never at storage.
2. **The root is passed explicitly.**
   - `copy_into_workarea` and `place_group_into_workarea` gain a keyword `workarea_root`, and `place_into_workarea` already has it.
   - Every placement call in `app.py` (9 sites) passes `workarea_root=self.workarea`.
   - The export and the gather thread the root through to their placement calls, taking it from their callers in `app.py`.
   - Add an AST census arm to `tests/test_b100_reuse.py`: every `app.py` placement call names `workarea_root`.
3. **The walk reaches the outermost anchor (N1).** With no root, `_guarded_destination`'s reparse walk runs up to the OUTERMOST `.s19tool/workarea` anchor of the unresolved destination.
4. **SEC-2.** An invalid path spelling (`WinError 123` from `resolve()`) raises the containment refusal, not a bare `OSError`.
5. **Tests.** Each case below starts RED (revert just that part to show it), then goes GREEN with 0 bytes outside the work area:
   - each app route places into a junction target the way the app would now hand it over: the variant append, the Save project copies, the MAC/A2L syncs, the gather and the export;
   - a nested-anchor arm: a junction `<wa>/nest` to a folder holding another `.s19tool/workarea`, then `<wa>/nest/.s19tool/workarea/x`;
   - mutants: the explicit root dropped from one `app.py` call (the census goes RED), and the outermost-anchor walk reverted to nearest (the nested arm goes RED).
6. **N2–N5 (MINOR):**
   - N2: re-derive the packet's evidence SHA-256 values with `python ~/.claude/skills/dev-flow/scripts/devflow-evidence.py --root . --write .dev-flow/2026-10-26-batch-100/03-increments/increment-001.md --rederive` (run from the worktree root).
   - N3: assign the `_gather_copy` sibling-scan rule. Declare it in the packet as owned by Inc 5, where `project_gather_service.py` is touched again; there is no "Inc 3b" in this batch.
   - N4: add tests for the F8 short-name fallback and the case-insensitive anchor match, or take the untested change out and say so.
   - N5: the group word compares names case-folded on Windows.
   - Fix the F9 nit too: `_reuse_candidate_names` gets a precise return type.

**Re-run:** the affected test files, the guards (`guards.txt`, `guards-census.txt`) and the mutants. Then update the packet:
- §1: fix pass 2;
- §2;
- §4: new RED, GREEN and mutation rows with SHA-256;
- §5: SEC-3 routed to backlog;
- §6.

Keep §4b as `pending — orchestrator`.

Finally, rename the previous done-marker in `HANDOFF.md` from `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX1__`. Then append a "Fix pass 2" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
