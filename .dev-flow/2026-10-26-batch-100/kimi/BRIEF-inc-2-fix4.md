# Kimi brief — batch-100 Increment 2 · redesign of the failed-save rollback (operator decision)

Work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc2`. It holds Inc 2 plus fix passes 1–3, uncommitted; keep them. `BRIEF-COMMON.md` still applies.

**The SOURCE files are now 3:** `app.py`, `workspace.py` and `s19_app/tui/services/project_gather_service.py` (LED .53).

**Read first, in the MAIN checkout:**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\01-requirements-ledger.md` → LED .53. This is the operator's ruling.
- `...\03-increments\security-increment-002.md` → "Round 3", findings SEC2-5 and SEC2-6. It includes the probe cases R7 and R8 in `...\scratchpad\probes\sec_inc2_r3_probe.py`.

**The design (LED .53):** a failed save removes EXACTLY what THIS save created.
1. **Collect the created files during the save.**
   - Every placement whose `PlacementResult.reused` is False. This covers the image, the MAC and the A2L.
   - Every file the gather actually wrote. `GatherOutcome` gains a field for that, e.g. `written: list[Path]`, and it must not list files the gather reused.
   - Every folder this save created, the project folder included.
2. **On failure, remove only those files.** Then remove the created folders that are empty, deepest first. Never walk a folder to decide what to delete. The rollback no longer uses the tree snapshot. Remove the snapshot and the snapshot-difference code from the rollback path.
3. **Keep `walk_tree_no_links` in `workspace.py`,** with its unit test. Inc 8b's save-as reuses it (LLR-171.1).
4. **Keep the app-state restore and the MISMATCH repaint** exactly as they are.

**Tests.** Each new arm goes RED first against the fix-pass-3 tree.
- **R7 (SEC2-5).** `ab/patches/keep.json` already exists. `ab/patches` is unreadable when the save starts (icacls deny), the deny is lifted during the save, and then the save is forced to fail. `keep.json` must survive. Lift the deny afterwards.
- **R8 (SEC2-6).** Another writer creates `ab/notes.txt` during the save, then the save is forced to fail. `notes.txt` must survive.
- **Keep GREEN:**
  - the merge-gathered arms: a gathered file is removed, and a pre-existing identical file survives;
  - the fresh-folder arm: no folder is left behind;
  - the junction arms: nothing outside is touched;
  - the junction-loop arm: the save works;
  - the F1 state assertions.
- **Mutants:**
  - (a) the rollback removes the reused placements too, so the identical-file arm goes RED;
  - (b) the rollback goes back to the snapshot difference, so R7 and R8 go RED;
  - (c) the gather's `written` list includes the reused files.

**Census:** update the LLR-164.4 AST census if it names snapshot helpers. The rule stays that every failure exit goes through `_abort_save`, and `_abort_save` restores the state.

**Re-run:** the affected files plus the reverse census of `GatherOutcome` and `gather_project_artifacts` in `tests/`, the guards (`guards.txt`, `guards-census.txt`) and the mutants.

**Packet:** update §1 (redesign, LED .53), §2 (3 SOURCE files, with `project_gather_service.py` traced to LLR-164.4), §4 (re-derive digests), §5 and §6. Leave §4b as `pending — orchestrator`.

**HANDOFF.md:** rename the previous `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX3__`. Then append a "Redesign (LED .53)" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
