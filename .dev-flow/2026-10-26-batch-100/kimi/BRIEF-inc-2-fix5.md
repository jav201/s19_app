# Kimi brief — batch-100 Increment 2 · corrective pass on the rollback redesign

This pass happens in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc2`. It holds Inc 2, fix passes 1–3 and the LED .53 redesign, all uncommitted; keep every one of them. `BRIEF-COMMON.md` still applies. The SOURCE files are still 3: `app.py`, `workspace.py` and `project_gather_service.py`. The design stays as it is: a failed save removes exactly what it created. This pass only fixes its implementation.

**Read first. These are in the MAIN checkout:**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\security-increment-002.md` "Round 4": SEC2-7, SEC2-8, SEC2-9. The probe is `...\scratchpad\probes\sec_inc2_r4_probe.py`.
- `...\03-increments\review-increment-002.md` "Round 5": R5-1, R5-2.

**Fix:**
1. **SEC2-7 (HIGH).** `_gather_copy` currently runs its own reuse check, which is case-sensitive, before it calls `copy_into_workarea`. That call hides `reused`. As a result, a byte-identical file under a case-variant name (`BOOST.json` or `boost.JSON` when the source is `boost.json`) is reported as written, and the rollback then deletes it.
   - `_gather_copy` calls `place_into_workarea` and records a path in `written` ONLY when `PlacementResult.reused` is False. The placement is the sole judge of reuse. Remove or align the gather's own pre-check so it never disagrees.
   - Tests: two arms, one for each case variant. Each one survives a forced failure, and each is RED first.
   - Add a census or unit arm: nothing that was reused ever ends up in `written`.
2. **SEC2-8.** When THIS save created `project.json` (fresh folder), add it to the created list the moment the write returns. A failure after that point, such as a forced verify mismatch, must leave no folder behind. Add a test arm.
3. **SEC2-9.** In a merge into an existing project, keep the previous `project.json` bytes before writing it. On failure, restore them atomically (stage them, then `os.replace`). Add a test arm: the forced verify failure leaves `project.json` byte-identical to its pre-save content.
4. **R5-1.** After each gather copy attempt, whether it succeeded or failed, record the home as created if it did not exist before the attempt and exists afterwards. Add a test arm: a copy failure that simulates a full disk, followed by a failed save, leaves no folder behind.
5. **R5-2.** Add a test arm: an empty `patches/` folder that existed before survives a failed save. It kills the mutant that drops the "home existed before" guard.

**Re-run:** the affected files (the module, `test_b99_staging.py`, `test_project_gather.py`, and the A-09 test), the guards (`guards.txt`, `guards-census.txt`), and the mutants, including Mf, which must now die.

**Packet:** update §1, §2, §4 (re-derive the digests) and §6. Leave §4b as `pending — orchestrator`.

**HANDOFF.md:** rename the previous `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_REDESIGN__`. Then append a "Redesign fix pass" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
