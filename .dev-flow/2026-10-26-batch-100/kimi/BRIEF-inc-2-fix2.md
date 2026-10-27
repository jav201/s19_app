# Kimi brief — batch-100 Increment 2 · corrective pass 2

You keep working in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc2`. It holds Inc 2 and fix pass 1, uncommitted; keep both. `BRIEF-COMMON.md` applies. You still have 2 SOURCE files: `app.py` and `workspace.py`.

**Read first.** These are in the MAIN checkout:
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-002.md` §"Round 2" (R2-1..R2-5)
- `...\03-increments\security-increment-002.md` §"Round 2" (SEC2-4 and the trap it describes)

**What to fix:**
1. **R2-1 (HIGH) and SEC2-4: a failed save must remove every file it placed (LED .52 (b)).**
   - Before the save touches the target project folder, snapshot its whole tree as a set of RELATIVE paths, files AND folders, sub-folders included.
   - On failure, remove only the files and folders that are not in that snapshot. Remove deepest first, and remove a folder only if it is empty after its new files are gone.
   - Never delete a path that was in the snapshot. That is the trap: the gather reuses a pre-existing identical file at the same path, and a bare-name check would delete it.
   - Add test arms:
     - (a) A merge into an existing project with a gathered document (e.g. `batch=("hotfix.json",)`), then the manifest write is forced to fail. The target tree must equal the snapshot exactly.
     - (b) The same case, but `patches/hotfix.json` already exists, byte-identical. It must survive.
     - (c) A fresh-folder save that fails. No folder may be left behind.
   - Each arm must be RED against the current tree before you fix it.
2. **R2-3.** Move the statements after the manifest write OUT of the rollback `try`. Once `project.json` is written and verified, the rollback can no longer unlink a variant that the manifest lists.
3. **R2-4.** The AST census requires the state restore at every failure exit. Removing the created folder alone no longer passes. Add a mutant that skips the restore at one exit; the census must go RED.
4. **R2-5.** Put the manifest verify MISMATCH back as the NEWEST status line, after `Saved project to …`, and add an arm for it.
5. **R2-2.** Add a packet §2 row for `tests/test_b99_staging.py`: Kind `test`, Traces `LLR-164.4` · `LLR-155.3`, with the two re-pins named. Fix the test-file count.

**Re-run** the affected files, the guards (`guards.txt`, `guards-census.txt`) and the mutants. Then update the packet §1, §2, §4 and §6, re-deriving the digests with `devflow-evidence.py --write ... --rederive`. Leave §4b `pending — orchestrator`.

**Finish:** rename the previous `__KIMI_UNIT_DONE__` in `HANDOFF.md` to `__KIMI_UNIT_DONE_FIX1__`, then append a "Fix pass 2" section that ends with `__KIMI_UNIT_DONE__` and a 5-line summary.
