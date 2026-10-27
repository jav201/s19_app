# Kimi brief — batch-100 Increment 2 · corrective pass 3 (bounded)

Work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc2`. It holds Inc 2 plus fix passes 1 and 2, uncommitted; keep all of them. `BRIEF-COMMON.md` still applies. SOURCE files stay at 2: `app.py` and `workspace.py`.

**This pass is BOUNDED**: the operator decided this at the iteration cap. Change only what is listed below. If you find anything else, write it in `HANDOFF.md` and leave it unfixed.

**Read first** (MAIN checkout): `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-002.md`, §"Round 3", for R3-1 and R3-2. The reviewer's probes are in `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\fix2\tests\test_zz_review_r3.py`.

**Fix:**
1. **R3-1 (HIGH): the rollback walks into junctions.** On Python 3.11, `Path.rglob` treats a junction as a plain folder, so the snapshot and the removal walk both go into it.
   - Add ONE walker to `workspace.py`. Suggested name: `walk_tree_no_links(root) -> Iterator[Path]`, yielding relative paths of files and folders. Use `os.scandir` with `follow_symlinks=False`.
   - It must never descend into a reparse point. A directory entry that is a symlink OR a junction is yielded as a leaf and not entered. Detect junctions on 3.11 via `st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`, or reuse the reparse check `_guarded_destination` already uses.
   - It must not loop.
   - Use this walker for BOTH the pre-save snapshot and the rollback's removal walk in `app.py`.
   - The rollback never deletes a reparse point's target. It may remove a junction it created itself; it creates none.
   - The contract asks for this same walker for save-as in Inc 8b (LLR-171.1), so write it as the reusable one. Name it in the packet §5 for 8b.
   - **Tests.** Write each one RED first, against the current fix-pass-2 tree:
     - (a) project `ab` holds a junction `ab\ext` that points outside the work area. A file appears in that outside folder during the save, then the save is forced to fail. The outside file survives, and the project tree equals its snapshot.
     - (b) a junction loop `ab\loop` → `ab`. A save into `ab` must succeed: no "could not save", no long-path error.
     - (c) a unit test of the walker: it yields the junction as a leaf, never its contents.
2. **R3-2 (MINOR):** initialise `_last_manifest_verify_result` in `__init__`.

**Re-run** the affected test files, the guards (`guards.txt`, `guards-census.txt`) and the rollback mutants. Add one mutant: the walker follows reparse points. Test (a) must go RED on it.

**Packet:** update §1, §2, §4 (re-derive the digests with `devflow-evidence.py --write ... --rederive`), §5 and §6. Leave §4b as `pending — orchestrator`.

**HANDOFF.md:** rename the previous `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX2__`. Then append a "Fix pass 3" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
