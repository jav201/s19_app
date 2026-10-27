# Kimi brief — batch-100 Increment 2 · corrective pass 1

You work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc2`. It already holds your Inc 2 changes, uncommitted; keep them. `BRIEF-COMMON.md` still applies. The SOURCE files stay at 2: `app.py` and `workspace.py`.

**Read first, from the MAIN checkout (absolute paths):**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-002.md` (code-reviewer, F1–F11);
- `...\03-increments\security-increment-002.md` (SEC2-1..3);
- `...\01-requirements-ledger.md` LED .52 (orchestrator rulings on F4, F5, F7).

**Fix:**
1. **F1 (HIGH) + LED .52 (b).** A failed save restores the app's `_variant_set` and current variant (and `current_project`) to their pre-save state. It also removes every file it placed during that save, including files placed into a folder that already existed (F5 / SEC2-3). Tests must assert the APP STATE after each forced failure (variant ids, variant paths, `current_project`), not only folders and tokens. Each test is RED first, by reverting the restore.
2. **F2.** The packet's `tests/test_id_registry.py` row traces to `HLR-164`, not to "registry hygiene" (V59). Check every §2 row: `Kind` must be one of the six (`source` · `test` · `doc` · `config` · `generated` · `fixture`), and `Traces to` must hold a real LLR/HLR id.
3. **F3 + SEC2-2.** `is_windows_device_name` takes the device stem up to the FIRST dot and strips trailing spaces and dots, so `con.tar.gz`, `NUL.tar.gz`, `com1.a.b` and `CON .txt` are refused. Keep refusing the superscript digits. Add arms for each.
4. **F4 + LED .52 (a).** With a project open, a typed name equal to its on-disk name ignoring case (or to its unsanitised form) saves into that project under its ON-DISK name. `current_project` keeps the on-disk spelling. Add arms for that case, and for a case-only match against ANOTHER project, which is still refused as a clash.
5. **F6.** Add a test of the empty-name refusal (token and next step). It must be RED when the message is reverted.
6. **F7 + LED .52 (c).** AT-B100-02 drives "another project (E4's P2) is open" by keys.
7. **F8 + SEC2-1.** The clash scan catches `OSError`. An unreadable work-area folder is skipped, the same as `list_projects` does it, so it never crashes the save. Add an arm: a folder with read denied (`icacls` deny), then save a fresh name. The save must succeed, or refuse with the `could not save` tokens, never raise. Lift the deny afterwards.
8. **F9.** The "0 folders" check also catches empty folders.
9. **F10.** Packet record: the artifact count, hashes for every transcript (re-derive with `devflow-evidence.py --write ... --rederive`), and environment lines in the transcript headers.
10. **F11.** No code. Note in packet §5 that the path limit and the clash check use the work area while the target uses the parent field, as a dependency for Inc 11, which removes that field.

**Re-run** the affected files, the guards (`guards.txt`, `guards-census.txt`) and the mutants, including M6/M7, which must now die. Update the packet §1, §2, §4, §5 and §6. Leave §4b as `pending — orchestrator`.

**Finish:** rename the previous `__KIMI_UNIT_DONE__` in `HANDOFF.md` to `__KIMI_UNIT_DONE_ROUND1__`. Then append a "Fix pass 1" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
