# Kimi brief — batch-99 Increment 3a · review fixes (code-reviewer F1–F6)

Read `BRIEF-COMMON.md` first. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc3a` (branch `b99-inc3a`, uncommitted changes on `a52e2be`). Do not commit. The contract was amended for F2 in LED-2026-10-25-batch-99.7 (LLR-155.3). Read the current LLR-155.3 and LED .7 from the MAIN checkout, `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\01-requirements.md` and `01-requirements-ledger.md`, because this worktree's copy is older.

The independent review returned **BLOCK** with three HIGH findings. Fix:

- **F1 [HIGH] — `copy_into_workarea` can still raise a plain `OSError` the callers do not catch** (`workspace.py:457-461`, `:486-495`).
  - On Windows, `os.open(O_CREAT|O_EXCL)` on a name that is an existing DIRECTORY raises `PermissionError`, not `FileExistsError`. Base `a52e2be` placed `fw_1.s19`; this tree raises. Treat "the name exists" (any type: file, directory or link) as taken and move to the next `_<N>`.
  - Wrap every other failure of the claim or the replace in `WorkareaPlacementError`, so callers that catch `WorkareaContainmentError` (`load_from_path` `app.py:8596`, the save dialog, the sync paths) never crash.
  - Add TC arms: a directory squatting the requested name → `_1`; a forced `OSError` (not `PermissionError`) in replace → `WorkareaPlacementError`.
- **F2 [HIGH] — TC-B99-13 gives false confidence** (`test_b99_staging.py:301-309`): its hook overwrites the file between two reads, which models no real writer. Per the amended LLR-155.3, rewrite TC-B99-13 so concurrent threads run `copy_into_workarea` on one name, with identical and with differing bytes, over 20 trials. Each caller's returned path must hold its own bytes, and a 0-byte target is never reused. Drop the double-read "narrowing" if it is no longer needed, or keep it with an honest comment. Do NOT touch `project_gather_service.py`: Inc 3b converts it.
- **F3 [HIGH, security] — `save_patched_image` (`apply.py:776`) and the `io.py:1604` path still stage under `temp/` directly, with no reparse-point check** (LLR-155.1). Both must stage in `tempfile.mkdtemp(dir=<workarea>/temp/.staging)` after checking that `temp` and `temp/.staging` are not reparse points (or links), exactly like `copy_into_workarea`. Factor ONE private helper in `workspace.py` and use it from all three paths. Add a forced-failure arm to TC-B99-11: a junction or symlink at `temp` → refused, nothing written outside the work area. On Windows create the junction with `mklink /J` through `subprocess`; if that is not permitted, skip the arm with the stated reason.
- **F4 [MEDIUM] — the converted `io.py` path (PDR C2) has no test, and TC-B99-39's census leaves it out.** Add a TC that drives that path (find what calls `io.py:≈1586-1604`) and checks private staging and correct placement, and add the path to the TC-B99-39 census.
- **F5 [MEDIUM] — AT-B99-05 and TC-B99-14 are not black-box.** They call `load_from_path` / `request_action`, set widget values and patch `set_status`. Drive them with keys and clicks: the Load file dialog (`l`, click `#load_path`, type, click `#load_ok`), the Patch Editor (rail key `6`), save-back by clicks, and Save project through the real `SaveProjectScreen` by clicks and typing. Assert on the painted status (`#log_line_4`) and on files on disk. Look at `tests/test_b99_s0.py` (AT-B99-02) for the idiom in this batch. Re-record `red-at_b99_05.txt` against the final test, on the unmodified tree (`git stash` is forbidden: use a scratch copy of the base, `git worktree add` of `a52e2be` in your temp dir, and remove it afterwards).
- **F6 [LOW]:**
  - (a) A placement failure after `mkdir` in Save project (`app.py:7989`) leaves a partial project folder. Remove the folder this call created when the save fails.
  - (b) Declare in the packet (§5 Risks) that a crash between the claim and the replace can leave a 0-byte file.
  - (c) Fix the stale `staging_block` docstring.
  - (d) Add the missing `f` prefix at `:732`.
  - (e) Fix the packet's `green-final.txt` digest (65 hex digits).

After the fixes:
1. Run `tests/test_b99_staging.py`, the 4 re-pinned files and `tests/test_address_census.py`. Run AT-B99-05 8 times. Save `green-fix-*.txt` and `stability-at05.txt`.
2. Re-run the 4 mutations, plus new ones for F1 (no directory handling → the arm goes RED) and F3 (staging under `temp/` → the junction arm goes RED).
3. Update the packet: add a "Review round 1 fixes" subsection, and rebuild the caller census table after F1.
4. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
