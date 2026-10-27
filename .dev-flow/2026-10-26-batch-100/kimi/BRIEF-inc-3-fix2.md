# Kimi brief — batch-100 Increment 3 · corrective pass 2 (bounded)

Work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc3`. It holds Inc 3 and fix pass 1, uncommitted; keep both. `BRIEF-COMMON.md` applies. SOURCE files stay at 1: `app.py`.

**Read first**, in the MAIN checkout: `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-003.md` §"Round 2" (R2-1, R2-2).

**Fix (this pass covers only these two):**
1. **R2-1 (MAJOR).** LED .55 (b) says the reset clears the paste buffer, but `mark_loaded()` clears only the dirty flag. After loading P2, P1's draft text stays in the paste buffer, now marked clean, so "Parse pasted" could apply P1's draft to P2. That breaks PH-2.
   - In the reset seam, clear the panel's paste buffer through the panel's existing widgets or public API.
   - Call `mark_loaded()` only after the buffer's change message has been handled (e.g. `call_after_refresh`). Otherwise that message sets the dirty flag again.
   - Do not edit `screens_directionb.py`. If the buffer cannot be cleared without editing it, STOP and write that in `HANDOFF.md`.
   - **Test.** AT-B100-03, driven by keys at both sizes: type a draft into the paste buffer with P1 open, then load P2. The buffer must be empty and the panel must show no `●`. Show RED first on the current tree, then add a mutant that skips the clear.
2. **R2-2 (MINOR).** Fix the AT comment that calls the ledger check "load-bearing" for the seam's repaint. Record in packet §4 that deleting `refresh_entries` is an equivalent mutant, because the install repaints the ledger.

**Re-run** `tests/test_b100_session_reset.py`, the panel-owning reverse-census files, the guards (`guards.txt`, `guards-census.txt`) and the mutants.

**Packet:** update §1, §4 (re-derive digests with `devflow-evidence.py --write ... --rederive`) and §6. Leave §4b as `pending — orchestrator`.

**HANDOFF.md:** rename the existing `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX1__`, then append a "Fix pass 2" section that ends with `__KIMI_UNIT_DONE__` and a 5-line summary.
