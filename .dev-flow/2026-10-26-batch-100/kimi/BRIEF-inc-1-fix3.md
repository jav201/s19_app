# Kimi brief — batch-100 Increment 1 · corrective pass 3 (bounded)

Work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc1`. It holds your Inc 1 changes plus fix passes 1 and 2, uncommitted; keep all of them. `BRIEF-COMMON.md` still applies. The SOURCE files stay at the same 4.

**This pass is BOUNDED.** It is the operator's decision at the iteration cap. Change only what is listed here. If you find anything else, write it in `HANDOFF.md` and do not fix it.

**Read first** (MAIN checkout): `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-001.md`, section "Round 3" (R3-1..R3-4). The reviewer's probe is `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probe\r3_export_junctioned_base.py`.

**Fix:**
1. **R3-1 (HIGH, regression of fix pass 2).** At `segment_split_view.py` ≈842, `home, workarea_root = _guarded_destination(dest_dir, workarea_root)` overwrites the caller's root with the resolved one. Keep the caller's root for the two placement calls (≈947, ≈969), and use the resolved value only for the staging home. Use two distinct variables.
   - **New test arm:** an app base reached through a junction (the work area under a junctioned folder), the export called with the app's root → exactly 1 file written, inside the work area.
   - **RED first:** run the arm against the current tree, where it must fail with "traverses a symbolic link". Then GREEN.
   - **Re-run** every export and junction arm. They must still refuse an escape.
2. **R3-2 / SEC-6.** In `app.py` ≈1911, `_active_project_dir`'s fallback drops `.resolve()` and returns the path under `self.workarea` unresolved, as LED .50 says.
3. **R3-3.** `gather_project_artifacts` and `_check_home_contained` / `_gather_copy` require `workarea_root`: a keyword-only parameter with no default.
   - The only production caller is `app.py` ≈8270, which already passes it.
   - Update the test callers to pass their work area: `tests/test_b99_staging.py` (≈1920, ≈1974) and `tests/test_project_gather.py` (≈231, ≈632). Each is recorded as a re-pin, `old → new`, under LED .50.
   - Add an arm: called without the root → `TypeError`.

**Do not touch R3-4.** The orchestrator routes it to the backlog.

**Re-run:**
- the affected test files;
- the whole-tree guards (`guards.txt`, `guards-census.txt`);
- the N1 mutant and the census root-drop mutant.

**Packet:** update §1 (fix pass 3), §4 (new rows with SHA-256; re-derive with `devflow-evidence.py --write ... --rederive`) and §6. Leave §4b `pending — orchestrator`.

**HANDOFF.md:** rename the previous `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX2__`. Then append a "Fix pass 3" section that ends with `__KIMI_UNIT_DONE__` and a 5-line summary.
