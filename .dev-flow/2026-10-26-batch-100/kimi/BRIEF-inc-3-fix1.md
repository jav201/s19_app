# Kimi brief — batch-100 Increment 3 · corrective pass 1

You work in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc3`. It holds your Inc 3 changes, uncommitted; keep them. `BRIEF-COMMON.md` still applies. SOURCE files stay at 1: `app.py`.

**Read first (MAIN checkout):**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-003.md` (F1–F11). The reviewer's mutant R6 and probes are in `...\scratchpad\mut\` and `...\scratchpad\probes\`.
- `01-requirements-ledger.md` LED .55 (orchestrator rulings on F2 and F3).

**Fix:**
1. **F1 (HIGH).** Give scenario P1 non-default values for S5–S12 in BOTH TC-B100-09 arms, the cold one and the load-over one: CRC template, comparison and check spec, flow run, execution, report filter, and the rest of the ARQ §2.2 inventory. The comparison must then see a missing reset. Discharge condition: the reviewer's mutant R6, which deletes the 7 reset lines for S7–S11, goes RED. Run R6 yourself and save `mut-R6.txt`.
2. **F2 + LED .55 (a).** The interim notice now reads exactly `Closed the Patch Editor document (N entries); unsaved changes were not kept` and is painted when the outgoing document holds N > 0 entries. Re-pin its arms.
3. **F3 + LED .55 (b).** The reset seam calls the panel's public `mark_loaded()`, which clears the dirty marker and the paste buffer. Add an arm, driven by keys: after a load-over, the Patch panel shows no `●`.
4. **F4.** Add a mutant that kills the notice arms, e.g. drop the notice or read N after the rebind. Record it truthfully in the packet.
5. **F5.** Correct the batch-C record: `at030c` failed in `green-06b`. Give every first-run failure a disposition: pre-existing at base (name its base transcript), or a flake shown at base.
6. **F6.** Add LLR-165.3's boundary arm: a worker still holding the old service after the rebind.
7. **F7.** Record the reviewer's R10 (snapshot without its normaliser → RED) in the packet as LLR-165.2's third negative control, and label the 3 base failures that are a missing method rather than a behaviour.
8. **F8.** AT-B100-03 checks HLR-165's "Patch Editor ledger is empty" through the painted ledger.
9. **F9.** The snapshot normaliser reduces a dict to a digest of its content, not to its keys alone.
10. **F10.** Fix the "seven" comment (8 caches). Give the two Inc-era attributes their classification in the census.
11. **F11.** Packet evidence rows use full repo paths, so `devflow-evidence.py --check` matches them. Re-derive with `--write ... --rederive`.

**Re-run:** `tests/test_b100_session_reset.py`, the reverse-census files that touch the reset, the guards (`guards.txt`, `guards-census.txt`) and the mutants. Write `HANDOFF.md` progress BEFORE any long run. Update packet §1, §2, §4 and §6, and leave §4b as `pending — orchestrator`. Finally, rename the previous `__KIMI_UNIT_DONE__` in `HANDOFF.md` to `__KIMI_UNIT_DONE_ROUND1__`, then append a "Fix pass 1" section that ends with `__KIMI_UNIT_DONE__` and a 5-line summary.
