# Kimi brief — batch-100 Increment 4 · corrective pass 1

Keep working in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc4`. It holds your uncommitted Inc 4 changes; keep them. `BRIEF-COMMON.md` still applies, and the SOURCE file is still only `app.py`.

**Read first (MAIN checkout):**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-004.md` (F1–F10). The reviewer's probes and mutants are in `...\scratchpad\r4\`.
- `01-requirements-ledger.md` LED .57 (the orchestrator's rulings).

**Fix:**
1. **F1 (HIGH) + LED .57 (a).** Every focus target must be focusable. Re-target Diff (`#ab_diff_panel`) and Map (`#memory_map_panel`) to a focusable widget inside each window. The registry assertion now checks `can_focus` too. Add a load test for EVERY window in the registry, not only Workspace, A2L, MAC and Split/Join: after an image load with that window active, the focused widget is that window's target (or its LED .57 (b) fallback) and `p` reaches its screen. Show it RED on the current tree for Diff.
2. **F2 (HIGH).** `healthy_focus_is_not_moved` must be able to fail. Today `watch_current_file` moves the focus before the load tail runs. Build the scenario so the focus is healthy at the moment the load tail runs. The reviewer's probe S4 shows how. Prove it with the reviewer's mutant R1 (re-home on every load): the test goes RED.
3. **F3.** Add a test with a focused `Input`/`TextArea` inside a content window that the load leaves stale: the focus moves to the target. Mutant R2 (that rule deleted) must go RED.
4. **F4.** The Split/Join boundary test polls for its precondition instead of reading it once. Fix the packet claim "green at base by design" so it matches the transcripts.
5. **F5 + LED .57 (b).** When the target has area 0 or is not displayed, fall back to the window's first visible, focusable, non-text widget, else the rail's active entry. Test it with an A2L-only load from a bare session.
6. **F6 + LED .57 (c).** The re-home never takes the focus from a visible `#palette_input` or Find field with area > 0. Test: type in the palette while a load finishes. The focus stays there, and the typed text is not sent as a command.
7. **LED .57 (d).** The rule reads `default_screen.focused`. Test: a modal is open while a load finishes, and the modal keeps its focus.
8. **F7.** Re-run every mutant on the FULL `tests/test_b100_focus.py`, and record the true kill counts.
9. **F8.** Delete the scratch files from the evidence folder (`revert_inc4.py`, `apply_mutation.py`, the `.bak`), or move them out of it. Give every remaining evidence file a packet row with full repo paths, and re-derive with `devflow-evidence.py --write ... --rederive`.
10. **F9.** Add a test that tells `Screen.set_focus` apart from `Widget.focus()`, if that difference matters. If it does not, drop the claim from the packet. The reviewer's R5 survives today.
11. **F10.** In the comment, the table is "hand-listed and asserted against the registry".

**Re-run:** the module, the reverse-census files that touch focus, the guards (`guards.txt`, `guards-census.txt`) and the mutants. Write progress to `HANDOFF.md` BEFORE any long run.

**Packet:** update §1, §2, §4 and §6, and leave §4b as `pending — orchestrator`.

**HANDOFF.md:** rename the existing `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_ROUND1__`, then append a "Fix pass 1" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
