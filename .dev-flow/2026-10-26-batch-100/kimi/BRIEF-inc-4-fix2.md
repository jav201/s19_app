# Kimi brief — batch-100 Increment 4 · corrective pass 2

Keep working in the same worktree, `C:\Users\jjgh8\Github\s19_app-b100-inc4`. It holds Inc 4 plus fix pass 1, uncommitted; keep both. `BRIEF-COMMON.md` still applies. There is 1 SOURCE file: `app.py`.

**Read first (MAIN checkout):**
- `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-26-batch-100\03-increments\review-increment-004.md` "Round 2" (R2-1 to R2-4). The reviewer's probe is `...\scratchpad\r4\probe-map-arrows.txt`, with its scripts in the same folder.
- `01-requirements-ledger.md` LED .58 (the rulings).

**Fix:**
1. **R2-1 (HIGH) + LED .58 (a)(b).** After a load on Map, the focus lands on the region row that LLR-116.5 auto-selects (`RegionRow`). The up/down walk must keep working.
   - Remove the general deferred re-assertion (`_reassert_focus_target`).
   - Never move a focus that is on a `RegionRow`.
   - Fix the `every_window[map]` arm: on Map the expected landing is that row, not `#memory_map_panel`.
   - Add a black-box test: load with Map shown, press `down`, and the selected row advances. Show it RED on the current tree.
   - Re-run mutant R7. It should be killed again, because removing the re-assertion brings back TC-13's kill.
2. **R2-2 + LED .58 (c).** Only stale text inputs are re-homed: in a hidden window, or of area 0. A visible text input in the active window (e.g. `#search_input`) keeps the focus.
   - Rewrite `text_input_in_a_content_window_is_rehomed` to use a STALE input.
   - Add a test: a visible Find input in the active window keeps the focus across a load.
3. **R2-3.** Re-capture the RED transcript of the final module at base. Use `git archive` of main `31eb572`, run with `PYTHONPATH` set to that archive and `NO_COLOR` unset, and put those settings in the transcript header. Replace `red-04` in the packet.
4. **R2-4.** The fallback also applies when a target is painted but not focusable.

**Re-run:** the module, the map tests (`grep -rln "RegionRow\|memory_map" tests/`), the guards (`guards.txt`, `guards-census.txt`), and the mutants on the full module. Write progress to `HANDOFF.md` BEFORE any long run. Do the long reverse census LAST, and only on files that touch focus or map.

**Packet:** update §1, §4 (re-derive the digests) and §6. Keep §4b `pending — orchestrator`.

**HANDOFF.md:** rename the current `__KIMI_UNIT_DONE__` to `__KIMI_UNIT_DONE_FIX1__`, then append a "Fix pass 2" section ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
