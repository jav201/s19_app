# Kimi brief — batch-99 Increment 8 · review fixes (code-reviewer F1–F5)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`; it gained rules on test ids, the registry bump and black-box ATs). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc8` (uncommitted changes on `c62c842`). Do not commit.

- **F1 [HIGH] — two regressions the census missed.** `tests/test_tui_flow_execution_b94.py:596` (AT-B94-20) and `:816` (AT-B94-23) count every `- Chain ` line as a provenance line. The new report sections push the count from 2 to 8. Re-pin them with the same `" input "` filter you used in `test_flow_chainset_b94.py`, and check `:981` too. Record each as old → new → LLR-156.3. Then widen your census: grep `tests/` for every test that reads the chain-set or flow report text (`"- Chain"`, `"Status:"`, `"## "` headings, `compose_chain_set_report`, `write_chain_set_report`, the flow report path), run them all and include them in `green-full.txt`.
- **F2 [HIGH] — AT-B99-06/07 are not black-box.** They go through `b97_fixtures` helpers (`_handle_load_project`, `action_show_screen`, `Button.press()`, `run.press()` for `#fx_run`). Rewrite them with the idiom in `tests/test_b99_s0.py:376-506`:
  - write the project folder and its flow files on disk as setup;
  - load it through the Load project dialog (open it, pick it, click `#project_ok`);
  - open Flow Execution by its rail key and `pilot.click("#fx_run")`;
  - assert painted text, plus the report files on disk.

  Also assert that the mix lane's PATCH card paints `notices` (PDR-ux row 97). Run each AT 8 times for stability.
- **F3 [MEDIUM] — the LLR-156.1 summary must name EVERY non-applied address with its disposition, and every refusal code** (`flow_execution_service.py:567-571` gives only a count; the error cause names only the first address). Put the full list in the block's summary/diagnostics. The lane's terminal log line (UX-C1) stays count + first address. Add a TC arm with 3 non-applied entries → all 3 addresses named.
- **F4 [MEDIUM] — PQ-7, painted arm.** The first mutant survived because `Text.append(str)` never parses markup (`flow_screens.py:3318`), not because of `repr`. Add a genuine killing mutant for the painted lane cell: switch that sink to `Text.from_markup(...)` → the hostile-name painted arm goes RED. Correct the packet text at `increment-008.md:268-272`.
- **F5 [LOW]** — `test_b99_patch_truth.py:275` asserts a constant map, not a painted cell: make it a painted-cell assertion or drop it. `:436` is annotated `-> Path` but returns a tuple: fix the annotation.

After the fixes:
1. Run `tests/test_b99_patch_truth.py`, the re-pinned files, every report-reading test from F1's census, the ac6 golden test, `tests/test_address_census.py` and `tests/test_id_registry.py` (bump the module count if needed).
2. Re-run the 4 mutations plus the new F4 one.
3. Update the packet with a "Review round 1 fixes" subsection.
4. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
