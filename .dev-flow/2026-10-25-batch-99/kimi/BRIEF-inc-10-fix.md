# Kimi brief — batch-99 Increment 10 · review fixes (code-reviewer F1–F4 + LOWs)

Read `BRIEF-COMMON.md` first. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc10` (branch `b99-inc10`, uncommitted changes on `e00f2f2`). Do not commit.

The independent review returned **Block** with two HIGH findings. Fix:

- **F1 [HIGH] — TAB_INTP encode picks the nearest TABLE ENTRY, not the nearest RAW value** (`s19_app/tui/a2l.py` `_reverse_table_lookup`, the `nearest = min(...)` limb, ≈:1913). That breaks ASAM interpolation, and it is a regression: the old code inverse-interpolated.
  - Fix: find the bracketing entries and inverse-interpolate to a fractional raw value. Round it to the nearest integer raw value, decode that raw value with the forward `_table_lookup(..., True)`, and raise the flag naming the written physical value only when it differs from the typed one.
  - Example: on the table (0→0, 100→100), typed 50 → raw 50, no flag.
  - Out of range stays refused, naming the range. `TAB_NOINTP` stays exact.
  - **Corpus gap:** every corpus table has one raw step per entry, so no test could see this. Extend `tests/fixtures/synth/generate.py` and its manifest with a SPARSE `TAB_INTP` symbol (e.g. raw 0→0.0, raw 100→100.0, plus one non-linear segment), recording in `a2l_expect` an off-grid typed value, its expected raw value and the written physical value. Regenerate and re-run `generate.py --check`.
  - Add TC arms on the sparse table: interior exact (no flag), interior non-integral (flag naming the written value), and both endpoints.
- **F2 [HIGH] — AT-B99-09 is not black-box** (`tests/test_b99_a2l_encode.py`, `_run_at_09`, `_physical_cells_plain`). It loads through private `_parse_loaded_file` / `_prepare_load_payload` / `_apply_prepared_load`, sets `current_a2l_path`, and at 80x24 reads the stored cell `Text.plain` instead of painted text.
  - Load through the shipped controls: the Load file dialog for the S19 and the A2L load path the UI offers. Copy the idiom in `tests/b97_fixtures.py` and `tests/test_b97_*`.
  - Assert PAINTED text at both widths (118 and 80): the rendered screen or region text from the pilot, not the table's stored cells. "No clipping" must be able to fail: show the clipping mutation, e.g. shrink the column, going RED.
- **F3 [MEDIUM] — PQ-5 half-checked** (test ≈:268, :297). `"0.0" in error` also matches `-50.0`, `500.0` and `100.0`. Assert the exact range text the error contains, e.g. `"[0.0, 62.5]"`, and the exact neighbour values for `TAB_NOINTP`.
- **F4 [MEDIUM] — the packet's census is incomplete.**
  - Three guards are RED before the merge: `test_tui_directionb::test_tc031_*` (×2) and `test_tui_issues_triage_b94::test_tc_b94_18*`. Read the last one: if it diffs against `main` like the others, list it with that reason; if it asserts something else, STOP and report it in HANDOFF.
  - The census grep must also cover `MOD_COMMON`.
  - The packet must state the user-visible impact on the repo examples: measure and record how many tags in `examples/**/case_06*` now decode big-endian, and how many RAT_FUNC tags in `software_a` (or wherever) change direction. The reviewer measured 71,513 and 1,640; reproduce those counts with a script and save it as evidence.
  - Make `green-full.txt` the transcript of the whole set of affected test files, not only the new module.
- **LOW, fix now:**
  - (a) In a multi-MODULE A2L, use each MODULE's own `MOD_COMMON BYTE_ORDER` for that module's tags (today the first module's applies to all). Add a TC with a two-module A2L built in tmp.
  - (b) Reject a RAT_FUNC root where the denominator d·P²+e·P+f is zero; treat it as no root.
- **LOW, backlog only (do NOT fix):** axis-point RAT_FUNC decodes get no limits. Say so in packet §6.

After the fixes:
1. Re-run the new module, every A2L-related test file, the corpus tests and the address census. Save `green-fix-*.txt`.
2. Re-run the 3 C-40 mutations, plus a new one for F1 (the nearest-entry limb restored → the sparse-table arm goes RED).
3. Update the packet with a "Review round 1 fixes" subsection.
4. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
