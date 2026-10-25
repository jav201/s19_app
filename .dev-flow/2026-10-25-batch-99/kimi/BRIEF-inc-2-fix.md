# Kimi brief — batch-99 Increment 2 · review fixes (code-reviewer F1–F6)

Read `BRIEF-COMMON.md` first. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc2`, branch `b99-inc2` (commit fc81767 on main `a52e2be`, plus an uncommitted orchestrator fix in `tests/test_b99_s0.py`: a wait for the LoadGuardScreen button — keep it). Do not commit.

The independent review returned **changes required**. Fix exactly these:

- **F1 [HIGH] — AT-B99-02's Memory Map check is vacuous** (`tests/test_b99_s0.py:407`). Each row starts with a band glyph (`░ 0x00000000 …`), so `startswith("0x00000000")` never fires. Assert `not any(re.search(r"\b0x00000000\b", r) for r in rows)`. Drop the call to `app.update_memory_map()` (≈:396), because the rows fill without it. Then re-run the S0 re-admit mutation against **step 4 alone** (temporarily skip steps 3 and 5, or split the step into its own test node) and show it RED. Transcript: `mut-F1-step4.txt`.
- **F2 [MEDIUM] — drive AT-B99-02 by keys and clicks.** Replace `Input.value = …` with focusing the input (`pilot.click("#id")`) and typing (`pilot.press(*text)`). Replace `Button.press()` with `pilot.click("#button_id")`. Replace any read of `current_file` or `has_class` with waiting on the painted status line or on painted text. Look at `tests/test_b97_patch_editor.py` for the idiom. Keep it stable: run it 8 times and save `stability-at02.txt`.
- **F3 [MEDIUM] — list the third freeze guard.** `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` is also RED before the merge. List all three guards in the packet (§4 / §6) with the reason: they diff the working tree against `main`, they pass once the change is on `main`, and LLR-153.1 names the crossing. Do NOT edit those tests.
- **F4 [MEDIUM] — the at040a colour branch uses made-up ranges** (`tests/test_tui_directionb.py:8485`). Instead of splitting case_04's one invalid range by hand, build a temporary S19 with a gap between a valid block and an invalid (bad-checksum) block, and assert on the real computed range validity.
- **F5 [MEDIUM] — TC-B99-06 cannot catch the mutation on the two checksum-defective files** (≈:225). Assert that `set(mem_map) - set(oracle.data)` is a subset of the addresses of the invalid (bad-checksum) records, computed from the file by the independent reader's error list or by parsing the defective lines. Show the S0 mutation RED on those two files too.
- **F6 [MEDIUM] — the packet's file list.**
  - §2 must list every changed file: the 3 re-pinned test files, the 16 SVGs, the 2 goldens, and anything else.
  - **A closed batch's evidence file was rewritten:** `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.bin`. A sealed record is never edited. RESTORE it (`git checkout a52e2be -- <that path>`). Then find the test that reads it. If that test needs the new S0-free capture, save the new capture under `tests/goldens/batch99/` (or this batch's evidence folder), point the test there, and record the re-pin as old → new → LLR-153.x.
  - Fix the SHA-256 row for `red-tc_b99_07.txt`, which has 65 hex digits. Re-hash every evidence row.

After the fixes:
1. Run `tests/test_b99_s0.py`, `tests/test_b99_corpus.py`, the re-pinned test files, `tests/test_tui_snapshot.py`, the test that reads the at288 capture, and `tests/test_address_census.py`. Save the transcripts as `green-fix-*.txt`.
2. Update the packet with a "Review round 1 fixes" subsection and the evidence table.
3. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and a 5-line summary.
