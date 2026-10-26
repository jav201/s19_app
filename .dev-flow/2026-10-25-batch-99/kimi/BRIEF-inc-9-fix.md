# Kimi brief — batch-99 Increment 9 · review fixes (code-reviewer F1–F4)

Read `BRIEF-COMMON.md` first. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc9` (branch `b99-inc9`, uncommitted changes on `c62c842`). Do not commit.

- **F1 [HIGH] — a HEX file with a binary tail now fails to load** (`s19_app/hexfile.py:50,123`). HEAD stopped reading at EOF. The new code reads to the end through a strict utf-8 text handle, so a valid HEX followed by newlines and `0xFF` padding raises `UnicodeDecodeError` ("Load failed") instead of loading with a `HEX-AFTER-EOF` notice.
  - Open the file in binary (`"rb"`). Decode lines strictly only up to and including the first EOF record. After it, count non-empty lines by stripping the BYTES; never decode them.
  - Add a TC arm with the reviewer's case: a valid HEX + 50 000 newlines + `0xFF` padding → loads its 272 data bytes, with 1 `HEX-AFTER-EOF` notice stating the count.
  - Apply the same post-terminator rule to S19 ONLY if it is a small change inside `_load`'s post-terminator branch. Otherwise leave it: the S19 locale-codec weakness predates this batch and goes to the backlog (the orchestrator files it).
  - Mutation: decode the tail → the arm goes RED.
- **F2 [MEDIUM] — the S6 mismatch is never tested** (`core.py:374`). Add a generated S19 (in tmp) with more than 65 535 data records and a WRONG S6 count → `S19-COUNT-MISMATCH`. Mutation: delete the S6 comparison → RED.
- **F3 [MEDIUM] — AT-B99-03's flow arm is not fully black-box.** It uses `b97_fixtures` helpers that call `app._handle_load_project`, opens the screen with `action_show_screen`, and starts the run with `Button.press()`. Replace them:
  - load the prepared project through the Load project dialog by keys and clicks (CW-U-1 is fixed: open it, pick the project, click `#project_ok`);
  - open Flow Execution by its rail key;
  - start the run with `pilot.click("#fx_run")`;
  - assert painted text only.

  If the flow-set setup truly cannot be reached from the UI, keep ONLY the file preparation on disk as setup (writing the project folder with its flow file is fine) and do everything else by keys and clicks.
- **F4 [LOW]:**
  - (a) Assert the status line `startswith` the defect text (UX-C7 "leads with").
  - (b) Reuse `_is_data_record` for the S5/S6 tally instead of duplicating the predicate.
  - (c) A data line that fails to parse must not count toward `S19-COUNT-MISMATCH`: count the parsed data records plus the unparseable lines that start with `S1`/`S2`/`S3`, so a damaged line gives its own parse issue and no false count mismatch. Add an arm.
  - (d) The re-pin should cite LLR-154.1, not HLR-154.

After the fixes:
1. Run `tests/test_b99_truncation.py`, `tests/test_core_srecord_validation.py`, `tests/test_address_census.py` and any HEX / S19 loader test file (`grep -rln "IntelHexFile\|hexfile\|S19File(" tests/`). Run AT-B99-03 8 times. Save `green-fix-*.txt` and `stability-at03.txt`.
2. Update the packet with a "Review round 1 fixes" subsection.
3. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
