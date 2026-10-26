# Kimi brief — batch-99 Increment 5 · review fixes (code-reviewer F1–F4)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc5`, branch `b99-inc5`, now REBASED onto main `d62b0c1` (Inc 8's lane log line and Inc 7 are present; your Inc-5 work is commit `08b6d4f`). Do not commit.

**Source budget widened by the orchestrator: 3 files** — `operations/crc.py`, `services/flow_execution_service.py`, and now `s19_app/tui/flow_screens.py` (still within the 4-file cap).

- **F1 [HIGH] — the partial-coverage absent-byte count never reaches the Flow Execution surface.** The FX notices line (`flow_screens.py` ≈:3328, "done with notices · wrote X") and the chain-set report (`flow_execution_service.py` ≈:1676-1712) do not show block findings, so the count is visible only in the Flow Builder result view. HLR-159's AT and UX-C2 require it on the painted lane log line.
  - For a CRC `notices` block, append the count to that lane's terminal log line, following the Inc-8 UX-C1 pattern for PATCH, e.g. `CRC: 12 of 4096 region bytes absent (0x1000-0x2000)`.
  - The chain-set report lists the CRC block's finding text (through `md_safe` / `md_code`).
  - Make AT-B99-10 assert the painted count, not only "done with notices". Mutation: drop the count from the line → RED.
- **F2 [MEDIUM]** — `crc_diagnostics` re-computes the absent count (`crc.py:1009-1024`) instead of reading the region result's `absent_bytes`: read it from the result, which is R23's single carrier. An empty region must not get a "covers present bytes only" note before its error; it gets the error only, which stays the last line (UX-C2).
- **F3 [MEDIUM]** — add the "exactly 1 present byte" boundary arm to TC-B99-26/27: `notices` with an absent count of region length − 1.
- **F4 [LOW]** — fix the packet's claim that equality is unchanged (`CrcCoverageResult == CrcRegionResult` is now False; no caller relies on it), and type `first_empty_target_span` as `CrcCoverageResult`.

Run `tests/test_b99_crc_region.py`, the Flow Execution, chain-set and CRC test files (`grep -rln "crc\|fx_run\|chain_set" tests/ | head -40`), `tests/test_b99_patch_truth.py` (Inc 8's lane-line tests must stay green), `tests/test_address_census.py` and `tests/test_id_registry.py`. Run AT-B99-10 8 times. Update the packet ("Review round 1 fixes", plus the budget note). Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
