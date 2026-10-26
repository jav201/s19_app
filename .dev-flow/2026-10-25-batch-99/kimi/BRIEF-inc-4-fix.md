# Kimi brief — batch-99 Increment 4 · review fixes (code-reviewer F1–F7)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`; it gained a test-id rule). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc4` (uncommitted changes on `9d7fb18`). Do not commit.

- **F1 [HIGH] — save writes overlapping entries that apply would refuse** (`change_service.py:2104`, the `save_patched` re-derive). `apply` refreshes the overlap (collision) check (`:1968-1975`); the save does not. Reviewer's probe: add `0xEB10 DEADBEEF`, apply, add `0xEB12 0102`, save → `ok`, the file holds `DE AD 01 02`, and the summary lists both as applied, while `apply` on the same document blocks both. Fix: the save re-derive runs the same overlap refresh before `apply_change_document`, so a blocked document saves nothing and says why. Add a TC arm (a sub-node of TC-B99-22) with that probe. Mutation: skip the refresh → RED.
- **F2 [HIGH] — the before/after strip shows the old file's bytes after a new file loads** (`source_image_view` ≈`:1903` never checks `mem_map is self._image_map`; refreshed from `app.py:10929`). Fix: return `mem_map` unchanged when it is not the bound dict, and reset or rebind the journal on a new load. Add an arm (a sub-node of TC-B99-40): load file A, apply, load file B, then the strip shows B's byte (`0x99` in the reviewer's probe), not A's source byte.
- **F3 [MEDIUM] — the "not applied before the save" status is untested.** Removing `last_save_not_applied` from the status line (`app.py:3970`) leaves all tests green. Extend AT-B99-08 with an add-without-apply step before the save: the painted status names that entry and states the "1 entry" count. Mutation: drop the names from the status → RED.
- **F4 [MEDIUM] — 3 wrong digests in the packet** (`green-tc_b99_22`, `green-address-census` (63 digits), `green-flake-isolation`). Recompute every digest from the files.
- **F5 [MEDIUM] — the mismatch arm of the save status must also carry the not-applied names** (UX-C6 and HLR-157 allow no exception). Use the same helper on that arm, and add a test arm with a forced verify mismatch.
- **F6 [MEDIUM] — the invented test id `test_tc_b99_40a_*`.** Rename it to `test_tc_b99_40_strip_shows_source_byte` and update the packet.
- **F7 [LOW]** — the packet claims the 4 flaky tests "pass deterministically in isolation", but its own transcript shows `at077c` failing in isolation. Correct the claim: it is flaky on main as well.

After the fixes:
1. Run `tests/test_b99_editor_image.py` and the census files you ran before, plus `tests/test_address_census.py`. Run AT-B99-08 8 times.
2. Re-run the 4 mutations plus the new ones (F1, F3).
3. Update the packet with a "Review round 1 fixes" subsection.
4. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
