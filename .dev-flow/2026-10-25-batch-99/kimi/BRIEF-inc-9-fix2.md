# Kimi brief — batch-99 Increment 9 · review round 2 fix (N1)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc9`. Do not commit.

- **N1 [MEDIUM] — a HEX file with CR-only line endings loads 0 bytes** and reports a false `HEX-NO-EOF` (`s19_app/hexfile.py:≈55`). Binary mode splits lines only on `\n`; HEAD loaded 272 bytes from such a file. Iterate over `data.splitlines()` (bytes `splitlines` splits on `\r`, `\n` and `\r\n`), keeping the rule: decode only up to the first EOF, count the trailing non-empty lines without decoding them.
  - Add sub-arms of TC-B99-09: CR-only, LF-only and CRLF versions of the same HEX each load the same bytes with 0 notices; a CR-only file with a binary tail gives one `HEX-AFTER-EOF` notice.
  - Mutation: split on `\n` only → the CR-only arm goes RED.
- **LOW:** AT-B99-03 picks the project row by setting `listing.index` directly. Use keys (`down` / `up`) or a click on the row instead.

Run `tests/test_b99_truncation.py`, every HEX loader test (`grep -rln "IntelHexFile\|hexfile" tests/`), `tests/test_address_census.py` and `tests/test_id_registry.py`. Run AT-B99-03 8 times. Update the packet ("Review round 2 fix"). Finish with `HANDOFF-fix2.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
