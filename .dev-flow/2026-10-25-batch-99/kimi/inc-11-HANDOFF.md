# HANDOFF — batch-99 Increment 11 (HLR-161, the Bytes field reads one base)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc11` (branch b99-inc11). Nothing committed; all changes are in the working tree for the orchestrator.

## What was done

- `s19_app/tui/services/change_service.py` — `parse_new_bytes` now reads every token as base 16 with an optional `0x` prefix, accepts 1–2 hex digits, and raises `ValueError` naming any other token (`100`, `G1`, `0x123`, bare `0x`). Docstring rewritten for LLR-161.1 (amends batch-07 LLR-001.2). CRLF preserved.
- `s19_app/tui/screens_directionb.py` — `#patch_entry_bytes_input` placeholder → `hex bytes, e.g. DE AD BE EF` (fits the compact input at width 118, verified in the pilot).
- `s19_app/tui/window_help.py` — the patch help "Bytes" line states the rule: every token is a hex byte (1–2 digits, `0x` optional), decimals not accepted. The "String" line keeps the document-encoding note.
- `tests/test_b99_bytes_field.py` (new, CRLF) — TC-B99-32 (grammar), TC-B99-33 (placeholder + help, both arms RED at HEAD per PQ-6/UX-C9), AT-B99-12 (pilot types `0F 10 1F 20`, Add, Apply, save-back; independent reader asserts the saved bytes).
- Re-pins (HLR-161 amends batch-07 LLR-001.2): `tests/test_change_service.py::test_parse_helpers_follow_tui_input_grammar` (decimal `2` → hex `02`; `100` refused) and `tests/test_tui_memory_patch.py::test_parse_new_bytes_accepts_prefixed_and_bare_hex` (renamed from `..._hex_decimal_and_bare_hex`; `100`-refusal arm added). Pinned values unchanged where 1-digit tokens are valid hex.

## Verification (all transcripts in `.dev-flow/2026-10-25-batch-99/evidence/inc-11/`)

- RED at HEAD: 3 failed (`red-initial.txt`). GREEN: 3 passed (`green-full.txt`, per-test `green-tc_b99_32/33.txt`, `green-at_b99_12.txt`).
- Re-pinned files: 30 passed (`green-repinned.txt`). Address census: 23 passed (`green-address-census.txt`).
- Reverse-census file set (11 files): 352 passed, 5 failures — ALL isolated as pre-existing/environmental (fail at HEAD or HEAD-flaky; the two TC-707 nodes need `prototypes/cambios_10_12_2026/help_sections.md`, absent from this worktree): `pre-existing-failures.txt`, `red-at031b-head-isolation.txt`, `red-head-isolation-others.txt`.
- C-40 mutations: base-0-first grammar (TC-32 KILLED) and placeholder revert (TC-33 KILLED); both SOURCE files restored byte-identical (SHA-256 in `baseline-hashes.txt`).
- Packet: `.dev-flow/2026-10-25-batch-99/03-increments/increment-011.md` — §4b left `pending — orchestrator`.

## Open items

- `s19_app/tui/changes/io.py:13-19` docstring still describes the old permissive TUI grammar (decimals). Doc-only, outside the 3-file SOURCE cap — flagged in the packet's Correction population; needs a doc-only follow-up.
- Pre-existing failures documented above are for the orchestrator's full-suite run to triage (not this increment's scope).

__KIMI_UNIT_DONE__
Files changed: 3 SOURCE (change_service.py, screens_directionb.py, window_help.py) + 3 test files (new test_b99_bytes_field.py; re-pinned test_change_service.py, test_tui_memory_patch.py).
Tests added: 3 (TC-B99-32, TC-B99-33, AT-B99-12); 2 existing test nodes re-pinned to the hex-only rule.
RED/GREEN: 3 RED at HEAD → 3 GREEN; companions 30 + 23 + 352 passed across the reverse-census file set (5 pre-existing/environmental failures isolated, none caused here).
Mutations: 2 run (base-0-first grammar, placeholder revert), both KILLED, both reverted byte-identical by SHA-256.
Open questions: stale doc-only mention in changes/io.py:13-19 (outside the SOURCE cap); 5 pre-existing failures documented for orchestrator triage.
