# Kimi brief — batch-99 Increment 11 · US-150 / HLR-161 · the Bytes field reads one base

Read `BRIEF-COMMON.md` first.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-161 (D1 = `hex`, final; it amends batch-07 LLR-001.2), LLR-161.1, 161.2; TC-B99-32, 33; AT-B99-12. Map row B99-I8. PDR condition **PQ-6 / UX-C9**: the help text already says "a run of hex bytes" (`window_help.py:84`), so a TC asserting "the help contains `hex`" passes at HEAD and is vacuous. TC-B99-33 must assert something that is RED today:
- the Bytes placeholder states hex (today it is `DE AD BE EF`, which contains no "hex");
- the help states that decimals are not accepted and that `0x` is optional.

String (value) entries are unchanged: they keep the document's `encoding` (utf-8 by default). Say so in the help line if it fits in one line.

## SOURCE files (max 3)
`s19_app/tui/services/change_service.py` (`parse_new_bytes`, ≈ `:170-223`), `s19_app/tui/screens_directionb.py` (the placeholder of `#patch_entry_bytes_input`, ≈ `:4941`), `s19_app/tui/window_help.py` (≈ `:84`).

## What to build
1. `parse_new_bytes`: every token is base 16 with an optional `0x`; accept 1–2 hex digits; raise `ValueError` naming any other token (`100`, `G1`, `0x123`). Update the docstring examples.
2. The placeholder reads e.g. `hex bytes, e.g. DE AD BE EF`. It must fit the field without clipping at width 118; check it.
3. The help line states hex, `0x` optional, no decimals.

## Tests — `tests/test_b99_bytes_field.py`
- **TC-B99-32:** `0F 10 1F 20` → `[0x0F,0x10,0x1F,0x20]`; `11 22` → `[0x11,0x22]`; `0x0A ff` → `[0x0A,0xFF]`; `00`, `FF` accepted; `100`, `G1` refused with the token named.
- **TC-B99-33:** the placeholder and help assertions above, each RED at HEAD (show it).
- **AT-B99-12** (pilot, keys): type `0F 10 1F 20` at an in-image address in the Patch Editor, Add, Apply, save back → the file holds `0F 10 1F 20` (independent reader). RED today (P-16: `0F 0A 1F 14`).
- Mutations: base-0 first (TC-32 RED); revert the placeholder (TC-33 RED). Revert each one.

## Reverse census
`grep -rln "parse_new_bytes\|patch_entry_bytes_input\|decimal" tests/`. Existing tests expecting a decimal reading (e.g. `tests/test_change_service.py:600-603`) are re-pinned to the new rule, with old → new → LLR-161.1 and a note that this amends batch-07 LLR-001.2.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-011.md`, REQ-ID `HLR-161`.
