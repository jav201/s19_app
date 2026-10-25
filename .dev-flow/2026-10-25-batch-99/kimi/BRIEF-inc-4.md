# Kimi brief — batch-99 Increment 4 · US-146 / HLR-157 · the editor image is the source plus the current document

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-157, LLR-157.1, 157.2, 157.4 (LLR-157.3 is retired); TC-B99-21, 22, 40; AT-B99-08. Design: `design/design-proposal-b99.md` §3 "Editor image" (the journal) and §4 B99-I7. ARQ evidence: `design/ARQ-batch-99.md` §2 (the `mem_map` writer census, the aliases at `app.py:9894` / `:9946`). PDR condition **UX-C6** (`design/PDR-ux.md`): after a save-back, `_surface_verify_result` overwrites the status, so the HLR-157 text naming entries not applied before the save never stays visible (`app.py:3388-3390`, `:3904`). Keep both visible: verify result plus the not-applied names in one status, outcome first.

## SOURCE files (max 3)
`s19_app/tui/services/change_service.py`, `s19_app/tui/app.py`, and `s19_app/tui/changes/apply.py` only if `before_bytes` needs it (it should not: with the journal restored before apply, the byte read at apply time is the source byte).

## What to build
1. A journal in `ChangeService`: `address → source byte`, recorded the first time an apply writes an address.
2. Every `apply` first restores every journalled address in place, in the SAME dict object (aliases hold it). Then it applies the current document, journalling new addresses.
3. `undo` / `redo` / `remove_entry` / `edit_entry` of an applied entry re-derive before the next save. `save_patched` re-derives from every entry currently in the document before emitting, and names in its status each entry not applied before the save (added after the last apply).
4. Reset the journal when a new file is loaded or the document is replaced (Load).
5. `before_bytes` in change records is the source byte, even on a repeated apply (LLR-157.4). Its readers (`report_service.py`, `diff_report_service.py`, `flow_report_service.py`, the before/after strip) then show the source byte.

## Tests — `tests/test_b99_editor_image.py`
- **TC-B99-21:** the p05 sequence; the alias arm (read the bytes through another holder of the same dict, e.g. with a MAC attached); all entries undone + apply → image == source.
- **TC-B99-22:** remove-after-apply and edit-after-apply leave 0 stale bytes; add-after-apply → save writes and names the entry.
- **TC-B99-40:** apply → apply on `0xEB10`; the before/after strip text and a before/after report show `20 41 70 70` as before.
- **AT-B99-08** (Textual pilot, real keys and clicks): add `0xEB10 DE AD BE EF`, Apply, Undo, add `0xEB40 01 02`, Apply, save back. The independent reader shows the source bytes at `0xEB10` and `01 02` at `0xEB40`, and the painted status names one applied entry and stays visible after the verify result (UX-C6). RED on today's tree (P-6: `deadbeef`).
- Mutations: skip the restore (TC-21 RED); rebind instead of restoring in place (alias arm RED); keep the image byte as `before_bytes` (TC-40 RED). Revert each one.

## Reverse census
`grep -rln "ChangeService\|save_patched\|before_bytes\|_surface_verify_result\|last_summary" tests/`. Re-pin only what HLR-157 changes, recording old → new → LLR.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-004.md`, REQ-ID `HLR-157`.
