# Kimi brief — batch-99 Increment 3b · HLR-155 D7 + D9 · duplicate output names refused; WRITE-OUT verifies

Read `BRIEF-COMMON.md` first. Inc 3a (private staging, `WorkareaPlacementError`) is already on the base you start from.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-155, its D7 and D9 clauses (operator verdict: D7 `rechazar`, D9 `si`); LLR-155.5, LLR-155.6; TC-B99-15, 16; AT-B99-04's duplicate-name arm (the RED arm). Map rows B99-I11 and B99-I12 in `docs/architecture.md`. PDR conditions (`design/PDR-2026-10-25-batch-99.md`, detail in `design/PDR-ux.md`):
- **UX-C2:** a WRITE-OUT verify `error` ends with a last diagnostic naming the first differing address.
- **UX-C4:** the chain-set refusal leads with the outcome within the first 50 characters, e.g. `Chain set not run: lanes A, B both write same.s19`.
- **UX-C10:** one hostile-lane-name TC asserting 0 markup spans.

## SOURCE files (max 2)
`s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/app.py` (the chain-set run handlers near `:2800` / `:2890` show the refusal in the status line).

## What to build
1. `run_chain_set`: before any lane runs, resolve every lane's WRITE-OUT file name and compare them case-folded. On a duplicate, return a refusal naming the lanes and write nothing. Use the existing result shape; do not invent a new return type unless needed, and if you do, add it to the packet's interface note.
2. The flow WRITE-OUT arm: after placement, call `verify_written_image`. On a mismatch the status is `error`, with the first differing address in the last diagnostic.

## Tests — `tests/test_b99_staging.py` (extend it)
- **TC-B99-15:** two lanes named `same.s19` (and `SAME.s19`) → refused, both names in the message, 0 files.
- **TC-B99-16:** a hook corrupts the file after placement → WRITE-OUT `error` naming the address; an intact write → `ok`.
- **AT-B99-04 duplicate arm** (pilot, Flow Execution `#fx_run`): the status line leads with the refusal and names both lanes; no file is written. RED today (P-5's set writes `same.s19`).
- **UX-C10:** a lane named `[red]x[/red]` → painted literally.
- Mutations: remove the duplicate check (TC-15 RED); skip the verify call (TC-16 RED). Revert each one.

## Reverse census
`grep -rln "run_chain_set\|write_out\|verify_written_image\|CHAIN_RUN" tests/`. Re-pin only what HLR-155 D7/D9 change.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-003b.md`, REQ-ID `HLR-155` (Inc 3b).
