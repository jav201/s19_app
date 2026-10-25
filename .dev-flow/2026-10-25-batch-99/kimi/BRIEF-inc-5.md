# Kimi brief — batch-99 Increment 5 · US-148 / HLR-159 + LLR-155.8 · CRC never covers an empty region; CRC write stages privately

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-159, LLR-159.1, 159.2; LLR-155.8 (CRC write staging); TC-B99-26, 27, 38; AT-B99-10. Design: `design/design-proposal-b99.md` §4 B99-I5. PDR conditions (`design/PDR-2026-10-25-batch-99.md`):
- **C5:** ARCH R23 is confirmed. The coverage count travels on the CRC region result, and the flow arm, `write_crc_image` and the operation path all read that one number.
- **PQ-8:** the RED of the race test TC-B99-38 must show a nonzero mismatch count, or use a deterministic hook.
- **UX-C2:** the last diagnostic of the CRC `error` block is the user-facing cause, with code plus address or count, e.g. `CRC region 0x20000-0x30000 holds 0 image bytes - nothing written`.

## SOURCE files (max 2)
`s19_app/tui/operations/crc.py`, `s19_app/tui/services/flow_execution_service.py`.

## What to build
1. **Region coverage** (`crc.py`, `region_segments` / `crc_diagnostics`):
   - 0 present bytes → an error result; nothing is injected;
   - partial coverage → `notices` naming the exact count of absent bytes, legacy regions included;
   - the count is carried on the region result (R23).
2. **Flow CRC arm:** status `error` on an empty region, and the flow stops before any later WRITE-OUT (0 files). Use the existing `_record_error` abort path. Partial coverage → `notices` with the count.
3. **CRC write `<stem>-crc.s19`:** place it through `copy_into_workarea`'s private staging (Inc 3a), never through a shared `temp/<name>`. Remove any delete of a re-derived name.
4. TC-B99-39 (Inc 3a's delete census) carries an `expected RED until Inc 5` exception for the CRC site. Remove that exception now; the census must pass with zero exceptions.

## Tests — `tests/test_b99_crc_region.py`
- **TC-B99-26:** `0x20000-0x30000` on `examples/case_00_public/prg.s19` → error, slot bytes unchanged.
- **TC-B99-27:** a region over a gap → `notices`, count == an independent count of absent addresses (compute it from the independent reader's map).
- **TC-B99-38:** two concurrent CRC writes of the same stem × 20 trials; each file's CRC slot is checked against its own CRC with an independent CRC computation (stdlib `binascii.crc32` or a small reference implementation matching the configured algorithm).
- **AT-B99-10** (pilot, Flow Execution `#fx_run`): a flow with a CRC step over the empty region shows the CRC cell failed, writes no file, and the last log line names the cause (UX-C2). The partial arm shows notices naming the count. RED on today's tree (P-9).
- Mutations: CRC of the empty stream (TC-26 RED); shared staging (TC-38 RED). Revert each one.

## Reverse census
`grep -rln "region_segments\|crc_diagnostics\|write_crc_image\|EMITTED_NAME_SUFFIX\|injected 1 CRC" tests/`. Re-pin only what HLR-159 / LLR-155.8 change, recording old → new → LLR.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-005.md`, REQ-ID `HLR-159`.
