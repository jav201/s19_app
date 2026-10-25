# Kimi brief — batch-99 Increment 8 · US-145 / HLR-156 · PATCH status and run records say what was not applied

Read `BRIEF-COMMON.md` first.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-156 (D5 = `mixta`, final), LLR-156.1..156.4; TC-B99-17..20; AT-B99-06, 07. Map row B99-I3. PDR conditions (`design/PDR-2026-10-25-batch-99.md`; detail in `design/PDR-ux.md`, `design/PDR-qa.md`):
- **UX-C1:** already in LLR-156.2. The lane's terminal run-log line names the PATCH block, the not-applied count, and the first address with its disposition, or the first refusal code.
- **UX-C2:** the last diagnostic of a PATCH `error` is the user-facing cause.
- **UX-C3:** vocabulary. No new glyph, status word or colour class (`_BLOCK_STATUS_GLYPH`, `_FX_BLOCK_STYLE`, `_FX_STATUS_STYLE`, `FX_CABLE_GLYPHS`, `_FLOW_STATUS_BANNER` stay unchanged in the diff). On flow surfaces, entry-level outcomes use the umbrella word the condition names, which must not be the block-level word `skipped` (read UX-C3 in full).
- **UX-C10:** hostile-name TCs for the new sinks.
- **PQ-7:** the markup arm needs a mutant, e.g. remove `safe_text` / `md_safe` → RED.

## SOURCE files (max 3)
`s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/services/flow_report_service.py`, `s19_app/tui/flow_screens.py`.

## What to build
1. PATCH arm status. The rule, first match wins:
   - `error` when the document could not be read, carries a document-level ERROR refusal (every entry `blocked`), or applied 0 of at least 1 entry;
   - `notices` when some entry was not applied and at least one was applied;
   - `ok` otherwise.

   `error` stops the flow before any later WRITE-OUT (use the existing `_record_error` path). The summary names each non-applied address with its disposition, and each refusal code.
2. `ChainRunOutcome` gets `change_records`, `refusals` and `image_ranges` (default factories, copied from `FlowRunResult`).
3. `compose_chain_set_report` lists, per lane: the written paths, the non-applied entries and the refusals, all through `md_safe` / `md_code`.
4. The flow report always carries a not-applied section and a refusals section (`none` when empty), never says `CLEAN` when either is non-empty, and uses `md_safe` / `md_code`.
5. The lane painter shows the PATCH cell from its block status, plus the UX-C1 log line. File-derived text goes through `safe_text`; notifications use `markup=False`.

## Tests — `tests/test_b99_patch_truth.py`
- **TC-B99-17:** the 8-case matrix in HLR-156's threshold. Expected: `error, error, notices, error, error, error, error, ok`; 0 WRITE-OUT files on `error`. Port the cases from `.dev-flow/design/investigation-rw-2026-10-22/p01_flow_patch_truthfulness.py` and `p06` (read by range).
- **TC-B99-18:** the outcome fields; a malformed-document lane holds `MF-JSON-PARSE`; its lane glyph is the error glyph.
- **TC-B99-19:** chain-set report contents.
- **TC-B99-20:** flow report contents for `mix.json` / `bad.json` (port from `p09`).
- **AT-B99-06 / 07** (pilot, Flow Execution `#fx_run`; the flow fixture includes a REPORT block): all-outside → PATCH failed, no file written, the report names the address and `skipped-outside`; partial → notices, the written file holds only the applied entry (independent reader), the report names the skipped address; malformed → error, the report names `MF-JSON-PARSE`; hostile symbol name → rendered literally.
- **Re-pins:**
  - TC-714 (`tests/test_changes_symbol_entries.py:768-795`) asserts `applied 0 entries` and that `out.s19` is written after a refused patch. Re-pin it to the new rule and record old → new → LLR-156.1.
  - The golden `tests/goldens/batch71/ac6-unscoped-flow-report.md` drifts because of the always-present sections. Rebaseline it surgically and show a text diff in which only the new sections were added (C-24).
- Mutations: hard-coded `ok` (TC-17 RED); drop an outcome field (TC-18 RED); omit a report section (TC-20 RED); remove `md_safe` / `safe_text` on one sink (hostile TC RED, PQ-7). Revert each one.

## Reverse census
`grep -rln "BLOCK_STATUS_OK\|ChainRunOutcome\|compose_chain_set_report\|applied 0 entr\|Status: CLEAN\|flow_report" tests/`.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-008.md`, REQ-ID `HLR-156`.
