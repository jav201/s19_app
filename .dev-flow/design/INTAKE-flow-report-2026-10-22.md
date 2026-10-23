# Intake — Flow Execution report improvement (future batch-98)

Date: 2026-10-22 · Tree: `b514b07` · Status: **inventory only**. The operator decided that this work gets its own batch after batch-97 closes. A prototype round with real rendered reports and an operator verdict comes before any implementation.

**Request (operator, 2026-10-22):** improve the md and html reports that Flow Execution produces, using the recent A2L-reading capabilities and the flow-execution data.

Source: a read-only `Explore` inventory. **The file:line claims below are the agent's, not yet re-probed.** Confirm them at the batch's P0.

## 1. Producers today
Every flow report is **Markdown only**. HTML exists only for the manual Diff and Before/After reports (`diff_report_service.py:2424`).

| Producer | Trigger | File |
|---|---|---|
| `compose_chain_set_report` / `write_chain_set_report` (`flow_execution_service.py:1561/1661`) | Every `run_chain_set` (FX Run and confirm re-run), both modes | `reports/<ts>-chain-set-report.md` |
| `write_flow_report` (`flow_report_service.py:496`) | Only when a chain carries a REPORT block | `reports/<ts>-report.md` |
| `generate_diff_report(..., "flow-a2b")` (`flow_execution_service.py:798`) | A2B block | `reports/<ts>-flow-a2b.md` |
| `write_fused_flow_report` (`flow_fused_report_service.py:382`) | Variant runs; its panel caller is orphaned (BACKLOG-CODE.md:1407) | `<ts>-report.md` |

## 2. Content today
- **Chain-set report:** a header (set, generated, mode, chains), a chain ledger (# · Chain · Template · Status · Blocks · Elapsed) and the input provenance.
- **Flow report:** a header, then these sections: pipeline ledger · change attribution · findings · image footprint · written files. The golden sample is `tests/goldens/batch71/ac6-unscoped-flow-report.md`.

## 3. Data computed but not reported
- **Chain-set layer:** `ChainRunOutcome` drops `change_records`, `refusals`, `image_ranges` and `pre_crc_ranges` from `FlowRunResult`.
- **CHECK:** the per-address `CheckRunEntry` records (expected/actual bytes, result, linkage symbol, reason) are discarded; only the counts survive.
- **CRC:** the `CrcRegionResult` records (output address, computed vs stored value, matched) are discarded; only the region count survives.
- **A2L:** the full parse payload and the enriched tags (unit, limits, datatype, COMPU_METHOD, physical value, out-of-limits, memory region, axis) are computed from the source image only. They are never re-read after the patch.
- **Funnel:** the applied name→value pairs are not reported.
- **External step:** the instruction, log and output exist only as summary text; `waiting` and `paused` have no glyph.
- **Timing:** measured per chain only, not per block.
- **Reusable A2L features:** `describe_curve_tag` (curve point tables), physical→raw encode, `extract_memory_segments`.

## 4. Candidate defects to confirm with probes before routing
- **D-a:** the chain-set report embeds the absolute host path of each input (`flow_execution_service.py:1621`). This goes against the relative-path rule the flow report enforces (AMD-8, `flow_report_service.py:226`).
- **D-b:** the A2B arm inside a flow passes neither `flow_changes` nor the A2L records (`flow_execution_service.py:798-804`), but LLR-143.2 requires flow-change attribution.
- **D-c:** the chain-set report filename does not match `REPORT_FILENAME_REGEX` (`report_service.py:494`), so the report viewer never lists it.
- **D-d:** the FX run log never shows `record.report_path`.

## 5. Constraints
- **Sanitisation:** `md_safe` / `md_code` (`md_code` is never placed in a table cell), absolute-path redaction, the hardened markdown viewer, and `html.escape` with no script or external resource.
- **Byte budget:** `FLOW_REPORT_MAX_TOTAL_BYTES`.
- **Tests that pin content:**
  - AT-212 golden byte-identity
  - `test_flow_report_service.py` (26)
  - `test_flow_report_fusion.py` (13)
  - TC-B94-30 (the `[bound] path=` line, which D-a would change)

## 6. Candidate improvements (for the prototype round)
1. **Chain-set report v2 with an HTML twin.** It carries the dropped `FlowRunResult` fields, embeds each chain's sections, fixes D-a and D-c, and links from the FX log (D-d).
2. **Changed parameters in A2L terms.** Symbol, unit, COMPU_METHOD and the physical value before → after, with an out-of-limits flag.
3. **Per-address check results.**
4. **CRC table:** address, computed vs stored value, written.
5. **Curve/map before/after point tables** for patched CURVE/MAP symbols.
6. **Run provenance:** funnel values, the A2L used (tag and error counts), mode, per-block timing.
7. **External-step evidence:** instruction, log reference, copied output, paused/confirmed state.
8. **In-flow A2B attribution** (fixes D-b), plus the memory-segment class for each change.
