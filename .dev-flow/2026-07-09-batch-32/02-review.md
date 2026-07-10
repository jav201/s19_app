# 02 — Cross-agent review · batch-32 · CRC multi-region single-CRC groups

**BLUF.** Three parallel Phase-2 reviews (architect / qa / security) over the locked
`01-requirements.md` @ `551fc77`: **0 blockers · 4 major · 9 minor — all folded at this gate** (fold
record in 01-requirements.md §12). Verdicts: architect **PASS-with-minors**, qa **PASS-with-minors**,
security **PASS-with-conditions**. The design (Option A `groups` key, normalize-to-one-loop,
width-on-result) survived ground-truthing; one consumer (`screens.py:1912` re-inject with no config in
hand) independently PROVES the width-on-result choice is mandatory. Artifact now carries the full LLR
decomposition (LLR-GRP-001.1–.15, LLR-WID-001.1–.6) and 23 ATs.

## Findings register (all folded)

| ID | Sev | Lens | Finding | Disposition |
|----|-----|------|---------|-------------|
| A-F1 | major | architect | `to_json_dict` is a **phantom symbol** (zero repo hits) — real serializer is `OperationResult.to_dict` (model.py:282-349); Phase 3 would have authored a test against a nonexistent surface | Renamed, 4 occurrences swept (C-15 sweep-back) |
| A-F2 | major | architect | S-7 unscoped overlap warnings **contradict AT-044a**: the committed dummy config's legacy regions self-overlap by design (crc_config.py:53-54), so warn-on-legacy adds new notes to legacy-only runs | S-7 scoped: notes fire only when ≥1 pair member is a group → LLR-GRP-001.8 |
| Q-M1 | major | qa | Counterfactual-directions block omitted AT-044e + AT-045c (block claimed complete); AT-044e is RED-first only AFTER the pre-fill update — a pre-update GREEN is not the pin | Block completed with the subtlety stated |
| Q-M2 | major | qa | No Layer-B AT drove group confirm-**WRITE** (AT-047e is check-only; AT-047b is the headless seam); `test_crc_inject_reaches_surface_via_handler` pins the literal "(4 LE bytes)" that width parameterization will change | **AT-047h added** (mixed config, non-default width, real Write button + modal + on-disk file + "(N LE bytes)" row) |
| S-F1 | major* | security | Compute is O(total_spans × mem_map) — `region_segments` full-scans per span; span count unbounded at parse (config capped only by 256 MB read cap) → self-DoS; §10 "same O(bytes)" claim wrong | LLR-GRP-001.14 span-count ceiling (mirrors change-doc entry ceiling) + §10 claim corrected |
| S-F2 | major* | security | Address domains unbounded: negative / >32-bit `output_address` (+width 8 nearing 2^32) flows to a structurally corrupt S19 record → baffling verify-mismatch instead of a parse error; change-doc parser has the bounding precedent (io.py:910-953) | LLR-GRP-001.15 groups-only numeric bounds (legacy tolerant for AT-044a compat) |
| S-F3 | minor | security | N5 empty-stream alternative = silent CRC 0x00000000, injectable footgun | N5 decided **REJECT** at parse (architect concurs, LLR-GRP-001.3) |
| S-F4 | minor | security | C-17: notes surface safety currently rests on one widget flag (`#operation_result_status` markup=False, screens.py:1232); operator text already reaches it via int-parse error echoes | C-17 clause in LLR-GRP-001.12 + hostile-input case in AT-047e fixture |
| A-F3 | minor | architect | screens.py citations stale by −6 (1225/1452/1742 → 1231/1458/1748); 10/10 other citations exact | Refreshed |
| A-F4 | minor | architect | S-3 note granularity per-span vs per-group ambiguity | Pinned per-group aggregate (LLR-GRP-001.6, flood-proof) |
| A-F5 | minor | architect | 3 concrete screens.py touch points: hardcoded "(4 LE bytes)" (1897-8), `0x{:08X}` stored format vs 64-bit, `_summarize_check` wording | LLR-GRP-001.12 |
| A-F6 | minor | architect | `matched` comparison rule at N≠4 implied, never stated | LLR-WID-001.5 |
| Q-m3..m7 | minor | qa | AT count arithmetic (→23); golden double-proof mandate for AT-044a; AT-047f ordering precondition; C-12 fixture non-default width + mixed; AT-046a ranges-clause altitude | Folded (§12 TC obligations + §11.2 fixture pin + BLUF count) |

*security majors are conditions on Phase-2 LLRs (now encoded), not spec blockers — the underlying
exposures pre-exist on the legacy path; batch-32 is simply the increment that touches this parser.

## Two-layer blocker checks (dev-flow Phase 2)

- (a) Every story has black-box ATs: US-044 ×5 · US-045 ×6 · US-046 ×4 · US-047 ×8 = **23**. ✓
- (b) Every output-producing requirement names deliverable + observation (§4 "Observable through" + §5 surfaces + §11.2). ✓
- (c) Dual traceability complete: US→HLR→LLR (§12) and US→AT (§5/§6); zero orphans. ✓
- (d) ATs black-box (oracles only; one mechanism-level clause consciously delegated to TC layer, QA m-7). ✓
- shall/should discipline: `grep -n "should"` → 0 normative hits. ✓
- Supersession census: change-first over crc_config.py / crc.py / model.py / screens.py — no test reads a symbol this batch renames (the one rename, `to_json_dict`, existed nowhere); `encode_le32`/`decode_le32`/`read_stored_crc_le` callers preserved by wrapper LLRs (WID-001.1/.2/.4). Best-effort + gate-confirmed.
- C-14 location-move census: no file moves on-disk this batch. n/a.

## Evidence checklists
All three reviewers returned completed checklists (✓ per item with file:line evidence) — architect §6,
qa (10 items incl. independently re-run ledger 49/1191 @ 551fc77), security (5 items). Embedded in the
review transcripts; key evidence mirrored in the findings table above.

## Gate

Exit axes: **Coverage** — dual chains complete incl. the new .14/.15 → AT-044d(d,e) rows; **Certainty**
— every AT has an explicit counterfactual direction; the two vacuity risks named (m-4 golden, m-5
ordering) carry TC obligations; **Certainty/Evidence** — every fold traceable to a finding, every
finding to file:line. No unmet-axis gap remains → **approve** (recorded under the session standing
authorization; operator may override any fold, esp. the Q1-Q4 defaults and the groups-only strictness
of LLR-GRP-001.15).
