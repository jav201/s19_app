# Diagram — PATCH dispositions into the run records (flowchart)

> **Role:** `docs-writer`. Mermaid flowchart, 12 nodes. It shows how a flow PATCH step's per-entry dispositions and refusals become the block status, the lane display, the chain-set report and the flow report (US-145; HLR-156, LLR-156.1–156.4; AT-B99-06, AT-B99-07; TC-B99-17..20). Facts come from `03-increments/increment-008.md` §1, `flow_execution_service.py:537`, `:1587`, `:1884`, `flow_report_service.py:282` and `flow_screens.py:3376`. Anchors are on the tree at `bf3917d`.

```mermaid
flowchart TD
    APPLY["PATCH arm applies the change document<br/>dispositions per entry: applied · skipped-outside ·<br/>skipped-partial · skipped-no-image · blocked; refusals"]
    RULE{"Status rule, first match wins<br/>fes:537"}
    ERR["error: unreadable document, document-level refusal,<br/>or 0 of ≥ 1 applied<br/>cause: 'applied 0 of 1 entries: 0x… skipped-outside'"]
    NOT["notices: some applied, some not<br/>'applied 1 of 2 entries, 1 not applied'"]
    OK["ok: everything applied<br/>'applied N entries'"]
    HALT["Chain aborts before WRITE-OUT<br/>(_record_error) · no output file"]
    OUT["ChainRunOutcome (fes:1587)<br/>+ change_records · refusals · image_ranges"]
    LANE["Lane: PATCH cell ✗ / ◇; last log line<br/>'PATCH: k of n entries not applied (0x… disp)'"]
    CSR["Chain-set report (fes:1884)<br/>per lane: Written files · Not applied · Refusals"]
    FR["Flow report<br/>Not applied · Refusals (always present)"]
    HEAD{"_provisional_status (frs:282)<br/>any not-applied or refusal?"}

    APPLY --> RULE
    RULE --> ERR --> HALT --> OUT
    RULE --> NOT --> OUT
    RULE --> OK --> OUT
    OUT --> LANE
    OUT --> CSR
    OUT --> FR --> HEAD
    HEAD -- "yes" --> X1["COMPLETED WITH ISSUES / FAILED<br/>never CLEAN"]
```

**Reading notes.**
- Before the batch, PATCH reported `ok` (`applied 0 entries`) for every outcome, and the outcome and both reports dropped dispositions (premises P-4, P-14).
- The 8-case matrix in TC-B99-17 reads `error, error, notices, error, error, error, error, ok`.
- File-derived text renders literally everywhere: lane cells through `safe_text`, reports through `md_safe` / `md_code`, notifications with `markup=False`. AT-B99-07 finds 0 markup spans from a hostile symbol name.
- The lane uses only existing glyphs, status words and colour classes (UX-C3).
- The chain-set report's not-applied listing is asserted at the service only (G-003).
- The CRC step follows the same shape (`diagrams/write-path.md` for placement). An empty region is `error` and stops before WRITE-OUT. Partial coverage is `notices`, with the absent count on the lane line (`fs:3353`).
