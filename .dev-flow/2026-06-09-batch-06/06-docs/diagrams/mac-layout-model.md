# Diagram — MAC View width-resolution model — Batch 2026-06-09-batch-06

How the MAC View resolves its two pane widths from the terminal width under the batch-06 proportional+floor model (`s19_app/tui/styles.tcss`: `#mac_records_pane 4fr`, `#mac_hex_pane 3fr; min-width: 82`). The activity rail determines `body_w`; the hex pane takes the larger of its proportional share and the 82-cell full-row floor; the records pane absorbs the rest. Sample points are the three measured widths from `04-validation.md` (TC-002/003 at 250, TC-004/006 at 120) plus the intermediate 160-col case.

```mermaid
flowchart TD
    T["Terminal width (term)"] --> R{"term >= 120?"}
    R -- "yes — activity rail shown" --> B1["body_w = term - 24"]
    R -- "no — rail collapsed<br/>(width-narrow, rail only:<br/>no MAC rule anymore)" --> B2["body_w = term - 6"]
    B1 --> H{"round(3/7 * body_w) >= 82?"}
    B2 --> H
    H -- "yes — proportional regime<br/>(term >= ~216)" --> HP["hex_w = round(3/7 * body_w)"]
    H -- "no — floor regime<br/>(120 <= term <= ~215)" --> HF["hex_w = 82<br/>(min-width floor: full hex row)"]
    HP --> REC["records_w = body_w - hex_w"]
    HF --> REC

    S1["Sample: 120 cols -> body 96<br/>3/7*96 = 41 < 82 -> hex 82, records 14<br/>(TC-004 / TC-006)"]:::sample
    S2["Sample: 160 cols -> body 136<br/>3/7*136 = 58 < 82 -> hex 82, records 54<br/>(TC-021' second size)"]:::sample
    S3["Sample: 250 cols -> body 226<br/>round(3/7*226) = 97 > 82 -> hex 97, records 129<br/>(TC-002 / TC-003)"]:::sample

    HF -.-> S1
    HF -.-> S2
    HP -.-> S3

    classDef sample fill:#1e2a38,stroke:#5b8db8,color:#d0dce8;
```
