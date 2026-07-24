# N8 — Per-view Legend enrichment · prototype decision notes

THROWAWAY design pass (supervised gate). Prototype: `legend_n8.prototype.py`
(sub-shape B — standalone, reuses real `LEGEND_TABLE` + `.sev-*` classes + the
real `styles.tcss`, so colours are honestly quantized). SVGs captured at 120- and
80-col regimes: `legend_n8.variant_{A,B,C}.{120w,80w}.svg`. Rendered on
textual==8.2.8 (honest on this box; not a cross-machine pixel contract).

Gallery artifact (both regimes side by side):
https://claude.ai/code/artifact/8fec4d40-0ac4-4471-8c29-25b4a801e1bc

## The three layouts

- **A — card on top.** Bordered example card, then the colour key stacked below.
  Calmest, most scannable; survives 80-col; taller (more scroll).
- **B — two-column.** Example | colour key side by side. Compact vertically;
  needs width — wraps/collapses at 80-col.
- **C — inline sample key.** Each colour row carries a sample token painted in
  that severity; example and key merge. Densest; weakest as an explicit
  "construction" for the Workspace (example-only) section.

## Content shown (the real N8 content proposal, layout aside)

- **Workspace** (NEW, example-only — no colour key): the "Loaded" panel slots
  `S19 firmware.s19 · 1.2 KB · 3 rng` / `MAC · 12 records` / `A2L · 48 tags` /
  `(none)`, annotated kind · filename · summary · what-it-is.
- **A2L**: a tag row `RPM_LIMIT VALUE 0x80040000 4 B` labelled
  name/type/address/length, + "row colour = memory-check result", above the
  existing colour key.
- (MAC / Map / Issues follow the same pattern in the real build.)

## Recommendation (provisional — awaiting operator pick)

**A (card on top)**, optionally borrowing **C's painted sample token** inside each
colour-key row (hue shown on a realistic value). A reads cleanest and is the only
one that holds up at 80-col; C's inline idea is worth grafting onto A's card.

## DECISION: _(pending operator)_
