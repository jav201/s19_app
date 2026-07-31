# Legend modal — widget tree, before vs after

> Batch `2026-07-30-batch-72`, HLR-072-5 / HLR-072-6 / HLR-072-7 · `s19_app/tui/screens.py::LegendScreen.compose`
> Ids are shown without their leading `#` for diagram legibility; in CSS and in the code they are
> `#legend_body`, `#legend_card_pane`, and so on.
> Every number below is measured — `00-measurements.md` M-2 (120x30), M-3 (80x24), M-6 (widget counts).

## The change in one sentence

**The body stopped being a single scrolling column and became a two-pane wrapper** — same id, same
data layer, same widgets, re-parented into two independently scrolling panes so the colour key is
beside the example card instead of ~18 content rows below it.

---

## BEFORE — one scrolling body (shipped on `origin/main`)

```mermaid
graph TD
    D["Container: legend_dialog<br/>width 70% · height 90%"]
    T["Label: 'Classification legend'<br/>class modal-title"]
    B["ScrollableContainer: legend_body<br/>height 1fr · overflow-y auto<br/><b>viewport 15 rows · virtual height 39 (mac) / 44 (map)</b><br/>max_scroll_y 24 (mac) / 29 (map)"]
    C1["_render_card() output<br/>17 widgets (mac) / 20 (map)<br/>the annotated example card"]
    K1["_render_key() output<br/>6 widgets (mac) / 7 (map)<br/>the colour key"]
    PY["'Pale yellow' key row<br/><b>content row 33 — 18 rows below the fold</b>"]
    BT["Container: legend_buttons"]
    CL["Button: legend_close"]

    D --> T
    D --> B
    D --> BT
    B --> C1
    B --> K1
    K1 -.-> PY
    BT --> CL

    style B fill:#4a2020,stroke:#c05050,color:#f0f0f0
    style PY fill:#4a2020,stroke:#c05050,color:#f0f0f0
```

**What the reader is looking at.** `compose` concatenated the two widget lists — `body =
_render_card() + _render_key()` — and handed the whole thing to one scrolling container. The card
comes first, the key comes after it, and the key therefore begins below whatever the card happens to
occupy. At 120x30 that is content row 33 in a 15-row viewport. The operator's report is exactly this
geometry: **to read what a colour means you first scroll past the example card that uses it.**

---

## AFTER — two panes inside the preserved wrapper (wide regime, width ≥ 120)

```mermaid
graph TD
    D["Container: legend_dialog<br/><b>width 96%</b> · height 90%<br/>= 113 cols, content 107 after 6 cols of modal chrome"]
    T["Label: 'Classification legend'<br/>class modal-title"]
    B["<b>Horizontal: legend_body</b><br/>id PRESERVED as the two-pane wrapper<br/><b>overflow: hidden</b> — no third scroll context<br/>Region(6, 6, 107, 15)"]
    CP["ScrollableContainer: legend_card_pane<br/>width 3fr = <b>64 cols</b> · height 1fr · overflow-y auto<br/>holds _render_card() output UNCHANGED<br/>17 widgets (mac) / 20 (map) · max_scroll_y 18"]
    KP["ScrollableContainer: legend_key_pane<br/>width 2fr = <b>43 cols</b> · height 1fr · overflow-y auto<br/>holds _render_key() output UNCHANGED<br/>6 widgets (mac) / 7 (map)<br/><b>14 content rows in a 15-row pane — max_scroll_y 0</b>"]
    PY["'Pale yellow' key row<br/><b>content rows [5, 8) — visible at scroll_offset 0</b>"]
    BT["Container: legend_buttons"]
    CL["Button: legend_close"]

    D --> T
    D --> B
    D --> BT
    B --> CP
    B --> KP
    KP -.-> PY
    BT --> CL

    style B fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
    style KP fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
    style PY fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
```

**Three things to notice, because each was a deliberate decision.**

1. **`legend_body` kept its id.** It was a candidate for retirement, and retirement was measured
   **wrong**: nine descendant query sites across three test files select through it, and two
   `REQUIREMENTS.md` rows name it. It is now the wrapper rather than the scroller.
2. **The scroll context moved down one level.** `overflow-y: auto` came off the body and went onto
   the two panes; the body is `overflow: hidden`. Without that move there would be three nested
   scroll contexts and the panes' scrollbars would fight the body's.
3. **The data layer did not change at all.** `_render_card()` and `_render_key()` are called once
   each, exactly as before, and their returned widgets are **re-parented, never reconstructed**.
   `s19_app/tui/legend.py` is byte-identical to `origin/main` — asserted, not assumed.

---

## AFTER — the floor regime (width < 120)

At the 80-column floor there is no room for two columns. The panes stack, **key first**, and the key
becomes scroll-reachable rather than fully visible.

```mermaid
graph TD
    D["Container: legend_dialog<br/><b>class legend-narrow</b> (toggled at runtime)"]
    B["Horizontal: legend_body<br/><b>layout: vertical</b> (narrow rule)<br/>content budget 9 rows"]
    KP["ScrollableContainer: legend_key_pane<br/>width 100% · height 1fr<br/>Region(6, 6, 68, 4)<br/><b>FIRST in document order</b><br/>key content 10 rows (mac) / 11 (map)<br/>max_scroll_y 6 (mac) / 7 (map)"]
    CP["ScrollableContainer: legend_card_pane<br/>width 100% · height 1fr<br/>Region(6, 10, 68, 5)<br/>SECOND"]

    D --> B
    B --> KP
    B --> CP

    style KP fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
```

**Why "key first" is not a CSS property.** Textual 8.2.8 has no CSS ordering property, so **document
order is the stacking order**. The wide order is what `compose` yields (card, then key); the floor
order is produced at runtime by `#legend_body.move_child(...)`. CSS alone can stack the panes — it
cannot reorder them. That distinction was proven by mutation: replacing the `move_child` call with a
no-op leaves the `legend-narrow` class flipping correctly and the panes stacking correctly, and only
the **order** wrong.

**Why the key is not required to be fully visible at the floor.** Measured: 9 rows of budget against
a 10-or-11-row key. "Both panes visible" is unachievable under any non-degenerate layout, so the
requirement asks for the honest, testable property instead — the key is **reachable under scroll**,
which is one interaction, and the card is guaranteed at least 2 rows so a future layout cannot
satisfy "key first" by starving the card to a single line.

---

## Data flow — what is computed where

```mermaid
flowchart LR
    LP["legend.py<br/>LEGEND_EXAMPLES, band-key branch<br/><b>UNCHANGED — byte-identical to origin/main</b>"]
    RC["LegendScreen._render_card()<br/>returns a flat List[Widget]<br/>0 containers"]
    RK["LegendScreen._render_key()<br/>returns a flat List[Widget]<br/>0 containers"]
    CO["LegendScreen.compose()<br/><b>the only function this batch changed</b>"]
    P1["legend_card_pane"]
    P2["legend_key_pane"]
    WR["legend_body wrapper"]

    LP --> RC
    LP --> RK
    RC --> CO
    RK --> CO
    CO --> P1
    CO --> P2
    P1 --> WR
    P2 --> WR

    style LP fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
    style CO fill:#2a3350,stroke:#6274a8,color:#f0f0f0
```

The split was cheap precisely because both render helpers already returned **flat widget lists with
no container of their own** — measured before the design was fixed, not discovered during
implementation. Had either returned a pre-wrapped container, the two-pane split would have required
a data-layer edit and this batch would have had a very different shape.
