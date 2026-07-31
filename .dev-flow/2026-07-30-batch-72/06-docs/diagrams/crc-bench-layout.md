# CRC Designer bench — layout, before vs after

> Batch `2026-07-30-batch-72`, HLR-072-1 / HLR-072-2 / HLR-072-3 ·
> `s19_app/tui/crc_designer_view.py::CrcDesignerPanel.compose`
> Ids are shown without their leading `#` for diagram legibility.
> The bench shipped in batch-59 and was **never registered in `REQUIREMENTS.md`** — this batch adds
> `R-TUI-100`, the first requirement row the CRC Designer has ever had.

## The change in one sentence

**Two controls that read as one became a single labelled pair, and a verdict that had been given a
hero tile became an annotation of the field it validates** — freeing the hero row's right column for
Warnings alone.

---

## BEFORE — stacked switch rows and a verdict hero (shipped on `origin/main`)

```mermaid
graph TD
    subgraph HERO["crc_hero_row"]
        CW1["Static: crc_coverage_window<br/>the live coverage strip · 2fr<br/>measured area 305"]
        TR1["Vertical: crc_top_right · 1fr"]
        LV["<b>Vertical: crc_live_verify</b><br/>class crc-field-group <b>crc-hero</b><br/>content-align center middle · min-height 3<br/>30 x 4 = area 120"]
        LVL["Label: 'Known answer · 123456789'<br/>class crc-group-title"]
        KV1["Static: crc_kat_verdict<br/>markup=False · the tri-state glyph"]
        WG1["Vertical: crc_warnings_group<br/>30 x 4 = area 120"]
    end
    TR1 --> LV
    LV --> LVL
    LV --> KV1
    TR1 --> WG1

    subgraph ALG1["crc_algorithm_fields — bench column c1"]
        R1["row: Preset (Select)"]
        R2["row: Width (bits)"]
        R3["row: Polynomial"]
        R4["row: Init"]
        S1["<b>row: 'Reflect in'  [Switch crc_field_refin]</b><br/>border: none · height 1"]
        S2["<b>row: 'Reflect out' [Switch crc_field_refout]</b><br/>border: none · height 1<br/><b>abuts the row above — reads as ONE control</b>"]
        R7["row: XOR out"]
        R8["row: Check"]
    end
    R1 --- R2 --- R3 --- R4 --- S1 --- S2 --- R7 --- R8

    style LV fill:#4a2020,stroke:#c05050,color:#f0f0f0
    style S1 fill:#4a2020,stroke:#c05050,color:#f0f0f0
    style S2 fill:#4a2020,stroke:#c05050,color:#f0f0f0
```

**The two defects the operator reported, in the geometry.**

- **"Two switches look like one."** Two stacked single-row rows, each holding a `Switch` styled
  `border: none; height: 1`, with no row margin and no separator between them. `border: none`
  removes the only visual boundary Textual would otherwise draw, so the two 1-row borderless
  switches abut and read as one wider control. Measured on the shipped tree: `crc_field_refin` at
  `y=32 h=1`, `crc_field_refout` at `y=33 h=1` — exactly abutting.
- **"The known-answer verdict does not earn its placement."** It occupied a centre-aligned hero tile
  in the hero row's right column, at the same visual weight as the Warnings group, for a value that
  is a bench self-test rather than an operational result.

---

## AFTER — a paired Reflection row, a Self-test annotation, a Warnings-only right column

```mermaid
graph TD
    subgraph HERO2["crc_hero_row"]
        CW2["Static: crc_coverage_window<br/>the live coverage strip · 2fr"]
        TR2["Vertical: crc_top_right · 1fr<br/><b>exactly one child group</b>"]
        WG2["Vertical: crc_warnings_group<br/><b>the whole right column</b>"]
    end
    TR2 --> WG2

    subgraph ALG2["crc_algorithm_fields — bench column c1"]
        Q1["row: Preset (Select)"]
        Q2["row: Width (bits)"]
        Q3["row: Polynomial"]
        Q4["row: Init"]
        PAIR["<b>row: 'Reflection'   in [Switch crc_field_refin]   out [Switch crc_field_refout]</b><br/>ONE Horizontal, class crc-field-row<br/>both switches share a single row band<br/><b>the 'out' sub-label renders BETWEEN their x-bands</b>"]
        Q7["row: XOR out"]
        Q8["row: Check"]
        ST["<b>row: 'Self-test'  123456789  [Static crc_kat_verdict]</b><br/>markup=False preserved · id preserved<br/>directly below the field it validates"]
    end
    Q1 --- Q2 --- Q3 --- Q4 --- PAIR --- Q7 --- Q8 --- ST

    style WG2 fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
    style PAIR fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
    style ST fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
```

**What each change buys.**

| Change | What the operator now sees | What is guaranteed |
|---|---|---|
| One `Reflection` row with `in` / `out` sub-labels | A single labelled control that plainly contains two toggles | The two switches share one row band, and a `Label` renders **strictly between** their x-bands. Not co-location — separation |
| `Self-test` row under `Check` | The verdict sits with the field it validates, and names the reference vector `123456789` on screen | The id, the `markup=False` flag and the tri-state tokens (`✓ MATCH` / `✗ MISMATCH` / `○ NO-EXPECTED`) are all preserved; the verdict is still live, driven by a real edit to the Check field |
| `crc_top_right` holds Warnings only | The hero row's right column spends its space on the one thing that reports problems | Exactly one child group; the `crc_live_verify` wrapper is no longer composed at all |
| The per-toggle row helper deleted | *(nothing — invisible)* | Repo-wide grep for the helper name returns **zero** hits. It is removed, not left dead |

**The reference vector naming is load-bearing, not decoration.** The old hero tile's title was the
only on-screen occurrence of `123456789` in the entire repository. Without carrying it into the new
row, the row would read `Self-test ✓ MATCH` and never say *what* was self-tested.

---

## The separability guard, and why it is scoped the way it is

```mermaid
flowchart TD
    START["G-1: 'no control reads as another control'<br/>How do we make this a test?"]
    A["Rule (a): no two abutting focusable controls"]
    B["Rule (b): no two abutting controls of the SAME widget class"]
    C["Rule (c): no two abutting <b>Switch</b> widgets"]
    AR["<b>16 violations before → 15 after</b><br/>the other 15 abut BY DESIGN<br/>(batch-59's approved compact-row decision)"]
    BR["<b>7 violations before → 6 after</b><br/>RED before AND after"]
    CR["<b>1 violation before → 0 after</b>"]
    AV["REJECTED — can never reach zero<br/>without a redesign nobody asked for"]
    BV["REJECTED — a gate that is red on both sides<br/>of the change is not a gate"]
    CV["<b>ADOPTED</b> — the only rule that is false<br/>before and satisfiable after"]

    START --> A --> AR --> AV
    START --> B --> BR --> BV
    START --> C --> CR --> CV

    style AV fill:#4a2020,stroke:#c05050,color:#f0f0f0
    style BV fill:#4a2020,stroke:#c05050,color:#f0f0f0
    style CV fill:#1f3a24,stroke:#4f9a5f,color:#f0f0f0
```

**Why this is a guard and not special-pleading for one pair.** The subject set is **derived from the
live screen** — every `Switch` with a non-zero render area — never hand-listed, so a third toggle
added to this screen is policed with no test edit. Its completeness rests on a separate, static fact
about the source: `Switch` is imported and constructed **only** in `crc_designer_view.py`, so every
`Switch` that can exist is composed by this view and is inside the scope the guard walks.

**A footnote that turned out to matter.** The specification pinned that fact as a *count* — "exactly
one construction site". That was true when it was measured, on `origin/main`. This batch then
**falsified it by succeeding**: deleting the per-toggle helper (one construction call invoked twice)
and inlining both toggles converted one site into two. The guard now asserts the invariant the count
stood for — single-module confinement — which survived the refactor untouched. A measured constant
is true of the tree it was measured on; when your own change *is* what moves that tree, prefer the
invariant to the number.
