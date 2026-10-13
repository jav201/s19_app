# Requirements ledger — s19_app — Batch 2026-10-13-batch-94

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-13-batch-94.1 — the spec sheet's fourth box names what it documents (P1)
- **Requirement:** HLR-134 (the amendment's own requirement; the amended target is the batch-93 legend law, named in the What-changed prose)
- **Date:** 2026-10-13
- **What changed:** the fourth box's title `Keys` -> `Map keys`. Before: a box titled `Keys` inside the OPEN legend read as the modal's own keys, but its pinned line documents the MAP's (`k` opens the legend; inside, only Esc closes and the arrows scroll). After: the title says what the line documents; the pinned `MAP_KEYS_LINE` verbatim is unchanged; the other three boxes and every other view's legend byte-identical.
- **Why:** the operator's feedback from live testing 2026-10-13: "Veo esto en la leyenda [Keys: j k select...] pero k precisamente abre la leyenda, no es para desplazarse o seleccionar, es esto un error?"
- **Evidence:** `s19_app/tui/screens.py` (`_box("Map keys", ...)`); the pin in `tests/test_legend_map_sheet.py` (the title census); the map legend's other pins (TC-681) byte-identical -- the amendment touches one word of chrome, no content.
