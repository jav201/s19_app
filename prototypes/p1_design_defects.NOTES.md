# P1 design defects — prototype NOTES (2026-07-30)

> THROWAWAY design artifacts for the four operator-flagged P1/P2 defects of 2026-07-28
> (`.dev-flow/BACKLOG-CODE.md` §"Operator-flagged 2026-07-28"). Produced under
> `/tui-design` PROTOTYPE mode (sub-shape A: variants mounted INSIDE the real app).
> The implementation plan for the next session is `p1_design_defects.HANDOFF-PLAN.md`.
> Rendered on the canonical pin: **textual 8.2.8 / rich 15.0.0** (skill's measured pin).

## 1. Brief (INTAKE — operator answers taken from the backlog capture, not re-asked)

| Question | CRC Designer | Legend pop-ups |
|---|---|---|
| **Posture** | **OPERATED** — a parameter bench the user drives field-by-field; live recompute, no Run button | **READ** — a reference document opened occasionally, scanned, closed |
| Subject | CRC algorithm definition + coverage over a loaded image | The meaning of every colour/glyph the active view paints |
| Single job | edit parameters and *see the consequence immediately* | answer "what does this colour/glyph mean?" in <10 s |
| Audience | firmware engineer at the designer bench | same, but mid-task and impatient |
| Operator verdict on file | switches must separate; KAT: **remove or demote, not keep-as-hero**; needs design guards | "mejor reorganización y otras mejor implementación" |

**Contradiction check (INTAKE rule):** the operator's KAT framing ("no use unless you know
the result beforehand") under-states one measured fact — `kat_ok` validates the *algorithm
definition* against the published `123456789` check, the standard CRC self-test. The
backlog already records this nuance; the variants below therefore explore **demote** and
**remove**, never silent keep.

## 2. State inventory (INTAKE law — a screen is a family of states)

**CRC Designer** (~10 states, 6 designed): seed/MATCH · edited/MISMATCH · NO-EXPECTED
(empty check) · invalid-params (one warning across all 6 surfaces) · coverage-empty (no
image) · coverage-live (concat+fill+store) · refused (`on_gap_conflict=abort`) ·
truncation warning · fill-no-pad warning · load/save status line. `_recompute` queries
ALL SIX surface ids and aborts on the first `NoMatches` — **any redesign that deletes a
surface id must also edit `_recompute`** (this is why Variant C *hides* rather than
removes `#crc_kat_verdict`).

**Legend modal** (static per view — 5 cards): workspace (29 lines, longest) · a2l · map
(band key branch, `markup=False` rows) · mac (inline-orange warning sample
`#legend_mac_warning_sample`) · issues. Two additive passes (N1 filtering, N8 cards) and
no layout pass between them: today the *actual key* sits BELOW a card that can be ~29
lines deep in one flat scroll.

## 3. Captured states (THREE STATES / FRAME laws)

Complete frames at real size, never crops. Pinned sizes: **120x30** (design size) and
**80x24** (floor). CRC per variant: `empty@120x30`, `loaded@120x30`, `invalid@120x30`,
`loaded@80x24`. Legend per variant: `workspace@120x30`, `mac@120x30`, `mac@80x24`.
**Dropped, stated (no silent caps):** legend `map`/`a2l`/`issues` shots (the variants
reorganize card+key generically, so the band-key branch renders — runnable live, not
captured); CRC `refused` state (needs a conflicting fixture; same tile as `loaded`).

## 4. CRC Designer variants (`crc_designer.p1.inapp_prototype.py`)

All three keep every shipped `#crc_*` id mounted so the real handlers stay live
(sub-shape A rule), and all three fix the switch-fusion defect — each by a *different
structure*, which is the point of the comparison.

| | Layout claim | Switch fix | KAT placement |
|---|---|---|---|
| **A — Guard rails** (surgical) | shipped bench unchanged | visible track tile + on/off state word + 1-row gap between the two switch rows | kept as hero tile (baseline for comparison; operator already rejected — control variant only) |
| **B — Paired reflection** | Algorithm group gains ONE `Reflection  in [sw] ⇄ out [sw]` row — a semantic pair reads as a pair | adjacency eliminated horizontally: label between the two switches | **demoted**: `Self-test` annotation row directly under `Check` (verdict is a property of the check field); hero right column = Warnings only |
| **C — Vocabulary + strip** | reflection collapses to a `Select` (`none/in/out/both`) — 4 combos, 1 control, 0 switches visible | the two Switches removed from view (hidden, synced from the Select so `_current_algorithm` still reads them) | **"removed"**: verdict hidden; a dim note points at the save-time KAT warning that `_save_template` already emits |

Design guards demonstrated (→ HANDOFF-PLAN §5 for the AT encodings):
**G-1 separability** (adjacent focusables must not abut without a non-colour boundary),
**G-2 state legibility** (a control's state must render as glyph/word, not slider position
alone), **G-3 hero extent** (the coverage window stays the 6:1 hero; no second
majority-bright tile).

## 5. Legend variants (`legend_p1.inapp_prototype.py`)

All three subclass the shipped `LegendScreen` and re-use its data pipeline
(`LEGEND_EXAMPLES` role mapping + `_render_key`, incl. the map band-key branch and the
`#legend_mac_warning_sample` inline-orange row).

| | Structure | Claim |
|---|---|---|
| **A — Tabbed** | one `TabPane` per `ROLE_SUB` card section + a final `Key` tab | a 29-line card becomes 5-7 shallow pages; nothing scrolls past a screen |
| **B — Two-pane** | card left (3fr) ∥ colour key right (2fr), independent scrolls; stacks at the floor | the key is *always on screen* — the thing named "legend" stops living below the fold |
| **C — Key-first outline** | colour key pinned at top, card sections as `Collapsible`s (first open, rest closed) | inverted hierarchy: the reference answer first, the teaching examples on demand |

## 6. Run / capture

```bash
python prototypes/crc_designer.p1.inapp_prototype.py A   # live (A|B|C), press 0 → CRC
python prototypes/crc_designer.p1.inapp_prototype.py shot
python prototypes/legend_p1.inapp_prototype.py A         # live (A|B|C), press k on any view
python prototypes/legend_p1.inapp_prototype.py shot
```

SVGs land beside this file as `crc_p1.variant_<V>.<size>.<state>.svg` /
`legend_p1.variant_<V>.<view>.<size>.svg`.

## 7. Verdict — OPERATOR TO FILL

| Surface | Winner | Steals from | Notes |
|---|---|---|---|
| CRC Designer | ☐ A ☐ B ☐ C | | KAT: ☐ demote (B) ☐ remove (C) |
| Legend modal | ☐ A ☐ B ☐ C | | |

Throwaway convention: absorb the decision into the implementing batch, then DELETE
`crc_designer.p1.*`, `legend_p1.*`, `p1_design_defects.NOTES.md` and the SVGs
(`screen_upgrades` precedent §10.4).
