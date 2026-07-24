# N8 — Kimi card-on-top Legend: exact copy + density notes

Design-prototype deliverable for feature N8 (comprehensive per-view Legend).
Companion files:

- `legend_n8.kimi.prototype.py` — runnable Textual app (keys 1–5 / ←→ switch views, `q` quits)
- `legend_n8.variant_kimi.<view>.svg` — captured at 120×40 (`workspace`, `a2l`, `memory_map`, `mac`, `issues`)
- Content spec: `legend_n8.INVENTORY.md`

Run:

```powershell
$env:PYTHONUTF8='1'; Remove-Item Env:NO_COLOR -ErrorAction SilentlyContinue
python prototypes/legend_n8.kimi.prototype.py        # live
python prototypes/legend_n8.kimi.prototype.py shot   # write the 5 SVGs
```

> **Gotcha (found while prototyping):** this shell exports `NO_COLOR=1`, and Textual
> honours it — under `NO_COLOR` the app runs with the `nocolor` pseudo-class and the
> SVGs come out **colourless** (layout intact, every custom fill stripped). The shot
> must run with `NO_COLOR` unset or the whole point of the legend is invisible.

## Layout (decided)

Single scrollable column at modal width (90% × 90% of 120×40): **annotated example
CARD on top, colour key below it**. Card lines are ≤ 98 visible chars so nothing
wraps unexpectedly; each whole view fits the ~32-row body viewport. Line roles:
**bold accent** = sub-heading, normal = rendered sample (Rich markup), dim = `= …`
annotation. Colour-key rows are the *real* `LEGEND_TABLE` entries painted with the
real `sev-*` classes; the Memory-Map key uses the real `band-*` classes.

> **Second found gotcha:** Textual `Label` *truncates* at viewport width; `Static`
> *wraps*. The production `LegendScreen` uses `Label`, so long meanings (e.g. the
> Issues "Errors" row, 148 chars) silently lose their tails at 120 cols. The
> prototype uses `Static` for key rows — the fold-in should too.

---

## 1 · Workspace (example-only, no colour key)

**Memory strip (top) — one glyph per address cell; glyph carries meaning, colour secondary**
```
·  ░  ▒  ▓  ╱  █
· constant/padding (grey)   ░ low—structured/tables (green)   ▒ medium—calibration (amber)
▓ high/random—code (red)   ╱ gap/unmapped   █ fallback: valid green / invalid red / gap grey
```
**Loaded panel — one slot per artifact**
```
S19  firmware.s19   1.2 KiB · 3 rng   = name · mapped bytes · range count
MAC  checks.mac   5 records      A2L  model.a2l   42 tags   = name · count
(none) dim = not loaded · [u] unload one · [U] unload all
```
**Data Sections (left pane) — one row per contiguous range**
```
✓ 0x00000000 – 0x000004FF   1.2 KiB ▒
= ✓/✗ validity · start address · inclusive end · humanized size · dominant band glyph
green row = valid · red = invalid · █░░░░░░░ 8-cell bar = range size vs largest range
... N more ranges (see log) ... = over 200 · MAC out-of-range @ 0x… = amber, outside ranges
```
**Hex view (center pane) — Search ASCII / Goto 0xADDR drive it**
```
0x00001000  DE AD BE EF … 00  |.....|
= row address · 16 byte values (blank = unmapped) · ASCII gutter (. = non-printable)
```
**Context / coverage stats (right pane)**
```
Coverage: 87.50%   Ranges: 3   Errors: 0   Warnings: 2
= % of image span covered by valid ranges · total ranges · ERROR issues · WARNING issues
Loader 0 err · ⚠4 OOO · Entry 0x00000000
= loader errors (red >0) · out-of-order S19 records (yellow >0) · entry point (— when absent)
A2L summary lines 1-20 / 142 = right-pane preview · No A2L loaded. = empty
```
**Status bar (under every screen)**
```
last action · progress bar · 4 log-tail lines · empty: No file loaded - Ctrl+L (or 'l') / 'p'
```
Closing note: `(this view has no severity colour key — its cues are the glyphs and labels above)`

**If density overwhelms, cut in this order:**
1. Status-bar block (sub + line) — the bar is self-explanatory in situ.
2. `A2L summary lines 1-20 / 142 …` caption.
3. The `... N more ranges (see log) ...` caption (truncation is rare).
4. Merge the two memory-strip captions into one (drop the per-glyph colour names, keep meanings).

## 2 · A2L Explorer (card + real `LEGEND_TABLE["A2L"]` key)

**One table row — the 16 Explorer columns (sample values, in two halves)**
```
RPM_LIMIT ✓  0x80040000  4  assigned  7500  7500.0  yes  flash
= Tag(name + ✓ in image / · not) · Address · Length(bytes, n/a) · Source(assigned/formula)
· Raw(decoded) · Physical(engineering value) · InMem(yes/no/n/a) · Region(flash/ram/unknown)
0..8000  rpm  —  MSB_FIRST  no  ENGINE  calibratable  UWORD
= Limits lo..hi · Unit · Bits mask · Endian · Virt · Func · Access · Dtype
Access: read_only / calibratable · Dtype: UWORD, FLOAT32_IEEE …
```
**Summary line**
```
Page 2/7 | tags 201-400 / 1394 (page size 200; +/- to change) · 312 in image
= current page / pages · tag range shown / total · page-size hint · in-image counter (green)
```
**Filter row**
```
[text]  [Field: name]  (All | Invalid | In-Memory)  [Find next]  [Page Prev/Next]
text narrows rows · Field targets one column · modes all/invalid/in-image · Find next · paging
```
**Detail card (selected tag — fields beyond the table)**
```
desc · unit/conv · layout(RECORD_LAYOUT) · byteorder · limits · display_identifier
~10 more fields stay in detail/log only (matrix dims, axis meta, decode errors, raw bytes…)
```
Colour key (verbatim from `LEGEND_TABLE`, painted `sev-error` / `sev-ok` / no-class / `sev-neutral`):
- Red — schema/structural failure: malformed required field, invalid required reference, or hard-error duplicate symbol
- Green — memory checked — tag/range fully found in the loaded S19/HEX image
- White — valid A2L record with no hard inconsistency, including valid records not present in the image
- Grey — memory not checked yet, or no primary S19/HEX context loaded

**Cuts:**
1. Filter-row block (buttons are labelled on screen).
2. `Access:`/`Dtype:` vocabulary caption.
3. Collapse the 16-column gloss to the 6 decision columns (Tag, Address, InMem, Region, Limits, Dtype).
4. `~10 more fields…` caption.

## 3 · Memory Map (card + real `band-*` key — NOT a severity key)

**Header + band bar (one proportional segment per merged run)**
```
Entropy bands - 7 region(s), 262144 B mapped
= merged runs + mapped bytes · empty: No file loaded … / No entropy detail for this image.
▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓╱╱╱░░░░░░░░░░····▓▓▓▓▓▓     (segments painted with the real band-* classes)
glyph repeated per segment · ╱╱╱ gap hatch = unmapped gap between runs (NOT a band)
80000000      80004000      80008000      8000C000      8000FFFF
address ruler — 5 ticks at 0/25/50/75/100 % of span (8-hex, no 0x prefix)
```
**Region row (click to inspect + jump to hex)**
```
░ 0x80000000  256 B  ██░░  3 sym  low ↵
= band glyph · start · size · 4-cell size bar(vs largest) · symbols · band label · ↵ open hex
```
**At a glance**
```
░ low 4 ████ 66%   = per-band histogram: glyph · band · count · 6-cell bar · % of regions
 ▁▂▅█▇▄▂▁ …
sparkline — 24-col entropy profile, 9-level ramp " ▁▂▃▄▅▆▇█" (0 none → 8 max), band-coloured
```
**Coverage stats + region inspector**
```
Coverage: 98.44% · Bytes covered · Valid/Invalid ranges · Gaps · Largest gap · Total issues
inspector: Status VALID/INVALID/GAP · Cell · Region(+A2L sym) · issues · Size · band · Peek
```
Band key (ranges from the real `ENTROPY_BANDS`, painted `band-constant/low/medium/high`):
- `· constant/padding [0,1)` — padding / fill
- `░ low [1,5)` — structured / tables
- `▒ medium [5,7.2)` — calibration / data
- `▓ high/random [7.2,8]` — code / compressed / random
- `╱ gap hatch` — unmapped gap between runs (NOT a band, no colour class)

Closing note: `bands = bits/byte entropy over a 256 B window; boundary values go to the HIGHER band. Bands ≠ severities: an ENTROPY domain, separate from the sev-* severity domain.`

**Cuts:**
1. Sparkline sample + caption (the band key already teaches the ramp colours).
2. Address-ruler sample (ticks are self-evident) — keep the "no 0x prefix" fact by appending to the header caption.
3. Inspector caption → keep only `Status VALID/INVALID/GAP · Peek`.
4. Histogram annotation (keep the sample; the sub-heading says what it is).

## 4 · MAC (card + real `LEGEND_TABLE["MAC"]` key + reconciliation block)

**Coverage strip**
```
MAC→S19 1 of 2 █████░░░░░ · A2L↔MAC 3 matches
= MAC addresses in the image (count + green bar) · A2L↔MAC same-address matches
```
**One table row — the 8 columns**
```
✓ VVT_ENABLE  0x80040000  yes  yes  OK  12  —  MEAS:VVT_ENABLE
= Tag(glyph+name) · Address · InA2L · InMem · Status · SourceLine(.mac) · ParseErr · A2LMatch
```
**Tag status glyphs (glyph is the primary cue)**
```
✗ parse error(red) · ⚠ out-of-image(orange) · ✓ in image(green) · · not checked(grey)
MAC-only / no primary image stays grey — deliberately NOT green
```
**Status vocabulary → row colour**
```
ERR_PARSE / A2L_ADDR_MISMATCH / NO_ADDR = error(red) · NOT_IN_A2L = warning
OUT_OF_IMAGE = info(white) · NO_A2L = neutral(grey) · OK = green
```
Colour key (verbatim from `LEGEND_TABLE`):
- Red — parse failed, invalid/missing name or hex address, or A2L↔MAC same-name address mismatch
- Pale yellow — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity
- Green — exact name + address match with A2L
- White — structurally valid MAC entry, no hard inconsistency, not positively cross-confirmed
- Grey — no A2L loaded, or validation context missing

**Reconciliation block (the gotcha — see next section):**
```
⚠ ORANGE vs Pale yellow — the key names the SEVERITY (.sev-warning #f6ff8f, cross-view lists)
⚠ VVT_TEMP  0x80041234  yes  no  NOT_IN_A2L  17   ← what a warning row looks like   (painted inline orange #d9a35b)
the MAC DataTable paints INLINE styles — a warning row renders orange (the MAC cue: ⚠ glyph,
hex MAC overlay, Sections labels). Two pipelines, one severity — trust glyph + Status not hue.
```

**Cuts:**
1. Coverage-strip block (the summary line already carries the coverage %s).
2. Status-vocabulary block (the key + glyphs carry the same mapping).
3. The second reconciliation caption (keep the orange sample row + one-line explanation).

## 5 · Issues (card + real `LEGEND_TABLE["Issues"]` key)

**Severity strip — whole-list distribution + 5-cell bars (red / pale yellow / cyan)**
```
Errors 3 ███░░   Warnings 1 █░░░░   Info 2 ██░░░
```
**Filter row**
```
(All | Errors | Warnings)  [Legend]   — Info rows appear only under All
```
**Grouped list (order ERROR → WARNING → INFO)**
```
✗ ERRORS (3)
   TRIPLE_NAME_ADDRESS_MISMATCH   VVT_ENABLE · 0x80040000 · addresses differ   a2l, mac, s19
= code chip · detail(symbol · 0xADDR · message) · related artifacts · ⚠/• head W/I groups
```
**The 17 issue codes, by family (E = error, W = warning)**
```
MAC: PARSE_ERROR · EMPTY_NAME · INVALID_ADDRESS · DUPLICATE_NAME (E) DUPLICATE_ADDRESS (E/W/I)
A2L: STRUCTURE_ERROR·INVALID_ADDRESS·DUPLICATE_SYMBOL(E) UNRECOGNIZED_BLOCK·BROKEN_REFERENCE(W)
CROSS: MAC_S19 / A2L_S19 OUT_OF_RANGE + OVERLAP_AMBIGUOUS (W) · MAC / A2L_ONLY_SYMBOL (W)
TRIPLE_NAME_ADDRESS_MISMATCH (E)
```
**Summary + Hex Peek**
```
total=6 | errors=3 | warnings=1 | info=2 | filter=all | page 1/1 rows 1-6/6
Hex Peek — ±6 hex rows around the selected issue's address · (issue has no address …)
```
Colour key (verbatim from `LEGEND_TABLE`):
- Errors — parse/structure errors, empty name, invalid/missing address, duplicate symbol, broken GROUP/FUNCTION references, or A2L↔MAC same-name mismatch  *(Red)*
- Warnings — address/range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias  *(Pale yellow)*
- Optional info — valid-but-not-image-backed, not-checked-without-primary-image, or virtual/dependent non-memory-backed objects  *(Cyan)*

**Cuts:**
1. The 17-code census → keep one line: `codes follow FAMILY_REASON: MAC_* · A2L_* · CROSS_* · TRIPLE_* (severity in the key below)`. The full census belongs in REQUIREMENTS.md, not a modal.
2. Filter-row block (only three buttons, all self-labelling).
3. Summary sample line (the counters name themselves).

---

## The MAC orange-vs-"Pale yellow" gotcha — how this legend reconciles it

**The conflict.** Two paint pipelines coexist:

1. The *legend-word* pipeline: `LEGEND_TABLE` words map through `COLOUR_SEVERITY`
   → `css_class_for_severity` → the frozen `.sev-warning` class = **pale yellow
   `#f6ff8f`** (rebound orange→yellow in batch-47). Cross-view severity lists that
   use `sev-*` classes (e.g. Issues) genuinely render warnings pale yellow, so the
   word "Pale yellow" is *correct* there.
2. The *MAC-table* pipeline: the MAC DataTable rows, coverage strip and hex
   overlays are painted with **inline Rich styles** (`green` / `red` / `orange3` /
   `white` / `grey70`), never touching `sev-*` classes. A `NOT_IN_A2L` warning row
   therefore renders **orange** in the table — the MAC-specific cue that Amendment F
   deliberately kept on the `⚠` record glyph, the frozen
   `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"` hex overlay, and the
   `.mac_out_of_range` Sections-list labels.

**The reconciliation (what the legend does, not just says):**
- Keep the colour key verbatim — it names the **severity**, which is the cross-view
  contract (`Pale yellow = .sev-warning`).
- Immediately under the key, show a **sample warning row painted in the actual
  inline orange** (`#d9a35b`) with the caption "← what a warning row looks like",
  so the reader sees the true table colour rather than a swatch that contradicts
  the screen.
- Name the orange family explicitly as the *MAC-specific cue* (⚠ glyph, hex MAC
  overlay, Sections labels) so the reader files orange under "MAC interaction
  cues", not under severity.
- Close with the C-10 rule: **trust the glyph + Status column over hue** — the
  glyph (`✗ ⚠ ✓ ·`) and the Status vocabulary (`ERR_PARSE … OK`) are identical in
  both pipelines, so they are the reliable signal when the colours disagree.

If the fold-in wants a cheaper fix: one caption line under the MAC key —
`in the table, warning rows paint ORANGE (MAC cue: ⚠ glyph, hex overlay) — the severity above is the cross-view word` —
but the rendered orange sample row is strictly better and costs only one extra line.

---

## Fold-in notes (for the production rewrite)

- **Use `Static`, not `Label`, for key rows** — `Label` truncates at viewport width
  and silently eats meaning tails; `Static` wraps. (Verified empirically in this repo,
  textual 8.2.8.)
- Width budget at 120×40: dialog 90% → ~104 inner; card border+padding → **~100
  usable columns**; when content exceeds the viewport a scrollbar steals 2 more.
  Keep card lines ≤ 95–98 chars.
- Vertical budget: ~32 body rows. Copy above is sized to fit each view without
  scrolling; the `ScrollableContainer` still protects the 80-col regime (C-13) where
  wrapping makes everything taller — there the body scrolls, by design.
- Custom palette vars (`$accent-calm` …) do **not** resolve inside an inline `CSS=`
  block — hex literals only (`#91abec` accent, `#0f1525` panel, `#1b233a` rule);
  `sev-*` / `band-*` come from `CSS_PATH` (honest).
- Run shots with `NO_COLOR` unset + `PYTHONUTF8=1`, or the SVGs lose all colour and
  the block/arrow glyphs risk mojibake on cp1252 consoles.
- Views not covered here per the task scope: **Checks** (would mirror the Issues
  card with `✓ pass / ✗ fail / ◐ uncheckable` vocabulary — the inventory has the
  elements if scope expands).
