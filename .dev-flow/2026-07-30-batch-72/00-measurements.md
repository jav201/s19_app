# 00-measurements — batch 2026-07-30-batch-72

> Every number below is executed output. Method + transcript per measurement.
>
> **Run context.** Worktree `C:\Users\jjgh8\OneDrive\Documents\Github\s19_app\.claude\worktrees\next-batch-backlog-8a6c43`,
> branch `claude/batch-72-design-defect-634a67` @ `b556e35`, date **2026-07-30**,
> Python 3.14.4, textual **8.2.8**.
> All probes are throwaway scripts in the session scratchpad; **no repo file other than this
> one was created or modified** (integrity proof in §M-4 Cleanup).
> `run_test(size=(120,30))` yields `screen.size == Size(118,28)` and
> `size=(80,24)` yields `Size(78,22)` — every coordinate below is a *measured* region,
> never the requested tuple.

**BLUF — what this run decides**

| # | Question | Answer |
|---|---|---|
| M-1 | Which abutment rule can be a 0-violation gate? | **Only Switch-only (c).** Same-class (b) is **7**, not 1, and stays at **6** post-batch → unusable. |
| M-2 | Is AT-216 (`Pale yellow` on the key pane's first screenful) achievable? | **YES** — key content 14 rows in a 15-row pane, `max_scroll_y == 0`, Pale yellow at content rows `[5,8)`. **1 row of slack only.** |
| M-3 | Should AT-217 say "visible" or "reachable under scroll"? | **"reachable under scroll"** — key content is 10–11 rows into a 4–6 row pane in every non-degenerate regime. |
| M-4 | Is `Select { height: 3 }` legible? | **NO — silently truncates** `CRC-32/ISO-HDLC` → `CRC-32/I` and clips the bottom border on 4 of 6 Selects. Minimum legible height = **6** (= today's `auto`). |
| M-5 | Test-suite base count | **2379** collected, 2026-07-30. |
| M-6 | Does `_render_key` emit a flat `List[Widget]` with no container? | **CONFIRMED** — 6 (mac) / 7 (map) widgets, 0 containers. |

---

## M-1 Abutment census by class

### Method

Pilot at `size=(120,30)`, CRC Designer reached through the **shipped surface** — `pilot.press("0")`
(the `tests/test_crc_designer_view.py` idiom, not a `.focus()` proxy). Over
`#crc_designer_panel` descendants filtered `widget.focusable and widget.region.area > 0`;
*vertically adjacent* is `b.region.y == a.region.y + a.region.height` **and** the x-bands overlap
(`a.x < b.x + b.width and b.x < a.x + a.width`). Probe: `scratchpad/m1_abutment.py`.

Six zero-area `SelectOverlay` phantoms were present and excluded, exactly as briefed.

### Transcript

```
screen.size = Size(width=118, height=28)
panel.region = Region(x=23, y=7, width=96, height=13)
total descendants=130 focusable-with-area=23 focusable-zero-area(excluded)=6
   EXCLUDED zero-area: textual.widgets._select.SelectOverlay id=None region=Region(x=0, y=0, width=0, height=0)
   ... (x6)

=== (a) ALL abutting pairs: 16 ===
  a01. Select#crc_preset_select@(x=39,y=23,w=12,h=6)  ->  OsClipboardInput#crc_field_width@(x=39,y=29,w=25,h=1)
  a02. OsClipboardInput#crc_coverage_ranges@(x=70,y=23,w=25,h=1)  ->  Select#crc_coverage_intra_gap@(x=70,y=24,w=12,h=3)
  a03. Select#crc_custom_vector_mode@(x=101,y=23,w=13,h=3)  ->  OsClipboardInput#crc_custom_vector@(x=101,y=26,w=26,h=1)
  a04. Select#crc_coverage_intra_gap@(x=70,y=24,w=12,h=3)  ->  Select#crc_coverage_join@(x=70,y=27,w=12,h=4)
  a05. Select#crc_coverage_join@(x=70,y=27,w=12,h=4)  ->  OsClipboardInput#crc_coverage_pad_byte@(x=70,y=31,w=25,h=1)
  a06. OsClipboardInput#crc_field_width@(x=39,y=29,w=25,h=1)  ->  OsClipboardInput#crc_field_poly@(x=39,y=30,w=25,h=1)
  a07. OsClipboardInput#crc_field_poly@(x=39,y=30,w=25,h=1)  ->  OsClipboardInput#crc_field_init@(x=39,y=31,w=25,h=1)
  a08. OsClipboardInput#crc_field_init@(x=39,y=31,w=25,h=1)  ->  Switch#crc_field_refin@(x=39,y=32,w=8,h=1)
  a09. OsClipboardInput#crc_coverage_pad_byte@(x=70,y=31,w=25,h=1)  ->  Select#crc_coverage_on_gap_conflict@(x=70,y=32,w=12,h=4)
  a10. Switch#crc_field_refin@(x=39,y=32,w=8,h=1)  ->  Switch#crc_field_refout@(x=39,y=33,w=8,h=1)
  a11. OsClipboardInput#crc_field_name@(x=101,y=32,w=26,h=1)  ->  OsClipboardInput#crc_field_aliases@(x=101,y=33,w=26,h=1)
  a12. Switch#crc_field_refout@(x=39,y=33,w=8,h=1)  ->  OsClipboardInput#crc_field_xorout@(x=39,y=34,w=25,h=1)
  a13. OsClipboardInput#crc_field_xorout@(x=39,y=34,w=25,h=1)  ->  OsClipboardInput#crc_field_check@(x=39,y=35,w=25,h=1)
  a14. OsClipboardInput#crc_load_path@(x=101,y=38,w=26,h=1)  ->  Button#crc_load_btn@(x=98,y=39,w=8,h=1)
  a15. OsClipboardInput#crc_field_output_address@(x=70,y=43,w=25,h=1)  ->  OsClipboardInput#crc_field_store_width@(x=70,y=44,w=25,h=1)
  a16. OsClipboardInput#crc_field_store_width@(x=70,y=44,w=25,h=1)  ->  Select#crc_field_store_endianness@(x=70,y=45,w=12,h=4)

=== (b) SAME-CLASS abutting pairs: 7 ===
  b01. [Select] Select#crc_coverage_intra_gap@(x=70,y=24,w=12,h=3)  ->  Select#crc_coverage_join@(x=70,y=27,w=12,h=4)
  b02. [OsClipboardInput] OsClipboardInput#crc_field_width@(x=39,y=29,w=25,h=1)  ->  OsClipboardInput#crc_field_poly@(x=39,y=30,w=25,h=1)
  b03. [OsClipboardInput] OsClipboardInput#crc_field_poly@(x=39,y=30,w=25,h=1)  ->  OsClipboardInput#crc_field_init@(x=39,y=31,w=25,h=1)
  b04. [Switch] Switch#crc_field_refin@(x=39,y=32,w=8,h=1)  ->  Switch#crc_field_refout@(x=39,y=33,w=8,h=1)
  b05. [OsClipboardInput] OsClipboardInput#crc_field_name@(x=101,y=32,w=26,h=1)  ->  OsClipboardInput#crc_field_aliases@(x=101,y=33,w=26,h=1)
  b06. [OsClipboardInput] OsClipboardInput#crc_field_xorout@(x=39,y=34,w=25,h=1)  ->  OsClipboardInput#crc_field_check@(x=39,y=35,w=25,h=1)
  b07. [OsClipboardInput] OsClipboardInput#crc_field_output_address@(x=70,y=43,w=25,h=1)  ->  OsClipboardInput#crc_field_store_width@(x=70,y=44,w=25,h=1)

=== (c) SWITCH-SWITCH abutting pairs: 1 ===
  c01. Switch#crc_field_refin@(x=39,y=32,w=8,h=1)  ->  Switch#crc_field_refout@(x=39,y=33,w=8,h=1)

=== Switch inventory: screen.query(Switch) -> 2 ===
  Switch id='crc_field_refin' classes=['-on', 'crc-field-switch'] region=Region(x=39, y=32, width=8, height=1) focusable=True
  Switch id='crc_field_refout' classes=['-on', 'crc-field-switch'] region=Region(x=39, y=33, width=8, height=1) focusable=True
app.query(Switch) -> 2
CONFIRM #crc_field_refin:  Switch region=Region(x=39, y=32, width=8, height=1)
CONFIRM #crc_field_refout: Switch region=Region(x=39, y=33, width=8, height=1)
```

Repo grep for `Switch(` construction sites (whole package):

```
$ grep -rn "Switch(" s19_app/ --include=*.py
s19_app/tui/crc_designer_view.py:467:            Switch(value=value, id=field_id, classes="crc-field-switch"),
$ grep -rn "Switch(" s19_app/ --include=*.py | wc -l
1
```

### Result

The briefed figures are **confirmed**: 16 abutting pairs; `#crc_field_refin` at `y=32 h=1`,
`#crc_field_refout` at `y=33 h=1`.

**The qa proposal that rule (b) yields 1 violation is FALSE. It yields 7.**
Post-batch, putting refin/refout on one row removes exactly `b04`; the other **six** same-class
pairs (`b01` Select→Select, and five Input→Input) are untouched and are all *legitimate* form
layout. So rule (b) can never reach 0 without a redesign nobody has asked for.

| Rule | Violating pairs PRE-batch | Expected POST-batch | Usable as a gate? |
|---|---|---|---|
| (a) any two abutting focusables | **16** | **15** (loses `a10`; `a08`/`a12` re-target to the shared row) | ❌ No — cannot reach 0; the form is legitimately dense |
| (b) abutting pair of the **same widget class** | **7** | **6** (`b01`, `b02`, `b03`, `b05`, `b06`, `b07` survive) | ❌ **No — not satisfiable.** A gate that is RED before and RED after proves nothing |
| (c) abutting pair where **both are `Switch`** | **1** (`c01` = refin/refout) | **0** | ✅ **Yes** |

- **(i) FALSE pre-batch:** all three rules are FALSE on the shipped tree (≥1 violation each), so
  all three go RED before the fix. Redness alone does not discriminate between them.
- **(ii) satisfiable post-batch (0 violations):** **only rule (c).**
- **Rule (b) is explicitly NOT usable** — its post-batch count is 6, not 0.

**Subject-set completeness for rule (c):** the entire application contains **2** `Switch`
widgets, both on the CRC Designer screen, both produced by the **single** construction site
`s19_app/tui/crc_designer_view.py:467`. The Switch-only subject set is therefore
**complete by construction** — there is no other `Switch` anywhere that a future change could
add without touching that one call. This is what makes (c) a narrow-but-honest gate rather than
a rule tailored to one pair: state the completeness argument in the requirement, or the gate
reads as special-pleading.

---

## M-2 Legend two-pane budget at 120x30 (mac AND map)

### Method

Two runs.

1. **Shipped baseline** (`scratchpad/m2_legend.py`): pilot at `(120,30)`, rail key `3` (mac) /
   `4` (map), then `k` to open `LegendScreen` through the real binding. Measured
   `#legend_dialog` / `#legend_body` `region`, `container_size`, `virtual_size`, and every body
   child's `outer_size.height`.
2. **Prospective layout** (`scratchpad/m2m3_twopane.py`): the card and key widgets are the
   **real** `LegendScreen._render_card()` / `_render_key()` output (per-view `sections` taken
   from `app.py:5682 _SCREEN_LEGEND_SECTIONS` — `mac → ("MAC",)`, `map → ()`), re-hosted in a
   `Horizontal` of two `ScrollableContainer` panes. The proposed CSS
   (`#legend_dialog {width: 96%}`, card `3fr`, key `2fr`) is injected via an `App` subclass in
   the throwaway script; the real `styles.tcss` is loaded unmodified as `CSS_PATH`.

> **Label — PROSPECTIVE-LAYOUT MEASUREMENT, not approximation.** The pane widths and the key's
> rendered row count are produced by Textual's real layout engine on the real widgets, so they
> are measured, not estimated. What is *assumed* is the CSS the implementation will actually
> write: `height: 1fr` on both panes and `overflow: hidden` on `#legend_body`. Different pane
> CSS shifts these numbers, so the requirement should pin the CSS it measured.

### Transcript — shipped baseline

```
### requested size=(120, 30) view='mac' -> app.screen(Legend).size=Size(width=118, height=28)
  legend_dialog   region=Region(x=19, y=2, width=82, height=25) container_size=Size(width=76, height=21)
  modal-title     region=Region(x=22, y=4, width=23, height=1)
  legend_body     region=Region(x=22, y=6, width=76, height=15) container_size=Size(width=76, height=15)
  legend_buttons  region=Region(x=22, y=21, width=76, height=4) container_size=Size(width=76, height=3)
  legend_body virtual_size=Size(width=74, height=39) scroll_offset=Offset(x=0, y=0) max_scroll_y=24
  dialog styles: width=70w height=90h padding=Spacing(top=1, right=2, bottom=1, left=2) border=round
  chrome_w = dialog.region.width - dialog.container_size.width = 6
  chrome_h = dialog.region.height - dialog.container_size.height = 4
  ...
  [17] Label   h=1 region=Region(x=22, y=36, width=3,  height=1) classes=['legend-artifact'] text='MAC'
  [18] Static  h=2 region=Region(x=22, y=37, width=74, height=2) classes=['legend-row','sev-error']   text='Red — ...'
  [19] Static  h=2 region=Region(x=22, y=39, width=74, height=2) classes=['legend-row','sev-warning'] text='Pale yellow — ...'
  [20] Static  h=1 region=Region(x=22, y=41, width=74, height=1) classes=['legend-row','sev-ok']      text='Green — ...'
  [21] Static  h=2 region=Region(x=22, y=42, width=74, height=2) classes=['legend-row']               text='White — ...'
  [22] Static  h=1 region=Region(x=22, y=44, width=74, height=1) classes=['legend-row','sev-neutral'] text='Grey — ...'
  SUM of child outer heights = 33  (body viewport h=15)
  'Pale yellow' widget index 19, region.y=39, body.region.y=6, content-row-offset=33

### requested size=(120, 30) view='map' -> screen.size=Size(width=118, height=28)
  legend_body   region=Region(x=22, y=6, width=76, height=15)
  legend_body virtual_size=Size(width=74, height=44) max_scroll_y=29
  SUM of child outer heights = 38  (body viewport h=15)
```

Body `h=15` at 120x30 — **confirmed**. Today the single-column body needs 39 (mac) / 44 (map)
rows of virtual height for a 15-row viewport, and `Pale yellow` sits at content row **33** —
i.e. today it is 18 rows below the fold. That is the defect AT-216 exists to close.

### Chrome derivation (cited, not guessed)

`s19_app/tui/styles.tcss`:

| Line(s) | Declaration | Cost |
|---|---|---|
| 1503–1511 | `.modal-dialog, #load_dialog { border: round …; padding: 1 2; width: 70%; height: auto; }` | border 1+1 cols / 1+1 rows; padding 2+2 cols / 1+1 rows |
| 1539–1541 | `#legend_dialog { height: 90%; }` | dialog height |
| 1543–1546 | `#legend_body { height: 1fr; overflow-y: auto; }` | body fills remainder |

⇒ `chrome_w = 2 (border) + 4 (padding) = 6` and `chrome_h = 2 + 2 = 4`.
Both **verified against the measurement**: `82 − 76 = 6`, `25 − 21 = 4`.

### Transcript — prospective two-pane layout

```
### M-2 Horizontal 3fr/2fr @96% | requested=(120, 30) view='mac' -> screen.size=Size(width=118, height=28)
  legend_dialog region=Region(x=3, y=2, width=113, height=25) container_size=Size(width=107, height=21)
  legend_body   region=Region(x=6, y=6, width=107, height=15) container_size=Size(width=107, height=15)
  card_pane     region=Region(x=6, y=6, width=64, height=15) virtual=Size(width=62, height=33) max_scroll_y=18
  key_pane      region=Region(x=70,y=6, width=43, height=15) virtual=Size(width=43, height=15) max_scroll_y=0
  --- key pane children (rendered at width 43) ---
    key[00] Label   h=1 region.y=7  margin_gap_before=1 text='MAC'
    key[01] Static  h=3 region.y=8  text='Red — parse failed, invalid/missing name or he'
    key[02] Static  h=3 region.y=11 text='Pale yellow — warning: symbol only in MAC (not'
    key[03] Static  h=1 region.y=14 text='Green — exact name + address match with A2L'
    key[04] Static  h=3 region.y=15 text='White — structurally valid MAC entry, no hard '
    key[05] Static  h=2 region.y=18 text='Grey — no A2L loaded, or validation context mi'
  key content total rows = 14 ; key viewport h = 15 ; key.virtual_size.height = 15
  >>> 'Pale yellow' key index 2: content rows [5, 8) ; region=Region(x=70, y=11, width=43, height=3) ;
      fully visible at scroll_offset 0 = True ; first row visible = True

### M-2 Horizontal 3fr/2fr @96% | requested=(120, 30) view='map' -> screen.size=Size(width=118, height=28)
  card_pane     region=Region(x=6, y=6, width=64, height=15) virtual=Size(width=62, height=36) max_scroll_y=21
  key_pane      region=Region(x=70,y=6, width=43, height=15) virtual=Size(width=43, height=15) max_scroll_y=0
  --- key pane children (rendered at width 43) ---
    key[00] Label   h=1 region.y=7  margin_gap_before=1 text='Entropy bands'
    key[01] Static  h=1 region.y=8  text='·  constant/padding  [0,1) — padding / fill'
    key[02] Static  h=1 region.y=9  text='░  low  [1,5) — structured / tables'
    key[03] Static  h=1 region.y=10 text='▒  medium  [5,7.2) — calibration / data'
    key[04] Static  h=2 region.y=11 text='▓  high/random  [7.2,8] — code / compressed / '
    key[05] Static  h=2 region.y=13 text='╱ gap hatch — unmapped gap between runs (NOT a'
    key[06] Static  h=5 region.y=15 text='bands = bits/byte entropy over a 256 B window;'
  key content total rows = 14 ; key viewport h = 15 ; key.virtual_size.height = 15
```

### Result

| Quantity | Measured |
|---|---|
| screen at `(120,30)` | `Size(118, 28)` |
| dialog @ `width: 96%` | `113` cols (`floor(118 × 0.96) = 113`) × 25 rows |
| modal chrome | **6** cols, **4** rows (derived from `styles.tcss:1504–1508`, verified) |
| dialog content width | `113 − 6 = ` **107** |
| card pane `3fr` | **64** cols |
| key pane `2fr` | **43** cols |
| body height | **15** rows (unchanged from today) |
| key content rows @43 cols — **mac** | **14** (1 `.legend-artifact` margin + 1+3+3+1+3+2) |
| key content rows @43 cols — **map** | **14** (1 margin + 1+1+1+1+2+2+5) |
| key pane `max_scroll_y` | **0** for both views — no scrollbar, full 43 cols stay content |
| `Pale yellow` row index within the key pane's own content | key-widget index **2**; content rows **`[5, 8)`** |

**Deliverable — does the key pane's first screenful contain `Pale yellow` at `scroll_offset 0`?**

# YES

Measured directly: `fully visible at scroll_offset 0 = True`, and the pane does not scroll at all
(`max_scroll_y == 0`). **AT-216 is physically achievable.**

⚠️ **One-row margin — state it in the requirement.** Both views land on **14 of 15** rows. A single
extra key row, one more wrapped line from a reworded meaning, or a key pane narrower than 43 cols
pushes the map key past the fold. The map key's last widget alone is **5 rows** at this width
(`BAND_DOMAIN_NOTE`). Recommendation: the requirement should pin `2fr` (not "about 40%") and the
AT should assert `key_pane.max_scroll_y == 0` **in addition to** the Pale-yellow visibility, so the
test fails on the *cause* (budget exhausted) rather than only on the symptom.

---

## M-3 Legend floor budget at 80x24

### Method

Same two probes at `size=(80,24)`. `scratchpad/m3_collapse.py` additionally sweeps four candidate
pane-height regimes for the stacked (key-above-card) `Vertical` layout and reports whether either
pane reaches height 0.

### Transcript — shipped floor + carried-number check

```
### requested size=(80, 24) view='mac' -> app.screen(Legend).size=Size(width=78, height=22)
  legend_dialog region=Region(x=13, y=2, width=54, height=19) container_size=Size(width=48, height=15)
  legend_body   region=Region(x=16, y=6, width=48, height=9) container_size=Size(width=48, height=9)
  legend_body virtual_size=Size(width=46, height=49) max_scroll_y=40
  chrome_w = 6 ; chrome_h = 4
    [17] Label   h=1 region=Region(x=16, y=43, width=3,  height=1) text='MAC'          <- 1 row margin-top before this
    [18] Static  h=3 region=Region(x=16, y=44, width=46, height=3) text='Red — ...'
    [19] Static  h=3 region=Region(x=16, y=47, width=46, height=3) text='Pale yellow — ...'
    [20] Static  h=1 region=Region(x=16, y=50, width=46, height=1) text='Green — ...'
    [21] Static  h=2 region=Region(x=16, y=51, width=46, height=2) text='White — ...'
    [22] Static  h=2 region=Region(x=16, y=53, width=46, height=2) text='Grey — ...'
  SUM of child outer heights = 43  (body viewport h=9)
```

### Transcript — stacked-layout regime sweep (80x24, body = 9 rows)

```
key:auto / card:1fr          view=mac  body_h=9 key_h=10 card_h=1 key.y=6 card.y=16 key_before_card=True key_scrolls=False(max=0) card_scrolls=True(max=29) body_overflows=True  ZERO_HEIGHT_PANE=False
key:auto / card:1fr          view=map  body_h=9 key_h=11 card_h=1 key.y=6 card.y=17 key_before_card=True key_scrolls=False(max=0) card_scrolls=True(max=34) body_overflows=True  ZERO_HEIGHT_PANE=False
key:1fr  / card:1fr          view=mac  body_h=9 key_h=4  card_h=5 key.y=6 card.y=10 key_before_card=True key_scrolls=True(max=6)  card_scrolls=True(max=25) body_overflows=False ZERO_HEIGHT_PANE=False
key:1fr  / card:1fr          view=map  body_h=9 key_h=4  card_h=5 key.y=6 card.y=10 key_before_card=True key_scrolls=True(max=7)  card_scrolls=True(max=30) body_overflows=False ZERO_HEIGHT_PANE=False
key:2fr  / card:1fr          view=mac  body_h=9 key_h=6  card_h=3 key.y=6 card.y=12 key_before_card=True key_scrolls=True(max=4)  card_scrolls=True(max=27) body_overflows=False ZERO_HEIGHT_PANE=False
key:2fr  / card:1fr          view=map  body_h=9 key_h=6  card_h=3 key.y=6 card.y=12 key_before_card=True key_scrolls=True(max=5)  card_scrolls=True(max=32) body_overflows=False ZERO_HEIGHT_PANE=False
key:auto max-h 6 / card:1fr  view=mac  body_h=9 key_h=6  card_h=3 key.y=6 card.y=12 key_before_card=True key_scrolls=True(max=4)  card_scrolls=True(max=27) body_overflows=False ZERO_HEIGHT_PANE=False
key:auto max-h 6 / card:1fr  view=map  body_h=9 key_h=6  card_h=3 key.y=6 card.y=12 key_before_card=True key_scrolls=True(max=5)  card_scrolls=True(max=32) body_overflows=False ZERO_HEIGHT_PANE=False
```

Pale-yellow position in the stacked `1fr/1fr` regime:

```
  >>> 'Pale yellow' key index 2: content rows [4, 6) ; region=Region(x=6, y=10, width=66, height=2) ;
      fully visible at scroll_offset 0 = False ; first row visible = False
```

### Result

**The 9-row content budget is CONFIRMED.** `#legend_body.container_size.height == 9` at 80x24,
in every regime measured.

**The carried "MAC key alone occupies 11" is NOT confirmed — it is not reproduced at any measured
width.** Measured MAC key heights:

| Layout / key render width | MAC key rows | MAP key rows |
|---|---|---|
| **shipped** single column, 70% dialog → 46 cols | **13** (12 widget rows + 1 `.legend-artifact` margin) | 12 |
| proposed stacked, 96% dialog → 66–68 cols | **10** | **11** |
| proposed side-by-side, 96% dialog → 43 cols (120x30 only) | 14 | 14 |

The closest match to "11" is the **map** key at the 96% stacked width, not the MAC key. The
requirement must re-state this number against the width it actually renders at — a key row count
is meaningless without its render width, because every row wraps.

**Pane heights actually achievable in 9 rows** (key above card):

| Regime | key h | card h | key content rows | Verdict |
|---|---|---|---|---|
| key `1fr` / card `1fr` | 4 | 5 | 10 (mac) / 11 (map) | key scrolls (`max_scroll_y` 6/7); `Pale yellow` at content `[4,6)` is **below the fold** |
| key `2fr` / card `1fr` | 6 | 3 | 10 / 11 | key still scrolls (4/5); `Pale yellow` `[4,6)` fits exactly — **fragile** |
| key `auto` / card `1fr` | 10 / 11 | **1** | 10 / 11 | key fits, but the card is starved to 1 row **and `#legend_body` itself overflows** — degenerate |
| key `auto; max-height: 6` | 6 | 3 | 10 / 11 | identical to `2fr` |

**Does a pane collapse to height 0?** **No** — `ZERO_HEIGHT_PANE=False` in all eight runs; the
minimum observed is `card_h=1` under `key: auto`. So an AT comparing `key.region.y < card.region.y`
is **not** the zero-height trap it could have been — `key.region.y == 6 < card.region.y` holds in
every regime. **But that also makes it a weak assertion**: it is TRUE in all four regimes,
including the degenerate one that destroys the card. Ordering alone cannot fail.

**Deliverable — exact wording AT-217 should use:**

> **AT-217.** At 80x24 the Legend stacks key-above-card: `#legend_key_pane.region.y <
> #legend_card_pane.region.y` (key precedes card in document order), both panes render at
> non-zero height with `#legend_card_pane.region.height >= 2`, and the full key is **reachable
> under scroll** — `#legend_key_pane.max_scroll_y >= 1` together with the last key row scrolling
> into a non-empty on-screen region via `scroll_visible()`.

Justification, from the numbers:

- **"both panes visible" is the wrong claim** and would be near-vacuous. The key *content* is
  10–11 rows and the pane is at most 6 — the key is **never** fully visible at 80x24 under any
  non-degenerate CSS. An AT asserting "visible" either fails permanently or gets weakened to mean
  "the pane widget has area", which is true even when the card is crushed to 1 row.
- **"reachable under scroll" is the honest and testable claim** — measured `max_scroll_y` is 4–7,
  so scrolling is the real access mechanism and the AT should assert it works.
- The `card.region.height >= 2` clause is the **non-vacuity tooth**: it is the only assertion in
  the set that fails under `key: auto`, the one regime that satisfies "key precedes card" while
  making the card useless. Without it AT-217 passes on a broken layout.

---

## M-4 CRC `Select { height: 3 }` legibility

### Method

The shared worktree was **not touched**. `s19_app/` was copied to
`scratchpad/privtree/s19_app`, and `#crc_designer_panel Select` in the **copy's**
`styles.tcss:1958` was rewritten for each height under test; the pilot ran with
`PYTHONPATH=scratchpad/privtree` (probe banner prints the tree in use, to prove which
`styles.tcss` was loaded). Widgets are scrolled into view with `scroll_visible(animate=False)`
before capture — at 120x30 the CRC form is scrolled and most fields sit outside the panel
viewport, so an uncscrolled capture reads the footer, not the widget. Visible text is read from
`app.screen._compositor.render_strips()` (note: `App.export_text()` does **not** exist on
textual 8.2.8). Probes: `scratchpad/m4_select.py`, `scratchpad/m4_sweep.py`.

### Transcript — `crc_preset_select` across heights

```
TREE IN USE: ...\scratchpad\privtree\s19_app\tui

=== M-4 height: auto ===   (the SHIPPED state)
  crc_preset_select            h=6 w=12 value='CRC-32/ISO-HDLC'
      |▊▔▔▔▔▔▔▔▔▔▔▎|
      |▊  CRC- ▼  ▎|
      |▊  32/I    ▎|
      |▊  SO-H    ▎|
      |▊  DLC     ▎|
      |▊▁▁▁▁▁▁▁▁▁▁▎|
      reconstructed_visible_text='CRC-32/ISO-HDLC'  complete=True  top_border=True bottom_border=True

=== M-4 height: 3 ===
  crc_preset_select            h=3 w=12 value='CRC-32/ISO-HDLC'
      |▊▔▔▔▔▔▔▔▔▔▔▎|
      |▊  CRC- ▼  ▎|
      |▊  32/I    ▎|
      reconstructed_visible_text='CRC-32/I'  complete=False  top_border=True bottom_border=False

=== M-4 height: 4 ===
  crc_preset_select            h=4 w=12 value='CRC-32/ISO-HDLC'
      |▊  CRC- ▼  ▎|  |▊  32/I    ▎|  |▊  SO-H    ▎|
      reconstructed_visible_text='CRC-32/ISO-H'  complete=False  top_border=True bottom_border=False

=== M-4 height: 5 ===
  crc_preset_select            h=5 w=12 value='CRC-32/ISO-HDLC'
      reconstructed_visible_text='CRC-32/ISO-HDLC'  complete=True  top_border=True bottom_border=False

=== M-4 height: 6 ===
  crc_preset_select            h=6 w=12 value='CRC-32/ISO-HDLC'
      reconstructed_visible_text='CRC-32/ISO-HDLC'  complete=True  top_border=True bottom_border=True
```

### Transcript — all six Selects, `auto` vs `height: 3`

```
=== M-4 height: auto ===                          === M-4 height: 3 ===
crc_preset_select            h=6 complete=True     crc_preset_select            h=3 complete=False  'CRC-32/I'
crc_custom_vector_mode       h=3 complete=True     crc_custom_vector_mode       h=3 complete=True   bottom_border=True
crc_coverage_intra_gap       h=3 complete=True     crc_coverage_intra_gap       h=3 complete=True   bottom_border=True
crc_coverage_join            h=4 complete=True     crc_coverage_join            h=3 complete=True   bottom_border=False
crc_coverage_on_gap_conflict h=4 complete=True     crc_coverage_on_gap_conflict h=3 complete=True   bottom_border=False
crc_field_store_endianness   h=4 complete=True     crc_field_store_endianness   h=3 complete=True   bottom_border=False
```

(Full per-row strips for all six at all five heights are in the run output; the `concat` / `abort` /
`little` values each need 2 content rows at width 12, e.g. `|▊  conc ▼  ▎| |▊  at      ▎|`.)

### Result

| Select id | `auto` (shipped) h | Value | h=3 visible text | h=3 complete? | h=3 box intact? |
|---|---|---|---|---|---|
| `crc_preset_select` | **6** | `CRC-32/ISO-HDLC` (15 ch) | **`CRC-32/I`** | ❌ **truncated, 8 of 15** | ❌ bottom border clipped |
| `crc_custom_vector_mode` | 3 | `ascii` | `ascii` | ✅ | ✅ |
| `crc_coverage_intra_gap` | 3 | `skip` | `skip` | ✅ | ✅ |
| `crc_coverage_join` | 4 | `concat` | `concat` | ✅ | ❌ bottom border clipped |
| `crc_coverage_on_gap_conflict` | 4 | `abort` | `abort` | ✅ | ❌ bottom border clipped |
| `crc_field_store_endianness` | 4 | `little` | `little` | ✅ | ❌ bottom border clipped |

**Deliverable — at `height: 3`, is the preset value legible?**

**TRUNCATED — silently.** `CRC-32/ISO-HDLC` renders as `CRC-32/I`: 8 of 15 characters, with
**no ellipsis and no overflow marker**. The operator sees a value that looks complete and is not.
Four of the six Selects additionally lose their bottom border, so the widget visibly overflows its
own box.

**Minimum legible height** (at the measured 12-col pane width):

- **5** — the full value text first appears, but the box is still broken (no bottom border).
- **6** — full value **and** an intact box. This is exactly what `height: auto` already produces.

So a blanket `#crc_designer_panel Select { height: 3 }` is **rejected by measurement**: it buys
3 rows on one control at the cost of silently lying about that control's value, and breaks the
chrome of three others. If the row budget must come down, the lever is the pane **width**
(15 chars need ~19 cols to fit on one line inside this Select's padding + arrow), not the height.
The architect's inability to verify this was well founded — the failure is invisible to any
assertion that reads `select.value` rather than the composited strip.

### Cleanup / integrity proof

```
$ sha256sum <shared>/s19_app/tui/styles.tcss          # BEFORE any probe
14558a41d5a3c53e5d4316e826375d4abbbe54e37a552e909b03730a3a8b8532
$ sha256sum <scratchpad>/privtree/s19_app/tui/styles.tcss   # the private copy, pre-edit
14558a41d5a3c53e5d4316e826375d4abbbe54e37a552e909b03730a3a8b8532

... edits applied to the COPY only (auto/3/4/5/6) ...

$ rm -rf <scratchpad>/privtree
$ sha256sum <shared>/s19_app/tui/styles.tcss          # AFTER
14558a41d5a3c53e5d4316e826375d4abbbe54e37a552e909b03730a3a8b8532   <-- IDENTICAL

$ git rev-parse --abbrev-ref HEAD; git rev-parse --short HEAD
claude/batch-72-design-defect-634a67
b556e35
$ git status --porcelain
(empty)
$ git diff --stat HEAD -- s19_app/tui/styles.tcss
(no output — unchanged)
```

The shared worktree's `styles.tcss` is byte-identical before and after, and the worktree
tree is clean. `git worktree add` was deliberately **not** used, since it would have written into
the shared repo's `.git/worktrees/`.

---

## M-5 Test-suite base count

### Method / Transcript

```
$ date
Thu Jul 30 14:36:01 CSTM 2026

$ python -m pytest --collect-only -q 2>&1 | tail -3
tests/test_workspace_variants.py::test_build_variant_set_honors_explicit_active_id
tests/test_workspace_variants.py::test_build_variant_set_rejects_unknown_active_id
tests/test_workspace_variants.py::test_build_variant_set_empty_project_has_no_active_variant

2379 tests collected in 0.78s
```

### Result

**2379 tests collected**, measured **2026-07-30** on `claude/batch-72-design-defect-634a67`
@ `b556e35`. The artifact figure of **2358 is stale** — use 2379 as the batch-72 base, and note
that the base moves whenever the branch does, so any requirement quoting a total must quote the
commit alongside it.

---

## M-6 `_render_key` / `_render_card` widget inventory

### Method

Pure call, no pilot needed — `LegendScreen(sections=…, view_key=…)._render_card()` /
`._render_key()`, with `sections` taken from `app.py:5682 _SCREEN_LEGEND_SECTIONS`
(`mac → ("MAC",)`, `map → ()`). Probe: `scratchpad/m6_inventory.py`.

### Transcript

```
=== view_key='mac' sections=('MAC',) ===
_render_card -> list len=17
   card[00] Static id=None classes=['legend-card-sub']     'Coverage strip'
   card[01] Static id=None classes=['legend-card-line']    'MAC→S19 1 of 2 █████░░░░░ · A2L↔MAC 3 matches'
   card[02] Static id=None classes=['legend-card-caption'] ...
   card[03] Static id=None classes=['legend-card-sub']     'One table row — the 8 columns'
   card[04] Static id=None classes=['legend-card-line']    ...
   card[05] Static id=None classes=['legend-card-caption'] ...
   card[06] Static id=None classes=['legend-card-sub']     'Tag status glyphs (glyph is the primary cue)'
   card[07] Static id=None classes=['legend-card-line']    ...
   card[08] Static id=None classes=['legend-card-caption'] ...
   card[09] Static id=None classes=['legend-card-sub']     'Status vocabulary → row colour'
   card[10] Static id=None classes=['legend-card-caption'] ...
   card[11] Static id=None classes=['legend-card-caption'] ...
   card[12] Static id=None classes=['legend-card-sub']     'Orange vs Pale yellow — two paint pipelines, one severity'
   card[13] Static id=None classes=['legend-card-caption'] ...
   card[14] Static id='legend_mac_warning_sample' classes=['legend-card-line'] ...
   card[15] Static id=None classes=['legend-card-caption'] ...
   card[16] Static id=None classes=['legend-card-caption'] ...
_render_key  -> list len=6
   key[00] Label  id=None classes=['legend-artifact']              'MAC'
   key[01] Static id=None classes=['legend-row','sev-error']       'Red — ...'
   key[02] Static id=None classes=['legend-row','sev-warning']     'Pale yellow — warning: symbol only in MAC ...'
   key[03] Static id=None classes=['legend-row','sev-ok']          'Green — ...'
   key[04] Static id=None classes=['legend-row']                   'White — ...'
   key[05] Static id=None classes=['legend-row','sev-neutral']     'Grey — ...'
  -> flat List[Widget], containers among key widgets: 0
  -> all are Widget instances: True
  -> total body widgets (card+key) = 23
  -> 'Pale yellow' at key index 2

=== view_key='map' sections=() ===
_render_card -> list len=20   (all Static; classes legend-card-sub / -line / -caption)
_render_key  -> list len=7
   key[00] Label  id=None classes=['legend-artifact']            'Entropy bands'
   key[01] Static id=None classes=['band-constant','legend-row'] '·  constant/padding  [0,1) — padding / fill'
   key[02] Static id=None classes=['band-low','legend-row']      '░  low  [1,5) — structured / tables'
   key[03] Static id=None classes=['band-medium','legend-row']   '▒  medium  [5,7.2) — calibration / data'
   key[04] Static id=None classes=['band-high','legend-row']     '▓  high/random  [7.2,8] — code / compressed / random'
   key[05] Static id=None classes=['legend-row']                 '╱ gap hatch — unmapped gap between runs (NOT a band, no colour class)'
   key[06] Static id=None classes=['legend-card-caption']        'bands = bits/byte entropy over a 256 B window; ...'
  -> flat List[Widget], containers among key widgets: 0
  -> all are Widget instances: True
  -> total body widgets (card+key) = 27
```

### Result

| View | `_render_card` | `_render_key` | Containers in key | Flat `List[Widget]`? |
|---|---|---|---|---|
| `mac` | **17** (all `Static`; one carries `id='legend_mac_warning_sample'`) | **6** (1 `Label` + 5 `Static`) | **0** | ✅ |
| `map` | **20** (all `Static`) | **7** (1 `Label` + 6 `Static`) | **0** | ✅ |

**The requirement's claim is CONFIRMED**: `_render_key` returns a flat `List[Widget]` with no
container wrapper — the return annotation is `List[Widget]` and every element is a leaf
`Label`/`Static`. Splitting the body into two panes therefore needs **no change to
`_render_key`/`_render_card` at all**; only `compose()` (`screens.py:1194–1206`) changes, from

```python
body = self._render_card() + self._render_key()
... ScrollableContainer(*body, id="legend_body")
```

to two sibling `ScrollableContainer`s inside a `Horizontal`/`Vertical`. Two consequences worth
writing into the requirement:

- `map`'s key emits **7** widgets, one more than `mac`'s 6 — but its *rendered* cost is the one
  that matters and the two are equal at 43 cols (14 rows each, M-2). Do not size the pane from
  the widget count.
- `key[06]` on the map is a `.legend-card-caption`, not a `.legend-row` — a domain note, not a
  band. Any AT that counts "key rows" by querying `.legend-row` will miss it and under-count the
  map key by the **5 rows** it occupies at 43 cols.

---

## M-7 CRC kernel values named by AT-213 / AT-215 *(added at the Phase-2 re-gate)*

Revision 2 labelled these "Measured" while they lived only in the qa lane review — a citation of
another document is not evidence (C-43). Re-executed here, and independently reproduced by both
re-gate reviewers:

| Quantity | Value | Used by |
|---|---|---|
| `SEED_ALGORITHM` | CRC-32/ISO-HDLC, `refin=True`, `refout=True`, `check=0xcbf43926` | AT-213, AT-215 |
| `#crc_custom_vector` seed | `"123456789"` (**not** empty — so the observable genuinely moves) | AT-213 |
| default computed vector | **`0xCBF43926`** (the externally published CRC-32 check value) | AT-213 |
| after driving `refin` → `False` (the non-default, C-10) | **`0x1898913F`** | AT-213 |
| after driving `refout` → `False` | `0x649C2FD3` | *(not used — recorded to show `refin` was chosen deliberately)* |
| `#crc_field_check` → `0x00000000` | verdict `✓ MATCH` → **`✗ MISMATCH`** | AT-215 |
| `#crc_field_check` cleared | `○ NO-EXPECTED` (`check=None`) — **excluded near-miss** | AT-215 |
| `#crc_field_check` non-hex | `"Invalid parameters: …"` — **excluded near-miss** | AT-215 |

## M-8 Hero extent on `main` *(added at the Phase-2 re-gate — refutes a rationale, not a requirement)*

```
#crc_coverage_window   area = 305
#crc_live_verify       30 x 4 = 120
#crc_warnings_group    30 x 4 = 120
ratio 305:120 = 2.54 : 1   (the G-3 "6:1 law" is ALREADY FALSE on main)
```

Retiring `#crc_live_verify` and giving its space to `#crc_warnings_group` changes the bounded
quantity by **zero**. See §6.4 G-3 — the pre-existing 2.54:1 violation is carried to the backlog.

## Summary table — what the requirements must be amended to say

| Measurement | Value | Requirement it constrains |
|---|---|---|
| M-1 abutting focusable pairs, 120x30 | **16** | G-1 scope — confirms the briefed census |
| M-1 same-class abutting pairs | **7** pre → **6** post | **G-1 re-scope: reject rule (b).** The "1 violation" premise is FALSE; a gate that is RED before *and after* is not a gate |
| M-1 Switch-Switch abutting pairs | **1** pre → **0** post | **G-1 re-scope: adopt rule (c).** The only rule that is FALSE pre-batch and satisfiable post-batch |
| M-1 `Switch` widgets in the whole app / construction sites | **2** / **1** (`crc_designer_view.py:467`) | G-1 — the subject set is complete by construction; state this so (c) does not read as special-pleading |
| M-2 dialog @ `width: 96%`, 120x30 | **113** cols; content **107** after **6** cols chrome (`styles.tcss:1504–1508`) | Legend two-pane geometry — replaces the prototype-inherited number |
| M-2 pane widths under `3fr`/`2fr` | card **64**, key **43** | Pin `2fr` explicitly; "about 40%" is not measurable |
| M-2 key content rows @43 cols | **14** (mac) and **14** (map) in a **15**-row pane, `max_scroll_y == 0` | **AT-216 is achievable.** Add `key_pane.max_scroll_y == 0` as the cause-level assertion — only **1 row** of slack |
| M-2 `Pale yellow` position in key pane | widget index **2**, content rows **`[5, 8)`**, fully visible at `scroll_offset 0` | AT-216 oracle |
| M-3 body content budget @80x24 | **9** rows (confirmed) | Legend floor |
| M-3 MAC key rows | **13** @46 cols (shipped) · **10** @66–68 cols (stacked) · **14** @43 cols | **The carried "11" is not reproduced** — restate the row count *with its render width* |
| M-3 stacked pane heights in 9 rows | `1fr/1fr` → 4/5 · `2fr/1fr` → 6/3 · `auto` → 10–11/**1** + body overflow | AT-217 — `auto` is degenerate, exclude it |
| M-3 zero-height pane | **never** (min = card `h=1`) | AT-217 — the ordering assertion is safe but **weak**; it passes in all four regimes |
| M-3 AT-217 wording | **"key pane precedes card pane in document order and is reachable under scroll"**, plus `card.region.height >= 2` | AT-217 — "both panes visible" is unachievable (key content 10–11 rows vs ≤6 available) and would be weakened into vacuity |
| M-4 `Select { height: 3 }` preset value | **`CRC-32/I`** — 8 of 15 chars, **no ellipsis**; bottom border clipped on 4 of 6 Selects | **Reject the `height: 3` fold.** Its own new threshold fails on measurement (C-39 rider) |
| M-4 minimum legible height @12 cols | **5** (text complete, box broken) · **6** (text + box, == today's `auto`) | Any Select-height requirement; the real lever is **width**, not height |
| M-5 test base count | **2379** @ `b556e35`, 2026-07-30 | Replaces the stale **2358**; quote the commit with the count |
| M-6 `_render_key` return | flat `List[Widget]`, **0** containers; mac 6 / map 7 widgets (card 17 / 20) | Confirms the two-pane split touches only `screens.py::compose` (`1194–1206`) |
| M-6 map key row-counting hazard | `key[06]` is `.legend-card-caption`, not `.legend-row` (**5** rows @43 cols) | Any AT counting key rows via `.legend-row` under-counts the map key |

### Unmeasured / out of scope

- No measurement was taken of the **CRC screen at 80x24** — outside the brief; if a requirement
  claims a CRC floor behaviour it is still un-measured.
- The M-2/M-3 pane geometry assumes the implementation writes `height: 1fr` on the panes and
  `overflow: hidden` on `#legend_body`. Different pane CSS moves these numbers; the requirement
  should pin the CSS these numbers were measured under.
