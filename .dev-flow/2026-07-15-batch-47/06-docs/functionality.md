# Functionality — s19_app visual data-insight layer (Batch A) — batch `2026-07-15-batch-47`

> **Audience:** technical stakeholder — a developer or maintainer of `s19_app` who needs to know what
> shipped, where it lives, and which constraints it must not break.
> **Purpose:** understand (not install/operate). For the requirement text see `REQUIREMENTS.md`
> §37 (R-TUI-065…074); for coverage see `06-docs/traceability-matrix.md`; for the data flow see
> `06-docs/diagrams/`.
> **Artifact language:** English.

---

## 1. What shipped, in one paragraph

Batch A adds a **render-level insight layer** over five TUI screens: an app-wide navy/pastel theme plus
a shared helper module, and per-screen enrichments on Workspace, A2L Explorer, MAC View, and Memory Map.
**It computes nothing new.** Every value it displays was already produced upstream — entropy windows,
coverage metrics, A2L enriched tags, out-of-order records, the S-record entry point. The layer's whole
job is to *surface* data the system already had but never rendered. The only additive data are two
**derived** `LoadedFile` fields (`out_of_order_count`, `entry_point`), computed in the non-frozen
`load_service` from values the frozen parsers already expose.

**Scope kept out (by design):** Issues Report tiers (PARKED) · Patch Editor BIG (Batch B) · raising the
120-column layout caps · Flow Builder · any parser/engine/validation behaviour change · any new
file-system or execution surface.

---

## 2. The design constraints that shaped it

These are not background — they determined the shape of nearly every decision below.

| # | Constraint | What it forced |
|---|---|---|
| C1 | **Render-only.** No parser, engine, or validation-logic change. | Every feature reads a pre-computed field. The memstrip does not compute entropy; it reads `LoadedFile.entropy_windows` (populated on the worker thread at load, batch-45). The map's `N sym` does not scan; it queries the `range_index` membership primitives. |
| C2 | **Engine-frozen set (C-27 dual-guard).** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` + 9 frozen test files must show **0 diff vs `main`**. | Frozen modules are **read-only oracles**. The MAC coverage strip lives in the non-frozen `services/validation_service.py`, not in `validation/`. The `sev-*` restyle is **CSS-only** — `color_policy.py` is untouched. No new test may land in a frozen test file. Verified 0-diff every increment and at HEAD `12c5d1c`. |
| C3 | **C-17 markup-safety.** A2L `description`/`unit`/`conversion`/`display_identifier`/`name` and MAC names are **file-derived and untrusted**. In Textual, a bare `str` handed to a widget is markup-parsed — so `evil[red]` in a fixture would inject styling, and `sensor[unclosed` could raise. | Every new sink composes with `safe_text = Text(value)` + `.append` — **never** `Text.from_markup`, **never** an f-string into a markup string. Four sinks, four gate-blocking hostile-input ATs. |
| C4 | **The severity contract is requirements-level.** `sev-*` class names and Red/Green/White/Grey (+ Orange MAC) semantics are fixed. | The pastel restyle changes hues only, each staying inside its colour family (§6.5 **Amendment C**). Where the new A2L per-cell accents collided with the severity-row contract, the conflict was **surfaced, not blended** (§6.5 **Amendment E**) — the severity contract stays dominant. |
| C5 | **C-29 two-axis geometry.** Every "how much fits" claim must pilot-measure **both** width-cols and height-rows of the **real boxed panel** at 80×24 and 120×30 — never assume an axis, never inherit a prototype's full-screen budget. | Measured, not assumed: `#map_grid` = **66×14 @80×24 / 52×12 @120×30** → the ruler drops the `0x` prefix at the measured 52-col grid (C-13.1 fallback); the A2L card is **h=5** and does not occlude the hex view at 80×24; the map region list is `height: auto`, overflow **reachable-under-scroll**. |
| C6 | **Textual internal-name shadowing.** A widget member named `_nodes` or `_context` causes a silent mount crash / idle boot deadlock with **no traceback**. | Both new widgets (`A2LDetailCard`, `MapRuler`) were checked against `dir(Widget)`. `A2LDetailCard`'s only new member is `show_tag`. |
| C7 | **Binary sizes** (§6.5 **Amendment D**, operator decision). | `human_bytes` uses the 1024 divisor + `KiB/MiB/GiB/TiB/PiB`, not decimal `KB/MB/GB`. Rationale: firmware/memory spans are powers of two, so a decimal read-out misaligns with the hex ranges the analyst is reading — `0x10000` reads `64.0 KiB`, not `65.5 KB`. |
| C8 | **Snapshot drift is massive by design**, and baselines regenerate only in canonical CI. | The app-wide restyle was sequenced **LAST** (Inc-8) so each functional increment kept live snapshot regression-coverage, drifting only its own cells. 29 cells are `xfail(strict=False)`, **0 xpassed** → the census is complete and non-masking. Regen = a post-merge canonical-CI PR. |

---

## 3. Foundation — the theme and `insight_style`

### 3.1 `s19_app/tui/insight_style.py` (NEW, non-frozen)

The shared vocabulary every screen story consumes. Modelled on the existing `entropy_style.py`.

**Palette constants** (`:34-62`) — the dolphie-derived navy/pastel set:

| Role | Constants |
|---|---|
| Text | `LABEL #c5c7d2` · `VALUE #e9e9e9` |
| Semantics | `GREEN #54efae` · `YELLOW #f6ff8f` · `RED #fd8383` · `CYAN #7dd3fc` · `DGRAY #969aad` · `PURPLE #b565f3` |
| Accent | `HILITE #91abec` · `LBLUE #bbc8e8` |
| Depth stack | `DEPTH_BG #0a0e1b` · `DEPTH_PANEL #0f1525` · `DEPTH_ODD_ROW #131a2c` · `DEPTH_BORDER #1b233a` |
| Microbar | `MICROBAR_FILLED █` · `MICROBAR_EMPTY ░` |

**Four pure helpers** — deterministic, unit-tested, no I/O:

| Helper | Signature | Notes |
|---|---|---|
| `human_bytes` | `(n: int) -> str` | Binary 1024 divisor, `KiB…PiB`; byte cutoff `< 1024` (Amendment D) |
| `label_value` | `(label, value, style="") -> Text` | Muted label + bright value — the dolphie idiom |
| `microbar` | `(frac, width, style="") -> Text` | Proportional `█`/`░` bar |
| `threshold_style` | `(pct, warn, bad) -> str` | Threshold colouring |

> **Why the `Text`-returning helpers matter for security.** `label_value` and `microbar` return a Rich
> `Text` object, never a `str`. A `Text` is **C-17-safe by construction** — it carries no markup to
> parse. This is the single most reusable safety property the foundation provides: a caller that
> composes with these helpers cannot accidentally re-open the injection surface.

### 3.2 `styles.tcss` — the app-wide restyle

- **`$`-variables retargeted** to the insight palette (`:26-31`): `$accent-calm #4ec9d4 → #91abec` ·
  `$bg-base #11141a → #0a0e1b` · `$bg-panel #171b23 → #0f1525` · `$fg-base #c8ccd4 → #e9e9e9` ·
  `$rule #2a2f3a → #1b233a`; NEW `$odd-row #131a2c`. Applied app-wide via the `Screen` rule.
- **The dolphie panel idiom** on the broad `.db-pane` class (`:237-247`): `border: round → tall`, an
  accent `border-title-color`, a muted `border-subtitle-color`, over the navy panel surface.
- **Zebra** (`:252-254`): `DataTable > .datatable--odd-row` — inert unless a table enables
  `zebra_stripes`.
- **`sev-*` hues restyled** (`:510-541`) — see §7 below.
- **`chip-button` CSS is deliberately absent.** Its only consumer is the Patch Editor BIG (Batch B); it
  ships with its consumer rather than as orphan CSS here.

---

## 4. Per-screen: what the insight layer does

### 4.1 Workspace (MID) — structure and load health at a glance

| Feature | What it does | Where |
|---|---|---|
| **Loader facts** | `#ws_stats` renders `Loader N err · ⚠K OOO · Entry 0x…` — N = `len(LoadedFile.errors)`, K = `out_of_order_count`, Entry = `entry_point` (`—` when absent). | `app.py::build_loader_facts_text:852` |
| **Entropy memstrip** | `#ws_memstrip` colours each address segment by its **entropy band** (class + texture glyph from `entropy_style.band_style`, glyph set `· ░ ▒ ▓`), and marks unmapped gaps with `╱`. | `app.py::update_memory_strip:8636`; gap glyph `_STRIP_GAP_GLYPH` `:628` |
| **Section micro-cues** | Each section row: in-range glyph + cyan address + right-aligned humanized size + size micro-bar (`size / biggest`) + entropy glyph. | `app.py::update_sections:8453` |
| **Classed hex** | Each hex byte is styled by kind: `00`/`FF` dim-grey · printable-ASCII cyan · everything else bright. | `hexview.py::_hex_byte_style:27` → `render_hex_view_text:360` |
| **Pane border titles** | Titles/subtitles on the three Workspace panes. | `app.py::_compose_screen_workspace` |

**Three things worth knowing:**

1. **The two derived fields.** `out_of_order_count` and `entry_point` are the batch's only additive
   data. They are **defaulted and appended after `entropy_windows`** on the `LoadedFile` dataclass
   (`models.py:72-73`) — `out_of_order_count: int = 0`, `entry_point: Optional[int] = None` — so all ~40
   existing constructors that omit them keep compiling and take safe defaults. **No frozen test file
   constructs `LoadedFile`**, which is why an additive dataclass change kept C-27 at 0-diff.
2. **The merge-carry bug that never reached code (MJ-1).** `LoadedFile` is **rebuilt, not mutated**, when
   a MAC is attached — via two merge sites that field-copy explicitly (`app.py:6954`, `:6997`). A copy
   site that pre-dates a new field silently defaults it. Without a fix, the loader facts would read
   correctly on a direct S19 load and then **silently lie** after a MAC attach (`⚠4 OOO` → `⚠0 OOO`).
   The Phase-2 **writer-census** (C-15.1) enumerated all four construction sites and caught this before
   any code was cut; `LLR-066.7` mandates carry-forward and `AT-066d` is its counterfactual.
   *General class: any additive field on a copy-constructed snapshot needs a writer-census.*
3. **HEX has no entry point, structurally.** `hexfile.py` discards record types 03/05, so every HEX load
   renders `Entry —`. This is correct product behaviour, not a defect — nodalized by `AT-066c`.

**Memstrip fallback:** when `entropy_windows` is empty, the strip falls back to the pre-existing
valid/invalid/gap colouring without raising. The `╱` gap glyph is **app-supplied**, not from
`entropy_style` — it is an *unmapped-address* indicator, not an entropy band.

### 4.2 A2L Explorer (MID) — read a symbol's metadata in place

| Feature | What it does | Where |
|---|---|---|
| **Colored/zebra tag table** | `_build_a2l_table_cells` returns a `tuple[Text, ...]` — **every one of the 16 cells is a Rich `Text`**, never a bare `str`. Zebra via the table's `zebra_stripes`. | `app.py::_build_a2l_table_cells:9542` → `#a2l_tags_list` |
| **In-image glyph** | A leading `✓` (in-image) / `·` (not) derived from each tag's **`in_memory`** flag. | same |
| **Colored summary** | `#a2l_tags_summary` shows a coloured in-image count. | `app.py` |
| **Detail card** | A card at the top of `#a2l_hex_pane` (hex view shrinks below it — no new pane) showing the highlighted tag's description, unit·conversion, record layout, byte order, and limits. | `app.py::A2LDetailCard:734` / `_a2l_detail_card_text:668` / `_card_field` |
| **Live highlight handler** | NEW `on_data_table_row_highlighted` → `A2LDetailCard.show_tag`. | `app.py:6345` |

**Notes.**
- The flag key is **`in_memory`**, not `in_image`. A spec or test naming `in_image` is wrong (`a2l.py:1316`).
- **RowHighlighted, not RowSelected** — deliberate: the card updates on cursor movement (live feedback),
  whereas the pre-existing `on_data_table_row_selected` fires only on explicit selection.
- **The card and the table cell are two distinct C-17 sinks**, each with its own gate-blocking AT
  (`AT-069b` card, `AT-069c` table cell). Neither covers the other.
- **§6.5 Amendment E — the accents you won't see.** LLR-068.1 originally specified per-cell accents
  (name bright / address cyan / source muted). Those accents **are** built in the builder, but the live
  table renders each row in its REQUIREMENTS-level A2L **severity** colour (Red/Green/White/Grey — the
  HLR-037 contract), applied as a whole-cell `.style` override in `update_a2l_tags_view`. Since every
  A2L row resolves to a severity, the accents are visible only in the (unit-tested) builder output.
  Per engineering-rule 7 ("surface conflicts, don't average them") this was recorded as an amendment
  rather than blended: **the severity contract stays dominant**, and the shipped A2L deliverable is the
  glyph column + coloured summary + zebra. Promoting accents onto non-error rows would need its own
  severity-restyle decision — flagged for the operator, out of Batch-A scope.

### 4.3 MAC View (MID) — per-record health plus overall coverage

| Feature | What it does | Where |
|---|---|---|
| **4-way status glyph** | `✓` parse-ok + in-image · `⚠` parse-ok + out-of-image (Orange semantics) · `✗` parse-error · `·` parse-ok but never image-checked (MAC-only load). Cyan addresses, zebra rows. | `app.py::_mac_status_glyph:583` → `_populate_mac_datatable:9192` / `update_mac_view:9043` |
| **Coverage strip** | `#mac_coverage_strip` renders `MAC→S19 X of Y ▓▓▓░░ · A2L↔MAC N matches` from `CoverageMetrics.mac_in_s19` / `mac_total` / `a2l_mac_address_matches`, shown whenever a MAC is loaded — **independent of the primary file type** (superseding the old conditional pct-line). | `services/validation_service.py::build_mac_coverage_strip:28`; gate `app.py::_update_mac_coverage_strip:9150` |

**The fourth glyph branch (Inc-5 F1 — worth reading).** The glyph was first keyed off the **collapsed
Status string**, which cannot distinguish *in-image* from *never-checked*. A MAC-only load
(`primary_file=None`, records parse fine but there is no image to check against) therefore rendered a
**false-green `✓`** — the UI asserting a check that never ran. The fix re-keys the glyph off `row[3]`
`in_mem_text`, the finest available discriminator: strictly parse-ok **and** in-image ⇒ `✓`. `AT-070d`
closes the branch. No amendment was needed — the requirement always said `✓` means in-image; the code
was wrong, not the spec. *Heuristic worth carrying: a display cue must key off the finest available
discriminator, never a lossy/collapsed proxy string.*

**Boundary:** `mac_total == 0` renders `0 of 0` with an empty micro-bar — no divide-by-zero
(`mac_in_s19_pct` returns 0.0).

### 4.4 Memory Map (BIG) — spatial understanding and navigation

| Feature | What it does | Where |
|---|---|---|
| **Bands + hatch gaps** | The proportional strip colours each segment by entropy band; unmapped gaps render as `╱` hatch segments (`.map-band-gap`). | `screens_directionb.py::MemoryMapPanel._build_band_widgets:1505`; `_MAP_GAP_HATCH:205`, applied `:1580` |
| **Address ruler** | A NEW widget beneath the strip: exactly 5 tick labels at 0/25/50/75/100 % of the address span; tick 0 % == span start, tick 100 % == span end. | `screens_directionb.py::MapRuler:1103` |
| **Enriched region rows** | Each row: size micro-bar (`region_size / largest_region`) + an `N sym` count of A2L symbols in the region span + an explicit `↵` open-in-hex affordance. | `screens_directionb.py::_region_symbol_counts:1455` → `_build_region_row:1617` |
| **Region inspector** | Activating a row populates `#map_detail_body` with span, size, dominant band, and a **≤3-row hex peek at the region start**. | `screens_directionb.py::on_region_row_activated` / `_region_hex_peek:1977`; `app.py::dominant_band_label:797` |
| **Humanized sizes** | All map size read-outs via `insight_style.human_bytes` (binary). | — |

**Notes.**
- **`N sym` uses `range_index`, not a linear scan** — `build_sorted_range_index` /
  `address_in_sorted_ranges` / `range_in_sorted_ranges`, the frozen binary-search membership
  primitives, consumed read-only. This is a requirement (LLR-073.1), not an optimization preference:
  many addresses × many ranges is exactly the case `range_index` exists for.
- **The activation path is reused, not rebuilt.** `RegionRow.Activated` and
  `MemoryMapPanel.OpenInHexRequested` are the existing batch-45 messages; the R-TUI-062 single-click →
  hex contract is intact.
- **The inspector is a C-17 sink, unconditionally.** A2L symbol names **do** surface there via
  `symbols_in_window` → `symbol_list_text` → `safe_text` (the batch-43-hardened path). MN-4 therefore
  made a hostile-input assertion **mandatory** rather than conditional — it is `AT-074`'s sub-assertion.
- **Geometry was measured, not inherited.** The real boxed `#map_grid` is **66×14 @80×24 and 52×12
  @120×30** — the wide regime's grid is *narrower*, because the detail pane docks beside it. Assuming
  the wide case is roomier would have been wrong. At the measured 52 columns the ruler drops the `0x`
  prefix (C-13.1 fallback), and the 3-row peek stays reachable-under-scroll.

---

## 5. Data flow — where each value comes from

See `06-docs/diagrams/architecture-dataflow.md` for the diagram. In prose:

```
parsers (FROZEN)  →  range/validation engine (FROZEN)  →  TUI services (non-frozen)  →  view (non-frozen)
```

The insight layer sits entirely in the last box and **reads**:

| Value | Produced by | Consumed by |
|---|---|---|
| `LoadedFile.entropy_windows` | `load_service.build_loaded_*` → `compute_entropy`, **on the worker thread** (batch-45) | memstrip, map bands, section entropy glyphs |
| `CoverageMetrics` (`mac_total` / `mac_in_s19` / `a2l_mac_address_matches`) | frozen `validation/engine.py` | MAC coverage strip |
| `_a2l_enriched_tags` (`list[dict]`, key `in_memory`) | frozen `tui/a2l.py` enrichment | A2L glyph + summary + card; map `N sym`; inspector symbol names |
| `S19File.get_out_of_order_records()` · S7/S8/S9 record address | frozen `core.py` | **derived** into `LoadedFile.out_of_order_count` / `.entry_point` in `load_service` |
| range membership | frozen `range_index.py` | map `N sym` |

**The thread split is a contract.** `LoadedFile` is built on a worker thread by `_parse_loaded_file`,
then handed to `_apply_loaded_file`, which calls each `update_*` renderer **on the main UI thread**.
Renderers must not parse. The insight layer honours this: the two derived fields are computed in
`load_service` (worker side), and every renderer only reads the finished snapshot.

---

## 6. Security posture (C-17)

Four new/extended untrusted-text sinks, four gate-blocking acceptance tests:

| Sink | Mechanism | AT |
|---|---|---|
| A2L detail card | composed at the `Text` level (`_card_field` appends `Text`) | AT-069b ★ |
| A2L table cells (all 16) | `_build_a2l_table_cells` returns `tuple[Text, ...]` | AT-069c ★ |
| MAC record names | `Text().append` | AT-070b ★ |
| Map region inspector | `symbols_in_window` → `symbol_list_text` → `safe_text` | AT-074 ★ (sub-assert) |

Each asserts the full payload set — `[red]…[/red]`, `[link=http://x]u[/link]`, `\x1b[31mX\x1b[0m`
(ANSI), and `sensor[unclosed` — renders **verbatim** in `Text.plain`, with no payload-derived span and
no `MarkupError`. The unbalanced-bracket `sensor[unclosed` is the discriminating counterfactual: it
would raise or mis-span under `Text.from_markup`, which is what makes the tests genuine rather than
vacuous. `#ws_stats` keeps `markup=False` and carries only numeric counts and a hex address — no
file-derived free text (LLR-066.6, C-17 **N/A with a stated reason**, not overlooked).

Security review signed **APPROVE-CLEAN** on Inc-4 and Inc-5 with an explicit sink inventory. **0 HIGH
findings** for the batch.

---

## 7. The severity contract under the restyle (§6.5 Amendment C)

Class **names** and severity **semantics** are unchanged. Only hues moved, each staying inside its
colour family:

| Class | Before → After | Family / semantics (preserved) |
|---|---|---|
| `.sev-ok` | `#5fb98a → #54efae` | GREEN — memory-checked + present |
| `.sev-error` | `#e06c75 → #fd8383` | RED — schema/structural failure |
| `.sev-warning` | `#d9a35b → #f6ff8f` | YELLOW — warning |
| `.sev-info` | `#4ec9d4 → #7dd3fc` | CYAN — info |
| `.sev-neutral` | `#6b7280 → #969aad` | DGRAY — not-yet-checked (Grey) |

**Preserved unchanged:** `.mac_out_of_range` stays `#d9a35b` (paired with the frozen
`MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"`), so the explicit **"Orange = MAC warning"** cue survives
the `sev-warning` restyle. The `band-*` entropy rules are a **separate colour domain** and were not
touched.

**`color_policy.py` is 0-diff.** The restyle is entirely in `styles.tcss`; the `SEVERITY_CLASS_MAP` and
the `css_class_for_severity` round-trip are untouched, and the frozen
`test_color_policy_round_trip.py` stays green. `AT-065b` asserts the live `sev-error` resolves to the
new pastel red **and** that the round-trip still holds for all five severities.

---

## 8. Assumptions · risks · tradeoffs · next steps

### Assumptions (all verified during the batch)
- **A1** `entropy_windows` is populated on the worker thread for every load (batch-45) — renderers only read. ✔
- **A2** `entropy_style.band_style` with glyph set `· ░ ▒ ▓` is the single source of band styling; `╱` (and the handoff-prose `█`) are app-supplied, NOT from `entropy_style`. ✔
- **A3** `CoverageMetrics` exposes `mac_total` / `mac_in_s19` / `a2l_mac_address_matches`. ✔ (frozen — cannot drift this batch)
- **A4** the A2L per-tag in-image key is **`in_memory`**, not `in_image`. ✔
- **A5** Intel-HEX discards type 03/05 → no entry point for HEX; renders `—`. ✔

### Risks (as shipped)
| Risk | Status |
|---|---|
| Snapshot drift (app-wide theme + per-screen cells) | **Accounted, open.** 29 cells `xfail(strict=False)`, 0 xpassed (non-masking). Retired by the canonical-CI regen follow-up PR. Until then the stale baselines encode pre-theme hues by design. |
| C-17 injection on the new sinks | **Closed.** Safe by construction + 4 gate-blocking ATs. |
| Geometry mis-fit in boxed panels | **Closed.** C-29 both-axes measured before any budget was fixed. |
| Widget-name shadowing | **Closed.** `dir(Widget)` checked for both new widgets. |
| Regression in touched symbols | **Closed.** C-26 reverse-census each increment; largest at Inc-6 (32 `MemoryMapPanel`/`RegionRow` tests, all green). |

### Tradeoffs taken
- **Theme sequenced LAST (Inc-8), against the architect's 6-increment cut.** An app-wide palette change
  drifts *every* snapshot cell at once; doing it first would have put the whole density matrix under
  `xfail` from increment 1 and blinded the functional increments to their own regressions. Cost: a
  larger final increment. Proof it worked: **Inc-7 (classed hex) added 0 new drift** — live coverage
  held right up to the restyle. This is control-candidate **CAND-A** (proposed, not yet encoded).
- **Detail card inside `#a2l_hex_pane`, not a new pane.** Keeps the 120-col cap; costs hex rows (the
  card is h=5, measured to not occlude the hex view at 80×24).
- **RowHighlighted over RowSelected.** Live feedback; costs a handler call per cursor move.
- **A2L accents deferred rather than blended** (Amendment E) — see §4.2.

### Next steps / open items
1. **Canonical-CI snapshot-regen follow-up PR** — retires the 29 `_batch47_*_drift_marks` xfails.
   Regen only in `snapshot-regen.yml` @ textual==8.2.8; **local regen is prohibited** (it drifts
   unrelated baselines).
2. **`chip-button` CSS** ships with Batch B (Patch Editor BIG), its only consumer.
3. **A2L per-cell accents (Amendment E)** — operator decides: promote to requirements, or drop.
4. **CAND-A control-encode decision** ("app-wide restyle sequencing LAST" → `docs/engineering-rules.md`)
   — needs an operator AskUserQuestion before/at Batch B kickoff.
5. **Batch B should reuse, not rebuild** the insight layer: `insight_style` helpers, the `safe_text`
   cell pattern, and the colour roles.
