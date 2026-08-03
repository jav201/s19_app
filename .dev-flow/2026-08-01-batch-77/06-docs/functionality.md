# Functionality — s19_app — Batch `2026-08-01-batch-77`

> **Artifact language:** English (`state.json.language`).
> Phase-6 artifact. Owner: `docs-writer`. **Audience:** a technical stakeholder who did not follow the batch.
> Merged as PR [#186](https://github.com/jav201/s19_app/pull/186), squash **`244ecf2`**. Every symbol and line number below was re-derived on disk at that commit.

## 🔑 At a glance (read first)

- **What this batch added:** the Memory Map's band bar now **distinguishes** regions instead of merely showing them — every mapped run gets a column count proportional to its size, inside a container the bar is actually measured against; the address ruler names only mapped addresses; and a region is focused and inspected on load with **zero operator gestures**.
- **Capabilities:** proportional, bounded band bar (bar **21 → 50** columns @120×30) · ruler labels that name **mapped** addresses · a stats readout with a discriminating percentage and humanized sizes · legend moved out of the map body · **keyboard region navigation** (↑ ↓ + Enter) · auto-selected first region with a safety-scrubbed inspector.
- **How to use it:** open the Memory Map screen with a file loaded. No new command, no new flag, no new footer chip. Arrow keys move between region rows; `Enter` inspects; `k` still opens the legend screen.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## The observable change

| | Before | After |
|---|---|---|
| `.map-band-bar` @120×30 | 21 cols | **50** |
| `prg.s19` runs rendered invisible | **5 of 14** | **0** — fits exactly at both regimes, with **zero** aggregation |
| ruler labels naming no mapped address | **4 of 5** | **0** |
| coverage readout | `0.00%` · `67108408 bytes` | **`0.0008%`** · **`64.0 MiB`** |
| inspector after load | needs a click | **populated, zero gestures** |
| keyboard region access | none | **↑ ↓ + Enter** |
| legend | 4 always-on rows resident in the map body | **absent from the body**; the `k` legend screen is unchanged |
| selected region row | indistinguishable (0 markers) | **exactly 1 marker**, applied by address |

Sources for each figure: bar 21 → 50 is premise **P-46**'s settled CSS sweep; 5-of-14 is **P-48** executed against an unbounded allocator at bar = 50; 4-of-5 ruler labels is `HLR-112`'s pre-change threshold; the coverage strings are `HLR-113`'s executed thresholds.

---

## Detail (reference)

### How it works (flow)

**1 — The bar is measured, not assumed.**
Segment widths used to be scaled against a hard-coded constant, `_BAND_BAR_WIDTH = 60`, while the actual container measured **66 or 21** columns depending on terminal size. The constant is now **deleted outright** (open question OQ-3 resolved; **0 live code references** at `244ecf2`). Widths derive from `.map-band-bar`'s **rendered** width, read at settled layout.

**2 — The container was widened first, then the allocation was bounded. Both halves are load-bearing.**
`.map-band-row` now lays the bar and the "At a glance" panel **vertically at every terminal size** (`s19_app/tui/styles.tcss:789`). 80×24 already stacked via `width-narrow`, so this is a *removal* of a special case, not a new one — and it takes the bar at 120×30 from **21 to 50** columns. Every alternative candidate measured (glance 20, glance 16, bar 3fr) widened the bar **less** and starved the histogram row, whose widest content line is 29 columns.
Widening alone is not enough: executed, an unbounded allocator at bar = 50 still leaves **5 of 14** runs on `prg.s19` invisible and emits **60 columns into a 50-column bar**, because a `max(1, …)` floor pads nine tiny runs while one run claims 26.

**3 — The allocator, plainly.**
> One column is reserved per emitted run and one per unmapped gap. The **surplus** is then apportioned by **largest remainder** over each run's share of the **total mapped bytes**. The sum is bounded **in the producer**.

Bounding in the producer — not in a test — is the design decision that matters, and it is batch-74's asset restated on a third surface:

> **An output-shaped predicate can *detect* an overflow but cannot *prevent* one.**

`AT-B77-03` (nothing paints outside the bar) is output-shaped. It is a genuine gate and it caught a real regression, but it can only observe the overflow after it has been emitted. The bound lives in `_allocate_band_widths` (`screens_directionb.py:504`), so `prg.s19` fits **exactly** at both regimes — 14 run segments summing to 56 columns plus 10 gap markers = 66 @80×24, and 40 + 10 = 50 @120×30 — all runs visible, monotone, and strict.

**4 — Gaps fold to exactly one column.**
Not two. Measured: at 21 columns `fold=2` yields `[3,3,3,3,1]`, collapsing three differently-sized runs to **equal** width and gutting the discrimination the batch exists to deliver. The 2-column marker and its humanized size label were **descoped** by ruling R-5 into carry `C-77-g`, with an explicit reopening condition: an operator report that gap magnitude is not readable from the stats line's largest-gap figure.

**5 — The ruler labels what the bar draws.**
The fixed 5-tick percentile derivation (`_TICK_COUNT = 5`) is retired. The ruler now emits **one label per emitted run start, plus one for the last mapped byte** (`span_end − 1`; `span_end` is exclusive — ruling R-4). Out of domain it **elides interior labels legibly** rather than rendering them at zero width, always retaining the first and last.

**6 — A region is selected and inspected on load, and the inspector is safe.**
The panel resolves the selection **by address** (never by index — a re-merge changes how many runs precede the selected one), preserving the previous selection when a region with that start address is still present and falling back to the new first region otherwise. Resolution runs on a **post-refresh hook**, because `grid.mount()` and `remove_children()` are both deferred: *"after the rows are mounted"* is not a synchronous point inside `render_ranges`. Focus is placed on a row that is **attached and among the panel's current rows** — identity alone reads `True` on a fully detached widget.
Auto-selection **never** posts `OpenInHexRequested`, and every file-derived string reaching `#map_detail_body` is scrubbed of C0/C1 control bytes.

### The domain, and what happens outside it — stated honestly

`HLR-111` holds **while `n_runs + n_gaps ≤ bar.region.width`**. Derived over the whole shipped corpus (`examples/**/*.s19`, **16** fixtures), that is **15 of 16** at both regimes.

**Out of domain, the bar is unreadable on `case_08_heavy_fragmentation`, and batch-77 does not fix that.** With 801 ranges (801 runs + 800 gaps = 1601 against a bar of 66 or 50), **768 of 801 runs** leave no distinguishable column. What the batch does claim, and what `AT-B77-18` gates, is exactly two things:

- the panel **renders without raising**, and
- **all 801 regions remain reachable in the region list.**

The batch **measurably improves** `case_08` over the pre-change producer. It does not make it readable. **batch-78 owns the rest**, chartered as carry `C-77-l` with 11 measurements already paid for and `case_08_heavy_fragmentation` named as its acceptance fixture from the start.

⚠️ **`HLR-112`'s domain is materially smaller — 13 of 16.** Three fixtures are excluded, and the most important one is the batch's own showcase: **`prg.s19` is out of `HLR-112`'s domain at both regimes** (15 ticks against a ceiling of 7 @80×24 / 5 @120×30). Every emitted label names a mapped address — the invariant holds universally — but the operator sees at most 7 of 15 run starts. That is weaker than US-77-2 implies, and it is on the page rather than behind it. `case_07_stress_smoke` is excluded at 120×30 only.

> The ceiling is derived, not chosen: ruler width **66 / 50**, tick labels **8 characters**, **one blank separator column required** (two adjacent 8-hex labels with no gap render as an unreadable 16-digit run) → pitch **9** → ceiling `⌊(width + 1) ÷ 9⌋` = **7 / 5**. ⚠️ **The separator convention is normative, not cosmetic:** at pitch 8 the ceiling would be 8/6 and `case_07_stress_smoke` would read as *in domain* at the wide regime. It is not. *A membership answer that changes with an unstated convention is not a membership answer.*

### One limit that cannot be engineered away

`HLR-111` promises *strict* discrimination — at least one strictly greater pair whenever two runs differ in mapped size — **only** when `surplus × (max_bytes − min_bytes) > total_bytes`.

That second condition is not a convenience. On the containment domain alone the clause is **unsatisfiable by any allocator**: two runs of different but *similar* mapped size legitimately round to the same integer column count, because a size difference smaller than one column's worth of bytes cannot be represented in integer columns. Executed in-domain counterexample: `runs=[1,2,4,…,512]`, `n_gaps=9`, `bar=19` → `widths=[1]*10`, `differing=True`, `strict=False`.

The threshold is **strict** (`>`, never `≥`): `≥` admits **285** non-strict cases at ratio exactly `1.000000000`, a measure-zero boundary that a 140 808-case random sweep never hit and only exhaustive enumeration finds. Verified over **859 276** consolidated in-domain cases with **0** counterexamples.

**`_allocate_band_widths` was not modified to chase this.** The requirement was the defect, not the code.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/screens_directionb.py:504` `_allocate_band_widths` | The bounded allocator: floor 1 per run and per gap, surplus by largest remainder over mapped bytes. **Unchanged by Amendment D.** |
| `screens_directionb.py:2532` `_build_band_widgets` | Builds the segment widgets; no longer constructs a `.map-band-legend` container. |
| `screens_directionb.py:1513` `BandBar` · `:1580` `BandBar.Measured` · `:1583` `on_resize` | 🆕 The merge-gate product fix. `BandBar` re-emits its own non-bubbling `Resize` as a **bubbling** `Measured`. |
| `screens_directionb.py:2436` `on_band_bar_measured` · `:2448` `_resize_band_segments` | Re-apportions at the real container width once the bar reports it. |
| `screens_directionb.py:1588` `MapRuler` · `:1691` `MapRuler.on_resize` | Ticks from run starts + last mapped byte; legible elision against the measured width. |
| `screens_directionb.py:2230` `render_ranges` · `:3064` `_live_region_rows` | Selection resolution on a post-refresh hook; **liveness** of the focused row. |
| `screens_directionb.py:1301` `RegionRow` · `:1347` `Activated` · `:3018` `on_region_row_activated` | Focusable rows; `Enter` posts the same message a click posts, through the single click-policy site. |
| `screens_directionb.py:878` `safe_text` | 🆕 Strips the C0/C1 control **byte class** via `str.translate`. Its docstring corrected in the same edit. |
| `screens_directionb.py:2853` `build_stats_text` · `insight_style.py:124` `human_bytes` | Dual mapped/span readout; coverage at exactly four fractional digits; humanized largest gap. |
| `s19_app/tui/styles.tcss:789/798/811` | Always-stack band row; bar at `width: 100%` of `#map_grid`; glance beneath it. |
| `styles.tcss:857-864` `.map-region-row.map-region-selected` | Selection styling — a background only. Sets **no** foreground colour and **no** inverting text style. |
| `s19_app/tui/legend.py` | Prose describing the retired 5-tick ruler, corrected. |
| `s19_app/tui/app.py:1352/1356/1359` | **Unmodified by design.** `j` / `k` / `o` stay application-level; `RegionRow.BINDINGS` stays `[]`. |

### Usage / examples

No new entry point. The behaviour is reached the same way it always was:

```
# Launch the TUI and open the Memory Map screen with a file loaded.
python -m s19_app
```

Then, on the Memory Map screen:

| Gesture | Result | Changed by this batch? |
|---|---|---|
| *(file load)* | first region auto-selected, inspector populated, focus on a live region row | 🆕 **yes** — was: needed a click |
| `↑` / `↓` | move focus to the previous / next region row in ascending address order. **No wraparound** at either edge. | 🆕 **yes** — was: arrows inert |
| `Enter` | inspect the focused region | 🆕 **yes** |
| single click on a region | inspect | no — batch-67 N4a split preserved |
| double click on a region | open in hex | no — and this is the **only** route to hex, since `o` was descoped (`C-77-f`) |
| `k` | legend screen | no — verified unmodified, **0 diff lines** |
| `j` / `o` | dump A2L JSON / open workarea | no — `RegionRow.BINDINGS` is `[]` so nothing is shadowed |

⚠️ **No new footer chip was added, deliberately.** The 14 existing chips already need ≈**181** columns of footer in the **78** available — already ~2.3× oversubscribed and truncating. A 15th chip would not merely *risk* truncation; it would **guarantee** displacing an existing one, and would drift **all 29** snapshot cells instead of 2. Discoverability is served by the existing `?` help panel.

⚠️ **`RegionRow.BINDINGS` stays `[]` — a decision, not an omission.** A widget-scoped binding shadows the App binding of the same key for as long as the row holds focus, and after this batch a row holds focus **by default on every render**. Only up/down/enter are consumed; everything else bubbles untouched.

### Verification

| Command | Result |
|---|---|
| `pytest --collect-only -q` | **2612 tests collected** (`2519 → 2612`; `−1 +94`) |
| `pytest tests/test_tui_map_big.py tests/test_tui_hostile_map.py tests/test_map_click_chain.py -q` | **100 passed in 155.45 s**, exit 0 |
| `pytest tests/test_tui_directionb.py tests/test_tui_snapshot.py tests/test_legend_two_pane.py -q` | **224 passed in 336.34 s**, exit 0; **29 snapshots passed** |
| Full suite at the merge gate (`2f427a9`, FULL form) | **2607 passed / 2 skipped / 3 xfailed**, exit 0 |

*(The first three were re-derived at write time on `claude/batch-77-closeout`; the full-suite figure stands on the `2f427a9` gate run's own output and was **not** re-run.)*

### Diagrams

- [`06-docs/diagrams/render-and-settle.md`](diagrams/render-and-settle.md) §1 — **render-and-settle sequence.** Where the batch's only product defect lived: the non-bubbling `Resize` edge, the incidental corrector that hid it, and the `BandBar.Measured` fix.
- [`06-docs/diagrams/render-and-settle.md`](diagrams/render-and-settle.md) §2 — **allocation flow.** Containment domain, floor, largest remainder, producer-side bound, and the strictness precondition.

---

## Known limitations

| Limitation | Status |
|---|---|
| **`case_08_heavy_fragmentation` (801 ranges): 768 of 801 runs leave no distinguishable column.** | Out of `HLR-111`'s domain. **Improved, not fixed.** batch-78 owns it (`C-77-l`). No raise; region list complete. |
| **`prg.s19`: the operator sees at most 7 of 15 run starts on the ruler.** | Out of `HLR-112`'s domain at both regimes. Every emitted label still names a mapped address. |
| **`o` = open-hex is not bound on the keyboard.** | Descoped (R-3) — `o` is bound app-wide and frozen under live `TC-011`. Hex reachable by double-click. Carry `C-77-f`; reversible. |
| **Gap markers carry no size label.** | Descoped (R-5) — `fold=2` guts the strict limb. Carry `C-77-g`; reopening condition stated. |
| **The "At a glance" box still clips its widest content row by 1 column @80×24.** | Pre-existing, **not introduced here**. `LLR-111.9` fixes it at 120×30 only. Carry `C-77-j`. |
| **The stats line sits below the fold and this batch deepens that scroll.** | Accepted (R-8). Already below the fold at both regimes; newly hides nothing. ⚠️ **The widen must not be narrowed to protect it** — every column surrendered lowers the ceiling on visible regions. Carry `C-77-k`. |
| **`AT-B77-19` guards first render only.** | Re-render, terminal resize, screen switch and resize-while-inactive were verified correct but are unguarded. All ride the same mechanism. Carry F-3. |
| **A future CSS change to `.map-band-bar`'s width reddens `AT-B77-02` by design.** | Not drift — the golden is keyed by settled bar width, and that coupling is the only thing that surfaces a silent width change. ⚠️ **`width: auto` would close the spin loop** and must not be applied. |

---

## Evidence checklist — `docs-writer`

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | **Audience and purpose declared at the top** | ✓ | Front-matter block: *"Audience: a technical stakeholder who did not follow the batch"*; the At-a-glance block states what shipped and how to reach it. |
| 2 | **Structure follows the relevant template** | ✓ | `~/.claude/templates/dev-flow/functionality-template.md` — At a glance / How it works / Components / Usage / Diagrams / Evidence checklist, all present and filled. **Justified deviations:** two sections added — *The observable change* (the brief's before/after table) and *Known limitations* (out-of-domain behaviour is a first-class fact for this batch, not a footnote). |
| 3 | **Code/CLI snippets actually run** | ✓ | The four `pytest` invocations in §Verification are transcribed from executed runs — three re-derived at write time on `claude/batch-77-closeout` (`04-validation.md` §Write-time confirmation), one from the `2f427a9` gate run's own output. ⚠️ **`python -m s19_app` is marked as the documented entry point and was NOT executed by this artifact** — it is the pre-existing launch path, unchanged by this batch. |
| 4 | **Assumptions listed** | ✓ | The containment domain is stated with its derived membership (15 of 16 / 13 of 16); the tick ceiling is derived, not chosen, with the separator convention flagged as **normative**; the strictness precondition is stated with its executed counterexample. |
| 5 | **Risks / limitations called out** | ✓ | §Known limitations — 8 rows, each with its ruling or carry id. `case_08` is stated as **not fixed**, in those words. |
| 6 | **Next steps stated** | ✓ | batch-78 owns aggregation via `C-77-l`; five product carries and one process carry named with their `BACKLOG-CODE.md` lines in `traceability-matrix.md` §6. |
| 7 | **Diagrams included where flow is non-trivial** | ✓ | `06-docs/diagrams/render-and-settle.md` — two Mermaid diagrams. **This closes the gap the Phase-5 architect checklist flagged ✗** (`05-postmortem.md:251`). |
| 8 | **No invented APIs / version numbers / metrics** | ✓ | Every symbol and line number re-derived by `grep -n` on the working tree at `244ecf2` — `_allocate_band_widths:504`, `BandBar:1513`, `Measured:1580`, `MapRuler:1588`, `safe_text:878`, `build_stats_text:2853`, `_SELECTED_ROW_CLASS:2145`, `app.py:1359`, `styles.tcss:798`. ⚠️ **The specification's own symbol lines are stale and were NOT copied** — e.g. it cites `_build_band_widgets:1988` and `safe_text:688`; on disk they are `:2532` and `:878`. Discrepancies reported in `traceability-matrix.md`, not reconciled to. |
