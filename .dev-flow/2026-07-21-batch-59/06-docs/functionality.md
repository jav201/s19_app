# CRC Algorithm Designer — Functional Description (post batch-59)

> Audience: technical stakeholder (firmware engineer / reviewer). Purpose: understand what the CRC Designer bench does after the batch-59 view rebuild.
> Scope note: batch-59 changed **only the layout/presentation**. The engine, compute, and Load/Save behavior are batch-58 and were carried across verbatim (0 engine change, 0 frozen-file diff).

---

## What it is

The CRC Algorithm Designer is a rail screen in the S19 TUI (key `0`, `#screen_crc_designer`), used to design a CRC algorithm and preview the checksum it would produce over a firmware image's real bytes. It is **preview-only** — it never mutates the loaded firmware (US-V8, preserved).

Batch-58 shipped its function correctly but rendered it as a **single flat vertical form**. Batch-59 gives it the approved **Variant B "coverage-first bench"** layout: the coverage the operator is checking is now the visual centerpiece, not a buried label.

---

## The layout (three regions)

```
┌─ #screen_crc_designer ─────────────────────────────────────────────┐
│  preset selector + help  (full width)                              │
├─ #crc_hero_row (Horizontal) ───────────────────────────────────────┤
│  ┌ #crc_coverage_window (2fr) ──────┐  ┌ #crc_top_right (1fr) ────┐ │
│  │  LIVE block-glyph coverage       │  │  verdict hero (centered) │ │
│  │  window: ██░░██ + policy CRCs    │  │  ─────────────────────── │ │
│  │  + store word                    │  │  Warnings tile           │ │
│  └──────────────────────────────────┘  └──────────────────────────┘ │
├─ #crc_bench (Horizontal) ──────────────────────────────────────────┤
│  ┌ c1 ─────────┐  ┌ c2 ──────────────┐  ┌ c3 ───────────────────┐  │
│  │ Algorithm   │  │ Coverage controls │  │ Job JSON (roomy)      │  │
│  │ Serialization│ │ Custom vector     │  │ Template              │  │
│  └─────────────┘  └───────────────────┘  │ Load / Save           │  │
│                                          └───────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

1. **Hero row (`#crc_hero_row`)** — the two most-scanned signals, side by side:
   - **Live coverage window (`#crc_coverage_window`, 2fr)** — the signature element (see below).
   - **Right column (`#crc_top_right`, 1fr)** — the **verdict hero** (`#crc_live_verify`, center-aligned `crc-hero` box holding the known-answer-test `#crc_kat_verdict`, MATCH / MISMATCH) stacked above the **Warnings** tile.

2. **3-column bench (`#crc_bench`)** below the hero row — the parameters, scannable side by side instead of one long scroll:
   - **c1** — Algorithm + Serialization fields.
   - **c2** — Coverage controls + Custom vector.
   - **c3** — Job JSON preview (roomy) + Template + Load/Save.

Under the existing `#workspace_body.width-narrow` regime (≤120 cols), **both the hero row and the bench reflow to a vertical stack** so nothing crushes at the 80×24 floor.

---

## The live coverage window (the signature)

The window **renders** coverage; it does not label it. It draws the current target's multi-range memory window in block glyphs, colored by coverage state, and appends the live-computed policy CRCs and the store word — all reflecting the operator's actual ranges and the loaded image.

| Glyph / element | Meaning | Cue |
|-----------------|---------|-----|
| `█` present bytes | bytes actually in a covered range | accent hue (`$accent-calm`) |
| `░` erased gap | inter-range gap under `join="concat"` | muted grey |
| `█` pad-filled gap | inter-range gap under `join="fill"` | warning hue (`.sev-warning` `#f6ff8f`) |
| concat policy CRC | checksum with gaps concatenated out | live-computed hex |
| fill policy CRC | checksum with gaps pad-filled | live-computed hex |
| store word | the bytes that would be written back | live-computed |

**It is live, not a mock.** The window reuses the view's existing coverage primitives (`_parse_ranges`, `_build_coverage_target`, `compute_target_crc`) with **no new engine math**. For the batch-58 two-range fill fixture it renders the exact pinned oracles `0x9C5BCBBD` (concat) and `0x2A8A3950` (fill); editing the ranges re-renders and re-pins to the recomputed oracles. A hardcoded-hex mock would fail this gate (AT-B59-01/02).

**It honors `on_gap_conflict="abort"`.** When a fill gap is dirty and the policy is abort, the window **refuses the store word** — matching exactly what the sibling coverage preview does. The primary readout never shows a store word the preview would reject (F2 contract, locked by a dedicated test).

**Boundary behavior:**
- No image loaded → the shipped empty-state note (`"Load an image to preview coverage CRCs over real bytes."`), no glyph compute, no crash.
- Malformed / inverted range (e.g. `0x8010-0x8000`, `zzz`) → a markup-safe "Invalid coverage" note; `mem_map` object unchanged (preview-only preserved).

---

## Root cause this batch fixed

The "flat form" was **not a missing feature** — the `crc-*` CSS classes referenced by the panel were **entirely undefined** in `styles.tcss`, so Textual fell back to default vertical stacking. Batch-59 defined the CSS the classes were always meant to have, re-nested the widgets into the hero row + 3 columns, and added the one new live-render method. Because every one of the 29 `#crc_*` widget ids and its handler wiring were carried verbatim (`query_one` resolves a descendant anywhere in the subtree), **every batch-58 behavior kept working** — proven both by a reused handler firing through the re-nested tree (AT-B59-06) and by the full batch-58 suite passing unchanged (AT-B59-07).

---

## Security note (the one new sink)

The coverage window is the single new file/operator-derived render sink. It renders `markup=False`. Its safety rests on `markup=False`, not on the source being int-only: on the invalid-range branch the operator's raw range token reaches the sink verbatim. A hostile markup range (`[link=evil]0x8000-0x8008[/]`) renders **literally** in `.plain` with no injected style span (AT-B59-09).

---

## Key surfaces (for maintainers)

| Element | Where |
|---------|-------|
| Panel + bench composition | `s19_app/tui/crc_designer_view.py::CrcDesignerPanel.compose` (:240) |
| Live window render method | `crc_designer_view.py::_render_coverage_window` (:933) |
| Recompute wiring (refreshes the window) | `crc_designer_view.py::_recompute` (:1030) |
| Layout CSS (`crc-*`, hero row, bench, reflow) | `s19_app/tui/styles.tcss` |
| Acceptance tests | `tests/test_crc_designer_view.py` |

**Assumptions:** loaded image exposed via `self.app.current_file.mem_map`; the `#workspace_body.width-narrow` cascade toggles at the 120-col breakpoint (verified). **Limitations:** the window truncates very wide ranges to a fixed glyph cap measured against the boxed 2fr width at 80×24. **Preview-only** throughout — no firmware mutation.
