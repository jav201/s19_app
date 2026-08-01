# HANDOFF — Memory Map redesign, Variant A (gap-fold band bar)

**Date:** 2026-08-01 · **From:** design session (tui-design + prototype captures) ·
**To:** a fresh agent running the full `/dev-flow` V-model in `C:\Users\jjgh8\Github\s19_app`.
**Operator decision (2026-08-01):** build **Variant A + the cross-cutting fixes** as one
dev-flow batch. Variants B/C were evaluated and NOT chosen (B parked, C absorbed partially).

This file is the batch charter INPUT. It is not a spec — Phase 1 owns the requirement,
the LLR set and the acceptances. Everything here is re-derivable; **re-derive it, don't
copy it** (a carried number is re-derived, not copied).

---

## 1 · What was decided, and why

The Memory Map screen's hero — the entropy band bar — scales segment widths over the full
**address span** (`round(60 · run_bytes / total_span)`, `screens_directionb.py:2066`).
S-record images are sparse by nature, so the shipped demo (5 regions, 1,030 B mapped,
span ~128 MiB) renders ≈59 columns of `╱` gap hatch with all five regions in a 1-column
sliver. Full findings F-1..F-6 with evidence anchors, the three variants considered, the
decision table, and real Textual 8.2.8 captures of each variant:

- `prototypes/memmap_redesign.proposals.html` — the proposal document (self-contained,
  captures embedded).
- `prototypes/memmap_variant_a.prototype.py` — the throwaway capture prototype
  (scratch quality; NOT implementation code, do not port it as-is).
- `prototypes/memmap_variant_a.variant_{A,B,C}.120w.svg` — headless captures
  (Textual 8.2.8 `export_screenshot`, 120 cols, real `band-*` palette + glyphs).

Repo state at handoff: `origin/main` @ `f8747b8`, local main synced. All handoff files
are **untracked** — commit them in this batch's PR (the `legend_n8.*` precedent).

## 2 · Scope (operator-approved)

| # | Item | Core of it |
|---|------|-----------|
| S-1 | Gap-fold band bar | Segment widths ∝ **mapped bytes**; each gap folds to a fixed 1–2-col `╱` marker (2-col + humanized size label at/above a fold threshold). A dense no-gap image must render **byte-identical to today** — the no-op case is the control. |
| S-2 | Edge-labeled ruler | Replace the 5 linear ticks with labels at region starts + span end (collapse overlaps; fold labels carry gap size). **This amends LLR-072.3 — requirement amendment with explicit Before/After** (operator rule). |
| S-3 | Stats one-liner | Dual readout ("Mapped 1.0 KiB / 128.0 MiB span (…%)"), `human_bytes` on largest gap. Fixes the "Coverage: 0.00%" + raw-bytes readouts. |
| S-4 | Legend demotion | The 4-row always-on legend block leaves the map body; footer hint ("░▒▓ legend: k"); app-wide `k` LegendScreen already exists. |
| S-5 | Keyboard path | Region rows focusable (`can_focus`), ↑↓/j/k moves, Enter=inspect, `o`=open hex (preserving the N4a single-inspect/double-navigate split for mouse). Surface in Footer + `?` keymap. |
| S-6 | Auto-select | First region auto-selected after `render_ranges` — inspector never empty with a file loaded. |
| S-7 | Selection renders | Selected row gets a highlight class (style-only motion). |

Optional (Phase 1 decides in/out, don't silently absorb): log-scale microbar denominator +
column-aligned region rows (the two ideas ported from Variant C).

**Out of scope:** Variant B (two-lane map) — if the operator wants it later it is its own
batch; register as a backlog candidate, do not build. The CC-1 encoding decision owed to
the operator is unrelated — do not absorb it here.

## 3 · Invariants that must survive (verified against origin/main @ f8747b8)

- **B3:** no file-derived text in bar/rows; counts, addresses and constant band labels only.
- **Color discipline:** colour only via `band-*` classes (`entropy_style.py` +
  `styles.tcss:665-679`); glyph textures `· ░ ▒ ▓` are the colour-blind cue (C-10).
- **LLR-041.7:** the panel is presentational — no entropy/coverage/parse re-derivation.
- **Remount discipline:** re-mounted children carry CLASSES, never ids (DuplicateIds).
- **Fold markers must NOT be `RegionRow`s** — `tests/test_tui_map_big.py` counts
  `query(RegionRow)`; the batch-67 `BandSegment` sibling-not-subclass precedent is the
  pattern (`screens_directionb.py:1185-1190`). Keep gap markers inert `Static`s.
- **N4a click split** (single=inspect, double=hex) and the `width-narrow` reflow regimes.
- **Textual internal-name shadowing:** no `_nodes`/`_context` members on new widgets.

## 4 · Expected footprint

`s19_app/tui/screens_directionb.py` (MemoryMapPanel, `_build_band_widgets`, `MapRuler`,
`_render_stats`/`build_stats_text`), `s19_app/tui/styles.tcss`, tests
(`test_tui_directionb.py`, re-check `test_tui_map_big.py` assumptions), AT/TC registry
(`AT-TC-REGISTRY.jsonl` — G1–G7 guard applies to new ATs/TCs). Snapshot goldens will
drift: **regenerate only in canonical CI** (textual 8.2.8 pin; local regen corrupts
unrelated baselines). Note `tui-ci` runs `-m "not slow"` on PRs — run the FULL suite
before merge and state which form produced any ledger figure.

## 5 · Draft acceptances (WHATs only — Phase 1 must re-derive and own these)

1. Sparse 5-region fixture: every region ≥1 visible bar column (today: 1-col sliver total).
2. Dense contiguous fixture: band bar byte-identical to pre-change render (the control —
   make the counterfactual fail on its ASSERTION, and record the substituted VALUE).
3. No ruler label names an unmapped address (today 3 of 5 do).
4. Stats line: dual mapped/span readout + humanized largest gap.
5. File loaded ⇒ inspector populated with zero clicks.
6. Keyboard-only path exists: focus row → Enter inspects → `o` posts `OpenInHexRequested`.
7. Legend block absent from map body; `k` LegendScreen unaffected.

## 6 · Process requirements for the executing session (operator-set, non-negotiable)

- **Ask the approval model at kickoff** — standing auth is per-batch, never carried.
- **Phase 0:** verify flow currency (`~/.claude/docs/FLOW-VERSION.md`, RC-1 hook); read
  the lane file `.dev-flow/BACKLOG-CODE.md` and register this item; **derive the next
  free batch number from disk + origin branches, not from memory** (two numbering
  collisions have already happened); re-read `state.json` immediately before any edit —
  it is a single-batch, last-writer-wins concurrency hazard.
- **Premise evaluation at every gate** (C-43): propositions TRUE/FALSE/UNDECIDABLE —
  including this handoff's own claims. The dominant defect class in this project is the
  **vacuous check, concentrated in specs/acceptances, not code** (batch-76: 14 defects,
  zero in shipped code). Consult `/dev-flow-lessons` before writing acceptances.
- Decisions as option tables (✅❌⚠️), inline-paste evidence at gates, review packet per
  increment, Before/After for the LLR-072.3 amendment, backlog reconciliation at close,
  vault sync after merge (`/dev-flow-sync`).

## 7 · Suggested skills for the next session

`/dev-flow` (the batch itself) · `/dev-flow-lessons` (before acceptances) ·
`tui-design` (only if a visual question reopens) · `review-packet` (per increment) ·
`/dev-flow-sync` (after merge).
