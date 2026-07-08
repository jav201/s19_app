# PLAN — batch-28 · Prototype-approved view enhancements (4 views)

**BLUF:** Fold the four winning prototype treatments into the real s19tui TUI —
**A2L → master/detail** (kills the 16-col crush), **Issues → worst-first worklist**,
**Workspace → inline signal** (coverage micro-bars + memory strip + stat pane),
**MAC → leading status glyphs**. TUI render-side only; no engine-frozen module
touched. Prototyped + operator-approved (`prototypes/view-enhancements.prototype.html`).

---

## Where we are
- **Phase:** 1 (Requirements engineering) → **`awaiting-gate`** (Phase-1 re-gate, iterate 2)
- **Route:** full `/dev-flow` (operator-directed 2026-07-07)
- **Batch id:** `2026-07-07-batch-28`
- **Gate history:** P0 DoR ✅ · P1 v1 derived (8 HLR/13 LLR/21 AT) → **SUPERSEDED at gate by operator prototype re-selection** → P1 v2 re-derived inline (§6.5 amendment): **A2L C→A (table polish), MAC B→A DROPPED, Issues C→B (grouped dense), Workspace B unchanged** → **4 HLR / 11 LLR / 14 AT / 11 TC**. Awaiting P1 re-gate.
- **Scope now = 3 stories:** US-038 (A2L polish · dir A), US-039 (Issues grouped-dense · dir B), US-040 (Workspace dense cockpit · dir B). US-041 (MAC) OUT.

## Objective
Raise the information-hierarchy / readability of the four highest-value non-entropy
views. The prototype answered "what should each look like"; this batch answers
"build it in Textual, safely." Two views get a **structural** rework (A2L, Issues);
two get **additive inline signal** (Workspace, MAC).

## Base currency (RC-1) — PASS @ `aa126fe`
- `git fetch origin` @ 2026-07-07. HEAD = merge-base(HEAD, origin/main) = origin/main tip = **`aa126fe`**.
- batch-27 close chain merged: PR #45 `d0b47fd` (Memory Map) · #46 `ba66568` (label fix) · #47 `2dce958` (snapshot-regen) · #48 `aa126fe` (Optional F401).
- Clean tree (only untracked `prototypes/`). No rebase / new cut needed.

## Already-shipped check (Phase-0 RC-1 second half)
- Highest existing `R-TUI-041` + `US-037` (batch-27). Grep of `REQUIREMENTS.md`
  finds **no** requirement covering master/detail, worklist, coverage bar, memory
  strip, or status glyph → all **net-new**. Opens **R-TUI-042 / US-038**.

## Stories (intake — Definition of Ready)
| id | title (view → direction) | INVEST | class |
|----|--------------------------|--------|-------|
| US-038 | A2L Explorer → master/detail record card (dir C) | ✓ | READY* |
| US-039 | Issues Report → worst-first worklist (dir C) | ✓ | READY* |
| US-040 | Workspace → inline signal: coverage bars + memory strip + stat pane (dir B) | ⚠ size | READY*† |
| US-041 | MAC View → leading status glyphs (dir B) | ✓ | READY* |

`*` READY pending operator confirmation of the design decisions below.
`†` US-040 bundles 3 sub-features → candidate to split at Phase 1/3 (see D3 + sizing).

## Open design decisions (resolve at DoR gate)
- **D1a — A2L replace vs toggle.** Master/detail default; keep the wide 16-col table
  behind a toggle key? → *Recommend default master/detail + retained table toggle*
  (no lost scan-many-fields capability, modest extra surface).
- **D1b — Issues replace + hex-peek.** Worklist replaces the flat 8-col table; does the
  live hex-peek pane stay or become a per-card **Open-in-Hex** jump (Memory Map pattern)?
  → *Recommend worklist replaces table; per-card Open-in-Hex replaces the live peek*.
- **D2 — Memory strip scope.** Workspace-only, or a persistent shell element on every
  screen? → *Recommend Workspace-only this batch* (global strip = bigger cross-view
  change → separate batch).
- **D3 — Workspace entropy sparkline.** Include it (reuse batch-26 `entropy_service`,
  adds load-time compute + a dependency) or drop it (entropy already has its `e`
  viewer)? → *Recommend DROP this batch* (simpler; keep coverage/counts stats only).

## Locked-in (not decisions — controls)
- **C-17 markup-safety (mandatory Phase-1 LLR + hostile-input AT).** Both the A2L
  record card and the Issues worklist render **file-derived** text
  (`ValidationIssue.message/.symbol/.code`, A2L symbol/tag names). Any markup-enabled
  render composes `rich.text.Text` with explicit `style=` (never interpolate raw file
  text into a markup string). Prototype deliberately seeded hostile `MAP_Model[bold]`
  + `BAD=LINE`.
- **C-16 real-mechanism ATs (mandatory).** Master/detail selection, worklist
  navigation, and every Open-in jump AT drives the **real** key/click path — never
  `.focus()` or a direct setter proxy (batch-27 arrow-nav lesson).

## Roadmap / increment plan (provisional — firms at Phase 3)
- **Inc 1:** MAC status glyphs (US-041) — smallest, `app.py update_mac_view` render-side + markup-safe.
- **Inc 2:** Issues worklist (US-039) — worklist widget + `app.py` + Open-in wiring + markup-safe + hostile AT.
- **Inc 3:** A2L master/detail (US-038) — record-card widget + `app.py update_a2l_*` + toggle + markup-safe + hostile AT.
- **Inc 4:** Workspace coverage bars + memory strip (US-040a) — `app.py`/`styles.tcss` (+ strip widget, maybe reuse `MemoryMapPanel` cell logic).
- **Inc 5:** Workspace stat pane (US-040b) + snapshot cells/xfail.
- (Boundaries provisional; ≤5 files each. Higher-risk C-rewrites sequenced early.)

## Risks / watch-items
- **R1 — snapshot baselines.** Every view here changes SVG baselines. Local regen
  FORBIDDEN (`reference_snapshot_regen_env`); textual pinned `8.2.8`. Add new/changed
  snapshot cells **xfail-until-baseline**, regen in canonical CI post-merge (batch-25/27 pattern).
- **R2 — C-17 injection sink (HIGH).** The prototype rendered CONTROLLED data → cannot
  reveal the injection sink. Markup-safe LLR + hostile-input AT designed-in at Phase 1.
- **R3 — engine-frozen boundary.** `a2l.py` / `mac.py` are frozen readers. All render
  changes live in `app.py` / new `tui/` widget modules, never in the parsers.
- **R4 — thread split.** New widgets stay render-only (driven by the `update_*`
  renderers on the UI thread); read already-computed enriched tags / `_validation_issues`
  / `ranges` — no new parse/coverage/validation analysis.
- **R5 — US-040 size.** 3 sub-features; may split into two increments (bars+strip / stat pane).
- **R6 — C-13 geometry.** New fixed siblings (A2L record card, Workspace stat pane,
  memory strip row) must clear the 80/120-col budget before a fixed width is committed.

## Conventions honored
- Engine-frozen set untouched. Colors via `color_policy` sev-* palette (single source of truth).
- Docstring section order; type hints; ≤5 files/increment; dual traceability (AT + TC).
- Reuse: coverage arithmetic from `render_ranges`; `MemoryMapPanel` cell logic for the strip; `update_hex_view(focus=...)` for Open-in-Hex jumps.

## Out-of-scope (carries)
- Prototype directions not chosen per view (A Baseline+; MAC/Workspace dir C).
- Patch Editor, A2B Diff (still placeholder), Bookmarks (dead placeholder) — untouched.
- Global persistent memory strip across all screens (D2 → separate batch if wanted).
- Entropy sparkline in Workspace (D3 → deferred unless operator opts in).
- Any change to how enriched tags / issues / ranges are COMPUTED (engine).

## Test ledger
- Base test count: TBD (measure at Phase 3 entry). `post = base − D + A`.

## Decision log (human mirror of state.json)
- 2026-07-07 — batch-27 closed/merged (PR #45 + #46/#47/#48, tip `aa126fe`); rolled to batch-28.
- 2026-07-07 — batch-28 opened; RC-1 PASS @ `aa126fe`; all stories net-new → R-TUI-042 / US-038.
- 2026-07-07 — 4 open decisions (D1a/D1b/D2/D3) + C-16/C-17 locked; awaiting DoR gate.
- 2026-07-07 — DoR decisions RESOLVED: D1a A2L = default card + **retained table toggle**;
  D1b Issues = worklist replaces table, **keep live hex-peek** (cards|hex); D2 = strip
  **Workspace-only**; D3 = **drop** entropy sparkline. All 4 stories READY. Approved → Phase 1.
- 2026-07-07 — P1 v1 derived (8 HLR/13 LLR/21 AT). **At the P1 gate the operator re-selected
  prototype directions** ("todo el potencial"): A2L **C→A** (table polish, not master/detail);
  MAC **B→A** = as-today → **DROPPED**; Issues **C→B** (grouped-by-severity + counts + chips,
  keep hex-peek); Workspace **B unchanged** (no entropy). 3 confirm forks resolved
  (A2L=polish; MAC=leave; entropy=out). **iterate-to-refine → P1 v2 re-derived inline**
  (§6.5 amendment); 4 HLR / 11 LLR / 14 AT. Awaiting P1 re-gate.
