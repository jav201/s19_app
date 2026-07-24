# PLAN — batch-n8 · Comprehensive per-view Legend (living compendium)

## Where we are
- **Phase 3 (Implementation) — Inc-1 GATED + Inc-2 DONE (green); resuming Inc-3.** Branch `feat/n8-comprehensive-legend` off `f56cf48`.
- Authorization: **AUTONOMOUS end-to-end + self-merge** (operator CHANGED the model at the 2026-07-24 resume — was supervised at kickoff; per-batch, never carried). Self-approve gates with a Coverage/Certainty/Evidence axis check; present packets in-conversation; final PR-level qa pass 0-HIGH before self-merge.

## Objective
Turn each rail view's Legend into a FULL reference explaining every informational
element that view shows (text, tiles, numbers, columns, glyphs, colours), via an
annotated example **card-on-top** + the real colour key below. Density FULL.
Extends N1 (per-screen scoping, shipped `7ba2631`).

## Scope — 5 stories (views)
| Story | View | Legend surface | Notes |
|---|---|---|---|
| US-N8-1 | Workspace | example-only (no colour key) | new mapped section (today unmapped → full-table fallback) |
| US-N8-2 | A2L Explorer | card + R/G/White/Grey key | 16 columns + detail fields |
| US-N8-3 | Memory Map | card + 4-band key (entropy, NOT severity) | bands ≠ severities |
| US-N8-4 | MAC | card + key + orange↔pale-yellow reconciliation | two colour pipelines |
| US-N8-5 | Issues | card + Errors/Warnings/Info key | 17 codes by family |

## Design inputs (pre-approved via /prototype gate — Kimi K3 build)
- `prototypes/legend_n8.kimi.NOTES.md` — exact per-view copy + density cuts.
- `prototypes/legend_n8.INVENTORY.md` — code-grounded element catalog per view.
- `prototypes/legend_n8.kimi.prototype.py` — runnable card-on-top layout.
- Gallery: https://claude.ai/code/artifact/8fec4d40-0ac4-4471-8c29-25b4a801e1bc

## Mandatory fold-ins (prototype findings)
1. **Label→Static:** `LegendScreen` uses Textual `Label` (truncates at viewport
   width); long meanings lose tails at 120 cols. Key rows must use `Static` (wraps).
2. **MAC colour reconciliation:** the key names the SEVERITY (pale yellow
   `#f6ff8f`) but the MAC table paints warning rows inline `orange3` `#d9a35b`.
   Show a real orange sample row + "trust glyph & Status over hue" (C-10).

## Files (production, NON-frozen)
- `s19_app/tui/legend.py` — per-section example content (new data).
- `s19_app/tui/screens.py` — `LegendScreen.compose` render (card + Static key rows).
- `s19_app/tui/app.py` — `_SCREEN_LEGEND_SECTIONS` add `workspace`.
- `s19_app/tui/styles.tcss` — n8 card styling.
- Tests: legend-specific black-box (Pilot) + white-box; NON-frozen test files.
- **Frozen OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py.

## Roadmap (phases)
- P0 intake ✓ → P1 requirements ✓ → P2 review ✓(iterate-to-refine B-1 applied) → **P3 impl (IN PROGRESS)** → P4 validation → P5 postmortem → P6 docs+PR (operator merges).

## Phase-3 increment plan (≤5 files each; code-reviewer per increment gate)
- **Inc-1 (data layer) — ✅ DONE + GREEN + GATED (code-reviewed inline 2026-07-24):** `legend.py` +612 (`LEGEND_EXAMPLES` role-tagged per view + `build_band_key_rows()` derived from `ENTROPY_BANDS` + `format_cutoff()` single-source + derived glyphs + map Hex overlays AMD-6 + MAC `warning_sample` row + notes consts). `tests/test_legend_n8.py` = 30 TCs incl **TC-N8-11**. 30 passed, RED-verified (move-aside C-20), 0 regressions, ruff clean. Code-review: 0 blockers/majors, 2 cosmetic minors (private `_*_lines()` docstrings = trivial-return exception; `_map_band_bar_sample` hardcodes stable band-label keys). **Gate: 'Aprobar → Inc-2'.**
- **Inc-2 (render + mapping) — ✅ DONE + GREEN + SELF-APPROVED (2026-07-24):** `screens.py` `LegendScreen.__init__(view_key=)` + `_render_card`/`_render_key` (`Static` rows — AMD-5/HLR-N8-6; map band key `markup=False` for the `[lo,hi)` bracket; MAC reconciliation sample `#legend_mac_warning_sample` painted `[orange3]` via `_MAC_WARNING_SAMPLE_STYLE` — AMD-7/AMD-11); `app.py` `_SCREEN_LEGEND_SECTIONS` workspace=`()` + map=`()`, `action_show_legend` passes `view_key`. Tests: AT-N8-01..05 (Pilot) + N1 amendments AMD-4 (map→`Entropy bands` header; workspace example-only; **full-table fallback RE-POINTED to the genuinely-unmapped `flow` screen** — the only screen still absent from `_SCREEN_LEGEND_SECTIONS`); `test_tui_legend` `_modal_meanings` `Label`→`Static` + 4 full-table tests re-pointed to `flow`. **5 files** (within cap). Full suite **1866 passed / 19 pre-existing snapshot failures (STASH-VERIFIED identical on base f56cf48) / 0 regressions**; ruff clean on new code (`app.py` `F821 Dict` pre-existing on main).
- **Inc-3 (CSS + fold-in ATs):** `styles.tcss` n8 card classes (no own colour — LLR-N8-6.2). Tests: **AT-N8-06** (`type(row) is Static AND size.height>=2` — AMD-5), **AT-N8-07** (painted `orange3` segment coupled to real MAC WARNING inline style — AMD-7/AMD-8 live-column oracle), remaining white-box TC-N8-*. Files: styles.tcss, test (2).
- Toolchain entry gate at Inc-1: verify pytest (+ ruff if configured) present.
- §6.5 AMD-* OVERRIDE the §3/§4 body on any conflict (precedence line).

## Risks / watch-items
- Legend modal is NOT tc016s-snapshot-captured → add legend-specific snapshot/black-box tests; may not need the 19-cell canonical regen, but verify.
- FULL density × 5 views → viewport/scroll budget at 80- and 120-col (C-13 consult `docs/engineering-rules.md`).
- Markup safety (C-17): example cards render sample tokens — keep them literal `Text`/escaped, no file-derived interpolation (though examples are static samples, not file data).

## Decision log
- 2026-07-23 P0: kickoff. Design pre-approved via /prototype (Kimi K3, FULL density). Authorization: supervised + operator-merge + record-all. state.json rotated from stale batch-52. Operator 'approve' → P1.
- 2026-07-23 P1: architect (6 HLR/15 LLR/AT-N8-01..07) + qa catalog. Orchestrator reconciliations (§6.5): AMD-1 architect ids canonical (qa ids superseded 1:1; qa AT-156 C-10a → method rider); AMD-2 AT-N8-06/07 observe PAINTED output not `.plain` (Label⊂Static blind to truncation — qa F-1); AMD-3 operator R-1 ruling = Map band-key + explain the 2 Hex overlays in the card; AMD-4 two intended N1 test amendments (map heading, workspace example-only). Operator 'approve' → P2.
- 2026-07-23 P2: dispatched architect+qa+security cross-review of 01-requirements.md (incl. §6.5). `iterate-to-refine` on B-1 applied inline (AMD-5..12). Operator 'approve' → P3.
- 2026-07-23 P3 Inc-1: data layer implemented + green (see Inc-1 line); operator PAUSED for a fresh-session resume.
- 2026-07-24 RESUME: re-verified Inc-1 on disk (44 passed, ruff clean); code-reviewed Inc-1 inline (0 blockers/majors, 2 cosmetic minors). Operator: Inc-1 gate 'Aprobar → Inc-2'; **authorization CHANGED supervised → autonomous + self-merge** (per-batch). Design-default rulings this increment (autonomy, logged): (a) full-table fallback re-pointed to `flow` (the sole unmapped screen) rather than retired (AMD-4 "if one remains"); (b) map/band key rows rendered `markup=False` to carry the literal `[lo,hi)` bracket safely (extends the AMD-9 markup-safety intent to the band range strings); (c) MAC orange coupled to app's `_SEVERITY_TO_RICH_STYLE[WARNING]` via the AT (not a screens.py import — app imports screens, circular); (d) `_modal_meanings` query `Label`→`Static` (Label⊂Static) to keep the 3 existing legend tests meaningful.
- 2026-07-24 P3 Inc-2: render + mapping implemented + green + self-approved (axis-check Coverage/Certainty/Evidence all OK; 0 regressions proven by stash-diff, not assumed). → Inc-3.

## Out-of-scope carries
- Checks view legend (Kimi noted it would mirror Issues) — deferred; add if scope expands.
- The ~10 unshown A2L fields — mention as "in detail/log only", not a new surface.

## Test ledger
- base (f56cf48): TBD at Phase 3 entry.
