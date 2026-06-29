# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `8654df5` (batch-18 PR #30 merged). **RC-1 every batch open:** `git fetch`; assert merge-base == origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix; commits/PRs only on operator approval. **Last refresh: 2026-06-29 (batch-18 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

---

## OPEN QUEUE

### D-1 — Declared-region UI save/load wiring (HLR-026 follow-on)
- **Flow:** `/dev-flow` or `/fast-dev-flow` (small). **Priority: P2.** **Origin:** batch-19 (operator option-1 scoped the persistence to the serialization layer only).
- **Scope:** wire the persistence shipped in batch-19 to the UI — save the report dialog's declared regions into `project.json` on project-save (via the existing `_write_and_verify_manifest` path, which now accepts `declared_regions`), and pre-fill the `ReportViewerScreen` region input from `ProjectManifest.declared_regions` on project load. Needs app-level declared-region state. The serialization layer (`serialize/write_project_manifest` + `read_project_manifest`) is already in place + tested (`R-RPT-ADDENDUM-PERSIST-001`).

### D-2 — Report dialog: feedback on skipped malformed region lines
- **Flow:** `direct` micro-PR or fold into D-1. **Priority: P3.** **Origin:** batch-19 Inc3 reviewer F1.
- **Scope:** `_parse_declared_regions` (`screens.py:543`) silently skips blank/malformed/invalid lines (log only). Surface a count to the operator (e.g. `self.set_status`/`notify` before dismiss) so a mistyped region isn't silently dropped. Touches the dismiss/post path in `ReportViewerScreen.on_button_pressed`.

### #8 — Patch-editor overhaul
- **Flow:** `/dev-flow` (largest; **scope-first Phase 0 — likely splits into several stories**). **Priority: P1** (after US-020c/d).
- **Scope:** 4-pane split + change-file default (`changes.json`) + change-file dropdown + dedicated workarea folder + variant dropdown + Checks-button fix.
- **Baseline:** `PatchEditorPanel(ScrollableContainer)` (`screens_directionb.py:335`) is currently a SINGLE scrollable container — the 4-pane split is net-new structural work. **C-13 geometry-budget is a prime case:** verify each pane's budget at 80/120-col at draft time (don't assume); C-13.1 deficit-matched fallback applies to any overflow.
- **High blast radius** — Phase-0 decomposition mandatory before any code.

### #12 — Before/after report + entropy viewer + reconcile
- **Flow:** `/dev-flow` (greenfield → **design proposal first**). **Priority: P2** — most design-heavy; last.
- **Scope:** (a) before/after report generation (original vs patched file); (b) entropy / data-classification viewer (greenfield); (c) A2L-colour ↔ issues-report reconcile (red A2L rows that produce no issue).
- Verified net-new: `report_service.py` has 0 `entropy`/`before-after` hits on main. (c) likely the smallest sub-item and could be split out early if value warrants.

---

## DONE (batches 14–18, merged + synced) — do NOT redo, verify-shipped if in doubt
- US-015 (16/32 S19 record width + S0 header) — batch-14, PR #22 (`b734c19`)
- US-016 (A↔B compare load-failure honesty) — batch-15, PR #20 (`R-DIFF-LOADFAIL-001`)
- US-017 / GAP #2 (manifest per-variant assignments) — batch-16, PR #23 (`dd46113`)
- US-018 (#9 workspace one-line hex) — batch-17, PR #29
- US-019 (CRC selectable record width) — batch-17, PR #29
- US-020a/b (#10 issues hex pane + Related column) — batch-17, PR #29
- US-022 / US-023 (#11 classification legend — report section + in-app modal) — batch-18, PR #30 (`8654df5`)
- US-020c / US-020d (#10 issues-report addendum + issue enrichment + region persistence) — batch-19 (REQUIREMENTS §25; 908→926). Persistence = serialization layer only; UI auto-wire split to D-1.
- Closed process/AT carries: C-9 (compare hex-pane AT), CRC-width lock-AT, ruff F401/F402, batch-07 report seam, batch-01 evidence packs, C-6 (TC-id retire), obsidian flips.

## Controls encoded (global `~/.claude` / templates) — do NOT re-encode
RC-1 (Phase-0 base-currency gate), C-1 (dev-flow-sync reject-check), C-10/C-11 (AT-authoring), C-12 (output-then-consume AT), **C-13 (geometry-budget)** + **C-13.1 (deficit-matched fallback, batch-18)**, QC-2 (value-discriminating RED), QC-3 (boundary-catalog pre-Phase-3). Two-layer AT/TC + dual traceability standing. dev-flow control-encode approval protocol (always ask before editing `~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **US-020c/d** — `/dev-flow`, Phase-0 design spike on "declared memory locations" before deriving HLR. Smallest; extends the issues-report line.
2. **#8 patch-editor overhaul** — `/dev-flow`, scope-first Phase 0 (decompose into stories); C-13 budget per pane.
3. **#12** — `/dev-flow`, design proposal first (greenfield entropy viewer + before/after + reconcile).

Operator confirms / reorders.
