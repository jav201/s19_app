# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `818a02b` (batch-19 PR #31 merged); **batch-20 (D-1+D-2) pending merge.** **RC-1 every batch open:** `git fetch`; assert merge-base == origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix; commits/PRs only on operator approval. **Last refresh: 2026-06-29 (batch-20 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

---

## OPEN QUEUE

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

### D-3 — Declared-region report dialog: per-line skip detail + comma-in-name support (D-2 follow-on)
- **Flow:** `direct` micro-PR or fold into a batch already touching the report dialog. **Priority: P3.** **Origin:** batch-20 (D-2 shipped count-only; reviewer/postmortem deferrals).
- **Scope:** (a) line-level detail in the skip notice (currently count-only `"N region line(s) skipped"`); (b) comma-escaping so a region name containing a comma round-trips (currently skipped as malformed in the `name,start,end` line format — no safety gap, the scrub neutralizes injection). UX polish only; fold opportunistically.

## DONE (batches 14–20, merged + synced) — do NOT redo, verify-shipped if in doubt
- US-015 (16/32 S19 record width + S0 header) — batch-14, PR #22 (`b734c19`)
- US-016 (A↔B compare load-failure honesty) — batch-15, PR #20 (`R-DIFF-LOADFAIL-001`)
- US-017 / GAP #2 (manifest per-variant assignments) — batch-16, PR #23 (`dd46113`)
- US-018 (#9 workspace one-line hex) — batch-17, PR #29
- US-019 (CRC selectable record width) — batch-17, PR #29
- US-020a/b (#10 issues hex pane + Related column) — batch-17, PR #29
- US-022 / US-023 (#11 classification legend — report section + in-app modal) — batch-18, PR #30 (`8654df5`)
- US-020c / US-020d (#10 issues-report addendum + issue enrichment + region persistence) — batch-19 (REQUIREMENTS §25; 908→926). Persistence = serialization layer only; UI auto-wire split to D-1.
- **D-1 / D-2 (declared-region UI round-trip + skip notice) — batch-20 (REQUIREMENTS §26; 958→974, 0 fail, frozen 0).** D-1 = save persists regions to project.json + load pre-fills the dialog (round-trip, C-12 gate AT-028a); D-2 = count-only skip notify. Closes the declared-region feature line. Pending PR/merge. Residual UX polish → D-3 (P3).
- Closed process/AT carries: C-9 (compare hex-pane AT), CRC-width lock-AT, ruff F401/F402, batch-07 report seam, batch-01 evidence packs, C-6 (TC-id retire), obsidian flips.

## Controls encoded (global `~/.claude` / templates) — do NOT re-encode
RC-1 (Phase-0 base-currency gate), C-1 (dev-flow-sync reject-check), C-10/C-11 (AT-authoring), C-12 (output-then-consume AT), **C-13 (geometry-budget)** + **C-13.1 (deficit-matched fallback, batch-18)**, QC-2 (value-discriminating RED), QC-3 (boundary-catalog pre-Phase-3), **inline-paste-at-gates protocol (batch-20, dev-flow.md point 5)**. Two-layer AT/TC + dual traceability standing. dev-flow control-encode approval protocol (always ask before editing `~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **#8 patch-editor overhaul** — `/dev-flow`, scope-first Phase 0 (decompose into stories); C-13 budget per pane. **Next (P1).**
2. **#12** — `/dev-flow`, design proposal first (greenfield entropy viewer + before/after + reconcile).
3. **D-3** — declared-region per-line skip detail + comma-in-name (P3, fold opportunistically).

Operator confirms / reorders.
