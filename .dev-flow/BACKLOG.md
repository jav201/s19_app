# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `ec3a2a7` (batch-20 PR #32 merged); **batch-21 (#8 slice-1) pending merge.** **RC-1 every batch open:** `git fetch`; assert merge-base == origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix; commits/PRs only on operator approval. **Last refresh: 2026-06-30 (batch-21 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

---

## OPEN QUEUE

### #8 — Patch-editor overhaul (DECOMPOSED batch-21; slice-1 DONE, remaining slices below)
- **Flow:** `/dev-flow`. **Priority: P1.** Phase-0 decomposition (batch-21) split #8 into 6 stories US-026..031.
- **Slice-1 DONE (batch-21):** US-026 (change-file dropdown) + US-027 (dedicated `patches/` folder) + US-029 (Checks clarity). Change-file default `changes.json` was already shipped; the "Checks-button fix" resolved as a clarity Label (US-029). See DONE + REQUIREMENTS §27.
- **Remaining slices (deferred, in order):**
  - **US-030 — 4-pane split** (P1, **NEXT for #8**): `PatchEditorPanel(ScrollableContainer)` (`screens_directionb.py`) is a single vertical scroll container — the 4-pane split is net-new structural work. **Its own geometry batch — C-13/C-13.1 SPIKE:** measure the patch-editor host width at 80/120 cols at draft time (est. ~37/~58, UNVERIFIED) + a deficit-matched fallback ladder BEFORE any code. US-031 (4-pane geometry snapshots) rides with it.
  - **US-028 — inline variant dropdown** (P2): switch the active variant without leaving the patch editor (net-new inline `Select` + persist `active_variant`). Independent, low-blast.

### #12 — Before/after report + entropy viewer + reconcile
- **Flow:** `/dev-flow` (greenfield → **design proposal first**). **Priority: P2** — most design-heavy; last.
- **Scope:** (a) before/after report generation (original vs patched file); (b) entropy / data-classification viewer (greenfield); (c) A2L-colour ↔ issues-report reconcile (red A2L rows that produce no issue).
- Verified net-new: `report_service.py` has 0 `entropy`/`before-after` hits on main. (c) likely the smallest sub-item and could be split out early if value warrants.

---

### D-3 — Declared-region report dialog: per-line skip detail + comma-in-name support (D-2 follow-on)
- **Flow:** `direct` micro-PR or fold into a batch already touching the report dialog. **Priority: P3.** **Origin:** batch-20 (D-2 shipped count-only; reviewer/postmortem deferrals).
- **Scope:** (a) line-level detail in the skip notice (currently count-only `"N region line(s) skipped"`); (b) comma-escaping so a region name containing a comma round-trips (currently skipped as malformed in the `name,start,end` line format — no safety gap, the scrub neutralizes injection). UX polish only; fold opportunistically.

## DONE (batches 14–21, merged + synced) — do NOT redo, verify-shipped if in doubt
- US-015 (16/32 S19 record width + S0 header) — batch-14, PR #22 (`b734c19`)
- US-016 (A↔B compare load-failure honesty) — batch-15, PR #20 (`R-DIFF-LOADFAIL-001`)
- US-017 / GAP #2 (manifest per-variant assignments) — batch-16, PR #23 (`dd46113`)
- US-018 (#9 workspace one-line hex) — batch-17, PR #29
- US-019 (CRC selectable record width) — batch-17, PR #29
- US-020a/b (#10 issues hex pane + Related column) — batch-17, PR #29
- US-022 / US-023 (#11 classification legend — report section + in-app modal) — batch-18, PR #30 (`8654df5`)
- US-020c / US-020d (#10 issues-report addendum + issue enrichment + region persistence) — batch-19 (REQUIREMENTS §25; 908→926). Persistence = serialization layer only; UI auto-wire split to D-1.
- **D-1 / D-2 (declared-region UI round-trip + skip notice) — batch-20 (REQUIREMENTS §26; 958→974, 0 fail, frozen 0).** D-1 = save persists regions to project.json + load pre-fills the dialog (round-trip, C-12 gate AT-028a); D-2 = count-only skip notify. Closes the declared-region feature line. Pending PR/merge. Residual UX polish → D-3 (P3).
- **#8 slice-1 (patch-editor change-file management + Checks clarity) — batch-21 (REQUIREMENTS §27; 974→985, 0 fail, frozen 0).** US-027 dedicated `patches/` folder + US-026 change-file dropdown (C-12 gate AT-030a + F1 read-path containment guard) + US-029 Checks clarity Label. Pending PR/merge. Remaining #8 slices → OPEN QUEUE (US-030 geometry batch next, US-028, US-031).
- Closed process/AT carries: C-9 (compare hex-pane AT), CRC-width lock-AT, ruff F401/F402, batch-07 report seam, batch-01 evidence packs, C-6 (TC-id retire), obsidian flips.

## Controls encoded (global `~/.claude` / templates) — do NOT re-encode
RC-1 (Phase-0 base-currency gate), C-1 (dev-flow-sync reject-check), C-10/C-11 (AT-authoring), C-12 (output-then-consume AT), **C-13 (geometry-budget)** + **C-13.1 (deficit-matched fallback, batch-18)**, **C-14 (location-move census sweep — e2e/save-observers, batch-21)**, QC-2 (value-discriminating RED), QC-3 (boundary-catalog pre-Phase-3), **inline-paste-at-gates protocol (batch-20, dev-flow.md point 5)**. Two-layer AT/TC + dual traceability standing. dev-flow control-encode approval protocol (always ask before editing `~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **#8 US-030 — 4-pane split** — `/dev-flow`, **its own geometry batch** (C-13/C-13.1 SPIKE: measure host width @80/120 + fallback ladder before code). US-031 snapshots ride with it. **Next (P1).**
2. **#8 US-028 — inline variant dropdown** — `/dev-flow` or `/fast-dev-flow` (small, independent). P2.
3. **#12** — `/dev-flow`, design proposal first (greenfield entropy viewer + before/after + reconcile). P2.
4. **D-3** — declared-region per-line skip detail + comma-in-name (P3, fold opportunistically).

Operator confirms / reorders.
