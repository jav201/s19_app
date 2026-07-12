# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `978a900` (batch-36 snapshot
> baselines, PR #67 merged); **batch-37 (US-061 persistent report control · US-062 entropy
> paging+sort · US-063 entropy legend+clickable strip · US-064a patch refresh · US-064b JSON popup)
> pending commit/PR.** **RC-1 every batch open:** `git fetch`; assert merge-base == origin/main tip;
> cut a fresh branch off origin/main; per-story already-shipped grep before deriving.
> **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py,
> tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5 files/increment;
> every behavioral change ships a black-box `AT-NNN` shown failing pre-fix; commits/PRs only on
> operator approval; **ask the approval model at every batch kickoff — a standing authorization is
> never carried across batches** (feedback_standing_auth_per_batch). **Last refresh: 2026-07-12
> (batch-37 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

Full B-01..B-24 backlog detail: `.dev-flow/project_baseline_backlog_2026-07-09.md` (vault memory)
with the 2026-07-11 status reconciliation. **Entire P1 set is CLOSED** (batches 31–35); batch-36
closed US-058/059/060 (B-22/B-24/B-23); **batch-37 closes the entire P2 set — B-11/B-12/B-13/B-14**
(US-061/062/063/064a/064b). What remains is P3 + the Bookmarks scaffold + hygiene carries.

---

## OPEN QUEUE

### P3 — low
- **B-16 — v2-path relabel.** Relabel the v2 change-set path for operator clarity. **Flow:**
  `direct` micro-PR or fold.
- **B-17 — A2L >32-bit defensive warning.** Emit a defensive warning when an A2L address/extent
  exceeds 32 bits. **Flow:** `/dev-flow` (touches parse-adjacent surfaces — keep off the frozen
  engine; TUI-side warning only).
- **B-18 — info buttons.** Add per-section info buttons across the TUI. **Flow:** `/dev-flow` or
  `/prototype` first.
- **B-19 — patch undo/redo.** Undo/redo for patch-editor edits (US-058 explicitly excluded it;
  batch-37 US-064b explicitly left undo/redo out of scope). **Flow:** `/dev-flow`.

### Dead scaffold (own future batch)
- **Bookmarks screen** — rail item 8 is a dead "coming soon" placeholder; the one clear TUI gap.
  Its own future batch (spec first). **Priority: P2–P3.**

### Hygiene carries (fold opportunistically)
- **S-F7** (P3): `report_service` surfaces raw `linkage_symbol` — sanitize/relabel. batch-35 carry.
- **`canonical_report_bytes` helper consolidation** (P3): consolidate the duplicated
  report-byte-identity golden helpers into one canonicalizer. batch-35 carry.
- **`__setattr__` retire** (P3): retire the `__setattr__` shim once callers are migrated. batch-35
  carry.
- **P-1 / P-2 / P-3** (P3): the standing process/polish carries from the baseline backlog
  (coverage-% `.6f` display; A2L-symbol region names + per-cell tooltips R-TUI-041 R-3;
  pre-existing full-suite TUI global-state flake). See baseline backlog for detail.
- **Native bracketed-paste 64 KiB cap gap (P3, NEW — batch-37 surfaced, US-064-adjacent,
  PRE-EXISTING).** Neither `#patch_paste_text` nor the new `#changeset_json_text` popup caps
  Textual's native bracketed paste at 64 KiB; the 65 KiB `os_clipboard_input` funnel guards a
  *different* ingress. Surfaced by the S-01 spec-premise correction
  (`.dev-flow/2026-07-11-batch-37/05-postmortem.md` §2 F-2 / §6). US-064b added no new uncapped
  ingress, so this is a separate item, not a batch-37 regression. **Flow:** `/dev-flow` or `direct`.
- **~9 LOW review carries (P3, NEW — batch-37 increment reviews).** All reviewer-accepted as
  non-blocking; groom only if they recur. Inc-1: TC-328 uses a status-line proxy for the None-guard.
  Inc-2: AT-061a activation via `.press()` not `pilot.click` (zero suite precedent; still routes
  end-to-end through the message→handler, not a proxy) + b-path asserts distributed across the node.
  Inc-3: `ENTROPY_STRIP_MAX_CELLS` vestigial after the fixed-512 page budget + a drift-mark unused
  arg. Inc-4: page-2 real-click is unit-covered (TC-327), AT drives page-0 cells + a benign
  deferred-mount race (`call_after_refresh`, green across toggles). Inc-5: `Escape` not bound on
  `ChangeSetJsonScreen` (Cancel button is; data-safe). Detail:
  `.dev-flow/2026-07-11-batch-37/05-postmortem.md` §6.
- **Snapshot-baseline regen (batch-37 carry)** (P3): the batch-36 patch cells were regenerated and
  their xfails retired via PR #67 (merged). NOW the **2 entropy snapshot cells**
  (`test_tc036s_entropy_modal_snapshot[entropy-comfortable-80x24 / -120x30]`,
  `test_tui_snapshot.py:613-634`) are `xfail(strict=False)`-until-baseline — they snapshot the new
  `#entropy_controls` / `#entropy_legend` / `#entropy_cell_k` surface. Regenerate ONLY in the
  canonical CI env **post-merge** (local regen drifts unrelated baselines —
  `reference_snapshot_regen_env`), then retire the xfails + the batch-37 `_batch37_entropy_drift_marks`.
  A follow-up snapshot-baselines PR, as in batches 35/36.

---

## Lessons carried (feed the next census)
- **Census cross-file sweep (batch-37, US-064a → C-26 / C-CAND-A, operator-approved).** Inc-1 added
  `#patch_doc_refresh_button` to `#patch_doc_controls` and updated its HOME-file id census
  (`test_at057a` in `test_tui_patch_editor_v2.py`) but NOT the SIBLING census
  `test_tc319_regroup_section_structure_census` in `test_tui_patch_layout.py`, which pins the SAME
  container's child order in a different file; the additive button broke the sibling pin and slipped
  every per-increment gate, caught only by the Phase-4 whole-suite run (orchestrator-fixed test-only,
  0 shipped defect). **Rule (C-26, extends C-14):** when an increment adds/moves/removes a widget in
  a PINNED structure (an id-census or exact-child-list layout test), grep the touched widget id AND
  its parent container id across ALL of `tests/` before closing the increment — every file that pins
  the surface must be in the increment's run scope and, if it asserts order/membership, superseded to
  the shipped state. Origin: `.dev-flow/2026-07-11-batch-37/04-validation.md` §7,
  `05-postmortem.md` §2 F-1 / §7. (Companion candidate C-CAND-B — verify existing-widget-class claims
  at draft time, from the S-01 spec-premise miss — proposed, lower priority, may be declined as
  already covered by Engineering Rule 8.)
- **Writer-census includes report-byte-identity goldens (batch-36, US-059).** Whenever a
  report-content SOURCE changes (e.g. `LEGEND_TABLE`, or any string that renders into a generated
  report), the supersession census MUST enumerate every byte-identity / full-output golden that
  snapshots rendered report bytes as a superseded consumer. From
  `.dev-flow/2026-07-11-batch-36/05-postmortem.md` §7.

---

## DONE (batches 31–37, shipped) — do NOT redo, verify-shipped if in doubt
- **batch-37 (US-061/062/063/064a/064b — the entire P2 set B-11/B-12/B-13/B-14) — pending
  commit/PR.** US-061 (B-11) persistent before/after-report control replacing the transient notify
  (R-TUI-049); US-062 (B-12) entropy viewer paging past the 512 cap + entropy/address sort
  (R-TUI-050); US-063 (B-13) entropy band-colour legend + clickable strip cells that navigate
  (R-TUI-051); US-064a (B-14) patch-editor Refresh re-reads the file over `document.source_path`
  (R-TUI-052); US-064b (B-14) full-size JSON popup editor with the file-loaded disable-guard
  closing the A-01 data-loss footgun (R-TUI-053). REQUIREMENTS §34. Gate green
  (`1358 passed, 2 skipped, 5 xfailed, 0 failed`; ledger 1369→1385, +16); 8/8 black-box ATs; frozen
  0. Autonomous + self-merge (operator grant, batch-37-only).
- **batch-36 (US-058/059/060) — snapshot PR #67 merged (`978a900` tip line).** US-058 (B-22)
  patch-editor readable paste box reparented (R-TUI-046); US-059 (B-24) hex-view colour legend in
  modal + report (R-TUI-047); US-060 (B-23) fixtures relocated to `examples/` + 54 MB duplicate A2L
  pruned, 96 M → ~42 M (R-TUI-048). REQUIREMENTS §33.
- **batch-35 (B-07, LAST P1) — PR #64 `2a647d1` + snapshot PR #65.** Report filter whitelist
  (R-RPT-FILTER-001) + patch-editor regroup into labeled patch-script / checks sections (R-TUI-045).
  Closes the 2026-07-09 P1 set. REQUIREMENTS §32.
- **batch-34 (B-08/09/10) — PR #63 `79699a5`.** Merged context windows, HTML side-by-side panes with
  per-byte highlights, linkage `HH HH |ascii|` cells (fast-flow reports lane).
- **batch-33 (B-02) — PR #61 `f79834e` + snapshot PR #62.** Check results explain themselves +
  per-entry taint (R-CHK-002).
- **batch-32 (B-21) — PR #60 `dd91941`.** CRC groups (`groups` beside legacy `regions`,
  declared-order concat → one CRC → one output_address + output_bytes {1,2,4,8} LE).
- **batch-31 (P1 quick strike B-01/03/04/05/06/15/20) — PR #58 `91d884a` + regen PR #59.** Hex-nav
  snap, clipboard inputs ×7, Issues PgUp/PgDn, Load-project button; goto/search to absent address
  repositions nearby.

## DONE (batches 14–28) — condensed; full lineage in the vault
Features #1–#12 + #17 and the #8 patch-editor line (US-026..031, b21/b22/b23) + #11 legend +
#10 issues + #9 one-line hex + declared-region round-trip (D-1/D-2) + A2L↔issues reconcile +
before/after report (#12(a)+(c)) + entropy viewer (#12(b), b26) + variant dropdown (#8 CLOSED, b23).
Full detail: `.dev-flow/project_baseline_backlog_2026-07-09.md` and the vault batch log.

## Controls encoded (global `~/.claude` / templates) — do NOT re-encode
RC-1, C-1..C-25 (canonical record: `project_devflow_control_lineage.md`). Headliners since the last
refresh: **C-23 (geometry pilot-measured, not fr-math)**, **C-24 (report byte-identity goldens in the
supersession census)**, **C-25 (orchestrator owns the Phase-4 gate run)** — all encoded 2026-07-11
(batch-36). **batch-37 proposes C-26 (census cross-file sweep, extends C-14 — TC-319 origin)** —
awaiting per-control operator approval before it enters the lineage. Standing: two-layer AT/TC + dual
traceability; inline-paste-at-gates; writer-census sweeps (C-14 / C-15.1); dev-flow control-encode
approval (always ask before editing `~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **Bookmarks screen** — dead scaffold; own batch, spec first. P2–P3.
2. **B-16..B-19** — the P3 pool (v2-path relabel, A2L >32-bit warning, info buttons, patch
   undo/redo). Fold or small batches.
3. **Hygiene carries** — S-F7, canonicalizer consolidation, `__setattr__` retire, P-1/P-2/P-3,
   native bracketed-paste 64 KiB cap gap, batch-37 entropy snapshot regen (post-merge), ~9 LOW
   review carries. Fold opportunistically.

Operator confirms / reorders.
