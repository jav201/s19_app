# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `7df60dd` (batch-35 snapshot
> baselines, PR #65 merged); **batch-36 (US-058 patch paste box · US-059 hex legend · US-060 fixture
> housekeeping) pending commit/PR.** **RC-1 every batch open:** `git fetch`; assert merge-base ==
> origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before
> deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/,
> tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5
> files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix;
> commits/PRs only on operator approval; **ask the approval model at every batch kickoff — a
> standing authorization is never carried across batches** (feedback_standing_auth_per_batch).
> **Last refresh: 2026-07-11 (batch-36 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

Full B-01..B-24 backlog detail: `.dev-flow/project_baseline_backlog_2026-07-09.md` (vault memory)
with the 2026-07-11 status reconciliation. **Entire P1 set is CLOSED** (batches 31–35); batch-36
closes US-058/059/060 (B-22/B-24/B-23). What remains is P2 / P3 + hygiene carries.

---

## OPEN QUEUE

### P2 — medium
- **B-11 — press-`b` persistent surface.** Make the `b` before/after-report affordance a
  persistent, discoverable surface rather than a transient offer. **Flow:** `/dev-flow` or
  `/fast-dev-flow`.
- **B-12 — entropy viewer pagination + sort.** Add pagination and column sort to the entropy /
  data-classification viewer (feature #12(b), shipped batch-26). **Flow:** `/dev-flow`.
- **B-13 — entropy legend / clickable rows.** Legend for the entropy bands + clickable rows that
  navigate to the region. **Flow:** `/dev-flow` (geometry — C-13 measurement).
- **B-14 — patch refresh / JSON popup.** Patch-editor refresh action + a JSON popup for the
  change-set (the popup US-058 explicitly deferred). **Flow:** `/dev-flow`.

### P3 — low
- **B-16 — v2-path relabel.** Relabel the v2 change-set path for operator clarity. **Flow:**
  `direct` micro-PR or fold.
- **B-17 — A2L >32-bit defensive warning.** Emit a defensive warning when an A2L address/extent
  exceeds 32 bits. **Flow:** `/dev-flow` (touches parse-adjacent surfaces — keep off the frozen
  engine; TUI-side warning only).
- **B-18 — info buttons.** Add per-section info buttons across the TUI. **Flow:** `/dev-flow` or
  `/prototype` first.
- **B-19 — patch undo/redo.** Undo/redo for patch-editor edits (US-058 explicitly excluded it).
  **Flow:** `/dev-flow`.

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
- **Snapshot-baseline regen (batch-36 carry)** (P3): the 2 patch snapshot cells
  (`patch-comfortable-80x24` / `-120x30`) are `xfail`-until-baseline; regenerate ONLY in the
  canonical CI env post-merge (local regen drifts unrelated baselines —
  `reference_snapshot_regen_env`), then retire the xfails + batch-36 marks.

---

## Lessons carried (feed the next census)
- **Writer-census includes report-byte-identity goldens (batch-36, US-059).** The LLR-059.3
  supersession census enumerated the legend's *assertion* consumers but missed the batch-35 report
  byte-identity golden `tests/goldens/batch35/at055b-project-report.md`, which the new `### Hex`
  section legitimately drifts — caught by the failing golden at Inc-1, rebaselined in-batch. **Rule:**
  whenever a report-content SOURCE changes (e.g. `LEGEND_TABLE`, or any string that renders into a
  generated report), the supersession census MUST enumerate every byte-identity / full-output golden
  that snapshots rendered report bytes as a superseded consumer. Proposed control **C-CAND-B**
  (`.dev-flow/2026-07-11-batch-36/05-postmortem.md` §7) — awaits operator per-control approval.

---

## DONE (batches 31–36, shipped) — do NOT redo, verify-shipped if in doubt
- **batch-36 (US-058/059/060) — pending commit/PR.** US-058 (B-22) patch-editor readable paste box
  reparented to its own cell (R-TUI-046); US-059 (B-24) hex-view colour legend in modal + report
  (R-TUI-047); US-060 (B-23) fixtures relocated to `examples/` + 54 MB duplicate A2L pruned, 96 M →
  ~42 M (R-TUI-048). REQUIREMENTS §33. Gate green (`1343 passed, 5 xfailed, 0 failed`); frozen 0.
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
RC-1, C-1..C-22 (canonical record: `project_devflow_control_lineage.md`). Headliners since the last
refresh: **C-16/C-17 (b27)**, **C-18 (every AT → exactly one on-disk node, b30)**, **C-19
(one-complete-run test evidence)**, **C-20 (move-aside RED not `git stash`)**, **C-21 (re-reconcile
the AT/TC registry after AT-amending gates)**, **C-22 (per-cell snapshot-drift)** — all encoded
2026-07-11 with the batch-kickoff-authorization rule (merge-authority + decision-recording) added to
dev-flow.md. Standing: two-layer AT/TC + dual traceability; inline-paste-at-gates; writer-census
sweeps (C-14 / C-15.1); dev-flow control-encode approval (always ask before editing
`~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **B-11 / B-12 / B-13 / B-14** — the P2 pool. B-12/B-13 cluster around the entropy viewer (fold
   together); B-11 and B-14 are independent. **Next (P2).**
2. **Bookmarks screen** — dead scaffold; own batch, spec first. P2–P3.
3. **B-16..B-19** — the P3 pool (v2-path relabel, A2L >32-bit warning, info buttons, patch
   undo/redo). Fold or small batches.
4. **Hygiene carries** — S-F7, canonicalizer consolidation, `__setattr__` retire, P-1/P-2/P-3,
   batch-36 snapshot regen. Fold opportunistically.

Operator confirms / reorders.
