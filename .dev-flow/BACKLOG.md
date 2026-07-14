# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `be62c97` (batch-38 merged —
> PRs #70 `4c3b821` + snapshot #71 `be62c97`; vault-synced 2026-07-13). **The entire B-01..B-24
> backlog is SHIPPED** (P1 batches 31–35, P2 batch-37, P3 batch-38). What remains = hygiene + small
> polish + one flaky-test spike, then the NEW Flow Builder (multi-batch, deferred — see CLOSURE PLAN
> below). **RC-1 every batch open:** `git fetch`; assert merge-base
> == origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before
> deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/,
> tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`) — AND the
> frozen TEST files (`_ENGINE_TEST_FILES`: test_tui_a2l.py, test_tui_mac.py, test_validation_*, …;
> batch-38 F-1 lesson). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown
> failing pre-fix; commits/PRs only on operator approval; **ask the approval model at every batch
> kickoff — a standing authorization is never carried across batches**
> (feedback_standing_auth_per_batch). **Last refresh: 2026-07-12 (batch-38 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

Full B-01..B-24 backlog detail: `.dev-flow/project_baseline_backlog_2026-07-09.md` (vault memory)
with the 2026-07-11 status reconciliation. **Entire P1 set is CLOSED** (batches 31–35); batch-36
closed US-058/059/060 (B-22/B-24/B-23); **batch-37 closes the entire P2 set — B-11/B-12/B-13/B-14**
(US-061/062/063/064a/064b). What remains is P3 + the Bookmarks scaffold + hygiene carries.

---

## OPEN QUEUE

### P3 — low
- **B-16/B-17/B-18/B-19 — SHIPPED batch-38 (US-065/066/067/068a/068b).** The entire P3 pool is
  CLOSED (pending commit/PR). See DONE below. What remains open is the Bookmarks scaffold + hygiene
  carries.

### Rail-8 "Bookmarks" → Flow Builder (NEW multi-batch feature, DEFERRED after hygiene)
- **Operator decision 2026-07-13:** Bookmarks is DROPPED (reports already track memory-address
  values, so bookmarks are redundant). Rail item 8 is instead repurposed into a **functional-block
  Flow Builder** — compose already-coded operations (patch → check → CRC → write-out) as an ordered
  pipeline of typed blocks, run across the project's S19 image(s), emit output file(s). Dropdown-to-add
  (no drag-drop). Architect grounding: most of the execution engine ALREADY exists
  (`variant_execution_service` runs ordered, state-threading, multi-op {patch,check} plans); NEW work
  = a typed-block vocabulary + a thin `flow_execution_service` + the rail-8 UI + persistence. All named
  ops are in NON-frozen modules. **Multi-batch roadmap:** b-N tracer (`source→patch→write-out`, run,
  observable output) → +check/crc blocks (CRC-into-loop = the real seam) → flow persistence → multi-image
  scope + report fusion → polish. **Deferred: operator finishes the open hygiene/polish backlog FIRST.**

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
  PRE-EXISTING; batch-38 EXTENDS).** Neither `#patch_paste_text`, the batch-37 `#changeset_json_text`
  popup, NOR batch-38's new `#entry_json_text` per-entry popup caps Textual's native bracketed paste
  at 64 KiB; the 65 KiB `os_clipboard_input` funnel guards a *different* ingress. Include
  `#entry_json_text` when this carry lands. **Flow:** `/dev-flow` or `direct`.
- **batch-38 LOW review carries (P3, NEW).** All reviewer-accepted non-blocking. Inc-4 F1: the Checks
  results panel goes stale after undo/redo (`last_check_result` not reset in `undo`/`redo`;
  `_refresh_patch_history_view` refreshes entries+issues but not check-results) — secondary
  user-invoked surface. Inc-4 F2: undo/redo discoverability is below the entries-pane fold →
  proposed `ctrl+z`/`ctrl+y` key bindings routed to the same `UndoRequested`/`RedoRequested`
  messages. Inc-5 F1: a per-entry edit that changes an address to collide with a sibling passes the
  per-entry parse but is re-detected + blocked at the document Validate/Apply/Save gate (by-design,
  LLR-068b.3). Detail: `.dev-flow/2026-07-12-batch-38/05-postmortem.md` §6.
- **batch-38 patch snapshot regen (P3, NEW).** The 2 `patch` density cells
  (`test_tc016s_density_layout_snapshot[patch-comfortable-80x24 / -120x30]`) are `xfail(strict=False)`
  from US-065's copy change + US-067's info button (`_batch38_drift_marks`, `test_tui_snapshot.py`).
  Regenerate ONLY in canonical CI **post-merge** (local regen drifts unrelated baselines), then
  retire the xfails + the helper. A follow-up snapshot-baselines PR, as in #67/#69.
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

## DONE (batches 31–38, shipped) — do NOT redo, verify-shipped if in doubt
- **batch-38 (US-065/066/067/068a/068b — the entire P3 pool B-16/B-17/B-18/B-19) — pending
  commit/PR.** US-065 (B-16) change-set free-path label clarity — title `"Change document (JSON)"` +
  placeholder framed as an alternative to the `patches/` dropdown (R-TUI-054); US-066 (B-17) defensive
  `A2L_ADDRESS_EXCEEDS_32BIT` WARNING for tag addresses > 0xFFFFFFFF, produced TUI-side in
  `services/validation_service.py` (engine frozen), C-17 markup-safe (R-TUI-055); US-067 (B-18)
  variant-selector info button → `VariantHelpScreen` modal (R-TUI-056); US-068a (B-19) patch-editor
  undo/redo, bounded deep-copy history `_HISTORY_MAX=20` in ChangeService + A-01 file-loaded guard
  (R-TUI-057); US-068b (B-19) per-entry JSON popup `EntryJsonScreen` (single-entry seed, validated
  `parse_change_document`) + A-01 guard (R-TUI-058). REQUIREMENTS §35. Gate green
  (`1377 passed, 2 skipped, 5 xfailed, 0 failed`; ledger 1358→1377, +19); 6/6 black-box ATs C-18
  single-node; frozen 0 (source + test). Autonomous + self-merge (operator grant, batch-38-only).
  Root causes: F-1 frozen-TEST-file guard gap (AT-066a briefly in frozen test_tui_a2l.py, fixed
  test-only); F-2 Phase-1 multi-author contract drift (Phase-2 caught). No scope drift.
- **batch-37 (US-061/062/063/064a/064b — the entire P2 set B-11/B-12/B-13/B-14) — MERGED PRs #68
  `18f1d30` + snapshot #69 `5a6c45b`.** US-061 (B-11) persistent before/after-report control
  (R-TUI-049); US-062 (B-12) entropy viewer paging past the 512 cap + entropy/address sort
  (R-TUI-050); US-063 (B-13) entropy band-colour legend + clickable strip cells that navigate
  (R-TUI-051); US-064a (B-14) patch-editor Refresh re-reads the file over `document.source_path`
  (R-TUI-052); US-064b (B-14) full-size JSON popup editor with the file-loaded disable-guard
  (R-TUI-053). REQUIREMENTS §34.
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
RC-1, C-1..C-26 (canonical record: `project_devflow_control_lineage.md`). **C-26 (touched-symbol
reverse census — generalizes C-14 + C-24) ENCODED 2026-07-12 (batch-37).** **batch-38 proposes
C-CAND-A (primary): the per-increment frozen-file guard must run BOTH `test_engine_unchanged` (SOURCE
freeze) AND `test_tc032`/`test_tc031` (engine TEST-file freeze) — origin batch-38 F-1, a stray AT in
frozen `test_tui_a2l.py` passed the increment gate because only the source-freeze guard ran; and
C-CAND-B (secondary): a Phase-1 shared-contract convergence step (issue codes / producer sink / AT
targets reconciled across §4/intake/PLAN/01b before the Phase-2 gate) — origin F-2.** Both await
per-control operator approval before entering the lineage. Standing: two-layer AT/TC + dual
traceability; inline-paste-at-gates; writer-census sweeps (C-14 / C-15.1 / C-26); dev-flow
control-encode approval (always ask before editing `~/.claude/commands/`).

---

## CLOSURE PLAN — operator-approved 2026-07-13 (finish open work BEFORE the Flow Builder)

Everything B-01..B-24 shipped; batch-38 snapshot regen DONE (PR #71). Remaining = hygiene + small
polish + one spike, grouped into 3 small themed batches, then the Flow Builder (multi-batch).

- **Batch 39 — "Untrusted-text hardening" (`/fast-dev-flow`) — DONE** ([PR #72](https://github.com/jav201/s19_app/pull/72) `fbd8aaa`): ① native paste **64 KiB cap** on all **5** stock TextAreas (pre-pass expanded 3→5) via `CappedTextArea`; ② **S-F7** escape `linkage_symbol` at report render sink `report_service:977` (was mis-specced :625); ③ **P-3** `markup=False` on `#status_text` + 3 notify sites + docstring fix. Pre-code+final security PASS.
- **Batch 40 — "Small UX fixes" (`/fast-dev-flow`) — DONE** ([PR #73](https://github.com/jav201/s19_app/pull/73) `0954826`): ④ undo/redo reset `last_check_result` + refresh Checks panel; ⑤ `ctrl+z`/`ctrl+y` bindings (A-01 guard preserved); ⑦ coverage `.6f`→`.2f`. (⑥ A2L-symbol region names + per-cell tooltips R-TUI-041 R-3 → **its own future batch**, operator 2026-07-13.)
- **Batch 41 — "Repo & test hygiene" (`/fast-dev-flow`) — DONE 2026-07-13:** ⑧ `_canonical_report_bytes`
  consolidated onto `conftest.canonical_report_bytes` (2 local copies deleted; 3 importers); ⑨
  `object.__setattr__` bypass retired in 2 files (`source_name=` kwarg — field already declared, zero
  production change); ⑩ **P-2** 7 of 8 ruff hits cleared (frozen `a2l.py:926` F841 = documented carry);
  ⑤ `Escape`→cancel binding on `ChangeSetJsonScreen` (RED-first AT); ⑥ vestigial `ENTROPY_STRIP_MAX_CELLS`
  removed (live `ENTROPY_MAX_ROWS` preserved). Gate **1394 passed / 0 failed / 3 xfailed** (+1 test), 0
  frozen diffs, C-27 dual-guard ×2, C-26 census clean, `security_required: false`. **⑪ P-1 DEFERRED**
  (no concrete defect — re-logged below). 12 code files, net −44 lines.
- **Spike ⑫ — DONE (batch-42, 2026-07-13):** full-suite TUI global-state flake root-caused via `/diagnose` +
  FIXED. Root cause: `workspace.py::setup_logging` attached a `RotatingFileHandler` to the process-global
  `s19tui` logger on every `S19TuiApp.__init__`; the per-path dedup guard never matched across tests (fresh
  `tmp_path` each) → handlers accumulated 1:1 with app constructions, never closed → O(N) log fan-out →
  intermittent `pilot`/`WaitForScreenTimeout` failures ("different unrelated test fails each run; passes in
  isolation"). Fix bounds the handler set to 1 per process (batch-42 fast-flow, self-merged). **Retires the
  standing per-batch control-run tax (C-CANDIDATE-C).**

> **Tracking rule (operator, 2026-07-13):** ALL code changes go through **at least `/fast-dev-flow`**
> (tracked: spec + branch + PR + tests). Do NOT do trivial/hygiene items as untracked `direct` edits —
> consolidate them into a fast-dev-flow batch. This supersedes the earlier "mostly direct" framing for
> batch 41 and any "fold opportunistically / direct" note elsewhere in this backlog.
- **Then → Flow Builder** (batches 42+, roadmap above).

**Accepted, no action:** batch-38 Inc-5 F1 (cross-entry collision caught at doc gate, by-design);
batch-37 ~9 LOW carries (groom only if they recur). **C-CAND-B** (Phase-1 contract convergence) left
proposed-only (operator chose C-CAND-A/C-27 only, 2026-07-13).
