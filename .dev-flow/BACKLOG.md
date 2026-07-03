# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for open feature work. `origin/main` tip = `9d2123c` (batch-23 PR #39 merged — feature #8 COMPLETE); **batch-24 (#12 (a)+(c): reconcile both directions + before/after report) pending commit/PR.** **RC-1 every batch open:** `git fetch`; assert merge-base == origin/main tip; cut a fresh branch off origin/main; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS:** core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py (TUI-side write logic → `tui/changes/io.py`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix; commits/PRs only on operator approval. **Last refresh: 2026-07-03 (batch-24 close).**

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

---

## OPEN QUEUE

### #12(b) — Entropy / data-classification viewer (the remaining #12 piece)
- **Flow:** `/dev-flow` with a batch-22-style Phase-0 SPIKE (algorithm: window size / estimator / band thresholds; ambition: entropy bands vs semantic classification; surface: report-section-first US-037 vs viewer US-036 w/ C-13 measurement; `/prototype` candidate per the UI-focus note). **Priority: P1 — NEXT.**
- Stories pre-drafted at batch-24 Phase 0 (01-requirements §2.6): US-035 (headless service — prerequisite), US-036 (viewer, HIGH geometry), US-037 (report section, cheap). Substrate verified: `LoadedFile.mem_map + ranges`; entropy computation TUI-side (engine-frozen constraint).
- **#12(a)+(c) DONE (batch-24):** US-032/033 (A2L↔issues reconcile BOTH directions + the no-MAC wipe fix LLR-037.4) + US-034 (before/after report on save-back w/ B-2 provenance guards). REQUIREMENTS §30/§31. Pending PR.

---

### SEC-F1 — Symlink parity hardening in the project-dir variant scan (batch-23 carry)
- **Flow:** `direct` micro-PR or fold opportunistically. **Priority: P3 (optional).** **Origin:** batch-23 security review (02-review SEC-F1).
- **Scope:** `validate_project_files` lists a symlinked `.s19` as a variant (dead dropdown/modal option — fails SAFELY at `copy_into_workarea`, no read of the target). Optional `item.is_symlink()` skip in the scan (`workspace.py:360-362`) for parity with US-026's change-file scan-skip. No data exposure today; UX/consistency only.

### Snapshot-baseline batch (batch-22/23 carry)
- **Flow:** own small batch or fold into the next batch touching CI. **Priority: P3.** The batch-22 patch snapshot cells (80×24/120×30) remain xfail-until-baseline; batch-23's variant row changed the pane tree, so baselines regenerate AFTER both merges, ONLY in the canonical CI env (memory: local regen drifts).

### Batch-24 carries (small, fold opportunistically)
- **I4-F1** (P3): orphan-md when the html half of the before/after pair refuses after the md wrote — theoretical branch; optional `unlink(missing_ok=True)` or diagnostic append. `before_after_service.py:346-351`.
- **Pre-existing ruff F401s** (P3): test_tui_app.py:1599 + 2 in the I3 sweep — one-token deletions, own micro-PR.
- **C1-range `_strip_ctl` extension** (P3): extend the predicate to U+0080–U+009F if the helper is touched again.
- **Recorded AT limitations** (no action): AT-037b single-shot inertness (spec-accepted); AT-038d state-level switch — RE-DERIVE if a future batch adds last-summary invalidation to the real project-switch path.

### D-3 — Declared-region report dialog: per-line skip detail + comma-in-name support (D-2 follow-on)
- **Flow:** `direct` micro-PR or fold into a batch already touching the report dialog. **Priority: P3.** **Origin:** batch-20 (D-2 shipped count-only; reviewer/postmortem deferrals).
- **Scope:** (a) line-level detail in the skip notice (currently count-only `"N region line(s) skipped"`); (b) comma-escaping so a region name containing a comma round-trips (currently skipped as malformed in the `name,start,end` line format — no safety gap, the scrub neutralizes injection). UX polish only; fold opportunistically.

### UI/UX focus pass — OPTIONAL / exploratory (not scheduled)
- **Flow:** `/prototype` (explore) → `/dev-flow` per concrete story if it earns a batch. **Priority: P3 (optional).** **Origin:** 2026-06-30 operator note — UI/UX has been under-focused; most batches were behavior/logic, geometry touched only reactively (C-13).
- **Scope (loose):** a deliberate pass on the TUI's look/layout/affordance quality rather than one feature — e.g. exploring the patch-editor 4-pane split (US-030) via `/prototype` before formalizing, reviewing cross-screen layout/spacing/legibility at 80/120 cols, and any operator-clarity wins (the batch-21 US-029 Checks-clarity was one such). Not a spec yet — a held intent to give UI its own attention when priorities allow.
- **Note:** design-sync / claude.ai/design does NOT apply (web/React-only; s19_app is a Textual TUI). TUI design tooling = `textual run --dev` live `.tcss` + SVG snapshots + `/prototype`.

## DONE (batches 14–22, merged + synced) — do NOT redo, verify-shipped if in doubt
- US-015 (16/32 S19 record width + S0 header) — batch-14, PR #22 (`b734c19`)
- US-016 (A↔B compare load-failure honesty) — batch-15, PR #20 (`R-DIFF-LOADFAIL-001`)
- US-017 / GAP #2 (manifest per-variant assignments) — batch-16, PR #23 (`dd46113`)
- US-018 (#9 workspace one-line hex) — batch-17, PR #29
- US-019 (CRC selectable record width) — batch-17, PR #29
- US-020a/b (#10 issues hex pane + Related column) — batch-17, PR #29
- US-022 / US-023 (#11 classification legend — report section + in-app modal) — batch-18, PR #30 (`8654df5`)
- US-020c / US-020d (#10 issues-report addendum + issue enrichment + region persistence) — batch-19 (REQUIREMENTS §25; 908→926). Persistence = serialization layer only; UI auto-wire split to D-1.
- **D-1 / D-2 (declared-region UI round-trip + skip notice) — batch-20 (REQUIREMENTS §26; 958→974, 0 fail, frozen 0).** D-1 = save persists regions to project.json + load pre-fills the dialog (round-trip, C-12 gate AT-028a); D-2 = count-only skip notify. Closes the declared-region feature line. Pending PR/merge. Residual UX polish → D-3 (P3).
- **#8 slice-1 (patch-editor change-file management + Checks clarity) — batch-21, PR #34 merged (§27; 974→985).** US-027 patches/ folder + US-026 dropdown (C-12 gate + F1 guard) + US-029 Checks Label.
- **#8 slice-2 (patch-editor 4-pane 2×2 layout) — batch-22, PR #35 merged `0802acd` (REQUIREMENTS §28; 985→991, 0 fail, frozen 0).** US-030 = 2×2 grid reparent (measured 70/92). US-031 = snapshot cells CI-locked. Also merged mid-batch: hooks-task PR #33; hook path fix PR #36 (`c6f75aa`).
- **#8 US-028 / FEATURE #8 CLOSED (inline variant dropdown) — batch-23 (REQUIREMENTS §29; 991→1002, 0 fail, frozen 0; full suite 971/0 on `f5f8111`).** `Select#patch_variant_select` in the 2×2 Variant pane → wholesale reuse of `_handle_select_variant`; Q1 disabled+placeholder; Q2 persist-on-save (C-12 AT over handler-written project.json); NEW LLR-035.7 suppress-while-loading race guard; C-13 measured top-of-pane placement. 3 §6.5 amendments (headline: `Select.BLANK`→`Select.NULL` — the 8.2.5 sentinel trap, also fixed in shipped code via PRs #37/#38 merged mid-batch `a4ab8ba`/`f5f8111`). **Control C-15 (symbol-identity + sweep-back) ENCODED 2026-07-02.** #8 = US-026..031 ALL DONE across b21/b22/b23. Pending commit/PR.
- Closed process/AT carries: C-9 (compare hex-pane AT), CRC-width lock-AT, ruff F401/F402, batch-07 report seam, batch-01 evidence packs, C-6 (TC-id retire), obsidian flips.

## Controls encoded (global `~/.claude` / templates) — do NOT re-encode
RC-1 (Phase-0 base-currency gate), C-1 (dev-flow-sync reject-check), C-10/C-11 (AT-authoring), C-12 (output-then-consume AT), **C-13 (geometry-budget)** + **C-13.1 (deficit-matched fallback, batch-18)**, **C-14 (location-move census sweep — e2e/save-observers, batch-21)**, **C-15 (symbol-identity probe + post-fold sweep-back, batch-23)** + **C-15.1 (writer-census probe, batch-24)**, **state-lifetime provenance rule (req-template, batch-24)**, **interruption protocol + golden double-proof (dev-flow.md, batch-24)**, QC-2 (value-discriminating RED), QC-3 (boundary-catalog pre-Phase-3), **inline-paste-at-gates protocol (batch-20, dev-flow.md point 5)**, **repo-hygiene close-checklist line (batch-23, dev-flow-sync.md step 3)**. Two-layer AT/TC + dual traceability standing. dev-flow control-encode approval protocol (always ask before editing `~/.claude/commands/`).

---

## Proposed sequence (pending operator approval — do NOT derive yet)
1. **#8 US-028 — inline variant dropdown** — `/dev-flow` or `/fast-dev-flow` (small, independent; lands in the 2×2 Variant pane). **Next (P1)** — closes #8.
2. **#12** — `/dev-flow`, design proposal first (greenfield entropy viewer + before/after + reconcile). P2.
3. **D-3** — declared-region per-line skip detail + comma-in-name (P3, fold opportunistically).
4. **UI/UX focus pass** — optional/exploratory (P3, not scheduled).

Operator confirms / reorders.
