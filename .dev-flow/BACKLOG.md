# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> **THE single canonical open-work queue.** Reconciled at every batch close (`/dev-flow` Phase 6 / `/fast-dev-flow` Phase C — mandatory close step, 2026-07-20). Any other list (memory `LIVE BACKLOG`, a postmortem) POINTS here, never replaces it.
>
> **`origin/main` tip = `69a2a49`** (batch-55 P-1b + re-freeze #104/#105 · memmap fix #106 · unload feature #107 · snapshot regen #108). **Last refresh: 2026-07-20 (post-#108).**
>
> **RC-1 every batch:** `git fetch`; assert merge-base == `origin/main` tip; cut a fresh branch off it; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS** (needs an explicit operator unfreeze, re-frozen post-merge PR-B): `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — AND the frozen TEST files (`_ENGINE_TEST_FILES`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix. **Standing authorization is NEVER carried across batches — ask at every kickoff** (`feedback_standing_auth_per_batch`). **All changes go through ≥ `/fast-dev-flow`** (`feedback_all_changes_tracked_min_fast_dev_flow`).

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct}

---

## OPEN QUEUE

### 🔺 TOP — active / parked
- **batch-56 — alignment-aware A2L padding sizing** (P-1b follow-up). `/dev-flow`. **Phase-1 DONE, PARKED 2026-07-20** (branch `claude/a2l-alignment-aware-b56`, WIP `741e86e`; autonomous+self-merge+a2l-unfreeze granted at kickoff). batch-55 force-Nones any summable CURVE/MAP layout carrying an `ALIGNMENT_*` (2-token padding) directive (safe honest-grey); batch-56 = a cumulative-offset padding walk in `_record_layout_full_span` so alignment-bearing layouts SIZE CORRECTLY. Architect pinned **R-A** (padding only when `ALIGNMENT_*` declared in the RECORD_LAYOUT body → packed default preserves batch-55 oracles 25/51/12) · **R-B** per-datatype `_DATATYPE_ALIGNMENT_DIRECTIVE` · **R-C = NO trailing record pad**. **⚠ AWAITING OPERATOR: RISK-1** — MOD_COMMON module-wide alignment is UNDER-MODELLED (layout-local only; a real ECU aligned via MOD_COMMON sizes packed). Architect recommends ship-layout-local + defer MOD_COMMON to a follow-up. Needs a non-demo alignment oracle fixture. Seed: `.dev-flow/2026-07-20-batch-55/` §6.5 A4 + code-review F1.

### P1 — open features
- **Issues Report v2 — filter (name/type) + sort.** PARKED — operator never picked a tier in the v2 prototype verdict. Data (`symbol`/`code`/`severity`) already on each row; only a 3-way severity filter today. `app.py:6564`, `issues_view.py:173`. *(B1 PgUp/PgDn no-op ✅ FIXED batch-49 #94.)*
- **Universal paste — paste into ALL text boxes.** PARTIAL. A2B-diff + file-load paths are paste-enabled (`OsClipboardInput`); search/goto/filter/name/save are stock `Input`. Extend the widget. `os_clipboard_input.py`, `command_bar.py`.
- **CRC Algorithm Designer** — **batch-57 (headless keel) DONE 2026-07-20** (PR pending; commits `1341fd3`+`063bea5` on `claude/crc-algorithm-designer-8f82ae`; autonomous+self-merge). Shipped ADDITIVELY (0 frozen diffs, shipped `crc.py` untouched): `crc_kernel.py` (width-general 8-64 engine + `crc_lut` LUT fast-path E7 + 7-preset catalogue) + `crc_designer_model.py` (`CrcTemplate`/`CrcJob`/`CrcTarget`; multi-range coverage intra×join; `gap_conflict`+`evaluate_target` gap-safety E8; parse/emit/read collect-don't-abort). 45 tests; code-review 1 HIGH (F1 parse_job crash) FIXED. Design in `docs/crc-algorithm-designer/01-requirements.md` + `prototypes/crc_designer.*`.
  - **→ batch-58 (the VIEW + carries):** the Variant B TUI screen (form + live KAT verdict + coverage strip + Load/Save + load/check/save flow strip — design/prototypes DONE); **E6** legacy `crc_config` up-converter; **`emit_job`** whole-job serializer; wire the width-general kernel into the shipped `crc.py` operation; `check==compute("123456789")` enforce-on-save in the view.

### P2 — A2L discoverability follow-ups (core '?' help SHIPPED batch-49 #95)
- Settings-surfacing · footer-truncation · CRC-modal-depth · only 14 of 30 A2L fields shown. In-app hints / onboarding pass.

### P3 — carries / hygiene (fold opportunistically into a themed fast-flow)
- **P-3 (A2L)** — reason-string precision on the address branch. BLOCKED by frozen `tc032` (needs the unfreeze). `validate_a2l_tags`.
- **report_service:1091** — raw `check.source_path` heading; sanitize/relabel (batch-39 carry).
- **P-1** — 1-based index convention for the axis-count / inline-axis surface (DEFERRED; no concrete defect).
- **Unload cosmetic** — a MAC-only state (after unloading the S19 spine) keeps the S19 `path` for the window title; the Loaded panel labels correctly from `mac_path`. Re-title on unload. (#107 follow-up.)
- **Throwaway prototype cleanup** — `prototypes/unload_state.*` (logic absorbed into the shipped unload feature). `prototypes/screen_upgrades.*` KEPT by operator decision 2026-07-17 (Batch A/B design source).

### Needs-repro
- **A2L address "two extra chars"** — the >32-bit case is handled (batch-38 `A2L_ADDRESS_EXCEEDS_32BIT` warning). If a DIFFERENT case, needs a concrete repro (symbol + value). `app.py`, `a2l.py`.

### Flow Builder (rail-8, multi-batch — the parallel FB session's stream)
- **batch-51 SHIPPED** ([#101](https://github.com/jav201/s19_app/pull/101) `640de1b`): CHECK block + LOAD integrity-notices + `completed-with-issues` amber status + "Pipeline Ledger" render. NEW global control **C-36**.
- **Next: batch-52 = CRC block** (template lib + address-space growth; the **CRC-into-loop seam** — split `write_crc_image` into a pure inject stage + shared write, ADR §7) + the before/after twin ribbon (§6.5 AMD-1) → **batch-53 = `flow.json` persistence** (untrusted-loader security — replicate the manifest guards) → **multi-image scope + report fusion**. ADR: `.fast-dev-flow/ADR-flow-builder-tracer.md`.

### Deferred control-encodes (need their own AskUserQuestion before touching `~/.claude/commands/`)
- **1c — code↔requirement REVERSE-index control** (deferred batch-48): `resource → {claimants}`, flag ≥2 claimants in one scope, WITH a CI staleness guard (every `R-*`/`LLR-*` code tag names a live requirement). Half-built: 25 back-refs in `screens_directionb.py`; `REQUIREMENTS.md` maps `R-*`→files. Detail: `project_devflow_control_lineage`.
- **1d — markup-sink SWEEP rule** (un-encoded candidate): when a markup sink is found, sweep EVERY site of that widget class (4 surfaces, 3 separate discoveries: batch-33 `screens.py` → batch-43 tooltips → batch-48 DataTable + Select). Assert `plain` verbatim AND `spans == []`.

---

## DONE (recent — do NOT redo; verify-shipped if in doubt)
- **post-55 fast-flows (2026-07-20):** **memmap "No file loaded" bug** ([#106](https://github.com/jav201/s19_app/pull/106)) — S19+MAC coexistence merge dropped `entropy_windows`+`source_s0_header`; carried forward + split the empty message. **Unload feature** ([#107](https://github.com/jav201/s19_app/pull/107) `ae4aef2` + regen [#108]) — Workspace `LoadedArtifactsPanel` + inverse-merge `_unload_*` (Variant B).
- **batch-55** (P-1b inline-axis length summer) — [#104](https://github.com/jav201/s19_app/pull/104) `a9608c8` + re-freeze [#105]. CURVE/MAP inline STD_AXIS/FIX_AXIS → correct byte length; external stays None (full-span-or-None). Also 🅰 missing-length (#92) · P-1 scalar length (#93) · P-2 re-freeze (#100).
- **🅱 report diff vs patched S19** — VERIFIED-WORKING 2026-07-18 (no code change; `compose_before_after_report` re-reads both sides fresh). Do NOT rebuild.
- **batch-54** (multi-line A2L header parsing — P-1b prerequisite) #102/#103. **batch-50** (a2l.py F841 + re-freeze) #99/#100; NEW C-35. **batch-49** (Issues MID + CHECKS rail #94/#95) #97; NEW C-33/C-34. **batch-48** (Patch Editor BIG) `fbafb82`; C-31/C-32. **batch-47** (screen-upgrades Batch A: insight layer + navy/pastel) `768f70a`; C-30. **batch-45** (Memory-Map entropy Band-Bands + single-click map-nav) #81/#82; R-TUI-060/061/062.
- **Field-audit (2026-07-14) items SHIPPED:** N1 entropy-shaded map (b45) · N3 single-click map-nav (b45) · B1 Issues paging (b49 #94) · B2/U8 patch 3-window (b47/48) · discoverability '?' help (b49 #95).
- **batches 31–46** (B-01..B-24 baseline + CRC groups + report filter + patch regroup + untrusted-text hardening + TUI-flake root-cause + Flow Builder tracer). Full lineage: `.dev-flow/project_baseline_backlog_2026-07-09.md` + the vault batch log.

## Controls encoded — do NOT re-encode
RC-1, **C-1..C-36** (canonical: `project_devflow_control_lineage.md`). Stack-specific controls (C-13/C-13.1/C-22/C-23/C-28/C-29/C-30) live in `docs/engineering-rules.md`; global flows stay project-agnostic (`feedback_devflow_general_flows_project_agnostic`). **NEW 2026-07-20: backlog carry-over is a mandatory close step in both flows** (`feedback_backlog_carryover_enforced`).
