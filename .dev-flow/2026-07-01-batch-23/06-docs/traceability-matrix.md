# Traceability Matrix — s19_app — Batch 2026-07-01-batch-23

> Two chains (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> **Batch scope:** feature #8 (patch-editor overhaul) **final slice** — US-028, the inline variant dropdown in the patch editor's Variant pane. Closes feature #8 entirely (US-026/027/029 batch-21 · US-030/031 batch-22 · US-028 batch-23). All node names below are the **V-5 reconciled** real on-disk pytest node ids (04-validation.md §1: 10 provisional ids → 11 collected nodes, 1:1, 0 orphans). Frozen-engine diff = 0 (verified Inc1 + post-ff + validator).
>
> **Executed result carried by every row:** new file `tests/test_tui_patch_variant.py` **11/11 PASSED** (validator's own run 2026-07-02, `11 passed in 29.63s`); full non-slow suite on final base `f5f8111`: **971 passed / 30 skipped / 3 xfailed / 0 FAILED** (448 s).
>
> *File:line citations are re-verified against the current tree at docs time; batch artifacts cite pre-fold positions for some symbols (e.g. `_handle_select_variant` at `app.py:2997` in 01-requirements → now `app.py:3134` after the Inc1 additions above it). Symbols, not line numbers, are the stable anchors.*

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC (tests/test_tui_patch_variant.py) | File:line | Result | Notes |
|----|-----|-----|--------------------------------------|-----------|--------|-------|
| US-028 | HLR-035 | LLR-035.1 (Select composed in Variant pane, always present, `disabled=True` at construction) | `::test_tc_035_1_compose_presence` | `s19_app/tui/screens_directionb.py:804` (`id="patch_variant_select"`) / `:809` (`id="patch_variant_row"`) | **PASSED** | Exactly 1 widget with and without a project; no `patch_*` id renamed/removed |
| US-028 | HLR-035 | LLR-035.2 (variant group ABOVE `#patch_execute_row`; Select first row visible at scroll 0 — C-13 geometry) | `::test_tc_035_2_variant_group_above_execute_row` | `s19_app/tui/styles.tcss:592` (`#patch_variant_row, #patch_execute_row { height: auto }`) + compose order in `screens_directionb.py` | **PASSED** (80×24 + 120×30) | @80×24 `region.y` ordering carried by the structural compose-order assert where the execute row is unmapped — amendment A-6.5-3 (footnote §7) |
| US-028 | HLR-035 | LLR-035.3 (options refresh + active preselection; N<2 → blank, no preselection; both F-3 triggers) | `::test_tc_035_3_options_order_preselection_and_triggers` | `s19_app/tui/app.py:2278` (`_refresh_patch_variant_select`) + `screens_directionb.py:614` (`set_variants`, `set_options` strictly before value assignment — F-4) | **PASSED** | Exact sequence equality on a 3-variant set; variant-append trigger while shown; blank-sentinel = `Select.NULL` (A-6.5-1) |
| US-028 | HLR-035 | LLR-035.4 (`Select.Changed` → `_handle_select_variant` wholesale reuse; NULL/same-as-active short-circuits) | `::test_tc_035_4_routing_guards` | `screens_directionb.py:538` (`VariantSelected`) / `:1027` (dispatch branch) → `app.py:2366` (handler) → `app.py:3134` (`_handle_select_variant`, unchanged) | **PASSED** | Non-active pick → exactly 1 activation; blank / echo / unknown-id / missing-file → 0 activations, guard status lines |
| US-028 | HLR-035 | LLR-035.5 (disabled placeholder for no-project / N<2 — DoR Q1) | `::test_tc_035_5_disabled_state_table` | `screens_directionb.py:614-664` (`disabled = len(options) < 2` inside `set_variants`) | **PASSED** | Pane geometry stable across enabled/disabled; state intact leg also in AT-035c(ii) |
| US-028 | HLR-035 | LLR-035.6 (persist-on-save only; no new disk-write surface — DoR Q2) | `::test_tc_035_6_switch_writes_nothing_to_disk` | `s19_app/tui/services/manifest_writer.py:319` (`"active_variant": variant_set.active_id` — the sole, pre-existing write site) | **PASSED** | Full byte-snapshot of the project dir equal before/after switch; inspection re-run by validator: 0 new `manifest_writer` call sites vs `origin/main` |
| US-028 | HLR-035 | LLR-035.7 (switch-during-load integrity — security SEC-F2; suppress-while-loading) | `::test_tc_035_7_rapid_double_pick_stays_consistent` | `app.py:2329` (`_variant_load_in_flight`) | **PASSED** | Rapid A→B pick: label == rendered content, 0 files created (phantom-copy guard), dropdown value self-heals at apply-finalize |

All 7 LLR rows: numeric thresholds **audited in-assert** by the validator (04-validation.md §2 — thresholds read from the test code, not from the increment doc).

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface, plus its counterfactual evidence. A story with a complete functional chain but no behavioral row is INCOMPLETE.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Counterfactual evidence | Result |
|----|----------------------------|-----------------|--------------------------------|-------------------------|--------|
| US-028 | `::test_at035a_dropdown_switch_updates_label_and_image` (AT-035a, **GATE, C-10**) | Patch editor Variant-pane dropdown → threaded load pipeline → command bar + hex view (workspace hop per Phase-2 R-1) | Non-default pick `a`→`b`: rendered label `proj:b (2/2)` AND hex view shows b's probe bytes, a's gone | **RED captured**: routing reverted → `AssertionError ... got 'Project: proj:a (1/2)'` at `tests/test_tui_patch_variant.py:166`, `1 failed in 3.95s`; restored → `11 passed in 31.38s` (03-increments/increment-1.md §4, node binding re-verified at Phase 4) | **PASSED** |
| US-028 | `::test_at035b_switch_persists_on_save_and_load_consumes` (AT-035b, **GATE, C-12** output-then-consume) | Shipped project-save flow → handler-written `project.json` on disk → fresh-app unmodified load path | Raw `json.loads` of the handler-written manifest yields `active_variant == "b"`; fresh `S19TuiApp` load of `proj2` renders `proj2:b (2/2)` | Design-level (04-validation §1): reverted route → manifest carries `"a"` → RED; consume leg discriminating because `a` sorts first. Saves into pre-seeded sibling `proj2` — amendment A-6.5-2 (footnote §7) | **PASSED** |
| US-028 | `::test_at035c_no_project_disabled_placeholder` + `::test_at035c_single_variant_disabled_placeholder` (AT-035c, GATE — 2 nodes as planned in 01b §2) | Patch editor Variant pane | (i) no project: dropdown present, disabled, blank placeholder, screen round-trip survives; (ii) N==1: same disabled state AND loaded state intact (label + variant-a hex unchanged) | Design-level: pre-implementation the widget id does not resolve → `query_one` raises → RED (04-validation §1) | **PASSED** (both nodes) |

Gate asserts are fully black-box: rendered text, widget public state, on-disk bytes — zero private-attribute reads in any AT assert path (04-validation §3). Pre-existing direct-consume test `tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant` kept as **guard only, never gate** (it stays green under a reverted route — zero counterfactual power).

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 1 (US-028) — covered 1/1 (100%) |
| Total HLR | 1 (HLR-035) — implemented 1/1 (100%) |
| Total LLR | 7 (LLR-035.1–.7; .7 added at Phase-2 from security SEC-F2) — implemented 7/7 (100%) |
| Functional test cases (TC) | 7 (TC-035.1–.7), all PASSED |
| Acceptance tests (AT) | 3 ids / 4 nodes (AT-035c = 2 sub-case nodes), all PASSED |
| Total new nodes | **11** (ledger 991 → 1002, +11 / −0, reconciled) |
| Full non-slow suite (final base `f5f8111`) | **971 passed / 30 skipped / 3 xfailed / 0 FAILED** (448 s); pre-ff run 969/0-fail |
| QC-3 boundary/negative catalog | 7/7 rows covered, 0 gaps (+ beyond-catalog: ghost id, N==3 ordering, duplicate stems) |
| Bidirectional reachability matrix | 0 gaps, both directions (04-validation §4) |
| Engine-frozen set | 0 diffs vs `origin/main` |
| fail / pending | 0 / 0 |

---

## 3. Detected gaps

> **ZERO gaps**, both chains. Every LLR has a passing TC with its numeric threshold audited in-assert; every AC of US-028 has a passing black-box AT with named counterfactual evidence; V-5 bound all 10 provisional ids 1:1 to the 11 collected nodes with no orphans.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | (none) | — |

**Tracked follow-ons (not gaps):** batch-22's two `patch-comfortable-*` SVG snapshot cells now also carry the variant-row tree change and remain `xfail(strict=False)` until baselines regenerate in the canonical CI env; SEC-F1 symlink dead-option parity hardening stays optional BACKLOG (pre-existing in the modal too).

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-035 / US-028 | Inline variant dropdown in the Variant pane; switch through the existing `_handle_select_variant` pipeline; persist-on-save only |
| new | LLR-035.7 | Switch-during-load integrity requirement, born from Phase-2 security finding SEC-F2 (suppress-while-loading mechanism) |
| new | `R-PATCH-VARIANT-SELECT-001` | REQUIREMENTS.md §29 (`REQUIREMENTS.md:2906`), status `Automated` |
| carried | batch-21/22 slices | US-026/027/029 + US-030/031 unchanged; the dropdown lands inside batch-22's `#patch_pane_variant` grid cell |
| closed | feature #8 | US-028 was the last open story — patch-editor overhaul complete |
| mid-batch | PRs #37/#38 | Select.NULL sentinel fixes to shipped US-026/AbDiff code (spawned by this batch's D-1 finding), merged mid-batch; 2 base moves absorbed (c6f75aa→a4ab8ba→f5f8111), RC-1 re-held, post-ff integration 138/138 |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-028** → HLR-035 → LLR-035.1–.7 → TC-035.1–.7 (functional) + AT-035a / AT-035b / AT-035c×2 (behavioral)

### 5.2 By code file
- `s19_app/tui/screens_directionb.py` → LLR-035.1 (compose :804/:809), LLR-035.2 (compose order), LLR-035.3 (`set_variants` :614), LLR-035.4 (`VariantSelected` :538, dispatch :1027), LLR-035.5 (disabled logic in `set_variants`)
- `s19_app/tui/app.py` → LLR-035.3 (`_refresh_patch_variant_select` :2278, `update_project_labels` tail :7769), LLR-035.4 (handler :2366 → `_handle_select_variant` :3134), LLR-035.7 (`_variant_load_in_flight` :2329)
- `s19_app/tui/styles.tcss` → LLR-035.2 (`height: auto` rule :592)
- `s19_app/tui/services/manifest_writer.py` → LLR-035.6 (sole `active_variant` write site :319 — pre-existing, no new call sites)

### 5.3 Boundary / safety nodes
- **AT-035b** is the **C-12 persistence gate** — the only test in the repo that goes RED on a reverted dropdown route (05b-postmortem-qa.md §2).
- **TC-035.6** is the **Q2 no-write invariant** — full byte-snapshot equality of the project directory across a switch.
- **TC-035.7** is the **SEC-F2 race safety node** — label/content coherence + 0 phantom files under a rapid double pick.

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-01-batch-23 |
| Closing date | 2026-07-02 |
| Total iterations (phases 0–4) | 5 (1 per phase — no phase re-ran) |
| Validation passed | **yes — PASS** per §5.3 batch acceptance criteria (04-validation.md §7) |
| Phase-2 findings | 1 BLOCKER + **5 MAJOR** (count corrected 4→5 at Phase-5 audit) + 9 MINOR — all folded body-first pre-gate |
| Findings total / caught-at-P2 | 21 / 15 (**71%**; 83% excluding execute-to-discover deviations) |
| Control decision (Phase 5) | **C-15 encoded** (symbol-identity check, from candidate CC-1); CC-2 recorded as operator-process note; CC-3 watch continues |
| Synced to Obsidian | pending post-merge (`/dev-flow-sync`) |

---

## 7. Footnotes — §6.5 requirement amendments (01-requirements.md §6.5) and REQUIREMENTS.md cross-reference

All three amendments were implementation-surfaced (Phase 3), flagged loudly with Before/After records, independently re-verified, and folded post-PASS. Each carries "Deleted: none. New: none." — spec corrections, not scope changes.

- **A-6.5-1 (D-1) — blank-sentinel symbol correction.** `Select.BLANK` → `Select.NULL` spec-wide (8 replacements). On installed textual 8.2.5, `Select.BLANK` resolves to the inherited `Widget.BLANK` bool (`False`) and can never match a `NoSelection` value. Contract (blank pick fires no activation) unchanged. Side effect: the same latent bug in shipped US-026/AbDiff code was fixed via operator PRs #37/#38. Root cause of control **C-15**.
- **A-6.5-2 (D-2) — AT-035b drive amended to a pre-seeded sibling project (`proj2`).** Re-saving the loaded project would hit `copy_into_workarea` dedup (`b_1.s19`) and fail a *correct* implementation. All C-12 properties preserved and re-verified by code-reviewer.
- **A-6.5-3 (D-3) — TC-035.2 geometry assert conditional on compositor mapping.** @80×24 a fully-scrolled-out execute row reports a NULL region; the ordering there is carried by the structural compose-order assert. The LLR's own threshold (Select first row visible at scroll 0) is asserted at both regimes unchanged.

**REQUIREMENTS.md cross-reference:** §29 "Patch-editor inline variant dropdown (batch-23)" (`REQUIREMENTS.md:2906`) — requirement id `R-PATCH-VARIANT-SELECT-001`, status **Automated**, mapped to `tests/test_tui_patch_variant.py` (this matrix's 11 nodes).
