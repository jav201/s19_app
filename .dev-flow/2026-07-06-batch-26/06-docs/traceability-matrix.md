# Traceability Matrix — s19_app — Batch 2026-07-06-batch-26

> **Audience:** dev-flow reviewer / future maintainer. **Purpose:** prove every requirement node is covered end-to-end (no orphan, no gap).
>
> Two chains (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> **Batch scope:** feature **#12(b)** — entropy / data-classification viewer, closing feature #12 (slice (a)+(c) shipped batch-24). Three stories: **US-035** headless entropy service · **US-037** per-variant report section · **US-036** viewer modal. R1 DoR resolved **bands-only** (no semantic code/data heuristic). All node names below are the **V-5 reconciled** real on-disk pytest node ids from `04-validation.md` §2/§3 (60 collected batch nodes, 0 orphans; 2 snapshot cells xfail-until-baseline). Frozen-engine set: **0-diff** (`git diff --name-only origin/main` over the 7 frozen paths → empty; guard suites `101 passed`).
>
> **Executed results carried by every row (04-validation.md §5, local Python 3.14.4 / textual 8.2.8 pinned):** batch modules **60 passed** in 29.70s; frozen guards **101 passed**; full non-slow suite **1048 passed / 0 non-snapshot failed / 2 skipped / 5 xfailed** (reproduced identically on a 2nd run); slow set **21 passed**. Purity probe `grep -E "import textual|from textual" entropy_service.py` → **0 hits**. Authoritative merge gate = the CI matrix (Python 3.11); the local run is confirmatory.
>
> *File:line citations verified against the current worktree tree at docs time (2026-07-06). Symbols, not line numbers, are the stable anchors.*

---

## 1. Master table — functional chain (white-box)

Test files: `tests/test_entropy_service.py` (=`entropy`), `tests/test_report_service.py` (=`report`), `tests/test_tui_entropy_viewer.py` (=`viewer`), `tests/test_tui_snapshot.py` (=`snapshot`).

| US | HLR | LLR | TC node(s) (real collected id) | File:line (re-verified) | Result | Notes |
|----|-----|-----|--------------------------------|--------------------------|--------|-------|
| US-035 | HLR-035 | LLR-035.1 (named `ENTROPY_WINDOW_BYTES=256` / `ENTROPY_MIN_SAMPLES=64` / `ENTROPY_BANDS` half-open `[lo,hi)`; `8.000001` headroom sentinel) | `entropy::test_tc035_2_band_cutoff_sides_direct_injection` · `entropy::test_tc035_5_constants_pinned` | `entropy_service.py:29/33/41` (constants), `:92` (`classify_band`) | **PASSED** | Direct float injection at 1.0/5.0/7.2 pins the `[lo,hi)` side; constants tuple pinned against silent drift |
| US-035 | HLR-035 | LLR-035.2 (per-range 256B walk, gap-safe — never straddles the unmapped gap) | `entropy::test_tc035_1_multi_range_window_count_and_containment` · `entropy::test_stress_guard_large_s19_window_count` | `entropy_service.py:132` (`_derive_ranges`), `:258-274` (walk in `compute_entropy`) | **PASSED** | Every window `[start,end)` ⊆ exactly one range; count = Σ ceil(len/256); `large_s19` stress guard |
| US-035 | HLR-035 | LLR-035.3 (Shannon `H = -Σ p·log2(p)` over the 256-bin histogram; 0.0 for constant fill) | `entropy::test_tc035_6_estimator_reference_values` | `entropy_service.py:173` (`_window_entropy`) | **PASSED** | Reference H==1.0/2.0/5.0 to `< 1e-9`; occupied bins only; bounded 0.0–8.0 |
| US-035 | HLR-035 | LLR-035.4 (low-sample tag: `sample_count < 64` → `low_confidence=True`, never drop) | `entropy::test_tc035_3_low_sample_tag_boundary` | `entropy_service.py:271` (`low_confidence=sample_count < ENTROPY_MIN_SAMPLES`) | **PASSED** | Boundary 63/64/65; ≥64 → False; no window omitted for being small (§2.6 D-b) |
| US-035 | HLR-035 | LLR-035.5 (`EntropyWindow` frozen dataclass + `compute_entropy(mem_map) -> list[EntropyWindow]`; headless purity) | `entropy::test_tc035_4_degenerate_empty_and_single_byte` · `entropy::test_tc035_7_service_purity_no_textual_import` · `entropy::test_llr035_5_entropy_window_frozen_shape` | `entropy_service.py:49` (`EntropyWindow`), `:214` (`compute_entropy`) | **PASSED** | `{}`→`[]`; six-field frozen record ascending by start; **purity probe 0 `textual` hits** (mirrors `before_after_service.py`) |
| US-037 | HLR-037 | LLR-037.1 (`ReportOptions.include_entropy: bool = True` + `__post_init__` reject-non-bool) | `report::test_include_entropy_default_true_and_validated` · `report::test_include_entropy_false_not_emitted` | `report_service.py:199` (field), `:238-241` (guard) | **PASSED** | Default True; `include_entropy="x"` → ValueError (reject-not-clamp, `include_legend` precedent) |
| US-037 | HLR-037 | LLR-037.2 (`_entropy_lines(result)` Markdown band-summary builder; empty map → heading + "no data") | `report::test_entropy_lines_shape_direct_call` · `report::test_entropy_lines_empty_mem_map_no_crash` · `report::test_entropy_section_confidentiality_no_raw_bytes_or_logging` | `report_service.py:985` (`_entropy_lines`) | **PASSED** | Band **count** summary (O(bands), not O(windows) — R-2); GUARD direct-call, never the gate; confidentiality: bands/H only, no raw bytes, no new logging |
| US-037 | HLR-037 | LLR-037.3 (per-variant emission via budget-charged `emit()`, after `_hexdump_section`; `include_entropy=False` byte-identical) | `report::test_entropy_section_charged_against_budget` · `report::test_report_contains_entropy_section_on_disk` (e2e) | `report_service.py:1222-1223` (`if options.include_entropy: emit(_entropy_lines(result))`), `:1234` (`target.write_text`) | **PASSED** | Emitted through `emit()` (budget-charged), NOT a raw `lines.extend`; e2e re-reads the written file |
| US-036 | HLR-036 | LLR-036.1 (own `ENTROPY_BAND_COLOUR` map grey/green/yellow/red; **no `sev-*` reuse**; low-confidence `dim`) | `viewer::test_tc036_1_band_colour_map_and_no_sev` | `screens.py:554` (`ENTROPY_BAND_COLOUR`), `:564` (`ENTROPY_LOW_CONFIDENCE_STYLE="dim"`) | **PASSED** | Four distinct band→colour entries; grep-guard 0 `sev-*` in the band-cell path; `color_policy.py` read-only (frozen) |
| US-036 | HLR-036 | LLR-036.2 (`EntropyViewerScreen(ModalScreen[Optional[int]])` compose: strip + jump list; `.modal-dialog` box-model reuse; push-time snapshot) | `viewer::test_tc036_2_strip_cell_per_window` · `viewer::test_tc036_3_jump_rows_documented_shape` | `screens.py:574` (`EntropyViewerScreen`), `:640` (strip), `:668` (`compose`) | **PASSED** | One `█` cell per window; jump rows `0xADDR  band  H=…`; reuses `LegendScreen` `.modal-dialog`; renders push-time `mem_map` snapshot (non-goal: live-track a reloaded image) |
| US-036 | HLR-036 | LLR-036.3 (strip fits measured 48 cols @80×24 / 76 cols @120×30, no overflow) | `viewer::test_geometry_fits_80` · `viewer::test_geometry_fits_120` | `screens.py:668` (`compose`) via `.modal-dialog` box model | **PASSED** | Dialog + strip right edge within terminal at both regimes; box-model reuse holds the budget by construction (no fallback rung — §2.6 C-13 verdict) |
| US-036 | HLR-036 | LLR-036.4 (`action_show_entropy` + `e` key binding; no-image safe no-op) | `viewer::test_tc036_4_e_binding_registered` | `app.py:685` (`Binding("e", "show_entropy", "Entropy", show=True)`), `:3616` (`action_show_entropy`), `:3649` (`push_screen`) | **PASSED** | `"e" in BINDINGS` → `show_entropy`; no image → `notify` no-op, no crash (`app.py:3646-3648`). C-15 note: `"e"` is a plain key string, no `Select.BLANK`-class sentinel trap |
| US-036 | HLR-036 | LLR-036.5 (jump-list activation moves focus — dismiss-with-target → host focuses) | `viewer::test_at036b_jump_second_row_moves_focus` (AT, black-box) | `screens.py:707-713` (`on_list_view_selected` → `dismiss(target)`), `app.py:3653` (`_focus_entropy_target` → `_apply_goto`+`update_hex_view`) | **PASSED** | Modal dismisses with the address int payload (`ModalScreen[Optional[int]]`); host callback routes through the existing `_apply_goto` guard — no new focus plumbing |
| US-036 | HLR-036 | LLR-036.6 (strip/jump cost cap `ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS` + on-screen truncation indicator) | `viewer::test_tc036_5_cost_cap_and_truncation` · `viewer::test_tc036_5_truncation_fires_on_either_cap` | `screens.py:570-571` (caps = 512/512), `:661/:671` (slice), `:688-690` (`#entropy_truncated`) | **PASSED** | On `large_s19`: cells ≤ 512, rows ≤ 512; truncation fires on **either** cap (min-cap semantics, mutation-verified); never silent (mirrors `MAX_HEX_ROWS`) |

All 17 LLR rows: numeric thresholds audited in-assert by the Phase-4 validator (04-validation.md §3 — every functional-chain row binds to a passing collected node; no vacuous assert).

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test observing the outcome through the shipped surface, plus its counterfactual (RED) evidence. Surfaces: **US-035** = the public `compute_entropy(mem_map)` return (a library — its call IS the shipped surface); **US-037** = `generate_project_report` → the WRITTEN report file re-read from disk (C-12); **US-036** = Pilot-driven `EntropyViewerScreen` through the `e` key. One counterfactual — **AT-037a** — was captured as a LIVE RED (stubbed `and False` wiring → precondition passed, section-present assert failed).

| US | Acceptance test (real collected node) | Class | Shipped surface | Observed outcome / deliverable | Counterfactual (RED) evidence | Result |
|----|---------------------------------------|-------|-----------------|--------------------------------|-------------------------------|--------|
| US-035 | `entropy::test_at035a_constant_fill_band_and_zero_entropy` | **GATE** | `compute_entropy(mem_map)` return | Constant-fill run → band `constant/padding`, H==0.0 exact | ImportError by construction (module absent pre-fix) — inc-001 §4 | **PASSED** |
| US-035 | `entropy::test_at035b_permutation_band_and_max_entropy` | **GATE** | `compute_entropy` | 0..255 permutation → band `high/random`, H==8.0 exact | ImportError by construction | **PASSED** |
| US-035 | `entropy::test_at035c_mixed_two_ranges_gap_not_straddled` | **GATE** | `compute_entropy` | Mixed image: constant@0x3000 + gap + perm@0x4000 → exactly 2 windows (gap NOT straddled), correct bands + H | ImportError by construction | **PASSED** |
| US-035 | `entropy::test_at035d_partial_final_window_low_confidence` | AT (boundary) | `compute_entropy` | 40-byte tail window → `low_confidence=True`, H==1.0 exact on the 40 present bytes (not padded) | ImportError by construction | **PASSED** |
| US-035 | `entropy::test_at035e_empty_map_returns_empty_list` | AT (edge/negative) | `compute_entropy` | `compute_entropy({})` → `[]`, no crash, no div-by-zero (positive empty assert) | ImportError by construction | **PASSED** |
| US-037 | `report::test_report_contains_entropy_section_on_disk` | **GATE, C-12** | `generate_project_report` → report file on disk | Precondition: executed variant `result.mem_map` non-empty; then re-read file carries the per-variant `### Entropy` heading + band line(s) | **LIVE RED** — inc-002 §4a: wiring stubbed `and False`, precondition PASSED, `"### Entropy" in variant_block` FAILED (1 failed in 0.66s) → the AT discriminates the feature, not the fixture | **PASSED** |
| US-037 | `report::test_report_omits_entropy_when_disabled_byte_identical` | **GATE (branch)** | `generate_project_report` → disk | `include_entropy=False` → section absent AND on−block == off byte-identical (load-bearing per LLR-037.3) | Branch-completeness; the US-037 counterfactual is carried by AT-037a (absent deliverable). Strengthened to byte-identical in the F2 fold — inc-002 F2 | **PASSED** |
| US-036 | `viewer::test_at036a_open_modal_strip_and_jump_list` | **GATE** | Pilot: load image → `press("e")` → modal | `e` opens the modal with band-coloured strip cells + a populated jump list | RED by construction (`e` unbound + `action_show_entropy`/`EntropyViewerScreen` absent pre-fix) — inc-003 §5; positively pinned by TC-036.4 | **PASSED** |
| US-036 | `viewer::test_at036b_jump_second_row_moves_focus` | AT (C-10 off-default) | Pilot: modal → activate 2nd jump row | Focus moves to the window start (==0x4000); before≠after discriminates a "renders but jump is a no-op" bug | Modal absent pre-fix | **PASSED** |
| US-036 | `viewer::test_at036c_no_image_safe_noop` | AT (edge) | Pilot: `e` with no image | Safe no-op notify, no crash | Modal absent pre-fix | **PASSED** |
| US-036 | `viewer::test_at036c_no_image_empty_state_text` | AT (edge) | Pilot: no image | Positive empty-state text assert (not vacuous) | Modal absent pre-fix | **PASSED** |
| US-036 | `viewer::test_at036c_single_window_one_cell_one_row` | AT (boundary) | Pilot: single-window image | Exactly one strip cell + one jump row | Modal absent pre-fix | **PASSED** |

**Additional white-box guard nodes** (covered above but noted for completeness): `report::test_entropy_lines_shape_direct_call` + `report::test_entropy_lines_empty_mem_map_no_crash` (LLR-037.2 GUARD, never the gate — the gate re-reads disk per C-12); `entropy::test_tc035_7_service_purity_no_textual_import` (LLR-035.5 purity probe); `entropy::test_llr035_5_entropy_window_frozen_shape` (frozen-dataclass shape); `report::test_entropy_section_confidentiality_no_raw_bytes_or_logging` (TC-037.4).

## 1c. Snapshot cells (non-gating regression artifact — xfail-until-baseline)

| Cell (real collected node) | Regime | Status | Note |
|----------------------------|--------|--------|------|
| `snapshot::test_tc036s_entropy_modal_snapshot[entropy-comfortable-80x24]` | 80×24 | **xfail** (`strict=False`, `reason="baseline pending canonical-CI regen"`) | Counted among the 5 xfailed, never `failed`. Behavioral proof is AT-036a/b/c (all PASS). |
| `snapshot::test_tc036s_entropy_modal_snapshot[entropy-comfortable-120x30]` | 120×30 | **xfail** (`strict=False`) | Baseline regenerated post-merge in the canonical CI env (batch-25 pattern); a follow-up drops the 2 xfail marks. Local `--snapshot-update` is forbidden (`snapshot-regen-env`). |

> Separately, 19 pre-existing `test_tc016s_density_layout_snapshot` cells drift because Inc-3 added the `e`/`Entropy` footer binding to every screen's rendered footer. This is the documented **non-gating** drift (snapshot job is `continue-on-error: true`); it is NOT a batch-26 validation failure and is resolved by the same post-merge canonical-CI regen (04-validation.md §6).

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 3 (US-035/037/036) — covered 3/3 (100%) |
| Total HLR | 3 (HLR-035/037/036) — implemented 3/3 (100%) |
| Total LLR | 17 (035.1–.5 · 037.1–.3 · 036.1–.6) — implemented 17/17 (100%) |
| Acceptance tests (AT) | 10 provisional ids / 12 collected nodes (AT-035a–e, AT-037a/b, AT-036a/b/c — AT-036c ×3), all PASSED — 5 GATE + boundary/negative; AT-037a a captured LIVE RED |
| Functional test cases (TC) | 16 provisional ids reconciled to 23 collected batch nodes (incl. frozen-shape + stress + geometry guards), all PASSED |
| Total batch nodes | **60 passed** (`tests/test_entropy_service.py` 14 · `tests/test_report_service.py` +8 new US-037 (33 total) · `tests/test_tui_entropy_viewer.py` 13) |
| Snapshot cells (US-036) | 2 (`entropy-comfortable-80x24` / `120x30`) — **xfail-until-baseline**, non-gating |
| Full non-slow suite | **1048 passed / 0 non-snapshot failed / 2 skipped / 5 xfailed** (reproduced identically); slow set **21 passed** |
| QC-3 boundary/negative catalogs | 3/3 complete — every row → node, 0 gaps (04-validation §4) |
| Bidirectional reachability matrix | 0 empty required cells (04-validation §4 — all three stories complete both directions) |
| Engine-frozen set | **0-diff** (`git diff --name-only origin/main` over 7 frozen paths → empty; guard suites 101 passed); `color_policy.py` referenced read-only |
| fail / pending | 0 / 0 (the only suite red = the non-gating snapshot drift) |

---

## 3. Detected gaps

> **ZERO gaps, both chains.** Every one of the 17 LLR has ≥1 passing TC with its numeric threshold audited in-assert; every one of the 3 US has passing black-box AT(s) observing the outcome through the shipped surface with boundary + negative evidence; V-5 bound all provisional ids onto the 60 collected nodes with 0 orphans (04-validation §3 reconciliation). The 2 US-036 snapshot cells are explicitly xfail-until-baseline (non-gating), not gaps.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | (none) | — |

**Tracked follow-ons (not gaps, Phase-6 carry-forward):** (a) canonical-CI snapshot regen (2 new entropy baselines + 19 refreshed drifted `tc016s` cells) then drop the 2 entropy xfail marks → all cells green, zero xfail (batch-25 pattern, commit 35238ea lineage); (b) `REQUIREMENTS.md` `R-*` status promotion for HLR-035/037/036 and the traceability rows.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-035 / US-035 | NEW `s19_app/tui/services/entropy_service.py` — headless per-window Shannon entropy + 4-band classification; outside the engine-frozen set; imports no `textual` (purity probe 0 hits) |
| new | HLR-037 / US-037 | `ReportOptions.include_entropy` (default True) + `_entropy_lines(result)` band-summary, emitted through the budget-charged `emit()` after `_hexdump_section`; consumes `result.mem_map` (no new capture plumbing) |
| new | HLR-036 / US-036 | `EntropyViewerScreen(ModalScreen[Optional[int]])` (band strip + jump list) + `action_show_entropy` on the `e` key; own `ENTROPY_BAND_COLOUR` map (NOT `sev-*`); cost caps 512/512 + truncation indicator; closes feature #12 |
| new | REQUIREMENTS.md `R-*` | Phase-6 carry: promote HLR-035/037/036 rows (status `Automated`) |
| unchanged | Engine-frozen set | `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py` — 0 diff vs `origin/main`; `color_policy.py` read-only reference in LLR-036.1 |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-035** → HLR-035 → LLR-035.1/.2/.3/.4/.5 → TC-035.1–.7 (+ frozen-shape + stress guards) (functional) + AT-035a/b/c/d/e (behavioral)
- **US-037** → HLR-037 → LLR-037.1/.2/.3 → TC-037.1–.4 (functional, GUARD-class direct calls) + AT-037a (C-12 disk gate) / AT-037b (byte-identical off-branch) (behavioral)
- **US-036** → HLR-036 → LLR-036.1/.2/.3/.4/.5/.6 → TC-036.1–.5 (+ geometry_80/120) (functional) + AT-036a/b/c×3 (behavioral) + 2 snapshot cells (non-gating)

### 5.2 By code file
- `s19_app/tui/services/entropy_service.py` (NEW) → LLR-035.1 (`:29/:33/:41`, `classify_band` `:92`), LLR-035.2 (`_derive_ranges` `:132`, walk `:258`), LLR-035.3 (`_window_entropy` `:173`), LLR-035.4 (`:271`), LLR-035.5 (`EntropyWindow` `:49`, `compute_entropy` `:214`)
- `s19_app/tui/services/report_service.py` → LLR-037.1 (`:199`/`:238`), LLR-037.2 (`_entropy_lines` `:985`), LLR-037.3 (`:1222-1223` emit, `:1234` write)
- `s19_app/tui/screens.py` → LLR-036.1 (`ENTROPY_BAND_COLOUR` `:554`, `dim` `:564`), LLR-036.2 (`EntropyViewerScreen` `:574`, `compose` `:668`), LLR-036.3 (geometry via `.modal-dialog`), LLR-036.5 (`on_list_view_selected`→`dismiss(target)` `:707`), LLR-036.6 (caps `:570-571`, `#entropy_truncated` `:688`)
- `s19_app/tui/app.py` → LLR-036.4 (`Binding("e",…)` `:685`, `action_show_entropy` `:3616`), LLR-036.5 (`_focus_entropy_target`→`_apply_goto`+`update_hex_view` `:3653`)

### 5.3 Boundary / safety nodes
- **AT-037a** is the **C-12 disk gate** — real variant execution (`capture_mem_maps=True`, precondition `result.mem_map` non-empty) → `generate_project_report` → re-read the written file; the only test that goes RED on a silently-absent entropy section. Captured as a live RED.
- **AT-035c** is the **gap-non-straddle safety node** — a window that crosses the unmapped inter-range gap would yield 1 window / wrong boundary H; this AT + `TC-035.1` pin exactly-2 windows.
- **TC-035.2** is the **band-cutoff off-by-`<`/`≤` node** — direct float injection at 1.0/5.0/7.2 pins the `[lo,hi)` side independently of histogram constructibility.
- **TC-035.7** is the **purity regression net** — any future `import textual` in `entropy_service.py` fails it (keeps the service headless/reusable).
- **TC-036.1** is the **`sev-*`-not-reused node** — grep-guards that band cells consult only `ENTROPY_BAND_COLOUR`, never the severity classes (frozen `color_policy.py`).
- **TC-036.5 / TC-036.5b** are the **cost-cap nodes** — on `large_s19`, rendered cells/rows ≤ 512 with a visible truncation indicator (either-cap min semantics, mutation-verified).

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-06-batch-26 |
| Feature | #12(b) entropy/data-classification viewer — closes feature #12 |
| Validation | **PASS** (04-validation.md §1 BLUF; §9 zero gaps/blockers) |
| DoR resolution | R1 → **bands-only**; US-036 → modal + measured geometry (48@80 / 76@120, no fallback rung) |
| Engine-frozen | 0-diff confirmed; purity probe 0 `textual` hits |
| Snapshot carry | 2 entropy cells xfail-until-baseline + 19 drifted `tc016s` cells → canonical-CI regen post-merge (non-gating) |
| Synced to Obsidian | pending post-merge (`/dev-flow-sync`) |
