# Phase-4 QA review — batch 2026-10-11-batch-92 — qa-reviewer (evaluator)

> Station: Phase 4 (Validation), evaluator role per `stations/p4-validation.md` (C-25: the orchestrator
> owns the gate run; this review CONSUMES executed results and re-runs only cheap load-bearing probes).
> Worktree: `C:/Users/jjgh8/Github/s19_app-b92` @ base `410cde5` (uncommitted batch diff).
> Date: 2026-10-12. Reviewer: `qa-reviewer` (this agent).
>
> **Attribution key (who executed what):** `software-dev` = increment agent (packets 001/002) ·
> `code-reviewer` = per-increment independent reviews + packet §4b · `architect` = DDR record ·
> `orchestrator` = P4 full-suite gate run + post-run characterization of the 3 outside-union failures +
> the pending base-tree full-suite confirmation · `qa-reviewer` = every probe marked "re-run by me" below.

---

## 1 · Layer A — white-box rows (TC-651…TC-655 ↔ LLR/HLR)

| TC | LLR / HLR | On-disk node (V-5) | Last executed result | Executed by | Evidence path | State |
|----|-----------|--------------------|----------------------|-------------|---------------|-------|
| TC-651 | LLR-001.4 · HLR-001 (import census, live-tree AST set-equality) | `tests/test_render_hexview.py::test_tc651_import_census_all_consumers_read_render_hexview` | **green** at the P4 gate (absent from the 36-id failing set); 3/3 then 5/5 at the increment gates; **1/1 re-run by me** | orchestrator · software-dev ×2 · qa-reviewer | `evidence/p4-full-suite.txt` · `evidence/increment-001-tc-modules.transcript` · `evidence/increment-002-tc-modules.transcript` | executed |
| TC-652 | LLR-002.1/002.2/002.3 · HLR-002 (wrapper absence + renderer surface identity; **also the re-pointed realization of AT-289**) | `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` | green at P4; 3/3 + 5/5 at gates; **1/1 re-run by me** | orchestrator · software-dev ×2 · qa-reviewer | same three transcripts | executed |
| TC-653 | LLR-003.1/003.3 · HLR-003 (safe_text live-tree census) | `tests/test_import_census.py::test_tc653_safe_text_import_census` | green at P4; 5/5 at Inc-B gate; **1/1 re-run by me** | orchestrator · software-dev · qa-reviewer | `evidence/p4-full-suite.txt` · `evidence/increment-002-tc-modules.transcript` | executed |
| TC-654 | LLR-004.2/004.3 · HLR-004 (format census + 8-symbol `is`-identity + value pins) | `tests/test_import_census.py::test_tc654_format_census_and_shim_identity` | green at P4; 5/5 at Inc-B gate; **1/1 re-run by me** | orchestrator · software-dev · qa-reviewer | same two transcripts | executed |
| TC-655 | LLR-001.1 · LLR-004.1 (style-constant equality pin to frozen tui origins) | `tests/test_render_format.py::test_tc655_render_format_values_pinned_to_frozen_origins` | green at P4; 3/3 + 5/5 at gates; **1/1 re-run by me** | orchestrator · software-dev ×2 · qa-reviewer | same three transcripts | executed |

RED capability (instrument RED-proof, C-57) per TC, all executed with hash-verified restores: TC-651
(flipped consumer + old file restored) · TC-652 (wrapper shim re-added) · TC-655 (`CYAN` one-digit drift)
· TC-653 (checks_view flipped to retired address) · TC-654 (service edge restored; copy-shim) —
transcripts `increment-001-tc651/tc652/tc655-red.transcript`, `increment-002-tc653/tc654/shim-copy-red.transcript`,
all KILLED, restores digest-proven (`software-dev`; one arm re-executed by `code-reviewer`).

### Repointed functional nodes per LLR (Layer-A behavioral coverage of the moved symbols)

Last gate-wide execution: P4 full run 2729 passed / 36 failed (orchestrator, `evidence/p4-full-suite.txt`);
every repointed node absent from the failing set. Increment-time: `increment-001-repointed-files-run2.transcript`
186 collected / 185 passed / 1 failed (`test_a16_…`, INSIDE the 44-id union → recorded not counted, §5.2 rule 2)
and `increment-002-repointed-files.transcript` 72/72 (`software-dev`); guard host `test_tui_directionb.py`
183/0 ×2 (`increment-001/002-directionb-guard.transcript`).

| LLR | Contract-named repointed node(s) | My sample verification (qa-reviewer, 2026-10-12) |
|-----|----------------------------------|--------------------------------------------------|
| LLR-001.2 (renderer fns) | `test_build_mem_map_s19_flattens_record_bytes` · `test_build_range_validity_s19_marks_invalid_ranges` · `test_build_range_validity_hex_reflects_loader_errors` · `test_build_row_bases_aligns_and_sorts_rows` · `test_render_hex_view_text_highlights_match_range` · `test_render_hex_view_text_accepts_row_bases_set` · `test_render_hex_view_includes_focus_context` · `test_render_hex_view_truncates_output` · `test_render_hex_view_text_includes_rows_for_mac_overlay_addresses` · `test_find_string_in_mem_finds_address` · `_returns_none_when_missing` · `_supports_next_search` (in `test_tui_hexview.py` / `test_tui_helpers.py` / `test_tui_hexview_classed.py`) | **6/6 re-run by me, all pass**: mem_map flatten · range_validity_hex · extras-outside-row_bases splice · focus_context · truncates_output · mac_overlay rows · find_string next_search |
| LLR-001.3 (layout constants) | 5 × `test_tc_023_*` constant nodes + `test_tui_public_api_exports_main_helpers_and_constants` | public-api node re-run by me: **pass** (the 5 tc_023 nodes ran inside the 183/0 guard host ×2) |
| LLR-002.1 (engine ownership) | 6 wrapper-behavior nodes in `test_tui_hexview.py:85-131` (repointed to `s19_app.range_index`) + untouched `tests/test_range_index.py` | `test_address_in_sorted_ranges_boundary_cases` re-run by me: **pass** |
| LLR-003.2 (C-17 behavior) | `test_b77_*` hostile family (3 nodes, 65/65 codepoint table) + view nodes c17 / at082f | `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` re-run by me: **pass** |
| LLR-004.1 (microbar/palette) | `test_microbar` · `test_microbar_floor_opt_in` · `test_palette_constants_present_and_correct` (shim-imported) | `test_microbar_floor_opt_in` + `test_palette_constants_present_and_correct` re-run by me: **2/2 pass** |

Sample verdict: 12 of the named repointed claims re-executed by me across all four moved-symbol
families — **12/12 pass** (0.36 s, `PYTHONDONTWRITEBYTECODE=1`). Contract claims on disk match the
named nodes (verified by `--co` collection this review).

---

## 2 · Layer B — black-box rows (AT-288…AT-291, V-5 / C-18 reconciliation)

| AT | On-disk node(s) (`pytest --co` verified this review) | Reconciliation per V-5 / C-18 | Last result / by | Evidence |
|----|------------------------------------------------------|-------------------------------|------------------|----------|
| AT-288 | `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` — exactly 1 node | C-18 ✓ one node drives the whole named chain (report service end-to-end → emitted bytes). Sole byte-identity oracle (§5.2 rule 4). Driveable non-default set per QA-PDR-1: `row_bases` spanning ≥2 disjoint fixture ranges + `context_bytes=0x200`, gap row asserted on emitted bytes | green at P4 (orchestrator) · **1/1 re-run by me**; pinned capture `061ee94c…4c39` re-hashed on disk by me this review — MATCH | `evidence/p4-full-suite.txt` · `evidence/increment-001-at288-post-move.transcript` · `evidence/at288-pre-move-report.bin`(+`.sha256`) |
| AT-289 | chartered `test_at289_tui_namespace_drops_range_index_wrappers` **absent on disk**; realized by `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` (single node: positive-absence `hasattr`/`__all__`/`import_module` + `app.py` engine-sourcing object identity) | V-5 re-point DISCHARGED in the contract text (`01-requirements.md` HLR-002 Acceptance block, LED-…92.14) at the DDR; C-18 ✓ via the re-point (one node drives the namespace-drop chain). **Bookkeeping owed at close:** `AT-TC-REGISTRY.jsonl` still shows AT-289 `RESERVED` with no node binding (read this review) — flip to LIVE + node name is a close-station edit, not a gate defect | green at P4 (orchestrator) · 3/3 + 5/5 at gates (software-dev) · **1/1 re-run by me** | `evidence/p4-full-suite.txt` · `increment-001/002-tc-modules.transcript` |
| AT-290 | **DECISION (below):** canonical binding = `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal`; `tests/test_tui_checks_view.py::test_c17_seed_hostile_linkage_and_reason_render_literal` → **mention, not a binding** | C-18 required a single canonical node — decided below | green at P4 (orchestrator) · 14/14 named AT family at Inc-B gate (software-dev) · **2/2 re-run by me** | `evidence/p4-full-suite.txt` · `evidence/increment-002-at-family.transcript` |
| AT-291 | 3 chartered nodes, all exist: `test_at071_strip` · `test_build_mac_coverage_strip_counts` · `test_zero_total_no_divzero` (`tests/test_tui_mac_coverage.py`) | PDR-approved 3-node charter (repointed pre-existing nodes), recorded at DDR B4. `test_at071_strip` is the whole-chain driver (strip through the shipped app surface, `mac_in_s19 of mac_total` via the service path); the other two are same-chain mechanism/edge reinforcement — the chain is not "satisfied in parts". **Note for close:** for C-18 cardinality cleanliness the registry should name `test_at071_strip` as the binding node and carry the other two as mentions (same normalization as AT-290) — or the close pass rules explicitly that same-chain reinforcement nodes are permitted. Observation, not a gate block | green at P4 (orchestrator) · 14/14 at Inc-B gate (software-dev) · **3/3 re-run by me** | `evidence/p4-full-suite.txt` · `evidence/increment-002-at-family.transcript` |

### The AT-290 judgment

C-18 operative text (`stations/p4-validation.md`, Phase 4 · Two validation layers): *"every `§3 AT-NNN`
must reconcile to exactly ONE distinct on-disk node driving the whole named chain — an AT satisfied only
'in parts' is UNREALIZED and blocks the gate until a single joined node exists."*

AT-290's chartered realization is two sibling nodes on **two disjoint shipped screens**: c17 observes the
checks screen only; at082f observes the issues screen only. Neither node drives the *whole* named chain
(the hostile-payload-rerenders-literally outcome across the shipped screens) — the AT is satisfied
**"in parts"**, which C-18 names UNREALIZED. The two-sibling-screen reading is therefore **not**
permitted by the rule's letter; Phase 4 must bind a single canonical node. No new authoring is owed — a
qualifying node already exists:

- **Canonical: `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal`.** It is
  the only through-surface driver node of the two: full app driver (`S19TuiApp.run_test` pilot →
  `action_show_screen("issues")` → `IssueRow` cells), asserting `.plain` verbatim + `spans == []` on the
  hostile code/detail/symbol payloads — exactly the Layer-B `test (driver)` idiom C-18 lives in.
- **Disposition of the second: `test_c17_seed_hostile_linkage_and_reason_render_literal` becomes a
  MENTION** — it stays on disk, stays run green (it did: P4 + my re-run), and is cited in the AT-290
  contract/registry block as the companion widget-level guard. It is not eligible as the binding node by
  its own text: its docstring declares itself "widget-level guard; the through-surface AT-084g comes in
  Inc-4" — i.e. it was authored as a guard, not as the through-surface acceptance observation.
- **Action owed at close (bookkeeping, same class as the AT-289 re-point):** re-bind AT-289-style in
  `AT-TC-REGISTRY.jsonl` (AT-290 → `test_at082f_hostile_issue_tokens_render_literal`, c17 as mention) and
  amend the contract's AT-289-style line. The AT-290 *statement* narrows to the driven issues surface with
  the checks surface carried as the c17 mention — or a single joined both-screens node is minted later;
  either discharges C-18. The test evidence itself is unaffected: both nodes are green.

---

## 3 · Bidirectional surface-reachability matrix

Handler surfaces for this refactor: (i) the **report-service handler** (`generate_project_report` →
`report_service` → `render_hex_view` → report bytes on disk) and (ii) the **TUI screen handler**
(`S19TuiApp` screens / row widgets → the moved render + safe_text + microbar symbols). The matrix names
which declared input dimension / output deliverable is exercised through which handler, with the
exercising TC/AT. `n/a — no new input class` rows cite the contract's QC-3 boundary catalogs verbatim.

| Direction | Dimension / deliverable (IFC Part A/B) | Handler surface exercised | TC / AT | Status |
|-----------|----------------------------------------|---------------------------|---------|--------|
| input | S19 image + ranges, incl. window spanning ≥2 disjoint ranges | report-service handler, non-default `context_bytes=0x200` | AT-288 | ✓ |
| input | HEX image + loader errors | unit nodes via repointed suite | `test_build_range_validity_hex_reflects_loader_errors` (re-run by me ✓) | ✓ |
| input | focus / start_row_index / max_rows windowing | TUI screen handler (NOT driveable through the report surface — QA-PDR-1, verified `report_service.py:590`) | `test_render_hex_view_includes_focus_context` · `test_collect_hex_rows_honors_start_and_row_limit` · `test_tc_023_focus_context_rows_drives_focus_window` (focus_context re-run by me ✓) | ✓ |
| input | extra_addresses (MAC overlay splice) | TUI screen handler | `test_render_hex_view_text_includes_rows_for_mac_overlay_addresses` + 6 `test_collect_hex_rows_*` extras/fast-path nodes (one re-run by me ✓) | ✓ |
| input | search strings (case-insensitive, next-search) | TUI screen handler | 3 × `test_find_string_in_mem_*` (next_search re-run by me ✓) | ✓ |
| input | sorted range lists (wrapper primitives) | unit nodes at the engine address | 6 wrapper-behavior nodes (boundary_cases re-run by me ✓) | ✓ |
| input | hostile file-derived strings (C-17 class) | shipped checks/issues screens | AT-290 (canonical at082f; c17 mention) + 3 × `test_b77_*` (scrubs-table re-run by me ✓) | ✓ |
| input | microbar frac/width incl. clamp arms 0.0/1.0/beyond | unit + service path | `test_microbar` · `test_microbar_floor_opt_in` (re-run by me ✓) · AT-291 `test_zero_total_no_divzero` (re-run by me ✓) | ✓ |
| output | hex rows (Text / str) | TUI screen handler, `.plain`/row content asserted | repointed `test_render_hex_view*` nodes | ✓ |
| output | **report file bytes on disk (the deliverable)** | report-service handler, byte-equality vs pinned capture | AT-288 (sole oracle; capture re-hash MATCH by me) | ✓ |
| output | layout constants HEX_WIDTH/MAX_HEX_ROWS/MAX_HEX_BYTES/FOCUS_CONTEXT_ROWS/SEARCH_ENCODING | both handlers (render windows + report header) | 5 × `test_tc_023_*` + public-api node (latter re-run by me ✓) | ✓ |
| output | markup-safe literal Text (no span, no MarkupError) | shipped screens, `.spans == []` asserted | AT-290 nodes | ✓ |
| output | microbar bar + palette constants via service + shim | validation_service strip through the shipped app surface | AT-291 `test_at071_strip` (re-run by me ✓) + TC-654 identity pins (re-run by me ✓) | ✓ |
| n/a | HLR-001 input class | — | — | **n/a — no new input class** (QC-3, `01-requirements.md` HLR-001: "repoint-only change; the batch moves an address, it introduces no new input class") |
| n/a | HLR-002 input class | — | — | **n/a — no new input class** (QC-3, HLR-002: "deletion-only change; the wrapper input domain … already exercised by the engine suite") |
| n/a | LLR-001.1/001.4/002.x/003.1/003.3/004.2/004.3 boundary classes | — | — | n/a — structural/census moves, "no input class" per each LLR's Boundary catalog |
| n/a | empty/error arms of safe_text & microbar | — | — | n/a per contract: "total over str / total function over float, no error arm" (HLR-003/LLR-003.2, HLR-004/LLR-004.1 QC-3 rows); boundary arm (empty string, style default) is exercised inside `test_b77_safe_text_scrubs_*` (re-run by me ✓) |

---

## 4 · Gate verdict — **PROVISIONAL GREEN**, conditioned on the pending base-tree full-suite run

Rule application, `01-requirements.md` §5.2 (flaky-tolerant, never a count comparison), against
`evidence/p4-full-suite.txt`: **36 failed / 2729 passed / 2 skipped / 3 xfailed** (2770 collected =
base 2765 + 5 net new TC nodes; one complete orchestrator-run, 38:19):

- Set reconciliation (recomputed by me from the two evidence files): **33 of 36 failures ⊆ the 44-id
  pinned union** (`evidence/baseline-failing-set.txt`); the 11 remaining union nodes passed (flaky
  tolerance, rule 2 — recorded, not counted). Rule 3: TC-651…TC-655 and every repointed functional TC
  absent from the failing set (gate-green; my re-runs all green). Rule 4: AT-288 gate-green, capture
  hash verified on disk.
- Rule 1 is violated **on the face of the run** by exactly 3 nodes outside the union:
  `test_tui_diff_screen.py::test_tc024_report_trigger_surfaces_paths`,
  `test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent`,
  `test_tui_patch_editor_v2.py::test_at064b_json_popup_edit_confirm_cancel_and_geometry`.
- **Extension by demonstrated base-flakiness (orchestrator's executed characterization, consumed):**
  tc024 failed 3/3 under post-suite load and in the P4 run but passes standalone now, after the guard
  host, after the snapshot suite, and at base standalone — mechanism known (worker-thread race,
  batch-68 N5; monkeypatch-by-name on an object identical at both addresses; no causal path from the
  repoint-only diff). at058b/at064b pass standalone in BOTH the batch tree and the clean base tree;
  `test_tui_patch_editor_v2.py` is in neither increment's repoint set (no edit-level causal path).
  **My own standalone re-run of the 3 nodes in the batch tree: 3/3 PASS** (10.3 s) — consistent with
  load-sensitivity, and not a substitute for the base full-suite run.
- **Verdict: PROVISIONAL GREEN.** It converts to **GREEN iff the pending orchestrator-run base-tree
  full-suite shows each of the 3 nodes failing at base (or otherwise base-unstable)** — then all 36
  failures ⊆ the extended union (44 + 3) and no stable-pass→fail flip exists outside it. It converts to
  **RED (iterate-to-fix → P3) iff any of the 3 passes the base full-suite** — a stable-passing node
  flipped by the batch tree is functionality loss under rule 1 and returns to Phase 3 for that node.

Additional gate-relevant facts verified by me this review: `tests/test_id_registry.py` → **13/13**
(DDR condition C-1's corpus-bound bump 159→162 has landed and is green — it would otherwise have
tripped rule 1 as a stable-passing node outside the union); AT-289's re-point is realized on disk
(TC-652 node, green); the AT-288 pinned capture re-hashes to `061ee94c…4c39`.

---

## 5 · Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| — | moved symbols' branchy paths | **No batch-92 gap.** Spot-check of `render_hex_view` / `_collect_hex_rows` / `find_string_in_mem` against the repointed nodes: every branch carries a named node — focus-not-present (`test_collect_hex_rows_reports_missing_focus_address`), start/limit (`…_honors_start_and_row_limit`), byte-budget truncation (`…_truncates_output`, `test_tc_023_max_hex_bytes_*`), focus window (`…_includes_focus_context`, `test_tc_023_focus_context_rows_*`), extras hot path / fast path / splice / `row_bases_set` (6 `test_collect_hex_rows_*` nodes), mac-overlay rows, and all three find_string arms | — | — |
| G-P4-1 (note) | `render_hex_view` empty-map header + `find_string_in_mem` guard arms | Two micro-branches carry no asserting node: the `["No data available."]` early return and find_string's empty-query / `UnicodeEncodeError` / empty-map guards. Verified **identical at base `410cde5`** (`git show` on the base test files) — inherited coverage, unchanged by a repoint-only batch whose QC-3 catalogs declare no new input class. Not a Phase-4 gap; listed so it does not read as an oversight | minor | optional hardening node in a later batch's Layer 0 |
| G-P4-2 (bookkeeping) | AT-289 / AT-290 (and AT-291 normalization) | `AT-TC-REGISTRY.jsonl` still carries all nine ids `RESERVED` with no node bindings; contract text carries the AT-289 re-point and (after close) needs the AT-290 canonical-binding line | minor — no gate impact | close-station re-binds (AT-289→TC-652 node; AT-290→at082f canonical + c17 mention; AT-291→at071 canonical + 2 mentions, or an explicit reinforcement ruling) |

---

## Re-execution log (qa-reviewer, 2026-10-12, worktree `s19_app-b92`, `PYTHONDONTWRITEBYTECODE=1`)

- `pytest tests/test_render_hexview.py tests/test_render_format.py tests/test_import_census.py
  + AT-288 + both AT-290 nodes + all 3 AT-291 nodes -q` → **11 passed** (8.99 s).
- 12 sample repointed nodes across LLR-001.2/001.3/002.1/003.2/004.1 → **12 passed** (0.36 s).
- The 3 outside-union failures standalone → **3 passed** (10.30 s).
- `pytest tests/test_id_registry.py -q` → **13 passed** (2.26 s).
- `--co` collection of all 11 TC/AT nodes → exactly the DDR-recorded node names.
- `sha256sum evidence/at288-pre-move-report.bin` → `061ee94c…4c39`, MATCH.
- Set reconciliation p4-failing-ids (36) vs union-ids (44) → 33 inside / 3 outside (the named 3) / 11
  in-union passes.
- Branch-coverage spot-check: grep of branch-marker strings across repointed test files + `git show
  410cde5:` comparison for the two unasserted micro-branches.
