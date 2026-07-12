# 04 — Validation — 2026-07-11-batch-36

> Phase 4 (Validation). Author: qa-reviewer. Independent two-layer validation of the three
> implemented stories (Inc-1 US-059 legend · Inc-2 US-060 fixtures · Inc-3 US-058 patch editor).
> Binds to `01-requirements.md` (§3 AT / §4 HLR-LLR / §5 traceability), `01b-qa-strategy-and-verification.md`,
> and the three `03-increments/increment-00{1,2,3}.md` packets. Tree: worktree `heuristic-wu-1c7c49`,
> branch `claude/ui-layout-backlog-review-f9a343`, base `7df60dd`. Python 3.14.4 / pytest 8.4.2 /
> textual-snapshot 1.1.0. **All results below are EXECUTED, not projected.**

**Verdict up front: PASS.** Gate run green (`1343 passed, 2 skipped, 20 deselected, 5 xfailed, 0
failed, exit 0`); all 5 black-box ATs reconcile to exactly one on-disk node each, each drives the
shipped surface, asserts the deliverable content, and carries a real (measured) counterfactual;
engine-frozen guards 0 diffs; ledger `--collect-only == 1370`. No BLOCKER. Residuals are all
accepted (F-01 N_80=1) or owed to Phase 6 (docs/ledger) — none is a defect.

---

## 1. Executed gate-run evidence (C-19 — ONE complete run)

```
$ python -m pytest -q -m "not slow"
......ss................................................................ [  5%]
 ... (full run) ...
1343 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 865.53s (0:14:25)
EXIT = 0
```

- **Exit code:** 0 · **Failures:** 0 · **Errors:** 0.
- **Tail:** `1343 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning`.
- **xfailed = 5:** the 2 batch-36 patch-snapshot cells (`patch-comfortable-80x24`,
  `patch-comfortable-120x30`, LLR-058.4) + 3 pre-existing entropy-modal snapshot cells
  (TC-036-S) — all canonical-CI-regen-deferred, none a regression.
- **skipped = 2 · deselected = 20:** the `-m "not slow"` filter excludes the slow stress cases
  (this is the CI-equivalent gate per `.github/workflows/tui-ci.yml:47`).
- This is the SINGLE complete run used for the pass/fail/xfail verdict. Partial runs below are
  fast name-selected confirmations only (C-19 — not stitched into the gate evidence).

**Ledger reconciliation:** `1343 passed + 2 skipped + 5 xfailed = 1350 collected-in-run` + `20
deselected-slow` = **1370 total collected**, matching `pytest --collect-only -q → 1370 tests
collected in 0.50s`. Base 1362 (Phase-1 §7) → +8 net (AT-058a, AT-058b, AT-059a, AT-059b, AT-060a,
TC-321, TC-322, TC-323) with the US-060 case-param swap netting 0 → 1370. ✓

---

## 2. Layer A — functional / white-box (TC ↔ LLR/HLR, on-disk fn cited)

Each TC confirmed present on disk and GREEN in the name-selected confirmation run
(`10 passed in 10.23s`, exit 0) and inside the gate run.

| TC / node | LLR ↔ HLR | On-disk test function (file:line) | What it pins | Result |
|---|---|---|---|---|
| **TC-321** | LLR-058.4 ↔ HLR-058 | `tests/test_tui_snapshot.py::test_tc321_batch36_patch_xfail_set` (:606) | xfail set == exactly `{patch-comfortable-80x24, patch-comfortable-120x30}`; no other cell carries a batch-36 xfail | **PASS** |
| **TC-322** | LLR-059.1 + LLR-059.3 ↔ HLR-059 | `tests/test_tui_legend.py::test_tc322_hex_block_coupled_to_overlay_styles` (:406) | Hex block colour names DERIVED from live `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE`; `_colour_name_from_style`→`Yellow`/`Orange3`; 2 rows; meanings non-blank + markup-free; both colours absent from `COLOUR_SEVERITY` | **PASS** |
| **TC-323** | LLR-060.3 ↔ HLR-060 | `tests/test_examples_smoke.py::test_tc323_discovery_and_coverage_map` (:229) | `SLOW_CASE_IDS == set()`; `case_07_stress_smoke` discovered; `pv__case_06_large_nested_a2l` NOT discovered; `case_06_large_nested_a2l` still discovered (large-A2L pipeline retained) | **PASS** |
| **TC-319** (survives) | LLR-058.3 supersession pin | `tests/test_tui_patch_layout.py::test_tc319_regroup_section_structure_census` (:351) | 15-id census + `#patch_doc_file_row` internal child order — invariant under the paste reparent | **PASS (survives, rerun as regression)** |
| **TC-035.2** (variant survives) | US-058 vertical-budget dependency | `tests/test_tui_patch_variant.py::test_tc_035_2_variant_group_above_execute_row` (:413) | variant `Select` group stays above the execute row (the Inc-3 `1fr 2fr 2fr` weight deviation was chosen precisely to keep this green — see Inc-3 §5) | **PASS** |

Anti-drift / single-source survivors also rerun green inside the gate: `test_tc_s2_report_and_modal_render_same_rows` (legend report↔modal parity, `test_tui_legend.py:454`), the modal-header equality `headers == list(LEGEND_TABLE)` (survives, dynamic — §6.5 R-A02), and the report-service legend-row coverage.

---

## 3. Layer B — behavioral / black-box + C-18 single-node realization

Each §3 AT reconciles (V-5 provisional-id) to EXACTLY ONE on-disk node driving the whole named
chain through the shipped surface. Each node was run BY NAME green individually (confirmation run,
`10 passed in 10.23s`), and again inside the complete gate run.

| AT (→ US) | ONE on-disk node (file:line) | Shipped surface driven | Deliverable OBSERVED (content, not non-empty) | Counterfactual (RED pre-change) — measured | Result |
|---|---|---|---|---|---|
| **AT-058a** (US-058) | `tests/test_tui_patch_layout.py::test_at058a_paste_editor_in_viewport_and_separated` (:532) — loops 80x24 AND 120x30 internally | Patch Editor screen via Pilot (`action_show_screen("patch")`, `_drive_paste_geometry` :457) | at `scroll_y==0` the paste editor's FIRST line is inside its pane's visible `content_region` with ≥ N_w lines (N_80=1, N_120=4 measured); `#patch_paste_row` NOT a descendant of `#patch_pane_changefile`; paste cell disjoint from the change-file cluster; no right-edge clip | paste editor below the fold: `region.y=38` vs pane content `[8,10)` @80x24 (`y=36` vs `[8,13)` @120x30) → **0** in-viewport lines, AND `#patch_paste_row` WAS a descendant of `#patch_pane_changefile` — both the placement predicate and the non-descendant guard flip RED (Inc-3 §4 RED capture: `1 failed` after source revert to HEAD) | **PASS** |
| **AT-058b** (US-058) | `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` (:2461) | Patch Editor screen via Pilot | all **15** `patch_*` ids resolve to exactly 1 widget; AT-032a `_CHECKS_HELP_TOKEN` span survives; pressing `#patch_checks_run_button` posts a real `Checks:` status line (C-12 — produced by the handler, not injected) | dropping/renaming any id → census fails; a handler regression → the `Checks:` line absent | **PASS** |
| **AT-059a** (US-059) | `tests/test_tui_legend.py::test_at059a_hex_legend_present_in_modal` (:368) | `LegendScreen` modal via the real `k` binding (no file loaded — static legend) | modal `#legend_body` carries a `Hex` artifact header AND the two SPECIFIC meaning strings `LEGEND_TABLE["Hex"]["Yellow"][1]` + `["Orange3"][1]` appear in `_modal_meanings` (C-10 — exact strings, not "a Hex heading exists") | no Hex block in `LEGEND_TABLE` → `"Hex" not in headers` (Inc-1 §4 RED: `AssertionError: the modal has no Hex artifact section`) | **PASS** |
| **AT-059b** (US-059, C-12) | `tests/test_tui_report_seam.py::test_at059b_hex_legend_present_in_report` (:1570) | project-report generation seam → written `reports/*.md` re-read off disk | the produced file bytes contain `### Hex` AND both `Yellow`/`Orange3` meaning strings — output-then-consume: handler WRITES, test RE-READS the file (never writes the legend itself) | report generated today has no `### Hex` in its `## Legend` (Inc-1 §4 RED: reread region held A2L/MAC/Issues but no `### Hex` — proves the mechanism reaches the file; only Hex missing) | **PASS** |
| **AT-060a** (US-060) | `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned` (:170) — one node, 4 outcomes | `examples/` tree on disk + git index + real service layer (`build_loaded_s19/hex`) | (1) `tmp/stress_smoke/` absent on disk AND `git ls-files` empty; (2) `case_07_stress_smoke` primary loads to a `LoadedFile` with **non-empty `mem_map`** (C-10 content, C-12 real pipeline); (3) 54 MB `professional_validation/case_06...` absent; (4) retained 36 MB `case_06_large_nested_a2l/firmware.a2l` present | pre-change: `tmp/stress_smoke/` exists (git-tracked), the pv__ case exists, the relocated case is not discovered (Inc-2 §4 RED: `2 failed, exit 1` — AT-060a on `tmp/stress_smoke` still present, TC-323 on non-empty `SLOW_CASE_IDS`) | **PASS** |

**C-18 verdict:** every AT is ONE node driving the whole chain — none is "covered in parts". AT-060a
explicitly fuses its four on-disk facts in a single node so a half-migration can't half-pass. AT-058a
loops both widths inside one body. No AT split across nodes.

**I-060-1 verify-before-delete gate (recorded BEFORE the `git rm`, Inc-2):** construct-kind subset
census — `kinds(54 MB) == kinds(36 MB)` = identical 13 `/begin` kinds
`{CHARACTERISTIC, COMPU_METHOD, DEF_CHARACTERISTIC, FUNCTION, GROUP, HEADER, MEASUREMENT, MODULE,
MOD_COMMON, MOD_PAR, PROJECT, RECORD_LAYOUT, REF_CHARACTERISTIC}`; `kinds(54 MB) ⊆ kinds(36 MB)` TRUE
→ pure scale duplicate, delete authorized. Evidence recorded in `increment-002.md` §I-060-1 before the
irreversible operation. ✓

---

## 4. Bidirectional surface-reachability matrix

Every named INPUT dimension AND every named OUTPUT/deliverable exercised/observed through the
HANDLER/shipped surface — not only a service API.

### US-058 — patch screen render → geometry
| Direction | Dimension / deliverable | Through the handler? | Node |
|---|---|---|---|
| Input | terminal size 80x24 (floor) | ✓ Pilot `run_test(size=(80,24))` → `action_show_screen("patch")` | AT-058a |
| Input | terminal size 120x30 (comfortable) | ✓ Pilot `run_test(size=(120,30))` | AT-058a |
| Input | Run-checks button press (wiring) | ✓ `#patch_checks_run_button.press()` on the live screen | AT-058b |
| Output | paste editor first line in-viewport @ scroll 0 | ✓ read `content_region`/`region` off the composed widget | AT-058a |
| Output | reparented (non-descendant) + disjoint paste cell + no clip | ✓ `walk_children` + rectangle math on live regions | AT-058a |
| Output | 15 preserved widget ids | ✓ `query("#id")` on the live screen | AT-058b |
| Output | `Checks:` status line (handler side-effect) | ✓ read `app.log_lines` after real press | AT-058b |
| Output | patch SVG cells drift (pixel-lock) | ✓ snapshot cells xfail-declared | TC-321 |

### US-059 — legend modal + report file
| Direction | Dimension / deliverable | Through the handler? | Node |
|---|---|---|---|
| Input | `k` binding opens LegendScreen | ✓ `pilot.press("k")` on the live app | AT-059a |
| Input | report generation triggered through the seam | ✓ `_generate_through_surface` drives the real report worker | AT-059b |
| Output | Hex section + 2 meanings in the MODAL | ✓ read rendered `#legend_body Label` text | AT-059a |
| Output | `### Hex` + 2 meanings in the written `reports/*.md` | ✓ handler writes → test re-reads the FILE (C-12) | AT-059b |
| Output (white-box) | Hex colour names coupled to live overlay-style constants | ✓ derived via `_colour_name_from_style`, asserted against the constants | TC-322 |

### US-060 — examples tree → smoke pipeline
| Direction | Dimension / deliverable | Through the handler? | Node |
|---|---|---|---|
| Input | relocated `case_07_stress_smoke` primary image | ✓ loaded via `build_loaded_s19/hex` (real service layer) | AT-060a |
| Input | dynamic case discovery | ✓ `_discover_cases()` (the same fn the smoke suite parametrizes on) | TC-323 |
| Output | non-empty `LoadedFile.mem_map` for the relocated case | ✓ asserted on the produced snapshot (content) | AT-060a |
| Output | `tmp/stress_smoke/` gone (disk + git index) | ✓ FS check + `git ls-files` | AT-060a |
| Output | 54 MB duplicate absent / 36 MB retained | ✓ FS path presence/absence | AT-060a |
| Output | `SLOW_CASE_IDS` empty + coverage map preserved | ✓ discovery-set assertions | TC-323 |

No output-producing story is observed only white-box: each has a black-box node driving the shipped
surface with boundary + negative evidence (80x24 floor for US-058; no-file-loaded boundary for US-059;
empty `SLOW_CASE_IDS` boundary + skip-clean negative for US-060).

---

## 5. Engine-frozen guard result

```
$ python -m pytest tests/test_engine_unchanged.py \
    tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main -q
..                                                                       [100%]
2 passed in 0.32s   EXIT = 0
```

- **0 diffs** against `main` on the frozen set (`core.py`, `hexfile.py`, `range_index.py`,
  `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).
- Consistent with the design: US-058 touched `screens_directionb.py` + `styles.tcss` (non-frozen);
  US-059 touched `legend.py` (non-frozen) and only READ `color_policy` constants; US-060 touched no
  engine module. The batch-36 change surface never crosses the frozen boundary. ✓

---

## 6. Residuals (accepted / owed — NOT defects)

| # | Residual | Classification | Evidence |
|---|---|---|---|
| F-01 | @80x24 the paste box shows **N_80 = 1** in-viewport line (physical ceiling of the 5-row height-starved shell); full multi-line readability is a ≥120-col affordance (**N_120 = 4**) | **Accepted residual** (operator-accepted "first option" — a real improvement over the below-fold 0; no scope expansion) | LLR-058.1 residual-scope-tension note; Inc-3 §4 measured table + §5 risk 1 |
| R-1 | The batch-35 report byte-identity golden `tests/goldens/batch35/at055b-project-report.md` had to be rebaselined to include the new `### Hex` legend section | **Writer-census carry → post-mortem** (LLR-059.3 supersession census missed the full-report byte-identity golden; census-completeness lesson) | Inc-1 §5 risk 1; re-verified by the green `at055b` byte-identity run inside the gate |
| R-2 | 2 patch snapshot cells `xfail(strict=False)` (`patch-comfortable-80x24`, `-120x30`) | **Deferred to canonical-CI regen post-merge** (local regen forbidden — `reference_snapshot_regen_env`) | TC-321 green; gate xfailed=5 includes these 2 |
| R-3 | REQUIREMENTS.md rows R-TUI-046/047/048, `.dev-flow/BACKLOG.md` refresh, operator-facing docs | **Owed to Phase 6** (docs deliverables, not code) | Inc-1 §6, Inc-2 §1, Inc-3 §6 |

None of the above blocks the gate. F-01 is an operator-accepted limit; R-1 is a post-mortem lesson
already remediated in-batch; R-2 is the standard canonical-CI regen convention; R-3 is Phase-6 scope.

---

## 7. Evidence checklist (each ✓ + citation)

- ✓ **Acceptance criteria use Given/When/Then equivalents (observable outcome / shipped surface / deliverable / counterfactual).** §3 of `01-requirements.md`; reconciled in §3 above.
- ✓ **Test cases have explicit Expected, not vague "works".** Layer A §2 (each TC's pinned predicate); Layer B §3 (each AT's deliverable-observed column).
- ✓ **Edge cases include empty, boundary, invalid, error.** US-058 80x24 floor (boundary) + non-descendant/no-clip (negative); US-059 no-file-loaded (boundary) + markup-free (negative); US-060 empty `SLOW_CASE_IDS` (boundary) + skip-clean missing-primary (error path, `_pick_primary` None guard).
- ✓ **Regression checklist exists.** 01b §6 (13-row supersession census) + TC-319/TC-035.2/TC-S2 survivors reran green (§2).
- ✓ **Exit criteria stated + met.** 01b §8; all met — gate green except the 2 declared patch xfails; frozen guards 0 diffs; `SLOW_CASE_IDS` pruned.
- ✓ **No real PII / secrets.** Synthetic/public fixtures only; retained large A2L is an existing repo fixture (documented synthetic, DF-2). No secret introduced.
- ✓ **Test-results section not fabricated.** Every result executed: gate run (§1, exit 0), 10-node confirmation (§2/§3, `10 passed`), frozen guards (§5, `2 passed`), collect-only (§1, `1370`).
- ✓ **Layer B (black-box):** every output-producing story observed through the SHIPPED surface with boundary + negative evidence — §3 + §4, not only white-box TCs.
- ✓ **Bidirectional surface-reachability:** every named input dimension AND output/deliverable exercised through the handler — §4 (three matrices).
- ✓ **No unfilled template:** this artifact has no `<...>`/`TC-NNN` placeholders; every node named + cited on disk; the phase actually ran.
- ✓ **C-18 single-node:** each AT reconciles to exactly one on-disk node (§3); AT-060a not split.
- ✓ **C-10 content discriminator:** AT-058a asserts content-region PLACEMENT (measured counterfactual 0); AT-059a/b assert the two exact Hex meaning strings; AT-060a asserts non-empty `mem_map`.
- ✓ **C-12 output-then-consume:** AT-059b writes → re-reads `reports/*.md`; AT-060a drives the real service pipeline; AT-058b reads the real handler's status line.
- ✓ **Engine-frozen 0 diffs.** §5.
- ✓ **Ledger reconciled 1370.** §1.

---

## 8. Gate axis verdict

| Axis | Assessment | Verdict |
|---|---|---|
| **Coverage** | 3 US → 3 HLR → 11 LLR → 5 ATs + 3 new TCs + survivors; every US has a black-box AT through the shipped surface; every LLR traces to a named on-disk node (§2/§3 tables). Bidirectional input+output reachability tabulated (§4). | **PASS** |
| **Certainty** | Every AT counterfactual is real and MEASURED (paste `region.y=38`→below-fold; `"Hex" not in headers`; `### Hex` absent in file; `tmp/stress_smoke` present) — each would RED pre-change (Inc-1/2/3 RED captures). No vacuous pass. | **PASS** |
| **Evidence** | ONE complete gate run (exit 0, `1343 passed / 5 xfailed / 0 failed`); 10-node name-selected confirmation green; frozen guards 0 diffs; collect-only 1370. All executed, cited. | **PASS** |

**GATE VERDICT: PASS.** No unmet axis. No BLOCKER. Proceed to Phase 5 (post-mortem) / Phase 6 (docs:
R-TUI-046/047/048, BACKLOG.md, operator docs). Post-merge: canonical-CI SVG regen retires the 2 patch
snapshot xfails.
