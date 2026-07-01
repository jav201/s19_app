# 01 — Requirements — batch-22 (#8 US-030 4-pane split + US-031 snapshots)

> Status: **Phase 0 (measurement SPIKE / DoR)**. §2.5 = the spike's measured geometry (the reason this batch exists); §2.6 = stories. Language: English. Normative: `shall`.

## 1. Purpose
Split `PatchEditorPanel` (a single vertical `ScrollableContainer`, ~10 stacked groups) into a **multi-pane layout** so the entries / change-file / checks / variant areas are visible together without clipping/underflow at 80 or 120 cols (US-030), and lock it with geometry snapshots (US-031).

## 2. Context

### 2.4 Constraints
- Engine-frozen set OFF-LIMITS. The split lives in `screens_directionb.py` (`PatchEditorPanel.compose` @:589-714) + `styles.tcss`. ≤5 files/increment.
- **This batch IS the C-13/C-13.1 case** — no layout ships without the measured budget below.

### 2.5 SPIKE RESULT — measured host geometry (verified 2026-07-01, this session)
Measured by driving the real app under Pilot at both sizes (`action_show_screen("patch")` → query widget `content_region`):

| Terminal | `#screen_patch` content | `#patch_editor_panel` content (the split host) |
|---|---|---|
| **80×24** | 74 | **70 cols** |
| **120×40** | 96 | **92 cols** |

- **Batch-21's estimate (~37/~58) was WRONG** — it assumed the patch editor shares the workspace body; in fact `#screen_patch` is near-full-width (terminal − ~6-col rail @80 / − ~24 @120), and the panel host is **~70 @80, ~92 @120**. The batch is far less geometry-constrained than deferred-feared.
- **Per-pane budget arithmetic (C-13):**
  - **2×2 grid:** ~35 cols/pane @80 · ~46/pane @120 — comfortable (a 5-button controls row fits ~35 with wrapping; panes scroll vertically so height is free).
  - **4-across:** ~17 cols/pane @80 · ~23/pane @120 — **underflows at 80** (17 cols can't hold the Load/Validate/Apply/Save/Run-checks row). Struck.
- **C-13.1 fallback ladder (deficit-matched):** PRIMARY = **2×2 grid**, deficit-free at both 80 and 120 (recovery not needed — the arithmetic clears). Rung-2 (if a specific pane's button row still overflows ~35 @80): let that row wrap (recovery ≈ a row, free — vertical scroll). Rung-3 (only if a min-width <80 is ever supported): responsive collapse 2×2 → 1-col stacked. Rungs 2-3 are pre-committed but arithmetic says PRIMARY suffices for the 80-col floor.

### 2.5b Current groups (the 4 areas to reorganize) — `PatchEditorPanel.compose`
1. **Entries** — the entries table + `#patch_doc_entry_inputs` (Address/String/Bytes + Add/Edit/Remove).
2. **Change-file** — `#patch_doc_file_row` (Select dropdown + path Input + Load/Validate/Apply/Save/Run-checks + Checks-help Label) + `#patch_paste_row` (paste TextArea + Parse).
3. **Checks** — `#patch_checks_status` + `#patch_checks_results` + `#patch_doc_issue_count`/`#patch_doc_issues`.
4. **Variant** — `#patch_execute_row` (Scope + Execute over variants).
   *(plus `#patch_saveback_row` — a hidden save-back prompt; spans/overlays, not a 4th pane.)*

### 2.6 Source user stories

| ID | Story | DoR status |
|----|-------|------------|
| US-030 | As an operator, I want the patch editor laid out as a 4-pane split (entries / change-file / checks / variant visible together) so I don't scroll a long stack. | **READY** *(layout = 2×2 grid, grouping as proposed — operator-confirmed at DoR gate)* |
| US-031 | As an operator, I want the 4-pane layout to hold at 80 and 120 cols with no clipping/underflow, locked by geometry snapshots. | **READY** *(SVG snapshot baselines @80/120; regen in CI env only per convention)* |

#### Refinement log
**US-030 — 4-pane split** · READY (measurement de-risked it)
- INVEST: I ~ (US-031 locks it) · N ✓ · V ✓ (all areas visible at once) · E ✓ (host measured) · S ✓ (structural but bounded — reparent 4 groups into a grid; `screens_directionb.py` + `styles.tcss`) · T ✓ (widget geometry + SVG snapshot observable).
- Path: wrap the 4 area-containers in a Textual `grid` (2×2) inside `PatchEditorPanel`; CSS `grid-size: 2 2` (or Horizontal-of-two-Vertical); each pane `overflow-y:auto`. The saveback prompt overlays/spans.
- AT: "At 120 (and 80) cols the patch editor renders the 4 areas as a 2×2 grid, each pane's content within its column budget (no horizontal clip), all 4 reachable without scrolling the whole panel."
- **Open (DoR):** confirm the 4-area grouping above + the **2×2 grid** (vs 4-across, which the measurement struck).

**US-031 — geometry snapshots** · READY
- SVG snapshot baseline of the 2×2 patch editor at 80 and 120 cols (the app's snapshot-test mechanism). **Regenerate baselines ONLY in the canonical CI env** (memory: local regen drifts unrelated baselines). AT: snapshot test passes at both sizes; a layout regression flips it RED.

### Recommendation
Ship **US-030 as a 2×2 grid** (primary, budget-clear at 80/120) + **US-031 snapshots** to lock it. The measurement removed the deferred geometry risk — this is now a bounded structural refactor.

---

## 3. High-level requirements (HLR)

> Numbering continues from batch-21 (last HLR-032). **HLR-033 = US-030 (2×2 split), HLR-034 = US-031 (snapshot lock).** `shall` only.

### HLR-033 — Patch editor 2×2 four-pane split · traces US-030
> The `PatchEditorPanel` shall present its controls as four area-panes in a 2×2 grid — Entries (top-left), Change-file (top-right), Checks (bottom-left), Variant (bottom-right) — all four visible together within `#patch_editor_panel`, each pane scrolling vertically and independently.
- **HLR-033.1:** the panel shall render exactly four pane containers with stable ids `#patch_pane_entries`, `#patch_pane_changefile`, `#patch_pane_checks`, `#patch_pane_variant`.
- **HLR-033.2:** every widget id and action-map entry from the pre-batch flat `compose` shall remain queryable and functionally unchanged after reparenting (the 6 `NEW_WIDGET_IDS` + all inner control ids resolve to exactly one widget). — VERIFIED contract `tests/test_tui_patch_editor_v2.py:61-78,138-161`.
- **HLR-033.3:** when a pane's content exceeds its rendered height, that pane shall provide a vertical scrollbar without expanding the grid or displacing siblings.
- **HLR-033.4:** while `#patch_saveback_row` is hidden the grid shall occupy full panel width; when shown it shall span the grid bottom (`column-span: 2`) without collapsing a pane.
- **HLR-033.5 (unwanted-behavior guard):** at the 80-column floor the panel shall lay out the 2×2 grid without horizontal clipping or pane overlap (measured host = 70 cols; ~35/pane).
- **Observable deliverable:** the four `#patch_pane_*` render 2×2 (two distinct column x's, two distinct row y's), each ≤ host_content/2, no clip, at 80 and 120. **Oracle:** Pilot `region`/`content_region`.
- **Acceptance:** AT-033a (80 floor) · AT-033b (120) · AT-033c (reparent-safety).

### HLR-034 — Geometry snapshot lock · traces US-031
> The batch shall lock the 2×2 layout with SVG snapshot baselines at the 80- and 120-column widths, such that a layout-drift regression changes the rendered SVG and fails the snapshot cell.
- **HLR-034.1:** the snapshot suite shall cover the patch screen at `80x24` and `120x30` (VERIFIED `_SIZES` `test_tui_snapshot.py:97-99`).
- **HLR-034.2 (guard):** baselines shall be regenerated only in the canonical CI env; local regen shall not be performed (standing convention — local regen drifts unrelated baselines).
- **HLR-034.3:** the pre-existing patch snapshot cell (`patch-comfortable-120x30`, currently `xfail` pending a batch-07 regen — VERIFIED `test_tui_snapshot.py:375-395`) shall be reconciled so the 2×2 baseline is the tracked expectation.
- **Observable deliverable:** the patch snapshot cells at 80/120; a layout regression flips them RED (once the CI baseline lands). **Oracle:** `snap_compare` SVG.
- **Acceptance:** AT-034a (80×24) · AT-034b (120×30) — baseline-pending-until-CI (see §6).

**`should`-misuse: PASS** (all `shall`). **Engine-frozen: PASS** — `screens_directionb.py` + `styles.tcss` + tests are outside `_ENGINE_PATHS`.

### 3.x C-13 geometry finding (the batch's whole point)
Measured host `#patch_editor_panel` content width = **70 @80 · 92 @120** (Phase-0 Pilot, verified — batch-21's ~37/~58 superseded). 2×2 = **~35/pane @80 · ~46 @120** (divisor = `#patch_editor_panel.content_region.width`, interior/gutter-excluded); panes scroll vertically (height free), only width budgeted → deficit-free at both. **Tightest = Change-file pane** (5-button `#patch_doc_controls` row): five labels don't fit one line at ~35 cols. **CORRECTION (Phase-2 architect MAJOR-R1): Textual `Horizontal` does NOT wrap** — it lays children on one line and CLIPS horizontal overflow (`#patch_doc_controls` is `width:100%; height:auto`, `styles.tcss:654`). So rung-2 is NOT "native wrap"; it must be an **explicit** button-flow: give `#patch_doc_controls` `layout: grid; grid-size: 3` so its 5 buttons deterministically flow to 2 rows within the ~35-col pane (version-stable, CSS-only). **C-13.1 ladder (corrected):** PRIMARY 2×2 (deficit-free); rung-2 = `#patch_doc_controls` becomes a `grid-size: 3` button-grid (explicit, recovers the row height — free, panes scroll); rung-3 responsive 1-col collapse (only if <80 supported — STRUCK). 4-across (~17 @80) STRUCK. **AT-033a's `region.right ≤ host` catches a clip if the button-grid is wrong.**

---

## 4. Low-level requirements (LLR) + increment plan

> Order: **Inc1 = HLR-033 reparent** (`screens_directionb.py` + `styles.tcss`) → **Inc2 = HLR-034 geometry AT + snapshot** (tests). Each ≤5 files; 0 engine-frozen.

### Increment 1 — HLR-033 (2×2 reparent)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-033.1** | Wrap the 10 flat `compose` yields into 4 `Container` panes per the mapping: `#patch_pane_entries` (title :614 + `#patch_doc_entries_table` :617 + `#patch_doc_empty_state` :622 + `#patch_doc_entry_inputs` :627); `#patch_pane_changefile` (`#patch_doc_file_row` :645 + `#patch_paste_row` :673); `#patch_pane_checks` (`#patch_doc_issue_count` :684 + `#patch_doc_issues` :685 + `#patch_checks_status` :713 + `#patch_checks_results` :714); `#patch_pane_variant` (`#patch_execute_row` :701). | `screens_directionb.py:589-714` | MODIFY | 4 NEW pane ids; inner sub-trees moved WHOLESALE (no inner rename/reorder). |
| **LLR-033.2** | Preserve every inner id + action wiring (`request_action`/`ActionRequested` :732; `set_change_files`→`#patch_doc_file_select` :586). | `screens_directionb.py` | MODIFY | Satisfies HLR-033.2 + `test_panel_composition`. |
| **LLR-033.3** | Restyle `#patch_editor_panel` → `layout: grid; grid-size: 2 3; grid-columns: 1fr 1fr; grid-rows: 1fr 1fr auto;` (2 cols × 3 rows — the 3rd row `auto` is the save-back home, zero-height while hidden so the 4 panes are NOT squeezed); each `#patch_pane_*` gets `overflow-y:auto; overflow-x:hidden; height:100%`. | `styles.tcss:556-561` | MODIFY | Scroll moves panel→panes. `grid-size: 2 3`+`auto` 3rd row (architect minor) gives the `column-span:2` save-back child a declared home. |
| **LLR-033.3b (rung-2 mechanism, architect MAJOR-R1)** | Give `#patch_doc_controls` (the 5-button Change-file row) `layout: grid; grid-size: 3` so its buttons flow to 2 rows within the ~35-col pane — Textual `Horizontal` does NOT wrap (would clip). | `styles.tcss:654` | MODIFY | Explicit button-flow replaces the false "native wrap" assumption. `region.right ≤ host` (AT-033a) verifies no clip. |
| **LLR-033.4** | `#patch_saveback_row` (hidden, :686-700) stays a full-width row with `column-span: 2`, yielded as a direct grid child after the 4 panes (NOT a pane), landing in the `auto` 3rd grid row. | `screens_directionb.py` + `styles.tcss` | MODIFY | Spans grid bottom when shown (auto row expands), no pane collapse. |
| **LLR-033.5 (census guard)** | Keep result-row `Static`s as DIRECT children of `#patch_checks_results` (the only structural test query is `#patch_checks_results > Static` @`test:785`) — do NOT interpose a wrapper. | `screens_directionb.py` | CONSTRAINT | Preserves the one child-combinator query. |

### Increment 2 — HLR-034 (geometry AT + snapshot)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-034.1** | Local geometry AT (the locally-runnable verdict): drive `action_show_screen("patch")` at 80×24 + 120×30; assert 4 `#patch_pane_*` resolve to one widget each; **2×2 arrangement — 2 distinct region.x + 2 distinct region.y AND each shared-y row-band contains EXACTLY 2 panes AND each shared-x column-band contains EXACTLY 2 panes** (rejects an L-shape/uneven layout — qa MINOR-1); each `region.width ≤ host_content//2` where host_content = `#patch_editor_panel.content_region.width` at runtime (qa MINOR-2, interior/gutter-excluded); each `region.right ≤ panel.region.right` (no clip); non-overlapping. | `tests/test_tui_patch_layout.py` (NEW) or `test_tui_patch_editor_v2.py` | NEW | Mirrors `test_tui_workspace_layout.py` `.region` idiom. |
| **LLR-034.2** | Snapshot cells via the existing `snap_compare` matrix: unpin/reconcile the `patch-comfortable-120x30` `xfail` (:385) + add an `80x24` patch cell. Render from `conftest.py` public generators only (no-leak). | `tests/test_tui_snapshot.py:379-436` | MODIFY | Reuses `pytest-textual-snapshot` / `_snapshot_run_before`. |
| **LLR-034.3** | CI-only regen: Phase 3 authors the cells + geometry AT locally; the snapshot cells land `xfail(strict=False)` until the CI regen commits the baseline (mirrors the existing :385 pattern). The geometry AT (LLR-034.1) is the gate-blocking local verdict; the SVG is the follow-through pixel-lock. | `tests/test_tui_snapshot.py` | CONSTRAINT | No fabricated local snapshot pass. |

**File-count:** Inc1 = `screens_directionb.py` + `styles.tcss` (2). Inc2 = `test_tui_patch_layout.py` (or reuse) + `test_tui_snapshot.py` (+ REQUIREMENTS.md at close) (2-3). All ≤5.

---

## 5. Acceptance & traceability

### 5.2 Dual traceability
**Behavioral (black-box):**
- US-030 → **AT-033a** (80 floor) → 4 panes 2×2 (2 distinct region.x + 2 distinct region.y), each `region.width ≤ host_content//2` (~35), no right-edge clip → *surface: Pilot region on `#patch_pane_*`* · **AT-033b** (120) → same, budget ~46 · **AT-033c** (80+120) → one key widget per area present + action routes post-reparent (`#patch_doc_entries_table` add_entry; `#patch_doc_load_button`/load_doc; `#patch_checks_run_button`/run_checks; execute-scope) → *surface: Pilot action-routing*.
- US-031 → **AT-034a** (80×24) / **AT-034b** (120×30) → patch SVG matches the approved baseline; a layout regression flips RED → *surface: `snap_compare`* — **baseline-pending-until-CI** (§6).

**Functional (white-box, TCs named; numbered Phase-3):**
- HLR-033 → LLR-033.1/.2 → **TC** 4 pane containers created + each parents its expected child ids; **TC** full `NEW_WIDGET_IDS` id-census survives reparent (extend `test_panel_composition`). LLR-033.3 → **TC** grid CSS present (`#patch_editor_panel` grid 2×3) **AND each `#patch_pane_*` has `styles.overflow_y == "auto"`** (qa MINOR-3 — covers HLR-033.3 per-pane independent scroll). LLR-033.3b → **TC** `#patch_doc_controls` is a `grid-size: 3` grid (not a bare Horizontal). LLR-033.5 → **TC** `#patch_checks_results > Static` still resolves.
- HLR-034 → LLR-034.1 → **TC** = the geometry AT itself (white+black overlap for a layout story).

### 5.3 Validation method
| Req | Method | Justification |
|---|---|---|
| AT-033a/b (geometry) | test (pilot) | Column/row counts + pane widths vs a runtime-computed budget — concrete numbers, locally runnable at every env, proves the 80-col floor. A snapshot can't assert "≤ budget". |
| AT-033c (reparent-safety) | test (pilot) | Action-routing survival is behavioral/deterministic; reuses the `request_action`+observable-effect idiom. |
| AT-034a/b (snapshot) | snapshot (`snap_compare`) | Pixel-level drift a geometry assertion may miss (overlap, re-theme). Baseline-pending locally; green verdict via CI-committed baseline. |
| TCs | test (pilot/unit) | White-box: grid CSS applied, 4 panes created, ids preserved — closes the HOW so a passing geometry AT can't be met by an accidental non-grid layout. |

### 5.4 Counterfactual table (QC-2)
| AT | Revert → RED |
|---|---|
| AT-033a (80) | leave the vertical stack (no grid) ⇒ panes share one region.x → `len({region.x})==1≠2` → RED |
| AT-033a (80) | a pane wider than its column budget / right-edge past host ⇒ `region.width > host//2` → RED (the 80-col underflow 4-across would hit) |
| AT-033b (120) | grid collapses to one row of 4 ⇒ `len({region.y})==1≠2` → RED |
| AT-033c | a key id dropped / action unrouted post-reparent ⇒ query 0 / no observable effect → RED |
| AT-034a/b | any layout drift (pane resized, grid→stack, re-theme) ⇒ SVG ≠ baseline → RED (once CI baseline exists) |

---

## 6. Decisions, risks, assumptions

### 6.2 Key decisions
- **D1 layout = 2×2 grid** (operator-confirmed; measured budget clears it; 4-across struck).
- **D2 grid over Horizontal(Vertical,Vertical)** — Textual `grid` gives explicit equal-fraction cols/rows + expresses the save-back `column-span: 2`.
- **D3 save-back row = grid-bottom span, not a pane** (it's a hidden conditional prompt).
- **D4 US-031 = geometry AT (local, gate-blocking) + snapshot (CI-locked)** — the snapshot baseline regenerates in CI only; no fabricated local pass.

### 6.3 Risks / watch-items
- **R1 (RESOLVED-in-text, verify pixel Phase-3):** Textual `Horizontal` does NOT wrap → rung-2 corrected to an explicit `#patch_doc_controls { layout: grid; grid-size: 3 }` button-grid (LLR-033.3b). No longer an "assumed native wrap". AT-033a's `region.right ≤ host` catches a clip.
- **R2 (RESOLVED-in-text):** save-back `column-span: 2` → grid is `grid-size: 2 3` with an `auto` 3rd row as its declared home (LLR-033.3/.4); zero-height while hidden. Confirm span render at Phase-3.
- **R3 (census, surfaced):** the existing `patch-comfortable-120x30` `xfail` snapshot cell WILL be invalidated by the relayout — US-031 (LLR-034.2/.3) reconciles it. **Phase-3 30-sec check:** confirm `patch` is only in `_SCAFFOLD_CELLS`, NOT also `_RESTYLED_CELLS` (else more cells go RED than planned) — architect minor.
- **R4 (reparent breadth):** dozens of tests query patch ids — census confirms all id-addressed (reparent-safe) except the one `> Static` combinator (guarded by LLR-033.5). LOW risk.

### 6.4 Reconciliation log

**Phase-2 cross-review (architect ∥ qa; security inline N/A — pure layout, no new surface) — 0 blockers; architect PROCEED, qa PROCEED. Folds APPLIED body-first:**
- **F-A1 (architect MAJOR-R1):** Textual `Horizontal` does NOT wrap (evidence `styles.tcss:654`) — the "native wrap" rung-2 was a false premise. Corrected §3.x + R1 + NEW LLR-033.3b: `#patch_doc_controls` becomes `layout: grid; grid-size: 3` (explicit button-flow to 2 rows). The 2×2 design is unchanged; only the tightest-pane button-row mechanism.
- **F-A2 (architect minor):** grid `grid-size: 2 3` + `grid-rows: 1fr 1fr auto` gives the `column-span:2` save-back child a declared home (auto row, zero-height while hidden). LLR-033.3/.4 updated.
- **F-A3 (architect minor):** Phase-3 confirm `patch` only in `_SCAFFOLD_CELLS` not `_RESTYLED_CELLS` (R3).
- **F-Q1 (qa MINOR-1):** LLR-034.1 tightened — 2×2 proof now asserts each row-band has EXACTLY 2 panes + each col-band EXACTLY 2 (rejects an L-shape that 2-distinct-x/2-distinct-y alone would pass).
- **F-Q2 (qa MINOR-2):** budget divisor = `#patch_editor_panel.content_region.width` (interior/gutter-excluded), computed at runtime — aligned in §3.x + LLR-034.1.
- **F-Q3 (qa MINOR-3):** per-pane independent scroll (HLR-033.3) now covered — TC asserts each `#patch_pane_*` `styles.overflow_y == "auto"`.
- **Pane-mapping census (architect):** all 12 physical compose yields (:614-714) map to exactly one pane/span, nothing dropped/doubled — COMPLETE. Only structural test query = `#patch_checks_results > Static` (survives, LLR-033.5). AT-033c routing genuine (drives `request_action`→observable effect). No-fabricated-snapshot discipline confirmed clean. 0 frozen edits.

**Phase-3 verify-at-render items (not blockers):** R1 button-grid pixel result @80; R2 span render; R3 snapshot-cell membership.
