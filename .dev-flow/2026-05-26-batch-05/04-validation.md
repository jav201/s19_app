# Validation Report — Phase 4 — Batch `2026-05-26-batch-05`

| Field | Value |
|-------|-------|
| **Date** | 2026-05-28 |
| **Agent** | `qa-reviewer` (does not modify production code/tests/state) |
| **Branch** | `claude/tender-ride-3d090c` |
| **Base for diffs** | `main` |
| **HEAD commit** | `de0e742` |
| **Python used (local)** | **3.14.4** (`3.14.4 (tags/v3.14.4:23116f9, Apr 7 2026) [MSC v1944 64-bit]`) |
| **CI authoritative gate** | Python **3.11** per `CLAUDE.md` / `.github/workflows/tui-ci.yml` |
| **Working tree** | `s19_app/tui/{app.py,hexview.py,styles.tcss}` + `tests/test_tui_directionb.py` modified; 3 new test suites + `.dev-flow/2026-05-26-batch-05/` untracked |

> **Python-version note (recorded per Phase-4 instruction).** CLAUDE.md states CI runs on Python 3.11; the Phase-3 packets noted a bash shim resolving to anaconda 3.12. The locally available interpreter in this worktree is **3.14.4** — newer than either. The batch touches no syntax, stdlib, or version-divergent API (pure Textual app fields, CSS tokens, Rich `Text` span assertions); behavior is version-independent. CI on 3.11 remains the authoritative gate. All counts below were produced on 3.14.4 and are green; no failure was version-sensitive.

---

## §1. Test execution log

All three commands were run from the worktree root with `python -m pytest`.

### 1.1 Three new batch-05 suites (lean)
```
python -m pytest -q tests/test_tui_search_pagination.py tests/test_tui_mac_layout.py tests/test_tui_goto_marker.py -m "not slow"
```
**Summary line (verbatim):**
```
25 passed in 13.83s
```
Breakdown: `test_tui_search_pagination.py` (6) + `test_tui_mac_layout.py` (4) + `test_tui_goto_marker.py` (15) = **25 passed, 0 failed**.

### 1.2 Whole suite — lean path (§5.3 CI-parity gate)
```
python -m pytest -q -m "not slow"
```
**Summary line (verbatim):**
```
772 passed, 29 skipped, 19 deselected, 3 xfailed in 176.80s (0:02:56)
```
- **passed: 772 · failed: 0 · deselected: 19** (the `slow`-marked cases) · skipped: 29 · xfailed: 3.
- The 3 `xfailed` are pre-existing expected-failures (noted in the Phase-3 packets, unrelated to batch-05). 0 `xpassed`, 0 errors. **Fully green.**

### 1.3 Full suite including slow
Ran the slow subset separately (the non-slow path above already confirmed green):
```
python -m pytest -q -m "slow"
```
**Summary line (verbatim):**
```
19 passed, 804 deselected in 503.57s (0:08:23)
```
- slow suite: **19 passed, 0 failed** (8m23s — run separately because it is heavy, per Phase-4 latitude).
- Combined coverage: lean (772) + slow (19) = **791 passed, 0 failed** across the entire repository. No batch-05 TC depends on a `@pytest.mark.slow` fixture (confirms §5.3 / §5.1).

---

## §2. Inspection evidence

### 2.1 `git diff main -- s19_app/tui/styles.tcss` (LLR-002.1 / 002.2 / 002.3)
```diff
 #mac_hex_pane {
-    width: 40;
+    width: 82;
     height: 100%;
 }
 
+/* Inner scroll container of the MAC hex pane — mirrors `#hex_scroll` so the
+ * embedded hex viewer fills the vertical extent below the title/controls
+ * (HLR-002 / LLR-002.2). */
+#mac_hex_scroll {
+    height: 100%;
+    overflow: auto;
+}
+
 /* < 120-column proportional regime ... */
```
- **ONLY** `#mac_hex_pane` width (40→82) changed and the new `#mac_hex_scroll` block was added.
- The two `#workspace_body.width-narrow` selectors (`#mac_hex_pane { width: 35% }`, `#mac_records_pane { width: 1fr }`) are **NOT present in the diff** → **0 lines changed inside them** (byte-identical). `git diff --stat` reports the whole file at **10 lines (+9 / −1)** — accounted for entirely by the width bump and the 8-line `#mac_hex_scroll` block.
- **VERDICT: PASS** (LLR-002.3 narrow-regime preservation confirmed).

### 2.2 `git diff main -- s19_app/tui/color_policy.py` (§5.3 colour-constant gate)
```
(empty — no output)
```
- `git diff --stat` does not list `color_policy.py` at all. `SEVERITY_CLASS_MAP`, `FOCUS_HIGHLIGHT_STYLE`, and `MAC_ADDRESS_OVERLAY_STYLE` are **byte-for-byte unchanged**.
- Independently corroborated by the Inc-3 packet (`git diff color_policy.py` → empty).
- **VERDICT: PASS.**

### 2.3 Literal CSS-token confirmation (LLR-002.1 / 002.2)
From `s19_app/tui/styles.tcss`:
- Line 282-284: `#mac_hex_pane { width: 82; height: 100%; }` — literal `width: 82` present, outside any `width-narrow` qualifier. **PASS.**
- Line 290-292: exactly **one** `#mac_hex_scroll { height: 100%; overflow: auto; }` block. **PASS.**
- Line 298-299: `#workspace_body.width-narrow #mac_hex_pane { width: 35%; }` — present, unchanged.
- Line 302-303: `#workspace_body.width-narrow #mac_records_pane { width: 1fr; }` — present, unchanged.

### 2.4 `\bshould\b` Grep over `01-requirements.md` (§5.3 normative gate)
3 total hits — none inside an HLR/LLR **Statement** block:

| Line | Context | Classification |
|------|---------|----------------|
| 5 | `> - \`should\` = informative. **Only** in rationale...` (convention preamble) | **rationale / meta (allowed)** |
| 6 | `> - Any \`should\` inside an HLR/LLR statement is a writing error...` (convention preamble) | **rationale / meta (allowed)** |
| 306 | §5.3 acceptance criterion describing the Grep check itself | **rationale / meta (allowed)** |

- **0 normative (blocker) hits.** No `### HLR-*` or `### LLR-*` Statement block contains `should`. **VERDICT: PASS.**

### 2.5 TC-009a negative-span (no-Rich-style) assertion exists & passed
`tests/test_tui_goto_marker.py:95-105` iterates `text.spans`, resolves each span style, and asserts **no non-null styled span overlaps the 2-cell marker prefix region** (`[row_start, row_start+2)`). Plus the alignment check (lines 107-116): stripping the uniform 2-char prefix reproduces the marker-less body. Both passed (part of the 25 green). **PASS.**

### 2.6 Deviation entry-points confirmed real (for §5)
- `s19_app/tui/app.py:3192` — `_jump_to_mac_address` exists (spec LLR-001.4 named the non-existent `_on_mac_records_row_highlighted`).
- `s19_app/tui/app.py:3603` — `_get_range_index(...)` + `address_in_sorted_ranges` is the real range path (spec LLR-003.1 named the non-existent `current_file.sorted_ranges`).
- `s19_app/tui/app.py:5918` — `_apply_goto(view, addr) -> bool` shared helper exists (LLR-003.5 acceptance criterion satisfied).

---

## §3. Per-requirement pass/fail table

Method legend: **I** = integration, **U** = unit, **insp** = inspection. All thresholds are `0 failures` unless otherwise noted.

### High-level requirements

| Req | TC-ID(s) | Verification executed | Threshold | Result | Evidence |
|-----|----------|-----------------------|-----------|--------|----------|
| **HLR-001** | TC-001/002/002b/002c/003/003b | `test_tui_search_pagination.py` (6 tests) | 0 fail across main/alt/mac variants | **PASS** | 6 passed (§1.1) |
| **HLR-002** | TC-004/005/006/013 | `test_tui_mac_layout.py` (4) + styles diff (§2.1) | pane ≥82 @120c; records ≥1; narrow 0-lines | **PASS** | 4 passed; diff §2.1 |
| **HLR-003** | TC-007/008/009a/009b/010/011/012 | `test_tui_goto_marker.py` (15) + color_policy diff (§2.2) | 0 fail; 1 marked row on hit, 0 on miss; constants unchanged | **PASS** | 15 passed; empty diff §2.2 |

### Low-level requirements

| Req | TC-ID(s) | Method | Verification executed | Threshold | Result | Evidence |
|-----|----------|--------|-----------------------|-----------|--------|----------|
| **LLR-001.1** | TC-001 | I | `test_main_hex_pagination_clears_search_anchor` | `last_search_address is None` after page next/prev | **PASS** | green (§1.1) |
| **LLR-001.2** | TC-002, 002b, 002c | I | `test_search_after_pagination_resumes_from_visible_address` / `_miss_round_trip` / `test_search_empty_row_bases_fallback` | resumes from `_first_visible_hex_address("main")`; idempotent miss; empty→None | **PASS** | 3 tests green |
| **LLR-001.3** | TC-003 | I | `test_alt_tag_selection_clears_search_anchor` (+ resume via `_first_visible_hex_address("alt")`) | anchor cleared after `_jump_to_tag_by_data`; alt resume | **PASS** | green |
| **LLR-001.4** | TC-003b | I | `test_mac_record_selection_clears_search_anchor` | anchor cleared after `_jump_to_mac_address`; mac resume | **PASS** *(see §5 doc-debt: name deviation)* | green |
| **LLR-002.1** | TC-004 | I+insp | `test_mac_hex_pane_width_at_wide_terminal` + literal `width: 82` (line 283) | width ≥82 @120c; 1 declaration | **PASS** | green; §2.3 |
| **LLR-002.2** | TC-005 | I+insp | `test_mac_hex_scroll_fills_pane_height` + 1 block (line 290) | scroll fills remaining height; 1 block | **PASS** *(see §5 doc-debt: structural-invariant wording)* | green; §2.3 |
| **LLR-002.3** | TC-006 | I+insp | `test_mac_hex_pane_narrow_regime_unchanged` + `git diff` (§2.1) | 0 lines changed in `width-narrow` selectors | **PASS** | green; diff §2.1 |
| **LLR-002.4** | TC-013 | I+insp | `test_mac_records_pane_positive_width_at_wide_terminal` | `mac_records_pane.region.width ≥ 1` @120c | **PASS** | green (measured 14 cells, Inc-2) |
| **LLR-003.1** | TC-007 | I | `test_handle_goto_out_of_range_sets_status_and_does_not_move_view` | status `Address 0x… not in loaded file.`; focus stays None; no view move | **PASS** *(see §5 doc-debt: `ranges` vs `sorted_ranges`)* | green |
| **LLR-003.2** | TC-008 | I | `test_handle_goto_valid_hit_sets_focus_address` | `_goto_focus_address == addr`; `update_hex_view(addr)` once | **PASS** | green |
| **LLR-003.3** | TC-009a, 009b | U | `test_render_hex_view_text_focus_row_marker_present_on_match` / `_absent_when_unset` | 1 `> ` row on hit, 0 on None; **no Rich style on marker cells**; alignment identical | **PASS** | green; negative-span §2.5 |
| **LLR-003.4** | TC-010 (×3) | U | `test_goto_focus_marker_forwarded_{main,alt,mac}` | each renderer forwards matching `_*_goto_focus_address` | **PASS** | 3 tests green |
| **LLR-003.5** | TC-011 (×4) | I | `test_handle_goto_{alt,mac}_out_of_range` / `_{alt,mac}_focus` | parity via shared `_apply_goto` (app.py:5918) | **PASS** | 4 tests green |
| **LLR-003.6** | TC-012 | I | `test_goto_focus_cleared_{main,alt,mac}_triggers` + `test_goto_focus_not_cleared_on_tab_switch` | focus None after each per-view trigger; persists on tab-switch | **PASS** | 4 tests green (incl. positive-control) |

**14 / 14 LLR PASS · 3 / 3 HLR PASS · 0 FAIL · 0 PARTIAL.**

---

## §4. §5.3 batch-acceptance criteria walk

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| 1 | 100% LLR coverage (every LLR → ≥1 passing TC) | **MET** | §3 table — all 14 LLRs map to ≥1 green TC (LLR-001.2→3, LLR-003.3→2) |
| 2 | 0 blocker fails in Phase 4 | **MET** | 0 failures in §1.1/1.2/1.3 |
| 3 | `pytest -q` (`-m "not slow"`) green; no batch-05 TC needs slow fixtures | **MET** | 772 passed, 0 fail (§1.2); 3 new suites are all non-slow (§1.1) |
| 4 | No `should` inside any HLR/LLR statement | **MET** | 3 Grep hits, all rationale/meta; 0 normative (§2.4) |
| 5 | `color_policy.py` constants byte-for-byte unchanged | **MET** | empty diff (§2.2) |
| 6 | Row-marker emits no Rich style (TC-009a negative-span) | **MET** | negative-span assertion present & green (§2.5) |
| 7 | `#mac_hex_pane width:82` + single `#mac_hex_scroll` block; `width-narrow` byte-identical | **MET** | §2.1 + §2.3 |

**7 / 7 acceptance criteria MET.**

> Python-version caveat on criterion #3: §5.3 specifies "green on Python 3.11 on the CI matrix." This run was on **3.14.4** locally. The behavior is version-independent (no version-divergent API touched). **The 3.11 CI run is the authoritative gate and must be confirmed green before merge** — see §5 / §6 recommended action.

---

## §5. Gaps / deviations / doc-debt for Phase 6

**No genuine functional gaps.** The items below are spec-wording deviations where the *implemented behavior is correct* (validation-PASS) but the LLR text names a symbol/threshold that does not match the codebase. Each is a Phase-6 doc-update flag, not a failure.

1. **LLR-001.4 entry-point name (doc-debt).** LLR names `_on_mac_records_row_highlighted`; that method does not exist. The real MAC record-selection entry-point is `_jump_to_mac_address` (`app.py:3192`). Implementation + TC-003b use the actual name. → Amend LLR-001.4 wording in Phase 6.
2. **LLR-003.1 range attribute (doc-debt).** LLR names `self.current_file.sorted_ranges`; the real `LoadedFile` attribute is `ranges`, accessed via the cached `_get_range_index()` (`app.py:3603`) → `address_in_sorted_ranges(addr, range_index)`. Behavior (binary-search membership) matches the LLR intent. → Amend LLR-003.1 wording in Phase 6.
3. **HLR-002 / TC-005 threshold wording (doc-debt).** HLR-002 + LLR-002.2 imply literal `scroll.height == pane.height`. The MAC pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll, so pixel-equality is structurally impossible. Implemented and tested as the more-robust "scroll fills the remaining vertical space / is the tallest child" invariant. → Reconcile HLR-002 / TC-005 wording in Phase 6.

**Non-deviation items carried forward (informational, not blockers):**
- `_jump_to_validation_issue_by_index` is **not** in the LLR-003.6 focus-clear trigger set (it shifts the hex view but is not enumerated). Inc-3 deliberately did not add it (would be scope creep). Phase-6 may decide whether to add an explicit LLR.
- `render_hex_view` (the non-`Text` str variant) was left untouched — off the goto path, only used by `test_tc_023_*` constant tests. Adding the param would be unused speculative code. Correct call.
- `REQUIREMENTS.md` `R-*` rows for batch-05 not yet added (batch tracked via `.dev-flow/`). Phase-6 docs task.
- **Python 3.11 CI confirmation outstanding** — local run was 3.14.4. Confirm the 3.11 CI job is green on the PR before merge (expected to pass; behavior is version-independent).

---

## §6. Verdict

### PASS-WITH-NOTES

- **All 3 HLR + all 14 LLR PASS.** All 7 §5.3 acceptance criteria MET. 0 blocker fails.
- **Headline counts:** new suites **25 passed / 0 failed**; lean whole-suite **772 passed · 0 failed · 19 deselected · 29 skipped · 3 xfailed (pre-existing)**; slow suite **19 passed / 0 failed**.
- **Both critical inspections PASS:** `styles.tcss` `width-narrow` selectors untouched (0 lines changed); `color_policy.py` diff empty.
- The "NOTES" are **three documentation deviations** (LLR-001.4 name, LLR-003.1 attribute, HLR-002/TC-005 threshold wording) — behavior is correct, only the spec text needs reconciliation in Phase 6. **None is a functional gap.**

### Recommended action
**Proceed to Phase 5 (post-mortem) → Phase 6 (documentation).** Do **not** iterate to Phase 3 — there is no failing test or behavioral gap.

Phase-6 must:
1. Amend LLR-001.4, LLR-003.1, and HLR-002/LLR-002.2/TC-005 wording per §5 items 1-3.
2. Add the batch-05 `R-*` rows to `REQUIREMENTS.md`.
3. Decide on `_jump_to_validation_issue_by_index` (add LLR or record as out-of-scope).

**Pre-merge gate:** confirm the Python-3.11 CI job (`.github/workflows/tui-ci.yml`) is green on the PR — local validation ran on 3.14.4, and 3.11 is the authoritative CI matrix per CLAUDE.md.
