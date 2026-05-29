# Phase 5 — Post-mortem · Batch 2026-05-26-batch-05

> Co-authored. The `architect` agent owns §0–§3, §6, §7 (process/engineering retrospective). The `qa-reviewer` agent owns §4 (metrics) and §5 (test-quality retrospective), spliced in via Edit.

## 0. Batch summary

**Objective.** Fix three independent hex-viewer UX-correctness defects surfaced from real operator use of the batch-04 build: (a) the hex-text search anchor goes stale after page navigation so Find Next misses or reports "not found"; (b) the MAC tab's hex pane (`width: 40`) is too narrow to render a full hex row; (c) the goto handler silently accepts out-of-range addresses and gives no row feedback.

**Scope.** Three user stories (US-001 / US-002 / US-003), decomposed into 3 HLR / 14 LLR, implemented across exactly 3 TUI-layer source files (`s19_app/tui/app.py`, `s19_app/tui/hexview.py`, `s19_app/tui/styles.tcss`). Strictly out of scope and untouched: parser, range/validation engine, A2L/MAC features, Patch Editor, `.s19tool/` project format, the `MAX_HEX_BYTES` / `MAX_HEX_ROWS` caps, and the `sev-*` / `FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE` colour constants.

**Outcome.** All 3 HLR and all 14 LLR validated PASS; all 7 §5.3 batch-acceptance criteria met; 0 blocker fails. 25 new tests added across 3 new suites (`test_tui_search_pagination.py` 6, `test_tui_mac_layout.py` 4, `test_tui_goto_marker.py` 15); lean whole-suite 772 passed / 0 failed; slow suite 19 passed / 0 failed; `color_policy.py` byte-identical; `styles.tcss` `width-narrow` selectors byte-identical. Three doc-only spec-wording deviations carried to Phase 6 (the implemented behavior is correct; only the LLR text names symbols/thresholds that differ from the codebase).

**Branch / worktree.** `claude/tender-ride-3d090c` (worktree off `main`), HEAD `de0e742`.

**Final verdict.** **PASS-WITH-NOTES** (per `04-validation.md` §6). Proceed to Phase 6 documentation; do not iterate to Phase 3 — there is no failing test or behavioral gap. Pre-merge gate: confirm the Python-3.11 CI job is green (local validation ran on 3.14.4; 3.11 is the authoritative matrix per CLAUDE.md).

---

## 1. What worked

**1.1 The parallel fan-out in Phase 1 and Phase 2 paid off.** Phase 1 dispatched `architect` (HLR/LLR derivation, §3–§4) and `qa-reviewer` (validation strategy, §5) in parallel against the same seeded user stories. Phase 2 then fanned out to three independent reviewers (`architect` re-review, `qa-reviewer`, `security-reviewer`) simultaneously. The independence is what gave the gate its teeth — the Phase-2 architect was a *different* reasoning pass from the Phase-1 architect, so it had no sunk-cost attachment to the fabricated field names it was reviewing.

**1.2 The single most valuable event: a requirements defect caught at the cheapest possible stage.** The Phase-2 independent re-review caught **F-A-01** (a blocker) *before a single line of code was written*: LLR-001.3 referenced per-view hex-window fields `_alt_hex_window_start` / `_mac_hex_window_start` that **do not exist** in `app.py`. A grep found only one such field — `self._hex_window_start` (`app.py:556`). The alt and MAC hex panes are *slaves* of the focused tag/record; they have no independent paginated window. The Phase-1 LLR was literally unimplementable as written.

This is the V-model's core value proposition demonstrated in one finding. Quantify the avoided cost: had F-A-01 slipped to Phase 3, the implementer would have started Increment 1 against a non-existent state model, hit the `AttributeError` (or worse, *added* the fields speculatively to satisfy the LLR), and either burned an increment debugging the requirement or shipped two dead instance fields that no renderer reads. The fix — reframing LLR-001.3 around the actual paging primitive (tag-selection via `_jump_to_tag` / `_handle_a2l_tag_find_next`) plus a new normative LLR-001.4 for the MAC record-selection trigger — cost one Phase-1 iteration and zero code. Catching it post-implementation would have cost an increment plus a re-review. The same pass also caught **F-A-02** (the MAC paging trigger was pushed into a test fixture instead of being normative — a phase-2 anti-pattern) and the qa-reviewer independently flagged **F-Q-01** (`tests/test_hexview.py` does not exist; the real file is `tests/test_tui_hexview.py`), which would otherwise have collection-failed *silently* in Phase 3 — exactly the silent-skip failure mode CLAUDE.md rule 12 forbids.

**1.3 The supervised-incremental split held the file budget comfortably.** The 3-increment partition (US-01 / US-02 / US-03) mapped cleanly onto the three user stories and kept every increment well under the 5-file cap: Inc-1 = 2 files, Inc-2 = 3 files, Inc-3 = 3 files. The forward-reference discipline was good — Inc-1 explicitly flagged that the LLR-003.6 focus-clear would reuse the *same five entry-points* it had just touched for the anchor-clear, and Inc-3 satisfied that forward-reference exactly (centralising anchor-clear and focus-clear so they cannot diverge, as LLR-003.6's acceptance criterion required). Each increment delivered a review packet and stopped at the boundary.

**1.4 Clean validation signal.** 25 new tests, 0 regressions across 772 lean + 19 slow. The two highest-risk "do not touch" invariants were both confirmed by `git diff`: `color_policy.py` produced an empty diff (the `sev-*` classes and the two byte-level overlay styles are byte-for-byte unchanged), and the `styles.tcss` `width-narrow` selectors changed 0 lines (the whole file diff was +9/−1, fully accounted for by the `#mac_hex_pane` width bump and the new `#mac_hex_scroll` block). The non-color-marker guarantee (no Rich `style=` on the `> ` marker cells) was verified by a concrete negative-span assertion (`test_tui_goto_marker.py:95-105`), not just by a substring check — the test encodes *why* the marker must stay plain-text (collision-avoidance with the reserved severity classes), satisfying engineering rule 9.

---

## 2. What didn't / friction points

**2.1 Phase 1 required an iteration (iteration #2), and the root cause was avoidable.** The original LLRs over-specified implementation details that didn't match the codebase. The headline case is F-A-01: the Phase-1 architect inferred a *symmetric* `_<view>_hex_window_start` design — reasoning "main has `_hex_window_start`, so alt and MAC must have parallel fields" — from the plan's hand-wave ("the alt/MAC equivalents reached via the `_active_view_name()` branches") **without grepping the actual app.py state model**. The symmetry was plausible and wrong: those dispatch branches paginate the *tag table* and the *MAC record table*, not the embedded hex pane. A 30-second grep at draft time would have shown one field, not three.

**2.2 An inter-LLR arithmetic interaction (F-A-03) was only caught by the cross-review.** LLR-002.1 first proposed `#mac_hex_pane { width: 78 }`. The acceptance arithmetic in iteration #1 actually summed to 82, not 78 — and separately, the width was computed *without* accounting for the 2-cell `> ` goto-marker padding that US-03's LLR-003.3 would later prepend to every row. So US-02's width fix would have been *silently undone* by US-03's marker: the pane would have been 3 cells too narrow once Increment 3 landed, exactly defeating the gain US-02 was supposed to deliver. This is the textbook inter-requirement-interaction defect the cross-review exists to catch — neither US-02 nor US-03 is wrong in isolation; only their composition is. Corrected to `width: 82` in iteration #2, with the historical lesson recorded in §6.2 of the requirements.

**2.3 Three requirement-vs-code naming mismatches surfaced only at implementation time.** These slipped *through* both the Phase-1 iteration and the Phase-2 gate and were caught by the implementer in Phase 3:
- LLR-001.4 named `_on_mac_records_row_highlighted`; the real entry-point is `_jump_to_mac_address` (`app.py:3192`, originally cited `:2891-2895` in Inc-1).
- LLR-003.1 named `current_file.sorted_ranges`; the real `LoadedFile` attribute is `ranges`, reached via the cached `_get_range_index()` accessor (`app.py:3603`).
- TC-005 / HLR-002 specified the literal `scroll.height == pane.height`; structurally impossible because the MAC pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll, so the implementer correctly softened it to a "scroll fills the remaining vertical space" structural invariant.

All three are symptomatic of the *same* root cause as 2.1: requirements written against *assumed* rather than *grep-verified* symbol names and *assumed* rather than *measured* layout geometry. Notably, even a thorough independent Phase-2 review did not catch these three — the F-A-01 grep checked `_hex_window_start` specifically, but the reviewers did not exhaustively grep *every* private symbol named in *every* LLR. The defect class survived the gate; it was only the implementer's contact with the real code that surfaced it. That is a gap in the gate's coverage, addressed by the §7 action items.

**2.4 Minor friction: method-tier churn.** Six LLRs were initially labelled `test (unit)` when `App.run_test()` makes them `test (integration)` (the handlers read state from the live widget tree via `self.query_one(...).value`, so they cannot be exercised against a `SimpleNamespace` shim). Caught as F-A-09 / F-Q-02 and relabelled in iteration #2. Low-cost, but it is the same "wrote the spec without checking how the code is actually exercised" pattern.

---

## 3. Scope management & root-cause analysis

**3.1 Was there scope creep? No — the Phase-1 derivations were legitimate decomposition.** Two structures appeared in the LLRs that the approved plan (`user-stories-the-quiet-alpaca.md`) did not literally enumerate:
- the shared private helper `_apply_goto(view: str, addr: int) -> bool`, and
- the per-view focus fields `_<view>_goto_focus_address` (plus the `_first_visible_hex_address(view)` helper and its alt/MAC instance caches).

The Phase-2 architect explicitly adjudicated this in **F-A-08** as *legitimate decomposition, not scope creep*: the plan said "apply the same pattern to `_handle_goto_alt` and the MAC goto handler" without saying *how* the pattern is shared, and a shared helper is the only realistic way to keep the three `_handle_goto*` bodies from drifting — consistent with the codebase's existing convention of sharing helpers across the three views (e.g. `_clamp_viewer_page_size`), per engineering rule 11. Critically, both derivations were **bounded to `app.py`**, so they did not enlarge any increment's file budget. **This held through Phase 3:** Inc-3 implemented `_apply_goto` (`app.py:5918`) and the three focus fields entirely within `app.py` + `hexview.py`, 3 files total. The implementer also *correctly declined* two tempting expansions — it did **not** add `_jump_to_validation_issue_by_index` to the focus-clear set (not enumerated in LLR-003.6; adding it would be creep) and left the non-`Text` `render_hex_view` variant untouched (off the goto path; adding the param would be unused speculative code). Scope stayed disciplined end-to-end.

**3.2 Root cause of the Phase-1 iteration.** The proximate causes were F-A-01 (fabricated fields), F-A-02 (non-normative trigger), F-A-03 (width arithmetic), and the editorial fixes. The *deepest* common cause is a single missing control:

> **Phase-1 LLRs named specific private symbols (`_alt_hex_window_start`, `_on_mac_records_row_highlighted`, `current_file.sorted_ranges`) and computed layout geometry (`width: 78`) without a grep-verification / measurement step at draft time.** The architect reasoned from *plausible symmetry* and *arithmetic on paper* rather than from *observed code*. Plausible-but-unverified symbol names are the through-line connecting the Phase-1 blocker (2.1), the surviving Phase-3 deviations (2.3), and the method-tier churn (2.4).

**3.3 Proposed preventive control for the dev-flow template.** Add a normative drafting rule to the requirements template, mirroring the template's existing "testing-strategy-vs-ADR" preventive rule:

> **LLR symbol-citation rule.** *Every LLR statement or acceptance criterion that names a private field, method, attribute, or widget id of the production code MUST cite its `file:line` and that citation MUST be verified by grep at draft time.* A named symbol with no verified `file:line` is a Phase-2 blocker class (call it `F-x-SYMBOL-UNVERIFIED`), checked by the same grep gate that already enforces the `should`-free rule. Layout-geometry constants (CSS widths, cell counts) that depend on a rendered shape MUST cite the measured value from an `App.run_test(size=...)` probe or be flagged `assumed — verify in Phase 3`.

This control would have caught all of F-A-01, the three Phase-3 deviations (2.3), and forced the width-82 arithmetic to be reconciled against an actual `render_hex_view_text` cell count at draft time rather than after Increment 3. It is cheap (grep is already in the gate), it is reversible (it only adds a citation requirement), and it converts the most expensive defect class in this batch into a draft-time mechanical check.

---

## 4. Metrics

All figures sourced from `state.json` (`iterations_per_phase`, `decisions_log`), `02-review.md` (findings funnel), the three `03-increments/` packets (test inventory), and `04-validation.md` (suite health, coverage, pass/fail). The headline `25 passed` was independently re-run on 2026-05-28 (`25 passed in 11.29s`, matches 04-validation §1.1).

### 4.1 Iterations per phase

| Phase | Iterations | Note |
|-------|:----------:|------|
| 1 — Requirements | **2** | The 2nd iteration was **forced by Phase-2 blockers** (3 blockers + 7 majors), not a Phase-1 self-defect. Phase 1 re-issued at 3 HLR / 14 LLR (was 3 / 11; added LLR-001.4 + LLR-002.4). |
| 2 — Review | 1 | One review pass produced 21 findings; the re-confirmation gate (02-review.md §5) verified all closed without a 2nd full review cycle. |
| 3 — Implementation | 1 | 3 increments, each ≤5 files, all approved first pass. |
| 4 — Validation | 1 | PASS-WITH-NOTES on first run; no re-validation needed. |

**Total dev-flow iterations: 5** across the 4 executed phases. The single forced iteration (Phase 1 #2) is the entire cost of the Phase-2 gate catching the blockers — cheap relative to discovering them mid-implementation.

### 4.2 Findings funnel (Phase 2 → close)

| Severity | Raised (Phase 2) | Closed in iteration #2 | Open at end |
|----------|:----------------:|:----------------------:|:-----------:|
| Blocker | 3 | 3 | **0** |
| Major | 7 | 7 | **0** |
| Minor | 11 | 11 | **0** |
| Info / security | 1 (security, no defect) | n/a (informational) | **0** |
| **Total actionable** | **21** | **21** | **0** |

- 100% of the 21 actionable findings closed in a single iteration (Phase 1 #2), verified by the orchestrator re-confirmation (02-review.md §5.1–5.6) and independent Grep gates (§5.4).
- 0 findings reopened in Phase 3/4. 0 security defects — the single security finding (F-S-01) cleared all 7 checkpoints.
- All 3 blockers were "spec names something that doesn't exist": F-A-01 (non-existent `_alt/_mac_hex_window_start` fields), F-A-02 (MAC paging trigger not normative), F-Q-01 (`tests/test_hexview.py` → `tests/test_tui_hexview.py`). Each would have cost Phase-3 implementer time had it slipped the gate.

### 4.3 Test inventory (per increment)

| Increment | New tests | Files touched | New test file | TC-IDs covered |
|-----------|:---------:|:-------------:|---------------|----------------|
| Inc 1 — US-01 (search anchor) | 6 | 2 | `tests/test_tui_search_pagination.py` | TC-001 · 002 · 002b · 002c · 003 · 003b |
| Inc 2 — US-02 (MAC pane CSS) | 4 | 3 | `tests/test_tui_mac_layout.py` | TC-004 · 005 · 006 · 013 |
| Inc 3 — US-03 (goto + marker) | 15 | 3 | `tests/test_tui_goto_marker.py` | TC-007 · 008 · 009a · 009b · 010(×3) · 011(×4) · 012(main/alt/mac + tab-switch control) |
| **Total** | **25** | **8 unique** | 3 new suites | — |

**Cumulative unique files touched: 8** — `s19_app/tui/app.py`, `s19_app/tui/hexview.py`, `s19_app/tui/styles.tcss`, the 3 new test suites, and 1 updated existing test (`tests/test_tui_directionb.py`, TC-021 band 38–42 → 80–84). `color_policy.py` deliberately **not** touched (byte-identical, confirmed twice).

### 4.4 TC → pass-status map (from `04-validation.md` §3)

| HLR | TC-IDs | Result |
|-----|--------|:------:|
| HLR-001 | TC-001/002/002b/002c/003/003b | **PASS** (6/6) |
| HLR-002 | TC-004/005/006/013 | **PASS** (4/4) |
| HLR-003 | TC-007/008/009a/009b/010/011/012 | **PASS** (15/15) |

All 14 LLRs map to ≥1 green TC (LLR-001.2 → 3 TCs, LLR-003.3 → 2 TCs). **14/14 LLR PASS · 3/3 HLR PASS · 0 FAIL · 0 PARTIAL.**

### 4.5 Coverage

| Metric | Value |
|--------|-------|
| High-level requirements | 3 (HLR-001/002/003) |
| Low-level requirements | 14 (LLR-001.1–001.4, 002.1–002.4, 003.1–003.6) |
| Test cases | 13 TC-IDs, expanding to 25 concrete tests (TC-010 ×3, TC-011 ×4, TC-012 ×4) |
| LLR → TC coverage | **100%** (every LLR → ≥1 passing TC) |
| Orphan TCs | **0** (every TC traces to an LLR — F-Q-12 walk + 04-validation §3) |
| §5.3 batch-acceptance criteria | **7/7 MET** (04-validation §4) |

### 4.6 Suite health (from `04-validation.md` §1)

| Run | Command | Result |
|-----|---------|--------|
| 3 new batch-05 suites (lean) | `pytest -q <3 suites> -m "not slow"` | **25 passed · 0 failed** in 13.83s (re-run 2026-05-28: 11.29s) |
| Whole suite — lean (CI-parity gate) | `pytest -q -m "not slow"` | **772 passed · 0 failed** · 19 deselected · 29 skipped · 3 xfailed in 176.80s |
| Slow subset | `pytest -q -m "slow"` | **19 passed · 0 failed** · 804 deselected in 503.57s |
| **Combined** | lean + slow | **791 passed · 0 failed** across the whole repo |

- The **3 xfailed are pre-existing** (noted in Phase-3 packets, unrelated to batch-05). 0 xpassed, 0 errors. Fully green.
- No batch-05 TC depends on a `@pytest.mark.slow` fixture — confirms the F-Q-04 lean-path commitment held.
- **Python-version caveat:** local validation ran on **3.14.4**; the CLAUDE.md / CI gate is **3.11**. No version-divergent API was touched (pure Textual fields, CSS tokens, Rich `Text` span assertions) — behavior is version-independent. The 3.11 CI job remains the authoritative pre-merge gate (action item A-1).

### 4.7 Cycle time

| Milestone | Date (`decisions_log`) |
|-----------|------------------------|
| Batch created (Phase 0) | 2026-05-26 |
| Phase 1 started | 2026-05-26 |
| Phase 1 approved · Phase 2 · forced-iterate · iter-2 · re-approved | 2026-05-27 |
| Phase 3 (all 3 increments) | 2026-05-27 → 2026-05-28 |
| Phase 4 validation completed | 2026-05-28 |

**Wall-clock span: 2026-05-26 → 2026-05-28 = 3 calendar days** of dev-flow time, with the bulk of Phases 1–3 compressed into 2026-05-27.

---

## 5. Test-quality retrospective & items for the next batch

### 5.1 Did the chosen validation methods hold up?

Yes — and the one method that would *not* have held up was caught at the right gate.

- **`test (integration)` was the correct call for the goto/search handlers (F-Q-02).** Phase-1 §4 originally labelled LLR-001.x and LLR-003.1/2/5 as `test (unit)`. But `_handle_goto`, `_handle_search`, and `_handle_search_alt/mac` read their input directly from the live widget tree (`self.query_one("#goto_input", Input).value`) and take no argument — there is no parameter to inject a value through, so a `SimpleNamespace` unit shim is **structurally unbuildable**. Phase 2 caught this (F-Q-02) and relabelled all six LLRs to `test (integration)` driven through `App.run_test()`. Had it slipped, the Phase-3 implementer would have burned time building a harness that cannot exist. **Lesson: classify the method against the handler's *actual* I/O surface, not the conceptual unit boundary.** Every batch-05 test that shipped is integration via `App.run_test()` and passed.

- **The `large_s19` off-marker risk (F-Q-04) was avoided.** Phase-1 §5.1 first hinted at wiring the `large_s19` / `large_mac` stress fixtures (which belong behind `@pytest.mark.slow`, per commit 86f4910) into batch-05 tests off-marker — which would have regressed CI-lean speed. Phase 2 replaced that with tiny purpose-built fixtures. Result: the 3 new suites run in **~11–14s total** on the lean path (search-pagination 6 tests in ~2.36s, mac-layout 4 in ~2.48s, goto-marker 15 in ~6.17s), and **no batch-05 TC depends on a slow fixture** (04-validation §5.3 criterion #3 MET). The lean whole-suite stayed green at 772/0.

- **TC-005's softened height assertion was the right tradeoff — but it created doc-debt.** HLR-002 / LLR-002.2 imply literal `scroll.height == pane.height`. That pixel-equality is **structurally impossible**: the MAC pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll, so the scroll can never equal the full pane height. Inc-2 correctly softened TC-005 to a structural invariant (scroll fills the *remaining* vertical space and is the tallest child) — this is the *more* robust assertion because it survives any future change to the title/controls row count. The cost: **HLR-002 wording now diverges from the test**, which is doc-debt to reconcile in Phase 6 (already flagged: 04-validation §5 item 3, §6 item 3 here).

- **The monkeypatch-import-path note (F-Q-09) saved Phase-3 time.** F-Q-09 pinned TC-010's monkeypatch target to `s19_app.tui.app.render_hex_view_text` (the imported alias inside `app.py`), not the canonical `s19_app.tui.hexview.render_hex_view_text` — because `app.py` does `from .hexview import render_hex_view_text`, binding a local name. The Inc-3 implementer used the correct target and TC-010 (×3) passed first try. A clean example of a Phase-2 testability note paying off directly in Phase 3: a half-day of "why isn't my patch taking effect" was pre-empted by one sentence in the requirements.

### 5.2 Items for the next batch (concrete)

1. **Promote the batch-05 tiny fixtures into a shared `conftest.py` helper.** The 3 new suites each hand-roll a small S19 with `row_bases` length ≥3 plus a few in-range goto addresses. If batch-06 needs the same lean primitive, extract a `tiny_s19_with_pages()` (or similar) into `tests/conftest.py` rather than re-rolling — and keep it **off** the `slow` marker so the lean-path discipline carries forward.

2. **Add a regression guard that `color_policy.py` constants don't drift.** This batch's whole premise (a *non-colour* focus marker) relied on `SEVERITY_CLASS_MAP` / `FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE` staying byte-identical, verified only by an ad-hoc `git diff` inspection per increment. A cheap unit test that snapshots those constant values (or asserts the `sev-*` class set) would turn a manual gate into an automated one and protect future marker/highlight work.

3. **Consider a `wcwidth` / East-Asian-Width lint if non-ASCII glyphs are reintroduced.** The marker glyph was deliberately switched from `▶` (U+25B6, EAW=Ambiguous → can render 2 cells, breaking column alignment) to ASCII `>` (F-A-07). If any future batch reintroduces a non-ASCII glyph into hex/ASCII rendering, add a `wcwidth`-based assertion (or a lint over `hexview.py` literals) so the 1-cell alignment invariant is machine-checked, not font-dependent.

4. **Close the Python 3.11 vs local-interpreter gap.** Validation ran on **3.14.4** locally while the authoritative CI gate is **3.11**. For this TUI-only batch the behavior is version-independent, but the gap is a recurring source of "is the local green the real green?" doubt that rides on every validation report. Recommendation: either document a **local 3.11 venv** as the dev-flow validation interpreter, or formally treat the 3.11 CI run as the sole authoritative gate and stop running full local validation on an arbitrary newer interpreter. Either removes the caveat.

5. **(Optional) Decide `_jump_to_validation_issue_by_index` focus-clear policy.** Inc-3 correctly did **not** add this to the LLR-003.6 focus-clear trigger set (it would be scope creep — it is not enumerated). But it *does* shift the hex view, so a stale focus marker could survive a validation-issue jump. Phase 6 / batch-06 should either add an explicit LLR or formally record it as out-of-scope, so the gap is a decision rather than an oversight (tracked as action item A-4).

---

## 6. Doc-debt carried into Phase 6

Phase 6 must reconcile the requirement wording with the as-built code for the three deviations recorded in `04-validation.md` §5 (behavior is correct in all three — these are spec-text edits, not functional changes), and update the living docs:

1. **LLR-001.4 entry-point name.** Amend `_on_mac_records_row_highlighted` → `_jump_to_mac_address` (`s19_app/tui/app.py:3192`). The implementation and TC-003b already use the real name.
2. **LLR-003.1 range attribute.** Amend `current_file.sorted_ranges` → `.ranges` accessed via the cached `_get_range_index()` → `address_in_sorted_ranges(addr, range_index)` (`app.py:3603`). The binary-search membership semantics the LLR intended are preserved.
3. **HLR-002 / LLR-002.2 / TC-005 height threshold.** Replace the literal `scroll.height == pane.height` with the structural invariant "the `#mac_hex_scroll` fills the remaining vertical space below `#mac_hex_title` + `#mac_hex_controls` (is the tallest child)." Pixel-equality is structurally impossible given the pane's stacked children.
4. **`REQUIREMENTS.md` living-doc update.** Add the new `R-*` rows for batch-05 (HLR-001/002/003 and their LLRs) with file+test traceability and `Automated` status — none exist yet because the batch was tracked via `.dev-flow/`. This is the living-documentation obligation in CLAUDE.md's conventions.
5. **`_jump_to_validation_issue_by_index` decision.** Record the explicit decision: it shifts the hex view but was deliberately *not* added to the LLR-003.6 focus-clear set (would be scope creep). Phase 6 either adds a new LLR for it or records it as a known, intentional out-of-scope item so a future reader does not mistake it for an oversight.

---

## 7. Action items

| # | Action | Owner | Priority | Gate / when |
|---|--------|-------|----------|-------------|
| A-1 | **Confirm the Python-3.11 CI job (`.github/workflows/tui-ci.yml`) is green on the PR.** Local validation ran on Python 3.14.4; 3.11 is the authoritative matrix per CLAUDE.md. Behavior is expected to be version-independent (no version-divergent API touched), but this must be confirmed, not assumed. | qa-reviewer / orchestrator | **Blocker** | Pre-merge gate, before PR is merged |
| A-2 | Apply the three §6 wording reconciliations (LLR-001.4, LLR-003.1, HLR-002/TC-005) to `01-requirements.md`. | docs-writer | High | Phase 6 |
| A-3 | Add the batch-05 `R-*` rows to `REQUIREMENTS.md` with file+test traceability and `Automated` status. | docs-writer | High | Phase 6 |
| A-4 | Record the explicit `_jump_to_validation_issue_by_index` decision (new LLR or documented out-of-scope). | architect | Medium | Phase 6 |
| A-5 | **Adopt the LLR symbol-citation preventive control (§3.3) into the dev-flow requirements template** so every LLR-named private symbol carries a grep-verified `file:line` at draft time, and layout-geometry constants carry a measured value or an `assumed — verify in Phase 3` flag. Add the matching Phase-2 blocker class to the gate checklist. | architect (template owner) | High | Template update, before the next batch's Phase 1 |
| A-6 | Run `/dev-flow-sync-en` to sync `.dev-flow/2026-05-26-batch-05/` to the Obsidian vault (`state.json` `obsidian_synced: false`). | orchestrator | Low | After PR merge (Phase 6 close) |
| A-7 | Consider a one-line regression strengthening the LLR-001.1 "anchor cleared even when clamped at `max_start` / `0`" boundary case (Inc-1 §5 noted TC-001 does not exercise it explicitly; the `min`/`max` assignment guarantees it, so this is hardening, not a gap). | qa-reviewer | Low | Optional, next batch |
