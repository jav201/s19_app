# Phase 2 — Cross-agent Review — Batch 2026-05-26-batch-05

> Reviewers append their findings under their own subsection. Do not overwrite a peer's section.

## 1. Findings (architect domain)

Reviewer: independent architect (re-review of Phase-1 architect's HLR/LLR derivation).
Scope: `.dev-flow/2026-05-26-batch-05/01-requirements.md` §§3–5, cross-checked against `C:/Users/jjgh8/.claude/plans/user-stories-the-quiet-alpaca.md` and the four code anchors named in §1.4.

### 1.0 Verdict summary
- Blockers: 2
- Majors: 4
- Minors: 4 (3 informational positive findings + 1 method-tier inconsistency)
- Recommended action: **iterate**

Both blockers are in LLR-001.3 — it references per-view hex-window fields that do not exist in the codebase, and treats the MAC variant's record-driven paging as an out-of-band test concern instead of a normative trigger. Everything else is recoverable with editorial fixes.

### F-A-01 — LLR-001.3 references non-existent per-view hex-window fields (BLOCKER)
- **Severity:** blocker
- **Location:** §4, LLR-001.3, line 145 (`_alt_hex_window_start` / `_mac_hex_window_start`); also acknowledged-but-not-fixed in §5.2 TC-003.
- **Observation:** Grep of `s19_app/tui/app.py` for `_hex_window_start` finds **only one** field, `self._hex_window_start` (declared at line 556). There is no `_alt_hex_window_start` and no `_mac_hex_window_start`. The alt and MAC hex renderers (`update_alt_hex_view` at lines 4983–5042 and `update_mac_hex_view` at lines 5044–5076) currently take a `focus_address` argument and render via `_row_start_for_near_top_focus`; they do **not** maintain an independent paginated hex-pane window. The user-story plan hand-waved this as "the alt/MAC equivalents reached via the `_active_view_name()` branches" — but those branches in `action_hex_page_*_dispatch` (`app.py:2186-2190`) route to `action_a2l_tags_page_*` and `action_mac_records_page_*`, which paginate the *tag table* and the *MAC record table* — not the embedded hex pane. The hex pane in those tabs is a slave of the focused tag/record.
- **Recommendation:** Phase 1 must either (a) introduce the per-view fields as an explicit new LLR (parallel to LLR-003.4's `_<view>_goto_focus_address`), making the dependency on new state surface-visible to qa-reviewer and security-reviewer; or (b) reframe LLR-001.3 as "after a tag/record selection change in alt/MAC, `last_search_address` shall be cleared and the next `_handle_search_alt` / `_handle_search_mac` shall resume from the first address rendered in the current hex pane" — which is the actual paging primitive in those tabs. The current wording is unimplementable as written.

### F-A-02 — HLR-001 / LLR-001.3 leave the MAC variant's paging trigger undefined (BLOCKER)
- **Severity:** blocker
- **Location:** §3 HLR-001 ("main / alt / MAC variants"); §4 LLR-001.3 acceptance criterion at line 151; §5.2 TC-003.
- **Observation:** HLR-001 demands parity across all three views, but as established in F-A-01, the MAC hex pane has no record-independent pagination. LLR-001.3's acceptance criterion ("If the mac variant does not have an independent hex-pane pagination action, the test fixture exercises the equivalent record-driven window shift") **acknowledges the gap but does not close it normatively** — it pushes the resolution into the test fixture, which is a phase-2 anti-pattern: the requirement is supposed to constrain the implementation, not the test.
- **Recommendation:** Promote the "record-driven window shift" trigger into a normative LLR statement. Suggested form: `LLR-001.3b — When the MAC records DataTable selection changes (via the existing _on_mac_records_row_highlighted entry-point or the equivalent), the TUI shall set self.last_search_address = None; the next _handle_search_mac shall resume from the first address visible in the current MAC hex pane render.` Without this, TC-003 has no defined trigger.

### F-A-03 — LLR-002.1 arithmetic conflicts with the marker padding added by LLR-003.3
- **Severity:** major
- **Location:** §4 LLR-002.1 acceptance criteria (line 160), HLR-002 rationale (line 104).
- **Observation:** LLR-002.1's acceptance arithmetic claims `78 = 2 (marker padding) + 10 (0xAAAAAAAA) + 2 (gap) + 48 (16×3) + 2 (gap+pipe) + 16 (ASCII) + 2 (pipe + slack)` — which actually sums to **82**, not 78. Reading `render_hex_view_text` lines 357–369: `0x%08X` is 10 chars + a 2-space gap = 12; then 16 × `XX ` = 48 (which absorbs its own trailing space); then ` |` = 2; then 16 ASCII = 16; then `|` = 1 → **79 cells before the marker is added**. After the new 2-cell `▶ ` / `  ` prefix from LLR-003.3 lands, total is **81 cells**. The chosen `width: 78` is therefore **3 cells too narrow** in the comfortable regime once US-03 lands, exactly undoing the gain US-02 was supposed to deliver. HLR-002's "≈74 visible columns" rationale also does not include the new marker padding. This is not a parent-direction violation (78 ≥ HLR-002's ≥74 threshold ✓) — but it is an arithmetic error that the implementer will see only after Increment 3 lands.
- **Recommendation:** Bump `#mac_hex_pane { width }` to **82** (or 81 with one slack cell trimmed) and update both the LLR-002.1 arithmetic and the HLR-002 rationale's "≈74" figure to include the LLR-003.3 marker. Phase 2 catching this is exactly the inter-LLR-interaction check that this review is for.

### F-A-04 — LLR-002.3 omits the records-pane shrink invariant
- **Severity:** major
- **Location:** §4 LLR-002.3 (lines 171–178), §3 HLR-002.
- **Observation:** Reading `styles.tcss` lines 276–280: `#mac_records_pane { width: 1fr; height: 100%; }` is the comfortable-regime rule. After raising `#mac_hex_pane` from 40 to 78 (or 82 per F-A-03), at terminal width 120 the records pane gets `120 − 78 − borders ≈ 40` cols (or 38 at 82). LLR-002.3 guards only the *narrow-regime* block byte-identically; it does **not** assert that the *comfortable-regime* records pane still receives a strictly-positive `1fr`. At small comfortable widths there is no defended invariant.
- **Recommendation:** Add LLR-002.4 (or extend LLR-002.3): "The `#mac_records_pane.region.width` shall be strictly positive at terminal width 120." Executed verification: `App.run_test(size=(120, 30))` asserting `app.query_one("#mac_records_pane").region.width >= 1`. Cheap to add and closes the symmetric invariant.

### F-A-05 — LLR-003.6 trigger list is incomplete (parse-error branch and others)
- **Severity:** major
- **Location:** §4 LLR-003.6 (lines 227–235); §5.2 TC-012.
- **Observation:** LLR-003.6 lists triggers as `action_hex_page_*`, `action_a2l_tags_page_*`, `action_mac_records_page_*`, `_handle_search*`, file-load, file-unload. Missing:
  1. The `int(raw, 0)` parse-error branch in `_handle_goto` (`app.py:5843-5847`) — if the user types garbage after a previous valid goto, the stale marker remains because the early `return` skips any reset. The prompt explicitly flagged this.
  2. `_jump_to_tag` / `_handle_a2l_tag_find_next` (listed in `update_alt_hex_view`'s "Used by") which mutate the alt hex window without going through any of the listed triggers.
  3. Tab/view switches — the marker should arguably not persist across tab switches; the LLR is silent.
- **Recommendation:** Extend LLR-003.6's trigger list with: parse-error branch in any `_handle_goto*` (clear the active view's focus address before the early return), `_jump_to_tag` / A2L tag-find, and an explicit decision (either way, but documented) on tab/view switches. Also extend TC-012's `≥5 trigger cases per view` to include the parse-error case. The "Invalid address format." status keeps firing per LLR-003.1's acceptance criterion — confirmed ✓; this only adds the focus-reset.

### F-A-06 — LLR-003.3 cites the wrong test-file path; §5.2 TC-009 corrects it only by note
- **Severity:** major
- **Location:** §4 LLR-003.3, line 203 (`pytest -q tests/test_hexview.py::...`); §5.2 TC-009a/b correctly uses `tests/test_tui_hexview.py`.
- **Observation:** Glob `tests/test_*.py` confirms the repository has `tests/test_tui_hexview.py` and `tests/test_hexfile.py` but **no** `tests/test_hexview.py`. The §5.2 row for TC-009 explicitly flags this as "flagged for architect correction," which acknowledges the bug, but the LLR's own `Executed verification` line is still wrong. Per the prompt this is correctly classified as a major, not a blocker, because §5.2 holds the corrected form.
- **Recommendation:** Replace `tests/test_hexview.py` with `tests/test_tui_hexview.py` directly in LLR-003.3's `Executed verification` line. One-character class fix.

### F-A-07 — Marker glyph U+25B6 has terminal-width-ambiguity vs the 2-space padding
- **Severity:** minor
- **Location:** §1.3 Definitions (line 33), §4 LLR-003.3 (line 201), §5.2 TC-009a (line 266), §2.5 Assumptions (line 78).
- **Observation:** §1.3 defines the marker as "`▶` followed by a space" (2 characters). LLR-003.3 says `prepend either ▶ (when …) or `  ` (two spaces) otherwise` — internally character-consistent. But `▶` (U+25B6 BLACK RIGHT-POINTING TRIANGLE) has East-Asian Width = Ambiguous, so many terminal/font combinations render it as a **2-cell-wide** glyph while the 2-space padding on non-focus rows is unambiguously 2 cells of width via 2 chars. The terminal could render the focus row as 3 cells wide where non-focus is 2, breaking LLR-003.3's "column alignment of the hex bytes is identical with and without the marker" pass-clause. §2.5 dismisses this with "renders correctly in the terminal fonts the operator uses" — that is informative, untested, and machine-dependent.
- **Recommendation:** Either (a) downgrade to the ASCII fallback `> ` (the plan §"US-03" line 50 already lists this as acceptable) and drop the unicode-rendering assumption, or (b) add a normative LLR `LLR-003.3b: The marker glyph shall occupy exactly 1 terminal cell when rendered next to an ASCII space`, with a wcwidth-style assertion in TC-009a. Option (a) is the "Simple > clever" choice and is what I'd recommend.

### F-A-08 — LLR-003.5 private helper `_apply_goto`: legitimate decomposition, not scope creep
- **Severity:** minor (clarification request, not a defect)
- **Location:** §4 LLR-003.5 (line 225 acceptance criterion). Plan §"US-03" implementation bullets do not mention any shared helper.
- **Observation:** The plan only says "Apply the same pattern to `_handle_goto_alt` and the MAC goto handler" without specifying *how* the pattern is shared. The Phase-1 architect inferred a private helper `_apply_goto(view: str, addr: int) -> bool` plus per-view focus-address fields (`_<view>_goto_focus_address`). Verdict: **legitimate decomposition, not scope creep** — it is the only realistic way to keep the three `_handle_goto*` bodies from drifting (rule 11 in the engineering rules: "Match the codebase's conventions"; the codebase already shares helpers across the three views, e.g. `_clamp_viewer_page_size`), and it is bounded to the same file (`app.py`) so the 5-file Increment-3 budget is not enlarged.
- **Recommendation:** Accept as-is. Add one sentence to LLR-003.5's rationale clarifying that the helper is a Phase-1 derivation (not an explicit plan item), bounded to `app.py`.

### F-A-09 — §5.2 TC-001 method tier disagrees with LLR-001.1's `test (unit)` tag
- **Severity:** minor
- **Location:** §4 LLR-001.1 line 126 (`Validation: test (unit)`); §5.2 line 256 (`Method: test (integration)`).
- **Observation:** Self-inconsistent method-tier between §4 and §5.2 for LLR-001.1 (and likewise LLR-001.3 vs TC-003). Not a correctness defect — both will be exercised — but it makes the coverage table self-inconsistent. `App.run_test()` *is* integration-level (it boots a real Textual App), so §5.2's classification is the truthful one.
- **Recommendation:** Change LLR-001.1's `Validation` from `test (unit)` to `test (integration)`. Same for LLR-001.3.

### F-A-10 — Normative-modal sanity (positive finding)
- **Severity:** minor (positive)
- **Location:** §3 HLR-001/002/003 Statements; §4 LLR-001.1..LLR-003.6 Statements.
- **Observation:** I mentally `grep`ped every `Statement:` field in §3 and §4 for the modal verb `should`. Every normative Statement uses `shall` (or `shall` in positive form). The `should` occurrences are confined to rationale / informative paragraphs (e.g. §1.3, §2.4) — that is permitted by §1's normative convention. The §5.3 batch-acceptance grep gate is already in place.
- **Recommendation:** None.

### F-A-11 — Parent-HLR threshold re-check (positive finding)
- **Severity:** minor (positive)
- **Location:** §3 HLR-002 ("pane ≥74 cols visible") vs §4 LLR-002.1 (`width: 78`, threshold ≥74). §3 HLR-003 ("exactly 1 row carries the `▶ ` prefix") vs §4 LLR-003.3 (same).
- **Observation:** Both threshold directions are consistent with the parent HLR. No parent-violation blocker. The *value* 78 has a separate arithmetic defect (see F-A-03) but the threshold-direction rule itself is not violated.
- **Recommendation:** None for the threshold rule.

### F-A-12 — Test-harness alignment (positive finding)
- **Severity:** minor (positive)
- **Location:** §5.1, §5.2 references to `tests/test_tui_app.py`, `tests/test_tui_hexview.py`, `App.run_test()`, and `tests/conftest.py` generators.
- **Observation:** `tests/test_tui_app.py` and `tests/test_tui_hexview.py` exist (Glob `tests/test_*.py`). `App.run_test()` is the established harness — grep `run_test\(` returns 8 test modules including `tests/test_tui_snapshot.py`, `tests/test_tui_commandbar.py`, `tests/test_tui_directionb.py`. The `large_s19` / `large_a2l` / `large_mac` generators referenced by §5.1 are real (in `tests/conftest.py`). No LLR depends on a fixture or runtime that does not exist in the repo.
- **Recommendation:** None.

### 1.1 Traceability check (summary)
- **US → HLR coverage:** US-001 → HLR-001 ✓, US-002 → HLR-002 ✓, US-003 → HLR-003 ✓. No orphans, no duplicates, no fan-out.
- **HLR → LLR coverage:** HLR-001 → {LLR-001.1, LLR-001.2, LLR-001.3} ✓; HLR-002 → {LLR-002.1, LLR-002.2, LLR-002.3} ✓; HLR-003 → {LLR-003.1..LLR-003.6} ✓. No orphan LLRs.
- **US → HLR + LLR completeness:** US-001 has the MAC-variant gap (F-A-01 + F-A-02). US-002 has the records-pane-shrink gap (F-A-04) and the arithmetic interaction with US-03 (F-A-03). US-003 has the parse-error focus-reset gap (F-A-05).

### 1.2 Action required before Phase-3
1. Fix F-A-01 (LLR-001.3 fabricated per-view fields).
2. Fix F-A-02 (MAC paging trigger undefined).
3. Fix F-A-03 (78 vs ≥81 marker arithmetic; bump width).
4. Fix F-A-04 (records-pane strictly-positive invariant).
5. Fix F-A-05 (LLR-003.6 trigger list, parse-error branch).
6. Fix F-A-06 (`tests/test_hexview.py` → `tests/test_tui_hexview.py`).
7. Apply F-A-07 + F-A-09 editorial fixes.
8. Accept F-A-08 as legitimate; document the helper origin in the LLR rationale.

Once the two blockers and four majors are addressed, Phase 1 may be re-issued and Phase 2 re-run — structural traceability is sound and the test harness alignment is correct.

## 2. Findings (software-dev domain)

*(software-dev to fill in)*

## 3. Findings (qa-reviewer domain)

Reviewer: independent qa-reviewer (separate agent from the Phase-1 §5 author). Scope per Phase-2 brief: testability of every LLR — pytest-node correctness, numeric thresholds, method classification, TC ↔ LLR coverage, naming, acceptance-criterion objectivity, CI realism.

Verification actually run during this review:
- Glob over `tests/` confirms `tests/test_hexview.py` does **not** exist; the real file is `tests/test_tui_hexview.py`.
- `App.run_test(size=(W, H))` + `query_one(...).region.width` is an established pattern — `tests/test_tui_directionb.py:1374-1375` already queries `#mac_hex_pane.region.width`.
- `_handle_goto` reads from the live widget tree (`self.query_one("#goto_input", Input).value` at `s19_app/tui/app.py:5839`); `_handle_search_alt` reads `#alt_search_input` the same way (`app.py:5856`). Neither is unit-testable via `SimpleNamespace` shims.
- CI runs `pytest -q` on Python 3.11 only (`.github/workflows/tui-ci.yml`); `pytest -m "not slow"` is the lean-default path per `CLAUDE.md`.
- §5.2 coverage walk: every one of the 12 LLRs maps to ≥1 TC; LLR-003.3 maps to 2 TCs. No orphan TCs.

### 3.0 Verdict summary
- Blockers: 1
- Majors: 3
- Minors: 7
- Info: 1
- Recommended action: **iterate**

### F-Q-01 — Wrong test-file path in LLR-003.3 (Executed verification)
- **Severity:** Blocker
- **Location:** `01-requirements.md` line 203 (LLR-003.3, "Executed verification").
- **Observation:** LLR-003.3 names `pytest -q tests/test_hexview.py::test_render_hex_view_text_focus_row_marker_present_on_match` and `::test_render_hex_view_text_focus_row_marker_absent_when_unset`. Glob over `tests/` returns no `test_hexview.py`; the real module is `tests/test_tui_hexview.py`. §5.2 TC-009a flags this in a "NOTE" but the §4 LLR statement is the contract Phase 3 will execute, so the source line must be corrected. A pytest invocation against a non-existent module fails at collection time, exactly the silent-skip mode CLAUDE.md rule 12 (Fail loud) forbids. (Architect's F-A-06 catches the same defect with a different severity classification; flagging as Blocker here per Phase-2 qa rubric — collection-fail-silent is a loud-failure-mode regression.)
- **Recommendation:** Edit LLR-003.3 line 203 to `tests/test_tui_hexview.py` (both occurrences). Drop the §5.2 "NOTE" once line 203 is fixed.

### F-Q-02 — LLR-001.x and LLR-003.1/2/5 method mislabelled as `test (unit)`
- **Severity:** Major
- **Location:** LLR-001.1 line 126, LLR-001.2 line 136, LLR-001.3 line 146; LLR-003.1 line 183, LLR-003.2 line 193, LLR-003.5 line 220.
- **Observation:** `_handle_goto` reads its address from `self.query_one("#goto_input", Input).value` (`s19_app/tui/app.py:5839`); `_handle_search` / `_handle_search_alt` read theirs from `#search_input` / `#alt_search_input` the same way. None of these methods take an arg; there is no parameter to pass `addr` / `query` in directly. Direct instantiation against a `SimpleNamespace` shim cannot exercise them — the existing precedent at `tests/test_tui_commandbar.py:342-375` drives `_handle_goto` through `async with app.run_test()` + `app.post_message(CommandBar.Goto(...))`. That is integration, not unit. Calling the method "unit" will mislead Phase 3 into trying a non-existent harness. (Architect's F-A-09 catches the same misalignment for LLR-001.1 / LLR-001.3 but only against the §5.2 cross-check; the unit-vs-integration question is structural for all six LLRs.)
- **Recommendation:** Relabel LLR-001.1 / 001.2 / 001.3 / 003.1 / 003.2 / 003.5 to `test (integration)`. Propagate to §5.2 TC-001, TC-002, TC-003, TC-007, TC-008, TC-011. The pytest invocations stay; only the method classification changes.

### F-Q-03 — LLR-002.1 / 002.2 / 002.3 `Validation:` field conflates the inspection/test pair
- **Severity:** minor
- **Location:** LLR-002.1 line 156, LLR-002.2 line 165, LLR-002.3 line 174 — declared `Validation: inspection`; §5.2 then re-describes them as `inspection (paired with test)` and pins TC-004/005/006 against `tests/test_tui_hexview.py`.
- **Observation:** §4 `Validation:` is a single token; §5 turns it into a pair. §5.1 itself says "the pytest form is the executed verification of record and inspection serves as the human-readable corroboration." A reader of §4 alone will not know a pytest run is the primary method.
- **Recommendation:** Change LLR-002.1/002.2/002.3 `Validation:` to `test (integration) + inspection`. Keep §5.2 wording.

### F-Q-04 — §5.1 hints at `large_s19` / `large_mac` without a `slow` marker
- **Severity:** Major
- **Location:** §5.1 "test (unit)" paragraph (line 243).
- **Observation:** `conftest.py::make_large_s19` is the stress fixture used elsewhere behind `@pytest.mark.slow`. None of the batch-05 LLRs need a stress-sized image — pagination, anchor reset, focus marker, and CSS pane width are observable on tiny (≤256-byte) images. Commit 86f4910 just marked `pv__case_06_large_nested_a2l` slow precisely to keep default CI lean. Wiring `large_s19` into batch-05 tests off-marker regresses that effort.
- **Recommendation:** Replace the `large_s19` / `large_mac` hint in §5.1 with a tiny purpose-built fixture (one S19 with `row_bases` of length ≥ 3 so pagination has somewhere to move, plus a few in-range addresses for goto). If any batch-05 TC genuinely needs the stress fixture, mark it `@pytest.mark.slow` and add a §5.3 acceptance criterion that the default `pytest -q -m "not slow"` invocation is green.

### F-Q-05 — LLR-003.6 "≥5 trigger cases per view" vs. TC-012 enumeration mismatch
- **Severity:** Major
- **Location:** LLR-003.6 line 232 numeric threshold + §5.2 TC-012 line 269.
- **Observation:** §5.2 TC-012 enumerates 5 triggers (`action_hex_page_next`, `action_hex_page_prev`, `_handle_search` with a new term, file-load, file-unload) — total 5 cases. LLR-003.6's statement says "≥5 trigger cases per view" and there are 3 views (main / alt / mac). 5 × 1 ≠ 5 × 3. Either the threshold is over-claiming or the TC enumeration is under-claiming. (Architect's F-A-05 surfaces an orthogonal hole — missing triggers entirely; this finding is about the count mismatch on the trigger list that *is* listed.)
- **Recommendation:** Resolve toward per-view enumeration (15 cases). Edit TC-012 to enumerate `action_hex_page_*` / `action_a2l_tags_page_*` / `action_mac_records_page_*`, the three `_handle_search*` handlers, file-load + file-unload covering all three views. Combine with F-A-05's additions (parse-error branch, `_jump_to_tag`, tab/view switches).

### F-Q-06 — TC-009a marker-style assertion needs a concrete predicate
- **Severity:** minor
- **Location:** §5.2 TC-009a (line 266) — "no `Span` in `text.spans` covers the leading 2 cells with a non-default style".
- **Observation:** "Non-default style" is verifiable but underspecified. Rich `Text.spans` carries `Span(start, end, style)`; an empty marker would emit no span at all. The threshold should pin the assertion shape.
- **Recommendation:** Rewrite the bullet inside TC-009a as: "For each rendered row, no `Span` in `text.spans` overlaps columns `[row_offset, row_offset+2)`, OR if one does its `style` resolves to `Style.null()` / `''`." Keep the column-alignment sub-check separately.

### F-Q-07 — HLR-002 numeric threshold uses approximate / CSS-token language
- **Severity:** minor
- **Location:** HLR-002 line 108 — "width ≥ 78 columns, height = 100 % present, narrow-regime rule byte-identical to current".
- **Observation:** "height = 100 % present" is a token-grep, not a behavioural assertion. The integration TC-005 already pins the live shape (`#mac_hex_scroll.region.height == #mac_hex_pane.region.height`); HLR-002's threshold should match that. (Also note: architect's F-A-03 reopens the underlying `78` value question — the threshold here will need to be bumped in lockstep with whatever value Phase 1 lands on for `#mac_hex_pane { width }`.)
- **Recommendation:** Reword HLR-002 threshold to: "rendered `#mac_hex_pane.region.width ≥ <post-F-A-03 value>` at terminal width 120; `#mac_hex_scroll.region.height == #mac_hex_pane.region.height` at same size; `git diff` over the two `width-narrow` selectors reports 0 changed lines."

### F-Q-08 — `_handle_search` "miss after pagination" round-trip not pinned
- **Severity:** minor
- **Location:** LLR-001.2 line 135 + §5.2 TC-002.
- **Observation:** When `_first_visible_hex_address("main")` returns an address but `find_string_in_mem` returns `None`, current handler resets `last_search_address = None` (`app.py:5871`). The next Find Next should resume from the new first-visible address, not from address 0. LLR-001.2 doesn't say so explicitly; an LLR that doesn't pin this branch invites the bug to re-emerge on a future refactor.
- **Recommendation:** Add to LLR-001.2 acceptance criteria: "When `find_string_in_mem` returns `None`, the anchor stays `None` and the next `_handle_search` invocation again resumes from `_first_visible_hex_address(view)`." Add TC-002b that covers the round-trip.

### F-Q-09 — TC-010 monkeypatch target is import-path sensitive
- **Severity:** minor
- **Location:** §5.2 TC-010 (line 267).
- **Observation:** `app.py` imports the renderer via `from .hexview import render_hex_view_text`, which binds a local name `s19_app.tui.app.render_hex_view_text`. A monkeypatch on `s19_app.tui.hexview.render_hex_view_text` will not affect callers in `app.py`. Phase 3 could lose half a day on this.
- **Recommendation:** Add to TC-010: "The monkeypatch target is `s19_app.tui.app.render_hex_view_text` (the imported alias inside `app.py`), not the canonical `s19_app.tui.hexview.render_hex_view_text`."

### F-Q-10 — `_first_visible_hex_address` empty-`row_bases` fallback not pinned to a TC
- **Severity:** minor
- **Location:** LLR-001.2 acceptance criterion at line 141.
- **Observation:** The "empty / out-of-bounds → `start_address = None`" branch is informative-only; no TC anchors it. This is the exact guard that gets lost during refactoring.
- **Recommendation:** Extend TC-002 (or add TC-002c) with: when `app.current_file.row_bases == []` (or `_hex_window_start == len(row_bases)`), the post-pagination `_handle_search` call receives `start_address=None`.

### F-Q-11 — §5.3 acceptance criterion 4 uses a Unix-only command verb
- **Severity:** minor
- **Location:** §5.3 line 275 — `grep -nE "\bshould\b" .dev-flow/...`
- **Observation:** CI is Linux per `.github/workflows/tui-ci.yml`, so `grep` works there. The operator's box is Windows + PowerShell. A criterion that can't be re-executed on the operator's box invites silent skip. CLAUDE.md mandates the Grep tool, not raw `grep`.
- **Recommendation:** Reword to: "Independent re-check — `Grep --pattern '\bshould\b' --path .dev-flow/2026-05-26-batch-05/01-requirements.md` — returns 0 hits inside `### HLR-*` or `### LLR-*` blocks. Matches in rationale paragraphs are allowed."

### F-Q-12 — Coverage matrix walk: no orphans, no gaps (info only)
- **Severity:** info
- **Location:** §5.2 (matrix) — full walk.
- **Observation:** Every LLR (001.1, 001.2, 001.3, 002.1, 002.2, 002.3, 003.1, 003.2, 003.3, 003.4, 003.5, 003.6) maps to ≥1 TC. No TC is orphaned from an LLR. HLR roll-ups are explicit. §5.3 first bullet's "100 % LLRs covered" claim confirmed by independent walk.
- **Recommendation:** None. Recorded as info so the domain matrix shows the coverage check was actually performed.

### Verdict (qa-reviewer)

**Total findings:** 12 (1 Blocker, 3 Major, 7 minor, 1 info).

**Biggest concern:** F-Q-01 (wrong test path in LLR-003.3). Trivial to fix; must be fixed before Phase 3 because pytest will collection-fail silently rather than assertion-fail loudly. Architect's F-A-06 catches the same defect.

- [ ] OK to ship — no mitigations required from this domain.
- [x] OK to ship with the listed mitigations applied first (F-Q-01 blocker + F-Q-02/04/05 majors).
- [ ] Block

## 4. Findings (security-reviewer domain)

**Scope reviewed.** `.dev-flow/2026-05-26-batch-05/01-requirements.md` (HLR-001/002/003 and LLR-001.1..003.6). Relevant existing code: `s19_app/range_index.py::address_in_sorted_ranges`, `s19_app/tui/hexview.py::find_string_in_mem` (151–189), `s19_app/tui/app.py::_handle_goto` (5835–5849) and `_handle_search` (5810–5833), `s19_app/tui/app.py:1493` (`Static(..., markup=False)`).

**Attack surface assessment.** Pure-TUI display fix. No new I/O channel, no new file format, no new auth/session flow, no new outbound call, no new MCP/Composio/n8n integration, no subprocess spawn, no new path-resolution code (the batch explicitly leaves `.s19tool/` workarea writes and `resolve_input_path` untouched). No new Python dependency.

### F-S-01 — No findings (Severity: info)
- **What:** Reviewed the seven security checkpoints requested. All pass.
  - **Input validation:** `_handle_goto` keeps the existing `int(raw, 0)` + `ValueError` fail-closed; the new `address_in_sorted_ranges(...)` guard (`s19_app/range_index.py:39-68`) is bisect-based on Python `int`, so negative ints (bisect_right→0, candidate=-1→False), huge ints (Python ints are arbitrary precision; no overflow), and zero handle correctly. No int range coercion is needed.
  - **Sensitive data exposure:** The new status `Address 0x{addr:08X} not in loaded file.` echoes only the user-typed address (after re-formatting from their own parsed int). No file path, no memory byte, no project name, no environment variable is interpolated. Safe.
  - **Search / goto field injection:** `find_string_in_mem` (`hexview.py:151-189`) uses the query only via `query.encode(SEARCH_ENCODING)` and `bytes.find(needle)` — no shell, no SQL, no regex compile, no filesystem call, no `eval`. The goto query is consumed only by `int(raw, 0)` and then by bisect math. No injection sink.
  - **Marker glyph / Rich markup:** `▶ ` (U+25B6) is a literal in source (not user-controlled). The Static widget at `app.py:1493` is constructed with `markup=False`, so even if someone later swapped the literal for an attacker-controlled string, Rich would not re-interpret it. The LLR-003.3 acceptance criterion also forbids passing a `style=` argument, which removes the only other interpolation path. Defense-in-depth is already in place.
  - **`.s19tool/` workarea:** Out of scope (§1.2 explicitly excludes path resolution and project format). No incidental change.
  - **CI / test plan:** All proposed tests are pytest unit/integration cases driven through `App.run_test()` and `SimpleNamespace` fixtures; no network, no subprocess, no privileged op, no real filesystem writes outside pytest tmp.
  - **Dependency surface:** No new Python dependency declared or implied.
- **Where:** N/A (no defect).
- **Why it matters:** N/A — recorded as `info` so the matrix shows the domain was reviewed and cleared, not skipped.
- **Recommendation:** None. Proceed to Phase 3.

### Verdict
- [x] OK to ship — no mitigations required from this domain.
- [ ] OK to ship with the listed mitigations applied first
- [ ] Block

---

## 5. Phase-1 iteration #2 — re-confirmation (orchestrator, 2026-05-27)

After the Phase 2 gate forced iteration on 3 blockers + 7 majors, the `architect` agent applied all findings to `01-requirements.md`. The orchestrator then re-verified the structural and editorial fixes directly:

### 5.1 Blocker fixes confirmed
- **F-A-01 + F-A-02** ✓ — LLR-001.3 rewritten around the actual paging primitive (alt tab tag-selection via `_jump_to_tag` / `_handle_a2l_tag_find_next`); new normative LLR-001.4 covers the MAC tab record-selection trigger (`_on_mac_records_row_highlighted`). Both LLRs explicitly state that no `_<view>_hex_window_start` field exists for alt/mac and the trigger is the selection entry-point. The shared `_first_visible_hex_address(view: str)` helper is contracted with a cache-on-app-instance approach (cached inside each renderer call) — documented in LLR-001.4 acceptance and §6.2.
- **F-Q-01 / F-A-06** ✓ — `tests/test_hexview.py` → `tests/test_tui_hexview.py` everywhere in the file; the §5.2 `NOTE` annotation was removed.

### 5.2 Major fixes confirmed
- **F-A-03** ✓ — `#mac_hex_pane { width }` is now `82` throughout (HLR-002 threshold, LLR-002.1 statement + acceptance arithmetic, §5.1 inspection bullet, §5.2 TC-004, §6.2). The acceptance arithmetic recomputes to 82 = 2 + 10 + 47 + 2 + 16 + 1 + 4. The historical "78 sums to 82, undercounts the marker" lesson is recorded in §6.2.
- **F-A-04** ✓ — New LLR-002.4 ("The records pane retains a strictly-positive width at 120 cols") closes the symmetric invariant. TC-013 in §5.2 pins it.
- **F-A-05** ✓ — LLR-003.6 trigger list is now explicit per view: main has 7 triggers, alt has 6, mac has 6, including the `int(raw, 0)` parse-error branches in all three `_handle_goto*` handlers and the `_jump_to_tag` / `_handle_a2l_tag_find_next` / `_on_mac_records_row_highlighted` entry-points. Tab-switch policy is stated explicitly ("focus persists per view; cleared only on file-load/unload or per-view triggers"). The "≥17 trigger cases" threshold is enumerated, not approximated.
- **F-Q-02** ✓ — LLR-001.1/.2/.3/.4 and LLR-003.1/.2/.5/.6 are labeled `test (integration)`. §5.2 method columns match. Reason recorded in §6.2.
- **F-Q-03** ✓ — LLR-002.1/.2/.3/.4 are labeled `test (integration) + inspection`.
- **F-Q-04** ✓ — §5.1's `test (unit)` paragraph drops the `large_s19` / `large_mac` references; tiny purpose-built fixtures only. The 86f4910 `@pytest.mark.slow` policy is honoured.
- **F-Q-05** ✓ — LLR-003.6 numeric threshold spells out the ≥17 trigger × view enumeration, not `≥5 × 3`.

### 5.3 Minor fixes confirmed
- **F-A-07 (glyph)** ✓ — switched to ASCII `>` everywhere. §1.3 definitions, §2.5 assumptions, HLR-003 statement, LLR-003.3 statement + acceptance, §5.2 TC-009a, §6.2 design decisions. The U+25B6 character now appears only once in the file: in §6.2's historical "the choice of ASCII over `▶` avoids East-Asian Width ambiguity" rationale line. wcwidth assertion no longer needed.
- **F-A-08** ✓ — LLR-003.5 acceptance criterion now documents that `_apply_goto` is a Phase-1 derivation bounded to `app.py`.
- **F-A-09** ✓ — covered by the F-Q-02 relabel; method tiers match between §4 and §5.2.
- **F-Q-06** ✓ — TC-009a marker-style assertion rewritten with a concrete span predicate.
- **F-Q-07** ✓ — HLR-002 threshold reworded to live-shape (`region.width >= 82`, `region.height` equal).
- **F-Q-08** ✓ — LLR-001.2 acceptance includes the miss-after-pagination round-trip; TC-002b added.
- **F-Q-09** ✓ — TC-010 monkeypatch path note added (`s19_app.tui.app.render_hex_view_text`).
- **F-Q-10** ✓ — TC-002c covers the empty-`row_bases` fallback.
- **F-Q-11** ✓ — §5.3 acceptance criterion reworded to Grep-tool wording (PowerShell-compatible).

### 5.4 Independent orchestrator gates
- `Grep '^- \*\*Statement:\*\* .*\bshould\b'` over the requirements file: **0 hits** ✓.
- `Grep 'test_hexview\.py'` (without `tui`): **0 hits** ✓.
- `Grep 'width: 78'`: **0 hits in normative rules** ✓ (one occurrence in §6.2 historical-rationale paragraph, allowed).
- `Grep '▶'`: **1 hit**, in §6.2 historical-rationale paragraph explaining why ASCII was chosen — informative ✓.
- HLR/LLR counts: 3 HLR / 14 LLR (was 3 / 11) — LLR-001.4 (MAC selection) and LLR-002.4 (records-pane invariant) added. Index in §1.5 updated. ✓.

### 5.5 Open items deferred to Phase 3
1. The Phase-3 implementer must verify `_handle_goto_alt` and `_handle_goto_mac` actually exist as separate methods (LLR-003.5 / LLR-003.6 assume they do; if they're shared via a common helper instead, the parse-error trigger enumeration collapses).
2. The cache contract for `_first_visible_hex_address("alt" | "mac")` lives on the app instance and is set inside each `update_<view>_hex_view()` renderer call — Phase 3 must wire this in the renderer, not in the search handler.

### 5.6 Verdict (iteration #2)
- Blockers: 0 (all 3 closed).
- Majors: 0 (all 7 closed).
- Minors: 0 (all 11 closed).
- Open items: 2 implementer verifications for Phase 3 (5.5 above) — not blockers, just things the implementer must confirm during Increment 1.
- **Recommended action: approve → advance to Phase 3.**

