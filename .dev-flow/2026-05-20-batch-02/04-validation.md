# Validation — s19_app — 2026-05-20-batch-02

**Phase:** 4 — Validation
**Iteration:** 1
**Date:** 2026-05-21
**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Source artifacts under validation:** `.dev-flow/2026-05-20-batch-02/01-requirements.md` (§5 Validation Strategy + §5.8 AC-B1..AC-B9), `02-review.md` (Phase 2 closure), `03-increments/increment-001.md` … `increment-012.md`, `increment-plan.md`, `keymap-proposal.md`
**Validator:** qa-reviewer agent
**Branch:** `dev-flow/batch-02-direction-b-restyle` @ `701a849`
**Environment:** Windows 11, Python 3.12.7, pytest 8.4.2, `textual` 8.0.2, `pytest-textual-snapshot` 1.1.0 + `syrupy` 4.8.0 (dev extra installed)

---

## 0. Summary

Phase 3 delivered 12 increments restyling the `s19tui` TUI to Direction B (rail + command bar + 8 single-context screens), all view-layer-only. Phase 4 re-executed the §5 validation strategy independently on a Windows host: the full `pytest -q` suite, the `-m snapshot` subset, the `-m "not slow"` subset, the engine-freeze `git diff`, and the inspection checklists for the `inspection`-method TCs.

The pytest baseline carried out of increment 12 — **419 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** — was reproduced exactly in this Phase 4 run with no drift. The engine-freeze `git diff` over the seven frozen modules is **empty** (zero bytes changed). All 38 active test cases (TC-001..TC-039 plus TC-016-S; TC-005 retired N/A) have an asserting test that passes. All 15 HLR and 38 LLR verdict `pass`. All nine acceptance criteria AC-B1..AC-B9 are **met**.

| Metric | Value |
|---|---|
| Total active TCs evaluated | 38 (TC-001..TC-039 + TC-016-S; TC-005 retired — N/A, no verdict) |
| TC pass | 38 |
| TC partial | 0 |
| TC fail (blocker) | 0 |
| TC fail (non-blocker) | 0 |
| HLR verdicts (15) | 15 pass · 0 partial · 0 fail |
| LLR verdicts (38) | 38 pass · 0 partial · 0 fail |
| AC-B met | 9 of 9 (AC-B1..AC-B9) |
| AC-B not-met | 0 |
| Open blocker findings at the gate | 0 |
| pytest result | 419 passed / 2 skipped / 3 xfailed / 0 failed; 27 snapshots passed |

**Verdict: `pass-with-gaps`.** The suite is green, the engine is frozen, every requirement and every AC is satisfied by recorded evidence. **No blocker-level fail was found — no rollback to Phase 3 is forced.** The `-with-gaps` qualifier records four documentary / environmental gaps (manual real-terminal TUI verification not performed in this headless environment; `ruff` not installed for increments 1–11; the TC-030 global-`BINDINGS`-vs-per-screen-`Binding` design realization; the CV-03 empty-state-not-snapshotted note). None of the four is a correctness defect, none gates the batch, and all four were already disclosed in the increment packets — they are carried to Phase 5/6, not re-opened.

> **Increment-13 reconciliation note (review-feedback re-validation touch).** After this Phase-4 run, increment 13 amended **LLR-009.1** — the A2L Explorer hex-pane layout was changed from the iteration-3 two-regime split (fixed 40-column hex pane at `>= 120` columns / 35% below 120) to a **flat 3/7 hex : 4/7 tags proportional ratio** that holds at every terminal width (`#a2l_hex_pane { width: 3fr }`, `#a2l_tags_pane { width: 4fr }`), because the fixed 40-column hex pane was too narrow to render the hex view correctly. MAC View (LLR-010.1) is unchanged. **TC-019** was reconciled to assert the flat 3/7 (≈42.9%) ±3-point ratio at 80×24, 120×30 and 160×40; the **6 `a2l-*` `pytest-textual-snapshot` baselines** were regenerated; the other 21 baselines are unchanged. The full suite still holds **419 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** — TC-019's two width tests were updated in place, not added, so the test count did not drift. The TC-019 row (§4), the LLR-009.1 / HLR-009 verdicts (§5), and the AC-B7 / AC-B9 entries (§6) below carry this amendment; all stay `pass`. See `03-increments/increment-013.md`.

---

## 1. pytest baseline

Executed at Phase 4 start against the worktree (Windows 11, Python 3.12.7, pytest 8.4.2), full suite:

```
python -m pytest -q
...
--------------------------- snapshot report summary ---------------------------
27 snapshots passed.
419 passed, 2 skipped, 3 xfailed in 162.81s (0:02:42)
```

Match against the increment-12 closing baseline (`419 passed / 2 skipped / 3 xfailed / 0 failed, 27 snapshots passed`) — **identical, zero drift.** The increment-by-increment progression (275 → 284 → 291 → 308 → 314 → 327 → 338 → 347 → 359 → 373 → 389 → 419) reconciles: each increment added exactly its own new cases and never regressed a prior one.

**Snapshot subset** — `python -m pytest -q -m snapshot`:
```
27 snapshots passed.
27 passed, 397 deselected in 23.29s
```
The 27-baseline `pytest-textual-snapshot` matrix re-matches its committed `.svg` baselines with no diff. The `tests/__snapshots__/test_tui_snapshot/` directory holds **exactly 27** `.svg` files — verified: 24 restyled (`{workspace,a2l,mac,issues}` × `{compact,comfortable}` × `{80x24,120x30,160x40}`) + 3 scaffold (`{map,patch,diff}` at `comfortable-120x30`) — matching the §5.5 narrowed matrix exactly.

**Non-slow subset** — `python -m pytest -q -m "not slow"`:
```
27 snapshots passed.
416 passed, 2 skipped, 3 deselected, 3 xfailed in 160.78s (0:02:40)
```
3 deselected = the 3 `slow`-marked stress/perf smoke tests; the remaining 416 + 3 = 419 reconciles with the full run. No drift.

**Snapshot-file non-snapshot tests** — `python -m pytest -q tests/test_tui_snapshot.py -m "not snapshot"`:
```
3 passed, 27 deselected in 1.38s
```
The 3 library-independent tests = the two CV-04 119/120-column boundary checks + the LLR-007.2 public-fixture-source assertion. The `snapshot` marker correctly deselects the 27 baseline cells on a constrained environment.

**The 3 documented `xfail` rows and the 2 skips** are pre-existing baseline cases inherited from batch-01 (unchanged through all 12 increments — every increment packet records "2 skipped + 3 xfailed unchanged (pre-existing)"). They are **not** Direction B cases and carry no Direction B finding. No unexpected `xpass` was observed.

Per the §5.8 AC-B8 / dev-flow Hard rule: an unexpected pytest failure would be a `blocker`. **None observed → no Phase 4 blocker.**

---

## 2. Engine-freeze inspection (HLR-014 / LLR-014.1 / TC-031)

The §5 strategy assigns `inspection` (primary) + `analysis` (supporting) to LLR-014.1. The written inspection method is the `git diff` over the frozen engine surface plus the cosmetic-only rubric.

**`git diff --stat main` over the engine surface** (run in Phase 4):
```
git diff --stat main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
  s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
[empty output]   EXIT:0

git diff --name-only main -- (same paths)
[empty output]
```

**Result: zero bytes changed across all seven frozen modules** (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`). The TC-031 cosmetic-only rubric (Q-11 — whitespace/comment/import-order = cosmetic; logic/constant/signature change = violation) is **vacuously satisfied**: there is nothing to classify because nothing changed. `render_a2l_view` / `a2l_render.py` (the view-layer carve-out under A-01) were not edited either — the A2L Explorer re-layout (increment 6) re-nested containers in `app.py` only and reused every A2L widget subtree verbatim.

**Engine test files** — `git diff --stat main` over `test_core_srecord_validation.py`, `test_hexfile.py`, `test_range_index.py`, `test_validation_engine.py`, `test_tui_a2l.py`, `test_tui_mac.py`: **empty, EXIT:0** — byte-identical to `main`. TC-032's "engine test files unmodified" assertion is re-confirmed.

**`color_policy.py` inspection** (TC-012 / LLR-005.1 corroboration): `SEVERITY_CLASS_MAP` (5 entries), `css_class_for_severity`, `FOCUS_HIGHLIGHT_STYLE = "bold yellow"`, `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"` all present and byte-identical to `main`. No new `ValidationSeverity` value.

**Verdict — engine freeze: PASS.** This is the master no-regression requirement (HLR-014) and it holds at the strictest possible level — zero diff.

---

## 3. Inspection-checklist results (TC-012, TC-016, TC-031, TC-033, TC-039)

The §5.1 strategy commits each `inspection`-method TC to an inline checklist. Each was applied in Phase 4 against the live tree.

### TC-012 — Theme token budget (LLR-005.1)
Inspected `s19_app/tui/styles.tcss` against the §5.3 inline checklist:

| Checklist item | Result | Evidence |
|---|---|---|
| Exactly one accent hue / accent variable | PASS | `$accent-calm: #4ec9d4;` (line 26) is the single declared accent token; the file comment states "exactly ONE accent hue". |
| All five `sev-*` classes present, unchanged | PASS | `.sev-ok`, `.sev-error`, `.sev-warning`, `.sev-info`, `.sev-neutral` rules present (lines 411–427). |
| `MAC_ADDRESS_OVERLAY_STYLE` preserved | PASS | `color_policy.py` byte-identical; `.mac_out_of_range` rule preserved in `styles.tcss`. |
| `FOCUS_HIGHLIGHT_STYLE` preserved | PASS | `color_policy.py` byte-identical. |
| No light-theme variant | PASS | `test_tui_theme.py::test_tc_012_no_light_theme_variant` asserts no `light` token/selector — green. |
| No severity class added/dropped/renamed | PASS | `test_tc_012_severity_class_names_match_color_policy` asserts the `.tcss` `sev-*` set equals `SEVERITY_CLASS_MAP` values — green. |

Backed by 16 passing `test_tui_theme.py` cases. **All six checklist items pass.**

### TC-016 — Density layout integrity, no overlap/clipping (LLR-007.1)
Inspection checklist corroborated by the TC-016-S snapshot verdict (§4 below) and the CV-04 boundary tests. The 27 SVG baselines render every screen × density × size with no overlap and no clip; the two CV-04 tests confirm the proportional regime at width 119 and the fixed regime at width 120. **PASS** (corroborating; the snapshot is the primary verdict).

### TC-031 — Engine modules + snapshot no-leak (LLR-014.1 / LLR-007.2)
(a) Engine-diff classification — covered in §2: zero diff, cosmetic rubric vacuously satisfied. **PASS.**
(b) Snapshot no-leak — increment 12's S-2 grep over all 27 committed `.svg` baselines found **0 matches** for client-case directory names (`case_0[1-6]`), proprietary symbol prefixes, or client artifact names; every baseline embeds only synthetic `snap.*` / `MEAS_*` / `CHAR_*` generator content. **PASS.**

### TC-033 — Modals adopt Calm Dark theme (LLR-015.1)
Inspection checklist applied to `screens.py` + the `styles.tcss` modal block:

| Checklist item | Result | Evidence |
|---|---|---|
| Each modal references Calm Dark tokens, not hard-coded color | PASS | `screens.py` declares no per-screen `DEFAULT_CSS`; the modal block in `styles.tcss` styles via `$accent-calm` / `$bg-*` / `$fg-*` / `$rule`. |
| No off-theme / hard-coded hex color | PASS | `test_tc033_..._no_hardcoded_color` green; the increment-8 render smoke read back `#4EC9D4` (= `$accent-calm`) for all 3 modals. |
| Single shared accent — no second accent | PASS | `variant="primary"` was deliberately avoided (would pull Textual's `$primary`); confirm-button uses `.modal-confirm` → `$accent-calm`. |
| No light-theme color | PASS | TC-033 ×4 green. |
| Severity coloring routes through `sev-*` | PASS | TC-033 asserts no non-canonical `sev-*` class in the modal block. |

Backed by 4 passing `TC-033` cases. **All five checklist items pass.**

### TC-039 — Command bar logs no typed text or file content (LLR-013.3)
Inspection checklist applied to `command_bar.py` + `app.py` wiring + the `.s19tool/logs/` surface:

| Checklist item | Result | Evidence |
|---|---|---|
| No code path writes typed find/go-to/palette text to the log | PASS | TC-039 AST-inspects `command_bar.py` — no `logger`/`logging` reference, no `.info`/`.debug`/`.warning` call. |
| No rendered file content written to the log by the command bar | PASS | TC-039 driven-session assertion: typed find/palette text never appears in the produced log file. |
| Command bar's only status surface is `set_status` | PASS | `on_command_bar_find`/`_goto` route to existing `_handle_search`/`_handle_goto`; malformed input via `set_status`. |
| No new log level/logger/handler raises verbosity | PASS | No logging added; pre-batch `update_hex_view` "Hex view focused at 0x..." line is unchanged pre-existing behavior (documented in increment 4 §5, confirmed acceptable). |
| Driven session shows no typed text in the log | PASS | TC-039 ×2 green. |

Backed by 2 passing `TC-039` cases. **All five checklist items pass.**

---

## 4. Per-TC pass/fail table

Verdict legend: `pass` = an asserting test is green / the inspection checklist is fully satisfied in this Phase 4 run; `N/A` = retired, no verdict. Every TC verdict below is backed by a Phase 4 evidence run.

| TC | Title | Covers | Method | Verdict | Evidence (Phase 4) |
|----|-------|--------|--------|---------|--------------------|
| TC-001 | Rail composes 8 ordered items on keys 1–8 | LLR-001.1 / HLR-001 | test | pass | `test_tui_directionb.py` `tc001` ×2 — green in the 419-pass run; increment-3 rail smoke composed exactly 8 items. |
| TC-002 | Exactly one rail item active; Workspace at startup | LLR-001.2 / HLR-001 | test | pass | `tc002` ×2 — single-active invariant across key + click path; Workspace active at startup. |
| TC-003 | Rail activation swaps workspace content | LLR-002.1 / HLR-002 | test | pass | `tc003` — exactly one `#screen_*` visible after each `action_show_screen`. |
| TC-004 | Bookmarks slot shows non-blocking placeholder | LLR-002.2 / HLR-002 | test | pass | `tc004` ×3 — Bookmarks activation raises no exception; "coming soon" text; no persistence surface. |
| TC-005 | Bookmarks slot omitted cleanly | LLR-002.2 / HLR-002 | — | **N/A** | Retired (OQ-3 resolved to "keep eight rail items"). Produces no verdict; superseded by TC-004. |
| TC-006 | Command bar present on every screen | LLR-003.1 / HLR-003 | test | pass | `tc006` — command bar mounted on all 8 rail screens. |
| TC-007 | Command palette lists every `BINDINGS` action | LLR-003.2 / HLR-003 | test+inspection | pass | `test_tui_commandbar.py` `tc007` ×2 — full `BINDINGS` set iterated; each action has one palette entry dispatching the same action id. |
| TC-008 | `/` focuses find; routes to `find_string_in_mem`; suppression | LLR-004.1/004.5/004.6 / HLR-003,004 | test | pass | `tc008` ×5 — `/` focus from every screen; find routes to `find_string_in_mem`; `g`/digit/`,`/`+` suppressed while focused; malformed input via `set_status`; AST guard — no new search/decode code. |
| TC-009 | `g` focuses go-to; `_handle_goto` effect; suppression | LLR-004.2/004.5 / HLR-003,004 | test | pass | `tc009` ×4 — `g` focus; submit → hex scrolled + `Goto 0x…` status; suppression; malformed via `set_status`; AST guard — no new address parser. |
| TC-010 | `Ctrl+K` opens/focuses the command palette | LLR-004.3 / HLR-004 | test | pass | `tc010` — `Ctrl+K` opens/focuses the palette from every Direction B screen. |
| TC-011 | No pre-batch binding unreachable; 1/2/3 remap is supersession | LLR-004.4 / HLR-004,013 | test+inspection | pass | `tc011` ×2 — every pre-batch `BINDINGS` action keeps a key/palette path; `1`/`2`/`3`→rail remap and `#view_bar` removal recorded as intended supersession. |
| TC-012 | Theme token budget — one accent + five `sev-*`, dark only | LLR-005.1 / HLR-005 | inspection | pass | §3 above — all six checklist items pass; 16 `test_tui_theme.py` cases green. |
| TC-013 | Severity colors from `SEVERITY_CLASS_MAP`; rule per `sev-*` | LLR-005.2 / HLR-005,014 | test | pass | `test_tui_theme.py` TC-013(a) round-trip anchor + TC-013(b) per-`sev-*` rule assertion — green. |
| TC-014 | `Ctrl+D` cycles density compact↔comfortable | LLR-006.1 / HLR-006 | test | pass | `tc014` — density root class cycles; active mode surfaced. |
| TC-015 | Startup density default is Comfortable | LLR-006.2 / HLR-006 | test | pass | `tc015` — startup density class is the Comfortable variant (OQ-2). |
| TC-016 | Density layout integrity — no overlap/clipping (checklist) | LLR-007.1 / HLR-007 | inspection | pass | §3 above; CV-04 boundary tests green (proportional@119, fixed@120). Corroborates TC-016-S. |
| TC-016-S | Density layout integrity — snapshot SVG | LLR-007.1/007.2 / HLR-007 | test (snapshot) | pass | `-m snapshot` → 27 snapshots passed; baseline dir holds exactly 27 `.svg` matching the §5.5 matrix; S-2 leak grep 0 matches. |
| TC-017 | Workspace 3 named panes at two-regime tolerances | LLR-008.1 / HLR-008 | test+inspection | pass | `tc017` ×3 — fixed regime 120×30/160×40 (left 22±2, right 40±2, rail 22, center `1fr`), proportional regime 80×24 (left 24%±3, right 30%±3, rail 4±1, center `1fr` strictly positive). |
| TC-018 | Workspace data wiring unchanged; hex caps honored | LLR-008.2 / HLR-008,014 | test | pass | `tc018` ×3 — panes populate via `update_sections`/`update_hex_view`; `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` unchanged. |
| TC-019 | A2L Explorer hex pane at the flat 3/7 : 4/7 ratio | LLR-009.1 / HLR-009 | test+inspection | pass | `tc019` (increment-13 amendment) — `test_tc019_a2l_hex_pane_three_sevenths_at_wide_sizes` asserts the hex pane is 3/7 (≈42.9%) ±3 points at 120×30 / 160×40; `test_tc019_a2l_hex_pane_three_sevenths_at_min_size` asserts the same flat 3/7 ratio at 80×24 (no 120-column regime split for A2L); `test_tc019_a2l_pane_order_table_then_hex` unchanged. The A2L symbol `DataTable` keeps the strictly-positive 4/7 (≈57.1%) remainder. 6 regenerated `a2l-*` snapshot baselines match the new layout. |
| TC-020 | A2L filtering, paging, jump preserved | LLR-009.2 / HLR-009,014 | test | pass | `tc020` — field/mode filtering, `+`/`-` + button paging, row-select jump all work on the restyled screen. |
| TC-021 | MAC View table + hex pane at two-regime tolerances | LLR-010.1 / HLR-010 | test+inspection | pass | `tc021` — MAC `1fr` table + 40±2 hex pane (fixed); 35%±4 (proportional); rail 4±1. |
| TC-022 | MAC paging, coloring, overlay, jump preserved | LLR-010.2 / HLR-010,014 | test | pass | `tc022` — MAC paging, severity coloring, overlay highlight, row-select jump preserved. |
| TC-023 | Issues Report is a dedicated rail screen | LLR-011.1 / HLR-011 | test | pass | `tc023` ×3 — `#validation_issues_list` is `#screen_issues` primary content; `#workspace_carryover` fully removed; status/log widgets re-homed. |
| TC-024 | Issues coloring, filters, paging, jump preserved | LLR-011.2 / HLR-011,014 | test | pass | `tc024` ×5 — severity coloring round-trips; All/Errors/Warnings filters, paging, row-select jump-to-source. |
| TC-025 | Memory Map scaffold renders coverage from `LoadedFile` | LLR-012.1 / HLR-012 | test | pass | `tc025` ×5 — ranges/gaps render from `LoadedFile.ranges`/`range_validity`; no new coverage computation. |
| TC-026 | Patch Editor view shell renders; inputs inert | LLR-012.2 / HLR-012 | test | pass | `tc026` ×4 — before/after panes + address/bytes inputs render; no `on_input_*` handler, no apply/undo/redo; deferral notice shown. |
| TC-027 | A↔B Diff renders three columns | LLR-012.3 / HLR-012 | test | pass | `tc027` ×4 — three columns with constant labelled PLACEHOLDER rows; no second-file load `Button`; deferral notice shown. |
| TC-028 | Deferred-logic guard — no new processing module | LLR-012.4 / HLR-012 | test+inspection | pass | `tc028` ×10 — `screens_directionb.py` imports no `bincopy`/`pya2l`/`crcmod`; none in `pyproject.toml`; no new module at `s19_app/` root; all scaffolds activate without error. |
| TC-029 | Every new control keyboard-reachable; suppression | LLR-013.1/004.5 / HLR-013 | test | pass | `tc029` ×4 — rail items, command-bar inputs, density toggle, scaffold inputs all keyboard-reachable; single-key suppression both directions. |
| TC-030 | Status bar shows the active screen's bindings | LLR-013.2 / HLR-013 | test | pass | `tc030` ×3 — keymap §2 global footer set present on all 8 screens; keymap §3 paging keys present on the 4 paging screens; footer never drifts from `active_bindings`. See §7 Gap 3 (design realization note). |
| TC-031 | Engine modules no behavioral change; no snapshot leak | LLR-014.1/007.2 / HLR-014,007 | inspection+analysis | pass | §2 + §3 — `git diff main` empty for all 7 engine modules; 0 client tokens in any of the 27 `.svg`. |
| TC-032 | Existing pytest suite passes unchanged | LLR-014.2 / HLR-014 | test | pass | `tc032` ×3 + the full 419-pass run; 9 engine test files byte-identical to `main`; no `skip` in engine tests; no engine monkeypatch. |
| TC-033 | Modals adopt the Calm Dark theme | LLR-015.1 / HLR-015 | inspection | pass | §3 above — all five checklist items pass; 4 `TC-033` cases green. |
| TC-034 | Modal behavior — project-file rules + workarea preserved | LLR-015.2 / HLR-015,014 | test | pass | `tc034` ×5 — `validate_project_files` cardinality, `copy_into_workarea` containment, `..\..\` traversal containment, `SaveProjectPayload` intact. |
| TC-035 | Rail items render Unicode glyph + ASCII fallback | LLR-001.3 / HLR-001 | test+inspection | pass | `tc035` ×3 — Unicode glyphs `◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` match the normative table; distinct ASCII fallbacks; ASCII mode renders without error. |
| TC-036 | Command palette filters as the user types | LLR-003.3 / HLR-003 | test | pass | `tc036` — typing narrows the visible command list (24→1 in the increment-4 smoke); clearing restores it. |
| TC-037 | Rail navigation before any load shows empty-state panel | LLR-002.3 / HLR-002 | test | pass | `tc037` ×3 + the increment-9 rewrite — every rail screen shows a non-blank empty-state panel with no file loaded; no exception. |
| TC-038 | Project name + A2L filename stay visible after Issues move | LLR-011.3 / HLR-011,013 | test | pass | `tc038` — project name + A2L filename render in the command bar, visible on every Direction B screen after the Issues table leaves the Status tile (`R-TUI-016` not regressed). |
| TC-039 | Command bar logs no typed text or rendered content | LLR-013.3 / HLR-003,013 | inspection | pass | §3 above — all five checklist items pass; 2 `TC-039` cases green. |

**Roll-up:** 38 active TCs · **38 pass** · 0 partial · 0 fail. TC-005 retired N/A (no verdict). The 39 numbered cases (TC-001..TC-039) minus the 1 retired (TC-005) plus TC-016-S = 38 active, all green — matching the §5.3 / AC-B1 coverage count exactly.

---

## 5. Per-requirement verdict

### 5.1 High-level requirements (15)

| HLR | Title | Verdict | Evidence |
|-----|-------|---------|----------|
| HLR-001 | Activity rail navigation | pass | TC-001, TC-002, TC-035 — 8 ordered items, single active marker, glyph table. |
| HLR-002 | Rail screen swap | pass | TC-003, TC-004, TC-037 — content swap, Bookmarks placeholder, empty state. |
| HLR-003 | Top command bar | pass | TC-006, TC-007, TC-036 — present on every screen, palette population, type-to-filter. |
| HLR-004 | Command-bar key bindings | pass | TC-008, TC-009, TC-010, TC-011 — `/`/`g`/`Ctrl+K` focus + binding regression guard. |
| HLR-005 | Calm Dark theme | pass | TC-012, TC-013 — one accent + five `sev-*`, dark-only, severity source-of-truth intact. |
| HLR-006 | Density toggle | pass | TC-014, TC-015 — `Ctrl+D` cycle; Comfortable default. |
| HLR-007 | Density layout integrity | pass | TC-016-S (27 snapshots passed), TC-016 (checklist + CV-04 boundary). |
| HLR-008 | Workspace 3-pane re-layout | pass | TC-017, TC-018 — three named panes, two-regime widths, data wiring unchanged. |
| HLR-009 | A2L Explorer re-layout | pass | TC-019 (increment-13 — flat 3/7 : 4/7 A2L hex/tags ratio), TC-020 — restyled layout; filtering/paging/jump preserved. |
| HLR-010 | MAC View re-layout | pass | TC-021, TC-022 — restyled layout; paging/coloring/overlay/jump preserved. |
| HLR-011 | Validation Issues screen | pass | TC-023, TC-024, TC-038 — dedicated rail screen; behavior preserved; labels relocated. |
| HLR-012 | New view scaffolds | pass | TC-025, TC-026, TC-027, TC-028 — Memory Map / Patch Editor / A↔B Diff shells; deferred-logic guard. |
| HLR-013 | Keyboard reachability + status bar | pass | TC-029, TC-030, TC-039 — every control keyboard-reachable; footer bindings; no command-bar logging. |
| HLR-014 | Data-processing behavior preserved | pass | TC-031 (zero engine diff), TC-032 (419-pass suite, engine tests unmodified). Master no-regression — strictest level. |
| HLR-015 | Modal re-skin | pass | TC-033, TC-034 — Calm Dark adoption; `validate_project_files` + workarea unchanged. |

**15 HLR · 15 pass · 0 partial · 0 fail.**

### 5.2 Low-level requirements (38)

| LLR | Verdict | TC / evidence | LLR | Verdict | TC / evidence |
|-----|---------|---------------|-----|---------|---------------|
| LLR-001.1 | pass | TC-001 | LLR-008.1 | pass | TC-017 |
| LLR-001.2 | pass | TC-002 | LLR-008.2 | pass | TC-018 |
| LLR-001.3 | pass | TC-035 | LLR-009.1 | pass | TC-019 (increment-13 — flat 3/7 ratio) |
| LLR-002.1 | pass | TC-003 | LLR-009.2 | pass | TC-020 |
| LLR-002.2 | pass | TC-004 | LLR-010.1 | pass | TC-021 |
| LLR-002.3 | pass | TC-037 | LLR-010.2 | pass | TC-022 |
| LLR-003.1 | pass | TC-006 | LLR-011.1 | pass | TC-023 |
| LLR-003.2 | pass | TC-007 | LLR-011.2 | pass | TC-024 |
| LLR-003.3 | pass | TC-036 | LLR-011.3 | pass | TC-038 |
| LLR-004.1 | pass | TC-008 | LLR-012.1 | pass | TC-025 |
| LLR-004.2 | pass | TC-009 | LLR-012.2 | pass | TC-026 |
| LLR-004.3 | pass | TC-010 | LLR-012.3 | pass | TC-027 |
| LLR-004.4 | pass | TC-011 | LLR-012.4 | pass | TC-028 |
| LLR-004.5 | pass | TC-008/009/029 | LLR-013.1 | pass | TC-029 |
| LLR-004.6 | pass | TC-008 (find-routing + AST guard) | LLR-013.2 | pass | TC-030 (see §7 Gap 3) |
| LLR-005.1 | pass | TC-012 | LLR-013.3 | pass | TC-039 |
| LLR-005.2 | pass | TC-013 | LLR-014.1 | pass | TC-031 (zero engine diff) |
| LLR-006.1 | pass | TC-014 | LLR-014.2 | pass | TC-032 (419-pass suite) |
| LLR-006.2 | pass | TC-015 | LLR-015.1 | pass | TC-033 |
| LLR-007.1 | pass | TC-016-S, TC-016 | LLR-015.2 | pass | TC-034 |
| LLR-007.2 | pass | TC-016-S, TC-031 (0-leak grep) | | | |

**38 LLR · 38 pass · 0 partial · 0 fail.** Every LLR maps to at least one passing TC; the iteration-2 additions (LLR-001.3, LLR-002.3, LLR-003.3, LLR-004.5) and iteration-4 additions (LLR-004.6, LLR-007.2, LLR-011.3, LLR-013.3) are all covered and green.

---

## 6. Batch acceptance criteria (AC-B1..AC-B9)

| AC | Statement (abridged) | Verdict | Evidence |
|----|----------------------|---------|----------|
| **AC-B1** | Full traceability — every HLR (15) and LLR (38) maps to ≥1 TC; every active TC has a recorded pass. | **met** | §4 + §5 — 15 HLR + 38 LLR all map to TCs; 38/38 active TCs pass; TC-005 retired N/A produces no verdict. No requirement lacks a validation method. |
| **AC-B2** | No-regression suite green — `pytest -q` passes; engine/parser/validation tests pass with zero source modification; no silent skip. | **met** | §1 — 419 passed / 0 failed. §2 — `git diff main` empty for the 9 engine test files. TC-032 confirms no `skip` marker in engine tests; the 2 skips + 3 xfails are pre-existing batch-01 baseline cases, not Direction B. |
| **AC-B3** | Severity policy intact — `SEVERITY_CLASS_MAP` + `sev-*` names unchanged; no new `ValidationSeverity`; round-trip test passes. | **met** | §2 — `color_policy.py` byte-identical. TC-012 / TC-013 green; the 5 `sev-*` classes present and unchanged in `styles.tcss`. |
| **AC-B4** | Hex-view caps intact — `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` unchanged. | **met** | TC-018 pins all four to their literal pre-batch values; `hexview.py` not in the touched-file set of any increment. |
| **AC-B5** | Project-file rules intact — `validate_project_files` + `.s19tool/` workarea / path resolution unchanged. | **met** | TC-034 — `validate_project_files` cardinality + `copy_into_workarea` containment + `..\..\` traversal containment all green; `workspace.py` not touched by any increment. |
| **AC-B6** | Keyboard reachability intact — no pre-batch `BINDINGS` action unreachable; every new control has a key path. | **met** | TC-011 (every pre-batch action keeps a key/palette path; 1/2/3 remap is intended supersession), TC-029 (every new control keyboard-reachable), TC-030 (footer bindings) — all green. |
| **AC-B7** | Layout verdict — every screen renders cleanly in both densities at {80×24,120×30,160×40}, two-regime layout (A2L Explorer on the increment-13 flat 3/7 : 4/7 ratio); verified by the 27-baseline snapshot; baselines use public fixtures only. | **met** | TC-016-S — 27 snapshots passed; the matrix matches §5.5 exactly (the 6 `a2l-*` baselines regenerated by increment 13 for the flat 3/7 A2L layout); the S-2 leak grep over all 27 `.svg` returns 0 client tokens (LLR-007.2). TC-016 + CV-04 corroborate; TC-019 pins the flat A2L 3/7 ratio numerically. |
| **AC-B8** | No blocker fails — zero blocker-severity fails; any non-blocker fail logged with disposition. | **met** | §1 — 0 failed in the full suite; §4 — 0 TC fails of any severity. No non-blocker fail to log. |
| **AC-B9** | Open questions resolved — all 13 OQ resolved; the A-03 fixed-width-vs-80×24 contradiction closed by the two-regime layout. Increment-13 amendment: A2L pane split superseded *for A2L only* by a flat 3/7 : 4/7 ratio. | **met** | `02-review.md` Phase 2 closure records all 24 findings (incl. A-03) CLOSED; OQ-1..OQ-13 resolved in §5.7. TC-017/021 assert the two-regime layout numerically; TC-019 (increment-13 amended) asserts the flat 3/7 : 4/7 A2L ratio at all three sizes; CV-04 confirms the 119/120 breakpoint (unchanged — A2L exception is width-flat, MAC View still two-regime). No residual concern. |

**9 of 9 acceptance criteria met. 0 not-met.**

---

## 7. Gaps

Four gaps are recorded. **None is a correctness defect, none is a blocker, none gates the batch.** All four were already disclosed in the increment packets; they are listed here for the Phase 5 post-mortem / Phase 6 docs sweep, not re-opened as findings.

### Gap 1 — Manual real-terminal TUI verification not performed (headless environment)
**Severity:** low (documentary). **Status:** open — deferred.
All Phase 3 verification and this Phase 4 run are headless (`App.run_test()` / `pytest` / computed-style read-back). Increments 6, 7, 8, 9, 10 each carry a "Manual TUI pass" pending item — eyeballing real-terminal rendering of the restyled screens, the relocated status bar, the modals' dimmed backdrop, the Memory Map fill bars, the Patch/Diff scaffolds, and resize behavior across the 120-column breakpoint in a live `s19tui`. This Phase 4 environment is headless and cannot launch an interactive terminal session, so the manual pass was **not** executed here. **Mitigation:** the 27-baseline `pytest-textual-snapshot` matrix renders the actual SVG output of every restyled/scaffold screen at every density × size and is the automated layout-drift guard; the CV-04 tests confirm the resize breakpoint. The residual unguarded surface is purely subjective real-terminal aesthetics (border-glyph tone, font-metric rendering, mouse hit-testing). **Recommendation:** Javier runs the increment-6/7/8/9/10 manual checklists (`s19tui --load examples/case_01_basic_valid/firmware.s19`, exercise each rail screen and the modals) once before merge — ~15 minutes, optional, not gate-critical given snapshot coverage.

### Gap 2 — `ruff check` / `ruff format --check` not executed for increments 1–11
**Severity:** low (CI hygiene). **Status:** open — deferred to CI.
`ruff` is not installed in the Phase 3 development environment; increments 1–11 each substituted `python -m py_compile` on every changed Python file (all clean) and recorded `ruff` as a pending item. Increment 12's environment had `pytest-textual-snapshot` installed but the packets do not record a `ruff` run there either. **Mitigation:** every changed file compiles; `styles.tcss` is parsed by the Textual engine on every `run_test()` case (a malformed rule would raise `StylesheetError` at mount — the suite is green, so it parses). The unguarded surface is lint-style only (import order, unused names, formatting). **Recommendation:** run `ruff check .` / `ruff format --check .` in CI or a ruff-equipped environment before merge — the project CI (`.github/workflows/tui-ci.yml`) is the natural home; no code change is anticipated.

### Gap 3 — TC-030: global-`BINDINGS` realization vs. per-screen `Binding` objects
**Severity:** low (design-judgement, disclosed). **Status:** resolved-by-design — recorded, no action.
The increment-1 `keymap-proposal.md` §3 lists *per-screen* `show=True` paging sets. Increments 2–7 realised those through a **single app-level `BINDINGS`** set: the paging keys (`period`/`comma`/`plus`/`minus`) are `show=True` globally and dispatch context-sensitively via `_active_view_name()`. The footer therefore shows a constant chip set on every screen; the per-screen behavior lives in the action dispatch, not in per-screen `Binding` objects. Increment 11's TC-030 verifies the honest, non-weakened reading of LLR-013.2 — (a) the keymap §2 global footer set is present on every screen, and (b) the paging keys the keymap §3 assigns to a screen are present in that screen's footer — and the scaffold screens additionally show inert paging dispatcher chips. **Assessment (qa-reviewer):** this satisfies LLR-013.2 ("display the active screen's key bindings in a footer/status bar") — a single always-`show=True` dispatcher binding is a superset of every screen's expected `show=True` set, and the keymap proposal §3 itself defines a screen's footer as "global footer set + per-screen `show=True` set". TC-030 is **pass**. The note is recorded because a reviewer who reads LLR-013.2 as mandating literal per-screen `Binding` objects would see a presentation difference; that would be a keymap-proposal/`architect` question, not a test or code defect, and out of scope for a Phase 4 verdict. No residual risk to the requirement.

### Gap 4 — CV-03: no-file empty-state layout not snapshot-guarded
**Severity:** low (drift coverage). **Status:** accepted — functionally covered.
The 27-baseline snapshot matrix (TC-016-S) renders only **file-loaded** public fixtures, so the no-file empty-state *layout* (LLR-002.3) is not captured by any `.svg` baseline. The increment-12 packet left the optional 120×30 empty-state baseline out at implementer discretion (it would add an un-pinned 28th baseline outside the §5.5 count of 27). **Mitigation:** LLR-002.3 is **functionally** fully covered — TC-037 (`test_tui_directionb.py`, ×3 + the increment-9 rewrite iterating all 8 rail screens) asserts every rail screen shows a neutral, non-blank empty-state panel with no file loaded and raises no exception. Only empty-state *layout drift* (pane geometry of the empty panel) is unguarded by a snapshot. **Recommendation:** accept as-is, or add one optional 120×30 empty-state baseline in a follow-up — non-gate-critical; the functional behavior is verified.

**Other items folded across the increments — recorded, no Phase 4 action:**
- `EmptyStatePanel` id duplication (`#empty_state_panel` shared by Workspace/Issues/Memory Map) — flagged in increments 7/9/10; benign because every query is type-scoped to a screen, never by the shared id. Candidate cleanup.
- `ScreenScaffold` is dead code in `app.py` after increment 10 (all 8 screens have real content) but retained/exported in `screens_directionb.py` — inert, harmless; candidate cleanup.
- Legacy shared `id="load_dialog"` across the 3 modals (pre-batch state) — unambiguous because the modals never mount simultaneously; candidate cleanup.
- Three recommended `security-reviewer` sign-offs (increment 4 command-bar S-1, increment 8 modals S-4, increment 12 snapshot baselines S-2) — each has its evidence captured in-packet (TC-008/009 AST guards; `workspace.py` byte-identical + TC-034 traversal sub-case; the S-2 0-match leak grep). These are recommended confirmations, not blockers, and should be collected before merge per increment 12 §6.

---

## 8. Verdict and recommendation

**Verdict: `pass-with-gaps`.**

The Phase 4 gate is satisfied:
- The full `pytest -q` suite is **green — 419 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** — reproduced in this Phase 4 run with zero drift from the increment-12 baseline.
- The engine-freeze `git diff main` over all seven frozen modules is **empty** — HLR-014 / LLR-014.1 hold at the strictest level (zero bytes changed). The 9 engine test files are byte-identical to `main`.
- **All 38 active TCs pass** (TC-001..TC-039 + TC-016-S; TC-005 retired N/A). 0 partial, 0 fail.
- **All 15 HLR and 38 LLR verdict `pass`.** 0 partial, 0 fail.
- **All 9 acceptance criteria AC-B1..AC-B9 are met.** 0 not-met.
- **Zero blocker-severity fails** — AC-B8 satisfied. The dev-flow Phase 4 rollback rule fires only on an open blocker; **there is none.**

**No rollback to Phase 3 is forced or warranted.** As the orchestrator's brief anticipated, the suite is green and the engine freeze was verified independently — no blocker was found.

The four `-with-gaps` items (manual real-terminal verification not run in this headless environment; `ruff` not installed for increments 1–11; the TC-030 global-`BINDINGS` design realization; the CV-03 empty-state-not-snapshotted note) are all documentary / environmental / design-disclosure items already surfaced in the increment packets. None is a correctness defect, none gates the batch.

**Recommended next step:** advance to **Phase 5 (post-mortem)**. The four gaps are carried forward — Gap 1 (manual TUI pass) and Gap 2 (`ruff` in CI) are quick pre-merge actions for Javier; Gap 3 is resolved-by-design and needs only an `architect` acknowledgement if a per-screen `Binding` presentation is later preferred; Gap 4 is accepted with an optional follow-up baseline. The three recommended `security-reviewer` sign-offs (S-1 / S-4 / S-2) should be collected before the PR merges. No code or test change is required to close the Phase 4 gate.

---

*Generated by the qa-reviewer agent — Phase 4 validation of batch-02-direction-b-restyle. All test output in this document is from Phase 4 evidence runs on the Windows host (Python 3.12.7, pytest 8.4.2) at branch `dev-flow/batch-02-direction-b-restyle` @ `701a849`.*
