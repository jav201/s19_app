# Traceability Matrix — s19_app — Batch 2026-05-20-batch-02

> Full chain: **User Story → HLR → LLR → Test Case → Increment → Validation verdict**.
> Every row is complete at batch close (Phase 6). Incomplete rows = coverage gaps and are listed in the gaps section.

This matrix is the consolidated traceability artefact for batch `2026-05-20-batch-02` — the **Direction B "Rail + Command" view-layer restyle** of the `s19tui` Textual TUI. Source artefacts:

- [`.dev-flow/2026-05-20-batch-02/01-requirements.md`](../01-requirements.md) §2.6 (US), §3 (HLR), §4 (LLR), §5.2/§5.3 (TC IDs + methods), §6 (`R-*` traceability + candidate entries)
- [`.dev-flow/2026-05-20-batch-02/02-review.md`](../02-review.md) §Phase-2 closure (24 findings CLOSED, CV-01..CV-05)
- [`.dev-flow/2026-05-20-batch-02/03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-012.md`](../03-increments/increment-012.md) + [`increment-plan.md`](../03-increments/increment-plan.md) + [`keymap-proposal.md`](../03-increments/keymap-proposal.md)
- [`.dev-flow/2026-05-20-batch-02/04-validation.md`](../04-validation.md) §4 (per-TC verdicts), §5 (per-requirement verdicts), §6 (AC-B1..AC-B9), §7 (gaps)
- [`.dev-flow/2026-05-20-batch-02/05-postmortem.md`](../05-postmortem.md)

This batch is a **view-layer-only restyle**: it changes how the TUI is laid out, navigated and themed, and adds three new view scaffolds, all wired to the **frozen** parsing/validation/services engine. "The system" referenced by `shall` clauses is the `s19_app/tui/` view layer (per `01-requirements.md` §1.1).

---

## 1. Master table

One row per US → HLR → LLR → TC tuple. `Increment` cites the Phase 3 increment that built the screen/feature and shipped the asserting test. `Verdict` is the Phase 4 per-TC verdict from [`04-validation.md`](../04-validation.md) §4: `pass` = an asserting test is green / the inspection checklist is fully satisfied; `N/A` = retired, no verdict. All 14 US, 15 HLR, 38 LLR and 38 active TC are traced — see §3 for the no-gap confirmation.

| US | HLR | LLR | TC | Method | Increment | Verdict | Evidence (Phase 4) |
|----|-----|-----|-----|--------|-----------|---------|--------------------|
| US-001 | HLR-001 | LLR-001.1 | TC-001 | test | 3 | pass | `test_tui_directionb.py::tc001` ×2 — rail composes exactly 8 ordered items on keys 1–8. |
| US-001 | HLR-001 | LLR-001.2 | TC-002 | test | 3 | pass | `test_tui_directionb.py::tc002` ×2 — exactly one rail item active; Workspace active at startup. |
| US-001 | HLR-001 | LLR-001.3 | TC-035 | test+inspection | 3 | pass | `test_tui_directionb.py::tc035` ×3 — Unicode glyphs `◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` match the normative table; distinct ASCII fallbacks; ASCII mode renders without error. |
| US-001 | HLR-002 | LLR-002.1 | TC-003 | test | 2 | pass | `test_tui_directionb.py::tc003` — rail activation swaps content; exactly one `#screen_*` visible after each `action_show_screen`. |
| US-001 | HLR-002 | LLR-002.2 | TC-004 | test | 9 | pass | `test_tui_directionb.py::tc004` ×3 — Bookmarks slot shows a non-blocking "coming soon" placeholder; no persistence surface. |
| US-001 | HLR-002 | LLR-002.2 | TC-005 | — | — | **N/A** | Retired (OQ-3 resolved → "keep eight rail items"). Produces no verdict; superseded by TC-004. |
| US-001 | HLR-002 | LLR-002.3 | TC-037 | test | 2 / 7 / 9 | pass | `test_tui_directionb.py::tc037` ×3 + the increment-9 rewrite — every rail screen shows a neutral empty-state panel with no file loaded; no exception. |
| US-002 | HLR-003 | LLR-003.1 | TC-006 | test | 4 | pass | `test_tui_commandbar.py::tc006` — command bar mounted on all 8 rail screens. |
| US-002 | HLR-003 | LLR-003.2 | TC-007 | test+inspection | 4 | pass | `test_tui_commandbar.py::tc007` ×2 — every `BINDINGS` action has one palette entry dispatching the same action id. |
| US-002 | HLR-003 | LLR-003.3 | TC-036 | test | 4 | pass | `test_tui_commandbar.py::tc036` — typing narrows the visible command list (24→1 smoke); clearing restores it. |
| US-002, US-013 | HLR-004 | LLR-004.1 | TC-008 | test | 4 | pass | `test_tui_commandbar.py::tc008` ×5 — `/` focuses find from every screen; routes to `find_string_in_mem`; single-key suppression; malformed input via `set_status`; AST guard. |
| US-002, US-013 | HLR-004 | LLR-004.6 | TC-008 | test | 4 | pass | `tc008` find-routing + AST guard sub-cases — submitted find text handled by `find_string_in_mem`; no new search/decoding code. |
| US-002, US-013 | HLR-004 | LLR-004.2 | TC-009 | test | 4 | pass | `test_tui_commandbar.py::tc009` ×4 — `g` focuses go-to; submit → hex scrolled + `Goto 0x…` status; suppression; malformed via `set_status`; AST guard. |
| US-002, US-013 | HLR-004 | LLR-004.3 | TC-010 | test | 4 | pass | `test_tui_commandbar.py::tc010` — `Ctrl+K` opens/focuses the palette from every Direction B screen. |
| US-002, US-013 | HLR-004 | LLR-004.4 | TC-011 | test+inspection | 11 | pass | `test_tui_directionb.py::tc011` ×2 — every pre-batch `BINDINGS` action keeps a key/palette path; `1`/`2`/`3`→rail remap and `#view_bar` removal recorded as intended supersession. |
| US-002, US-013 | HLR-004 | LLR-004.5 | TC-008, TC-009, TC-029 | test | 4 / 11 | pass | `tc008`/`tc009`/`tc029` input-focus sub-cases — `g`, digits `1`–`8`, paging keys `+ - , .` routed as text while a command-bar input holds focus; modified keys stay live. |
| US-003 | HLR-005 | LLR-005.1 | TC-012 | inspection | 1 | pass | `04-validation.md` §3 checklist (6/6) — `$accent-calm: #4ec9d4` single accent; 5 `sev-*` rules; `MAC_ADDRESS_OVERLAY_STYLE`/`FOCUS_HIGHLIGHT_STYLE` preserved; no light variant. 16 `test_tui_theme.py` cases green. |
| US-003, US-014 | HLR-005 | LLR-005.2 | TC-013 | test | 1 | pass | `test_tui_theme.py` TC-013(a) round-trip anchor + TC-013(b) per-`sev-*` rule assertion — green; no new `ValidationSeverity` value. |
| US-004 | HLR-006 | LLR-006.1 | TC-014 | test | 2 | pass | `test_tui_directionb.py::tc014` — `Ctrl+D` cycles the density root class compact↔comfortable; active mode surfaced. |
| US-004 | HLR-006 | LLR-006.2 | TC-015 | test | 2 | pass | `test_tui_directionb.py::tc015` — startup density class is the Comfortable variant (OQ-2). |
| US-004 | HLR-007 | LLR-007.1 | TC-016-S | test (snapshot) | 12 | pass | `pytest -q -m snapshot` → 27 snapshots passed; baseline dir holds exactly 27 `.svg` matching the §5.5 matrix. |
| US-004 | HLR-007 | LLR-007.1 | TC-016 | inspection | 12 | pass | `04-validation.md` §3 checklist — no overlap/clip across the 27 SVG baselines; CV-04 boundary tests confirm proportional@119 / fixed@120. |
| US-004 | HLR-007 | LLR-007.2 | TC-016-S | test (snapshot) | 12 | pass | `tc016-S` fixture-setup check — every committed `.svg` traces to a public synthetic fixture (`examples/case_00_public/` or a `tests/conftest.py` generator). |
| US-004 | HLR-007 | LLR-007.2 | TC-031 | inspection+analysis | 12 | pass | `04-validation.md` §3 — S-2 leak grep over all 27 `.svg`: 0 matches for client tokens. |
| US-005 | HLR-008 | LLR-008.1 | TC-017 | test+inspection | 5 | pass | `test_tui_directionb.py::tc017` ×3 — fixed regime (left 22±2, right 40±2, rail 22, center `1fr`) at 120×30/160×40; proportional regime (left 24%±3, right 30%±3, rail 4±1, center `1fr` positive) at 80×24. |
| US-005, US-014 | HLR-008 | LLR-008.2 | TC-018 | test | 5 | pass | `test_tui_directionb.py::tc018` ×3 — panes populate via `update_sections`/`update_hex_view`; `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` unchanged. |
| US-006 | HLR-009 | LLR-009.1 | TC-019 | test+inspection | 6, 13 | pass | LLR-009.1 amended by increment 13 (review feedback) — A2L hex pane re-laid-out from the iteration-3 two-regime split to a flat 3/7 hex : 4/7 tags proportional ratio at all terminal widths (`#a2l_hex_pane` 3fr, `#a2l_tags_pane` 4fr). `test_tui_directionb.py::tc019` — hex pane 3/7 (≈42.9%) ±3 points at 80×24 / 120×30 / 160×40, A2L symbol `DataTable` the strictly-positive 4/7 (≈57.1%) remainder; 6 `a2l-*` snapshot baselines regenerated. MAC View (LLR-010.1) unchanged. |
| US-006, US-014 | HLR-009 | LLR-009.2 | TC-020 | test | 6 | pass | `test_tui_directionb.py::tc020` — field/mode filtering, `+`/`-` + button paging, row-select jump all work on the restyled screen (`R-A2L-007`, `R-TUI-018/019/020` not regressed). |
| US-007 | HLR-010 | LLR-010.1 | TC-021 | test+inspection | 6 | pass | `test_tui_directionb.py::tc021` — MAC `1fr` table + 40±2 hex pane (fixed); 35%±4 (proportional); rail 4±1. |
| US-007, US-014 | HLR-010 | LLR-010.2 | TC-022 | test | 6 | pass | `test_tui_directionb.py::tc022` — MAC paging, severity coloring, overlay highlight, row-select jump preserved (`R-TUI-018` not regressed). |
| US-008 | HLR-011 | LLR-011.1 | TC-023 | test | 7 | pass | `test_tui_directionb.py::tc023` ×3 — `#validation_issues_list` is `#screen_issues` primary content; `#workspace_carryover` fully removed; status/log widgets re-homed. |
| US-008, US-014 | HLR-011 | LLR-011.2 | TC-024 | test | 7 | pass | `test_tui_directionb.py::tc024` ×5 — severity coloring round-trips; All/Errors/Warnings filters, paging, row-select jump-to-source. |
| US-008, US-013 | HLR-011 | LLR-011.3 | TC-038 | test | 4 / 7 | pass | `test_tui_commandbar.py::tc038` — project name + A2L filename render in the command bar, visible on every screen after the Issues table leaves the Status tile (`R-TUI-016` not regressed). |
| US-009 | HLR-012 | LLR-012.1 | TC-025 | test | 9 | pass | `test_tui_directionb.py::tc025` ×5 — ranges/gaps render from `LoadedFile.ranges`/`range_validity`; no new coverage computation. |
| US-010 | HLR-012 | LLR-012.2 | TC-026 | test | 10 | pass | `test_tui_directionb.py::tc026` ×4 — before/after panes + address/bytes inputs render; no `on_input_*` handler, no apply/undo/redo; deferral notice shown. |
| US-011 | HLR-012 | LLR-012.3 | TC-027 | test | 10 | pass | `test_tui_directionb.py::tc027` ×4 — three columns with constant labelled PLACEHOLDER rows; no second-file load `Button`; deferral notice shown. |
| US-009, US-010, US-011 | HLR-012 | LLR-012.4 | TC-028 | test+inspection | 9 / 10 | pass | `test_tui_directionb.py::tc028` ×10 — `screens_directionb.py` imports no `bincopy`/`pya2l`/`crcmod`; none in `pyproject.toml`; no new module at `s19_app/` root; all scaffolds activate without error. |
| US-013 | HLR-013 | LLR-013.1 | TC-029 | test | 11 | pass | `test_tui_directionb.py::tc029` ×4 — rail items, command-bar inputs, density toggle, scaffold inputs all keyboard-reachable; single-key suppression both directions. |
| US-013 | HLR-013 | LLR-013.2 | TC-030 | test | 11 | pass | `test_tui_directionb.py::tc030` ×3 — keymap §2 global footer set present on all 8 screens; keymap §3 paging keys present on the 4 paging screens. See §3 Gap G-3 (design realization note). |
| US-002, US-013 | HLR-013 | LLR-013.3 | TC-039 | inspection | 4 | pass | `04-validation.md` §3 checklist (5/5) — `command_bar.py` AST-inspection: no logger reference; driven session shows no typed text in the log. 2 `TC-039` cases green. |
| US-014 | HLR-014 | LLR-014.1 | TC-031 | inspection+analysis | 11 | pass | `04-validation.md` §2 — `git diff main` empty for all 7 engine modules (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); cosmetic-only rubric vacuously satisfied. |
| US-014 | HLR-014 | LLR-014.2 | TC-032 | test | 11 | pass | `test_tui_directionb.py::tc032` ×3 + the full 419-pass run; 9 engine test files byte-identical to `main`; no `skip` in engine tests; no engine monkeypatch. |
| US-012 | HLR-015 | LLR-015.1 | TC-033 | inspection | 8 | pass | `04-validation.md` §3 checklist (5/5) — modals style via `$accent-calm`/`$bg-*`/`$fg-*`/`$rule`; no hard-coded hex; single shared accent. 4 `TC-033` cases green. |
| US-012, US-014 | HLR-015 | LLR-015.2 | TC-034 | test | 8 | pass | `test_tui_directionb.py::tc034` ×5 — `validate_project_files` cardinality, `copy_into_workarea` containment, `..\..\` traversal containment, `SaveProjectPayload` intact (`R-TUI-014` not regressed). |

**Row count:** 41 traceability rows covering 38 active TCs (TC-001..TC-039 + TC-016-S; TC-005 retired N/A). LLRs covered by more than one TC (LLR-004.5, LLR-004.6, LLR-007.1, LLR-007.2, LLR-011.3) appear on multiple rows; every distinct LLR and TC is present at least once.

---

## 2. Coverage summary

Counts folded from [`04-validation.md`](../04-validation.md) §0, §4, §5, §6.

| Metric | Value |
|--------|-------|
| Total user stories | 14 (US-001..US-014) |
| Covered user stories | 14 (100%) |
| Total HLR | 15 (HLR-001..HLR-015) |
| HLR with verdict `pass` | 15 (100%) |
| Total LLR | 38 |
| LLR with verdict `pass` | 38 (100%) |
| Active test cases | 38 (TC-001..TC-039 + TC-016-S; TC-005 retired — N/A, no verdict) |
| TC pass | 38 (100%) |
| TC partial | 0 |
| TC fail (blocker) | 0 |
| TC fail (non-blocker) | 0 |
| Batch acceptance criteria (AC-B1..AC-B9) | 9 met / 0 not-met |
| Open blocker findings at the gate | 0 |
| pytest baseline at gate (full suite) | **419 passed / 0 failed / 3 xfailed / 2 skipped**; 27 snapshots passed |
| Suite trajectory | 275 → 419 across the 12 increments (+144 net new tests) |
| Phase 4 verdict | `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps) |

### 2.1 Coverage by validation method

| Method | TC count | Notes |
|--------|----------|-------|
| test (`run_test()` / unit) | 31 | Rail, command bar, density, screen layouts, behavior preservation, scaffolds, no-regression sweep. |
| test (snapshot) | 1 | TC-016-S — the 27-baseline `pytest-textual-snapshot` matrix. |
| inspection | 5 | TC-012 (theme tokens), TC-016 (layout checklist), TC-031 (engine no-change + snapshot no-leak), TC-033 (modal theme), TC-039 (command-bar logging). Each carries its checklist inline in `04-validation.md` §3. |
| test+inspection / inspection+analysis | (overlap) | TC-007, TC-011, TC-016, TC-019, TC-021, TC-028, TC-031, TC-035 carry a primary + supporting method; counted once above under the primary method. |
| **Total active** | **38** | TC-005 retired (N/A) — not counted. |

### 2.2 Suite trajectory across Phase 3 increments

| Increment | Title | Tests | Δ |
|-----------|-------|-------|---|
| baseline | (batch-01 close) | 275 | — |
| 1 | Theme tokens + `styles.tcss` extraction | 284 | +9 |
| 2 | App shell + 8-container routing + density | 291 | +7 |
| 3 | Activity rail widget | 308 | +17 |
| 4 | Command bar + key bindings + suppression | 314 | +6 |
| 5 | Workspace 3-pane re-layout | 327 | +13 |
| 6 | A2L Explorer + MAC View re-layout | 338 | +11 |
| 7 | Issues Report dedicated screen | 347 | +9 |
| 8 | Modal re-skin | 359 | +12 |
| 9 | Memory Map + Bookmarks scaffolds | 373 | +14 |
| 10 | Patch Editor + A↔B Diff scaffolds | 389 | +16 |
| 11 | No-regression + behavior verification | 419 | +30 |
| 12 | Snapshot test increment | 419 | +0 (27 snapshot cells) |

The progression reconciles: each increment added exactly its own new cases and regressed none. Increment 12 adds 27 `pytest-textual-snapshot` cells (counted in the snapshot report, not the `passed` integer drift) — full-run total is `419 passed` + `27 snapshots passed`.

---

## 3. Detected gaps

> Incomplete rows, requirements without a TC, or open findings carrying into a follow-up batch.

**Traceability completeness: NO GAPS.** Every one of the 14 US, 15 HLR, 38 LLR and 38 active TC is traced end-to-end in §1 and carries a Phase 4 `pass` verdict. TC-005 is the only retired case (N/A — OQ-3 resolved to keep eight rail items); it produces no verdict and is superseded by TC-004. There is **no requirement without a validation method, no LLR without a passing TC, and no TC without a recorded verdict** — this satisfies acceptance criterion **AC-B1** ([`04-validation.md`](../04-validation.md) §6).

The four items below are the `-with-gaps` qualifiers from the Phase 4 verdict ([`04-validation.md`](../04-validation.md) §7). **None is a correctness defect, none is a blocker, none gates the batch.** They are documentary / environmental / design-disclosure items carried to Phase 5/6.

| ID | Type | Severity | Description | Disposition |
|----|------|----------|-------------|-------------|
| G-1 | Environmental | low | Manual real-terminal TUI verification not performed — Phase 3/4 ran headless (`App.run_test()` / `pytest`). Increments 6–10 each carry a "Manual TUI pass" pending item (eyeballing real-terminal rendering, the relocated status bar, the modal backdrop, scaffold visuals, the 120-column resize). | Deferred. Mitigated by the 27-baseline `pytest-textual-snapshot` matrix (automated layout-drift guard) + the CV-04 resize boundary tests. Recommended: Javier runs the increment-6/7/8/9/10 manual checklists once before merge (~15 min, optional). |
| G-2 | CI hygiene | low | `ruff check` / `ruff format --check` not executed for increments 1–11 (`ruff` not installed in the Phase 3 environment; each increment substituted `python -m py_compile`). | Deferred to CI. Mitigated — every changed file compiles; `styles.tcss` is parsed by Textual on every `run_test()`. Recommended: run `ruff` in `.github/workflows/tui-ci.yml` before merge. |
| G-3 | Design judgement | low | TC-030 — the keymap proposal §3 lists *per-screen* `show=True` paging sets; increments 2–7 realised them through a **single app-level `BINDINGS`** set dispatching context-sensitively via `_active_view_name()`. The footer shows a constant chip set; per-screen behavior lives in the action dispatch. | Resolved-by-design. TC-030 verifies the honest, non-weakened reading of LLR-013.2 and is `pass`. A reviewer who reads LLR-013.2 as mandating literal per-screen `Binding` objects would see a presentation difference — an `architect`/keymap-proposal question, not a test or code defect. |
| G-4 | Drift coverage | low | CV-03 — the 27-baseline snapshot matrix renders only **file-loaded** public fixtures, so the no-file empty-state *layout* (LLR-002.3) is not captured by any `.svg`. | Accepted. LLR-002.3 is **functionally** fully covered by TC-037 (every rail screen shows a neutral empty-state panel with no file loaded). Only empty-state *layout drift* is unguarded by a snapshot. Optional follow-up: add one 120×30 empty-state baseline. |

**Other items folded across the increments — recorded, no Phase 4 action (candidate cleanups):**

- `EmptyStatePanel` id duplication (`#empty_state_panel` shared by Workspace/Issues/Memory Map) — benign because every query is type-scoped to a screen.
- `ScreenScaffold` is dead code in `app.py` after increment 10 (all 8 screens have real content) but retained/exported in `screens_directionb.py` — inert, harmless.
- Legacy shared `id="load_dialog"` across the 3 modals (pre-batch state) — unambiguous because the modals never mount simultaneously.
- Three recommended `security-reviewer` sign-offs (increment 4 command-bar S-1, increment 8 modals S-4, increment 12 snapshot baselines S-2) — each has its evidence captured in-packet; recommended confirmations, not blockers, to be collected before merge.

---

## 4. Changes from previous batch

This is **batch 2** of the s19_app dev-flow. Batch 1 (`2026-05-05-batch-01`) was an audit batch that left 18 open findings.

| Field | Value |
|-------|-------|
| Previous batch | `2026-05-05-batch-01` (audit batch) |
| Carried-forward findings closed by this batch | None — batch-02 is a view-layer restyle; it does not touch the engine modules where the batch-01 findings live (F-7.2-*, F-7.7-*, F-9.*). The engine freeze (HLR-014 / `git diff main` empty) means batch-01's engine findings are untouched and remain open for their planned batches B-2A..E. |
| `R-*` traceability rows added to the living `REQUIREMENTS.md` | 16 new `R-TUI-021`..`R-TUI-036` (merged from `01-requirements.md` §6.2 — see the living [`REQUIREMENTS.md`](../../../REQUIREMENTS.md)). |
| `R-*` rows superseded by this batch | `R-TUI-003` (five-tile layout) — superseded by `R-TUI-029` (Direction B 3-pane Workspace); the retired `#view_bar` button bar and `view_main`/`view_alt`/`view_mac` actions are superseded by rail items 1/2/3 (intended Direction B change, A-02/A-07 — not a regression). |
| `R-*` rows protected and confirmed not regressed | `R-TUI-001/002/004/005/006/007/008/009/010/011/012/013/014/015/016/017/018/019/020`, `R-A2L-002/003/006/007`, `R-PROJ-001/002`, `R-DOC-001` — see `01-requirements.md` §6.1. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-001 (activity rail)** → HLR-001, HLR-002 → LLR-001.1/001.2/001.3, LLR-002.1/002.2/002.3 → TC-001..004, TC-035, TC-037
- **US-002 (command bar)** → HLR-003, HLR-004 → LLR-003.1/003.2/003.3, LLR-004.1..004.6 → TC-006..011, TC-036, TC-039
- **US-003 (Calm Dark theme)** → HLR-005 → LLR-005.1/005.2 → TC-012, TC-013
- **US-004 (density)** → HLR-006, HLR-007 → LLR-006.1/006.2, LLR-007.1/007.2 → TC-014..016, TC-016-S, TC-031
- **US-005 (Workspace)** → HLR-008 → LLR-008.1/008.2 → TC-017, TC-018
- **US-006 (A2L Explorer)** → HLR-009 → LLR-009.1/009.2 → TC-019, TC-020
- **US-007 (MAC View)** → HLR-010 → LLR-010.1/010.2 → TC-021, TC-022
- **US-008 (Issues Report)** → HLR-011 → LLR-011.1/011.2/011.3 → TC-023, TC-024, TC-038
- **US-009/010/011 (Memory Map / Patch Editor / A↔B Diff scaffolds)** → HLR-012 → LLR-012.1/012.2/012.3/012.4 → TC-025..028
- **US-012 (modal re-skin)** → HLR-015 → LLR-015.1/015.2 → TC-033, TC-034
- **US-013 (keyboard reachability)** → HLR-013 (+ HLR-004) → LLR-013.1/013.2/013.3, LLR-004.4/004.5 → TC-011, TC-029, TC-030, TC-039
- **US-014 (engine freeze)** → HLR-014 → LLR-014.1/014.2 → TC-031, TC-032

### 5.2 By code file

Files touched by the Direction B restyle. New modules created this batch are marked **(new)**.

| Code file | LLR(s) / role | Increment | Test(s) |
|-----------|---------------|-----------|---------|
| `s19_app/tui/styles.tcss` **(new)** | LLR-005.1, LLR-005.2, LLR-007.1, LLR-015.1 — Calm Dark token set, 5 `sev-*` rules, two-regime layout, modal block | 1, 5, 6, 8 | `tests/test_tui_theme.py` |
| `s19_app/tui/app.py` | LLR-002.1, LLR-002.3, LLR-006.*, LLR-008.*, LLR-009.*, LLR-010.*, LLR-011.*, LLR-013.* — orchestration, 8-container routing, density action, screen re-layout, binding map | 1–11 | `tests/test_tui_directionb.py`, `tests/test_tui_app.py` |
| `s19_app/tui/rail.py` **(new)** | LLR-001.1, LLR-001.2, LLR-001.3 — `Rail` / `RailItem` widgets, 8 items, glyphs + ASCII fallback, single active marker | 3 | `tests/test_tui_directionb.py` |
| `s19_app/tui/command_bar.py` **(new)** | LLR-003.1, LLR-003.2, LLR-003.3, LLR-004.1/002/006, LLR-011.3, LLR-013.3 — `CommandBar` widget, palette / find / go-to, project labels | 4 | `tests/test_tui_commandbar.py` |
| `s19_app/tui/screens_directionb.py` **(new)** | LLR-012.1, LLR-012.2, LLR-012.3, LLR-012.4, LLR-002.2 — Memory Map, Patch Editor, A↔B Diff, Bookmarks placeholder scaffolds | 9, 10 | `tests/test_tui_directionb.py` |
| `s19_app/tui/screens.py` | LLR-015.1, LLR-015.2 — `LoadFileScreen` / `SaveProjectScreen` / `LoadProjectScreen` re-skin (behavior, `validate_project_files`, `SaveProjectPayload` unchanged) | 8 | `tests/test_tui_directionb.py` (tc034) |
| `s19_app/tui/color_policy.py` | LLR-005.2 / HLR-014 — **frozen** (`git diff main` empty); `SEVERITY_CLASS_MAP` source of truth, unchanged | — | `tests/test_tui_theme.py` (TC-013 round-trip) |
| `s19_app/tui/hexview.py` | LLR-008.2 / HLR-014 — **not touched** by any increment; render caps `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` pinned by TC-018 | — | `tests/test_tui_hexview.py` |
| `s19_app/tui/a2l.py` (+ facades), `mac.py`, `core.py`, `hexfile.py`, `range_index.py`, `validation/` | HLR-014 / LLR-014.1 — **frozen engine surface**, zero bytes changed | — | engine test files byte-identical to `main` (TC-032) |
| `pyproject.toml` | C-2 scoped exception — `pytest-textual-snapshot` declared dev-only under `[project.optional-dependencies]`; `textual` gains a `>=` floor | 1, 12 | TC-028 (no new runtime dep) |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-05-20-batch-02` |
| Batch title | Direction B "Rail + Command" view-layer restyle |
| Branch | `dev-flow/batch-02-direction-b-restyle` @ `701a849` |
| Closing date | Phase 4 validated `2026-05-21`; Phase 6 docs delivered `2026-05-21` |
| Total iterations | Phase 1: 4 iterations · Phase 2: `pass` (0 blockers, 24 findings closed) · Phase 3: 12 increments · Phase 4: 1 · Phase 5: 1 |
| Validation passed | yes — `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps G-1..G-4) |
| pytest baseline at gate | 419 passed / 0 failed / 3 xfailed / 2 skipped; 27 snapshots passed (Windows 11, Python 3.12.7, pytest 8.4.2, textual 8.0.2) |
| Engine freeze | verified — `git diff main` empty across all 7 frozen modules; 9 engine test files byte-identical to `main` |
| Traceability completeness | NO GAPS — 14 US / 15 HLR / 38 LLR / 38 active TC all traced and `pass` |
| `R-*` rows added to living `REQUIREMENTS.md` | 16 (`R-TUI-021`..`R-TUI-036`); `R-TUI-003` marked superseded |
| Synced to Obsidian | (post-merge — `/dev-flow-sync-en` after PR close) |
