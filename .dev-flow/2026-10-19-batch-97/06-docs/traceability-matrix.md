# Traceability Matrix — s19_app — Batch 2026-10-19-batch-97

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-19-batch-97`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Verdict source:** every `Status` below is the Layer A / Layer B verdict of `04-validation.md` — `Result: PASS-WITH-NOTES`, `Requirements: 81/81 pass (8 HLR + 73 LLR) · 0 blocker fails`, 26/26 ATs on one chain node each. The gate run is the orchestrator's full suite `evidence/inc-7/suite-full.txt` (11 failed / 3617 passed / 3 skipped / 3 xfailed; source digest-equal to `432ecf0`), in which 0 nodes of any `tests/test_b97_*.py` failed. Requirement topology (US → HLR → LLR → TC/AT) is the contract `01-requirements.md` §2.6 / §3 / §4. Increment attribution is the packets' §2 tables (`03-increments/increment-001…009.md`).
> **Anchors:** `File:line` is the implementing symbol, measured on the tree at `c899113` (the close commit; `git diff 432ecf0 c899113 -- s19_app tests` is empty, so the lines are the gated code's lines). `Notes` names the TC's first test node (file:line on the same tree) and the evidence transcript from `04-validation.md` §Layer A. Where an LLR's behaviour is spread across a panel rather than one function, the anchor names the panel class and says so.

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label**. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`/`R-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block; what it must not do is order the translation of somebody else's.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row. ⚠ **This template is seeded by a BULLET under that table rather than by a row**, because `06-docs/` exists only in `full` — the same fact `V39`'s `_V39_OWED_IN["P6"]` carries.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

---

## 1. Master table — functional chain (white-box)

> One row per LLR (73 rows). `TC` = the contract's verification id for the LLR (`TC-B97-01…72`); LLR-151.1 has no TC id (gap G-005 / G-006 below). Short paths: `sd` = `s19_app/tui/screens_directionb.py`, `fs` = `s19_app/tui/flow_screens.py`, `fo` = `s19_app/tui/services/folder_open_service.py`, `wh` = `s19_app/tui/window_help.py`, `app` = `s19_app/tui/app.py`, `css` = `s19_app/tui/styles.tcss`; test files are `tests/test_b97_<name>.py`.

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| **Inc-4 (`09e44de`) — Patch Editor → pe_A, JSON tab, geometry cleanup** | | | | | | |
| US-134 | HLR-144 | LLR-144.1 | TC-B97-01 | `sd:4359` (`PatchEditorPanel`, the 66 shipped ids kept) | pass | `patch_editor.py:191` · `evidence/inc-4/green.txt` |
| US-134 | HLR-144 | LLR-144.2 | TC-B97-02 | `sd:4359` (ledger + `TabChip` `sd:6891` over one `ContentSwitcher`) | pass | `patch_editor.py:217` · 6 of 6 rows at 118x54 (packet §1) |
| US-134 | HLR-144 | LLR-144.3 | TC-B97-03 | `sd:5320` (`_apply_layout`; `_apply_window_geometry` and the app's show-time block deleted) | pass | `patch_editor.py:276` |
| US-134 | HLR-144 | LLR-144.4 | TC-B97-04 | `css:2663` (scoped `batch-97 patch_editor` section; E-3 pairs deleted) | pass | `patch_editor.py:349` |
| US-134 | HLR-144 | LLR-144.5 | TC-B97-05 | `sd:6701` (`PatchDocumentView`) · `app:5299` (`_patch_document_view`) | pass | `patch_editor.py:428` |
| US-134 | HLR-144 | LLR-144.6 | TC-B97-06 | `sd:6727` (`json_stamp_text`) | pass | `patch_editor.py:599` · stamp saved → unsaved → saved; `green-fold.txt` (paste → `mark_pasted`, H1 fold) |
| US-134 | HLR-144 | LLR-144.7 | TC-B97-07 | `sd:4901` (`#patch_identity_ribbon`, `markup=False`, through `safe_text`) | pass | `patch_editor.py:779` · 0 `MarkupError` |
| US-134 | HLR-144 | LLR-144.8 | TC-B97-39 | `sd:4112` (`before_after_card_text`) · `sd:4230` (`BeforeAfterCard`) | pass | `patch_editor.py:822` · strip states, cap and bold (Layer 0, mutations M11/M13/M16 killed) |
| US-134 | HLR-144 | LLR-144.9 | TC-B97-40 | `sd:4359` (inspector form and entry chips, in the panel) | pass | `patch_editor.py:1013` |
| US-134 | HLR-144 | LLR-144.10 | TC-B97-41 | `sd:4359` (focus chain of the panel) | pass | `patch_editor.py:1183` |
| US-134 | HLR-144 | LLR-144.11 | TC-B97-42 | `css:2663` (filled elements: Save + ledger) | pass | `patch_editor.py:1294` |
| US-134 | HLR-144 | LLR-144.12 | TC-B97-60 | `sd:4359` (every shipped control displayed in its tab) | pass | `patch_editor.py:1377` · `green-after-fixes.txt` |
| **Inc-3 (`98f3c84`) — Check Editor → ce_A** | | | | | | |
| US-135 | HLR-145 | LLR-145.1 | TC-B97-08 | `sd:6916` (`CheckEditorPanel` re-composed, ids kept) | pass | `check_editor.py:163` · `evidence/inc-3/green.txt` |
| US-135 | HLR-145 | LLR-145.2 | TC-B97-09 | `sd:6859` (`check_layout`) · `sd:6897` (`IncludeTable`) | pass | `check_editor.py:232` · `max_scroll_x == 0` at 118x54 / 220x60; 75/75 full addresses |
| US-135 | HLR-145 | LLR-145.3 | TC-B97-10 | `sd:6796` (`clip_param`) | pass | `check_editor.py:272` · Layer 0 (M1–M3 killed on the unit node) |
| US-135 | HLR-145 | LLR-145.4 | TC-B97-11 | `css:2392` (scoped `batch-97 check_editor` section) | pass | `check_editor.py:402` |
| US-135 | HLR-145 | LLR-145.5 | TC-B97-12 | `sd:6916` (file-derived names through `safe_text`, in the panel) | pass | `check_editor.py:433` · 0 `MarkupError` |
| US-135 | HLR-145 | LLR-145.6 | TC-B97-43 | `sd:6916` (REPORT FIELDS card) · `sd:6674` (`cap_json_lines`) | pass | `check_editor.py:494` · Fields lines equal the included set |
| US-135 | HLR-145 | LLR-145.7 | TC-B97-44 | `sd:6916` (memory table: `Address`, `Label`, `Size (bytes)`) | pass | `check_editor.py:617` |
| US-135 | HLR-145 | LLR-145.8 | TC-B97-45 | `sd:6897` (`IncludeTable`, include by key) | pass | `check_editor.py:731` · count N → N+1 |
| US-135 | HLR-145 | LLR-145.9 | TC-B97-46 | `css:2392` (filled elements: Write + ledger) | pass | `check_editor.py:879` |
| US-135 | HLR-145 | LLR-145.10 | TC-B97-61 | `sd:6916` (every shipped control displayed in its home) | pass | `check_editor.py:930` · `green-fold.txt` |
| **Inc-2 (`f93dadc`) + Inc-5 (`b514b07`) — flow foundations, Flow Builder → fb_A** | | | | | | |
| US-136 | HLR-146 | LLR-146.1 | TC-B97-13 | `fs:793` (`pipeline_text`) · `fs:689` (`pipeline_layout`) | pass | `flow_builder.py:518` · 4 cards / 3 cables; `evidence/inc-5/green.txt` |
| US-136 | HLR-146 | LLR-146.2 | TC-B97-14 | `fs:961` (`KindChip`) · `fs:1103` (`_KIND_OPTIONS`, 7 kinds) | pass | `flow_builder.py:555` |
| US-136 | HLR-146 | LLR-146.3 | TC-B97-15 | `fs:575` (`_ADD_PATH_INPUTS`) · `fs:1060` (`FlowBuilderPanel` add form) | pass | `flow_builder.py:584` |
| US-136 | HLR-146 | LLR-146.4 | TC-B97-16 | `fs:627` (`clip_head`) · `fs:651` (`clip_tail`) | pass | `flow_builder.py:622` · Layer 0 (M9 killed) |
| US-136 | HLR-146 | LLR-146.5 | TC-B97-17 | `fs:1060` (foot row) · `css:3021` (scoped `batch-97 flow_builder` section) | pass | `flow_builder.py:694` · Run inside at scroll 0 |
| US-136 | HLR-146 | LLR-146.6 | TC-B97-18 | `s19_app/tui/insight_style.py:126` (`WAITING_HUMAN`) · `:131` (`CRC_FAMILY`) | pass | `flow_builder.py:356` · token arm Inc-2, paint arms Inc-5 |
| US-136 | HLR-146 | LLR-146.7 | TC-B97-19 | `fs:1060` (`FlowBuilderPanel` strings) | pass | `flow_builder.py:805` · 0 Spanish markers |
| US-136 | HLR-146 | LLR-146.8 | TC-B97-20 | `fs:793` (`pipeline_text`, file text through `safe_text`) | pass | `flow_builder.py:872` |
| US-136 | HLR-146 | LLR-146.9 | TC-B97-47 | `fs:1060` (copy/paste strip) | pass | `flow_builder.py:918` |
| US-136 | HLR-146 | LLR-146.10 | TC-B97-48 | `fs:1060` (`Variables (n)` chip) | pass | `flow_builder.py:951` |
| US-136 | HLR-146 | LLR-146.11 | TC-B97-49 | `fs:851` (`ribbon_text`) | pass | `flow_builder.py:987` |
| US-136 | HLR-146 | LLR-146.12 | TC-B97-50 | `app:2536` (`on_flow_builder_panel_run_requested`; the D8 variant branch deleted) | pass | `flow_builder.py:1153` · 0 `#flow_scope` |
| US-136 | HLR-146 | LLR-146.13 | TC-B97-51 | `fs:943` (`FlowChip`, binds `space`) · `fs:961` (`KindChip`) | pass | `flow_builder.py:1220` |
| US-136 | HLR-146 | LLR-146.14 | TC-B97-62 | `s19_app/tui/services/flow_persistence_service.py:333` (`dict_to_flow`) · `:671` (`_parse_a2b_entry`) · `s19_app/tui/services/variant_execution_service.py:205` · `fs:586` (`nul_add_refusal`) | pass | `flow_builder.py:149` · `FLOW-UNSAFE-REF`, 0 exceptions; `evidence/inc-2/green.txt` (M1–M3 killed), `evidence/inc-5/mutations-fold.txt` (M53) |
| **Inc-2 (`f93dadc`) + Inc-6 (`9793fcd`) — Flow Execution → fx_A** | | | | | | |
| US-137 | HLR-147 | LLR-147.1 | TC-B97-21 | `fs:2445` (`cable_glyph`) · `fs:2386` (`FX_CABLE_GLYPHS`) | pass | `flow_execution.py:408` · Layer 0 (M1 killed); `evidence/inc-6/green.txt` |
| US-137 | HLR-147 | LLR-147.2 | TC-B97-22 | `fs:2641` (`FlowExecutionPanel`, SOURCE card holds the rebind input + Bind) | pass | `flow_execution.py:475` |
| US-137 | HLR-147 | LLR-147.3 | TC-B97-23 | `fs:2641` (`FlowExecutionPanel`, attention scroll; focus never moved) | pass | `flow_execution.py:523` · Confirm in the viewport |
| US-137 | HLR-147 | LLR-147.4 | TC-B97-24 | `fs:984` (`ModeToggle`, `sequential · parallel`) | pass | `flow_execution.py:681` |
| US-137 | HLR-147 | LLR-147.5 | TC-B97-25 | `s19_app/tui/services/flow_execution_service.py` (11 strings, Inc-2) · `fs:2500` (`fx_run_error_line`) | pass | `flow_execution.py:84` · service arm Inc-2, panel arm Inc-6 |
| US-137 | HLR-147 | LLR-147.6 | TC-B97-26 | `fs:2641` (lane and set-picker text through `safe_text`) | pass | `flow_execution.py:834` |
| US-137 | HLR-147 | LLR-147.7 | TC-B97-52 | `s19_app/tui/insight_style.py:126` (`WAITING_HUMAN`) · `css:3268` | pass | `flow_execution.py:897` · waiting colour exclusive |
| US-137 | HLR-147 | LLR-147.8 | TC-B97-53 | `fs:2478` (`lane_layout`) · `fs:3222` (`_apply_layout`) | pass | `flow_execution.py:998` · Layer 0 (M33 killed) |
| US-137 | HLR-147 | LLR-147.9 | TC-B97-54 | `css:3268` (scoped `batch-97 flow_execution` section) | pass | `flow_execution.py:1082` |
| US-137 | HLR-147 | LLR-147.10 | TC-B97-55 | `app:2758` (`on_flow_execution_panel_run_requested`) · `fs:2641` (Run and Confirm disabled before posting) | pass | `flow_execution.py:1106` |
| US-137 | HLR-147 | LLR-147.11 | TC-B97-56 | `fs:943` (`FlowChip`; 0 `Button(` constructors) | pass | `flow_execution.py:1282` |
| US-137 | HLR-147 | LLR-147.12 | TC-B97-63 | `fs:2641` (`#fx_lanes_scroll`, both axes) | pass | `flow_execution.py:1364` |
| US-137 | HLR-147 | LLR-147.13 | TC-B97-64 | `app:1455` (`Binding("c", "confirm_attention", …)`) · `app:7085` (`action_confirm_attention`) · `fs:2400` (`CONFIRM_DWELL_S`) | pass | `flow_execution.py:1435` · `c c` → 1 confirm; `green-fold.txt`, `green-post-suite.txt` |
| **Inc-1 (`d5d0ff9`) + Inc-3..Inc-7 — folder chips and window help** | | | | | | |
| US-138 | HLR-148 | LLR-148.1 | TC-B97-27 | `fo:76` (`CHIP_FAMILY_FLOWS`) · `fo:340` (`resolve_chip_target`) | pass | `chips_help.py:65` · Layer 0 (M10/M11 killed); `evidence/inc-1/green.txt` |
| US-138 | HLR-148 | LLR-148.2 | TC-B97-28 | `fo:77` (`CHIP_FAMILY_SESSION`) · `fo:340` | pass | `chips_help.py:145` |
| US-138 | HLR-148 | LLR-148.3 | TC-B97-29 | `fo:227` (`no_project_reason`) | pass | `chips_help.py:216` · Layer 0 (M7 killed) |
| US-138 | HLR-148 | LLR-148.4 | TC-B97-30 | `s19_app/tui/open_folder_chip.py:66` (`OpenFolderChip`, `id_suffix`) | pass | `chips_help.py:334` |
| US-138 | HLR-148 | LLR-148.5 | TC-B97-31 | `s19_app/tui/open_folder_chip.py:218` (`titled_header`) · `app` screen headers | pass | `chips_help.py:729` |
| US-138 | HLR-148 | LLR-148.6 | TC-B97-32 | `wh:578` (`WindowHelpScreen`) · `wh:662` (`action_scroll_help`, Inc-7) | pass | `chips_help.py:806` · 100 % help coverage; `evidence/inc-7/green-r2.txt` |
| US-138 | HLR-148 | LLR-148.7 | TC-B97-33 | `sd:6691` (`PATCH_GLYPHS`) · `sd:6667` (`CHECK_GLYPHS`) · `fs:532` (`FLOW_KIND_GLYPHS`) · `fs:2386` | pass | `chips_help.py:863` |
| US-138 | HLR-148 | LLR-148.8 | TC-B97-57 | `fo:268` (`is_openable_chip_dir`) · `fo:247` (`chip_family_root`) | pass | `chips_help.py:389` · file / junction → 0 seam calls; Layer 0 (M3–M5, M8, M12 killed) |
| US-138 | HLR-148 | LLR-148.9 | TC-B97-58 | `sd:4090` (`CARD_NO_ENTRIES`) and the region-state lines of the four panels | pass | `chips_help.py:951` · one English line per region state |
| US-138 | HLR-148 | LLR-148.10 | TC-B97-65 | `fo:204` (`chip_label`) | pass | `chips_help.py:585` |
| **Inc-3..Inc-7 (`432ecf0`) — width-adaptive layouts** | | | | | | |
| US-139 | HLR-149 | LLR-149.1 | TC-B97-34 | `sd:6754` (`patch_layout`) · `sd:6859` (`check_layout`) · `fs:689` (`pipeline_layout`) · `fs:2478` (`lane_layout`) | pass | `width.py:47` · Layer 0 (M25, M27, M32, M33 killed) |
| US-139 | HLR-149 | LLR-149.2 | TC-B97-35 | the four layout functions above · `css` scoped sections | pass | `width.py:181` · 0 overflowing descendants |
| US-139 | HLR-149 | LLR-149.3 | TC-B97-36 | the four layout functions above | pass | `width.py:221` · actions inside at scroll 0 |
| US-139 | HLR-149 | LLR-149.4 | TC-B97-37 | `sd:6796` (`clip_param`) · `fs:627` / `fs:651` (`clip_head` / `clip_tail`) | pass | `width.py:247` · 0 wrapped rows |
| US-139 | HLR-149 | LLR-149.5 | TC-B97-38 | the four layout functions above | pass | `width.py:363` · void within bound; 118x53 arms retired at Inc-8 (LED-…97.40) |
| US-139 | HLR-149 | LLR-149.6 | TC-B97-59 | `fs:1060` / `fs:2641` (`ScrollableContainer` panels) · `sd:4359` / `sd:6916` | pass | `width.py:417` · reachable by key below 118x54, down to 80x24 |
| **Inc-8 (`354857c`) — two-row key bar** | | | | | | |
| US-140 | HLR-150 | LLR-150.1 | TC-B97-66 | `wh:774` (`WINDOW_KEYS`, the one window-key table) | pass | `key_bar.py:155` · `evidence/inc-8/green.txt` |
| US-140 | HLR-150 | LLR-150.2 | TC-B97-67 | `wh:938` (`global_tokens`) | pass | `key_bar.py:354` · 8 global tokens |
| US-140 | HLR-150 | LLR-150.3 | TC-B97-68 | `wh:956` (`window_tag`) · `wh:916` (`resolve_window_tokens`) | pass | `key_bar.py:437` |
| US-140 | HLR-150 | LLR-150.4 | TC-B97-69 | `app:7035` (`check_action`) · `app:7062` (`key_condition`) | pass | `key_bar.py:647` · 0 tokens outside the allowed set; Inc-7 height-only arms |
| US-140 | HLR-150 | LLR-150.5 | TC-B97-70 | `wh:989` (`pack_key_row`) · `wh:950` (`more_token`) | pass | `key_bar.py:1045` · Layer 0 (M3–M5 killed) |
| US-140 | HLR-150 | LLR-150.6 | TC-B97-71 | `app:2086` (`KeyBar(id="key_bar")` replaces `Footer`) · `wh:1091` (`KeyBar`) | pass | `key_bar.py:1134` · container −1 row |
| US-140 | HLR-150 | LLR-150.7 | TC-B97-72 | `wh:1046` (`KeyRow`) · `wh:1075` (`on_click`) · `wh:896` (`owner_widget`) | pass | `key_bar.py:1208` · a click runs the action |
| **Inc-9 (`5cb7618`) — Load project dialog (out-of-band, CW-U-1)** | | | | | | |
| — (R-TUI-013, CW-U-1) | HLR-151 | LLR-151.1 | — (no TC id) | `s19_app/tui/screens.py:691` (`LoadProjectScreen`, dismisses with `self.projects[index]`) | pass | `tests/test_b97_load_project_dialog.py::test_load_project_button_loads_the_picked_project` · RED on `354857c` (`evidence/inc-9/red.txt`), mutants 2/2 killed; invalid arm not-run (G-005) |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| *(example)* US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| *(example)* US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| *(example)* US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |
```

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance tests that observe the outcome through the shipped surface. All 26 AT ids pass in the orchestrator's gate run (`04-validation.md` §Layer B: none is among the 11 FAILED lines); C-18: each AT reconciles to one named function driving the whole chain. Node lines are on the tree at `c899113`.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-134 | AT-B97-01 (`patch_editor.py:1442`) | `#patch_doc_load_button` → `_patch_editor_load_tail` (`app:5316`) | every entry in the ledger; `#patch_json_view` parses with `json.loads` to the file's 6 addresses; stamp `6 entries · … · saved` | pass |
| US-134 | AT-B97-02 (`patch_editor.py:1474`) | Add, Save; empty and legacy v1 files | after Add the view holds 7 entries and the stamp says `unsaved changes`, after Save `saved`; empty and legacy documents shown as loaded | pass |
| US-134 | AT-B97-03 (`patch_editor.py:1510`) | Load of a hostile name and content | name and value read literally; 0 `MarkupError` | pass |
| US-134 | AT-B97-17 (`patch_editor.py:1538`) | keys only | the first task done from the keyboard | pass |
| US-135 | AT-B97-04 (`check_editor.py:1004`; empty arm in the sibling `check_editor.py:1039`, G-003) | rail, include button | every address painted in full; field count N → N+1 | pass |
| US-135 | AT-B97-05 (`check_editor.py:1060`) | A2L with a hostile parameter name | the name reads literally | pass |
| US-135 | AT-B97-18 (`check_editor.py:1095`) | keys only | the first task done from the keyboard | pass |
| US-135 | AT-B97-21 (`check_editor.py:1131`) | six parameters sharing one address; Write | six distinguishable rows; the written `.chk.json` parses to the included set | pass |
| US-136 | AT-B97-06 (`flow_builder.py:1471`) | palette, `#flow_run` | the chain on one painted row; `fw_app_patched.s19` absent before Run, present after | pass |
| US-136 | AT-B97-07 (`flow_builder.py:1506`) | kind chips, add form | each kind shows only its inputs; EXT-STEP adds a card | pass |
| US-136 | AT-B97-08 (`flow_builder.py:1546`) | hostile and NUL refs, Load | refs read literally; a NUL ref is refused with one line, never a crash | pass |
| US-136 | AT-B97-19 (`flow_builder.py:1607`) | keys only | the first task done from the keyboard | pass |
| US-137 | AT-B97-09 (`flow_execution.py:1990`) | `#fx_import`, `#fx_run` | three lanes run; the paused lane in view; English run log and REQUIRED line | pass |
| US-137 | AT-B97-10 (`flow_execution.py:2048`) | Save Set / Load Set | the saved set restored in a new app | pass |
| US-137 | AT-B97-11 (`flow_execution.py:2100`) | hostile and NUL inputs | rendered literally or refused | pass |
| US-137 | AT-B97-20 (`flow_execution.py:2181`) | keys only: run, pause, Confirm | the run completes from the keyboard | pass |
| US-137 | AT-B97-22 (`flow_execution.py:2243`) | mode control, per-lane rebind | each lane runs on its own image; `reports/*-chain-set-report.md` mode line parsed | pass |
| US-138 | AT-B97-12 (`chips_help.py:2016`) | chip presses (OS open seam spied) | each of four chips opens its folder or refuses | pass |
| US-138 | AT-B97-13 (`chips_help.py:2099`) | chips with no project | flow chips disabled; the status line names their folder | pass |
| US-138 | AT-B97-14 (`chips_help.py:2209`) | `?` help chip | a help body covering the screen | pass |
| US-138 | AT-B97-23 (`chips_help.py:2287`) | Run with a NUL bind, failing regions | each failed region says so in one line | pass |
| US-139 | AT-B97-15 (`width.py:1576`) | rail at 118x54 and 160x56 with the widest values | regions within bounds, painted rows whole, DataTable cells equal to the column | pass |
| US-139 | AT-B97-16 (`width.py:1651`) | `pilot.resize_terminal` in session | layouts grow and return | pass |
| US-139 | AT-B97-24 (`width.py:1726`) | the 119↔120 breakpoint and below the range, `tab` / `pagedown` | reachable by key below the range | pass |
| US-140 | AT-B97-25 (`key_bar.py:1373`) | rail keys, clicks on tokens | two painted rows on every window; a click runs the action | pass |
| US-140 | AT-B97-26 (`key_bar.py:1459`) | keys only, help, `.` on Patch | the target window shown, nothing typed; dim colour on keys that cannot act | pass |
| — (HLR-151) | no AT id — `tests/test_b97_load_project_dialog.py::test_load_project_button_loads_the_picked_project` | dialog: highlight `proj_b`, click Load | `app.current_project == "proj_b"`, dialog closed (app state, not painted text) | pass — partial surface (G-006) |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | AT-001 | `<handler/screen/CLI>` | `<outcome / file:path>` | pass |
```

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `7` (US-134…US-140; US-140 added 2026-10-20 by the PDR key-bar delta). HLR-151 traces to R-TUI-013 and CW-U-1, not to a batch story |
| Covered user stories | `7` (`100%`) — each story has ≥1 passing AT and a complete functional chain |
| Total HLR | `8` (HLR-144…HLR-151) |
| Implemented HLR | `8` (`100%`) |
| Total LLR | `73` |
| Implemented LLR | `73` (`100%`) — 72 with a TC id, LLR-151.1 with one integration node and no TC id |
| Test cases | `72` ids (TC-B97-01…72) |
| TC pass | `72` |
| TC fail | `0` |
| TC pending | `0` |
| Acceptance tests | `26` ids (AT-B97-01…26), `26` pass |

> Layer A executor attribution per `04-validation.md`: `software-dev` sub-agents ran the Inc-1…8 gates; the orchestrator ran Inc-9 and the full gate suite; `qa-reviewer` evaluated and executed none apart from two collection counts and the digest check. Test ledger: collected 3146 → 3634 (`3146 − 3 + 491`), reconciled by collection.

---

## 3. Detected gaps

> The requirement chain is complete for US-134…US-140. The gaps below are the seven minor gaps of `04-validation.md` §Gaps detected (0 blocker, 0 HIGH); G-005 and G-006 are the one trace gap of this matrix (HLR-151 has no story, AT or TC id). Each has an owner.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| G-001 | evidence | the gate transcript `suite-full.txt` records the source digests but not the command line or exit code | answered on the `Gate run` line of `04-validation.md`; future gate transcripts start with the command line |
| G-002 | test ledger | the packets' declared +A sums to 441; the collected delta is 491 | the measured ledger is the record (DDR DC-4) |
| G-003 | AT node shape | AT-B97-04's empty boundary arm sits in a sibling function | fold at a later Check Editor touch |
| G-004 | Layer 0 | `fx_run_error_line` is declared layer 0 with no named reddening mutation | add one mutant when Flow Execution is next touched, or drop the claim |
| G-005 | no coverage | LLR-151.1's invalid arm (no highlighted entry → no dismiss) has no node; LLR-151.1 has no TC id | integrity batch (DDR DC-1) |
| G-006 | no coverage | HLR-151 has no US / AT id; its node reads `app.current_project`, not the painted status line | integrity batch (DDR DC-1) |
| G-007 | supersession | Inc-9 carries no Correction population row; the sibling `str(Label)` in `app.py` `_load_from_item` survives | already in `.dev-flow/BACKLOG-CODE.md` (CW-U-1 status) |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| *(example)* G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |
```

---

## 4. Changes from previous batch

*(What was added, modified, or closed since the previous batch — `2026-10-12-batch-94` close.)*

| Type | Item | Detail |
|------|------|--------|
| new | HLR-144…151 · LLR-144.1…151.1 | the batch-97 requirement set, folded into `REQUIREMENTS.md` at the close (`81 folded, 0 kept, 0 refused`) |
| modified | Patch Editor (`PatchEditorPanel`) | batch-94's pe_b becomes pe_A: full-height ledger + inspector with Inspector / JSON / Checks tabs, a live read-only JSON view under a count · time · saved stamp; the geometry pass `_apply_window_geometry` deleted |
| modified | Check Editor (`CheckEditorPanel`) | ce_A: full-height parameter ledger with the Address never clipped, REPORT FIELDS card with Fields / JSON / Addendum tabs, one docked row with Write as the primary action |
| modified | Flow Builder (`FlowBuilderPanel`) | fb_A: one pipeline row of cards and cables, 7 kind chips, a contextual add form, Run on screen; `#flow_scope` removed (multi-variant work runs as lanes in Flow Execution) |
| modified | Flow Execution (`FlowExecutionPanel`) | fx_A: one pipeline per lane with cable status, attention lane brought into view, scoped `c` Confirm after a 0.5 s dwell, one run at a time, a lane with two external steps now reaches its end |
| new | chip families `flows`, `session` + real-directory guard | `folder_open_service` grows to 6 families; a chip opens only a real directory inside its family root; every chip names its folder |
| new | two-row key bar (US-140) | `KeyBar` replaces Textual's `Footer` on all 13 windows, fed from one window-key table (`WINDOW_KEYS`) that also generates the help keys block |
| new | NUL refusal | a NUL in any flow, chain-set, manifest or bound lane-input ref is refused with a finding (`FLOW-UNSAFE-REF`, `MANIFEST-PATH-ESCAPE`) instead of raising |
| modified | English UI strings | Flow Builder, Flow Execution and the flow execution service strings in English; `segment_split_view.py` cues `^E` → `e` |
| new | colour tokens | `WAITING_HUMAN` `#e8ad3d` and `CRC_FAMILY` `#c9562b` in `insight_style.py` |
| fixed | Load project dialog (HLR-151) | the dialog now loads the picked project (it dismissed with `Label()`, so no project ever loaded through it) |
| modified | snapshot baselines | 29 SVG cells regenerated locally after the harness race fix (a deviation from D17; one CI regen run recommended) |
| closed | 4 baseline failures | four failures present on `main` before the batch now pass (`05-close.md` §4) |
| carried | DDR DC-1…DC-5, PC-26, the P4 gaps, flakes, ux LOWs | routed to `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 (the b94 polish) close* |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-134** (Patch Editor) → HLR-144 → LLR-144.1…144.12 → TC-B97-01…07, 39…42, 60 · AT-B97-01/02/03/17
- **US-135** (Check Editor) → HLR-145 → LLR-145.1…145.10 → TC-B97-08…12, 43…46, 61 · AT-B97-04/05/18/21
- **US-136** (Flow Builder) → HLR-146 → LLR-146.1…146.14 → TC-B97-13…20, 47…51, 62 · AT-B97-06/07/08/19
- **US-137** (Flow Execution) → HLR-147 → LLR-147.1…147.13 → TC-B97-21…26, 52…56, 63, 64 · AT-B97-09/10/11/20/22
- **US-138** (chips + help) → HLR-148 → LLR-148.1…148.10 → TC-B97-27…33, 57, 58, 65 · AT-B97-12/13/14/23
- **US-139** (width-adaptive) → HLR-149 → LLR-149.1…149.6 → TC-B97-34…38, 59 · AT-B97-15/16/24
- **US-140** (two-row key bar) → HLR-150 → LLR-150.1…150.7 → TC-B97-66…72 · AT-B97-25/26
- **— (R-TUI-013, CW-U-1)** → HLR-151 → LLR-151.1 → no TC / AT id (`tests/test_b97_load_project_dialog.py`)

### 5.2 By code file
- `s19_app/tui/screens_directionb.py` → LLR-144.1…144.3, 144.5…144.10, 144.12, LLR-145.1…145.3, 145.5…145.8, 145.10, LLR-148.7, 148.9, LLR-149.1…149.6 (+ Inc-7 `AbDiffPanel.apply_regime`, Inc-8 `_DIFF_MIN_H`) → TC-B97-01…03, 05…12, 33…41, 43…45, 58…61
- `s19_app/tui/flow_screens.py` → LLR-146.1…146.5, 146.7…146.11, 146.13, 146.14, LLR-147.1…147.6, 147.8, 147.10…147.13, LLR-148.7, 148.9, LLR-149.1, 149.4, 149.5 → TC-B97-13…17, 19…26, 47…49, 51, 53, 55, 56, 62…64
- `s19_app/tui/app.py` → LLR-144.3, 144.5, 144.6, LLR-146.12, LLR-147.10, 147.13, LLR-148.4, 148.5, 148.9, 148.10, LLR-150.4, 150.6 → TC-B97-03, 05, 06, 30, 31, 50, 55, 58, 64, 65, 69, 71
- `s19_app/tui/styles.tcss` → LLR-144.4, 144.11, LLR-145.4, 145.9, LLR-146.5, 146.6, LLR-147.3, 147.4, 147.7…147.9, LLR-148.6, LLR-149.2…149.6, LLR-150.2, 150.3, 150.6 → TC-B97-04, 11, 17, 18, 23, 24, 32, 35…38, 42, 46, 52…54, 59, 67, 68, 71
- `s19_app/tui/window_help.py` → LLR-148.6, 148.10, LLR-147.13, LLR-150.1…150.3, 150.5, 150.7 → TC-B97-32, 64, 65, 66…68, 70, 72
- `s19_app/tui/services/folder_open_service.py` → LLR-148.1…148.3, 148.8, 148.10 → TC-B97-27…29, 57, 65
- `s19_app/tui/open_folder_chip.py` → LLR-148.3, 148.4, 148.5, 148.8, 148.10 → TC-B97-29…31, 57, 65
- `s19_app/tui/services/flow_persistence_service.py` · `s19_app/tui/services/variant_execution_service.py` → LLR-146.14 → TC-B97-62
- `s19_app/tui/services/flow_execution_service.py` → LLR-147.5 → TC-B97-25
- `s19_app/tui/insight_style.py` → LLR-146.6, 147.7 → TC-B97-18, 52
- `s19_app/tui/segment_split_view.py` → HLR-150 (LED-…97.43, the `^E` → `e` cues) → `tests/test_segment_split_window.py::test_export_cues_name_the_bound_export_key`
- `s19_app/tui/screens.py` → LLR-151.1 → `tests/test_b97_load_project_dialog.py`

> Source: the packets' §2 `Traces to` column (`03-increments/increment-001…009.md`).

**Worked examples of both maps — text to read, never lines of your record:**

```text
- *(example)* **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003
- *(example)* `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- *(example)* `src/bar.ts` → LLR-002.1 → TC-003
```

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-19-batch-97` |
| Closing date | `2026-10-25` (opened 2026-10-19; P5 closed 2026-10-25, close commit `c899113` on `main`; this P6 artifact written 2026-10-25) |
| Total iterations (sum of phases) | counted from the record (`05-close.md` §5): P0 1 · ARQ 1 · P1 1 + 3 iterations · P2 3 rounds + 1 scoped verification · PDR 1 seal + 1 scope delta · P3 9 increments, each with at least one gate fold · DDR 1 · P4 1 · P5 1 · P6 1. `state.json`'s `iterations_per_station` is stale for P2 (reads 0; declared in `05-close.md` §1) |
| Validation passed | yes — `PASS-WITH-NOTES` (7 minor gaps, 0 HIGH; §3) |
| Synced to Obsidian | no — the operator commits, pushes and runs `/dev-flow-sync` |
