# Functionality — s19_app — Batch 2026-10-19-batch-97

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-19-batch-97`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 At a glance (read first)

- **What this batch added:** the operator-approved prototype layouts (verdict A on all four screens) ported into the four batch-94 screens — Patch Editor (pe_A), Check Editor (ce_A), Flow Builder (fb_A), Flow Execution (fx_A) — plus `flows` / `session` folder chips and window help on each, width-adaptive layouts, a two-row key bar on all 13 windows, and a fix to the Load project dialog (`05-close.md` §1).
- **Capabilities:** a live read-only JSON view of the change-set under a count · time · saved stamp · a check-spec ledger whose addresses are never clipped · a flow drawn as one row of cards and cables with a contextual add form · one pipeline per lane with cable status and a scoped `c` Confirm · chips that open only a real directory inside their family root · layouts derived from the terminal size, 118x54 to 220x60, with no wrapped rows · a key bar that paints only the keys the active window handles.
- **How to use it:** launch the TUI (`s19_app/tui/app.py`, `S19TuiApp`); reach the four screens through the rail (`action_show_screen`, `app.py:6955`); press `?` on any screen for its help; the key bar's second row lists the active window's own keys.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

> Line anchors are measured on the tree at `c899113`; `s19_app/` and `tests/` there are byte-identical to the gated `432ecf0`. Every behaviour below is `approved` at P4 (`04-validation.md`, `Result: PASS-WITH-NOTES`) unless its line says otherwise.

### How it works (flow)

The batch re-composes four existing panels at their shipped ids and extends two services; no module was created and no boundary moved (ARQ, trigger A1 not fired; `PLAN.md` §Triggers). Nine increments, executed in the order Inc-1 → 2 → 3 → 4 → 5 → 6 → 8 → 9 → 7 (`PLAN.md` §Per-story status).

1. **Patch Editor — ledger + inspector + live JSON view (HLR-144, Inc-4).** `PatchEditorPanel` (`screens_directionb.py:4359`) keeps all 66 shipped ids. The left column is the full-height `#patch_doc_entries_table` (the growing region: 6 of 6 rows at 118x54, where batch-94 showed 3). The right column is one inspector with Inspector / JSON / Checks `TabChip`s over one `ContentSwitcher`. The Inspector tab carries the before→after hex strip (`before_after_card_text`, `:4112`; rows aligned to 8 bytes at 118 columns and 16 at 220, at most `STRIP_ROW_CAP = 8` rows), the labelled entry form and the entry chips. The JSON tab is read-only: the app builds one `PatchDocumentView` (`_patch_document_view`, `app.py:5299`) and passes it to every `refresh_entries` call site, so Load, Add, Save and a parsed paste all refresh the view at once, under the stamp `json_stamp_text` (`:6727`) — `N entries · HH:MM:SS · saved | unsaved changes`. The forced-geometry pass `_apply_window_geometry` and the app's show-time geometry block are deleted; widths come from the pure `patch_layout` (`:6754`) through `_apply_layout` (`:5320`) on mount, resize and show. Save is the panel's one filled action (operator decision 2).
2. **Check Editor — ledger + REPORT FIELDS card (HLR-145, Inc-3).** `CheckEditorPanel` (`:6916`): `#check_param_table` is an `IncludeTable` with columns `✓ · Parameter · Address · Fmt`. `check_layout` (`:6859`) sizes the columns so the Address column is never clipped (`max_scroll_x == 0` at 118x54 and 220x60); long names paint as first segment + `…` + tail (`clip_param`, `:6796`) and `#check_full_name_line` shows the highlighted name in full. The REPORT FIELDS card has Fields / JSON / Addendum tabs; the JSON tab is a real document (`"apply": false`) capped at `JSON_TAB_LINE_CAP = 5000` lines. Validate, Write `.chk.json` (the one filled action), the struck APPLY ghost and the field count sit on one docked row; the no-apply doctrine from batch-94 stays.
3. **Flow Builder — pipeline rail (HLR-146, Inc-2 + Inc-5).** `FlowBuilderPanel` (`flow_screens.py:1060`) paints the flow as one horizontal row of cards joined by `───▶` cables (`pipeline_text`, `:793`); `pipeline_layout` (`:689`) gives 24-cell cards at 118 columns for 4 blocks and 45 at 220, never below 21, and the frame scrolls sideways from the 5th card at 118. The palette is one `KindChip` per kind (7). The add form shows only the chosen kind's inputs; EXT-STEP puts log and output on a second row. The ribbon (`ribbon_text`, `:851`) reads `Flow: <name> · saved|unsaved`, the kind summary and the session directory. Run requests the single-image scope; `#flow_scope` is removed, and multi-variant work runs as one chain per variant in Flow Execution (operator decision 3). CRC cards paint in the new `CRC_FAMILY` token (`insight_style.py:131`). All Builder strings are English.
4. **Flow Execution — one pipeline per lane (HLR-147, Inc-2 + Inc-6).** `FlowExecutionPanel` (`:2641`) stacks lanes in `#fx_lanes_scroll`; each lane is a head line, its pending lines while it waits and one row of 5-row cards. `lane_layout` (`:2478`) is `pipeline_layout` minus a reserve for the Confirm chip, so card *k* starts at the same x in every lane. Each cable carries its block's status from the retained run record (`cable_glyph`, `:2445`): `▓` ok, `◇` notices, `✗` error, `░` not run / skipped, `□` into a waiting block. The panel alone owns the attention state; it brings the waiting card and its Confirm into view without moving the focus. `c` (`app.py:1455`, `action_confirm_attention` `:7085`) confirms the attention lane once per waiting entry after a 0.5 s dwell (`CONFIRM_DWELL_S`, `:2400`). Run and every displayed Confirm are disabled before the request is posted, so only one run is in flight; a run failure paints one line (`fx_run_error_line`, `:2500`), never a traceback. A lane with two external steps now reaches its end (the Inc-6 architect HIGH, fixed in the increment). The run log is English and capped at 8 lines (diagram `diagrams/sequence-attention-confirm.md`).
5. **Folder chips + window help (HLR-148, Inc-1, then each screen's increment).** `folder_open_service` gains the `flows` and `session` families (`folder_open_service.py:76-77`, six in all). `resolve_chip_target` (`:340`) maps `flows` → `<project>/flows` and `session` → `<project>`, `None` with no project. Before the operating-system open seam is called, `is_openable_chip_dir` (`:268`) requires a directory reached through no reparse point and lying inside the family root from `chip_family_root` (`:247`); otherwise the status line reads `Refused to open <target>: not a real folder inside <root>/` and the seam is not called. Chips are labelled `📂 Open <folder>/` (`chip_label`, `:204`); with no project a project-only chip is disabled and its reason names its folder (`no_project_reason`, `:227`). Each screen's help (`WindowHelpScreen`, `window_help.py:578`) names every control, input, tab, key and glyph as `label — effect`; from Inc-7 the body scrolls by key and Close reads `Close  esc` (diagram `diagrams/sequence-folder-chip.md`).
6. **Width-adaptive layouts (HLR-149, Inc-3..Inc-7).** The four pure layout functions recompute on every resize; the tests sweep 118x54, 119, 120, 160x56, 220x60 and 260x70, plus 80x24, 100x40 and 220x40 below or beside the range (`04-validation.md` Layer A). Below 118x54, down to 80x24, the screens stay reachable under scroll.
7. **Two-row key bar (HLR-150, Inc-8).** `KeyBar` (`window_help.py:1091`, mounted at `app.py:2086`) replaces Textual's `Footer` on all 13 windows and costs exactly one extra row. Row 1 is the global keys (`global_tokens`, `:938`), always including `? Help`. Row 2 is the window tag, then the window's keys, then its go keys, from the one window-key table `WINDOW_KEYS` (`:774`), which also generates each help's keys block. A key the window does not handle is neither painted nor live; one that cannot act now is dimmed (`check_action` / `key_condition`, `app.py:7035` / `:7062`). Rows hold whole tokens only and end with `? more` on overflow (`pack_key_row`, `:989`). A click on a token runs the binding's action in its own namespace, whatever holds the focus (operator decision on QA finding H-1) (diagram `diagrams/architecture.md`).
8. **Load project dialog (HLR-151, Inc-9).** `LoadProjectScreen` (`screens.py:691`) now dismisses with `self.projects[index]`. Before, it dismissed with the `Label` widget's string form (`Label()`), so no project ever loaded through the dialog. `enter` on the list is unchanged by decision (a `Selected` handler would load on one click); that interaction is routed to the Load+projects prototype round.
9. **Hardening carried by the flow work (LLR-146.14, Inc-2 + Inc-5).** A NUL character in any ref of a flow file, chain-set, project manifest, bound lane input or the Builder's add form is refused with a finding (`FLOW-UNSAFE-REF`, `CHAIN-SET-UNSAFE-REF`, `MANIFEST-PATH-ESCAPE`) and never raised. Batch-94's tree raised `ValueError` on such a load (`01-requirements.md` §2.7 P-36).

### Operator rulings honoured (the decision pins)

From `PLAN.md` §Key decisions, the PDR verdict and the gate decisions in `state.json` `decisions_log`:

- **Colours:** waiting-for-a-human `#e8ad3d`, CRC `#c9562b`; notices yellow `#f6ff8f` kept, with the operator's reservation to re-judge it on captures. The waiting colour is painted by no other element on the four screens (LLR-147.7).
- **Primary action per editor:** Patch Editor = Save, Check Editor = Write.
- **JSON tab:** live, with a stamp, read-only, no Update button.
- **Multi-variant runs:** one Builder chain per variant, run as lanes in Flow Execution; the Builder's scope selector is retired.
- **Key bar:** variant A, two rows; a click runs the binding's action, never a simulated key.
- **PDR decisions 1–3:** pe_A grid strip; one meaning for the check mark; a click selects a word in the mode toggle, `enter` / `space` toggle it.
- **Accepted for now:** the waiting lane's head and pending lines scroll out of view when the lanes scroll sideways (LED-…97.33); a next-batch prototype round is in the backlog.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel` re-composed (pe_A), `BeforeAfterCard` grid, `PatchDocumentView`, `json_stamp_text`, `patch_layout`; `CheckEditorPanel` re-composed (ce_A), `IncludeTable`, `TabChip`, `check_layout`, `clip_param`; Inc-7 `AbDiffPanel.apply_regime` refreshes bindings; Inc-8 `_DIFF_MIN_H` 28 → 29 (Inc-3, -4, -7, -8) |
| `s19_app/tui/flow_screens.py` | `FlowBuilderPanel` (fb_A) and `FlowExecutionPanel` (fx_A); `pipeline_text`, `pipeline_layout`, `ribbon_text`, `KindChip`, `FlowChip`, `ModeToggle`, `cable_glyph`, `lane_layout`, `fx_run_error_line`, `nul_add_refusal` (Inc-5, -6) |
| `s19_app/tui/app.py` | screen headers as `WindowSection` with both chips; JSON view wiring; `c` binding, `check_action`, `key_condition`, `action_confirm_attention`; `KeyBar` replaces `Footer` (Inc-3..-6, -8) |
| `s19_app/tui/styles.tcss` | one scoped section per screen (`batch-97 check_editor`, `patch_editor`, `flow_builder`, `flow_execution`), plus `key bar` and `help modal` sections; the shipped sheet stays a byte-equal prefix where the tests pin it |
| `s19_app/tui/window_help.py` | code-authored help sections for the four screens; `WINDOW_KEYS`, `KeyBar`, `KeyRow`, `pack_key_row`; help body scrolls by key (Inc-3..-8, -7) |
| `s19_app/tui/services/folder_open_service.py` | `flows` / `session` families, `chip_label`, `no_project_reason`, `chip_family_root`, `is_openable_chip_dir` (Inc-1) |
| `s19_app/tui/open_folder_chip.py` | `id_suffix`, label recomputed on refresh, guard before the seam (Inc-1); silent first refresh (Inc-5, the approved 5th source file) |
| `s19_app/tui/services/flow_persistence_service.py` · `variant_execution_service.py` | NUL pre-rejects in every ref parser (Inc-2) |
| `s19_app/tui/services/flow_execution_service.py` | 11 service strings in English (Inc-2) |
| `s19_app/tui/insight_style.py` | `WAITING_HUMAN`, `CRC_FAMILY` tokens (Inc-2) |
| `s19_app/tui/segment_split_view.py` | five painted cues `^E` → `e` (Inc-7) |
| `s19_app/tui/screens.py` | `LoadProjectScreen` Load handler (Inc-9) |

Source budget: every increment ≤ 4 source files except Inc-5 (5, approved by the operator at its gate) (`05-close.md` §5 `source_files_max: 5`).

### Usage / examples

```bash
# the batch's own verification (the packets' §3 and 04-validation.md Layer A)
pytest tests/test_b97_chips_help.py                    # Inc-1, extended by Inc-3..Inc-6
pytest tests/test_b97_check_editor.py                  # Inc-3
pytest tests/test_b97_patch_editor.py                  # Inc-4
pytest tests/test_b97_flow_builder.py                  # Inc-2 + Inc-5
pytest tests/test_b97_flow_execution.py                # Inc-2 + Inc-6
pytest tests/test_b97_key_bar.py                       # Inc-8 (+ Inc-7 height-only arms)
pytest tests/test_b97_load_project_dialog.py           # Inc-9
pytest tests/test_b97_width.py                         # Inc-3..Inc-7 width sweep
pytest tests/test_tui_directionb.py                    # the C-34 guard host, run at every render increment
```

These are the commands the packets and `04-validation.md` record; this document did not re-run them (P4's gate run is the evidence). Run them from the repository root in the project environment; the tests read colour, so do not set `NO_COLOR`.

Operator walkthrough (the AT scenarios): load a change-set in the Patch Editor and open the JSON tab — the stamp reads `saved`; add an entry — the view shows it and the stamp reads `unsaved changes`; open the Check Editor at 118x54 — every address is whole; include a parameter — the field count rises by one; in the Flow Builder load a 4-block flow — the chain is one row and Run is on screen; import three flows in Flow Execution and Run — a waiting lane is brought into view and `c` confirms it; press a `📂` chip — the folder opens, or the status line says why not; press `?` — the help names every control; look at the bottom two rows on any window.

### Risks / limitations (from the record)

- **No evaluation with real users** (`04-validation.md` §UX walkthrough: one expert agent reviewer, real-terminal captures; mouse-wheel help scrolling not tested).
- **Synthetic and demo fixtures only;** whether the app reads real memory images and A2L files correctly on the operator's own data is the integrity batch's subject (`05-close.md` §6).
- **Snapshot baselines regenerated locally,** not by the CI workflow design decision D17 named; one CI `snapshot-regen.yml` containment run is recommended (carried).
- **No fresh full-suite run** after the two test-only fixes; targeted re-runs only (`evidence/inc-7/post-suite-fix.txt`).
- **Runs stay on the UI thread;** a large image may freeze the UI (measured demo freeze 0.021 s, `01-requirements.md` §2.6 OUT list).
- **Flow Builder band 120–123 columns:** the 4-block chain scrolls sideways there because the wide rail takes 16 cells (Inc-5 packet, declared).
- **HLR-151** is traced to no story, AT or TC id; its invalid arm has no node (G-005, G-006 → integrity batch).
- **PC-26** (key-bar review page) is outstanding as an operator decision.

### Diagrams

- `06-docs/diagrams/architecture.md` — the four screens, the key bar and the services they use.
- `06-docs/diagrams/sequence-attention-confirm.md` — a Flow Execution run that pauses on an external step and the scoped `c` Confirm.
- `06-docs/diagrams/sequence-folder-chip.md` — a folder-chip press through the target resolution and the real-directory guard.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] Audience and purpose declared at the top of the doc (or implicit and obvious). — ✓ header: technical stakeholder, Phase 6, `docs-writer`.
- [x] Structure follows the relevant template (or a justified deviation is noted). — ✓ `templates/functionality-template.md` sections kept; added "Operator rulings" and "Risks / limitations", as batch-94 did for the first.
- [x] Code/CLI snippets actually run (or marked "untested"). — ✓ the pytest commands are the packets' and `04-validation.md` Layer A's own; marked above as not re-run by this document.
- [x] Assumptions listed. — ✓ the operator rulings section; the line-anchor tree (`c899113` = `432ecf0` for `s19_app/` and `tests/`) stated under Detail.
- [x] Risks / limitations called out. — ✓ "Risks / limitations (from the record)".
- [x] Next steps stated. — ✓ `executive-summary.md` §Next steps and `traceability-matrix.md` §3 (owners per gap).
- [x] Diagrams included where flow is non-trivial. — ✓ three mermaid diagrams under `06-docs/diagrams/`.
- [x] No invented APIs / version numbers / metrics. — ✓ figures from `04-validation.md`, `05-close.md` and the packets (81/81, 26/26, 3146 → 3634, 3617 passed / 11 failed); symbol lines grepped on the tree.
