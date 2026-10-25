# Increment 005 — HLR-146 (+ Builder arms of HLR-148 / HLR-149) · `Flow Builder: pipeline rail with a contextual add form`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-005.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `005` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | gate fold: `LLR-148.3` (LED-…97.24), `LLR-149.5` (.25), `LLR-146.11` (.26; supersedes batch-53 `LLR-003.1`), `HLR-146` / batch-51 `LLR-088.5` (.27), `LLR-148.9` + `LLR-146.14` (.28) · `HLR-146 / LLR-146.1–146.13`, `LLR-146.6` paint half, `LLR-146.14` add-form arms (`LED-…97.23`) · `LLR-147.5` module scope (`flow_screens.py:235`) · Builder arms of `LLR-148.5, 148.6, 148.7, 148.9` · Builder arms of `LLR-149.1–149.6` |
| Acceptance | AT-B97-06, AT-B97-07, AT-B97-08, AT-B97-19 (layer B) · TC-B97-13..20, 47..51, 62 (add-form + helper arms), TC-B97-25 (module arm) · TC-B97-31..33, 58 (Builder arms) · TC-B97-34..38, 59 (Builder arms) |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-21` · gate fold `2026-10-22` |
| Design refs | `PDR-2026-10-19-batch-97#D6`, `#D7`, `#D8`, `#D11`, `#D12`, `#D21`, `#D23`, `#D25`; I-6 (S4-1), I-8; PDR delta 2026-10-21 (b); PC-7 (implemented here), PC-10, PC-11, PC-24 (owed here) |

---

## 1 · What changed

The Flow Builder now shows the chain as one row of block cards joined by cables, with Run on screen. The layout follows fb_A and decision B (`LED-…97.11`). Every shipped id is kept except `#flow_scope` (D8).

- **Ribbon (LLR-146.11):** `#flow_ribbon` holds `#flow_name_strip`. It paints `Flow: <name>  · saved|· unsaved` (gate fold, operator decision 3; was `●|✓`), the kind summary (`LOAD → PATCH → …`) and, right-aligned, `session <path tail>`. With no project it ends with `session (no active project)`. The text comes from the pure `ribbon_text(...)` at the measured ribbon width. `#flow_ext_session` stays mounted and is not displayed.
- **Pipeline (LLR-146.1, 146.4, 146.6, 146.8):** `#flow_pipeline_scroll` is a frame with `height: auto` that holds `#flow_pipeline`. The pure `pipeline_text(blocks, card_w)` paints each card as `7 + 2·m` rows (11, or 13 with an EXT-STEP). `───▶` cables sit on the output row. The pure `pipeline_layout(avail_w, n)` gives the card width: 24 at 118 for 4 cards, 45 at 220, never below 21. From the 5th card at 118 the frame scrolls sideways. **Declared (code-reviewer F5):** in the 120–133 column band (degraded, `LED-…97.13`) the shell's wide rail takes 16 cells, so the 4-block chain itself scrolls sideways at **120–123 columns** (rail 92–95 cells < 96 = 4·21 + 3·4); from 124 it fits again (`band-fold.txt`, measured 118–134; the reviewer's estimate was ~127). `clip_head` clips titles and commands; `clip_tail` clips refs, logs and outputs. File text goes through `safe_text`. The CRC card paints in `CRC_FAMILY`. The frame title is `chain · N blocks`. With no blocks the frame shows one line: `No blocks yet — a chain starts with ◉ LOAD …`. `#flow_canvas`, `#flow_blocks`, `#flow_help` and `#flow_kind` stay mounted and are still repainted, but are not displayed.
- **Palette + add form (LLR-146.2, 146.3):** there is one `KindChip` per kind of `_KIND_OPTIONS`, 7 in all. `KindChip` binds `space`; it is declared in `flow_screens.py`, with no `TabChip` import. `#flow_add_row` holds a kind tag, a field label and only that kind's inputs. For EXT-STEP the inputs are mode and command, with log and output on `#flow_ext_row`, which is now nested in the add fields so it is the second row. A `Manual` mode renames the command field `instruction`. `_PALETTE_TYPES` is retired.
- **NUL refusal at Add (S4-1, LLR-146.14):** the first statement of the `flow_add` branch calls the pure `nul_add_refusal(kind, values)` over `_ADD_PATH_INPUTS`. On a NUL it paints `Add refused: [FLOW-UNSAFE-REF] <kind> <field> carries a NUL character - not a path` and returns. No block is added and the inputs keep their text.
- **Strip, Variables, foot row (LLR-146.5, 146.9, 146.10):** the copy/paste strip (`copy block #`, Copy, Paste, status) and `Variables (n)` share one row. Run, Clear, Save… and Load… are 1-row chips, and Run is the one `fill-accent`.
- **Result area (decision B, LLR-149.5):** `#flow_result` is the `1fr` growing region with no border. Before a run it shows one line: `No run yet — Run executes this chain …`. `_BLOCK_STATUS_GLYPH` error `✖` → `✗` (D7). The paused banner reads `PAUSED - WAITING FOR A HUMAN` (`:235`, LLR-147.5). A refused load's card lines now read `[<code>] <message>`, so a NUL load paints one line naming `FLOW-UNSAFE-REF`. The frame's bottom border shows `load refused: flows/<stem>.json — this chain is kept` (LLR-148.9).
- **Legend (LLR-148.7):** `#flow_legend` is generated from `FLOW_KIND_GLYPHS` + `FLOW_CABLE_GLYPHS` on one row. `≡ report` is shown only while the chain carries a report block (see §6).
- **English (LLR-146.7):** all 27 Spanish `FlowBuilderPanel` constants are translated.
- **app.py:** `titled_header("Flow Builder", OpenFolderChip("flows"), help_button=…)` (LLR-148.5). The D8 variant branch of `on_flow_builder_panel_run_requested` is deleted, so Run always runs `run_flow`. There is no `Binding(` line in the diff.
- **styles.tcss:** `$crc-family` / `$waiting-human` are mirrored after `$odd-row` (TC-B97-18 mirror arm). `#flow_gating` / `#flow_result` move into one `/* batch-97 flow_builder */` section, with every selector rooted at `#flow_panel`. `.flow-name-strip`, `.sev-*`, `.modal-hint` and `.patch-docked-row, .patch-docked-group` are byte-equal to `09e44de`.
- **window_help.py:** `flow` is rewritten as code-authored (D25), with one `label — effect` line per chip, field, key and glyph.

**Visible deltas vs fb_A** (`prototypes/b94_polish/png/fb_A*.png` vs `evidence/inc-5/png/impl.flow-builder*.png`):
1. The CRC card paints `#c9562b`, not `#d9a35b` (decided).
2. The result error mark is `✗`, not `✖` (decided).
3. The pipeline frame has no blank padding rows, and the result area takes the spare rows (decision B).
4. **New, not decided before:** the copy/paste + Variables row sits *under* the add form, not under the frame. The reason is LLR-146.13's focus order (kind chips → add inputs → Add → copy/paste → Variables → foot). Textual sorts the focus chain by on-screen position (`Widget._focus_sort_key`), so the fb_A order would invert the groups.
5. The chips paint a `$bg-panel` cell box and have no padding beyond Button's line-pad, so the seven kind chips fit the 96-cell panel of the 120–133 band.
6. The header gains `📂 Open flows/`.
7. A legend row has been added.

### 1b · Gate fold

Gate fold (2026-10-22). **Five source files**: the four Inc-5 files plus `s19_app/tui/open_folder_chip.py`, approved by the operator at the Inc-5 gate (2026-10-22) as a fifth source file for operator decision 1 only. `app.py` is not touched by the fold (digest unchanged, `fd5c6960…`); no `Binding(` anywhere in `app.py`'s diff. Operator decisions were asked at the Inc-5 gate on 2026-10-22 and relayed by the orchestrator; each has a ledger entry citing that.

| Finding | What changed | Pinned by |
|---|---|---|
| **Operator 1 — chip announces only on a transition** (LED-…97.24) | `OpenFolderChip.refresh_target` reads and sets `_resolved_once`: the first call (from `on_mount`) writes no status line; a transition to disabled after mount writes `no_project_reason(family)`. LLR-148.3 amended; batch-95 TC-704's status arm superseded by name (the reason now read after a load-then-drop transition; the Reports modal chip is refreshed by its own `refresh_target`, because the app's refresh loop queries the default screen only). **On press:** a disabled `Button` swallows the press in Textual (`Button.press` returns early when `disabled`), so a disabled chip cannot write the reason on press — the tooltip keeps it; a chip enabled when pressed whose target has since become `None` writes it (`_open_target`, unchanged). This half of the decision is met only that way; flagged in §6. **PC-10 re-verified per cell:** 0 of 29 cells differ from `09e44de` (`cells-fold.txt` is byte-identical to `cells-head.txt`, `cells-diff-fold.txt` empty); the earlier falsification (29 of 29, one status row each) is kept in §4 as history | `test_tc_b97_29_no_status_line_at_startup_without_a_project` (NEW), `test_tc_b97_29_no_project_chips_disabled_with_their_own_reason`, `test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason` (rewritten, `chips_help.py`), `test_tc704_…` (named supersession) — all RED on the pre-fold source at the at-mount clause; statuses recorded through a `set_status` wrapper (`b97_probes.record_statuses`; `app.log_lines` is a `deque(maxlen=4)`); M40, M41 |
| **Operator 2 — air in the control block** (LED-…97.25) | Scoped section: `margin-top: 1` on `#flow_palette`, `#flow_clip_row`, `#flow_run_row`; `border-top: solid $rule` on `#flow_result`. To keep a 4-block run unscrolled at 118x53: `.flow-banner` margin 0 (ux L2), `.flow-ribbon` margin 0 (the blank row before the memory ribbon — a third trim the brief did not name; without it the run needs 17 rows and 118x53 has 16), and the written path on one row (ux M1). **Measured result area** (`#flow_result` content rows under the rule row, `budget-fold.txt`): 4-block chain **17 · 16 · 23 · 22** at 118x54 · 118x53 · 220x60 · 220x59 (were 21 · 20 · 27 · 26); EXT-STEP chain with its form open **14 · 13 · 20 · 19**. The 4-block run needs exactly **17 / 16** rows: `max_scroll_y` 0 at all four sizes, **0 rows of slack at 118x54 and 118x53**. LLR-149.5's Builder arm and TC-B97-38 amended ("k = 3 named separator rows") | `test_tc_b97_38_builder_height_goes_to_the_result[*]` (6 nodes: separators == the 3 named rows, rule row `─`, `NOTICES`, four verdict heads, `max_scroll_y == 0`, one-row `wrote …`); RED on the pre-fold source (`[]` vs `[17, 19, 20]`); M49–M52 |
| **Operator 3 — ribbon saved state as a word** (LED-…97.26) | `ribbon_text`: `· saved` in `DGRAY`, `· unsaved` in `YELLOW`. Colour: `YELLOW` (`#f6ff8f`, `.sev-warning`) is the attention colour the dirty strip already carried; `WAITING_HUMAN` (`#e8ad3d`) is reserved by LLR-146.6 / 147.7 for what waits for a human, so it was not used. Help: `✓` / `●` lines keep one meaning each; a `saved / unsaved` line added. Batch-53 LLR-003.1's glyph superseded by name (AT-002 and three more nodes) | `test_tc_b97_49_ribbon_saved_state_is_a_word` (layer 0), `test_tc_b97_49_ribbon_paints_saved_then_unsaved` (painted, hue ≤ 4° of YELLOW, grey unsaturated) — both NEW, RED on the pre-fold source; `test_at002_…`, `test_at006_quarantine_…`, `test_at005_dirty_guard_…` (`test_tui_flow_persistence_ui.py`), `test_at_b94_17_…` (named supersession); M45, M46 |
| **Operator 4 — `ISSUES` → `NOTICES`** (LED-…97.27) | `render_result`: `completed-with-issues` with no block in `error` → `NOTICES` (yellow, `sev-warning`); `ISSUES` stays when a block erred without aborting (LLR-088.5's AT-088a case). LLR-088.5 (batch-51) **does** pin the literal: superseded by name for the notices-only case (`test_at085a_…`). HLR-146's threshold and AT-B97-06 read `NOTICES` | `test_b97_flow_builder.py` AT-06 ×2, TC-50 (were `ISSUES`); `test_b97_width.py` TC-38 after-run; `test_at085a_…` (supersession); `test_at088a_…` green (ISSUES kept); M47, M48 |
| **code F1 (HIGH)** | TC-B97-34 hidden arm also returns `#flow_pipeline_scroll.scrollable_content_region.width` and asserts `hidden == fs.pipeline_layout(rail_w, 4).card_w and hidden > fs.CARD_MIN_W` before the equality. Verdicts: **M29** (`on_show` removed) **GREEN — SURVIVED** (equivalent: showing a `display: none` screen delivers a Resize, so `on_resize` re-derives); **M29b** (both triggers removed, two edits) **RED — KILLED** at the new clause: `(21, 192)` — no layout pass ran, the card stayed at the 21-cell default (the reviewer's finding: both sessions then paint 21 and the equality alone passed). §4's earlier M29 text ("RED only with both triggers removed") was not executed and was wrong; corrected below | `tests/test_b97_width.py::test_tc_b97_34_builder_resize_while_hidden_rederives_on_show` (`:886-908`); `mutations-fold.txt` |
| **code F2 (HIGH)** | `PipelineLayout(card_w, spare)`: `spare` = the remainder of `(avail − 4·(n−1)) // n` (0 … n−1, 0 when the 21-cell minimum binds); `pipeline_text(blocks, card_w, spare)` widens cable i by 1 when `i < spare`. The chain now paints exactly the rail width | `test_tc_b97_38_pipeline_spare_cells_go_to_the_cables[2..6]` (NEW, layer 0, rail widths 60–260); `test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width` + **163x56, 223x60** (RED on the pre-fold source: void **3** at both); M42, M43 |
| code F3 | TC-51: `poll(lambda: app.focused is <widget>)` before each `settle` after `focus()` (scroller, anchor, chip ×2) | `test_tc_b97_51_…` green |
| code F4 | Docstrings with Args / Returns / Data Flow / Dependencies on `nul_add_refusal`, `clip_head`, `clip_tail`, `pipeline_layout`, `pipeline_text`, `ribbon_text`, `flow_legend_text`, `KindChip` | review |
| code F5 | Declared in §1 and §5: 120–123 columns scroll the 4-block chain sideways (measured, `band-fold.txt`) | — |
| code F6 | The `_RIBBON_CELLS` comment now says the table is batch-51's (bordered pane) and that the current `#flow_result` is wider; `render_fused_result` has no production caller (D8 keeps it) → `.dev-flow/BACKLOG-CODE.md` (batch-97 section) | — |
| ux H1 / M2 | = operator decisions 2 / 3 | — |
| ux M1 | The written path is one row `wrote <path, tail kept at the result width>` (`.flow-wrote-path`, re-clipped by the layout pass, CSS nowrap as backstop). The WRITE-OUT node's own summary (`wrote fw_app_patched.s19`, service text) is unchanged; the path line no longer wraps to 2 rows | TC-38 after-run (one row, tail `fw_app_patched.s19`); `test_at088b_…` expected `wrote <path>` (named supersession; first fold gate run RED on the sink census — the line had moved its `safe_text` into a helper; fixed by rendering `safe_text(...)` at the `# SINK:` site); M52 |
| **ux M3** (LED-…97.28) | Add with the single-ref field empty → `Add needs <field label> — nothing added` in `#flow_wiring_notice`; LLR-148.9's Builder row gains the add-form error state | `test_tc_b97_58_add_with_an_empty_field_says_what_it_needs[source, check, write_out]` (NEW, RED on the pre-fold source); M44 |
| ux L1 (LED-…97.28) | `nul_add_refusal` names kind and field by UI labels: `Add refused: [FLOW-UNSAFE-REF] WRITE-OUT output file holds a NUL character - not a path`; code kept. HLR-146's threshold ("naming `FLOW-UNSAFE-REF`") still met; LLR-146.14's "the field name" → "the kind and field labels" | TC-62 helper ×9 + add-form ×9, AT-B97-08 (literal) — RED on the pre-fold literal; M53 |
| ux L2 | = the banner's blank row removed (operator 2) | M51 |
| **ux L-a (gate re-read)** | `on_button_pressed` clears `#flow_wiring_notice` on a palette kind change and on Run: a stale `Add needs …` line held the result area's only spare row at 118x53 and hid `wrote …` after a good run | `test_tc_b97_58_add_notice_clears_on_kind_change_and_run[kind change, Run]` (NEW); M54, M55 KILLED (`mutations-gate-reread.txt`) |
| code L1 (gate re-read) | the spare-cells arm skips a width only where the 21-cell minimum binds, so a 21-cell chain with spare cells is now pinned | `test_tc_b97_38_pipeline_spare_cells_go_to_the_cables[2..6]` green |
| ux L3 | design §3 Builder tree amended by name: palette + add form (EXT row nested) before the clip row, for LLR-146.13's focus order; separators and rule row drawn | `design/design-proposal.md` §3 |
| ux L4 | §6 item 3 relabelled: `≡ report` only with a report block **is D7's own text**, not a deviation | §6 |
| ux L5, L6, ⚠1, `✖` in the report service | routed to `.dev-flow/BACKLOG-CODE.md`, batch-97 section (stale verdicts after an edit; empty-clipboard Paste silent + LOAD placeholder `e.g. prg.s19`; `SaveFlowScreen` (`screens.py:733`) not closing on `escape`; `flow_report_service.py:111` `✖`) | — |

**Visible deltas vs fb_A after the fold** (`png/impl.flow-builder*.png` vs `*.pre-fold.png` and `prototypes/b94_polish/png/fb_A*.png`): one blank row above the kind chips, the copy/paste strip and the run row, and a `$rule` line opening the result area (fb_A's air); `· saved` grey on the ribbon (no glyph); `NOTICES` banner directly above the first verdict; the written path on one row with its head clipped (`wrote …jgh8\Github\…\fw_app_patched.s19`); the memory ribbon directly under the last verdict. The `· unsaved` yellow state is not in a capture (every scenario loads a saved flow); it is pinned headless by hue.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/flow_screens.py` | source | HLR-146, LLR-146.1–146.14, LLR-147.5, LLR-148.7, 148.9, 149.1, 149.4, 149.5 | `FLOW_KIND_GLYPHS`, `FLOW_CABLE_GLYPHS`, `_KIND_LOOK`, `_REF_FIELD`, `_ADD_PATH_INPUTS`, `nul_add_refusal`, `clip_head`/`clip_tail`, `PipelineLayout`/`pipeline_layout`, `pipeline_text`, `ribbon_text`, `flow_legend_text`, `KindChip`; `FlowBuilderPanel` re-composed; layout pass (`on_resize`/`on_show`/`_apply_layout`); English strings; `✗`; paused banner; quarantine code prefix + frame subtitle; `_PALETTE_TYPES`/`_SCOPE_OPTIONS` removed. **Fold:** `PipelineLayout.spare` + cable widening; `nul_add_refusal` UI labels; ribbon word; `_NOTICES_BANNER`; `Add needs …`; `_wrote_line` + re-clip in `_apply_layout`; docstrings (F4); `_RIBBON_CELLS` comment (F6) |
| `s19_app/tui/app.py` | source | LLR-146.12, LLR-148.5 | `📂 Open flows/` header chip; D8 variant branch deleted |
| `s19_app/tui/styles.tcss` | source | LLR-146.5, 146.6, 146.13, 149.2, 149.3, 149.5 | token mirrors; `#flow_gating`/`#flow_result` moved; one scoped `batch-97 flow_builder` section. **Fold:** separator margins, result rule row, banner / memory-ribbon margins 0, `.flow-wrote-path` (all inside the scoped section) |
| `s19_app/tui/window_help.py` | source | LLR-148.6 | `flow` body rewritten (code-authored). **Fold:** Add / saved-unsaved / NOTICES / ISSUES lines; `✓`, `●` one meaning each |
| `s19_app/tui/open_folder_chip.py` | source | LLR-148.3 (LED-…97.24) | **5th source file, fold only — approved by the operator at the Inc-5 gate 2026-10-22 for decision 1.** `_resolved_once`; the first `refresh_target` is silent |
| `tests/test_b97_flow_builder.py` | test | HLR-146, LLR-146.1–146.14 | +41 nodes (TC-13..20, 47..51, 62 ×18, AT-06 ×2, 07, 08, 19, CSS guard); local hue helper → probe |
| `tests/test_b97_width.py` | test | HLR-149, LLR-149.1–149.6 | +34 Builder nodes |
| `tests/test_b97_chips_help.py` | test | LLR-148.5, 148.6, 148.7, 148.9 | +8 Builder nodes; `WT_NARROW_GLYPHS` extended (14 glyphs) |
| `tests/test_b97_flow_execution.py` | test | LLR-147.5 | +1 node (module arm) |
| `tests/b97_probes.py` | fixture | LLR-146.6 (PC-7) | `ColourRun`, `span_colours`, `hue_distance`, `hue_matches`, `HUE_TOLERANCE`, `MIN_SATURATION`, `settled` |
| `tests/b97_fixtures.py` | fixture | HLR-146 (A.5) | `baseline_check`, `write_flow`, `patch_chain_demo`, `flash_chain_demo`, `crc_chain_demo`, `hostile_flow_demo`, `flow_project`, `open_flow_builder`, `load_flow` |
| `tests/test_tui_flow_builder_b94.py` | test | LLR-146.2, 146.14 | named supersession: palette = `_KIND_OPTIONS` (7); AT-B94-18 canvas arm binds the payload minus its NUL |
| `tests/test_flow_external_step_b96.py` | test | LLR-146.2, 146.7, 146.11 | named supersession: palette, English refusal, hidden session line |
| `tests/test_flow_funnel_b96.py` | test | LLR-146.7, 146.10 | named supersession: `Variables (1)`, English notices |
| `tests/test_flow_multi_image_ui.py` | test | LLR-146.12 | 3 nodes retired (scope select), `this_image` rewritten; 185/271 kept |
| `tests/test_window_usage_help.py` · `tests/test_changes_file_notation_help.py` | test | LLR-148.5, 148.6 (D25) | `flow` leaves the md census; the header seat gains `open_folder_flows` |
| `AT-TC-REGISTRY.jsonl` | config | LLR-146.12 | TC-642 drops the 3 retired node ids (G2 guard) |
| `prototypes/b94_polish/run_real.py` | doc | | untracked harness: `flow-builder-run` scenario; session dir set for the real tree |
| `.dev-flow/…/evidence/inc-5/*` | doc | | evidence (§4) |
| `tests/test_flow_builder_render.py` | test | HLR-146 | named supersessions LED-2026-10-19-batch-97.25 / .27 (`NOTICES` banner, one-row written-path line); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own |
| `tests/test_tui_flow_persistence_ui.py` | test | HLR-146 | named supersession LED-2026-10-19-batch-97.26 (`· saved` / `· unsaved` word replaces the glyph); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own |

| Count | Value |
|---|---|
| **SOURCE files** | **`5` / 4 — over the cap by one, approved**: the four Inc-5 files plus `s19_app/tui/open_folder_chip.py`, approved by the operator at the Inc-5 gate (2026-10-22) as a fifth source file for decision 1 only (the chip's mount-time status line; it lives in that file and nowhere else, so it could not be cut smaller). `app.py` is unchanged by the fold |
| Test files | 11 (6 b97 modules/helpers, 5 superseded) + 1 config (`AT-TC-REGISTRY.jsonl`). **Fold:** + `tests/test_open_folder_chips.py`, `tests/test_flow_builder_render.py` (named supersessions), `tests/b97_fixtures.py` (`unload_project`), `tests/b97_probes.py` (`record_statuses`) |
| Doc files | this packet, evidence, one untracked harness file |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8; unset NO_COLOR
python -m pytest $(cat .dev-flow/2026-10-19-batch-97/evidence/inc-5/gate-files.txt) -q -rfE -p no:cacheprovider
python .dev-flow/2026-10-19-batch-97/evidence/inc-5/mutate.py            # 39 mutants / 51 arms
python .dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_budget.py    # PC-24 budget
python .dev-flow/2026-10-19-batch-97/evidence/inc-5/frames.py <tree>     # Check / Patch / Execution frames
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/snapshot_cells.py <tree>   # PC-10
powershell -File prototypes/b94_polish/capture.ps1 -Scenario flow-builder[-ext|-run] -RealTree -OutPng <png> [-Rows 53 | -Cols 220 -Rows 60]
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `clip_head`/`clip_tail`, `pipeline_text` card arm, `pipeline_layout`, `nul_add_refusal` ×9, TCSS mirror, CSS guard, censuses TC-19/TC-25 | passed |
| **A · white-box** | `core` · `full` | gate set (`gate-files.txt`, 28 files incl. guard host `test_tui_directionb.py`, snapshot module, Check/Patch b97 modules) | **488 passed, 29 xfailed, 2 failed** (`green.txt`). The 2 failures are not in the baseline: `test_tui_legend.py::test_at023e_c13_geometry_at_80_cols` and `test_tui_patch_json.py::test_at079a_gauge_tracks_buffer`. Both are single-`pause()` nodes, and both pass **5/5 isolated on the Inc-5 tree and 5/5 on a clean `09e44de` worktree** (`rerun-nonbaseline.txt`): this is the load-flake class, not Inc-5 |
| re-run after edits | | the four b97 flow modules whole (after the docstring edit and the TC-38 clauses) | **214 passed** (`green-after-fixes.txt`) |
| **Full suite (gate close)** | `full` | whole suite, Inc-5 final source (`suite-full.txt`) | **3404 passed, 10 failed, 3 skipped, 32 xfailed** in 1:33:54. Against `baseline-pytest-51ee191.txt` (10 failed): 3 not in the baseline — `test_tc330_before_after_row_reveal_hide_state_machine`, `test_save_back_prompt`, `test_ac2_1_ctrl_z_y_undo_redo_via_real_key`; 3 baseline nodes passed (`test_at064c_…`, `test_at_batch41_…`, `test_ac1_checks_panel_…`). The 3 re-run 5× isolated on the Inc-5 tree: 13 of 15 passed (`suite-rerun-nonbaseline.txt`); on a clean `09e44de` worktree tc330 failed 2/10 and ac2_1 3/10, save_back_prompt already intermittent at Inc-4 (`suite-head-flake-check.txt`) — pre-existing flakes, not Inc-5 |
| **B · black-box** | `core` · `full` | AT-B97-06 ×2 (118x54, 118x53), -07, -08, -19 | passed (same runs) |

**PC-24, the 118x53 arms:** TC-B97-36 Builder arm, TC-B97-38 Builder height clause (before and after run) and AT-B97-06 all pass at 118x53. The budget measured on the real tree (`budget.txt`) equals the design §3 table:

| Size | H | Fixed rows | Frame (cards) | Result (4-block) | EXT-STEP chain: frame · result | Run inside |
|---|---|---|---|---|---|---|
| 118x54 | 40 | 6 | 13 (11) | **21** | 15 · **18** | yes |
| 118x53 | 39 | 6 | 13 (11) | **20** | 15 · **17** | yes |
| 220x60 | 46 | 6 | 13 (11) | **27** | 15 · **24** | yes |
| 220x59 | 45 | 6 | 13 (11) | **26** | 15 · **23** | yes |

**PC-10 after the gate fold — 0 of 29 cells differ** (`cells-fold.txt` byte-identical to `cells-head.txt`, digest `8bc937d1…`; `cells-diff-fold.txt` empty). The prediction (0 drift) holds again once the chip is silent at mount (LED-…97.24). The first Inc-5 run's falsification stays recorded below.

**PC-10 — first Inc-5 run (history): prediction falsified.** Prediction: 0 of 29 cells drift. **Verified: 29 of 29 cells differ, each by exactly one row**, the bottom status-log line: `📂 Open flows/: no active project — load a project first.` (`cells-head.txt` / `cells-inc5.txt`, classified in `cells-classified.txt`). The cause is that the new header chip mounts at app start with no project. Inc-1's `OpenFolderChip.refresh_target` (`open_folder_chip.py:122-128`) posts that status line on the "newly disabled" transition, and the first mount counts as one. All 29 cells stay inside the batch-94 `xfail(strict=False)` envelope (29 xfailed). The fix belongs in `open_folder_chip.py`, a fifth source file, and was not taken (§6).

**Neighbour screens (design item (6)):** the painted frames of the Check Editor, the Patch Editor and Flow Execution at 118x54 and 220x60 are **identical** to `09e44de` (`frames-diff.txt` is empty). Positive control: `.flow-name-strip margin-bottom: 0` shifts Flow Execution rows (4 differing lines, `frames-positive-control.txt`); restore proven by SHA-256.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new tests ran on the unchanged HEAD `09e44de` source (digests in the transcript headers) |
| Transcript | `red.txt` — **81 failed, 48 passed** over the selection (the 48 passing are Inc-1/Inc-2 nodes the `-k` also matched, plus 2 TC-36 sizes where Run is inside on main) |
| Instrument | pytest, one complete run per transcript; restores n/a (no source edit) |
| Where it ran | the working tree, by this sub-agent (no other session reading it) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 129 selected = 81 + 48 |
| Verdict granularity | per node (`-rfE --tb=line`) |
| Arms that stayed GREEN | TC-B97-36 Builder at 220x60 / 260x70 (Run inside on main) and TC-B97-59 Builder ×3 (pins on main; RED by mutation M30) |

**PC-11 classification.** At the named, main-observable clause:
- TC-13 `list / canvas displayed`
- TC-14 the 4-chip list
- TC-15 EXT inputs `on 1 row [13]`
- TC-17 run row `(44, 3)` ×4
- TC-18 mirror: no declaration
- TC-19: 27 Spanish constants
- TC-47 `flow_clip_status` outside
- TC-48 `Funnel (0)`
- TC-49 ×2 `#flow_ext_session is displayed`
- TC-50: scope selector composed
- TC-51: 4 chips in the chain
- TC-25: the module banner
- CSS guard: no section
- TC-31 `(0, 1)`
- TC-32: missing labels
- TC-33 WT `['✖']`
- TC-58 ×3: no state line
- TC-35 ×6 `flow_clip_status`/`flow_help` overflow
- TC-36 ×5 Run at y 47
- TC-37 ×6: no category class
- AT-07: 4 chips
- AT-19: the CHECK chip is unreachable

**Not RED at the clause at first, then reordered and re-run on the unchanged source** (`red-rerun.txt`, `red-rerun2.txt`):
- TC-62 add-form ×9 hit `NoMatches` on `flow_palette_source`. They now drive `#flow_kind`, and are **9/9 RED at "a NUL … was added (1 -> 2)"**.
- AT-06 ×2 hit a pipeline presence assertion. Now **RED at "Run at (51, 44) outside"**.
- TC-34 painted hit `NoMatches`. Now **RED `[28, 28, 28, 28]`** (P-22).
- TC-38 height ×6 now RED at the blank-row clause, the main base count (`[5]` at 118, `[5, 41]` at 220).
- TC-38 width ×3 now RED at the EXT row voids `[80, 26]` …

**Presence-RED only (AssertionError, not NoMatches; killed by the battery):** TC-16 ×2, TC-18 paint, TC-20, TC-62 helper ×9, TC-34 layer 0 / hidden arm, TC-33 Builder ×2, AT-08 (also M1/M7/M38). The final readings hold 0 `ImportError` and 0 collection errors.

| Field | Value |
|---|---|
| **RED counterfactual** | 81 of 129 selected nodes RED on the unchanged `09e44de` source (`red.txt`); 20 re-checked after the PC-11 reorders (`red-rerun.txt` 23 RED, `red-rerun2.txt` TC-34 RED `[28, 28, 28, 28]`); 0 restores needed (no source edit) |

| Field | Value |
|---|---|
| **Mutation verdicts** | **39 mutants, 51 arms: 50 KILLED / 1 SURVIVED-explained / 0 BAD**, every restore proven by SHA-256 (`mutations.txt`, `mutations-rerun.txt`, `mutate.py`). First run: 49/2/0. The survivor **M27** (cards fixed at 24) on TC-38's width arm passed because the demo refs never clip. The arm now carries the 60-cell ref (LLR-149.5 NC) and M27 is **KILLED** (`mutations-rerun.txt`). Explained survivor **M29** (the `on_show` trigger removed): the hidden-resize arm stays green because showing a `display:none` screen delivers a Resize to the panel, so `on_resize` re-derives too — an equivalent mutant under this app's show path. **Corrected at the gate fold (code-reviewer F1):** the claim "the arm goes RED only with both triggers removed" was not executed and was false — with both removed no layout pass ran, both sessions painted the 21-cell default and the equality passed. The arm now carries a path-independent clause; executed: M29 GREEN (equivalent), **M29b (both triggers) RED at `(21, 192)`** (`mutations-fold.txt`). Killed: NUL check removed (×4), helper reads `#flow_ref` only (×3), `✖` back, CRC in waiting / fb_A amber, mirror swapped, `Text.from_markup` (×2), command keeps tail, clip swapped (×2), second fill, selected filled, chip unfocusable, `space` removed, variant scope, count dropped, ribbon head-kept (×2), ext session shown, list shown, cable left out (×2), kind left out, ext row hidden, gating everywhere, clip status wide, `pegado:` left, banner reverted (×2), frame `1fr`, resize trigger removed, panel `overflow: hidden`, shared rule edited, unscoped `#flow_result`, glyph outside the vocabulary, help line without effect, header chip removed, refusal subtitle removed, result empty line removed, quarantine code dropped, pipeline empty line removed (×2) |

### Gate fold (2026-10-22) — RED, GREEN, mutations

| Field | Value |
|---|---|
| **RED counterfactual (fold)** | the fold's test edits on the **pre-fold source** (digests `7bd6936d…`, `fd5c6960…`, `95455cc6…`, `5ad9838e…`, `6ceb4f9b…`): **49 failed, 6 passed** over 23 selected functions (`red-fold-selection.txt`, `red-fold.txt`). The 6 green: TC-34 hidden (its guard is RED by M29b only), TC-51 (F3 is a wait fix), the TC-38 width arm at 160/220/260 (on-grid), AT-088a. Then the four chip nodes re-ran with the status recorder (the first run hit `TypeError` slicing the 4-line deque): **4 failed** at the at-mount clause (second section of `red-fold.txt`) |
| **GREEN (fold)** | gate set + guard host `tests/test_tui_directionb.py` (`gate-files-fold.txt`, 29 files): **686 passed, 29 xfailed, 1 failed** — `test_at088b_every_render_sink_renders_hostile_literally` (sink census 4 ≠ 5: the written-path sink had moved `safe_text` into a helper). Fixed (`safe_text(...)` at the `# SINK:` site, expected `wrote <path>` by named supersession) and re-run: render module + `test_tui_directionb.py -k flow/render/sink`: **36 passed**; the five Builder-touching modules on the final source: **152 passed** (all in `green-fold.txt`). The 29 xfails are the batch-94 snapshot envelope (`strict=False`) |
| **Mutation verdicts (fold)** | **16 mutants, 29 arms: 28 KILLED / 1 SURVIVED-explained (M29, equivalent) / 0 BAD**, each restore SHA-256-proven (`mutations-fold.txt`, `mutate.py` M29, M29b, M40–M53) |
| Neighbour screens (fold) | Check / Patch / Flow Execution painted frames at 118x54 and 220x60 **identical to `09e44de`** (`frames-fold.txt` = `frames-09e44de.txt`, `frames-diff-fold.txt` empty). The only legitimate change decision 1 makes — the startup status line — is outside these panel frames, and it is now back to HEAD's (PC-10 above) |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the new Inc-5 test nodes | the unchanged base source | 81 failed (`red.txt`) |
| `frames.py` (neighbour frames diff) | `.flow-name-strip margin-bottom: 0` | 4 differing rows (`frames-positive-control.txt`) |
| `snapshot_cells.py` (PC-10) | the two trees | 29 cells differ, each by one row (`cells-classified.txt`), so it sees a status-pane change |
| `mutate.py` | 39 one-edit mutants | per-arm verdicts; asserts each anchor occurs once and the edit applied |
| `span_colours` / `hue_matches` (PC-7) | the CRC card in `#e8ad3d` / `#d9a35b` (M4, M5) | TC-18 paint RED both times |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 5 instruments, each shown failing on a known-bad input before its first PASS was believed |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | TC-13 / AT-06 read the compositor's painted rows of the pipeline; `card_count` and AT-07 read the emitted `Content` of `#flow_pipeline`; TC-16 asserts `pipeline_text(...).plain` cell by cell; AT-06 checks `fw_app_patched.s19` absent before and present after Run; TC-18 matches painted strip colours by hue |

### Evidence files

All paths under `.dev-flow/2026-10-19-batch-97/evidence/inc-5/`.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| HEAD source digests | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/source-digests-head.txt` | `8403687213cc19aa86763cb1ceb7349bbafed32ed7724e49a9355211af679d92` |
| Census files | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/census-files.txt` | `47a0e79c89e43dd83ffd19d8356bd388138b70e64bc47c0caa1a7065be734b28` |
| on HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/census-head-run.txt` | `53841ebaa6962c4af1fb4de7d2164b3d801b58840e36e6d7732162028a411765` |
| on Inc-5 before rewrites | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/census-new-first.txt` | `bf2c1cd2a975a29f1b60a06e58f81fa670f0e722f58fab190a95e7d3112171fe` |
| RED selection | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red-selection.txt` | `1383006edfd09b8bd660579bde67c1edc3ce737550da5807d1b077aeece0ce8d` |
| RED | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red.txt` | `fa44b203f874b8df07175b50292feb0a0cb0dd2530cc2236bae0b10fbc2799d4` |
| re-run | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red-rerun.txt` | `7d6975ec7ecc16495cb5efbdb82b56fff0d4ba743220124bd177c63fedef9ee5` |
| re-run 2 | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red-rerun2.txt` | `af14fc33a160ef3b74825c51d5b3d56b609fe06a39e90934196cf8d5e41befbb` |
| Gate file list | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/gate-files.txt` | `b74fbf46153b7e09e16a367e19124948eea7a8e10f1760a22e159b45799b333e` |
| GREEN gate | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/green.txt` | `0cae02c652416c0ff2776a5ebd847f61ad31fd167558b64697e3fab04b70219c` |
| GREEN after edits | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/green-after-fixes.txt` | `342a9ad79003b494ee2f28e75442da874fb952da57974828539b826a13f2f76f` |
| Non-baseline re-runs (Inc-5 + HEAD) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/rerun-nonbaseline.txt` | `cf536f9737c4cf4d5a3b2acca87ce5601e17d77acbb96054b7a2f6c9e1450658` |
| Full suite (gate close) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/suite-full.txt` | `ed83303e23629c2e63c4b6f7f1a2acc7db01e86dc093bf38fcfa36b656ea2f4a` |
| Full-suite non-baseline re-runs | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/suite-rerun-nonbaseline.txt` | `023cf2df3ec98d76fdabfdcf75eab99a620e0c43ece5155081fbb94331860a8c` |
| Non-baseline nodes on clean HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/suite-head-flake-check.txt` | `69e984811207bc3e73c3c76e79511a5b1e37f7eef514fe7ba57f44cdefbd2040` |
| Gate re-read mutations (M54, M55) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations-gate-reread.txt` | `1fa967e581859d207a277ff1036c9b6bec7783b121e1eae40cfadbdb180f8394` |
| Mutations | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations.txt` | `49a44eea38ea9079abbc5b97167d81af5e724222fb9ee1103496fe3e38818586` |
| re-run | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations-rerun.txt` | `c43d96f78bedea26f7a8b35b2b669c427f915aaec24f8c1360ece1fb40fe9531` |
| script (first run; the fold appended to `mutate.py`, so these bytes are kept as) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutate.pre-fold.py` | `6baee1670f1ce5aaecbeebf7daf64065ddf5a0d3d194b6546b14a4f24b7b030a` |
| Frames HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-09e44de.txt` | `ead4adea79ccd532373a5f27b7f6b98ecf87946af9311879a0dee7d2b3961e46` |
| Inc-5 | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-inc5.txt` | `ead4adea79ccd532373a5f27b7f6b98ecf87946af9311879a0dee7d2b3961e46` |
| diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-diff.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| positive control | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-positive-control.txt` | `10ed73663ec6354865a61b440cc248afae40f2e2acbd2ef44489374edbfe3e10` |
| script | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames.py` | `37753da6bbf4c3990a9a90e68aa308ba6a91f8ad5b0e397fee28d2e71118588d` |
| Snapshot cells HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-head.txt` | `8bc937d17414f7f03b5525ee114c01c9fc58aa2c655b1e522c95314bfcdba9dd` |
| Inc-5 | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-inc5.txt` | `caeabac5c8550e7204d0e17499adf753865e3f6e951c36d4a0f9dd70edeeb474` |
| diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-diff.txt` | `a4436efdb5e78df0810c20c521b8893b2aeb2d350405fe5bb8dbdf8884ec2414` |
| classified | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-classified.txt` | `7f19747e6cf796b9940d625aac0cc8ed1857bd103b40983b1438c5a7aa2803a8` |
| Budget | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/budget.txt` | `4acec0bb372ef6077a6a92c46f4ddd53f4b48d2d8023925cf16ff76cb8cdf9aa` |
| script | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_budget.py` | `83968d7634e102fe079369d7a0c3cd38dfca6b406d50d3ff567f369782e00711` |
| WT capture 118x54 (first run) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.pre-fold.png` | `40e7e03f68a6d372a21621a6104f61b2f4fe173e506d5b4b5625adc8db6c36e5` |
| 118x53 (first run) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.118x53.pre-fold.png` | `081803041d7300664ea90cd5c03df327dc06c322ad86aaae131c674d870b15f6` |
| 220x60 (first run) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.220.pre-fold.png` | `01ff344420280ef2355d38f92e79657b934ac36ab38546807d868fab1233fd7b` |
| Validator `--brief` after `--atlas --write`: 12 blocks, all V2 (AT ids of Inc-6..8) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/validate-brief.txt` | (digest in the gate report: the file is rewritten by each validator run that reads this packet) |
| WT capture EXT-STEP chain (first run) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder-ext.pre-fold.png` | `e7c0949b6566a7df9879952f075f52c0a97fdf9132af35c37a7048e6ff252a4e` |
| after a Run (118x54) (first run) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder-run.pre-fold.png` | `d40e40ff77b3bd65a741477035a8b82ca9daa6645327ea9b7733677f2c3c09ad` |

**Gate-fold evidence** (repo-relative, SHA-256):

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED selection | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red-fold-selection.txt` | `1883680b9516d37174e8065881085975e608ed6ce8098c4c7485bd7946a3b062` |
| RED fold (49 failed / 6 passed; 4 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/red-fold.txt` | `8bd56aaa39b42bc75b9d3987733d0e5b60c5503f0f3830b17a9baf1c43458fed` |
| Gate file list | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/gate-files-fold.txt` | `c29266564d44b5ee91cb97c51f896413317b17c077d423d6a7ca4981f54cdfd2` |
| GREEN fold (686 / 29 xf / 1 F; 36; 152) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/green-fold.txt` | `4fc3f4648fbec1d980941593da25cbc9db9d5a31a6bdc7f0ea38865ad6473ac7` |
| Mutations fold (28 / 1 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations-fold.txt` | `5ddab934467784bbf0ea503851760f635c60edc7553511ea5ab7b472ae77ff3c` |
| script (after the fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutate.py` | `16e667bc4a131bcd0f1775379ae163d242893f251e6a8a24fb8d2ae6b6712ab1` |
| Budget fold | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/budget-fold.txt` | `457bb2fbb0c4f1e5dee32adb6619a7af8a56131e15c9c06f2dc071ccd4d93ef0` |
| script | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_budget_fold.py` | `102ee84d80d68bd452867fb21d5bd2c4eb289048e03c80f9d1d1e02af2e75d87` |
| 118–134 band (F5) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/band-fold.txt` | `50d8d7b30a5f8d1b019f5e870bcd3d9a88f89655b7158c48d239169b6f3b72f4` |
| script | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_band.py` | `bbd26815e9617aa1fb31b604d6b026d06ce29b80ded7c9cc39e38222d181a063` |
| Snapshot cells fold (= HEAD) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-fold.txt` | `8bc937d17414f7f03b5525ee114c01c9fc58aa2c655b1e522c95314bfcdba9dd` |
| diff (empty) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/cells-diff-fold.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Frames fold (= HEAD) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-fold.txt` | `ead4adea79ccd532373a5f27b7f6b98ecf87946af9311879a0dee7d2b3961e46` |
| diff (empty) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/frames-diff-fold.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| WT 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.png` | `440a8e1025a102802bb1c4683b973ab654783df0aa177bbc551846b75b16c076` |
| WT 118x53 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.118x53.png` | `092e2545b2ec5ff27133f3e5d47854a049b6841642fcb3fa5f68bff614943ed3` |
| WT 220x60 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder.220.png` | `646abb538e9800eab036d173054c4a2aec75e9d5d4ee149d52fed4f32cb253f5` |
| WT EXT chain 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder-ext.png` | `1974eee5df6b5258733b860be11c22db0765e4a46f2225b9515f680e620294d3` |
| WT after Run 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/png/impl.flow-builder-run.png` | `c7eb4592069caa1157d2bd433ce0f2fbf59f3c606d5954554d1f8e6c4cf7c9f3` |

The first-run capture rows and the first-run `mutate.py` row above point at the `*.pre-fold.png` copies and at `mutate.pre-fold.py` (rebuilt by reversing the fold's four edits; its SHA-256 equals the first-run digest `6baee167…`), because the fold overwrote `impl.flow-builder*.png` and appended to `mutate.py`. Final fold source digests: `flow_screens.py eae1ef95…`, `app.py fd5c6960…` (unchanged), `styles.tcss 362f962b…`, `window_help.py eaf189a6…`, `open_folder_chip.py 5c60ea67…`. The fold gate run (`green-fold.txt` first section) ran on `flow_screens.py f1557bac…` (before the sink fix); its re-runs and the mutation battery ran on `eae1ef95…`. The WT glyph check holds on the fold captures: no glyph glued to its neighbour; `·` in `· saved` one cell.

| Field | Value |
|---|---|
| **Evidence files** | 34 first-run artifacts + 20 gate-fold artifacts under `.dev-flow/2026-10-19-batch-97/evidence/inc-5/`, each with its SHA-256 above (`validate-brief.txt` is rewritten by the validator step) |

Final source digests: `flow_screens.py 7bd6936d9766f211`, `app.py fd5c696021bd6972`, `styles.tcss 95455cc67476557f`, `window_help.py 5ad9838ea7630f53`. `green.txt` ran on `flow_screens.py d66ad154…` (before the docstring edit). The mutation battery and `green-after-fixes.txt` ran on the final digest.

**WT glyph check** (the captures, read at the chips, card kind lines, legend and result heads): `◉ ▣ ✓ ⊕ ▼ ⏚ » ─ ▶ ● ◈ □` each paint one cell, with no glyph glued to the next character. The `✗` and `○` marks do not appear in these captures (no failed or skipped block); their width rests on the pre-Inc-5 ruler capture. `≡` does not appear either (no report block).

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes, in nine places: 0 blank rows inside the frame; 0 blank rows outside `#flow_result`; 0 h-overflowing descendants; 0 Spanish constants in `FlowBuilderPanel`; 0 module-level Spanish constants; 0 unscoped `#flow_` selectors; 0 differing neighbour-frame rows; 0 payload spans; 0 `Binding(` in the `app.py` diff |
| What made the search wide enough | full-width painted panel rows; every displayed descendant (guard ≥ 10); AST censuses keyed on the `ClassDef` / module nodes with a reach guard on `9c7beaf` (27 + 1 found there); the CSS parsed into rules over the whole sheet; span colours checked against the panel's palette |
| Positive control | M26 / M37 (frame `1fr`, empty line) → TC-38 RED; M24 → TC-19 RED; M32 → CSS guard RED; M7 → payload spans RED; the frames positive control (4 rows) |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a: tests reaching Builder ids / `flow_screens` symbols | 15 files (`git grep` in §1 of the session; `census-files.txt` + help modules + `test_import_census.py` + `test_id_registry.py`). On HEAD: 110 passed (`census-head-run.txt`). On Inc-5 before the rewrites: **16 failed** (`census-new-first.txt`); each was rewritten by named supersession (§2) or retired (3, TC-642). Later finds: `test_import_census.py` TC-653 (the new test imported `safe_text`; it now reads `fs.safe_text`) and `test_id_registry.py` G2 (registry updated) |
| B1b: removed symbols | `_PALETTE_TYPES`, `_SCOPE_OPTIONS`, `#flow_scope`: 0 code references left (`git grep`, comments only) |
| B1c: hex sweep | new literals `#56e0d6` (claimed: PATCH teal), `#c9562b`/`#e8ad3d` (claimed), `#f6ff8f`/`#969aad` (claimed / excluded). `test_tui_patch_json.py` hue census green in `green.txt` |
| B1d: TC-081.4 | 0 `Binding(` lines in the `app.py` diff; `KindChip`'s binding lives in `flow_screens.py` |
| B2 · B3 | no file moved; no golden captures the Builder |
| A3 | `RunRequested` shape unchanged (frozen); `FlowBuilderPanel` keeps `set_blocks` / `render_*` / `mark_saved` / `set_session_dir` signatures; `render_fused_result` kept (backlog). **Interaction found:** the I-1 chip's mount-time status line (§4 PC-10) |

| Field | Value |
|---|---|
| **Reverse census** | B1a 15 files; 16 failing nodes on Inc-5, all rewritten or retired by name; 2 more modules found by the registry/import guards and fixed; B1b–B1d clean; B2–B3 none; A3: one cross-increment interaction, reported |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | Spanish in `FlowBuilderPanel`: 27 frozen values (`ES_48_9C7BEAF`), enumerated by the AST census with a reach guard; **27 translated**, 0 left (TC-19). Module scope: 1 (`:235`), translated (TC-25). Spanish test pins: 5 sites (`test_flow_funnel_b96.py:331, 436, 475, 477`; `test_flow_external_step_b96.py:423, 427`), rewritten. Execution-panel Spanish (9) is Inc-6's |

### Signed-balance test ledger

`post = base − deleted + added` → `base − 3 + 84`. Deleted 3 (`test_flow_multi_image_ui.py` scope nodes, TC-642 updated). Added 41 (`test_b97_flow_builder.py`) + 34 (`test_b97_width.py`) + 8 (`test_b97_chips_help.py`) + 1 (`test_b97_flow_execution.py`) = 84. Rewritten in place: 1 in `test_flow_multi_image_ui.py`, 2 in `test_tui_flow_builder_b94.py`, 1 in `test_flow_external_step_b96.py`, 3 in `test_flow_funnel_b96.py`, the help key sets (2 modules) and the header seat map. D18: no new scanned module, so the registry bound stays 197 (`test_id_registry.py` green).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · OK to advance on re-read (2026-10-22): F1 (HIGH) resolved — derived-width guard in TC-34's hidden arm, M29b RED re-executed by the reviewer `(21, 192)`; F2 (HIGH) resolved — `spare` spread over the cables, layer-0 arm 60–260 and TC-38 at 163x56 / 223x60, the no-`spare` mutant RED re-executed by the reviewer; F3–F6 applied; LOW L1 (21-cell skip) applied by the orchestrator. `ux-reviewer` · approve on re-read (2026-10-22): H1 air as in fb_A (LED-.25, 4-block run 17/16 rows, `max_scroll_y` 0); M1 one-line written path; M3 `Add needs <field> — nothing added` for 5 of 5 kinds; L1 UI labels; .24 chip silent at mount; .26 `· saved` / `· unsaved`; .27 NOTICES/ISSUES; accepted the ribbon-margin trim, the EXT-STEP 1–2-row scroll and the tooltip-only reason; LOW L-a applied by the orchestrator (M54, M55), L-b recorded, L-c backlog |

## 5 · Risks

- ~~Startup status line on every screen~~ — closed by the fold (LED-…97.24; PC-10 0 of 29).
- **Zero slack in the result area at 118x54 / 118x53** for the 4-block run (17 / 16 rows needed and available). A longer run (more blocks, a finding line, a second written path) scrolls the result area. The EXT-STEP chain's paused run already scrolls by 1 / 2 rows at 118x54 / 118x53 (`budget-fold.txt`); the decision bound only the 4-block chain.
- **120–123 columns: the 4-block chain scrolls sideways** (F5; degraded band LED-…97.13; the frame grows by the scrollbar row there).
- **A disabled chip cannot announce on press** (Textual swallows it); the no-project reason is then only on the tooltip and on a transition (§6 item 1).
- The chip transition is exercised by clearing the project fields and calling `update_project_labels` — the app has no unload action, so no real user path reaches it today beyond a project folder vanishing.
- **Reordered visual layout** (copy/paste row below the add form) is a delta against fb_A that the operator has not seen yet.
- **Single-pause flakes:** `at023e` and `at079a` failed in the long gate run, and pass 5/5 isolated on both trees; `tc330`, `save_back_prompt` and `ac2_1` failed in the full suite and also fail intermittently on clean `09e44de` (backlog: flake class).
- **The memory ribbon sits directly under the last verdict** (ux L-b), the cost of the accepted margin trim.
- **Card clipping is by `len`, not cell width:** a CJK or emoji ref could misalign a card border.
- ~~Ribbon `✓` / `●` second meanings~~ — closed by the fold (LED-…97.26). Flow Execution's own `#fx_name_strip` still uses `✓` / `●` (Inc-6's screen).
- ~~Written path wraps to 2 rows~~ — one row since the fold (tail kept, M1).

## 6 · Pending items / spec deviations

1. **Decided (operator, Inc-5 gate 2026-10-22): (a) — fixed in the fold** with `open_folder_chip.py` as an approved 5th file (LED-…97.24; PC-10 0 of 29). **Open half:** the decision said the message also appears "on press"; a disabled Textual `Button` swallows the press, so a genuinely disabled chip cannot do that without re-shaping LLR-139.2 / LLR-148.3's "genuinely disabled" contract (e.g. dimmed-but-enabled, press → reason). Orchestrator decision (gate close): keep the genuinely-disabled contract; the reason stays on the tooltip and the transition. The tooltip is not reachable by keyboard (ux L-c) → backlog. Inc-6's `session` header chip inherits the silent mount.
2. **Layout order — design §3 amended by name at the fold (ux L3):** the clip row and `Variables (n)` sit under the add form, forced by LLR-146.13 together with Textual's position-sorted focus chain; still a delta against fb_A's picture.
3. **Not a deviation — per D7 (relabelled at the fold, ux L4):** the legend shows `≡ report` only while the chain carries a report block; D7 itself fixes "`≡` only when a loaded flow carries a report block". All ten pairs (116 cells) would not fit the 112-cell panel at 118.
4. **Deviation — the load-refusal state line** (LLR-148.9, Builder "pipeline · error") is painted on the pipeline frame's bottom border, and the findings card stays under Run. The quarantine lines gained a `[<code>]` prefix, so a NUL load names `FLOW-UNSAFE-REF` on one line (HLR-146 threshold).
5. **Deviation — `test_flow_multi_image_ui.py` 185 and 271 are kept.** The design listed them as retired. They test the service and `render_fused_result`, both kept by D8.
6. **D6 conflict — resolved at the fold** (operator decision 3, LED-…97.26; batch-53 LLR-003.1 superseded by name).
7. **`_EXT_MODE_OPTIONS` labels shortened** to `Terminal` / `Manual` (values unchanged).
8. **`flow_report_service.py:111` still maps error to `✖`** — routed to `.dev-flow/BACKLOG-CODE.md` (batch-97 section) at the fold, with ux L5, L6, the `SaveFlowScreen` escape and `render_fused_result` (F6).
10. **Fold: the `.flow-ribbon` margin removed inside the Builder result** — a third trim beyond the brief's M1 + L2, needed for the 4-block run to fit at 118x53 (17 rows needed, 16 with only M1 + L2). Reversible if the operator prefers the blank row and accepts a 1-row scroll at 118x53. Accepted by the orchestrator and by `ux-reviewer` on re-read.
11. **Fold: `NOTICES` only for notices-only runs**; a finished run with an erred, non-aborting block keeps `ISSUES` (my reading of "a finished run with notices only"; LED-…97.27 records it). Accepted by the orchestrator: the banner keeps an error distinguishable from a notice.
9. Full suite run at the gate close by the orchestrator (§4): 10 failed vs baseline 10; the 3 non-baseline nodes are pre-existing flakes on clean HEAD.

## 7 · Suggested next task

Inc-6 (Flow Execution): PC-4, PC-13, PC-15, PC-16, the PC-21 attention-lane owner, the `c` binding described as `Confirm`, the wide `⚠` glyph, the session chip under Inc-5's silent-mount rule, and the remaining Spanish strings in `FlowExecutionPanel`.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ (approved overage) | 5 / 4: `open_folder_chip.py` approved by the operator at the Inc-5 gate 2026-10-22 as a 5th source file for decision 1 only (§2); `app.py` untouched by the fold |
| 2 | Tests written in this same increment | all | ✓ | 84 new nodes; fold: +13 nodes (TC-29 startup, TC-49 ×2, TC-58 add-empty ×3, TC-38 spare ×5, TC-38 width +2 sizes) and the rewrites in §1b |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | clip / layout / pipeline / helper / mirror / censuses |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 81, `red-rerun*.txt`; fold `red-fold.txt` 49 + 4 |
| 5 | Reverse census declared | `core` · `full` | ✓ | `census-*.txt` |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | BLOCK-UNTIL F1, F2 → folded → OK to advance on re-read (§4b) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched | all | ⚠ | I-1 signatures, families and labels unchanged; its `refresh_target` **behaviour** changed (A3, operator-approved, LED-…97.24; design I-1 row amended); I-8 shape unchanged; I-9 names as D12 |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt`, `green-after-fixes.txt`, `green-fold.txt` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 51 arms: 50 / 1 explained / 0; fold 29 arms: 28 / 1 explained (M29) / 0; re-read M54, M55 killed |
| 12 | Instrument RED-proof | all | ✓ | 5 instruments |
| 13 | Correction population | all | ✓ | 27 + 1 + 5 pins |
| 14 | Emitted-form assertion | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | `code-reviewer`, `ux-reviewer` (Inc-5 gate, 2026-10-22) |
| 16 | Evidence files with digests | all | ✓ | §4 (first run + gate fold) |
