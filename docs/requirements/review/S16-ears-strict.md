# S16 — Flow Builder UI: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S16 (lines 6673–6714): R-TUI-059 only (S16 owns it; S15 is second). Also the screen rows of S0's table (HLR-013, 016, 017, 018, 019, 020, 021, 142 (the Builder's part), 146, 147, 149 and LLR-016.1, 017.1, 017.2, 018.1, 020.1, 146.1 … 146.14, 147.1 … 147.13), and the items S6 and S7 passed (`c` on Flow Execution; the contents of Save flow, Load flow and `Discard unsaved flow edits?`).
Code: `tui/flow_screens.py` (`FlowBuilderPanel` `:1061-2395`, `FlowExecutionPanel` `:2642-3900`, the painters `:137-943`, `:2397-2640`); in `screens.py` `SaveFlowScreen`, `LoadFlowScreen`, `ConfirmDiscardScreen` (`:733-930`); the S16 functions of `app.py` (`_compose_screen_flow*` `:2694-2767`, `on_flow_builder_panel_*` `:2843-2994`, `on_flow_execution_panel_*` `:3008-3340`, `action_confirm_attention` `:7538`, `check_action` `:7507`, `_publish_flow_session_dir` `:9716`). Read directly, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: the "Code today" cells of R-FB-RIB.1 and R-FB-RIB.2 (cites only) verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-BUILDER, CTX-FXSCREEN.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. The chapter had one row for two windows; rows whose "Code today" starts with **NEW** describe behaviour no requirement in this chapter named (D16-2). The run engine behind both windows is S15's (rule D-9). Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first** (TUI rule).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S16.md`. Nothing is changed in the code yet.

---

## 1. How S16 was written before

- One row, R-TUI-059 (batch-44): the "tracer slice" — "rail item 8 (formerly the dropped Bookmarks placeholder) hosts a Flow Builder", "a dropdown-add block list + Run", SOURCE → PATCH → WRITE-OUT, with the engine, its security rules, an OUT list of deferred batches and the snapshot xfail marks in the same paragraph.
- What the two windows do today — the pipeline of cards, the kind chips, the add form, copy/paste, variables, Save/Load/Import, the whole Flow Execution window with lanes, binding, modes, waiting and confirming, chain-set save and load — had no row in this chapter. S0's table carried part of it as batch HLR/LLR rows; the rest had none.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-059 | "formerly the dropped Bookmarks placeholder", "tracer slice", "Batch-44 ships…", "OUT (deferred): flow persistence (batch-45), CHECK/CRC (batch-46), multi-image (batch-47)": history; all three shipped since. | Out (D16-1). |
| R-TUI-059 | "a dropdown-add block list": batch-97 replaced it by kind chips and a pipeline of cards; the list and the grid canvas are still built but never shown. | Rows S16.1 … S16.3; the hidden widgets are removed (D16-6). |
| R-TUI-059 | The engine (`run_flow`, containment, `save_patched_image`) is S15's behaviour (rule D-9). | Engine rows R-TUI-059.1 … .6 live in S15 (D16-4). |
| (S0 HLR-013) | "a block-diagram editor — a block palette, a canvas with refined cable routing": superseded by HLR-146's one-row pipeline. | HLR-013 superseded (D16-3). |
| (S0 HLR-142) | "the Flow Builder shall ask for the A2L reference": the engine reads `a2l_ref`, the Builder has no input for it. | R-FB-ADD.17 (D16-25, prototype first). |
| (nothing) | The Builder's palette has no REPORT kind, so a flow report can only come from an imported flow file. | R-FB-ADD.16 (D16-26, prototype first). |
| (nothing) | The Save dialog says `(overwrites existing)`; the save never overwrites, it writes `<name>_2.json`. | R-FB-SAVE.2 (D16-13). |
| (nothing) | The Builder accepts blocks and variables that its own loader refuses, so Save writes a flow that Load then rejects. LOAD and WRITE-OUT added in the Builder are always S19, also for `.hex` files. | R-FB-ADD.10, .11, R-FB-VAR.6 (D16-10, D16-11). |
| (S0 HLR-019 / 147) | "While a run is in flight": both windows run on the screen's thread, so nothing repaints until the run ends. | R-FB-RUN.4, R-FX-RUN.7 (D16-15). |

Context notes that would have carried behaviour (E6): none were written before.

---

## 3. Context notes (informative)

Block kinds, statuses, run statuses, flow files and chain sets are S15's (CTX-FLOW, CTX-FLOWFILE, CTX-CHAIN). Colours and glyphs below are today's; D16-27 and D16-28 put them through a prototype round.

### CTX-BUILDER · The Flow Builder (S16.1 … S16.6)

```text
Flow Builder    Rail window (S6: position 9, key 8). Header "Flow Builder" with the
                📂 Open flows/ chip and the ? chip (S5, S7). Then, top to bottom:
  ribbon        "Flow: <name>  · saved|· unsaved  <kind summary>" and, at the right,
                "session <project folder, tail kept>" or "session (no active project)".
  pipeline      The chain as one row of cards joined by cables "───▶"; with no block:
                "No blocks yet — a chain starts with ◉ LOAD: pick it below, type the
                image file, press Add."
  palette       "add block" and one chip per kind: ◉ LOAD · ▣ PATCH · ✓ CHECK · ⊕ CRC ·
                ▼ WRITE-OUT · ⏚ A2B-DIFF · » EXT-STEP
  add form      The chosen kind's tag, its inputs, then "+ Add".
  clip row      "copy block #" box (empty means the last block), Copy, Paste, the
                clipboard status, "Variables (<n>)".
  variables     "variable" box, "value" box, "+ Add var", then the variable list;
                hidden until Variables is pressed.
  notice        One warning line; hidden when empty.
  foot row      Run (the one filled control), Clear, Save…, Load…
  result        The last run's result, or "No run yet — Run executes this chain against
                the loaded image; the block verdicts land here."
  legend        ◉ load ▣ patch ✓ check ⊕ CRC ▼ write-out ⏚ A2B diff » external step
                [≡ report, while the chain has one] ─ cable ▶ feeds the next block
add inputs      LOAD "image file" · PATCH "change doc" · CHECK "check doc" and gating
                (advisory, block-own-op) · CRC "CRC template" · WRITE-OUT "output file" ·
                A2B-DIFF "image A", "image B" (a file name, or #<n> for the image after
                block n) · EXT-STEP "mode" (Terminal, Manual), "command" or
                "instruction", "log", "output file".
card            "<n>" on the top border; "<glyph> <KIND>"; what it does; each input as
                "in · <name>" and its value; a note; "out" and the output.
clip            A ref or path keeps its tail, a label or command its head; the cut
                side ends or starts with "…".
card width      The pipeline width shared by the cards, at least 21 columns; a longer
                chain scrolls sideways inside the pipeline frame.
result          The banner; one node per block: "<glyph> <kind> <status>", the summary,
                the findings (warning colour), the diagnostics (error colour); the
                memory ribbon (48 cells: █ mapped, ░ gap) and "<n> range(s) · 0x<low>‥
                0x<high>"; "before:" and "after:" ribbons when a CRC grew the image;
                "wrote <path>" per written file; then the run's own diagnostics.
banner          CLEAN · NOTICES (issues, no block in error) · ISSUES · FAILED ·
                PAUSED - WAITING FOR A HUMAN
block glyph     ● ok · ◈ notices · ✗ error · ○ skipped · □ waiting
Save flow as:   Name box (prefilled with the flow name), the hint "Name is sanitised
                (letters, numbers, - _); identity is the filename.", the notice line,
                Save, Cancel.
Load flow:      The saved flows (S15 R-FLOW-FILE.10), the import line, Import…, Load,
                Cancel.
Discard unsaved "Loading '<name>' replaces the current unsaved flow.", Discard, Cancel.
flow edits?
```

### CTX-FXSCREEN · Flow Execution (S16.7 … S16.10)

```text
Flow Execution  Rail window (S6: position 10, key ]). Header "Flow Execution" with the
                📂 Open session chip and the ? chip (S5, S7). Then:
  ribbon        "Set: <set name>  · saved|· unsaved" … "session <folder>", Import…,
                the mode switch "sequential · parallel", Run (filled).
  set row       "set name" box, Save Set, "saved sets" list ("flowsets/<name>.json", or
                "(no saved sets)"), Load Set.
  notice        One warning line; hidden when empty.
  lanes         One lane per imported flow, top to bottom; with none: "No chains yet —
                Import… adds a lane from a saved flow."
  REQUIRED      "log + output file: REQUIRED for <lane> · press c to confirm", shown
                while a lane waits.
  run log       At most 8 lines. Before any run: "No run yet — Run executes every lane."
                With more: "… <k> earlier lines — the full log is in the run report",
                then the newest 7.
  legend        ▓ done ░ not run / skipped ✗ error ◇ notices □ waiting for a human
                ▪ owed before the lane goes on
lane            Head "<mark> <lane> · <status>[ at #<n>][ · <mm:ss.mmm>] · <n> blocks
                [ · tpl <template>][ · wrote <files>]"; red pending lines; one row of
                cards joined by cables; Confirm after the last card while it waits.
lane status     ░ not run · ▓ done · ◇ done with notices · ✗ failed · □ waiting for a human
card            Border title "<glyph> <KIND>". LOAD: the ref box, Bind, "fmt <type>".
                Other kinds: two io lines. Then "<mark> <status word>".
cable mark      □ into a waiting block; else ▓ ok, ◇ notices, ✗ error, ░ skipped /
                waiting / not run.
pending lines   "▪ '<ref>' missing - re-bind" per reloaded ref whose file is gone;
                "▪ log '<log>' pending" and "▪ output file not confirmed — waiting for a
                human" while the lane waits.
attention lane  The first lane, in lane order, that waits at a step it has not confirmed.
log lines       Per lane and run: "<mm:ss.mmm> <lane> · started" (a confirm re-run:
                "· re-run after confirming the external step (block <i>/<n>)"), then
                "<mm:ss.mmm> <mark> <lane>" and one of:
                  " · done" or " · done with notices", then
                  [" · PATCH: <k> of <n> entries not applied (0x<address> <disposition>)"]
                  [" · <the CRC absent-bytes finding>"] [" · wrote <files>"]
                  " · block <i>/<n> <KIND> — <cause> · chain halted"
                  " · WAITING FOR A HUMAN — external step (block <i>/<n>) · log '<log>'
                  pending"
dwell           0.5 s: how long the attention lane must have waited before c confirms it.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test named), **Partly** / **No** with the decision; a leading **NEW** marks a row for behaviour no requirement in this chapter named (D16-2).

### S16.1 · The Flow Builder window (CTX-BUILDER; R-TUI-059 screen half, from S0 HLR-146, LLR-146.1, 146.5, 146.11)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-059.20 | U | The system shall offer the Flow Builder of CTX-BUILDER as a rail window. | Yes; tested (`test_at_flow_rail_key_8_reaches_panel`). |
| R-TUI-059.21 | U | The system shall show the parts of the Flow Builder in the order of CTX-BUILDER. | Yes; tested (`test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas`, `test_tc_b97_47_copy_paste_strip_on_one_row_inside`). |
| R-TUI-059.22 | U | The system shall show the flow's name and its saved state on the ribbon. | Yes; tested (`test_tc_b97_49_ribbon_saved_state_is_a_word`). |
| R-FB-RIB.1 | When | When the chain or the variables change after a load or a save, the system shall show `· unsaved` on the ribbon. | **NEW** · Yes; tested (`test_tc_b97_49_ribbon_paints_saved_then_unsaved`, `test_at002_name_strip_glyph_dirty_then_saved`). An unsaved flow is one item of the load question (S5 R-LOADQ-001.4, CTX-LOADQ: `flow <flow name>`). |
| R-FB-RIB.2 | While | While a project is open, the system shall show the project folder on the ribbon. | **NEW** · Yes; tested (`test_tc_b97_49_session_on_the_ribbon`). After a save as, the new project folder (S11 R-SAVEAS-8, `test_tc_b100_31_flow_session_folder_follows_q`; batch-100 LLR-171.1l). |
| R-FB-RIB.3 | U | The system shall show every name, ref, command, path and finding on the Flow Builder as plain text, never as markup. | Yes; tested (`test_tc_b97_20_hostile_refs_render_literally`, `test_at_flow_block_label_markup_safe`, `test_at_b94_18_hostile_names_render_literally`). |
| R-FB-RIB.4 | When | When the operator presses Space on a chip of a Flow window, the system shall press that chip. | **NEW** · Yes (`flow_screens.py:944-960`). |
| R-FB-RIB.5 | While | While the Flow Builder is shown at 118 columns by 54 rows or more, the system shall keep the foot row in view without scrolling. | **NEW** · Yes; tested (`test_tc_b97_17_run_is_the_one_filled_action_on_one_foot_row`). |
| R-FB-RIB.6 | While | While the Flow Builder is shown at less than 118 columns or less than 54 rows, the system shall keep every control reachable by scrolling. | **NEW** · Yes; tested for Run at 80 × 24, 100 × 40 and 220 × 40 (`test_tc_b97_59_builder_below_the_range_run_reachable`). From S0 HLR-149, LLR-149.6. |

### S16.2 · Adding blocks (CTX-BUILDER; from S0 HLR-146, LLR-146.2, 146.3, 146.14, HLR-014, HLR-142)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FB-ADD.1 | When | When the operator presses a kind chip, the system shall show only that kind's add inputs. | **NEW** · Yes; tested (`test_tc_b97_15_add_form_shows_exactly_the_kind_inputs`, `test_tc_b97_14_palette_offers_every_kind_in_order`). |
| R-FB-ADD.2 | When | When the operator presses a kind chip, the system shall clear the notice. | **NEW** · Yes; tested (`test_tc_b97_58_add_notice_clears_on_kind_change_and_run`). |
| R-FB-ADD.3 | When | When the operator presses + Add with the chosen kind's inputs filled, the system shall append a block of that kind to the chain. | Yes; tested (`test_at_flow_add_blocks_and_run_renders_result`). |
| R-FB-ADD.4 | If | If a required add input is empty, then the system shall add nothing and show the notice `Add needs <field> — nothing added`. | **NEW** · Yes; tested (`test_tc_b97_58_add_with_an_empty_field_says_what_it_needs`). |
| R-FB-ADD.5 | If | If a path input of the add form holds a NUL character, then the system shall add nothing and show the notice `Add refused: [FLOW-UNSAFE-REF] <KIND> <field> holds a NUL character - not a path`. | **NEW** · Yes (`flow_screens.py:587-625`, `:1998-2009`). |
| R-FB-ADD.6 | If | If an A2B binding is empty or malformed, then the system shall add nothing and show the notice `A2B wiring refused: empty or malformed binding — use a file name or #<n> (a flow output).` | **NEW** · Yes (`flow_screens.py:1920-1925`). |
| R-FB-ADD.7 | If | If the A2B bindings break S15 R-FLOW-A2B.2 … .4, then the system shall add nothing and show the notice `A2B wiring refused: <reasons, separated by "; ">`. | **NEW** · Yes; tested (`test_at_b94_16_a2b_wiring_rule_and_report_provenance`). |
| R-FB-ADD.8 | If | If an EXT-STEP's command or instruction is empty, then the system shall add nothing and show the notice `External step refused: <the exact command or the instruction> to run outside the app is missing.` | **NEW** · Yes. |
| R-FB-ADD.9 | If | If an EXT-STEP's log is empty, then the system shall add nothing and show the notice `External step refused: the log file is required (the record of the step, never optional).` | **NEW** · Yes; tested (`test_tc1804_builder_palette_select_and_config_row_gate`). |
| R-FB-ADD.10 | If | If an EXT-STEP's output file is empty, then the system shall add nothing and show the notice `External step refused: the output file is missing (an absolute path is preferred).` | **NEW** · Yes. |
| R-FB-ADD.11 | If | If an added block breaks a rule of S15 CTX-FLOWFILE, then the system shall add nothing and show the notice `Add refused: <first finding message>`. | **NEW** · No: Add accepts it, Save writes it, Load refuses the file (D16-10). |
| R-FB-ADD.12 | When | When the operator adds a LOAD or WRITE-OUT block whose file name ends in `.hex` or `.ihex`, ignoring case, the system shall declare it Intel HEX. | **NEW** · No: always S19 (D16-11). |
| R-FB-ADD.13 | When | When the operator adds a LOAD or WRITE-OUT block whose file name has any other ending, the system shall declare it S19. | **NEW** · Yes (`flow_screens.py:160-167`). |
| R-FB-ADD.14 | When | When the operator sets the EXT-STEP mode to Terminal, the system shall label its text box `command`. | **NEW** · Yes (`flow_screens.py:2089-2094`). |
| R-FB-ADD.15 | When | When the operator sets the EXT-STEP mode to Manual, the system shall label its text box `instruction`. | **NEW** · Yes (`flow_screens.py:2089-2094`). |
| R-FB-ADD.16 | U | The system shall offer a REPORT kind in the palette. | **NEW** · No: a REPORT block can only come from an imported flow file (D16-26, prototype first). |
| R-FB-ADD.17 | U | The system shall offer an A2L reference input for LOAD and PATCH blocks. | **NEW** · No: none; the engine reads it from flow files only (D16-25, prototype first). |
| R-FB-ADD.18 | When | When a block is added, the system shall clear the add inputs it used. | **NEW** · Yes (`flow_screens.py:2026`, `:1933-1934`, `:1980-1982`). |

### S16.3 · The pipeline (CTX-BUILDER; from S0 LLR-146.1, 146.4, 146.6)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FB-PIPE.1 | U | The system shall show the chain as one row of cards in block order, with one cable between neighbours. | **NEW** · Yes; tested (`test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas`). |
| R-FB-PIPE.2 | U | The system shall give every card the same width, at least 21 columns. | **NEW** · Yes (`flow_screens.py:690-720`). |
| R-FB-PIPE.3 | If | If the cards do not fit the pipeline's width, then the system shall scroll the pipeline sideways inside its frame. | **NEW** · Yes (`flow_screens.py:1221-1226`). |
| R-FB-PIPE.4 | U | The system shall clip card texts as CTX-BUILDER clip. | **NEW** · Yes; tested (`test_tc_b97_16_clip_head_and_clip_tail`, `test_tc_b97_16_cards_clip_every_line_to_the_card`). |
| R-FB-PIPE.5 | U | The system shall paint CRC cards in the CRC colour. | **NEW** · Yes; tested (`test_tc_b97_18_crc_card_painted_in_the_crc_colour`). |

### S16.4 · Copy, paste and variables (CTX-BUILDER; funnel is S15 R-FLOW-FUNNEL)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FB-CLIP.1 | When | When the operator presses Copy with the block box empty, the system shall copy the last block and show `clipboard: <kind>`. | **NEW** · Yes; tested (`test_tc1818_copy_paste_duplicates_config_via_wire`). |
| R-FB-CLIP.2 | When | When the operator presses Copy with a block number n, the system shall copy block n and show `clipboard: <kind>`. | **NEW** · Yes. |
| R-FB-CLIP.3 | If | If the block number names no block, then the system shall show the notice `Copy refused: there is no block #<n> (the chain has <k>).` | **NEW** · Yes. |
| R-FB-CLIP.4 | If | If the chain is empty when the operator presses Copy, then the system shall show the notice `Copy refused: the chain is empty.` | **NEW** · Yes. |
| R-FB-CLIP.5 | When | When the operator presses Paste, the system shall append a new block equal to the copied one and show `pasted: <kind>`. | **NEW** · Yes; tested (`test_tc1818_copy_paste_duplicates_config_via_wire`). |
| R-FB-CLIP.6 | If | If nothing was copied, then the system shall show the notice `Paste: the clipboard is empty - nothing to paste.` | **NEW** · Yes; tested (`test_tc1819_paste_empty_clipboard_is_friendly_noop`). |
| R-FB-CLIP.7 | If | If no project is open when the operator presses Paste, then the system shall show the notice `Paste refused: load a project first (the paste is checked against the session directory).` | **NEW** · Yes. |
| R-FB-CLIP.8 | If | If the pasted block breaks a rule of S15 CTX-FLOWFILE, then the system shall add nothing and show the notice `Paste refused: <first finding message>`. | **NEW** · Yes (`flow_screens.py:1877-1887`). |
| R-FB-VAR.1 | When | When the operator presses Variables, the system shall show or hide the variable editor and list. | **NEW** · Yes; tested (`test_tc_b97_48_variables_chip_counts_and_toggles`). |
| R-FB-VAR.2 | U | The system shall label the Variables chip `Variables (<n>)`, n the number of declared variables. | **NEW** · Yes; tested (`test_tc_b97_48_variables_chip_counts_and_toggles`). |
| R-FB-VAR.3 | When | When the operator presses + Add var with a valid name and value, the system shall declare the variable, replacing the value of a variable of the same name. | **NEW** · Yes; tested (`test_tc1817_builder_funnel_table_edits`). |
| R-FB-VAR.4 | If | If the name is not 1 to 32 characters of `A-Z`, `0-9` and `_`, then the system shall show the notice `Variable refused: the name must be a placeholder [A-Z0-9_] (e.g. BOOST) - no lower case, no spaces.` | **NEW** · Yes. |
| R-FB-VAR.5 | If | If the value is empty, then the system shall show the notice `Variable refused: the value cannot be empty.` | **NEW** · Yes. |
| R-FB-VAR.6 | If | If the value is longer than 256 characters or the flow already has 32 variables, then the system shall show the notice `Variable refused: at most 32 variables, each value at most 256 characters.` | **NEW** · No: accepted, then the saved file is refused on load (D16-10). |
| R-FB-VAR.7 | U | The system shall list each variable as `${<NAME>} = <value>`, or `no variables — ${NAME} placeholders in change docs pass through unchanged` when there is none. | **NEW** · Yes. |

### S16.5 · Run, Clear and the result (CTX-BUILDER; R-TUI-059 screen half)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-059.23 | When | When the operator presses Run, the system shall run the chain once over the open project as S15 states. | Yes; tested (`test_at_flow_add_blocks_and_run_renders_result`, `test_tc_b97_50_run_requests_the_single_image_scope`). |
| R-TUI-059.24 | If | If no project is open when the operator presses Run, then the system shall show a FAILED result with `no project loaded - load a project first`. | Yes. |
| R-FB-RUN.1 | If | If the chain is empty when the operator presses Run, then the system shall show the notice `No blocks to run — add a block first.` | **NEW** · No: the empty run shows CLEAN (D16-12). |
| R-FB-RUN.2 | When | When a run ends, the system shall show the result of CTX-BUILDER. | **NEW** · Yes; tested (`test_at088a_pipeline_ledger_structure_all_three_banners`, `test_tc088_4_ribbon_encodes_footprint`). |
| R-FB-RUN.3 | If | If a run completed with issues and no block ended error, then the system shall show the banner NOTICES. | **NEW** · Yes (`flow_screens.py:2171-2174`). |
| R-FB-RUN.4 | U | The system shall keep the screen responsive while a run is in progress. | **NEW** · No: the run holds the screen's thread (D16-15). |
| R-FB-RUN.5 | When | When a Builder run reaches an external step, the system shall pause the run there. | **NEW** · Yes (`app.py:2895-2897`: no confirmations; D16-7). |
| R-FB-RUN.6 | When | When the operator presses Clear, the system shall empty the chain, the variables, the clipboard, the notice and the result. | **NEW** · Yes (`flow_screens.py:2037-2049`). |
| R-FB-RUN.7 | If | If the flow has unsaved changes when the operator presses Clear, then the system shall ask `Discard unsaved flow edits?` first. | **NEW** · No: cleared at once (D16-14). |

### S16.6 · Save, load and import a flow (CTX-BUILDER; from S0 HLR-015, LLR-015.1, LLR-015.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FB-SAVE.1 | When | When the operator presses Save…, the system shall open the dialog `Save flow as:` of CTX-BUILDER. | **NEW** · Yes. |
| R-FB-SAVE.2 | If | If a flow of the cleaned typed name exists, then the system shall show the notice `(exists — saves as <name>_<N>.json)`. | **NEW** · Partly: shows `(overwrites existing)` although the save never overwrites (D16-13); tested (`test_at003_save_overwrite_notice_fires_on_existing_name`). |
| R-FB-SAVE.3 | If | If the name box is empty when the operator presses Save, then the system shall keep the dialog open. | **NEW** · Yes. |
| R-FB-SAVE.4 | When | When a flow is saved, the system shall show `✓ saved flows/<name>.json` in the result area. | **NEW** · Yes; tested (`test_at002_name_strip_glyph_dirty_then_saved`). |
| R-FB-SAVE.5 | When | When a flow is saved, the system shall show its saved name on the ribbon with `· saved`. | **NEW** · Yes; tested (`test_at002_name_strip_glyph_dirty_then_saved`). |
| R-FB-SAVE.6 | If | If the typed name is empty after cleaning, then the system shall show the status `Flow name is empty after sanitising - not saved.` | **NEW** · Yes. |
| R-FB-SAVE.7 | If | If no project is open when the operator presses Save… or Load…, then the system shall show a FAILED result with `no project loaded - load or save a project first`. | **NEW** · Yes; tested (`test_tc018_no_project_save_and_load_render_error_card`). |
| R-FB-LOAD.1 | When | When the operator presses Load…, the system shall open the dialog `Load flow:` of CTX-BUILDER. | **NEW** · Yes; tested (`test_at003_load_screen_lists_saved_flow_stems`). |
| R-FB-LOAD.2 | When | When the operator presses Load on a listed flow, the system shall load that flow file into the Builder. | **NEW** · Yes; tested (`test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces`). |
| R-FB-LOAD.3 | If | If the flow has unsaved changes when a flow loads, then the system shall ask `Discard unsaved flow edits?` first. | **NEW** · Yes; tested (`test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces`). |
| R-FB-LOAD.4 | When | When the operator presses Cancel in `Discard unsaved flow edits?`, the system shall keep the current chain. | **NEW** · Yes; tested (`test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces`). |
| R-FB-LOAD.5 | When | When a flow loads, the system shall show its file name on the ribbon with `· saved` and the empty result. | **NEW** · Yes (`flow_screens.py:1358-1381`). |
| R-FB-LOAD.6 | If | If the flow file is refused (S15 R-FLOW-FILE.5), then the system shall keep the chain and show the card `✗ LOAD REJECTED — flows/<name>.json (<n> findings)`, one line `[<code>] <message>` per finding, and `Current flow unchanged.` | **NEW** · Yes; tested (`test_at006_quarantine_card_painted_and_flow_unchanged`). |
| R-FB-LOAD.7 | If | If the flow file is refused, then the system shall show `load refused: flows/<name>.json — this chain is kept` on the pipeline frame. | **NEW** · Yes (`flow_screens.py:1423-1425`). |
| R-FB-LOAD.8 | When | When the operator presses Import…, the system shall open the system's file picker for `.json` files. | **NEW** · Yes (`screens.py:870-886`). |
| R-FB-LOAD.9 | When | When the operator picks a file to import, the system shall copy it as S15 R-FLOW-FILE.9 states, add it to the list and show `imported flows/<file>`. | **NEW** · Yes; tested (`test_at_b94_17_template_save_listing_import_and_dedup`). |
| R-FB-LOAD.10 | If | If the import is refused, then the system shall show `import refused: <error type>` in the dialog. | **NEW** · Yes. |
| R-FB-LOAD.11 | If | If no file picker is available, then the system shall show `import unavailable in this environment` in the dialog. | **NEW** · Yes. |

### S16.7 · Flow Execution: lanes and binding (CTX-FXSCREEN; from S0 HLR-017, 018, LLR-017.1, 017.2, 018.1, HLR-147, LLR-147.2, 147.4)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FX-SCR.1 | U | The system shall offer the Flow Execution of CTX-FXSCREEN as a rail window. | **NEW** · Yes; tested (`test_at_b94_02_rail_twelve_entries_mount_panels`). |
| R-FX-SCR.2 | U | The system shall show the parts of the Flow Execution in the order of CTX-FXSCREEN. | **NEW** · Yes; tested (`test_tc_b97_24_header_rows_inside_and_mode_control_narrow`, `test_tc_b97_53_no_blank_row_outside_or_between_lanes`). |
| R-FX-SCR.3 | U | The system shall show every lane name, set name, ref, command and path on the Flow Execution as plain text, never as markup. | **NEW** · Yes; tested (`test_tc_b97_26_hostile_text_renders_literally`). |
| R-FX-LANE.1 | When | When the operator presses Import…, the system shall open the dialog `Load flow:` of CTX-BUILDER. | **NEW** · Yes. |
| R-FX-LANE.2 | When | When the operator loads a flow from that dialog, the system shall add a lane for it below the others. | **NEW** · Yes; tested (`test_at_b94_19_import_mounts_lanes_side_by_side`). |
| R-FX-LANE.3 | If | If a lane of that name exists, then the system shall name the new lane `<name>_<N>` with the lowest free N from 1. | **NEW** · Partly: N starts at 2 (D16-19). |
| R-FX-LANE.4 | If | If the flow file is refused, then the system shall keep the lanes and show the notice `import refused: flows/<name>.json — [<code>] <message>`. | **NEW** · Yes. |
| R-FX-LANE.5 | If | If no project is open when the operator presses Import…, then the system shall show the notice `import refused: no project loaded - load or save a project first`. | **NEW** · Partly: shows `import refused: flows/?.json — [FX-NO-PROJECT] no project loaded - load or save a project first` (D16-20). |
| R-FX-LANE.6 | When | When a lane is added, the system shall show in each LOAD card's box the ref that lane reads. | **NEW** · Yes; tested (`test_tc_b97_22_rebind_input_and_bind_inside_the_source_card`). |
| R-FX-LANE.7 | When | When the operator presses Bind on a LOAD card, the system shall bind that lane's LOAD ref to the box's text. | **NEW** · Yes; tested (`test_at_b94_20_rebind_run_reads_each_chains_own_inputs`). |
| R-FX-LANE.8 | U | The system shall leave every other lane's refs unchanged by a Bind. | **NEW** · Yes; tested (`test_tc_b94_27_lane_binding_isolation_and_noop`). |
| R-FX-LANE.9 | If | If the box is empty when the operator presses Bind, then the system shall show the notice `binding refused: lane '<lane>' input <n> needs a non-empty ref`. | **NEW** · Yes. |
| R-FX-LANE.10 | If | If the box holds the ref the lane already reads, then the system shall change nothing on Bind. | **NEW** · Yes; tested (`test_tc_b94_27_lane_binding_isolation_and_noop`). |
| R-FX-LANE.11 | When | When a lane's binding changes, the system shall drop that lane's confirmed external steps. | **NEW** · Yes (`flow_screens.py:3894-3899`). |
| R-FX-LANE.12 | U | The system shall give every card of every lane the same width, so the k-th cards line up. | **NEW** · Yes (`flow_screens.py:2479-2498`). |

### S16.8 · Flow Execution: Run and the run log (CTX-FXSCREEN; from S0 HLR-019, 020, LLR-020.1, HLR-147, LLR-147.1, 147.8, 147.9, 147.10)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FX-RUN.1 | When | When the operator presses Run, the system shall run the lanes as a chain set (S15) in the mode the switch shows. | **NEW** · Yes; tested (`test_at_b94_21_parallel_mode_overlaps_isolates_and_captures`, `test_at_b94_22_default_run_is_strictly_sequential`). |
| R-FX-RUN.2 | When | When the operator presses or clicks the mode switch, the system shall switch between sequential and parallel. | **NEW** · Yes; tested (`test_tc_b97_24_mode_click_selects_the_word_keys_toggle_report_records_it`). |
| R-FX-RUN.3 | When | When the Flow Execution first shows, the system shall show the mode sequential. | **NEW** · Yes. |
| R-FX-RUN.4 | If | If there is no lane when the operator presses Run, then the system shall show the log line `No chains to run — Import… adds a lane first.` | **NEW** · Yes. |
| R-FX-RUN.5 | If | If no project is open when the operator presses Run, then the system shall show the log line `✗ no project loaded - load or save a project first`. | **NEW** · Yes. |
| R-FX-RUN.6 | While | While a run is in progress, the system shall disable Run and every Confirm. | **NEW** · Yes; tested (`test_tc_b97_55_input_queued_during_a_run_starts_no_second_run`). |
| R-FX-RUN.7 | U | The system shall keep the screen responsive while a run is in progress. | **NEW** · No: the run holds the screen's thread (D16-15). |
| R-FX-RUN.8 | When | When a run ends, the system shall show each lane's head, card statuses and cable marks of CTX-FXSCREEN from that run. | **NEW** · Yes; tested (`test_tc_b97_21_three_lane_run_paints_each_cable`, `test_tc_b97_21_cable_glyph_truth_table`). |
| R-FX-RUN.9 | When | When a run ends, the system shall replace the run log with the log lines of CTX-FXSCREEN for that run. | **NEW** · Yes; tested (`test_at_b94_23_run_log_inline_failure_and_report_provenance`, `test_tc_b94_29_run_log_emission_and_all_clean_arm`). |
| R-FX-RUN.10 | If | If the run log holds more than 8 lines, then the system shall show the earlier-lines line and the newest 7. | **NEW** · Yes; tested (`test_tc_b97_53_run_log_paints_at_most_eight_lines`). |
| R-FX-RUN.11 | If | If the chain set is refused (S15 R-FLOW-CHAIN.7), then the system shall show the reason in the run log and on the status line. | **NEW** · Yes (`app.py:3118-3127`). |
| R-FX-RUN.12 | If | If a run raises an error, then the system shall show the log line `✗ run failed - <error type>: <first line of the message>`, at most 160 characters. | **NEW** · Yes; tested (`test_tc_b97_55_a_run_that_raises_paints_one_english_line`). |
| R-FX-RUN.13 | When | When a run ends, the system shall show the chain-set report's path in the run log. | **NEW** · No: the path is never shown (D16-18). |
| R-FX-RUN.14 | U | The system shall use the typed set name for the report of a run and of a confirm re-run. | **NEW** · Partly: Run uses the name of the last load or save (D16-16). |
| R-FX-SIZE.1 | While | While the Flow Execution is shown at 118 columns by 54 rows or more, the system shall show Import…, the mode switch, Run, Save Set and Load Set without scrolling. | **NEW** · Yes; tested (`test_tc_b97_36_execution_actions_inside_at_scroll_zero`). From S0 HLR-149, LLR-149.3. |
| R-FX-SIZE.2 | While | While the Flow Execution is shown at less than 118 columns or less than 54 rows, the system shall keep every control reachable by scrolling. | **NEW** · Yes; tested for Run, Save Set and Load Set at 80 × 24, 100 × 40 and 220 × 40 (`test_tc_b97_59_execution_below_the_range_actions_reachable`). From S0 HLR-149, LLR-149.6. |

### S16.9 · Waiting and confirming (CTX-FXSCREEN; from S0 HLR-147, LLR-147.3, 147.13)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FX-WAIT.1 | While | While a lane waits at an external step, the system shall show its pending lines and its Confirm. | **NEW** · Yes; tested (`test_tc1804_fx_lane_pause_confirm_rerun`). |
| R-FX-WAIT.2 | While | While a lane waits, the system shall paint its waiting elements in the waiting colour, which no other element of the Flow windows uses. | **NEW** · Yes; tested (`test_tc_b97_52_waiting_colour_only_on_waiting_human_elements`). |
| R-FX-WAIT.3 | While | While an attention lane exists, the system shall show the REQUIRED line naming it. | **NEW** · Yes (`flow_screens.py:3655-3660`). |
| R-FX-WAIT.4 | When | When the attention lane changes, the system shall scroll its waiting card and its Confirm into view without moving the focus. | **NEW** · Yes; tested (`test_tc_b97_23_three_lane_pause_waiting_lane_in_view_focus_kept`, `test_tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view`). |
| R-FX-WAIT.5 | When | When the operator presses a waiting lane's Confirm, the system shall run that lane again as S15 R-FLOW-CHAIN.9 states. | **NEW** · Yes; tested (`test_tc1804_fx_lane_pause_confirm_rerun`). |
| R-FX-WAIT.6 | When | When the operator presses `c` and the attention lane has waited for the dwell, the system shall confirm it with the status `Confirmed <lane> — re-running from block <i>/<n>.` | **NEW** · Yes (`flow_screens.py:3726-3747`). |
| R-FX-WAIT.7 | If | If the attention lane has waited less than the dwell when the operator presses `c`, then the system shall show the status `c ignored — <lane> started waiting a moment ago. Press c again to confirm.` | **NEW** · Yes. |
| R-FX-WAIT.8 | If | If no lane waits when the operator presses `c`, then the system shall show the status `c: no lane is waiting for confirmation.` | **NEW** · Yes. |
| R-FX-WAIT.9 | If | If a run is in progress when the operator presses `c`, then the system shall show the status `c: a run is in progress — wait for it to finish.` | **NEW** · Yes. |
| R-FX-WAIT.10 | While | While another window is shown, the system shall ignore `c`. | **NEW** · Yes (`app.py:7507-7508`). |
| R-FX-WAIT.11 | U | The system shall confirm each waiting step of a lane at most once. | **NEW** · Yes (`flow_screens.py:3749-3766`). |
| R-FX-WAIT.12 | If | If a confirm re-run stops the flow, then the system shall show the status `<lane> failed at block <i>/<n> — <cause>; Run re-runs the set.` | **NEW** · Yes (`flow_screens.py:3527-3534`). |
| R-FX-WAIT.13 | If | If a confirm re-run raises an error or the lane no longer waits there, then the system shall add the log line `✗ <lane> · confirm re-run failed - <reason>` and keep the lane waiting, unconfirmed. | **NEW** · Yes; tested (`test_tc_b97_55_confirm_rerun_that_raises_leaves_the_entry_unconfirmed`). |

### S16.10 · Save and load a chain set (CTX-FXSCREEN; from S0 HLR-021, LLR-021.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-FX-SET.1 | When | When the operator presses Save Set, the system shall save the lanes as a chain set under the typed set name (S15 R-FLOW-SET.1). | **NEW** · Yes; tested (`test_at_b94_24_save_reload_rerun_regenerates_and_notices`). |
| R-FX-SET.2 | When | When a chain set is saved, the system shall show its saved name on the ribbon with `· saved`. | **NEW** · Yes. |
| R-FX-SET.3 | When | When a chain set is saved, the system shall refresh the saved sets list. | **NEW** · Yes (`app.py:3266`). |
| R-FX-SET.4 | If | If the chain set is not saved (S15 R-FLOW-SET.2), then the system shall show the status `Chain set not saved - the set is empty or the name sanitised away.` | **NEW** · Yes. |
| R-FX-SET.5 | If | If no project is open when the operator presses Save Set or Load Set, then the system shall show the status `No project loaded - load or save a project first.` | **NEW** · Yes. |
| R-FX-SET.6 | When | When the Flow Execution is shown, the system shall fill the saved sets list from the flowsets home. | **NEW** · Yes (`app.py:2998-3006`, `:7481-7484`). |
| R-FX-SET.7 | When | When the operator presses Load Set with a set chosen, the system shall replace the lanes with that set's lanes. | **NEW** · Yes; tested (`test_at_b94_24_save_reload_rerun_regenerates_and_notices`). |
| R-FX-SET.8 | If | If the lanes have unsaved changes when the operator presses Load Set, then the system shall ask `Discard unsaved flow edits?` first. | **NEW** · No: replaced at once (D16-14). |
| R-FX-SET.9 | If | If the chain-set file is refused, then the system shall keep the lanes and show the notice `load refused: flowsets/<name>.json — [<code>] <message>`. | **NEW** · Yes. |
| R-FX-SET.10 | If | If the chain-set file is refused, then the system shall show the status `Chain set load refused: <first message>`. | **NEW** · Yes. |
| R-FX-SET.11 | If | If a lane's flow file is missing or refused, then the system shall leave that lane out and name it in the notice `chain(s) skipped, template missing: <lanes>`. | **NEW** · Yes. |
| R-FX-SET.12 | When | When a chain set loads, the system shall show the notice `<n> chain(s) restored`. | **NEW** · Yes. |
| R-FX-SET.13 | If | If a loaded lane's bound ref names no file, then the system shall show the pending line `▪ '<ref>' missing - re-bind` on that lane. | **NEW** · Yes; tested (`test_at_b94_24_save_reload_rerun_regenerates_and_notices`). |
| R-FX-SET.14 | When | When a chain set loads, the system shall show every lane as not run. | **NEW** · No: a lane with recorded files shows `done` (D16-17). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D16-1 | R-TUI-059's history ("formerly the dropped Bookmarks placeholder", "tracer slice", the OUT list of batches 45–47, the snapshot xfail marks, "fast-dev-flow", "Frozen-engine diff = 0"). | Out of the requirements; they stay in the batch records. |
| D16-2 | The chapter was incomplete: one row for two windows with about 60 controls, messages and states. S0's table held part as batch rows. | NEW rows S16.1 … S16.10; the S0 rows they restate are listed in each sub-heading. |
| D16-3 | S0 HLR-013 asks for a block-diagram canvas with cable routing; batch-97 (HLR-146) replaced it by one row of cards. | HLR-013 is superseded; S0 says so. |
| D16-4 | R-TUI-059's engine and security sentences (containment before open, WRITE-OUT through the sanitiser) are run behaviour. | Rows R-TUI-059.1 … .6 in S15 (rule D-9); the safe-text sentence is R-FB-RIB.3 here. |
| D16-7 | A Builder run gets no confirmations (`app.py:2895-2897`), so a chain with an external step always pauses there; confirming lives in Flow Execution. | Keep (R-FB-RUN.5); the help text should say so (S7). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D16-6 | `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_ext_session` (`flow_screens.py:2066-2067`) and `#fx_help` (`:2825`) are built and painted on every change but never shown; `_canvas_text`, `_blocks_text`, `_flow_block_label` serve only them (the last still says `REPORT  (generation deferred - FB-P1b)`, false since batch-60). `render_fused_result` goes with S15 D15-8. | Delete (not used). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D16-10 | Add checks only non-empty inputs and NUL (`flow_screens.py:157-170`, `:1998-2029`); a variable only its name and a non-empty value (`:1776-1804`). Refs that escape the project, unsafe output names, values over 256 characters, a 33rd variable or a 65th block are accepted, saved, and then refused by Load (S15 CTX-FLOWFILE). Paste already checks a block with the loader (`:1877-1887`). | Check each Add and + Add var with the loader's rules, as Paste does (R-FB-ADD.11, R-FB-VAR.6). |
| D16-11 | Add builds `SourceBlock(ref)` and `WriteOutBlock(ref)` with the default S19 type (`flow_screens.py:160-167`); the run reads a `.hex` LOAD as S19 and writes a `.hex` output as S19 records (`flow_execution_service.py:325-332`, `:675-678`). The card then shows `fmt s19`. | Declare Intel HEX for `.hex` and `.ihex` names (R-FB-ADD.12). |
| D16-12 | Run on an empty chain posts the run (`flow_screens.py:2030-2032`) and shows a CLEAN banner over nothing. | Refuse with `No blocks to run — add a block first.` (R-FB-RUN.1). |
| D16-13 | The Save dialog shows `(overwrites existing)` (`screens.py:789-794`), but `save_flow_json` never overwrites; it writes `<name>_2.json` (`flow_persistence_service.py:1024-1030`). | Notice `(exists — saves as <name>_<N>.json)` with the name that will be written (R-FB-SAVE.2). |
| D16-14 | Clear empties an unsaved chain at once (`flow_screens.py:2037-2049`), and Load Set replaces unsaved lanes at once (`app.py:3309`), while Load flow asks first (`app.py:2985-2992`). | Ask with `Discard unsaved flow edits?` in all three (R-FB-RUN.7, R-FX-SET.8). |
| D16-15 | The Builder's Run (`app.py:2895`) and Flow Execution's Run and confirm (`:3109`, `:3208`) run on the screen's thread; nothing repaints until the run ends, parallel mode included. | Run in a worker; keep Run disabled meanwhile, as Flow Execution already does (R-FB-RUN.4, R-FX-RUN.7). |
| D16-16 | Run sends the set name stored at the last load or save (`flow_screens.py:3851-3853`); a confirm re-run reads the typed box (`app.py:3212`); Save Set reads the typed box (`flow_screens.py:3858`). | Use the typed name everywhere (R-FX-RUN.14). |
| D16-17 | A reloaded lane with recorded files shows `▓ done` (`flow_screens.py:2941`), although it has not run this session and its last run may have failed. | `░ not run` until it runs (R-FX-SET.14). |
| D16-18 | Every set run writes a chain-set report (S15 R-FLOW-CHAIN.11), but the window never shows where (`render_run` ignores `record.report_path`, `flow_screens.py:3468-3498`); the log even points to "the run report". | Add the log line `report: reports/<file>` (R-FX-RUN.13). |
| D16-19 | Lane names take `_2`, `_3` … (`flow_screens.py:2891-2898`); S5's numbered names start at 1. | From 1, with S15 D15-15 (R-FX-LANE.3). |
| D16-20 | With no project, Import… shows `import refused: flows/?.json — [FX-NO-PROJECT] …` (`app.py:3035-3039`): a file that does not exist and an internal code. | `import refused: no project loaded - load or save a project first` (R-FX-LANE.5). |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D16-25 | S0 HLR-142: "the Flow Builder shall ask for the A2L reference". The engine reads `a2l_ref` on LOAD and PATCH (S15 R-FLOW-SRC.8, R-FLOW-PATCH.4); the add form has no input for it (`flow_screens.py:1234-1279`). | Where the optional A2L input sits in the LOAD and PATCH add forms, and how the card shows it. |
| D16-26 | The palette offers seven kinds and no REPORT (`flow_screens.py:1104-1113`); a REPORT block, and so the flow report, can only come from an imported flow file. | Where a REPORT chip goes in the palette, and whether the legend shows `≡ report` always. |
| D16-27 | The same statuses have two glyph sets: the Builder result uses `● ◈ ✗ ○ □` (`flow_screens.py:227-236`), Flow Execution `▓ ◇ ✗ ░ □` (`:2424-2440`); `✓` is the CHECK kind on the same screen. | One status vocabulary for both windows and the chain-set report (S15 R-FLOW-CHAIN.16). |
| D16-28 | The flow colours (PATCH `#56e0d6`, CRC `#c9562b`, waiting `#e8ad3d`, A2B purple, LOAD and EXT blues; `flow_screens.py:548-561`) are not S3's palette. | Which palette colours carry the kinds and the waiting state (S3 CTX-LEGEND: one palette everywhere). |

**Passed to other groups**

- **S1**: the Flow windows are already safe-text views; no change.
- **S5**: the 📂 Open flows/ chip (target `<project>/flows/`) and the 📂 Open session chip (target: the project folder) on the two headers.
- **S6**: keys `8` (Flow Builder) and `]` (Flow Execution); `c` acts only on Flow Execution (R-FX-WAIT.10).
- **S7**: `Save flow as:`, `Load flow:` and `Discard unsaved flow edits?` contents are here (CTX-BUILDER); Enter on a list item (D7-21) and first focus on Cancel (D7-22) stay S7's. The flow help sections should say that a Builder run pauses at an external step and that confirming is done in Flow Execution (D16-7). Space presses a chip on both windows (R-FB-RIB.4).
- **S15**: every run, file and report behaviour these windows start; the Intel HEX choice (D16-11) and the add-time check (D16-10) use S15's rules.
- **S0**: pointers from HLR-013 (superseded), 016, 017, 018, 019 (controls), 020 (log), 021 (controls), 142 (the Builder's part), 146, 147, 149 and LLR-016.1, 017.1, 017.2, 018.1, 020.1, 146.1 … 146.14, 147.1 … 147.13 to S16.

---

**Received from later groups** (after all groups were written)

- S16.1 (S0 residual of HLR-149: sizes) → rows R-FB-RIB.6, R-FX-SIZE.1, .2. They describe today's layout; no layout change, so no prototype round.
- S16.2 (S6: `c`) → covered by R-FX-WAIT.6 … .10.
- S16.3 (S7: Save flow, Load flow, Discard contents) → covered by CTX-BUILDER, R-FB-SAVE.x, R-FB-LOAD.x, R-FX-LANE.1.
- S16.4 (S13: the flow CRC arm) → covered: its rows are S15 R-FLOW-CRC.1 … .8; S16 shows their texts (CTX-BUILDER result lines, CTX-FXSCREEN log lines) without restating them.
- S16.5 (S15: the screens of the runs; the A2L reference field and the file-format choice) → covered by R-FB-ADD.17 (D16-25) and R-FB-ADD.12 (D16-11).

**Reconciled with batch-100 (s19_app 570b4b5)**

- From S11 and the sweep: R-FB-RIB.2 cites S11 R-SAVEAS-8 (after a save as the Flow panels use the new project folder, batch-100 LLR-171.1l, TC-B100-31). Cell change only.
- From S5: R-FB-RIB.1's unsaved state is the "unsaved flow" of S5 CTX-LOADQ; the cell cites S5 R-LOADQ-001.4. Cell change only.
- From the sweep: batch-100 LLR-171.4i, .4j (no flow or chain set saved outside the work area) are engine rows in S15 (R-FLOW-FILE.11, R-FLOW-SET.7, S15 D15-18); no S16 row.
- No row added, changed in text or retired; no decision added or superseded.

## 6. Counts

| | Old S16 | Strict |
|---|---:|---:|
| Requirement statements | 1 row | 132 rows (125 NEW) |
| Statements the code contradicts or that are not product behaviour | 1 (R-TUI-059: dropdown list, OUT list, engine) | 0 |
| Rows by form: U / When / While / If / Where | — | 21 / 49 / 10 / 52 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 21 (5 follow the code or move, 1 remove, 11 correct a defect, 4 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
