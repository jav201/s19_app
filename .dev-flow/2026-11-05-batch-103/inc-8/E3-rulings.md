# Inc 8 — E3 rulings (orchestrator)

Orchestrator claude-opus-5-5, 2026-11-13 (time in `steps.log`, from `date`). The E3 verdicts in `E3-architect.md` and `E3-security.md` are both FAIL, with 11 MAJOR findings. One correction pass (E3R1) applies the rulings below to `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `codewire/graph-inc8.md` and `E1-rulings.md` §4. The same reviewer then re-reviews only the corrected parts.

## MAJOR: all accepted, fixed as the reviewer proposed, with these choices

| Finding | Ruling |
|---|---|
| E3A-01 | Accepted. Add a row window with scrolling that keeps the selection in view, plus its rows, cases and the node changes. |
| E3A-02 | **Pin one per-kind operations table now** (option 1). Then Inc 9 adds only keys and new functions, and 8 and 9 can be built in parallel. `build_row`, the preview, submit and `set_document` dispatch through that table, so they no longer branch on the kind. The table becomes part of I-8.5. |
| E3A-03 | Accepted. I-8.2 becomes `_stage_encoded(name, encoded, shown)`, where `shown` is the decoded text for the message. Re-pin it. |
| E3A-04 | Accepted. Reuse the picker's population describe (canon R-PICKER-CORRECT.019), so a page change does not walk the A2L again. Adjust R-PE-DEF.11 and .12 and the thread note. |
| E3A-05 | Accepted. Inc 8 owns I-8.3 (the dock is yielded from `_compose_doc_controls` in `actions.py`). **Inc 10's re-map (PENDING P-020) must consume I-8.3 and must not rely on `#patch_main`.** The two merge in either order, and whichever merges second rebases. Record this in `E1-slice.md` §5. Inc 10's records are not edited here; the orchestrator carries it into P-020. |
| E3A-06 | Accepted. Add the help-text rows: the Patch help section and the labels that law TC-B97-32 needs, against canon R-WHELP.12. Add `s19_app/tui/window_help.py` to group A (`change_service.py`, `app/patch.py`, `window_help.py` = 3 files). |
| E3S-01 | Accepted. Stage and sheet read the same source of bytes. Pin which one, so that Apply plus Remove never resurrects removed bits. Add the reviewer's `1A E6` case as a robustness case. |
| E3S-02 | Accepted. An equal-span stage over a `string` entry updates what the writer saves (or converts the entry). Add a save round-trip case. |
| E3S-03 | Accepted. A stage is refused while a session action runs (R-PE-110 and the CTX-BUSY list). Add the row and the case, and `_refuse_if_busy` first in node A3. |
| E3S-04 | Accepted. Cap the text rows painted (with a visible cut) and the formula input length for every fill route, not only the typed one. Add the hostile 1 MiB case. |
| E3S-05 | Accepted. Equal limits paint without a division (a fixed form), with a case. |

## MEDIUM: fix in E3R1
- E3A-07: `select_next` targets the staged row by name, not by the current selection.
- E3S-06: R-PE-DEF.42 states the real toolkit behaviour (the whole oversized insert is refused, or it is truncated by our own code). Pick the one the product can show, and state its text.
- E3S-07: markup off for the formula bar's name label, with a hostile-name case.

## MINOR
Fix them in E3R1 when the fix is a row or case text: E3A-08 (correct §5), E3A-09, E3A-10, E3A-11, E3A-12, E3S-08. Anything else goes to `E1-rulings.md` §5 as a backlog line, and the orchestrator copies it to PENDING.

## Unchanged
D-1, D-2 and D-6 remain provisional pending capture verdicts (DF-09). The cap is about 80 requirements and 40 nodes. If E3R1 goes past about 90 rows or 48 nodes, stop and report the split point instead of continuing.

## E3R1 corrections

Worker claude-opus-5-5 (architect, E3R1), 2026-11-13 (time in `steps.log`, from `date`). Records only. Counts: 72 → 88 active requirements (16 new, R-PE-110 changed, R-PE-DEF.1 retired by its split), 160 → 205 cases, 42 → 46 graph nodes (under the stop line of about 90 / 48). Paths are relative to this folder (`R` = `01-requirements.md`, `C` = `02-test-cases.md`, `G` = `codewire/graph-inc8.md`, `S` = `E1-slice.md`, `E1` = `E1-rulings.md`). Evidence: `evidence-e1/examples_e3r1-transcript.txt` (examples, `uptime` beside it), `evidence-e1/cw-e3r1-*` (Code-Wire extractor on the changed existing functions), `evidence-e1/trace_check-e3r1.txt`.

**MAJOR**
- E3A-01 → fixed: CTX *row window* R:29; new R-PE-DEF.81 R:228 (cases C:151-153); new node `row_window` G:442; `action_move` G:514, `_paint` G:585, entity `StagingSheet.top`; I-8.4 row window G:61.
- E3A-02 → fixed (option 1): CTX *kind operations*, *editor*, *staged row*, fallback value text R:55, R:60, R:73; new R-PE-DEF.75 R:184; R-PE-DEF.23 fallback case R:191; I-8.5 re-pinned with `KindOps`, `_KIND_OPS`, `ops_for`, `_FALLBACK_OPS` G:86 and the per-kind table G:107; new node `ops_for` G:325; `build_row` G:343, `value_text`, `on_input_submitted` dispatch; `formula_label` removed; S §4 rewritten S:123.
- E3A-03 → fixed: I-8.2 `_stage_encoded(name, encoded, shown)` G:35; node G:714; R-PE-DEF.58 R:242 (`<text>` = the caller's shown text).
- E3A-04 → fixed (option A): R-PE-DEF.11 and .12 rewritten R:176-177; I-8.4 `show_page(names, definitions, image)`, source `A2LParameterPicker.definitions` G:61; node `A2LParameterPicker.set_parameters` G:741 (group S2, Inc 7's file, rebase note G groups table); `show_page` G:491, view-changed handler G:677; threads note E1:102; F-1 cost G:840; EX-C1's vacuous figure withdrawn G:141.
- E3A-05 → fixed in Inc 8's records: I-8.3 (a)…(e) G:52; ruling text S:145; R-PE-DEF.1 split into R-PE-DEF.1.1 ("other shown regions", dock case) R:154 and new R-PE-DEF.74 (`min-height: 12`) R:156. Inc 10's records not edited (orchestrator → P-020).
- E3A-06 → fixed: new module M7, R-PE-DEF.83 … .87 R:269-273 (cases C:206-213); node `WINDOW_HELP_SECTIONS` G:751; `window_help.py` in group A S:11; TC-B97-32's `PATCH_TABS` retarget E1:94; wording batched as V-12 E1:124.
- E3S-01 → fixed: CTX *image* = the source view R:65; R-PE-DEF.51 Apply-and-Remove case R:235 (C:160); A3 passes `_strip_source_map` G:728; `stage_definition` G:702; I-8.2 stage seam G:35; F-2 premise corrected.
- E3S-02 → fixed: R-PE-DEF.52 "replace that entry with a bytes entry" R:236 (round-trip case C:163, probe `X.*`); R-PE-DEF.54 R:238; I-8.2 G:35; `_stage_encoded` example EX-S8 G:714.
- E3S-03 → fixed: R-PE-110 changed (+ "a stage") R:250 (case C:192); A3 begins with `_refuse_if_busy()` G:728; callers in the baseline table (`cw-e3r1-*`).
- E3S-04 → fixed: CTX *editor* (text span ≤ 4,096 B) R:60 and *text rows* (≤ 4) R:125; R-PE-DEF.36 cases R:208; new R-PE-DEF.78 (input empty without an editor), .79 (`… <n> more B`), .80 (4,096-character fill cap) R:215-217, with the 1 MiB cases C:134-139; `<text>` as a name echo in R-PE-DEF.58 R:242; nodes `formula_fill` G:451, `detail_lines` G:428, `action_choose` G:535, `name_echo` G:482.
- E3S-05 → fixed: CTX Δ text and limits cell "while upper > lower"; new R-PE-DEF.76 and .77 R:188-189; `limits_cell` G:396, `delta_text` G:377.

**MEDIUM**
- E3A-07 → fixed: `select_after(name)` in I-8.4 G:61 and node G:574 (replaces `select_next`); R-PE-DEF.60 R:244 (selection-moved case C:180); new R-PE-DEF.82 (pending cleared) R:245; `note_staged(name)` G:651; entity `StagingSheet.pending`.
- E3S-06 → fixed: R-PE-DEF.42 reworded to "leave the formula text unchanged" R:214 (3 cases C:131-133, probe `P4`); EX-H3; `on_input_changed` G:554.
- E3S-07 → fixed: R-PE-DEF.70 case /5 R:258 (C:199); `_paint` updates the bar's name, label and tail as `Text` G:585.

**MINOR**
- E3A-08 → fixed: the wrong `b97_fixtures` sentence corrected and the six laws listed "retarget selectors only; assertion unchanged" E1:93-94.
- E3A-09 → fixed: `min-height: 12` (R-PE-DEF.74 R:156); V-1 gains "the JSON and Inspector tabs scroll inside 6 rows at 118×54" (E1, §6 V-1).
- E3A-10 → fixed: `ChangeActionResult.notices` (I-8.2 G:35); `stage_definition` G:702 and A3 G:728 print the notice as its own line; R-PE-DEF.59 negative control R:243.
- E3A-11 → fixed: CTX *formula text* (base text, pending) and *row fill* R:76-80; R-PE-DEF.24 case /3 R:192 (C:89); R-PE-DEF.38 row fill R:210; `formula_fill` G:451, `on_input_changed` G:554.
- E3A-12 → fixed: CTX column widths in cells R:44; R-PE-DEF.7 case /4 R:169 (C:45, probe `C.*`); `row_line` G:407.
- E3S-08 → fixed: R-PE-DEF.62 case /4 R:249 (C:191, probe `M.*`); `build_row`, `set_document`, `set_image_mem_map` G:642 examples.
- Backlog (no row text fixes them): E3S-09's bidi controls (pre-existing), the real bracketed-paste pilot, and the two stand-in-only cases E1:104.

**Inc 9 items (orchestrator message; Inc 9 `E1-rulings.md` §4 at `cf755dcf`)**
- Inc 9 C-2 → pinned: I-8.4 overridable methods, `SelectionChanged` handled by the sheet itself, `selected_name`, `states`, child ids, `_paint()` as the one repaint entry G:61; entity `StagingSheet.states`; S:123.
- Inc 9 K-1 → pinned: `KindOps.detail(row, preview, width, state, room)` G:86; `detail_lines` G:428; `_paint` G:585.
- Inc 9 K-2 → pinned: optional `KindOps.cells`, None → Inc 8's cell rules G:86; `row_line` G:407.
- Inc 9 K-3 → pinned: optional `KindOps.bar`, None → Inc 8's name and tail G:86; `formula_tail` G:461, `_paint` G:585.
- Inc 9 C-6 → pinned: CTX definition line ` · <record layout>` when named R:109; R-PE-DEF.31 case /5 R:203 (C:105); `detail_lines` example EX-R11 G:428.
- Inc 9 C-8 → pinned: `note_staged(name, advance=True)` G:651 and I-8.4 G:61; R-PE-DEF.60 and .82 narrowed to formula-bar stages R:244-245 (no-advance case C:181).
- Inc 9 C-9 → applied: R-PE-DEF.36's curve case replaced by a refused row, a `cuboid` copy and the span-bound cases R:208; the fallback cases use a synthesized kind, not a software_a curve (R-PE-DEF.75 R:184).
- Inc 9 E-2 → pinned: CTX *stage* (formula-bar and record stage) R:84; R-PE-110 R:250; the stage seam in I-8.2 G:35 (`_refuse_if_busy()` first, the source view).
- Inc 9 C-4 → applied, provisional: CTX staging sheet subtitle `enter edit · ↑↓ row · arrays open the bench` R:25; `LayoutMixin.compose` G:597; V-13 E1:125.
- Inc 9 C-5 → applied, provisional: R-PE-DEF.1.2 (LANDS IN 6 rows while a bench is shown) R:155; the `-bench` CSS rule owned by group P (S §2 E3R1 table); V-13 E1:125.
- Inc 9 C-1 → no Inc 8 change (Inc 9's integrator constructs the subclass after the merge) S:123.
- Inc 9 C-7 → no Inc 8 change (Inc 8 keeps `staged as <shown>`; Inc 9 rewords R-PE-BENCH.72) S:123.

**Not done in E3R1:** Inc 10's records (orchestrator, P-020); PENDING entries (orchestrator copies E1 §5's backlog lines); the re-review of the corrected parts (next step).

## E3R2 corrections

Worker claude-opus-5-5 (architect, E3R2), 2026-11-13 (time in `steps.log`, from `date`). Records only, applying the orchestrator's rulings on the re-review (`E3-architect.md` and `E3-security.md` §"Re-review after E3R1", commit 79ee4aae). Counts: 88 → 89 active requirements (new R-PE-DEF.88; R-PE-DEF.11, .12 and .81 changed in place), 205 → 210 cases, graph nodes 46 (unchanged). Abbreviations as in §E3R1. Evidence: `evidence-e1/examples_e3r2.py` and its transcript (`W2.*`, `R12.*`, `S.*`, `uptime` beside the timings, load 7.7–8.0), `evidence-e1/trace_check-e3r2.txt`.

- E3A-13 (MAJOR) → fixed: I-8.4 re-pinned as `show_page(names, definitions, a2l_data, image)`, with `set_document` and every `build_row`, `KindOps.decode` and `KindOps.preview` using the stored payload, never `app.current_a2l_data` G:63. `A2LParameterPicker.definitions_source` sits beside `definitions` G:92, and `set_parameters` sets it G:761. The view-changed handler passes both G:697. Nodes changed: `show_page` G:509, `set_document` G:522, `build_row` G:358, `on_input_changed`. New entity `StagingSheet.a2l_data` G:797. New CTX term *page A2L* R:73. R-PE-DEF.11 gains case /3, where the picker's data and the app's data differ: `143.5` until the picker repopulates, then `287` (R:187, C:51, `R12.*`).
- E3A-14 (MINOR) → fixed: CTX *row window* cuts the detail to room = visible − 1, so the selected row is always painted R:32. `row_window` now returns (top, detail lines painted). Its example `(3, 0, 3, 3)` becomes top 3 with the detail cut to 2 G:459, and `_paint` cuts the detail G:605. R-PE-DEF.81 gains case /4: 10 detail lines at visible 8 → cut to 7 (R:240, C:158, `W2.*`).
- E3A-15 (MINOR) → fixed: Inc 8 paints `enter edit · ↑↓ row` R:29, G:617. Inc 9's integrator appends ` · arrays open the bench` when the bench lands (S:89, S:130). V-13 stays provisional E1:125.
- E3S-10 (MEDIUM) → fixed:
  - A text span over 4,096 B is not decoded. Its Current is `<n> B`: new R-PE-DEF.88 R:196 (C:79-80), CTX value text R:99, the I-8.5 text row G:124.
  - The staged check of the fallback, and of a text row over 4,096 B, makes one pass over the document entries' bytes inside the span against the image: CTX *staged row* R:80, `ops_for` G:339. The image is a `Mapping[int, int]`, so a memoryview is not available. The bound is the document, and the span is never read twice.
  - R-PE-DEF.12 gains the hostile case /2 R:188 (C:53): 200 copies of a 1 MiB span, ≤ 0.5 s. The bounded rule measured 0.00086 s for 200 rows. The negative control, a full decode ×2 per row, is about 62 s (`S.*`).
- E3S-11 (MINOR) → fixed: the E4 pilot note now says that a bracketed paste over 4,096 characters leaves the formula text unchanged E1:101.
- Inc 9 C-4 → now split (E3A-15): Inc 8 keeps `enter edit · ↑↓ row`, and Inc 9's integrator adds ` · arrays open the bench` after the merge. The §E3R1 line "Inc 9 C-4 → applied" is superseded by this one.
