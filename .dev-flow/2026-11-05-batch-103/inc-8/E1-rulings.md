# Inc 8 — E1 rulings: changes to canon rows, open decisions, capture verdicts

Base `91d5ae56`. Rows: `01-requirements.md`; cases: `02-test-cases.md`; slice: `E1-slice.md`; evidence: `evidence-e1/`. Every decision in §3 is **PROPOSED — awaiting orchestrator ruling**; the rows carry the recommended option.

## 1. Sources and what the approved design fixes

- **G2 q1 `q1_pe=approve`** (`../design/G2-verdict-2026-11-12.md`; export `../evidence/G2/veredicto-b103-r2.json`, round `b103_ux_r2`): the round-2 *pe mix* — pe_B's STAGING SHEET (filter row, sheet with header `Parameter | Kind | Current | New | Unit | Limits | Δ`, the limits ruler, the detail under the selected row, the formula bar `new =` / `field =` / `text =`, the border subtitle with the keys), LANDS IN with Patch script / JSON / Checks, file row, document row, legend; pe_C's benches for arrays (Inc 9).
- Scenes read (read only, cited by name, never copied): round 2 `pe_mix.py`, `scn_pe.py`, `b103_ux_r2.html`, captures `pe_mix.pe-value.118.png`, `pe_mix.pe-enum.118.png`, `pe_mix.pe-bits.118.png`, `pe_mix.pe-map.118.png`, `pe_mix.pe-enum.220.png`; round 1 (the archive the brief names) `DESIGN-BRIEF.md`, `variants/pe_B.py`, `pe_B.pe-value.118.png`, `pe_B.pe-enum.118.png`, `veredicto-b103.json` (pe note: B's simple change list, parameter list and horizontal detail; C's detailed views).
- **Finding on the evidence:** `pe_mix.pe-enum.220.png` shows the Workspace screen, not the Patch Editor (a failed capture in the approved round). The 220-column look of the enum detail was therefore never shown to the operator; it is a capture verdict below (V-6).
- **Where the rows deviate from the capture, and why** (DF-04 (b): a proposal adjusts the requirement; each is a decision below): the Inspector tab and `Use parameter` (D-1), the ledger subtitle (D-2), the record-layout word in the definition line (D-7), the narrow-width columns (D-6). The prototype's stand-in enum and bit-mask rows (render only) become real I-2 rows.

## 2. Changes to existing canon rows (with reasons)

| # | Row | Before | After | Reason |
|---|---|---|---|---|
| R-1 | R-TUI-063.1 | ribbon, the ledger beside the inspector, file row, document row, legend | ribbon, filter row, staging sheet, landing pane, file row, document row, legend | G2 q1 (the mix). Inc 10's R-2 later inserts the save-back prompt between the document row and the legend (D-8). |
| R-2 | R-TUI-063.2 | ledger beside the inspector at every width | **Withdrawn**; R-PE-DEF.1 gives the heights | The mix stacks the sheet over LANDS IN. |
| R-3 | R-TUI-063.3 | chips Inspector, JSON, Checks, A2L | Patch script, Inspector, JSON, Checks | G2 q1 + D-1 A. |
| R-4 | R-TUI-063.4 | first shown → Inspector | first shown → Patch script | The capture opens on Patch script. |
| R-5 | R-TUI-063.6 | When the tab changes → INSPECTOR / JSON / CHECKS / A2L | U: the landing pane's title is `LANDS IN` | The capture keeps one title. |
| R-6 | R-TUI-063.7 | the ledger's border title `PATCH SCRIPT` | **Withdrawn** | The ledger has no border inside LANDS IN (capture). |
| R-7 | R-PE-041 | U: the ledger subtitle (on the ledger border) | While Patch script or Inspector is shown: the ledger subtitle on the landing pane's border | The ledger border is gone; the dirty marker ` ●` must stay visible (D-2). |
| R-8 | R-PE-034 | Add, Edit, Remove, Parse pasted, undo, redo, per-entry JSON | + a stage | A stage changes the document. Dirty writer census C-15.1 gains **w6** (`note_staged`). |
| R-9 | R-PE-035 | refused Add, Edit or Remove keeps the flag | + a refused stage | Same rule. |
| R-10 | R-PICKER-CORRECT.011 | When the Patch A2L tab is shown … | When the Patch Editor is shown … (the filter row) | The A2L tab is retired (D-1). |
| R-11 | R-PICKER-CORRECT.020 | the A2L tab's surfaces contained | the filter row, the Use row and its status contained | Same. |

Context notes: **CTX-PE** changes — its picture lists the filter row, the staging sheet and the landing pane (LANDS IN: Patch script, Inspector, JSON, Checks); `inspector` becomes *landing pane*; the `A2L` line leaves and `Use parameter` joins the Inspector line; *save-back prompt* keeps "It sits in the JSON tab" until Inc 10 rules it. **CTX-PE-DEF** is new (`01-requirements.md` Definitions). R-PICKER-CORRECT.005 … .008 and .016 keep their text: "the highlighted row" is now the sheet's selected row (R-PE-DEF.49).

## 3. Decisions — PROPOSED, awaiting orchestrator ruling

### D-1 — Where the Inspector pane, the A2L tab and `Use parameter` go

The capture shows LANDS IN with three chips (Patch script, JSON, Checks); the prototype put the Inspector pane and the A2L tab's `Use parameter` row on a hidden shelf. Hidden, they would leave the entry form (S10.3, `R-PE-020` … `R-PE-033`: raw address entries, Edit, Remove, per-entry Edit JSON), the before → after strip (S10.5), the tally (R-PE-046) and Inc 6's `Use parameter` (R-PICKER-CORRECT.005 … .008, .016, just merged) with no control.
- **A (recommended):** four chips — Patch script, Inspector, JSON, Checks. The Inspector tab keeps today's pane and gains the `Use parameter` row and status line; the picker moves to the filter row; the A2L chip leaves. `Use parameter` acts on the sheet's selected row (R-PE-DEF.49). Consequence: one chip more than the capture; every existing feature stays reachable; until Inc 9 lands, `Use parameter` is the way to patch an array (full length since Inc 6). Rows: as written.
- **B:** the capture literally (three chips). Consequence: about 20 canon rows lose their control and must be withdrawn or deferred; arrays cannot be patched until Inc 9. Not recommended: it removes approved features the verdict did not ask to remove (DF-04 (c): new → defer, and removing is not in the verdict).
- **C:** five chips (A plus the A2L chip with the picker's own table). Consequence: the picker appears twice (filter row and tab) — one widget cannot mount in two places, so the tab would need a second picker: two describes per population (R-PICKER-CORRECT.019's budget doubles).

### D-2 — The ledger subtitle (`N entries ●`) without the ledger border

- **A (recommended):** on the landing pane's border subtitle while Patch script or Inspector is shown; JSON keeps `v2 schema` (R-TUI-063.8) and Checks its run state. Consequence: the dirty marker is visible on the two tabs where entries are edited; the JSON tab already shows its own stamp with the dirty state.
- **B:** keep a bordered `#patch_win_script` inside the tab. Consequence: 2 of the 9 rows lost to a border; differs from the capture.

### D-3 — The symbol of an entry that holds two masked fields of one word

Two masked fields of one word share one span (DEFC `MASK_FIELD_0001` and `MASK_BIT_0001`, both 0x800010, 2 B). Two entries at one address are a `CHG-COLLISION` (`changes/validate.py:45`), so a word holds **one** entry; the second stage replaces its bytes over the overlay (R-PE-DEF.51, .52; pilot `ORDER.*`: both orders end at `1F F6`, both fields decode as typed; without the overlay the first field reverts: `ORDER.*.no_overlay`).
- **A (recommended):** the entry keeps the symbol of the field staged first (R-PE-DEF.54). The reader accepts it on reload, as both names resolve to the same address and length (`changes/io.py:23-33`, `CHG-SYMBOL-VALUE` checks address and byte length). The sheet's staged marks come from the overlay, not from the symbol (R-PE-DEF.62), so both rows show `●`.
- **B:** drop the symbol (address form) once a second field joins. Consequence: the ledger loses the name; nothing else changes.

### D-4 — Dropping one masked field of a staged word (E3A-07's "delete hazard")

With one entry per word (D-3), there is no separate earlier entry to drop: removing the entry (Remove, Undo) drops every field of the word at once, so no stale bits remain.
- **A:** a new key on a staged row (e.g. `delete`) unstages that field: the bits under its mask return to the image's bits, the others keep the entry's bits (pilot `UNSTAGE`: `1ff6` → `1ff7`), the entry leaves when it equals the image. Consequence: one key, two rows, a capture verdict; not in the approved design.
- **B (recommended):** no per-field unstage in Inc 8. To drop one field the operator stages its current value again (the overlay re-encode keeps the other field) or uses Undo. Consequence: no new key; the E3 ruling's AT (two masked edits in either order) is R-PE-DEF.51. A per-field key goes to the backlog with view levels (backlog item 1).

### D-5 — Files and groups (the brief's cap: 4 source files per worker group)

- **A (recommended):** three file groups — S (2 new modules: the pure sheet model, the widget), P (`layout.py`, `panel.py`, `a2l_picker.py`, `styles.tcss`), A (`change_service.py`, `app/patch.py`); 8 files, none of the groups over 4 (`E1-slice.md` §1). At E4, S runs as two implementers by file (S1 `definition_sheet.py`, 17 nodes; S2 `sheet.py`, 10 nodes), so four implementers in all (E2 node count, `codewire/graph-inc8.md`). Interfaces between them: I-8.1 (`StagedOverlay`), I-8.2 (`_stage_encoded`), I-8.4 (the widget's API and messages), pinned in the graph.
- **B:** two groups, the pure model inside the widget module. Consequence: one file fewer, but the ~30 cell rules are tested only through Textual.

### D-6 — Columns below 100 cells

The capture covers 118 and 220 columns only; R-TUI-064.3 asks that every control stay reachable below 118 × 54.
- **A (recommended):** a third width class below 100 cells that hides Kind and Unit and narrows the rest (CTX-PE-DEF column widths); no row is wider than the sheet (R-PE-DEF.7).
- **B:** keep the 100-cell layout and scroll the sheet horizontally. Consequence: the formula bar and the detail scroll away from the row.

### D-7 — The record layout word in the definition line

The capture shows `… · RL_U16 · …`; I-2's `Definition.record_layout` is `None` for every scalar (pilot `DEFC.*.record_layout = None`, `V171.*.record_layout = None`); it is filled only for Inc 3's kinds.
- **A (recommended):** leave the layout word out for scalars (R-PE-DEF.31). No interface change.
- **B:** an I-2 change: `describe_definitions` fills `record_layout` for scalars. Consequence: a change to a pinned interface and to `a2l_definition.py` (Incs 2/3, closed), with its own E3.

### D-8 — Shared points with Inc 10 (PROPOSED interface I-8.3)

`E1-slice.md` §5. **A (recommended):** Inc 10 yields its export dock from inside `_compose_doc_controls` (`actions.py`), so it never edits `layout.py`; R-TUI-063.1 takes Inc 8's text with Inc 10's insertion; `styles.tcss` hunks stay disjoint. **B:** Inc 10 edits `LayoutMixin.compose` after Inc 8 merges (sequential, one shared function).

### D-9 — Node count at the cap (added at E2)

The graph has 42 prototype nodes against "about 40" (`codewire/graph-inc8.md` §Node count); 72 requirements are under their cap of about 80.
- **A (recommended):** keep one increment. Three of the 42 are one-line helpers (`short_number`, `formula_label`, `kind_word`); a split leaves the operator a sheet that shows values but cannot stage them.
- **B:** split into 8a (layout and the read-only sheet: M1–M3) and 8b (staging: M4–M5), the visible boundary "see" versus "stage". Consequence: two E3/E4/E5 cycles; 8a's sheet ships with a formula bar that cannot stage.

## 4. Interfaces

Consumed, pinned elsewhere, unchanged: **I-2** (`../inc-2/codewire/graph-inc2.md` §Interfaces: `describe_definition`, `describe_definitions`, `decode_definition`, `encode_definition`, `Definition`, `Decoded`, `Encoded`, `Refusal`, `Limits`, `EnumEntry`, and its consumer notes E3A-07/E3S-08, E3S-04a, E3A-25/E3S-19); **I-1** (`OsClipboardInput` for the formula input); **I-4** (the A2L signature `_a2l_enriched_key` that makes the picker repopulate after every A2L change, Inc 5); **I-5** not consumed.

Produced, PROPOSED (pinned in `codewire/graph-inc8.md` §Interfaces, changed only by an orchestrator ruling): **I-8.1** `StagedOverlay(image, entries)`; **I-8.2** `ChangeService._stage_encoded(name, encoded) -> ChangeActionResult` (the Inc 9 seam); **I-8.3** the Inc 10 shared points (D-8); **I-8.4** the `StagingSheet` API (`show_page`, `set_document`, `selected_name`, `select_next`) and its messages `StagingSheet.StageRequested(name, text)`, `StagingSheet.SelectionChanged(name)`; **I-8.5** the three pinned tables `_DETAIL_BY_KIND`, `_EDITABLE_KINDS`, `_FORMULA_LABELS` (the only Inc 8 symbols Inc 9 edits).

**E3R1 (re-pinned per `E3-rulings.md`, text in `codewire/graph-inc8.md` §Interfaces; supersedes the paragraph above where they differ):** **I-8.2** `_stage_encoded(name, encoded, shown) -> ChangeActionResult` — equal span replaces the entry with a bytes entry that keeps the old symbol (E3A-03, E3S-02); `ChangeActionResult.notices` (E3A-10); the stage seam: every stage handler calls `_refuse_if_busy()` first and passes the source view (E3S-03, E3S-01, Inc 9 E-2). **I-8.3** as above plus the E3A-05 ruling (`E1-slice.md` §5). **I-8.4** `show_page(names, definitions, image)` with 0 describes and `A2LParameterPicker.definitions` as the source (E3A-04); `select_after(name)` replaces `select_next` (E3A-07); the row window (E3A-01); `states`, `_paint()` as the one repaint entry, child ids `#patch_sheet_body` / `#patch_sheet_input`, and the overridable methods (Inc 9 C-2); `note_staged(name, advance=True)` (Inc 9 C-8). **I-8.5** one table `_KIND_OPS: dict[str, KindOps]` with `ops_for` and the pinned `_FALLBACK_OPS` (E3A-02); `KindOps.detail(row, preview, width, state, room)` (Inc 9 K-1), optional `cells` and `bar` (K-2, K-3). Inc 9 adds keys only.

## 5. Risks and notes for E3 / E4

- **Tests that pin today's layout:** `tests/test_b100_session_reset.py`, `test_b101_symbol_reads.py`, `test_b102_patch_picker.py`, `test_b103_picker_editor.py`, `test_b103_picker_model.py`, `test_b97_chips_help.py`, `test_b97_flow_execution.py`, `test_b97_patch_editor.py`, `test_b97_width.py`, `test_tui_directionb.py`, `test_tui_patch_big.py`, `test_tui_patch_card.py`, `test_tui_patch_editor_v2.py`, `test_tui_patch_layout.py`, `test_tui_snapshot.py` (+ 2 snapshot SVGs). E4 retargets them; each retarget cites the changed row. *(E3R1, E3A-08: the E1 sentence "`tests/b97_fixtures.py`'s frozen id set loses `patch_tab_a2l`, `patch_win_a2l`, `patch_main`" was wrong — `tests/b97_fixtures.py:95-120` holds none of the three; no edit of the fixture is needed or allowed.)*
- **Approved-design laws in that list: retarget selectors only; assertion unchanged** (E3R1, E3A-08; the E4 testers' briefs carry this list):
  1. `tests/test_b97_patch_editor.py:206-208` (LLR-144.1): `PE_IDS_9C7BEAF` stays a subset with its `Container` types.
  2. TC-B97-32 (`tests/test_b97_chips_help.py:1044-1115`, LLR-148.6): only `PATCH_TABS` (`:1009`) is retargeted (`patch_tab_script` in, `patch_tab_a2l` out); the help rows R-PE-DEF.83 … .87 make it pass.
  3. `tests/test_b97_flow_execution.py:2088-2100`: the stylesheet is append-only except for named supersessions; Inc 8's removal of `#patch_main` and of the A2L-tab rules enters as `supersede(…, "<sha> Inc 8 R-…")` entries; the `startswith` assertion is not edited.
  4. TC-B97-38 (`tests/test_b97_width.py:679-691`, LLR-149.5): the exclusion moves from `#patch_main` to the sheet window and LANDS IN; the no-blank-row assertion stays.
  5. TC-B97-59 (LLR-149.6): unchanged.
  6. The two snapshot SVGs: regenerated only by the canonical CI, never locally (HT-09).
- **Inputs to pilot at E4 (P rows):** that up/down/enter/left/right reach a focusable body `Static` inside the sheet under Windows Terminal (R-PE-DEF.45 … .47); that a real Windows Terminal bracketed paste longer than 4,096 characters leaves the formula text unchanged (R-PE-DEF.42; E3R2, E3S-11: the paste is refused, not truncated); that Escape in the formula input reaches the widget and is not the screen's back action (R-PE-DEF.48).
- **Threads:** describe (≈ 0.13 s per 200-row page on `<runner>`) and decode run on the UI thread at a page change, as the picker's own describe does; under the 0.5 s row R-PE-DEF.12. A larger page is not possible (`PAGE_SIZE = 200`). *E3R1 (E3A-04) supersedes this note:* the cost of a describe follows the A2L's size, not the page's (1 name 0.12 s, 200 names 0.20 s, 3,452 names 0.54 s at 13,990 tags, E3 probe `P1`, load 9.5), and canon R-PICKER-CORRECT.019 forbids describes during filter or page rebuilds. The sheet therefore describes nothing at a page change: it reads `A2LParameterPicker.definitions`, the picker's one describe per population. Decode stays on the UI thread (0.0008 s per 200 rows over a full image). The stage still re-describes its one name per Enter (F-1, ≈ 0.12 s).
- **E3 is due** (SKILL E3): Inc 8 pins I-8.1 … I-8.5, which Inc 9 and Inc 10 use, and its formula input takes operator text.
- **Backlog (E3R1; the orchestrator copies these to PENDING):** (1) E3S-09 "not covered": bidi controls inside A2L words are painted as they are, in the sheet as in every existing A2L view (pre-existing class, no Inc 8 row). (2) E3S-06's probe drove the paste as a posted `events.Paste`; a real Windows Terminal bracketed paste (and the terminal's own cap) is still an E4 pilot item with R-PE-DEF.42. (3) R-PE-DEF.1.2 and R-PE-DEF.60/4 are reachable only through a stand-in until Inc 9 lands (the `-bench` class set by the test; `note_staged(name, advance=False)` called directly): both cases are `partial` until Inc 9's integration re-runs them.
- `add_symbol_entry` / `resolve_symbol_entry` have no product caller after this change either (they had none before): left for the batch-end census (usa/difiere/borra: defer), noted in PENDING by the orchestrator.

## 6. Capture verdicts needed (real Windows Terminal captures, 118×54 and 220×60)

Each element below is visible to the operator and needs a real-capture verdict, batched with Inc 7 and Inc 9 into one review page.

| V | Element | Rows | What the operator judges |
|---|---|---|---|
| V-1 | The whole layout: ribbon, filter row, STAGING SHEET, LANDS IN (4 chips, D-1 A), file row, document row, legend | R-TUI-063.1, .3, .4, .6, R-PE-DEF.1.1, .2, .74 | The fourth chip (Inspector) and the Use row inside it, against the approved three-chip capture. E3R1 (E3A-09): the JSON and Inspector tabs scroll inside 6 content rows at 118×54. |
| V-2 | The filter row (picker filter, status, paging, Include parameter, Add list on one row) | R-PE-DEF.2, R-PICKER-CORRECT.011, .020 | Whether Include and Add list fit on the row at 118 (the capture shows none of them). |
| V-3 | The sheet rows: header, marks `▶ ● ◆`, Current / New / Unit, the limits ruler, Δ texts | R-PE-DEF.5, .15 … .28 | Real I-2 values (DEFC, V171) instead of the prototype's; the Δ percent text. |
| V-4 | The number detail and formula bar: definition line without the layout word, tail `raw … · bytes → bytes  ✓ in limits`, `▲ <notice>`, `✗ <message>` cut with `…` | R-PE-DEF.31, .37, .40, .41 | D-7 A; the long-message cut (E3S-11). |
| V-5 | The enum widget: options line `(●) 2 RUN`, `default "…"`, hint `↔ choose · enter stage` | R-PE-DEF.33, .47 | The real enum (ENUM_0001), not the stand-in. |
| V-6 | The enum widget at 220 columns | R-PE-DEF.33 | Never shown: the approved round's 220 capture is the Workspace (§1). |
| V-7 | The bit-mask widget: bit strip, `word 1A E7 → 1F F7`, mask line, label `field =` | R-PE-DEF.34, .37 | The real masked pair (MASK_FIELD_0001, MASK_BIT_0001), both staged in one word. |
| V-8 | The text widget: `text =`, `+00 41 42 43 00 …` rows, `3/42 chars · NUL-padded` | R-PE-DEF.35, .38, .40 | Text editing was never captured (round 1 and 2 show ASCII rows only). |
| V-9 | A row with no editor (curve, array, refused): `edit <kind word> objects in the Inspector tab`, `refused` | R-PE-DEF.19, .32, .36, .75, .78 | The interim text until Inc 9's benches. E3R1: `<n> values` in Current (E3A-02); a text object over 4,096 bytes has no editor and its rows end in `… <n> more B` (E3S-04, R-PE-DEF.79). |
| V-10 | The narrow layout (< 100 cells: Kind and Unit hidden) at 80×24 | R-PE-DEF.6, .7 | D-6 A; never captured. |
| V-11 | The status lines: `staged as …`, `overlaps the entry at …`, the notice line | R-PE-DEF.55, .57 … .59 | Wording. |
| V-12 | The Patch Editor help section (E3R1, E3A-06) | R-PE-DEF.83 … .87 | The wording of step 1, `Patch script — …`, `STAGING SHEET — …`, `new = / field = / text = — …`, `Use parameter — …`; batched with V-1 (DF-09). |
| V-13 | Inc 9's visible items pinned in Inc 8, **provisional** (E3R1, Inc 9 C-4, C-5) | R-PE-DEF.1.2; CTX-PE-DEF staging sheet subtitle | The sheet subtitle: Inc 8 paints `enter edit · ↑↓ row`, and Inc 9's integrator appends ` · arrays open the bench` when the bench lands (E3R2, E3A-15: Inc 9 C-4 split; still provisional); LANDS IN at 6 rows while a bench is shown. Judged with Inc 9's bench captures (DF-09). |

## 7. Orchestrator rulings

Orchestrator claude-opus-5-5, 2026-11-13T12:43-0600 (from `date`). These rulings override the PROPOSED rows above.

**Not visible to the operator (decided and recorded, DF-02):**

| D | Ruling | Reason |
|---|---|---|
| D-3 | A | One entry per word follows from `CHG-COLLISION`, and the reader accepts the first field's symbol on reload. Option B loses the ledger name and gains nothing. |
| D-4 | B | No new key in Inc 8. The per-field unstage goes to the backlog with the view levels. Adding a key the approved design does not have is "new → defer" (DF-04 c). |
| D-5 | A | Three file groups, four implementers at E4. Each group stays within the 4-source-file cap, and the pure model can be tested without Textual. |
| D-7 | A | No change to the pinned I-2 interface for a cosmetic word. The capture verdict V-4 shows the result. |
| D-8 | A | Inc 10 yields its dock from `_compose_doc_controls` (`actions.py`), so `layout.py` keeps a single writer (DF-10). I-8.3 is pinned as written. |
| D-9 | A | Keep one increment of 42 nodes. Two of the extra nodes are one-line helpers, and the 8a/8b split would ship a sheet that cannot stage. |

**Visible to the operator (provisional, DF-09):**
- D-1 → A, D-2 → A and D-6 → A are **provisional**. E3 and E4 proceed on these options.
- Each one is only final after the operator's real-capture verdict: V-1 for D-1 and D-2, V-10 for D-6. A different verdict reopens the rows that depend on it.
- D-1 A keeps every approved feature reachable. B would silently withdraw about 20 canon rows that the verdict never asked to remove (DF-04).

**Interfaces:** I-8.1, I-8.2, I-8.4 and I-8.5 are pinned as written in `codewire/graph-inc8.md`. I-8.3 is pinned per D-8.

**E3 is due** on the shared interfaces (DF-03): one architecture and security review pass.

**Inc 9 seam:** Inc 9 only adds functions, modules and keys of the I-8.5 tables, so Inc 9's E1/E2 may run in parallel with Inc 8's E3/E4.

**Base:** before E4, `b103-inc8` is rebased onto the final `b103-pe-split` tip (the test retargets after `91d5ae56`).

**Notes for the batch close and PENDING:**
- `add_symbol_entry` / `resolve_symbol_entry` have no product caller (defer, census at batch end).
- The E2 layered extraction against the Inc 2 and Inc 6 graphs did not run, because those graphs predate the package paths.
