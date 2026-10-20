# Requirements Document — s19_app — Batch 2026-10-19-batch-97

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
The live requirements contract for batch-97: it ports the operator-approved prototype round
`prototypes/b94_polish/` (verdict **A on all four screens**) into the four batch-94 panels
(Patch Editor, Check Editor, Flow Builder, Flow Execution). It derives HLR-144..HLR-149 from
the six READY stories US-134..US-139 and their LLRs, and declares the acceptance tests
(`AT-B97-NN`), the white-box tests (`TC-B97-NN`) and the Information Flow Contract.

### 1.2 Scope
**In:** the re-composition of `PatchEditorPanel`, `CheckEditorPanel`, `FlowBuilderPanel` and
`FlowExecutionPanel` at their shipped widget ids; the Patch Editor's JSON tab fed from the
editor's document; the open-folder chip and the help chip on all four screens (two new chip
families, `flows` and `session`); the CRC token and the waiting hue chosen as a pair at PDR; English UI
strings on the four screens, including the seven `flow_execution_service.py` strings that paint on
the two flow screens (§2.7 P-17); keyboard reachability and region states on the four screens;
width-adaptive layouts at any size from 118x54 up (samples 118x54, 160x56, 220x60, 260x70) with no
wrapped rows, the shipped 80x24 floor kept reachable under scroll; markup safety (C-17) for every
render of file-derived text on the four screens.
**Out:** the items listed under "Not taken in" in §2.6; run semantics, persistence formats and
the batch-96 waiting-human doctrine itself; chips and help on any other screen.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| ledger | a full-height table that lists the screen's records one per row (entries, A2L parameters) |
| inspector | the right-hand column that shows the highlighted ledger row and the tab chips |
| pipeline rail | one horizontal row of block cards joined by cable glyphs (fb_A / fx_A) |
| cable status glyph | the glyph painted on the cable after block *i*: `▓` ok · `░` not run · `✗` error · `◇` notices · `□` waiting (§4 LLR-147.1 truth table) |
| horizontal overflow | a displayed descendant of a panel whose painted region extends past the panel's region on the x axis (measured by `widget.region`, C-32) |
| wrapped row | one logical ledger/log line painted on more than one terminal row |
| 118x54 / 220x60 | the minimum and the large reference terminal sizes (operator, handoff §1); "the range" = every width ≥ 118 and height ≥ 54 |
| shipped id | a literal `id="…"` a panel's `compose` yields on `main` at `9c7beaf` |
| filled element | a `Button` whose `variant == "primary"` or a widget painted with a background fill of the accent set (named at PDR) |
| waiting hue / CRC hue | the two colours PDR chooses as a pair (§6.2 item 7); "waiting-human elements" = the waiting card, the cable into it, `#fx_confirm_<i>`, the paused lane's status text |
| painted extent | the rightmost terminal column, inside a region, whose painted cell is not blank (read from the compositor's strips, C-32) |
| no-wrap set | the ledger rows, run-log lines, pipeline rows, identity ribbons, legends, inspector headings and REPORT FIELDS lines of a panel |
| focus order | the order of `app.screen.focus_chain` restricted to the panel's ids and its header chips |

### 1.4 References
- Brief: `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md` (§1 verdict, §3 R-1..R-9, §4, §5).
- ARQ: `docs/architecture.md` §"Batch-97 declarations — the b94 polish port" (I-1..I-4, R13-R17, open questions).
- Prototype evidence (design intent, never imported): `prototypes/b94_polish/variants/{pe_A,ce_A,fb_A,fx_A}.py`, `NOTES.editors.md`, `NOTES.flows.md`, `png/`.
- Project rules: `docs/engineering-rules.md` (C-13, C-13.1, C-23, C-29, C-32, C-34, C-37, C-42; AT/TC id routing).
- Standards: ISO/IEC/IEEE 29148:2018; EARS.

### 1.5 Document overview
§2 context, stories (§2.6, P0), premises (§2.7), fork preconditions (§2.8); §3 one HLR per story
with its acceptance block; §4 LLRs and the Information Flow Contract; §5 the two-layer validation
strategy; §6 design decisions deferred to PDR and open risks. The ledger is
`01-requirements-ledger.md`.

---

## 2. Overall description

### 2.1 Product perspective
s19_app is a Textual TUI over S19/HEX images, A2L files and change-sets. Batch-94 shipped the four
panels; this batch changes their layout and four seams named by ARQ (I-1 chip families, I-2/I-3
the Patch Editor's identity + JSON feed, I-4 the help keys). No module is created and no boundary
moves (ARQ: A1, B2 not fired).

### 2.2 Product functions
Patch Editor ledger + inspector with a consultable JSON tab · Check Editor ledger + report-fields
card · Flow Builder pipeline rail with a contextual add form · Flow Execution per-lane pipeline
with cable status · folder + help chips on the four screens · width-adaptive layouts.

### 2.3 User characteristics
The calibration engineer (change-sets, check specs) and the engineer composing and running flows;
both read dense terminal UIs daily and scale the terminal to taste. New users are named by the
operator as the beneficiaries of the folder chips.

**Environment:** Windows terminal, keyboard and mouse both in use (every task reachable by
keyboard alone, LLR-144.10/145.8/146.13/147.11); 24-bit colour assumed for the visual half. Under
`NO_COLOR` the colour cues degrade: the hex strip's changed bytes keep a text attribute (LLR-144.8),
the cable glyphs and marks are characters, so the meaning survives; hue claims (LLR-146.6, 147.7)
are judged on the 24-bit captures only — **inspected, not exercised** for their visual half (§5.1).

### 2.4 Constraints
- At most **4 source files per increment** (tests uncapped) — the operator's global budget.
- **English** for every string the four screens paint (R-9); Spanish only in chat.
- **Nothing promoted from `prototypes/`** — the variants are re-composed in `s19_app/`, never imported (ARQ: the `prototypes/**` boundary).
- Size regimes: **118x54 minimum** for the no-overflow and primary-actions properties, **220x60 large reference**; widths derived from the available width, never fixed to 118. The shipped **80x24 floor is kept**: below 118x54 the four screens stay reachable under scroll (LLR-007.1 / CV-04 not superseded, LLR-149.6). The shipped `width-narrow` breakpoint (`app.py:7475` `narrow = width < 120`) falls inside the range, so 118 and 119 are narrow and 120 up is wide (LLR-149.2 boundary arm).
- Increment budget pressure: Q-2 brings `services/flow_execution_service.py` into the Flow Execution increment and R16 puts `insight_style.py` in Inc 3/4 — the cut is re-made at PDR (02-review A-14, carried).
- Python 3.11, Textual 8.2.8 (`pyproject.toml:73` pins `textual==8.2.8`; `textual.__version__` → `8.2.8`, executed 2026-10-20).
- The no-apply doctrine of `.chk.json` (`PDR-2026-10-12-batch-94#D2`) and the batch-96 waiting-human doctrine stay as they are.
- Ids: batch-scoped `AT-B97-NN` / `TC-B97-NN` (`docs/engineering-rules.md:48`), no registry reservation.

### 2.5 Assumptions and dependencies
Every assumption the contract relies on is a row of §2.7 with executed evidence. Acceptance
fixtures use the tracked `examples/case_00_public/ASAP2_Demo_V161.a2l` and `prg.s19` (byte-identical
to the demo's `calib.a2l` / `fw_app.s19`, §2.7 P-24) and generate every JSON fixture (change-sets,
`.chk.json`, flows, sets) in `tmp_path` with the current serialisers (§5.3).

### 2.6 Source user stories

Source for every story: the operator-approved prototype round `prototypes/b94_polish/` (verdict
`veredicto-b94-polish.md`, final section: **A on all four screens**, confirmed in chat 2026-10-19
"Sí, cambié de opinión") and its implementation brief `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md`
(§1 verdict, §3 R-1..R-9). The handoff file carries the next calendar day in its name (written
past midnight UTC); the batch dates are local days.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-134 | As the calibration engineer editing a change-set, I want the Patch Editor as a full-height entries ledger beside an inspector (before→after hex strip, labelled entry form, chips) whose JSON tab shows the current document on demand, so that I see my whole document and can consult the JSON without a permanently empty panel. | verdict pe_A + the operator's JSON condition (handoff R-1) | READY |
| US-135 | As the calibration engineer assembling a check spec, I want the Check Editor as a full-height A2L parameter ledger with the address always visible beside a report-fields card (fields / JSON / addendum tabs), with Validate and Write on one docked row, so that I pick parameters by address and see what the report will hold. | verdict ce_A (handoff R-2) | READY |
| US-136 | As the engineer composing a flow, I want the Flow Builder as one horizontal pipeline of block cards joined by cables, with a contextual add form showing only the inputs the chosen kind needs and Run reachable without scrolling, so that the chain reads as one object and no input runs off screen. | verdict fb_A (handoff R-3, R-5) | READY |
| US-137 | As the engineer running flow sets, I want Flow Execution as one pipeline per lane with each cable carrying its block's run status, the rebind input inside the source card, the batch-96 waiting-human doctrine kept, and an English run log, so that I read a whole set's state at a glance and know exactly which lane waits for me. | verdict fx_A (handoff R-4, R-5) | READY |
| US-138 | As an engineer new to the tool, I want every one of the four screens to carry a visible open-folder chip for the folder its files live in and a help chip whose entry names every control and glyph on that screen, so that I never guess where files are or what a mark means. | operator round-2 answer: "es un problema adivinar y buscarlos, sobre todo para usuarios nuevos"; verdict note: "No olvides las leyendas y ayudas en cada ventana" (handoff R-6, R-7) | READY |
| US-139 | As an engineer who scales the terminal to taste (≈220x60, variable), I want the four screens to use the width they get — no horizontal overflow at 118x54, no half-screen voids from fixed widths at 220x60, and no row ever wrapping onto a second line — so that information density follows the window. | operator round-2 answer + the 220x60 pass (handoff R-8) | READY |

**Ledger pairing:** stories live in this table (the batch-91 shape); the P1 derivation entry in the
ledger names the HLR/LLR they trace to.

#### Refinement log (one block per story)

**US-134 — Patch Editor ledger + inspector, consultable JSON**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the calibration engineer · outcome = entries table full height beside an inspector with tabs Inspector / JSON / Checks; the JSON tab shows the document the editor holds (after Load and after edits); Load from the patches folder keeps populating table + tab · why = the baseline shows 2 of 6 rows and a ~40-row empty JSON frame (handoff §5 E-6: the JSON editor never receives the loaded document) · out of scope = a new change-set format, apply semantics.
- **Feasibility (E, S):** path = re-compose `PatchEditorPanel` at its shipped ids, remove the double geometry work (handoff §5 E-1..E-3), feed the JSON view from the editor state · unknowns = live refresh vs an explicit `Update JSON` action — the operator accepts either; decided at PDR with its reason · fits one batch? = yes (one increment).
- **Evaluability (T):** "When the engineer loads `calib_hotfix.json` from the patches folder and opens the JSON tab, the user observes that document's entries in the tab and all six rows in the ledger; after adding an entry, the tab shows the new entry (live, or after `Update JSON` with its stamp)."
- **Open questions:** live vs explicit refresh — a design-step decision, not a DoR blocker (operator: "No se si se pueda actualizar en tiempo real o poner algún botón").
- **Classification:** `READY`.

**US-135 — Check Editor ledger + inspector**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the calibration engineer · outcome = parameter table full height, Address never truncated; REPORT FIELDS card with Fields / JSON / Addendum tabs; one docked row Validate · Write .chk.json · struck APPLY ghost (the no-apply doctrine stays) · why = baseline Address truncated to one glyph, a 9-item unranked right column · out of scope = the `Fmt · Unit` column of ce_C (offered, not chosen).
- **Feasibility (E, S):** path = re-compose `CheckEditorPanel` at its ids; the 1-row chip shape the Patch Editor already has · unknowns = none blocking · fits one batch? = yes.
- **Evaluability (T):** "When the engineer opens the Check Editor with `calib.a2l` loaded, the user observes every visible row's address in full at 118x54, and the field count on the docked row changes when a parameter is included."
- **Open questions:** none.
- **Classification:** `READY`.

**US-136 — Flow Builder pipeline rail**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer composing a flow · outcome = one pipeline of cards with cables; kind chip strip + only the chosen kind's inputs (EXT-STEP on two measured rows); copy/paste strip; `Variables (n)` chip; foot Run · Clear · Save… · Load… with Run the second bright element; CRC accent burnt orange · why = baseline Run below the fold, a wrapped canvas band, a duplicated numbered list, a surviving variant-scope selector · out of scope = a new block kind, flow model or persistence changes.
- **Feasibility (E, S):** path = re-compose `FlowBuilderPanel`; the six-kind palette is already accepted by the shipped handler (handoff §5 F-5); fb_A hides the grid canvas, so `_CANVAS_COLS` (F-2/F-3) matters only if the canvas stays reachable — decided at PDR · fits one batch? = yes.
- **Evaluability (T):** "When the engineer opens the Builder with `patch_chain` loaded at 118x54, the user observes all four cards joined by cables on one row and the Run chip on screen without scrolling; selecting EXT-STEP shows its command, log and output inputs, and pressing Add appends the card."
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-137 — Flow Execution pipeline rail**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer running a set · outcome = per-lane pipeline; status glyph on each cable; rebind input in the SOURCE card; paused lane = amber card + `□` cable + two red pending lines + Confirm inside the lane + `log + output file: REQUIRED`; two-row header without overflow; English run log · why = baseline set row overflows (Save/Load Set off screen), ~13 dead rows, a detached rebind input, a 70-cell mode selector · out of scope = run semantics and the waiting-human doctrine itself (batch-96, kept as is).
- **Feasibility (E, S):** path = re-compose `FlowExecutionPanel`; per-block status from the retained record (handoff §5 F-8) · unknowns = `render_run` assumes outcome i belongs to lane i (F-8) — confirmed at PDR · fits one batch? = yes.
- **Evaluability (T):** "When the engineer runs `flash_q4`, the user observes the first lane's cables marked done, the second lane paused at block 3 with its Confirm in the lane row, and the run log's lines in English."
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-138 — open-folder chip + help chip on the four screens**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the new engineer · outcome = Patch Editor (`patch`, shipped), Check Editor (`checks`, shipped family), Flow Builder (`flows`, new family = the project's flows folder), Flow Execution (`session`, new family = the session dir) each carry the chip, dimmed with no project as the shipped chips are; each carries a help chip whose entry names every control, tab and glyph · why = the operator's round-2 answer (quoted in the table) · out of scope = chips on other screens (the all-screens review), the batch-96 `d`-key help follow-up.
- **Feasibility (E, S):** path = two families through `folder_open_service` (`CHIP_FAMILY_*` at `s19_app/tui/services/folder_open_service.py:57-60`; the flows folder is `project_dir / FLOWS_SUBDIR`, `flow_persistence_service.py:973`) and `titled_header` for the two bare headers (the Check Editor's `Label`, Flow Execution's `titled_header` with no chip, both in `app.py`) · fits one batch? = yes.
- **Evaluability (T):** "When a project is open, pressing the Flow Builder's folder chip opens the project's flows folder; with no project the chip is dimmed; pressing each screen's help chip shows an entry that names that screen's controls."
- **Open questions:** none.
- **Classification:** `READY`.

**US-139 — width-adaptive layouts, no wrapped rows**
- **INVEST:** I ✗ (cuts across US-134..137) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer at variable sizes · outcome = column widths and panel splits derived from the available width at mount and on resize; 118x54 = no horizontal overflow, Run / Validate / document controls on screen; ≈220x60 = no half-screen void caused by a fixed width; no table / ledger / log row wraps · why = the 220x60 pass (review page §7): fixed 118 widths in every chosen variant and in main · out of scope = the hex-viewer no-wrap rule on A2L viewer / Hex View (routed to the backlog for the all-screens review).
- **Feasibility (E, S):** path = each screen increment derives its own widths; a final sweep increment measures both sizes · fits one batch? = yes.
- **Evaluability (T):** "When each of the four screens renders at 118x54 and at 220x60, the user observes no horizontal scrollbar, every ledger row on one line, and the primary action on screen."
- **Open questions:** none. Not Independent by nature (a quality bar over the other four); kept as its own story so its acceptance is one node per size, not four buried clauses.
- **Classification:** `READY`.

**Not taken in (OUT, with where it lives):** the `Fmt · Unit` column of ce_C as a layout choice and the matrix density mode (fx_C) — offered by the prototyping session, not chosen by the operator (ce_A's own `Fmt · Unit` column stays, LLR-149.4); the hex-viewer no-wrap rule outside these four screens — `.dev-flow/BACKLOG-CODE.md:1393` (P2, origin A-15); bidi/zero-width controls through `safe_text` — `BACKLOG-CODE.md:1394` (S-6); the footer key bar — `BACKLOG-CODE.md:1395` (U-17); a loading state on the two editors — OUT: Load, Validate and Write run synchronously on the UI thread, so no region shows a partial load (the running state of Flow Execution is in, LLR-148.9); the eight Code-Wire pilot findings — already in `BACKLOG-CODE.md` (`51ee191`), a separate lane; the batch-96 follow-ups — untouched.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

Probes executed 2026-10-20 on `main` at `9c7beaf` (`git rev-parse --short HEAD`), `git status --short s19_app/` → 0 lines. The two probe drivers run the REAL tree through the harness's scenarios (`run_real._APP_COPY` repointed to the repository root): `probe_b97.py` / `probe_overflow.py` (session scratch; their outputs are pasted below, which is the evidence).

| # | Premise, as a truth-apt proposition | Tier (axiom · hypothesis · premise) | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| P-1 | The shipped `PatchEditorPanel` (`screens_directionb.py:4383-6861`, the `ClassDef` span) yields 66 literal widget ids; 65 are reached from outside the panel. | premise | ✅ TRUE | `git show 9c7beaf:s19_app/tui/screens_directionb.py` → AST `ClassDef` span + `re.findall(r'\bid=f?"([^"{]+)"')` → `PatchEditorPanel 4383 6861 66`; set identical to the QA probe's `pe_ids.txt` (`diff` empty). Reach grep: `65/66` (only `patch_win_json_dock_spacer` unreached). Frozen literal: §5.3 `PE_IDS_9C7BEAF` | LLR-144.1 keys on this frozen set |
| P-2 | The shipped `CheckEditorPanel` (`:6864-7551`) yields 31 literal ids; 14 are reached from outside. | premise | ✅ TRUE | same AST probe → `CheckEditorPanel 6864 7551 31`; frozen literal §5.3 `CE_IDS_9C7BEAF`; reach `14/31` | LLR-145.1 keys on this frozen set |
| P-3 | `FlowBuilderPanel` (`flow_screens.py:502-1799`) yields 39 literal ids + the computed `flow_palette_{kind}`; `FlowExecutionPanel` (`:1874-2693`) 23 ids, 6 of them computed (`fx_lane_{i}`, `fx_confirm_{i}`, `fx_in_{i}_{j}`, …). | premise | ✅ TRUE | same census: `39 literal ids … 31/39 reached`; `23 literal ids … 12/23 reached` | LLR-146.1 / LLR-147.1 |
| P-4 | After Load of `calib_hotfix.json` the JSON editor still holds the dummy template, not the document (E-6). | premise | ✅ TRUE | `probe_b97.py patch-editor 118x54` → `service entries 6 source calib_hotfix.json` · `json buffer == DUMMY True address-keys in buffer 2` | the RED side of AT-B97-01 / TC-B97-05 |
| P-5 | The canonical serialiser emits the loaded document with all six entries. | premise | ✅ TRUE | `ChangeService().load(str(p), dir)` + `serialize_change_document(doc)` → `type: bytes bytes: 706 lines: 39`; emitted head `{` / `"format": "s19app-changeset",` / … / `"address": "0xEB10",`; `addresses: ['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']` | predicates parse the JSON (C-42), never substring-match it |
| P-6 | `ChangeService.document` has exactly nine writers: `undo` `:861`, `redo` `:893`, `add_entry` `:1080`, `add_symbol_entry` `:1154`, `edit_entry` `:1196`, `remove_entry` `:1223` (`del`), `edit_entry_json` `:1344`, `load` `:1404`, `load_text` `:1465`; eight have an app caller, `add_symbol_entry` has none. | premise | ✅ TRUE | `grep -nE "self\.document\s*=[^=]|self\.document\.entries\.(append|…)|self\.document\.entries\[[^]]*\]\s*=|del self\.document\.entries"` over `change_service.py` → the nine sites, enclosing `def` read per site; `grep -rnE "\.document\s*=[^=]" s19_app/` outside them → none; app callers `app.py:3152` add, `:3157` edit, `:3162` remove, `:3177` load_text (paste-parse), `:3589` undo, `:3615` redo, `:3823` edit_entry_json, Load via `_patch_editor_load_tail`; `grep -rn add_symbol_entry s19_app` → definition and docstrings only (0 callers) | LLR-144.6 quantifies over these nine |
| P-7 | The shipped panels add their table columns exactly once; the brief's "columns added a second time" (E-1) was an artefact of the prototype's MRO-dispatched `on_mount`, not a shipped defect. | premise | ✅ TRUE | `probe_b97.py patch-editor` → `table columns 5 ['Kind', 'Address', 'Value / bytes', 'Status', 'Linkage']`; `add_columns` sites: `screens_directionb.py:5613` (one per panel), `:7365`, `:7368`; `prototypes/b94_polish/NOTES.editors.md:17-22` names the subclass+base dispatch | LLR-144.3 targets the real double work (forced heights/widths, three geometry call sites) and pins `len(columns) == 5` |
| P-8 | `_apply_window_geometry` has three call sites — `on_resize` (`screens_directionb.py:5596`), `on_mount` (`:5656`), the show path (`app.py:6978`) — and no test references it; `on_mount` forces `table.styles.height = 3` (`:5616`), select width 30 (`:5638`), path width 28 (`:5641`). | premise | ✅ TRUE | `grep -c _apply_window_geometry` → `app.py:1`, `screens_directionb.py:7` (def + docstrings + 2 calls); `grep -rln _apply_window_geometry tests/` → empty | LLR-144.3 |
| P-9 | The E-3 rules exist in `styles.tcss`: `#patch_win_script { width: 2fr }` (`:1117-1118`), `#patch_doc_entries_table { height: 10 }` (`:1536-1538`), `layout: grid` on `#patch_doc_entry_buttons` (`:1160-1168`) and `#patch_doc_controls` (`:1581-1584`). | premise | ✅ TRUE | `grep -n` over `s19_app/tui/styles.tcss` (output above) | LLR-144.4 |
| P-10 | Today every one of the four screens overflows horizontally at both sizes. | premise | ✅ TRUE | `probe_overflow.py` (displayed descendants with `region.right > panel.right`): 118x54 → patch 1 (`patch_script_section_label`), check 1 (`check_apply_ghost x=95 w=54`), builder 2 (`flow_help`, `flow_clip_status`), execution 7 (`fx_help`, `fx_save x=117`, `fx_set_select`, …, `fx_load x=134`); 220x60 → 1 / 1 / 1 / 6. `panel.max_scroll_x` reads 0 on three of them (clip, not scroll — the C-32 trap) | the RED side of LLR-149.2 |
| P-11 | At 118x54 the Builder's Run and the Execution's Save Set / Load Set are outside the panel viewport at scroll 0; the editors' primary actions are inside. | premise | ✅ TRUE | `probe_overflow.py`: panel `(5,4,112,40)` (bottom 44); `#flow_run (51,42,16,3)` → False; ext scenario `#flow_run (51,49,16,3)` → False; `#fx_save (117,10,16,3)` False; `#fx_load (134,10,16,3)` False; `#patch_doc_*` and `#check_validate_button`/`#check_write_button` → True. Re-measured (`p1r2/geo.py`, ext scenario): `flow_panel (5, 4, 112, 40) flow_run (51, 48, 16, 3)` — y = 48 | LLR-149.3 |
| P-12 | At 118x54 the Check Editor's Address column is clipped: column render widths `3+49+12+15 = 79` in a 56-cell table, `max_scroll_x 25`; at 220x60 the table is 98 cells and `max_scroll_x 0`. | premise | ✅ TRUE | `probe_b97.py check-editor`: `param table region (5, 8, 56, 40) rows 75 scroll_x max 25`; columns `'Parameter' content_width 47 get_render_width 49`, `'Address' content_width 10 get_render_width 12`; at 220x60 `region (23, 8, 98, 46) … scroll_x max 0` | LLR-145.2 / LLR-145.3 |
| P-13 | The Builder palette offers 4 kinds (`flow_palette_patch/crc/a2b/external_step`) while `_KIND_OPTIONS` lists 7 placeable kinds; the handler accepts any `flow_palette_<kind>`. | premise | ✅ TRUE | probe `palette ids ['flow_palette_patch', 'flow_palette_crc', 'flow_palette_a2b', 'flow_palette_external_step']`; `flow_screens.py:542-551` (7 kinds); `:1455-1461` (`removeprefix("flow_palette_")` → `#flow_kind`) | LLR-146.2 (the brief's "six" is stale: batch-96 added EXT-STEP) |
| P-14 | `_plc_block` paints a block's IO text without clipping it to the block width (F-1). | premise | ✅ TRUE | `flow_screens.py:440` builds `left` from the whole `text_`; `:443` `g.put(x + 6, yy, text_, tstyle)` — no slice to `w` | LLR-146.4 |
| P-15 | The retained run record carries per-block status, and outcome *i* belongs to lane *i* (F-8). | premise | ✅ TRUE | writer census of `record.outcomes`: `flow_execution_service.py:1546` (`pool.map`, submission order) and `:1548` (sequential append) only; `app.py:2806-2813` builds `chains` from `event.lanes` in lane order. Executed: `probe_b97.py flow-execution-paused` → `outcome[0] chain=patch_chain … blocks=0:ok,1:ok,2:notices,3:ok` · `outcome[1] chain=flash_chain status=paused blocks=0:ok,1:ok,2:waiting,3:skipped` | LLR-147.1 needs no record change (no A3 on the service) |
| P-16 | No CRC family colour ships; the waiting state paints `YELLOW #f6ff8f`, the hex warnings and the dirty strip also use; no demo flow contains a CRC block. | premise | ✅ TRUE | `flow_screens.py:1800` `_S_PAUSE = "bold " + YELLOW`; `insight_style.py:64` `YELLOW = "#f6ff8f"`; `grep crc` near a colour in `flow_screens.py` → none; demo flow kinds: `flash_chain ['source','patch','external_step','write_out']`, `patch_chain ['source','patch','check','write_out']`, `release_diff ['source','patch','a2b','write_out']` | LLR-146.6; the CRC-beside-paused AT uses a NEW fixture |
| P-17 | With the committed marker regex `ES_MARKER` (§5.3), the painted Spanish census on `9c7beaf` is 42 non-docstring string constants: 25 in the `FlowBuilderPanel` `ClassDef`, 9 in the `FlowExecutionPanel` `ClassDef`, 1 module constant `flow_screens.py:235` (`'PAUSED - ESPERANDO HUMANO'`), 7 in `services/flow_execution_service.py` (`:501, :846 ×2, :860, :867 ×2, :885` — the external-step summary/diagnostic lines both flow screens paint); 0 in `PatchEditorPanel`, `CheckEditorPanel`, `window_help.py`. 14 assert lines pin them. | premise | ✅ TRUE | `p1r2/es.py 9c7beaf` (AST keyed on `ClassDef` nodes, docstrings excluded) → `FlowBuilderPanel 25`, `FlowExecutionPanel 9`, whole `flow_screens.py 35`, `PatchEditorPanel 0`, `CheckEditorPanel 0`, `flow_execution_service.py 7`, `window_help.py 0`; identical on `bc4fbd3` (no `s19_app/` diff). Pin census (`p1r2/pins.py` + read): `test_flow_external_step_b96.py:265, 266, 302, 333, 345, 422, 425, 507, 508, 509, 514`; `test_flow_funnel_b96.py:331, 475, 477` | LLR-146.7 / LLR-147.5 |
| P-18 | Chip families: 4 (`folder_open_service.py:57-60`, `CHIP_FAMILIES :64`); the no-project status `REPORTS_NO_PROJECT_REASON` (`:78`) names Reports and `open_folder_chip.py:115`/`:160` emit it for any `None` target; flows live at `project_dir / FLOWS_SUBDIR` (`flow_persistence_service.py:95`, `:973`); the session dir pushed to the flow panels is the active project dir (`app.py:8130-8137`). | premise | ✅ TRUE | `grep -n` outputs above | LLR-148.1..148.3 |
| P-19 | A Check Editor chip of family `checks` would carry the id `open_folder_checks`, which the Checks screen already mounts. | premise | ✅ TRUE | `open_folder_chip.py:77` `id=f"open_folder_{family}"`; `app.py:2321` `OpenFolderChip("checks")`; `tests/test_open_folder_chips.py:94-98` `_RAIL_CHIPS` addresses `#open_folder_checks` | LLR-148.4 (scoping decided at PDR) |
| P-20 | `SHIPPED_WINDOW_KEYS` holds 8 keys (`window_help.py:270-279`) and `tests/test_window_usage_help.py:250` asserts set equality; no Check Editor or Flow Execution section exists; the Check Editor header is a bare `Label` (`app.py:3082`) and Flow Execution's `titled_header` has neither chip (`app.py:2438`). | premise | ✅ TRUE | `grep -n` / `sed -n` outputs above | LLR-148.5 / LLR-148.6 |
| P-21 | Today's help entries name few of the buttons their panel renders. | premise | ✅ TRUE | help probe at 118x54 (button labels in the panel vs `section_body_text`): `#patch_editor_panel … buttons=19 named-in-help=6`; `#check_editor_panel … key=None buttons=6 named-in-help=0`; `#flow_panel … buttons=13 named-in-help=2`; `#fx_panel … key=None buttons=4 named-in-help=0` | the RED side of LLR-148.6 |
| P-22 | The EXT-STEP inputs are fixed-width: 28 / 26 / 28 cells at both 118x54 and 220x60. | premise | ✅ TRUE | `probe_b97.py flow-builder-ext`: `#flow_ext_instruction … (31, 13, 28, 3)` / `(49, 13, 28, 3)`; `#flow_ext_log` 26 / 26; `#flow_ext_output` 28 / 28 | the RED side of LLR-149.1 |
| P-23 | Textual's pilot can resize the terminal inside one session. | premise | ✅ TRUE | `python -c "… Pilot.resize_terminal"` → `8.2.8 True (self, width: 'int', height: 'int') -> 'None'` | AT-B97-15 drives the real resize |
| P-24 | The demo's binary fixtures are byte-identical to tracked examples; its JSON fixtures are serialiser output, regenerable in `tmp_path`. | premise | ✅ TRUE | `diff -q polishdemo/calib.a2l examples/case_00_public/ASAP2_Demo_V161.a2l` → same; `cmp polishdemo/fw_app.s19 examples/case_00_public/prg.s19` → same; both tracked (`git ls-files`); `prg.s19` 133 records `0x17e0..0x10000`; `parse_a2l_file(ASAP2_Demo_V161.a2l)` → `tags 75 with int address 75`, `longest name 47 ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE` | §5.3 fixture table |
| P-25 | The batch-77 hostile payload already reaches the Check Editor as an A2L symbol name in a shipped AT, so a file-derived injection path exists. | axiom | ✅ TRUE | `tests/test_tui_check_editor.py:52-56` (`_HOSTILE`), `:433` `test_at_b94_13_hostile_symbol_and_file_name` | the C-17 ATs reuse the payload and add `[bold]`, `[/]`, `[link=…]` |
| P-26 | The only snapshot cells rendering a batch-97 screen are the two `patch` cells (80x24, 120x30). | premise | ✅ TRUE | `ls tests/__snapshots__/test_tui_snapshot \| grep -ci patch` → `2`; `_SCAFFOLD_SCREENS = ["map", "patch", "diff"]` (`tests/test_tui_snapshot.py:110`) | C-22 upper bound: ≤ 2 drifting cells, Inc 2; both cells are already `xfail(strict=False)`, so the bound cannot go RED — carried to P3 (02-review Q-18) |
| P-27 | On Windows a file name may carry `[bold]`, `[red]`, `[link=e]` and `[@click=app.quit]`, but not `[/]`, `https://` or C0 bytes. | premise | ✅ TRUE | `p1r2/fname.py` in a temp dir: `'b97[bold]x[red]y[link=e]z[@click=app.quit]w.json' OK`; `'b97[bold]x[/]y.json' FileNotFoundError`; `'b97[link=https://e]x.json' OSError [Errno 22]`; `'b97\x01x.json' OSError [Errno 22]` | §5.3 `HOSTILE_NAME` / `HOSTILE_CONTENT` split (Q-1) |
| P-28 | The A2L parser admits the full bracket payload, including `[/]`, `https://` and a C0 byte, as a CHARACTERISTIC name with an integer address. | premise | ✅ TRUE | `p1r2/a2l.py`: the first CHARACTERISTIC of `ASAP2_Demo_V161.a2l` renamed → `'b97[bold]x[/]y' admitted … int-addr: [True]`; `'b97[link=https://e.invalid]l[/link]' admitted … [True]`; `'b97\x07bel' admitted … [True]` | LLR-145.5 rides the A2L name (no fallback needed) |
| P-29 | A v2 change-set admits the full payload (with C0 bytes) as a `string` entry's `value`; a payload `symbol` is refused with a finding that echoes it. | premise | ✅ TRUE | `p1r2/hostile_doc2.py` → `value_brackets entries 1`, `value_c0 entries 1`; `symbol_brackets entries 0 … ["entry 0: the symbol 'b97[bold]x[/]y[red]z[link=https://e.invalid]l[/link][@click=app.quit]…"]` | LLR-144.7 content arms: ledger, inspector, JSON tab, issues line |
| P-30 | A flow file admits the NUL-free payload in an EXT-STEP `instruction`, `log_ref` and a patch block's `change_doc_ref`; a payload flow `name` is refused (`FLOW-BAD-FIELD`). | premise | ✅ TRUE | `p1r2/hostile_flow.py` → `name loaded False findings ["ValidationIssue(code='FLOW-BAD-FIELD'…"]`; `ext_instruction loaded True`; `ext_log loaded True`; `patch_ref loaded True` | LLR-146.8 / LLR-147.6 arms; lane names carry the file-name subset (P-27). NUL excluded: 02-review Q-13 |
| P-31 | A deterministic error lane exists: `patch_chain` with its patch block pointed at a change-set whose one entry lies past the image end runs to `error` at block 1. | premise | ✅ TRUE | `p1r2/geo.py` (3 lanes, sequential, 118x54) → `outcome 0 completed-with-issues ['ok','ok','notices','ok']`; `outcome 1 paused ['ok','ok','waiting','skipped']`; `outcome 2 error ['ok','error','skipped','skipped']` (entry `0x00020000`, image ends `0x10000`) | §5.3 `err_chain` |
| P-32 | Blank painted rows outside each screen's growing region today: Patch 3 (118x54) / 2 (220x60) outside the ledger; Check 0 / 0 outside the parameter table; Execution 3 / 3 outside `#fx_lanes_scroll` and 9 / 16 blank rows inside it with two lanes after a run. | premise | ✅ TRUE | `p1r2/geo2.py` (compositor strips, `render_strips()`, row blank ⇔ `line[panel.x:panel.right].strip() == ""`) | LLR-147.8 / LLR-149.5 RED sides; Check 0 is a pin |
| P-33 | Today's focus chains: Patch 40 ids (help + folder chips, then 26 panel ids, no tab chip); Check 27 (no header chip); Builder reaches `window_help_flow`, the 4 palette chips, `flow_scope`, `flow_run`; Execution reaches `fx_import … fx_load`, `fx_confirm_1` after the lane inputs. | premise | ✅ TRUE | `p1r2/geo.py` → `focus chain patch 40 [... 'window_help_patch', 'open_folder_patch', 'patch_editor_panel', …]`, `check_editor 27`, flow `[… 'window_help_flow', 'flow_panel', 'flow_palette_patch', … 'flow_scope', 'flow_run']`, fx `[… 'fx_import', 'fx_mode', 'fx_run', 'fx_set_name', 'fx_save', 'fx_set_select', 'fx_load', 'fx_lanes_scroll', 'fx_in_0_0', …, 'fx_confirm_1', …]` | LLR-144.10 / 145.8 / 146.13 / 147.11 |
| P-34 | Python 3.11 has no `os.path.isjunction`; a junction reports `is_dir() True`, `is_symlink() False` and the reparse-point attribute set. | premise | ✅ TRUE | `3.11.15 False 1024`; `_winapi.CreateJunction` → `junction is_dir True is_symlink False reparse True resolve False`; real dir `reparse False` | LLR-148.8 tests the attribute, not `is_symlink` |
| P-35 | Every Patch/Check/flow-screen test that sizes the app at 80x24 runs in 17 files; the workspace switches to `width-narrow` below 120 columns. | premise | ✅ TRUE | `grep -rn "size=(80" tests/*.py` filtered to patch/check/flow → 17 files (e.g. `test_tui_patch_card.py` 11 sites, `test_tui_patch_layout.py` 7, `test_flow_builder_render.py` 7); `app.py:7475` `narrow = width < 120` | LLR-149.6 keeps them reachable; LLR-149.2 boundary arm |

- **Premise evaluation:** 35 premise(s) · ✅ TRUE 35 / ❌ FALSE 0 / ❓ UNDECIDABLE 0 — P-1..P-26 executed on `9c7beaf`, P-27..P-35 on `bc4fbd3` (no `s19_app/` diff from `9c7beaf`), 2026-10-20; P-7 records the corrected form of a brief claim (E-1), P-13 and P-16 the corrected form of two others (the palette count, the CRC-and-paused capture).

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

| # | Condition (`C-52`) | Discharged? | The executed evidence |
|---|---|---|---|
| 1 | **Frozen contract** — no shared interface is touched inside a lane; one that must change returns to the trunk (trigger A3) | ✅ | n/a — one lane: I-1..I-4 are changed by this trunk batch, sequenced per `docs/architecture.md` (batch-97 section, "Parallelisation verdict: sequential") |
| 2 | **Disjoint FILE sets**, not just modules — two lanes may not edit the same file, not even different regions | ✅ | n/a — one lane: every increment pair shares `styles.tcss` (ARQ's mechanical verdict), which is why the batch does not fork |
| 3 | **Crossed reverse census** — family B run per lane and **shared before starting**; the trunk's act, impossible from inside a lane | ✅ | n/a — one lane; the reverse census runs per increment inside this batch |
| 4 | **One owner of the trunk** — requirements, traceability, backlog and spec are never written from a lane | ✅ | this batch is the trunk (single worktree, single lane) |

- **Fork preconditions:** none — this batch runs one lane

---

## 3. High-level requirements (HLR)

> Test-file paths, `-k` selectors and node ids in every *Executed verification* line are provisional until Phase 3 (V-5) and reconciled from the real tree at Phase 4. Every acceptance fixture, driver and RED arm is in the §5.3 per-AT table. Every render-increment gate also runs the full guard host `pytest tests/test_tui_directionb.py` (C-34, `docs/engineering-rules.md`).

### HLR-144 — Patch Editor as a ledger + inspector with a consultable JSON tab
- **Traceability:** US-134
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While the Patch Editor is displayed, the Patch Editor shall present the document's entries as a full-height ledger beside an inspector carrying Inspector, JSON and Checks tabs, the inspector showing the highlighted entry's before→after hex strip, labelled entry form and entry chips; when a change-set is loaded or an entry changes, the JSON tab shall show the document the editor holds.
- **Rationale (informative):** operator verdict pe_A with the binding JSON condition (brief R-1, R-1.1, R-1.2). Today the ledger shows 2 of 6 rows in a 3-row band and the JSON editor keeps the dummy template after Load (§2.7 P-4, P-8).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_patch_editor.py -k "at_b97_01 or at_b97_02 or at_b97_03 or at_b97_17"` (Textual pilot, real presses and keys) + the C-34 guard host.
- **Numeric pass threshold:** after Load of the 6-entry fixture at 118x54: 6 of 6 ledger rows painted without scrolling, and the JSON tab's text parses (`json.loads`) to 6 entries whose `address` list equals the list parsed from the fixture FILE (`['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']`, §2.7 P-5); after one Add: 7 entries in the parsed tab text (immediately, or after `Update JSON` with a stamp naming 7); the hostile name and content arms of AT-B97-03 render with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Load the engineer sees every entry in the left ledger, the highlighted entry's before→after strip in the inspector and, on the JSON tab, the same document as JSON; after adding an entry the JSON tab shows it (live, or after `Update JSON` with its stamp); a markup-laden file name and entry value read literally; the whole first task works from the keyboard.
  - **Shipped surface:** `#screen_patch` → `PatchEditorPanel` (`s19_app/tui/screens_directionb.py:4383`), loaded through `#patch_doc_load_button` → `S19TuiApp._patch_editor_load_tail` (`s19_app/tui/app.py:5266`).
  - **Acceptance test(s):** AT-B97-01, AT-B97-02, AT-B97-03, AT-B97-17
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a 0-entry document shows the empty-state line in the ledger and `"entries": []` in the tab (AT-B97-02 first arm); boundary: the 118x54 floor (AT-B97-01); invalid: a legacy v1 file loads as the empty document plus its one ERROR finding and the tab shows that empty document, not the previous one (AT-B97-02 second arm); error: the hostile name and content (AT-B97-03).
  - **Negative control:** executed on `main` (§2.7 P-4): after Load the JSON buffer equals `DUMMY_CHANGESET_TEXT` with 2 `"address"` keys against 6 entries — AT-B97-01's tab clause is RED on today's tree.

### HLR-145 — Check Editor as a ledger + report-fields card
- **Traceability:** US-135
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While the Check Editor is displayed, the Check Editor shall present the A2L parameters as a full-height ledger whose Address column is never truncated, beside a REPORT FIELDS card with Fields, JSON and Addendum tabs whose Fields tab lists exactly the included parameters and memory rows, and one docked row carrying Validate, Write .chk.json, the struck APPLY ghost and the field count.
- **Rationale (informative):** operator verdict ce_A (brief R-2). At 118x54 today the Address column sits 52 cells into a 56-cell table (`max_scroll_x 25`, §2.7 P-12). The no-apply doctrine stays (`PDR-2026-10-12-batch-94#D2`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_check_editor.py -k "at_b97_04 or at_b97_05 or at_b97_18 or at_b97_21"` + the C-34 guard host.
- **Numeric pass threshold:** at 118x54 and at 220x60: the parameter table's `max_scroll_x == 0` and, for every painted row, the Address cell's painted text equals the full `0x%08X` address (75 of 75 rows reachable by vertical scroll only); the field-count text changes from N to N+1 after one Include press; the Fields tab's parsed ledger equals the included set (AT-B97-21); the written `.chk.json` parses to the same address set; 0 apply actions in the panel; the hostile parameter name renders with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer reads every parameter's address in full at both sizes, includes a parameter and sees it on the REPORT FIELDS card and the field count rise by one, writes the spec and finds the same fields in the file, reads a markup-laden parameter name literally, and does the first task from the keyboard.
  - **Shipped surface:** `#screen_check_editor` → `CheckEditorPanel` (`s19_app/tui/screens_directionb.py:6864`), prefilled by `S19TuiApp._prefill_check_editor` (`app.py:5329`).
  - **Acceptance test(s):** AT-B97-04, AT-B97-05, AT-B97-18, AT-B97-21
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: no A2L loaded → the ledger shows its empty state and the docked row stays inside the panel (AT-B97-04 first arm); boundary: 118x54 and the 47-cell longest name (AT-B97-04); invalid: N/A — the panel has no free-text input whose invalid value this story changes (the memory-row inputs keep their batch-94 validation, untouched); error: the hostile name (AT-B97-05).
  - **Negative control:** executed on `main` (§2.7 P-12): `max_scroll_x 25` at 118x54 — AT-B97-04's address clause is RED on today's tree.

### HLR-146 — Flow Builder as a pipeline rail with a contextual add form
- **Traceability:** US-136
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While a flow is loaded in the Flow Builder, the Flow Builder shall present its blocks as one horizontal pipeline of cards joined by cables, shall offer every placeable block kind in its palette with an add form that shows only the chosen kind's inputs, shall carry the copy/paste strip, the `Variables (n)` chip and the session directory on its ribbon, and shall keep Run inside the panel viewport without scrolling.
- **Rationale (informative):** operator verdict fb_A (brief R-3, R-5). Today Run sits below the fold at 118x54 (§2.7 P-11), the palette offers 4 of 7 kinds (P-13), card text overruns its card (P-14) and 25 strings are Spanish (P-17).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_builder.py -k "at_b97_06 or at_b97_07 or at_b97_08 or at_b97_19"` + the C-34 guard host.
- **Numeric pass threshold:** with the 4-block `patch_chain` fixture at 118x54: 4 cards on one painted row joined by 3 cables, `#flow_run` inside the panel region at scroll 0; 7 palette chips, and for each of the 7 kinds the displayed add inputs equal LLR-146.3's table row; pressing Add after EXT-STEP appends a 5th card; pressing Run posts one run request; the hostile EXT-STEP fields render with 0 `MarkupError` and 0 spans originating in the payload; 0 `ES_MARKER` matches in the panel's painted text.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer sees the whole chain as one row of cards with cables and Run on screen; choosing a kind chip shows only that kind's inputs (EXT-STEP: command, log and output on two rows) and Add appends the card; a markup-laden ref reads literally on its card; the first task works from the keyboard.
  - **Shipped surface:** `#screen_flow` → `FlowBuilderPanel` (`s19_app/tui/flow_screens.py:502`), mounted by `_compose_screen_flow` (`app.py:2378`, header `:2404`).
  - **Acceptance test(s):** AT-B97-06, AT-B97-07, AT-B97-08, AT-B97-19
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no blocks → the rail shows its empty line and Run stays reachable (AT-B97-06 first arm); boundary: 118x54 and a ref longer than the card (clipped, AT-B97-08); invalid: EXT-STEP Add with an empty log is refused with the English refusal line (AT-B97-07, EXT-STEP arm); error: the hostile ref (AT-B97-08).
  - **Negative control:** executed on `main` (§2.7 P-11, P-13): `#flow_run (51,42,16,3)` ends past the panel bottom 44, and the palette holds 4 buttons — AT-B97-06 and AT-B97-07 are RED on today's tree.

### HLR-147 — Flow Execution as one pipeline per lane with cable status
- **Traceability:** US-137
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When a flow set runs in Flow Execution, the Flow Execution panel shall paint one pipeline per lane whose cables carry the run status of their blocks from the retained run record; while a lane waits for a human, the panel shall show that lane's Confirm inside the lanes viewport, paint the waiting-human elements in the waiting hue that no other element on the four screens paints, and name the wait in English in the run log.
- **Rationale (informative):** operator verdict fx_A (brief R-4, R-5); the batch-96 waiting-human doctrine is kept as it is. Per-block status and lane order are already in the record (§2.7 P-15), so no record change is owed; the seven Spanish service strings are translated (P-17, ruling 2 in LED-…97.2). The hue pair is the operator's at PDR (§6.2 item 7).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_execution.py -k "at_b97_09 or at_b97_10 or at_b97_11 or at_b97_20 or at_b97_22"` + the C-34 guard host.
- **Numeric pass threshold:** importing `patch_chain`, `flash_chain`, `err_chain` through `#fx_import` and pressing `#fx_run` (sequential) at 118x54: lane 0 cables `▓ ▓ ◇`, lane 1 cables `▓ □ ░`, lane 2 cables `✗ ░ ░`; `#fx_confirm_1` region inside `#fx_lanes_scroll`'s region and focused; `#fx_confirm_0` and `#fx_confirm_2` not displayed; every span painted in the waiting hue belongs to a waiting-human element; 0 `ES_MARKER` matches in the painted log and lanes; `#fx_save` / `#fx_load` inside the panel at scroll 0; Save Set writes the set file and Load Set restores its lanes; the hostile arms render with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Run the engineer sees lane 0 done with notices, lane 1 paused at its external step with Confirm on screen and focused, lane 2 failed, a REQUIRED line above the log, and the log in English; Save Set and Load Set are on screen and round-trip the set; a CRC card beside the waiting card is painted in a hue distinct from the waiting hue (judged on the capture, §5.1).
  - **Shipped surface:** `#screen_flow_execution` → `FlowExecutionPanel` (`s19_app/tui/flow_screens.py:1874`), lanes added through `#fx_import` → `on_flow_execution_panel_import_requested` (`app.py:2719`), run through `on_flow_execution_panel_run_requested` (`app.py:2776`; chains built `:2806-2814`, rendered `:2821`).
  - **Acceptance test(s):** AT-B97-09, AT-B97-10, AT-B97-11, AT-B97-20, AT-B97-22
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: Run with no lanes paints no pipeline and an English no-lanes line (AT-B97-10 first arm); boundary: 118x54 header and set row, and the waiting lane third of three with 6 blocks (AT-B97-10, AT-B97-20); invalid: N/A — the run inputs' validation (bindings, containment) is batch-94's and unchanged; error: `err_chain` (`✗` cable, AT-B97-09) and the hostile arms (AT-B97-11).
  - **Negative control:** executed on `main` (§2.7 P-11, P-17): `#fx_save (117,10,16,3)` and `#fx_load (134,10,16,3)` outside the panel; the run log line `□ flash_chain · ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` — AT-B97-09/10 are RED on today's tree.

### HLR-148 — Folder chip and help chip on the four screens
- **Traceability:** US-138
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When the engineer presses the open-folder chip on the Patch Editor, Check Editor, Flow Builder or Flow Execution screen, the system shall open the folder that screen's files live in only if it is a real directory inside that family's root, and shall otherwise refuse on the status line. When the engineer presses that screen's help chip, the system shall show that screen's help entry naming every control, tab, key and glyph on the screen as `label — effect` lines. While no project is active, a project-only family's chip shall be disabled and its status message shall name that family's folder. While a region of the four screens has no content, an error, or a run in flight, that region shall show one English line naming the state.
- **Rationale (informative):** the operator's round-2 answer ("es un problema adivinar y buscarlos, sobre todo para usuarios nuevos") and the verdict note on legends (brief R-6, R-7). ARQ I-1 / I-4; R14 (project-only limb), R15 (`FLOWS_SUBDIR` imported). The real-directory clause is 02-review S-1; the region-state clause U-10.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_chips_help.py -k "at_b97_12 or at_b97_13 or at_b97_14 or at_b97_23"` with the open seam spied (the `SeamSpy` idiom of `tests/test_open_folder_chips.py:101`).
- **Numeric pass threshold:** with a project: 4 presses → 4 seam calls with targets `patch` home, `checks` home, `project_dir / "flows"`, `project_dir`; a `flows` that is a file or a junction → 0 seam calls and a refusal line; without a project: the `flows` and `session` chips are disabled, 0 seam calls, and the status line names the family's folder and not "Reports"; each of the 4 help chips opens a modal whose `label — effect` lines cover 100 % of the screen's coverage set (LLR-148.6; today 6/19, 0/6, 2/13, 0/4 buttons — §2.7 P-21); each region state of LLR-148.9 shows its line.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** every one of the four screens shows an open-folder chip and a `?` chip in its header; with a project the chip opens the right folder, without one the flow chips are dimmed and say why, and a folder replaced by a file or link is refused; `?` explains every control, key and mark on that screen; an empty, failed or running region says so in one line.
  - **Shipped surface:** `OpenFolderChip` / `titled_header` (`s19_app/tui/open_folder_chip.py:59`, `:185`), `folder_open_service.resolve_chip_target` (`s19_app/tui/services/folder_open_service.py:232`), `WindowHelpChip` (`s19_app/tui/window_help.py:401`).
  - **Acceptance test(s):** AT-B97-12, AT-B97-13, AT-B97-14, AT-B97-23
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no project (AT-B97-13); boundary: a project whose `flows/` does not exist yet → the chip is dimmed and the press follows the create decision of PDR within LLR-148.1's containment (AT-B97-12 second arm); invalid: `flows` is a file or a junction → refused, 0 seam calls (AT-B97-12 fourth arm); error: the seam raises → the status line carries the failure, no traceback (AT-B97-12 third arm).
  - **Negative control:** executed on `main` (§2.7 P-18, P-20, P-21): `OpenFolderChip("flows")` raises `ValueError` (family not in `CHIP_FAMILIES`), the Check Editor header has no chip, and the help coverage is 6/19 · 0/6 · 2/13 · 0/4 — all three ATs are RED on today's tree.

### HLR-149 — Width-adaptive layouts, no wrapped rows
- **Traceability:** US-139
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While the Patch Editor, Check Editor, Flow Builder or Flow Execution screen is displayed at any terminal size of at least 118x54, on either side of the 120-column `width-narrow` breakpoint, the system shall derive that screen's column widths, panel splits and region heights from the available size at mount and on every resize, so that no element overflows horizontally, the primary actions stay inside the panel viewport, no row of the no-wrap set wraps and the remaining space goes to the screen's growing region; below 118x54 the screen shall stay reachable under scroll.
- **Rationale (informative):** the operator's variable-size rule and the 220x60 pass (brief R-8). Every screen overflows today at both sizes (§2.7 P-10) and the EXT-STEP inputs keep the same width at both sizes (P-22). The 80x24 floor is kept (ruling 1 in LED-…97.2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_width.py -k "at_b97_15 or at_b97_16 or at_b97_24"` (four screens × the samples 118x54, 160x56, 220x60, 260x70; an in-session `pilot.resize_terminal` 118x54 → 220x60 → 118x54; the 119↔120 boundary; 80x24 reachability).
- **Numeric pass threshold:** per screen and sample: 0 displayed descendants with `region.right > panel.region.right` or `region.x < panel.region.x`; the LLR-149.3 primary actions inside the panel region at scroll 0; 0 wrapped no-wrap rows; at 220x60 and 260x70 the painted-extent void of LLR-149.5 within its bound; after the resize back to 118x54 the overflow count is 0 again; at 119x54 and 120x54 the same 0 counts; at 80x24 every LLR-149.3 action reachable by scrolling the panel.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** at any size from 118x54 up nothing runs off the right edge and Run / Validate / Save Set / the document controls are on screen; at large sizes the ledgers and inputs grow into the space instead of leaving a void; no table, ledger or log line breaks onto a second line; at 80x24 everything is still reachable by scrolling.
  - **Shipped surface:** the four panels above, driven through the rail (`action_show_screen`) at each sample size.
  - **Acceptance test(s):** AT-B97-15, AT-B97-16, AT-B97-24
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — empty: N/A — geometry is asserted on the loaded scenarios, the empty states are covered by each screen's own AT; boundary: 118x54, 119x54↔120x54, the in-session resize (AT-B97-16, AT-B97-24); invalid: N/A — below 118x54 only reachability is promised (LLR-149.6); error: a 60-cell ref and the 47-cell parameter name, the widest real values, clip with an ellipsis instead of overflowing (AT-B97-15).
  - **Negative control:** executed on `main` (§2.7 P-10, P-11, P-22): overflow counts 1/1/2/7 at 118x54 and 1/1/1/6 at 220x60; EXT-STEP inputs 28/26/28 at both sizes — both ATs are RED on today's tree.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level. EARS owed (`full`). ID format: `LLR-<HLR>.<M>`. A symbol marked `NEW` is created in Phase 3; every other symbol carries its `file:line` on `9c7beaf`. Test paths and selectors are provisional (V-5). Every `NEW` widget id below is a working name, fixed at PDR.

### LLR-144.1 — Patch Editor re-composed at its shipped ids
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `PatchEditorPanel` shall yield every id of `PE_IDS_9C7BEAF` (§5.3, the 66 shipped ids frozen from `9c7beaf`) in the ledger + inspector composition, with each `patch_win_*`, `patch_saveback_row`, `patch_before_after_row` and `patch_checks_results` id keeping its `Container` type.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-01 — `pytest tests/test_b97_patch_editor.py -k tc_b97_01`: assert `len(PE_IDS_9C7BEAF) == 66` (the literal's own guard), mount the app, `{w.id for w in panel.query("*")} ⊇ PE_IDS_9C7BEAF`, plus `query_one(id, Container)` for the container ids. The set is a committed literal, never re-derived from the source it certifies.
- **Numeric pass threshold:** 0 of 66 ids missing; 0 container-type mismatches.
- **Negative control:** remove one shipped id from the composition (mutation, executed at Phase 3 per C-40) → 1 missing id, RED; against the literal, the mutation cannot also shrink the expected set.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the census at 118x54 and 220x60 (an id hidden by `display:none` still counts; one never yielded does not). Empty/invalid/error: N/A — the composition has no input.

### LLR-144.2 — Full-height ledger and Inspector / JSON / Checks tabs
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `PatchEditorPanel` shall render `#patch_doc_entries_table` in the left column with a height that grows with the panel, and shall carry three focusable tab chips (Inspector, JSON, Checks — ids NEW), each activated by a click, `enter` or `space`, that switch one `ContentSwitcher` (NEW) between the inspector pane (NEW), `#patch_win_json` and `#patch_win_checks`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-02 — at 118x54 with the 6-entry fixture: `table.region.height >= table.row_count + 1`; activate each tab chip once by `pilot.click` and once by focus + `pilot.press("enter")` / `("space")`, reading `ContentSwitcher.current` and the target pane's `display`.
- **Numeric pass threshold:** table region height ≥ 7 at 118x54 (today 3, §2.7 P-8 — `region (9, 6, 102, 3)`); 9 of 9 activations (3 chips × click/enter/space) show their pane and hide the other two.
- **Negative control:** executed on `main`: `table region (9, 6, 102, 3)` with `rows 6` → `3 >= 7` is False, RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: a 0-entry document shows `#patch_doc_empty_state`; boundary: 118x54. Invalid/error: N/A — tab chips take no input.

### LLR-144.3 — The double geometry work removed (E-1, E-2)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `PatchEditorPanel` shall size its ledger, file row and inputs without forcing a fixed table height, fixed select/path widths or a show-time geometry pass, and shall add its five entries columns exactly once.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-03 — show the patch screen, leave and show it again, then `pilot.resize_terminal(220, 60)`; read `len(table.columns)`, `table.region.height`, `#patch_doc_file_select` / `#patch_doc_path_input` widths at both sizes. Plus the source probe `grep -n "_apply_window_geometry" s19_app/tui/app.py` (today 1 hit at `app.py:6978`).
- **Numeric pass threshold:** `len(table.columns) == 5` after 2 shows + 1 resize; the select and path widths differ between 118x54 and 220x60 (today 30 / 28 at both — `screens_directionb.py:5638`, `:5641`); 0 hits for the app-side geometry call.
- **Negative control:** executed on `main`: the probe returns 1 hit (`app.py:6978`) and `table.styles.height = 3` (`:5616`) yields a 3-row table at both sizes — RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 → 220x60 → 118x54 in one session. Others N/A — no input.

### LLR-144.4 — The E-3 stylesheet rules replaced, not overridden
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The stylesheet `s19_app/tui/styles.tcss` shall carry no `width: 2fr` rule on `#patch_win_script`, no fixed `height: 10` on `#patch_doc_entries_table`, and no `layout: grid` on `#patch_doc_entry_buttons` or `#patch_doc_controls`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-04 — parse the selector blocks of `styles.tcss` (a block-level read: selector list → declarations, never a line grep, C-42 mechanic 5) and assert the four selector/declaration pairs are absent.
- **Numeric pass threshold:** 0 of the 4 pairs present (today 4: `:1117-1118`, `:1536-1538`, `:1160-1168`, `:1581-1584`, §2.7 P-9).
- **Negative control:** executed on `main`: the 4 pairs are present → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: a selector list naming two ids (`#patch_doc_entry_buttons,` on its own line, `:1160`) is matched as one block. Others N/A.

### LLR-144.5 — The JSON tab shows the loaded document
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When a change-set is loaded into the Patch Editor, the app shall feed the JSON tab (`#patch_win_json`) with `ChangeService.document` (`change_service.py:696`) serialised by `serialize_change_document` (`s19_app/tui/changes/io.py:1392`) through the I-2/I-3 seam at the `refresh_entries` sites (`app.py:3265`, `:3451`, `:5279`, `:10758`), in a read-only view; if the serialised document exceeds `JSON_TAB_LINE_CAP` lines (NEW, value fixed at PDR, ≤ 5,000), then the view shall show the first `JSON_TAB_LINE_CAP` lines followed by one note line `showing N of M lines`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-05 — load the fixture through `#patch_doc_load_button`; `json.loads(<JSON tab text>)` (C-42: parse the emitted form) and compare its `entries[*].address` to the addresses parsed from the fixture file; type into the view and read the text back unchanged; a generated document of `JSON_TAB_LINE_CAP + 1` lines and one of 100,000 entries, read for the note line and for the view's line count.
- **Numeric pass threshold:** 6 parsed entries, address list `['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']` (the emitted form pasted in §2.7 P-5); the tab text never equals `DUMMY_CHANGESET_TEXT` after a Load; 0 characters changed by typing; at `CAP + 1` lines: `CAP` document lines + 1 note line naming `CAP` and `CAP + 1`; at `CAP` lines: no note.
- **Negative control:** executed on `main` (§2.7 P-4): buffer `== DUMMY True`, 2 address keys → RED; removing the cap (mutation, Phase 3) → the 100,000-entry arm shows > `CAP` lines, RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a 0-entry document → `"entries": []`; boundary: `CAP` and `CAP + 1` lines; invalid: a legacy v1 file → the empty document (not the previous one). Error: N/A — the serialiser is reused unchanged and raises on nothing a loaded document can hold.

### LLR-144.6 — The JSON tab after an entry change (live or Update JSON — decided at PDR)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When any of the nine writers of `ChangeService.document` (§2.7 P-6) changes the Patch Editor document, the JSON tab shall show the changed document either at once (live) or after the engineer presses an `Update JSON` action (NEW, explicit); in the explicit mechanism the tab shall keep showing the previous document until that press and shall carry the stamp `generated from N entries · HH:MM` (NEW) naming the document it shows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-06 — one arm per writer, driven through its Patch Editor control: Add `#patch_entry_add_button`, Edit `#patch_entry_edit_button`, Remove `#patch_entry_remove_button`, Undo `#patch_undo_button`, Redo `#patch_redo_button`, edit-entry-JSON `#patch_entry_edit_json_button`, paste-parse `#patch_paste_parse_button` (`load_text`), Load `#patch_doc_load_button`; `add_symbol_entry` has 0 UI callers (P-6), so its arm calls the service and then the I-3 refresh seam. Explicit mechanism: read the tab before the press (parsed == the previous document) and after (parsed == the current one).
- **Numeric pass threshold:** 9 of 9 writer arms (8 through controls, 1 through the seam) leave the parsed tab equal to `json.loads(serialize_change_document(service.document))` after the mechanism's step; explicit mechanism only: 9 of 9 stale-before reads equal the previous document and stamp N == parsed count. The mechanism is **decided at PDR** with its reason (brief R-1.1); both mechanisms satisfy this statement.
- **Negative control:** a JSON feed that skips one writer (mutation: drop the feed on Undo, executed at Phase 3 per C-40) → the Undo arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: Remove the last entry → `"entries": []`; boundary: Undo at the bottom of the stack (no-op) leaves the tab unchanged. Others N/A — entry validation is reused unchanged and is not this LLR's subject.

### LLR-144.7 — Identity ribbon and file-derived fields, markup-safe (E-5, C-17)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `PatchEditorPanel` shall show the loaded document's file name (`ChangeDocument.source_path.name`, `changes/model.py:258`) and kind (`:253`) on an identity ribbon (NEW), and shall render that name and every file-derived entry field (value, symbol, address text) in the ledger, the inspector pane, the JSON tab and the issues line `#patch_doc_issues` as `rich.text.Text` through `safe_text` (`s19_app/utils.py:44`), never interpolated into a markup-parsed string; the call shape that delivers name and kind (a `refresh_entries` keyword or a setter, I-2) is decided at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-07 — two arms through `#patch_doc_load_button`. NAME arm: a file named `HOSTILE_NAME` (§5.3, filename-legal, P-27). CONTENT arm: a file whose `string` entry `value` is `HOSTILE_CONTENT` (incl. `[/]`, `https://`, C0 bytes, P-29) and a second entry whose `symbol` is `HOSTILE_CONTENT` (refused with a finding that echoes it). Read `render()` spans (C-37) and plain text of the ribbon, the ledger row, the inspector pane, the JSON tab and `#patch_doc_issues`.
- **Numeric pass threshold:** 0 `MarkupError`; each payload bracket token literal in the plain text of each of the 5 surfaces; 0 spans whose range lies inside a payload occurrence and whose style differs from the surface's own base style (spans **originating in the payload**, whatever their style — bold, red, link or click); 0 C0/C1 control characters painted.
- **Negative control:** build the ribbon or one inspector line with `Text.from_markup(f"… {name}")` (mutation, Phase 3, C-40) → `MarkupError` or a payload-originated span, RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☒ error — empty: a new unsaved document → the ribbon says `draft` with no name; error: the NAME and CONTENT arms. Others N/A.

### LLR-144.8 — The inspector's before→after hex strip follows the highlighted row
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** When the ledger's highlighted row changes, the inspector shall paint that entry's before and after bytes as a hex strip (NEW id, fixed at PDR) whose changed bytes carry a text attribute (bold, reverse or underline, named at PDR) as well as a colour.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-39 — 6-entry fixture with `prg.s19` loaded; move the cursor with `pilot.press("down")` over 3 rows; read the strip's plain text and `render().spans`.
- **Numeric pass threshold:** 3 of 3 rows: the strip's after-bytes equal the highlighted entry's encoded bytes and its before-bytes equal the image bytes at that address; every changed byte cell carries the attribute; 0 unchanged cells carry it.
- **Negative control:** a strip bound to row 0 only (mutation, Phase 3) → rows 2-3 RED; today no strip in the inspector → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no image loaded → the strip shows its one English empty line (LLR-148.9). Others N/A.

### LLR-144.9 — Labelled entry form and entry chips in the inspector
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The inspector pane shall carry `#patch_entry_address_input`, `#patch_entry_value_input` and `#patch_entry_bytes_input`, each beside a visible label naming its field, and the entry chips `#patch_entry_add_button`, `#patch_entry_edit_button`, `#patch_entry_remove_button`, `#patch_entry_edit_json_button` on one row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-40 — region containment of the 3 inputs and 4 chips in the inspector pane; per input a displayed `Label` on the same row whose text names the field; the 4 chips share one `region.y`.
- **Numeric pass threshold:** 7 of 7 contained; 3 of 3 labelled; 1 distinct chip row.
- **Negative control:** executed on `main`: the inputs sit in `#patch_doc_entry_inputs` outside any inspector pane (no such pane) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-144.10 — Patch Editor keyboard order
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The Patch Editor's focus order shall run header chips → ledger → tab chips → inspector form → entry chips → file row → document controls, and every control in it shall be operable by `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-41 — read `app.screen.focus_chain`, keep the ids of the seven groups (group membership is the LLR's list, not the DOM), and check group order; `pilot.press("tab")` from the panel top visits them in that order.
- **Numeric pass threshold:** group order monotone (0 inversions); ≥ 1 member per group; the tab chips present in the chain.
- **Negative control:** executed on `main` (§2.7 P-33): no tab chip in the 40-id chain → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the JSON tab active (its view in the chain, read-only). Others N/A.

### LLR-144.11 — Patch Editor filled elements
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `PatchEditorPanel` shall paint exactly one filled element besides the ledger hero: its primary action, named at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-42 — `[b.id for b in panel.query(Button) if b.display and b.variant == "primary"]` plus the widgets carrying the filled accent class.
- **Numeric pass threshold:** exactly 1 filled element, equal to the PDR primary, on 3 of 3 tab states.
- **Negative control:** a second `variant="primary"` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each of the 3 tabs active. Others N/A.

### LLR-145.1 — Check Editor re-composed: ledger, REPORT FIELDS card, one docked row
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `CheckEditorPanel` shall yield every id of `CE_IDS_9C7BEAF` (§5.3, 31 ids frozen from `9c7beaf`) with `#check_param_table` in the left column at full height holding one row per A2L tag with an integer address (filled by `_prefill_check_editor`, `app.py:5329`), a REPORT FIELDS card with focusable Fields / JSON / Addendum tab chips (ids NEW, activated by click, `enter` or `space`) on the right, and `#check_validate_button`, `#check_write_button`, `#check_apply_ghost` and `#check_fields_count` on one docked row; the panel shall offer no apply action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-08 — `len(CE_IDS_9C7BEAF) == 31`, then the id census as TC-B97-01; `table.row_count` vs the int-address tag count of the loaded A2L; the four docked ids share one `region.y`; each tab chip activated by click/enter/space switches the card; `check_apply_ghost` is not a `Button` that posts an apply.
- **Numeric pass threshold:** 0 of 31 ids missing; `row_count == 75` with `ASAP2_Demo_V161.a2l` (P-24); 1 distinct `region.y` across the 4 docked ids (today 2 rows: y=35 and y=38 at 118x54, P-12 probe); 9 of 9 tab activations; 0 apply actions.
- **Negative control:** executed on `main`: `#check_validate_button (62,35,…)` and `#check_fields_count (62,38,…)` sit on different rows → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no A2L → the ledger's empty state; boundary: 118x54. Others N/A.

### LLR-145.2 — The Address column is never truncated
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `CheckEditorPanel` shall size `#check_param_table`'s Address column to its longest address and place it so that the whole column lies inside the table's viewport at horizontal scroll 0, at every width from 118 columns upward.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-09 — at 118x54 and 220x60: `table.max_scroll_x`, the Address column's offset (sum of preceding `get_render_width`) + its render width vs the table's content width, and each painted row's Address text (`_render_line`, C-32) vs the address string.
- **Numeric pass threshold:** `max_scroll_x == 0`; offset + width ≤ content width; 75 of 75 addresses painted in full.
- **Negative control:** executed on `main` (§2.7 P-12): `scroll_x max 25`; offset 52 + 12 > 56 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 (tightest) and the longest address (10 cells). Others N/A.

### LLR-145.3 — Long parameter names keep their first segment and tail
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** If a parameter name is wider than its column (the Parameter column, or the name field of a REPORT FIELDS line), then the `CheckEditorPanel` shall paint the name's first dot-separated segment, an ellipsis and the name's tail filling the remaining width, and when the column is at least as wide as the name it shall paint the name in full.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-10 — at 118x54 read the painted Parameter cell of every row of `ASAP2_Demo_V161.a2l` and the painted line of each of 6 included `ASAM.M.SCALAR.*` parameters on the Fields tab; at 220x60 the same rows.
- **Numeric pass threshold:** every clipped cell starts with its name's first segment, contains exactly one `…`, ends with the name's last characters, and has cell length == the column width; 0 pairs of painted rows equal while their names differ (all 75 ledger rows; the 6 Fields lines); at 220x60 the 47-cell name painted in full.
- **Negative control:** a pure tail-keeping truncation (mutation, Phase 3) → two `ASAM.M.SCALAR.UBYTE.*` rows paint equal, RED; head-keeping → same.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a name exactly the column width (no ellipsis); a name with no dot (head + `…` + tail). Others N/A.

### LLR-145.4 — One-row chip shape in the Check Editor (E-4)
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `CheckEditorPanel` shall render every one of its buttons as a one-row chip.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-11 — `[b.region.height for b in panel.query(Button) if b.display]` at 118x54.
- **Numeric pass threshold:** every height == 1 (today `#check_validate_button` height 3 — P-12 probe `(62, 35, 16, 3)`).
- **Negative control:** executed on `main`: heights of 3 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-145.5 — File-derived names in the Check Editor render literally (C-17)
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `CheckEditorPanel` shall render every A2L parameter name, spec file name and REPORT FIELDS ledger line as `rich.text.Text` built through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-12 — `ASAP2_Demo_V161.a2l` copied to `tmp_path` with its first CHARACTERISTIC renamed to `HOSTILE_CONTENT` (admitted with an integer address, executed: §2.7 P-28) and a spec file named `HOSTILE_NAME` + `.chk.json` (P-27); include the hostile parameter; read the ledger cell, the REPORT FIELDS line, the JSON tab and the spec file row (spans + plain).
- **Numeric pass threshold:** 0 `MarkupError`; payload brackets literal in all 4 surfaces; 0 spans originating in the payload (LLR-144.7's definition); 0 control characters painted.
- **Negative control:** render one surface with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-145.6 — The REPORT FIELDS card holds exactly the included fields
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The REPORT FIELDS card's Fields tab shall list one line per included parameter (`☑`, name, address) and one per memory row (`▪`, label, address), in inclusion order, its JSON tab shall show the spec document those fields produce, and its Addendum tab the addendum preview (`#check_addendum_preview`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-43 — include 2 parameters with `#check_param_include_button` and add 1 memory row with `#check_mem_add_button`; parse the Fields lines into `(mark, address)` tuples (C-42: split the painted line on its column layout, never substring-search) and `json.loads` the JSON tab; switch to Addendum and read `#check_addendum_preview`'s display.
- **Numeric pass threshold:** parsed Fields set == `{("☑", a1), ("☑", a2), ("▪", m1)}`; JSON tab entry addresses == `[a1, a2, m1]`; `#check_fields_count` reads 3; Addendum tab shows `#check_addendum_preview`.
- **Negative control:** a card fed from the unfiltered parameter list (mutation, Phase 3) → 75 lines, RED; executed on `main`: no Fields tab → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: nothing included → one empty-state line, `"entries": []`; boundary: include then exclude the same parameter → the line disappears. Others N/A.

### LLR-145.7 — Memory-row table with labelled inputs
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The REPORT FIELDS card shall carry `#check_mem_table` (columns Address, Label, Fmt) above `#check_mem_address_input`, `#check_mem_label_input` and `#check_mem_size_input`, each beside a visible label naming its field, with `#check_mem_add_button` and `#check_mem_remove_button`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-44 — region containment of the 6 ids in the card; per input a displayed `Label` on its row naming the field.
- **Numeric pass threshold:** 6 of 6 contained; 3 of 3 labelled.
- **Negative control:** executed on `main`: the memory inputs carry placeholders only, no label widget → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A (input validation is batch-94's, unchanged).

### LLR-145.8 — Check Editor keyboard order
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The Check Editor's focus order shall run header chips → parameter filter → parameter ledger → include chip → REPORT FIELDS tab chips → memory inputs and chips → spec row → docked row, and every control in it shall be operable by `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-45 — as TC-B97-41 over these eight groups.
- **Numeric pass threshold:** 0 group inversions; ≥ 1 member per group.
- **Negative control:** executed on `main` (§2.7 P-33): the 27-id chain holds no header chip and no tab chip → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: no A2L loaded (the ledger still in the chain). Others N/A.

### LLR-145.9 — Check Editor filled elements
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `CheckEditorPanel` shall paint exactly one filled element besides the ledger hero: its primary action, named at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-46 — as TC-B97-42.
- **Numeric pass threshold:** exactly 1 filled element, equal to the PDR primary, on 3 of 3 card-tab states.
- **Negative control:** a second `variant="primary"` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each of the 3 card tabs active. Others N/A.

### LLR-146.1 — Pipeline of block cards joined by cables
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While a flow is loaded, the `FlowBuilderPanel` shall paint its blocks as cards in block order on one horizontal pipeline (id NEW) with one cable between consecutive cards, and shall not display the numbered block list or the grid canvas as separate panes; whether the grid canvas (`#flow_canvas`, `_CANVAS_COLS = 88`, `flow_screens.py:333`) stays reachable is decided at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-13 — with `patch_chain` (4 blocks) at 118x54: count the cards and cables on the painted pipeline row (structured read of the rendered `Text`, not a substring count of the glyphs, C-42) and read `#flow_blocks.display`.
- **Numeric pass threshold:** 4 cards, 3 cables, all on one painted row band; `#flow_blocks` not displayed (today `(5, 37, 110, 5)` displayed).
- **Negative control:** executed on `main`: `#flow_blocks` displayed and no pipeline id → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: 0 blocks → an empty-rail line; boundary: more cards than fit at 118 → the rail scrolls horizontally inside its own container (never the panel). Others N/A.

### LLR-146.2 — The palette offers every placeable kind
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowBuilderPanel` shall render one `flow_palette_<kind>` chip for each kind of `_KIND_OPTIONS` (`flow_screens.py:542-551`), in that order, each routed through the shipped handler (`:1455-1461`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-14 — the chip id list vs `[kind for _, kind in FlowBuilderPanel._KIND_OPTIONS]` (the set drawn from the rule, C-40 limb 2); click each chip and read `#flow_kind`.
- **Numeric pass threshold:** 7 chips in `_KIND_OPTIONS` order; 7 of 7 clicks set `#flow_kind` to their kind.
- **Negative control:** executed on `main` (§2.7 P-13): 4 chips → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the default kind (`source`) and the last kind (`external_step`). Others N/A.

### LLR-146.3 — The add form shows only the chosen kind's inputs
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When a kind is chosen, the `FlowBuilderPanel` shall display exactly the inputs of that kind's row in the table below and hide every other add input, with the EXT-STEP inputs on two rows.

| kind | displayed add inputs |
|---|---|
| `source`, `patch`, `crc`, `write_out` | `#flow_ref` |
| `check` | `#flow_ref`, `#flow_gating` |
| `a2b` | `#flow_ref_a`, `#flow_ref_b` |
| `external_step` | `#flow_ext_mode`, `#flow_ext_instruction`, `#flow_ext_log`, `#flow_ext_output` (two rows) |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-15 — one arm per table row: click the kind chip, collect the displayed add inputs, compare with the row; EXT-STEP arm also reads the inputs' `region.y` (two distinct values).
- **Numeric pass threshold:** 7 of 7 arms equal their row; EXT-STEP inputs on 2 distinct rows. The table restates today's `_sync_kind_dependent_visibility` (`:1534-1547`) — it is a regression PIN for the visibility and a gate for the two-row layout.
- **Negative control:** executed on `main`: the EXT-STEP inputs share one `region.y` (13, §2.7 P-22) → the two-row clause RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: switching kinds twice in a row; invalid: Add on EXT-STEP with an empty log → the English refusal. Others N/A.

### LLR-146.4 — Card text clipped to the card (F-1)
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The pipeline card renderer shall clip every title and IO line to the card's inner width with one ellipsis, keeping the head of a label (kind, title) and the tail of a file name or path (refs, log, output).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-16 — render cards whose title is 40 cells and whose ref is a 60-cell path ending `…\fw_app_flashed.s19`; check every painted line's cell length and which end survives.
- **Numeric pass threshold:** 0 painted card lines wider than the card; per clipped line exactly 1 `…`; title lines start with the title's first `w-1` cells; path lines end with the path's last `w-1` cells.
- **Negative control:** executed on `main` (§2.7 P-14): `_plc_block` with a 60-cell `text_` paints past `x + w` → RED; a head-keeping path clip (mutation, Phase 3) → the tail clause RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a ref exactly the inner width (no ellipsis). Others N/A.

### LLR-146.5 — The foot row, and Run as the Builder's primary action
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall carry `#flow_run`, `#flow_clear`, `#flow_save` and `#flow_load` on one foot row and shall paint exactly one filled element besides the pipeline hero: `#flow_run`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-17 — the four ids share one `region.y`; the filled list as TC-B97-42; press `#flow_run` once and count `RunRequested` messages.
- **Numeric pass threshold:** 1 row; the filled list equals `['flow_run']` (today `flow_screens.py:824` `variant="primary"` on Run); 1 run request per press.
- **Negative control:** add a second primary chip (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-146.6 — CRC family accent token, a hue apart from the waiting hue
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `insight_style` module shall declare the CRC family token and the waiting token (NEW names; the hex pair chosen at PDR, §6.2 item 7), the CRC token's hue lying at least 20° from the waiting token's hue, and the flow screens shall paint CRC cards with the CRC token and never with the waiting style.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-18 — read the CRC card's span colour off `render().spans` (C-37) and couple it to the token constant; compute the hue distance of the two tokens with `colorsys.rgb_to_hsv` (circular distance).
- **Numeric pass threshold:** CRC card span colour == the CRC token; hue distance ≥ 20°. Measured candidates (executed 2026-10-20): `#cf6a2d` 22.6° vs shipped wait `#f6ff8f` 64.8° → 42.2° (passes); `#cf6a2d` vs prototype amber `#e8a33d` → 13.2° (fails, so that pair cannot be chosen as is).
- **Negative control:** executed: `#cf6a2d` against `#e8a33d` → 13.2° < 20°, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a CRC card next to a waiting card in one capture (`crc_wait_chain`, §5.3). Others N/A.

### LLR-146.7 — Flow Builder strings in English
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall paint every user-facing string in English.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-19 — the §2.7 P-17 AST census with the committed `ES_MARKER` (§5.3), keyed on the `FlowBuilderPanel` `ClassDef` node (never on line spans), docstrings excluded; reach guard: the same census run on `git show 9c7beaf:s19_app/tui/flow_screens.py` returns ≥ 25 for this class (proves the regex and keying still reach the strings). Pins rewritten in Inc 4: `test_flow_external_step_b96.py:422, 425`, `test_flow_funnel_b96.py:331, 475, 477`.
- **Numeric pass threshold:** 0 `ES_MARKER` constants in the class on the increment's tree; reach guard ≥ 25 on `9c7beaf`.
- **Negative control:** executed on `9c7beaf`: 25 → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: English text sharing a marker shape (`DE AD BE EF`, hex in `window_help.py`) is not matched — `de` is case-sensitive in `ES_MARKER`, executed: `PatchEditorPanel 0`, `window_help.py 0`. Others N/A.

### LLR-146.8 — File-derived text on cards and the add form renders literally (C-17)
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall render every flow name, block ref, EXT-STEP `instruction`, `log_ref` and `output_path`, file name and session path on the pipeline, the ribbon and the add form as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-20 — `flash_chain` generated in `tmp_path` with its patch `change_doc_ref`, EXT-STEP `instruction` and `log_ref` set to `HOSTILE_CONTENT` minus NUL (admitted, P-30; NUL excluded per 02-review Q-13) and loaded through `#flow_load`; read the pipeline's, ribbon's and card's spans and plain text.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal on each of the 3 fields; 0 spans originating in the payload; 0 control characters painted.
- **Negative control:** render the card IO line with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-146.9 — One-row copy/paste strip
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall carry `#flow_pick`, `#flow_copy`, `#flow_paste` and `#flow_clip_status` on one painted row inside the panel region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-47 — the 4 ids share one `region.y`, each `region.height == 1` except the input, all inside the panel; copy block 2 and paste through the chips, read the block count.
- **Numeric pass threshold:** 1 row; 4 of 4 inside the panel; block count +1 after copy + paste.
- **Negative control:** executed on `main` (§2.7 P-10): `flow_clip_status` overflows the panel → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A (refusals are batch-96's, translated by LLR-146.7).

### LLR-146.10 — `Variables (n)` chip
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall label `#flow_funnel_toggle` `Variables (n)`, where n is the number of funnel variables, and pressing it shall show or hide `#flow_funnel_editor`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-48 — add one variable through `#flow_funnel_add`; read the chip's label; press the chip twice, read the editor's `display`.
- **Numeric pass threshold:** label == `Variables (1)`; display toggles 2 of 2.
- **Negative control:** executed on `main`: label `Funnel (1)` (`flow_screens.py:1243`, pinned by `test_flow_funnel_b96.py:330`) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: 0 variables → `Variables (0)`. Others N/A.

### LLR-146.11 — Session directory on the Builder ribbon
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall show the session directory set by `set_session_dir` on its identity ribbon (`#flow_name_strip`), path tail kept, and shall not paint a separate session row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-49 — `set_session_dir(tmp_path)` through `_publish_flow_session_dir` (project open); read the ribbon's plain text and `#flow_ext_session.display`.
- **Numeric pass threshold:** 1 of 1 ribbon reads end with the session path's last segment; 0 displayed session rows (`#flow_ext_session`).
- **Negative control:** executed on `main`: the session sits in `#flow_ext_session` (`flow_screens.py:764`) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project → the ribbon's English no-session text (LLR-148.9). Others N/A.

### LLR-146.12 — The variant-scope selector leaves the Builder
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `FlowBuilderPanel` shall keep `#flow_scope` mounted and not displayed, and its Run shall request the single-image scope (`FLOW_SCOPE_SINGLE`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-50 — `#flow_scope.display`; press `#flow_run`, read the posted scope.
- **Numeric pass threshold:** 0 displayed scope selectors; 1 of 1 run requests carries `FLOW_SCOPE_SINGLE`.
- **Negative control:** executed on `main`: `#flow_scope` displayed in `#flow_run_row` (`flow_screens.py:818-823`) → RED.
- **Boundary catalog:** none — the selector takes no input once hidden. Where multi-variant runs live after this is a PDR item (§6.2 item 12).

### LLR-146.13 — Flow Builder keyboard order
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The Flow Builder's focus order shall run header chips → kind chips → add inputs → Add → copy/paste strip → `Variables (n)` → foot row, every kind chip shall be focusable and set the kind on `enter` or `space`, and every control shall be operable by `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-51 — as TC-B97-41 over these seven groups; focus each kind chip and press `enter`, read `#flow_kind`.
- **Numeric pass threshold:** 0 group inversions; 7 of 7 kind chips set their kind by key.
- **Negative control:** executed on `main` (§2.7 P-33): 4 kind chips in the chain, `flow_scope` between paste and Run → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the EXT-STEP form open (most inputs). Others N/A.

### LLR-147.1 — Per-lane pipeline with cable status from the retained record
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When a run record is rendered, the `FlowExecutionPanel` shall paint lane *i* (0-based, the import order) from `last_run_record.outcomes[i]` (`flow_screens.py:2550-2553`) and paint the cable after block *j* (0-based) with the glyph the table below gives for block *j* and block *j+1*.

| block *j* status (`flow_model.py:99-108`) | block *j+1* status | cable glyph |
|---|---|---|
| any | `waiting` | `□` |
| `ok` | not `waiting` | `▓` (`_FX_BAR_DONE`, `flow_screens.py:1795`) |
| `notices` | not `waiting` | `◇` (NEW) |
| `error` | not `waiting` | `✗` |
| `skipped`, `waiting`, or no record yet | not `waiting` | `░` (`_FX_BAR_GAP`, `:1796`) |

- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-21 — feed records built from the five statuses (one arm per table row) and read the painted cable glyphs per lane (structured read of the lane `Text`); then the real 3-lane run of §5.3 (`patch_chain`, `flash_chain`, `err_chain`).
- **Numeric pass threshold:** 5 of 5 rows (6 status cells); with the executed record of §2.7 P-31, lane 0 cables `▓ ▓ ◇`, lane 1 cables `▓ □ ░`, lane 2 cables `✗ ░ ░`.
- **Negative control:** executed on `main`: the panel paints a progress bar, not per-cable glyphs — no cable carries `◇` or `□` between blocks → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no record yet → every cable `░`; boundary: a 1-block lane (0 cables). Others N/A — the statuses are a closed enum.

### LLR-147.2 — The rebind input sits inside the SOURCE card
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowExecutionPanel` shall place each `fx_in_<i>_<j>` input (`flow_screens.py:2178`) inside the region of lane *i*'s SOURCE card *j*.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-22 — region containment of each input in its card region at 118x54.
- **Numeric pass threshold:** every rebind input contained (0 outside).
- **Negative control:** the predicate needs the card region the new layout declares, so its RED run is executed on the Flow Execution increment's own tree with the input re-parented to the lane row (mutation, Phase 3, C-40) → containment fails, RED; it cannot run on `main`, where no card region exists.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a lane with two SOURCE blocks (two inputs, two cards). Others N/A.

### LLR-147.3 — The paused-lane doctrine, Confirm inside the lane and the viewport
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While a lane's record holds a `waiting` block, the `FlowExecutionPanel` shall paint that block's card in the waiting style, show two red pending lines (log, output file) under the lane header whose leading glyph is not in the LLR-147.1 cable vocabulary, show `#fx_confirm_<i>` inside the lane's region painted in the waiting style, and show the line `log + output file: REQUIRED` (NEW) above the run log; when a lane enters the waiting state, the panel shall scroll `#fx_lanes_scroll` so that the first waiting lane's Confirm lies inside its viewport and shall focus that Confirm.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-23 — two fixtures: the 3-lane run of §5.3 and `wait_third_6` (two 6-block lanes, then a 6-block lane paused at block 4). Read region containment of `#fx_confirm_<i>` in lane *i* and in `#fx_lanes_scroll`'s region, `app.focused.id`, the pending lines' spans and leading glyphs, the REQUIRED line before and after Confirm (pressed by `enter`).
- **Numeric pass threshold:** `#fx_confirm_<i>` contained in its lane and in the lanes viewport on both fixtures; `app.focused.id == "fx_confirm_<i>"`; other lanes' Confirm not displayed; 2 pending lines, leading glyph ∉ `{▓, ░, ✗, ◇, □}`; REQUIRED line count 1 while waiting, 0 after confirm.
- **Negative control:** executed on `main`: no REQUIRED line in the panel → RED; `wait_third_6` with the scroll-into-view step removed (mutation, Phase 3) → Confirm outside the viewport, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two lanes waiting at once (one REQUIRED line, two Confirms, the first one scrolled to and focused); the waiting lane below the fold (`wait_third_6`). Others N/A.

### LLR-147.4 — Two-row header; a two-word mode control
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowExecutionPanel` shall lay out a ribbon row (set identity, session directory, `#fx_import`, the mode control, `#fx_run`) and a set row (`#fx_set_name`, `#fx_save`, `#fx_set_select`, `#fx_load`), and shall present the mode as a two-word control (`sequential` / `parallel`) no wider than 30 cells, switchable by click, `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-24 — the eight ids inside the panel region at 118x54; the mode control's region width; switching the mode by key changes `last_run_record.mode` on the next Run (C-10, non-default `parallel`).
- **Numeric pass threshold:** 8 of 8 inside; mode control width ≤ 30 cells (today `#fx_mode` 80 at 118x54, P-31 probe `(21, 7, 80, 3)`); `record.mode == "parallel"` after choosing it by key.
- **Negative control:** executed on `main` (§2.7 P-11): `#fx_save`, `#fx_set_select`, `#fx_load` outside → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 and a 40-cell set name. Others N/A.

### LLR-147.5 — Flow Execution strings and run log in English
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowExecutionPanel` and the external-step summary and diagnostic strings of `services/flow_execution_service.py` that it paints shall be in English.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-25 — the `ES_MARKER` AST census keyed on the `FlowExecutionPanel` `ClassDef`, on the module constant `flow_screens.py:235`, and over `flow_execution_service.py` (docstrings excluded); reach guard on `9c7beaf` ≥ 17 (9 + 1 + 7); the painted lanes and run log of the 3-lane run and of a confirmed re-run, and every `block_results[*].summary` / `.diagnostics` line, matched against `ES_MARKER`. Pins rewritten in Inc 5: `test_flow_external_step_b96.py:265, 266, 302, 333, 345, 507, 508, 509, 514`.
- **Numeric pass threshold:** 0 `ES_MARKER` constants in the three scopes; reach guard ≥ 17 on `9c7beaf`; 0 matches in the painted text and in the record's summaries/diagnostics.
- **Negative control:** executed on `9c7beaf` (§2.7 P-17): 17 constants; the painted line `· ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: as LLR-146.7. Others N/A.

### LLR-147.6 — File-derived text in lanes renders literally (C-17)
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `FlowExecutionPanel` shall render every chain name, template name, bound ref, EXT-STEP `instruction`, `log_ref` and `output_path`, written path and session path on the lanes, the pending lines, the header and the run log as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-26 — a flow file named `HOSTILE_NAME` (P-27) whose EXT-STEP `instruction` and `log_ref` carry `HOSTILE_CONTENT` minus NUL (P-30) imported through `#fx_import` and run to the pause; read the lane, pending-line, header and log spans and plain text.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal in 4 surfaces; 0 spans originating in the payload; 0 control characters painted.
- **Negative control:** interpolate the chain name into a markup string (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-147.7 — The waiting hue belongs to the waiting-human elements
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The four panels shall paint the waiting token (LLR-146.6) only on waiting-human elements, and shall paint the notices glyph, the dirty marker and every other accent in colours whose hue lies at least 20° from the waiting token's hue.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-52 — run every screen's fixtures (§5.3) incl. the 3-lane paused run and a dirty Patch Editor document; walk every displayed widget's `render()` spans (and the lanes' painted grid) collecting `(colour, owner widget/element)`; the span set comes from the renderers' output, not a hand list.
- **Numeric pass threshold:** every span whose colour == the waiting token belongs to a waiting-human element; ≥ 1 such span while waiting (guard); every other distinct accent colour ≥ 20° hue from the waiting token.
- **Negative control:** executed on `main` (§2.7 P-16): `YELLOW #f6ff8f` paints the waiting state and the dirty strip → RED if PDR keeps that hue for waiting without moving the dirty strip; a notices glyph painted in the waiting token (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a CRC card beside the waiting card (`crc_wait_chain`). Others N/A.

### LLR-147.8 — No dead rows in Flow Execution; the lanes take the remaining height
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** While displayed, the `FlowExecutionPanel` shall paint no blank row outside `#fx_lanes_scroll` and no blank row between two consecutive lanes inside it, and shall give `#fx_lanes_scroll` the panel height its header rows and run log leave.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-53 — after the 3-lane run at 118x54 and 220x60: blank rows from the compositor strips (`render_strips()`, row blank ⇔ the panel slice `.strip() == ""`) outside `#fx_lanes_scroll`; blank rows between lane *i*'s last painted row and lane *i+1*'s first; `#fx_lanes_scroll.region.bottom == #fx_log.region.y` (or the REQUIRED line's y while waiting).
- **Numeric pass threshold:** 0 blank rows outside; 0 between lanes; the bottom equality holds at both sizes.
- **Negative control:** executed on `main` (§2.7 P-32): 3 blank rows outside at both sizes → RED; the inter-lane count on `main` is `assumed — measured in the Inc 5 RED run` (P-32 measured 9 / 16 blank rows inside the scroll, not yet split between inter-lane and trailing).
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no lanes → `#fx_empty` line only, still 0 blank rows outside; boundary: 118x54 and 220x60. Others N/A.

### LLR-147.9 — Flow Execution filled elements
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The `FlowExecutionPanel` shall paint exactly one filled element besides the lanes hero, `#fx_run`, plus `#fx_confirm_<i>` for each waiting lane.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-54 — the filled list as TC-B97-42, before the run and while lane 1 waits.
- **Numeric pass threshold:** before: `['fx_run']`; waiting: `['fx_run', 'fx_confirm_1']`.
- **Negative control:** a primary Import (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two lanes waiting (two Confirms). Others N/A.

### LLR-147.10 — One run at a time
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** If Run is pressed while a run is in flight, then the `FlowExecutionPanel` shall start no second run; while a run is in flight `#fx_run` shall be disabled, and if the run executes off the UI thread the run log shall show the English line `running…` (NEW) until it ends; when the run ends `#fx_run` shall be enabled again.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-55 — wrap `run_chain_set` (called synchronously from `app.py:2815` today) so that during its execution it presses `#fx_run` once more (`button.press()`, which queues a `Pressed` message); after the run, settle and count `run_chain_set` calls; read `#fx_run.disabled` inside the wrapper and after. For a worker mechanism (PDR §6.2 item 13), the wrapper also reads the log for `running…`.
- **Numeric pass threshold:** 1 call for 2 presses; disabled inside, enabled after; worker mechanism only: the running line present inside, absent after.
- **Negative control:** on `main` the queued press is delivered after the handler returns, with `#fx_run` enabled — a second run is expected, `assumed — measured in the Inc 5 RED run`.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a press right after the run ends starts a run (1 more call); error: a run that raises → `#fx_run` enabled and one English error line (LLR-148.9). Others N/A.

### LLR-147.11 — Flow Execution keyboard order
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** The Flow Execution focus order shall run header chips → `#fx_import` → mode control → `#fx_run` → set row → lanes (per lane: rebind inputs, then Confirm), and every control shall be operable by `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-56 — as TC-B97-41 over these groups after the 3-lane run.
- **Numeric pass threshold:** 0 group inversions; `fx_confirm_1` after `fx_in_1_0` and before `fx_in_2_0`.
- **Negative control:** executed on `main` (§2.7 P-33): no header chip in the chain → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: no lanes. Others N/A.

### LLR-148.1 — Chip family `flows`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `folder_open_service` shall declare a `flows` chip family (NEW `CHIP_FAMILY_FLOWS`) whose target is `project_dir / FLOWS_SUBDIR` (imported from `flow_persistence_service.py:95`, never re-declared) and `None` without a project; if the press path creates a missing `flows` folder (the create decision is PDR's), it shall create it only through `create_chip_home` (`folder_open_service.py:279`) and only at a path whose resolved form lies inside the resolved project directory.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-27 — `resolve_chip_target(p, family="flows", …)` and `(None, …)`; an AST import check that `folder_open_service` imports `FLOWS_SUBDIR` and holds no `"flows"` literal; with `p/"flows"` absent and the create branch chosen, `create_chip_home(p, family="flows", …)` then `target.resolve().is_relative_to(p.resolve())`.
- **Numeric pass threshold:** `== p / "flows"`; `is None`; 1 import, 0 literals; created path inside `p` (create branch only).
- **Negative control:** executed on `main`: `"flows" in CHIP_FAMILIES` is False → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no project; boundary: `flows` absent. Others N/A.

### LLR-148.2 — Chip family `session`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `folder_open_service` shall declare a `session` chip family (NEW `CHIP_FAMILY_SESSION`) whose target is the active project directory itself — the value `_publish_flow_session_dir` pushes (`app.py:8130-8137`) — and `None` without a project, and the `session` chip shall never create a folder.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-28 — `resolve_chip_target(p, family="session", …)` and `(None, …)`; press the `session` chip with `p` deleted after resolution and spy `create_chip_home`.
- **Numeric pass threshold:** 2 of 2 arms — `== p` with a project, `is None` without one; 0 `create_chip_home` calls for `session`.
- **Negative control:** executed on `main`: `"session" in CHIP_FAMILIES` is False → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no project; boundary: the project dir removed under the app (refusal line, no create). Others N/A.

### LLR-148.3 — The no-project message names the family's folder
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** If a chip's target resolves to `None`, then the `OpenFolderChip` shall disable itself and set a status message that names that chip's family folder, never another family's.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-29 — no project; for every family of `folder_open_service.CHIP_FAMILIES` (the rule's set, read at test time, guard `len >= 6`) whose target is `None` without a project, mount its chip and read the status after refresh.
- **Numeric pass threshold:** every such message names its own family; 0 messages naming `Reports` for a non-`reports` family; ≥ 3 families exercised (`reports`, `flows`, `session`).
- **Negative control:** executed on `main`: `open_folder_chip.py:115` sets `REPORTS_NO_PROJECT_REASON` for any `None` target — the message for a `flows` chip would read "(Reports)" → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project. Others N/A.

### LLR-148.4 — Chip ids unique in the app
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The system shall give each mounted open-folder chip an id no other mounted widget carries, and the Check Editor's chip shall resolve the `checks` family home; the id scheme (scoping vs a suffix) is decided at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-30 — `collections.Counter(w.id for w in app.query("OpenFolderChip"))` after compose; press the Check Editor chip and read the spied target.
- **Numeric pass threshold:** every count == 1 (6 chips: patch, checks ×2 screens, templates, flows, session; reports lives in its modal); the Check Editor target == the `checks` home.
- **Negative control:** executed on `main` (§2.7 P-19): a second `OpenFolderChip("checks")` yields `open_folder_checks` twice → count 2, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the Reports modal open at the same time (its chip counted too). Others N/A.

### LLR-148.5 — Headers of the four screens carry both chips
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `S19TuiApp` shall build the Check Editor, Flow Builder and Flow Execution headers with `titled_header` (`open_folder_chip.py:185`) carrying an `OpenFolderChip` (families `checks`, `flows`, `session`) and a `WindowHelpChip`, as the Patch Editor header already does (`app.py:3048-3049`), and a press on each enabled folder chip shall make exactly one call to the open seam with its resolved target.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-31 — for each of `#screen_patch`, `#screen_check_editor`, `#screen_flow`, `#screen_flow_execution`: one `OpenFolderChip` and one `WindowHelpChip` inside its `.db-screen-header`; with a project, press each folder chip (click and `enter`) under the `SeamSpy`.
- **Numeric pass threshold:** 4 of 4 screens with 1 + 1 chips (today 1 of 4 with both: `app.py:3082` bare Label; `:2404` help only; `:2438` neither); 1 seam call per press, target == `resolve_chip_target(…)` for the family.
- **Negative control:** executed on `main`: 1 of 4 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 (the chips inside the header row). Others N/A.

### LLR-148.6 — Help entries name every control, tab, key and glyph as `label — effect`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The `window_help` module shall carry an entry for each of the four screens — `patch` and `flow` rewritten, a Check Editor key and a Flow Execution key added (NEW, names fixed at PDR) to `WINDOW_HELP_SECTIONS` and `SHIPPED_WINDOW_KEYS` (`window_help.py:57`, `:270`) — whose body holds one `label — effect` line, with a non-empty effect, for every button label, tab label, key binding and glyph its screen renders.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-32 — per screen, the coverage set = rendered button and tab-chip labels (glyph prefix stripped) collected from the live DOM ∪ the screen's active key bindings (`panel.BINDINGS` ∪ the screen-scoped app bindings, plus `enter`/`space` on chips) ∪ the glyphs LLR-148.7 collects from the renderer (the rule's sets, C-40 limb 2); parse `section_body_text(key)` into lines split on ` — ` and match each member to a line's label part; `tests/test_window_usage_help.py:95-107` `_EXPECTED_KEYS` grows by the two keys.
- **Numeric pass threshold:** 100 % coverage on each of the 4 screens, every matched line with a non-empty effect; guards: coverage-set size ≥ 19 (patch), ≥ 6 (check), ≥ 13 (flow), ≥ 4 (execution) — today's button counts (P-21), so a DOM read that returns too few members fails.
- **Negative control:** executed on `main` (§2.7 P-21): 6/19 · 0/6 · 2/13 · 0/4 → RED; a body listing the labels without ` — effect` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a label carrying a glyph prefix (`⊕ CRC`) is matched on its words. Others N/A.

### LLR-148.7 — A legend for every glyph vocabulary on screen
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The four panels shall each paint a one-line legend (id NEW) naming every glyph its renderers paint — the Patch Editor's before→after strip cues, the Check Editor's `☑` (picked) and `▪` (memory row) marks, the Builder's own card and cable glyphs, Flow Execution's cable glyphs of LLR-147.1 and its pending-line glyph — with one meaning per glyph and the word `notices` for every non-blocking finding on the four screens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-33 — run each screen's fixtures (§5.3, incl. the 3-lane run, so `▓ ░ ✗ ◇ □` are all painted); collect the non-alphanumeric glyphs painted inside each vocabulary region (ledger mark column, card band, lanes, strip) from the compositor strips; each must appear in that panel's displayed legend text; grep the four panels' painted text for `issues`.
- **Numeric pass threshold:** 0 painted vocabulary glyphs missing from the legend; guards: painted set size ≥ 5 (execution), ≥ 2 (check), ≥ 1 (builder); 0 painted `issues` used for a non-blocking finding; no glyph listed with two meanings.
- **Negative control:** executed on `main`: no legend widget in `#fx_panel` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the legend fits on one painted row at 118x54 (LLR-149.4). Others N/A.

### LLR-148.8 — A chip opens only a real directory inside its family root
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** When a folder chip is pressed, the `OpenFolderChip` shall call the open seam only if its target is a directory (`is_dir()`), is not a reparse point (symlink or junction: `os.lstat(t).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT == 0` on Windows, `not t.is_symlink()` elsewhere) and resolves inside its family root (the project directory for project-only families); otherwise it shall set an English refusal status naming the folder and make 0 seam calls.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-57 — with a project in `tmp_path`: `flows` as a regular file; `flows` as a junction to a directory outside the project (`_winapi.CreateJunction`, P-34; a symlink on POSIX); `flows` a real directory. Press the chip under the `SeamSpy`.
- **Numeric pass threshold:** file → 0 calls + refusal; junction → 0 calls + refusal; real dir → 1 call.
- **Negative control:** executed on `main` (§2.7 P-34, `open_folder_chip.py:118` checks only `exists()`): a junction passes `is_dir()` and `not is_symlink()` → the seam is called, RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☒ error — invalid: file and junction; error: `lstat` raising (target vanished) → refusal, 0 calls. Others N/A.

### LLR-148.9 — Region states in one English line
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** While a region of the table below is in a listed state, the panel shall paint in that region one English line naming the state, and no traceback.

| screen | region | states |
|---|---|---|
| Patch Editor | ledger · hex strip · JSON tab · Checks tab | empty (no document / no image) · error (load refused: its finding) |
| Check Editor | parameter ledger · REPORT FIELDS card | empty (no A2L / nothing included) · error (write refused) |
| Flow Builder | pipeline · ribbon | empty (no blocks / no session) · error (load refused) |
| Flow Execution | lanes · run log | empty (no lanes) · running (worker mechanism, LLR-147.10) · error (run raised) |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-58 — one arm per table cell state, each driven through the shipped control (Load of a missing path, Write into a read-only dir, a flow file refused by `load_flow_json`, a run whose `run_chain_set` raises); read the region's painted text.
- **Numeric pass threshold:** per arm exactly 1 painted state line, 0 `ES_MARKER` matches, 0 lines containing `Traceback`.
- **Negative control:** executed on `main`: the Flow Builder with no blocks shows no English empty line in a pipeline (no pipeline exists) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☒ error — empty and error: the table. Others N/A.

### LLR-149.1 — Widths derived at mount and on resize
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** When one of the four panels mounts or receives a resize, it shall derive its column widths, panel split, input widths and region heights from its current content size.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-34 — in one session at 118x54, `pilot.resize_terminal` to 160x56, 220x60, 260x70, then back to 118x54; read the LLR-149.5 elements' widths after each step.
- **Numeric pass threshold:** each element's width non-decreasing along 118 → 160 → 220 → 260 and strictly greater at 220 than at 118; back at 118x54 equal to the first reading.
- **Negative control:** executed on `main` (§2.7 P-22): `#flow_ext_instruction` 28 at both 118x54 and 220x60 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: four resizes in one session. Others N/A.

### LLR-149.2 — No horizontal overflow over the range
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While displayed at any width of at least 118 columns and height of at least 54 rows, on either side of the 120-column `width-narrow` breakpoint, each of the four panels shall keep every displayed descendant's painted region inside the panel's region on the x axis.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-35 — the §2.7 P-10 probe as a test, per screen at the samples 118x54, 119x54, 120x54, 160x56, 220x60, 260x70: count displayed descendants with `region.right > panel.region.right` or `region.x < panel.region.x` (reads `region`, not `max_scroll_x`, which reads 0 on a clipped overflow, C-32); assert `#workspace_body` has the `width-narrow` class at 119 and not at 120.
- **Numeric pass threshold:** 0 on 24 of 24 screen×sample cells; the class flips between 119 and 120.
- **Negative control:** executed on `main` (§2.7 P-10): 1/1/2/7 at 118x54 and 1/1/1/6 at 220x60 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: 118, the 119↔120 breakpoint, 260; error: the widest real values (60-cell ref, 47-cell name, 40-cell set name).

### LLR-149.3 — Primary actions inside the viewport over the range
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While displayed at any size of at least 118x54 with the panel scrolled to its top, each panel shall keep its primary actions inside the panel region: `#patch_doc_load_button`, `#patch_doc_save_button`, `#patch_doc_validate_button`, `#patch_doc_apply_button`; `#check_validate_button`, `#check_write_button`; `#flow_run`; `#fx_run`, `#fx_save`, `#fx_load`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-36 — region containment of each id in its panel region at scroll 0, at the LLR-149.2 samples, with `patch_chain` and the EXT-STEP form open.
- **Numeric pass threshold:** 10 of 10 inside at every sample.
- **Negative control:** executed on `main` (§2.7 P-11): `#flow_run (51, 48, 16, 3)` past the panel bottom 44, `#fx_save` and `#fx_load` outside → 7 of 10 at 118x54, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 with the EXT-STEP form open (the tallest add form). Others N/A.

### LLR-149.4 — No wrapped row; truncation keeps the discriminating part
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** The four panels shall paint each logical row of their no-wrap set (§1.3) on exactly one terminal row, truncating with one ellipsis by element class — file names and paths keep the tail, labels and headings keep the head, parameter names keep the first segment and the tail (LLR-145.3), addresses are never truncated — and no two painted rows of one ledger shall be equal unless their records are equal. The Check Editor's `Fmt · Unit` column shall show the parameter's width `u<bits>` and its A2L unit (`screens_directionb.py:7039`), the unit clipped before the width.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-37 — per screen, the no-wrap set read from the DOM by category (ledger rows, run-log lines, pipeline rows, ribbons, legends, inspector headings, REPORT FIELDS lines — ids fixed at PDR), guard ≥ 1 member per category the screen has; for each `Static`, painted height == its logical line count; for each `DataTable`, every row's painted height 1 and each cell's painted cell length ≤ its column's render width (`get_render_width`), read from `_render_line` (C-32); per ledger, the painted rows compared pairwise; at the LLR-149.2 samples with the widest real values.
- **Numeric pass threshold:** 0 wrapped rows; 0 cells longer than their column; 0 equal painted row pairs with different records (75-row parameter ledger, 6-entry patch ledger, lanes); per truncated cell, the kept end matches its class.
- **Negative control:** a 20-cell width forced on `#fx_log` (mutation, Phase 3, C-40) → painted height > line count, RED; a tail-only parameter truncation → equal `ASAM.M.SCALAR.UBYTE.*` rows, RED; on `main` the inspector-heading arm has no inspector (02-review U-15), RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a log line exactly the panel width; error: the widest real values.

### LLR-149.5 — The space goes to the growing region: no width or height void
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2
- **Statement:** While displayed at any size of at least 118x54, the four panels shall give their adaptive elements — the Patch Editor ledger, the Check Editor parameter table and its Parameter column, the Flow Builder pipeline and EXT-STEP inputs, the Flow Execution lanes — the width their split assigns, the painted extent of each reaching the end of its region within the bound the PDR card-growth choice sets (§6.2 item 11), and shall give the height the docked rows leave to the screen's growing region (ledger, parameter table, pipeline area, lanes), so that no blank row lies outside it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-38 — at 160x56, 220x60, 260x70: per adaptive region, `void = region.right − (painted extent + 1)` read from the compositor strips over the region's rows (§1.3). Card bands (pipeline, lanes): **grow** choice → `void ≤ 2` for any flow of ≥ 1 card; **more per band** choice → each full band's void < one card width + one cable, and a band breaks only when the next card does not fit. Tables: `void ≤ 2` on the header row. EXT-STEP inputs: `sum(widths) + gaps ≥ row width − 2`. Height: blank painted rows outside the growing region (the P-32 method) at 118x54 and 220x60.
- **Numeric pass threshold:** every void within its bound; the 47-cell name in full at 220x60; 0 blank rows outside the growing region on each screen.
- **Negative control:** executed on `main` (§2.7 P-22, P-32): EXT-STEP inputs equal at both sizes; Patch 3 / 2 blank rows outside the ledger → RED. Check 0 / 0 is a regression **pin**, not a gate; the Builder's base count is `assumed — measured in the Inc 4 RED run`.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 160x56 (off-grid), 260x70 (above the reference). Others N/A.

### LLR-149.6 — Below 118x54 the four screens stay reachable under scroll
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.2
- **Statement:** While displayed below 118x54 down to the shipped 80x24 floor, each of the four panels shall keep every LLR-149.3 action reachable by scrolling the panel, without overlapping buttons.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-59 — at 80x24 and 100x40: for each LLR-149.3 id, `panel.scroll_to_widget(w)` then region containment in the panel region; pairwise region intersection of the displayed buttons.
- **Numeric pass threshold:** 10 of 10 reachable at both sizes; 0 overlapping button pairs.
- **Negative control:** a panel with `overflow: hidden` (mutation, Phase 3) → an action unreachable, RED; on `main` (§2.7 P-10) `#fx_load` sits at x = 134 in a panel whose `max_scroll_x` reads 0 → unreachable, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 80x24 (the shipped floor, LLR-007.1 / CV-04). Others N/A.

### Information Flow Contract (IFC) — C-54

> Part A — one FLOW block per information flow this batch adds or re-routes; every node has exactly one owner LLR. LLRs that state structure rather than a transform (144.1-144.4, 144.9-144.11, 145.4, 145.7-145.9, 146.5, 146.7, 146.9, 146.12, 146.13, 147.2, 147.4, 147.8, 147.9, 147.11, 148.4, 148.7, 148.9, 149.2-149.6) own Part B outputs or are verified on the painted layout instead of owning nodes. Part B — the trigger question is answered **yes**: the four panels and their header chips are components a consumer addresses independently (tests and the app select a panel by id and index its children). Component ids are new (V19: one id, one declaration, across the corpus — batch-94 already declared `patch_editor_panel` & co.).

- **Part A — flows:**

```
FLOW: change_doc_to_json_tab
  SOURCE : a v2 change-set file in the patches folder, chosen by the Patch Editor's Load
  NODES  :
    - fn    : ChangeService.load (change_service.py:1355) — the file becomes the owned document
      owner : LLR-144.5
      in    : path text + base dir
      out   : ChangeDocument (6 entries for the fixture)
    - fn    : serialize_change_document (changes/io.py:1392)
      owner : LLR-144.5
      in    : ChangeDocument
      out   : canonical v2 JSON bytes (706 bytes, 39 lines for the fixture)
    - fn    : app-to-panel JSON feed at the refresh_entries sites (I-3, NEW), read-only view capped at JSON_TAB_LINE_CAP lines + note
      owner : LLR-144.5
      in    : canonical v2 JSON text
      out   : the JSON tab's text (first CAP lines + "showing N of M lines" when longer)
  SINK   : the JSON tab #patch_win_json, read by the engineer
```

```
FLOW: entry_change_to_json_tab
  SOURCE : any of the nine document writers (§2.7 P-6) — eight Patch Editor controls, plus add_symbol_entry (no UI caller)
  NODES  :
    - fn    : the ChangeService writers of the document (change_service.py:861, :893, :1080, :1154, :1196, :1223, :1344, :1404, :1465)
      owner : LLR-144.6
      in    : the entry action
      out   : the changed ChangeDocument
    - fn    : JSON tab refresh — live, or Update JSON with the generated-from stamp (NEW; mechanism decided at PDR)
      owner : LLR-144.6
      in    : the changed ChangeDocument
      out   : the JSON tab's text (+ stamp)
  SINK   : the JSON tab #patch_win_json
```

```
FLOW: document_identity_to_ribbon
  SOURCE : ChangeDocument.source_path and .kind (changes/model.py:253, :258)
  NODES  :
    - fn    : identity feed through refresh_entries keyword or setter (I-2, NEW; shape decided at PDR)
      owner : LLR-144.7
      in    : Optional[Path], str
      out   : name + kind strings
    - fn    : safe_text render (utils.py:44) of the name, kind and every file-derived entry field
      owner : LLR-144.7
      in    : name, kind, entry value / symbol / address text, finding messages (file-derived)
      out   : rich Text with no markup parsed
  SINK   : the identity ribbon (NEW), the ledger, the inspector pane, the JSON tab, #patch_doc_issues
```

```
FLOW: highlighted_row_to_hex_strip
  SOURCE : the ledger's highlighted row (DataTable cursor) + the loaded image
  NODES  :
    - fn    : before/after byte read for the highlighted entry, changed bytes marked with a text attribute (NEW)
      owner : LLR-144.8
      in    : ChangeEntry (address, encoded bytes) + image bytes at that address
      out   : hex strip Text (before, after, attribute on changed cells)
  SINK   : the inspector's hex strip (NEW)
```

```
FLOW: a2l_parameters_to_check_ledger
  SOURCE : the loaded A2L file
  NODES  :
    - fn    : S19TuiApp._prefill_check_editor (app.py:5329) — one row per tag with an integer address
      owner : LLR-145.1
      in    : parsed A2L tags
      out   : parameter rows (75 for ASAP2_Demo_V161.a2l)
    - fn    : Address column sizing and placement
      owner : LLR-145.2
      in    : parameter rows + table content width
      out   : column widths with Address fully inside the viewport
    - fn    : first-segment + ellipsis + tail name truncation
      owner : LLR-145.3
      in    : parameter name + column width
      out   : painted name (head segment + … + tail, or full)
    - fn    : REPORT FIELDS composition — Fields lines, JSON spec, Addendum preview (NEW layout over the shipped collector)
      owner : LLR-145.6
      in    : included parameters + memory rows
      out   : ☑/▪ lines, spec JSON, addendum
    - fn    : safe_text render of names and spec file names
      owner : LLR-145.5
      in    : file-derived names
      out   : rich Text with no markup parsed
  SINK   : #check_param_table and the REPORT FIELDS card
```

```
FLOW: flow_template_to_pipeline
  SOURCE : a flow JSON in the project's flows folder (Load…), or blocks added by Add
  NODES  :
    - fn    : FlowBuilderPanel.set_blocks (flow_screens.py:878) and the pipeline layout (NEW)
      owner : LLR-146.1
      in    : Flow (blocks in order)
      out   : one card per block, cables between
    - fn    : card text clipping
      owner : LLR-146.4
      in    : card title and IO lines
      out   : lines no wider than the card
    - fn    : CRC family paint with the CRC token of the PDR pair (NEW)
      owner : LLR-146.6
      in    : block kind
      out   : card style
    - fn    : session directory onto the ribbon (set_session_dir → #flow_name_strip)
      owner : LLR-146.11
      in    : session dir path
      out   : ribbon text, tail kept
    - fn    : funnel count into the Variables (n) label (flow_screens.py:1243)
      owner : LLR-146.10
      in    : len(funnel)
      out   : chip label
    - fn    : safe_text render of flow names, refs, EXT-STEP instruction / log_ref / output_path, paths
      owner : LLR-146.8
      in    : file-derived strings
      out   : rich Text with no markup parsed
  SINK   : the Flow Builder pipeline (NEW) and ribbon
```

```
FLOW: palette_kind_to_add_form
  SOURCE : a palette chip press
  NODES  :
    - fn    : FlowBuilderPanel.on_button_pressed flow_palette_ prefix (flow_screens.py:1455-1461)
      owner : LLR-146.2
      in    : chip id
      out   : #flow_kind value
    - fn    : FlowBuilderPanel._sync_kind_dependent_visibility (flow_screens.py:1534)
      owner : LLR-146.3
      in    : kind
      out   : displayed add inputs
  SINK   : the add form
```

```
FLOW: run_record_to_lane_cables
  SOURCE : the ChainSetRunRecord returned by run_chain_set (app.py:2815)
  NODES  :
    - fn    : FlowExecutionPanel.render_run cable glyphs (flow_screens.py:2399)
      owner : LLR-147.1
      in    : record.outcomes[i].block_results
      out   : one glyph per cable per lane
    - fn    : paused-lane paint, pending lines, Confirm placement, scroll-into-view + focus, REQUIRED line
      owner : LLR-147.3
      in    : waiting block index per lane
      out   : waiting-styled card + #fx_confirm_<i> inside the lane and the lanes viewport, focused
    - fn    : waiting-hue assignment restricted to waiting-human elements
      owner : LLR-147.7
      in    : element kind (waiting-human or not)
      out   : span colour
    - fn    : external-step summaries and diagnostics (flow_execution_service.py:501, :846, :860, :867, :885) and run-log lines in English
      owner : LLR-147.5
      in    : outcome status + block index + block fields
      out   : English summary / diagnostic / log lines
    - fn    : safe_text render of chain names, refs, EXT-STEP fields, written paths
      owner : LLR-147.6
      in    : file-derived strings
      out   : rich Text with no markup parsed
  SINK   : #fx_lanes and #fx_log
```

```
FLOW: run_press_to_single_run
  SOURCE : a #fx_run press (click or key)
  NODES  :
    - fn    : in-flight guard — disable #fx_run, drop a press while a run is in flight (NEW)
      owner : LLR-147.10
      in    : press + in-flight flag
      out   : 0 or 1 RunRequested
  SINK   : on_flow_execution_panel_run_requested (app.py:2776)
```

```
FLOW: project_dir_to_folder_chip
  SOURCE : S19TuiApp.active_project_dir() (Path or None)
  NODES  :
    - fn    : resolve_chip_target, flows family (folder_open_service.py:232)
      owner : LLR-148.1
      in    : project dir
      out   : project_dir / FLOWS_SUBDIR, or None
    - fn    : resolve_chip_target, session family
      owner : LLR-148.2
      in    : project dir
      out   : project_dir, or None
    - fn    : OpenFolderChip.refresh_target per-family no-project status (open_folder_chip.py:92-127)
      owner : LLR-148.3
      in    : None target + family
      out   : disabled chip + status naming the family folder
    - fn    : real-directory guard — is_dir, not a reparse point, inside the family root (NEW)
      owner : LLR-148.8
      in    : resolved target
      out   : the target, or a refusal status
    - fn    : OpenFolderChip._open_target to the open seam (open_folder_chip.py:139)
      owner : LLR-148.5
      in    : guarded target
      out   : one open call
  SINK   : the OS file manager, or the status line
```

```
FLOW: help_chip_to_modal
  SOURCE : a WindowHelpChip press on one of the four screens
  NODES  :
    - fn    : open_window_help + section_body_text (window_help.py:290, :305)
      owner : LLR-148.6
      in    : window key
      out   : the section body text
  SINK   : the WindowHelpScreen modal
```

```
FLOW: terminal_size_to_layout
  SOURCE : the terminal size at mount and on each Resize event
  NODES  :
    - fn    : per-panel width and height derivation (NEW, on mount and on_resize)
      owner : LLR-149.1
      in    : panel content size
      out   : column widths, split, input widths, growing-region height
    - fn    : ellipsis truncation keeping the discriminating part
      owner : LLR-149.4
      in    : row text + its width
      out   : one painted row per logical row
  SINK   : the painted layout of the four panels
```

- **Part B — boundary decomposition:** yes — the TUI panels are components a consumer addresses on their own. Parent: `workspace_shell`, the outermost declared boundary (`docs/architecture.md` §11), which is not itself a COMPONENT anywhere in the corpus, so `V12` balancing reports *could not be tested* for these blocks (the batch-87/94 precedent, a NOTICE, not a pass). Addresses marked COMPUTED are built at runtime (`f"#fx_confirm_{i}"`, `f"open_folder_{family}"`, `f"window_help_{key}"`); `V13` cannot grep them, and their consumers were measured with the id census of §2.7 P-3 and `grep -rl` (2026-10-20).

```
COMPONENT: pe_ledger_inspector
  PARENT : workspace_shell
  SURFACE: Patch Editor (batch-97 pe_A port)
  INPUTS : change_document: ChangeDocument ; document_json: str ; loaded_image: dict
  OUTPUTS:
    - id          : entries_ledger
      value       : one row per document entry (Kind, Address, Value / bytes, Status, Linkage)
      address     : query("#patch_doc_entries_table"), INDEXED POSITIONALLY
      cardinality : len(document.entries)
      consumers   : s19_app/tui/screens_directionb.py
                    s19_app/tui/styles.tcss
                    tests/test_tui_checks_screen.py
                    tests/test_tui_patch_big.py
                    tests/test_tui_patch_card.py
                    tests/test_tui_patch_checks_strip.py
                    tests/test_tui_patch_editor_b94.py
                    tests/test_tui_patch_editor_v2.py
                    tests/test_tui_patch_glyphs.py
                    tests/test_tui_patch_layout.py
                    tests/test_tui_patch_variant.py
      owner       : LLR-144.2
    - id          : json_tab
      value       : the document the editor holds, as canonical v2 JSON
      address     : query("#patch_win_json")
      cardinality : 1
      consumers   : s19_app/tui/screens_directionb.py
                    s19_app/tui/styles.tcss
                    tests/test_tui_patch_big.py
                    tests/test_tui_patch_card.py
                    tests/test_tui_patch_editor_v2.py
                    tests/test_tui_patch_history_strip.py
                    tests/test_tui_patch_json.py
                    tests/test_tui_patch_layout.py
                    tests/test_tui_patch_variant.py
                    tests/test_tui_snapshot.py
      owner       : LLR-144.5
    - id          : identity_ribbon
      value       : the loaded file name and kind (or draft)
      address     : query("#patch_identity_ribbon")
      cardinality : 1
      consumers   : none
      owner       : LLR-144.7
```

```
COMPONENT: ce_ledger_inspector
  PARENT : workspace_shell
  SURFACE: Check Editor (batch-97 ce_A port)
  INPUTS : a2l_parameters: list ; check_spec_entries: list ; spec_file_listing: list
  OUTPUTS:
    - id          : parameter_ledger
      value       : one row per A2L parameter (mark, Parameter, Address, Fmt · Unit)
      address     : query("#check_param_table"), INDEXED POSITIONALLY
      cardinality : one per A2L parameter (75 in the fixture)
      consumers   : s19_app/tui/screens_directionb.py
                    tests/test_tui_check_editor.py
      owner       : LLR-145.2
    - id          : write_action
      value       : the docked Write .chk.json action
      address     : query("#check_write_button")
      cardinality : 1
      consumers   : tests/test_tui_check_chain_b94.py
                    tests/test_tui_check_editor.py
      owner       : LLR-145.1
    - id          : fields_count
      value       : the collected field count on the docked row
      address     : query("#check_fields_count")
      cardinality : 1
      consumers   : s19_app/tui/screens_directionb.py
      owner       : LLR-145.1
```

```
COMPONENT: fb_pipeline_rail
  PARENT : workspace_shell
  SURFACE: Flow Builder (batch-97 fb_A port)
  INPUTS : flow: Flow ; flow_name: str ; session_dir: str
  OUTPUTS:
    - id          : pipeline
      value       : one card per block in block order, cables between
      address     : query("#flow_pipeline"), INDEXED POSITIONALLY
      cardinality : len(flow.blocks)
      consumers   : none
      owner       : LLR-146.1
    - id          : palette
      value       : one chip per placeable kind
      address     : query("#flow_palette")
      cardinality : 7
      consumers   : tests/test_flow_external_step_b96.py
                    tests/test_tui_flow_builder_b94.py
      owner       : LLR-146.2
    - id          : run_action
      value       : the Run chip, the only primary button
      address     : query("#flow_run")
      cardinality : 1
      consumers   : tests/test_flow_builder_render.py
                    tests/test_flow_crc_ui.py
                    tests/test_flow_multi_image_ui.py
                    tests/test_flow_report_ui.py
                    tests/test_tui_directionb.py
                    tests/test_tui_flow_builder_b94.py
      owner       : LLR-146.5
```

```
COMPONENT: fx_pipeline_rail
  PARENT : workspace_shell
  SURFACE: Flow Execution (batch-97 fx_A port)
  INPUTS : run_record: ChainSetRunRecord ; lanes: list ; session_dir: str
  OUTPUTS:
    - id          : lanes
      value       : one pipeline per lane, cables carrying block status
      address     : query("#fx_lanes"), INDEXED POSITIONALLY
      cardinality : one per imported lane (lane i reads record.outcomes[i])
      consumers   : s19_app/tui/flow_screens.py
                    tests/test_tui_flow_execution_b94.py
      owner       : LLR-147.1
    - id          : confirm
      value       : the waiting lane's Confirm, inside its lane
      address     : query("#fx_confirm_<i>") COMPUTED
      cardinality : 1 per lane
      consumers   : tests/test_flow_external_step_b96.py
      owner       : LLR-147.3
    - id          : run_log
      value       : English run-log lines
      address     : query("#fx_log")
      cardinality : 1
      consumers   : s19_app/tui/flow_screens.py
                    tests/test_flow_external_step_b96.py
                    tests/test_tui_flow_execution_b94.py
      owner       : LLR-147.5
    - id          : set_row
      value       : set name, Save Set, saved sets, Load Set
      address     : query("#fx_set_row")
      cardinality : 1
      consumers   : s19_app/tui/flow_screens.py
      owner       : LLR-147.4
```

```
COMPONENT: screen_header_chips
  PARENT : workspace_shell
  SURFACE: the headers of Patch Editor, Check Editor, Flow Builder, Flow Execution
  INPUTS : active_project_dir: Path ; family: str ; window_key: str
  OUTPUTS:
    - id          : folder_chip
      value       : the open-folder chip of the screen's family
      address     : query("#open_folder_<family>") COMPUTED
      cardinality : exactly 1 widget per id
      consumers   : s19_app/tui/app.py
                    s19_app/tui/open_folder_chip.py
                    s19_app/tui/screens.py
                    s19_app/tui/services/folder_open_service.py
                    s19_app/tui/styles.tcss
                    tests/test_open_folder_chips.py
                    tests/test_window_usage_help.py
                    tests/test_segment_split_window.py
                    tests/test_id_registry.py
      owner       : LLR-148.4
    - id          : help_chip
      value       : the window's ? chip
      address     : query("#window_help_<key>") COMPUTED
      cardinality : 1 per window key
      consumers   : tests/test_window_usage_help.py
                    tests/test_segment_split_window.py
      owner       : LLR-148.6
    - id          : glyph_legend
      value       : the one-line legend of the screen's glyph vocabulary
      address     : query(".glyph-legend")
      cardinality : 1 per panel
      consumers   : none
      owner       : LLR-148.7
```

> `consumers : none` is written where no file reaches the address today because the address is NEW (`#patch_identity_ribbon`, `#flow_pipeline`, `.glyph-legend` — working names fixed at PDR). The defining modules are declared as consumers (they query their own ids and break if the address moves); a docstring that names an id is a mention, not a dependant (`screens.py:331` and `change_service.py:1237` name `#patch_doc_entries_table` in prose only, re-read 2026-10-20); `REQUIREMENTS.md` and `.fast-dev-flow/archive/…` reach two addresses as prose mentions and are not dependants; `prototypes/**` is never imported (the ARQ boundary) and is not declared. The batch's ATs/TCs become their consumers in Phase 3 and the Phase-4 record re-runs `V13`/`V14`.

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-B97-01` … `TC-B97-59`):** one TC per LLR, validating the mechanism. Methods: `test (unit)` / `test (integration)` under `App.run_test` (Textual 8.2.8, pytest — the project's ratified runtime, `pyproject.toml:66-73`).
> - **Layer B — black-box / behavioral acceptance (`AT-B97-01` … `AT-B97-24`):** at least two per story, driving the shipped controls only (`pilot.click` / `pilot.press` on shipped ids, Load / Import / Run / chip presses, `pilot.resize_terminal`; never a panel method such as `add_lane` or `_patch_editor_load`) and observing the painted result (C-32: `region`, `_render_line`, compositor strips, `render().spans`; C-42: parse the emitted JSON / Text, never substring-match the readable form). The driver, fixture and RED arm of each AT are in §5.3.

- **C-10 (one AT per policy branch, a non-default value driven through the real control):** JSON tab after Load (AT-B97-01) vs after Add (AT-B97-02); Address at 118 vs 220 and Include changing the count (AT-B97-04); Fields / JSON / Addendum tabs (AT-B97-21); palette kinds — one arm per kind (AT-B97-07); `sequential` default vs `parallel` driven through the mode control, and a rebound SOURCE input (AT-B97-22); chip with project (AT-B97-12) vs without (AT-B97-13); 118x54 (AT-B97-15) vs resize to 260x70 (AT-B97-16) vs 119↔120 and 80x24 (AT-B97-24); mouse (AT-B97-01..16) vs keyboard only (AT-B97-17..20).
- **C-12 (a produced artifact consumed):** Save Set writes the set file and Load Set restores it (AT-B97-10); Write .chk.json is parsed and equals the card (AT-B97-21); the JSON tab is the consumer of the serialiser's output (AT-B97-01).
- **C-16:** n/a — the prototypes are Textual monkeypatches over the shipped app, the same technology as the target (brief §2), and trigger D2 did not fire; the ATs still drive the real mechanism, keyboard included.
- **C-17:** LLR-144.7, LLR-145.5, LLR-146.8, LLR-147.6 with AT-B97-03, -05, -08, -11; the payload is split by what the surface can carry (§5.3): `HOSTILE_NAME` through real file names, `HOSTILE_CONTENT` (+ `_HOSTILE` minus NUL where admitted) through file content. NUL is not exercised: a flow ref with NUL raises an uncaught `ValueError` on load (`variant_execution_service.py:273`, 02-review Q-13, routed to security + the Flow Builder increment) — recorded gap.
- **C-40:** every NEW predicate's RED counterfactual is executed in its increment (`**RED counterfactual**` field); the ones already RED on `main` are stated per LLR above; LLR-147.2's runs on the Flow Execution increment's own tree.
- **Visual half — inspected, not exercised:** the hue claims (LLR-146.6, LLR-147.7: "distinct", "burnt orange"), the hex strip's colour, and "reads as one object" are judged by the operator on the 24-bit captures (`prototypes/b94_polish/png/impl.*`); the tests exercise only the token, span and hue-distance halves.
- **Captures:** each increment re-captures its screen at 118x54 and 220x60 into `prototypes/b94_polish/png/impl.*` for the operator's side-by-side judgement (brief §4.7) — a `demo`, auxiliary to the ATs.

### 5.2 Batch acceptance criteria
- 100 % of the 59 LLRs covered by their TC with a pass result; 24 of 24 ATs pass; every story has ≥ 2 ATs with boundary and negative evidence.
- 0 blocker fails at Phase 4; the full guard host `tests/test_tui_directionb.py` green at every render increment (C-34).
- Every superseded shipped node of §6.3 retired or rewritten through the ledger in its owning increment; the 14 Spanish pin lines (§2.7 P-17) rewritten to English, not deleted.
- No requirement without a validation method; the operator judges the captures on the review page before the batch closes.

### 5.3 Fixtures, frozen literals and the per-AT table

**Committed literals (Phase 3, `tests/b97_fixtures.py`, NEW):**
- `ES_MARKER` = `[áéíóúñÁÉÍÓÚÑ¿¡]|\bde\b|\b(?i:del|la|las|los|el|una|para|con|sin|tras|paso|bloque|pendiente|esperando|humano|guardar|cargar|ejecutar|archivo|carpeta|salida|entrada|hay|ninguno|ninguna|cadena|cadenas|copiar|pegar|borrar|limpiar|correr|confirmar|registro|falta|faltan|ya|desde|hasta|cada)\b` (executed counts §2.7 P-17).
- `HOSTILE_NAME` = `b97[bold]x[red]y[link=e]z[@click=app.quit]w` (file-name legal, P-27). `HOSTILE_CONTENT` = `b97[bold]x[/]y[red]z[link=https://e.invalid]l[/link][@click=app.quit]q\x07` (admitted by the change-set value, the three flow fields and an A2L name — `p1r2/hc.py`: `changeset value admitted: True`, `flow instruction / log_ref / change_doc_ref … value kept True`, `a2l name admitted: True`). `HOSTILE_C1` = the batch-77 `_HOSTILE` (`tests/test_tui_check_editor.py:54-56`) minus `\x00`, appended on the change-set and flow arms only (admitted there, executed; the A2L parser refuses it).
- `PE_IDS_9C7BEAF` (66, guard `len == 66`): `patch_before_after_button patch_before_after_buttons patch_before_after_card patch_before_after_row patch_checks_controls patch_checks_help patch_checks_results patch_checks_run_button patch_checks_section_label patch_checks_status patch_checks_strip patch_doc_apply_button patch_doc_controls patch_doc_empty_state patch_doc_entries_table patch_doc_entry_buttons patch_doc_entry_inputs patch_doc_file_line1 patch_doc_file_line2 patch_doc_file_row patch_doc_file_select patch_doc_issue_count patch_doc_issues patch_doc_load_button patch_doc_path_input patch_doc_refresh_button patch_doc_save_button patch_doc_validate_button patch_edit_json_button patch_editor_panel patch_entry_add_button patch_entry_address_input patch_entry_bytes_input patch_entry_edit_button patch_entry_edit_json_button patch_entry_remove_button patch_entry_value_input patch_execute_buttons patch_execute_row patch_execute_run_button patch_execute_scope_button patch_history_controls patch_history_strip patch_pane_entries patch_paste_controls patch_paste_gauge patch_paste_parse_button patch_paste_row patch_paste_text patch_redo_button patch_saveback_buttons patch_saveback_confirm_button patch_saveback_decline_button patch_saveback_name_input patch_saveback_row patch_saveback_width_button patch_scope_line patch_script_section_label patch_undo_button patch_win_checks patch_win_checks_body patch_win_json patch_win_json_body patch_win_json_dock_spacer patch_win_script patch_win_script_body`.
- `CE_IDS_9C7BEAF` (31, guard `len == 31`): `check_actions_row check_actions_row2 check_addendum_preview check_apply_ghost check_apply_hint check_columns check_editor_panel check_fields_count check_file_name_input check_left_column check_mem_add_button check_mem_address_input check_mem_controls check_mem_inputs check_mem_label_input check_mem_remove_button check_mem_size_input check_mem_table check_param_controls check_param_filter check_param_include_button check_param_table check_preview check_preview_toggle_button check_results check_right_column check_spec_file_row check_spec_file_select check_status check_validate_button check_write_button`.

**Fixtures** — the project lives in `tmp_path` (`.s19tool/workarea/<name>`); binaries are copied from tracked examples, every JSON is generated per test with the current serialiser:

| fixture | how built | provenance |
|---|---|---|
| `prg.s19`, `ASAP2_Demo_V161.a2l` | copied | tracked `examples/case_00_public/` (P-24) |
| `calib_hotfix.json` (6 entries) | `serialize_change_document` over 6 `bytes` entries at `0xEB10 0xEB40 0xEC00 0xECA0 0xED00 0xED40` | addresses inside `prg.s19` (`0x17e0..0x10000`) |
| `empty.json` · `legacy_v1.json` | serialiser (0 entries) · a literal v1 dict | AT-B97-02 arms |
| `HOSTILE_NAME.json` · `hostile_content.json` | serialiser; content: a `string` entry `value = HOSTILE_CONTENT + HOSTILE_C1`, a `bytes` entry with `symbol = HOSTILE_CONTENT` | P-27, P-29 |
| `hostile.a2l` | `ASAP2_Demo_V161.a2l` with its first CHARACTERISTIC renamed `HOSTILE_CONTENT` | P-28 |
| `baseline.chk.json` | the check serialiser over 4 fields | for `patch_chain`'s check block |
| `patch_chain`, `flash_chain` | `save_flow_json` with the demo's block lists (P-16) | outcomes `ok ok notices ok` / `ok ok waiting skipped` (P-31) |
| `err_chain` + `err_out_of_image.json` | `patch_chain` with its patch ref → a change-set whose one entry is `0x00020000` | deterministic `error` at block 1 (P-31) |
| `crc_wait_chain` | `source, crc, external_step, write_out` | a CRC card beside a waiting card (P-16) |
| `wait_third_6` | three 6-block lanes, the third pausing at block 3 (0-based) | Confirm below the fold (U-6) |
| `patch_chain_b` · `prg_v2.s19` | `patch_chain` with `output_name = fw_b.s19` · `prg.s19` with one data byte outside the patched addresses flipped | parallel + rebind arm (AT-B97-22) |
| `hostile_flow` (file `HOSTILE_NAME.json`) | `flash_chain` with `change_doc_ref`, `instruction`, `log_ref` = `HOSTILE_CONTENT + HOSTILE_C1` | P-30 |

**Per-AT table** (driver = shipped controls only; RED = the executed or mutation arm that fails today):

| AT | story / HLR | fixture | driver | assertion | RED arm |
|---|---|---|---|---|---|
| AT-B97-01 | US-134 / HLR-144 | `calib_hotfix.json` + `prg.s19` | rail → patch; pick the file in `#patch_doc_file_select`; click `#patch_doc_load_button`; click the JSON tab chip | 6 ledger rows painted at 118x54; `json.loads(tab)` addresses == the fixture file's | `main`: tab == `DUMMY_CHANGESET_TEXT` (P-4) |
| AT-B97-02 | US-134 / HLR-144 | `calib_hotfix.json`, `empty.json`, `legacy_v1.json` | Load; type address/bytes; click `#patch_entry_add_button`; (explicit: read, then click `Update JSON`) | 7 parsed entries (stale-before read == 6 in the explicit branch; stamp N == 7); empty → `[]`; v1 → empty doc + 1 ERROR | `main`: tab unchanged after Add |
| AT-B97-03 | US-134 / HLR-144 | `HOSTILE_NAME.json`, `hostile_content.json` | Load each through `#patch_doc_load_button`; move the highlight; open JSON tab | LLR-144.7 threshold on ribbon, ledger, inspector, JSON tab, issues line | mutation: `Text.from_markup` on the ribbon |
| AT-B97-04 | US-135 / HLR-145 | `ASAP2_Demo_V161.a2l` + `prg.s19` | rail → check_editor; `down` ×2; click `#check_param_include_button`; at 118x54 and 220x60; empty arm without A2L | 75/75 addresses in full; count N→N+1; empty-state line, docked row inside | `main`: `max_scroll_x 25` (P-12) |
| AT-B97-05 | US-135 / HLR-145 | `hostile.a2l` | load A2L; include the hostile row | LLR-145.5 threshold on 4 surfaces | mutation: `Text.from_markup` on the cell |
| AT-B97-06 | US-136 / HLR-146 | `patch_chain` | rail → flow; `#flow_load` → pick; click `#flow_run`; empty arm with no blocks | 4 cards, 3 cables on one band; `#flow_run` inside at scroll 0; 1 run request | `main`: `#flow_run (51,48,16,3)` past bottom 44 (P-11) |
| AT-B97-07 | US-136 / HLR-146 | `patch_chain` | click each of 7 kind chips; EXT-STEP: type 3 inputs, click `#flow_add`; empty log → `#flow_add` | inputs per LLR-146.3 table; 5th card; English refusal | `main`: 4 palette chips (P-13) |
| AT-B97-08 | US-136 / HLR-146 | `hostile_flow` | `#flow_load` → pick | LLR-146.8 threshold; long ref clipped with tail kept | mutation: `Text.from_markup` on the IO line |
| AT-B97-09 | US-137 / HLR-147 | `patch_chain`, `flash_chain`, `err_chain`; `crc_wait_chain` | rail → flow_execution; `#fx_import` ×3 → pick; click `#fx_run` | cables `▓▓◇` / `▓□░` / `✗░░`; Confirm inside viewport and focused; 0 `ES_MARKER` in log; waiting-hue spans only on waiting-human elements | `main`: progress bar, Spanish log (P-17) |
| AT-B97-10 | US-137 / HLR-147 | the 3-lane set | type `#fx_set_name`; click `#fx_save`; restart panel; pick in `#fx_set_select`; click `#fx_load`; empty arm: `#fx_run` with no lanes | set file parsed (3 lanes); Load restores 3 lanes in order; 8 header ids inside at 118x54; English no-lanes line | `main`: `#fx_save`/`#fx_load` outside (P-11) |
| AT-B97-11 | US-137 / HLR-147 | `hostile_flow` | `#fx_import` → pick; `#fx_run` to the pause | LLR-147.6 threshold on lane, pending lines, header, log | mutation: chain name into a markup string |
| AT-B97-12 | US-138 / HLR-148 | project in `tmp_path`; `flows` absent / file / junction | click each folder chip under `SeamSpy`; seam raising | 4 calls with the 4 targets; absent → PDR create branch inside the project; file/junction → 0 calls + refusal; raise → status line, no traceback | `main`: `OpenFolderChip("flows")` raises `ValueError` |
| AT-B97-13 | US-138 / HLR-148 | no project | rail through the 4 screens; press the flow chips | `flows`/`session` disabled, 0 calls, status names the family | `main`: "(Reports)" message (P-18) |
| AT-B97-14 | US-138 / HLR-148 | each screen's loaded fixture | click each `?` chip, and once by focus + `enter` | the modal body parsed into `label — effect` lines covers 100 % of the LLR-148.6 coverage set; legend glyphs ⊆ help glyphs | `main`: 6/19 · 0/6 · 2/13 · 0/4 (P-21) |
| AT-B97-15 | US-139 / HLR-149 | widest values: 60-cell ref, 47-cell name, 40-cell set name | each screen at 118x54 and 160x56 | 0 overflow; LLR-149.3 actions inside; 0 wrapped rows; 0 equal painted row pairs | `main`: overflow 1/1/2/7 (P-10) |
| AT-B97-16 | US-139 / HLR-149 | same | `resize_terminal` 118x54 → 220x60 → 260x70 → 118x54 | adaptive widths grow; voids within the PDR bound; 0 blank rows outside the growing region; overflow 0 after return | `main`: EXT-STEP 28 at both sizes (P-22); Patch 3 blank rows (P-32) |
| AT-B97-17 | US-134 / HLR-144 | `calib_hotfix.json` | keys only: `tab` to the file select, `enter`, choose, `tab` to Load, `enter`; `tab` to the JSON chip, `space`; `down` in the ledger | JSON tab parsed == file; the strip follows the highlight | `main`: no tab chip in the chain (P-33) |
| AT-B97-18 | US-135 / HLR-145 | `ASAP2_Demo_V161.a2l` | keys only: filter → ledger `down` → include by `enter`; `tab` to Write, `enter` | the Fields line appears; `.chk.json` written and parsed | `main`: no header chip / tab chip in the chain (P-33) |
| AT-B97-19 | US-136 / HLR-146 | `flash_chain` | keys only: `tab` to the EXT-STEP kind chip, `enter`; type 3 inputs; `enter` on Add; `tab` to Run, `enter` | 5th card; 1 run request | `main`: 4 kind chips, `flow_scope` in the chain (P-33) |
| AT-B97-20 | US-137 / HLR-147 | 3-lane set; `wait_third_6` | keys only: Import by `enter` + pick; mode by key; `enter` on Run; on pause `enter` on the focused Confirm | Confirm focused and inside the lanes viewport on both fixtures; confirm clears REQUIRED | mutation: no scroll-into-view (LLR-147.3); `main`: Confirm not focused on pause |
| AT-B97-21 | US-135 / HLR-145 | `ASAP2_Demo_V161.a2l` | include 2 parameters; add 1 memory row by its labelled inputs; click Fields / JSON / Addendum chips; click `#check_write_button` | parsed Fields set == the 3 included; JSON tab == written file's addresses; Addendum shows the preview | `main`: no Fields tab |
| AT-B97-22 | US-137 / HLR-147 | `patch_chain` + `patch_chain_b` (same blocks, output `fw_b.s19`); `prg_v2.s19` | choose `parallel` in the mode control; type `prg_v2.s19` into `#fx_in_1_0`; `#fx_run` | `record.mode == "parallel"`; lane 1's written output differs from lane 0's at the changed byte | `main`: mode control 80 cells (`(21, 7, 80, 3)`, P-31 probe) |
| AT-B97-23 | US-138 / HLR-148 | per LLR-148.9 row | each state through its control (Load of a missing path, Write into a read-only dir, a refused flow, a raising run; Run pressed during a run) | 1 English state line per arm, 0 tracebacks; 1 run for 2 presses | `main`: Builder empty pipeline has no line (no pipeline) |
| AT-B97-24 | US-139 / HLR-149 | `patch_chain`, widest values | `resize_terminal` 119x54 ↔ 120x54; then 80x24: `scroll_to_widget` + press `#flow_run` | 0 overflow on both sides; `width-narrow` flips; at 80x24 every LLR-149.3 action reachable and Run posts | `main`: overflow at 118/120 (P-10) |

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
Decided at ARQ (`docs/architecture.md`, batch-97 section): R13 in-place re-composition, R14 project-only chip families, R15 `FLOWS_SUBDIR` imported, R16 the tokens in `insight_style.py`, R17 the canonical serialiser feeds the JSON tab.

**Deferred to PDR (each named in the LLR it governs; every requirement holds for any choice):**
1. JSON tab refresh: live vs `Update JSON` + stamp (LLR-144.6; brief R-1.1). Both satisfy LLR-144.6; the explicit branch carries the stale-then-current clause.
2. JSON tab widget: a new read-only view (LLR-144.5 requires read-only) vs reseeding `#patch_paste_text` read-only, and what that means for the A-01 guard on Edit JSON; the value of `JSON_TAB_LINE_CAP` (≤ 5,000).
3. I-2 / I-3 call shape: a `refresh_entries` keyword with the `mem_map` sentinel idiom, or a setter (LLR-144.5, LLR-144.7).
4. The Check Editor chip id scheme — scoping or a suffix (LLR-148.4; ARQ open question 1).
5. Create-on-press for `flows` (inside the project only, LLR-148.1); `session` never creates (LLR-148.2).
6. The two new help keys' names, and whether Flow Execution becomes a `WindowSection` (LLR-148.6).
7. **Operator:** the waiting hue and the CRC hue as a PAIR (LLR-146.6, LLR-147.7) — constraints: CRC ≥ 20° from waiting; waiting painted only on waiting-human elements; notices, dirty marker and every other accent ≥ 20° from waiting. Executed: `#cf6a2d` vs `#f6ff8f` 42.2° (allowed); vs the approved-capture amber `#e8a33d` 13.2° (not allowed as a pair). The dirty strip moves off the waiting hue if the shipped `#f6ff8f` stays.
8. Whether the grid canvas stays reachable, which decides whether `_CANVAS_COLS` (F-2/F-3) must become width-derived (LLR-146.1).
9. **Operator:** the primary (filled) action of the Patch Editor and of the Check Editor (LLR-144.11, LLR-145.9); Run on both flow screens is the operator's answer (LLR-146.5, LLR-147.9).
10. The final names of every NEW widget id in §4 / IFC Part B, the no-wrap set's ids per category (LLR-149.4), the hex strip's text attribute (LLR-144.8).
11. **Operator:** card growth at large widths — cards grow vs more cards per band (LLR-149.5 keys its void bound on the choice).
12. Where multi-variant runs live once `#flow_scope` leaves the Builder (LLR-146.12).
13. The Flow Execution run mechanism — on the UI thread (today, `app.py:2815`) or a worker — which decides whether `running…` paints (LLR-147.10).
14. The increment re-cut (02-review A-14): the Flow Execution increment now carries `flow_execution_service.py` as a fifth source file, and R16 adds `insight_style.py` to Inc 3/4.
15. **Operator (02-review U-11):** the cable after a waiting block — `░` (LLR-147.1 table) or the approved capture's plain line.
16. Folder-chip labels: whether each chip names its folder in the label or the tooltip (02-review U-13).

### 6.3 Open risks
- **Security pattern scan (2026-10-20, re-run on this amendment):** `devflow-scan-spec.py` over this file → 5 of 5 controls ok, flags `token`, `session`, `form`, `security_required: true` (exit 1). Answers: **`token`** — a design (colour) token in `insight_style.py`, not a credential; no secret, key or auth token is read, stored or shown by this batch. **`session`** — the flow session directory (the active project dir), not an auth session; its chip only opens that folder through the existing seam, never creates one (LLR-148.2), and only when it is a real directory (LLR-148.8). **`user input`** / **`form`** — the add form and the set-name / rebind inputs keep their shipped validation (batch-94/96: containment of refs, the EXT-STEP log/output refusal, `save_flow_json` → `sanitize_project_name`, `flow_persistence_service.py:970`); this batch moves them and adds no new write path; every file-derived string they echo is covered by the C-17 LLRs.
- **C-17:** the control is the per-surface hostile ATs (AT-B97-03, -05, -08, -11), not a source scan: the guard host's scan (`tests/test_tui_directionb.py:8231`) sees explicit `from_markup` / `markup=True` sites but cannot see an implicit sink (a `Static(str)` whose default markup parse reads file text, a `Button` label, a `DataTable` cell given a `str`). `safe_text` covers control characters and wraps as literal `Text` (`utils.py:41-44`); bidi/zero-width controls are not covered (`BACKLOG-CODE.md:1394`).
- **NUL in a flow ref** raises an uncaught `ValueError` on load (`variant_execution_service.py:273`) — pre-existing; routed to security + the Flow Builder increment (02-review Q-13); the ATs use NUL-free payloads meanwhile.
- **The `session` chip opens the project directory itself** — a wider folder than any other chip opens; same seam, one call per press, no shell string, real-directory guard (LLR-148.8).
- **Hue proximity:** the operator-approved captures paint the waiting state in the prototype amber; the CRC candidate sits 13.2° from it — the pair is decided at PDR (§6.2 item 7).
- **Multi-variant runs:** hiding `#flow_scope` removes the only UI path to `FLOW_SCOPE_ALL_VARIANTS` / `FLOW_SCOPE_ASSIGNMENTS` from the Builder (`flow_screens.py:583-587`; consumer `tests/test_flow_multi_image_ui.py`) — §6.2 item 12.
- **Synchronous runs:** `run_chain_set` runs inside the message handler (`app.py:2815`), so a press during a run is queued and delivered after it; LLR-147.10 drops it.
- **Carried to Phase 3 (not P1's to fix):** `tests/test_id_registry.py:124` `EXPECTED_SCANNED_TEST_FILES = 189` is exact — every test-adding increment bumps it (Q-14); the two `patch` snapshot cells are already `xfail(strict=False)`, so the C-22 bound cannot go RED — tie it to a regen or mark the cells in the Patch Editor increment (Q-18); the increment re-cut (A-14).
- **Superseded shipped nodes (C-26, change-first census of 02-review, re-checked 2026-10-20)** — each retired or rewritten through the ledger in its owning increment:

| shipped node | superseded by | increment |
|---|---|---|
| `tests/test_tui_check_editor.py` button height 3 | LLR-145.4 | Check Editor |
| `tests/test_window_usage_help.py:250` `SHIPPED_WINDOW_KEYS`, `_EXPECTED_KEYS` (`:95-107`), `tests/test_changes_file_notation_help.py` `_EXPECTED_KEYS` | LLR-148.6 | Check Editor (check key), Flow Execution (execution key) |
| `tests/test_open_folder_chips.py:94-98` `_RAIL_CHIPS` / id scheme | LLR-148.4 | Check Editor |
| `tests/test_tui_patch_layout.py` (9 tests, 7 at 80x24) | LLR-144.2, LLR-144.3, LLR-149.6 | Patch Editor |
| `tests/test_tui_patch_chips.py` (E-3 grid rules) | LLR-144.4 | Patch Editor |
| the 24 Patch Editor test files reaching the 66 ids — kept green by LLR-144.1; only layout assertions move | LLR-144.1 | Patch Editor |
| `tests/test_flow_funnel_b96.py:330` `"Funnel (1)"` | LLR-146.10 | Flow Builder |
| `tests/test_tui_flow_builder_b94.py:144-159, 241, 371, 436-454` (AT-B94-15..18: painted canvas, palette, canvas region) | LLR-146.1, LLR-146.2 | Flow Builder |
| `tests/test_flow_external_step_b96.py:404` (canvas displayed) | LLR-146.1 | Flow Builder |
| `tests/test_flow_multi_image_ui.py` (`#flow_scope`) | LLR-146.12 | Flow Builder |
| Spanish pins `test_flow_external_step_b96.py:422, 425`, `test_flow_funnel_b96.py:331, 475, 477` | LLR-146.7 | Flow Builder |
| `tests/test_tui_flow_execution_b94.py:626, 693` (`#fx_mode` read as a `Select`) | LLR-147.4 | Flow Execution |
| Spanish pins `test_flow_external_step_b96.py:265, 266, 302, 333, 345, 507, 508, 509, 514` | LLR-147.5 | Flow Execution |
| 80x24 runs in 17 patch/check/flow test files (P-35) | not superseded — LLR-149.6 keeps them reachable; layout-asserting ones re-baselined with their screen | each screen's increment |

- **The brief's line numbers drifted** (E-2 `:6848` → `:6978`); every line cited here was re-read on `9c7beaf` / `bc4fbd3`.

### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-19-batch-97

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
