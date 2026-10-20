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
families, `flows` and `session`); the burnt-orange CRC token; English UI strings on the four
screens; width-adaptive layouts at 118x54 (minimum) and 220x60 (large reference) with no wrapped rows;
markup safety (C-17) for every new render of file-derived text.
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
| 118x54 / 220x60 | the minimum and the large reference terminal sizes (operator, handoff §1) |
| shipped id | a literal `id="…"` a panel's `compose` yields on `main` at `9c7beaf` |

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

### 2.4 Constraints
- At most **4 source files per increment** (tests uncapped) — the operator's global budget.
- **English** for every string the four screens paint (R-9); Spanish only in chat.
- **Nothing promoted from `prototypes/`** — the variants are re-composed in `s19_app/`, never imported (ARQ: the `prototypes/**` boundary).
- Size regimes: **118x54 minimum**, **220x60 large reference**; widths derived from the available width, never fixed to 118.
- Python 3.11, Textual 8.2.8 (`pyproject.toml:73` pins `textual==8.2.8`; `textual.__version__` → `8.2.8`, executed 2026-10-20).
- The no-apply doctrine of `.chk.json` (`PDR-2026-10-12-batch-94#D2`) and the batch-96 waiting-human doctrine stay as they are.
- Ids: batch-scoped `AT-B97-NN` / `TC-B97-NN` (`docs/engineering-rules.md:48`), no registry reservation.

### 2.5 Assumptions and dependencies
Every assumption the contract relies on is a row of §2.7 with executed evidence. Acceptance
fixtures are copied from the untracked demo project into `tests/` in Phase 3 (§2.7 P-24), because
an untracked folder cannot be a CI fixture.

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

**Not taken in (OUT, with where it lives):** the `Fmt · Unit` column (ce_C) and the matrix density mode (fx_C) — offered by the prototyping session, not chosen by the operator; the hex-viewer no-wrap rule outside these four screens — a backlog item for the all-screens review; the eight Code-Wire pilot findings — already in `BACKLOG-CODE.md` (`51ee191`), a separate lane; the batch-96 follow-ups — untouched.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

Probes executed 2026-10-20 on `main` at `9c7beaf` (`git rev-parse --short HEAD`), `git status --short s19_app/` → 0 lines. The two probe drivers run the REAL tree through the harness's scenarios (`run_real._APP_COPY` repointed to the repository root): `probe_b97.py` / `probe_overflow.py` (session scratch; their outputs are pasted below, which is the evidence).

| # | Premise, as a truth-apt proposition | Tier (axiom · hypothesis · premise) | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| P-1 | The shipped `PatchEditorPanel` (`screens_directionb.py:4383-6863`) yields 66 literal widget ids; 65 are reached from outside the panel. | premise | ✅ TRUE | id census (regex `id=f?"…"` over the span, then `#id`/`"id"` grep over `s19_app/` + `tests/`): `66 literal ids … -> 65/66 ids reached outside the panel span` (only `patch_win_json_dock_spacer` unreached) | LLR-144.1 keys on this set |
| P-2 | The shipped `CheckEditorPanel` (`:6864-7602`) yields 31 literal ids; 14 are reached from outside. | premise | ✅ TRUE | same census: `31 literal ids … -> 14/31` | LLR-145.1 keys on this set |
| P-3 | `FlowBuilderPanel` (`flow_screens.py:502-1799`) yields 39 literal ids + the computed `flow_palette_{kind}`; `FlowExecutionPanel` (`:1874-2693`) 23 ids, 6 of them computed (`fx_lane_{i}`, `fx_confirm_{i}`, `fx_in_{i}_{j}`, …). | premise | ✅ TRUE | same census: `39 literal ids … 31/39 reached`; `23 literal ids … 12/23 reached` | LLR-146.1 / LLR-147.1 |
| P-4 | After Load of `calib_hotfix.json` the JSON editor still holds the dummy template, not the document (E-6). | premise | ✅ TRUE | `probe_b97.py patch-editor 118x54` → `service entries 6 source calib_hotfix.json` · `json buffer == DUMMY True address-keys in buffer 2` | the RED side of AT-B97-01 / TC-B97-05 |
| P-5 | The canonical serialiser emits the loaded document with all six entries. | premise | ✅ TRUE | `ChangeService().load(str(p), dir)` + `serialize_change_document(doc)` → `type: bytes bytes: 706 lines: 39`; emitted head `{` / `"format": "s19app-changeset",` / … / `"address": "0xEB10",`; `addresses: ['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']` | predicates parse the JSON (C-42), never substring-match it |
| P-6 | `ChangeService.document` is replaced only by `undo`/`redo`/`load`/`load_text` and mutated only by the entry operations. | premise | ✅ TRUE | writer census `grep -n "\.document\s*=[^=]"` → `change_service.py:861` (undo), `:893` (redo), `:1404` (load), `:1465` (load_text); `grep "self.document.entries\.(append|pop…)|entries\[..\]="` → `:1080, :1154, :1196, :1223, :1344` | LLR-144.6's "entry change" is this writer set |
| P-7 | The shipped panels add their table columns exactly once; the brief's "columns added a second time" (E-1) was an artefact of the prototype's MRO-dispatched `on_mount`, not a shipped defect. | premise | ✅ TRUE | `probe_b97.py patch-editor` → `table columns 5 ['Kind', 'Address', 'Value / bytes', 'Status', 'Linkage']`; `add_columns` sites: `screens_directionb.py:5613` (one per panel), `:7365`, `:7368`; `prototypes/b94_polish/NOTES.editors.md:17-22` names the subclass+base dispatch | LLR-144.3 targets the real double work (forced heights/widths, three geometry call sites) and pins `len(columns) == 5` |
| P-8 | `_apply_window_geometry` has three call sites — `on_resize` (`screens_directionb.py:5596`), `on_mount` (`:5656`), the show path (`app.py:6978`) — and no test references it; `on_mount` forces `table.styles.height = 3` (`:5616`), select width 30 (`:5638`), path width 28 (`:5641`). | premise | ✅ TRUE | `grep -c _apply_window_geometry` → `app.py:1`, `screens_directionb.py:7` (def + docstrings + 2 calls); `grep -rln _apply_window_geometry tests/` → empty | LLR-144.3 |
| P-9 | The E-3 rules exist in `styles.tcss`: `#patch_win_script { width: 2fr }` (`:1117-1118`), `#patch_doc_entries_table { height: 10 }` (`:1536-1538`), `layout: grid` on `#patch_doc_entry_buttons` (`:1160-1168`) and `#patch_doc_controls` (`:1581-1584`). | premise | ✅ TRUE | `grep -n` over `s19_app/tui/styles.tcss` (output above) | LLR-144.4 |
| P-10 | Today every one of the four screens overflows horizontally at both sizes. | premise | ✅ TRUE | `probe_overflow.py` (displayed descendants with `region.right > panel.right`): 118x54 → patch 1 (`patch_script_section_label`), check 1 (`check_apply_ghost x=95 w=54`), builder 2 (`flow_help`, `flow_clip_status`), execution 7 (`fx_help`, `fx_save x=117`, `fx_set_select`, …, `fx_load x=134`); 220x60 → 1 / 1 / 1 / 6. `panel.max_scroll_x` reads 0 on three of them (clip, not scroll — the C-32 trap) | the RED side of LLR-149.2 |
| P-11 | At 118x54 the Builder's Run and the Execution's Save Set / Load Set are outside the panel viewport at scroll 0; the editors' primary actions are inside. | premise | ✅ TRUE | `probe_overflow.py`: panel `(5,4,112,40)` (bottom 44); `#flow_run (51,42,16,3)` → False; ext scenario `#flow_run (51,49,16,3)` → False; `#fx_save (117,10,16,3)` False; `#fx_load (134,10,16,3)` False; `#patch_doc_*` and `#check_validate_button`/`#check_write_button` → True | LLR-149.3 |
| P-12 | At 118x54 the Check Editor's Address column is clipped: column render widths `3+49+12+15 = 79` in a 56-cell table, `max_scroll_x 25`; at 220x60 the table is 98 cells and `max_scroll_x 0`. | premise | ✅ TRUE | `probe_b97.py check-editor`: `param table region (5, 8, 56, 40) rows 75 scroll_x max 25`; columns `'Parameter' content_width 47 get_render_width 49`, `'Address' content_width 10 get_render_width 12`; at 220x60 `region (23, 8, 98, 46) … scroll_x max 0` | LLR-145.2 / LLR-145.3 |
| P-13 | The Builder palette offers 4 kinds (`flow_palette_patch/crc/a2b/external_step`) while `_KIND_OPTIONS` lists 7 placeable kinds; the handler accepts any `flow_palette_<kind>`. | premise | ✅ TRUE | probe `palette ids ['flow_palette_patch', 'flow_palette_crc', 'flow_palette_a2b', 'flow_palette_external_step']`; `flow_screens.py:542-551` (7 kinds); `:1455-1461` (`removeprefix("flow_palette_")` → `#flow_kind`) | LLR-146.2 (the brief's "six" is stale: batch-96 added EXT-STEP) |
| P-14 | `_plc_block` paints a block's IO text without clipping it to the block width (F-1). | premise | ✅ TRUE | `flow_screens.py:440` builds `left` from the whole `text_`; `:443` `g.put(x + 6, yy, text_, tstyle)` — no slice to `w` | LLR-146.4 |
| P-15 | The retained run record carries per-block status, and outcome *i* belongs to lane *i* (F-8). | premise | ✅ TRUE | writer census of `record.outcomes`: `flow_execution_service.py:1546` (`pool.map`, submission order) and `:1548` (sequential append) only; `app.py:2806-2813` builds `chains` from `event.lanes` in lane order. Executed: `probe_b97.py flow-execution-paused` → `outcome[0] chain=patch_chain … blocks=0:ok,1:ok,2:notices,3:ok` · `outcome[1] chain=flash_chain status=paused blocks=0:ok,1:ok,2:waiting,3:skipped` | LLR-147.1 needs no record change (no A3 on the service) |
| P-16 | No CRC family colour ships; the waiting state paints `YELLOW #f6ff8f`, the hex warnings and the dirty strip also use; no demo flow contains a CRC block. | premise | ✅ TRUE | `flow_screens.py:1800` `_S_PAUSE = "bold " + YELLOW`; `insight_style.py:64` `YELLOW = "#f6ff8f"`; `grep crc` near a colour in `flow_screens.py` → none; demo flow kinds: `flash_chain ['source','patch','external_step','write_out']`, `patch_chain ['source','patch','check','write_out']`, `release_diff ['source','patch','a2b','write_out']` | LLR-146.6; the CRC-beside-paused AT uses a NEW fixture |
| P-17 | 34 non-docstring string constants in `flow_screens.py` carry Spanish (25 in the Builder span, 9 in the Execution span, plus the module banner `:235`); 2 test files pin them. | premise | ✅ TRUE | AST census (string constants minus docstrings, Spanish-marker regex) → `34`, e.g. `:2477 ' · ESPERANDO HUMANO — paso externo (block '`, `:2531 ' · re-run tras confirmar paso externo\n'`, `:782 'Añadir var'`; `grep -cE` over tests → `test_flow_external_step_b96.py 9`, `test_flow_funnel_b96.py 2` | LLR-146.7 / LLR-147.5 |
| P-18 | Chip families: 4 (`folder_open_service.py:57-60`, `CHIP_FAMILIES :64`); the no-project status `REPORTS_NO_PROJECT_REASON` (`:78`) names Reports and `open_folder_chip.py:115`/`:160` emit it for any `None` target; flows live at `project_dir / FLOWS_SUBDIR` (`flow_persistence_service.py:95`, `:973`); the session dir pushed to the flow panels is the active project dir (`app.py:8130-8137`). | premise | ✅ TRUE | `grep -n` outputs above | LLR-148.1..148.3 |
| P-19 | A Check Editor chip of family `checks` would carry the id `open_folder_checks`, which the Checks screen already mounts. | premise | ✅ TRUE | `open_folder_chip.py:77` `id=f"open_folder_{family}"`; `app.py:2321` `OpenFolderChip("checks")`; `tests/test_open_folder_chips.py:94-98` `_RAIL_CHIPS` addresses `#open_folder_checks` | LLR-148.4 (scoping decided at PDR) |
| P-20 | `SHIPPED_WINDOW_KEYS` holds 8 keys (`window_help.py:270-279`) and `tests/test_window_usage_help.py:250` asserts set equality; no Check Editor or Flow Execution section exists; the Check Editor header is a bare `Label` (`app.py:3082`) and Flow Execution's `titled_header` has neither chip (`app.py:2438`). | premise | ✅ TRUE | `grep -n` / `sed -n` outputs above | LLR-148.5 / LLR-148.6 |
| P-21 | Today's help entries name few of the buttons their panel renders. | premise | ✅ TRUE | help probe at 118x54 (button labels in the panel vs `section_body_text`): `#patch_editor_panel … buttons=19 named-in-help=6`; `#check_editor_panel … key=None buttons=6 named-in-help=0`; `#flow_panel … buttons=13 named-in-help=2`; `#fx_panel … key=None buttons=4 named-in-help=0` | the RED side of LLR-148.6 |
| P-22 | The EXT-STEP inputs are fixed-width: 28 / 26 / 28 cells at both 118x54 and 220x60. | premise | ✅ TRUE | `probe_b97.py flow-builder-ext`: `#flow_ext_instruction … (31, 13, 28, 3)` / `(49, 13, 28, 3)`; `#flow_ext_log` 26 / 26; `#flow_ext_output` 28 / 28 | the RED side of LLR-149.1 |
| P-23 | Textual's pilot can resize the terminal inside one session. | premise | ✅ TRUE | `python -c "… Pilot.resize_terminal"` → `8.2.8 True (self, width: 'int', height: 'int') -> 'None'` | AT-B97-15 drives the real resize |
| P-24 | The demo fixtures exist but are untracked, so acceptance fixtures are copied into `tests/` in Phase 3. | premise | ✅ TRUE | `ls …/polishdemo/` → `calib.a2l calib_hotfix.json flows fw_app.s19 …`; `git status --short` → `?? prototypes/b94_polish/` | every AT fixture is `NEW — created in Phase 3` |
| P-25 | The batch-77 hostile payload already reaches the Check Editor as an A2L symbol name in a shipped AT, so a file-derived injection path exists. | axiom | ✅ TRUE | `tests/test_tui_check_editor.py:52-56` (`_HOSTILE`), `:433` `test_at_b94_13_hostile_symbol_and_file_name` | the C-17 ATs reuse the payload and add `[bold]`, `[/]`, `[link=…]` |
| P-26 | The only snapshot cells rendering a batch-97 screen are the two `patch` cells (80x24, 120x30). | premise | ✅ TRUE | `ls tests/__snapshots__/test_tui_snapshot \| grep -ci patch` → `2`; `_SCAFFOLD_SCREENS = ["map", "patch", "diff"]` (`tests/test_tui_snapshot.py:110`) | C-22 upper bound: ≤ 2 drifting cells, Inc 2 |

- **Premise evaluation:** 26 premise(s) · ✅ TRUE 26 / ❌ FALSE 0 / ❓ UNDECIDABLE 0 — every row executed on `9c7beaf` on 2026-10-20; P-7 records the corrected form of a brief claim (E-1), P-13 and P-16 the corrected form of two others (the palette count, the CRC-and-paused capture).

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

> Test-file paths, `-k` selectors and node ids in every *Executed verification* line are provisional until Phase 3 (V-5) and reconciled from the real tree at Phase 4. Every acceptance fixture is `NEW — created in Phase 3` under `tests/` (copied, content-identical, from the untracked demo project — §2.7 P-24). Every render-increment gate also runs the full guard host `pytest tests/test_tui_directionb.py` (C-34, `docs/engineering-rules.md`).

### HLR-144 — Patch Editor as a ledger + inspector with a consultable JSON tab
- **Traceability:** US-134
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When the engineer loads a change-set or changes an entry in the Patch Editor, the Patch Editor shall present the document's entries as a full-height ledger beside an inspector carrying Inspector, JSON and Checks tabs, and the JSON tab shall show the document the editor holds.
- **Rationale (informative):** operator verdict pe_A with the binding JSON condition (brief R-1, R-1.1, R-1.2). Today the ledger shows 2 of 6 rows in a 3-row band and the JSON editor keeps the dummy template after Load (§2.7 P-4, P-8).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_patch_editor.py -k "at_b97_01 or at_b97_02 or at_b97_03"` (Textual pilot, real presses) + the C-34 guard host.
- **Numeric pass threshold:** after Load of the 6-entry fixture at 118x54: 6 of 6 ledger rows painted without scrolling, and the JSON tab's text parses (`json.loads`) to 6 entries whose `address` list equals the service document's; after one Add: 7 entries in the parsed tab text (immediately, or after `Update JSON` with a stamp naming 7 entries); the hostile file name renders with 0 markup errors and its characters literal.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Load the engineer sees every entry of the document in the left ledger and, on the JSON tab, the same document as JSON; after adding an entry the JSON tab shows it (live, or after pressing `Update JSON`, with its "generated from N entries" stamp); a file name full of markup brackets reads literally in the identity ribbon.
  - **Shipped surface:** `#screen_patch` → `PatchEditorPanel` (`s19_app/tui/screens_directionb.py:4383`), loaded through `S19TuiApp._patch_editor_load_tail` (`s19_app/tui/app.py:5266`).
  - **Acceptance test(s):** AT-B97-01, AT-B97-02, AT-B97-03
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a document with 0 entries shows the empty-state line in the ledger and `"entries": []` in the tab (AT-B97-02 first arm); boundary: the 118x54 floor (AT-B97-01); invalid: a legacy v1 file loads as the empty document plus its one ERROR finding and the tab shows that empty document, not the previous one (AT-B97-02 second arm); error: the hostile file name (AT-B97-03).
  - **Negative control:** executed on `main` (§2.7 P-4): after Load the JSON buffer equals `DUMMY_CHANGESET_TEXT` with 2 `"address"` keys against 6 entries — AT-B97-01's tab clause is RED on today's tree.

### HLR-145 — Check Editor as a ledger + report-fields card
- **Traceability:** US-135
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While the Check Editor is displayed, the Check Editor shall present the A2L parameters as a full-height ledger whose Address column is never truncated, beside a REPORT FIELDS card with Fields, JSON and Addendum tabs, and one docked row carrying Validate, Write .chk.json, the struck APPLY ghost and the field count.
- **Rationale (informative):** operator verdict ce_A (brief R-2). At 118x54 today the Address column sits 52 cells into a 56-cell table (`max_scroll_x 25`, §2.7 P-12). The no-apply doctrine stays (`PDR-2026-10-12-batch-94#D2`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_check_editor.py -k "at_b97_04 or at_b97_05"` + the C-34 guard host.
- **Numeric pass threshold:** at 118x54 and at 220x60: the parameter table's `max_scroll_x == 0` and, for every painted row, the Address cell's painted text equals the full address string (75 of 75 rows of the fixture reachable by vertical scroll only); the field-count text changes from N to N+1 after one Include press; 0 apply actions in the panel; the hostile parameter name renders with 0 markup errors.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer reads every parameter's address in full at both sizes, includes a parameter and sees the field count on the docked row rise by one, and sees a markup-laden parameter name literally.
  - **Shipped surface:** `#screen_check_editor` → `CheckEditorPanel` (`s19_app/tui/screens_directionb.py:6864`), prefilled by `S19TuiApp._prefill_check_editor` (`app.py:5329`).
  - **Acceptance test(s):** AT-B97-04, AT-B97-05
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: no A2L loaded → the ledger shows its empty state and the docked row stays inside the panel (AT-B97-04 first arm); boundary: 118x54 and the 47-cell longest name (AT-B97-04); invalid: N/A — the panel has no free-text input whose invalid value this story changes (the memory-row inputs keep their batch-94 validation, untouched); error: the hostile name (AT-B97-05).
  - **Negative control:** executed on `main` (§2.7 P-12): `max_scroll_x 25` at 118x54 — AT-B97-04's address clause is RED on today's tree.

### HLR-146 — Flow Builder as a pipeline rail with a contextual add form
- **Traceability:** US-136
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While a flow is loaded in the Flow Builder, the Flow Builder shall present its blocks as one horizontal pipeline of cards joined by cables, shall offer every placeable block kind in its palette with an add form that shows only the chosen kind's inputs, and shall keep Run inside the panel viewport without scrolling.
- **Rationale (informative):** operator verdict fb_A (brief R-3, R-5). Today Run sits below the fold at 118x54 (§2.7 P-11), the palette offers 4 of 7 kinds (P-13), card text overruns its card (P-14) and 25 strings are Spanish (P-17).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_builder.py -k "at_b97_06 or at_b97_07 or at_b97_08"` + the C-34 guard host.
- **Numeric pass threshold:** with the 4-block `patch_chain` fixture at 118x54: 4 cards on one painted row joined by 3 cables, `#flow_run` inside the panel region at scroll 0; 7 palette buttons, and for each of the 7 kinds the displayed add inputs equal LLR-146.3's table row; pressing Add after EXT-STEP appends a 5th card; the hostile block ref renders with 0 markup errors; 0 Spanish strings painted on the panel.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer sees the whole chain as one row of cards with cables and Run on screen; clicking a kind chip shows only that kind's inputs (EXT-STEP: command, log and output on two rows) and Add appends the card; a markup-laden ref reads literally on its card.
  - **Shipped surface:** `#screen_flow` → `FlowBuilderPanel` (`s19_app/tui/flow_screens.py:502`), mounted by `_compose_screen_flow` (`app.py:2378`, header `:2404`).
  - **Acceptance test(s):** AT-B97-06, AT-B97-07, AT-B97-08
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no blocks → the rail shows its empty line and Run stays reachable (AT-B97-06 first arm); boundary: 118x54 and a ref longer than the card (clipped, AT-B97-08); invalid: EXT-STEP Add with an empty log is refused with the English refusal line (AT-B97-07, EXT-STEP arm); error: the hostile ref (AT-B97-08).
  - **Negative control:** executed on `main` (§2.7 P-11, P-13): `#flow_run (51,42,16,3)` ends past the panel bottom 44, and the palette holds 4 buttons — AT-B97-06 and AT-B97-07 are RED on today's tree.

### HLR-147 — Flow Execution as one pipeline per lane with cable status
- **Traceability:** US-137
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When a flow set runs in Flow Execution, the Flow Execution panel shall paint one pipeline per lane whose cables carry the run status of their blocks from the retained run record, and while a lane waits for a human the panel shall show that lane's Confirm inside the lane row and the run log shall name the wait in English.
- **Rationale (informative):** operator verdict fx_A (brief R-4, R-5); the batch-96 waiting-human doctrine is kept as it is. Per-block status and lane order are already in the record (§2.7 P-15), so no service change is owed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_execution.py -k "at_b97_09 or at_b97_10 or at_b97_11"` + the C-34 guard host.
- **Numeric pass threshold:** running the 2-lane `flash_q4` fixture (sequential) at 118x54: lane 1's 3 cables painted with the LLR-147.1 glyphs for `ok, ok, notices` and lane 2's cable into block 3 painted `□`; `#fx_confirm_1` region inside lane 2's region; `#fx_confirm_0` hidden; 0 Spanish strings in the run log; `#fx_save` and `#fx_load` inside the panel region at scroll 0 and Save Set writes the set file; the hostile chain name renders with 0 markup errors.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Run the engineer sees lane 1 done and lane 2 paused at its external step, with Confirm in lane 2's row, a REQUIRED line above the log, and the log in English; Save Set and Load Set are on screen; a CRC card in the same capture is painted burnt orange, distinct from the waiting card.
  - **Shipped surface:** `#screen_flow_execution` → `FlowExecutionPanel` (`s19_app/tui/flow_screens.py:1874`), run through `S19TuiApp.on_flow_execution_panel_run_requested` (`app.py:2776`; chains built `:2806-2814`, rendered `:2821`).
  - **Acceptance test(s):** AT-B97-09, AT-B97-10, AT-B97-11
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: Run with no lanes paints no pipeline and an English no-lanes line (AT-B97-10 first arm); boundary: 118x54 header and set row (AT-B97-10); invalid: N/A — the run inputs' validation (bindings, containment) is batch-94's and unchanged; error: an error lane (`✗` cable, AT-B97-09 second fixture lane) and the hostile chain name (AT-B97-11).
  - **Negative control:** executed on `main` (§2.7 P-11, P-17): `#fx_save (117,10,16,3)` and `#fx_load (134,10,16,3)` outside the panel; the run log line `□ flash_chain · ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` — AT-B97-09/10 are RED on today's tree.

### HLR-148 — Folder chip and help chip on the four screens
- **Traceability:** US-138
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When the engineer presses the open-folder chip or the help chip on the Patch Editor, Check Editor, Flow Builder or Flow Execution screen, the system shall open the folder that screen's files live in or show that screen's help entry naming every control and glyph on the screen; while no project is active, a project-only family's chip shall be disabled and its status message shall name that family's folder.
- **Rationale (informative):** the operator's round-2 answer ("es un problema adivinar y buscarlos, sobre todo para usuarios nuevos") and the verdict note on legends (brief R-6, R-7). ARQ I-1 / I-4; R14 (project-only limb), R15 (`FLOWS_SUBDIR` imported).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_chips_help.py -k "at_b97_12 or at_b97_13 or at_b97_14"` with the open seam spied (the `SeamSpy` idiom of `tests/test_open_folder_chips.py:101`).
- **Numeric pass threshold:** with a project: 4 presses → 4 seam calls with targets `patch` home, `checks` home, `project_dir / "flows"`, `project_dir`; without a project: the `flows` and `session` chips are disabled, 0 seam calls, and the status line names the family's folder and not "Reports"; each of the 4 help chips opens a modal whose body names 100 % of the button labels rendered in its panel (today 6/19, 0/6, 2/13, 0/4 — §2.7 P-21).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** every one of the four screens shows a `📂 Open folder` chip and a `?` chip in its header; with a project the chip opens the right folder, without one the flow chips are dimmed and say why; `?` explains every control on that screen.
  - **Shipped surface:** `OpenFolderChip` / `titled_header` (`s19_app/tui/open_folder_chip.py:59`, `:185`), `folder_open_service.resolve_chip_target` (`s19_app/tui/services/folder_open_service.py:232`), `WindowHelpChip` (`s19_app/tui/window_help.py:401`).
  - **Acceptance test(s):** AT-B97-12, AT-B97-13, AT-B97-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: no project (AT-B97-13); boundary: a project whose `flows/` does not exist yet → the chip is dimmed and the press follows the create-offer decision of PDR (AT-B97-12 second arm); invalid: N/A — a chip takes no user input; error: the seam raises → the status line carries the failure, no traceback (AT-B97-12 third arm).
  - **Negative control:** executed on `main` (§2.7 P-18, P-20, P-21): `OpenFolderChip("flows")` raises `ValueError` (family not in `CHIP_FAMILIES`), the Check Editor header has no chip, and the help coverage is 6/19 · 0/6 · 2/13 · 0/4 — all three ATs are RED on today's tree.

### HLR-149 — Width-adaptive layouts, no wrapped rows
- **Traceability:** US-139
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While the Patch Editor, Check Editor, Flow Builder or Flow Execution screen is displayed at a terminal size of at least 118x54, the system shall derive that screen's column widths and panel splits from the available width at mount and on every resize, so that no element overflows horizontally, the primary actions stay inside the panel viewport and no ledger or log row wraps.
- **Rationale (informative):** the operator's variable-size rule and the 220x60 pass (brief R-8). Every screen overflows today at both sizes (§2.7 P-10) and the EXT-STEP inputs keep the same width at both sizes (P-22).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_width.py -k "at_b97_15 or at_b97_16"` (four screens × two sizes, plus an in-session `pilot.resize_terminal` 118x54 → 220x60 → 118x54).
- **Numeric pass threshold:** per screen and size: 0 displayed descendants with `region.right > panel.region.right` or `region.x < panel.region.x`; the LLR-149.3 primary actions inside the panel region at scroll 0 at 118x54; 0 wrapped ledger/log rows; at 220x60 every LLR-149.5 adaptive element wider than at 118x54, and after the resize back to 118x54 the overflow count is 0 again.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** at 118x54 nothing runs off the right edge and Run / Validate / Save Set / the document controls are on screen; at 220x60 the ledgers and inputs grow into the space instead of leaving a void; no table, ledger or log line breaks onto a second line.
  - **Shipped surface:** the four panels above, driven through the rail (`action_show_screen`) at the two terminal sizes.
  - **Acceptance test(s):** AT-B97-15, AT-B97-16
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — empty: N/A — geometry is asserted on the loaded scenarios, the empty states are covered by each screen's own AT; boundary: exactly 118x54 and 220x60, plus the in-session resize (AT-B97-16); invalid: N/A — sizes below 118x54 are outside the operator's supported range (§2.4); error: a 60-cell ref and the 47-cell parameter name, the widest real values, must clip with an ellipsis instead of overflowing (AT-B97-15).
  - **Negative control:** executed on `main` (§2.7 P-10, P-11, P-22): overflow counts 1/1/2/7 at 118x54 and 1/1/1/6 at 220x60; EXT-STEP inputs 28/26/28 at both sizes — both ATs are RED on today's tree.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level. EARS owed (`full`). ID format: `LLR-<HLR>.<M>`. A symbol marked `NEW` is created in Phase 3; every other symbol carries its `file:line` on `9c7beaf`. Test paths and selectors are provisional (V-5). Every `NEW` widget id below is a working name, fixed at PDR.

### LLR-144.1 — Patch Editor re-composed at its shipped ids
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `PatchEditorPanel` shall yield every one of its 66 shipped widget ids (§2.7 P-1) in the ledger + inspector composition, with each `patch_win_*`, `patch_saveback_row`, `patch_before_after_row` and `patch_checks_results` id keeping its `Container` type.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-01 — `pytest tests/test_b97_patch_editor.py -k tc_b97_01`: mount the app, `{w.id for w in panel.query("*")} ⊇` the 66-id set derived by the §2.7 P-1 census (re-run in the test from the source, not hand-listed), plus `query_one(id, Container)` for the container ids.
- **Numeric pass threshold:** 0 of 66 ids missing; 0 container-type mismatches.
- **Negative control:** remove one shipped id from the composition (mutation, executed at Phase 3 per C-40) → 1 missing id, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the census at 118x54 and 220x60 (an id hidden by `display:none` still counts; one never yielded does not). Empty/invalid/error: N/A — the composition has no input.

### LLR-144.2 — Full-height ledger and Inspector / JSON / Checks tabs
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `PatchEditorPanel` shall render `#patch_doc_entries_table` in the left column with a height that grows with the panel, and shall carry three tab chips (Inspector, JSON, Checks — ids NEW) that switch one `ContentSwitcher` (NEW) between the inspector pane (NEW), `#patch_win_json` and `#patch_win_checks`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-02 — at 118x54 with the 6-entry fixture: `table.region.height >= table.row_count + 1`; press each tab chip with `pilot.click` and read `ContentSwitcher.current` and the target pane's `display`.
- **Numeric pass threshold:** table region height ≥ 7 at 118x54 (today 3, §2.7 P-8 — `region (9, 6, 102, 3)`); 3 of 3 tab presses show their pane and hide the other two.
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
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When a change-set is loaded into the Patch Editor, the app shall feed the JSON tab (`#patch_win_json`) with `ChangeService.document` (`change_service.py:696`) serialised by `serialize_change_document` (`changes/io.py:1392`) through the I-2/I-3 seam at the `refresh_entries` sites (`app.py:3265`, `:3451`, `:5279`, `:10758`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-05 — load the fixture through the real Load control; `json.loads(<JSON tab text>)` (C-42: parse the emitted form) and compare its `entries[*].address` to the service document's entries.
- **Numeric pass threshold:** 6 parsed entries, address list `['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']` (the emitted form pasted in §2.7 P-5); the tab text never equals `DUMMY_CHANGESET_TEXT` after a Load.
- **Negative control:** executed on `main` (§2.7 P-4): buffer `== DUMMY True`, 2 address keys → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☒ invalid ☐ error — empty: a 0-entry document → `"entries": []`; invalid: a legacy v1 file → the empty document (not the previous one). Boundary/error: N/A — the serialiser is reused unchanged (`changes/io.py:1392`), its limits are not this batch's subject.

### LLR-144.6 — The JSON tab after an entry change (live or Update JSON — decided at PDR)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When an entry of the Patch Editor document is added, edited, removed, undone or redone, the JSON tab shall show the changed document either at once or after the engineer presses an `Update JSON` action (NEW), and in the second mechanism shall carry the stamp `generated from N entries · HH:MM` (NEW) naming the document it shows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-06 — one arm per writer of P-6 (Add, Edit, Remove, Undo, Redo) through the real chips; for the explicit mechanism, assert the tab is stale before `Update JSON` and current after, and that the stamp's N equals the parsed entry count.
- **Numeric pass threshold:** 5 of 5 writer arms leave the parsed tab equal to `serialize_change_document(service.document)` after the mechanism's step; stamp N == parsed count (explicit mechanism only). The mechanism is **decided at PDR** with its reason (brief R-1.1); both mechanisms satisfy this statement.
- **Negative control:** a JSON feed that skips one writer (mutation: drop the feed on Undo, executed at Phase 3 per C-40) → the Undo arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: Remove the last entry → `"entries": []`; boundary: Undo at the bottom of the stack (no-op) leaves the tab unchanged. Others N/A — entry validation is reused unchanged and is not this LLR's subject.

### LLR-144.7 — Identity ribbon: document name and kind, markup-safe (E-5, C-17)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `PatchEditorPanel` shall show the loaded document's file name (`ChangeDocument.source_path.name`, `changes/model.py:258`) and kind (`:253`) on an identity ribbon (NEW) built as a `rich.text.Text` through `safe_text` (`s19_app/utils.py:44`), never interpolated into a markup-parsed string; the call shape that delivers them (a `refresh_entries` keyword or a setter, I-2) is decided at PDR.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-07 — load a fixture file named with the payload `b97[bold]x[/]` + the batch-77 `_HOSTILE` string (`tests/test_tui_check_editor.py:52-56`) and `[link=https://e.invalid]l[/link]`; read the ribbon's `render()` (C-37: spans) and plain text.
- **Numeric pass threshold:** 0 `MarkupError`; plain text contains `[bold]`, `[/]`, `[link=` literally; 0 spans whose style is `bold` or a link; 0 C0/C1 control characters.
- **Negative control:** build the ribbon with `Text.from_markup(f"… {name}")` (mutation, Phase 3, C-40) → `MarkupError` or a bold span, RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☒ error — empty: a new unsaved document → the ribbon says `draft` with no name; error: the hostile name. Others N/A.

### LLR-145.1 — Check Editor re-composed: ledger, REPORT FIELDS card, one docked row
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `CheckEditorPanel` shall yield its 31 shipped ids (§2.7 P-2) with `#check_param_table` in the left column at full height, a REPORT FIELDS card with Fields / JSON / Addendum tab chips (ids NEW) on the right, and `#check_validate_button`, `#check_write_button`, `#check_apply_ghost` and `#check_fields_count` on one docked row; the panel shall offer no apply action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-08 — id census as TC-B97-01; the four docked ids share one `region.y`; tab presses switch the card; `check_apply_ghost` is not a `Button` that posts an apply.
- **Numeric pass threshold:** 0 of 31 ids missing; 1 distinct `region.y` across the 4 docked ids (today 2 rows: y=35 and y=38 at 118x54, P-12 probe); 3 of 3 tab presses; 0 apply actions.
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

### LLR-145.3 — Long parameter names keep their tail
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** If a parameter name is wider than the Parameter column, then the `CheckEditorPanel` shall paint it as an ellipsis followed by the name's tail, and when the column is at least as wide as the name it shall paint the name in full.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-10 — at 118x54 read the painted cell of the 47-cell name; at 220x60 the same row.
- **Numeric pass threshold:** at 118x54 the painted cell starts with `…` and ends with the name's last `w-1` characters; at 220x60 the painted cell equals the full 47-cell name.
- **Negative control:** a head-keeping truncation (mutation, Phase 3) → the tail clause RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a name exactly the column width (no ellipsis). Others N/A.

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
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `CheckEditorPanel` shall render every A2L parameter name, spec file name and REPORT FIELDS ledger line as `rich.text.Text` built through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-12 — an A2L fixture (NEW) whose CHARACTERISTIC name carries `[bold]`, `[/]`, `[link=https://e.invalid]` and `_HOSTILE`; read the ledger cell, the REPORT FIELDS line and the tab text (spans + plain). Whether the A2L loader admits the bracket payload in a name is `assumed — verify in Phase 3`; if it does not, the same payload rides the `.chk.json` file name (the AT-B94-13 precedent, P-25).
- **Numeric pass threshold:** 0 `MarkupError`; payload brackets literal in all 3 surfaces; 0 styled spans from the payload; 0 control characters.
- **Negative control:** render one surface with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

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
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The pipeline card renderer shall clip every title and IO line to the card's inner width, ending a clipped line with an ellipsis.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-16 — render a card whose ref is 60 cells and check every painted line's cell length.
- **Numeric pass threshold:** 0 painted card lines wider than the card; exactly 1 trailing `…` on the clipped line.
- **Negative control:** executed on `main` (§2.7 P-14): `_plc_block` with a 60-cell `text_` paints past `x + w` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a ref exactly the inner width (no ellipsis). Others N/A.

### LLR-146.5 — The foot row, and Run as the only primary chip
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowBuilderPanel` shall carry `#flow_run`, `#flow_clear`, `#flow_save` and `#flow_load` on one foot row and shall mark `#flow_run` as its only primary (bright) button.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-17 — the four ids share one `region.y`; `[b.id for b in panel.query(Button) if b.variant == "primary"]`.
- **Numeric pass threshold:** 1 row; the primary list equals `['flow_run']` (today `flow_screens.py:824` `variant="primary"` on Run).
- **Negative control:** add a second primary chip (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-146.6 — CRC family accent burnt orange, distinct from the waiting state
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `insight_style` module shall declare the CRC family token (NEW, value `#cf6a2d`), and the flow screens shall paint CRC cards with it and never with the waiting-state style.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-18 — read the CRC card's span style off `render().spans` (C-37) and couple it to the token constant; compute the hue distance between the token and the waiting style's colour (`colorsys`).
- **Numeric pass threshold:** CRC card span colour == the token; hue distance to the waiting colour ≥ 20° (executed: `#cf6a2d` hue 22.6°, shipped wait `#f6ff8f` hue 64.8° → 42.2°; the prototype amber `#e8a33d` would sit 13.2° away). The ≥ 20° figure is `assumed — verify in Phase 3` against the operator's capture; which hex the waiting state paints is decided at PDR.
- **Negative control:** executed: the token compared with `#e8a33d` → 13.2° < 20°, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a CRC card next to a waiting card in one capture (NEW fixture flow with a CRC block, §2.7 P-16). Others N/A.

### LLR-146.7 — Flow Builder strings in English
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowBuilderPanel` and the module-level flow banners shall paint every user-facing string in English.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-19 — the §2.7 P-17 AST census restricted to `flow_screens.py:1-1873`, plus the pinning tests rewritten (`tests/test_flow_funnel_b96.py`, 2 lines; the Builder lines of `tests/test_flow_external_step_b96.py`).
- **Numeric pass threshold:** 0 Spanish-marker constants in the span (today 26: 25 Builder + the banner `:235`).
- **Negative control:** executed on `main`: 26 → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: an English word sharing a marker (e.g. `hay` inside `hayward`) is excluded by the census's word boundaries. Others N/A.

### LLR-146.8 — File-derived text on cards renders literally (C-17)
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowBuilderPanel` shall render every flow name, block ref, file name and session path on the pipeline and the add form as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-20 — a block ref and a flow name carrying the hostile payload; read the pipeline's spans and plain text.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal; 0 styled spans from the payload; 0 control characters.
- **Negative control:** render the card title with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-147.1 — Per-lane pipeline with cable status from the retained record
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When a run record is rendered, the `FlowExecutionPanel` shall paint lane *i* from `last_run_record.outcomes[i]` (`flow_screens.py:2550-2553`) and paint the cable after block *j* with the glyph the table below gives for block *j* and block *j+1*.

| block *j* status (`flow_model.py:99-108`) | block *j+1* status | cable glyph |
|---|---|---|
| any | `waiting` | `□` |
| `ok` | not `waiting` | `▓` (`_FX_BAR_DONE`, `flow_screens.py:1795`) |
| `notices` | not `waiting` | `◇` (NEW) |
| `error` | not `waiting` | `✗` |
| `skipped`, `waiting`, or no record yet | not `waiting` | `░` (`_FX_BAR_GAP`, `:1796`) |

- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-21 — feed records built from the five statuses (one arm per table row) and read the painted cable glyphs per lane (structured read of the lane `Text`).
- **Numeric pass threshold:** 5 of 5 rows (6 status cells); with the `flash_q4` record of §2.7 P-15, lane 0 cables `▓ ▓ ◇`, lane 1 cables `▓ □ ░`.
- **Negative control:** executed on `main`: the panel paints a progress bar, not per-cable glyphs — no cable carries `◇` or `□` between blocks → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no record yet → every cable `░`; boundary: a 1-block lane (0 cables). Others N/A — the statuses are a closed enum.

### LLR-147.2 — The rebind input sits inside the SOURCE card
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowExecutionPanel` shall place each `fx_in_<i>_<j>` input (`flow_screens.py:2178`) inside the region of lane *i*'s SOURCE card *j*.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-22 — region containment of each input in its card region at 118x54.
- **Numeric pass threshold:** every rebind input contained (0 outside).
- **Negative control:** executed on `main`: the input is mounted in a row detached from the card (brief R-4) — containment fails → RED (`assumed — verify in Phase 3` that the detached row's region falls outside the card the new layout declares).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a lane with two SOURCE blocks (two inputs, two cards). Others N/A.

### LLR-147.3 — The paused-lane doctrine, Confirm inside the lane
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While a lane's record holds a `waiting` block, the `FlowExecutionPanel` shall paint that block's card in the pause style, show two red pending lines (log, output file) under the lane header, show `#fx_confirm_<i>` inside the lane's region, and show the line `log + output file: REQUIRED` (NEW) above the run log.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-23 — the paused fixture: region containment of `#fx_confirm_1` in lane 1, the two pending lines' spans (red), the REQUIRED line present while waiting and absent after Confirm.
- **Numeric pass threshold:** `#fx_confirm_1` contained; `#fx_confirm_0` not displayed; 2 pending lines; REQUIRED line count 1 while waiting, 0 after confirm.
- **Negative control:** executed on `main`: no REQUIRED line in the panel → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two lanes waiting at once (one REQUIRED line, two Confirms). Others N/A.

### LLR-147.4 — Two-row header; a two-word mode control
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowExecutionPanel` shall lay out a ribbon row (set identity, `#fx_import`, the mode control, `#fx_run`) and a set row (`#fx_set_name`, `#fx_save`, `#fx_set_select`, `#fx_load`), and shall present the mode as a two-word control (`sequential` / `parallel`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-24 — the eight ids inside the panel region at 118x54; the mode control's region width; switching the mode by its real control changes `last_run_record.mode` on the next Run (C-10, non-default `parallel`).
- **Numeric pass threshold:** 8 of 8 inside; mode control width < 30 cells (today `#fx_mode` 80 at 118x54, 164 at 220x60 — the 30-cell bound is `assumed — PDR confirms`); `record.mode == "parallel"` after choosing it.
- **Negative control:** executed on `main` (§2.7 P-11): `#fx_save`, `#fx_set_select`, `#fx_load` outside → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 and a 40-cell set name. Others N/A.

### LLR-147.5 — Flow Execution strings and run log in English
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowExecutionPanel` shall paint every user-facing string and run-log line in English.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-25 — the AST census over `flow_screens.py:1874-end`, and the painted run log of the paused fixture checked against the same marker regex; the pinning lines of `tests/test_flow_external_step_b96.py` rewritten.
- **Numeric pass threshold:** 0 Spanish-marker constants in the span (today 9); 0 Spanish markers in the painted log.
- **Negative control:** executed on `main` (§2.7 P-17): 9 constants; the painted line `· ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: as LLR-146.7. Others N/A.

### LLR-147.6 — File-derived text in lanes renders literally (C-17)
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `FlowExecutionPanel` shall render every chain name, template name, bound ref, written path and session path on the lanes, header and run log as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-26 — a lane named with the hostile payload, run once; read the lane, header and log spans and plain text.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal in 3 surfaces; 0 styled spans from the payload; 0 control characters.
- **Negative control:** interpolate the chain name into a markup string (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-148.1 — Chip family `flows`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `folder_open_service` shall declare a `flows` chip family (NEW `CHIP_FAMILY_FLOWS`) whose target is `project_dir / FLOWS_SUBDIR` (imported from `flow_persistence_service.py:95`, never re-declared) and `None` without a project.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-27 — `resolve_chip_target(p, family="flows", …)` and `(None, …)`; an AST import check that `folder_open_service` imports `FLOWS_SUBDIR` and holds no `"flows"` literal.
- **Numeric pass threshold:** `== p / "flows"`; `is None`; 1 import, 0 literals.
- **Negative control:** executed on `main`: `"flows" in CHIP_FAMILIES` is False → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project. Others N/A.

### LLR-148.2 — Chip family `session`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `folder_open_service` shall declare a `session` chip family (NEW `CHIP_FAMILY_SESSION`) whose target is the active project directory itself — the value `_publish_flow_session_dir` pushes (`app.py:8130-8137`) — and `None` without a project.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-28 — `resolve_chip_target(p, family="session", …)` and `(None, …)`.
- **Numeric pass threshold:** 2 of 2 arms — `== p` with a project, `is None` without one.
- **Negative control:** executed on `main`: `"session" in CHIP_FAMILIES` is False → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project. Others N/A.

### LLR-148.3 — The no-project message names the family's folder
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** If a chip's target resolves to `None`, then the `OpenFolderChip` shall disable itself and set a status message that names that chip's family folder, never another family's.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-29 — no project; mount the `flows`, `session` and `reports` chips; read the status after each refresh.
- **Numeric pass threshold:** 3 of 3 messages name their own family (Flows, Session, Reports); 0 messages naming `Reports` for `flows` or `session`.
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
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `S19TuiApp` shall build the Check Editor, Flow Builder and Flow Execution headers with `titled_header` (`open_folder_chip.py:185`) carrying an `OpenFolderChip` (families `checks`, `flows`, `session`) and a `WindowHelpChip`, as the Patch Editor header already does (`app.py:3048-3049`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-31 — for each of `#screen_patch`, `#screen_check_editor`, `#screen_flow`, `#screen_flow_execution`: one `OpenFolderChip` and one `WindowHelpChip` inside its `.db-screen-header`.
- **Numeric pass threshold:** 4 of 4 screens with 1 + 1 chips (today 1 of 4 with both: `app.py:3082` bare Label; `:2404` help only; `:2438` neither).
- **Negative control:** executed on `main`: 1 of 4 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 (the chips inside the header row). Others N/A.

### LLR-148.6 — Help entries name every control
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The `window_help` module shall carry an entry for each of the four screens — `patch` and `flow` rewritten, a Check Editor key and a Flow Execution key added (NEW, names fixed at PDR) to `WINDOW_HELP_SECTIONS` and `SHIPPED_WINDOW_KEYS` (`window_help.py:57`, `:270`) — whose body names every button label, tab label and glyph its screen renders.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-32 — per screen, the set of rendered button labels (glyph prefix stripped) collected from the live DOM (the rule's set, C-40 limb 2) ∪ the screen's legend glyphs, each searched in `section_body_text(key)`; `tests/test_window_usage_help.py:95-107` `_EXPECTED_KEYS` grows by the two keys.
- **Numeric pass threshold:** 100 % coverage on each of the 4 screens.
- **Negative control:** executed on `main` (§2.7 P-21): 6/19 · 0/6 · 2/13 · 0/4 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a label carrying a glyph prefix (`📂 Open folder`, `⊕ CRC`) is matched on its words. Others N/A.

### LLR-148.7 — A legend for every glyph vocabulary on screen
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The four panels shall each paint a one-line legend (id NEW) for every glyph vocabulary they render: the Patch Editor's before→after strip colours, the Check Editor's `✓` / `▪` marks, and the flow screens' cable glyphs of LLR-147.1.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-33 — every glyph the panel paints from its vocabulary appears in that panel's displayed legend text.
- **Numeric pass threshold:** 0 vocabulary glyphs missing from the legend on each of the 4 panels.
- **Negative control:** executed on `main`: no legend widget in `#fx_panel` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the legend fits on one painted row at 118x54 (LLR-149.4). Others N/A.

### LLR-149.1 — Widths derived at mount and on resize
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** When one of the four panels mounts or receives a resize, it shall derive its column widths, panel split and input widths from its current content width.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-34 — in one session at 118x54, `pilot.resize_terminal(220, 60)`, then back; read the LLR-149.5 elements' widths after each step.
- **Numeric pass threshold:** each element's width at 220x60 > its width at 118x54, and back at 118x54 equal to the first reading.
- **Negative control:** executed on `main` (§2.7 P-22): `#flow_ext_instruction` 28 at both sizes → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two resizes in one session. Others N/A.

### LLR-149.2 — No horizontal overflow at 118x54 and 220x60
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While displayed at 118x54 or 220x60, each of the four panels shall keep every displayed descendant's painted region inside the panel's region on the x axis.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-35 — the §2.7 P-10 probe as a test: count displayed descendants with `region.right > panel.region.right` or `region.x < panel.region.x`, per screen and size (reads `region`, not `max_scroll_x`, which reads 0 on a clipped overflow, C-32).
- **Numeric pass threshold:** 0 on 8 of 8 screen×size cells.
- **Negative control:** executed on `main` (§2.7 P-10): 1/1/2/7 and 1/1/1/6 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: the two sizes; error: the widest real values (60-cell ref, 47-cell name, 40-cell set name).

### LLR-149.3 — Primary actions inside the viewport at 118x54
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While displayed at 118x54 with the panel scrolled to its top, each panel shall keep its primary actions inside the panel region: `#patch_doc_load_button`, `#patch_doc_save_button`, `#patch_doc_validate_button`, `#patch_doc_apply_button`; `#check_validate_button`, `#check_write_button`; `#flow_run`; `#fx_run`, `#fx_save`, `#fx_load`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-36 — region containment of each id in its panel region at scroll 0, with `patch_chain` and the EXT-STEP form open.
- **Numeric pass threshold:** 10 of 10 inside.
- **Negative control:** executed on `main` (§2.7 P-11): `#flow_run`, `#fx_save`, `#fx_load` outside → 7 of 10, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the EXT-STEP form open (the tallest add form). Others N/A.

### LLR-149.4 — No wrapped ledger or log row
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** The four panels shall paint each logical row of their ledgers, run log, pipeline rows, identity ribbons and legends on exactly one terminal row, truncating with an ellipsis that keeps the discriminating part (file and parameter names keep the tail; addresses are never truncated).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-37 — for each such `Static`, painted height (`region.height` under `height: auto`) == its logical line count; for each `DataTable`, `max_scroll_x == 0` with every cell painted on its row; at both sizes with the widest real values.
- **Numeric pass threshold:** 0 wrapped rows on 8 of 8 screen×size cells.
- **Negative control:** a 20-cell width forced on `#fx_log` (mutation, Phase 3, C-40) → painted height > line count, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a log line exactly the panel width; error: the widest real values.

### LLR-149.5 — No fixed-width void at 220x60
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1
- **Statement:** While displayed at 220x60, the four panels shall give their adaptive elements — the Patch Editor ledger, the Check Editor parameter table and its Parameter column, the Flow Builder pipeline and EXT-STEP inputs, the Flow Execution lanes — the width their split assigns, so that no void is left by a width fixed for 118.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-38 — at 220x60, each element's width vs its 118x54 width (LLR-149.1) and the Parameter column showing the 47-cell name in full (LLR-145.3).
- **Numeric pass threshold:** every adaptive element wider at 220x60 than at 118x54; 47-cell name in full.
- **Negative control:** executed on `main` (§2.7 P-22): EXT-STEP inputs equal at both sizes → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 220x60. Others N/A.

### Information Flow Contract (IFC) — C-54

> Part A — one FLOW block per information flow this batch adds or re-routes; every node has exactly one owner LLR. LLRs that state structure rather than a transform (144.1-144.4, 145.4, 146.5, 146.7, 147.2, 147.4, 148.4, 148.7, 149.2, 149.3, 149.5) own Part B outputs instead of nodes. Part B — the trigger question is answered **yes**: the four panels and their header chips are components a consumer addresses independently (tests and the app select a panel by id and index its children). Component ids are new (V19: one id, one declaration, across the corpus — batch-94 already declared `patch_editor_panel` & co.).

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
    - fn    : app-to-panel JSON feed at the refresh_entries sites (I-3, NEW)
      owner : LLR-144.5
      in    : canonical v2 JSON text
      out   : the JSON tab's text
  SINK   : the JSON tab #patch_win_json, read by the engineer
```

```
FLOW: entry_change_to_json_tab
  SOURCE : an Add / Edit / Remove / Undo / Redo on the Patch Editor
  NODES  :
    - fn    : the ChangeService writers of the document (change_service.py:861, :893, :1080, :1154, :1196, :1223, :1344)
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
    - fn    : safe_text render (utils.py:44)
      owner : LLR-144.7
      in    : name + kind strings (file-derived)
      out   : rich Text with no markup parsed
  SINK   : the Patch Editor identity ribbon (NEW)
```

```
FLOW: a2l_parameters_to_check_ledger
  SOURCE : the loaded A2L file
  NODES  :
    - fn    : S19TuiApp._prefill_check_editor (app.py:5329)
      owner : LLR-145.1
      in    : parsed A2L tags
      out   : parameter rows
    - fn    : Address column sizing and placement
      owner : LLR-145.2
      in    : parameter rows + table content width
      out   : column widths with Address fully inside the viewport
    - fn    : tail-keeping name truncation
      owner : LLR-145.3
      in    : parameter name + Parameter column width
      out   : painted name (ellipsis + tail, or full)
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
    - fn    : CRC family paint with the burnt-orange token (NEW)
      owner : LLR-146.6
      in    : block kind
      out   : card style
    - fn    : safe_text render of flow names, refs, paths
      owner : LLR-146.8
      in    : file-derived strings
      out   : rich Text with no markup parsed
  SINK   : the Flow Builder pipeline (NEW)
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
    - fn    : paused-lane paint, pending lines, Confirm placement, REQUIRED line
      owner : LLR-147.3
      in    : waiting block index per lane
      out   : pause-styled card + #fx_confirm_<i> inside the lane
    - fn    : run-log lines in English
      owner : LLR-147.5
      in    : outcome status + block index
      out   : English log lines
    - fn    : safe_text render of chain names, refs, written paths
      owner : LLR-147.6
      in    : file-derived strings
      out   : rich Text with no markup parsed
  SINK   : #fx_lanes and #fx_log
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
    - fn    : OpenFolderChip._open_target to the open seam (open_folder_chip.py:139)
      owner : LLR-148.5
      in    : resolved target
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
    - fn    : per-panel width derivation (NEW, on mount and on_resize)
      owner : LLR-149.1
      in    : panel content width
      out   : column widths, split, input widths
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
      consumers   : s19_app/tui/screens.py
                    s19_app/tui/screens_directionb.py
                    s19_app/tui/services/change_service.py
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
      consumers   : none
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

> `consumers : none` is written where no file reaches the address today: the address is NEW (`#patch_identity_ribbon`, `#flow_pipeline`, `.glyph-legend` — working names fixed at PDR) or only the throwaway prototypes reach it (`#fx_set_row`). The defining modules are declared as consumers (they query their own ids and break if the address moves); `REQUIREMENTS.md` and `.fast-dev-flow/archive/…` reach two addresses as prose mentions and are not dependants; `prototypes/**` is never imported (the ARQ boundary) and is not declared. The batch's ATs/TCs become their consumers in Phase 3 and the Phase-4 record re-runs `V13`/`V14`.

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-B97-01` … `TC-B97-38`):** one TC per LLR, validating the mechanism. Methods: `test (unit)` / `test (integration)` under `App.run_test` (Textual 8.2.8, pytest — the project's ratified runtime, `pyproject.toml:66-73`).
> - **Layer B — black-box / behavioral acceptance (`AT-B97-01` … `AT-B97-16`):** at least two per story, driving the real controls (`pilot.click` / `pilot.press` on the shipped ids, the real Load / Run / chip presses, `pilot.resize_terminal`) and observing the painted result (C-32: `region`, `_render_line`, `render().spans`; C-42: parse the emitted JSON / Text, never substring-match the readable form).

- **C-10 (one AT per policy branch, a non-default value driven through the real control):** JSON tab after Load (AT-B97-01) vs after Add (AT-B97-02); Address at 118 vs 220 and Include changing the count (AT-B97-04); palette kinds — one arm per kind (AT-B97-07); sequential default vs the driven `parallel` mode (TC-B97-24); chip with project (AT-B97-12) vs without (AT-B97-13); 118x54 (AT-B97-15) vs 220x60 + resize (AT-B97-16).
- **C-12 (a produced artifact consumed):** Save Set writes the set file and Load Set restores it (AT-B97-10); the JSON tab is the consumer of the serialiser's output (AT-B97-01).
- **C-16:** n/a — the prototypes are Textual monkeypatches over the shipped app, the same technology as the target (brief §2), and trigger D2 did not fire; the ATs still drive the real mechanism.
- **C-17:** LLR-144.7, LLR-145.5, LLR-146.8, LLR-147.6 with the hostile ATs AT-B97-03, -05, -08, -11 (payload: batch-77 `_HOSTILE` + `[bold]`, `[/]`, `[link=https://e.invalid]…[/link]`).
- **C-40:** every NEW predicate's RED counterfactual is executed in its increment (`**RED counterfactual**` field); the ones already RED on `main` are stated per LLR above.
- **Fixtures:** copied from the demo project into `tests/` (NEW, Phase 3); real Runs write into `tmp_path` only (brief F-10).
- **Captures:** each increment re-captures its screen at 118x54 and 220x60 into `prototypes/b94_polish/png/impl.*` for the operator's side-by-side judgement (brief §4.7) — a `demo`, auxiliary to the ATs.

### 5.2 Batch acceptance criteria
- 100 % of the 38 LLRs covered by their TC with a pass result; 16 of 16 ATs pass; every story has ≥ 2 ATs with boundary and negative evidence.
- 0 blocker fails at Phase 4; the full guard host `tests/test_tui_directionb.py` green at every render increment (C-34).
- Snapshot drift ≤ 2 cells (the two `patch` cells, §2.7 P-26), marked per cell (C-22).
- The 11 pinning lines of `test_flow_external_step_b96.py` / `test_flow_funnel_b96.py` rewritten to English, not deleted (§2.7 P-17).
- No requirement without a validation method; the operator judges the captures on the review page before the batch closes.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
Decided at ARQ (`docs/architecture.md`, batch-97 section): R13 in-place re-composition, R14 project-only chip families, R15 `FLOWS_SUBDIR` imported, R16 the token in `insight_style.py`, R17 the canonical serialiser feeds the JSON tab.

**Deferred to PDR (each named in the LLR it governs):**
1. JSON tab refresh: live vs `Update JSON` + stamp (LLR-144.6; brief R-1.1).
2. JSON tab widget: reseed `#patch_paste_text` inside `#patch_win_json`, or a new read-only view, and what that means for the A-01 guard that disables Edit JSON on a stale buffer (LLR-144.5).
3. I-2 / I-3 call shape: a `refresh_entries` keyword with the `mem_map` sentinel idiom, or a setter (LLR-144.5, LLR-144.7).
4. The Check Editor chip id scheme — scoping or a suffix (LLR-148.4; ARQ open question 1).
5. Create-on-press for `flows` / `session` (HLR-148 boundary arm; ARQ open question 2).
6. The two new help keys' names, and whether Flow Execution becomes a `WindowSection` (focused `?`) (LLR-148.6).
7. The waiting-state hex — the shipped `YELLOW #f6ff8f` or the prototype's amber — and the CRC token's name; the ≥ 20° hue rule (LLR-146.6; ARQ open question 4).
8. Whether the grid canvas stays reachable, which decides whether `_CANVAS_COLS` (F-2/F-3) must become width-derived (LLR-146.1).
9. The mode control's width bound (LLR-147.4).
10. The final names of every NEW widget id in §4 / IFC Part B.

### 6.3 Open risks
- **Security pattern scan (2026-10-20):** `devflow-scan-spec.py` over this file → 5 of 5 controls ok, flags `token`, `session`, `user input`, `form`, `security_required: true` (exit 1). Answers: **`token`** — a design (colour) token in `insight_style.py`, not a credential; no secret, key or auth token is read, stored or shown by this batch. **`session`** — the flow session directory (the active project dir), not an auth session; its chip only opens that folder through the existing seam (risk below). **`user input`** / **`form`** — the add form and the set-name / rebind inputs keep their shipped validation (batch-94/96: containment of refs, the EXT-STEP log/output refusal, `save_flow_json` → `sanitize_project_name`, `flow_persistence_service.py:970`); this batch moves them and adds no new write path; every file-derived string they echo is covered by the C-17 LLRs. Routed to the security lens at Phase 2.
- **C-17:** four new renders of file-derived text (§5.1). The existing `safe_text` covers control characters and wraps as literal `Text` (`utils.py:41-44`); the new risk is a render path that bypasses it. Mitigation: the four hostile ATs plus the guard host's source scan (`tests/test_tui_directionb.py:8231`).
- **The `session` chip opens the project directory itself** — a wider folder than any other chip opens; it rides the same seam (`open_folder_in_file_manager`, one call per press, no shell string), so no new external action surface is added. Flagged for the security lens at Phase 2.
- **A2L name admission:** whether the loader admits a bracket payload in a CHARACTERISTIC name is `assumed — verify in Phase 3` (LLR-145.5 names its fallback).
- **Hue proximity:** if PDR moves the waiting state to amber, the CRC token sits 12-13° away (LLR-146.6 executed figures); the operator's capture decides.
- **Test churn:** 24 test files reach the Patch Editor's ids (§2.7 P-1 census); a re-composition that keeps the ids keeps them green, but layout assertions (`test_tui_patch_layout.py`, 9 tests) will move with the layout and are re-baselined per increment with the reason recorded.
- **The brief's line numbers drifted** (E-2 `:6848` → `:6978`); every line cited here was re-read on `9c7beaf`.

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
