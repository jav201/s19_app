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
the six READY stories US-134..US-139 and their LLRs, plus HLR-150 (the two-row key bar, US-140) that
the operator routed into the batch after the key-bar prototype round (LED-…97.9), and declares the acceptance tests
(`AT-B97-NN`), the white-box tests (`TC-B97-NN`) and the Information Flow Contract. The full
probe transcripts, the frozen literals and the P0 refinement log live in the companion
`01-requirements-appendix.md` (A.1 premise transcripts, A.2 literals, A.3 refinement log, A.4 TC procedures,
A.5 fixtures and the per-AT table), which is cited, never normative.

### 1.2 Scope
**In:** the re-composition of `PatchEditorPanel`, `CheckEditorPanel`, `FlowBuilderPanel` and
`FlowExecutionPanel` at their shipped widget ids; the Patch Editor's live, read-only JSON view;
the open-folder chip (labelled with its folder) and the help chip on all four screens (two new
chip families, `flows` and `session`; the real-directory guard and the label apply to every chip
in the app); the waiting colour `#e8ad3d` and the CRC colour `#c9562b`; English UI strings on the
four screens, including the eleven `flow_execution_service.py` strings that paint on the two flow
screens (§2.7 P-17); keyboard reachability, a scoped confirm key and region states on the four
screens; width-adaptive layouts at any size from 118x54 up with no wrapped rows, the shipped 80x24
floor kept reachable under scroll; markup safety (C-17) for every render of file-derived text on
the four screens; the refusal of NUL characters in flow, chain-set and manifest refs; the two-row
bottom key bar on every window of the app — the global keys on row 1, the active window's keys on
row 2 — that replaces the one-row `Footer` (HLR-150, LED-…97.9, the one app-wide change besides the chips).
**Out:** the items listed under "Not taken in" in §2.6; run semantics, persistence formats and
the batch-96 waiting-human doctrine itself; chips and help on any other screen.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| ledger | a full-height table that lists the screen's records one per row (entries, A2L parameters) |
| inspector | the right-hand column that shows the highlighted ledger row and the tab chips |
| pipeline rail | one horizontal row of block cards joined by cable glyphs (fb_A / fx_A) |
| cable status glyph | the glyph painted on the cable after block *j*: `▓` ok · `░` not run · `✗` error · `◇` notices · `□` into a waiting block (LLR-147.1 truth table) |
| hero | the screen's growing region, painted as its main object: the Patch Editor ledger, the Check Editor parameter ledger, the Flow Builder pipeline, the Flow Execution lanes |
| filled element | a displayed `Button` whose `variant == "primary"`, or a widget carrying the filled-accent class (NEW, name fixed at PDR); the hero is filled by definition and is never counted among "the filled elements besides the hero" |
| selection style | the style of the active tab chip or the selected kind chip (class NEW); its background differs from the filled accent and it is not a fill; a tab or kind chip paints three pairwise distinct styles — unfocused, focused, selected |
| waiting-human elements | the waiting block's card, the cable into it, the paused lane's status text, `#fx_confirm_<i>` of a waiting lane, the REQUIRED line, and the `□` mark of a waiting line in the run log |
| waiting colour / CRC colour | `#e8ad3d` (hue 39.3°) / `#c9562b` (hue 16.3°), 23.0° apart (§2.7 P-40), declared as NEW `insight_style` tokens |
| accent colour | a painted foreground or background colour whose HSV saturation is ≥ 0.15 (greys and whites, whose hue is undefined, are not accents) |
| horizontal overflow | a displayed descendant of a panel whose **clipped region** extends past the panel's region on the x axis; the clipped region is `widget.region` intersected with the `content_region` of every ancestor strictly inside the panel whose `overflow_x` is `auto` or `scroll` (a part scrolled out of such an ancestor is reachable, not overflow); an ancestor that does not scroll clips nothing (C-32; §2.7 P-52) |
| wrapped row | one logical ledger/log line painted on more than one terminal row, or clipped to fewer rows than its content height |
| 118x54 / 220x60 | the minimum and the large reference terminal sizes; "the range" = every width ≥ 118 and height ≥ 54; "below the range" = width < 118 or height < 54 |
| shipped id | a literal `id="…"` a panel's `compose` yields on `main` at `9c7beaf` |
| content region | a widget's `content_region` (its region minus border and padding) |
| painted extent | the rightmost terminal column inside a content region whose painted cell is not blank (read from the compositor's strips, C-32) |
| no-wrap set | the ledger rows, run-log lines, pipeline rows, identity ribbons, legends, inspector headings and REPORT FIELDS lines of a panel |
| focus order | the order of `app.screen.focus_chain` restricted to the panel's ids and its header chips |
| control / read-out | a **control** is a displayed `Button`, `Input`, `Select`, `TextArea`, `DataTable` or tab chip, or a scroll view a focus order names by id (`#fx_lanes_scroll`, the Check Editor's JSON / Addendum scroll views); a **read-out** is a displayed `Static` or `Label` that takes no key (§2.7 P-55) |
| attention lane | the first waiting lane, in lane order, whose waiting card and `#fx_confirm_<i>` have been painted; its Confirm carries the attention class; after a confirm the attention moves to the next waiting lane once that lane has been painted |
| family root | the active project directory when a project is active; otherwise the tool root `app.base_dir / WORKAREA_DIRNAME` (`.s19tool`, `workspace.py:16`), which holds every common home |
| window | one surface the app can make active: a key of `SCREEN_CONTAINER_IDS` (`app.py:6752`, 12) or `split_join` (the Split / Join / Export window, `app.py:7036`) — 13 in all |
| key bar | the two-row bar docked at the bottom of the app (NEW, I-11), replacing the shipped `Footer`: row 1 the global tokens, row 2 the active window's tag, its window tokens and its go tokens |
| token | one painted key glyph + description pair (`^s Save`); a token is painted whole or not at all |
| window key / go key | an entry of the window-key table (NEW, I-10) for one window: a key that window handles / a key that takes the engineer from that window to one of its workflow neighbours — a rail jump (`6`, `9`, `=`, `]`, …) or the reports view (`t`) — an editorial choice recorded in the table, reviewable there |
| dimmed token | the token of a key a window handles that cannot act in the current state (a condition of the table is false), painted with the `dim` attribute and not clickable |

### 1.4 References
- Brief: `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md` (§1 verdict, §3 R-1..R-9, §4, §5).
- ARQ: `docs/architecture.md` §"Batch-97 declarations — the b94 polish port" (I-1..I-4, R13-R17, open questions).
- Prototype evidence (design intent, never imported): `prototypes/b94_polish/variants/{pe_A,ce_A,fb_A,fx_A}.py`, `NOTES.editors.md`, `NOTES.flows.md`, `png/`, `colores-espera-crc.html`.
- Companion: `01-requirements-appendix.md` (A.1 premise transcripts, A.2 frozen literals, A.3 refinement log, A.4 TC procedures, A.5 fixtures and per-AT table).
- Project rules: `docs/engineering-rules.md` (C-13, C-13.1, C-23, C-29, C-32, C-34, C-37, C-42; AT/TC id routing).
- Standards: ISO/IEC/IEEE 29148:2018; EARS.

### 1.5 Document overview
§2 context, stories (§2.6, P0), premises (§2.7), fork preconditions (§2.8); §3 one HLR per story
with its acceptance block; §4 LLRs and the Information Flow Contract; §5 the two-layer validation
strategy; §6 the implementation-shape items left to PDR and open risks. The ledger is
`01-requirements-ledger.md`.

---

## 2. Overall description

### 2.1 Product perspective
s19_app is a Textual TUI over S19/HEX images, A2L files and change-sets. Batch-94 shipped the four
panels; this batch changes their layout and four seams named by ARQ (I-1 chip families, I-2/I-3
the Patch Editor's identity + JSON feed, I-4 the help keys), plus the loader-side NUL refusal
(S2-2). No module is created and no boundary moves (ARQ: A1, B2 not fired).

### 2.2 Product functions
Patch Editor ledger + inspector with a live JSON view · Check Editor ledger + report-fields card ·
Flow Builder pipeline rail with a contextual add form, single-image Run · Flow Execution per-lane
pipeline with cable status and a scoped confirm key · folder + help chips on the four screens ·
width-adaptive layouts.

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
- Size regimes: **118x54 minimum** for the no-overflow and primary-actions properties, **220x60 large reference**; widths derived from the available width, never fixed to 118. The shipped **80x24 floor is kept**: below the range the four screens stay reachable under scroll (LLR-007.1 / CV-04 not superseded, LLR-149.6). The `width-narrow` breakpoint (`app.py:7475` `narrow = width < 120`) falls inside the range, so 118 and 119 are narrow and 120 up is wide.
- Runs stay on the UI thread, as shipped (`app.py:2815`); the UI freezes for the run's duration — 0.021 s median for the 3-lane demo set (§2.7 P-42) — and that freeze is declared OUT (§2.6).
- Python 3.11, Textual 8.2.8 (`pyproject.toml:73` pins `textual==8.2.8`; `textual.__version__` → `8.2.8`).
- The no-apply doctrine of `.chk.json` (`PDR-2026-10-12-batch-94#D2`) and the batch-96 waiting-human doctrine stay as they are.
- Ids: batch-scoped `AT-B97-NN` / `TC-B97-NN` (`docs/engineering-rules.md:48`), no registry reservation.

### 2.5 Assumptions and dependencies
Every assumption the contract relies on is a row of §2.7 with executed evidence. Acceptance
fixtures use the tracked `examples/case_00_public/ASAP2_Demo_V161.a2l` and `prg.s19`, and
`examples/crc_config.example.json` for the CRC block, and generate every JSON fixture (change-sets,
`.chk.json`, flows, sets) in `tmp_path` with the current serialisers (fixture table, appendix A.5); every fixture project
lives under `tmp_path/.s19tool/workarea/<name>` (write-out containment, P-41).

### 2.6 Source user stories

Source for every story: the operator-approved prototype round `prototypes/b94_polish/` (verdict
`veredicto-b94-polish.md`, final section: **A on all four screens**, confirmed in chat 2026-10-19
"Sí, cambié de opinión") and its implementation brief `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md`
(§1 verdict, §3 R-1..R-9). The P0 refinement log (INVEST, functionality, feasibility,
evaluability, one block per story) is appendix A.3.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-134 | As the calibration engineer editing a change-set, I want the Patch Editor as a full-height entries ledger beside an inspector (before→after hex strip, labelled entry form, chips) whose JSON tab shows the current document on demand, so that I see my whole document and can consult the JSON without a permanently empty panel. | verdict pe_A + the operator's JSON condition (handoff R-1) | READY |
| US-135 | As the calibration engineer assembling a check spec, I want the Check Editor as a full-height A2L parameter ledger with the address always visible beside a report-fields card (fields / JSON / addendum tabs), with Validate and Write on one docked row, so that I pick parameters by address and see what the report will hold. | verdict ce_A (handoff R-2) | READY |
| US-136 | As the engineer composing a flow, I want the Flow Builder as one horizontal pipeline of block cards joined by cables, with a contextual add form showing only the inputs the chosen kind needs and Run reachable without scrolling, so that the chain reads as one object and no input runs off screen. | verdict fb_A (handoff R-3, R-5) | READY |
| US-137 | As the engineer running flow sets, I want Flow Execution as one pipeline per lane with each cable carrying its block's run status, the rebind input inside the source card, the batch-96 waiting-human doctrine kept, and an English run log, so that I read a whole set's state at a glance and know exactly which lane waits for me. | verdict fx_A (handoff R-4, R-5) | READY |
| US-138 | As an engineer new to the tool, I want every one of the four screens to carry a visible open-folder chip for the folder its files live in and a help chip whose entry names every control and glyph on that screen, so that I never guess where files are or what a mark means. | operator round-2 answer: "es un problema adivinar y buscarlos, sobre todo para usuarios nuevos"; verdict note: "No olvides las leyendas y ayudas en cada ventana" (handoff R-6, R-7) | READY |
| US-139 | As an engineer who scales the terminal to taste (≈220x60, variable), I want the four screens to use the width they get — no horizontal overflow at 118x54, no half-screen voids from fixed widths at 220x60, and no row ever wrapping onto a second line — so that information density follows the window. | operator round-2 answer + the 220x60 pass (handoff R-8) | READY |
| US-140 | As an engineer moving between the app's windows, I want two rows of keys at the bottom — the global keys always in the same place on the first row, and on the second the keys that act on the window I am in and the windows it leads to — so that I find the keys that matter here without guessing and never read a key that does nothing on this window. | the operator's PDR objection 2026-10-20 (PC-22, `evidence/operator-pdr-verdict-2026-10-20.md`) and the key-bar prototype round `prototypes/keybar/` — verdict **A · Two rows** accepted and preferred, no per-screen objection (`evidence/operator-keybar-verdict-2026-10-20.json`); the operator's instruction in chat 2026-10-20 "Mete el cambio al incremento" routes it into this batch (LED-…97.9) | READY |

**Ledger pairing:** stories live in this table (the batch-91 shape); the ledger entries name the
HLR/LLR they trace to.

**Not taken in (OUT, with where it lives):** the `Fmt · Unit` column of ce_C as a layout choice and the matrix density mode (fx_C) — offered, not chosen (ce_A's own `Fmt · Unit` column stays, LLR-149.4); the hex-viewer no-wrap rule outside these four screens — `.dev-flow/BACKLOG-CODE.md:1393` (P2, origin A-15); bidi/zero-width controls through `safe_text` — `BACKLOG-CODE.md:1394` (S-6); go keys for the eight windows the key-bar prototype round did not render (A2L, MAC, Map, Issues, Diff, Checks, CRC Designer, Split / Join / Export) — a later edit of the window-key table, not this batch; a loading state on the two editors — Load, Validate and Write run synchronously on the UI thread, so no region shows a partial load; **a running state and a worker for Flow Execution** — runs stay on the UI thread (orchestrator decision 9, revisable at PDR), the measured demo freeze is 0.021 s (P-42), and a large image may freeze the UI for longer (§6.3); **a variant-scope selector in the Flow Builder** — retired with the operator's consent (LLR-104.6 retired for the Builder, §6.3): multi-variant work runs as one chain per variant, each set up through its funnel block and run as a lane in Flow Execution (AT-B97-22 drives two lanes over two source images); the eight Code-Wire pilot findings — already in `BACKLOG-CODE.md` (`51ee191`); the batch-96 follow-ups — untouched.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

Probes executed 2026-10-20 on `9c7beaf` and on `0f21e00` (`git diff --stat 9c7beaf 0f21e00 -- s19_app` → empty). Each row's evidence cell carries the decisive output; the full transcript of every row is appendix A.1 under the same id.

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (decisive output) | Disposition |
|---|---|---|---|---|---|
| P-1 | `PatchEditorPanel` (`screens_directionb.py:4383-6861`) yields 66 literal ids; 65 are reached from outside the panel. | premise | ✅ TRUE | AST census → `PatchEditorPanel 4383 6861 66`; reach `65/66` | LLR-144.1 keys on the frozen set (A.2) |
| P-2 | `CheckEditorPanel` (`:6864-7551`) yields 31 literal ids; 14 reached from outside. | premise | ✅ TRUE | `CheckEditorPanel 6864 7551 31`; reach `14/31` | LLR-145.1 |
| P-3 | `FlowBuilderPanel` (`flow_screens.py:502-1799`) yields 39 literal ids + `flow_palette_{kind}`; `FlowExecutionPanel` (`:1874-2693`) 23, 6 computed. | premise | ✅ TRUE | `39 literal ids … 31/39 reached`; `23 literal ids … 12/23 reached` | LLR-146.1 / 147.1 |
| P-4 | After Load of `calib_hotfix.json` the JSON editor still holds the dummy template (E-6). | premise | ✅ TRUE | `service entries 6 source calib_hotfix.json` · `json buffer == DUMMY True address-keys in buffer 2` | RED side of AT-B97-01 / TC-B97-05 |
| P-5 | The canonical serialiser emits the loaded document with all six entries. | premise | ✅ TRUE | `bytes: 706 lines: 39`; `addresses: ['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']` | predicates parse the JSON (C-42) |
| P-6 | `ChangeService.document` has exactly nine writers (`change_service.py:861, 893, 1080, 1154, 1196, 1223, 1344, 1404, 1465`); eight have an app caller, `add_symbol_entry` none. | premise | ✅ TRUE | writer grep → the nine sites; app callers `app.py:3152, 3157, 3162, 3177, 3589, 3615, 3823` + Load; `add_symbol_entry` 0 callers | LLR-144.6 quantifies over these nine |
| P-7 | The shipped panels add their table columns exactly once (E-1 is a prototype artefact). | premise | ✅ TRUE | `table columns 5 ['Kind', 'Address', 'Value / bytes', 'Status', 'Linkage']`; `add_columns` at `:5613`, `:7365`, `:7368` | LLR-144.3 pins `len(columns) == 5` |
| P-8 | `_apply_window_geometry` has three call sites (`screens_directionb.py:5596`, `:5656`, `app.py:6978`), no test references it; `on_mount` forces height 3, widths 30 / 28. | premise | ✅ TRUE | `grep -c` → `app.py:1`, `screens_directionb.py:7`; `tests/` empty | LLR-144.3 |
| P-9 | The E-3 rules exist in `styles.tcss` (`:1117-1118`, `:1536-1538`, `:1160-1168`, `:1581-1584`). | premise | ✅ TRUE | `grep -n` over `styles.tcss` | LLR-144.4 |
| P-10 | Today every one of the four screens overflows horizontally at both sizes. | premise | ✅ TRUE | 118x54 → 1 / 1 / 2 / 7; 220x60 → 1 / 1 / 1 / 6; `max_scroll_x` 0 on three (clip, C-32) | RED side of LLR-149.2 |
| P-11 | At 118x54 the Builder's Run and Execution's Save Set / Load Set sit outside the panel viewport at scroll 0, `#fx_mode` is 80 cells wide; the editors' primary actions are inside. | premise | ✅ TRUE | panel `(5,4,112,40)`; `#flow_run (51, 48, 16, 3)`; `#fx_mode (21, 7, 80, 3)`; `#fx_save (117, 10, 16, 3)`, `#fx_load (134, 10, 16, 3)` off screen | LLR-149.3, LLR-147.4 |
| P-12 | At 118x54 the Check Editor's Address column is clipped (render widths 3+49+12+15 in a 56-cell table, `max_scroll_x 25`). | premise | ✅ TRUE | `param table region (5, 8, 56, 40) rows 75 scroll_x max 25` | LLR-145.2 / 145.3 |
| P-13 | The palette offers 4 kinds while `_KIND_OPTIONS` lists 7; the handler accepts any `flow_palette_<kind>`. | premise | ✅ TRUE | 4 palette ids; `flow_screens.py:542-551`; `:1455-1461` | LLR-146.2 |
| P-14 | `_plc_block` paints a block's IO text without clipping (F-1). | premise | ✅ TRUE | `flow_screens.py:440`, `:443` `g.put(x + 6, yy, text_, tstyle)` | LLR-146.4 |
| P-15 | The retained run record carries per-block status, and outcome *i* belongs to lane *i* (F-8). | premise | ✅ TRUE | writers `flow_execution_service.py:1546`, `:1548`; `outcome[1] … status=paused blocks=0:ok,1:ok,2:waiting,3:skipped` | LLR-147.1 (no record change) |
| P-16 | No CRC family colour ships; the waiting state paints `.sev-warning` = `YELLOW #f6ff8f`; no demo flow holds a CRC block. | premise | ✅ TRUE | `flow_screens.py:211`, `:1800`; `insight_style.py:64`; demo kinds listed in A.1 | LLR-146.6; `crc_wait_chain` fixture |
| P-17 | With the extended `ES_MARKER` (A.2) the painted Spanish census on `9c7beaf` is 48 non-docstring constants: 27 in `FlowBuilderPanel`, 9 in `FlowExecutionPanel`, 1 module constant (`flow_screens.py:235`), 11 in `services/flow_execution_service.py`; 0 in `PatchEditorPanel`, `CheckEditorPanel`, `window_help.py`; 14 assert lines pin them. | premise | ✅ TRUE | `p1r3/es48.py` → `FB 27 FX 9 MOD235 1 SVC 11 TOTAL 48` · `PatchEditorPanel 0 CheckEditorPanel 0 window_help 0`; same on `0f21e00` | LLR-146.7 / 147.5 key on the frozen `ES_48_9C7BEAF` |
| P-18 | Chip families: 4 (`folder_open_service.py:57-64`); the no-project status names Reports for any `None` target; flows live at `project_dir / FLOWS_SUBDIR`; the session dir is the active project dir. | premise | ✅ TRUE | `:78`; `open_folder_chip.py:115`, `:160`; `flow_persistence_service.py:95`, `:973`; `app.py:8130-8137` | LLR-148.1..148.3 |
| P-19 | A Check Editor chip of family `checks` would carry the id `open_folder_checks`, which the Checks screen already mounts. | premise | ✅ TRUE | `open_folder_chip.py:77`; `app.py:2321`; `tests/test_open_folder_chips.py:94-98` | LLR-148.4 |
| P-20 | `SHIPPED_WINDOW_KEYS` holds 8 keys (`window_help.py:270-279`, set equality at `tests/test_window_usage_help.py:250`); no Check Editor or Flow Execution section; Check header a bare `Label` (`app.py:3082`), Execution header has no chip (`:2438`). | premise | ✅ TRUE | `grep -n` / `sed -n` | LLR-148.5 / 148.6 |
| P-21 | Today's help entries name few of the buttons their panel renders. | premise | ✅ TRUE | named-in-help / buttons: patch 6/19 · check 0/6 · flow 2/13 · execution 0/4 | RED side of LLR-148.6 |
| P-22 | The EXT-STEP inputs are fixed-width: 28 / 26 / 28 at both sizes. | premise | ✅ TRUE | `#flow_ext_instruction … (31, 13, 28, 3)` / `(49, 13, 28, 3)` | RED side of LLR-149.1 |
| P-23 | Textual's pilot can resize the terminal inside one session. | premise | ✅ TRUE | `8.2.8 True (self, width: 'int', height: 'int') -> 'None'` | AT-B97-16 |
| P-24 | The demo's binary fixtures are byte-identical to tracked examples. | premise | ✅ TRUE | `diff -q` / `cmp` → same; `prg.s19` 133 records `0x17e0..0x10000`; `tags 75 with int address 75`, longest 47 | fixture table (A.5) |
| P-25 | The batch-77 hostile payload reaches the Check Editor as an A2L symbol name in a shipped AT. | axiom | ✅ TRUE | `tests/test_tui_check_editor.py:52-56`, `:433` | the C-17 ATs reuse it |
| P-26 | The only snapshot cells rendering a batch-97 screen are the two `patch` cells. | premise | ✅ TRUE | `grep -ci patch` → `2`; `_SCAFFOLD_SCREENS` (`tests/test_tui_snapshot.py:110`) | carried to P3 (Q-18) |
| P-27 | On Windows a file name may carry `[bold]`, `[red]`, `[link=e]`, `[@click=app.quit]`, not `[/]`, `https://` or C0 bytes. | premise | ✅ TRUE | `… OK`; `[/]` `FileNotFoundError`; `https://` `OSError [Errno 22]`; `\x01` `OSError` | `HOSTILE_NAME` / `HOSTILE_CONTENT` split |
| P-28 | The A2L parser admits the full bracket payload, `https://` and a C0 byte as a CHARACTERISTIC name with an integer address. | premise | ✅ TRUE | `'b97[bold]x[/]y' admitted … int-addr: [True]` (3 arms) | LLR-145.5 |
| P-29 | A v2 change-set admits the payload as a `string` value; a payload `symbol` is refused with a finding that echoes it. | premise | ✅ TRUE | `value_brackets entries 1`, `value_c0 entries 1`; `symbol_brackets entries 0` + echoing finding | LLR-144.7 |
| P-30 | A flow file admits the NUL-free payload in `instruction`, `log_ref`, `change_doc_ref`; a payload flow `name` is refused (`FLOW-BAD-FIELD`). | premise | ✅ TRUE | `name loaded False … FLOW-BAD-FIELD`; three fields `loaded True` | LLR-146.8 / 147.6 |
| P-31 | A deterministic error lane exists (`err_chain`, an entry at `0x00020000` past the image end). | premise | ✅ TRUE | `outcome 2 error ['ok','error','skipped','skipped']` | `err_chain` (A.5) |
| P-32 | Blank painted rows outside each screen's growing region: Patch 3 / 2, Check 0 / 0, Execution 3 / 3 outside and 9 / 16 inside the lanes scroll. | premise | ✅ TRUE | `p1r2/geo2.py` (compositor strips) | LLR-147.8 / 149.5 |
| P-33 | Today's focus chains: Patch 40 ids, no tab chip; Check 27, no header chip; Builder `flow_scope` before `flow_run`; Execution `fx_confirm_1` after the lane inputs. | premise | ✅ TRUE | `p1r2/geo.py` focus-chain dumps | keyboard LLRs |
| P-34 | Python 3.11 has no `os.path.isjunction`; a junction reports `is_dir() True`, `is_symlink() False`, reparse attribute set. | premise | ✅ TRUE | `3.11.15 False 1024`; `junction is_dir True is_symlink False reparse True` | LLR-148.8 |
| P-35 | 17 Patch/Check/flow test files size the app at 80x24. | premise | ✅ TRUE | `grep -rlE "\(80, ?24\)" tests/*.py \| grep -iE "patch\|check\|flow" \| wc -l` → `17` | LLR-149.6 keeps them reachable |
| P-36 | A NUL in a flow block ref, a chain-set input ref, a chain-set template or a manifest entry raises an uncaught `ValueError`. | premise | ✅ TRUE | `p1r3/nul.py`: `load_flow_json(nul change_doc_ref) -> RAISES ValueError`; `load_chain_set(nul input ref) -> RAISES ValueError`; `load_chain_set(nul template) -> (True, [])` then its template load `-> RAISES ValueError`; `_resolve_manifest_entry(nul entry) -> RAISES ValueError` | LLR-146.14 |
| P-37 | `#fx_set_select` paints `flowsets/{stem}.json` from the directory listing as markup. | premise | ✅ TRUE | `flow_screens.py:2566`; `selprobe.py` → plain `'flowsets/b97xyzw.json'`, spans `bold`, `red`, `link=e`, `@click=app.quit` | LLR-147.6 |
| P-38 | First-segment + tail gives 75 distinct Parameter cells only at W ≥ 42; a tail-kept 24-cell name gives 75 distinct (name, address) lines; the six `0x13A00` parameters are distinct only by name. | premise | ✅ TRUE | `min W with 0 first+tail collisions: 42`; `W 24 tail: cell 15 row 0 \| head: cell 23 row 17 \| first+tail: cell 16 row 2`; Check panel content width 112 at 118x54 | LLR-145.3 |
| P-39 | A `height: 1` Static clips a wrapped line while `painted height == logical lines` holds, and a DataTable hard-clips a cell with no ellipsis. | premise | ✅ TRUE | `fixed region.h 1 logical lines 1 content_height 4 -> … passes: True`; cell `' ASAM.M.SCALA  0x00012345 '`, render widths `[14, 12]` | LLR-149.4 predicates |
| P-40 | Waiting `#e8ad3d` and CRC `#c9562b` lie 23.0° apart; every accent colour painted by the four panels lies ≥ 20° from the waiting hue; the one palette colour within 20° (`#d9a35b`, 5.0°) paints only outside the four panels. | premise | ✅ TRUE | `p1r3/hues.py`: `distance 23.0`; `YELLOW … 25.5`, `RED … 39.3`, others ≥ 44.0; `#d9a35b … 5.0` at `screens_directionb.py:7669` (`AbDiffPanel`), `styles.tcss:765`, `:782` | LLR-146.6 / 147.7 |
| P-41 | The six-block and CRC fixtures run to known statuses inside a work area, and every chain-set run writes one report carrying its mode. | premise | ✅ TRUE | `six_ok_a0 … ['ok', 'ok', 'notices', 'ok', 'ok', 'ok']`; `six_wait2 paused [… 'notices', 'ok', 'waiting', 'skipped']`; `crc_wait_chain ['ok', 'notices', 'waiting', 'skipped']`; `- **Mode:** sequential` / `- **Mode:** parallel` | fixtures (A.5); AT-B97-09/-20/-22 |
| P-42 | A demo-scale run takes tens of milliseconds on the UI thread. | premise | ✅ TRUE | 3-lane `run_chain_set` median `0.021` s; Builder `run_flow` median `0.013` s | freeze declared OUT |
| P-43 | `c` is bound neither by the app nor by `FlowExecutionPanel`; Textual 8.2.8 `Button` binds only `enter`; `DataTable` binds no `space`. | premise | ✅ TRUE | app keys listed in A.1 (no `c`); `Button.BINDINGS ['enter']`; `DataTable.BINDINGS` without `space` | LLR-147.13, 145.8 |
| P-44 | Disabling Run for a synchronous run drops a press queued during it. | premise | ✅ TRUE | model: without the disable `press -> run calls 2`; with it `press -> run calls 1` (both `press` and queued key) | LLR-147.10 |
| P-45 | A flow loader admits `HOSTILE_NAME` as an EXT-STEP `output_path` and refuses `HOSTILE_CONTENT` there. | premise | ✅ TRUE | `output_path=HOSTILE_NAME loaded True value kept True`; `HOSTILE_CONTENT … ['FLOW-UNSAFE-OUTPUT-NAME']` | LLR-146.8 / 147.6 arms |
| P-46 | The app mounts 4 chips today, labelled `📂 Open folder`, pinned by no assertion; a successful open sets `Opened {label}: {path}`. | premise | ✅ TRUE | `app.py:2321, 2476, 3048`, `screens.py:1668`; `open_folder_chip.py:76`; `folder_open_service.py:182` | LLR-148.8 / 148.10 |
| P-47 | `#flow_scope` is the only UI path to the variant scopes; 6 nodes of `tests/test_flow_multi_image_ui.py` reach it. | premise | ✅ TRUE | `flow_screens.py:818-823`, `:1485`; `app.py:2586-2609`; nodes `:150, :185, :215, :234, :251, :271` | LLR-146.12; LLR-104.6 retired for the Builder |
| P-48 | The Patch Editor's dirty flag has four writers. | premise | ✅ TRUE | `screens_directionb.py:4851`; set `:5707`, `:5771`; cleared `:5953`, `:5964` | LLR-144.6 stamp |
| P-49 | Shipped lane-paint and session-row assertions exist that the new LLRs supersede. | premise | ✅ TRUE | `test_tui_flow_execution_b94.py:345-348`, `:451-454`; `test_flow_external_step_b96.py:387`, `:425` | §6.3 superseded table |
| P-50 | A NUL ref pasted into `#fx_in_0_0`, bound by `#fx_bind_0_0` and run by `#fx_run` raises an uncaught `ValueError` at `variant_execution_service.py:273`; without the Bind press a typed rebind never reaches the run. | premise | ✅ TRUE | `p2qa3/q_nulbind.py` → `input value 'base\x00.s19'` · `RAISED ValueError stat: embedded null character in path` (`app.py:2815` → `flow_execution_service.py` → `_resolve_manifest_entry` `:273`); `p2qa3/q1_mode.py` → `press_bind=False … outputs identical True` / `press_bind=True … outputs identical False` | LLR-146.14, 147.2; AT-B97-22, -23 |
| P-51 | The Check Editor's Write stages at `<base>/.s19tool/workarea/temp/<name>` and renames a collision at the target; a read-only target directory, a directory or a read-only file at the target do not refuse on Windows; a directory or a read-only file at the staging path raises `PermissionError`, caught as `MF-WRITE-CONTAINMENT` with no file written. | premise | ✅ TRUE | `p1r4/q6_write.py` → `readonly_dir: path=…\spec.chk.json issues=[]`; `dir_at_target` / `readonly_file: path=…\spec.chk_1.json issues=[]`; `dir_at_staged` / `readonly_file_at_staged: path=None issues=['PermissionError: [Errno 13] Permission denied …']` (`changes/io.py:1590-1597`) | LLR-148.9 write arm |
| P-52 | On Textual 8.2.8 the region predicate counts cards correctly scrolled inside a `HorizontalScroll` and the clipped-region predicate does not; a non-scrolling `Horizontal` is counted by both; on HEAD both give 1 / 1 / 2 / 7 at 118x54. | premise | ✅ TRUE | `p1r4/a2_overflow.py` → `scroll box.overflow_x=auto max_scroll_x=66 region-pred=4 clipped-pred=0`; `noscroll box.overflow_x=hidden … region-pred=4 clipped-pred=4`; HEAD `flow-execution 7/7`, `flow-builder 2/2`, `patch-editor 1/1`, `check-editor 1/1` | §1.3; LLR-147.12, 149.2 |
| P-53 | A `ScrollableContainer` is focusable and binds `left` / `right`; `tab` reaches it and `right` brings `scroll_x` to `max_scroll_x`. | premise | ✅ TRUE | `p1r4/u3_lanes_key.py` → `wide=True chain=['run', 'lanes'] focused=lanes rights=66 scroll_x=66 max=66 last_inside=True`; `ScrollableContainer True [… 'left', … 'right', 'up']` | LLR-147.11, 147.12 |
| P-54 | A reference set built by control type (displayed, enabled) is contained in the focus chain on the four screens at HEAD, and `can_focus = False` on one Button removes it from the chain while the type-built set keeps it. | premise | ✅ TRUE | `p1r4/u2_chain.py` → ref 19 / 14 / 16 / 12, 0 missing; mutation on `patch_checks_run_button`, `check_mem_add_button`, `flow_add`, `fx_bind_0_0` → each `RED`; a chain-built set misses each (`True`) | §4 method (b) |
| P-55 | Of `PE_IDS_9C7BEAF` / `CE_IDS_9C7BEAF`, 28 / 14 ids are control-typed, every one in the LLR-144.12 / 145.10 controls column; the tables' other shipped ids are 9 / 5 `Static` or `Label` read-outs. | premise | ✅ TRUE | `p1r4/q9_subset.py` → `PE: frozen 66 control-typed 28 missing-from-table []`, `CE: frozen 31 control-typed 14 missing-from-table []`, dropping one → `RED`; `p1r4/q5_types.py` → the 9 / 5 read-outs listed in A.1 | LLR-144.12, 145.10 |
| P-56 | On `main` the keys-only Builder path completes (2 → 3 blocks, Run pressed), the palette lacks `check`, `source`, `write_out`, `tab` visits `flow_scope`, and the banner after an EXT-STEP run is Spanish. | premise | ✅ TRUE | `p1r4/q3_at19.py` → `palette ids on HEAD ['flow_palette_a2b', 'flow_palette_crc', 'flow_palette_external_step', 'flow_palette_patch']`; `flow_scope visited by tab: True`; `PAUSED - ESPERANDO HUMANO` → `ES_MARKER` matches `['ESPERANDO', 'HUMANO', 'esperando', 'humano', 'SALIDA']` | AT-B97-19 |
| P-57 | Save and paste-buffer typing change the Patch Editor's dirty flag and write no document field: neither is among the nine writers. | premise | ✅ TRUE | `ChangeService.save` at `change_service.py:1546`, outside the nine writer lines of P-6 (`undo :861`, `redo :893`, `add_entry :1080`, `add_symbol_entry :1154`, `edit_entry :1196`, `remove_entry :1223`, `edit_entry_json :1344`, `load :1404`, `load_text :1465`); `screens_directionb.py:5707` (buffer typing), `:5953` (`mark_saved`), each followed by `_refresh_dirty_indicator` | LLR-144.6 |
| P-58 | The app holds the active project directory resolved. | premise | ✅ TRUE | `app.py:1861` `return (self.workarea / self.current_project).resolve()`; `app.py:8200` `self.current_project_dir = project_dir.resolve()` | LLR-148.8 trust anchor |
| P-59 | `tests/test_open_folder_chips.py` holds 11 test nodes; the shipped press path creates a missing target through `create_chip_home` before the open seam. | premise | ✅ TRUE | `grep -c "^def test_\|^async def test_"` → `11`; `open_folder_chip.py:160-172` | LLR-148.1, 148.8 |
| P-60 | Under the pilot a paint completes between the two keys of `press("c", "c")`, ~0.05 s apart; a chain with two EXT-STEP blocks pauses again at the second after the shipped confirm re-run; a stray `enter` on `#fx_run` while a lane waits starts one more run and confirms nothing. | premise | ✅ TRUE | `p1r4/u1_burst.py` → `[(0.0003, False), (0.0488, True)]`; `p1r4/u1_two_ext.py` → `run 1 paused ['ok', 'ok', 'waiting', 'skipped', 'skipped']`, `confirm re-run paused ['ok', 'ok', 'ok', 'waiting', 'skipped']`; `p1r4/u5_stray_enter.py` → `after enter 1: focused fx_run reports 1 lane ['ok', 'ok', 'waiting', 'skipped']`, `after enter 2: focused fx_run reports 2 lane ['ok', 'ok', 'waiting', 'skipped']` | LLR-147.13; AT-B97-20 |
| P-61 | `WindowSection` binds `?` with `show=False` (`window_help.py:449`); while a window holds the focus that binding shadows the app's `? Help` (`app.py:1414`), so the shipped Footer paints no `? Help`. | premise | ✅ TRUE | probe → `WindowSection ? : [('question_mark', False)]`; the 118x54 capture of the prototype round's baseline row holds no `? Help` (`prototypes/keybar/keybar.html` "Painted rows") | LLR-150.2 |
| P-62 | `window_help` holds no key table — `SHIPPED_WINDOW_KEYS` is its only key-named constant — and its sections have no `check_editor` or `flow_execution` key. | premise | ✅ TRUE | probe → `has key table attr: ['SHIPPED_WINDOW_KEYS']`; `help sections: ['a2l', 'changes_file_notation', 'checks', 'crc_designer', 'flow', 'map', 'patch', 'reports', 'split_join_export', 'workspace']` | LLR-150.1 |
| P-63 | `+` / `-` act only on A2L and MAC; `,` / `.` act on any window whose view is `"main"` — every window but A2L and MAC — so on the Patch, Check, Flow and Flow Execution windows they page the hidden Workspace hex view. | premise | ✅ TRUE | `app.py:1832-1836` (`"alt"` / `"mac"` / else `"main"`); `app.py:7562-7566` (`page_next_context` routes only `alt` / `mac`); `app.py:7678-7679` (`hex_page_next` returns only when the view is not `"main"`) | LLR-150.4 |
| P-64 | `S19TuiApp` overrides no `check_action`. | premise | ✅ TRUE | probe → `check_action in S19TuiApp.__dict__: False` | LLR-150.4 (I-11) |
| P-65 | The `period` binding carries no `key_display`, and Textual displays it as the word `period`. | premise | ✅ TRUE | probe → `period key_display: None`; `display period: period` (`App.get_key_display`) | LLR-150.5 |
| P-66 | A click on a shipped Footer key runs `app.simulate_key(key)` (a bell when disabled); a binding whose `check_action` answers `False` is left out of `active_bindings`. | premise | ✅ TRUE | `textual/widgets/_footer.py:133-137`; `textual/screen.py:473-481` (Textual 8.2.8) | LLR-150.7, LLR-150.4 |
| P-67 | At 118x54 the shipped Footer row reads `^k Palette ^d Density ^l Load ^s Save / Find q Quit x Operations + Page+ - Page- , Hex- perio▏^p palette` on the Workspace with the focus in a window. | premise | ✅ TRUE | real Windows Terminal capture, text from its SVG export (`prototypes/keybar/keybar.html` "Painted rows, hex viewer") | LLR-150.2, LLR-150.5 |
| P-68 | With a two-row bar each window container loses exactly one row: 42 → 41 at 118x54 on the Workspace, Patch, Check, Flow and Flow Execution windows. | premise | ✅ TRUE | `prototypes/keybar/measure.txt` → `container_rows=42` baseline, `container_rows=41` variant A on all five; `hex_scroll 32 → 31`, `patch_editor_panel 40 → 39`, `check_param_table 40 → 39`, `flow_panel 40 → 39` | LLR-150.6 |
| P-69 | The app's `show=True` bindings are the 14 keys AT-B78-28 pins by set-equality (`tests/test_tui_diff_screen.py:3590-3606`). | premise | ✅ TRUE | probe → `shown bindings: ['ctrl+k', 'ctrl+d', 'ctrl+l', 'ctrl+s', 'slash', 'g', 'q', 'x', 'k', 'question_mark', 'plus', 'minus', 'comma', 'period']` (14) | §6.3 superseded table |

- **Premise evaluation:** 69 premise(s) · ✅ TRUE 69 / ❌ FALSE 0 / ❓ UNDECIDABLE 0 — executed 2026-10-20 on `9c7beaf` / `bc4fbd3` / `0f21e00` / `bdd88f3` (no `s19_app/` diff between them) and, for P-61..P-69, on `d5d0ff9` (`app.py` and `window_help.py` unchanged since `9c7beaf`); P-7, P-13, P-16 record corrected brief claims; P-11, P-17 and P-35 were restated in round 2; P-50..P-60 are new in round 3; P-61..P-69 are new in the key-bar fold (LED-…97.9, transcript `evidence/keybar-premises-2026-10-20.txt`).

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

> Test-file paths, `-k` selectors and node ids in every *Executed verification* line are provisional until Phase 3 (V-5) and reconciled from the real tree at Phase 4. Every acceptance fixture, driver and RED arm is in the per-AT table (appendix A.5). Every acceptance test observes only the shipped surface: painted text and regions, files written on disk (`reports/*`, written images, saved sets and specs), the status line — never an internal attribute, a posted message or a wrapped service function — with one exception, the OS boundary: the open seam `folder_open_service.open_folder_in_file_manager` is spied with the `SeamSpy` idiom (`tests/test_open_folder_chips.py:101`), because opening a file manager paints nothing in the terminal (HLR-148). Every render-increment gate also runs the full guard host `pytest tests/test_tui_directionb.py` (C-34).

### HLR-144 — Patch Editor as a ledger + inspector with a live JSON view
- **Traceability:** US-134
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While the Patch Editor is displayed, the Patch Editor shall present the document's entries as a full-height ledger beside an inspector carrying Inspector, JSON and Checks tabs, the inspector showing the highlighted entry's before→after hex strip, labelled entry form and entry chips, every shipped control displayed in its home, and Save as its one filled action besides the ledger. When any writer of the document changes it — a Load is one of them — the Patch Editor shall show that document in the JSON tab's read-only view at once, under a stamp naming its entry count, time and saved state. When the panel's dirty flag changes, the Patch Editor shall recompose that stamp at once.
- **Rationale (informative):** operator verdict pe_A with the binding JSON condition (brief R-1); the refresh is live with a stamp and no button, and Save is the primary action (operator decisions 2 and 4, LED-…97.3). Today the ledger shows 2 of 6 rows in a 3-row band and the JSON editor keeps the dummy template after Load (§2.7 P-4, P-8).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_patch_editor.py -k "at_b97_01 or at_b97_02 or at_b97_03 or at_b97_17"` (Textual pilot, real presses and keys) + the C-34 guard host.
- **Numeric pass threshold:** after Load of the 6-entry fixture at 118x54: 6 of 6 ledger rows painted without scrolling, and the JSON view's text parses (`json.loads`) to 6 entries whose `address` list equals the list parsed from the fixture FILE (`['0xEB10', '0xEB40', '0xEC00', '0xECA0', '0xED00', '0xED40']`, P-5), stamp `6 entries · HH:MM:SS · saved`; after one Add, with no further press: 7 parsed entries and stamp `7 entries · … · unsaved changes`; after Save, with no further press: stamp `7 entries · … · saved`; the hostile name and content arms of AT-B97-03 render with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Load the engineer sees every entry in the left ledger, the highlighted entry's before→after strip in the inspector and, on the JSON tab, the same document as read-only JSON under its stamp; after adding an entry the JSON view shows it at once and the stamp says `unsaved changes`, and after Save it says `saved`; the paste area stays editable; a markup-laden file name and entry value read literally; the whole first task works from the keyboard.
  - **Shipped surface:** `#screen_patch` → `PatchEditorPanel` (`s19_app/tui/screens_directionb.py:4383`), loaded through `#patch_doc_load_button` → `S19TuiApp._patch_editor_load_tail` (`s19_app/tui/app.py:5266`).
  - **Acceptance test(s):** AT-B97-01, AT-B97-02, AT-B97-03, AT-B97-17
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a 0-entry document shows the empty-state line in the ledger and `"entries": []` in the view (AT-B97-02); boundary: the 118x54 floor (AT-B97-01); invalid: a legacy v1 file loads as the empty document plus its one ERROR finding and the view shows that empty document, not the previous one (AT-B97-02); error: the hostile name and content (AT-B97-03).
  - **Negative control:** executed on `main` (§2.7 P-4): after Load the JSON buffer equals `DUMMY_CHANGESET_TEXT` with 2 `"address"` keys against 6 entries — AT-B97-01's view clause is RED on today's tree.

### HLR-145 — Check Editor as a ledger + report-fields card
- **Traceability:** US-135
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** While the Check Editor is displayed, the Check Editor shall present the A2L parameters as a full-height ledger whose Address column is never truncated and whose parameter names stay distinguishable, beside a REPORT FIELDS card with Fields, JSON and Addendum tabs whose Fields tab lists exactly the included parameters and memory rows, with every shipped control displayed in its home and one docked row carrying Validate, Write .chk.json (its one filled action besides the ledger), the struck APPLY ghost and the field count.
- **Rationale (informative):** operator verdict ce_A (brief R-2); Write is the primary action (operator decision 2). At 118x54 today the Address column sits 52 cells into a 56-cell table (`max_scroll_x 25`, P-12). The no-apply doctrine stays (`PDR-2026-10-12-batch-94#D2`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_check_editor.py -k "at_b97_04 or at_b97_05 or at_b97_18 or at_b97_21"` + the C-34 guard host.
- **Numeric pass threshold:** at 118x54 and at 220x60: the parameter table's `max_scroll_x == 0` and, for every painted row, the Address cell's painted text equals the full `0x%08X` address (75 of 75 rows reachable by vertical scroll only); 0 equal painted Parameter cells for different names; the field-count text changes from N to N+1 after one include; the Fields tab's parsed lines equal the included set (AT-B97-21); the written `.chk.json` parses to the same address set; 0 apply actions in the panel; the hostile parameter name renders with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer reads every parameter's address in full at both sizes and tells every parameter name apart, includes a parameter and sees it on the REPORT FIELDS card and the field count rise by one, writes the spec and finds the same fields in the file, reads a markup-laden parameter name literally, and does the first task from the keyboard.
  - **Shipped surface:** `#screen_check_editor` → `CheckEditorPanel` (`s19_app/tui/screens_directionb.py:6864`), prefilled by `S19TuiApp._prefill_check_editor` (`app.py:5329`).
  - **Acceptance test(s):** AT-B97-04, AT-B97-05, AT-B97-18, AT-B97-21
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: no A2L loaded → the ledger shows its empty state and the docked row stays inside the panel (AT-B97-04); boundary: 118x54, the 47-cell longest name and the six names sharing `0x13A00` (AT-B97-04, AT-B97-21); invalid: N/A — the panel has no free-text input whose invalid value this story changes (the memory-row inputs keep their batch-94 validation); error: the hostile name (AT-B97-05).
  - **Negative control:** executed on `main` (§2.7 P-12): `max_scroll_x 25` at 118x54 — AT-B97-04's address clause is RED on today's tree.

### HLR-146 — Flow Builder as a pipeline rail with a contextual add form
- **Traceability:** US-136
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While a flow is loaded in the Flow Builder, the Flow Builder shall present its blocks as one horizontal pipeline of cards joined by cables, CRC cards painted in the CRC colour, shall offer every placeable block kind in its palette with an add form that shows only the chosen kind's inputs, shall carry the copy/paste strip, the `Variables (n)` chip and the session directory on its ribbon, and shall keep Run, its one filled action besides the pipeline, inside the panel viewport without scrolling at any size of at least 118x54, Run requesting the single-image scope with no scope selector. If a flow file, chain-set, manifest or bound lane-input ref carries a NUL character, then the system shall refuse that ref — load nothing from it and resolve no path for it — with a finding, and raise no exception.
- **Rationale (informative):** operator verdict fb_A (brief R-3, R-5); multi-variant work moves to Flow Execution lanes, one chain per variant (operator decision 3, LLR-104.6 retired for the Builder); the NUL refusal is security's S2-2, fixed at the Flow Builder increment. Today Run sits below the fold at 118x54 (P-11), the palette offers 4 of 7 kinds (P-13), card text overruns its card (P-14), 27 builder strings are Spanish (P-17) and a NUL ref crashes the load (P-36).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_builder.py -k "at_b97_06 or at_b97_07 or at_b97_08 or at_b97_19"` + the C-34 guard host.
- **Numeric pass threshold:** with the 4-block `patch_chain` fixture at 118x54: 4 cards on one painted row joined by 3 cables, `#flow_run` inside the panel region at scroll 0, 0 `#flow_scope` widgets; 7 palette chips, and for each of the 7 kinds the displayed add inputs equal LLR-146.3's table row; Add after EXT-STEP appends a 5th card; a Run press paints `ISSUES` in `#flow_result` and creates `<project>/fw_app_patched.s19` (absent before the press); the hostile EXT-STEP fields render with 0 `MarkupError` and 0 spans originating in the payload; Load of a NUL-ref flow paints one refusal line naming `FLOW-UNSAFE-REF` and raises 0 exceptions; 0 `ES_MARKER` matches in the panel's painted text.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the engineer sees the whole chain as one row of cards with cables and Run on screen; choosing a kind chip shows only that kind's inputs (EXT-STEP: command, log and output on two rows) and Add appends the card; Run runs the chain on the loaded image and writes its output; a markup-laden ref reads literally on its card; a flow file carrying a NUL ref is refused with a line, not a crash; the first task works from the keyboard.
  - **Shipped surface:** `#screen_flow` → `FlowBuilderPanel` (`s19_app/tui/flow_screens.py:502`), mounted by `_compose_screen_flow` (`app.py:2378`, header `:2404`); Run handled by `on_flow_builder_panel_run_requested` (`app.py:2518`).
  - **Acceptance test(s):** AT-B97-06, AT-B97-07, AT-B97-08, AT-B97-19
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no blocks → the rail shows its empty line and Run stays reachable (AT-B97-06); boundary: 118x54 and a ref longer than the card (clipped, AT-B97-08); invalid: EXT-STEP Add with an empty log is refused with the English refusal line (AT-B97-07), a NUL ref is refused (AT-B97-08); error: the hostile ref (AT-B97-08).
  - **Negative control:** executed on `main` (§2.7 P-11, P-13, P-36): `#flow_run (51,48,16,3)` ends past the panel bottom 44, the palette holds 4 buttons, and a NUL `change_doc_ref` raises `ValueError` on load — AT-B97-06, -07 and -08 are RED on today's tree.

### HLR-147 — Flow Execution as one pipeline per lane with cable status
- **Traceability:** US-137
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** When a flow set runs in Flow Execution, the Flow Execution panel shall paint one pipeline per lane whose cables carry the run status of their blocks from the retained run record. While a run is in flight, the panel shall start no second run. While a lane waits for a human, the panel shall bring the attention lane's waiting card and Confirm into the lanes viewport without moving the focus, offer a scoped key that confirms the attention lane once per waiting entry, paint the waiting-human elements in the waiting colour that no other element on the four screens paints, and name the wait and its chain in English in the run log and the REQUIRED line. Run shall be its one filled action besides the lanes, with each waiting lane's Confirm.
- **Rationale (informative):** operator verdict fx_A (brief R-4, R-5); the batch-96 waiting-human doctrine is kept. Per-block status and lane order are already in the record (P-15). Colours: operator decision 1 (`#e8ad3d` / `#c9562b`, 23.0°); Confirm is not auto-focused so that a repeated key cannot attest human work (orchestrator decision 6, U2-3).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_flow_execution.py -k "at_b97_09 or at_b97_10 or at_b97_11 or at_b97_20 or at_b97_22"` + the C-34 guard host.
- **Numeric pass threshold:** importing `patch_chain`, `flash_chain`, `err_chain` through `#fx_import` and pressing `#fx_run` (sequential) at 118x54: lane 0 cables `▓ ▓ ◇`, lane 1 cables `▓ □ ░`, lane 2 cables `▓ ✗ ░`; `#fx_confirm_1` region inside `#fx_lanes_scroll`'s region and painted in the attention style (its compositor-strip style ≠ `#fx_run`'s), the focus still on `#fx_run`; the REQUIRED line names `flash_chain`; lane headers carry the worst-status marks `◇`, `□`, `✗`; `press("c", "c")` with two lanes waiting → 1 confirm; a stray `enter` on `#fx_run` while lane 1 waits → 1 more run and 1 more report, 0 confirms; `#fx_confirm_0` and `#fx_confirm_2` not displayed; every span painted in the waiting colour belongs to a waiting-human element; 0 `ES_MARKER` matches in the painted log and lanes; `#fx_save` / `#fx_load` inside the panel at scroll 0 and the mode control ≤ 30 cells wide; each rebind input and its Bind inside its SOURCE card; Save Set writes the set file and Load Set in a new app on the same `tmp_path` restores its lanes; the chain-set report of a run driven in `parallel` carries `- **Mode:** parallel`; the hostile arms render with 0 `MarkupError` and 0 spans originating in the payload.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** after Run the engineer sees lane 0 done with notices, lane 1 paused at its external step with its card and Confirm on screen and highlighted, lane 2 failed, each lane's header mark telling its worst status, a REQUIRED line naming the waiting chain and the confirm key above the log, and the log in English; Save Set and Load Set are on screen and round-trip the set; a CRC card beside the waiting card is painted in a colour distinct from the waiting colour (judged on the capture, §5.1).
  - **Shipped surface:** `#screen_flow_execution` → `FlowExecutionPanel` (`s19_app/tui/flow_screens.py:1874`), lanes added through `#fx_import` → `on_flow_execution_panel_import_requested` (`app.py:2719`), run through `on_flow_execution_panel_run_requested` (`app.py:2776`), which writes `<project>/reports/<ts>-chain-set-report.md` (`flow_execution_service.py:1551`, `:1661`).
  - **Acceptance test(s):** AT-B97-09, AT-B97-10, AT-B97-11, AT-B97-20, AT-B97-22
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: Run with no lanes paints no pipeline and an English no-lanes line (AT-B97-10); boundary: 118x54 header and set row, and the waiting lane third of three with 6 blocks, past the viewport on both axes (AT-B97-10, AT-B97-20); invalid: an imported flow or a loaded set carrying a NUL ref is refused (AT-B97-11); error: `err_chain` (`✗` cable, AT-B97-09) and the hostile arms (AT-B97-11).
  - **Negative control:** executed on `main` (§2.7 P-11, P-17): `#fx_save (117,10,16,3)` and `#fx_load (134,10,16,3)` outside the panel; the run log line `□ flash_chain · ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` — AT-B97-09/10 are RED on today's tree.

### HLR-148 — Folder chip and help chip on the four screens
- **Traceability:** US-138
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** When the engineer presses an open-folder chip, the system shall open the folder the chip's label names only if it is a real directory reached through no reparse point inside that family's root, and shall otherwise refuse on the status line. When the engineer presses the help chip of the Patch Editor, Check Editor, Flow Builder or Flow Execution screen, the system shall show that screen's help entry naming every control, input, tab, key and glyph on the screen as `label — effect` lines. While no project is active, a project-only family's chip shall be disabled and its status message shall name that family's folder. While a region of the four screens has no content or an error, that region shall show one English line naming the state.
- **Rationale (informative):** the operator's round-2 answer ("es un problema adivinar y buscarlos, sobre todo para usuarios nuevos") and the verdict note on legends (brief R-6, R-7); chip labels name their folder (orchestrator decision 7). ARQ I-1 / I-4; R14, R15. The real-directory guard and the label change apply to every chip in the app (A2-10).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_chips_help.py -k "at_b97_12 or at_b97_13 or at_b97_14 or at_b97_23"` with the open seam spied (the `SeamSpy` idiom of `tests/test_open_folder_chips.py:101`).
- **Numeric pass threshold:** with a project: 4 presses → 4 seam calls with targets `patch` home, `checks` home, `project_dir / "flows"`, `project_dir`, labels `📂 Open patches/`, `📂 Open checks/`, `📂 Open flows/`, `📂 Open session`, each status line ending with the opened target's full path; in a project opened through the app's own load (its resolved directory the trust anchor, §2.7 P-58), a `flows` that is a file or a junction → 0 seam calls and a refusal line; a missing `flows` → created inside the project, then guarded, then 1 seam call; without a project: the `flows` and `session` chips are disabled, 0 seam calls, and the status line names the family's folder and not "Reports"; each of the 4 help chips opens a modal whose `label — effect` lines cover 100 % of the screen's coverage set (LLR-148.6); each region state of LLR-148.9 shows its line, including a NUL ref pasted into `#fx_in_0_0`, bound by `#fx_bind_0_0` and run → 1 English line naming `MANIFEST-PATH-ESCAPE`, 0 tracebacks.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** every one of the four screens shows an open-folder chip naming its folder and a `?` chip in its header; with a project the chip opens that folder and the status line shows its full path, without one the flow chips are dimmed and say why, and a folder replaced by a file or reached through a link inside the project is refused; `?` explains every control, input, key and mark on that screen; an empty or failed region says so in one line.
  - **Shipped surface:** `OpenFolderChip` / `titled_header` (`s19_app/tui/open_folder_chip.py:59`, `:185`), `folder_open_service.resolve_chip_target` (`s19_app/tui/services/folder_open_service.py:232`), `WindowHelpChip` (`s19_app/tui/window_help.py:401`).
  - **Acceptance test(s):** AT-B97-12, AT-B97-13, AT-B97-14, AT-B97-23
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no project (AT-B97-13); boundary: a project whose `flows/` does not exist yet → the chip is dimmed and the press creates it through the shipped create-on-press path inside the project, then guards and opens it (AT-B97-12); invalid: `flows` a file or a junction in a project opened through the app's load → refused, 0 seam calls (AT-B97-12); a NUL ref bound to a lane and run → refused with one line (AT-B97-23); error: the seam raises → the status line carries the failure, no traceback (AT-B97-12).
  - **Negative control:** executed on `main` (§2.7 P-18, P-20, P-21, P-34): `OpenFolderChip("flows")` raises `ValueError` (family not in `CHIP_FAMILIES`), the Check Editor header has no chip, a junction passes the shipped `exists()` check, and the help coverage is 6/19 · 0/6 · 2/13 · 0/4 — all four ATs are RED on today's tree.

### HLR-149 — Width-adaptive layouts, no wrapped rows
- **Traceability:** US-139
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While the Patch Editor, Check Editor, Flow Builder or Flow Execution screen is displayed at any terminal size of at least 118 columns by 54 rows, on either side of the 120-column `width-narrow` breakpoint, the system shall derive that screen's column widths, panel splits and region heights from the available size at mount and on every resize, so that no element overflows horizontally, the primary actions stay inside the panel viewport, no row of the no-wrap set wraps and the remaining space goes to the screen's growing region. While such a screen is displayed at a width below 118 or a height below 54, down to 80x24, the system shall keep it reachable under scroll.
- **Rationale (informative):** the operator's variable-size rule and the 220x60 pass (brief R-8). Every screen overflows today at both sizes (P-10) and the EXT-STEP inputs keep the same width at both sizes (P-22). The 80x24 floor is kept (ruling 1 in LED-…97.2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_width.py -k "at_b97_15 or at_b97_16 or at_b97_24"` (four screens × the samples 118x54, 160x56, 220x60, 260x70; an in-session `pilot.resize_terminal` 118x54 → 220x60 → 260x70 → 118x54; the 119↔120 boundary; 80x24 and 220x40 reachability).
- **Numeric pass threshold:** per screen and sample: 0 displayed descendants whose clipped region (§1.3) has `right > panel.region.right` or `x < panel.region.x` (over ≥ 10 displayed descendants); the LLR-149.3 primary actions inside the panel region at scroll 0; 0 wrapped no-wrap rows; at 220x60 and 260x70 the void of LLR-149.5 within its bound; after the resize back to 118x54 the overflow count is 0 again; at 119x54 and 120x54 the same 0 counts; at 80x24 and 220x40 every LLR-149.3 action reached from the keyboard (`tab` focuses it and scrolls it into view, `pagedown` scrolls the panel) and inside the panel region once reached.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** at any size from 118x54 up nothing runs off the right edge and Run / Validate / Save Set / the document controls are on screen; at large sizes the ledgers, inputs and cards grow into the space instead of leaving a void; no table, ledger or log line breaks onto a second line or is cut without an ellipsis; at 80x24 or a short-but-wide window everything is still reachable by scrolling.
  - **Shipped surface:** the four panels above, driven through the rail (`action_show_screen`) at each sample size.
  - **Acceptance test(s):** AT-B97-15, AT-B97-16, AT-B97-24
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — empty: N/A — geometry is asserted on the loaded scenarios, the empty states are covered by each screen's own AT; boundary: 118x54, 119x54↔120x54, 220x40, the in-session resize (AT-B97-16, AT-B97-24); invalid: N/A — below the range only reachability is promised (LLR-149.6); error: a 60-cell ref and the 47-cell parameter name, the widest real values, clip with an ellipsis instead of overflowing (AT-B97-15).
  - **Negative control:** executed on `main` (§2.7 P-10, P-11, P-22): overflow counts 1/1/2/7 at 118x54 and 1/1/1/6 at 220x60; EXT-STEP inputs 28/26/28 at both sizes — the ATs are RED on today's tree.

### HLR-150 — Two-row key bar scoped to the active window
- **Traceability:** US-140
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** While any window of the app is displayed, the system shall paint a two-row key bar at the bottom of the terminal: the first row the global keys, the same on every window and always including `? Help`; the second row the active window's name tag, then that window's own keys, then its go keys. The key bar shall paint no key the active window does not handle, shall dim a key the window handles that cannot act in the current state, and shall paint whole tokens only, ending an overflowing row with `? more`. When the engineer clicks an enabled token, the system shall run that token's binding action in the binding's own namespace, whatever widget holds the focus.
- **Rationale (informative):** the operator's PDR objection (PC-22: "necesitamos dos líneas en el fondo de la pantalla … las teclas de interés para la pantalla") and the key-bar prototype round, verdict **A · Two rows** accepted and preferred with no per-screen objection (`evidence/operator-keybar-verdict-2026-10-20.json`), including the operator's colour amendment (the window tag in the `.db-screen-title` pair). Today the one-row `Footer` lists 14 app bindings on every window (P-69), clips at 118 columns (`perio▏`, P-65, P-67), shows `Page±` / `Hex±` where they do nothing and `,` / `.` page a hidden view there (P-63), and drops `? Help` whenever a window holds the focus (P-61). Routed into the batch as Inc-8 (LED-…97.9); backlog U-17. Row 1 is the rendered and accepted one (Find / Go-to are window keys, not global: they own an input only on Workspace, A2L and MAC, `app.py:6794`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b97_key_bar.py -k "at_b97_25 or at_b97_26"` (Textual pilot, real clicks and keys) + the C-34 guard host.
- **Numeric pass threshold:** on each of the 13 windows at 118x54 and at 220x60 (26 cells): row 1 paints exactly the 8 global tokens in order (`^k Palette`, `^d Density`, `^l Load`, `^s Save`, `x Operations`, `? Help`, `q Quit`, `^p palette`) and never `? more`, whatever holds the focus; row 2 starts with the window's tag; 0 painted tokens outside the window's allowed set (the globals ∪ its window keys ∪ its go keys ∪ `? more`); 0 partially painted tokens and 0 `perio`; 0 `? more` at 220x60, and the Workspace row 2 ends with `? more` at 118x54; every window's container is exactly 1 row shorter than on `main` (41 at 118x54, P-68); a click on `9 Checks` on the Patch Editor with a text `Input` focused shows the Checks window and types nothing, a click on a dimmed token changes nothing; `.` pressed on the Patch Editor with an image loaded leaves the Workspace hex view's first painted address unchanged.
- **Priority:** medium
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** on every window the engineer reads the same global keys on the bottom row, `? Help` included, and above them the window's name in the title colours followed by the keys that act on that window and the windows it leads to; a key that exists but cannot act right now is dimmed; nothing is cut in half and a row that is too long ends with `? more`; clicking a key runs that key's action even while a text field has the focus, without typing into it; `Page±` / `Hex±` no longer show where they did nothing, and pressing them there no longer pages a hidden view.
  - **Shipped surface:** the bottom bar of `S19TuiApp` — today `Footer()` (`s19_app/tui/app.py:2077`) over `S19TuiApp.BINDINGS` (`app.py:1384`); after Inc-8 the key bar (I-11) fed from the window-key table (I-10) in `s19_app/tui/window_help.py`, reached through the rail keys and `action_show_screen` (`app.py:6895`).
  - **Acceptance test(s):** AT-B97-25, AT-B97-26
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: a window whose row holds no window key and no go key paints its tag alone on row 2 — Split / Join / Export unless the PC-26 derivation gives it an entry, in which case the arm is recorded `n/a — no empty window` (AT-B97-25); boundary: 118x54, where the Workspace row 2 overflows, 220x60, where every row fits, and 80x24, where row 1 drops `^p palette` whole (AT-B97-25); invalid: N/A — the key bar takes no typed input; error: a key pressed on a window that does not handle it (`.` on the Patch Editor) does nothing (AT-B97-26).
  - **Negative control:** executed on `main` (§2.7 P-61, P-63, P-67): the Footer at 118x54 ends `perio▏`, paints no `? Help` with the focus in a window and paints `+ Page+ - Page- , Hex-` on the Patch Editor, and `.` there advances the hidden hex view — AT-B97-25 and AT-B97-26 are RED on today's tree.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level. EARS owed (`full`); a statement of several sentences carries one trigger per sentence. ID format: `LLR-<HLR>.<M>`. A symbol marked `NEW` is created in Phase 3; every other symbol carries its `file:line` on `9c7beaf`. Test paths and selectors are provisional (V-5). Every `NEW` widget id or class below is a working name, fixed at PDR (§6.2 item 5). Keyboard TCs share one method, stated once: read `app.screen.focus_chain`, keep the panel's ids and its header chips, and check (a) group order (group membership is the LLR's list, not the DOM), (b) **completeness** — a reference set built by widget type and id, independent of `can_focus`: every displayed, enabled control (§1.3) inside the panel and its header; the reference set ⊆ the chain's set (no displayed control left out), and a control given `can_focus = False` (mutation, Phase 3, run on each of the four screens) stays in the reference set and so turns the clause RED (§2.7 P-54), (c) one `enter` arm per button group, focusing one member and observing its effect, and (d) chip states — each one-row chip's painted style differs between unfocused and focused, and a tab or kind chip's three states (unfocused, focused, selected) are pairwise distinct.

### LLR-144.1 — Patch Editor re-composed at its shipped ids
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `PatchEditorPanel` shall yield every id of `PE_IDS_9C7BEAF` (the 66 shipped ids frozen from `9c7beaf`, appendix A.2) in the ledger + inspector composition, with each `patch_win_*`, `patch_saveback_row`, `patch_before_after_row` and `patch_checks_results` id keeping its `Container` type.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-01 — `pytest tests/test_b97_patch_editor.py -k tc_b97_01`; procedure: appendix A.4 TC-B97-01.
- **Numeric pass threshold:** 0 of 66 ids missing; 0 container-type mismatches.
- **Negative control:** remove one shipped id from the composition (mutation, Phase 3, C-40) → 1 missing id, RED; the mutation cannot shrink the expected set.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the census at 118x54 and 220x60 (an id hidden by `display:none` still counts; one never yielded does not). Empty/invalid/error: N/A — the composition has no input.

### LLR-144.2 — Full-height ledger and Inspector / JSON / Checks tabs
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `PatchEditorPanel` shall render `#patch_doc_entries_table` in the left column with a height that grows with the panel, and shall carry three focusable tab chips (Inspector, JSON, Checks — ids NEW), each activated by a click, `enter` or `space`, that switch one `ContentSwitcher` (NEW) between the inspector pane (NEW), `#patch_win_json` and `#patch_win_checks`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-02 — `pytest tests/test_b97_patch_editor.py -k tc_b97_02`; procedure: appendix A.4 TC-B97-02.
- **Numeric pass threshold:** table region height ≥ 7 at 118x54 (today 3, P-8); 9 of 9 activations show their pane and hide the other two.
- **Negative control:** executed on `main`: `table region (9, 6, 102, 3)` with `rows 6` → `3 >= 7` False, RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: a 0-entry document shows `#patch_doc_empty_state`; boundary: 118x54. Invalid/error: N/A — tab chips take no input.

### LLR-144.3 — The double geometry work removed (E-1, E-2)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The `PatchEditorPanel` shall size its ledger, file row and inputs without forcing a fixed table height, fixed select/path widths or a show-time geometry pass, and shall add its five entries columns exactly once.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-03 — `pytest tests/test_b97_patch_editor.py -k tc_b97_03`; procedure: appendix A.4 TC-B97-03.
- **Numeric pass threshold:** `len(table.columns) == 5` after 2 shows + 1 resize; select and path widths differ between 118x54 and 220x60 (today 30 / 28 at both); 0 hits for the app-side geometry call.
- **Negative control:** executed on `main`: the probe returns 1 hit (`app.py:6978`) and `table.styles.height = 3` (`:5616`) yields a 3-row table at both sizes — RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 → 220x60 → 118x54 in one session. Others N/A — no input.

### LLR-144.4 — The E-3 stylesheet rules replaced, not overridden
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The stylesheet `s19_app/tui/styles.tcss` shall carry no `width: 2fr` rule on `#patch_win_script`, no fixed `height: 10` on `#patch_doc_entries_table`, and no `layout: grid` on `#patch_doc_entry_buttons` or `#patch_doc_controls`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-04 — `pytest tests/test_b97_patch_editor.py -k tc_b97_04`; procedure: appendix A.4 TC-B97-04.
- **Numeric pass threshold:** 0 of the 4 pairs present (today 4, P-9).
- **Negative control:** executed on `main`: the 4 pairs present → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: a selector list naming two ids (`#patch_doc_entry_buttons,` on its own line, `:1160`) is matched as one block. Others N/A.

### LLR-144.5 — The JSON tab's read-only view of the loaded document
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** When a change-set is loaded into the Patch Editor, the app shall feed a read-only view (`#patch_json_view`, NEW) inside `#patch_win_json` with `ChangeService.document` (`change_service.py:696`) serialised by `serialize_change_document` (`s19_app/tui/changes/io.py:1392`), through the I-2/I-3 seam at the `refresh_entries` sites (`app.py:3265`, `:3451`, `:5279`, `:10758`). If the serialised document exceeds `JSON_TAB_LINE_CAP = 5000` lines (NEW), then the view shall show its first 5000 lines followed by one note line `showing 5000 of M lines`. The view shall be display-only: no parse, apply, save or paste action shall read its text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-05 — `pytest tests/test_b97_patch_editor.py -k tc_b97_05`; procedure: appendix A.4 TC-B97-05.
- **Numeric pass threshold:** 6 parsed entries, address list as P-5; the view text never equals `DUMMY_CHANGESET_TEXT` after a Load; 0 characters changed by typing; at 5001 lines: 5000 document lines + 1 note line naming `5000` and `5001`; at 5000 lines: no note; display-only arm: the document holds the 6 pasted entries, not the capped view's.
- **Negative control:** executed on `main` (§2.7 P-4): buffer `== DUMMY True`, 2 address keys → RED; removing the cap (mutation, Phase 3) → the 100,000-entry arm shows > 5000 lines, RED; Parse wired to the view's text (mutation) → the display-only arm reads the capped document, RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a 0-entry document → `"entries": []`; boundary: 5000 and 5001 lines; invalid: a legacy v1 file → the empty document (not the previous one). Error: N/A — the serialiser is reused unchanged and raises on nothing a loaded document can hold.

### LLR-144.6 — The JSON view follows every writer at once, under its stamp
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** When any of the nine writers of `ChangeService.document` (§2.7 P-6) changes the Patch Editor document, the panel shall refresh `#patch_json_view` at once and shall show above it the stamp `N entries · HH:MM:SS · saved` or `N entries · HH:MM:SS · unsaved changes` (NEW), where N is the document's entry count, HH:MM:SS the refresh time and the last part the panel's dirty flag (`screens_directionb.py:4851`, P-48). When the dirty flag changes — paste-buffer typing (`:5707`), an entry Add / Edit / Remove (`:5771`), Save's `mark_saved` (`:5953`) or `mark_loaded` (`:5964`) — the panel shall recompose the stamp at once.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-06 — `pytest tests/test_b97_patch_editor.py -k tc_b97_06`; procedure: appendix A.4 TC-B97-06.
- **Numeric pass threshold:** 9 of 9 writer arms: parsed view == `json.loads(serialize_change_document(service.document))`; stamp N == parsed entry count; stamp state == `saved` iff the dirty flag is False; after Load the state reads `saved`, after Add `unsaved changes`; 2 of 2 dirty-flag arms with no further press: after Save the stamp reads `saved` with N unchanged, after one character typed into `#patch_paste_text` it reads `unsaved changes` with the view unchanged.
- **Negative control:** a feed that skips one writer (mutation: drop the refresh on Undo, Phase 3, C-40) → the Undo arm RED; a stamp counting the pre-change document (mutation) → N ≠ parsed count, RED; a stamp recomposed only by the document writers (mutation) → the Save and typing arms keep the stale state, RED (neither writes the document, §2.7 P-57).
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: Remove the last entry → `"entries": []`, stamp `0 entries`; boundary: Undo at the bottom of the stack (no-op) leaves view and N unchanged. Others N/A — entry validation is reused unchanged.

### LLR-144.7 — Identity ribbon and file-derived fields, markup-safe (E-5, C-17)
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `PatchEditorPanel` shall show the loaded document's file name (`ChangeDocument.source_path.name`, `changes/model.py:258`) and kind (`:253`) on an identity ribbon (NEW), and shall render that name and every file-derived entry field (value, symbol, address text) in the ledger, the inspector pane, the JSON view and the issues line `#patch_doc_issues` as `rich.text.Text` through `safe_text` (`s19_app/utils.py:44`), never interpolated into a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-07 — `pytest tests/test_b97_patch_editor.py -k tc_b97_07`; procedure: appendix A.4 TC-B97-07.
- **Numeric pass threshold:** 0 `MarkupError`; each payload bracket token literal in the plain text of each of the 5 surfaces; 0 spans whose range lies inside a payload occurrence and whose style differs from the surface's base style (spans **originating in the payload**); 0 C0/C1 control characters painted.
- **Negative control:** build the ribbon with `Text.from_markup(f"… {name}")` (mutation, Phase 3, C-40) → `MarkupError` or a payload-originated span, RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☒ error — empty: a new unsaved document → the ribbon says `draft` with no name; error: the NAME and CONTENT arms. Others N/A.

### LLR-144.8 — The inspector's before→after hex strip follows the highlighted row
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** When the ledger's highlighted row changes, the inspector shall paint that entry's before and after bytes as a hex strip (NEW id) whose changed bytes carry a text attribute (bold, reverse or underline) as well as a colour.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-39 — `pytest tests/test_b97_patch_editor.py -k tc_b97_39`; procedure: appendix A.4 TC-B97-39.
- **Numeric pass threshold:** 3 of 3 rows: after-bytes == the entry's encoded bytes, before-bytes == the image bytes at that address; every changed byte cell carries the attribute; 0 unchanged cells carry it.
- **Negative control:** a strip bound to row 0 only (mutation, Phase 3) → rows 2-3 RED; today no strip in an inspector → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no image loaded → the strip's one English empty line (LLR-148.9). Others N/A.

### LLR-144.9 — Labelled entry form and entry chips in the inspector
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The inspector pane shall carry `#patch_entry_address_input`, `#patch_entry_value_input` and `#patch_entry_bytes_input`, each beside a visible label naming its field, and the entry chips `#patch_entry_add_button`, `#patch_entry_edit_button`, `#patch_entry_remove_button`, `#patch_entry_edit_json_button` on one row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-40 — `pytest tests/test_b97_patch_editor.py -k tc_b97_40`; procedure: appendix A.4 TC-B97-40.
- **Numeric pass threshold:** 7 of 7 contained; 3 of 3 labelled; 1 distinct chip row.
- **Negative control:** executed on `main`: the inputs sit in `#patch_doc_entry_inputs` outside any inspector pane → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-144.10 — Patch Editor keyboard order
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.5
- **Statement:** The Patch Editor's focus order shall run, with the Inspector tab active, header chips → ledger → tab chips → inspector form → entry chips → file row → document controls; with the JSON tab active, header chips → ledger → tab chips → JSON view → paste area → paste controls → history controls → execute row (→ save-back and before/after rows while offered) → file row → document controls; with the Checks tab active, header chips → ledger → tab chips → checks controls → file row → document controls. Every button and chip in it shall be operable by `enter` or `space` and every scroll view in it (the JSON view) by the arrow keys, a focused chip shall paint a style different from its unfocused style, and a tab chip's unfocused, focused and selected styles shall be pairwise distinct.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-41 — `pytest tests/test_b97_patch_editor.py -k tc_b97_41`; procedure: appendix A.4 TC-B97-41.
- **Numeric pass threshold:** per tab state: 0 group inversions; ≥ 1 member in each group of that state; reference set (§4 method (b)) ⊆ chain set; one `enter` arm per button group with its effect; 0 chips with two equal states among unfocused · focused · selected.
- **Negative control:** executed on `main` (§2.7 P-33): no tab chip in the 40-id chain → RED; a displayed control with `can_focus = False` (mutation, Phase 3) → the completeness clause RED (executed on HEAD, §2.7 P-54).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each of the 3 tab states; the save-back row offered. Others N/A.

### LLR-144.11 — Patch Editor filled elements
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `PatchEditorPanel` shall paint exactly one filled element besides the ledger hero, `#patch_doc_save_button`, and shall paint the active tab chip in the selection style.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-42 — `pytest tests/test_b97_patch_editor.py -k tc_b97_42`; procedure: appendix A.4 TC-B97-42.
- **Numeric pass threshold:** the filled list == `['patch_doc_save_button']` on 3 of 3 tab states; the active chip carries the selection class and its background ≠ the filled background.
- **Negative control:** a second `variant="primary"` (mutation, Phase 3) → RED; the active chip given the filled class (mutation) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each of the 3 tabs active. Others N/A.

### LLR-144.12 — Every shipped Patch Editor control displayed in its home
- **Traceability:** HLR-144
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** The `PatchEditorPanel` shall display each item of the table below inside its home whenever its condition holds, with `#patch_paste_text` editable; each displayed control of the controls column (§1.3) shall be in the panel's focus chain, and the read-outs column is displayed without a focus-chain requirement.

| home | controls | read-outs | displayed when |
|---|---|---|---|
| ledger column | `#patch_doc_entries_table` | `#patch_doc_empty_state` (instead of the table, with no entries) | always |
| inspector pane | `#patch_entry_address_input`, `#patch_entry_value_input`, `#patch_entry_bytes_input`, `#patch_entry_add_button`, `#patch_entry_edit_button`, `#patch_entry_remove_button`, `#patch_entry_edit_json_button` | the hex strip | Inspector tab active |
| `#patch_win_json` | `#patch_json_view`, `#patch_paste_text`, `#patch_paste_parse_button`, `#patch_edit_json_button`, `#patch_undo_button`, `#patch_redo_button`, `#patch_execute_scope_button`, `#patch_execute_run_button` | the stamp, `#patch_paste_gauge`, `#patch_history_strip`, `#patch_scope_line` | JSON tab active |
| `#patch_win_json` | `#patch_saveback_name_input`, `#patch_saveback_width_button`, `#patch_saveback_confirm_button`, `#patch_saveback_decline_button` · `#patch_before_after_button` | — | JSON tab active and the save-back offer / the before-after report is open (shipped conditions) |
| `#patch_win_checks` | `#patch_checks_run_button` | `#patch_doc_issue_count`, `#patch_doc_issues`, `#patch_checks_status`, `#patch_checks_strip`, `#patch_checks_help` | Checks tab active |
| file row | `#patch_doc_file_select`, `#patch_doc_path_input`, `#patch_doc_load_button`, `#patch_doc_refresh_button` | — | always |
| document controls | `#patch_doc_validate_button`, `#patch_doc_apply_button`, `#patch_doc_save_button` | — | always |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-60 — `pytest tests/test_b97_patch_editor.py -k tc_b97_60`; procedure: appendix A.4 TC-B97-60.
- **Numeric pass threshold:** 0 items missing from their home over the 4 states; 29 of 29 controls in the focus chain where displayed and 11 of 11 read-outs displayed where their condition holds (guard: each item checked in ≥ 1 state); subset guard: every id of `PE_IDS_9C7BEAF` whose widget is a control type lies in the controls column (28 of 28 on HEAD, §2.7 P-55); `read_only` False; the paste-parse arm changes the entry count.
- **Negative control:** a control left under a hidden pane (mutation, Phase 3) → RED; `#patch_paste_text` reseeded read-only (mutation) → RED; a shipped control dropped from the table (mutation) → the subset guard RED (executed, P-55).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the conditional rows (save-back, before/after) and 118x54. Others N/A.

### LLR-145.1 — Check Editor re-composed: ledger, REPORT FIELDS card, one docked row
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `CheckEditorPanel` shall yield every id of `CE_IDS_9C7BEAF` (31 ids, appendix A.2) with `#check_param_table` in the left column at full height holding one row per A2L tag with an integer address (filled by `_prefill_check_editor`, `app.py:5329`), a REPORT FIELDS card with focusable Fields / JSON / Addendum tab chips (ids NEW, activated by click, `enter` or `space`) on the right, and `#check_validate_button`, `#check_write_button`, `#check_apply_ghost` and `#check_fields_count` on one docked row; the panel shall offer no apply action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-08 — `pytest tests/test_b97_check_editor.py -k tc_b97_08`; procedure: appendix A.4 TC-B97-08.
- **Numeric pass threshold:** 0 of 31 ids missing; `row_count == 75` (P-24); 1 distinct `region.y` across the 4 docked ids (today y=35 and y=38); 9 of 9 tab activations; 0 apply actions.
- **Negative control:** executed on `main`: `#check_validate_button (62,35,…)` and `#check_fields_count (62,38,…)` on different rows → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no A2L → the ledger's empty state; boundary: 118x54. Others N/A.

### LLR-145.2 — The Address column is never truncated
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The `CheckEditorPanel` shall size `#check_param_table`'s Address column to its longest address and place it so that the whole column lies inside the table's viewport at horizontal scroll 0, at every width from 118 columns upward.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-09 — `pytest tests/test_b97_check_editor.py -k tc_b97_09`; procedure: appendix A.4 TC-B97-09.
- **Numeric pass threshold:** `max_scroll_x == 0`; offset + width ≤ content width; 75 of 75 addresses painted in full.
- **Negative control:** executed on `main` (§2.7 P-12): `scroll_x max 25`; offset 52 + 12 > 56 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 and the longest address (10 cells). Others N/A.

### LLR-145.3 — Parameter names stay distinguishable when clipped
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** The `CheckEditorPanel` shall give the Parameter column a content width of at least 42 cells and each REPORT FIELDS line's name field at least 24 cells at every width from 118 columns upward, the name field growing with the card (LLR-149.5). The panel shall show the highlighted ledger row's full parameter name and its address on one full-name line (NEW) under the ledger. If a parameter name is wider than the Parameter column, then the panel shall paint its first dot-separated segment, one ellipsis and the name's tail filling the column. If a parameter name is wider than a REPORT FIELDS name field, then the panel shall paint one ellipsis and the name's tail filling the field. A name that fits shall be painted in full.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-10 — `pytest tests/test_b97_check_editor.py -k tc_b97_10`; procedure: appendix A.4 TC-B97-10.
- **Numeric pass threshold:** Parameter content width W ≥ 42 and Fields name width ≥ 24 at both sizes; per clipped Parameter cell: starts with `first_segment + "…"`, exactly one `…`, ends with the name's last `W − len(first_segment) − 1` characters, cell length == W (guard: ≥ 1 clipped cell at 118x54 — 15 names exceed 42); per clipped Fields name: starts with `…`, ends with the name's last `width − 1` characters; **per cell:** 0 pairs of equal Parameter cells with different names over the 75 rows; 0 pairs of equal Fields lines over the six (they share one address, so only the name separates them); at 220x60 the 47-cell name painted in full; the full-name line holds the 47-cell name and its address in full when that row is highlighted at 118x54; the Fields name width at 220x60 > its width at 118x54.
- **Negative control:** measured on the fixture (§2.7 P-38): a head-keeping truncation (mutation, Phase 3) fails the tail clause on every clipped cell and paints 3 of the six Fields names as `ASAM.M.SCALAR.UBYTE.TAB…` at 24 cells → RED; a tail-only Parameter truncation fails the first-segment clause → RED; a 40-cell Parameter column leaves `ASAM.M.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` / `ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0` equal → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a name exactly W cells (no ellipsis); a name with no dot (`UNKNOWN…`, head + `…` + tail). Others N/A.

### LLR-145.4 — One-row chip shape in the Check Editor (E-4)
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The `CheckEditorPanel` shall render every one of its buttons as a one-row chip.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-11 — `pytest tests/test_b97_check_editor.py -k tc_b97_11`; procedure: appendix A.4 TC-B97-11.
- **Numeric pass threshold:** every height == 1 (today `#check_validate_button` height 3).
- **Negative control:** executed on `main`: heights of 3 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A.

### LLR-145.5 — File-derived names in the Check Editor render literally (C-17)
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `CheckEditorPanel` shall render every A2L parameter name, spec file name and REPORT FIELDS line as `rich.text.Text` built through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-12 — `pytest tests/test_b97_check_editor.py -k tc_b97_12`; procedure: appendix A.4 TC-B97-12.
- **Numeric pass threshold:** 0 `MarkupError`; payload brackets literal in all 4 surfaces; 0 spans originating in the payload; 0 control characters painted.
- **Negative control:** render one surface with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload. Others N/A.

### LLR-145.6 — The REPORT FIELDS card holds exactly the included fields
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The REPORT FIELDS card's Fields tab shall list one line per included parameter (`☑`, name, address) and one per memory row (`▪`, label, address), in inclusion order; its JSON tab (`#check_preview`) shall show the spec document those fields produce, capped at `JSON_TAB_LINE_CAP` lines with the LLR-144.5 note line; and its Addendum tab shall show `#check_addendum_preview`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-43 — `pytest tests/test_b97_check_editor.py -k tc_b97_43`; procedure: appendix A.4 TC-B97-43.
- **Numeric pass threshold:** parsed Fields set == `{("☑", a1), ("☑", a2), ("▪", m1)}`; JSON tab addresses == `[a1, a2, m1]`; `#check_fields_count` reads 3; Addendum shows `#check_addendum_preview`; at 5001 lines: 5000 + 1 note line.
- **Negative control:** a card fed from the unfiltered parameter list (mutation, Phase 3) → 75 lines, RED; executed on `main`: no Fields tab → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: nothing included → one empty-state line, `"entries": []`; boundary: include then exclude the same parameter → the line disappears; 5000/5001 lines. Others N/A.

### LLR-145.7 — Memory-row table with labelled inputs
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The REPORT FIELDS card's Fields tab shall carry `#check_mem_table` (columns Address, Label, Fmt) above `#check_mem_address_input`, `#check_mem_label_input` and `#check_mem_size_input`, each beside a visible label naming its field, with `#check_mem_add_button` and `#check_mem_remove_button`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-44 — `pytest tests/test_b97_check_editor.py -k tc_b97_44`; procedure: appendix A.4 TC-B97-44.
- **Numeric pass threshold:** 6 of 6 contained; 3 of 3 labelled.
- **Negative control:** executed on `main`: the memory inputs carry placeholders only, no label widget → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A (input validation is batch-94's).

### LLR-145.8 — Check Editor keyboard order and include by key
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.5
- **Statement:** The Check Editor's focus order shall run header chips → parameter filter → parameter ledger → include chip → REPORT FIELDS tab chips → the active tab's controls (Fields: memory inputs and chips; JSON and Addendum: their scroll view) → spec row → docked row, and every button and chip in it shall be operable by `enter` or `space` and every scroll view in it by the arrow keys. When the engineer presses `space` on a highlighted ledger row, the panel shall toggle that parameter's inclusion. A focused chip shall paint a style different from its unfocused style, and a tab chip's unfocused, focused and selected styles shall be pairwise distinct.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-45 — `pytest tests/test_b97_check_editor.py -k tc_b97_45`; procedure: appendix A.4 TC-B97-45.
- **Numeric pass threshold:** per tab state: 0 group inversions, ≥ 1 member per group, reference set (§4 method (b)) ⊆ chain set, one `enter` arm per button group, 0 chips with two equal states among unfocused · focused · selected; `space` → count N+1 then N.
- **Negative control:** executed on `main` (§2.7 P-33): the 27-id chain holds no header chip and no tab chip → RED; `DataTable` binds no `space` today (P-43) → the include-by-key arm RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: no A2L loaded (the ledger still in the chain); each tab state. Others N/A.

### LLR-145.9 — Check Editor filled elements
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `CheckEditorPanel` shall paint exactly one filled element besides the ledger hero, `#check_write_button`, and shall paint the active tab chip in the selection style.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-46 — `pytest tests/test_b97_check_editor.py -k tc_b97_46`; procedure: appendix A.4 TC-B97-46.
- **Numeric pass threshold:** the filled list == `['check_write_button']` on 3 of 3 tab states; the active chip's background ≠ the filled background.
- **Negative control:** a second `variant="primary"` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each of the 3 card tabs active. Others N/A.

### LLR-145.10 — Every shipped Check Editor control displayed in its home
- **Traceability:** HLR-145
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** The `CheckEditorPanel` shall display each item of the table below inside its home whenever its condition holds, each displayed control of the controls column (§1.3) in the panel's focus chain and the read-outs column displayed without a focus-chain requirement, and shall keep `#check_preview_toggle_button` mounted and not displayed, its function carried by the Addendum tab chip.

| home | controls | read-outs | displayed when |
|---|---|---|---|
| ledger column | `#check_param_filter`, `#check_param_table`, `#check_param_include_button` | — | always |
| Fields pane | `#check_mem_table`, `#check_mem_address_input`, `#check_mem_label_input`, `#check_mem_size_input`, `#check_mem_add_button`, `#check_mem_remove_button` | the Fields lines, `#check_status` | Fields tab active |
| JSON pane | the JSON pane's scroll view (NEW) | `#check_preview` | JSON tab active |
| Addendum pane | the Addendum pane's scroll view (NEW) | `#check_addendum_preview` | Addendum tab active |
| spec row | `#check_spec_file_select`, `#check_file_name_input` | — | always |
| docked row | `#check_validate_button`, `#check_write_button` | `#check_apply_ghost`, `#check_fields_count` | always |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-61 — `pytest tests/test_b97_check_editor.py -k tc_b97_61`; procedure: appendix A.4 TC-B97-61.
- **Numeric pass threshold:** 0 items missing over 3 states; 15 of 15 controls in the focus chain where displayed and 6 of 6 read-outs displayed (guard: each item checked in ≥ 1 state); subset guard: every control-typed id of `CE_IDS_9C7BEAF` but the hidden toggle lies in the controls column (13 of 13 on HEAD, §2.7 P-55); the toggle mounted and hidden.
- **Negative control:** a control left under a hidden pane (mutation, Phase 3) → RED; a shipped control dropped from the table (mutation) → the subset guard RED (executed, P-55).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: each tab state at 118x54. Others N/A.

### LLR-146.1 — Pipeline of block cards joined by cables
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** While a flow is loaded, the `FlowBuilderPanel` shall paint its blocks as cards in block order on one horizontal pipeline (id NEW) with one cable between consecutive cards, and shall display neither the numbered block list (`#flow_blocks`) nor the grid canvas (`#flow_canvas`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-13 — `pytest tests/test_b97_flow_builder.py -k tc_b97_13`; procedure: appendix A.4 TC-B97-13.
- **Numeric pass threshold:** 4 cards, 3 cables, one painted row band; `#flow_blocks` and `#flow_canvas` not displayed (today `#flow_blocks (5, 37, 110, 5)` displayed).
- **Negative control:** executed on `main`: `#flow_blocks` displayed and no pipeline id → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: 0 blocks → an empty-rail line; boundary: more cards than fit at 118 → the rail scrolls horizontally inside its own container (never the panel). Others N/A.

### LLR-146.2 — The palette offers every placeable kind
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall render one `flow_palette_<kind>` chip for each kind of `_KIND_OPTIONS` (`flow_screens.py:542-551`), in that order, each routed through the shipped handler (`:1455-1461`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-14 — `pytest tests/test_b97_flow_builder.py -k tc_b97_14`; procedure: appendix A.4 TC-B97-14.
- **Numeric pass threshold:** 7 chips in `_KIND_OPTIONS` order; 7 of 7 clicks set `#flow_kind`.
- **Negative control:** executed on `main` (§2.7 P-13): 4 chips → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the default kind (`source`) and the last (`external_step`). Others N/A.

### LLR-146.3 — The add form shows only the chosen kind's inputs
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** When a kind is chosen, the `FlowBuilderPanel` shall display exactly the inputs of that kind's row in the table below and hide every other add input, with the EXT-STEP inputs on two rows.

| kind | displayed add inputs |
|---|---|
| `source`, `patch`, `crc`, `write_out` | `#flow_ref` |
| `check` | `#flow_ref`, `#flow_gating` |
| `a2b` | `#flow_ref_a`, `#flow_ref_b` |
| `external_step` | `#flow_ext_mode`, `#flow_ext_instruction`, `#flow_ext_log`, `#flow_ext_output` (two rows) |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-15 — `pytest tests/test_b97_flow_builder.py -k tc_b97_15`; procedure: appendix A.4 TC-B97-15.
- **Numeric pass threshold:** 7 of 7 arms equal their row; EXT-STEP on 2 distinct rows. The visibility table restates `_sync_kind_dependent_visibility` (`:1534-1547`) — a regression PIN; the two-row clause is the gate.
- **Negative control:** executed on `main`: the EXT-STEP inputs share `region.y` 13 (P-22) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: switching kinds twice; invalid: EXT-STEP Add with an empty log → the English refusal. Others N/A.

### LLR-146.4 — Card text clipped to the card (F-1)
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The pipeline card renderer shall clip every title and IO line to the card's inner width with one ellipsis, keeping the head of a label (kind, title) and of an EXT-STEP `instruction` (a command), and the tail of a file name or path (refs, log, output).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-16 — `pytest tests/test_b97_flow_builder.py -k tc_b97_16`; procedure: appendix A.4 TC-B97-16.
- **Numeric pass threshold:** 0 painted card lines wider than the card; per clipped line exactly 1 `…`; title and instruction lines start with their first `w−1` cells; path lines end with their last `w−1` cells.
- **Negative control:** executed on `main` (§2.7 P-14): a 60-cell `text_` paints past `x + w` → RED; a tail-keeping instruction clip (mutation) → the head clause RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a ref exactly the inner width (no ellipsis). Others N/A.

### LLR-146.5 — The foot row, and Run as the Builder's one filled action
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall carry `#flow_run`, `#flow_clear`, `#flow_save` and `#flow_load` on one foot row, shall paint exactly one filled element besides the pipeline hero, `#flow_run`, and shall paint the selected kind chip in the selection style.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-17 — `pytest tests/test_b97_flow_builder.py -k tc_b97_17`; procedure: appendix A.4 TC-B97-17.
- **Numeric pass threshold:** 1 row; filled list == `['flow_run']` on 7 of 7 kind selections (today `flow_screens.py:824` primary on Run); selected chip background ≠ filled background; 1 run request per press.
- **Negative control:** a second primary chip, or the selected kind given the filled class (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54; each kind selected. Others N/A.

### LLR-146.6 — The CRC and waiting colour tokens
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `insight_style` module shall declare the CRC token `#c9562b` and the waiting token `#e8ad3d` (names NEW), and the flow screens shall paint CRC cards with the CRC token and never with the waiting token.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-18 — `pytest tests/test_b97_flow_builder.py -k tc_b97_18`; procedure: appendix A.4 TC-B97-18.
- **Numeric pass threshold:** CRC card span colour == the CRC token; token values `#c9562b` / `#e8ad3d`; hue distance 23.0° ≥ 20° (P-40).
- **Negative control:** executed (§2.7 P-40): `#c9562b` against the prototype amber `#e8a33d` → 19.5° < 20°, RED; a CRC card painted with the waiting token (mutation) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a CRC card beside a waiting card in one lane (`crc_wait_chain`, A.5). Others N/A.

### LLR-146.7 — Flow Builder strings in English
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall paint every user-facing string in English.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-19 — `pytest tests/test_b97_flow_builder.py -k tc_b97_19`; procedure: appendix A.4 TC-B97-19.
- **Numeric pass threshold:** 0 `ES_MARKER` constants and 0 frozen values in the class; reach guard 27 == 27 on `9c7beaf`.
- **Negative control:** executed on `9c7beaf` (§2.7 P-17): 27 → RED; a translation that leaves `'pegado: '` (one of the six the round-2 marker missed) → census (b) RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: English text sharing a marker shape (`DE AD BE EF` in `window_help.py`) is not matched — `de` is case-sensitive, executed `window_help 0`. Others N/A.

### LLR-146.8 — File-derived text on cards and the add form renders literally (C-17)
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall render every flow name, block ref, EXT-STEP `instruction`, `log_ref` and `output_path`, file name and session path on the pipeline, the ribbon and the add form as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-20 — `pytest tests/test_b97_flow_builder.py -k tc_b97_20`; procedure: appendix A.4 TC-B97-20.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal on each of the 4 fields; 0 spans originating in the payload; 0 control characters painted.
- **Negative control:** render the card IO line with `Text.from_markup` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload on 4 fields. Others N/A.

### LLR-146.9 — One-row copy/paste strip
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall carry `#flow_pick`, `#flow_copy`, `#flow_paste` and `#flow_clip_status` on one painted row inside the panel region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-47 — `pytest tests/test_b97_flow_builder.py -k tc_b97_47`; procedure: appendix A.4 TC-B97-47.
- **Numeric pass threshold:** 1 row; 4 of 4 inside; block count +1 after copy + paste.
- **Negative control:** executed on `main` (§2.7 P-10): `flow_clip_status` overflows the panel → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54. Others N/A (refusals are batch-96's, translated by LLR-146.7).

### LLR-146.10 — `Variables (n)` chip
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall label `#flow_funnel_toggle` `Variables (n)`, n the number of funnel variables, and pressing it shall show or hide `#flow_funnel_editor`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-48 — `pytest tests/test_b97_flow_builder.py -k tc_b97_48`; procedure: appendix A.4 TC-B97-48.
- **Numeric pass threshold:** label == `Variables (1)`; display toggles 2 of 2.
- **Negative control:** executed on `main`: label `Funnel (1)` (`flow_screens.py:1243`, pinned by `test_flow_funnel_b96.py:330`) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: 0 variables → `Variables (0)`. Others N/A.

### LLR-146.11 — Session directory on the Builder ribbon
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall show the session directory set by `set_session_dir` on its identity ribbon (`#flow_name_strip`), path tail kept, and shall not display `#flow_ext_session`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-49 — `pytest tests/test_b97_flow_builder.py -k tc_b97_49`; procedure: appendix A.4 TC-B97-49.
- **Numeric pass threshold:** 1 of 1 ribbon reads ends with the session path's last segment; 0 displayed `#flow_ext_session` rows.
- **Negative control:** executed on `main`: the session sits in `#flow_ext_session` (`flow_screens.py:764`) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project → the ribbon's English no-session text (LLR-148.9). Others N/A.

### LLR-146.12 — Run is single-image; no scope selector in the Builder
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowBuilderPanel` shall compose no variant-scope selector (`#flow_scope`), and its Run shall request the single-image scope `FLOW_SCOPE_SINGLE` (`flow_model.py:132`) whatever variant set the project declares.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-50 — `pytest tests/test_b97_flow_builder.py -k tc_b97_50`; procedure: appendix A.4 TC-B97-50.
- **Numeric pass threshold:** 0 `#flow_scope` widgets; 1 of 1 run requests carries `FLOW_SCOPE_SINGLE`; `#flow_result` holds 0 `variant(s):` lines.
- **Negative control:** executed on `main` (§2.7 P-47): `#flow_scope` composed (`flow_screens.py:818-823`) → query length 1, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a project with a declared variant set (the case the retired selector served). Others N/A.

### LLR-146.13 — Flow Builder keyboard order
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.5
- **Statement:** The Flow Builder's focus order shall run header chips → kind chips → add inputs → Add → copy/paste strip → `Variables (n)` → funnel editor (while open) → foot row; every kind chip shall be focusable and set the kind on `enter` or `space`; every button and chip shall be operable by `enter` or `space` and every scroll view by the arrow keys; a focused chip shall paint a style different from its unfocused style, and a kind chip's unfocused, focused and selected styles shall be pairwise distinct.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-51 — `pytest tests/test_b97_flow_builder.py -k tc_b97_51`; procedure: appendix A.4 TC-B97-51.
- **Numeric pass threshold:** 0 group inversions; reference set (§4 method (b)) ⊆ chain set; one `enter` arm per button group; 7 of 7 kind chips set their kind by key; 0 chips with two equal states among unfocused · focused · selected.
- **Negative control:** executed on `main` (§2.7 P-33): 4 kind chips in the chain, `flow_scope` between paste and Run → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the EXT-STEP form and the funnel editor open (most inputs). Others N/A.

### LLR-146.14 — A NUL character in a ref is refused, never raised
- **Traceability:** HLR-146
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.8
- **Statement:** If a path-bearing block field of a flow file — `SourceBlock.image_ref`, `PatchBlock.change_doc_ref`, `WriteOutBlock.output_name`, `CheckBlock.check_doc_ref`, `CrcBlock.config_ref`, the `ref` of each `A2BBlock` binding, `ExternalStepBlock.log_ref` or `ExternalStepBlock.output_path` (`flow_model.py:229, 250, 267, 289, 315, 338, 505, 506`) — carries a NUL character, then `load_flow_json` shall refuse the file with a `FLOW-UNSAFE-REF` finding (`flow_persistence_service.py:114`). If a chain-set's template or input ref carries a NUL character, then `load_chain_set` shall refuse the set with a `CHAIN-SET-UNSAFE-REF` finding (`:1098`). If a manifest entry or a lane input bound through `#fx_bind_<i>_<j>` carries a NUL character, then `_resolve_manifest_entry` (`variant_execution_service.py:205`, the resolve at `:273`, §2.7 P-50) shall refuse that entry — resolve no path for it — with a `MANIFEST-PATH-ESCAPE` finding (`:106`). The `stat()` guards of `load_flow_json` and `load_chain_set` (`flow_persistence_service.py:903-906`, `:1463-1471`) shall catch `ValueError` as well as `OSError`. None of these shall raise.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-62 — `pytest tests/test_b97_flow_builder.py -k tc_b97_62`; procedure: appendix A.4 TC-B97-62.
- **Numeric pass threshold:** 0 exceptions over 15 arms — the 5 of P-36, one per enumerated block field (8), and a NUL in the file path handed to each `stat()` guard (2); each refusal arm returns no flow / set / path and exactly one finding of its code naming the field.
- **Negative control:** executed on `main` at the Inc-2 RED run (`evidence/inc-2/red.txt`, LED-.8): the loader arms of P-36 raise `ValueError`, the chain-set template arm loads, `run_flow` records a block error carrying the raw `ValueError` text instead of a finding, the `output_name` / `log_ref` / `output_path` arms are accepted, and the bound lane input yields that raw block error → RED on every arm (by raise, by raw text, or by acceptance); a `stat()` guard catching `OSError` only (as shipped) → the path arms raise `ValueError` (P-36 F), RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☒ error — invalid: NUL in each of the four field families; error: the uncaught `ValueError` of P-36. Others N/A.

### LLR-147.1 — Per-lane pipeline with cable status from the retained record
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** When a run record is rendered, the `FlowExecutionPanel` shall paint lane *i* (0-based, the import order) from `last_run_record.outcomes[i]` (`flow_screens.py:2550-2553`) and paint the cable after block *j* (0-based) with the glyph the table below gives for block *j* and block *j+1*.

| block *j* status (`flow_model.py:99-108`) | block *j+1* status | cable glyph |
|---|---|---|
| any | `waiting` | `□` |
| `ok` | not `waiting` | `▓` (`_FX_BAR_DONE`, `flow_screens.py:1795`) |
| `notices` | not `waiting` | `◇` (NEW) |
| `error` | not `waiting` | `✗` |
| `skipped`, `waiting`, or no record yet | not `waiting` | `░` (`_FX_BAR_GAP`, `:1796`) |

- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-21 — `pytest tests/test_b97_flow_execution.py -k tc_b97_21`; procedure: appendix A.4 TC-B97-21.
- **Numeric pass threshold:** 5 of 5 rows; 3-lane run: lane 0 `▓ ▓ ◇`, lane 1 `▓ □ ░`, lane 2 `▓ ✗ ░` (outcomes P-31: `ok ok notices ok` / `ok ok waiting skipped` / `ok error skipped skipped`); `wait_third_6` lane 2 `▓ ▓ ◇ □ ░` (P-41).
- **Negative control:** executed on `main`: a progress bar, no `◇` or `□` between blocks → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no record → every cable `░`; boundary: a 1-block lane (0 cables). Others N/A — the statuses are a closed enum.

### LLR-147.2 — The rebind input and its Bind sit inside the SOURCE card
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** The `FlowExecutionPanel` shall place each `fx_in_<i>_<j>` input (`flow_screens.py:2178`) and its `#fx_bind_<i>_<j>` button (`:2181`) — the press that makes a rebind take effect (§2.7 P-50) — inside the region of lane *i*'s SOURCE card *j*, the Bind directly after its input in the focus order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-22 — `pytest tests/test_b97_flow_execution.py -k tc_b97_22`; procedure: appendix A.4 TC-B97-22.
- **Numeric pass threshold:** every rebind input and every Bind contained (0 outside); each `fx_bind_<i>_<j>` immediately after `fx_in_<i>_<j>` in the chain.
- **Negative control:** the predicate needs the card region the new layout declares, so its RED run is executed on the Flow Execution increment's own tree with the input, or its Bind, re-parented to the lane row (mutation, C-40) → RED; it cannot run on `main`, where no card region exists.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a lane with two SOURCE blocks. Others N/A.

### LLR-147.3 — The paused lane: waiting style, Confirm in view, focus left alone
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While a lane's record holds a `waiting` block, the `FlowExecutionPanel` shall paint that lane's waiting-human elements in the waiting colour, show two red pending lines (log, output file) under the lane header whose leading glyph is not in the LLR-147.1 cable vocabulary, show `#fx_confirm_<i>` inside lane *i*'s region, and show above the run log the line `log + output file: REQUIRED for <chain> · press c to confirm` (NEW), `<chain>` the attention lane's chain name rendered through `safe_text`. When a lane enters the waiting state, the panel shall scroll `#fx_lanes_scroll` on both axes so that the attention lane's (§1.3) waiting card and its Confirm lie inside the viewport, shall give that Confirm the attention class (NEW), whose painted style differs from a waiting Confirm without it and from `#fx_run`'s, and shall leave the focus where it was. If the focus lies inside `#fx_lanes_scroll` when a lane enters the waiting state, then the panel shall keep the focused widget inside the viewport, scrolling only as far as that allows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-23 — `pytest tests/test_b97_flow_execution.py -k tc_b97_23`; procedure: appendix A.4 TC-B97-23.
- **Numeric pass threshold:** waiting card and Confirm contained in the viewport on both fixtures; the attention style on the attention lane's Confirm only, read from the compositor strips (≠ the other waiting Confirm's, ≠ `#fx_run`'s); `app.focused.id` == the id focused before Run (`fx_run`); other lanes' Confirm not displayed; 2 pending lines, leading glyph ∉ `{▓, ░, ✗, ◇, □}`; REQUIRED line count 1 while waiting, naming the attention lane's chain, 0 after confirm; focus-in-lanes arm: the focused `#fx_in_0_0` inside the viewport after the pause.
- **Negative control:** executed on `main`: no REQUIRED line → RED; the scroll step removed (mutation, Phase 3) → on `wait_third_6` the card outside the viewport, RED; Confirm auto-focused (mutation) → the focus clause RED; a scroll that ignores the focused widget (mutation) → the focus-in-lanes arm RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two lanes waiting at once (one REQUIRED line naming the attention lane, two Confirms, the attention lane scrolled to and highlighted); the waiting lane past the viewport on both axes (`wait_third_6`); the focus in a rebind input when the wait begins. Others N/A.

### LLR-147.4 — Two-row header; a two-word mode control
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowExecutionPanel` shall lay out a ribbon row (set identity, session directory, `#fx_import`, the mode control, `#fx_run`) and a set row (`#fx_set_name`, `#fx_save`, `#fx_set_select`, `#fx_load`), and shall present the mode as a two-word control (`sequential` / `parallel`) no wider than 30 cells, switchable by click, `enter` or `space`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-24 — `pytest tests/test_b97_flow_execution.py -k tc_b97_24`; procedure: appendix A.4 TC-B97-24.
- **Numeric pass threshold:** 8 of 8 inside; mode control width ≤ 30 (today `#fx_mode (21, 7, 80, 3)`, P-11); the report line reads `- **Mode:** parallel`.
- **Negative control:** executed on `main` (§2.7 P-11): `#fx_save`, `#fx_set_select`, `#fx_load` outside → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 and a 40-cell set name. Others N/A.

### LLR-147.5 — Flow Execution strings and run log in English
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowExecutionPanel`, the module constant `flow_screens.py:235` and the strings of `services/flow_execution_service.py` that the flow screens paint shall be in English.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-25 — `pytest tests/test_b97_flow_execution.py -k tc_b97_25`; procedure: appendix A.4 TC-B97-25.
- **Numeric pass threshold:** 0 `ES_MARKER` constants and 0 frozen values in the three scopes; reach guard 21 == 21; 0 matches in the painted text and in the record's summaries / diagnostics.
- **Negative control:** executed on `9c7beaf` (§2.7 P-17): 21 constants; the painted line `· ESPERANDO HUMANO — paso externo (block 3/4) · LOG 'flash_log.txt' pendiente` → RED; a summary keeping `comando` (missed by the round-2 marker) → census (b) RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid: as LLR-146.7. Others N/A.

### LLR-147.6 — File-derived text in lanes and the set picker renders literally (C-17)
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowExecutionPanel` shall render every chain name, template name, bound ref, EXT-STEP `instruction`, `log_ref` and `output_path`, written path, session path and saved-set file name on the lanes, the pending lines, the header, the run log and the options of `#fx_set_select` as `rich.text.Text` through `safe_text`, never as a markup-parsed string.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-26 — `pytest tests/test_b97_flow_execution.py -k tc_b97_26`; procedure: appendix A.4 TC-B97-26.
- **Numeric pass threshold:** 0 `MarkupError`; brackets literal in 5 surfaces; 0 spans originating in the payload; 0 control characters painted.
- **Negative control:** executed on `main` (§2.7 P-37): the set picker paints `flowsets/b97xyzw.json` with `bold`, `red`, `link=e`, `@click=app.quit` spans → RED; the chain name interpolated into a markup string (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☐ boundary ☐ invalid ☒ error — error: the hostile payload on 5 surfaces. Others N/A.

### LLR-147.7 — The waiting colour belongs to the waiting-human elements
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The four panels shall paint the waiting token `#e8ad3d` only on waiting-human elements (§1.3), and shall paint every other accent colour (saturation ≥ 0.15) in a colour whose hue lies at least 20° from the waiting hue.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-52 — `pytest tests/test_b97_flow_execution.py -k tc_b97_52`; procedure: appendix A.4 TC-B97-52.
- **Numeric pass threshold:** every span in `#e8ad3d` belongs to a waiting-human element; guards: ≥ 1 such span while waiting, ≥ 1 on each of the six element kinds of §1.3, ≥ 3 distinct accent colours collected over the four screens; every other accent ≥ 20° from 39.3° (measured today: notices `#f6ff8f` 25.5°, `#fd8383` 39.3°, the CRC token 23.0°, P-40).
- **Negative control:** executed on `main` (§2.7 P-16): the waiting state paints `.sev-warning` (`flow_screens.py:211`), the same colour as notices → RED; a notices glyph painted in the waiting token (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a CRC card beside the waiting card (`crc_wait_chain`); greys and whites (`#969aad`, `#e9e9e9`, saturation < 0.15) excluded. Others N/A.

### LLR-147.8 — No dead rows in Flow Execution; the lanes take the remaining height
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** While displayed, the `FlowExecutionPanel` shall paint no blank row outside `#fx_lanes_scroll` and no blank row between two consecutive lanes inside it, and shall give `#fx_lanes_scroll` the panel height its header rows and run log leave.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-53 — `pytest tests/test_b97_flow_execution.py -k tc_b97_53`; procedure: appendix A.4 TC-B97-53.
- **Numeric pass threshold:** 0 blank rows outside; 0 between lanes; the bottom equality at both sizes.
- **Negative control:** executed on `main` (§2.7 P-32): 3 blank rows outside at both sizes → RED (the inter-lane split of the 9 / 16 inside rows is recorded by the Flow Execution increment's RED run).
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no lanes → `#fx_empty` line only, 0 blank rows outside; boundary: 118x54 and 220x60. Others N/A.

### LLR-147.9 — Flow Execution filled elements
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `FlowExecutionPanel` shall paint exactly one filled element besides the lanes hero, `#fx_run`, plus `#fx_confirm_<i>` for each waiting lane.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-54 — `pytest tests/test_b97_flow_execution.py -k tc_b97_54`; procedure: appendix A.4 TC-B97-54.
- **Numeric pass threshold:** before: `['fx_run']`; waiting: `['fx_run', 'fx_confirm_1']`.
- **Negative control:** a primary Import (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: two lanes waiting (two Confirms). Others N/A.

### LLR-147.10 — One run at a time
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** If Run is pressed while a run is in flight, then the `FlowExecutionPanel` shall start no second run. While a run is in flight, `#fx_run` shall be disabled. When the run ends or raises, `#fx_run` shall be enabled again.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-55 — `pytest tests/test_b97_flow_execution.py -k tc_b97_55`; procedure: appendix A.4 TC-B97-55.
- **Numeric pass threshold:** 1 call and 1 new report for the 3 presses; disabled inside, enabled after; error arm: enabled after and one English error line (LLR-148.9).
- **Negative control:** executed on a model of the handler (§2.7 P-44): without the disable, `run calls 2` for both the press and the queued key → RED; the real-tree RED run is recorded by the Flow Execution increment.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a press right after the run ends starts a run (1 more call); error: a run that raises. Others N/A.

### LLR-147.11 — Flow Execution keyboard order
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.5
- **Statement:** The Flow Execution focus order shall run header chips → `#fx_import` → mode control → `#fx_run` → set row → lanes group (`#fx_lanes_scroll`, then per lane: each rebind input followed by its Bind, then Confirm), every button and chip shall be operable by `enter` or `space` and every scroll view (including `#fx_lanes_scroll`) by the arrow keys, and a focused chip shall paint a style different from its unfocused style.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-56 — `pytest tests/test_b97_flow_execution.py -k tc_b97_56`; procedure: appendix A.4 TC-B97-56.
- **Numeric pass threshold:** 0 group inversions; reference set (§4 method (b)) ⊆ chain set; one `enter` arm per button group; `fx_lanes_scroll` before `fx_in_0_0`; `fx_bind_1_0` right after `fx_in_1_0`; `fx_confirm_1` after `fx_bind_1_0` and before `fx_in_2_0`; 0 equal focused/unfocused chip styles.
- **Negative control:** executed on `main` (§2.7 P-33): no header chip in the chain → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: no lanes. Others N/A.

### LLR-147.12 — A lane wider than the viewport scrolls inside the lanes area
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While a lane's painted pipeline is wider than `#fx_lanes_scroll`'s viewport, the `FlowExecutionPanel` shall scroll that pipeline horizontally inside `#fx_lanes_scroll`, focusable and scrolled by `left` / `right` (§2.7 P-53), and shall keep every displayed descendant's clipped region (§1.3) inside the panel region. The panel shall paint at the head of each lane header one worst-status mark from the LLR-147.1 cable vocabulary — `✗` error, else `□` waiting, else `◇` notices, else `▓` ok, else `░` (nothing run) — so that a lane's state reads at horizontal scroll 0.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-63 — `pytest tests/test_b97_flow_execution.py -k tc_b97_63`; procedure: appendix A.4 TC-B97-63.
- **Numeric pass threshold:** `max_scroll_x > 0`; 0 panel overflow over clipped regions; keyboard arm: `tab` to `#fx_lanes_scroll`, `right` until `scroll_x == max_scroll_x` → the 6th card of each lane inside the viewport; header marks at `scroll_x` 0: `◇`, `◇`, `□` on `wait_third_6` and `◇`, `□`, `✗` on the 3-lane run.
- **Negative control:** executed on `main` (§2.7 P-11): `#fx_panel max_scroll_x 77` — the overflow lands on the panel, not on the lanes area → RED; the region predicate counting a scrolled card (mutation of the predicate) → RED on a correct tree, which is why the clipped region is read (P-52); executed on `main`: no lane-header mark → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 6 blocks at 118 (wider) vs 4 blocks at 220 (no scroll, `max_scroll_x == 0`). Others N/A.

### LLR-147.13 — A scoped key confirms the attention lane once per waiting entry
- **Traceability:** HLR-147
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.5
- **Statement:** When the engineer presses `c` on the Flow Execution screen, the `FlowExecutionPanel` shall confirm the attention lane's (§1.3) current waiting entry exactly as a press of its `#fx_confirm_<i>` does, provided the focus lies outside a text input, that entry has not been confirmed already and it has held the attention for at least `CONFIRM_DWELL_S = 0.5` s (NEW); otherwise the key shall confirm nothing, and in a text input it types `c`. The help entry and the REQUIRED line shall name the key. If `enter` is pressed on `#fx_run` while a lane waits, then the panel shall start one new run of the set (LLR-147.10) and confirm nothing.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-64 — `pytest tests/test_b97_flow_execution.py -k tc_b97_64`; procedure: appendix A.4 TC-B97-64.
- **Numeric pass threshold:** after the dwell, 1 re-run of lane 1 (its waiting block confirmed) per `c`, REQUIRED line count 0 after; `press("c", "c")` with two lanes waiting → 1 confirm, the second lane still waiting; `press("c", "c")` on `flash2_chain` → 1 confirm, the lane waiting at its second EXT-STEP; after `pilot.pause(0.6)` one more `c` confirms the next entry; 0 confirms with the focus in an input (its value gains `c`) or with no waiting lane; a stray `enter` on `#fx_run` while lane 1 waits → 1 more run call, 1 more report, 0 confirms, lane 1 waiting again; `c` named in the help entry and the REQUIRED line.
- **Negative control:** executed on `main` (§2.7 P-43): `c` is unbound on the screen → 0 re-runs, RED; a paint-only rule without the dwell (mutation) → the burst arms confirm 2, RED — a paint completes between the two keys of `press("c", "c")`, 0.049 s apart (P-60).
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: two lanes waiting (only the attention lane confirmed); a chain with two EXT-STEP blocks (one confirm per waiting entry, P-60); invalid: `c` with the focus in an input, `c` with no waiting lane, a stray `enter` on Run. Others N/A.

### LLR-148.1 — Chip family `flows`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** The `folder_open_service` shall declare a `flows` chip family (NEW `CHIP_FAMILY_FLOWS`) whose target is `project_dir / FLOWS_SUBDIR` (imported from `flow_persistence_service.py:95`, never re-declared) and `None` without a project. If the `flows` chip is pressed while `flows` is missing, then the shipped press path (`open_folder_chip.py:160-172`, §2.7 P-59) shall create it only through `create_chip_home` (`folder_open_service.py:279`) and only at a path whose resolved form lies inside the resolved project directory.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-27 — `pytest tests/test_b97_chips_help.py -k tc_b97_27`; procedure: appendix A.4 TC-B97-27.
- **Numeric pass threshold:** `== p / "flows"`; `is None`; 1 import, 0 literals; created path inside `p`.
- **Negative control:** executed on `main`: `"flows" in CHIP_FAMILIES` False → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no project; boundary: `flows` absent. Others N/A.

### LLR-148.2 — Chip family `session`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `folder_open_service` shall declare a `session` chip family (NEW `CHIP_FAMILY_SESSION`) whose target is the active project directory — the value `_publish_flow_session_dir` pushes (`app.py:8130-8137`) — and `None` without a project, and the `session` chip shall never create a folder.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B97-28 — `pytest tests/test_b97_chips_help.py -k tc_b97_28`; procedure: appendix A.4 TC-B97-28.
- **Numeric pass threshold:** `== p` / `is None`; 0 `create_chip_home` calls for `session`.
- **Negative control:** executed on `main`: `"session" in CHIP_FAMILIES` False → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: no project; boundary: the project dir removed under the app (refusal line, no create). Others N/A.

### LLR-148.3 — The no-project message names the family's folder
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** If a chip's target resolves to `None`, then the `OpenFolderChip` shall disable itself and set a status message that names that chip's family folder, never another family's.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-29 — `pytest tests/test_b97_chips_help.py -k tc_b97_29`; procedure: appendix A.4 TC-B97-29.
- **Numeric pass threshold:** every such message names its own family; 0 naming `Reports` for a non-`reports` family; ≥ 3 families exercised (`reports`, `flows`, `session`).
- **Negative control:** executed on `main`: `open_folder_chip.py:115` sets `REPORTS_NO_PROJECT_REASON` for any `None` target → "(Reports)" for a `flows` chip, RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☐ error — empty: no project. Others N/A.

### LLR-148.4 — Chip ids unique in the app
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.3
- **Statement:** The system shall give each mounted open-folder chip an id no other mounted widget carries, and the Check Editor's chip shall resolve the `checks` family home.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-30 — `pytest tests/test_b97_chips_help.py -k tc_b97_30`; procedure: appendix A.4 TC-B97-30.
- **Numeric pass threshold:** every count == 1 (6 chips: patch, checks ×2 screens, templates, flows, session; reports in its modal); the Check Editor target == the `checks` home.
- **Negative control:** executed on `main` (§2.7 P-19): a second `OpenFolderChip("checks")` yields `open_folder_checks` twice → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the Reports modal open at the same time. Others N/A.

### LLR-148.5 — Headers of the four screens carry both chips
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The `S19TuiApp` shall build the Check Editor, Flow Builder and Flow Execution headers with `titled_header` (`open_folder_chip.py:185`) carrying an `OpenFolderChip` (families `checks`, `flows`, `session`) and a `WindowHelpChip`, as the Patch Editor header already does (`app.py:3048-3049`), and a press on each enabled folder chip shall make exactly one call to the open seam with its resolved target.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-31 — `pytest tests/test_b97_chips_help.py -k tc_b97_31`; procedure: appendix A.4 TC-B97-31.
- **Numeric pass threshold:** 4 of 4 screens with 1 + 1 chips (today 1 of 4); 1 seam call per press, target == `resolve_chip_target(…)`.
- **Negative control:** executed on `main`: 1 of 4 → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 (the chips inside the header row). Others N/A.

### LLR-148.6 — Help entries name every control, input, tab, key and glyph as `label — effect`
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.9
- **Statement:** The `window_help` module shall carry an entry for each of the four screens — `patch` and `flow` rewritten, a Check Editor key and a Flow Execution key added (NEW) to `WINDOW_HELP_SECTIONS` and `SHIPPED_WINDOW_KEYS` (`window_help.py:57`, `:270`) — whose body holds one `label — effect` line, with a non-empty effect, for every button label, input or select label, tab label, key binding and glyph its screen renders in any of its states, block-kind glyphs included. From Inc-8 on, the key-binding lines of a window are its generated keys block (LLR-150.1), shown in the same help modal beneath the steps, and no key is described twice.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-32 — `pytest tests/test_b97_chips_help.py -k tc_b97_32`; procedure: appendix A.4 TC-B97-32.
- **Numeric pass threshold:** 100 % coverage on each screen of the coverage set taken as the union over the states the test drives (Patch: 3 tabs, save-back offered; Check: 3 tabs; Builder: 7 kinds, funnel editor open; Execution: no lanes and the paused 3-lane run), every matched line with a non-empty effect; guards on the **control** subset only (buttons, inputs, selects, tab chips — never bindings or glyphs): ≥ 26 (patch: 19 buttons + 7 inputs of `PE_IDS_9C7BEAF`), ≥ 12 (check: 6 + 6), ≥ 21 (flow: 13 + the 8 add inputs of LLR-146.3), ≥ 6 (execution: 4 + `#fx_set_name`, `#fx_set_select`).
- **Negative control:** executed on `main` (§2.7 P-21): 6/19 · 0/6 · 2/13 · 0/4 → RED; a body listing labels without ` — effect` (mutation) → RED; a coverage set read from one state only (mutation) → a label shown only on another tab or kind escapes, which the union catches.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a label carrying a glyph prefix (`⊕ CRC`) matched on its words; a control displayed in one state only. Others N/A.

### LLR-148.7 — Closed glyph vocabularies and a legend on every screen
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** Each renderer of the four panels — the Patch Editor hex strip, the Check Editor marks, the Builder cards and cables, the Execution lanes and pending lines — shall draw its glyphs from a closed vocabulary constant (NEW, one per renderer, each glyph with one meaning). Each panel shall paint a legend of at most two rows (id NEW) naming every status and mark glyph of its vocabularies, the block-kind glyphs being named in the help entry (LLR-148.6), and shall use the word `notices` for every non-blocking finding.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-33 — `pytest tests/test_b97_chips_help.py -k tc_b97_33`; procedure: appendix A.4 TC-B97-33.
- **Numeric pass threshold:** painted glyphs ⊆ vocabulary; vocabulary status / mark glyphs ⊆ legend text; vocabulary kind glyphs ⊆ help body; legend ≤ 2 painted rows, each on one row (LLR-149.4); 0 glyphs with two meanings; 0 `issues` for a non-blocking finding; guards: painted set size ≥ 6 (execution: 5 cables + the pending-line glyph), ≥ 2 (check), ≥ 1 (builder), ≥ 1 (patch).
- **Negative control:** a renderer painting a glyph outside its vocabulary (mutation, Phase 3) → RED; executed on `main`: no legend widget in `#fx_panel` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the Execution legend at 118 cells (its two-row allowance). Others N/A.

### LLR-148.8 — A chip opens only a real directory inside its family root
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.7
- **Statement:** When any open-folder chip in the app is pressed, the `OpenFolderChip` shall call the open seam only if its target — after any create-on-press — is a directory (`is_dir()`), `_path_traverses_reparse_point(target, stop_at=root.parent)` (`workspace.py:184`) is False and `target.resolve()` lies inside `root.resolve()`, `root` being the chip's family root (§1.3); otherwise it shall set an English refusal status naming the folder and make 0 seam calls. The trust anchor is the family root (§1.3) — with a project, the active project directory as the app holds it, resolved at load (`app.py:1861`, `:8200`, §2.7 P-58). The walk covers the root itself and every component below it, and stops at `root.parent`: a reparse point above the root is not this guard's, and a root that is itself a reparse point (the no-project `.s19tool`) is refused.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-57 — `pytest tests/test_b97_chips_help.py -k tc_b97_57`; procedure: appendix A.4 TC-B97-57.
- **Numeric pass threshold:** with the project opened through the app's own load: file → 0 calls + refusal; `flows` junction → 0 + refusal; real dir → 1 call; missing `flows` → created, guarded, 1 call; no-project `patch` → 1 call (root = the tool root); the 11 existing nodes of `tests/test_open_folder_chips.py` (P-59) stay green.
- **Negative control:** executed on `main` (§2.7 P-34, `open_folder_chip.py:118` checks only `exists()`): a junction passes `is_dir()` and `not is_symlink()` → the seam is called, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary: `flows` missing (created, then guarded); invalid: file, leaf junction; error: `lstat` raising (target vanished) → refusal, 0 calls. Empty: N/A — the no-project chip is LLR-148.3's.

### LLR-148.9 — Region states in one English line
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While a region of the table below is in a listed state, the panel shall paint in that region one English line naming the state, and no traceback.

| screen | region | states |
|---|---|---|
| Patch Editor | ledger · hex strip · JSON view · Checks tab | empty (no document / no image) · error (load refused: its finding) |
| Check Editor | parameter ledger · REPORT FIELDS card | empty (no A2L / nothing included) · error (write refused) |
| Flow Builder | pipeline · ribbon | empty (no blocks / no session) · error (load refused, NUL ref included) |
| Flow Execution | lanes · run log | empty (no lanes) · error (run raised; import or set load refused; a NUL ref bound to a lane refused at run, `MANIFEST-PATH-ESCAPE`) |

- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-58 — `pytest tests/test_b97_chips_help.py -k tc_b97_58`; procedure: appendix A.4 TC-B97-58.
- **Numeric pass threshold:** per arm exactly 1 painted state line, 0 `ES_MARKER` matches, 0 lines containing `Traceback`.
- **Negative control:** executed on `main`: the Flow Builder with no blocks shows no English empty line in a pipeline (no pipeline exists) → RED.
- **Boundary catalog:** ☒ empty ☐ boundary ☐ invalid ☒ error — empty and error: the table. Others N/A.

### LLR-148.10 — Folder chips are labelled with their folder
- **Traceability:** HLR-148
- **Ledger:** LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4, LED-2026-10-19-batch-97.6
- **Statement:** Every `OpenFolderChip` in the app shall carry the label `📂 Open <folder>/`, `<folder>` the name of the folder the chip's target resolves to — the family's folder-name constant (`patches`, `checks`, `templates`, `reports`, `flows`) with a project, and `patches` for the `checks` chip without a project, whose common home is `workarea/patches` — or `📂 Open session` for the `session` family. When a chip press opens a folder, the status line shall name its full path (`Opened … : <path>`, `folder_open_service.py:182`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-65 — `pytest tests/test_b97_chips_help.py -k tc_b97_65`; procedure: appendix A.4 TC-B97-65.
- **Numeric pass threshold:** 7 of 7 labels equal; 4 of 4 status lines end with `str(target)`.
- **Negative control:** executed on `main` (§2.7 P-46): every label reads `📂 Open folder` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the label inside the header at 118x54 (no overflow, LLR-149.2). Others N/A.

### LLR-149.1 — Widths derived at mount and on resize
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** When one of the four panels mounts or receives a resize, it shall derive its column widths, panel split, input widths and region heights from its current content size.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-34 — `pytest tests/test_b97_width.py -k tc_b97_34`; procedure: appendix A.4 TC-B97-34.
- **Numeric pass threshold:** each width non-decreasing along 118 → 160 → 220 → 260 and strictly greater at 220 than at 118; back at 118x54 equal to the first reading.
- **Negative control:** executed on `main` (§2.7 P-22): `#flow_ext_instruction` 28 at both sizes → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: four resizes in one session. Others N/A.

### LLR-149.2 — No horizontal overflow over the range
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While displayed at any width of at least 118 columns and height of at least 54 rows, on either side of the 120-column `width-narrow` breakpoint, each of the four panels shall keep every displayed descendant's clipped region (§1.3) inside the panel's region on the x axis.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-35 — `pytest tests/test_b97_width.py -k tc_b97_35`; procedure: appendix A.4 TC-B97-35.
- **Numeric pass threshold:** 0 on 24 of 24 screen×sample cells, each over ≥ 10 displayed descendants (guard); the class flips between 119 and 120.
- **Negative control:** executed on `main` (§2.7 P-10, P-52): 1/1/2/7 at 118x54 and 1/1/1/6 at 220x60 → RED, the same 1/1/2/7 under the clipped-region predicate (a non-scrolling ancestor clips nothing); executed on Textual 8.2.8: cards scrolled inside a `HorizontalScroll` count 4 under the region predicate and 0 under the clipped one, and a non-scrolling `Horizontal` counts 4 under both (P-52).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: 118, the 119↔120 breakpoint, 260; error: the widest real values (60-cell ref, 47-cell name, 40-cell set name).

### LLR-149.3 — Primary actions inside the viewport over the range
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** While displayed at any size of at least 118x54 with the panel scrolled to its top, each panel shall keep its primary actions inside the panel region: `#patch_doc_load_button`, `#patch_doc_save_button`, `#patch_doc_validate_button`, `#patch_doc_apply_button`; `#check_validate_button`, `#check_write_button`; `#flow_run`; `#fx_run`, `#fx_save`, `#fx_load`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-36 — `pytest tests/test_b97_width.py -k tc_b97_36`; procedure: appendix A.4 TC-B97-36.
- **Numeric pass threshold:** 10 of 10 inside at every sample.
- **Negative control:** executed on `main` (§2.7 P-11): `#flow_run (51, 48, 16, 3)` past the panel bottom 44, `#fx_save` and `#fx_load` outside → 7 of 10, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 118x54 with the EXT-STEP form open. Others N/A.

### LLR-149.4 — No wrapped row; truncation keeps the discriminating part
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3
- **Statement:** The four panels shall paint each logical row of their no-wrap set (§1.3) on exactly one terminal row, clipping with one ellipsis by element class — file names and paths keep the tail, labels, headings and commands keep the head, parameter names follow LLR-145.3, addresses are never clipped. No two painted rows of one ledger shall be equal unless their records are equal. The Check Editor's `Fmt · Unit` column shall show the parameter's width `u<bits>` and its A2L unit (`screens_directionb.py:7039`), the unit clipped before the width.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-37 — `pytest tests/test_b97_width.py -k tc_b97_37`; procedure: appendix A.4 TC-B97-37.
- **Numeric pass threshold:** 0 Statics whose content height ≠ line count; 0 over-wide cells painted without their class's ellipsis; 0 equal painted row pairs with different records (75-row parameter ledger, 6-entry patch ledger, lanes); per clipped cell, the kept end matches its class.
- **Negative control:** executed (§2.7 P-39): a `height: 1` Static carrying a 4-row line → content height 4 ≠ 1, RED; Textual's hard clip `' ASAM.M.SCALA '` has no ellipsis → RED; a 20-cell width forced on `#fx_log` (mutation, Phase 3) → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a log line exactly the panel width; error: the widest real values.

### LLR-149.5 — The space goes to the growing region: no width or height void
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.1, LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While displayed at any size of at least 118x54, the four panels shall give their adaptive elements — the Patch Editor ledger, the Check Editor parameter table, its Parameter column and the REPORT FIELDS name field, the Flow Builder pipeline cards and EXT-STEP inputs, the Flow Execution lane cards — the width their split assigns, cards growing from a 21-cell minimum, so that the void after each element's painted extent inside its content region is at most 2 cells unless no card line in that band is clipped, and shall give the height the docked rows leave to the screen's growing region, so that no blank row lies outside it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-38 — `pytest tests/test_b97_width.py -k tc_b97_38`; procedure: appendix A.4 TC-B97-38.
- **Numeric pass threshold:** every void ≤ 2, or > 2 with 0 clipped card lines in that band; card width ≥ 21; the 47-cell name in full at 220x60; 0 blank rows outside the growing region.
- **Negative control:** fixed 24-cell cards with a 60-cell ref at 220x60 (mutation, Phase 3) → a void > 2 beside a clipped line, RED; measuring over `region` instead of `content_region` reads 0 void on any bordered band (U2-5) — the predicate reads the content region; executed on `main` (§2.7 P-22, P-32): EXT-STEP inputs equal at both sizes, Patch 3 / 2 blank rows outside the ledger → RED. Check 0 / 0 is a regression **pin**; the Builder's base count is recorded by the Flow Builder increment's RED run.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 160x56 (off-grid), 260x70 (above the reference). Others N/A.

### LLR-149.6 — Below the range the four screens stay reachable under scroll
- **Traceability:** HLR-149
- **Ledger:** LED-2026-10-19-batch-97.2, LED-2026-10-19-batch-97.3, LED-2026-10-19-batch-97.4
- **Statement:** While displayed at a width below 118 or a height below 54, down to the shipped 80x24 floor, each of the four panels shall keep every LLR-149.3 action reachable from the keyboard — `tab` focuses it and scrolls it into view, `pagedown` scrolls the panel to it — without overlapping buttons.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-59 — `pytest tests/test_b97_width.py -k tc_b97_59`; procedure: appendix A.4 TC-B97-59.
- **Numeric pass threshold:** 10 of 10 reached by `tab` (≤ 200 presses) and inside the panel region once focused, at the three sizes; 10 of 10 inside the panel region after `pagedown` presses on the panel; 0 overlapping button pairs.
- **Negative control:** a panel with `overflow: hidden` (mutation, Phase 3) → an action unreachable, RED; on `main` (§2.7 P-10) `#fx_load` at x = 134 in a panel whose `max_scroll_x` reads 0 → unreachable, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 80x24 (the floor, LLR-007.1 / CV-04) and 220x40 (wide but short). Others N/A.

### LLR-150.1 — One window-key table feeds row 2 and the help
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** The `window_help` module shall hold the window-key table (NEW, I-10): for each of the 13 windows (§1.3) an ordered tuple of window-key entries and an ordered tuple of go keys, each entry naming a key bound either in `S19TuiApp.BINDINGS` or on a widget the entry names inside that window, with an optional state condition. Every token label shall be the description of the binding it names, resolved when the key bar mounts and never typed a second time, with exactly two painter literals named here: `more` (the `?` binding relabelled as the row-2 overflow tail) and `palette` (Textual's command-palette binding); an entry whose key resolves to no binding, or to a binding whose description is empty, shall raise at mount. Help sections map to windows by the help-key → window table (NEW, I-10): every help key equal to a window key maps to that window, `split_join_export` maps to `split_join`, and `reports` and `changes_file_notation` map to no window (`SHIPPED_WINDOW_KEYS`, `window_help.py:270-279`, holds `reports`, which is a modal, not a window). The help modal of every help section mapped to a window shall show, beneath its steps, a keys block (NEW) listing that window's entries as `key — description` lines generated from the same table; a section mapped to no window shows no keys block; `section_body_text` stays the steps alone.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-66 — `pytest tests/test_b97_key_bar.py -k tc_b97_66`; procedure: appendix A.4 TC-B97-66.
- **Numeric pass threshold:** the table's window set == `set(SCREEN_CONTAINER_IDS) | {"split_join"}` (13); 100 % of entries and go keys resolve to a binding, guard ≥ 15 entries and ≥ 9 go keys over the five windows the prototype round rendered (I-10 rows); for each help section mapped to a window (the mapping above), the keys block's `key — description` lines == the lines the table yields for that window, set-equal, and 0 of them repeated as a hand-typed step line; the Reports and the Split / Join / Export help modals open with 0 exceptions, Reports with no keys block and Split / Join / Export with `split_join`'s block; `section_body_text(key)` unchanged by the block (TC-707's numbered-steps census stays green); 0 label strings in the table and exactly the two painter literals `more` and `palette`; 0 resolved bindings with an empty description.
- **Negative control:** executed on `main` (§2.7 P-62): `window_help` holds no key table and no `check_editor` / `flow_execution` section → RED; an entry naming an unbound key, or a binding with an empty description (mutations) → the mount raises; a keys block typed by hand with a different label (mutation) → the set comparison RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: entries bound on a widget inside the window (`space` on `#check_param_table`, `c` on the Flow Execution section) and `split_join`, which has no rail key; invalid: an unbound key, an empty description (the mount raises); `reports` and `changes_file_notation`, help sections that map to no window. Others N/A.

### LLR-150.2 — Row 1: the global keys, fixed, with Help always painted
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** The key bar's first row shall paint, on every window and whatever widget holds the focus, the global tokens in this order — `^k Palette`, `^d Density`, `^l Load`, `^s Save`, `x Operations`, `? Help`, `q Quit`, `^p palette` (Textual's command palette, `S19TuiApp.COMMAND_PALETTE_BINDING`) — in the shipped footer colours (the theme variables `footer-key-foreground`, `footer-description-foreground`, `footer-background`); when the row is narrower than its tokens it shall drop whole tokens by the LLR-150.5 rule and never `? Help`; row 1 never paints `? more`, since `? Help` is always on it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-67 — `pytest tests/test_b97_key_bar.py -k tc_b97_67`; procedure: appendix A.4 TC-B97-67.
- **Numeric pass threshold:** 13 windows × the focus {on the rail, on the window's first control, in a text `Input`} × {118x54, 220x60}: the row-1 tokens == exactly the 8 in order and 0 `? more`; at 80x24 exactly the first 7 in order, `^p palette` absent and 0 `? more`; every key-glyph cell's foreground == `footer-key-foreground` (`#ffa62b` on the shipped theme, guard).
- **Negative control:** executed on `main` (§2.7 P-61, P-67): with the focus inside a `WindowSection` the Footer paints no `? Help` → RED; at 118x54 its row ends `perio▏` → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 80x24 (the 84-cell row is wider than 80); the focus in an `Input` and inside a `WindowSection`. Others N/A.

### LLR-150.3 — Row 2: the window tag, the window's keys, then its go keys
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** The key bar's second row shall paint the active window's title as a tag in the window-title pair of `.db-screen-title` (`styles.tcss:130-138`: foreground `$bg-base` `#0a0e1b` on background `$accent-calm` `#91abec`), in bold, then the window's entries in table order, then the go separator — ` · go` after window keys, ` go` when the window has none (the prototype's rule) — and the window's go keys, with key glyphs in the row-1 key colour, descriptions in `$accent-calm` `#91abec` and the row background the row-1 background (`footer-background`). Every colour shall come from component classes of the key-bar rows styled in `styles.tcss` through its `$` variables and read with `get_component_rich_style` (I-11); no hex value shall be written in Python. The tag text shall be the description of the window's rail binding (`Patch Editor`, `Check Editor`, …), and `Split / Join / Export` for `split_join`. When the active window changes, the second row shall show the new window's tag and tokens once the switch has settled, and after a modal screen (a help modal) is dismissed it shall show the window it showed before the modal opened.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-68 — `pytest tests/test_b97_key_bar.py -k tc_b97_68`; procedure: appendix A.4 TC-B97-68.
- **Numeric pass threshold:** 13 of 13 tags == the window's rail description; tag cells foreground `#0a0e1b` on background `#91abec`, every enabled description cell foreground `#91abec`, every key-glyph cell foreground == the row-1 key colour (read from the compositor strips, PC-7); the tag cells bold; the separator ` · go` on Patch / Check / Flow Execution and ` go` on Flow Builder; row-2 background == `footer-background`; 0 cells in `#e8ad3d`, `#c9562b` or `#f6ff8f` anywhere in the key bar; 0 hex literals in the key-bar code (AST scan for `#rrggbb` strings in `window_help.py`); after each rail key and one `pilot.pause()`, the new window's tag; after opening and dismissing the Patch Editor help modal, row 2 == its reading before the modal.
- **Negative control:** executed on `main`: no second row exists (one `Footer`, height 1) → RED; the tag painted in the description pair (mutation) → the foreground / background clause RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: the switch to Split / Join / Export (no rail key) and back; a window whose row 2 holds go keys only (Flow Builder). Others N/A.

### LLR-150.4 — A key the window does not handle is neither painted nor live; a key that cannot act now is dimmed
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** The key bar shall paint no token whose action has no effect on the active window. The `S19TuiApp` shall answer `check_action` (NEW override) `False` for `page_next_context` / `page_prev_context` (`+` / `-`) on every window but A2L and MAC, and for `hex_page_prev` / `hex_page_next` (`,` / `.`) on every window but Workspace, so that those keys do nothing there instead of paging the hidden hex view (§2.7 P-63). A window entry whose condition is false — Undo / Redo on a file-backed change-set (`_patch_history_action_allowed`, `app.py:3536`), Select variant with no variant set, Hex± and Unload all with no image loaded — shall be painted dimmed.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-69 — `pytest tests/test_b97_key_bar.py -k tc_b97_69`; procedure: appendix A.4 TC-B97-69.
- **Numeric pass threshold:** per window, the painted keys ⊆ its allowed set — a pin on the table, not the proof; the proof is behavioural: with an image and an A2L loaded, each of `,` `.` `+` `-` pressed on every window where it is disabled (11 windows for `, .`, 11 for `+ -`) leaves the Workspace hex window start, the A2L tag page and the MAC record page unchanged (0 of 44 presses change one), while `.` on Workspace advances the hex window by one page and `+` on A2L advances the tag page; each derived row of PC-26 carries the `file:line` of the guard it was read from inside the test's data, and the test asserts that line still holds the guard (a moved guard fails loud); dim arms: a file-backed document → `^z` / `^y` dimmed, a paste-authored one → lit; no variant set → `v` dimmed; no image → `,` `.` `U` dimmed; each flip painted after one `pilot.pause()` with no timer wait (PC-23).
- **Negative control:** executed on `main` (§2.7 P-63, P-64): `S19TuiApp` overrides no `check_action` and `action_hex_page_next` returns only off the `"main"` view, which the Patch Editor is, so `.` there advances the hidden view → RED; the Footer paints `+ Page+ - Page- , Hex-` on the four batch-97 screens → RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: Workspace with and without an image; the Patch Editor with a file-backed and a paste-authored document; invalid: `+` and `.` pressed where they are not handled. Others N/A.

### LLR-150.5 — Whole tokens only; an overflowing row ends with `? more`
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** Each row of the key bar shall paint whole tokens: when its tokens are wider than the row, the row shall first reserve the width of its mandatory parts — `? Help` on row 1; the tag and the `? more` tail on row 2 — and then keep the longest display-order prefix of the other tokens that fits in what is left (a prefix, never a greedy skip: no token shows while an earlier one is hidden), mandatory tokens keeping their display position; the second row then ends with `? more`, the `?` binding labelled `more`; no token shall be cut. The `.` key shall display as `.` (`key_display="."` on the `period` binding, NEW), never as `period`.
- **Validation:** `test (unit)` + `test (integration)`
- **Executed verification:** TC-B97-70 — `pytest tests/test_b97_key_bar.py -k tc_b97_70`; procedure: appendix A.4 TC-B97-70.
- **Numeric pass threshold:** every painted row of the 13 windows at 118x54, 220x60 and 80x24 parses into a sequence of known tokens with no remainder but padding; 0 occurrences of `perio`; Workspace at 118x54: row 2 ends `? more` and holds no `U Unload all`; 0 `? more` at 220x60; layer 0, `pack_key_row` over widths 20..240: painted cell length ≤ width, every kept token whole, the kept non-mandatory tokens a display-order prefix (0 gaps) and the mandatory ones present at every width ≥ their own width.
- **Negative control:** executed on `main` (§2.7 P-65, P-67): Textual displays the key as `period` and the Footer row at 118x54 ends `perio▏` → RED; a packer that crops at the width instead of dropping (mutation) → a partial token, RED; a greedy packer that skips a long token and keeps a later short one (mutation, the prototype's `pack`) → a gap, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a row exactly as wide as its tokens; 80x24. Others N/A.

### LLR-150.6 — The key bar replaces the Footer and costs exactly one row
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** The `S19TuiApp` shall mount the key bar (NEW, I-11) docked at the bottom with a height of 2 rows in place of the shipped `Footer` (`app.py:2077`), so that each window's container is exactly one row shorter than on `main` and nothing else in the shell moves; the four batch-97 screens shall keep LLR-149.3, LLR-149.5 and LLR-149.6 with the key bar mounted.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-71 — `pytest tests/test_b97_key_bar.py -k tc_b97_71`; procedure: appendix A.4 TC-B97-71.
- **Numeric pass threshold:** `app.query(Footer)` empty; the key bar's region height 2 and `y` == terminal height − 2; each of the 13 windows' container rows == its `main` reading − 1 at 118x54 and 220x60 (`main` 42 at 118x54, P-68); LLR-149.3 10 of 10, LLR-149.5's blank-row clause and LLR-149.6 at 80x24 hold with the key bar (re-run in the Inc-7 sweep).
- **Negative control:** executed on `main` (§2.7 P-68): one `Footer` of height 1 and container rows 42 at 118x54 → the height and row clauses RED; a key bar of height 3 (mutation) → container rows `main` − 2, RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: 80x24 (the floor); 220x60. Others N/A.

### LLR-150.7 — A click on a token runs its key
- **Traceability:** HLR-150
- **Ledger:** LED-2026-10-19-batch-97.9, LED-2026-10-19-batch-97.10
- **Statement:** When the engineer clicks an enabled token of either row, the key bar shall run that token's binding action in the binding's own namespace, never by simulating the key: for an entry with no `owner`, `app.run_action(action)` in the app's namespace, which honours `S19TuiApp.check_action` (`textual/app.py:4223-4248`); for an entry with an `owner` selector, the action run on the widget that selector resolves inside the active window (`widget.run_action(action)`). Whatever holds the focus — a text input, a tab chip, a button — shall neither receive the key nor change. A click on `? Help` (or `? more`) shall run the app binding `show_help_panel`, the stock help panel listing every binding, whatever the focus; pressing `?` keeps its focus-dependent meaning (inside a `WindowSection`, that window's help, `window_help.py:449`). A click on a dimmed token shall ring the bell and run nothing, and a click on the tag, a separator or the padding shall run nothing.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B97-72 — `pytest tests/test_b97_key_bar.py -k tc_b97_72`; procedure: appendix A.4 TC-B97-72.
- **Numeric pass threshold:** a click on `space Include` on the Check Editor with the focus on a card tab chip → the active card tab unchanged and the highlighted parameter's include toggled (count ±1); a click on `c Confirm` on Flow Execution with the focus in `#fx_bind_<i>_<j>` → that input's value unchanged and the attention lane confirmed (1 re-run); a click on `q` and on `9` with a text `Input` focused → the action runs (the quit request is observed through a spy on `action_quit`; the Checks window shown) and the input's value unchanged (0 characters typed); a click on `? Help` with the focus inside the Patch Editor's section → the stock help panel, not the window-help modal; on the dimmed `^z Undo` (file-backed document) → the document and the active window unchanged and one bell; on the tag → the active window unchanged; per token, its hit range == its painted cells.
- **Negative control:** a click implemented as `app.simulate_key(key)` (mutation, the prototype's and the Footer's path, P-66) → `space` reaches the focused tab chip and presses it, `c` and `q` type into the focused input → RED; hit ranges offset by the tag's width (mutation) → the click on `9 Checks` runs the neighbouring token → RED; dimmed tokens clickable (mutation) → the Undo arm RED.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary: the last cell of one token beside the first cell of the next; a click with the focus in a text input, on a tab chip and inside a `WindowSection`; an `owner` entry (`space`, `c`) vs an app entry (`q`, `9`, `?`); invalid: a dimmed token, the tag. Others N/A.

### Information Flow Contract (IFC) — C-54

> Part A — one FLOW block per information flow this batch adds or re-routes; every node has exactly one owner LLR. LLRs that state structure rather than a transform own Part B outputs or are verified on the painted layout instead of owning nodes. Part B — the trigger question is answered **yes**: the four panels and their header chips are components a consumer addresses independently. Component ids are new (V19).

- **Part A — flows:**

```
FLOW: change_doc_to_json_view
  SOURCE : a v2 change-set loaded by the Patch Editor's Load, any of the nine document writers (§2.7 P-6), or any of the panel's four dirty-flag writers (P-48, P-57)
  NODES  :
    - fn    : the ChangeService writers of the document (change_service.py:861, :893, :1080, :1154, :1196, :1223, :1344, :1404, :1465)
      owner : LLR-144.6
      in    : the entry action or the loaded file
      out   : the changed ChangeDocument
    - fn    : serialize_change_document (changes/io.py:1392)
      owner : LLR-144.5
      in    : ChangeDocument
      out   : canonical v2 JSON text (706 bytes, 39 lines for the fixture)
    - fn    : app-to-panel feed at the refresh_entries sites (I-3, NEW) into the read-only view, capped at JSON_TAB_LINE_CAP lines + note
      owner : LLR-144.5
      in    : canonical v2 JSON text
      out   : the view's text (first 5000 lines + "showing 5000 of M lines" when longer)
    - fn    : the panel's dirty-flag writers (screens_directionb.py:5707, :5771, :5953, :5964), each followed by _refresh_dirty_indicator
      owner : LLR-144.6
      in    : paste-buffer typing, an entry Add / Edit / Remove, Save (mark_saved), Load (mark_loaded)
      out   : the dirty flag
    - fn    : stamp composition — entry count, refresh time, dirty flag (NEW), re-run on every document write and every dirty-flag change
      owner : LLR-144.6
      in    : ChangeDocument + the panel's dirty flag
      out   : "N entries · HH:MM:SS · saved|unsaved changes"
  SINK   : #patch_json_view and its stamp, read by the engineer
```

```
FLOW: document_identity_to_ribbon
  SOURCE : ChangeDocument.source_path and .kind (changes/model.py:253, :258)
  NODES  :
    - fn    : identity feed through refresh_entries keyword or setter (I-2, NEW)
      owner : LLR-144.7
      in    : Optional[Path], str
      out   : name + kind strings
    - fn    : safe_text render (utils.py:44) of the name, kind and every file-derived entry field
      owner : LLR-144.7
      in    : name, kind, entry value / symbol / address text, finding messages
      out   : rich Text with no markup parsed
  SINK   : the identity ribbon (NEW), the ledger, the inspector pane, the JSON view, #patch_doc_issues
```

```
FLOW: highlighted_row_to_hex_strip
  SOURCE : the ledger's highlighted row (DataTable cursor) + the loaded image
  NODES  :
    - fn    : before/after byte read for the highlighted entry, changed bytes marked with a text attribute (NEW)
      owner : LLR-144.8
      in    : ChangeEntry (address, encoded bytes) + image bytes at that address
      out   : hex strip Text
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
    - fn    : name clipping — first segment + ellipsis + tail in the ledger, ellipsis + tail on Fields lines
      owner : LLR-145.3
      in    : parameter name + field width (≥ 42 / ≥ 24)
      out   : painted name
    - fn    : REPORT FIELDS composition — Fields lines, capped JSON spec, Addendum preview (NEW layout over the shipped collector)
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
    - fn    : card text clipping by element class
      owner : LLR-146.4
      in    : card title and IO lines
      out   : lines no wider than the card
    - fn    : CRC card paint with the CRC token #c9562b (NEW)
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
FLOW: ref_text_to_load_guard
  SOURCE : a flow file, a chain-set file or a project manifest read from disk, or a lane input bound through #fx_bind_<i>_<j>
  NODES  :
    - fn    : NUL test on the eight path-bearing block fields in load_flow_json (flow_persistence_service.py:868), FLOW-UNSAFE-REF; its stat() guard catches ValueError and OSError
      owner : LLR-146.14
      in    : block field strings
      out   : the flow, or None + one finding
    - fn    : NUL test on template and input refs in load_chain_set (:1452) / _is_plain_template_stem (:1147), CHAIN-SET-UNSAFE-REF
      owner : LLR-146.14
      in    : chain-set entries
      out   : the set, or None + one finding
    - fn    : NUL test in _resolve_manifest_entry (variant_execution_service.py:205, resolve at :273), MANIFEST-PATH-ESCAPE
      owner : LLR-146.14
      in    : manifest entry text or bound lane-input text
      out   : the resolved path, or None + one finding
  SINK   : the Builder / Execution region-state line (LLR-148.9) and the run's findings
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
    - fn    : paused-lane paint, pending lines, REQUIRED line naming the attention lane's chain, scroll-into-view on both axes (a focused widget in the lanes kept in view), attention class (focus untouched)
      owner : LLR-147.3
      in    : waiting block index per lane
      out   : waiting-styled card + the attention lane's #fx_confirm_<i> in view and highlighted
    - fn    : lane-header worst-status mark from the LLR-147.1 vocabulary (NEW)
      owner : LLR-147.12
      in    : record.outcomes[i].block_results statuses
      out   : one glyph per lane header
    - fn    : waiting-colour assignment restricted to waiting-human elements
      owner : LLR-147.7
      in    : element kind
      out   : span colour
    - fn    : external-step summaries and diagnostics (flow_execution_service.py:501, :840-:846, :860, :867, :885) and run-log lines in English
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
FLOW: flowset_listing_to_set_picker
  SOURCE : list_chain_sets (flow_persistence_service.py:1495) — the stems of flowsets/*.json
  NODES  :
    - fn    : set_available_sets option prompts as safe_text Text (flow_screens.py:2566)
      owner : LLR-147.6
      in    : file stems
      out   : literal option prompts
  SINK   : #fx_set_select
```

```
FLOW: run_press_to_single_run
  SOURCE : a #fx_run press (click or key)
  NODES  :
    - fn    : in-flight guard — #fx_run disabled for the run's duration, re-enabled when it ends or raises (NEW)
      owner : LLR-147.10
      in    : press + in-flight state
      out   : 0 or 1 run
  SINK   : on_flow_execution_panel_run_requested (app.py:2776) → reports/<ts>-chain-set-report.md
```

```
FLOW: confirm_key_to_rerun
  SOURCE : a `c` key press on the Flow Execution screen
  NODES  :
    - fn    : attention-lane lookup; confirm only with the focus outside a text input, once per waiting entry, after CONFIRM_DWELL_S of attention; the same confirmation a #fx_confirm_<i> press posts (NEW)
      owner : LLR-147.13
      in    : the attention lane, its waiting entry, its confirm state and attention time
      out   : one ExternalStepConfirmed for the attention lane, or nothing
  SINK   : on_flow_execution_panel_external_step_confirmed (app.py:2823, the shipped re-run handler)
```

```
FLOW: project_dir_to_folder_chip
  SOURCE : S19TuiApp.active_project_dir() (Path or None), resolved at load (app.py:1861, :8200) — the guard's trust anchor
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
    - fn    : chip label from the family's folder-name constant (NEW)
      owner : LLR-148.10
      in    : family
      out   : "📂 Open <folder>/" or "📂 Open session"
    - fn    : real-directory guard, after any create-on-press — is_dir, no reparse point up to the family root (workspace.py:184), inside the root (NEW)
      owner : LLR-148.8
      in    : resolved target + family root
      out   : the target, or a refusal status
    - fn    : OpenFolderChip._open_target to the open seam (open_folder_chip.py:139)
      owner : LLR-148.5
      in    : guarded target
      out   : one open call + "Opened … : <path>"
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
FLOW: renderer_vocabulary_to_legend
  SOURCE : the closed glyph vocabulary constant of each renderer (NEW)
  NODES  :
    - fn    : legend composition — status and mark glyphs with one meaning each, at most two rows (NEW)
      owner : LLR-148.7
      in    : vocabulary constants
      out   : legend text
  SINK   : each panel's legend (NEW id)
```

```
FLOW: terminal_size_to_layout
  SOURCE : the terminal size at mount and on each Resize event
  NODES  :
    - fn    : per-panel width and height derivation (NEW, on mount and on_resize)
      owner : LLR-149.1
      in    : panel content size
      out   : column widths, split, input widths, card widths, growing-region height
    - fn    : ellipsis clipping by element class
      owner : LLR-149.4
      in    : row text + its width
      out   : one painted row per logical row
  SINK   : the painted layout of the four panels
```

```
FLOW: active_window_to_key_bar
  SOURCE : the active window key (`_active_screen_key`, `app.py:1505`), the focus, and the state conditions of the window-key table
  NODES  :
    - fn    : window-key table lookup and binding resolution at mount; labels are the bindings' descriptions (NEW, I-10)
      owner : LLR-150.1
      in    : window key + S19TuiApp.BINDINGS + the bindings of the widget an entry names
      out   : the window's ordered window tokens and go tokens
    - fn    : global row composition in the theme's footer colours (NEW)
      owner : LLR-150.2
      in    : GLOBAL_KEYS + COMMAND_PALETTE_BINDING
      out   : row-1 tokens
    - fn    : window row composition: tag in the .db-screen-title pair, window tokens, go tokens (NEW)
      owner : LLR-150.3
      in    : window tokens + go tokens + the rail binding's description
      out   : row-2 tokens
    - fn    : handled-key filter and state dimming; S19TuiApp.check_action (NEW)
      owner : LLR-150.4
      in    : action + active window + table conditions
      out   : each token painted, dimmed or absent; the key live or inert
    - fn    : whole-token packing with "? more" (NEW, pack_key_row)
      owner : LLR-150.5
      in    : tokens + row width
      out   : painted row text + one hit range per kept token
    - fn    : click hit-test to app.simulate_key (NEW)
      owner : LLR-150.7
      in    : click x + hit ranges
      out   : one simulated key, or a bell
  SINK   : the key bar's two painted rows and the action the key runs
```

- **Part B — boundary decomposition:** yes — the TUI panels are components a consumer addresses on their own. Parent: `workspace_shell` (`docs/architecture.md` §11), not itself a COMPONENT anywhere in the corpus, so `V12` reports *could not be tested* (the batch-87/94 precedent, a NOTICE). Addresses marked COMPUTED are built at runtime (`f"#fx_confirm_{i}"`, `f"open_folder_{family}"`, `f"window_help_{key}"`); their consumers were measured with `grep -rl` over `s19_app/` and `tests/` (2026-10-20).

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
      value       : the JSON tab pane holding the read-only view, the paste area and the editing rows
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
      owner       : LLR-144.12
    - id          : json_view
      value       : the document the editor holds, as canonical v2 JSON, read-only
      address     : query("#patch_json_view")
      cardinality : 1
      consumers   : none
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
      value       : the docked Write .chk.json action, the one filled element
      address     : query("#check_write_button")
      cardinality : 1
      consumers   : s19_app/tui/screens_directionb.py
                    tests/test_tui_check_chain_b94.py
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
      consumers   : s19_app/tui/flow_screens.py
                    tests/test_flow_external_step_b96.py
                    tests/test_tui_flow_builder_b94.py
      owner       : LLR-146.2
    - id          : run_action
      value       : the Run chip, the only primary button, single-image scope
      address     : query("#flow_run")
      cardinality : 1
      consumers   : s19_app/tui/app.py
                    s19_app/tui/flow_screens.py
                    tests/test_flow_builder_render.py
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
      value       : the waiting lane's Confirm, inside its lane, highlighted, not focused
      address     : query("#fx_confirm_<i>") COMPUTED
      cardinality : 1 per waiting lane
      consumers   : s19_app/tui/flow_screens.py
                    tests/test_flow_external_step_b96.py
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
      value       : the open-folder chip of the screen's family, labelled with its folder
      address     : query("#open_folder_<family>") COMPUTED
      cardinality : exactly 1 widget per id
      consumers   : s19_app/tui/app.py
                    s19_app/tui/open_folder_chip.py
                    s19_app/tui/screens.py
                    s19_app/tui/segment_split_view.py
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
      consumers   : s19_app/tui/window_help.py
                    tests/test_window_usage_help.py
                    tests/test_segment_split_window.py
      owner       : LLR-148.6
    - id          : glyph_legend
      value       : the legend of the screen's status and mark glyph vocabularies, at most two rows
      address     : query(".glyph-legend")
      cardinality : 1 per panel
      consumers   : none
      owner       : LLR-148.7
```

```
COMPONENT: bottom_key_bar
  PARENT : workspace_shell
  SURFACE: the bottom two rows of every window (replaces the shipped Footer, app.py:2077)
  INPUTS : active_window: str ; focus: Widget ; window_key_table: Mapping[str, WindowKeys]
  OUTPUTS:
    - id          : key_bar
      value       : the two-row key bar docked at the bottom, height 2
      address     : query("#key_bar")
      cardinality : exactly 1
      consumers   : none
      owner       : LLR-150.6
```

> `consumers : none` is written where no file reaches the address today because the address is NEW (`#patch_json_view`, `#patch_identity_ribbon`, `#flow_pipeline`, `.glyph-legend` — working names fixed at PDR). The defining modules are declared as consumers (they query or build their own ids and break if the address moves); a docstring that names an id is a mention, not a dependant (`screens.py:331` and `change_service.py:1237` name `#patch_doc_entries_table` in prose only); `REQUIREMENTS.md` and `.fast-dev-flow/archive/…` reach addresses as prose mentions; `prototypes/**` is never imported (the ARQ boundary) and is not declared. The batch's ATs/TCs become consumers in Phase 3 and the Phase-4 record re-runs `V13`/`V14`.

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-B97-01` … `TC-B97-72`):** one TC per LLR, validating the mechanism. Methods: `test (unit)` / `test (integration)` under `App.run_test` (Textual 8.2.8, pytest — `pyproject.toml:66-73`). A TC may read internal state; an AT may not.
> - **Layer B — black-box / behavioral acceptance (`AT-B97-01` … `AT-B97-26`):** at least two per story, driving the shipped controls only (`pilot.click` / `pilot.press` on shipped ids, Load / Import / Run / chip presses, `pilot.resize_terminal`, a new `S19TuiApp` on the same `tmp_path` for a restart; never a panel method such as `add_lane`, never a wrapped service — the OS-boundary open seam spied by `SeamSpy` excepted, §3 preamble) and observing only the shipped surface: painted text, regions and spans (C-32: `region`, `_render_line`, compositor strips, `render().spans`), files on disk (`reports/*-chain-set-report.md` and its `- **Mode:**` line, written images, saved sets and specs), the status line. C-42: parse the emitted JSON / Text / report, never substring-match the readable form.

- **C-10 (one AT per policy branch, a non-default value driven through the real control):** JSON view after Load (AT-B97-01) vs after Add (AT-B97-02); Address at 118 vs 220 and include changing the count (AT-B97-04); Fields / JSON / Addendum tabs (AT-B97-21); palette kinds, one arm per kind (AT-B97-07); `sequential` default vs `parallel` chosen in the mode control and read from the report, and a rebound SOURCE input (AT-B97-22); chip with project (AT-B97-12) vs without (AT-B97-13); 118x54 (AT-B97-15) vs resize to 260x70 (AT-B97-16) vs 119↔120, 80x24 and 220x40 (AT-B97-24); mouse (AT-B97-01..16) vs keyboard only (AT-B97-17..20); the key bar at 118x54 vs 220x60 vs 80x24, a file-backed vs a paste-authored change-set (dimmed vs lit Undo), a click (AT-B97-25) vs a key press on a window that does not handle the key (AT-B97-26).
- **C-12 (a produced artifact consumed):** Save Set writes the set file and Load Set in a new app restores it (AT-B97-10); Write .chk.json parsed and equal to the card (AT-B97-21); the chain-set report parsed for its mode (AT-B97-22); the JSON view consumes the serialiser's output (AT-B97-01).
- **C-16:** n/a — the prototypes are Textual monkeypatches over the shipped app, the target's technology (brief §2), and trigger D2 did not fire; the ATs drive the real mechanism, keyboard included.
- **C-17:** LLR-144.7, 145.5, 146.8, 147.6 with AT-B97-03, -05, -08, -11; the payload is split by what the surface can carry (A.2): `HOSTILE_NAME` through real file names and the EXT-STEP `output_path`, `HOSTILE_CONTENT` (+ `HOSTILE_C1` where admitted) through file content; NUL through LLR-146.14's refusal arms.
- **C-36:** every quoted value an AT or LLR keys on is a defined constant (`FLOW_SCOPE_SINGLE`, `CHAIN_RUN_PARALLEL` = `parallel`, `FLOW-UNSAFE-REF`, `CHAIN-SET-UNSAFE-REF`, `MANIFEST-PATH-ESCAPE`, `ISSUES` in `_FLOW_STATUS_BANNER` `flow_screens.py:229`) or is marked NEW (`◇`, the REQUIRED line, the stamp, the chip labels, the tokens).
- **C-40:** every NEW predicate's RED counterfactual is executed in its increment (`**RED counterfactual**` field); the ones already RED on `main` or executed on a model are stated per LLR; LLR-147.2's runs on the Flow Execution increment's own tree.
- **Visual half — inspected, not exercised:** the hue claims (LLR-146.6, 147.7), the hex strip's colour, the attention highlight and "reads as one object" are judged by the operator on the 24-bit captures (`prototypes/b94_polish/png/impl.*`); the tests exercise the token, span and hue-distance halves.
- **Captures:** each increment re-captures its screen at 118x54 and 220x60 into `prototypes/b94_polish/png/impl.*` for the operator's side-by-side judgement (brief §4.7) — a `demo`, auxiliary to the ATs; the notices yellow is re-judged there (§6.3).

### 5.2 Batch acceptance criteria
- 100 % of the 72 LLRs covered by their TC with a pass result; 26 of 26 ATs pass; every story has ≥ 2 ATs with boundary and negative evidence.
- 0 blocker fails at Phase 4; the full guard host `tests/test_tui_directionb.py` green at every render increment (C-34).
- Every superseded shipped node of §6.3 retired or rewritten through the ledger in its owning increment; the 14 Spanish pin lines (P-17) rewritten to English, not deleted.
- No requirement without a validation method; the operator judges the captures on the review page before the batch closes.

### 5.3 Literals, fixtures and the per-AT table

**Committed literals** (Phase 3, `tests/b97_fixtures.py`, NEW): `ES_MARKER`, `ES_48_9C7BEAF`, `HOSTILE_NAME`, `HOSTILE_CONTENT`, `HOSTILE_C1`, `HOSTILE_NUL`, `PE_IDS_9C7BEAF`, `CE_IDS_9C7BEAF` — their values are appendix A.2, copied verbatim.

**Fixtures and the per-AT table** — appendix A.5 holds the fixture table (every project under `tmp_path/.s19tool/workarea/<name>`; binaries and `crc.json` copied from tracked examples; every JSON generated per test with the current serialiser; outcomes executed in P-31 and P-41) and the per-AT table (fixture · driver · assertion · RED arm for AT-B97-01..24). Each AT's normative threshold is its HLR's *Numeric pass threshold*; the table is the test design that meets it, with drivers limited to shipped controls and observations limited to the shipped surface (§5.1).

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3; the bulk evidence is `01-requirements-appendix.md`.

### 6.2 Relevant design decisions
Decided at ARQ (`docs/architecture.md`, batch-97 section): R13 in-place re-composition, R14 project-only chip families, R15 `FLOWS_SUBDIR` imported, R16 the tokens in `insight_style.py`, R17 the canonical serialiser feeds the JSON view.

**Decided by the operator (2026-10-20, LED-…97.3), written into the requirements:** the colour pair `#e8ad3d` / `#c9562b` (LLR-146.6, 147.7); the primary actions Save / Write / Run / Run (LLR-144.11, 145.9, 146.5, 147.9); multi-variant runs as one chain per variant in Flow Execution, `#flow_scope` out of the Builder (LLR-146.12); the JSON view live with a stamp, read-only, no button, the paste area editable (LLR-144.5, 144.6, 144.12).

**Decided under the standing authorization, revisable at PDR:** cards grow from 21 cells with the clipped-line void rule (LLR-149.5); Confirm highlighted and scrolled into view, not focused, with the `c` key (LLR-147.3, 147.13); chip labels name their folder (LLR-148.10); `░` after a waiting block (LLR-147.1); runs on the UI thread with the freeze declared OUT (§2.4, §2.6, LLR-147.10); lanes scroll horizontally (LLR-147.12); the grid canvas not displayed (LLR-146.1); `JSON_TAB_LINE_CAP = 5000` (LLR-144.5, 145.6); the Fields line keeps the tail (LLR-145.3, from P-38); the `c` key confirms the attention lane once per waiting entry after `CONFIRM_DWELL_S = 0.5` s, a stray `enter` on Run re-runs the set and confirms nothing, and a focused widget in the lanes stays in view (LLR-147.3, 147.13, P-60); the lane-header worst-status mark (LLR-147.12); the full-name line under the Check ledger (LLR-145.3); the chip guard's trust anchor is the resolved project directory (LLR-148.8, P-58).

**Deferred to PDR (implementation shape only; every requirement holds for any choice):**
1. I-2 / I-3 call shape: a `refresh_entries` keyword with the `mem_map` sentinel idiom, or a setter (LLR-144.5, 144.7).
2. The Check Editor chip id scheme — scoping or a suffix (LLR-148.4; ARQ open question 1).
3. *Settled in LED-…97.4:* create-on-press for `flows` is the shipped families' path (`open_folder_chip.py:160-172`, `create_chip_home`, P-59), inside the project only (LLR-148.1), the LLR-148.8 guard running after the create; `session` never creates (LLR-148.2).
4. The two new help keys' names, and whether Flow Execution becomes a `WindowSection` (LLR-148.6).
5. Final names of every NEW id, class and constant (`#patch_json_view`, the stamp, tab chips, `#flow_pipeline`, legends, the filled / selection / attention classes, the tokens, the vocabulary constants), the no-wrap set's ids per category (LLR-149.4), the hex strip's text attribute (LLR-144.8).
6. The increment re-cut (02-review A-14): Flow Execution carries `flow_execution_service.py`, R16 adds `insight_style.py` to Inc 3/4, and LLR-146.14 adds `flow_persistence_service.py` and `variant_execution_service.py` to the Flow Builder increment.
7. The hex strip: reuse the shipped `#patch_before_after_card` or replace it (02-review A2-14).
8. One meaning per glyph for `✓` and `▼` in lanes and header (02-review U2-11).
9. The app's Builder variant branch (`app.py:2586-2609`): deleted, or left unreachable from the Builder (LLR-146.12 holds either way).

### 6.3 Open risks
- **Security pattern scan:** `devflow-scan-spec.py` over this file at each amendment (verdict in the ledger). Standing answers: **`token`** — a design (colour) token in `insight_style.py`, not a credential. **`session`** — the flow session directory (the active project dir), not an auth session; its chip only opens that folder through the existing seam, never creates one (LLR-148.2), and only when it is a real directory reached through no reparse point (LLR-148.8). **`user input`** / **`form`** — the add form and the set-name / rebind inputs keep their shipped validation (batch-94/96: containment of refs, the EXT-STEP log/output refusal, `save_flow_json` → `sanitize_project_name`, `flow_persistence_service.py:970`); this batch adds no write path; every file-derived string they echo is covered by the C-17 LLRs and NUL refs by LLR-146.14. **`escape`** — `MANIFEST-PATH-ESCAPE` is the shipped containment refusal (`variant_execution_service.py:106`) that LLR-146.14 reuses for a NUL manifest entry, which tightens containment rather than opening a path; the other uses are markup escaping under C-17. No escape from the project directory or the work area is added. **`permission`** — `PermissionError` is the operating system's refusal that the Check Editor's Write arm provokes at its staging path (a directory or a read-only file there, §2.7 P-51) to exercise the shipped `MF-WRITE-CONTAINMENT` refusal; the batch grants, changes or checks no permission.
- **C-17:** the control is the per-surface hostile ATs (AT-B97-03, -05, -08, -11), not a source scan: the guard host's scan (`tests/test_tui_directionb.py:8231`) cannot see an implicit sink (a `Static(str)`, a `Button` label, a `DataTable` cell or a `Select` prompt given a `str` — P-37 is one). `safe_text` does not cover bidi / zero-width controls (`BACKLOG-CODE.md:1394`).
- **Chip trust anchor:** the guard walks from the target up to the active project directory as the app resolved it at load (P-58); a project directory that is itself a reparse point in the work area is resolved — trusted — at load, outside this guard. The hand-built project-junction arm is dropped because the app never holds an unresolved project path; the real-load arm stays (TC-B97-57).
- **Check Editor Fields name at 24 cells (118 wide):** a tail-kept name loses the leading `ASAM.M.` / `ASAM.C.` class segment, so two Fields lines of the same address can differ only there; the six `0x13A00` names stay distinct (P-38), the full-name line shows the highlighted row's whole name, and the Fields name grows at wider sizes (LLR-145.3, 149.5). Residual: two included M/C twins read alike at 118 until highlighted.
- **The `c` dwell:** a deliberate second `c` within 0.5 s of the attention landing confirms nothing; the engineer presses again (the REQUIRED line still names the chain).
- **The `session` chip opens the project directory itself** — a wider folder than any other chip opens; same seam, one call per press, no shell string, real-directory guard.
- **App-wide chip change:** the reparse-point guard and the folder labels apply to all 7 chip instances (`templates` and `reports` included, P-46); the 11 nodes of `tests/test_open_folder_chips.py` (P-59) use real directories and stay green.
- **Operator note — the notices yellow `#f6ff8f`:** kept, with the operator's reservation ("Sólo el de aviso no me convence al 100% pero al mismo tiempo dudo que haya un mejor candidato") — re-judged on the implementation captures; a change of value stays ≥ 20° from `#e8ad3d` (LLR-147.7) and is a ledger amendment, not a silent edit.
- **A palette colour 5.0° from the waiting hue** (`#d9a35b`, P-40) paints on `AbDiffPanel`, the MAC out-of-range labels and `.band-medium` — outside the four panels, so LLR-147.7 holds; it is a finding for the all-screens review.
- **Multi-variant runs:** the Builder's scope selector is retired with the operator's consent; **LLR-104.6 (batch-70, "the scope is selectable and wired through the ONE run call site") is RETIRED for the Builder**. Multi-variant work runs as one chain per variant in Flow Execution (AT-B97-22); `run_flow_over_variants` and its `test_d4_*` service nodes stay.
- **UI-thread runs (declared OUT):** a run freezes the UI for its duration — 0.021 s median for the demo set (P-42); a large image or many lanes may freeze it visibly; a worker is backlog material, not this batch.
- **Carried to Phase 3 (not P1's to fix):** `tests/test_id_registry.py:124` `EXPECTED_SCANNED_TEST_FILES = 189` is exact — every test-adding increment bumps it (Q-14); the two `patch` snapshot cells are `xfail(strict=False)`, so the C-22 bound cannot go RED — tie it to a regen or mark the cells in the Patch Editor increment (Q-18); the `Size` label vs `Fmt` column term (02-review U2-15); the increment re-cut (A-14, §6.2 item 6).
- **Superseded shipped nodes (C-26, re-run over all 65 LLRs on `0f21e00`)** — each retired or rewritten through the ledger in its owning increment:

| shipped node | superseded by | increment |
|---|---|---|
| `tests/test_tui_check_editor.py` button height 3 | LLR-145.4 | Check Editor |
| `tests/test_window_usage_help.py:250` `SHIPPED_WINDOW_KEYS`, `_EXPECTED_KEYS` (`:95-107`), `tests/test_changes_file_notation_help.py` `_EXPECTED_KEYS` | LLR-148.6 | Check Editor (check key), Flow Execution (execution key) |
| `tests/test_open_folder_chips.py:94-98` `_RAIL_CHIPS` / id scheme | LLR-148.4 | Check Editor |
| `tests/test_tui_patch_layout.py` (9 tests, 7 at 80x24) | LLR-144.2, 144.3, 149.6 | Patch Editor |
| `tests/test_tui_patch_chips.py` (E-3 grid rules) | LLR-144.4 | Patch Editor |
| the 24 Patch Editor test files reaching the 66 ids — kept green by LLR-144.1; only layout assertions move; `tests/test_tui_patch_json.py` / `test_tui_patch_history_strip.py` keep the paste area editable (LLR-144.12) | LLR-144.1, 144.12 | Patch Editor |
| `tests/test_flow_funnel_b96.py:330` `"Funnel (1)"` | LLR-146.10 | Flow Builder |
| `tests/test_tui_flow_builder_b94.py:144-159, 241, 371, 436-454` (AT-B94-15..18: painted canvas, palette, canvas region) | LLR-146.1, 146.2 | Flow Builder |
| `tests/test_flow_external_step_b96.py:404` (canvas displayed) | LLR-146.1 | Flow Builder |
| `tests/test_flow_external_step_b96.py:387` (`#flow_ext_session` read), `:425` (`"sesión:"`) | LLR-146.11, 146.7 | Flow Builder |
| `tests/test_flow_multi_image_ui.py:150` (`_SCOPE_OPTIONS`), `:185`, `:215`, `:251`, `:271` (drive `#flow_scope`) — retired with LLR-104.6 for the Builder; `:234` rewritten to press Run without the selector; `:156` kept | LLR-146.12 | Flow Builder |
| Spanish pins `test_flow_external_step_b96.py:422, 425`, `test_flow_funnel_b96.py:331, 475, 477` | LLR-146.7 | Flow Builder |
| `tests/test_tui_flow_execution_b94.py:277` AT-B94-19, asserts `:345-348` (`"source → patch → write_out"`, `"tpl base"`, `"in1 base.s19"` in the lane paint) | LLR-147.1, 147.2 | Flow Execution |
| `tests/test_tui_flow_execution_b94.py:363` TC-B94-26, asserts `:451-454` (`▓`/`░` status-bar region, `"in1" … "base.s19"`) | LLR-147.1, 147.2 | Flow Execution |
| `tests/test_tui_flow_execution_b94.py:626, 693` (`#fx_mode` read as a `Select`) | LLR-147.4 | Flow Execution |
| Spanish pins `test_flow_external_step_b96.py:265, 266, 302, 333, 345, 507, 508, 509, 514` | LLR-147.5 | Flow Execution |
| 80x24 runs in 17 patch/check/flow test files (P-35) | not superseded — LLR-149.6 keeps them reachable; layout-asserting ones re-baselined with their screen | each screen's increment |
| LLR-146.14, 147.12, 147.13, 148.10 | 0 shipped nodes (NUL: no test feeds a NUL ref; `c`: unbound; the label: pinned by no assertion, P-46) | — |
| `tests/test_tui_diff_screen.py:3692` AT-B78-28 clause 3 — the 14 shown keys `_B79_COMMITTED_SHOWN_KEYS` (`:3590-3606`) by set-equality on the diff window (P-69) | LLR-150.4 (`+ - , .` leave the diff window's live set), LLR-150.6 (the painted bar replaces the Footer's set); clauses 1-2 (the run-list keys in the help panel) kept | Inc-8 |
| `tests/test_tui_directionb.py:6910` `test_tc030_global_footer_set_present_on_every_screen`, `:6940` `test_tc030_per_screen_paging_bindings_in_footer` (`_PAGING_FOOTER_KEYS` on `issues`, `:6887-6893`), `:6972` `test_tc030_footer_updates_and_reflects_active_screen` (a `Footer` mounted), `:7011` `test_tc030_operations_binding_shown_in_footer` — rewritten to read the painted key bar | LLR-150.2, 150.4, 150.6 | Inc-8 |
| `tests/test_tui_diff_screen.py:3806` AT-B78-32 — the App `BINDINGS` block pinned row by row (a baseline failure, `PLAN.md` §Test ledger); the `period` row gains `key_display="."` | LLR-150.5 | Inc-8 (re-pinned, the row named in the ledger) |
| `tests/test_tui_snapshot.py` — the bottom rows of all 29 cells (every window paints the key bar) | LLR-150.6 | Inc-8 per-cell prediction (PC-10), Inc-7 regen (D17) |
| `tests/test_discoverability.py:33` (the Help binding `show=True`) | not superseded — the `show` flags stay as shipped; the key bar does not read them | — |
| `tests/test_tui_patch_history_strip.py:667` TC-081.4 — diffs `app.py` against `main` and fails on any `Binding(` line not carrying a marker of `_SANCTIONED_BINDING_MARKERS` (`:739-745`) | Inc-6: the `Binding("c", "confirm_attention", "Confirm", show=False)` line of `_FlowExecutionSection` (declared in `app.py`, D10) → marker `confirm_attention` added in Inc-6; Inc-8: the `Binding("period", "hex_page_next", "Hex+", key_display=".")` line (LLR-150.5) → marker `key_display="."` added in Inc-8; each with its comment in the shipped style | Inc-6, Inc-8 (named supersession, the list extended, never relaxed) |
| batch-02 LLR-013.2 "the footer shows the active screen's `show=True` bindings" (`.dev-flow/2026-05-20-batch-02/01-requirements.md:583`) and `keymap-proposal.md` §2 (the always-shown set) / §3 (per-screen paging on Workspace, A2L, MAC, Issues) (`.dev-flow/2026-05-20-batch-02/03-increments/keymap-proposal.md`), as encoded at `tests/test_tui_directionb.py:6881-6893` | HLR-150: row 1 = the 8 global tokens of LLR-150.2 (no `/`, `g` — window keys); per window: `, .` on Workspace only, `+ -` on A2L and MAC only, Issues none of the four (its paging rides `pageup` / `pagedown`, `app.py:1441-1442`); the rest per I-10 | Inc-8 (LED-…97.10) |

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
