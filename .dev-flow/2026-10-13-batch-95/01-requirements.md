# Requirements Document — s19_app — Batch 2026-10-13-batch-95

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
This document is the Phase-1 contract for batch 2026-10-13-batch-95: the implementation of the
operator's four changes of 2026-10-12 (`prototypes/cambios_10_12_2026/`, the prototype round that
closed 2026-10-13 with all four changes and all six rulings accepted). The batch ships: (1) the
**Split / Join / Export** screen — the grafted terminal design (V1 chassis + V2's full-width visor
band at ≥118 columns + split-mode per-file gantt), the color/glyph preview visor, split/join/export
in S19+HEX+BIN with skip/fill gaps (pad default `0x00`), the span guard, palette-first; (2) the
project save-gather with project-scoped artifact homes; (3) the four open-folder buttons on a
cross-platform open seam; (4) per-window usage help sections.

**Amended mid-P3 (change 5, 2026-10-13, `LED-2026-10-13-batch-95.2`):** the operator's fifth
change adds (5) the **A2L-referenced patch changes** — change-set entries that reference A2L
symbols from the Patch Editor and the change-set JSON, resolved through the shipped tag map with
the physical→raw conversion via the shipped COMPU_METHOD enrichment — plus the **Flow Builder's
A2L reference** (the Load/Patch blocks carry it, sourced from the loaded project or the organized
workspace folders) and the **report/diff attribution** (every flow change names its
symbol/address in the report; an A2B diff block over a flow-produced image references all the
flow's changes). The amendment lands mid-P3: increment 001 (the engine) is running and untouched;
increments 002–004 are not yet launched and carry the amended scope (PLAN.md).

### 1.2 Scope
In scope: the new screen and its engine additions (range slicer, BIN emitter, pad-byte fill
emitter, `extract_memory_segments` hardening); the change-1 save-gather and artifact homes; the
change-2 open-folder buttons; the change-3 per-window usage help; the change-5 A2L-referenced
patch entries (the change-set wire's symbol-reference form + the Patch Editor's symbol
resolution/picker), the Flow Builder's A2L reference on the Load/Patch blocks, and the
report/diff attribution. Out of scope: the HTML mock's
chrome (the terminal design **superseded** it — see the ledger); XCP `IF_DATA SEGMENT` extraction
(the recon named it, this batch punts it); any rail-key repurpose (ruling: palette-first, no rail
slot); report subfolders (the Reports button opens the project `reports\` dir as today).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| the graft / v3 "FINAL" | the signed design: V1's cockpit chassis + V2's full-width visor band at ≥118 cols + V2's per-file gantt as split-mode's band when 1..6 files fit |
| the visor | the preview band map: a byte-class map of the would-be output over a real address ruler |
| visor class | one of: data ▓ · fill ░ · conflict ▒ · context · · absent (space) — output content class, the ONE visual variable (glyph density + hue) |
| span guard | the two-step confirm on `join=fill` when the padded span dwarfs the real data (span ≥ 1 MiB and fill ≥ 50% of span) |
| ‹stem›_‹segment›.‹ext› | the split naming pattern; join resolves ‹segment› to `joined` → ‹stem›_joined.‹ext› |
| COMMON folders | the workspace-shared homes: `<base>\.s19tool\workarea\patches\`, `<base>\.s19tool\templates\` |
| save-gather | change 1: on project save, COPY the JSON artifacts the project uses into its own folder |
| the round | `prototypes/cambios_10_12_2026/` — README, OPEN_QUESTIONS, the three verdicts, design_notes, tui_prototype, frames, help_sections, folders.html |
| the frame discipline | batch-93's pinning rule: captures/assertions run at the measured geometry — `App.run_test(size=(120,36))` hands the app a **118×34** screen |
| A2L-referenced change | a change-set entry that names an A2L tag instead of a bare address; the address/length/datatype resolve through the tag map at load |
| symbol-reference form | the change-set wire's entry form carrying `"symbol": "‹tag name›"` **alongside** — never replacing — the address form (P-19) |
| the tag map | `extract_a2l_tags`' rows plus the parse payload's side tables (`record_layouts_by_name` / `compu_methods_by_name`) — the name → address+length+datatype+conversion resolution source (P-16) |
| A2L reference (flow) | a flow Load/Patch block's declared A2L filename, resolved through the same containment guard as the other block references, that the run uses for symbol lookups (P-20/P-23) |
| the REFUSAL | the load-time/press-time refusal raised when a symbol or an A2L reference resolves to nothing — the error **names the symbol or reference** (the operator's law) |

### 1.4 References
- `prototypes/cambios_10_12_2026/README.md` — the four changes re-derived into laws (SHIPPED-vs-NEW with code citations).
- `prototypes/cambios_10_12_2026/OPEN_QUESTIONS.md` — the rulings; the six verdict-sheet rulings (Q1–Q6 = 8a–8e + 7a) all answered with the recommendations in `veredicto-ronda1.json`.
- `prototypes/cambios_10_12_2026/veredicto-ronda1.json` — C1–C4 accept; Q1 pad `0x00`; Q2 first-range base; Q3 `‹stem›_joined.‹ext›`; Q4 original offsets + guard; Q5 split-fill confirmed; Q6 palette-first.
- `prototypes/cambios_10_12_2026/veredicto-tui-pass.json` — V = the GRAFT; the visor reads well.
- `prototypes/cambios_10_12_2026/veredicto-final.json` — the graft ships AS the screen; the four visor classes are distinguishable ("si, se distinguen").
- `prototypes/cambios_10_12_2026/design_notes.md` + `tui_prototype.py` + `frames/final_120x36.svg` · `final_80x24.svg` · `final_guard_120x36.svg` — the SIGNED terminal design (the oracle frames).
- `prototypes/cambios_10_12_2026/help_sections.md` — the change-3 authored copy (operator-editable).
- `prototypes/cambios_10_12_2026/folders.html` — the change-1/2 spec (folder trees, the four annotated captures, the behaviour spec).
- REQUIREMENTS.md canon: `US-026`/`HLR-030` (the patch-dropdown scanner), `LLR-003.7` (flows project-only), `LLR-008.1` (Reports refuses without a project) / `LLR-008.3` (reports project-only), batch-58 F3 (`ensure_template_lib`, the cross-project template library), `HLR-132`/`R-TUI-N8` (the `VariantHelpScreen`-family modal precedent), `LLR-111.7`/`R-TUI-103` (the band allocator law).
- `AT-TC-REGISTRY.jsonl` + `.dev-flow/AT-TC-REGISTRY-SPEC.md` — the id authority (G1–G7 guard).
- The operator's change 5 (2026-10-13), quoted verbatim in `01-requirements-ledger.md`
  (`LED-2026-10-13-batch-95.2`).
- The shipped seats of change 5: `s19_app/tui/a2l.py` (the tag map + the raw/physical
  enrichment — batch-91 `LLR-122.2` pins it), `s19_app/tui/changes/io.py` (the
  `s19app-changeset` v2 wire), `s19_app/tui/changes/model.py` + `apply.py` (the address-only
  engine), `s19_app/tui/services/flow_model.py` + `flow_execution_service.py` (the Load/Patch
  blocks), `s19_app/tui/services/report_service.py` + `flow_report_service.py` + `diff_report_service.py`
  (the attribution seats), `s19_app/tui/screens_directionb.py` + `services/change_service.py`
  (the Patch Editor entry path).

### 1.5 Document overview
§2 restates the product context, the four source user stories, the premise evaluation (C-43) and
the fork preconditions (C-52). §3 carries the HLRs. §4 carries the LLRs and the IFC (C-54).
§5 declares the two-layer validation strategy and the batch acceptance criteria. §6/§7 point at
the ledger.

---

## 2. Overall description

### 2.1 Product perspective
The app is the shipped 10-rail-key TUI (`s19_app/tui/app.py`, rail bindings `1`–`9`,`0` all
occupied, `app.py:1362-1371`). This batch adds an eleventh surface reachable **palette-first**
(`^K` → "Split / Join / Export" — the shipped palette binding is `app.py:1335`), extends the
save-project action's gather (the binaries copy at `app.py:6786-6797` is the precedent), adds four
open-folder chips on existing windows, and adds a per-window usage-help modal on the shipped
`VariantHelpScreen` pattern (`screens.py:416`). The screen rides shipped engine parts
(contiguous-range discovery, the S19/HEX mem_map emitters, the CRC gap vocabulary) plus three new
engine pieces and one hardened extractor (§3 HLR-137).

### 2.2 Product functions
1. Render the Split / Join / Export screen as the graft: V1 chassis, the visor as the entry point, the two-regime reflow, the split-mode per-file gantt.
2. Encode the preview as the five visor classes (one visual variable per cell) and keep the band run-economical (12–14 runs/row at any width).
3. Plan and export split (one file per range, `intra_gap skip|fill`) and join (one `‹stem›_joined.‹ext›`, `concat` from the first range's base or `fill` at original offsets) in S19/HEX/BIN, pad default `0x00`, abort on a fill that would clobber source bytes.
4. Fire the two-step span guard on `join=fill` with span ≥ 1 MiB and fill ≥ 50% of span.
5. Gather the project's used JSON artifacts into project homes on save (COPY; common originals stay).
6. Open the artifact home from Patch Editor / Checks / CRC Designer / Reports via one cross-platform seam.
7. Render per-window usage help as a modal per window, authored from `help_sections.md`.

### 2.3 User characteristics
The operator: an embedded-tooling user on an 80×24..160×48 terminal, keyboard-first, who asked for
a visual preview of joins before writing files ("una especie de visor de cambios en los joins… con
colores para expresar los segmentos y los fillers" — `veredicto-ronda1.json` notes). Colour-blind
legibility is a hard requirement (C-10): glyph density carries the class, hue is the redundant cue.

### 2.4 Constraints
- **A chosen language's commitments outrank defaults:** the Calm Dark palette ships (`styles.tcss:26-31` — `$accent-calm #91abec` et al.; the severity set `:684-702` — `.sev-ok #54efae` / `.sev-error #fd8383` / `.sev-warning #f6ff8f`); the visor's four class hexes are reuses of shipped tokens + two verified context tints, nothing outside the set.
- **One accent hue; grey ramp for identity-less content:** the pad filler is deliberately on the grey ramp (`#6b7280`); coverage colours are data states (ok/err/amber), not decoration.
- **The 2-colors-per-cell law / C-10:** one visual variable (output content class) per cell, encoded redundantly as glyph density + hue (the shipped Memory Map band idiom, `entropy_style.py:53`).
- **The bound lives in the producer:** band column apportioning is `floor-one-then-largest-remainder` bounded by the MEASURED container — the shipped `_allocate_band_widths` law (`screens_directionb.py:610`, `LLR-111.7`/`R-TUI-103`), never a predicate over emitted text.
- **Thresholds read the measured screen**, never the nominal one: the wide regime sits at **screen width ≥ 118** because `run_test(size=(120,36))` hands the app a 118×34 screen (the batch-93 frame discipline).
- **S1 (preserved):** every file-derived string renders as plain `Text` spans; `markup=False` on toasts; no markup parsing anywhere on the new surface.
- **Palette-first, no rail key (ruling Q6/7a):** the screen is NOT bound to a rail key; it opens from the `^K` palette named "Split / Join / Export".
- **Esc closes** the screen and every modal this batch adds.
- **Snapshot goldens regenerate only in canonical CI** (textual==8.2.8 pin, `pyproject.toml:73`); the FULL suite runs before merge and every ledger figure states which form produced it.
- **AT/TC registry:** new ids pass the G1–G7 guard (`AT-TC-REGISTRY.jsonl`); this batch's reservation (AT-296..301 + TC-682..711) was written at P0.
- **No git from the batch lane** — the coordinator commits at close (standing authorization, `state.json`).

### 2.5 Assumptions and dependencies
- The round's three verdicts stand as recorded (all accepted, 2026-10-13); the standing authorization "Implement the batch" is quoted in `state.json`.
- The shipped code citations of premise P-1..P-15 hold on the RC-1 tree (`origin/main` = `348c125`, verified at P1).
- The textual pin stays 8.2.8 for this batch.
- The four authored help sections' voice matches the shipped `VariantHelpScreen`; the copy ships operator-editable.

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-129 | As the operator preparing firmware images, I want a Split / Join / Export window — A2L segments / image ranges / manual localities as slice sources, split or join with skip/fill gaps, S19/HEX/BIN output, and a color/glyph preview visor of the exact output bytes with a guard before a huge padded span — so that I can see what a join will write before it lands on disk. | change 4 (`veredicto-ronda1.json` C4 + the operator's visor note) | READY |
| US-130 | As the operator archiving or delivering a project, I want saving a project to gather every artifact it uses — change-sets, check runs, CRC templates, flows, reports, the binaries — into the project's own folder (a self-contained snapshot), with the common library copies kept, so that the project folder is complete and the shared scanners keep working. | change 1 (`veredicto-ronda1.json` C1; `folders.html` §1) | READY |
| US-131 | As the operator, I want one "📂 Open folder" chip on the Patch Editor, Checks, CRC Designer and Reports windows, opening exactly the folder each window's artifacts live in, so that I never hunt paths by hand. | change 2 (`veredicto-ronda1.json` C2; `folders.html` §2) | READY |
| US-132 | As the operator learning a window's functions, I want a "how to use this window" help section per window, reachable from the window itself, so that the key list of `?` is not the only discoverable help. | change 3 (`veredicto-ronda1.json` C3; `help_sections.md`) | READY |
| US-133 | As the operator patching a firmware image against a declared A2L, I want change entries that reference A2L symbols — from the Patch Editor and from the change-set JSON — resolving to address/length/datatype with values set in physical units; I want the Flow Builder to ask for the A2L reference (from the loaded project or the organized workspace folders) so flows resolve those symbols; and I want every report to attribute each change by its symbol/address, with an A2B diff over a flow-produced image referencing all the flow's changes. | change 5 — the operator's words 2026-10-13, quoted in the ledger (`LED-2026-10-13-batch-95.2`) | READY |

**Ledger pairing:** US-129, US-130, US-131, US-132 and US-133 each name **Ledger:** LED-2026-10-13-batch-95.1
or LED-2026-10-13-batch-95.2 respectively (the batch's derivation entries; V26 pairs both ways).

#### Refinement log (one block per story)

**US-129 — the Split / Join / Export screen (change 4, operator-extended)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator preparing images · outcome = the grafted screen with the visor preview, split/join/export in three formats, the span guard, exports named per the pattern · why = the operator's change request + the visor add from the round-1 notes · out of scope = rail keys, XCP IF_DATA, a chosen-base join variant.
- **Feasibility (E, S):** implementation path = a new screen composed from shipped idioms + three new engine pieces on the shipped parser/emitter base · dependencies/unknowns = the A2L extractor hardening (P-6) is a prerequisite for the A2L tab's real rows · fits one batch? = yes.
- **Evaluability (T) — behavioral, black-box:** "When the operator selects ranges and presses `^E`, the user observes the named files on disk byte-matching the preview band (split: one `‹stem›_‹segment›.‹ext›` per range; join: one `‹stem›_joined.‹ext›`), and — on a huge padded span — a warning that must be confirmed before anything writes."
- **Open questions:** none blocking; the `.addr` sidecar and the empty-file confirm enter via the round's recommendations (ledger).
- **Classification:** `READY` — the signed frames are the oracle.

**US-130 — the save-gather (change 1)**
- **INVEST:** I ✓ · N · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator saving a project · outcome = the project folder holds gathered COPIES of the used change-sets/check runs/templates alongside the binaries; without a project, the artifacts stay in the COMMON folders · why = the split-brain complaint (binaries project-scoped, artifacts scattered) · out of scope = MOVE semantics (rejected: the common folders are live libraries, OPEN_QUESTIONS #4), flows/reports homes (already project-only).
- **Feasibility (E, S):** path = extend `action_save_project` (`app.py:6786-6797` region) with a gather pass · unknowns = the exact "used by this project" predicate — P3 defines and records it (observation O-1) · fits one batch? = yes.
- **Evaluability (T):** "When the operator saves a project, the user observes the used JSON artifacts copied into the project's `patches\`/`checks\`/`templates\` folders while the COMMON originals remain in place, and — with no project — the artifacts staying in the COMMON folders."
- **Open questions:** the "used" predicate (O-1); checks get their own `checks\` folder per the round's drawing (7d).
- **Classification:** `READY`.

**US-131 — the open-folder buttons (change 2)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator on Patch/Checks/CRC/Reports · outcome = one ghost chip per window header opening exactly the change-1 home; disabled with a reason when the target cannot exist · why = "never hunt paths by hand" · out of scope = per-file logic, a global shortcut, report subfolders.
- **Feasibility (E, S):** path = a chip on each window's tab strip + one shared open helper · unknowns = the cross-platform seam's non-Windows arms are commission-level (the folders.html spec accepted Windows-only; the commission says cross-platform — the contract follows the commission, ledger records it) · fits one batch? = yes.
- **Evaluability (T):** "When the operator clicks the chip, the user observes the OS file manager opening at the window's artifact home; with no project on Reports, the chip is dimmed and the status line says why."
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-132 — per-window usage help (change 3)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator learning a window · outcome = a per-window modal carrying that window's numbered usage steps, opened from a "?" affordance beside the window title and/or the `?` key while the window is focused · why = the stock `?` HelpPanel lists keys only, no prose · out of scope = forking Textual's HelpPanel (rejected by the round, OPEN_QUESTIONS #6), rewriting the key-list panel.
- **Feasibility (E, S):** path = the shipped `VariantHelpScreen` pattern (`screens.py:416`) + authored sections from `help_sections.md` · unknowns = none · fits one batch? = yes.
- **Evaluability (T):** "When the operator opens help from a window, the user observes that window's usage section in a modal; Esc/Close dismisses it; every shipped window plus the new screen has one."
- **Open questions:** none blocking; copy stays operator-editable.
- **Classification:** `READY`.

**US-133 — A2L-referenced patch changes, the Flow Builder's A2L reference, the report/diff attribution (change 5, 2026-10-13)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator patching against a declared A2L · outcome = change entries that reference A2L symbols (resolved to address/length/datatype, values set in physical units), a Flow Builder that asks for the A2L reference — from the loaded project or the organized workspace folders — and reports that attribute every change by its symbol/address, the A2B diff over a flow-produced image referencing all the flow's changes · why = the operator's change 5, quoted in the ledger · out of scope = a per-family COMMON A2L folder (no shipped home exists; the workspace containment root serves, P-23), rewriting the operator-editable help copy.
- **Feasibility (E, S):** path = the shipped tag map + COMPU_METHOD side tables + the lenient v2 wire (P-16..P-19) + the blocks' project-relative ref grammar (P-20) · unknowns = the physical→raw encode direction is net-new composition on the shipped side tables (decode ships — P-17); its conversion limbs are P3-recorded · fits one batch? = yes — it rides increments 002–004, none launched yet.
- **Evaluability (T) — behavioral, black-box:** "When the operator picks an A2L symbol in the Patch Editor and sets a value, the user observes the entry resolve (its address/length shown), the saved JSON carrying the symbol, a flow run applying the entry through the flow's declared A2L reference, and the report plus the A2B diff naming every change — and an unknown symbol refused with its name in the error."
- **Open questions:** none blocking; the no-project A2L home (the `.s19tool\workarea\` containment root) and the encode-direction limbs are P3-recorded (§6.3).
- **Classification:** `READY`.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| P-1 | Rail keys `1`–`9`,`0` are all bound on the shipped tree — there is no free rail key for a new screen | measured at P1 | TRUE | `s19_app/tui/app.py:1362-1371` — `1` workspace · `2` a2l · `3` mac · `4` map · `5` issues · `6` patch · `7` diff · `8` flow · `9` checks · `0` crc_designer | the palette-first ruling (Q6/7a) is the consequence |
| P-2 | `?` is the stock Textual HelpPanel (key list only) and the shipped prose-help pattern is `VariantHelpScreen` | measured at P1 | TRUE | `app.py:1360` — `Binding("question_mark", "show_help_panel", "Help", show=True)`; `s19_app/tui/screens.py:416` — `class VariantHelpScreen(ModalScreen[None])` | change 3 rides the shipped pattern; the HelpPanel stays untouched |
| P-3 | The only shipped folder-open action is Windows-only: `action_open_workarea` shells `explorer` | measured at P1 | TRUE | `app.py:5437-5446` — `subprocess.Popen(["explorer", str(self.workarea)])` in `action_open_workarea`, `o` key | change 2's seam extends this idiom cross-platform (commission) |
| P-4 | Saving a project today copies the loaded binaries (S19/HEX + MAC + A2L) into the project folder | measured at P1 | TRUE | `app.py:6786-6797` — three `copy_into_workarea(...)` calls under `action_save_project` (file → MAC → A2L), `WorkareaContainmentError` guard | change 1 extends the same action to the JSON artifacts, same COPY stamp semantics |
| P-5 | Contiguous-range discovery ships for both image formats | measured at P1 | TRUE | `s19_app/core.py:496-514` — `S19File.get_memory_ranges`; `s19_app/hexfile.py:176-191` — `IntelHexFile.get_ranges` (identical merge algorithm) | the ranges tab rides these verbatim |
| P-6 | `extract_memory_segments` breaks on quoted multi-word `MEMORY_SEGMENT` names (base/size parse to null) and extracts no `offset` field | measured at P1 | TRUE | `s19_app/tui/a2l.py:862-895` — `first.split()` tokenization, no quoted-name handling; entry dict carries `block_name/raw_first_line/usage/kind/base/size` only; the round's gap table (`segment_split.prototype.html:231`): "GAP: `offset` field + XCP `IF_DATA SEGMENT` are not extracted" | HLR-137's hardening is a prerequisite for the A2L tab (the recon's bug) |
| P-7 | S19/HEX mem_map emitters ship; no BIN emitter exists anywhere in the engine | measured at P1 | TRUE | `s19_app/tui/changes/io.py:1419` — `emit_s19_from_mem_map`; `io.py:1569` — `emit_intel_hex_from_mem_map`; `grep -rn "def emit.*bin\|def write.*bin" s19_app/tui/changes/io.py` → no hit | the BIN emitter is net-new (HLR-137) |
| P-8 | The multi-range gap vocabulary ships in the CRC coverage editor: `intra_gap skip|fill`, `join concat|fill`, pad byte; `on_gap_conflict` defaults to `abort` | measured at P1 | TRUE | `s19_app/tui/operations/crc_designer_model.py:48-49` — `INTRA_GAP_VALUES=("skip","fill")`, `JOIN_VALUES=("concat","fill")`; `:56` — `ON_GAP_CONFLICT_VALUES=("abort","warn","ignore")`; `:106` — `on_gap_conflict: str = "abort"` | the screen reuses the vocabulary verbatim so both surfaces speak one language; 8f's abort is adopted as the fixed conflict behaviour |
| P-9 | The CRC editor's pad byte defaults to `0xFF` — the new screen's `0x00` default is a deliberate divergence | measured at P1 | TRUE | `s19_app/tui/crc_designer_view.py:375` — `self._text_row("Pad byte", "crc_coverage_pad_byte", "0xFF")`; `:926` — `pad_byte = int(pad_raw, 16) if pad_raw else 0xFF` | ruling Q1/8a pins `0x00` for this window; the two surfaces differ by intent (erased-flash `0xFF` vs neutral `0x00`) |
| P-10 | The COMMON folders are live libraries the app scans — the COPY-not-MOVE rationale | measured at P1 | TRUE | `app.py:4390-4402` — the patches folder is `<base_dir>/.s19tool/workarea/patches`, feeding the dropdown (US-026, scanner `app.py:2217-2240`); `s19_app/tui/workspace.py:58-83` — `ensure_template_lib`, the cross-project template library (batch-58 F3) | MOVE would silently empty those scanners; HLR-138 pins COPY |
| P-11 | The visor's precedents ship: the `·░▒▓` band glyph idiom and the measured-container allocator | measured at P1 | TRUE | `s19_app/tui/entropy_style.py:53` — `ENTROPY_BAND_GLYPH`; `s19_app/tui/screens_directionb.py:610` — `_allocate_band_widths` (floor-one-then-largest-remainder, docstring example at `:672`) | the visor reuses both; the bound stays in the producer |
| P-12 | The Calm Dark palette, the `.db-pane` chrome and the severity hues ship at the cited addresses | measured at P1 | TRUE | `styles.tcss:26-31` — `$accent-calm:#91abec`, `$bg-base:#0a0e1b`, `$bg-panel:#0f1525`, `$fg-base:#e9e9e9`, `$rule:#1b233a`, `$odd-row:#131a2c`; `:334` — `.db-pane { border: tall $rule; border-title-color: $accent-calm; … }`; `:684-702` — `.sev-ok #54efae` / `.sev-error #fd8383` / `.sev-warning #f6ff8f` | the visor classes reuse these tokens + `#6b7280` fill + `#46557a` context (256-colour-verified in the round's bench) |
| P-13 | The app is palette-first on `^K` today | measured at P1 | TRUE | `app.py:1335` — `Binding("ctrl+k", "focus_palette", "Palette", priority=True)`; `styles.tcss:51,69` — `#command_bar_slot` / `#command_bar` the palette host | ruling Q6/7a rides the shipped palette; no new key |
| P-14 | The range slicer is composable from shipped parts | measured at P1 | TRUE | `s19_app/core.py:485` — `get_memory_map`; `core.py:407` — `set_bytes_at`; emitters per P-7 | HLR-137.1 composes them; no parser changes |
| P-15 | The round's design numbers re-derive from the artifacts | measured at P1 | TRUE | `scratch/extracted.json` executes to: 3 A2L rows (AscetCode CODE FLASH @0x08000000 63,488 B · AscetCalibrationRom DATA ROM @0x0800F800 2,048 B · Variables DATA RAM @0x20000000 10,240 B) + 11 S19 ranges, 3,968 B, span 0x000017E0–0x00010000; the guard case = span 0x20002800−0x08000000 = 402,659,328 B (384.01 MiB) from 75,776 B (74 KiB); `tui_prototype.py:111` — `GUARD_SPAN_MIN = 1 << 20`, `:112` — `GUARD_FILL_MIN = 0.5`; `:1041` — wide at `screen.size.width >= 118` (pane 58, band 54), `:1032` — narrow at `< 100` (pane 30), `:1110-1112` — gantt cap 6 split-only; `frames/final_120x36.svg` viewBox `0 0 1482 928.4` (118×34 measured), `final_80x24.svg` viewBox `0 0 994 635.6`; class hexes present in `final_80x24.svg`: `#91abec` ×2 · `#6b7280` · `#f6ff8f` · `#46557a` | every contract number traces here; P4 re-runs the bench under the batch's own harness |
| P-16 | The tag map ships: one flat tag list with name/address/length/datatype plus RECORD_LAYOUT and COMPU_METHOD names per tag, and name-keyed side tables in the parse payload | measured at the amendment | TRUE | `s19_app/tui/a2l.py:1460-1649` — `extract_a2l_tags` (CHARACTERISTIC+MEASUREMENT); the entry dict at `:1487-1516` carries `name/address/length/datatype/record_layout_name/compu_method_name/…`; `:1720-1728` — `parse_a2l_file` returns `tags` + `record_layouts_by_name` + `compu_methods_by_name`; the app holds the loaded map at runtime: `app.py:1393-1394` — `current_a2l_path` / `current_a2l_data` | HLR-141's name → address+length+datatype resolution source exists shipped |
| P-17 | The raw+physical enrichment ships (batch-91 `LLR-122.2` pins it) — but in the DECODE direction only; physical→raw encode is net-new composition on the same shipped tables | measured at the amendment | TRUE | `a2l.py:1731-1791` — `enrich_a2l_tags_with_values` (entries gain `raw_bytes`/`raw_value`/`physical_value`/`conversion_status`, `:1771-1790`); `_apply_compu_method` decodes at `a2l.py:1422`; the side tables ship the encode inputs: `extract_compu_methods` `:779-826` — entries carry `coeffs_linear`/`coeffs`/`compu_tab_ref` (`:792-802`) | the amendment composes the encode direction from shipped tables; recorded as net-new in the ledger |
| P-18 | The change-set engine addresses bytes by ADDRESS only; no symbol→address resolution exists anywhere in `changes/` | measured at the amendment | TRUE | `s19_app/tui/changes/model.py:79-185` — `ChangeEntry(address: int, encoded_bytes, …)`, no symbol field; `s19_app/tui/changes/apply.py:335-336` — `mem_map[start + offset] = byte_value`; the only name-awareness is reverse-direction: `_a2l_linkage_source` `apply.py:402-435` / `_classify_linkage` `:567-616` label an entry's range from a tag's range | the symbol-reference form is the net-new forward direction (HLR-141) |
| P-19 | The v2 wire reader is lenient to an ADDED optional entry field (touches only `type`/`address`/`value`/`bytes` via `.get()`) but rejects a reference form REPLACING `address`; the canonical writer emits exactly `{type, address, value\|bytes}` | measured at the amendment | TRUE | `s19_app/tui/changes/io.py:896-915` — entry read via `element.get(...)`; `:907-909` + `:918-966` — missing/invalid address → `CHG-ADDRESS-SYNTAX`, entry skipped; `:1248-1282` — `_encode_entry` emits the four fields only, so an unknown field would not round-trip | the symbol form is ADDED alongside the address (never replacing it) and the canonical writer keeps the resolved address — v2.0 readers apply canonical symbol entries byte-identically (the leniency law of LLR-141.1) |
| P-20 | The Flow Builder blocks reference artifacts by project-relative filename through the containment guard, and the flow context already carries the loaded A2L | measured at the amendment | TRUE | `s19_app/tui/services/flow_model.py:97-110` — `SourceBlock(image_ref: str)`; `:113-124` — `PatchBlock(change_doc_ref: str)` only; `:229-258` — `FlowContext` carries `a2l_data`; `flow_execution_service.py:209-236` — the PATCH arm resolves the ref through `_resolve_manifest_entry` (`:217-220`) then `read_change_document` → `apply_change_document` (`:227-230`) | HLR-142 rides the shipped ref grammar; the run-time A2L seat exists |
| P-21 | The change-set application report lists every entry by address with best-effort reverse-direction symbol linkage; the flow report is a per-block pipeline ledger with NO per-entry attribution | measured at the amendment | TRUE | `s19_app/tui/services/report_service.py:1841-1939` — `_modifications_lines`, one row per entry, header `:1934` `\| Address \| Length \| Before \| After \| Linkage \| Symbol \|` (symbol from `linkage_symbol`); `s19_app/tui/services/flow_report_service.py:274-340` — the Pipeline ledger (`:331-338`), a PATCH row's summary is `"applied N entries"` | HLR-143.1's attribution seat: the grammar exists per-entry in the project report; the flow report gains the section |
| P-22 | The A2B diff report annotates differing runs with best-effort symbols (reverse direction) and has NO change-set attribution of the differences | measured at the amendment | TRUE | `s19_app/tui/services/diff_report_service.py:957-1001` — `_run_table_lines`, rows `\| Start \| End \| Length \| Classification \| Symbols \|`; `_annotate_run` `:822-862` maps artifact `(address, name)` pairs whose point address falls inside a run — never change-set entries | HLR-143.2's law (all flow changes referenced) is net-new attribution on the shipped run table |
| P-23 | The A2L homes ride change 1: the project save copies the loaded A2L flat into the project folder root under the single-A2L guard, and the workspace tree is the organized artifacts home; the Patch Editor today keys entries by address with no symbol input | measured at the amendment | TRUE | `s19_app/tui/app.py:6796` — `copy_into_workarea(self.current_a2l_path, project_dir)` (flat, project root); `:6774-6783` — the single-A2L-per-project guard; `s19_app/tui/workspace.py:16-26` — the `.s19tool\workarea\` tree (patches/templates homes); the Patch Editor add-row `screens_directionb.py:5768-5788` — Address/String/Bytes inputs only; `change_service.py:718-767` — `add_entry(address, value_text, bytes_text)`; the name-keyed UI lookup ships: `app.py:525-535` — `_build_a2l_name_index` | HLR-142's source homes + HLR-141.2's picker ride shipped idioms; no new COMMON folder is invented |

- **Premise evaluation:** 23 premise(s) · ✅ TRUE ×23

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

- **Fork preconditions:** none — this batch runs ONE lane on the main checkout. (Batch-94 — the
  prior lane's amendment — is closed and merged at RC-1 `348c125`; no cross-batch hold applies.
  Change 1 edits the save path, change 2 the four windows' chrome, change 3 the help surface,
  change 4 a new screen — one lane owns all of it; P3 sequences the increments inside the lane.)

---

## 3. High-level requirements (HLR)

### HLR-135 — The screen: the graft as the shipped terminal design
- **Traceability:** US-129
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the operator opens the Split / Join / Export screen (palette-first — `^K` → "Split / Join / Export"; no rail key), the system shall render the grafted design: the V1 cockpit chassis — segment-source chips, the range table (cursor + `●`/`○` selection + coverage column), one control per row (MODE / GAPS+PAD / FORMAT / DEST / NAMING), and the right PREVIEW pane (output label, the union visor band, legend, address ruler, stats + guard chip, summary, `EXPORT ^E`) — with the preview visor as the entry point; at a measured screen width ≥ 118 columns the preview pane shall widen to 58 columns (band 54 cells), below 100 columns it shall reflow to 30, mirroring the `width-narrow` two-regime idiom; in split mode the preview pane shall additionally render the per-file gantt (one row per output file: label · per-file byte band · size) when 1..6 files are selected and shall hide it otherwise (at the floor the union map carries the story alone); Esc shall close the screen. **The signed frames are the oracle, pinned byte-level at the measured geometries:** `frames/final_120x36.svg` (split — both graft deltas visible; the real screen is 118×34 per the frame discipline), `frames/final_80x24.svg` (the floor — all four visor classes), `frames/final_guard_120x36.svg` (the guard state, 402 MB of `░`).
- **Rationale (informative):** `veredicto-tui-pass.json` (V = the graft) + `veredicto-final.json` (ship the graft AS the screen; the visor classes read distinctly). The HTML mock's chrome is superseded — the terminal design is the law (ledger).
- **Validation:** `test` + `inspection`
- **Executed verification:** P1: the frames' grid reconstructions (design_notes §8/§9 — 27-key tour green at both sizes, gantt show/hide confirmed by class and computed display at both regimes, bench re-run). Owed at P4: the TCs minted from TC-682..711 driving the shipped screen headless at `size=(120,36)` (real 118×34) and `size=(80,24)`, asserting the chassis, both regimes, the gantt and the class hexes from the rendered DOM/SVG.
- **Numeric pass threshold:** at 118×34: preview pane width 58, band 54 cells, gantt visible in split with 1..6 files; at 80×24: pane 30, gantt hidden (display none), every control row reachable; the four class hexes (`#91abec`/`#6b7280`/`#f6ff8f`/`#46557a`) present in the rendered frame; Esc closes 1/1.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** the operator lands on a cockpit whose right pane previews the exact output bytes — data, pads, conflicts, unselected context — over a real address ruler; widening to ≥118 columns widens the band; in split with up to six files, one gantt row per file appears under the union map.
  - **Shipped surface:** the Split / Join / Export screen (the new rail-less, palette-first surface).
  - **Acceptance test(s):** AT-296
  - **Boundary catalog (QC-3):** ☑ boundary — the 118-column regime threshold itself and the 80×24 floor; ☑ empty — an empty selection renders the source map all-context plus a "tick a row" note, never a blank panel.
  - **Negative control:** the pre-change tree has no screen at all — the same DOM assertions go RED; and a render keyed on the nominal 120 columns (instead of the measured 118) misses the wide regime — the regime assertion goes RED at 118×34.

### HLR-136 — The visor semantics and the export contract
- **Traceability:** US-129
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the operator configures the export and reads the preview, the system shall encode the band as output content class with one visual variable per cell — `▓` data (accent `#91abec`) · `░` fill (grey `#6b7280`) · `▒` conflict (warn `#f6ff8f`) · `·` context (dim indigo `#46557a`) · (space) absent — glyph density and hue two correlated encodings of the same variable; when the operator exports, split mode shall write one file per selected range named `‹stem›_‹segment›.‹ext›` with `intra_gap skip|fill` padding only INSIDE each file's own span between its covered sub-ranges, and join mode shall write one `‹stem›_joined.‹ext›` — `concat` packing the ranges back-to-back from the first (lowest) range's base, or `fill` keeping the original offsets with the gaps padded; the pad byte shall default to `0x00` and be configurable; the format S19 / HEX / BIN shall apply to both modes, BIN writing exactly `size` flat bytes from the segment base (intra-range gaps not padded) plus a one-line `‹name›.addr` sidecar carrying the base address; a fill that would overwrite real source bytes shall abort the export with a reason (the `▒` class renders exactly those bytes); a range with zero coverage shall render as a first-class warn state and shall not export an empty file without an explicit confirm.
- **Rationale (informative):** rulings Q1–Q5 (pad `0x00` · first-range base · `‹stem›_joined.‹ext›` · original offsets + guard · split-fill confirmed) + 8f's abort (adopted as fixed behaviour — the accepted visor's `▒` class embodies it) + 7c's zero-coverage-first-class + the round's #2 sidecar recommendation (a BIN without its base is unflashable out of context).
- **Validation:** `test`
- **Executed verification:** P1: the plan model executed over the real rows (`tui_prototype.py:239-343` — per-file blocks, coverage sweep, conflict marks, guard flag); the 35-check mock logic run (`README` — the split/join/gap-policy checks). Owed at P4: the TCs minted from TC-682..711 asserting the plan model, the emitters' bytes, the abort, and the naming.
- **Numeric pass threshold:** split with `n` selected ranges → `n` files on disk named per the pattern; join → exactly 1 file `‹stem›_joined.‹ext›`; BIN limbs: byte count == `size`, gaps inside a range not padded, `.addr` content == the base address; a planted pad-over-data case aborts (0 bytes written, reason named); the demo guard case reads span 402,659,328 B (384.01 MiB) from 75,776 B (74 KiB) of data.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the files on disk byte-match what the band showed; a join that would pad 384 MiB around 74 KiB of data asks twice; nothing clobbers real bytes silently.
  - **Shipped surface:** the screen's `EXPORT ^E` → the destination folder.
  - **Acceptance test(s):** AT-297 (the export bytes + naming) · AT-298 (the guard two-step)
  - **Boundary catalog (QC-3):** ☑ boundary — a 1-byte range at the span edge stays visible (floor-one apportioning); a single-range selection in each mode; ☑ empty — a zero-coverage range (`∅ empty — 0 B of source in span`) warns and refuses a silent empty export; ☑ error — the conflict abort and the unwritable destination.
  - **Negative control:** a fill that clobbers source bytes and still writes — the abort assertion goes RED; an export that ignores the armed guard on the first `^E` — the two-step assertion goes RED.

### HLR-137 — The engine additions the screen rides
- **Traceability:** US-129
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the screen computes an output plan or writes an export, the system shall ride: a **range slicer** composing the shipped `get_memory_map` + `set_bytes_at` + emitters (bytes for `[base, base+size)`); a **BIN emitter** (none ships today); a **pad-byte fill emitter** — one gap-fill pass composing the shipped mem_map emitters with the CRC editor's `join="fill"` semantics; and the **hardened `extract_memory_segments`** — quoted multi-word `MEMORY_SEGMENT` names shall parse to full rows (base/size non-null on the shipped quoted ASAP2 demos) and the entry shall carry the `offset` field; the shipped unquoted fixtures shall keep parsing byte-identically, and the function's signature and address shall stay compatible with its existing consumers.
- **Rationale (informative):** the README's NEW-ENGINE three pieces + the recon's bug (P-6): on the shipped quoted `ASAP2_Demo_V161/V171.a2l` fixtures the extractor returns `base/size = null`; only `memorysegment.a2l` yields full rows today.
- **Validation:** `test`
- **Executed verification:** P1: P-6's code reading (`a2l.py:862-895`); the composability reading (P-14); the no-BIN grep (P-7). Owed at P4: `python -m pytest tests -q` — the unit TCs from TC-682..711 over the three new emitters and the hardened extractor (quoted + unquoted + offset fixtures).
- **Numeric pass threshold:** quoted-name fixtures → 3/3 rows with non-null base/size; `memorysegment.a2l` → its 3 rows byte-identical to today's parse; the offset field present on rows that declare one; slicer bytes == the source image's bytes on the covered sub-ranges (0 diffs); BIN bytes == `size` (0 extra, 0 missing).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the A2L tab shows full rows for real quoted A2Ls; exports in all three formats carry the bytes the preview showed.
  - **Shipped surface:** the screen's three segment-source tabs and its export path.
  - **Acceptance test(s):** exercised through AT-297's bytes; the extractor unit limbs are TCs (Layer A).
  - **Boundary catalog (QC-3):** ☑ boundary — quoted vs unquoted name forms; a segment with an offset vs without; ☑ empty — an image with no ranges yields an empty plan, never a raise.
  - **Negative control:** today's extractor on the quoted demo fixtures — the non-null assertion goes RED (the shipped bug, executed at P1).

### HLR-138 — Change 1: the save-gather and the scoped artifact homes
- **Traceability:** US-130
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the operator saves a project, the system shall COPY the JSON artifacts the project uses into the project's own folder — change-sets → `<project>\patches\`, check runs → `<project>\checks\` (a new folder; checks share the common `patches\` today), used CRC templates → `<project>\templates\` — leaving the COMMON originals untouched; the binaries shall keep their shipped copy-in (`app.py:6786-6797`); `flows\` and `reports\` stay project-only as shipped; with no project the artifacts shall keep living in the COMMON folders (`<base>\.s19tool\workarea\patches\`, `<base>\.s19tool\templates\`), the loaded files are read from their origin paths and are not copied; the gather is a snapshot stamped at save time (re-saving refreshes the project's copies).
- **Rationale (informative):** `veredicto-ronda1.json` C1 + `folders.html` §1/§3 (the behaviour spec row: "COPY, keep the common originals untouched") + OPEN_QUESTIONS #4's rationale (MOVE would silently empty the live scanners, P-10) + 7d (checks get their own folder as drawn).
- **Validation:** `test`
- **Executed verification:** P1: the shipped save path reading (P-4); the folders.html tree spec. Owed at P4: the TCs minted from TC-682..711 driving `action_save_project` over a fabricated on-disk project (the case07 idiom) and asserting the gathered tree + the untouched commons.
- **Numeric pass threshold:** after save: project `patches\`/`checks\`/`templates\` hold the used artifacts' copies (count == the used set, P3-recorded predicate); the COMMON originals all present (0 moved/deleted); with no project: 0 files created outside the COMMON homes.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the project folder is a self-contained snapshot; the Patch Editor dropdown and the CRC template library still see everything they saw.
  - **Shipped surface:** `^S` save project (the `action_save_project` path) + the on-disk tree.
  - **Acceptance test(s):** AT-299
  - **Boundary catalog (QC-3):** ☑ boundary — save with zero used artifacts (the project homes are created empty or skipped per the recorded predicate, never an error); re-save refreshes stale copies; ☑ empty — no project → nothing is gathered anywhere new.
  - **Negative control:** a MOVE-semantics implementation — the COMMON-originals assertion goes RED; a gather that fires without a project — the no-project assertion goes RED.

### HLR-139 — Change 2: the four open-folder buttons on one cross-platform seam
- **Traceability:** US-131
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the operator is on the Patch Editor, Checks, CRC Designer or Reports window, the system shall present one ghost chip `📂 Open folder` at the header-right of the window's tab strip — always visible, no key binding — opening exactly the change-1 home for that window's artifact family: Patch Editor → the change-set home (project `patches\` with a project, else COMMON `workarea\patches\`), Checks → the check-artifact home (project `checks\`, else COMMON `workarea\patches\`), CRC Designer → the template library (project `templates\`, else COMMON `.s19tool\templates\`), Reports → the project `reports\` dir; when the target folder is missing the chip shall stay visible but dimmed with a tooltip, offering to create the folder (patches/checks/templates) or staying disabled with a status-line reason (Reports without a project — the modal itself refuses there, `LLR-008.1`); every open shall ride one cross-platform seam — the shipped `subprocess.Popen(["explorer", …])` idiom (`app.py:5437`) generalized per platform (`explorer` on Windows, `open` on macOS, `xdg-open` elsewhere) — with the status-line confirmation and the failure path preserved.
- **Rationale (informative):** `veredicto-ronda1.json` C2 + `folders.html` §2/§3 (button identity, target resolution, missing-folder behaviour) + 7e (Reports button exists only in project mode). The cross-platform arm is the commission's (the `state.json` objective says cross-platform; the round's spec accepted the shipped Windows-only constraint — the contract follows the commission, recorded in the ledger).
- **Validation:** `test`
- **Executed verification:** P1: the shipped idiom reading (P-3); the four annotated captures (`folders.html` §2 — the outlined chips are the only drawn-on pixels). Owed at P4: the TCs minted from TC-682..711 pressing the four chips with a spied seam and asserting the resolved path per mode.
- **Numeric pass threshold:** 4/4 chips resolve to the change-1 home in both modes (project / no project); the seam receives exactly one open call with the resolved dir per press; the failure path sets the status line (0 unhandled exceptions); Reports-without-project: 0 open calls, a dimmed chip + a status reason.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** one click opens the file manager at the folder that window's files live in; nothing opens when the target cannot exist, and the status line says why.
  - **Shipped surface:** the four windows' tab strips + the OS file manager.
  - **Acceptance test(s):** AT-300
  - **Boundary catalog (QC-3):** ☑ boundary — project vs no-project target resolution on all four windows; a missing folder (created-on-demand vs disabled-with-reason); ☑ error — the seam's failure path (a nonexistent/unopenable dir) lands on the status line, never a traceback.
  - **Negative control:** a chip that opens a second-guessed path (e.g. the last report's dir) — the resolution assertion goes RED; an open call on a disabled Reports button — the disabled assertion goes RED.

### HLR-140 — Change 3: per-window usage help on the shipped modal pattern
- **Traceability:** US-132
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the operator asks for usage help on a window, the system shall render that window's "how to use this window's functions" section as a per-window modal following the shipped `VariantHelpScreen` pattern (`screens.py:416`) — numbered steps in plain prose, opened from a "?" affordance beside the window title and/or the `?` key while that window is focused — covering all nine authored sections of `help_sections.md` (Patch Editor · Checks · CRC Designer · Reports · Memory Map · Flow Builder · A2L Explorer · Workspace · Split / Join / Export) and dismissed with Close or Esc; the stock `?` HelpPanel (the binding list) shall remain untouched.
- **Rationale (informative):** `veredicto-ronda1.json` C3 + OPEN_QUESTIONS #6 (the round's recommendation: per-window modal — forking Textual's HelpPanel would own its internals across upgrades; `VariantHelpScreen` is shipped, tested incl. C-17 content tokens, and dismissed with Close) + `help_sections.md` (the operator-editable copy).
- **Validation:** `test`
- **Executed verification:** P1: the pattern reading (P-2); the nine authored sections against the shipped surfaces. Owed at P4: the TCs minted from TC-682..711 pressing the "?" affordance on each window and asserting the modal content + the dismiss.
- **Numeric pass threshold:** 9/9 windows render their section (each ≥3 numbered steps, zero markup-parsed file-derived strings); the modal opens from the affordance and from `?`-when-focused, and Close + Esc each dismiss 1/1; the HelpPanel binding still opens the stock panel.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the operator reads how the focused window works, in its own voice, without leaving the window.
  - **Shipped surface:** the nine windows' "?" affordances + the help modal.
  - **Acceptance test(s):** AT-301
  - **Boundary catalog (QC-3):** ☑ boundary — the new screen's section ships with the window; a window with no authored section keeps the stock help only (the affordance is absent, never a blank modal); ☑ empty — Esc/Close dismissal with no content change pending.
  - **Negative control:** a forked/replaced stock HelpPanel — the untouched-binding assertion goes RED.

### HLR-141 — Change 5a: A2L-referenced patch entries (the symbol-reference form)
- **Traceability:** US-133
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** When the operator authors a change entry while an A2L is loaded, the system shall accept an **A2L-referenced entry** — the operator's law, verbatim: *"si hay parametros declarados en el A2L, que pueda referenciarlos en el JSON (y desde el Patch Editor) para cambiar los valores"* — the change-set JSON shall gain a **symbol-reference form alongside the address form**: an entry may name an A2L tag (`"symbol": "‹tag name›"`) and the system shall resolve the name through the tag map to address + length + datatype, interpreting the set value with the **physical→raw conversion via the COMPU_METHOD enrichment** so values are written in physical units; the canonical writer shall keep emitting the resolved address so existing v2.0 readers apply the entry byte-identically; a symbol that resolves to nothing shall be a **REFUSAL whose error names the symbol**; the Patch Editor shall offer symbol resolution — a picker over the loaded A2L's tag names resolving address/length/datatype live — and the entries table shall show the symbol alongside the address.
- **Rationale (informative):** the operator's change 5 (2026-10-13, quoted in the ledger); the shipped seats: the tag map (P-16), the address-only engine (P-18), the lenient v2 wire (P-19), the Patch Editor entry path + the shipped name index (P-23). The symbol form is ADDITIVE — it never replaces the address form — per the wire-leniency law verified at P-19.
- **Validation:** `test`
- **Executed verification:** the amendment: P-16/P-17/P-18/P-19/P-23 executed readings (§2.7). Owed at P4: the TCs minted from TC-712..714 — the wire's symbol form (resolution + the lenient-reader limbs + the refusal), the physical→raw encode over the shipped COMPU_METHOD tables, the Patch Editor picker + refusal.
- **Numeric pass threshold:** a symbol entry resolves to the tag's exact address/length/datatype (0 drift from the tag map); the canonical wire carries both the `symbol` field and the resolved address; the SHIPPED v2.0 reader applies a canonical symbol entry byte-identically (0 changes to the shipped reader); the physical→raw encode round-trips the shipped decode (raw → physical → raw, 0 diffs); an unknown symbol → 0 bytes applied, the error names the symbol (1/1).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator picks a parameter declared in the A2L, sets its value in physical units, and the entry lands resolved — in the editor and in the JSON; reloading the JSON anywhere applies the same bytes.
  - **Shipped surface:** the Patch Editor's entry row + the change-set JSON (`s19app-changeset` v2).
  - **Acceptance test(s):** AT-302
  - **Boundary catalog (QC-3):** ☑ boundary — a tag with no COMPU_METHOD (raw == physical) · a value outside the tag's limits · the symbol+address coexistence on the wire; ☑ error — the unresolved-symbol refusal naming the symbol.
  - **Negative control:** a symbol-referenced entry authored without resolution (address guessed) — the resolution assertion goes RED; the shipped v2.0 reader failing on a canonical symbol entry — the leniency assertion goes RED; a refusal that omits the symbol's name — the attribution assertion goes RED.

### HLR-142 — Change 5b: the Flow Builder's A2L reference
- **Traceability:** US-133
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** When the operator builds a flow whose changes reference A2L symbols, the Flow Builder shall ask for the A2L reference — the operator's law, verbatim: *"el flow builder tendrá que pedir un A2L, ya sea del que esté cargado en el proyecto, de un folder de la aplicacion (donde viven los demas artefactos, workspace, bien organizados en folders) para usar como referencia en los cambios"* — the **Load block shall carry the A2L reference** (a Patch block may carry its own overriding reference for its change-set), declared as a project-relative filename and resolved through the **same containment guard** as the other block references, sourced from **either the loaded project's A2L or the application's organized workspace folder** (the change-1 homes, P-23); the run shall load the referenced A2L's tag map into the flow context and resolve the flow's symbol entries against it at apply time; a reference that resolves to no A2L shall **refuse the run, naming the reference**.
- **Rationale (informative):** the operator's change 5 (quoted in the ledger). The blocks' ref grammar ships (P-20) and the A2L homes ride change 1 (P-23) — no new COMMON folder is invented; the no-project home is the `.s19tool\workarea\` containment root.
- **Validation:** `test`
- **Executed verification:** the amendment: P-20/P-23 executed readings. Owed at P4: the TC minted from TC-715 — the Load/Patch `a2l_ref` resolution from both homes, the override limb, the refusing limb.
- **Numeric pass threshold:** a flow whose Load block declares the project A2L resolves its change-set's symbol entries 100% (each entry's symbol → the referenced tag map's address); the Patch-block override wins for its change-set only; a reference resolving to nothing → the run applies 0 entries and the error names the reference (1/1).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator declares the A2L on the flow (defaulting to the project's), and the flow's symbol-referenced changes apply resolved; a dangling reference stops the run with the reason.
  - **Shipped surface:** the Flow Builder's Load/Patch block forms + the flow run.
  - **Acceptance test(s):** AT-303
  - **Boundary catalog (QC-3):** ☑ boundary — project vs no-project source resolution · the Patch-block override vs the Load-block default · a flow mixing address-form and symbol-form entries; ☑ error — the dangling-reference refusal naming the reference.
  - **Negative control:** a run that resolves symbols against an undeclared/implicit A2L — the reference assertion goes RED; a dangling reference that applies anyway — the refusal assertion goes RED.

### HLR-143 — Change 5c: the report attribution (every change named; the A2B diff references all flow changes)
- **Traceability:** US-133
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** When a flow run reports, **everything shall land in the report** — the operator's laws, verbatim: *"Todo esto debe terminar en el reporte"* and *"si al final se pone un bloque de reporte A2B diff, y el input es un s19 que acaba de pasar por un flujo, todos los cambios del flujo deben referenciarse"* — the flow report shall attribute **every change the flow applied**: each entry named by its **symbol when symbol-referenced and always by its resolved address**, with the before/after bytes per the shipped report grammar; and when a report block emits an **A2B diff whose input B is an image this flow produced**, the diff shall **reference ALL the flow's changes** — each differing run attributed to the change entry/entries that produced it (by address-range intersection, the shipped linkage idiom), and every flow change listed at least once, a change with no differing run included as a no-diff entry.
- **Rationale (informative):** the operator's change 5 (quoted in the ledger) — the diff attribution is the operator's key law. The seats: the per-entry report grammar ships (P-21); the diff run table + reverse symbol annotation ship (P-22) — the change-set attribution is net-new on both.
- **Validation:** `test`
- **Executed verification:** the amendment: P-21/P-22 executed readings. Owed at P4: the TCs minted from TC-716..717 — the flow-report attribution section, the A2B diff reference law over a flow-produced image.
- **Numeric pass threshold:** the flow report's change section lists 100% of the applied entries (each row: symbol when present + resolved address + before/after bytes); the A2B diff block over a flow-produced image references 100% of the flow's changes (each differing run carries its producing entry/entries; changes with no diff appear as no-diff entries — 0 flow changes unreferenced).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator reads which parameter (or address) every applied change touched, and a diff of the flow's own output points back at every change that produced it — nothing the flow did is unnamed.
  - **Shipped surface:** the flow report + the A2B diff report block (the report block of a flow).
  - **Acceptance test(s):** AT-304
  - **Boundary catalog (QC-3):** ☑ boundary — a flow change whose bytes produce no diff (the no-diff listing) · a diff run produced by several entries · a flow report over an address-only change-set; ☑ empty — a report block with no prior flow changes emits the diff with the shipped best-effort symbols only, never a crash.
  - **Negative control:** an A2B diff block over a flow-produced image that omits one of the flow's changes — the reference-all assertion goes RED; a report row naming neither symbol nor address — the attribution assertion goes RED.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### LLR-135.1 — The graft chassis
- **Traceability:** HLR-135
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The screen shall compose the V1 chassis: segment-source chips, the range table (cursor movement, `●`/`○` per-row selection, the coverage column), one control row per setting (MODE / GAPS+PAD / FORMAT / DEST / NAMING), and the right PREVIEW pane with the output label, the union band, the legend, the address ruler, the stats + guard chip, the summary, and the `EXPORT ^E` button; the pane chrome shall use the `.db-pane` idiom (`styles.tcss:334`), the border title `PREVIEW`.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC driving the shipped screen headless at 118×34 and querying the DOM for the chassis order.
- **Numeric pass threshold:** 8/8 control/preview surfaces in the contracted order at both geometries; 0 hand-typed style lists on the new ids (styles via `styles.tcss`).
- **Negative control:** a chassis that stacks the preview under the table at 118 columns — the order assertion goes RED.
- **Boundary catalog:** none — chrome is state-independent (the empty state renders the all-context map + the tick-a-row note, never a blank pane).

### LLR-135.2 — The visor class system
- **Traceability:** HLR-135 · HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The band shall render exactly the five classes — `▓` data `#91abec` · `░` fill `#6b7280` · `▒` conflict `#f6ff8f` · `·` context `#46557a` · (space) absent — one styled span per block (12–14 runs per row at any width, coalesced by construction, never one run per cell); the column apportioning shall be `floor-one-then-largest-remainder` bounded by the measured container width (every block ≥ 1 column); address space maps linearly to columns; the ruler shall render the `0xXXXXXXXX` ends (+ midpoint when it fits) of the band's real span.
- **Validation:** `test (unit)`
- **Executed verification:** P1: the prototype's run census + the bench (design_notes §5/§9 — 0.16–0.54 runs/cell; H@60 17–27 @80×24, 8–13 @120×36). Owed at P4 — a unit TC over the band builder: class mapping, run census, floor-one apportioning at hostile widths.
- **Numeric pass threshold:** class→glyph→hex mapping exact (5/5); runs per band row ≤ 14 at every tested width; a 1-byte block keeps ≥ 1 column inside a 57 KiB span; the band width == its container's measured width (0 predicate-over-text bounds).
- **Negative control:** per-cell markup (the ≈6.9 µs/cell failure mode) — the run-census assertion goes RED; a √/log-scaled address map — the linearity assertion goes RED.
- **Boundary catalog:** ☑ boundary — the 1-byte block inside a huge span; a width-0 first frame (no paint against width 0, the batch-93 bounded-retry discipline).

### LLR-135.3 — The two-regime reflow at the measured thresholds
- **Traceability:** HLR-135
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The regime decision shall read the measured screen width: ≥ 118 → the `wide` class (preview pane 58, band 54 cells); < 100 → `narrow` (pane 30, compact vocabulary, gantt wrap display-none); between them the base 40-column pane stands; the threshold shall sit at 118 (the measured geometry `run_test(size=(120,36))` actually hands the app), never the nominal 120; on resize the band, the gantt and the ruler re-apportion against the then-measured width.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC piloting 160×48 → 120×36 → 96×30 → 80×24 and asserting the pane widths + the gantt visibility at each settle.
- **Numeric pass threshold:** 0 regime mismatches across the pilot (pane 58 at ≥118 · 40 mid · 30 below 100); the gantt hidden below 100 and at >6 files; 0 stale-width surfaces after any settle.
- **Negative control:** a regime keyed on the terminal's nominal width — at 118×34 the wide class never sets and the assertion goes RED.
- **Boundary catalog:** ☑ boundary — the 118 threshold itself, the 100 narrow threshold, and the 80×24 floor.

### LLR-135.4 — The split-mode per-file gantt
- **Traceability:** HLR-135
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** In split mode with a non-empty selection of 1..6 files, the preview pane shall render the per-file gantt under the union map — one row per output file (label · the file's own byte band · its size) — and shall hide the wrap otherwise (join mode, 0 files, or > 6 files; at the floor the CSS hides it by construction); an empty file shall render its `∅ empty — 0 B of source in span` row.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the gantt show/hide confirmed by class and by computed `display` at both regimes (design_notes §9). Owed at P4 — a TC at 1/2/6/7 selected ranges and both regimes.
- **Numeric pass threshold:** gantt visible exactly when (split ∧ 1 ≤ files ≤ 6); row count == the selected file count; each row's band re-apportions to the measured width; the union map remains rendered in all limbs.
- **Negative control:** a gantt that renders in join mode or at 7 files — the show/hide assertion goes RED.
- **Boundary catalog:** ☑ boundary — the 1-file split, the 6/7 file cap, the empty-file row.

### LLR-135.5 — The span guard's two-step
- **Traceability:** HLR-135 · HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the plan is `join=fill` with span ≥ 1 MiB (`GUARD_SPAN_MIN`) and fill ≥ 50% of the span (`GUARD_FILL_MIN`), the guard chip shall render in the stats (`⚠ GUARD …`) and the first `^E` shall arm the guard only — no write — with a warning naming the span, the data size and the pad percentage; any state change (selection, mode, gap, pad, format, destination, naming) shall disarm; the second `^E` while still armed shall export.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the guard frame (`final_guard_120x36.svg` — the 402 MB `░` sea) + the 27-key tour's two-step. Owed at P4 — a TC on the demo guard case (3 A2L segments, join=fill) asserting arm → disarm → re-arm → confirm.
- **Numeric pass threshold:** first `^E` writes 0 bytes and flips the armed flag; a state change clears it (armed 0/1 limbs); the second `^E` writes exactly the planned files; below the thresholds the guard never fires (0 arms).
- **Negative control:** an export that writes on the first `^E` while the guard is up — the two-step assertion goes RED.
- **Boundary catalog:** ☑ boundary — span exactly 1 MiB ± 1 and fill fraction exactly 0.5 ± ε (the thresholds are tested inputs); ☑ error — the toast carries `markup=False`.

### LLR-135.6 — Palette-first entry and Esc close
- **Traceability:** HLR-135
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The screen shall open from the shipped `^K` palette (`app.py:1335` binding) as the entry named "Split / Join / Export" and shall bind NO rail key; `Esc` shall close the screen (and every modal this batch adds); the footer/status surfaces shall advertise the palette entry, not a fabricated key.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC invoking the palette entry and pressing Esc.
- **Numeric pass threshold:** the palette lists exactly one entry reaching the screen; 0 rail bindings added to `app.py:1362-1371`'s set; Esc closes 1/1 from focus and from the preview pane.
- **Negative control:** a new rail binding — the binding-census assertion goes RED.
- **Boundary catalog:** none.

### LLR-135.7 — The three segment sources with the ranges-first default
- **Traceability:** HLR-135 · HLR-137
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The table shall offer three segment sources — A2L `MEMORY_SEGMENT`s (the hardened extractor's rows), the image's own contiguous ranges (`get_memory_ranges` / `get_ranges`), and manual localities — with the ranges source as the default tab in all cases (ranges are always available and never empty); with no A2L loaded the A2L tab shall stay clickable with the neutral note `no A2L loaded — load one (^L) or use ranges/manual`, never silently disabled; the manual tab shall accept one range per line, hex, inclusive end (`0x0000EB00-0x0000EBFF`), tolerating spaces, uppercase `0X`, and bare hex; unparsable lines shall be dropped and named in the status line; A2L/ranges tables stay read-only.
- **Validation:** `test (unit)` + `test (integration)`
- **Executed verification:** P1: `tui_prototype.py:853` — the shipped-by-design default `self._tab = "s19"`; `parse_manual` (:141-153) — the tolerant parser + inclusive end. Owed at P4 — unit TCs over the parser + an integration TC over the three tabs' states with/without an A2L.
- **Numeric pass threshold:** default tab = ranges at every entry path (with and without an A2L); the no-A2L tab renders the neutral note and stays focusable (0 disabled states); the parser yields `end = last byte` (size `hi − lo + 1`) for the tolerant forms and drops + reports 100% of the garbage lines.
- **Negative control:** the A2L tab disabled with no A2L — the clickable-empty assertion goes RED; a manual parse that treats the end as exclusive — the size assertion goes RED (the ±1 trap the ruling closed).
- **Boundary catalog:** ☑ boundary — the inclusive-end convention (`END = last byte`, the typed value equals the shown value); ☑ invalid — garbage manual lines are dropped, listed, and never crash the tab.

### LLR-136.1 — Split mode and the per-file intra-gap
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** In split mode the system shall plan one output file per selected range; with `intra_gap=skip` each file carries only its covered sub-ranges (sparse, today's emitter semantics); with `intra_gap=fill` each file's span `[base, base+size)` shall be padded with the pad byte across the gaps BETWEEN the source sub-ranges inside that file's own span — never across files, never outside the file's span; each file's band and the union map shall render the same classes the file will contain.
- **Validation:** `test (unit)`
- **Executed verification:** P1: the plan model (`build_plan`, `tui_prototype.py:277-331` — per-file marks, per-file bands). Owed at P4 — a unit TC with a gapped range (bytes only in patches) under both policies.
- **Numeric pass threshold:** skip → the file's bytes == the covered sub-ranges concatenated (0 pad bytes); fill → the file's bytes == `size` (pad bytes == the intra-span gaps with source bytes untouched); per-file pad counts match the bands.
- **Negative control:** a split-fill that pads across files (or outside a file's span) — the byte assertion goes RED.
- **Boundary catalog:** ☑ boundary — a range fully covered (0 intra-gaps under both policies) and a range with zero coverage (`∅`).

### LLR-136.2 — Join concat from the first range's base
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** In join mode with `join=concat`, the system shall sort the selected ranges ascending by base, concatenate their covered bytes back-to-back into the single output whose base address is the first (lowest) range's base, name it `‹stem›_joined.‹ext›`, and the band shall cover `[0, packed)` as pure `▓` with the dim note `offsets remapped` (no fills or context are addressable there).
- **Validation:** `test (unit)`
- **Executed verification:** P1: `build_plan` concat branch (`tui_prototype.py:259-275`). Owed at P4 — a unit TC on ordering, packing and the base.
- **Numeric pass threshold:** output bytes == the ranges' covered bytes in ascending-base order (0 reorder); the emitted base == the lowest range's base; the band carries 0 fill/conflict/context cells.
- **Negative control:** a concat whose base is an arbitrary chosen value — the base assertion goes RED (ruling Q2).
- **Boundary catalog:** ☑ boundary — a zero-coverage selection under concat (the empty-file limb of LLR-136.6).

### LLR-136.3 — Join fill at the original offsets
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** In join mode with `join=fill`, the system shall keep the selected ranges at their ORIGINAL offsets — span = last end − first base — padding the gaps with the pad byte; the band shall cover the union of the source image and the selected span (source annotated by output class: `·` context where unselected source exists); no chosen-base variant shall ship (manual localities cover custom spans).
- **Validation:** `test (unit)`
- **Executed verification:** P1: `build_plan` fill branch (`tui_prototype.py:280-293`) + the guard frame (the 384.01 MiB case rendered). Owed at P4 — a unit TC asserting the demo case's span and content placement.
- **Numeric pass threshold:** the demo case (3 A2L segments, join=fill) plans span 402,659,328 B with the 75,776 data bytes at their original offsets; `·` cells cover exactly the unselected source bytes inside the band's span.
- **Negative control:** a join=fill that re-bases the output — the offset assertion goes RED (ruling Q4).
- **Boundary catalog:** ☑ boundary — adjacent ranges (0 gap) and disjoint ranges under the same policy.

### LLR-136.4 — Pad byte 0x00 and the conflict abort
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The pad byte shall default to `0x00` (ruling Q1/8a — deliberately diverging from the CRC editor's `0xFF`, P-9) and be user-configurable (one control, cycled or typed); when a `fill` pad would overwrite real source bytes (source bytes inside a pad span), the export shall ABORT with a reason naming the offending span (the fixed `on_gap_conflict="abort"` behaviour adopted from the CRC editor, 8f) and the band shall render those bytes as `▒`.
- **Validation:** `test (unit)`
- **Executed verification:** P1: the conflict marks in `_sweep`/`build_plan` (priority `conflict` > `fill`). Owed at P4 — a unit TC planting source bytes inside a pad span.
- **Numeric pass threshold:** the default pad is `0x00` at every entry path; a planted conflict → 0 bytes written, the reason names the span, the plan's conflict count == the planted byte count.
- **Negative control:** a fill that clobbers source bytes and writes — the abort assertion goes RED (as the shipped CRC `abort` would).
- **Boundary catalog:** ☑ error — the conflict class is the error limb.

### LLR-136.5 — Naming, destination and the live sample
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The naming pattern shall default to `‹stem›_‹segment›` and resolve to `‹stem›_‹segment›.‹ext›` per split file and `‹stem›_joined.‹ext›` for join (`‹segment›` → `joined`); the sample filename shall update live with stem/pattern/format/selection; the destination shall follow the change-1 homes (project or COMMON) and the output label in the preview pane shall render the resolved join name / the split file count.
- **Validation:** `test (unit)`
- **Executed verification:** P1: `resolve_sample` (`tui_prototype.py:346-347`) + the outlabel sync (`:1094-1097`). Owed at P4 — a unit TC over the resolver and the sample.
- **Numeric pass threshold:** the resolver maps the three tokens for every mode/format limb; the sample == the first resolved file name (0 stale samples after any change).
- **Negative control:** a sample that survives a format change — the freshness assertion goes RED.
- **Boundary catalog:** none.

### LLR-136.6 — Zero coverage as a first-class state
- **Traceability:** HLR-136
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** A selected range whose span holds no source bytes shall render as a first-class state: the coverage column shows the zero-coverage marker, the stats name it, the gantt row reads `∅ empty — 0 B of source in span`, and exporting it shall require an explicit confirm (the round's 7c recommendation — zero coverage is the norm on real A2L/S19 pairs, not an edge).
- **Validation:** `test (integration)`
- **Executed verification:** P1: the 3 A2L segments over `prg.s19` (0 B of 75,776 B — `extracted.json` executes to zero intersections). Owed at P4 — a TC exporting a zero-coverage selection.
- **Numeric pass threshold:** the confirm gate fires exactly on empty files (0 silent empty exports); with the confirm, the empty file (0 bytes for BIN / header-only for S19/HEX per the emitters' shipped semantics) writes.
- **Negative control:** an empty file written without the confirm — the gate assertion goes RED.
- **Boundary catalog:** ☑ empty — the zero-coverage range is the tested empty class.

### LLR-137.1 — The range slicer
- **Traceability:** HLR-137
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The slicer shall return exactly the source image's bytes on `[base, base+size)` — the covered sub-ranges composed via the shipped `get_memory_map` + `set_bytes_at` + emitters (P-14) — exposing per-range bytes to the split/join emitters without touching the parsers.
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — a unit TC slicing gapped and ungapped ranges out of the demo images.
- **Numeric pass threshold:** sliced bytes == the source image's bytes on the covered sub-ranges (0 diffs); an out-of-image range yields empty coverage, never a raise.
- **Negative control:** a slicer that pads or invents bytes — the byte-equality assertion goes RED.
- **Boundary catalog:** ☑ boundary — a range partially inside the image; an empty image.

### LLR-137.2 — The BIN emitter and the `.addr` sidecar
- **Traceability:** HLR-137
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The BIN emitter shall write exactly `size` flat bytes starting at the segment base — no gap padding inside a range, no embedded base address — and a one-line sidecar `‹name›.addr` carrying the base address (e.g. `0x08000000`), so the base stays recoverable from the pair (the round's #2 recommendation).
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — a unit TC on the demo ranges + the sidecar.
- **Numeric pass threshold:** byte count == `size` (0 extra/missing); the sidecar's single line parses as the segment's base; the S19/HEX emitters stay byte-identical for the same plan.
- **Negative control:** a BIN with an embedded header — the flat-bytes assertion goes RED.
- **Boundary catalog:** ☑ boundary — a zero-coverage range (0-byte file + sidecar, behind the LLR-136.6 confirm).

### LLR-137.3 — The pad-byte fill emitter
- **Traceability:** HLR-137
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The fill emitter shall compose the shipped mem_map emitters with one gap-fill pass — the pad byte written across the pad spans, the CRC editor's `join="fill"` semantics (P-8) — for both split (`intra_gap=fill`) and join (`join=fill`).
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — a unit TC comparing its output to the CRC coverage path's fill on the same image.
- **Numeric pass threshold:** filled bytes == pad byte at every pad span; data bytes == the source bytes (0 clobbered — the abort limb of LLR-136.4 fires first).
- **Negative control:** a fill pass that runs after the emitters (unfilled gaps) — the byte assertion goes RED.
- **Boundary catalog:** none.

### LLR-137.4 — The hardened `extract_memory_segments`
- **Traceability:** HLR-137
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The extractor shall parse quoted multi-word `MEMORY_SEGMENT` names (tokenizing quotes as single tokens) so the shipped quoted fixtures (`ASAP2_Demo_V161/V171.a2l`) yield full rows with non-null base/size; each entry shall carry the `offset` field when the block declares one; the unquoted fixtures (`memorysegment.a2l`) shall parse byte-identically to today; the function's signature and its consumers (`a2l.py:1448`, `a2l.py:1676`, the `a2l_parse` re-export) shall keep working unchanged; XCP `IF_DATA SEGMENT` extraction stays out of scope (punted, recorded).
- **Validation:** `test (unit)`
- **Executed verification:** P1: P-6 (the bug, executed). Owed at P4 — a unit TC over quoted/unquoted/offset fixtures.
- **Numeric pass threshold:** quoted fixtures → 3/3 rows non-null base/size; the unquoted fixture's rows == today's parse (0 diffs); the offset field present where declared.
- **Negative control:** today's extractor on the quoted fixtures — the non-null assertion goes RED (executed at P1).
- **Boundary catalog:** ☑ boundary — quoted vs unquoted names; an offset vs none.

### LLR-138.1 — Gathering the used change-sets
- **Traceability:** HLR-138
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** On save with a project, the system shall COPY the change-set JSONs the project uses into `<project>\patches\` (creating it), leaving the COMMON `workarea\patches\` originals untouched; the Patch Editor dropdown's scan (US-026) shall observe no change.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC saving the fabricated on-disk project and diffing both trees.
- **Numeric pass threshold:** used change-set copies land in `<project>\patches\` (count == the used set per the recorded predicate); COMMON originals 100% present.
- **Negative control:** a MOVE (common original gone) — the presence assertion goes RED.
- **Boundary catalog:** ☑ empty — zero used change-sets → the folder is created empty or skipped per the recorded predicate, never an error.

### LLR-138.2 — Gathering the check runs into the new `checks\` home
- **Traceability:** HLR-138
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** On save with a project, the system shall COPY the project's check-run artifacts into `<project>\checks\` — a new folder; checks share the common `patches\` today and get their own project home as drawn (7d).
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — same TC as LLR-138.1, the checks limb.
- **Numeric pass threshold:** used check-run copies land in `<project>\checks\`; COMMON check artifacts untouched.
- **Negative control:** check runs dumped into the project `patches\` — the folder assertion goes RED.
- **Boundary catalog:** ☑ empty — a project that never ran checks → empty/no `checks\`, never an error.

### LLR-138.3 — Gathering the used CRC templates
- **Traceability:** HLR-138
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** On save with a project, the system shall COPY the CRC templates the project uses into `<project>\templates\`, leaving the COMMON `.s19tool\templates\` library (the cross-project `ensure_template_lib`, batch-58 F3) untouched.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — the templates limb of the save TC.
- **Numeric pass threshold:** used template copies land in `<project>\templates\`; the COMMON library byte-untouched.
- **Negative control:** a template MOVED out of the COMMON library — the library assertion goes RED.
- **Boundary catalog:** none.

### LLR-138.4 — No-project mode and the snapshot semantics
- **Traceability:** HLR-138
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** With no project saved, the system shall gather nothing and the artifacts shall stay in the COMMON folders; the loaded S19/HEX/MAC/A2L files shall be read from their origin paths (not copied); every gather is a COPY stamped at save time — re-saving refreshes the project's copies, and divergence from later COMMON edits is accepted (same semantics as the shipped binaries copy).
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a no-project save TC + a re-save refresh TC.
- **Numeric pass threshold:** no-project save → 0 new files outside the COMMON homes; re-save → stale copies refreshed (mtime/content == the COMMON original's).
- **Negative control:** a gather firing without a project — the no-project assertion goes RED.
- **Boundary catalog:** ☑ empty — the no-project mode is the tested empty class.

### LLR-139.1 — The four chips and their target homes
- **Traceability:** HLR-139
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** Each of the four windows shall carry one ghost chip `📂 Open folder` at its tab strip's header-right — always visible, no key binding — resolving its target to exactly the change-1 home: Patch Editor → change-set home (project `patches\` / COMMON `workarea\patches\`), Checks → check-artifact home (project `checks\` / COMMON `workarea\patches\`), CRC Designer → template library (project `templates\` / COMMON `.s19tool\templates\`), Reports → project `reports\`; the resolution shall follow change 1 with no second-guessing and no per-file logic.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the four annotated captures (`folders.html` §2). Owed at P4 — a TC pressing each chip in both modes with a spied seam.
- **Numeric pass threshold:** 4/4 chips resolve to the contracted home in both modes (8/8 limbs); the chip renders header-right on all four windows.
- **Negative control:** a chip resolving to a per-file guess — the resolution assertion goes RED.
- **Boundary catalog:** ☑ boundary — project vs no-project target resolution on all four.

### LLR-139.2 — The missing-folder and no-project behaviours
- **Traceability:** HLR-139
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** When the target folder is missing the chip shall stay visible but dimmed with the tooltip `no project — files are in the common folders` / `folder does not exist yet`; on press it shall offer to create the folder (patches/checks/templates) or stay disabled with a status-line reason (Reports without a project — the Reports modal refuses there today, `LLR-008.1`); the Reports chip exists only in project mode.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC over the missing-folder limbs and the no-project Reports limb.
- **Numeric pass threshold:** dimmed + tooltip on every missing-target limb; the create-offer creates exactly the offered folder; Reports-without-project → 0 open calls + a status reason.
- **Negative control:** an enabled Reports chip without a project — the disabled assertion goes RED (7e).
- **Boundary catalog:** ☑ boundary — missing vs present folder; project vs no project.

### LLR-139.3 — The cross-platform open seam
- **Traceability:** HLR-139
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** All opens shall ride one shared seam — the shipped `action_open_workarea` idiom (`subprocess.Popen([opener, dir])`, `app.py:5437`) generalized per platform: `explorer` on Windows, `open` on macOS, `xdg-open` on other POSIX — preserving the status-line confirmation (`Opened …`) and the caught-failure path (`Failed to open …`), and leaving the shipped `o`-key behaviour untouched.
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — a unit TC spying `subprocess.Popen` per platform arm.
- **Numeric pass threshold:** each platform arm issues exactly one Popen with the resolved dir and the platform opener; a Popen failure → the status line names it (0 escapes).
- **Negative control:** a seam that shells a bare string on POSIX — the argv assertion goes RED.
- **Boundary catalog:** ☑ error — the opener's exception path.

### LLR-140.1 — The per-window modal on the shipped pattern
- **Traceability:** HLR-140
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** Each window's usage help shall render as a modal on the shipped `VariantHelpScreen` pattern (`screens.py:416`) — numbered steps in plain prose, no markup parsing — opened from a "?" affordance beside the window title and/or the `?` key while that window is focused; Close and Esc shall dismiss it; the stock `?` HelpPanel (the binding list) shall remain the app-wide key reference, untouched.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC opening the modal from both affordances on each window and pressing Close + Esc.
- **Numeric pass threshold:** 9/9 windows render their section; both affordances open, both dismissers close; the HelpPanel binding still opens the stock panel.
- **Negative control:** a replaced/forked HelpPanel — the untouched-binding assertion goes RED.
- **Boundary catalog:** ☑ boundary — a window with no authored section keeps stock help only (no affordance, never a blank modal).

### LLR-140.2 — The authored sections ship operator-editable
- **Traceability:** HLR-140
- **Ledger:** LED-2026-10-13-batch-95.1
- **Statement:** The nine sections shall ship from the authored copy (`help_sections.md` — Patch Editor · Checks · CRC Designer · Reports · Memory Map · Flow Builder · A2L Explorer · Workspace · Split / Join / Export), each ≥ 3 numbered steps in the shipped `VariantHelpScreen` voice; the copy lives in one editable home per the operator's inline-editing workflow.
- **Validation:** `test (unit)`
- **Executed verification:** P1: the nine sections read against the shipped code and the real captures (the draft's own claim). Owed at P4 — a content census TC (section ↔ window, step counts).
- **Numeric pass threshold:** 9/9 sections present, each ≥ 3 steps; the new screen's section ships with the window.
- **Negative control:** a section hand-edited into markup-laden text — the markup-free assertion goes RED (S1).
- **Boundary catalog:** none.

### LLR-141.1 — The symbol-reference form in the change-set wire
- **Traceability:** HLR-141
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** The `s19app-changeset` v2 entry grammar shall accept an **optional `symbol` field** — the A2L tag name — **alongside** the address form, never replacing it (P-19): the canonical writer shall emit a symbol-referenced entry with BOTH the `symbol` field and the resolved address, so the shipped v2.0 reader applies it byte-identically with no reader change; at read time an entry carrying `symbol` shall resolve the name through the referenced A2L's tag map to address + length + datatype (P-16), interpreting the set value with the physical→raw conversion composed from the shipped COMPU_METHOD side tables (P-17 — decode ships, encode composes); an entry whose symbol resolves to nothing — no such tag, a tag without address or length, or no A2L context — shall be **REFUSED at load with an entry-level issue naming the symbol** (the `CHG-*` issue family, entry skipped, 0 bytes applied); address-only entries shall read and write byte-identically to today.
- **Validation:** `test (unit)`
- **Executed verification:** the amendment: P-16/P-17/P-19 readings. Owed at P4 — unit TCs over the wire: the symbol form's resolution, the lenient-reader limbs, the refusal, the encode round-trip.
- **Numeric pass threshold:** symbol resolution == the tag map's address/length/datatype (0 drift); the canonical bytes for a symbol entry == the address entry's bytes + the added `symbol` field (the shipped reader applies them unchanged — executed against today's reader); the physical→raw encode round-trips the shipped decode (0 diffs); the refusal names the symbol (1/1) and applies 0 bytes.
- **Negative control:** a wire form where `symbol` replaces `address` — the shipped reader drops it (`CHG-ADDRESS-SYNTAX`) and the leniency assertion goes RED; a silent skip of the unresolved symbol — the refusal assertion goes RED.
- **Boundary catalog:** ☑ boundary — a tag with no COMPU_METHOD (raw == physical) · a value outside the tag's limits (flagged, the write proceeds per the recorded P3 limb) · the symbol+address coexistence on one entry; ☑ invalid — a `symbol` naming nothing is refused, named, never applied.

### LLR-141.2 — The Patch Editor's symbol resolution and picker
- **Traceability:** HLR-141
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** The Patch Editor's entry-add row shall gain a **symbol input with a picker** over the loaded A2L's tag names (the shipped name-index idiom, `app.py:525-535`): picking or typing a symbol shall resolve address/length/datatype live into the entry (the value interpreted in physical units per LLR-141.1); the entries table shall render the symbol alongside the address (a `Symbol` column beside the shipped `Kind/Address/Value/Status/Linkage` set, `screens_directionb.py:5126`); with no A2L loaded the symbol input shall be absent (never a dead control — the address form carries the row alone); an unknown symbol shall **REFUSE the add, the status line naming the symbol**.
- **Validation:** `test (integration)`
- **Executed verification:** the amendment: P-23 reading (the add-row + `add_entry` path). Owed at P4 — a TC driving the picker, the live resolution, the table column, and the refusal.
- **Numeric pass threshold:** the picker lists exactly the loaded A2L's tag names; picking resolves the entry's address/length to the tag map's values (0 drift); the table shows symbol + address for symbol entries and address alone for address entries; the refusal names the symbol (1/1), 0 entries added.
- **Negative control:** an entry added with a guessed address under a symbol label — the resolution assertion goes RED; a refusal that adds anyway or omits the name — the refusal assertion goes RED.
- **Boundary catalog:** ☑ boundary — the no-A2L limb (the symbol input absent, the row fully usable by address) · editing an existing symbol entry back to the address form.

### LLR-142.1 — The Load/Patch blocks carry the A2L reference
- **Traceability:** HLR-142
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** The flow's **Load (`source`) block shall carry an optional `a2l_ref`** — a project-relative A2L filename in the shipped ref grammar (P-20) — resolved through the same manifest containment guard as `image_ref`/`change_doc_ref`; a **Patch block may carry its own `a2l_ref`**, overriding the Load block's for that change-set only; at run time the resolved A2L's tag map shall be loaded into the flow context (`FlowContext.a2l_data`, P-20) BEFORE the patch arms apply, so symbol entries resolve against it per LLR-141.1; the flow JSON shall round-trip the fields; when no `a2l_ref` is declared anywhere, symbol entries shall be refused per LLR-141.1 (no implicit A2L).
- **Validation:** `test (unit)`
- **Executed verification:** the amendment: P-20 reading. Owed at P4 — unit TCs over the block model, the resolution order, the override limb, the round-trip.
- **Numeric pass threshold:** the Load block's `a2l_ref` resolves through the containment guard (1 guard call per resolution); the Patch override wins for its change-set only (the flow's other patches resolve against the Load block's); the flow JSON round-trips both fields byte-identically; a run with symbol entries and no declared reference refuses 100% of them, named.
- **Negative control:** an implicit-A2L run (resolving symbols against whatever is loaded) — the no-implicit assertion goes RED; an override leaking to sibling patches — the override-scope assertion goes RED.
- **Boundary catalog:** ☑ boundary — Load-carried vs Patch-override vs undeclared (the three declaration limbs); ☑ invalid — an `a2l_ref` escaping the containment guard is refused like any other ref.

### LLR-142.2 — The A2L reference's source: the project or the organized workspace folder
- **Traceability:** HLR-142
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** The `a2l_ref` shall resolve **first against the project folder** — the shipped home of the loaded project's A2L (saved flat at the project root by the shipped save, `app.py:6796`, under the single-A2L guard `:6774-6783`) — and, with no project, **against the organized workspace tree** under `<base>\.s19tool\workarea\` (the change-1 artifact homes' containment root, P-23); the Flow Builder's block form shall offer exactly these two sources — *"del que esté cargado en el proyecto, de un folder de la aplicacion (donde viven los demas artefactos, workspace, bien organizados en folders)"* — and a reference resolving to no A2L in either home shall **refuse the run, the error naming the reference**.
- **Validation:** `test (integration)`
- **Executed verification:** the amendment: P-23 reading. Owed at P4 — a TC saving a project with an A2L, running a flow in project mode and no-project mode, and asserting both resolution arms + the refusal.
- **Numeric pass threshold:** project mode resolves the project-root A2L (1/1); no-project mode resolves an A2L under the workarea containment root (1/1); a reference present in neither home → the run applies 0 entries, the error names the reference (1/1); the block form offers no third source.
- **Negative control:** a resolution that second-guesses the reference against a path outside the two homes — the source assertion goes RED; a dangling reference that runs — the refusal assertion goes RED.
- **Boundary catalog:** ☑ boundary — project vs no-project source arms · the loaded-but-unsaved A2L (not yet a project home — the operator saves or picks the workspace copy).

### LLR-143.1 — The flow report attributes every change by symbol/address
- **Traceability:** HLR-143
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** The flow report shall carry a **change-attribution section** listing every entry the flow's patch arms applied — one row per entry in the shipped per-entry grammar (P-21): symbol when the entry is symbol-referenced + always the resolved address + length + before/after bytes + the A2L reference the entry resolved against; the section shall render even when the flow also emits a standalone change-set report (the flow report stands alone — *"Todo esto debe terminar en el reporte"*, this section is where the flow's changes terminate).
- **Validation:** `test (integration)`
- **Executed verification:** the amendment: P-21 reading. Owed at P4 — a TC over a multi-patch flow asserting the section's rows against the applied change-sets.
- **Numeric pass threshold:** rows == applied entries (100%, 0 unlisted); every row names the symbol (when present) AND the resolved address; before/after bytes == the applied bytes (0 diffs); the rendering reuses the shipped report grammar (no second table dialect).
- **Negative control:** an attribution section listing only symbol entries (address-only entries omitted) — the census assertion goes RED; a row naming neither symbol nor address — the attribution assertion goes RED.
- **Boundary catalog:** ☑ boundary — a flow mixing symbol-referenced and address-only entries · zero applied changes (the section renders empty, never absent).

### LLR-143.2 — The A2B diff block references all the flow's changes
- **Traceability:** HLR-143
- **Ledger:** LED-2026-10-13-batch-95.2
- **Statement:** When a report block emits an **A2B diff whose input B is an image this flow run produced**, the diff shall **reference ALL the flow's changes** — the operator's law, verbatim: *"si al final se pone un bloque de reporte A2B diff, y el input es un s19 que acaba de pasar por un flujo, todos los cambios del flujo deben referenciarse"* — each differing run shall carry the change entry/entries that produced it (attributed by address-range intersection, the shipped linkage idiom extended forward, P-18/P-22), and **every flow change shall be listed at least once** — an entry whose bytes produced no differing run shall appear as an explicit no-diff reference; when B is NOT a flow product, the diff shall render as shipped (best-effort symbols, no change attribution, P-22).
- **Validation:** `test (integration)`
- **Executed verification:** the amendment: P-22 reading. Owed at P4 — a TC running a flow, diffing source vs the flow's output through the report block, and asserting the reference-all law.
- **Numeric pass threshold:** the diff block references 100% of the flow's applied entries (each differing run names its producing entry/entries; no-diff entries appear as no-diff references — 0 flow changes unreferenced); the attribution is exact (a run names an entry iff the entry's address range produced run bytes); a non-flow B renders the shipped report unchanged (0 drift).
- **Negative control:** a diff block over a flow-produced image omitting one flow change — the reference-all assertion goes RED; an attribution naming an entry that produced no run bytes — the exactness assertion goes RED.
- **Boundary catalog:** ☑ boundary — a run producing zero diffs (all entries as no-diff references) · one run produced by several entries · B not a flow product (the shipped limb).

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:**

```
FLOW: split_join_screen
  SOURCE : the loaded image (S19/HEX ranges via get_memory_ranges/get_ranges) ; the loaded A2L's
           MEMORY_SEGMENT rows (extract_memory_segments, hardened) ; manual localities ; the
           operator's selections (tab, rows, mode, gap, pad, format, destination, naming) ; the
           change-1 destination homes
  NODES  :
    - fn    : the three segment-source tabs + the ranges-first default + the manual parser
      owner : LLR-135.7
      in    : image ranges ; A2L rows ; manual text
      out   : a uniform SegRow list per tab
    - fn    : the graft chassis composition
      owner : LLR-135.1
      in    : SegRow list ; selection ; settings
      out   : the rendered cockpit DOM
    - fn    : the output plan (per-file blocks, coverage sweep, conflict marks, guard flag)
      owner : LLR-136.1
      in    : SegRow list ; selection ; mode ; gap ; pad
      out   : Plan (files, map blocks, span, fill, conflicts, guard)
    - fn    : the visor band + legend + ruler
      owner : LLR-135.2
      in    : Plan ; measured container width
      out   : the class-encoded band spans
    - fn    : the two-regime reflow + the split gantt show/hide
      owner : LLR-135.3
      in    : measured screen width ; mode ; file count
      out   : wide/narrow classes ; the gantt wrap visibility
    - fn    : the span guard arm/disarm
      owner : LLR-135.5
      in    : Plan ; ^E presses ; state changes
      out   : armed flag ; writes or holds
    - fn    : split/join emission (slicer + pad-fill emitter + S19/HEX/BIN emitters + naming)
      owner : LLR-136.5
      in    : Plan ; pad byte ; stem/pattern ; destination
      out   : files on disk (+ .addr sidecar for BIN)
  SINK   : the shipped screen (the operator's terminal) and the destination folder's files
```

```
FLOW: save_gather
  SOURCE : the save-project action (action_save_project, app.py:6786-6797 region) ; the used
           artifact registries (change-sets, check runs, CRC templates) ; the project state
  NODES  :
    - fn    : the used-set computation (the P3-recorded predicate)
      owner : LLR-138.1
      in    : project state ; the COMMON artifact folders
      out   : the used artifact set
    - fn    : the COPY gather into the project homes
      owner : LLR-138.2
      in    : the used set ; the project folder
      out   : <project>\patches\ + <project>\checks\ + <project>\templates\ copies
    - fn    : the no-project guard + the snapshot refresh on re-save
      owner : LLR-138.4
      in    : project presence ; save events
      out   : gather or no-op
  SINK   : the on-disk project tree + the status line
```

```
FLOW: open_folder_buttons
  SOURCE : the four windows' chip presses ; the change-1 home resolution ; the platform
  NODES  :
    - fn    : the per-window target resolution (project vs COMMON, missing-folder limbs)
      owner : LLR-139.1
      in    : window id ; project state ; folder existence
      out   : resolved dir or the disabled reason
    - fn    : the cross-platform seam
      owner : LLR-139.3
      in    : resolved dir
      out   : one Popen per press + the status line
  SINK   : the OS file manager
```

```
FLOW: usage_help
  SOURCE : the authored sections (help_sections.md) ; the focused window ; the ? affordances
  NODES  :
    - fn    : the per-window modal on the VariantHelpScreen pattern
      owner : LLR-140.1
      in    : window id ; authored section
      out   : the modal content + the dismiss
    - fn    : the section census (9/9, step counts, markup-free)
      owner : LLR-140.2
      in    : the authored copy
      out   : the section set
  SINK   : the operator's terminal (the modal)
```

```
FLOW: a2l_referenced_patch
  SOURCE : the loaded / referenced A2L (the tag map + the COMPU_METHOD side tables, P-16) ;
           the change-set JSON (the v2 wire, symbol-reference form) ; the operator's symbol +
           value inputs ; the flow blocks' a2l_ref declarations ; the flow-produced image B
  NODES  :
    - fn    : symbol resolution (name -> address+length+datatype via the tag map)
      owner : LLR-141.1
      in    : the entry's symbol ; the referenced A2L's tag map
      out   : the resolved address+length+datatype or the REFUSAL naming the symbol
    - fn    : physical->raw encode (the COMPU_METHOD composition) + the canonical wire form
      owner : LLR-141.1
      in    : the physical value ; the tag's conversion
      out   : raw bytes at the resolved address (+ the symbol field on the wire, address kept)
    - fn    : the Patch Editor symbol picker + the refusal limb
      owner : LLR-141.2
      in    : the loaded A2L's names ; the operator's entry inputs
      out   : symbol-referenced entries or the named refusal
    - fn    : the flow blocks' A2L reference resolution (project / workspace homes)
      owner : LLR-142.1 / LLR-142.2
      in    : the Load/Patch blocks' a2l_ref ; the project folder ; the workarea containment root
      out   : the run's resolution A2L or the named refusal
    - fn    : report attribution + the A2B diff reference block
      owner : LLR-143.1 / LLR-143.2
      in    : the applied entries ; the flow-produced image B ; the diff runs
      out   : the change-attribution section + the diff block referencing ALL flow changes
  SINK   : the Patch Editor entries table ; the flow's applied image ; the flow report + the
           A2B diff report block
```

- **Part B — boundary decomposition:** `yes — the hardened extractor, the new emitters, and the
  change-set wire's symbol-reference form are consumer-addressable engine components`:

```
COMPONENT: split_join_engine
  PARENT : SYSTEM
  SURFACE: the Split / Join / Export screen
  INPUTS : image: S19File|IntelHexFile ; segments: SegRow[] ; selection: set[int] ; mode: str ;
           gap: str ; pad_byte: int ; fmt: str ; stem: str ; pattern: str ; destination: Path
  OUTPUTS:
    - id          : output_files
      value       : the planned/emitted files (one per selected range in split; exactly one
                    joined file in join; + the .addr sidecar for BIN)
      address     : s19_app/tui/changes/io.py (the split/join emit entry minted by LLR-137.1-137.3)
      cardinality : 1..N
      consumers   : none — the first consumer is the screen's export action and the batch's own
                    TCs; no shipped consumer indexes it
      owner       : LLR-136.5
    - id          : memory_segment_rows
      value       : MEMORY_SEGMENT rows (name/usage/kind/base/size/offset)
      address     : s19_app/tui/a2l.py::extract_memory_segments
      cardinality : 0..N
      consumers   : s19_app/tui/a2l.py
                    s19_app/tui/a2l_parse.py
      owner       : LLR-137.4
```

```
COMPONENT: change_set_wire
  PARENT : SYSTEM
  SURFACE: the change-set JSON (the s19app-changeset v2 wire) + the flow blocks' a2l_ref
  INPUTS : document: ChangeDocument (address-form and symbol-form entries) ; a2l: the referenced
           A2L's tag map (symbol resolution at read)
  OUTPUTS:
    - id          : resolved_entries
      value       : entries with resolved addresses + raw bytes (symbol entries decoded by
                    the COMPU_METHOD composition; the symbol preserved on the entry)
      address     : s19_app/tui/changes/io.py (read_change_document — the v2 reader seam)
      cardinality : 1..N
      consumers   : s19_app/tui/changes/apply.py
                    s19_app/tui/services/flow_execution_service.py
                    s19_app/tui/services/report_service.py
      owner       : LLR-141.1
```

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

Layer A: LLR-level TCs minted from the reserved block **TC-682..718** (P0 wrote the RESERVED
registry rows for TC-682..711; the change-5 amendment extended the block to TC-712..718 —
`LED-2026-10-13-batch-95.2`) across new + existing test modules under the textual==8.2.8 pin; every TC passes
the G1–G7 guard. Layer B: **AT-296..304**, each driving the shipped surface through
`App.run_test(size=…)` (the frame discipline: `(120,36)` ⇒ a real 118×34 screen) and, for the
export limbs, asserting the files on disk:

| AT | Story | Outcome observed through the shipped surface | Counterfactual / negative side |
|----|-------|--------------------------------------------|-------------------------------|
| AT-296 | US-129 | the grafted screen at 118×34 (pane 58, band 54, split gantt visible) and at 80×24 (pane 30, gantt hidden, all four class hexes) — the shipped-surface half of HLR-135 | the pre-change tree has no screen (DOM assertions RED); a nominal-120 regime keying misses the wide regime |
| AT-297 | US-129 | export bytes on disk byte-match the plan: split → `n` files `‹stem›_‹segment›.‹ext›`; join → one `‹stem›_joined.‹ext›`; BIN → `size` flat bytes + the `.addr` sidecar; the conflict abort writes 0 bytes with a reason | a fill that clobbers source bytes and writes (abort RED) |
| AT-298 | US-129 | the guard two-step: first `^E` arms with the span/pad warning and writes nothing; a state change disarms; the second `^E` exports | an export on the first `^E` while the guard is up (two-step RED) |
| AT-299 | US-130 | save-gather: the project folder holds the gathered copies; the COMMON originals are all present; no-project → nothing gathered | a MOVE (common original gone) RED; a gather without a project RED |
| AT-300 | US-131 | the four chips open their change-1 homes (seam spy) in both modes; the missing-folder limbs dim/offer/create/disable per spec | a second-guessed path (e.g. last report's dir) RED; an open on the disabled Reports chip RED |
| AT-301 | US-132 | the usage modal per window (9/9 sections) opens from the "?" affordance and `?`-when-focused; Close + Esc dismiss; the stock HelpPanel still works | a forked/replaced HelpPanel RED; a blank modal for an unauthored window RED |
| AT-302 | US-133 | the Patch Editor's A2L-referenced entries: a symbol picked from the loaded A2L resolves address/length/datatype live, the saved change-set JSON carries the symbol form WITH the resolved address, a re-load through the shipped v2.0 reader applies byte-identically, and an unknown symbol is refused with its name in the error | a symbol entry authored blind (address guessed) RED; the shipped v2.0 reader failing a canonical symbol entry (leniency RED); a refusal omitting the symbol's name RED |
| AT-303 | US-133 | a flow run whose Load block declares the project's A2L (and a Patch block overriding to a workspace-folder A2L) resolves the change-set's symbol entries and applies them; a reference resolving to nothing refuses the run naming it | a run resolving symbols against an undeclared/implicit A2L RED; a dangling reference that still applies RED |
| AT-304 | US-133 | the flow report's change-attribution section names every applied change (symbol when present + always the resolved address + before/after bytes), and an A2B diff block over the flow-produced image references ALL the flow's changes (each run attributed; no-diff entries listed) | a diff block omitting one flow change RED; a report row naming neither symbol nor address RED |

### 5.2 Batch acceptance criteria
- Every LLR (135.1–140.2, 141.1–143.2) is covered by ≥1 TC minted from TC-682..718 with a pass result under textual==8.2.8; every story (US-129..133) has ≥1 passing black-box AT (AT-296..304) observing its outcome through the shipped surface — with boundary + negative evidence.
- The signed-frame oracles hold at the measured geometries: at 118×34 the wide regime (pane 58, band 54, gantt visible in split with 1..6 files); at 80×24 the floor (pane 30, gantt hidden, the four class hexes rendered); the guard state renders the 402 MB `░` sea on the demo case.
- The negative controls execute RED on the shipped tree and GREEN after P3 (the quoted-A2L non-null assertion on today's extractor; the no-screen DOM assertions; the MOVE-gather presence assertion; the two-step assertion; the amendment's: the unresolved-symbol refusal naming the symbol, the shipped-v2.0-reader leniency on canonical symbol entries, the diff-block reference-all law).
- The shipped surfaces this batch touches stay intact: the `?` HelpPanel binding (`app.py:1360`), the rail census (`app.py:1362-1371`), the `o`-key workarea open (`app.py:5437`), the patch-dropdown scan (US-026) and the template library (batch-58 F3) — all green, 0 drift; the change-5 amendment adds: the v2 wire's address-only grammar (address entries byte-identical through the new writer), the shipped v2.0 reader (applies canonical symbol entries unchanged), and the A2B diff report for non-flow inputs (0 drift).
- The full suite (`python -m pytest tests -q`, not the `-m "not slow"` PR form) stays green before merge; every ledger figure states which form produced it.
- The registry shows the batch's reservation (AT-296..304 + TC-682..718 — the change-5 amendment extended AT-302..304 / TC-712..718 at the registry's high-water mark) and every minted id conforms G1–G7.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
- The operator's round-2 ruling: **the graft ships as the screen** (V1 chassis + V2's two best ideas); v1/v2 were evaluated live and not chosen (nothing ships for them).
- The HTML mock (`segment_split.prototype.html`) was the round-1 artifact; the terminal design **superseded** it — the contract pins the rulings and the graft, never the mock's chrome (ledger).
- The pad-byte divergence (`0x00` here vs the CRC editor's `0xFF`) is deliberate and ruled (Q1/8a): erased-flash `0xFF` and neutral `0x00` are different intents.
- Palette-first (Q6/7a): no rail key is repurpose; the screen lives in the shipped `^K` palette.

### 6.3 Open risks
- The wide threshold (118) is prototype-measured on the house box; P3 re-confirms it on the shipped screen under the frame discipline and records the value (C-29 pilot idiom) — a drift re-opens LLR-135.3's constant.
- The "used by this project" gather predicate is P3's to define and record (observation O-1); over-gathering copies the whole library, under-gathering breaks the self-contained promise.
- The design's budget numbers (H@60 17–27 @80×24, 8–13 @120×36; 12–14 runs/row) are design-measured; P4 re-runs the bench under the batch's own harness — H ≥ 5 is the contract floor.
- The round's dir is throwaway; the oracle frames it holds are referenced by path and re-captured at P4 if the dir moved.
- The physical→raw encode direction (change 5) is net-new composition on the shipped COMPU_METHOD side tables (decode ships — P-17); the conversion limbs (unknown conversion, value outside limits) are P3-recorded in the increment packet.
- The no-project A2L home is the `.s19tool\workarea\` containment root (change-5 flows); a dedicated per-family COMMON A2L folder is punted — no shipped home exists and the containment guard already bounds the source.

### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-13-batch-95

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
