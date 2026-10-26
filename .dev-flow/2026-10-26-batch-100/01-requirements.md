
# Requirements Document — s19_app — Batch 2026-10-26-batch-100

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
This document states what the Load + projects batch obliges. A saved project restores what the session held, or the load names what it could not restore. One Load dialog offers what is already loaded and opens projects. No unsaved work is replaced without a question, and long actions show that they are working. It derives from the project round-trip investigation of 2026-10-23, re-run on this batch's base `1d677ba` (§2.7).

### 1.2 Scope
**In:** PH-1, PH-2, PH-4, PH-5, M-1..M-7, L-2, L-3 (remaining paths) and L-4 of `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md`; G-005 (byte-identical reuse; TC-018 and AT-031b re-pinned); the Load dialog requests (a picker of work-area files and recent sources, Load opens projects, Enter loads, D10); CW-U-2, CW-U-5, CW-U-12 and CW-U-13 of `.dev-flow/design/AUDIT-codewire-ui-2026-10-23.md`; reserved and device project names; the progress indicator (N5); and the Load-result panel P-E (from the operator's D2 note). The prototype round's verdict (`design/veredicto-load-projects.json`: P-A C, P-B A, P-C B, P-D A, P-E B) fixes every UI surface.

**Out (with where each lives):** PH-3, L-1 and the outside-work-area half of L-3 closed in batch-99 (premise P-21). The Code-Wire F6 findings and the integrity mediums and lows stay in `BACKLOG-CODE.md`. Three writers put images in the open project without the manifest writer — flow WRITE-OUT (`flow_execution_service.py:679`), the external-step copy (`:1108`) and variant execution (`variant_execution_service.py:797`). Routing them through it is out of this batch's file budget and lives in `BACKLOG-CODE.md` §*Routed 2026-10-26 — batch-100 P2 round 1*; what they write is reported at Load as "present, not recorded" (LLR-169.5). Flow runs stay on the main thread (ruling O-7). The A2L tag-table build stays on the main thread (HLR-176). Double-click in the Load dialog is not bound (VS-PA-2).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Work area | `<base>/.s19tool/workarea/`, the folder Load lists (`app.py:8519-8524`). "Inside the work area" means inside `self.workarea.resolve()` after every link and junction is resolved (`contained_in_workarea`, LLR-171.4), never inside some other `.s19tool/workarea`. |
| Work copy | The copy of a loaded source in `workarea/temp/` (`WORKAREA_TEMP`, `workspace.py:20`). |
| Data differs | The emit decision (LLR-167.1): the change document's entries, re-derived onto a copy of the source image (the `save_patched` split, LLR-167.7), give data that differs from the source file's data. A check document never counts. It decides whether Save project emits or copies. |
| Unsaved | `ChangeService.differs_from_last_saved(mem_map)` (NEW, LLR-167.5): the image differs from the copy last loaded or written. With the Patch Editor dirty flag and the Flow Builder dirty flag it decides the load question (HLR-174) and the Save summary's pending line (HLR-175). It never decides emit or copy. |
| Project | A direct child folder of this work area, not a link or junction, not a reserved home, holding a `project.json` or a data file (Q-2). |
| Save plan | The one object `plan_project_save` (NEW, LLR-167.6) returns: target folder and kind, one row per top-level file, one row per sub-folder with its file count, and one row for `project.json`, each with its source, landing name (from `predict_placement`, LLR-163.7) and action word (`new`, `replace`, `keep`, `merge`, `rewrite`). The Save dialog paints it and `_handle_save_dialog` executes it (R-PC). |
| `derived_from` | The `project.json` per-variant key (NEW, LLR-168.4) naming the variant a patched variant was derived from; written by the save-back and by Save project's emit, carried by every rewrite. |
| Active set | The image variant, MAC and A2L that a load will install. The Load dialog's preview marks it with `●` (P-A verdict note). |
| Load-result panel | The P-E B modal that a project load opens: the opened variant and why, how it differs from the variant it derives from, the other variants, and every problem (HLR-178). |
| Problem (D3) | One entry of the Load-side problem list (LLR-169.5, LLR-169.9), at most one per file. |
| Recent source | An entry of the per-user store `%LOCALAPPDATA%\s19_app\recent_sources.json`, outside every work area (B100-I9 as amended, LLR-172.1; the operator's S-16 decision). |
| Refusal token | A fixed, NEW phrase an acceptance test can match: the reason and the next step of every refusal, problem and empty state (§3 preface table). |
| Image-replacing route | Every user action that replaces the loaded image: the Load dialog, the Workarea Files pick, the variant switch (`v`, the panel's `v`) and a project load. All pass the one load seam (LLR-174.4). |

### 1.4 References
- `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (PH-*, M-*, L-* ids) and `AUDIT-codewire-ui-2026-10-23.md` (CW-U-* ids).
- `design/ARQ-batch-100.md` (§2 session inventory, §3 manifest, §4 Save project, §5 reuse rule, §6 Load sources, §7 progress, §10.1 rulings O-1..O-11) and `docs/ARCHITECTURE.md` §10 *Batch-100 declarations*, §11 B100-I1 to B100-I12.
- `design/plan-b100.html` and `design/veredicto-b100.json`: D1–D7, all on the recommended option; the D2 note became surface P-E.
- `evidence/p0-premises/`: the probes re-run at `1d677ba`.
- `REQUIREMENTS.md`: R-TUI-012 (`:1244`), HLR-151 (`:6404`), HLR-162 (`:6488`); batch-14 LLR-015.3 (`.dev-flow/2026-06-23-batch-14/01-requirements.md:222`).

### 1.5 Document overview
§2 holds the stories, the premise re-run and the fork verdict. §3 has one HLR per story, §4 the LLRs and the Information Flow Contract, §5 the validation strategy, the AT-by-increment index and the reverse census. Ids: US-153 through US-168, HLR-163 through HLR-178, AT-B100-NN, TC-B100-NN. Round 2 (P2 round-1 dispositions) is recorded in the ledger, entries .2 to .13.

## 2. Overall description

### 2.1 Product perspective
The change sits on the project round-trip:
- Save project (`_handle_save_dialog`, `app.py:8087`) and its name rules (`workspace.py:40`, `:1028`);
- Load project (`_handle_load_project`, `app.py:8444`) and the manifest reader (`variant_execution_service.py:376`);
- the manifest writer (`manifest_writer.py:225`, `:414`, `:632`) and the save gather (`project_gather_service.py:400`);
- the work-area placement (`copy_into_workarea`, `workspace.py:402`);
- the Load, Save project and confirm dialogs (`screens.py:179`, `:483`, `:691`, `:902`) and the progress seam (`app.py:13615`).

No module is created and no boundary moves (ARQ §1).

### 2.2 Product functions
- Reuse a byte-identical work-area copy instead of adding `_<N>` copies.
- Guard project names, and leave nothing behind when a save is refused.
- Start each project load from an empty session.
- Save the image the session holds, and record the active variant, file digests and the active change document.
- Load what is valid, and list every problem.
- One Load dialog with projects, work-area files, recent sources and a typed path.
- Ask before replacing unsaved work. Show progress on long actions.

### 2.3 User characteristics
Calibration and test engineers who keep a session as a project, switch between projects, patch images and come back later. They trust the status line. They work at a Windows terminal, often resized, with the keyboard.

### 2.4 Constraints
- Python 3.11, Textual 8.2.8; Windows first; `LongPathsEnabled = 0` assumed (a directory path ≤ 247 characters, a file path ≤ 259; A-10).
- At most 4 SOURCE files per increment (ARQ §8); sequential increments, one worktree each; 12a and 12b land together (R-PD).
- The repo is public: records describe region extraction only as memory-region extraction.
- Every UI string is in English, and no painted string carries an internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`).
- Every layout derives for any terminal width, and is judged at the two reference sizes 118×54 and 220×60.
- `prototypes/` is never committed.

### 2.5 Assumptions and dependencies
- `copy_into_workarea` is the placement path for project files (B99-I2); re-checked as premise P-22.
- `ChangeService.save_patched` emits and verifies the source plus the current document (batch-99 B99-I7), and Save project uses it unchanged (A-06); re-checked as P-23.
- The prototype round's verdict is final for the five surfaces; the ids and bindings of `pa_C`, `pb_A`, `pc_B`, `pd_A` and `pe_B` are the shipped ids (P-30).

### 2.6 Source user stories

Every story comes from the operator's commission of 2026-10-26 (PLAN header), the verdicts D1–D7 (`design/veredicto-b100.json`) and P-A..P-E (`design/veredicto-load-projects.json`), the orchestrator rulings O-1..O-11 (ARQ §10.1) and the P2 round-1 dispositions (`design/P2-dispositions-r1.md`), and the findings in §1.4. Each row is one row of PLAN's increment table, except US-168, which is the P-E panel that Inc 6 and Inc 7 show.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-153 | As the calibration engineer, I want a re-load or re-save of a file whose bytes are already in the work area to reuse that file, so that my project does not fill with identical `_<N>` copies and duplicate variants. | Inc 1 · M-1, G-005 | READY |
| US-154 | As the engineer saving a project, I want a name that is reserved, a Windows device name, too long, or a disguised clash with another project to be refused with a reason and a next step, so that no save hides a project, merges two projects silently or crashes the app. | Inc 2 · M-4 (O-9, Q-2), M-7 (Q-1), reserved and device names, L-3 | READY |
| US-155 | As the engineer switching projects, I want a project load to start from an empty session, so that no A2L, MAC or change entry of the previous project leaks into the new one or into its next save. | Inc 3 · PH-2 | READY |
| US-156 | As the engineer who just loaded a file or a project, I want the keyboard focus on a named, visible, non-text widget, so that the single-key commands work. | Inc 4 · CW-U-2 | READY |
| US-157 | As the calibration engineer, I want Save project to save the source plus every entry of my document, verified, and to say what it saved, so that what I reopen is what I saved. | Inc 5 · PH-1, D1, O-5, O-6, A-06 | READY |
| US-158 | As the calibration engineer, I want a patched image saved into my project to become the project's active variant, so that Load reopens where I stopped. | Inc 6 · PH-4, D2, O-1, O-10 | READY |
| US-159 | As the engineer opening a project, I want Load to open what is valid and list every problem — a damaged or absent manifest, a missing file, an unreadable image, a file changed on disk, a file nobody recorded — so that I never work on a project that silently differs from what I saved. | Inc 7 · PH-5, L-4, D3, O-2, O-11, A-01 | READY |
| US-160 | As the calibration engineer, I want the change document I was editing to be saved with the project and reopened on Load, so that I see my entries, not only the image. | Inc 8a · M-2, D4, Q-5 | READY |
| US-161 | As the engineer managing projects, I want "save as" to copy the whole project, an A2L-only project to open, and every project to live in this work area, so that what I save always reopens complete and nothing is written elsewhere. | Inc 8b · M-3 (D5, O-4), M-6 (D6), M-5 (D7, handler), S-02 | READY |
| US-162 | As the engineer loading files, I want my recent sources remembered, a project path typed into Load to open the project, and file names shown literally, so that I reach my work without retyping paths. | Inc 9a · Load request (data), L-2, C6, C8 | READY |
| US-163 | As the engineer loading anything, I want one Load dialog with the list on the left and a preview on the right that marks the set that will be active, where Enter loads and `esc` closes, so that I load with the keyboard and know what I am opening. | Inc 9b · Load request, D10, CW-U-12, CW-U-13, C8, P-A C | READY (P-A verdict C) |
| US-164 | As the calibration engineer, I want one short question before a load would lose a patch I have not saved, unsaved Patch Editor entries or unsaved Flow Builder edits, so that no work is lost silently. | Inc 10 · CW-U-5, O-3, P-B A | READY (P-B verdict A) |
| US-165 | As the engineer saving a project, I want the Save project dialog to show, before I press Save, exactly what will be saved, where, and anything that will be renamed, kept or refused, and to close on `esc`, so that my work is never invalidated, lost, overwritten or renamed without my knowing. | Inc 11 · M-4 preview, D7 (dialog half), CW-U-12, CW-U-13, P-C B, R-PC | READY (P-C verdict B) |
| US-166 | As any engineer, I want an action that runs on a worker to show a spinner, its step and its elapsed time in the status line, with a progress bar that really moves, so that I do not think the app froze. | Inc 12a · N5, P-D A, R-PD | READY (P-D verdict A) |
| US-167 | As any engineer, I want project load, Save project and the A2L parse to run off the main thread, so that the progress shows and the app answers. | Inc 12b · N5, O-7, R-PD | READY (P-D verdict A; unconditional) |
| US-168 | As the engineer opening a project, I want a result panel that tells me which variant opened, why, how it differs from the base, and every problem, so that a switch to the latest saved image never goes unnoticed. | P-E · D2 note, D3 display, P-E B | READY (P-E verdict B) |

**Ledger pairing:** stories live in this table. Ledger entries name the HLR or LLR they amend.

#### Refinement log (one block per story)

Each block carries the four context lines (user · task · environment · observable outcome). Unless a block says otherwise, the environment is a Windows terminal of any width, judged at 118×54 and 220×60, keyboard first, with the work area on a local NTFS volume.

**US-153 — identical copies are reused**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = the calibration engineer; task = re-loading a source or re-saving a document; outcome = one file per distinct content, and every status that reports a placement tells reuse apart; why = `p02` C leaves `firmware_1` and `firmware_2` with the same bytes; out of scope = `place_group_into_workarea` (requested names only, B99 PDR C3(e)).
- **Feasibility:** path = one shared byte-identical function in `workspace.py`, used by `copy_into_workarea` and the export (QA-05); Inc 1 = `workspace.py`, `segment_split_view.py`, `app.py`; fits one batch = yes.
- **Evaluability:** when the same file is loaded twice with a project open, the work area holds one copy, the project folder one data file for it, and the status does not say a variant was added.
- **Open questions:** none.
- **Classification:** `READY`.

**US-154 — Save project name guards**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving under a new or reused name; outcome = a refusal naming the reason and the next step, the app running, no folder left; or a save into the named project shown as such; why = `reports` is saved and then hidden, `CON` is accepted, a 300-character name crashes, `a b` merges into `ab` silently; out of scope = the dialog summary (US-165).
- **Feasibility:** path = `_handle_save_dialog` and `list_projects` in `app.py`, the name rules in `workspace.py`; fits one batch = yes.
- **Evaluability:** when the engineer saves as `Reports`, the status carries the reserved-name token and no `Reports` folder appears.
- **Open questions:** none (Q-1 = 64 with the full-path check; Q-2 with QA-04's definitions and A-09's merge).
- **Classification:** `READY`.

**US-155 — a project load starts clean**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = opening P2 after working in P1; outcome = P2 alone in the session and in its re-save; why = `p03` prints six `LEAK` lines; out of scope = a loose Load file, which still composes with the session.
- **Feasibility:** path = one seam `_reset_project_session()` (B100-I4) and the app-owned `_session_snapshot()` that tests read; fits one batch = yes.
- **Evaluability:** when P2 is loaded over P1 and saved, P2's folder holds only P2's files.
- **Open questions:** none.
- **Classification:** `READY`.

**US-156 — focus after a load**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading, then pressing a single-key command; outcome = the command runs; why = the focus lands on the hidden Split/Join table (`S4`); out of scope = the Split/Join window's own bindings.
- **Feasibility:** path = the load tails in `app.py` and the modal-close path; fits one batch = yes.
- **Evaluability:** when a file is loaded and the engineer presses `p`, the Load dialog opens; after a project load, the panel holds the focus, and after it closes `p` works.
- **Open questions:** none.
- **Classification:** `READY`.

**US-157 — Save project saves the source plus the document**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving a session after editing patches, with or without an apply; outcome = the project image is the source plus every entry of the document, verified, and the view shows what was saved; why = `p01` saves the original under "manifest verified"; out of scope = a width or S0 prompt (O-5).
- **Feasibility:** path = `save_patched` as the save-back does (A-06), driven by the save plan (R-PC); Inc 5 = `app.py`, `change_service.py`, `project_gather_service.py`; fits one batch = yes.
- **Evaluability:** when the patched session is saved and reopened, the image holds the patch and the panel names the variant as patched.
- **Open questions:** none (D1 = `imagen`, A-06).
- **Classification:** `READY`.

**US-158 — the saved patched image becomes the active variant**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = save-back into the open project, then reopen; outcome = the reopened image is the patched one; why = `p02` A/B reopen the original; out of scope = the panel's wording (US-168).
- **Feasibility:** path = the save-back handler (`app.py:3364`) and the manifest seam, every key carried; fits one batch = yes.
- **Evaluability:** when the engineer saves back into project P and reopens P, the loaded file is the patched variant.
- **Open questions:** none (D2 = `ultima`, O-1, O-10).
- **Classification:** `READY`.

**US-159 — Load opens what is valid and lists every problem**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = opening a project after its files changed; outcome = the project opens, the status log carries one summary line and the panel lists every problem, one per file; why = `p04` loads a damaged manifest, a corrupt image and an edited image with `notices=[]`; out of scope = the panel's layout (US-168).
- **Feasibility:** path = `files` digests, `check_project_files`, the load-result merge in `_handle_load_project`, private manifest staging; fits one batch = yes.
- **Evaluability:** when an image is edited on disk after the save, Load opens the project and names that file as changed on disk.
- **Open questions:** none (D3 = `abre_y_reporta`, O-2, O-11, A-01).
- **Classification:** `READY`.

**US-160 — the change document travels with the project**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving with the Patch Editor open, then reopening; outcome = the Patch Editor shows the document's entries; why = `p06` A reopens no document and `p01` drops a pasted one; out of scope = undo history.
- **Feasibility:** path = `active_document` in the manifest; the app writes a pasted document as `patches/changes.json` (Q-5, A-12); the reopen after the A2L attaches; fits one batch = yes.
- **Evaluability:** when a project saved with one entry is reopened, the Patch Editor lists that entry.
- **Open questions:** none.
- **Classification:** `READY`.

**US-161 — projects reopen complete and stay in this work area**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = "save as", an A2L-only project, a project folder that is a junction; outcome = the copy holds every sub-folder, the A2L-only project opens, nothing outside this work area is listed, loaded or written; why = `p06` C, `p04` 10, `p05`, the security probe's junction (S-02); out of scope = the dialog's parent field (US-165).
- **Feasibility:** path = `_handle_save_dialog`, `_handle_load_project`, `project_gather_service`, one containment helper; fits one batch = yes.
- **Evaluability:** when P is saved as Q, Q's flow list matches P's; a junction folder in the work area is not listed.
- **Open questions:** none (D5 with O-4, D6, D7).
- **Classification:** `READY`.

**US-162 — recent sources, project paths and literal names**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading again a file used before, or typing a project path; outcome = the source is remembered, the project opens, names render as written; why = Load file gives `Unsupported file type: ` for a project folder (`p05`), and file names are parsed as markup (P-24); out of scope = the dialog that lists the recents (US-163).
- **Feasibility:** path = two functions in `workspace.py` (B100-I9), one work-area lister, the typed-path router (ARQ §6); fits one batch = yes.
- **Evaluability:** when a project folder is typed into Load, the project opens.
- **Open questions:** none.
- **Classification:** `READY`.

**US-163 — one Load dialog**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading by keyboard; outcome = one two-pane dialog, the preview marking the active set with `●`, Enter loads, `esc` closes, an empty Load or an invalid path explained inside the dialog; why = `S1`/`S3`: no picker, `esc` ignored, an empty Load says nothing; operator note on P-A: "Me gusta la idea de los dos paneles, con el simbolo de cuál es el set que se va a usar como archivos activos en el proyecto para las vistas y funciones en la aplicación."
- **Feasibility:** path = `screens.py` + `app.py` + `styles.tcss` (Inc 9b); fits one batch = yes.
- **Evaluability:** when the engineer opens Load, highlights a project and presses Enter, the files the preview marked are the files installed.
- **Open questions:** none; every slot VS-PA-1 to VS-PA-6 is filled (HLR-173).
- **Classification:** `READY` — P-A verdict C.

**US-164 — ask before losing work**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading while something unsaved would be lost; outcome = one short question, `y` replaces, `n`/`esc` cancels, the focus starts on `n`; why = `S5`: a load over a patched image asks nothing; operator note on P-B: "Pregunta corta, hace el trabajo y crea menos dependencias."
- **Feasibility:** path = a confirm modal on the `pb_A` ids, keyed on the unsaved predicate (Inc 10 after Inc 5); fits one batch = yes.
- **Evaluability:** when a patched, unsaved image is about to be replaced, the engineer sees a question and `n` keeps the patch; after Save project, the same load asks nothing.
- **Open questions:** none; slots VS-PB-1 to VS-PB-3 are filled (HLR-174).
- **Classification:** `READY` — P-B verdict A.

**US-165 — the Save project dialog**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = naming and saving a project; outcome = a summary, rendered from the same save plan the save executes, of every file, its action and its landing name; why = `S2`: no preview, `esc` ignored, an empty Save silent; operator note on P-C: "…es importante saber que se está guardando en cuestión de proyecto. Se extra cuidadoso con la información que se despliega aquí. Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información."
- **Feasibility:** path = `SaveProjectScreen` (`screens.py:483`) on the `pc_B` ids, consuming `plan_project_save` (Inc 11; the plan lands in Inc 5); fits one batch = yes.
- **Evaluability:** for each save scenario, the summary rows equal the files written, by path and digest.
- **Open questions:** none; slots VS-PC-1 to VS-PC-3 are filled (HLR-175).
- **Classification:** `READY` — P-C verdict B.

**US-166 — progress for worker actions**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = waiting for a load, a parse, a report or a save; outcome = a spinner, the step n/m and the elapsed time in the status line, and a bar that moves with the steps, then the outcome; why = N5 reopened; operator note on P-D: "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso."
- **Feasibility:** path = `begin_busy` / `step_busy` / `end_busy` (B100-I12) painting `#status_text` (`pd_A`); fits one batch = yes, with US-167 in the same unit.
- **Evaluability:** when the case_06 A2L is parsed, the elapsed time advances and the bar moves before the parse ends.
- **Open questions:** none; slots VS-PD-1 and VS-PD-2 are filled (HLR-176).
- **Classification:** `READY` — P-D verdict A.

**US-167 — long actions off the main thread**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading a large project; outcome = the elapsed time advances during the load, and a second such request is refused with a status naming the running action; why = project load, Save project and the A2L parse block the main thread (ARQ §7); out of scope = flow runs (O-7) and the A2L tag-table build (HLR-176).
- **Feasibility:** path = `@work(thread=True)` for three actions, installs through `call_from_thread`; fits one batch = yes.
- **Evaluability:** when the project holding the case_06 A2L loads, the elapsed time advances before the load ends.
- **Open questions:** none (R-PD makes 12b unconditional; VS-PD-3 = refuse).
- **Classification:** `READY` — P-D verdict A.

**US-168 — the Load-result panel**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = reopening a project after a save-back or after damage; outcome = a panel that names the opened variant, why, how it differs from the base, the other variants, and every problem; `enter`/`esc` close it and `v` opens the variant selector; why = the operator's D2 note ("that the switch does not go unnoticed").
- **Feasibility:** path = a pure composer in `variant_execution_service.py` (A-16) and the panel on the `pe_B` ids; fits one batch = yes.
- **Evaluability:** when project P with two variants is reopened after a save-back, the panel names `firmware_1`, "patched, 4 B differ", and P's 2 variants.
- **Open questions:** none; slots VS-PE-1 to VS-PE-3 are filled (HLR-178).
- **Classification:** `READY` — P-E verdict B.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

Probes P-1..P-21 were executed 2026-10-26 on a `git archive` of `1d677ba` (this batch's `base_ref`; `git diff --stat 1d677ba HEAD -- s19_app tests` is empty) with `PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1`, `NO_COLOR` unset. Transcripts: `evidence/p0-premises/` (`proj-pNN_*.txt`, `ui_load_dialogs_probe.txt`, `g005-tests.txt`). Rows P-22..P-29 were executed by this author at draft time on the same tree; their command is in the cell.

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (decisive output) | Disposition |
|---|---|---|---|---|---|
| P-1 | Save project with an applied, unsaved patch saves the original and reports success (PH-1). | premise | ✅ TRUE | `proj-p01`: `project firmware.s19 == in-memory patched image? False \| == original? True`; status `Project saved + manifest verified` | RED side of AT-B100-05 |
| P-2 | Loading P2 over P1 keeps P1's MAC, A2L and change entry (PH-2). | premise | ✅ TRUE | `proj-p03`: `LEAK mac_records: cold=0 after-P1=2`, `LEAK a2l_tags: cold=0 after-P1=3`, `LEAK change_entries: cold=0 after-P1=1`; `P2 files after re-save: ['firmware.a2l', 'firmware.mac', 'prg.s19', 'project.json']` | RED side of AT-B100-03 |
| P-3 | After a save-back into the open project, Load reopens the unpatched original (PH-4). | premise | ✅ TRUE | `proj-p02` [A]: `project.json: {… 'active_variant': 'firmware' …}`, `RELOAD -> file=firmware.s19 variants=['firmware', 'firmware_1'] active=firmware image_is_patched=False` | RED side of AT-B100-06, AT-B100-19 |
| P-4 | Load reports success over a corrupt manifest, a corrupt image and an image edited on disk (PH-5). | premise | ✅ TRUE | `proj-p04` [2]/[6]/[7]: `status=["Loaded project 'P' -> firmware.s19 + firmware.mac"] notices=[]`; [2] `loaded image == saved image? False (no hash in project.json to detect it)` | RED side of AT-B100-07 |
| P-5 | A project whose image was deleted opens the MAC with a misleading status (L-4). | premise | ✅ TRUE | `proj-p04` [5]: `"Manifest active_variant 'firmware' not found - activating the first variant.", "Loaded project 'P' -> firmware.mac"` | RED side of LLR-169.6 |
| P-6 | Re-loading a same-name source creates byte-identical `_<N>` copies and variants (M-1). | premise | ✅ TRUE | `proj-p02` [C]: `firmware_1.s19 310 a9e114d56077`, `firmware_2.s19 310 a9e114d56077`, variants `['firmware', 'firmware_1', 'firmware_2']`; `ui_load_dialogs_probe` S7: `copy case_02 again -> firmware_2.s19` | RED side of AT-B100-01 |
| P-7 | TC-018 and AT-031b are red at `1d677ba`, because the bare-name reuse (B8) already returns the identical file. | premise | ✅ TRUE | `g005-tests.txt`: `FF`, `assert … cs.json != … cs.json`, `assert 1 == 2`; `exit: 1` | LLR-163.3 re-pins both |
| P-8 | Load does not reopen the gathered change document, and a pasted document is not saved (M-2). | premise | ✅ TRUE | `proj-p06` [A]: `gathered: {'patches': ['patches/boost.json']}` → `after Load: editor doc = None entries = 0`; `proj-p01`: `DIFF change_entries: saved-session=1 restored=0` | RED side of AT-B100-08 |
| P-9 | "Save as" copies only the top-level data files (M-3). | premise | ✅ TRUE | `proj-p06` [C]: `Q tree: ['firmware.a2l', 'firmware.s19', 'project.json']`, `flows visible: []` | RED side of AT-B100-09 |
| P-10 | Names are sanitised silently (`a b` → `ab`, `../evil` → `evil`) (M-4). | premise | ✅ TRUE | `proj-p05`: `name 'a b' -> project='ab'`, `name '../evil' -> project='evil'`, each `Project saved + manifest verified` | RED side of LLR-164.2 |
| P-11 | A save under another installation's work area is accepted and never listed (M-5). | premise | ✅ TRUE | `proj-p05`: `parent = another workarea -> … Project saved + manifest verified`, `listed by Load project? False` | RED side of LLR-171.3 |
| P-12 | An A2L-only project saves and then cannot be loaded (M-6). | premise | ✅ TRUE | `proj-p04` [10]: `files: ['firmware.a2l', 'project.json']` → `status=['No supported files in project: P']` | RED side of AT-B100-10 |
| P-13 | A 300-character project name raises out of Save project (M-7). | premise | ✅ TRUE | `proj-p05`: `!! _handle_save_dialog RAISED FileNotFoundError: [WinError 3]` | RED side of LLR-164.3 |
| P-14 | Reserved homes are accepted as project names, and `Splits` is listed because the filter is case-sensitive. | premise | ✅ TRUE | `ui_load_dialogs_probe` S6: `dialog Save 'reports' -> … Saved project …`, `list_projects(): ['Splits']` | RED side of AT-B100-02 |
| P-15 | A project folder or `project.json` typed into Load file gives an unhelpful status (L-2). | premise | ✅ TRUE | `proj-p05`: `Load file 'ab' -> status=['Unsupported file type: ']`, `'ab/project.json' -> ['Unsupported file type: .json']` | RED side of AT-B100-12 |
| P-16 | After a load the focus is on the hidden Split/Join table and `p` does nothing (CW-U-2). | premise | ✅ TRUE | `ui_load_dialogs_probe` S4: `focused: _SegTable#sje_table \| focused region area: 0 \| split window hidden: True`, `` `p` -> Screen `` | RED side of AT-B100-04 |
| P-17 | A load over a patched, unsaved image asks nothing (CW-U-5). | premise | ✅ TRUE | `ui_load_dialogs_probe` S5: `Load file over patched image -> stack: ['Screen'] \| … image still patched? False` | RED side of AT-B100-15 |
| P-18 | Load file, Save project and Load project ignore `escape` (CW-U-12). | premise | ✅ TRUE | `ui_load_dialogs_probe` S1/S2/S3: `escape on LoadFileScreen -> screen: LoadFileScreen`, the same for `SaveProjectScreen` and `LoadProjectScreen` | RED side of AT-B100-14, AT-B100-16 |
| P-19 | An empty Load or Save gives no feedback (CW-U-13), and Enter with a typed path loads nothing. | premise | ✅ TRUE | `ui_load_dialogs_probe` S1: `empty Load click -> … new status: [] \| new notices: []`, `Enter with a typed path -> … current_file before/after: firmware_1.s19 / firmware_1.s19`; S2: `empty name Save click -> … new status: []` | RED side of AT-B100-14, AT-B100-16 |
| P-20 | The Load file dialog has no list, and names no work-area file or recent source. | premise | ✅ TRUE | `ui_load_dialogs_probe` S1: `dialog has a list/picker widget? none`, `names a work-area file (firmware_1)? False \| names a recent source (case_01/case_02)? False` | RED side of AT-B100-14 |
| P-21 | PH-3, L-1 and the outside-work-area L-3 are closed (batch-99). | axiom | ✅ TRUE | `proj-p08`: `work copy exists after save-back: True`; `proj-p04` [12]: `list_projects(): ['P']`; `proj-p05`: `left behind: []` | out of scope (§1.2) |
| P-22 | Of the 4 test files that name a `_2+` file, only `test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name` re-places identical bytes through `copy_into_workarea`. | premise | ✅ TRUE | `grep -nE "_[2-9]\.(s19\|json\|bin\|addr)" <the 4 files>`: `test_b99_export.py:415`, whose third export re-uses the second's `changed` map (`:396-412`) through `segment_split_view.py:940` (`copy_into_workarea`); `:487` goes through `place_group_into_workarea` (`segment_split_view.py:949`, unchanged); `test_flow_a2b_b94.py:529-536` and `test_tui_flow_builder_b94.py:306` save different blocks; `test_b99_staging.py:1962` is docstring text | LLR-163.4 re-pins the one; the others stay |
| P-23 | R-TUI-012 says Save project copies the loaded file, while LLR-015.3 routes the project save through the emitter, and its TC-220 drives `ChangeService.save_patched`. | premise | ✅ TRUE | `REQUIREMENTS.md:1244-1245`; `2026-06-23-batch-14/01-requirements.md:222-225`; `tests/test_changes_apply.py:926-929` (`TC-220 — ChangeService.save_patched (the project/service save path)`) | R-TUI-012 amended (LED-2026-10-26-batch-100.1) |
| P-24 | Textual 8.2.8 `Label` parses markup by default, and both the project list and the work-area list build `Label(name)` from disk names. | premise | ✅ TRUE | `python -I -c "import inspect; from textual.widgets import Label; print(inspect.signature(Label.__init__))"` → `… markup: 'bool' = True …`; `screens.py:707` `ListItem(Label(name))`; `app.py:6559` `ListItem(Label(item.name))` | LLR-172.6, LLR-173.3 |
| P-25 | `current_a2l_data` has two writers and none clears it, not even `_apply_unload`. | premise | ✅ TRUE | `grep -n "current_a2l_data\s*=" s19_app/tui/app.py` → `:8844`, `:11112` only; `_apply_unload` clears `current_a2l_path` alone (`:10250-10251`) | LLR-165.4 |
| P-26 | Nothing outside `app.py` holds the change service, so a rebind resets it completely. | premise | ✅ TRUE | `grep -n "_change_service[,)]" s19_app/tui/app.py` → 0 hits; `grep -rn "_change_service" s19_app --include=*.py \| grep -v tui/app.py` → 0 hits | LLR-165.3 |
| P-27 | The manifest is staged at the fixed `temp/project.json`, and the manifest reader accepts any `int \| str` schema version. | premise | ✅ TRUE | `manifest_writer.py:509` `staged = workarea / WORKAREA_TEMP / PROJECT_MANIFEST_NAME`; `variant_execution_service.py:478-486` | LLR-169.7; no `schema_version` bump |
| P-28 | `set_status` writes the four status log lines, the newest at `#log_line_4`, with markup off, and no P-E prototype variant replaces it. | premise | ✅ TRUE | `app.py:13584-13585` (`set_status` → `_append_log_line`), `:2118` `Label("", id="log_line_4", markup=False)`; `grep -n "set_status" prototypes/load_projects/variants/pe_*.py prototypes/load_projects/variants/_pe_common.py` → 0 hits | the status log is the AT observation point of HLR-168, HLR-169, HLR-178 |
| P-29 | `app.py` calls `set_progress` 24 times, directly or through `call_from_thread`, inside 12 functions. | premise | ✅ TRUE | AST walk of `s19_app/tui/app.py` (calls whose attribute is `set_progress`, or `call_from_thread` whose first argument is it) → `calls 24 enclosing functions 12` (`_finish_generate_report`, `_handle_load_error`, `_start_before_after_worker`, `_start_diff_report_worker`, `_start_generate_report_worker`, `_start_load_worker`, `_trigger_generate_report`, `action_before_after_report`, `load_a2l_from_path`, `load_from_path`, `on_ab_diff_panel_report_requested`, `report_failed`) | LLR-176.2's derived set |
| P-30 | The verdict's prototype variants carry these ids and bindings: `pa_C` `#load_dialog`, `#load_list` (auto-focus), `#load_path`, `#load_preview`, `#load_reason`, `#load_ok`, `#load_cancel`, `escape` / `alt+l`, active-set mark `●`; `pb_A` `#confirm_yes`, `#confirm_no` (auto-focus), `y` / `n` / `escape`; `pc_B` `#project_name` (auto-focus), `#save_summary`, `#save_where`, `#save_ok`, `#save_cancel`, `escape` / `alt+s`; `pd_A` paints `#status_text`; `pe_B` `#result_body`, `#result_variant`, `#result_ok` (auto-focus), `enter` / `escape` / `v`. | premise | ✅ TRUE | `grep -noE 'id="[a-z_]+"\|Binding\("[^"]+"\|AUTO_FOCUS' prototypes/load_projects/variants/{pa_C,_pa_common,pb_A,pc_B,_pc_common,pe_B}.py`; `pd_A.py` `query_one("#status_text", Label).update(t)`; `pa_C.py:44` `mark = "●" if opens …` | the shipped ids (HLR-173..HLR-178) |
| P-31 | The app binds `v` to `select_variant` and `p` to `load_project`. | premise | ✅ TRUE | `app.py:1437-1439` (`Binding("p", "load_project" …)`, `Binding("v", "select_variant" …)`); `action_select_variant` `app.py:6687` | VS-PE-3, VS-PA-4 |
| P-32 | The change-document guard is `LoadGuardScreen`, and `ConfirmDiscardScreen` is the flow-discard modal. | premise | ✅ TRUE | `screens_directionb.py:4279` `class LoadGuardScreen`; `:4808` `self._dirty`; `screens.py:902` `ConfirmDiscardScreen` ("Discard unsaved flow edits?", `:922`) | LLR-174.1 (QA-03) |
| P-33 | `examples/case_06_large_nested_a2l/firmware.a2l` is 37 742 888 bytes, large enough to keep a parse running for several timer ticks. | premise | ✅ TRUE | `ls -la examples/case_06*/` → `37742888 … firmware.a2l`; UX-02's capture: about 5 s to parse | AT-B100-17, AT-B100-18 slow fixture (QA-16) |
| P-34 | `copy_into_workarea` has 15 call sites in 7 product files (17 grep lines, 2 of them docstrings), and 15 test files name it. | premise | ✅ TRUE | `git grep -n "copy_into_workarea(" -- s19_app` → 17 lines; `operations/crc.py:1443` and `flow_persistence_service.py:1096` are docstring text (B-08), leaving `app.py` ×9, `changes/apply.py:781`, `operations/crc.py:1507`, `segment_split_view.py:940`, `flow_execution_service.py:1108`, `flow_persistence_service.py:1106`, `project_gather_service.py:364`; `grep -rl --include=*.py copy_into_workarea tests \| wc -l` → 15 | LLR-163.1 keeps the `Path` return (§6.3) |
| P-35 | The B1 trigger set is 35 test sources, not 116 (the 116 counted `.pyc` files). | premise | ✅ TRUE | `grep -rl --include=*.py "LoadFileScreen\|SaveProjectScreen\|LoadProjectScreen\|copy_into_workarea\|_handle_load_project\|_handle_save_dialog" tests \| wc -l` → 35 | §5.4 reverse census |
| P-36 | Three writers land data files in the open project without the manifest seam. | premise | ✅ TRUE | architect review A-01: `flow_execution_service.py:679`, `:1108`, `variant_execution_service.py:797`; `app.py:2614-2626` (`FlowContext(project_dir=…)`) | the "present, not recorded" kind (LLR-169.5); backlog |

| P-37 | A check document with one entry makes `save_patched` refuse (`ok=False`, 1 entry blocked), because the apply gate blocks every entry of a non-change document. | premise | ✅ TRUE | architect probe `checkdoc.py` (P2 round 2, B-01): `save_patched ok: False \| Patched image not saved - 1 entry blocked - see issues`; `apply.py:227` docstring | the emit decision ignores check documents (LLR-167.1) |
| P-38 | An emit of unchanged data into a folder holding the 16-byte-per-line source lands as a byte-different `_1` file. | premise | ✅ TRUE | QA probe `emit_identity.py` (round 2, R2-01): `firmware_1.s19; data identical: True \| bytes identical: False` | the emit decision is made on data (LLR-167.1) |
| P-39 | Variants sort by `(name.lower(), name)`, so `firmware-patched.s19` sorts before `firmware.s19`. | premise | ✅ TRUE | `python -I -c "print(sorted(['firmware.s19','firmware-patched.s19','firmware_1.s19']))"` → `['firmware-patched.s19', 'firmware.s19', 'firmware_1.s19']`; `workspace.py:1110-1124` | `derived_from` (LLR-168.4) replaces "first by name" |
| P-40 | A 1 MiB `project.json` of `batch` entries takes about 15 s to read with the per-entry resolver. | premise | ✅ TRUE | security probe R3 (round 2): `bytes=1048424 batch entries=75677 read_project_manifest=14.92s` | every manifest array capped at 1 000 (LLR-169.4) |
| P-41 | Tightening `_resolve_manifest_entry` for every caller turns `test_tc_b97_20_hostile_refs_render_literally` red. | premise | ✅ TRUE | architect probe `patch_p8.py` (round 2, B-03): `FAILED tests/test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally`; on base `1 passed` | the tightening runs in a manifest-key mode only (LLR-169.8) |
| P-42 | The Workarea Files pick and the variant switch replace the image without passing the Load dialog's route. | premise | ✅ TRUE | `app.py:9021-9031` (`_load_from_item` → `load_selected_file`); `app.py:6736` `_handle_select_variant` → `load_from_path` (`:6789`) | the one load seam (LLR-174.4) |
| P-43 | The Patch Editor panel's dirty flag has no public reader; it is cleared only by `mark_saved` / `mark_loaded`. | premise | ✅ TRUE | `screens_directionb.py:4808` `self._dirty`; `:5805` `def mark_saved`; `:5815` `def mark_loaded`; `grep -n "def is_dirty" screens_directionb.py` → 0 | Inc 10 adds `screens_directionb.py` (§5.5); Save project calls `mark_saved` (LLR-167.8) |

- **Premise evaluation:** 43 premises · ✅ 43 TRUE · ❌ 0 FALSE · ❓ 0 UNDECIDABLE. Every finding the batch closes reproduces on its base.

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

| # | Condition (`C-52`) | Discharged? | The executed evidence |
|---|---|---|---|
| 1 | **Frozen contract** — no shared interface is touched inside a lane; one that must change returns to the trunk (trigger A3) | ✅ | n/a — one lane: B100-I1 to B100-I12 (`docs/ARCHITECTURE.md` §11) are changed by this trunk batch in sequence |
| 2 | **Disjoint FILE sets**, not just modules — two lanes may not edit the same file, not even different regions | ✅ | n/a — one lane. `app.py` is in 14 of 15 increments (ARQ §8, §9), so no two increments are disjoint |
| 3 | **Crossed reverse census** — family B run per lane and **shared before starting**; the trunk's act, impossible from inside a lane | ✅ | n/a — one lane; the reverse census runs per increment |
| 4 | **One owner of the trunk** — requirements, traceability, backlog and spec are never written from a lane | ✅ | the orchestrator owns the trunk; the implementer works one increment at a time in a throwaway worktree and never commits |

- **Fork preconditions:** none — this batch runs one lane (ARQ §9 verdict: sequential, one worktree per increment)

---

## 3. High-level requirements (HLR)

> **What every acceptance test may observe.** An acceptance test drives the shipped surface with Textual pilot keys and clicks on `S19TuiApp` (headless `run_test`). It observes only:
> - files on disk (image bytes read with `tests/support/independent_reader.py`; `project.json` and `recent_sources.json` read as JSON; digests with `hashlib` in the test);
> - painted text: the status log (`#log_line_1..4`, P-28), `#status_text`, the Loaded panel (`#loaded_panel`), the Patch Editor ledger, dialog and panel text;
> - the screen stack and the focused widget's type and region.
>
> **An AT node holds no `app._…` access and no private call, setup included** (batch-99 QC-AT). A slow action comes from a large fixture file, never a monkeypatch: the case_06 A2L (P-33) or a project built from it.
>
> **Sizes and notifications.** Every UI AT runs twice, at `size=(118, 54)` and `size=(220, 60)`, with `notifications=True`. In every UI surface: no list row wraps, a cut row ends with `…`, and no painted string carries an internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`).
>
> **Keys.** A modal with no text field binds single letters (`y` / `n` / `escape`); a modal with a text field binds `alt+<letter>` and leaves plain letters to the field. Every shown key is verified by pressing it. Test paths and `-k` selectors are provisional until Phase 3 and reconciled at Phase 4 (V-5).
>
> **Output-then-consume (C-12, trigger B4).** Every `project.json` writer/reader pair runs in one chain: drive the shipped handler, re-read what it wrote from disk, open it with the unmodified Load in a fresh app, and assert the consumer's outcome. AT-B100-05, -06, -07, -08, -10 and -20 are those gates. A test that writes `project.json` directly is a consumer-contract guard (a TC), never the gate.
>
> **Refusal tokens (NEW, created in Phase 3 as constants in one module; an AT matches the token, the rest of the wording is free).** Each refusal, problem and empty state paints its reason token and its next-step token.
>
> | Case | Reason token | Next-step token |
> |---|---|---|
> | reserved home as a name | `reserved name` | `choose another name` |
> | Windows device name | `device name` | `choose another name` |
> | disguised clash (Q-2) | `already a project` | `choose another name` |
> | name over 64 characters | `name too long` | `shorten the name` |
> | full path over the limit | `path too long` | `shorten the name` |
> | folder cannot be created or written | `could not save` | `check the folder` |
> | blocked document entry | `blocked entries` | `fix or remove them in the Patch Editor` |
> | empty name | `name is empty` | `type a project name` |
> | empty Load | `nothing selected` | `pick a row or type a path` |
> | typed path not found / unsupported | `not found` / `not a supported file` | `check the path` |
> | typed folder in the work area, not a project | `not a project` | `pick a project in the list` |
> | typed folder outside the work area | `outside the work area` | `copy the folder into the work area` |
> | project folder with no data or A2L file | `no data or A2L file` | `load a file and Save project` |
> | save-as larger than the free space | `not enough free space` | `free disk space or remove files from the project` |
> | Save target is a link or junction | `link or junction` | `choose another name` |
> | empty Projects / work-area files / recents | `no projects` / `no work-area files` / `no recent sources` | `ctrl+s saves a project` / `l loads a file` / — |
> | recent source missing on pick | `not found` | `the entry was removed` |
> | an image-replacing or project action while a worker runs | `busy` + the running action's label | `wait for it to finish` |
> | quit while a worker runs | `still working` + the running action's label | `wait, or quit after it finishes` |
> | problem: manifest damaged | `manifest damaged` + what is wrong in user terms | `Save project rewrites it` |
> | problem: no `project.json` | `no project.json` | `Save project writes it` |
> | problem: missing | `missing` | `restore the file, or Save project to drop it` |
> | problem: not readable | `not readable` + the reason in user terms | `replace the file, or Save project to drop it` |
> | problem: changed on disk | `changed on disk` | `Save project records the new state` |
> | problem: not recorded | `not recorded` | `Save project records it` |
> | problem: no digests saved | `no digests saved` | `Save project records them` |
>
> **An exception to "no private access", declared:** AT-B100-21 reads the save plan the Save dialog holds (one public accessor, `SaveProjectScreen.plan`, NEW) to compare its rows with the written tree by full path and action, because the painted summary may be cut at 118 columns (dispositions r2, UX-32). The accessor returns an immutable value, is read only after `alt+s` has been pressed by key, and each painted row that is not cut at 220 columns is compared by landing name and action (PDR-QA-1).

### HLR-163 — Byte-identical copies are reused
- **Traceability:** US-153
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.9, LED-2026-10-26-batch-100.20
- **Statement:** When a file is placed in the work area or a project, and an existing regular, non-link, non-empty file named `<name>` or `<stem>_<N><suffix>` in the destination holds the same bytes, the system shall reuse that file and write nothing new. Otherwise it shall place the file under the lowest free `_<N>`, as before. One placement function shall decide byte-identity and the landing name for every placement, for the Split/Join export and for the save plan's prediction. The two statuses that claim a file was added or written — the variant append into an open project and the Split/Join export — shall say whether the file was reused: the variant append shall name the existing variant and not report a variant as added, and the export shall report a reused file as reused.
- **Rationale (informative):** identical copies and duplicate variants accumulate (P-6). The reuse widens B99-I2 (B100-I6). The export keeps a second copy of the B8 rule (QA-05). The other placement statuses ("Saved change-set to X", the save-back suffix) are true either way and are not changed (B-09, QA R2-10).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_reuse.py`, plus the re-pinned nodes of LLR-163.3 and LLR-163.4.
- **Numeric pass threshold:** the `p02` C sequence (5 loads of two distinct `firmware.s19` sources) → 2 files in `temp/`, 2 data files in P's folder on disk; 0 status lines reporting an added variant for a reused file; a re-export of identical bytes → 1 `reused` status, 0 new files.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** with project P open, the engineer loads `examples/case_01_basic_valid/firmware.s19`, then `examples/case_02_gaps_and_patch_targets/firmware.s19`, then each again. The work area holds two image files, P's folder on disk holds two data files (listed from disk, QA-25), and the status for each repeated load names the existing variant.
  - **Shipped surface:** Load (`l`, `#load_path`, `#load_ok`; the path field has the focus when the dialog opens, P-30 as corrected by UX-05), the status log, the work area on disk.
  - **Acceptance test(s):** AT-B100-01
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: a 0-byte candidate is never reused; boundary: a same-size candidate with one differing byte (new `_<N>`), a deleted `_1` beside an identical `_2` (reused). Invalid/error: N/A — no input grammar changes.
  - **Negative control:** executed on `1d677ba` (P-6): `firmware_2.s19 310 a9e114d56077` beside an identical `firmware_1` → AT-B100-01 is RED today.

### HLR-164 — Save project refuses unsafe names and leaves nothing behind
- **Traceability:** US-154
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.22
- **Statement:** When Save project receives a project name, the system shall refuse it, painting the reason token and the next-step token, if (a) it is a disguised clash — its sanitised form equals an existing project's folder name compared case-folded while the typed name differs from that folder name — in which case the refusal names both and tells the engineer to choose another name; (b) its sanitised form equals, compared case-folded, a reserved work-area home; (c) the typed name or its sanitised form, compared case-folded, is a Windows device name, with or without an extension or a superscript digit; (d) its sanitised form is longer than 64 characters; (e) it would make a project file path longer than the path limit; or (f) the target folder exists and is a link or junction. A name equal to an existing project that is not open shall save into that project as a merge, shown as a merge in the summary; a name equal to the open project, typed or as its unsanitised form, shall save into the open project. If any operating-system error occurs after the folder is created or after a merge has placed files, then the system shall report it with its tokens, remove the folder the save created or the files the merge placed, and keep running. Every refused or failed save shall leave the work area as it was. The project list shall omit every reserved home compared case-folded.
- **Rationale (informative):** silent merges (P-10), hidden reserved projects (P-14), device names (S-04), a crash on a long name (P-13), escaping `OSError`s (S-05). Q-1 sets the cap at 64 with the full-path check (A-10). Q-2 with QA-04's definitions and A-09's merge decides the existing-project cases; the refusal never suggests a merge (UX-35). Device names are checked on the raw name too (dispositions r2, R2-04/05).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_guards.py`
- **Numeric pass threshold:** 5 reserved spellings (`reports`, `CRC`, `Splits`, `FLOWS`, `Temp`) and 6 device names (`nul`, `CON`, `com1`, `LPT¹`, `con.txt`, `C O N`) → 11 refusals with tokens, 0 folders created; `a b` with project `ab` existing and not open → 1 refusal naming `a b` and `ab` with `choose another name`; `ab` exactly → 1 merge; 64 characters → saved, 65 and 300 → refused, app running, 0 folders; a forced `OSError` at each stage → 0 folders left, 0 raises; a forced `OSError` mid-merge → the target's file set and `project.json` unchanged; `list_projects` over `Splits` and `Reports` folders → 0 listed.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** in the Save project dialog the engineer types `Reports` and saves: the status carries `reserved name` and `choose another name`, and no `Reports` folder appears. `CON` is refused the same way with `device name`. A 300-character name gives `name too long` and the app keeps running. With project `ab` saved and P2 open, saving as `a b` is refused naming `ab`, with `choose another name`.
  - **Shipped surface:** Save project (`ctrl+s`, `#project_name`, `alt+s` / `#save_ok`, P-30), the status log, the work area on disk.
  - **Acceptance test(s):** AT-B100-02
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: an empty name (`name is empty`); boundary: 64 (saved) and 65 (refused), the full-path limit met and exceeded by 1; invalid: reserved and device names in mixed case, a disguised clash, a junction target; error: a forced `OSError` after creation and mid-merge.
  - **Negative control:** executed on `1d677ba` (P-14): `dialog Save 'reports' -> … Saved project` → AT-B100-02 is RED today.

### HLR-165 — A project load starts from an empty session
- **Traceability:** US-155
- **Ledger:** LED-2026-10-26-batch-100.8
- **Statement:** When a project is loaded, the system shall, after the project validates and before it installs the project's first file, reset the session state of ARQ §2.2 rows S1–S13 in one place: the loaded image with its MAC and A2L attachments, the A2L path and parsed data, the change service, the variant ids, the declared regions, the last CRC template, the last comparison and check spec, the last flow run and execution, the report filter, the A2L derived views, and the MAC view caches, validation report and row-key maps. It shall keep the monotonic generation counters (K1) and the view preferences (K2). The app shall expose `_session_snapshot()`, a normalised projection of every attribute its own source assigns, so that a load-over can be compared with a cold load. A Save project after the load shall then copy only that project's files.
- **Rationale (informative):** six leaks and a contaminating re-save (P-2). The snapshot domain is derived from the live app (A-07), not hand-listed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_session_reset.py`
- **Numeric pass threshold:** the `p03` sequence → 0 `LEAK` lines; P2's re-save tree = `['prg.s19', 'project.json']`; the snapshot comparison (LLR-165.2) → 0 differing names outside the declared exclusions.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads P1 (S19 + MAC + A2L), adds a Patch Editor entry, loads P2 (S19 only), answers the load question with `y` (from Inc 10 on), and saves. P2's folder holds `prg.s19` and `project.json` only. The Loaded panel shows no MAC and no A2L, and the Patch Editor ledger is empty.
  - **Shipped surface:** Load (`p`, the project row, `enter`), Save project (`ctrl+s`), the Loaded panel, the Patch Editor ledger, the project folder on disk.
  - **Acceptance test(s):** AT-B100-03
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: loading a project into a fresh session; boundary: loading the same project twice. Invalid/error: N/A — an invalid project is refused before the reset (`app.py:8453-8461`).
  - **Negative control:** executed on `1d677ba` (P-2): `P2 files after re-save: ['firmware.a2l', 'firmware.mac', 'prg.s19', 'project.json']` → AT-B100-03 is RED today.

### HLR-166 — The focus lands on a named, visible, non-text widget
- **Traceability:** US-156
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** When a file load, a project load or an A2L load completes, when a modal opened in the load path closes (the Load dialog, the load question, the Load-result panel), and when a load is cancelled, the system shall put the keyboard focus on the displayed window's focus target: a named widget with a non-zero visible region that is never a text input, never a widget of a hidden window. While the Load-result panel is open, it holds the focus. After the focus lands, the app's single-key bindings reach their actions.
- **Rationale (informative):** every load focuses the hidden Split/Join table (P-16). The panel (P-E B) is a modal on top after a project load, so the focus rule is stated around it (QA-17, UX-04).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_focus.py`
- **Numeric pass threshold:** 4 load paths (Load dialog file, Load dialog project, Workarea Files pick, A2L load) → 4 focused widgets, each the window's declared target, region area > 0, 0 of type `Input` or `TextArea`; `p` after each → the Load dialog opens (4 of 4); panel `enter`, panel `esc`, question `n`, dialog `esc` → the focus on the target (4 of 4).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after a file loads through the Load dialog, pressing `p` opens the Load dialog. After a project load the panel holds the focus; after `enter` closes it, `p` opens the Load dialog.
  - **Shipped surface:** Load (`l`, `p`), the Load-result panel (`#result_ok`), the screen stack.
  - **Acceptance test(s):** AT-B100-04
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: a cancelled load (`esc` in the dialog); boundary: a load while the Split/Join window is shown (its table is the target). Invalid/error: N/A — a failed load leaves the focus where it was.
  - **Negative control:** executed on `1d677ba` (P-16): `focused region area: 0`, `` `p` -> Screen `` → AT-B100-04 is RED today.

### HLR-167 — Save project saves the source plus the change document, verified, and copies when nothing changed
- **Traceability:** US-157
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.13, LED-2026-10-26-batch-100.14
- **Statement:** When Save project runs, the system shall re-derive the change document's entries onto a copy of the source image; a check document never counts. If the re-derived data differs from the source file's data, the system shall emit that image into the project through `save_patched`'s emit-and-verify half (the save-back's rule, B99-I7), with 32 bytes per line and the source's S0 header, record its `derived_from`, and update the view's image in place so that it equals what was saved; the status shall say how many document entries the image carries and how many this save applied. Otherwise the system shall copy the source byte for byte and create no new variant. A check document is saved to `checks/` and never blocks the save. If the re-derive blocks any entry of a change document, then the system shall refuse the whole save, name the blocked entries with their tokens, and leave no folder it created. MAC and A2L files stay byte copies. When the target folder already holds a different file with the image's name, the image shall land as the save plan predicts (`<stem>_<N>`) and become the project's active variant. Every file a Save project writes shall be the one its save plan names (HLR-175, R-PC). A successful Save project shall record the saved image state and clear the Patch Editor's dirty flag once the document is written.
- **Rationale (informative):** the save copies the work copy and drops the patch (P-1). D1 = `imagen`; A-06 keeps one rule for one fact. B-01 / QA R2-01 move the emit decision onto data (P-37, P-38): the round-2 rule ("differs from source or the document holds an entry") made a check document refuse every save and wrote byte-different copies of unchanged data — §6.3 records it as a round-2 deviation corrected here. UX-27: the dirty flag is cleared like the save-back clears it.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_image.py`
- **Numeric pass threshold:** the `p01` sequence → the project image read by the independent reader equals source + change document (0 differing addresses), every S19 data record ≤ 32 data bytes, the S0 equal to the source's; a check-document-only session → byte copy (0 differing bytes) and the document written under `checks/`, 0 refusals; an unchanged change document (an entry that writes the bytes already there) → byte copy, 0 new variants; a real change → emit; an entry added after the apply → written; only unapplied entries → emitted; a blocked change document → 0 files, 0 folders left; save-back then Save project → the patch in the project image; after Save project → the Patch Editor dirty flag clear (1 assertion).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads `case_01` `firmware.s19`, applies `0x8000007C DE AD BE EF` in the Patch Editor without a save-back, saves project P1, and reopens P1 in a fresh app. The independent reader finds `DE AD BE EF` at `0x8000007C` in `P1/firmware.s19`; the save status names 1 entry; after the reopen, the Loaded panel names `firmware.s19` and (from Inc 6) the Load-result panel names it as patched (the consumer oracle, QA-09). A session holding only a check document saves `firmware.s19` byte-identical to the source.
  - **Shipped surface:** Patch Editor (Add, Apply), Save project (`ctrl+s`, `alt+s`), Load (`p`), the Loaded panel, the Load-result panel, the project folder.
  - **Acceptance test(s):** AT-B100-05
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no entry and an unchanged image (byte copy); boundary: an entry that writes the bytes already there (byte copy, no variant), an entry added after the apply, a folder that already holds `firmware.s19` (lands as `firmware_1.s19`); invalid: a check document (never an emit, never a refusal); error: a blocked change-document entry (whole save refused).
  - **Negative control:** executed on `1d677ba` (P-1): `project firmware.s19 == in-memory patched image? False` → AT-B100-05 is RED today.

### HLR-168 — A save-back into the project becomes the active variant
- **Traceability:** US-158
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.23
- **Statement:** When a Patch Editor save-back writes an image into the open project, the system shall make that image the project's active variant in the session and in `project.json`, record the variant it derives from as `derived_from`, and keep `current_file.path` on the source the image was loaded from. When any write lands a file in the open project — Save project, the save-back, the Load-file variant append, the MAC sync or the A2L sync — the system shall rewrite `project.json` through the manifest seam, carrying every key it does not own (`batch`, `assignments`, `declared_regions`, `gathered`, `active_document`, `derived_from`, `files` records of untouched files) unchanged and project-relative. A Load file that makes the loaded file the project's active variant shall say so in a status line naming the project and the file it now opens. When the project is loaded, the system shall open the active variant `project.json` records.
- **Rationale (informative):** the save-back adds a variant that Load never opens (P-3). D2 = `ultima`; O-1; O-10. A-02, A-03, UX-14; UX-26 (`derived_from`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_active_variant.py`
- **Numeric pass threshold:** `p02` A and B → the reload opens the patched variant (2 of 2 arms); 4 in-project writers → 4 manifest rewrites, each with 0 changed keys it does not own and 0 absolute paths; a document recorded, then a variant append, then reopen → the document reopened (1 arm); the append → 1 status line naming the project and the file; a save-back → `derived_from` names the source variant (1 arm).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-06) with project P open, the engineer applies a patch and saves back as `firmware.s19` (placed as `firmware_1.s19`). Reopening P in a fresh app loads `firmware_1.s19`: the status log's summary line names it, and the independent reader finds the patch in it. `project.json` on disk names `firmware_1` as `active_variant` and `firmware` as its `derived_from`. (AT-B100-20) With P open and `batch`, `assignments`, `declared_regions`, `gathered` and `active_document` all set, the engineer (1) loads a new S19, (2) loads a MAC, (3) loads an A2L through Load. After each, `project.json` on disk keeps those five keys equal (JSON compare) with 0 absolute paths, and after (1) it names the new `active_variant`. A fresh app opening P shows the new variant in the Load-result panel, the document in the Patch Editor ledger, and the batch documents in the Execute-scope list.
  - **Shipped surface:** Patch Editor save-back (`#patch_saveback_*`), Load (`l`, `p`), the status log, the Load-result panel, the Patch Editor ledger, the Flow Execution Execute-scope list, `project.json` on disk.
  - **Acceptance test(s):** AT-B100-06, AT-B100-20
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: the default save-back name (`firmware-patched.s19`, `p02` B) and a reused identical name (M-1); error: a manifest rewrite whose verify fails (the existing mismatch notice, `app.py:8416-8423`). Empty/invalid: N/A.
  - **Negative control:** executed on `1d677ba` (P-3): `RELOAD -> file=firmware.s19 … image_is_patched=False` → AT-B100-06 is RED today; A-03's executed carry probe (`serialize_manifest` refuses the reader's absolute `batch`) → AT-B100-20 RED for a carry written without the conversion: 3 arms, each with 5 key comparisons.

### HLR-169 — Load opens what is valid and lists every problem
- **Traceability:** US-159
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.29
- **Statement:** When the manifest seam writes `project.json`, the system shall record under `files` the size and SHA-256 of every top-level file with a project data or A2L suffix and of the active document, computed from disk after every copy has landed, and shall stage the manifest in a private directory. When a project is loaded, the system shall open every valid file, open the next valid variant when the active one is missing or unreadable, and report at most one problem per file, its highest by this precedence: manifest damaged or no `project.json` > missing > not readable > changed on disk > not recorded > no digests saved. It shall read at most 1 MiB of `project.json` and at most 1 000 entries in each of `batch`, `declared_regions`, `gathered`, `files` and `derived_from`, and 1 000 in total across `assignments`, reporting the excess as a damaged manifest. Problems shall be painted in user terms with their next step; internal issue codes go to the log only. The status log shall carry one summary line; the Load-result panel shall carry the full list (HLR-178). Every malformed or unsafe manifest record shall be reported and skipped, never trusted.
- **Rationale (informative):** damaged manifests, corrupt images and edited images load as success (P-4); a missing image gives a misleading status (P-5). D3; O-2; O-11; QA-07; A-01; A-18; S-08 and security R2-03 (P-40: every array is capped); A-05; QA R2-09 (user terms).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_check.py`
- **Numeric pass threshold:** the `p04` cases 2, 5, 6, 7, 9, a legacy project and a hand-copied data file → exactly 1 problem each, of the matching kind, naming the file (case 6: `not readable` only; case 7: `manifest damaged` only); a clean project → 0 problems; every case → the project opens; a manifest with 1 001 entries in any one array → 1 `manifest damaged`, load under 1 s.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer saves project P, a byte of `P/firmware.s19` changes on disk, and P is reopened in a fresh app: P opens, the summary line (`#log_line_4`, read at 118 columns) carries `1 problem` inside the painted width, and the panel names `firmware.s19` as `changed on disk` with `Save project records the new state`. A hand-edited `project.json` whose `files` names `../outside.s19` opens P; the panel paints `manifest damaged` naming that record in user terms ("a file path points outside the project"), the internal code appears only in the log, and nothing outside P is read.
  - **Shipped surface:** Save project, Load (`p`), the status log, the Load-result panel, `project.json` on disk.
  - **Acceptance test(s):** AT-B100-07
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no `files` key (legacy), no `project.json`; boundary: an equal size with a different digest, exactly 1 000 entries in an array; invalid: hostile `files` keys and values (LLR-169.4); error: a `project.json` that is not JSON.
  - **Negative control:** executed on `1d677ba` (P-4): `[2 image edited on disk] … notices=[]` → AT-B100-07 is RED today.

### HLR-170 — The change document is saved and reopened with the project
- **Traceability:** US-160
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.10
- **Statement:** When Save project runs while the Patch Editor holds a document with at least one entry, the system shall place that document in the project's `patches/` (or `checks/` by kind) — a document that has no file is written by the app as `patches/changes.json` through the M-1 rule, landing as `changes_<N>.json` when a different `changes.json` is there — and record the landed project-relative path as `active_document` in `project.json`. When the project is loaded, the system shall reopen that document in the Patch Editor after the project's A2L is attached. If the recorded document is missing, unreadable, outside `patches/` or `checks/`, or not a `.json` file, then the load shall continue and list the problem.
- **Rationale (informative):** the gathered document is not reopened and a pasted one is not saved (P-8). D4 = `reabrir`; Q-5; A-12 (the app writes, the gather only places); S-11 (the reader enforces the writer's rule).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_document.py`
- **Numeric pass threshold:** `p06` A → after Load, the Patch Editor document is `patches/boost.json` with 1 entry; `p01` (pasted) → `P/patches/changes.json`, reopened with 1 entry; a different `changes.json` already there → `changes_1.json` recorded; a missing recorded document → 1 problem, the project opens.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer pastes one entry into the Patch Editor, saves project P and reopens P in a fresh app: the Patch Editor ledger lists that entry's address.
  - **Shipped surface:** Patch Editor, Save project, Load, the Patch Editor ledger.
  - **Acceptance test(s):** AT-B100-08
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a document with 0 entries (not recorded); boundary: a file-backed document already in `P/patches/` (reused, M-1), a clashing `changes.json`; invalid: an `active_document` outside `patches/`/`checks/` or not `.json`. Error: N/A — a missing document is a listed problem.
  - **Negative control:** executed on `1d677ba` (P-8): `after Load: editor doc = None entries = 0` → AT-B100-08 is RED today.

### HLR-171 — Projects live in this work area and reopen complete
- **Traceability:** US-161
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.22
- **Statement:** When Save project saves the open project under a new name, the system shall copy every sub-folder of the open project, with its regular files, into the new project, without following any directory link or junction, and listing each link it skipped; one link-pruned walk shall produce both the file list and the total, and the save shall be refused before the new folder is created when that total exceeds the free space of the work area's volume. When a project holds an A2L and no data file, Load shall open its A2L. Every placement — every file any writer lands in the work area, the save-back and Save project's emit included — shall be refused unless its destination is inside this app's work area after links and junctions are resolved; this check lives in the one placement function, so no writer is left off a list. A project folder that is itself a link or junction shall not be listed, loaded or written, and Save project shall check its target for a link or junction before resolving it. When Save project is given a parent folder that does not resolve to this work area, the system shall refuse the save before creating any folder.
- **Rationale (informative):** "save as" leaves flows, patches and reports behind (P-9); an A2L-only project cannot be loaded (P-12); a save elsewhere is never listed (P-11); a junction in the work area escapes every containment check (S-02, security R2-01); a junction inside a sub-folder copies an outside tree (S-03, security R2-06); a large copy can fill the disk (S-15).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_homes.py`
- **Numeric pass threshold:** `p06` C → Q holds every file of P's sub-folders (0 missing, 0 differing bytes); a top-level directory junction, a nested junction and a file symlink in P → 0 files copied through them, 3 skips listed, 0 bytes added to the total; `p04` 10 → the A2L-only project opens with 3 A2L tags; a junction project folder pointing into another work area → 0 listed, 0 loads, and 0 bytes written outside `self.workarea` by Save project (new name and merge), the save-back, the variant append and the MAC and A2L syncs; a foreign parent → refused, 0 folders.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-09) the engineer opens P (with `flows/f1.json`, `patches/boost.json`, `reports/r.md`) and saves it as Q: Q's folder holds those files, and Q's flow list shows `f1`. (AT-B100-10) An A2L-only project saved and reopened shows its A2L in the Loaded panel. (AT-B100-11) A project folder in the work area that is a junction into another work area is not listed in the Load dialog, and typing its name in Save project is refused with `link or junction`, while a project saved through the dialog is listed.
  - **Shipped surface:** Save project, Load, the Loaded panel, the Flow Execution import list, the project folders on disk.
  - **Acceptance test(s):** AT-B100-09, AT-B100-10, AT-B100-11
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a project with no sub-folder; boundary: a nested sub-folder, a copy exactly at the free space; invalid: links and junctions; error: a foreign parent, a copy over the free space.
  - **Negative control:** executed on `1d677ba`: P-9 → AT-B100-09 RED; P-12 → AT-B100-10 RED; S-02's executed probe (a junction folder is listed and written through) → AT-B100-11 RED.

### HLR-172 — Recent sources, typed project paths and literal file names
- **Traceability:** US-162
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.30
- **Statement:** When a file from outside the work area loads successfully through Load or the A2L load, the system shall record it in the per-user store `%LOCALAPPDATA%\s19_app\recent_sources.json`, outside every work area and every `.s19tool` folder, newest first, de-duplicated by resolved path, at most 20 entries, staged under a unique name. Reading that store shall return only safe entries and shall never raise; an unparseable file shall read as empty, and an oversized one as empty with a `too large` problem. The Workarea Files list and the Load dialog shall enumerate the work-area files through one function. When a typed path resolves to a project in this work area, or to its `project.json`, the system shall load that project; a reserved home shall never load as a project; any other folder inside the work area shall be answered with the `not a project` tokens, and a folder outside it with the `outside the work area` tokens. The Workarea Files list shall render file names through `safe_text`.
- **Rationale (informative):** L-2 (P-15); the unified dialog needs its data sources (ARQ §6); file names are parsed as markup (P-24); `temp` loads as a project (S-01); store entries could reach the network or carry control characters (S-06, S-07, S-12). The operator's S-16 decision moves the store per user, which also removes the planted-store route S-07 started from.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_recents.py`
- **Numeric pass threshold:** 25 outside loads → 20 entries, newest first, in the per-user store; 0 files named `recent_sources.json` under the base folder; the hostile store set (LLR-172.2) → 0 raises, 0 unsafe entries returned; `ab` and `ab/project.json` typed → 2 project loads of `ab`; `temp`, `TEMP`, `patches` typed → 0 project loads, 0 files written; 4 hostile file names → 4 literal rows, 0 markup spans, 0 control characters.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-12) the engineer loads `examples/case_01_basic_valid/firmware.s19` through Load, then types the work-area path of project `ab`: the per-user store on disk (the test points `LOCALAPPDATA` at a temporary folder) lists the example's absolute path, nothing is written under the base folder, and the status log names project `ab` loaded. (AT-B100-13) Files named `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and one with U+009B in the work area appear in the Workarea Files list exactly as named, with no style and no control character.
  - **Shipped surface:** Load (`l`, `#load_path`), the Workarea Files list (`#files_list`), the status log, the per-user store on disk.
  - **Acceptance test(s):** AT-B100-12, AT-B100-13
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no store file (an empty list); boundary: the 20th and 21st entry, exactly 65 536 bytes; invalid: hostile store entries and markup-shaped names; error: an unreadable store file, `LOCALAPPDATA` unset.
  - **Negative control:** executed on `1d677ba` (P-15): `Load file 'ab' -> status=['Unsupported file type: ']` → AT-B100-12 RED today. AT-B100-13: with today's `Label(item.name)` (`app.py:6559`, markup on) `[bold]x.s19` paints 1 span (QA-02 probe) → RED.

### HLR-173 — One Load dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.18
- **Statement:** When the engineer opens Load, the system shall show one two-pane dialog: on the left a typed-path field and the work area's projects, the work-area files and the recent sources; on the right a preview of the highlighted item that marks with `●` the active set — the image variant, MAC and A2L that loading it will install, including what the session keeps and, with a project open, the note that a loaded file becomes its active variant. The panes shall stack below 100 columns. In that dialog: the focus shall start on the path field; `tab` shall move path → list → preview → buttons; a printable key typed while the list has the focus shall move to the path field and type there, never reaching an app binding; `enter`, `alt+l` and `#load_ok` shall load the highlighted row when the list has the focus and the typed path otherwise; `escape` shall close it and change nothing; a Load with nothing selected or typed, or with a typed path that is invalid, shall keep the dialog open, keep the typed text and paint the reason and next-step tokens in `#load_reason`; a click shall select a row and not load it. Every name read from disk or from the store shall render through `safe_text`. A recent row shall show only its path, size and when it was last seen, say that it is checked when loaded, and touch the filesystem only after Enter. A project row's preview shall read the manifest on a worker with a bounded read, so a highlight never blocks the dialog. The dialog shall dismiss with `LoadChoice(kind, value)`, routed through the one load seam (LLR-174.4), and a work-area pick shall load that file in place, with no second copy. The files installed by a load shall be the files the preview marked.
- **Variant slots (filled by the P-A verdict C, LED-2026-10-26-batch-100.2; corrected by LED-2026-10-26-batch-100.18):** VS-PA-1 = two panes, preview on the right. VS-PA-2 = a click selects; Enter loads; a double-click is not bound. VS-PA-3 = the `pa_C` ids (`#load_dialog`, `#load_list`, `#load_path`, `#load_preview`, `#load_reason`, `#load_ok`, `#load_cancel`); `#project_list` and the separate Load project dialog retire. VS-PA-4 = `l` and `ctrl+l` open this dialog with the focus on the path field; `p` opens it with the open project's row highlighted, else the first project; the key bar labels them "Load" and "Projects". VS-PA-5 = the preview marks the active set with `●` for every row kind (project, file, work-area, recent). VS-PA-6 = the focus order above (path field first, which corrects `pa_C`'s start on the list).
- **Rationale (informative):** the dialog has no list, ignores `escape`, and an empty or Enter-only Load does nothing (P-18..P-20). The operator's P-A note asks for the active-set symbol. UX-05 / QA R2-06 (focus), UX-36 (marks for every row kind), UX-37 (`p`), security R2-03 (the preview never blocks).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py`
- **Numeric pass threshold:** 4 `LoadChoice` kinds → 4 routes; `enter` on each section → 1 load; for a project, a file and a file with a project open, the `●` rows = the installed image, MAC and A2L paths (3 of 3 each); `escape` → 0 changes to the session; an empty Load and 3 invalid typed paths → 4 painted token pairs, the dialog open, the typed text kept; `p` typed while the list has the focus → the path field holds `p`, 0 app actions; 4 hostile names → 0 markup spans, 0 control characters; a recent entry rendered → 0 filesystem calls before Enter; highlighting a project with an over-cap manifest → a key answered within 200 ms; a work-area pick → 0 new files in `temp/`; at 99 columns → panes stacked, at 118 → side by side.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads an example through Load (which records it), restarts the app, opens Load, moves to the recent source and presses Enter: that file loads. Highlighting a project, the preview marks `●` on its active image, MAC and A2L, and after Enter the Loaded panel names exactly those three. `escape` closes the dialog with the session unchanged. An empty Load paints `nothing selected`. A project named `[b]P` is listed as written.
  - **Shipped surface:** the Load dialog (`l`, `p`; `#load_path`, `#load_list`, `#load_preview`, `#load_reason`, `alt+l`), the Loaded panel, the status log, the screen stack.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no project, no file, no recent (each section shows its tokens); boundary: one item per section, 99 and 100 columns; invalid: hostile names, a hostile store, an invalid typed path, an over-cap manifest; error: a recent source missing on pick (`not found`, the entry removed).
  - **Negative control:** executed on `1d677ba` (P-18, P-19): `escape on LoadFileScreen -> screen: LoadFileScreen`; `Enter with a typed path -> current_file before/after: firmware_1.s19 / firmware_1.s19` → AT-B100-14 RED today.

### HLR-174 — One short question before unsaved work is lost, on every route
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17
- **Statement:** When an image-replacing route — the Load dialog, the Workarea Files pick, the variant switch (`v`, the panel's `v`) or a project load — would lose unsaved work, the system shall ask once before loading, in the one load seam every such route passes. Unsaved work is: an image that differs from the copy last loaded or saved (lost by any image replacement and any project load), Patch Editor entries the dirty flag marks (lost by a project load), and Flow Builder edits not saved (lost by a project load). Loading a MAC or an A2L only attaches it, loses nothing and never asks. The question shall be short and name what would be lost, all items in one question. `y` shall replace and continue; `n` and `escape` shall cancel and leave the session unchanged; the focus shall start on `n`, and `enter` shall act on the focused button. A load that would lose nothing shall not ask, whether or not a project is open. The question shall be answered before the project-session reset runs, and never inside `_handle_load_project`.
- **Variant slots (filled by the P-B verdict A, LED-2026-10-26-batch-100.2):** VS-PB-1 = the short question. VS-PB-2 = no "save first" key. VS-PB-3 = the `pb_A` ids (`#confirm_yes`, `#confirm_no`).
- **Rationale (informative):** a patched image is replaced with no question (P-17). UX-01, UX-11, QA-03, UX-12, O-3. B-02 / QA R2-03: the Workarea pick and the variant switch bypassed the dialog's route (P-42). QA R2-02: an attach loses nothing. UX-27: Save project clears the document flag (LLR-167.8).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py`
- **Numeric pass threshold:** the 24-cell trigger table (LLR-174.1) → 24 of 24 cells as tabulated (11 ask, 13 load); 4 routes with an unsaved patch → 4 questions; patched → Save project → load = 0 questions; patched + entries → Save project → project load = 0 questions; patched → save-back → load = 0 questions; patched → saved → patched again → load = 1 question; an unsaved patch, then an A2L load → 0 questions, the patch kept; `n`, `escape` and an immediate `enter` → 0 changes to the image digest, the file path and the project; `y` → 1 load; 2 items unsaved → 1 question listing both.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer applies a patch and loads another file: a question appears naming the patched image, with the focus on No; `enter` keeps the patched image (the hex view still shows the patch); repeating with `y` loads the new file. A Workarea Files pick with an unsaved patch asks the same question. After Save project, the same load asks nothing.
  - **Shipped surface:** Load, the Workarea Files list, `v`, the question (`#confirm_yes`, `#confirm_no`, `y` / `n` / `escape`), the hex view, the status log.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: nothing unsaved, with or without a project open (no question); boundary: a patch that writes the bytes already there (no question), saved-then-patched-again (asks), an A2L or MAC attach (no question). Invalid/error: N/A — the answer keys are a closed set.
  - **Negative control:** executed on `1d677ba` (P-17): `Load file over patched image -> stack: ['Screen'] … image still patched? False` → AT-B100-15 RED today.

### HLR-175 — The Save project dialog shows exactly what the save will do
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.31
- **Statement:** While the engineer types a project name in the Save project dialog, the system shall paint, from the same save plan `_handle_save_dialog` executes, a summary at the plan's granularity: the target folder and its kind (new, the open project, a merge); one row per top-level file, one row per sub-folder with its file count, and one row for `project.json`; each row with its source, its landing name and its action word (`new`, `replace`, `keep`, `merge`, `rewrite`); the image as "source + N change entries (K of them applied by this save)" or as an unchanged copy; the document; skipped links. Nothing is overwritten silently: every `replace` or `rewrite` is a row that says so, and in a merge the target's active-variant change is its own row. When the name would be refused (HLR-164), the summary shall paint the refusal tokens, and Save shall stay focusable and refuse with the reason painted. When the name is over 64 characters or would update the open project, the summary shall say so. A long summary shall scroll with Save and Cancel pinned. The image digest shall be computed once per dialog open, and the name-dependent rows recomputed at most every 150 ms of typing, with no hashing per keystroke. The dialog shall offer no parent folder field and no Browse… button, and the save shall go to this work area. `escape` shall close the dialog and save nothing; a Save with an empty name shall keep the dialog open and paint `name is empty`; Save is `alt+s` and plain letters stay in the name field; names read from disk shall render through `safe_text`.
- **Variant slots (filled by the P-C verdict B, LED-2026-10-26-batch-100.2):** VS-PC-1 = the name plus the "what will be saved" summary, at the row granularity above. VS-PC-2 = during a refusal, Save stays focusable and refuses with the reason painted. VS-PC-3 = the `pc_B` ids (`#project_name`, `#save_summary`, `#save_where`, `#save_ok`, `#save_cancel`).
- **Rationale (informative):** no preview, no `escape`, a silent empty Save (P-18, P-19); D7's dialog half removes the parent field. The operator's P-C note: "Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información." — hence R-PC: one plan, painted and executed. UX-32 / QA R2-05 (granularity), UX-33 / B-04 (cost), UX-35 (merge row).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py`
- **Numeric pass threshold:** 5 scenarios (fresh; exact name of an existing project; save-as with sub-folders; pending patch; reserved and clash refused) → the plan's rows equal the written tree at the plan's granularity, by full path and action (0 differences), refused scenarios → 0 files; `a b` → the folder line shows `ab`; 0 widgets `#project_parent_path` / `#save_browse`; `escape` → 0 folders; an empty Save → 1 token pair; typing `s` → the name field holds `s`; 20 keystrokes on the case_06 project → 0 digest computations, each echoed within one frame; a 300-row summary at 118×54 → Save and Cancel visible.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16) the engineer opens Save project, types `a b` and sees `ab` as the folder; types the disguised name of another project and sees `already a project` and `choose another name` before pressing Save; presses `escape`, and no folder appears. (AT-B100-21) For each of the 5 scenarios, the engineer presses `alt+s`; the test then reads the dialog's save plan (never calling the planner or driving the save through it) and finds its rows equal to the tree on disk, at the plan's granularity, by full path and action; at 220 columns each painted row that is not cut matches its plan row by landing name and action.
  - **Shipped surface:** the Save project dialog (`ctrl+s`, `#project_name`, `#save_summary`, `alt+s`; the plan through `SaveProjectScreen.plan`, the exception declared in the §3 preface), the work area on disk.
  - **Acceptance test(s):** AT-B100-16, AT-B100-21
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: an empty name; boundary: a name of 64 and 65 characters, a target holding the source's name, a 300-row summary; invalid: reserved, device and clashing names; error: a refused save (0 files).
  - **Negative control:** executed on `1d677ba` (P-18, P-19): `escape on SaveProjectScreen -> screen: SaveProjectScreen`; `empty name Save click -> … new status: []` → AT-B100-16 RED today. AT-B100-21: a mutation where the handler places a file the plan did not name → 1 tree row without a plan row → RED.

### HLR-176 — Worker actions show real progress in the status line
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19
- **Statement:** When an action that runs on a worker starts — a file or project load, an A2L parse, Save project, a report, a diff report, a before/after run — the system shall paint in `#status_text` a spinner, the action's label, the step `n/m` and the elapsed time, and shall show the progress bar from 0. The bar shall advance within a step wherever progress is measurable (bytes copied, read or parsed) and by step only for an indivisible step. While the action runs, the spinner and the elapsed time shall advance, and `#status_text` shall have one owner, the progress line. When it ends, by success, failure or exception, one final writer shall paint, in this order, the outcome, then the project and file line, then the file state, and the bar shall be hidden — never left at a stale `100%`; when idle the bar is hidden. A step that cannot leave the main thread — the A2L tag-table build — shall have its step name painted before it starts; during it the indicator stays frozen, and this freeze is declared and not covered by the elapsed-time clause.
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-1 = the status line (`#status_text`), with the progress bar kept working. VS-PD-2 = no cancel.
- **Rationale (informative):** N5. The operator's P-D note: "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso." — hence R-PD and UX-30: the bar moves within the long steps. UX-29 / B-11: one owner of `#status_text`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py`
- **Numeric pass threshold:** every action key → exactly 1 begin and 1 end on its success, failure and exception exits (0 indicators left showing); the case_06 A2L parse → the bar value increases ≥ 2 times within the parse step and the elapsed text changes ≥ 1 time before the end; after a project load ends → `#status_text` holds the project and file line, the bar hidden (2 assertions); the tag-table step → its name painted before it starts.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads the case_06 A2L: `#status_text` shows a spinner, the label and a running elapsed time while it parses, the bar moves during the parse, and at the end the status names the outcome and the bar is gone.
  - **Shipped surface:** Load (`l`), `#status_text`, `#progress_bar`, the status log.
  - **Acceptance test(s):** AT-B100-17
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: an action shorter than one timer tick (shown and cleared); error: an action that raises (the indicator ends with the failure). Empty/invalid: N/A — no input.
  - **Negative control:** executed on `1d677ba` by the round's capture (UX-02): the screen did not repaint between the start and the end of the case_06 parse → AT-B100-17 RED today.

### HLR-177 — Project load, Save project and the A2L parse run off the main thread
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19
- **Statement:** The system shall run project load, Save project and the A2L parse on worker threads and install their results on the main thread only. Save project shall re-derive the image on the main thread before its worker starts, and the worker shall write from a copy. While one of these actions runs, the indicator's elapsed time shall advance, and every action that replaces or changes the image or the project — a load on any route, an unload, `v`, a save-back, Save project, a Patch apply or undo — shall be refused with the `busy` token naming the running action, leaving the session and the focus unchanged. Quit shall ask first, with the focus on No; if the engineer confirms, the app shall wait for the worker to finish or roll back, so no partial folder is left. Flow runs stay on the main thread.
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-3 = a second request is refused with a status naming the running action.
- **Rationale (informative):** these three block the main thread (ARQ §7). R-PD makes 12b unconditional; O-7 leaves flow runs; A-17 keeps the worker off the live image; UX-34 lists the refused set and the quit rule.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py`
- **Numeric pass threshold:** the project holding the case_06 A2L → the elapsed text changes ≥ 1 time before the load ends (the worker share measured above one timer tick at P3); 0 writes to the session outside the main thread (thread-id probe); the same final snapshot as a main-thread load (0 differing names, LLR-165.2); `l`, `v`, an unload, a save-back and a Patch apply during a Save project → 5 `busy` refusals, 0 changes; `q` during a Save project → 1 question; confirmed → 0 partial folders.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads a project holding the case_06 A2L: the elapsed time advances during the load, and the status log then names the project loaded. During a Save project, pressing `l` (after the worker step is painted) paints `busy` naming Save project, and `q` asks first.
  - **Shipped surface:** Load, Save project, `#status_text`, the status log, the quit question.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a load that finishes inside one tick; error: a worker that raises (the app keeps running, the indicator ends, 0 folders left). Empty/invalid: N/A.
  - **Negative control:** code-read on `1d677ba`: `_handle_load_project → load_selected_file` runs synchronously (`app.py:8510`, `:10731`), so the elapsed text cannot advance during it → AT-B100-18 RED today (executed at Phase 3).

### HLR-178 — The Load-result panel says which variant opened and lists the problems
- **Traceability:** US-168
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16
- **Statement:** When a project load completes, the system shall open the Load-result panel, which names the variant it opened, the number of variants the project holds and why that one opened — recorded as active; first by name because the manifest records none; first by name because the manifest is damaged or absent; or the next valid one because the recorded one is missing or not readable — and, from the `derived_from` record (from Inc 7), how it relates to its base — "patched, N bytes differ from `<base>`" when the base is a file of the project, "patched from `<base>` (not in this project); N bytes differ from it" when it is not; a variant with a record is always called patched, never identical — the other variants, the MAC and A2L that loaded, and every problem of HLR-169 with its file and next step, with no truncation. The word "latest" shall be used only for the variant the app's last recorded write made active, never from file times. The focus shall start on the problem list (↑, ↓, PgUp, PgDn scroll it); `tab` moves to OK; `enter` on OK and `escape` dismiss it; `v` opens the existing variant selector. The status log shall carry one summary line naming the opened variant, the variant count and the problem count, ending with "details: p", and the progress line's final writer shall set `#status_text` to the project and the opened file. Problems shall be worded in user terms, never as an exception class or an internal code. Every name read from disk shall render through `safe_text`. The same information shall stay reachable for the session in the Load dialog's preview of the open project.
- **Variant slots (filled by the P-E verdict B, LED-2026-10-26-batch-100.2):** VS-PE-1 = the result panel to dismiss. VS-PE-2 = the wording above. VS-PE-3 = `v` opens the existing variant selector (`select_variant`, `app.py:6687`).
- **Rationale (informative):** the operator's D2 note; D3; UX-26 (the default `firmware-patched.s19` sorts before `firmware.s19`, P-39, so "first by name" compared the patched image with itself; `derived_from` is written from Inc 7, ARQ §8.1); UX-31 / UX-39 (keyboard reach); UX-38; UX-40; A-16; A-18.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_announce.py`
- **Numeric pass threshold:** the 5-reason truth table (LLR-178.1) → 5 of 5; from Inc 7: a save-back named `firmware_1.s19` and one with the default `firmware-patched.s19` → each panel says "patched, 4 bytes differ from `firmware.s19`" (2 of 2); a base not in the project → "patched from `firmware.s19` (not in this project); 4 bytes differ from it"; 0 panels containing "identical"; 30 problems at 118×54 → the last row reaches a visible region by keyboard; 1 summary line in `#log_line_4` inside 118 columns ending "details: p"; a hostile variant name → 0 markup spans; 0 exception class names and 0 internal codes in the panel.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after a default save-back into P (`firmware-patched.s19`), reopening P opens the panel naming `firmware-patched.s19` as opened, recorded as active, "patched, 4 bytes differ from `firmware.s19`" (from Inc 7), and P's 2 variants. With the opened file deleted on disk, reopening names `firmware.s19` as opened because the recorded one is missing, and lists the file as `missing`. `end` scrolls to the last problem; `tab`, then `enter`, closes the panel.
  - **Shipped surface:** Load (`p`), the Load-result panel (`#result_body`, `#result_variant`, `#result_ok`), the status log.
  - **Acceptance test(s):** AT-B100-19
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a one-variant project, no `derived_from`; boundary: a project whose every image is unreadable (A2L or MAC only), 30 problems, the default save-back name, a base not in the project; invalid: a hostile variant name. Error: N/A — problems are data, covered by HLR-169.
  - **Negative control:** executed on `1d677ba` (P-3): the reload status is `Loaded project 'P' -> firmware.s19`, with no panel, no count and no reason → AT-B100-19 RED today; P-39: a composer comparing with the first variant by name says "identical" for the default name → RED.

---

## 4. Low-level requirements (LLR)

> Ids `LLR-<HLR>.<M>`. TC ids are `TC-B100-NN`. Each LLR's mutation (Negative control) is run at Phase 3 (C-40) and described by position and operation, never pasted (C-56). Symbols marked NEW are created in Phase 3. Round 2 added LLR-163.6, LLR-167.5, LLR-167.6, LLR-169.8, LLR-169.9, LLR-171.4, LLR-173.5, LLR-173.6, LLR-175.4 and LLR-178.3 (and LLR-173.7); round 3 added LLR-163.7, LLR-167.7, LLR-167.8, LLR-168.4 and LLR-174.4; no requirement was retired.

### LLR-163.1 — One placement function holds every guard and decides reuse
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.9, LED-2026-10-26-batch-100.20
- **Statement:** `find_identical(destination, name, staged)` (NEW, `workspace.py`) shall enumerate the reuse candidates from a listing of the destination — `<name>` and every `<stem>_<digits><suffix>`, compared case-insensitively on Windows — and return the first that is a regular file, not a link or reparse point, non-empty, of the staged size and byte-identical. `place_into_workarea(source, destination, …) -> PlacementResult(path, reused)` (NEW, `workspace.py`) shall hold every guard `copy_into_workarea` holds today — the source and destination reparse checks, the size cap, private staging — plus containment in this work area (`contained_in_workarea`, LLR-171.4), and shall reuse the identical file or claim the lowest free `_<N>`. `copy_into_workarea` (`workspace.py:402`) shall be `return place_into_workarea(...).path`, with no second claim loop, so its 15 call sites in 7 files (P-34) are unchanged; this widens B100-I6.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-01 — `pytest tests/test_b100_reuse.py -k tc_b100_01`
- **Numeric pass threshold:** the S7 sequence (case_01, case_02, case_02, case_01, case_02) → names `firmware.s19`, `firmware_1.s19`, `firmware_1.s19`, `firmware.s19`, `firmware_1.s19` with `reused` False, False, True, True, True; 2 files in the destination; `copy_into_workarea` returns a `Path` (1 type assertion); `place_into_workarea` called directly with a destination outside every work area, through a junction, and with a source over the cap → 3 refusals, 0 bytes written; an AST check → 1 claim loop in `workspace.py`.
- **Negative control:** executed on `1d677ba` (`ui_load_dialogs_probe` S7): `copy case_02 again -> firmware_2.s19` → RED. Mutation at Phase 3: restrict the comparison to the bare name → RED; move the size cap back into the wrapper only → the direct over-cap arm writes → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — empty: a 0-byte candidate (not reused); boundary: `_1` deleted beside an identical `_2` (reused), an upper-case `_2` name on Windows (reused); invalid: a link candidate (not reused), a junction destination, an over-cap source.

### LLR-163.2 — Size before bytes
- **Traceability:** HLR-163
- **Ledger:** none
- **Statement:** `copy_into_workarea` shall read a candidate's bytes only when its size equals the staged size.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-02 — `pytest tests/test_b100_reuse.py -k tc_b100_02`
- **Numeric pass threshold:** 5 candidates of which 1 has the staged size → ≤ 1 candidate read.
- **Negative control:** a mutation removing the size check → 5 reads → RED.
- **Boundary catalog:** ☒ boundary — a same-size candidate with one differing byte (read, not reused).

### LLR-163.3 — G-005: the re-pinned expectations of TC-018 and AT-031b
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.9
- **Statement:** `test_tc018_existing_name_is_dedup_suffixed` (`tests/test_unified_write.py:372`) shall assert two pairs: the same change document written twice under `cs.json` returns the same path and leaves 1 file; a different document written under `cs.json` lands at `cs_1.json` and both files survive. `test_at031b_two_saves_are_distinct_no_clobber` (`tests/test_tui_patch_editor_v2.py:1304`) shall assert: two `save_doc` of an unchanged document leave 1 file; a `save_doc` after an added entry leaves 2 files with distinct names. The node names stay, so the registry entries TC-018 and AT-031b keep resolving. R-PATCH-SAVE-FOLDER-001's "two distinct saves" reads as two saves of distinct content (QA-27).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber`
- **Numeric pass threshold:** 2 passed, each with 2 arms asserted.
- **Negative control:** executed on `1d677ba` (P-7): the old single-arm expectations → `FF`. Mutation at Phase 3: disable the reuse → the identical arm of both → RED.
- **Boundary catalog:** ☒ boundary — identical bytes (one file) and one differing byte (two files).

### LLR-163.4 — The one ripple re-pin
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.9
- **Statement:** `test_tc_b99_31_changed_bytes_take_the_next_free_name` (`tests/test_b99_export.py:375`) shall assert that a third export with the same changed bytes reuses `t_isle_1.s19` and reports it as `reused`, leaving 2 files. `test_tc_b99_31_bin_pair_placed_under_one_suffix`, `test_tc_b94_04_template_save_reload_and_dedup`, `test_at_b94_17_template_save_listing_import_and_dedup` and `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate` stay unchanged (P-22). The re-pin lands in Inc 1, with `segment_split_view.py` (LLR-163.6).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name tests/test_b99_export.py::test_tc_b99_31_bin_pair_placed_under_one_suffix tests/test_flow_a2b_b94.py::test_tc_b94_04_template_save_reload_and_dedup tests/test_tui_flow_builder_b94.py::test_at_b94_17_template_save_listing_import_and_dedup tests/test_b99_staging.py::test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`
- **Numeric pass threshold:** 5 passed, 0 failed; the re-pinned arm asserts 2 files in the export home and the action `reused`.
- **Negative control:** a mutation disabling the reuse → the re-pinned arm sees `t_isle_2.s19` → RED.
- **Boundary catalog:** ☒ boundary — the second export (differing bytes, `_1`) and the third (identical, reused).

### LLR-163.5 — No "added" status for a reused variant
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.9
- **Statement:** `_sync_loaded_file_to_project` (`app.py:8526`) shall place through `place_into_workarea` and, when `PlacementResult.reused` is true, name the existing variant and not emit its added-variant status (`app.py:8616`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-03 — `pytest tests/test_b100_reuse.py -k tc_b100_03`
- **Numeric pass threshold:** a repeated load → 0 added-variant lines and 1 line naming the existing variant; a first load → 1 added-variant line (`tests/test_tui_variants.py:274` stays green).
- **Negative control:** a mutation always emitting the added-variant status → RED.
- **Boundary catalog:** ☒ boundary — a first load (added) and a repeated load (existing).

### LLR-163.6 — The export reports reuse from the placement it performed
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.9, LED-2026-10-26-batch-100.20
- **Statement:** The Split/Join export (`segment_split_view.py:939-946`) shall place each single file through `place_into_workarea` and take its status word only from that call's `PlacementResult.reused`; `_export_reuse_target` (`segment_split_view.py:673`) shall no longer hold its own byte-identity rule, and no separate `find_identical` call shall decide the word. `place_group_into_workarea` keeps "requested names only".
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-57 — `pytest tests/test_b100_reuse.py -k tc_b100_57`
- **Numeric pass threshold:** identical re-export to an existing `_1` → action `reused`, 0 new files; changed bytes → `wrote`, 1 new file; a census over `s19_app/` → 1 byte-identity function and 0 status words computed outside a `PlacementResult`.
- **Negative control:** a mutation restoring the requested-name-only check in the export → the `_1` arm reports `wrote` → RED.
- **Boundary catalog:** ☒ boundary — reuse at the bare name and at `_1`.

### LLR-163.7 — `predict_placement` uses the placement code itself
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.15
- **Statement:** `predict_placement(digest_or_bytes, size, destination, name) -> PlacementResult` (NEW, `workspace.py`) shall share `find_identical` and the free-name walk with `place_into_workarea` and write nothing. The save plan (LLR-167.6) shall predict every landing name with it, and `_handle_save_dialog` shall check each landed `PlacementResult` against its planned row; a mismatch is an error naming both paths, never silent.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-68 — `pytest tests/test_b100_reuse.py -k tc_b100_68`
- **Numeric pass threshold:** a directory named `firmware_1.s19` in the target → predicted `firmware_2.s19`, placed `firmware_2.s19` (1 equality); identical bytes present → predicted `reused`, placed `reused`; a concurrent claim between prediction and placement (forced) → 1 mismatch error naming both paths; 0 bytes written by a prediction.
- **Negative control:** a mutation giving the prediction its own free-name walk that skips directories → the directory arm predicts `firmware_1.s19` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a directory and a link at a `_<N>` name; a forced concurrent claim.

### LLR-164.1 — Reserved homes and device names, compared case-folded
- **Traceability:** HLR-164
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.20
- **Statement:** `_handle_save_dialog` (`app.py:8087`) shall refuse, before creating any folder and with the `reserved name` or `device name` tokens, a sanitised name whose case-fold equals that of an entry of `RESERVED_WORKAREA_HOMES` (`workspace.py:40`), and a typed name or sanitised name for which `is_windows_device_name` (NEW, one shared predicate in `workspace.py`, also used by LLR-169.8 and LLR-172.2) is true: `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, the superscript-digit forms, `CONIN$`, `CONOUT$`, with or without an extension, compared case-folded. `list_projects` (`app.py:8519`) shall omit every folder whose case-folded name is a reserved home. The two existing device lists (`changes/apply.py:107`, `segment_split_view.py:524`) stay and are filed in the backlog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-04 — `pytest tests/test_b100_save_guards.py -k tc_b100_04`
- **Numeric pass threshold:** every tuple entry in 3 casings (the set derived from the imported tuple, ≥ 9 entries) and `nul`, `CON`, `com1`, `LPT¹`, `con.txt` (raw), `CONIN$` (raw) and `C O N` (sanitised `CON`) → refused with tokens, 0 folders; folders `Splits` and `Reports` → 0 listed.
- **Negative control:** executed on `1d677ba` (P-14): `Splits` saved and listed → RED; (S-04) `CON` saved → RED; a mutation checking only the sanitised name → `con.txt` saved as `contxt` → RED.
- **Boundary catalog:** ☒ invalid — every reserved and device name in mixed case, raw and sanitised.

### LLR-164.2 — Q-2: clash, merge and the open project
- **Traceability:** HLR-164
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.22, LED-2026-10-26-batch-100.23
- **Statement:** `_handle_save_dialog` shall decide by Q-2. A project is a direct child of this work area holding a `project.json` or a data file, not a reserved home and not a link. (a) A disguised clash — the sanitised name equals a project's folder name compared case-folded while the typed name differs from it — shall be refused before writing, with the `already a project` and `choose another name` tokens naming both names. (b) A name equal to a project that is not open shall merge: it keeps the target's other keys and variants, adds the new files as variants (LLR-005.1), rewrites `project.json` through the seam carrying every key it does not own (the LLR-168.3 rule), and sets `active_variant` per D2; sub-folders and the target's document are untouched; if the merge fails, the files it placed are removed and listed in the status. (c) A name equal to the open project, typed exactly or as its unsanitised form, shall save into the open project. A target folder that is a link or junction is refused before `resolve()` with the `link or junction` tokens. The completed save's status shall name the folder written.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-05 — `pytest tests/test_b100_save_guards.py -k tc_b100_05`
- **Numeric pass threshold:** `ab` existing and not open, `a b` typed → 1 refusal naming both, `ab/` with 0 changed digests; `AB` typed → 1 refusal (case-only); `ab` typed → merge, 1 variant added; the carried keys: `batch`, `assignments`, `declared_regions` from Inc 2, `gathered` from Inc 6, `active_document` from Inc 8a (0 changed at each); `a b` typed while `ab` is open → saved into `ab`; a forced `OSError` mid-merge → the target's file set and `project.json` unchanged; a junction `evil` typed → refused, 0 bytes written; `tests/test_tui_variants.py::test_save_second_s19_into_project_appends_variant` → passed.
- **Negative control:** executed on `1d677ba` (P-10): `'a b' -> project='ab'` saved silently → RED; a mutation passing the session's `batch` in the merge → the carried-key arm RED.
- **Boundary catalog:** ☒ boundary ☒ invalid ☒ error — boundary: the open project's name typed both ways, an exact-name merge; invalid: a case-only and a sanitised clash, a junction target; error: a failed merge.

### LLR-164.3 — Name cap, path limit and `OSError`
- **Traceability:** HLR-164
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.22
- **Statement:** `_handle_save_dialog` shall refuse, before creating any folder, a sanitised name longer than `PROJECT_NAME_MAX_CHARS = 64` (NEW, `workspace.py`) with the `name too long` tokens, and a name for which `len(str(self.workarea)) + 1 + len(name) + 53 > 259` (the longest fixed in-project file, `\reports\<ts>-NN-before-after-report.html`; the `_MAX_FULL_PATH` idiom, `segment_split_view.py:544`) with the `path too long` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-06 — `pytest tests/test_b100_save_guards.py -k tc_b100_06`
- **Numeric pass threshold:** 64 characters → saved; 65 and 300 → 2 refusals, 0 folders, app running; with a work area of length L = 150: a 55-character name (`150 + 1 + 55 + 53 = 259`) → saved, a 56-character name (`= 260`) → refused with `path too long`.
- **Negative control:** executed on `1d677ba` (P-13): `RAISED FileNotFoundError` → RED.
- **Boundary catalog:** ☒ boundary — 64 and 65; the path limit exactly met (259) and exceeded by 1 (260).

### LLR-164.4 — A refused or failed save leaves no folder it created
- **Traceability:** HLR-164
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.19
- **Statement:** Every statement of `_handle_save_dialog` and of the Save worker body (LLR-177.1) after the folder's creation — validation, the copies, the save-as walk, the emit and the manifest write — shall run under one `OSError` handler that reports the error with the `could not save` tokens and calls `_remove_created_project_dir` (`app.py:8076`) in the path where the failure happens, removing only a folder this call created; every `return` after the creation that does not complete the save shall also call it.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-07 — `pytest tests/test_b100_save_guards.py -k tc_b100_07` (an AST census over the handler's and the worker body's returns and exception exits, plus one behavioural arm per stage)
- **Numeric pass threshold:** the census derives the post-creation returns and exception exits from the AST of both functions (≥ 3 returns at `1d677ba`, `app.py:8148-8170`) → 0 without the removal; a forced `OSError` at each of 5 stages, on the worker → 0 folders left, 0 raises, app running.
- **Negative control:** a mutation deleting one removal call → the census names that exit → RED; S-05's executed probe (a 262-character path) → `FileNotFoundError` escapes and the folder stays → RED.
- **Boundary catalog:** ☒ error — every stage after creation, on the main thread and on the worker; a pre-existing folder is never removed.

### LLR-165.1 — One reset seam, before the first install
- **Traceability:** HLR-165
- **Ledger:** LED-2026-10-26-batch-100.8
- **Statement:** `S19TuiApp._reset_project_session()` (NEW, `app.py`) shall reset rows S1–S12 of ARQ §2.2 and these S13 names: the seven `_mac_view_cache_*`, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address` and `_a2l_row_key_to_tag`; then it shall repaint the Patch panel through `refresh_entries`. `_handle_load_project` (`app.py:8444`) shall call it once per load, after `validate_project_files` succeeds (`:8453-8461`) and before `load_selected_file` (`:8510`). No other caller shall call it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-08 — `pytest tests/test_b100_session_reset.py -k tc_b100_08`
- **Numeric pass threshold:** per project load → 1 call, ordered before the first install; a Load file → 0 calls; call sites in `s19_app/` → 1.
- **Negative control:** a mutation moving the call after `load_selected_file` → the MAC merge sees the old file → RED.
- **Boundary catalog:** ☒ boundary — loading the open project again.

### LLR-165.2 — The session snapshot, derived from the live app (C-31)
- **Traceability:** HLR-165
- **Ledger:** LED-2026-10-26-batch-100.8, LED-2026-10-26-batch-100.23
- **Statement:** `S19TuiApp._session_snapshot() -> dict` (NEW, `app.py`) shall return, for every attribute name that `S19TuiApp`'s own source assigns (`self.<name> =`, derived by a census at test time), minus a declared exclusion list of Textual internals, each with its reason, a normalised value: paths relative to the base, the `current_*` objects as `(type, relative path, image digest)`, the change service as its public counts, stat-keyed caches (such as `_mac_view_cache_key`) without their mtime and with relative paths, other objects as counts or keys. The leak check shall compare the snapshot of a cold load of P2 with that of a load of P2 over P1, allow-listing K1 and K2.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-09 — `pytest tests/test_b100_session_reset.py -k tc_b100_09`
- **Numeric pass threshold:** cold vs cold → 0 differing names; P2-over-P1 vs cold P2 → 0 differing names outside the allow-list; the derived domain holds ≥ 60 names (source census 67), and every name the census finds is in the domain or in the exclusion list with a reason (0 unclassified).
- **Negative control:** a code mutation dropping one reset line (`current_a2l_path`) → 1 differing name → RED; a set mutation dropping one census name without an exclusion → the classification arm RED; QA's probe without the stat-key normaliser → cold vs cold differs in `_mac_view_cache_key` → RED for an un-normalised snapshot.
- **Boundary catalog:** ☒ boundary — the K1 counters differ by design and are allow-listed; a stat-keyed cache.

### LLR-165.3 — The change service is rebound
- **Traceability:** HLR-165
- **Ledger:** none
- **Statement:** The reset shall assign a new `ChangeService()` and re-push `set_image_generation(self._image_generation)` (`change_service.py:2494`); it shall not add a reset method to the service.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-10 — `pytest tests/test_b100_session_reset.py -k tc_b100_10`
- **Numeric pass threshold:** after a load over P1: a different service object, 0 document entries, 0 undo steps, an image generation equal to the app's.
- **Negative control:** a mutation keeping the old object → 1 leaked entry → RED.
- **Boundary catalog:** ☒ boundary — a worker that captured the old service finishes against it (no exception).

### LLR-165.4 — Unload clears the parsed A2L
- **Traceability:** HLR-165
- **Ledger:** none
- **Statement:** `_apply_unload` (`app.py:10173`) shall set `current_a2l_data` to `None` for the kinds `all` and `a2l`, beside `current_a2l_path` (`:10250-10251`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-11 — `pytest tests/test_b100_session_reset.py -k tc_b100_11`
- **Numeric pass threshold:** load S19 + A2L, unload `all`, load an S19 with no A2L → 0 A2L tags.
- **Negative control:** today's code (P-25, no clearing writer) → the tags survive → RED (repro planned at Phase 3).
- **Boundary catalog:** ☒ boundary — unloading `a2l` alone.

### LLR-166.1 — The load tails and the modal closes put the focus on the window's target
- **Traceability:** HLR-166
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.23
- **Statement:** Each window shall declare its focus target, a non-text widget (NEW, a per-window table in `app.py`, derived at Phase 3 from the window registry and checked by TC-B100-12 against every window). The load tail `_step_finalize` (`app.py:11191`), the dismiss of the Load dialog, of the load question and of the Load-result panel, and a cancelled load shall move the focus to the displayed window's target when the focused widget has region area 0, belongs to a window that is not displayed, or is an `Input` / `TextArea`. While the Load-result panel is open, the focus stays in it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-12 — `pytest tests/test_b100_focus.py -k tc_b100_12`
- **Numeric pass threshold:** every window in the registry → 1 declared target, 0 of type `Input` / `TextArea`; written at Inc 4: 3 load paths (Load file, Load project, Workarea Files pick) → the focus on the target, then `p` → a dialog opens (3 of 3); extended at Inc 6 (panel `enter`, panel `esc`), Inc 9b (dialog `esc`, cancelled load) and Inc 10 (question `n`) → the focus on the target each time.
- **Negative control:** executed on `1d677ba` (P-16): `focused region area: 0` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — a cancelled load; the Split/Join window displayed (its table is the target).

### LLR-166.2 — The A2L load tail re-homes the focus
- **Traceability:** HLR-166
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** The A2L load tail of `load_a2l_from_path` (`app.py:8789`) shall apply the rule of LLR-166.1.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-13 — `pytest tests/test_b100_focus.py -k tc_b100_13`
- **Numeric pass threshold:** 1 A2L load → the focus on the window's target, not an `Input`; then `p` → the Load dialog opens.
- **Negative control:** a mutation removing the re-home from the A2L tail → area 0 → RED.
- **Boundary catalog:** ☒ boundary — an A2L load with no image loaded.

### LLR-167.1 — The emit decision is made on data
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.14, LED-2026-10-26-batch-100.32
- **Statement:** Save project shall decide emit or copy by re-deriving the change document's entries onto a copy of the source image (`rederive_for_save`, LLR-167.7) and comparing the result with the source file's data: emit iff they differ. A check-kind document never counts and never triggers an emit. `ChangeService.image_differs_from_source(mem_map)` (B100-I5, `change_service.py:895`, `:887`) is kept only as a fast path into this comparison: when it is true, the re-derive and comparison start at once; it never decides copy by itself, and a false result still runs the comparison whenever the document holds a change entry. The load question and the Save summary's pending line never use this decision.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-14 — `pytest tests/test_b100_save_image.py -k tc_b100_14`
- **Numeric pass threshold:** no entry → copy; a change entry writing new bytes → emit; a change entry writing the bytes already there → copy; a check document with 1 entry → copy; applied then undone → copy; only unapplied change entries that write new bytes → emit (the pre-check false, the comparison run); save-back then Save project → emit (the pre-check true, the comparison run); 0 writes to `mem_map` while deciding.
- **Negative control:** the round-2 rule (emit when the document holds any entry) → the check-document arm emits and is refused (P-37), and the same-byte arm emits a byte-different file (P-38) → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — an empty document; a same-byte entry; a check document.

### LLR-167.2 — Save project emits through the split or copies the source
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.13, LED-2026-10-26-batch-100.14
- **Statement:** `_handle_save_dialog` shall execute the save plan (LLR-167.6). When the emit decision (LLR-167.1) is emit, it shall apply the re-derived image to the session map in place on the main thread and call `emit_and_verify` (LLR-167.7) with the plan's landing name, the source kind, `bytes_per_line=32`, the source's S0, `source_image_path=current_file.path` and the MAC records and A2L tags, then record `derived_from` (LLR-168.4); the landed image becomes `active_variant`. Otherwise it shall call `copy_into_workarea(current_file.path, project_dir)` (`app.py:8173`) and add no variant. A check document is placed under `checks/` through the gather and never blocks the save. MAC and A2L stay `copy_into_workarea` copies.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-15 — `pytest tests/test_b100_save_image.py -k tc_b100_15`
- **Numeric pass threshold:** a patched S19 → 0 differing addresses between the file (independent reader) and source + change document, every data record ≤ 32 bytes, the S0 equal to the source's; check document only → byte copy (0 differing bytes) + the document under `checks/`, 0 refusals; unchanged change document → byte copy, 0 new variants; real change → emit; an entry removed after the apply → absent; a patched HEX → 0 differing addresses; MAC and A2L → 0 differing bytes; save-back then Save project → the patch in the project image; a target holding a different `firmware.s19` → `firmware_1.s19`, `active_variant` = `firmware_1`; `tests/test_project_gather.py::test_tc700_active_editor_document_is_gathered_by_kind` → passed.
- **Negative control:** executed on `1d677ba` (P-1): `== in-memory patched image? False` → RED; a mutation deciding emit-or-copy on `differs_from_last_saved` → the save-back-then-Save arm copies the unpatched source → RED (A-08).
- **Boundary catalog:** ☒ boundary ☒ invalid — S19 and HEX sources; an S19 with no S0; a same-byte entry; a check document; a clashing landing name.

### LLR-167.3 — The status names the entries the image carries
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.4
- **Statement:** The status of an emitting Save project shall name the number of document entries the image carries and how many of them this save applied, from `save_back_status_suffix` (`change_service.py:131`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-16 — `pytest tests/test_b100_save_image.py -k tc_b100_16`
- **Numeric pass threshold:** 1 applied entry → a status carrying `1` and 0 applied by the save; 1 applied + 1 added after the apply → `2` and `1 applied by this save`.
- **Negative control:** a mutation dropping the suffix → 0 counts → RED.
- **Boundary catalog:** ☒ boundary — an entry added after the last apply.

### LLR-167.4 — A blocked re-derive refuses the whole save
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.4
- **Statement:** When the save plan finds a blocked entry, or `save_patched` returns `ok=False` (`change_service.py:2146-2158`), `_handle_save_dialog` shall paint the `blocked entries` tokens naming them, write no file and no manifest, and remove the folder it created.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-17 — `pytest tests/test_b100_save_image.py -k tc_b100_17`
- **Numeric pass threshold:** a document with 1 blocked entry → 1 status naming it, 0 files, 0 folders left.
- **Negative control:** a mutation ignoring `ok=False` → a manifest is written → RED.
- **Boundary catalog:** ☒ error — the blocked document.

### LLR-167.5 — The unsaved predicate and the saved-state record
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.3
- **Statement:** `ChangeService.mark_saved(mem_map)` and `ChangeService.differs_from_last_saved(mem_map) -> bool` (NEW, `change_service.py`) shall record, after a load, a successful save-back and a successful Save project, the bytes of the journaled addresses as last loaded or written, and report whether any journaled or recorded address now holds a different byte. The cost is O(journaled addresses). This predicate decides the load question (LLR-174.1) and the Save summary's pending line (LLR-175.4), and nothing else.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-58 — `pytest tests/test_b100_save_image.py -k tc_b100_58`
- **Numeric pass threshold:** loaded → False; applied → True; applied → Save project → False; applied → save-back → False; saved → patched again → True; saved → undone → True; 0 iterations of `mem_map`.
- **Negative control:** a mutation calling `mark_saved` on the save-back path only → the Save project arm stays True → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — nothing journaled; saved then undone.

### LLR-167.6 — One save plan, painted and executed (R-PC)
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.26
- **Statement:** `plan_project_save(...) -> SavePlan` (NEW, a pure function in `services/project_gather_service.py`) shall compute, without writing, the target folder and its kind (new, open project, merge), one row per top-level file, one row per sub-folder with its file count, and one row for `project.json`, each with its source, landing name (from `predict_placement`, LLR-163.7) and action word (`new`, `replace`, `keep`, `merge`, `rewrite`), plus the image description (source + N change entries, K applied by this save, or an unchanged copy), the document, skipped links and the manifest keys, or the refusal with its tokens. The emitted image's bytes and digest, and the copied files' digests, are computed once per dialog open on a worker (LLR-175.4) and passed in, so `project_gather_service` gains no import of `change_service` or `changes`. `_handle_save_dialog` shall execute exactly that plan.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** written at Inc 5: fresh, open-project, pending patch and refused scenarios → the plan's rows equal the written tree at the plan's granularity, by full path and action (0 differences), the refused scenario → 0 files; extended at Inc 8a (the document row) and Inc 8b (save-as with sub-folders); computing a plan writes 0 bytes, leaves `mem_map` unchanged and computes 0 digests; 0 new imports from `project_gather_service`.
- **Negative control:** a mutation where the handler places a file the plan did not name → 1 tree row without a plan row → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ error — a fresh empty folder; a clashing landing name; a refused name.

### LLR-167.7 — `save_patched` split into re-derive and emit-and-verify
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.14
- **Statement:** `ChangeService` shall expose `rederive_for_save(copy) -> (map, summary)` (NEW), which re-derives the source plus the current change document onto the given copy without touching the session map, and `emit_and_verify(map, ranges, dest_dir, filename, …) -> ChangeActionResult` (NEW), which emits and verifies. `save_patched` (`change_service.py:2009`) shall be composed of the two, so the save-back's rule (B99-I7) is unchanged. Inc 5 lands the split.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-69 — `pytest tests/test_b100_save_image.py -k tc_b100_69`
- **Numeric pass threshold:** `rederive_for_save` → 0 writes to the session map; `save_patched` before and after the split → byte-identical files for 4 documents (applied, undone, added after apply, blocked); `tests/test_b99_editor_image.py` → 0 new failures.
- **Negative control:** a mutation where `rederive_for_save` writes the session map → the 0-writes arm RED.
- **Boundary catalog:** ☒ boundary ☒ error — the 4 documents, the blocked one included.

### LLR-167.8 — Save project clears the Patch Editor's dirty flag
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.17
- **Statement:** After a Save project that wrote the change or check document into the project, `_handle_save_dialog` shall call the Patch Editor panel's `mark_saved` (`screens_directionb.py:5805`) and `ChangeService.mark_saved`, so neither the document flag nor the image predicate reports unsaved work that is on disk.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-70 — `pytest tests/test_b100_save_image.py -k tc_b100_70`
- **Numeric pass threshold:** an entry added → Save project → a project load → 0 questions; a refused Save project → the flag still set (1 assertion).
- **Negative control:** a mutation skipping the panel's `mark_saved` → the load asks → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a check document; a refused save.

### LLR-168.1 — The reader parses `gathered`
- **Traceability:** HLR-168
- **Ledger:** none
- **Statement:** `read_project_manifest` (`variant_execution_service.py:376`) shall expose `gathered: dict[str, list[Path]]` on `ProjectManifest` (`:160`), each entry through `_resolve_manifest_entry` (`:205`); a malformed value shall give one `MANIFEST-BAD-STRUCTURE` (`:102`) and be skipped; an absent key shall give an empty dict and no issue.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-18 — `pytest tests/test_b100_active_variant.py -k tc_b100_18`
- **Numeric pass threshold:** a valid `gathered` → an equal dict; a list instead of a dict → 1 issue; `../x.json` → 1 issue, 0 entries; absent → `{}` and 0 issues.
- **Negative control:** a mutation ignoring the key → the rewrite drops `gathered` → RED in TC-B100-20.
- **Boundary catalog:** ☒ empty ☒ invalid — an absent key; hostile entries.

### LLR-168.2 — The save-back becomes the active variant
- **Traceability:** HLR-168
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `on_patch_editor_panel_save_back_decision` (`app.py:3364`), after a save-back into the open project, shall set `_variant_set.active_id` and `current_file.variant_id` to the written file's variant and rewrite `project.json` through the seam; it shall leave `current_file.path` unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-19 — `pytest tests/test_b100_active_variant.py -k tc_b100_19`
- **Numeric pass threshold:** `p02` A → `active_variant` = `firmware_1`; `p02` B → `firmware-patched`; `current_file.path` = `temp/firmware.s19` in both (2 arms).
- **Negative control:** executed on `1d677ba` (P-3): `active_variant 'firmware'` → RED.
- **Boundary catalog:** ☒ boundary — a save-back with no project open (no manifest write).

### LLR-168.3 — Every in-project writer rewrites the manifest, carrying every key it does not own
- **Traceability:** HLR-168
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16
- **Statement:** The Load-file variant append and the MAC and A2L syncs (`app.py:8591`, `:8622`, `:8630`, `:8652`) shall place their files through `place_into_workarea` and each end in `_write_and_verify_manifest`, passing every key of the existing manifest they do not change — `batch`, `assignments`, `declared_regions`, `gathered`, `active_document`, `derived_from` — converted from the reader's absolute paths back to project-relative POSIX strings. The variant append shall make the appended file active and paint a status line naming the project and the file it now opens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-20 — `pytest tests/test_b100_active_variant.py -k tc_b100_20`
- **Numeric pass threshold:** 4 writers → 4 rewrites; each → 0 changed keys it does not own and 0 absolute paths in the written file; a recorded document and a `derived_from` → still recorded after the append; the append → `active_variant` = the appended id and 1 status line naming project and file.
- **Negative control:** a mutation removing the seam call from the variant append → `active_variant` stale → RED; a mutation passing the reader's absolute `batch` → `serialize_manifest` refuses and no manifest is written (A-03 probe) → RED.
- **Boundary catalog:** ☒ boundary — a manifest with every key filled.

### LLR-168.4 — `derived_from` records what a patched variant derives from
- **Traceability:** HLR-168
- **Ledger:** LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.33
- **Statement:** `serialize_manifest` shall emit, as part of the B100-I1 envelope, an additive per-variant `derived_from` map (B100-I16), only when non-empty: for each patched variant file (project-relative, through `_reject_unsafe_entry`), the base's file name, the base's SHA-256 and the number of bytes that differ from it, all computed at the write, when both images are in hand. `read_project_manifest` shall parse it in the manifest-keys mode, an unsafe or malformed value giving one issue and no entry, capped at 1 000 entries. The save-back into a project and Save project's emit shall set it from Inc 7 on; an emit before Inc 7 records nothing. Every rewrite carries it (LLR-168.3). The base need not be in the project: when no project file has the recorded name and digest, the record still names the base and its byte count.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-71 — `pytest tests/test_b100_active_variant.py -k tc_b100_71`
- **Numeric pass threshold:** a save-back to `firmware_1.s19` and one to `firmware-patched.s19` → `derived_from` names `firmware.s19` with its SHA-256 and `4` differing bytes in both (2 of 2); a Save project emit of a session loaded from outside the project → the base's name and digest recorded, the base absent from the project (1 arm); a byte copy → not set; `../x.s19` as a value → 1 issue, 0 entries; a manifest with no key → output byte-identical to `1d677ba`'s.
- **Negative control:** a mutation dropping the key from the carry → after a variant append the panel loses the "patched" line → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — no key; a base not in the project; hostile and malformed values.

### LLR-169.1 — The `files` envelope
- **Traceability:** HLR-169
- **Ledger:** none
- **Statement:** `serialize_manifest` (`manifest_writer.py:225`) shall emit `files` as a map from a project-relative POSIX path to `{"size": int, "sha256": 64 lowercase hex characters}`, only when non-empty, every key through `_reject_unsafe_entry` (`:179`); `file_record(path)` (NEW) shall stream the SHA-256. The output with no `files` shall be byte-identical to today's.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-21 — `pytest tests/test_b100_project_check.py -k tc_b100_21`, plus `pytest tests/test_manifest_writer.py`
- **Numeric pass threshold:** 3 files → 3 records equal to `hashlib.sha256` of the bytes; no files → 0 byte differences against `1d677ba`'s output; the pins `test_manifest_writer.py:99`, `:216`, `:481` → 3 passed.
- **Negative control:** a mutation emitting an empty `files` key → the byte-identity arm → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no files; a 0-byte file.

### LLR-169.2 — The seam computes `files` from disk, over the O-2 scope
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6
- **Statement:** `_write_and_verify_manifest` (`app.py:8272`) shall compute `files` itself, after every copy has landed, over the top-level regular files whose suffix is in `PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS` (`workspace.py:75-77`, `.srec` and `.ihex` included) and the active document, and over no file under a sub-folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-22 — `pytest tests/test_b100_project_check.py -k tc_b100_22`
- **Numeric pass threshold:** a project with `firmware.s19`, `firmware.mac`, `firmware.a2l`, `prg.srec`, `flows/f1.json` and `reports/r.md` → `files` keys = the 4 top-level files (the set derived from the listing by the suffix constants). The active-document arm runs at Inc 8a (TC-B100-28).
- **Negative control:** a mutation walking sub-folders → `flows/f1.json` recorded → RED; a mutation keyed on `.s19` only → `prg.srec` missing → RED.
- **Boundary catalog:** ☒ boundary — `.srec` and `.ihex` variants.

### LLR-169.3 — Verify covers the new keys
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.33
- **Statement:** `verify_written_manifest` (`manifest_writer.py:632`) shall include `files`, `active_document` and `derived_from` — the keys the B100-I1 envelope adds — in its drift domain (today `:717-723`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-23 — `pytest tests/test_b100_project_check.py -k tc_b100_23`
- **Numeric pass threshold:** one digest changed between write and verify → 1 mismatch reported; one `derived_from` byte count changed → 1 mismatch; unchanged → 0.
- **Negative control:** a mutation leaving `files` out of the domain → 0 mismatches → RED.
- **Boundary catalog:** ☒ boundary — a changed `active_document` only; a changed `derived_from` only.

### LLR-169.4 — The reader treats `project.json` as untrusted (C6)
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.29
- **Statement:** `read_project_manifest` shall read at most 1 MiB of `project.json` (an excess gives one `MANIFEST-SIZE-CAP`), parse at most 1 000 entries in each of `batch`, `declared_regions`, `gathered`, `files` and `derived_from`, and at most 1 000 entries in total across all `assignments` lists with at most 1 000 `assignments` keys (an excess gives one `MANIFEST-BAD-STRUCTURE`), and parse `files` into `dict[Path, FileRecord]`. A `files` key passes the manifest-key predicate (LLR-169.8) or gives one `MANIFEST-PATH-ESCAPE`; a contained key outside the scope (not a top-level name with a project data or A2L suffix, and not `active_document`) gives one `MANIFEST-BAD-STRUCTURE`. A record whose `size` is not an `int` ≥ 0 (a `bool` included) or whose `sha256` is not 64 hex characters gives one `MANIFEST-BAD-STRUCTURE`. Every refused record is skipped; an absent key gives an empty dict and no issue. These codes go to the log; the panel words them in user terms (LLR-169.9).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-24 — `pytest tests/test_b100_project_check.py -k tc_b100_24`
- **Numeric pass threshold:** per arm, the code asserted: `../x.s19`, an absolute path, `C:x`, a UNC path, `x.s19:ads`, `CON`, `x.s19.`, `patches/NUL.json` → 8 × `MANIFEST-PATH-ESCAPE`; `sub/x.s19` → 1 × `MANIFEST-BAD-STRUCTURE`; `size: true`, `size: -1`, `size: "1"`, `sha256: "XYZ"`, 63 and 65 hex → 6 × `MANIFEST-BAD-STRUCTURE`; 1 001 entries in `batch` (and separately in `files`) → 1 issue each, read under 1 s; 75 `assignments` keys × 1 000 entries (security probe: 14.80 s uncapped) → 1 issue, read under 1 s; a 1 MiB + 1 byte file → 1 `MANIFEST-SIZE-CAP`; a valid record → 1 record.
- **Negative control:** a mutation accepting a `bool` size → 0 issues on that arm → RED; P-40: an uncapped `batch` of 75 677 entries takes 14.92 s → RED for the timing arm.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — an absent key; exactly 1 000 entries and 1 MiB; the hostile set.

### LLR-169.5 — `check_project_files`: manifest and disk problems
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.7
- **Statement:** `check_project_files(project_dir, manifest) -> list[ProjectFileProblem]` (NEW, `manifest_writer.py`) shall return manifest and disk problems only: `manifest damaged` (`MANIFEST-JSON-PARSE`, `-SIZE-CAP`, top-level `-BAD-STRUCTURE`, an over-cap record count), `no project.json`, `missing` (a recorded file absent), `changed on disk` (size or digest differs; only `S_ISREG` files are hashed, any other type is `not readable`), `not recorded` (a top-level data or A2L file absent from a present `files`), and `no digests saved` (no `files` key). It shall never raise, and shall not parse images.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-25 — `pytest tests/test_b100_project_check.py -k tc_b100_25`
- **Numeric pass threshold:** the `p04` cases 2, 5, 7, 9, a legacy project and a hand-copied `firmware_9.s19` → 6 problems of the matching kinds; a clean project → 0; a file unreadable by permission → 1 problem, 0 raises; `P/NUL` recorded → `not readable`, not `ok`.
- **Negative control:** executed on `1d677ba` (P-4): `notices=[]` for cases 2 and 7 → RED; a mutation dropping the `not recorded` kind → the hand-copied arm → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ error — legacy; no `project.json`; an equal size with a different digest; an unreadable file.

### LLR-169.6 — Load opens the valid files and writes one summary line
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7
- **Statement:** `_handle_load_project` shall run `check_project_files`, open the active variant when it is valid, otherwise the next valid variant in `build_variant_set` order, then the MAC, and write one status log line: the opened variant, `k of n`, the problem count and a pointer to the panel, in that order; it shall no longer write "activating the first variant" when no variant can be opened.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-26 — `pytest tests/test_b100_project_check.py -k tc_b100_26`
- **Numeric pass threshold:** the active variant deleted with 2 variants → the other opens, 1 problem; every image deleted → the MAC opens, 1 problem per missing image; per project load → exactly 1 new status log line, its count token inside 118 columns.
- **Negative control:** executed on `1d677ba` (P-5): `activating the first variant` then `-> firmware.mac` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the last valid variant; no valid variant.

### LLR-169.7 — The manifest is staged privately
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6
- **Statement:** `write_project_manifest` (`manifest_writer.py:414`) shall stage `project.json` in a private directory from `_private_stage_dir` (`workspace.py:298`) and place it with `os.replace`, never through the fixed `temp/project.json` (`:509`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-27 — `pytest tests/test_b100_project_check.py -k tc_b100_27`
- **Numeric pass threshold:** 8 concurrent manifest writes for 8 projects × 10 trials → 80 of 80 return a path, 80 manifests present, each holding its own `active_variant`, 0 issues; the source predicate "no `WORKAREA_TEMP / PROJECT_MANIFEST_NAME` staging in `manifest_writer.py`" → 0 hits.
- **Negative control:** executed on `1d677ba` by the QA race probe: `ok=3 cross-content=12 failed-writes=60` → RED; the source predicate → 1 hit at `:509` → RED.
- **Boundary catalog:** ☒ boundary — 1 and 8 writers.

### LLR-169.8 — A manifest-key mode refuses drive-relative, stream and device names (S-09)
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20
- **Statement:** `_resolve_manifest_entry` (`variant_execution_service.py:205`) shall gain a manifest-key mode, used by `read_project_manifest` and `_reject_unsafe_entry` only, that refuses with `MANIFEST-PATH-ESCAPE` an entry with a drive or a root (`PureWindowsPath(entry).drive or .root`), a `:` anywhere, or a path component that ends in a dot or a space or for which `is_windows_device_name` is true, with or without an extension. Both flow-reference callers — `flow_persistence_service.py` (`:84`, `:582`, `:619`, `:780`, `:1433`) and `flow_execution_service.py` (`:117`, `:315`, `:345`, `:427`, `:448`, `:734`, `:798`, `:942`, `:1695`) — keep the default mode, so `tests/test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally` stays green.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-60 — `pytest tests/test_b100_project_check.py -k tc_b100_60` and `pytest tests/test_b97_flow_builder.py tests/test_flow_persistence.py tests/test_flow_execution_service.py`
- **Numeric pass threshold:** in manifest-key mode: `C:x.s19`, `c:sub/x.s19`, `x.s19:ads`, `x.s19.`, `x.s19 `, `CON`, `patches/NUL.json`, `nul.s19`, `sub./x.s19`, `patches/x.json `, `../x.s19`, `C:/x.s19`, `\\host\share\x.s19`, `\\?\C:\x.s19` → 14 × `MANIFEST-PATH-ESCAPE`; `x.s19` and `patches/a.json` → accepted; the flow tests → 0 new failures.
- **Negative control:** executed (S-09): `'C:x.s19' -> …\workarea\P\x.s19 0` at `1d677ba` → RED; P-41: the same tightening applied to every caller → `test_tc_b97_20_hostile_refs_render_literally` RED, so the mode is required.
- **Boundary catalog:** ☒ boundary ☒ invalid — a nested relative path (accepted); the hostile set, per path component.

### LLR-169.9 — The load result adds `not readable`, one problem per file wins, worded for the user
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.22
- **Statement:** `_handle_load_project` shall add `not readable` for an image whose install reports load errors or an empty `mem_map`, merge it with `check_project_files`' list, and keep for each file only its highest problem by the precedence `manifest damaged` / `no project.json` > `missing` > `not readable` > `changed on disk` > `not recorded` > `no digests saved`; at most one manifest-level problem is kept. Each problem is painted with its reason in user terms ("not an S19 or HEX file", "0 data bytes", "a file path points outside the project") and its next-step token (§3 table); internal issue codes and exception class names go to the log only.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-61 — `pytest tests/test_b100_project_check.py -k tc_b100_61`
- **Numeric pass threshold:** `p04` case 6 → 1 problem, `not readable`; case 7 → 1, `manifest damaged`; a file both changed and unrecorded → 1, `changed on disk`; 7 kinds → 7 next-step tokens; 0 exception class names and 0 `MANIFEST-` codes in painted problem text.
- **Negative control:** a mutation keeping every kind per file → case 6 gives 2 problems → RED; a mutation painting the issue code → 1 `MANIFEST-` code painted → RED.
- **Boundary catalog:** ☒ boundary — a file matching three kinds.

### LLR-170.1 — The `active_document` key
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** `serialize_manifest` shall emit `active_document` as a project-relative POSIX path under `patches/` or `checks/`, through `_reject_unsafe_entry`, only when set; `read_project_manifest` shall parse it through `_resolve_manifest_entry` and accept it only with a `patches/` or `checks/` prefix and a `.json` suffix, giving one issue and `None` otherwise.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-28 — `pytest tests/test_b100_document.py -k tc_b100_28`
- **Numeric pass threshold:** `patches/boost.json` → round-trip equal; `../x.json`, an absolute path, a number, `firmware.s19`, `project.json` → 5 issues, 5 `None`; absent → `None`, 0 issues; with an active document, the seam's `files` holds 4 keys (A-15's arm).
- **Negative control:** a mutation skipping the prefix rule → `firmware.s19` accepted → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — absent; hostile values.

### LLR-170.2 — The app writes a pasted document; the gather places
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.10
- **Statement:** `_handle_save_dialog` shall write a document with no `source_path` through `write_change_document` (`changes/io.py:146`) into `<project>/patches/` as `changes.json`, which `copy_into_workarea` places by the M-1 rule (`changes_<N>.json` beside a different `changes.json`), and pass its path to `gather_project_artifacts` (`project_gather_service.py:400`), which only places files and whose `GatherOutcome` (`:369`) names the landed project-relative path.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-29 — `pytest tests/test_b100_document.py -k tc_b100_29`
- **Numeric pass threshold:** a pasted document with 1 entry → `P/patches/changes.json` holding 1 entry, named in the outcome; a different `changes.json` there → `changes_1.json` recorded; a file-backed document → 1 file, byte-equal to the source; 0 new imports from `project_gather_service` to `changes`.
- **Negative control:** executed on `1d677ba` (P-8): nothing under `patches/` for a pasted document → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 entries (not placed); an identical `changes.json` (reused); a different one (`_1`).

### LLR-170.3 — Load reopens the document after the A2L
- **Traceability:** HLR-170
- **Ledger:** none
- **Statement:** `_handle_load_project` shall load `active_document` into the change service after the project's A2L is attached, and shall list a missing or unreadable document as a problem and continue.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-30 — `pytest tests/test_b100_document.py -k tc_b100_30`
- **Numeric pass threshold:** `p06` A → the document `patches/boost.json`, 1 entry; a symbol entry → resolved against the project's A2L (0 unresolved); a missing document → 1 problem, the project opens.
- **Negative control:** executed on `1d677ba` (P-8): `editor doc = None` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a symbol entry; a missing document.

### LLR-171.1 — Save as copies every sub-folder, never through a link
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20
- **Statement:** When `_handle_save_dialog` saves an open project to a new folder, one walk of `current_project_dir` shall prune every directory entry for which `_is_reparse_point` (`workspace.py:172`) is true before descending, at every depth including the top-level sub-folder, and skip file links; that walk's file list gives both the total and the copy. The save shall be refused, before the folder is created and with the `not enough free space` tokens, when the total exceeds `shutil.disk_usage` free space of the work area's volume; otherwise each file is copied through `place_into_workarea` into the same relative path, and each skipped link is listed in the summary and the status.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P with `flows/`, `flowsets/`, `patches/`, `checks/`, `reports/`, `templates/`, `splits/` (one file each; the expected set derived from P's listing) → 0 missing and 0 differing files in Q; P → 0 changed digests; a top-level directory junction, a nested junction and a file symlink → 0 files copied through them, 3 skips listed, 0 bytes added to the total; a total over the free space (simulated) → refused with tokens, 0 folders.
- **Negative control:** executed on `1d677ba` (P-9): Q lacks the sub-folders → RED; S-03's executed probe: `os.walk(P)` lists `flows\secret.txt` through a junction → RED; security R2-06's probe: a plain walk descends a junction → the total arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — no sub-folder; a nested sub-folder; links and junctions; a copy over the free space.

### LLR-171.2 — An A2L-only project opens
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.24
- **Statement:** `_handle_load_project` shall, when the project has no data file and one A2L, reset the session, set the project and `_variant_set = build_variant_set(name, [])`, attach the A2L through the A2L load path and report it, instead of `No supported files in project`; a project folder holding neither a data file nor an A2L shall be answered with the `no data or A2L file` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `p04` 10 → 3 A2L tags, the project set, no `current_file`; then a Load file → `project.json` rewritten (1 arm, A-14); a folder whose `project.json` records no missing file and that holds no data and no A2L file → 1 status with the `no data or A2L file` / `load a file and Save project` tokens (UX-22); a folder with neither and no `project.json` → the `no project.json` tokens.
- **Negative control:** executed on `1d677ba` (P-12): `No supported files in project: P` → RED; a mutation leaving `_variant_set` as `None` → the rewrite arm writes nothing → RED.
- **Boundary catalog:** ☒ empty — a folder with no data file and no A2L, with and without a `project.json`.

### LLR-171.3 — Only this work area is a parent
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_save_dialog` shall refuse, before creating any folder, a `SaveProjectPayload.parent_folder` (`screens.py:144-176`) that does not resolve to `self.workarea`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-33 — `pytest tests/test_b100_project_homes.py -k tc_b100_33`
- **Numeric pass threshold:** parent = another `.s19tool/workarea` → refused, 0 folders; a parent outside any work area → refused, 0 folders; the work area under a different spelling (a trailing separator, mixed case) → saved and listed (1 listing).
- **Negative control:** executed on `1d677ba` (P-11): the other work area accepted, not listed → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — equivalent spellings; foreign parents.

### LLR-171.4 — Containment means this work area, checked inside the placement (S-02)
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.28
- **Statement:** `contained_in_workarea(path, workarea) -> bool` (NEW, `workspace.py`, B100-I14, frozen before Inc 1) shall be true iff the path, after resolving every link and junction, is inside `workarea.resolve()`. `place_into_workarea` (LLR-163.1) shall require it for every destination, so every placing writer — Save project's image, MAC, A2L and sub-folder copies, its emit (`save_patched_image` places through `copy_into_workarea`, `changes/apply.py:781`), the save-back, the variant append, the MAC and A2L syncs, and document placement — is covered by construction. The manifest seam replaces `project.json` rather than placing it, so `write_project_manifest`'s `_check_destination_contained` (`manifest_writer.py:366`) shall call `contained_in_workarea` with this app's work area. `list_projects` and `_handle_load_project` (picked or typed) shall require it too, and `_handle_save_dialog`, `list_projects` and `_handle_load_project` shall refuse a project folder for which `_is_reparse_point` is true, checked before `resolve()`, for new and merge targets alike.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62` (the placement guard and its junction arm are written at Inc 1 with `place_into_workarea`; the listing and load uses at Inc 8b)
- **Numeric pass threshold:** at Inc 1: `place_into_workarea` into a junction pointing at another work area and at a plain outside folder → 2 refusals, 0 bytes written; at Inc 8b: a junction `workarea/evil` into another work area's project → 0 listed, 0 loads (picked and typed), and 0 bytes written outside `self.workarea` by 8 writers (Save project new name, Save project merge, Save project emit, the save-back, the variant append, the MAC sync, the A2L sync, and the manifest seam `write_project_manifest`); a junction to a plain outside folder → the same; a normal project → listed, loaded and saved.
- **Negative control:** executed (S-02 probe): `_check_destination_contained PASSED (no raise)` and `copy_into_workarea WROTE …\other\.s19tool\workarea\target\src.s19` at `1d677ba` → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — a normal folder; junctions into another work area and outside, for each writer.

### LLR-172.1 — The recent-sources store is written per user
- **Traceability:** HLR-172
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.30
- **Statement:** `recent_store_path() -> Path` (NEW, `workspace.py`) shall return `%LOCALAPPDATA%\s19_app\recent_sources.json` (from the `LOCALAPPDATA` environment variable, the per-user, per-machine profile that does not roam; when it is unset, the store is disabled and nothing is written). `record_recent_source(path)` (NEW) shall write `{"schema_version": 1, "sources": [{"path", "kind"}]}` there, newest first, de-duplicated by resolved path, at most 20 entries, staged under a unique `tempfile.mkstemp` name in the same folder and placed with `os.replace` after an `_is_reparse_point` check on that folder. `load_from_path` (`app.py:8710`) and `load_a2l_from_path` (`:8789`) shall call it after a successful copy, for sources outside the work area only. No file of the store is written under the base folder or any `.s19tool`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34` (`LOCALAPPDATA` pointed at a temporary folder)
- **Numeric pass threshold:** 25 distinct outside loads → 20 entries, newest first; the same file twice → 1 entry; a source inside the work area → 0 entries; a failed load → 0 entries; the store folder as a junction → 0 writes; 2 concurrent writers → a valid file, 0 fixed staging names; `LOCALAPPDATA` unset → 0 files written; 0 `recent_sources.json` under the base folder.
- **Negative control:** a mutation dropping the de-duplication → 2 entries → RED; a mutation writing to `<base>/.s19tool/` (round-2 location) → the base-folder arm RED.
- **Boundary catalog:** ☒ boundary ☒ error — the 20th and 21st entry; a junctioned store folder; `LOCALAPPDATA` unset.

### LLR-172.2 — The store is read as untrusted input (C6)
- **Traceability:** HLR-172
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.21
- **Statement:** `read_recent_sources() -> RecentSources(entries, problem)` (NEW, `workspace.py`) shall read the per-user store with `read(65 536 + 1)`; a file over 65 536 bytes gives no entries and the problem `too large`; an unparseable or wrongly shaped file gives no entries. It shall return only entries whose `path` has a drive letter and a root (not UNC, not `\\?\` or `\\.\`, not drive-relative), no path component for which `is_windows_device_name` is true, no C0 or C1 control character, and whose `kind` is one of `s19`, `hex`, `mac`, `a2l` and matches the path's suffix, at most 20, in order. It shall never raise. A mapped network drive letter cannot be told from a local one by syntax; the guard against touching it is that a recent is never touched before Enter (LLR-173.4).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** 1 000 distinct valid entries (`C:\NNN.s19`, about 41 KB) → exactly the first 20, in order; exactly 65 536 bytes → parsed; 65 537 → 0 entries and `too large`; `{not json`, a top-level list, `schema_version: 2` → 0 entries; `kind: exe`, a relative path, a NUL, `\x1b[2J` in a path, U+009B, `\\host\share\x.s19`, `\\?\GLOBALROOT\x.s19`, `C:x.s19`, `C:\x\NUL.s19`, `C:\x\a.s19:ads`, `C:\x\a.s19.`, a `.s19` path with `kind: a2l` → 0 returned; 0 raises.
- **Negative control:** a mutation removing the size cap → the 65 537-byte arm returns entries → RED; S-07's executed probe: `\\host\share\x.s19 … is_absolute = True` → RED for an absolute-only filter.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — no file; 65 536 and 65 537 bytes; hostile entries; an unreadable file.

### LLR-172.3 — Recent paths stay out of projects, reports and every work area
- **Traceability:** HLR-172
- **Ledger:** LED-2026-10-26-batch-100.21
- **Statement:** No writer of `project.json`, of a report, of a project folder or of any file under the base folder or a `.s19tool` shall copy an entry of the recent-sources store.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-36 — `pytest tests/test_b100_recents.py -k tc_b100_36`
- **Numeric pass threshold:** after an outside load, Save project and a report → 0 occurrences of the recent path's unique marker directory in any file under the base folder.
- **Negative control:** a mutation adding the recents to the manifest → 1 occurrence → RED.
- **Boundary catalog:** none — no input class; the arm is one end-to-end save and report.

### LLR-172.4 — One work-area lister
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** `list_workarea_files(workarea)` (NEW, `workspace.py`) shall return the regular, non-link files of `workarea/temp/`, excluding `.staging`, and `refresh_files` (`app.py:6543`) shall build its list from it.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37` (an AST census: one enumeration of the temp folder in `s19_app/`)
- **Numeric pass threshold:** the census → 1 function enumerating `temp/`; the list equals `refresh_files`' items (0 differences); a link and `.staging` → 0 listed.
- **Negative control:** a mutation adding a second enumeration of `temp/` in `app.py` → the census counts 2 → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — an empty temp; a link.

### LLR-172.5 — A typed project path opens the project (L-2); reserved homes never do (S-01)
- **Traceability:** HLR-172
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.10
- **Statement:** `_load_path_from_user_input` (`app.py:8658`) shall resolve the typed path; when it is a project of this work area (§1.3), or that folder's `project.json`, it shall load that project; `_handle_load_project` shall refuse any name that `list_projects` would not list (a reserved home compared case-folded, a link, a non-project). Any other folder inside the work area shall give the `not a project` tokens; a folder outside it shall give the `outside the work area` tokens; a file with no or an unsupported suffix shall give `not a supported file`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `ab`, `ab/project.json` and `ab` reached through a `..` segment → 3 loads of `ab`; `temp`, `TEMP`, `patches` → 0 project loads, 0 files written; an empty folder inside → 1 `not a project`; a folder outside holding a `project.json` → 1 `outside the work area`, 0 project loads; `firmware` (no suffix) → 1 `not a supported file`.
- **Negative control:** executed on `1d677ba` (P-15): `Unsupported file type: ` → RED; S-01's executed probe: `validate_project_files(workarea/temp)` accepts → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — `..` segments; reserved homes; a folder outside the work area.

### LLR-172.6 — The Workarea Files list renders names literally (C8)
- **Traceability:** HLR-172
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** `refresh_files` shall build each item's label through `safe_text` (`utils.py:44`, markup off and control characters removed), replacing today's `Label(item.name)` (`app.py:6559`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39`
- **Numeric pass threshold:** `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and a name holding U+009B → 4 rows whose plain text equals the name minus control characters, 0 spans, 0 control characters, 0 raises.
- **Negative control:** today's markup-on `Label` paints 1 span for `[bold]x.s19` (QA-02 probe) → RED.
- **Boundary catalog:** ☒ invalid — the four hostile names.

### LLR-173.1 — `LoadChoice` and one router
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.12
- **Statement:** The Load dialog (`screens.py`) shall dismiss with `LoadChoice(kind, value)` (NEW, B100-I8), `kind` one of `project`, `workarea`, `recent`, `path`; one app handler shall route `project` to `_handle_load_project`, `workarea` to `load_selected_file` in place, `recent` to `load_from_path` (or `load_a2l_from_path` by kind), and `path` to `_load_path_from_user_input`. `_handle_load_dialog` keeps accepting a `Path` (routed as `path`), so `tests/test_tui_app.py:1254`, `:1288` stay valid. The load question (HLR-174) runs in this router.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** 4 kinds → 4 routes; a `Path` → the `path` route; a work-area pick → 0 new files in `temp/`; a direct `_handle_load_project` call → 0 questions.
- **Negative control:** a mutation routing `workarea` through `load_from_path` → 1 new copy → RED.
- **Boundary catalog:** ☒ boundary — a recent A2L (routed by kind).

### LLR-173.2 — Keys, focus order and the empty Load
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18
- **Statement:** The Load dialog shall start with the focus on `#load_path`; bind `tab` to the order `#load_path` → `#load_list` → `#load_preview` → buttons; move a printable key typed while `#load_list` has the focus to `#load_path` and type it there, so it never reaches an app binding; bind `enter` and `alt+l`, and make `#load_ok`, load the highlighted row when `#load_list` had the focus last and the typed text otherwise; bind `escape` to dismiss with `None`; a click selects a row and does not load. A Load with no selection and no typed text shall paint `nothing selected` and `pick a row or type a path` in `#load_reason` and stay open. `p` opens the dialog with the open project's row highlighted, else the first project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** on open → the focus on `#load_path` (1 assertion); `enter` in each section → 1 dismiss with the item; `#load_ok` after a list highlight vs after typing → the row and the typed path respectively (2 arms); `p` typed with the list focused → `#load_path` holds `p`, 0 app actions; `escape` → 1 dismiss with `None`; an empty Load → 1 token pair, 0 dismisses; 1 click → 0 loads; `p` with project P open → P's row highlighted; every shown key pressed → its action (5 of 5).
- **Negative control:** executed on `1d677ba` (P-18, P-19) → RED; a mutation starting the focus on `#load_list` (`pa_C`'s start) → the open arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty Load; both precedence cases; no project open for `p`.

### LLR-173.3 — Every list renders names through `safe_text` (C8)
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** Every row and preview line of the Load dialog built from names on disk or from the recent store shall render through `safe_text` (today's `screens.py:707` builds `Label(name)` with markup on).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** a project `[b]P`, a file `[@click=app.bell]x.s19`, a file `[link=x]a.s19` and a name with U+009B → 4 literal rows, 0 spans, 0 control characters, 0 raises.
- **Negative control:** today's `Label(name)` paints 1 span for `[b]P` (QA-02 probe) → RED.
- **Boundary catalog:** ☒ invalid — hostile names.

### LLR-173.4 — The dialog's sources, empty sections and recent rows
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.18
- **Statement:** The Load dialog shall take projects from `list_projects`, files from `list_workarea_files` and recents from `read_recent_sources`; each empty section shall paint its tokens. A recent row shall show only its path, size and last-seen time from the store, and "checked when loaded"; a recent entry shall not be stat-ed, previewed or read before the engineer presses Enter on it, and a recent source missing on pick shall paint `not found` and drop the entry. A project row's preview shall read its manifest on a worker with the LLR-169.4 caps, cancelled when the highlight moves.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 2 projects + 1 reserved folder + 1 junction, 2 files, 3 recents → 2 + 2 + 3 rows; empty sources → 3 token lines; rendering and highlighting 3 recents → 0 filesystem calls (a counting probe on `os.stat` / `open`); a missing recent picked → 1 `not found`, the store without it; highlighting a project with a 1 MiB manifest → a key answered within 200 ms.
- **Negative control:** a mutation listing folders without `list_projects` → the reserved folder listed → RED; a mutation previewing a recent on highlight → 1 filesystem call → RED; a main-thread preview read → the 200 ms arm RED.
- **Boundary catalog:** ☒ empty ☒ invalid ☒ error — every section empty; an over-cap manifest; a missing recent.

### LLR-173.5 — An invalid typed path is explained inside the dialog (UX-06)
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** When the typed path does not exist, has an unsupported suffix, or is a folder that is not a project or lies outside the work area, the Load dialog shall stay open, keep the typed text and paint the matching tokens (LLR-172.5) in `#load_reason`, without dismissing.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** 4 invalid paths → 4 token pairs, 0 dismisses, the field unchanged (4 of 4).
- **Negative control:** a mutation dismissing with the path → the dialog closes → RED.
- **Boundary catalog:** ☒ invalid — the four invalid kinds.

### LLR-173.6 — The preview marks the active set for every row kind, and the load installs it
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.34
- **Statement:** `#load_preview` shall mark with `●` the files a load of the highlighted row installs, computed by `choose_install_set` (NEW, a pure module-level function in `app.py`, landed at Inc 7 with the fallback rule of LLR-169.6 and reused by the Inc 9b preview, so Inc 9b stays at 3 files): for a project, its variant, MAC and A2L, with its variants, sub-folders, manifest state and problems listed; for a file or work-area row, the file plus the MAC and A2L the session keeps, and, with a project open, the note that the file becomes that project's active variant; for a recent row, nothing beyond LLR-173.4's fields. The panes shall stack below 100 columns, and no row shall wrap.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** 4 projects (clean, after a save-back, active variant missing, A2L-only), a file row and a file row with a project open → the `●` rows equal the installed paths after Enter (6 of 6); the project-open file row carries the active-variant note; at 99 columns → stacked, at 100 and 118 → side by side; 0 wrapped rows at 118.
- **Negative control:** a mutation computing the mark from the first variant by name → the save-back project's mark differs from the install → RED.
- **Boundary catalog:** ☒ boundary — 99 and 100 columns; the six row kinds.

### LLR-173.7 — Painted text carries no internal decision id
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** No string painted by a surface this batch adds or changes — the Load dialog, the load question, the Save dialog, the busy indicator, the Load-result panel and the refusal tokens — shall carry an internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`, `HLR-…`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-66 — `pytest tests/test_b100_load_dialog.py -k tc_b100_66` (renders each surface at 118×54 and greps its painted text)
- **Numeric pass threshold:** 5 surfaces × their scenarios → 0 matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`.
- **Negative control:** the prototypes paint "Browse is gone (D7)" and "D10: click loads OFF" (UX-18 captures) → a surface copied from them → RED.
- **Boundary catalog:** none — the scan has no input classes; its set is every painted string of the five surfaces.

### LLR-174.1 — The trigger truth table
- **Traceability:** HLR-174
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17
- **Statement:** The load guard (NEW, in the one load seam, LLR-174.4) shall decide over unsaved image (D, `differs_from_last_saved`) × Flow Builder dirty (F, `is_dirty`, `flow_screens.py:1354`) × Patch Editor document dirty (W, a public accessor added to the panel, `screens_directionb.py:4808`) × load kind (image replace, attach, project): an image replace asks iff D; an attach (MAC or A2L) never asks; a project load asks iff D or F or W. Of the 24 cells, 11 ask and 13 load. A project open with nothing unsaved does not ask.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:** 24 of 24 cells as tabulated (executed: `cells 24 ask 11 load 13`); patched → Save project → image replace → load; patched + entries → Save project → project load → load; patched → save-back → image replace → load.
- **Negative control:** dropping D → 5 cells wrong, dropping F → 1, dropping W → 1 (executed); making an attach ask on D (the round-2 table) → 4 cells wrong → RED.
- **Boundary catalog:** ☒ boundary — every cell is one; the saved-then-patched cell.

### LLR-174.2 — One short question, safe focus, keys
- **Traceability:** HLR-174
- **Ledger:** LED-2026-10-26-batch-100.3
- **Statement:** The confirm modal (NEW, `screens.py`, on the `pb_A` ids `#confirm_yes`, `#confirm_no`) shall name in one short question every item that would be lost, start with the focus on `#confirm_no`, bind `y` to replace and `n` and `escape` to cancel, let `enter` act on the focused button, render names through `safe_text`, and push no second modal; cancel leaves the session unchanged. `LoadGuardScreen` (`screens_directionb.py:4279`) keeps guarding the Patch Editor's own document load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** `n`, `escape` and an immediate `enter` → 0 changes to the image digest, `current_file.path` and `current_project`; `y` → 1 load; D, F and W together → 1 modal naming 3 items; 3 shown keys pressed → 3 actions.
- **Negative control:** a mutation focusing `#confirm_yes` first → the immediate `enter` replaces → RED.
- **Boundary catalog:** ☒ invalid — a key outside the set (ignored).

### LLR-174.3 — The question comes before the reset
- **Traceability:** HLR-174
- **Ledger:** none
- **Statement:** For a project load, the answer shall be taken before `_reset_project_session` runs; a cancel shall not run it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_confirm.py -k tc_b100_46`
- **Numeric pass threshold:** cancel → 0 reset calls; replace → 1 reset call after the answer.
- **Negative control:** a mutation resetting before asking → the cancelled session is empty → RED.
- **Boundary catalog:** ☒ boundary — re-loading the open project.

### LLR-174.4 — One load seam for every image-replacing route
- **Traceability:** HLR-174
- **Ledger:** LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.27
- **Statement:** `_confirm_then_load(kind, go)` (NEW, `app.py`) shall be the one seam through which every image-replacing route passes before it changes the session: the `LoadChoice` router (LLR-173.1), the Workarea Files pick (`_load_from_item`, `app.py:9021`, before `load_selected_file`), the variant switch (`_handle_select_variant`, `app.py:6736`, before `load_from_path`, reached by `v` and by the panel's `v`) and a project load from the dialog. It runs the guard (LLR-174.1) and the worker refusal (LLR-177.1). `_handle_load_project` called directly by tests is not a route and meets no modal.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:** with an unsaved patch: the Load dialog, a Workarea pick, `v` and the panel's `v` → 4 questions; `n` on each → 0 changes; a direct `_handle_load_project` call → 0 questions; an AST census of `load_selected_file` / `load_from_path` / `_handle_load_project` callers reachable from a binding or a list event → each passes the seam (0 bypasses).
- **Negative control:** executed on `1d677ba` (P-42): the Workarea pick and `v` replace the image with no question → RED.
- **Boundary catalog:** ☒ boundary — the four routes; a direct test call.

### LLR-175.1 — The dialog's lines follow the name rules
- **Traceability:** HLR-175
- **Ledger:** LED-2026-10-26-batch-100.5
- **Statement:** `SaveProjectScreen` (`screens.py:483`) shall, on every change of the name, show in `#save_where` the sanitised folder and its kind (new, the open project, a merge), and the refusal tokens computed by the HLR-164 rules (reserved, device, disguised clash, over 64, path too long), including the open-project update in place.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `a b` → `ab`; `Reports` → `reserved name`; `CON` → `device name`; a disguised clash → `already a project`; 65 characters → `name too long`; the open project's name → "updates the open project"; each line with 0 markup spans.
- **Negative control:** a mutation computing the lines without case-folding → `Reports` shows no line → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — 64 and 65 characters; reserved, device and clashing names.

### LLR-175.2 — No parent field
- **Traceability:** HLR-175
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `SaveProjectScreen` shall compose no `#project_parent_path` and no `#save_browse` (`screens.py:555`), and its payload's `parent_folder` shall be this work area.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** 0 widgets with either id; the payload's parent resolves to `self.workarea` (1 equality).
- **Negative control:** today's dialog (`screens.py:555`) → 1 Browse button → RED.
- **Boundary catalog:** ☒ boundary — a work area under a long base path.

### LLR-175.3 — Keys and the empty Save
- **Traceability:** HLR-175
- **Ledger:** LED-2026-10-26-batch-100.10
- **Statement:** `SaveProjectScreen` shall start with the focus on `#project_name`, bind `escape` to dismiss with `None` and `alt+s` to save, leave plain letters to the name field, keep Save focusable during a refusal and refuse on press with the reason painted, and keep the dialog open with `name is empty` / `type a project name` on an empty name.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `escape` → 1 dismiss with `None`, 0 folders; an empty Save → 1 token pair, 0 dismisses; `s` typed → the field holds `s`; `alt+s` → 1 save; Save pressed during a clash → 1 refusal painted, Save still focusable, 0 files.
- **Negative control:** executed on `1d677ba` (P-18, P-19) → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — an empty and an all-space name; a refused name.

### LLR-175.4 — The summary is the save plan (R-PC)
- **Traceability:** HLR-175
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.31
- **Statement:** `#save_summary` shall be painted only from `plan_project_save` (LLR-167.6), at the plan's granularity — one row per top-level file, one per sub-folder with its file count, one for `project.json` — each with its action word, the image as source + N change entries (K applied by this save) or an unchanged copy, the pending line when `differs_from_last_saved` is true, the document, skipped links, and, in a merge, the target's active-variant change as its own row, through `safe_text`; no row is omitted, and every `replace` or `rewrite` says so. The summary scrolls with Save and Cancel pinned. The dialog shall paint its first frame before any digest is computed; the emitted image's digest and the digests of the files the plan copies shall be computed once per open on a worker, the summary showing those rows as `computing…` until they arrive, and `alt+s` pressed before they arrive waits for them under the busy indicator. The name-dependent rows are recomputed at most every 150 ms of typing, with no hashing per keystroke. `SaveProjectScreen.plan` (NEW, read-only) exposes the plan the summary paints as an immutable value (a frozen dataclass), so a reader cannot change what the handler executes.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** for the 5 scenarios, the painted rows equal the plan's rows (0 differences at 220 columns); 0 rows painted from any other source (an AST check that the dialog calls no placement or listing function); 20 keystrokes → ≤ 3 recomputations and 0 digests; with the case_06 project (37.7 MB A2L), the dialog's first frame → painted before any digest starts, and the digests → complete within 2 s on the CI host (budget assumed — measured at Inc 11, recorded in the packet); a 300-row plan at 118×54 → Save and Cancel visible, the last row reachable by scrolling; a merge → 1 active-variant row.
- **Negative control:** a mutation dropping `keep` rows from the painter → 1 row missing in the merge scenario → RED; a mutation recomputing the plan with digests per keystroke → the 0-digests arm RED.
- **Boundary catalog:** ☒ boundary — the 5 scenarios; a 300-row plan.

### LLR-176.1 — The busy seam owns `#status_text` and moves the bar within steps
- **Traceability:** HLR-176
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19
- **Statement:** `begin_busy(key, label, steps)`, `step_busy(key, text, done=None, total=None)` and `end_busy(key, outcome, final_lines)` (NEW, `app.py`) shall widen `set_progress` (`app.py:13615`). `begin_busy` takes ownership of `#status_text` (no other writer, `set_file_status` included, paints it until `end_busy`) and shows `#progress_bar` from 0; `step_busy` paints the step and sets the bar from `done/total` when the step reports bytes (copy, read, parse) and from the step index otherwise; one `set_interval` timer on the main thread drives the spinner and elapsed time; worker calls go through `call_from_thread`. `end_busy` runs on every exit, an exception included, paints in order the outcome, then the project and file line, then the file state, and hides the bar; when idle the bar is hidden.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50 — `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** begin → 1 indicator in `#status_text`, the bar at 0 and shown; a byte-reporting step of 1 MiB in 4 chunks → the bar increases 4 times within the step; a `set_file_status` call during the action → 0 changes to `#status_text`; end → the 3 final lines in order, the bar hidden; a raising action → 0 indicators left, the bar hidden.
- **Negative control:** a mutation dropping `end_busy` on the exception path → 1 indicator left → RED; a mutation setting the bar from the step index only → the within-step arm RED.
- **Boundary catalog:** ☒ boundary ☒ error — an action shorter than a tick; an exception; an indivisible step.

### LLR-176.2 — Every progress caller maps to one action (C-31)
- **Traceability:** HLR-176
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19
- **Statement:** A table of actions (NEW, keyed, in `app.py`) shall list, for each action, its begin site, its step sites and its end sites on success, failure and exception; every `set_progress` site at `1d677ba` (P-29: 24 calls in 12 functions) shall map to exactly one action's begin, step or end.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 — `pytest tests/test_b100_busy.py -k tc_b100_51` (an AST derivation over `app.py`)
- **Numeric pass threshold:** the derivation maps 24 of 24 sites (≥ 24, derived) to exactly one action's begin, step or end (≥ 4 steps: `app.py:4951`, `:6210`, `:8769`, `:8841`); each action → ≥ 1 begin and an end on its success, failure and exception exits.
- **Negative control:** a mutation removing one action's failure-path end → the census names that action → RED.
- **Boundary catalog:** none — the census has no input classes; its set is derived from the code.

### LLR-176.3 — Main-thread steps paint before they work
- **Traceability:** HLR-176
- **Ledger:** LED-2026-10-26-batch-100.11
- **Statement:** For a step that runs on the main thread (the A2L tag-table build, and any action left on it), `step_busy` shall paint the step's name once before the work starts, through the `call_after_refresh` idiom (`app.py:8708`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-52 — `pytest tests/test_b100_busy.py -k tc_b100_52`
- **Numeric pass threshold:** the step text read in a `call_after_refresh` callback scheduled before the step starts → equals the step name (1 equality).
- **Negative control:** a mutation starting the work before the refresh → the callback reads the previous text → RED.
- **Boundary catalog:** ☒ boundary — a step on a 1-byte image.

### LLR-177.1 — Three actions on workers, installs on the main thread, everything else refused
- **Traceability:** HLR-177
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19
- **Statement:** Project load, Save project and the A2L parse shall run under `@work(thread=True)`. Every write of `current_file`, `current_a2l_path`, `current_a2l_data`, the variant set and the change service shall run on the main thread through `call_from_thread`. Save project shall run `rederive_for_save` and apply the result on the main thread before its worker starts, and the worker shall emit, copy, hash and write the manifest from a copy, under LLR-164.4's handler. While one runs, the one load seam (LLR-174.4), unload, `v`, the save-back, Save project, Patch apply and undo shall be refused with the `busy` tokens naming the running action. Quit shall ask with the focus on No; confirmed, it shall wait for the worker to finish or roll back before exiting.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** the project holding the case_06 A2L → the elapsed text changes ≥ 1 time before the end; a thread-id probe on the listed writes → 0 off-main writes; during a Save project: `l`, a Workarea pick, `v`, `U`, a save-back, Patch apply and undo → 7 `busy` refusals, 0 changes; `q` → 1 question with the focus on No; confirmed during a forced slow save → 0 partial folders after exit.
- **Negative control:** today's synchronous load (`app.py:8510`) → 0 changes → RED; a mutation omitting `v` from the refused set → the image changes during the save → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a load inside one tick; quit during a save.

### LLR-177.2 — Worker failures keep the app running
- **Traceability:** HLR-177
- **Ledger:** none
- **Statement:** A worker of LLR-177.1 that raises shall end the busy indicator with the failure, report it in the status, and leave the app running and the session as it was before the action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** 3 forced raises (one per action) → 3 failure statuses, the app running, 0 changed session attributes.
- **Negative control:** a mutation letting the exception escape the worker → the app exits → RED.
- **Boundary catalog:** ☒ error — one raise per action.

### LLR-178.1 — The announcement composer
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16
- **Statement:** `compose_load_announcement(...)` (NEW, a pure function in `services/variant_execution_service.py`) shall return the opened variant, the variant count, the reason — recorded active; first by name, none recorded; first by name, manifest damaged; first by name, no `project.json`; next valid, the recorded one missing or not readable — the relation recorded in `derived_from` — "patched, N bytes differ from `<base>`" when the base is a file of the project (name and SHA-256 match), "patched from `<base>` (not in this project); N bytes differ from it" when it is not, and no relation line when nothing is recorded (a variant with a `derived_from` record is always described as patched, never as identical) — whether the opened variant is the one the app's last recorded write made active, and the problem list.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-55 — `pytest tests/test_b100_announce.py -k tc_b100_55`
- **Numeric pass threshold:** 5 reason cases → 5 of 5 reasons; a save-back to `firmware_1.s19` and to `firmware-patched.s19` → "patched, 4 bytes differ from `firmware.s19`" in both (2 of 2); a base not in the project → "patched from `firmware.s19` (not in this project); 4 bytes differ from it"; no `derived_from` → 0 relation lines; 0 announcements containing "identical"; 3 problems → 3 entries in precedence order; "latest" true only for the variant the last recorded write made active, false for a touched file (2 arms).
- **Negative control:** a mutation reporting "recorded active" for the fallback case → RED; a mutation comparing with the first variant by name → the `firmware-patched.s19` arm compares the image with itself (P-39) → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 1 variant; no openable image; no `derived_from`; a base not in the project.

### LLR-178.2 — The summary line and the final `#status_text`
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16
- **Statement:** `_handle_load_project` shall write the announcement's summary line to the status log through `set_status` (opened variant, `k of n`, problem count, then "details: p"), and pass the project and opened-file line to `end_busy` as its final lines, so `#status_text` shows them once the progress line releases it; both render names through `safe_text`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-56 — `pytest tests/test_b100_announce.py -k tc_b100_56`
- **Numeric pass threshold:** a 2-variant load → 1 summary line in `#log_line_4` naming the opened variant and the count 2, ending "details: p", inside 118 columns; after the load ends, `#status_text` names project and file (1 assertion); a variant named `[b]x.s19` → 0 spans.
- **Negative control:** a mutation painting with markup on → 1 span → RED.
- **Boundary catalog:** ☒ invalid — a hostile variant name.

### LLR-178.3 — The Load-result panel, reachable by keyboard
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.25
- **Statement:** After a project load, the app shall push the Load-result panel (NEW, `screens.py`, on the `pe_B` ids `#result_body`, `#result_variant`, `#result_ok`) with the composed announcement and every problem in a scrolling list with no truncation, rendered through `safe_text`. The focus starts on the list (↑, ↓, PgUp, PgDn, Home, End scroll it); `tab` moves to `#result_ok`, labelled "Close (esc)"; `escape` dismisses it from anywhere and `enter` dismisses it only when `#result_ok` has the focus; `v` dismisses it and runs `select_variant` (`app.py:6687`) through the one load seam. The Load dialog's preview of the open project shows the same announcement for the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-67 — `pytest tests/test_b100_announce.py -k tc_b100_67`
- **Numeric pass threshold:** 30 problems at 118×54 → after `end`, the last row has a visible region (a geometry read after layout); an immediate `enter` → the panel still open; the shown key `esc` pressed from the list → dismissed (the label's key verified, UX C-1); `tab`, `enter` → dismissed; `escape` → dismissed; `v` → the variant selector open; 0 exception class names; 0 internal decision ids; the preview of the open project lists the same 30.
- **Negative control:** a mutation starting the focus on `#result_ok` → the immediate `enter` closes the panel unread → RED; a mutation truncating the list at 10 rows → 20 missing → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 problems; 30 problems at 118×54.

### Information Flow Contract (IFC) — C-54

- **Part A — flows:**

```
FLOW: session_to_saved_project
  SOURCE : the session (current_file, MAC, A2L, change document, open project) and the typed project name
  NODES  :
    - fn    : reserved-name check, case-folded (app.py _handle_save_dialog)
      owner : LLR-164.1
      in    : sanitised name
      out   : refusal or pass
    - fn    : clash check against other projects (app.py _handle_save_dialog)
      owner : LLR-164.2
      in    : sanitised name + current_project_dir
      out   : refusal naming the project, in-place update, or pass
    - fn    : name cap and OSError on create (app.py _handle_save_dialog)
      owner : LLR-164.3
      in    : sanitised name
      out   : refusal status or a created folder
    - fn    : parent must be the app work area (app.py _handle_save_dialog)
      owner : LLR-171.3
      in    : SaveProjectPayload.parent_folder
      out   : refusal before mkdir, or the work area
    - fn    : image_differs_from_source (change_service.py)
      owner : LLR-167.1
      in    : current_file.mem_map
      out   : bool
    - fn    : emit through save_patched or copy the source (app.py _handle_save_dialog)
      owner : LLR-167.2
      in    : mem_map or the source path
      out   : the project image file
    - fn    : entry count in the save status (app.py _handle_save_dialog, save_back_status_suffix)
      owner : LLR-167.3
      in    : the save result
      out   : the status line
    - fn    : blocked re-derive refusal (app.py _handle_save_dialog)
      owner : LLR-167.4
      in    : ChangeActionResult ok=False
      out   : status naming blocked entries; no files
    - fn    : byte-identical reuse (workspace.py copy_into_workarea)
      owner : LLR-163.1
      in    : staged bytes + destination listing
      out   : an existing path or a new name
    - fn    : size precheck before the byte comparison (workspace.py copy_into_workarea)
      owner : LLR-163.2
      in    : candidate sizes
      out   : candidates worth reading
    - fn    : predict the landing name with the placement code (workspace.py predict_placement)
      owner : LLR-163.7
      in    : digest + size + destination listing
      out   : the predicted PlacementResult
    - fn    : re-derive onto a copy, then emit and verify (change_service.py rederive_for_save, emit_and_verify)
      owner : LLR-167.7
      in    : source image copy + change document
      out   : the re-derived map; the written, verified image
    - fn    : clear the Patch Editor dirty flag after the document is written (app.py _handle_save_dialog)
      owner : LLR-167.8
      in    : a successful Save project
      out   : the flag and the saved-state record cleared
    - fn    : record derived_from (manifest_writer.py serialize_manifest)
      owner : LLR-168.4
      in    : the patched variant, its base name, digest and byte count
      out   : the derived_from key
    - fn    : the save plan, painted and executed (project_gather_service.py plan_project_save)
      owner : LLR-167.6
      in    : session + typed name + target folder
      out   : SavePlan rows with landing names, actions and digests
    - fn    : record the saved state (change_service.py mark_saved)
      owner : LLR-167.5
      in    : mem_map after a successful save
      out   : the saved-state record
    - fn    : place the active document (project_gather_service.py gather_project_artifacts)
      owner : LLR-170.2
      in    : the change document, pasted or file-backed
      out   : patches/<file> + its path in GatherOutcome
    - fn    : copy every sub-folder on save-as (app.py _handle_save_dialog)
      owner : LLR-171.1
      in    : current_project_dir
      out   : the new project's sub-folders
    - fn    : compute files digests from disk (app.py _write_and_verify_manifest)
      owner : LLR-169.2
      in    : the project folder after every copy
      out   : files mapping
    - fn    : serialize files (manifest_writer.py serialize_manifest)
      owner : LLR-169.1
      in    : files + composition
      out   : project.json text
    - fn    : serialize active_document (manifest_writer.py serialize_manifest)
      owner : LLR-170.1
      in    : the document's project-relative path
      out   : the active_document key
    - fn    : private staging + os.replace (manifest_writer.py write_project_manifest)
      owner : LLR-169.7
      in    : project.json text
      out   : project.json on disk
    - fn    : verify with files and active_document in the drift domain (manifest_writer.py verify_written_manifest)
      owner : LLR-169.3
      in    : the written project.json
      out   : verified or a mismatch notice
    - fn    : remove a folder this save created (app.py _remove_created_project_dir)
      owner : LLR-164.4
      in    : every refusal after creation
      out   : no folder left
    - fn    : containment in this work area after links are resolved (workspace.py contained_in_workarea)
      owner : LLR-171.4
      in    : every project path written
      out   : a contained path or a refusal
  SINK   : the project folder and its project.json, then the status log
```

```
FLOW: project_json_to_session
  SOURCE : a project folder and its project.json, picked in Load
  NODES  :
    - fn    : parse files (variant_execution_service.py read_project_manifest)
      owner : LLR-169.4
      in    : project.json
      out   : files records or MANIFEST-BAD-STRUCTURE issues
    - fn    : one shared path predicate (variant_execution_service.py _resolve_manifest_entry)
      owner : LLR-169.8
      in    : a manifest entry
      out   : a contained path or MANIFEST-PATH-ESCAPE
    - fn    : parse gathered (variant_execution_service.py read_project_manifest)
      owner : LLR-168.1
      in    : project.json
      out   : gathered mapping or issues
    - fn    : parse active_document (variant_execution_service.py read_project_manifest)
      owner : LLR-170.1
      in    : project.json
      out   : a project-relative path, or None + an issue
    - fn    : unsaved-work question before replacing (app.py load guard)
      owner : LLR-174.3
      in    : the answer
      out   : continue or cancel
    - fn    : reset the session (app.py _reset_project_session)
      owner : LLR-165.1
      in    : the previous session
      out   : S1-S12 reset, K1/K2 kept
    - fn    : rebind the change service (app.py _reset_project_session)
      owner : LLR-165.3
      in    : the old service
      out   : a new ChangeService with the image generation
    - fn    : check_project_files (manifest_writer.py)
      owner : LLR-169.5
      in    : project dir + manifest
      out   : list of problems
    - fn    : open the active or the next valid variant (app.py _handle_load_project)
      owner : LLR-169.6
      in    : variant set + problems
      out   : the installed image and MAC
    - fn    : add not readable from the load result; keep one problem per file (app.py _handle_load_project)
      owner : LLR-169.9
      in    : the install result + check_project_files' list
      out   : the merged problem list
    - fn    : open the Load-result panel (screens.py)
      owner : LLR-178.3
      in    : the announcement
      out   : the panel, holding the focus
    - fn    : open an A2L-only project (app.py _handle_load_project)
      owner : LLR-171.2
      in    : a project with an A2L and no data file
      out   : the attached A2L
    - fn    : reopen the active document after the A2L (app.py _handle_load_project)
      owner : LLR-170.3
      in    : active_document
      out   : the Patch Editor document
    - fn    : re-home the focus after an image or project load (app.py _step_finalize)
      owner : LLR-166.1
      in    : the focused widget
      out   : a visible focused widget
    - fn    : compose the announcement (compose_load_announcement)
      owner : LLR-178.1
      in    : opened variant + variant set + problems + manifest state
      out   : the announcement
    - fn    : write the announcement to the status log, markup off (app.py set_status)
      owner : LLR-178.2
      in    : the announcement
      out   : the status log line and the VS-PE-1 painter
  SINK   : the loaded session, the status log and the announcement surface
```

```
FLOW: a2l_load_to_session
  SOURCE : an A2L file picked in Load
  NODES  :
    - fn    : re-home the focus after the A2L load (app.py load_a2l_from_path)
      owner : LLR-166.2
      in    : the focused widget
      out   : a visible focused widget
    - fn    : clear the parsed A2L on unload (app.py _apply_unload)
      owner : LLR-165.4
      in    : unload kind all or a2l
      out   : current_a2l_data None
  SINK   : the A2L state of the session
```

```
FLOW: in_project_write_to_manifest
  SOURCE : a write into the open project (save-back, variant append, MAC sync, A2L sync)
  NODES  :
    - fn    : save-back becomes the active variant (app.py on_patch_editor_panel_save_back_decision)
      owner : LLR-168.2
      in    : the written file
      out   : active_id + a manifest rewrite
    - fn    : every other in-project writer ends in the seam (app.py _sync_loaded_file_to_project and the MAC/A2L syncs)
      owner : LLR-168.3
      in    : the written file + the existing manifest
      out   : project.json rewritten with the composition carried
    - fn    : name a reused variant instead of reporting it added (app.py _sync_loaded_file_to_project)
      owner : LLR-163.5
      in    : the PlacementResult place_into_workarea returned
      out   : the status line
    - fn    : the export's status from the placement outcome (segment_split_view.py)
      owner : LLR-163.6
      in    : PlacementResult
      out   : wrote or reused
  SINK   : project.json on disk and the status log
```

```
FLOW: load_source_to_load_dialog
  SOURCE : a file loaded from outside the work area, the work-area temp folder, the typed path
  NODES  :
    - fn    : record_recent_source (workspace.py)
      owner : LLR-172.1
      in    : the loaded source path
      out   : recent_sources.json
    - fn    : read_recent_sources (workspace.py)
      owner : LLR-172.2
      in    : recent_sources.json
      out   : valid entries only
    - fn    : keep recent paths out of projects and reports (manifest, report and gather writers)
      owner : LLR-172.3
      in    : the session
      out   : project files with no recent entry
    - fn    : list_workarea_files (workspace.py)
      owner : LLR-172.4
      in    : workarea/temp
      out   : regular files
    - fn    : Workarea Files list rows, markup off (app.py refresh_files)
      owner : LLR-172.6
      in    : file names
      out   : literal rows
    - fn    : typed-path routing (app.py _load_path_from_user_input)
      owner : LLR-172.5
      in    : a typed path
      out   : a project load, a file load, or a status naming Load project
    - fn    : the dialog's sources (screens.py Load dialog)
      owner : LLR-173.4
      in    : projects + files + recents
      out   : the sections
    - fn    : the dialog's rows, markup off (screens.py Load dialog)
      owner : LLR-173.3
      in    : names from disk and the store
      out   : literal rows
    - fn    : mark the active set in the preview (screens.py Load dialog)
      owner : LLR-173.6
      in    : the highlighted item
      out   : the preview with ● on the files a load installs
    - fn    : explain an invalid typed path inside the dialog (screens.py Load dialog)
      owner : LLR-173.5
      in    : a typed path
      out   : a reason in #load_reason; the dialog stays open
    - fn    : the dialog's keys and empty-Load reason (screens.py Load dialog)
      owner : LLR-173.2
      in    : enter, escape, an empty Load
      out   : a dismiss or a painted reason
    - fn    : LoadChoice router (app.py)
      owner : LLR-173.1
      in    : LoadChoice(kind, value)
      out   : the matching load path
  SINK   : the loaded session and the status log
```

```
FLOW: typed_name_to_save_dialog
  SOURCE : the name typed in the Save project dialog
  NODES  :
    - fn    : preview of the folder and the warning lines (screens.py SaveProjectScreen)
      owner : LLR-175.1
      in    : typed name + projects + image differs
      out   : the folder line and the warning lines
    - fn    : payload with the work area as parent (screens.py SaveProjectScreen)
      owner : LLR-175.2
      in    : the confirmed name
      out   : SaveProjectPayload
    - fn    : the dialog's keys and empty-Save reason (screens.py SaveProjectScreen)
      owner : LLR-175.3
      in    : escape, an empty Save
      out   : a dismiss or a painted reason
    - fn    : paint the save plan as the summary (screens.py SaveProjectScreen)
      owner : LLR-175.4
      in    : SavePlan
      out   : #save_summary rows
  SINK   : _handle_save_dialog
```

```
FLOW: unsaved_work_to_question
  SOURCE : a load request while the session holds unsaved work or an open project
  NODES  :
    - fn    : the trigger table (app.py load guard)
      owner : LLR-174.1
      in    : unsaved image, flow dirty, document dirty, load kind
      out   : ask or load
    - fn    : the one load seam for every image-replacing route (app.py _confirm_then_load)
      owner : LLR-174.4
      in    : the Load dialog, the Workarea pick, the variant switch, a project load
      out   : the guard run once, then the load
    - fn    : the confirm modal (screens.py)
      owner : LLR-174.2
      in    : what would be lost
      out   : replace or cancel
  SINK   : the load continues, or the session stays unchanged
```

```
FLOW: long_action_to_indicator
  SOURCE : the start of a load, parse, save, report or comparison
  NODES  :
    - fn    : begin_busy / step_busy / end_busy (app.py)
      owner : LLR-176.1
      in    : action label, steps, outcome
      out   : the working indicator and its elapsed time
    - fn    : every set_progress caller routed through the seam (app.py)
      owner : LLR-176.2
      in    : the 12 calling functions
      out   : one begin and one end per action
    - fn    : main-thread paint before work (app.py call_after_refresh)
      owner : LLR-176.3
      in    : a main-thread action
      out   : one painted frame before the work
    - fn    : worker moves with main-thread installs (app.py @work)
      owner : LLR-177.1
      in    : project load, Save project, A2L parse
      out   : results installed through call_from_thread
    - fn    : worker failure handling (app.py)
      owner : LLR-177.2
      in    : an exception in a worker
      out   : a failure status, the app running
  SINK   : the indicator (VS-PD-1) and the status log
```

- **Part B — boundary decomposition:** yes — the TUI has addressable dialogs and status widgets. The four modals (Load dialog, load question, Save dialog, Load-result panel) are top-level screens pushed on the app, so their parent is `SYSTEM`. The status log, the status line and the progress bar sit in `workspace_shell`, which no contract declares, so V12 reports their balancing as not checked, as in batch-99. Consumers were measured with `grep -rl <id> --include=*.py --include=*.tcss s19_app tests` at `1d677ba`. The addresses are the ids the prototype verdict fixed (P-30); the Save dialog's Save is `#save_ok` in `pc_B` as today, and the Load dialog keeps `#load_dialog`.

```
COMPONENT: load_dialog
  PARENT : SYSTEM
  SURFACE: Load dialog
  INPUTS : projects: list[str] ; workarea_files: list[Path] ; recent_sources: list[RecentSource] ; typed_path: str
  OUTPUTS:
    - id          : load_choice
      value       : the dismiss result LoadChoice(kind, value)
      address     : query("#load_dialog")
      cardinality : 1
      consumers   : s19_app/tui/screens.py
                    s19_app/tui/styles.tcss
                    s19_app/tui/app.py::_handle_load_dialog
                    tests/test_tui_app.py
                    tests/test_tui_directionb.py
      owner       : LLR-173.1
```

```
COMPONENT: save_project_dialog
  PARENT : SYSTEM
  SURFACE: Save project dialog
  INPUTS : project_name: str ; work_area: Path ; image_differs: bool ; projects: list[str]
  OUTPUTS:
    - id          : save_payload
      value       : SaveProjectPayload with the work area as parent_folder
      address     : query("#save_ok")
      cardinality : 1
      consumers   : s19_app/tui/screens.py
                    s19_app/tui/app.py::_handle_save_dialog
                    tests/test_b99_staging.py
                    tests/test_tui_directionb.py
                    tests/test_tui_manifest_save.py
      owner       : LLR-175.2
```

```
COMPONENT: status_log
  PARENT : workspace_shell
  SURFACE: Workspace status line
  INPUTS : message: str
  OUTPUTS:
    - id          : log_line_4
      value       : the newest status line (load result, announcement, problem count)
      address     : query("#log_line_4"), INDEXED POSITIONALLY
      cardinality : 4
      consumers   : s19_app/tui/app.py
                    tests/test_b99_a2l_encode.py
                    tests/test_b99_bytes_field.py
                    tests/test_b99_crc_region.py
                    tests/test_b99_editor_image.py
                    tests/test_b99_export.py
                    tests/test_b99_load_project.py
                    tests/test_b99_patch_truth.py
                    tests/test_b99_s0.py
                    tests/test_b99_staging.py
                    tests/test_legend_scope_and_logwidth.py
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-178.2
```

```
COMPONENT: busy_indicator
  PARENT : workspace_shell
  SURFACE: Workspace status line
  INPUTS : action_label: str ; step_text: str ; outcome: str
  OUTPUTS:
    - id          : progress_bar
      value       : working state, step and elapsed time of the running action
      address     : query("#progress_bar")
      cardinality : 1
      consumers   : s19_app/tui/app.py
                    s19_app/tui/styles.tcss
                    tests/test_report_progress.py
                    tests/test_tui_directionb.py
      owner       : LLR-176.1
```

```
COMPONENT: busy_status_line
  PARENT : workspace_shell
  SURFACE: Workspace status line
  INPUTS : action_label: str ; step_text: str ; outcome: str
  OUTPUTS:
    - id          : status_text
      value       : spinner, action label, step n/m and elapsed time while a worker action runs (P-D A); the project and opened file after a project load
      address     : query("#status_text")
      cardinality : 1
      consumers   : s19_app/tui/app.py
                    s19_app/tui/flow_screens.py
                    s19_app/tui/screens_directionb.py
                    s19_app/tui/services/change_service.py
                    s19_app/tui/styles.tcss
                    tests/test_b97_load_project_dialog.py
                    tests/test_b99_a2l_encode.py
                    tests/test_b99_editor_image.py
                    tests/test_b99_export.py
                    tests/test_b99_load_project.py
                    tests/test_b99_patch_truth.py
                    tests/test_b99_s0.py
                    tests/test_b99_staging.py
                    tests/test_b99_truncation.py
                    tests/test_change_service.py
                    tests/test_diff_same_path_guard.py
                    tests/test_filename_markup_safety.py
                    tests/test_tui_commandbar.py
                    tests/test_tui_diff_compare_realpath.py
                    tests/test_tui_diff_screen.py
                    tests/test_tui_directionb.py
                    tests/test_tui_memory_patch.py
                    tests/test_tui_operations_view.py
                    tests/test_tui_patch_big.py
                    tests/test_tui_patch_card.py
      owner       : LLR-176.1
```

```
COMPONENT: load_question
  PARENT : SYSTEM
  SURFACE: Load question (P-B A)
  INPUTS : unsaved_items: list[str]
  OUTPUTS:
    - id          : confirm_no
      value       : the safe answer, focused first; y replaces, n and escape cancel
      address     : query("#confirm_no")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_load_dialog
      owner       : LLR-174.2
```

```
COMPONENT: load_result_panel
  PARENT : SYSTEM
  SURFACE: Load-result panel (P-E B)
  INPUTS : announcement: LoadAnnouncement
  OUTPUTS:
    - id          : result_ok
      value       : the panel's close button, focused while the panel is open; enter, escape and v act on the panel
      address     : query("#result_ok")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_load_project
      owner       : LLR-178.3
```

---

## 5. Validation strategy

### 5.1 Methods

- **Layer A — white-box / functional:** TC-B100-01 through TC-B100-72 (`test (unit)` / `test (integration)`), each named in its LLR, plus the re-pinned nodes TC-018, AT-031b and `test_tc_b99_31_changed_bytes_take_the_next_free_name` (LLR-163.3, LLR-163.4). Each declared mutation runs at Phase 3 (C-40). The AST censuses derive their sets from the code (C-31: TC-B100-07, -09, -37, -51, -59, -65, -66).
- **Layer B — black-box acceptance:** AT-B100-01 through AT-B100-21, one node each, marked `at_b100_NN`, in the `tests/test_b100_*.py` file of their story. Each drives the shipped surface (§3 preface), runs at 118×54 and 220×60 with notifications on, and observes files on disk, painted text or the screen stack.
- **Expert inspection (Phase 4, UX-16):** the Load-result panel and the Save project summary are inspected in a real Windows Terminal at 118×54 and 220×60 by the `ux-reviewer`: a cognitive walkthrough of reopening a project after a save-back, after damage, and of saving into a new, the open and an existing project, each checked against HLR-175 and HLR-178. It is recorded in `04-validation.md` beside the ATs and does not replace them. Evaluation with users: not performed (one operator).
- **Oracles:** image bytes through `tests/support/independent_reader.py`; digests through `hashlib` in the test; never through the app's own loader.
- **Environment:** every run in a worktree sets `PYTHONPATH=<worktree>` and probes `s19_app.__file__` first (the `pip -e` trap); `NO_COLOR` unset.
- **Regression at every increment gate:** the full suite against a baseline captured at `1d677ba` before Inc 1, plus the whole-tree guards as one command: `pytest tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_address_census.py tests/test_batch91_registry_hygiene.py tests/test_engine_unchanged.py`, and `devflow-validate --brief`.

### 5.2 Batch acceptance criteria
- 100 % of LLRs covered by at least one passing TC; every declared mutation goes RED.
- Every story has at least one passing AT-B100 observing its outcome through the shipped surface, with its boundary and negative evidence, at both reference sizes.
- Every §2.7 premise probe that served as a RED side is re-run at Phase 4 on the closing tree, and its decisive line has flipped: `p01` → `== in-memory patched image? True`; `p03` → no `LEAK` line; `p02` A → `active=firmware_1`; `p04` 2/6/7 → one problem each; `p02` C → one `firmware_1`; S4 → the focus on the window's target; the S-02 junction → not listed.
- The Phase-4 expert inspection (§5.1) is recorded with no open HIGH.
- 0 blocker findings open at Phase 4; the full suite and the whole-tree guards with no new failure against the baseline.

### 5.3 AT-by-increment index (QA-14, B-06)

ATs drive through the ids the verdict fixed (P-30), with the Load dialog's focus starting on the path field (LLR-173.2). An AT written before Inc 9b that types a path into `#load_path` and presses Enter keeps working after 9b, because the path field has the focus and the typed path wins. Its project loads go through `p`, re-pinned at Inc 9b from `#project_list` / `#project_ok` to the highlighted row + `enter`. An AT that loads over unsaved work is re-pinned at Inc 10 to answer `y`. TC arms that need a later increment are written at that increment (ARQ §8.1).

| AT | Story | Written at | Extended or re-pinned at | Output-then-consume (C-12) |
|---|---|---|---|---|
| AT-B100-01 | US-153 | Inc 1 | — (typed path, path field focused) | — |
| AT-B100-02 | US-154 | Inc 2 | Inc 11 (`alt+s`; no parent field) | — |
| AT-B100-03 | US-155 | Inc 3 | Inc 9b (project pick), Inc 10 (answers `y`: the P1 entry is unsaved) | Save project → project folder |
| AT-B100-04 | US-156 | Inc 4 | Inc 6 (dismiss the panel first), Inc 9b (`p` opens the Load dialog) | — |
| AT-B100-05 | US-157 | Inc 5 | Inc 6 (panel oracle), Inc 7 (the "patched" line against `derived_from`), Inc 9b | Save project → `P1/firmware.s19` → Load |
| AT-B100-06 | US-158 | Inc 6 | Inc 7 (`derived_from` on disk), Inc 9b | save-back → `project.json` → Load |
| AT-B100-07 | US-159 | Inc 7 | Inc 9b | Save project → `files` → Load |
| AT-B100-08 | US-160 | Inc 8a | Inc 9b | Save project → `active_document` → Load |
| AT-B100-09 | US-161 | Inc 8b | Inc 9b, Inc 11 | save-as → Q folder → flow list |
| AT-B100-10 | US-161 | Inc 8b | Inc 9b | A2L-only Save → Load |
| AT-B100-11 | US-161 | Inc 8b (listing and Save refusal; the placement guard's junction arm is TC-B100-62 at Inc 1) | Inc 9b (reads `#load_list`) | — |
| AT-B100-12 | US-162 | Inc 9a | — (typed path, path field focused) | Load → per-user store |
| AT-B100-13 | US-162 | Inc 9a | — | — |
| AT-B100-14 | US-163 | Inc 9b | — | Load → store → Load dialog; preview marks → install |
| AT-B100-15 | US-164 | Inc 10 (all four routes) | — | — |
| AT-B100-16 | US-165 | Inc 11 | — | — |
| AT-B100-17 | US-166 | Inc 12a+12b | — | — |
| AT-B100-18 | US-167 | Inc 12a+12b | — | — |
| AT-B100-19 | US-168 | Inc 6 (panel, reasons) | Inc 7 (problems; the `derived_from` line, default-name arm), Inc 9b | save-back → `project.json` → Load |
| AT-B100-20 | US-158 | Inc 6 | Inc 7 (`derived_from` carried), Inc 8a (`active_document` carried), Inc 9b | variant append / MAC / A2L sync → `project.json` → fresh Load and Execute scope |
| AT-B100-21 | US-165 | Inc 11 (fresh, pending patch, refused, `files`, document, merge, save-as) | — | save plan → files on disk |

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-05 (LLR-164.2) | Inc 2: refusals, open-project save, an exact-name save that adds a variant | Inc 8a: the merge carry of `gathered` and `active_document` |
| TC-B100-12 (LLR-166.1) | Inc 4: the load tails | Inc 6: panel closes; Inc 9b: dialog `esc`, cancelled load; Inc 10: question `n` |
| TC-B100-59 (LLR-167.6) | Inc 5: fresh, open project, pending patch, refused | Inc 7: the `files` row; Inc 8a: the document row and the merge; Inc 8b: save-as with sub-folders |
| TC-B100-62 (LLR-171.4) | Inc 1: the placement guard, junction arms | Inc 8b: listing, load, the 7 writers |
| TC-B100-71 (LLR-168.4) | Inc 7 | — |
| TC-B100-72 (LLR-174.4) | Inc 10: all four routes | — |

### 5.4 Reverse census (QA-15, trigger B1)

Executed at `1d677ba` with `grep -rl --include=*.py <symbol> tests` (35 test sources match the B1 set, P-35). One row per touched symbol.

| Symbol (increment) | Test sources | Disposition |
|---|---|---|
| `copy_into_workarea` (Inc 1) | 15 | `Path` return kept (LLR-163.1); re-pinned: TC-018, AT-031b, `test_tc_b99_31_changed_bytes_take_the_next_free_name`; the other 3 `_2+` files stay (P-22) |
| `_export_reuse_target` (Inc 1) | `test_b99_export.py` | the status word now comes from the placement outcome (LLR-163.6) |
| `Added variant` (Inc 1) | `test_tui_variants.py:274` | the first-load arm stays green |
| `_handle_save_dialog` exact-name merge (Inc 2, Inc 5) | `test_tui_variants.py::test_save_second_s19_into_project_appends_variant` (`:354`) | kept green (A-09) |
| `_handle_load_project` direct callers (Inc 3, Inc 7) | 13: `b97_fixtures.py`, `test_b97_load_project_dialog.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`, `test_report_progress.py`, `test_tui_commandbar.py`, `test_tui_manifest_save.py`, `test_tui_patch_variant.py` (`:338`, `:343`, `:782`, `:788`), `test_tui_report_filter_surface.py`, `test_tui_report_seam.py`, `test_tui_report_view.py`, `test_tui_variants.py`, `test_variant_execution.py` | the load question sits in the dialog router, so a direct call meets no modal; status-text assertions re-pinned at Inc 7 where the summary line replaces `Loaded project '` (4 files: `test_b99_export.py`, `test_b99_load_project.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`) |
| manifest API (Inc 6, 7, 8a) | 9 | additive keys (`files`, `active_document`, `derived_from`), no `schema_version` bump; pins `test_manifest_writer.py:99`, `:216`, `:481` hold |
| `_resolve_manifest_entry` (Inc 7, LLR-169.8) | `test_b97_flow_builder.py`, `test_flow_persistence.py`, `test_flow_execution_service.py`, `test_manifest_writer.py`, `test_variant_execution.py` | the manifest-keys mode is used by `read_project_manifest` and `_reject_unsafe_entry` only; both flow-reference callers, `flow_persistence_service.py` and `flow_execution_service.py`, stay on the default mode, so `test_tc_b97_20_hostile_refs_render_literally` stays green (B-03) |
| `_handle_save_dialog` (Inc 2, 5, 8a, 8b, 11) | 7: `test_b99_staging.py`, `test_project_gather.py`, `test_tui_app.py`, `test_tui_evidence_packs.py`, `test_tui_manifest_save.py`, `test_tui_report_seam.py`, `test_tui_variants.py` | under the emit decision on data (LLR-167.1) an unpatched session still byte-copies, so `test_save_project_creates_project_folder_on_disk` and the evidence-pack saves keep their files; `test_project_gather.py::test_tc700_active_editor_document_is_gathered_by_kind` (a check document) keeps a byte copy and its `checks/` placement; AT-B99-05 (save-back, then Save project) now emits and keeps `status.startswith("Project saved")` on `#log_line_4` with the entry-count suffix (LLR-167.3); the plan execution and the refusals are re-checked per file at each listed increment |
| `_load_from_item`, `_handle_select_variant` (Inc 10) | callers through the Workarea Files list and `v` in `test_tui_directionb.py`, `test_tui_variants.py` | the one load seam asks only when something unsaved would be lost; tests without unsaved work meet no modal |
| `#project_parent_path` (Inc 11, D7) | `test_b99_staging.py` (6 nodes: `test_tc_b99_14_save_project_missing_source`, `test_tc_b99_14_placement_failure_removes_created_folder`, `test_tc_b99_14_preexisting_folder_survives_placement_failure`, `test_at_b99_05_save_project_after_same_name_save_back`, `test_tc_b99_ux_c10_save_project_filename_renders_literally`, `test_tc_b99_ux_c10_placement_error_path_renders_literally`), `test_loadfilescreen_input.py:898`, `test_tui_directionb.py:3090` | re-pinned at Inc 11 with the same expectations and no parent typing (the payload's parent is the work area); AT-B99-05 keeps its outcome (LED-2026-10-26-batch-100.12) |
| `LoadFileScreen` / `#load_path` / `#load_ok` (Inc 9b) | 4 / 10 | the ids survive in `pa_C`; class-name references re-pinned to the new dialog class |
| `LoadProjectScreen` / `#project_list` / `#project_ok` (Inc 9b) | 7 / 7: `test_b97_load_project_dialog.py`, `test_b99_crc_region.py`, `test_b99_export.py`, `test_b99_load_project.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`, `test_b99_truncation.py` | the dialog retires (VS-PA-3); project picks re-pinned to `#load_list` + `enter` |
| `_handle_load_dialog(Path)` (Inc 9b) | `test_tui_app.py:1254`, `:1288` | unchanged: the handler keeps accepting a `Path` (LLR-173.1) |
| `set_progress` / `#progress_bar` (Inc 12a+12b) | 5: `test_before_after_report.py`, `test_report_off_ui_thread.py`, `test_report_progress.py`, `test_tui_directionb.py`, `test_tui_report_attribution.py` | the bar keeps working (P-D A); value assertions re-pinned if the step mapping changes them |
| snapshot cells (Inc 9b, 11, 12a) | 29 SVG cells carrying the status line or a dialog (QA-15 count) | rebaselined in the increment that changes them, each named in its packet |

---

### 5.5 Per-increment source files (ARQ §8, B-07)

Taken from `design/ARQ-batch-100.md` §8 / §8.1 as amended for round 2. Every conditional was decided at PDR (LED .27, .34); the design proposal `design/design-proposal-b100.md` repeats the sets. Interfaces by name: B100-I13 (`find_identical`, `place_into_workarea`), B100-I14 (`contained_in_workarea`), B100-I15 (the `save_patched` split), B100-I16 (`derived_from`), B100-I17 (the save plan), B100-I18 (the unsaved predicate), B100-I19 (`_session_snapshot`), B100-I20 (the one load seam), B100-I21 (the manifest-keys mode), B100-I22 (`predict_placement`).

| Inc | Source files | # |
|---|---|---|
| 1 | `workspace.py` (B100-I13, I14, I22), `segment_split_view.py`, `app.py` | 3 |
| 2 | `app.py`, `workspace.py` (device-name predicate, `PROJECT_NAME_MAX_CHARS`) | 2 |
| 3 | `app.py` | 1 |
| 4 | `app.py` | 1 |
| 5 | `app.py`, `change_service.py` (B100-I15, I18), `project_gather_service.py` (B100-I17) | 3 |
| 6 | `app.py`, `variant_execution_service.py`, `screens.py`, `styles.tcss` (the panel needs its layout rules) | 4 (at cap) |
| 7 | `manifest_writer.py`, `variant_execution_service.py`, `app.py` (`derived_from` B100-I16; `choose_install_set`; the plan's `files` row takes its key list from `app.py`, so `project_gather_service.py` is not touched) | 3 |
| 8a | `app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py` | 4 (at cap) |
| 8b | `app.py`, `project_gather_service.py`, `workspace.py` (`contained_in_workarea` uses for listing and load) | 3 |
| 9a | `workspace.py`, `app.py` | 2 |
| 9b | `screens.py`, `app.py`, `styles.tcss` (`choose_install_set` already in `app.py` from Inc 7) | 3 |
| 10 | `screens.py`, `app.py` (B100-I20), `styles.tcss`, `screens_directionb.py` (the public dirty-flag reader LLR-174.1 requires) | 4 (at cap) |
| 11 | `screens.py`, `app.py`, `styles.tcss` | 3 |
| 12a + 12b | `app.py`, `styles.tcss` (the quit question reuses the Inc 10 confirm modal with its own text) | 2 |

No increment exceeds 4 source files; Inc 6, Inc 8a and Inc 10 are at the cap.

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
D1–D7 and O-1..O-11 are mapped to the requirements they shape in LED-2026-10-26-batch-100.1.
### 6.3 Open risks

**Security questions (trigger family C; the `devflow-scan-spec.py` verdict is recorded in LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.13 and LED-2026-10-26-batch-100.23):**
- **Input surface (C6).** Four untrusted inputs: the typed project name (HLR-164: sanitised, case-folded, reserved and device names refused on the raw and sanitised name, capped at 64 and by path length, a junction target refused), the typed load path (LLR-172.5: resolved, contained in this work area, reserved homes refused), `project.json` (LLR-169.4, LLR-169.8, LLR-170.1, LLR-168.1, LLR-168.4: 1 MiB, 1 000 entries per array, a manifest-keys mode that refuses drive-relative, stream and device names per path component), and the per-user recent store (LLR-172.2: size-capped, parse-guarded, drive-rooted paths only, kind matching the suffix, no control characters, never touched before Enter). Every placement requires containment in this work area inside `place_into_workarea` (LLR-163.1, LLR-171.4), so no writer can be left off a list; save-as never follows a directory link (LLR-171.1).
- **Markup and control-character injection (C8).** Every name from disk or the store renders through `safe_text` (`utils.py:44`): LLR-172.6, LLR-173.3, LLR-174.2, LLR-175.4, LLR-178.2, LLR-178.3.
- **Privacy (S-16, decided).** The operator chose a per-user store, outside every work area and every `.s19tool` (LLR-172.1). The orchestrator's PDR-C3 ruling places it at `%LOCALAPPDATA%\s19_app\recent_sources.json`, the per-machine profile, because a roaming `%APPDATA%` would copy the paths to a domain profile server, against the operator's choice that the paths never travel. Zipping or syncing a work area no longer carries absolute local paths, and a shared folder can no longer plant a store. The store holds the same paths the log already holds (`app.py:10820-10825`), bounded to 20.
- **Known gap.** A mapped network drive letter cannot be told from a local one by syntax; the protection is that a recent entry is never touched before Enter (LLR-173.4), and pressing Enter is the engineer's own action.
- **"token", "session", "form", "escape", "expose", "permission", "hash"** mean a refusal phrase or name token, a TUI editing session, a dialog form, the keyboard key, a method on a service API, a file a test makes unreadable, and the SHA-256 digest used only to detect that a project file changed on disk; `secret.txt` is the name of the probe file behind a junction in the S-03 test. No credential, network access or secret value is involved.

**Rulings written into the contract (the author's round-1 questions):** Q-1 → `PROJECT_NAME_MAX_CHARS = 64` plus the path-length check (LLR-164.3). Q-2 → HLR-164 (a) and LLR-164.2 with QA-04's definitions and A-09's merge; a clash now tells the engineer to choose another name (UX-35). Q-3 → `_session_snapshot()` derived from the live app (LLR-165.2). Q-4 → moot: every UI story is READY. Q-5 → `patches/changes.json`, written by the app (LLR-170.2). Q-6 → VS-PD-3 = refuse (HLR-177). Q-7 → recorded as an amendment of LLR-015.3 (LED-2026-10-26-batch-100.13).

**Deviations, stated rather than closed silently:**
- **The Save-project emit rule (introduced in round 2, corrected in round 3).** Round 2 made Save project emit when "the image differs from its source or the document holds at least one entry" (LED .4). That rule made a check document refuse every Save project (B-01, P-37) and wrote byte-different copies of unchanged data as new active variants (QA R2-01, P-38). Round 3 decides on data: the change document is re-derived onto a copy, and Save project emits only if that data differs from the source's; a check document never counts (LLR-167.1, LED .14). R-TUI-012's restatement ("otherwise copies byte for byte") holds again.
- **QA-05 return shape.** `copy_into_workarea` keeps its `Path` return and is exactly `return place_into_workarea(...).path`, with every guard in `place_into_workarea` and no second claim loop (LLR-163.1); a changed return type would reach 15 call sites in 7 files (P-34).
- **S-15 count cap.** Save-as refuses a copy larger than the volume's free space; no file-count cap was ruled, so none is set.
- **VS-PA-4 `p` and the initial focus.** `p` opens the one Load dialog with the open project's row highlighted, and the dialog opens with the focus on the path field, correcting `pa_C`'s start on the list (UX-05, UX-37).
- **Device names on the raw name.** The dispositions check device names on the raw and the sanitised name, so `con.txt` is refused (LLR-164.1); the security reviewer's round-2 closure would have saved it as `contxt`. The ruling governs.
- **AT-B100-21 reads the save plan** through `SaveProjectScreen.plan`, an exception to "no private access" declared in the §3 preface, because the painted summary may be cut at 118 columns (dispositions r2, UX-32).

**Decided at PDR:** the `image_differs_from_source` pre-check stays only as a fast path into the data comparison and never decides copy alone (LLR-167.1, LED .32); the conditional files of §5.5 are decided (LED .27, .34).

**Other risks:**
- `app.py` is in 14 of 15 increments: sequential merges, one worktree each (ARQ §9).
- Additive manifest keys: an older build re-saving a project drops `files`, `active_document` and `derived_from`; the next Load shows `no digests saved`, and the panel has no "patched" line (ARQ §3.2).
- Hash cost: estimated, not measured (ARQ §3.1); from Inc 12b it runs on the worker; the Save dialog computes the image digest once per open.
- Reuse widening (Inc 1): the variant append and the export must stay true about reuse (LLR-163.5, LLR-163.6).
- Re-pinned tests (§5.4) could hide a regression: each re-pin names the old value, the new value and the requirement that changes it in its increment's reverse census.
- Three writers still bypass the manifest writer (A-01); their files show as `not recorded` until the backlog item lands.

### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-26-batch-100

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
