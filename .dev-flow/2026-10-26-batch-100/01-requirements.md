
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
| Work area | `<base>/.s19tool/workarea/`, the folder Load lists (`list_projects`, `app.py`). "Inside the work area" means inside `self.workarea.resolve()` after every link and junction is resolved (`contained_in_workarea`, LLR-171.4), never inside some other `.s19tool/workarea`. |
| Work copy | The copy of a loaded source in `workarea/temp/` (`WORKAREA_TEMP`, `workspace.py:20`). |
| Data differs | The emit decision (LLR-167.1): the change document's entries, re-derived onto a copy of the source image (the `save_patched` split, LLR-167.7), give data that differs from the source file's data. A check document never counts. It decides whether Save project emits or copies. |
| Unsaved | `ChangeService.differs_from_last_saved(mem_map)` (NEW, LLR-167.5): the image differs from the copy last loaded or written. With the Patch Editor dirty flag and the Flow Builder dirty flag it decides the load question (HLR-174) and the Save summary's pending line (HLR-175). It never decides emit or copy. |
| Project | A direct child folder of this work area, not a link or junction, not a reserved home, holding a `project.json`, a data file or an A2L file (Q-2; the A2L file since Inc 8b, HLR-171a, E3-architect A3-16). |
| Save plan | The one object `plan_project_save` (NEW, LLR-167.6) returns: target folder and kind, one row per top-level file, one row per sub-folder with its file count, and one row for `project.json`, each with its source, landing name (from `predict_placement`, LLR-163.7) and action word (`new`, `keep`, `merge`, `rewrite`; no increment through Inc 8a produces `replace`, E3 R1 — a later increment adds it only with its own requirement arm). The Save dialog paints it and `_handle_save_dialog` executes it (R-PC). |
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
| P-24 | Textual 8.2.8 `Label` parses markup by default, and both the project list and the work-area list build `Label(name)` from disk names. | premise | ✅ TRUE | `python -I -c "import inspect; from textual.widgets import Label; print(inspect.signature(Label.__init__))"` → `… markup: 'bool' = True …`; `screens.py:707` `ListItem(Label(name))`; `app.py:6559` `ListItem(Label(item.name))` (at `1d677ba`; at `4fef292`: `screens.py:712`, `app.py:7316`, LED .82) | LLR-172.6, LLR-173.3 |
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
> **Platform arms.** Windows-only arms (junctions, links, case-insensitive names) skip on other platforms with a named reason, and the packet counts and names every skip; junctions are made with `_winapi.CreateJunction` (C-QA-6).
>
> **Keys.** A modal with no text field binds single letters (`y` / `n` / `escape`); a modal with a text field binds `alt+<letter>` and leaves plain letters to the field. Every shown key is verified by pressing it. Test paths and `-k` selectors are provisional until Phase 3 and reconciled at Phase 4 (V-5).
>
> **Output-then-consume (C-12, trigger B4).** Every `project.json` writer/reader pair runs in one chain: drive the shipped handler, re-read what it wrote from disk, open it with the unmodified Load in a fresh app, and assert the consumer's outcome. AT-B100-05, -06, -07, -08, -10 and -20 are those gates. A test that writes `project.json` directly is a consumer-contract guard (a TC), never the gate. The project builders of the design proposal's enabler E4 state which of them may write `project.json` (the damaged, legacy and hostile cases only); an output-then-consume AT takes its `project.json` only from the shipped handler (C-QA-4).
>
> **Refusal tokens (NEW, created in Phase 3 as constants in one module; an AT matches the token, the rest of the wording is free).** Each refusal, problem and empty state paints its reason token and its next-step token.
>
> | Case | Reason token | Next-step token |
> |---|---|---|
> | reserved home as a name (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `reserved name` | `choose another name` |
> | Windows device name (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `device name` | `choose another name` |
> | disguised clash (Q-2; painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `already a project` | `choose another name` |
> | name over 64 characters (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `name too long` | `shorten the name` |
> | full path over the limit (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `path too long` | `shorten the name` |
> | folder cannot be created or written; a Save worker that raises any exception (Inc 12b, LLR-177.2a) | `could not save` | `check the folder` |
> | blocked document entry (Inc 5; painted in the Save dialog from Inc 11, LLR-175.1m) | `blocked entry` / `blocked entries` | `fix them in the Patch Editor` |
> | the Save summary is out of date at Save (Inc 11, LLR-175.4b) | `the summary changed` | `check it, then save again` |
> | Save project with nothing loaded (Inc 11, LLR-175.3j) | `Nothing to save` | `load a data file or A2L first` |
> | a session file is missing at save (LLR-155.4; in the Save dialog from Inc 11, LLR-175.1k) | `source file missing` + the file | `reload it or remove it from the project` |
> | a session file cannot be read at save (LLR-164.4; Inc 11, LLR-175.1l) | `could not be read` + the file | `check that the file can be opened, then save again` |
> | empty name (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `name is empty` | `type a project name` |
> | empty Load (Inc 9b, LLR-173.2h, LLR-173.2i) | `nothing selected` | `pick a row or type a path` |
> | typed path not found / unsupported, a relative typed folder path included (Inc 9a, LLR-172.5h), a typed text holding a character the path calls refuse (Inc 12a, LLR-172.5i); painted in `#load_reason` from the dialog (Inc 9b, LLR-173.5 … LLR-173.5e) | `not found` / `not a supported file` | `check the path` |
| Workarea Files pick: the entry is no longer a regular file (Inc 12a, LLR-172.6b) | `not a regular file` | `pick another file` |
| Workarea Files pick: the file is over the copy size cap (Inc 12a, LLR-172.6c) | `too large to open` + the file | `load a smaller file` |
> | typed folder in the work area, not a project, a reserved home included (Inc 9a, LLR-172.5b); a name the project list does not list passed to a project load, a reserved home and its other spellings included (LLR-172.5g); painted in `#load_reason` from the dialog (Inc 9b, LLR-173.5 … LLR-173.5e) | `not a project` | `pick a project in the list` |
> | typed folder outside the work area; painted in `#load_reason` from the dialog (Inc 9b, LLR-173.5 … LLR-173.5e) | `outside the work area` | `copy the folder into the work area` |
> | project folder with no data or A2L file | `no data or A2L file` | `load a file and Save project` |
> | save-as larger than the free space (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `not enough free space` | `free disk space or remove files from the project` |
> | Save target is a link or junction (painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `link or junction` | `choose another name` |
> | Save parent is not this work area (Inc 8b, LLR-171.3) | `not the work area folder` | `choose the work area as the parent folder` |
> | Load: the project folder is a link or junction (Inc 8b, LLR-171.4e); a typed folder or `project.json` path through a link or junction (Inc 9a, LLR-172.5d); painted in `#load_reason` from the dialog (Inc 9b, LLR-173.5 … LLR-173.5e) | `link or junction` | `pick a project in the list` |
> | a typed data or A2L file inside the work area that is a link (Inc 9b E5, CR9b-03) | `is a link or junction` | `open the file it points to` |
> | Load: the project folder is not one folder of this work area, or resolves outside it (Inc 8b, LLR-171.4f) | `outside the work area` | `copy the folder into the work area` |
> | Load or Save target: the project folder cannot be inspected, such as a permission error (Inc 8b E5 F7(a), LLR-171.4f); a project load whose worker step raises (Inc 12b, LLR-177.2); painted in `#load_reason` from the dialog for the typed arm (Inc 9b, LLR-173.5e); painted in the Save dialog before Save (Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `could not be read` | `check that the folder can be opened, then load again` / `then save again` |
> | second MAC file in the target (Inc 8b, LLR-167.6c; painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `already has a MAC file` + the target's MAC name | `choose another name` |
> | second A2L file in the target (Inc 8b, LLR-167.6d; painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `already has an A2L file` + the target's A2L name | `choose another name` |
> | a project file over the per-file cap: sub-folder file or top-level copy (Inc 8b, LLR-167.6g; painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `too large to copy` + the file + the limit | `move it out of the project folder, then save again` |
> | a session file over the per-file cap: image, MAC, A2L or document (Inc 8b, LLR-167.6g) | `too large to copy` + the file + the limit | `a project cannot hold files over <limit>` |
> | save as: copy list over 2 000 files, a walk over 10 000 entries, or a path over 32 components (Inc 8b, LLR-171.1j; painted in the Save dialog before Save, Inc 11, LLR-175.1a … LLR-175.1j, LLR-175.1o, LLR-175.1p) | `too many files to copy` (over 2 000 / over 10 000 entries) / `nested too deep` | `move files out of the project, then save again` |
> | save as: a sub-folder that cannot be listed, or an entry that cannot be classified (Inc 8b, LLR-171.1k) | `could not be read` + the entries | `check that they can be opened, then save again` |
> | save as: the open project folder became a link, left the work area, or cannot be inspected (Inc 8b; `could not be read` E5 F7(a)) | `link or junction` / `outside the work area` / `could not be read` | `pick a project in the list` |
> | save as: a copy landed on a file of the new project that holds the same bytes under another name, so every save repeats it (Inc 8b E5 F5) | `the plan named` + both names + `already holds the same bytes as` | `remove the duplicate copy from the open project folder '<P>', then save again` |
> | save to a new folder while the open project's folder is gone, one line after the success line (Inc 8b E5, LLR-171.1n) | `The open project folder '<P>' was not found` + `its other files were not copied` | `copy them into '<target>' if you still have them` |
> | save as: a copy changed while saving, landed under another name, or failed (Inc 8b, LLR-171.7b) | `could not save` + the file | `check the folder` |
> | links or junctions the save as skipped, one line after the success line (Inc 8b, LLR-171.1c) | `links or junctions not copied` + the paths | `copy those files into the project if it needs them` |
> | a gathered file `project.json` cannot record, one line per file (Inc 8b, LLR-171.5) | `copied but not recorded` + the file + why (`Windows reserves that name` for a device stem, `the name is not one project.json records` for any other reason, E5 F4) | `rename it in the common folder, select the new name, then Save project` |
> | more than 10 entries of the open project's tree in one status list (Inc 8b, LLR-171.7a; the 10 is defined once, `PAINTED_NAME_LIMIT`, E5 F6) | the first 10 entries + `and K more` | — |
> | a failed save's rollback kept a file because a folder changed while saving (Inc 8b E5, LLR-171.7c) | `Not removed after the failed save` + the files + `a folder changed while saving` | `check the project folders` |
> | Load: no `project.json` and no data or A2L file (Inc 8b, LLR-171.2e) | `no project.json` | `load a file and Save project` |
> | Load: an A2L-only project's A2L is a link or over the cap (Inc 8b, LLR-171.2f) | `link or junction` / `too large to open` + the A2L | `replace the A2L file, then Load again` |
> | empty Projects / work-area files / recents | `no projects` / `no work-area files` / `no recent sources` | `ctrl+s saves a project` / `l loads a file` / — |
> | recent source missing on pick (Inc 9b, LLR-173.4k) | `not found` | `check the path` |
> | recent-sources store problem (Inc 9b, LLR-173.4g) | `too large` / `could not be read` | `the next load starts a new list` / `check that the recent-sources file can be opened` |
> | load question (Inc 10, LLR-174.2k, LLR-174.2o, LLR-174.2p, LLR-174.2q) | `unsaved changes` | `Load <target> anyway?` — buttons `Replace (y)` / `Cancel (n)` |
> | a request that changes the image, the change document or the project while a file load, A2L attach, project load or Save project runs (Inc 12b, LLR-177.3 … LLR-177.3f) | `busy` + the running action's label | `wait for it to finish` |
> | quit while a worker runs (Inc 12b, LLR-177.4a; the quit question's text, title Quit?, buttons Quit (y) / Stay (n)) | `still working` + the running action's label | `wait, or quit after it finishes` |
> | an A2L attach whose copy or parse raises (Inc 12b, LLR-177.2b) | `could not be read` + the A2L file | `check that the file can be opened, then load again` |
> | problem: manifest damaged | `manifest damaged` + what is wrong in user terms | `Save project rewrites it` |
> | problem: no `project.json` | `no project.json` | `Save project writes it` |
> | problem: missing | `missing` | `restore the file, or Save project to drop it` |
> | problem: not readable | `not readable` + the reason in user terms | `replace the file, or Save project to drop it` |
> | problem: not readable — the active document too large to reopen (Inc 8a, R10) | `not readable` + `too large to reopen` | `open it from the Patch Editor (it can take a while)` |
> | problem: not readable — the active document could not be read (Inc 8a, R10/R16) | `not readable` + `could not be read` | `check that the file can be opened, then Load again` |
> | problem: not readable — the project's A2L beside a data file is a link or over the cap (Inc 8b, LLR-171.2g; painted through the `STEP_REPLACE_A2L` mark since E5 F2) | `not readable` + `link or junction` / `too large to open` | `replace the A2L file, then Load again` |
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.13, LED-2026-10-26-batch-100.14, LED-2026-10-26-batch-100.42, LED-2026-10-26-batch-100.62, LED-2026-10-26-batch-100.63, LED-2026-10-26-batch-100.66
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.42, LED-2026-10-26-batch-100.67, LED-2026-10-26-batch-100.68
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.29, LED-2026-10-26-batch-100.42, LED-2026-10-26-batch-100.70
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.42, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.74, LED-2026-10-26-batch-100.75
- **Statement:** When Save project runs while the Patch Editor holds a document — a pasted document with at least one entry, or a file-backed document whatever its entry count (E3 R9) — the system shall place that document in the project's `patches/` (or `checks/` by kind) — a document that has no file is written by the app as `changes.json` in the home for its kind through the M-1 rule, landing as `changes_<N>.json` when a different `changes.json` is there — and record the landed project-relative path as `active_document` in `project.json`. When the project is loaded, the system shall reopen that document in the Patch Editor after the project's A2L is attached. If the recorded document is missing, unreadable, outside `patches/` or `checks/`, or not a `.json` file, then the load shall continue and list the problem. If the document cannot be written or placed, then Save project shall complete without it, record no `active_document` of its own (a merge or an open-project save carries the target's value, LLR-164.2; E3 R3) and name the unsaved document in the status.
- **Rationale (informative):** the gathered document is not reopened and a pasted one is not saved (P-8). D4 = `reabrir`; Q-5; A-12 (the app writes, the gather only places); S-11 (the reader enforces the writer's rule).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_document.py`
- **Numeric pass threshold:** `p06` A → after Load, the Patch Editor document is `patches/boost.json` with 1 entry; `p01` (pasted) → `P/patches/changes.json`, reopened with 1 entry; a different `changes.json` already there → `changes_1.json` recorded; a missing recorded document → 1 problem, the project opens; a forced document-write failure → the project saved, no `active_document` of its own (into a fresh `P`: none; in a merge whose target records one: the target's value carried, LLR-164.2), 1 status line naming the document.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer pastes one entry into the Patch Editor, saves project P and reopens P in a fresh app: the Patch Editor ledger lists that entry's address.
  - **Shipped surface:** Patch Editor, Save project, Load, the Patch Editor ledger.
  - **Acceptance test(s):** AT-B100-08
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a pasted document with 0 entries (not recorded); boundary: a file-backed document already in `P/patches/` (recorded as on disk, `keep`, E3 R1), a file-backed document with 0 entries (recorded, E3 R9), a clashing `changes.json`; invalid: an `active_document` outside `patches/`/`checks/` or not `.json`; error: a document write that fails (the save completes without it). A missing document is a listed problem.
  - **Negative control:** executed on `1d677ba` (P-8): `after Load: editor doc = None entries = 0` → AT-B100-08 is RED today.

### HLR-171 — Save as copies the whole project
- **Traceability:** US-161
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.22, LED-2026-10-26-batch-100.42, LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79, LED-2026-10-26-batch-100.81
- **Statement (EARS event):** When Save project saves the open project into a new project folder, the system shall make the new project hold every regular file of the open project, at the top level and in its sub-folders, that is not reached through a link or junction and that the save does not write itself, other than `project.json` backups (`project.json.previous-*`).
- **Decomposition:** LLR-171.1, LLR-171.1a … LLR-171.1m, LLR-171.5, LLR-171.6, LLR-171.6a, LLR-171.6b, LLR-171.7, LLR-171.7a, LLR-171.7b; the plan rows LLR-167.6a, LLR-167.6b, LLR-167.6g. The split of the former compound HLR-171 (save as, A2L-only, containment) into HLR-171, HLR-171a and HLR-171b is LED .76; the top-level files, the ceilings, the unreadable entries, the session switch, the carried `batch` rule and the painted names are LED .78.
- **Rationale (informative):** "save as" leaves flows, patches and reports behind (P-9); a junction inside a sub-folder copies an outside tree (S-03, security R2-06); a large copy can fill the disk (S-15).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_homes.py -k "tc_b100_31 or at_b100_09"`
- **Numeric pass threshold:** `p06` C → Q holds every regular file of P's sub-folders and every top-level file of P the save does not write itself (0 missing, 0 differing bytes), and 0 of P's `project.json.previous-*` backups; a top-level directory junction, a nested junction and a file symlink in P → 0 files copied through them.
- **Negative control:** executed on `1d677ba` (P-9): `Q tree: ['firmware.a2l', 'firmware.s19', 'project.json']` → AT-B100-09 RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-09) the engineer opens P (with `flows/f1.json`, `patches/boost.json`, `reports/r.md`) and saves it as Q: Q's folder holds those files, and Q's flow list shows `f1`.
  - **Shipped surface:** Save project, the Flow Execution import list, the project folders on disk.
  - **Acceptance test(s):** AT-B100-09
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a project with no sub-folder; boundary: a nested sub-folder, a copy exactly at the free space; invalid: links and junctions; error: a copy over the free space.

### HLR-171a — An A2L-only project opens
- **Traceability:** US-161
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.81
- **Statement (EARS event):** When a project folder that holds one A2L file and no data file is loaded, the system shall open that project with its A2L attached.
- **Decomposition:** LLR-171.2, LLR-171.2a … LLR-171.2g (LLR-171.2f and .2g, the A2L link and cap guard of both load branches, are LED .78).
- **Rationale (informative):** an A2L-only project saves and then cannot be loaded (P-12).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_homes.py -k "tc_b100_32 or at_b100_10"`
- **Numeric pass threshold:** `p04` 10 → the project opens, 3 A2L tags, 0 `No supported files` status lines, the session's A2L is the project's own file (orchestrator ruling Q4, LED .77).
- **Negative control:** executed on `1d677ba` (P-12): `status=['No supported files in project: P']` → AT-B100-10 RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-10) an A2L-only project saved and reopened shows its A2L in the Loaded panel.
  - **Shipped surface:** Save project, Load, the Loaded panel.
  - **Acceptance test(s):** AT-B100-10
  - **Boundary catalog (QC-3):** ☒ empty — a folder with no data file and no A2L, with and without a `project.json`.

### HLR-171b — Only folders inside this work area are listed, loaded or written as projects
- **Traceability:** US-161
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.81
- **Statement (EARS ubiquitous):** The system shall treat a folder as a project only when that folder is not a link or junction and resolves inside this work area.
- **Decomposition:** LLR-171.3, LLR-171.3a, LLR-171.4, LLR-171.4a, .4b, .4c, .4e … .4h (listing, load, Save project's target and parent, and the 8 named writers each have their own LLR). LLR-171.4d is withdrawn into .4c; LLR-171.4i and .4j (SEC-5) are routed out of 8b to the LED .50 backlog item (LED .77).
- **Rationale (informative):** a save elsewhere is never listed (P-11); a junction in the work area escapes every containment check (S-02, security R2-01); a junction `flows/` sends a saved flow outside (SEC-5, `security-increment-001.md`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_homes.py -k "tc_b100_33 or tc_b100_62 or at_b100_11"` (plus the Inc 1 arms of TC-B100-62 in `tests/test_b100_reuse.py` and `tests/test_b100_project_check.py`)
- **Numeric pass threshold:** a junction project folder pointing into another work area → 0 listed, 0 loads, 0 bytes written outside this work area by the 8 writers of LLR-171.4h; a foreign parent → refused, 0 folders.
- **Negative control:** executed (S-02 probe) on `1d677ba`: a junction folder is listed and written through → AT-B100-11 RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-11) a project folder in the work area that is a junction into another work area is not listed in the Load dialog, and typing its name in Save project is refused with `link or junction`, while a project saved through the dialog is listed.
  - **Shipped surface:** Save project, Load, the project folders on disk.
  - **Acceptance test(s):** AT-B100-11
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid ☒ error — boundary: a normal folder, the work area under another spelling; invalid: junctions into another work area, into this work area and to a plain outside folder; error: a foreign parent.

### HLR-172 — Recent sources are remembered per user
- **Traceability:** US-162
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.30, LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83, LED-2026-10-26-batch-100.84, LED-2026-10-26-batch-100.85, LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When Load copies a data or A2L file from outside this work area into the work area, the system shall record that file's absolute path in the per-user recent-sources store.
- **Decomposition:** LLR-172.1, LLR-172.1a … LLR-172.1n (… LLR-172.1n leaves out a source found only through the relative fallback, CR9-1) (the write; LLR-172.1k, LLR-172.1l and LLR-172.1m's entry-that-cannot-fit arm are the three declared exceptions to the record — an unreadable store is left unchanged, a path the store read would drop is not recorded, and a single entry that cannot fit is not recorded — and LLR-172.1m also bounds the file the writer produces); LLR-172.2, LLR-172.2a … LLR-172.2j, LLR-172.2k (the read; LLR-172.2k is also the record's entry check, LLR-172.1l); LLR-172.3. The split of the former compound HLR-172 (store, read, lister, typed path, literal names) into HLR-172, HLR-172a and HLR-172b is LED .82.
- **Rationale (informative):** the unified dialog needs its recent sources (ARQ §6); store entries could reach the network or carry control characters (S-06, S-07, S-12). The operator's S-16 decision moves the store per user, which also removes the planted-store route S-07 started from.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_recents.py -k "tc_b100_34 or tc_b100_35 or tc_b100_36 or at_b100_12"`
- **Numeric pass threshold:** 25 distinct outside sources → 20 entries, newest first, in `<LOCALAPPDATA>/s19_app/recent_sources.json`; 0 files named `recent_sources.json` under the base folder; the hostile store set of LLR-172.2a … LLR-172.2i → 0 raises, 0 refused entries returned.
- **Negative control:** code read on `4fef292`: `grep -rn LOCALAPPDATA s19_app` → 0 hits, so a load writes no store file → AT-B100-12's store half RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-12, store half) the engineer loads `examples/case_01_basic_valid/firmware.s19` through Load: the per-user store on disk (the test points `LOCALAPPDATA` at a temporary folder) lists the example's absolute path, and nothing is written under the base folder.
  - **Shipped surface:** Load (`l`, `#load_path`), the per-user store on disk.
  - **Acceptance test(s):** AT-B100-12
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no store file (an empty list); boundary: the 20th and 21st entry, exactly 65 536 bytes; invalid: hostile store entries; error: an unreadable store file, `LOCALAPPDATA` unset.
  - **Negative control:** code read on `4fef292` (above): no store file after the load → AT-B100-12 RED.

### HLR-172a — A typed project path opens the project
- **Traceability:** US-162
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When the absolute path typed into Load names a project folder of this work area or that folder's `project.json`, the system shall load that project.
- **Decomposition:** LLR-172.5, LLR-172.5a … LLR-172.5h. "Absolute" is `Path.is_absolute()` on the typed text (on Windows a drive and a root; `\x` and `C:x` are relative); a relative typed path keeps the file route and never reaches the project route, so the base-folder fallback of `resolve_input_path` never runs for it (LLR-172.5h).
- **Rationale (informative):** L-2 (P-15); `temp` loads as a project (S-01).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_recents.py -k "tc_b100_38 or at_b100_12"`
- **Numeric pass threshold:** `<workarea>/ab` and `<workarea>/ab/project.json` typed → 2 project loads of `ab`; `<workarea>/temp`, `<workarea>/TEMP`, `<workarea>/patches` and the relative `.s19tool/workarea/ab` typed → 0 project loads, 0 files written.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): typed `<workarea>/ab` → `['Unsupported file type: ']`, no project; `<workarea>/ab/project.json` → `['Unsupported file type: .json']` → AT-B100-12's typed half RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-12, typed half) after the load above, the engineer types the absolute work-area path of project `ab` into Load: the status log names project `ab` loaded. The two halves of AT-B100-12 are independent at Inc 9a: the typed half reads no store, and the consume link (a recent picked in the Load dialog) is Inc 9b's (LLR-173.4).
  - **Shipped surface:** Load (`l`, `#load_path`), the status log.
  - **Acceptance test(s):** AT-B100-12
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid ☒ error — boundary: `..` segments, the work area under another case spelling, the work area itself; invalid: reserved homes and other spellings of them, a relative folder path, a link or junction folder, a folder outside the work area, a folder that is not a project, an unsupported suffix; error: a path that does not exist.
  - **Negative control:** executed on `4fef292` (above) → AT-B100-12 RED.

### HLR-172b — Work-area file names render literally
- **Traceability:** US-162
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.84
- **Statement (EARS ubiquitous):** The system shall show each file name of the Workarea Files list as named on disk, with no markup applied and every control character removed.
- **Decomposition:** LLR-172.4, LLR-172.4a, LLR-172.4b, LLR-172.4c, LLR-172.4d, LLR-172.6, LLR-172.6a.
- **Rationale (informative):** file names are parsed as markup (P-24); the unified dialog needs one work-area lister (ARQ §6).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_recents.py -k "tc_b100_37 or tc_b100_39 or at_b100_13"`
- **Numeric pass threshold:** 4 hostile file names → 4 rows whose plain text equals the name minus control characters, 0 markup spans, 0 control characters.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): the `[bold]x.s19` row paints `Content('x.s19', spans=[Span(0, 5, style='bold')])` → AT-B100-13 RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-13) Files named `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and one with U+009B in the work area appear in the Workarea Files list exactly as named, with no style and no control character.
  - **Shipped surface:** the Workarea Files list (`#files_list`).
  - **Acceptance test(s):** AT-B100-13
  - **Boundary catalog (QC-3):** ☒ empty ☒ invalid ☒ error — empty: an empty temp folder; invalid: markup-shaped names, a control character, a file link; error: a temp folder that is missing or cannot be listed.
  - **Negative control:** executed on `4fef292` (above) → AT-B100-13 RED.

### HLR-173 — One Load dialog lists everything that can be loaded
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.36, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.88
- **Statement (EARS event):** When the engineer opens Load, the system shall show one dialog that holds a typed-path field, one list of this work area's projects, the work-area files and the recent sources, and a preview pane of the highlighted row.
- **Decomposition:**
  - LLR-173.1, LLR-173.1e, LLR-173.1g: the dialog's one result and its one router.
  - LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.2c, LLR-173.2d, LLR-173.2e, LLR-173.2j: opening, focus, keys, clicks.
  - LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.3d: literal names.
  - LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4l, LLR-173.4m: the sections.
  - LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n: the preview's content and the layout.
  - LLR-173.7: no internal decision id in the painted text.
  - The compound HLR-173 (about 20 behaviours) is split here into HLR-173 and HLR-173a … HLR-173e (LED .NN).
- **Variant slots (filled by the P-A verdict C, LED-2026-10-26-batch-100.2; corrected by LED-2026-10-26-batch-100.18):**
  - VS-PA-1 = two panes, preview on the right; stacked below 100 columns.
  - VS-PA-2 = a click selects; Enter loads; a double-click is not bound.
  - VS-PA-3 = the `pa_C` ids (`#load_dialog`, `#load_list`, `#load_path`, `#load_preview`, `#load_reason`, `#load_ok`, `#load_cancel`); `#project_list` and the separate Load project dialog retire.
  - VS-PA-4 = `l` and `ctrl+l` open this dialog with the focus on the path field; `p` opens it with the focus on `#load_list` and the open project's row highlighted, else the first project.
  - VS-PA-5 = the preview marks the active set with `●` for project, file and work-area rows; a recent row shows its path and kind and "checked when loaded" instead of a mark, because nothing is read before Enter.
  - VS-PA-6 = the focus order of LLR-173.2c.
- **Rationale (informative):**
  - The dialog has no list, ignores `escape`, and an empty or Enter-only Load does nothing (P-18 … P-20).
  - The operator's P-A note asks for the active-set symbol.
  - Review sources: UX-05 / QA R2-06 (focus), UX-36 (marks for every row kind), UX-37 (`p`), security R2-03 (the preview reads no image and follows no link).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_41 or tc_b100_42 or tc_b100_43 or tc_b100_64 or tc_b100_66 or at_b100_14"`
- **Numeric pass threshold:** The fixture holds 2 projects, a reserved folder, a junction folder, 2 loadable work-area files and 3 recent entries. Opening Load gives 1 dialog on the screen stack, 3 sections in the order projects, work-area files, recent sources, and 2 + 2 + 3 rows.
  - A project named `[b]P` → 1 row whose plain text is `[b]P`, with 0 markup spans.
  - At 99 columns → panes stacked; at 118 → side by side.
- **Negative control:** executed on `1d677ba` (P-20): `dialog has a list/picker widget? none`. `LoadFileScreen` is unchanged at `4fef292` and in the 9a tree (code read) → AT-B100-14's list half is RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, list half) the engineer opens Load. The dialog lists the work area's projects, its loadable work-area files and the recent sources, each in its own section, and a project named `[b]P` is listed exactly as written.
  - **Shipped surface:** the Load dialog (`l`, `ctrl+l`, `p`; `#load_list`, `#load_preview`).
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid
    - empty: no project, no file and no recent (each section paints its tokens);
    - boundary: one item per section; 99 and 100 columns;
    - invalid: hostile names, a hostile store.
  - **Negative control:** executed on `1d677ba` (P-20, above) → AT-B100-14 RED.

### HLR-173a — The preview marks the set a load installs
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall mark with `●`, in the Load dialog's preview, exactly the image variant, MAC and A2L files that loading the highlighted project or work-area file installs.
- **Decomposition:** LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.4n.
- **Rationale (informative):** the operator's P-A note ("the symbol for the set that will be used as the active files"); UX-36.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_64 or at_b100_14"`
- **Numeric pass threshold:** 4 projects (clean; after a save-back, so the recorded active variant is not first by name; recorded active variant missing; A2L-only), plus 1 file row with nothing loaded, 1 file row with an A2L loaded, and 1 file row with project P open. After Enter, the image, MAC and A2L paths the Loaded panel names equal the `●` rows (7 of 7).
- **Negative control:** a mutation that marks the first variant by name → the save-back project's `●` differs from the installed variant → RED. On the 9a tree no preview exists (P-20) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, preview half) the engineer highlights a project saved after a save-back. The preview marks `●` on its active image, MAC and A2L, and after Enter the Loaded panel names exactly those three.
  - **Shipped surface:** the Load dialog (`#load_list`, `#load_preview`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: recorded variant missing; A2L-only project; a project open while a file row is highlighted;
    - error: the marked variant is unreadable at install (LLR-173.6a).
  - **Negative control:** as above → AT-B100-14 RED.

### HLR-173b — A recent source reopens from the dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer loads a recent row of the Load dialog, the system shall load the file at that row's recorded path.
- **Decomposition:** LLR-173.1f, LLR-173.4h, LLR-173.4i, LLR-173.4j, LLR-173.4k.
- **Rationale (informative):** the consume half of AT-B100-12's chain (9a recorded the source; 9b reopens it). A recent entry may name a network or removable drive, so nothing touches it before Enter (S-07; §6 "Known gap").
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_43 or at_b100_14"`
- **Numeric pass threshold:** the engineer loads `examples/case_01_basic_valid/firmware.s19` by its absolute path, a new app instance starts with the same `LOCALAPPDATA`, Load opens, and Enter on that recent row → `current_file` holds a work copy whose bytes equal the example's (1 of 1), and the store's first entry is that path.
- **Negative control:** on the 9a tree, `LoadFileScreen` has no list, so no recent row can be picked (P-20, code read) → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, recent half) the engineer loads an example through Load (which records it), restarts the app, opens Load, moves to the recent source and presses Enter: that file loads.
  - **Shipped surface:** the Load dialog (`#load_list`, `#load_reason`), the per-user store, the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: a recent A2L (routed by kind);
    - error: a recent source missing on pick (`not found`, `check the path`; the entry stays, LLR-173.4k).
  - **Negative control:** as above → AT-B100-14 RED.

### HLR-173c — Enter loads what has the focus
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer asks the Load dialog to load, the system shall load the highlighted row if `#load_list` held the focus more recently than `#load_path`, and the typed path otherwise.
- **Decomposition:** LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.2f, LLR-173.2g.
- **Rationale (informative):** P-19: Enter with a typed path loads nothing today. VS-PA-2: Enter loads and a click only selects. "Asks to load" means `enter`, `alt+l` or `#load_ok`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_40 or tc_b100_41"`
- **Numeric pass threshold:** each of the three triggers, from list focus on a project, a work-area file and a recent row → 9 loads of the highlighted item; from path focus with a typed valid file path → 3 loads of the typed file (12 of 12).
- **Negative control:** executed on `1d677ba` (P-19): `Enter with a typed path -> current_file before/after: firmware_1.s19 / firmware_1.s19` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, Enter half) the engineer highlights a project and presses Enter: the project loads. They open Load again, type a file path and press Enter: the file loads.
  - **Shipped surface:** the Load dialog (`enter`, `alt+l`, `#load_ok`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary — the focus on the preview or on a button when the request comes (the last of list / path decides).
  - **Negative control:** executed on `1d677ba` (P-19, above) → RED.

### HLR-173d — An empty or refused Load is explained inside the dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load while nothing is highlighted and nothing is typed, or while the typed path is refused, then the system shall keep the dialog open with the typed text unchanged and paint the reason and the next step in `#load_reason`.
- **Decomposition:** LLR-173.2h, LLR-173.2i, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e.
- **Rationale (informative):** CW-U-13 (P-19: an empty Load says nothing). UX-06: a refused path is explained where it was typed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_41 or tc_b100_63 or at_b100_14"`
- **Numeric pass threshold:** an empty Load plus the 6 typed refusal reasons → 7 token pairs in `#load_reason`, 0 dismisses, the field text unchanged (7 of 7).
- **Negative control:** executed on `1d677ba` (P-19): `empty Load click -> … new status: [] | new notices: []` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, empty half) an empty Load paints `nothing selected` and `pick a row or type a path`, and the dialog stays.
  - **Shipped surface:** the Load dialog (`#load_reason`, `#load_path`).
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ invalid ☒ error
    - empty: no row and no text; spaces only;
    - invalid: an unsupported suffix, a relative folder, a non-project folder, an outside folder, a link;
    - error: a missing path, an unreadable folder.
  - **Negative control:** executed on `1d677ba` (P-19, above) → RED.

### HLR-173e — `escape` closes the dialog and changes nothing
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `escape` in the Load dialog, the system shall close the dialog and leave the session unchanged.
- **Decomposition:** LLR-173.2k, LLR-173.2l. The focus after the close is LLR-166.1 (TC-B100-12, Inc 9b arms).
- **Rationale (informative):** CW-U-12 (P-18).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py -k "tc_b100_41 or at_b100_14"`
- **Numeric pass threshold:** `escape` with the focus on each of `#load_path`, `#load_list`, `#load_preview` and `#load_ok` → 4 closes, the session digest unchanged and the store bytes unchanged (4 of 4).
- **Negative control:** executed on `1d677ba` (P-18): `escape on LoadFileScreen -> screen: LoadFileScreen` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-14, escape half) `escape` closes the dialog with the session unchanged.
  - **Shipped surface:** the Load dialog, the screen stack, the Loaded panel.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ boundary — `escape` from each focus position; `escape` after a refused path was painted.
  - **Negative control:** executed on `1d677ba` (P-18, above) → RED.

### HLR-174 — One question before an image-replacing route replaces unsaved work
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.89, LED-2026-10-26-batch-100.91
- **Statement (EARS event):** When an image-replacing route requests a load while unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load), the system shall ask the engineer one question before the load changes the session.
- **Decomposition:**
  - LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c: when the guard asks (the 24-cell table) and the public reader of the Patch Editor flag.
  - LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2j, LLR-174.2r, LLR-174.2s, LLR-174.2t: the modal, its focus, its keys, its layout, and the two unwanted-behaviour guards (a second answer; the Patch Editor's change-file dropdown).
  - LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d: the question comes before the project-session reset, never inside the project-load handler, and a cancelled variant switch leaves the pending selection unchanged.
  - LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c: one load seam for every route, one question per request, the load kind of each route.
  - The compound HLR-174 (about 12 behaviours, 8 normative clauses) is split here into HLR-174 and HLR-174a … HLR-174d (LED .89).
- **Variant slots (filled by the P-B verdict A, LED-2026-10-26-batch-100.2):** VS-PB-1 = the short question. VS-PB-2 = no "save first" key. VS-PB-3 = the `pb_A` ids (`#confirm_yes`, `#confirm_no`).
- **Rationale (informative):**
  - A load over a patched image asks nothing (P-17 on `1d677ba`; this E1's probe on the 9a tree: the Workarea pick, the Load dialog router and the variant switch each replace a patched image with the stack `['Screen']`).
  - Review sources: UX-01, UX-11, QA-03, UX-12, O-3. B-02 / QA R2-03: the Workarea pick and the variant switch bypassed the dialog's route (P-42).
  - The operator's P-B note: "Pregunta corta, hace el trabajo y crea menos dependencias."
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_question.py -k "tc_b100_44 or tc_b100_45 or tc_b100_72 or at_b100_15"`
- **Numeric pass threshold:**
  - With an unsaved patch (D), by keys: the Load dialog with a typed data file, a Workarea Files pick of a data file, and `v` to another variant → 3 questions, 1 per request, each pushed before the image changes (the session digest read when the question is on top equals the digest before the request).
  - The Load-result panel's `v` with D forced through a private call (declared: by keys the panel opens only right after a project load, which records the image as saved) → 1 question.
  - 4 of 4.
- **Negative control:** executed on `1d677ba` (P-17): `Load file over patched image -> stack: ['Screen'] … image still patched? False`. Executed on the 9a tree (this E1, `work/probe_p10.out.txt`): `WORKAREA pick over patch: stack ['Screen'] | … patched image kept = False`; `LOAD DIALOG router over patch: stack ['Screen']`; `VARIANT switch over patch: stack ['Screen']` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, question half) the engineer adds and applies a patch in the Patch Editor and loads another data file through Load. A question appears naming the patched image, with the focus on Cancel. A Workarea Files pick of a data file, and `v` in a project, ask the same question.
  - **Shipped surface:** Load (`l`, `#load_path`), the Workarea Files list, `v`, the question (`#confirm_yes`, `#confirm_no`).
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — the three key-reachable routes; the panel's `v` (TC arm, forced state).
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174a — A load that would replace or move no unsaved work does not ask
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When an image-replacing route requests a load and no unsaved work it would replace or move to another project exists (D for an image replacement; D, W or F for a project load), the system shall load without the question.
- **Decomposition:** LLR-174.1, LLR-174.1a, LLR-174.1b (the cells that load).
- **Rationale (informative):** QA R2-02 (an attach loses nothing); UX-27 (Save project clears the document flag, LLR-167.8). The `pb_A` prototype asked whenever a project was open; HLR-174's approved text overrides it ("whether or not a project is open"), and this split keeps that.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_question.py -k "tc_b100_44 or at_b100_15"`
- **Numeric pass threshold:** 0 questions in each of these 7 scenes:
  - nothing unsaved, no project open, data load;
  - nothing unsaved, project P open, project load of Q;
  - patched → Save project → data load;
  - patched + 1 Patch Editor entry → Save project → project load;
  - patched → save-back → data load;
  - an unsaved patch, then an A2L load (the patched byte kept);
  - an unsaved patch, then a MAC load (the patched byte kept).
  - 7 of 7.
- **Negative control:** the `pb_A` prototype rule ("ask when a project is open", `_pb_common.install`) → the scene with P open asks → RED. A mutation asking on an attach when D → the A2L and MAC scenes ask → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, after-save half) after Save project, the same load that asked before asks nothing and loads.
  - **Shipped surface:** Load, Save project, the status log.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary
    - empty: nothing unsaved, with and without a project open;
    - boundary: a patch that writes the bytes already there; undo alone asks (C13); undo then Apply does not (C12); an A2L or MAC attach.
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174b — Replace continues the load
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer answers the question with replace, the system shall run the load that asked.
- **Decomposition:** LLR-174.2c, LLR-174.2e, LLR-174.2f, LLR-174.3.
- **Rationale (informative):** VS-PB-1; `y` replaces.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_question.py -k "tc_b100_45 or tc_b100_72 or at_b100_15"`
- **Numeric pass threshold:** `y` on each of the 4 routes → 1 load of the requested item each (`current_file.path.name` or `current_project` equals the request), and the question closed (4 of 4).
- **Negative control:** a mutation that dismisses the question and drops `go` → 0 loads → RED. On the 9a tree there is no question (probe above) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, replace half) the engineer repeats the load and presses `y`: the new file loads.
  - **Shipped surface:** the question (`y`), the Loaded panel.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — `y` with the focus on either button; a click on `#confirm_yes`.
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174c — Cancel keeps everything
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer cancels the question, the system shall leave the session and the kept work unchanged.
- **Decomposition:** LLR-174.2b, LLR-174.2d, LLR-174.2e, LLR-174.3a. The focus after the close is LLR-166.1 (TC-B100-12, Inc 10 arm).
- **Rationale (informative):** "Cancel" means `n`, `escape`, `enter` on the initial focus, or a click on `#confirm_no`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_question.py -k "tc_b100_45 or at_b100_15"`
- **Numeric pass threshold:** a project load with D, F and W, and a data load with D; each cancelled by `n`, `escape` and an immediate `enter` → the session digest and the kept work unchanged, 0 status lines (6 of 6).
- **Negative control:** a mutation focusing `#confirm_yes` first → the immediate `enter` replaces → RED. On the 9a tree the load runs with no question (probe above) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, keep half) at the question the engineer presses `enter`: the patched image stays, and the hex view still shows the patched byte.
  - **Shipped surface:** the question (`n`, `escape`, `enter`), the hex view, the Loaded panel.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — each cancel key; a typed path whose recent entry would be recorded (the store unchanged).
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-174d — The question names every unsaved item
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall name in one question every unsaved item that made the guard ask.
- **Decomposition:** LLR-174.2i, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q.
- **Rationale (informative):** "name what would be lost, all items in one question" (HLR-174 as approved). The Flow Builder item is named as holding unsaved changes; whether a project load clears it is ruling Q1.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_question.py -k "tc_b100_45 or at_b100_15"`
- **Numeric pass threshold:** a project load with D, F and W → 1 question whose painted text holds the image file name, `Patch Editor entries` and `flow <name>` (3 items, 1 modal); D and F only → 2 items; W only → 1 item (3 of 3).
- **Negative control:** a mutation naming only the first unsaved item → the 3-item arm finds 1 → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-15, items half) with a patched image and unsaved Flow Builder edits, the engineer opens a project: one question names both.
  - **Shipped surface:** the question.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ boundary — 1, 2 and 3 items.
  - **Negative control:** as above → AT-B100-15 RED.

### HLR-175 — The Save project dialog shows exactly what the save will do
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.31, LED-2026-10-26-batch-100.37, LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.94
- **Statement (EARS state):** While the Save project dialog is open, the system shall paint in `#save_summary` the plan for the typed name at the plan's granularity, with the target folder and its kind in `#save_where`.
- **Decomposition:**
  - LLR-175.1: the target line (sanitised folder, kind).
  - LLR-175.4, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.4j: the summary's rows, the image line, the pending line, the links row, the merge's active-variant row, literal names, one line per row.
  - LLR-175.5, LLR-175.5a: what is computed once per open and what per name.
  - The compound HLR-175 (about 20 behaviours, 11 normative clauses) is split here into HLR-175 and HLR-175a … HLR-175f (LED-2026-10-26-batch-100.92).
- **Variant slots (filled by the P-C verdict B, LED-2026-10-26-batch-100.2):** VS-PC-1 = the name plus the "what will be saved" summary, at the row granularity of LLR-175.4. VS-PC-2 = during a refusal, Save stays focusable and refuses with the reason painted (LLR-175.3f). VS-PC-3 = the `pc_B` ids (`#project_name`, `#save_summary`, `#save_where`, `#save_ok`, `#save_cancel`).
- **Rationale (informative):** the base dialog paints nothing before Save (P-19; P11-2: `typed 'a b' -> dialog text has 'ab' folder line? False`). The operator's P-C note: "Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información." — hence R-PC: one plan, painted and executed. M-4 ("show the sanitised name before saving"). UX-32 / QA R2-05 (granularity), UX-35 (merge row).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_47 or tc_b100_65 or at_b100_16 or at_b100_21"`
- **Numeric pass threshold:**
  - 7 scenarios (fresh, pending patch, refused, `files`, document, merge, save-as; §5.3) → for each, the painted rows equal the painted plan's rows, by landing name and action word, at 220 columns (0 differences, 7 of 7).
  - `a b` in F-fresh → `#save_where` names the folder `ab` and the kind `new folder` (1).
- **Negative control:** executed on the 9a tree (P11-2): `widgets … #save_summary: 0 #save_where: 0`; `typed 'a b' -> dialog text has 'ab' folder line? False` → AT-B100-16's folder half and AT-B100-21's painted half RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, folder half) the engineer opens Save project, types `a b` and sees `ab` as the folder, a new folder. (AT-B100-21, painted half) for each of the 7 scenarios, each painted row that is not cut at 220 columns matches its plan row by landing name and action. (AT-B100-09 re-pin) before saving P as Q, the summary lists `flows/`, `patches/` and `reports/`, 1 file each.
  - **Shipped surface:** the Save project dialog (`ctrl+s`, `#project_name`, `#save_where`, `#save_summary`; the plan through `SaveProjectScreen.plan`, the exception declared in the §3 preface).
  - **Acceptance test(s):** AT-B100-16, AT-B100-21
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid
    - empty: an empty name (no target line, no rows); an A2L-only session (no image row);
    - boundary: a 64- and a 65-character name; a target that holds the image's name; a 300-row plan;
    - invalid: hostile names on disk.
  - **Negative control:** as above → AT-B100-16 and AT-B100-21 RED.

### HLR-175a — Save writes exactly the plan the dialog painted
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer confirms Save in the Save project dialog, the system shall write exactly the files the painted plan's rows name; the active CRC template and the batch and assignment documents are copied outside the plan and are not named by its rows.
- **Decomposition:** LLR-175.3c, LLR-175.4a, LLR-175.4b, LLR-175.4k, LLR-175.4l.
- **Rationale (informative):** R-PC; the operator's P-C note. Without LLR-175.4b, a Save pressed within the 150 ms recompute window (LLR-175.5a) would save a plan nobody saw.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_65 or at_b100_21"`
- **Numeric pass threshold:** for the 7 scenarios, `alt+s` by key; then the plan read from `SaveProjectScreen.plan` equals the work-area tree written, at the plan's granularity, by full path and action (0 differences, 7 of 7); the refused scenario → 0 new paths in the work-area listing. The AT-B100-21 oracle excludes the gather homes (the active CRC template and the batch and assignment documents) by name.
- **Negative control:** a mutation where the handler places a file the plan did not name (for example, it re-plans without the document row) → 1 tree row without a plan row → RED. On the 9a tree the dialog holds no plan (code read: `SaveProjectScreen` has no `plan`) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-21, executed half) for each of the 7 scenarios, the engineer presses `alt+s`; the test then reads the dialog's plan (never calling the planner or driving the save through it) and finds its rows equal to the tree on disk.
  - **Shipped surface:** the Save project dialog (`alt+s`), `SaveProjectScreen.plan`, the work area on disk.
  - **Acceptance test(s):** AT-B100-21
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: `alt+s` pressed within 150 ms of the last keystroke (LLR-175.4b); a file appearing in the target after the paint;
    - error: a refused save (0 files).
  - **Negative control:** as above → AT-B100-21 RED.

### HLR-175b — A refused name is explained in the dialog before Save
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the save for the typed name would be refused, then the system shall paint the refusal's reason token and next-step token in the Save project dialog before Save is confirmed.
- **Decomposition:** LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1o, LLR-175.1p, LLR-175.3f, LLR-175.6.
- **Rationale (informative):** O-9 ("Inc 11's dialog shows the clash before Save"); M-4; HLR-164 refusals were painted only after the dialog closed.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_47 or tc_b100_49 or at_b100_16"`, plus the AT-B100-02 re-pin `pytest tests/test_b100_save_guards.py -k at_b100_02`
- **Numeric pass threshold:** the 9 name refusals (reserved, device, disguised clash, over 64, path too long, link target, unreadable target, no usable character, a case-folded folder that is not the open project) and the 6 save refusals (plan refusal, free space, missing source, unreadable source, blocked entries, an unreadable work area) → 15 token pairs painted in the dialog with the dialog open and 0 new paths in the work-area listing (15 of 15; platform arms counted, §3 preface).
- **Negative control:** executed on the 9a tree (P11-2): `typed 'Reports' -> dialog text has 'reserved name'? False` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, clash half) with project `ab` saved and another project open, the engineer types `a b` and sees `already a project` and `choose another name` before pressing Save. (AT-B100-02 re-pin) `Reports`, `CON` and a 300-character name each paint their token pair in the dialog; `alt+s` keeps the dialog open; no folder appears.
  - **Shipped surface:** the Save project dialog (`#project_name`, `#save_where`, `alt+s`), the work area on disk.
  - **Acceptance test(s):** AT-B100-16, AT-B100-02
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid ☒ error
    - boundary: 64 / 65 characters; the full-path limit met and exceeded by 1;
    - invalid: reserved and device names in mixed case, `con.txt`, `LPT¹`, a disguised clash, a junction target;
    - error: a source deleted after the load; a blocked document entry.
  - **Negative control:** as above → AT-B100-16 RED.

### HLR-175c — `escape` closes the dialog and saves nothing
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer presses `escape` in the Save project dialog, the system shall close the dialog and save nothing.
- **Decomposition:** LLR-175.3, LLR-175.3a.
- **Rationale (informative):** CW-U-12 (P-18).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** `escape` with the focus on each of `#project_name`, `#save_summary`, `#save_ok` and `#save_cancel`, with a valid name typed → 4 closes, the work-area listing and the session digest unchanged (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `escape -> stack: ['Screen', 'SaveProjectScreen']`; and on `1d677ba` (P-18) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, escape half) after typing a valid name, `escape` closes the dialog and no folder appears.
  - **Shipped surface:** the Save project dialog, the screen stack, the work area on disk.
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ boundary — `escape` from each focus position; `escape` after a refusal was painted.
  - **Negative control:** as above → RED.

### HLR-175d — An empty Save is explained in the dialog
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the engineer confirms Save while the name field holds no character other than spaces, then the system shall keep the dialog open and paint `name is empty` and `type a project name`.
- **Decomposition:** LLR-175.3b.
- **Rationale (informative):** CW-U-13 (P-19: an empty Save says nothing).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** an empty and an all-space name, each with `alt+s` and with `#save_ok` → 4 token pairs, 0 dismisses, 0 new paths (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `empty Save click -> stack: ['Screen', 'SaveProjectScreen'] | dialog text has 'name is empty'? False`; and on `1d677ba` (P-19) → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, empty half, new) with the name field empty, `alt+s` paints `name is empty` and `type a project name`, and the dialog stays.
  - **Shipped surface:** the Save project dialog (`#project_name`, `#save_where`, `alt+s`).
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ empty — no character; spaces only.
  - **Negative control:** as above → RED.

### HLR-175e — The dialog saves only into this work area
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall save every project named in the Save project dialog as a direct folder of this work area.
- **Decomposition:** LLR-175.2, LLR-175.2a.
- **Rationale (informative):** D7 = `solo_workarea`, the dialog half (the handler half is LLR-171.3). P-11.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k tc_b100_48`, plus the AT-B100-02 re-pin
- **Numeric pass threshold:** 0 widgets `#project_parent_path` and 0 `#save_browse` in the dialog; a save through the dialog → the new folder's parent equals `self.workarea` (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `widgets #project_parent_path: 1 #save_browse: 1` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-02 re-pin) the dialog offers no parent-folder field and no Browse button; a saved project appears in the work area.
  - **Shipped surface:** the Save project dialog, the work area on disk.
  - **Acceptance test(s):** AT-B100-02
  - **Boundary catalog (QC-3):** ☒ boundary — a work area under a long base path.
  - **Negative control:** as above → RED.

### HLR-175f — Save project opens one dialog with the name, the summary and two buttons
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer asks Save project with a data file or an A2L loaded, the system shall open one dialog that holds `#project_name`, `#save_where`, `#save_summary`, `#save_ok` and `#save_cancel`.
- **Decomposition:** LLR-175.3d, LLR-175.3e, LLR-175.3g, LLR-175.3h, LLR-175.3i, LLR-175.3j, LLR-175.4h, LLR-175.4i, LLR-175.5b.
- **Rationale (informative):** VS-PC-3; UX-05 (focus); §3 preface "Keys" (`alt+<letter>` in a modal with a text field). Ruling Q6 of Inc 9b routes the priority-key exposure of this dialog here (LLR-175.3g).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py -k "tc_b100_49 or at_b100_16"`
- **Numeric pass threshold:** `ctrl+s` and the palette entry `save_project`, each with F-fresh → 1 dialog on the screen stack (depth 2) holding the 5 ids, 1 each (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `#save_summary: 0 #save_where: 0` → RED.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-16, open half) `ctrl+s` opens the dialog with the focus in the name field; typing `s` puts `s` in the field.
  - **Shipped surface:** `ctrl+s`, the Save project dialog.
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary
    - empty: nothing loaded (LLR-175.3j);
    - boundary: 118×54 and 220×60; a 300-row plan.
  - **Negative control:** as above → RED.

### HLR-176 — A long action shows a progress line when it begins
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.39, LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.97
- **Statement (EARS event):** When a long action begins, the system shall paint in `#status_text` one progress line that holds a spinner glyph, the action's label, the step `n/m` with the step's name, and the elapsed time.
- **Decomposition:** LLR-176.1, LLR-176.1a, LLR-176.1g, LLR-176.1n, LLR-176.1p, LLR-176.1r, LLR-176.2, LLR-176.2a, LLR-176.2b.
  - The compound HLR-176 (8 obligation clauses, about 14 behaviours) is split into HLR-176 … HLR-176d (LED .95).
  - Its A2L parse callback clause and its main-thread freeze clause move with LLR-176.4 and LLR-176.3 to Inc 12b (ruling Q1).
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-1 = the status line (`#status_text`), with the progress bar kept working. VS-PD-2 = no cancel.
- **Rationale (informative):** N5. The operator's P-D note: "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso." The `pd_A` prototype paints `⠋ Loading <name>  ·  step 1/3 <step>  ·  00:03`. UX-29 / B-11: one owner of `#status_text`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or tc_b100_51 or at_b100_17"`
- **Numeric pass threshold:** each of the 4 actions that run a worker today (file load, report, diff report, before/after) → the first `#status_text` text after the begin matches `^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] .+  ·  step 1/[1-9] .+  ·  00:0[0-9]$` (4 of 4).
- **Negative control:** executed P12a-2 on `8947666`: across a file load, `#status_text` takes only `Ready.` and `Loaded firmware.s19 (S19 only)`, with no glyph and no step → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-17, 12a half) the engineer loads a generated S19 holding 8 MiB of data by `l`, a typed path and Enter. While it parses, `#status_text` shows a spinner, `Loading <name>`, the step and an elapsed time that advances at least once. At the end, the status log names the file loaded, `#status_text` shows the file state, and the bar is empty.
  - **Shipped surface:** Load (`l`), `#status_text`, `#progress_bar`, the status log.
  - **Acceptance test(s):** AT-B100-17
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error
    - boundary: an action shorter than one timer tick (shown, then cleared);
    - error: a load that fails (the indicator ends with `Load failed`);
    - empty / invalid: N/A, no input.
  - **Negative control:** as above → AT-B100-17 (12a half) RED.

### HLR-176a — The spinner and the elapsed time advance while a worker runs
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS state):** While a long action runs its worker, the system shall advance the spinner glyph and the elapsed time of the progress line.
- **Decomposition:** LLR-176.1e, LLR-176.1f, LLR-176.1g, LLR-176.1q.
- **Rationale (informative):** "so that I do not think the app froze" (US-166). Declared limit at 12a: the three main-thread actions (A2L load, project load, Save project) block the event loop, so nothing advances between their begin and end; Inc 12b moves them to workers (HLR-177).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or at_b100_17"`
- **Numeric pass threshold:**
  - The 8 MiB-data S19 load (P12a-3: 2.38 s of parse) → before the end, the elapsed text changes at least 1 time and the glyph takes at least 5 distinct values (2 assertions).
  - A synthetic worker action of 1.2 s → the same 2 assertions.
- **Negative control:** executed P12a-2: `set_interval(` occurs 0 times in `app.py`, so no clock can repaint → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half), as HLR-176.

### HLR-176b — The bar moves within a step that reports its progress
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a running step reports how much of its work is done, the system shall advance the progress bar within that step.
- **Decomposition:** LLR-176.1b, LLR-176.1c, LLR-176.1d.
- **Rationale (informative):** the operator's condition, "asumiendo que la barra de progreso realmente hace su trabajo" (UX-30, R-PD). At 12a no shipped action reports a done-of-total amount; the seam carries it, and the first shipped reporter is the A2L parse callback at Inc 12b (LLR-176.4). The old HLR named "bytes copied, read or parsed"; copy and read have no callback inside the 12a+12b files (ruling Q5).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a synthetic worker action of 2 steps whose step 2 reports 1, 2, 3 and 4 MiB of 4 MiB → the bar reads 50, 62, 75, 87 within step 2, rising 4 times, never falling (4 of 4).
- **Negative control:** executed P12a-1: every bar value at `8947666` is a constant (0, 10, 15, 50, 55, 100), and no call carries a done-of-total amount → RED. A mutation that sets the bar from the step index only → the 4 within-step values stay at 50 → RED.
- **Priority:** medium
- **Acceptance (black-box):** none at 12a; the AT arm "the bar rises at least 2 times during the A2L parse" is AT-B100-17's 12b half.

### HLR-176c — The end of a long action removes the indicator and shows the outcome
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a long action ends, by success, failure or exception, the system shall replace its progress indicator with the action's outcome.
- **Decomposition:** LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1l, LLR-176.1m, LLR-176.1o, LLR-176.1s, LLR-176.2c, LLR-176.2d.
- **Rationale (informative):** the old text said "never left at a stale `100%`" and "one final writer … paint[s], in this order, the outcome, then the project and file line, then the file state". `#status_text` is one row, so three paints in order leave only the last; that contradicted HLR-176's own threshold and LLR-178.2 (the project and file line stays). The order is replaced by a precedence (LLR-176.1j, ruling Q4).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k "tc_b100_50 or tc_b100_51 or at_b100_17"`
- **Numeric pass threshold:** each of the 7 long actions, on its success exit and on its failure exit (14 arms) → after the end, `#status_text` holds no glyph, the bar is cleared, the status log's last line is the outcome, and 0 timers run.
- **Negative control:** executed P12a-2: after a successful load the bar stays at 100 → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half): at the end the status log names the file loaded and the bar is empty.

### HLR-176d — `#status_text` has one owner while a long action runs
- **Traceability:** US-166
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS state):** While a long action runs, the system shall keep `#status_text` for the progress line.
- **Decomposition:** LLR-176.1h, LLR-176.1j.
- **Rationale (informative):** UX-29 / B-11. P12a-2 shows the file state painted over the status line while the action still runs (bar at 50).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a worker file load whose install writes the file state before the end → every `#status_text` value between the begin and the end is a progress line (0 other values), and after the end `#status_text` holds the file state (`Loaded <name> (S19 only)`, 1 equality).
- **Negative control:** executed P12a-2: `Loaded firmware.s19 (S19 only)` is painted while the bar is at 50, before the load's last progress call → RED.
- **Priority:** medium
- **Acceptance (black-box):** covered by AT-B100-17 (12a half).

### HLR-177 — Project load, Save project and the A2L parse do their heavy work on worker threads
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall run the reading and parsing of a project load, the writing of Save project and the copy and parse of an A2L attach on worker threads.
- **Decomposition:**
  - LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1k, LLR-177.1c: the three worker steps, the work-area image pick on the existing file-load worker, and the event loop staying free.
  - LLR-177.1d, LLR-177.1e: the session is written only on the main thread, and a worker reads only its request.
  - LLR-177.1f, LLR-177.1g, LLR-177.1h: the project load's result, reset and Load-result panel after the worker.
  - LLR-177.1i, LLR-177.1j: the Save project re-derive before the worker and the adopt after it.
  - LLR-177.2, LLR-177.2a, LLR-177.2b, LLR-177.2c: a worker that raises, and the A2L attach's pre-begin refusals.
  - LLR-177.5, LLR-177.5a, LLR-176.3, LLR-176.4, LLR-176.4a, LLR-176.4b: the 12b actions on 12a's indicator (the parse's byte reports, the save's files placed, the main-thread step painted first, the parser callback and the `a2l.py` re-freeze).
  - The compound HLR-177 (7 obligations: workers, main-thread installs, re-derive, copy, elapsed time, refusal, quit) is split here into HLR-177, HLR-177a, HLR-177b and HLR-177c (LED-2026-10-26-batch-100.98). "Flow runs stay on the main thread" is a scope note (O-7), kept in the Rationale.
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-3 = a second request is refused with a status naming the running action (HLR-177a).
- **Rationale (informative):**
  - These three block the main thread today (ARQ §7). Executed on the base (P12b-4 … P12b-6): the case_06 A2L attach blocks the event loop for 8.76 s, the case_06 project load for 5.81 s, a 0.1 s interval timer ticks 0 times during either; Save project of that project takes 0.12 s.
  - R-PD makes 12b unconditional. O-7 leaves flow runs on the main thread. A-17 keeps the worker off the live image. UX-34 lists the refused set and the quit rule.
  - A thread worker, not an async one: Textual 8.2.8 runs an async worker's coroutine on the event loop (`Worker._run_async` awaits it there), so CPU-bound parsing would still block it.
  - The tag-table build of an attached A2L stays on the main thread; HLR-176 declares that freeze (12a, LLR-176.3). P12b-7 measures the worker share: `parse_a2l_file` takes 5.01 s of the attach's 8.76 s.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or tc_b100_54 or at_b100_18"`
- **Numeric pass threshold:**
  - A project holding the case_06 A2L, data and MAC files, loaded from the Load dialog → the indicator's elapsed text changes ≥ 1 time before the install ends, and the status log then names the project loaded (2 of 2).
  - Each of the three worker steps → the thread that runs it is not the main thread (thread-id probe, 3 of 3).
- **Negative control:** executed on the base (P12b-5): `_handle_load_project('P'): wall 5.81 s; ticks during the call 0; … ran on main thread True` → the elapsed text cannot change during the load → AT-B100-18's worker half RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, worker half) the engineer loads a project holding the case_06 A2L: the elapsed time advances during the load, and the status log then names the project loaded.
  - **Shipped surface:** Load (`p`, `#load_list`, `enter`), `#status_text`, the status log.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error
    - boundary: a project whose worker step ends inside one timer tick (shown and cleared, the result installed);
    - error: a worker that raises (the app keeps running, the indicator ends, the session unchanged; LLR-177.2 … LLR-177.2b).
    - empty / invalid: N/A — the inputs are the existing load and save inputs, whose classes earlier HLRs own.
  - **Negative control:** executed on the base (P12b-5, above) → AT-B100-18 RED.

### HLR-177a — A second request is refused while a session action runs
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks for an action that replaces or changes the image, the change document or the project while a session action runs, then the system shall refuse it with the busy line naming the running action.
- **Decomposition:** LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h, LLR-177.3i.
- **Variant slots:** VS-PD-3 = refuse (P-D verdict A; Q-6 at round 1).
- **Rationale (informative):**
  - Two writers of the session at once are the defect class this removes. An exclusive worker group does not prevent it: Textual 8.2.8 cancels the older `Worker` object, but its thread keeps running and its `call_from_thread` install still lands (P12b-1: `first worker state: CANCELLED | landed: [('second', …), ('first', …)]`). So the refusal is a state check before the action starts.
  - "Changes the change document" widens the approved list (apply, undo) to every Patch Editor change (ruling Q3). Only the four session actions trigger the refusal; reports, diff reports and before/after runs may overlap, as 12a ruling Q3 shows them (ruling Q2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `l`, a Workarea Files pick, `v`, `U`, a save-back, a Patch apply, a Patch undo and `ctrl+s` → 8 busy lines naming Save project, the session digest unchanged after each, the screen stack depth unchanged (8 of 8).
- **Negative control:** code read, base: no busy state exists (`grep -n "begin_busy\|busy" s19_app/tui/app.py` finds no refusal), and Save project runs synchronously (P12b-6), so no key reaches the app during it → AT-B100-18's refusal half RED. Mutation: omitting `v` from the refused set → the image changes during the save → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, refusal half) during a Save project, after the worker step is painted, the engineer presses `l`: the status log paints `busy` naming Save project, and no Load dialog opens.
  - **Shipped surface:** `l`, `ctrl+s`, `v`, `U`, the Workarea Files list, the Patch Editor, the status log.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid
    - boundary: a request in the frame after the session action ends (accepted, LLR-177.3h); a report running alone (no refusal);
    - invalid: each refused request kind (load, variant, unload, save, Patch Editor change).
  - **Negative control:** as above → AT-B100-18 RED.

### HLR-177b — Quit asks first while a session action runs
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.100
- **Statement (EARS event):** When the engineer asks to quit while a session action runs, the system shall ask the quit question before exiting.
- **Decomposition:** LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4d.
- **Rationale (informative):** UX-34. The question reuses the Inc 10 modal with its own texts (C-UX-4, ARCH-PDR-4); the modal starts on its No button (LLR-174.2b).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** `q` during a Save project held at a forced slow step → 1 quit question, the focus on `#confirm_no`, the app running (3 of 3); `q` with no session action → the app exits with 0 questions.
- **Negative control:** code read, base: `S19TuiApp` defines no `action_quit`, so `q` and `ctrl+q` run Textual's `App.action_quit` (`self.exit()`, `textual/app.py:4460`) → 0 questions → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, quit half) during a Save project the engineer presses `q`: a question asks first, with the focus on Stay.
  - **Shipped surface:** `q`, `ctrl+q`, the quit question (`#confirm_yes`, `#confirm_no`).
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary — `q` and `ctrl+q`; no session action running.
  - **Negative control:** as above → AT-B100-18 RED.

### HLR-177c — A confirmed quit leaves no partial save
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the engineer confirms the quit question, the system shall exit only after the running session action has finished or rolled back.
- **Decomposition:** LLR-177.4c, LLR-177.4e.
- **Rationale (informative):** UX-34; backlog row "the 2 000-file save-as runs on the main thread … closing the app mid-copy leaves a partial Q", moved to 12b without its cancel by 12a ruling Q2 (R12's "rollback on close"). Exiting at once is unsafe: after `App.exit()` a thread worker's later `call_from_thread` still runs its callback, on an app that is no longer running (P12b-3: `landed: [('late', …)] | … app running: False`). A confirmed quit is withdrawn when a successful Save leaves in-memory work unsaved (LLR-177.4e, SE5-12b-1).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** a Save project held at a forced slow step, `q`, `y` → the app still running while the step is held (1 check); the step released → the app exits, and the target folder is either complete (its `project.json` verifies) or absent (0 partial folders); the same with the held step forced to raise → the app **keeps running**, the folder is absent, the failure line is `log_lines[-1]` and the failure toast is shown, and the entries are kept (2 of 2).
- **Negative control:** a mutation that exits at once on `y` → the app stops while the step is held → RED. Executed P12b-3 shows why the arm is needed (the worker's callback runs on a stopped app).
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, quit-confirm half) during a slow save-as the engineer presses `q`, then `y`: the app stays until the save ends, then exits, and the work area holds no partial project folder.
  - **Shipped surface:** `q`, the quit question, the work area on disk.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: the action ends in the frame `y` is pressed;
    - error: the worker step raises after `y` (rolled back; the app keeps running, the failure line is `log_lines[-1]` and the failure toast is shown, and the entries are kept).
  - **Negative control:** as above → AT-B100-18 RED.

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

> Ids `LLR-<HLR>.<M>`. TC ids are `TC-B100-NN`. Each LLR's mutation (Negative control) is run at Phase 3 (C-40) and described by position and operation, never pasted (C-56). Symbols marked NEW are created in Phase 3. Round 2 added LLR-163.6, LLR-167.5, LLR-167.6, LLR-169.8, LLR-169.9, LLR-171.4, LLR-173.5, LLR-173.6, LLR-175.4 and LLR-178.3 (and LLR-173.7); round 3 added LLR-163.7, LLR-167.7, LLR-167.8, LLR-168.4 and LLR-174.4; the PDR added LLR-176.4; no requirement was retired.

### LLR-163.1 — One placement function holds every guard and decides reuse
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.9, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.44, LED-2026-10-26-batch-100.49, LED-2026-10-26-batch-100.50
- **Statement:** `find_identical(destination, name, staged)` (NEW, `workspace.py`) shall enumerate the reuse candidates from a listing of the destination — `<name>` and every `<stem>_<digits><suffix>`, compared case-insensitively on Windows — and return the first that is a regular file, not a link or reparse point, non-empty, of the staged size and byte-identical. `place_into_workarea(source, destination, …) -> PlacementResult(path, reused)` (NEW, `workspace.py`) shall hold every guard `copy_into_workarea` holds today — the source and destination reparse checks, the size cap, private staging — plus containment in this work area (`contained_in_workarea`, LLR-171.4). The work-area root is taken from the destination **as the caller gave it, before any resolution**: either the nearest `.s19tool/workarea` ancestor of the unresolved path, or the root an app-level caller passes explicitly. Only then are the root and the destination resolved and compared, so a junction or link anywhere in the destination is caught. Callers pass the unresolved destination. It shall reuse the identical file or claim the lowest free `_<N>`. `place_group_into_workarea` (the BIN + `.addr` group, B99-I2a) is the second placement kind: it keeps its own frozen reuse rule (R30) but passes through the same destination guard. Both take a `workarea_root` keyword. Every placement call in `app.py` passes `workarea_root=self.workarea`, and the app keeps its project paths unresolved under the work area. Without a root, the guard's reparse walk runs to the OUTERMOST `.s19tool/workarea` anchor of the unresolved destination (LED .50). `copy_into_workarea` (`workspace.py:402`) shall be `return place_into_workarea(...).path`, with no second claim loop, so its 15 call sites in 7 files (P-34) are unchanged; this widens B100-I6.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-01 — `pytest tests/test_b100_reuse.py -k tc_b100_01`
- **Numeric pass threshold:** the S7 sequence (case_01, case_02, case_02, case_01, case_02) → names `firmware.s19`, `firmware_1.s19`, `firmware_1.s19`, `firmware.s19`, `firmware_1.s19` with `reused` False, False, True, True, True; 2 files in the destination; `copy_into_workarea` returns a `Path` (1 type assertion); `place_into_workarea` called directly with a destination outside every work area, through a junction, and with a source over the cap → 3 refusals, 0 bytes written; an AST check → 1 claim loop per placement kind in `workspace.py` (2: single file, group); a junction under the destination, given unresolved to the export, to `place_group_into_workarea` and to Save project's gather → 3 refusals, 0 bytes written.
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.22, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.52, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.74, LED-2026-10-26-batch-100.75
- **Statement:** `_handle_save_dialog` shall decide by Q-2. A project is a direct child of this work area holding a `project.json` or a data file, not a reserved home and not a link. (a) A disguised clash — the sanitised name equals a project's folder name compared case-folded while the typed name differs from it — shall be refused before writing, with the `already a project` and `choose another name` tokens naming both names. (b) A name equal to a project that is not open shall merge: it keeps the target's other keys and variants, adds the new files as variants (LLR-005.1), rewrites `project.json` through the seam carrying every key it does not own (the LLR-168.3 rule), and sets `active_variant` per D2; sub-folders and the target's document file are untouched (a session document is placed beside it and recorded, HLR-170); if the merge fails, the files it placed are removed and listed in the status. (c) A name equal to the open project, typed exactly or as its unsanitised form, shall save into the open project. A target folder that is a link or junction is refused before `resolve()` with the `link or junction` tokens. The completed save's status shall name the folder written.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-05 — `pytest tests/test_b100_save_guards.py -k tc_b100_05`
- **Numeric pass threshold:** `ab` existing and not open, `a b` typed → 1 refusal naming both, `ab/` with 0 changed digests; `AB` typed → 1 refusal (case-only); `ab` typed → merge, 1 variant added; the carried keys: `batch`, `assignments`, `declared_regions` from Inc 2, `gathered` from Inc 6, `active_document` from Inc 8a (0 changed at each; at Inc 8a `gathered` = the target's entries plus the rows this save's gather adds, 0 target entries dropped, and `active_document` is carried unchanged, unless Save project drops it as below, when the session holds no document with an entry or its document was not placed (a failed write, a gather refusal, a file-backed document inside the project but outside its home or whose source is gone or a link, or a landing outside the form counts as no session document: the target's value is carried, plus the one status line about the document; E3 R3, R11), and names the session's placed document when it holds one, with the target's document file 0 bytes changed; a Save project into an open project or a merge classifies a carried `active_document` with LLR-170.3's one classifier and drops it when its file is absent, a link, or present but not readable as a change or check document (`missing`, `link`, `unreadable`: not parsing, `RecursionError` included, a v1 file, bad structure or metadata) and paints 1 status line naming it, which is the "Save project to drop it" recovery of the `missing` and `not readable` rows (E3 R2, R8 refined); it keeps the record when the file is over the reopen caps or cannot be read now (`too_large`, `io_error`; 1 status line for `io_error`), so the app's own large document or a locked file is never dropped: a pasted document with 1 500 entries → Save project `P` → Load `P` (1 `not readable`, "too large to reopen") → Save project `P` with no session document → `active_document` kept, the file on disk; a merge into a never-loaded target recording a 20 000-entry document → Save project under 1 s, the document not parsed, the record kept (E3 R10); a refused `active_document` in the target manifest is a skipped entry, so Save project keeps `project.json.previous-<UTC>` and the status names the copy and the dropped value; E3 R5); `a b` typed while `ab` is open → saved into `ab`; a forced `OSError` mid-merge → the target's file set and `project.json` unchanged; a junction `evil` typed → refused, 0 bytes written; `tests/test_tui_variants.py::test_save_second_s19_into_project_appends_variant` → passed.
- **Negative control:** executed on `1d677ba` (P-10): `'a b' -> project='ab'` saved silently → RED; a mutation passing the session's `batch` in the merge → the carried-key arm RED; a mutation passing the session's `active_document` (`None`) in a merge with no session document → the target's key dropped → RED (Inc 8a); a mutation carrying an absent-file `active_document` → the next Load lists the same `missing` row → RED (R2); a mutation carrying a not-readable (`unreadable`, for example `{`) `active_document` → the next Load lists the same `not readable` row → RED (R8); a mutation dropping a `too_large` value → the 1 500-entry record is lost → RED (R8 refined); a mutation running Save project's check without the caps → the 20 000-entry merge takes more than 1 s → RED (R10); a mutation dropping the target's value after a failed document write → RED (R3); a mutation dropping a refused value with no `.previous-<UTC>` copy → RED (R5).
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
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.52, LED-2026-10-26-batch-100.53, LED-2026-10-26-batch-100.54, LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.99
- **Statement:** Every statement of `_handle_save_dialog` and of the Save worker body (LLR-177.1) after the folder's creation — validation, the copies, the save-as walk, the emit and the manifest write — shall run under one `OSError` handler that reports the error with the `could not save` tokens and calls `_remove_created_project_dir` (`app.py:8076`) in the path where the failure happens, removing only a folder this call created; every `return` after the creation that does not complete the save shall also call it.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-07 — `pytest tests/test_b100_save_guards.py -k tc_b100_07` (an AST census over the handler's and the worker body's returns and exception exits, plus one behavioural arm per stage)
- **Numeric pass threshold:** the census derives the post-creation returns and exception exits from the AST of both functions (≥ 3 returns at `1d677ba`, `app.py:8148-8170`) → 0 without the removal; a forced `OSError` at each of 5 stages, on the worker → 0 folders left, 0 raises, app running; a pasted-document write that fails after creating its home (`patches/`) → 0 folders left (the home joins `created_dirs` before `write_change_document`, A3R2-8 / CR12b-1).
- **Negative control:** a mutation deleting one removal call → the census names that exit → RED; S-05's executed probe (a 262-character path) → `FileNotFoundError` escapes and the folder stays → RED.
- **Boundary catalog:** ☒ error — every stage after creation, on the main thread and on the worker; a pre-existing folder is never removed.

### LLR-165.1 — One reset seam, before the first install
- **Traceability:** HLR-165
- **Ledger:** LED-2026-10-26-batch-100.8, LED-2026-10-26-batch-100.98
- **Statement:** `S19TuiApp._reset_project_session()` (NEW, `app.py`) shall reset rows S1–S12 of ARQ §2.2 and these S13 names: the seven `_mac_view_cache_*`, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address` and `_a2l_row_key_to_tag`; then it shall repaint the Patch panel through `refresh_entries`. The project load's main-thread install step (Inc 12b, LLR-177.1g) shall call it once per load, after the worker step succeeds and before the first install. No other caller shall call it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-08 — `pytest tests/test_b100_session_reset.py -k tc_b100_08` (its one-call-site census re-pinned from `_handle_load_project` to the install handler, Inc 12b)
- **Numeric pass threshold:** per project load → 1 call, ordered before the first install; a Load file → 0 calls; call sites in `s19_app/` → 1.
- **Negative control:** a mutation moving the call after `load_selected_file` → the MAC merge sees the old file → RED.
- **Boundary catalog:** ☒ boundary — loading the open project again.

### LLR-165.2 — The session snapshot, derived from the live app (C-31)
- **Traceability:** HLR-165
- **Ledger:** LED-2026-10-26-batch-100.8, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.98
- **Statement:** `S19TuiApp._session_snapshot() -> dict` (NEW, `app.py`) shall return, for every attribute name that `S19TuiApp`'s own source assigns (`self.<name> =`, derived by a census at test time), minus a declared exclusion list of Textual internals, each with its reason, a normalised value: paths relative to the base, the `current_*` objects as `(type, relative path, image digest)`, the change service as its public counts, stat-keyed caches (such as `_mac_view_cache_key`) without their mtime and with relative paths, other objects as counts or keys. The leak check shall compare the snapshot of a cold load of P2 with that of a load of P2 over P1, allow-listing K1 and K2.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-09 — `pytest tests/test_b100_session_reset.py -k tc_b100_09`
- **Numeric pass threshold:** cold vs cold → 0 differing names; P2-over-P1 vs cold P2 → 0 differing names outside the allow-list; the derived domain holds ≥ 60 names (source census 67), and every name the census finds is in the domain or in the exclusion list with a reason (0 unclassified).
- **Note (informative):** Inc 12b (TC-B100-09, LLR-177.1f): the one attribute 12b adds to `S19TuiApp` (the `_quit_pending` quit flag) is classified in the exclusion list with a reason (0 unclassified), and the P2-over-P1 arm runs on the worker path.
- **Negative control:** a code mutation dropping one reset line (`current_a2l_path`) → 1 differing name → RED; a set mutation dropping one census name without an exclusion → the classification arm RED; QA's probe without the stat-key normaliser → cold vs cold differs in `_mac_view_cache_key` → RED for an un-normalised snapshot.
- **Boundary catalog:** ☒ boundary — the K1 counters differ by design and are allow-listed; a stat-keyed cache.

### LLR-165.3 — The change service is rebound
- **Traceability:** HLR-165
- **Ledger:** LED-2026-10-26-batch-100.51, LED-2026-10-26-batch-100.55, LED-2026-10-26-batch-100.60, LED-2026-10-26-batch-100.89
- **Statement:** The reset shall assign a new `ChangeService()` and re-push `set_image_generation(self._image_generation)` (`change_service.py:2494`); it shall not add a reset method to the service.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-10 — `pytest tests/test_b100_session_reset.py -k tc_b100_10`
- **Numeric pass threshold:** after a load over P1: a different service object, 0 document entries, 0 undo steps, an image generation equal to the app's; and a project load whose outgoing document held N > 0 entries paints 0 lines holding `Closed the Patch Editor document` (Inc 10, ruling Q2).
- **Negative control:** a mutation keeping the old object → 1 leaked entry → RED; a mutation that keeps the interim line → the Inc 10 arm finds 1 line → RED.
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
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.57, LED-2026-10-26-batch-100.58, LED-2026-10-26-batch-100.59, LED-2026-10-26-batch-100.89
- **Statement:** Each window shall declare its focus target, a non-text widget (NEW, a per-window table in `app.py`, derived at Phase 3 from the window registry and checked by TC-B100-12 against every window). The load tail `_step_finalize` (`app.py:11191`), the dismiss of the Load dialog, of the load question and of the Load-result panel, and a cancelled load shall move the focus to the displayed window's target when the focused widget has region area 0, belongs to a window that is not displayed, or is an `Input` / `TextArea`. While the Load-result panel is open, the focus stays in it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-12 — `pytest tests/test_b100_focus.py -k tc_b100_12`
- **Numeric pass threshold:** every window in the registry → 1 declared target, 0 of type `Input` / `TextArea`; written at Inc 4: 3 load paths (Load file, Load project, Workarea Files pick) → the focus on the target, then `p` → a dialog opens (3 of 3); extended at Inc 6 (panel `enter`, panel `esc`), Inc 9b (dialog `esc`, cancelled load) and Inc 10 (question `n`) — Inc 10's arm (LLR-166.1 governs, ruling 7): the Patch window with the focus on `#patch_entry_address_input` (an `Input`) and D set, `ctrl+l` + a typed data file + `enter` → the question → `n` → the focus stays on `patch_entry_address_input` (a visible, healthy `Input` keeps the focus) and `_rehome_focus_after_load` was called once (spy); the Workspace window with the focus on `#files_list` and D set, pick a data file → the question → `escape` → the focus stays on `files_list` and the spy count is 1 (2 of 2).
- **Negative control:** executed on `1d677ba` (P-16): `focused region area: 0` → RED; a mutation whose cancel branch skips the re-home → the spy count is 0 (not 1) → RED (M36).
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
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.64
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
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.23, LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.45, LED-2026-10-26-batch-100.63, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.74, LED-2026-10-26-batch-100.75, LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.79
- **Statement:** `plan_project_save(...) -> SavePlan` (NEW, a pure function in `services/project_gather_service.py`) shall compute, without writing, the target folder and its kind (new, open project, merge), one row per top-level file, one row per sub-folder with its file count, and one row for `project.json`, each with its source, landing name (from `predict_placement`, LLR-163.7) and action word (`new`, `keep`, `merge`, `rewrite`; `replace` is not produced through Inc 8a, E3 R1), plus the image description (source + N change entries, K applied by this save, or an unchanged copy), the document, skipped links and the manifest keys, or the refusal with its tokens. The manifest-key list is an input of `plan_project_save` from Inc 5 (the app passes the keys it writes), so the function does not change when Inc 7 or Inc 8a adds a key. The emitted image's bytes and digest, and the copied files' digests, are computed once per dialog open on a worker (LLR-175.4) and passed in, so `project_gather_service` gains no import of `change_service` or `changes`. `_handle_save_dialog` shall execute exactly that plan.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** written at Inc 5: fresh, open-project, pending patch and refused scenarios → the plan's rows equal the written tree at the plan's granularity, by full path and action (0 differences), the refused scenario → 0 files; extended at Inc 8a: a pasted document → 1 document row with its landing under its home (`changes.json` `new`; `changes_1.json` `new` beside a different one; `keep` for an identical one), a file-backed document that is placed or recorded → 1 row with its landing name; one the gather does not place (inside the project but outside its home, its source gone, or its source a link) → 0 document rows and the save completes (E3 R11, A3R2-1); no document → 0 document rows, and a merge → target kind `merge` with its `project.json` row `merge` — each equal to the written tree by full path and action (0 differences), the document's digest and size an input like the image's, and `manifest_keys` holding `active_document` exactly when the write records it; extended at Inc 8b by LLR-167.6a (sub-folder rows), LLR-167.6b (skipped links), LLR-167.6c and LLR-167.6d (the MAC and A2L refusals decided in the plan, LED .66), LLR-167.6e (one row per landing path), LLR-167.6f (the open project's own A2L) and LLR-167.6g (the per-file cap), each with its own threshold and negative control, and a save as with top-level copies → 1 `carried` row per copy, action `new`, equal to the written tree by full path and action (0 differences; orchestrator rulings R3, R11, E3-architect A3R2-6); computing a plan writes 0 bytes, leaves `mem_map` unchanged and computes 0 digests; 0 new imports from `project_gather_service`. Orchestrator decision (E1 §4 Q3, LED .72; amended by E3 R1, LED .73): the document row's action is `new` when the document is written or copied this save and `keep` when it is recorded as already in its home; the document row never has `replace`; mutation always writing `new` → 1 action-word difference on the `keep` arm → RED; the plan's key list is settled after the write outcome is known (Inc 8a F4).
- **Negative control:** a mutation where the handler places a file the plan did not name → 1 tree row without a plan row → RED; a mutation planning without the `inside_elsewhere` class → 1 document row with no file in the tree → RED; a mutation letting the document digest's `OSError` propagate → "Project NOT saved" → RED (E3 R11, A3R2-1).
- **Boundary catalog:** ☒ empty ☒ boundary ☒ error — a fresh empty folder; a clashing landing name; a refused name.

### LLR-167.6a — The save-as plan has one row per sub-folder with its file count
- **Traceability:** HLR-167, HLR-171 · trace: `plan_project_save`, `SavePlanRow` (`project_gather_service.py`), `_plan_project_save` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS event):** When Save project computes the plan for a save as, the system shall include one row for each top-level sub-folder of the open project, holding the count of files LLR-171.1 copies under it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** P with the 7 sub-folders of LLR-171.1 → 7 sub-folder rows, each count equal to the files written under that sub-folder (0 differences, `reports` = 2 with the nested file); P with no sub-folder → 0 sub-folder rows; a sub-folder holding only a junction → 1 row with 0 files (orchestrator ruling Q9, LED .77); computing the plan writes 0 bytes.
- **Negative control:** a mutation planning without sub-folder rows → 7 written sub-folders with no plan row → RED; a mutation omitting a sub-folder with 0 files → the links-only sub-folder has no row → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no sub-folder; a nested sub-folder.

### LLR-167.6b — The save-as plan lists each skipped link
- **Traceability:** HLR-167, HLR-171 · trace: `plan_project_save` (`project_gather_service.py`), `_plan_project_save` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS event):** When Save project computes the plan for a save as, the system shall list in the plan each link or junction that the save-as enumeration skips.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** the 3 links of LLR-171.1a and LLR-171.1b → 3 skipped-link entries in the plan, equal to the 3 paths LLR-171.1c names in the status (0 differences); 0 links → 0 entries; the junction of a links-only sub-folder is listed against that sub-folder's 0-file row (orchestrator ruling Q9, LED .77).
- **Negative control:** a mutation that drops the skipped links from the plan → 0 of 3 → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — no link; three links.

### LLR-167.6c — A second MAC file is refused in the plan
- **Traceability:** HLR-167 · trace: `_plan_project_save`, `_handle_save_dialog` (`app.py`) — LED .63 (b), LED .66
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78
- **Statement (EARS unwanted):** If the target project folder holds a MAC file and the session holds a MAC file other than it, then the system shall put the `already has a MAC file` refusal into the save plan.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** a merge target holding `a.mac` and a session MAC `b.mac` → the plan carries the refusal and 0 rows; 0 `mkdir` calls on the target (a spy: the decision is taken before any folder creation is attempted), 0 bytes written, 0 rollback runs; 1 status line holding `already has a MAC file` and `choose another name`. "Other than it" means not the same path (compared as text) and not the same name with the same bytes, the A2L rule of LLR-167.6d / .6f (pre-ruling 5, E3-architect A3-4, Code-Wire DR-6): a session MAC `a.mac` with other bytes than the target's `a.mac` → refused; with the same bytes → not refused; a target MAC that is a link → never the session's own (E3-security S3-8). A new target folder cannot hold a MAC file, so this arm is a merge or open-project target (Code-Wire note).
- **Negative control:** base `ebe6d0c`: the refusal runs in the save body after `project_dir.mkdir` (LED .63 (b)) → the spy records 1 `mkdir` call and the plan has rows → RED; a mutation keeping the check only in the save body → RED; a mutation exempting by name only (the `ebe6d0c` rule, `app.py:9746-9758`) → the other-bytes arm is saved as a second MAC → RED.
- **Boundary catalog:** ☒ invalid — a second MAC file.

### LLR-167.6d — A second A2L file is refused in the plan
- **Traceability:** HLR-167 · trace: `_plan_project_save`, `_handle_save_dialog` (`app.py`) — LED .63 (b), LED .66
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS unwanted):** If the target project folder holds an A2L file and the session holds an A2L file other than it, then the system shall put the `already has an A2L file` refusal into the save plan.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** a merge target holding `a.a2l` and a session A2L `b.a2l` → the plan carries the refusal and 0 rows; 0 `mkdir` calls on the target (spy), 0 bytes written, 0 rollback runs; 1 status line holding `already has an A2L file`. "Other than it" means not the same path and not the same name with the same bytes; the exemption is LLR-167.6f (orchestrator ruling Q3, LED .77; Code-Wire C3).
- **Negative control:** base `ebe6d0c`: the refusal runs in the save body after `project_dir.mkdir` → the spy records 1 `mkdir` call and the plan has rows → RED; a mutation keeping the check only in the save body → RED.
- **Boundary catalog:** ☒ invalid — a second A2L file.

### LLR-167.6e — One plan row per landing path
- **Traceability:** HLR-167, HLR-171 · trace: `plan_project_save` (`project_gather_service.py`), `_plan_project_save` (`app.py`) — Code-Wire C5
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS ubiquitous):** The system shall give each landing path of a Save project at most one plan row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** P open with the Patch Editor document `P/patches/boost.json`, saved as Q → 1 plan row for `Q/patches/boost.json`, whose action equals what the tree shows (0 differences); every landing path of the plan appears once (0 duplicates). Which row owns that landing (the document row or the sub-folder copy) is a design seam for E2.
- **Negative control:** a mutation planning both the document row and the sub-folder copy for the same landing → 2 rows for 1 path, one with action `new` over a reused file → RED.
- **Boundary catalog:** ☒ boundary — a document inside a copied sub-folder.

### LLR-167.6f — The open project's own A2L is not refused
- **Traceability:** HLR-167, HLR-171a · trace: `_plan_project_save` (`app.py`) — orchestrator ruling Q3 (LED .77), Code-Wire C3
- **Ledger:** LED-2026-10-26-batch-100.77
- **Statement (EARS event):** When Save project plans a save into a target project folder whose A2L file is the session's A2L file (the same path, or the same name with the same bytes), the system shall plan the save without the `already has an A2L file` refusal.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** the A2L-only project `p04` 10 loaded and saved into itself twice → 2 saves, 0 refusals, 1 A2L file in P (0 `_1` copies); a project with an image and an A2L loaded and saved into itself → saved, 0 refusals; a target A2L with the same name and different bytes → refused (LLR-167.6d).
- **Negative control:** base `ebe6d0c` (Code-Wire C3): the second save into itself is refused with `Project already has an A2L file.` → RED; a mutation exempting by name only → the different-bytes arm is saved → RED.
- **Boundary catalog:** ☒ boundary — the same path; the same name and bytes; the same name and other bytes.

### LLR-167.6g — A file over the per-file cap is refused in the plan
- **Traceability:** HLR-167, HLR-171 · trace: `_plan_project_save` (`app.py`), `DEFAULT_COPY_SIZE_CAP_BYTES` (`workspace.py`, read, not changed) — orchestrator ruling Q10 (LED .77), Code-Wire C6
- **Ledger:** LED-2026-10-26-batch-100.77
- **Statement (EARS unwanted):** If a file the save would copy is larger than the placement's per-file size cap, then the system shall put a refusal naming that file into the save plan.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-59 — `pytest tests/test_b100_save_image.py -k tc_b100_59`
- **Numeric pass threshold:** with the cap lowered for the test (the shipped cap is 256 MiB), `P/splits/big.bin` at cap + 1 bytes → the plan carries a refusal naming `splits/big.bin`, 0 rows, 0 `mkdir` calls (spy), 0 bytes written; at exactly the cap → saved.
- **Negative control:** base `ebe6d0c`: `place_into_workarea` raises `WorkareaPlacementError` after `project_dir.mkdir` and the save rolls back → the spy records 1 `mkdir` call → RED; a mutation refusing at size ≥ cap → the boundary arm is refused → RED.
- **Boundary catalog:** ☒ boundary ☒ error — exactly the cap; one byte over.

### LLR-167.7 — `save_patched` split into re-derive and emit-and-verify
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.14, LED-2026-10-26-batch-100.56
- **Statement:** `ChangeService` shall expose `rederive_for_save(copy) -> (map, summary)` (NEW), which re-derives the source plus the current change document onto the given copy without touching the session map, and `emit_and_verify(map, ranges, dest_dir, filename, …) -> ChangeActionResult` (NEW), which emits and verifies. `save_patched` (`change_service.py:2009`) shall be composed of the two, so the save-back's rule (B99-I7) is unchanged. Inc 5 lands the split.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-69 — `pytest tests/test_b100_save_image.py -k tc_b100_69`
- **Numeric pass threshold:** `rederive_for_save` → 0 writes to the session map; `save_patched` before and after the split → byte-identical files for 4 documents (applied, undone, added after apply, blocked); `tests/test_b99_editor_image.py` → 0 new failures.
- **Negative control:** a mutation where `rederive_for_save` writes the session map → the 0-writes arm RED.
- **Boundary catalog:** ☒ boundary ☒ error — the 4 documents, the blocked one included.

### LLR-167.8 — Save project clears the Patch Editor's dirty flag
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.61, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.75, LED-2026-10-26-batch-100.89
- **Statement:** When a Save project completes after the app wrote the editor's document into the project (LLR-170.2), `_handle_save_dialog` shall clear the Patch Editor panel's dirty flag through `PatchEditorPanel.mark_saved` (`screens_directionb.py`); a refused or rolled-back save, a failed document write, and a file-backed document copied or recorded as on disk while the panel holds unsaved edits leave the flag set, because no file on disk holds those edits (LED .61). `ChangeService.mark_saved` runs after every completed Save project (LLR-167.5).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-70 — `pytest tests/test_b100_save_image.py -k tc_b100_70`
- **Numeric pass threshold:** an entry pasted → Save project → the panel's flag False, and a following Patch Editor Load → 0 `LoadGuardScreen` pushes; a refused Save project → the flag True; a forced document-write failure → True; a file-backed document with 1 entry added after its load → Save project → True, both for a document from outside the project (copied) and on the natural path Load P → add 1 entry → Save project into P (the document in P's home is recorded as on disk, not written; E3 R1, LED .73) (5 arms, 1 assertion each). Inc 5's `test_tc_b100_70_unwritten_document_keeps_the_flag` is re-pinned at Inc 8a: its typed document is now written, so it becomes the first arm. The project-load question arm runs at Inc 10: an entry pasted → Save project → a project load through the Load dialog → 0 questions (Save project cleared the flag); a refused Save project (the flag stays set) → a project load through the Load dialog → 1 question naming `Patch Editor entries` — 2 of 2 (LLR-174.1b). Orchestrator decision (E1 §4 Q2, LED .72): pasted text not yet parsed into entries counts as unsaved — Save project with an unparsed paste buffer keeps the flag True; mutation clearing it → flag False → RED.
- **Negative control:** a mutation skipping the panel's `mark_saved` → flag True and the Patch Editor Load asks → RED; a mutation calling it after every completed save → the file-backed arm False → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a check document; a file-backed document with unsaved edits; a refused save; a failed write.

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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.67, LED-2026-10-26-batch-100.75
- **Statement:** The Load-file variant append and the MAC and A2L syncs (`app.py:8591`, `:8622`, `:8630`, `:8652`) shall place their files through `place_into_workarea` and each end in `_write_and_verify_manifest`, passing every key of the existing manifest they do not change — `batch`, `assignments`, `declared_regions`, `gathered`, `active_document`, `derived_from` — converted from the reader's absolute paths back to project-relative POSIX strings. The variant append shall make the appended file active and paint a status line naming the project and the file it now opens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-20 — `pytest tests/test_b100_active_variant.py -k tc_b100_20`
- **Numeric pass threshold:** 4 writers → 4 rewrites; each → 0 changed keys it does not own and 0 absolute paths in the written file; a recorded document and a `derived_from` → still recorded after the append; the append → `active_variant` = the appended id and 1 status line naming project and file.
- **Negative control:** a mutation removing the seam call from the variant append → `active_variant` stale → RED; a mutation passing the reader's absolute `batch` → `serialize_manifest` refuses and no manifest is written (A-03 probe) → RED.
- **Boundary catalog:** ☒ boundary — a manifest with every key filled.

### LLR-168.4 — `derived_from` records what a patched variant derives from
- **Traceability:** HLR-168
- **Ledger:** LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.33, LED-2026-10-26-batch-100.48
- **Statement:** `serialize_manifest` shall emit, as part of the B100-I1 envelope, an additive per-variant `derived_from` map (B100-I16), only when non-empty: for each patched variant file (project-relative, through `_reject_unsafe_entry`), the base's file name, the base's SHA-256 and the number of bytes that differ from it, all computed at the write, when both images are in hand. `read_project_manifest` shall parse it in the manifest-keys mode, an unsafe or malformed value giving one issue and no entry, capped at 1 000 entries. The save-back into a project and Save project's emit shall set it from Inc 7 on; an emit before Inc 7 records nothing. Every rewrite carries it (LLR-168.3). The JSON field names of a record are fixed in the Inc 7 packet and frozen with B100-I16. The base need not be in the project: when no project file has the recorded name and digest, the record still names the base and its byte count.
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.75
- **Statement:** `_write_and_verify_manifest` (`app.py:8272`) shall compute `files` itself, after every copy has landed, over the top-level regular files whose suffix is in `PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS` (`workspace.py:75-77`, `.srec` and `.ihex` included) and the active document, and over no file under a sub-folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-22 — `pytest tests/test_b100_project_check.py -k tc_b100_22`
- **Numeric pass threshold:** a project with `firmware.s19`, `firmware.mac`, `firmware.a2l`, `prg.srec`, `flows/f1.json` and `reports/r.md` → `files` keys = the 4 top-level files (the set derived from the listing by the suffix constants). The active-document arm runs at Inc 8a (TC-B100-28, A-15): the same project plus `patches/boost.json` recorded as `active_document` and a second `patches/other.json` → `files` keys = the 4 top-level files + `patches/boost.json` (5), `patches/other.json` absent; a recorded document absent from disk → no record for it, 0 raises.
- **Negative control:** a mutation walking sub-folders → `flows/f1.json` recorded → RED; a mutation keyed on `.s19` only → `prg.srec` missing → RED; (Inc 8a) a mutation leaving the active document out → 4 keys → RED.
- **Boundary catalog:** ☒ boundary — `.srec` and `.ihex` variants.

### LLR-169.3 — Verify covers the new keys
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.33, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.75
- **Statement:** `verify_written_manifest` (`manifest_writer.py:632`) shall include `files`, `active_document` and `derived_from` — the keys the B100-I1 envelope adds — in its drift domain (today `:717-723`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-23 — `pytest tests/test_b100_project_check.py -k tc_b100_23`
- **Numeric pass threshold:** one digest changed between write and verify → 1 mismatch reported; one `derived_from` byte count changed → 1 mismatch; unchanged → 0; from Inc 8a, one `active_document` changed between write and verify → 1 mismatch.
- **Negative control:** a mutation leaving `files` out of the domain → 0 mismatches → RED; (Inc 8a) a mutation leaving `active_document` out of the domain → 0 mismatches on that arm → RED.
- **Boundary catalog:** ☒ boundary — a changed `active_document` only; a changed `derived_from` only.

### LLR-169.4 — The reader treats `project.json` as untrusted (C6)
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.29, LED-2026-10-26-batch-100.71, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.75
- **Statement:** `read_project_manifest` shall read at most 1 MiB of `project.json` (an excess gives one `MANIFEST-SIZE-CAP`), parse at most 1 000 entries in each of `batch`, `declared_regions`, `gathered`, `files` and `derived_from`, and at most 1 000 entries in total across all `assignments` lists with at most 1 000 `assignments` keys (an excess gives one `MANIFEST-BAD-STRUCTURE`), and parse `files` into `dict[Path, FileRecord]`. A `files` key passes the manifest-key predicate (LLR-169.8) or gives one `MANIFEST-PATH-ESCAPE`; a contained key outside the scope (not a top-level name with a project data or A2L suffix, and not `active_document`) gives one `MANIFEST-BAD-STRUCTURE`. A record whose `size` is not an `int` ≥ 0 (a `bool` included) or whose `sha256` is not 64 hex characters gives one `MANIFEST-BAD-STRUCTURE`. Every refused record is skipped; an absent key gives an empty dict and no issue. These codes go to the log; the panel words them in user terms (LLR-169.9).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-24 — `pytest tests/test_b100_project_check.py -k tc_b100_24`
- **Numeric pass threshold:** per arm, the code asserted: `../x.s19`, an absolute path, `C:x`, a UNC path, `x.s19:ads`, `CON`, `x.s19.`, `patches/NUL.json` → 8 × `MANIFEST-PATH-ESCAPE`; `sub/x.s19` → 1 × `MANIFEST-BAD-STRUCTURE`; `size: true`, `size: -1`, `size: "1"`, `sha256: "XYZ"`, 63 and 65 hex → 6 × `MANIFEST-BAD-STRUCTURE`; 1 001 entries in `batch` (and separately in `files`) → 1 issue each, read under 1 s; 75 `assignments` keys × 1 000 entries (security probe: 14.80 s uncapped) → 1 issue, read under 1 s; a 1 MiB + 1 byte file → 1 `MANIFEST-SIZE-CAP`; a valid record → 1 record; from Inc 8a, a `files` key equal to the accepted `active_document` → 1 record, 0 issues, and `patches/other.json` when it is not the active document → 1 `MANIFEST-BAD-STRUCTURE`.
- **Negative control:** a mutation accepting a `bool` size → 0 issues on that arm → RED; (Inc 8a) a mutation accepting any `patches/` key → the `patches/other.json` arm gives 0 issues → RED; P-40: an uncapped `batch` of 75 677 entries takes 14.92 s → RED for the timing arm.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — an absent key; exactly 1 000 entries and 1 MiB; the hostile set.

### LLR-169.5 — `check_project_files`: manifest and disk problems
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.75
- **Statement:** `check_project_files(project_dir, manifest) -> list[ProjectFileProblem]` (NEW, `manifest_writer.py`) shall return manifest and disk problems only: `manifest damaged` (`MANIFEST-JSON-PARSE`, `-SIZE-CAP`, top-level `-BAD-STRUCTURE`, an over-cap record count), `no project.json`, `missing` (a recorded file absent), `changed on disk` (size or digest differs; only `S_ISREG` files are hashed, any other type is `not readable`), `not recorded` (a top-level data or A2L file absent from a present `files`), and `no digests saved` (no `files` key). It shall never raise, and shall not parse images.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-25 — `pytest tests/test_b100_project_check.py -k tc_b100_25`
- **Numeric pass threshold:** the `p04` cases 2, 5, 7, 9, a legacy project and a hand-copied `firmware_9.s19` → 6 problems of the matching kinds; a clean project → 0; a file unreadable by permission → 1 problem, 0 raises; `P/NUL` recorded → `not readable`, not `ok`; from Inc 8a, a recorded `active_document` absent from disk → 1 `missing` naming it, with and without a `files` record for it (2 arms); a missing variant id `boost` with a document `patches/boost.json` present → the missing problem names the variant's data file, never the document (`_missing_recorded` is limited to primary data suffixes; E3 R7, LED .73).
- **Negative control:** executed on `1d677ba` (P-4): `notices=[]` for cases 2 and 7 → RED; a mutation dropping the `not recorded` kind → the hand-copied arm → RED; a mutation dropping the primary-data-suffix restriction in `_missing_recorded` → the problem names `boost.json` → RED (R7).
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
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.54
- **Statement:** `write_project_manifest` (`manifest_writer.py:414`) shall stage `project.json` in a private directory from `_private_stage_dir` (`workspace.py:298`) and place it with `os.replace`, never through the fixed `temp/project.json` (`:509`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-27 — `pytest tests/test_b100_project_check.py -k tc_b100_27`
- **Numeric pass threshold:** 8 concurrent manifest writes for 8 projects × 10 trials → 80 of 80 return a path, 80 manifests present, each holding its own `active_variant`, 0 issues; the source predicate "no `WORKAREA_TEMP / PROJECT_MANIFEST_NAME` staging in `manifest_writer.py`" → 0 hits.
- **Negative control:** executed on `1d677ba` by the QA race probe: `ok=3 cross-content=12 failed-writes=60` → RED; the source predicate → 1 hit at `:509` → RED.
- **Boundary catalog:** ☒ boundary — 1 and 8 writers.

### LLR-169.8 — A manifest-key mode refuses drive-relative, stream and device names (S-09)
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.71
- **Statement:** `_resolve_manifest_entry` (`variant_execution_service.py:205`) shall gain a manifest-key mode, used by `read_project_manifest` and `_reject_unsafe_entry` only, that refuses with `MANIFEST-PATH-ESCAPE` an entry with a drive or a root (`PureWindowsPath(entry).drive or .root`), a `:` anywhere, or a path component that ends in a dot or a space or for which `is_windows_device_name` is true, with or without an extension. Both flow-reference callers — `flow_persistence_service.py` (`:84`, `:582`, `:619`, `:780`, `:1433`) and `flow_execution_service.py` (`:117`, `:315`, `:345`, `:427`, `:448`, `:734`, `:798`, `:942`, `:1695`) — keep the default mode, so `tests/test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally` stays green.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-60 — `pytest tests/test_b100_project_check.py -k tc_b100_60` and `pytest tests/test_b97_flow_builder.py tests/test_flow_persistence.py tests/test_flow_execution_service.py`
- **Numeric pass threshold:** in manifest-key mode: `C:x.s19`, `c:sub/x.s19`, `x.s19:ads`, `x.s19.`, `x.s19 `, `CON`, `patches/NUL.json`, `nul.s19`, `sub./x.s19`, `patches/x.json `, `../x.s19`, `C:/x.s19`, `\\host\share\x.s19`, `\\?\C:\x.s19` → 14 × `MANIFEST-PATH-ESCAPE`; `x.s19` and `patches/a.json` → accepted; the flow tests → 0 new failures.
- **Negative control:** executed (S-09): `'C:x.s19' -> …\workarea\P\x.s19 0` at `1d677ba` → RED; P-41: the same tightening applied to every caller → `test_tc_b97_20_hostile_refs_render_literally` RED, so the mode is required.
- **Boundary catalog:** ☒ boundary ☒ invalid — a nested relative path (accepted); the hostile set, per path component.

### LLR-169.9 — The load result adds `not readable`, one problem per file wins, worded for the user
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.22, LED-2026-10-26-batch-100.69
- **Statement:** `_handle_load_project` shall add `not readable` for an image whose install reports load errors or an empty `mem_map`, merge it with `check_project_files`' list, and keep for each file only its highest problem by the precedence `manifest damaged` / `no project.json` > `missing` > `not readable` > `changed on disk` > `not recorded` > `no digests saved`; at most one manifest-level problem is kept. Each problem is painted with its reason in user terms ("not an S19 or HEX file", "0 data bytes", "a file path points outside the project") and its next-step token (§3 table); internal issue codes and exception class names go to the log only.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-61 — `pytest tests/test_b100_project_check.py -k tc_b100_61`
- **Numeric pass threshold:** `p04` case 6 → 1 problem, `not readable`; case 7 → 1, `manifest damaged`; a file both changed and unrecorded → 1, `changed on disk`; 7 kinds → 7 next-step tokens; 0 exception class names and 0 `MANIFEST-` codes in painted problem text.
- **Negative control:** a mutation keeping every kind per file → case 6 gives 2 problems → RED; a mutation painting the issue code → 1 `MANIFEST-` code painted → RED.
- **Boundary catalog:** ☒ boundary — a file matching three kinds.

### LLR-170.1 — The `active_document` key
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.75
- **Statement:** The `active_document` manifest key shall hold one project-relative POSIX path with a `patches/` or `checks/` prefix and a `.json` suffix, enforced by one predicate at both ends (S-11): `serialize_manifest` emits the key only when set and refuses the whole serialize (no text, one write finding) for a value outside that form or refused by `_reject_unsafe_entry`; `read_project_manifest` accepts it through `_resolve_manifest_entry` (manifest-keys mode) only in that form, and otherwise gives one issue and `None` and reads the rest of the manifest. The key is a known top-level key (`KNOWN_MANIFEST_KEYS`), so a manifest holding it is carried by an in-project rewrite, not refused as holding unknown keys (SEC6-2).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-28 — `pytest tests/test_b100_document.py -k tc_b100_28`
- **Numeric pass threshold:** `patches/boost.json` and `checks/c.json` → round-trip equal (2 of 2); the reader given `../x.json`, an absolute path, a number, `firmware.s19`, `project.json`, `patches/x.txt` → 6 issues, 6 `None`, `active_variant` still read; the writer given `firmware.s19` or `../x.json` → `(None, findings)` in 2 of 2, 0 text; absent → `None`, 0 issues, and the serialized text has no `active_document` key; a manifest holding a valid `active_document` → 0 unknown keys, and a variant append keeps it (1 rewrite, key equal). The A-15 arm of LLR-169.2 runs in this TC.
- **Negative control:** a mutation skipping the reader's prefix rule → `firmware.s19` accepted → RED; a mutation dropping the writer's form check → `firmware.s19` serialized → RED; a mutation leaving `active_document` out of `KNOWN_MANIFEST_KEYS` → the variant append refuses the rewrite → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — absent; hostile values at the reader and at the writer.

### LLR-170.2 — The app writes a pasted document; the gather places
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.74, LED-2026-10-26-batch-100.75
- **Statement:** When Save project runs while the Patch Editor holds a document with at least one entry and no `source_path`, `_handle_save_dialog` shall write it through `write_change_document` (`changes/io.py`) into the home for its kind (`patches/`, or `checks/` for a check document) as `changes.json` — placed by the M-1 rule, so an identical `changes.json` is reused and a different one gives `changes_<N>.json` — and pass the landed path to `gather_project_artifacts` (`project_gather_service.py`) as the active document, which only places files (a file already in its home is reused, and still named) and whose `GatherOutcome` names the landed project-relative path. A write that fails leaves the save to complete with no document placed, no `active_document` of its own recorded (a merge or an open-project save carries the target's value, LLR-164.2; E3 R3) and one status line naming the document as not saved; a failure later in the same save removes a document this save created (it joins the save's placed files).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-29 — `pytest tests/test_b100_document.py -k tc_b100_29`
- **Numeric pass threshold:** a pasted change document with 1 entry → `P/patches/changes.json` holding 1 entry, named in the outcome and recorded as `active_document`; a pasted check document → `P/checks/changes.json`; a different `changes.json` there → `changes_1.json` recorded; an identical one → reused, 0 new files; a file-backed document → 1 file, byte-equal to the source; a file-backed document with 0 entries → 1 file, recorded as `active_document` (E3 R9: the ≥1-entry rule applies to a pasted document only); a pasted document with 0 entries → 0 files written by the app and no `active_document`; a forced write failure → the save completes, no `active_document` of its own (into a fresh `P`: none; in a merge into `ab` recording `patches/boost.json`: that value carried, E3 R3), 1 status line naming the document; a forced failure after the write (the manifest write) → the written `changes.json` removed, 0 new files under `patches/`; 0 new imports from `project_gather_service` to `changes`. Orchestrator decision (E1 §4 Q1, LED .72; amended by E3 R1, LED .73): after the first write the editor's document is bound to the landed file (`source_path` = the landing). Save project never overwrites a file that already exists in the project, so a second Save project of the bound document with edits writes nothing for the document, keeps the panel flag and paints 1 status line saying the change document has unsaved edits and naming the Patch Editor save as the way to keep them → 1 file under `patches/`, 0 `changes_1.json`, `P/patches/changes.json` bytes unchanged; a mutation rewriting it in place → 2 writes or a changed byte → RED. A file-backed document already in the target's home is recorded as it is on disk and not written; a file-backed document outside the project is copied (byte-equal).
- **Negative control:** executed on `1d677ba` (P-8): nothing under `patches/` for a pasted document → RED; a mutation leaving the written document off the save's placed files → the rollback arm keeps `changes.json` → RED; a mutation recording the failed document as `active_document` after a failed write → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ error — 0 entries pasted (not placed), 0 entries file-backed (recorded); an identical `changes.json` (reused); a different one (`_1`); a check document (`checks/`); a failed write; a failure after the write.

### LLR-170.3 — Load reopens the document after the A2L
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.72, LED-2026-10-26-batch-100.73, LED-2026-10-26-batch-100.74, LED-2026-10-26-batch-100.75
- **Statement:** When a project whose `project.json` records an accepted `active_document` (LLR-170.1) is loaded, `_handle_load_project` shall end with exactly one of two outcomes for that document: it is loaded into the session's `ChangeService`, parsed with the project's A2L context (`a2l_context`, so symbol entries resolve against the project's A2L; E3 R10: the parse of the classifier's bytes, not a second read through `ChangeService.load`), after that A2L is loaded (with no context when the project has no A2L), the Patch Editor lists its entries and its dirty flag is clear; or, if the file cannot be read or does not parse as a change or check document, the Patch Editor holds no document, the load adds one `not readable` problem naming the file with its reason in user terms, and the load continues. A missing document is not reported here: `check_project_files` owns `missing` for it (LLR-169.5, the recorded `active_document` counts as a recorded file), and LLR-169.9's merge keeps one problem per file. A document that parses with entry issues (an unresolved symbol, a blocked entry) is loaded and shows them; that is not a load problem. The file is read once through one classifier shared with Save project (E3 R10): `lstat` of the home and the file (a link → not readable), the 1 MiB byte cap, one bounded read, a guarded decode of those bytes and the entry count (only when `entries` is a list; more than 1 000 → too large; not a list → not readable), then the parse of the same bytes; a decode or parse exception (`JSONDecodeError`, `RecursionError`, `UnicodeDecodeError`, `ValueError`, `TypeError`) is `not readable`, never a raise, and an `OSError` on the read is `not readable` ("could not be read now"). The record stays in `project.json` in every case; only Save project drops it (LLR-164.2).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-30 — `pytest tests/test_b100_document.py -k tc_b100_30`
- **Numeric pass threshold:** `p06` A → the document `patches/boost.json`, 1 entry, the panel's dirty flag clear; a symbol entry → resolved against the project's A2L (0 unresolved); a project with no A2L and one address entry → loaded, 1 entry; the recorded file deleted → exactly 1 problem naming it (`missing`, from `check_project_files`), 0 editor entries, the image opens; the file holding `{` → exactly 1 `not readable` problem naming it, 0 editor entries, the image opens; a document over 1 MiB (1 048 576 bytes) or over 1 000 entries, checked before the parse → exactly 1 `not readable` problem ("too large to reopen"), 0 editor entries, the project still loads, Load and panel under 1 s (E3 R4, LED .73; measured at 20 000 entries: 33 s without the cap); a file of 1 048 576 × `[` (1 MiB) → exactly 1 `not readable`, 0 raises, the image opens and Load completes under 1 s (E3 R10; the count step raised `RecursionError` in probe P2); `{"entries": 5}` → 1 `not readable` (not "too large"); the file a link → 1 `not readable`, 0 bytes read through it; the file locked by another program → 1 `not readable` ("could not be read now"), the record kept (E3 R8 refined); 0 raises. Orchestrator decision (E1 §4 Q6, LED .72): the reopen lists the entries and never applies them again (the saved image already holds them) → the loaded image bytes equal the file's bytes, 0 entries re-applied; mutation applying on reopen → image bytes differ → RED. The no-`a2l_context` mutation is the primary control for the A2L order (Q5).
- **Negative control:** executed on `1d677ba` (P-8): `editor doc = None` → RED; a mutation loading without `a2l_context` (C1: no app caller passes it today) or before the A2L is loaded → the symbol arm has 1 unresolved entry → RED; a mutation where the load also reports `missing` for the document → 2 problems for one file → RED; a mutation with the reopen caps removed → a 20 000-entry document takes more than 1 s → RED (R4); a mutation whose catch set lacks `RecursionError` → the 1 MiB `[` file raises out of Load → RED (R10).
- **Boundary catalog:** ☒ boundary ☒ error — a symbol entry; no A2L; a missing document; an unreadable one; a 1 MiB `[` file; a link; a locked file.

### LLR-171.1 — Save as copies each file of the open project to the same path
- **Traceability:** HLR-171 · trace: `_handle_save_dialog`, `_copy_project_subfolders` (NEW) (`app.py`), `inventory_project_tree`, `plan_project_save` (`project_gather_service.py`), `walk_tree_no_links` (`workspace.py`), `place_into_workarea` (every copy places through it, LLR-171.4a)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.44, LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79
- **Statement (EARS event):** When Save project saves the open project into a new project folder, the system shall copy each regular file of the open project that the save does not write itself, other than `project.json` backups (`project.json.previous-*`), at the top level and at every depth of its sub-folders, to the same project-relative path in the new project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P with `flows/`, `flowsets/`, `patches/`, `checks/`, `reports/`, `templates/`, `splits/` (one file each) and a nested `reports/2026/r2.md`, the expected set derived from P's link-free listing → 100 % of the expected set present in Q (0 missing), 0 files with a differing SHA-256; P with the top-level `a.json`, `other.s19` (a second variant) and `notes.txt` beside the session's image, A2L and `project.json` → `a.json`, `other.s19` and `notes.txt` present in Q byte-equal at the same names, the session's image and A2L written once by their rows, Q's `project.json` written by the save, 0 `_1` copies (orchestrator ruling R3, E3-architect A3-2); P with no sub-folder and no other top-level file → 0 copied files in Q and the save completes; a fresh session with no open project → no enumeration, 0 copied files (the trigger needs an open project). The files the save writes itself are `project.json`, the files of the image, MAC and A2L rows, and, when the session plans a MAC or an A2L row, every other MAC or A2L file of P (Q holds one of each, LED .63 (b) / .66; Code-Wire F-7); P's `project.json.previous-*` backups are not copied (R10): P with `project.json.previous-20261030T000000Z` beside `a.json` → Q holds `a.json` and 0 files whose name, compared with `normcase`, starts `project.json.previous-`. A save into an existing project copies no sub-folder (LLR-171.1g, orchestrator ruling Q2). The sub-folder copy runs right after the project folder is created, before the first home placement; the top-level copy runs after the image, MAC and A2L rows are placed and before the gather (orchestrator rulings R2, R11). P holding `firmware.s19` (the session image) and `firmware_1.s19` byte-identical to the image this save emits → saved, Q holds both names, 0 lines holding `the plan named`.
- **Negative control:** executed on `1d677ba` (P-9): Q lacks the sub-folders → RED; a mutation copying only the first level of each sub-folder → `reports/2026/r2.md` missing → RED; a mutation copying the sub-folders only → `Q/a.json` absent → RED (R3); a mutation without the backup exclusion → `Q/project.json.previous-20261030T000000Z` present → RED (R10); a mutation copying the top-level entries before the rows loop, with P holding `firmware_1.s19` byte-identical to the emitted image → the image row reuses it and the save aborts → RED (R11).
- **Boundary catalog:** ☒ empty ☒ boundary — no sub-folder; a nested sub-folder.

### LLR-171.1a — The save-as enumeration never descends into a directory link
- **Traceability:** HLR-171 · trace: `walk_tree_no_links`, `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS state):** While the system enumerates the open project's sub-folders for a save as, the system shall not descend into a directory that is a symbolic link or junction.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** a top-level directory junction (`P/linked` → an outside folder holding `secret.txt`) and a nested junction (`P/reports/j` → the same) → 0 files of the outside folder in Q; a junction cycle `P/flows/loop` → `P` → the save completes in under 5 s with 0 files copied through the cycle.
- **Negative control:** S-03's executed probe: `os.walk(P)` lists `flows\secret.txt` through a junction → RED; a mutation testing only `DirEntry.is_dir(follow_symlinks=False)` without the reparse-point re-check (Python 3.11 reads a junction as a plain directory) → `secret.txt` copied → RED.
- **Boundary catalog:** ☒ invalid — junctions at the top level, nested, and in a cycle.

### LLR-171.1b — The save-as copy skips a file link
- **Traceability:** HLR-171 · trace: `walk_tree_no_links`, `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS state):** While the system enumerates the open project's sub-folders for a save as, the system shall not copy a file that is a symbolic link.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** `P/patches/l.json`, a symbolic link to an outside file → 0 files at `Q/patches/l.json`, the link's target 0 bytes changed. Feasibility: creating a file symbolic link on Windows needs Developer Mode or the create-symlink privilege; when the test cannot create one it is reported as not run, never as passed.
- **Negative control:** a mutation following file links → `Q/patches/l.json` present → RED.
- **Boundary catalog:** ☒ invalid — a file symbolic link.

### LLR-171.1c — Each skipped link is named in the status
- **Traceability:** HLR-171 · trace: `_handle_save_dialog` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78
- **Statement (EARS event):** When the save-as enumeration skips a link or junction, the system shall name that link's project-relative path in the Save project status, within the 10-name limit of LLR-171.7a.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the three links of LLR-171.1a and LLR-171.1b → 3 of 3 project-relative paths named in the full `set_status` message (read whole, as TC-B100-16 does, because the status log clips at the terminal width, LED .64), with `links or junctions not copied` and `copy those files into the project if it needs them`; 0 links → 0 skip clauses; 25 links → 1 line naming 10 and holding `and 15 more` (orchestrator ruling R6, E3-security S3-4).
- **Negative control:** a mutation that skips silently → 0 of 3 named → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — no link; three links.

### LLR-171.1d — Bytes behind a link do not count toward the save-as total
- **Traceability:** HLR-171 · trace: `_handle_save_dialog` (`app.py`), `walk_tree_no_links` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS ubiquitous):** The system shall exclude every byte reached through a link or junction from the save-as size total.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the save-as total is T bytes (LLR-171.1i) and a junction in P reaches a 10 MiB outside file; with the work area's free space simulated at exactly T → the save completes (0 refusals).
- **Negative control:** security R2-06's probe: a plain walk descends the junction → total T + 10 MiB > T → refused → RED.
- **Boundary catalog:** ☒ invalid — a junction reaching a large file.

### LLR-171.1e — A save as larger than the free space is refused before any folder exists
- **Traceability:** HLR-171 · trace: `_handle_save_dialog` (`app.py`), `shutil.disk_usage`
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.78
- **Statement (EARS unwanted):** If the save-as size total exceeds the free space of the work area's volume, then the system shall refuse the save, with the `not enough free space` tokens, before creating the project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** with T the total of LLR-171.1i (each file rounded up to a multiple of 4 096 bytes, plus 65 536 bytes; orchestrator ruling R7), free space simulated at T − 1 → 1 status line holding `not enough free space` and `free disk space or remove files from the project`, 0 folders created, 0 bytes written; free space simulated at exactly T → the save completes.
- **Negative control:** a mutation checking after the folder is created → 1 folder exists after the refusal → RED; a mutation refusing at `total >= free` → the boundary arm is refused → RED.
- **Boundary catalog:** ☒ boundary ☒ error — exactly the free space; one byte over.

### LLR-171.1f — Save as leaves the open project unchanged
- **Traceability:** HLR-171 · trace: `_handle_save_dialog` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS ubiquitous):** The system shall not modify, add or remove any file of the open project when it saves that project into a new project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P's (path, SHA-256) set before and after the save as → 0 changed, 0 added, 0 removed.
- **Negative control:** a mutation moving the sub-folder files instead of copying them → P loses them → RED.
- **Boundary catalog:** ☒ boundary — a P with every sub-folder of LLR-171.1.

### LLR-171.1g — A save into an existing project copies no sub-folder of the open project
- **Traceability:** HLR-171 · trace: `_handle_save_dialog`, `_plan_project_save` (`app.py`) — orchestrator ruling Q2 (LED .77)
- **Ledger:** LED-2026-10-26-batch-100.77
- **Statement (EARS state):** While the Save project target is an existing project folder, the system shall not copy the open project's sub-folders into it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P open with the 7 sub-folders of LLR-171.1, saved into an existing project R (a merge) → 0 files of P's sub-folders in R other than the rows the gather places (the Patch Editor document, the composition documents, the CRC template), 0 sub-folder rows in the plan; P saved into itself → 0 sub-folder copies, P's tree unchanged apart from the gather's rows.
- **Negative control:** a mutation running the sub-folder copy for a merge target → `R/flows/f1.json` present → RED.
- **Boundary catalog:** ☒ boundary — a merge target; the open project as its own target.

### LLR-171.1h — Save as carries the open project's records into the new project.json
- **Traceability:** HLR-171 · trace: `_handle_save_dialog`, `_manifest_carry`, `_write_and_verify_manifest` (`app.py`) — orchestrator ruling Q7 (LED .77)
- **Ledger:** LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.80
- **Statement (EARS event):** When Save project saves the open project into a new project folder, the system shall write the open project's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` and `derived_from` records, as project-relative paths, into the new project's `project.json`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P holding the top-level `a.json` and `c.json`, whose `project.json` (written by the shipped Save project, so in the dialog's form: `batch` `["a.json"]`, `assignments` naming `c.json`) sets all 6 records, with no Patch Editor document in the session and nothing selected in the dialog, saved as Q → 6 of 6 records in Q's `project.json` equal to P's as project-relative strings, every file they name present in Q (copied with the top level and the tree, LLR-171.1), `gathered` = P's rows plus this save's rows (0 dropped); Q's `files` keeps its scope (top-level data and A2L files plus the active document, LLR-169.2); Load of Q → 0 `missing` problems. `batch` and `assignments` follow LLR-171.6 / .6a (a non-empty dialog selection wins). `derived_from` carries only the records whose key names a top-level data file Q holds after the save; a record for a variant file P no longer holds → not carried; when the image is emitted, its key holds this save's record (pre-ruling 9, E3-architect A3-8). A session that holds a Patch Editor document records its own landing as `active_document` (HLR-170), not P's value.
- **Linked source manifest (E5 SEC8b-3, LED-2026-10-26-batch-100.80):** P's `project.json` replaced by a file link to an outside manifest whose `batch` is `["OUTSIDE_BATCH_NAME.s19"]` after the load, saved as Q → saved, Q's `batch` does not hold `OUTSIDE_BATCH_NAME.s19` (0 records carried from a linked manifest), 1 line naming `project.json` with `links or junctions not copied`; pre snapshot (sha `b75f9125c9eb12c1`): Q's `batch` = the outside value (probe E1) → RED; a mutation without the `lstat` check → RED.
- **Negative control:** a mutation writing a fresh manifest for a save as → Q's `batch` empty → RED; a mutation carrying absolute paths → the serializer refuses the manifest → RED; a mutation dropping `derived_from` → Q lacks P's record for `firmware.s19` → RED. (The former fixture form `batch` `["patches/a.json"]` can only come from a hand-written manifest and is withdrawn, A3-2.)
- **Boundary catalog:** ☒ empty ☒ boundary — P with no records (0 carried); P with all 6.

### LLR-171.1i — The save-as total counts every byte the save writes
- **Traceability:** HLR-171 · trace: `_plan_project_save`, `_handle_save_dialog` (`app.py`) — orchestrator ruling Q8 (LED .77)
- **Ledger:** LED-2026-10-26-batch-100.77, LED-2026-10-26-batch-100.78
- **Statement (EARS ubiquitous):** The system shall count in the save-as size total every file the save as copies or writes — the top-level files, the emitted image and the sub-folder files — each rounded up to a multiple of 4 096 bytes, plus 65 536 bytes for `project.json` and the folders.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P with `firmware.s19` of 4 000 bytes, `firmware.a2l` of 1 200 bytes and 8 sub-folder files of 100 bytes, saved as Q with a pending patch (the emitted image is 5 000 bytes) → T = 8 192 + 4 096 + 8 × 4 096 + 65 536 = 110 592 bytes; free space simulated at 110 591 → refused (LLR-171.1e); at 110 592 → saved; files of 0, 1, 4 096 and 4 097 bytes count 0, 4 096, 4 096 and 8 192 (orchestrator ruling R7, E3-security S3-9: NTFS allocates per 4 KiB cluster, and `project.json` was not counted).
- **Negative control:** a mutation counting the sub-folder files only → free space T − 1 accepted → RED; a mutation counting the source image instead of the emitted bytes (4 096 rounded in place of 8 192) → T − 1 accepted → RED (the fixture's source and emitted image fall on different 4 KiB steps); a mutation summing raw sizes (72 536) → RED; a mutation without the 65 536-byte margin → RED.
- **Boundary catalog:** ☒ boundary — exactly the free space with the top-level files counted; file sizes on and one byte over a 4 KiB step.

### LLR-171.1j — A save as with too many files or too deep a tree is refused before any folder exists
- **Traceability:** HLR-171 · trace: `inventory_project_tree`, `plan_project_save` (`project_gather_service.py`), `walk_tree_no_links` (`workspace.py`, `max_entries`), `_handle_save_dialog` (`app.py`) — orchestrator rulings R1, R13 (`inc-8b/E3-rulings.md`), E3-security S3-1, S3R2-1
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79
- **Statement (EARS unwanted):** If the files a save as would copy from the open project number more than 2 000, the save-as enumeration walks more than 10 000 entries of the open project's tree, or an entry of that tree lies more than 32 path components deep, then the system shall refuse the save, naming the limit, before creating the project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** a copy list of 2 000 files (1 999 one-byte files under `reports/` plus the top-level `a.json`; `project.json` and the session's image are not in it) → saved, 2 000 copied files in Q; 2 001 → 1 status line holding `too many files to copy` and `move files out of the project, then save again`, 0 `mkdir` calls (spy), 0 bytes written; a file at 32 path components → saved; at 33 → 1 status line holding `nested too deep`, 0 `mkdir` calls; a walk of exactly 10 000 entries (folders, links, unreadable entries and files all count; `project.json`, `firmware.s19`, `reports/` and 9 997 empty folders under it) → saved; 10 001 entries with 0 files to copy → 1 status line holding `too many files to copy` and `over 10 000 entries`, 0 `mkdir` calls, the refusal painted in under 2 s; one folder of 50 000 files → refused with at most 10 001 entries read and no folder of more than 10 001 names sorted (R13, the ceiling read at call time). The time of the 2 000-file save is measured at E4 and reported, not gated: a background copy with progress and cancel stays with Inc 12a (R1).
- **Negative control:** the ceiling removed → the 2 001 arm saves → RED; a ceiling at `>=` → the 2 000 arm is refused → RED; the depth check removed → the 33 arm saves → RED; the entry count removed (regular files only) → the 10 001-folder arm passes the plan → RED (R13).
- **Boundary catalog:** ☒ boundary ☒ error — exactly 2 000 files, 10 000 entries and 32 components; one over each.

### LLR-171.1k — An unreadable part of the open project refuses the save as before any folder exists
- **Traceability:** HLR-171 · trace: `walk_tree_no_links` (`workspace.py`), `inventory_project_tree`, `plan_project_save`, `painted_names` (`project_gather_service.py`) — orchestrator ruling R8, E3-architect A3-5, E3-security S3-2, S3R2-6, pre-ruling 6
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79
- **Statement (EARS unwanted):** If the save-as enumeration cannot list a sub-folder of the open project or cannot classify one of its entries, then the system shall refuse the save, naming each such entry, before creating the project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** `P/reports/locked` that cannot be listed → 1 status line holding `reports/locked`, `could not be read` and `check that they can be opened, then save again`, 0 `mkdir` calls (spy), 0 bytes written; `P/flows/x.json.` (a name ending in a dot), alone and beside `P/flows/x.json` → the same refusal naming `flows/x.json.`; 12 such entries → 10 named and `and 2 more` (LLR-171.7a); 0 such entries → 0 such lines and the save goes on; the open project folder itself cannot be listed → the refusal names `'P'` (the project's name), never `.`; `P/NUL.txt` made through the `\\?\` form → the refusal names `NUL.txt` (reported as not run where the platform refuses to create the name). "Cannot classify" means `lstat` fails, the entry is neither a regular file, a folder nor a link, its name ends in a dot or a space, or its stem (case-insensitive, before the first dot) is a reserved device name: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `CONIN$`, `CONOUT$` (S3R2-6).
- **Negative control:** a mutation skipping an unlistable folder silently (the walker's behaviour at `ebe6d0c`, `workspace.py:296-299`) → saved, Q lacks the folder's files with 0 lines → RED; a mutation dropping an unclassifiable entry → saved with 0 lines → RED; a mutation without the device-name rule → `NUL.txt` reaches the copy list → RED (where the name can be created).
- **Boundary catalog:** ☒ invalid ☒ error — a trailing-dot name; a reserved device name; an unlistable folder; the unlistable project folder.

### LLR-171.1l — After a save as, the Flow panels use the new project folder
- **Traceability:** HLR-171 · trace: `_handle_save_dialog`, `_publish_flow_session_dir` (`app.py`) — orchestrator ruling R9, E3-architect A3-11
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.81
- **Statement (EARS event):** When a save as completes, the system shall make the new project folder the Flow panels' session folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P open, saved as Q → 1 session strip naming Q, 0 naming P, and the session folder equals `workarea/Q` (unresolved); a refused or failed save as → 0 changes to the session folder (it stays `workarea/P`).
- **Negative control:** base `ebe6d0c`: `_publish_flow_session_dir` has one caller, the load (`app.py:11427`) → the strip still names P after the save as → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a completed save as; a refused one.

### LLR-171.1m — After a save as, a Patch Editor document from the previous project is bound to its copy
- **Traceability:** HLR-171, HLR-170 · trace: `_handle_save_dialog` (`app.py`) — orchestrator ruling R9, E3-architect A3-11, E3-security S3R2-5
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79, LED-2026-10-26-batch-100.80
- **Statement (EARS event):** When a save as completes, the system shall bind a Patch Editor document whose file lies inside the previous project folder to that file's copy in the new project folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P open with the file-backed Patch Editor document `P/patches/boost.json`, saved as Q → the document's file is `workarea/Q/patches/boost.json` (unresolved, the 8a R12 spelling); an edit, then Save project → P's files 0 bytes changed; a document from outside P (the common folder) → its binding unchanged; the document is bound only to a file this save copied (an entry of the copy list) or to the document row's landing, never to a path whose part relative to P holds `..`: `workarea/P/../R/x.json` → binding unchanged and 0 writes under `workarea/R` on the next Save project; a document under a skipped junction of P → binding unchanged (S3R2-5). P records `patches/changes.json` and also holds a byte-identical `patches/changes_1.json` (E5 F5 (b), LED-2026-10-26-batch-100.80) → saved; the document is bound to the file the gather placed or reused in Q (the one Q's `active_document` names, which exists and holds the document's bytes), never to the planned name the gather did not write; pre snapshot: bound to `workarea/Q/patches/changes.json`, which does not exist → RED.
- **Negative control:** a mutation without the rebind → the document stays bound to `workarea/P/patches/boost.json` → RED; a mutation rebinding after a file-exists probe of the new path → the `..` arm binds `workarea/Q/../R/x.json` → RED (S3R2-5).
- **Boundary catalog:** ☒ boundary ☒ invalid — a document inside P; a document outside P; a `..` spelling; an identical sibling at the landing.

### LLR-171.1n — A save to a new folder while the open project folder is gone saves the session
- **Traceability:** HLR-171, HLR-164 · trace: `_handle_save_dialog`, `_save_as_source_for`, `_plan_project_save` (`app.py`) — E5 code review F1 (MAJOR, design-gap)
- **Ledger:** LED-2026-10-26-batch-100.80
- **Statement (EARS unwanted):** If the open project's folder does not exist when Save project saves to a folder that does not exist, then the system shall save the session's files to that folder without a copy from the open project and paint one status line naming the missing folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k open_project_folder_gone`
- **Numeric pass threshold:** P open, the session image loaded from outside P, `workarea/P` moved away outside the app; Save project under P's own name and as Q → each: `Saved project to`, the target holds the session image byte-equal, the open project is the target, 1 status line holding `The open project folder 'P' was not found`, `its other files were not copied` and `copy them into '<target>' if you still have them`, 0 lines holding `could not be read`. P still present, save as Q → P is copied (LLR-171.1) and 0 such lines.
- **Negative control:** pre snapshot (sha `b75f9125c9eb12c1`): both saves refused with `'P' could not be read — check that they can be opened, then save again`, no folder created (probe P-4) → RED; a mutation that ignores whether P's folder exists → the same refusal → RED.
- **Boundary catalog:** ☒ error ☒ boundary — P gone, saved under its own name; P gone, saved as Q; P present.

### LLR-171.1o — The save-as copy refuses when a folder above a copied file becomes a link
- **Traceability:** HLR-171, HLR-171b · trace: `_copy_project_subfolders` (`app.py`), `_path_traverses_reparse_point` (`workspace.py`) — E5 security SEC8b-2
- **Ledger:** LED-2026-10-26-batch-100.80
- **Statement (EARS unwanted):** If a folder from the work area down to a file the save-as copy reads, the open project folder included, is a link or junction when the copy reads that file, then the system shall refuse the save with a status line holding `changed while saving`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k p_itself_becomes_a_junction`
- **Numeric pass threshold:** P open; between the plan and the copy, `workarea/P` replaced by a junction to a look-alike folder outside every work area (same names, other bytes) → 1 line holding `changed while saving`, Q absent (the rollback, LLR-171.7b), 0 saved files; no swap → saved (every other save-as node).
- **Negative control:** pre snapshot: saved and Q holds the look-alike's bytes (probe B7: 15 of 16 files) → RED; a mutation with the check back to `contained_in_workarea(source, source_dir)` only → RED.
- **Boundary catalog:** ☒ invalid — the open project folder swapped for a junction after the S3-6 check.

### LLR-171.2 — An A2L-only project attaches its A2L
- **Traceability:** HLR-171a · trace: `_handle_load_project` (`app.py`), `_load_a2l_data_with_cache` (in place; not `load_a2l_from_path`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.24, LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS event):** When a project folder that holds one A2L file and no data file is loaded, the system shall attach that project's A2L file, in place, to the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `p04` 10 → 3 A2L tags, the Loaded panel names `firmware.a2l`, 0 status lines holding `No supported files`, 0 status lines holding `already has an A2L file`; the session's A2L path is the project's file (`workarea/P/firmware.a2l`, unresolved) and 0 files are created under `workarea/temp` (orchestrator ruling Q4, LED .77; Code-Wire C4).
- **Negative control:** executed on `1d677ba` (P-12): `No supported files in project: P` → RED; a mutation attaching through the Load-file A2L path (`load_a2l_from_path`) → a `workarea/temp` copy (or the `already has an A2L file` refusal of its own project) → RED.
- **Boundary catalog:** ☒ boundary — one A2L, no data file.

### LLR-171.2a — Loading an A2L-only project clears the previous data file
- **Traceability:** HLR-171a · trace: `_handle_load_project`, `_reset_project_session` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS event):** When a project folder that holds one A2L file and no data file is loaded, the system shall remove the previously loaded data file from the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** a data file loaded, then `p04` 10 loaded → 0 data files in the session (`current_file` is None), 0 images shown.
- **Negative control:** a mutation skipping the session reset on the A2L-only arm → the previous image stays → RED.
- **Boundary catalog:** ☒ boundary — a data file loaded before.

### LLR-171.2b — An A2L-only project becomes the open project
- **Traceability:** HLR-171a · trace: `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS event):** When a project folder that holds one A2L file and no data file is loaded, the system shall make that folder the open project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `p04` 10 → the open project is `P` (1 project label naming P), its folder the unresolved `workarea/P`.
- **Negative control:** a mutation not setting the project → the open project is None → RED.
- **Boundary catalog:** ☒ boundary — no project open before.

### LLR-171.2c — A data file loaded into an open A2L-only project is recorded
- **Traceability:** HLR-171a · trace: the variant append (`app.py`), `build_variant_set` (A-14)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS state):** While an A2L-only project is open, the system shall record a data file loaded into it in that project's `project.json`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `p04` 10 open, then Load file `firmware.s19` → `project.json` rewritten, 1 variant recorded, `active_variant` = `firmware`.
- **Negative control:** a mutation leaving the session's variant set empty (`None`) → the rewrite writes nothing → RED.
- **Boundary catalog:** ☒ boundary — the first data file of an A2L-only project.

### LLR-171.2d — A project with neither a data file nor an A2L is refused with its tokens
- **Traceability:** HLR-171a · trace: `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78
- **Statement (EARS unwanted):** If a project folder that holds a `project.json` holds neither a data file nor an A2L file, then the system shall refuse the load with the `no data or A2L file` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** such a folder → 1 status line holding `no data or A2L file` and `load a file and Save project` (UX-22), 0 session resets, the open project unchanged; the same folder whose `project.json` records the absent `firmware.s19` → the same 1 line, 0 resets (E3-architect A3-6: one line for both arms; the `missing` problem names absent records once a project loads, and the next step is true in both because the save rebuilds `files`).
- **Negative control:** a mutation painting `No supported files in project` → 0 tokens → RED.
- **Boundary catalog:** ☒ empty — a `project.json` and no data or A2L file.

### LLR-171.2e — A folder with no project.json and no project file is refused with its tokens
- **Traceability:** HLR-171a · trace: `_handle_load_project` (`app.py`), `PROBLEM_NO_MANIFEST` (`variant_execution_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.86
- **Status:** retired — superseded by LLR-173.4a (Inc 9b, Q7).
- **Statement (EARS unwanted):** If a folder given to the project load has no `project.json` and holds neither a data file nor an A2L file, then the system shall refuse the load with the `no project.json` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** such a folder (passed by name to the project load) → 1 status line holding `no project.json`, 0 session resets.
- **Negative control:** a mutation reaching the `no data or A2L file` branch for it → `no project.json` absent → RED.
- **Boundary catalog:** ☒ empty — an empty folder.

### LLR-171.2f — An A2L-only project whose A2L is a link or over the cap is refused before the session is reset
- **Traceability:** HLR-171a · trace: `_handle_load_project` (`app.py`), `DEFAULT_COPY_SIZE_CAP_BYTES` (`workspace.py`, read at call time) — orchestrator ruling R5, E3-security S3-3
- **Ledger:** LED-2026-10-26-batch-100.78
- **Statement (EARS unwanted):** If the A2L file of a project folder that holds no data file is a link or junction or is larger than the placement's per-file size cap, then the system shall refuse the load, with the `link or junction` or `too large to open` tokens, before resetting the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `workarea/P/firmware.a2l` a file symbolic link to an outside A2L, no data file → 1 status line holding `link or junction` and `replace the A2L file, then Load again`, 0 session resets, 0 parses of the outside file, the open project unchanged; with the cap lowered for the test, an A2L of cap + 1 bytes → 1 status line holding `too large to open`, 0 resets; an A2L of exactly the cap → the project opens with its A2L (3 tags). When the test cannot create a file link, that arm is reported as not run, never as passed (LLR-171.1b feasibility).
- **Negative control:** a mutation without the guard → the link arm parses the outside file and attaches it → RED; a mutation refusing at size ≥ cap → the exactly-the-cap arm is refused → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a linked A2L; exactly the cap; one byte over.

### LLR-171.2g — A project's linked or over-cap A2L beside a data file is left out and listed
- **Traceability:** HLR-171a, HLR-169 · trace: `_handle_load_project` (`app.py`) — orchestrator ruling R5, E3-security S3-3, S3R2-3
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79, LED-2026-10-26-batch-100.80
- **Statement (EARS unwanted):** If the A2L file of a project folder that holds a data file is a link or junction or is larger than the placement's per-file size cap, then the system shall open the project without that A2L file and list it as a `not readable` problem.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `firmware.s19` and a linked `firmware.a2l` → the project opens with its image, 0 A2L tags, the session holds no A2L, 1 `not readable` problem naming `firmware.a2l` with `link or junction` and `replace the A2L file, then Load again`; an A2L of cap + 1 bytes (cap lowered) → the same with `too large to open`; an A2L of exactly the cap → attached; `firmware.mac` and a linked `firmware.a2l` → the project opens with the MAC, 0 calls of the A2L parse with that path (spy on `_load_a2l_data_with_cache` and `parse_a2l_file`), the session holds no A2L, 1 `not readable` problem naming `firmware.a2l` (S3R2-3).
- **Painted next step (E5 F2, LED-2026-10-26-batch-100.80; ruling D-3 reversed):** the `not readable` row of that A2L paints `replace the A2L file, then Load again` (the `STEP_REPLACE_A2L` mark), never `Save project to drop it` — Save project does not drop the A2L (probe P-1: load, save, load again → the same row); pre snapshot: `replace the file, or Save project to drop it` → RED; a mutation without the mark → RED. Document-record rows keep the composer's step.
- **Negative control:** base `ebe6d0c`: `_handle_load_project` parses the project A2L in place with no link check and no cap (`app.py:11316`) → the outside A2L is parsed and attached → RED; a mutation dropping the problem → 0 `not readable` problems → RED; a mutation leaving the A2L out of the install-set choice only → the MAC load parses the linked A2L (1 parse call) → RED (S3R2-3).
- **Boundary catalog:** ☒ invalid ☒ boundary — a linked A2L beside an image; a linked A2L beside a MAC; exactly the cap; one byte over.

### LLR-171.2h — The A2L unload of a session with no data file detaches the A2L
- **Traceability:** HLR-171a · trace: `_apply_unload` (`app.py`), the Loaded panel's A2L slot (`screens_directionb.py`, ruling D-5) — E5 code review F3 (I-2)
- **Ledger:** LED-2026-10-26-batch-100.80
- **Statement (EARS event):** When the A2L unload is chosen in a session that holds an A2L file and no data file, the system shall detach that A2L file from the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k unload_of_an_a2l_only_session`
- **Numeric pass threshold:** an A2L-only project P open (3 A2L tags, no data file) → the A2L unload → the session holds no A2L, 0 tags, the status `Unloaded A2L.`, 0 lines `Nothing to unload.`; no A2L and no data file → `Nothing to unload.` (unchanged).
- **Negative control:** pre snapshot: `Nothing to unload.` and the A2L stays attached (probe P-3) → RED; a mutation without the A2L-only branch → RED.
- **Boundary catalog:** ☒ boundary — an A2L-only session; an empty session.

### LLR-171.3 — Save project refuses a parent other than this work area
- **Traceability:** HLR-171b · trace: `_handle_save_dialog` (`app.py`), `SaveProjectPayload.parent_folder` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.76
- **Statement (EARS unwanted):** If the Save project parent folder does not resolve to this work area, then the system shall refuse the save before creating any folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-33 — `pytest tests/test_b100_project_homes.py -k tc_b100_33`
- **Numeric pass threshold:** parent = another `.s19tool/workarea` → 1 status line starting `Project NOT saved` and 0 `mkdir` calls (a spy on folder creation, because the rollback already leaves 0 folders net); a parent outside any work area → the same; a parent below this work area (`workarea/patches`) → the same. The refusal's token row is drafted in E2 and confirmed in E3 (orchestrator ruling Q5).
- **Negative control:** base `ebe6d0c` (Code-Wire C2): the foreign parent is refused by the placement's explicit-root guard only after `project_dir.mkdir`, with the rollback removing the folder → the spy records 1 `mkdir` call → RED (P-11 at `1d677ba` is superseded as the control: there the save was accepted); a mutation accepting any parent below the work area (`is_relative_to` instead of equality) → `workarea/patches/P` created → RED.
- **Boundary catalog:** ☒ invalid ☒ error — another work area; outside any work area; below this work area.

### LLR-171.3a — The work area under another spelling is accepted as the parent
- **Traceability:** HLR-171b · trace: `_handle_save_dialog` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS event):** When the Save project parent folder resolves to this work area under a different spelling, the system shall save the project into this work area.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-33 — `pytest tests/test_b100_project_homes.py -k tc_b100_33`
- **Numeric pass threshold:** the work area with a trailing separator, in mixed case (Windows) and through a `..` segment → 3 of 3 saved, each listed once by the project list.
- **Negative control:** a mutation comparing the parent as text → the mixed-case arm is refused → RED.
- **Boundary catalog:** ☒ boundary — equivalent spellings.

### LLR-171.4 — Inside this work area means inside its resolved root
- **Traceability:** HLR-171b · trace: `contained_in_workarea` (`workspace.py`, B100-I14)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.20, LED-2026-10-26-batch-100.28, LED-2026-10-26-batch-100.44, LED-2026-10-26-batch-100.50, LED-2026-10-26-batch-100.65, LED-2026-10-26-batch-100.66, LED-2026-10-26-batch-100.68, LED-2026-10-26-batch-100.76
- **Statement (EARS ubiquitous):** The system shall judge a path inside this work area only when the path, with every link and junction resolved, equals the work area's resolved root or lies below it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_reuse.py -k tc_b100_62_containment_predicate` (Inc 1)
- **Numeric pass threshold:** written at Inc 1: a junction into another work area → outside; a plain outside folder → outside; the work area itself and a child → inside; a resolution `OSError` → outside (5 of 5).
- **Negative control:** executed (S-02 probe): `copy_into_workarea WROTE …\other\.s19tool\workarea\target\src.s19` at `1d677ba` → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — the root itself; junctions into another work area and outside.

### LLR-171.4a — A placement outside this work area is refused
- **Traceability:** HLR-171b · trace: `place_into_workarea` (LLR-163.1), which every placing writer uses
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS unwanted):** If a placement's destination is not inside this work area, then the system shall refuse the placement.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_reuse.py -k tc_b100_62` (Inc 1)
- **Numeric pass threshold:** written at Inc 1: a destination through a junction into another work area and through one to a plain outside folder → 2 refusals, 0 bytes written.
- **Negative control:** executed (S-02 probe) at `1d677ba`: `copy_into_workarea WROTE …` → RED.
- **Boundary catalog:** ☒ invalid — junctions into another work area and outside.

### LLR-171.4b — A manifest write outside this work area is refused
- **Traceability:** HLR-171b · trace: `write_project_manifest`, `_check_destination_contained` (`manifest_writer.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS unwanted):** If the `project.json` destination is not inside this work area, then the system shall refuse the manifest write.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_check.py -k tc_b100_62` (Inc 1 / LED .28)
- **Numeric pass threshold:** a project swapped for a junction into another work area → 0 bytes of `project.json` written outside.
- **Negative control:** executed (S-02 probe): `_check_destination_contained PASSED (no raise)` at `1d677ba` → RED.
- **Boundary catalog:** ☒ invalid — a junction project folder.

### LLR-171.4c — A link or junction folder is not listed as a project
- **Traceability:** HLR-171b · trace: `list_projects` (`app.py`), `_is_reparse_point` (`workspace.py`); absorbs the withdrawn LLR-171.4d's arm (orchestrator ruling Q6, LED .77)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS unwanted):** If a folder of the work area is a link or junction, then the system shall leave that folder out of the project list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** `workarea/evil` (a junction into another work area's project) → 0 rows; `workarea/alias` (a junction to `workarea/P`) → 0 rows while `P` is listed once; a junction to a plain outside folder → 0 rows; a normal project → 1 row.
- **Negative control:** executed (S-02 probe) on `1d677ba`: the junction folder is listed → RED; a mutation without the link check → `alias` listed → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — a normal folder; junctions into another work area, into this work area and outside.

### LLR-171.4d — Withdrawn: merged into LLR-171.4c
- **Traceability:** HLR-171b
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Status:** withdrawn at Inc 8b E1 by orchestrator ruling Q6 (LED .77). It had no independent RED: a direct child of the work area resolves outside only through a link or junction, which LLR-171.4c drops. Its arm (`workarea/evil` → 0 rows) is LLR-171.4c's first arm. The id is kept and not reused.

### LLR-171.4e — A link or junction project folder is not loaded
- **Traceability:** HLR-171b · trace: `_handle_load_project` (`app.py`), `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If a project folder to be loaded is a link or junction, then the system shall refuse the load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** `evil` and `alias`, each picked from a list built before the junction appeared (the picked arm, the only load path at 8b: `_route_load_project`) → 0 loads, 0 session resets, 1 status line each. The typed arm is LLR-172.5d's, at Inc 9a. The refusal's token row is drafted in E2 and confirmed in E3 (orchestrator ruling Q5).
- **Negative control:** a mutation without the link check → `alias` loads → RED.
- **Boundary catalog:** ☒ invalid — junctions into another work area and into this work area.

### LLR-171.4f — A project folder resolving outside this work area is not loaded
- **Traceability:** HLR-171b · trace: `_handle_load_project` (`app.py`), `contained_in_workarea` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.80, LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If a project folder to be loaded is not one direct child folder of this work area or resolves outside this work area, then the system shall refuse the load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** a picked name with `..` segments that reaches another work area's project (no link involved) → 0 loads, 0 session resets, 1 status line holding `outside the work area`; a picked name `sub/P` with `workarea/sub` a junction to `workarea/R` → 0 loads, 0 resets (E3-security S3-7); `evil` → 0 loads. The typed arms are LLR-172.5c's (outside the work area) and LLR-172.5d's (through a link or junction), at Inc 9a. `lstat` of the picked folder fails with a permission error (E5 F7(a), LED-2026-10-26-batch-100.80) → refused with 1 line holding `could not be read` and `check that the folder can be opened, then load again` (the Save project target: `then save again`), 0 lines holding `outside the work area` or `is not the work area folder`; pre snapshot: the `outside` texts → RED; a mutation mapping the error to `outside` → RED.
- **Negative control:** a mutation without the one-component name check (S3-7) → the `..` name and `sub/P` load → RED. The containment check stays as defence and, after the name check, has no independent RED (declared, as for LLR-171.4d).
- **Boundary catalog:** ☒ invalid — `..` segments; a junction into another work area.

### LLR-171.4g — A Save project target that is a link or junction is refused before it is resolved
- **Traceability:** HLR-171b · trace: `_handle_save_dialog` (`app.py`, the HLR-164(f) check), `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS unwanted):** If the Save project target folder is a link or junction, then the system shall refuse the save, with the `link or junction` tokens, before resolving the target.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** typing `evil` (new name) and typing it while it is a merge target → 2 status lines holding `link or junction` and `choose another name`, 0 folders created, 0 bytes written outside this work area.
- **Negative control:** a mutation resolving the target before the check → the check sees a plain folder and the save writes through it → RED.
- **Boundary catalog:** ☒ invalid — a junction as a new and as a merge target.

### LLR-171.4h — Eight writers write nothing outside this work area
- **Traceability:** HLR-171b · trace: `place_into_workarea` (LLR-171.4a) and `write_project_manifest` (LLR-171.4b), reached by the writers below
- **Ledger:** LED-2026-10-26-batch-100.76
- **Statement (EARS ubiquitous):** The system shall write 0 bytes outside this work area through Save project (new name, merge and emit), the save-back, the variant append, the MAC sync, the A2L sync and the manifest seam.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** for each of the 8 writers, with the open or target project folder swapped for a junction into another work area's project, and again for a junction to a plain outside folder → 0 bytes written outside (16 of 16 arms); a normal project → each writer writes inside (8 of 8).
- **Negative control:** a mutation removing the containment check from `place_into_workarea` → at least 1 writer writes outside → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — a normal folder; junctions into another work area and outside, for each writer.

### LLR-171.4i — A flow is not saved outside this work area
- **Traceability:** HLR-171b · trace: `save_flow_json` (`flow_persistence_service.py`), reached from `on_flow_builder_panel_save_requested` (`app.py`) — SEC-5, Code-Wire C1. **Not in Inc 8b:** routed to the LED .50 backlog item and `.dev-flow/BACKLOG-CODE.md` by orchestrator ruling Q1 (LED .77).
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS unwanted):** If the folder a flow is saved into is not inside this work area, then the system shall refuse to save the flow.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** `P/flows` a junction to an outside folder → 0 files in the outside folder, 1 refusal; a normal `P/flows` → the flow saved.
- **Negative control:** executed (`sec_inc1_r2_flow_probe.out`): `files in the OUTSIDE folder: ['probe.json']` → RED.
- **Boundary catalog:** ☒ invalid — a junction `flows/`.

### LLR-171.4j — A flowset is not saved outside this work area
- **Traceability:** HLR-171b · trace: `save_chain_set` / the flowset writer (`flow_persistence_service.py`), reached from `on_flow_execution_panel_save_requested` (`app.py`) — SEC-5, Code-Wire C1. **Not in Inc 8b:** routed to the LED .50 backlog item and `.dev-flow/BACKLOG-CODE.md` by orchestrator ruling Q1 (LED .77).
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.77
- **Statement (EARS unwanted):** If the folder a flowset is saved into is not inside this work area, then the system shall refuse to save the flowset.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-62 — `pytest tests/test_b100_project_homes.py -k tc_b100_62`
- **Numeric pass threshold:** `P/flowsets` a junction to an outside folder → 0 files in the outside folder, 1 refusal; a normal `P/flowsets` → the flowset saved.
- **Negative control:** a mutation leaving the flowset writer's plain `mkdir` and `write_text` → 1 file outside → RED (the SEC-5 probe pattern).
- **Boundary catalog:** ☒ invalid — a junction `flowsets/`.

### LLR-171.5 — A copied file project.json cannot record is named in the status
- **Traceability:** HLR-171 · trace: `gather_project_artifacts` (`project_gather_service.py`, the review F1 device-stem guard), `_handle_save_dialog` (`app.py`) — BACKLOG-CODE R2-1
- **Ledger:** LED-2026-10-26-batch-100.76, LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.80
- **Statement (EARS unwanted):** If Save project copies into the project a file whose project-relative path `project.json` cannot record, then the system shall paint one status line naming that file.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the active CRC template is a file outside the project whose name `project.json` cannot record (`con.json`, created where the platform allows it; otherwise reported as not run) → the save completes, 1 status line naming `templates/con.json` with `copied but not recorded`, `Windows reserves that name` and `rename it in the common folder, select the new name, then Save project`, 0 raises; no such file → 0 such lines. The 10-line cap (12 rows → 10 lines and 1 line holding `and 2 more`, LLR-171.7a) is verified at the painting seam with `GatherOutcome.unrecorded` injected, because one save gathers at most one template; a row refused for another reason than a device stem → `the name is not one project.json records` (no length rule exists; E5 F4, LED-2026-10-26-batch-100.80). A dialog `batch` entry with a device stem fails the whole save at the manifest writer (pre-existing, backlog), so it is not this requirement's example. The active document keeps its own Inc 8a finding and never gets a second line (pre-ruling 7). The save-as tree copy records nothing in `project.json`, so it adds no line here.
- **Negative control:** base `ebe6d0c` (R2-1, code read, not executed): the row is copied and left out of `gathered` with 0 status lines → RED expected; a mutation dropping the line → RED.
- **Boundary catalog:** ☒ invalid — a device-stem name.

### LLR-171.6 — Save project keeps the carried batch when the dialog selects none
- **Traceability:** HLR-171, HLR-164 · trace: `_handle_save_dialog` (`app.py`), `SaveProjectPayload.batch` (`screens.py`) — orchestrator ruling R4, E3-architect A3-3 (C-7 confirmed)
- **Ledger:** LED-2026-10-26-batch-100.78
- **Statement (EARS event):** When Save project writes the target's `project.json`, the system shall record as `batch` the Save dialog's batch selection when that selection is non-empty, and otherwise the carried `batch` value.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the carried value is the open project's for a save as, the target's for a save into the open project or a merge, and none for a fresh session's new folder. P with `batch` `["a.json"]` (written by the shipped Save project) loaded, Save project into P with nothing selected → P's `batch` `["a.json"]` (0 changed); then save as Q with nothing selected → Q's `batch` `["a.json"]` and Q holds `a.json` (LLR-171.1); a merge into R whose `batch` is `["r.json"]`, nothing selected → R's `batch` `["r.json"]`; a selection `["b.json"]` → `batch` `["b.json"]` for each of the three targets. An empty selection cannot clear a `batch`: an untouched dialog and an empty selection cannot be told apart (A3-3, G1 R-10).
- **Negative control:** base `ebe6d0c`: `app.py:10097-10098` writes the dialog's selection for every target → P's `batch` `[]` after the save into P → RED; a mutation writing the selection only → the same → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no selection; a selection; the three target kinds.

### LLR-171.6a — Save project keeps the carried assignments when the dialog selects none
- **Traceability:** HLR-171, HLR-164 · trace: `_handle_save_dialog` (`app.py`), `SaveProjectPayload.assignments` (`screens.py`) — orchestrator ruling R4, E3-architect A3-3
- **Ledger:** LED-2026-10-26-batch-100.78
- **Statement (EARS event):** When Save project writes the target's `project.json`, the system shall record as `assignments` the Save dialog's assignment selection when that selection is non-empty, and otherwise the carried `assignments` value.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the carried value as in LLR-171.6. P with `assignments` naming `c.json` for `firmware` loaded, Save project into P with nothing selected → P's `assignments` unchanged; then save as Q with nothing selected → Q's `assignments` equal P's and Q holds `c.json`; a merge into R with nothing selected → R's `assignments` unchanged; a selection → the selection for each of the three targets.
- **Negative control:** base `ebe6d0c`: `app.py:10097-10098` writes the dialog's selection for every target → P's `assignments` `{}` after the save into P → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no selection; a selection; the three target kinds.

### LLR-171.6b — The gather takes the composition documents from the recorded batch and assignments
- **Traceability:** HLR-171, HLR-164 · trace: `_handle_save_dialog` (`app.py`), `gather_project_artifacts` (`project_gather_service.py`, unchanged) — orchestrator ruling R4, E3-architect A3-3, A3R2-3, A3R2-4
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79
- **Statement (EARS event):** When Save project gathers the composition documents, the system shall take their names from the `batch` value that LLR-171.6 records plus the names in the `assignments` value that LLR-171.6a records.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P with `batch` `["a.json"]`, P's top-level `a.json` and `patches/a.json` removed, the common library holding `a.json`, Save project into P with nothing selected → the `composition_names` passed to the gather hold `a.json` (spy) and `P/patches/a.json` is present (gathered this save); the same P with `assignments` naming `c.json` for `firmware`, P's top-level `c.json` and `patches/c.json` removed, the common library holding `c.json` → the `composition_names` hold `a.json` and `c.json` and `P/patches/c.json` is present (LLR-138.1 kept).
- **Negative control:** base `ebe6d0c`: `app.py:9932-9936` builds the list from the dialog's selection → the `composition_names` spy holds 0 names, `P/patches/a.json` absent → RED; a mutation feeding the gather from the recorded `batch` only → `c.json` absent from the spy and `P/patches/c.json` absent → RED.
- **Boundary catalog:** ☒ empty — no selection with a carried `batch` and carried `assignments`.

### LLR-171.7 — Names from the open project's tree are painted scrubbed and clipped
- **Traceability:** HLR-171 · trace: `painted_names` (NEW, `project_gather_service.py`), `_handle_save_dialog`, `_copy_project_subfolders` (`app.py`) — orchestrator ruling R6, E3-security S3-4, S3R2-4, SEC8a-4
- **Ledger:** LED-2026-10-26-batch-100.78, LED-2026-10-26-batch-100.79
- **Statement (EARS ubiquitous):** The system shall paint each name taken from the open project's tree without characters of the Unicode categories Cc, Cf, Zl and Zp, with each unpaired surrogate replaced by U+FFFD, and clipped to 120 characters.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** a skipped junction named `patches/` + U+202E + `osj.exe.json` → the painted line holds `patches/osj.exe.json` and 0 characters of the categories Cc, Cf, Zl or Zp (U+0000–U+001F, U+007F–U+009F, U+200B–U+200F, U+202A–U+202E, U+2066–U+2069 among them); names holding U+061C, U+2028 and the unpaired surrogate U+DC80 → painted without U+061C and U+2028 and with U+FFFD in place of U+DC80, 0 raises in the paint or the log, the log holding each name in its escaped (`%r`) form; a name of 300 characters → painted as 120 characters ending in `…`; a plain name → painted unchanged. The rule covers every Inc 8b line that names an entry of P's tree: rows 7, 8 and 11 and the refusals that name a file.
- **Negative control:** a mutation without the scrub → U+202E painted → RED; a mutation scrubbing round 1's fixed list instead of the categories → U+061C painted → RED (S3R2-4); a mutation without the clip → 300 characters painted → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a bidi character; a line separator; an unpaired surrogate; a name of exactly 120 and of 300 characters.

### LLR-171.7a — A status list names at most 10 entries of the open project's tree
- **Traceability:** HLR-171 · trace: `painted_names` (NEW, `project_gather_service.py`), `_handle_save_dialog` (`app.py`) — orchestrator ruling R6, E3-security S3-4
- **Ledger:** LED-2026-10-26-batch-100.78
- **Statement (EARS event):** When Save project would name more than 10 entries of the open project's tree in one status list, the system shall paint the first 10 entries followed by `and K more`, K being the number of entries not named.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** 25 skipped junctions → 1 line naming 10 and holding `and 15 more`; 12 unrecorded gathered rows → 10 lines and 1 line holding `and 2 more`; 12 unreadable entries → the refusal names 10 and holds `and 2 more`; exactly 10 entries → 10 named, 0 `more`.
- **Negative control:** a mutation naming every entry → 25 named → RED; a limit of 9 → the 10-entry arm holds `more` → RED.
- **Boundary catalog:** ☒ boundary — exactly 10 entries; 11 and more.

### LLR-171.7b — A failed save-as copy is reported in user terms
- **Traceability:** HLR-171 · trace: `_copy_project_subfolders` (NEW), `_handle_save_dialog`, `_abort_save` (`app.py`) — orchestrator ruling R6, E3-security S3-4, S3-5
- **Ledger:** LED-2026-10-26-batch-100.78
- **Statement (EARS unwanted):** If a save-as copy fails after the project folder is created, then the system shall paint the `could not save` and `check the folder` tokens naming the file, with no exception text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** the 4th of 8 copies raising `PermissionError` → 1 status line holding `could not save`, the file's project-relative path and `check the folder`, 0 lines holding `WinError` or `Refusing`, Q absent and P 0 bytes changed (LLR-164.4, LLR-171.1f); `P/reports` swapped for a junction after the plan → the same line holding `changed while saving`.
- **Negative control:** a mutation without the copy's own exception handling → the existing handlers (`app.py:10123-10180`) paint the exception text (`[WinError 5] …`) → RED.
- **Boundary catalog:** ☒ error — a copy that raises; a source changed during the copy.

### LLR-171.7c — The rollback of a failed save never removes a file through a changed folder
- **Traceability:** HLR-164, HLR-171 · trace: `_abort_save`, `_PlacedFiles` (`app.py`), `_path_traverses_reparse_point` (`workspace.py`) — E5 security SEC8b-1 (the mechanism is from Inc 2, LED .53; save as widens it)
- **Ledger:** LED-2026-10-26-batch-100.80
- **Statement (EARS unwanted):** If a failed Save project's rollback finds a file it recorded under a folder that is now a link or junction, or a file whose `(st_dev, st_ino)` differs from the one recorded when the save wrote it, then the system shall keep that file and paint one status line naming it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k rollback_never_deletes`
- **Numeric pass threshold:** a save as fails right after its last `reports` copy, once `Q/reports` (a) is replaced by a junction to another project's `R/reports` holding files of the same names → R's 7 files unchanged; (b) is replaced by a junction to Q's own moved folder → the 7 copies kept; (c) holds a user's file moved over Q's first copy → that file kept with its bytes; each arm: 1 line holding `Not removed after the failed save` and `a folder changed while saving`, 0 lines holding `WinError`. No change → every file the save wrote is removed and Q is absent (LLR-171.7b).
- **Negative control:** pre snapshot: (a) R's files deleted (probe B3: 6 of 7) → RED; a mutation without the reparse check → (b) RED; a mutation without the identity check → (c) RED.
- **Boundary catalog:** ☒ error ☒ invalid — a folder swapped for a junction; a file replaced; no change.

### LLR-172.1 — The recent-sources store lives in the per-user local profile
- **Traceability:** HLR-172 · trace: `recent_store_path` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.30, LED-2026-10-26-batch-100.41, LED-2026-10-26-batch-100.82
- **Statement (EARS ubiquitous):** The system shall keep the recent-sources store at `%LOCALAPPDATA%\s19_app\recent_sources.json`, in the per-user profile folder that does not roam.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`; an autouse fixture in `tests/conftest.py` points `LOCALAPPDATA` at `tmp_path` for every test (Inc 9a)
- **Numeric pass threshold:** `LOCALAPPDATA` = `<tmp>/lad`, 1 outside load → 1 file at `<tmp>/lad/s19_app/recent_sources.json` and 0 files named `recent_sources.json` under the base folder (`.s19tool` included); the real `%LOCALAPPDATA%\s19_app\recent_sources.json` → its SHA-256 (or its absence) unchanged after a full test run (1 guard, LED .41).
- **Negative control:** code read on `4fef292`: `grep -rn LOCALAPPDATA s19_app` → 0 hits, so 0 store files after the load → RED; a mutation writing to `<base>/.s19tool/recent_sources.json` (the round-2 location) → the base-folder arm RED; a mutation reading `APPDATA` (the round-3 location, LED .30) → 0 files at the `LOCALAPPDATA` path → RED.
- **Boundary catalog:** none — one location; the unusable-variable cases are LLR-172.1f.

### LLR-172.1a — A source loaded from outside the work area is recorded first
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW, `workspace.py`); `load_from_path`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When Load copies a data or A2L file from outside this work area into the work area, the system shall put that file's absolute path and its kind first in the recent-sources store.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** the absolute path is the lexical form `os.path.abspath` gives (`.` and `..` folded, no link resolved, no network call), so a mapped network drive keeps its letter. `examples/case_01_basic_valid/firmware.s19` typed into Load → the store reads `{"schema_version": 1, "sources": [{"path": <the absolute path>, "kind": "s19"}]}` (1 entry); a relative `firmware.s19` found in the working folder `<src>` → `<src>\firmware.s19`; `<tmp>/j/x.s19` with `<tmp>/j` a junction to `<tmp>/real` → `<tmp>\j\x.s19` (Windows only; reported not run, never passed, when no junction can be made); then an outside `.a2l`, `.mac` and `.hex` → 4 entries, newest first, kinds `hex`, `mac`, `a2l`, `s19`. The kind follows the suffix, case-folded: `.s19` and `.srec` → `s19`, `.hex` and `.ihex` → `hex`, `.mac` → `mac`, `.a2l` → `a2l` (the load's own sets, `workspace.py:107-110`); `<tmp>/A.SREC` → kind `s19`. The entry is written once the copy into `workarea/temp` succeeds (Q1).
- **Negative control:** code read on `4fef292` (LLR-172.1) → 0 entries → RED; a mutation recording the work copy's path (`workarea/temp/firmware.s19`) → the path arm RED; a mutation appending the entry last → the order arm RED; a mutation recording `Path.resolve()` → the junction arm records `<tmp>\real\x.s19` → RED (on a mapped network drive the same mutation gives the `\\server\share` form, which LLR-172.2e drops; E3 A9-1).
- **Boundary catalog:** ☒ boundary — each of the 4 kinds; `.srec` in upper case.

### LLR-172.1b — A source already in the store keeps one entry
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When the system records a source whose absolute path is already in the recent-sources store, the system shall keep one entry for that path, in first place.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** paths are compared with `os.path.normcase` after `os.path.abspath` (stored texts are not re-normalised). The same file twice → 1 entry; the same file spelled in another case (`<d>\A.s19`, then `<D>\a.S19`) → 1 entry, its text the second call's; `<d>\sub\..\A.s19` after `<d>\A.s19` → 1 entry; A, then B, then A → 2 entries, A first. Two link spellings of one file make two entries (declared; the list is a convenience). The case arm is Windows only (`normcase` folds case only there), reported not run on the Linux CI.
- **Negative control:** a mutation without the de-duplication → 2 entries for the same file → RED; a mutation keeping the old position → B first → RED; a case-sensitive comparison → 2 entries for the case arm → RED.
- **Boundary catalog:** ☒ boundary — the same file; another case spelling.

### LLR-172.1c — The store holds at most 20 entries
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS ubiquitous):** The system shall keep at most 20 entries in the recent-sources store, dropping the oldest entry first.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** 20 distinct sources recorded → 20 entries, source 1 last; the 21st → 20 entries, source 1 gone, source 21 first; 25 → 20 entries, entry 1 = source 25, entry 20 = source 6.
- **Negative control:** a mutation capped at 21, or uncapped → 21 entries after the 21st → RED; a mutation dropping the newest → source 21 missing → RED.
- **Boundary catalog:** ☒ boundary — the 20th and the 21st entry.

### LLR-172.1d — A load that fails before its copy records nothing
- **Traceability:** HLR-172 · trace: `load_from_path`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If a Load fails before its copy into the work area completes, then the system shall leave the recent-sources store unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** a store holding 1 entry, then: a path that does not exist, a file with an unsupported suffix, an outside source over the placement's per-file cap (the cap lowered in the test; `Cannot load file:`), and an outside A2L while the open project already holds an A2L (`Project already has an A2L file.`) → the store's SHA-256 unchanged after each of the 4 arms. A data file that copies and then fails to parse is recorded (Q1, declared).
- **Negative control:** a mutation recording before the copy → the over-cap arm adds 1 entry → RED.
- **Boundary catalog:** ☒ error — the 4 failure arms.

### LLR-172.1e — A source inside this work area is not recorded
- **Traceability:** HLR-172 · trace: `load_from_path`, `load_a2l_from_path` (`app.py`); `contained_in_workarea` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the source a load copies lies inside this work area, then the system shall not record that source in the recent-sources store.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** typed `<workarea>/ab/firmware.s19`, a Workarea Files pick of an `.a2l` work copy (`_load_from_item` → `load_a2l_from_path`) and a variant switch (`_handle_select_variant` → `load_from_path` with the project's variant) → 0 entries for each of the 3 arms. "Inside" is §1.3's (`contained_in_workarea`).
- **Negative control:** a mutation without the inside check → typed `<workarea>/ab/firmware.s19` adds 1 entry → RED.
- **Boundary catalog:** ☒ boundary — a project's own file; a work copy; a variant.

### LLR-172.1f — No usable `LOCALAPPDATA`, no store file
- **Traceability:** HLR-172 · trace: `recent_store_path`, `record_recent_source` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If `LOCALAPPDATA` is unset, is empty, does not start with a drive letter followed by a root, or names a folder that does not exist, then the system shall write no recent-sources store file.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** the drive-and-root test is the text test `^[A-Za-z]:[\/]` on every platform. `LOCALAPPDATA` unset, `""`, `relative\lad`, `/tmp/lad` (a POSIX absolute path) and `<tmp>/absent` (drive-rooted, no such folder; only the `s19_app` folder is ever created, never its parents), the process working folder set to `<tmp>` → 0 files named `recent_sources.json` under `<tmp>` and the base folder, 0 folders created, the image installed, 0 raises (5 of 5 arms). Tester note: every fixture value derives from `tmp_path`, never a literal drive path (off Windows a `C:\…` text passes the test and names a relative folder).
- **Negative control:** a mutation using a relative `LOCALAPPDATA` as a folder → `<tmp>/relative/lad/s19_app/recent_sources.json` written → RED; a mutation falling back to `Path.home()` → 1 file → RED; a mutation creating the missing parents (`mkdir(parents=True)`) → `<tmp>/absent/s19_app/recent_sources.json` written → RED.
- **Boundary catalog:** ☒ error — unset; empty; relative; a POSIX absolute path; a folder that does not exist.

### LLR-172.1g — A linked store folder is not written
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW), `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the store folder `%LOCALAPPDATA%\s19_app` is a link or junction, then the system shall not write the recent-sources store.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** `<tmp>/lad/s19_app` a junction to `<tmp>/elsewhere` → 0 files in `<tmp>/elsewhere` after an outside load, the image installed, 0 raises.
- **Negative control:** a mutation without the reparse-point check → 1 file in `<tmp>/elsewhere` → RED.
- **Boundary catalog:** ☒ invalid — a junctioned store folder.

### LLR-172.1h — The store is replaced through a uniquely named staging file
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS ubiquitous):** The system shall write the recent-sources store through a staging file with a unique name in the store folder and then replace the store in one step.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** 100 records → 100 distinct staging names (a spy on the staging creation), each in `%LOCALAPPDATA%\s19_app`, 100 `os.replace` calls onto `recent_sources.json`, 0 staging files left; a read of the store file after each of the 100 records → it parses as version 1 each time, 0 partial files (S-12: a reader sees the old or the new file). Every record runs on the UI thread, so no two writers of one process exist; two app instances are last-writer-wins, never a broken file (accepted, E3 A9-4).
- **Negative control:** a mutation with a fixed staging name → 1 distinct name in 100 → RED; a mutation writing the store in place → 0 `os.replace` calls → RED.
- **Boundary catalog:** ☒ boundary — 100 successive records.

### LLR-172.1i — A failed store write never fails the load
- **Traceability:** HLR-172 · trace: `record_recent_source` (NEW, `workspace.py`); `load_from_path`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If writing the recent-sources store fails, then the system shall complete the load with the store left as it was.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** `os.replace` raising `PermissionError` and the staging creation raising `OSError` (2 injected arms), for a data file and for an A2L → the file installed as without the store, 0 raises out of the load, the store's SHA-256 unchanged, 0 staging files left, 1 log warning and 0 status lines about the store (Q5) — 4 of 4.
- **Negative control:** a mutation letting the `OSError` out → the load stops before the install → RED.
- **Boundary catalog:** ☒ error — the 2 injected failures.

### LLR-172.1j — Recording writes back only the entries the store read accepts
- **Traceability:** HLR-172 · trace: `record_recent_source`, `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When the system writes the recent-sources store, the system shall carry over only those existing entries that the store read (LLR-172.2) returns.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** a store holding 2 accepted entries and 3 refused ones (`\\host\share\x.s19`, `kind: exe`, a path holding `\x1b[2J`) → after 1 record: 3 entries, 0 refused; an unparseable store and a 65 537-byte store → after 1 record: 1 entry each. A store the read reports `could not be read` is not written (LLR-172.1k), and a source the read would drop is not recorded (LLR-172.1l).
- **Negative control:** a mutation carrying the raw entries forward → the UNC entry written back → RED.
- **Boundary catalog:** ☒ invalid ☒ error — refused entries; an unparseable and an oversized store.

### LLR-172.1k — An unreadable store is left unchanged by a record
- **Traceability:** HLR-172 · trace: `record_recent_source`, `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the store read reports `could not be read` while the system records a source, then the system shall leave the recent-sources store unchanged.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** a store holding 3 accepted entries, then 1 record of an outside `<src>\n.s19` with (1) the store open raising `PermissionError` (injected, as a transient sharing violation) and (2) the store read raising `OSError` (injected) → the store's SHA-256 unchanged, `record_recent_source` returns `False`, 0 staging files, 0 raises (2 of 2). Through Load the image is installed as without the store.
- **Negative control:** a mutation treating `could not be read` as an empty store → after the record the store holds 1 entry, its SHA-256 changed → RED (a transient read failure would wipe 20 entries to 1, G1 R-2).
- **Boundary catalog:** ☒ error — a refused open; a failed read.

### LLR-172.1l — A source the store read would drop is not recorded
- **Traceability:** HLR-172 · trace: `record_recent_source`, `_recent_entry_ok` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the absolute path of the source to record fails an entry check of the store read (LLR-172.2e, LLR-172.2f or LLR-172.2g), then the system shall not record that source.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** a store holding 1 accepted entry, then 3 records: `\\host\share\x.s19` (UNC; `abspath` keeps it), `<src>\a` + U+009B + `.s19` (a control character) and `C:\CON\a.s19` (a device component) → `False` each, the store's SHA-256 unchanged, 0 staging files, 0 raises (3 of 3); `<src>\b.s19` → `True`, 2 entries (control arm). A typed UNC source loads but is not remembered (declared); a mapped drive letter is remembered (LLR-172.1a).
- **Negative control:** a mutation writing without the entry check → the UNC entry is written (SHA-256 changed) and dropped again on the next read → RED.
- **Boundary catalog:** ☒ invalid — a UNC path; a control character; a device component.

### LLR-172.1m — The store file the writer produces fits the read's size cap
- **Traceability:** HLR-172 · trace: `record_recent_source`, `_encode_recent_store` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.83
- **Statement (EARS ubiquitous):** The system shall keep each recent-sources store file it writes at most 65 536 bytes long, dropping the oldest entries first.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** (unit arms; the record reads no source, so the paths need not exist) 20 entries `C:\` + 3 240 × `p` + `.s19` → 65 492 bytes, 20 entries kept; 20 entries of 3 245 × `p` → 19 entries kept, 62 314 bytes, the oldest dropped; 1 new entry `C:\` + 11 000 × `é` + `.s19` (its path alone 66 008 bytes escaped) → 0 writes, the store's SHA-256 unchanged, `False` (3 of 3).
- **Note (E3 R10, the cap kept):** the store bytes are `json.dumps(..., ensure_ascii=True, separators=(",", ":"))`; the document costs 32 bytes and each entry 25 bytes plus its escaped path (probe p9a-g1: `32 + k × (33 + n)` for a path of `n + 7` characters), so 20 entries fit only if each escaped path is at most (65 536 − 32) / 20 − 25 = 3 250 bytes. The store read has no per-entry length bound (LLR-172.2e … LLR-172.2i check the form only), so the bound is the operating system's: with long paths off a path is at most 259 UTF-16 units, at most 6 bytes each escaped (`\uXXXX`; an astral character is 2 units and 12 bytes) → at most about 1 554 bytes, which fits; with `LongPathsEnabled` a path reaches 32 767 units → up to about 196 602 bytes, which does not. Without this requirement a store above 65 536 bytes reads as `too large` (LLR-172.2a) and the next record keeps 1 entry (LLR-172.1j). So the cap stays.
- **Negative control:** a mutation without the size rule → the 3 245 arm writes 65 592 bytes, which the next read reports `too large` → RED; a mutation dropping the newest → the new entry missing → RED.
- **Boundary catalog:** ☒ boundary — 65 492 and 65 592 bytes; one entry that cannot fit.

### LLR-172.1n — A source found only through the relative fallback is not recorded (CR9-1)
- **Traceability:** HLR-172 · trace: `load_from_path`, `load_a2l_from_path` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a Load copies a source that the path resolver found only through its base-folder or repository-root fallback, then the system shall leave the recent-sources store unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** 4 of 4 — "found only through the fallback" means the typed text is relative and does not exist relative to the working folder. Arms:
  - Working folder `W` ≠ base folder `B`, `B\j` a junction to `R`, typed `j\x.s19` → 1 load, the store bytes unchanged, 0 `Recent sources not updated` warnings.
  - Typed `fw.s19`, present only in `B` → 1 load, the store unchanged.
  - The same relative file typed with `W` = `B` (found as typed) → 1 entry, `os.path.abspath` of the typed text (control).
  - Typed absolute `B\j\x.s19` → 1 entry `B\j\x.s19`, the link not followed (control, LLR-172.1a).
  - 4 of 4. The junction arms are Windows only and are reported not run when no junction can be made.
- **Negative control:** executed probe on the 9a tree (`review-increment-017.md` CR9-1): typed `j/x.s19` → the store holds `R\x.s19` (the link followed, against LLR-172.1a) → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a relative path through a junction; a base-only file; the same file found as typed; an absolute path through a junction.

### LLR-172.2 — The store read returns the accepted entries in order
- **Traceability:** HLR-172 · trace: `read_recent_sources`, `RecentSources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.82
- **Statement (EARS event):** When the recent-sources store is read, the system shall return, in stored order, at most the first 20 entries that pass the entry checks of LLR-172.2e … LLR-172.2i.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** 1 000 distinct accepted entries (`C:\NNN.s19`, about 41 KB) → exactly the first 20, in order; 5 accepted entries with 2 refused ones between them → the 5, in order; the problem is `None` in both arms.
- **Negative control:** a mutation without the cap → 1 000 entries → RED; a mutation sorting the entries → the order arm RED.
- **Boundary catalog:** ☒ boundary — 20 of 1 000 entries.

### LLR-172.2a — An oversized store reads as empty with `too large`
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the recent-sources store file is larger than 65 536 bytes, then the system shall return no entries with the problem `too large`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** exactly 65 536 bytes of valid store → parsed; 65 537 bytes → 0 entries, problem `too large`; 1 read of at most 65 537 bytes (a spy on the read size, S-12).
- **Negative control:** a mutation without the size cap → the 65 537-byte arm returns entries → RED; `>=` → the 65 536-byte arm RED; a stat followed by a full read → the read-size arm RED.
- **Boundary catalog:** ☒ boundary — 65 536 and 65 537 bytes.

### LLR-172.2b — A store of the wrong shape reads as empty
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the recent-sources store file is not a JSON object holding `schema_version` 1 and a `sources` list, then the system shall return no entries.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** `{not json`, bytes that are not UTF-8, a top-level list, `schema_version: 2`, `sources` a string → 0 entries, problem `None`, 0 raises (5 of 5).
- **Negative control:** a mutation without the shape check → the top-level list raises → RED; a mutation accepting any `schema_version` → the `2` arm returns entries → RED.
- **Boundary catalog:** ☒ invalid — 5 wrong shapes.

### LLR-172.2c — An unreadable store reads as empty with `could not be read`
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the recent-sources store file exists but cannot be opened or read, or the file or its folder is a link or junction, then the system shall return no entries with the problem `could not be read`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** the open raising `PermissionError` (injected), a directory at the store path, the store file a symbolic link to a valid store `<tmp>/other.json`, and the store folder a junction to `<tmp>/elsewhere` holding a valid store → 0 entries, problem `could not be read`, 0 raises, 0 bytes read through a link (a spy on the open: 0 opens of the link arms) (4 of 4) (Q6; E3 S9-4). The file-link arm is reported not run, never passed, when the platform refuses to create a file symbolic link.
- **Negative control:** a mutation without the catch → `PermissionError` raised → RED; a mutation returning problem `None` → RED; a mutation without the link check → the two link arms return the target's entries → RED.
- **Boundary catalog:** ☒ error ☒ invalid — a refused open; a directory; a linked store file; a linked store folder.

### LLR-172.2d — A missing store reads as empty with no problem
- **Traceability:** HLR-172 · trace: `read_recent_sources`, `recent_store_path` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the recent-sources store file does not exist or `LOCALAPPDATA` is not usable (LLR-172.1f), then the system shall return no entries and no problem.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** no store file → 0 entries, problem `None`; `LOCALAPPDATA` unset → 0 entries, problem `None`, 0 files or folders created (2 of 2).
- **Negative control:** a mutation reporting `could not be read` for a missing file → RED; a mutation raising `FileNotFoundError` → RED.
- **Boundary catalog:** ☒ empty — no store file; no variable.

### LLR-172.2e — An entry not rooted at a drive is dropped
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the path of a store entry is not a drive letter followed by a root, then the system shall drop that entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** `x.s19`, `C:x.s19`, `\x.s19`, `\\host\share\x.s19`, `\\?\GLOBALROOT\x.s19` and `\\.\C:\x.s19` → 0 returned (6 of 6); `C:\x\a.s19` → returned. A mapped network drive letter cannot be told from a local one by syntax; the guard against touching it is that a recent is never touched before Enter (LLR-173.4).
- **Negative control:** S-07's executed probe: `\\host\share\x.s19 … is_absolute = True` → an absolute-only filter returns it → RED; a mutation accepting `\\?\` → RED.
- **Boundary catalog:** ☒ invalid — 6 path forms.

### LLR-172.2f — An entry naming a device is dropped
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW), `is_windows_device_name` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If a component of a store entry's path is a Windows device name, then the system shall drop that entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** `C:\x\NUL.s19`, `C:\CON\a.s19` and `C:\x\com1.s19` → 0 returned (3 of 3); `C:\x\console.s19` → returned.
- **Negative control:** a mutation checking the last component only → `C:\CON\a.s19` returned → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — device names in the folder and the file; `console`.

### LLR-172.2g — An entry holding a control character is dropped
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the path of a store entry holds a control character (U+0000–U+001F or U+007F–U+009F), then the system shall drop that entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** a NUL, `\x1b[2J`, U+007F and U+009B in a path → 0 returned (4 of 4).
- **Negative control:** a mutation refusing NUL only → the `\x1b[2J` arm returned → RED (S-06).
- **Boundary catalog:** ☒ invalid — 4 control characters.

### LLR-172.2h — An entry whose kind does not match its suffix is dropped
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If a store entry's `kind` is not the kind that LLR-172.1a maps its path's suffix to, then the system shall drop that entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** `kind: exe`; `C:\x\a.s19` with `kind: a2l`; `C:\x\a.s19:ads` (a stream) with `s19`; `C:\x\a.s19.` (a trailing dot) with `s19`; `C:\x\a.exe` with `s19` → 0 returned (5 of 5); `C:\x\A.SREC` with `s19` → returned.
- **Negative control:** a mutation not comparing the kind with the suffix → the `a2l` arm returned → RED (S-07).
- **Boundary catalog:** ☒ invalid ☒ boundary — 5 mismatches; an upper-case suffix.

### LLR-172.2i — A malformed entry is dropped
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If a store entry is not an object holding a string `path` and a string `kind`, then the system shall drop that entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** `null`, `"C:\\x.s19"`, `{"path": 7, "kind": "s19"}` and `{"path": "C:\\x.s19"}` between 2 accepted entries → the 2 accepted entries returned, 0 of the 4, 0 raises.
- **Negative control:** a mutation indexing the entry without the type check → `null` raises → RED.
- **Boundary catalog:** ☒ invalid — 4 malformed entries.

### LLR-172.2j — The store read never raises
- **Traceability:** HLR-172 · trace: `read_recent_sources` (NEW, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS ubiquitous):** The system shall return from every read of the recent-sources store without raising.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** the stores of LLR-172.2a … LLR-172.2i and 200 seeded random byte strings of 0 to 70 000 bytes → 0 raises.
- **Negative control:** a mutation without the decode guard → the non-UTF-8 store raises → RED.
- **Boundary catalog:** ☒ invalid ☒ error — random bytes.

### LLR-172.2k — A store path holding a character no Win32 file name can hold is dropped and never recorded
- **Traceability:** HLR-172 · trace: `_recent_entry_ok` (`workspace.py`), the one entry check shared by `read_recent_sources` and `record_recent_source` (LLR-172.1l)
- **Ledger:** LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If a store entry's path holds any of `<>:"|?*` after its 2-character drive prefix, or a character of Unicode category Cf, Zl, Zp or Cs, then the system shall drop that entry when it reads the store and refuse to record that path.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 (read) and TC-B100-34 (record) — `pytest tests/test_b100_recents.py -k win32_forbidden_character`
- **Numeric pass threshold:** (read) a store of `C:\x\a.s19`, the 6 entries `C:\x\a:b.s19`, `C:\x\CON:.s19`, `C:\x\a::$DATA.s19` and `C:\x\a` + U+202E / U+2028 / U+DC80 + `b.s19`, then `C:/x/../TEMPLA~1/b.s19` → the 2 valid entries, in order, problem none (a `..` segment and an 8.3 spelling stay legal); (record) a store of 2 accepted entries, then records of the same 6 names under `<src>` and of the typed `\??\<src>\x.s19` (which `os.path.abspath` turns into `C:\??\C:\…`, E5 SEC9-4) → False each (7 of 7), the store's SHA-256 unchanged, 0 staging files; control `<src>\c.s19` → True, 3 entries. The record half is Windows only (LLR-172.1f), reported not run on the Linux CI.
- **Negative control:** the E4 integration state (`workspace.py` `a3342ed048ebe157`): 8 entries read and 7 of 7 records True → RED (`evidence/inc-9a/red-02-corrective.txt`); a mutation removing the check → RED (`evidence/inc-9a/mut-c-SEC9-3.txt`).
- **Boundary catalog:** ☒ invalid — an alternate data stream, a device spelling with a colon, the NT prefix, a bidi override, a line separator, an unpaired surrogate.

### LLR-172.3 — Recent paths stay out of every file under the base folder
- **Traceability:** HLR-172 · trace: the `project.json`, report and gather writers (`manifest_writer.py`, `project_gather_service.py`, the report writers in `app.py`); none of them changes at Inc 9a
- **Ledger:** LED-2026-10-26-batch-100.21, LED-2026-10-26-batch-100.82
- **Statement (EARS ubiquitous):** The system shall not copy an entry of the recent-sources store into any file under the base folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-36 — `pytest tests/test_b100_recents.py -k tc_b100_36`
- **Numeric pass threshold:** (1) a store seeded with 3 entries under the marker folder `<tmp>/m4rk3r-9a/`, never loaded in the session, then an outside load of another file, Save project and a report → 0 occurrences of `m4rk3r-9a` in any file under the base folder, the log included; (2) an outside load from `<tmp>/m4rk3r-9b/firmware.s19`, Save project and a report → 0 occurrences of `m4rk3r-9b` in any file under the base folder other than `.s19tool/logs/` (the log records the load's own source path, §6.3).
- **Negative control:** a mutation adding the store's entries to `project.json` → 3 occurrences in arm (1) → RED. Declared: both arms hold on `4fef292` (no store exists), so the mutation is the only RED.
- **Boundary catalog:** none — no input class; one end-to-end save and report per arm.

### LLR-172.4 — One function enumerates the work-area temp folder
- **Traceability:** HLR-172b · trace: `list_workarea_files` (NEW, `workspace.py`); `refresh_files` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS ubiquitous):** The system shall enumerate the work-area temp folder for a file list in exactly one function.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37` (an AST census of `s19_app/`)
- **Numeric pass threshold:** the census (calls of `iterdir`, `glob`, `rglob`, `scandir`, `listdir` or `walk` on a path built from `WORKAREA_TEMP`) → 1 function, `list_workarea_files` in `workspace.py`, and 0 in `app.py`.
- **Negative control:** base `4fef292`: the census finds `refresh_files` (`app.py:7313`, `temp_dir.glob("*")`) → the `workspace.py` arm RED; a mutation adding a second enumeration in `app.py` → 2 functions → RED.
- **Boundary catalog:** none — a code census.

### LLR-172.4a — The Workarea Files list shows each regular file of the temp folder
- **Traceability:** HLR-172b · trace: `list_workarea_files` (NEW, `workspace.py`); `refresh_files` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.84
- **Statement (EARS event):** When the Workarea Files list is refreshed, the system shall show one row per regular file directly in the work-area temp folder, sorted by name.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37`
- **Numeric pass threshold:** `b.s19`, `a.hex`, `c.a2l` → 3 rows `a.hex`, `b.s19`, `c.a2l`, equal to `list_workarea_files` (0 differences); the private `.staging` folder holding 1 file and a sub-folder `sub/x.s19` → 0 rows for them; an empty temp folder → 0 rows.
- **Negative control:** a mutation listing recursively → the `.staging` and `sub/x.s19` files listed → RED; a mutation without the sort → the order arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty temp folder; nested folders.

### LLR-172.4b — A file link in the temp folder is not listed
- **Traceability:** HLR-172b · trace: `list_workarea_files` (NEW), `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If an entry of the work-area temp folder is a symbolic link or reparse point, then the system shall leave that entry out of the Workarea Files list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37`
- **Numeric pass threshold:** `temp/l.s19`, a file symbolic link to an outside file → 0 rows for it, and the other files listed. Feasibility: when the test cannot create a file symbolic link it is reported not run, never passed (as LLR-171.1b).
- **Negative control:** base `4fef292`: `refresh_files` tests `is_file()`, which follows a file link → `l.s19` listed → RED (code read; executed when a link can be made); a mutation using `is_file()` without the link check → RED.
- **Boundary catalog:** ☒ invalid — a file symbolic link.

### LLR-172.4c — A temp folder that cannot be listed gives an empty list
- **Traceability:** HLR-172b · trace: `list_workarea_files` (NEW, `workspace.py`); `refresh_files` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the work-area temp folder is missing, is a link or junction, or cannot be listed, then the system shall show an empty Workarea Files list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37`
- **Numeric pass threshold:** the temp folder removed → 0 rows, 0 raises; the listing raising `PermissionError` (injected) → 0 rows, 0 raises; `temp` a junction to `<tmp>/elsewhere` holding `z.s19` → 0 rows, 0 raises (3 of 3). The junction arm is reported not run, never passed, when no junction can be made.
- **Negative control:** a mutation without the catch → the injected arm raises out of `refresh_files` → RED; base `4fef292`: `glob` follows the junction and lists `z.s19` → the junction arm RED (code read; executed when a junction can be made); a mutation without the folder link check → `z.s19` listed → RED. Declared: `glob` on `4fef292` returns nothing for a missing folder, so for that arm the mutation is the only RED.
- **Boundary catalog:** ☒ error ☒ invalid — a missing folder; a refused listing; a junctioned temp folder.

### LLR-172.4d — A temp file whose name ends in a dot or a space is not listed
- **Traceability:** HLR-172b · trace: `list_workarea_files` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If a regular file in the work-area temp folder has a name that ends in a dot or a space, then the system shall leave that file out of the Workarea Files list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37_lister_skips_a_name_ending_in_a_dot_or_space`
- **Numeric pass threshold:** `a.s19.` and `b.s19 ` (each made through a `\?\` path, one arm each) beside the regular file `c.s19` → the lister returns `[temp/c.s19]` and the list shows 1 row `c.s19`, 0 rows naming either (2 of 2 arms). Win32 opens `a.s19.` as `a.s19`, so a pick of that row would load another file (E5 SEC9-1, probe G). The arms are Windows only (the `\?\` spelling), reported not run on the Linux CI.
- **Negative control:** the E4 integration state (`workspace.py` `a3342ed048ebe157`): `['a.s19.', 'c.s19']` and `['b.s19 ', 'c.s19']` → RED (`evidence/inc-9a/red-02-corrective.txt`); a mutation removing the skip → 1 extra row in each arm (2 in all) → RED (`evidence/inc-9a/mut-c-SEC9-1.txt`).
- **Boundary catalog:** ☒ invalid ☒ boundary — a trailing dot; a trailing space.

### LLR-172.4e — A project folder ending in a dot or a space is not listed on any platform (CR9-9 addendum)
- **Traceability:** HLR-172b · trace: `list_projects` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a folder in the work area has a name that ends in a dot or a space, then the system shall leave it out of the project list on every operating system.
- **Rationale (informative):** the lister skip (LLR-172.4d) has no platform gate; the project-list skip has `os.name == "nt"`. Removing the gate makes both rules the same (backlog disposition B7: prefer removal over a new helper in `workspace.py`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform`
- **Numeric pass threshold:** `fw-v1.` and `fw-v2 ` (both holding `project.json` and a data file) beside `P` → the project list is `[P]` (1 row) on Windows (folders made through `\\?\`) and on the Linux CI (plain names) (2 platform arms).
- **Negative control:** executed P12a-4: the `os.name == "nt"` gate is present in `list_projects` → the Linux arm lists 3 projects → RED on the Linux CI.
- **Boundary catalog:** ☒ invalid ☒ boundary — a trailing dot; a trailing space.

### LLR-172.4f — The Workarea Files list holds only loadable files (C7)
- **Traceability:** HLR-172b · trace: `refresh_files`; the loadable-suffix predicate shared with `_load_dialog_rows` (Inc 9b, LLR-173.4b) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a file in the work-area temp folder does not have a loadable suffix, then the system shall leave it out of the Workarea Files list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-37 — `pytest tests/test_b100_recents.py -k tc_b100_37_files_list_shows_loadable_suffixes_only`
- **Numeric pass threshold:** temp holds `a.s19`, `b.hex`, `c.mac`, `d.a2l`, `d.a2l.json` and `e.txt` → 4 rows (`a.s19`, `b.hex`, `c.mac`, `d.a2l`), 0 rows for `d.a2l.json` or `e.txt` (1 list equality); an AST check → 1 loadable-suffix predicate, read by `refresh_files` and by the Load dialog's files section (1 assertion).
- **Negative control:** code read on `8947666`: `refresh_files` paints every regular file the lister returns (C7) → 6 rows → RED.
- **Boundary catalog:** ☒ invalid — a sidecar dump; an unrelated suffix; an upper-case suffix `F.S19` (listed).

### LLR-172.5 — A typed project folder path loads the project (L-2)
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input`, `_route_load_project`, `_handle_load_project`, `_project_folder_refusal` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83, LED-2026-10-26-batch-100.84
- **Statement (EARS event):** When the absolute path typed into Load names a project folder of this work area, the system shall load that project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** project `ab` (a `project.json` and `firmware.s19`): `<workarea>/ab`, `<workarea>/temp/../ab`, `<workarea>` spelled in upper case followed by `/ab`, and `<workarea>/AB` → 4 loads of `ab` (`current_project == "ab"`, the on-disk name, 1 line naming `ab` loaded each). A project folder is §1.3's Project; the typed path is normalised lexically, and no link is followed before the link check (LLR-172.5d). The folder is matched by listing, not by spelling: the typed last component must equal (on Windows after `os.path.normcase`) the name of a folder the project list (`list_projects`) lists, and the load uses that on-disk name. The two case arms are Windows only (case-insensitive file system), reported not run on the Linux CI.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): `<workarea>/ab` and `<workarea>/temp/../ab` → `['Unsupported file type: ']`, no project → RED.
- **Boundary catalog:** ☒ boundary — `..` segments; the work area under another case spelling.

### LLR-172.5a — A typed `project.json` path loads its project
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When the absolute path typed into Load names the `project.json` of a project folder of this work area, the system shall load that project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `<workarea>/ab/project.json` and `<workarea>/ab/PROJECT.JSON` → 2 loads of `ab`; `<workarea>/ab/flows/project.json` → 0 loads, 1 line holding `not a project` (its folder is not a project folder). The `PROJECT.JSON` arm is Windows only (case-insensitive file system), reported not run on the Linux CI.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): `<workarea>/ab/project.json` → `['Unsupported file type: .json']` → RED.
- **Boundary catalog:** ☒ boundary — the name in another case; a `project.json` below a project.

### LLR-172.5b — A typed folder inside the work area that is not a project is refused (S-01)
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83, LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If the absolute path typed into Load names a folder inside this work area that is not a project folder, then the system shall load nothing and paint the `not a project` and `pick a project in the list` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** a folder is matched by listing, not by spelling (LLR-172.5): a typed last component that equals no name the project list lists is not a project folder, and the project list never lists a reserved home. `<workarea>/temp`, `<workarea>/TEMP` and `<workarea>/patches` (reserved homes; `temp` holding a work copy), `<workarea>/temp::$INDEX_ALLOCATION` (a stream spelling of `temp`), `<workarea>/TEMPLA~1` (the 8.3 name of `templates`, holding a file), `<workarea>/temp.` (a trailing dot), an empty folder `<workarea>/empty`, the sub-folder `<workarea>/ab/flows` and `<workarea>` itself → 0 project loads, 0 files written, 1 line holding both tokens each (9 of 9) (Q9; E3 S9-1). The `TEMP`, stream, 8.3 and trailing-dot arms are Windows only (case-insensitive file system, Win32 name rules); the 8.3 arm is reported not run when the volume makes no 8.3 names; each is reported not run on the Linux CI. A project typed by its 8.3 name is refused the same way (declared: fail closed).
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): `<workarea>/temp` → `['Unsupported file type: ']`, neither token → RED; S-01's executed probe (`validate_project_files(workarea/temp)` accepts the work copy) → a route that loads any folder holding a data file loads `temp` → RED; a mutation comparing the typed name case-folded with the reserved homes instead of matching the listing (the E2 design) → `temp::$INDEX_ALLOCATION` loads `temp` (E3 S9-1 P2: every other predicate passes) → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — the work area itself; reserved homes in two cases; a stream, an 8.3 and a trailing-dot spelling of a reserved home; a project's sub-folder; an empty folder.

### LLR-172.5c — A typed folder outside the work area is refused
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input`, `_project_folder_refusal` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the absolute path typed into Load names a folder outside this work area, or the `project.json` of such a folder, then the system shall load nothing and paint the `outside the work area` and `copy the folder into the work area` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `<tmp>/elsewhere/P` holding a `project.json` and an image, that folder's `project.json`, another work area's project `<tmp>/other/.s19tool/workarea/R`, and the base folder → 0 project loads, 0 files written, 1 line holding both tokens each (4 of 4). This is LLR-171.4f's typed arm.
- **Negative control:** code read on `4fef292`: the same `Unsupported file type: ` branch as the probe's `<workarea>/ab` → neither token → RED; a mutation loading any folder that holds a `project.json` → `<tmp>/elsewhere/P` loads → RED.
- **Boundary catalog:** ☒ invalid — an outside folder, its manifest, another work area, the base folder.

### LLR-172.5d — A typed folder path through a link or junction is refused
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input`, `_project_folder_refusal` (`app.py`); `_is_reparse_point` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If the absolute folder or `project.json` path typed into Load passes through a symbolic link or junction inside this work area, then the system shall load nothing and paint the `link or junction` and `pick a project in the list` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `<workarea>/alias` (a junction to `<workarea>/ab`), `<workarea>/alias/project.json`, and `<workarea>/sub/P` with `<workarea>/sub` a junction to another work area → 0 project loads, 0 session resets, 1 line holding both tokens each (3 of 3). This is LLR-171.4e's typed arm.
- **Negative control:** code read on `4fef292`: `resolve_input_path` returns the path and `exists()` follows the junction → `Unsupported file type: `, neither token → RED; a mutation resolving the path before the link check → `alias` loads `ab` → RED.
- **Boundary catalog:** ☒ invalid — a junction to this work area's project, its manifest, a junction to another work area.

### LLR-172.5e — A typed file with no or an unsupported suffix is refused
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.84
- **Statement (EARS unwanted):** If the path typed into Load names a file whose suffix is missing or is not a supported data or A2L suffix, then the system shall load nothing and paint the `not a supported file` and `check the path` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `<tmp>/firmware` (no suffix), `<tmp>/notes.txt` and `<tmp>/x.json` → 0 loads, 0 files copied into `temp/`, 1 line holding both tokens each (3 of 3).
- **Negative control:** code read on `4fef292` (`_load_path_from_user_input`): `Unsupported file type: <suffix>`, neither token → RED.
- **Boundary catalog:** ☒ invalid — no suffix; 2 unsupported suffixes.

### LLR-172.5f — A typed path that does not exist is refused
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82
- **Statement (EARS unwanted):** If the path typed into Load does not exist, then the system shall load nothing and paint the `not found` and `check the path` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `<tmp>/missing.s19` and `<workarea>/nope` → 0 loads, 1 line holding both tokens each (2 of 2).
- **Negative control:** code read on `4fef292`: `File not found: <path>` holds `not found` but not `check the path` → RED.
- **Boundary catalog:** ☒ error — a missing file; a missing folder.

### LLR-172.5g — A project load of a name the project list does not list is refused (S-01)
- **Traceability:** HLR-172a · trace: `_handle_load_project`, `list_projects` (`app.py`); `RESERVED_WORKAREA_HOMES` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If a project load is asked for a name that equals no name the project list of this work area lists, then the system shall refuse the load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** names are compared on Windows after `os.path.normcase`; a match loads the listed on-disk name. The project list (`list_projects`, `app.py:12057` at `4fef292`) skips every entry whose case-folded name is in `RESERVED_WORKAREA_HOMES`, so no reserved home is ever listed. `_handle_load_project("temp")`, `("TEMP")`, `("patches")`, `("temp::$INDEX_ALLOCATION")`, `("TEMPLA~1")` (the 8.3 name of `templates`, holding a file) and `("temp.")`, with a work copy in `temp/` → 0 project loads, 0 session resets, 0 files written (`temp/project.json` and `templates/project.json` absent), 1 line holding `not a project` and `pick a project in the list` each (6 of 6); `("AB")` for the project `ab` → 1 load, `current_project == "ab"` (control). The refusal comes after the existing link, outside, unreadable and not-found refusals (LLR-171.4e, LLR-171.4f), so their tokens are unchanged. Every arm except `temp` and `patches` is Windows only (case-insensitive file system, Win32 name rules), reported not run on the Linux CI; the 8.3 arm is reported not run when the volume makes no 8.3 names.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): `_handle_load_project('temp')` → `Loaded project 'temp' -> [bold]x.s19 - variant 1 of 2 …`, `current_project = temp` → RED; a mutation comparing the name case-folded with the reserved homes instead of matching the listing (the E2 design) → `temp::$INDEX_ALLOCATION` and `TEMPLA~1` load (E3 S9-1 P2) → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — reserved homes in two cases; a stream, an 8.3 and a trailing-dot spelling; a project name in another case.

### LLR-172.5h — A typed relative folder path is refused
- **Traceability:** HLR-172a · trace: `_load_path_from_user_input` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.83
- **Statement (EARS unwanted):** If a relative path typed into Load names a folder, then the system shall load nothing and paint the `not a supported file` and `check the path` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** "relative" is `not Path(text).is_absolute()` on the typed text (stripped as `resolve_input_path` strips it). With a working folder other than the base folder: `.s19tool/workarea/ab` (found by the base-folder fallback), `.s19tool/workarea/alias` (a junction to `ab`, which the fallback's `resolve()` follows), and the root-relative `\…\.s19tool\workarea\ab` (no drive) → 0 project loads, 0 session resets, 0 files copied into `temp/`, 1 line holding both tokens each (3 of 3). The root-relative and junction arms are Windows only, reported not run on the Linux CI; the junction arm is reported not run when no junction can be made.
- **Negative control:** code read on `4fef292` (`_load_path_from_user_input`): a folder gives `Unsupported file type: ` (an empty suffix), neither token → RED; a mutation sending a relative folder to the project route → `.s19tool/workarea/ab` loads `ab` and the `alias` arm loads `ab` through the junction → RED; a mutation testing `os.path.isabs` (true for `\x` on Python 3.12, E3 S9-6) → the root-relative arm routes as a project → RED.
- **Boundary catalog:** ☒ invalid — a relative folder; a relative junction; a root-relative folder.

### LLR-172.5i — A typed path the operating system refuses is refused (CR9-8)
- **Traceability:** HLR-172a · trace: `_typed_load_route`, `_load_path_from_user_input`; `_load_dialog_verdict` (Inc 9b) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If the text typed into Load holds a character that the operating system's path calls refuse, such as NUL, or names a path whose existence check the operating system refuses, then the system shall load nothing and paint the `not found` and `check the path` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38_nul_in_typed_path_is_refused`
- **Numeric pass threshold:** a typed text whose `Path.exists` is monkeypatched to raise `PermissionError` (EACCES) and one to raise `OSError(ENAMETOOLONG)`, each through the status-line route and through the Load dialog's `#load_reason` (4 arms) → 0 exceptions, 0 loads, the token pair painted (4 of 4). Regression arms, GREEN on the post-9b base: the relative and absolute NUL texts (4 arms) → the same token pair, 0 exceptions.
- **Negative control:** on base `_typed_load_route` catches only `ValueError` / `RuntimeError` around its one `resolve_input_path` call, so the monkeypatched `PermissionError` leaves `_typed_load_route` and stops the app → RED. The `_typed_load_route` catch is widened to `(OSError, ValueError, RuntimeError)` (S12a-01).
- **Boundary catalog:** ☒ invalid ☒ error — a NUL in a relative and in an absolute text; EACCES and ENAMETOOLONG.

### LLR-172.5j — A name is matched to the project list in one place (CR9-7, match)
- **Traceability:** HLR-172a · trace: `_listed_project_name` (NEW); `_handle_load_project`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS ubiquitous):** The system shall decide whether a name matches a listed project in one function.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38_one_project_match` (AST), plus every TC-B100-38 arm kept green
- **Numeric pass threshold:** an AST check → exactly 1 function compares a name against the `list_projects()` result (1 assertion); that function returns the exact listed name first, then the first case-insensitive (`normcase`) match — `["Proj", "proj"]` → `proj` → `proj`, `Proj` → `Proj`, `PROJ` → `Proj` on Windows (SE5-12a-3); the TC-B100-38 and TC-B100-40 arms → 0 failures.
- **Negative control:** executed P12a-4: 2 functions hold the match (`_handle_load_project`, `_typed_load_route`) → RED; a mutation returning only the first `normcase` match → `proj` loads `Proj` when both are listed → RED (SE5-12a-3).
- **Boundary catalog:** none — the census has no input classes.

### LLR-172.5k — The shared project refusals are worded from one table (CR9-7, wording)
- **Traceability:** HLR-172a · trace: `_TYPED_REFUSAL_TOKENS` (Inc 9b), `_load_path_from_user_input`, `_handle_load_project`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS ubiquitous):** The system shall word the `could not be read` and `not a project` project refusals of the status line and of the Load dialog from one table.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-38 (AST), plus TC-B100-63 kept green
- **Numeric pass threshold:** an AST check → the two token pairs are defined once, and every painted Load refusal sentence reads one of the two pairs (0 string literals of either reason outside the table, docstrings excluded); no exact site count is asserted, because the count breaks on every future site (A12a-01) (2 assertions).
- **Negative control:** executed P12a-4 (raw count, docstrings included): `could not be read` 8 occurrences and `not a project` 6 in `app.py`; E2 derives the painting sites (CR9-7: 3 copies) → RED.
- **Boundary catalog:** none.

### LLR-172.6 — Workarea Files rows paint names literally (C8)
- **Traceability:** HLR-172b · trace: `refresh_files` (`app.py`); `painted_names` (`project_gather_service.py:965`); `safe_text` (`utils.py:44`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS ubiquitous):** The system shall paint the file name of each Workarea Files row with no markup applied, every character of Unicode category Cc, Cf, Zl or Zp removed and every unpaired surrogate replaced by U+FFFD.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39`
- **Numeric pass threshold:** the label is the project's one category scrub, `painted_names([name])` (8b S3R2-4; clipped to 120 characters ending in `…`), painted with markup off. `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, a name holding U+009B, `x` + U+202E + `gpj.s19` (a bidi override) and `a` + U+DC80 + `b.s19` (an unpaired surrogate) → 6 rows whose plain text equals the name with those characters removed (the surrogate as U+FFFD), 0 spans, 0 characters of category Cc, Cf or Cs, 0 raises; a 130-character name → a label of 120 characters ending in `…` (7 of 7). The surrogate arm is reported not run, never passed, where the test cannot create that name.
- **Negative control:** executed on `4fef292` (`evidence/inc-9a/e1-probe-4fef292.md`): the `[bold]x.s19` row (built at `app.py:7316`) paints `Content('x.s19', spans=[Span(0, 5, style='bold')])` → RED; a mutation painting `safe_text(name)` (C0 / C1 only, the E2 design) → the U+202E row keeps the Cf character and the U+DC80 row keeps the surrogate → RED (E3 S9-2).
- **Boundary catalog:** ☒ invalid ☒ boundary — the six hostile names; a name over the 120-character clip.

### LLR-172.6a — A picked Workarea Files row loads the file as named on disk
- **Traceability:** HLR-172b · trace: `refresh_files`, `_load_from_item` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.82, LED-2026-10-26-batch-100.83
- **Statement (EARS event):** When the engineer picks a Workarea Files row, the system shall load the file whose exact on-disk name that row holds.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39`
- **Numeric pass threshold:** picking the `[bold]x.s19` row, the U+009B row, the U+202E row and the 130-character row (its label clipped) → `current_file.path.name` equals each on-disk name (4 of 4); the row's data is the on-disk name, never the painted label (`painted_names`, LLR-172.6).
- **Negative control:** a mutation storing the painted text as the row's name → the U+009B pick loads nothing → RED. Declared: on `4fef292` the row holds `item.name`, so the mutation is the only RED.
- **Boundary catalog:** ☒ invalid — a markup-shaped name; a control character.

### LLR-172.6b — A Workarea Files pick that is no longer a regular file loads nothing (SEC9-2)
- **Traceability:** HLR-172b · trace: `_load_workarea_file` (Inc 9b G1), `_load_from_item` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS unwanted):** If the picked work-area entry is not a regular file when it is picked, a link or another reparse point included, then the system shall load nothing and paint the `not a regular file` and `pick another file` tokens.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39_pick_rechecks_the_entry`
- **Numeric pass threshold:** list `fw.s19`, then replace it before the pick with (a) a folder `fw.s19`, (b) a junction `fw.s19`, (c) a file symbolic link to a file outside the work area (3 arms; arm (c) needs the symbolic-link privilege and is reported not run, never passed, where the platform cannot make it) → 0 parses (spy on the parse), the token pair painted, the session digest unchanged; through the Workarea Files list and through the Load dialog's `workarea` choice (2 routes; 6 arms in all).
- **Negative control:** code read on `8947666` (SEC9-2): `_load_from_item` tests `candidate.exists()`, which follows a link, then parses it → arm (c) loads the outside file → RED. E2 executes arms (a) and (b) on the baseline.
- **Boundary catalog:** ☒ invalid ☒ error — a folder; a junction; a file link.

### LLR-172.6c — A Workarea Files pick larger than the copy cap loads nothing (SEC9-2)
- **Traceability:** HLR-172b · trace: `_load_workarea_file` (Inc 9b G1); `DEFAULT_COPY_SIZE_CAP_BYTES` (`workspace.py`, read only) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS unwanted):** If the picked work-area file is larger than the work-area copy size cap when it is picked, then the system shall load nothing and paint the `too large to open` token with the file name and the `load a smaller file` token.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39_pick_over_cap_is_refused`
- **Numeric pass threshold:** the cap read at call time, patched to 1 024 bytes → a 1 025-byte `big.s19` → 0 parses, the tokens painted; a 1 024-byte `edge.s19` → loaded (2 arms).
- **Negative control:** code read on `8947666`: `_load_from_item` has no size check → the 1 025-byte arm parses → RED.
- **Boundary catalog:** ☒ boundary — cap and cap + 1 bytes.

### LLR-173.1 — The dialog closes with one `LoadChoice`
- **Traceability:** HLR-173 · trace: `LoadChoice` (NEW, B100-I8), the Load dialog class (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.12, LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall close the Load dialog with either no result or one `LoadChoice(kind, value)` whose `kind` is one of `project`, `workarea`, `recent` and `path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** A load from each section and from the path field → 4 dismiss values, each a `LoadChoice` of the matching kind, `value` the on-disk project name, the on-disk work-area file name, the recorded path text or the typed text respectively (4 of 4).
  - `escape` → `None`.
- **Negative control:** code read, 9a tree: `LoadFileScreen` dismisses with a `Path` and `LoadProjectScreen` with a `str` → no `LoadChoice` → RED.
- **Boundary catalog:** ☒ boundary — each of the four kinds; no result.

### LLR-173.1a — A project choice opens the project through the project route
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_route_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog closes with a `project` choice, the system shall load that project through the route that opens the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** `LoadChoice("project", "ab")` → `current_project == "ab"` and 1 `LoadResultScreen` on the stack (2 of 2).
- **Negative control:** a mutation that calls `_handle_load_project` directly → 0 Load-result panels → RED.
- **Boundary catalog:** ☒ boundary — a project name in another case than on disk (the listed spelling loads, LLR-172.5g).

### LLR-173.1b — A work-area choice loads that file as the list pick does
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_load_from_item`, `load_selected_file`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog closes with a `workarea` choice, the system shall load the named file of `workarea/temp` as the Workarea Files list's pick of that name loads it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** `LoadChoice("workarea", "x.s19")` → `current_file.path == <workarea>/temp/x.s19`, 0 calls to `copy_into_workarea` (spy, the data arm only), and the set of names in `temp/` unchanged.
  - `LoadChoice("workarea", "c.a2l")` → the same session digest as a `#files_list` pick of `c.a2l` on a twin fixture, and the set of names in `temp/` unchanged (the copy is an identical-file reuse, G-005) (2 of 2).
- **Negative control:**
  - A mutation that routes the `workarea` data choice through `load_from_path` → 1 `copy_into_workarea` call → RED.
  - Declared: since Inc 1 that copy reuses the identical file (G-005), so the name-set arm alone passes on the mutant; the spy is the RED. The A2L arm keeps the 9a `load_a2l_from_path` route (its `copy_into_workarea`, 256 MB cap and link re-check), so it carries no 0-copy spy (A9b-05).
- **Boundary catalog:** ☒ boundary — a data file and an A2L file.

### LLR-173.1c — A path choice takes the typed-path route
- **Traceability:** HLR-173c · trace: `_handle_load_dialog`, `_load_path_from_user_input`, `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog closes with a `path` choice, the system shall load the typed text through the typed-path route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** typed `<tmp>/a.s19`, `<tmp>/b.a2l` and `<workarea>/ab` (absolute) → 1 data load, 1 A2L attach and 1 project load of `ab` (3 of 3).
- **Negative control:** a mutation that routes `path` to `load_from_path` → the `<workarea>/ab` arm loads nothing → RED.
- **Boundary catalog:** ☒ boundary — a data file, an A2L file, a project folder.

### LLR-173.1e — One router receives every Load dialog result
- **Traceability:** HLR-173 · trace: `_handle_load_dialog`, `action_load_file`, `action_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall pass every Load dialog result to one app handler.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** AST census of `s19_app/tui/app.py`: every `push_screen` call whose first argument constructs the Load dialog passes `self._handle_load_dialog` as its callback. That gives 2 sites (`action_load_file`, `action_load_project`), 2 of 2, and 0 other callbacks.
- **Negative control:**
  - Code read, 9a tree: `action_load_project` pushes `LoadProjectScreen` with `_route_load_project` → 2 callbacks → RED.
  - A mutation that gives `action_load_project` its own callback → RED.
- **Boundary catalog:** none — a structural census; its set is every push site of the dialog.
- **Note (informative):** the load question (HLR-174) is inserted at Inc 10, through the one seam (LLR-174.4) in this router. Inc 9b adds no question.

### LLR-173.1f — A recent choice loads the recorded path unchanged
- **Traceability:** HLR-173b · trace: `_handle_load_dialog`, `_load_path_from_user_input`, `load_from_path`, `load_a2l_from_path` (`app.py`); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS event):** When the Load dialog closes with a `recent` choice, the system shall load the recorded path text, with no change, through the typed-path route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** A recent `C:\…\src\fw.s19` → 1 data load, and `fw.s19`'s work copy is installed.
  - A recent `C:\…\src\cal.a2l` → 1 A2L attach.
  - After the data load, that path is the store's first entry (the 9a record, LLR-172.1b).
  - A recent `C:\…\gone\fw.s19` that is missing, while `<base>\fw.s19` exists → 0 loads (a recorded path is drive-rooted, LLR-172.2e, so the relative fallback of `resolve_input_path` never runs).
  - 4 of 4.
- **Negative control:** a mutation that loads the recent by its file name relative to the base folder → the `gone` arm loads `<base>\fw.s19` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a data and an A2L recent; a missing recent whose name exists under the base folder.

### LLR-173.1g — An unreadable picked project paints one status line and does not crash
- **Traceability:** HLR-173 · trace: `_handle_load_project`, `_list_project_files` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS unwanted):** If the picked project cannot be read (`OSError`), then the system shall paint one status line with `could not be read`, keep the session unchanged, and not crash.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** `PermissionError` injected into `_list_project_files` of a listed project, then `enter` → 1 status line holding `could not be read`, 0 raises, the session digest unchanged (1 of 1).
- **Negative control:** a mutation with no catch at `:11743` → the `OSError` leaves the dismiss callback and the app stops → RED.
- **Boundary catalog:** ☒ error — a listed project that cannot be inspected.

### LLR-173.2 — `l` and `ctrl+l` open the dialog on the path field
- **Traceability:** HLR-173 · trace: `action_load_file`, `BINDINGS` (`app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.36, LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `l` or `ctrl+l` on the main screen, the system shall open the Load dialog with the focus on `#load_path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `l` → the dialog open and `focused.id == "load_path"`; `ctrl+l` → the same (2 of 2); `#load_list` exists in that dialog (1).
- **Negative control:**
  - Code read, 9a tree: `LoadFileScreen` has no `#load_list` (P-20) → RED.
  - A mutation that opens every Load on `#load_list` → the `l` arm RED.
- **Boundary catalog:** ☒ boundary — both keys.

### LLR-173.2a — `p` opens the dialog on the list
- **Traceability:** HLR-173 · trace: `action_load_project`, `on_button_pressed` (`#ws_load_project_button`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `p` on the main screen or activates `#ws_load_project_button`, the system shall open the Load dialog with the focus on `#load_list`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `p` → `focused.id == "load_list"`; the button → the same; `p` in a work area with 0 projects → the dialog opens and the projects section paints `no projects` (3 of 3).
- **Negative control:**
  - Code read, 9a tree: `action_load_project` pushes `LoadProjectScreen` (`#project_list`), and with 0 projects it paints `No saved projects found.` and opens nothing → RED.
  - A mutation that opens the `p` dialog on `#load_path` → `p`, then `enter`, loads nothing → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 projects; the key and the button.

### LLR-173.2b — The list opens on the open project
- **Traceability:** HLR-173 · trace: the Load dialog `on_mount` (`screens.py`); `current_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog opens with the focus on `#load_list`, the system shall highlight the open project's row, or the first project row when no project is open.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** 3 of 3 — Projects `A`, `P`, `Z` with `P` open, then `p` → `P`'s row highlighted.
  - No project open → `A`'s row highlighted.
  - 0 projects and 1 work-area file → the file's row highlighted (3 of 3).
- **Negative control:** a mutation that always highlights row 0 → the `P` arm highlights `A` → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no project open; 0 projects.

### LLR-173.2c — `tab` order
- **Traceability:** HLR-173 · trace: the Load dialog compose order and focus chain (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `tab` in the Load dialog, the system shall move the focus along `#load_path`, `#load_list`, `#load_preview`, `#load_ok`, `#load_cancel` and back to `#load_path`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** from `#load_path`, 5 `tab` presses → the focused ids in that order, ending on `#load_path` (5 of 5); `shift+tab` → the reverse order (5 of 5).
- **Negative control:** a mutation that leaves `#load_preview` unfocusable → the third press lands on `#load_ok` → RED.
- **Boundary catalog:** ☒ boundary — the wrap from `#load_cancel` to `#load_path`.

### LLR-173.2d — A printable key in the list types into the path field
- **Traceability:** HLR-173 · trace: the Load dialog `on_key` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer types a printable character while `#load_list` has the focus, the system shall move the focus to `#load_path` and append that character to its text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** 6 of 6 — Each of `p`, `l`, `q`, `s`, `r` and `?` pressed with the list focused and the field empty → `#load_path` holds that one character and has the focus.
  - The screen stack depth is unchanged and 0 app actions run (a spy on `S19TuiApp.run_action`) (6 of 6).
  - `up`, `down`, `enter` and `tab` → not redirected (4 of 4).
- **Negative control:**
  - A mutation with no key redirect → `p` leaves `#load_path` empty → RED.
  - Declared: under Textual 8.2.8 a modal screen already stops the app's non-priority bindings (`Screen._modal_binding_chain`, `textual/screen.py:449-455`), so the "0 app actions" arm passes without the redirect; the field arm is the RED.
- **Boundary catalog:** ☒ boundary — printable keys that are app bindings on the main screen; non-printable navigation keys.

### LLR-173.2e — App priority keys are inert while the dialog is open
- **Traceability:** HLR-173 · trace: `BINDINGS` (`priority=True` entries), `check_action` or the four actions (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the Load dialog is open, then the system shall run no app action for that key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** each of the 4 keys pressed with the dialog open → the screen stack stays the main screen plus the Load dialog (depth 2), the focus is inside the dialog, and the density and palette are unchanged (4 of 4); `ctrl+p` over the dialog (the command palette opens over it), then `ctrl+s` and `ctrl+l` → 0 Save pushes and 0 second dialogs (the guard reads the whole screen stack, S9b-1) (2 of 2).
- **Negative control:** code read on Textual 8.2.8 and the 9a tree. `App._check_bindings(priority=True)` walks `reversed(self.screen._binding_chain)`, App included (`textual/app.py:3978-3981`), and the four bindings are `priority=True` (`BINDINGS` in `app.py`). So `ctrl+l` pushes a second Load dialog and `ctrl+s` pushes the Save dialog over it → RED. Status: `executed` (the S9b-1 probe: after `ctrl+l`, `ctrl+p` then `ctrl+s` stacks `Save` under the old stack-top guard → RED; the whole-stack guard keeps the stack `['Screen','Dlg','CommandPalette']`).
- **Boundary catalog:** ☒ invalid — the four priority keys, and `ctrl+p` over the dialog.

### LLR-173.2f — A load asked with the list last loads the highlighted row
- **Traceability:** HLR-173c · trace: the Load dialog `action_load`, `on_button_pressed`, focus tracking (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `enter` or `alt+l`, or activates `#load_ok`, while `#load_list` held the focus more recently than `#load_path`, the system shall close the Load dialog with the highlighted row's choice.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** The 3 triggers × a project, a work-area file and a recent row highlighted → 9 dismisses with the matching `LoadChoice` (9 of 9).
  - Text in `#load_path`, then `tab` into the list, then `enter` → the row's choice (1).
- **Negative control:** a mutation that always takes the typed text → the list arms dismiss with `path` → RED.
- **Boundary catalog:** ☒ boundary — text present in the field while the list was last.

### LLR-173.2g — A load asked with the path field last loads the typed text
- **Traceability:** HLR-173c · trace: the Load dialog `action_load`, `on_input_submitted` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `enter` or `alt+l`, or activates `#load_ok`, while `#load_path` held the focus more recently than `#load_list` and holds a path the typed-path route accepts, the system shall close the Load dialog with a `path` choice of that text.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** a valid typed file path with a row highlighted → the 3 triggers give 3 `path` choices of the text (3 of 3).
- **Negative control:** a mutation that always takes the highlighted row → `path` arms dismiss with the row → RED.
- **Boundary catalog:** ☒ boundary — a row highlighted while the field was last.

### LLR-173.2h — An empty typed text is explained
- **Traceability:** HLR-173d · trace: the Load dialog `action_load` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a load is asked while `#load_path` held the focus more recently than `#load_list` and its text is empty or only spaces, then the system shall keep the Load dialog open and paint `nothing selected` and `pick a row or type a path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `""` and `"   "` → 2 token pairs, 0 dismisses, the field text unchanged (2 of 2).
- **Negative control:** executed on `1d677ba` (P-19): an empty Load gives no status and no notice → RED.
- **Boundary catalog:** ☒ empty — no text; spaces only.

### LLR-173.2i — A load with no highlighted row is explained
- **Traceability:** HLR-173d · trace: the Load dialog `action_load` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a load is asked while `#load_list` held the focus more recently than `#load_path` and no loadable row is highlighted, then the system shall keep the Load dialog open and paint `nothing selected` and `pick a row or type a path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** An empty work area, an empty temp folder and no store → `p`, then `enter` → 1 token pair, 0 dismisses.
  - A section heading or an empty-section token line highlighted → 1 token pair, 0 dismisses (2 of 2).
- **Negative control:** a mutation that dismisses with the heading row's text → 1 dismiss → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — every section empty; a heading highlighted.

### LLR-173.2j — A click selects and never loads
- **Traceability:** HLR-173 · trace: the Load dialog list message handlers (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer clicks a row of `#load_list`, the system shall highlight that row and keep the Load dialog open.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** 1 click on the second project row → that row highlighted, 0 dismisses; 2 clicks within 300 ms (a double-click) → 0 dismisses (2 of 2).
- **Negative control:** a dialog that loads on the list's selected message → 1 dismiss on the first click → RED. Textual 8.2.8 posts the same `Selected` message for a click as for `enter` (`textual/widgets/_option_list.py:721-730`), so the dialog cannot load on that message.
- **Boundary catalog:** ☒ boundary — a single and a double click.

### LLR-173.2k — `escape` closes with no result
- **Traceability:** HLR-173e · trace: the Load dialog `BINDINGS` / `action_cancel` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer presses `escape` in the Load dialog, the system shall close it with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `escape` from `#load_path`, `#load_list`, `#load_preview` and `#load_ok` → 4 dismisses with `None`, the session digest unchanged and the store bytes unchanged (4 of 4).
- **Negative control:** executed on `1d677ba` (P-18): `escape on LoadFileScreen -> screen: LoadFileScreen` → RED.
- **Boundary catalog:** ☒ boundary — each focus position.

### LLR-173.2l — `#load_cancel` closes with no result
- **Traceability:** HLR-173e · trace: the Load dialog `on_button_pressed` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer activates `#load_cancel`, the system shall close the Load dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** a click and `enter` on `#load_cancel` → 2 dismisses with `None`, the session digest unchanged (2 of 2).
- **Negative control:** a mutation that maps `#load_cancel` to the load action → the empty-Load tokens and 0 dismisses → RED.
- **Boundary catalog:** ☒ boundary — click and key activation.

### LLR-173.2m — The key bar and the palette name the two actions "Load" and "Projects"
- **Traceability:** HLR-173 · trace: `BINDINGS`, `_build_palette_entries` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS ubiquitous):** The system shall label the load-file action "Load" and the load-project action "Projects" in the key bar and in the command palette.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41_labels`; `pytest tests/test_b97_key_bar.py`; `pytest tests/test_tui_snapshot.py -m snapshot`
- **Numeric pass threshold:** 6 assertions, the key-bar re-pins and the 29 snapshot rebaselines (29 of 29; 35 cells):
  - The footer at 118 columns holds `^l Load` and 0 occurrences of `Load file` (2 assertions).
  - The palette holds the entries "Load" and "Projects" and 0 entries "Load file" or "Load project" (4 assertions).
  - `tests/test_b97_key_bar.py` `GLOBAL_TEXTS` re-pinned to `^l Load`; the 80×24 row-1 set `GLOBAL_TEXTS_80` re-measured with the shorter label (the drop of `q Quit` and `^p palette` was caused by the longer labels; the measured set is recorded in the packet).
  - The 29 snapshot files rebaselined in the CI-matching environment and named one by one in the packet (29 of 29; 35 cells: 29 `Load file`, 6 `Load project`).
- **Negative control:** code read on `8947666`: `Binding("ctrl+l", "load_file", "Load file", priority=True)` (`app.py:2122`), `Binding("l", "load_file", "Load file", …)` (`:2127`), `Binding("p", "load_project", "Load project", …)` (`:2135`) → RED.
- **Boundary catalog:** ☒ boundary — the key bar at 80, 99 and 118 columns.
- **Note (informative):** the Workspace button `Load project (p)` (`#ws_load_project_button`, `app.py:2892`) is not part of VS-PA-4 and keeps its text (ruling Q6). The help overlay lists binding descriptions, so it shows "Load" and "Projects" too.

### LLR-173.3 — Project rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names` (`project_gather_service.py`); `safe_text` (`utils.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint each project row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** projects named `[b]P`, `[@click=app.bell]Q`, `x` + U+202E + `R` and `a` + U+009B + `S` → 4 rows whose plain text equals the name with the Cc / Cf characters removed, 0 spans, 0 characters of category Cc, Cf or Cs, 0 raises (4 of 4). The U+009B arm is reported not run where the volume refuses that folder name.
- **Negative control:** code read, `4fef292` and 9a tree: `screens.py:712` builds `ListItem(Label(name))` with markup on, and `[b]P` paints 1 span (QA-02 probe) → RED. A mutation that paints `safe_text(name)` (C0 / C1 only) keeps U+202E → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped, bidi and C1 names.

### LLR-173.3a — Work-area file rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names`; `safe_text`
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint each work-area file row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** The six hostile names of LLR-172.6 (each given a loadable suffix) → 6 literal rows, 0 spans, 0 Cc / Cf / Cs characters.
  - A 130-character name → a 120-character label ending in `…` (7 of 7). The surrogate arm is reported not run where the name cannot be made.
- **Negative control:** a mutation that builds the row as `Label(name)` → the `[bold]x.s19` row paints 1 span → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the hostile names; the 120-character clip.

### LLR-173.3b — Recent rows are painted literally (C8)
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `painted_names`; `safe_text`
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint each recent row of the Load dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** store entries `C:\x\[bold]a.s19`, `C:\x\[link=y]b.hex` and `C:\x\[@click=app.bell]c.a2l` (each accepted by the 9a read) → 3 rows with 0 spans whose plain text holds the literal file name (3 of 3).
- **Negative control:** a mutation that builds the row as `Label(path)` → 1 span per row → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped paths the store read accepts.

### LLR-173.3c — Preview lines are painted literally (C8)
- **Traceability:** HLR-173 · trace: the preview builder (NEW, `app.py`); the Load dialog preview pane (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint literally every file, variant and problem name shown in the Load dialog's preview.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** project `P` holding `[b]v.s19`, `[i]m.mac` and `[u]c.a2l` → the preview's plain text holds the 3 literal names and 0 spans come from them; a recent `C:\x\[bold]a.s19` previewed → 0 spans (4 of 4).
- **Negative control:** a mutation that writes the preview with markup on → `[b]v.s19` paints bold → RED.
- **Boundary catalog:** ☒ invalid — markup-shaped names in every preview line kind.

### LLR-173.3d — A picked row loads the on-disk name, never the label
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); the Load dialog row data (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the engineer loads a project or work-area file row, the system shall load the exact on-disk name that row holds.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** the `[b]P` project → `current_project == "[b]P"`; the U+009B file and the 130-character file (label clipped) → `current_file.path.name` equals each on-disk name (3 of 3).
- **Negative control:** a mutation that stores the painted label as the row's value → the U+009B and clipped arms load nothing → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a C1 name; a clipped label.

### LLR-173.4 — The projects section is the project list
- **Traceability:** HLR-173 · trace: `list_projects`, the dialog rows builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.6, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its projects section exactly the names the project list of this work area returns, in that order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** projects `ab` and `cd`, the reserved folders `temp` and `patches`, and a junction folder `jx` → 2 project rows, `ab` then `cd`. The junction arm is Windows only and is reported not run when no junction can be made.
- **Negative control:** a mutation that lists the work area's folders without `list_projects` → `temp`, `patches` and `jx` listed → RED.
- **Boundary catalog:** ☒ invalid — reserved homes; a junction.

### LLR-173.4a — A folder that is not a project is not listed (§1.3; 9a C4, Q9)
- **Traceability:** HLR-173 · trace: `list_projects`, `validate_project_files` (`app.py`, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a direct child folder of this work area holds no `project.json`, no data file and no A2L file, then the system shall leave it out of the Load dialog's projects section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** An empty folder `e` and a folder `n` holding only `notes.txt` → 0 rows.
  - A folder holding only `project.json`, one holding only `x.s19` and one holding only `c.a2l` → 1 row each (5 of 5).
  - A typed `<workarea>/e` still gives `not a project` (LLR-172.5b, unchanged).
- **Negative control:** code read, 9a tree: `list_projects` appends every folder that passes the link and reserved checks and `is_dir()`, so `e` and `n` are listed → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty folder; each of the three contents alone.

### LLR-173.4b — The files section is the one lister, filtered to loadable files (CR9-11, 9a C7)
- **Traceability:** HLR-173 · trace: `list_workarea_files`, `recent_kind` (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its work-area files section each file `list_workarea_files` returns whose suffix maps to a load kind.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`; TC-B100-37 (the census, widened) — `pytest tests/test_b100_recents.py -k tc_b100_37`
- **Numeric pass threshold:** `temp/` holding `a.s19`, `b.hex`, `c.a2l`, `d.a2l.json`, `e.txt` and the folder `.staging/` → 3 rows, `a.s19`, `b.hex`, `c.a2l`, in the lister's order.
  - The TC-B100-37 census, widened to count a string literal equal to `temp` in any letter case joined to a path expression (CR9-11) → 1 enumerating function, `list_workarea_files`.
  - A runtime spy on `os.scandir`, `os.listdir`, `Path.iterdir` and `Path.glob` during one dialog open → 1 enumeration of `temp/`, from `list_workarea_files`.
  - 3 of 3.
- **Negative control:**
  - A dialog section written as `(self.workarea / "temp").iterdir()` → the widened census finds 2 functions and the spy 2 enumerations → RED. The 9a census misses it, as CR9-11 showed.
  - A mutation with no suffix filter → 5 rows → RED.
- **Boundary catalog:** ☒ invalid — an A2L JSON dump, a text file, the staging folder.

### LLR-173.4c — The recents section is the store read
- **Traceability:** HLR-173 · trace: `read_recent_sources` (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When the Load dialog opens, the system shall list in its recents section each entry the recent-sources read returns, in the returned order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** a store of 3 entries → 3 rows in stored order; a store of 20 → 20 rows; a store of 2 valid entries among 3 the read refuses → 2 rows (3 of 3).
- **Negative control:** a mutation that sorts the rows by path → the 3-entry arm order differs → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — 20 entries; refused entries.

### LLR-173.4d — An empty projects section paints its tokens
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the project list returns no name, then the system shall paint `no projects` and `ctrl+s saves a project` in the Load dialog's projects section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 0 projects → 1 line holding both tokens, and that line cannot be loaded (LLR-173.2i) (1 of 1).
- **Negative control:** a mutation that paints nothing → 0 lines → RED.
- **Boundary catalog:** ☒ empty — no project.

### LLR-173.4e — An empty files section paints its tokens
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the work-area files section has no row, then the system shall paint `no work-area files` and `l loads a file` in it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** an empty `temp/`, and a `temp/` holding only `d.a2l.json` → 1 token line each (2 of 2).
- **Negative control:** a mutation that paints the tokens only when `list_workarea_files` is empty → the `d.a2l.json` arm paints nothing → RED.
- **Boundary catalog:** ☒ empty — no file; only unloadable files.

### LLR-173.4f — An empty recents section paints its token
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the recent-sources read returns no entry and no problem, then the system shall paint `no recent sources` in the Load dialog's recents section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** no store file; and a `LOCALAPPDATA` that is unset → 1 line holding `no recent sources` each (2 of 2).
- **Negative control:** a mutation that paints nothing → 0 lines → RED.
- **Boundary catalog:** ☒ empty — no store; no usable variable.

### LLR-173.4g — A store problem is painted in the recents section
- **Traceability:** HLR-173 · trace: `read_recent_sources` (`RecentSources.problem`) (`workspace.py`); the dialog rows builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the recent-sources read reports a problem, then the system shall paint that problem word and its next-step token in the Load dialog's recents section.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** A 65 537-byte store → 1 line holding `too large` and `the next load starts a new list`.
  - A store whose read raises `PermissionError` (injected) → 1 line holding `could not be read` and `check that the recent-sources file can be opened`.
  - 0 recent rows each (2 of 2).
- **Negative control:** a mutation that ignores `problem` → `no recent sources` painted → RED.
- **Boundary catalog:** ☒ error — too large; unreadable.

### LLR-173.4h — A recent row shows the recorded file name and kind only
- **Traceability:** HLR-173b · trace: the dialog rows builder (NEW, `app.py`); `RecentEntry` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint each recent row as the recorded path's file name followed by the recorded kind.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** `C:\cal\v2\fw.s19` (kind `s19`) → plain text `fw.s19` then `s19`, 0 `●` (1); a 300-character recorded path → a row of 1 line (LLR-173.6n).
- **Negative control:** a mutation that adds a size or a date to the row → that value can only come from a filesystem call, so LLR-173.4j turns RED; the text arm also differs → RED.
- **Boundary catalog:** ☒ boundary — a long path.

### LLR-173.4i — A highlighted recent previews the store's facts and nothing else
- **Traceability:** HLR-173b · trace: the preview builder (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS event):** When a recent row is highlighted, the system shall paint in the preview its full recorded path, its kind and `checked when loaded`, with no `●`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 3 recents highlighted in turn → 3 previews, each holding the full recorded path (the preview's content text, not the clipped painted strip — S9b-8 governs the paint), the kind and `checked when loaded`, 0 `●` (3 of 3).
- **Negative control:** code read, `1d677ba` prototype `pa_C.preview_file` reads the recent's bytes on highlight (`r.path.read_bytes()`) → a dialog copied from it previews size and "same bytes" → RED here and on LLR-173.4j.
- **Boundary catalog:** ☒ boundary — each kind.

### LLR-173.4j — No filesystem call touches a recent before it is loaded
- **Traceability:** HLR-173b · trace: the dialog rows builder, the preview builder (NEW, `app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall make no filesystem call on a recent entry's path before the engineer loads that row.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** the dialog opened and 3 recents highlighted (one present, one missing, one on an unassigned drive letter `Q:`) → 0 calls naming any of the 3 paths among `os.stat`, `os.lstat`, `os.scandir`, `os.listdir`, `open`, `os.path.exists` and `Path.exists` / `is_file` / `resolve` (a counting spy).
- **Negative control:** a mutation that previews a recent's size on highlight → 1 call per highlight → RED.
- **Boundary catalog:** ☒ invalid ☒ error — a missing entry; an unassigned drive.

### LLR-173.4k — A recent missing on pick is explained inside the dialog
- **Traceability:** HLR-173b · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a recent row the engineer loads names a path that does not exist, then the system shall keep the Load dialog open and paint `not found` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** a recent whose file was deleted, then `enter` → 1 token pair, 0 dismisses, 0 loads, the store bytes unchanged (the entry stays; ruling Q3) (1 of 1).
- **Negative control:** a mutation that dismisses and lets the router paint the status line → the dialog closes → RED.
- **Boundary catalog:** ☒ error — a deleted source.

### LLR-173.4l — The list order is projects, files, recents
- **Traceability:** HLR-173 · trace: the Load dialog compose (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall order the Load dialog's list as the projects section, then the work-area files section, then the recents section, each under a heading that cannot be loaded.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 1 item per section → 6 list lines in the order heading, project, heading, file, heading, recent (6 of 6); the headings read "Projects", "Work area" and "Recent".
- **Negative control:** a mutation that lists recents first → RED.
- **Boundary catalog:** ☒ boundary — one item per section.

### LLR-173.4m — An unreadable project list says so in the projects section
- **Traceability:** HLR-173 · trace: the dialog rows builder (NEW, `app.py`); `list_projects` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the project list cannot be read, then the system shall paint `could not be read` and `check that the folder can be opened, then load again` in the Load dialog's projects section, and the other sections still load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** `PermissionError` injected into `list_projects` → 1 token line in the projects section, the files and recents sections built as usual, 0 raises, the dialog open (1 of 1).
- **Negative control:** a mutation with no catch in the rows builder → the exception leaves `rows()` on mount and the app stops (Textual `exit_on_error`) → RED.
- **Boundary catalog:** ☒ error — an unreadable project list.

### LLR-173.4n — A linked file in a project folder is neither listed in the Load dialog preview nor installed by a project load
- **Traceability:** HLR-173a · trace: `_list_project_files`, `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS unwanted):** If a file in a project folder is a link, then the system shall neither list it in the Load dialog preview nor install it in a project load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project `P` holding `a.s19` and a symlink `b.s19` (to a regular file), with `active_variant` `b` → 1 preview row (`a.s19`), 1 `●`, and after `enter` 1 install (`a.s19`) and 0 opens of the link target (1 of 1).
- **Negative control:** a mutation whose scan follows links lists 2 rows → RED.
- **Boundary catalog:** ☒ invalid — a linked `.s19` beside a regular `.s19`.

### LLR-173.5 — A typed path not found is explained inside the dialog (UX-06)
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`); the Load dialog (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed path that does not exist, then the system shall keep the dialog open with the typed text unchanged and paint `not found` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/missing.s19` and `<workarea>/nope` → 1 token pair each, 0 dismisses, 0 status lines, the field text unchanged (2 of 2). SEC9b-1 (ruling B: refused, not truncated): an over-long paste (40 000 characters, over `#load_path`'s 4096 `max_length`) → the field unchanged and the app stays up; a `resolve_input_path` `ValueError`/`RuntimeError` → `not found` / `check the path`.
- **Negative control:** code read, 9a tree: `LoadFileScreen` dismisses with the `Path` and the refusal becomes a status line after the dialog has closed (LLR-172.5f) → RED.
- **Boundary catalog:** ☒ error — a missing file; a missing folder.

### LLR-173.5a — A typed unsupported file or relative folder is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.87
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed path that the typed-path route refuses as not a supported file, then the system shall keep the dialog open with the typed text unchanged and paint `not a supported file` and `check the path` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/notes.txt`, `<tmp>/fw.s19.` (trailing dot, CR9-3) and the relative `.s19tool/workarea/ab` → 1 token pair each, 0 dismisses, the field text unchanged (3 of 3).
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — an unsupported suffix; a trailing dot; a relative folder.

### LLR-173.5b — A typed folder that is not a project is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed folder of this work area that is not a project, then the system shall keep the dialog open with the typed text unchanged and paint `not a project` and `pick a project in the list` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<workarea>/temp`, `<workarea>/TEMP`, an empty `<workarea>/e` and `<workarea>/ab/flows` → 1 token pair each, 0 dismisses, 0 session resets (4 of 4). The `TEMP` arm is Windows only.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — reserved homes in two cases; an empty folder; a sub-folder.

### LLR-173.5c — A typed folder outside the work area is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed folder, or a typed `project.json`, outside this work area, then the system shall keep the dialog open with the typed text unchanged and paint `outside the work area` and `copy the folder into the work area` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<tmp>/P` and `<tmp>/P/project.json` → 1 token pair each, 0 dismisses (2 of 2).
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — an outside folder; an outside manifest.

### LLR-173.5d — A typed path through a link or junction is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed work-area folder path that passes through a link or junction, then the system shall keep the dialog open with the typed text unchanged and paint `link or junction` and `pick a project in the list` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `<workarea>/jx` (a junction to `ab`) and `<workarea>/jx/project.json` → 1 token pair each, 0 dismisses, 0 resets (2 of 2). Windows only; reported not run when no junction can be made.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED.
- **Boundary catalog:** ☒ invalid — a junction folder; a manifest through it.

### LLR-173.5e — A typed folder that cannot be read is explained inside the dialog
- **Traceability:** HLR-173d · trace: the dialog verdict callback (NEW), `_typed_load_route` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If the engineer asks the Load dialog to load a typed work-area folder that cannot be inspected, then the system shall keep the dialog open with the typed text unchanged and paint `could not be read` and `check that the folder can be opened, then load again` in `#load_reason`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-63 — `pytest tests/test_b100_load_dialog.py -k tc_b100_63`
- **Numeric pass threshold:** `PermissionError` injected into `os.lstat` of a walk prefix, and separately into `list_projects` → 1 token pair each, 0 dismisses, 0 raises (2 of 2). These are the CR9-6 arms painted in the dialog.
- **Negative control:** code read, 9a tree (as LLR-173.5) → RED; a mutation that drops the classifier's `OSError` catch → the exception leaves the key handler → RED.
- **Boundary catalog:** ☒ error — a walk error; a listing error.

### LLR-173.6 — A project row's preview marks what `choose_install_set` installs
- **Traceability:** HLR-173a · trace: `choose_install_set`, `build_variant_set`, `read_project_manifest`, `manifest_is_damaged`, the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.18, LED-2026-10-26-batch-100.34, LED-2026-10-26-batch-100.40, LED-2026-10-26-batch-100.46, LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When a project row is highlighted, the system shall mark with `●` in the preview the variant, MAC and A2L that the project-load install rule selects for that project with no variant known to be unreadable.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** 4 projects: clean; after a save-back (recorded active ≠ first by name); recorded active missing; A2L-only. Each highlighted, then `enter` → the `●` rows equal the Loaded panel's image, MAC and A2L paths (4 of 4). The A2L-only project marks the A2L only.
- **Negative control:** a mutation that computes the mark from the first variant by name → the save-back arm differs → RED.
- **Boundary catalog:** ☒ boundary — the four project kinds.

### LLR-173.6a — A load that installs another variant than the one marked names it
- **Traceability:** HLR-173a · trace: `_handle_load_project`, `choose_install_set` (`unreadable`), the Load-result composition (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a project load installs a variant other than the one the preview marked, then the system shall name the opened variant and the reason in the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project whose recorded active variant is a 0-byte file → the preview marks it (no image is read before Enter); after `enter` the Load-result panel names the next valid variant and `not readable` on the marked one (2 of 2).
- **Negative control:**
  - A mutation that drops the reason line from the panel → RED.
  - Declared: the panel behaviour holds since Inc 7 (LLR-169.6, HLR-178), so this arm passes on the 9a tree; the requirement fixes the one case where the mark and the install may differ, and the mutation is the RED.
- **Boundary catalog:** ☒ error — the marked variant unreadable at install.

### LLR-173.6b — A file row's preview marks the file and what the session keeps
- **Traceability:** HLR-173a · trace: the file preview builder (NEW), the install of a data or A2L load (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When a work-area file row is highlighted, the system shall mark with `●` in the preview that file and the MAC and A2L the session keeps after loading it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** each case highlighted, then `enter` → the `●` rows equal the Loaded panel's image, MAC and A2L paths:
  - nothing loaded and an S19 row → 1 `●`;
  - an A2L loaded and an S19 row → 2 `●`;
  - an S19 and a MAC loaded and a HEX row → as the install keeps them;
  - an S19 loaded and an A2L row → 2 `●`.
  - 4 of 4.
- **Negative control:** a mutation that marks only the highlighted file → the second arm differs → RED.
- **Boundary catalog:** ☒ boundary — nothing loaded; A2L kept; MAC present; A2L attach.

### LLR-173.6c — With a project open, a file row's preview says it becomes the active variant
- **Traceability:** HLR-173a · trace: the file preview builder (NEW), `current_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS state):** While a project is open, the system shall paint, in the preview of a highlighted data-file row, a note that the file becomes that project's active variant.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** project `P` open, S19 row → 1 note naming `P` (painted literally); no project open → 0 notes; project `P` open, A2L row → 0 notes (3 of 3).
- **Negative control:** a mutation that paints the note whatever the state → the no-project arm RED.
- **Boundary catalog:** ☒ boundary — no project; an A2L row.

### LLR-173.6d — A project row's preview lists its variants
- **Traceability:** HLR-173 · trace: `build_variant_set`, the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When a project row's preview read completes, the system shall list every variant of that project in the preview in `build_variant_set` order.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a project with `b.s19`, `a.s19` and `c.hex` → 3 variant lines in `build_variant_set` order, exactly one carrying `●` (1 of 1).
- **Negative control:** a mutation that lists only the marked variant → 1 line → RED.
- **Boundary catalog:** ☒ boundary — three variants of two kinds.

### LLR-173.6f — A project row's preview states the manifest
- **Traceability:** HLR-173 · trace: `read_project_manifest`, `manifest_is_damaged` (`variant_execution_service.py`, called from `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS event):** When a project row's preview read completes, the system shall paint the state of that project's `project.json` as `ok`, `no project.json` or `manifest damaged`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a valid manifest → `ok`; none → `no project.json`; a 1 MiB + 1 byte manifest → `manifest damaged` (3 of 3).
- **Negative control:** a mutation that paints `ok` whenever the file exists → the over-cap arm RED.
- **Boundary catalog:** ☒ empty ☒ boundary — absent; over the 1 MiB cap.

### LLR-173.6k — A project preview that cannot be read says so
- **Traceability:** HLR-173 · trace: the project preview builder (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS unwanted):** If a project's preview read raises an `OSError`, then the system shall paint `could not be read` and `check that the folder can be opened, then load again` in the preview, with no `●`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** `PermissionError` injected into the folder listing and, separately, into the manifest read → 1 token pair each, 0 `●`, 0 raises, the dialog open (2 of 2).
- **Negative control:** a mutation with no catch in the preview builder → the builder error ends the app's run (Textual's default `exit_on_error`) → RED.
- **Boundary catalog:** ☒ error — a listing error; a manifest read error.

### LLR-173.6l — The dialog reads nothing itself
- **Traceability:** HLR-173 · trace: the Load dialog (`screens.py`); its callables (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall give the Load dialog its rows, its previews and its typed-path verdicts only through callables from `app.py`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** AST census: the Load dialog class references 0 names bound by imports from `s19_app.tui.services.*`, `s19_app.tui.workspace` or `os` / `pathlib` filesystem calls.
  - `screens.py`'s set of imported modules gains 0 modules over the 9a tree (2 of 2).
- **Negative control:** a mutation where the dialog calls `list_workarea_files` itself → census 1 and 1 new import → RED.
- **Note (defect fixed):** the old text "`screens.py` imports no service module" is false at `4fef292`. `screens.py` already imports `operation_service`, `report_service`, `entropy_service` and `report_addendum` (lines 66-73). So the census is scoped to the dialog class and to no new module.
- **Boundary catalog:** none — a structural census.

### LLR-173.6m — The panes stack below 100 columns
- **Traceability:** HLR-173 · trace: the Load dialog `on_resize` (`screens.py`); `#load_dialog` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS state):** While the terminal is narrower than 100 columns, the system shall place the Load dialog's preview below its list.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** at 99 columns → the preview's region starts below the list's region (`preview.y >= list.y + list.height`); at 100 and 118 → the preview's region starts right of the list (`preview.x >= list.x + list.width`) (3 of 3); a resize from 118 to 99 with the dialog open → stacked (1).
- **Negative control:** a mutation that sets the break at 118 → the 100-column arm stacks → RED.
- **Boundary catalog:** ☒ boundary — 99, 100, 118; a live resize.

### LLR-173.6n — A list row never wraps
- **Traceability:** HLR-173 · trace: the Load dialog rows (`screens.py`); `#load_list` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.86
- **Statement (EARS ubiquitous):** The system shall paint each row of `#load_list` on one terminal line.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-64 — `pytest tests/test_b100_load_dialog.py -k tc_b100_64`
- **Numeric pass threshold:** a 120-character project name, a 130-character file name and a 300-character recent path, at 99, 100 and 118 columns → every row's region height is 1 (9 of 9).
- **Negative control:** a mutation that allows wrapping → the 130-character row is 2 lines high at 99 columns → RED.
- **Boundary catalog:** ☒ boundary — long names at three widths.

### LLR-173.7 — Painted text carries no internal decision id
- **Traceability:** HLR-173
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.86, LED-2026-10-26-batch-100.89, LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** No string painted by a surface this batch adds or changes — the Load dialog, the load question, the Save dialog, the busy indicator, the Load-result panel and the refusal tokens — shall carry an internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`, `HLR-…`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-66 — `pytest tests/test_b100_load_dialog.py -k tc_b100_66` (renders each surface at 118×54 and greps its painted text)
- **Numeric pass threshold:** Written at Inc 9b: the Load dialog in 6 scenarios (each section highlighted, the empty Load, a refused path, a store problem), the Load-result panel and the refusal-token constants → 0 matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-`, `HLR-`.
  - Extended at Inc 10 (the load question in 3 scenes — 1 item, 3 items, a project target — and the quit-parameter arm of LLR-174.2a), Inc 11 (the Save dialog in 6 scenarios — fresh, open project, merge, save as, a refusal, an empty Save → 0 decision ids), Inc 12a (the progress lines of the 7 long actions — labels and step names — and the two new token pairs) and Inc 12b (the busy line and the quit question — LLR-177.3f, LLR-177.4a).
- **Negative control:** the prototypes paint "Browse is gone (D7)" and "D10: click loads OFF" (UX-18 captures; `pa_C` via `_pa_common._paint_d10`) → a surface copied from them → RED; the prototypes' decision-id strings (UX-18) copied into the question → RED.
- **Boundary catalog:** none — the scan has no input classes; its set is every painted string of the surfaces written so far.

### LLR-174.1 — An image replacement asks exactly when the image is unsaved
- **Traceability:** HLR-174, HLR-174a · trace: `_confirm_then_load` (NEW, B100-I20), the load guard (NEW, `app.py`); `ChangeService.differs_from_last_saved` (`change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When a route requests an image replacement, the system shall ask the question if and only if the loaded image differs from the copy last loaded or written.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_load_question.py -k tc_b100_44`
- **Numeric pass threshold:** 14 of 14 arms:
  - The 8 image-replacement cells of the table (D × F × W) → 4 ask (D = 1), 4 load (D = 0), 8 of 8.
  - Boundaries, 0 questions each: patched → Save project → data load; patched → save-back → data load; a patch that writes the bytes already there; undo then Apply of the now-empty document (C12, the byte restored) (4 of 4).
  - Boundary, 1 question: `undo()` alone (C13, the patched byte stays) (1 of 1).
  - Boundary, 1 question: patched → Save project → patched again → data load (1 of 1).
- **Negative control:**
  - Dropping D from the rule → 4 cells wrong (executed enumeration, LED .17).
  - Executed on the 9a tree (this E1's probe): `after apply: D = True`, then the Workarea pick runs with the stack `['Screen']` → RED.
- **Boundary catalog:** ☒ boundary — every cell; the saved-then-patched cell.

### LLR-174.1a — An attach never asks
- **Traceability:** HLR-174a · trace: the load guard (NEW, `app.py`); `_merge_mac_with_existing_primary`, `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When a route requests a MAC or A2L attach, the system shall attach the file without the question.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_load_question.py -k tc_b100_44`
- **Numeric pass threshold:** 10 of 10 arms:
  - The 8 attach cells → 0 ask (8 of 8).
  - An unsaved patch, then a MAC attach → the patched byte unchanged and D still true; then an A2L attach → the same (2 of 2).
- **Negative control:**
  - The round-2 rule (an attach asks on D) → 4 cells wrong (executed enumeration, LED .17).
  - Executed on the 9a tree (this E1's probe): `MAC attach over patch: stack ['Screen'] | byte kept = True | D = True` — the attach keeps the patch, so asking would be a false alarm.
- **Boundary catalog:** ☒ boundary — a MAC attach with and without a loaded image; an A2L attach.

### LLR-174.1b — A project load asks when any of the three flags is set
- **Traceability:** HLR-174, HLR-174a · trace: the load guard (NEW, `app.py`); `ChangeService.differs_from_last_saved`; `FlowBuilderPanel.is_dirty` (`flow_screens.py`, unchanged); `PatchEditorPanel.is_dirty` (NEW, LLR-174.1c)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When a route requests a project load, the system shall ask the question if and only if the image is unsaved, the Flow Builder is dirty or the Patch Editor is dirty.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_load_question.py -k tc_b100_44`
- **Numeric pass threshold:** 10 of 10 arms:
  - The 8 project cells → 7 ask, 1 load (8 of 8). With LLR-174.1 and LLR-174.1a: 24 of 24 cells, 11 ask, 13 load.
  - Project P open, nothing unsaved, project load of Q → 0 questions (1 of 1).
  - Patched + 1 Patch Editor entry → Save project → project load → 0 questions (1 of 1).
- **Negative control:**
  - Dropping F → 1 cell wrong; dropping W → 1 cell wrong; dropping D → 1 project cell wrong (executed enumeration, LED .17).
  - The `pb_A` rule "ask when a project is open" → the P-open arm asks → RED.
- **Boundary catalog:** ☒ boundary — every cell; re-loading the open project.

### LLR-174.1c — The Patch Editor flag is read through a public reader
- **Traceability:** HLR-174 · trace: `PatchEditorPanel.is_dirty` (NEW, `screens_directionb.py`); `_handle_save_dialog` (`app.py`, the E3 R1 read at the 9a tree's `:10576`); the load guard (NEW)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall read the Patch Editor panel's dirty flag only through a public reader of that panel.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_load_question.py -k tc_b100_44`
- **Numeric pass threshold:** 6 of 6 arms:
  - AST census of `s19_app/` outside `screens_directionb.py`: 0 attribute reads of `_dirty` on a `PatchEditorPanel` value (1 of 1).
  - The reader follows the flag's writers: True after an entry edit, after typing in the paste buffer and after Parse pasted; False after `mark_saved` and after `mark_loaded` (5 of 5).
- **Negative control:** executed on the 9a tree (this E1's probe): `hasattr(PatchEditorPanel,'is_dirty') = False`; `private reads of panel._dirty in app.py: 1 [10576]` → RED.
- **Boundary catalog:** ☒ boundary — each of the five writers of the flag.
- **Note (premise):** P-43. The reader is the reason `screens_directionb.py` is Inc 10's fourth file (§5.5).

### LLR-174.2 — One modal with exactly two buttons
- **Traceability:** HLR-174 · trace: the question modal (NEW, `screens.py`); `_confirm_then_load` (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.3, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the guard asks, the system shall show one modal question holding exactly the two buttons `#confirm_yes` and `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** one guarded data load with D → the screen stack grows by 1, the top screen holds 2 `Button` widgets with ids `confirm_yes` and `confirm_no`, 0 other buttons and 0 `Input` / `TextArea` widgets; while it is open, the question itself pushes 0 screens (VS-PB-2, no "save first" key) (4 of 4).
- **Negative control:** the `pb_B` variant (a third "Save first" button bound to `s`) → 3 buttons → RED. On the 9a tree: 0 modals (probe) → RED.
- **Boundary catalog:** ☒ boundary — one modal per request.

### LLR-174.2a — The modal takes its text and labels as parameters
- **Traceability:** HLR-174 · trace: the question modal `__init__` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall build the question modal from a title, a question text and two button labels passed to it as parameters.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** the modal built with the title `Quit?`, the text `A save is running.` and the labels `Quit (y)` / `Stay (n)` → those 4 strings painted, 0 painted `Replace`; `y` → the replace answer and `n` → the cancel answer (6 of 6).
- **Negative control:** a mutation that hard-codes `Replace (y)` → the quit arm paints `Replace (y)` → RED.
- **Boundary catalog:** ☒ boundary — the load question and the quit question (Inc 12 reuses the modal, C-UX-4).

### LLR-174.2b — The focus starts on Cancel
- **Traceability:** HLR-174c · trace: the question modal `AUTO_FOCUS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the question opens, the system shall put the focus on `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** the question pushed → `focused.id == "confirm_no"` (1 of 1; Q1-2).
- **Negative control:** a mutation with `AUTO_FOCUS = "#confirm_yes"` → RED (and HLR-174c's immediate `enter` replaces).
- **Boundary catalog:** ☒ boundary — the question pushed.

### LLR-174.2c — `y` answers replace
- **Traceability:** HLR-174b · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer presses `y` in the question, the system shall close the question with the replace answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** `y` with the focus on `#confirm_no` and with the focus on `#confirm_yes` → the replace answer each time (2 of 2).
- **Negative control:** a mutation with no `y` binding → the question stays open → RED.
- **Boundary catalog:** ☒ boundary — the focus on either button.

### LLR-174.2d — `n` and `escape` answer cancel
- **Traceability:** HLR-174c · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer presses `n` or `escape` in the question, the system shall close the question with the cancel answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** `n` and `escape`, each with the focus on each button → the cancel answer 4 times (4 of 4).
- **Negative control:** a mutation with no `escape` binding (the P-18 shape) → the question stays open → RED.
- **Boundary catalog:** ☒ boundary — both keys, the focus on either button.

### LLR-174.2e — `enter` acts on the focused button
- **Traceability:** HLR-174b, HLR-174c · trace: Textual `Button` (`enter` → press); the question modal `on_button_pressed` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer presses `enter` in the question, the system shall give the answer of the focused button.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** an immediate `enter` → cancel; `tab`, then `enter` → replace; `tab`, `tab`, then `enter` → cancel (3 of 3).
- **Negative control:** a mutation that maps `enter` to replace at the screen level → the immediate `enter` replaces → RED.
- **Boundary catalog:** ☒ boundary — the focus wrapping after two `tab`s.

### LLR-174.2f — A click answers with the clicked button
- **Traceability:** HLR-174b, HLR-174c · trace: the question modal `on_button_pressed` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer clicks `#confirm_yes` or `#confirm_no`, the system shall close the question with that button's answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** a click on `#confirm_yes` → replace; a click on `#confirm_no` → cancel (2 of 2).
- **Negative control:** a mutation that ignores `Button.Pressed` → the click leaves the question open → RED.
- **Boundary catalog:** ☒ boundary — both buttons.

### LLR-174.2g — Any other key leaves the question open
- **Traceability:** HLR-174 · trace: the question modal `BINDINGS` (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If the engineer presses a key that no priority binding holds, other than `y`, `n`, `escape`, `enter`, `tab` or `shift+tab`, while the question is open, then the system shall keep the question open with the session unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** `a`, `l`, `p`, `s`, `q` and `space` → the question still the top screen and the session digest unchanged (6 of 6).
- **Negative control:** the `pb_B` binding of `s` (save first) → the `s` arm leaves the question → RED.
- **Boundary catalog:** ☒ invalid — six keys outside the set, two of them app keys (`l`, `p`) and `q` (quit).
- **Note (informative):** priority keys are LLR-174.2h's subject; `ctrl+q` and the palette's Quit under the question belong to Inc 12's quit question, and no guard is added here (A10-06).

### LLR-174.2h — The priority keys are inert under the question
- **Traceability:** HLR-174 · trace: `S19TuiApp.check_action` (`app.py`; the 9b guard `_LOAD_DIALOG_INERT_ACTIONS`); `BINDINGS` (`ctrl+k`, `ctrl+d`, `ctrl+l`, `ctrl+s`, `priority=True`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the question is open, then the system shall keep the question as the top screen and run no app action.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** each of the 4 keys → the stack depth unchanged, the question on top, 0 calls of `action_load_file`, `action_save_project`, `action_focus_palette` and `action_cycle_density` (spies) (4 of 4).
- **Negative control:** code read, Textual 8.2.8: priority bindings walk the full chain, the App included, through a modal (the 9b finding behind LLR-173.2e), and 9b's guard is keyed on `LoadDialog` only → `ctrl+l` pushes a Load dialog over the question → RED. The executed probe is `planned` for the E2 baseline.
- **Boundary catalog:** ☒ invalid — the four priority keys.

### LLR-174.2i — Names are painted literally
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `painted_names` (`project_gather_service.py`); the question modal widgets with markup off (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall paint every name in the question literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** a loaded image `[b]x.s19`, a flow named `[red]f`, a project `[i]P` as the open project and as the target, and an image name holding U+202E → each painted name equals `painted_names([name])` and the painted text has 0 markup spans (5 of 5).
- **Negative control:** a mutation that paints with markup on → `[b]x.s19` paints as `x.s19` → RED.
- **Boundary catalog:** ☒ invalid — markup, a bidirectional control, a 130-character name (clipped to 120 with `…`).

### LLR-174.2j — The Patch Editor's own load keeps its guard
- **Traceability:** HLR-174 · trace: `LoadGuardScreen`, `PatchEditorPanel.DirtyLoadRequested` (`screens_directionb.py`, unchanged); `on_patch_editor_panel_dirty_load_requested` (`app.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall guard the Patch Editor's own document load with its existing dirty-load warning, not with the load question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** a dirty Patch Editor, then its Load button → 1 `LoadGuardScreen`, 0 load questions (1 of 1).
- **Negative control:** a mutation routing `DirtyLoadRequested` through the load question → 0 `LoadGuardScreen` → RED.
- **Boundary catalog:** none — one route, kept as it is.

### LLR-174.2k — The title names what is replaced
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall title the load question `Replace <current>?`, where `<current>` is the open project's name, else the loaded image's file name, else `the current session`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** project P open → `Replace P?`; no project, image `fw.s19` loaded → `Replace fw.s19?`; neither, a dirty Flow Builder, then a project load → `Replace the current session?` (3 of 3).
- **Negative control:** a mutation that always uses the image name → the P arm paints `Replace fw.s19?` → RED.
- **Boundary catalog:** ☒ boundary — project, image only, neither.

### LLR-174.2l — The unsaved image is named by its file name
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the guard asks while the image is unsaved, the system shall name the loaded image's file name in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** D with `fw.s19` loaded → the question text holds `fw.s19`, for a data load and for a project load (2 of 2).
- **Negative control:** a mutation that names the project instead of the image → the data-load arm (no project) misses `fw.s19` → RED.
- **Boundary catalog:** ☒ boundary — an image replacement and a project load.

### LLR-174.2m — Unsaved Patch Editor work is named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the guard asks for a project load while the Patch Editor is dirty, the system shall name `Patch Editor entries` in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** W only → `Patch Editor entries` present; D only → absent (2 of 2).
- **Negative control:** a mutation that names it on D → the D-only arm holds it → RED.
- **Boundary catalog:** ☒ boundary — an entry edit; an unparsed paste buffer (both set W).

### LLR-174.2n — Unsaved Flow Builder edits are named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `FlowBuilderPanel.current_flow`, `FlowBuilderPanel.is_dirty` (`flow_screens.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the guard asks for a project load while the Flow Builder is dirty, the system shall name `flow <flow name>` in the question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** F with the flow `patch_chain` → `flow patch_chain` present; F with an unnamed flow → `flow flow` (the panel's default name) present; D only → no `flow ` item (3 of 3).
- **Negative control:** a mutation that drops the flow item → the F arm misses it → RED.
- **Boundary catalog:** ☒ boundary — a named flow, the default name.

### LLR-174.2o — The load target is named
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`); `_confirm_then_load` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall end the load question with `Load <target> anyway?`, where `<target>` is `project <name>` for a project load and the file name of the requested file otherwise.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** a project row `Q` → `Load project Q anyway?`; a typed `<tmp>/b.s19` → `Load b.s19 anyway?`; a Workarea pick `x.hex` → `Load x.hex anyway?`; `v` to `firmware_b` → `Load firmware_b.s19 anyway?` (4 of 4).
- **Negative control:** a mutation that names the current file as the target → the typed arm paints the old name → RED.
- **Boundary catalog:** ☒ boundary — one target per route.

### LLR-174.2p — The load question's buttons say Replace and Cancel
- **Traceability:** HLR-174b, HLR-174c · trace: `_confirm_then_load` (NEW, `app.py`); the question modal (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall label the load question's buttons `Replace (y)` on `#confirm_yes` and `Cancel (n)` on `#confirm_no`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** 2 labels painted, each on its id (2 of 2); each shown key pressed acts (the "every shown key is verified" rule, §3 preface) (2 of 2).
- **Negative control:** a mutation that reuses `ConfirmDiscardScreen`'s labels `Discard` / `Cancel` (`screens.py:934-935`) → 0 `Replace (y)` painted → RED.
- **Boundary catalog:** none — two fixed labels.

### LLR-174.2q — The question says the items hold unsaved changes, in two sentences
- **Traceability:** HLR-174d · trace: the question text composer (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall state in the load question, in at most two sentences, that the named items hold unsaved changes.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** with 1, 2 and 3 items → the body holds the token `unsaved changes` once and at most 2 sentence ends (`.` or `?` outside names) (3 of 3).
- **Negative control:** a mutation that writes one sentence per item → the 3-item arm has 4 sentences → RED.
- **Boundary catalog:** ☒ boundary — 1, 2 and 3 items.

### LLR-174.2r — Both buttons and the body stay on screen
- **Traceability:** HLR-174 · trace: the question modal box rules (`styles.tcss`); the question modal (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall keep both buttons and the body of the question fully visible: each of the three regions equals its clipped region and lies inside the screen region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** 3 items whose names are 120 characters long, at 99×54, 118×54 and 220×60 → both buttons and the body fully visible (each region equals its clipped region and lies inside the screen region) (3 of 3); the same at 118×54 with 1 short item (1).
- **Negative control:** a mutation setting `min-width: 120` on `#confirm_box` → at 99 columns `#confirm_no` has 0 visible columns → RED; a mutation that fixes the box height at 7 rows with `#confirm_buttons` undocked → both buttons have 0 visible rows → RED.
- **Boundary catalog:** ☒ boundary — 99, 118 and 220 columns; the longest names.

### LLR-174.2s — A second answer is ignored
- **Traceability:** HLR-174 · trace: the question modal `_close` `_dismissed` guard (NEW, `screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If a second answer reaches the question after the first, then the system shall ignore it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** Q5-1 (`_close(True); _close(False)` in one tick) → 1 callback `True`, 1 pop, 0 exceptions; Q5-2 (`y` then `n` queued) → 1 answer; Q5-3 (the `_dismissed` flag, `escape` returns) → `CB == [False]` (3 of 3).
- **Negative control:** the `_dismissed` guard removed → `ScreenStackError` (K7, executed) → RED.
- **Boundary catalog:** ☒ error — a double answer in one tick.

### LLR-174.2t — The Patch Editor's change-file dropdown keeps the guard
- **Traceability:** HLR-174 · trace: `PatchEditorPanel.ChangeFileSelected`; `on_patch_editor_panel_change_file_selected` (`app.py`); `LoadGuardScreen` (`screens_directionb.py`, unchanged)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If the engineer picks a change file in the Patch Editor's dropdown while the panel holds unsaved entries, then the system shall show the Patch Editor's load guard before replacing them.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_load_question.py -k tc_b100_45`
- **Numeric pass threshold:** dirty + pick → 1 `LoadGuardScreen`, 0 loads, the entry count and the flag unchanged; clean + pick → 0 guards and the file loads (2 of 2).
- **Negative control:** the `is_dirty` read removed → the dirty pick replaces the entries with no guard → RED.
- **Boundary catalog:** ☒ boundary — a dirty panel; a clean panel.

### LLR-174.3 — The answer comes before the project-session reset
- **Traceability:** HLR-174b · trace: `_confirm_then_load` (NEW); `_route_load_project`, `_handle_load_project`, `_reset_project_session` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer confirms a project load, the system shall run the project-session reset after the answer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_load_question.py -k tc_b100_46`
- **Numeric pass threshold:** `y` on a project load with W → 1 reset call, recorded after the question closed (an order spy on the dismiss and the reset); the same for re-loading the open project (2 of 2).
- **Negative control:** a mutation that resets before asking → the reset is recorded before the dismiss → RED.
- **Boundary catalog:** ☒ boundary — re-loading the open project.

### LLR-174.3a — A cancelled project load runs no reset
- **Traceability:** HLR-174c · trace: `_confirm_then_load` (NEW); `_reset_project_session` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If the engineer cancels the question of a project load, then the system shall not run the project-session reset.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_load_question.py -k tc_b100_46`
- **Numeric pass threshold:** `n`, `escape` and an immediate `enter` on a project load with D, F and W → 0 reset calls, the Patch Editor entry count unchanged and the Flow Builder blocks unchanged (3 of 3).
- **Negative control:** a mutation that resets before asking → the cancelled session is empty → RED.
- **Boundary catalog:** ☒ boundary — each cancel key.

### LLR-174.3b — The project-load handler asks nothing
- **Traceability:** HLR-174 · trace: `_handle_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS ubiquitous):** The system shall ask no question from inside the project-load handler.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_load_question.py -k tc_b100_46`
- **Numeric pass threshold:** 2 of 2 arms:
  - A direct `_handle_load_project("P")` with D, F and W → 0 questions and 1 load (`current_project == "P"`).
  - AST: the body of `_handle_load_project` holds 0 calls of `push_screen` and 0 calls of the seam (2 of 2).
- **Negative control:** a mutation that moves the guard into `_handle_load_project` → the direct call pushes 1 question (and the 13 test files that call it directly, §5.4, wait on a modal) → RED.
- **Boundary catalog:** none — a structural census plus one direct call.

### LLR-174.3c — A confirmed project load that is then refused keeps the work
- **Traceability:** HLR-174b, HLR-174c · trace: `_confirm_then_load` (NEW); `_handle_load_project` (`app.py`, the refusals before the reset)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If a project load that the engineer confirmed is refused before the project-session reset, then the system shall keep the unsaved work.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_load_question.py -k tc_b100_46`
- **Numeric pass threshold:** a listed project `M2` holding 1 data file and 2 MAC files (listed by §1.3; refused by `_list_project_files`), with D and W → `y` → 1 refusal line, 0 reset calls, the session digest unchanged, D still true, the Patch Editor entry count and W unchanged (5 of 5); an A2L-only project `A2LONLY` whose one A2L cannot be read (an ACL deny-read or a lock) → `y` → 1 refusal line `No supported files in project: A2LONLY`, 0 reset calls, `current_file` unchanged, the entry count unchanged and the flag unchanged (5 of 5; probe_sec_refuse).
- **Negative control:** a mutation that clears the flags or runs the reset when `y` is pressed → D or W false after the refusal → RED; the base order (the reset before the A2L read) → the A2L arm finds `current_file` `None`, 0 entries and the flag cleared after `y` → RED.
- **Boundary catalog:** ☒ error — a project refused after the answer.

### LLR-174.3d — A cancelled variant switch leaves the pending selection unchanged
- **Traceability:** HLR-174c · trace: `_handle_select_variant` (`app.py`); `_pending_variant_id`
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS unwanted):** If the engineer cancels the question of a variant switch, then the system shall leave the pending variant selection unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-46 — `pytest tests/test_b100_load_question.py -k tc_b100_46`
- **Numeric pass threshold:** `n` on the C40 switch → `_pending_variant_id is None` and `0` `load_from_path` calls; then a `#files_list` pick of `other.s19` answered `y` → after the install `current_file.variant_id is None` and `_variant_set.active_id == "firmware_a"` (2 of 2; C42).
- **Negative control:** the stamp set before the seam (the base order) → `_pending_variant_id == "firmware_b"` after `n`, and the next install stamps `other.s19` as `firmware_b` → RED.
- **Boundary catalog:** ☒ boundary — a cancelled switch; the next confirmed load.

### LLR-174.4 — One load seam for every image-replacing route
- **Traceability:** HLR-174 · trace: `_confirm_then_load` (NEW, B100-I20); `_handle_load_dialog`, `_load_workarea_file`, `_load_from_item`, `_handle_select_variant`, `_route_load_project`, `_load_path_from_user_input` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.17, LED-2026-10-26-batch-100.27, LED-2026-10-26-batch-100.89, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall pass every image-replacing route through one load guard before the route changes the session.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_load_question.py -k tc_b100_72`
- **Numeric pass threshold:** 8 of 8 arms plus the census:
  - With an unsaved patch: the Load dialog, a Workarea Files pick and `v` by keys, and the Load-result panel's `v` with D forced through a private call (declared) → 4 questions; `n` on each → the session digest unchanged (4 + 4).
  - AST census of `app.py`: every call of `load_selected_file`, `load_from_path`, `load_a2l_from_path` and `_handle_load_project` is inside a `go` passed to the load seam, inside `_handle_load_project`, or is `load_from_path`'s worker start; `_route_load_project`'s body is the project seam, so its callers are exempt (0 bypasses).
- **Negative control:** executed on the 9a tree (this E1's probe): the Workarea pick, the Load dialog router and the variant switch each replace a patched image with the stack `['Screen']`; on `1d677ba` (P-42) the same for the Workarea pick and `v` → RED.
- **Boundary catalog:** ☒ boundary — the four routes; the start-up load.
- **Note (informative):** Inc 12b adds the busy refusal to this seam (LLR-177.3a, TC-B100-72 extension): an image-replacing route that reaches the guard while a session action runs paints the busy line without asking the load question.

### LLR-174.4a — One question per load request
- **Traceability:** HLR-174 · trace: `_confirm_then_load` (NEW); `_handle_load_dialog`, `_load_path_from_user_input`, `_route_load_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When one load request passes the load guard, the system shall ask at most one question for that request.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_load_question.py -k tc_b100_72`
- **Numeric pass threshold:** with D and W: a typed absolute project folder (the router, the typed-path route, then the project route) → 1 question; a recent data path → 1; a project row → 1 (3 of 3). After `y`, 0 further questions until the load ends.
- **Negative control:** a mutation that guards both the dialog router and the project route → the typed project folder asks twice → RED.
- **Boundary catalog:** ☒ boundary — a request that passes two routing functions.

### LLR-174.4b — A typed or recent path takes its load kind from the resolved path
- **Traceability:** HLR-174, HLR-174a · trace: `_load_path_from_user_input`, `_typed_load_route` (`app.py`); `_confirm_then_load` (NEW); `resolve_input_path` (`workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.89, LED-2026-10-26-batch-100.90
- **Statement (EARS event):** When the Load dialog closes with a `path` or `recent` choice, the system shall take the load kind from the path the typed-path route resolves, not from the typed text: an attach only when the resolved suffix is a MAC suffix and equals the typed suffix, else an image (fail closed).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_load_question.py -k tc_b100_72`
- **Numeric pass threshold:** with D and W: typed `.mac` → 0 questions (attach); typed `.a2l` → 0; typed `.s19` → 1 question (image); typed `<W>/P` → 1 question naming `Patch Editor entries` (project); a typed file removed after the dialog's verdict (the classification refuses `not found`) → 0 questions and 1 refusal line; a relative `cal.mac` that is a symlink to a `.s19` → 1 question (the resolved suffix differs, fail closed to image, CR10-01); a plain relative `.mac` → 0 questions and the attach keeps D (CR10-01) (7 of 7).
- **Negative control:** a mutation that keys the kind on the dismiss kind (`path` → image) → the `.mac` arm asks → RED; a mutation that keys the kind on the typed suffix (the 1747479 rule) → the `cal.mac`-link arm attaches with no question → RED (MC2).
- **Boundary catalog:** ☒ boundary ☒ error — the three kinds; a refusal found at routing time; a typed suffix that differs from the resolved suffix.

### LLR-174.4c — A work-area file takes its load kind from its suffix
- **Traceability:** HLR-174, HLR-174a · trace: `_load_workarea_file` (9b G1), `_load_from_item` (`app.py`); `_confirm_then_load` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.89
- **Statement (EARS event):** When the engineer picks a work-area file, the system shall treat a MAC or A2L file as an attach and any other file as an image replacement.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_load_question.py -k tc_b100_72`
- **Numeric pass threshold:** with D: `x.mac`, `c.a2l`, `x.s19` and `x.hex`, from the Load dialog's `workarea` rows and from the Workarea Files list → 0, 0, 1 and 1 questions on each surface (8 of 8).
- **Negative control:** a suffix-blind mutation (every pick is an image replacement) → the `.mac` and `.a2l` arms ask → RED.
- **Boundary catalog:** ☒ boundary — each loadable suffix on both surfaces; a suffix in upper case (`X.MAC`).

### LLR-175.1 — The target line names the sanitised folder and its kind
- **Traceability:** HLR-175 · trace: `SaveProjectScreen` name-change handler (`screens.py`); `_prepare_project_save` (NEW), `_save_dialog_preview` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.5, LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.93
- **Statement (EARS event):** When the name in the Save project dialog changes, the system shall paint in `#save_where` the sanitised folder name and one kind of `new folder`, `updates the open project`, `merges into an existing project` and `new project in an existing folder`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** 7 of 7 target lines:
  - F-fresh: `a b` → `ab` and `new folder`; `../evil` → `evil` and `new folder`.
  - F-open (`P` open): `P` → `updates the open project`; the unsanitised form `P ` → `P` and `updates the open project`; with `P` saved on disk as `Ab` and open, `ab` typed → `Ab` and `updates the open project` (LED .52(a)). The LED .52(a) rebind applies only when no folder holds the exact typed (sanitised) name: `straße` typed with `strasse` open and `straße` present → `straße` and `merges into an existing project` (SR-11-1).
  - F-merge: `ab` → `ab` and `merges into an existing project`.
  - an existing folder that is not a project (empty, or `notes.txt` only) → `<folder>` and `new project in an existing folder`.
  - 7 of 7, each line with 0 markup spans.
- **Negative control:** executed on the 9a tree (P11-2): `typed 'a b' -> dialog text has 'ab' folder line? False` → RED. Mutation: the kind computed with a case-sensitive comparison → the `ab` / `Ab` arm says `merges into an existing project` → RED.
- **Boundary catalog:** ☒ boundary — the open project in another case; the unsanitised form of the open project's name.

### LLR-175.1a — A reserved name is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW, the HLR-164 reserved rule moved out of `_handle_save_dialog`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name's sanitised form equals a reserved work-area home compared case-folded, then the system shall paint `reserved name` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `reports`, `CRC`, `Splits`, `FLOWS`, `Temp` → 5 token pairs in the dialog, 0 dismisses on `alt+s`, 0 new paths (5 of 5).
- **Negative control:** executed on the 9a tree (P11-2): `typed 'Reports' -> dialog text has 'reserved name'? False` → RED. Mutation: the comparison without case-folding → `Reports` paints no pair → RED.
- **Boundary catalog:** ☒ invalid — 5 spellings in mixed case.

### LLR-175.1b — A device name is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `is_windows_device_name`, `workspace.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name, one of its path components or its sanitised form is a Windows device name compared case-folded, then the system shall paint `device name` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `nul`, `CON`, `com1`, `LPT¹`, `con.txt`, `C O N` → 6 token pairs, 0 dismisses on `alt+s`, 0 new paths (6 of 6).
- **Negative control:** mutation: only the sanitised form is checked → `con.txt` (sanitised `contxt`) paints no pair → RED. On the 9a tree the dialog paints nothing before Save (code read: no name-change handler) → RED.
- **Boundary catalog:** ☒ invalid — an extension, a superscript digit, spaces inside.

### LLR-175.1c — A disguised clash is refused in the dialog, naming both names
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name's sanitised form equals, compared case-folded, the folder name of a project that is not open while the typed name differs from that folder name, then the system shall paint `already a project`, both names and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** F-merge with another project open: `a b` → 1 line holding `already a project`, `a b`, `ab` and `choose another name`; `AB` → the same tokens naming `AB` and `ab`; `ab` exactly → no refusal and `merges into an existing project` (3 of 3); 0 new paths and the `ab` folder's file digests unchanged after `alt+s` on each refused arm.
- **Negative control:** mutation: the clash compares without case-folding → `AB` paints `new folder` → RED. On the 9a tree the clash is painted only after the dialog closes (code read) → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — a case-only clash; the exact name (a merge, not a clash).

### LLR-175.1d — A name over 64 characters is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `PROJECT_NAME_MAX_CHARS`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name's sanitised form is longer than 64 characters, then the system shall paint `name too long` and `shorten the name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** 64 characters → no refusal; 65 and 300 → 2 token pairs, the app running, 0 new paths (3 of 3).
- **Negative control:** mutation: the cap read as 65 → the 65-character arm paints no pair → RED.
- **Boundary catalog:** ☒ boundary — 64 / 65 / 300.

### LLR-175.1e — A name that makes the path too long is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_SAVE_FULL_PATH_LIMIT`, `_SAVE_REPORT_SUFFIX_CHARS`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name would make a project file path longer than the path limit, then the system shall paint `path too long` and `shorten the name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a base path sized so that a name of length L meets the limit exactly → no refusal; length L + 1 → 1 token pair (2 of 2).
- **Negative control:** mutation: the 53-character report suffix dropped from the sum → the L + 1 arm paints no pair → RED.
- **Boundary catalog:** ☒ boundary — the limit met; exceeded by 1.

### LLR-175.1f — A target that is a link or junction is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_project_folder_refusal`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the folder the typed name selects exists as a link or junction, then the system shall paint `link or junction` and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a directory junction `W/jt` (made with `_winapi.CreateJunction`) and `jt` typed → 1 token pair, 0 files written through the junction after `alt+s` (1 of 1; Windows-only arm, counted).
- **Negative control:** mutation: the link check removed from the preparation → the dialog shows `merges into an existing project` for `jt` → RED.
- **Boundary catalog:** ☒ invalid — a junction; a symbolic link where the platform allows one.

### LLR-175.1g — A target that cannot be inspected is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `_project_folder_refusal`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the folder the typed name selects cannot be inspected, then the system shall paint `could not be read` and `check that the folder can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `os.lstat` raising `PermissionError` for the target (the TC-B100-62 fixture pattern) → 1 token pair, 0 dismisses on `alt+s` (1 of 1).
- **Negative control:** mutation: the `unreadable` reason mapped to "no refusal" → the dialog paints a kind → RED.
- **Boundary catalog:** ☒ error — a permission error on the target.

### LLR-175.1h — A name with no usable character is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; `sanitize_project_name`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name holds a character other than a space but its sanitised form is empty, then the system shall paint `name is empty` and `type a project name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `!!!`, `..`, `/` → 3 token pairs painted before Save, 0 dismisses on `alt+s` (3 of 3).
- **Negative control:** mutation: the pair painted only on Save (as for an empty field, LLR-175.3b) → `!!!` paints nothing before Save → RED.
- **Boundary catalog:** ☒ invalid — punctuation only; `..`.

### LLR-175.1i — A plan refusal is painted in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW), `_plan_project_save`, `plan_project_save` (`SavePlan.refusal`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the plan for the typed name is refused, then the system shall paint the plan's refusal text, with its reason token and next-step token, in the Save project dialog in place of the summary rows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** a target holding a second MAC file → `already has a MAC file` and `choose another name`; a target holding a second A2L file → `already has an A2L file` and `choose another name`; a save as over 2 000 files → `too many files to copy` and `move files out of the project, then save again` (3 of 3); 0 summary rows painted and 0 new paths after `alt+s` on each.
- **Negative control:** mutation: the painter paints the rows of a refused plan and drops its refusal → 0 token pairs → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the MAC rule, the A2L rule, the 2 000 / 2 001-file ceiling.

### LLR-175.1j — Too little free space is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW; the free-space check moved out of `_handle_save_dialog`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If a save to a new folder needs more bytes than the work area's volume has free, then the system shall paint `not enough free space` and `free disk space or remove files from the project` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `shutil.disk_usage` stubbed (TC only) to report `plan.total_bytes − 1` free → 1 token pair, 0 dismisses on `alt+s`; exactly `plan.total_bytes` free → no refusal (2 of 2).
- **Negative control:** mutation: the free-space check left in the handler only → the dialog paints no pair, and `alt+s` closes it before the refusal → RED.
- **Boundary catalog:** ☒ boundary — free space equal to the need; one byte short.

### LLR-175.1k — A missing source file is refused in the dialog
- **Traceability:** HLR-175b · trace: `_save_session_inputs` (NEW), `_prepare_project_save` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If a file the session would save no longer exists, then the system shall paint `source file missing`, the file's name and `reload it or remove it from the project` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** F-fresh with the loaded work copy deleted, then `ctrl+s` → 1 line with the tokens and the name, 0 dismisses on `alt+s`, 0 new paths (1 of 1).
- **Negative control:** on the 9a tree this refusal is painted only after the dialog closes (code read: `_handle_save_dialog`, the LLR-155.4 arm) → RED.
- **Boundary catalog:** ☒ error — the image, the MAC or the A2L missing (3 arms).

### LLR-175.1l — An unreadable source file is refused in the dialog
- **Traceability:** HLR-175b · trace: `_save_session_inputs` (NEW; `_file_digest`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If a file the session would save cannot be read, then the system shall paint `could not be read`, the file's name and `check that the file can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `_file_digest` raising `PermissionError` for the MAC (TC stub) → 1 line with the tokens and the name, 0 dismisses on `alt+s`, the app running (1 of 1).
- **Negative control:** mutation: the `OSError` not caught at dialog open → the dialog does not open, or the app raises → RED. On the 9a tree the text has no next step (`… could not be read: <reason>. Nothing written.`, `_handle_save_dialog`) → the next-step token is absent → RED (ruling Q11).
- **Boundary catalog:** ☒ error — a permission error on a source.

### LLR-175.1m — Blocked document entries are refused in the dialog
- **Traceability:** HLR-175b · trace: `_decide_project_image` (called once per open by `_save_session_inputs`, NEW)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the re-derive of the change document blocks an entry, then the system shall paint the blocked-entries reason token, the blocked addresses and the next-step token in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** the 1-blocked-entry document of TC-B100-57 (`0x8000007C`) → 1 line holding the reason token, `0x8000007C` and the next-step token; 0 dismisses on `alt+s`; 0 new paths (1 of 1). The tokens are those of the amended §3 row (ruling Q11).
- **Negative control:** on the 9a tree this refusal is painted only after the dialog closes (code read) → RED.
- **Boundary catalog:** ☒ error — 1 and 3 blocked entries.

### LLR-175.1o — A work area that cannot be listed is refused in the dialog
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW, the F-1 / P-5 arm)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the work area cannot be listed while the Save project dialog prepares a save, then the system shall paint `could not be read` and `check that the folder can be opened, then save again` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `os.listdir` (the `Path.iterdir` listing) raising `PermissionError` for the work area → 1 token pair, 0 dismisses on `alt+s`, the app running, 0 new paths (1 of 1).
- **Negative control:** mutation: the catch removed → the `PermissionError` leaves `preview()` inside the dialog's timer and the app stops → RED.
- **Boundary catalog:** ☒ error — a permission error on the work area.

### LLR-175.1p — A case-folded match that is not the open project is a disguised clash
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (G10, the file-identity test), `_plan_project_save` (the `open` kind test)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the typed name's sanitised form equals, compared case-folded, the folder name of a project folder that is not the open project's folder by file identity, while the typed name differs from that folder name, then the system shall paint `already a project`, both names and `choose another name` in the Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `strasse` open with `straße` present, `strasse` typed → 1 token pair naming both names, 0 dismisses on `alt+s`, 0 files written, `straße/project.json` unchanged (1 of 1; Windows arm).
- **Negative control:** mutation: the open-project test kept on case-folding → `straße` is taken as the open project, the dialog paints `updates the open project`, and the files land in `straße` → RED.
- **Boundary catalog:** ☒ invalid — two folders equal under Python `casefold` but distinct on disk (`strasse` / `straße`, `abs` / `abſ`, `abk` / `abK`).

### LLR-175.2 — No parent field
- **Traceability:** HLR-175e · trace: `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The Save project dialog shall compose no `#project_parent_path` widget and no `#save_browse` widget.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** 0 widgets with either id, at both reference sizes (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `widgets #project_parent_path: 1 #save_browse: 1` → RED.
- **Boundary catalog:** none — a fixed composition.

### LLR-175.2a — The dialog's payload names this work area as the parent
- **Traceability:** HLR-175e · trace: `SaveProjectScreen` save action (`screens.py`), `SaveProjectPayload.parent_folder`
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the Save project dialog closes with a payload, the system shall set the payload's parent folder to this work area.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** a save through the dialog under a base path of 150 characters → `Path(payload.parent_folder)` equals `app.workarea` (1 equality) and the new folder's parent equals `app.workarea` (2 of 2).
- **Negative control:** mutation: the payload's parent taken from `base_dir` → the handler refuses `not the work area folder` → RED. On the 9a tree the parent comes from an editable field (code read) → declared: the default value already equals the work area, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — a long base path.

### LLR-175.3 — `escape` closes the dialog with no result
- **Traceability:** HLR-175c · trace: `SaveProjectScreen.BINDINGS`, the cancel action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.10, LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer presses `escape` in the Save project dialog, the system shall dismiss the dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `escape` from each of the 4 focus positions → 4 dismisses with `None`, 0 new paths, the session digest unchanged (4 of 4).
- **Negative control:** executed on the 9a tree (P11-2): `escape -> stack: ['Screen', 'SaveProjectScreen']` → RED.
- **Boundary catalog:** ☒ boundary — each focus position; after a refusal.

### LLR-175.3a — Cancel closes the dialog with no result
- **Traceability:** HLR-175c · trace: `SaveProjectScreen.on_button_pressed` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer presses `#save_cancel`, the system shall dismiss the Save project dialog with no result.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a click and a focused `enter` on `#save_cancel`, each with a valid name typed → 2 dismisses with `None`, 0 new paths (2 of 2).
- **Negative control:** mutation: Cancel routed to the save action → 1 new folder → RED. Declared: on the 9a tree Cancel already dismisses with `None`, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — click and keyboard.

### LLR-175.3b — An empty Save keeps the dialog open and says why
- **Traceability:** HLR-175d · trace: `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the engineer confirms Save while the name field holds no character other than spaces, then the system shall keep the Save project dialog open and paint `name is empty` and `type a project name` in `#save_where`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `""` and `"   "`, each with `alt+s`, `#save_ok` and `enter` → 6 token pairs, 0 dismisses, 0 new paths (6 of 6).
- **Negative control:** executed on the 9a tree (P11-2): `empty Save click -> … 'name is empty'? False` → RED.
- **Boundary catalog:** ☒ empty — no character; spaces only.

### LLR-175.3c — Confirming Save closes the dialog and runs the save
- **Traceability:** HLR-175a · trace: `SaveProjectScreen.BINDINGS` (`alt+s`), the save action, `on_input_submitted`, `on_button_pressed` (`screens.py`); `_handle_save_dialog` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer confirms Save while the painted plan is the plan for the typed name and is not refused, the system shall close the Save project dialog and run the save.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** F-fresh, `fresh1` typed, the summary painted, then each of `alt+s`, a `#save_ok` click and `enter` in `#project_name` (3 fresh apps) → 1 dismiss each and 1 folder `fresh1` holding the plan's files (3 of 3).
- **Negative control:** code read on the 9a tree: `SaveProjectScreen` has no `BINDINGS` and no `on_input_submitted` → `alt+s` and `enter` save nothing → RED.
- **Boundary catalog:** ☒ boundary — the three triggers.

### LLR-175.3d — The dialog opens with the focus in the name field
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.AUTO_FOCUS` / `on_mount` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the Save project dialog opens, the system shall place the focus on `#project_name`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `ctrl+s` and the palette entry → `app.focused.id == "project_name"` (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2): `focused at open: OsClipboardInput project_parent_path` → RED.
- **Boundary catalog:** ☒ boundary — both open routes.

### LLR-175.3e — Plain letters stay in the name field
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.BINDINGS` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall deliver every printable key pressed while `#project_name` has the focus to the name field.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `s`, `q`, `l`, `p`, `v`, `y` typed → the field holds `sqlpvy`, the stack depth stays 2, 0 status lines added (1 of 1).
- **Negative control:** mutation: a plain `s` bound to the save action → the field misses `s` and the dialog closes → RED. Declared: on the 9a tree the modal already blocks the app's non-priority letters, so the RED is the mutation.
- **Boundary catalog:** ☒ boundary — letters the app binds on the main screen.

### LLR-175.3f — Save during a refusal keeps the dialog open
- **Traceability:** HLR-175b · trace: `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the engineer confirms Save while the plan for the typed name is refused, then the system shall keep the Save project dialog open with `#save_ok` focusable and the refusal's token pair painted.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a disguised clash, then `alt+s`, then `tab` to `#save_ok` and `enter` → 0 dismisses, `#save_ok.can_focus` is true and `#save_ok` gains the focus, the pair painted after each press, 0 new paths (1 of 1).
- **Negative control:** mutation: `#save_ok` disabled during a refusal → it cannot gain the focus → RED; mutation: the refused payload dismissed → 1 dismiss → RED.
- **Boundary catalog:** ☒ invalid — every refusal of HLR-175b keeps Save focusable (one arm per kind is in TC-B100-47).

### LLR-175.3g — App priority keys are inert while the dialog is open
- **Traceability:** HLR-175f · trace: `S19TuiApp.check_action` (`app.py`; the Inc 9b guard, S-g, widened by one screen class)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the engineer presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the Save project dialog is open, then the system shall run no app action for that key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** each of the 4 keys pressed with the dialog open → the screen stack stays the main screen plus the Save dialog (depth 2), the focus stays inside the dialog, the `#workspace_body` density class is unchanged and the palette stays closed (4 of 4). Declared: `ctrl+k` and `ctrl+d` then reach the name field's own line-editing bindings (Textual 8.2.8 `Input`: delete to the end, delete right), which is the field's behaviour, not an app action.
- **Negative control:** executed on the 9a tree (P11-2, P11-3): `ctrl+l over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'LoadFileScreen']`; `ctrl+s over Save dialog -> stack: ['Screen', 'SaveProjectScreen', 'SaveProjectScreen']`; `ctrl+d over Save: density classes ['density-comfortable'] -> ['density-compact']` → RED.
- **Boundary catalog:** ☒ invalid — the four priority keys.

### LLR-175.3h — The open project's name is offered, selected
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.on_mount` (`screens.py`); `action_save_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS state):** While a project is open, the system shall open the Save project dialog with that project's on-disk name in `#project_name`, all of it selected.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** F-open → the field holds `P`, the selection covers all of it, `#save_where` says `updates the open project`; typing `x` → the field holds `x`; F-fresh → the field is empty (3 of 3).
- **Negative control:** code read on the 9a tree: `on_mount` fills only `#project_parent_path`; the name field starts empty → RED.
- **Boundary catalog:** ☒ boundary — no project open; a project whose on-disk name differs in case from `current_project`.

### LLR-175.3i — The buttons show their keys
- **Traceability:** HLR-175f · trace: `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The Save project dialog shall label `#save_ok` with `alt+s` and `#save_cancel` with `esc`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** each label holds its key, and each shown key pressed by key performs its button's action (2 of 2; §3 preface "every shown key is verified by pressing it").
- **Negative control:** code read on the 9a tree: the labels are `Save` and `Cancel` → RED.
- **Boundary catalog:** none — two fixed labels.

### LLR-175.3j — Save project with nothing loaded opens no dialog
- **Traceability:** HLR-175f · trace: `action_save_project` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS unwanted):** If the engineer asks Save project while no data file and no A2L is loaded, then the system shall open no dialog and paint `Nothing to save` and `load a data file or A2L first` in the status log.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** a fresh app, `ctrl+s` and the palette entry → stack depth 1, 1 status line with both tokens each, 0 new paths (2 of 2).
- **Negative control:** executed on the 9a tree (P11-2, nothing loaded): `open ctrl+s -> stack: ['Screen', 'SaveProjectScreen']` → RED.
- **Boundary catalog:** ☒ empty — nothing loaded; ☒ boundary — an A2L alone loaded opens the dialog.

### LLR-175.4 — The summary rows are the plan's rows
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW, `app.py`); `SaveProjectScreen` paint method (`screens.py`); `plan_project_save` (LLR-167.6)
- **Ledger:** LED-2026-10-26-batch-100.4, LED-2026-10-26-batch-100.15, LED-2026-10-26-batch-100.26, LED-2026-10-26-batch-100.31, LED-2026-10-26-batch-100.37, LED-2026-10-26-batch-100.43, LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall paint in `#save_summary` one row per file row of the painted plan, one row per planned sub-folder with its file count and one row for `project.json`, each with its landing name (and its source name when the two differ) and its action word.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** 7 of 7 scenarios:
  - The 7 scenarios → the painted file rows, folder rows and `project.json` row equal the painted plan's `rows` and `folders` one for one, by landing name and action word (and source name when the two differ), at 220 columns (0 differences, 7 of 7).
  - An AST census of the dialog class and `_save_dialog_preview` → 0 calls to a placement or listing function other than through the one preparation (`predict_placement`, `place_into_workarea`, `os.listdir`, `iterdir`, `list_projects`).
  - The action words painted are only `new`, `keep`, `merge` and `rewrite`; `replace` is not produced (E3 R1).
- **Negative control:** mutation: the painter drops `keep` rows → 1 row missing in the merge scenario → RED. On the 9a tree there is no summary (P11-2) → RED.
- **Boundary catalog:** ☒ boundary — the 7 scenarios; an A2L-only session.

### LLR-175.4a — Save executes the painted plan
- **Traceability:** HLR-175a · trace: `_handle_save_dialog`, `_prepare_project_save` (NEW) (`app.py`); `SaveProjectScreen` save action (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the Save project dialog closes with a payload, the system shall execute the plan the dialog painted, with no file row added, removed or renamed; the active CRC template and the batch and assignment documents are copied outside the plan and are not part of its rows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** for the 7 scenarios, the plan the handler executes (a spy on the commit step) equals `SaveProjectScreen.plan` read after `alt+s` (dataclass equality, 7 of 7), and the written tree equals that plan by full path and action (0 differences). The document arm: `P` records `patches/changes.json` beside an identical `patches/changes_1.json`; save as `Q` → the painted document row `patches/changes_1.json — keep` equals the tree (base RED: `changes.json new`). The AT-B100-21 oracle excludes the gather homes (the active CRC template and the batch and assignment documents) by name.
- **Negative control:** mutation: the handler re-plans and drops the document row → the spy's plan differs and `patches/changes.json` is written without a painted row → RED.
- **Boundary catalog:** ☒ boundary — the 7 scenarios; the document-keep arm (p11b U3).

### LLR-175.4b — A summary out of date at Save is shown again, not saved
- **Traceability:** HLR-175a · trace: `SaveProjectScreen` save action (`screens.py`); `_prepare_project_save` (NEW, `app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.93
- **Statement (EARS unwanted):** If the engineer confirms Save while the plan for the typed name differs from the painted plan, then the system shall keep the Save project dialog open, paint the current plan and paint `the summary changed` and `check it, then save again`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** 3 of 3 arms:
  - `abc` typed and `alt+s` within 50 ms of the last key (before the 150 ms recompute) → 0 dismisses, the token pair painted, the summary now the plan for `abc`; a second `alt+s` → 1 dismiss and 1 folder `abc`.
  - F-merge, `ab` painted, then a test writes `ab/firmware.s19` with other bytes, then `alt+s` → 0 dismisses, the token pair, the image row now `firmware_1.s19` (`new`).
  - a save queued on the dialog before the first paint is marked shown → `confirm(name, None)`, 0 dismisses, `the summary changed`; a second `alt+s` saves (SR-11-2).
  - 0 new paths before the second press in all arms (3 of 3).
- **Negative control:** mutation: the save action dismisses with the freshly computed plan → arm 1 saves a plan never painted (1 dismiss, 0 token pairs) → RED.
- **Boundary catalog:** ☒ boundary — a pending recompute; a folder changed between paint and Save.

### LLR-175.4c — The image line says emit or copy
- **Traceability:** HLR-175 · trace: `_plan_project_save` (`SavePlan.image`), `_save_dialog_preview` (NEW)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall paint the painted plan's image description in `#save_summary`: the source plus N change entries with K applied by this save, or an unchanged copy.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-pending (1 entry applied, 0 not applied) → `firmware.s19 + 1 change entry, 0 applied by this save`; F-document (1 pasted entry, not applied) → `+ 1 change entry, 1 applied by this save`; F-fresh → `firmware.s19 unchanged copy` (3 of 3).
- **Negative control:** mutation: the description built from `image_differs_from_source` alone → F-document (image unchanged, 1 entry) says `unchanged copy` → RED.
- **Boundary catalog:** ☒ boundary — applied, not applied, none; an A2L-only session (no image line).

### LLR-175.4d — The pending line marks unsaved changes
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `ChangeService.differs_from_last_saved` (B100-I18)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS state):** While the session image differs from the copy last loaded or saved, the system shall paint one line holding `unsaved changes` and the image's name in `#save_summary`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-pending → 1 line; the same session after a Save project → 0 lines; F-fresh → 0 lines; patched, saved, patched again → 1 line (4 of 4).
- **Negative control:** mutation: the line keyed on `image_differs_from_source` → after a Save project the journal still shows the patch, so the line is painted → RED.
- **Boundary catalog:** ☒ boundary — saved then patched again; a patch that writes the bytes already there (0 lines).

### LLR-175.4e — Skipped links get one row
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `SavePlan.skipped_links`
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the painted plan skips links or junctions, the system shall paint one row holding `links or junctions not copied` and the first 10 of their paths, followed by `and K more` when there are more.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a save as of P holding 1 directory junction → 1 row naming it; 12 junctions → 1 row naming 10 and `and 2 more` (2 of 2; Windows-only arms, counted).
- **Negative control:** mutation: the links row omitted → 0 rows → RED.
- **Boundary catalog:** ☒ boundary — 10 / 11 / 12 links (`PAINTED_NAME_LIMIT`).

### LLR-175.4f — A merge names the active variant it sets
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW; the target's recorded `active_variant` read in the preparation, the image row's landing)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the painted plan's target is a merge with an image row, the system shall paint one row holding `active variant`, the variant the save makes active and the variant the target recorded before.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** F-merge where `ab` records `firmware` and the image lands as `firmware_1.s19` → 1 row naming `firmware_1` and `firmware`; after `alt+s`, `ab/project.json` records `active_variant == "firmware_1"` (2 of 2); a merge whose target records no active variant → 1 row naming `none recorded` (1).
- **Negative control:** mutation: the row omitted → 0 rows → RED; mutation: the row names the first variant by name → the after-save equality fails → RED.
- **Boundary catalog:** ☒ boundary — the same variant stays active; no record; a damaged manifest (`none recorded`).

### LLR-175.4g — Names in the dialog are painted literally
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW; `painted_names`), the dialog's widgets with markup off (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.93
- **Statement (EARS ubiquitous):** The system shall paint every name read from disk or typed by the engineer in the Save project dialog literally.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a loaded file named `[b]x.s19`, a sub-folder file `flows/[i]f.json`, a typed name `[red]a` (sanitised `reda`) and a disguised clash typed `[b]a b` against project `bab` → the plain text of each painted line holds the name exactly as `painted_names` returns it, with 0 markup spans; a name holding U+202E → the character absent from the painted text (5 of 5).
- **Negative control:** mutation: the summary widget with markup on → `[b]x.s19` paints `x.s19` in bold → RED. On the 9a tree there is no summary (P11-2) → RED.
- **Boundary catalog:** ☒ invalid — markup brackets, U+202E, a name of 130 characters (clipped to 120 ending in `…`).

### LLR-175.4h — Save and Cancel stay visible under a long summary
- **Traceability:** HLR-175f · trace: the dialog's layout rules (`styles.tcss`); `SaveProjectScreen.compose` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS state):** While the summary holds more rows than its region shows, the system shall keep `#save_ok` and `#save_cancel` inside the visible screen region.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a save-as plan of 300 rows (TC builder) at 118×54 and at 220×60 → both buttons' regions inside the screen and of height ≥ 1 (2 of 2).
- **Negative control:** mutation: `#save_summary` with `height: auto` and no scroll → the buttons are pushed below the screen → RED.
- **Boundary catalog:** ☒ boundary — 300 rows; 1 row.

### LLR-175.4i — The last summary row is reachable by keyboard
- **Traceability:** HLR-175f · trace: `#save_summary` (focusable scroll region, `screens.py`); the focus order
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall let the engineer scroll `#save_summary` to its last row with the keyboard alone.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** the 300-row plan at 118×54: `tab` from `#project_name` gives the focus to `#save_summary`, then `end` → the last row's region is visible (1 of 1); `tab` order `#project_name` → `#save_summary` → `#save_ok` → `#save_cancel` → `#project_name` and the reverse with `shift+tab` (2 of 2).
- **Negative control:** mutation: `#save_summary` not focusable → `tab` skips it and `end` stays in the name field → RED.
- **Boundary catalog:** ☒ boundary — 300 rows; the focus order with and without assignment rows (ruling Q4).

### LLR-175.4j — A summary row never wraps
- **Traceability:** HLR-175 · trace: `_save_dialog_preview` (NEW); `#save_summary` rules (`styles.tcss`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall paint each summary row on one line, a cut row ending with `…`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** the save-as scenario with a 120-character sub-folder file name at 118×54 → each row's region has height 1 and the cut row's text ends with `…` (all rows; 1 assertion per row).
- **Negative control:** mutation: the summary rows allowed to wrap → the long row takes 2 lines → RED.
- **Boundary catalog:** ☒ boundary — 118 and 220 columns.

### LLR-175.4k — The painted plan is exposed read-only
- **Traceability:** HLR-175a · trace: `SaveProjectScreen.plan` (NEW, read-only property, `screens.py`); `SavePlan` (frozen, `project_gather_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS ubiquitous):** The system shall expose the painted plan as `SaveProjectScreen.plan`, an immutable value.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** assigning `plan.rows`, assigning `screen.plan` and appending to `plan.rows` → 3 errors (`FrozenInstanceError`, `AttributeError`, `AttributeError` on a tuple) (3 of 3); `plan` is `None` while no plan is painted (1).
- **Negative control:** mutation: `plan` returns a mutable copy built from lists → the append succeeds → RED.
- **Boundary catalog:** ☒ boundary — before the first paint; after a refusal (`plan` is the refused plan, 0 rows).

### LLR-175.4l — A payload built without the dialog is saved through the same preparation
- **Traceability:** HLR-175a · trace: `_handle_save_dialog`, `_prepare_project_save` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When `_handle_save_dialog` receives a payload the Save project dialog did not prepare, the system shall prepare the plan for that payload's name and execute it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`, plus the 58 direct calls in 11 test files (§5.4)
- **Numeric pass threshold:** the same name through the dialog and through a direct `SaveProjectPayload` call on a twin fixture → equal written trees and equal session digests (1 of 1); the 58 direct calls in 11 test files pass unchanged (0 new failures against the gate baseline).
- **Negative control:** mutation: the handler requires a dialog-prepared plan → every direct call refuses → RED.
- **Boundary catalog:** ☒ boundary — a payload whose parent is not the work area (LLR-171.3 still refuses).

### LLR-175.4m — A session built before a load landed is rebuilt
- **Traceability:** HLR-175a · trace: `_SaveSession.image_generation` (NEW), `_current_save_session`, `_prepare_project_save`, the router (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.93
- **Statement (EARS event):** When a load lands while the Save project dialog is open, the system shall rebuild the per-open session before any plan or confirm reuse, recording the image generation the session was computed for.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** 2 layouts — a load of a same-layout image and of a different-layout image landing under the dialog → the first Save repaints `the summary changed` with the fresh image decision, and the second Save writes an image whose `derived_from.base` names the new file (same ranges) or an unchanged copy of the new file (other ranges), the app running (2 of 2) (SE5-11-1).
- **Negative control:** a session without the generation writes the stale image → `derived_from.base` names the old file and the in-memory map disagrees → RED.
- **Boundary catalog:** ☒ boundary — the same and different address ranges; an unchanged-copy landing.

### LLR-175.5 — The session's image decision and digests are computed once per open
- **Traceability:** HLR-175 · trace: `_save_session_inputs` (NEW), `action_save_project` (`app.py`); `_decide_project_image`, `_file_digest`
- **Ledger:** LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.93
- **Statement (EARS event):** When the Save project dialog opens, the system shall compute the image decision and the digests of the session's files once.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:**
  - F-case06: 1 dialog open and 20 keystrokes of a new name → 1 call to `_decide_project_image` and 1 `_file_digest` call per session file that is not an emitted image (the MAC and the A2L; an emitted image is not digested, B11-36), 0 more during the keystrokes and 0 more at `alt+s` (spies).
  - F-case06: the summary painted within 2 s of `ctrl+s` on the Windows development host; the measured time is recorded in the packet (C-QA-5). P11-1 measured the A2L digest at 26.1 ms (best of 5).
- **Negative control:** mutation: the decision and digests recomputed with the plan → 20 keystrokes give ≥ 2 decisions → RED.
- **Boundary catalog:** ☒ boundary — the case_06 project; an A2L-only session (no decision).

### LLR-175.5a — The plan is recomputed at most once per 150 ms of typing
- **Traceability:** HLR-175 · trace: `SaveProjectScreen` name-change handler and its timer (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the name in the Save project dialog changes, the system shall recompute the plan no sooner than 150 ms after the previous recomputation and once after the last change.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** 20 keystrokes 10 ms apart → ≤ 3 recomputations, each keystroke echoed in `#project_name` within one frame, and the plan for the final name painted within 300 ms of the last keystroke (3 assertions). A 4 MiB emitting image (any applied entry): each recompute echoes the keystroke within one frame and the final paint ≤ 300 ms — the `emitted_record` is computed once per open, not per recompute (1 of 1).
- **Negative control:** mutation: a recomputation per keystroke → 20 recomputations → RED; mutation: no trailing recomputation → the final name's plan is never painted → RED.
- **Boundary catalog:** ☒ boundary — one keystroke; a burst; a pause longer than 150 ms between two bursts.

### LLR-175.5b — The dialog appears before the session is computed
- **Traceability:** HLR-175f · trace: `action_save_project`, `_save_session_inputs` (NEW) (`app.py`); `SaveProjectScreen.on_mount` (`screens.py`)
- **Ledger:** LED-2026-10-26-batch-100.92
- **Statement (EARS event):** When the engineer asks Save project, the system shall render the dialog's first frame before it computes the image decision.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-65 — `pytest tests/test_b100_save_dialog.py -k tc_b100_65`
- **Numeric pass threshold:** a spy on `_decide_project_image` records, at its first call, that `app.screen` is a mounted `SaveProjectScreen` that has completed 1 refresh (1 of 1).
- **Negative control:** mutation: the decision computed in `action_save_project` before `push_screen` → at the first call the screen is the main screen → RED.
- **Boundary catalog:** ☒ boundary — F-case06 with 1 entry; a 4 MiB patched image (P11-4: render 1 215 ms).

### LLR-175.6 — One preparation decides what the dialog shows and what the save does
- **Traceability:** HLR-175b · trace: `_prepare_project_save` (NEW), its two callers (`_save_dialog_preview`, `_handle_save_dialog`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.92, LED-2026-10-26-batch-100.93
- **Statement (EARS ubiquitous):** The system shall decide the Save project dialog's refusal and plan and the save's refusal and plan for a name with one function.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** 16 of 16 names:
  - An AST census of `app.py` → `sanitize_project_name`, `is_windows_device_name`, the reserved-home comparison, `PROJECT_NAME_MAX_CHARS`, `_project_folder_refusal` (target) and `_plan_project_save` are reached by Save project only inside `_prepare_project_save` (0 other Save-path call sites).
  - 16 names (the 15 refusal arms with a fixture each, plus a valid one) → the dialog's painted token pair equals the token pair a direct `_handle_save_dialog` call paints in the status log, per name (16 of 16).
  - the save-as inventory is used only when the plan walks the source: P open, `Q` typed (a new folder, the inventory fills with P's tree), P renamed outside, `R` typed → `source_gone` painted with 0 copy rows; `alt+s` saves `R` fresh with the app running (CR11-F1).
- **Negative control:** mutation: the dialog side keeps its own copy of the rules without case-folding → `Reports` paints no pair in the dialog while the direct call refuses → RED.
- **Boundary catalog:** ☒ invalid — every refusal arm.

### LLR-176.1 — The begin paints the first progress line
- **Traceability:** HLR-176 · trace: `begin_busy` (NEW), `_busy_line` (NEW, guess) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.39, LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a long action begins, the system shall paint in `#status_text` the progress line with the first glyph, the action's label, `step 1/<m>` with the first step's name, and `00:00`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50 — `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** a begin with label `Loading x.s19` and steps `Copy into the work area`, `Parse`, `Install` → `#status_text` equals `⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00` (1 equality), read in the same frame as the begin.
- **Negative control:** executed P12a-2: no progress line is ever painted at `8947666` → RED.
- **Boundary catalog:** ☒ boundary — 1 step (`step 1/1`); a label of 200 characters (clipped by the `#status_text` ellipsis, never wrapped).

### LLR-176.1a — The begin shows the bar from 0
- **Traceability:** HLR-176 · trace: `begin_busy`, `set_progress` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a long action begins, the system shall set `#progress_bar` to 0 of 100.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** the bar at 40 before a begin (set by a prior call) → 0 of 100 after it (1 equality).
- **Negative control:** a mutation that leaves the bar untouched at begin → 40 → RED. Declared: at `8947666` the file load begins with `set_progress(10, …)`, so the base starts at 10, not 0 (P12a-1) → RED.
- **Boundary catalog:** none — the begin has no input classes.

### LLR-176.1b — A step without an amount sets the bar from its index
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a running action reaches step `n` of `m` without reporting an amount, the system shall paint `step n/m` with that step's name and set the bar to `floor(100 × (n − 1) / m)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** 4 steps reached in order → `step 1/4` … `step 4/4` painted and the bar at 0, 25, 50, 75 (4 of 4).
- **Negative control:** a mutation that paints the step but leaves the bar → 0, 0, 0, 0 → RED.
- **Boundary catalog:** ☒ boundary — `m = 1`; the last step (`n = m`).

### LLR-176.1c — A step with an amount moves the bar within the step
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a running action's step `n` of `m` reports `done` of `total`, the system shall set the bar to `floor(100 × (n − 1 + done / total) / m)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** step 2 of 2 reporting 1, 2, 3, 4 MiB of 4 MiB → 62, 75, 87, 100 (4 of 4, strictly rising).
- **Negative control:** a mutation that ignores `done` / `total` → 50, 50, 50, 50 → RED.
- **Boundary catalog:** ☒ boundary — `done = 0`; `done = total`.

### LLR-176.1d — Out-of-range step data is clamped
- **Traceability:** HLR-176b · trace: `step_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a running action reports a step outside `1 … m`, a `total` of 0 or less, or a `done` outside `0 … total`, then the system shall clamp the step to `1 … m` and the fraction to `0 … 1` without raising.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** step 0, step `m + 1`, `total = 0`, `total = −1`, `done = −5`, `done = total + 1` (6 arms) → 0 exceptions, the painted step within `1 … m`, the bar within 0 … 100 and never below the previous value of the same step (6 of 6).
- **Negative control:** a mutation dividing by `total` without the clamp → `ZeroDivisionError` on the `total = 0` arm → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — the 6 arms.

### LLR-176.1e — One timer advances the line while an action runs
- **Traceability:** HLR-176a · trace: `begin_busy`, `_busy_tick` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS state):** While at least one long action runs, the system shall keep exactly one 0.1-second interval timer that advances the glyph by one frame and repaints the elapsed time.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a synthetic worker action of 1.2 s → at least 5 distinct glyphs and the elapsed text `00:00` then `00:01` (2 assertions); 2 overlapping actions → 1 active timer (the app's timer count rises by 1, not 2).
- **Negative control:** executed P12a-2: `set_interval(` occurs 0 times → RED. A mutation that starts one timer per begin → 2 timers in the overlap arm → RED.
- **Boundary catalog:** ☒ boundary — an action that ends before the first tick (0 ticks, the line painted once and cleared).

### LLR-176.1f — The timer stops when no action runs
- **Traceability:** HLR-176a · trace: `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS event):** When the last running long action ends, the system shall stop the progress timer.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** after the last end → 0 progress timers active, and 0.5 s later `#status_text` unchanged (2 assertions).
- **Negative control:** a mutation that never stops the timer → the glyph-free final text is overwritten by a progress line on the next tick → RED.
- **Boundary catalog:** ☒ boundary — the end inside the first tick.

### LLR-176.1g — Elapsed time is minutes and seconds since the begin
- **Traceability:** HLR-176, HLR-176a · trace: `_busy_line` (guess) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS ubiquitous):** The system shall paint the elapsed time of a progress line as `mm:ss` counted from that action's begin, with the minutes not capped at 59.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a clock injected at 0, 59.9, 60, 3 599 and 4 503 s → `00:00`, `00:59`, `01:00`, `59:59`, `75:03` (5 of 5).
- **Negative control:** a mutation using `%M:%S` of a time value → `75:03` becomes `15:03` → RED.
- **Boundary catalog:** ☒ boundary — 59 / 60 s; over 60 minutes.

### LLR-176.1h — The file state waits while an action runs
- **Traceability:** HLR-176d · trace: `set_file_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS state):** While a long action runs, the system shall store a file state written for `#status_text` as the one stored file-state line instead of painting it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** 2 file-state writes during an action → 0 changes to `#status_text` before the end, and the second write kept as the stored file state (2 assertions).
- **Negative control:** executed P12a-2: the file state is painted while the load runs (bar at 50) → RED.
- **Boundary catalog:** ☒ boundary — a file-state write while no action runs (painted at once, as today).

### LLR-176.1i — The end writes the outcome to the status log
- **Traceability:** HLR-176c · trace: `end_busy`, `set_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a long action ends with a non-empty outcome, the system shall append that outcome as one status-log line.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** an end with outcome `Loaded x.s19` → the log's last line is `Loaded x.s19` and the line count rose by 1; an end with an empty outcome → the count unchanged (2 arms).
- **Negative control:** a mutation that drops the outcome → the count unchanged in the first arm → RED.
- **Boundary catalog:** ☒ empty — an empty outcome.

### LLR-176.1j — The last end paints the stored file state
- **Traceability:** HLR-176c, HLR-176d · trace: `end_busy`, `set_file_status` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When the last running long action ends, the system shall set `#status_text` to the one stored file-state line (the last text a file-state write stored, `Ready.` until the first write).
- **Rationale (informative):** A12a-06: one stored `file_state` replaces the three hand-back slots `restore` / `pending` / `final_line`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50; TC-B100-56 (Inc 12a extension, the project load's file state)
- **Numeric pass threshold:** two file-state writes during a run → `#status_text` = the last one after the end (1 equality); no write during a run → `#status_text` = the prior stored value (`Ready.` from a fresh app) (1 equality). Result 2 of 2.
- **Negative control:** a mutation that paints a `final_line` argument over `file_state` → the project-load arm of TC-B100-56 loses the project and file line → RED.
- **Boundary catalog:** ☒ boundary — a run with and without a file-state write.

### LLR-176.1k — The last end clears the bar
- **Traceability:** HLR-176c · trace: `end_busy`, `set_progress` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS event):** When the last running long action ends, the system shall clear the progress bar.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50; re-pinned `tests/test_report_progress.py::test_report_generation_drives_progress_bar_then_clears_it`
- **Numeric pass threshold:** an action whose last step reported 100 → after the end, progress 0 of total 100 (1 equality); the rendered bar row equals the start-up idle render (1 string comparison).
- **Negative control:** executed P12a-2: after a load the bar is at 100 → RED.
- **Boundary catalog:** ☒ boundary — an end after a failure (bar never past 0).

### LLR-176.1l — An exception still ends the indicator
- **Traceability:** HLR-176c · trace: the 7 actions' bodies (try / finally), `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If a long action raises before its end, then the system shall end that action's progress with a failure outcome before the exception leaves the action.
- **Rationale (informative):** at 12a the app's survival of a raising worker is not claimed; LLR-177.2 (Inc 12b) keeps the app running (ruling Q8).
- **Note (informative):** Inc 12b (TC-B100-50 arm per worker): the exception exit now also covers the three new worker bodies — a worker-step failure ends its run through its failure handler (the end is the handler's last statement); `_busy_fail` is posted only after a main-thread handler raises, before the worker re-raises.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a forced raise inside each of the 7 actions (7 arms) → an end recorded by a spy before the exception is observed, its outcome non-empty, 0 progress timers after it (7 of 7).
- **Negative control:** a mutation dropping the end on the exception path of the file load → 0 ends recorded → RED.
- **Boundary catalog:** ☒ error — one forced raise per action.

### LLR-176.1m — A step or an end from an unknown or replaced run leaves the indicator unchanged
- **Traceability:** HLR-176c · trace: `step_busy`, `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a step or an end names a key that is not running, or comes from a run that a later begin of the same key replaced, then the system shall leave the progress line, the bar and the timer unchanged, while an end with a non-empty outcome still appends that outcome to the status log.
- **Rationale (informative):** the load, report, diff-report and before/after workers are `exclusive=True` per group, so a second request replaces the first worker while the first thread can still post its end. The log is history, not indicator state (A12a-04).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** an end for a key never begun (with a non-empty outcome); a step for it; an end posted by the first of two file-load runs while the second runs (3 arms) → 0 changes to `#status_text`, the bar and the timer count in all three, and the log gains the outcome in the first and third arms (the step arm writes nothing) (3 of 3).
- **Negative control:** a mutation keyed only by the key name → the third arm clears the second run's indicator → RED.
- **Boundary catalog:** ☒ invalid ☒ boundary — an unknown key; a replaced run.

### LLR-176.1n — A second action begun while one runs is the one shown
- **Traceability:** HLR-176 · trace: `begin_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a long action begins while another long action runs, then the system shall show the newer action's progress line and bar.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a report running, then a file load begun → `#status_text` holds the load's progress line and the bar the load's value (2 assertions); the report's later steps change neither (1 assertion).
- **Negative control:** a mutation keeping the first action shown → the report's line stays → RED.
- **Boundary catalog:** ☒ boundary — 2 and 3 overlapping actions.

### LLR-176.1o — When a shown action ends, the newest one still running is shown
- **Traceability:** HLR-176c · trace: `end_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS event):** When a running long action ends while another long action still runs, the system shall show the progress line and bar of the most recently begun action still running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** report begun, load begun, load ends → the report's progress line and bar shown, the load's outcome in the log, the timer still active (3 assertions); then the report ends → LLR-176.1j applies (1 assertion).
- **Negative control:** a mutation that runs the last-end hand-back on any end → `#status_text` loses the report's line while it runs → RED.
- **Boundary catalog:** ☒ boundary — the older action ends first (the newer stays shown).

### LLR-176.1p — A begin under a running key restarts that key's line
- **Traceability:** HLR-176 · trace: `begin_busy` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS unwanted):** If a long action begins under the key of an action that is already running, then the system shall restart that key's progress line at `step 1/<m>` and `00:00`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a file load at `step 2/3`, `00:01`, then a second file load → `step 1/3` and `00:00`, 1 entry for the key (2 assertions).
- **Negative control:** a mutation that keeps both entries → 2 entries → RED.
- **Boundary catalog:** ☒ boundary — the replaced run then ends (LLR-176.1m).

### LLR-176.1q — Progress widgets are written only on the main thread
- **Traceability:** HLR-176a · trace: the seam; the 4 worker bodies (`call_from_thread`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall write `#status_text` and `#progress_bar` only on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** a thread-id probe on `#status_text` and `#progress_bar` updates during the 7 worker actions (the 12a four plus the three 12b workers, TC-B100-50) → 0 writes off the main thread (7 of 7).
- **Negative control:** a mutation that calls the step function directly from the load worker → at least 1 off-main write → RED.
- **Boundary catalog:** none — the probe covers every worker action.

### LLR-176.1r — Names in a progress line are painted literally
- **Traceability:** HLR-176 · trace: `_busy_begin_action`, `painted_names` (`project_gather_service.py`), `_paint_status_text` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS ubiquitous):** The system shall paint a file or project name inside a progress line, and write the end's outcome line, through the batch's one name scrub and the one `safe_text` choke point, with markup off.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** driven through `load_from_path` (the real entry): `[b]x.s19`, `fw` + U+202E + `gpj.s19`, a 130-character name, and `a` + ESC + `]0;x` + BEL + `.s19` → 0 markup spans, 0 U+202E characters, the long name clipped to 120 characters ending in `…`, and the painted line and the end's outcome log line hold no `\x1b` / `\x07` (4 of 4). AST: `begin_busy(` is called only inside `_busy_begin_action` (1 call site).
- **Negative control:** a mutation inserting the raw name → U+202E present → RED; a site that calls `begin_busy` directly with a formatted label → the AST finds 2 → RED.
- **Boundary catalog:** ☒ invalid — a markup-shaped name; a bidirectional control; a long name; an ESC-bearing name.

### LLR-176.1s — The bar keeps its row when idle
- **Traceability:** HLR-176c · trace: `compose` (`#progress_bar`), `styles.tcss` `#progress_bar`
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS ubiquitous):** The system shall keep the progress bar's row height and the status log's vertical position the same whether or not a long action runs.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50
- **Numeric pass threshold:** at 118×54 and 80×24, idle and during an action → `#progress_bar` region height equal and `#log_line_1` region `y` equal (2 sizes × 2 assertions).
- **Negative control:** declared RED only as a mutation: executed P12a-2 shows the base already holds (height 1 / 1, `y` 47 / 47). A mutation hiding the bar when idle → `#log_line_1` moves up 2 rows → RED.
- **Boundary catalog:** ☒ boundary — 80×24, the smallest supported size.

### LLR-176.1t — Every status-log line goes through the one control-byte choke point (SE5-12a-1)
- **Traceability:** HLR-176 · trace: `_append_log_line`, `safe_text` (`utils.py`) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.96
- **Statement (EARS ubiquitous):** The system shall write every status-log line through `safe_text(...).plain`, so no control code point reaches `log_lines` or the four painted log rows.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50 — `pytest tests/test_b100_busy.py -k tc_b100_50_control_bytes_never_reach_the_status_log`
- **Numeric pass threshold:** `_format_coexistence_status` patched to return `Loaded a` + ESC + `]0;x` + BEL + `.s19 (S19 only)`, then a real `load_from_path` → 0 C0/C1 code points in `app.log_lines`, `#log_line_1..4` and `#status_text`, and the scrubbed line `Loaded a]0;x.s19 (S19 only)` arrives; a direct `_append_log_line` of a text holding U+009B and NUL → `direct 2J line` (2 arms).
- **Negative control:** on base `_append_log_line` does `message.strip()` with no scrub, so a raw append keeps ESC / BEL → RED.
- **Boundary catalog:** ☒ invalid — a control byte in a file name; a direct append.

### LLR-176.2 — Every progress-bar write maps to one action (C-31)
- **Traceability:** HLR-176 · trace: the action table `_BUSY_ACTIONS` (NEW, data); the 12 functions of P-29 (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** Every site that set the progress bar at the Inc 12a baseline shall map to exactly one long action's begin, step or end in the action table.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 — `pytest tests/test_b100_busy.py -k tc_b100_51` (an AST derivation over the baseline's `app.py`, stored as a fixture list at E2)
- **Numeric pass threshold:** the derivation maps 24 of 24 sites (P-29, re-derived at the E2 baseline after Inc 9b, 10 and 11; at least 24) to exactly one begin, step or end (24 of 24, 0 sites mapped twice).
- **Negative control:** executed P12a-1: 24 sites in 12 functions, none mapped (no table exists) → RED. A mutation removing one row → the census names its site → RED.
- **Note (informative):** Inc 12b re-derives TC-B100-51 over the moved code: the census sites now sit in the worker bodies and their main-thread handlers; every exit, the worker failures included, still ends its run (LLR-176.2c); the Save project phases are reported from the Save worker (LLR-176.2d).
- **Boundary catalog:** none — the set is derived from the code.

### LLR-176.2a — Only the seam sets the bar
- **Traceability:** HLR-176 · trace: `set_progress`, the seam (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95
- **Statement (EARS ubiquitous):** The system shall set the progress bar only from inside the progress seam.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 (AST over `app.py`)
- **Numeric pass threshold:** calls of `set_progress` outside `begin_busy`, `step_busy` and `end_busy`, direct or through `call_from_thread` → 0; `#progress_bar` query sites outside `set_progress` and `compose` → 0 (2 assertions).
- **Negative control:** executed P12a-1: 24 calls outside any seam → RED.
- **Boundary catalog:** none — the census has no input classes.

### LLR-176.2b — The action table names the seven long actions
- **Traceability:** HLR-176 · trace: `_BUSY_ACTIONS` (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96
- **Statement (EARS ubiquitous):** The action table shall hold one entry, with an English label and at least one named step, for each of file load, A2L load, project load, Save project, report, diff report and before/after.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** 7 keys, each with a non-empty label and at least 1 step name (7 of 7); TC-B100-66 finds 0 decision ids in the 7 labels and their step names.
- **Negative control:** code read on `8947666`: no table → RED.
- **Boundary catalog:** none.

### LLR-176.2c — Each action ends on every success and failure exit
- **Traceability:** HLR-176c · trace: the 7 actions' exits; `_handle_load_error`, `report_failed` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** Each long action of the action table shall end its progress on every success exit and every failure exit.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** per action, 1 success and 1 forced failure (7 × 2 = 14 arms: for example a file that is not found, an A2L of an unsupported type, a project that cannot be read, a placement failure after the save begins, a report write that fails, a diff report on a missing file, a before/after on a missing file; E2 lists the reachable arm per action) → exactly 1 begin and 1 end per arm, 0 indicators left (14 of 14).
- **Negative control:** a mutation dropping the end in `_handle_load_error` → the failure arm of the file load leaves 1 indicator → RED.
- **Boundary catalog:** ☒ error — 1 failure per action.

### LLR-176.2d — Save project reports its phases as steps (Inc 11 ruling Q2, the indicator half)
- **Traceability:** HLR-176c · trace: `_handle_save_dialog`, `_prepare_project_save` (Inc 11) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.95, LED-2026-10-26-batch-100.96, LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When Save project runs, the system shall report each save phase named in the action table as one step of its progress line, in order.
- **Rationale (informative):** Inc 11 ruling Q2 moved "the save runs on a worker with real progress" to 12a+12b. The indicator half is here: the Save project entry, its step reports and its end. Inc 12b moves the save onto a worker (HLR-177), and only then does the line show between the begin and the end. A refused save is refused in the dialog (Inc 11 ruling Q5), so it never begins.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-51
- **Numeric pass threshold:** a Save project of the case_01 session → a step spy records the phases of the Save project entry in order, each once (at least 3, for example `Copy the files`, `Write project.json`, `Check the saved files`; E2 names them), then 1 end with the success outcome (1 sequence equality); a name refused in the dialog → 0 begins (1 assertion).
- **Negative control:** executed P12a-1: no progress call sits in `_handle_save_dialog` at `8947666` → 0 steps → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a save of a session with no MAC and no A2L (the phases still reported once each); a placement failure after the begin (1 end with the failure outcome).

### LLR-176.3 — A main-thread step paints its name before its work
- **Traceability:** HLR-176 · trace: `step_busy` (12a), the `call_after_refresh` idiom (`app.py:8708`); the A2L tag-table build (`update_a2l_view`) and the install steps of the four session actions (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When a long action reaches a step that runs on the main thread, the system shall paint that step's name before the step's work starts.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-52 — `pytest tests/test_b100_a2l_progress.py -k tc_b100_52`
- **Numeric pass threshold:** the case_06 A2L attach's tag-table step and the case_06 project load's install step → the step text read in a `call_after_refresh` callback scheduled before each step starts equals that step's name (2 equalities); a step on a 1-byte image → 1 equality.
- **Negative control:** a mutation that starts the tag-table build before the refresh → the callback reads the previous step's name → RED.
- **Boundary catalog:** ☒ boundary — a step on a 1-byte image; the tag-table build of the 37.7 MB A2L.
- **Note (informative):** after 12b the main-thread steps are the installs and the tag-table build; during the tag-table build the indicator stays frozen, as HLR-176 declares (about 3.5 s for case_06: P12b-4 minus P12b-7).

### LLR-176.4 — The A2L parser reports the bytes it has consumed
- **Traceability:** HLR-176 · trace: `parse_a2l_file`, `build_section_tree` (`s19_app/tui/a2l.py`; a named frozen-engine crossing, `docs/ARCHITECTURE.md` §7, chosen by the operator at the PDR gate, C-UX-1 / C-QA-1)
- **Ledger:** LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall report, to an optional progress callback of the A2L parse entry point, the bytes consumed and the total bytes as the parser consumes its input.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_a2l_progress.py -k tc_b100_73`
- **Numeric pass threshold:** the case_06 A2L → ≥ 2 calls, the consumed values non-decreasing, the last equal to the file size (3 of 3); an A2L smaller than one progress chunk → ≥ 1 call, the last equal to the size.
- **Negative control:** a mutation that calls the callback only once at the end → fewer than 2 calls → RED. Code read, base: `parse_a2l_file(path)` takes no callback (`a2l.py:2627`) → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no callback; an A2L smaller than one chunk.

### LLR-176.4a — The parse result does not depend on the callback
- **Traceability:** HLR-176 · trace: `parse_a2l_file` (`s19_app/tui/a2l.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall parse an A2L file to the same result with a progress callback as without one.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_a2l_progress.py -k tc_b100_73`
- **Numeric pass threshold:** the case_06 A2L parsed with and without a callback → identical results: tag count and every parsed field equal (1 comparison); the same for `examples/case_01_basic_valid/firmware.a2l`.
- **Negative control:** a mutation that changes a parsed field when a callback is given → the comparison RED.
- **Boundary catalog:** ☒ boundary — a large and a small A2L.
- **Note (informative):** the callback-free parse makes 0 `os.fstat` calls (`total` is read only when a callback is given), so it is byte-identical to the base parse (CR12b-4).

### LLR-176.4b — `a2l.py` is frozen again after the increment
- **Traceability:** HLR-176 · trace: `tests/test_engine_unchanged.py::_ENGINE_PATHS`, TC-027
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.100
- **Statement (EARS ubiquitous):** The system shall list `s19_app/tui/a2l.py` in the frozen-engine guard's paths.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_a2l_progress.py -k tc_b100_73`; `pytest tests/test_engine_unchanged.py` after the increment merges
- **Numeric pass threshold:** `_ENGINE_PATHS` contains `s19_app/tui/a2l.py` (1 assertion); after the merge, TC-027 reports 0 changed engine paths against `main`.
- **Negative control:** code read, base: the entry is commented out since batch-95 (`tests/test_engine_unchanged.py:125-133`) → RED.
- **Boundary catalog:** none — one list entry.
- **Note (informative):** on the increment branch TC-027 compares against `main`, where `a2l.py` differs until the merge, so its full run is owed on main after the merge (declared; CONFLICT-1).

### LLR-177.1 — The project load reads and parses on a worker
- **Traceability:** HLR-177 · trace: `_handle_load_project` (changed), the project-load worker (NEW, `@work(thread=True)`), `check_project_files`, `read_project_manifest`, `build_variant_set`, `parse_a2l_file`, `_parse_loaded_file`, `recorded_document_state` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall read and parse a project's files for a project load on a worker thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project with data, MAC, A2L and a recorded change document, loaded from the Load dialog → the calls that read the files (the digest check, the manifest read, the A2L parse, each image parse, the document read) each record a thread id other than the main thread's (spies, 5 of 5). The refusals that need no file content (a link, outside, not listed, no data or A2L file) still paint in the frame of the request, before any worker starts (4 of 4).
- **Negative control:** executed on the base (P12b-5): `ran on main thread True`, 0 timer ticks in 5.81 s → RED. Mutation: calling the A2L parse in the main-thread install → that spy records the main thread → RED.
- **Boundary catalog:** ☒ boundary — an A2L-only project; a project whose recorded variant is unreadable (the next valid one is parsed on the same worker).

### LLR-177.1a — Save project writes on a worker
- **Traceability:** HLR-177 · trace: `_handle_save_dialog` (changed: the commit half), the Save worker (NEW, `@work(thread=True)`), `_save_project_files`, `save_patched_image`, `verify_written_image`, `_write_manifest_for_save`, `_abort_save` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall create the project folder, place the files, write the emitted image and write and verify `project.json` for Save project on a worker thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a patched session saved as a new project → the folder creation, each placement, the image emit and the manifest write record a thread id other than the main thread's (spies, 4 of 4). Every refusal of the Inc 11 preparation (empty, device, reserved, too long, path, clash, link, missing source, plan, free space) paints before any worker starts and creates 0 folders (10 of 10).
- **Negative control:** executed on the base (P12b-6): `_handle_save_dialog('Q') … ran on main thread True` → RED.
- **Boundary catalog:** ☒ boundary — a copy-only save and an emitting save; a save into the open project (merge).

### LLR-177.1b — Every A2L attach copies and parses on a worker
- **Traceability:** HLR-177 · trace: `load_a2l_from_path` (changed), `_load_workarea_file` (9b G1, its A2L arm), the A2L worker (NEW, `@work(thread=True)`), `copy_into_workarea`, `parse_a2l_cached` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall copy an attached A2L file into the work area and parse it on a worker thread, on every A2L attach route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a typed `.a2l` path, a recent `.a2l` entry, a Workarea Files pick of an `.a2l` file (in place, parse only) and the start-up `load_path` of an `.a2l` → the parse records a thread id other than the main thread's (4 of 4); the three copying routes → the copy records a non-main thread id (3 of 3).
- **Negative control:** executed on the base (P12b-4): `load_a2l_from_path(case_06 A2L): wall 8.76 s; ticks during the call 0; … ran on main thread True` → RED.
- **Boundary catalog:** ☒ boundary — each route; an A2L smaller than one progress chunk.

### LLR-177.1c — The event loop keeps running during a worker step
- **Traceability:** HLR-177 · trace: the three workers (NEW); Textual `set_interval` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS state):** While a worker step of the three 12b actions runs, the system shall keep running the main thread's timers.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a 0.1 s interval timer started before the request → ≥ 10 ticks between the worker's start and the install for the case_06 project load, and ≥ 10 ticks during the case_06 A2L attach's worker step; a Save project held at a forced slow step for 1.5 s → ≥ 10 ticks (3 of 3).
- **Negative control:** executed on the base (P12b-4, P12b-5): 0 ticks during 8.76 s and during 5.81 s → RED.
- **Boundary catalog:** ☒ boundary — the measured step on the development host; a worker step shorter than one tick (0 ticks required, the result installed).

### LLR-177.1d — The session is written only on the main thread
- **Traceability:** HLR-177 · trace: the three workers and their main-thread install handlers (NEW); `call_from_thread`; `parse_a2l_cached` / `_store_a2l_cache` (the cache write), `_write_manifest_for_save` / `_write_and_verify_manifest` (the `_last_manifest_verify_result` write), `_abort_save` (its session restore), `ChangeService.record_save_entries` / `adopt_rederived` / `mark_saved` (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall write the session only on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a probe that records the thread of every attribute write on the app object (a test subclass overriding `__setattr__`) and of every `ChangeService` method that changes its state, during a project load, a Save project (emitting), an A2L attach and one forced failure of each → 0 writes from a thread other than the main thread (6 runs, 0 off-main writes).
- **Negative control:** code read, base: `_start_load_worker` → `_parse_loaded_file` → `_load_a2l_data_with_cache` assigns `_a2l_cache_key` and `_a2l_cache_data` on the load worker (`app.py:15151`, `:15851-15852`), and `_write_and_verify_manifest` assigns `_last_manifest_verify_result` (`:11260`, `:11311`); moved into a worker unchanged, each records an off-main write → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the success and the failure path of each action.

### LLR-177.1e — A worker reads only its request
- **Traceability:** HLR-177 · trace: the three workers (NEW); their request values (NEW, frozen dataclasses) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall give each worker of the three 12b actions everything it reads from the session in an immutable request built on the main thread before the worker starts.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53` (an AST census)
- **Numeric pass threshold:** AST census of `s19_app/tui/app.py`: the body of each worker function, and of every `app.py` method it calls, holds 0 reads of `self.current_file`, `self.current_project`, `self.current_project_dir`, `self.current_a2l_path`, `self.current_a2l_data`, `self._variant_set` and `self._change_service` (3 workers, 0 reads); each worker takes one request argument whose class is a frozen dataclass (3 of 3).
- **Negative control:** code read, base: `_parse_loaded_file` reads `self.current_file` and `self.current_a2l_*` to merge a MAC with the loaded primary (`app.py:15098-15226`), and the save's emit reads `self.current_file.ranges` (`:10006-10019`) → moved into a worker unchanged, the census names them → RED.
- **Boundary catalog:** none — a structural census; its set is every function the workers reach in `app.py`.

### LLR-177.1f — A project loaded on a worker equals a cold load
- **Traceability:** HLR-177 · trace: the project-load worker and its install handler (NEW); `_session_snapshot` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When a project load's worker step completes, the system shall install a session equal to a cold load of that project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-09 (its P2-over-P1 arm, on the worker path)
- **Numeric pass threshold:** 3 of 3:
  - P2 holds a data file, a MAC file and an A2L file. P2 loaded over P1 (an image loaded, a patch applied) → `_session_snapshot()` equals that of a cold load of P2, 0 differing names outside LLR-165.2's allow-list.
  - The cold P2 session digest equals the digest the base produces for the same fixture (recorded at the E2 baseline).
  - After the install, `current_file.variant_id` equals the opened variant's id (1 assertion; the snapshot normalises `current_file` to type, path and image digest, so it does not see a lost variant id).
  - 3 of 3.
- **Negative control:** a mutation in which the worker parses P2's MAC against the live `current_file` (the base's `_merge_mac_with_existing_primary` path) → the MAC merges into P1's image → 1 differing name (`current_file`) → RED. The base-digest arm is a `planned` control, recorded at the E2 baseline.
- **Boundary catalog:** ☒ boundary — a MAC beside a data file; an A2L-only project.

### LLR-177.1g — The project session resets after the worker read, before the first install
- **Traceability:** HLR-177 · trace: `_reset_project_session` (caller moves), the project-load install handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When a project load's worker step completes, the system shall reset the project session on the main thread before the first install.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-08 (its one-call-site census, re-pinned to the install handler)
- **Numeric pass threshold:** call-order spy on a project load → worker step end, then 1 reset on the main thread, then the first install (order 3 of 3); a forced worker failure → 0 resets.
- **Negative control:** a mutation that resets before the worker starts → the forced-failure arm leaves an empty session → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a successful load; a worker failure.

### LLR-177.1h — The Load-result panel opens after the install
- **Traceability:** HLR-177, HLR-178 · trace: `_route_load_project` (changed), the project-load install handler (NEW), `LoadResultScreen` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When a project load started from a load route completes its install, the system shall open the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project row of the Load dialog, `enter` → 0 `LoadResultScreen` while the worker step is held, 1 after the install (2 of 2); a typed absolute project path → 1 panel after the install; a direct `_handle_load_project` call → 0 panels (LLR-174.3b).
- **Negative control:** a mutation that keeps the base's identity check after `_handle_load_project` returns (`_route_load_project`, `app.py:7478-7482`) → the announcement is not yet composed when the call returns → 0 panels → RED.
- **Boundary catalog:** ☒ boundary — the dialog route, the typed-path route, a direct call; a load that stops before composing (0 panels).

### LLR-177.1i — Save project re-derives the image on the main thread before its worker
- **Traceability:** HLR-177 · trace: `_decide_project_image`, `ChangeService.rederive_for_save`, `render_patched_image` (Inc 11: called by `_prepare_project_save` / the per-open session inputs) (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall re-derive and render the image Save project emits on the main thread before the Save worker starts.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** an emitting save → `rederive_for_save` and `render_patched_image` each record the main thread's id, and both calls precede the worker start (order spy, 2 + 2).
- **Negative control:** a mutation that re-derives inside the worker → the thread-id arm RED, and LLR-177.1e's census names `self._change_service` → RED.
- **Boundary catalog:** ☒ boundary — an emitting save; a copy-only save (no re-derive, 0 calls).

### LLR-177.1j — Save project adopts the re-derived image after the save commits
- **Traceability:** HLR-177 · trace: the Save commit handler (NEW), `ChangeService.adopt_rederived` / `mark_saved` (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the Save worker reports a committed save, the system shall adopt the re-derived image on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; `pytest tests/test_b100_save_image.py -k "failed_manifest_write_adopts_nothing"` (re-pinned to wait for the worker)
- **Numeric pass threshold:** an emitting save that commits → 1 `adopt_rederived` call on the main thread, after `project.json` is on disk; a forced manifest-write failure → 0 adopt calls and the session map still holds the source bytes at the entry (review F4) (3 of 3).
- **Negative control:** a mutation that adopts before the worker starts (the old LLR-177.1 reading "apply the result … before its worker starts") → the forced-failure arm shows the re-derived image although no file holds it → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a committed save; a manifest-write failure.

### LLR-177.1k — A data file picked from the work area is parsed on a worker
- **Traceability:** HLR-177 · trace: `_load_workarea_file` (9b G1; its data arm), `_start_load_worker` (existing, key `file_load`), `load_selected_file` (no longer called by the pick) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the engineer picks a data file from the work area, the system shall parse it on the file-load worker, in place.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a Workarea Files pick and a Load dialog `workarea` row of a generated S19 holding 8 MiB of data → the parse records a thread id other than the main thread's, ≥ 10 ticks of a 0.1 s timer pass during it, 0 `copy_into_workarea` calls (spy), and the session digest equals that of the base's synchronous pick on a twin fixture (4 of 4 per surface).
- **Negative control:** code read, base: `_load_from_item` → `load_selected_file` parses on the main thread (`app.py:13325-13335`, `:15047`); 12a P12a-3 measured the 8 MiB-data S19 parse at 2.38 s → 0 ticks → RED.
- **Boundary catalog:** ☒ boundary — both surfaces; a MAC file (attached, same worker); a file deleted after the list was painted (0 loads, as today).
- **Note (informative):** 12a's E1 left this pick and the typed load's copy to 12b's E1 (`inc-12a-design/E1-rulings-proposed.md`, "Observations for Inc 12b's E1"); ruling Q5 decides it. The typed load's copy (`copy_into_workarea` before `_start_load_worker`) stays on the main thread.

### LLR-177.2 — A project load whose worker raises keeps the session
- **Traceability:** HLR-177 · trace: the project-load worker and its failure handler (NEW); `end_busy` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If a project load's worker step raises, then the system shall paint the `could not be read` line for that project and keep the session and the app as they were before the load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** a `PermissionError` and a `ValueError` forced into the worker's manifest read → each: 1 status line holding `could not be read` and `check that the folder can be opened, then load again`, the session digest unchanged, 0 resets, the app running, the indicator ended with the failure (2 × 4 checks).
- **Negative control:** executed on a minimal Textual 8.2.8 app (P12b-2): an exception escaping a `@work(thread=True)` body ends the app (`WorkerFailed`, return code 1) → RED. Mutation: no catch in the worker → the same.
- **Boundary catalog:** ☒ error — an `OSError` and a non-`OSError`.

### LLR-177.2a — A Save project whose worker raises rolls back and reports
- **Traceability:** HLR-177, HLR-164 · trace: the Save worker (NEW), `_abort_save`, `_remove_created_project_dir`, the Save failure handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the Save worker raises an exception that is not an `OSError`, then the system shall remove what this save created, paint the `could not save` line and keep the app running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`; `pytest tests/test_b100_save_image.py -k non_os_error_after_the_emit` (re-pinned: reported, not raised)
- **Numeric pass threshold:** a `ValueError` forced into the image verify after the emit → the target folder absent, the work-area tree digest unchanged, 1 status line holding `could not save` and `check the folder`, 1 logged traceback, the app running, the session digest unchanged (6 of 6).
- **Negative control:** code read, base: the handler re-raises after the rollback (`app.py:10413-10425`, SEC-7 "then let it surface"); on a worker that raise ends the app (P12b-2) → RED.
- **Boundary catalog:** ☒ error — a non-`OSError` after the emit; before the emit.
- **Note (informative):** an `OSError` keeps LLR-164.4's handler (extended at 12b, §C).

### LLR-177.2b — An A2L attach whose worker raises keeps the session
- **Traceability:** HLR-177 · trace: the A2L worker and its failure handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If an A2L attach's worker step raises, then the system shall paint the `could not be read` line for that A2L file and keep the session and the app as they were before the attach.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** a `ValueError` forced into the parse and a `PermissionError` forced into the copy → each: 1 status line holding `could not be read` and `check that the file can be opened, then load again`, `current_a2l_path` and `current_a2l_data` unchanged, the app running (2 × 3 checks).
- **Negative control:** executed P12b-2 (an escaping exception ends the app) → RED.
- **Boundary catalog:** ☒ error — the copy and the parse.
- **Note (informative):** a failed A2L attach records nothing in the recents — recording moves to the install handler (E2 ruling P2-9); the base recorded the source before the parse.

### LLR-177.2c — An A2L attach whose folder or file is gone at the use-time look is refused (CR12b-2 / SE5-12b-2)
- **Traceability:** HLR-177 · trace: `load_a2l_from_path` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.99
- **Statement (EARS unwanted):** If an A2L attach's open-project folder cannot be read or its source file's size cannot be read before any busy run begins, then the system shall paint the existing refusal line and begin no run.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** the open project's folder renamed away, and the A2L file's size read forced to raise → each: 1 status line, 0 begins, no run, the app running, nothing raised (2 arms). The two lines: `validate_project_files` `OSError` → `A2L NOT loaded: project '<name>' could not be read — check that the folder can be opened, then load again.`; the size `stat()` `OSError` → `A2L file not found: <path>` (the same form as the use-time look).
- **Negative control:** the unguarded base calls (`validate_project_files` → `project_dir.iterdir()`, and `normalized.stat()`) raise out of the request, and a deferred callback then ends the app → RED.
- **Boundary catalog:** ☒ error — the open-project folder gone or unreadable; the source file gone at the size look.

### LLR-177.3 — Load requests are refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_load_file`, `action_load_project`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks to open Load while a session action runs, then the system shall paint the busy line and open no Load dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a project load held at a forced slow step: `l`, `ctrl+l`, `p`, a click on `#ws_load_project_button` and the palette entries `load_file` and `load_project` → 6 busy lines, 0 `LoadDialog` on the stack (6 of 6).
- **Negative control:** code read, base: `action_load_file` pushes the dialog unconditionally (`app.py:7329`) → RED.
- **Boundary catalog:** ☒ invalid — each of the six triggers.

### LLR-177.3a — The load guard refuses before it asks
- **Traceability:** HLR-177a, HLR-174 · trace: `_confirm_then_load` (Inc 10, B100-I20), the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.100
- **Statement (EARS unwanted):** If an image-replacing route reaches the load guard while a session action runs, then the system shall paint the busy line without asking the load question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_load_question.py -k tc_b100_72`
- **Numeric pass threshold:** with an unsaved patch and an A2L attach held at a forced slow step: a Workarea Files pick of `x.s19` and the variant selector's pick → 2 busy lines, 0 load questions, the session digest unchanged (2 of 2).
- **Negative control:** a mutation that runs the busy check after the guard's question → 1 question before the refusal → RED.
- **Boundary catalog:** ☒ boundary — a route with unsaved work (the question would have been asked); one without.

### LLR-177.3b — The variant selector is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_select_variant`, `_handle_load_result`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks for the variant selector while a session action runs, then the system shall paint the busy line and open no variant selector.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `v` and the palette entry `select_variant` → 2 busy lines, 0 `SelectVariantScreen` (2 of 2).
- **Negative control:** code read, base: `action_select_variant` pushes the selector with no state check (`app.py:7509`) → RED.
- **Boundary catalog:** ☒ invalid — `v`, the palette entry.

### LLR-177.3c — An unload is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks to unload while a session action runs, then the system shall paint the busy line and unload nothing.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `U` and a Loaded panel `[u]` on the A2L slot → 2 busy lines, the session digest unchanged (2 of 2).
- **Negative control:** code read, base: `action_unload_all` (`app.py:14668`) has no state check → RED.
- **Boundary catalog:** ☒ invalid — unload all; one artifact.

### LLR-177.3d — Save project is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_save_project`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks for Save project while a session action runs, then the system shall paint the busy line and open no Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a project load held at a forced slow step: `ctrl+s`, `s` and the palette entry `save_project` → 3 busy lines, 0 `SaveProjectScreen`; during a Save project, `ctrl+s` → 1 busy line (4 of 4).
- **Negative control:** code read, base: `action_save_project` (`app.py:7355`) has no state check → RED.
- **Boundary catalog:** ☒ invalid — each trigger; a second save during a save.

### LLR-177.3e — Patch Editor changes are refused while a session action runs
- **Traceability:** HLR-177a · trace: `on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`, `on_patch_editor_panel_undo_requested`, `on_patch_editor_panel_redo_requested`, `action_patch_undo`, `action_patch_redo`, `on_patch_editor_panel_edit_json_requested`, `on_patch_editor_panel_entry_edit_json_requested`, `on_patch_editor_panel_change_file_selected`, `on_patch_editor_panel_dirty_load_requested`, `_apply_changeset_json_edit`, `_apply_entry_json_edit`, the two `LoadGuardScreen` accept arms, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS unwanted):** If the engineer asks the Patch Editor for an action that changes the image or the change document while a session action runs, then the system shall paint the busy line and leave the image and the document unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: the 11 dispatcher actions `apply_doc`, `add_entry`, `edit_entry`, `remove_entry`, `load_doc`, `parse_paste`, `refresh_doc`, `validate_doc`, `run_checks`, `save_doc`, `execute_scope`; the `UndoRequested` and `RedoRequested` handlers; a save-back decision; an edit-JSON request and an entry edit-JSON request → 16 busy lines; the image SHA-256 and the document's serialised entries unchanged after each (16 of 16). The four continuations — the `ChangeSetJsonScreen` result, the `EntryJsonScreen` result, and the accept arm of the two `LoadGuardScreen` paths — also refuse, dropping the JSON the user typed, with the busy line (4 of 4).
- **Negative control:** a mutation that refuses only `apply_doc` and undo (the old list) → the `add_entry` arm adds an entry that the save's commit then marks saved (`panel.mark_saved()`, `app.py:10558-10572`) although no file holds it → RED.
- **Boundary catalog:** ☒ invalid — every message the Patch Editor sends that reaches the change service.

### LLR-177.3f — The busy line names the running action
- **Traceability:** HLR-177a · trace: the busy check (NEW); 12a's run state and action-table label (12a S-b, S-c) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall word each busy refusal as `busy: <label> is running — wait for it to finish.`, where `<label>` is the running action's label.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-66 (no decision id)
- **Numeric pass threshold:** a refusal during each of the three 12b actions → 1 status-log line each, holding `busy`, that action's label and `wait for it to finish` (3 of 3); a project named `[b]P` → the label paints `[b]P` with 0 markup spans; 0 decision ids (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`) in the line.
- **Negative control:** a mutation that paints a fixed `busy` with no label → the label arm RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — each action; a hostile project name.

### LLR-177.3g — A refusal changes nothing
- **Traceability:** HLR-177a · trace: the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS ubiquitous):** The system shall leave the session, the focus and the screen stack unchanged when it refuses a request as busy.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** for each refusal of LLR-177.3 … LLR-177.3e → the session digest, `app.focused` and the screen-stack depth equal their values before the request (3 checks per refusal).
- **Negative control:** a mutation that moves the focus to the status log before refusing → the focus arm RED.
- **Boundary catalog:** ☒ boundary — the focus on a list, on an input, on the rail.

### LLR-177.3h — Refusals stop when the session action ends
- **Traceability:** HLR-177a · trace: the busy check (NEW); `end_busy` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When a session action ends by success, failure or exception, the system shall accept the requests it refused while that action ran.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project load ending by success, by a reported failure and by a forced exception → after each, `l` opens the Load dialog (3 of 3).
- **Negative control:** a mutation that leaves the running state set on the exception exit → `l` paints the busy line after the failure → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the three exits.

### LLR-177.3i — The report viewer stores its regions only while no session action runs (CR12b-3)
- **Traceability:** HLR-177a · trace: `on_report_viewer_screen_generate_requested` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.99
- **Statement (EARS state):** While a session action runs, the system shall leave the session's declared regions unchanged when the report viewer's Generate stores regions; the report itself still runs.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a Save held at a forced slow step, the report viewer's Generate asked with regions `R` → the regions unchanged after the request, the report still generated with the user's regions; idle → the regions stored (2 of 2).
- **Negative control:** a mutation that always stores → `Generate wrote the regions during the Save` → RED.
- **Boundary catalog:** ☒ boundary — a running session action; idle.

### LLR-177.4 — Quit during a session action opens the quit question
- **Traceability:** HLR-177b · trace: `action_quit` (NEW override), the question modal (Inc 10) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.100
- **Statement (EARS event):** When the engineer asks to quit while a session action runs, the system shall open the quit question with the focus on its Stay button.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `q`, `ctrl+q` and the palette entry `quit` → 1 quit question each, `focused.id == "confirm_no"`, the app running (3 × 3).
- **Negative control:** code read, base: no `action_quit` in `S19TuiApp`; Textual's `App.action_quit` calls `self.exit()` (`textual/app.py:4460-4462`) → RED.
- **Boundary catalog:** ☒ boundary — `q`, `ctrl+q`, the palette.

### LLR-177.4a — The quit question names the running action
- **Traceability:** HLR-177b · trace: the quit question texts (NEW), the question modal `__init__(title, body, yes_label, no_label)` (Inc 10, LLR-174.2a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.100
- **Statement (EARS ubiquitous):** The system shall build the quit question with the title `Quit?`, the text `still working: <label> — wait, or quit after it finishes` and the button labels `Quit (y)` and `Stay (n)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-66 (no decision id)
- **Numeric pass threshold:** the question during a Save project of `P1` → the 4 strings painted, the label naming Save project; 0 painted `Replace`; 0 decision ids (6 of 6).
- **Negative control:** a mutation that opens the Inc 10 load question texts → `Replace …?` painted → RED.
- **Boundary catalog:** ☒ boundary — each of the three 12b actions as the running one.

### LLR-177.4b — Stay keeps the session action running
- **Traceability:** HLR-177b · trace: the quit-answer handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the engineer answers the quit question with Stay, the system shall keep the app and the session action running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** `n`, `escape` and an immediate `enter` → the question closed, the app running, and after the held step is released the save completes and its success line paints (3 of 3).
- **Negative control:** a mutation that exits on any answer → the `n` arm stops the app → RED.
- **Boundary catalog:** ☒ boundary — the three cancel answers (LLR-174.2d, LLR-174.2e).

### LLR-177.4c — Confirmed quit waits for the session action's end
- **Traceability:** HLR-177c · trace: the quit-answer handler (NEW), the end handlers of the three actions (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98, LED-2026-10-26-batch-100.99
- **Statement (EARS event):** When the engineer answers the quit question with Quit, the system shall exit after the running session action's end handler has run on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** 5 of 5:
  - A Save project held at a forced slow step, `y` → the app running while held; released → the app exits, and the target folder's `project.json` verifies.
  - The held step forced to raise after `y` → the app keeps running, the folder is absent, the failure line is `log_lines[-1]` and the failure toast is shown (the failure arm clears `_quit_pending`).
  - A project load held at its worker step, `y` → the app exits after the install, with 0 exceptions logged.
  - A ROUTED project load (the Load dialog's route) held at its worker step, `y` → the app exits after the install with no Load result panel mounted and nothing raised (R2-F1, `test_tc_b100_53_confirmed_quit_during_a_routed_project_load_exits_cleanly`).
  - 0 partial folders over the three arms (5 of 5).
- **Negative control:** a mutation that exits on `y` → the app stops while the step is held → RED. Executed P12b-3: after `App.exit()` the worker's `call_from_thread` callback runs with `app running: False`, so the end handler's status and rollback reporting would run on a stopped app.
- **Boundary catalog:** ☒ boundary ☒ error — a save, a load, a failing save.
- **Note (informative):** the wait is a flag read by the end handler, never a main-thread wait on the worker: a main-thread wait would deadlock with the worker's own `call_from_thread`, which blocks until the main thread runs its callback (Textual 8.2.8 `call_from_thread` returns `future.result()`). A committed Save that leaves in-memory work unsaved withdraws the confirmed quit (LLR-177.4e, SE5-12b-1).

### LLR-177.4d — Quit with no session action exits at once
- **Traceability:** HLR-177b · trace: `action_quit` (NEW override) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the engineer asks to quit while no session action runs, the system shall exit without a question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** idle `q` and idle `ctrl+q` → the app exits, 0 questions (2 of 2); `q` while the Inc 10 load question is open and idle → the question keeps the key (LLR-174.2g), 0 exits.
- **Negative control:** a mutation that always asks → the idle arm opens a question → RED.
- **Boundary catalog:** ☒ boundary — idle; idle under a modal.

### LLR-177.4e — A confirmed quit is withdrawn when a committed Save leaves in-memory work unsaved (SE5-12b-1)
- **Traceability:** HLR-177c · trace: `_on_project_saved` (committed arm), `end_busy` → `_exit_if_quit_pending` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.99
- **Statement (EARS event):** When a Save commits while a quit is confirmed and leaves in-memory work unsaved — a change-document line was painted or the "has unsaved edits" line was added — the system shall withdraw the confirmed quit and stay open after the Save ends.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** `q`, `y` during a held Save that commits with a pasted-document line (scenario B) and with the "has unsaved edits" line (scenario A) → the app stays open after the Save ends, the line is `log_lines[-1]`, the entries / the panel's dirty state are kept (2 of 2).
- **Negative control:** a mutation that always honours the quit (`_quit_pending` kept) → the app exits over a Save that left work unsaved → RED.
- **Boundary catalog:** ☒ boundary — scenario A (Patch Editor edits unsaved) and scenario B (pasted entries not written).
- **Note (informative):** the declared cautious scope (CR12b-5) is wider than the ruling: any change-document line withdraws a confirmed quit, also lines about records already on disk (nothing is lost; the engineer quits again). The manifest-mismatch case is not added (no in-memory loss, S12b-R2-3).

### LLR-177.5 — The A2L parse step reports its bytes from the worker
- **Traceability:** HLR-177, HLR-176 · trace: the A2L worker and the project-load worker (NEW); the parser's progress callback (LLR-176.4, moved to 12b by 12a ruling Q1) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When an A2L parse runs on a worker, the system shall pass the parser's consumed-byte reports to the indicator's current step.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; AT-B100-17
- **Numeric pass threshold:** the case_06 A2L attach and the case_06 project load → `#progress_bar`'s value increases ≥ 2 times within the parse step, read on the main thread (2 of 2).
- **Negative control:** a mutation that passes no callback → the bar moves by step only → 0 increases within the step → RED.
- **Boundary catalog:** ☒ boundary — an attach and a project load; an A2L smaller than one progress chunk (≥ 1 report).
- **Note (informative):** the bar reaches the end of the parse step after the A2L text is read (about 1 s of 6.6 s for case_06) and holds there while the tags are extracted; the spinner and the elapsed time keep moving during the tag-table build (E2 ruling P2-8).

### LLR-177.5a — The Save worker advances the bar per file placed
- **Traceability:** HLR-177, HLR-176 · trace: the Save worker (NEW), its placement loop over the plan rows; `step_busy(key, gen, n, done, total)` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.98
- **Statement (EARS event):** When the Save worker finishes placing one file of the save plan, the system shall advance the indicator's bar within the placement step.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a Save project placing 4 files → `#progress_bar`'s value increases ≥ 4 times within the placement step, read on the main thread; a save-as placing 2 000 files → the value increases ≥ 10 times within that step (2 of 2).
- **Negative control:** a mutation that reports only at the step's end → 1 increase per step → RED. On the base no save step is reported at all (12a P12a-1) → RED.
- **Boundary catalog:** ☒ boundary — 1 file (1 increase); 4 files; 2 000 files.
- **Note (informative):** 12a ruling Q5 removed "copied, read" from the within-step promise because the byte callbacks would live in `workspace.py`; it kept "Save project's copy by files placed" open if 12b finds it countable in `app.py`. The placement loop is in `app.py`, so it is counted by files, not bytes. The project load's digest check (`check_project_files`, `manifest_writer.py`) has no per-file hook in `app.py` and moves by step.

### LLR-178.1 — The announcement composer
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.47, LED-2026-10-26-batch-100.72
- **Statement:** `compose_load_announcement(...)` (NEW, a pure function in `services/variant_execution_service.py`) shall return the opened variant, the variant count, the reason — recorded active; first by name, none recorded; first by name, manifest damaged; first by name, no `project.json`; next valid, the recorded one missing or not readable — the relation recorded in `derived_from` — "patched, N bytes differ from `<base>`" when the base is a file of the project (a `files` record of the manifest has its name and SHA-256; the composer is pure and reads no disk, so a manifest with no `files` gives the next form — OBS-7-1), "patched from `<base>` (not in this project); N bytes differ from it" when it is not, and no relation line when nothing is recorded (a variant with a `derived_from` record is always described as patched, never as identical) — whether the opened variant is the one the app's last recorded write made active, and the problem list.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-55 — `pytest tests/test_b100_announce.py -k tc_b100_55`
- **Numeric pass threshold:** 5 reason cases → 5 of 5 reasons; a save-back to `firmware_1.s19` and to `firmware-patched.s19` → "patched, 4 bytes differ from `firmware.s19`" in both (2 of 2); a base not in the project → "patched from `firmware.s19` (not in this project); 4 bytes differ from it"; no `derived_from` → 0 relation lines; 0 announcements containing "identical"; 3 problems → 3 entries in precedence order; "latest" true only for the variant the last recorded write made active, false for a touched file (2 arms).
- **Negative control:** a mutation reporting "recorded active" for the fallback case → RED; a mutation comparing with the first variant by name → the `firmware-patched.s19` arm compares the image with itself (P-39) → RED; this arm is written at Inc 7, where `derived_from` exists.
- **Boundary catalog:** ☒ empty ☒ boundary — 1 variant; no openable image; no `derived_from`; a base not in the project.

### LLR-178.2 — The summary line and the final `#status_text`
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.95
- **Statement:** `_handle_load_project` shall write the announcement's summary line to the status log through `set_status` (opened variant, `k of n`, problem count, then "details: p"), and pass the project and opened-file line to `end_busy` as its final lines, so `#status_text` shows them once the progress line releases it; both render names through `safe_text`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-56 — `pytest tests/test_b100_announce.py -k tc_b100_56`
- **Numeric pass threshold:** a 2-variant load → 1 summary line in `#log_line_4` naming the opened variant and the count 2, ending "details: p", inside 118 columns; after the load ends, `#status_text` names project and file (1 assertion); a variant named `[b]x.s19` → 0 spans.
- **Negative control:** a mutation painting with markup on → 1 span → RED.
- **Boundary catalog:** ☒ invalid — a hostile variant name.

### LLR-178.3 — The Load-result panel, reachable by keyboard
- **Traceability:** HLR-178
- **Ledger:** LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.7, LED-2026-10-26-batch-100.16, LED-2026-10-26-batch-100.25, LED-2026-10-26-batch-100.68, LED-2026-10-26-batch-100.98
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
      in    : typed name + the one preparation (LLR-175.6)
      out   : the folder line and the warning lines
    - fn    : payload with the work area as parent (screens.py SaveProjectScreen)
      owner : LLR-175.2
      in    : the confirmed name
      out   : SaveProjectPayload
    - fn    : the dialog's keys and empty-Save reason (screens.py SaveProjectScreen)
      owner : LLR-175.3
      in    : escape, Cancel, alt+s / Save / enter, an empty Save, the priority keys
      out   : a dismiss or a painted reason
    - fn    : paint the save plan as the summary (screens.py SaveProjectScreen)
      owner : LLR-175.4
      in    : the painted SavePlan
      out   : #save_summary rows; the same plan executed (LLR-175.4a)
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
    - fn    : the public dirty reader (screens_directionb.py PatchEditorPanel.is_dirty)
      owner : LLR-174.1c
      in    : the panel's flag
      out   : bool
    - fn    : the one load seam for every image-replacing route (app.py _confirm_then_load)
      owner : LLR-174.4
      in    : the Load dialog, the Workarea pick, the variant switch, a project load
      out   : the guard run once, then the load
    - fn    : the confirm modal (screens.py)
      owner : LLR-174.2
      in    : title, question text, two labels
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
    - fn    : A2L parse progress callback (a2l.py, named frozen-engine crossing)
      owner : LLR-176.4
      in    : the A2L bytes as they are consumed
      out   : bytes_consumed / total_bytes to step_busy
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
  INPUTS : project_name: str ; preview: Callable[[str], SavePreview] (app side, painted plain text) ; initial_name: Optional[str]
  OUTPUTS:
    - id          : save_payload
      value       : SaveProjectPayload with the work area as parent_folder (LLR-175.2a)
      address     : query("#save_ok")
      cardinality : 1
      consumers   : s19_app/tui/screens.py
                    s19_app/tui/app.py::_handle_save_dialog
                    tests/test_b99_staging.py
                    tests/test_tui_directionb.py
                    tests/test_tui_manifest_save.py
      owner       : LLR-175.2a
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
  INPUTS : title: str, body: str, yes_label: str, no_label: str
  OUTPUTS:
    - id          : confirm_no
      value       : the safe answer, focused first; y replaces, n and escape cancel
      address     : query("#confirm_no")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_confirm_then_load
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

- **Layer A — white-box / functional:** TC-B100-01 through TC-B100-73 (`test (unit)` / `test (integration)`), each named in its LLR, plus the re-pinned nodes TC-018, AT-031b and `test_tc_b99_31_changed_bytes_take_the_next_free_name` (LLR-163.3, LLR-163.4). Each declared mutation runs at Phase 3 (C-40). The AST censuses derive their sets from the code (C-31: TC-B100-07, -09, -37, -51, -59, -65, -66).
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
| AT-B100-02 | US-154 | Inc 2 | Inc 11 (alt+s; no parent field; the refusals read in #save_where with the dialog open — ruling Q5) | — |
| AT-B100-03 | US-155 | Inc 3 | Inc 9b (project pick), Inc 10 (answers `y`: the P1 entry is unsaved) | Save project → project folder |
| AT-B100-04 | US-156 | Inc 4 | Inc 6 (dismiss the panel first), Inc 9b (`p` opens the Load dialog) | — |
| AT-B100-05 | US-157 | Inc 5 | Inc 6 (panel oracle), Inc 7 (the "patched" line against `derived_from`), Inc 9b | Save project → `P1/firmware.s19` → Load |
| AT-B100-06 | US-158 | Inc 6 | Inc 7 (`derived_from` on disk), Inc 9b | save-back → `project.json` → Load |
| AT-B100-07 | US-159 | Inc 7 | Inc 9b | Save project → `files` → Load |
| AT-B100-08 | US-160 | Inc 8a | Inc 9b | Save project → `active_document` → Load |
| AT-B100-09 | US-161 | Inc 8b | Inc 9b, Inc 11 (alt+s; the summary lists flows/, patches/, reports/ before Save) | save-as → Q folder → flow list |
| AT-B100-10 | US-161 | Inc 8b | Inc 9b | A2L-only Save → Load |
| AT-B100-11 | US-161 | Inc 8b (listing and Save refusal; the placement guard's junction arm is TC-B100-62 at Inc 1) | Inc 9b (reads `#load_list`) | — |
| AT-B100-12 | US-162 | Inc 9a | — (typed path, path field focused) | Load → per-user store |
| AT-B100-13 | US-162 | Inc 9a | — | — |
| AT-B100-14 | US-163 | Inc 9b | — | Load → store → Load dialog; preview marks → install |
| AT-B100-15 | US-164 | Inc 10 (the three key-reachable routes — Load, the Workarea Files pick, `v` — plus the question, keep, replace, items and after-save halves; the panel's `v` is TC-B100-72's forced-state arm, because by keys the panel opens only on an image just recorded as saved) | — | — |
| AT-B100-16 | US-165 | Inc 11 (open, folder, clash, escape and empty halves; HLR-175, HLR-175b, HLR-175c, HLR-175d, HLR-175f) | — | — |
| AT-B100-17 | US-166 | Inc 12a (the 12a half: a worker file load of a generated S19 with 8 MiB of data — the line, the advancing elapsed time, the outcome and the cleared bar); Inc 12b (the 12b half, its parse half written at 12b: the engineer loads the case_06 A2L by keys, the bar rises ≥ 2 times and the elapsed time advances during the parse — LLR-177.5, LLR-176.4) | — | — |
| AT-B100-18 | US-167 | Inc 12b (four halves: worker, refusal, quit, quit-confirm; HLR-177, HLR-177a, HLR-177b, HLR-177c) | — | — |
| AT-B100-19 | US-168 | Inc 6 (panel, reasons) | Inc 7 (problems; the `derived_from` line, default-name arm), Inc 9b | save-back → `project.json` → Load |
| AT-B100-20 | US-158 | Inc 6 | Inc 7 (`derived_from` carried), Inc 8a (`active_document` carried), Inc 9b | variant append / MAC / A2L sync → `project.json` → fresh Load and Execute scope |
| AT-B100-21 | US-165 | Inc 11 (fresh, pending patch, refused, `files`, document, merge, save-as) | — | save plan → files on disk |

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-05 (LLR-164.2) | Inc 2: refusals, open-project save, an exact-name save that adds a variant | Inc 8a: the merge carry of `gathered` and `active_document` |
| TC-B100-12 (LLR-166.1) | Inc 4: the load tails | Inc 6: panel closes; Inc 9b: dialog `esc`, cancelled load; Inc 10: question `n` (a visible healthy `Input` keeps the focus — LLR-166.1 governs) and `escape` (a healthy focus kept) (LED .89) |
| TC-B100-10 (LLR-165.3) | Inc 3 | Inc 10: the interim line removed — 0 closed-document lines; `test_tc_b100_10_interim_discard_notice` and `test_tc_b100_10_notice_names_every_discarded_entry` re-pinned to that arm (LED .89) |
| TC-B100-59 (LLR-167.6, LLR-167.6a–g) | Inc 5: fresh, open project, pending patch, refused | Inc 7: the `files` row; Inc 8a: the document row and the merge; Inc 8b: sub-folder rows, skipped links, the MAC and A2L plan refusals, one row per landing, the own-A2L exemption, the per-file cap (LLR-167.6a–g) |
| TC-B100-70 (LLR-167.8) | Inc 5: refused save; document not written | Inc 8a: the positive arm (re-pins the not-written arm), the failed-write and file-backed arms; Inc 10: the project-load question arm — 0 questions after Save project, 1 after a refused one (LED .89) |
| TC-B100-20 (LLR-168.3) | Inc 6 | Inc 8a: `active_document` carried (with AT-B100-20) |
| TC-B100-22 (LLR-169.2) | Inc 7 | Inc 8a: the active-document arm, run in TC-B100-28 (A-15) |
| TC-B100-23 (LLR-169.3) | Inc 7 | Inc 8a: the `active_document` drift arm |
| TC-B100-24 (LLR-169.4) | Inc 7 | Inc 8a: the `files` key of the active document |
| TC-B100-62 (LLR-171.4, LLR-171.4a–c, LLR-171.4e–h) | Inc 1: the predicate, the placement guard and the manifest seam (LLR-171.4, .4a, .4b) | Inc 8b: listing (.4c; .4d withdrawn into it), the picked load (.4e, .4f), the Save target (.4g), the 8 writers (.4h); the flow and flowset writers (.4i, .4j) routed to the LED .50 backlog item (LED .77) |
| TC-B100-31 (LLR-171.1j, LLR-171.1k) | Inc 8b: the file (2 000 / 2 001), entry (10 000 / 10 001, R13) and depth (32 / 33) ceilings; unlistable folders, trailing-dot and device names, the unlistable project folder painted `'P'` — each refused before any folder exists (LED .78, .79) | — |
| TC-B100-31 (LLR-171.1l, LLR-171.1m) | Inc 8b: the Flow panels' session folder becomes Q; a Patch Editor document inside P rebound to its copy in Q, never through a `..` path (LED .78, .79); bound to the gather's landing when an identical sibling is reused (LED .80) | — |
| TC-B100-31 (LLR-171.1n, LLR-171.1o, LLR-171.7c) | Inc 8b E5: a save to a new folder while P's folder is gone; the copy refused when P itself becomes a junction; the rollback never deletes through a changed folder (LED .80) | — |
| TC-B100-32 (LLR-171.2h) | Inc 8b E5: the A2L unload of an A2L-only session (LED .80) | — |
| TC-B100-31 (LLR-171.6, LLR-171.6a, LLR-171.6b) | Inc 8b: the carried `batch` and `assignments` kept when nothing is selected, for the three target kinds; the gather fed from the recorded `batch` plus the recorded `assignments` names (LED .78, .79) | — |
| TC-B100-31 (LLR-171.7, LLR-171.7a, LLR-171.7b) | Inc 8b: names scrubbed by Unicode category and clipped to 120; at most 10 entries then `and K more`; a failed copy painted in user terms (LED .78, .79) | — |
| TC-B100-32 (LLR-171.2f, LLR-171.2g) | Inc 8b: a linked or over-cap A2L of an A2L-only folder refused before the reset; beside an image or a MAC left out with 1 `not readable` problem and 0 parses (LED .78, .79) | — |
| TC-B100-34 (LLR-172.1, LLR-172.1a, LLR-172.1b, LLR-172.1c, LLR-172.1d, LLR-172.1e, LLR-172.1f, LLR-172.1g, LLR-172.1h, LLR-172.1i, LLR-172.1j) | Inc 9a: the per-user store location, the record of an outside source (first, kind by suffix), one entry per path, 20 entries, nothing recorded on a failed or inside load, no store without a usable `LOCALAPPDATA` or through a linked folder, unique staging, a failed write never fails the load, refused entries not written back (LED .82) | — |
| TC-B100-34 (LLR-172.1k, LLR-172.1l, LLR-172.1m) | Inc 9a E3: an unreadable store left unchanged by a record; a source the read would drop (UNC, control character, device component) not recorded; the written store at most 65 536 bytes, oldest dropped first (LED .83) | — |
| TC-B100-34 (LLR-172.2k) | Inc 9a E5: a source path holding `<>:"\|?*` after the drive prefix, a Cf / Zl / Zp / Cs character, or the NT prefix `\??\` not recorded (LED .84) | — |
| TC-B100-35 (LLR-172.2, LLR-172.2a, LLR-172.2b, LLR-172.2c, LLR-172.2d, LLR-172.2e, LLR-172.2f, LLR-172.2g, LLR-172.2h, LLR-172.2i, LLR-172.2j) | Inc 9a: the store read — order and cap, `too large`, wrong shape, `could not be read`, missing, the five entry checks, never raises (LED .82) | — |
| TC-B100-35 (LLR-172.2k) | Inc 9a E5: a store entry holding `<>:"\|?*` after the drive prefix or a Cf / Zl / Zp / Cs character dropped; a `..` segment and an 8.3 spelling kept (LED .84) | — |
| TC-B100-36 (LLR-172.3) | Inc 9a: the two marker arms (LED .82) | — |
| TC-B100-37 (LLR-172.4, LLR-172.4a, LLR-172.4b, LLR-172.4c) | Inc 9a: the one-lister census, the listed rows, a file link left out, an unlistable temp folder (LED .82) | Inc 9b: the Load dialog's files section reads the same lister, the census widened to the string literal "temp" in any letter case, and a runtime enumeration spy during a dialog open (LLR-173.4b, CR9-11) |
| TC-B100-37 (LLR-172.4d) | Inc 9a E5: a temp file whose name ends in a dot or a space not listed (LED .84) | — |
| TC-B100-38 (LLR-172.5, LLR-172.5a, LLR-172.5b, LLR-172.5c, LLR-172.5d, LLR-172.5e, LLR-172.5f, LLR-172.5g) | Inc 9a: the typed project folder and `project.json`, the four typed refusals by token pair, a missing path, a reserved home refused by the project load (LED .82) | Inc 9b: the refusals painted in `#load_reason` (LLR-173.5) |
| TC-B100-38 (LLR-172.5h) | Inc 9a E3: a relative typed folder path (base-folder fallback, a relative junction, a root-relative path) refused with `not a supported file` / `check the path`, never routed as a project (LED .83) | Inc 9b: painted in `#load_reason` (LLR-173.5) |
| TC-B100-39 (LLR-172.6, LLR-172.6a) | Inc 9a: literal rows, the picked row loads the on-disk name (LED .82) | — |
| TC-B100-34 (LLR-172.1n) | Inc 9b: a source found only through the base-folder or repository-root fallback (a junction arm and a base-only arm) not recorded; a file found as typed and an absolute junction path recorded lexically (LED .86) | — |
| TC-B100-40 (LLR-173.1, LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f, LLR-173.1g) | Inc 9b: one `LoadChoice` per kind, the project route with the Load-result panel, the work-area file in place (copy spy), the typed-path route, the one router census, the recent's recorded path unchanged, an unreadable picked project explained (LED .86) | Inc 10: the load question in this router (LLR-174.4) |
| TC-B100-41 (LLR-173.2, LLR-173.2a, LLR-173.2b, LLR-173.2c, LLR-173.2d, LLR-173.2e, LLR-173.2f, LLR-173.2g, LLR-173.2h, LLR-173.2i, LLR-173.2j, LLR-173.2k, LLR-173.2l) | Inc 9b: the open keys and their focus, the open project highlighted, the `tab` order, printable keys typed into the path field, the priority keys inert, the list / path precedence of a load, the two empty-Load arms, a click selects, `escape` and Cancel close (LED .86) | — |
| TC-B100-42 (LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c, LLR-173.3d) | Inc 9b: project, file, recent and preview names painted literally; a pick loads the on-disk name (LED .86) | — |
| TC-B100-43 (LLR-173.4, LLR-173.4a, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4h, LLR-173.4i, LLR-173.4j, LLR-173.4k, LLR-173.4l, LLR-173.4m) | Inc 9b: the three sources and their order, a non-project folder left out, loadable files only, the empty-section and store-problem tokens, the recent row and preview, 0 filesystem calls before Enter, a missing recent explained in the dialog, an unreadable project list explained (LED .86) | — |
| TC-B100-63 (LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e) | Inc 9b: the six typed refusal reasons painted in `#load_reason`, the dialog open, the text kept (LED .86) | — |
| TC-B100-64 (LLR-173.6, LLR-173.6a, LLR-173.6b, LLR-173.6c, LLR-173.6d, LLR-173.6f, LLR-173.6k, LLR-173.6l, LLR-173.6m, LLR-173.6n, LLR-173.4n) | Inc 9b: the `●` marks equal the install for project and file rows, a linked `.s19` neither marked nor installed, the project-open note, the project preview's lines, a read error, the dialog import census, the stacking break and one-line rows (LED .86) | — |
| TC-B100-47 (LLR-175.1, LLR-175.1a, LLR-175.1b, LLR-175.1c, LLR-175.1d, LLR-175.1e, LLR-175.1f, LLR-175.1g, LLR-175.1h, LLR-175.1i, LLR-175.1j, LLR-175.1k, LLR-175.1l, LLR-175.1m, LLR-175.1o, LLR-175.1p, LLR-175.6) | Inc 11: the target line, the 15 refusals in the dialog, the one preparation | — |
| TC-B100-48 (LLR-175.2, LLR-175.2a) | Inc 11 | — |
| TC-B100-49 (LLR-175.3, LLR-175.3a, LLR-175.3b, LLR-175.3c, LLR-175.3d, LLR-175.3e, LLR-175.3f, LLR-175.3g, LLR-175.3h, LLR-175.3i, LLR-175.3j) | Inc 11: keys, focus, empty Save, Save during a refusal, the priority keys, the prefill, the labels, nothing loaded | — |
| TC-B100-65 (LLR-175.4, LLR-175.4a, LLR-175.4b, LLR-175.4c, LLR-175.4d, LLR-175.4e, LLR-175.4f, LLR-175.4g, LLR-175.4h, LLR-175.4i, LLR-175.4j, LLR-175.4k, LLR-175.4l, LLR-175.4m, LLR-175.5, LLR-175.5a, LLR-175.5b) | Inc 11: rows = plan, executed = painted, the out-of-date summary, the image, pending, links and merge rows, literal names, layout, the plan accessor, the direct payload, the once-per-open cost, the 150 ms recompute, the first frame, the rebuilt session | — |
| TC-B100-66 (LLR-173.7) | Inc 9b: the Load dialog, the Load-result panel and the refusal tokens (LED .86) | Inc 10: the question in 3 scenes and the quit-parameter arm (LED .89); Inc 11: the Save dialog in 6 scenarios (fresh, open project, merge, save as, a refusal, an empty Save) → 0 decision ids; Inc 12a: the progress lines of the 7 long actions (labels and step names) and the two new token pairs (LED .95); Inc 12b: the busy line and the quit question (LLR-177.3f, LLR-177.4a) |
| TC-B100-71 (LLR-168.4) | Inc 7 | — |
| TC-B100-44 (LLR-174.1, LLR-174.1a, LLR-174.1b, LLR-174.1c) | Inc 10: the 24-cell table by kind, the saved / save-back / saved-then-patched boundaries, an attach keeps the patch, the public reader of the Patch Editor flag (LED .89) | — |
| TC-B100-45 (LLR-174.2, LLR-174.2a, LLR-174.2b, LLR-174.2c, LLR-174.2d, LLR-174.2e, LLR-174.2f, LLR-174.2g, LLR-174.2h, LLR-174.2i, LLR-174.2j, LLR-174.2k, LLR-174.2l, LLR-174.2m, LLR-174.2n, LLR-174.2o, LLR-174.2p, LLR-174.2q, LLR-174.2r, LLR-174.2s, LLR-174.2t) | Inc 10: one modal with two buttons, the parameters (quit arm), the focus, `y`, `n` / `escape`, `enter`, clicks, other keys, the priority keys inert, literal names, the Patch Editor's own guard kept, the title, the three items, the target, the labels, two sentences, the buttons and body on screen, a second answer ignored, the change-file dropdown keeps the guard (LED .89) | Inc 12a+12b: the quit question built through the same modal |
| TC-B100-46 (LLR-174.3, LLR-174.3a, LLR-174.3b, LLR-174.3c, LLR-174.3d) | Inc 10: the reset after the answer, no reset on cancel, the project-load handler asks nothing, a confirmed and then refused project load keeps the work, a cancelled variant switch leaves the pending selection unchanged (LED .89) | — |
| TC-B100-72 (LLR-174.4, LLR-174.4a, LLR-174.4b, LLR-174.4c) | Inc 10: all four routes (the panel's `v` with a forced state), the seam census, one question per request, the kind of a typed or recent path (from the resolved path, CR10-01), the kind of a work-area file (LED .89) | Inc 12b: the busy refusal before the question (LLR-177.3a) |
| TC-B100-55 (LLR-178.1) | Inc 6: the reasons and the counts | Inc 7: the "first variant by name" mutation arm and the `derived_from` lines (ARCH-PDR-3) |
| TC-B100-73 (LLR-176.4, LLR-176.4a, LLR-176.4b) | Inc 12b (moved from 12a): the parser's byte callback, the identical result, the `a2l.py` re-freeze | — |
| TC-B100-50 (LLR-176.1, LLR-176.1a, LLR-176.1b, LLR-176.1c, LLR-176.1d, LLR-176.1e, LLR-176.1f, LLR-176.1g, LLR-176.1h, LLR-176.1i, LLR-176.1j, LLR-176.1k, LLR-176.1l, LLR-176.1m, LLR-176.1n, LLR-176.1o, LLR-176.1p, LLR-176.1q, LLR-176.1r, LLR-176.1s, LLR-176.1t) | Inc 12a: the begin line and bar, steps by index and by amount, the clamp, one timer and its stop, `mm:ss`, the stored file state, the outcome line, the file-state hand-back, the cleared bar, the exception end, unknown and replaced runs (a replaced run's outcome is still logged), overlapping actions, main-thread writes, scrubbed names (ESC and C0 included), the status-log control-byte choke point (SE5-12a-1), the idle row (LED .95, .96) | Inc 12b: the three moved actions animate between begin and end; Inc 12b: the three new worker bodies (LLR-176.1l, LLR-176.1q) |
| TC-B100-51 (LLR-176.2, LLR-176.2a, LLR-176.2b, LLR-176.2c, LLR-176.2d) | Inc 12a: the site census, only the seam sets the bar, the 7-entry table, an end on every success and failure exit, the Save project phases (LED .95, .96) | Inc 12b: re-derived over the worker bodies and their handlers (LLR-176.2, LLR-176.2c, LLR-176.2d) |
| TC-B100-41 (LLR-173.2m) | Inc 12a: the "Load" / "Projects" labels in the key bar and the palette (LED .95) | — |
| TC-B100-37 (LLR-172.4e, LLR-172.4f) | Inc 12a: the project-list skip on every platform; the Workarea Files list holds loadable suffixes only (LED .95) | — |
| TC-B100-38 (LLR-172.5i, LLR-172.5j, LLR-172.5k) | Inc 12a: a path the OS refuses (EACCES / ENAMETOOLONG) refused, with the NUL arms as regression arms; one project match; one refusal wording table (LED .95, .96) | — |
| TC-B100-39 (LLR-172.6b, LLR-172.6c) | Inc 12a: the pick re-checks the entry (folder, junction, link) and the copy cap (LED .95, .96) | — |
| TC-B100-56 (LLR-178.2) | Inc 6: the summary line and the final `#status_text` | Inc 12a: the project and file line reaches `#status_text` as the project load's file state (LLR-176.1j) (LED .95) |
| TC-B100-52 (LLR-176.3) | Inc 12b (moved from 12a, 12a ruling Q1): a main-thread step's name painted before its work (LED .98) | — |
| TC-B100-53 (LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1c, LLR-177.1d, LLR-177.1e, LLR-177.1f, LLR-177.1g, LLR-177.1h, LLR-177.1i, LLR-177.1j, LLR-177.1k, LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h, LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4c, LLR-177.4d, LLR-177.5, LLR-177.5a) | Inc 12b: the three worker steps and the work-area pick off the main thread, timers during them, main-thread session writes, the request census, a cold-load equal result, the reset order, the panel after the install, the Save re-derive before and adopt after, the busy refusals and their wording, quit (ask, stay, wait, idle), the parse's byte reports and the save's files placed (LED .98) | — |
| TC-B100-54 (LLR-177.2, LLR-177.2a, LLR-177.2b, LLR-177.2c) | Inc 12b: one forced raise per action, the session kept, the save rolled back, the app running (LED .98, .99) | — |
| TC-B100-07 (LLR-164.4, worker arm) | — | Inc 12b: the census over the Save worker body, 5 forced stage failures on the worker |
| TC-B100-08 (LLR-165.1) | — | Inc 12b: the one call site moves to the project-load install handler |
| TC-B100-09 (LLR-165.2) | — | Inc 12b: the new attribute names classified; the P2-over-P1 arm on the worker |

### 5.4 Reverse census (QA-15, trigger B1)

Executed at `1d677ba` with `grep -rl --include=*.py <symbol> tests` (35 test sources match the B1 set, P-35). One row per touched symbol.

| Symbol (increment) | Test sources | Disposition |
|---|---|---|
| `copy_into_workarea` (Inc 1) | 15 | `Path` return kept (LLR-163.1); re-pinned: TC-018, AT-031b, `test_tc_b99_31_changed_bytes_take_the_next_free_name`; the other 3 `_2+` files stay (P-22) |
| `_export_reuse_target` (Inc 1) | `test_b99_export.py` | the status word now comes from the placement outcome (LLR-163.6) |
| `Added variant` (Inc 1) | `test_tui_variants.py:274` | the first-load arm stays green |
| `_handle_save_dialog` exact-name merge (Inc 2, Inc 5) | `test_tui_variants.py::test_save_second_s19_into_project_appends_variant` (`:354`) | kept green (A-09) |
| `_handle_load_project` direct callers (Inc 3, Inc 7) | 13: `b97_fixtures.py`, `test_b97_load_project_dialog.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`, `test_report_progress.py`, `test_tui_commandbar.py`, `test_tui_manifest_save.py`, `test_tui_patch_variant.py` (`:338`, `:343`, `:782`, `:788`), `test_tui_report_filter_surface.py`, `test_tui_report_seam.py`, `test_tui_report_view.py`, `test_tui_variants.py`, `test_variant_execution.py` | the load question sits in the dialog router, so a direct call meets no modal; status-text assertions re-pinned at Inc 7 where the summary line replaces `Loaded project '` (4 files: `test_b99_export.py`, `test_b99_load_project.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`); Inc 12b: the success path finishes on a worker, so a caller waits for the install (ruling Q6) |
| manifest API (Inc 6, 7, 8a) | 9 | additive keys (`files`, `active_document`, `derived_from`), no `schema_version` bump; pins `test_manifest_writer.py:99`, `:216`, `:481` hold |
| `_resolve_manifest_entry` (Inc 7, LLR-169.8) | `test_b97_flow_builder.py`, `test_flow_persistence.py`, `test_flow_execution_service.py`, `test_manifest_writer.py`, `test_variant_execution.py` | the manifest-keys mode is used by `read_project_manifest` and `_reject_unsafe_entry` only; both flow-reference callers, `flow_persistence_service.py` and `flow_execution_service.py`, stay on the default mode, so `test_tc_b97_20_hostile_refs_render_literally` stays green (B-03) |
| `_handle_save_dialog` (Inc 2, 5, 8a, 8b, 11) | 7: `test_b99_staging.py`, `test_project_gather.py`, `test_tui_app.py`, `test_tui_evidence_packs.py`, `test_tui_manifest_save.py`, `test_tui_report_seam.py`, `test_tui_variants.py` | under the emit decision on data (LLR-167.1) an unpatched session still byte-copies, so `test_save_project_creates_project_folder_on_disk` and the evidence-pack saves keep their files; `test_project_gather.py::test_tc700_active_editor_document_is_gathered_by_kind` (a check document) keeps a byte copy and its `checks/` placement; AT-B99-05 (save-back, then Save project) now emits and keeps `status.startswith("Project saved")` on `#log_line_4` with the entry-count suffix (LLR-167.3); the plan execution and the refusals are re-checked per file at each listed increment |
| `_load_from_item`, `_handle_select_variant`, `_load_workarea_file` (9b G1), `_handle_load_dialog`, `_route_load_project`, `_load_path_from_user_input` (Inc 10) | the breaking set (E2 census): `test_at_b100_03…[size0/1]`, TC-B100-10 (`test_b100_session_reset.py`) and `test_tc_b99_40_strip_shows_new_file_source_byte` (`test_b99_editor_image.py`); `test_tui_patch_variant.py`, `test_b100_active_variant.py` and `test_loadfilescreen_input.py` were struck from the E1 first cut | the one load seam asks only when something unsaved would be lost; tests without unsaved work meet no modal; the 5 re-pinned nodes answer `y` or assert 0 closed-document lines |
| interim closed-document line (Inc 10, LLR-165.3) | `tests/test_b100_session_reset.py`: `test_tc_b100_10_interim_discard_notice`, `test_tc_b100_10_notice_names_every_discarded_entry`, `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2`; `test_tc_b100_10_no_discard_notice_when_nothing_unsaved` holds unchanged | re-pinned (§C.1, §C.5): the first two assert 0 closed-document lines, AT-B100-03 answers `y` |
| `PatchEditorPanel._dirty` read outside its module (Inc 10, LLR-174.1c) | `app.py` `_handle_save_dialog` | replaced by the public reader `PatchEditorPanel.is_dirty` |
| `#project_parent_path` (Inc 11, D7) | `test_b99_staging.py` (6 nodes: `test_tc_b99_14_save_project_missing_source`, `test_tc_b99_14_placement_failure_removes_created_folder`, `test_tc_b99_14_preexisting_folder_survives_placement_failure`, `test_at_b99_05_save_project_after_same_name_save_back`, `test_tc_b99_ux_c10_save_project_filename_renders_literally`, `test_tc_b99_ux_c10_placement_error_path_renders_literally`), `test_loadfilescreen_input.py:898`, `test_tui_directionb.py:3090` | re-pinned at Inc 11 with the same expectations and no parent typing (the payload's parent is the work area); AT-B99-05 keeps its outcome (LED-2026-10-26-batch-100.12); `test_loadfilescreen_input.py:898` is docstring text only |
| `SaveProjectScreen` (Inc 11) | 11 test files reference it (`test_b100_active_variant.py`, `test_b100_document.py`, `test_b100_project_check.py`, `test_b100_project_homes.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`, `test_b99_staging.py`, `test_loadfilescreen_input.py`, `test_tui_directionb.py`, `test_tui_manifest_save.py`) | drives that click `#save_ok` and wait for the dialog to close keep working for a valid name once the summary is painted (LLR-175.3c); drives that save a refused name and read the status log re-pin to `#save_where` with the dialog open (ruling Q5); drives that save immediately after typing wait for the summary first (LLR-175.4b) |
| `_handle_save_dialog(SaveProjectPayload(...))` direct calls (Inc 11) | 58 calls in 11 files (`support/b100_projects.py` 2, `test_b100_active_variant.py` 2, `test_b100_project_homes.py` 2, `test_b100_save_guards.py` 38, `test_b100_save_image.py` 3, `test_project_gather.py` 1, `test_tui_app.py` 1, `test_tui_evidence_packs.py` 1, `test_tui_manifest_save.py` 4, `test_tui_report_seam.py` 1, `test_tui_variants.py` 1) | unchanged (LLR-175.4l) |
| `#assign_batch` / `#assign_<n>` (Inc 11) | `test_tui_manifest_save.py` (3 nodes) | kept (ruling Q4); the focus order gains them between `#save_summary` and `#save_ok` |
| `LoadFileScreen` / `#load_path` / `#load_ok` (Inc 9b) | 13 files / 60 references to `LoadFileScreen` | the ids survive in `pa_C`; class-name references re-pinned to the new dialog class |
| `LoadProjectScreen` / `#project_list` / `#project_ok` (Inc 9b) | 17 files / 57 references to `LoadProjectScreen`; 17 files / 63 references to `#project_list` or `project_ok` | the dialog retires (VS-PA-3); project picks re-pinned to `#load_list` + `enter` |
| `_handle_load_dialog(Path)` (Inc 9b) | `test_tui_app.py:1254`, `:1288` | unchanged: the handler keeps accepting a `Path` (LLR-173.1) |
| `set_progress` / `#progress_bar` (Inc 12a+12b) | 5: `test_before_after_report.py` (`:228` spy), `test_report_off_ui_thread.py` (`:173`, `:259` spies), `test_report_progress.py` (`:49` AC-2/3 "leave the bar at 100", `:66` AC-4, `:126` direct call), `test_tui_directionb.py` (`:2048`, `:2206` direct call), `test_tui_report_attribution.py` (`:106` replaces `set_progress` with a one-argument lambda) | `set_progress(value, message=None)` keeps its signature and stays the seam's bar writer, so the spies and the lambda still see every value. `test_report_generation_drives_progress_bar_then_clears_it` (renamed from `test_report_generation_drives_progress_bar_to_100`, CR12a-3) is re-pinned: the bar moves while the report runs and is cleared at the end — a report never writes 100 (LLR-176.1k; the old pin encodes the stale-100 defect HLR-176c removes). The direct calls (`test_report_progress.py:126`, `test_tui_directionb.py:2206`) are allowed: LLR-176.2a counts sites in `app.py` only. Inc 12b: the three 12b actions' step and end calls move into worker bodies, through `call_from_thread` (LLR-176.2, re-derived). |
| `_handle_load_project`, `_route_load_project`, `_handle_save_dialog`, `load_a2l_from_path` direct callers (Inc 12b) | 26 test files; 184 direct call sites; 1 no-app test (`test_tui_app.py:85`) | the W class is taken by a **poll on a condition**, not by a helper's name (E3 A12b-01), and only `test_tc_b100_30_…under_one_second` becomes vacuous; refusal paths stay synchronous; success paths re-pinned by ruling Q6 and the one Q6 wait helper (`wait_for_complete()` + 2 pauses) |
| `set_file_status` (Inc 12a) | E2 derives it (the `#status_text` consumers in the `busy_status_line` component list 25 test sources) | the stored file state is painted at the end, so a test that reads `#status_text` after an action ends sees the same text; a test that reads it while an action runs is re-pinned |
| `list_projects` trailing-dot gate (Inc 12a) | E2 derives it | Windows unchanged; a Linux test that lists a dot-ending folder is re-pinned |
| `refresh_files` rows (Inc 12a, C7) | E2 derives it (tests that count Workarea Files rows with a `.a2l.json` or another non-loadable file) | re-pinned to the loadable rows |
| snapshot cells (Inc 12a; replaces the "Inc 9b, 11, 12a" row's 12a share) | the 29 pinned SVG files named in the increment packet | rebaselined in the CI-matching environment (`.github/workflows/snapshot-regen.yml`) after the merge, committing only those 29 files; pending until then |

---

### 5.5 Per-increment source files (ARQ §8, B-07)

Taken from `design/ARQ-batch-100.md` §8 / §8.1 as amended for round 2. Every conditional was decided at PDR (LED .27, .34); the design proposal `design/design-proposal-b100.md` repeats the sets. Interfaces by name: B100-I13 (`find_identical`, `place_into_workarea`), B100-I14 (`contained_in_workarea`), B100-I15 (the `save_patched` split), B100-I16 (`derived_from`), B100-I17 (the save plan), B100-I18 (the unsaved predicate), B100-I19 (`_session_snapshot`), B100-I20 (the one load seam), B100-I21 (the manifest-keys mode), B100-I22 (`predict_placement`).

| Inc | Source files | # |
|---|---|---|
| 1 | `workspace.py` (B100-I13, I14, I22), `segment_split_view.py`, `app.py`, `project_gather_service.py` (the gather passes its destination unresolved, LED .49) | 4 ⚠ |
| 2 | `app.py`, `workspace.py` (device-name predicate, `PROJECT_NAME_MAX_CHARS`) | 2 |
| 3 | `app.py` | 1 |
| 4 | `app.py` | 1 |
| 5 | `app.py`, `change_service.py` (B100-I15, I18), `project_gather_service.py` (B100-I17), `changes/apply.py` (SEC-4 staging, LED .56) | 4 ⚠ |
| 6 | `app.py`, `variant_execution_service.py`, `screens.py`, `styles.tcss` (the panel needs its layout rules) | 4 (at cap) |
| 7 | `manifest_writer.py`, `variant_execution_service.py`, `app.py` (`derived_from` B100-I16; `choose_install_set`; the plan's `files` row takes its key list from `app.py`, so `project_gather_service.py` is not touched) | 3 |
| 8a | `app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py` | 4 (at cap) |
| 8b | `app.py`, `project_gather_service.py`, `workspace.py` (`contained_in_workarea` uses for listing and load) | 3 |
| 9a | `workspace.py`, `app.py` | 2 |
| 9b | `screens.py`, `app.py`, `styles.tcss` (`choose_install_set` already in `app.py` from Inc 7) | 3 |
| 10 | `screens.py`, `app.py` (B100-I20), `styles.tcss`, `screens_directionb.py` (the public dirty-flag reader LLR-174.1 requires) | 4 (at cap) |
| 11 | `screens.py`, `app.py`, `styles.tcss` | 3 |
| 12a + 12b | `app.py`, `styles.tcss`, `s19_app/tui/a2l.py` (the parse-progress callback, a named frozen-engine crossing, LLR-176.4; the quit question reuses the Inc 10 confirm modal) | 3 |

No increment exceeds 4 source files; Inc 6, Inc 8a and Inc 10 are at the cap.

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
D1–D7 and O-1..O-11 are mapped to the requirements they shape in LED-2026-10-26-batch-100.1.
### 6.3 Open risks

**Security questions (trigger family C; the `devflow-scan-spec.py` verdict is recorded in LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.13 and LED-2026-10-26-batch-100.23):**
- **Input surface (C6).** Four untrusted inputs: the typed project name (HLR-164: sanitised, case-folded, reserved and device names refused on the raw and sanitised name, capped at 64 and by path length, a junction target refused), the typed load path (LLR-172.5: the project route for an absolute path only, normalised lexically with no link followed, matched by listing against the project list, which never lists a reserved home; LLR-172.5g, LLR-172.5h), `project.json` (LLR-169.4, LLR-169.8, LLR-170.1, LLR-168.1, LLR-168.4: 1 MiB, 1 000 entries per array, a manifest-keys mode that refuses drive-relative, stream and device names per path component), and the per-user recent store (LLR-172.2: size-capped, parse-guarded, drive-rooted paths only, kind matching the suffix, no control characters, never touched before Enter). Every placement requires containment in this work area inside `place_into_workarea` (LLR-163.1, LLR-171.4), so no writer can be left off a list; save-as never follows a directory link (LLR-171.1).
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
