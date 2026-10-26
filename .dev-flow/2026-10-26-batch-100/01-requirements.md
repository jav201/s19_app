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
**In:** PH-1, PH-2, PH-4, PH-5, M-1..M-7, L-2, L-3 (remaining paths) and L-4 of `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md`; G-005 (byte-identical reuse; TC-018 and AT-031b re-pinned); the Load dialog requests (a picker of work-area files and recent sources, Load opens projects, Enter loads, D10); CW-U-2, CW-U-5, CW-U-12 and CW-U-13 of `.dev-flow/design/AUDIT-codewire-ui-2026-10-23.md`; reserved project names; the progress indicator (N5); and the Load-result announcement P-E (from the operator's D2 note).

**Out (with where each lives):** PH-3, L-1 and the outside-work-area half of L-3 closed in batch-99 (premise P-21). The Code-Wire F6 findings and the integrity mediums and lows stay in `BACKLOG-CODE.md`. A present-but-unrecorded project file is not reported, because ruling O-1 makes every in-app write record its file (ARQ §3.3). Flow runs stay on the main thread (ruling O-7).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Work area | `<base>/.s19tool/workarea/`, the folder Load project lists (`app.py:8519-8524`). |
| Work copy | The copy of a loaded source in `workarea/temp/` (`WORKAREA_TEMP`, `workspace.py:20`). |
| Image differs | `ChangeService.image_differs_from_source(mem_map)` is true (B100-I5, LLR-167.1): the in-memory image holds a byte its source file does not. |
| Manifest seam | `S19TuiApp._write_and_verify_manifest` (`app.py:8272`), the one writer of `project.json` (B100-I7). |
| Variant slot `VS-<surface>-<n>` | A named clause of a UI requirement whose content waits for the prototype round's verdict on surface P-A..P-E. The verdict fills it through a ledger entry. A slot is not a deferral to the backlog, so it carries no deferral marker. |
| Problem (D3) | One entry of the Load-side check `check_project_files` (B100-I3, LLR-169.5). |
| Recent source | An entry of `<base>/.s19tool/recent_sources.json` (B100-I9, LLR-172.1). |

### 1.4 References
- `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (PH-*, M-*, L-* ids) and `AUDIT-codewire-ui-2026-10-23.md` (CW-U-* ids).
- `design/ARQ-batch-100.md` (§2 session inventory, §3 manifest, §4 Save project, §5 reuse rule, §6 Load sources, §7 progress, §10.1 rulings O-1..O-11) and `docs/ARCHITECTURE.md` §10 *Batch-100 declarations*, §11 B100-I1 to B100-I12.
- `design/plan-b100.html` and `design/veredicto-b100.json`: D1–D7, all on the recommended option; the D2 note became surface P-E.
- `evidence/p0-premises/`: the probes re-run at `1d677ba`.
- `REQUIREMENTS.md`: R-TUI-012 (`:1244`), HLR-151 (`:6404`), HLR-162 (`:6488`); batch-14 LLR-015.3 (`.dev-flow/2026-06-23-batch-14/01-requirements.md:222`).

### 1.5 Document overview
§2 holds the stories, the premise re-run and the fork verdict. §3 has one HLR per story, §4 the LLRs and the Information Flow Contract, §5 the validation strategy and the AT index. Ids: US-153 through US-168, HLR-163 through HLR-178, AT-B100-NN, TC-B100-NN.

---

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
- Python 3.11, Textual 8.2.8; Windows first.
- At most 4 SOURCE files per increment (ARQ §8); 15 sequential increments, one worktree each.
- The repo is public: records describe region extraction only as memory-region extraction.
- Every UI string is in English. `prototypes/` is never committed.
- A UI layout lands only after the prototype round's verdict on its surface.

### 2.5 Assumptions and dependencies
- `copy_into_workarea` is the placement path for project files (B99-I2); re-checked as premise P-22.
- `ChangeService.save_patched` emits and verifies the source plus the current document (batch-99 B99-I7); re-checked as P-23.
- The status log keeps naming the loaded file in every P-E variant (P-28). If a verdict drops it, the ATs that read it are amended by ledger entry.

### 2.6 Source user stories

Every story comes from the operator's commission of 2026-10-26 (PLAN header), the verdict D1–D7 (`design/veredicto-b100.json`), the orchestrator rulings O-1..O-11 (ARQ §10.1) and the findings in §1.4. Each row is one row of PLAN's increment table, except US-168, which is the P-E display that Inc 6 and Inc 7 wait for.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-153 | As the calibration engineer, I want a re-load or re-save of a file whose bytes are already in the work area to reuse that file, so that my project does not fill with identical `_<N>` copies and duplicate variants. | Inc 1 · M-1, G-005 | READY |
| US-154 | As the engineer saving a project, I want a name that clashes with another project, names a reserved folder or is too long to be refused with a reason, so that no save merges two projects, hides a project or crashes the app. | Inc 2 · M-4 (O-9), M-7, reserved names, L-3 | READY |
| US-155 | As the engineer switching projects, I want a project load to start from an empty session, so that no A2L, MAC or change entry of the previous project leaks into the new one or into its next save. | Inc 3 · PH-2 | READY |
| US-156 | As the engineer who just loaded a file or a project, I want the keyboard focus on a visible window, so that the single-key commands work. | Inc 4 · CW-U-2 | READY |
| US-157 | As the calibration engineer, I want Save project to save the image I see, with my applied patch, and to say how many entries it carries, so that what I reopen is what I saved. | Inc 5 · PH-1, D1, O-5, O-6 | READY |
| US-158 | As the calibration engineer, I want a patched image saved into my project to become the project's active variant, so that Load reopens where I stopped. | Inc 6 · PH-4, D2, O-1, O-10 | READY |
| US-159 | As the engineer opening a project, I want Load to open what is valid and list every problem — a damaged manifest, a missing file, a file changed on disk, an unreadable image — so that I never work on a project that silently differs from what I saved. | Inc 7 · PH-5, L-4, D3, O-2, O-11 | READY |
| US-160 | As the calibration engineer, I want the change document I was editing to be saved with the project and reopened on Load, so that I see my entries, not only the image. | Inc 8a · M-2, D4 | READY |
| US-161 | As the engineer managing projects, I want "save as" to copy the whole project, an A2L-only project to open, and every project to be saved where Load finds it, so that what I save always reopens complete. | Inc 8b · M-3 (D5, O-4), M-6 (D6), M-5 (D7, handler) | READY |
| US-162 | As the engineer loading files, I want my recent sources remembered, a project path typed into Load file to open the project, and file names shown literally, so that I reach my work without retyping paths. | Inc 9a · Load request (data), L-2, C6, C8 | READY |
| US-163 | As the engineer loading anything, I want one Load dialog that lists projects, work-area files and recent sources and accepts a typed path, where Enter loads and `esc` closes, so that I load with the keyboard and see what is available. | Inc 9b · Load request, D10, CW-U-12, CW-U-13, C8 | REFINE — layout waits for the P-A verdict |
| US-164 | As the calibration engineer, I want a question before a load replaces a patched image I have not saved, an open project or unsaved Flow Builder edits, so that no work is lost silently. | Inc 10 · CW-U-5, O-3 | REFINE — question layout waits for the P-B verdict |
| US-165 | As the engineer saving a project, I want the Save project dialog to show the real folder name, warn of a clash, a reserved name or a pending patch before I press Save, and close on `esc`, so that I know what the save will do. | Inc 11 · M-4 preview, D7 (dialog half), CW-U-12, CW-U-13 | REFINE — layout waits for the P-C verdict |
| US-166 | As any engineer, I want long actions to show that they are working and for how long, so that I do not think the app froze. | Inc 12a · N5 | REFINE — placement waits for the P-D verdict |
| US-167 | As any engineer, I want project load, Save project and the A2L parse to keep the screen alive while they run, so that the progress shows and the app answers. | Inc 12b · N5, O-7 | REFINE — conditional on the P-D verdict |
| US-168 | As the engineer opening a project, I want to be told which variant opened and why, and to see the problem list, so that a switch to the latest saved image never goes unnoticed. | P-E · D2 note, D3 display | REFINE — display waits for the P-E verdict |

**Ledger pairing:** stories live in this table. Ledger entries name the HLR or LLR they amend.

#### Refinement log (one block per story)

Each block carries the four context lines (user · task · environment · observable outcome). Unless a block says otherwise, the environment is a Windows terminal of 118 to 220 columns, keyboard first, with the work area on a local NTFS volume.

**US-153 — identical copies are reused**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = the calibration engineer; task = re-loading a source or re-saving a document; outcome = one file per distinct content; why = `p02` C leaves `firmware_1` and `firmware_2` with the same bytes; out of scope = `place_group_into_workarea` (requested names only, B99 PDR C3(e)).
- **Feasibility:** path = the B100-I6 reuse rule in `workspace.py`, plus the status of the variant append (ARQ condition C-1); fits one batch = yes.
- **Evaluability:** when the same file is loaded twice with a project open, the work area holds one copy and the project one variant, and the status does not say a variant was added.
- **Open questions:** none. The operator chose "reuse + re-pin tests" at the kickoff.
- **Classification:** `READY`.

**US-154 — Save project name guards**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving under a new or reused name; outcome = a refusal that names the reason, the app still running, no folder left; why = `a b`/`ab` merge silently, `reports` is saved and then hidden, a 300-character name crashes; out of scope = the dialog preview (US-165).
- **Feasibility:** path = `_handle_save_dialog` and `list_projects` in `app.py`, the name rules in `workspace.py`; fits one batch = yes.
- **Evaluability:** when the engineer saves as `Reports`, the save is refused with a reason and no `Reports` folder appears.
- **Open questions:** the length cap's value (§6.3, Q-1); O-9 retires a save into an existing project that is not open (§6.3, Q-2).
- **Classification:** `READY`; the cap's value is fixed at PDR.

**US-155 — a project load starts clean**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = opening P2 after working in P1; outcome = P2 alone in the session and in its re-save; why = `p03` prints six `LEAK` lines; out of scope = a loose Load file, which still composes with the session (MAC + S19 + A2L).
- **Feasibility:** path = one seam `_reset_project_session()` (B100-I4); fits one batch = yes.
- **Evaluability:** when P2 is loaded over P1 and saved, P2's folder holds only P2's files.
- **Open questions:** none.
- **Classification:** `READY`.

**US-156 — focus after a load**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading, then pressing a single-key command; outcome = the command runs; why = the focus lands on the hidden Split/Join table (`S4`); out of scope = the Split/Join window's own bindings.
- **Feasibility:** path = the load tails in `app.py` (`_step_finalize`, `:11191`; the A2L load tail); fits one batch = yes.
- **Evaluability:** when a file is loaded through the dialog and the engineer presses `p`, a dialog opens.
- **Open questions:** none.
- **Classification:** `READY`.

**US-157 — Save project saves the image you see**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving a session after applying a patch, without a save-back; outcome = the project image holds the patch and the status says how many entries; why = `p01` saves the original under "manifest verified"; out of scope = a width or S0 prompt (O-5).
- **Feasibility:** path = `ChangeService.image_differs_from_source` + `save_patched` (ARQ §4); fits one batch = yes.
- **Evaluability:** when the patched session is saved and reopened, the image holds the patch.
- **Open questions:** none (D1 = `imagen`). R-TUI-012 is amended to agree with LLR-015.3 (LED-2026-10-26-batch-100.1).
- **Classification:** `READY`.

**US-158 — the saved patched image becomes the active variant**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = save-back into the open project, then reopen; outcome = the reopened image is the patched one; why = `p02` A/B reopen the original; out of scope = the announcement (US-168).
- **Feasibility:** path = the save-back handler (`app.py:3364`) and the manifest seam; the reader parses `gathered`; fits one batch = yes.
- **Evaluability:** when the engineer saves back into project P and reopens P, the loaded file is the patched variant.
- **Open questions:** none (D2 = `ultima`, O-1, O-10).
- **Classification:** `READY`.

**US-159 — Load opens what is valid and lists every problem**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = opening a project after its files changed; outcome = the project opens and the status leads with the problem count; why = `p04` loads a damaged manifest, a corrupt image and an edited image with `notices=[]`; out of scope = the display of the list (US-168), present-but-unrecorded files (§1.2).
- **Feasibility:** path = `files` digests in the manifest, `check_project_files` (B100-I1 to B100-I3), private manifest staging; fits one batch = yes.
- **Evaluability:** when an image is edited on disk after the save, Load opens the project and names that file as changed.
- **Open questions:** none (D3 = `abre_y_reporta`, O-2, O-11).
- **Classification:** `READY`.

**US-160 — the change document travels with the project**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = saving with the Patch Editor open, then reopening; outcome = the Patch Editor shows the document's entries; why = `p06` A reopens no document and `p01` drops a pasted one; out of scope = undo history.
- **Feasibility:** path = `active_document` in the manifest, the gather, the reopen after the A2L attaches; fits one batch = yes.
- **Evaluability:** when a project saved with one entry is reopened, the Patch Editor lists that entry.
- **Open questions:** the file name a pasted document takes in `patches/` (§6.3, Q-5).
- **Classification:** `READY`.

**US-161 — projects reopen complete**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = "save as", an A2L-only project, saving anywhere; outcome = the copy holds every sub-folder, the A2L-only project opens, every saved project is listed; why = `p06` C, `p04` 10, `p05`; out of scope = the dialog's parent field and Browse… (US-165).
- **Feasibility:** path = `_handle_save_dialog`, `_handle_load_project`, `project_gather_service`; fits one batch = yes.
- **Evaluability:** when P is saved as Q, Q's flow list matches P's.
- **Open questions:** none (D5 = `copiar` with O-4, D6 = `abrir`, D7 = `solo_workarea`).
- **Classification:** `READY`.

**US-162 — recent sources, project paths and literal names**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading again a file used before, or typing a project path; outcome = the source is remembered, the project opens, names render as written; why = Load file gives `Unsupported file type: ` for a project folder (`p05`), and file names are parsed as markup (P-24); out of scope = the dialog that lists the recents (US-163).
- **Feasibility:** path = two functions in `workspace.py` (B100-I9), one work-area lister, the typed-path router (ARQ §6); fits one batch = yes.
- **Evaluability:** when a project folder is typed into Load file, the project opens.
- **Open questions:** none.
- **Classification:** `READY`.

**US-163 — one Load dialog**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading by keyboard; outcome = one dialog, Enter loads, `esc` closes, an empty Load explains; why = `S1`/`S3`: no picker, `esc` ignored, an empty Load says nothing; out of scope = the Workarea Files rail list (US-162).
- **Feasibility:** path = `screens.py` + `app.py` + `styles.tcss` (ARQ §8, Inc 9b); fits one batch = yes.
- **Evaluability:** when the engineer opens Load, highlights a recent source and presses Enter, that file loads.
- **Open questions:** the layout (VS-PA-1), whether a click loads (VS-PA-2, D10), the widget ids (VS-PA-3), the bindings (VS-PA-4), the preview (VS-PA-5).
- **Classification:** `REFINE` — P-A verdict. The clauses that hold in any variant are derived now (the batch-99 US-143 precedent); each slot is filled by a ledger entry.

**US-164 — ask before losing work**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading while something is unsaved; outcome = a question with direct keys, and cancel keeps everything; why = `S5`: a load over a patched image asks nothing; out of scope = the existing dirty-document question (`ConfirmDiscardScreen`, `screens.py:902`), which stays.
- **Feasibility:** path = a confirm modal on the `ConfirmDiscardScreen` pattern; fits one batch = yes.
- **Evaluability:** when a patched image is about to be replaced, the engineer sees a question and `n` keeps the patch.
- **Open questions:** short question or loss list (VS-PB-1); a "save first" key (VS-PB-2); the modal's ids (VS-PB-3).
- **Classification:** `REFINE` — P-B verdict.

**US-165 — the Save project dialog**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = naming a project; outcome = the folder name, the clash, reserved-name and pending-patch lines before Save; why = `S2`: no preview, `esc` ignored, an empty Save silent; out of scope = the handler rules (US-154, US-161).
- **Feasibility:** path = `SaveProjectScreen` (`screens.py:483`) + `app.py` (+ `styles.tcss`); fits one batch = yes.
- **Evaluability:** when the engineer types `a b`, the dialog shows `ab` as the folder before Save.
- **Open questions:** a line under the name or a summary of what is saved (VS-PC-1); Save disabled or refused on press during a clash (VS-PC-2); the ids (VS-PC-3).
- **Classification:** `REFINE` — P-C verdict.

**US-166 — progress for long actions**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = waiting for a load, a report or a save; outcome = a label, a running elapsed time, then the outcome; why = N5 reopened; out of scope = moving actions to workers (US-167).
- **Feasibility:** path = `begin_busy` / `step_busy` / `end_busy` over `set_progress` (B100-I12); fits one batch = yes.
- **Evaluability:** when a report is generated, the engineer sees it working and then its outcome.
- **Open questions:** the placement (VS-PD-1) and cancel (VS-PD-2).
- **Classification:** `REFINE` — P-D verdict.

**US-167 — long actions off the main thread**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = loading a large project; outcome = the elapsed time advances during the load; why = project load, Save project and the A2L parse block the main thread (ARQ §7); out of scope = flow runs (O-7).
- **Feasibility:** path = `@work(thread=True)` for three actions, installs through `call_from_thread`; fits one batch = yes.
- **Evaluability:** when a slow project loads, the elapsed time advances before the load ends.
- **Open questions:** a request made while one of these actions runs (VS-PD-3, §6.3 Q-6).
- **Classification:** `REFINE` — conditional on the P-D verdict (O-7).

**US-168 — the Load-project announcement**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** task = reopening a project after a save-back; outcome = a statement of which variant opened, why, how many variants exist, and the problem list; why = the operator's D2 note ("that the switch does not go unnoticed"); out of scope = switching variants (the existing selector).
- **Feasibility:** path = a pure announcement composer and its painters; fits one batch = yes.
- **Evaluability:** when project P with two variants is reopened, the engineer reads the opened variant's name and that P has 2 variants.
- **Open questions:** toast + badge, result panel or project strip (VS-PE-1); wording (VS-PE-2); a `v` key to switch (VS-PE-3).
- **Classification:** `REFINE` — P-E verdict.

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

- **Premise evaluation:** 29 premises · ✅ 29 TRUE · ❌ 0 FALSE · ❓ 0 UNDECIDABLE. Every finding the batch closes reproduces on its base.

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
> - files on disk (image bytes read with `tests/support/independent_reader.py`; `project.json` and `recent_sources.json` read as JSON);
> - painted text: the status log (`#log_line_1..4`, P-28), the Loaded panel (`#loaded_panel`), the Patch Editor ledger, dialog text;
> - the screen stack and the focused widget's region.
>
> It never asserts on an app attribute or a wrapped service. Test paths and `-k` selectors are provisional until Phase 3 and reconciled at Phase 4 (V-5).
>
> **Output-then-consume (C-12, trigger B4).** Every `project.json` writer/reader pair runs in one chain: drive the shipped handler, re-read what it wrote from disk, open it with the unmodified Load project in a fresh app, and assert the consumer's outcome. AT-B100-05, -06, -07, -08 and -10 are those gates. A test that writes `project.json` directly is a consumer-contract guard (a TC), never the gate.
>
> **UI stories (REFINE).** HLR-173 through HLR-178 state now what holds in any prototype variant. Each variant-specific clause is a named slot `VS-<surface>-<n>`; the verdict on that surface fills it through a ledger entry before the increment opens.

### HLR-163 — Byte-identical copies are reused
- **Traceability:** US-153
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When a file is placed in the work area or a project, and an existing regular, non-link, non-empty file named `<name>` or `<stem>_<N><suffix>` in the destination holds the same bytes, the system shall reuse that file and write nothing new. Otherwise it shall place the file under the lowest free `_<N>`, as before. When a load into an open project reuses a file already in the project, the status shall name the existing variant and shall not report a variant as added.
- **Rationale (informative):** identical copies and duplicate variants accumulate (P-6). The reuse widens B99-I2 (B100-I6).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_reuse.py`, plus the re-pinned nodes of LLR-163.3 and LLR-163.4.
- **Numeric pass threshold:** the `p02` C sequence (5 loads of two distinct `firmware.s19` sources) → 2 files in `temp/`, 2 variants in the project; 0 status lines reporting an added variant for a reused file.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** with project P open, the engineer loads `examples/case_01_basic_valid/firmware.s19`, then `examples/case_02_gaps_and_patch_targets/firmware.s19`, then each again. The work area holds two image files, P holds two variants, and the status for each repeated load names the existing variant.
  - **Shipped surface:** Load file (`l`, `#load_path`, `#load_ok`), the status log, the work area on disk.
  - **Acceptance test(s):** AT-B100-01
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: a 0-byte candidate is never reused; boundary: a same-size candidate with one differing byte (new `_<N>`), a deleted `_1` beside an identical `_2` (reused). Invalid/error: N/A — no input grammar changes.
  - **Negative control:** executed on `1d677ba` (P-6): `firmware_2.s19 310 a9e114d56077` beside an identical `firmware_1` → AT-B100-01 is RED today.

### HLR-164 — Save project refuses unsafe names and leaves nothing behind
- **Traceability:** US-154
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When Save project receives a project name, the system shall refuse it with a status naming the reason if its sanitised form (a) equals, compared case-folded, an existing project folder other than the open project, (b) equals, compared case-folded, a reserved work-area home, or (c) is longer than the name cap. When the sanitised name differs from the typed one, the status of a completed save shall name the folder it wrote. If creating the folder raises an `OSError`, then the system shall report it in the status and keep running. Every refused or failed save shall leave no folder that the save created. The project list shall omit every reserved home compared case-folded.
- **Rationale (informative):** silent merges (P-10), hidden reserved projects (P-14), a crash on a long name (P-13). Ruling O-9: the open project updates in place without a warning.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_guards.py`
- **Numeric pass threshold:** 5 reserved spellings (`reports`, `CRC`, `Splits`, `FLOWS`, `Temp`) → 5 refusals, 0 folders created; a clash with another project → 1 refusal naming it; a 300-character name → 1 status, app running, 0 folders; `list_projects` over `Splits` and `Reports` folders → 0 listed.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** in the Save project dialog the engineer types `Reports` and saves: the status gives the reason and no `Reports` folder appears. A 300-character name gives a status and the app keeps running. With project `ab` saved and P2 open, saving as `a b` is refused and the status names `ab`.
  - **Shipped surface:** Save project (`ctrl+s`, `#project_name`, `#save_ok`; ids provisional under VS-PC-3), the status log, the work area on disk.
  - **Acceptance test(s):** AT-B100-02
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary: a name at the cap (saved) and at cap + 1 (refused); invalid: reserved names in mixed case, a clash; error: a forced `OSError` on `mkdir`. Empty: N/A — an empty name is already refused as `Invalid project name.` (`app.py:8101-8104`).
  - **Negative control:** executed on `1d677ba` (P-14): `dialog Save 'reports' -> … Saved project` → AT-B100-02 is RED today.

### HLR-165 — A project load starts from an empty session
- **Traceability:** US-155
- **Ledger:** none
- **Statement:** When a project is loaded, the system shall, after the project validates and before it installs the project's first file, reset the session state of ARQ §2.2 rows S1–S12 in one place: the loaded image with its MAC and A2L attachments, the A2L path and parsed data, the change service, the variant ids, the declared regions, the last CRC template, the last comparison and check spec, the last flow run and execution, the report filter and the A2L derived views. It shall keep the monotonic generation counters (K1) and the view preferences (K2). A Save project after the load shall then copy only that project's files.
- **Rationale (informative):** six leaks and a contaminating re-save (P-2). A loose Load file still composes with the session, as intended.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_session_reset.py`
- **Numeric pass threshold:** the `p03` sequence → 0 `LEAK` lines; P2's re-save tree = `['prg.s19', 'project.json']`; the derived-set comparison (LLR-165.2) → 0 attributes differ outside the K1/K2 allow-list.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads P1 (S19 + MAC + A2L), adds a Patch Editor entry, loads P2 (S19 only) and saves. P2's folder holds `prg.s19` and `project.json` only. The Loaded panel shows no MAC and no A2L, and the Patch Editor ledger is empty.
  - **Shipped surface:** Load project (`p`, `#project_list`, `#project_ok`), Save project (`ctrl+s`), the Loaded panel, the Patch Editor ledger, the project folder on disk.
  - **Acceptance test(s):** AT-B100-03
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: loading a project into a fresh session (nothing to reset, the same outcome); boundary: loading the same project twice. Invalid/error: N/A — an invalid project is refused before the reset (`app.py:8453-8461`).
  - **Negative control:** executed on `1d677ba` (P-2): `P2 files after re-save: ['firmware.a2l', 'firmware.mac', 'prg.s19', 'project.json']` → AT-B100-03 is RED today.

### HLR-166 — The focus stays on a visible window after a load
- **Traceability:** US-156
- **Ledger:** none
- **Statement:** When a file load, a project load or an A2L load completes, the system shall leave the keyboard focus on a widget with a non-zero visible region in the displayed window, never on a widget of a hidden window, so that the app's single-key bindings reach their actions.
- **Rationale (informative):** every load focuses the hidden Split/Join table, which eats `p`, `t`, `k`, `g`, `d`, `j` (P-16).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_focus.py`
- **Numeric pass threshold:** 4 load paths (Load file dialog, Load project dialog, Workarea Files pick, A2L load) → 4 focused widgets with region area > 0; `p` after each image or project load → the screen stack grows by 1.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after a file loads through the Load file dialog, pressing `p` opens a dialog. The same holds after a project load.
  - **Shipped surface:** Load file (`l`), Load project (`p`; the dialog `p` opens follows VS-PA-4), the screen stack.
  - **Acceptance test(s):** AT-B100-04
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary: a load while the Split/Join window is shown (its table keeps the focus, region area > 0). Empty/invalid/error: N/A — a failed load moves no focus.
  - **Negative control:** executed on `1d677ba` (P-16): `focused region area: 0`, `` `p` -> Screen `` → AT-B100-04 is RED today.

### HLR-167 — Save project saves the image the session holds
- **Traceability:** US-157
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When Save project runs while the loaded image differs from its source file, the system shall write the in-memory image into the project through `ChangeService.save_patched` (`change_service.py:2009`), with 32 bytes per line and the source's S0 header, under the source's file name; it shall verify the written file and report in the status how many entries the saved image carries. When the image does not differ, it shall copy the source byte for byte. If the re-derive blocks any entry, then the system shall refuse the whole save, name the blocked entries and leave no folder it created. MAC and A2L files stay byte copies.
- **Rationale (informative):** the save copies the work copy and drops the patch (P-1). D1 = `imagen`; O-5 sets the save-back defaults with no prompt; O-6 refuses a partial save.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_image.py`
- **Numeric pass threshold:** the `p01` sequence → the project image read by the independent reader equals the in-memory image (0 differing addresses), every S19 data record of the emitted file carries ≤ 32 data bytes, its S0 equals the source's; an unpatched save → 0 differing bytes against the source file; a blocked document → 0 files written, 0 folders left.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads `case_01` `firmware.s19`, applies `0x8000007C DE AD BE EF` in the Patch Editor without a save-back, saves project P1, and reopens P1 in a fresh app. The independent reader finds `DE AD BE EF` at `0x8000007C` in `P1/firmware.s19`, and the save status names the number of entries.
  - **Shipped surface:** Patch Editor (Add, Apply), Save project (`ctrl+s`, `#save_ok`), Load project (`p`), the status log, the project folder.
  - **Acceptance test(s):** AT-B100-05
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: no entry applied (byte copy); boundary: an entry that writes the bytes already there (no difference, byte copy); error: a blocked entry (the whole save refused). Invalid: N/A — the entry grammar is unchanged.
  - **Negative control:** executed on `1d677ba` (P-1): `project firmware.s19 == in-memory patched image? False` → AT-B100-05 is RED today.

### HLR-168 — A save-back into the project becomes the active variant
- **Traceability:** US-158
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When a Patch Editor save-back writes an image into the open project, the system shall make that image the project's active variant in the session and in `project.json`, and shall keep `current_file.path` on the source the image was loaded from. When any write lands a file in the open project — Save project, the save-back, the Load-file variant append, the MAC sync or the A2L sync — the system shall rewrite `project.json` through the manifest seam, carrying the existing `batch`, `assignments`, `declared_regions` and `gathered` values unchanged. When the project is loaded, the system shall open the active variant `project.json` records.
- **Rationale (informative):** the save-back adds a variant that Load never opens (P-3). D2 = `ultima`; O-1 (every in-project writer rewrites the manifest); O-10 (the source path stays, for the before/after report).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_active_variant.py`
- **Numeric pass threshold:** `p02` A and B → the reload opens the patched variant (2 of 2 arms); 4 in-project writers → 4 manifest rewrites, each with 0 changed composition keys; `current_file.path` after a save-back = the work copy (1 assertion).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** with project P open, the engineer applies a patch and saves back as `firmware.s19` (placed as `firmware_1.s19`). Reopening P in a fresh app loads `firmware_1.s19`: the newest status log line names it, and the independent reader finds the patch in it. `project.json` on disk names `firmware_1` as `active_variant`.
  - **Shipped surface:** Patch Editor save-back (`#patch_saveback_*`), Load project (`p`), the status log, `project.json` on disk.
  - **Acceptance test(s):** AT-B100-06
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: the default save-back name (`firmware-patched.s19`, `p02` B) and a reused identical name (M-1); error: a manifest rewrite whose verify fails (the existing mismatch notice, `app.py:8416-8423`). Empty/invalid: N/A.
  - **Negative control:** executed on `1d677ba` (P-3): `RELOAD -> file=firmware.s19 … image_is_patched=False` → AT-B100-06 is RED today.

### HLR-169 — Load opens what is valid and lists every problem
- **Traceability:** US-159
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When the manifest seam writes `project.json`, the system shall record under `files` the size and SHA-256 of every top-level S19, HEX, MAC and A2L file of the project and of the active document, computed from disk after every copy has landed, and shall stage the manifest in a private directory. When a project is loaded, the system shall open every valid file, open the next valid variant when the active one is missing or unreadable, and report each problem: the manifest is unreadable (defaults used), no digests are saved (an older project), a recorded file is missing (named), a file's size or digest differs from the record, or an image could not be read or holds 0 data bytes. The status log shall lead with the number of problems. Every malformed manifest record shall be reported and skipped, never trusted.
- **Rationale (informative):** damaged manifests, corrupt images and edited images load as success (P-4); a missing image gives a misleading status (P-5). D3 = `abre_y_reporta`; O-2 (the scope of `files`); O-11 (private staging).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_check.py`
- **Numeric pass threshold:** the `p04` cases 2, 5, 6, 7 and a legacy project → exactly 1 problem each, of the matching kind, naming the file; a clean project → 0 problems; every case → the project opens (a file is loaded or the A2L attached).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer saves project P, a byte of `P/firmware.s19` changes on disk, and P is reopened in a fresh app: P opens, and the status log leads with 1 problem and names `firmware.s19`. A hand-edited `project.json` whose `files` names `../outside.s19` opens P, reports the record, and reads nothing outside P.
  - **Shipped surface:** Save project, Load project (`p`), the status log, `project.json` on disk.
  - **Acceptance test(s):** AT-B100-07
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: a project with no `files` key (the legacy notice); boundary: a size equal to the record with a different digest; invalid: hostile `files` keys and values (LLR-169.4); error: a `project.json` that is not JSON.
  - **Negative control:** executed on `1d677ba` (P-4): `[2 image edited on disk] … notices=[]` → AT-B100-07 is RED today.

### HLR-170 — The change document is saved and reopened with the project
- **Traceability:** US-160
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When Save project runs while the Patch Editor holds a document with at least one entry, the system shall place that document in the project's `patches/` — a document that has no file is written there as a new file — and record its project-relative path as `active_document` in `project.json`. When the project is loaded, the system shall reopen that document in the Patch Editor after the project's A2L is attached. If the recorded document is missing, unreadable or outside the project, then the load shall continue and list the problem.
- **Rationale (informative):** the gathered document is not reopened and a pasted one is not saved (P-8). D4 = `reabrir`.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_document.py`
- **Numeric pass threshold:** `p06` A → after Load, the Patch Editor document is `patches/boost.json` with 1 entry; `p01` (pasted) → 1 file in `P/patches/`, reopened with 1 entry; a missing recorded document → 1 problem, the project opens.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer pastes one entry into the Patch Editor, saves project P and reopens P in a fresh app: the Patch Editor ledger lists that entry's address.
  - **Shipped surface:** Patch Editor, Save project, Load project, the Patch Editor ledger.
  - **Acceptance test(s):** AT-B100-08
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a document with 0 entries (not recorded); boundary: a file-backed document already in `P/patches/` (reused, M-1); invalid: an `active_document` outside the project. Error: N/A — a missing document is a listed problem, covered by LLR-170.3.
  - **Negative control:** executed on `1d677ba` (P-8): `after Load: editor doc = None entries = 0` → AT-B100-08 is RED today.

### HLR-171 — Projects are saved where Load finds them and reopen complete
- **Traceability:** US-161
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When Save project saves the open project under a new name, the system shall copy every sub-folder of the open project, with its regular files, into the new project. When a project holds an A2L and no data file, Load project shall open its A2L. When Save project is given a parent folder that does not resolve to the app's own work area, the system shall refuse the save before creating any folder.
- **Rationale (informative):** "save as" leaves flows, patches and reports behind (P-9); an A2L-only project cannot be loaded (P-12); a save elsewhere is never listed (P-11). D5 = `copiar` with O-4 (every sub-folder); D6 = `abrir`; D7 = `solo_workarea` (the dialog half is HLR-175).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_project_homes.py`
- **Numeric pass threshold:** `p06` C → Q holds every file of P's sub-folders (0 missing, 0 differing bytes); `p04` 10 → the A2L-only project opens with 3 A2L tags; a foreign parent → refused, 0 folders created; 1 dialog save → listed by `list_projects`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-09) the engineer opens P (with `flows/f1.json`, `patches/boost.json`, `reports/r.md`) and saves it as Q: Q's folder holds those files, and Q's flow list shows `f1`. (AT-B100-10) An A2L-only project saved and reopened shows its A2L in the Loaded panel. (AT-B100-11) A project saved through the dialog is listed by Load project.
  - **Shipped surface:** Save project, Load project, the Loaded panel, the Flow Execution import list, the project folders on disk.
  - **Acceptance test(s):** AT-B100-09, AT-B100-10, AT-B100-11
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty: a project with no sub-folder (nothing extra copied); boundary: a nested sub-folder and a link inside a sub-folder (skipped); error: a foreign parent (refused). Invalid: N/A — the folder names come from the project, not from input.
  - **Negative control:** executed on `1d677ba`: P-9 `Q tree: ['firmware.a2l', 'firmware.s19', 'project.json']` → AT-B100-09 RED; P-12 `No supported files in project: P` → AT-B100-10 RED; P-11 `listed by Load project? False` → the foreign-parent arm of TC-B100-33 RED.

### HLR-172 — Recent sources, typed project paths and literal file names
- **Traceability:** US-162
- **Ledger:** none
- **Statement:** When a file from outside the work area loads successfully through Load file or the A2L load, the system shall record it in `<base>/.s19tool/recent_sources.json`, newest first, de-duplicated by resolved path, at most 20 entries. Reading that file shall drop every invalid entry, and an oversized or unparseable file shall read as empty; reading shall never raise. The Workarea Files list and the Load dialog shall enumerate the work-area files through one function. When a typed path resolves to a project folder inside the work area, or to its `project.json`, the system shall load that project; any other folder shall be answered with a status that names Load project. The Workarea Files list shall render file names literally.
- **Rationale (informative):** L-2 (P-15); the unified dialog needs its data sources (ARQ §6); file names are parsed as markup (P-24).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_recents.py`
- **Numeric pass threshold:** 25 outside loads → 20 entries, newest first; the hostile store set (LLR-172.2) → 0 raises, 0 invalid entries returned; `ab` and `ab/project.json` typed → 2 project loads of `ab`; 3 hostile file names → 3 literal rows, 0 markup spans.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-12) the engineer loads `examples/case_01_basic_valid/firmware.s19` through Load file, then types the work-area path of project `ab` into Load file: `recent_sources.json` on disk lists the example's absolute path, and the status log names project `ab` loaded. (AT-B100-13) Files named `[bold]x[/bold].s19` and `[red.s19` in the work area appear in the Workarea Files list exactly as named, with no style.
  - **Shipped surface:** Load file (`l`, `#load_path`), the Workarea Files list (`#files_list`), the status log, `recent_sources.json` on disk.
  - **Acceptance test(s):** AT-B100-12, AT-B100-13
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty: no store file (an empty list); boundary: the 20th and 21st entry; invalid: hostile store entries and markup-shaped names; error: an unreadable store file.
  - **Negative control:** executed on `1d677ba` (P-15): `Load file 'ab' -> status=['Unsupported file type: ']` → AT-B100-12 RED today. AT-B100-13: a mutation building the list `Label` with markup on (today's `app.py:6559`) → the bold name paints styled and `[red.s19` raises → RED (C-40, Phase 3).

### HLR-173 — One Load dialog
- **Traceability:** US-163
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When the engineer opens Load, the system shall show one dialog that offers the work area's projects, the work-area files, the recent sources and a typed path, laid out as slot VS-PA-1 selects. In that dialog: `enter` shall load the highlighted or typed item; `escape` shall close it and change nothing; a Load with nothing selected or typed shall keep the dialog open and paint a line that says why; every button shall show a direct key; every name read from disk shall render with markup off. The dialog shall dismiss with `LoadChoice(kind, value)`, routed by one app handler, and a work-area pick shall load that file in place, with no second copy.
- **Variant slots (filled by the P-A verdict through a ledger entry):** VS-PA-1 the layout (tabs · one sectioned list with the path as filter · two panes with a preview); VS-PA-2 whether a click loads (D10); VS-PA-3 the widget ids, and whether `#load_path` / `#project_list` survive (PDR); VS-PA-4 which bindings open it (`l`, `ctrl+l`, `p`); VS-PA-5 the preview's content.
- **Rationale (informative):** the dialog has no list, ignores `escape`, and an empty or Enter-only Load does nothing (P-18..P-20).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_load_dialog.py`
- **Numeric pass threshold:** 4 `LoadChoice` kinds → 4 routes to their handlers; `enter` on each section → 1 load; `escape` → 0 changes to the session; an empty Load → 1 painted reason, the dialog still open; 3 hostile names → 0 markup spans; a work-area pick → 0 new files in `temp/`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads an example through Load file (which records it), restarts the app, opens Load, moves to the recent source and presses Enter: that file loads. `escape` closes the dialog with the session unchanged. An empty Load paints a reason. A project named `[b]P[/b]` is listed as written.
  - **Shipped surface:** the Load dialog (opened by the VS-PA-4 binding), the status log, the screen stack.
  - **Acceptance test(s):** AT-B100-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: no project, no file, no recent (each section says so); boundary: one item per section; invalid: hostile names and a hostile `recent_sources.json`. Error: N/A — a failing load reports through the existing load path.
  - **Negative control:** executed on `1d677ba` (P-18, P-19): `escape on LoadFileScreen -> screen: LoadFileScreen`; `Enter with a typed path -> current_file before/after: firmware_1.s19 / firmware_1.s19` → AT-B100-14 RED today.

### HLR-174 — A question before unsaved work is replaced
- **Traceability:** US-164
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When a load would replace a session in which the loaded image differs from its source, or the Flow Builder holds unsaved edits, or when a project load would replace an open project, the system shall ask before loading, in the form slot VS-PB-1 selects. The question shall name what would be lost. `y` shall replace and continue the load; `n` and `escape` shall cancel it and leave the session unchanged. The question shall be answered before the project-session reset runs. The existing question for a dirty change document stays.
- **Variant slots (filled by the P-B verdict through a ledger entry):** VS-PB-1 a short question, or a list of what is lost and what stays on disk; VS-PB-2 an `s` key that saves first and then continues; VS-PB-3 the modal's ids.
- **Rationale (informative):** a patched image is replaced with no question (P-17). O-3 adds unsaved Flow Builder edits.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_confirm.py`
- **Numeric pass threshold:** the 16-cell trigger table (LLR-174.1) → 16 of 16 cells as tabulated; `n` → 0 changes to the image digest, the file path and the project; `y` → 1 load.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer applies a patch and loads another file: a question appears naming the patched image; `n` keeps the patched image (the hex view still shows the patch); repeating with `y` loads the new file. With a project open, loading another project asks first.
  - **Shipped surface:** Load (file and project), the confirm modal, the hex view, the status log.
  - **Acceptance test(s):** AT-B100-15
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☐ error — empty: nothing unsaved and no project open (no question); boundary: a patch that writes the bytes already there (no question), re-loading the open project (asks). Invalid/error: N/A — the answer keys are a closed set.
  - **Negative control:** executed on `1d677ba` (P-17): `Load file over patched image -> stack: ['Screen'] … image still patched? False` → AT-B100-15 RED today.

### HLR-175 — The Save project dialog says what the save will do
- **Traceability:** US-165
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** While the engineer types a project name in the Save project dialog, the system shall show the folder name the save will create, and a line when that name clashes with another project or is a reserved home, or when the loaded image differs from its source (the patch will be written), in the form slot VS-PC-1 selects. The dialog shall offer no parent folder field and no Browse… button, and the save shall go to the app's work area. `escape` shall close the dialog and save nothing; a Save with an empty name shall keep the dialog open and paint a line that says why; every button shall show a direct key; names read from disk shall render with markup off.
- **Variant slots (filled by the P-C verdict through a ledger entry):** VS-PC-1 a line under the name, or a summary of what is saved; VS-PC-2 during a clash, Save disabled or refused on press; VS-PC-3 the widget ids.
- **Rationale (informative):** no preview, no `escape`, a silent empty Save (P-18, P-19); D7's dialog half removes the parent field.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_save_dialog.py`
- **Numeric pass threshold:** `a b` → the folder line shows `ab`; `reports`, an existing other project, and a patched session → 3 warning lines; 0 widgets `#project_parent_path` / `#save_browse`; `escape` → 0 folders; an empty Save → 1 painted reason.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer opens Save project, types `a b` and sees `ab` as the folder; types the name of another existing project and sees the clash line before pressing Save; presses `escape`, and no folder appears.
  - **Shipped surface:** the Save project dialog (`ctrl+s`), the work area on disk.
  - **Acceptance test(s):** AT-B100-16
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: an empty name; boundary: a name at the cap; invalid: reserved and clashing names. Error: N/A — handler errors are HLR-164's.
  - **Negative control:** executed on `1d677ba` (P-18, P-19): `escape on SaveProjectScreen -> screen: SaveProjectScreen`; `empty name Save click -> … new status: []` → AT-B100-16 RED today.

### HLR-176 — Long actions show that they are working
- **Traceability:** US-166
- **Ledger:** none
- **Statement:** When a long action starts — a file or project load, an A2L parse, Save project, a report, a diff report, a before/after run — the system shall show that it is working, labelled with the action, at the place slot VS-PD-1 selects. While an action runs on a worker, the elapsed time shall advance. When the action ends, by success, failure or exception, the system shall stop showing it as working and show its outcome.
- **Variant slots (filled by the P-D verdict through a ledger entry):** VS-PD-1 the status line with a spinner, a modal with a bar, or a thin bar over the key bar; VS-PD-2 whether `escape` cancels, and for which actions.
- **Rationale (informative):** N5: no action shows its progress beyond one bar step (ARQ §7).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_busy.py`
- **Numeric pass threshold:** every begin → exactly 1 end, also on an exception (0 indicators left showing); a 1.2 s worker action → the elapsed text advances at least 1 time; the 12 functions that call `set_progress` at `1d677ba` (P-29) → 12 routed through the seam.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads an image: the working indicator shows the action's label while it runs and disappears at the end, and the status log names the outcome.
  - **Shipped surface:** Load file (`l`), the working indicator (VS-PD-1), the status log.
  - **Acceptance test(s):** AT-B100-17
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: an action shorter than one timer tick (shown and cleared); error: an action that raises (the indicator ends with the failure). Empty/invalid: N/A — no input.
  - **Negative control:** a mutation dropping the end call on the exception path → the indicator stays after a failed load → AT-B100-17 RED (C-40, Phase 3).

### HLR-177 — Project load, Save project and the A2L parse run off the main thread
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** Where the P-D verdict keeps increment 12b, the system shall run project load, Save project and the A2L parse on worker threads and install their results on the main thread only. While one of them runs, the working indicator's elapsed time shall advance. A request for another of these actions while one runs shall be handled as slot VS-PD-3 selects. Flow runs stay on the main thread.
- **Variant slots (filled by the P-D verdict through a ledger entry):** VS-PD-3 the policy for a second request while one runs (refuse with a status, or queue).
- **Rationale (informative):** these three block the main thread, so no indicator can tick (ARQ §7). O-7 moves these three and leaves flow runs, which keeps the batch-97 D14 Run/Confirm surface (I-7) untouched.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py`
- **Numeric pass threshold:** a project load slowed by 1.5 s → the elapsed text advances at least 1 time before the load ends; 0 writes to the session outside the main thread (thread-id probe); the same final session as a main-thread load (0 differing names in the LLR-165.2 comparison).
- **Priority:** low
- **Acceptance (black-box):**
  - **Observable outcome:** the engineer loads a slowed project: the elapsed time advances during the load, and the status log then names the project loaded.
  - **Shipped surface:** Load project, the working indicator, the status log.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error — boundary: a load that finishes inside one tick; error: a worker that raises (the app keeps running, the indicator ends). Empty/invalid: N/A.
  - **Negative control:** code-read on `1d677ba`: `_handle_load_project → load_selected_file` runs synchronously (`app.py:8510`, `:10731`), so the elapsed text cannot advance during it → AT-B100-18 RED today (executed at Phase 3).

### HLR-178 — Load project announces which variant opened and lists the problems
- **Traceability:** US-168
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When a project load completes, the system shall announce the variant it opened, the number of variants the project holds, and why that one opened — recorded as active, or first by name because the manifest records none, or first by name because the manifest could not be read, or the next valid one because the recorded one is missing or unreadable — and shall list every problem of HLR-169 with the file it names. The announcement shall be written to the status log and painted as slot VS-PE-1 selects, with every name read from disk rendered with markup off.
- **Variant slots (filled by the P-E verdict through a ledger entry):** VS-PE-1 a toast with a title badge, a result panel to dismiss, or a persistent project strip; VS-PE-2 the wording; VS-PE-3 a `v` key that switches variant from the announcement.
- **Rationale (informative):** the operator's D2 note asks that the switch to the latest saved image never goes unnoticed; D3 asks for the problem list.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_announce.py`
- **Numeric pass threshold:** the 4-reason truth table (LLR-178.1) → 4 of 4 reasons; a 2-variant project → the announcement names the opened variant and the count 2; 3 problems → 3 named files; a hostile variant name → 0 markup spans.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after a save-back into P (two variants), reopening P announces `firmware_1` as opened, that P holds 2 variants, and that it is the recorded active one. With `firmware_1.s19` deleted on disk, reopening announces `firmware` as opened because the recorded one is missing, and lists the missing file.
  - **Shipped surface:** Load project, the status log, the announcement surface (VS-PE-1).
  - **Acceptance test(s):** AT-B100-19
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty: a one-variant project; boundary: a project whose every image is unreadable (A2L or MAC only); invalid: a hostile variant name. Error: N/A — problems are data, covered by HLR-169.
  - **Negative control:** executed on `1d677ba` (P-3): the reload status is `Loaded project 'P' -> firmware.s19`, with no count and no reason → AT-B100-19 RED today.

---

## 4. Low-level requirements (LLR)

> Ids `LLR-<HLR>.<M>`. TC ids are `TC-B100-NN`. Each LLR's mutation (Negative control) is run at Phase 3 (C-40) and described by position and operation, never pasted (C-56). Symbols marked NEW are created in Phase 3.

### LLR-163.1 — Reuse any identical `<name>` or `<stem>_<N><suffix>`
- **Traceability:** HLR-163
- **Ledger:** none
- **Statement:** `copy_into_workarea` (`workspace.py:402`) shall enumerate its reuse candidates from a listing of the destination — `<name>` and every `<stem>_<digits><suffix>`, compared case-insensitively on Windows — and reuse the first that is a regular file, not a link or reparse point, non-empty, of the staged size and byte-identical. Otherwise it shall claim the lowest free `_<N>`. Its parameters, its `Path` return and its staging and failure contract stay as B99-I2 states them.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-01 — `pytest tests/test_b100_reuse.py -k tc_b100_01`
- **Numeric pass threshold:** the S7 sequence (case_01, case_02, case_02, case_01, case_02) → names `firmware.s19`, `firmware_1.s19`, `firmware_1.s19`, `firmware.s19`, `firmware_1.s19`; 2 files in the destination.
- **Negative control:** executed on `1d677ba` (`ui_load_dialogs_probe` S7): `copy case_02 again -> firmware_2.s19` → RED. Mutation at Phase 3: restrict the comparison to the bare name → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — empty: a 0-byte candidate (not reused); boundary: `_1` deleted beside an identical `_2` (reused), an upper-case `_2` name on Windows (reused); invalid: a link candidate (not reused).

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
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `test_tc018_existing_name_is_dedup_suffixed` (`tests/test_unified_write.py:372`) shall assert two pairs: the same change document written twice under `cs.json` returns the same path and leaves 1 file; a different document written under `cs.json` lands at `cs_1.json` and both files survive. `test_at031b_two_saves_are_distinct_no_clobber` (`tests/test_tui_patch_editor_v2.py:1304`) shall assert: two `save_doc` of an unchanged document leave 1 file; a `save_doc` after an added entry leaves 2 files with distinct names. The node names stay, so the registry entries TC-018 and AT-031b keep resolving.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber`
- **Numeric pass threshold:** 2 passed, each with 2 arms asserted.
- **Negative control:** executed on `1d677ba` (P-7): the old single-arm expectations → `FF`. Mutation at Phase 3: disable the reuse → the identical arm of both → RED.
- **Boundary catalog:** ☒ boundary — identical bytes (one file) and one differing byte (two files).

### LLR-163.4 — The one ripple re-pin
- **Traceability:** HLR-163
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `test_tc_b99_31_changed_bytes_take_the_next_free_name` (`tests/test_b99_export.py:375`) shall assert that a third export with the same changed bytes reuses `t_isle_1.s19` and reports it as reused, leaving 2 files. `test_tc_b99_31_bin_pair_placed_under_one_suffix`, `test_tc_b94_04_template_save_reload_and_dedup`, `test_at_b94_17_template_save_listing_import_and_dedup` and `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate` stay unchanged (P-22).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name tests/test_b99_export.py::test_tc_b99_31_bin_pair_placed_under_one_suffix tests/test_flow_a2b_b94.py::test_tc_b94_04_template_save_reload_and_dedup tests/test_tui_flow_builder_b94.py::test_at_b94_17_template_save_listing_import_and_dedup tests/test_b99_staging.py::test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`
- **Numeric pass threshold:** 5 passed, 0 failed; the re-pinned arm asserts 2 files in the export home.
- **Negative control:** a mutation disabling the reuse → the re-pinned arm sees `t_isle_2.s19` → RED.
- **Boundary catalog:** ☒ boundary — the second export (differing bytes, `_1`) and the third (identical, reused).

### LLR-163.5 — No "added" status for a reused variant
- **Traceability:** HLR-163
- **Ledger:** none
- **Statement:** `_sync_loaded_file_to_project` (`app.py:8526`) shall name the existing variant, and shall not emit its added-variant status (`app.py:8616`), when the copy into the project returned a file that already existed.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-03 — `pytest tests/test_b100_reuse.py -k tc_b100_03`
- **Numeric pass threshold:** a repeated load → 0 added-variant lines and 1 line naming the existing variant; a first load → 1 added-variant line.
- **Negative control:** a mutation always emitting the added-variant status → RED.
- **Boundary catalog:** ☒ boundary — a first load (added) and a repeated load (existing).

### LLR-164.1 — Reserved homes compared case-folded, at save and at list
- **Traceability:** HLR-164
- **Ledger:** none
- **Statement:** `_handle_save_dialog` (`app.py:8087`) shall refuse, before creating any folder, a sanitised name whose case-fold equals the case-fold of an entry of `RESERVED_WORKAREA_HOMES` (`workspace.py:40`); `list_projects` (`app.py:8519`) shall omit every folder whose case-folded name is in that set.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-04 — `pytest tests/test_b100_save_guards.py -k tc_b100_04`
- **Numeric pass threshold:** every tuple entry in 3 casings (lower, upper, title; the set is derived from the imported tuple, ≥ 9 entries) → refused, 0 folders; folders `Splits` and `Reports` → 0 listed.
- **Negative control:** executed on `1d677ba` (P-14): `Splits` saved and listed → RED.
- **Boundary catalog:** ☒ invalid — every reserved name in mixed case.

### LLR-164.2 — A clash with another project is refused; the open project updates in place
- **Traceability:** HLR-164
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_save_dialog` shall refuse, before writing any file, a sanitised name whose case-folded form equals that of an existing work-area folder other than `current_project_dir`, with a status and a `notify(…, markup=False)` that name the existing project. A name equal to the open project shall update it in place with no warning. When the sanitised name differs from the typed one, the completed save's status shall name the folder.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-05 — `pytest tests/test_b100_save_guards.py -k tc_b100_05`
- **Numeric pass threshold:** with `ab` saved and P2 open, `a b` → 1 refusal naming `ab`, `ab/` unchanged (0 changed digests); with `ab` open, `ab` → saved in place, 0 warnings; `my proj` → the status names `myproj`.
- **Negative control:** executed on `1d677ba` (P-10): `'a b' -> project='ab'` saved silently → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — boundary: the open project's own name; invalid: a clash differing only in case.

### LLR-164.3 — Name cap and `OSError`
- **Traceability:** HLR-164
- **Ledger:** none
- **Statement:** `_handle_save_dialog` shall refuse, before creating any folder, a sanitised name longer than `PROJECT_NAME_MAX_CHARS` (NEW, `workspace.py`; its value is fixed at PDR, §6.3 Q-1), with a status naming the cap; it shall catch an `OSError` from creating the folder and report it in the status.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-06 — `pytest tests/test_b100_save_guards.py -k tc_b100_06`
- **Numeric pass threshold:** a name of exactly the cap → saved; cap + 1 and 300 characters → 2 statuses, 0 folders, app running; a forced `OSError` on `mkdir` → 1 status, 0 raises.
- **Negative control:** executed on `1d677ba` (P-13): `RAISED FileNotFoundError` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the cap and cap + 1; a forced `OSError`.

### LLR-164.4 — A refused or failed save leaves no folder it created
- **Traceability:** HLR-164
- **Ledger:** none
- **Statement:** Every `return` of `_handle_save_dialog` that follows the folder's creation and does not complete the save shall be preceded on its path by `_remove_created_project_dir` (`app.py:8076`), which removes only a folder this call created.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-07 — `pytest tests/test_b100_save_guards.py -k tc_b100_07` (an AST census over the handler's returns, plus one behavioural arm per refusal kind)
- **Numeric pass threshold:** the census derives the post-creation returns from the AST (≥ 3 at `1d677ba`: the validation error, the MAC clash, the A2L clash, `app.py:8148-8170`) → 0 returns without the removal; each behavioural arm → 0 folders left.
- **Negative control:** a mutation deleting one removal call → the census names that return → RED.
- **Boundary catalog:** ☒ error — every refusal path after creation; a pre-existing folder is never removed.

### LLR-165.1 — One reset seam, before the first install
- **Traceability:** HLR-165
- **Ledger:** none
- **Statement:** `S19TuiApp._reset_project_session()` (NEW, `app.py`) shall reset rows S1–S12 of ARQ §2.2, then repaint the Patch panel through `refresh_entries`. `_handle_load_project` (`app.py:8444`) shall call it once per load, after `validate_project_files` succeeds (`:8453-8461`) and before `load_selected_file` (`:8510`). No other caller shall call it.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-08 — `pytest tests/test_b100_session_reset.py -k tc_b100_08`
- **Numeric pass threshold:** per project load → 1 call, ordered before the first install; a Load file → 0 calls; call sites in `s19_app/` → 1.
- **Negative control:** a mutation moving the call after `load_selected_file` → the MAC merge sees the old file → RED.
- **Boundary catalog:** ☒ boundary — loading the open project again.

### LLR-165.2 — The derived-set comparison (C-31)
- **Traceability:** HLR-165
- **Ledger:** none
- **Statement:** The leak check shall compare `vars(app)`, the `current_*` attributes and the change service's public state between a cold load of P2 and a load of P2 over P1, with an explicit allow-list of rows K1 and K2. The compared set shall be derived from the live object, never hand-listed, and guarded by a size floor.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-09 — `pytest tests/test_b100_session_reset.py -k tc_b100_09`
- **Numeric pass threshold:** 0 differing names outside the allow-list; the derived set holds ≥ 60 names (ARQ §2.1 census: 67).
- **Negative control:** a code mutation dropping the `current_a2l_path` reset → 1 differing name → RED; a set mutation filtering the derived set below 60 names → the size floor → RED.
- **Boundary catalog:** ☒ boundary — the K1 counters differ by design and are allow-listed.

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

### LLR-166.1 — The image and project load tails re-home the focus
- **Traceability:** HLR-166
- **Ledger:** none
- **Statement:** The load tail `_step_finalize` (`app.py:11191`) shall, when the focused widget's region area is 0 or it belongs to a window that is not displayed, move the focus to a focusable widget of the displayed window.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-12 — `pytest tests/test_b100_focus.py -k tc_b100_12`
- **Numeric pass threshold:** 3 paths (Load file, Load project, Workarea Files pick) → 3 focused widgets with region area > 0.
- **Negative control:** executed on `1d677ba` (P-16): `focused region area: 0` → RED.
- **Boundary catalog:** ☒ boundary — the Split/Join window displayed (its table keeps the focus).

### LLR-166.2 — The A2L load tail re-homes the focus
- **Traceability:** HLR-166
- **Ledger:** none
- **Statement:** The A2L load tail of `load_a2l_from_path` (`app.py:8789`) shall apply the rule of LLR-166.1.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-13 — `pytest tests/test_b100_focus.py -k tc_b100_13`
- **Numeric pass threshold:** 1 A2L load → a focused region area > 0.
- **Negative control:** a mutation removing the re-home from the A2L tail → area 0 → RED.
- **Boundary catalog:** ☒ boundary — an A2L load with no image loaded.

### LLR-167.1 — `image_differs_from_source`
- **Traceability:** HLR-167
- **Ledger:** none
- **Statement:** `ChangeService.image_differs_from_source(mem_map) -> bool` (NEW, B100-I5) shall return true iff the journal is bound to this dict (`_image_map is mem_map`, `change_service.py:895`, bound at `:1814`) and some journaled address (`_journal`, `:887`) holds a byte other than its source byte. It shall be read-only and shall not iterate `mem_map`.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-14 — `pytest tests/test_b100_save_image.py -k tc_b100_14`
- **Numeric pass threshold:** unpatched → False; applied → True; applied then undone → False; a same-byte patch → False; an unbound map → False; 0 iterations of `mem_map` (a counting subclass).
- **Negative control:** a mutation returning true whenever the map is bound → the unpatched arm → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty journal; a same-byte patch; an unbound map.

### LLR-167.2 — Save project emits or copies the image
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_save_dialog` shall, when `image_differs_from_source(current_file.mem_map)` is true, call `ChangeService.save_patched` with the in-memory map and ranges, `project_dir`, `current_file.path.name`, the source kind, `bytes_per_line=32`, the source's S0 as `s0_header`, `source_image_path=current_file.path` and the MAC records and A2L tags; otherwise it shall call `copy_into_workarea(current_file.path, project_dir)` (`app.py:8173`). MAC and A2L stay `copy_into_workarea` copies.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-15 — `pytest tests/test_b100_save_image.py -k tc_b100_15`
- **Numeric pass threshold:** a patched S19 → 0 differing addresses against `mem_map` (independent reader), every data record ≤ 32 bytes, the S0 equal to the source's; a patched HEX → 0 differing addresses; unpatched → 0 differing bytes against the source file; MAC and A2L → 0 differing bytes.
- **Negative control:** executed on `1d677ba` (P-1): `== in-memory patched image? False` → RED.
- **Boundary catalog:** ☒ boundary — S19 and HEX sources; an S19 with no S0 (the emitter's synthesized S0).

### LLR-167.3 — The status names the entries the image carries
- **Traceability:** HLR-167
- **Ledger:** none
- **Statement:** The status of an emitting Save project shall carry the entry count of `save_back_status_suffix` (`change_service.py:131`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-16 — `pytest tests/test_b100_save_image.py -k tc_b100_16`
- **Numeric pass threshold:** 1 and 2 applied entries → status lines carrying `1` and `2` with the entry noun.
- **Negative control:** a mutation dropping the suffix → 0 counts → RED.
- **Boundary catalog:** ☒ boundary — an entry added after the last apply (named as applied by the save).

### LLR-167.4 — A blocked re-derive refuses the whole save
- **Traceability:** HLR-167
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When `save_patched` returns `ok=False` (`change_service.py:2146-2158`), `_handle_save_dialog` shall report its message with the blocked entries, write no manifest, copy no MAC or A2L, and remove the folder it created.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-17 — `pytest tests/test_b100_save_image.py -k tc_b100_17`
- **Numeric pass threshold:** a document with 1 blocked entry → 1 status naming it, 0 files, 0 folders left.
- **Negative control:** a mutation ignoring `ok=False` → a manifest is written → RED.
- **Boundary catalog:** ☒ error — the blocked document.

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

### LLR-168.3 — Every in-project writer rewrites the manifest
- **Traceability:** HLR-168
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** The Load-file variant append and the MAC and A2L syncs (`app.py:8591`, `:8622`, `:8630`, `:8652`) shall each end in `_write_and_verify_manifest`, passing the `batch`, `assignments`, `declared_regions` and `gathered` of the existing manifest.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-20 — `pytest tests/test_b100_active_variant.py -k tc_b100_20`
- **Numeric pass threshold:** 4 writers → 4 rewrites; each → 0 changed composition keys; the variant append → `active_variant` = the appended id.
- **Negative control:** a mutation removing the seam call from the variant append → `active_variant` stale → RED.
- **Boundary catalog:** ☒ boundary — a manifest with every composition key filled.

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
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_write_and_verify_manifest` (`app.py:8272`) shall compute `files` itself, after every copy has landed, over the top-level S19, HEX, MAC and A2L files and the active document, and over no file under `flows/`, `flowsets/`, `reports/`, `checks/`, `splits/` or `templates/`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-22 — `pytest tests/test_b100_project_check.py -k tc_b100_22`
- **Numeric pass threshold:** a project with 3 data/A2L files, `flows/f1.json` and `reports/r.md` → `files` keys = the 3 (the set derived from the folder listing by suffix); with an active document → 4.
- **Negative control:** a mutation walking sub-folders → `flows/f1.json` recorded → RED.
- **Boundary catalog:** ☒ boundary — a HEX and an S19 variant; an active document.

### LLR-169.3 — Verify covers the new keys
- **Traceability:** HLR-169
- **Ledger:** none
- **Statement:** `verify_written_manifest` (`manifest_writer.py:632`) shall include `files` and `active_document` in its drift domain (today `:717-723`).
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-23 — `pytest tests/test_b100_project_check.py -k tc_b100_23`
- **Numeric pass threshold:** one digest changed between write and verify → 1 mismatch reported; unchanged → 0.
- **Negative control:** a mutation leaving `files` out of the domain → 0 mismatches → RED.
- **Boundary catalog:** ☒ boundary — a changed `active_document` only.

### LLR-169.4 — The reader treats `files` as untrusted (C6)
- **Traceability:** HLR-169
- **Ledger:** none
- **Statement:** `read_project_manifest` shall parse `files` into `dict[Path, FileRecord]`, each key through `_resolve_manifest_entry`; a record whose `size` is not an `int` ≥ 0 (a `bool` included), whose `sha256` is not 64 hex characters, or whose key is unsafe shall give one `MANIFEST-BAD-STRUCTURE` and be skipped; an absent key shall give an empty dict and no issue.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-24 — `pytest tests/test_b100_project_check.py -k tc_b100_24`
- **Numeric pass threshold:** the hostile set (`../x.s19`, an absolute path, `C:x`, a UNC path, `size: true`, `size: -1`, `size: "1"`, `sha256: "XYZ"`, 63 and 65 hex characters) → 10 issues, 0 records; a valid record → 1 record.
- **Negative control:** a mutation accepting a `bool` size → 0 issues on that arm → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — an absent key; the hostile set.

### LLR-169.5 — `check_project_files`
- **Traceability:** HLR-169
- **Ledger:** none
- **Statement:** `check_project_files(project_dir, manifest) -> list[ProjectFileProblem]` (NEW, `manifest_writer.py`) shall return one problem per: the manifest unreadable (`MANIFEST-JSON-PARSE`, `-SIZE-CAP`, top-level `-BAD-STRUCTURE`); no `files` key; a recorded file missing; a size or digest differing; an image whose load reports errors or whose `mem_map` is empty. It shall never raise.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-25 — `pytest tests/test_b100_project_check.py -k tc_b100_25`
- **Numeric pass threshold:** the `p04` cases 2, 5, 6, 7 and a legacy project → 5 single problems of the matching kinds; a clean project → 0; a file unreadable by permission → 1 problem, 0 raises.
- **Negative control:** executed on `1d677ba` (P-4): `notices=[]` for cases 2, 6, 7 → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ error — legacy; an equal size with a different digest; an unreadable file.

### LLR-169.6 — Load opens the valid files and leads with the count
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_load_project` shall run `check_project_files`, open the active variant when it is valid, otherwise the next valid variant in `build_variant_set` order, then the MAC, and shall write a status log line that leads with the problem count; it shall no longer write "activating the first variant" when no variant can be opened.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-26 — `pytest tests/test_b100_project_check.py -k tc_b100_26`
- **Numeric pass threshold:** the active variant deleted with 2 variants → the other opens, 1 problem; every image deleted → the MAC opens, 1 problem per missing image; a clean project → 0 problem lines.
- **Negative control:** executed on `1d677ba` (P-5): `activating the first variant` then `-> firmware.mac` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the last valid variant; no valid variant.

### LLR-169.7 — The manifest is staged privately
- **Traceability:** HLR-169
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `write_project_manifest` (`manifest_writer.py:414`) shall stage `project.json` in a private directory from `_private_stage_dir` (`workspace.py:298`) and place it with `os.replace`, never through the fixed `temp/project.json` (`:509`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-27 — `pytest tests/test_b100_project_check.py -k tc_b100_27`
- **Numeric pass threshold:** 8 concurrent manifest writes for 8 projects × 10 trials → 0 manifests holding another project's content; 0 files at `temp/project.json` after.
- **Negative control:** executed on `1d677ba` (P-27): the fixed staging path → the structural arm RED; a mutation restoring it → the concurrency arm RED.
- **Boundary catalog:** ☒ boundary — 1 and 8 writers.

### LLR-170.1 — The `active_document` key
- **Traceability:** HLR-170
- **Ledger:** none
- **Statement:** `serialize_manifest` shall emit `active_document` as a project-relative POSIX path under `patches/` or `checks/`, through `_reject_unsafe_entry`, only when set; `read_project_manifest` shall parse it through `_resolve_manifest_entry`, giving one issue and `None` for an unsafe or malformed value.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-28 — `pytest tests/test_b100_document.py -k tc_b100_28`
- **Numeric pass threshold:** `patches/boost.json` → round-trip equal; `../x.json`, an absolute path, a number → 3 issues, 3 `None`; absent → `None`, 0 issues.
- **Negative control:** a mutation skipping `_resolve_manifest_entry` → `../x.json` accepted → RED.
- **Boundary catalog:** ☒ empty ☒ invalid — absent; hostile values.

### LLR-170.2 — The gather places the active document, pasted or file-backed
- **Traceability:** HLR-170
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `gather_project_artifacts` (`project_gather_service.py:400`) shall place the active document into the project's `patches/` (or `checks/` by kind) — writing a document with no `source_path` as a new file — and `GatherOutcome` (`:369`) shall name the project-relative path where it landed.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-29 — `pytest tests/test_b100_document.py -k tc_b100_29`
- **Numeric pass threshold:** a pasted document with 1 entry → 1 file in `P/patches/` holding 1 entry, its path named in the outcome; a file-backed document → 1 file, byte-equal to the source.
- **Negative control:** executed on `1d677ba` (P-8): nothing under `patches/` for a pasted document → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 0 entries (not placed); an identical document already in `patches/` (reused).

### LLR-170.3 — Load reopens the document after the A2L
- **Traceability:** HLR-170
- **Ledger:** none
- **Statement:** `_handle_load_project` shall load `active_document` into the change service after the project's A2L is attached, and shall list a missing or unreadable document as a problem and continue.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-30 — `pytest tests/test_b100_document.py -k tc_b100_30`
- **Numeric pass threshold:** `p06` A → the document `patches/boost.json`, 1 entry; a symbol entry → resolved against the project's A2L (0 unresolved); a missing document → 1 problem, the project opens.
- **Negative control:** executed on `1d677ba` (P-8): `editor doc = None` → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a symbol entry; a missing document.

### LLR-171.1 — Save as copies every sub-folder
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** When `_handle_save_dialog` saves an open project to a new folder, it shall copy every sub-folder of `current_project_dir`, recursively, regular files only, each through `copy_into_workarea` into the same relative path, skipping links and reparse points.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-31 — `pytest tests/test_b100_project_homes.py -k tc_b100_31`
- **Numeric pass threshold:** P with `flows/`, `flowsets/`, `patches/`, `checks/`, `reports/`, `templates/`, `splits/` (one file each; the expected set derived from P's listing) → 0 missing and 0 differing files in Q; P → 0 changed digests; a link inside `flows/` → 0 copied.
- **Negative control:** executed on `1d677ba` (P-9): Q lacks the sub-folders → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid — no sub-folder; a nested sub-folder; a link.

### LLR-171.2 — An A2L-only project opens
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_load_project` shall, when the project has no data file and one A2L, reset the session, set the project, attach the A2L through the A2L load path and report it, instead of `No supported files in project`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-32 — `pytest tests/test_b100_project_homes.py -k tc_b100_32`
- **Numeric pass threshold:** `p04` 10 → 3 A2L tags, the project set, no `current_file`; a folder with neither → the existing refusal, 1 status.
- **Negative control:** executed on `1d677ba` (P-12): `No supported files in project: P` → RED.
- **Boundary catalog:** ☒ empty — a folder with no data file and no A2L.

### LLR-171.3 — Only the app's work area is a parent
- **Traceability:** HLR-171
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `_handle_save_dialog` shall refuse, before creating any folder, a `SaveProjectPayload.parent_folder` (`screens.py:144`) that does not resolve to `self.workarea`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-33 — `pytest tests/test_b100_project_homes.py -k tc_b100_33`
- **Numeric pass threshold:** parent = another `.s19tool/workarea` → refused, 0 folders; a parent outside any work area → refused, 0 folders; the work area under a different spelling (a trailing separator, mixed case) → saved and listed (1 listing).
- **Negative control:** executed on `1d677ba` (P-11): the other work area accepted, not listed → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — equivalent spellings; foreign parents.

### LLR-172.1 — The recent-sources store is written
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** `record_recent_source(base_dir, path)` (NEW, `workspace.py`) shall write `{"schema_version": 1, "sources": [{"path", "kind"}]}` to `<base>/.s19tool/recent_sources.json`, newest first, de-duplicated by resolved path, at most 20 entries, staged and placed with `os.replace` after an `_is_reparse_point` check (`workspace.py:172`) on `.s19tool`. `load_from_path` (`app.py:8710`) and `load_a2l_from_path` (`:8789`) shall call it after a successful copy, for sources outside the work area only.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-34 — `pytest tests/test_b100_recents.py -k tc_b100_34`
- **Numeric pass threshold:** 25 distinct outside loads → 20 entries, newest first; the same file twice → 1 entry; a source inside the work area → 0 entries; a failed load → 0 entries; `.s19tool` as a junction → 0 writes.
- **Negative control:** a mutation dropping the de-duplication → 2 entries → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the 20th and 21st entry; a junctioned `.s19tool`.

### LLR-172.2 — The store is read as untrusted input (C6)
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** `read_recent_sources(base_dir)` (NEW, `workspace.py`) shall read at most 64 KiB, parse it under a guard, and return only entries whose `path` is an absolute string with no NUL and whose `kind` is one of `s19`, `hex`, `mac`, `a2l`, at most 20; an oversized, unparseable or wrongly shaped file shall read as an empty list; it shall never raise.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-35 — `pytest tests/test_b100_recents.py -k tc_b100_35`
- **Numeric pass threshold:** a 65 KiB file, `{not json`, a top-level list, `schema_version: 2` → 4 empty lists; entries with `kind: exe`, a relative path, a NUL, a number as path → 0 returned; 10 000 valid entries within 64 KiB → ≤ 20 returned; 0 raises.
- **Negative control:** a mutation removing the size cap → the 65 KiB arm returns entries → RED.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — no file; exactly 64 KiB; hostile entries; an unreadable file.

### LLR-172.3 — Recent paths stay local
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** No writer of `project.json`, of a report or of a project folder shall copy an entry of the recent-sources store.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-36 — `pytest tests/test_b100_recents.py -k tc_b100_36`
- **Numeric pass threshold:** after an outside load, Save project and a report → 0 occurrences of the recent path's unique marker directory in the project folder's files.
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

### LLR-172.5 — A typed project path opens the project (L-2)
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** `_load_path_from_user_input` (`app.py:8658`) shall resolve the typed path; when it is a direct child folder of `self.workarea` holding a `project.json` or a data file, or that folder's `project.json`, it shall load that project through `_handle_load_project`; any other folder shall give a status naming Load project; a path that resolves outside the work area shall never route to a project load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-38 — `pytest tests/test_b100_recents.py -k tc_b100_38`
- **Numeric pass threshold:** `ab`, `ab/project.json` and `ab` reached through a `..` segment → 3 loads of `ab`; an empty folder → 1 status naming Load project; a folder outside the work area holding a `project.json` → 0 project loads.
- **Negative control:** executed on `1d677ba` (P-15): `Unsupported file type: ` → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — `..` segments; a folder outside the work area.

### LLR-172.6 — The Workarea Files list renders names literally (C8)
- **Traceability:** HLR-172
- **Ledger:** none
- **Statement:** `refresh_files` shall build each item's `Label` with `markup=False` (today `app.py:6559`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-39 — `pytest tests/test_b100_recents.py -k tc_b100_39`
- **Numeric pass threshold:** `[bold]x[/bold].s19`, `[red.s19`, `[link=http://e]a[/link].s19` → 3 rows whose plain text equals the name, 0 spans, 0 raises.
- **Negative control:** a mutation restoring markup on → spans or a markup error → RED.
- **Boundary catalog:** ☒ invalid — the three hostile names.

### LLR-173.1 — `LoadChoice` and one router
- **Traceability:** HLR-173
- **Ledger:** none
- **Statement:** The Load dialog (`screens.py`) shall dismiss with `LoadChoice(kind, value)` (NEW, B100-I8), `kind` one of `project`, `workarea`, `recent`, `path`; one app handler shall route `project` to `_handle_load_project`, `workarea` to `load_selected_file` in place, `recent` to `load_from_path` (or `load_a2l_from_path` by kind), and `path` to `_load_path_from_user_input`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-40 — `pytest tests/test_b100_load_dialog.py -k tc_b100_40`
- **Numeric pass threshold:** 4 kinds → 4 routes; a work-area pick → 0 new files in `temp/`.
- **Negative control:** a mutation routing `workarea` through `load_from_path` → 1 new copy → RED.
- **Boundary catalog:** ☒ boundary — a recent A2L (routed by kind).

### LLR-173.2 — Keys and the empty Load
- **Traceability:** HLR-173
- **Ledger:** none
- **Statement:** The Load dialog shall bind `enter` to load the highlighted or typed item and `escape` to dismiss with `None`; a Load with no selection and no typed text shall paint a reason line and stay open; each button's label shall show its direct key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-41 — `pytest tests/test_b100_load_dialog.py -k tc_b100_41`
- **Numeric pass threshold:** `enter` in each section → 1 dismiss with the item; `escape` → 1 dismiss with `None`; an empty Load → 1 reason line, 0 dismisses; every button → 1 direct key shown.
- **Negative control:** executed on `1d677ba` (P-18, P-19) → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — an empty Load; a typed path while an item is highlighted (the precedence is fixed at PDR with VS-PA-1).

### LLR-173.3 — Every list builds names with markup off (C8)
- **Traceability:** HLR-173
- **Ledger:** none
- **Statement:** Every list in the Load dialog shall build names from disk and from the recent store with `markup=False` (today `screens.py:707`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-42 — `pytest tests/test_b100_load_dialog.py -k tc_b100_42`
- **Numeric pass threshold:** a hostile project name, file name and recent path → 3 literal rows, 0 spans, 0 raises.
- **Negative control:** a mutation restoring today's `Label(name)` → RED.
- **Boundary catalog:** ☒ invalid — hostile names.

### LLR-173.4 — The dialog's sources
- **Traceability:** HLR-173
- **Ledger:** none
- **Statement:** The Load dialog shall take projects from `list_projects`, files from `list_workarea_files` and recents from `read_recent_sources`, each section stating when it is empty.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-43 — `pytest tests/test_b100_load_dialog.py -k tc_b100_43`
- **Numeric pass threshold:** 2 projects + 1 reserved folder, 2 files, 3 recents → 2 + 2 + 3 rows; empty sources → 3 empty-section lines.
- **Negative control:** a mutation listing folders without `list_projects` → the reserved folder listed → RED.
- **Boundary catalog:** ☒ empty — every section empty.

### LLR-174.1 — The trigger truth table
- **Traceability:** HLR-174
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** The load guard (NEW, `app.py`) shall decide over image differs (D) × Flow Builder dirty (F, `is_dirty`, `flow_screens.py:1354`) × project open (P) × load kind (file, project): it shall ask when D or F; it shall ask for a project load when P; otherwise it shall load without asking. Of the 16 cells, 13 ask (the 12 with D or F, plus the project load with P and neither D nor F) and 3 load.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-44 — `pytest tests/test_b100_confirm.py -k tc_b100_44`
- **Numeric pass threshold:** 16 of 16 cells as tabulated; 13 ask, 3 load.
- **Negative control:** a mutation dropping the F term → 4 cells wrong → RED.
- **Boundary catalog:** ☒ boundary — every cell is one.

### LLR-174.2 — The question's keys and outcomes
- **Traceability:** HLR-174
- **Ledger:** none
- **Statement:** The confirm modal (NEW, `screens.py`, on the `ConfirmDiscardScreen` pattern, `:902`) shall bind `y` to replace and `n` and `escape` to cancel, name what would be lost, and render file names with markup off; cancel shall leave the session unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-45 — `pytest tests/test_b100_confirm.py -k tc_b100_45`
- **Numeric pass threshold:** `n`, `escape` → 0 changes to the image digest, `current_file.path` and `current_project`; `y` → 1 load; every button → 1 direct key shown.
- **Negative control:** a mutation making `escape` replace → RED.
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

### LLR-175.1 — The preview lines
- **Traceability:** HLR-175
- **Ledger:** none
- **Statement:** `SaveProjectScreen` (`screens.py:483`) shall, on every change of the name, show the sanitised folder name and the clash, reserved-name and pending-patch lines computed by the HLR-164 rules and `image_differs_from_source`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-47 — `pytest tests/test_b100_save_dialog.py -k tc_b100_47`
- **Numeric pass threshold:** `a b` → `ab`; `Reports` → 1 reserved line; another project's name → 1 clash line; a patched session → 1 pending line; each line rendered with 0 markup spans.
- **Negative control:** a mutation computing the preview without case-folding → `Reports` shows no line → RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — a name at the cap; reserved and clashing names.

### LLR-175.2 — No parent field
- **Traceability:** HLR-175
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** `SaveProjectScreen` shall compose no `#project_parent_path` and no `#save_browse` (`screens.py:555`), and its payload's `parent_folder` shall be the app's work area.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-48 — `pytest tests/test_b100_save_dialog.py -k tc_b100_48`
- **Numeric pass threshold:** 0 widgets with either id; the payload's parent resolves to `self.workarea` (1 equality).
- **Negative control:** today's dialog (`screens.py:555`) → 1 Browse button → RED.
- **Boundary catalog:** ☒ boundary — a work area under a long base path.

### LLR-175.3 — Keys and the empty Save
- **Traceability:** HLR-175
- **Ledger:** none
- **Statement:** `SaveProjectScreen` shall bind `escape` to dismiss with `None`; a Save with an empty name shall paint a reason line and stay open; each button's label shall show its direct key.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-49 — `pytest tests/test_b100_save_dialog.py -k tc_b100_49`
- **Numeric pass threshold:** `escape` → 1 dismiss with `None`, 0 folders; an empty Save → 1 reason line, 0 dismisses; every button → 1 direct key shown.
- **Negative control:** executed on `1d677ba` (P-18, P-19) → RED.
- **Boundary catalog:** ☒ empty — an empty and an all-space name.

### LLR-176.1 — The busy seam
- **Traceability:** HLR-176
- **Ledger:** none
- **Statement:** `begin_busy(label)`, `step_busy(text, value=None)` and `end_busy(outcome)` (NEW, `app.py`) shall widen `set_progress` (`app.py:13615`); one `set_interval` timer on the main thread shall drive the elapsed time; worker calls shall go through `call_from_thread`; `end_busy` shall run on every exit of the action, an exception included.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-50 — `pytest tests/test_b100_busy.py -k tc_b100_50`
- **Numeric pass threshold:** begin → 1 indicator shown; end → 0 shown; a 1.2 s worker → the elapsed text changes ≥ 1 time; a raising action → 0 indicators left.
- **Negative control:** a mutation dropping `end_busy` on the exception path → 1 indicator left → RED.
- **Boundary catalog:** ☒ boundary ☒ error — an action shorter than a tick; an exception.

### LLR-176.2 — Every progress caller goes through the seam (C-31)
- **Traceability:** HLR-176
- **Ledger:** none
- **Statement:** Every function of `app.py` that calls `set_progress`, directly or through `call_from_thread`, at `1d677ba` (P-29: 24 calls in 12 functions) shall open and close its action through the seam.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-51 — `pytest tests/test_b100_busy.py -k tc_b100_51` (an AST census over `app.py`)
- **Numeric pass threshold:** the census derives the action set from the code (≥ 12 functions, P-29) → each has 1 begin and 1 end on every path.
- **Negative control:** a mutation removing one begin → the census names that function → RED.
- **Boundary catalog:** none — the census has no input classes; its set is derived from the code.

### LLR-176.3 — Main-thread actions paint before they work
- **Traceability:** HLR-176
- **Ledger:** none
- **Statement:** For an action that runs on the main thread, `begin_busy` shall paint once before the work starts, through the `call_after_refresh` idiom (`app.py:8708`).
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-52 — `pytest tests/test_b100_busy.py -k tc_b100_52`
- **Numeric pass threshold:** a main-thread Save project → the indicator painted ≥ 1 frame before the first copy.
- **Negative control:** a mutation starting the work before the refresh → 0 painted frames → RED.
- **Boundary catalog:** ☒ boundary — a save of a 1-byte image.

### LLR-177.1 — Three actions on workers, installs on the main thread
- **Traceability:** HLR-177
- **Ledger:** LED-2026-10-26-batch-100.1
- **Statement:** Project load, Save project and the A2L parse shall run under `@work(thread=True)`; every write of `current_file`, `current_a2l_path`, `current_a2l_data`, the variant set and the change service shall run on the main thread through `call_from_thread`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a 1.5 s slowed project load → the elapsed text changes ≥ 1 time before the end; a thread-id probe on the listed writes → 0 off-main writes.
- **Negative control:** today's synchronous load (`app.py:8510`) → 0 changes → RED.
- **Boundary catalog:** ☒ boundary — a load inside one tick.

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
- **Ledger:** none
- **Statement:** `compose_load_announcement` (NEW, a pure function; its module is named at PDR) shall return the opened variant, the variant count, the reason — one of: recorded active; first by name, none recorded; first by name, manifest unreadable; next valid, the recorded one missing or unreadable — and the problem list.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-55 — `pytest tests/test_b100_announce.py -k tc_b100_55`
- **Numeric pass threshold:** 4 reason cases → 4 of 4 reasons; 2 variants → count 2; 3 problems → 3 entries in order.
- **Negative control:** a mutation reporting "recorded active" for the fallback case → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — 1 variant; no openable image.

### LLR-178.2 — The status log carries the announcement, literally
- **Traceability:** HLR-178
- **Ledger:** none
- **Statement:** `_handle_load_project` shall write the announcement to the status log through `set_status`, and every painter of it shall render file and variant names with markup off.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-56 — `pytest tests/test_b100_announce.py -k tc_b100_56`
- **Numeric pass threshold:** a 2-variant load → 1 status log line naming the opened variant and the count 2; a variant named `[b]x[/b]` → 0 spans in every painter.
- **Negative control:** a mutation painting with markup on → 1 span → RED.
- **Boundary catalog:** ☒ invalid — a hostile variant name.

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
      in    : the path copy_into_workarea returned
      out   : the status line
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
  SINK   : _handle_save_dialog
```

```
FLOW: unsaved_work_to_question
  SOURCE : a load request while the session holds unsaved work or an open project
  NODES  :
    - fn    : the trigger table (app.py load guard)
      owner : LLR-174.1
      in    : image differs, flow dirty, project open, load kind
      out   : ask or load
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

- **Part B — boundary decomposition:** yes — the TUI has addressable dialogs and status widgets. The two modal dialogs are top-level screens pushed on the app, so their parent is `SYSTEM`. The status log and the progress bar sit in `workspace_shell`, which no contract declares, so V12 reports their balancing as not checked, as in batch-99. Consumers were measured with `grep -rl <id> --include=*.py --include=*.tcss s19_app tests` at `1d677ba`. The addresses of the REFINE surfaces are today's; a verdict that renames one amends its block through a ledger entry (VS-PA-3, VS-PC-3, VS-PD-1).

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

---

## 5. Validation strategy

### 5.1 Methods

- **Layer A — white-box / functional:** TC-B100-01 through TC-B100-56 (`test (unit)` / `test (integration)`), each named in its LLR, plus the re-pinned nodes TC-018, AT-031b and `test_tc_b99_31_changed_bytes_take_the_next_free_name` (LLR-163.3, LLR-163.4). Each declared mutation runs at Phase 3 (C-40). The AST censuses derive their sets from the code (C-31: TC-B100-07, -09, -37, -51).
- **Layer B — black-box acceptance:** AT-B100-01 through AT-B100-19, one node each, marked `at_b100_NN`, in the `tests/test_b100_*.py` file of their story. Each drives the shipped surface (§3 preface) and observes files on disk, painted text or the screen stack.
- **Oracles:** image bytes through `tests/support/independent_reader.py`; digests through `hashlib` in the test; never through the app's own loader.
- **Environment:** every run in a worktree sets `PYTHONPATH=<worktree>` and probes `s19_app.__file__` first (the `pip -e` trap); `NO_COLOR` unset.
- **Regression:** the full suite once per increment, against a baseline captured at `1d677ba` before Inc 1; the whole-tree guards (import census, snapshot cells, id registry) and `devflow-validate --brief` at every increment gate.

| AT | Story | Inc | Output-then-consume (C-12) | Slot it waits for |
|---|---|---|---|---|
| AT-B100-01 | US-153 | 1 | — | — |
| AT-B100-02 | US-154 | 2 | — | VS-PC-3 (dialog ids) |
| AT-B100-03 | US-155 | 3 | Save project → project folder | — |
| AT-B100-04 | US-156 | 4 | — | VS-PA-4 (which dialog `p` opens) |
| AT-B100-05 | US-157 | 5 | Save project → `P1/firmware.s19` → Load project | — |
| AT-B100-06 | US-158 | 6 | save-back → `project.json` → Load project | — |
| AT-B100-07 | US-159 | 7 | Save project → `files` → Load project | — |
| AT-B100-08 | US-160 | 8a | Save project → `active_document` → Load project | — |
| AT-B100-09 | US-161 | 8b | save-as → Q folder → flow list | — |
| AT-B100-10 | US-161 | 8b | A2L-only Save → Load project | — |
| AT-B100-11 | US-161 | 8b | Save project → Load project list | — |
| AT-B100-12 | US-162 | 9a | Load file → `recent_sources.json` | — |
| AT-B100-13 | US-162 | 9a | — | — |
| AT-B100-14 | US-163 | 9b | Load file → store → Load dialog | VS-PA-1 to VS-PA-5 |
| AT-B100-15 | US-164 | 10 | — | VS-PB-1 to VS-PB-3 |
| AT-B100-16 | US-165 | 11 | — | VS-PC-1 to VS-PC-3 |
| AT-B100-17 | US-166 | 12a | — | VS-PD-1, VS-PD-2 |
| AT-B100-18 | US-167 | 12b | — | VS-PD-3 |
| AT-B100-19 | US-168 | 6, 7 | save-back → `project.json` → Load project | VS-PE-1 to VS-PE-3 |

### 5.2 Batch acceptance criteria
- 100 % of LLRs covered by at least one passing TC; every declared mutation goes RED.
- Every story has at least one passing AT-B100 observing its outcome through the shipped surface, with its boundary and negative evidence.
- Every §2.7 premise probe that served as a RED side is re-run at Phase 4 on the closing tree, and its decisive line has flipped: `p01` → `== in-memory patched image? True`; `p03` → no `LEAK` line; `p02` A → `active=firmware_1`; `p04` 2/6/7 → one problem each; `p02` C → one `firmware_1`; S4 → a focused region area > 0.
- Every variant slot of HLR-173 through HLR-178 is filled by a ledger entry before its increment opens.
- 0 blocker findings open at Phase 4; the full suite with no new failure against the baseline.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
D1–D7 and O-1..O-11 are mapped to the requirements they shape in LED-2026-10-26-batch-100.1.
### 6.3 Open risks

**Security questions (trigger family C; the `devflow-scan-spec.py` verdict is recorded in LED-2026-10-26-batch-100.1):**
- **Input surface (C6).** Four untrusted inputs: the typed project name (HLR-164; sanitised, case-folded, capped), the typed load path (LLR-172.5; resolved and contained in the work area before any project route), `project.json` (LLR-169.4, LLR-170.1, LLR-168.1; every key through `_resolve_manifest_entry`, malformed records reported and skipped), and `recent_sources.json` (LLR-172.2; size-capped, parse-guarded, shape-checked). The save-as copy (LLR-171.1) skips links and reparse points and places every file through `copy_into_workarea`. The `security-reviewer` at P2 reviews the hostile sets.
- **Markup injection (C8).** File, folder, project and variant names from disk reach `Label`s, which parse markup by default (P-24). LLR-172.6, LLR-173.3, LLR-174.2, LLR-175.1 and LLR-178.2 render them with markup off; AT-B100-13 and AT-B100-14 carry hostile names.
- **Privacy.** `recent_sources.json` holds absolute local paths, as the log already does (`app.py:10820-10825`); it is bounded to 20 entries and never copied into a project or report (LLR-172.3).
- **"token", "session", "form"** mean a name token, a TUI editing session and a dialog form. **"escape"** is the keyboard key. **"expose"** is a method on a service API. **"permission"** is a file a test makes unreadable to exercise an error path. **"hash"** is the SHA-256 digest of a project file, used only to detect that the file changed on disk since the save. No credential, network or secret is involved.

**Open decisions and assumptions (each listed for the operator; none is decided here):**
- **Q-1 — the name cap's value.** M-7 asks for a cap, and no document fixes the number. `PROJECT_NAME_MAX_CHARS` is fixed at PDR.
- **Q-2 — O-9 against the multi-variant save.** Today a save into an existing project that is not open adds a variant (`app.py:8152-8156`, LLR-005.1). O-9 refuses it, so adding a variant then means opening the project and loading the file. The P2 reviewers confirm this, or the ruling is re-opened.
- **Q-3 — the PH-2 acceptance surface.** The commission asked for an AT that compares `vars(app)`. That comparison reads internal state, which the flow forbids in an AT. It is TC-B100-09 (LLR-165.2), and AT-B100-03 observes the leak through the surface.
- **Q-4 — HLRs derived from REFINE stories.** The flow derives HLRs from READY stories. HLR-173 through HLR-178 are derived now from their variant-independent clauses, as batch-99 did for US-143; their slots stay open until the verdicts.
- **Q-5 — the pasted document's file name** in `patches/` (D4). Assumed to be the Patch Editor's default name (`changes.json`, as `g005-tests.txt` shows), placed through `copy_into_workarea`; to be confirmed at PDR.
- **Q-6 — a second request while a worker action runs** (12b). No document sets the policy; slot VS-PD-3.
- **Q-7 — LLR-015.3's selector clause.** LLR-015.3 asks the "project save flow" to expose a width selector. Its TC-220 drives `ChangeService.save_patched` (P-23), the Save project dialog never had one, and O-5 adds none. The amendment of R-TUI-012 assumes that reading.

**Other risks:**
- `app.py` is in 14 of 15 increments: sequential merges, one worktree each (ARQ §9).
- Additive manifest keys: an older build re-saving a project drops `files` and `active_document`; the next Load shows the legacy notice (ARQ §3.2).
- The hash cost on the main thread until Inc 12b is estimated, not measured (ARQ §3.1).
- Reuse widening (Inc 1): every status that says "added" or "saved as" must stay true (LLR-163.5).
- Re-pinned tests (TC-018, AT-031b, `test_tc_b99_31_changed_bytes_take_the_next_free_name`) could hide a regression: each re-pin names the old value, the new value and this requirement in its increment's reverse census.

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
