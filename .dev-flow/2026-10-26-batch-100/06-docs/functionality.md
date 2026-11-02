# Functionality — s19_app — Batch 2026-10-26-batch-100

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (engineers and leads who use or maintain the tool). Purpose: understand what the tool now does differently, and what users will notice.

> **Owed in.** `core` · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 At a glance (read first)

- **What this batch added:** the Load + projects batch. One Load dialog replaces the three load surfaces; a project restores exactly what was saved or names what it could not; nothing the user has not saved is replaced without a question; and long actions show progress and answer to the keyboard. It closes the project round-trip findings still open from the 2026-10-23 investigation (PH-1, PH-2, PH-4, PH-5), the project-management findings M-1…M-7 and L-2…L-4, the Load-dialog requests (work-area picker, recent sources, Load opens projects, Enter-to-load), the G-005 save-naming decision, the Code-Wire UI items CW-U-2, CW-U-5, CW-U-12, CW-U-13, and the progress indicator (N5 reopened).
- **Capabilities:**
  - One Load dialog: projects, work-area files and recent sources in one list, a preview that marks what a load installs, Enter loads, `esc` closes.
  - Save project writes the in-memory image (source plus every document entry), verified, and says what it saved.
  - A save-back becomes the project's active variant; Load reopens where the engineer stopped and a result panel says which variant opened and why.
  - Load opens what is valid and lists every problem, with a reason and a next step for each.
  - A project load starts from an empty session — no A2L, MAC or change entry leaks across projects.
  - Save-as copies the whole project; A2L-only projects open; every project lives inside this work area.
  - Recent sources are remembered per user; a typed project path opens the project; names render literally.
  - One question before a load would lose unsaved work.
  - A progress spinner, step and elapsed time on long actions; the heavy work runs on worker threads; a second request is refused while one runs; quit asks first.
- **How to use it:** the same TUI (`S19TuiApp`) and the same keys. `l` / `ctrl+l` open the Load dialog on the path field, `p` on the list; `s` (Save project) opens the plan dialog; the Patch Editor, Flow Builder and A2L window `2` are unchanged. See *Detail* below for what each surface now does.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

> Behaviour below is stated as the contract (`01-requirements.md`) states it. Each area names its story (`US-`), its requirements (`HLR-` / `LLR-`) and the increment that shipped it. The full per-requirement trace is `traceability-matrix.md`.

### The Load dialog (US-163 · HLR-173 … HLR-173e · Inc 9b)

One dialog replaces the old Load file and Load project dialogs. `l` and `ctrl+l` open it with the focus on the path field (`#load_path`); `p` opens it with the focus on the list. The list holds three sections in order — projects, work-area files, recent sources — and a right-hand preview marks the set a load installs (the `●` marks equal the files `choose_install_set` installs, HLR-173a). Enter loads what has the focus: a highlighted row loads the on-disk name, a typed path takes the typed-path route (HLR-173c). `esc` closes the dialog and changes nothing (HLR-173e). An empty or refused Load is explained inside the dialog (`#load_reason`, HLR-173d). Names from disk, the store and the preview render literally — no markup — through `safe_text` (LLR-173.3…173.3d, LLR-172.6). A click selects and never loads (LLR-173.2j); a printable key in the list types into the path field (LLR-173.2d); the app's priority keys are inert while the dialog is open (LLR-173.2e).

- **Projects section** is `list_projects`; a folder that is not a project is not listed, and an unreadable project list says so in the section (LLR-173.4a, LLR-173.4m).
- **Files section** is the one work-area lister, filtered to loadable files (LLR-173.4b, LLR-172.4f); a file link or a temp file whose name ends in a dot or space is not listed (LLR-172.4b, LLR-172.4d).
- **Recents section** is the store read (`read_recent_sources`); a store problem is painted in the section, a highlighted recent previews the store's facts only, and no filesystem call touches a recent before it is loaded (LLR-173.4g…173.4j, LLR-173.4k).
- **Typed paths** (HLR-172a · Inc 9a) route through `_route_load_project` / `_load_path_from_user_input`: an absolute project folder or `project.json` path opens the project; the six typed refusals (not found, unsupported file or relative folder, not a project, outside the work area, through a link or junction, unreadable) are explained in `#load_reason` (LLR-172.5…172.5k, LLR-173.5…173.5e).

### Projects: open, save, restore

**Save project writes the patched image (US-157 · HLR-167 · Inc 5).** The emit decision is made on data: Save project re-derives the change document onto a copy and emits only if that data differs from the source's; otherwise it copies the source byte-for-byte (LLR-167.1, LLR-167.2). The status names the entries the image carries (LLR-167.3), a blocked re-derive refuses the whole save (LLR-167.4), and Save project clears the Patch Editor's dirty flag (LLR-167.8). The save goes through `save_patched` split into re-derive then emit-and-verify (LLR-167.7).

**A load starts from an empty session (US-155 · HLR-165 · Inc 3).** One reset seam, `_reset_project_session`, runs before the first install; the session snapshot is derived from the live app; the change service is rebound; and unload clears the parsed A2L (LLR-165.1…165.4). No A2L, MAC or change entry of the previous project leaks into the new one.

**Save-back becomes the active variant (US-158 · HLR-168 · Inc 6).** A patched image saved into the project becomes the project's `active_variant`; every in-project writer rewrites the manifest carrying every key it does not own, and `derived_from` records what a patched variant derives from (LLR-168.1…168.4). Load therefore reopens where the engineer stopped.

**Load opens what is valid and lists every problem (US-159 · HLR-169 · Inc 7).** The `files` envelope holds per-file digests; Load verifies them, treats `project.json` as untrusted (size- and entry-capped, a manifest-keys mode that refuses drive-relative, stream and device names), opens the valid files, and writes one summary line (LLR-169.1…169.9). Problems — damaged manifest, no manifest, missing, not readable, changed on disk, not recorded, no digests saved — each carry a reason token and a next-step token.

**The result panel names the variant and why (US-168 · HLR-178 · Inc 6).** After a project load the Load-result panel names the variant it opened, how many variants the project holds, why that one opened, how it relates to its base ("patched, N bytes differ from …"), the MAC and A2L that loaded, and every problem — with no truncation, and never an exception class or internal code (LLR-178.1…178.3). `v` opens the variant selector.

**The change document comes back (US-160 · HLR-170 · Inc 8a).** The `active_document` key records the document; the app writes a pasted document and the gather places it; Load reopens the document after the A2L (LLR-170.1…170.3).

### Save-as, A2L-only projects, and the work area (US-161 · HLR-171 / HLR-171a / HLR-171b · Inc 8b)

- **Save-as copies the whole project** — every sub-folder to the same relative path, never descending into a directory link, skipping and naming each file link, refusing before any folder exists on a free-space, file-count, depth or unreadable-part limit, and leaving the open project unchanged (LLR-171.1…171.1o). After a save-as, the Flow panels use the new folder and a Patch Editor document is rebound to its copy, never through a `..` path (LLR-171.1l, LLR-171.1m).
- **An A2L-only project opens** (HLR-171a): it attaches its A2L, clears the previous data file, becomes the open project, and a data file loaded into it is recorded (LLR-171.2…171.2h). A project with neither a data file nor an A2L, and a folder with no `project.json` and no project file, are refused with their tokens (LLR-171.2d; LLR-171.2e is retired into LLR-173.4a).
- **Every project lives in this work area** (HLR-171b): Save refuses a parent other than this work area; containment is against the resolved root; links and junctions are neither listed nor loaded nor written; and the eight writers, the flow and the flowset write nothing outside this work area (LLR-171.3…171.4j).

### Save naming and reuse (US-153 · HLR-163 · Inc 1; US-154 · HLR-164 · Inc 2)

One placement function, `place_into_workarea` (`workspace.py`), holds every guard and decides reuse: a byte-identical, regular, non-link, non-empty candidate (`<name>` or `<stem>_<N><suffix>`) is reused; otherwise the lowest free `_<N>` is claimed. `copy_into_workarea` is now exactly `return place_into_workarea(...).path`, so all 15 call sites keep their `Path` return and every guard covers them by construction (LLR-163.1…163.7). Repeated loads of an identical file no longer accumulate `_<N>` copies, and the variant append and the Split/Join export say whether a file was reused (LLR-163.5, LLR-163.6).

Save project refuses unsafe names with their reason and next step — a disguised clash, a reserved work-area home, a Windows device name, a name over 64 characters or over the path limit, or a link/junction target — and every refused or failed save leaves the work area as it was (HLR-164, LLR-164.1…164.4). The G-005 decision (byte-identical reuse) re-pins the two baseline tests `test_tc018_…` and `test_at031b_…` (LLR-163.3, LLR-163.4).

### The Save project dialog (US-165 · HLR-175 … HLR-175f · Inc 11)

Save project opens one dialog with the name field, the summary and two buttons (Save / Cancel). The summary rows are the plan's rows: the image line says emit or copy, the pending line marks unsaved changes, skipped links get one row, a merge names the active variant it sets (LLR-175.4…175.4m). Save executes exactly the painted plan; a summary out of date at Save is shown again, not saved (LLR-175.4a, LLR-175.4b). The dialog has no parent field — its payload names this work area as the parent (LLR-175.2, LLR-175.2a). `esc` and Cancel close it and save nothing; an empty Save keeps it open and says why (LLR-175.3…175.3j). The 15 refusals (reserved, device, disguised clash, too long, too-long path, link, unreadable, empty, plan refusal, free space, missing source, unreadable source, blocked entries, unlistable work area) are painted in the dialog before Save (LLR-175.1…175.1p).

### Recent sources and literal names (US-162 · HLR-172 / HLR-172a / HLR-172b · Inc 9a)

Recent sources are remembered in a per-user local store (`%LOCALAPPDATA%\s19_app\recent_sources.json`), outside every work area. A source loaded from outside the work area is recorded first; a source already in the store keeps one entry; the store holds at most 20 entries; a load that fails before its copy records nothing; a source inside this work area is not recorded (LLR-172.1…172.1n). The store read returns the accepted entries in order, drops malformed, device, control-character, wrong-suffix or non-drive-rooted entries, and never raises (LLR-172.2…172.2k). Work-area file names and store paths render literally through `safe_text` (LLR-172.6, LLR-172.6a).

### The replace question (US-164 · HLR-174 … HLR-174d · Inc 10)

One modal with exactly two buttons (Replace / Cancel) asks before an image-replacing route would lose unsaved work — a patch not saved, unsaved Patch Editor entries, or unsaved Flow Builder edits. It asks exactly when the image is unsaved; an attach never asks; a project load asks when any of the three flags is set (LLR-174.1…174.1c). The focus starts on Cancel; `y` answers replace, `n` and `escape` answer cancel, `enter` acts on the focused button, a click answers with the clicked button, any other key leaves the question open, and the priority keys are inert under it (LLR-174.2…174.2t). The answer comes before the project-session reset; a cancelled load runs no reset; a confirmed load that is then refused keeps the work (LLR-174.3…174.3d). One load seam covers every image-replacing route, one question per load request (LLR-174.4…174.4c).

### The progress indicator and the busy model (US-166 · HLR-176 · Inc 12a; US-167 · HLR-177 · Inc 12b)

The begin paints the first progress line; one timer advances the line (spinner, step and `mm:ss` elapsed) while an action runs and stops when none runs; a step with an amount moves the bar within the step and out-of-range data is clamped; the end writes the outcome to the status log, hands the stored file state back, and clears the bar; an exception still ends the indicator (LLR-176.1…176.1t). Only the seam sets the bar, and the action table names the seven long actions; every action ends on every success and failure exit (LLR-176.2…176.2d). The `#status_text` line has one owner while a long action runs (HLR-176d).

Project load, Save project and the A2L parse do their heavy work on worker threads (HLR-177). The project load reads and parses on a worker and resets the session after the worker read, before the first install; Save project re-derives the image on the main thread before its worker and adopts it after the save commits; every A2L attach copies and parses on a worker; the session is written only on the main thread (LLR-177.1…177.1k). A worker that raises keeps the session (project load), rolls back and reports (Save project), or keeps the session (A2L attach) (LLR-177.2…177.2c).

**Busy refusal (HLR-177a · Inc 12b).** While a session action runs, a second load, variant switch, unload, Save project or Patch Editor change is refused — the busy line names the running action, the refusal changes nothing, and refusals stop when the action ends (LLR-177.3…177.3h).

**Quit question (HLR-177b / HLR-177c · Inc 12b).** Quit asks first while a session action runs: the question names the still-working action (`still working` + the action's label, `wait, or quit after it finishes`), the safe answer carries the emphasis, and a confirmed quit leaves no partial save (LLR-177.4…177.4e).

### A2L parse progress (LLR-176.4 · Inc 12b)

The A2L parser reports the bytes it has consumed through a callback, and the parse result does not depend on the callback (LLR-176.4, LLR-176.4a). `s19_app/tui/a2l.py` was unfrozen for this increment and re-frozen after it (LLR-176.4b). The progress bar rises as the parse consumes the file, so a large A2L (e.g. `examples/case_06_…/firmware.a2l`) shows real movement instead of a static line.

### Focus (US-156 · HLR-166 · Inc 4)

After a load, the focus lands on a named, visible, non-text widget so the single-key commands work. The load tails and the modal closes put the focus on the window's target, and the A2L load tail re-homes the focus (LLR-166.1, LLR-166.2).

### Operator rulings honoured (D1–D7 and the prototype round)

The operator chose the recommended option on all seven P0 decisions (`design/veredicto-b100.json`) and picked the prototype variants P-A C, P-B A, P-C B, P-D A, P-E B (`design/veredicto-load-projects.json`):

| Decision | Ruling | Effect |
|---|---|---|
| D1 | `imagen` | Save project saves the in-memory image (source plus the document), verified (HLR-167) |
| D2 | `ultima` | a save-back becomes the latest/active variant; the switch is announced (the Load-result panel, P-E) (HLR-168, HLR-178) |
| D3 | `abre_y_reporta` | Load opens what is valid and reports every problem (HLR-169) |
| D4 | `reabrir` | the change document is saved and reopened (HLR-170) |
| D5 | `copiar` | save-as copies the whole project (HLR-171) |
| D6 | `abrir` | an A2L-only project opens (HLR-171a) |
| D7 | `solo_workarea` | projects live only inside this work area (HLR-171b) |
| P-A | C | the Load dialog: two panes, with the mark showing the set that becomes active |
| P-B | A | one short question before unsaved work is lost |
| P-C | B | the Save project dialog shows exactly what will be saved, with care for the listed information |
| P-D | A | a spinner plus a bar that really moves |
| P-E | B | the Load-result panel |

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/app.py` | the Load-dialog router (`_handle_load_dialog`, `_route_load_project`, `_load_path_from_user_input`), `_reset_project_session`, Save-project handlers, the busy seam (`begin_busy` / `step_busy` / `end_busy`, `_refuse_if_busy`), the worker bodies, focus re-homing, the two project-sync guards |
| `s19_app/tui/screens.py` | `LoadDialog`, `SaveProjectScreen`, `ConfirmQuestionScreen`, `LoadResultScreen` and their styles |
| `s19_app/tui/workspace.py` | `place_into_workarea` / `find_identical` / `contained_in_workarea` / `predict_placement` (Inc 1); device-name predicate and `PROJECT_NAME_MAX_CHARS` (Inc 2); the recent-sources store (`read_recent_sources`, `record_recent_source`, `_recent_entry_ok`) and the work-area lister (Inc 9a) |
| `s19_app/tui/services/change_service.py` | `save_patched` split into re-derive and emit-and-verify; the unsaved predicate (Inc 5) |
| `s19_app/tui/services/variant_execution_service.py` | `active_variant`, `derived_from`, `choose_install_set`, the `files` envelope (Inc 6, Inc 7) |
| `s19_app/tui/services/manifest_writer.py` | the `files` / `active_document` / `derived_from` keys and the manifest-keys mode (Inc 7, Inc 8a) |
| `s19_app/tui/services/project_gather_service.py` | `gather_project_artifacts` (work-area root), `plan_project_save` (Inc 5, Inc 8b, Inc 11) |
| `s19_app/tui/screens_directionb.py` | the public dirty-flag reader (Inc 10); the A2L-only panel fixes (Inc 8b) |
| `s19_app/tui/a2l.py` | the parse-progress byte callback (unfrozen then re-frozen, Inc 12b) |
| `s19_app/tui/styles.tcss` | dialog, panel, busy-line and progress styles |

Source budget: every increment stayed at or under 4 SOURCE files; Inc 1, Inc 5, Inc 6, Inc 8a, Inc 10 and Inc 20 are at the cap (§5.5 of `01-requirements.md`).

### Usage / examples

```bash
# the batch's own verification surfaces (the packets' and fix rounds' commands)
pytest tests/test_b100_reuse.py          # HLR-163 (byte-identical reuse)
pytest tests/test_b100_save_guards.py    # HLR-164 (Save refusals)
pytest tests/test_b100_session_reset.py  # HLR-165 (empty session)
pytest tests/test_b100_focus.py          # HLR-166 (focus)
pytest tests/test_b100_save_image.py     # HLR-167 (Save project saves the image)
pytest tests/test_b100_active_variant.py # HLR-168 (active variant)
pytest tests/test_b100_project_check.py  # HLR-169 (Load lists problems)
pytest tests/test_b100_document.py       # HLR-170 (change document)
pytest tests/test_b100_project_homes.py  # HLR-171/171a/171b (save-as, A2L-only, work area)
pytest tests/test_b100_recents.py        # HLR-172/172a/172b (recents, typed path, literal names)
pytest tests/test_b100_load_dialog.py    # HLR-173 (Load dialog)
pytest tests/test_b100_load_question.py  # HLR-174 (replace question)
pytest tests/test_b100_save_dialog.py    # HLR-175 (Save dialog)
pytest tests/test_b100_busy.py           # HLR-176 (progress)
pytest tests/test_b100_workers.py        # HLR-177 (workers)
pytest tests/test_b100_announce.py       # HLR-178 (result panel)
pytest tests/test_b100_a2l_progress.py   # LLR-176.4 (A2L parse progress)
```

These are the commands the packets and the fix rounds record. This document did not re-run them. Run them from the repository root in the project environment with `PYTHONPATH=<worktree>` and `NO_COLOR` unset (the pilot tests read painted text).

### Risks / limitations (from the record)

- **No evaluation with real users.** The automated pilot proves the text is painted, not that an engineer reads it correctly (one operator; §5.1 of the contract).
- **Save project sits at its 1 s bound at the TC-B100-20 composition** since Inc 12b (base 0.71–0.79 s → 0.75–1.0 s). The arm passes alone after the re-pin but may flake under load; routed as R1-P1 (profile the worker step).
- **The Linux-only posix arms** (CI9b-3, CI11-3, CI11-1) are confirmed only by the next CI run; the fix rounds proved them by code-read, posix probes and forced arms on Windows (`fix-round-1.md` §Pending).
- **An older build re-saving a project drops the additive manifest keys** (`files`, `active_document`, `derived_from`); the next Load shows `no digests saved` and no "patched" line (ARQ §3.2).
- **Three writers still bypass the manifest writer** (A-01); their files show as `not recorded` until the backlog item lands.
- **Re-pinned tests could hide a regression**; each re-pin names the old value, the new value and the requirement that changes it (§5.4).
- **Open backlog rows from this batch** (`BACKLOG-CODE.md`): R1-P1, SR12b-7 (the 30 bare-`pilot.pause()` wait helpers), Inc 11 O-1 (design ruling owed), OBS-F2-1 (deleted-project-folder re-create), and the LOW findings listed under the batch-100 routing section.

### Diagrams

- `06-docs/diagrams/load-dialog-routes.md`: the Load dialog's routes (file / project / recent / work-area pick → worker → install on the main thread).
- `06-docs/diagrams/project-lifecycle.md`: open → edit → Save project → manifest → restore, with the refusal paths.
- `06-docs/diagrams/busy-model.md`: begin → step → end/fail, busy refusal, and the quit question.

### Record discrepancies

> Where a packet and the contract disagree, this document follows the contract. The disagreements found while writing it:

1. **Increment numbering.** The packet headers number the last two packets `012` (increment-021) and `013` (increment-022); the plan roadmap and this document name them `12a` (the progress indicator) and `12b` (the workers). The same packets, the same content — only the label differs.
2. **US-168's increment.** The §2.6 user-story table carries `P-E` in the increment column for US-168 rather than an `Inc N`. Its shipped increment is Inc 6: the increment-006 packet names `HLR-178` · `US-168`. The matrix follows the packet.
3. **LLR-171.2e.** The increment-018 header writes "`LLR-171.2e` (retired)"; the contract block carries `Status: retired — superseded by LLR-173.4a (Inc 9b, Q7)`. The two agree; it is listed retired in `traceability-matrix.md` §1c.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] Audience and purpose declared at the top of the doc. — ✓ header: technical stakeholder; understand the changes and what users will notice.
- [x] Structure follows the relevant template (or a justified deviation is noted). — ✓ `templates/functionality-template.md` sections kept; added the per-area detail and the rulings table, as batch-99 did.
- [x] Code/CLI snippets actually run (or marked "untested"). — ✓ the commands are the packets' and fix rounds' own; marked above as not re-run by this document.
- [x] Assumptions listed. — ✓ behaviour is stated per the contract; increment attribution from the packet headers and §5.3.
- [x] Risks / limitations called out. — ✓ "Risks / limitations (from the record)".
- [x] Next steps stated. — ✓ `executive-summary.md` (presentation-builder) and `fix-round-2.md` §Open.
- [x] Diagrams included where flow is non-trivial. — ✓ three Mermaid diagrams under `06-docs/diagrams/`.
- [x] No invented APIs / version numbers / metrics. — ✓ function names were grepped from `s19_app/`; counts came from a script over `01-requirements.md`; no number was estimated.
