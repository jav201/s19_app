# Executive summary — s19_app — Batch 2026-10-26-batch-100

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `core` · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 Bottom line (read first)

- **What we delivered:** the Load + projects batch. One Load dialog offers everything that can be loaded and opens projects; a project restores exactly what was saved or names what it could not; nothing the user has not saved is replaced without a question; and long actions show that they are working. Sixteen user stories (US-153…US-168) shipped in 16 increment packets (Increments 1–7, 8a, 8b, 9a, 9b, 10, 11, 12a, 12b, and the 3b hotfix).
- **Business outcome:** the project round-trip is now honest. Save project writes the image the engineer actually sees (source plus every patch entry), a save-back becomes the project's active variant so Load reopens where the engineer stopped, and Load names every problem instead of silently differing from what was saved. The four project round-trip defects the investigation found still open (PH-1, PH-2, PH-4, PH-5) and the project-management findings (M-1…M-7, L-2…L-4) are fixed on `main`.
- **What users will notice:** one Load dialog instead of three; a Save project dialog that shows, before Save, exactly what will be written, renamed, kept or refused; a progress spinner with elapsed time on project load, Save project and A2L parse; a question before a load would lose unsaved work; and a quit question while a long action runs.
- **Next step:** the final full-suite CI gate on `main` is still running; its result lands on the `Gate run` line of `04-validation.md`. After it returns, the operator closes the batch.

---

## Context (reference)

### Context

s19_app is the terminal tool (TUI, terminal user interface) a calibration engineer uses to prepare and review software changes for ECUs (engine control units). It reads and writes memory images (S19 and Intel HEX), tracks A2L calibration tags and MAC records, and organises that work into projects on disk. Batch-99 fixed how the tool reads and writes files. This batch fixes how the engineer *loads* and *saves projects*: the Load dialog, the project round-trip, save naming, and the progress feedback for long actions. It started on 2026-10-26 and reached its close on 2026-11-01 (`PLAN.md` §Header, §Where we are).

### Problem

The engineer could not trust the project they saved:

- **Save project saved the wrong image.** A pending patch was dropped and the original was saved, with a success message (PH-1). A save-back then reopened the *unpatched* original on the next Load (PH-4).
- **Projects bled into each other.** Loading project P2 over P1 kept P1's A2L, MAC and change entries, which then leaked into P2's next save (PH-2).
- **Load reported success over a broken project.** A damaged or absent manifest, a missing or unreadable image, or an image edited on disk all loaded as "ok" with no warning (PH-5).
- **No single way to load.** There were separate Load file and Load project dialogs, no list of what could be loaded, no recent sources, no typed project path, and no confirmation before a load discarded unsaved work (CW-U-5, CW-U-12, CW-U-13, L-2).
- **Long actions looked frozen.** Project load, Save project and the A2L parse ran on the main thread with no progress, and the app answered to nothing while they ran (N5).
- **Save-name traps.** Reserved names, Windows device names, over-long names and disguised clashes were accepted or crashed the app; identical re-loads filled the project with `_<N>` copies (M-4, M-7, M-1).

### Solution

What shipped, in plain terms (16 stories, US-153…US-168):

- **One Load dialog.** A single dialog lists projects, work-area files and recent sources with a preview that marks what a load installs; `l`/`ctrl+l` open on the path field, `p` on the list, Enter loads, `esc` closes and changes nothing (US-163).
- **A project restores exactly what was saved.** Save project writes the source plus every change-document entry, verified, and says what it saved. A save-back becomes the project's active variant. Load opens what is valid and lists every problem — a damaged or absent manifest, a missing, unreadable or changed-on-disk file, a file nobody recorded — with a next step for each (US-157, US-158, US-159, US-168).
- **A clean start on every project load.** A project load starts from an empty session, so no A2L, MAC or change entry of the previous project leaks in (US-155).
- **The change document comes back.** The document the engineer was editing is saved with the project and reopened on Load (US-160).
- **"Save as" copies the whole project, and A2L-only projects open.** Every sub-folder is copied, skipped links are named, and every project lives inside this work area (US-161).
- **Recent sources and typed paths.** Recent sources are remembered per user; a project path typed into Load opens the project; names render literally (US-162).
- **One question before unsaved work is lost.** A short, two-button question asks before a load would lose a patch, unsaved Patch Editor entries or unsaved Flow Builder edits (US-164).
- **The Save project dialog shows the plan.** Before Save, it paints exactly what will be saved, where, and anything that will be renamed, kept or refused, and it closes on `esc` (US-165).
- **Progress and honesty for long actions.** Long actions show a spinner, step and elapsed time with a progress bar that really moves; project load, Save project and the A2L parse run on worker threads; a second request is refused while one runs; and quit asks first (US-166, US-167).

### Outcomes / results

The status of each claim is in brackets.

- **Requirements verified [executed per packet, fixed at the batch-end battery].** The contract holds 16 user stories, 42 high-level requirements (HLR-163…HLR-178), 349 live low-level requirements (two retired: LLR-171.2e, LLR-171.4d), 73 white-box test cases (TC-B100-01…73) and 21 acceptance tests (AT-B100-01…21). Every requirement resolves to a test node on the current tree; no requirement is without a test (see `traceability-matrix.md` §2).
- **Batch-end battery [executed, local].** The batch-end battery ran locally in 4 shards on `9e4dd3b`. Its failures and the Linux-CI failures were fixed in two fix rounds (`fix-round-1.md`, `fix-round-2.md`), each with executed transcripts: fix round 1 covers the Linux-only CI failures CI9b-3/CI9b-4/CI11-1…4; fix round 2 covers the battery's real failures (R-1…R-3, A12-51) and two product guards (SE5-12b-2, OBS-12b-2).
- **Full-suite gate [executed, Linux].** The whole suite ran once on the final code (`f72eef1`) on a Linux machine: 5,027 tests passed and 18 failed; the 18 are 5 old failures that predate this batch and 13 timing tests that only fail when 8 run at once, 12 of which pass when run one at a time and the last on its own, so the validation verdict is PASS-WITH-NOTES.
- **No product defect known open at HIGH.** The two fix rounds fixed two product defects found by the battery (CI11-1 on the document rebind, SE5-12b-2 on the two project-sync helpers) and one cosmetic product item (OBS-12b-2). One product slowdown is routed, not fixed: Save project at the TC-B100-20 composition sits at its 1-second bound since Inc 12b (R1-P1).
- **Visible changes [as shipped].** One Load dialog replaces the old Load file / Load project dialogs. Save project now saves the patched image and says so; the Save project dialog paints the plan; the Load-result panel names the opened variant and every problem; a progress line shows on long actions.

### Next steps

The sources do not record target dates.

1. **GitHub's CI run on the final code (41372953464) confirms after the close.** The operator closed the batch on the Linux gate; anything that run finds is fixed after the close (a recorded deferral in `04-validation.md`, not a pass).
2. **Close this batch (now, operator).** Approve the `06-docs/` documents, then commit, push and run `/dev-flow-sync`.
3. **Route the open items.** `fix-round-2.md` §Open and `BACKLOG-CODE.md` hold the open rows from this batch: R1-P1 (profile the Save-project worker step), SR12b-7 (re-pin the 30 bare-`pilot.pause()` wait helpers), the Inc 11 O-1 design ruling, the deleted-project-folder re-create observation (OBS-F2-1), and the Linux-only posix arms confirmed only by the next CI run.
