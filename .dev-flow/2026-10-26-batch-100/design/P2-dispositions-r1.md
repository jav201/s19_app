# P2 round 1 — orchestrator dispositions and the prototype verdict (batch-100)

> **Inputs:**
> - The four independent reviews of `01-requirements.md` at `3060d66`: `P2-ux-r1.md` (2 HIGH · 14 MAJOR · 9 MINOR), `P2-security-r1.md` (0 · 9 · 7), `P2-qa-r1.md` (3 · 14 · 10) and `P2-architect-r1.md` (pending at the time of writing; added as §4 when it lands).
> - The operator's prototype-round verdict, `veredicto-load-projects.json` (exported 2026-10-26T14:26Z).
>
> **Rule.** Every finding is **accepted with the closure its reviewer proposed**, unless §2 rules otherwise. The P1 author applies this file as round 2 of `01-requirements.md`, records each change in a ledger entry, and every finding id leaves round 2 as closed, or open with a reason. These rulings were taken under the batch's standing authorization. None of them re-opens an operator decision. Where a ruling touches what the operator sees, it follows the operator's own verdict notes.

## 1. The prototype verdict fills the REFINE slots (operator, quoted)

| Surface | Verdict | Operator note (verbatim) | What it fills |
|---|---|---|---|
| P-A Load dialog | **C** (two panes, preview on the right) | "Me gusta la idea de los dos paneles, con el simbolo de cuál es el set que se va a usar como archivos activos en el proyecto para las vistas y funciones en la aplicación." | VS-PA-1 = two panes. VS-PA-5 = the preview, which **must mark with a symbol the active set**: the image variant, A2L and MAC that the views and functions will use once loaded. That set must be the one that is actually installed (AT oracle: the marked rows equal the installed paths). VS-PA-3/4: the ids and bindings of `pa_C`. Below a declared width the panes stack (UX-10). VS-PA-2 (D10): click selects and Enter loads, which is the default the round showed. |
| P-B confirm | **A** (short question, `y` replace / `n`·`esc` cancel) | "Pregunta corta, hace el trabajo y crea menos dependencias." | VS-PB-1 = the short question. VS-PB-2: **no "save first" key**; the operator chose the variant without it (also closes QA-17's add-behaviour concern). VS-PB-3: the ids of `pb_A`. |
| P-C Save project | **B** (name + "what will be saved" summary) | "…es importante saber que se está guardando en cuestión de proyecto. Se extra cuidadoso con la información que se despliega aquí. Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información." | VS-PC-1 = the summary. **Ruling R-PC (from the note):** the summary is rendered from the SAME save-plan object that the save executes. It is one function that computes the plan (target folder, each file with its source, image patched or not, document, sub-folders, manifest keys), and both the dialog and `_handle_save_dialog` consume it. New AT: for each of N scenarios (fresh, exact-name existing, save-as with sub-folders, pending patch, reserved/clash refused), the summary rows equal the files actually written, compared by path and digest. A row that would overwrite, rename or drop a file is painted as such, never omitted. VS-PC-2: during a clash, Save is refused with the reason painted, and the button stays focusable (no silent disable). |
| P-D progress | **A** (status line: spinner, step n/m, elapsed) | "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso." | VS-PD-1 = the status line. **Ruling R-PD (from the note and UX-02):** the indicator must reflect real progress. So Inc 12b (project load, Save project and the A2L parse moved to workers) becomes **unconditional**, and 12a + 12b land together. HLR-176 is scoped to actions that run on a worker. The step that cannot leave the main thread (the A2L tag-table build) is declared out of scope, with its freeze stated in the contract; it is not hidden. VS-PD-2: no cancel (variant A has none). VS-PD-3: a second request while a worker runs is refused, with the status naming the running action. |
| P-E Load project result | **B** (result panel to dismiss; `v` opens the variant selector) | (no note) | VS-PE-1 = the panel. VS-PE-3: `v` opens the existing variant selector, an existing action, not new behaviour. **HLR-166 / AT-04 (focus) are re-stated (QA-17):** while the panel is open it holds the focus. After it is dismissed (`esc`/`enter`), the focus lands on the visible window HLR-166 names. The panel lists every problem with no truncation (closes UX-08 / QA-08 for project loads: the status log carries only a one-line summary that points to the panel). The D2 announcement is a line in the panel naming the opened variant and "patched, N bytes differ" (UX-09). |

## 2. Orchestrator rulings on contested or design-level findings

| Finding(s) | Ruling |
|---|---|
| **UX-01** (HIGH) | "Unsaved" means **differs from the last saved or loaded copy**, not from the source. The app keeps a digest of the image as last written or loaded (save-back, Save project, load). The P-B question and P-C's pending line fire on that difference. Add cells: patched → saved → load = no question; patched → Save project → load = no question. |
| **UX-02** (HIGH), QA-16 | See R-PD above: 12b is unconditional. ATs that need a slow action get one black-box: a large fixture file (the `case_06` A2L, or a generated one in `tests/fixtures/`). Never a monkeypatch in the AT node. §3's preface bans private calls in AT nodes (batch-99 QC-AT). |
| **QA-01** (HIGH) | Replace `vars(app)` with an app-owned projection, `S19TuiApp._session_snapshot() -> dict`, which covers the ARQ §2.2 inventory (12 kinds). TC-B100-09 compares it through a normaliser (paths relative, counts instead of identities), cold load against load-over. Its negative control: drop one reset line, and the snapshot differs. |
| **QA-02** (HIGH), S-13 | Markup fixtures use only names that can exist on disk and that paint a span with markup on: unclosed open tags (`[bold]x.s19`, `[b]P`), `[@click=app.bell]x.s19` if it can exist (verify), plus an ESC / U+009B arm through `safe_text` (S-06). The negative control is real: markup on paints ≥1 span, and markup off with `safe_text` paints 0. |
| **QA-03** (HIGH) | The load guard (P-B) also fires on the **Patch Editor's dirty document flag** (batch-94), alongside the changed image (UX-01's definition) and a dirty Flow Builder. Name the real modal classes: the change-document question is `LoadGuardScreen` (`screens_directionb.py:4279`), and `ConfirmDiscardScreen` is the flow-discard modal. If several apply, ONE question lists them, with no stacked modals (UX-12). Initial focus is on `n` (the safe choice); `enter` = the focused button. |
| **UX-11** (P-B trigger) | It asks **only when something unsaved would be lost** (the three conditions above). An open project with nothing unsaved loads without a question. This follows the operator's "pregunta corta, hace el trabajo". |
| **QA-04**, Q-2 | Write Q-2 into the contract with its definitions:
- **"holds a project":** a direct child of THIS work area containing `project.json` or a data file, not a reserved home.
- **A clash:** the sanitised name equals an existing project folder **case-folded**, AND the typed name differs from it. That is refused, and the refusal names both.
- **The exact name of an existing project that is not open:** LLR-005.1 is kept (add files as a variant). The P-C summary shows each added and kept file (R-PC), and `project.json` is rewritten through the one writer (O-1). Sub-folders and the document are untouched.
- **Typing the open project's unsanitised name** (`a b` while `ab` is open): treated as a save into the open project, and shown so in the summary. |
| **QA-05** | Inc 1 adds `segment_split_view.py` (`_export_reuse_target` uses the same byte-identical rule as `copy_into_workarea`, through one shared function in `workspace.py`), giving 3 files. `copy_into_workarea` returns a result that tells reuse apart (`(path, reused: bool)` or a small dataclass). Every caller is listed, and the contract states the return change as an interface amendment. |
| **QA-06** | **Superseded by A-06 (§4).** Save project uses the SAME rule as save-back (B99-I7, `ChangeService.save_patched`): source + every entry the document holds now, verified. There is one rule for one fact. The view's `mem_map` is updated in place by that save, so after saving, what you see equals what was saved. The P-C summary (R-PC) states it: "image = source + N document entries (K of them added since the last apply, applied by this save)". O-6 stands: a blocked entry refuses the whole save and is named. Landing name in a folder that already holds the source's name: `<stem>_<N>` per M-1, it becomes `active_variant` (D2), and the summary shows the name before saving. |
| **QA-07, QA-08** | State a problem precedence: unreadable manifest > missing file > unreadable image > digest differs > no digests recorded. Each file reports ONE problem, its highest. The counts in AT-06/07/19 follow from that. The full list lives in the P-E panel (§1); the status log gets one summary line with a stated order. |
| **QA-10, QA-11, QA-12, QA-13** | Accept the reviewers' closures:
- **QA-10:** AT-11 is rebuilt on a RED path that exists after D7, for example a project saved under another work area by hand is not listed.
- **QA-11:** 80 of 80 written, each with its own content.
- **QA-12:** the cap arm uses an entry count that fits within 64 KiB (≈1 900), plus a separate oversize arm that must report "too large", not "empty".
- **QA-13:** a census of begin/end pairs per ACTION (a key), not per function. |
| **QA-14, QA-15** | Add a reverse census (B1) with the real count of 35 test sources and a per-file disposition: `test_b99_staging.py` (6 nodes on `#project_parent_path`, removed by D7: re-pin or retire, with a ledger entry), `test_tui_directionb.py:3090`, `test_tui_patch_variant.py` (direct `_handle_load_project` with a project open: where the guard sits), `test_tui_app.py:1254/1288`, `test_tui_variants.py:274`, the 5 `progress_bar` files, and the 29 snapshot cells (named for Inc 12a/9b/11 regeneration). The AT index states which ATs are written at which increment and how they survive Inc 9b/10/11 id changes: ATs drive through the ids of `pa_C`/`pb_A`/`pc_B`, now fixed by the verdict. |
| **S-01..S-09** | Accept the security closures. The largest is **S-02**: every containment check new or touched in this batch resolves real paths and requires the target to be inside **this** app's work area (`self.workarea.resolve()`), not any `.s19tool/workarea`. Junctions and symlinks are resolved before the check, and a project folder that is itself a link is refused. That makes it an LLR with an executed junction arm. The rest:
- **S-03:** save-as walks without following directory links, and a link inside a sub-folder is skipped and listed.
- **S-04:** Windows device names are refused case-folded, with or without an extension or a superscript digit.
- **S-05:** every `OSError` after `mkdir` is caught, and the partial folder is removed (exceptions census, not returns).
- **S-06:** names render through `safe_text`.
- **S-07:** the recent store refuses UNC, `\\?\`, device and drive-relative paths, and a preview never touches a network path.
- **S-08:** caps of 1 MiB on manifest bytes and 1 000 `files` records; the reader refuses above them with a problem line.
- **S-09:** the path check refuses drive-relative `C:x`, in a shared helper with its own TC (it touches other manifest keys too; list them). |
| **UX-03..UX-16 (MAJOR)** | Accept, with these specifics:
- **UX-03:** the focus target is named per window, and a text Input never gets the focus after a load.
- **UX-05:** a new slot VS-PA-6, filled now: typed text wins when the path field has focus, and the highlighted row wins when the list has focus. Tab order is path → list → preview → buttons.
- **UX-06:** an invalid typed path is explained inside the dialog, which stays open.
- **UX-07:** every refusal names the reason AND the next step, with a fixed token an AT can match.
- **UX-10:** the width rule goes into each UI HLR. ATs run at 118×54 and 220×60 with notifications on.
- **UX-13:** keys are verified by pressing them. Alt+letter applies in modals with a text field.
- **UX-14:** a Load file into an open project makes the file the active variant only with the P-E-style announcement line.
- **UX-15:** slot outcomes are stated.
- **UX-16:** a Phase-4 expert inspection of the P-E panel and the P-C summary in a real terminal is declared in §5.1. |
| **All MINOR** | Accept the proposed closures. Q-1 (64) and Q-5 (`patches/changes.json`) are written into the contract (QA-18, QA-19, S-14). PLAN is corrected by the orchestrator (QA-20). |

## 3. Increment table changes that follow

- **Inc 1:** `workspace.py`, `segment_split_view.py` (+ `app.py`). 3 files.
- **Inc 12a + 12b:** land as one unit, in order. 12b is unconditional (R-PD).
- **Inc 10 (P-B A):** no "save first". The trigger is the unsaved-state digest (UX-01), so Inc 10 depends on Inc 5, which introduces the last-saved digest.
- **Inc 11 (P-C B):** the shared save-plan function (R-PC) is introduced in **Inc 5**, with the dialog consuming it in Inc 11. The ARQ file list for Inc 5 is re-checked against the cap.
- **P-E B panel:** shown by Inc 6 and Inc 7 (no longer gated).

## 4. Architect findings

`P2-architect-r1.md`: 1 HIGH · 8 MAJOR · 9 MINOR. These are new findings only; the reviewer skipped what §2 already rules. Accepted with the reviewer's closure, except where a ruling below says otherwise.

| Finding | Ruling |
|---|---|
| **A-01** (HIGH) | **Restore the "present, not recorded" problem kind** (a data file in the project folder that `project.json` does not list). It sits below "digest differs" in the QA-07 precedence. Three writers put images in the project without the manifest writer: flow WRITE-OUT `flow_execution_service.py:679`, the external-step copy `:1108`, and variant execution `variant_execution_service.py:797`. Routing them through the manifest writer is out of this batch's file budget, so it goes to `BACKLOG-CODE.md`, citing A-01. |
| **A-02** | Every O-1 rewrite carries `active_document`, plus every other key it does not own. The carry list is "all keys except the ones this writer changes". |
| **A-03** | Add an output-then-consume AT. For each O-1 sync writer (variant append, MAC, A2L), the rewritten `project.json` is read back by the reader and reloads. Paths stay project-relative; the carry converts the reader's absolute paths back. |
| **A-04** | The code is `MANIFEST-PATH-ESCAPE` (executed). |
| **A-05** | The "unreadable image" kind comes from the load result in `_handle_load_project`, not from `check_project_files`. That adds no new import edge and no second parse. |
| **A-06** | **Accepted; it reverses the QA-06 ruling** (see the QA-06 row). Save project uses `save_patched`, so there is no B99-I7 amendment. Re-count Inc 5's files. |
| **A-07** | The compared set is derived from the live app: the attributes `S19TuiApp`'s own source assigns, read by a census at test time, minus a declared exclusion list of Textual internals, each with its reason. The normaliser turns paths into relative ones and objects into counts or keys. The probe's 11 extra names (`_mac_view_cache_*` ×7, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address`, `_a2l_row_key_to_tag`) are either reset by the seam or listed with a reason. The negative control is unchanged. |
| **A-08** | There are two separate predicates, each named in the contract. `differs_from_last_saved()` decides the P-B question and the P-C pending line. `differs_from_source()` decides emit (`save_patched`) vs byte copy. A cell covers it: save-back → Save project emits (never copies the unpatched source). |
| **A-09** | An exact-name save into an existing project that is not open **merges**. It keeps the target's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` and other variants, appends the new variant, and leaves `active_variant` per D2. `test_tui_variants.py::test_save_second_s19_into_project_appends_variant` stays green, and it is named in the reverse census as kept. |
| **A-10** | Q-1's 64 stays. Also check the full path against `_MAX_FULL_PATH` the way split/join does, refusing with the path length named. |
| **A-11, A-12** | Q-7 is recorded as a ledger amendment of LLR-015.3. The pasted document is written by the app (Q-5) through the M-1 rule. |
| **A-13..A-18 (MINOR)** | Accept the proposed closures. |

