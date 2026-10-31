# Requirements ledger — s19_app — Batch 2026-10-26-batch-100

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-26-batch-100.1 — Phase-1 derivation: D1–D7, rulings O-1 to O-11, the G-005 answer, the R-TUI-012 amendment and the variant-slot policy
- **Requirement:** HLR-163, HLR-164, HLR-167, HLR-168, HLR-169, HLR-170, HLR-171, HLR-173, HLR-174, HLR-175, HLR-177, HLR-178
- **Requirement:** LLR-163.3, LLR-163.4, LLR-164.2, LLR-167.2, LLR-167.4, LLR-168.2, LLR-168.3, LLR-169.2, LLR-169.6, LLR-169.7, LLR-170.2, LLR-171.1, LLR-171.2, LLR-171.3, LLR-174.1, LLR-175.2, LLR-177.1
- **Date:** 2026-10-26
- **What changed:** the live contract was written from the seeded template. The requirements above say what they say because of an operator decision, an orchestrator ruling or a requirement change that this entry records. Body first: every line the table names already exists in `01-requirements.md`.

| Decision | What it put in the contract | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| Kickoff G-005 = "reuse + re-pin tests" | identical bytes reuse any `<name>` or `<stem>_<N>`; TC-018 and AT-031b re-pinned as two pairs each; the one ripple re-pin (P-22) | HLR-163: the re-pins are its test expectations, no change | HLR-163 Statement; LLR-163.3; LLR-163.4 |
| O-9 | a clash with a project other than the open one is refused with a notice; the open project updates in place | HLR-164 clause (a) carries it | HLR-164 Statement; LLR-164.2 |
| D1 = `imagen`; O-5; O-6 | Save project emits the in-memory image through `save_patched` at 32 bytes per line with the source S0, with no prompt; a blocked re-derive refuses the whole save | HLR-167 carries all three | HLR-167 Statement; LLR-167.2; LLR-167.4 |
| D2 = `ultima`; O-1; O-10 | the save-back becomes `active_variant`; every in-project writer rewrites the manifest through the seam; `current_file.path` keeps the source | HLR-168 carries all three | HLR-168 Statement; LLR-168.2; LLR-168.3 |
| D3 = `abre_y_reporta`; O-2; O-11 | `files` digests over the top-level data and A2L files and the active document only; Load opens what is valid and lists every problem; private manifest staging | HLR-169 carries all three | HLR-169 Statement; LLR-169.2; LLR-169.6; LLR-169.7 |
| D4 = `reabrir` | the active document, pasted or file-backed, is placed in `patches/`, recorded and reopened | HLR-170 | HLR-170 Statement; LLR-170.2 |
| D5 = `copiar` with O-4; D6 = `abrir`; D7 = `solo_workarea` | save-as copies every sub-folder; an A2L-only project opens; the parent must be the app's work area (the handler half), and the dialog has no parent field (the dialog half, HLR-175) | HLR-171 and HLR-175 | HLR-171 Statement; LLR-171.1; LLR-171.2; LLR-171.3; HLR-175 Statement; LLR-175.2 |
| O-3 | the unsaved-work question also fires for unsaved Flow Builder edits | HLR-174 | HLR-174 Statement; LLR-174.1 (the 16-cell table) |
| O-7 | Inc 12b moves project load, Save project and the A2L parse to workers; flow runs stay; conditional on the P-D verdict | HLR-177 | HLR-177 Statement; LLR-177.1 |
| O-8 and the D2 note | the Load-result announcement is its own story, US-168, and its own HLR, HLR-178 | HLR-178 | HLR-178 Statement and its Variant slots line |
| Commission: the UI stories stay REFINE until the prototype round | HLR-173, HLR-174, HLR-175, HLR-177 and HLR-178 state the clauses that hold in any variant; each variant-specific clause is a named slot that the verdict on its surface fills by a new entry in this ledger before the increment opens. HLR-176 carries slots VS-PD-1 and VS-PD-2 but no ruling, so it pairs with no entry yet | each REFINE HLR | the `Variant slots` line of each of the six UI HLRs |

- **Requirement change — R-TUI-012 is amended to agree with LLR-015.3.** Before (`REQUIREMENTS.md:1244-1245`): "Saving a project must copy the loaded file into a workarea subfolder named by a sanitized project name." After (written into the canon at the batch's documentation station, not by P1): "Saving a project must place the image the session holds into a workarea subfolder named by a sanitized project name: an image that differs from its source file is emitted through the verified emitter (`ChangeService.save_patched`, 32 bytes per line, source S0 preserved); an unchanged image, its MAC and its A2L are copied byte for byte." The conflict: R-TUI-012 says copy, while LLR-015.3 (`2026-06-23-batch-14/01-requirements.md:222`) routes the project save flow through the emitter, and its TC-220 drives `ChangeService.save_patched` (`tests/test_changes_apply.py:926-929`). The copy is what drops the patch (PH-1). D1 resolved the conflict in LLR-015.3's favour. Deleted tokens: "copy the loaded file". New tokens: "place the image the session holds", "emitted through the verified emitter". Re-derived verification: HLR-167, LLR-167.2, TC-B100-15, AT-B100-05. R-TUI-012's own node, `test_save_project_creates_project_folder_on_disk` (an unpatched session), is expected to stay green. Assumption, listed as Q-7 in the contract's §6.3: LLR-015.3's width-selector clause is met by the service argument TC-220 drives, and O-5 adds no prompt to Save project.
- **Why:** the operator's verdict of 2026-10-26 (`design/veredicto-b100.json`: D1–D7 all on the recommended option, plus the D2 note), the kickoff answers (PLAN header), and the orchestrator rulings O-1 to O-11, taken under the standing authorization (`design/ARQ-batch-100.md` §10.1). Questions that no document settles are listed in the contract's §6.3 (Q-1 to Q-7) and are not decided here.
- **Evidence:** `evidence/p0-premises/` (premises P-1 to P-21, executed on a `git archive` of `1d677ba`); the draft-time probes of P-22 to P-29 (their commands are in §2.7). Security pattern scan: `python -I ~/.claude/skills/dev-flow/scripts/devflow-scan-spec.py <abs>/01-requirements.md` → 5 control rows ok; flags `session`, `permission`, `hash`, `form`, `escape`, `expose`; `security_required: true`; exit 1. Each flag is answered in §6.3.

### LED-2026-10-26-batch-100.2 — Round 2: the prototype verdict fills every variant slot; US-163 to US-168 become READY
- **Requirement:** HLR-173, HLR-174, HLR-175, HLR-176, HLR-177, HLR-178
- **Requirement:** LLR-173.2, LLR-173.6, LLR-178.3
- **Date:** 2026-10-26
- **What changed:** the slot lines of the six UI HLRs now carry the operator's choice (`design/veredicto-load-projects.json`, exported 2026-10-26T14:26Z), and the six stories moved from REFINE to READY.
  - **P-A = C** (two panes, preview right). Operator note: "Me gusta la idea de los dos paneles, con el simbolo de cuál es el set que se va a usar como archivos activos en el proyecto para las vistas y funciones en la aplicación." The slots it fills:
    - VS-PA-1: two panes.
    - VS-PA-5: the preview marks the active set with `●`, and the installed files equal the marked ones (LLR-173.6, the AT-B100-14 oracle).
    - VS-PA-3/4: the `pa_C` ids and bindings (P-30), with `p` opening the same dialog.
    - VS-PA-2: a click selects, Enter loads, no double-click.
    - VS-PA-6 (added from UX-05): typed text wins with the path focused, the highlighted row wins with the list focused, and `tab` goes path → list → preview → buttons (LLR-173.2).
    - The panes stack below 100 columns (UX-10).
  - **P-B = A** (short question). Operator note: "Pregunta corta, hace el trabajo y crea menos dependencias." VS-PB-1: the short question. VS-PB-2: no "save first" key. VS-PB-3: the `pb_A` ids.
  - **P-C = B** (name + summary). Operator note: "…es importante saber que se está guardando en cuestión de proyecto. Se extra cuidadoso con la información que se despliega aquí. Un error aquí podría hacer que el trabajo del usuario se invalide o se pierda o se sobreescriba o se renombre. Mucho cuidado al popular esta información." VS-PC-1: the summary, under ruling R-PC (one plan, painted and executed: LED .4). VS-PC-2: during a refusal, Save stays focusable and refuses with the reason painted. VS-PC-3: the `pc_B` ids.
  - **P-D = A** (status line). Operator note: "El spinner con la acción en progreso debe ser suficiente. asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso." VS-PD-1: `#status_text`, with the bar kept working. VS-PD-2: no cancel. VS-PD-3: a second request is refused. Ruling R-PD makes 12b unconditional (LED .11).
  - **P-E = B** (result panel). No note. VS-PE-1: the panel. VS-PE-2: the HLR-178 reason vocabulary. VS-PE-3: `v` runs the existing `select_variant` (P-31). The panel holds the focus while it is open (LLR-178.3).
- **Closes:** UX-05, UX-15, UX-24, QA-17. Each slot is filled with an existing behaviour or none: no "save first", no cancel, refuse instead of queue, and `v` is an existing action.
- **Why:** the operator's prototype verdict and dispositions §1 (`design/P2-dispositions-r1.md`).
- **Evidence:** `design/veredicto-load-projects.json`; P-30 and P-31 (§2.7).

### LED-2026-10-26-batch-100.3 — Round 2: two predicates, and one question only when something would be lost
- **Requirement:** HLR-174
- **Requirement:** LLR-167.1, LLR-167.5, LLR-174.1, LLR-174.2
- **Date:** 2026-10-26
- **What changed:**
  - **UX-01, A-08:** "unsaved" now means "differs from the copy last loaded or saved". This is a new predicate, `differs_from_last_saved` with `mark_saved` (LLR-167.5), recorded at load, save-back and Save project. `image_differs_from_source` stays the emit-or-copy predicate only (LLR-167.1). New cells: patched → Save project → load asks nothing; patched → save-back → load asks nothing; saved → patched again asks.
  - **UX-11:** the "project open" term is removed. A load that would lose nothing asks nothing.
  - **QA-03:** the Patch Editor dirty flag (W) joins the triggers. The existing change-document question is `LoadGuardScreen` (P-32), now cited correctly.
  - **QA-21:** the table is re-derived per load kind and executed. A file load loses only the image; a project load loses the image, the document and the flow edits. Result: 16 cells, 11 ask, 5 load. Dropping F or W leaves 1 cell wrong each.
  - **UX-12:** one question for every item. The focus starts on `#confirm_no`, and `enter` acts on the focused button.
- **Closes:** UX-01, UX-11, UX-12, QA-03, QA-21, A-08.
- **Why:** dispositions §2 (the UX-01, UX-11 and QA-03 rows) and §4 (A-08).
- **Evidence:** the `itertools.product` enumeration → `cells 16 ask 11 load 5`, `drop-F wrong 1`, `drop-W wrong 1`; `screens_directionb.py:4279`, `:4808`.

### LED-2026-10-26-batch-100.4 — Round 2: Save project uses `save_patched`, driven by one save plan (A-06, R-PC)
- **Requirement:** HLR-167, HLR-175
- **Requirement:** LLR-167.2, LLR-167.3, LLR-167.4, LLR-167.6, LLR-175.4
- **Date:** 2026-10-26
- **What changed:**
  - **A-06 (supersedes the QA-06 ruling).** Save project writes the source plus every entry the document holds now, through `save_patched`. This is the save-back's rule, so B99-I7 is unchanged and needs no amendment.
    - The view's image is updated in place.
    - A document with only unapplied entries is emitted, not dropped.
    - The status names the N entries and the K that this save applied (LLR-167.3).
    - The landing name follows M-1 (`<stem>_<N>`), and the landed image becomes `active_variant`.
  - **R-PC.** `plan_project_save` (LLR-167.6, in `project_gather_service.py`) computes the plan without writing anything. The handler executes it (Inc 5) and the dialog paints it (LLR-175.4, Inc 11). The new AT-B100-21 compares the painted rows with the files on disk, by path and digest, over 5 scenarios.
  - **QA-09:** AT-B100-05 gains its consumer oracle: the Loaded panel, then the panel naming the variant as patched.
  - **UX-21:** the summary names the cap and the in-place update of the open project.
  - **A-17:** the re-derive runs on the main thread before the Save worker starts, and the worker writes from a copy (LLR-177.1).
  - **Inc 5 files:** `app.py`, `change_service.py`, `project_gather_service.py`. That is 3, within the cap.
- **Closes:** QA-06 (superseded by A-06), A-06, QA-09, UX-21, A-17.
- **Why:** dispositions §2 (QA-06 row), §1 (R-PC), §3 (Inc 5 and Inc 11), §4 (A-06).
- **Evidence:** `change_service.py:2009-2040` (the docstring: re-derive, journal restored in place); P-23.

### LED-2026-10-26-batch-100.5 — Round 2: Q-1, Q-2 and the name guards
- **Requirement:** HLR-164
- **Requirement:** LLR-164.1, LLR-164.2, LLR-164.3, LLR-164.4, LLR-175.1
- **Date:** 2026-10-26
- **What changed:**
  - **Q-1 (QA-18, S-14, A-10).** `PROJECT_NAME_MAX_CHARS = 64` is now in the contract: 64 characters saves, 65 and 300 refuse. A full-path check also refuses when `len(str(workarea / name)) + 53 > 259`; 53 is the longest fixed in-project file name, following the `_MAX_FULL_PATH` idiom.
  - **Q-2 (QA-04, A-09).**
    - A project is a direct child of this work area that holds `project.json` or a data file, is not reserved and is not a link.
    - A disguised clash (case-folded equal, typed name different) is refused, and the refusal names both.
    - An exact name of a project that is not open merges. The merge carries the target's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` and variants, and `test_save_second_s19_into_project_appends_variant` stays green.
    - The open project's name, typed exactly or unsanitised, saves into the open project.
  - **S-04, QA-22:** Windows device names are refused case-folded, with or without an extension or a superscript digit.
  - **S-05:** one `OSError` handler covers every stage after the folder is created, and the census counts exception exits.
  - **UX-07 (names part):** every refusal paints a reason token and a next-step token (§3 preface table).
- **Closes:** QA-04, QA-18, QA-22, S-04, S-05, S-14, A-09, A-10.
- **Why:** the P1-gate rulings Q-1 and Q-2 (`state.json` decisions_log, P1 entry), dispositions §2 (the QA-04 and S-01..S-09 rows) and §4 (A-09, A-10).
- **Evidence:**
  - `p2sec_probe.py` §1 (security): device names accepted.
  - `p2sec_probe2.py` §A (security): a `FileNotFoundError` escapes and a partial folder is left.
  - `q1.py` (architect): `dir 247 True / 248 FileNotFoundError`.

### LED-2026-10-26-batch-100.6 — Round 2: containment in this work area and untrusted input (security closures)
- **Requirement:** HLR-169, HLR-171, HLR-172
- **Requirement:** LLR-169.2, LLR-169.4, LLR-169.7, LLR-169.8, LLR-171.1, LLR-171.4, LLR-172.1, LLR-172.2, LLR-172.5, LLR-173.4
- **Date:** 2026-10-26
- **What changed:**
  - **S-02 (QA-10).** The new LLR-171.4 defines containment as inside `self.workarea.resolve()` after links are resolved. A project folder that is a junction is not listed, loaded or written. AT-B100-11 is rebuilt on that RED path: today a junction folder is listed.
  - **S-01:** reserved homes never load as projects, whether picked or typed (LLR-172.5).
  - **S-03, S-15:** save-as prunes directory links before descending, and refuses a copy larger than the volume's free space (LLR-171.1).
  - **S-07, S-12, QA-12:** the recent store.
    - It keeps local drive paths only, whose kind matches the suffix and which hold no control characters.
    - It is never touched before Enter.
    - It stages under a unique name.
    - Size arms: 1 900 entries → 20 returned; 65 536 bytes → parsed; 65 537 bytes → `too large`.
  - **S-08:** `project.json` reads are capped at 1 MiB and 1 000 `files` records.
  - **S-09, A-04:** the new LLR-169.8 makes the shared predicate refuse drive-relative, stream and device names with `MANIFEST-PATH-ESCAPE`. §5.4 names its callers' tests.
  - **S-10:** a `files` key must be a top-level data or A2L name, or `active_document`; only `S_ISREG` files are hashed.
  - **A-13:** the scope is keyed on `PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS`, which includes `.srec` and `.ihex`.
  - **QA-11:** the race arm requires 80 of 80 writes, each with its own content, plus a source predicate.
- **Closes:** S-01, S-02, S-03, S-07, S-08, S-09, S-10, S-12, S-15, A-04, A-13, QA-10, QA-11, QA-12. **S-16** is answered in §6.3 and stays open until the operator accepts it.
- **Why:** dispositions §2 (the S-01..S-09 and QA-10..QA-13 rows) and §4 (A-04, A-13).
- **Evidence:** the security probes (`p2sec_probe.py` §2, §3, §3b, §4; `p2sec_probe3.py`); the QA `race_probe.py` (`ok=3 cross-content=12 failed-writes=60`).

### LED-2026-10-26-batch-100.7 — Round 2: the problem list, its precedence and the Load-result panel
- **Requirement:** HLR-168, HLR-169, HLR-178
- **Requirement:** LLR-168.3, LLR-169.5, LLR-169.6, LLR-169.9, LLR-171.2, LLR-178.1, LLR-178.2, LLR-178.3
- **Date:** 2026-10-26
- **What changed:**
  - **A-01:** the "not recorded" kind is restored, because three writers bypass the manifest writer. Routing them through it is filed in `BACKLOG-CODE.md` §*Routed 2026-10-26 — batch-100 P2 round 1*, and §1.2 no longer claims that every write is recorded.
  - **A-05:** `not readable` comes from the load result in `_handle_load_project` (the new LLR-169.9), with no parser import in `manifest_writer.py`.
  - **A-18:** a `no project.json` kind.
  - **QA-07:** one problem per file, by this precedence: manifest damaged / no `project.json` > missing > not readable > changed on disk > not recorded > no digests saved.
  - **QA-08, UX-08:** the status log gets one summary line, the panel holds the full list, and `#status_text` names the project and the file.
  - **UX-09, UX-19, UX-20:** the panel words its content for the user.
    - It states "patched, N bytes differ" or "identical" against the first variant.
    - It words problems in user terms.
    - It says "latest" only for the newest-written variant.
    - The Load dialog's preview keeps the list reachable.
  - **A-02, A-03:** every O-1 rewrite carries every key it does not own, `active_document` included, converted back to project-relative paths. The new AT-B100-20 chains each sync writer → `project.json` → a fresh Load and Execute scope.
  - **A-14:** an A2L-only load builds an empty variant set, so later rewrites still run.
  - **A-15:** the active-document arm of LLR-169.2 moves to TC-B100-28 (Inc 8a).
  - **A-16:** the composer lives in `variant_execution_service.py`.
  - **UX-14:** the variant append names the project and the file it now opens.
- **Closes:** A-01, A-02, A-03, A-05, A-14, A-15, A-16, A-18, QA-07, QA-08, UX-08, UX-09, UX-14, UX-19, UX-20.
- **Why:** dispositions §1 (P-E), §2 (the QA-07, QA-08 row) and §4 (A-01 to A-05, A-13 to A-18).
- **Evidence:** the architect's `carry.py` (`serialize_manifest` refuses the reader's absolute `batch`); P-36; `variant_execution_service.py:427-429`.

### LED-2026-10-26-batch-100.8 — Round 2: the session snapshot is derived from the live app
- **Requirement:** HLR-165
- **Requirement:** LLR-165.1, LLR-165.2
- **Date:** 2026-10-26
- **What changed:**
  - **QA-01, A-07:** `vars(app)` is replaced by `_session_snapshot()`.
    - Its domain is the names that `S19TuiApp`'s source assigns, derived by a census at test time.
    - It excludes a declared list of Textual internals, each with its reason.
    - Values are normalised: relative paths, counts and keys.
  - The 11 names the architect's probe found outside the inventory are reset by the seam (LLR-165.1): the seven `_mac_view_cache_*`, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address` and `_a2l_row_key_to_tag`.
  - The negative control is unchanged, plus a set mutation for the classification.
- **Closes:** QA-01, A-07.
- **Why:** dispositions §2 (QA-01) as amended by §4 (A-07: the set stays derived).
- **Evidence:** the QA `vars_probe.py` (35 names differ between two identical cold loads); the architect's `vars_probe.py` (58 differ, 27 of them app-owned, the 11 named).

### LED-2026-10-26-batch-100.9 — Round 2: one byte-identity function and a placement result
- **Requirement:** HLR-163
- **Requirement:** LLR-163.1, LLR-163.3, LLR-163.4, LLR-163.5, LLR-163.6
- **Date:** 2026-10-26
- **What changed:**
  - **QA-05:** Inc 1 takes `segment_split_view.py`, for 3 files.
    - One `find_identical` in `workspace.py` decides byte-identity for both the placement and the export (the new LLR-163.6), and the export's status word comes from the placement outcome.
    - Callers learn about reuse through `place_into_workarea(...) -> PlacementResult(path, reused)`. `copy_into_workarea` wraps it and keeps its `Path` return, so its 17 call sites in 7 product files (P-34) are unchanged. This is the interface amendment of B100-I6.
    - **Deviation:** the literal ruling says "`copy_into_workarea` returns a result", which would put 7 files in Inc 1. §6.3 states this.
  - **QA-25:** AT-B100-01 observes P's data files on disk.
  - **QA-27:** after the AT-031b re-pin, R-PATCH-SAVE-FOLDER-001 ("Two distinct saves shall not clobber one another", `REQUIREMENTS.md:3553`) reads as two saves of distinct content. No canon text changes.
- **Closes:** QA-05, QA-25, QA-27.
- **Why:** dispositions §2 (QA-05) and §3 (Inc 1).
- **Evidence:** `git grep -n "copy_into_workarea(" -- s19_app` (P-34); `segment_split_view.py:673`, `:939-946`.

### LED-2026-10-26-batch-100.10 — Round 2: focus, keys, widths, painted text and the document name
- **Requirement:** HLR-166, HLR-170, HLR-172, HLR-173
- **Requirement:** LLR-166.1, LLR-166.2, LLR-170.1, LLR-170.2, LLR-172.5, LLR-172.6, LLR-173.3, LLR-173.5, LLR-173.7, LLR-175.3
- **Date:** 2026-10-26
- **What changed:**
  - **UX-03, UX-04:** each window declares a non-text focus target. The rule also holds after the dialog, the question and the panel close, and after a cancelled load.
  - **UX-06:** an invalid typed path is explained inside the dialog (the new LLR-173.5).
  - **UX-07, UX-22, UX-23:** the §3 preface's refusal-token table covers names, paths, empty sections and a recent source that is missing when picked.
  - **UX-10:** every UI AT runs at 118×54 and 220×60 with notifications on. No row wraps, and the panes stack below 100 columns.
  - **UX-13:** the key rule is single letters in a modal without a text field and `alt+<letter>` in one with a text field. Every shown key is pressed in a test.
  - **UX-17:** a typed folder gets one of two statuses: inside the work area but not a project, or outside the work area.
  - **UX-18:** the new LLR-173.7 forbids painting an internal decision id.
  - **QA-02, S-06, S-13:** names render through `safe_text`. The fixtures are names that can exist on disk and paint a span with markup on: `[bold]x.s19`, `[b]P`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, and U+009B.
  - **Q-5, QA-19, UX-25, A-12:** the app writes a pasted document as `patches/changes.json` through the M-1 rule (`changes_1.json` on a clash), and the summary shows that name.
  - **S-11:** the reader enforces the `patches/`/`checks/` prefix and the `.json` suffix.
- **Closes:** UX-03, UX-04, UX-06, UX-07, UX-10, UX-13, UX-17, UX-18, UX-22, UX-23, UX-25, QA-02, QA-19, S-06, S-11, S-13, A-12.
- **Why:** dispositions §2 (QA-02, UX-03..UX-16 and the MINOR rows) and §4 (A-11, A-12).
- **Evidence:** the QA `markup_probe.py` (`[bold]x.s19 … spans=1`; names with a closing tag cannot exist on disk); the security `p2sec_probe2.py` §D (ESC and U+009B kept with markup off).

### LED-2026-10-26-batch-100.11 — Round 2: real progress (R-PD), workers unconditional, per-action census
- **Requirement:** HLR-176, HLR-177
- **Requirement:** LLR-176.1, LLR-176.2, LLR-176.3, LLR-177.1
- **Date:** 2026-10-26
- **What changed:**
  - **R-PD, UX-02:** 12a and 12b land together, and 12b is unconditional.
    - HLR-176 is scoped to worker actions.
    - The A2L tag-table build stays on the main thread; its step name is painted before it starts, and its freeze is declared.
    - The indicator paints `#status_text` and moves the bar by step.
  - **QA-13:** the census is keyed per action. Each of the 24 `set_progress` sites (P-29) maps to one action's begin or end.
  - **QA-16:** the slow ATs use the case_06 A2L (P-33), and the §3 preface bans private calls in AT nodes.
  - **QA-26:** the paint-before-work probe reads the step text in a `call_after_refresh` callback.
  - **VS-PD-3:** while a worker action runs, a second request, a Patch apply and an undo are refused with the `busy` token.
- **Closes:** UX-02, QA-13, QA-16, QA-26.
- **Why:** dispositions §1 (P-D), §2 (the UX-02 and QA-16 rows) and §3 (Inc 12a + 12b).
- **Evidence:** the UX review's capture (no repaint between the start and the end of the case_06 parse); `ls -la examples/case_06*/` (P-33).

### LED-2026-10-26-batch-100.12 — Round 2: the validation plan — AT index, reverse census, guards
- **Requirement:** LLR-173.1
- **Date:** 2026-10-26
- **What changed:**
  - **QA-14:** §5.3 lists, for each AT, the increment that writes it, the increments that re-pin it (9b for project picks, 10 for answering `y`), and its C-12 chain.
  - **QA-15:** §5.4 is the reverse census over the 35 test sources (P-35), one row per touched symbol with its disposition.
    - 8 nodes type into `#project_parent_path`: 6 in `test_b99_staging.py` and 2 elsewhere. They are re-pinned at Inc 11 with their expectations unchanged, and AT-B99-05 keeps its outcome.
    - The load question sits in the router, so the 13 files that call `_handle_load_project` directly meet no modal.
  - **QA-23:** `_handle_load_dialog` keeps accepting a `Path` (`tests/test_tui_app.py:1254`, `:1288`), and the `load_dialog` component names that consumer.
  - **QA-24:** §5.1 names the whole-tree guard command.
  - **UX-16:** §5.1 declares the Phase-4 expert inspection of the panel and the Save summary.
  - **QA-20** (PLAN's wording) belongs to the orchestrator and lies outside this file.
- **Closes:** QA-14, QA-15, QA-23, QA-24, UX-16. QA-20 is routed to the orchestrator (PLAN).
- **Why:** dispositions §2 (the QA-14, QA-15 row; UX-16; the MINOR rows).
- **Evidence:** `grep -rl --include=*.py <symbol> tests` for each §5.4 row (counts 35, 15, 13, 4, 7, 10, 7, 5); `ls tests/test_import_census.py … tests/test_engine_unchanged.py`.

### LED-2026-10-26-batch-100.13 — Round 2: requirement changes to the canon — LLR-015.3 and R-TUI-012 (A-11, Q-7)
- **Requirement:** HLR-167
- **Requirement:** LLR-167.2
- **Date:** 2026-10-26
- **What changed:**
  - **A-11 — LLR-015.3 is amended.**
    - Before (`.dev-flow/2026-06-23-batch-14/01-requirements.md:224`): "The patch-editor save-back flow and the project save flow shall each expose a NEW {16,32} selector (default 32) and pass the chosen width + captured header through to the emitter."
    - After (written into the canon at P6): "The patch-editor save-back flow shall expose a {16,32} selector (default 32); the project save flow shall emit at 32 bytes per line with the captured header and expose no selector (O-5). Both pass the width and header through to the emitter."
    - Deleted tokens: "and the project save flow shall each expose".
    - Re-derived verification: TC-220 (the service kwarg, unchanged) and TC-B100-15 (32 bytes per line, S0 kept).
    - Q-7's "assumption" is withdrawn: this is a requirement change.
  - **R-TUI-012 is restated after A-06.** This supersedes the wording in LED .1. After (written into the canon at P6): "Saving a project must place, in a folder of this work area named by a sanitized project name, the source plus every entry of the change document through the verified emitter (`ChangeService.save_patched`, the save-back's rule, 32 bytes per line, source S0 kept) when the image differs from its source or the document holds entries; otherwise it copies the loaded file byte for byte. MAC and A2L are copied byte for byte."
  - The security pattern scan is re-run on the round-2 contract, and its result is recorded in `02-review.md`.
- **Closes:** A-11.
- **Why:** dispositions §4 (A-11) and the D1 and A-06 rulings.
- **Evidence:** `2026-06-23-batch-14/01-requirements.md:222-225`; `tests/test_changes_apply.py:926-929`; `REQUIREMENTS.md:1244-1245`.

### LED-2026-10-26-batch-100.14 — Round 3: the emit decision is made on data; `save_patched` is split (corrects round 2)
- **Requirement:** HLR-167
- **Requirement:** LLR-167.1, LLR-167.2, LLR-167.7
- **Date:** 2026-10-26
- **What changed:**
  - **B-01, QA R2-01:** the round-2 trigger ("the image differs from its source or the document holds at least one entry", LED .4) is withdrawn. Save project now re-derives the **change** document onto a copy of the source image and emits only if the resulting data differs from the source data; a check document never counts and is saved to `checks/` without blocking (LLR-167.1, LLR-167.2). Three arms: check document only → byte copy plus `checks/` written; unchanged change document → byte copy and no new variant; a real change → emit. §6.3 lists the round-2 rule as a deviation that this round corrects; R-TUI-012's restatement in LED .13 ("otherwise copies byte for byte") holds again.
  - **B-04:** `save_patched` is split into `rederive_for_save` and `emit_and_verify` (B100-I15, LLR-167.7) as Inc 5's API, and is composed of the two, so B99-I7 stays one rule.
  - **Coordinator alignment (4):** whether `image_differs_from_source` (B100-I5) survives as a pre-check is left to PDR (§6.3).
- **Closes:** B-01, QA-R2-01, B-04.
- **Why:** dispositions r2 (the B-01 + QA R2-01 and UX-33 + B-04 rows) and the coordinator's alignment with ARQ §8.
- **Evidence:** P-37 (architect `checkdoc.py`: `save_patched ok: False`), P-38 (QA `emit_identity.py`: data identical, bytes different).

### LED-2026-10-26-batch-100.15 — Round 3: the save plan's granularity, cost and prediction (R-PC)
- **Requirement:** HLR-175
- **Requirement:** LLR-163.7, LLR-167.6, LLR-175.4
- **Date:** 2026-10-26
- **What changed:**
  - **UX-32, QA R2-05:** the plan has one row per top-level file, one per sub-folder with its file count, and one for `project.json`, each with an action word (`new`, `replace`, `keep`, `merge`, `rewrite`). AT-B100-21 compares the plan's rows with the written tree at that granularity by full path and action, read from the plan the dialog holds (`SaveProjectScreen.plan`, declared as an exception in the §3 preface), and checks the painted action words at 220 columns. A long summary scrolls with its buttons pinned. "Nothing is overwritten silently": every `replace` or `rewrite` is a row that says so.
  - **UX-33, B-04:** the image digest is computed once per dialog open; the name-dependent rows are recomputed at most every 150 ms, with no hashing per keystroke; `project_gather_service` gains no import of the change service.
  - **B-05:** the new `predict_placement` (B100-I22, LLR-163.7) predicts every landing name with the placement code itself; the handler checks each landed path against its planned row, and a mismatch is an error naming both.
- **Closes:** UX-32, QA-R2-05, UX-33, B-05.
- **Why:** dispositions r2 (the UX-32 + QA R2-05, UX-33 + B-04 and B-05 rows); the operator's P-C note.
- **Evidence:** the architect's code read `workspace.py:546-620` (the claim loop decides names); `png/pc_B.pc.118.png` (grouped sub-folders).

### LED-2026-10-26-batch-100.16 — Round 3: `derived_from` and the Load-result panel
- **Requirement:** HLR-168, HLR-178
- **Requirement:** LLR-168.3, LLR-168.4, LLR-178.1, LLR-178.2, LLR-178.3
- **Date:** 2026-10-26
- **What changed:**
  - **UX-26:** a new per-variant `derived_from` key (B100-I16, LLR-168.4) records the base's name, its SHA-256 and the byte count, computed at the write. It is set by the save-back and by Save project's emit from Inc 7; emits before Inc 7 record nothing. Every rewrite carries it. The panel compares against it, never against the first variant by name (P-39). When the base is not in the project, the panel says "patched from `<base>` (not in this project); N bytes differ from it"; a variant with a record is never called identical (coordinator alignment 2 and 3, ARQ §8.1).
  - **UX-31, UX-39:** the focus starts on the problem list (↑, ↓, PgUp, PgDn), `tab` moves to OK, and `enter` on OK or `escape` dismisses; the test reaches the last row by geometry.
  - **UX-38:** the summary line ends "details: p".
  - **UX-40:** "latest" comes from the app's own recorded write, never file times.
  - **B-11 (panel part):** `#status_text` gets the project and file line through the progress line's final writer (LLR-178.2).
- **Closes:** UX-26, UX-31, UX-38, UX-39, UX-40.
- **Why:** dispositions r2 (the UX-26 and UX-31 rows, MINOR rows) and the coordinator's alignment points 2 and 3.
- **Evidence:** P-39 (`sorted(...)` puts `firmware-patched.s19` first).

### LED-2026-10-26-batch-100.17 — Round 3: one load seam, the 24-cell table, and Save project clears the document flag
- **Requirement:** HLR-174
- **Requirement:** LLR-167.8, LLR-174.1, LLR-174.4
- **Date:** 2026-10-26
- **What changed:**
  - **B-02, QA R2-03:** every image-replacing route — the Load dialog, the Workarea Files pick, the variant switch (`v` and the panel's `v`), a project load — passes one seam, `_confirm_then_load` (B100-I20, LLR-174.4), with one test arm per route (P-42).
  - **QA R2-02:** a MAC or A2L load only attaches, loses nothing and never asks. The table now has three kinds (image replace, attach, project): 24 cells, 11 ask, 13 load; dropping D → 5 wrong, F → 1, W → 1; the round-2 rule of asking on an attach → 4 wrong (executed).
  - **UX-27:** Save project calls the Patch Editor panel's `mark_saved` once the document is written (LLR-167.8); cell added: patched + entries → Save project → project load = no question.
- **Closes:** B-02, QA-R2-02, QA-R2-03, UX-27.
- **Why:** dispositions r2 (the QA R2-03 + B-02, QA R2-02 and UX-27 rows).
- **Evidence:** `itertools.product` enumeration → `cells 24 ask 11 load 13`, `drop-D wrong 5`, `drop-F wrong 1`, `drop-W wrong 1`, `attach-asks-on-D wrong 4`; P-42; P-43.

### LED-2026-10-26-batch-100.18 — Round 3: the Load dialog's focus, rows and preview
- **Requirement:** HLR-173
- **Requirement:** LLR-173.2, LLR-173.4, LLR-173.6
- **Date:** 2026-10-26
- **What changed:**
  - **UX-05, QA R2-06:** the dialog opens with the focus on the path field, correcting `pa_C`'s start on the list. The order is path → list → preview → buttons. A printable key typed while the list has the focus moves to the path field and types there, never reaching an app binding. `#load_ok`, `enter` and `alt+l` load the highlighted row when the list had the focus and the typed path otherwise. ATs 01 and 12 therefore need no re-pin at Inc 9b (§5.3).
  - **UX-36:** `●` marks the installed set for every row kind; a file row with a project open says it becomes the project's active variant; a recent row shows only path, size and last seen, says "checked when loaded", and is never read before Enter.
  - **UX-37:** `p` highlights the open project's row, else the first project; the key bar labels the keys "Load" and "Projects".
  - **Security R2-03 (preview part):** a project row's preview reads its manifest on a worker, capped, cancelled when the highlight moves; a key is answered within 200 ms.
- **Closes:** UX-05, QA-R2-06, UX-36, UX-37.
- **Why:** dispositions r2 (the UX-05 + QA R2-06, UX-36, UX-37 and security R2-03 rows).
- **Evidence:** P-30 (`pa_C` `AUTO_FOCUS = "#load_list"`); security probe R3 (P-40).

### LED-2026-10-26-batch-100.19 — Round 3: the status line's owner, real progress, and the worker refusal set
- **Requirement:** HLR-176, HLR-177
- **Requirement:** LLR-164.4, LLR-176.1, LLR-176.2, LLR-177.1
- **Date:** 2026-10-26
- **What changed:**
  - **UX-29, B-11:** while an action is busy, `#status_text` has one owner, the progress line. At the end, a single final writer paints, in order: the outcome, the project and file line, then the file state. The bar starts at 0, is hidden when idle, and is never left at a stale `100%`.
  - **UX-30:** the bar moves within a step wherever progress is measurable (bytes copied, read or parsed), and by step only for indivisible steps; the A2L tag-table build stays declared out of scope.
  - **B-10:** the census maps each `set_progress` site to an action's begin, **step** or end.
  - **QA R2-12:** the worker share is measured above one timer tick at P3, and AT-18 presses `l` after the worker step is painted.
  - **UX-34:** while a worker runs, the refused set is the load seam, unload, `v`, the save-back, Save project, Patch apply and undo; quit asks first (focus on No) and, if confirmed, waits for the worker to finish or roll back.
  - **Security R2-09:** the `OSError` handler and the census cover the Save worker body, and the folder removal runs on the worker.
- **Closes:** UX-29, B-11, UX-30, B-10, QA-R2-12, UX-34, S-R2-09.
- **Why:** dispositions r2 (the UX-29 + B-11, UX-30, UX-34 and MINOR rows); the operator's P-D note.
- **Evidence:** `png/pd_A.pd.118.png` (stale `100%` bar); the architect's `sed` of the 24 sites (`:4951`, `:6210`, `:8769`, `:8841` are steps).

### LED-2026-10-26-batch-100.20 — Round 3: containment inside the placement, caps on every array, the manifest-keys mode, device names
- **Requirement:** HLR-163, HLR-164, HLR-169, HLR-171
- **Requirement:** LLR-163.1, LLR-163.6, LLR-164.1, LLR-164.2, LLR-169.4, LLR-169.8, LLR-171.1, LLR-171.4
- **Date:** 2026-10-26
- **What changed:**
  - **Security R2-01 (S-02 carried):** the this-work-area check (`contained_in_workarea`, B100-I14) lives inside `place_into_workarea`, so every writer is covered by construction, Save project's own copies and its emit included (`save_patched_image` places through `copy_into_workarea`, `changes/apply.py:781`). The Save target gets a link/junction check before `resolve()`, for new and merge targets. Per the coordinator's alignment (1), the guard and its junction arm ship at Inc 1; only the listing and load uses stay at Inc 8b.
  - **Security R2-02:** every guard lives in `place_into_workarea`; `copy_into_workarea` is exactly `return place_into_workarea(...).path`, with no second claim loop; the export uses the placement's `reused` (B-14).
  - **Security R2-03 (S-08 carried):** every manifest array (`batch`, `assignments`, `declared_regions`, `gathered`, `files`, `derived_from`) is capped at 1 000 entries (P-40).
  - **Security R2-04, R2-05, B-12:** one device-name predicate in `workspace.py`, applied to the raw and the sanitised name and to every path component; the two older lists go to the backlog.
  - **Security R2-06:** one link-pruned walk gives both the total and the copy.
  - **Security R2-07:** a failed merge removes what it placed.
  - **B-03:** the path tightening is a manifest-keys mode (B100-I21), used only by `read_project_manifest` and `_reject_unsafe_entry`. Both flow-reference callers, `flow_persistence_service.py` and `flow_execution_service.py`, stay on the default mode, so `test_tc_b97_20_hostile_refs_render_literally` stays green (P-41, §5.4; coordinator alignment 5).
  - **B-13:** a contained but out-of-scope key gives `MANIFEST-BAD-STRUCTURE`.
  - **B-08:** P-34 is restated as 15 calls plus 2 docstring lines.
  - **B-09, QA R2-10:** HLR-163's status clause is narrowed to the variant append and the export.
- **Closes:** S-02, S-08, S-R2-01, S-R2-02, S-R2-03, S-R2-04, S-R2-05, S-R2-06, S-R2-07, B-03, B-08, B-09, B-12, B-13, B-14, QA-R2-10.
- **Why:** dispositions r2 (the security R2-01, R2-02, R2-03, B-03 and MINOR rows) and the coordinator's alignment points 1 and 5.
- **Evidence:** the security probes R1–R5 (round 2); P-40; P-41; `git grep -n "copy_into_workarea("` (P-34).

### LED-2026-10-26-batch-100.21 — Round 3: the recent-sources store is per user (S-16, operator decision)
- **Requirement:** HLR-172
- **Requirement:** LLR-172.1, LLR-172.2, LLR-172.3
- **Date:** 2026-10-26
- **What changed:**
  - **S-16:** the operator answered: the recent list is kept per user at `%APPDATA%\s19_app\recent_sources.json`, outside any work area (dispositions r2, operator decisions; the coordinator's round-3 brief). LLR-172.1 writes there, through the new `recent_store_path()`; when `APPDATA` is unset, nothing is written. The arms check that no store file appears under the base folder. LLR-172.3 widens "stays local" to every file under the base folder. §6.3's privacy item is now decided and leaves the open list.
  - **QA R2-08:** the cap arm uses 1 000 distinct entries (about 41 KB) and expects exactly the first 20 in order.
  - **Security R2-08:** mapped drives are not claimed "local"; §6.3 names the gap. The stream and trailing-dot entries are refused by the kind-to-suffix match, and `C:\x\NUL.s19` is refused as a device-name component.
- **Closes:** S-16, QA-R2-08, S-R2-08.
- **Why:** the operator's S-16 decision; dispositions r2 (MINOR rows).
- **Evidence:** the QA `recents_size.py` (1 900 distinct entries take 70 332 bytes); the security probe R5.

### LED-2026-10-26-batch-100.22 — Round 3: names, tokens and the path-limit arms
- **Requirement:** HLR-164, HLR-171
- **Requirement:** LLR-164.2, LLR-164.3, LLR-169.9
- **Date:** 2026-10-26
- **What changed:**
  - **UX-35:** a disguised clash tells the engineer to choose another name; it never suggests a merge. A merge happens only on the exact name, shown as a merge row.
  - **UX-07 residual:** every problem kind has a next-step token (§3 table), and "outside the work area" now says `copy the folder into the work area`.
  - **UX-22 residual:** a `no data or A2L file` row.
  - **UX-41:** a `not enough free space` row.
  - **QA R2-09:** problems are painted in user terms ("manifest damaged: a file path points outside the project"); the internal code goes to the log only (LLR-169.9, HLR-169's AT).
  - **QA R2-13:** LLR-164.3 arms with L = 150: a 55-character name gives 259 and is saved; a 56-character name gives 260 and is refused.
- **Closes:** UX-35, UX-07, UX-22, UX-41, QA-R2-09, QA-R2-13.
- **Why:** dispositions r2 (the UX-35, QA R2-09 and MINOR rows).
- **Evidence:** the §3 preface token table; `before_after_service.py:78-85` (the 53-character suffix, QA's check).

### LED-2026-10-26-batch-100.23 — Round 3: the validation plan — arm moves, AT-20, census rows, file sets
- **Requirement:** HLR-168
- **Requirement:** LLR-164.2, LLR-165.2, LLR-166.1, LLR-167.6
- **Date:** 2026-10-26
- **What changed:**
  - **B-06 (with ARQ §8.1):** each arm runs at the increment that makes it possible. LLR-164.2(b)'s merge carry runs at Inc 8a. TC-B100-59's `files` row runs at Inc 7, its document and merge at Inc 8a, and its sub-folders at Inc 8b. TC-B100-12's modal closes are split across Inc 6, 9b and 10. The `derived_from` comparison runs at Inc 7. The containment junction arm runs at Inc 1. §5.3 lists the AT and TC rows.
  - **QA R2-04:** AT-B100-20 is written in HLR-168's acceptance block, with its surface, observable and threshold.
  - **QA R2-07:** the snapshot normalises stat-keyed caches (`_mac_view_cache_key`) (LLR-165.2).
  - **QA R2-11:** §5.4 gains the `_handle_save_dialog` row (7 files: TC-700, AT-B99-05), plus the `_resolve_manifest_entry` and load-seam rows.
  - **B-07:** the per-increment file sets come from ARQ §8 as amended (§5.5); the interfaces are named B100-I13..I22. The ARQ record and `docs/architecture.md` are the architect's.
  - **Coordinator alignment (6, 7):** Inc 10 may add `screens_directionb.py` for a public dirty-flag reader.
  - **QA R2-14:** PLAN's `vars(app)` row was corrected by the orchestrator (`322bbab`); `grep -n "vars(app)" PLAN.md` → 0.
  - The security pattern scan was re-run on the round-3 contract; its result is recorded in `02-review.md` round 2.
- **Closes:** B-06, B-07, QA-R2-04, QA-R2-07, QA-R2-11, QA-R2-14.
- **Why:** dispositions r2 (the B-06, B-07, QA R2-04, QA R2-11 and MINOR rows) and the coordinator's alignment points 6 and 7.
- **Evidence:** `design/ARQ-batch-100.md` §8, §8.1; `docs/ARCHITECTURE.md` §11 rows B100-I13..I22; `grep -rl --include=*.py _handle_save_dialog tests` → 7.

### LED-2026-10-26-batch-100.24 — PDR: UX-22, the `no data or A2L file` refusal is painted
- **Requirement:** LLR-171.2
- **Date:** 2026-10-26
- **What changed:** LLR-171.2 now answers a project folder whose `project.json` records no missing file and that holds no data and no A2L file with the `no data or A2L file` / `load a file and Save project` tokens. TC-B100-32 gets that arm. A folder with neither and no `project.json` keeps the `no project.json` tokens.
- **Closes:** UX-22 (carried as a PDR condition, `design/P2-ux-r3.md` C-3).
- **Why:** the token row existed in the §3 table, but no requirement obliged anyone to paint it.
- **Evidence:** `design/P2-ux-r3.md` (UX-22 row); `design/design-proposal-b100.md` §9.

### LED-2026-10-26-batch-100.25 — PDR: UX C-1, the panel's button label matches its key
- **Requirement:** LLR-178.3
- **Date:** 2026-10-26
- **What changed:** `#result_ok` is labelled "Close (esc)". `escape` dismisses the panel from anywhere; `enter` dismisses it only when the button has the focus. TC-B100-67 presses the shown key `esc` from the list.
- **Closes:** UX C-1.
- **Why:** with the focus starting on the list, the label "OK (enter)" named a key that does nothing in the opening state, which breaks the §3 rule that every shown key works.
- **Evidence:** `design/P2-ux-r3.md` C-1.

### LED-2026-10-26-batch-100.26 — PDR: UX C-2, where the Save dialog's digests run and their budget
- **Requirement:** LLR-167.6, LLR-175.4
- **Date:** 2026-10-26
- **What changed:** the Save dialog paints its first frame before any digest is computed. The emitted image's digest and the copied files' digests are computed once per open, on a worker. Until they arrive, the summary shows those rows as `computing…`, and an `alt+s` pressed before then waits under the busy indicator. Budget: with the case_06 project (37.7 MB A2L), the digests complete within 2 s on the CI host. This figure is assumed; it is measured at Inc 11 and recorded in the packet.
- **Closes:** UX C-2.
- **Why:** hashing a large project on the main thread at dialog open would bring back the freeze class that UX-02 removed.
- **Evidence:** `design/P2-ux-r3.md` C-2; P-33 (case_06 size).

### LED-2026-10-26-batch-100.27 — PDR: ARCH C-4 and C-5; ARCH C-1..C-3 listed
- **Requirement:** LLR-174.4
- **Date:** 2026-10-26
- **What changed:**
  - **ARCH C-4:** LLR-174.4 now names the real method `_handle_load_project`; it previously said `_handle_project_load`.
  - **ARCH C-5:** §5.5 gives Inc 10 as 4 files with no bracket, because the public dirty-flag reader in `screens_directionb.py` is required by LLR-174.1.
  - **ARCH C-1..C-3:** no contract change. The map rows B100-I15 (`rederive_for_save` / `emit_and_verify`), B100-I22 (`predict_placement(digest_or_bytes, size, destination, name)`) and B100-I16 (name, SHA-256 and byte count) take the contract's forms. The architect updates the map at PDR (`design/design-proposal-b100.md` §4).
- **Closes:** ARCH C-4, ARCH C-5; ARCH C-1, C-2 and C-3 are routed to the architect's map update.
- **Why:** `design/P2-architect-r3.md` C-1..C-5.
- **Evidence:** `app.py:8444` (`def _handle_load_project`); `screens_directionb.py:4808` (P-43).

### LED-2026-10-26-batch-100.28 — PDR: SEC PDR-C1, the manifest seam calls `contained_in_workarea`
- **Requirement:** LLR-171.4
- **Date:** 2026-10-26
- **What changed:** LLR-171.4 no longer counts the manifest seam among the writers covered by construction, because the seam replaces `project.json` rather than placing it. `write_project_manifest`'s `_check_destination_contained` (`manifest_writer.py:366`) now calls `contained_in_workarea` with this app's work area. The Inc 8b arm adds the seam as an 8th writer, with 0 bytes written outside `self.workarea`.
- **Closes:** SEC PDR-C1.
- **Why:** `design/P2-security-r3.md` PDR-C1. The architecture row B100-I14 already listed the seam separately; only the LLR wording was off.
- **Evidence:** `manifest_writer.py:13-15`, `:366`, `:431` (the security reviewer's read).

### LED-2026-10-26-batch-100.29 — PDR: SEC PDR-C2, `assignments` is capped in total and by key count
- **Requirement:** HLR-169
- **Requirement:** LLR-169.4
- **Date:** 2026-10-26
- **What changed:** `assignments` is capped at 1 000 entries in total across all its lists, and at 1 000 keys; the other arrays keep their 1 000-entry cap each. New arm: 75 keys × 1 000 entries → 1 issue, read under 1 s.
- **Closes:** SEC PDR-C2.
- **Why:** a per-list reading of the cap allowed 75 × 1 000 entries inside 1 MiB, which took 14.80 s to read.
- **Evidence:** `design/P2-security-r3.md` PDR-C2 (executed: `read=14.80s`).

### LED-2026-10-26-batch-100.30 — PDR: SEC PDR-C3, the recent store moves to `%LOCALAPPDATA%` (orchestrator ruling)
- **Requirement:** HLR-172
- **Requirement:** LLR-172.1
- **Date:** 2026-10-26
- **What changed:** `recent_store_path()` now returns `%LOCALAPPDATA%\s19_app\recent_sources.json`, read from the `LOCALAPPDATA` environment variable. The arms point `LOCALAPPDATA` at a temporary folder, and with it unset nothing is written. §1.3 and §6.3 follow.
- **Closes:** SEC PDR-C3.
- **Why:** the orchestrator ruling recorded in `02-review.md` Round 3. `%APPDATA%` roams: on a domain with roaming profiles, the absolute local paths would be copied to a profile server, against the operator's S-16 choice ("Por usuario … las rutas nunca viajan con el proyecto"). `%LOCALAPPDATA%` is per user and per machine.
- **Evidence:** `design/P2-security-r3.md` PDR-C3; `02-review.md` Round 3 ruling.

### LED-2026-10-26-batch-100.31 — PDR: PDR-QA-1, the save-plan accessor is immutable and read after `alt+s`
- **Requirement:** HLR-175
- **Requirement:** LLR-175.4
- **Date:** 2026-10-26
- **What changed:**
  - `SaveProjectScreen.plan` returns an immutable value (a frozen dataclass).
  - AT-B100-21 reads it only after `alt+s` has been pressed by key, and never calls the planner or drives the save through it.
  - At 220 columns, each painted row that is not cut is compared with its plan row by landing name and action.
  - The §3 preface's exception text says all three.
- **Closes:** PDR-QA-1.
- **Why:** `design/P2-qa-r3.md` (*The AT-21 exception*, conditions a–c).
- **Evidence:** `design/P2-qa-r3.md` PDR-QA-1.

### LED-2026-10-26-batch-100.32 — PDR: PDR-QA-2 and B100-I5, the pre-check is only a fast path into the data comparison (orchestrator ruling)
- **Requirement:** LLR-167.1
- **Date:** 2026-10-26
- **What changed:** `image_differs_from_source` stays only as a fast path into the data comparison: when it is true, the re-derive and the comparison start at once. It never decides copy by itself: a false result still runs the comparison whenever the document holds a change entry. TC-B100-14 has two new arms:
  - unapplied change entries only: pre-check false, comparison run → emit;
  - save-back, then Save project: pre-check true, comparison run → emit.

  §6.3's open PDR item is closed.
- **Closes:** PDR-QA-2; the B100-I5 question left to PDR.
- **Why:** the orchestrator ruling in the PDR brief; `design/P2-qa-r3.md` PDR-QA-2. A pre-check that decided copy could copy the unpatched source after a save-back (A-08).
- **Evidence:** `design/P2-qa-r3.md` (QA's `emit_rule_r3.py`: check doc → copy; same bytes → copy; real change → emit).

### LED-2026-10-26-batch-100.33 — PDR: `derived_from` belongs to the B100-I1 envelope (orchestrator ruling)
- **Requirement:** LLR-168.4, LLR-169.3
- **Date:** 2026-10-26
- **What changed:** LLR-168.4 states that `derived_from` is emitted as part of the B100-I1 envelope. LLR-169.3 adds `derived_from` to `verify_written_manifest`'s drift domain, with an arm where a changed byte count → 1 mismatch.
- **Closes:** the PDR question "`derived_from` in the B100-I1 envelope".
- **Why:** the orchestrator ruling in the PDR brief. A key written by the envelope's writer belongs in what that writer verifies.
- **Evidence:** `docs/ARCHITECTURE.md` §11 B100-I1 and B100-I16.

### LED-2026-10-26-batch-100.34 — PDR: `choose_install_set` lives in `app.py`
- **Requirement:** LLR-173.6
- **Date:** 2026-10-26
- **What changed:** `choose_install_set` is a pure module-level function in `app.py`. It lands at Inc 7 with the fallback rule of LLR-169.6, and the Inc 9b preview reuses it. §5.5 consequences: Inc 7 stays at 3 files (the plan's `files` row takes its key list from `app.py`, so `project_gather_service.py` is not touched), and Inc 9b is 3 files.
- **Closes:** the PDR question about `choose_install_set`'s home.
- **Why:** both of its callers, `_handle_load_project` and the dialog through the app, already sit in `app.py`. Placing it in `variant_execution_service.py` would make Inc 9b 4 files for no reader's benefit.
- **Evidence:** `design/design-proposal-b100.md` §2 and §9.

### LED-2026-10-26-batch-100.35 — PDR seal: the A2L parse reports progress through a named frozen-engine crossing
- **Requirement:** HLR-176, LLR-176.1, LLR-176.4
- **Date:** 2026-10-26
- **What changed:** new LLR-176.4 (TC-B100-73). It adds an optional bytes-consumed callback to the A2L parse entry point of `s19_app/tui/a2l.py`, and the parsed result stays identical. The crossing is named the way batch-99 named HLR-158's. HLR-176 and LLR-176.1 now drive the bar from that callback during the parse. AT-B100-17's arm requires the bar to rise at least 2 times during the parse. Inc 12 becomes 3 files (`app.py`, `styles.tcss`, `a2l.py`) and re-adds `s19_app/tui/a2l.py` to `tests/test_engine_unchanged.py::_ENGINE_PATHS`. An IFC Part A FLOW node is owned by LLR-176.4.
- **Closes:** C-UX-1, C-QA-1 (the operator chose "Cruce con nombre").
- **Why:** the parse is the longest step, and a bar that does not move during it reads as a hang. The callback is the only source of real progress inside the step.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-1, C-QA-1; `.dev-flow/2026-10-25-batch-99/01-requirements.md` (HLR-158 crossing wording).

### LED-2026-10-26-batch-100.36 — PDR seal: the opening key sets the Load dialog's focus
- **Requirement:** HLR-173, LLR-173.2
- **Date:** 2026-10-26
- **What changed:** `l` and `ctrl+l` open the dialog with the focus on `#load_path`. `p` opens it with the focus on `#load_list`, with the open project's row highlighted. VS-PA-4 and VS-PA-6 are restated. LLR-173.2 gains the `p` focus assertion, plus the arm `p`, `enter` → the highlighted project loads, with a mutation for each key.
- **Closes:** C-UX-2.
- **Why:** `p` means "pick a project", so Enter on it must load at once. `l` means "type a path".
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-2.

### LED-2026-10-26-batch-100.37 — PDR seal: an early `alt+s` closes the Save dialog; the `computing…` rows are defined
- **Requirement:** HLR-175, LLR-175.4
- **Date:** 2026-10-26
- **What changed:** an `alt+s` pressed before the digests arrive closes the dialog at once. The save then finishes the digests and runs on a worker under the status line. A `computing…` row is a plan row whose landing name and action depend on a digest not yet known: the emitted image, and each copied file whose destination already holds a file of the same name. No other row shows it. LLR-175.4 gains the early-`alt+s` arm and the image-only arm.
- **Closes:** C-UX-3.
- **Why:** waiting in an open dialog under a busy indicator hides the work. The status line already carries real progress (P-D A).
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-3.

### LED-2026-10-26-batch-100.38 — PDR seal: the confirm modal takes its question and labels; quit reuses it
- **Requirement:** HLR-177, LLR-174.2, LLR-177.1
- **Date:** 2026-10-26
- **What changed:** the confirm modal takes the question text and both button labels as parameters. LLR-174.2 gains an arm that builds it with a quit question and the labels "Quit (y)" / "Stay (n)". HLR-177 and LLR-177.1 state that quit asks through that modal, with its own text and the focus on No.
- **Closes:** C-UX-4, ARCH-PDR-4.
- **Why:** one modal for both questions keeps one key contract. A second modal would duplicate it in Inc 12.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-4, ARCH-PDR-4.

### LED-2026-10-26-batch-100.39 — PDR seal: an idle bar keeps its row
- **Requirement:** HLR-176, LLR-176.1
- **Date:** 2026-10-26
- **What changed:** "the bar is hidden" becomes "the bar is cleared". When idle, the bar is empty and keeps its row. LLR-176.1 gains an idle arm: the bar's row height equals its busy height, and `#log_line_1` stays at the same `y`.
- **Closes:** C-UX-7.
- **Why:** a bar that appears and disappears moves the log lines under the reader at every action.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-7.

### LED-2026-10-26-batch-100.40 — PDR seal: a recent row shows path and kind only; VS-PA-5 reconciled
- **Requirement:** HLR-173, LLR-173.4, LLR-173.6
- **Date:** 2026-10-26
- **What changed:** a recent row shows its path and kind from the store, plus "checked when loaded". It shows no size, no last-seen time and no `●`, and makes no stat before Enter. VS-PA-5 now marks only project, file and work-area rows with `●`. LLR-173.4's arm asserts the painted text (path + kind + `checked when loaded`, 0 `●`). LLR-173.6 states that a recent row carries no `●`.
- **Closes:** C-UX-8, and the conflict between VS-PA-5's `●` on every row kind and LLR-173.4 / LLR-173.6's no-read rule. The no-read rule wins, because a mark needs a read.
- **Why:** a size or a mark on a recent row needs a filesystem call before Enter, which LLR-173.4 forbids.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-UX-8.

### LED-2026-10-26-batch-100.41 — PDR seal: an autouse isolation of the recent store, plus a guard on the real store
- **Requirement:** LLR-172.1
- **Date:** 2026-10-26
- **What changed:** an autouse fixture in `tests/conftest.py` points `LOCALAPPDATA` at `tmp_path` for every test (Inc 9a). LLR-172.1 gains a guard: the real `%LOCALAPPDATA%\s19_app\recent_sources.json` keeps its digest, or stays absent, after a full test run.
- **Closes:** C-QA-2.
- **Why:** a per-test redirect misses every test that loads a source without asking for it, and those tests would write the operator's real recents.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-QA-2.

### LED-2026-10-26-batch-100.42 — PDR seal: the E4 builders state who may write `project.json`
- **Requirement:** HLR-167, HLR-168, HLR-169, HLR-170, HLR-171
- **Date:** 2026-10-26
- **What changed:** the §3 preface states two rules. The E4 project builders say which of them may write `project.json`: only the damaged, legacy and hostile cases. An output-then-consume AT takes its `project.json` only from the shipped handler. These are the HLRs whose ATs consume a saved project.
- **Closes:** C-QA-4.
- **Why:** an AT that hand-writes the manifest it then loads tests the builder, not the save.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-QA-4.

### LED-2026-10-26-batch-100.43 — PDR seal: the save-plan budget is measured on the Windows development host
- **Requirement:** LLR-175.4
- **Date:** 2026-10-26
- **What changed:** "within 2 s on the CI host" becomes "within 2 s on the Windows development host". The budget is still an assumption, measured there at Inc 11 and recorded in the packet.
- **Closes:** C-QA-5.
- **Why:** the batch has no CI host for the TUI timing arm. The host where the operator runs the app is the one that matters.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-QA-5.

### LED-2026-10-26-batch-100.44 — PDR seal: Windows-only arms skip by name; junctions via `_winapi.CreateJunction`
- **Requirement:** LLR-163.1, LLR-171.1, LLR-171.4
- **Date:** 2026-10-26
- **What changed:** a "Platform arms" paragraph in the §3 preface. Windows-only arms (junctions, links, case-insensitive names) skip on other platforms with a named reason, and the packet counts and names every skip. Junctions are made with `_winapi.CreateJunction`. These are the LLRs that carry such arms.
- **Closes:** C-QA-6.
- **Why:** a silent skip reads as a pass, and creating a junction without the documented call needs elevation or a shell.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` C-QA-6.

### LED-2026-10-26-batch-100.45 — PDR seal: `plan_project_save` takes the key list as input from Inc 5
- **Requirement:** LLR-167.6
- **Date:** 2026-10-26
- **What changed:** the manifest-key list is an input of `plan_project_save` from Inc 5, and the app passes the keys it writes. The function does not change when Inc 7 or Inc 8a adds a key.
- **Closes:** ARCH-PDR-1.
- **Why:** the plan would otherwise be edited at every key-adding increment, and those increments are already near the file cap.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` ARCH-PDR-1.

### LED-2026-10-26-batch-100.46 — PDR seal: the dialog's marks and preview come from `app.py`
- **Requirement:** LLR-173.6
- **Date:** 2026-10-26
- **What changed:** the dialog gets its `●` marks and preview from `app.py`, through a callback or message to the app, which runs the manifest read on an app-side worker. `screens.py` imports no service module, and the Inc 9b import census confirms it.
- **Closes:** ARCH-PDR-2.
- **Why:** a view → service edge would break the layering that `docs/ARCHITECTURE.md` keeps between screens and services.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` ARCH-PDR-2.

### LED-2026-10-26-batch-100.47 — PDR seal: TC-B100-55's "first variant by name" arm moves to Inc 7
- **Requirement:** LLR-178.1
- **Date:** 2026-10-26
- **What changed:** the mutation arm "compares with the first variant by name" is written at Inc 7, where `derived_from` exists. Inc 6 keeps the reasons and the counts. The §5.3 index has a TC-B100-55 row for this split.
- **Closes:** ARCH-PDR-3.
- **Why:** at Inc 6 there is no `derived_from`, so the arm could not tell the right base from the first one.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` ARCH-PDR-3.

### LED-2026-10-26-batch-100.48 — PDR seal: the `derived_from` field names are fixed in the Inc 7 packet
- **Requirement:** LLR-168.4
- **Date:** 2026-10-26
- **What changed:** the JSON field names of a `derived_from` record are fixed in the Inc 7 packet and frozen with B100-I16.
- **Closes:** ARCH-PDR-5.
- **Why:** later increments (8a, 9b, 11) read these names, so they need one fixed point.
- **Evidence:** `design/PDR-2026-10-26-batch-100.md` ARCH-PDR-5.

### LED-2026-10-26-batch-100.49 — Inc 1 gate: containment is judged on the unresolved destination; the group is a second placement kind
- **Requirement:** LLR-163.1
- **Date:** 2026-10-26
- **What changed:**
  - In LLR-163.1, `contained_in_workarea` takes the work-area root from the destination as the caller gave it, before any resolution. That is either the nearest `.s19tool/workarea` ancestor of the unresolved path, or a root an app-level caller passes explicitly. Only then are the root and the destination resolved and compared, and every caller passes the unresolved destination.
  - `place_group_into_workarea` is named as the second placement kind. It keeps its frozen reuse rule (R30) and goes through the same destination guard.
  - The AST threshold becomes one claim loop per placement kind (2), with three junction arms: the export, the group, and Save project's gather.
  - Inc 1's file set adds `project_gather_service.py`, for 4 files (⚠ at cap). The gather is a writer that resolves before the guard, and the guard must see its destination unresolved.
- **Closes:** code-reviewer Inc 1 F1, F2 and F7.
  - F1 (HIGH): the S-02 escape is still live through the export, the group and the gather. The reviewer executed it.
  - F2: a root taken from the destination itself was near-tautological.
  - F7: the "1 claim loop" wording was false while the group keeps its own loop.
- **Why:** this is the batch-99 S-02 / H-9 class. A guard that resolves the path first cannot see the junction it exists to refuse. The orchestrator ruled on F2 under the batch's standing authorization.
- **Evidence:** `03-increments/review-increment-001.md` F1, F2, F7.

### LED-2026-10-26-batch-100.50 — Inc 1 gate round 2: app paths stay unresolved, app callers pass the root, the guard walks to the outermost anchor
- **Requirement:** LLR-163.1, LLR-171.4
- **Date:** 2026-10-26
- **What changed:**
  - **App paths stay unresolved.** `current_project_dir` is stored as the path under `self.workarea`, not as `project_dir.resolve()` (`app.py:8506`). Save project builds its target the same way, with no `.resolve()` (`app.py:8135`). Every destination the app hands on therefore still shows any junction under the work area.
  - **App callers pass the root.** Every placement call in `app.py` (9 sites) passes `workarea_root=self.workarea`. `copy_into_workarea` and `place_group_into_workarea` gain that keyword, and the export and the gather thread it through. An AST census arm checks that every `app.py` placement call names the root.
  - **The guard walks to the outermost anchor.** When no root is passed, the reparse walk extends to the OUTERMOST `.s19tool/workarea` anchor of the unresolved destination, not just the nearest one. This closes the nested-anchor escape (N1).
  - **No bare `OSError`.** An invalid path spelling raises the containment refusal, not a bare `OSError` (SEC-2).
  - **New arms:**
    - each app route places into a resolved junction target and gets 0 bytes outside: the variant append, the Save project copies, the MAC/A2L syncs, the gather and the export;
    - a nested-anchor arm.
  - The file set is unchanged: `workspace.py`, `segment_split_view.py`, `app.py`, `project_gather_service.py` (4 ⚠).
- **Closes:** security-reviewer Inc 1 SEC-1 (HIGH: the escape still works with resolved app paths; executed), SEC-2 (MINOR), and code-reviewer round 2 N1 (MAJOR: nested-anchor bypass; executed).
- **Not closed here (routed):** the remaining placement callers `changes/apply.py`, `operations/crc.py`, `services/flow_execution_service.py` and `services/flow_persistence_service.py` would each need a fifth-to-eighth source file to pass the root explicitly. They receive their destinations from the app, which are now unresolved, so the derived-root guard with the outermost-anchor walk covers them. Passing the root explicitly in those four files goes to `BACKLOG-CODE.md` §Routed 2026-10-26 batch-100 as defence in depth. SEC-3 (a false refusal when the work area itself sits under a junction, not run) goes to the backlog too.
- **Why:** the guard can only know "this app's work area" if it is told the root or sees the path before resolution. The orchestrator ruled under the batch's standing authorization to do both within the 4-file cap. Making the root mandatory in all 8 calling files would break the cap.
- **Evidence:** `03-increments/security-increment-001.md` SEC-1..3; `03-increments/review-increment-001.md` Round 2 N1.

### LED-2026-10-26-batch-100.51 — Interim notice: a project load names the unsaved Patch Editor entries it discards (Inc 3 → Inc 10)
- **Requirement:** LLR-165.3
- **Date:** 2026-10-26
- **What changed:** From Inc 3 until Inc 10, a project load whose outgoing Patch Editor document holds N > 0 unsaved entries writes this status line: `Discarded N unsaved Patch Editor entries`. Inc 10's question (LLR-174.x) replaces the line, and its test arm is re-pinned there.
- **Closes:** the interim exposure of QA-03 (P2 round 1). Inc 3's reset rebinds the change service, and every increment lands on `main`, so between Inc 3 and Inc 10 unsaved editor entries would be dropped with no trace. Before the batch they leaked into the next project.
- **Why:** this is the orchestrator's ruling under the batch's standing authorization ("never lose silently"). The status line already exists, and no new glyph or pane is added.
- **Evidence:** `02-review.md` QA-03; ARQ §2.3.

### LED-2026-10-26-batch-100.52 — Inc 2 gate: the open project's name ignores case; a failed save removes the files it placed; "P2 open" means another project
- **Requirement:** LLR-164.2, LLR-164.4
- **Date:** 2026-10-26
- **What changed:**
  - **(a)** When a project is open, a typed name equal to its on-disk folder name ignoring case, or to its unsanitised form, is a save into that open project under its ON-DISK name. `current_project` keeps the on-disk spelling and no folder is renamed. A case-only match against ANOTHER project is still a disguised clash.
  - **(b)** A failed Save project removes every file it placed during that save, including in a folder that already existed. It also restores the app's variant set and current variant to their state before the save. Only the full merge carry of `gathered` and `active_document` stays at Inc 8a.
  - **(c)** HLR-164's acceptance phrase "P2 open" means another project (E4's P2, `prg.s19`) is open. AT-B100-02 drives that case by keys.
- **Closes:** code-reviewer Inc 2 F1 (HIGH: app state points at the deleted folder after a failed save), F4, F5 and F7, and security-reviewer Inc 2 SEC2-3.
- **Why:** the operator's rule is that nothing is lost or altered silently. A failed save must leave the app and the disk exactly as they were. These are orchestrator rulings under the batch's standing authorization.
- **Evidence:** `03-increments/review-increment-002.md` F1, F4, F5, F7; `03-increments/security-increment-002.md` SEC2-3.

### LED-2026-10-26-batch-100.53 — Inc 2 redesign: a failed save removes exactly what it created, never "what the snapshot lacks"
- **Requirement:** LLR-164.4
- **Date:** 2026-10-26
- **What changed:** LED .52 (b) is narrowed. A failed Save project removes exactly the files THIS save created and nothing else:
  - the placements whose `PlacementResult.reused` is False;
  - the files the gather wrote. `GatherOutcome` gains the list of files it actually wrote, not those it reused.
  - It also removes the folders this save created, if they end up empty.
  - The rollback walks no folder to decide what to delete. The recursive tree snapshot is dropped from the rollback.
  - `walk_tree_no_links` stays in `workspace.py` for Inc 8b's save-as (LLR-171.1).
  - The app-state restore of LED .52 (b) is unchanged.
  - Inc 2's file set adds `project_gather_service.py`, for 3 files.
- **Closes:**
  - security-reviewer Inc 2 round 3 SEC2-5 (MAJOR): an incomplete snapshot (an unreadable folder) led the rollback to delete pre-existing user files. Executed: `ab/patches/keep.json` was deleted.
  - SEC2-6: a file another writer added during the save was deleted.
  - Both close by construction.
- **Why:** the operator's decision at the stop that the bounded pass triggered ("Lista exacta"). It was asked at the gate on 2026-10-26.
- **Evidence:** `03-increments/security-increment-002.md` Round 3; `03-increments/review-increment-002.md` Round 4.

### LED-2026-10-26-batch-100.54 — Inc 2 gate: a failed manifest restore must never lose the previous project.json (→ Inc 7); the gather reuse rule moved into Inc 2
- **Requirement:** LLR-164.4, LLR-169.7
- **Date:** 2026-10-27
- **What changed:**
  - **(a) The manifest restore never loses the previous bytes (lands at Inc 7, which already rewrites manifest staging under O-11).** When a failed save's rollback cannot restore the previous `project.json`, the previous bytes are never lost silently. Example causes: another process holds the file, or the disk is full.
    - The restore retries `os.replace` on `PermissionError`, the same way placement does.
    - If the retry also fails, the previous bytes are written to a claimed `project.json.previous-<UTC timestamp>` beside the manifest.
    - The status names the change and the location of that copy.
    - Arms: a held `project.json` during the rollback, and staging out of space. Each one is RED first.
  - **(b) The gather's byte-identity rule moved into Inc 2.** The ARQ census had assigned it to Inc 5. It was converted in Inc 2: `_gather_copy` places through `place_into_workarea`, which is the only judge of reuse, and `_same_artifact_name` is retired. Inc 5 no longer owns it.
- **Closes:** security-reviewer Inc 2 round 5 SEC2-10 (MAJOR, needs two failures in one save, executed) is routed by (a). code-reviewer Inc 2 round 6 R6-2 is closed by (b).
- **Why:** this is the operator's rule that nothing is lost silently. The exposure between Inc 2 and Inc 7 needs a save failure followed by a restore failure in the same save.
- **Evidence:** `03-increments/security-increment-002.md` Round 5; `03-increments/review-increment-002.md` Round 6.

### LED-2026-10-26-batch-100.55 — Inc 3 gate: the interim notice states only what is known; the reset clears the panel's dirty marker
- **Requirement:** LLR-165.3
- **Date:** 2026-10-27
- **What changed:**
  - **(a)** LED .51's interim wording becomes `Closed the Patch Editor document (N entries); unsaved changes were not kept`, painted when the outgoing document holds N > 0 entries. Inc 3 cannot read the panel's dirty flag: it is private, and its public reader arrives at Inc 10 (`screens_directionb.py`). So until then the line never claims that the N entries were unsaved. Inc 10 replaces it with the question, keyed on the dirty flag.
  - **(b)** The reset seam calls the panel's public `mark_loaded()`. This clears the dirty marker and the paste buffer, so after a project load the Patch panel no longer shows `0 entries ●` and no later guard asks about nothing.
- **Closes:** code-reviewer Inc 3 F2 (MAJOR: N counted saved entries as unsaved; executed) and F3 (MAJOR: the panel stayed dirty on an empty ledger; probed by keys).
- **Why:** the operator's rule that nothing is said or lost falsely. These are orchestrator rulings under the batch's standing authorization.
- **Evidence:** `03-increments/review-increment-003.md` F2, F3.

### LED-2026-10-26-batch-100.56 — Inc 5 file set: the save-back emit stages inside this work area (SEC-4)
- **Requirement:** LLR-167.7
- **Date:** 2026-10-27
- **What changed:** Inc 5 adds `s19_app/tui/changes/apply.py`, which brings it to 4 files (⚠ at the cap). `save_patched_image` currently resolves `dest_dir` internally to choose its staging root (`apply.py` ≈741, ≈885). The staging root must come from `_guarded_destination(dest_dir, workarea_root)`, and the emit passes `workarea_root`. A save-back or Save project emit with a junction project open then creates no `temp/` or `temp/.staging/` in another work area. Arm: with a junction project open, a save-back leaves 0 entries in the other work area.
- **Closes:** security-reviewer Inc 1 round 2 SEC-4 (MAJOR, executed), routed to Inc 5 at the Inc 1 gate.
- **Why:** Inc 5 already splits `save_patched` (LLR-167.7), so the emit path is open there.
- **Evidence:** `03-increments/security-increment-001.md` Round 2 SEC-4.

### LED-2026-10-26-batch-100.57 — Inc 4 gate: focus targets must be focusable and visible; persistent chrome inputs are never taken; judge the default screen
- **Requirement:** LLR-166.1
- **Date:** 2026-10-27
- **What changed:**
  - **(a) Targets.** Every focus target is focusable (`can_focus` True). The registry assertion checks focusability as well as membership.
  - **(b) Fallback.** When the window's declared target has region area 0 or is not displayed (an empty-state window), the focus goes to the window's first visible, focusable, non-text widget. If there is none, it goes to the rail's active entry. The rail is always visible and keeps keys reaching the app bindings.
  - **(c) Persistent chrome.** The re-home never takes the focus from a visible persistent-chrome text field with area > 0, such as `#palette_input` or the Find field. The text-input rule applies only to text fields inside content windows that the load left stale (hidden, or area 0).
  - **(d) Focus source.** The rule reads `default_screen.focused`, never `self.focused`, so a widget inside an open modal is never judged or moved.
- **Closes:** code-reviewer Inc 4 F1 (HIGH, two unfocusable targets left P-16 on Diff; executed), F5 (empty-state targets with area 0), F6 (typing in the palette or Find lost its focus), and the reviewer's modal recommendation ahead of Inc 6/9b/10.
- **Why:** these are orchestrator rulings under the batch's standing authorization. The focus must land where the user can work, and must never be taken from where the user is working.
- **Evidence:** `03-increments/review-increment-004.md` F1, F5, F6, check 2.

### LED-2026-10-26-batch-100.58 — Inc 4 gate round 2: Map keeps the LLR-116.5 row; only stale text inputs are re-homed
- **Requirement:** LLR-166.1
- **Date:** 2026-10-27
- **What changed:**
  - **(a) Map.** On Map, the landing after a load is the region row that batch-77 LLR-116.5 auto-selects and focuses, because the up/down walk lives on that row. No re-assertion moves focus off a `RegionRow`, whether LLR-116.5 put it there or the user chose it. HLR-166's "named widget" for Map is that row.
  - **(b) Re-assertion removed.** The general deferred re-assertion goes. If a timing gap still needs covering, it must not apply to a widget the window's own requirement focuses.
  - **(c) Stale text inputs only.** LED .57 (c) is applied as written: the rule re-homes a text input only when it is stale (in a hidden window, or of area 0). A visible text input in the active window, such as a per-window Find, keeps its focus.
- **Closes:** code-reviewer Inc 4 round 2 R2-1 (HIGH: after every load the Map arrows did nothing, against LLR-116.5; executed on three trees) and R2-2 (MAJOR: a visible Find field was taken, against LED .57 (c)).
- **Why:** a requirement that already shipped wins over a new landing rule. These are orchestrator rulings under the batch's standing authorization.
- **Evidence:** `03-increments/review-increment-004.md` Round 2; scratchpad `r4/probe-map-arrows.txt`.


### LED-2026-10-26-batch-100.59 — Inc 4 gate round 3: no widget type is exempt from the stale rule; a hidden Map row is re-homed
- **Requirement:** LLR-166.1
- **Date:** 2026-10-29
- **What changed:**
  - **Amends LED .58 (a).** The Map landing is still the LLR-116.5 row. It needs no exemption: a row in the displayed Map window paints a region, so the stale rule leaves it alone. The `RegionRow` exemption in `_focus_needs_rehome` is removed. A row left holding the focus in a HIDDEN Map window (area 0, still swallowing `up`/`down`/`enter`) is re-homed like any other stale widget.
  - **Simplification.** The separate `Input`/`TextArea` branch is removed. It repeated the generic stale rule exactly, and mutant R2 survived because of it. LED .58 (c) holds through the generic rule.
- **Closes:** code-reviewer Inc 4 round 3 R3-1 (MAJOR: the exemption kept a hidden row focused after an A2L load; no test needed it — mutant RG passed 31/31) and the R2 equivalent survivor.
- **Why:** the exemption's comment claimed Textual clears a hidden row's focus; the reviewer's probe showed it does not. Orchestrator ruling under the batch's standing authorization; the reviewer stated an exact fix needs no re-read.
- **Evidence:** `03-increments/review-increment-004.md` Round 3; `evidence/inc-4/red-07-r3-1-hidden-map-row.txt` (RED with the exemption), `evidence/inc-4/green-21-r3-final-focus-tuiapp.txt`.

### LED-2026-10-26-batch-100.60 — Hotfix 3b: the reset clears the paste buffer without marking the Patch Editor dirty
- **Requirement:** LLR-165.3
- **Date:** 2026-10-29
- **What changed:**
  - **Defect.** Inc 3's reset emptied `#patch_paste_text` by assigning its text. That posted `TextArea.Changed`, and the panel's handler (writer w2) set the dirty flag. The `mark_loaded` meant to clear it was deferred with `call_after_refresh`, and in the fresh-session path it ran before the bubbled message was handled. So after any project load, the next Patch Load raised the dirty-load question with nothing unsaved, and the document did not load.
  - **Fix.** `PatchEditorPanel.clear_paste_buffer()` (public, `screens_directionb.py`) clears the buffer with `TextArea.Changed` prevented and repaints the gauge and heading. The reset calls it and then `mark_loaded()` synchronously. LED .55 (b)'s outcome (buffer empty, no dirty marker) is unchanged; only its mechanism changes. `screens_directionb.py` is edited one increment before Inc 10, for this one method.
- **Closes:** the 5 batch-97 nodes red on main since the Inc 3 merge: `test_b97_chips_help.py::test_at_b97_14_…[patch]` (stopped on `LoadGuardScreen`) and `test_b97_width.py::test_at_b97_15_…[size0]`, `[size1]`, `test_at_b97_16_…`, `test_at_b97_24_…`. They failed in CI from run 40497466178 on, and locally on 6d8631a.
- **Why it escaped:** Inc 3's reverse census was a symbol grep that did not reach the batch-97 files, and nobody compared the failed-node set of the post-merge CI runs with the run before. The operator chose "Hotfix ahora" on 2026-10-29.
- **Evidence:** `03-increments/increment-015.md` (hotfix 3b, numbered out of sequence); `03-increments/review-increment-015.md`; `evidence/inc-3b/`.

### LED-2026-10-26-batch-100.61 — Inc 5: the panel's `mark_saved` and TC-B100-70's positive arm move to Inc 8a
- **Requirement:** LLR-167.8
- **Date:** 2026-10-29
- **What changed:**
  - LLR-167.8 binds only after a Save project that **wrote the change or check document into the project**. In Inc 5, Save project writes no editor document; the pasted-document write is Inc 8a (LLR-170.2). The gather copies only the document's on-disk file, and that file differs from the editor's document whenever the panel is dirty.
  - So in Inc 5, Save project calls `ChangeService.mark_saved` (the image record) and does NOT call `PatchEditorPanel.mark_saved`. Clearing the panel's flag here would hide unsaved document edits, and a later Patch Load would then replace them without asking (a silent-loss path).
  - TC-B100-70 in Inc 5 keeps its refused arm and adds an arm that pins "document not written → flag kept". The positive arm (entry added → Save project → project load → 0 questions) and the panel `mark_saved` call move to Inc 8a, which writes the document.
- **Closes:** the Inc 5 implementer's STOP item (`HANDOFF.md`, "LLR-167.8 panel `mark_saved`").
- **Why:** losing no user work outranks a premature clean flag. Orchestrator ruling under the batch's standing authorization.
- **Evidence:** `03-increments/increment-005.md` (when written); Inc 8a brief carries the positive arm.

### LED-2026-10-26-batch-100.62 — Inc 5: B100-I15 re-frozen with `ranges` and `session_map`
- **Requirement:** HLR-167 (B100-I15, the `save_patched` split)
- **Date:** 2026-10-29
- **What changed:** `ChangeService.rederive_for_save` takes two more required keywords than the frozen form: `ranges` (the apply needs them) and `session_map` (the journal binds by dict identity, and a copy has none; without it a newly loaded image could take the previous image's source bytes). The public helpers the packet lists in §6 (`image_differs_from_source`, `mark_saved`, `differs_from_last_saved`, `record_save_entries`, `rederived_differs_from_source`, `apply.render_patched_image`) are part of the frozen interface, each with a named caller. Code-review F7 is resolved in corrective pass 1: the new pure `ChangeService.save_entry_split()` (wrapped by `record_save_entries()`) is added to the frozen interface; the decide step writes no service state, and the handler records the split on the line before `emit_and_verify` (a precondition its docstring states). A save that rolls back keeps its own split in `last_save_*`; both readers record before reading, so the stale value is never shown.
- **Why:** the independent code-reviewer ruled the deviation justified, not scope creep (`review-increment-005.md`, ruling 1).
- **Evidence:** `03-increments/increment-005.md` §6; `03-increments/review-increment-005.md`.

### LED-2026-10-26-batch-100.63 — Inc 5: the save plan is partial until Inc 7, 8a and 8b
- **Requirement:** HLR-167, LLR-167.6, TC-B100-59
- **Date:** 2026-10-29
- **What changed:** In Inc 5 the plan names the image and the files Save project copies; it has no rows for gathered sub-folders or merges. Until Inc 7, 8a and 8b land, (a) the gather still writes files the plan does not name, so HLR-167's "every file … the plan names" is not yet true for a project with gathered content, and (b) the single-MAC and single-A2L refusals still run after the project folder exists, with the existing rollback removing it.
- **Why:** declared TC-B100-59 split; the code-reviewer accepted it on condition of these two lines (ruling 3).
- **Evidence:** `03-increments/review-increment-005.md`.

### LED-2026-10-26-batch-100.64 — Inc 5: LLR-167.3 counts on two status lines
- **Requirement:** LLR-167.3
- **Date:** 2026-10-29
- **What changed:** The verify line carries `save_back_status_suffix` (document entries); the success line carries "N change entries, K applied by this save" (summary dispositions). The two count different things. The success line's image clause comes after the full project path and the status log caps each line at the terminal width, so the clause is clipped whenever the path is long (at 118 columns, and also at 220 with a deep path; code-review R2-1). The verify line still names the entries. Moving the counts before the path goes to the UX pass of Inc 11; until then the TC-B100-16 nodes and AT-B100-05 read the full `set_status` message, so they do not depend on the path's length (Inc 5 corrective pass 2).
- **Why:** threshold met at 220 columns; code-reviewer ruling 2.
- **Evidence:** `03-increments/review-increment-005.md`.

### LED-2026-10-26-batch-100.65 — Inc 5 security notes routed: SEC-8 to Inc 11, SEC-9 to the LED .50 backlog item
- **Requirement:** LLR-171.4 (containment)
- **Date:** 2026-10-29
- **What changed:** SEC-8 (pre-existing, not made worse): Save project creates the project folder before any containment guard; through a junction a folder briefly exists outside this work area and the rollback removes it (net 0). Fix (`_guarded_destination(project_dir, self.workarea)` before decide, plan and `mkdir`) goes to Inc 11, which owns Save project's dialog. SEC-9 (pre-existing): `variant_execution_service.py:797` calls `save_patched_image` without `workarea_root`; added to the LED .50 backlog item. SEC-7 is the same defect as code-review F1 and is fixed in the Inc 5 corrective pass.
- **Why:** `security-increment-005.md` (PASS-WITH-NOTES, SEC-4 discharged).
- **Evidence:** `03-increments/security-increment-005.md`; `evidence/inc-5/sec/`.

### LED-2026-10-26-batch-100.66 — Inc 5 leftovers assigned to Inc 8b, Inc 11 and the LED .50 backlog item
- **Requirement:** HLR-167, LLR-171.4
- **Date:** 2026-10-29
- **What changed:**
  - **Inc 8b:** the single-MAC and single-A2L refusals move before the project folder is created (LED .63 (b)). Inc 8b closes the save plan, so the refusal becomes a plan-time decision there.
  - **Inc 11:** a Save project arm that emits through a junction project (only the save-back has one today; code-review hand-off to `security-reviewer`). It lands with SEC-8 (LED .65), which moves the containment check before `mkdir` in the same handler.
  - **LED .50 backlog item:** `flow_execution_service` still passes `workarea_root=None`, which Inc 5 made stricter (a junction destination as written is refused). The security confirmation the code-reviewer asked for goes with SEC-9 in that item.
- **Why:** none of the three had a named owner after the Inc 5 gate. The operator approved the assignment on 2026-10-29.
- **Evidence:** `03-increments/review-increment-005.md` (hand-offs), `03-increments/security-increment-005.md`.

### LED-2026-10-26-batch-100.67 — Inc 6 OQ-1: a writer creates a missing project.json and never rewrites a damaged one
- **Requirement:** HLR-168, LLR-168.3
- **Date:** 2026-10-29
- **What changed:** (a) In a project folder with no `project.json`, an in-project writer (save-back, variant append, MAC sync, A2L sync) creates one, as HLR-168 reads literally; Execute in such a project then moves from the "no manifest" fallback to "manifest present". (b) A damaged `project.json` (not JSON — including an integer over Python's digit limit —, top level not an object, over the size cap, or unreadable) is never rewritten by those four writers: the placed file stays, the rewrite is skipped and one status line says the manifest is damaged and was not rewritten. The session's active variant is then the new file while disk still records the old one; the status line says why. Save project, the explicit user command, stays the recovery path that replaces a damaged manifest.
- **Why:** the implementer's open question OQ-1; orchestrator ruling under the standing authorization. Both reviewers found (b) violated in the first cut (code-review F1, SEC6-1, HIGH); fixed in Inc 6 corrective pass 1 and re-verified (12/12 byte-identical).
- **Evidence:** `03-increments/increment-006.md` §5/§6; `03-increments/review-increment-006.md`; `03-increments/security-increment-006.md`.

### LED-2026-10-26-batch-100.68 — Inc 6 leftovers routed to Inc 7, Inc 9b, Inc 11 and the LED .50 backlog item
- **Requirement:** HLR-168, LLR-178.3, LLR-171.4
- **Date:** 2026-10-29
- **What changed:**
  - **Inc 7:** SEC6-2 (a rewrite drops unknown top-level keys, writes `schema_version` 1 over a higher one, and drops skipped entries, silently) lands with the manifest-keys mode; SEC6-5 (the panel builds one row per problem with no cap: 6 000 bad entries froze load and panel for 10.2 s) lands with Inc 7's caps and the one-problem-per-file rule, with an explicit test arm; the panel's error-colour "not readable" mark of the P-E verdict B lands with HLR-169's readability state.
  - **Inc 9b:** the summary line's `details: p` points at the Load dialog's preview of the open project (LLR-178.3, last sentence), which Inc 9b builds; until then `p` opens the dialog without it.
  - **Inc 11:** code-review F4 — the seam's `Project saved + manifest verified` line now also follows the MAC and A2L syncs and the variant append, where "Project saved" reads wrong.
  - **Inc 7 (re-routed at the Inc 6 close; first routed to the LED .50 backlog item):** SEC6-3 (pre-existing, now reachable from four more writers) — `manifest_writer._check_destination_contained` resolves before it checks, so a project folder swapped for a junction between placement and the manifest write lands the manifest in another work area; the fix (`_guarded_destination` on the unresolved destination) needs a fifth source file. Inc 7 owns `manifest_writer.py` and its design (§5.7, SEC PDR-C1) already has `_check_destination_contained` call `contained_in_workarea`, so the fix needs no fifth file there.
  - **Accepted deviation:** `tests/test_import_census.py::MEASURED_SAFE_TEXT_CONSUMERS` gained `s19_app.tui.screens` (the panel renders disk names through `safe_text`, LLR-178.3), measured in as the guard's own comment prescribes instead of stopping; both reviewers accepted it.
  - **Not exercised:** POSIX limits of `Path.resolve()` (long entries, symlink loops) — only Windows ran.
- **Why:** none had a named owner after the Inc 6 gate; code-review and security round reports.
- **Evidence:** `03-increments/review-increment-006.md`; `03-increments/security-increment-006.md`; `evidence/inc-6/e13/` (real-terminal captures read against P-E verdict B).

### LED-2026-10-26-batch-100.69 — Inc 7 OQ-7a: LLR-169.9's "load errors" means fatal load errors
- **Requirement:** LLR-169.9
- **Date:** 2026-10-30
- **What changed:** `not readable` applies only to a project image whose install yields no data (an empty `mem_map`) or that does not parse as S19 or HEX. LLR-169.9 says "an image whose install reports load errors"; that is read as *fatal* load errors. An image that installs with data but carries record-level errors (bad checksums, `examples/case_04_bad_checksums`) stays open, is not a `not readable` problem, and its errors show on the loaded file where the app showed them before this batch. The statement's wording is not rewritten; this entry is the reading.
- **Why:** viewing a file with checksum errors is a primary use of the tool; refusing to open it would be a regression. Orchestrator ruling OQ-7a, 2026-10-30, on the implementer's open question.
- **Evidence:** `03-increments/increment-007.md` §6 (OQ-7a); arms `test_tc_b100_61_checksum_errors_only_keep_the_image_open` and `test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on`; mutants `OQ-7a-record-errors` and `OQ-7a-empty` KILLED (`evidence/inc-7/mut-OQ-7a-record-errors.txt`, `evidence/inc-7/mut-OQ-7a-empty.txt`).

### LED-2026-10-26-batch-100.70 — Inc 7 close: the corrective-pass-2 verification was cut by the operator; the remaining runs go to Inc 8a's validation
- **Requirement:** HLR-169
- **Date:** 2026-10-30
- **What changed:** corrective pass 2 (round-2 findings R2-1 to R2-4 and SEC7-R2-1 to SEC7-R2-4) finished its code and ran part of its chain on the final tree: RED 15 failed / 2 passed, the cp2 arms 17 passed, the touched modules 379 passed, the reviewers' probes 10 passed / 1 failed (Q2 = R2-3, backlog), 50 of 50 mutants KILLED and restored. The operator then cut the remaining runs to move to Inc 8a. They are **not run** and are routed to Inc 8a's validation: (1) the 31-module reverse census on the final tree (`census-tree-cp2.txt` stopped at about 29 %, no failure so far); (2) the guards and the census sweep on the final `app.py` bytes (the cp2 runs, 75 + 87 passed, are on the previous bytes); (3) the security probes re-run (`sec-probes-cp2.txt` is empty); (4) round-3 code and security review of the cp2 diff. The Inc 7 packet marks checklist row 5 (reverse census) as not met and row 6 (`code-reviewer`) as partial; neither is marked met.
- **Why:** operator decision at the Inc 7 close, 2026-10-30.
- **Evidence:** `03-increments/increment-007.md` §4 (Corrective pass 2 — results), §4b, §7; `evidence/inc-7/` (`red-cp2-vs-cp1-tree.txt`, `green-cp2-arms.txt`, `green-cp2-touched-modules.txt`, `review-probes-cp2.txt`, `mut-cp2-*`, `guards-cp2.txt`, `guards-census-cp2.txt`, `census-tree-cp2.txt`, `sec-probes-cp2.txt`).

### LED-2026-10-26-batch-100.71 — Inc 6 CI-6-1: the overlong-entry rule is decided on the text (fixed in Inc 7)
- **Requirement:** LLR-169.4, LLR-169.8
- **Date:** 2026-10-30
- **What changed:** Inc 6's CI on Linux had three new failures. The rule that skips an overlong manifest entry depended on `Path.resolve()` raising `ValueError`, which Windows does for a 40 000-character path and POSIX does not. Now an entry longer than `MANIFEST_ENTRY_MAX_CHARS = 32 767` characters (the Windows path maximum) is one skipped entry (`MANIFEST-PATH-ESCAPE`, "a file path is not a plain name in the project") on the text, in every mode and on every platform, before any filesystem call; the `OSError` / `ValueError` / `RuntimeError` fallback stays. On POSIX an entry over that length in a flow reference (the default mode) is now skipped instead of carried. A third CI node (`test_tc_b100_20_append_says_now_opens_only_after_the_write`) had a different root cause (a POSIX `rename` replaces a read-only file): it now skips off Windows with a named reason and has an any-platform sibling that forces `os.replace` onto `project.json` to raise `PermissionError`.
- **Why:** orchestrator item at the Inc 6 close (the Linux CI result); a rule that depends on the platform's error is not a rule.
- **Evidence:** `03-increments/increment-007.md` §6 (CI-6-1); `test_tc_b100_67_overlong_entry_is_decided_on_the_text` RED at base (`evidence/inc-7/red-04-ci-6-1-vs-base.txt`), mutant `CI-6-1` KILLED (`evidence/inc-7/mut-CI-6-1.txt`). Reasoned for Linux, not executed there; the orchestrator confirms on a Linux CI run.

### LED-2026-10-26-batch-100.72 — Inc 8a E1 — requirements review (EARS / ISO 29148)
- **Requirement:** HLR-170, LLR-170.1, LLR-170.2, LLR-170.3, LLR-167.8, LLR-164.2, LLR-167.6, LLR-169.2, LLR-169.3, LLR-169.4, LLR-169.5, LLR-178.1; §5.3
- **Date:** 2026-10-30
- **What changed:** each Inc 8a requirement was checked for one EARS form and the ISO/IEC/IEEE 29148 characteristics (necessary, unambiguous, complete, singular, feasible, verifiable, correct, conforming). Ids and structure are kept. Changes (id: before → after — why):
  - **HLR-170:** a pasted document is written as `patches/changes.json` → as `changes.json` in the home for its kind; adds the unwanted case "if the document cannot be written, then Save project completes without it, records no `active_document` and names the unsaved document in the status"; boundary `☐ error` → `☒ error` (failed write) — the HLR said `checks/` by kind in one clause and `patches/` in the next (ambiguous), and the write-failure path was missing (complete).
  - **LLR-170.1:** two "shall"s (writer, reader) → one ubiquitous statement about the key's form, enforced by one predicate at both ends (S-11); adds the writer's refusal for a value outside the form and states that `active_document` is a known top-level key (SEC6-2); threshold "with an active document, `files` holds 4 keys" → removed here, made exact in LLR-169.2 (5 keys); adds writer, `checks/`, `patches/x.txt` and carry arms; 2 more mutants — singular; the old count could not tell an active-document record from a fifth top-level file (unambiguous, verifiable; Code-Wire baseline item 1); the writer side had no unwanted-behaviour clause; today the key is unknown and all four carry writers refuse the rewrite (C2).
  - **LLR-170.2:** no trigger → event-driven ("When Save project runs while the Patch Editor holds a document with at least one entry and no `source_path`"); `patches/` only → the home for its kind; line citations (`changes/io.py:146` is the constant `DEFAULT_CHANGE_FILE_NAME`, `:400`, `:369` stale) → symbols; the gather names a reused in-home document (C3); adds the write-failure outcome (save completes, no key, one status line) and the rollback of a created document; threshold adds check-document, identical-reuse, 0-entry, failed-write and failure-after-write arms; 2 mutants — EARS form, correct citations (baseline item 2), complete failure paths.
  - **LLR-170.3:** two "shall"s → one event-driven statement with exactly one of two outcomes; names `ChangeService.load` with the project's `a2l_context`, loaded after that A2L (no context when there is no A2L); `missing` is owned by `check_project_files`, the load adds only `not readable` (one-problem-per-file, LLR-169.9); a document with entry issues loads and is not a load problem; threshold adds no-A2L, unreadable, dirty-flag-clear and exact problem counts; mutants: no `a2l_context` / before the A2L (C1: no app caller passes it today), a double report — "after the A2L is attached" did not say the context is passed, so the order alone could not make the symbol arm pass (feasible, verifiable; baseline item 4); two owners of `missing` would collide with LLR-169.9 (baseline item 3); "unreadable" was undefined.
  - **LLR-169.5:** adds the Inc 8a arm: a recorded `active_document` absent from disk → 1 `missing`, with and without a `files` record — the owner named in LLR-170.3 needs a threshold.
  - **LLR-167.8:** "After …, shall call the panel's `mark_saved` and `ChangeService.mark_saved`" → "When a Save project completes after the app wrote the editor's document, … shall clear the panel's dirty flag through `PatchEditorPanel.mark_saved`"; a refused/rolled-back save, a failed write and a file-backed document copied while the panel holds unsaved edits leave the flag set; `ChangeService.mark_saved` → a pointer to LLR-167.5 — two actions (singular); the file-backed dirty case would clear the flag over edits no file holds (the LED .61 silent-loss path). Threshold "→ a project load → 0 questions" → the panel flag and a following Patch Editor Load (0 `LoadGuardScreen` pushes), 4 arms; the project-load question arm moves to Inc 10 — at Inc 8a there is no project-load question (LLR-174.1 is Inc 10) and the project-load reset clears the flag itself (LED .55 (b)), so the old threshold and its mutant could not fail. `test_tc_b100_70_unwritten_document_keeps_the_flag` is re-pinned at Inc 8a (C5).
  - **LLR-164.2:** "the target's document [is] untouched" → "the target's document file is untouched (a session document is placed beside it and recorded, HLR-170)"; the Inc 8a carry threshold states `gathered` = target entries + this save's rows (0 dropped) and `active_document` carried when the session holds no document, the session's placed document when it holds one; 1 mutant — the merge's carry conflicted with HLR-170, which records the session's document on every Save project (correct, unambiguous).
  - **LLR-167.6:** "extended at Inc 8a (the document row)" → exact document-row and merge arms (landing, action word, 0 differences, digest as input, `manifest_keys` holding `active_document` exactly when written) — the 8a arm had no threshold (verifiable).
  - **LLR-169.2:** "The active-document arm runs at Inc 8a (TC-B100-28)" → the arm with numbers: 4 top-level files + `patches/boost.json` = 5 keys, a non-active `patches/other.json` absent, a recorded document missing on disk → no record, 0 raises; 1 mutant — baseline item 1 (exact count) and A-15.
  - **LLR-169.3:** adds the `active_document` drift arm (1 mismatch) and its mutant — the boundary catalog named the case, the threshold did not.
  - **LLR-169.4:** adds the Inc 8a arm: the `files` key equal to the accepted `active_document` → 1 record, 0 issues; a non-active `patches/other.json` → 1 `MANIFEST-BAD-STRUCTURE`; 1 mutant — today that key is refused (C2).
  - **LLR-178.1 (OBS-7-1):** "when the base is a file of the project (name and SHA-256 match)" → "(a `files` record of the manifest has its name and SHA-256; the composer is pure and reads no disk, so a manifest with no `files` gives the next form — OBS-7-1)". OBS-7-1 stays an observation: no code change and no new requirement. The app always writes `files` with `derived_from`, so only a hand-made manifest reaches it, and that manifest also shows `no digests saved`. The wording now matches the pure composer.
  - **§5.3:** TC arm rows added for TC-B100-70, -20, -22, -23 and -24 (the Inc 8a arms above).
  - **Not written as requirements (E5/E6):** LED .70's deferred Inc 7 verification (full reverse census on the final tree, the guards and the census sweep on the final `app.py` bytes, the security probes, round-3 review of the cp2 diff) belongs to Inc 8a's validation.
- **Why:** experiment step E1 (`experiment-8a/PLAN.md`): each 8a requirement gets one EARS form, a numeric threshold and a negative control that can fail. Items 1–4, C1–C3 and C5 came from the parallel Code-Wire baseline (`experiment-8a/codewire/baseline-notes.md`). These are rulings under the batch's standing authorization; the open questions are listed in `experiment-8a/E1-scope.md` §4 for E3.
- **Evidence:** `experiment-8a/E1-scope.md`; `git diff` of `01-requirements.md` on branch `b100-inc8a`.
- **Addendum (orchestrator, 2026-10-30, E1 §4 decisions):** Q1 a pasted document is bound to its landing after the first write, later saves replace it in place (LLR-170.2); Q2 an unparsed paste buffer keeps the panel flag (LLR-167.8); Q3 the document row's action is `replace` (different bytes) or `keep` (equal bytes) (LLR-167.6); Q5 the no-`a2l_context` mutation is the primary control; Q6 the reopen never re-applies entries (LLR-170.3). Q4 (deferred A2L steps after the reopen) is checked by a probe in E2. Why: each closes a behaviour the requirements left open that the design review (E3) would otherwise have to guess; Q6 prevents a double patch.

### LED-2026-10-26-batch-100.73 — Inc 8a E3 round 1 — design review rulings
- **Requirement:** LLR-170.2, LLR-167.6, LLR-167.8, LLR-164.2, LLR-170.3, LLR-169.5
- **Date:** 2026-10-30
- **What changed:** the orchestrator's rulings R1–R7 after the architect review (FAIL, 5 MAJOR) and the security review (FAIL, 4 MAJOR) of the Inc 8a design. Ids and structure are kept. Changes (id: before → after — why):
  - **LLR-170.2 (R1):** the Q1 sentence "a second Save project with an edit replaces `P/patches/changes.json` in place → 1 file under `patches/`, 0 `changes_1.json`; mutation leaving the document unbound → 2 files → RED" → "Save project never overwrites a file that already exists in the project; a second Save project of the bound document with edits writes nothing for the document, keeps the flag and paints 1 status line naming the Patch Editor save; 1 file under `patches/`, bytes unchanged; a mutation rewriting it in place → 2 writes or a changed byte → RED"; adds that a file-backed document already in the target's home is recorded as on disk and not written, and one from outside is copied — the in-place rewrite broke LLR-155.3 (a placed file is immutable), could delete a user file in the rollback and write through a junction (E3-security S3-2, S3-3, S3-4, S3-5, S3-10; E3-architect A3-4).
  - **LLR-167.6 (R1):** "the document row's action is `replace` when the landing exists with different bytes and `keep` when equal" → "`new` when the document is written or copied this save and `keep` when it is recorded as already in its home; never `replace`; the always-`new` mutation is RED on the `keep` arm" — follows the withdrawal of the in-place rewrite.
  - **LLR-167.8 (R1):** the file-backed arm "a file-backed document with 1 entry added after its load → True" now also holds on the natural path (Load P → add 1 entry → Save project into P: recorded as on disk, not written, flag True); 4 arms → 5 — A3-4: the natural fixture would have given False.
  - **LLR-164.2 (R2, R3, R5):** the carry "unchanged when the session holds no document" → "while its file exists"; adds R2 (Save project into an open project or a merge drops a carried `active_document` whose file is absent, with 1 status line naming it), R3 (a session document that was not placed counts as no session document: the target's value is carried plus the one status line), R5 (a refused target `active_document` is a skipped entry: `project.json.previous-<UTC>` kept, the status names the copy and the dropped value); 3 more mutants — a `missing` row's "Save project to drop it" had no way to drop (A3-2), the text set two outcomes for a failed write (A3-3), a merge silently discarded a refused value (S3-6).
  - **LLR-170.3 (R4):** adds the reopen caps (1 MiB, 1 000 entries, checked before the parse) → exactly 1 `not readable` ("too large to reopen"), the project still loads, Load and panel under 1 s; mutant: caps removed → a 20 000-entry document takes more than 1 s → RED — the automatic reopen took 33 s at 20 000 entries (probe P1 in E3-security; S3-1).
  - **LLR-169.5 (R7):** adds the arm "a missing variant id `boost` with a document `patches/boost.json` present → the missing problem names the variant's data file, never the document" and the mutant dropping the primary-data-suffix restriction → RED — the change to `_missing_recorded` had no requirement (A3-11).
  - **Not requirement changes:** R6 (painted text in user terms, control characters refused by `is_active_document_form`, amends pre-ruling 1) and the prototype edits live in the three `codewire/proto-8a-*.md` files and `interfaces-8a.md`. R6's example is a design example for E4, not a new threshold.
  - **Superseded:** pre-ruling 9 of `interfaces-8a.md` (in-place `replace`) and the LED .72 Q3 `replace` sentence, by R1.
- **Why:** step E3 of `experiment-8a/PLAN.md` ends with no open MAJOR; these rulings close the nine MAJOR findings (A3-1 … A3-5, S3-1 … S3-4) and the findings that follow from them. They are rulings under the batch's standing authorization.
- **Evidence:** `experiment-8a/E3-rulings.md`, `experiment-8a/E3-architect.md`, `experiment-8a/E3-security.md`; `git diff` of `01-requirements.md` on branch `b100-inc8a`.

### LED-2026-10-26-batch-100.74 — Inc 8a E3 round 2 — design review rulings
- **Requirement:** HLR-170, LLR-170.2, LLR-164.2, LLR-170.3, LLR-167.6; the "Save plan" definition (§1.3)
- **Date:** 2026-10-30
- **What changed:** the orchestrator's round-2 rulings R8 (refined), R9 and R10–R14 after the round-2 architect review (FAIL: A3R2-1, A3R2-2 MAJOR) and security review (FAIL: S3R2-1, S3R2-3 MAJOR) of the Inc 8a design. Ids and structure are kept. Changes (id: before → after — why):
  - **HLR-170 (R9, R3, R11):** "while the Patch Editor holds a document with at least one entry" → "holds a document — a pasted document with at least one entry, or a file-backed document whatever its entry count (E3 R9)"; "If the document cannot be written, then Save project shall complete without it, record no `active_document`" → "cannot be written or placed … record no `active_document` of its own (a merge or an open-project save carries the target's value, LLR-164.2; E3 R3)"; the threshold's failed-write arm gains the same qualifier; boundary catalog "a document with 0 entries (not recorded)" → "a pasted document with 0 entries (not recorded)", "a file-backed document already in `P/patches/` (reused, M-1)" → "(recorded as on disk, `keep`, E3 R1)", plus "a file-backed document with 0 entries (recorded, E3 R9)" — the statement contradicted LLR-164.2's R3 carry and left the 0-entry file-backed path with no requirement (E3-architect A3R2-3, A3R2-9).
  - **LLR-170.2 (R3, R9):** "no `active_document` recorded" (statement and the forced-write-failure arm) → "no `active_document` of its own … (a merge or an open-project save carries the target's value, LLR-164.2; E3 R3)"; adds the arm "a file-backed document with 0 entries → 1 file, recorded as `active_document` (E3 R9)"; "0 entries → 0 files" → "a pasted document with 0 entries → 0 files"; the negative control "recording `active_document` after a failed write" → "recording the failed document as `active_document`" — same reason (A3R2-3).
  - **LLR-164.2 (R8 refined, R10, R11):** "carried unchanged, while its file exists on disk" → "carried unchanged, unless Save project drops it"; "drops a carried `active_document` whose file is absent from disk" → "classifies it with LLR-170.3's one classifier and drops it when its file is absent, a link, or present but not readable (`missing`, `link`, `unreadable`) … the recovery of the `missing` and `not readable` rows; keeps it on `too_large` and `io_error` (1 status line for `io_error`)", with the arms 1 500 pasted entries → Save → Load → Save → kept, and a never-loaded merge target recording 20 000 entries → under 1 s, not parsed, kept; "not placed" now also covers a file-backed document inside the project but outside its home, gone, or a link (R11); 3 more mutants (carrying an `unreadable` value → RED; dropping a `too_large` value → RED; Save project's check without the caps → more than 1 s → RED) — R8 was ruled after round 1 and the design said the opposite; the plain "not readable" drop would also drop the app's own over-cap document or a locked file, and a check without the caps brought the 33 s parse back into Save project (A3R2-2, S3R2-1, S3R2-2).
  - **LLR-170.3 (R10):** "loaded through `ChangeService.load`" → "loaded into the session's `ChangeService`, parsed … (the parse of the classifier's bytes, not a second read)"; adds the classifier order (two `lstat`, 1 MiB cap, one bounded read, guarded decode and count only for a list, parse of the same bytes; the exception set → `not readable`, never a raise; `OSError` → "could not be read now"; the record stays); threshold arms: 1 MiB of `[` → exactly 1 `not readable`, 0 raises, Load completes under 1 s; `{"entries": 5}` → `not readable`, not "too large"; a link → `not readable`, 0 bytes read through it; a locked file → `not readable`, record kept; mutant: catch set without `RecursionError` → raises → RED; boundary catalog + 3 — the pre-parse count raised `RecursionError` / `TypeError` on hostile input (probe P2), which would make such a project impossible to load, and the count and the load read the file twice (S3R2-3, S3R2-4).
  - **LLR-167.6 (R11, A3R2-1, A3R2-9):** action words "`new`, `replace`, `keep`, `merge`, `rewrite`" → "`new`, `keep`, `merge`, `rewrite`; `replace` is not produced through Inc 8a"; "a file-backed document → 1 row with its landing name" → "a file-backed document that is placed or recorded → 1 row; one the gather does not place (inside the project but outside its home, its source gone, or its source a link) → 0 document rows and the save completes"; 2 mutants (no `inside_elsewhere` class → 1 row with no file → RED; the document digest's `OSError` propagated → "Project NOT saved" → RED) — the planner and the gather disagreed on such a document, and the new digest refused the whole save (A3R2-1).
  - **§1.3 "Save plan" (A3R2-9):** the action-word list drops `replace` with the same note — no increment through Inc 8a produces it.
  - **Not requirement changes:** R10's classifier node (`recorded_document_state`), R11's gather classifier (`classify_active_document`), R12 (the bind stores the unresolved `project_dir / home / name`), R13 (`gathered` carried for a merge only), A3R2-4 … A3R2-8 and S3R2-4 … S3R2-8 live in the three `codewire/proto-8a-*.md` files and `interfaces-8a.md`.
  - **Open, not changed here:** the shared `not readable` next-step token "replace the file, or Save project to drop it" (`01-requirements.md`, the token table row "problem: not readable") does not hold for `too_large` and `io_error`, which R8 refined keeps; HLR-175's statement still names `replace` as an action word. Both need an orchestrator decision.
- **Why:** step E3 of `experiment-8a/PLAN.md` ends with no open MAJOR; these rulings close A3R2-1, A3R2-2, S3R2-1 and S3R2-3 and the findings that follow from them. They are rulings under the batch's standing authorization.
- **Evidence:** `experiment-8a/E3-rulings.md` ("E3 round 2 — orchestrator rulings"), `experiment-8a/E3-architect.md` ("## Round 2"), `experiment-8a/E3-security.md` ("## Round 2"); `git diff` of `01-requirements.md` on branch `b100-inc8a`.
- **Addendum (orchestrator, 2026-10-30):** §3 token table gains two `not readable` rows for the active document — `too large to reopen` → `open it from the Patch Editor`, `in use by another program` → `close the program holding it and Load again` — because R8 refined keeps those records, so `Save project to drop it` would be false for them. HLR-175's `replace` stays: the document row never produces it, other plan rows are outside 8a.
- **Addendum (orchestrator, 2026-10-30, E3 round 3):** design approved (architect and security PASS-WITH-NOTES, 0 HIGH / 0 MAJOR). R15–R19 (`experiment-8a/E3-rulings.md`) are implemented in E4: carried-record line painted at commit only when written (LLR-164.2); one `io_error` reason `could not be read` / `check that the file can be opened, then Load again` and the `too_large` step `open it from the Patch Editor (it can take a while)` (§3 rows amended); file-level codes only make a document unreadable (LLR-170.3); the gather passes the unresolved source and the classifier checks the source's parent (LLR-170.2); `ValueError` in the catch set (LLR-170.3).

### LED-2026-10-26-batch-100.75 — Inc 8a close: the design-first experiment, the per-increment test scope, the Inc 7 deferred items, F4, R20
- **Requirement:** HLR-170, LLR-170.1, LLR-170.2, LLR-170.3, LLR-167.6, LLR-167.8, LLR-164.2, LLR-168.3, LLR-169.2, LLR-169.3, LLR-169.4, LLR-169.5
- **Date:** 2026-10-30
- **What changed:** Inc 8a closes (HLR-170: the change document is recorded as `active_document` and reopened). Decisions recorded at the close:
  - **The experiment.** Inc 8a ran as the design-first pipeline of `experiment-8a/PLAN.md`: E1 requirements (LED .72) -> E2 Code-Wire prototype, graph only, no source change -> E3 code-free design review by an architect and a security reviewer, three rounds (LED .73, .74; R1-R19) -> E4 parallel build and tester -> E5 change validation (mutants, code review, security review, one corrective pass). The step table with times is in `03-increments/increment-008.md` §4 (from `experiment-8a/steps.log`). The comparison with Inc 7 (wall time, where each MAJOR was found, corrective passes) stays an observation for the operator; nothing was added to the flow during the run.
  - **Per-increment test scope (operator ruling, 2026-10-30).** For each increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. No reverse census and no full suite per increment. The full battery runs once, when all increments are done (the batch-end list is in `increment-008.md` §7). This is a process decision: the Inc 8a packet marks the reverse-census checklist row as not run per increment, never as met.
  - **Inc 7 deferred items (LED .70).** (1) Round-3 code and security review of Inc 7 corrective pass 2: DONE in Inc 8a E5 (both reviewers, tag `inc7-cp2`, closed; the findings F9 and SEC8a-5 were fixed in the 8a corrective pass). (2) Inc 7 security probes re-run: DONE (`evidence/inc-8a/security/inc7-rerun/`; SEC7-R2-1 to SEC7-R2-4 closed by executed probes). (3) Guards on Inc 7's final bytes: covered by the Inc 8a guards (75 passed, 29 snapshots; the tree contains them). (4) Inc 7 full reverse census: MOVED to the batch-end full battery.
  - **F4 (LLR-167.6).** The code reviewer's probe Q4 spies the plan predicted before the write; the pass settles the plan after the outcome is known (`_plan_without_document_key`). The orchestrator and the code reviewer (round 2) accept this as meeting LLR-167.6. LLR-167.6's threshold gains one clause: the plan's key list is settled after the write outcome is known (Inc 8a F4).
  - **R20 (E3-rulings, E5 pre-ruling).** The problem row of a refused or unreadable `active_document` is labelled `change document <text>`, so it never merges with a data file of the same name (`active_document: "firmware.s19"` must not paint `not readable firmware.s19` against an image that opened). Out-of-form reason: `the recorded change document path is not one the app can use`. Applied in the 8a corrective pass.
  - **Model observation.** A Sonnet design pass (E3-fix) truncated `proto-8a-writer-gather.md` twice and rebuilt it from its own `cat -n` output; round 2 found content lost in the rebuild (A3R2-5). The design pass was redone on Opus (E3-fix2, no line loss). Design work moved to Opus; the Sonnet use stays limited to mechanical work.
  - **Backlog added** (`.dev-flow/BACKLOG-CODE.md`): R2-1, R2-2, SEC8a-2, the `parse_change_document` "never raises" contract bug (R19), the undo depth after the reopen (A-R14), and the R-12 not-run mutant. Known CI flake recorded: `tests/test_b97_flow_execution.py::test_tc_b97_64_a_new_set_run_restarts_the_dwell` failed once in CI (Inc 7 run 41121137306) and passed 3 of 3 locally on `dc3b314`.
- **Why:** closes the experiment and the Inc 7 carry-over with one record, so the next increment starts from a stated process (per-increment scope, batch-end battery).
- **Evidence:** `03-increments/increment-008.md` (§4, §4b, §6, §7); `03-increments/review-increment-008.md`; `03-increments/security-increment-008.md`; `experiment-8a/steps.log`, `E3-rulings.md`, `E5-cp1-notes.md`; `evidence/inc-8a/` (`red-01-vs-base.txt`, `green-01-new-and-touched.txt`, `guards-01.txt`, `mutation-summary.md`, `cp1/`, `review/`, `security/`, `e13/`).
- **Addendum (orchestrator, 2026-10-30):** packet numbering — Inc 8a's packet and review records are `03-increments/increment-008.md`, `review-increment-008.md`, `security-increment-008.md` (the evidence tool and the validator read `increment-NNN.md` only); Inc 8b will take the next free number, `increment-016.md` (015 is the Inc 3 hotfix). Evidence stays under `evidence/inc-8a/`.

### LED-2026-10-26-batch-100.76 — Inc 8b E1 — requirements to strict EARS / ISO 29148
- **Requirement:** HLR-171, HLR-171a (new), HLR-171b (new), LLR-171.1 (+ .1a–.1f new), LLR-171.2 (+ .2a–.2e new), LLR-171.3 (+ .3a new), LLR-171.4 (+ .4a–.4j new), LLR-171.5 (new), LLR-167.6 (+ .6a–.6e new); §1.3 "Work area"; §5.3
- **Date:** 2026-10-30
- **What changed:** each Inc 8b requirement was rewritten to the operator's strict standard: one EARS sentence in one of the five forms, one "shall", every failure path its own unwanted-behaviour requirement, a numeric pass threshold and a negative control each, checked against ISO/IEC/IEEE 29148 (necessary, unambiguous, complete, singular, feasible, verifiable, correct, conforming). Function names moved from the statements to the trace. Existing ids kept; a split keeps the id for the first part and adds a suffix; nothing renumbered. Changes (id: before → after — why):
  - **HLR-171:** one compound statement (save as, A2L-only load, containment of every placement, link folders, foreign parent; 5 "shall"s) → "When Save project saves the open project into a new project folder, the system shall make the new project hold every regular file of the open project's sub-folders that is not reached through a link or junction"; acceptance keeps AT-B100-09 only — singular; the old text mixed three behaviours with three ATs.
  - **HLR-171a (new, split from HLR-171):** "When a project folder that holds one A2L file and no data file is loaded, the system shall open that project with its A2L attached"; AT-B100-10 — singular.
  - **HLR-171b (new, split from HLR-171):** "The system shall treat a folder as a project only when that folder is not a link or junction and resolves inside this work area"; AT-B100-11 — singular; the claim "no writer is left off a list" is dropped from the HLR because it holds only for placing writers (Code-Wire C1); the writers are now named one by one in LLR-171.4h–.4j.
  - **LLR-171.1:** one statement with 4 behaviours (link-pruned walk, total, free-space refusal, copy and skip listing) and a stale citation (`workspace.py:172`) → event "copy each regular file under the open project's sub-folders, at every depth, to the same project-relative path in the new project folder"; threshold adds the nested file and the no-open-project case — singular, correct citations (by symbol).
  - **LLR-171.1a (new):** state "not descend into a directory that is a symbolic link or junction", with a junction-cycle arm (under 5 s) — split from LLR-171.1; mutant: the Python 3.11 junction read without the reparse re-check.
  - **LLR-171.1b (new):** state "not copy a file that is a symbolic link"; feasibility note: a test that cannot create a file link is reported not run — split.
  - **LLR-171.1c (new):** event "name that link's project-relative path in the Save project status" (3 of 3, read from the whole `set_status` message, LED .64) — split; the plan half is LLR-167.6b.
  - **LLR-171.1d (new):** ubiquitous "exclude every byte reached through a link or junction from the save-as size total", measured black-box through the free-space boundary — split; "one walk gives both" was a design statement.
  - **LLR-171.1e (new):** unwanted "if the total exceeds the free space …, refuse with the `not enough free space` tokens before creating the project folder"; boundary arm at exactly the free space; mutants: check after `mkdir`, `>=` — split; the boundary had no threshold.
  - **LLR-171.1f (new):** ubiquitous "not modify, add or remove any file of the open project" — the old threshold arm "P → 0 changed digests" had no statement.
  - **LLR-171.2:** one statement with 5 actions and an implementation recipe (`_variant_set = build_variant_set(name, [])`) plus 2 refusals → event "attach that A2L file to the session"; the attach path and the expected A2L file are left open (Q4, Code-Wire C4) — singular, implementation-free.
  - **LLR-171.2a, .2b, .2c (new):** the reset (previous data file removed), the open project set, and the later data-file load recorded in `project.json` (A-14, state form) — each split out with its own mutant.
  - **LLR-171.2d, .2e (new):** the two refusals (`no data or A2L file` with `project.json`; `no project.json` without) as unwanted requirements — every failure path its own requirement.
  - **LLR-171.3:** cited `screens.py:144-176`; control "P-11 accepted" → unwanted "refuse the save before creating any folder", threshold measured by a `mkdir` spy (0 calls), plus a parent below the work area; control re-based on `ebe6d0c`: the foreign parent is refused only after `mkdir` + rollback (1 call) — Code-Wire C2: "0 folders" alone already holds on base, so the old control could not fail.
  - **LLR-171.3a (new):** event "the work area under a different spelling … save into this work area" — split from LLR-171.3's threshold.
  - **LLR-171.4:** one statement with 6 "shall"s (predicate, placement, manifest seam, listing, load, link checks) → ubiquitous predicate only (Inc 1, done) — singular.
  - **LLR-171.4a, .4b (new):** the placement refusal and the manifest-seam refusal (both Inc 1, done; LED .28) — split, so the 8b arms do not hide behind arms already met.
  - **LLR-171.4c, .4d (new):** the listing leaves out a link folder, and a folder resolving outside — split; .4d has no independent RED (declared double mutant, Q6).
  - **LLR-171.4e, .4f (new):** the load refuses a link folder, and a folder resolving outside (`..` arm gives .4f its own RED); "picked or typed" → picked only, the typed arm is LLR-172.5 at Inc 9a — Code-Wire caller 1: no typed load path exists at `ebe6d0c`.
  - **LLR-171.4g (new):** the Save target link check before `resolve()`, with the `link or junction` tokens (implemented at Inc 2, owed as AT-B100-11's arm) — split.
  - **LLR-171.4h (new):** the 8-writer arm as its own ubiquitous requirement (16 junction arms, 8 normal arms) — split; §5.3 said "the 7 writers" while LLR-171.4 said 8 (LED .28 added the manifest seam): corrected to 8.
  - **LLR-171.4i, .4j (new):** SEC-5 (`security-increment-001.md`, routed to Inc 8b in `security-increment-005.md`): the flow and flowset writers refuse a folder outside this work area — the finding asked to add them to LLR-171.4's list by a ledger entry; their increment is pending Q1 (a fourth source file).
  - **LLR-171.5 (new):** BACKLOG-CODE R2-1: "if Save project copies a file whose project-relative path `project.json` cannot record, then paint one status line naming it" — the backlog item tied to Inc 8b had no requirement.
  - **LLR-167.6:** "extended at Inc 8b (save-as with sub-folders)" (no threshold) → a pointer to LLR-167.6a–e; ledger line + .76 — the 8b arm was not verifiable.
  - **LLR-167.6a, .6b (new):** one plan row per top-level sub-folder with its file count; the skipped links listed in the plan (equal to LLR-171.1c's) — split from LLR-167.6's statement.
  - **LLR-167.6c, .6d (new):** LED .63 (b) / LED .66: the single-MAC and single-A2L refusals decided in the plan, measured by a `mkdir` spy (0 calls) and 0 rollback runs — the routing had no EARS requirement, and "0 folders" cannot fail because the rollback already leaves none (coordinator input 1). .6d copies today's A2L rule unchanged (Q3, Code-Wire C3).
  - **LLR-167.6e (new):** ubiquitous "at most one plan row per landing path" — Code-Wire C5: the save-as copy and the document row both land `patches/boost.json` in Q, which would give TC-B100-59 two rows for one path; the owner is an E2 seam.
  - **§1.3 "Work area":** `app.py:8519-8524` → `list_projects` (by symbol) — stale citation.
  - **§5.3:** TC-B100-59 and TC-B100-62 rows name the new ids; "the 7 writers" → "the 8 writers".
- **Why:** step E1 of the design-first pipeline (`design-first-increment` skill) for Inc 8b. Items C1–C5, caller 1 and the stale citations came from the parallel Code-Wire baseline (`inc-8b/codewire/baseline-notes.md`) through the coordinator. These are E1 rulings under the batch's standing authorization; decisions the requirements leave open are listed in `inc-8b/E1-scope.md` §4 for the orchestrator.
- **Evidence:** `inc-8b/E1-scope.md`; `inc-8b/codewire/baseline-notes.md`; `git diff` of `01-requirements.md` on branch `b100-inc8b`.

### LED-2026-10-26-batch-100.77 — Inc 8b E1 — orchestrator rulings on the E1 open questions Q1–Q11
- **Requirement:** HLR-171, HLR-171a, HLR-171b, LLR-171.1d, LLR-171.1e, LLR-171.1g (new), LLR-171.1h (new), LLR-171.1i (new), LLR-171.2, LLR-171.4c, LLR-171.4d (withdrawn), LLR-171.4i, LLR-171.4j, LLR-167.6, LLR-167.6a, LLR-167.6b, LLR-167.6d, LLR-167.6f (new), LLR-167.6g (new); §5.3
- **Date:** 2026-10-30
- **What changed:** the orchestrator ruled on the eleven questions of `inc-8b/E1-scope.md` §4, and E1 applied the rulings to the same strict EARS / ISO 29148 standard as LED .76. Ids are kept, new ones take a suffix, and nothing is deleted. Changes (ruling: id — before → after):
  - **Q1 (SEC-5 and the non-placing writers OUT of 8b):** LLR-171.4i, .4j — "increment pending Q1" → "Not in Inc 8b: routed to the LED .50 backlog item and `.dev-flow/BACKLOG-CODE.md`". Their statements stay, as the record of SEC-5's requirement. The chain-set save, the three report writers and the report-filter folder (Code-Wire C1) go to the same item. HLR-171b's decomposition and the §5.3 TC-B100-62 row say so. Inc 8b sources: `app.py`, `project_gather_service.py` (+ `workspace.py` only if a helper is needed).
  - **Q2 (a save into an existing project copies no sub-folder):** LLR-171.1g (new, state) "While the Save project target is an existing project folder, the system shall not copy the open project's sub-folders into it"; merge and save-into-itself arms. LLR-171.1's threshold now points to it.
  - **Q3 (the A2L refusal exempts the open project's own A2L):** LLR-167.6d — "the session holds an A2L file" → "the session holds an A2L file other than it" (not the same path, and not the same name with the same bytes); LLR-167.6f (new, event) holds the exemption, with the arm "A2L-only project saved into itself twice → 2 saves, 0 refusals" and the name-only mutant.
  - **Q4 (A2L-only attaches its own file in place):** LLR-171.2 — "attach that A2L file" → "attach that project's A2L file, in place"; arms: the session's A2L path is `workarea/P/firmware.a2l`, 0 files under `workarea/temp`; mutant: the Load-file A2L path → temp copy or self-refusal. HLR-171a's threshold gains the same clause.
  - **Q5 (tokens):** no token-table change in E1. E2 drafts the rows and E3 confirms them; the placeholder list is in `inc-8b/E1-scope.md` §4. The references in LLR-171.3, .4e and .4f now say this.
  - **Q6 (drop LLR-171.4d):** LLR-171.4d → "Withdrawn: merged into LLR-171.4c" (id kept, not reused); LLR-171.4c already holds its arm (`workarea/evil` → 0 rows).
  - **Q7 (save as carries the records):** LLR-171.1h (new, event): the new project's `project.json` carries the open project's `batch`, `assignments`, `declared_regions`, `gathered` and `active_document` as project-relative paths. `files` keeps its scope (LLR-169.2). With a session Patch Editor document, HLR-170's landing wins.
  - **Q8 (the total counts every byte):** LLR-171.1i (new, ubiquitous): the top-level files, the emitted image and the sub-folder files; LLR-171.1d and .1e now refer to it for T.
  - **Q9 (plan row granularity):** LLR-167.6a — one row per top-level sub-folder with its recursive count; a links-only sub-folder → 1 row with 0 files (+1 mutant). LLR-167.6b lists that sub-folder's junction against its row.
  - **Q10 (per-file cap):** LLR-167.6g (new, unwanted): a file over the placement's per-file cap (256 MiB shipped; lowered in the test) → a plan refusal naming it, 0 `mkdir` calls; base `ebe6d0c` raises after `mkdir` → RED.
  - **Q11 (Execute on an A2L-only project OUT of 8b):** no requirement. It goes to the backlog; E3 only checks that Execute does not crash on such a project.
- **Why:** the orchestrator's rulings close the decisions E1 left open, so E2 designs against settled behaviour. These are rulings under the batch's standing authorization.
- **Evidence:** `inc-8b/E1-scope.md` (§1 and §3 updated, §4 now the rulings and the Q5 placeholder list); `git diff` of `01-requirements.md` on branch `b100-inc8b`.

### LED-2026-10-26-batch-100.78 — Inc 8b E3 round 1 — design review rulings
- **Requirement:** HLR-171, HLR-171a, LLR-167.6c, LLR-171.1, LLR-171.1c, LLR-171.1e, LLR-171.1h, LLR-171.1i, LLR-171.1j (new), LLR-171.1k (new), LLR-171.1l (new), LLR-171.1m (new), LLR-171.2d, LLR-171.2f (new), LLR-171.2g (new), LLR-171.4f, LLR-171.5, LLR-171.6 (new), LLR-171.6a (new), LLR-171.6b (new), LLR-171.7 (new), LLR-171.7a (new), LLR-171.7b (new); §1.3 "Project"; §3 refusal-token table
- **Date:** 2026-10-30
- **What changed:** the orchestrator's rulings R1–R9 and the reviewer items accepted as written, after the architect review (FAIL, 3 MAJOR: A3-1, A3-2, A3-3) and the security review (FAIL, 1 MAJOR: S3-1) of the Inc 8b design. Same strict EARS / ISO 29148 standard as LED .76: one "shall", one of the five forms, a threshold and a negative control each. Ids are kept, new ones take a suffix, nothing is renumbered or deleted. Changes (ruling: id — before → after — why):
  - **R1 (S3-1):** LLR-171.1j (new, unwanted) — "if the files a save as would copy number more than 2 000, or an entry lies more than 32 path components deep, refuse, naming the limit, before creating the project folder"; arms 2 000 / 2 001 files and 32 / 33 components, 0 `mkdir`; mutants: ceiling removed, `>=`, depth removed; the save's time is measured at E4, not gated — a 20 000-file save as froze the main thread for about 6 min (P1, extrapolated) and nothing bounded the count; the background copy stays with Inc 12a.
  - **R2 (A3-1):** LLR-171.1 threshold gains "the copy runs right after the project folder is created, before the first home placement and before the gather" — the pasted document was placed into an empty home and its predicted `changes_1.json` landed at `changes.json`, so the save aborted every time.
  - **R3 (A3-2):** HLR-171 — "every regular file of the open project's sub-folders that is not reached through a link" → "every regular file of the open project, at the top level and in its sub-folders, that is not reached through a link and that the save does not write itself"; LLR-171.1 — title, statement ("each regular file of the open project that the save does not write itself, at the top level and at every depth of its sub-folders") and threshold (`a.json`, `other.s19`, `notes.txt` copied byte-equal; the image and A2L once; the exclusion list), +1 mutant (sub-folders only → `Q/a.json` absent) — the carried `batch` / `assignments` name top-level files (the dialog lists only P's top-level `*.json`, `app.py:7366-7397`), which a save as did not copy.
  - **R3 / A3-2 / A3-8 / pre-ruling 9:** LLR-171.1h — 5 records → 6 (`derived_from` added, only records whose key names a top-level data file Q holds; the emitted image's key holds this save's record); the fixture moves to the dialog's form (`batch` `["a.json"]`, top-level, written by the shipped Save project) and the hand-written form `["patches/a.json"]` is withdrawn; +1 mutant (drop `derived_from`) — the old fixture could pass while the production form failed (vacuous check), and `derived_from` was lost by a save as.
  - **R4 (A3-3, C-7 confirmed):** LLR-171.6, .6a, .6b (new, event) — for every target `batch` and `assignments` are the dialog's selection when non-empty, otherwise the carried value (the open project's for a save as, the target's for an open-project save or a merge), and the gather's composition names come from the recorded `batch`; arm Load P → Save P (nothing selected) → `batch` unchanged → Save as Q → Q's `batch` = P's; base `ebe6d0c` writes the empty selection over P's `batch` (`app.py:10097-10098`, `:9932`) → RED — the save most engineers make just before a save as emptied the records LLR-171.1h carries.
  - **R5 (S3-3):** LLR-171.2f (new, unwanted) — a linked or over-cap A2L of an A2L-only folder → refused with `link or junction` / `too large to open` before the reset; LLR-171.2g (new, unwanted) — the same A2L beside a data file → the project opens without it, 1 `not readable` problem; boundary at exactly the cap; HLR-171a's decomposition names them — attaching the A2L in place dropped the link refusal and the 256 MiB cap that the Load-file route had, and the data+A2L branch already parsed in place unguarded (`app.py:11316`).
  - **R6 (S3-4):** LLR-171.7 (new, ubiquitous: names from P's tree painted without control, bidi or zero-width characters, clipped to 120), LLR-171.7a (new, event: at most 10 entries then `and K more`), LLR-171.7b (new, unwanted: a failed copy paints `could not save` / `check the folder` with no exception text); LLR-171.1c statement gains "within the 10-name limit of LLR-171.7a" and a 25-link arm; LLR-171.5 gains the 12-row arm — 5 000 junctions gave a 250 KB status line, bidi names reordered on screen (SEC8a-4 on four more paint sites), and the existing excepts painted `Refusing to copy …` and `[WinError 5]`.
  - **R7 (S3-9):** LLR-171.1i statement — "every byte the save as copies or writes" → "every file …, each rounded up to a multiple of 4 096 bytes, plus 65 536 bytes for `project.json` and the folders"; threshold re-based (source image 4 000 → emitted 5 000 so the two fall on different 4 KiB steps; T = 110 592), +2 mutants (raw sizes, no margin); LLR-171.1e's threshold names the rule — byte sums under-counted NTFS cluster allocation and left out `project.json`.
  - **R8 (A3-5, S3-2):** LLR-171.1k (new, unwanted) — an unlistable sub-folder or an entry the walk cannot classify (`lstat` fails, not a file / folder / link, or a name ending in a dot or space) → refused before any folder, naming each (10-name limit) — the walker skipped an unlistable folder silently (`workspace.py:296-299`) and a trailing-dot file was dropped with no line, so LLR-171.1's "0 missing" could be false silently. Pre-ruling 6's status line becomes this refusal.
  - **R9 (A3-11):** LLR-171.1l (new, event: the Flow panels' session folder becomes Q) and LLR-171.1m (new, event: a Patch Editor document whose file is inside P is bound to its copy in Q) — after a save as the open project was Q but the Flow panels and the document still pointed at P (`_publish_flow_session_dir` has one caller, the load, `app.py:11427`).
  - **A3-4 (accepted):** LLR-167.6c — "the session's MAC file is not one of the target's data files" (name-only) → "the session holds a MAC file other than it" (not the same path, and not the same name with the same bytes, as LLR-167.6d), + an other-bytes arm, a link-target arm (S3-8) and the name-only mutant (pre-ruling 5, DR-6); LLR-171.5 — "a gathered flow row" → "a gathered row (a composition document or the CRC template)" (pre-ruling 7: the gather has no flow limb), with the final row-8 tokens.
  - **A3-6 (accepted, R-8):** LLR-171.2d — "a project folder whose `project.json` records no missing file" → "a project folder that holds a `project.json`"; + the arm with a recorded absent `firmware.s19` → the same 1 line — the qualifier left one arm with no requirement.
  - **A3-7 (accepted):** §3 token table — 17 Inc 8b rows added (save parent, load link / outside, second MAC / A2L, the two cap rows, the R1 ceiling, the unreadable entries, the save-as source folder, copy failures, skipped links, copied-but-not-recorded, the 10-entry list, no `project.json` on load, the A2L-only A2L refusal, the `not readable` A2L problem), one wording each; row 8's next step is the true one ("rename it in the common folder, select the new name, then Save project") — G1's "rename it and Save project" recorded nothing.
  - **S3-7 (accepted):** LLR-171.4f — "resolves outside this work area" → "is not one direct child folder of this work area or resolves outside this work area"; + the `sub/P` arm (a junction above the project); the negative control moves to the one-component name check, the containment check declared as defence with no independent RED — a two-part name loaded a project through a junction, and with the name check in place the old containment mutant could not fail.
  - **A3-16 (accepted):** §1.3 "Project" gains "or an A2L file" — an A2L-only folder loads under HLR-171a.
  - **Not requirement changes:** A3-8 (the plan's `derived` flag from the source carry), A3-9 (landing in resolved form), A3-10 (AT-B100-09 removes `P/flows/f1.json` after the save), A3-12, A3-13 (refusal precedence), A3-14 (the total's rule), S3-5, S3-6, S3-8, S3-10 and the alignment to pre-rulings 1–11 live in `inc-8b/codewire/proto-8b-app.md`, `proto-8b-gather.md` and `interfaces-8b.md` ("E3 round-1 rulings applied"). Backlog: A3-15, A3-17.
  - **Open for E3 round 2 (design findings, not requirement changes):** F-7 (the R3 exclusion of P's other MAC / A2L files when the session plans one, and `project.json.previous-<UTC>` copied), F-8 (a copied top-level variant identical to the image can be reused by the image row and abort the save, loud), F-9 (R1 bounds the count, not the time).
- **Why:** step E3 of the design-first pipeline (`design-first-increment` skill) ends with no open MAJOR; these rulings close the four MAJOR findings (A3-1, A3-2, A3-3, S3-1) and the accepted MINOR / LOW items. They are rulings under the batch's standing authorization.
- **Evidence:** `inc-8b/E3-rulings.md`, `inc-8b/E3-architect.md`, `inc-8b/E3-security.md`; `inc-8b/codewire/proto-8b-app.md`, `proto-8b-gather.md`, `interfaces-8b.md`; `git diff` of `01-requirements.md` on branch `b100-inc8b`.

### LED-2026-10-26-batch-100.79 — Inc 8b E3 round 2 + R10–R13
- **Requirement:** HLR-171, LLR-167.6, LLR-171.1, LLR-171.1j, LLR-171.1k, LLR-171.1m, LLR-171.2g, LLR-171.6b, LLR-171.7; §3 refusal-token table (the R1 row); §5.3 TC index (5 rows)
- **Date:** 2026-10-30
- **What changed:** the orchestrator's rulings R10–R13 and the round-2 reviewer items accepted as written, after the architect re-review (FAIL on text only, 1 MAJOR: A3R2-1) and the security re-review (PASS-WITH-NOTES: S3R2-1 … S3R2-6). Same strict EARS / ISO 29148 standard as LED .76: one "shall", one of the five forms, a threshold and a negative control each. Ids are kept, nothing is renumbered or deleted. Changes (ruling: id — before → after — why):
  - **R10 (F-7; A3R2-2, S3R2-2):** HLR-171 and LLR-171.1 statements — "… that the save does not write itself" → "…, other than `project.json` backups (`project.json.previous-*`)"; HLR-171 threshold gains "0 of P's backups"; LLR-171.1 threshold names the backups as not copied (`normcase`), +1 mutant (exclusion removed → `Q/project.json.previous-…` present) — the backups hold values the reader refused (8a R5), and copying them spread those values to every later save as and spent the 2 000-file ceiling, whose walk stop assumed at most 5 left-out files. The companion rule (every other MAC / A2L of P left out when the session saves one) is confirmed unchanged.
  - **R11 (F-8; A3R2-1, A3R2-5):** LLR-171.1 threshold, last sentence — "the copy runs right after the project folder is created, before the first home placement and before the gather" → "the sub-folder copy runs right after the project folder is created, before the first home placement; the top-level copy runs after the image, MAC and A2L rows are placed and before the gather"; + the arm P holding `firmware_1.s19` identical to the emitted image → saved, Q holds both; +1 mutant (top-level copy before the rows loop → abort) — with the top-level copy first, the image row reused an identical `_1` variant of P and the save aborted; as written, the unchanged rows loop would also have placed every carried row a second time (A3R2-1).
  - **A3R2-6:** LLR-167.6 threshold gains "a save as with top-level copies → 1 `carried` row per copy, `new`, equal to the written tree" — G2 produces the rows and no threshold named them.
  - **R13 (S3R2-1):** LLR-171.1j statement — "files … more than 2 000, or an entry … more than 32 deep" → "files … more than 2 000, the save-as enumeration walks more than 10 000 entries, or an entry … more than 32 deep"; arms 10 000 / 10 001 entries (folders, links, unreadable entries and files), under 2 s, a 50 000-file folder never sorted whole; +1 mutant (regular files only); trace adds `walk_tree_no_links` (`max_entries`) — 20 000 empty folders took 4.70 s with 0 files counted (executed), so 200 000 folders or junctions froze the main thread for about 47 s (extrapolated) under the file-only ceiling.
  - **A3R2-3, A3R2-4:** LLR-171.6b — title "… from the recorded batch" → "… from the recorded batch and assignments"; statement adds "plus the names in the `assignments` value that LLR-171.6a records"; threshold — P's top-level `a.json` is removed too and the oracle is the `composition_names` spy plus `P/patches/a.json` reappearing; "P's `gathered` names exactly what the written `batch` names" withdrawn; + the assignments arm (`c.json`) and its mutant (recorded `batch` only) — the text dropped the assignments' documents the gather takes today (`app.py:9932-9936`, LLR-138.1), the dialog-form fixture could not turn GREEN while P's top-level `a.json` existed, and `gathered` keeps P's rows by carry, so its kill was vacuous.
  - **S3R2-3:** LLR-171.2g threshold gains the MAC arm (`firmware.mac` + linked `firmware.a2l` → 0 parse calls by spy, 1 `not readable` problem), +1 mutant (the list cleared for the install-set choice only) — the local `a2l_files` also feeds the MAC load, which parses `a2l_files[0]` (`app.py:13221-13228`).
  - **S3R2-4:** LLR-171.7 statement — "without control, bidirectional or zero-width characters" → "without characters of the Unicode categories Cc, Cf, Zl and Zp, with each unpaired surrogate replaced by U+FFFD"; + arms U+061C, U+2028, U+DC80 and the escaped log; +1 mutant (round 1's fixed list) — 151 Cf / Zl / Zp code points passed the fixed list, and an unpaired surrogate made the UTF-8 encode raise (executed).
  - **S3R2-5:** LLR-171.1m threshold gains the `..` arm (`workarea/P/../R/x.json` → binding unchanged) and the skipped-junction arm; +1 mutant (rebind after a file-exists probe) — a lexical `relative_to` keeps `..`, so a probe-based rebind bound a file of another project.
  - **S3R2-6:** LLR-171.1k threshold — "cannot classify" adds a reserved device-name stem (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `CONIN$`, `CONOUT$`); + the arm "the unlistable project folder is named `'P'`, never `.`"; +1 mutant — the refusal read ". could not be read", and an open of a device name could block the main thread.
  - **§3 token table:** the R1 row adds "a walk over 10 000 entries" with `too many files to copy` (over 10 000 entries), the same next step.
  - **§5.3 TC index (A3R2-6):** 5 rows: TC-B100-31 (LLR-171.1j, .1k), (LLR-171.1l, .1m), (LLR-171.6, .6a, .6b), (LLR-171.7, .7a, .7b); TC-B100-32 (LLR-171.2f, .2g).
  - **Not requirement changes:** the rows loop skipping `carried` rows, the second `_copy_project_subfolders` call with `carried` rows checked by `_plan_row_mismatch` (A3R2-1, A3R2-5), the walk stop at more than `SAVE_AS_FILE_CEILING + 4` counted files (R10), `max_entries` and the 100-name log limit (S3R2-1), the `%r` log form (S3R2-4) and the plan-entry rebind (S3R2-5) live in `inc-8b/codewire/proto-8b-app.md`, `proto-8b-gather.md` and `interfaces-8b.md` ("E3 round-2 rulings applied"). F-7 and F-8 of LED .78 are closed by R10 and R11; F-9 stays as ruled by R12 (measured at E4, not gated).
- **Why:** step E3 of the design-first pipeline (`design-first-increment` skill) ends with no open MAJOR; these edits write R10, R11 and R13 into the requirements and close A3R2-1 … A3R2-6. The security minors are verified at E5. They are rulings under the batch's standing authorization.
- **Evidence:** `inc-8b/E3-rulings.md` ("After design pass 1", "E3 round 2"), `inc-8b/E3-architect.md` "Round 2", `inc-8b/E3-security.md` "Round 2"; `inc-8b/codewire/proto-8b-app.md`, `proto-8b-gather.md`, `interfaces-8b.md`; `git diff` of `01-requirements.md` on branch `b100-inc8b`.

### LED-2026-10-26-batch-100.80 — Inc 8b E5 corrective pass 1
- **Requirement:** LLR-171.1h, LLR-171.1m, LLR-171.1n (new), LLR-171.1o (new), LLR-171.2g, LLR-171.2h (new), LLR-171.4f, LLR-171.5, LLR-171.7c (new); §3 refusal-token table (5 rows changed or added); §5.3 TC index (3 rows)
- **Date:** 2026-10-31
- **What changed:** the orchestrator's corrective-pass rulings on the E5 code review (FAIL, BLOCK-UNTIL F1: F1 MAJOR, F2–F7) and the E5 security review (PASS-WITH-NOTES: SEC8b-1 … SEC8b-3). Same strict EARS / ISO 29148 standard as LED .76: one "shall", one of the five forms, a threshold and a negative control each. Ids are kept, new ones take a suffix, nothing is renumbered or deleted. Changes (finding: id — before → after — why):
  - **F1 (MAJOR, design-gap):** LLR-171.1n (new, unwanted) — "If the open project's folder does not exist when Save project saves to a folder that does not exist, then the system shall save the session's files to that folder without a copy from the open project and paint one status line naming the missing folder"; arms: P moved away, saved under its own name and as Q → saved, 1 line `The open project folder 'P' was not found` … `copy them into '<target>' if you still have them`; negative control P present → 0 lines; mutant: P's folder existence ignored → RED — with P gone every new-target save was refused with an untrue next step ("could not be read … save again"), a regression against `ebe6d0c` for a save under P's own name.
  - **F3 (I-2):** LLR-171.2h (new, event) — the A2L unload of a session with an A2L and no data file detaches the A2L; arm A2L-only P → no A2L, 0 tags, `Unloaded A2L.`; mutant → RED — D-5 shows the A2L slot, and its unload painted "Nothing to unload.".
  - **F4 (I-1):** LLR-171.5 threshold — the example "a gathered row … `patches/con.json`" → "the active CRC template outside the project named `con.json` … `templates/con.json`" (end to end); the 12-row cap arm stays at the painting seam (`GatherOutcome.unrecorded` injected); token row "copied but not recorded" reason "the path is too long to record" → "the name is not one project.json records" for every non-device reason — the old example could not run end to end (the manifest writer refuses a device-stem `batch` entry first) and no length rule exists.
  - **F5:** token table +1 row (a copy reusing an identical file under another name: next step "remove the duplicate copy from the open project folder '<P>', then save again", not "save again"); LLR-171.1m threshold + the arm P records `patches/changes.json` beside an identical `patches/changes_1.json` → the document is bound to the file the gather placed or reused — the reviewer predicted a repeating mismatch for this case; executed, the save completed but bound the document to `Q/patches/changes.json`, a file the gather never wrote (a wrong binding, not a refusal), so the arm names the true landing.
  - **F6:** §3 row "more than 10 entries" names the one definition (`PAINTED_NAME_LIMIT`); the prototype's token rows 7 / 8 carry the shipped lines (D-2, D-4).
  - **F7 (a):** LLR-171.4f threshold + the arm `lstat` fails with a permission error → `could not be read` / `check that the folder can be opened, then load again` (Save target: `then save again`); token table +1 row; the save-as source row gains `could not be read` — a permission error painted "outside the work area" / "is not the work area folder". **F7 (b):** R-7 routed to `.dev-flow/BACKLOG-CODE.md` (no requirement change).
  - **SEC8b-1 (MINOR, design-gap; mechanism since Inc 2, LED .53):** LLR-171.7c (new, unwanted) — the rollback keeps a recorded file under a folder that is now a link or junction, or whose `(st_dev, st_ino)` differs from the one recorded when the save wrote it, and paints one line; arms: junction to another project's folder, junction to Q's own moved folder, a replaced file; one mutant per check — the rollback deleted 6 of 7 files of another project through a swapped folder (probe B3).
  - **SEC8b-2 (LOW, impl):** LLR-171.1o (new, unwanted) — the save-as copy refuses with `changed while saving` when a folder from the work area down to a copied file, P included, is a link or junction; arm probe B7; mutant: containment-only check → RED — the old check compared two resolutions that moved with P.
  - **SEC8b-3 (LOW, design-gap):** LLR-171.1h + the arm a linked `P/project.json` → 0 records carried, the link line names `project.json`; mutant → RED — the inventory named the link "not copied" while the carry followed it.
  - **CI timing factor (Inc 7 / 8a CI failures):** no requirement change. The requirements keep their 1 s bounds (measured locally); `tests/support/timing.py` `timing_bound(seconds)` returns `seconds × 2` when env `CI` is truthy, applied to every "< 1 s" assertion of the b100 tests (21 sites in 4 files) — the Linux CI runners failed four of these nodes on runner load, not on behaviour.
  - **F2 (D-3 reversed; 5 source files: operator-approved for F2, 2026-10-31):** LLR-171.2g + the painted-next-step arm — the A2L `not readable` row paints `replace the A2L file, then Load again` through a new `STEP_REPLACE_A2L` mark in `variant_execution_service.py` `DOCUMENT_NEXT_STEP`, set by `app.py` on the A2L problem; never `Save project to drop it`; the requirement and token-row text were already the true one and are kept; mutant MC15 (mark removed) → RED — the composer's step told the user that Save project drops the A2L, and it does not (probe P-1).
- **Why:** step E5 of the design-first pipeline (`design-first-increment` skill) blocks until F1 is fixed; these edits write F1, F3–F7 and SEC8b-1 … SEC8b-3 into the requirements as the orchestrator ruled. They are rulings under the batch's standing authorization.
- **Evidence:** `03-increments/review-increment-016.md`, `03-increments/security-increment-016.md`, `inc-8b/E5-cp1-notes.md`; RED `evidence/inc-8b/cp1/red-cp1.txt`; mutants `evidence/inc-8b/mut-cp1-MC01.txt` … `mut-cp1-MC15.txt`; GREEN `evidence/inc-8b/cp1/green-cp1.txt`; guards `evidence/inc-8b/cp1/guards-cp1.txt`; probes `evidence/inc-8b/cp1/probes-cp1.txt`; `git diff` of `01-requirements.md` on branch `b100-inc8b`.

### LED-2026-10-26-batch-100.81 — Inc 8b close: round-2 review, E13, routed items
- **Requirement:** HLR-171, HLR-171a, HLR-171b (the increment's HLRs; no requirement statement changed at the close)
- **Date:** 2026-10-31
- **What changed:** Inc 8b closes. The close records one review round, the E13 capture, and the routing of the open items; nothing in `01-requirements.md` moved.
  - **Round-2 review verdict.** `code-reviewer` re-read the corrective pass (narrow scope, `diff -u` of the 5 sources against the pre-cp1 snapshot) and returned **PASS-WITH-NOTES**: F1 (MAJOR, design-gap) is **discharged** — the reviewer re-read the fix on the diff and re-ran probe P-4 (`evidence/inc-8b/review/r2-P4.txt`); the cp1 items F2–F7a, SEC8b-1..3, M24/M35 and the `timing_bound` factor hold. Two new LOW notes, neither blocking: R2-1 and R2-2. No HIGH.
  - **E13.** The `pe-a2l-only` scenario (open + closed, 3 sizes) captured **6 of 6, failures=0** (`evidence/inc-8b/e13/`, `inc-8b/E13-notes.md`). D-5 renders at 220x60; the two compact-panel observations (OBS-8b-1, OBS-8b-2) and the pre-existing empty-state observation (OBS-8b-3) are MINOR and route to the backlog.
  - **Routed to `BACKLOG-CODE.md`** (`.dev-flow/BACKLOG-CODE.md`, each naming Inc 8b and its source file): R2-1 (the save-as source predicate `os.path.lexists` treats a `PermissionError` as gone → a false "was not found" line; token row 9 unreachable), R2-2 (the handler and the planner compute the save-as source separately), the SEC8b-3 TOCTOU hand-off (`_manifest_is_link` then `read_project_manifest`), OBS-8b-1, OBS-8b-2, OBS-8b-3, A3-15 (Execute next step on an A2L-only project), A3-17 (a MAC appearing mid-save), and the background copy with progress and cancel (→ Inc 12a). R-7 (F7 b), the device-stem `batch` entry (F4 side note) and the F5 plan-prediction remainder were already routed by the corrective pass and are not duplicated.
  - **Recorded, not routed:** M46 stays an accepted equivalent mutant (`_variant_set` left `None` on the A2L-only branch has no observable effect), and the 2 000-file save-as on the main thread is the R12 cost (the background copy is Inc 12a).
- **Why:** closes Inc 8b with one record, so the next increment starts from the round-2 verdict, the E13 gate and a settled backlog surface. These are rulings under the batch's standing authorization.
- **Evidence:** `03-increments/increment-016.md` (§4, §4b, §6, §7); `03-increments/review-increment-016.md` (round 2); `03-increments/security-increment-016.md`; `inc-8b/steps.log`, `inc-8b/E13-notes.md`; `evidence/inc-8b/review/r2-P4.txt`, `evidence/inc-8b/e13/`; `git diff` of `01-requirements.md` on branch `b100-inc8b` (empty at the close).
