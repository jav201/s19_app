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
