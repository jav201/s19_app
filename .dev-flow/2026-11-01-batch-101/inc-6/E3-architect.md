# Inc 6 — E3 code-free design review: architect

Batch 2026-11-01-batch-101, increment 6 (Patch Editor document lifecycle). Base `9bb0e3a`, records commit `2c323ee`. Read: `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc6.md`, the pilot transcript, the canon rows in `REQUIREMENTS.md` (:3368-3399, :3439-3457, :3622-3625, :3747, :3769-3771, :5939-5941), the code in scope and its callers in `app.py`, `change_service.py`, `screens_directionb.py`, `changes/io.py`, `workspace.py`, `project_gather_service.py`, and the Inc 5 working tree diff (`git -C …/s19_app-b101-inc5 diff main -- s19_app`).

Run: one service-level probe (no TUI) on the LAN Linux host, detached worktree of `origin/main` = `9bb0e3a` at `/tmp/i6e3a/wt`, removed afterwards. Nothing ran on this PC. Transcript in §5.

## Verdict: FAIL

4 MAJOR, 11 MINOR, no BLOCKER or HIGH. The design fixes the four reproduced findings on the paths it names. Four gaps remain: a load-path tail that also runs on Save project; the Checks screen while it is displayed; a "current run" definition that the mechanism does not follow; and lists that go stale when the project changes. Each needs a targeted edit, with no redesign.

## 1. Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| E3A-01 | MAJOR | R-TUI-049.3.1, .3.2 · #6 `_patch_editor_load_tail` | The tail has five callers, not the three the graph names ("Load, dropdown pick, guarded accept"): `_patch_editor_load` (app.py:7146), `_reopen_active_document` (:14274, project install) and `_on_project_saved` (:12657-12658, `if outcome.pasted_placed`). The last one is Save project placing a pasted document into the project. The document is not replaced there: it is the same object, only `source_path` is set (:12650), and `last_summary` is kept. Yet #6 would hide the save-back prompt and the before/after control. That is a visible change no record admits, and it contradicts the graph's Inc 15 row ("the prompt is hidden only on a replacement … and on its buttons"). `_on_project_saved` is also an Inc 5 function, and the overlap list does not name it. | Call #9 in `_patch_editor_load`, which runs on every load, also a failed read, in place of the tail. Keep #8 in the tail: it only renders and does no harm on Save project. List the five tail callers in the slice and the graph. Add a case: paste C2, Apply (prompt shown), Save project → prompt still shown. |
| E3A-02 | MAJOR | R-CHKS-004, R-CHKS-009 · #7, #10, #11 | The Checks screen renders only when it is opened (app.py:9606-9610, comment "checks state changes only on run/undo/redo, so no load hook"), in the run arm (:4903) and in the history view (:5169). Inc 6 makes loads end a run, but it adds only the Patch-tab render (#8) to the image install (#10) and to the project reset (#7). `ctrl+l` (priority binding) and `p` load an image or a project while the Checks screen is displayed, and the load does not switch screens: `_step_finalize` (:18174-18182) re-homes the focus on the displayed window. The stale groups and aggregate line stay painted, which breaks R-CHKS-009 (a State row) and R-CHKS-004. The cases R-CHKS-001/2, -004/1 and -009/1 reopen the screen first, so none of them can catch this. | Call `update_checks_view()` beside #8 in #7 and #10, or inside #8. Add a case: Checks screen shown, K run, `ctrl+l` image 2 → the no-run note and the zero line without reopening the screen. |
| E3A-03 | MAJOR | CTX-CHECK-TEXT "current run" (`E1-rulings.md` §3) · I-1 · R-CHK-PE-008 … 012, R-CHKS-001 | The amended definition does not match the mechanism, in both directions. **(a) An apply that ends no run.** The claim "an apply alone does not end a run (… needs a new document first, which ends it)" is false. `ChangeService.apply` first restores the journal in place (change_service.py:1984), and the journal survives a document load (:1581). The probe (§5) shows it: Load C, Apply (`0x8003` = `AA`), load K′ (kind check, `0x8003` = `AA`), Run → `1 passed`. Then Apply K′ (blocked): the byte goes back to `03`, the stamp still matches, and a fresh run says `1 failed`. With Inc 6, the tab and the screen would keep showing `1 passed` as the current run. Inc 5 rules the opposite for the same event: an in-place write clears the Check Editor's verdicts (R-CHKED-057, `_note_image_bytes_written`). **(b) A MAC load that ends a run.** The generation bumps on every install (app.py:17996-18004), a MAC load included (:14098, :17801). So the tab and the screen clear on a MAC load, which "image load" in the text does not admit. | Preferred: end the run on every in-place image write inside `ChangeService`: `apply`, `save_patched` and `adopt_rederived` reset `last_check_result`, as `undo`/`redo` already do. This stays in G2 and touches no Inc 5 line. Render with #8, and with `update_checks_view` where an arm does not already. Amend the CTX text to "… are the ones it ran over and no write of the loaded image's bytes (an apply, a save-back, a Save project commit), no image or MAC load and no project load has happened since". Add cases for the journal-restore apply and for a MAC load. Alternative, if the scope is narrowed: drop the false parenthetical, record (a) as a known gap with this counterexample, and still fix the wording of (b). Backlog note: unloading the primary image bumps nothing (app.py:17245-17262), so a run stays current with no image loaded. |
| E3A-04 | MAJOR | R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040, R-DIFF-CHK.1 · #12 … #15 | Inc 6 makes the three lists depend on the open project, but they refill only when their screen opens (:9594-9606), after a Save or a Refresh, and after a spec Write. The project changes at two sites, and neither refills them: the project install (`_install_prepared_project`, :14089-14090) and the create/save-as swap of Save project (`_on_project_saved`, :12682-12683). Both `p` and `ctrl+s` work while the Patch Editor is displayed. After them the dropdown keeps the values of the old state. A bare common name then has no home and is refused with `… is outside the patches folder — not loaded.`. An old project's `patches/x.json` resolves to the new project's file of the same name. This is new: at base the lists never depended on the project. | After `current_project_dir` is set at both sites, refill the three lists with one call: `_prefill_patch_change_files`, the Spec half of `_prefill_check_editor` and `_prefill_diff_check_files`. All three tolerate an unmounted panel. Do not refill in `_reset_project_session`, which runs before the assignment (:14071 vs :14090). Add "or a project load or a Save project ends" to the three rows' triggers, and one case per site. Add `_on_project_saved` to the Inc 5 overlap list. |
| E3A-05 | MINOR | D-3 / D-1 · R-CHKED-040, R-DIFF-CHK.1 | The D-3 ruling's mitigation, "common-library files open by typed path", exists only in the Patch Editor. The Check Editor and the A2B Diff have no typed spec path, and the app has no project close. So for a whole project session, neither screen can reach the common library's specs. That includes the specs written in a project before this fix, which D9-15 put in `workarea/patches/`. The behaviour follows the canon, but no record says so. | Record it per screen in `E1-rulings.md` §5, with the real workaround: copy the file into `<project>/checks/` through the 📂 Open checks/ chip, then reopen the screen. Add one guide line (ch10). |
| E3A-06 | MINOR | D-6 · R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5 · #16 | A `patches/` or `checks/` link that points inside the project (for example to `proj/other`) passes both guard checks: the file is inside `folder.resolve()` and inside the project. The pick loads, while a Write through the same link is refused by the placement guard (`workspace.py:1182-1200`). D-6 says to refuse every pick and every Write through a link. | Also require `folder.resolve() == project.resolve() / <subdir>`. This works on Python 3.11 and needs no `is_junction`. Add the inside-link arm to R-PATCH-DOC-DROPDOWN-001.4/2. |
| E3A-07 | MINOR | cases R-TUI-049.3.1/1-7, .3.2/1-7 | All 14 cases assert the `hidden` class and are marked `full`. The flow counts "a CSS class in place of the painted style" as `partial` (SKILL.md E4). | Assert the painted absence: the row is not displayed and its text is absent from the painted rows. Keep the class as the wait predicate. |
| E3A-08 | MINOR | `02-test-cases.md` preamble; R-TUI-049.3.2/7; R-BEFORE-AFTER-REPORT-001.36/1; R-CHKS-009/1 | (a) The cases do not cite engineering rule 7 (`docs/engineering-rules.md:203`): wait through the shared `tests.b97_probes.settled` for a sign that the app handled the press, also when the case asserts that nothing changed. Each negative arm needs a named sign. (b) The /7 negative arm ("history empty, `ctrl+z` on a fresh apply") cannot be built. Every authoring path pushes history (change_service.py:1240 … 1643), so a shown prompt never coexists with an empty undo stack. The reachable form is `ctrl+y` with an empty redo stack (apply pushes nothing), followed by a later key whose effect shows that the press was handled. (c) In .36/1, the sign `Patched image saved as …` is a status-log line; `Saved + verified: …` is painted after it (app.py:5667). (d) R-CHKS-009/1 takes its expected value from the product's own builder. | (a) One preamble line plus a named sign per negative arm. (b) Replace the arm as described. (c) Read the sign from the status log. (d) Use the exact text: `Pass 0 / Fail 0 / Uncheck 0`, with no `█`. |
| E3A-09 | MINOR | docs and help (no row) | After the fix these texts become false: guide ch08 §8.10 "(finding F-05 — the notice offers it anyway)" and §8.19 "The Checks tab still shows the results … (finding F-40)"; ch10 §10.1 "Spec dropdown (check specs in the patches folder)"; in-app help `window_help.py:113-116` ("picks a change file in `patches/`", "re-reads the file list of `patches/`") and `:530` ("Spec — loads a check spec from the patches folder"); and the DOSSIER §5 rows F-05, F-06, F-40 and F-47. Inc 5 edited its own guide chapter inside the increment. | Plan these edits at E4: `window_help.py` would be the 4th source file, within the cap of 4. Or record them for the batch end. |
| E3A-10 | MINOR | R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5 (texts) | In a project, a refused `checks/` pick says "outside the patches folder". The canon text stays unchanged, because UI text is out of scope (P0). | Backlog row. |
| E3A-11 | MINOR | R-DIFF-CHK.3 | `AbDiffPanel.set_check_files([])` (screens_directionb.py:8602-8636) empties the options but never unmounts the row. Switching to a project whose `checks/` is empty therefore leaves an empty check row in place of no row. This was rare at base; project-scoped lists make it routine. | Backlog row, or take R-DIFF-CHK.3 in with an unmount. |
| E3A-12 | MINOR | slice §3 · graph §Interfaces | The Inc 5 overlap list misses two functions. One is `on_check_editor_panel_action_requested`: Inc 5 edits its docstring (hunk `@@ -7344`), and Inc 6 #23 edits the Write call (:7374). The other is `_on_project_saved` (E3A-01, E3A-04). There is no textual clash in the three listed functions: Inc 5's hunks sit at :4906, :5032 and :7490; Inc 6's lines at :4823/:4941, :5063 and :7452-7460. | Add both functions to the list, and re-check after the rebase. |
| E3A-13 | MINOR | #2 (`_refresh_patch_checks_tab` at the handler's end) | While a run is current, every Validate, Save, Refresh, Apply and Execute now removes and re-mounts every result row: `refresh_check_results` has no mount cap (screens_directionb.py:6922-6925). At base the tab re-rendered only on Run and on undo/redo. | Call #8 only in the arms that can change whether the run is current (add, edit, remove, the load paths, and apply under E3A-03), or skip the render when the shown state is unchanged. |
| E3A-14 | MINOR | `E1-rulings.md` §1, out of scope (a) | The backlog row "an image load while a save-back prompt is open leaves the prompt" should name its hazard. Write file then saves the new image, re-derived with the document, under the old variant's prefilled name `<old>-patched.s19` (app.py:4868, :5006-5034). #10 is already in the slice, so hiding the prompt there costs one line and one row. | The orchestrator either pulls it in or keeps it as a backlog row with the hazard stated. |
| E3A-15 | MINOR | US-PE-LIFE-1 | Its "so that the app does not promise a report it then refuses" is only half met. Without a project, the persistent control, which D-2 keeps, still offers the refused report. | Narrow the story to the notice ("no 'press b' notice"), or cite D-2 in it. |

## 2. Every path that replaces the document, loads, or changes the project

✓ the design covers it · ✗ open finding · — not applicable or not reached.

| Path | Hide control | Hide prompt | Checks tab | Checks screen (if displayed) | Lists |
|---|---|---|---|---|---|
| Typed Load (`load_doc` → `_patch_editor_load`) | ✓ arm + #6 | ✓ #6 | ✓ #6, #2 | — (Patch Editor displayed) | — |
| Dropdown pick, clean / dirty → accept | ✓ #6 | ✓ #6 | ✓ #6 | — | — |
| Dirty Load → accept | ✓ #6 | ✓ #6 | ✓ #6 | — | — |
| Paste, also JSON popup Confirm (posts `parse_paste`, :5436) | ✓ #9 | ✓ #9 | ✓ #2 | — | — |
| Undo / redo that moves a step | ✓ #3/#4 | ✓ #3/#4 | ✓ #5 | ✓ existing (:5169) | — |
| Project load (reset + reopen + install) | ✓ #7 | ✓ #7 | ✓ #7, #10 | ✗ E3A-02 | ✗ E3A-04 |
| Image load (`ctrl+l`, `v`) | — (backlog (a)) | — (backlog (a), E3A-14) | ✓ #10 | ✗ E3A-02 | — |
| MAC load | — | — | clears, but the text does not admit it (✗ E3A-03b) | ✗ E3A-02 | — |
| Apply with a journal restore after a run | — | — | stale verdict shown as current (✗ E3A-03a) | ✗ E3A-03a | — |
| Save project with a pasted document placed | ✗ E3A-01 (hidden, not a replacement) | ✗ E3A-01 | ✓ (render only) | — | ✗ E3A-04 |
| Save project create / save-as | — | — | — | — | ✗ E3A-04 |
| Add / Edit / Remove / per-entry JSON edit | — (not a replacement) | — | ✓ #2 / #5 | — (re-rendered on open) | — |

## 3. Interfaces with other increments, and observables

- **Inc 5 overlap (the three named functions).** No textual clash. Inc 5's `apply_doc` hook sits after the `try`, Inc 6's `parse_paste` arm is inside it, and Inc 6's #8 is appended after `set_entry_edit_json_enabled`. Inc 5's save-back hook comes right after `save_patched`, while Inc 6 edits the final `notify` and can reuse `project_dir` (:5042). Inc 5's item dicts change and Inc 6's guard lines change in the same function, about 30 lines apart. The semantic overlaps are E3A-01, E3A-03 and E3A-04; the missed functions are E3A-12.
- **Inc 15 observables.** `source_path` keeps its base form: a pick still loads `str(candidate)` resolved, and `read_change_document` stores the resolved path. The `#patch_saveback_row` hidden class is not moved in Inc 15's flows (`test_save_back_prompt`: image, Apply, the decline and confirm buttons). It would move on Save project (E3A-01).
- **Check home vs the common library.** Without a project, Write, the Spec list, the A2B list and every guard keep `workarea/patches/`: `_check_home()` equals the writer's default target (io.py:1649). With a project, Write lands in `<project>/checks/`, the folder the 📂 chip already opens. The placement guard creates the folder and refuses a link on the destination (`workspace.py:1182-1200`). This is the meaning R-CHKED-031 and R-DIFF-CHK.1 give the canon. What is missing is the stranded-spec consequence (E3A-05).
- **The visible change D-3 admits.** The `patches/<name>` and `checks/<name>` option values go through `safe_text`, and `ChangeFileSelected` forwards them verbatim (screens_directionb.py:4924, :6190-6194). Without a project, the bare names are unchanged.

## 4. Checked and found sound

- F-05: `notify` gated on `_active_project_dir()` with the exact `.1` text; `show_before_after_prompt()` stays unconditional (D-2). Nothing else parses `(action: …)`.
- A failed read replaces the document: `ChangeService.load` always assigns (change_service.py:1579), and the reader collects issues without aborting. So hiding on a failed read is correct.
- Undo/redo: the identity test `service.document is not before` matches `undo()`/`redo()`, which return the same object on an empty stack (change_service.py:988-1053). The A-01 guard runs first.
- The `_check_glyphs` refactor preserves behaviour. The `refresh_check_results` census stays at 3, with #8 passing the live `check_aggregates()` positionally (`test_tc078_3_both_sites`). The subtitle stays author-composed.
- The D-1 scope is right: the three lists share one scan, and leaving the A2B list out would break R-CHKED-033 in a project.
- Requirement rows: EARS forms; one `shall` each; no function or file named in a statement; numeric thresholds and negative controls present; R-TUI-049.3 split under the parent id.
- F-47: the ruling has evidence. Only the `b` binding and the panel control reach the action, so no product change is warranted.

## 5. Probe transcript (LAN host, `9bb0e3a`, service level)

```
s19_app.__file__ = /tmp/i6e3a/wt/s19_app/__init__.py
ranges [(32768, 32784)] apply C counts {'applied': 1, 'skipped-partial': 0, 'skipped-outside': 0, 'skipped-no-image': 0, 'blocked': 0} byte@8003 0xaa
run K: Checks: 1 passed, 0 failed, 0 uncheckable
current after run: True
apply K counts {'applied': 0, 'skipped-partial': 0, 'skipped-outside': 0, 'skipped-no-image': 0, 'blocked': 1}
byte@8003 after apply K: 0x3
current after apply K: True
a fresh run now says: Checks: 0 passed, 1 failed, 0 uncheckable
```

("current" = `last_check_result is not None and _last_check_stamp == (_document_signature(), image_generation)`, which is I-1 exactly. The second range spelling gave identical output.)

## 6. Evidence checklist (architect)

| Item | Mark | Evidence |
|---|---|---|
| Constraints stated | ✓ | 4-source-file cap (slice §1: 3 used); UI rows out of scope by P0 (D-2); Python 3.11 CI (E3A-06 fix avoids `is_junction`) |
| 2+ alternatives where a real decision exists | ✓ | E3A-03: service-local reset vs narrowed record; E3A-01: hide in `_patch_editor_load` vs a flag on the tail. Elsewhere `n/a`: the canon rows and D-1…D-6 already decide |
| Constraints that do not apply marked | ✓ | cost/latency `n/a`: local UI, no external calls; except E3A-13 (render cost) |
| Recommendation tied to constraints | ✓ | every fix stays inside the 3 slice files, except E3A-09's optional 4th (cap 4) |
| Risks listed | ✓ | §1, all rows; E3A-03a (stale verdict) and E3A-14 (saved-file meaning) are the data-meaning risks |
| Cost / latency estimated | ✓ | E3A-13: re-mount of every result row per action while a run is current; no other cost |
| Diagram when flow is non-trivial | ✓ | §2 path matrix |
| What would change the verdict | ✓ | §7 |
| Two-layer requirements | n/a — the v3 flow traces US → R → TC with black-box cases; `trace_check.py` runs at E5 |

## 7. What would change the verdict

PASS-WITH-NOTES once E3A-01 … E3A-04 are corrected in the records and the graph, by targeted edits, or once the orchestrator rules each one out with a reason; the MINOR rows can go to E4 as addenda. E3A-03 drops to MINOR if the orchestrator takes the narrowed alternative (an admitted gap with the counterexample) and fixes the MAC-load wording.

## Round 2

Re-check of E3A-01 … E3A-04 and the revised D-3 (`E3-rulings.md`) on the corrected records at `64c24ac` (records only: `git show 64c24ac --stat`, 6 files under `inc-6/`). Code read on local main `823d0c9` (base plus Inc 5), extracted with `git show` into a scratch folder: `app.py`, `services/change_service.py`, `screens_directionb.py`, `services/project_gather_service.py`, and Inc 5's hook as merged (`git diff 9bb0e3a 823d0c9 -- s19_app/tui/app.py`). Nothing imported `s19_app` and nothing ran. Line numbers below are `823d0c9`'s unless a record is named.

### Verdict: PASS-WITH-NOTES

E3A-01 … E3A-04 and the revised D-3 are closed as ruled. Three new MINOR rows (E3A-16 … E3A-18) fold at E4 as addenda; none reopens a design decision. Other findings are not re-checked here.

### R2.1 Closure

| Item | State | Evidence |
|---|---|---|
| E3A-01: hide only where a document is replaced | closed | #9 sits in `_patch_editor_load` (graph :278-286). Its callers are the `load_doc` arm, the pick (clean, and the popup accept) and the typed-Load popup (app.py:4821, :7133, :7137, :7242). The tail hides nothing (graph :90-98). The other #9 sites are the paste arm, undo, redo, the project reset and the install of a new image dict (graph :416). `_on_project_saved` (app.py:12589-12730) runs `adopt_rederived` and the hook (:12636-12642), the tail (:12691), `mark_saved`, `update_project_labels` and `refresh_files`, none of which is a #9 site. `_reset_project_session` has one caller (:14104), and `_start_load_worker` is reached only from file loads (:15604, :16057). So neither Save project nor a save-back reaches the reset or an install. R-TUI-049.3.1/9 and .3.2/9 go RED if the hide moves into the tail or into the hook. |
| E3A-02: a displayed Checks screen repaints | closed | `update_checks_view()` is added in #7 and #10 (graph :104, :134) and in the hook (#33). Undo and redo already repaint through `_refresh_patch_history_view`. So every path that ends a run while the screen can be displayed repaints: an image load, a MAC load, a project load, and a Save project that writes the image. With its widgets absent, `update_checks_view` is a guarded no-op (app.py:16506, the `screen_stack` and `query_one` guards). R-CHKS-004/2 can fail, because #10 is the only repaint on an image load. For -009/2, see E3A-16. |
| E3A-03: an in-place write ends the run, through one seam | closed | Inc 5's hook (app.py:17910-17955) takes no argument. It has three callers: the apply arm, ungated (:4914); after `save_patched`, whatever `result.ok` (:5046); and inside Save project's image `if` (:12642). It returns early when the Check Editor is not mounted (:17954). The graph prepends Inc 6's three statements (graph :302), so that return cannot skip them. `end_check_run` (I-7, graph :24, :392-400) has #33 as its only caller, and G2 changes none of `apply`, `save_patched` and `adopt_rederived`, so there is no second seam. The seam is complete. The loaded map is written in place only by `_restore_journal` (change_service.py:1840, from `apply`, :1984), by `apply_changes` (changes/apply.py:341) and by `adopt_rederived` (change_service.py:2358, from `save_patched` and from app.py:12636). Those are exactly the three hook sites. The repaint through #6 is the same render as the apply arm's site 1 (`_strip_source_map`, `_patch_document_view`), so the five `refresh_entries` sites stay five. The amended CTX (`E1-rulings.md` :42) matches the mechanism. The one generation bump is in the install (app.py:18083); a MAC load goes through it, and an A2L attach does not (`_a2l_attach_worker` → `_on_a2l_attached`). *Reading for E4:* the hook also fires on an Apply press or a confirmed save-back that moves no byte, for example a blocked apply with an empty journal. The CTX parenthetical names these events, so the text holds. No E4 test may assert that a run survives an Apply. R-CHK-PE-009/5 and -014/1 fail both ways: with no run end, `1 checked` or `◐` stays; with the run ended but no repaint, the same stays painted. The `◐` precondition of -014/1 is reachable, because a blocked run stores its result and stamp (change_service.py:2685). |
| E3A-04: the lists refill after every project change | closed | `current_project_dir` has exactly two assignments (app.py:12716, :14123), and #35 follows each one (graph :317-334). Each of the three halves tolerates an unmounted panel. 001.1/5, /6, R-CHKED-040/3 and R-DIFF-CHK.1/3 go RED without the refill, since no other path refills a displayed list. For a side effect, see E3A-17. |
| Revised D-3: `library/<n>`, and Write lands in the project home | closed | The three lists use one form: `library/<file name>` for `workarea/patches`, after the project's entries, with each home sorted and the homes joined in order (I-5, I-6, graph :22-23, :152-160, :288-296; CTX `E1-rulings.md` :40-41). Both builders name the same `checks/` path (`P / PROJECT_CHECKS_DIR`, and `scoped_home_target` = `project_dir / subdir`, project_gather_service.py:909-911). Without a project the names stay bare. Both editors write into the project home. Check Editor Write gets `dest_dir=_check_home()` (graph :271; case R-CHKED-031/3). Patch Editor Save always writes a new file into `scoped_home(project, kind folder)` (app.py:6908; `ChangeService.save` → `write_change_document(…, dest_dir=dest_dir)`, change_service.py:1764), never back to the picked source. So a `library/` pick saves into the project. That the spec lists show no project `patches/` entry is a recorded reading (`E1-rulings.md` :72: the canon source is the check home). I accept that reading. |
| Slice | holds | 4 of 4 source files and 37 functions (slice :5-9). `scoped_home_target` is not yet imported in app.py, which imports only `scoped_home` (:226). Adding it is one import line in the same file. |
| Rows | strict EARS | Each amended row has one trigger or one condition, exactly one `shall`, and no code name: R-TUI-049.3.1 and .3.2, R-PATCH-DOC-DROPDOWN-001.1, .2 and .4, R-CHKED-040 and -044, R-DIFF-CHK.1, .3 and .5. |
| Cases | able to fail | All except E3A-16. |

Path matrix of §2, rows that were ✗ in round 1:

| Path | Hide control | Hide prompt | Checks tab | Checks screen (if displayed) | Lists |
|---|---|---|---|---|---|
| Project load | ✓ #7 (and #10 with a variant) | ✓ #7 (#10) | ✓ #7, reopen tail, #10 | ✓ #7, #10 | ✓ #36 |
| Image load | ✓ #10 | ✓ #10 | ✓ #10 | ✓ #10 | — |
| MAC load | — (dict kept) | — | ✓ #10 (the CTX admits it) | ✓ #10 | — |
| Apply with a journal restore; a save-back | — | — | ✓ #33 | ✓ #33 | — |
| Save project, pasted document placed | ✓ kept | ✓ kept | ✓ #6, and #33 when it writes the image | ✓ #33 when it writes the image | ✓ #37 (E3A-17) |
| Save project, create or save-as | — | — | — | — | ✓ #37 |

### R2.2 New findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| E3A-16 | MINOR | R-CHKS-009 negative control · case -009/2 · #7 | The row's negative control, "no repaint at the project reset → displayed arm RED", cannot fire, because `proj` holds a variant. The reset sets `current_file = None` (app.py:13507). The variant install then reaches #10 with `previous_map` `None`, and #10 repaints the screen too (it also hides and renders the tab). So without #7's `update_checks_view()` the case stays GREEN. The same masking covers every project-load arm: R-TUI-049.3.1/4 and .3.2/4, R-CHK-PE-009/3, -010/2, -011/2, -012/2. Only for a project with no variant (and no recorded document) is #7 the only path, and no case loads such a project. | Run -009/2 on a project with no variant and no recorded document, or restate the negative control as "no repaint at the install". |
| E3A-17 | MINOR | R-DIFF-CHK.1 · #35, #37 | The refill after every committed Save project clears a spec picked on a displayed A2B Diff. The chain: `set_check_files` ends with `select.value = ""` (screens_directionb.py:8801-8802); the panel forwards the blank as `CheckFileSelected("")` (:8808-8811); the app drops the stashed spec and paints `Check spec: none — the report gains no addendum.` (app.py:7813-7817). The next report then has no addendum. At base, leaving and reopening the screen already clears the pick, so the new case is only a Save project pressed while the screen is displayed. After a create or save-as, clearing is right: the old value no longer names the same file. The other two lists ignore a blank (screens_directionb.py:6158, :7991-7996). Read in code, not run. | Admit it in R-DIFF-CHK.1's Base column or a context note ("a refill clears the pick"), with one case. Do not special-case the refill. |
| E3A-18 | MINOR | R-CHKED-040, R-DIFF-CHK.1 (cases) | Two trigger alternatives have no case: a project load for R-CHKED-040, and a Save project for R-DIFF-CHK.1. Every single-site mutant of #35, #36 and #37 is still caught through another list's case. Separately, no case pins Patch Editor Save after a `library/` pick. Unchanged code holds it, and the revised D-3 relies on it. | Add R-CHKED-040/4 (project load with the Check Editor displayed) and R-DIFF-CHK.1/4 (Save project creating `new`). On 001.3/3, add one assertion: Add, then Save, writes `proj/patches/changes.json` and leaves `workarea/patches/` unchanged. |

### R2.3 Evidence checklist (round 2)

| Item | Mark | Evidence |
|---|---|---|
| Constraints stated | ✓ | 4-source-file cap (4 used), P0 UI scope, Python 3.11: unchanged from round 1 |
| 2+ alternatives where a real decision exists | n/a — the E3 rulings decided each item; round 2 checks conformance | — |
| Constraints that do not apply marked | ✓ | cost/latency `n/a`: local UI, no external call |
| Recommendation tied to constraints | ✓ | every fold stays in the slice's files or in the records |
| Risks listed | ✓ | E3A-16 (an arm that cannot fail), E3A-17 (a lost A2B pick) |
| Cost / latency estimated | ✓ | the hook adds one `refresh_entries` per Apply (the tail, then site 1), with no new site; negligible |
| Diagram when flow is non-trivial | ✓ | the R2.1 path matrix |
| What would change the verdict | ✓ | R2.4 |
| Two-layer requirements | n/a — as in round 1 | — |

### R2.4 What would change the verdict

FAIL if the rebase on `823d0c9` puts Inc 6's statements after the hook's early `return`, or if it adds an `end_check_run` call outside the hook. A case planned for E3A-16 that stays GREEN on a project with no variant and no #7 call would also mean FAIL.
