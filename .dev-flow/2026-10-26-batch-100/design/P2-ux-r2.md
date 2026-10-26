# P2 · UX review · round 2 — batch-100 (Load + projects)

- **Reviewer:** `ux-reviewer` (trigger D1). Read-only: I changed no requirement, prototype or code, and committed nothing.
- **Under review:** `01-requirements.md`, `01-requirements-ledger.md` (LED .2–.13) and `02-review.md`, all at `0c7ca1d`. Also read: the operator's verdict `design/veredicto-load-projects.json` (P-A C, P-B A, P-C B, P-D A, P-E B), the rulings `design/P2-dispositions-r1.md`, and my round 1, `design/P2-ux-r1.md`.
- **Scope:** (1) closure of UX-01..UX-25; (2) the new text: filled VS-* slots, the P-E panel, the P-C summary (R-PC), the P-D status line, VS-PA-6, the 16-cell P-B table, and `p` opening the one Load dialog; (3) the author's deviations in §6.3.

## Verdict

**`iterate-to-refine`.** The unmet axis is **requirement content**.

Round 1 closed well: 20 of 25 findings are closed, 2 are closed differently in an acceptable way, and 3 stay open (UX-05 MAJOR; residuals of UX-07 and UX-22, both MINOR).

The new text brings **1 HIGH**. UX-26: the P-E panel's "patched, N bytes differ" compares against the *first variant by name*. With the app's default save-back name, `firmware-patched.s19` sorts before `firmware.s19`, so the panel compares the patched image with itself. That is the exact switch the operator's D2 note asks never to pass unnoticed. The new text also brings **9 MAJOR** and **5 MINOR**.

**Open after round 2: 18 — HIGH 1 · MAJOR 10 · MINOR 7.**

| Count | HIGH | MAJOR | MINOR | Total |
|---|---|---|---|---|
| Round-1 findings still open | 0 | 1 (UX-05) | 2 (UX-07 residual, UX-22 residual) | 3 |
| New in round 2 | 1 | 9 | 5 | 15 |
| **Open** | **1** | **10** | **7** | **18** |

## 1. Closure of round-1 findings

| id | r1 sev | state | where the contract closes it | note |
|---|---|---|---|---|
| UX-01 | HIGH | **closed** | LLR-167.5 (`differs_from_last_saved`, `mark_saved` at load / save-back / Save project), LLR-167.1 (source predicate limited to emit-or-copy), LLR-174.1, LLR-175.4; LED .3 | The image half is closed: the two predicates are separate, and the "patched → saved → load = no question" cells exist. The same defect class remains for the Patch Editor document flag (W); that is new finding UX-27. |
| UX-02 | HIGH | **closed** | HLR-176, HLR-177, LLR-176.3, LLR-177.1; LED .11 | 12b is unconditional (R-PD). The tag-table freeze is declared, its step name is painted first, and the AT uses a black-box slow fixture (case_06). |
| UX-03 | MAJOR | **closed** | LLR-166.1 (per-window table of focus targets, never `Input`/`TextArea`), LLR-166.2; LED .10 | — |
| UX-04 | MAJOR | **closed** | HLR-166 (closes of dialog, question and panel; cancelled load), LLR-166.1; §5.3 (AT-04 re-pinned at Inc 6 and Inc 9b) | — |
| UX-05 | MAJOR | **still open** | LLR-173.2 (VS-PA-6); LED .2 | The precedence and the `tab` order are filled. Two defects remain. (a) The initial focus is `#load_list`, but `tab` runs path → list → preview → buttons, so from the start the path field is 3 `tab`s away (or one `shift+tab`), and `pa_C`'s hint "or type a path (tab)" becomes false. (b) What a printable key does while the list has the focus is still unstated. It may do nothing, or it may reach an app binding under the modal (`l`, `p`, `s`, `v` are app-level bindings, `app.py:1430-1439`). **Closes:** start the focus on `#load_path`, or make the tab order start at the list. State that a printable key with the list focused goes to `#load_path` (and never to an app binding). Add a TC: from the opening state, typing `C:\x.s19` puts it in `#load_path`. |
| UX-06 | MAJOR | **closed** | LLR-173.5 (dialog stays open, typed text kept, tokens in `#load_reason`); LED .10 | — |
| UX-07 | MAJOR | **closed differently, MINOR residual open** | §3 refusal-token table; LED .10 | Every refusal and empty state now has a reason token and a next-step token an AT can match, which is the main closure. Residual: 4 of the 7 problem kinds (`manifest damaged`, `missing`, `not readable`, `changed on disk`) have no next step, and "outside the work area → `projects open only from the work area`" states a reason, not an action. **Closes:** add the next-step tokens (for example `Save project rewrites it`; `restore the file, or Save project to drop it`; `copy the folder into the work area`). For the disguised clash's next step, see UX-35. |
| UX-08 | MAJOR | **closed** | LLR-169.6 (exactly 1 new log line per project load, count inside 118), LLR-178.2 (`#status_text` = project + file); LED .7 | The ownership conflict this creates on `#status_text` is new finding UX-29. |
| UX-09 | MAJOR | **closed differently** | HLR-178, LLR-178.1, LLR-178.3; LED .7 | The panel replaces the toast, so persistence (reachable through the open project's preview) and occlusion are closed. The content clause ("how it differs from the base") is added, but its base is defeated in the default naming case; that is new HIGH UX-26. |
| UX-10 | MAJOR | **closed** | §3 preface (two sizes, `notifications=True`, no wrap, `…`), LLR-173.6 (stack below 100); §2.6 environment line; LED .10 | — |
| UX-11 | MAJOR | **closed** | LLR-174.1 (the "project open" term is removed; 11 cells ask, 5 load); LED .3 | — |
| UX-12 | MAJOR | **closed** | LLR-174.2 (focus on `#confirm_no`, `enter` acts on the focused button, one modal); LED .3 | — |
| UX-13 | MAJOR | **closed** | §3 preface *Keys*; LLR-173.2, LLR-174.2, LLR-175.3 (each shown key is pressed); LED .10 | — |
| UX-14 | MAJOR | **closed differently, acceptable** | HLR-168, LLR-168.3 (a status line names the project and the file it now opens); LED .7 | There is no question; a status line names the consequence. That is acceptable under UX-11's "ask only when something is lost". The preview half is new finding UX-36. |
| UX-15 | MAJOR | **closed** | HLR-174 / HLR-176 / HLR-177 slot lines (no "save first", no cancel, refuse with `busy`, session and focus unchanged); LED .2 | — |
| UX-16 | MAJOR | **closed** | §5.1 (Phase-4 expert inspection of the panel and the Save summary at both sizes; evaluation with users declared not performed); §5.2; LED .12 | — |
| UX-17 | MINOR | **closed** | LLR-172.5 (`not a project` vs `outside the work area`); LED .10 | — |
| UX-18 | MINOR | **closed** | LLR-173.7, TC-B100-66; LED .10 | — |
| UX-19 | MINOR | **closed** | LLR-169.9 (user terms, 0 exception class names); LED .7 | — |
| UX-20 | MINOR | **closed** | HLR-178 ("latest" only for the newest file written), LLR-178.1; LED .7 | "Newest written" is undefined; that is new finding UX-40. |
| UX-21 | MINOR | **closed** | LLR-175.1 (`name too long`, "updates the open project"); LED .4/.5 | — |
| UX-22 | MINOR | **still open (residual)** | §3 token table; LLR-172.5 | `Unsupported file type: ` and `Invalid project name.` are replaced by tokens. LLR-171.2 still keeps "the existing refusal" (`No supported files in project: P`) for a folder that holds a `project.json` but no data file and no A2L, and that case has no tokens. **Closes:** add a row, `no data or A2L file` / `load a file and Save project`. |
| UX-23 | MINOR | **closed** | LLR-173.4 (`not found`, the entry is dropped); LED .10 | — |
| UX-24 | MINOR | **closed** | HLR-173 VS-PA-2 (double-click not bound, declared in §1.2); LED .2 | — |
| UX-25 | MINOR | **closed** | HLR-170, LLR-170.2 (`patches/changes.json`, `changes_<N>.json` on a clash); LED .10 | — |

## 2. New findings (round-2 text)

Id UX-28 is not used: the open UX-05 items are carried in §1.

| id | severity | location | finding | evidence | what closes it |
|---|---|---|---|---|---|
| UX-26 | HIGH | HLR-178 ("how it differs from the project's first variant by name"), LLR-178.1; AT-B100-19 | The panel's base for "patched, N bytes differ" is the **first variant by name**. Variants are sorted by `(name.lower(), name)`, and the app's own default save-back name `firmware-patched.s19` sorts **before** `firmware.s19` (`-` is 0x2D, `.` is 0x2E). After a default save-back, the opened variant *is* the first by name, so the panel compares it with itself and says "identical". In a project that opens the original instead, the panel calls the patched file the base. The D2 statement then fails in the default path, and AT-B100-19 cannot see it because it only uses `firmware_1`. | `workspace.py:1110-1124` (order `(name.lower(), name)`); `sorted(['firmware.s19','firmware-patched.s19','firmware_1.s19'])` → `['firmware-patched.s19', 'firmware.s19', 'firmware_1.s19']`; HLR-168 boundary names `firmware-patched.s19` (`p02` B) as a covered case. | Define the base as the image the patch derives from, not a name order. For example, the save-back and Save project record the variant they derive from (or the source digest), and the composer compares against it; when nothing is recorded, the panel says "base unknown" instead of guessing. Add an AT-B100-19 / TC-B100-55 arm with the default name `firmware-patched.s19` (`p02` B): the panel says "patched, 4 B differ from `firmware.s19`". |
| UX-27 | MAJOR | HLR-174 (W = "Patch Editor entries the dirty flag marks"), LLR-174.1; HLR-170 | This is UX-01's defect for the **document**. Save project writes the document into `patches/` (HLR-170), but nothing in the contract clears the batch-94 dirty flag afterwards. Today only `save_doc` / save-back paths call `panel.mark_saved()`. So "add an entry → Save project → load a project" still asks about "unsaved Patch Editor entries" that are on disk, and the false question trains `y`. HLR-174's numeric arms cover the image only. | `screens_directionb.py:4801-4808` (flag cleared only by `mark_saved` / `mark_loaded`; writer census of 4); callers `app.py:2672`, `:2995`, `:3306`, `:5418` (none on the Save project path). | A Save project that places the document clears W (it calls `mark_saved` on the panel), or W is defined as "differs from the document last saved or loaded". Add a cell and a TC arm: entry added → Save project → project load = no question. |
| UX-29 | MAJOR | HLR-176 ("paint its outcome" in `#status_text`), LLR-176.1; LLR-178.2 (`#status_text` = project + opened file); existing `set_file_status` | `#status_text` has three writers at the end of a project load, with no order between them: the busy seam's outcome, LLR-178.2's project + file line, and the existing file-state writer. Two ATs assert different content on the same widget at the same moment, and the result depends on scheduling. The progress bar's state before and after an action is also unstated. In `pd_A` the bar still shows the previous action's `100% 00:00:00` while the new action is labelled "Loading". | `app.py:13587-13590` (`set_file_status` → `#status_text`); LLR-176.1 / LLR-178.2 statements; `png/pd_A.pd.118.png` (stale bar under the indicator). | Write one ownership rule. During an action, `#status_text` is the indicator. At its end, the outcome is shown (for a project load, the outcome *is* the project + file line) and then the file state. The bar resets to 0 at `begin_busy`, and its end state is stated (cleared, or 100% without a stale timer). Add a TC that reads `#status_text` after a project load ends. |
| UX-30 | MAJOR | HLR-176 / LLR-176.1 (`#progress_bar` "from the step index"); operator P-D note | The operator's verdict was conditional: "asumiendo que la barra de progreso realmente hace su trabajo también, mostrando el progreso". A bar set from the step index sits still for the whole longest step: the A2L parse, about 5 s of a 7 s load in the round. The AT passes on step transitions alone ("bar value increases ≥ 1 time"), so a bar frozen during the parse satisfies the contract while failing the operator's assumption. | Page P-D (≈5 s parse; `pd_A` "✓ Loaded … in 00:07"); HLR-176 numeric threshold. | Either report progress inside the long steps (bytes read for copy, parse and hash) and assert a bar change *during* the parse step, or state in the contract and to the operator that the bar moves per step only, and record the operator's acceptance. |
| UX-31 | MAJOR | LLR-178.3 ("every problem in a scrolling body", focus on `#result_ok`) | Keyboard-only path: with 30 problems at 118×54 the body scrolls, but the focus sits on the OK button and no key is stated to scroll the body. A keyboard user cannot reach the rows below the fold, which is truncation by another name. TC-B100-67 counts rows in `#result_body` (a structural read) and cannot see that they are unreachable. With the focus on OK, a repeated `enter` from the Load dialog also closes the panel unseen (see UX-39). | LLR-178.3 statement and numeric threshold. | Put the focus on the scrolling body, or bind up/down/pgup/pgdn/home/end to scroll it while OK has the focus. `enter` and `esc` still close it. TC: after `end`, the last problem row has a visible region (a geometry read after layout, not a row count). |
| UX-32 | MAJOR | HLR-175, LLR-175.4, AT-B100-21 ("summary rows = files written, by path and digest") | Three gaps on the operator's high-stakes surface. (a) Grouping: AT-B100-21 makes the painted summary list every file written, but the chosen `pc_B` groups sub-folders ("flows/ — 1 file copied"). A save-as of a project with hundreds of report files would paint hundreds of rows. (b) Layout: no scroll rule and no pinned Save/Cancel at 118×54 for a long plan. (c) "Nothing shall be overwritten" contradicts the rewrite of `project.json`, and the in-place update of the open project and of a merge target. | `png/pc_B.pc.118.png` (grouped sub-folders); HLR-175 statement; LLR-164.2 (b) merge rewrites the target's `project.json`. | State the grouping: data, MAC, A2L and document as one row each; each sub-folder as one row with its counts (new / reused / skipped links). The oracle compares the plan's complete list with the disk, and the painted rows with the plan's groups. The summary scrolls with Save/Cancel pinned. Replace "nothing shall be overwritten" with "no data file is overwritten; `project.json` is updated, and is painted as updated". |
| UX-33 | MAJOR | LLR-175.1 / LLR-175.4 ("on every change of the name"), LLR-167.6 (plan includes the SHA-256 of every file and of the emitted bytes, derived on a copy) | The plan, including digests of every file and an emitted copy of the image, is recomputed on every keystroke of the name, on the main thread. On a large image or a project with many sub-folder files, typing the name lags. That is the "app froze" class UX-02 removed elsewhere. No budget and no debounce is stated. | LLR-167.6 statement; LLR-175.1 "on every change of the name". | Recompute only the name-dependent rows per keystroke (folder, kind, refusal, landing names), debounced. Compute digests once, at Save on the worker, or derive them only for the test oracle. Add a TC: with the case_06 project, a keystroke echoes in `#project_name` within one frame. |
| UX-34 | MAJOR | HLR-177 ("a request for another of them, or a Patch apply or undo, shall be refused"), LLR-177.1; AT-B100-18 ("pressing `l` during it paints `busy`") | Moving the three actions to workers makes new actions reachable while they run, and the refused set does not cover them. A file load (`l`, a Workarea pick, a recent), unload, variant select (`v`), save-back and quit are not in it. The AT expects `l` → `busy`, which the statement does not oblige: a file load is not "another of them". Quitting during a worker Save project can leave a partial project folder, which was impossible while the main thread was blocked. | HLR-177 and LLR-177.1 statements vs AT-B100-18; `app.py:1425-1439` bindings. | List the refused set explicitly: every action that reads or writes the session or the project folder, each with `busy` and the running action. Quit while a write runs waits, or asks with the P-B question pattern (focus on No). Add AT arms: `l`, `v` and `q` during a Save project → `busy` (or the question), 0 partial folders. |
| UX-35 | MAJOR | §3 token table, disguised clash → next step `type the exact name to add to it`; LLR-164.2 (b) merge | The only next step offered for a disguised clash (`a b` vs existing `ab`) is to **merge into another project that is not open**. That merge adds variants there and moves its `active_variant` (D2). The operator's P-C note names exactly this risk: "…se sobreescriba o se renombre". The refusal steers the user toward the riskier action. | Token table row "disguised clash"; LLR-164.2 (b); `veredicto-load-projects.json` P-C note. | Change the next step to `choose another name`, with the merge as the second option (`or type ab exactly to add to it`). In a merge, the summary names the target's active-variant change on its own row ("ab will open <file>"). |
| UX-36 | MAJOR | LLR-173.6 ("for a file, the file and what it pairs with"); LLR-173.4 (a recent is not stat-ed before Enter); operator P-A note | The `●` active-set mark is specified and tested for **project** rows only (TC-B100-64: 4 projects). For file and work-area rows, "what it pairs with" is undefined. Yet a file load composes with the session's MAC and A2L, and with a project open it becomes that project's active variant (LLR-168.3). For recent rows the security rule forbids any look before Enter, so the preview cannot show the set, and the contract does not say what it shows instead. The operator's note asks for the active-set symbol for "las vistas y funciones", which covers every load, not only projects. | LLR-173.6 numeric (projects only); LLR-168.3; LLR-173.4. | Define the preview for each row kind. File and work-area rows: the resulting active set marked `●`, including the MAC and A2L the session keeps, plus "becomes <P>'s active variant" when a project is open. Recent rows: the path plus "checked when loaded" (no stat). Extend TC-B100-64 with a file row and a file row with a project open (marks = installed set). |
| UX-37 | MINOR | VS-PA-4 (`p` opens the dialog "with the Projects section highlighted") | Which row `p` highlights is unstated. HLR-178 promises the panel's information stays reachable "in the Load dialog's preview of the open project", so `p` should land on the open project's row. The key bar still labels `p` as "Load project" and `l` as "Load file" for what is now one dialog. | HLR-173 VS-PA-4; HLR-178 last sentence; `app.py:1430`, `:1438`. | `p` highlights the open project's row, or else the first project. The key-bar labels name what each key does ("Load", "Projects"). |
| UX-38 | MINOR | HLR-178 / LLR-178.2 (the summary line ends "with a pointer to the panel") | The panel is a modal that is gone once closed, so a pointer to it points nowhere. The information lives on in the open project's preview. | HLR-178 statement. | The pointer names the key that reaches it (`p`: "details: p"). |
| UX-39 | MINOR | LLR-178.3 (focus on `#result_ok`); HLR-173 (`enter` loads) | A repeated `enter` (or key auto-repeat) after the Load dialog's `enter` dismisses the panel before it is read. The summary line and the preview keep the information, so this is minor, but it weakens the D2 notice. | LLR-178.3. | Covered by UX-31's closure (focus on the body). Or `enter` closes only after the panel has painted once. |
| UX-40 | MINOR | HLR-178 ("latest" only when the opened variant is the newest file written), LLR-178.1 | "Newest file written" is undefined. If it is read from file times, a hand-copied or touched file becomes "latest". | LLR-178.1 numeric ("newest true only for the newest-written variant"). | Define it from the app's own write record (the manifest or the save that wrote it), never from file times. |
| UX-41 | MINOR | HLR-171 (a save-as refused when the copy exceeds free space, S-15); §3 token table | The new free-space refusal has no reason or next-step token. | HLR-171 statement; token table. | Add a row: `not enough free space` / `free space or save with a shorter project`, or the closest accurate next step. |

## 3. The author's deviations (§6.3)

| Deviation | Judgment (UX lens) |
|---|---|
| **QA-05 return shape:** keep `copy_into_workarea -> Path`, add `place_into_workarea -> PlacementResult(path, reused)` for the two callers that report reuse. | **Accept.** The user-visible obligation (every placement status says reused or new, HLR-163, LLR-163.5/.6) is still driven by a result, not by guessing. It has no UX cost. |
| **S-15:** free-space cap only, no file-count cap. | **Accept**, because the save runs on a worker with progress (HLR-177). Raises UX-41 (the refusal needs tokens). A save-as of a very large tree is covered by UX-32's grouping. |
| **S-16:** `recent_sources.json` in `.s19tool/` is shared if the folder is zipped or synced; open for the operator. | **Not a UX call.** It is correctly left open for the operator. It should appear on the operator's decision page with its consequence (paths visible to whoever receives the zip), not as a label. |
| **VS-PA-4 `p`:** `pa_C` replaced only the Load file dialog; the contract also has `p` open the same dialog with Projects highlighted. | **Accept.** It follows US-163 ("one Load dialog") and the original request ("Load opens projects"), and it retires a second dialog with its own keys. It needs UX-37 (which row, key-bar labels). |
| **P-B trigger per load kind:** a file load asks on D only; a project load on D, F or W. | **Accept.** It is the direct reading of "ask only when something would be lost": a file load keeps the Flow Builder and the Patch Editor document. It depends on UX-27 (W must clear on Save project) to stay truthful. |

## 4. Checks on the new text that pass

These were checked and raise nothing:
- **16-cell table:** 2³ × 2 kinds = 16. File loads ask in 4 of 8 cells and project loads in 7 of 8, giving 11 ask / 5 load, as tabulated.
- **Load question:** focus on No, `enter` on the focused button, one modal, `LoadGuardScreen` left on its own path.
- **Load dialog:** stacking below 100 columns with a 99/100 boundary arm; the in-dialog invalid path.
- **Painted text:** the internal-id ban with a negative control taken from the prototype captures.
- **P-D:** the declared tag-table freeze with its step name painted first.
- **P-E:** `v` reuses the existing `select_variant`.
- **The modal-key rule** (single letters, or `alt+<letter>` with a text field), with every shown key pressed.

## ⚠ Notices (declared, not blocking)

- ⚠ **P-E B opens a modal after every project load**, including clean ones. The round named this cost ("hay que cerrarlo en cada carga") and the operator chose B anyway. Recorded, not reopened.
- ⚠ **`v` from the panel switches variant through `select_variant`, which the P-B load guard does not cover** (the guard sits in the Load dialog router). Right after a load nothing is unsaved, so this is harmless here. A variant switch over a patched, unsaved image elsewhere is outside this batch and is left for the backlog.
- ⚠ **The Phase-4 expert inspection (§5.1) names this reviewer.** It has to check the visual claims in UX-31 (last row reachable) and UX-32 (buttons pinned) on the real terminal, because the ATs read structure.

## Evidence checklist

| Item | State | How |
|---|---|---|
| Closure of UX-01..UX-25 | `executed` (inspection) | Each closure read in `01-requirements.md` at `0c7ca1d`, and cross-checked with `02-review.md` rows 42-66 and ledger entries .2-.13. |
| Filled slots VS-PA/PB/PC/PD/PE | `executed` | HLR-173..178 slot lines against the verdict JSON and the operator notes. |
| P-E base ordering (UX-26) | `executed` | `workspace.py:1110-1124` read; ordering reproduced with Python `sorted`. |
| Document dirty flag (UX-27) | `executed` | `screens_directionb.py:4801-4808`, `:5805-5823`; `mark_saved` / `mark_loaded` callers in `app.py` found with grep. |
| `#status_text` writers (UX-29) | `executed` | `app.py:13587-13590`; LLR-176.1 and LLR-178.2 text; `png/pd_A.pd.118.png` (visual read of the stale bar). |
| Keyboard-only path | `failed` | UX-05 (path field reach, printable keys on the list), UX-31 (panel body), UX-34 (actions not refused during workers). |
| Refusal / empty state says why and what to do | `failed` (minor residuals) | UX-07 residual, UX-22 residual, UX-35, UX-41. |
| Prototype driven live | `not-run — inspection round` | No variant was run. The claims come from the captures (visual) and the page text, and are marked *inspected, not exercised*. |

### The three acts (ISO 9241-210)

- **Automated walkthrough through the real mechanism:** `not performed`. P2 reviews a contract, and no surface ships yet.
- **Expert inspection against declared criteria:** `performed` (this review), and planned again at Phase 4 in a real terminal (§5.1).
- **Evaluation with users:** `not performed`. The team is one person and this surface has no user outside it.

## Not covered

- The 220×60 captures, and any re-capture of the chosen variants (none was made after the verdict).
- The security merits of S-02..S-16 and the QA/architect closures, except where they change what the user sees.
- Whether `select_variant` and unload should join the load guard. This is outside the batch and listed as a notice.
