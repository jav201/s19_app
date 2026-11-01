# Phase-4 expert UX inspection — s19_app — Batch 2026-10-26-batch-100

- **Reviewer:** `ux-reviewer` (read-only toward the product; no source, test or record other than this file was changed).
- **Discharges:** gap G-001 (`04-validation.md`, *Gaps detected*), contract §5.1 *Expert inspection (Phase 4, UX-16)* and §5.2 bullet 4, PDR finding C-UX-5 (`design/PDR-ux.md`).
- **Product tree inspected:** `main` 570b4b5 (worktree `b100-close`, no product diff against 570b4b5).
- **Date:** 2026-11-01.

## Verdict (read first)

**Expert-inspection row: `PASS-WITH-NOTES`.** 0 blocker, 5 major, 11 minor, 4 cosmetic (20 findings).

- **Severity mapping to §5.2 ("no open HIGH"):** blocker = HIGH. A blocker loses work, or stops the engineer from finishing a task named in the context of use. None of the 20 findings does either, so §5.2 bullet 4 is met. The majors make the engineer misread what was loaded, saved or offered.
- **Two majors are unmet requirement clauses, not just usability issues.** The orchestrator should also log them as Layer-A gaps, because no AT observes them:
  - UX-I-01: HLR-178, last sentence ("the same information shall stay reachable … in the Load dialog's preview of the open project"). LED .68 routed it to Inc 9b, and Inc 9b never built it.
  - UX-I-13: HLR-173a ("mark … exactly the variant … that loading … installs").
- **Proposed for the release-fix increment:** UX-I-01, UX-I-06, UX-I-10, UX-I-12 (preview half), UX-I-13; UX-I-17 if the operator rules on it. Everything else goes to the backlog (table at the end).

| Severity | Count | Ids |
|---|---|---|
| blocker | 0 | — |
| major | 5 | UX-I-01, UX-I-06, UX-I-10, UX-I-12, UX-I-13 |
| minor | 11 | UX-I-02, -03, -04, -07, -08, -11, -14, -15, -17, -18, -19 |
| cosmetic | 4 | UX-I-05, -09, -16, -20 |

## Method

**Context of use** (contract §2.3, refinement-log default):

- **User:** a calibration or test engineer who keeps a session as a project.
- **Task:** prepare and review memory-image changes, save them into a project, and come back later. They reopen a project after a save-back or after damage, and save into a new project, the open project or an existing one.
- **Environment:** a Windows terminal, keyboard first and often resized, judged at 118×54 and 220×60. The engineer "trusts the status line".

**Acts** (ISO 9241-210; kept apart, and the weaker is never offered as evidence of the stronger):

| Act | State | Notes |
|---|---|---|
| Automated walkthrough | `performed` (by the battery, before this record) | `04-validation.md` *UX walkthrough*. Not repeated here. |
| Expert inspection | `performed` (this record) | A cognitive walkthrough of the §5.1 tasks, plus a heuristic review of every batch surface. |
| Evaluation with users | `not performed — this team is one person and no user of this surface exists outside it` | contract §5.1 |

**Heuristics applied:**

- Nielsen's 10, cited as N1 … N10. N1 is visibility of system status, N2 match with the real world, N4 consistency, N5 error prevention, N6 recognition over recall, N8 minimal design, N9 error recovery.
- Terminal heuristics:
  - T1: every action shows its key.
  - T2: the focus is always visible.
  - T3: the state of a long action is visible.
  - T4: the destructive answer is never the emphasised default.
  - T5: text fits at 118 columns and at narrower widths.

**Evidence used and how far it goes:**

1. **Real Windows Terminal PNGs (E13)** at 118×54, 220×60 and 99×54, taken at the increment closes. Each finding cites them as `evidence/inc-*/e13/<name>.<size>.png`. Several predate later increments (for example the footer label, the progress bar and the quit-question emphasis), so every claim taken from them was re-checked against HEAD.
2. **Headless runs at HEAD:** Textual `run_test`, driven through the shipped keys (`p`, `l`, `enter`, `down`, `end`, `escape`, `ctrl+s`, `alt+s`, typed text). A few setup steps used widget presses: the Patch Editor entry and Apply, as the E13 tool does. Each run saved an SVG plus a JSON of the widget state (focused id, painted texts, CSS classes, regions). The SVGs were rasterised with headless Edge for the visual claims, and each finding says which kind of evidence it rests on.
   - **Sizes:** 118×54 for every state; 220×60 for the save-back walk; 80×30, 80×54, 99×30 and 118×30 for the width and height checks.
   - **Location:** the scratch folder `%TEMP%\s19c\ux\out\` (SVG, JSON, `png/`), not committed. The work area and `LOCALAPPDATA` also pointed at scratch, and `%LOCALAPPDATA%\s19_app` was confirmed absent afterwards.
   - **Probe script:** `%TEMP%\s19c\ux\ux_probe.py`. It reuses the E13 seeders in `tools/e13/run.py`, read-only.
3. **Code reading,** cited as `file:function`, to explain a cause. It is never a substitute for a painted result.

**Limit (declared):** §5.1 asks for the inspection "in a real Windows Terminal". The states that only the headless SVGs show were painted by Textual's own exporter, not by Windows Terminal. Those states are the save-back walk, the merge and refusal summaries, the Load preview of a recent row and of the open project, the idle bar at HEAD, and the 80- and 30-row layouts. The text, layout and classes in them are the shipped ones. Font metrics and terminal colour mapping are not. No reviewer drove Windows Terminal by hand in this record.

## Scope

**In scope:** the batch's own surfaces:

- the Load-result panel (HLR-178);
- the Save project dialog and its outcome (HLR-175 … 175f, HLR-167/168 status);
- the Load dialog with projects, work-area files, recents, typed path and preview (HLR-173 … 173e, HLR-172/172b);
- the replace question (HLR-174);
- the progress line, busy refusal and quit question (HLR-176/177).

**Walkthroughs performed** (the §5.1 tasks):

| # | Task | Path driven | Outcome |
|---|---|---|---|
| W1 | Reopen a project after a save-back | `p` → `enter` → `esc` → patch 0x8000007C → `ctrl+s` (name P) → `alt+s` → `p` → `enter` | Panel: `firmware_1.s19`, "recorded as the active variant (the latest saved)", "patched, 4 bytes differ from firmware.s19". **Task succeeds.** The status after the save is stale (UX-I-10), and the summary wording misleads (UX-I-06). |
| W2 | Reopen after damage (not JSON / unreadable variant / 31 problems) | `p` → `enter` | Panel names the fallback reason and every problem; `end` reaches the last row at 118×54 and 80×30 (`scroll_y == max_scroll_y`). **Task succeeds.** Re-reading the problems through "details: p" fails (UX-I-01, UX-I-13). |
| W3 | Save into a new project | `ctrl+s`, name `P2` | "P2 — new folder" and the plan. **Succeeds** (UX-I-06 wording). |
| W4 | Save into the open project | `ctrl+s`, name `P` | "P — updates the open project". **Succeeds.** No active-variant row on a save-back (UX-I-08). |
| W5 | Save into an existing project | `ctrl+s`, name `Q` | "Q — merges into an existing project", plus "active variant firmware (before: none recorded)". **Succeeds.** |
| W6 | Refused and empty names | `CON`; empty + `alt+s` | "'CON' is a device name — choose another name." / "name is empty — type a project name." **Succeeds.** |

**Not covered:**

- Progress-bar movement *during* the A2L parse. No capture shows the parse in progress at HEAD; AT-B100-17 covers it by pilot only.
- The 220×60 rendering of the Save and Load dialogs at HEAD. Only the E13 PNGs (Inc 9b, Inc 11) and the 220×60 save-back walk were read.
- Mouse paths beyond what the E13 PNGs show.
- Colour contrast measurement.
- Surfaces outside the batch.

## Findings by surface

### S1 · Load-result panel (HLR-178, US-168)

**What works:**

- The title states the problem count ("Project P opened with 31 problems").
- Opened, reason, relation ("patched, 4 bytes differ from firmware.s19"), variant count, others, MAC and A2L are all on one screen at 118×54.
- Every problem carries a file and a next step, with no truncation, and it scrolls by keyboard. A scrollbar shows the overflow.
- The safe answer "Close (esc)" carries the emphasis, and `v` is shown on its button (T1, T4).
- The status log gets one summary line ending "details: p" within 118 columns.

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-01 | **major** | N1, N6; HLR-178 last sentence | **"details: p" leads to no details.** After the panel is closed, `p` opens the Load dialog. The preview of the open project shows only the variant marks and "project file: ok". The reason, the relation and the problems are not shown. Seen after an unreadable-variant load that reported 2 problems: `● variant broken.s19 / variant firmware.s19 / project file: ok`. Once the panel is closed, its information cannot be reached again in the session. LED .68 routed this clause to Inc 9b; no Inc 9b record builds it, and no AT observes it. | headless `panel-details.118x54.json` (`details_preview`); `app.py:_load_dialog_preview` (8472–8591) has no announcement input | For the open project, append the last `LoadAnnouncement` to the preview: the reason line, the relation and one line per problem, with the same wording as the panel. Add an AT arm: load with problems, `esc`, `p`, and assert the preview names every problem. |
| UX-I-02 | minor | N2 | The unreadable-variant reason reads "the next valid variant (the recorded one is missing or not readable)". It neither names the recorded variant nor says which of the two cases applies, although the panel knows both. | `evidence/inc-8a/e13/pe-unreadable.99x54.png`; headless `panel-unreadable.118x54.svg` | "the recorded variant broken.s19 is not readable — opened the next valid one". The VS-PE-2 wording changes, so it needs a ledger entry. |
| UX-I-03 | minor | N2, N4 | On an A2L-only project the panel paints "Opened (no image)", the reason "the first variant by name (the manifest records no active variant)" and "0 in the project". The reason contradicts the other two rows. "Select variant (v)" is offered with 0 variants. | headless `panel-a2l.118x54.png`; `evidence/inc-8b/e13/pe-a2l-only.118x54.png` | When the count is 0, use the reason "no image in this project (A2L only)" and disable or hide `#result_variant`. |
| UX-I-04 | minor | T2 | The focus starts on `#result_body`, which shows it only as a background tint (`#result_body:focus { background: $bg-base }`). "Close (esc)" is always filled, so it looks focused. `enter` on the body does nothing. | `styles.tcss` (`#result_body:focus`); E13 `pe-*.png`; headless JSON `focused: result_body` | Give `#result_body:focus` the same round accent border as `#load_list:focus`, or add a hint line "↑↓ PgUp PgDn scroll · tab Close". |
| UX-I-05 | cosmetic | N8 | 30 identical "manifest damaged: ../escape_NN.json a file path points outside the project – Save project rewrites it" rows, each wrapping to 2 lines (3 at 80 columns). | `evidence/inc-8a/e13/pe-problems.118x54.png`; headless `panel-problems.80x30.png` | Group rows that share a reason ("30 files point outside the project:" followed by the names), keeping no truncation. |

### S2 · Save project dialog (HLR-175 … 175f, US-165)

**What works:**

- `#save_where` names the target and its kind: "new folder", "updates the open project" or "merges into an existing project". A long name wraps instead of clipping (80×30).
- A merge names the active variant it sets, with the value before.
- A refusal or an empty name is painted with its reason and next step before Save.
- `esc` and `alt+s` are shown on the buttons (T1). The focus starts in the name field.

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-06 | **major** | N2, N4; HLR-175 intent ("exactly what will be saved") | **One file is described by two rows that read as contradictory.** The image-content row has no label and its own grammar, followed by the landing row: "firmware.s19 unchanged copy" + "image firmware.s19 — keep" (copy *and* keep?). In a save-back, "firmware.s19 + 1 change entry, 0 applied by this save" reads as "your change is not applied". In fact the entry is already in the image: the outcome line says "1 entry applied before this save". This is the summary the operator asked to be "extra careful" about (P-C), and §5.1 names it for this inspection. | headless `walk-saveback-1save.118x54.png`, `save-other.118x54.png`, JSON `summary_rows`; `app.py` (image content line ≈12643–12656, summary rows ≈11330–11345) | Fold the content into the landing row: "image firmware.s19 — keep (unchanged)" / "image firmware.s19 → firmware_1.s19 — new (source + 1 change entry, already applied)". Drop "0 applied by this save" from the dialog and the outcome. Check that AT-B100-16/21 still match, since they compare rows by landing name and action word. |
| UX-I-07 | minor | N1 | The dialog has no title naming the action. Its only heading is "Project name", while the Load dialog is titled "Load". | E13 `sd-dialog.*.png`; headless `titles: ["Project name"]` | Add a title "Save project" above the field label. |
| UX-I-08 | minor | N1, N5 | A save-back into the open project switches the active variant (firmware → firmware_1), but the summary has no "active variant … (before: …)" row. The dialog shows that row for a merge only. | headless `walk-saveback-1save.118x54.png` (no such row); `save-other.118x54.png` (row present) | Paint the active-variant row whenever the save changes `active_variant`. This needs a ledger entry (LLR-175.4). |
| UX-I-09 | cosmetic | N1 | During a refusal the summary is an empty bordered strip. | headless `save-con.118x54.png` | Paint one row: "nothing will be saved". |

### S3 · After Save project (status line, HLR-176c / HLR-168)

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-10 | **major** | N1, N4; §2.3 ("they trust the status line") | **After a save-back the status line names the old variant.** `#status_text` reads "Loaded project 'P' -> firmware.s19", while the right segment of the same row reads "P:firmware_1 (2/2)". Two status elements disagree on what is open, right after the action that changed it. Cause: the end of the busy action hands back the status text stored when the action began. | headless `walk-saveback-2saved.118x54.png` and `.220x60.png`; JSON `after_save_status`; `app.py:end_busy` (20299) | Make Save project's final writer set `#status_text` to the project and the now-active variant, for example "Saved project 'P' -> firmware_1.s19", as HLR-178 already requires of the load. Add an AT-B100-16 arm: after a save-back, `#status_text` names `firmware_1.s19`. |
| UX-I-11 | minor | T5 | The save outcome line leads with the absolute work-area path. At 118 columns it is clipped at "— fir…", losing what was saved. | headless `walk-saveback-2saved.118x54.png` (220×60 shows the full line) | Lead with the project and variant, and put the path last or make it relative to the work area. |

### S4 · Load dialog (HLR-173 … 173e, HLR-172/172b, US-162/163)

**What works:**

- `p` focuses the list on the open project; `l` focuses the path field (C-UX-2 discharged).
- The sections render in order; the headings are disabled and skipped by `down`; `●` marks the install set.
- A refused typed path keeps the text and paints "not found — check the path"; an empty Load paints "nothing selected — pick a row or type a path".
- `esc` closes. Names render literally (`[b]markup[red]text.s19`, E13 `wa-files-closed`).
- The layout stacks below 100 columns and is usable at 99×54 and 80×54. The footer label at HEAD is "^l Load" (the "^l Load file" label in early captures is gone).

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-12 | **major** | N6, N5 | **Two recent sources with the same file name cannot be told apart.** Recent rows paint only the name and kind, so `firmware.s19` from two folders gives two identical rows "firmware.s19 (s19)". The preview's path line is cut at the end (nowrap + ellipsis) at 118 columns, which hides exactly the distinguishing folder and the file name: "C:\…\s19_app-b100-close\example…". In this domain one image name across release folders is the norm, so the engineer can reopen the wrong image. | headless `load-recent.118x54.png`, `load-p.118x30.png`; `styles.tcss` (`#load_preview Static` nowrap/ellipsis) | **Release-fix:** let the preview's path line wrap, or ellipsise in the middle so the tail is kept. **Backlog (needs a ledger entry, LLR-173.4):** add the parent folder to a recent row's label when names collide ("firmware.s19 · case_02_gaps… (s19)"). |
| UX-I-13 | **major** | N1, N5; HLR-173a | **The preview marks a variant that the load will not install.** For a project whose recorded variant `broken.s19` is not readable, the preview marks `● variant broken.s19`. Loading installs `firmware.s19`, as the panel had just said. The mark promises "exactly the variant … that loading installs", and here it shows the opposite. | headless `panel-details.118x54.json`; `app.py:_load_dialog_preview` | For the open project, mark from the last announcement (what actually installed) and tag the recorded one "not readable". For any other project, where nothing is read before Enter, label the mark "recorded active (checked when loaded)" instead of implying it will install. Can ship with UX-I-01 (same function). |
| UX-I-14 | minor | T1; PDR C-UX-9 (owed at Inc 9b) | No hint line. That `enter` loads, and that `tab` moves between the path and the list, is shown nowhere. Only `alt+l` and `esc` are on the buttons. C-UX-9 is undischarged. | E13 `ld-dialog.*.png`; `screens.py:LoadDialog.compose` | Add a hint line built from the shipped keys: "enter loads · tab path/list · esc closes". |
| UX-I-15 | minor | T5 | Stacked and short (80×30): the list shows 2 rows ("Projects", "P"). Q, the work-area files and the recents are hidden behind a scrollbar, while 4 blank rows sit above the buttons. 80×54 and 118×30 are fine, so it is the combination of narrow and short. | headless `load-p.80x30.png` vs `load-p.80x54.png`, `load-p.118x30.png` | In stacked mode give the list 2fr and the preview 1fr (min-height 4), and remove the blank band above the buttons. |
| UX-I-16 | cosmetic | T5 | The path placeholder is cut in the two-pane layout at 118 ("…, .a2l, or a"), losing "project folder". | E13 `ld-dialog.118x54.png` | Shorter text: "file path (.s19 .hex .mac .a2l) or project folder". |

### S5 · Replace question (HLR-174, US-164)

**What works:** one question that names every unsaved item; the focus starts on Cancel, with the focus ring visible on the label; `y` and `n` are shown on the buttons; `esc` cancels.

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-17 | minor | T4, N4 | The destructive answer "Replace (y)" carries the filled primary style. The quit question carries the opposite since OBS-12b-2. The same component class now uses opposite emphasis conventions, and here the emphasis points at the answer that discards unsaved work. It is not the default, because the focus is on Cancel, so a misread `enter` fails safe. Fix round 2 kept this on purpose ("the load question unchanged", with a test asserting it), and the pb_A prototype showed it. **It needs an operator ruling, not a silent change.** | headless `replace-q.118x54.png`, JSON `yes_primary: true`; `screens.py:ConfirmQuestionScreen.PRIMARY_BUTTON`; `fix-round-2.md` §OBS-12b-2 | Recommended: `PRIMARY_BUTTON = "confirm_no"` for the load question too (one line), with the fix-round-2 arm re-pinned. |
| UX-I-18 | minor | N2 | The title "Replace firmware.s19?" frames the question as a file replacement, while the body asks "Load project P anyway?" and the button says "Replace". The consequence (the unsaved work is lost) is implied, not stated. | E13 `lq-question.118x54.png` | Title "Load project P?"; body "Unsaved: changes in firmware.s19, Patch Editor entries. They will be lost."; buttons "Load and discard (y)" / "Cancel (n)". Needs a VS-PB-1 ledger entry. |

### S6 · Progress line, busy refusal, quit question (HLR-176/177, US-166/167)

**What works:**

- The progress line holds the spinner, the label, `step n/m` with the step name, and the elapsed `mm:ss`; the bar sits on its own row (T3).
- A second request is refused with "busy: Saving project P9 is running — wait for it to finish." (headless `busy-refuse.118x54.png`).
- The quit question names the running action, with Stay focused and, at HEAD, emphasised (OBS-12b-2).
- The two disagreeing clocks of Inc 12a are resolved at HEAD: `evidence/inc-12a/e13/bz-busy.118x54.png` showed the bar's "00:00:01" next to the line's "00:06", and HEAD has `show_eta` off.

| Id | Sev | Heuristic | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| UX-I-19 | minor | N1, T3 | When idle after an action, the bar row paints an empty track with "0%". It reads as an action at 0 % or stalled. C-UX-7 asked to keep the row but hide the bar. | headless `idle-after.118x54.png` (JSON `bar.progress 0, display true`) | Hide the percentage, or the whole bar with `visibility: hidden`, while idle, and keep the row. |
| UX-I-20 | cosmetic | N2 | The quit text starts in lower case ("still working: …"), and "wait, or quit after it finishes" leaves it unclear what `y` does. | E13 `qz-quit.118x54.png` | "Saving project P1 is still running. Quit (y) waits for it to finish, then quits." |

## Routing proposal

| Route | Findings | Why |
|---|---|---|
| **Release-fix increment** | UX-I-01, UX-I-13 (one function, `_load_dialog_preview`, plus one AT arm); UX-I-10 (Save's final status writer, plus one arm); UX-I-06 (summary wording, with the AT-16/21 row matchers checked); UX-I-12, preview half (wrap or middle-ellipsis of the path line) | The majors. Two of them close unmet requirement clauses (HLR-178, HLR-173a). All are local changes in `app.py`, `screens.py` and `styles.tcss`. |
| **Operator ruling, then release-fix or backlog** | UX-I-17 | It reverses an approved prototype look and a fix-round-2 assertion. |
| **Backlog** (`BACKLOG-CODE.md`, batch-100 routing section) | UX-I-02, -03, -04, -05, -07, -08, -09, -11, -12 (list-label half), -14 (C-UX-9, still undischarged), -15, -16, -18, -19, -20 | Minor and cosmetic. UX-I-02, -08, -12 (list) and -18 change contract wording and need a ledger entry first. |

## ⚠ Notices (declared, not blocking)

- ⚠ Several E13 PNGs predate later increments (the footer label, the idle bar, the quit emphasis). Any future reader should treat `evidence/inc-*/e13/` as close-of-increment snapshots, not as HEAD.
- ⚠ The headless SVGs, JSON and rasterised PNGs of this record live in scratch only (`%TEMP%\s19c\ux\out\`). If the orchestrator wants them kept, they belong under `evidence/p4-ux/`. This reviewer did not write them into the repo.
- ⚠ The recent-sources rows in the 80×30 and 118×30 runs show two entries. The headless runs shared one scratch store, which is how UX-I-12 surfaced; it is not a product duplication bug.

## Orchestrator rulings (2026-11-01)

- Verdict PASS-WITH-NOTES accepted for the expert-inspection row (G-001 discharged). Probe evidence moved to `evidence/p4-ux/` (SVG, JSON, rasterised PNG, `ux_probe.py`).
- Release-fix increment (before the first-release baseline): UX-I-01 + UX-I-13 (same function, an AT arm each), UX-I-10 (arm), UX-I-06 (wording; AT-16/AT-21 matchers re-checked), UX-I-12 preview half (path shown in full or cut in the middle). The recent-row folder label goes to the backlog.
- UX-I-17 rule: a question's filled (primary) emphasis follows its focused default, the answer Enter picks. If the replace question's default focus is `Replace (y)`, it keeps the emphasis; if the focus is the safe answer, the emphasis moves to it. The release-fix increment checks the focus and applies the rule; the test that asserts the current emphasis is re-pinned to the rule.
- Every other finding goes to BACKLOG-CODE, including UX-I-14 (C-UX-9, the Load dialog hint line, owed since Inc 9b).
