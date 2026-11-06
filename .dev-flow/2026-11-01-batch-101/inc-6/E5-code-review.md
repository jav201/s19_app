# Inc 6 — E5 code review

Batch 2026-11-01-batch-101, increment 6. Reviewer: code-reviewer (independent of the implementers, the testers and the integrator). Scope: `git diff origin/main HEAD -- s19_app tests docs README.md`, with origin/main = `98d94d7` and HEAD = `8530ebe`. That is 4 source files (`app.py`, `change_service.py`, `screens_directionb.py`, and `window_help.py`, which changes text only), 2 new test files, 6 edited test files, and 4 doc files. I read all of it in full against `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md` (rounds 1 and 2), `codewire/graph-inc6.md` and the E4 notes, including `E4-integration-notes.md`.

I ran nothing that imports `s19_app` (operator rule). Every statement about a test run comes from the integrator's transcripts `evidence/inc-6/int-00` … `int-08` and from the testers' base runs `red-01-tester1-base.txt` and `red-01-tester2-base.txt`. To tie those transcripts to this diff, I rebuilt the staged tree with a temporary index (`git read-tree 98d94d7`, then this diff through `git apply --cached`). It gives `4d71b9b7e1bd…`, the final tree of int-05 and int-07.

## Verdict

**PASS-WITH-NOTES.** There is no BLOCKER, HIGH or MAJOR finding. I traced the product code against every row, and it is correct. It matches the 37 slice nodes:
- The offer appears only when a project is open, with the exact text.
- The hide runs on all eight replacement routes and never on Save project.
- There is one in-place-write seam (Inc 5's hook), and nothing else ends a run.
- One pick guard reuses the Write guard's walk and stop point.
- The lists refill at both sites that assign `current_project_dir`, and no other site assigns it.

There are three MINOR findings:
- F1: the guide text and two captures contradict the shipped behaviour.
- F2: stale docstrings on the replaced guard and the offer.
- F3: a case clause, "no file written", that cannot fail.

There are also three NITs. Every finding is a recommendation, and none blocks the increment.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Code = graph | All 37 nodes match. **#1:** the `notify` is gated on the `project_dir` already read after `save_patched` (`app.py:5089`), and `show_before_after_prompt()` stays unconditional (D-2). **#2–#4, #31:** hide and render sites. **#7, #10:** reset and install (`:13991-13995`, `:18548-18555`). **#12–#16, #32:** homes, scans and guard. **#17–#19:** pick handlers. **#23:** `dest_dir=self._check_home()`. **#33:** three statements prepended to Inc 5's body (`:18356-18363`). **#35–#37:** list refill. **G2/G3:** I-1 … I-4 and I-7 exactly as the graph states them. | executed (read) |
| 2 | Exact texts | The offer, the three refusals, `Check Editor: spec NOT written.`, the `.8` loaded status and the `.11` reason are unchanged or equal to the rows. Status lines name the listed value; Write as takes `candidate.name` (R-CHKED-042). | executed (read) |
| 3 | Every replacement route hides both controls | Load, pick and popup accept all go through `_patch_editor_load`, which hides first (`:7537`). Both `ChangeService.load` and `load_text` always assign the document (`change_service.py:1584`, `:1648`), so a failed read is a replacement too. **Paste:** the `parse_paste` arm; Edit-JSON Confirm posts `parse_paste`. **Undo/redo:** only when `service.document is not before`. `undo()` and `redo()` return the same object on an empty stack (`:1019`, `:1055`), so the /7 negative arm holds. **Project load:** the reset. **Image load:** `loaded.mem_map is not previous_map`. A MAC or A2L attach keeps the dict and hides nothing, which matches the *image load* Definition. | executed (read) |
| 4 | Hide not on Save project | `_on_project_saved` reaches only `_note_image_bytes_written` and `_patch_editor_load_tail`, and neither hides anything. The refill's `set_options` resets each Select to blank, which posts no pick (`screens_directionb.py:6158`, `:8806`). | executed (read) |
| 5 | Every project-change path refills | `self.current_project_dir =` and `self.current_project =` are each assigned only at `:13105-13106` (Save project) and `:14522-14523` (install). `_refill_document_lists()` follows each assignment directly. There is no project-close path. | executed (read, grep) |
| 6 | No second in-place-write seam | `end_check_run` has one caller (`app.py:18356`). The hook's callers are apply (`:4922`), save-back (`:5054`) and Save project with an image (`:13032`), as I-8 states. | executed (read, grep) |
| 7 | Pick guard = Write guard | `_path_traverses_reparse_point(path, stop_at=workarea.parent)` plus `_is_reparse_point(workarea.parent)`, the same walk and stop point as `copy_into_workarea` (`workspace.py:770-778`). `OSError` counts as a refusal. Containment is in the resolved work area. The unresolved `folder / name` is returned (S-4), and the popup's `_answer` runs the guard again (S-5). Project folders always lie inside the work area: the load refuses others (`app.py:14143-14164`), so the containment test cannot refuse a legitimate project entry. | executed (read) |
| 8 | Readers of the run state | `check_aggregates`, `check_rows`, `check_display_rows` and `last_check_result` are read only in `app.py`, `checks_view.py` and the panel. No report service reads them, so the new gate changes no report. | executed (grep) |
| 9 | `app.py` edits are local | Every hunk falls inside a slice function or a new private helper, plus one import (`scoped_home_target`). | executed (read) |
| 10 | Reuse | Reused as they are: the workspace reparse helpers, Inc 5's hook, `list_change_documents`, `scoped_home_target`, `write_change_document(dest_dir=)`, and `hide_*_prompt`. No new parsing or write surface. | executed (read) |
| 11 | Tests assert the case result from product output, wait for a sign, and can fail | Oracles: painted Patch Editor and Checks-screen strips, the inspector border subtitle, `#patch_checks_status`, the strip, result children, DataTable cells, option values and labels, status-log lines since a mark, and files on disk. Every absence read first proves that the JSON tab is painted (`await_gone`), and every negative arm waits for a later press's sign. Base RED: 38 and 34 nodes, all for behavioural reasons, with the standing guards declared. Gap: F3. | executed (read); verified (linux, int-01: 215 passed; int-07: 261 passed) |
| 12 | Edited existing nodes | `test_at_038a` now keys on the title and pins the exact text. The `checks_screen` injections carry the stamp, the state a real run leaves. The `check_editor` spy takes the full writer signature. `symbol_reads` stages into `P/checks/`. `help_legend_docs` pins the stale sentence and extends `_FIXED` by named supersession (I-D2). None of these weakens an assertion. | executed (read) |
| 13 | Docs and help | README, ch10, DOSSIER §5 and `window_help.py` match the change. ch08 does not match: see F1. | executed (read; captures viewed) |
| 14 | Mutant table | Not run by me; this is E5's runner. | not-run |

## Findings

### F1 — the guide contradicts the shipped behaviour in §8.9 and beside two captures  [MINOR · impl (doc)]
- **What:**
  - §8.9 is the no-project save-back (§8.10 opens "Without a project"), yet it still says "A notice offers the before/after report with `b`."
  - Its capture `ch08-09-patch-image-written.png` shows the toast `… (action: before_after_report).` with project `(none)`.
  - §8.19 now says "The Checks tab shows no stale run after the project load". Its capture `ch08-20-patch-before-after-report-project.png` shows `Checks: 3 passed, 1 failed, 1 uncheckable` and `5 checked`, which is the F-40 state.
- **Where:** `docs/user-guide/ch08-patch-editor.md:102` (§8.9), and `:176` with `:180-182` (§8.19).
- **Why it matters:** E3A-09 asks E4 to update the text the change makes stale. On the first, an operator reads a claim the app no longer makes. On the second, the text contradicts its own picture. Inc 14's capture-note convention (R-DOC-GUIDE.1.12) exists for exactly this case. The E1 slice listed only `:109` and `:181`.
- **Suggested fix:** in §8.9, replace the sentence with "Without a project no before/after offer is shown (8.10)." and add `(capture taken before 1.0.0: it shows the earlier offer toast)`. In §8.19, add `(capture taken before 1.0.0: it shows the earlier run's results)`. Optionally add `("ch08-patch-editor.md", "ch08-09-")` and `("ch08-patch-editor.md", "ch08-20-")` to `_CAPTURES_BEFORE`, by named supersession as I-D2 did.

### F2 — the docstrings of the replaced guard and the gated offer still describe the base  [MINOR · impl]
- **What:**
  - `on_patch_editor_panel_change_file_selected` Data Flow still says "Build `candidate = patches_dir / event.filename` and re-resolve" and "F1 guard … not inside `patches_dir.resolve()`", and `Uses: _patches_dir` (`app.py:7456-7473`).
  - The spec pick handler (`:7870`) and the A2B pick handler (`:8192`) still "re-resolve under the patches folder".
  - `on_patch_editor_panel_save_back_decision` still says a successful save "offers the before/after report action" with no project condition (`:4993-4995`).
  - `PatchEditorPanel.set_change_files` Args (`screens_directionb.py:4886`) and `AbDiffPanel.set_check_files` Args (`:8788`) still say "bare names", but the values now carry `checks/`, `patches/` or `library/`.
- **Why it matters:** this is the repo's docstring contract, and Inc 5 E5 raised the same class as its F2. The text misdescribes a security guard: the walk refuses a link that stays inside the project, and containment is the work area, not `patches/`. A later editor who reads the docstring as the rule could restore the old check.
- **Suggested fix:** in the three handlers, describe `_resolve_listed_file` over `_change_homes()` / `_spec_homes()`: refused when the prefix is unknown, the name is not plain, a link lies on the walk from the work area, or the file is outside the work area; the unresolved path is returned, and the popup accept checks again (S-5). Add "only when a project is open (R-BEFORE-AFTER-REPORT-001.36)" to the offer sentence. Say "listed values (`checks/`, `patches/`, `library/` prefix in a project; bare without)" in the two Args.

### F3 — the "no file written" clause of R-TUI-049.3.2/1 and /8 cannot fail  [MINOR · design-gap (case)]
- **What:** `test_r_tui_049_3_2_prompt_hidden` ends every arm with `assert not list(app.workarea.rglob("img-patched*.s19"))` (`tests/test_b101_patch_lifecycle.py:460`). No arm ever presses Write file, so nothing could write that file, with or without the fix. The assertion also holds on base. Case /8 states its base as "a confirm writes image 2 under that name", but the case's Inputs contain no confirm.
- **Why it matters:** the prompt-absence assertion is discriminating, so the requirement's threshold is met. The S-1 consequence the case names, though, is asserted by a line that cannot turn RED. The case and the node docstring claim more than they check (false confidence in that one clause).
- **Suggested fix:** in `02-test-cases.md` /1 and /8, drop "no file written" / "no `img-patched.s19`" from the Expected result, or note it as implied by the absent prompt. Delete the assertion, or keep it with a comment saying it is a sanity check, not an oracle. A discriminating variant would need a route that reaches the confirm while the prompt is hidden, and the shipped UI offers none.

### F4 — the pick guard accepts the name `.`  [NIT · impl]
- **What:** `pathlib` drops a `.` part, so for `patches/.` the guard builds `folder / "."` = the folder itself. That path is inside the work area, so the guard returns it (`app.py:7258-7264` refuses only an empty name, `/`, `\` and `..`). In the Patch Editor, `_patch_editor_load` then hides the controls and replaces the document with a read-error document, instead of showing the row's refusal text.
- **Why it matters:** the listing cannot reach it (`list_change_documents` globs `*.json`); only a crafted message can. It is still outside R-PATCH-DOC-DROPDOWN-001.4 ("lies outside its folder" → refuse).
- **Suggested fix:** `if name in ("", ".", "..") or "/" in name or "\\" in name: return None`.

### F5 — duplicated scan loop and refusal text  [NIT · impl]
- **What:** `_scan_patch_change_files` and `_scan_spec_files` share the same four-line loop over different homes (`app.py:7156-7160`, `:7190-7194`). The pick handler builds the Patch Editor refusal f-string twice, once at the first check and once in the popup's re-check (`:7486-7489`, `:7508-7512`).
- **Suggested fix (optional):** add one `_scan_homes(homes)` helper that both scans call, and one local `refuse()` closure in the pick handler, so that the R-PATCH-DOC-DROPDOWN-001.4 text has a single spelling.

### F6 — every Apply now renders the ledger twice  [NIT · design-gap]
- **What:** the in-place-write hook runs the whole `_patch_editor_load_tail`: `refresh_entries`, `refresh_issues`, three enable guards and the Checks tab (`app.py:18358-18362`). The `apply_doc` arm then runs the same tail itself (`:4931-4955`). The graph (#33) approved this. For save-back and Save project the tail is the only repaint, and it is needed. Relatedly, the comment in the load tail, "a load replaces the document, so any completed run is no longer current" (`:7596`), now also covers the hook and Save project. Under the CTX *current run* a reload of identical entries keeps the run current, so the comment overstates.
- **Why it matters:** there is no behaviour impact. The cost is one extra ledger render per Apply.
- **Suggested fix (optional, a graph change):** skip the hook's tail call when the caller re-renders anyway, or narrow it to `refresh_entries` plus `_refresh_patch_checks_tab`. Reword the comment to "re-render the Checks tab from the live run state".

## Carried, not findings

- E4 already records M10, M27 and M35 as equivalent mutants on every project load that can be built, and M28 as the effective control (I-D3).
- E3A-17 is admitted behaviour, and S-9 is in the backlog.
- The Windows file-link and junction arms are unexercised (operator rule; I-D5).
- The mutant table and the coverage audit belong to E5's other roles.

## Evidence checklist

- [x] Diff read in full: `app.py` (+488 / −58), `change_service.py`, `screens_directionb.py`, `window_help.py`, the 2 new test files (801 + 1117 lines) and the 6 edited test files, `README.md:190-195`, `ch08:105-110` and `:177-182`, `ch10:23-24`, and DOSSIER §5.
- [x] Correctness pass: None, empty and error paths (failed read, empty undo stack, unmounted panels, `OSError` in resolve, an unknown or bare prefix, `..`, `.` → F4) and every replacement and project-change route (checks 3–5).
- [x] Simplicity pass: no premature abstraction; the double render is F6 and the duplication is F5.
- [x] Reuse checked against the workspace helpers, Inc 5's hook, `list_change_documents` and `scoped_home_target` (check 10).
- [x] Tests reviewed for intent: oracles, rule-7 signs, absence reads gated on a painted surface, base RED, and the one vacuous clause (F3).
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH or MAJOR finding to resolve.

## §4b Independent review cell

`code-reviewer · PASS-WITH-NOTES · no HIGH (none to resolve); open as recommendations: F1–F3 MINOR (guide §8.9 and captures ch08-09 / ch08-20; stale guard and offer docstrings; vacuous "no file written" clause of R-TUI-049.3.2/1, /8), F4–F6 NIT (`.` name in the pick guard; duplicated scan loop and refusal text; double ledger render per Apply)`
