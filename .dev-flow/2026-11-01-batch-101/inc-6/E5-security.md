# Inc 6 — E5 security review (implemented code, probed)

Batch 2026-11-01-batch-101, increment 6, branch `b101-inc6`, head `8530ebe`, base `origin/main` `98d94d7`. Reviewer: security-reviewer, independent of the implementers, the testers and the integrator. Scope: `git diff origin/main HEAD -- s19_app tests docs README.md`. That is 4 source files (`tui/app.py`, `tui/screens_directionb.py`, `tui/services/change_service.py`, `tui/window_help.py`), 3 guide pages, `README.md`, and 8 test files (2 new). Records read: `E3-security.md` (S-1 … S-7, Round 2: S-8, S-9), `E3-rulings.md` (both rounds), `E1-rulings.md` §1 and the D-6 row, and the rows of `01-requirements.md`.

Lens (as at E3): no write outside the work area or the open project through a link, `..` or a dangling link; no time-of-check gap between a pick and its read or a Write; displayed check verdicts and the before/after offer stay true; untrusted names painted only through escapers; the meaning of a saved file's location; no new file writer; no clipboard. Severity: HIGH / MEDIUM / LOW / INFO (flow scale: MEDIUM = MAJOR, LOW = MINOR, INFO = note). Tags: `impl` (the code differs from the design), `design-gap` (the design itself leaves the risk).

## Verdict

**PASS-WITH-NOTES.** HIGH 0, MEDIUM 0, LOW 2, INFO 4.

- **Ruled mitigations.** Every E3 mitigation ruled into this increment is `executed` in the code. The code mitigations are also `approved`: their nodes are GREEN on the branch tree, and a mutant of each turns its nodes RED for the stated reason. That covers S-1, S-3, S-4 and S-5. S-2 (revised D-3) is `executed` and `approved` on GREEN nodes and the code read. The record-only rulings S-6 and S-8 are `executed` in the records. S-7 and S-9 stay in the backlog, as ruled.
- **Path safety holds.** The probes found no Write that lands outside the work area or the open project. They tried a link, a dangling link, a linked `.s19tool`, a hard link, and a folder swapped while the popup was open. Every Write claims a free name. No existing file is overwritten, and no file outside the work area changes.
- **New findings, neither blocking.**
  - E5-1 (LOW, `impl`, pre-existing): a dangling link at `workarea/patches` makes a Check Editor Write end the app with an uncaught `FileExistsError`. This happens with or without a project open. Nothing is written.
  - E5-2 (LOW, `design-gap`): the Write status names the file but not its home. After a `library/<n>` pick, the operator cannot tell from the status that the library copy is unchanged.
- This clearance covers the security lens of the E5 gate only. It does not authorise the merge or the push.

## How it was probed

- **Host.** The LAN laptop host only: env `s19ci`, Python 3.11.
- **Tree.** A detached worktree `<HOME>/work/s19_i6s` at `origin/main` `98d94d7`, with `git diff origin/main 8530ebe -- s19_app tests` applied. The result was 10 files changed plus the 2 new test files. A pytest probe checked that `s19_app.__file__` was the worktree's own file.
- **Isolation.**
  - `LOCALAPPDATA` pointed at a `/tmp/i6s-` folder.
  - Every link was made under the test's `tmp_path`.
  - No arm touched the clipboard.
  - Nothing that imports `s19_app` ran on the Windows PC.
- **Helpers.** Each is prefixed `i6s-`: a temporary probe test of 8 arms (A–H), a text-only mutant script that imports nothing from the project, and a runner.
- **Teardown.** The worktree and every helper were removed afterwards: `git worktree list` shows 0 `i6s` entries, and no `/tmp/i6s*` path remains on either machine.
- **Run 1 — mitigation nodes.** These nodes ran on the branch tree: the whole of `test_b101_document_homes.py`, `test_r_tui_049_3_1_control_hidden` and `…_3_2_prompt_hidden` (8 alternatives each), `test_r_chk_pe_009_no_run` (6 arms), `test_r_chk_pe_014_glyph_after_save_back` and `test_r_before_after_report_001_36_1_no_offer_without_a_project`. Result: **60 passed** (1:40).
- **Run 2 — probe arms A–H.** Results are in the table below. State: `executed`.
- **Run 3 — security mutants.** Each mutant was applied alone, and only its claimed nodes ran. `app.py` was copied back after each one, and a final `cmp` against the saved copy was equal. Every RED fails on an assertion about behaviour, never at import or by timeout.

### Probe arms

| # | Set-up | Result |
|---|---|---|
| A | Project open; `proj/checks` made a dangling link to a folder outside that does not exist; Check Editor Write | `Check Editor: spec NOT written.` with `MF-WRITE-CONTAINMENT … destination traverses a symbolic link or reparse point: …/proj/checks`. The link target was not created, and nothing reached the library. |
| B | No project; `workarea/patches` made a dangling link; spec pick `x.chk.json`, then Write | The pick is refused with the row's exact text. The Write **ends the app**: `FileExistsError` from `ensure_workarea` (`workspace.py:141`), raised through `write_change_document` (`changes/io.py:1648`) and the handler (`app.py:7789`). Nothing is written (E5-1). |
| C | Project open; `.s19tool` renamed and replaced by a link to itself; pick `library/w.chk.json`, then Write | The pick is refused (`outside the patches folder`) and the Write gives `spec NOT written.`. No new `.json` file appears anywhere in the real tree. |
| D | `proj/checks/h.chk.json` a **hard link** to a file outside the work area; pick, add a row, Write as `h.chk.json` | The pick is accepted. That is the design: it is a read, and a hard link is no reparse point. The Write gives `wrote h.chk_1.json`, a new claim. The outside file's bytes are unchanged and its link count stays 2. |
| E | Directories named `library/d.json` and `library/e.chk.json` (the glob lists folders); one pick from each of the three lists | Each fails closed with `MF-PATH-UNRESOLVED … IsADirectoryError`. The app keeps running. |
| F | Project open; Apply until the save-back prompt shows; load image 2 with `ctrl+l` | The prompt is not painted, and `#patch_saveback_row` has the class `hidden`. A click on the confirm button returns `False`. After the click, `project.json` and the project tree are unchanged, and there is no `*-patched*.s19` anywhere. The load itself appends `img2` as a variant and rewrites `project.json`, so the snapshot was taken after the load. This is the project half of S-1, which had no E4 case. |
| G | A2B Diff spec `library/w.chk.json` picked, then Save project as `proj2` | The dropdown value is `''` and the stash is `''`. A report cannot carry a check addendum that the screen does not show (E3A-17, as admitted). |
| H | As B, but with a project open, so Write targets `proj/checks/` | The same `FileExistsError` ends the app (E5-1). The Inc 6 project route reaches it too. |

### Mutant results (security subset)

| Id | Operation | Nodes run | Result | RED reason (assertion) |
|---|---|---|---|---|
| M-S5 | The popup accept loads the path checked before the popup (no re-check) | 001.4 `[popup-recheck]` | **KILLED 1/1** | `Loaded change: 1 entry, 0 error(s)` instead of the refusal line |
| M-S3 | The pick guard drops the link walk and the `.s19tool` check, so it only resolves and compares | 001.4 `[link]`, `[inside-link]`; R-CHKED-044 `[link]`; R-DIFF-CHK.5 `[link]`; probe C | **KILLED 5/5** | Each pick reads through the link: `Loaded change: 1 entry`; `Check Editor: loaded 'checks/l.chk.json'`; `Check spec 'checks/l.chk.json' loaded`; C loads `library/w.chk.json` through the linked `.s19tool` |
| M-S4 | The guard returns the resolved path | 001.3/4 `pick_keeps_spelling` | **KILLED 1/1** | The source is `…/real/.s19tool/…`, not the work area's spelling |
| M-S1 | No hide at the image install | 049.3.1 `[image]`, 049.3.2 `[image]`, probe F | **KILLED 3/3** | `Before/after report available:` and `Save patched image as:` stay painted, also in a project |

## Mitigations ruled at E3 — state in the code

| E3 item | Ruled mitigation | State | Code location | Evidence |
|---|---|---|---|---|
| S-1 (MAJOR) | An image load hides the save-back prompt and the control (#10). R-TUI-049.3.1/.3.2 name the image load. | `executed` · `approved` | `app.py:18478`: `previous_map` is taken before `current_file` is replaced. The hide is at `:18548-18549`, behind `loaded.mem_map is not previous_map`, so a MAC attach keeps the reviewed image. The other replace paths: `_patch_editor_load` `:7537` (before `service.load`), paste `:4830`, undo / redo `:5398` / `:5433` (only when the document moved), project reset `:13991`. Helper `:5172`. | 049.3.x `[image]` GREEN; M-S1 KILLED; probe F (project) |
| S-2 (MAJOR) | Revised D-3: in a project the lists show `checks/<n>` and `patches/<n>`, then `library/<n>`. A pick opens the file, and every Write lands in the project home. | `executed` · `approved` | Homes: `_change_homes` `:7044` and `_spec_homes` `:7082`. Scans: `:7118` and `:7162`. `_check_home` `:7010` is path arithmetic only; the Write's placement does the containment check and the `mkdir`. Write: `:7790`. Write as takes the bare name: `load_spec(items, candidate.name)` `:7916`. Refill: `:7393`, called at `:13109` and `:14526`. | 001.1, 001.3, R-CHKED-031 `[after-library-pick]` / `[never-overwrites]`, 040, 042, R-DIFF-CHK.1 / .8 GREEN; probes D, G |
| S-3 (MINOR) | The pick guard uses the Write guard's walk and stop point. Inc 9 is named as an interface. | `executed` · `approved` | `_resolve_listed_file` `:7196-7279`; the walk is at `:7267-7270` and matches `_guarded_destination` (`workspace.py:764-775`): stop below `.s19tool`, then check `.s19tool` itself. The name-shape refusals (empty, `/`, `\`, `..`) are at `:7257-7263`. | M-S3 KILLED 5/5; probes A, C |
| S-4 (MINOR) | The guard returns the unresolved `folder / name`. | `executed` · `approved` | `:7279` | M-S4 KILLED |
| S-5 (MINOR) | `_answer` runs the guard again before loading. | `executed` · `approved` | `:7502-7514`. The Check Editor and A2B Diff picks are synchronous: there is no `await` between the guard and `read_change_document`. | M-S5 KILLED |
| S-6 (MINOR) | The three refusal rows state the linked-folder condition. | `executed` (records) | `01-requirements.md:59`, `:69`, `:72` | Read |
| S-7 (LOW) | Backlog: bidi and format characters in names | backlog, as ruled | `E1-rulings.md:19` item (d) | `safe_text` is unchanged. Every new listed name is painted through `safe_text` into a plain `Text` label (`screens_directionb.py:4923`, `:7273`, `:8721`). Status lines use `!r` (bidi characters are escaped) and `markup=False` (`#diff_status`, `screens_directionb.py:8437-8442`). |
| S-8 (LOW) | Reword the D-6 sentence so a `library/<n>` pick is not refused by the project condition. | `executed` (records) | `E1-rulings.md:59` | Read; the code (`:7275-7278`, inside the resolved work area) agrees |
| S-9 (LOW) | Backlog: no unsaved-edits warning for an edited library document | backlog, as ruled | `E1-rulings.md:21` item (i) | — |
| E3A-03 (verdict integrity) | An in-place write ends the current run, at Inc 5's hook. | `executed` · `approved` | `_note_image_bytes_written` `app.py:18356` calls `end_check_run`, then repaints through the load tail (render only) and `update_checks_view`. The gate is `check_run_is_current` (`change_service.py:2732`). Status `:2772` and aggregates `:2875`, glyphs `:3128`, the Checks tab `app.py:5165` and the Checks screen `:16958` all read it. No other reader of `last_check_result` exists in the package (grep). | R-CHK-PE-009 (6 arms), -014 GREEN |
| Before/after offer (R-BEFORE-AFTER-REPORT-001.1/.36) | The notice is shown only with a project. The control stays. | `executed` | `app.py:5089` | 001.36/1 GREEN. `b` after an image load still refuses as stale (`before_after_service.py:327-333`). |

## Checked, no finding

- **No new file writer, no clipboard.** The `s19_app` diff adds no `open`, `write_*`, `replace`, `mkdir`, `shutil` or clipboard call. The only change on the write side is `dest_dir=self._check_home()` on the existing `write_change_document`, which goes through `copy_into_workarea` → `place_into_workarea` → `_guarded_destination` and the `lstat` + `O_EXCL` claim. The test files write and link only under `tmp_path`, and they state that no case touches the OS clipboard.
- **Write never targets the picked source.** The Check Editor writes the bare name into `_check_home()`, and `_safe_name` strips any folder part. Patch Editor Save writes to `_change_doc_save_home()` (`ChangeService.save` never uses `source_path`). So a `library/<n>` or hard-linked pick is only ever read (probe D).
- **Project folders.** Both `current_project_dir` assignments (`app.py:13106`, `:14523`) take `self.workarea / <name>`. A linked project folder is refused at load and at save. The Write guard's walk covers a project folder that becomes a link after the load.
- **Displayed verdicts.** The run arm paints `result.message` right after the run, while it is current. Every other paint goes through `_refresh_patch_checks_tab`, which gates the rows, the status and the counts on `check_run_is_current`. The subtitle now follows the status line (`screens_directionb.py:6933`), so a stale run shows `no run yet`.
- **Painted names.** The `checks/`, `patches/` and `library/` prefixes are fixed literals. The A2B report addendum passes the listed value through `md_safe` and then `_esc` (`diff_report_service.py:1637`, `:2249`).

## Findings

| Id | Tag | Severity | Where | What · why | Recommendation |
|---|---|---|---|---|---|
| E5-1 | `impl` (pre-existing, outside the slice) | LOW | `changes/io.py:1648`; `workspace.py:135-143` | **A dangling link at `workarea/patches` ends the app on Write.** `write_change_document` calls `ensure_workarea(base_dir)` before its `try`. `mkdir(exist_ok=True)` raises `FileExistsError` when `patches` is a dangling link or a plain file, and the Check Editor handler does not catch it. Probes B and H reproduced this; H was the Inc 6 project route. Nothing is written, so containment holds, but the session's unsaved state is lost. A library linked to a drive that is later disconnected would be enough. Base: the same by code (`changes/io.py` is unchanged, and base Write called the same function); not run on base. | Backlog. Move `ensure_workarea` inside the `try` (or catch `OSError` there), so the outcome is the usual `MF-WRITE-CONTAINMENT` refusal. Other writers that call it get the same fix. |
| E5-2 | `design-gap` | LOW | `app.py:7804-7807`; R-CHKED-031 | **The Write status does not say where the spec landed.** In a project, `library/w.chk.json` is picked and written, and the status reads `Check Editor: wrote w.chk.json (1 fields, kind=check).`. The E4 node asserts exactly this text. The file is in `proj/checks/`, and the library copy is unchanged. An operator can believe the library spec was updated, and a later run without a project then uses the old spec. At base there was one home, so the bare name was not ambiguous. | Paint the home-relative form, in the shape the lists use (`checks/w.chk.json`, and the claimed `_N` name on a collision). Add a status row or an amendment to R-CHKED-031. Not blocking. |
| E5-3 | — | INFO | `_resolve_listed_file` `:7275-7278` | A hard link in `checks/` or `patches/` to a file outside the work area is accepted as a pick. It is not a reparse point, and its path resolves inside. It is only read, and every Write claims a new name (probe D). The typed-path Load already reads any path, so the pick gives no new read. | None. Accepted by design (E3 round 1). |
| E5-4 | — | INFO | `list_change_documents` (`changes/io.py:1743`) | A folder named `*.json` is listed in all three lists. A pick of it fails closed with `MF-PATH-UNRESOLVED` (probe E). In the Patch Editor the failed load still replaces the document with an empty one; the hide runs first. This is functional, not a security issue, and it already happened at base for the library. | Optional: filter `is_file()` in the listing. |
| E5-5 | — | INFO | `workspace.py:1189-1290` | **Remaining race windows, both pre-existing.** A Write's parent folder could be swapped for a junction between the guard and the claim. The claim's `lstat`, `O_EXCL` and post-claim `S_ISREG` / reparse checks hold, but the parent is not walked again; B100 rested this on the immutability invariant. The pick-to-read gap is synchronous, and S-5 closes the popup window. | None for Inc 6. |
| E5-6 | — | INFO | `E1-rulings.md:19` item (g) | Unloading the primary image bumps no generation, so a check run stays current with no image loaded. This is recorded. The stale rows describe the unloaded image; no write can follow from them (a confirm after an unload writes nothing — E3 round 2). | Keep in the backlog as recorded. |

## Evidence checklist

- ✓ Each finding has what, where, why and a recommendation (table above).
- ✓ Each finding has a severity and a tag.
- ✓ No secret values: none are in scope, and none appear here.
- ✓ The verdict is explicit: PASS-WITH-NOTES. No HIGH. Each ruled mitigation is `executed`; the code ones are verified by GREEN nodes and killed mutants.
- n/a — no new tool or integration. No new file writer, and no clipboard.
