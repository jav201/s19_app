# Inc 9b — E5 corrective notes (increment 018, the one corrective pass)

Tree: `C:/Users/jjgh8/Github/s19_app-b100-inc9b`, branch `b100-inc9b`, on `741cc07` plus the uncommitted changes below. Rulings: `E5-rulings.md`. Evidence: `../evidence/inc-9b/red-02-corrective.txt`, `green-03-corrective.txt`, `green-04-new-and-guards.txt`.

## Outcome per id

| Id | Outcome | Where (file:line after the pass) |
|---|---|---|
| CR9b-01 | Fixed (test). The `ctrl+k` arm now also asserts that the main screen under the modal keeps its focused widget (`screen_stack[0].focused is` the one before `ctrl+k`) and that its CommandBar palette stays closed (`palette_is_open is False`). The mutant that drops `focus_palette` from the guard turns the test RED: `'ctrl+k': True` (the old arm still passes) and `'ctrl+k main focus kept': False`. | `tests/test_b100_load_dialog.py:1088` (function), the `ctrl+k` block and the two new asserts in it |
| CR9b-02 | Fixed (test). The store is seeded `[gone, cal, fw]`, so `fw` is last. The store is read right after the `fw` load, before the `cal` load, and the test asserts `after_fw[0] == fw`. The mutant with `record_recent_source` as a no-op turns it RED (`fw` stays last). | `tests/test_b100_load_dialog.py:743` |
| CR9b-03 | Fixed. New reason `link file` → `("is a link or junction", "open the file it points to")`. `_typed_load_route` returns it when the lstat walk meets a link and the typed path names a data or A2L file that is not `project.json`. The status line is `File NOT loaded: '<t>' is a link or junction — open the file it points to.`, with no "Project". The project-link wording (`link`) is unchanged. | `s19_app/tui/app.py:303` (token row), `:13444-13449` (walk), `:13557-13561` (status line); docstring `:13378-13379` |
| CR9b-04 | Fixed (docs, not source). The docstring names `LoadDialog`. `architecture.md` B100-I8 says the router takes `Optional[LoadChoice]` only. In REQUIREMENTS.md, LLR-151.1 is `superseded by batch-100 HLR-173 (Inc 9b)`, and the other mentions now say the Load dialog (`LoadDialog`). | `s19_app/tui/os_clipboard_input.py:470`; `docs/architecture.md:670`; `REQUIREMENTS.md:309`, `:914`, `:960-961`, `:1262`, `:6478` |
| CR9b-05 | Backlog (Inc 12a sweep). No change. | — |
| CR9b-06 | Fixed. `Summary:` and `Dependencies` (`Uses` / `Used by`) sections were added, with `Args` / `Returns` where they apply, in the file's docstring format. | `s19_app/tui/screens.py:370` (`_initial_index`), `:407` (`on_key`), `:471` (`action_load`), `:530` (`_close`), `:555` (`on_descendant_focus`) |
| SEC9b-1 | Fixed, ruling B (refuse, not truncate). `#load_path` has `max_length=4096`. Textual refuses an edit that would go past it, so an over-long paste leaves the field unchanged. `_typed_load_route` now calls `resolve_input_path` once, inside `try`. A `ValueError` or `RuntimeError` returns `("refuse", "not found")`, which maps to `not found` / `check the path`. Before, the call was made twice (once per branch) with the same arguments; there is now one call before the branch. | `s19_app/tui/screens.py:326`; `s19_app/tui/app.py:13390-13398`; docstring `:13352-13354` |
| SEC9b-2 | Fixed. The preview gate and the install gate refuse a `project.json` that is not `S_ISREG` **or** is a reparse point (`_is_reparse_point`). This is the `_folder_holds_project` test. The refusal text is unchanged (`could not be read`). | `s19_app/tui/app.py:7718-7722` (preview), `:12216-12219` (install) |
| SEC9b-3 | Fixed. `_list_project_files` skips an entry when `is_file(follow_symlinks=False)` is False **or** `_is_reparse_point(item)` is True. That costs one more `lstat` per entry. | `s19_app/tui/app.py:12733-12741`; docstring Data Flow / Uses |

## New and changed test arms (10 items)

| Arm | Id |
|---|---|
| `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open` (changed) | CR9b-01 |
| `test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged` (changed) | CR9b-02 |
| `test_tc_b100_63_typed_linked_file_is_explained_as_a_file[linked s19]` (new; a file symlink in `temp/`; skips where `os.symlink` raises, and ran here) | CR9b-03 |
| `test_tc_b100_63_typed_linked_file_is_explained_as_a_file[a2l through a junction]` (new; Windows only) | CR9b-03 |
| `test_tc_b100_63_over_long_paste_is_refused_and_the_app_stays_up` (new: 40 000 characters refused, field `""`; exactly 4096 accepted whole) | SEC9b-1 |
| `test_tc_b100_63_resolve_error_is_refused_not_raised[ValueError-relative / ValueError-absolute / RuntimeError-relative]` (new, 3 items) | SEC9b-1 |
| `test_tc_b100_64_project_json_that_is_a_reparse_point_is_refused` (new; `_is_reparse_point` patched True for `project.json`) | SEC9b-2 |
| `test_tc_b100_64_reparse_file_in_a_project_is_neither_listed_nor_installed` (new; `_is_reparse_point` patched True for `b.s19`) | SEC9b-3 |

Helpers added: `LINK_FILE` (`:2490`), `_reparse_names` (`:3197`).

## RED → GREEN evidence

- **RED on 741cc07's source** (`red-02-corrective.txt` Part 1). Scratch tree `scratchpad/base10`; my test file was copied there as `tests/test_corr9b_load_dialog.py`; the source was not edited. `s19_app.__file__` = `…\scratchpad\base10\s19_app\__init__.py`. **8 failed, 2 passed.**
  - CR9b-03 ×2: `link or junction — pick a project in the list`.
  - SEC9b-1 paste: the field held `40000` characters.
  - SEC9b-1 resolve ×3: the injected `ValueError` / `RuntimeError` escaped the key handler.
  - SEC9b-2: `timed out waiting for the refusal line` (the base loaded the project).
  - SEC9b-3: `['variant a.s19', '● variant b.s19', 'project file: ok']`.
  - The 2 passes are CR9b-01 and CR9b-02. Those are test-only fixes of correct code, so they are expected to pass on the base.
- **RED by mutant** for CR9b-01 and CR9b-02 (`red-02-corrective.txt` Parts 2a and 2b). These are one-off pytest plugin mutants (`scratchpad/corr9b/plugins/corr9b_mutant.py`, source in the transcript) run on the worktree; no source was edited. `s19_app.__file__` = the worktree.
  - `drop_focus_palette`: **1 failed**.
  - `skip_recent_record`: **1 failed**.
- **GREEN in the worktree** (`green-03-corrective.txt`): **10 passed**, 131 deselected; `s19_app.__file__` = `…\s19_app-b100-inc9b\s19_app\__init__.py`.
- **New file + guards** (`green-04-new-and-guards.txt`), run after every source and test change of this pass, including the added mutant scope below: **197 passed, 4 skipped**, exit 0; `s19_app.__file__` = the worktree.
  - The 4 skips are existing long-name arms (`_make_or_skip`: "the volume refuses this name"). They hit MAX_PATH under the long scratch `--basetemp`.
  - They are reported not run (environment). The security reviewer saw the same skip.
- **The project-homes module, once** (`green-05-project-homes.txt`): see the added scope below.

Not run, per the operator override: the whole touched modules (except the ruled project-homes exception) and the full suite.

## Source sha256[:16] (after the pass)

| File | sha256[:16] |
|---|---|
| `s19_app/tui/app.py` | `d0cfd46e22c3f60e` |
| `s19_app/tui/screens.py` | `120d39b9697fab0f` |
| `s19_app/tui/styles.tcss` | `5093edc072e03091` (unchanged) |
| `s19_app/tui/__init__.py` | `0a5baebdb9fa71d2` (unchanged) |
| `s19_app/tui/os_clipboard_input.py` | `df9755c8b6d1b6c5` (one docstring line, CR9b-04; ruled as docs) |

Test files after the pass: `tests/test_b100_load_dialog.py` `676a89c15223e7be`, `tests/test_b100_project_homes.py` `48f604b9b8c1e3bb`.

## Risks and decisions recorded

- **CR9b-03 scope (my decision).** `link file` applies to any link met on the walk when the typed path has a data or A2L suffix. That covers a linked file and a file under a linked folder (the reviewer named both cases). One edge remains: a junction **folder** named like a data file (`<W>/x.s19` → junction) now gets the file wording. It is still refused; only the step differs.
- **SEC9b-1, the list-to-field redirect.** `on_key` appends one printable character by setting `inp.value` directly, which bypasses `max_length`, so the field can reach 4097 characters once. That is harmless: the classifier now catches `ValueError`. It is not fixed (outside the ruling).
- **SEC9b-1, ruling B.** An over-long paste is refused without notice, apart from Textual's `restricted()` bell. The field just stays as it was.
- **SEC9b-3 cost.** One `lstat` per entry in each project folder listing, on every open, verdict and pick (the SR-2 listing cost, plus one syscall per file).
- **architecture.md:670** still says "a project preview reads the manifest on a worker with a bounded read". A9b-04 made the preview synchronous. That text was not in the ruling and is left for close.
- **Pre-existing working-tree noise.** `tests/test_b99_{a2l_encode,bytes_field,corpus,editor_image,s0}.py` show as modified with line-ending changes only. They were modified before this pass and are not mine.
- `green-03` ran before the CR9b-04 docstring edit in `os_clipboard_input.py` (one comment line, no behaviour). `green-04` ran after every edit.

## Added scope: mutant survivors (orchestrator rulings (1)–(4))

The E4 mutation run gave 70 killed, 26 survived, 0 invalid (`../evidence/inc-9b/mutation-summary.md`). The per-id table is in `E5-rulings.md` § *Mutant survivors*.

How the re-runs were done:
- **Where.** Every re-run used a scratch copy of the corrected tree, `scratchpad/corr9b/mut`, never the worktree. The copy was taken from the worktree after the test changes. The sha256 of `app.py`, `screens.py` and the test file matched the worktree.
- **Runner.** `scratchpad/corr9b/mutrun/mutc.py` patches the source, runs the target nodes, restores the file, and checks the restore by sha256. Every transcript shows `restored = True`.
- **Baseline.** A clean baseline of every target node in the copy ran first (`mut-c-baseline.txt`): 33 passed. A second baseline after the M26/M34 arms: 2 passed.
- **Transcripts.** `../evidence/inc-9b/mut-c-<id>.txt`.

### (1) M87 and the project-homes module

- **M87's killer, re-pinned.** The named killer `test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link]` tested 9a's link-following listing. It is re-pinned to LLR-173.4n: the linked A2L is not listed, so the folder holds `no data or A2L file`, with 0 resets and no A2L.
- **The admission's own reparse test.** With SEC9b-3 in place, no reparse file can reach `_a2l_admission` through the listing. The new `test_tc_b100_32_a2l_admission_refuses_any_reparse_point` (2 arms) pins that test directly. M87 against it: **KILLED** (`mut-c-M87.txt`).
- **The grep for other link-dependent arms.** The other link arms in this module are on the Save side (save as, the link line) or on folder junctions (the listing and the load refusal). 9b changes neither.
- **One arm the grep missed.** The module run found `test_e4_llr_171_2g_linked_a2l_beside_a_mac_is_never_parsed`, re-pinned the same way. It now expects 0 parses, no A2L, and the panel's A2L slot reading `(none)`, instead of a "not readable … link or junction" row.
- **Module run, once** (`green-05-project-homes.txt`): 3 failed, 87 passed.
  - The re-pinned `test_e4_…_never_parsed` was re-run alone: PASSED (Part 2).
  - `test_tc_b100_31_depth_ceiling[32]` and `[33]` fail with `WinError 206` (path too long) under the long scratch `--basetemp`. They fail the same way on 741cc07 (Part 3). The cause is the environment, not 9b, so their state on this host is `blocked`. They need a short `--basetemp` or long-path support.
  - Result: 88 items pass and 2 are blocked by the environment. The module was not run whole a second time, per "once".

### (2) Weak tests, strengthened: 12 of 12 KILLED

M04, M09, M32, M38, M39, M61, M64, M71, M78, M81, M85 and M95 each went RED against a new or strengthened arm. The table is in `E5-rulings.md`.

M78 was re-expressed on the corrected source, because SEC9b-2 changed the gate text. The mutant now moves the session reset to before the `project.json` gate.

### (3) Wrong target, re-targeted: 4 of 4 KILLED

- **M17.** No arm pressed Enter on the preview, so a new arm does.
- **M35.** The path-last test now also runs in list mode.
- **M57.** No test change: a work-area row picked with keys goes through the verdict.
- **M89.** Reachable. The content listing fails while the folder stays listed fail-open, and a new arm covers that case.

### (4) Equivalents: 5 confirmed, 4 re-classified

**Confirmed equivalent:**
- M02, M12, M14 and M36, by reading.
- M92, by execution: it survives 6 behavioural project loads (`mut-c-M92.txt`). Reading alone could not settle it, because Textual's `dismiss` queues the callback with `call_next` and then calls `pop_screen`.

**Re-classified as not equivalent, against the "no test change" in the ruling (declared).** I told the orchestrator before the change ("tighten unless you reply no"); no reply had arrived.
- **M33 and M59** change the painted `#load_reason` line: the separator, and the reason and step swapped. `_assert_refused` now asserts the exact line, `painted == f"{reason} — {step}"`.
- **M26.** A queued second Enter re-ran the verdict on a dismissed dialog, which A9b-02 forbids.
- **M34.** `action_cancel` has no guard of its own, so a queued Escape after an Enter dismissed twice. That raised `ScreenStackError: Can't pop screen; there must be at least one screen`, and the app crashed.
- M26 and M34 are now pinned by `test_tc_b100_41_double_enter_dismisses_once[enter|escape]`. All 4: **KILLED**.

**Final mutation count: 91 killed, 5 equivalent, 0 invalid, 0 non-equivalent survivors (of 96).**

### New and changed arms in this added scope

| Arm | Mutant |
|---|---|
| `test_tc_b100_63_pasted_nul_is_not_inserted` (a second paste, with DEL) | M04 |
| `test_tc_b100_41_headings_cannot_be_reached_by_keys` (new) | M09 |
| `test_tc_b100_41_typed_text_reaches_the_verdict_verbatim` (new) | M32 |
| `test_tc_b100_41_path_mode_opens_with_an_empty_preview` (new) | M38 |
| `test_tc_b100_41_moving_to_the_path_field_clears_the_list_preview` (new) | M39 |
| `test_tc_b100_43_recent_preview_shows_the_store_facts_only` (+ a 200-character recent) | M61 |
| `test_tc_b100_64_preview_does_not_mark_an_a2l_the_install_refuses` (new) | M64 |
| `test_tc_b100_64_file_row_preview_marks_what_the_session_keeps[S19 loaded, MAC row]` (new case) | M71; M57 via `[nothing loaded, S19 row]` |
| both `project.json` gate tests preload an image | M78 |
| `test_tc_b100_43_a_reparse_project_json_alone_is_not_a_project` (new) | M81 |
| `test_tc_b100_64_more_than_one_mac_marks_nothing[A2L]` (new arm) | M85 |
| `test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed` (new) | M95 |
| `test_tc_b100_41_enter_on_the_preview_loads_the_highlighted_row` (new) | M17 |
| `test_tc_b100_41_load_with_the_path_last_takes_the_typed_text[*-list]` (list mode added) | M35 |
| `test_tc_b100_63_typed_folder_that_cannot_be_read_is_explained[content listing]` | M89 |
| `_assert_refused` asserts the exact line | M33, M59 |
| `test_tc_b100_41_double_enter_dismisses_once[enter|escape]` (+ the verdict count) | M26, M34 |
| `test_b100_project_homes.py`: `…a2l_guard…[link]` re-pinned; `…a2l_admission_refuses_any_reparse_point` (new); `test_e4_llr_171_2g_…_never_parsed` re-pinned | M87 |

### Observations for the orchestrator

- **UX change behind the 9a re-pins.**
  - Under 9a, the Load-result panel told the engineer that a linked A2L in the project folder was left out ("not readable — link or junction").
  - Under 9b, the link is not listed at all, so the panel says `A2L (none)` and gives no reason.
  - LLR-173.4n allows this, but the explanation is lost. It is a backlog candidate; the tests now pin the 9b behaviour.
- **M34 was a real crash path.** The guard in `_close` matters for Enter followed by Escape. The E4 summary called it redundant.
- **Stray temp folders.** The mutant runner first wrote its pytest `--basetemp` folders under `.dev-flow/…/evidence/`. I removed them; they were my own temp output. The `mut-c` transcripts still name those paths in their `command:` line.
