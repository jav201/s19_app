# E5 corrective notes — batch-100 Inc 10 (increment 019)

Tree: `<HOME>/Github/s19_app-b100-inc10`, branch `b100-inc10`, HEAD `1747479` plus the working-tree edits below (not committed). Rulings: `E5-rulings.md`. Evidence (`.dev-flow/2026-10-26-batch-100/evidence/inc-10/`): `red-02-corrective.txt`, `green-03-merged.txt`, `green-04-corrective.txt`, `mut-c-<id>.txt` (21 files).

Run environment, every pytest run: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<scratch>/c10/lad`, `-p no:cacheprovider`, `--basetemp=<scratch>/c10/bt`, interpreter `s19env` Python 3.11.15. The mutant runs used `<scratch>/c10/btm` and `<scratch>/c10/ladm` (same shape, own folders). No basetemp under the repo. Each transcript header records the HEAD sha, the `git status` of `s19_app` / `tests`, `s19_app.__file__` (always the tree under test) and the file shas. No whole module was run except the ones ruling CR10-02 names. The full suite is `not-run` (operator override, batch-end battery). No pytest process is left running.

## Per id

| Id | What changed (file:line, worktree) | Evidence | State |
|---|---|---|---|
| CR10-01 = SEC10-01 | `s19_app/tui/app.py:13782-13798` (`_load_path_from_user_input`, data arm; comment at :13783): `resolved = resolve_input_path(path, self.base_dir)`; `kind = "attach"` only when the resolved suffix is in `MAC_EXTENSIONS` AND equals the typed suffix, else `"image"` (fail closed; a `None` resolve gives `image` too); the target is `(resolved or typed).name`. Docstring Data Flow at `app.py:13749-13759`. | Arm (a) RED on 1747479 → GREEN in the worktree; arm (b) GREEN on both; MC1 / MC2 killed (§New arms, §Mutants). | executed |
| SR-2 (E4) | New test `tests/test_b100_load_question.py:1289` `test_tc_b100_45_refusal_lines_paint_names_literally` (C60). No source change. | RED on e4bfd6a (pre-Inc 10, raw names); GREEN on 1747479 and in the worktree; M63, M64, M70 KILLED. | executed |
| CR10-02 | No code. GREEN re-recorded on the merged tree as `green-03-merged.txt`. | §GREEN: 257 passed, 4 skipped, 0 failed. | executed (4 skips `not-run`, see §GREEN) |
| CR10-03 | `s19_app/tui/screens_directionb.py:4812-4815` (the `_dirty` comment) and `:5871-5874` (the `is_dirty` docstring) now name three outside readers, with the change-file dropdown guard (LLR-174.2t) as the third. | By reading. Comment and docstring only. | executed |
| CR10-04 | `s19_app/tui/app.py:7563-7566` (`_confirm_then_load` Data Flow): `False` only; "the modal never dismisses `None`". | By reading. | executed |
| CR10-05 | `tests/test_id_registry.py:160-167`: the `230 -> 231` comment line is removed from the old block, and the entry now opens the `EXPECTED_SCANNED_TEST_FILES` docstring in the 8b–9b form. The value stays 231. | `tests/test_id_registry.py` 13 of 13 passed in `green-03-merged.txt`, so the measured count is 231. | executed |
| SEC10-02 | No code change. The backlog row is widened (§SEC10-02). | n/a — backlog only | n/a — backlog only |

### Notes on CR10-01

- **Why the second `resolve_input_path` call is safe.** The classifier has just called it on the same text and returned `data`, so it did not raise. Both raises it guards depend on the text, not on the disk: `ValueError` for an over-long path and `RuntimeError` for a `~user` with no home. A file removed between the two calls gives `None`, so `image` and one question, then `load_from_path`'s own `File not found` line. Nothing is lost.
- **Where the typed and resolved paths can differ.** Only on the relative fallbacks: `(base_dir / p).resolve()` and the repo-root one. When the typed path exists from the working folder, or is absolute, `resolve_input_path` returns it unchanged, so the two suffixes are equal and the kind is as before. The `W\temp\x.mac.` residual (Q-4) is unchanged: both suffixes read `""`, so `image`.
- **Fail closed in the other direction too.** A typed `.s19` that resolves to a `.mac` now asks once, because the suffixes differ. That is the ruling, and nothing is lost: `n` keeps the session.
- **Declared deviation: the scope of "the target name".** The `a2l` arm keeps `typed.name` as its target. An A2L attach never asks (`_load_would_lose("attach")` is `[]`), so that target is never painted, and no test could observe a change there. The classifier routes `a2l` only when the RESOLVED suffix is an A2L suffix, and `load_a2l_from_path` never replaces `current_file`, so no image can be lost on that arm.

## New arms (CR10-01, SR-2)

| Node | Arm | On 1747479 (source untouched) | In the worktree |
|---|---|---|---|
| `test_tc_b100_72_relative_mac_takes_its_kind_from_the_resolved_path[link]` (`:2557`) | (a) `<base>/cal.mac` is a symlink to `src/b.s19`; typed relative `cal.mac`; D true | **FAILED**: `AssertionError: (0, None, False, False)`. 0 questions, `b.s19` installed over the patched `fw.s19`, D lost: the reported defect. | **PASSED**: 1 question, body `There are unsaved changes in fw.s19. Load b.s19 anyway?`; `n` keeps the digest; D true |
| `…[plain]` | (b) `<base>/plain.mac` is a real MAC; typed relative `plain.mac`; D true | PASSED (expected: 1747479 already handles a plain `.mac` correctly) | **PASSED**: 0 questions, `plain.mac` attached, the patched byte kept, D true |
| `test_tc_b100_45_refusal_lines_paint_names_literally` (`:1289`) | C60: `Variant not found`, `Variant file missing`, `No supported files in project`, each checked as the recorded message and as the painted `#log_line_4` | PASSED (1747479 already scrubs; SR-2 was a test gap) | **PASSED**: 3 of 3, 0 markup spans |
| same | C60 on **e4bfd6a** (pre-Inc 10, raw names) | **FAILED**: all three lines keep U+202E / U+00AD, e.g. `Variant not found: [b]v\xadX\u202e` | — |

Each CR10-01 arm carries a live-guard control in the same session: a typed `b.s19` asks 1 question. It runs first, so a base failure is an assertion and not a timeout. Arm (a) skips with the `os.symlink` error where links cannot be made; here it ran.

**Fail loud on "each arm RED on 1747479".** Arm (b) and C60 cannot be RED on 1747479. Arm (b) guards against over-correction (1747479 already attaches a plain relative `.mac`), and C60's scrub already shipped in 1747479. Their can-fail proofs are C60 RED on e4bfd6a and the mutants: M63, M64 and M70 for C60, and MC1 (any path difference fails closed) for arm (b), all KILLED. MC2 (the 1747479 typed-suffix rule) kills arm (a) on the corrected tree.

The RED transcripts ran test file sha256[:16] `c44244959bcd0e61`. The 1747479 worktree came from `git worktree add --detach <scratch>/c10/base10c 1747479` and the e4bfd6a worktree is `<scratch>/c10/pre10`. Only the test file was copied into each; their sources were never edited.

## Arms added for the mutation rulings

The original mutation run was on 1747479, 69 killed and 14 survived. Each arm below targets behaviour that 1747479 already has, so its can-fail proof is its mutant on a scratch copy of the corrected tree (`<scratch>/c10/mutc`), not a RED on base.

| Mutant | Ruling | Arm (test, worktree line) | Re-run |
|---|---|---|---|
| M63, M64, M70 | covered by C60 | `test_tc_b100_45_refusal_lines_paint_names_literally` (`:1289`) | KILLED ×3 (`AssertionError` on the raw U+202E / U+00AD line) |
| M50 | weak test | `test_tc_b100_45_names_paint_literally` (`:1221`): the project is now `[i]` + U+202E + `P` | KILLED (`Replace [i]\u202eP?`) |
| M15 | wrong target | `test_tc_b100_45_modal_builds_from_its_parameters` (`:908`): `#confirm_box > *` is `[confirm_title, confirm_body, confirm_buttons]` (interfaces S-g; ruling "Outer id") | KILLED (`[]`) |
| M16 | gap | `test_tc_b100_45_click_answers_with_the_clicked_button` (`:1076`): the app class's `on_button_pressed` is wrapped (declared spy), and 0 question presses reach it | KILLED (`['confirm_yes', 'confirm_no']`) |
| M29 | gap | `test_tc_b100_45_change_file_dropdown_keeps_the_guard` (`:1692`): each cancel paints exactly `Patch Editor: load cancelled — changes kept.` | KILLED |
| M30 | gap | same test: dirty again, pick, `#load_guard_accept` → the file loads (1 entry, flag clear) | KILLED (`(['second.json'], 1, True)`) |
| M32 | may stay a gap | `test_tc_b100_46_go_runs_at_once_when_clean_and_after_the_question_on_replace` (`:2098`): with nothing unsaved, `go` has run when `_confirm_then_load` returns | KILLED (`([], 0)`). Cheap, so written. |
| M33 | gap | same test: after `y`, `go` runs outside the answer callback (declared spy wraps the callback), with the question off the stack | KILLED (`[('replace', True, False)]`) |
| M71 | gap | `test_tc_b100_46_project_load_adopts_declared_regions_after_the_reset` (`:2156`): after `y`, project `DR`'s `cal_block` is in `_declared_regions` | KILLED (`[]`) |
| M79 | may stay a gap | `test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix` (`:2626`): a pick of a missing `ghost.s19` with D asks 0 questions and keeps the session | KILLED. Cheap, so written. The C39 race itself (a file deleted while the question is open) stays a declared design note. |
| M14 | ruled equivalent | **Not equivalent.** `test_tc_b100_45_one_modal_with_replace_and_cancel` already asserts the button order `[confirm_yes, confirm_no]`. The original run used the wrong killer. No new arm. | KILLED (`[('confirm_no', …), ('confirm_yes', …)]`) |
| M08 | ruled equivalent | Confirmed by reading and by a run. The focused `Button` binds `enter` itself and the focused widget's binding wins, while `AUTO_FOCUS` pins `#confirm_no` and the modal's only focusable widgets are its two buttons, so a screen-level `enter` binding is never reached. Not probed: a state with no focus (not reachable by keys). | SURVIVED against all 25 TC-B100-45 nodes, as expected for an equivalent mutant |

**Mutants re-derived on the line CR10-01 rewrote.** M75, M76 and M77 targeted `kind = "attach" if typed.suffix.lower() in MAC_EXTENSIONS else "image"`, which no longer exists, so their original kills say nothing about the corrected line. Re-derived and run:
- **M75r**: the resolved suffix not case-folded → KILLED. The kill comes from the setup wait `reset the MAC` timing out (`typed2.MAC` now asks), a behavioural kill, not the final assertion.
- **M75s**: the typed suffix not case-folded → KILLED (the same wait).
- **M76r**: `kind = "image"` → KILLED (2 of 2 killer nodes).
- **M77r**: the data arm calls `load_from_path` without the seam → KILLED (seam census `['_load_path_from_user_input:13793:load_from_path']`).

M10, M21 and M22 are in `screens.py`, which this pass did not change, so their original verdicts stand.

## GREEN

| Transcript | Scope | Result | State |
|---|---|---|---|
| `green-03-merged.txt` (CR10-02) | merged tree `1747479` + the corrective source edits, test file `c44244959bcd0e61` (before the mutation-ruling arms): all of `tests/test_b100_load_question.py`, the 5 re-pinned nodes (`test_b100_session_reset.py` ×4, `test_b99_editor_image.py` ×1), and the guards `test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`, `test_b100_load_dialog.py` | **257 passed, 4 skipped, 0 failed** in 1472.6 s. Per file: load_question 55, session_reset 4, editor_image 1, id_registry 13, staging 31, engine_unchanged 1, load_dialog 152 + 4 skipped. | executed |
| `green-04-corrective.txt` | the worktree with the FINAL test file `17622fbeb800f08e`: every node this pass added or changed (10 nodes: the two CR10-01 arms, C60, the five changed tests and the two new ones) | **10 passed, 0 failed** in 55.2 s | executed |
| `red-02-corrective.txt` | §New arms | the expected FAILs | executed |

**The 4 skips are `not-run`.** All 4 are `test_b100_load_dialog.py:377` "the volume refuses this name": `test_tc_b100_42_work_area_file` ×1 and `test_tc_b100_64_list_rows_neve…` ×3. The mandated basetemp (`<scratch>/c10/bt`, about 110 characters) plus their 120-character names exceed the Windows path limit. The same class of path-length casualty appeared in the reviewer's runs. E4's `guards-01.txt`, with the default temp, ran them green on 741cc07. They were not re-run here with a shorter temp, because the brief fixes the basetemp.

The nodes of `test_b100_load_question.py` that this pass did not change ran in `green-03` with the earlier test file. Their text is identical in the final file, and every changed or new node ran in `green-04` with the final file.

## SEC10-02 — the widened backlog row (Inc 12a sweep)

The S10-04 row lives today only in `E3-rulings.md` (S10-04) and `codewire/proto-10-app.md:169`; it is not yet in `.dev-flow/BACKLOG-CODE.md`. Widened text, for the close to carry into BACKLOG-CODE:

> **(security NIT, S10-04 + SEC10-02, batch-100 Inc 10; Inc 12a sweep) Status lines after `y` paint a raw path or exception text, without `painted_names`.** The lines: `load_from_path`'s `File not found: {path}` (`app.py:13913`, C43's race outcome); `load_selected_file`'s `Load failed: {exc}` (`app.py:16027`, C39's Workarea race outcome, where the `FileNotFoundError` text holds the raw path); `_handle_load_error`'s `Load failed: {exc}` (`app.py:16757`). The question keeps the race window open for as long as it waits. A U+202E in a name reverses the painted line. The labels have markup off, so the impact is spoofed text only. **What closes it:** each line paints its name through `painted_names` (one call each), with a C60-style test (a hostile name, 0 Cf characters painted).

(Line numbers are the worktree's, after this pass.)

## Source sha256[:16] after this pass

| File | Working-tree bytes (CRLF) | LF-normalised (the committed blob form) | 1747479 blob |
|---|---|---|---|
| `s19_app/tui/app.py` | `5a9550c493ab6ad1` | `c281c15fe98933cf` | `4303b54269923270` |
| `s19_app/tui/screens.py` (unchanged) | `69a749f331f6d5c1` | `e98c04bda25a87b5` | `e98c04bda25a87b5` |
| `s19_app/tui/screens_directionb.py` | `1288d9015c281fe2` | `8d3398054caa7a42` | `b3058a4ae9abf6a2` |
| `tests/test_b100_load_question.py` | `17622fbeb800f08e` | `7892c0440b0bb6ac` | `33f6c74e4f51c397` |
| `tests/test_id_registry.py` | `2eb05cb5dd747f9f` | `840001fae51cade6` | `3d3a62a96f4afb0f` |

The mutation summary's "sha256 before" for `app.py` (`85ed4dab…`) is 1747479's working-tree (CRLF) bytes, which matches this table's convention.

Source files touched: 2 of the 3 allowed (`app.py`, `screens_directionb.py`); `screens.py` is unchanged. CRLF is kept in every edited file (line-ending counts checked: CRLF = LF in each).

## Final kill count

Of the 83 Inc 10 mutants: **82 killed, 1 equivalent (M08), 0 surviving.** That is the original 69 kills, plus the 13 re-targeted here (M14, M15, M16, M29, M30, M32, M33, M50, M63, M64, M70, M71, M79), with M75, M76 and M77 re-derived on the corrected line and still killed. The corrective-pass mutants MC1 and MC2: 2 of 2 killed.
