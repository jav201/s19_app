# Inc 6 - E4 tester 2 notes: document homes and lists

Group: R-PATCH-DOC-DROPDOWN-001.1 .. .4, R-CHKED-031 / -034 / -040 / -042 / -044, R-DIFF-CHK.1 / .3 / .5 / .8. Written from `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E3-rulings.md` (round 2: S-8, E3A-17, E3A-18); no product line was read to decide an assertion.

## Files

- New: `tests/test_b101_document_homes.py` (36 collected nodes, 17 functions).
- Body edit, name unchanged: `tests/test_b101_symbol_reads.py::test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[ab-diff-project-a2l-not-implicit]` stages the check document in `P/checks/` (not the common folder) and picks `checks/<name>`; the other five parameters and `test_r_chg_sym_9` are untouched.
- Adjusted as the addendum requires: `tests/test_b101_help_legend_docs.py::test_r_doc_readme_4_1_no_stale_claim`. `_CHECK_EDITOR_PHRASE` became `_CHECK_EDITOR_STALE` (the old sentence, now pinned absent); the present claim is read from the README's Write sentence itself: it must name `checks/`, a project, and `.s19tool/workarea/patches/`, and must not say "with or without a project". Wording-tolerant, so it does not depend on the exact README text.

## Tests per case (all `full`; waits are `settled` / `wait_until` on a sign, the negative arms wait for the refusal line)

| Case(s) | Node |
|---|---|
| R-PATCH-DOC-DROPDOWN-001.1/1 .. /6 | `test_r_patch_doc_dropdown_001_1_change_list[open, save, refresh, no-project, project-load, save-project]` (/5 loads the project through the `p` dialog, /6 saves through `ctrl+s`; both assert the Patch Editor stays displayed) |
| .2/1, .2/2 | `test_r_patch_doc_dropdown_001_2_empty[all-empty, library-only]` (prompt read from the painted dropdown) |
| .3/1, .3/3 | `test_r_patch_doc_dropdown_001_3_pick[project, library]` (source path, status, ribbon; picks go through click + arrow keys) |
| .3/4 | `test_r_patch_doc_dropdown_001_3_pick_keeps_spelling` (base folder reached through a link; Save project status line) |
| .3 Save arm, E3A-18 + free-name claim | `test_r_patch_doc_dropdown_001_3_save_after_library_pick` (file lands in `proj/patches/`, an existing `changes.json` keeps its bytes, library unchanged) |
| .4/1 .. /5 | `test_r_patch_doc_dropdown_001_4_refused[link, linked-folder, unknown-folder, inside-link, popup-recheck]` (exact status; document snapshot unchanged; the popup arm swaps the folder for a link while the popup is open, then clicks Accept) |
| R-CHKED-031/1 .. /3 | `test_r_chked_031_write_home[project, no-project, after-library-pick]`; extra `[never-overwrites]` (free-name claim) |
| R-CHKED-034/1 | `test_r_chked_034_linked_check_home` |
| R-CHKED-040/1 .. /3, E3A-18 | `test_r_chked_040_spec_list[project, after-write, save-project, project-load]` (`project` also checks both labels end ` CHECK`) |
| R-CHKED-042/1 | `test_r_chked_042_write_as_bare_name` |
| R-CHKED-044/1, /2 | `test_r_chked_044_refused[link, linked-folder]` |
| R-DIFF-CHK.1/1, /3, E3A-18 | `test_r_diff_chk_1_list[project, project-load, save-project]` (/2 stays `test_tc_b94_15_dropdown_population`) |
| R-DIFF-CHK.3/1 | `test_r_diff_chk_3_no_row_for_empty_list` |
| R-DIFF-CHK.5/1, /2 | `test_r_diff_chk_5_refused[link, linked-folder]` |
| R-DIFF-CHK.8/1 | `test_r_diff_chk_8_library_spec_loads` |

Uncovered, named: E3A-17 (the Save-project refill clears a spec picked on a displayed A2B Diff) has no case in the catalogue and no node here. S-8 (the D-6 wording) is a text edit, nothing to test.

## RED on base 823d0c93 (`m5-main`), GREEN on the committed implementation

- RED: one complete run on the LAN laptop, detached worktree of `m5-main`, `s19_app.__file__` printed first: **34 failed, 9 passed** over the three targets (`.dev-flow/2026-11-01-batch-101/evidence/inc-6/red-01-tester2-base.txt`, redacted). Command is quoted in the file's first lines.
- The 9 passes are declared standing guards, not RED claims: `001.1[no-project]`, `001.2[all-empty]`, `031[no-project]`, `DIFF-CHK.3/1` (these hold on base by design: the no-project lists, the empty prompt, the common-folder write, the absent row) and the five unchanged parameters of `test_r_chg_sym_10`.
- Reasons the 34 fail (each read from the transcript, none is a harness error): lists hold bare names or `[]` instead of `checks/..`, `patches/..`, `library/..` (`001.1/1,2,3,5,6`, `.2/2`, `040/1..3 + project-load`, `DIFF-CHK.1` x3); the picked value is not offered (`001.3/1,3,4`, save-after-library-pick, `042/1`, `031/after-library-pick`, `DIFF-CHK.8/1`, `.4/5`); Write lands in the common folder (`031/project`, `/never-overwrites`) or is accepted through a linked check home (`034/1`); the link and unknown-folder picks give `MF-PATH-UNRESOLVED` or load instead of the refusal text (`001.4/1..4`, `044/1,2`, `DIFF-CHK.5/1,2`); README keeps the stale Write sentence; `test_r_chg_sym_10[ab-diff-project...]` waits 60 s for a list row that a project does not compose from the common folder.
- GREEN: the same three targets on a second throwaway worktree with the committed Inc 6 implementation (`e7951cf0`, source and README applied as a patch): **43 passed** (36 + 6 + 1), one complete run. Informational for the orchestrator: it is not the gate run (C-25), and `test_before_after_report`, `test_tui_checks_screen` and tester 1's lifecycle nodes were not run.
- Both remote worktrees are removed.

## Findings and limits

1. No production defect found; every case passes against the implementation.
2. `001.4`, `044`, `DIFF-CHK.5` file-link arms use a symbolic link: on Windows that needs a privilege, so those arms `skip` there with the reason named. Folder links are junctions on Windows. Nothing ran on Windows (py_compile only); both Windows arms are unexercised.
3. The three refusal texts say "patches folder" for a `checks/` or `library/` pick (E3A-10, backlog, pinned as the row's exact text).
4. `001.3/4` makes the base folder a link above `.s19tool` (symlink or junction); it relies on the app not resolving `base_dir`.
5. The case catalogue's `DIFF-CHK.3/1` and `001.2/1` cannot fail on base; they guard against a future regression of the absent row and the prompt.

## Evidence checklist

- [x] Every node named exists in `tests/test_b101_document_homes.py` (36 collected).
- [x] Results read from one complete run each (RED 34 failed / 9 passed; GREEN 43 passed), commands quoted.
- [x] RED on base 823d0c93 captured; standing guards declared.
- [x] Assertions read painted values, status lines and files, not call sequences.
- [x] Uncovered named (E3A-17); environment limits declared (Windows).
- [x] Fixtures synthetic, no personal data; `LOCALAPPDATA` isolated by `tests/conftest.py`; no clipboard.
- [x] States used: executed, not-run, n/a only; no approval claimed.
