# Increment 018 — Inc 9b · HLR-173 … HLR-173e / LLR-173.x / LLR-172.1n · the unified Load dialog

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `009b` |
| Lane | `main` · 4 SOURCE files (`screens.py`, `styles.tcss`, `__init__.py`, `app.py`), at the 4-file cap; `os_clipboard_input.py` carries a docstring change only (CR9b-04, ruled as docs) |
| Requirement(s) | `HLR-173` · `HLR-173a` · `HLR-173b` · `HLR-173c` · `HLR-173d` · `HLR-173e` · `LLR-173.1`–`LLR-173.7` and their suffixes (`LLR-173.1a/.1b/.1c/.1e/.1f/.1g`, `LLR-173.2a`–`.2l`, `LLR-173.3a`–`.3d`, `LLR-173.4a`–`.4n`, `LLR-173.5a`–`.5e`, `LLR-173.6a/.6b/.6c/.6d/.6f/.6k/.6l/.6m/.6n`) · `LLR-172.1n` (new, CR9-1) · `LLR-171.2e` (retired) |
| Acceptance | `AT-B100-14` (six halves under one id: list, preview, recent, Enter, empty, escape) · `TC-B100-40` (LLR-173.1…) · `TC-B100-41` (LLR-173.2…) · `TC-B100-42` (LLR-173.3…) · `TC-B100-43` (LLR-173.4…) · `TC-B100-63` (LLR-173.5…) · `TC-B100-64` (LLR-173.6…) · `TC-B100-66` (LLR-173.7) · `TC-B100-34` (LLR-172.1n) · `TC-B100-37` (census widened) — all in `tests/test_b100_load_dialog.py`, `tests/test_b100_recents.py` and `tests/test_b100_focus.py` |
| Interfaces | consumes `LoadChoice`, `LoadDialog` (`screens.py`), `_typed_load_route`, `_load_path_from_user_input`, `_route_load_project`, `_handle_load_project`, `list_projects`, `_folder_holds_project`, `_list_project_files`, `_a2l_admission`, `choose_install_set`, `load_from_path`, `load_a2l_from_path`, `load_selected_file`, `_load_from_item`, `list_workarea_files`, `read_recent_sources`, `recent_kind`, `RecentEntry`, `painted_names`, `safe_text`; adds `_load_dialog_rows`, `_load_dialog_verdict`, `_load_dialog_preview`, `_file_preview_marks`, `_load_workarea_file`, `_TYPED_REFUSAL_TOKENS` (with the `link file` key) to `app.py`; adds `LoadChoice` + `LoadDialog` to `screens.py` and re-exports them from `__init__.py`; retires `LoadFileScreen` and `LoadProjectScreen` |
| Agent | design-first experiment (`inc-9b/`): E1 requirements · E2 Code-Wire prototype (graph only) · E3 code-free design review (3 rounds: architect + security) · E4 parallel build (2 DeepSeek implementers + Opus tester) · E5 change validation (96 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass). Models per stage in the step table below |
| Date | `2026-10-31` (E1 start 13:41:04Z through the close records 19:33Z, all UTC) |
| Base | `8947666` (Inc 9a final); tree at `e4bfd6a` (E5 WIP) plus uncommitted changes at the time of writing |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-173 / HLR-173a … HLR-173e).** The two retired Load screens (`LoadFileScreen`, `LoadProjectScreen`) are replaced by one `LoadDialog` with a typed-path field, one list of the work area's projects, work-area files and recent sources, and a preview pane. The dialog dismisses with one `LoadChoice(kind, value)` routed through the one app handler; the preview marks with `●` the variant, MAC and A2L a load installs; Enter loads the highlighted row when the list held the focus more recently than the path field, the typed path otherwise; an empty or refused Load stays open and paints the reason in `#load_reason`; `escape` closes and changes nothing.

- **HLR-173 — one dialog lists everything that can be loaded.** `l` / `ctrl+l` open on the path field, `p` and `#ws_load_project_button` on the list with the open project's row (else the first project) highlighted (LLR-173.2, .2a, .2b); the `tab` order and the printable-key redirect (LLR-173.2c, .2d); the four priority keys inert while the dialog is open (LLR-173.2e); the list / path precedence (HLR-173c, LLR-173.2f, .2g); a click selects and never loads (LLR-173.2j). Names paint literally through `painted_names` with markup off (LLR-173.3 … .3d), and a pick loads the on-disk name (LLR-173.3d). The sections are `list_projects` (with the §1.3 content test, LLR-173.4a), `list_workarea_files` filtered to loadable suffixes (LLR-173.4b), and `read_recent_sources` (LLR-173.4c), each with its empty and problem tokens (LLR-173.4d … .4g, .4m).
- **HLR-173a — the preview marks the set a load installs.** A project row's `●` equals `choose_install_set` (LLR-173.6); a load that installs another variant than the mark names it (LLR-173.6a); a file row's `●` equals what the session keeps (LLR-173.6b, .6c); the project preview lists the variants and the manifest state (LLR-173.6d, .6f); a read error says so (LLR-173.6k); a linked file in a project folder is neither listed nor installed (LLR-173.4n, narrowed to the Load dialog preview and the project load). The dialog reads nothing itself (LLR-173.6l).
- **HLR-173b — a recent source reopens from the dialog.** A recent row shows its file name and kind (LLR-173.4h) and previews only the store's facts with no `●` and no filesystem call before Enter (LLR-173.4i, .4j); a missing recent is explained in the dialog and the entry stays (LLR-173.4k, Q3).
- **HLR-173d — an empty or refused Load is explained inside the dialog.** The six typed refusals each paint their token pair in `#load_reason` and keep the field text (LLR-173.5 … .5e); the two empty-Load arms paint `nothing selected` (LLR-173.2h, .2i). SEC9b-1 (ruling B): `#load_path` gets `max_length=4096`, so an over-long paste is refused (not truncated), and a `resolve_input_path` `ValueError`/`RuntimeError` maps to `not found` / `check the path` (LLR-173.5).
- **HLR-173e — `escape` closes and changes nothing.** `escape` and `#load_cancel` dismiss with no result (LLR-173.2k, .2l); the focus after the close is LLR-166.1 (TC-B100-12, Inc 9b arms in `tests/test_b100_focus.py`).
- **CR9-1 (LLR-172.1n).** A source found only through the base-folder or repository-root fallback is not recorded; the record calls in `load_from_path` / `load_a2l_from_path` test `via_fallback` and leave the store unchanged.
- **CR9-11 (LLR-173.4b).** The one-lister census is widened to the string literal `"temp"` in any letter case, plus a runtime enumeration spy during a dialog open.

**Corrective pass (E5).** 9 fix rows + the mutant-survivor rulings, one pass (`inc-9b/E5-corrective-notes.md`). CR9b-01 / CR9b-02 fixed two vacuous test arms; CR9b-03 added the `link file` token pair (`is a link or junction` / `open the file it points to`) and its arm; CR9b-04 corrected the docstring and the `LoadFileScreen` / `LoadProjectScreen` references (docs, not source); CR9b-06 added the docstring sections; SEC9b-1 (ruling B) added `max_length=4096` and the `ValueError`/`RuntimeError` mapping; SEC9b-2 / SEC9b-3 added the `_is_reparse_point` test to both `project.json` gates and to `_list_project_files` (LLR-173.4n's "link" now covers every reparse point). The 26 mutant survivors were re-run in a scratch copy: 21 re-killed and 5 confirmed equivalent (M02, M12, M14, M36, M92), final count **91 killed / 5 equivalent / 0 invalid / 0 non-equivalent survivors of 96**.

**Process decision (operator override 2026-10-31).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The touched-module run and the full suite are deferred to the batch-end battery; the only exception was `test_b100_project_homes.py`, run once because the mutants showed this increment breaks it by design (M87) — see §4.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | source | HLR-173 · HLR-173c · HLR-173e · LLR-173.2 … .2l · LLR-173.3c | `LoadChoice` (frozen dataclass) and `LoadDialog(ModalScreen[Optional[LoadChoice]])` with `compose` / `on_mount` / `on_key` / `action_load` / `action_cancel` / `_close` / `_initial_index` / `on_descendant_focus` / `_schedule_preview` / `show_preview` / `on_resize`; `LoadFileScreen` and `LoadProjectScreen` retired; the CR9b-06 docstring sections. Final sha256[:16] `120d39b9697fab0f` |
| `s19_app/tui/styles.tcss` | source | LLR-173.6m · LLR-173.6n | C1 (`#load_box` width, two panes), C2 (drop `#project_list`), C3 (`#load_panes` / `.stacked`), C4 (sizes, one-line rows, focus border) and the SR-1 rule `#load_preview Static { text-wrap: nowrap; text-overflow: ellipsis; }`. Final sha256[:16] `5093edc072e03091` |
| `s19_app/tui/__init__.py` | source | HLR-173 | re-exports `LoadChoice` and `LoadDialog`. Final sha256[:16] `0a5baebdb9fa71d2` |
| `s19_app/tui/app.py` | source | HLR-173 … HLR-173e · LLR-173.1 … .7 · LLR-172.1n | `action_load_file` / `action_load_project` (push `LoadDialog`), `_handle_load_dialog` (the one router), `_load_dialog_rows` / `_load_dialog_verdict` / `_load_dialog_preview` / `_file_preview_marks` / `_load_workarea_file`, `list_projects` (the §1.3 content test), `_folder_holds_project` / `_list_project_files` / `_a2l_admission` (link-safe scan shared by the preview and the install), the `project.json` gates, `_typed_load_route` (the `link file` reason, the `max_length` mapping), the record calls (`via_fallback`), `check_action` (the whole-stack guard), `_TYPED_REFUSAL_TOKENS`. Final sha256[:16] `d0cfd46e22c3f60e` |
| `s19_app/tui/os_clipboard_input.py` | source | HLR-173 (CR9b-04) | one docstring line: `Used by:` now names `LoadDialog`. Final sha256[:16] `df9755c8b6d1b6c5` |
| `tests/test_b100_load_dialog.py` | test | HLR-173 … HLR-173e · LLR-173.1…–173.7 · AT-B100-14 · TC-B100-40/41/42/43/63/64/66 | NEW module (78 functions, some parametrised) plus `tests/support/b100_load_dialog.py`; the E5 arms (CR9b-01/02/03, SEC9b-1/2/3) and the mutant arms |
| `tests/test_b100_recents.py` | test | LLR-172.1n · LLR-172.4 (census) · LLR-173.4b | TC-B100-34 ×3 (CR9-1 arms), TC-B100-37 (widened census + runtime spy); the TC-B100-38 "route: validate_project_files" arm re-pinned to `_list_project_files` (A9b-R3-1) |
| `tests/test_b100_focus.py` | test | LLR-166.1 (TC-B100-12) | 2 functions × 2 (dialog `escape` / cancelled load close re-homes focus) |
| `tests/test_b100_project_homes.py` | test | LLR-173.4n | TC-B100-32 `[link]` and `test_e4_llr_171_2g_…_never_parsed` re-pinned to the 9b outcome; new `test_tc_b100_32_a2l_admission_refuses_any_reparse_point` |
| `tests/test_b100_project_check.py` | test | LLR-173.1e (SR-3) | the paint clock starts when the load returns (`_paint_clock_start`) |
| re-pins | test | HLR-173 | `test_tui_app.py`, `test_tui_helpers.py`, `test_b99_load_project.py`, `test_tui_directionb.py`, `test_b97_load_project_dialog.py`, `test_loadfilescreen_input.py`, `test_b100_active_variant.py`, `test_b100_announce.py`, `test_b100_reuse.py`, `test_b99_crc_region.py`, `test_b99_export.py`, `test_b99_patch_truth.py`, `test_b99_staging.py`, `test_b99_truncation.py`, `test_clipboard_tk_singleton.py`, `test_b100_document.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b100_session_reset.py` |
| `tests/test_id_registry.py` | config | HLR-173 | `EXPECTED_SCANNED_TEST_FILES` 228 → 230 (measured, F2) |
| `REQUIREMENTS.md` · `docs/architecture.md` | doc | CR9b-04 | LLR-151.1 marked superseded; the `LoadFileScreen` / `LoadProjectScreen` references re-pointed to `LoadDialog` |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-173 … HLR-173e · LLR-172.1n | E1 / E3 / E5 edits (LED .86–.88) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-173 … HLR-173e · LLR-172.1n | LED .86 – .88 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-173 | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-9b/*` | doc | HLR-173 … HLR-173e | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-018.md` | doc | HLR-173 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-9b/*` | generated | HLR-173 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-173 | orchestrator-owned: scenario `ld-dialog` |

## 3 · How to test

```bash
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
# the new Load dialog module (every test):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_load_dialog.py
# the CR9-1 arms and the widened census (targeted):
python -m pytest -q -p no:cacheprovider tests/test_b100_recents.py -k "tc_b100_34 or tc_b100_37"
# the focus re-homes (targeted):
python -m pytest -q -p no:cacheprovider tests/test_b100_focus.py -k "tc_b100_12"
# guards (the frozen-engine guard, the registry, the staging re-pin):
python -m pytest -q -p no:cacheprovider tests/test_id_registry.py tests/test_b99_staging.py tests/test_engine_unchanged.py
# mutants: evidence/inc-9b/mutation-summary.md (96 rows) + mut-c-*.txt (the E5 re-runs)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-9b/`. **Final source hashes** (sha256[:16], verified with `sha256sum` at close): `screens.py` `120d39b9697fab0f` · `styles.tcss` `5093edc072e03091` · `__init__.py` `0a5baebdb9fa71d2` · `app.py` `d0cfd46e22c3f60e` · `os_clipboard_input.py` `df9755c8b6d1b6c5` (one docstring line, CR9b-04). Base `8947666`. Import proof in every header; `NO_COLOR` unset.

**Scope (operator override 2026-10-31, stated plainly):** run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The whole touched modules and the full suite are **deferred to the batch-end battery** (with fix rounds for failures found there). The only exception was `test_b100_project_homes.py`, run **once** because the mutants showed this increment breaks it by design (M87): its 9a link-following arms were re-pinned to the LLR-173.4n outcome, and the two `test_tc_b100_31_depth_ceiling[32]` / `[33]` arms fail with `WinError 206` (path too long under the scratch basetemp) and fail the same way on the base, so they are `blocked` by the environment, not by 9b.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-40/41/42/43/63/64/66 (`tests/test_b100_load_dialog.py`), TC-B100-34 (LLR-172.1n) and TC-B100-37 (widened census) (`tests/test_b100_recents.py`), TC-B100-12 (LLR-166.1, `tests/test_b100_focus.py`) | `executed` — `green-01-new.txt`: **133 passed** (562.9 s); `green-02-repinned.txt`: **127 passed / 1 failed** (1183.5 s; the failure is the SEC6-5 timing arm, SR-7); `green-02b-timing-rerun.txt`: **3 of 3 passed** on rerun; `guards-01.txt`: **45 passed** (107.2 s); `green-03-corrective.txt`: **10 passed, 131 deselected** (70.7 s); `green-04-new-and-guards.txt`: **197 passed, 4 skipped** (938.9 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-14 (six halves) | `executed`: `test_at_b100_14_one_load_dialog_from_record_to_reopen` in `green-01-new.txt` (133) and `green-04-new-and-guards.txt` (197); RED `red-01-vs-base.txt` Part 1 fails all 133 new-file tests (ImportError of `LoadChoice`) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's new tests vs base `8947666` | `red-01-vs-base.txt` (4 parts) | Part 1 `tests/test_b100_load_dialog.py` every test → **133 failed** (1277.1 s, ImportError of `LoadChoice`); Part 2 `tests/test_b100_recents.py` new arms → **4 failed, 157 deselected** (10.4 s); Part 3 `tests/test_b100_focus.py` new arms → **4 failed, 34 deselected** (43.5 s); Part 4 a sample of re-pinned tests → **6 failed, 7 passed** (25.0 s). 141 new items, 141 RED on base |
| E5 corrective arms on the pre-fix source `741cc07` | `red-02-corrective.txt` | Part 1 **8 failed, 2 passed** (80.5 s) of the 10 new/changed nodes (CR9b-03 ×2, SEC9b-1 paste, SEC9b-1 resolve ×3, SEC9b-2, SEC9b-3 RED; CR9b-01 and CR9b-02 pass, expected — test-only fixes of correct code); Parts 2a/2b **1 failed each** (the CR9b-01 `drop_focus_palette` and CR9b-02 `skip_recent_record` plugin mutants, RED on the worktree) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the one dialog | `red-01-vs-base.txt` Part 1: all 133 new-file tests fail on `8947666` (no `LoadChoice` / `LoadDialog` exists); the retired screens are gone (TC-B100-40 `test_tc_b100_40_retired_load_screens_are_gone`) |
| the one router | `test_tc_b100_40_one_router_receives_every_dialog_result` (AST census of the push sites); the A9b-03 re-home probe (`probe_cr_rehome.py`) turns both `test_tc_b100_12_load_dialog_close_*` arms RED |
| the preview marks = the install | the preview and `_handle_load_project` share `_list_project_files`, `_a2l_admission` and `choose_install_set`; M64/M71/M78/M81/M85 re-killed against new arms (`mut-c-*.txt`) |
| the recent is never touched before Enter | LLR-173.4j's counting spy; M61 re-killed against the 200-character recent arm |
| the link-safe listing | M87 re-killed against the re-pinned `test_tc_b100_32_a2l_guard_of_an_a2l_only_folder[link]` and the new `…_a2l_admission_refuses_any_reparse_point` |
| the priority-key guard | the CR9b-01 probe: dropping `focus_palette` from the guard survives, the other three drops RED; fixed by the new main-screen assert |

### Mutation verdicts (C-40)

**E4 run on the 9b tree (`mut9b` copy)** (`mutation-summary.md`; every transcript ends `restored = True`): **96 rows total. 70 KILLED, 26 SURVIVED, 0 INVALID.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 70 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, equivalent | M02, M12, M14, M36 (by reading); M92 (by execution — survives 6 behavioural project loads, `mut-c-M92.txt`) | recorded, no code change (`E5-rulings.md`) |
| SURVIVED, weak test | M04, M09, M32, M38, M39, M61, M64, M71, M78, M81, M85, M95 | strengthened arms in E5, all KILLED (`mut-c-*.txt`) |
| SURVIVED, wrong target | M17, M35, M57, M89 | re-targeted arms in E5, all KILLED (`mut-c-*.txt`) |
| SURVIVED, re-classified | M33, M59 (the exact-line `_assert_refused`), M26, M34 (the double-Enter/Escape dismiss guard) | ruled "not equivalent", pinned, all KILLED (`mut-c-*.txt`) |
| SURVIVED, killer pre-existing failure | M87 | the project-homes module ran once; the re-pinned arm + the new admission arm KILL it (`mut-c-M87.txt`, `green-05-project-homes.txt`) |

**Final count (E5): 91 KILLED, 5 equivalent (M02, M12, M14, M36, M92), 0 INVALID, 0 non-equivalent survivors of 96.** The 96 E4 mutants ran on the pre-E5 bytes; the E5 re-runs used a scratch copy of the corrected tree (`scratchpad/corr9b/mut`, never the worktree), with a clean baseline first (`mut-c-baseline.txt`, 33 passed).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the Load dialog | `LoadChoice` is a frozen dataclass of four kinds; the dialog is a `ModalScreen[Optional[LoadChoice]]`; `screens.py` / `app.py` / `__init__.py` / `styles.tcss` hold 0 references to the retired `LoadFileScreen` / `LoadProjectScreen` / `#project_list` / `#project_ok` ids |
| the rows | `OptionList(markup=False)` + `Text` into a `Static(markup=False)`; every name through `painted_names`, 0 markup spans |
| the refusals | `#load_reason` paints only `_TYPED_REFUSAL_TOKENS` values or `LOAD_NOTHING_SELECTED`; `_assert_refused` asserts the exact `reason — step` line (M33/M59) |
| the preview | `show_preview` paints `●` only where `marked`; the `#load_preview Static` nowrap rule keeps one line per row |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards on the integrated bytes | `guards-01.txt` | **45 passed** (`tests/test_id_registry.py`, `tests/test_b99_staging.py`, `tests/test_engine_unchanged.py` — the frozen-engine guard) (107.2 s) |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer ran the priority-key probe (`probe_cr_priority.py`: 4 mutants, 3 RED, the `focus_palette` drop survived) and the re-home probe (`probe_cr_rehome.py`: 2 mutants, 2 RED); CR9b-02/03/04 were read. The security reviewer executed `probe_e2e.py` (the 40 000-character paste → `ValueError`, `return_code 1`; the linked `project.json` → `could not be read`, 0 opens), `probe_resolve.py` / `probe_resolve2.py`, and ran the targeted slices (21 passed, 1 skipped; then 16 + 1 skipped; 4 passed; 2 passed). The full suite and the touched modules were `not-run` in both lanes (out of scope; batch-end battery).

### Security probes

`security-increment-018.md`: SEC9b-1 (the over-long paste and the POSIX `~user` crash — executed `probe_e2e.py`, `probe_resolve.py`), SEC9b-2 (the `project.json` reparse-point gate — by reading, the symlink/FIFO arms executed), SEC9b-3 (the listing's reparse test — by reading, CPython `DirEntry` derives `S_IFLNK` only from the symlink tag). Re-verification of the E3 mitigations: S9b-1 (whole-stack guard), S9b-2 (link-safe preview), S9b-4 (`restrict=`), S9b-5 (scrubbed status lines), S9b-6 (the A2L pick keeps the copy), S9b-7 / R3-2 (a folder named like a file), S9b-8 (preview nowrap) — all `executed`, `approved`. Full per-question results in `security-increment-018.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `ld-dialog` (key `p`), project P highlighted with its `firmware` variant marked `●`, projects P and Q, work-area temp files `fw.s19` and `cal.a2l`, one recorded recent (CASE02). **3 PNGs** in `evidence/inc-9b/e13/` (`ld-dialog.118x54.png`, `ld-dialog.220x60.png`, `ld-dialog.99x54.png`), `DONE failures=0` (`E13-notes.md`). At 118 and 220 columns the panes sit side by side; at 99 they stack; sections in order Projects → Work area → Recent; names paint literally; no row wraps; the preview shows `● variant firmware.s19` / `project file: ok`. OBS-9b-1 routed to the backlog.

### Experiment step table (from `inc-9b/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 13:41:04Z | 14:01:11Z | E1 | 1 x Opus | 8 → 64 single-shall (6 HLR, 57 LLR, LLR-172.1n); slice screens 9 / app 12(+3) / tcss 9; Q1–Q10 ruled (Q8 deferred → LLR-173.2m removed); LED .86 |
| 14:01:11Z | 15:34:39Z | E2 | 3 x Opus (baseline, G-A, G-B) | baseline 34 nodes / G-A 15 nodes / G-B 17 nodes; operator: Q2 remove preview problems, Q8 defer; E2 rulings |
| 15:35:18Z | 14:47 | design-fix | 1 x DeepSeek v4 Pro (pi) | Q2 synchronous branch applied; first run hung 5 h on stdin, relaunched `< /dev/null` |
| 14:47 | — | E3 r1 | 2 x Opus (architect, security) | architect FAIL (6 MAJOR), security PASS-WITH-NOTES (2 MAJOR) |
| 15:04 | 15:20 | E3 r1 design-fix | 1 x DeepSeek v4 Pro | A9b-01 … A9b-12, S9b-1 … S9b-9 applied |
| 15:25 | 15:33 | E3 r2 + design-fix | 2 x Opus + 1 x DeepSeek v4 Pro | architect FAIL (1 new MAJOR A9b-R2-1); r2 rulings; design-fix r2 |
| 15:36 | — | E3 r3 closed | 2 x Opus | both PASS-WITH-NOTES; addenda R3; LLR-173.4n narrowed; E4 start |
| 15:36 | 16:46 | E4 | 2 x DeepSeek v4 Pro (G-A + G-B) + 1 x Opus (tester) | 141 new items, 141 RED on base; integration start (Opus) |
| 16:46 | 17:12 | E4 integration | 1 x Opus | SR-1 … SR-7; green-01 133 passed; guards 45 passed |
| 19:23 | — | E5 | 1 x Opus (reviews + corrective) + 1 x DeepSeek v4 Pro (mutants) | code-review PWN (1 MAJOR test-only), security PWN (0 MAJOR); 70/96 → 91 killed + 5 equivalent; no re-review (nothing blocking) |
| 19:33 | — | E13 | 1 x DeepSeek v4 Pro | `ld-dialog` 3 PNGs, failures=0, OBS-9b-1; close records start |

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 13:41:04Z to 19:33Z = about 5 h 52 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 6 MAJOR in round 1 (A9b-01 … A9b-06), 2 MAJOR in round 1 (S9b-1, S9b-2), 1 new MAJOR in round 2 (A9b-R2-1), 0 in round 3; E5 (code) caught 0 HIGH and 1 MAJOR (CR9b-01, test-only); 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs, taken after the close writes. The table is filled by the orchestrator.

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-9b/` | SHA-256 |
|---|---|---|
| ld-dialog.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/e13/ld-dialog.118x54.png | 4f25b8c7af2d13fcdc9e0ae00a0875513c770511880dd1cda17f9d25795b5395 |
| ld-dialog.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/e13/ld-dialog.220x60.png | fb01d1794064d354834ca3d1bc8bfbe87bd057d5dc7b86fb4fb306c2bf23d045 |
| ld-dialog.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/e13/ld-dialog.99x54.png | f4cb3fd65a5e31900f3e83d47b813094bb76ed393a3b230df1af2101486c74cc |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-01-new.txt | 90aea62d8c8c18327f1e4be3e5fb841f5201c493f45a0abadaec41982204c1fb |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-02-repinned.txt | a66f19527bf6aeee04fd583bb4758e7ed615ff3ad479e4a48aaea83323fdebc5 |
| green-02b-timing-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-02b-timing-rerun.txt | dbc347e723a5d4dbfc4ff32bc31c05e2f95c61b0a7029128dd2f1a5167447968 |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-03-corrective.txt | e17d9e6bd5c291ae5a325b191eaab966a2085284aefe832c1c510c01b68713bb |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-04-new-and-guards.txt | f24522cc3313835574706b310ddb1a20bde4fba46105eec1ece3fe2e72af8d73 |
| green-05-project-homes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-05-project-homes.txt | 2913a3872ad1079704dd08032b60186aa354416dd72ce917c40685c95ad4d22d |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/guards-01.txt | c6cbeda36013d21e4fe52dadf5252c6d65b95f24031d2f1510eb80561f11f120 |
| mut-M01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M01.txt | a97f60aa35e09badb20ba9526dc97cc887a03b5952d2b81d73d395bd2f312910 |
| mut-M02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M02.txt | 0b4e618cedc41a67fc8c76e71a9f357fd06050c48942d65011020e06072e789d |
| mut-M03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M03.txt | 05c32a904effef2e3b8b07e0f77769ef4c8316d57b98cca1fff07ee60eec4d16 |
| mut-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M04.txt | 1b831bc28357905ee9cc20f889001ec30678ee1ec336b7dda0ed35b22d782bf6 |
| mut-M05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M05.txt | 598094e0367e6fa57a37b95c5f2204ee5bba71aa2ab02df07b7d9f41e4f211d4 |
| mut-M06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M06.txt | 61d411a6c8a1056ec7b86d3bc7e1a228f03895362fc65184c94792c1786bf3e0 |
| mut-M07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M07.txt | 57996bf4f6a8d82d14d56cd6b9d48f3846f7827733fca269a7b2c0bfe0c2c030 |
| mut-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M08.txt | ec763e3a63dc1fdd455123c5b68c03264faa7f1f5ba16a49cf140dcf1ccf04df |
| mut-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M09.txt | 9e21f1d64390e1b45bbb7570925a3fe54935c8bdfbcbb839a21ce7ad3d87ac93 |
| mut-M10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M10.txt | 9b9c6f25ed3b60e4d8161ddde3dd44bcb3e7d2dace3093a50c7b4801433fb94e |
| mut-M11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M11.txt | a5442cf574da2aa21e2564f3a95b5ac0e4c3fb450ffb446d99df0abfe756b9e8 |
| mut-M12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M12.txt | 5f19e14ec692158b9a1545a3f36501f3026116b5e24e7d1d123e30687969b2e6 |
| mut-M13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M13.txt | b1a9927ccba868e38ffc0a633f4fcebc8c430d5d1d343df61b0c8109c60edd85 |
| mut-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M14.txt | 842ff5904f2b8a208150c64f8f91599c9fca6050e970d66912a5365a5dbd0717 |
| mut-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M15.txt | 0e7e4fd60b485dea00ca46c19b2363e237a8be736270c7e10410dbed398555ab |
| mut-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M16.txt | 9de47d47246c277bd549f41ae430b65f63a7dfbc31266efbe3d209fa513aab0e |
| mut-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M17.txt | 5dd7fb0ecbdd0226be2b1c78851856a5366180dfc6b1c31468853dc2b76113f2 |
| mut-M18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M18.txt | 1742987ede4e70a12f7dfef3427415254de9a2820694e98427a8c8e74a60e9e5 |
| mut-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M19.txt | b505a431ddea8e0e968f35526906b237460d7e89c2aaaaa6880e752ca84d1450 |
| mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M20.txt | 11ea8c3a4b256797af5546ffb10583facb79206868f6a06e3df63b36b866f49b |
| mut-M21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M21.txt | 8209709cbadb44563a57593333e71fd83fcfd7b716d86dc995c4a2b892688abb |
| mut-M22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M22.txt | 1f554ba1ae5b49567c308c30620c84e03f8dfc98eda7f308aefc64528d58427b |
| mut-M23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M23.txt | 22c0b517be5f9f84853db4fae3c89ac234effeb2d623f20457cc193a68a2cd75 |
| mut-M24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M24.txt | a41222f638062fc5f28f2262b6f6f3224e7a597dfbaa8c1fd38bfd6dff6b3382 |
| mut-M25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M25.txt | b503efdd6fcaa28ea6ee1fd88b4396b1ba60ea7e2f6892d1a53c9c7b828cfccc |
| mut-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M26.txt | 987c6338213fecf7d614872c082a86c783d4dad2546a038a87390ddafcb2a1cd |
| mut-M27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M27.txt | a97ea836801c291a71998e2c4d752744269cec5ce86eb11b3d90b4a7ed9beec3 |
| mut-M28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M28.txt | 044b6cb169e9613d9fb64bc50cd2e7b46798be85069bd2c83ecb00bb62700131 |
| mut-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M29.txt | dd4496e58d65fe10086bf8c4ce30fa4b571ab6213a33cfbb423ee3842fb1b190 |
| mut-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M30.txt | 52fff7bf0ae501357b974f24fcdf1ecb501728c7538ff378117c7eb9e2868591 |
| mut-M31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M31.txt | 017e1407cce0c1e54c75ce5156209761dde39819a5e970c286b19ec0aa402249 |
| mut-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M32.txt | afbf6f40a3fa6bc09aa19f3b764e007998be5af8d3f925133e2c3f1cf9e06bff |
| mut-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M33.txt | 598e5adeb69f70a3e6d5a900c108f64528f11e615ce400360a319bc2c73f065d |
| mut-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M34.txt | 9906d7e83bc71db63c08c8c390b4040d15e386c3ebe4c6ed59771c05ed7f5a84 |
| mut-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M35.txt | 5f7474bc24d387dfd857a6ba1b81b406b46ff14428ee12239943ce3812474e76 |
| mut-M36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M36.txt | 4a5526015564b63a6e62347471ac97b957342d153850a41ea3876d66e226f347 |
| mut-M37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M37.txt | c302046ce31b087cf99e5bf7202f0f00c3e1d9808a4f3bb1cb4b8c2cef9128cc |
| mut-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M38.txt | 8563ef7b29e52fcd2314dcb5029de83ef7e4c86d4c70ea2a943eb73d4b733300 |
| mut-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M39.txt | 1a7b24f8efb57f2f00b24f077e664f4dcc538b35118cd8c5eac9b451adde4bc0 |
| mut-M40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M40.txt | e7bd6fb88f33cc768123a75bbd2888126a3e4dda798bae38fcbbfda7b1a70663 |
| mut-M41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M41.txt | 538cd6ddd4ca3522f45319660df831bcbfc117c886b874197606629264220a08 |
| mut-M42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M42.txt | c056825d5ed06310b96bab4df343c02d80c9559a32780860ed3418b26dca187f |
| mut-M43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M43.txt | d1445e736091da65dfd54224200f69ed71ba8524bb1990d071ed1cd34e910491 |
| mut-M44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M44.txt | b776980a5f703f8416f6af0f2a6e9f5c6f39de17c34e508e4acf66b42e243a41 |
| mut-M45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M45.txt | cfdc82c62f636b619e77667d03a833339a2c5c4df30c7113151a1ffbda7313f1 |
| mut-M46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M46.txt | d0f9528890efced303ba585698eeaa061163e16d2576987de7fa14bf642de88c |
| mut-M47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M47.txt | dcfa4673b1237c522240a1d277abd39f126f27e7b79452a2ac4c3b376e53a651 |
| mut-M48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M48.txt | 43b347ff4e61382aa007602855369f5d69ea00f044f46d59fdad43faba3fc335 |
| mut-M49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M49.txt | 6c33781c07fcec1921fa43cfc6a06e8c431fe41792ccc9b965c0d570975794e3 |
| mut-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M50.txt | 21f2faeae50d44bd25a48bed21e268d0ad5bec16014fac637c6efb87acb9d4a0 |
| mut-M51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M51.txt | 09ea9069b87d07e068b8ed3b2af8936aedf8cd4d61193c4c2398120da3d2a214 |
| mut-M52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M52.txt | 6e9ca5189ab91396e37f9cabcf0cde010e16909bfafbe2e2847daa727f89d49d |
| mut-M53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M53.txt | 22cb3bb11142491a8011e1a37aff4e8d2e0a2703cfcd08588b1b5c83e8787a09 |
| mut-M54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M54.txt | 5c2bc915d563f407a62894cddfc65b458312d63f011562fce8654bb457b9a5be |
| mut-M55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M55.txt | 464caa6ddb7840ae812cc267fae1a053765693db149cbbbfe7ded1f78599fcab |
| mut-M56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M56.txt | b8b89bebb85b3cf9778d1c9a94de6ab9fa59599f4f1b6dec3345f4d7918427f4 |
| mut-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M57.txt | 7d48acb7ebd0dfa068e213ca4a8e45a58a07ec7aa6f41afa95ed45dbc417cfbc |
| mut-M58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M58.txt | e42aaa1a79174b9adcf6c215c417d7c653feabf58ffc32290a02fcb91aca98ad |
| mut-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M59.txt | e3c4717b1b6bd39be0e9941f4af5d0532402b0a33fb0e492de282aec77231a3a |
| mut-M60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M60.txt | b3ae55c5c99f97eb6f505261968b283fcd1517a06988b3027c041a3241b5f26a |
| mut-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M61.txt | b06561127b26267c182fdec94220648cc2bf19ebd22c94c4a4542d7a928aaf91 |
| mut-M62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M62.txt | f31aa239978fafedd3b12d18b14cea95d5c364f5c2e4c503e9494ae7126c360d |
| mut-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M63.txt | 12385e48fc7c4cd0939c8b8a93c57797d84971489ba1acaa4407cbe04c6f5762 |
| mut-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M64.txt | 5ff5df2eab108c5cf0802f64f34b993e10d727e512e898b24a5ba2e8ef577773 |
| mut-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M65.txt | 992b016c162bdb8d88573a07de203f14f3a7c8cdf9a7cab6f245ac36371d0967 |
| mut-M66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M66.txt | 5f1255e6d67ea8fb9b84631cad0e97ea563c22f35488bb89fde22afce5f35af7 |
| mut-M67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M67.txt | 0c521c10a81027b6e7bc34c04cb390634b4541bd25c954d8b858ee7ef844c49d |
| mut-M68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M68.txt | c1ee32b3ea59b05ef263d7c7e40c95cb152f25036ee453f18762bb7df41d2246 |
| mut-M69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M69.txt | 0f0b95f68ead7027a83dd6e409dbcfe1b9ffec9cfe5e1c666013ac8b6fcd241a |
| mut-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M70.txt | 6b0d2408f2f1ff4b56aee8e6671e6b6c85a7685e2d18d6989372677c59e9533c |
| mut-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M71.txt | 8e9c59e13560303529fc239457da52ddd21c5f3db9bf30d85da98315a39e4b23 |
| mut-M72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M72.txt | 411f8d0b3e1e8677c5ec594f838275cbde27d81de1c698f407d5f3e8b67be900 |
| mut-M73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M73.txt | a14a508c59b19cf3a2e9e517bd7a773091e36370b8e13e0e3d88fd09b32912e1 |
| mut-M74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M74.txt | 3fcbca6f1a66daecf00d247c3651444ce009061d37fb595ee4232d8d3f54bd9c |
| mut-M75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M75.txt | 86d5cb96bb92993ae0e1cbd5899f68ee2cb12a2f3807a464e3976531b35157b4 |
| mut-M76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M76.txt | 6b9b30a4bc19942da53b9d24c0eda6276f94c06af5c691c5cedb4b99e8949f8c |
| mut-M77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M77.txt | 00a45058d25cf1b63744c9474b8477f9988947439d8fc174aa7436f1c731621c |
| mut-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M78.txt | 6b2742c0ef4570745a3588e22cab7feb59f3256220d0e5d707ce64bc70806a16 |
| mut-M79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M79.txt | f0ecaacf957b701c79f3efbf3d2738db36d40705756a64e34bb7bec66953cccd |
| mut-M80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M80.txt | 49d9b94a958e286ac3fa850b4d553f90c10ae0c335a9d2c0f086ba1e64f85c22 |
| mut-M81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M81.txt | eeecd8b248464cdd6d7f236212c9820d25dc4301202e0a7d60cf4352d7b070be |
| mut-M82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M82.txt | a85ea2c2712da1e3e0964b83c3f73f04f9dcdb16bee14c5b5bb7c80ff88cff13 |
| mut-M83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M83.txt | c667eb8699b5aee672fd26d5d40785af9c5010572ffdbbbc3d764937093a51dd |
| mut-M84.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M84.txt | 51bc8dd8afe88e3175d28abac390c7adfe2ef95ab4b00faa382651f65001f9ba |
| mut-M85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M85.txt | cb21e92481d7d267f3092556514493ee33a8412350eec507d6a9a1beb6eb3f49 |
| mut-M86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M86.txt | aff849074fb57bf8fc4a8d0a324348c8d41957435e6c6ccffa1d2e81a9d08ce2 |
| mut-M87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M87.txt | f7c0e3ec2fb022e152d170befa7285c0e53ff09dc933ad17d1e79ab7e083a95e |
| mut-M88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M88.txt | 162b59e42f43f37967a7aea5bdd52bc46b981d536cc87d0da730b1b216115c19 |
| mut-M89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M89.txt | 7861c721590d45c23701bcb8e4b983ae8f934652e9f0c50404e24343cf676607 |
| mut-M90.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M90.txt | bd4ce851bea7e810ffda661ba967f6a958d0e79d279795e1ea9176e2f2dd4eca |
| mut-M91.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M91.txt | a2f95518994f766d2cf99fb39bf89f26ea70f54b7651dbabc54c5a90f1db8537 |
| mut-M92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M92.txt | 77459e8cf84d237b45a785e07556d03e815917429a7a7c9f6837515282d74305 |
| mut-M93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M93.txt | 1a1d3a8c7187deeb2639e0decb06575f9785d1f5f1ed7226d7989fc83b11735a |
| mut-M94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M94.txt | 6693f2d102866b0217d30f85f21987d196e50b615d7035e43c382c2dd85b938d |
| mut-M95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M95.txt | f8121fa653165f8abf07631894071e7e3c52c859301198e4c8c118cb18bac594 |
| mut-M96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M96.txt | abdbe1e20f3b702b328311127e98bd440df1e83dd080dd392fca4f33cb77571c |
| mut-c-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M04.txt | c1db43c93901a13d5b55316a725938b670e6a6cfd6a9168a4218a19571261920 |
| mut-c-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M09.txt | f736e27bd5824c344b2c863ddfe4258526ae17972fba795910bcba8541bec3a9 |
| mut-c-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M17.txt | 9b050c3957e12c11f599570d7c6c870b248dd19e8311f822854a76aa61ea0f6e |
| mut-c-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M26.txt | b33064a946226a319ba7e5034c779a6809e1f1e4ef0661dbda0263db90462e03 |
| mut-c-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M32.txt | fff076ba149bee7d060d5650755620282514aee9f8deaf1daa3420065f921829 |
| mut-c-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M33.txt | 032511b856efe47eb7fbe2f0cd3dd63800b75de951487828076930c879924baa |
| mut-c-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M34.txt | 31b7ed6c11f709f94c746f3169588fc9c1aace060402e357725a2add4f1351be |
| mut-c-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M35.txt | 710158053274faec7e7de8564647e4366013e71852a1455aed96850547f01f9a |
| mut-c-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M38.txt | 64409a8ae2eb7e4736ce9203af9d9017428aedb88c1907f00f8471bd4f0f78c3 |
| mut-c-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M39.txt | 82525950d3804fa2f94899af1dd14792b33ecc3e21af6aa2dedd2e82e76e49d2 |
| mut-c-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M57.txt | e5575a9ccd30caebfeaf452b46d16bc9bc731b5ac01179ef9c664fa7d86e6101 |
| mut-c-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M59.txt | de6f79a816e37bd333dae5dc2a1e5e0f043f4728cf349a34abcf5205777f3360 |
| mut-c-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M61.txt | 06f60f23746498f98cdef52527179417849007baa26c117e6a009bab4dfe04b2 |
| mut-c-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M64.txt | 1bc8507c6f553b4cfb26aa121704f2429d31b03a32f008956cfab7779fada9c7 |
| mut-c-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M71.txt | e238325478f5d9158dca57f4ec321f1808ef16feb478b55e28f55844da78ab62 |
| mut-c-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M78.txt | 010d17ecd70321b6c8eaeaff6cfc36917a4b2b04f4954e761b4bf23e12bbf827 |
| mut-c-M81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M81.txt | 1df936bb8dcb134842346ff55a6c9be33a2fe95a312205652e2938410c3f8635 |
| mut-c-M85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M85.txt | c4ff3c719934cd225b27fcebdea93f3e267d03fd83b7b11b199437d0f94ab7a0 |
| mut-c-M87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M87.txt | 8f40cb480f968928c353e7d6a8b631c2e33521771e69573a314aa52196f20ef9 |
| mut-c-M89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M89.txt | 6531dcc99662c6144f0bb34b7775048d7d89a2eb75c990fab471656af9e56ac2 |
| mut-c-M92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M92.txt | 988ee47bd7a22ce27ff25312f899261ff33fcdffa2c97c357d82119265e0b9ec |
| mut-c-M95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M95.txt | f5e07b8641fa8c86509864768b69eb820ea24d923b1b7b4705efcf49672f09af |
| mut-c-baseline.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-baseline.txt | 36f6f1d35c087999361f02e27285a2ca667a7763f9fd7e672f9b6cff8c2d8e75 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mutation-summary.md | d2d596fbd22f3600e170978bc0f46b1c361fe31eaa284c248c8c2c857ccfd0a5 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/red-01-vs-base.txt | d1a5a74a2c100a5d0e659a09d25dd0bd7b2e001500d630534157e014fcb5826f |
| red-02-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/red-02-corrective.txt | 92f089407b17101b540234c27fab4c3efae20e9cfea0c46d864a2d969d5de929 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 1 MAJOR, 3 MINOR, 2 NIT) — "OK to advance, with notes". The MAJOR CR9b-01 is a test vacuity (`ctrl+k` arm cannot fail), proved with a probe; MINORs CR9b-02 (the recent re-record arm cannot fail), CR9b-03 (a typed linked file gets the project wording), CR9b-04 (retired-class references outside the slice); NITs CR9b-05, CR9b-06. Diff read in full. — `review-increment-018.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 2 MINOR, 1 NIT) — SEC9b-1 (the over-long paste and the POSIX `~user` crash), SEC9b-2 (the `project.json` gate is narrower than the codebase's own regular-file test), SEC9b-3 (the same narrowing in the listing). Executed probes; the E3 mitigations re-verified. — `security-increment-018.md`. **Design reviews (E3, code-free):** `architect` (3 rounds: r1 FAIL, r2 FAIL, r3 PASS-WITH-NOTES) and `security-reviewer` (3 rounds: r1 PASS-WITH-NOTES, r2 PASS-WITH-NOTES, r3 PASS-WITH-NOTES) → design approved (`inc-9b/E3-architect.md`, `E3-security.md`). **There was no re-review:** nothing was blocking — the E5 reviews left 0 HIGH and 0 MAJOR in the source (the one MAJOR was test-only), so the narrow re-review is satisfied by the corrective pass's RED/GREEN/mutant evidence (`red-02-corrective.txt`, `green-03-corrective.txt`, `green-04-new-and-guards.txt`, `mut-c-*.txt`). **Orchestrator (2026-10-31).** Final source hashes `screens.py` `120d39b9697fab0f`, `styles.tcss` `5093edc072e03091`, `__init__.py` `0a5baebdb9fa71d2`, `app.py` `d0cfd46e22c3f60e`. Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75); the touched-module run and the full suite are deferred to the batch-end battery by the 2026-10-31 override. Rulings applied: Q1–Q10 (`inc-9b/E1-rulings.md`), the E2 rulings (`inc-9b/E2-rulings.md`), A9b-* / S9b-* / R2-* / R3-* (`inc-9b/E3-rulings.md`), SR-1 … SR-7 (`inc-9b/E4-integration-notes.md`), and the E5 rulings CR9b-* / SEC9b-* (LED .87). |

---

## 5 · Risks

- **The touched-module run and the full suite were not run for Inc 9b** (operator override 2026-10-31). A module outside the new-file/re-pinned set that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7). The three known pre-existing failures named by `green-02-known-on-base.txt` stay red at base and in the touched run: `tests/test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` and `tests/test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`.
- **The SEC6-5 timing arms sit at 0.8–1.03 s against a 1 s bound on this host, base included** (SR-7). One `green-02` run failed at 1.033 s under concurrent load; `green-02b` passed 3 of 3 on rerun. The arms go to the batch-end battery on a quiet host; the bound is not changed in 9b.
- **The `WinError 206` project-homes arms are blocked by the environment, not by 9b.** `test_tc_b100_31_depth_ceiling[32]` and `[33]` fail with "path too long" under the long scratch `--basetemp` and fail the same way on `741cc07`. They need a short `--basetemp` or long-path support.
- **The SR-2 cost.** `_folder_holds_project` lists the whole folder through `_list_project_files` (R3-4's early stop was a cost note), so every dialog open, verdict and pick pays one metadata listing per project folder. Declared, not a behaviour change.
- **The security review ran on the pre-E5 bytes.** E5 changed `app.py`, `screens.py` and the test files after it (SEC9b-1/2/3, CR9b-01/02/03/06). Their arms and mutants ran on the final bytes (`mut-c-*` KILLED); no reviewer re-read them — the E5-rulings addendum records the corrective pass's evidence as the narrow re-review.
- **Declared risks (not backlog).** A9b-R2-5: a queued `escape` then `alt+l` loads instead of closing (a rare double-key type-ahead; no code change). R2-N3b: the race between the `project.json` regular-file check and the open (needs a local writer of the work area). The SEC9b-1 list-to-field redirect appends by setting `inp.value` directly, bypassing `max_length` by one character — harmless, the classifier catches `ValueError`, not fixed (outside the ruling).
- **Model performance.** DeepSeek v4 Pro implemented G-A (0 deviations) and G-B (5 declared, all accepted), ran the 96 E5 mutants (70 killed at first, then the 26 survivors re-run to 91 killed / 5 equivalent), and did 3 design-fix passes. Two earlier pi runs hung 6.5 h and 5 h on stdin before the `< /dev/null` fix (steps.log). Opus did E1, E2, E3 (3 rounds), the tester, the integration, the reviews and the corrective pass.

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- Q6 (E1-rulings) — the Save-dialog priority-key exposure (the same `ctrl+l`/`ctrl+s` reachability through a modal) → **Inc 11**.
- Q8 (E1/E2-rulings) — the VS-PA-4 binding labels "Load" / "Projects" and the 35 snapshot rebaselines → **Inc 12a**.
- S9b-5 (E3-rulings) — the load-tail `Loaded {path.name}` status lines paint the raw name → **Inc 12a sweep**.
- A9b-R3-3 (E3-rulings) — the variant-list rebuild after a save or a file activation still goes through `validate_project_files` (LLR-173.4n is narrowed to the Load dialog preview and the project load) → **Inc 12a sweep**.
- `_COLLIDING_PATH` (E4-integration-notes pt 9) — the pre-existing (batch-29) user-name fixture in `tests/test_loadfilescreen_input.py`, to be replaced with `username_subject` → **Inc 12a sweep**.
- CR9b-05 (E5-rulings) — the `could not be read` pair is written 3 more times beside the table; one `_UNREADABLE_LINE` constant → **Inc 12a sweep**.
- the UX loss "A2L (none)" with no reason (E5-corrective-notes obs) — under 9b a linked A2L is not listed at all, so the Load-result panel says `A2L (none)` with no "link or junction" reason → **Inc 12a sweep**.
- the SEC9b-1 list-to-field redirect that bypasses `max_length` (E5-corrective-notes obs) — harmless, the classifier catches `ValueError`; not fixed (outside the ruling) → **Inc 12a sweep**.
- `architecture.md:670`'s "on a worker" (E5-corrective-notes obs) — A9b-04 made the preview synchronous; the stale text was not in the ruling → **Inc 12a sweep**.
- OBS-9b-1 (E13-notes) — the Load path-field placeholder is clipped at 118×54 (cosmetic) → **Inc 12a sweep**.

**Declared (Risks, not backlog).** A9b-R2-5 (queued `escape` then `alt+l`), R2-N3b (the gate/open race), SR-2's one-listing-per-project cost, and SR-7's SEC6-5 timing arms → batch-end battery on a quiet host.

**Named gaps / observations.** M02, M12, M14, M36 and M92 are equivalent mutants (recorded, no fix). Linux CI is not reproduced for the junction arms and the CR9-9 native half. The `mut-c` transcripts name the scratch `--basetemp` paths in their `command:` line (the temp folders themselves were removed). Five test files show line-ending-only noise and stay out of the commit (SR-6).

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| A9b-01 … A9b-06 (dialog `alt+l` priority, `_close` re-entry, the router re-home, the synchronous preview, the data-arm copy spy, the redirect + escape order) | MAJOR | E3 r1 rulings A9b-01 … A9b-12 (LED .86) |
| S9b-1, S9b-2 (whole-stack guard; link-safe preview and the `project.json` gate) | MAJOR | E3 r1 rulings S9b-1 … S9b-9 (LED .86) |
| A9b-R2-1 (the router input type), R2-N1 … R2-N5, S9b-7 (R2) | MAJOR / MINOR | E3 r2 rulings (LED .86) |
| R3-1 … R3-4, A9b-R3-1 … A9b-R3-5 | NIT / MINOR | E3 r3 addenda (LED .86) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| CR9b-01 the `ctrl+k` arm cannot fail; CR9b-02 the recent re-record arm cannot fail | MAJOR / MINOR (test) | fixed (new asserts); `red-02-corrective.txt` Parts 2a/2b |
| CR9b-03 a typed linked file gets the project wording | MINOR / design-gap | fixed (`link file` token pair); `mut-c` via `test_tc_b100_63_typed_linked_file_is_explained_as_a_file` |
| CR9b-04 retired-class references outside the slice | MINOR / impl (docs) | fixed (docstring + REQUIREMENTS.md + architecture.md) |
| CR9b-05 `_UNREADABLE_LINE` drift | NIT / impl | backlog → Inc 12a sweep |
| CR9b-06 docstring sections | NIT / impl | fixed (five methods) |
| SEC9b-1 the over-long paste and the POSIX `~user` crash | MINOR / design-gap | fixed (ruling B, refuse not truncate) |
| SEC9b-2 the `project.json` gate narrower than the codebase's test | MINOR / impl | fixed (`_is_reparse_point` in both gates) |
| SEC9b-3 the listing's reparse test | NIT / design-gap | fixed (`_list_project_files` skips reparse points) |
| M87 and the 26 mutant survivors | weak test / wrong target / equivalent | re-run: 91 killed / 5 equivalent / 0 invalid / 0 surviving |

**Orchestrator rulings Q1–Q10** are in `inc-9b/E1-rulings.md`; the **E2 rulings** (Q2 operator, Q8 operator, PSC-1, F-1, F-2, F-12, B-2, B-3, P-1..P-3, V-1, H-1, `_closed`) are in `inc-9b/E2-rulings.md`; the **E3 rulings A9b-* / S9b-* / R2-* / R3-*** are in `inc-9b/E3-rulings.md`; the **seam rulings SR-1 … SR-7** are in `inc-9b/E4-integration-notes.md`; the **E5 rulings CR9b-* / SEC9b-*** are in `inc-9b/E5-rulings.md` (LED .87).

**Re-pins (test::node — old -> new — requirement).** The 13 + 17 re-pinned test files move project picks from `#project_list` + `#project_ok` to the highlighted row + `enter` (and AT-B100-11 reads `#load_list`); `test_tui_app.py::test_handle_load_dialog_defers_load_until_after_modal_dismiss` re-pins to `LoadChoice("path", …)` (A9b-08); `test_tui_app.py:367` and `test_tui_helpers.py:132` give both folders a `project.json` (Q7); `test_b99_load_project.py` (TC-B99-35) gives `P1`/`P2` content and one reserved home content; `test_tui_directionb.py:9072` re-pins to `isinstance(app.screen, LoadDialog)`; the TC-B100-32 `[no project.json]` arm re-pins to `is not a project` / `pick a project in the list` (LLR-171.2e retired); the TC-B100-38 "route: validate_project_files" arm re-pins to `_list_project_files` (A9b-R3-1); the TC-B100-61 paint clock starts when the load returns (SR-3).

## 7 · Suggested next task

**Inc 10 of batch-100** — the load question (HLR-174) — with the `dev-flow-v3-beta` pipeline; its E4 integration is in progress on `b100-inc10`. Carried into it from this increment: the load question runs in the one router (LLR-174.4), whose seam LLR-173.1e leaves open at Inc 9b.

**Batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 96 Inc 9b mutants ran on the pre-E5 bytes; the E5 re-runs cover what E5 changed);
5. the SR-7 SEC6-5 timing arms on a quiet host, and the `WinError 206` project-homes arms under a short `--basetemp`;
6. the CI run, comparing the FAILED set with the previous run.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 of the 4-file cap (`screens.py`, `styles.tcss`, `__init__.py`, `app.py`); `os_clipboard_input.py` is a docstring-only change (CR9b-04, ruled as docs) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_load_dialog.py` (NEW, 133 items) + `tests/support/b100_load_dialog.py` + the re-pins + `test_id_registry.py` F2 — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `LoadChoice`, the dialog's verdict and preview providers, `_list_project_files`, `_a2l_admission`, the `via_fallback` record condition |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (141 new items RED vs `8947666`; 6 failed / 7 passed of the re-pin sample); `red-02-corrective.txt` (8 failed / 2 passed; 2 plugin mutants 1 failed each) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator override 2026-10-31, batch-end full battery** (§7). The new file, the re-pinned nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES (0 HIGH, 0 MAJOR in source); no re-review owed (nothing blocking) |
| 7 | No file from another lane touched | all | ✓ | the 4 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `_ENGINE_PATHS` modules untouched (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); `screens.py` / `app.py` changes are additive (the two Load screens retire, no engine file changes) |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 96 E4 mutants are stated as run on the pre-E5 bytes, the E5 re-runs on the corrected scratch tree |
| 10 | Load-bearing emptiness declared | all | ✓ | the CR9b-01/02 arms now fail on their mutants; the M87 killer is re-pinned to the LLR-173.4n outcome; the M26/M34 double-Enter arms pin the `_dismissed` guard |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 96 run: 70 KILLED, 26 SURVIVED, 0 INVALID; E5 re-runs: 91 KILLED, 5 equivalent, 0 INVALID, 0 surviving — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of the dialog: `_load_dialog_rows`, `_load_dialog_verdict`, `_load_dialog_preview`, `_file_preview_marks`, `_load_workarea_file`, `_handle_load_dialog`, `list_projects`, `_folder_holds_project`, `_list_project_files`, `_a2l_admission`, the `project.json` gates, `_typed_load_route`, the record calls, `check_action` |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence digest table (filled by the orchestrator from the staged blobs) covers `evidence/inc-9b/` |
