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
| `tests/support/b100_load_dialog.py` | test | HLR-173 | NEW: the Load dialog drive helpers — 741cc07 |
| `tests/test_b97_load_project_dialog.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_b99_crc_region.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_b99_load_project.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_b99_patch_truth.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_b99_truncation.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_clipboard_tk_singleton.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_tui_app.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_tui_directionb.py` | test | HLR-173 | re-pin (741cc07) |
| `tests/test_tui_helpers.py` | test | HLR-173 | re-pin (741cc07) |
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
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
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
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-01-new.txt | 32cdf34ee1348d83f1db937cdb844088b42f03efc0066e31ce8194a09d48fbdd |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-02-repinned.txt | e4add9a4e90683241bc205dd0b1aede484248908d110eb76cb9e34302f4058f1 |
| green-02b-timing-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-02b-timing-rerun.txt | aac141382518722f39cbf5564fbd49e966c3470f55c33c110873cde87b955bfe |
| green-03-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-03-corrective.txt | 514ddd8a0ca8b8ad1a2d52869a14604c81dee04e49d02c5f32012bb04efadc29 |
| green-04-new-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-04-new-and-guards.txt | c030b6f111455798a58ed7e31340ae89aae3c37e13a13f1c546bf856f5c1312f |
| green-05-project-homes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/green-05-project-homes.txt | 2a9dcbce4ec211f34363c1eb8c9959e0e1f493ff73f48630f777de58449b69a6 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/guards-01.txt | 57c7ce2a777fd3467750eff68a688005f7d185959b15d8926f56abf95f020038 |
| mut-M01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M01.txt | 435ea7304afbc0b4123f85ae1ed451042f27caabb1911636ee72b015cdddf688 |
| mut-M02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M02.txt | 72154777d465ca994d2576941d643bba11e44ed86452c4dc1c82f610d33ae8fa |
| mut-M03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M03.txt | 6ce02df86afeadbc8de6ee2a8552a9edfface64052310b901be72486a8e90961 |
| mut-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M04.txt | b11fbc05e7408bf3f348599d926ba7f83bec311943ba645f920393681d74feb4 |
| mut-M05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M05.txt | 3de80cae65f9fce795a8b4abbe3c25093bf18af9122e34a23c46be97b79ce0df |
| mut-M06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M06.txt | daee7e7b1d912d557ed5971a68864a638a008e500f3581479c075315dd21da8d |
| mut-M07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M07.txt | 6474d0b53e86764c82004c31905bfebc020ba7b028321f1e9d4476cc1c1d73ca |
| mut-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M08.txt | 767d8719f0cfec906339566429c504cae0cc2fb7b0fe77b9b8a51db40a495fae |
| mut-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M09.txt | 35cdea93ca1913a61712740f536efbff98f9adb0fc300e5755f0a769770260a5 |
| mut-M10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M10.txt | 5d8f1159c6762fe94ba9ecc966e36f7e1ffe9544465df641f2ee505fca2b87f4 |
| mut-M11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M11.txt | 2486586e6def3ad7a99c00da8966f2e83f31c0e6a81362ddf475019ce896f1e1 |
| mut-M12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M12.txt | a7de1b8ef04db7c74d7d9c5374afbfaca8a907273ee19fb66270894d9bc9b60e |
| mut-M13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M13.txt | 431d9db5b8c2373c5ffa318944b6c543965c7d844ebf45cd65f9e459d31cd4b3 |
| mut-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M14.txt | 0d06dd4ce0bb317a9ff3c7baddc1a70fe153041ed418151a29e9fc452562fbb7 |
| mut-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M15.txt | 16329a365242dfe2901a6eb34d1ee7c471bd602457b35d0aa7002ee0c36624cd |
| mut-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M16.txt | 2d0e85db691dc6c78cbc1c1ee0c2fca7319c27ed1b327d9b23f10b0549ff0f2e |
| mut-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M17.txt | 18cbeeafa502b1136376862ff9d9d7441ec4ae90a7fad4db4c18dac15e6c97f3 |
| mut-M18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M18.txt | c35fee49f8df1b9f27483ab7e1aa720b16c92e0e575905b0e1be9fa0a9a30297 |
| mut-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M19.txt | 5b5cb22e7eb14ca04d043b9355551d9f6da1844c622e86ea18f97f6dca3261db |
| mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M20.txt | 9fcf5dd51c47cce9e89e9605a8ef465cda68cd48008fac54f15dcdc39539ae2a |
| mut-M21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M21.txt | a56de2fe103e936529321421d3a48da487789eb004f9d05d38024a1f612d41a0 |
| mut-M22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M22.txt | 018b5a9c6df1ce94565f84ec869d605d642bbf3e5d3e3f87b3d477d9b92c222e |
| mut-M23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M23.txt | 97b804ac8061a94bf619563dd1d5f5aca77b87b5992df92ee363845d943e03a9 |
| mut-M24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M24.txt | d8afc379d75d0d1242a77e7831ad7e101822078b9db996e4e739c70dbdaccd17 |
| mut-M25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M25.txt | f5bb207fc84fa150eb21bdf26e9c300fbdf9b50b0cff7155ed5e34f2dbb9998f |
| mut-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M26.txt | df4c5792446aa682a36928a583610c985ef9af3ae3d5600bd3863e2f59ef7a0d |
| mut-M27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M27.txt | dddfeb0a67367ddb6c7b87f8de88047226b02268cd231d0f989bfe9c924de073 |
| mut-M28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M28.txt | f69918feb82db8d93708dd88b2323bbd1419e9b3d33d9e26cd6bbcedfa6e115a |
| mut-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M29.txt | 6ce5d5034ae0fac4ef41b2f6d3f3d8655c5ba5c7a8ac363d4b5eacc5acf9238c |
| mut-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M30.txt | 789ce859213bf17df49187aafcccf7ea86363972c8e2ae930d1b40ea39718784 |
| mut-M31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M31.txt | 6bf54af1b6d4f13107443c4ac233505fe6188100d625b010fd3d4bea9c6cacbe |
| mut-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M32.txt | a3fed7216ab151e9c2a5cf4646c32f11a0b15b8ee7f9058adc8cd76ac11615b4 |
| mut-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M33.txt | 3a7f0000d189c5b898baf864cf6fe89cd4b1ae439cf8825b734bec573f710d01 |
| mut-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M34.txt | fb264ff293f7fa61077b03b55f82a4f79e49d19adf212339b908141d991797b1 |
| mut-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M35.txt | 6178d7eca5e883a9b0a19915a6685d5e311190d26d2e3af81a973b50ae072ca6 |
| mut-M36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M36.txt | 5b9f2dc783d83e6185046c041fc20e84c4facc25760d7dff0b9e8a03161b9445 |
| mut-M37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M37.txt | e2c2ddaf5046c182e3d5493b3ea1e04ef924ad8875b7217209e99c5ce349d7fc |
| mut-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M38.txt | 2a69169d379e6baa481a92fc16dc873f0e149b74abbe794334e5a7f1dce1a6a6 |
| mut-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M39.txt | 2fdb61ff1311ae6b2d71aa23291d28fd58f4c507bc1c93b4a0ec5cf41e943220 |
| mut-M40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M40.txt | 8b409c819bceabb02b8e72d238222a39cd4b68d0b1418b3262fb61c4a031309b |
| mut-M41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M41.txt | 3bf7909487ef970549690b2e4c0b3420366541edceaf9281af86938873f0ea68 |
| mut-M42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M42.txt | 44aecd851afaddbc263c27a87ae980e059d86ea02c55e04f201c7e7d4466b194 |
| mut-M43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M43.txt | 3d8344ab6dcc3f03d6f4621d41a39e633fed035995c9e290a6a1f6675f6af52a |
| mut-M44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M44.txt | 53c5a537503284f9a9c705f0cd1c8addcfee371efadd09e24d0ef9c85f9ded90 |
| mut-M45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M45.txt | 3c8b542d727a9f0caa86242484f21198851e9ea73a4a11b6e9ae1cade24e0476 |
| mut-M46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M46.txt | 4a3674e6322ad3d54b841b946dcd4aa5e579f8263b58bbf08f93b2e022197021 |
| mut-M47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M47.txt | c3ab24ec46892d50d783adc8f26734c2002208fbc0803e215cda63ea06c296b0 |
| mut-M48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M48.txt | 1d993ff007ad6aa74722da092b3b79eaf2ec623082d51f0212b2cf455d72dc2f |
| mut-M49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M49.txt | d89e640a44b91bfa020668f4d98d93a7840a1777a811652d8668e889c16e9130 |
| mut-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M50.txt | ad5d83768258263dc512e98ed1aa4ca3b7a7892a397c6af58e71e656b16f70eb |
| mut-M51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M51.txt | 574c05ee27f26450e2dd9ac94893f431130ffc6e4994bd42b4d62de6268e2c21 |
| mut-M52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M52.txt | d00918b5008ad910c9a31947056e0a2e7e049df7af74841fc192f9d618d49e4d |
| mut-M53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M53.txt | fed618de79bafb0c01048fad813379fb080c1a5ba9fee3bed830a58a55766bb1 |
| mut-M54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M54.txt | 06bc0b55929b2ff8fc72c12021817a8bca4fbac8c2fa42c61c125c4378fa703e |
| mut-M55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M55.txt | eb17b25ce9ad1e37c7e321cfcdf7e8110119e1ba2e6a4a9a1f96dc2a450ac1dc |
| mut-M56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M56.txt | dacf700163e7413fd17a968d0941080f9a33b80617d08e4a9f069f80b5127d51 |
| mut-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M57.txt | 17d909d8ac3bf2272253ae845035a71404d5a0044741fe59ac48597e70b069cf |
| mut-M58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M58.txt | ce9f09745052244a03eda38e57fe03295b0eac5eb0471fcbdb419d6b5ed2ec20 |
| mut-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M59.txt | 4d557ec95fa70564b8dfa98d391062be00e2ee618716facdc99173d3f2b8fa50 |
| mut-M60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M60.txt | 2a22d4bb658eee6ac60a5cbc9294e9277830b17b1e8eca538faafa49a67f6595 |
| mut-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M61.txt | 7d98b58de05770874858ce49a054c1d9355c13a99b299196e443fe38f21d04b5 |
| mut-M62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M62.txt | 0a6ec90ec9408e9114f4886d81a792929dc4bb20fa3681d9d061a9ee5105c43a |
| mut-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M63.txt | ac5f3f0ae58ce93c0da7938a036dadf6ac99a579f1818ac72acb755346bce9d7 |
| mut-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M64.txt | 8a2f009f47355c7d931209ffb2f1b8858659f5661251c7bf4d0dbd18f368cf35 |
| mut-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M65.txt | 87f5ba7d4b541bace8cd0fd3f18384969f87563e3e8a8552b7db2affc6cf0311 |
| mut-M66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M66.txt | 8cc200d87c38c680ce93bf2344708c9f4663230630bc45e12f14f3de705d1fac |
| mut-M67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M67.txt | e19fd9acd637b7b7faa6ead702fbe8fafab4f9bf1ef7016f2be8f556c2622344 |
| mut-M68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M68.txt | 311a761eadcdb8918a77a2a2acd25619548fd4ebfbaa7b415cb8ac2d1b34e1cb |
| mut-M69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M69.txt | 2dd2d5b2d86afe686f517d764f69219362cd4ce6b5138e41aae84f454ae95aae |
| mut-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M70.txt | 8c44b2ef03422bdcd61cc51f78b69963c34425c203dcea4e6d4716345bdd5648 |
| mut-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M71.txt | 9706a9985afbb2d9959bef59bab5b56389fb004bb956768e91a85339c79b1442 |
| mut-M72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M72.txt | b376bcdc6394cb9d6ddeb656b4854dc606cd1dd360568d1b7ab5c1500003268b |
| mut-M73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M73.txt | 1e78de9649abb85d3993dff34db54937361bda73d29d1b9d033abdedd7d0dc71 |
| mut-M74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M74.txt | a07e6725353707054e8fca8d365d656d5f464585a817de5785dafabe642762dc |
| mut-M75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M75.txt | 2662187fa30df730b0acbf49ec03c97566ba7c5fd0e83dcb01e695092c432283 |
| mut-M76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M76.txt | 52d76e058dee98a8aa7ea9ce6283648f6ee39ef5cb4b99d43e0b1fa1e8733000 |
| mut-M77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M77.txt | b914f662c08269fba9324f767414148861d31bc21bf9c020fd652de9df15784c |
| mut-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M78.txt | 9317bbf5f631862422f65b163a3c2f3720a0f292332a937f43668a9cbf1f4ed8 |
| mut-M79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M79.txt | cde815fb1b64bb104c50d8e1bc2b524e8b3f47503fdf58301bb09ab4e4e86342 |
| mut-M80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M80.txt | c3f227f84f5614abd9fb5941ecd29e9bc40ba42dc8bab53091f0519d8358f6c4 |
| mut-M81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M81.txt | a3b2f7f7e03d4a99f63882e2e5a4a249c02ba28c97e498e2e77a9352c54ca9cf |
| mut-M82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M82.txt | c83e9323850b47465a5aefc537246002a6afa03aa78f0156f5776b454600d163 |
| mut-M83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M83.txt | 24cdf9866a9c2efa1186c99ff537d8368d7ed0f36b60119acbb57e4d8d435888 |
| mut-M84.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M84.txt | d6d69b2ce9cedd35fdd396d7b025f4c63e530b63017c7a67c0c75952e6f89ca4 |
| mut-M85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M85.txt | 46e5fe199dcc55ba19ca8174ec8ef9c5e79056b0e46f8361f68025a2d4d6f138 |
| mut-M86.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M86.txt | 21832e252862c33e37390930afb8ab03d91e4cc34d3276ab5436ea0ffa3aeea2 |
| mut-M87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M87.txt | 4348498534c134613f2ed9795adba31a0136faf82cc952185879469ee7f666e2 |
| mut-M88.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M88.txt | c8170684165bcf9a6ee1bd803943cd3856ca49125f595a20ccfc7e2599c67294 |
| mut-M89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M89.txt | 553a3b00297df0e55c94f8e55312d676bd96c48e3ce5f7ee1480c47a7e67030f |
| mut-M90.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M90.txt | 49ed8fb3d02950d391328217b963df7fd9dc76e01c2592a129ca7ee313def4a8 |
| mut-M91.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M91.txt | 5909886ddbc0554269a55105bc4a15446183102b92803f12173ecdeb5d147d66 |
| mut-M92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M92.txt | 54bd873f24e3299615246e29cafee06d18d69e68c91e06cc30c246aeb87c3680 |
| mut-M93.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M93.txt | ce84ea69eb9e8baa8f9c38c616b47978225d46ea45863a4df74fa607ed9e078b |
| mut-M94.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M94.txt | 168285c12178dae0663178d153cca68dbc816bde4da8edd0bcd3db3a944a4fd5 |
| mut-M95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M95.txt | 8ba8a1ec8c7131df878eab74d65efac215911b2055e6ea907f53bfbea3125cfe |
| mut-M96.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-M96.txt | 5c8d13b4f5d2804baf807766b01f4af5d0de1e401f1097c7b06cdb3381bdecf8 |
| mut-c-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M04.txt | 549597823e6174fd57e00e7ac64885d27c92674cb9dbcda31098e8692094a4a8 |
| mut-c-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M09.txt | b77ef7069d7c0e68b3ef5d1582db8cd9c839cc192bca01fd1338f47df26ca197 |
| mut-c-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M17.txt | 2409a1493854d721f7488420ef73d142446a60a1e36bb61577943dd771735f3f |
| mut-c-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M26.txt | 3e9f181499275ec206f658fd53dc576f4a8d94dade6e0fd9f8bea6d9ebb4f55e |
| mut-c-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M32.txt | 535c146befdc41a4f3b0f40da1468648b20c0962067c385e14d934b637e88803 |
| mut-c-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M33.txt | 20d87c495ad80c28c8f5e85f0b671ef12214a8c6a420ccd45994e7acb7346a45 |
| mut-c-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M34.txt | 925264396ceb12f4cd9350d531b15bce4e237220e3200cdadfa3f1faecaf97a1 |
| mut-c-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M35.txt | ccdd0b8a9d4c43880f42334488ecd1adfe2eeef1ee36b827f033d51ae91d3c8e |
| mut-c-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M38.txt | c7d642618a7e83bff376ba5519a8dcf5e9f67c1a4e66642511a3c44fd2e5095d |
| mut-c-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M39.txt | fc0ccd38160e6f7f8f232329e51831d1069f084b5f73f091b268349bf6990931 |
| mut-c-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M57.txt | 8883bb0523cb675373829ca0501780038ae3218288e281bd6b3d1534e9dae2df |
| mut-c-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M59.txt | 835da5839a1b13b2c6e1f32a966cd02bd8c5a7d93bc11b680d10ea76cecff4f1 |
| mut-c-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M61.txt | d9541386dfd2a88d9cf47470c6afd5c792d227dedfe164e9e08a9cbc0d4aceff |
| mut-c-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M64.txt | 2106d3815bcab853c3cb921787eee6349af8e92053f7d830c7bad575ce474984 |
| mut-c-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M71.txt | 98ebdb0565c7d671bf3b8265951cbe6e15ee824fcea90373316975d1d9eeb5a3 |
| mut-c-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M78.txt | 9619e40f1e3d00b4b846f0df7adc51acd71f8bf4c897825b52a31b4b1beb2db6 |
| mut-c-M81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M81.txt | 489f8ec5270f9dba9c01e8f47d0ab82a388cc20e30734ec147029e58dd613698 |
| mut-c-M85.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M85.txt | 4cac8e748b6dd3d10ec043b1bacbd2e4cb266b9a03b367767437bab29f343a61 |
| mut-c-M87.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M87.txt | b736c78353d0fb63b868c2c7b9df4533f4e808d3967e80ab67793d00c35d79fc |
| mut-c-M89.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M89.txt | e31c708e34c605ed6f39a19026759808b254b75cfb60f39f375738fa77ab2620 |
| mut-c-M92.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M92.txt | ccd7f23f3876c50a70387658147d17ae47a5fe41aa2b5ed07c25e3df0351f060 |
| mut-c-M95.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-M95.txt | fc28e0d666c00f41c3f30676c784bd32694a827c9989702f8c8af08360577ca7 |
| mut-c-baseline.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mut-c-baseline.txt | a7cbe9934d318202a8e4eaf2acaed25fabc0f4de55f576be6bc304e9512b863e |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/mutation-summary.md | c34499bdfb24e54f1ce81fb3b4f30b2ef94b14f4c2880cc5f7828ae9c067087d |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/red-01-vs-base.txt | 9fc2d3a2d786f79622890b3a2bd0507fe60aebfc4dd7d5f5e665b9a9c4df63f0 |
| red-02-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9b/red-02-corrective.txt | 9df5f400d06c266bd2bbf063177d5bb0df8eebcd57734bb01ca9c525b9ee814a |

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
