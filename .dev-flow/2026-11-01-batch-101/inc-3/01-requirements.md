# Inc 3 — Save project margin; a vanished project folder: requirements (E1)

Batch 2026-11-01-batch-101, increment 3. Base: `e266395` (branch `b101-inc3` = main); Inc 2 (PR #212) merges before E4, so the test rows build on its `serial_timing` marker, `report_margin` and `wait_until` (`tests/support/timing.py` on `b101-inc2`). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Scope, decisions and reasons: `E1-rulings.md`. Profile behind R1-P1 and the painted-step diagnosis: `E1-profile.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc3.md`.

Sources: plan row 3 (`p0/PLAN-draft.md`, `PLAN.md` rulings of 2026-11-01 on R1-P1 and OBS-F2-1); triage rows R1-P1 and OBS-F2-1 (`p0/triage-E-ux-and-backlog.md`, verified against the code); `s19w/review/CODE-CHANGES.md` D11-72; the routed item R-3 (`inc-2/E4-integration-notes.md` §8 item 2 on `b101-inc2`); canon S11 (`REQUIREMENTS.md` §S11.3, §S11.4, R-PROJ-002, R-MAN-VERIFY-001.4, R-PROJ-ASSIGN-001.7) and Inc 2's R-TST rows (R-TST-025, R-TST-047 on `b101-inc2`).

Form column: U = ubiquitous, E = event (`When`), N = unwanted (`If … then`). "Base" column: what `e266395` does today. E3 round 1 corrections carry the finding id in brackets ([F1] … [F11] architect, [S-1] … [S-5] security; rulings in `E3-rulings.md`). Line numbers are `e266395`'s; origin/main `f11b3f4` (batch-102) moved the `app.py` and `workspace.py` lines without changing any slice function (map: `E1-slice.md` §0).

No row changes a screen layout, and every painted text is a canon text already shipped. One painted line changes in one scene [F1, S-1]: a Save project whose composition names a link loop in the project folder ended at `e266395` with R-PROJ-ROLLBACK.18's `Project NOT saved: could not save — an unexpected error stopped the save. check the folder.` (the gather raised) and now ends with R-PROJ-ROLLBACK.9's `Project NOT saved: could not save — project.json was not written. check the folder.` (the gather goes on; the manifest writer refuses the link entry). `E1-rulings.md` §1 admits it.

## User stories

### US-PROJ-SAVE-1 — Save project keeps its time bound with room to spare
As the operator, I want Save project to finish well inside its 1 s bound when the project records 1 000 documents deep in sub-folders, so that the save stays quick and its timing arm does not fail on a busy machine. (At `e266395` the arm takes 1.11–1.33 s on the E1 host and fails 10/10; batch-100 measured 0.75–1.0 s.)

### US-PROJ-SYNC-1 — a deleted project folder is not silently brought back
As the operator, I want a load into an open project whose folder I deleted outside the app to be refused with the existing `… sync NOT done …` line, so that the app does not re-create the folder and write a partial project I did not ask for. (OBS-F2-1, D11-72.)

### US-TST-PAINT-1 — the panel and append timing arms measure what the app paints
As the author or reviewer of a later increment, I want the Load-result panel arms and the variant-append arms to stop their clocks at stamps the app emits, so that a red serial lane names a real paint delay and not the time the app takes to go idle after the paint. (Routed from Inc 2, ruling R-3: `painted` values of 0.001 s or 0.6–1.36 s, never between.)

## Definitions

- **T2 composition.** The open project P records 1 000 real files at the end of a 31-folder chain (each entry has 32 parts) in `batch`, in `assignments['firmware']` and in `gathered['patches']`; Save project is confirmed into P under its own name with `batch` = those 1 000 names and `assignments` = {`firmware`: the same 1 000 names}. (Security probe T2's shape; the scene of `tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]`.)
- **Composition document name.** Each name in the batch and each name in the assignments that the save writes (R-PROJ-ASSIGN-001.7). The same text may occur in both, or more than once. Two names are the same name only when their texts are equal (`./x.json` and `x.json` are two names) [F11].
- **Confirm.** The Save dialog's dismiss with a payload (`_handle_save_dialog` called with it); the interval of R-PROJ-001.13 runs from that call to the status line.
- **Link loop.** A link or junction that leads back to itself, so the path through it names no file (on Windows: a directory junction pointing to itself; on POSIX: a symbolic link `x.json` whose target is `x.json`) [F6].
- **Install stamp.** The moment the app's project install callback returns (as R-TST-025 on `b101-inc2`).
- **Panel paint stamp.** The first layout-refresh publish of the pushed Load-result panel screen (its `screen_layout_refresh_signal`) at which its summary (`#result_summary`) has a height above 0 [F3]. Textual publishes that signal once per layout pass, not once per frame. Outside a `batch_update` it publishes after the pass's screen refresh, so the stamp follows the frame that holds the laid-out panel. Inside a `batch_update` it publishes before the deferred refresh. `s19_app/tui` has no `batch_update` today. Diagnosed on the dev pin `textual==8.2.8` (`pyproject.toml:73`); re-check on a Textual bump. At E1 it falls on the first layout pass in 8/8 runs (`E1-profile.md` §2.2).
- **Outcome-line stamp.** The moment the app's status line receives the variant append's manifest outcome line (`… manifest verified` or `… was not rewritten …`).
- **Panel arm.** A timing arm of `tests/test_b100_project_check.py` that bounds a Load-result panel paint: `test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second`, `test_tc_b100_61_files_at_the_cap_all_missing_are_bounded`, and the 4 arms that run `_sec6_5_filesystem_scene` (`…_deep_entries_need_one_check_each_parent`, `…_entries_under_an_existing_folder_are_all_checked`, `…_distinct_folders_stop_at_the_folder_ceiling`, `…_junction_loop_costs_one_failure`; the last one Windows only).
- **Append arm.** One of those 4 scene arms, for its bound on the variant append that follows the panel (`sec6_5 appended`).

## Requirements

### R1-P1 — Save project at the T2 composition (US-PROJ-SAVE-1)

Source implementing R-PROJ-001.13, R-PROJ-GATHER.12 and R-PROJ-GATHER.13: `s19_app/tui/services/project_gather_service.py` (`gather_project_artifacts`, composition limb; map in `E1-slice.md` §1). [E4 integration: named here so the trace check's SLICE rule finds it.]

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-PROJ-001.13 | E | When the operator confirms Save project into the open project at the T2 composition, the system shall show the status `Project saved + manifest verified` within 1 second of the confirm. | < 1.0 s (`timing_bound(1.0)`), 5/5 runs alone; increment target ≤ 0.8 s alone (QC-TM margin ≥ 20 %), 5/5 on Windows and 5/5 on the LAN Linux host (E1 measured 0.65–0.74 s on Windows with the design applied as a runtime wrapper) | the composition check's `resolve()` restored → ≥ 1.0 s on the E1 host (base: 1.11–1.33 s) → RED | US-PROJ-SAVE-1 | No: 1.11–1.33 s, 10/10 over the bound (`E1-profile.md` §1.3) |
| R-PROJ-GATHER.12 | E | When the system gathers composition documents, the system shall check each distinct composition document name against the project folder once. | T2 composition: 2 000 names, 1 000 distinct → 1 000 project-folder checks, 1/1; a missing name given twice → 1 check, 1 finding, 1/1; a name with `..` over a missing folder (`missing/../x.json`, `x.json` in the project) → 1 check, on the lexically folded path, and the name counts as already home, 1/1 [F5] | the once-per-name rule removed → 2 000 checks → RED | US-PROJ-SAVE-1 | No: 2 000 checks, each with a `resolve()` |
| R-PROJ-GATHER.13 | N | If the project folder holds a link loop at a composition document's name, then the system shall look that name up in the common patches library by its last part. [F1, S-1: restated at gather level] | gather level, 2/2: a link loop `x.json` at the project folder's top level (Windows: a junction to itself; POSIX: `os.symlink("x.json", <project>/x.json)` [F6]), `x.json` (a change document) in the common patches library, `composition_names=["x.json"]` → `gather_project_artifacts` returns without raising and the library `x.json` is gathered: `outcome.gathered == {"patches": ["patches/x.json"]}` | `resolve()` restored in the composition check → `RuntimeError: Symlink loop from '…x.json'` leaves the gather → RED (both arms; measured at E1 and E3 on a junction, Python 3.11 and 3.12) | US-PROJ-SAVE-1 | No: the gather raises `RuntimeError` |

### The same scene at save level: canon rows, unchanged text [F1, S-1]

What Save project does when its composition names a link loop. The gather goes on (R-PROJ-GATHER.13), copies the library `x.json` into `patches/`, and the manifest writer then refuses the batch entry `x.json` because it is a link (`_reject_unsafe_entry` → `_EntryWalk`, LLR-001.5 / SEC7). So project.json is not written and the save rolls back. These two canon rows give that end; this increment verifies them in that scene and changes neither. The writer's link refusal (`_reject_unsafe_entry`, `_EntryWalk`, `_entry_text`) is outside the slice and must not change [S-1].

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-PROJ-ROLLBACK.9 | N | If project.json cannot be written, then the system shall show the status `Project NOT saved: could not save — project.json was not written. check the folder.` | Windows (junction): P open with a junction loop `x.json` at its top level, `x.json` in the common patches library; Save project into P with `batch=("x.json",)` → the lines since the confirm hold `Project NOT saved: could not save — project.json was not written. check the folder.` exactly once, 0 lines holding `an unexpected error stopped the save`, 0 lines `Project saved + manifest verified`; the app keeps running; 1/1 | `resolve()` restored in the composition check → the line is R-PROJ-ROLLBACK.18's `… an unexpected error stopped the save. check the folder.` → RED; a writer that accepts the link entry (an out-of-slice mutant, E5 copy only) → `Project saved + manifest verified` → RED | US-PROJ-SAVE-1 | No for this scene: R-PROJ-ROLLBACK.18's line (the gather raises first) |
| R-PROJ-ROLLBACK.2 | N | If a save fails, then the system shall remove every file and folder created by the save. | the same scene → after the save ends, `<P>/patches/x.json` does not exist, and `<P>/patches/` does not exist unless it existed before the save; 1/1 | the gather's `written` list not handed to the rollback (`placed_files.extend(gather_outcome.written)` removed, E5 copy only) → `patches/x.json` stays → RED | US-PROJ-SAVE-1 | Yes for this scene, trivially: nothing was gathered before the raise |

### OBS-F2-1 / D11-72 — a deleted open-project folder (US-PROJ-SYNC-1)

R-PROJ-002.12 and R-PROJ-002.13 are canon rows, unchanged in text; this increment makes their "no longer exists" alternative true. R-PROJ-002.14 is new.

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-PROJ-002.12 | N | If the open project's folder cannot be read or no longer exists when the system adds an S19, Intel HEX or MAC file to it, then the system shall show the status `Project sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` | the line exactly once in the lines painted since the load, 6/6: S19, Intel HEX and MAC loads, each with the folder deleted outside the app and with a regular file in its place (the S19 file-in-place case is TC-B100-54, existing) | the sync's `mkdir(parents=True, exist_ok=True)` restored → the deleted case paints 0 such lines (the folder comes back and `Added variant 'other' to project 'P2'` is painted) → RED | US-PROJ-SYNC-1 | Partly: the "cannot be read" alternative yes (TC-B100-54); "no longer exists" no — the folder is re-created |
| R-PROJ-002.13 | N | If the open project's folder cannot be read or no longer exists when the system adds an A2L file to it, then the system shall show the status `A2L sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` | folder deleted after the A2L attach's request-time guard passed (during the attach worker): the line exactly once, 1/1; `validate_project_files` raising `PermissionError` (TC-B100-54, existing): 1/1 | `mkdir` restored → 0 such lines → RED | US-PROJ-SYNC-1 | Partly, as R-PROJ-002.12 |
| R-PROJ-002.14 | N | If the open project's folder no longer exists when the system adds an S19, Intel HEX, MAC or A2L file to it, then the system shall create no folder at that folder's path. | after the load, the project folder's path does not exist (`os.path.lexists` False), 4/4 (one per file kind) | `mkdir` restored in the sync of that kind → the path exists → RED | US-PROJ-SYNC-1 | No: `mkdir(parents=True, exist_ok=True)` at `app.py:14615` and `:14738` (`:14940`, `:15063` on origin/main) re-creates it; measured: `sync-end-lines-base.txt`, `lexists=True` in 3/3 deleted scenes |

### The panel and append clocks, routed item R-3 (US-TST-PAINT-1)

Subject: the test suite. Bounds are not raised (plan rule: a bound is never raised blind).

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TST-110 | E | When a panel arm measures the paint of the Load-result panel, the test suite shall start the clock at the install stamp. | the arms' clock-start rule given an install stamp of 10.0 and a click return of 12.0 → 10.0, 1/1; the 2 panel arms and the shared scene start at the install stamp, 3/3 sites | the `max(pressed, install)` rule restored → 12.0 → RED | US-TST-PAINT-1 | No: `max(pressed, _load_returned_at)` (`tests/test_b100_project_check.py:767` on `e266395`, `:774` on `b101-inc2`) |
| R-TST-111 | E | When a panel arm measures the paint of the Load-result panel, the test suite shall stop the clock at the panel paint stamp. | the value each arm passes to `report_margin` for its painted bound equals (panel paint stamp − install stamp), both recorded by a class-level observer that shares no state with the arm, within 0.001 s, 3/3 runs of the all-bad arm, 3/3 of the cap arm and 3/3 of the distinct-folders scene (verifier: graph node `test_r_tst_111_112_arm_values_equal_the_product_stamps`, marked `serial_timing`) [F2]; at the stamp, the problem-row count of the panel equals the arm's final `rows`, 3/3 per arm [F4] | the clock stopped when the arm's wait notices the panel → the value exceeds the stamp difference by > 0.1 s (E1: 0.50–0.66 s more) → RED | US-TST-PAINT-1 | No: stops when `_wait_for` notices `#result_summary` with a height |
| R-TST-112 | E | When an append arm measures the variant append, the test suite shall stop the clock at the outcome-line stamp. | the value the scene passes to `report_margin` for `sec6_5 appended` equals (outcome-line stamp − the entry of `load_from_path`), both recorded by the class-level observer, within 0.001 s, 3/3 runs of the distinct-folders scene (same verifier node) [F2] | the clock stopped when the wait notices the line → exceeds by > 0.05 s (E1: 0.1–0.4 s more) → RED | US-TST-PAINT-1 | No: stops when `_wait_for` notices the line |
| R-TST-113 | U | The test suite shall hold 1 second as the bound of every panel-paint and variant-append interval of the panel arms and the append arms. | 4/4 bound sites are `report_margin(<label>, <value>, timing_bound(1.0))` (all-bad painted, cap painted, `sec6_5 painted`, `sec6_5 appended`) | one bound raised to `timing_bound(1.5)` → the static check names its line → RED | US-TST-PAINT-1 | Yes (4/4 at 1.0 on `b101-inc2`) |

## Coverage of the stories

| US | Rows |
|---|---|
| US-PROJ-SAVE-1 | R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13, R-PROJ-ROLLBACK.9, R-PROJ-ROLLBACK.2 |
| US-PROJ-SYNC-1 | R-PROJ-002.12, R-PROJ-002.13, R-PROJ-002.14 |
| US-TST-PAINT-1 | R-TST-110, R-TST-111, R-TST-112, R-TST-113 |

## New and changed canon rows (for the requirements session)

- New, S11: R-PROJ-001.13 (§S11.3), R-PROJ-GATHER.12, R-PROJ-GATHER.13 (§S11.4), R-PROJ-002.14 (after R-PROJ-002.13).
- New, S0 (process rows of the test suite, Inc 2's family): R-TST-110, R-TST-111, R-TST-112, R-TST-113.
- Changed: none. R-PROJ-002.12, R-PROJ-002.13, R-PROJ-ROLLBACK.9 and R-PROJ-ROLLBACK.2 keep their canon text (verified, not edited). R-PROJ-GATHER.13's text changed at E3 round 1 before it reached the canon (it is still a new row). CODE-CHANGES D11-72 → done at this increment's merge.
- Ids checked new: `grep` over `REQUIREMENTS.md` and Inc 2's `01-requirements.md` (branch `b101-inc2`) finds none of the 8 new ids.
