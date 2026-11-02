# Inc 9a — E4 integration notes (orchestrated integrator)

Scope: bring G1 (`s19_app/tui/workspace.py`, DeepSeek v4 Pro) and G2 (`s19_app/tui/app.py`, DeepSeek v4 Pro) together with the independent tester's suite (`tests/test_b100_recents.py`, `tests/conftest.py`, `tests/test_id_registry.py`), to GREEN, and check both implementations against the approved graph (`codewire/proto-9a-workspace.md`, `codewire/proto-9a-app.md`, `codewire/interfaces-9a.md` "Applied after E3 r1", `E3-rulings.md` R1–R17, `01-requirements.md` HLR-172/172a/172b, LLR-172.*). Worktree `<HOME>\Github\s19_app-b100-inc9a`, branch `b100-inc9a`, base `4fef292`, uncommitted.

Source files edited in integration: `s19_app/tui/app.py` only (1 of the 2-file cap). `workspace.py` unchanged from the G1 hand-off.

## 1. Graph review of the DeepSeek code (both diffs read in full against the graph)

### Fixes made

| # | File:line (final) | Graph node / ruling | What was wrong | Fix |
|---|---|---|---|---|
| F1 | `app.py:12122-12125` (`list_projects`) | E3 R14 (S9R2-1 LOW), addendum to G2's `list_projects` context node | Not implemented (declared in `steps.log` by the G2 run). `list_projects` listed an on-disk folder named `temp.` or `ab ` (created through `\\?\`); Win32 opens `W/temp.` as `W/temp`, so a pick would load another folder. Tester nodes `tc_b100_38_project_list_skips_a_name_ending_in_a_dot_or_space[temp.]` and `[ab ]` were RED (`pre-new.txt` run: 2 failed / 139 passed). | `if item.name.endswith((".", " ")): continue`, after the reserved-home skip and before `_project_folder_refusal` (whose `lstat` would itself be redirected by Win32). 4 lines incl. a 2-line comment citing R14. |

### Checked and found conforming (no change)

- **(b) Workarea Files label** (`app.py:7321`): `Label(safe_text(painted_names([path.name])))`. `painted_names` (`services/project_gather_service.py:965`) returns `str`: each name with Cc/Cf/Zl/Zp removed, unpaired surrogates as U+FFFD, clipped to 120 characters ending in `…`, joined with `", "` (a single name → no join text). `safe_text` (`s19_app/utils.py:44`) wraps it as a `rich.text.Text` with an explicit style, so Textual never parses it as markup: literal and markup-free per LLR-172.6 / R4 / R17. `entry.data = path.name` keeps the on-disk name (LLR-172.6a, C5). Proven by `tc_b100_39_rows_paint_names_literally` (7 arms) and `tc_b100_39_picked_row_loads_the_file_as_named` (4 arms) GREEN, and by mut-int-07 / mut-int-08 RED.
- **(c) No caller try/except around `record_recent_source`** (`app.py` `load_from_path`, `load_a2l_from_path`): confirmed — `if not contained_in_workarea(normalized, self.workarea): if not record_recent_source(normalized): self.logger.warning(...)`, exactly 1 warning on `False` (S6 / G2 P-2), records `normalized`, never `copied` (S7), placed after the copy and before the worker / `refresh_files` (S1). mut-int-03/04/05/06 RED.
- `workspace.py` — all 9 owned nodes match the graph step by step: `recent_store_path` (call-time `os.environ`, `^[A-Za-z]:[\\/]` on every platform, R5/S9), `recent_kind` (`PureWindowsPath` suffix, loader sets), `_recent_entry_ok` (check order 2i → 2g → 2e → 2f → 2h), `read_recent_sources` (link check before open R6, one `read(65 537)`, strict decode, `(ValueError, RecursionError)`, `type(v) is int and v == 1`, outer guard), `_encode_recent_store` (compact ASCII, drop-oldest loop, `b""` for one oversized entry), `record_recent_source` (abspath R1, entry check LLR-172.1l, `mkdir(parents=False)` R7, link check after mkdir, "could not be read" → no write LLR-172.1k, normcase de-dup, `mkstemp` + `os.replace`, staging unlink, debug-only logging S6, no lock R8), `list_workarea_files` (temp link check R11, `scandir` + two gates, `OSError` → `[]`, `(casefold, name)` sort).
- `app.py` — `_typed_load_route` steps 0–11 (step 0 `Path(text).is_absolute()`, lexical `abspath`, link walk, listing match on `normcase` returning the on-disk name R3, §1.3 test; old step 10 absent R13), the dispatcher's 6 status lines (character-for-character against the "Status lines" table), `_handle_load_project` listing step after `_project_folder_refusal` and `exists()`, `refresh_files` through the lister (no `WORKAREA_TEMP` enumeration left in `app.py`, S8).

### Implementer-declared deviations — rulings

| Source | Deviation | Ruling |
|---|---|---|
| G1 dev. 1 | read debug line prints `problem=none` on success | Accept — DEBUG, no path text (LLR-172.3 / R-9 hold). |
| G1 dev. 2 | `_encode_recent_store([])` returns the 32-byte empty document, not `b""` | Accept — unreachable from `record_recent_source` (step 4 always yields ≥ 1 entry); the graph does not define the empty input. |
| G2 dev. 1 | step (7) `S_ISDIR` test skipped when `parts` is empty (`W`, `W\`) | Accept — falls to step (8) `not a project`, the graph's own pinned example. |
| G2 dev. 2 | extra `logger.warning` on the `list_projects()` `OSError` arm of `_handle_load_project` | Accept — consistent with sibling refusals; logs the name only to the app log (LLR-172.3 excludes `.s19tool/logs/`). |
| G2 dev. 3 | `PROJECT_MANIFEST_NAME` instead of the literal `"project.json"` | Accept — same value, file convention. |

## 2. Test re-pins

| # | Test | Change | Why (the test contradicted the graph/requirement) |
|---|---|---|---|
| RP1 | `tests/test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement` (allow-list `_FINAL_NAME_ALLOWLIST`, `tests/test_b99_staging.py:2048-2060`) | `"record_recent_source"` added to the `s19_app/tui/workspace.py` allow-list, with a 5-line comment citing LLR-172.1h / LLR-172.1i. No assertion changed, no positive control touched (the census still finds 2 hits in its restored-style sample and 1 in the `write_text` sample). | The census is a syntactic proxy for LLR-155.3, whose invariant is "no code path **inside the work area** replaces or deletes a file at a final name except the placement" (`.dev-flow/2026-10-25-batch-99/01-requirements-ledger.md:91`). LLR-172.1h **requires** `record_recent_source` to replace the store through a unique staging file and `os.replace`, and LLR-172.1i requires it to remove its own staging file on failure. The store lives under `%LOCALAPPDATA%`, outside every work area, so neither call is inside LLR-155.3's scope. Without the re-pin the test is RED for a call the graph mandates (`workspace.py:2503 os.replace`, `:2514 unlink`). **Design gap, not an implementer fault:** neither graph, E1's census nor E3 listed TC-B99-13 among the tests the new writer reaches. Before the re-pin: RED (first green-02 run). After: `1 passed` (alone). |

No other test changed. No assertion was weakened.

## 3. Seam rulings

| Seam | Ruling at integration |
|---|---|
| S1 record after copy | Holds in both loads (call after `copy_into_workarea`, before `_start_load_worker` / `refresh_files`). |
| S2 inside test = caller | Holds (`contained_in_workarea(normalized, self.workarea)` in G2; none in G1). |
| S3 lister returns `Path`s | Holds (`.name` for label and `item.data`). |
| S4 `None` store path | Holds (G2 never calls `recent_store_path`; `False` → 1 warning, 0 status lines). |
| S5 problem words | Exported by G1; 0 consumers in `app.py` at 9a (as designed). |
| S6 who logs | Holds: G1 logs DEBUG only, G2 exactly 1 WARNING on `False`. mut-int-05 and mut-int-12 RED. |
| S7 record argument | Holds (`normalized`; G1 stores `os.path.abspath`). mut-int-03 RED. |
| S8 census shape | Holds (only `list_workarea_files` enumerates `temp`). mut-int-09 RED. |
| S9 `LOCALAPPDATA` at call time | Holds (`os.environ.get` inside `recent_store_path`). Not mutated: an import-time cache mutant would read the operator's real `%LOCALAPPDATA%` at collection, before the C8 fixture, and could write the real store — the tester's own node pins it. |
| S10 every routed suffix has a kind | Holds (`recent_kind` maps `SUPPORTED_EXTENSIONS ∪ A2L_EXTENSIONS`). |

## 4. GREEN runs

All runs used cwd = the worktree, `env -u NO_COLOR`, and `LOCALAPPDATA` set to a scratch folder. Each transcript header prints the cwd, both source shas and `s19_app.__file__`.

| Transcript | Content | Result | Status |
|---|---|---|---|
| `evidence/inc-9a/green-01-new.txt` | `tests/test_b100_recents.py` after integration (R14 added), sources `a3342ed048ebe157` / `6223201188232562` | 141 passed, 226.6 s | integration GREEN (pre-E5) |
| `evidence/inc-9a/green-02-touched.txt` | the 33 touched modules, integration state | transcript ends at 36 %, no summary line | **superseded**, no result claimed |
| `evidence/inc-9a/green-03-recents.txt` | `tests/test_b100_recents.py` in full after the E5 corrective pass, sources `0af4b92489233ff2` / `bbf04117fbf0d3f5` | **157 passed**, 0 skipped, 0 failed, 251.6 s | **final** |
| `evidence/inc-9a/green-04-targeted.txt` | the new or changed arms outside the recents module: `tc_b100_33` (4 arms), `tc_b99_13` (the RP1 re-pin), `test_id_registry` tc607 and tc600–tc603 | **10 passed**, 14.1 s | **final** |
| `evidence/inc-9a/guards-02.txt` | the guards-01 command | **75 passed**, 29 snapshots passed, 129.4 s | **final** (guards-01: 75 passed) |

The touched-module run was deferred to the batch-end battery by operator override (2026-10-31); failures found there get fix rounds. A `green-04-touched` run had been started. It was stopped on the override, and its partial transcript was deleted. E5 RED and mutant evidence: `red-02-corrective.txt` and `mut-c-*.txt` (13 KILLED), summarised in `E5-corrective-notes.md`.

## 5. Integration sanity mutants (13 of 13 RED)

Run in a **copy** of the worktree (`scratchpad/int9a/mutwt`, made with `tar` minus `.git`, `.dev-flow`, `__pycache__`; every transcript prints `s19_app.__file__` inside the copy). The worktree was never mutated. Before each run the copy's file was byte-copied; after each run it was restored and its sha256 compared (all 13: `restored OK`, app.py `6223201188232562`, workspace.py `a3342ed048ebe157`). The copy was deleted afterwards. Transcripts: `evidence/inc-9a/mut-int-01.txt` … `mut-int-13.txt`.

| Id | File | Mutant | Node(s) run | Result (RED reason) |
|---|---|---|---|---|
| 01 | app | R14: `list_projects` skips only a trailing space | `tc_b100_38_project_list_skips_…` | 1 failed / 1 passed — `['ab', 'temp.']` |
| 02 | app | R14: skips only a trailing dot | same | 1 failed / 1 passed — `['ab', 'ab ']` |
| 03 | app | S7: `load_from_path` records `copied` | `tc_b100_34_outside_load_records_the_source_not_the_work_copy` | 1 failed — stored path is the work copy |
| 04 | app | S2: inside test removed in `load_from_path` | `tc_b100_34_source_inside_the_work_area_is_not_recorded` | 1 failed — inside arms recorded |
| 05 | app | S6: no warning on `False` in `load_from_path` | `tc_b100_34_failed_store_write_never_fails_the_load` | 2 failed / 2 passed (data arms) — warning delta `(0, 0)` |
| 06 | app | S1: `load_a2l_from_path` never records | `…never_fails_the_load`, `…record_puts_newest_first_with_its_kind` | 2 failed / 3 passed (a2l arms) — "the control load wrote no store" |
| 07 | app | R4: label `safe_text(path.name)` without `painted_names` | `tc_b100_39_rows_paint_names_literally` | 3 failed / 4 passed — U+202E kept, U+DC80 kept, no 120 clip |
| 08 | app | C5: `item.data = painted_names([...])` | `tc_b100_39_picked_row_loads_the_file_as_named` | 3 failed / 1 passed — U+009B, U+202E, 130-char picks load nothing |
| 09 | app | S8: `refresh_files` keeps its own `temp_dir.glob` | `tc_b100_37_one_function_enumerates_the_temp_folder` | 1 failed — census finds `app.py::refresh_files` |
| 10 | app | R3: `_handle_load_project` loads the asked spelling | `tc_b100_38_project_load_of_another_case_loads_the_listed_name` | 1 failed — `current_project == 'AB'` |
| 11 | app | R2: step 0 `os.path.isabs` | `tc_b100_38_typed_relative_folder_is_refused` | 1 failed / 2 passed — root-relative path loads `ab` |
| 12 | workspace | S6: record logs a WARNING on a failed write | `…never_fails_the_load` | 4 failed — 2 warnings instead of 1 |
| 13 | workspace | LLR-172.1k: unreadable store overwritten | `tc_b100_34_unreadable_store_is_left_unchanged` | 2 failed — open-refused and read-failed arms |

S9 (import-time cache of `LOCALAPPDATA`) was deliberately not mutated: at collection time that cache would hold the operator's real `%LOCALAPPDATA%`, before the C8 fixture runs, and a record could write the real store.

## 6. Final hashes

PENDING.

## 7. Assessment

PENDING.
