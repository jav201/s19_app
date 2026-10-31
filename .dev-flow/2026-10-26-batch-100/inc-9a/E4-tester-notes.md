# Inc 9a — E4 tester notes

Author: tester (independent of the G1 / G2 implementers; no source file read from the in-flux worktree, no test run in the worktree). Base for RED: `4fef292` (scratch tree `base9a`, detached; test files copied in, nothing committed there).

## What was written

| File | Change |
|---|---|
| `tests/test_b100_recents.py` | new — 141 collected nodes (65 test functions, parametrized) |
| `tests/conftest.py` | C8: session-scoped autouse guard (records the real `%LOCALAPPDATA%\s19_app\recent_sources.json` SHA-256 or its absence, points `LOCALAPPDATA` at a session temp folder for every session/module/class fixture, fails the session if the real store changed — LLR-172.1's "1 guard", LED .41) + function-scoped autouse fixture (`LOCALAPPDATA` = a fresh existing folder from `tmp_path_factory.mktemp("lad")`, outside the test's own `tmp_path`, so no existing test's folder listing changes) |
| `tests/test_id_registry.py` | `EXPECTED_SCANNED_TEST_FILES` 227 → 228, measured (`scanned_test_files()` → 228 in `base9a` with the new file present) |

Fixture reach: `tests/conftest.py` is the only conftest; every collected test lives under `tests/`. `.dev-flow/**/test_*.py` probe files are outside it, but pytest's default `norecursedirs` (`.*`) keeps them out of a bare `pytest -q` (CI's command). No test builds its own subprocess environment (`grep -rn "env=" tests` → 0, per G2), so subprocess-based tests inherit the patched variable. Sample run with the new conftest at `base9a`: `tests/test_b99_load_project.py`, `tests/test_loadfilescreen_input.py` and `tests/test_b100_project_homes.py -k tc_b100_62` → 46 passed; `tests/test_id_registry.py` → 13 passed (G1–G7 and the 228 bound). The full suite was NOT run with the new conftest (orchestrator's gate run, C-25).

## Node count per requirement

| Requirement | Nodes | Of which Windows-only |
|---|---|---|
| LLR-172.1 (+ S9) | 1 | 1 |
| LLR-172.1f | 11 (6 pure `recent_store_path` arms + 5 load arms) | 1 (absent folder) |
| LLR-172.1a / .2h (`recent_kind`) | 13 | 0 |
| LLR-172.1a (record, app) | 4 | 4 |
| LLR-172.1b | 2 | 2 |
| LLR-172.1c | 1 | 1 |
| LLR-172.1d (+ Q1 declared arm) | 2 | 2 |
| LLR-172.1e | 1 | 1 |
| LLR-172.1g | 1 | 1 |
| LLR-172.1h | 1 | 1 |
| LLR-172.1i (unit 2, load 4, NUL 1) | 7 | 7 |
| LLR-172.1j | 1 | 1 |
| LLR-172.1k | 2 | 2 |
| LLR-172.1l | 1 | 1 |
| LLR-172.1m | 1 | 1 |
| HLR-172 (25 loads) | 1 | 1 |
| LLR-172.2 | 1 | 0 |
| LLR-172.2a | 1 | 0 |
| LLR-172.2b | 9 | 0 |
| LLR-172.2c | 4 | 1 (junction) |
| LLR-172.2d | 1 | 0 |
| LLR-172.2e / .2f / .2g | 3 | 0 |
| LLR-172.2h | 1 | 0 |
| LLR-172.2i (+ .2j malformed arm) | 1 | 0 |
| LLR-172.2j | 1 | 0 |
| LLR-172.3 (read arm 1 + 2 end-to-end arms) | 3 | 3 |
| LLR-172.4 (census) | 1 | 0 |
| LLR-172.4a | 2 | 0 |
| LLR-172.4b | 1 | 0 (skips where no file symlink can be made) |
| LLR-172.4c | 7 | 2 (junction) |
| LLR-172.5 | 4 | 2 (case) |
| LLR-172.5a | 3 | 1 (case) |
| LLR-172.5b | 9 | 4 (case, stream, 8.3, trailing dot) |
| LLR-172.5c | 4 | 0 |
| LLR-172.5d | 3 | 3 |
| LLR-172.5e | 3 | 0 |
| LLR-172.5f | 2 | 0 |
| LLR-172.5g (6 + control) | 7 | 5 |
| E3 R14 (`list_projects` trailing dot / space) | 2 | 2 |
| LLR-172.5h | 3 | 2 (junction, root-relative) |
| LLR-172.6 | 7 | 0 (surrogate arm skips where the name cannot be made) |
| LLR-172.6a | 4 | 0 |
| AT-B100-12 | 2 (118, 220 columns) | 2 (store half) |
| AT-B100-13 | 2 (118, 220 columns) | 0 |
| **Total** | **141** | **54** |

On the Linux CI 54 nodes skip with a named reason (reported not run, never passed); 87 run. On this Windows machine 0 skipped (file symbolic links and 8.3 names were available).

## RED on base

Transcript: `.dev-flow/2026-10-26-batch-100/evidence/inc-9a/red-01-vs-base.txt` — one complete run, `s19_app.__file__` = `<scratchpad>\base9a\s19_app\__init__.py`. The command is the prescribed one plus `-rA` (per-node summary), stated in the header.

**135 failed, 6 passed, 0 skipped, 0 errors** in 210 s.

- **71 nodes RED by ImportError of a new 9a symbol inside the node** (new-function nodes, expected): `record_recent_source` 21, `read_recent_sources` 24, `recent_kind` 13, `recent_store_path` 7, `list_workarea_files` 6. Per id: TC-B100-34 41, TC-B100-35 23, TC-B100-36 1, TC-B100-37 6.
- **64 nodes RED on a behavioural assertion**: TC-B100-34 9 (no store written by the load: the `outside load`, `load failing before its copy` control, `copies then fails`, `inside` control, 4 × `never fails the load` control, 25 loads), TC-B100-36 1 (store does not hold the loaded source), TC-B100-37 3 (census finds `app.py::refresh_files`; `l.s19` link listed; junctioned `temp` lists `z.s19`), TC-B100-38 40 (`Unsupported file type: …`, `File not found: …`, `Loaded project 'temp'` / `'TEMP'` / `'temp::$INDEX_ALLOCATION'` / `'TEMPLA~1'` / `'temp.'` / `'AB'`, `patches` → `has no project.json`, `list_projects` lists `temp.` and `ab `), TC-B100-39 7 (bold / link / action markup applied; U+009B, U+202E, U+DC80 painted; no clip), AT-B100-12 2 (store empty), AT-B100-13 2 (markup applied).
- **6 nodes pass at base**:
  - `tc_b100_39_picked_row_loads_the_file_as_named[×4]` — declared by LLR-172.6a ("on `4fef292` the row holds `item.name`, so the mutation is the only RED"): M78.
  - `tc_b100_37_unlistable_temp_shows_no_rows[temp removed]` — declared by LLR-172.4c (`glob` returns nothing for a missing folder): M59 is its RED.
  - `tc_b100_37_unlistable_temp_shows_no_rows[listing refused]` — **not declared by the requirement**: at base `Path.glob("*")` swallows the injected `PermissionError` (pathlib's selector catches it), so `refresh_files` already shows 0 rows and raises nothing. Only a mutant of the new lister (M59, catch removed) makes it RED. The requirement's note for LLR-172.4c should say so (finding for the orchestrator; no test change).

Post-RED edit (declared): `tc_b100_34_record_with_an_embedded_nul_never_raises` gained the `STORE_WRITE` skip marker after the full run (off Windows the store is off before `abspath` runs, so the node would pass vacuously there). The marker is inactive on win32; the node was re-run alone on base after the edit → 1 failed (ImportError), same as in the transcript.

## Design choices that touch the oracles

- Store bytes in fixtures are written by the test (`json`, compact, `ensure_ascii`), never by the code under test; store reads in assertions use `json.loads`.
- "0 staging files" = the store folder holds nothing but `recent_sources.json`. "Unique staging name in the store folder, replaced in one step" is observed on `os.replace` (source names, their folder, the target) instead of a spy on `mkstemp`, so any staging-creation API passes as long as the requirement holds.
- The staging-creation failure (LLR-172.1i) is injected by patching `tempfile.mkstemp` (and `workspace.mkstemp` if the name is imported) — the interface names `mkstemp`. If G1 creates the staging file another way, those 3 nodes would fail for a test reason: tester's to repair.
- The open / read failures (LLR-172.1k, LLR-172.2c) and the read-size spy (LLR-172.2a) wrap `builtins.open` and `io.open` (`Path.open` goes through `io.open`), acting only on read opens of the store. A reader that used `os.open` / `os.read` would escape the spy: the 2a node then fails with "no read of the store was observed" (a test-side signal, not a pass).
- "1 log warning" (LLR-172.1i) is measured as a delta: warnings during the failing load minus warnings during a control load in the same session, from the `s19tui` logger and the root logger. The warning text is not pinned.
- "0 spans" counts spans with a non-empty style only (a plain `safe_text` label may carry an empty-style span).
- Project `ab` comes from the shipped Save project (LED .42), built once per module with `LOCALAPPDATA` pointed at a folder that does not exist (records nothing, R7), then copied per test.
- Status oracles are the token pairs of `01-requirements.md` §3; full lines are not pinned except `Loaded project` + `'ab'`.

## Examples not turned into tests, and why

| Example (source) | Why not |
|---|---|
| `_encode_recent_store` exact byte counts (65, 65 492, 62 314) — G1 | Private helper; the observable thresholds (entries kept, file ≤ 65 536) are asserted through `record_recent_source`. The 20 × 3 240 arm still fails a non-compact encoding (it would exceed the cap and keep 19). |
| `recent_store_path` with `C:/t/lad` → a path — G1 (LLR-172.1f D-1) | Not covered: a forward-slash drive root as `LOCALAPPDATA`. Uncovered arm, named. |
| Q1 call-order spies (`copy_into_workarea` → `record_recent_source` → `_start_load_worker`) — G2 | Internal call sequence (anti-mirror). The observable halves are covered: over-cap arm records nothing (M18), copied-then-unparseable source is recorded (M19), the work copy is never recorded (M11). |
| `record_recent_source` spy "0 calls" for inside / failed loads — G1, G2 | Replaced by the store on disk (entries / SHA-256) plus a positive control in the same node. |
| A2L that copies and then fails to parse is recorded (Q1, A2L side) — G2 | Not covered; the data-file arm is. Uncovered arm, named. |
| LLR-172.1k "through Load" and LLR-172.1l "through Load" (typed UNC source) — G2 | Unit arms only. The UNC through-Load arm needs a reachable share (not available: not run). |
| "1 debug line each" on skips / failures — G1 | Debug logging is not a requirement threshold. |
| Start-up `load_path` recorded (Q2) and a start-up project path opening the panel (R-1) — G2 | Not covered (ruled behaviour, no requirement threshold). |
| Typed refusal painting `<tmp>/[bold]<U+202E>x` (literal, no Cf) — G2 | Not covered: no requirement threshold for the typed-path painting at 9a (the §3 tokens are asserted). Uncovered example, named. |
| `_typed_load_route` unit examples (return tuples, "0 `lstat` calls", "0 calls of `list_projects`") — G2 | Private classifier; every arm is driven through the shipped dispatcher instead. The "0 lstat / 0 list_projects" counts for LLR-172.5h are not asserted. |
| `W/locked` (listing refused) → `could not be read`; `list_projects` raising → `unreadable` — G2 | Token row exists from 8b; no 9a requirement threshold. Not covered. |
| A2L-only project typed → loads (8b HLR-171a) — G2 | 8b behaviour, covered by TC-B100-32 tests through the project load; not re-tested on the typed route. |
| 8.3 name of a project (`ABCDEF~1`) refused (R-10, declared) — G2 | Declared fail-closed behaviour, no threshold. Not covered. |
| `_handle_load_project` order kept (link / outside / not-found tokens before the listing step) — G2 | Already pinned by the 8b TC-B100-62 nodes, which must stay green. |
| U-3 case-folded order (`B.s19`, `a.hex` → `a.hex`, `B.s19`) — G1 | LLR-172.4a says "sorted by name" without a case rule (ambiguous): not asserted. The asserted names agree under both orders. Ambiguity for `qa-reviewer` if a case rule is wanted. |
| C7 `x.a2l.json` listed beside `x.a2l` — G1 | Scope note (today's file set kept), no threshold. |
| `_is_reparse_point` / `is_windows_device_name` "holds" examples — G1 | Unchanged context nodes, already tested by earlier batches. |
| LLR-172.2c through a real sharing violation (`held_exclusively`) | The requirement says "injected"; and a real exclusive lock also blocks `os.replace`, which would let the LLR-172.1k mutant survive. Injection used. |

## Environment limits

- Store write arms, the AT-B100-12 store half, case-spelling, Win32-name, junction and root-relative arms: Windows only (54 nodes skip on Linux, each with its reason). On Linux the read arms pin the store location by patching `recent_store_path`.
- File symbolic-link arms (LLR-172.2c, LLR-172.4b) skip where the platform refuses the link; the 8.3 arm skips where the volume makes no 8.3 names; the surrogate-name arm skips where the name cannot be created. None skipped here.
- No mapped SMB drive: the `resolve()` → UNC outcome of R-6 / A9-1 is not run (the junction arm is the executed RED for that mutant, M10).
- Nothing was run in the worktree (sources in flux). GREEN is not claimed; no mutant has been executed (`E4-mutants.md`, all `planned`).
