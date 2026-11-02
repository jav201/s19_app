# Increment 017 — Inc 9a · HLR-172 / HLR-172a / HLR-172b / LLR-172.x · recent-sources store, one work-area lister, typed-path route, literal names

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `009a` |
| Lane | `main` · 2 SOURCE files (`app.py`, `workspace.py`), within the 4-file cap |
| Requirement(s) | `HLR-172` · `HLR-172a` · `HLR-172b` · `LLR-172.1`–`LLR-172.1m` · `LLR-172.2`–`LLR-172.2k` · `LLR-172.3` · `LLR-172.4`–`LLR-172.4d` · `LLR-172.5`–`LLR-172.5h` · `LLR-172.6`/`LLR-172.6a` (LLR-172.1k/.1l/.1m/.5h are new in E3, LLR-172.4d and LLR-172.2k are new in the E5 corrective pass) |
| Acceptance | `AT-B100-12` (HLR-172 store half + HLR-172a typed half) · `AT-B100-13` (HLR-172b) · `TC-B100-34` (LLR-172.1…) · `TC-B100-35` (LLR-172.2…) · `TC-B100-36` (LLR-172.3) · `TC-B100-37` (LLR-172.4…) · `TC-B100-38` (LLR-172.5…) · `TC-B100-39` (LLR-172.6/.6a) — all in `tests/test_b100_recents.py` |
| Interfaces | consumes `contained_in_workarea`, `_is_reparse_point`, `is_windows_device_name`, `resolve_input_path`, `RESERVED_WORKAREA_HOMES`, the loader extension sets, `painted_names`, `safe_text`, `_project_folder_refusal`, `list_projects`, `_route_load_project`, `_handle_load_project`, `_load_from_item`; adds `recent_store_path`, `recent_kind`, `_recent_entry_ok`, `read_recent_sources`, `_encode_recent_store`, `record_recent_source`, `list_workarea_files`, `RecentEntry`, `RecentSources` and the `RECENT_*` constants to `workspace.py`; adds `_typed_load_route` and changes `refresh_files`, `_handle_load_project`, `list_projects`, `_load_path_from_user_input`, `load_from_path`, `load_a2l_from_path` in `app.py` |
| Agent | design-first experiment (`inc-9a/`): E1 requirements · E2 Code-Wire prototype (graph only) · E3 code-free design review (architect 2 rounds, security 2 rounds) · E4 parallel build (2 DeepSeek implementers + tester) · E5 change validation (79 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass). Models per stage in the step table below |
| Date | `2026-10-31` (E1 start 07:43:34Z through the close records 14:30Z, all UTC) |
| Base | `4fef292` (Inc 8b final); tree uncommitted at the time of writing |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-172 / HLR-172a / HLR-172b).** When Load copies an outside data or A2L file into the work area, its absolute path is remembered in a per-user store; a typed absolute project path loads that project through the same route a pick uses; the Workarea Files list renders every on-disk name literally.

- **HLR-172 — recent sources are remembered per user.** `record_recent_source` runs on the UI thread in `load_from_path` / `load_a2l_from_path`, after the copy and before the worker / `refresh_files`, only for a source outside the work area (LLR-172.1, .1a, .1d, .1e). The store lives at `%LOCALAPPDATA%\s19_app\recent_sources.json` (LLR-172.1, .1f); one entry per `normcase(abspath)` path, newest first, at most 20 (LLR-172.1b, .1c); a unique staging name then one `os.replace`, never raising (LLR-172.1h, .1i, S-12); the write carries over only the entries the read accepts, leaves an unreadable store unchanged, and refuses a path the read would drop (LLR-172.1j, .1k, .1l); the file it writes fits the read's 65 536-byte cap (LLR-172.1m). `read_recent_sources` makes one bounded `read(65 537)`, checks the shape and each entry, and never raises (LLR-172.2 … .2j, .2k). No store entry reaches any file under the base folder (LLR-172.3).
- **HLR-172a — a typed project path opens the project.** `_typed_load_route` runs the absolute test on the stripped text (step 0), walks `lstat` on every prefix before any resolve, matches the typed component against one `list_projects` listing (normcase) and routes the on-disk name, then `_load_path_from_user_input` dispatches `project` → `_route_load_project`, `a2l`/`data` → the loaders, `refuse` → one six-reason status line (LLR-172.5 … .5f, .5h). `_handle_load_project` gains the same listing-match step after `_project_folder_refusal` and `exists()` (LLR-172.5g).
- **HLR-172b — work-area file names render literally.** `refresh_files` now enumerates `temp` through the one new `list_workarea_files` (regular, non-link direct children, sorted, `[]` on missing/unlistable/linked — LLR-172.4, .4a, .4b, .4c) and paints each label through `painted_names` + `safe_text` with markup off, `item.data` keeping the on-disk name (LLR-172.6, .6a; R4/R17). The E5 pass adds the trailing-dot/space skip (LLR-172.4d).

**Corrective pass (E5).** 11 fix rows + 5 weak-test survivors, one pass (`inc-9a/E5-corrective-notes.md`). SEC9-1 → `list_workarea_files` skips a name ending in a dot or space (new LLR-172.4d); SEC9-3/SEC9-4 → `_recent_entry_ok` refuses `<>:"|?*` after the drive prefix and any Cf/Zl/Zp/Cs character (new LLR-172.2k, one check for read and record); CR9-3 → the data/A2L decision uses the loader's suffix; CR9-6 → four `OSError → could not be read` arms tested; CR9-9 → the R14 skip gated on `os.name == "nt"`; SEC9-5 (part) → the `mkstemp` descriptor closed when `fdopen` raises; SEC9-7 → the session guard also compares the names in the real store folder; CI `tc_b100_33[upper case]` → skipped unless `os.name == "nt"`. CR9-4/CR9-10 corrected two docstrings; M19/M57/M61/M64/M65 got direct arms (M19's input replaced, M57 a reverse-order `scandir` spy, M61/M64/M65 direct `_typed_load_route` calls). Equivalent mutants M21, M24, M28, M42 are recorded, not fixed.

**Process decision (operator ruling, carried from Inc 8a, LED .75).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. **New operator override (2026-10-31):** the touched-module run is deferred to the batch-end battery, and failures found there get fix rounds — so `green-02-touched.txt` is superseded and was not re-run after the corrective pass (see §4).

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/workspace.py` | source | HLR-172 · LLR-172.1/.1a–.1m · LLR-172.2/.2a–.2k · LLR-172.3 · LLR-172.4/.4a–.4d | `recent_store_path`, `recent_kind`, `_recent_entry_ok`, `read_recent_sources`, `_encode_recent_store`, `record_recent_source`, `list_workarea_files`, `RecentEntry`, `RecentSources`, the `RECENT_*` constants; `import json`, `PureWindowsPath`, `unicodedata`. Final sha256[:16] `0af4b92489233ff2` |
| `s19_app/tui/app.py` | source | HLR-172 · HLR-172a · HLR-172b · LLR-172.1a/.1d/.1e/.1i · LLR-172.4/.4a/.4c · LLR-172.5/.5a–.5h · LLR-172.6/.6a | `refresh_files` (lister + `painted_names`/`safe_text` label), `_handle_load_project` (listing step after `_project_folder_refusal`), `list_projects` (R14 dot/space skip, `os.name == "nt"` gate), `_typed_load_route` (NEW, steps 0–11), `_load_path_from_user_input` (dispatcher + six status lines), `load_from_path` / `load_a2l_from_path` (record calls). Final sha256[:16] `bbf04117fbf0d3f5` |
| `tests/test_b100_recents.py` | test | HLR-172/172a/172b · LLR-172.1…–172.6a · AT-B100-12/13 · TC-B100-34…39 | NEW module: 141 nodes at E4 (54 Windows-only), 157 after the E5 arms (the 16 new arms of LLR-172.4d, LLR-172.2k, CR9-6/CR9-9/SEC9-5, M19/M57/M61/M64/M65) |
| `tests/conftest.py` | fixture | HLR-172 · LLR-172.1 | C8: a session-scoped autouse guard for the real `%LOCALAPPDATA%\s19_app` (digest + folder name set, SEC9-7) and a function-scoped `LOCALAPPDATA` fixture at a fresh folder outside each test's own `tmp_path` |
| `tests/test_b99_staging.py` | test | LLR-172.1h/.1i | RP1: `record_recent_source` added to the `_FINAL_NAME_ALLOWLIST` (the store lives outside every work area, so outside LLR-155.3's scope) |
| `tests/test_b100_project_homes.py` | test | LLR-172.5 | CI fix: `tc_b100_33[upper case]` skipped unless `os.name == "nt"` ("needs a case-insensitive file system") |
| `tests/test_id_registry.py` | config | HLR-172 | `EXPECTED_SCANNED_TEST_FILES` 227 → 228 (measured) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | LLR-172.4d/.6 | orchestrator-owned: scenario `wa-files` (closed-panel only) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-172/172a/172b | E1 / E3 / E5 edits (LED .82–.84); R16 alignment and the .85 back-pointer at close |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-172/172a/172b | LED .82 – .85 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-172/172a/172b | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-9a/*` | doc | HLR-172/172a/172b | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-017.md` | doc | HLR-172 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-9a/*` | generated | HLR-172 | transcripts (evidence digest table at the end of §4) |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# new and modified requirement tests (the recents module):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_recents.py
# the new or changed arms outside the recents module (targeted):
python -m pytest -q -p no:cacheprovider tests/test_b100_project_homes.py -k tc_b100_33 \
  tests/test_b99_staging.py -k test_tc_b99_13 tests/test_id_registry.py -k "tc607 or tc600 or tc601 or tc602 or tc603"
# guards:
python -m pytest -q -p no:cacheprovider tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py \
  tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py
# mutants: evidence/inc-9a/mutation-summary.md (79 rows) + mut-int-*.txt (13 integration) + mut-c-*.txt (13 corrective)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-9a/`. **Final source hashes** (sha256[:16], printed in the header of every post-E5 transcript): `workspace.py` `0af4b92489233ff2` · `app.py` `bbf04117fbf0d3f5`. Pre-E5 (E4 integration) hashes: `a3342ed048ebe157` · `6223201188232562` (the E4-G2 hand-off was `559ef0a79aab2ce1` before integration's R14 edit). Base `4fef292`. Import proof in every header: the worktree's `s19_app\__init__.py`; `NO_COLOR` unset.

**Scope (operator ruling, carried from Inc 8a, LED .75; amended by the 2026-10-31 override):** new and modified requirement tests, the modules that exercise the changed functions, and the guards. The touched-module run (33 modules, `green-02-touched.txt`) was **started, then stopped on the override at 36 % with no failure printed, and its partial transcript deleted; it was not re-run after the corrective pass** — the batch-end battery owes it, and failures found there get fix rounds. `green-01-new.txt` (141 passed on the pre-E5 integration bytes) is superseded by `green-03-recents.txt` (157 passed on the final bytes). No reverse census, no full suite.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-34 (LLR-172.1…) · TC-B100-35 (LLR-172.2…) · TC-B100-36 (LLR-172.3) · TC-B100-37 (LLR-172.4…) · TC-B100-38 (LLR-172.5…) · TC-B100-39 (LLR-172.6/.6a) — `tests/test_b100_recents.py` | `executed` — final `green-03-recents.txt`: **157 passed, 0 skipped, 0 failed** (251.6 s). Pre-E5 `green-01-new.txt`: **141 passed** (226.6 s, superseded). `green-04-targeted.txt` (the new/changed arms outside the recents module): **10 passed** (14.1 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-12 (store half + typed half), AT-B100-13 (literal names) | `executed`: AT-B100-12/13 in `green-01-new.txt` (141) and `green-03-recents.txt` (157); RED `red-01-vs-base.txt` 135 failed, 6 passed vs base |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's nodes vs base `4fef292` (141 nodes) | `red-01-vs-base.txt` | **135 failed, 6 passed, 0 skipped, 0 errors** (210.5 s, run in the `base9a` scratch tree). 71 RED by `ImportError` of a new 9a symbol (expected: new-function nodes), 64 RED on a behavioural assertion, 6 pass at base by declaration (LLR-172.6a's 4 pick nodes, LLR-172.4c's missing-temp arm, and the `listing refused` arm whose base pass was later declared in the CR9-10 docstring fix) |
| E5 corrective arms on the pre-fix snapshot | `red-02-corrective.txt` | **7 failed, 23 passed** of the 30 new/changed nodes, each RED for its behavioural reason (SEC9-5 staging file left, SEC9-3/SEC9-4 7 records `True` + 8 entries read, SEC9-1 two dot/space rows listed, CR9-3 `Unsupported file type: ` without the LLR-172.5e tokens, CR9-9 off-Windows `fw-v1.` listed); the 23 passes declared (docstring-only, or existing arms of an extended node) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the per-user store | `red-01-vs-base.txt` fails on base: no store file is written by a load (code read `grep -rn LOCALAPPDATA s19_app` → 0 hits); each behavioural node has its own mutant in `mutation-summary.md` |
| the read's bounds | M37 (`>=` vs `>` at 65 536), M38 (`stat` then unbounded `read`), M51 (only `ValueError` caught), M52 (no decode guard) are KILLED |
| the entry checks | M46–M50 (drive-root, device, control, kind, shape) KILLED; the E5 SEC9-3 check is killed by `mut-c-SEC9-3` (the check removed → 8 entries read / 7 records `True`) |
| the lister | M55 (a second enumeration), M56 (recursion), M57 (no sort — re-killed by `mut-c-M57` with a reverse `scandir`), M58 (`is_file` follows links), M59/M60 (the `OSError`/link gates) |
| the typed route | M61/M64/M65 were masked by `_handle_load_project`'s second check and re-killed in E5 by `mut-c-M61`/`M64`/`M65` with direct `_typed_load_route` calls; M73/M74 (`os.path.isabs` / step 0 removed) RED |
| the label | M75 (markup on), M76 (`safe_text` only), M77 (no clip) KILLED; `mut-int-07` (no `painted_names`) 3 failed, `mut-int-08` (`item.data` = painted label) 3 failed |

### Mutation verdicts (C-40)

**E5 run on the 9a tree (`mut9a` copy)** (`mutation-summary.md`; every transcript ends `restored = True`): **79 rows total. 70 KILLED, 9 SURVIVED, 0 INVALID.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 70 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, equivalent | M24, M28, M42 (an inner `except` removed is caught by the outer never-raise guard with the same result) | recorded, no code change (`E5-rulings.md`) |
| SURVIVED, equivalent under test | M21 (the write-side link check after `mkdir` is masked by the read-side check of `store.parent`; kept as a race guard) | recorded, declared |
| SURVIVED, weak test | M19 (the old `bad.s19` installed with 2 errors, so the node could not tell "record after copy" from "record after install"), M57 (`os.scandir` already returned NTFS-sorted order) | fixed in E5: M19's input replaced with bytes that raise `UnicodeDecodeError` in both UTF-8 and cp1252 (`mut-c-M19` KILLED); M57 a reverse-order `scandir` spy (`mut-c-M57` KILLED) |
| SURVIVED, wrong target | M61, M64, M65 (the route's own listing match / reserved-home step / on-disk name masked by `_handle_load_project`'s second check) | fixed in E5 with direct `_typed_load_route` arms (`mut-c-M61`/`M64`/`M65` KILLED) |

**Integration sanity mutants (`mut-int-01`…`mut-int-13`, run in a `scratchpad/int9a/mutwt` copy): 13 of 13 RED**, all `restored OK`. **E5 corrective mutants (`mut-c-*.txt`, 13): 13 KILLED / 0 SURVIVED.** The 79 E5 mutants ran on the pre-E5 bytes (`a3342ed048ebe157` / `6223201188232562`); the 13 corrective mutants cover what E5 changed, on the final bytes.

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| `recent_sources.json` | written by the test, read with `json.loads`; `schema_version` is `1` (exact int, `type(v) is int`), `sources` is a list of `{path, kind}` objects; ≤ 65 536 bytes, at most 20 entries, newest first |
| the store replace | observed on `os.replace` (source names, their folder, the target), 0 staging files left; a read after each of 100 records parses as version 1 (0 partial files) |
| the Workarea Files rows | `Label(safe_text(painted_names([name])))` — 0 markup spans, 0 Cc/Cf/Zl/Zp/Cs characters, `item.data` keeps the on-disk name |
| the status lines | the six typed-refusal lines reproduce the §3 "Status lines" table character for character (em-dash, exact tokens) |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards on the integration bytes | `guards-01.txt` | **75 passed; 29 snapshots passed** (178.1 s) |
| guards on the final bytes | `guards-02.txt` | **75 passed; 29 snapshots passed, 0 snapshot cells changed** (129.4 s) |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer ran a targeted recents slice → **49 passed, 92 deselected**, plus scratch probes (CR9-1 junction-follow, CR9-2 8.3 spelling, CR9-3 trailing dot, CR9-8 NUL) each with `LOCALAPPDATA` to its own scratch folder. The security reviewer ran the full recents module → **141 passed in 269.08 s, 0 skipped, 0 failed** (Windows-only arms included), plus three probe scripts (P1/P2/P3 and A–I in the record); `git status` showed the same set before and after. The 13 `mut-int-*` and 13 `mut-c-*` transcripts are the mutants' own RED evidence.

### Security probes

`security-increment-017.md` §1: probe G (the `a.s19.` row loads another file than its label), probe A3 (the entry check accepted `a:b.s19`, `CON:.s19`, `a::$DATA.s19`, U+202E, U+2028, U+D800 before SEC9-3), probes B/C/D (store hard-link / junction / symlink), probe E (read-only store → `False`, 0 staging left), probe F (`/`-spelled and `x\..\` sources stored as one folded absolute text), probe 2 (R2/R3 route refusals), probe 3 (the `\??\` path recorded as `C:\??\C:\…`). Full per-question results in `security-increment-017.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `wa-files` (closed-panel only), the temp folder holding seven long-path-prefix names (`plain.s19`, `[b]markup[red]text.s19`, `fw`+U+202E+`gpj.s19`, a 130-`x` name, `del`+U+007F+`name.s19`, `dot.s19.`, `space.s19 `) × 3 sizes (118x54, 220x60, 99x54) = **3 PNGs** in `evidence/inc-9a/e13/`, `DONE failures=0` (`E13-notes.md`). At 220x60: 5 rows sorted by casefold (`[b]markup[red]text…` literal, `delname.s19`, `fwgpj.s19`, `plain.s19`, `xxxx…`), no row for `dot.s19.` or `space.s19 ` (LLR-172.4d), no crash. OBS-9a-1 and OBS-9a-2 routed to the backlog.

### Experiment step table (from `inc-9a/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 07:42:48Z | — | setup | orchestrator | worktree `b100-inc9a` + `base9a` at `4fef292` |
| 07:43:34Z | 08:04:32Z | E1 | 1 x Opus | 7 → 40 single-shall (E 10, U 8, UW 22), LED .82, Q1–Q9 |
| 07:43:34Z | 07:51:48Z | E2-baseline | 1 x Opus | 28 nodes (app 19, screens 2, workspace 6, utils 1), 59 ex (24 target), extractor exit 0; C1–C8 |
| 08:05:11Z | — | E1-rulings | orchestrator | Q1–Q9 + C1–C8; interfaces fixed; E2 start |
| 08:05:11Z | 08:14:39Z | E2-G1 | 1 x Opus | 11 nodes, 94 ex, 0/31 reqs uncovered, P9a-G1-1..6 |
| 08:05:11Z | 08:16:22Z | E2-G2 | 1 x Opus | 8 nodes, 84 ex, 0/25 uncovered, P-1..P-4, F-2/F-3/F-5 |
| 08:16:22Z | — | E3-prerulings | orchestrator | 12 rulings; E3 r1 start (2 x Opus architect, security) |
| 08:16:22Z | 08:23:15Z | E3-r1 | 2 x Opus | architect FAIL (A9-1, A9-2 MAJOR; 5 MINOR 5 LOW), security FAIL (S9-1 MAJOR; 2 MINOR 3 LOW) |
| 08:23:15Z | — | E3-rulings | orchestrator | R1–R13; E3-fix1 start |
| 08:23:15Z | 08:44:09Z | E3-fix1 | 1 x Opus | R1–R13 applied; +4 LLR (172.1k/.1l/.1m/.5h), LED .83; G1 106 ex, G2 97 ex; cap kept |
| 08:44:09Z | 08:47:42Z | E3-r2 | 2 x Opus | architect PASS-WITH-NOTES (A9R2-1..3 LOW), security PASS (S9R2-1 LOW) → PDR approved; R14–R17 addenda |
| 08:47:42Z | — | E4 start | orchestrator | G1 workspace + G2 app = DeepSeek v4 Pro (pi) x2; tester = Opus |
| 08:47:42Z | 08:56:31Z | E4-G2 | 1 x DeepSeek v4 Pro (pi) | app.py +284, 3 deviations; R14 NOT applied → integration; sha `559ef0a79aab2ce1` |
| 08:47:42Z | 08:57:46Z | E4-G1 | 1 x DeepSeek v4 Pro (pi) | workspace.py +544, 2 trivial deviations; sha `a3342ed048ebe157` |
| 08:47:42Z | 09:17:15Z | E4-tester | 1 x Opus | 141 nodes (54 Windows-only), RED 135F/6P, conftest C8, registry 228, 79 mutants planned |
| 04:41Z | — | CI 41181522185 | — | 7 failed = 6 known + NEW `tc_b100_33[upper case]` (Linux case-sensitive); timing failures gone; fixed in E5 (skip unless `os.name == "nt"`) |
| 09:17:15Z | 12:23:33Z | E4-integration | 1 x Opus | 1 fix (R14), 5 deviations accepted, 1 re-pin (TC-B99-13), 13/13 int mutants RED, guards 75 passed; `green-02` re-run deferred |
| 12:23:33Z | 12:33:07Z | E5-security | 1 x Opus | PASS-WITH-NOTES, 0 HIGH / 0 MAJOR / 3 MINOR / 5 NIT (SEC9-1..8) |
| 12:23:33Z | 12:35:16Z | E5-code | 1 x Opus | PASS-WITH-NOTES, 0 HIGH / 0 MAJOR / 7 MINOR / 4 NIT (CR9-1..11); predicts M28 survives |
| 12:23:33Z | 12:55:08Z | E5-mutants | 1 x DeepSeek v4 Pro (pi) | 79 run → 70 KILLED / 9 SURVIVED / 0 INVALID; M29 mis-applied once, self-corrected; real `LOCALAPPDATA` untouched |
| 12:55:08Z | — | E5-rulings | orchestrator | fix/backlog/declare rows; LLR-172.4d, LLR-172.2k |
| 12:55:36Z | 13:52:09Z | E5-corrective | 1 x Opus | red-02 7 RED, green-03 157 passed, green-04-targeted 10 passed, guards-02 75 passed, 13/13 mut-c KILLED; final shas `0af4b92489233ff2` / `bbf04117fbf0d3f5` |
| 13:39:17Z | — | operator override | orchestrator | per-increment touched-module run dropped; touched modules → batch-end battery with fix rounds |
| 13:52:09Z | — | E13 | orchestrator, Opus | `wa-files` captured 3/3; OBS-9a-1/9a-2 → backlog |
| 13:52:09Z | 14:30Z | close records | DeepSeek v4 Pro (pi) | first run hung 6.5 h on stdin and was killed; relaunched `< /dev/null`, timeout 90 m |

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 07:42:48Z to 14:30Z = about 6 h 47 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 2 MAJOR in round 1 (A9-1, A9-2) and 1 MAJOR in round 1 (S9-1), 0 in round 2; E5 (code) caught 0 HIGH and 0 MAJOR; 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59); full SHA-256 of the staged blobs

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-9a/` | SHA-256 |
|---|---|---|
| e1-probe-4fef292.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e1-probe-4fef292.md | 9136eb8428ea7f6001fc919e2c0c09a5e2e463acebab3896ddd71ae5fd600808 |
| wa-files-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.118x54.png | 3c9e5d4b62085476f8aa2e46ebc5e69947c1295c8af38ad352c4064c46a437d0 |
| wa-files-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.220x60.png | ee22463b582ce9f53369db6a948c3285fbf9ef99bf8f3f1ad357bddd63bad248 |
| wa-files-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.99x54.png | f8fdb82b23c7d063092931fff0fa1e0d64ebe0f5ced5b1228f98e802745d756b |
| flake-tc024.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/flake-tc024.txt | 1f1d263b94a93ca45d5001157efc16449bd79d43c6b98488a5a21897d2210756 |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-01-new.txt | f2bde58b7f57b6e4b7a069f0e835ca14e6c0071eb980b3598f695bd0b268a29a |
| green-02-known-on-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-02-known-on-base.txt | ca80e87d09ed96a7eca543ff59ed9da76c058bc0eb30676a849edcfa623e7cb7 |
| green-02-touched.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-02-touched.txt | 2bd6d73fd0932242cbbe783b732ac4bbc1df7f7eeccecc293e4c9e42f94a5c53 |
| green-03-recents.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-03-recents.txt | b30ac5d8d53b6270457cc857c665d5e95950145d79e8ab5b97bc8c9f5110a756 |
| green-04-targeted.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-04-targeted.txt | 74240402cf767e3e8fa2c730f5884aa616ad5bca1cf32c4b7ff0d17239217fc9 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/guards-01.txt | 5351975279d31a89a5d5303815dfddac0e91c319ba9e328466cd9cc1f4a77e43 |
| guards-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/guards-02.txt | b7c40556dfeaa0ab82144216eb14a9bb32b1ca5a7e51cede831a242c81e93404 |
| mut-M01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M01.txt | e52590adf7f2db698ba2c0b4b93e1bc14d25be45f18528800df38ba6c46e563b |
| mut-M02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M02.txt | 6143180a8318c4547f4db2cadab7a8f8450e34d678e58f3286c5e6098a8cb472 |
| mut-M03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M03.txt | 1ed9fe9d6de01bc6bc296b9fe55317754f01eb14d75ef234221536fd14d25042 |
| mut-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M04.txt | f6b1f325682bcbe03fa69ab2dfd455e95cd3b2f1e8971a4c02d2bb6720007150 |
| mut-M05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M05.txt | fd216dbdb910c4eb609e367c1f2c5c128106a8d2e701ab36e848a2cbcc4f351a |
| mut-M06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M06.txt | 2838d46c7fafe39fd8b92e52a1a54dd56ba5ce69de900e08b9a2559d9467e5ff |
| mut-M07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M07.txt | 0adf093efcabf092e5ad257db91afc7c5f5b951d89e0223ec640001eb6919194 |
| mut-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M08.txt | 74ef9af882caedbb9634ca8f88be678d428bb00a58a1a4f83ca391041762062a |
| mut-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M09.txt | 97fd9ee378afda7118d9592248ca6917df5602af71418d6805c2c616dc3c0ab2 |
| mut-M10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M10.txt | ef62794204708256c491fab6babe139ee7db9295bae8ed03cc52e48193ac2d5e |
| mut-M11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M11.txt | a36b3744b905f2526220a2fd41edb56cd0bcb6dfc1c90cd1d96010b52287b35d |
| mut-M12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M12.txt | 8c3fa3612a2761299897262612f65084869c9d810b10c37664484fc76c8ee9ba |
| mut-M13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M13.txt | 3bb13d200a53ebdd702d809bae0c2d0f92fe7b47803cee4402be6f5d09228639 |
| mut-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M14.txt | 4d2b75ae231bb94bf424e753134aa3691b5756ad7bd740463a4864b3f3b5aca7 |
| mut-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M15.txt | 401294a595709c1262345dc46c6aead208ce7429ffd9bc0373bc77b0c0cc7426 |
| mut-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M16.txt | 0d56be7d4a29393ad5361afa16698fe354b10bd2b1978b8233395fe1a4bd5c97 |
| mut-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M17.txt | 764cbcc4206e8b9cc9b84e5ef74a3d6334f3d5e7e041d46597eb671284106036 |
| mut-M18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M18.txt | ac691f51dae43f3c13d4fbf9b874873bed237c091ce98c2cfb24713eaeaedf59 |
| mut-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M19.txt | 2e1877f8cbd63676b6797ae26f21d7186c68ba33729c09235f3769a0d30189c3 |
| mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M20.txt | d6a5d1962ee0c086f0251ceb0459deed552c033b2dc0c6712a287a25ff378503 |
| mut-M21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M21.txt | bba5a061ce6e9ffad10ecbf64cf340f7b93464796c88e562055d772761d683a5 |
| mut-M22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M22.txt | ca5c1da0eeb0c4aebf37a96f30b9d267624a307d4df15c6afc7088a27c1d8faf |
| mut-M23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M23.txt | adde4a6dce0a4883fd439f80a86b67c183c1951a45c0755732401b8217133275 |
| mut-M24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M24.txt | 6bc6a0b474911f995af41e4da052383b856647c855eb3fcc8575c264948c97b1 |
| mut-M25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M25.txt | c0e1689be1747d398d9c089d035fe1be7f435fba655849dc9168d86915812d21 |
| mut-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M26.txt | ec332b9f39e10bb986dc885e801560745fd1805cc2272c94838c5cc93939e81c |
| mut-M27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M27.txt | 4bd9b596f9873330248306e7402f6d1dcc06fe69075317efb12be6b876919210 |
| mut-M28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M28.txt | 5194847763818889ec7b757a9ef6dc7cc51e45e5d6a1135f392568cff6d795af |
| mut-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M29.txt | 69d325823e8ae8d08d17baa24c5b6ff8ffb8ea907b2343ca980fa522f60b5016 |
| mut-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M30.txt | 191467bc70ee3e8ecd1313cea34f124cfb436e4ac3499d0f143885c1f8a3e734 |
| mut-M31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M31.txt | 9f46001aad100b5e04c508f42130faf07bd9f37c7bfed13b11018378a6268b31 |
| mut-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M32.txt | b4e27b4a6b7b24516e47e28fdf6e0110422a1330d3a456765fbbfd71ba6cc4a3 |
| mut-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M33.txt | d3b66e8cec0f3a2741cbc5b24748fecfaf13e9c0699835e004a23ea1e4d755a4 |
| mut-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M34.txt | 2b3d38a53660e228ff4e2db0fb445e52f1860454f09b49a1a09cae5cfc0eb3a4 |
| mut-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M35.txt | fd1cb7a5f612877be40416cbaf0739b6347e1e2029673f98ead0f91b32949824 |
| mut-M36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M36.txt | 681987314f7661cc601793e4229cbdc9c733e9b8b9607f5bd9d47b01df0c8c16 |
| mut-M37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M37.txt | dd2cc8ac34e12b88d7f0ff4a20fdbc4b88aa78d9cc78f6a96e3e89399c9a09a2 |
| mut-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M38.txt | 5eb4dee688ffac19c2750563c18d6a6380b0a06986467d255c7678a183cb117a |
| mut-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M39.txt | 17b137cbe9737457c221d9c77edf38ac6ec30eeee6e4f12ba258eb65720e3dc5 |
| mut-M40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M40.txt | 0fdefb77c2437d19463f555e8a2a1a5f89500d5c2ea33d9a32f40f99bca02196 |
| mut-M41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M41.txt | d37312f657dd8ccd8067bf0d567bd3c39c77c9a775c3c7436dd315685f6174b1 |
| mut-M42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M42.txt | 74ff898f733845d6aa46fc1ad248a964e26ce4034009e6a55904096046d8247f |
| mut-M43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M43.txt | 0526d4821751e3f8c2f6ef2f2a37713fd92a214bfac06cd5279598402e46629c |
| mut-M44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M44.txt | 609e7e3456f02fb8a8cfc0450717c53edc5f4f3b9dad8f271d602647ee64820b |
| mut-M45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M45.txt | 8d3dadd57ce981ed6ab87d9f4b59ee6ca9d0348aaa0f1a52ec2095e80856e8fc |
| mut-M46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M46.txt | 21ba3562b047549cba0e763cd11cb84433476d1fc3d9ee14d70bef8993c11b49 |
| mut-M47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M47.txt | ce07920652800e54c3a2939cb916d561d3df456f3e73d8e86ed5e05fbe4e6f03 |
| mut-M48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M48.txt | d1d12c2f9b95fbb92d598abc5244f18ef0b81eb4eaa6afb3c2d783121bcd0950 |
| mut-M49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M49.txt | c2f726efe13199bf641dc3fcb77db75db08fb584ab78ad813bff272bcad7ba3d |
| mut-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M50.txt | c70b9782249582227984d228c96c910063209cfbca127fbd656d008bd4e29f10 |
| mut-M51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M51.txt | 865ffaca2dd4e7d1c8110ebed4c514af11bbd79e94cd17dacf0dd603a3c5ea32 |
| mut-M52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M52.txt | fa1e4c9a22391e6c1a942e53980313a82a8586e9eabb2707347a6a7f8d248a0f |
| mut-M53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M53.txt | dbdc6b1c40d475cd53274387f5119f2a324baae78868a0c097af6576b7fd159b |
| mut-M54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M54.txt | 524803ee2f6c0cd4c36d0479fad231f3e6532d048660b963b5320418c91c67fe |
| mut-M55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M55.txt | ca3baac85e425c7816d2eecbe9c3906edf0d256e3e3f657c115dc86882eba89b |
| mut-M56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M56.txt | 4d258fc042903222d2595d9d690ed74dbeed79b7f7fed0652f964989f2c65243 |
| mut-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M57.txt | 8b92df5d31f27f5329467dca7650b9fbc7ead55b2cb5ff06c66f47c328662167 |
| mut-M58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M58.txt | f15bd6073d9265ffff685e2bfb940aca0d1042372675819d56c212596b4ca6ac |
| mut-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M59.txt | 0921a0d6b284d9d3a68c8e2fb91997d651ce53cc2498870a9ed3144079e8c31b |
| mut-M60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M60.txt | b4c8a69f4e4e96e813d8fcf3bb8d0a58065abb1d76181226223a093fe7f3ac6b |
| mut-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M61.txt | f089407192eeb6106905279b4bec98d02155f957ca9b3b159d49c2f1c7e3b696 |
| mut-M62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M62.txt | 698f1eefa2b6f7913cdd0f11e7553045061ec6250aebb68c6deb0a66645b0622 |
| mut-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M63.txt | 2485490754ffef4798a6c56f3d092131e0209c1cacc897ea59681ddcfb76f27f |
| mut-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M64.txt | 313e0e5cafe79e5f4894cabd85bc8b6c2586ab6e8aebaa7509b2501305b4b99e |
| mut-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M65.txt | 4c4ac429fc48c8ada3cf575821d1578fcb369692b924e11e359aa661df8fd64e |
| mut-M66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M66.txt | b93e19c82fc367b3336ae0cae2fbcac7ec0d52eefd93805a7cacd41b52db3dd6 |
| mut-M67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M67.txt | 2042b7e13c3d00117a44159c2738386cbedf0eb2925349dcf82ae9ffb681dbea |
| mut-M68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M68.txt | 7894981216cd9aba536fe99781236cd5838e2eef52d11b1411113e90f276ea2c |
| mut-M69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M69.txt | 1bf065ca0e3b7cdb2dc71b447732945fb59afcf50189f3f96889aa893a15f636 |
| mut-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M70.txt | 5bede1d69af70bf6b4d139a633f34b9bdfb5946bda1cb894b790a7f709060bc8 |
| mut-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M71.txt | e8629fb59652556070620fceded3e1c35e7bdad801dae1a8bd73d924fc622370 |
| mut-M72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M72.txt | eaeb67f6b4e877bb1b5e6f9bf9288c82944b401ef8d48bc330ef10c6f193ee5c |
| mut-M73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M73.txt | c3b7906092d8224e2b26897c1ba4b9715e129dbc7a1b44abd15a78709e771ece |
| mut-M74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M74.txt | f9ccba6c41fec23271b7d40c73904abb7e56f951df0b32dab10ba1b145eff72c |
| mut-M75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M75.txt | 270d7f9afd567d396114788679cc08efcaf7bfcfc52488de3633b61af1914700 |
| mut-M76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M76.txt | 2058cda6224d9025c3b8791a91606d29a7caa481eace09e5a40ca1cb99fac925 |
| mut-M77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M77.txt | 1eb96236ab5a8ba63a1d106e4d0201a2acfce5ba8f3d7c4744a15b2f8804c6fd |
| mut-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M78.txt | 64761140864262b9e7c13ce502e61ec10dcd08755e4768fddf626e7e425225e6 |
| mut-M79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M79.txt | 411fbaedd8031559846869f7d667fd153018f4b58275ba9bb6685aba0dc2cc9f |
| mut-c-CR9-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-3.txt | 622cc4c0b5a72acd7306b406403c21ad704d8b6fbd2377aaac31effa36985f43 |
| mut-c-CR9-6a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6a.txt | 6a1fe5edad51a29707aba62245af38e87f3536ad9d679621ba83b1e977e00f66 |
| mut-c-CR9-6b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6b.txt | fba44b195340aac6b00e235b3dab3004eaef1c679d2711ec209189e34a64f057 |
| mut-c-CR9-6c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6c.txt | 4426b545eeac0457dec09325a0d22590cee44e690716320e13391c996840794f |
| mut-c-CR9-6d.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6d.txt | d2146948abfcac30cc2c4f8876d47378234b2b403d68f5e43e96e0c62fbf5c26 |
| mut-c-CR9-9.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-9.txt | d159e929461b4ce054c26f22dc38d0228a584c62cf69609c098b77e9a457ab4e |
| mut-c-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M19.txt | 2bb6e2e09112588def76aecaef54411e74afa7ea932234e860e72a2fe33a68f6 |
| mut-c-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M57.txt | b6578a8777a981a6db79bd91a9c57323ec7e2960955dfe6784fb343df9c053d8 |
| mut-c-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M61.txt | fb4cd67f6e9e8a97eb18357257134c274906d75a654d24e2827674945ba0dcf4 |
| mut-c-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M64.txt | 926617e3df5b936cce701c5e3907eb698bbf98a4aa85050f0d2e4423c0ced47f |
| mut-c-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M65.txt | 4ac9646b88d092fcbc67babd741b09cd6dac689b245961e239038f8beeb7a65c |
| mut-c-SEC9-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-SEC9-1.txt | 694a57a380c3b6ac62856af702620c70eb5fc162ceb0e0ba9f9e5338c37545cc |
| mut-c-SEC9-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-SEC9-3.txt | db277c772b6e53c3e4c071b42e7127f276d46095601ce452612d8973c686f658 |
| mut-int-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-01.txt | 9b35652f53d1f6cd9908efa02ba8f3d43648355b9b4949380c56e6eea7a7ef75 |
| mut-int-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-02.txt | fb57412a3da6e8ed18068fd3b11e322fa68516431cf2fea4374d30f0269209c0 |
| mut-int-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-03.txt | e96cc216b9c54cff3846693eaba44f759c941529acc1f3e2b403ca1830dd7174 |
| mut-int-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-04.txt | 4b07e31e7235b47ba834cf07d5be2a4491b3093e66b81a45289eb4d8e2631635 |
| mut-int-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-05.txt | 7785de59c6d3c7a2052a88dd762e8d20ae6e9e967ca17e2d006673141ab2de4a |
| mut-int-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-06.txt | 65b331a13fb4f2207085c909746d3266bca300f845cc9dd9bbd41fd2d29f485d |
| mut-int-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-07.txt | e5b8aa96a7a45133033cac506188602b193e94a1f6e9a1d32a3e6c496c99e2fe |
| mut-int-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-08.txt | 5dc5430a0889da59dc014da8fc05d83f4e859de54610918b3eef6a77f5b0741d |
| mut-int-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-09.txt | 2ab54942d32ed49e6f42d5ba87513429a498fac73b4a214e40c0bd5d254d4318 |
| mut-int-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-10.txt | 3ddde2820d69dd36614b04056e7a90bd64709bb049d4288d75fb822da792c7fb |
| mut-int-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-11.txt | 767c040dedae179e6df079e9a62d484df4209f53d4e2819d2103267220a6d1e7 |
| mut-int-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-12.txt | fbe12469234d224f40f73e7e4c2d691ce695a73a9c1333a4c6799029bd9790a4 |
| mut-int-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-13.txt | 2080b46466e13416c2faa310f929d6d8df387b9a66bbd1b7f03fc1bf501bc4c9 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mutation-summary.md | 3b328cc1ba9c60cf9f787a9c50846ff7d5379ae3d1a83f11d5de159cd2a4a611 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/red-01-vs-base.txt | 12b572f44355dfce3b06f9d51d0df2c76db6094e9c52c31e119495232ef48ebb |
| red-02-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/red-02-corrective.txt | 6c94862b4a02473e0f52b7ef4b7ec539e11d859edba315d725ba1333d2690ad9 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 7 MINOR, 4 NIT) — "OK to advance, with notes". MINORs: CR9-1 (a relative source found by the base/repo fallback reaches the record already resolved), CR9-2 (an 8.3 spelling of the work area routes a listed project "outside"), CR9-3 (trailing-dot suffix mismatch between classifier and loader), CR9-4 (the NUL test is mislabelled; M28 will survive), CR9-5 (non-link reparse files hidden; inferred, not run), CR9-6 (four `OSError` arms untested), CR9-7 (listing-match duplication); NITs CR9-8 … CR9-11. Diff read in full, targeted run 49 passed. — `review-increment-017.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 3 MINOR, 5 NIT) — SEC9-1 (lister shows trailing dot/space names), SEC9-2 (pick-time recheck, pre-existing), SEC9-3 (entry check accepts ADS/device/bidi/surrogate), SEC9-4 … SEC9-8 NITs. Executed probes G/A3/B/C/D/E/F/2/3; the full recents module 141 passed. — `security-increment-017.md`. **Design reviews (E3, code-free):** `architect` (2 rounds: r1 FAIL, r2 PASS-WITH-NOTES) and `security-reviewer` (2 rounds: r1 FAIL, r2 PASS) → PDR approved (`inc-9a/E3-architect.md`, `E3-security.md`). **There was no round 2:** nothing was blocking — the E5-rulings addendum states no HIGH or MAJOR was open after the reviews, so the narrow re-review is satisfied by the corrective pass's RED/GREEN/mutant evidence (`red-02-corrective.txt`, `green-03-recents.txt`, `mut-c-*.txt`). **Orchestrator (2026-10-31).** Final source hashes `workspace.py` `0af4b92489233ff2`, `app.py` `bbf04117fbf0d3f5`. Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75); the touched-module run is deferred to the batch-end battery by the 2026-10-31 override. Rulings applied: Q1–Q9 / C1–C8 (`inc-9a/E1-rulings.md`), R1–R17 (`inc-9a/E3-rulings.md`), and the E5 rulings CR9-* / SEC9-* (LED .84). |

---

## 5 · Risks

- **The touched-module run (33 modules) was not completed for Inc 9a** (operator override 2026-10-31). `green-02-touched.txt` ends at 36 % with no summary; a module outside the recents module that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7). The three known pre-existing failures named by `green-02-known-on-base.txt` stay red at base and in the touched run: `tests/test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` and `tests/test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`.
- **The CI failure `tc_b100_33[upper case]` (Linux, an Inc 8b test) is fixed only on Windows.** The arm is now skipped unless `os.name == "nt"`; the Linux half has not been seen passing because no Linux run happened here. CR9-9's native Linux half was shown only through the `os.name` proxy (state: `not-run` for both Linux halves).
- **The lister skip (LLR-172.4d) and the R14 project-list skip now behave differently off Windows.** SEC9-1's lister skip has no `os.name` gate, while CR9-9 gates R14's skip on `os.name == "nt"`; on Linux a temp file `a.s19.` is hidden while a project folder `fw-v1.` is listed. Both fail safe; the addendum rules "declare and backlog → Inc 12a" (unify both behind one helper).
- **The security review ran on the pre-E5 bytes.** E5 changed `workspace.py`, `app.py` and `tests/conftest.py` after it (SEC9-1/SEC9-3/SEC9-5/SEC9-7, CR9-3/CR9-9). Their arms and mutants ran on the final bytes (`mut-c-*` KILLED); no reviewer re-read them — the E5-rulings addendum records the corrective pass's evidence as the narrow re-review.
- **SEC9-7's session guard has a declared residual** (a store or the folder created and then deleted inside the session leaves no net trace), and the store's `fsync`/staging sweep is left to the backlog.
- **CR9-5 / SEC9-8 (inferred, not executed):** a work area inside a OneDrive-synced folder may show 0 Workarea Files rows (cloud placeholders keep the reparse attribute). Declared; backlog → Inc 12a.
- **Model performance.** DeepSeek v4 Pro implemented G1 and G2 (E4): it missed one ruling (R14, applied at integration) and declared 5 deviations (3 G2, 2 G1), all accepted. DeepSeek ran the 79 E5 mutants: 1 mis-applied (M29), self-corrected. Opus did the design (E1–E3), the reviews, the integration and the correction.

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- CR9-1 — a relative source found by the base/repo fallback is recorded resolved (a junction is followed) → **Inc 9b**.
- CR9-2 — an 8.3 spelling of the work area refuses a listed project's long path as "outside" (fails closed) → declared in Risks · **Inc 12a**.
- CR9-5 / SEC9-8 — reparse-attribute files (OneDrive placeholders) hidden from the list (fails safe) → declared in Risks · **Inc 12a**.
- CR9-7 — the refusal lines and the listing-match rule written twice/three times → **Inc 12a** (refactor).
- CR9-8 — a relative typed text holding a NUL raises out of `_typed_load_route` (pre-existing) → **Inc 12a**.
- CR9-11 — the one-lister census misses a literal `"temp"` → **Inc 9b**.
- SEC9-2 — pick-time recheck of a listed file (pre-existing code), merged with the open SEC TOCTOU row → **Inc 12a**.
- SEC9-5 (part) — `fsync` and the leftover-staging sweep → backlog.
- the LLR-172.4d `os.name`-gate addendum (unify the two dot/space skips behind one helper) → declared in Risks · **Inc 12a**.
- OBS-9a-1 — the Workarea Files panel is ~20 columns wide even at 220 columns, so long names are cut by the widget before `painted_names`'s 120-character clip (the clip is proven by the test, not the capture) → backlog.
- OBS-9a-2 — the status line "1 problem - details: p" appears for a clean project (read from the capture, not investigated) → backlog.

**Declared (Risks, not backlog).** SEC9-6 (check-then-open on the store, same-user only, accepted at E3); CR9-2 and CR9-5/SEC9-8 (fails-closed, also backlog as above).

**Named gaps / observations.** M21, M24, M28, M42 are equivalent mutants (recorded, no fix). The A2L side of the Q1 arm (a copied A2L that then fails to parse is recorded) and the UNC through-Load arm of LLR-172.1k/.1l are uncovered (no reachable share) — named in `E4-tester-notes.md`, not run. Linux CI is not reproduced for the `tc_b100_33[upper case]` and CR9-9 halves (`E5-corrective-notes.md` item 1). The threshold text of the LLRs that gained arms without a text change (LLR-172.1d, .1i, .4a, .5, .5b, .5e) is untouched — a threshold touch-up is pending for the orchestrator (`E5-corrective-notes.md` item 4). The `red-01-vs-base.txt` run used Python 3.12.7 in the scratch base tree; the GREEN/guards runs the s19env 3.11 interpreter — recorded, not a deviation.

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| A9-1 (resolve() drops mapped drives; P9a-G1-2 unstated), A9-2 (absolute-only route unwritten), S9-1 (stream/8.3 spellings reach reserved homes) | MAJOR | R1/R2/R3 (LED .83) |
| A9-3 … A9-12, S9-2 … S9-6 | MINOR / LOW | R4–R13 (LED .83) |
| A9R2-1 (stale E1 rows), A9R2-2 (two vs three exceptions), A9R2-3 (G2 `repaint`) | LOW | R15, R16, R17 (LED .83) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| SEC9-1 lister shows names ending in a dot or space | MINOR / design-gap | fixed (`list_workarea_files` skip); LLR-172.4d; `mut-c-SEC9-1` KILLED |
| SEC9-3 store read accepts ADS / device / bidi / surrogate | MINOR / design-gap | fixed (`_recent_entry_ok`); LLR-172.2k; `mut-c-SEC9-3` KILLED (also SEC9-4) |
| CR9-3 route decided from the abspath suffix | MINOR / impl | fixed (the loaders' suffix); `mut-c-CR9-3` KILLED |
| CR9-4 NUL test mislabelled; CR9-10 false base-RED docstring | MINOR / impl (test) | docstrings corrected; M28 recorded equivalent |
| CR9-6 four `OSError` arms untested | MINOR / impl (test) | 4 monkeypatched arms; `mut-c-CR9-6a…6d` KILLED |
| CR9-9 R14 skip runs on Linux | NIT / impl | gated on `os.name == "nt"`; `mut-c-CR9-9` KILLED |
| SEC9-5 (part) fd leak on `fdopen` failure | NIT / impl | descriptor closed; pre-fix RED is the mutant |
| SEC9-7 conftest guard hashes only the store file | NIT / impl (test) | guard also compares the folder's name set |
| CI `tc_b100_33[upper case]` fails on Linux | impl (test, Inc 8b) | skipped unless `os.name == "nt"` |
| M19 / M57 / M61 / M64 / M65 (survivors) | weak test / wrong target | fixed in E5 (`mut-c-M19`/`M57`/`M61`/`M64`/`M65` KILLED) |
| CR9-1, CR9-2, CR9-5/SEC9-8, CR9-7, CR9-8, CR9-11, SEC9-2, SEC9-6, SEC9-5 fsync/sweep, the LLR-172.4d gate addendum | design-gap / impl | backlog or declare, as listed above |

**Orchestrator rulings Q1–Q9 / C1–C8** are in `inc-9a/E1-rulings.md`; **R1–R17** are in `inc-9a/E3-rulings.md`: R1 record `os.path.abspath` (lexical) · R2 absolute-only project route · R3 match by listing, route the on-disk name · R4 `painted_names` labels · R5 drive-rooted `LOCALAPPDATA` on every platform · R6 reader link check · R7 `mkdir(parents=False)` · R8 no lock, one seam list · R9 thread arm dropped · R10 cap kept (LLR-172.1m) · R11 temp-is-a-link into LLR-172.4c · R12 Windows-only arms · R13 wording fixes · R14 `list_projects` dot/space skip · R15 E1-scope corrections (done at close) · R16 HLR-172 exceptions text (done at close) · R17 G2 `repaint` reads `painted_names`. E5 rulings: CR9-* / SEC9-* (LED .84).

**Re-pins (test::node — old -> new — requirement).** RP1 `tests/test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement` allow-list gains `record_recent_source` (a `workspace.py` name, LLR-172.1h/.1i) — the store is outside every work area, so outside LLR-155.3's scope. Removed: 0.

## 7 · Suggested next task

**Inc 9b of batch-100** — the Load dialog — with the `dev-flow-v3-beta` pipeline (its E1 is already drafted in parallel). Carried into it from this increment: CR9-1 (fallback-resolved source decision), CR9-11 (widen the one-lister census where the dialog's files section lands), and the consume link of AT-B100-12 (pick a recent, LLR-173.4).

**Batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 79 Inc 9a mutants ran on the pre-E5 bytes; the 13 corrective mutants cover what E5 changed);
5. the CI run, comparing the FAILED set with the previous run (the `tc_b100_33[upper case]` Linux fix has not yet been seen on Linux) and the known flake `test_tc024_report_trigger_surfaces_paths` (`flake-tc024.txt`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 of the 4-file cap (`app.py`, `workspace.py`) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_recents.py` (NEW, 157 nodes) + `tests/conftest.py` C8 + RP1 + the CI `tc_b100_33` skip + `tools/e13/run.py` — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `recent_store_path`, `recent_kind`, `_recent_entry_ok`, `read_recent_sources`, `_encode_recent_store`, `record_recent_source`, `list_workarea_files` |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (135 failed, 6 passed vs `4fef292`); `red-02-corrective.txt` (7 failed / 23 passed) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator rulings (LED .75; override 2026-10-31), batch-end full battery** (§7). The recents module, the targeted nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES (0 HIGH, 0 MAJOR); no round 2 owed (nothing blocking) |
| 7 | No file from another lane touched | all | ✓ | the 2 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `_ENGINE_PATHS` modules untouched (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); `workspace.py` changes are additive |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 79 E5 mutants are stated as run on the pre-E5 bytes, the 13 corrective mutants on the final tree |
| 10 | Load-bearing emptiness declared | all | ✓ | the M19 node now installs nothing (the new bytes raise in both codecs); the M57 node spies `os.scandir` reversed; M61/M64/M65 use direct `_typed_load_route` calls |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 79 run: 70 KILLED, 9 SURVIVED (equivalent / equivalent-under-test / weak test / wrong target), 0 INVALID; 13 int RED, 13 corrective KILLED — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of the store and lister: `record_recent_source`, `read_recent_sources`, `_recent_entry_ok`, `list_workarea_files`, `refresh_files`, the record calls in `load_from_path` / `load_a2l_from_path`, `_typed_load_route`, `_handle_load_project`, `list_projects` |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence digest table (staged-blob sha256[:16], filled by the orchestrator) covers `evidence/inc-9a/` |
