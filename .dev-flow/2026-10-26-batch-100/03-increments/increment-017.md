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
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
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

First step start to the last logged step: 07:42:48Z to 14:30Z = about 6 h 47 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 2 MAJOR in round 1 (A9-1, A9-2) and 1 MAJOR in round 1 (S9-1), 0 in round 2; E5 (code) caught 0 HIGH and 0 MAJOR; 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59); full SHA-256 of the staged blobs

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-9a/` | SHA-256 |
|---|---|---|
| e1-probe-4fef292.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e1-probe-4fef292.md | 9136eb8428ea7f6001fc919e2c0c09a5e2e463acebab3896ddd71ae5fd600808 |
| wa-files-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.118x54.png | 3c9e5d4b62085476f8aa2e46ebc5e69947c1295c8af38ad352c4064c46a437d0 |
| wa-files-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.220x60.png | ee22463b582ce9f53369db6a948c3285fbf9ef99bf8f3f1ad357bddd63bad248 |
| wa-files-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/e13/wa-files-closed.99x54.png | f8fdb82b23c7d063092931fff0fa1e0d64ebe0f5ced5b1228f98e802745d756b |
| flake-tc024.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/flake-tc024.txt | 59e0d25f23ad78198d1d3c8e391b9ad2f6e0625af36c208ee48fc9e005242cfa |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-01-new.txt | ed64420668e2b7e726fabc738bf10f6b0f517cc9e9309b3d933bb031e86c6f48 |
| green-02-known-on-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-02-known-on-base.txt | ba33b6220b0f6e9dfaf79cdfabe60f4d5ac68df235b90bcdb32be2ad77ac4563 |
| green-02-touched.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-02-touched.txt | eaf3c4fa4a84820e120bba0f075b4e1c3b56065ca15d7fc05c59fc01fc8dea6a |
| green-03-recents.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-03-recents.txt | 1d1bcfaf1aa69acc3191498f6c50128f2da3575f4a63e47eec4712b8bd1890d3 |
| green-04-targeted.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/green-04-targeted.txt | 1cf3aadb4c03353cc776660163a013e8191dacd26ee0012fd5a1cee116541d70 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/guards-01.txt | 16c07589a9bc77f3a26923f097c3d0f9df14903d44d9efeb98d4166d0d0214e2 |
| guards-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/guards-02.txt | 37de597755ad7d259554cead887800a2f96dd42a35b6de25544a1ef0aee28b84 |
| mut-M01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M01.txt | dcbff13d77ec6a84107a5573865a1240e097c54845a78891824f00f3911cb270 |
| mut-M02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M02.txt | cded6bc0b4e2835757f06489a3fd27e2f1cef7ab1ccd8e2a1b953cd2e02a5375 |
| mut-M03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M03.txt | fc04903639ca9a2269aee7219e6009961ae314a9a27d100f2e66c6ca5e083bcf |
| mut-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M04.txt | 157c7fb83e38e1f08962652e53ae1c44d5ff08963050bcdb46f56703883d0745 |
| mut-M05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M05.txt | 9852964ec3299bc201df6ee6c48517604208e0c72b73120eec02209ec6a70dbf |
| mut-M06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M06.txt | da1e14b9bb61cc391a40a53426aa380c52ec990379064ac1fab7835aacc22a3e |
| mut-M07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M07.txt | 665096bf41c213d6f59fa1f6699c6b10cfb387a4472354e3df9a78d510a1a56c |
| mut-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M08.txt | b0883b421122b08ccd12c2caf9cf8144a4a6e1f070a4ee82e70da724da8179d2 |
| mut-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M09.txt | 85b73797111aa7f29a3c6b256ff1343b18e92dce814f6e551b558afd538df1a8 |
| mut-M10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M10.txt | 68ff31fa5b467ff6e3ee21bd43a07452e7281a23fbb7092fb8fb17a6c0cdc5cf |
| mut-M11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M11.txt | 4c1ccae2ebed455e9137f0e7fd84dada10803f8deab1dbe87df996ef5f9e0e57 |
| mut-M12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M12.txt | 8a9a994abe7cc70bf4ef3ee32cdf92dcc4af4a22e1056b22891f9c3fbd392e1d |
| mut-M13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M13.txt | 9734e31a5d7f1b8cbc7e5420b8bd0c8a433ce16ac888a8c367f3e745e9cccfcd |
| mut-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M14.txt | 33ede092349511cd0fcce107333ed6495ffc6d9718173c38fbacad3545c56e34 |
| mut-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M15.txt | 83e2358558f9b701284b71702399b73f20fd51f77d29191461d638ea908a29f8 |
| mut-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M16.txt | ca01334b53b73b6284448a4d01fdb56c04d170e1a38f20d9b51e71f6522bcc17 |
| mut-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M17.txt | 04db02a2df0194da56d4d7f3be31898575d18cccc346c815c4fced6ad236657b |
| mut-M18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M18.txt | 0f6473f08521883df073007f984c2cba59dad0685d5be77019ad7af466dcfa6b |
| mut-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M19.txt | bd6eb4b7614e80f160ce34bfdd7558678bbb996cf8aa43651223356b57f51815 |
| mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M20.txt | bce07a613ed705503a771f8a60b3ecfde7f4f3f515360a0b9ef98ac97716e570 |
| mut-M21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M21.txt | dfd6e6836b853fd496a6c0f6530ca58e7ace1f4ef7f37a6fc274961832b62f13 |
| mut-M22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M22.txt | 5016e5ed0b5c9fb6f121921584d51c6ba7be077956c9f749f85a585850ef98dc |
| mut-M23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M23.txt | f1ca95c36b140cab72e6b22b43a67c395e98065978ad4378ea7c07c44dd7aada |
| mut-M24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M24.txt | a4b21dbd64182a7f86aaa559f3a24685d1c86a953d609c0a5ddca4f9897631ef |
| mut-M25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M25.txt | 5780459a8855e2d90757b7abe23d05f5271441e2ae127d1534b6b6a88f99956d |
| mut-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M26.txt | cef63ba6dfcbdba7f2b83b33b54c8fab5284cc80d0de1a279c1cd5d851669468 |
| mut-M27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M27.txt | ede091f9f89ea18ae522ecbf0f977301848059ab24819aa819a47f8048a56d42 |
| mut-M28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M28.txt | 55daef22866e0128c5164bb7dd8eabc6bb0c3964a6d30e314109e594fea40575 |
| mut-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M29.txt | 229c7151f235ce495a8fcea53b01f976c612013d160f65d1b8f56f42d8af1598 |
| mut-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M30.txt | 2bc6dc9f6e443f7a145d87654e2f218682e5ce3be9116f490f5c2f2a8f70cb9b |
| mut-M31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M31.txt | db0c5fc92fe222a7052a476973af59283056e143c166030beb0fc0e100984e62 |
| mut-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M32.txt | dd06d68d71db5c02bead36d6f435412badba42c5edbe5d9aba51547cc793c5ea |
| mut-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M33.txt | 6571dd002ef8f2fde99b9cd2666841e50a009a1dca73076d73f8a49d50ad9fb8 |
| mut-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M34.txt | 49fbc06363ec6225a2b92a55a03ef9fbdbb9a1bf2be3ce4d443aeed0cc1cae0c |
| mut-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M35.txt | 5b5ac24ad71426bc0b24cb704ba06b98d84d0b9980a3adbc438930090711cbc2 |
| mut-M36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M36.txt | 72e0447aa4a7d20bc7f777f11ae2a5b9934dd275203c41486e43a7349d8f2e63 |
| mut-M37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M37.txt | 7a45a62471669df4ff59268a6abdd876d03c92e13ff02ccc9950da7c05a62edd |
| mut-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M38.txt | 40ba4f4622c6faa81cc7672e38121b6e3a233158ab10c1763c5184f5893f246b |
| mut-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M39.txt | e0b1d7e00c5eac98cefc0f5df3965ae72b78b6492479736bd0ec6b2e5f6ffe26 |
| mut-M40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M40.txt | aaf1d99254d105dfbd2a2244169a81c77cd76e103f45b7f784841856e918120f |
| mut-M41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M41.txt | 6d2445452f42586a475262adf5211de240c09c83af4135edba4512e9b48e0054 |
| mut-M42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M42.txt | 36b1a1c4586e1eec13619c0d4491173097d9b5b6d3eee8c7a59de5f1191f1efa |
| mut-M43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M43.txt | 378262a52c06d93c014078122878630fbfba1cc41725cbbf09ded9c28b24b404 |
| mut-M44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M44.txt | 5a9cbacb664767f0c032bcefa6a2d67fc429ccd51606b0194a65195b8f8ac069 |
| mut-M45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M45.txt | 4c9a319c40e4607d55dc44f3a1d66ab3dff0763cad999f87467f1af7997d0cf4 |
| mut-M46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M46.txt | 6393613149cb42fa5cd43a7e1425cfe2b1c4f96bf42e8e1155a7d4115e05c9dd |
| mut-M47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M47.txt | 53c197931e20fb0dbbcd66df3589c2f08ae0cd471f48bb089b16008180aaac7c |
| mut-M48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M48.txt | aa5ceadacca26db8875ec4899943577734ecdf81a20a2af9f44a014c7d62aa63 |
| mut-M49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M49.txt | 04d4b59094753114b9ede2aebbb273571fd58a010317e86f31cd1753f84174b8 |
| mut-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M50.txt | 37507ddb8b32d8f34634ebb3ca80ed80911ba9a52c8d0aa62b6a9ab584e61460 |
| mut-M51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M51.txt | 059ae8cbb955f1d4921f331af34418e75a9119e89da5dce127f9237996bc82ab |
| mut-M52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M52.txt | 038d1dcc3094de016f2200de9d043c5be269d6f7bac5e260fe41b10f98f4f098 |
| mut-M53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M53.txt | b19736fda092903df489f9e4a3f806e539e7492bf49c167f85e474a4d6f640f4 |
| mut-M54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M54.txt | 8ae74e13c1876ec37d8333992198358f471fb0d51879b0e82e00b5ddf7ea6baa |
| mut-M55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M55.txt | 6bc3a460f177f07e772b4a51fd2ca4f75de00cd0fb684174d9f56d10f085e2a1 |
| mut-M56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M56.txt | f0b7d461cad3d475bff63ae4a5df54dd76a5d6324dd1cc909d54a8056ad4032d |
| mut-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M57.txt | f34636824d0bf84d981c711a9454c8fed796607d732ea37d40732606ca5bec2f |
| mut-M58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M58.txt | bd9596e458a450125fa7d76a31db0c5ec66a8868024a857f41945c549ef40970 |
| mut-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M59.txt | 87a6ac4612380f434152c2584df9bf9210fa3b6e241d6f24f7e323adc63f25e3 |
| mut-M60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M60.txt | aa43e90a93ff82927fa6030b9d3b78b5ae9ed7f7f346fa10f213ade7e17bef4a |
| mut-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M61.txt | a6adeeaed03c5a3b3ec5577a0f3c2ef028dab3deea3e2bffe14fede383cfaa3a |
| mut-M62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M62.txt | 646f4290950df948e39e8a212d22ede09675ee984e852b5c25e12a1906214c3e |
| mut-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M63.txt | 2e1e917216aafff8d194b518d0dfa7c9a2216b0459dcd5de4f436476bb01a87b |
| mut-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M64.txt | f70c40fc4ade09541edb75aa52db950a6cb5993ae8cad686dd5ee66590457a6c |
| mut-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M65.txt | 48ab4cbe6ca3b5bd68dbc6584433eec92d0e8056dba11409da0b58e16e77fc09 |
| mut-M66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M66.txt | ee6019704f59018c5379889550514b91d61c5279185b9377437bcd8b645f02f3 |
| mut-M67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M67.txt | 8ed3aac8562871cbe2d37ccd433e9e7d44d40d4f498bc55924899d3ccd7c5188 |
| mut-M68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M68.txt | b8331d81bceff102c9be05dbd1fbbdd46b8906ade94e97fdaf639f4fe15b4edd |
| mut-M69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M69.txt | 7dcd97e324c8c76413eec4df52b25769b6fc2fe909a32a238c96e98ca86a4149 |
| mut-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M70.txt | 47d98310bc8482c9d9c290ffed3549e210475124a6517c9d9ad85acdd570078d |
| mut-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M71.txt | 0e3737f399d297ac56bb52d41185530341d4a60a5c972e7507201b7e153e272e |
| mut-M72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M72.txt | b4ef19174d1d46915054cc41d749330f11b1ae3d5abae9ee691bb9bc5cc4e7f2 |
| mut-M73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M73.txt | eff370bf8afde29e602455445c01de30e4ab48fb515b04ea91ad8b99fc5e126d |
| mut-M74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M74.txt | f8a2bfdf66d26bfaa426d1d07973b0ff449cd615f0df1e913238a683aa6b497a |
| mut-M75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M75.txt | bed4f3801d43601a4a646e15913b54a3f3b786536163c4aa246e09152f5f30ce |
| mut-M76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M76.txt | cb39850625baed244075e7a10d14220c2edf4ee4b06179c481670f7b90782093 |
| mut-M77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M77.txt | adb32ecaac3a7902fbe26c7d21b389f78fbe28a7a882be0b0fa8a2e0b210324e |
| mut-M78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M78.txt | 5cb9981d65a566d7949d0b23db7cae4a626bbe1a733a62f7ed7b8f05a625b32c |
| mut-M79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-M79.txt | 33482ecbe6a93412ae45b955ebc2c375e0b9f534a36d53693a2ff4664a3e8c88 |
| mut-c-CR9-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-3.txt | 6bc5971f301330bce8519f571570c569ca85e149519dc39e19b8415dc54ae1e8 |
| mut-c-CR9-6a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6a.txt | c047fa6617e48856db123c0423b9797552867263be1b5f7d37e17c5539b08c50 |
| mut-c-CR9-6b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6b.txt | 53e923362f1a2a1899625f8d1adfcf60f07b35a777377340143f4f13f3965643 |
| mut-c-CR9-6c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6c.txt | bde53f3b22fb53378eabdd62b87a4b4ec754dcc846de7e727cc9a1a254403eca |
| mut-c-CR9-6d.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-6d.txt | a19e6806d017f2feafd9882540d2a630623888a4e60be8b4322120dd6e1b56c1 |
| mut-c-CR9-9.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-CR9-9.txt | 5365a0f146abc033e257f55a4cdf300790345292fc3ba6df07a0d15b3b7a79a0 |
| mut-c-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M19.txt | 247d326f5d0beea54f91d133d2ad902f26959498bcb7e98ecda8e60a31fd4e83 |
| mut-c-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M57.txt | 96769acc45f2473ff98cec4e3ed4d4ef675973c99be03de2d868726a2e0468e6 |
| mut-c-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M61.txt | 6a660e89d5d2673794efeac33b3f014b2b3449e5c1cd96b7628dfc3e40c9a370 |
| mut-c-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M64.txt | 3abe7f0189817e6aa8acea657640d431d75323ebf6eb3debf3c5186aed2da710 |
| mut-c-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-M65.txt | 114f6c1ffa5c1710a373fb0f36571bb282dcd08c1fdea05de95faaf1a48f472d |
| mut-c-SEC9-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-SEC9-1.txt | 56848659d5c46187bbf9496bcc7f7c07f7833ae663543d66455b1636b535e003 |
| mut-c-SEC9-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-c-SEC9-3.txt | b76e7915f47f01d5ac55e2aba8ca5d5e4c9c19217a0aa5e237c3da5257550da8 |
| mut-int-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-01.txt | 9cd80cbf59d1e3723204c7274085f4449f7f949201a6134fe0875ab31edf7208 |
| mut-int-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-02.txt | 1cf4b79befc6143ba4ea08d805a6ef30f97d62a0d601a42f3c0e175ed79287cf |
| mut-int-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-03.txt | 3e730325c4bf8946738a35c24977ae65b79685ba7a7cb32047b69989a6873acf |
| mut-int-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-04.txt | 032a211a3ca1377c368c48165d3dd67fd881103065d51fdce95f17a1ee46a8dd |
| mut-int-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-05.txt | d8ccf91c21d9c82693d8dc6974b404d471212737433f749eb877f73d81fce664 |
| mut-int-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-06.txt | fc4caed1a5397f42f6d2068010d874cab26d66ad97f399c398b7f2b3b04b0d01 |
| mut-int-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-07.txt | 530c03ab14fd1de388f9382cbf100598e516329cf1e8565d10fc61d2d17d21d6 |
| mut-int-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-08.txt | 544e49c81ed4c3677a9ee653e79c321461e4dbff3ff113e7e867bbe9c002c2a2 |
| mut-int-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-09.txt | deafcf8d22839b80ac0783eb134c2bb21099a1de346ee64eab4d6e58e38cf318 |
| mut-int-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-10.txt | 30b9813e1e96363234c9dc783aa28b06c5a9d1147d976127f8304920f127d36e |
| mut-int-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-11.txt | 38c61ceb2523b3c0a93115dddbd960a75bf0536b434ae1a97939e1c73104511f |
| mut-int-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-12.txt | 88b7db74e2ea15fa332601bbb50b2c4468f79ead3891ee9a2f420d4e6512552c |
| mut-int-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mut-int-13.txt | 4f9b8e22292caca605ea2e3dd96a3c87761bad38e7b01538f918b3a028d41909 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/mutation-summary.md | 40e1f9972f9c56b763f3e1c9f6695893ebe0bb8a578ff4bd7ebac5a3d0b49a00 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/red-01-vs-base.txt | cdbd0c6ab4c33a1e6982d42ebdeaa78fb3c5e4a013a624f9d2d891e2206ab8eb |
| red-02-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-9a/red-02-corrective.txt | d713223bf8654eec171f1eb0cf70680d216c3be281661d304ed53b99d0a10ff0 |

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
