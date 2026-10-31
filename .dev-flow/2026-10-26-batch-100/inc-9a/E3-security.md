# E3 — security review of the Inc 9a design (PDR, no code), round 1

| Field | Value |
|---|---|
| **Reviewer** | `security-reviewer`, independent, read-only toward the design and the source |
| **Subject** | `E1-scope.md`, `E1-rulings.md` (Q1–Q9, C1–C8), `codewire/interfaces-9a.md` with the orchestrator's rulings on P9a-G1-1…6 and G2 P-1…P-4, F-5 (a ruling wins over a prototype line), `codewire/proto-9a-workspace.md` (G1), `codewire/proto-9a-app.md` (G2), `codewire/baseline-9a.md`, `codewire/baseline-notes.md`; requirements HLR-172, HLR-172a, HLR-172b, LLR-172.1…172.6a, AT-B100-12, AT-B100-13 in `01-requirements.md`; premises S-01, S-06, S-07, S-12, S-16 (`design/P2-security-r1.md` rows, `02-review.md`, `01-requirements.md` §6.3). |
| **Execution** | Design read, plus read-only checks of the code at `4fef292` (worktree `C:\Users\jjgh8\Github\s19_app-b100-inc9a`). Two executed probes in a session scratch folder, removed afterwards: P1 (`python -I`, Python 3.12.7, win32, no repository code) and P2 (s19env Python, `-I`, worktree on `sys.path`; first line printed `s19_app\__init__.py` under the worktree). No source, test, requirement or graph was edited; nothing was committed. |
| **VERDICT** | **`FAIL`** for this E3 round: 0 HIGH, **1 MAJOR open** (S9-1), 2 MINOR, 3 LOW. PLAN E3 requires no open MAJOR. S9-1 reopens S-01 through Windows name spellings the design does not fold; its fix removes the typed spelling as a project name instead of guarding more spellings. The store design (S-06, S-07, S-12, S-16) holds. This verdict authorises nothing beyond E3. |

## 1 · Executed evidence

**P1 — spellings of a reserved home** (OS only; `W` = a scratch work area holding `temp\f.s19` and `templates\t.s19`, on `C:`):

| typed component | `os.path.abspath` keeps | `os.lstat` | `os.listdir` | a write of `<spelling>\project.json` lands in |
|---|---|---|---|---|
| `temp::$INDEX_ALLOCATION` | `temp::$INDEX_ALLOCATION` | folder, not a reparse point | `['f.s19']` | `W\temp\project.json` |
| `temp:$I30:$INDEX_ALLOCATION` | same text | folder, not a reparse point | `['f.s19']` | `W\temp\project.json` |
| `temp::$DATA` | same text | `PermissionError` | `NotADirectoryError` | refused |
| `temp.` / `temp ` | `temp` (both folded) | folder | — | `W\temp` |
| `TEMPLA~1` (8.3 name of `templates`; `GetShortPathNameW` returned it) | `TEMPLA~1` | folder | `['t.s19']` | `W\templates\project.json` |

Also: `os.path.isabs("\\x")` → `True` (root-relative counts as absolute on 3.12); `"a\udc80b.s19".encode("utf-8")` → `UnicodeEncodeError`; `PurePosixPath(r"C:\t\lad").is_absolute()` → `False` and `/ "s19_app"` gives the relative `C:\t\lad/s19_app`.

**P2 — the same spellings against the repository predicates** the typed route and `_handle_load_project` rely on (`W / name`): for `temp::$INDEX_ALLOCATION` and `temp:$I30:$INDEX_ALLOCATION`: parent textually `W` → True, `_is_reparse_point` → False, `contained_in_workarea` → True, `validate_project_files` → `([…\temp::$INDEX_ALLOCATION\f.s19], [], None)` (a project by §1.3), the `_is_reserved_home` rule (`rstrip(" .").casefold()` in the folded set) → **False**. `TEMP` → reserved True (control).

**Read-only source checks:** `resolve_input_path` (`workspace.py:2020`) returns an existing candidate unchanged and resolves only in the base / repo fallbacks; `_project_folder_refusal` (`app.py:12116`) checks textual parent, `lstat` link bit and containment, never the name's form; `safe_text` (`utils.py:41-44`) removes C0/C1 only; `painted_names` (`project_gather_service.py:965`) removes Cc/Cf/Zl/Zp and replaces surrogates (8b S3R2-4); no test fixture of module/session scope drives a load (grep: 0), so the C8 autouse fixture covers today's suite.

## 2 · Findings

| id | severity | graph line / requirement | attack (concrete) | design fix (prefer removal) |
|---|---|---|---|---|
| **S9-1** | **MAJOR** | G2 `_typed_load_route` steps (2), (8)–(11); `_is_reserved_home`; `_handle_load_project` new step; LLR-172.5b, LLR-172.5g (S-01) | Typed `<W>\temp::$INDEX_ALLOCATION` (or `temp:$I30:$INDEX_ALLOCATION`): `abspath` keeps the text, the link walk sees a plain folder, one component, `_is_reserved_home` False, `_project_folder_refusal` None, §1.3 content test True (P2) → `_route_load_project("temp::$INDEX_ALLOCATION")` loads `W\temp` as a project; a later Save project writes `project.json` into `temp` (the OS write executed in P1; not run through the app). Same with `W\TEMPLA~1` for `templates` on any volume with 8.3 names (C: here). R-2's case spelling (`W\AB` saved as `AB`) is the same root cause. | Remove the typed spelling as a project name: after the walk, take one `os.scandir(W)` and route only when the typed component matches an entry whose name `list_projects` would list (`normcase` equality on the entry name); route **the on-disk entry name**, never the typed text. `_handle_load_project` gains the same rule (refuse a name not among the plain, non-reserved entries of `W`) instead of more spelling folds. Examples: the two stream spellings, `TEMPLA~1`, `temp.`, `temp ` → `not a project`, 0 loads, 0 writes; `W\AB` → project `ab`. Add the arms to LLR-172.5b / .5g. |
| S9-2 | MINOR | G2 `refresh_files` step (3) `Label(safe_text(p.name))`; HLR-172b, LLR-172.6 (S-06) | A file in `W\temp` named with an unpaired surrogate (`a\udc80b.s19`, legal on NTFS; it lands there by an ordinary Load copy) passes `safe_text`; its UTF-8 encode raises (P1), and `refresh_files` runs at `on_mount` and after every load, so the paint can fail on each start while the file stays (crash not run in the TUI). `x\u202egpj.s19` (bidi) also passes and reorders the row (SEC8a-4 / S3R2-4 class); the graph checks Cc only. | Paint the label through the project's one category scrub (`painted_names([p.name])`, Cc/Cf/Zl/Zp removed, surrogate → U+FFFD) rather than `safe_text`; `item.data` keeps the on-disk name (C5 unchanged). Examples: U+DC80, U+202E rows → 0 Cs, 0 Cf, 0 raises; mutant `safe_text` → RED. |
| S9-3 | MINOR | G1 `recent_store_path` (regex `^[A-Za-z]:[\\/]`, D-1); LLR-172.1, LLR-172.1f; C8 | Off Windows the regex accepts `C:\t\lad`, which is a **relative** POSIX path (P1): the store lands at `./C:\t\lad/s19_app/recent_sources.json` in the working folder, possibly the base folder or the repository, against LLR-172.1f and "0 under base". A test that copies the graph's literal `<lad>` = `C:\t\lad` writes there on Linux, and on Windows writes the real `C:\t\lad` outside `tmp_path`. | Turn the store off when `sys.platform != "win32"` (P9a-G1-6 already makes write arms Windows-only), and require `Path(value).is_absolute()` as well. Examples: `C:\t\lad` on POSIX → `None`, 0 files. Tester note: every fixture value derives from `tmp_path`, never a literal drive path. |
| S9-4 | LOW | G1 `read_recent_sources` step (2); U-8; LLR-172.1g | The reader opens the store with no link check (the folder check sits only in `record_recent_source`, and only on the folder). A store file (or a folder symlink) pointing at `\\host\share\x` makes every outside load (record → read) open it: an outbound SMB authentication per load; 9b's dialog read inherits it. Needs same-user write in `%LOCALAPPDATA%` (and symlink rights). | In `read_recent_sources`, `lstat` the folder and the file first; a link or reparse point → `((), None)`, no open. Reverse U-8. Example: store file a symlink → 0 opens of the target. |
| S9-5 | LOW | G1 `record_recent_source` step (5) `mkdir(parents=True)` then `_is_reparse_point` | `parents=True` creates every missing ancestor of `LOCALAPPDATA` (a value naming an absent or removable drive path gets folders made). Same-user race: the folder swapped for a junction between the check and `mkstemp` / `os.replace`. | `mkdir(parents=False)`: `LOCALAPPDATA` itself must exist, else `False`. Race accepted (same user, as 8a pre-ruling 11). |
| S9-6 | LOW | Ruling on F-5 ("project route only for an ABSOLUTE typed path"), G2 `_typed_load_route` step (1) | The graph still calls `resolve_input_path` before any absolute test, and "absolute" is not pinned: `os.path.isabs("\\x")` is True (P1), while `resolve_input_path` treats `\x` as relative and its fallback `(base_dir / candidate).resolve()` follows a junction (`\t\base\.s19tool\workarea\alias` typed from another drive → `W\ab`), so the link refusal is skipped. Impact: the junction's target inside `W` loads; no containment breach. | Test the raw typed text with the store's drive-rooted predicate before step (1); anything else keeps the file route and never reaches the project branch. Example: `\…\workarea\alias` → file route → `not a supported file`. |

## 3 · Threat checklist

| surface | state | where |
|---|---|---|
| Store: UNC, `\\?\`, `\\.\`, root-only, drive-relative entries | covered (S-07) | `_recent_entry_ok` check (3), 6 examples + `is_absolute` mutant |
| Store: device names, control characters, kind/suffix, ADS `a.s19:ads` | covered (S-06, S-07) | checks (2), (4), (5); suffix `.s19:ads` → `None` |
| Store: oversized, deep nesting (`RecursionError`), BOM, `true`/`1.0`, huge ints | covered: one `read(65 537)`, `(ValueError, RecursionError)` + outer guard (R-4, R-5); an over-long integer raises `ValueError` | `read_recent_sources` (3)–(6) |
| Store: staging, atomic replace, writer above the reader's cap | covered (S-12; P9a-G1-3 accepted) | `_encode_recent_store`, record (9) |
| Store: link folder | covered for the writer; reader and file link **S9-4** | record (5) |
| Store: TOCTOU, two processes | accepted (same user; last writer wins, never a broken file) | R-8, S9-5 |
| Recorded path auto-opened or sent to the network | none at 9a: `read_recent_sources` has 0 app callers; stored texts are never resolved or stat'ed; only the just-copied source is resolved | G1 RecentEntry, record (7); LLR-173.4 rule for 9b |
| Typed route: junction in any component after `W`, `..`, case of `W`, trailing dot/space | covered (lexical `abspath`, walk before resolve, C2) | `_typed_load_route` (2), (6); examples |
| Typed route: stream names, 8.3 names, typed spelling as project name | **missing → S9-1** | — |
| Typed route: UNC, `\\?\W`, junction into `W` from outside | refused as `outside` (fail closed; R-7, R-9) | step (4) |
| Typed route: relative / root-relative through the resolving fallback | **S9-6** | ruling F-5 |
| Markup in Workarea Files rows and status lines | covered for markup and C0/C1 (`safe_text`; status via `painted_names`); Cs/Cf in rows **S9-2** | `refresh_files`, dispatcher |
| Privacy: entries in projects, reports, logs, work area | covered: G1 logs no path (R-9); G2 logs the loaded source only (already logged at `copy_started`); LLR-172.3 arms 1–2; per-user `%LOCALAPPDATA%` (S-16) | record, read, `load_from_path` |
| Tests / tools writing the real store (C8) | covered: autouse fixture, read-time env (P-3), session digest guard, two tools set `LOCALAPPDATA`, no broader-scope load fixture today; literal fixture paths **S9-3** | G2 §C8 |

## 4 · Checklist

- [x] Every finding has a graph line or requirement, a concrete attack and a fix: S9-1 … S9-6.
- [x] Severities: 0 HIGH, 1 MAJOR (S9-1), 2 MINOR (S9-2, S9-3), 3 LOW (S9-4 … S9-6).
- [x] Probes ran in scratch and were removed; P2 imported the worktree (first line).
- [x] No secret values, dependencies or external tools in the design.

## Round 2

| Field | Value |
|---|---|
| **Scope** | Narrow re-review after the fix pass (LED .83): `E3-rulings.md` R1–R7, R3 in full; `01-requirements.md` (LLR-172.1f, .1k, .1l, .2c, .5b, .5g, .5h, HLR-172a note); `codewire/proto-9a-workspace.md` (G1), `codewire/proto-9a-app.md` (G2, steps 0–11, `_handle_load_project` step, R-11). |
| **Execution** | Code read at `4fef292` (`list_projects` `app.py:12057-12087`, `resolve_input_path` `workspace.py:2020`, `painted_names`). Two probes in a session scratch folder, removed afterwards: R2-P1 (system Python 3.12.7, `-I`, no repository code): folders `temp.`, `temp `, `ab.`, `CON`, `nul` made through `\?\`; R2-P2 (a conda Python with Textual, `-I`, worktree first on `sys.path`, first line printed `s19_app\__init__.py` under the worktree): the real `S19TuiApp.list_projects` on a work area holding `temp\f.s19`, `ab\a.s19` and a `\?\`-made `temp.`. Nothing in the repository edited except this section; nothing committed. |
| **VERDICT** | **`PASS`** for E3 round 2: 0 HIGH, **0 MAJOR open**, 0 MINOR open, 1 new LOW (S9R2-1, backlog accepted). This verdict authorises nothing beyond E3. |

**Executed evidence (R2-P2, real `list_projects`):** listed `['ab', 'temp.']` (`temp` excluded). Typed route match (abspath name vs listing, normcase): `temp::$INDEX_ALLOCATION` → no match; `TEMPLA~1` → no match; `temp.` → abspath name `temp` → no match; `TEMP` → no match; `AB` → `ab`. Handler match (raw name vs listing): the same, except `"temp."` matches the literal `temp.` entry, and `W/"temp."` opens `['f.s19']`, the content of `temp` (R-11 reproduced). R2-P1: `W\CON` and `W\temp ` address their own folders (no alias); `nul` is not `is_dir` (not listed); `ab.` opens `ab`.

### Status per round-1 finding

| id | ruling | status | evidence |
|---|---|---|---|
| S9-1 MAJOR | R3 | **closed** (`approved`) | G2 step (9) and the `_handle_load_project` step match against one `list_projects` listing and continue with the on-disk name; R2-P2 shows 0 matches for the stream, 8.3, trailing-dot and case spellings of a reserved home on both paths, and `AB` → `ab` (R-2 closed). `list_projects` excludes all 9 homes by case-folded on-disk name and yields long names only. Matching by listing also covers spellings round 1 did not name (e.g. a Unicode case alias that NTFS upcases to a home name): nothing unlisted is ever loaded. Arms are in LLR-172.5b / .5g. |
| S9-2 MINOR | R4 | closed as ruled | G2 `refresh_files` (3): `Label(safe_text(painted_names([p.name])))`, `data = p.name`; `painted_names` returns `str` with Cc/Cf/Zl/Zp removed and Cs → U+FFFD; LLR-172.6a negative control present. |
| S9-3 MINOR | R5 | closed as ruled | G1 `recent_store_path`: regex on every platform; POSIX `tmp_path` values → `None` (LLR-172.1f arms, tester note "derive from `tmp_path`"). Residual accepted: a hand-set POSIX `LOCALAPPDATA` of `C:\…` text still names a relative folder; contrived, same user, not a test path. |
| S9-4 LOW | R6 | closed as ruled | G1 read step (1b): link folder or file → `could not be read`, 0 opens; LLR-172.2c arms + negative control; record then writes nothing (LLR-172.1k). |
| S9-5 LOW | R7 | closed as ruled | G1 record (5) `mkdir(parents=False)`; absent `LOCALAPPDATA` → `False`, 0 folders; negative control `parents=True` → RED. Race accepted. |
| S9-6 LOW | R2 | closed | G2 step (0): `Path(text).is_absolute()` false → file branch only; `\x`, `C:x` relative; a relative folder → `not a supported file` (LLR-172.5h). `resolve_input_path` returns an absolute candidate unchanged or `None` (its resolving fallbacks are under `not candidate.is_absolute()`), so no junction-following resolve feeds the project route. |

### Checks of the fix-pass edits (no new HIGH/MAJOR)

- **R1 (`os.path.abspath` recording):** lexical, no network, no link followed; a `\?\`, UNC, stream (`x.s19::$DATA` fails the kind/suffix check), device or control-character source fails `_recent_entry_ok` and is not recorded (LLR-172.1l), so the writer stores nothing the reader drops. Stored texts are never opened or resolved at 9a; the 9b reopen must re-run the link and containment checks on the stored text (LLR-173.4 rule, unchanged).
- **R2 (absolute-only route):** `\?\W\…`, `\.\…` and UNC are absolute, then fail the `normcase` prefix test → `outside` (fail closed). `~\…` is relative before `expanduser`, so it keeps the file route.
- **R3 dependency:** `list_projects` is now the only reserved-home guard on both project paths; its one gap is S9R2-1.

### New findings

| id | severity | location | issue | fix |
|---|---|---|---|---|
| S9R2-1 | LOW (backlog accepted) | `list_projects` (`app.py:12078-12086`, unchanged at 9a); G2 design risk R-11; LLR-172.5g arm `"temp."` | A folder literally named `temp.` (only made through `\?\` or a non-Win32 tool) is listed (R2-P2) and, when picked, `W/"temp."` opens `W\temp` through Win32 name rules: its files load as a project, and a later Save project targets `temp`. Same class for `ab.` aliasing `ab` (confusion only). Pre-existing at `4fef292` in the Load project dialog; typing cannot reach it (abspath folds the dot; `\?\` is `outside`). Not MAJOR: needs an out-of-band folder made by someone who can already write `W\temp` directly, plus an operator pick; no containment or privilege boundary crossed. The LLR-172.5g `"temp."` arm holds only while no literal `temp.` folder exists; the test must not create one. | Backlog, as R-11 recommends: `list_projects` skips an entry whose name differs from `name.rstrip(" .")` (one condition, same rule as LLR-171.1k). Example: `\?\`-made `temp.` and `ab.` → not listed; `_handle_load_project("temp.")` → `not a project`; negative control without the condition → `temp.` listed → RED. Cheap enough to fold into 9a if the source budget allows; not a gate condition. |

### Checklist (round 2)

- [x] S9-1 re-probed against the R3 rule with the real `list_projects` (R2-P2): stream, 8.3, trailing dot, case → 0 matches.
- [x] R4–R7 each found in G1/G2/requirements with an arm and a negative control.
- [x] R1, R2 edits checked: no new HIGH or MAJOR.
- [x] Probes ran in scratch and were removed; no secret values in this record.
