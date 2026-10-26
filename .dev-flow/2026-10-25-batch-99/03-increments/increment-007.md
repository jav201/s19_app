# Increment 007 — HLR-162 · `Project and work-area pickers load by name`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `007` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-151 / HLR-162 / LLR-162.1 · LLR-162.2 · LLR-162.3` |
| Acceptance | `AT-B99-13` · white-box `TC-B99-34 · TC-B99-35 · TC-B99-36` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: both pickers now load **by name**, and the project list holds **no
reserved home** (design-proposal §4 row B99-I9). Concretely:

- `tui/workspace.py` gains the closed tuple `RESERVED_WORKAREA_HOMES`
  (LLR-162.2): `temp`, `patches`, `templates`, `logs`, `crc`, `flows`,
  `flowsets`, `splits`, `reports`. The writer census (below) confirms only
  `temp` and `patches` are created **directly under the work area**
  (`ensure_workarea`, `workspace.py:85-86`); `templates` / `logs` live under
  `.s19tool/`, and `crc` / `flows` / `flowsets` / `splits` / `reports` are
  per-project homes (`CRC_OUTPUT_SUBDIR`, `FLOWS_SUBDIR`, `FLOWSETS_SUBDIR`,
  `SPLITS_DIR`, `REPORTS_DIR_NAME`). No ninth+ home exists, so the LLR's
  closed set stands unchanged.
- `S19TuiApp.list_projects` (`app.py`) now omits every name in the tuple —
  previously only `temp` was skipped, so `patches` (and any future reserved
  home) presented as a project (premise P-20).
- `S19TuiApp.refresh_files` (`app.py`) now lists the **regular files of
  `workarea/temp`** — the folder every file load copies into
  (`load_from_path` / `load_a2l_from_path` → `copy_into_workarea(..,
  self.workarea / WORKAREA_TEMP)`) — never the work-area root (CW-U-3: the
  old listing read a folder loads never write to) and never `temp/.staging`
  (a directory; `is_file()` excludes it, and its contents sit two levels
  below `temp/*`). Each `ListItem` now carries its file name on `item.data`
  — the codebase's existing stored-payload idiom (`app.py` sets `item.data`
  for section rows, A2L filters, settings and the command bar).
- `S19TuiApp._load_from_item` (`app.py`) reads the stored name back from
  `item.data` and resolves it against `workarea/temp` — never
  `str(Label)` (CW-U-1 / P-19: Textual 8.2.8 `Label` has no `.text`, so the
  old code resolved every pick to `"Label()"` and loaded nothing).

Shipped surface the user reaches: the Load project dialog (`#project_list`,
`#project_ok`) and the Workarea Files list (`#files_list`).

Out of scope, per the brief: enter-to-load on the list itself (D10) and any
dialog redesign (routed to the Load+projects batch).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/workspace.py` | source | HLR-162, LLR-162.2 | source 1 of 2: `RESERVED_WORKAREA_HOMES` tuple constant (+ doc comment) |
| `s19_app/tui/app.py` | source | HLR-162, LLR-162.1/.2/.3 | source 2 of 2: import the tuple; `list_projects` omits the tuple; `refresh_files` reads `workarea/temp`, stores `entry.data = name`; `_load_from_item` reads `item.data`, resolves against `workarea/temp` |
| `tests/test_b99_load_project.py` | test | HLR-162 | TC-B99-34 (both name arms), TC-B99-35 (populated + reserved-only arms), TC-B99-36 (empty + loaded arms), AT-B99-13 (dialog listing, 3 pick paths, file pick, empty boundary) — 4 nodes |
| `tests/test_id_registry.py` | test | HLR-162 (BRIEF-COMMON rule; +1 = `tests/test_b99_load_project.py`) | `EXPECTED_SCANNED_TEST_FILES` 209 → 210 (the new module), one-line comment |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-007.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-7/*` | doc | — | transcripts, hashes (outside the count) |

SOURCE budget: 2 / 4 used.

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |
| Test files | 2 (uncapped; `test_id_registry.py` is a one-line measured bump) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched; the frozen
  engine layer untouched. Both edited files remain pure CRLF
  (`app.py` 13619 CRLF / 0 LF-only after the edits — re-measured at
  evidence time; `workspace.py` 862 CRLF / 0 LF-only).

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # -> C:\Users\jjgh8\Github\s19_app-b99-inc7\s19_app\__init__.py (proved, this session)
pytest tests/test_b99_load_project.py -q                        # -> 4 passed
pytest tests/test_b99_load_project.py -k tc_b99_34              # -> 1 passed, 3 deselected
pytest tests/test_b99_load_project.py -k tc_b99_35              # -> 1 passed, 3 deselected
pytest tests/test_b99_load_project.py -k tc_b99_36              # -> 1 passed, 3 deselected
pytest tests/test_b99_load_project.py -k at_b99_13              # -> 1 passed, 3 deselected
pytest tests/test_id_registry.py -q                             # -> 13 passed
pytest tests/test_address_census.py -q                          # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — LLR-162.2 rides the TC/AT | n/a |
| **A · white-box** `TC-B99-34/35/36` ↔ LLR-162.1/.2/.3 | `core` · `full` | `test_tc_b99_34_pick_loads_the_picked_file_name` · `test_tc_b99_35_reserved_homes_are_not_projects` · `test_tc_b99_36_workarea_files_reads_the_load_folder` | 3 passed |
| **B · black-box** `AT-B99-13` ↔ US-151, through the Textual pilot | `core` · `full` | `test_at_b99_13_project_and_file_pickers_load_by_name` | 1 passed |

Regression companion (reverse-census files, §4 Reverse census): 8 census
files re-run on the fixed tree (`green-regression.txt`): **390 passed,
1 xfailed, 1 failed** — the single failure is
`test_at_b78_32_app_bindings_block_is_untouched`
(`tests/test_tui_diff_screen.py`), which is **red at the batch baseline
too** (`evidence/baseline-pytest-a293213.txt:255` and `:755`) and pins the
App `BINDINGS` block — a block this increment never touches. No re-pins.

`tests/test_address_census.py` — 23 passed (`green-address-census.txt`,
transcript `green-load-project.txt` for the 4 new nodes + 23 census nodes
run together: 27 passed).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | 3, one per declared negative control — each applied, shown RED, reverted; restore verified by SHA-256 |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 against `fixed-tree-hashes.txt` |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc7`), run by the implementer |
| Transcript | `evidence/inc-7/mut-LLR-162.1.txt` · `mut-LLR-162.2.txt` · `mut-LLR-162.3.txt` |
| Restore proven by | `app.py` back to `0979a4bb81aa…` after every revert (`fixed-tree-hashes.txt`); no mutant left in place |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | all 4 nodes FAILED on the unmodified tree (`red-initial.txt`) — TC-34 `[] == ['a.s19']` (the file is in `temp/`, the old list read the root), TC-35 `ImportError: RESERVED_WORKAREA_HOMES`, TC-36 `[] == ['one.s19']`, AT `['P1', 'P2', 'patches'] == ['P1', 'P2']` — the P-19/P-20/CW-U-3 premises reproduced |
| Arms that stayed GREEN under a mutation | TC-35 and the file-list arms under mut-162.1 (they serve other LLRs) — each mutation run resolves its own target node(s) RED |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED (tests in, tree unmodified): all 4 nodes FAILED on their exact oracles (`red-initial.txt`) |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-162.1 · restore `str(label_widget)` in `_load_from_item` · KILLED — `test_tc_b99_34…`, `test_tc_b99_36…` (pick arm), `test_at_b99_13…` (file-pick arm) FAILED (the pick loads nothing: every name resolves to `Label()`) · transcript `mut-LLR-162.1.txt` · restore `0979a4bb…` ‖ LLR-162.2 · `!= WORKAREA_TEMP` only in `list_projects` · KILLED — `test_tc_b99_35…` (`['P1', 'P2', 'patches']`) and `test_at_b99_13…` (dialog-listing arm) FAILED · transcript `mut-LLR-162.2.txt` · restore `0979a4bb…` ‖ LLR-162.3 · `refresh_files` reads the work-area root (today's behaviour) · KILLED — `test_tc_b99_36…`, `test_tc_b99_34…`, `test_at_b99_13…` (file arms) FAILED (the load folder's files never appear) · transcript `mut-LLR-162.3.txt` · restore `0979a4bb…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the unmodified tree (all 4 nodes) | TC-34/36 `[] == ['a.s19'/'one.s19']`, TC-35 `ImportError`, AT `['P1','P2','patches']` (`red-initial.txt`) |
| `pytest` + TC-B99-34/36, AT file-pick arm | mut LLR-162.1 (`str(Label)` restored) | the pick loads nothing — the `#log_line_3` re-push never happens (`mut-LLR-162.1.txt`) |
| `pytest` + TC-B99-35, AT dialog-listing arm | mut LLR-162.2 (`!= WORKAREA_TEMP` only) | `patches` listed as a project again (`mut-LLR-162.2.txt`) |
| `pytest` + TC-B99-36/34, AT file arms | mut LLR-162.3 (root listing) | the Workarea Files list stays empty after a load (`mut-LLR-162.3.txt`) |
| the Textual pilot (painted `#project_list` / `#files_list` / `#log_line_*`) | the unmodified tree and each mutant | the painted listing / status failed the black-box assertion in every run above |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 5 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the painted Workarea Files list (emitted by `refresh_files`) | TC-34/36 and AT read the `ListItem` Labels' painted text via DOM query | `['a.s19']`, `['a b.s19']`, `['one.s19']` — exactly the loaded file, no `.staging` artefact (`green-tc_b99_34.txt`, `green-tc_b99_36.txt`, `green-at_b99_13.txt`) |
| the painted Load project dialog (emitted by `list_projects` → `LoadProjectScreen`) | AT step 1 reads the `#project_list ListItem` Labels' painted text | `['P1', 'P2']` with the `patches` home present (`green-at_b99_13.txt`) |
| the painted status line (emitted by the app's `set_status`) | AT steps 2/3/4 wait on `#log_line_4` / `#log_line_3` | `Loaded project 'P2' -> firmware.s19` for all three pick paths; the `Loaded <file>` re-push into `#log_line_3` on the file pick; `No saved projects found.` on the empty boundary (`green-at_b99_13.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifact families, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-7/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| GREEN, the new module alone (4 passed; AT-B99-13 also `1 passed` inside it) | `green-module-4.txt` | `21f49b05840a6d836d66d46297cf921c5e1aa07fd75c4cdf32a0f4942a2941d5` |
| RED baseline (unmodified tree, 4 failed) | `red-initial.txt` | `0fb29b9c6e93ced6cdada9ce61358f744473008c2451b940ff0a672b0f571c5e` |
| GREEN full new module + census jointly (27 passed) | `green-load-project.txt` | `26c565fcf1135b41ee51c897f0925632027fb0f430a37a619c481318588d8720` |
| GREEN TC-B99-34 | `green-tc_b99_34.txt` | `5c791fbf6773ab9379093a22d5c8158cd791aba9d8f6c18a3cfe2c426da42f01` |
| GREEN TC-B99-35 | `green-tc_b99_35.txt` | `05c9f480b3281343e40c28127e02dc632497cb69323a47e6a0223d4385870c21` |
| GREEN TC-B99-36 | `green-tc_b99_36.txt` | `6b8a1efeb951fae815a10bad3be8e9d736b752012834ffcc46cdf236f7e9b95a` |
| GREEN AT-B99-13 | `green-at_b99_13.txt` | `4738b60acc0f4d40eb0a5fa54d0aa2e48b9eda18ef1d5a282ec549b9e8809c1c` |
| GREEN address census (23 passed) | `green-address-census.txt` | `04afa43b1f0188246296a98f40de34e5fae147955fe62d1bc102354469a7b832` |
| GREEN id registry (13 passed) | `green-id-registry.txt` | `cd42569e418bf22ac5aff6ddce424a4fc7d526b4839a1e208f427f83c6921b0d` |
| GREEN regression companion (census files: 390 passed, 1 xfailed, 1 pre-existing failure) | `green-regression.txt` | `b70fc7dd857427c330558aef5ccad94fd38f9f861d37787d511795a772ae0326` |
| Mutation LLR-162.1 (KILLED) | `mut-LLR-162.1.txt` | `d124f3181227331d0a5914d05706b6437c73e5a1bc36b7ac91ef811acb5dea5d` |
| Mutation LLR-162.2 (KILLED) | `mut-LLR-162.2.txt` | `8ad32ff85f6326e1b47200f5429d826d2434632602685dc77f9de8ff52f7b7ce` |
| Mutation LLR-162.3 (KILLED) | `mut-LLR-162.3.txt` | `7e5803e24db30d816eda2ee3819c04b3acb0460671a2a33cae292c4ee071c1d2` |
| Fixed-tree hashes (restore target) | `fixed-tree-hashes.txt` | `173f17e419cb75fbcb4245db46ac0e9f626cb075998ab6151874e2c874746d49` |

`SHA256SUMS.txt` is the folder's own digest list; every digest above is of
the stored working-tree bytes.

| Field | Value |
|---|---|
| **Evidence files** | 13 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) no folder beyond the nine reserved homes is ever created directly under the work area (the tuple is a CLOSED set); (2) the empty Workarea Files list at fresh mount |
| If the result is an ABSENCE, what made the search wide enough | (1) writer census: `grep` of every `mkdir` under the work area — `ensure_workarea` (`workspace.py:85-86`) creates only `temp` and `patches` directly under `workarea/`; `templates`/`logs` are created under `.s19tool/` (`ensure_template_lib` / `setup_logging`); `crc`/`flows`/`flowsets`/`splits`/`reports` are per-project homes (`tui/operations/crc.py:989`, `flow_persistence_service.py:99,1123`, `segment_split_view.py:149`, `report_service.py:498`) — no direct work-area creation site exists for them; (2) the fresh-mount emptiness is asserted by TC-B99-36's first arm (`_files_list_names(app) == []`) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | TC-B99-36's empty arm and TC-B99-35's reserved-only arm pin the ABSENT cases directly (0 items / 0 projects) — each is a positive assertion on an empty painted list, not a skipped check |
| Conjunctive criteria: one mutation per conjunct | LLR-162.1's stored name has two conjuncts — WRITE (`refresh_files` stores `entry.data`) and READ (`_load_from_item` reads it, never `str(Label)`) — the declared mutation kills the read side (the write side alone loads nothing without a reader, and the RED baseline shows the absent-tuple case) |
| Synthetic instance of the absent case | each mutant IS the forbidden implementation, existing only transiently and reverted by hash; the RED baseline IS the absent-fix case |

| Field | Value |
|---|---|
| **Positive control for every probe that returned an ABSENCE** | (1) TC-B99-35's populated arm shows the identical `list_projects` probe returning `['P1','P2']` (non-empty); (2) TC-B99-36's loaded arm shows the identical `#files_list` probe returning `['one.s19']` (non-empty); (3) the AT shows all three pick paths producing a non-empty `Loaded project 'P2'` status |

### Reverse census — trigger family B

Probe: `grep -rln "list_projects\|refresh_files\|_load_from_item\|files_list\|project_list" tests/` → 8 files, all re-validated by the regression run (§4) and the per-symbol analysis below. **No test re-pinned** — HLR-162 changes behaviour no existing assertion pinned (each old-pin candidate is analysed below).

| Probe | Command | Result |
|---|---|---|
| B1a `list_projects` pins | `grep -rn "list_projects" tests/` | 3 hits — `test_tui_app.py:367` (`test_list_projects_skips_files_and_sorts_names`: Alpha/Zulu/temp/notes.txt → `['Alpha','Zulu']`) and `test_tui_helpers.py:132` (`test_list_projects_ignores_temp`: ProjectA/ProjectB/temp) pin exactly the behaviour HLR-162 keeps (temp still omitted, user projects still listed) — no re-pin; this increment's TC-B99-35 is the third hit |
| B1b `refresh_files` pins | `grep -rn "refresh_files" tests/` | 2 hits — `test_tui_app.py:71` monkeypatches `refresh_files` (binding-shape test, content-agnostic) and `test_tui_diff_screen.py:3710` pins the `r`-key binding name — neither pins the listed folder — no re-pin |
| B1c `_load_from_item` pins | `grep -rn "_load_from_item" tests/` | none — no re-pin |
| B1d `files_list` pins | `grep -rn "files_list" tests/` | `test_tui_directionb.py:8971` (`test_ac5_files_list_grows_beyond_legacy_cap`) asserts the list's OUTER HEIGHT with a loaded file installed — content-agnostic (elastic-height AC-5/B-06) — no re-pin |
| B1e `project_list` pins | `grep -rn "project_list" tests/` | `test_b97_load_project_dialog.py` (Inc-9: `proj_a`/`proj_b` only — reserved homes absent from its fixture, unchanged) and `test_b99_truncation.py:602` (one project `proj1` — unchanged) — no re-pin |
| B3 golden captures | `grep -rl "files_list\|project_list" tests/goldens/ tests/__snapshots__/` | no snapshot or golden captures either list's content — nothing re-pinned |
| B4 `patches`-as-project pins | `grep -rn "patches" tests/test_b97_load_project_dialog.py tests/test_b99_truncation.py` | none — no test ever pinned `patches` appearing in the dialog |

REGRESSION_RESULT

| Field | Value |
|---|---|
| **Reverse census** | 8-file census executed, 7 per-symbol probes — 0 re-pins; the one regression failure (`test_at_b78_32_app_bindings_block_is_untouched`, App `BINDINGS` block PIN) is pre-existing — red at the batch baseline `baseline-pytest-a293213.txt:255`/`:755` — and untouched by this increment (the `BINDINGS` block has no edit; the increment's only `app.py` line above it is one import line in the workspace-import block) |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| reserved homes must not present as projects | `S19TuiApp.list_projects` (the only project enumerator) | `grep -n "def list_projects" s19_app/tui/app.py` → 1 site; `grep -rn "iterdir" s19_app/tui` → no other project enumerator | 1 | 1 | 0 |
| the Workarea Files list must read the load folder and store names | `S19TuiApp.refresh_files` + `S19TuiApp._load_from_item` (the only `#files_list` writer and its pick handler) | `grep -n "files_list" s19_app/tui/app.py` → compose + `refresh_files` + `on_list_view_selected` dispatch; `_load_from_item` is the only handler | 2 | 2 | 0 |
| the tuple constant | `tui/workspace.py` constants block (the home of `WORKAREA_TEMP` et al.) | the module's own constant idiom | 1 | 1 | 0 |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, 4 sites enumerated before the first edit, 4 edited, 0 left |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| `!= WORKAREA_TEMP` (the P-20 filter) | `grep -rn "!= WORKAREA_TEMP" s19_app/` | yes — no surviving reference; the tuple subsumes it | `s19_app/tui/app.py` `list_projects` now uses `not in RESERVED_WORKAREA_HOMES` |
| `str(label_widget)` (the P-19 pattern) | `grep -rn "str(label_widget)\|hasattr(label_widget" s19_app/` | yes — no surviving reference in the picker path | `s19_app/tui/app.py` `_load_from_item` reads `item.data` |

### Signed-balance test ledger

`post = base − deleted + added` → `4 = 0 − 0 + 4` ✓ reconciles
(`tests/test_b99_load_project.py`: 0 baseline nodes — new file — 0 deleted,
4 added: TC-B99-34, TC-B99-35, TC-B99-36, AT-B99-13). The regression files
changed by 0 nodes — no re-pins. `tests/test_id_registry.py` changed by 0
nodes (a measured constant bump).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · OK to advance with notes (all 3 mutants re-run and killed for the right reason; `RESERVED_WORKAREA_HOMES` complete). F1 MEDIUM (two pass counts with no cited transcript) fixed by the orchestrator with `green-module-4.txt`; F2 LOW comment corrected; F3 LOW (AT reads `app.screen` type / `app.workarea`) and F4 LOW (Save project accepts a reserved name) routed to BACKLOG-CODE; the focus shadowing of `p` after a load is CW-U-2 (Load+projects batch) |

---

## 5 · Risks

- `RESERVED_WORKAREA_HOMES` is a closed set: a future feature that creates a
  new folder directly under the work area must add its name to the tuple or
  the folder will present as a project. The census evidence (§4
  Load-bearing emptiness) shows today's writers are exactly the nine homes.
- `_load_from_item` treats a missing `item.data` as "not a file item" and
  returns silently; only `#files_list` items reach it (`on_list_view_selected`
  dispatches by list id), and `refresh_files` is their only writer — the
  silent return is the empty-list no-op, not a swallowed error.
- The AT's file-pick observation rests on the log rotation (`set_status`
  pushes the newest line into `#log_line_4`, shifting the previous line to
  `#log_line_3`): re-loading the same file repeats the identical status
  text, so the test waits for the previous newest text to appear in
  `#log_line_3` — a fresh-load signal that no static text check could give.
- After a file load the Segment Split window holds focus and binds `p` to
  its own pad cycle, so the `p` rail key does not reach the app in that
  state (pre-existing behaviour, unchanged by this increment). The AT's
  empty-boundary step therefore drives the shipped "Load project (p)"
  button (`#ws_load_project_button`) — the same action, by a real click.

## 6 · Pending items / spec deviations

- None against the brief. The AT empty boundary uses the shipped button
  instead of the `p` key for the reason in §5 (recorded as a drive
  decision, not a requirement deviation — the HLR's observable outcome
  "pressing Load loads nothing and the current file stays loaded" is exactly
  what is asserted).
- Pre-existing, not mine: `test_at_b78_32_app_bindings_block_is_untouched`
  fails at the batch baseline too (`baseline-pytest-a293213.txt`) — an App
  `BINDINGS`-block PIN no increment edit approaches (orchestrator's
  full-suite run owns it).

## 7 · Suggested next task

Batch-99 Increment 8 (per the orchestrator's plan; the remaining B99-I
rows are I8 Bytes grammar, I10 loader notice codes, I11 chain-set start
check, I12 WRITE-OUT verify — the orchestrator owns the ordering).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 SOURCE files (`git status` — `app.py`, `workspace.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_load_project.py` (4 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no layer-0 shipped-source node; LLR-162.1/.2/.3 verified by the TCs/AT |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED `red-initial.txt` (4 failed, exact oracles) + 3 mutations with transcripts + restore digests |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 8-file census, 7 per-symbol probes, 0 re-pins |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — 2 SOURCE + 2 test + this packet + evidence |
| 8 | Frozen interfaces untouched | all | ✓ | engine layer untouched; `LoadProjectScreen` (Inc-9 fix) untouched |
| 9 | Coverage claims verified **on disk** | all | ✓ | every assertion reads painted text / files on disk through the pilot; fixtures are copied per test |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (populated arms of the identical probes) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: 3 mutations, per-target KILLED, no surviving mutant |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 5 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 3 corrections, 4 sites enumerated before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 3 artifact families asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` (the one published form for a not-yet-reviewed packet) |
| 16 | **Evidence files** declared | all | ✓ | §4: 13 artifacts with stored-byte SHA-256 digests |
