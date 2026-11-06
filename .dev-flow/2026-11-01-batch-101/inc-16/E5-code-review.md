# Inc 16 — E5 independent code review

**Verdict: PASS-WITH-NOTES.** 0 BLOCKER, 0 HIGH, 0 MAJOR, 5 MINOR, 6 NIT. No HIGH is open, so no fix is owed before advance; the MINOR rows are recommendations for a fix pass or for the briefs of later increments.

Reviewer: `code-reviewer` (independent of the E4 units, the tester and the integrator; read-only, no fix applied).
Scope: `git diff c2cba35 d461d0f` on branch `b101-inc16` (84 paths: 33 `.fast-dev-flow/` removals, 3 renames into `.dev-flow/design/archive/`, 1 new archive file, 4 other removals, 9 edited documents, 2 comment-only source files, 8 comment-only test files, `tests/test_id_registry.py`, the widened `tests/test_docs_canon.py`, the new `tests/test_b101_doc_hygiene.py`, and the increment records), read against `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md`, `E4-integration-notes.md` (incl. I-1) and the E4 unit and tester notes.

**Security lens carried here.** There is no separate security reviewer for this docs increment; this review carries that lens (public-repository identity leaks, removed files that something still reads, comment edits that change code).

Method: reading and read-only scans only. Nothing that imports `s19_app` ran on Windows; no pytest ran. Scripts were plain `git` and `python -I` over text and ASTs.

## Checks run

| # | Check | Result | State |
|---|---|---|---|
| C-1 | Added lines of the whole diff (3,473) scanned for home and profile paths, drive-letter cloud-folder paths, the local account name, host names, LAN addresses, `user@host` prompts, UNC paths | 0 hits. The transcripts use `<user>`, `<HOME>` and "LAN Linux host 2". The `My Drive` hits are the guard's own regex and the CTX text | executed |
| C-2 | D-8 redaction: `PENDIENTES-batch96.md:3` in the moved copy | now `<operator drive>/Scan_…pdf`. Rename similarity is 98 % (the only changed line is `:3`). The old path stays in git history, which was already public | executed |
| C-3 | The 4 files of `.dev-flow/design/archive/` scanned with the C-1 patterns | 0 hits | executed |
| C-4 | Readers of removed or moved paths (`.fast-dev-flow`, `docs/diagrams/architecture.md`, `REQ-crc.md`, the two example `.txt`, the CRC draft, `tools/synth/VERIFY.md`, `PENDIENTES`) in `tests/`, `tools/`, `.github/`, `s19_app/`, `setup.py`, `pyproject.toml` | No reader. `tools/id_registry.py:724` and `tools/seed_id_registry.py:348` skip an absent folder (`if not base.exists()`). No `MANIFEST.in` and no package-data rule, so `REQ-crc.md` was never packaged. The `s19_sample.s19` that tests read is a different file from the removed `.txt`. `PENDIENTES` is cited only by bare name (D-5) | executed |
| C-5 | Comment-only edits: base vs head token streams (COMMENT/NL dropped, docstrings masked) and `ast.dump` with docstrings masked, for the 2 source files and 8 test files | 10/10 identical by both measures. Line counts are unchanged. `tests/test_id_registry.py` differs only in `262 → 263` (+1 comment line) | executed |
| C-6 | R-DOC-ARCHIVE.2/1: every non-blank line removed from `docs/architecture.md` is present in the archive file | 366 of 372 present. The 6 that are absent are in §1, §2, §8 and §9 (corrected in place), outside the row's §10/§11/amendment scope, so the row holds | executed |
| C-7 | R-DOC-ARCHIVE.1/2: `git log --follow` of the 3 archive paths | each lists the 2 pre-increment commits plus the move | executed |
| C-8 | Doc claims against the code: `[project.scripts]`, `dependencies`, `cli.py` sub-parsers and positionals (I-1 order), `tui-ci.yml` branches, lanes and PR `slow` filter, `RAIL_ENTRIES` + `RAIL_ENTRIES_B94` order and labels, `=` / `]` bindings, `render/hexview.py` and `render/format.py` imports and exports, `tui/__init__` re-exports, `render.format` and `flow_screens` consumers, `find_repo_root` and the test helper's fallback, `WINDOW_KEYS` (13 windows) | all hold, except F-1 | executed |
| C-9 | §11 anchors spot-checked beyond the integrator's list (36 symbols: `predict_placement`, `contained_in_workarea`, `find_identical`, `place_into_workarea`, `rederive_for_save`, `emit_and_verify`, `mark_saved`, `differs_from_last_saved`, `plan_project_save`, `_resolve_manifest_entry`, `begin_busy`/`step_busy`/`end_busy`, `_session_snapshot`, `LoadChoice`, `ModeToggle`, `confirmed_blocks`, `render_confirm_error`, `verify_written_image` in the WRITE-OUT arm, the chip-family functions and others) | all present | executed |
| C-10 | `docs/README.md` against the tree | links all 12 CTX-DOCINDEX entries and nothing that does not exist. `docs/images/` is excluded by definition | executed |
| C-11 | All 49 repository documents decode as UTF-8, so no document is silently left out of the scans | 49/49 | executed |
| C-12 | Guards vs later increments: the Inc 5 branch (`app.py`, `screens_directionb.py`, user guide ch10, 2 new tests), the Inc 15 branch (`test_suite_hygiene.py`, `engineering-rules.md`) and the `batch-103` branch, scanned for retired needles, paths, CDFX, `s19tool` and `tui/hexview` | 0 hits. Inc 15 leaves `_REDACTION_PATTERNS` / `_PLACEHOLDER` untouched, so ARCHIVE.4's AST read stays valid. Inc 5's two new test files will need a second `EXPECTED_SCANNED_TEST_FILES` re-measure at merge (routine). Incs 6, 9, 10 and 12 have no branch yet; see F-4 | executed |
| C-13 | ARCH.1/2 (validator V8 orphan scan), ARCHIVE.2/2 (Atlas id census) | not run by this reviewer | not-run |

## Findings

### F-1 — `docs/architecture.md` §8 states a wrong runtime dependency set and an incomplete marker list  [MINOR · design-gap]
- **What:** `:163` says "the runtime dependency set (`rich`, `textual`) is unchanged". `pyproject.toml` declares `markdown-it-py>=3` as a third runtime dependency (since batch-60), and this increment aligned `requirements.txt` to those three (DEV.8). `:154-157` "Markers (registered in `pyproject.toml`)" lists `slow` and `snapshot` and leaves out `serial_timing`, which `pyproject.toml` registers and both CI lanes use.
- **Why it matters:** US-DOC-HYG-2 asks that the developer documents state the runtime dependencies of the 1.0.0 tree, and this file is edited by the increment. No row covers §8, so the false claim survives the hygiene pass.
- **Fix:** "(`rich`, `textual`, `markdown-it-py`)". Add a `serial_timing` bullet ("a wall-clock timing arm; lane 2 runs these serially"). Optionally widen DEV.8's oracle to this sentence.

### F-2 — Census anchors written as equalities make tree-computed guards fail on a legitimate change  [MINOR · impl]
- **What:** `tests/test_b101_doc_hygiene.py:672` has `assert len(declared) == 3` (runtime deps). `:880` has `assert len(folders) == 15` (example cases).
- **Why it matters:** DEV.15 is "computed from the tree" and DEV.8 is a set equality. Suppose a later increment adds a fourth dependency to both files, or adds `case_09_*` and lists it in the manifest. The docs are then correct and the guard still goes RED, which blocks a correct change. (`:990` `len(rows) == 3` for the sub-module table follows R-DOC-ARCH.4's "3/3"; that is a requirement choice, noted only.)
- **Fix:** keep a non-empty anchor and drop the exact count, e.g. `assert declared, ...` and `assert len(folders) >= 15, ...` (or `assert folders`). The set equality and the missing-entry check stay the oracle.

### F-3 — DEV.11 does not bind the labels to the window list  [MINOR · design-gap]
- **What:** `test_r_doc_dev_11_1_overview_names_every_window` (`:750-758`) checks each label as a substring of all of §3. Four of the 13 labels (`Memory Map`, `Patch Editor`, `Flow Builder`, `CRC Designer`) also occur in other §3 bullets. Deleting any of them from the shell bullet (`docs/overview.md:37`) keeps the test green. Measured by removing the bullet and re-checking §3.
- **Why it matters:** the row's intent is "names each window by its rail label". For 4 of 13 labels the guard cannot fail. The requirement's "appear in §3" is the loose part; the test follows it faithfully.
- **Fix:** check inside the one list item of §3 that holds "rail screens" (the `_list_items` helper already exists). Add a deletion control for `Memory Map`.

### F-4 — ARCH.4/2 constrains how Inc 9 may rewrite the `flow_screens.py` docstring; that docstring is stale meanwhile  [MINOR · design-gap]
- **What:** `:1001-1015` requires every `docs/architecture.md §<n>` citation in `s19_app/tui/flow_screens.py`'s module docstring to land on a section that holds the sub-module table. Inc 9, which owns that docstring rewrite (BACKLOG row added here), would go RED if it cites §11. §11 is where the `flow_screens` module-surface row lives, so that citation would be legitimate. Meanwhile `flow_screens.py:5-10` still cites §10 for "the one declared data edge `flow_screens → services/flow_model`", which §10 now marks `not declared`. That is a stale source claim, known and routed (E1 §5, `BACKLOG-CODE.md`), and the test passes on structure only.
- **Fix:** put both facts in Inc 9's brief. Alternatively relax the check to: the cited section exists, and a §10 citation finds the sub-module table.

### F-5 — `CLAUDE.md` names the hex renderer with a path that reads as tui-relative  [MINOR · impl]
- **What:** `CLAUDE.md:69` writes `` `render/hexview.py` `` under "### TUI layer (`s19_app/tui/`)", where the sibling bullets are tui-relative (`app.py`, `models.py`, `screens.py`, `workspace.py`). A reader resolves it to `s19_app/tui/render/hexview.py`, which does not exist. That is the same kind of wrong-home citation that R-DOC-DEV.4 removes.
- **Fix:** `` `s19_app/render/hexview.py` (outside `tui/`) ``. DEV.4/2 still passes because it matches the substring `render/hexview.py`.

### F-6 — `docs/README.md` row for the architecture map  [NIT · impl]
- `:14` lists "path / XML / JSON safety". XML safety exists only as a historic note (`docs/architecture.md:134`, CDFX removed). The row also omits §10/§11 (module map, interface contracts), the part the flow reads. Suggested: "… path / JSON safety, engine invariant, testing, module map (§10) and interface contracts (§11)".

### F-7 — Reworded test comments leave citations to an unnamed spec  [NIT · impl]
- `tests/test_tui_evidence_packs.py:3-4` "Spec §3 AC-B1/AC-B2.", `tests/test_tui_report_seam.py:3-4` "Spec §3 AC-A1/A2/A3." and `tests/test_tui_directionb.py:7577-7578` "See §AC-5." now cite a section of a document they no longer name. A wording that names it as retired passes REF.3/REF.4 (no path, a removal mark), e.g. "the audit-gaps follow-up spec of 2026-06-24 (retired workflow, removed; in git history) §3 AC-B1/AC-B2".

### F-8 — One definition, several copies  [NIT · impl]
- `tests/test_docs_canon.py:98-124` re-implements the CTX-DOCHYG "repository document" list and the removal-mark regex that `tests/test_b101_doc_hygiene.py:104-128` also defines. `tests/test_b101_doc_hygiene.py:1194-1208` copies `_local_account_and_host_names` from `tests/test_suite_hygiene.py:1955-1970`, while the same file reads `_REDACTION_PATTERNS` from that module by AST "so no drift". Two copies of one definition can drift silently. Either share one helper module, or add a one-line "keep equal to …" cross-reference at each copy.

### F-9 — The local-name arm gives a false RED under a `root` account  [NIT · design-gap]
- The arm excludes only `runner`. In a container that runs as root, `Path.home().name` / `USER` is `root`, and ARCHIVE.4/1 reports 11 ordinary words in the archive ("a root, a colon", "repo root"). The same exposure exists in `tests/test_suite_hygiene.py`'s helper. The fix is to exclude `root` beside `runner` in both copies (see F-8).

### F-10 — The examples manifest describes files the tree does not hold  [NIT · impl]
- `examples/case_00_public/MANIFEST.md:29-32` describes `case_08_release_demo` as "~10 MiB S19 image, an identical Intel HEX pair, A2L/MAC, patch and check documents". The folder tracks only `README.txt`; the data is generated. Add: "only `README.txt` is tracked; generate the files with `python tools/synth/make_release_case.py --out examples/case_08_release_demo --seed 20260001 --size-mb 10`".

### F-11 — A dated census stays in the present-tense map  [NIT · design-gap]
- `docs/architecture.md:182-183` "Measured 2026-08-24 … **266 tracked source files**" is the kind of dated count US-DOC-HYG-2 retires. It is honest because it is dated. Dropping the number keeps the sentence true ("every tracked `.py` file is classified below except …").

## What is right (stated so it is not re-litigated)

- I-1 is correctly closed. The four CLI examples match `cli.py` (`<command> <file>`), and DEV.2/1 kills both wrong forms.
- The CI sentence matches `tui-ci.yml`, including the PR `slow` filter (I-2).
- The §10 sub-module facts and the §11 rows checked (C-8, C-9) hold on the tree. The `render.format` surface now lists what is actually consumed (I-3).
- The guard probes are assembled from parts. The guard file passes its own REF.3/REF.4 scans, and the exemptions are keyed by file and text (and line for X-2), each with a leak control.
- RED-on-base is shown for 38 of 45 nodes (`red-01-tester-base.txt`). The 7 green nodes are instrument checks plus ARCH.1, whose base was already "Yes". The integrator added 5 mutant kills (`int-04.txt`).

## Observation outside this diff (for the orchestrator, not a finding of Inc 16)

48 tracked files under `.dev-flow/` hold a drive-letter cloud-folder path and 14 hold the local account name. Examples are the `state-snapshot-at-close.json` of batches 05–17 and the batch-102 evidence transcripts. None is outside `.dev-flow/` and none is added by this diff. The repository is public. A redaction pass belongs in the backlog, next to the `BACKLOG-CODE.md` item the integrator already flagged; `test_r_tst_070_2` does not cover those folders.

## Evidence checklist

- [x] Diff read in full: `git diff c2cba35 d461d0f`, all 84 paths. The 33 `.fast-dev-flow/` deletions were checked by name and by reader search (C-4), not line by line.
- [x] Correctness pass: doc claims against `pyproject.toml`, `cli.py`, `rail.py`/`app.py`, `tui-ci.yml`, `render/*`, `tui/__init__.py`, `window_help.py`, `workspace.py` (C-8, C-9). Found F-1 and F-5.
- [x] Simplicity pass: the guards use one helper per concern. F-2 records an over-constraint.
- [x] Reuse / duplication: F-8.
- [x] Tests reviewed for intent: each node's oracle was read against its row, its controls and the RED-on-base transcript. Found F-2, F-3 and F-4.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH or BLOCKER exists, so no applied-and-verified evidence is owed.

## Independent review cell (§4b)

`code-reviewer` · PASS-WITH-NOTES · no HIGH raised (0 BLOCKER / 0 HIGH / 0 MAJOR); 5 MINOR (F-1 … F-5) and 6 NIT (F-6 … F-11) are recommendations, open, for a fix pass or the Inc 9 brief (F-4); security lens carried here (diff clean, C-1 … C-5).
