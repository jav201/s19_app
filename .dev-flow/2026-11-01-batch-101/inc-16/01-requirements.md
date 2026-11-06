# Inc 16 — documentation hygiene: requirements (E1)

Batch 2026-11-01-batch-101, increment 16 (operator request 2026-11-05: stale, dead and duplicate docs). Base: `c2cba35` (branch `b101-inc16` = local main with Incs 1, 2, 3, 4, 7, 8, 11, 13, 14 merged). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Input: `../p0/doc-inventory.md` (written at `f9f3cb0`), groups D1 … D7 of its section E, every row re-verified on `c2cba35` (`E1-rulings.md` §1 lists the rows dropped or changed). Orchestrator rulings R1 … R5 and the E1 decisions: `E1-rulings.md`. Slice (documents, two comment-only source files, test comments): `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc16.md` (not applicable, with the document change map).

Form column: U = ubiquitous (every row of this increment is U: each states a property the tree holds). Canon rows are cited by their `REQUIREMENTS.md` id; new ids (`R-DOC-REF`, `R-DOC-DEV`, `R-DOC-ARCH`, `R-DOC-ARCHIVE`) were checked absent from `REQUIREMENTS.md`, from every batch-101 worktree's increment folders and from `s19w/review` at `c2cba35`. "Base" = what `c2cba35` holds, read in the files unless a file:line is given; the base counts were measured on Windows by read-only scans of tracked text (no script imported `s19_app`, no test ran).

No screen changes: the only source edits are two comments and one docstring that name removed `prototypes/` files (R4). The guards are new tests in `tests/test_b101_doc_hygiene.py` (new file) and a widened arm of `tests/test_docs_canon.py` (`E1-slice.md` §3).

## User stories

### US-DOC-HYG-1 — a contributor finds only paths, links and commands that exist
As a contributor (a person or an agent) reading the repository's documents and comments, I follow a path, a link or a command and it exists, so I do not chase removed files, retired folders or a console script the package no longer installs.

### US-DOC-HYG-2 — the developer documents describe the shipped app
As a contributor, I read `CLAUDE.md`, `PROJECT_RULES.md`, `docs/engineering-rules.md`, `docs/README.md`, `docs/overview.md`, `docs/architecture.md`, `requirements.txt` and the examples manifest and they state what the 1.0.0 tree is: twelve rail windows, the CI lanes, the hex renderer's home, the runtime dependencies, without dated counts that have gone stale.

### US-DOC-HYG-3 — finished notes leave the living documents, with their history kept
As a contributor, I find finished handoff notes, superseded documents and the retired workflow's folder out of the living documents: notes archived under `.dev-flow/design/archive/` with their git history, superseded and unused files removed (they stay in git history).

## Definitions

### CTX-DOCHYG · Terms of this increment (proposed for S0 at integration, `E1-rulings.md` D-1)

```text
repository document   A tracked file whose name ends in .md, .txt or .rst, except a file
                      under .dev-flow/, docs/requirements/, tests/goldens/ or
                      tests/__snapshots__/, and except REQUIREMENTS.md (S0.3 owns it).
                      56 files at c2cba35 outside .fast-dev-flow/ (whose 33 files go in
                      this increment; the base counts exclude them); 7 of the 56 move
                      or go.
tracked text file     A tracked file git does not mark binary, outside .dev-flow/ and
                      docs/requirements/ (the records and the canon's history keep their
                      words as written).
repository path       A token in a repository document that starts with s19_app/, tests/,
                      tools/, docs/, examples/, prototypes/, .fast-dev-flow/, .github/ or
                      evidence/, preceded by no letter, digit, '.', '/' or '-', and running
                      to the first space, backtick, quote, ')' or ','; a trailing '.', ':',
                      ';' or '/' and a ':<line>' suffix are not part of it.
exists                A repository path exists when it names a tracked file or a folder
                      that holds a tracked file; a path with '*' exists when it matches at
                      least one tracked file (fnmatch; a trailing '/**' matches the folder).
removal mark          One of the words removed, deleted, historic, superseded, legacy,
                      no longer, moot, retired, moved, on the same line, any case (the
                      _HISTORIC words of tests/test_docs_canon.py plus retired and moved).
retired folder        .fast-dev-flow/ (the retired fast-dev-flow workflow's records) and
                      prototypes/ (removed 2026-11-05; the operator keeps it local, ignored).
retired-folder path   A token .fast-dev-flow/<...> or prototypes/<...> preceded by no
                      letter, digit or '_'.
exempt line           A line of the table EXEMPT below; a guard skips it by file and text.
s19tool shape         An occurrence of s19tool that is one of: .s19tool/ or .s19tool\ (the
                      work-area folder), s19tool/ (a path), s19tool.egg-info, `pip <verb>
                      s19tool`, or on a line that holds "Distribution name", "module-only",
                      "runs only as a module", "No `s19tool` console script" or
                      "what remains" (the _S19TOOL_OK shapes of tests/test_docs_canon.py),
                      or a removal mark.
module table          The table under "## 10. Composition" of docs/architecture.md whose
                      header holds "Paths it owns"; a module prefix is a `<folder>/**`
                      token of its "Paths it owns" column.
Python folder         A top-level folder that holds a tracked .py file: .dev-flow, docs,
                      s19_app, tests, tools at c2cba35 (setup.py is a root file, outside
                      every prefix by construction; the map already says so).
archive folder        .dev-flow/design/archive/
```

EXEMPT — lines the retired-folder rows skip, each with its reason (`E1-rulings.md` D-3):

| # | File | Line text (key) | Reason |
|---|---|---|---|
| X-1 | `.gitignore` | `/prototypes/` | An ignore rule for the operator's local prototype rounds, not a citation. |
| X-2 | `AT-TC-REGISTRY.jsonl` | line 1, `"not_scanned": [` | The registry's seed metadata; it equals what `tools/seed_id_registry.py` writes, and a docs increment does not edit the AT/TC authority. |
| X-3 | `tools/seed_id_registry.py` | `"not_scanned": [` and `for folder in (".dev-flow", ".fast-dev-flow"):` | The seeder's metadata (= X-2) and its optional corpus roots; a missing folder is skipped (`if not base.exists()`). |
| X-4 | `tools/id_registry.py` | `for folder in (".dev-flow", ".fast-dev-flow"):` | `iter_corpus` optional corpus roots, skipped when absent; no caller passes `include_devflow=True`. |
| X-5 | `.gitattributes` | `# fast-dev-flow.md is LF)` | Names the retired command file outside this repository in a line-ending note for rollback hashes. |

CTX-DOCINDEX — the entries `docs/README.md` links: every top-level entry of `docs/` except `docs/README.md` itself and `docs/images/` (after this increment: `overview.md`, `architecture.md`, `engineering-rules.md`, `CENSUS-BASELINE-canon-mirror.md`, `requirements/`, `user-guide/`), and the root documents `README.md`, `REQUIREMENTS.md`, `CLAUDE.md`, `PROJECT_RULES.md`, `SECURITY.md`, `CHANGELOG.md`. A link counts for an entry when its target is the entry or a path inside it. Computed from the tree, so a document added to `docs/` later must be indexed.

CTX-ARCHIVE — finished notes and their archive paths (R2; names per `E1-rulings.md` D-5):

| Note at `c2cba35` | Archive path |
|---|---|
| `PENDIENTES-batch96.md` | `.dev-flow/design/archive/PENDIENTES-batch96.md` |
| `docs/crc-algorithm-designer/01-requirements.md` | `.dev-flow/design/archive/crc-algorithm-designer-requirements-draft-2026-07-20.md` |
| `tools/synth/VERIFY.md` | `.dev-flow/design/archive/synth-case08-release-demo-VERIFY.md` |
| `docs/architecture.md` §10–§11 amendment notes and per-batch declarations of batches 88 … 100 (new file, verbatim blocks) | `.dev-flow/design/archive/architecture-batch-declarations-88-100.md` |

CTX-REMOVED — files the tree holds no longer (they stay in git history):

| File(s) | Reason | Ruling |
|---|---|---|
| `.fast-dev-flow/**` (33 tracked files) | retired workflow; no test or tool needs it as a corpus (`E1-rulings.md` §2) | R2 |
| `docs/diagrams/architecture.md` | superseded (header "batch-04", `cdfx/` package, `s19tool` CLI, 8 screens) | R3 |
| `s19_app/tui/operations/requirements/REQ-crc.md` | stale second CRC source; S13 is the one source | CODE-CHANGES D13-17 (S13 D13-17) |
| `examples/case_00_public/from_source_input.txt`, `examples/case_00_public/s19_sample.txt` | read by no test, glob, loader or tool | R5 |

CTX-SUBMOD — the sub-modules inside product that the archived batch-92 and batch-94 declarations created, and the four facts each declaration gives: `s19_app/render/hexview.py`, `s19_app/render/format.py`, `s19_app/tui/flow_screens.py`; facts = what it encapsulates, what it exposes, what it may import, what it must not import.

CTX-IFACE — the current interface contracts of `docs/architecture.md` §11: the three Part B contracts (`loaded_panel`, `screen_workspace`, `workspace_body`), the four batch-92 surfaces (`render.hexview`, `render.format`, `utils.safe_text`, `tui/__init__` re-export) and the five batch-94 surfaces (`PatchEditorPanel.ActionRequested`, `.chk.json` artifact, `flow_screens` module surface, flow template / chain-set artifacts, rail invariant) — 12 contracts.

## Requirements

Columns: Id · Form · Requirement · Pass threshold · Negative control (mutant that turns the guard RED) · US · Base (`c2cba35`).

### US-DOC-HYG-1 — references (all repository documents and comments)

| Id | Form | Requirement | Pass threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-REF.1 | U | The system shall name in its repository documents only repository paths that exist, except on a line that carries a removal mark. **new** | 0 unmarked repository paths that do not exist, over every repository document; the guard reports a synthetic line `see tests/does_not_exist.py` (1/1, instrument check) and passes `see s19_app/tui/hexview.py (removed)` (1/1) | restore `s19_app/tui/hexview.py` at `PROJECT_RULES.md:135` → RED | US-DOC-HYG-1 | No: 22 unmarked (CLAUDE.md:80, PROJECT_RULES.md:135, PENDIENTES-batch96.md:11, :80, docs/architecture.md 10 on 7 lines (:28 ×2, :238, :255, :264, :280 ×2, :422, :424 ×2), docs/diagrams/architecture.md 7, docs/crc-algorithm-designer/01-requirements.md:203; list in `02-test-cases.md` R-DOC-REF.1/1) |
| R-DOC-REF.2 | U | The system shall link in its Markdown repository documents only to files and folders that exist. **new** | 0 broken relative links over every `.md` repository document (base 0 of 249 links); in particular the 5 links to `docs/diagrams/architecture.md` (`README.md:465`, `docs/README.md:15`, `docs/architecture.md:6`, `:59`, `docs/overview.md:94`) are removed or point to `docs/architecture.md` (5/5) | delete `docs/diagrams/architecture.md` and keep `README.md:465` → RED | US-DOC-HYG-1 | Yes today (0/249); it guards the four deletions and three moves of this increment |
| R-DOC-REF.3 | U | The system shall name a retired-folder path in no tracked text file, except on an exempt line. **new** (R2, R4) | 0 retired-folder paths outside the exempt lines X-1 … X-3 over every tracked text file; the 3 exempt lines are skipped (3/3) and the guard reports a synthetic `prototypes/x.svg` comment (1/1) | restore `` ``prototypes/cambios_10_12_2026`` `` in the docstring of `s19_app/tui/services/project_gather_service.py` → RED | US-DOC-HYG-1 | No: 15 non-exempt lines — `s19_app/tui/legend.py:382`, `:832`, `s19_app/tui/services/project_gather_service.py:3`, `tests/test_report_logging.py:3`, `tests/test_tui_directionb.py:7578`, `tests/test_tui_evidence_packs.py:4`, `tests/test_tui_report_seam.py:4`, `tests/test_tui_map_big.py:2918`, `tests/test_tui_patch_layout.py:287`, `docs/architecture.md:238`, `:255`, `:422`, `:424`, `PENDIENTES-batch96.md:11`, `:80` |
| R-DOC-REF.4 | U | The system shall name the retired fast-dev-flow workflow in a tracked text file only on a line that carries a removal mark, except on an exempt line. **new** (R2) | 0 occurrences of `fast-dev-flow` (any case) without a removal mark outside X-2 … X-5 over every tracked text file (5 exempt lines skipped, 5/5) | restore `` Both `/dev-flow` (Phase 0 input, Phase 6 close) and `/fast-dev-flow` `` at `docs/engineering-rules.md:11` → RED | US-DOC-HYG-1 | No: 10 non-exempt lines — `docs/engineering-rules.md:11`, `tests/test_report_logging.py:3`, `tests/test_tui_directionb.py:7016`, `:7213`, `:7578`, `:8973`, `tests/test_tui_evidence_packs.py:4`, `tests/test_tui_patch_editor_v2.py:1905`, `tests/test_tui_report_seam.py:4`, `tests/test_tui_snapshot.py:413` |
| R-DOC-REF.5 | U | The system shall present `s19tool` in its repository documents only in an s19tool shape. **new** (R1; widens the AT-285 arm of `tests/test_docs_canon.py` from 3 files to every repository document) | 0 occurrences of `s19tool` outside an s19tool shape over every repository document; `pip show s19tool` (`SECURITY.md:15`) and `.s19tool\templates\` (`docs/user-guide/ch12-crc-designer.md:69`) pass (2/2) | add `s19tool firmware.s19 info` to `CLAUDE.md` → RED | US-DOC-HYG-1 | No: 7 lines — `CLAUDE.md:9`, `:41`, `:42`, `:43`, `:44`, `docs/diagrams/architecture.md:18`, `:45` |
| R-DOC-REF.6 | U | The system shall name CDFX in its repository documents only on a line that carries a removal mark. **new** (widens the AT-285 CDFX arm from 3 files to every repository document) | 0 unmarked `CDFX` or `CDF 2.0` tokens (word, any case) over every repository document | restore `` `cdfx/` package `` in the architecture row of `docs/README.md` → RED | US-DOC-HYG-1 | No: 5 lines in `docs/README.md` (:3, :14, :15, :33, :34) and 22 in `docs/diagrams/architecture.md` |
| R-DOC-README.4 | U | The system shall describe in its README no window, key, command or file that the system does not provide. (canon, unchanged; in scope as the guard of the README's documentation table after `docs/diagrams/architecture.md` goes) | Inc 14's thresholds hold (`tests/test_b101_help_legend_docs.py::test_r_doc_readme_4_1_no_stale_claim`, `::test_r_doc_readme_4_2_linked_documents_exist`); the documentation table has no `docs/diagrams/architecture.md` row (0) and still links `docs/architecture.md` (1/1) | keep the diagrams row with the file deleted → `test_r_doc_readme_4_2` RED | US-DOC-HYG-1 | Yes (row at `README.md:465` links an existing file today) |

### US-DOC-HYG-2 — developer documents (D1, D2, D3, D5)

| Id | Form | Requirement | Pass threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-DEV.1 | U | The system shall list in `CLAUDE.md` exactly the console scripts that `pyproject.toml` declares. **new** (R1) | the set of console-script names `CLAUDE.md` lists under "Project layout" equals the keys of `[project.scripts]` (`{s19tui}`, 1/1); 0 lines present `s19tool` as an entry point | add `` - `s19tool` → `s19_app.cli:main` `` back → RED | US-DOC-HYG-2 | No: lists `s19tool` and `s19tui` ("Two console entry points", `CLAUDE.md:7-10`); `pyproject.toml` has `s19tui` only |
| R-DOC-DEV.2 | U | The system shall show each command-line example of the CLI in `CLAUDE.md` in the form `python -m s19_app.cli <file> <command>`. **new** (R1) | each CLI example line of the "Common commands" block starts `python -m s19_app.cli ` and names a sub-command `s19_app/cli.py` defines (4/4: `info`, `verify`, `dump`, `patch-hex`) | write one example as `s19tool firmware.s19 verify` → RED | US-DOC-HYG-2 | No: 4 examples start `s19tool ` (`CLAUDE.md:41-44`) |
| R-DOC-DEV.3 | U | The system shall state in `CLAUDE.md` the branches and the two test lanes that `.github/workflows/tui-ci.yml` runs. **new** | the CI sentence names `main` and `main-tui` (2/2) and the lane markers `-m "not serial_timing"` (parallel) and `-m serial_timing` (serial) (2/2), each equal to a marker in `tui-ci.yml`; 0 occurrences of `pushes/PRs to \`main-tui\`` | delete `main` from the sentence → RED | US-DOC-HYG-2 | No: "runs `pytest -q` on Python 3.11 against pushes/PRs to `main-tui`" (`CLAUDE.md:47`); the workflow triggers on `main` and `main-tui`, two lanes (`tui-ci.yml:1-19`) |
| R-DOC-DEV.4 | U | The system shall name the hex renderer `s19_app/render/hexview.py` in `CLAUDE.md`, `PROJECT_RULES.md` and `docs/engineering-rules.md`. **new** | 0 occurrences of `tui/hexview.py` in the three files (base 2); each file that names the hex renderer names `render/hexview.py` (3/3: `CLAUDE.md` TUI-layer bullet and docstring baseline, `PROJECT_RULES.md` pipeline line, `docs/engineering-rules.md` render-module list) | restore `` `s19_app/tui/hexview.py` `` in `CLAUDE.md`'s docstring-baseline line → RED | US-DOC-HYG-2 | No: `CLAUDE.md:80`, `PROJECT_RULES.md:135` say `s19_app/tui/hexview.py`; `CLAUDE.md:70` lists bare `hexview.py` under "TUI layer (`s19_app/tui/`)"; `docs/engineering-rules.md:192` lists bare `hexview.py`. The file moved in batch-92 (`s19_app/tui/__init__.py:17` imports `..render.hexview`) |
| R-DOC-DEV.5 | U | The system shall state no size in lines of a source module in `CLAUDE.md`. **new** (`E1-rulings.md` D-6) | 0 matches of `\d+(\.\d+)?k?[- ](line\|LOC)\b` (any case) in `CLAUDE.md` | restore `~5k-line` → RED | US-DOC-HYG-2 | No: "`app.py::S19TuiApp` is a ~5k-line" (`:68`; measured 21,138 lines), "`tui/a2l.py` (1.4k LOC)" (`:56`; measured 3,716) |
| R-DOC-DEV.6 | U | The system shall cite source code in `CLAUDE.md` without a line number. **new** (`E1-rulings.md` D-6) | 0 matches of `` [\w/]+\.py:\d+ `` in `CLAUDE.md`; the `project.toml` paragraph names the two readers by file and function (`workspace.py` `find_repo_root`, `tests/test_changes_schema.py` repo-root helper) (2/2) | restore `` `s19_app/tui/workspace.py:508` `` → RED | US-DOC-HYG-2 | No: `workspace.py:508` (the reader is now at `:2279`) and `tests/test_changes_schema.py:523` (`CLAUDE.md:12`) |
| R-DOC-DEV.7 | U | The system shall name in `docs/engineering-rules.md` only files of the repository as its sources. **new** | 0 occurrences of `project_devflow_control_lineage` and of "Canonical history: memory" (base 1 each); R-DOC-REF.1 holds for the file | restore the sentence `Canonical history: memory project_devflow_control_lineage.md.` → RED | US-DOC-HYG-2 | No: `docs/engineering-rules.md:6-7` points to a personal memory file outside the repository |
| R-DOC-DEV.8 | U | The system shall declare in `requirements.txt` the runtime requirements that the `dependencies` of `pyproject.toml` declare. **new** (`E1-rulings.md` D-7) | the set of requirement lines of `requirements.txt` (comments and blanks skipped, whitespace removed) equals the `[project] dependencies` list of `pyproject.toml` (3/3: `rich>=13.0`, `textual>=8.2.8,<9`, `markdown-it-py>=3`) | delete the `markdown-it-py>=3` line → RED | US-DOC-HYG-2 | No: 1/3 (`rich>=13.0`); `textual` is bare, `markdown-it-py` missing |
| R-DOC-DEV.9 | U | The system shall link in `docs/README.md` each entry of CTX-DOCINDEX. **new** | 12/12 entries linked (CTX-DOCINDEX computed from the tree at the commit) | delete the `engineering-rules.md` link → RED | US-DOC-HYG-2 | No: 6/12 (overview, architecture, requirements/, README, REQUIREMENTS, CLAUDE); missing engineering-rules, CENSUS, user-guide/, PROJECT_RULES, SECURITY, CHANGELOG |
| R-DOC-DEV.10 | U | The system shall state in `docs/README.md` no branch, commit, test tally or batch list as the project's state. **new** | 0 headings `Project state`, 0 `latest merge`, 0 test tallies (`\d+ pass`), 0 rows of a per-batch table (`` `2026-\d\d-\d\d-batch-\d+` `` in a table row) in `docs/README.md` | restore `- **Tests:** 762 pass / 3 xfailed / 2 skipped` → RED | US-DOC-HYG-2 | No: "Project state" block (`docs/README.md:38-43`: `86f4910`, 762 pass) and the batch table stopping at batch-04 (`:29-34`) |
| R-DOC-DEV.11 | U | The system shall name in `docs/overview.md` each window of CTX-README by its rail label. **new** | 13/13: the 12 rail labels of S6 CTX-SHELL (`Workspace`, `A2L Explorer`, `MAC View`, `Memory Map`, `Issues Report`, `Patch Editor`, `Check Editor`, `A2B Diff`, `Flow Builder`, `Flow Execution`, `Checks`, `CRC Designer`) and `Split / Join / Export` appear in §3 | delete `Check Editor` from §3 → RED | US-DOC-HYG-2 | No: 9/13 (missing `Check Editor`, `Flow Execution`, `Split / Join / Export`; `A↔B Diff` is not the rail label `A2B Diff`) |
| R-DOC-DEV.12 | U | The system shall state the number of rail windows as twelve in `docs/overview.md` and `docs/architecture.md`. **new** | 0 lines that give the rail, its windows or its screens a count other than twelve (`\bten\b` near `screen`/`rail`/`items`, digits other than 12) in the two files; `docs/architecture.md` §2 keeps "The twelve rail screens" (1/1) | restore "ten single-context screens" at `docs/overview.md:16` → RED | US-DOC-HYG-2 | No: `docs/overview.md:16` ("ten single-context screens"), `:37` ("**ten** rail screens … keys `1`–`0`"), `docs/architecture.md:215` (b94 banner, "exactly ten ordered items") and `:624` (batch-94 rail-invariant row) |
| R-DOC-DEV.13 | U | The system shall state no count of tests in `docs/overview.md` and `docs/architecture.md`. **new** (`E1-rulings.md` D-6) | 0 matches of `\d[\d,]*\s+(collected\s+)?tests\b` in the two files (the snapshot-baseline count "29 SVG baselines" is not a test count and stays) | restore "Roughly **2760 tests**" in §8 → RED | US-DOC-HYG-2 | No: `docs/overview.md:48` (2760, measured 2026-10-11), `docs/architecture.md:154` (2760) |
| R-DOC-DEV.14 | U | The system shall state in `docs/overview.md` that the Operations modal lists `extract` and `split_by_segment` without running them. **new** (same fact as R-DOC-README.4's Operations phrase) | the Operations bullet names `extract` and `split_by_segment` as listed but not implemented (1/1); 0 occurrences of "executable from the in-app Operations modal" | restore the base bullet → RED | US-DOC-HYG-2 | No: "A deterministic registry (`crc`, `extract`, `split_by_segment`) executable from the in-app Operations modal" (`docs/overview.md:43`); `extract` and `split_by_segment` answer `placeholder: <name> not yet implemented` (`README.md:247-248`, `s19_app/tui/operations/placeholders.py`) |
| R-DOC-DEV.15 | U | The system shall list in `examples/case_00_public/MANIFEST.md` each example case folder of `examples/`. **new** | 15/15: the 8 top-level `case_0n_*` folders other than `case_00_public` (case_01 … case_08) and the 7 folders of `examples/professional_validation/`, each named once; computed from the tree | delete the `case_08_release_demo` entry → RED | US-DOC-HYG-2 | No: 7/15 (case_01 … case_07; `case_08_release_demo` and the 7 professional-validation cases missing) |

### US-DOC-HYG-2 — the architecture map (D3)

| Id | Form | Requirement | Pass threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-ARCH.1 | U | The system shall declare in the module table of `docs/architecture.md` a module prefix for each Python folder. **new** | 5/5 (`.dev-flow/**`, `docs/**`, `s19_app/**`, `tests/**`, `tools/**`; Python folders computed from `git ls-files '*.py'`); the dev-flow validator's V8 reports no orphan file (its `path/**` scan, `devflow-validate.py:894`) | delete the `tools` row → RED | US-DOC-HYG-2 | Yes (5/5) |
| R-DOC-ARCH.2 | U | The system shall declare in the module table of `docs/architecture.md` no module prefix that matches no tracked file. **new** (split of ARCH.1 per rule E2) | 0 module prefixes without a tracked file (base 1: `prototypes/**`); rationale row #2 of §10 ("`prototypes/**` is a declared module") is gone (0) | restore the `prototypes` row → RED | US-DOC-HYG-2 | No: `prototypes/**` (`docs/architecture.md:238`, rationale `:255`); `prototypes/` was removed 2026-11-05 |
| R-DOC-ARCH.3 | U | The system shall hold in `docs/architecture.md` no amendment note and no per-batch declaration of batches 88 … 100. **new** (D3; R2) | 0 lines starting `> **Amended at` or `> **Post-gate amendment` (base 4); 0 headings matching `^#{2,4} Batch-(88\|92\|94\|97\|99\|100)\b` (base 7, two of them `#### Batch-9n dependency amendments`); 0 paragraphs starting `**Batch-(92\|94\|97\|99\|100) interface amendments**` (base 5); 0 occurrences of `none frozen yet` (base 1) and of `(planned` (base 2: `:510`, `:661`) | restore the batch-100 interface block → RED | US-DOC-HYG-2 | No: banners `:182`, `:190`, `:204`, `:213`; declarations `:258`, `:341`, `:365`, `:400`, `:420`, `:462`, `:504`; amendment paragraphs and tables in §11 `:605`, `:616`, `:626`, `:641`, `:659`; batch-100 "planned at ARQ … none frozen yet" (`:659`) |
| R-DOC-ARCH.4 | U | The system shall declare in §10 of `docs/architecture.md` each sub-module of CTX-SUBMOD with the four facts of CTX-SUBMOD. **new** (keeps what the archived declarations made true; `s19_app/tui/flow_screens.py:10` cites §10) | 12/12 facts present, in present tense (0 of `NEW`, `landed`, `Inc-00` in those entries); the `flow_screens.py` entry names the data edge `flow_screens → services/flow_model` as read-only constants and dataclasses (1/1) | delete the `flow_screens.py` entry's "must not import" fact → RED | US-DOC-HYG-2 | Partly: the facts exist only inside the batch-92 and batch-94 declaration blocks (`:262-300`, `:369-378`, `:400-418`), worded as batch history |
| R-DOC-ARCH.5 | U | The system shall list the contracts of CTX-IFACE in one Interfaces table in §11 of `docs/architecture.md`. **new** | one table with the header `Interface \| Owner module \| Consumers \| Shape \| Frozen?` (the architecture template's, 1/1) holds 12/12 CTX-IFACE contracts; the rail-invariant row states twelve rail items (1/1); each `Frozen?` cell names an open batch or reads `no` (12/12; no open batch has frozen one at `c2cba35`) | delete the `utils.safe_text` row → RED | US-DOC-HYG-2 | No: four tables (Part B "frozen for `2026-08-24-batch-88`", batch-92, batch-94 with rail "exactly ten … became twelve", then batch-97/99/100 change tables) (`:585-684`) |
| R-DOC-ARCH.6 | U | The system shall state in `docs/architecture.md` that an increment changes at most 4 source files. **new** | §9 states the cap as `≤ 4 source files` (1/1); 0 occurrences of `≤ 5 files` | restore "capped at ≤ 5 files" → RED | US-DOC-HYG-2 | No: "supervised increments capped at ≤ 5 files" (`docs/architecture.md:174`); `CLAUDE.md` global rule and the flow use 4 source files |

### US-DOC-HYG-3 — archive and removal (D4, D5, D6)

| Id | Form | Requirement | Pass threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-ARCHIVE.1 | U | The system shall hold each finished note of CTX-ARCHIVE only at its archive path. **new** (R2) | the three moved notes exist at their archive paths (3/3) and not at their earlier paths (0/3); `git log --follow` of each archive path lists the note's commits before this increment (3/3, at E5, transcript); the archived `crc-algorithm-designer` draft is not named `01-requirements.md` (1/1, `E1-rulings.md` D-5) | copy `PENDIENTES-batch96.md` back to the root → RED | US-DOC-HYG-3 | No: the three notes are at the root, in `docs/` and in `tools/synth/` |
| R-DOC-ARCHIVE.2 | U | The system shall keep, in the architecture archive of CTX-ARCHIVE, each line that this increment removes from §10 and §11 of `docs/architecture.md` and from its amendment notes. **new** (R2: history kept in the tree) | every line removed from `docs/architecture.md` between `c2cba35` and the increment's commit, inside §10, §11 or an amendment note, appears in `.dev-flow/design/archive/architecture-batch-declarations-88-100.md` (100 %; at E5 by a `git diff` transcript); the archive's ids add at most the one new Atlas id `LLR-155.1..155.4` to `.dev-flow/` (all other 53 already occur there) | drop the batch-99 table from the archive → E5 check RED | US-DOC-HYG-3 | No: no archive file |
| R-DOC-ARCHIVE.3 | U | The system shall hold none of the files of CTX-REMOVED. **new** (R2, R3, R5; CODE-CHANGES D13-17) | 0 tracked files under `.fast-dev-flow/` (base 33), `docs/diagrams/architecture.md` absent (base present), `s19_app/tui/operations/requirements/REQ-crc.md` absent (base present), the two `examples/case_00_public/*.txt` files absent (base 2) — 4 groups, 0 tracked files each | restore `examples/case_00_public/s19_sample.txt` → RED | US-DOC-HYG-3 | No: all present |
