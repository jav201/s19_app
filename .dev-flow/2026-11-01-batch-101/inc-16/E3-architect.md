# Inc 16 — E3 code-free design review (architect, with the security lens)

Base `c2cba35`, branch `b101-inc16` at `dbf0165`. Read: `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings at its end), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc16.md`, the documents and source lines in the slice, their readers (tests, tools, CI workflows, `pyproject.toml`), the dev-flow validator's V8, and Inc 15's E1 records. Every count below comes from a read-only text scan of tracked files (`git grep`, `git ls-files` and a small Python scan that imports nothing from `s19_app`). No test ran.

## Verdict: FAIL

There are 6 MAJOR findings (A16-1 to A16-6) and no BLOCKER or HIGH. Each has a targeted fix to a row, a definition or a test case, so one correction pass and a re-read of the six should be enough. The MINOR findings can go to E4 as addenda.

The design is sound. The deletions are safe and the security surface is small. The D-4 shape works: keep the module table that V8 reads, add one sub-module table and keep one Interfaces table. The findings are about precision: a path grammar, a count predicate and a guard that scans its own file. Two are about content: the four facts per sub-module, and which interfaces the map keeps.

## Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| A16-1 | MAJOR | R-DOC-REF.1, CTX-DOCHYG "repository path" | The grammar removes a trailing `:<line>` but not a `::<name>` suffix. Applied as written, it finds **25** unmarked dead paths at base, not the 22 the row and REF.1/1 claim. The 3 extra lines cite valid pytest nodes or symbols: `CLAUDE.md:31` (`tests/test_tui_app.py::test_filter_…`), `CLAUDE.md:58` (`tests/test_tui_directionb.py::test_tc031_*`) and `README.md:42` (`s19_app/validation/engine.py::validate_artifact_consistency`). With the grammar as written, E4 either goes RED on correct lines (`README.md` belongs to Inc 14) or changes the grammar without saying so. | Add "a `::<name>` suffix (pytest node or symbol) is not part of it" to the definition, and add a 4th synthetic line `see tests/test_docs_canon.py::test_x` to REF.1/2, expected 0. |
| A16-2 | MAJOR | R-DOC-REF.3, R-DOC-REF.4; REF.3/3, REF.4/2 | Both rows scan **every tracked text file**, and that includes the new `tests/test_b101_doc_hygiene.py`. That file must hold the synthetic inputs (`# see prototypes/x.svg`, `run /fast-dev-flow`) and the EXEMPT keys (`for folder in (".dev-flow", ".fast-dev-flow"):`). Written as literals, they put REF.3 or REF.4 RED on the guard's own source, so the rows cannot be met as written. The records give no rule for this, which invites a quiet whole-file exemption of the guard, or of `tests/`. | State in CTX-DOCHYG: a guard source assembles each retired token from parts at runtime (for example `"proto" + "types/"`), and no file is exempt as a whole. The row then holds for the guard file itself, which also gives a self-check. |
| A16-3 | MAJOR | R-DOC-DEV.12 / DEV.12/1 | The threshold is not a deterministic predicate. "Near" is undefined, and "digits other than 12" catches the line the row must keep: `docs/architecture.md:28`, "Exactly twelve ordered items — keys `1`–`0` …". It would also catch any "13 windows" phrasing (DEV.11 counts 13 windows: 12 rail windows plus Split / Join / Export). Two testers would write two different guards. | Give the exact rule, for example: a line that holds `rail` and one of `screen\|item\|window\|entr` fails when it holds `\b(nine\|ten\|eleven\|thirteen)\b` or `\b(9\|10\|11\|13)\b` outside a backtick code span (key names like `` `1` `` and `` `0` `` sit in spans). Keep the positive anchor "The twelve rail screens", and add the base line `:28` as a must-pass case. |
| A16-4 | MAJOR | R-DOC-ARCH.4, CTX-SUBMOD; ARCH.4/1–2 | ARCH.4 asks for the batch-94 facts in the present tense. At `c2cba35` the code breaks one of them. Batch-94 says `flow_screens` must not import `tui/services/*` into view logic, and declares a single data edge to `services/flow_model`. But `s19_app/tui/flow_screens.py:119` imports `flow_persistence_service as fps` and calls it directly at `:824`, `:2235`, `:2267` and `:2273`; this edge has been there since batch-96 (`047ef5e`). Restating the batch-94 facts would put a false invariant into the living map. The module docstring (`flow_screens.py:5-10`, "the one declared data edge") is already stale. Incs 9 and 12 edit this file, so its imports can change again without any guard noticing. (`render/hexview.py` and `render/format.py` match their facts: no `s19_app.tui` import.) | Take the four facts from an import census of the three modules at the commit, and record it in E1 with file:line. Declare the measured `flow_screens → services/flow_persistence_service` edge (wire-format serialize and parse for copy and paste, plus the unsafe-ref code), and either accept it with a reason or open a backlog row. Make ARCH.4/1 compare the declared may-import set with an `ast.parse` census of each file's imports (read as text; no import of `s19_app`), so a new import from Inc 9 or 12 goes RED until §10 declares it. Route the `flow_screens.py` docstring fix to Inc 9 or Inc 12, which own that file. |
| A16-5 | MAJOR | R-DOC-ARCH.5, CTX-IFACE; D-4 | CTX-IFACE keeps only the 12 contracts of batches 88, 92 and 94. D-4 moves the batch-97, 99 and 100 tables to the archive as "change records", but their "After" column is the contract that shipped. Batch-99's table says "landed at `e7732f6`; every row frozen", and batch-100 closed. The tables hold about 45 live cross-module contracts, among them persisted file shapes: the `project.json` envelope (B100-I1), the `derived_from` manifest key (B100-I16) and the recent-sources store (B100-I9). They also hold the window-key table (I-10), the editor image (B99-I7) and the chain-set start check (B99-I11). Leaving them out of §11 understates the interfaces whose change fires trigger A3, which includes saved-file meaning, a one-way door. Keeping them under `.dev-flow/` does not put them back in the map. | Widen CTX-IFACE to every landed contract that crosses a module boundary or defines a persisted file shape. Write each as a present-tense row of the one table, without file:line and without Current/After columns. Intra-module function details can stay in the archive. If the orchestrator keeps 12, the ruling should name the rows dropped and the reason, and §11 should say that the dropped contracts still bind A3. In the Shape cell of each persisted format (`.chk.json`, flow template / chain-set, `project.json`), say it is a saved file, so that `Frozen? no` is not read as "free to change". |
| A16-6 | MAJOR (security) | D-8 ruling; R-DOC-ARCHIVE.1 | Ruling D-8 says to redact the operator drive path at `PENDIENTES-batch96.md:3` in the moved copy, but no row, threshold or test case checks it. The archive folder `.dev-flow/design/archive/` (new) is outside the scope of `test_r_tst_070_2` (it scans the batch-101 folder only). Its patterns do not match a drive-letter cloud-drive path either. Scanning all four files the increment adds there finds this one leak and nothing else. | Add to R-DOC-ARCHIVE.1, with an N test: the four files this increment adds under `.dev-flow/design/archive/` hold 0 drive-letter cloud-drive paths and 0 hits of the `_REDACTION_PATTERNS` forms of `tests/test_suite_hygiene.py` (0/4 files). Negative control: restore line 3 → RED. Keep the illustrative `C:\work\flash\app_v2.s19` example at `:89`; it is a sample path, not a home path. |
| A16-7 | MINOR | R-DOC-REF.5 | The row does not say whether matching is case-sensitive; REF.6 says "any case". The existing AT-285 regex is case-sensitive. Matched in any case, `examples/case_00_public/MANIFEST.md:3` ("stress-test S19Tool") is an 8th base finding. | State "case-sensitive", or count the MANIFEST line in the base. Either way, reword `MANIFEST.md:3` in the DEV.15 edit. |
| A16-8 | MINOR | R-DOC-DEV.15/1 | `case_03_overlapping_records` and `case_04_bad_checksums` exist both at the top level and under `professional_validation/`. A bare-name check lets one entry cover both, so deleting either `professional_validation/` entry does not go RED (2 of 15 entries cannot fail). | Identify each folder by its path relative to `examples/`. Add the negative control: delete `professional_validation/case_03_overlapping_records` → RED. |
| A16-9 | MINOR | R-DOC-DEV.11/1 | The rail labels are parsed from `RailEntry(` calls in `app.py` (`:641`, `:643`) and `rail.py`. If Incs 5, 6, 9, 10 or 12 reformat those lines, the parsed set shrinks and the check passes on fewer labels. `rail.py:64` holds a doctest duplicate. | Assert that the label set read from source has exactly 12 members before comparing; deduplicate with a set. |
| A16-10 | MINOR | R-DOC-ARCH.4/2 | The test case reads the citation at `flow_screens.py:10`, a line number in a file that Incs 9 and 12 edit. | Search the module docstring for `docs/architecture.md` §`<n>`, and check that `<n>` resolves to the heading that holds the sub-module table. |
| A16-11 | MINOR | R-DOC-DEV.5 | `\d+(\.\d+)?k?[- ](line\|LOC)\b` misses the plural and comma-grouped numbers: "21,138 lines" passes. | Use `[\d,]+(\.\d+)?k?[- ](lines?\|LOC)\b`, and add "21,138 lines" as a negative control. |
| A16-12 | MINOR | R-DOC-DEV.7 | The statement ("only files of the repository as its sources") is broader than the threshold, which checks two literal strings. | Narrow the statement to "cites no file outside the repository (personal memory file)", or add a pattern: a `.md` source name that `git ls-files` does not hold. |
| A16-13 | MINOR | R-DOC-DEV.3, R-DOC-ARCH.3 | Neither row is singular: DEV.3 covers branches and lanes, ARCH.3 covers amendment notes and declarations. | Split each row in two (`.3a`/`.3b`), or note "one property: CI facts" / "one property: no batch history" in E1. |
| A16-14 | MINOR | R-DOC-ARCH.5/1–2 | "Names a batch with no `05-close.md` verdict" has no parse rule, and batch-101 already holds a scaffold `05-close.md`. "Exactly 1 table in §11" will catch the batch-end doc pass if it adds Inc 14's I-8 … I-16 (handoff) as a new table. | Define the open-batch test (for example, `state.json` `batches[].status`). Make 5/1 a superset check (⊇ 12). Add to `E1-rulings.md` §6: later interfaces are added as rows of the one table. |
| A16-15 | MINOR | CTX-DOCHYG "removal mark" | The escape works per physical line, and each Markdown paragraph is one line. One "moved", "legacy" or "no longer" anywhere in a paragraph excuses every path, `s19tool` and CDFX in it; `docs/overview.md:42` already holds "legacy". This behaviour comes from AT-285. | Accept it with a note, or require the mark in the same sentence or parenthesis as the token. |
| A16-16 | MINOR | `E1-rulings.md` §1 row 8 | "Fourteen modal screens" is at `docs/architecture.md:48`, not in `docs/overview.md`, and no row covers the edit. | Fix the record. E4 drops the count word only and keeps the list of modals. |

## Deletions and moves: nothing a reader needs is removed

| Removed / moved | Readers checked | Result |
|---|---|---|
| `.fast-dev-flow/` (33 files) | `git grep` outside the folder: 15 lines, which are the 10 the increment rewords plus X-2 … X-5. `tools/id_registry.py:724-728` and `tools/seed_id_registry.py:347-350` skip an absent folder, and no caller passes `include_devflow=True`. The only AT/TC id that occurs in no other place is `AT-0000`, a placeholder, so re-running the seeder would not move a high-water mark. No CI step, no `pyproject.toml` rule. | safe |
| `docs/diagrams/architecture.md` | 5 inbound links (R3). No test or tool reads it; the validator only names it as a case-fold hazard. | safe; after the deletion the tree holds no architecture diagram (OBS-2) |
| `s19_app/tui/operations/requirements/REQ-crc.md` | No `MANIFEST.in` and no `package-data`; `pyproject.toml` has only `packages.find include = ["s19_app*"]`. No code, test or tool names it; `REQUIREMENTS.md` does not cite it. | safe |
| `examples/case_00_public/{from_source_input,s19_sample}.txt` | Every directory-level reader globs by extension (`*.s19`, `*.hex`, `*.a2l`, `*.mac`, `*.json`). No `copytree` of `case_00_public`, and no snapshot or golden names the folder. | safe (R5 holds) |
| 3 notes moved | Only bare-name citations of `PENDIENTES-batch96.md` (`app.py:13391` and two test docstrings), which D-5 keeps resolvable. Nothing reads `tools/synth/VERIFY.md` or the CRC draft. The draft's rename avoids the validator's reserved name `01-requirements.md`. | safe |
| `requirements.txt` edit | CI installs it, then `pip install -e .[…]`, which already pins `textual>=8.2.8,<9` and `markdown-it-py>=3`. The final environment is unchanged. | safe |

## Security lens

- **Leak forms.** In the moved and edited documents and the inc-16 records, the only leak is the drive path at `PENDIENTES-batch96.md:3`, which A16-6 covers. They hold no LAN address, no account or host name and no personal name. Branch names that carry a model name are not personal names. `docs/engineering-rules.md:6-7` points at a personal memory file, and DEV.7 removes it.
- **The architecture archive** copies text verbatim. The source blocks hold "operator" wording only, and A16-6's check also covers this file.
- **The new guard file** reads only text and `git ls-files`, and imports no `s19_app`. Its only process call is `git`.

## Each guard's negative control

| Guard | Negative control | Can it fail as specified? |
|---|---|---|
| REF.1 | restore `s19_app/tui/hexview.py` at `PROJECT_RULES.md:135` | yes, once A16-1 is fixed (otherwise it fails on correct lines) |
| REF.2 | delete the diagrams file and keep `README.md:465` | yes |
| REF.3 | restore the `prototypes/cambios_10_12_2026` docstring | yes; needs A16-2 so it does not fail on its own source |
| REF.4 | restore `docs/engineering-rules.md:11` | yes; needs A16-2 |
| REF.5 / REF.6 (A, widened) | `s19tool firmware.s19 info` in `CLAUDE.md` / restore the CDFX row in `docs/README.md` | yes (A16-7: state the case) |
| DEV.1 … DEV.10, DEV.13, DEV.14 | as in the rows | yes (A16-11: the DEV.5 regex is too narrow) |
| DEV.11 | delete `Check Editor` from §3 | yes; A16-9 closes the silent shrink |
| DEV.12 | restore "ten single-context screens" | not deterministic until A16-3 is fixed |
| DEV.15 | delete `case_08_release_demo` | yes, except for 2 entries (A16-8) |
| ARCH.1, ARCH.2, ARCH.3, ARCH.6 | as in the rows | yes |
| ARCH.4 | delete the "must not import" fact | yes, but it would pass on a false fact (A16-4) |
| ARCH.5 | delete the `utils.safe_text` row | yes (A16-14) |
| ARCHIVE.1 / ARCHIVE.3 | copy `PENDIENTES-batch96.md` back / restore `s19_sample.txt` | yes; the redaction arm is missing (A16-6) |
| ARCHIVE.2, ARCH.1/2, ARCHIVE.1/2 | E5 transcripts | one-off history facts, as recorded |

## Overlaps with increments still in flight

- **Incs 5, 6, 9, 10, 12** (`app.py`, `screens_directionb.py`, `flow_screens.py`; help text):
  - DEV.11 parses the `app.py` rail rows (A16-9). ARCH.4's facts and its docstring check depend on `flow_screens.py` (A16-4, A16-10).
  - Help text added to `docs/user-guide/` or `README.md` falls under REF.1, REF.2, REF.5 and REF.6 only. These are generic hygiene checks; no row pins text another increment owns.
  - Help text in `window_help.py` falls only under REF.3 and REF.4 (retired folders).
  - In `tests/test_tui_directionb.py`, this increment changes four comment lines and no line with an AT or TC id, so any merge conflict is in comments only.
- **Inc 15** (tests):
  - `tests/test_tui_patch_editor_v2.py`: Inc 15 works on `:3501` (TC-331), this increment rewords the comment at `:1905`. No overlap.
  - Inc 15's E1 changes no document (its R-TST-158 is folded). Its records cite `docs/engineering-rules.md:200`, which moves after this increment edits `:6-13`; only the records go stale.
  - `EXPECTED_SCANNED_TEST_FILES` conflicts on every merge, as already known.
  - DEV.3 reads `tui-ci.yml`, and Inc 15 does not touch it.
- **Batch-end doc pass:** see A16-14 (rows of the one Interfaces table).

## Checked, no finding

- Naming documents and config files in a statement (`CLAUDE.md`, `pyproject.toml`, `tui-ci.yml`) is justified here: the documents are the subject of the rows, and none of them names a function as its subject.
- The base counts reproduce: REF.3 = 15 non-exempt lines plus 3 exempt; REF.4 = 10 plus 5 exempt; REF.6 = 27 lines; the CTX-DOCHYG document census = 56; DEV.5, DEV.6 and DEV.13 = 2 each; the repointed evidence files at `.dev-flow/2026-10-12-batch-94/evidence/` are tracked.
- None of the reworded test comment or docstring lines holds an AT or TC id, so the registry G-checks are unaffected.
- D-4 keeps V8 working: the module table and its `path/**` prefixes stay, the `prototypes` row goes, and `.dev-flow`, `docs`, `s19_app`, `tests` and `tools` stay declared.

## Observations (outside the slice; for the orchestrator)

- **OBS-1.** Forward to the requirements session: this increment closes CODE-CHANGES D13-17, and D0-7 (`docs/requirements/review/S0-ears-strict.md:249`) cites the CRC draft at its old path.
- **OBS-2.** Once the superseded diagrams file is gone, the tree holds no architecture diagram. The architecture template expects one where the flow is non-trivial, so open a backlog row for a current diagram.
- **OBS-3.** Eight `.pyc` files are tracked under `s19_app/__pycache__/`. They are dead files rather than documents, so they belong in a backlog row.
- **OBS-4.** Older committed records (batch-05 … batch-17 `state-snapshot-at-close.json`, and batch-101's `HANDOFF-2026-11-06.md`) hold operator drive paths. The R-TST-070.2 patterns do not match that form. This is not in this increment's scope; it is routed to the orchestrator.
