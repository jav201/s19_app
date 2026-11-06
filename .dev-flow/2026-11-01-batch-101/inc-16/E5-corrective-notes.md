# Inc 16 — E5 corrective notes

One Opus pass over the rulings of `E5-rulings.md` (C-1 … C-10). Branch `b101-inc16`, start head `b843fc6`. Inputs read: `E5-rulings.md`, `E5-code-review.md`, `E5-coverage-audit.md`, `E5-mutants.md`, `E4-integration-notes.md`, `01-requirements.md`, `02-test-cases.md`. Source files stay comment-only (no `s19_app/` file is touched here). Nothing that imports `s19_app` ran on the Windows PC; every run is on the LAN Linux host 2 (§3).

## 1. Sites, enumerated before the first edit

Line numbers are at `b843fc6`.

| Ruling | Sites |
|---|---|
| C-1 | `02-test-cases.md`: the Coverage and Result cells of the 52 case rows (`:18-30`, `:36-53`, `:59-69`, `:75-84`), the Tests cell of README.4/4 (`:30`, N full → partial); the header paragraph (`:3`) and the "Docs" common input (`:10`, "E4 records the measured number"); the Summary table (`:88-97`). Each case cites its negative control from `E5-mutants.md` (mut-01 … mut-33, by requirement). |
| C-2 | `docs/architecture.md:154-157` (marker list: add `serial_timing`), `:163` (runtime dependency set: add `markdown-it-py`); `01-requirements.md:144` (R-DOC-DEV.8: requirement, pass threshold, negative control, base widened to §8 of the map); `tests/test_b101_doc_hygiene.py` new node `test_r_doc_dev_8_2_…` after `:673`; `02-test-cases.md` new case R-DOC-DEV.8/2 after `:44`. |
| C-3 | `tests/test_b101_doc_hygiene.py:672` (`len(declared) == 3`), `:880` (`len(folders) == 15`), `:883` (the "of 15" message); `02-test-cases.md:44`, `:53` (case texts: the count follows the tree). |
| C-4 | `tests/test_b101_doc_hygiene.py:742-758` (`_rail_labels`, DEV.11/1: the 13th label read from `EXTRA_PALETTE_ENTRIES` of `s19_app/tui/app.py`, the check bound to the one §3 list item that holds "rail screens"); `02-test-cases.md:48` (DEV.11/1 inputs and expected). |
| C-5 | `tests/test_b101_doc_hygiene.py:1001-1015` (ARCH.4/2: drop the `flow_screens.py` docstring read); `02-test-cases.md:66` (ARCH.4/2 objective, inputs, expected); `.dev-flow/BACKLOG-CODE.md:1791-1792` (row I-7: one sentence for Inc 9, F-4). |
| C-6 | `CLAUDE.md:69` (`render/hexview.py` → `s19_app/render/hexview.py` (outside `tui/`)). |
| C-7 | F-6 `docs/README.md:14` (drop XML, name §10/§11); F-10 `examples/case_00_public/MANIFEST.md:29-32` (only `README.txt` is tracked, the generator command); F-11 `docs/architecture.md:182-183` (dated count dropped; the removed base lines are in the archive at `:53-54`, so R-DOC-ARCHIVE.2 holds); F-9 `tests/test_b101_doc_hygiene.py:1206` (exclude `root` beside `runner`, one line); F-8 left (ruling); F-7 left (not ruled for a fix; no test churn). |
| C-8 | REF.5/1: `tests/test_docs_canon.py:104-107` (occurrence shapes split out), `:126-136` (`_live_token_findings` excuses an occurrence, not the line), `:147-157` (one mixed control line judged 1); `02-test-cases.md:27` (A back to full). ARCH.1/2: `02-test-cases.md:60` (expected = the V8 output: 0 stale notices, exactly 1 root notice for `setup.py`). DEV.1/1: `02-test-cases.md:36` (entry-point list items). ARCHIVE.2/2: `02-test-cases.md:78` (grammar, corpus, expected). |
| C-9 | ARCH.1/2, ARCHIVE.1/2, ARCHIVE.2/1, ARCHIVE.2/2: one transcript each (§3), cited at `02-test-cases.md:60`, `:76`, `:77`, `:78`. |
| C-10 | `.dev-flow/BACKLOG-CODE.md`: one new row after `:1792`, with the counts re-measured at `b843fc6` (§2). No old record is redacted. |

## 2. C-10 counts, re-measured at `b843fc6` (read-only `git grep` over the index)

- **Drive-letter cloud-folder path** (`<letter>:` + `/` or `\` + the synced-folder name): **48** tracked files under `.dev-flow/` — 41 in batch folders 05 … 100, 4 under `.dev-flow/design/` (outside `archive/`), `BACKLOG-CODE.md` (2 lines), `BACKLOG-PROCESS.md`, and 1 in this batch (`2026-11-01-batch-101/HANDOFF-2026-11-06.md`, the orchestrator's handoff). With a trailing separator required, 47 (one batch-100 prototype note names the bare drive root).
- **Local account name**: **14** files — 13 batch-102 evidence transcripts and `.dev-flow/state.json` (1 line).
- The archive folder holds none (R-DOC-ARCHIVE.4).

## 3. What was done, per ruling

| Ruling | State | How |
|---|---|---|
| C-1 | done | All 52 cases (53 with DEV.8/2) moved to the audited marks: Coverage `covered` 53, Result `verified` 53. README.4/4: N is now `partial` (the two row clauses) beside G14 `partial` (existence), coverage `covered` (audit C-2). Each Result cell names the final run and the case's control (`E5-mutants.md` row, RED on base, or an instrument check), with the legend in the header. Summary table updated. |
| C-2 | done | `docs/architecture.md` §8 names `markdown-it-py` and lists `serial_timing`. R-DOC-DEV.8 widened to §8 (requirement, threshold, control, base); new case DEV.8/2 and node `test_r_doc_dev_8_2_architecture_states_dependencies_and_markers` (set equality both ways, both read from `pyproject.toml`). Controls `e5c-01` M-2, M-3, M-4 RED. |
| C-3 | done | DEV.8/1 keeps the set equality with a non-empty anchor; DEV.15/1 anchors "both families present" and reports `n of len(folders)`. `e5c-01`: M-1, M-5, M-6 RED; P-1 (a fourth dependency named everywhere) and P-2 (a tracked, named `case_09`) GREEN, and both RED under the guard file of `b843fc6`. |
| C-4 | done | DEV.11/1 reads the 13th label from the `EXTRA_PALETTE_ENTRIES` pair of `app.py` (`open_split_join_export`) and checks all 13 as whole phrases inside the one §3 list item that holds "rail screens". `e5c-02`: M-7 (`Memory Map` dropped) RED, and GREEN under the E4 guard (F-3 shown); M-8 … M-10 RED (M-10 renames the palette label in a copy of `app.py`). |
| C-5 | done | ARCH.4/2 reads the map only; case text amended (the docstring clause of A16-10 withdrawn). Row I-7 of `BACKLOG-CODE.md` tells Inc 9 the guard does not read the docstring. `e5c-03`: M-11 RED; P-3 (the docstring cites §11) GREEN, RED under the E4 guard (F-4 shown). |
| C-6 | done | `CLAUDE.md` names `s19_app/render/hexview.py` (outside `tui/`). |
| C-7 | done | F-6 `docs/README.md` row (no XML; names §10 and §11); F-10 manifest (only `README.txt` tracked, the generator command); F-11 dated count dropped from §10 (the two base lines are in the archive: `e5c-07` 368/368); F-9 our helper excludes `root` beside `runner` (one line). Left: F-8 (ruling), F-7 (not ruled for a fix). **Open:** `tests/test_suite_hygiene.py`'s copy of the helper keeps the `root` exposure (that file is Inc 15's; the two copies now differ by that one word). |
| C-8 | done | REF.5/1: `tests/test_docs_canon.py` excuses an occurrence shape only for its own occurrence (`_S19TOOL_OCCURRENCE` removed before the bare-name search; phrases and removal marks stay per line, as CTX-DOCHYG says); one mixed control line added; A back to `full`. `e5c-04`: M-12 (mixed line in `CLAUDE.md`) RED, and GREEN under the E4 test; M-13, M-14 RED. ARCH.1/2, DEV.1/1, ARCHIVE.2/2: case texts corrected to the measured output and to what the tests check. |
| C-9 | done | `e5c-05` ARCH.1/2 (the validator's `v8_module_map` on the staged tree: 1 finding, the `setup.py` root notice), `e5c-06` ARCHIVE.1/2 (`git log --follow` at the branch ref `b843fc6`, fetched from a bundle into a temporary ref: 3/3, each with 2 earlier commits and a rename line), `e5c-07` ARCHIVE.2/1 (368/368 removed in-scope lines in the archive), `e5c-08` ARCHIVE.2/2 (49 ids, new = {`LLR-155.1..155.4`}). The four oracles' own negative controls: `e5c-09`, 4/4 FAIL as expected. |
| C-10 | done | One row in `.dev-flow/BACKLOG-CODE.md`, counts of §2; no old record redacted. |

Not in the rulings, stated: ARCH.5/2's three own clauses (rail "ten", a saved-file Shape cell, a `Frozen?` cell) still have no mutant of their own (coverage audit F-1); its Result cell says so.

## 4. Runs (LAN Linux host 2, interpreter `s19ci` Python 3.11)

Two own detached worktrees at `m4fix-main` (= `c2cba35`), the branch diff plus these uncommitted edits applied as one binary patch and staged (`git add -A`, `steps.log` force-added): the main one for the E5-T cases and the final run, a COPY for the controls (each control backs up the files it mutates, runs its node serially, and restores them; the copy equals its index afterwards in every transcript). Each transcript prints the source commit, the patch hash, the base, the index tree and `s19_app.__file__` (the worktree's own). Paths are redacted (`<HOME>`).

| Run | What | Result |
|---|---|---|
| `e5c-01` | C-2 / C-3 controls, DEV.8/1, DEV.8/2, DEV.15/1 | 10/10 as expected |
| `e5c-02` | C-4 controls, DEV.11/1 | 5/5 as expected |
| `e5c-03` | C-5 controls, ARCH.4/2 | 3/3 as expected |
| `e5c-04` | C-8 controls, the AT-285 node | 4/4 as expected |
| `e5c-05` … `e5c-08` | C-9: ARCH.1/2, ARCHIVE.1/2, ARCHIVE.2/1, ARCHIVE.2/2 | 4/4 PASS |
| `e5c-09` | negative controls of those four oracles | 4/4 FAIL as expected |
| `e5c-10` | final: the guard files (`test_b101_doc_hygiene.py`, `test_docs_canon.py`, `test_b101_help_legend_docs.py`), `test_id_registry.py`, `test_suite_hygiene.py`, `-n 8 -m "not serial_timing"`, on the tree with these records | **192 passed, 0 failed** (113 s); 193 collected, 1 deselected by the marker (`tests/test_suite_hygiene.py::test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock`, the serial lane, not run here); 45 nodes in `test_b101_doc_hygiene.py`, 2 in `test_docs_canon.py`; 49 repository documents |

The worktrees, the temporary ref and the helper files (`i16c-*`) were removed after the runs.

After `e5c-10` only these notes (this table row and §5), `steps.log` and the transcript `e5c-10.txt` changed; the redaction gate of `tests/test_suite_hygiene.py` read every other record of the commit in that run. The commit touches none of the three archive paths that `e5c-06` read at `b843fc6` (`git diff --cached b843fc6 -- .dev-flow/design/archive/` is empty).

## 5. Evidence checklist

- ✓ Tests / checks: `e5c-10` 192 passed, 0 failed; controls `e5c-01` … `e5c-04` 22/22 as expected; E5-T `e5c-05` … `e5c-08` 4/4 PASS; oracle controls `e5c-09` 4/4. Not run: the serial lane of the five files (1 node).
- ✓ No secrets or local identities: the ten transcripts are redacted (`<HOME>`) and scanned for the account names, the LAN prefix, home paths and the cloud-folder name before the commit (0 hits); the C-10 row gives counts, never the strings.
- ✓ No destructive command outside own scratch: `git reset --hard` / `git clean` ran only in the two worktrees created for this pass, both removed; the temporary ref `refs/i16c/b101-inc16` was deleted; no push.
- ✓ File count: source files under `s19_app/` touched by the commit: 0 (the controls mutated `app.py` and `flow_screens.py` only inside the COPY worktree, restored). Documents 4 (`CLAUDE.md`, `docs/README.md`, `docs/architecture.md`, the examples manifest), tests 2, records.
- ✓ Records: `01-requirements.md` (R-DOC-DEV.8 only, C-2), `02-test-cases.md` (marks and texts, one case added), `BACKLOG-CODE.md` (row I-7 sentence, C-10 row), these notes, `steps.log`.
