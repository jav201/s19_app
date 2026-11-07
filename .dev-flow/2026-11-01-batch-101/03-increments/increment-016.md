# Increment 016 — Inc 16 · R-DOC-REF, -DEV, -ARCH, -ARCHIVE · documentation hygiene: stale, dead and duplicate docs

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-16/`: `01-requirements.md` (US-DOC-HYG-1 … 3, R-DOC-REF.1 … .6, R-DOC-DEV.1 … .15, R-DOC-ARCH.1 … .6, R-DOC-ARCHIVE.1 … .4, R-DOC-README.4), `02-test-cases.md` (53 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E4-impl-notes-u1.md` / `-u2.md` / `-u3.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc16.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-16/`. Branch `b101-inc16` from `main` (base `c2cba35`), head `739a2128` plus the uncommitted E5 records and this packet.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design-review rounds, the E3 corrective), the E4 integration step, the E5 code review (carrying the security lens) and the E5 corrective pass; DeepSeek v4 Pro — the E4 implementers (3 units), the E5 mutant battery, and this record; Sonnet — the E4 independent tester; qa-reviewer (Opus) — the coverage audit and re-audit.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `016` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-DOC-REF.1 … R-DOC-REF.6 · R-DOC-DEV.1 … R-DOC-DEV.15 · R-DOC-ARCH.1 … R-DOC-ARCH.6 · R-DOC-ARCHIVE.1 … R-DOC-ARCHIVE.4 · R-DOC-README.4 (stories US-DOC-HYG-1, US-DOC-HYG-2, US-DOC-HYG-3) |
| Acceptance | the 53 cases of `02-test-cases.md`; black-box by E5 transcript: R-DOC-ARCH.1/2, R-DOC-ARCHIVE.1/2, R-DOC-ARCHIVE.2/1, R-DOC-ARCHIVE.2/2 · white-box: the standing guards of `tests/test_b101_doc_hygiene.py`, the widened AT-285 arm and Inc 14's `test_r_doc_readme_4_2` · unit: 0 functions (document change map, `codewire/graph-inc16.md`) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

The repository's living documents no longer send a contributor after removed files, retired folders, a retired workflow, a console script the package no longer installs, or dated counts that have rotted. `CLAUDE.md`, `PROJECT_RULES.md`, `docs/engineering-rules.md`, `docs/README.md`, `docs/overview.md`, `docs/architecture.md`, `README.md` and `examples/case_00_public/MANIFEST.md` are corrected in place and `requirements.txt` now equals the runtime dependencies of `pyproject.toml`. Three finished notes move into `.dev-flow/design/archive/` with their git history; the removed §10/§11 blocks and amendment notes of the architecture map are archived verbatim; the superseded diagrams file, the package-tree `REQ-crc.md`, two unused example text files and the retired `.fast-dev-flow/` folder (33 files) are removed. No code line, signature or behaviour changes: the only source edits are two comments and one docstring that named removed `prototypes/` files.

## 2 · Files modified

Committed: `git diff --stat main...HEAD` (134 files). Uncommitted: the E5 re-audit/ruling records (`E5-rulings.md` RA-1/RA-2, the `02-test-cases.md` header executor note) and the two new records below (`04-validation.md`, this packet). SOURCE files: **3 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/legend.py` | source | US-DOC-HYG-1 | comment only: two comments that cited removed `prototypes/` files (`:382`, `:832`) reworded to the records that hold them, no path (R-DOC-REF.3) |
| `s19_app/tui/services/project_gather_service.py` | source | US-DOC-HYG-1 | module docstring only (`:3`): the operator's round cited by its batch record, no path (R-DOC-REF.3) |
| `s19_app/tui/operations/requirements/REQ-crc.md` | source | US-DOC-HYG-3 | `git rm` — the Markdown file inside the package tree (CODE-CHANGES D13-17); the folder disappears (R-DOC-ARCHIVE.3) |
| `CLAUDE.md` | doc |  | one console script (`s19tui`); CLI examples as `python -m s19_app.cli <command> <file>` (I-1); CI sentence (`main`, `main-tui`, two lanes, PR `slow` filter); no module sizes; no `file.py:<line>`; `s19_app/render/hexview.py` (outside `tui/`) |
| `PROJECT_RULES.md` | doc |  | `:135` → `s19_app/render/hexview.py` (R-DOC-REF.1, R-DOC-DEV.4) |
| `README.md` | doc |  | `:465`: the documentation-table row linking `docs/diagrams/architecture.md` deleted |
| `docs/README.md` | doc |  | short index of the 12 CTX-DOCINDEX entries; no state block, no batch table, no CDFX, no diagrams link; the architecture row names §10/§11 (F-6) |
| `docs/architecture.md` | doc |  | D-4 shape: §1–§9 corrected in place (evidence paths, no test count, `≤ 4 source files`, no diagrams link); §10 module table without `prototypes/**` plus the sub-module table (8 facts, no import rule for `flow_screens.py`); §11 one Interfaces table of the 57 CTX-IFACE contracts; §8 names `markdown-it-py` and the `serial_timing` marker (C-2); dated counts dropped (F-11) |
| `docs/engineering-rules.md` | doc |  | drop the personal memory-file pointer; `/fast-dev-flow` named only as retired; `render/hexview.py` |
| `docs/overview.md` | doc |  | 13 windows by rail label, twelve rail windows with the key range, no test count, Operations placeholders, no diagrams link |
| `examples/case_00_public/MANIFEST.md` | doc |  | 15 case folders by path relative to `examples/`; `case_08` notes only `README.txt` is tracked (F-10); `S19Tool` reworded (A16-7) |
| `requirements.txt` | doc |  | the 3 runtime dependencies of `pyproject.toml` (`rich`, `textual`, `markdown-it-py`) |
| `PENDIENTES-batch96.md` → `.dev-flow/design/archive/PENDIENTES-batch96.md` | doc |  | `git mv`; in the moved copy the drive path at `:3` is redacted (D-8, R-DOC-ARCHIVE.4) |
| `docs/crc-algorithm-designer/01-requirements.md` → `.dev-flow/design/archive/crc-algorithm-designer-requirements-draft-2026-07-20.md` | doc |  | `git mv`, renamed (D-5) |
| `tools/synth/VERIFY.md` → `.dev-flow/design/archive/synth-case08-release-demo-VERIFY.md` | doc |  | `git mv`, renamed (D-5) |
| `.dev-flow/design/archive/architecture-batch-declarations-88-100.md` | doc |  | created: the removed §10/§11 blocks and amendment notes, verbatim (R-DOC-ARCHIVE.2) |
| `docs/diagrams/architecture.md` | doc |  | `git rm` (R-DOC-ARCHIVE.3) |
| `examples/case_00_public/from_source_input.txt` | doc |  | `git rm` (R-DOC-ARCHIVE.3) |
| `examples/case_00_public/s19_sample.txt` | doc |  | `git rm` (R-DOC-ARCHIVE.3) |
| `.fast-dev-flow/ADR-flow-builder-tracer.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-06-19-crc-footer-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-06-24-audit-gaps-followup-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-06-25-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-06-batch-25-snapshot-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-07-sections-label-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-09-batch-30-r043-3-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-10-batch-34-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-13-batch-39-untrusted-text-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-18-a2l-missing-length-fix-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-18-a2l-record-layout-length-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-18-issues-paging-stride-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-18-json-editor-fill-height-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-18-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-20-memmap-entropy-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-20-unload-feature-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-21-n3-report-logging-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-23-n1-n2-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-23-n6-n7-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-24-batch-61-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-28-batch-67-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-28-batch-68-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-28-batch-69-fbp2-design-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-07-31-at-tc-registry-lane-a-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-08-15-batch-83-address-census-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-08-17-batch-84-assembled-selector-census-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/batch-40-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/batch-41-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/batch-42-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `.fast-dev-flow/archive/batch-43-spec.md` | doc |  | `git rm` — retired fast-dev-flow workflow (R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4) |
| `tests/test_b101_doc_hygiene.py` | test | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | new: 45 standing guards (44 at E4 + R-DOC-DEV.8/2 added at E5), text and `git ls-files` only, no import of `s19_app` |
| `tests/test_docs_canon.py` | test | US-DOC-HYG-1 | the AT-285 arm widened from 3 files to every repository document (node name kept); occurrence shapes split out (C-8) |
| `tests/test_id_registry.py` | test | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | `EXPECTED_SCANNED_TEST_FILES` 262 → 263 (one new test module, measured) |
| `tests/test_report_logging.py` | test | US-DOC-HYG-1 | module docstring `:3` (comment only) |
| `tests/test_tui_evidence_packs.py` | test | US-DOC-HYG-1 | module docstring `:4` (comment only) |
| `tests/test_tui_report_seam.py` | test | US-DOC-HYG-1 | module docstring `:4` (comment only) |
| `tests/test_tui_directionb.py` | test | US-DOC-HYG-1 | 4 comment/docstring lines (`:7016`, `:7213`, `:7578`, `:8973`) |
| `tests/test_tui_patch_editor_v2.py` | test | US-DOC-HYG-1 | comment `:1905` |
| `tests/test_tui_snapshot.py` | test | US-DOC-HYG-1 | comment `:413` |
| `tests/test_tui_map_big.py` | test | US-DOC-HYG-1 | docstring `:2918` |
| `tests/test_tui_patch_layout.py` | test | US-DOC-HYG-1 | docstring `:287` |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | rows appended: the C-10 redaction pass, I-7 (Inc 9 `flow_screens.py` docstring), the `flow_screens → flow_persistence_service` edge (Inc 9), D-9 (`check.py:278`) |
| `.dev-flow/2026-11-01-batch-101/inc-16/01-requirements.md` | doc |  | EARS requirements: 32 rows (31 new + R-DOC-README.4 canon unchanged) + Definitions (CTX-DOCHYG, CTX-DOCINDEX, CTX-ARCHIVE, CTX-REMOVED, CTX-SUBMOD, CTX-IFACE) + US-DOC-HYG-1 … 3 |
| `.dev-flow/2026-11-01-batch-101/inc-16/02-test-cases.md` | doc |  | 53 ISO 29119-3 cases; audited and re-audited at E5 (uncommitted RA-2 header executor note) |
| `.dev-flow/2026-11-01-batch-101/inc-16/E1-rulings.md` | doc |  | E1 scope census, decisions D-1 … D-12, orchestrator rulings, E3 round-1 corrections, E4 addenda |
| `.dev-flow/2026-11-01-batch-101/inc-16/E1-slice.md` | doc |  | the document change map, the 3 source files, tests touched |
| `.dev-flow/2026-11-01-batch-101/inc-16/E3-architect.md` | doc |  | E3 design review (architect, security lens): round 1 FAIL, 6 MAJOR, 10 MINOR; round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-16/E3-rulings.md` | doc |  | E3 orchestrator rulings A16-1 … A16-16 |
| `.dev-flow/2026-11-01-batch-101/inc-16/E4-impl-notes-u1.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, unit 1) |
| `.dev-flow/2026-11-01-batch-101/inc-16/E4-impl-notes-u2.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, unit 2) |
| `.dev-flow/2026-11-01-batch-101/inc-16/E4-impl-notes-u3.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, unit 3) |
| `.dev-flow/2026-11-01-batch-101/inc-16/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN, I-1 … I-7, D-U1 … D-U3, F-1 … F-8, runs int-01 … int-06 |
| `.dev-flow/2026-11-01-batch-101/inc-16/E4-tester-notes.md` | doc |  | E4 independent tester (Sonnet): test→case map, RED-on-base |
| `.dev-flow/2026-11-01-batch-101/inc-16/E5-code-review.md` | doc |  | E5 code review (security lens): PASS-WITH-NOTES, F-1 … F-5 MINOR, F-6 … F-11 NIT |
| `.dev-flow/2026-11-01-batch-101/inc-16/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 … C-10, runs e5c-01 … e5c-10 |
| `.dev-flow/2026-11-01-batch-101/inc-16/E5-coverage-audit.md` | doc |  | E5 coverage audit (5.8 % judgment changes) + Re-audit (PASS-WITH-NOTES, no mark changed) |
| `.dev-flow/2026-11-01-batch-101/inc-16/E5-mutants.md` | doc |  | E5 mutant table: mut-01 … mut-35, 35/35 KILLED |
| `.dev-flow/2026-11-01-batch-101/inc-16/E5-rulings.md` | doc |  | E5 orchestrator rulings C-1 … C-10 and Re-audit rulings RA-1, RA-2 |
| `.dev-flow/2026-11-01-batch-101/inc-16/codewire/graph-inc16.md` | doc |  | Code-Wire graph: not applicable (0 functions); holds the document change map |
| `.dev-flow/2026-11-01-batch-101/inc-16/steps.log` | doc |  | stage log, models and UTC stamps (E5 end appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-16/04-validation.md` | doc |  | this increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-016.md` | doc |  | this packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-16/e5c-01.txt` … `e5c-10.txt` | generated | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | E5 corrective: controls 22/22, E5-T 4/4, oracles 4/4 FAIL, final 192 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-01.txt` … `int-06.txt` | generated | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | E4 integration runs (guards, readers, CLI forms, controls, base differential, final tree) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-16/mut-01.txt` … `mut-35.txt` | generated | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | E5 mutant battery, one transcript per mutant, 35/35 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-16/red-01-tester-base.txt` | generated | US-DOC-HYG-1 · US-DOC-HYG-2 · US-DOC-HYG-3 | E4 tester RED-proof: 38 of 45 nodes RED on base |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 11 (1 new, 1 widened, 8 comment-only, 1 `test_id_registry` re-measure; uncapped) |
| Doc files | 34 (9 edited + `requirements.txt` + 3 moved + 1 created + 4 removed + the 33-file folder + `BACKLOG-CODE.md` + 16 inc-16 records; outside the count) |
| Generated | 52 transcripts under `evidence/inc-16/` |

## 3 · How to test

```bash
# the standing guards + the widened AT-285 arm + Inc 14's README guard (LAN Linux host, Python 3.11)
python -m pytest -q -n 8 -m "not serial_timing" tests/test_b101_doc_hygiene.py tests/test_docs_canon.py \
  tests/test_b101_help_legend_docs.py tests/test_id_registry.py tests/test_suite_hygiene.py
# the law guards and the edited/reader files (int-01, int-02, int-06)
python -m pytest -q -n 8 -m "not serial_timing" tests/test_id_registry.py tests/test_suite_hygiene.py \
  tests/test_address_census.py tests/test_requirements_canon.py
```

All of these ran on the LAN Linux host only (operator rule); nothing ran on the Windows PC. The transcripts are `evidence/inc-16/int-01.txt` … `int-06.txt`, `e5c-01.txt` … `e5c-10.txt`, `mut-01.txt` … `mut-35.txt`, `red-01-tester-base.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · white-box** (`R-*` ↔ case) | `tests/test_b101_doc_hygiene.py` (45 nodes) + `tests/test_docs_canon.py` (2) + `tests/test_b101_help_legend_docs.py` (G14) | **192 passed, 0 failed** (`e5c-10`); 53 cases, 53 covered / 0 partial / 0 gap after the re-audit |
| **B · black-box** (E5 transcripts) | R-DOC-ARCH.1/2, R-DOC-ARCHIVE.1/2, R-DOC-ARCHIVE.2/1, R-DOC-ARCHIVE.2/2 | **4/4 PASS** (`e5c-05` … `e5c-08`); oracles 4/4 FAIL as expected (`e5c-09`) |
| **Guards / laws** | `test_id_registry`, `test_suite_hygiene`, `test_address_census`, `test_requirements_canon` + the reader/edited files | **228 passed, 0 failed** (`int-06`); readers **978 passed, 2 failed, 11 skipped** (`int-02`, the 2 failing on base too) |

Details: `inc-16/04-validation.md`.

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | the 45 nodes of the increment on base `c2cba35`: **38 failed, 7 passed** — every failure is the row's base defect, and the 7 passes are the design's holds-on-base instrument checks plus ARCH.1/1 (base already 5/5) (`red-01-tester-base.txt`). Each E5 corrective addition went RED against its own mutation before it was believed: `e5c-01` … `e5c-04` (22 controls as expected, each GREEN or RED under the pre-correction guard) and `e5c-09` (the four E5-T oracles' own negative controls, 4/4 FAIL). |

### Mutation verdicts

| Field | Value |
|---|---|
| **Mutation verdicts** | 35 mutants, per-node verdicts in `E5-mutants.md` (mut-01 … mut-35): **35 KILLED, 0 SURVIVED, 0 BAD**. Baseline `46 passed, 0 failed` before any mutant. Each mutant re-introduces its row's defect into the docs one at a time and the row's guard goes RED with an assertion naming the defect. Transcripts `evidence/inc-16/mut-01.txt` … `mut-35.txt`. The two int-04 controls (M-1 old CLI order, M-2 option where the file goes) and M-4 (`EXPECTED_SCANNED_TEST_FILES` = 262) are also KILLED (`int-04.txt`). |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their first PASS was believed: the new guard file on base (38 of 45 failed — `red-01-tester-base.txt`); the mutant harness (unmutated copy 46 passed, every mutant non-zero — `E5-mutants.md`); the corrective controls (`e5c-01` … `e5c-04` 22/22 as expected, each also GREEN/RED under the pre-correction guard); the E5-T oracles (`e5c-09` 4/4 FAIL as expected). |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | the four E5 transcripts assert the tree itself (the documents and history facts the increment emits), not an intent: `e5c-05` the validator's V8 output (1 root notice for `setup.py`); `e5c-06` `git log --follow` 3/3; `e5c-07` 368/368 removed in-scope lines in the archive; `e5c-08` 49 Atlas ids, new = {`LLR-155.1..155.4`} — `e5c-05.txt` … `e5c-08.txt`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-16/`.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| e5c-01.txt | evidence/inc-16/e5c-01.txt | b75f0dc4eee95df28c3db31f0c5c2f1c1513c80a49717cea0e3f38d1ec11baab |
| e5c-02.txt | evidence/inc-16/e5c-02.txt | 84ad0a8451a3d6b7720d227c50dd7523d13c40911d35705b8ae432596e4c92f9 |
| e5c-03.txt | evidence/inc-16/e5c-03.txt | 134c410237c7eef7a02647643df4a14944ef6b1b674c49c586e782b68d484234 |
| e5c-04.txt | evidence/inc-16/e5c-04.txt | ce15cc14df5a92b6a690fb4b78d4f917bd2209a91b7cbcf4df42afc5ef739930 |
| e5c-05.txt | evidence/inc-16/e5c-05.txt | ee4047baa32b1987e2ed8f278d78e0e3138101bf31859bf1638c2bf6d823189a |
| e5c-06.txt | evidence/inc-16/e5c-06.txt | 37ccfba029c346fbcd1e74707663e2d79e9f66209218a3d6e2dc55f77582a89b |
| e5c-07.txt | evidence/inc-16/e5c-07.txt | 30bc68460b45428ee1870eb2ac4c964ef90a5f9256c54644875ba443007fd5a9 |
| e5c-08.txt | evidence/inc-16/e5c-08.txt | 55246172b7bda79a4abc411f8f93ee5a915a8e282b9d442bf16e06fa0f7c0cd7 |
| e5c-09.txt | evidence/inc-16/e5c-09.txt | 5836976f644e43534180e28657f813d88d7fb0889c364f022a0f24e335639677 |
| e5c-10.txt | evidence/inc-16/e5c-10.txt | ef46184c172377aab896dedf27b693667c922410fd772d9300971c563c6aa6e9 |
| int-01.txt | evidence/inc-16/int-01.txt | ae5f496e5bc38135942a09e41071e261404c931d8f8698dffd5d839f6887ce75 |
| int-02.txt | evidence/inc-16/int-02.txt | ae85a27acd5633d8e6893afe1fb45ff50691d53c85f60edcfe2b3f5a9a90e8f9 |
| int-03.txt | evidence/inc-16/int-03.txt | 4912a1d2572ec9e3ae46681cb6665d998dafd1c36960d0f994e056378ca38edb |
| int-04.txt | evidence/inc-16/int-04.txt | 434f58f40ea7712853ce867a729f4287d5feb5f50b4f77229e51c8164ac9453c |
| int-05.txt | evidence/inc-16/int-05.txt | 88d32b95ab9368885799509218e783664918de220f778a1d5a648e3fdf8ca26b |
| int-06.txt | evidence/inc-16/int-06.txt | 3f72032948f84b80b3fed5f91eda141d7703c4db09823bf9472f1371381682a5 |
| mut-01.txt | evidence/inc-16/mut-01.txt | 0ad97e01af745f4ca32a61e6410fd52c0e490e53b0c6aa8bc3af8bde64e9af39 |
| mut-02.txt | evidence/inc-16/mut-02.txt | e96f2c6d47323a8bb1978ae42a559b6b333d7f35069897ec3c7ee0b51eabced3 |
| mut-03.txt | evidence/inc-16/mut-03.txt | 46ef7a28b149e9e2c98fd16dac505ea1ab2b9ff6c29ec1d798e7ece93ed52564 |
| mut-04.txt | evidence/inc-16/mut-04.txt | 617c49558b78244f96a0429662e0591f0769524545740b24d7a5fbcfe7d449e1 |
| mut-05.txt | evidence/inc-16/mut-05.txt | da58605d689ee9590932a7576beb95d5a7ecb28a756bf403c041d2dbb24200b7 |
| mut-06.txt | evidence/inc-16/mut-06.txt | 2adcf681237c0c7dadf622e0f031f2da95b128e5b6fc0515125e0d79ebdddfa7 |
| mut-07.txt | evidence/inc-16/mut-07.txt | 7065f992b36c5766e8318ec7eb7e3d5b5b4f2902ae7294c3b9400563d1830056 |
| mut-08.txt | evidence/inc-16/mut-08.txt | c9abe5a4a605b73e4ef3ec997c376b7470075db710f37f8594c1666249c63282 |
| mut-09.txt | evidence/inc-16/mut-09.txt | 914d71328dcb7c6ffb53a1427af1d4485a918988fb231cc9f3d53af2b15f0ca7 |
| mut-10.txt | evidence/inc-16/mut-10.txt | 9a9b7a4977ac897aec8600149f346f22b35f93abf9d09e2868d9d22d25d49b2e |
| mut-11.txt | evidence/inc-16/mut-11.txt | b585744e16ae60d8433be72ec5ff5f977e0fac6e4f9cf8de8fc086b49867cc96 |
| mut-12.txt | evidence/inc-16/mut-12.txt | 2ba4d18184fa3c95038de1adeb27ad0129928a7ad0bb0ca22437af58589caedd |
| mut-13.txt | evidence/inc-16/mut-13.txt | 7fa2e6745bdf589fcfe310076e57918a5aa0d4902ca8d0b0c71810384142e2d0 |
| mut-14.txt | evidence/inc-16/mut-14.txt | 77d64b4fdf59416e78f1930ea9f00a18cf805d1c21e0b2f085c8d9a64af56f0e |
| mut-15.txt | evidence/inc-16/mut-15.txt | f4c8a40c17ec3da19a479af4c0f554bc047293e870c4a094e8e9c9fd095adb9c |
| mut-16.txt | evidence/inc-16/mut-16.txt | 0a57b2b45793552bf9c51c39d558de3bff411dae1af341ba2bf5ade6792543b1 |
| mut-17.txt | evidence/inc-16/mut-17.txt | 576d053ebca32ca787027d9a7e044521b842380a446360e1c9dae6c68ff60735 |
| mut-18.txt | evidence/inc-16/mut-18.txt | 41f2a1057fce73960e75e696242a2df16efe5e22980ec2b73b717b6cd74bed31 |
| mut-19.txt | evidence/inc-16/mut-19.txt | fdb55ad0660dcb02af4835042ba36e94104492934456fcb80079e6e4ec16ba0a |
| mut-20.txt | evidence/inc-16/mut-20.txt | ae3a41229ac74176ec98f6b4cbead5e85ad56d6f0a3a019e00d768b37cac1123 |
| mut-21.txt | evidence/inc-16/mut-21.txt | 5e28177944142d3e25859d5eb5a77a2f794d999b281b0a186603c8f943304262 |
| mut-22.txt | evidence/inc-16/mut-22.txt | aa5748fde5e46b8f2718caeb663c201ef4663aa6742bda15d3cffa1a74c15ce6 |
| mut-23.txt | evidence/inc-16/mut-23.txt | 85a6746c239ac4ec705199fd040f9807793c275cad533cd760f8a3ab5c49699b |
| mut-24.txt | evidence/inc-16/mut-24.txt | 14cd240ad097f782bd587cb10b7eb413daa41c5f3798945f547d43cdab132d0b |
| mut-25.txt | evidence/inc-16/mut-25.txt | e3ee05a48782e4321851d9c4fc054b592fd36386b65638c2893ba2bc088f6443 |
| mut-26.txt | evidence/inc-16/mut-26.txt | 2b46d8d1b2004625e6e73638250667a5eea980c771ed7aa3ffebfd39e450f1ec |
| mut-27.txt | evidence/inc-16/mut-27.txt | 0338f9e6d7dcf17faa38b339616d6703e32176e9807263ad46c09079312f5b6b |
| mut-28.txt | evidence/inc-16/mut-28.txt | fd5f4a3ff83f9c6717db34a90b6358b8985d015e43dcc63184d4d3278eceb956 |
| mut-29.txt | evidence/inc-16/mut-29.txt | 1dd81921e757c55a215af22d028a2077a893be656e0c7f500d106fbfb13f98e1 |
| mut-30.txt | evidence/inc-16/mut-30.txt | 003b44af49480573fca04abc314596fc22199423b32e531694d106129566d2cc |
| mut-31.txt | evidence/inc-16/mut-31.txt | fcd7b479e761618e99fb226d9c3e0c4c9c328be7b9afd51bdf2b5ebff1fddb89 |
| mut-32.txt | evidence/inc-16/mut-32.txt | f9eda9703c35c7cda317f1b678e309c5559d8067f7b2fb93ef2a8ac82cb2011c |
| mut-33.txt | evidence/inc-16/mut-33.txt | 7410ca539533cce6148b45111bdceeda38057fa185dba78f4d63834fe0d9274d |
| mut-34.txt | evidence/inc-16/mut-34.txt | 0ad3f32d39d029c6bafa82fc9ab650b81a11fffe6826978283e6fc3f05bb4c46 |
| mut-35.txt | evidence/inc-16/mut-35.txt | 62097ce2776a29477d37803239afcbd39b3476041f0e10697eb40cede855a74b |
| red-01-tester-base.txt | evidence/inc-16/red-01-tester-base.txt | e53b8a2d92d722d6c712da9d7bf57a9324c2776bc3a2e778211c895e0400070e |

| Field | Value |
|---|---|
| **Evidence files** | 52 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl <removed/moved name> tests/ tools/ .github/ s19_app/ setup.py pyproject.toml` | no reader of the removed or moved paths; only bare-name `PENDIENTES` citations kept resolvable (D-5); `tools/id_registry.py` and `tools/seed_id_registry.py` skip an absent folder (C-4, E3) |
| B2 file moved / removed on disk | `git diff --name-status main...HEAD` moves and removals | 3 moves, 37 removals; every reader enumerated before removal (E1 R2, R3, R5; code review C-4) |
| B3 byte-identical golden captures these files | `grep <name> tests/goldens/**` | no hit — no golden captures the changed docs or source comments |
| B4 artifact produced here is consumed elsewhere | the archive folder and the corrected documents | the guards of this increment read them (`test_b101_doc_hygiene.py`, `test_docs_canon.py`); the CENSUS header is indexed (DEV.9) |
| A3 interface consumed by another module changed | `grep <symbol>` outside its owning file | no code symbol changed — comment/docstring-only, so no interface moved |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and verdict: B1 found no reader of a removed path (only resolvable bare-name citations); B2 the 3 moves and 37 removals enumerated with their readers before removal; B3 no golden hit; B4 the guards are the consumers; A3 no code symbol changed (comment-only, so no interface). |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the audited marks or the corrected tests | every `02-test-cases.md` row whose Coverage/Result/Expected no longer matched its test or transcript | the coverage audit's row-by-row read (`E5-coverage-audit.md` §2/§4) | 52 stale marks (51 `gap`, 1 `partial`) + 5 judgment changes (3 of them marks, 5.8 %) + 1 added case (DEV.8/2) | all, by the E5 corrective pass (C-1 … C-10) | none; re-audit: 53 cases, all `covered`/`verified`, no mark changed |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (§2/§4) before the corrective pass edited its first site: every stale `02-test-cases.md` mark (51 `gap` + 1 `partial`) plus the 5 judgment changes and the added DEV.8/2 case. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `263 = 262 − 0 + 1` (`tests/test_id_registry.py`, measured). Test cases `53 = 52 + 1` (E1/E3 52, E5 +R-DOC-DEV.8/2). 45 nodes in the new guard file, 2 in the widened `test_docs_canon.py`; no test function renamed or deleted, no assertion weakened (`E5-corrective-notes.md` §1).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 BLOCKER / 0 HIGH / 0 MAJOR; F-1 … F-5 MINOR, F-6 … F-11 NIT; carried the security lens — no separate security reviewer for a docs increment; diff clean, C-1 … C-5) — `inc-16/E5-code-review.md`. `qa-reviewer` coverage audit (record stale, 5.8 % judgment changes) → corrective C-1 … C-10 → **re-audit PASS-WITH-NOTES, no mark changed** (RA-1 keeps ARCH.5/2 `full`/`covered`; RA-2 records the test-cases header executor note) — `inc-16/E5-coverage-audit.md`. The independent `tester` (E4, Sonnet) wrote the guards from the design records only and ran them RED on base — `inc-16/E4-tester-notes.md`. **Design review (E3, code-free):** `architect` round 1 **FAIL** (6 MAJOR A16-1 … A16-6, 10 MINOR, no BLOCKER/HIGH) → round 2 **PASS-WITH-NOTES** (A16-1 … A16-6 closed; N-1 … N-3 to E4) — `inc-16/E3-architect.md`, `inc-16/E3-rulings.md`. |

## 5 · Risks

- **The guards are standing.** REF.1, REF.2, REF.5, REF.6 and DEV.9 now scan every repository document; a later increment that names a removed path, a dead link, `s19tool` as a command, an unmarked CDFX or an unindexed `docs/` entry goes RED until it corrects the doc. That is the point, but it means later doc edits must be hygiene-clean on first attempt.
- **Two helper copies can drift.** `tests/test_b101_doc_hygiene.py` copies `_local_account_and_host_names` from `tests/test_suite_hygiene.py` (F-8); this increment fixed only its own `root` exclusion (F-9); Inc 15 owns the other copy.
- **The archive keeps the old bytes.** Removed and moved text (including the redacted `PENDIENTES-batch96.md` drive path, now `<operator drive>`) remains in git history, which was already public; the tip no longer carries it (D-8, ARCHIVE.4).
- **`flow_screens.py`'s docstring is still stale** until Inc 9 rewrites it (I-7); ARCH.4 no longer states the broken import rule, so the map is safe meanwhile.

## 6 · Pending items / spec deviations

- **The full suite at merge time, including the serial lane** — this increment ran its guards, every edited/reader file, the law guards and the final guard run in the non-serial lane; the one serial-lane node (`tests/test_suite_hygiene.py::test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock`) is owed at merge.
- **C-10 backlog redaction row** — the redaction pass over the 48 older `.dev-flow/` records holding a drive path and the 14 holding the local account name is one `BACKLOG-CODE.md` row; no old record is redacted here.
- **Inc 9 docstring row I-7** — `flow_screens.py`'s stale docstring citation is routed to Inc 9 (which owns the file).
- **Root exposure F-9** — the `root`-account false RED in `tests/test_suite_hygiene.py`'s helper copy is owned by Inc 15; this increment fixed only its own copy in `tests/test_b101_doc_hygiene.py`.
- **ARCH.5/2's three own clauses** have no cited negative control of their own (RA-1) — recorded as owed and as a backlog line.
- **Uncommitted records** — this packet, `04-validation.md`, the RA-1/RA-2 rulings and the `02-test-cases.md` header note are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 16; run the full suite at batch end (both lanes, including the serial lane); hand the S0.4 fold (D-1) to the requirements session; open Inc 9 with the `flow_screens.py` docstring fix (I-7) in its first slice.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 / 4 (`E1-slice.md` §1) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_doc_hygiene.py` (45 nodes) + `tests/test_docs_canon.py` widened arm |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the guards are the layer-0 (no code function) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | 38 of 45 RED on base — `red-01-tester-base.txt` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes (B1 · B2 · B3 · B4 · A3) — this §4 |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | `code-reviewer` PASS-WITH-NOTES, 0 HIGH — `inc-16/E5-code-review.md` |
| 7 | No file from another lane touched | all | ✓ | single lane; comment-only test edits coordinated with Incs 5/6/10/12/15 |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no code symbol changed |
| 9 | Coverage claims verified **on disk** | all | ✓ | re-audit: 53 cases covered/verified — `inc-16/E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared | all | ✓ | the guards protect the absence of removed paths/folders; mutant 35/35 proves the probes report a present case |
| 11 | **Mutation verdicts** declared | all | ✓ | 35 KILLED, 0 SURVIVED — `inc-16/E5-mutants.md` |
| 12 | **Instrument RED-proof** declared | all | ✓ | 4 instruments shown RED — this §4 |
| 13 | **Correction population** declared | all | ✓ | 1 correction enumerated before editing — this §4 |
| 14 | **Emitted-form assertion** declared | all | ✓ | the 4 E5 transcripts assert the emitted tree — this §4 |
| 15 | **Independent review** names somebody | all | ✓ | `architect` · `code-reviewer` · `qa-reviewer` · `tester` — §4b |
| 16 | **Evidence files** declared | all | ✓ | 52 transcripts, SHA-256 of stored bytes — this §4 |
