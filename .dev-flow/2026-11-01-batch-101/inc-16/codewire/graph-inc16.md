# Inc 16 — Code-Wire graph (E2): not applicable

**Not applicable.** Inc 16 changes no function: no signature, no code line, no data contract and no behaviour (`E1-slice.md` §5: 0 functions). Its only edits inside `s19_app/` are two comments and one module docstring (`s19_app/tui/legend.py:382`, `:832`; `s19_app/tui/services/project_gather_service.py:3`) and the deletion of a Markdown file from the package tree (`s19_app/tui/operations/requirements/REQ-crc.md`), so a Code-Wire baseline of the code in scope would equal its prototype and carry no contract or example to review. The design under review at E3 is the document change map below, the rows of `01-requirements.md` (each with its pass threshold and negative control) and the D3 shape of `docs/architecture.md` (`E1-rulings.md` D-4). Concrete examples per row are the base findings and thresholds in `01-requirements.md` and the inputs / expected results of `02-test-cases.md`.

## Document change map (file → action → rows)

| # | File | Action | Rows |
|---|---|---|---|
| 1 | `CLAUDE.md` | edit: one console script `s19tui`; CLI examples as `python -m s19_app.cli <file> <command>`; CI sentence (`main`, `main-tui`, two lanes); no module sizes; no `file.py:<line>`; `render/hexview.py` | R-DOC-REF.1, R-DOC-REF.5, R-DOC-DEV.1 … R-DOC-DEV.6 |
| 2 | `PROJECT_RULES.md` | edit `:135` → `s19_app/render/hexview.py` | R-DOC-REF.1, R-DOC-DEV.4 |
| 3 | `docs/engineering-rules.md` | edit `:6-7` (drop memory pointer), `:11-13` (`/dev-flow` only; fast-dev-flow named as retired), `:192` (`render/hexview.py`); Test-timing section untouched | R-DOC-REF.4, R-DOC-DEV.4, R-DOC-DEV.7 |
| 4 | `requirements.txt` | edit: the 3 runtime requirements of `pyproject.toml` | R-DOC-DEV.8 |
| 5 | `docs/README.md` | edit: short index of CTX-DOCINDEX; no state block, no batch table, no CDFX, no diagrams link | R-DOC-REF.2, R-DOC-REF.6, R-DOC-DEV.9, R-DOC-DEV.10 |
| 6 | `docs/overview.md` | edit: 13 windows by rail label, twelve, no test count, Operations placeholders, no diagrams link | R-DOC-REF.2, R-DOC-DEV.11 … R-DOC-DEV.14 |
| 7 | `README.md` | edit `:465`: delete the diagrams row | R-DOC-REF.2, R-DOC-README.4 |
| 8 | `docs/architecture.md` | edit (D-4): §1–§9 fixed in place (evidence paths → `.dev-flow/2026-10-12-batch-94/evidence/…`, no test count, `≤ 4 source files`, no diagrams link); §10 module table without `prototypes/**` + sub-module table; §11 one Interfaces table; banners and batch blocks out | R-DOC-REF.1 … R-DOC-REF.3, R-DOC-DEV.12, R-DOC-DEV.13, R-DOC-ARCH.1 … R-DOC-ARCH.6 |
| 9 | `.dev-flow/design/archive/architecture-batch-declarations-88-100.md` | create: the removed blocks, verbatim | R-DOC-ARCHIVE.2 |
| 10 | `PENDIENTES-batch96.md` | git mv → `.dev-flow/design/archive/PENDIENTES-batch96.md` | R-DOC-ARCHIVE.1, R-DOC-REF.3 |
| 11 | `docs/crc-algorithm-designer/01-requirements.md` | git mv → `.dev-flow/design/archive/crc-algorithm-designer-requirements-draft-2026-07-20.md` | R-DOC-ARCHIVE.1, R-DOC-REF.1 |
| 12 | `tools/synth/VERIFY.md` | git mv → `.dev-flow/design/archive/synth-case08-release-demo-VERIFY.md` | R-DOC-ARCHIVE.1 |
| 13 | `docs/diagrams/architecture.md` | git rm | R-DOC-ARCHIVE.3, R-DOC-REF.1, R-DOC-REF.5, R-DOC-REF.6 |
| 14 | `s19_app/tui/operations/requirements/REQ-crc.md` | git rm (CODE-CHANGES D13-17) | R-DOC-ARCHIVE.3 |
| 15 | `examples/case_00_public/from_source_input.txt`, `s19_sample.txt` | git rm | R-DOC-ARCHIVE.3 |
| 16 | `.fast-dev-flow/` (33 files) | git rm -r | R-DOC-ARCHIVE.3, R-DOC-REF.3, R-DOC-REF.4 |
| 17 | `examples/case_00_public/MANIFEST.md` | edit: 15 case folders | R-DOC-DEV.15 |
| 18 | `s19_app/tui/legend.py` | comment only (`:382`, `:832`) | R-DOC-REF.3 |
| 19 | `s19_app/tui/services/project_gather_service.py` | docstring only (`:3`) | R-DOC-REF.3 |
| 20 | 8 test files (`test_report_logging.py`, `test_tui_evidence_packs.py`, `test_tui_report_seam.py`, `test_tui_directionb.py`, `test_tui_patch_editor_v2.py`, `test_tui_snapshot.py`, `test_tui_map_big.py`, `test_tui_patch_layout.py`) | comment / docstring only; no node renamed | R-DOC-REF.3, R-DOC-REF.4 |
| 21 | `tests/test_docs_canon.py` | AT-285 arm widened to every repository document (node name kept) | R-DOC-REF.5, R-DOC-REF.6 |
| 22 | `tests/test_b101_doc_hygiene.py` | create (E4 tester): the standing guards | every other row but R-DOC-ARCH.1/2, R-DOC-ARCHIVE.1/2, R-DOC-ARCHIVE.2 (E5 transcripts) |
| — | `docs/CENSUS-BASELINE-canon-mirror.md`, `tools/id_registry.py`, `tools/seed_id_registry.py`, `AT-TC-REGISTRY.jsonl`, `.gitignore`, `.gitattributes` | unchanged (D-2, D-3) | — |

Counts per action: edit 9 documents + 2 source comment-only + 8 test comment-only + 1 guard widened; create 1 archive + 1 test file; git mv 3; git rm 4 files + 1 folder (33 files) = 37 files.

## Interfaces with other increments

Listed in `E1-rulings.md` §6. The one code-facing interface: `s19_app/tui/flow_screens.py:10` cites `docs/architecture.md` §10 for the read-only data edge `flow_screens → services/flow_model`; R-DOC-ARCH.4 keeps that edge declared in §10 (Incs 9 and 12 change `flow_screens.py`). A later change to a CTX-IFACE contract amends §11's single Interfaces table (R-DOC-ARCH.5).
