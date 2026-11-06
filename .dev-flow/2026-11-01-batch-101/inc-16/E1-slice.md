# Inc 16 — E1 slice

Base `c2cba35`. A documentation increment: **0 functions change** (no code line, no signature, no behaviour). The slice is the file change map below, each file mapped to its rows. Code-Wire graph: not applicable (`codewire/graph-inc16.md`).

## 1. Source files under `s19_app/` (cap 4)

| # | File | Change | Lines | Rows |
|---|---|---|---|---|
| 1 | `s19_app/tui/legend.py` | comment only: two comments that cite removed `prototypes/` files | `:382` (``prototypes/memmap2_legend_A.120w.svg``), `:832` (``prototypes/legend_n8.kimi.NOTES.md`` / ``legend_n8.INVENTORY.md``) — reword to the record that holds them (batch-93 HLR-132 legend sheet; the batch-n8 notes), no path | R-DOC-REF.3 |
| 2 | `s19_app/tui/services/project_gather_service.py` | module docstring only | `:3` (``prototypes/cambios_10_12_2026``) — cite the operator's 2026-10-12 round by its batch record (batch-95 / batch-97), no path | R-DOC-REF.3 |
| 3 | `s19_app/tui/operations/requirements/REQ-crc.md` | `git rm` (a Markdown file inside the package tree; the folder disappears) | whole file | R-DOC-ARCHIVE.3 (CODE-CHANGES D13-17) |

Count: **3 of 4** (2 comment-only Python files + 1 document deleted from the package tree; counted to be safe though it is not code). `s19_app/tui/changes/check.py:278` is **not** in the slice (`E1-rulings.md` D-9). `s19_app/tui/app.py:13391` keeps its bare-name citation of `PENDIENTES-batch96.md` (D-5).

## 2. Documents and other tracked files (uncapped; not source)

| Action | File | Rows |
|---|---|---|
| edit | `CLAUDE.md` — entry points (`:7-10`), CLI examples (`:41-44`), CI sentence (`:47`), `project.toml` reader citations (`:12`), sizes (`:56`, `:68`), `hexview.py` home (`:70`, `:80`) | REF.1, REF.5, DEV.1 … DEV.6 |
| edit | `PROJECT_RULES.md:135` | REF.1, DEV.4 |
| edit | `docs/engineering-rules.md` — `:6-7` (memory pointer), `:11-13` (`/fast-dev-flow` routing), `:192` (`hexview.py`); **not** the "Test timing, waits and oracles (batch-101 Inc 2)" section (`tests/test_suite_hygiene.py:635-648` reads it) | REF.4, DEV.4, DEV.7 |
| edit | `requirements.txt` | DEV.8 |
| edit | `docs/README.md` (short index; no state block, no batch table, no CDFX) | REF.2, REF.6, DEV.9, DEV.10 |
| edit | `docs/overview.md` | REF.2, DEV.11 … DEV.14 |
| edit | `README.md:465` (delete the diagrams row) | REF.2, R-DOC-README.4 |
| edit | `docs/architecture.md` (D-4 shape) | REF.1 … REF.3, DEV.12, DEV.13, ARCH.1 … ARCH.6 |
| edit | `examples/case_00_public/MANIFEST.md` | DEV.15 |
| create | `.dev-flow/design/archive/architecture-batch-declarations-88-100.md` (verbatim blocks from `docs/architecture.md`) | ARCHIVE.2 |
| git mv | `PENDIENTES-batch96.md` → `.dev-flow/design/archive/PENDIENTES-batch96.md` | ARCHIVE.1, REF.3 |
| git mv | `docs/crc-algorithm-designer/01-requirements.md` → `.dev-flow/design/archive/crc-algorithm-designer-requirements-draft-2026-07-20.md` | ARCHIVE.1, REF.1 |
| git mv | `tools/synth/VERIFY.md` → `.dev-flow/design/archive/synth-case08-release-demo-VERIFY.md` | ARCHIVE.1 |
| git rm | `docs/diagrams/architecture.md` | ARCHIVE.3, REF.1, REF.5, REF.6 |
| git rm | `examples/case_00_public/from_source_input.txt`, `examples/case_00_public/s19_sample.txt` | ARCHIVE.3 |
| git rm -r | `.fast-dev-flow/` (33 files) | ARCHIVE.3, REF.3, REF.4 |
| unchanged (decided) | `docs/CENSUS-BASELINE-canon-mirror.md` (D-2), `tools/id_registry.py`, `tools/seed_id_registry.py`, `AT-TC-REGISTRY.jsonl`, `.gitignore`, `.gitattributes` (D-3, exempt lines X-1 … X-5) | — |

## 3. Tests

| Action | File | What | Rows |
|---|---|---|---|
| comment / docstring only | `tests/test_report_logging.py` | module docstring `:3` (`.fast-dev-flow/spec.md`) | REF.3, REF.4 |
| comment / docstring only | `tests/test_tui_evidence_packs.py` | module docstring `:4` | REF.3, REF.4 |
| comment / docstring only | `tests/test_tui_report_seam.py` | module docstring `:4` | REF.3, REF.4 |
| comment / docstring only | `tests/test_tui_directionb.py` | `:7016` (docstring of `test_tc030_operations_binding_shown_in_footer`), `:7213` (comment), `:7578` (docstring of `test_at_038c_a2l_error_row_keeps_severity_style`), `:8973` (comment) | REF.3, REF.4 |
| comment only | `tests/test_tui_patch_editor_v2.py:1905`, `tests/test_tui_snapshot.py:413` | REF.4 |
| docstring only | `tests/test_tui_map_big.py:2918` (helper `_demo_loaded`), `tests/test_tui_patch_layout.py:287` (helper `_fully_visible`) | REF.3 |
| guard, body widened | `tests/test_docs_canon.py::test_at285_no_live_cdfx_or_s19tool_console_script_token` — scope from 3 files to every repository document (CTX-DOCHYG); `_HISTORIC` and `_S19TOOL_OK` gain the shapes of CTX-DOCHYG (`retired`, `moved`, `.s19tool\`, `s19tool.egg-info`, `pip <verb> s19tool`); docstring cites R-DOC-REF.5, R-DOC-REF.6 | REF.5, REF.6 |
| guard, new file | `tests/test_b101_doc_hygiene.py` (E4 tester) — one test per row family, names carrying the row id (`test_r_doc_ref_1_…` … `test_r_doc_archive_3_…`) | REF.1 … REF.4, DEV.1 … DEV.15, ARCH.1 … ARCH.6, ARCHIVE.1, ARCHIVE.3 |

New test file: **1** → `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` is re-measured at integration. The guards read text and `git ls-files` only; none imports `s19_app` (ARCH.1 reads `git ls-files '*.py'`; DEV.2 reads `s19_app/cli.py` as text).

## 4. Nodes touched (no node renamed, none deleted)

- `tests/test_tui_directionb.py::test_tc030_operations_binding_shown_in_footer` — docstring line only.
- `tests/test_tui_directionb.py::test_at_038c_a2l_error_row_keeps_severity_style` — docstring line only.
- `tests/test_docs_canon.py::test_at285_no_live_cdfx_or_s19tool_console_script_token` — body (file scope and allowed shapes) and docstring; name unchanged.
- Module docstrings / comments outside any node: `tests/test_report_logging.py`, `tests/test_tui_evidence_packs.py`, `tests/test_tui_report_seam.py`, `tests/test_tui_directionb.py` (`:7213`, `:8973`), `tests/test_tui_patch_editor_v2.py:1905`, `tests/test_tui_snapshot.py:413`; helpers `_demo_loaded` (`tests/test_tui_map_big.py`), `_fully_visible` (`tests/test_tui_patch_layout.py`).
- New nodes: in `tests/test_b101_doc_hygiene.py` only.

## 5. Counts

| Item | Count |
|---|---|
| Functions changed | 0 |
| Source files under `s19_app/` | 3 (2 comment-only, 1 Markdown deleted) |
| Documents edited | 9 (`CLAUDE.md`, `PROJECT_RULES.md`, `docs/engineering-rules.md`, `requirements.txt`, `docs/README.md`, `docs/overview.md`, `README.md`, `docs/architecture.md`, `examples/case_00_public/MANIFEST.md`) |
| Files created | 1 (architecture archive) + 1 test file |
| Files moved (`git mv`) | 3 |
| Files removed (`git rm`) | 37 (33 `.fast-dev-flow/`, diagrams, `REQ-crc.md` counted in §1, 2 example `.txt`) |
| Test files with comment/docstring edits | 8 |
| Test files with guard changes | 2 (1 widened, 1 new) |
| Requirements | 31 (30 new + `R-DOC-README.4` unchanged) |
