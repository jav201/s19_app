# Inc 16 — E4 implementation notes (U1, developer-facing docs)

Unit U1. Files owned: `CLAUDE.md`, `PROJECT_RULES.md`, `docs/engineering-rules.md` (not its "Test timing, waits and oracles (batch-101 Inc 2)" section), `requirements.txt`, `docs/README.md`, `docs/overview.md`, `README.md` (only the diagrams row), `examples/case_00_public/MANIFEST.md`.

Constraints honoured: no test logic written or edited; `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl`, `tests/test_id_registry.py`, `tests/test_docs_canon.py`, `tests/test_b101_doc_hygiene.py` untouched; no `pytest` run, no `s19_app` import. Line endings preserved: all eight files remain CRLF. No file outside this unit was edited (the parallel edits to `docs/architecture.md` and `tests/test_docs_canon.py` in the working tree are other units').

## Per file — what changed and the rows it satisfies

### CLAUDE.md
- Project layout: "Two console entry points" → "One"; deleted the `` `s19tool` → `s19_app.cli:main` `` bullet, kept `s19tui`. Rows: R-DOC-DEV.1, R-DOC-REF.5.
- `project.toml` paragraph: removed the `:508` / `:523` line citations; named the two readers by file and function — `s19_app/tui/workspace.py` `find_repo_root` and `tests/test_changes_schema.py` repo-root helper. Rows: R-DOC-DEV.6, R-DOC-REF.1.
- CLI examples: `s19tool …` → `python -m s19_app.cli …` for `info`, `verify`, `dump`, `patch-hex`; the block comment now reads "module-only; no console script". Rows: R-DOC-DEV.2, R-DOC-REF.5.
- CI sentence: names `main` and `main-tui` and both lanes — lane 1 parallel (`-m "not serial_timing"`) and lane 2 the timing arms serial (`-m serial_timing`) — verified against `.github/workflows/tui-ci.yml`. Row: R-DOC-DEV.3.
- Removed stale module sizes: `(1.4k LOC)` on `tui/a2l.py`, `~5k-line` on `app.py::S19TuiApp`. Row: R-DOC-DEV.5.
- Hex renderer home: `hexview.py` → `render/hexview.py` in the TUI-layer bullet, and `s19_app/tui/hexview.py` → `s19_app/render/hexview.py` in the docstring-baseline line. Rows: R-DOC-DEV.4, R-DOC-REF.1.

### PROJECT_RULES.md
- Pipeline line `:135`: `s19_app/tui/hexview.py` → `s19_app/render/hexview.py`. Rows: R-DOC-DEV.4, R-DOC-REF.1.

### docs/engineering-rules.md
- Header: removed the "Canonical history: memory project_devflow_control_lineage.md." sentence (the personal memory-file pointer). Row: R-DOC-DEV.7.
- Backlog-routing paragraph: dropped the retired `/fast-dev-flow` arm; the routing fact now names `/dev-flow` alone. Row: R-DOC-REF.4.
- C-34 render-module list: bare `hexview.py` → `render/hexview.py`. Row: R-DOC-DEV.4.
- The "Test timing, waits and oracles (batch-101 Inc 2)" section is byte-identical (only shifted up two lines by the removals above it); it was not touched.

### requirements.txt
- Runtime requirements now equal the `[project] dependencies` of `pyproject.toml`: `rich>=13.0`, `textual>=8.2.8,<9`, `markdown-it-py>=3`. Row: R-DOC-DEV.8.

### docs/README.md
- Rewritten as the short index: no "Project state" block, no batch table, no CDFX token, no `diagrams/architecture.md` row. It links all 12 CTX-DOCINDEX entries — `overview.md`, `architecture.md`, `engineering-rules.md`, `CENSUS-BASELINE-canon-mirror.md`, `requirements/`, `user-guide/` (docs side) and `README.md`, `REQUIREMENTS.md`, `CLAUDE.md`, `PROJECT_RULES.md`, `SECURITY.md`, `CHANGELOG.md` (root). Rows: R-DOC-DEV.9, R-DOC-DEV.10, R-DOC-REF.2, R-DOC-REF.6.

### docs/overview.md
- §1 `:16`: "ten single-context screens" → "twelve single-context screens". Row: R-DOC-DEV.12.
- §3 shell bullet: "**ten** rail screens" → "**twelve** rail screens"; lists the 12 rail labels in B94 order (Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, Check Editor, A2B Diff, Flow Builder, Flow Execution, Checks, CRC Designer) plus the Split / Join / Export window; keys now `1`–`0`, `=`, `]`; the "fourteen" modal count word was dropped while keeping the modal list. Rows: R-DOC-DEV.11, R-DOC-DEV.12.
- Operations bullet: "executable from the in-app Operations modal" → `extract` and `split_by_segment` are "listed but not implemented". Row: R-DOC-DEV.14.
- Test suite line: removed "2760 collected tests (measured 2026-10-11)". Row: R-DOC-DEV.13.
- §6 `:87`: "the rail's ten screens" → "the rail's twelve screens". Row: R-DOC-DEV.12.
- §7 "Where things live": deleted the `diagrams/architecture.md` row. Row: R-DOC-REF.2.

### README.md
- Deleted the `docs/diagrams/architecture.md` documentation-table row (`:465`); the table still links `docs/architecture.md`. Rows: R-DOC-REF.2, R-DOC-README.4.

### examples/case_00_public/MANIFEST.md
- `:3`: "stress-test S19Tool" → "stress-test `s19_app`" (E3 A16-7).
- Listed all 15 example case folders once, by path relative to `examples/`: the 8 top-level `case_01…case_08` folders and the 7 `professional_validation/` cases. Row: R-DOC-DEV.15.

## Deviations from the records

- `docs/README.md` was rewritten whole rather than line-edited. This is not a content deviation: the slice asks for exactly a short index with no state block, no batch table and no CDFX, which is what the rewrite produces.
- `docs/overview.md` "Test suite" line now also names `main-tui` ("pushes to `main` and `main-tui`") in addition to dropping the test count. One-word accuracy addition aligned to `tui-ci.yml`; DEV.13 only required the count removal.
- `examples/case_00_public/MANIFEST.md` gained a blank line after "## Cases" (formatting only, no content change).

## Verification performed (read-only)

- Rail labels read from `s19_app/tui/rail.py` `RAIL_ENTRIES` and `s19_app/tui/app.py` `RAIL_ENTRIES_B94`; window keys from `s19_app/tui/window_help.py` `SHIPPED_WINDOW_KEYS`.
- CLI sub-commands read from `s19_app/cli.py` (`info`, `verify`, `dump`, `patch-hex` present); `[project.scripts]` and `dependencies` read from `pyproject.toml`; lanes and markers read from `.github/workflows/tui-ci.yml`.
- Greps confirmed, across the eight owned files: 0 `tui/hexview.py`, 0 `.py:<line>`, 0 `\d[k -]?(lines?|LOC)`, 0 `fast-dev-flow`, 0 `prototypes/`, 0 `project_devflow_control_lineage`, 0 "Canonical history: memory", 0 "executable from the in-app Operations modal", 0 "2760 collected tests", 0 `diagrams/architecture.md`, 0 CDFX/CDF 2.0 tokens without a removal mark, and no standalone `ten`/`nine`/`eleven`/`thirteen`/`9`/`10`/`11`/`13` word on a `rail` line (the guard's `\b` pattern).
- All eight files verified CRLF after edit.
