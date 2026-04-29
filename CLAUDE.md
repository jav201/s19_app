# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project layout

Single Python package `s19_app/` (distribution name `s19tool`) plus a `tests/` suite, with `examples/` carrying realistic S19/HEX/A2L/MAC fixtures used both as TUI inputs and parser-stress targets. Two console entry points are exposed via `pyproject.toml`:

- `s19tool` → `s19_app.cli:main` (Rich-formatted CLI)
- `s19tui`  → `s19_app.tui:main` (Textual TUI)

Note: the active build config is `pyproject.toml`. A nearly-identical `project.toml` also lives at the repo root and is only the historical pre-PEP 621 copy — do **not** edit it expecting setuptools to read it. Only `pyproject.toml` is read by the build backend; keep them aligned if you must change one.

## Common commands

```bash
# Install the package in editable mode (preferred for dev)
pip install -e .

# Or install runtime deps only
pip install -r requirements.txt

# Run the full test suite
pytest -q

# Skip stress/perf smoke tests (registered under the "slow" marker in pyproject.toml)
pytest -q -m "not slow"

# Run a single test file or test
pytest tests/test_tui_app.py
pytest tests/test_tui_app.py::test_filter_a2l_tags_supports_in_memory_and_boolean_fields

# Regenerate large stress fixtures outside pytest (uses tests/conftest.py generators)
python tests/generate_large_samples.py

# Launch the TUI (optionally with a file pre-loaded)
s19tui
s19tui --load examples/case_00_public/prg.s19

# CLI examples
s19tool firmware.s19 info
s19tool firmware.s19 verify
s19tool firmware.s19 dump --start 0x7AF0 --length 64
s19tool firmware.s19 patch-hex --addr 0x80040000 --bytes "01 02 03 04" --save-as out.s19
```

CI (`.github/workflows/tui-ci.yml`) runs `pytest -q` on Python 3.11 against pushes/PRs to `main-tui`.

## Architecture

The system has three layers that should be modified together when behavior crosses boundaries: **parsers** → **range/validation engine** → **TUI services + view code**.

### Parsing layer (`s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/mac.py`, `s19_app/tui/a2l.py`)

- `S19File` and `IntelHexFile` build a sparse `Dict[int, int]` memory map plus contiguous `(start, end)` ranges and per-line `errors`. Both are designed to **collect** validation failures (per-record + per-file) without aborting the load — preserve that contract. Address-length and checksum rules per record type are documented in the header comment of `core.py`.
- `tui/a2l.py` (1.4k LOC) is the canonical A2L module. The four sibling files `a2l_parse.py`, `a2l_extract.py`, `a2l_render.py`, `a2l_validate.py` are thin re-export facades around it — add new public symbols to `a2l.py` and re-export from the matching facade so imports stay narrow.
- `tui/mac.py` parses `.mac` `TAG=hexaddr` files and emits both records and human-readable diagnostics.

### Range/validation engine (`s19_app/range_index.py`, `s19_app/validation/`)

- `range_index.py` is the binary-search membership primitive (`build_sorted_range_index`, `address_in_sorted_ranges`, `range_in_sorted_ranges`). Use it instead of linear scans whenever checking many addresses against many ranges — it is shared by both the validation engine and the hex view.
- `validation/engine.py::validate_artifact_consistency` is the cross-artifact entry point that fuses S19 ranges, A2L tags, and MAC records into a single `ValidationReport(issues, coverage)`. `validation/rules.py` holds per-artifact rules; `validation/model.py` defines `ValidationIssue`, `ValidationSeverity`, and `CoverageMetrics`. Issue codes (e.g. `CROSS_MAC_S19_OUT_OF_RANGE`, `TRIPLE_NAME_ADDRESS_MISMATCH`) are public contract — tests assert on them, so do not rename without grepping `tests/`.
- Severity colours flow through `tui/color_policy.py::SEVERITY_CLASS_MAP`, which is the single source of truth for the TUI's `sev-*` CSS classes.

### TUI layer (`s19_app/tui/`)

- `app.py::S19TuiApp` is a ~5k-line Textual `App`. It is intentionally orchestration-only: parsing/enrichment/validation calls are routed through `tui/services/` (`load_service.build_loaded_s19/build_loaded_hex`, `a2l_service.enrich_tags_and_render`, `validation_service.build_validation_report`). When adding new feature logic, **prefer extending a service** and calling it from the app; only put UI state machinery in `app.py`. PROJECT_RULES.md explicitly calls this module out for ongoing decomposition.
- `models.py::LoadedFile` is the snapshot every renderer reads. It is built on a worker thread by `_parse_loaded_file`, then handed to `_apply_loaded_file` which calls each `update_*` renderer on the main UI thread. Keep this thread split — renderers must not parse files.
- `hexview.py` produces all hex/ASCII output (`render_hex_view_text`, `find_string_in_mem`, `_collect_hex_rows`). The constants `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, and `SEARCH_ENCODING` cap rendering cost and are part of the public API exported from `tui/__init__.py`.
- `screens.py` defines the modal Load/Save/Project screens and the `SaveProjectPayload` dataclass passed back to `S19TuiApp`.
- `workspace.py` owns the on-disk `.s19tool/` layout: `.s19tool/workarea/temp/` for transient loads, `.s19tool/workarea/<project>/` for saved projects (one S19/HEX + one MAC + one A2L max — enforced by `validate_project_files`), and `.s19tool/logs/s19tui.log` (5 MB rotating). Project names are normalized through `sanitize_project_name`. Path resolution for user-typed inputs goes through `resolve_input_path` which walks both the app cwd and the nearest repo root (`find_repo_root` looks for `pyproject.toml`/`project.toml`).

### Severity / colour conventions (from REQUIREMENTS.md)

A2L row colouring: Red = schema/structural failure; Green = memory-checked + present; White = valid record without image hit; Grey = not yet checked. MAC row colouring adds Orange for warning-level overlap/alias/symbol-only-in-MAC findings. Validation logic that affects row colour must produce a `ValidationIssue` whose severity round-trips through `css_class_for_severity`.

## Conventions to preserve

- **Docstrings**: PROJECT_RULES.md is enforced for non-trivial functions/methods. Use the fixed section order `Summary → Args → Returns → Raises → Data Flow → Dependencies → Example`. The `Data Flow` and `Dependencies` (`Uses` / `Used by`) sections are not optional on new public functions; existing files in `s19_app/tui/a2l.py`, `s19_app/tui/hexview.py`, and `s19_app/tui/app.py` are the style baseline.
- **Type hints**: mandatory for new/changed functions and must agree with the Args/Returns docstring types.
- **Function granularity**: split when a function exceeds ~40-60 logical lines, mixes parse/validate/render concerns, or accumulates 3+ side effects. Prefer pipelines like `sections → segments → tags → validated_tags` at call sites.
- **Requirements traceability**: REQUIREMENTS.md maps each `R-*` requirement to specific files and tests with status (`Automated` / `Partial` / `Manual`). When you add behavior covered by a requirement, update the corresponding `R-*` entry; when you add a test that promotes a `Manual` or `Partial` row to `Automated`, update its status line.
- **Stress fixtures**: `tests/conftest.py` exposes `large_s19`, `large_a2l`, `large_mac`, and `large_project` fixtures via deterministic generators (`make_large_s19/a2l/mac`). Reuse these — do not introduce ad-hoc large-file builders.
- **Generated artefacts**: `.s19tool/`, `.cursor/`, `*.log`, `__pycache__/`, and `*.egg-info/` are gitignored; never commit work-area or log output.
