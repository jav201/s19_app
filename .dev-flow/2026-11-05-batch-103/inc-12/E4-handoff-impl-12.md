# E4 handoff — Inc 12 implementer (DeepSeek v4 Pro)

## Role and ownership

Implement the approved Code-Wire graph for **Inc 12 — A2L tag table: no glued or cut values**. An independent tester works in another worktree; do not read or write its branch.

You are in worktree branch `b103-inc12-code`, cut from `batch-103` at the current session start. Own **only `s19_app/tui/app.py`**. Do not edit tests, requirements, the case ledger, snapshots, or any other source file. One source file is the whole increment.

## Read first

1. `.dev-flow/2026-11-05-batch-103/inc-12/codewire/graph-inc12.md` — implement every changed/new node, including the E3 corrections and the existing `_repaint_a2l_tag_cells` consumer.
2. `inc-12/01-requirements.md` — all eight active rows R-TUI-042a.2 through .8 and the definitions.
3. `inc-12/E3-rulings.md` — every round; rulings win over stale graph wording. Report any disagreement instead of changing records.
4. `inc-12/E1-rulings.md`, `E1-slice.md`, `E2-rulings.md`.
5. `CLAUDE.md` and `PROJECT_RULES.md` — style, type hints and mandatory docstring sections.
6. Current `s19_app/tui/app.py`; it already contains batch-101 Inc 10b's `_repaint_a2l_tag_cells`. Inc 1b has not landed, so `A2LTagTable` directly subclasses `DataTable` as I-12.2 permits.

## Required implementation

- `A2LTagTable(DataTable)` with `cell_padding=1`, `fixed_columns=2`, its namespaced bubbling `Measured` message from the table's own `on_resize`, and the app handler that stops the message and fits directly. Do not add a fit to `S19TuiApp.on_resize` or `action_show_screen`.
- Column/cell order Address, Length, Tag, then the existing 13 columns unchanged. Keep all existing values, styles, row keys and the full-name copy seam.
- `_build_a2l_table_cells(tag, name_width=None)` and pure `_shorten_tag_name`: middle cut capped at 34; characters outside U+0021…U+007E become U+FFFD; project only the retained slices; O(width), never scan a hostile tail; width below 1 behaves as 1.
- `_a2l_tag_name_width`, `_fit_a2l_tag_cells`, the post-refresh fit after every non-empty page build, and `_repaint_a2l_tag_cells` passing the measured width. Fit rewrites in place only when a Tag cell differs; no new `S19TuiApp` instance attribute; preserve cursor, scroll and detail card.
- `_card_value_text`, `_card_field`, `_a2l_detail_card_text`: every file-derived card value uses the one helper; each maximal TAB/LF/CR run becomes one space before `safe_text`; all other controls are scrubbed. Add the Name line only when the header uses a display identifier. Preserve the existing header, address, layout and styles.
- Update every docstring/comment that describes the old zero padding, cell order, index 0, raw card append, or rebuild-based fit. New/changed functions need the project's full docstring structure and accurate types.

## Rules

- English code and docstrings; match surrounding idioms. No new dependency and no whole-file rewrite.
- On this Windows PC run **only** `python -m py_compile s19_app/tui/app.py`. Do not import `s19_app`, run the app, run pytest, or run probe scripts here. The orchestrator runs all tests and probes on Linux.
- No clipboard access, proprietary/operator A2L text, corpus text in records, secrets, push, merge, rebase, reset, or branch deletion.
- If the approved design cannot be followed, record the deviation in your final report; do not silently change scope or interfaces.
- Commit your single source-file change on `b103-inc12-code` as `batch-103 Inc 12 E4: implement tag table (DeepSeek)` with `Co-Authored-By: DeepSeek V4 Pro`. Do not commit `__pycache__` or other generated files.

## Report (concise)

Node-to-function summary, exact commands and exit codes, commit id, deviations/open concerns. Do not claim behavioral verification from `py_compile`.
