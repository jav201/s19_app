# CLAUDE.md — Hex Lab project conventions

Read this first. These are the rules every change must respect.

## Architecture

- `core/` is pure Python. **No** `import textual` here. Ever.
- `widgets/` are presentational. They take data via `__init__`, emit `Message`
  events out. They never call `core` directly.
- `screens/` compose widgets and call `core`. Routing lives here.
- `app.py` owns global key bindings and density.

If you need data from `core` inside a widget: post a Message → screen handles
it → screen pushes the result back into the widget via a method or reactive.

## Style

- Format: `ruff format` (line length 100).
- Lint: `ruff check`. Fix or `# noqa: <code> — <reason>`.
- Types: `mypy --strict` for `core/`. Widgets/screens may relax to
  `--strict-optional` only.
- Strings: f-strings. No `.format()`, no `%`.
- Imports: `from __future__ import annotations` at the top of every module.

## Testing

- Add a test for every public function in `core/`.
- Add a snapshot test for every new screen at 120×30.
- `pytest -q` must pass on Python 3.10, 3.11, 3.12.
- Run `pytest-textual-snapshot` and review SVG diffs before committing.

## TUI conventions

- Every action reachable by mouse must also be reachable by keyboard.
- Status bar binds (`BINDINGS` with `show=True`) are the user's contract —
  never silently break a binding.
- One accent color (`$accent`, calm cyan-blue) plus three severity colors
  (`$sev-ok`, `$sev-warn`, `$sev-error`). Don't add more.
- Never `print()`. Use `self.app.notify()` for user-visible messages and
  `self.log()` for dev console output.
- Long-running work goes in a `@work(thread=True)` worker, never the UI thread.

## Commits

- Reference the relevant Step in `handoff/PLAN.md` (e.g. "Step 3 — MAC
  per-byte overlay").
- One concept per commit. Refactors and feature additions go separately.

## When in doubt

Re-read `handoff/PLAN.md` §3 (Architecture) and §7 (Things to NOT do).
The mocks at `Hex Lab.html` are the visual spec — open them in a browser when
working on a screen and match the proportions of the corresponding artboard.
