# Hex Lab — Claude Code Handoff Plan

> Read this top-to-bottom before writing any code. The HTML mocks under
> `../Hex Lab.html` are the visual spec. The Textual sketch in this folder
> is the architectural spec. Your job is to flesh out the sketch into a
> working tool while staying faithful to **Direction B (Rail + Command)**.

---

## 1. Goal

Replace the existing `s19_app` CLI with a Textual TUI that handles SREC files,
A2L symbol explorer, MAC validation, memory-map / CRC checks, patch editing,
and A↔B firmware diffs — all in one keyboard-driven workspace.

**Non-goals (yet):** Web UI, GUI, plugin system, multi-user.

## 2. Stack — exact versions to install

| Layer | Library | Why |
|---|---|---|
| TUI framework | `textual >= 0.79` | Modern Python TUI; CSS styling |
| Rich text | `rich >= 13.7` | Used internally by Textual; we use directly for hex coloring |
| SREC / Intel-HEX | `bincopy >= 20` | Mature, handles all common motorola/intel hex variants |
| A2L parser | `pya2l >= 0.0.13` | Standard Python A2L lib; AST-style API |
| CRC | `crcmod >= 1.7` | Parametric (CRC-32, CRC-16-CCITT, custom polys for ECU vendors) |
| Tests | `pytest`, `pytest-textual-snapshot` | Unit + TUI snapshot |
| Lint / type | `ruff`, `mypy --strict` | Apply to `core/` strictly; widgets can be `--strict-optional` only |

Install: `pip install -e ".[dev]"` from the handoff folder.

## 3. Architecture — the rule that matters

```
hexlab/
  core/      ← pure Python. NO textual imports. Unit-tested.
  widgets/   ← dumb. Take data via __init__, emit Messages out.
  screens/   ← compose widgets, wire to core, handle key bindings.
  app.py     ← global bindings, density toggle, screen routing.
  styles.tcss
```

**Never import Textual from `core/`.** This is the rule that lets us swap to
a GUI later, run domain logic in CI without a TTY, and keep tests fast.

When you find yourself wanting to call into `core` from a widget, instead:
emit a Message → screen catches it → screen calls `core` → screen pushes
result back into the widget via a property or method. Widgets stay dumb.

## 4. Build order — do these in sequence

Each step ships a runnable app. Don't start step N until N-1 actually runs.

### Step 1 · Wire real SREC parsing
- Replace `core/sample_data.py::sample_hex_rows` with `core/srec.py`.
- API: `class FirmwareImage` wrapping `bincopy.BinFile`.
- Methods: `read(addr, length)`, `ranges() -> list[Range]`, `coverage() -> float`.
- Test against fixtures in `tests/fixtures/*.s19`. Use real (sanitized) ECU files.
- HexView already accepts `list[(addr, bytes)]` — feed it from `FirmwareImage.iter_rows()`.

### Step 2 · Real A2L
- `core/a2l.py` — load with `pya2l`, expose `symbols()`, `lookup(addr)`, `at(name)`.
- New screen: `screens/a2l_explorer.py`. Layout from mock `b-a2l` artboard:
  left = symbol tree (`Tree` widget), right = symbol detail.
- Wire ⌘K command bar: typing a symbol name jumps the workspace HexView to that addr.

### Step 3 · MAC validation
- `core/mac.py` — Message Authentication Code check.
- Match the existing CLI's algorithm bit-for-bit. Add a `compare(actual, expected)`
  that returns a `MacReport` with deltas.
- New screen: `screens/mac.py`. Visual: per-byte yellow overlay on HexView.
  HexView already supports `mac_addrs: set[int]` — just feed it the report.

### Step 4 · Memory map + CRC
- `core/crc.py` — wraps `crcmod`. Per-range CRC32 + the vendor's custom polys.
- Screen: `screens/map.py`. The `MemoryMap` widget already exists; extend it
  to render multiple stripes (calc'd / expected / mismatch overlay).

### Step 5 · Patch editor
- `core/patch.py` — `class Patch`: list of `(addr, old_bytes, new_bytes)`.
  `apply(image)`, `revert(image)`, `serialize()`/`deserialize()`.
- Screen: `screens/patch.py`. Side-by-side HexView (before / after) with
  shared scroll. Add `HexView.diff_against(other)` that highlights differences.

### Step 6 · Diff (A↔B firmware)
- Reuses `Patch`-style diff logic on whole files.
- Screen: `screens/diff.py`. Three columns: range list, hex A, hex B. Synced scroll.

### Step 7 · Save / Load project
- `core/project.py` — JSON file, schema in `tests/fixtures/project.schema.json`.
  Captures: open files, bookmarks, applied patches, last cursor.
- Modal screens: `screens/load_modal.py`, `screens/save_modal.py`.
  Use `Textual`'s `ModalScreen` base.

### Step 8 · Polish
- Snapshot test every screen at 80×24, 120×30, 160×40.
- Verify density toggle (`Ctrl+D`) doesn't break layout at any size.
- `pyinstaller` or `shiv` for single-file distribution.

## 5. Visual fidelity — what to copy from the mocks

Open `../Hex Lab.html` in the browser. For each artboard in Direction B:

1. Note exact pane proportions — match in `.tcss` using `width: <fr>`.
2. Note information density (rows visible at a glance) — that's your default density.
3. Note where accents / colors are used. **Use them sparingly** — calm dark theme means
   one accent hue (cyan-blue) plus three severity colors. Don't add more.
4. Status bar contents map directly to `BINDINGS` with `show=True`.

## 6. Testing strategy

- `tests/core/` — unit tests, no Textual. Aim for 90%+ on `core/`.
- `tests/widgets/` — widget snapshot tests. `pytest-textual-snapshot` records SVGs.
- `tests/screens/` — full screen snapshots at multiple sizes.
- `tests/integration/` — drive the App with `App.run_test()`, simulate keypresses,
  assert on widget state.

CI: GitHub Actions, Python 3.10/3.11/3.12, ubuntu + macOS.

## 7. Things to NOT do

- ❌ Don't add a mouse-only feature without a keyboard equivalent.
- ❌ Don't put domain logic in `widgets/` or `screens/`.
- ❌ Don't add new accent colors. Three severity + one accent is the budget.
- ❌ Don't use `print()` — use `app.notify()` or `app.log()`.
- ❌ Don't rely on `time.sleep` in the UI thread; use `asyncio` workers.
- ❌ Don't ship until snapshot tests pass at 80×24.

## 8. Open questions for the human

Before starting, get answers from the project owner on:

1. **A2L variant** — vendor-specific extensions? Which ECU vendor's A2L do we target first?
2. **MAC algorithm** — exact polynomial / key handling? (The current CLI is the reference.)
3. **Custom CRC polys** — list them all, with init values and reflection settings.
4. **Project file format** — must we stay backwards-compatible with the CLI's existing
   project files, or is this a clean break?
5. **Single binary or pip package** — preferred distribution channel?
6. **Telemetry / logging** — anything to capture for support?

## 9. First commit

After reading this doc, your first commit should:

1. Run `pip install -e ".[dev]"` and confirm `hexlab` launches.
2. Replace `core/sample_data.py::sample_hex_rows` with a real `bincopy` reader,
   plumbed through one fixture file.
3. Add `tests/core/test_srec.py` covering: load, range detection, byte read, error cases.
4. Snapshot test the workspace screen at 120×30.

That's Step 1 of §4. Do not skip ahead.
