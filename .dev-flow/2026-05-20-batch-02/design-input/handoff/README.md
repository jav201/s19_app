# Hex Lab — Textual rewrite (Direction B)

A real, runnable Textual sketch of **Direction B (Rail + Command)** from the HTML mocks.

This isn't a full port — it's a vertical slice that proves the mock translates to Textual cleanly.
What's in here:

- `pyproject.toml` — installs as `hexlab` console script
- `src/hexlab/app.py` — the Textual `App`, key bindings, screen routing
- `src/hexlab/screens/workspace.py` — Direction B workspace screen (rail + 3-pane grid)
- `src/hexlab/widgets/command_bar.py` — top command bar (`⌘K` / find / go-to)
- `src/hexlab/widgets/rail.py` — left activity rail
- `src/hexlab/widgets/hex_view.py` — virtualized hex+ASCII pane (skeleton — only renders visible rows)
- `src/hexlab/widgets/memory_map.py` — coverage strip
- `src/hexlab/widgets/inspector.py` — right context panel
- `src/hexlab/core/sample_data.py` — placeholder data so the screen renders without a real .s19
- `src/hexlab/styles.tcss` — the **Calm Dark** theme, ported from `tokens.css`

## Run

```bash
cd handoff
pip install -e .
hexlab
```

Or in dev mode with hot reload:

```bash
textual run --dev src/hexlab/app.py
```

## Key bindings (matches the mock's status bar)

| Key | Action |
|---|---|
| `Ctrl+K` | Focus the command bar |
| `Ctrl+L` | Load project |
| `Ctrl+S` | Save project |
| `/` | Focus the find input |
| `g` | Go-to address |
| `1`–`8` | Switch rail screen |
| `q` | Quit |

## What's NOT in the sketch (intentionally)

These are listed in `PLAN.md` as next steps for the full rewrite:

- A2L parsing (uses `pya2l` or roll your own)
- SREC parsing (uses `bincopy`)
- Real CRC / checksum engine
- Patch editor (before/after diff view)
- Diff screen (A↔B firmware compare)
- Save/Load modals wired to a real project format
- Snapshot tests (`pytest-textual-snapshot`)

## Theme parity with the mock

The HTML mock uses OKLCH; Textual CSS uses standard hex/RGB. Conversion table is in
`styles.tcss` comments. Density and accent color are exposed as `App.theme` toggles
(see `app.py::action_cycle_density`).
