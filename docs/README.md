# `s19_app` — Project documentation index

Project-level documentation for `s19_app` (distribution name `s19tool`) — an offline desktop tool for embedded / automotive firmware engineering (S19 / Intel-HEX / A2L / MAC analysis, ASAM CDFX exchange for vCDM, unified parameter + memory change-set).

This `docs/` directory holds the **general** documentation that sits above the per-batch dev-flow archives. For per-batch detail (requirements, decisions, test verdicts, post-mortems), follow the batch links below.

---

## Start here

| Document | For |
|---|---|
| [overview.md](./overview.md) | what `s19_app` is, who it's for, current capabilities, typical workflow, what's deferred |
| [architecture.md](./architecture.md) | three-layer architecture, Direction B TUI shell, `cdfx/` package, Patch Editor flow, path / XML / JSON safety, engine invariant, testing |
| [diagrams/architecture.md](./diagrams/architecture.md) | canonical living Mermaid diagrams (system, TUI shell, two-regime layout, CDFX, memory layer) |

## Living references

| Document | Role |
|---|---|
| [../README.md](../README.md) | install + CLI + TUI usage |
| [../REQUIREMENTS.md](../REQUIREMENTS.md) | living `R-*` traceability — engine, batch-02 `R-TUI-021..037`, batch-03 `R-CDFX-001..018`, batch-04 `R-MEM-001..005` |
| [../CLAUDE.md](../CLAUDE.md) | coding conventions, common commands, file-layer rules, the docstring / type-hint contract |

## Per-batch archives

Each batch was delivered through GRNDIA's six-phase V-model dev-flow. Artefacts (requirements, review, validation, post-mortem, docs) are archived per batch under `.dev-flow/<batch>/`.

| Batch | Headline | Local archive |
|---|---|---|
| `2026-05-05-batch-01` | s19_app QA audit / review (integrity + functionality pass with the dev-flow agents) | [.dev-flow/2026-05-05-batch-01/06-docs/executive-summary.md](../.dev-flow/2026-05-05-batch-01/06-docs/executive-summary.md) |
| `2026-05-20-batch-02` | Direction B TUI restyle — activity rail + command bar + 8 screens; engine frozen | [.dev-flow/2026-05-20-batch-02/06-docs/executive-summary.md](../.dev-flow/2026-05-20-batch-02/06-docs/executive-summary.md) |
| `2026-05-21-batch-03` | Functional Patch Editor + ASAM CDFX read/write (CDF 2.0 for vCDM) | [.dev-flow/2026-05-21-batch-03/06-docs/executive-summary.md](../.dev-flow/2026-05-21-batch-03/06-docs/executive-summary.md) |
| `2026-05-21-batch-04` | Memory-value editing + `UnifiedChangeSet` + selective export (CDFX + memory JSON) | [.dev-flow/2026-05-21-batch-04/06-docs/executive-summary.md](../.dev-flow/2026-05-21-batch-04/06-docs/executive-summary.md) |

Current dev-flow batch state: [.dev-flow/state.json](../.dev-flow/state.json).

## Project state

- **Branch:** `main` — latest merge `86f4910`, clean working tree.
- **Tests:** 762 pass / 3 xfailed / 2 skipped — 0 failures, 0 regressions across the four batches.
- **Engine invariant:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` byte-for-byte unchanged across batches 02–04 (SHA-256-pinned).
- **Status:** active development. Apply-to-image / undo-redo / CRC / bookmark persistence / PDF report / live vCDM round-trip are tracked for follow-up batches (see [overview.md](./overview.md) §6).
