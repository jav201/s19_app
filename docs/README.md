# `s19_app` — Project documentation index

Project-level documentation for `s19_app` (distribution name `s19tool`) — an offline desktop tool for embedded / automotive firmware engineering (S19 / Intel-HEX / A2L / MAC analysis, calibration change-set authoring, patched-image emission).

This `docs/` directory holds the **general** documentation that sits above the per-batch dev-flow archives. For per-batch detail (requirements, decisions, test verdicts, post-mortems), follow the archive links in [requirements/](requirements/) and the dev-flow archive folders.

---

## Docs

| Document | For |
|---|---|
| [overview.md](./overview.md) | what `s19_app` is, who it's for, current capabilities, typical workflow, what's deferred |
| [architecture.md](./architecture.md) | three-layer architecture, Direction B TUI shell, Patch Editor flow, path / XML / JSON safety, engine invariant, testing |
| [engineering-rules.md](./engineering-rules.md) | project- and stack-specific dev-flow gates and engineering controls |
| [CENSUS-BASELINE-canon-mirror.md](./CENSUS-BASELINE-canon-mirror.md) | frozen census baseline mirror of the requirements canon |
| [requirements/](requirements/) | requirements rationale ([review](requirements/review/)) and earlier canon ([history](requirements/history/)) |
| [user-guide/](user-guide/) | the user guide |

## Root documents

| Document | Role |
|---|---|
| [../README.md](../README.md) | install + CLI + TUI usage |
| [../REQUIREMENTS.md](../REQUIREMENTS.md) | the requirements canon: strict EARS rows per module S0–S17 |
| [../CLAUDE.md](../CLAUDE.md) | coding conventions, common commands, file-layer rules, the docstring / type-hint contract |
| [../PROJECT_RULES.md](../PROJECT_RULES.md) | docstring and function-design contract |
| [../SECURITY.md](../SECURITY.md) | how to report a vulnerability, supported versions |
| [../CHANGELOG.md](../CHANGELOG.md) | release notes |
