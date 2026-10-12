# CHUNK — Kimi K2.7-code — batch-91 increment 002 (the docs catch-up)

You implement batch-91's increment 002 in `C:/Users/jjgh8/Github/s19_app`:
the docs describe the shipped app. Read the contract first:
`.dev-flow/2026-10-08-batch-91/01-requirements.md` — HLR-123 / LLR-123.1/.2/.3.

## SANDBOX
- NEVER write or run outside the project tree: no /tmp, no site-packages. Scratch
  under `.dev-flow/2026-10-08-batch-91/evidence/`. No git.
- DO NOT touch `tests/` or `AT-TC-REGISTRY.jsonl` — a parallel increment owns them.

## THE WORK — `README.md`, `docs/overview.md`, `docs/architecture.md`,
## `docs/crc-algorithm-designer/01-requirements.md` ONLY.

1. **README.md**:
   - Kill the CDFX promise (the `tui/cdfx/` package is deleted — the shipped
     replacement is the v2 change-set JSON + the patched S19/HEX image emit; say
     that). Every line that names CDFX as live must go or read as history.
   - Add the undocumented shipped surfaces: the variants system (project.json
     manifest, per-variant assignments, variant-scoped execution, the fused
     report), the Flow Builder screen, the CRC Designer screen, the Operations
     modal, the undocumented global keys (`U` unload-all, `r` refresh, `o` open
     workarea, `v` variant, `j` A2L JSON dump, `t` report viewer, `b` before/after,
     `+`/`-`/`,`/`.`/PgUp/PgDn paging, `Ctrl+Z`/`Ctrl+Y` undo/redo) — read the real
     keymap in `s19_app/tui/app.py` (the BINDINGS ~app.py:1339) and write the truth,
     every bound key documented or deliberately left out with a reason.
   - The CLI: the README's CLI section should note `s19tool` is the library's
     legacy module-only CLI (`python -m s19_app.cli`), not a console script, with
     the TUI as the product surface.
2. **docs/overview.md + docs/architecture.md**: they describe the batch-02..04 app
   (8 screens, the A↔B Diff as "static placeholder", the CDFX package, `s19tool`).
   Rewrite the stale parts to the shipped app: the 10 rail screens (Workspace, A2L
   Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Flow
   Builder, Checks, CRC Designer) + the 14 modals; the engines list (the parsers,
   the validation engine's 17 issue codes, the change-set engine v2, the CRC
   family, the entropy service); keep their structure and style — correct the
   content, don't rewrite the genre. Mark superseded claims as superseded or drop
   them; NEVER leave a sentence describing the old app as if current.
3. **docs/crc-algorithm-designer/01-requirements.md**: header note that it is the
   designer's DESIGN record (pre-ship); the shipped behavior is the CRC Designer's
   screen contract in the canon.

## DISCIPLINE
- Verify every surface you name against the code (`s19_app/tui/app.py` screens +
  BINDINGS, `pyproject.toml`'s scripts, the engines' modules) — a doc naming a
  thing that does not exist is the exact defect this batch closes.
- Run nothing but: `python -m pytest tests/test_id_registry.py -q -p no:cacheprovider`
  (sanity) — the coordinator owns the full suite.
- Match each doc's existing voice/structure; English; shipped tone.

## REPORT BACK
Per file: what changed (the stale claims corrected, the surfaces added), the
keymap-vs-README reconciliation (every bound key's status), anything punted.
