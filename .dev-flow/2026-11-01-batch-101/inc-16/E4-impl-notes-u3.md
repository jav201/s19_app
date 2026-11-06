# Inc 16 — E4 implementation notes — U3 (moves, removals, comments)

Unit scope: the three `git mv` moves, the removals, and the comment/docstring-only
edits in the two source files and the eight test files of `E1-slice.md` §3 rows 1-7.
No code token, statement, test name or assertion was changed. No line ending changed
(every file was LF before and after).

## Moves (`git mv`, ×3)

| From | To | Note |
|---|---|---|
| `PENDIENTES-batch96.md` | `.dev-flow/design/archive/PENDIENTES-batch96.md` | line 3 redacted per D-8 (see below); no personal name was present (the note already says "the operator"). |
| `docs/crc-algorithm-designer/01-requirements.md` | `.dev-flow/design/archive/crc-algorithm-designer-requirements-draft-2026-07-20.md` | verbatim. |
| `tools/synth/VERIFY.md` | `.dev-flow/design/archive/synth-case08-release-demo-VERIFY.md` | verbatim. |

Redaction detail (D-8): the moved `PENDIENTES-batch96.md` line 3 held a source path
into a synced cloud folder on a drive letter. In the moved copy the drive letter and
cloud-folder portion was replaced by `<operator drive>/`, keeping the scan filename,
so the line no longer carries a drive-letter cloud-folder path (R-DOC-ARCHIVE.4). The
illustrative sample path near the end of the note (an example field) was
left as-is per E3 ruling A16-6 (a sample path, not a local identity).

## Removals (`git rm`)

- `docs/diagrams/architecture.md`
- `examples/case_00_public/from_source_input.txt`
- `examples/case_00_public/s19_sample.txt`
- `s19_app/tui/operations/requirements/REQ-crc.md`
- `git rm -r .fast-dev-flow/` (33 tracked files)

All removed paths are absent from `git ls-files` and from the working tree.

## Comment/docstring edits — source files

| File:line | Old | New |
|---|---|---|
| `s19_app/tui/legend.py:381-382` | `The operator ruling of 2026-08-06 (legend A, captured in` / ` ``prototypes/memmap2_legend_A.120w.svg``) replaced the map's annotated` | `The operator ruling of 2026-08-06 (legend A, the HLR-132 legend sheet)` / `replaced the map's annotated` |
| `s19_app/tui/legend.py:832` | `#: ``prototypes/legend_n8.kimi.NOTES.md`` / ``legend_n8.INVENTORY.md``. Rendered` | `#: the batch-n8 legend notes. Rendered` |
| `s19_app/tui/services/project_gather_service.py:3` | `Change 1 of the operator's 2026-10-12 round (``prototypes/cambios_10_12_2026``):` | `Change 1 of the operator's 2026-10-12 round (batch-95 / batch-97):` |

## Comment/docstring edits — test files

| File:line | Old | New |
|---|---|---|
| `tests/test_report_logging.py:3` | `Covers the spec ACs for `.fast-dev-flow/spec.md` batch `n3-report-logging`:` | `Covers the spec ACs of batch `n3-report-logging`:` |
| `tests/test_tui_evidence_packs.py:4` | ` ``.fast-dev-flow/spec.md`` §3 AC-B1/AC-B2.` | `§3 AC-B1/AC-B2.` |
| `tests/test_tui_report_seam.py:4` | ` ``.fast-dev-flow/spec.md`` §3 AC-A1/A2/A3.` | `§3 AC-A1/A2/A3.` |
| `tests/test_tui_directionb.py:7016` | `    Intent: fast-dev-flow AC "x/Operations is footer-discoverable" — now row 1` | `    Intent: AC "x/Operations is footer-discoverable" — now row 1` |
| `tests/test_tui_directionb.py:7213` | `# fast-dev-flow (sections-label) — Data Sections range label two-line wrap.` | `# (sections-label) — Data Sections range label two-line wrap.` |
| `tests/test_tui_directionb.py:7578` | `    ``.fast-dev-flow/spec.md`` §AC-5.)` | `    §AC-5.)` |
| `tests/test_tui_directionb.py:8973` | `# batch-31 (fast-dev-flow P1 quick strike) — Inc-1 geometry.` | `# batch-31 (P1 quick strike) — Inc-1 geometry.` |
| `tests/test_tui_patch_editor_v2.py:1905` | `# batch-31 (fast-dev-flow P1 quick strike) — Inc-1 geometry, AC-4 (B-05).` | `# batch-31 (P1 quick strike) — Inc-1 geometry, AC-4 (B-05).` |
| `tests/test_tui_snapshot.py:413` | `# batch-31 (fast-dev-flow P1 quick strike) geometry drift: AC-5/AC-7 (B-06` | `# batch-31 (P1 quick strike) geometry drift: AC-5/AC-7 (B-06` |
| `tests/test_tui_map_big.py:2918` | `    Mirrors ``prototypes/memmap2.tui_prototype.py::_fixture`` — the capture` | `    Mirrors the memmap2 prototype's ``_fixture`` — the capture` |
| `tests/test_tui_patch_layout.py:287` | `    Lifted from ``prototypes/patch_editor_layout.prototype.py:243-259``: the` | `    Lifted from the patch-editor layout prototype: the` |

Every retired-folder token and retired-workflow name is gone from the ten Python
files above (verified by grep for `fast-dev-flow`, `.fast-dev-flow/`, `prototypes/`).
The `docs/architecture.md` `prototypes/` citations and the `docs/engineering-rules.md`
`fast-dev-flow` routing line belong to another unit, not to this one.

## `py_compile` results

`python -m py_compile` over the ten edited `.py` files:

- `s19_app/tui/legend.py` — OK
- `s19_app/tui/services/project_gather_service.py` — OK
- `tests/test_report_logging.py` — OK
- `tests/test_tui_evidence_packs.py` — OK
- `tests/test_tui_report_seam.py` — OK
- `tests/test_tui_directionb.py` — OK
- `tests/test_tui_patch_editor_v2.py` — OK
- `tests/test_tui_snapshot.py` — OK
- `tests/test_tui_map_big.py` — OK
- `tests/test_tui_patch_layout.py` — OK

All 10 compiled with no errors.

## Deviations

None. Every slice line number was found at the cited location, every move/removal
matched its target name, and the redaction follows D-8 as ruled. The
`project_gather_service.py:3` citation uses the slice's exact wording
`batch-95 / batch-97` (verified: HLR-138, the save-gather, is a batch-95 record; the
operator's 2026-10-12 round spans those two batch folders). Line endings were
verified LF before and after each edit.
