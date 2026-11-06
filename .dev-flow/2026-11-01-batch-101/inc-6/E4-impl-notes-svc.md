# Inc 6 — E4 implementation notes (Unit B: service + panel + help + docs)

Batch 2026-11-01-batch-101, increment 6. Implementer unit B (E4). Files touched:
`s19_app/tui/services/change_service.py`, `s19_app/tui/screens_directionb.py`,
`s19_app/tui/window_help.py`, and the four doc files the E1 addenda assign to E4
(`README.md`, `docs/user-guide/ch08-patch-editor.md`,
`docs/user-guide/ch10-check-editor.md`, `docs/user-guide/DOSSIER.md`).
`app.py` and the test files are the other unit's; not touched here.

## 1. Functions changed

| File | Function | Slice # | Change |
|---|---|---|---|
| `s19_app/tui/services/change_service.py` | `ChangeService.__init__` | #24 | Adds `self._last_check_message: str = ""` beside `_last_check_stamp`. |
| `s19_app/tui/services/change_service.py` | `ChangeService.run_checks` | #25 | Stores the composed status message (blocked and runnable branches) in `_last_check_message` before returning. |
| `s19_app/tui/services/change_service.py` | `ChangeService.check_run_is_current` | #26 | **New** (I-1): `last_check_result is not None and _last_check_stamp == (_document_signature(), image_generation)`. |
| `s19_app/tui/services/change_service.py` | `ChangeService.check_status_line` | #27 | **New** (I-2): `_last_check_message` while `check_run_is_current()`, else `""`. |
| `s19_app/tui/services/change_service.py` | `ChangeService.check_aggregates` | #28 | All-zero while `not check_run_is_current()` (was: only while `last_check_result is None`). |
| `s19_app/tui/services/change_service.py` | `ChangeService._check_glyphs` | #29 | Refuses via `check_run_is_current()` (was: its own `result is None` + stamp comparison). Behaviour unchanged. |
| `s19_app/tui/services/change_service.py` | `ChangeService.end_check_run` | #34 | **New** (I-7): `last_check_result = None`, `_last_check_message = ""`; idempotent. |
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel.refresh_check_results` | #30 | Subtitle `f"{len(rows)} checked" if status_line else "no run yet"` (was: gated on `rows`). Status, strip and row rendering unchanged. |

## 2. Doc / help text changed

`file:line` uses the base line numbers the design cites (`old → new`).

| File:line | Old | New |
|---|---|---|
| `s19_app/tui/window_help.py:113-114` | `File — picks a change file in \`patches/\`, or takes a typed path for Load.` | `File — picks a change file in the project's \`checks/\` and \`patches/\` then the common \`library/\`, or a typed path for Load.` |
| `s19_app/tui/window_help.py:116` | `Refresh — re-reads the file list of \`patches/\`.` | `Refresh — re-reads the file list (project files, then the library).` |
| `s19_app/tui/window_help.py:530-531` | `Spec — loads a check spec from the patches folder into the collector.` | `Spec — loads a check spec from the project's \`checks/\` then the common \`library/\` into the collector.` |
| `README.md:192-195` | `… **Write .chk.json** writes the spec into the common \`.s19tool/workarea/patches/\` folder, with or without a project; Save project copies the specs the project uses into its \`checks/\` folder.` | `… **Write .chk.json** writes the spec into the check home: the project's \`checks/\` folder with a project open, or the common \`.s19tool/workarea/patches/\` folder without one; the common folder's specs stay reachable in the Spec list as \`library/<n>\`.` |
| `docs/user-guide/ch08-patch-editor.md:109` | `Without a project, **Write before/after report** (or \`b\`) is refused: … (finding F-05 — the notice offers it anyway).` | `Without a project the save-back shows no before/after offer (finding F-05); **Write before/after report** (or \`b\`) is still refused: …` |
| `docs/user-guide/ch08-patch-editor.md:181` | `The Checks tab still shows the results of the earlier check run, from before the project was loaded (finding F-40).` | `The Checks tab shows no stale run after the project load: the earlier check run ended with it (finding F-40).` |
| `docs/user-guide/ch10-check-editor.md:23` | `*Spec* dropdown (check specs in the patches folder)` | `*Spec* dropdown (the project's check specs, then the common library's \`library/<n>\`; without a project, the common patches folder)` |
| `docs/user-guide/DOSSIER.md` §5 F-05 | `usability, live` | `usability, live · fixed in 1.1.0` |
| `docs/user-guide/DOSSIER.md` §5 F-06 | `defect, code` | `defect, code · fixed in 1.1.0` |
| `docs/user-guide/DOSSIER.md` §5 F-40 | `defect, live` | `defect, live · fixed in 1.1.0` |
| `docs/user-guide/DOSSIER.md` §5 F-47 | `to investigate, live` | `to investigate, live · carried to backlog (not reproduced on the base)` |

Every heading and anchor in the edited doc files was kept; the changes are text
only (no link target, heading or anchor touched).

## 3. Deviations

- **DOSSIER fix version marker (`fixed in 1.1.0`).** The design names the rows
  as "fixed" without a release number. The DOSSIER's existing convention pins a
  release (`· fixed in 1.0.0`); `pyproject.toml` is at `1.0.0rc1` and the
  CHANGELOG's newest release is `1.0.0`, so the next release was read as
  `1.1.0`. If the operator prefers a different marker, only the three DOSSIER
  Kind cells and the test unit's `_FIXED` pin need to change together.
- **F-47 marker wording** records the ruling's evidence ("not reproduced on the
  base", D-4 / E1-rulings §4) inside the Kind cell, since the DOSSIER has no
  separate "carried" column.
- **`check_aggregates` / `_check_glyphs` docstrings** were reworded to name
  `check_run_is_current` as the gate (the body changed); the `check_aggregates`
  `Used by` line ("at BOTH call sites") was left as-is because exactly two
  `refresh_check_results` sites still pass the live `check_aggregates()` (the
  run arm and #8; the Check Editor validate arm does not), so the count stays
  true.

## 4. py_compile

`python -m py_compile s19_app/tui/services/change_service.py
s19_app/tui/screens_directionb.py s19_app/tui/window_help.py` → OK (no output,
exit 0). The operator rule (no `pytest`, no `import s19_app`) was respected.

## 5. Line endings

All seven edited files remain pure CRLF (0 bare LF), verified byte-count after
each edit.
