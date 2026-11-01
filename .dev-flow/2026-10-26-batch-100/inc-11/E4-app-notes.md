# E4 — G-B implementation notes (app.py + project_gather_service.py)

Implemented by the G-B group (app.py + project_gather_service.py) against the
fixed `interfaces-11.md`, `proto-11-app.md` and the E1/E2/E3 rulings (including
the E4-binding Round 3 addenda). English only. No names. Line numbers are of the
post-edit files (CRLF, unchanged from the base file).

## Functions added / changed / deleted

### app.py

Added (module level, beside `_ProjectImageStep`, lines 1733–1922):
- `_SAVE_KIND_WORDS` (:1733), `_SAVE_ROW_LABELS` (:1740),
  `_SAVE_SUMMARY_CHANGED` (:1750), `_SAVE_REFUSAL_PREFIX` (:1754),
  `_UNSET` (:1758), `_DOCUMENT_UNREADABLE_KEY` (:1765),
  `_unreadable_text(exc: OSError) -> str` (:1768),
  `@dataclass(frozen=True) class _SaveSession` (:1803),
  `@dataclass(frozen=True) class _PreparedSave` (:1835).

Added (methods):
- `_handle_save_dialog` — rewritten as the one-argument router (:10258).
- `_prepare_project_save(name, session=None) -> _PreparedSave` (:10343) —
  G4–G18 moved from the base handler, plus the lazy-inventory fill and P-4.
- `_save_session_inputs() -> _SaveSession` (:10678).
- `_current_save_session() -> _SaveSession` (:10759).
- `_save_dialog_preview(name, session) -> SavePreview` (:10765).
- `_compose_save_preview(prepared) -> SavePreview` (:10801).
- `_confirm_project_save(name, plan) -> Optional[SavePreview]` (:10918).
- `_commit_project_save(prepared, payload) -> None` (:10976) — the base
  commit half (`:9856`–`:10605` on the base), moved verbatim except (d).

Changed (methods):
- `__init__` (:2442) — three attribute lines beside `_variant_set`
  (:2478–2489): `_save_session`, `_save_confirmed`, `_save_painted_preview`.
- `action_save_project` (:7601) — nothing-loaded → one status line, no push
  (Q9); keyword-only `SaveProjectScreen` constructor; the preview lambda
  computes the session lazily; per-open state dropped before the push.
- `check_action` (:8832) — the whole-stack tuple now
  `(LoadDialog, ConfirmQuestionScreen, SaveProjectScreen)`; docstring updated.
- `_plan_project_save` (:11908) — keyword-only `save_as_source` (`_UNSET`
  sentinel), `digests`, `inventory`, `payload_sha256`; target kind by file
  identity (`os.path.samefile`); image description scrubbed via
  `painted_names`; image/MAC/A2L digests read from the session mapping on a
  preparation call; document-digest warning memoised via
  `_DOCUMENT_UNREADABLE_KEY` (S11-11).

Deleted: none. The graph's "`_predict_in_copy` retired" has no code to delete
on this tree (the helper never landed on main; grep finds no `_predict_in_copy`).

### project_gather_service.py

Changed:
- Imports (:71, :76–88): `PurePosixPath` from pathlib; `_match_identical` and
  `_placed_name_candidates` from `..workspace`.
- `plan_project_save` (:1517) — document arm only (ruling Q10 / Q-5 narrowed
  by A11-03). Summary + Data Flow updated; the owner-document-row prediction
  block sits at :1683–:1720.

Deleted: none.

## Graph node → code location

| Graph node | Location |
|---|---|
| `S19TuiApp.__init__` | `app.py:2478` (three `_save_*` attribute lines) |
| `S19TuiApp.action_save_project` | `app.py:7601` |
| `S19TuiApp.check_action` | `app.py:8832` (tuple at :8838) |
| `S19TuiApp._handle_save_dialog` (router) | `app.py:10258` |
| `S19TuiApp._prepare_project_save` | `app.py:10343` |
| `S19TuiApp._save_session_inputs` | `app.py:10678` |
| `S19TuiApp._current_save_session` | `app.py:10759` |
| `S19TuiApp._save_dialog_preview` | `app.py:10765` |
| `S19TuiApp._compose_save_preview` | `app.py:10801` |
| `S19TuiApp._confirm_project_save` | `app.py:10918` |
| `S19TuiApp._commit_project_save` | `app.py:10976` |
| `S19TuiApp._plan_project_save` | `app.py:11908` |
| Module data (constants + dataclasses + `_unreadable_text`) | `app.py:1733–1922` |
| `plan_project_save` (Q10 document arm) | `project_gather_service.py:1517` (arm :1683) |

## Deviations (each with reason)

1. **`c.relative.name` in the Q10 occupants dict.** The graph writes
   `occupants = {c.relative.name: …}` but `InventoryFile.relative` is a `str`
   (no `.name`). Implemented as `PurePosixPath(entry.relative).name` (the
   basename), the only sensible reading. Behaviour matches B11-76.

2. **`_match_identical` imported but called via `_workspace._match_identical`.**
   The graph's imports line says "`_match_identical` joins the `..workspace`
   import" while A11-03 says the call is `workspace._match_identical`. Both are
   honoured: the bare name is imported (per the import line) and the call goes
   through `_workspace` (per A11-03). The bare import is therefore technically
   unused; harmless (no flake8 gate; the module-set census
   `test_tc_b100_59_gather_service_imports_no_change_module` only counts
   `ast.ImportFrom` modules, and the byte-identity census keys on `_hash_file`
   calls, not imports).

3. **S11-11 warning memoisation mechanism.** The graph says the unreadable
   change document logs "one warning per dialog open … memoised on the
   session" without naming a mechanism. `_SaveSession` is frozen and has no
   slot for it, so the memo lives in the session's `digests` mapping (always
   the plain `dict` built by `_save_session_inputs`, never replaced during an
   open) under the sentinel `_DOCUMENT_UNREADABLE_KEY` (`app.py:1765`). The
   prepared call mutates that dict; the positional caller (`digests=None`)
   logs every time as before.

4. **Occupants dict values are not read.** `_match_identical` re-stats and
   re-hashes candidates (S11-09: "regular file, not a reparse point, current
   size"), so the `(entry.size, inventory.root / entry.relative)` values the
   graph's `occupants` literal carries are never consumed — only the dict keys
   (the copied basenames) become the `listing`. Kept verbatim per the graph.

5. **`_refused` neutral `image_step` for a `None` session.** The graph's
   `_refused` fill says `image_step = session.image_step`, but on the direct
   path the name rules (G4–G10) run before the session is computed, so
   `session` can be `None` there. `_refused` falls back to
   `_ProjectImageStep(emit=False)` in that case; only `refusal`/`toast`/`plan`
   are ever read on a refused save, so the fallback is unobservable.

## Open questions

- None blocking. The S11-11 memoisation (deviation 3) is the only place the
  spec left the mechanism open; if the orchestrator prefers a `_SaveSession`
  field for it, the field list in `interfaces-11.md` would need to change.

## Verification performed (no test suite run)

- `python -m py_compile s19_app/tui/app.py s19_app/tui/services/project_gather_service.py`
  → clean.
- `import s19_app.tui.app` and `import s19_app.tui.services.project_gather_service`
  → both import clean (names `_SaveSession` / `_PreparedSave` / `_unreadable_text`
  / `SavePreview` / `ProjectInventory` all present).
- A throwaway smoke script (deleted after use) exercised the Q10 document arm
  (reuse → `keep` at `patches/changes_1.json`; free-name → `new` at
  `patches/changes.json`), `_unreadable_text` output, and the refused
  `_PreparedSave` shape → all passed.
