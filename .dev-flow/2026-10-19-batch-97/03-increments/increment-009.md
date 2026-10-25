# Increment 009 — R-TUI-013 · `The Load project dialog loads the picked project (CW-U-1)`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-009.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `009` (out-of-band, added by the operator 2026-10-23, executed before Inc-7) |
| Lane (if the batch forked) | `none — one lane` |
| Requirement(s) | `HLR-151 / LLR-151.1` (refine batch-01 `R-TUI-013`, `Partial` in its trace) · ledger `LED-2026-10-19-batch-97.42` (new) |
| Acceptance | `tests/test_b97_load_project_dialog.py::test_load_project_button_loads_the_picked_project` |
| Agent | orchestrator (main session); review by `code-reviewer` (spawned sub-agent) |
| Date | `2026-10-23` |
| Design refs | `.dev-flow/design/AUDIT-codewire-ui-2026-10-23.md` CW-U-1 |

---

## 1 · What changed
- `LoadProjectScreen` (`s19_app/tui/screens.py`) now dismisses with `self.projects[index]`, the ListView index into the list it was built from. Before, it dismissed with `label.text if hasattr(label, "text") else str(label)`. Textual 8.2.8 `Label` has no `.text`, so every pick reached `_handle_load_project` as `"Label()"` and no project ever loaded through the dialog (key `p` or the Workspace "Load project" button).
- Not changed, by decision: `enter` on the list. In Textual 8.2.8 a click on a ListItem also posts `ListView.Selected` (`_list_view.py:388-392`), so a `Selected` handler would load a project on one click. A first version had that handler; it was removed after code-reviewer F2 so this increment changes no interaction. Routed to the Load+projects prototype round.
- Operator authorisation: "try it in this batch and test it; if it has problems move it to the integrity batch; in the integrity batch delegate more detailed tests of the change" (2026-10-23).

## 2 · Files modified
| **SOURCE files** | **`1` / 4** — `s19_app/tui/screens.py` |
|---|---|

- Source (1): `s19_app/tui/screens.py`.
- Tests (new): `tests/test_b97_load_project_dialog.py`.
- Records: `01-requirements-ledger.md` (LED-…97.42), `.dev-flow/BACKLOG-CODE.md` (CW-U-1 status, sibling defects), this packet, `evidence/inc-9/`.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | source | HLR-151, LLR-151.1 | `LoadProjectScreen` Load handler: the name comes from `self.projects` by the ListView index (CW-U-1); close-time table (2026-10-25), the packet listed its files as bullets only |
| `tests/test_b97_load_project_dialog.py` | test | HLR-151, LLR-151.1 | NEW `test_load_project_button_loads_the_picked_project`; close-time table (2026-10-25) |

## 3 · How to test
- `pytest tests/test_b97_load_project_dialog.py` — creates `proj_a` and `proj_b` in a temp work area, opens the dialog, highlights `proj_b` (not the first entry, since `patches` and `proj_a` sort before it), clicks Load, and checks `app.current_project == "proj_b"` and that the dialog closed.
- Manual: save two projects, press `p`, move to the second one, press Load: the status says `Loaded project '<name>' -> …`.

## 4 · Test results
- **RED on HEAD `354857c`** (`evidence/inc-9/red.txt`): 1 failed — `got None (status: 'Ready.')`. A probe on the same tree showed the handler received `['Label()']`.
- **GREEN gate** (`evidence/inc-9/green.txt`, every test file that names `LoadProjectScreen` / `load_project` / `_handle_load_project`, plus `test_tui_theme.py`, on screens.py `6345198c…`): **3 failed, 594 passed** (0:49:57). The 3 failures are baseline nodes (`comm` against `baseline-pytest-51ee191.txt`: no new failure). Full suite not re-run for a one-file dialog fix; Inc-7's full suite covers it.
- **Mutants** (`evidence/inc-9/mutations.txt`): 2 of 2 killed — M1 always the first entry, M3 the old `str(Label)`.

### Evidence files

| Evidence | File | SHA-256 |
|---|---|---|
| RED (1 failed, HEAD screens.py) | `.dev-flow/2026-10-19-batch-97/evidence/inc-9/red.txt` | `fb3289e5ef7f4a58403549001c7f7be35eeeee35f1324078d9e225c24dffc4f6` |
| Mutants (2/2 killed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-9/mutations.txt` | `e159a0f5baa6995ce5d9c2ed9531469574915cd5bf525c7ccf2cf44f6b9003eb` |
| Mutant script | `.dev-flow/2026-10-19-batch-97/evidence/inc-9/mutate.py` | `c6b1014fbe8dc29f09b0d6b7165f3a1028cc2fe71158c256e3195a34a347549f` |
| GREEN gate (594 passed / 3 baseline failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-9/green.txt` | `6cddb37c10e983a8194832c5dbcef1af477d0d4fc42d0d963e0a87f0f31e484c` |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — OK to advance · CW-U-1 fixed by index into self.projects (list built in the same order); the test picks proj_b, so neither a first-entry fallback nor "Label()" can pass; F2 (click-to-load via `Selected`) resolved by removing the enter handler; F1 sibling (`_load_from_item`) routed to the backlog; F3 green.txt summary line added |

## 5 · Risks
- The fix covers the dialog only. Loading a project still has the defects in `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (PH-1..PH-5): now that the dialog works, they are reachable through it. They belong to the Load+projects batch.
- `_load_from_item` (Workarea Files list) has the same `str(Label)` pattern (code-reviewer F1, code-read). It is masked by CW-U-3 (the list is always empty).

## 6 · Pending items / spec deviations
- Integrity batch: deeper tests of this change, delegated (operator instruction).
- Load+projects batch: `enter`/click semantics on the list; `patches` listed as a project; the `_load_from_item` sibling.

## 7 · Suggested next task
Inc-7 (snapshot harness race, regen, sweep, the Inc-8 leftovers).

## Increment gate checklist

| # | Check | Level | State | Where |
|---|---|---|---|---|
| 1 | Requirement traced | all | ✓ | R-TUI-013, LED-…97.42 |
| 2 | RED before GREEN, executed | all | ✓ | §4 |
| 3 | Mutation evidence | `full` | ✓ | §4, 2/2 killed |
| 4 | Max 4 source files | all | ✓ | §2 |
| 5 | `code-reviewer` passed | `core` · `full` | ✓ | §4b |
| 6 | Independent review names somebody | all | ✓ | §4b |
