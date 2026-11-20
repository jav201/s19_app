# Unit FB-B97 — re-pin two key-bar tests to the approved D10-23 (Undo/Redo lit for every document) [deepseek-v4-pro · medium]

Tree: `b103-fix-round` at **`a7961422`** (HEAD check mandatory). Rules: `FB-common.md`. No agent edits `~/.claude/skills`. **Append to `../REPORT.md` after EACH row.**

## Fixed diagnosis (orchestrator, relevo-24; PP-04 of PR #214 run 44679721882 + serial triage + `git bisect`)
- `tests/test_b97_key_bar.py::test_tc_b97_69_dimmed_entries_follow_their_condition` and `::test_tc_b97_72_clicks_run_the_action_and_type_nothing` FAIL on a7961422 and PASS on main 3afebf90 (serial, `-n 0`). `git bisect` (merge-base 3afebf90, 31 commits): first bad commit **f7973d8f** "patch editor: Undo, Redo and per-entry Edit JSON for every document (D10-23, fix round)".
- f7973d8f implements the operator-approved D10-23: **R-TUI-057.8** "The system shall keep Undo, Redo and their keys enabled for every document." Its message says the tests asserting the old A-01 guard were re-pinned; these two key-bar tests were missed (the earlier PR run stopped at ~38 % of the lean lane, before `test_b97_key_bar.py`).
- Failures today:
  - tc_b97_69 (`:796`, asserts at ~:862-868): `out["file_backed"] == (True, True)` gets `(False, False)`: `^z Undo` / `^y Redo` are now lit for a file-backed change-set.
  - tc_b97_72 (`:1242`, the "dimmed ^z" arm at ~:1274-1280, assert ~:1309): it clicks `^z Undo` as a **dimmed** token on the Patch window and expects nothing to happen plus one bell; `^z` is now lit, so the click runs Undo: `('patch', False, 0)` vs `('patch', True, 1)`.
- DF-04: the approved design wins; the tests are re-pinned to the canon rows. The intent of each test stays (TR-01: the old "^z dimmed when file-backed" expectation was superseded by D10-23, so only that expectation changes, never the rest).

## Files you may edit
`tests/test_b97_key_bar.py` only.

## Rows
| row | change | negative control (scratch copy) → RED |
|---|---|---|
| 1 | tc_b97_69: the file-backed arm now expects `^z ^y` **lit**: `assert out["file_backed"] == (False, False), out`. Rewrite the docstring clause "a file-backed change-set → Patch ``^z ^y`` dimmed, lit after a paste-authored one" to say they are lit for a file-backed and for a paste-authored change-set (R-TUI-057.8, D10-23). Keep every other arm and wait unchanged. | In `scratch/nc-1`, restore the old product guard that dimmed Undo/Redo for a file-backed document (read `git show f7973d8f -- s19_app` and revert only the key-bar/`check_action` guard hunk for `^z`/`^y`) → the node RED on the file-backed arm |
| 2 | tc_b97_72: the dimmed-click arm must click a token that is **dimmed** in that state on the Patch window. Find one in the same state (no variant set is loaded in this test; `v Select variant` is dimmed on the Patch window per tc_b97_69's `no_variants` arm — check which bar row paints it with `_token_offset`). Before the click assert the token is dimmed (`dims(app, "<token>") == (True,)`), then keep the oracle: the active screen stays `patch`, the change document is unchanged, exactly one bell. Rename nothing; update the out-dict key from `undo` to a neutral name only if the assert message needs it (keep the test function name). Update the docstring clause about "a click on the dimmed ``^z Undo``" to name the new token and cite R-TUI-057.8 (D10-23) for why `^z` no longer serves. **If no dimmed token exists on the Patch window bar in that state, STOP: write what you checked to REPORT.md and end with `UNIT_DONE FB-B97 STOPPED`.** | In `scratch/nc-2`, make the chosen token's guard return True (lit) → the pre-click dimmed assert RED |

## Nodes you may run (`timeout 300`)
- `-n 0`: the two nodes;
- `-n 4`: `tests/test_b97_key_bar.py` (regression; report any other failure with its id and whether it also fails on main — clone `git clone -q -b main ~/work/zq-fb/fb.bundle ../scratch/main` once to check).
- Never run a `slow` node.
