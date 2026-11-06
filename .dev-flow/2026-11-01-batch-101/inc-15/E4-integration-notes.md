# Inc 15 — E4 integration notes

**Verdict: GREEN for the right reasons.** Every wait D1 … D8 is shown necessary (base form RED at the read it guards under its own hold) and sufficient (fixed form GREEN 3/3 under the same hold). Every product mutant and vacuity control of slice §5 fails the fixed arm at the assertion it targets. The Windows host runs 80 of 80 node runs GREEN, against the 5 of 16 TC-331 failures at the base. 0 files under `s19_app/` changed.

Branch `b101-inc15`. Integrated head `77f4553` = `68452f6` (DeepSeek's E4 edits) + one guard fix. Base `c2cba35`. Model: Opus. Transcripts: `../evidence/inc-15/int-NN.txt`, redacted (`<HOME>`, `<USER>`, `<HOST>`, `<LAN-LAPTOP>`). Each transcript prints the commit under test and `s19_app.__file__`. Index files: `int-index-linux.txt`, `int-index-windows.txt`. Probes: `../evidence/inc-15/probes/`.

## 1. Review of the E4 edits against the records

| Item | Record | Finding |
|---|---|---|
| D1 … D8 placement, predicates, descriptions | table D, slice §2 | Match. Each wait is the statement directly after its trigger. D1, D2 and D5 read `document.source_path`, never the button. D6 waits for `#patch_saveback_row` without `hidden`; D7 and D8 wait for it with `hidden`. D2 has no address check (E3 F8). |
| Bind-step recorder | slice §2, E3 F5 | Matches. The recorder reads `panel._rebind` first, passes `*args, **kwargs` through and appends after the real step returns. `_rebind` has one caller (`flow_screens.py:4392`), so the count is exact. |
| `add_entry` | requirements, TC-051 note | Unchanged, as ruled. |
| Docstrings | slice §5 | Each changed arm cites its R-TST ids. |
| Rule 7 and the guard entry | R-TST-158, E3 F7 | Rule 7 holds the sentence verbatim, with an inline Origin citing Inc 15 and R-TST-158. "Seven rules". `_CONVENTION_RULES` and the parametrize list each gain `R-TST-158`. |
| N1 (`_drive` as the arm's body) | E3 round 2 | Absorbed: `_drive_body` walks into the `async with app.run_test(...)` block. |
| N2 (commit in each header) | E3 round 2 | Done here: the probe header prints the commit. |
| N3 (census script kept) | E3 round 2 | Already done at E3 (`evidence-e3/probes/i15e3-census.py`). |
| **Static guard, R-TST-155** | "8/8 wait sites call `tests.b97_probes.settled`" | **Deviation, fixed.** The guard matched the bare name `settled` only, so a module-local `def settled` passed it. Shown at the 68452f6 form: int-64 GREEN with a local `settled` in the b94 module. |

### The fix (`tests/test_suite_hygiene.py`, commit `77f4553`)

New helper `_settled_bindings(tree)` lists every statement that binds the name `settled`. The test now asserts that each module of the four arms binds it only through `from tests.b97_probes import settled`. Control: the same module-local `settled` turns the fixed guard RED (int-63), while the pre-fix guard passes (int-64). Nothing else changed: the four test functions, the docs and the other guard checks are DeepSeek's text as committed.

Seen, not changed (records are out of this step's edit scope): the D-3 cell of `E1-rulings.md` §4 still says "beside rule 2", while R-TST-158 and the file place the sentence as rule 7 (E3 round 2 also noted this).

## 2. Runs

LAN Linux host: a fresh worktree at `c2cba35` with `git diff c2cba35 77f4553 -- tests docs` applied (patch sha256 `fdde60cc…`). Interpreter `s19ci` (Python 3.11.18, Textual 8.2.8), `NO_COLOR` unset. The probe `i15int_guard.py` blocks the OS clipboard writers in every run. Holds, mutants and guard controls ran in rsync copies of that worktree (no `.git`), never in the worktree itself. A **base-form** copy has `tests/test_tui_patch_editor_v2.py`, `tests/test_tui_flow_execution_b94.py`, `tests/test_suite_hygiene.py` and `docs/engineering-rules.md` restored to `c2cba35`. The worktree was removed afterwards.

| Run | What | Result |
|---|---|---|
| int-01 | the 3 changed files, `-n 6 -m "not serial_timing"` | **129 passed** |
| int-02 | the 3 changed files, `-m serial_timing` | **1 passed**, 129 deselected |
| int-03 … 05 | the 4 nodes, serial, 3 reps (R-TST-157) | **12/12 passed** |
| int-65 | the new guard test + all 7 conventions parameters, `-v` | 8 passed, `[R-TST-158]` included |
| int-66 | R-TST-158 control: rule 7 deleted (copy) | RED: `R-TST-158 sentence missing or edited` |
| int-70 … 89 | **Windows host**, 20 serial runs of the 4 nodes (R-TST-156) | **20/20 runs, 80/80 node runs passed** |

The Windows runs (`s19env`, Python 3.11.15, Textual 8.2.8): cwd is the worktree, and `s19_app.__file__` = `<HOME>\Github\s19_app-b101-inc15\s19_app\__init__.py` in each header (the runner aborts otherwise). Each run gets a fresh `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERPROFILE` and `HOME` under the job's `tmp/i15int-win/int-NN/`. `NO_COLOR` is unset, and the clipboard writers are replaced by a raising guard, which never fired. These 20 runs cover the requested 16 per node (int-70 … 85: 64/64) and R-TST-156's threshold of 20 per node. Base for comparison (E1, same host): TC-331 failed 5 of 16 runs.

### Hold table (`I15_HOLD_S` = 1.5 s; fixed form × 3, base form × 2)

| Wait | Hold | Fixed form | Base form: RED at the guarded read |
|---|---|---|---|
| D1 | `patch_action[*]` | GREEN 3/3 (int-06 … 08) | RED 2/2 (int-09, 10): load step, `a file-backed document … Edit JSON disabled` |
| D2 | `patch_action[parse_paste]` | GREEN 3/3 (int-11 … 13) | RED 2/2 (int-14, 15): paste step, `a subsequent paste … Edit JSON re-enabled` |
| D3 + D4 | `fx_bind` | GREEN 3/3 (int-16 … 18) | RED 2/2 (int-19, 20): D4's read, `assert {} == {0: 'variant_b.hex'}`. D3's no-op read passes vacuously under a hold alone, so its RED is the mutant pair int-44 / 45 below. |
| D5 | `change_file` | GREEN 3/3 (int-21 … 23) | RED 2/2 (int-24, 25): `… load its 0x300 entry, got -0x1` |
| D6 | `patch_action[apply_doc]` | GREEN 3/3 (int-26 … 28) | RED 2/2 (int-29, 30): `AttributeError … 'saved_path'` (no apply has run) |
| D7 | `save_back[decline]` | GREEN 3/3 (int-31 … 33) | RED 2/2 (int-34, 35): `assert outcomes["prompt_hidden_after_decline"] is True` |
| D8 | `save_back[confirm]` | GREEN 3/3 (int-36 … 38) | RED 2/2 (int-39, 40): `assert traversal_path is not None` |

The fx_bind hold sits at the class level of `FlowExecutionPanel.on_button_pressed`, above the instance recorder (E3 F5).

### Product mutants and vacuity controls (copies; slice §5)

| Control | Run | Fixed form | Base form |
|---|---|---|---|
| R-TST-150 (b): both load-path guard writers removed (`app.py:4929`, `:7191`) | int-41 | RED at the load step | — |
| R-TST-151 (b): only `app.py:4929` removed | int-42 | RED at the paste step | — |
| R-TST-153 (b): the bind writes every lane's record | int-43 | RED on lane B, `{0: 'variant_b.hex'} == {}` | — |
| R-TST-152: same-ref early return removed + `fx_bind` hold | int-44 / 45 | RED at the no-op assertion, `rebinding to the same ref wrote a record: {0: 'base.s19'}` | no-op assertion passes (vacuous); RED later at `after_a` |
| R-TST-161 (b): Don't save writes under the name box's text + `save_back[decline]` | int-46 / 47 | RED at `declined_saved_path is None` (an `img-patched.s19` was written) | RED earlier, at `prompt_hidden_after_decline` |
| R-TST-162 (b): reserved-name refusal removed + `save_back[confirm]` (Linux only) | int-48 / 49 | RED at `a Windows reserved device name must be refused` (`CON.s19` written) | RED earlier, at `traversal_path is not None` |

### R-TST-154 behavioural half (R-TST-157's negative control)

`I15_NEVER=<description>` makes that one site's predicate never hold, with a 3 s bound. The wait still goes through the real `settled` → `wait_until` path. Runs int-50 … 57, one site per run, each RED with its own text:

- D1 `did not settle: TC-331: the load of f.json reached the change document`
- D2 `did not settle: TC-331: the parsed paste reached the change document`
- D3 `did not settle: TC-B94-27: the panel handled the Bind to the same ref`
- D4 `did not settle: TC-B94-27: the panel handled the Bind to variant_b.hex`
- D5 `did not settle: AT-030c: the load of dropped.json reached the change document`
- D6 `did not settle: TC-051: the apply showed the save-back prompt`
- D7 `did not settle: TC-051: the decline hid the save-back prompt`
- D8 `did not settle: TC-051: the confirm hid the save-back prompt`

### Static guard negative controls (copies)

| Run | Change | Result |
|---|---|---|
| int-58 | wait D1 removed | RED, names `test_tc331… › _drive` and the trigger `panel.request_action('load_doc')` |
| int-59 | wait D1 moved after its read (R-TST-163/2) | RED, same site named |
| int-60 | D3 description built as an f-string | RED at D3's site |
| int-61 | D5 description text changed | RED at D5's site |
| int-62 | `for _ in range(50): await pilot.pause()` in TC-331 | RED, `has a range-counted pause loop` |
| int-63 | module-local `settled` in the b94 module | RED (integrated guard) |
| int-64 | same, with the pre-integration guard (68452f6 form) | GREEN: the hole the fix closes |

## 3. Case → evidence (for E5)

R-TST-150/1, 151/1, 152/1, 153/1, 159/1, 160/1, 161/1, 162/1: int-03 … 05, int-70 … 89. 150/2: int-06 … 10. 151/2: int-11 … 15. 152/2: int-44 / 45. 153/2: int-16 … 20. 159/2: int-21 … 25. 160/2: int-26 … 30. 161/2: int-31 … 35. 161/3: int-46 / 47. 162/2: int-36 … 40. 162/3: int-48 / 49. 154/1, 155/1, 163/1: int-01, int-65. 154/2: int-50 … 57. 163/2: int-59. 156/1: int-70 … 89. 157/1: int-03 … 05 serial; the parallel half ran on the changed files with `-n 6` (int-01), not the release gate's `-n 8` whole-suite lane, which is E5's. 158/1: int-65, control int-66. Product mutants 150 (b), 151 (b), 153 (b): int-41 … 43.

`trace_check.py --req inc-15/01-requirements.md --base c2cba35 --src s19_app`: 2 US, 14 requirements, **1 gap** (EVID: no `04-validation.md`, owed by E5). The E1/E3 TEST gaps of R-TST-154, 155, 158 and 163 are closed.

## 4. Not run

The whole-suite release gate (`-n 8` + serial lane, E5). `tests/test_id_registry.py` was not re-measured: no test file was added. No run imported `s19_app` on Windows other than the 4 Windows-only nodes.
