# Inc 15 — validation (E5)

**Verdict: PASS-WITH-NOTES.** Both Windows-only failures are test defects, not product defects: each arm reads app state after one `pilot.pause()` (a one-pause read), and on the Windows host that pause can return before the press is handled. The fix is tests-only — nine waits (D1 … D9) go through the shared `tests.b97_probes.settled` helper instead of a single pause, a static guard pins each site's description, predicate, position and shared-wait binding, and the handled-press rule joins the test conventions as rule 7 (R-TST-158). Every wait is shown necessary (base form RED at the read it guards, under its own hold) and sufficient (fixed form GREEN under the same hold). **0 files under `s19_app/` change.** The open notes are records-only: the release gate's whole-suite parallel lane is owed at merge time, and the D-6 census row is backlog. Branch `b101-inc15` at `972ba5b` (the E5 re-audit records RA-1/RA-2 applied over the `5edcb3f` tests) plus the uncommitted E5 records and this file.

## Runs

Platform: the LAN Linux host for every hold, mutant, guard control and lane run; the Windows host for the serial node runs, each with a fresh isolated app-state folder. Evidence: `../evidence/inc-15/` (indexes `int-index-linux.txt`, `int-index-windows.txt`, `e5c-index-linux.txt`, `e5c-index-windows.txt`).

| Run | Platform | Result | Evidence |
|---|---|---|---|
| E4 integration, the 3 changed test files `-n 6 -m "not serial_timing"` | LAN Linux | **129 passed** | `../evidence/inc-15/int-01.txt` |
| E4 integration, the 3 changed test files `-m serial_timing` | LAN Linux | **1 passed**, 129 deselected | `../evidence/inc-15/int-02.txt` |
| E4 integration, the 4 nodes serial ×3 (R-TST-157/1) | LAN Linux | **12/12 node runs passed** | `../evidence/inc-15/int-03.txt` … `int-05.txt` |
| E4 integration, the static guard + the 7 conventions parameters | LAN Linux | **8 passed** (`[R-TST-158]` included) | `../evidence/inc-15/int-65.txt` |
| E4 integration, R-TST-158 control (rule 7 deleted) | LAN Linux | **RED** `R-TST-158 sentence missing or edited` | `../evidence/inc-15/int-66.txt` |
| E4 integration, 20 serial runs of the 4 nodes (R-TST-156) | Windows | **20/20 runs, 80/80 node runs passed** | `../evidence/inc-15/int-70.txt` … `int-89.txt` |
| E5 corrective, the 3 changed test files `-n 8 -m "not serial_timing"` (R-TST-157/2, C-8) | LAN Linux | **129 passed** | `../evidence/inc-15/e5c-01.txt` |
| E5 corrective, the 3 changed test files `-m serial_timing` | LAN Linux | **1 passed**, 129 deselected | `../evidence/inc-15/e5c-02.txt` |
| E5 corrective, the 4 nodes serial ×3 (R-TST-157/1) | LAN Linux | **12/12 node runs passed** | `../evidence/inc-15/e5c-03.txt` … `e5c-05.txt` |
| E5 corrective, the static guard + the 7 conventions parameters | LAN Linux | **8 passed** | `../evidence/inc-15/e5c-06.txt` |
| E5 corrective, 20 serial runs of TC-B94-27 (the arm C-10 changed) | Windows | **20/20 passed** | `../evidence/inc-15/e5c-31.txt` … `e5c-50.txt` |

Every final transcript prints the commit under test (`77f4553` for `int-NN`, `5edcb3f` for `e5c-NN`) and `s19_app.__file__` in the worktree; the Windows runners abort otherwise. The Windows runs point `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERPROFILE` and `HOME` at a fresh scratch folder per run, keep `NO_COLOR` unset, and replace the OS clipboard writers with a raising guard that never fired.

## Hold / control table (each wait: base form RED under its hold, fixed form GREEN)

`I15_HOLD_S` = 1.5 s. Fixed form ×3, base form ×2 per wait; all on the LAN Linux host.

| Wait | Hold | Fixed form | Base form (RED at the guarded read) |
|---|---|---|---|
| D1 | `patch_action[*]` | GREEN 3/3 (int-06 … 08) | RED 2/2 (int-09, 10): load step, `a file-backed document … Edit JSON disabled` |
| D2 | `patch_action[parse_paste]` | GREEN 3/3 (int-11 … 13) | RED 2/2 (int-14, 15): paste step, `a subsequent paste … Edit JSON re-enabled` |
| D3 + D4 | `fx_bind` | GREEN 3/3 (int-16 … 18) | RED 2/2 (int-19, 20): D4's read, `assert {} == {0: 'variant_b.hex'}`; D3's no-op RED is the mutant pair int-44/45 |
| D5 | `change_file` | GREEN 3/3 (int-21 … 23) | RED 2/2 (int-24, 25): `… load its 0x300 entry, got -0x1` |
| D6 | `patch_action[apply_doc]` | GREEN 3/3 (int-26 … 28) | RED 2/2 (int-29, 30): `AttributeError … 'saved_path'` |
| D7 | `save_back[decline]` | GREEN 3/3 (int-31 … 33) | RED 2/2 (int-34, 35): `prompt_hidden_after_decline` |
| D8 | `save_back[confirm]` | GREEN 3/3 (int-36 … 38) | RED 2/2 (int-39, 40): `traversal_path is not None` |
| D9 | `fx_import` | GREEN 3/3 (e5c-07 … 09) | RED 2/2 (e5c-10, 11): `KeyError: 'base_2'` (the arm at `5054743`, one pause) |

Product mutants and vacuity controls (copies of the tree): R-TST-150 (b) RED at the load step (int-41); 151 (b) RED at the paste step (int-42); 153 (b) RED on lane B (int-43, e5c-15); 152 (same-ref early return removed + `fx_bind`) RED at the no-op assertion, base form vacuous then RED at `after_a` (int-44/45, e5c-16); 161 (b) RED at `declined_saved_path is None` (int-46/47); 162 (b, Linux only) RED at `a Windows reserved device name must be refused` (int-48/49). R-TST-154 behavioural half (R-TST-157's negative control): one never-settling site per run, each RED with its own `did not settle: <description>` — int-50 … 57 (D1 … D8) and e5c-17 … 19 (D9, D3, D4 on the changed arm).

## Guard controls (static check `test_r_tst_154_155_inc15_arms_wait_through_settled`)

| Change | Result | Evidence |
|---|---|---|
| D1 removed · D1 moved after its read (R-TST-163/2) · D3 description as f-string · D5 description text changed · `range` pause loop · module-local `settled` | each **RED** | int-58 … 63 |
| pre-integration guard on the module-local `settled` (the hole `77f4553` closes) | GREEN | int-64 |
| D6 predicate → `lambda: True` · D7 polls D6's sign (C-2) · `_wait_for` in TC-B94-27 (C-7) · `_confirm_with` renamed, 0 skipped (C-9) · D9 removed (C-10) | each **RED** | e5c-20 … 24 |
| pre-corrective guard (`5054743`) on the C-2 (a) and C-7 edits (the holes `5edcb3f` closes) | GREEN | e5c-25, 26 |

## Reviews

- **E3 design:** `architect` round 1 **FAIL** (1 HIGH F1, 2 MAJOR F2/F3, 7 MINOR F4 … F10) → round 2 **PASS-WITH-NOTES** (F1–F3 closed as ruled; notes N1–N3 folded into E4) — `E3-architect.md`, `E3-rulings.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES**, 0 HIGH/MAJOR, 1 MINOR (F1 design-gap, the predicate pin) + 4 NIT (F2–F5), all folded by the corrective pass. The reviewer carried the security lens — **no separate security-reviewer ran, because the increment changes no product code**; the lens checked evidence redaction (0 hits), Windows isolation and tmp-only writes — `E5-code-review.md`.
- **Coverage audit:** first audit over the 26 E1/E3 cases: 23 hold as `full`/`covered`/`verified`, 2 `partial` (153/1, 155/1), 1 `not_run` (157/1) — **3 of 26 = 11.5 % departures** from a plain mark update. Rulings C-1 … C-10 → corrective pass → **re-audit**: 28 cases over 15 requirements, 14 robustness / 14 normal, 28 `full`, 27 `covered` + 1 `partial` (R-TST-157/2), 28 `verified`, 0 `failed`, 0 `not_run` — `E5-coverage-audit.md` (incl. its Re-audit), `E5-rulings.md`, `E5-corrective-notes.md`.

## Windows result

Base `c2cba35`: TC-331 failed **5 of 16** serial Windows runs (the reported `NoMatches '#patch_editor_panel'` ×4 and one paste assertion). After the fix: the four nodes pass **20/20 per node** — 80/80 node runs at `77f4553` (int-70 … 89), and TC-B94-27 alone 20/20 at `5edcb3f` (e5c-31 … 50). R-TST-156's threshold (20 per node) is met.

## Owed

- **Merge-time full suite.** R-TST-157/2's Coverage is `partial` until the batch merge verification runs the release gate's whole-suite parallel lane (`pytest -n 8 -m "not serial_timing"`) plus the serial lane; the runs here used the lane's flags over the 3 changed files only. The merge record cites that run and flips the case to `covered`.
- **The D-6 backlog census row.** The suite-wide census of one-pause reads (146 sites in 28 test files, plus 88 direct reads after the self-pausing `pilot.press`/`pilot.click`, plus `while` loops whose body calls `pilot.pause()`, and the retirement of the module-local `_settled` onto `tests.b97_probes.settled`) stays a backlog row; no ratchet guard.

## Trace

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base c2cba35 --src s19_app` at close: `trace_check: 2 US, 15 active requirements (0 withdrawn), 0 gap(s)` (no EVID "not committed" gaps — every evidence path this record cites is committed; the files this close creates, `04-validation.md` and `increment-015.md`, are uncommitted and are not cited as evidence).
