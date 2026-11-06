# Inc 15 — E1 rulings: cause, scope and decisions

Base `c2cba35`. Records: `01-requirements.md` (9 rows at E1, R-TST-150 … R-TST-158; 14 rows after the E3 round-1 corrections, R-TST-150 … R-TST-163), `E1-slice.md`, `02-test-cases.md`. Transcripts: `evidence-e1/` (redacted: `<HOME>`, `<USER>`, `<HOST>`, `<LAN-LAPTOP>`) and `evidence-e3/` (E3 correction). Model: Opus. 0 files under `s19_app/`. E3 round-1 changes to this record are tagged with their finding id (`E3-rulings.md`).

## 1. Verdict

Both failures are **test defects**, not product defects and not a Windows-specific product path. Each arm reads app state after one `pilot.pause()` that follows a press (a one-pause read, `01-requirements.md` Definitions). On Windows that pause can return before the app has handled the press, so the arm reads the state from before the handler ran.

| Node | Reported (`e279c8b`, Windows) | Reproduced at `c2cba35` | Cause |
|---|---|---|---|
| `test_tc331_disable_guard_predicate_tracks_source_path` | `NoMatches: No nodes match '#patch_editor_panel' on Screen(id='_default')` (chunk-10 and serial re-run, 2/2) | **Yes, Windows host, 5 of 16 runs** (4 × the reported `NoMatches`, 1 × `a subsequent paste … re-enabled`); Linux 0 of 10 | The arm presses Parse pasted, pauses once and returns. The paste action reaches the app after the test body ends, while `App._shutdown` removes the screen, and the app's action handler then fails to find the panel (trace below). When the action is dropped instead, the paste assertion fails. |
| `test_tc_b94_27_lane_binding_isolation_and_noop` | `assert {} == {0: 'variant_b.hex'}` (chunk-10 and serial re-run, 2/2) | **Not reproduced natively**: 0 of 16 Windows runs (unloaded, traced, and pinned to one CPU with 2 and 6 competing processes), 0 of 10 Linux runs. **Symptom reproduced exactly** with the held-handler probe: 2/2 on Linux | Same form: the arm presses Bind, pauses once, reads lane A's bindings. With the press handled 1.5 s late (product logic unchanged) the read gives `{}`, the reported failure. The no-op arm before it passes in that state although its handler never ran (vacuous, US-TST-16). |

A result counts only for its commit and platform: the two `e279c8b` failures are the requirements session's; every run below is at `c2cba35` (`s19_app.__file__` printed at the top of each transcript: `<HOME>\Github\s19_app-b101-inc15\s19_app\__init__.py` on Windows, `/tmp/i15/wt/s19_app/__init__.py` on Linux).

## 2. Mechanism and evidence

**The pause on Windows.** `Pilot.pause()` with no delay runs `_wait_for_screen()` and then `textual._wait.wait_for_idle(0)`, which sleeps 20 ms at a time and stops at the first window where `time.process_time()` advanced by less than 1 ms (Textual 8.2.8, `SLEEP_IDLE = 1/1000`). On the Windows host that clock moves in 15.625 ms steps: 5 ms of busy work reads 0.0 ms in 14 of 20 samples, and `asyncio.sleep(0.02)` takes 24–32 ms (`evidence-e1/win/clock-probe.txt`). A window in which the app works for less than a tick usually reads as idle, so the pause can end while the press is still travelling. On Linux the clock is fine-grained and the pause keeps waiting while the app works.

**Traces** (`I15_TRACE_FILE`, seconds from session start; `evidence-e1/win/run-04-trace.txt`, `evidence-e1/lin/lin-trace-1-trace.txt`):

| Host | Press | Handler runs | Pause ends | Outcome |
|---|---|---|---|---|
| Windows, TC-331 paste | 1.6219 | 1.7024 (+80.5 ms), **after** `_shutdown` 1.6605–1.7023, no screen on the stack | 1.6603 (+38.4 ms) | `NoMatches '#patch_editor_panel'` |
| Linux, TC-331 paste | 2.4452 | 2.5062 (+61.0 ms) | 2.5846 (+139.4 ms) | pass |
| Windows, TC-B94-27 Bind to `variant_b.hex` | 4.5121 | 4.5463 (+34.2 ms), bindings `{0: 'variant_b.hex'}` | 4.6123 (+100.2 ms) | pass |
| Linux, TC-B94-27 Bind to `variant_b.hex` | 6.0856 | 6.1447 (+59.1 ms) | 6.2063 (+120.7 ms) | pass |
| Windows, 6 competing processes, TC-B94-27 Bind (`run-07-2-trace.txt`) | 23.7164 | +1002.1 ms | +1002.3 ms (the pause's 1 s cap) | pass by 0.2 ms |

The press reaches its handler asynchronously (31–1004 ms on Windows, 58–61 ms on Linux), and nothing ties the end of the pause to that handler. TC-331's chain is longer (button → panel → posted action → app) than TC-B94-27's (button → panel), which fits TC-331 failing on this host today and TC-B94-27 only on the `e279c8b` runs. Under heavy load a second limit appears on any host: the pause stops at its 1 s cap (`run-07-2`, 0.2 ms margin).

**The product does the right thing once the handler runs.** The Windows trace shows the bind writing exactly lane A's record; TC-331 passes 11 of 16 Windows runs; the held-handler probe reproduces both reported symptoms on Linux with the product logic unchanged (`evidence-e1/lin/lin-hold-fxbind-*.txt`: `assert {} == {0: 'variant_b.hex'}`; `lin-hold-patch-*.txt`: the load-step assertion).

**Windows product paths ruled out.** (a) The recent-sources store under `%LOCALAPPDATA%` (active only where `LOCALAPPDATA` is set): `tests/conftest.py` gives every test its own `LOCALAPPDATA` since `f1b8960`, an ancestor of `e279c8b`, and neither arm loads an S19/HEX/MAC/A2L source. (b) The OS clipboard: neither arm calls a copy, cut or paste action; the only writers are `action_copy`/`action_cut` of `OsClipboardInput` and `CappedTextArea` (ctrl+c / ctrl+x); every run also replaced the writers with a raising guard, which never fired. (c) Path or line-ending handling: the failing reads are of in-memory state (`lane.bindings`, a button's `disabled`), not of files.

**Probes that did not reproduce, kept for the record.** `I15_PAUSE=zero` (the pause yields once): TC-331 fails with the paste assertion, TC-B94-27 passes (`win/run-03.txt`). `I15_PAUSE=quantized` on Linux (the process clock floored to 15.625 ms steps): 0 of 6 failures (`lin/lin-quantized-*.txt`); flooring does not imitate Windows' tick sampling, so this probe is not evidence either way.

## 3. Scope list

| Item | Source | In / out | Rows |
|---|---|---|---|
| TC-331: wait for the load and for the paste before reading Edit JSON | PLAN Inc 15; this diagnosis | in | R-TST-150, 151, 154, 155 |
| TC-B94-27: wait until the panel handled each Bind; make the no-op arm non-vacuous | PLAN Inc 15; this diagnosis | in | R-TST-152, 153, 154, 155 |
| Windows and Linux runs of the four nodes (two at E1, plus the D-1 arms) | US-TST-15 | in | R-TST-156, 157 |
| The handled-press rule in the test conventions | this diagnosis (vacuous no-op arm) | in (D-3 = yes) | R-TST-158 |
| AT-030c, `test_save_back_prompt` (same file, same form, failed in the Windows chunk-10 run at `e279c8b`) | `run-e279c8b-win-chunk-10.log` | **in (D-1 = yes; rows at E3 round 1, F1)** | R-TST-159 … 162, 154, 155, 163 |
| Static position check of the eight wait sites | E3 F4 | in | R-TST-163 |
| A harness-level fix of Textual's idle clock on Windows | — | out (D-2) | — |
| A census or guard of one-pause reads across the suite | E3 F3 census | out, backlog (D-6): 146 sites in 28 test files, plus 88 direct reads after the self-pausing `pilot.press` / `pilot.click` | — |
| Any change under `s19_app/` | — | out: no product defect | — |

## 4. Decisions

| Id | Decision | Reason | Recommendation |
|---|---|---|---|
| D-1 | Add the two sibling arms that failed on the Windows chunk-10 run at `e279c8b` (`test_at030c_directly_dropped_file_is_listed_and_loadable`: 1 wait after `select.value = …`; `test_save_back_prompt`: about 9 waits after `add_entry`, 4 × `apply_doc`, Decline, 3 × Confirm) to Inc 15 as R-TST-160 … | Same file as TC-331, same one-pause form, real Windows failures (`AssertionError: … got -0x1`, `prompt_hidden_after_decline False`); they passed 1/1 here (`win/run-02.txt`), so their next Windows run can fail again | **Yes, both.** Tests are not capped; the signals are the change document (load) and `last_summary` / the save-back row (apply, decline, confirm). The orchestrator's yes reopens E1 for these rows only. **Folded at E3 round 1 (F1):** rows R-TST-159 … R-TST-162, waits D5 … D8 at 4 static sites (13 waits at run time with D1 … D4). The signals are the change document's source path (pick) and the save-back row's `hidden` class (apply, decline, confirm; the decision handler hides the row first, `app.py:5002`); `last_summary` is not used as a sign, because a declined or refused answer leaves `saved_path` `None`, the value the apply before it already left. `add_entry` gets no wait of its own, because nothing is read before the first apply and D6 needs an applied entry. Base RED of each new wait under its own hold: `evidence-e3/lin/` (2/2 each) |
| D-2 | Fix the whole class on Windows in `tests/conftest.py` by giving `textual._wait` a precise process clock (`QueryProcessCycleTime`) | One change would cover every one-pause read on Windows | **No.** It patches a private Textual module, it hides the defect the conventions already forbid instead of removing it, and it does not cover the 1 s cap under load. Backlog note only |
| D-3 | State the handled-press rule in `docs/engineering-rules.md` (R-TST-158) | Rule 2 (Post-press) covers a press "while a real worker runs"; these arms have no worker, and the vacuous no-op arm is a real finding (a rule grows only from a real defect) | **Yes**, one sentence beside rule 2, held by the existing parametrized conventions guard |
| D-4 | Reproduce TC-B94-27 at `e279c8b` on Windows | Native reproduction at `c2cba35` failed 16 times | **No.** It needs a second worktree, and the run rules pin the Windows runs to this worktree. The held-handler probe gives a deterministic RED on base for the same symptom, which E4 owes anyway |
| D-5 | Make the app's patch-editor action handler tolerate an action that lands during shutdown | It raised `NoMatches` in the TC-331 failure | **No product change, no backlog row.** It is reachable only with an action in flight while the app is torn down; the waits remove that from the test |
| D-6 | Census and guard of one-pause reads in the suite (374 `.press()` calls in 73 test files, plus `request_action` and `select.value` triggers) | The defect class is wide | **Backlog row, no guard now.** A static check cannot tell which read depends on the press (Inc 2 ruled the same for SR12b-7b, its D-4). **Backlog row content (E3 F3):** the E3 AST census of `tests/` at this tree (trigger `.press()` / `value =` / `request_action` / `post_message`, then exactly one `await pilot.pause()`, then an assign, return or assert) finds 146 sites in 28 files (55 in `tests/test_tui_patch_editor_v2.py`), plus 88 direct reads after the self-pausing `pilot.press` / `pilot.click`; in a 10-site sample every site was a real read of press-dependent state. Blind spot: a trigger wrapped in a helper (`_seed_via_paste`, `_bind`, `_apply`, `_confirm_with`) escapes the pattern, which matches only 3 of the 13 Inc 15 waits. A suite-wide ratchet is out of this increment (E3 rulings, F3) |

## 5. Overlap with other increments

0 files under `s19_app/`: no overlap with `s19_app/tui/app.py` or `screens_directionb.py`, which the serial Inc 5 → 6 → 9 → 10 → 12 chain owns. Test-file overlap is possible: Inc 6 (Patch Editor document lifecycle) may edit `tests/test_tui_patch_editor_v2.py` and may change the load and paste path that waits D1 and D2 read (`document.source_path`); Inc 9 (`flow_screens.py`) may change the bind step that TC-B94-27's recorder wraps (`FlowExecutionPanel._rebind`; a rename fails the arm loudly with `AttributeError`). Recommendation: merge Inc 15 before Inc 6 reaches E4, and give Inc 6 and Inc 9 E1 these two read points. The D-1 arms add two Inc 6 read points (E3 F1): the dropdown load path (`on_patch_editor_panel_change_file_selected` → `_patch_editor_load`, wait D5) and the save-back prompt row `#patch_saveback_row` with its `hidden` class and the decision handler's hide-first order (waits D6 … D8).

## 6. Isolation of the Windows runs (operator rules)

1. Every Windows run had `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERPROFILE` and `HOME` pointed at a fresh scratch folder per run, `--basetemp` in that folder and `-p no:cacheprovider` (`probes/i15-run.sh`; each transcript's header prints the values).
2. Clipboard: both arms and what they call were checked first (§2 (b)); the writers were also replaced by a raising guard (`probes/i15_guard.py`); it never fired.
3. Serial runs of the two named nodes only, plus 3 neighbours once (`run-02`: the commandbar AT before them in the serial re-run, AT-030c, `test_save_back_prompt`); interpreter `s19env`; cwd the worktree; `s19_app.__file__` and `NO_COLOR set = False` in every header.
4. The load processes of `run-06`/`run-07` (`probes/i15_burn.py`) were pinned to CPU 0 with the test process, stopped themselves at 110–120 s, and were confirmed gone; the Linux worktree `/tmp/i15/wt` and the helper folder `/tmp/i15` were removed after copying the transcripts.

## 7. Not run at E1

TC-B94-27 natively failing at `c2cba35` (16 attempts, D-4); either node at `e279c8b` on Windows (D-4); the Linux parallel lane (R-TST-157 is owed at E5); AT-030c and `test_save_back_prompt` beyond one run (D-1).

## 8. Evidence index (`evidence-e1/`)

| File | Shows |
|---|---|
| `win/clock-probe.txt` | Windows process clock in 15.625 ms steps; sleep length |
| `win/run-01.txt`, `run-02.txt` | both nodes pass, unloaded; run-02 with the 3 neighbours (the commandbar AT fails: a known failure) |
| `win/run-03.txt` | `I15_PAUSE=zero` probe |
| `win/run-04.txt`, `run-04-trace.txt` | TC-331 `NoMatches` with the trace placing the paste handler after `_shutdown` |
| `win/run-05-1.txt` … `run-05-6.txt` | 6 unloaded runs: TC-331 fails 2 (`NoMatches`, paste assertion) |
| `win/run-06-1.txt` … `run-06-4.txt` | pinned to CPU 0 with 2 load processes: TC-331 fails 2 (`NoMatches`) |
| `win/run-07-1.txt` … `run-07-3.txt` and traces | pinned with 6 load processes: all pass; `run-07-2` shows the 1 s cap 0.2 ms after the handler |
| `lin/lin-native-1.txt` … `-3.txt`, `lin-quantized-1.txt` … `-6.txt`, `lin-trace-1.txt` (+ `-trace.txt`) | Linux, 0 of 10 failures |
| `lin/lin-hold-fxbind-1.txt`, `-2.txt` | held Bind: `assert {} == {0: 'variant_b.hex'}` 2/2, the no-op arm passing first |
| `lin/lin-hold-patch-1.txt`, `-2.txt` | held patch action: the load-step assertion 2/2 |
| `probes/` | the run guard, runners, load process and clock probe used above |
| `../evidence-e3/lin/i15c-hold-{paste,select,apply,decline,confirm}-{1,2}.txt` | E3 correction, LAN Linux host at `c2cba35` (`s19_app.__file__` in each header): each base form under its own hold, RED 2/2 each: paste-only → the paste-step assertion; `change_file` → AT-030c `got -0x1`; `apply_doc` → `AttributeError … 'saved_path'`; `decline` → `prompt_hidden_after_decline`; `confirm` → `traversal_path is not None` |
| `../evidence-e3/probes/` | `i15c_guard.py` (hold modes `patch_action` with the `I15_HOLD_ACTION` filter, `change_file`, `save_back` with `decline` / `confirm`), `i15c-run.sh`, `i15c-holds.sh`; the LAN worktree was removed after the run |

## Orchestrator rulings on E1 decisions (2026-11-06)

Taken under the operator's standing commission (decide with a recorded reason).

- **D-1 → yes.** AT-030c and `test_save_back_prompt` get the same wait fix. Why: they failed the same way on Windows at e279c8b; same cause, same files, no extra source file.
- **D-2 → no** suite-wide clock patch in conftest. Why: it would change the timing of every test to fix four; explicit waits on the product's own observable state are the suite's convention (R-TST-020 shared wait).
- **D-3 → yes**, add the conventions sentence. Why: the pattern (one `pilot.pause()` after a press, then a state read) is easy to repeat; the sentence binds new and changed arms, and the static guard pins the named arms of this increment only (wording corrected at E3, F3: the guard reads only the four named functions and stops no new instance elsewhere).
- **D-4 → no** second Windows reproduction at e279c8b. Why: the held-handler run gives a deterministic RED on base on the LAN host, which is the stronger evidence; a second Windows worktree costs time for a flaky signal.
- **D-5 → no** product change to make the action handler tolerate shutdown. Why: the failure is the test reading state before the press is handled; a product guard would hide the test defect and change behaviour outside the scope.
- **D-6 → backlog row** for a suite-wide census of the same pattern. Why: the static guard in this increment covers the named functions of this increment only; the existing one-pause reads (146 sites in 28 files, plus 88 direct reads after `pilot.press` / `pilot.click`, D-6 row of §4) are routed with their own evidence (wording corrected at E3, F3; no ratchet).
- **Merge order:** Inc 15 merges before Inc 6 (Inc 6 may move `document.source_path` and the load/paste path the new waits read).
