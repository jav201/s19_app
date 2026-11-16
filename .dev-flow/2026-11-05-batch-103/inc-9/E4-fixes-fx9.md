# Inc 9 product fixes F-MW9-1 and F-MW9-2 (FX9, relevo-13)

Model claude-opus-5-5 (software-dev). Tree `b103-inc9`, start tip `a8c936ee`. Rulings applied: F-MW9-1 and F-MW9-2 are
DF-04 (a) defects, F-MW9-3 confirmed (no test change), F-MW9-4 left to the batch close (unchanged).
Runner scratch `~/work/zq-fx9/` (HT-02 env, HOME basename `<runner-home>` read from `RUNNER_HOME_NAME`, `s19_app.__file__`
printed atop every transcript, timing nodes alone at `-n 0` once the 1-min load is < 2). Probes, scripts, the control mutant
and transcripts: `evidence-e4/fixes-fx9/` (redacted: `~`, `<user>`, `<runner-home>`).

## State / next step
- F-MW9-1: fixed in the product; 26_2 RED on `a8c936ee` -> GREEN (results below).
- F-MW9-2: **measured cause = the instrument, not the product.** The key is handled in 0.03-0.16 s while the encode runs;
  `pilot.press` itself takes 2.2 s because Textual's test driver waits for the whole process to go idle. Fixed on the test
  side (in Inc 9's slice), threshold unchanged, with a UI-thread-stall control mutant that the repaired nodes catch.
  **The ruling's premise ("keys take 2.1-3.0 s") is falsified; the orchestrator should confirm the test-side fix (or send
  the instrument to an independent tester).**
- Next (orchestrator): confirm F-FX9-1 below, then E5.

## F-MW9-1 - LARGE's derived values kept after the deselect (R-PE-BENCH.26/2)
**Cause** (MW9's probe, `evidence-e4/mutants-w/`): `ArrayBenchSheet.on_staging_sheet_selection_changed` cleared `values`,
`staged` and `axes` of a deselected LARGE row, but kept `labels` (65,576 axis-label strings, 4.07 MiB for LARGE) and `strip`.

**Fix** (`s19_app/tui/screens_directionb/patch_editor/bench_sheet.py`, the deselect branch): also reset `labels`, `strip`
and `lo` / `hi` (everything `_derive` builds from the decoded row). The row's next selection decodes again (`job="decode"`
and `_enqueue("decode")` are unchanged), so nothing reads the dropped fields before they are rebuilt: `bench_cells` reads
`strip` only when `values` is set, and `definition_bench_view` computes the labels when `labels` is None.
Kept on purpose: `refusal` (a few bytes; it keeps a refused row's `--`), and `edit` / `undo` / `preview` / `runs` (the
operator's edit and its encode, not decoded values; R-PE-BENCH.26 bounds decoded values).

**RED -> GREEN** (node `test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values`, unchanged, `slow`, `-n 0`):

| Tree | Load before -> after | Result | Transcript |
|---|---|---|---|
| `a8c936ee` | 1.09 -> 1.22 | **RED** `4.0 MiB allocated by s19_app are still retained after deselecting LARGE (all allocations: 7.8 MiB)`, `1 failed in 452.15s` | `transcripts/r262-base.txt` |
| fixed (`10a15f91`) | 1.17 -> 1.07 | **GREEN** `1 passed in 439.29s` | `transcripts/r262-fix.txt` |

Inc 9 widget files on the fixed tree (`_a9`, `_i`, `_w_keys`, `_w_select`, `_w_stage`, `_w_jobs`, `_w_mutants`,
`-m "not serial_timing and not slow" -n 2`): **106 passed in 417.35s** (`transcripts/r-widget.txt`; MW9: 104 + 2).

Deviation: my first fixed-tree run (`chain1-log.txt`, 06:56) shipped the tree without `tools/` and errored at setup
(`make_release_case.py` missing; 0 tests ran). Both runs were repeated on a tree built from `git archive a8c936ee` plus the
changed files (`chain3-log.txt`); the errored outputs were overwritten and are not evidence.

## F-MW9-2 - keys during LARGE's preview / record encode (R-PE-BENCH.29/2, .82/1)
### Diagnosis (skill `diagnose`; each probe one run of 29_2's scenario on `a8c936ee`, quiet host)
Hypotheses from the ruling: (H1) GIL held by the worker's encode, (H2) encode on the UI thread, (H3) a per-row message
flood, (H4) a repaint proportional to the row. Probes (`test_fx9_probe.py`, `test_fx9_probe2.py`; `PRESS` rows are
`[offset from the apply, press seconds, worker phase, selector calls]`):

| Probe | Load before | What a `right` press took (`pilot.press`) | Reading |
|---|---|---|---|
| `base` (product as is) | 0.15 | 2.238, 2.221, 2.234, 2.220 s, then 1.138 s; 156-174 selector calls each; after the encode 0.13 s / 26 calls | reproduces MW9's 2.2 s |
| `swi` (`sys.setswitchinterval(0.0005)`) | 0.73 | 2.216, 2.216, 2.296, 2.233 s | **not** the 5 ms GIL convoy: a 10x shorter switch interval changes nothing |
| `sleep` (worker sleeps 12 s before the real encode; GIL released) | 0.87 | 0.128-0.228 s | the UI thread, its paint and its messages are fast: not H2 / H3 / H4 |
| `spin` (worker spins 12 s in pure Python, no product code, then the real encode) | 0.73 | 2.218, 2.210, 2.229 s while spinning, the same during the encode | ANY CPU-busy thread gives 2.2 s, whatever it computes |

So the 2.2 s does not depend on the product's encode, nor on the GIL switch interval. Textual 8.2.8's
`App._press_keys` (used by `pilot.press`) runs, per key, `driver.send_message(key)`, `await wait_for_idle(0)`,
`await animator.wait_until_complete()`, `await wait_for_idle(0)`; `textual/_wait.py::wait_for_idle` sleeps in 20 ms
steps until the PROCESS's CPU time (`time.process_time()`, every thread) stops advancing, at most `max_sleep = 1` s.
With a worker thread computing, both waits run to their 1 s cap: 2 x 1 s + the key's own work = 2.2 s.

Probe 2 measures the key itself: from the key event reaching the driver (`driver.send_message`) to the sheet's
`action_choose` returning (`handle_s`), and to the next frame the app displayed (`frame_s`):

| Probe 2 | Load before -> after | `handle_s` | `frame_s` | `press_s` |
|---|---|---|---|---|
| `base` | 0.32 -> 1.90 | 0.034-0.067 s | 0.077-0.309 s | 1.071-2.225 s |
| `spin` | 1.90 -> 2.68 (my own probe's two threads) | 0.057-0.164 s | 0.134-0.262 s | 0.767-2.277 s |
| `stall` (control: `action_choose` sleeps 0.8 s on the UI thread) | 2.68 -> 2.17 | 0.860-0.861 s | 0.926-0.942 s | 2.206-2.231 s |

**Measured cause:** the product handles a key in at most 0.16 s (first frame at most 0.31 s) while LARGE's encode runs; the
2.1-3.0 s MW9 measured is `pilot.press`'s idle wait, which reads the same 2.2 s with the UI thread free (`base`) and with it
stalled 0.8 s (`stall`). The instrument cannot tell a defect from no defect while a worker computes. None of H1-H4 holds as a
product defect: the encode is off the UI thread (H2 no), and the GIL it holds costs the key under 0.16 s (H1 small).

### Fix (test side, Inc 9's slice; the 0.5 s bound is unchanged)
`tests/test_b103_inc9_w_jobs.py`: new `handled_press(pilot, sheet, key)` = the time from the key event reaching
`app._driver.send_message` to the sheet's key action (`action_choose` for right/left, `action_move` for down/up) returning,
so a key that waits behind other UI-thread work (a result's arrival, a paint) still counts. `keys_until` (29_2, 82_1) uses
it; 29_1 and 20_1 keep `timed_press` (no worker computes during their presses, so `pilot.press`'s time is a safe upper
bound there). The module docstring says which instrument each node uses and why. White-box points: `app._driver` and an
instance attribute over the sheet's action, both restored after the press.

No product change for F-MW9-2: no new process model, no `codewire/` interface touched.

### RED before / GREEN after / control (each node alone, `-n 0`, `-m serial_timing`, load < 2 read before each)

| Node | Tree | Load before -> after | Result | Transcript |
|---|---|---|---|---|
| 29_1 | `a8c936ee` | 1.03 -> 1.05 | GREEN, 0.169 s, `1 passed in 107.32s` | `transcripts/t-base-291.txt` |
| 29_2 | `a8c936ee` | 1.05 -> 0.95 | **RED** `slowest press 2.304 s` | `transcripts/t-base-292.txt` |
| 82_1 | `a8c936ee` | 0.95 -> 2.69 | **RED** `slowest press 3.615 s` | `transcripts/t-base-821.txt` |
| 29_1 | fixed | 1.86 -> 1.12 | **GREEN**, 0.219 s, `1 passed in 110.37s` | `transcripts/t-fix2-291.txt` |
| 29_2 | fixed | 1.12 -> 0.92 | **GREEN**, slowest 0.212 s, `1 passed in 98.31s` | `transcripts/t-fix2-292.txt` |
| 82_1 | fixed | 0.92 -> 2.04 | **GREEN**, slowest 0.079 s, `1 passed in 142.56s` | `transcripts/t-fix2-821.txt` |
| 29_2 | fixed + stall mutant | 1.57 -> 2.37 | **RED** `slowest press 0.972 s` (the repaired instrument catches UI-thread work) | `transcripts/t-fix2m-292.txt` |
| 82_1 | fixed + stall mutant | 1.77 -> 1.27 | **RED** `slowest press 0.986 s` | `transcripts/t-fix2m-821.txt` |

Control mutant (`mutant-stall.diff`, on a copy, HT-09): `ArrayBenchSheet._paint` sleeps 0.8 s on the UI thread while a
bench job is active. The load after a run includes the run's own two busy threads (UI + worker).

## Findings for the orchestrator
- **F-FX9-1 (decision):** F-MW9-2's ruling assumed a product defect; the measurement shows a test-instrument defect. I fixed
  the instrument (above) instead of the product, with the threshold unchanged and a control mutant RED. Confirm, or have an
  independent tester review `handled_press` (the implementer wrote the oracle change).
- **F-FX9-2 (observation, no change):** 20_1 ("a key while a LARGE decode runs") holds the decode in `Gate` (a sleeping
  worker), so it never measures a key against a COMPUTING decode; with `pilot.press` as its instrument it could not (2.2 s,
  as above). Its claim is shown only for an idle worker. Suggest `handled_press` with a released (computing) decode.

## Step 3 - fresh clone of `1d805115` (bundle of `b103-inc9`, `chain4.sh`, one run per file, `-n 2`, `timeout 300`)
`s19_app.__file__` = `~/work/zq-fx9/clone/s19_app/__init__.py` atop every transcript (`transcripts/clone/c-*.txt`; summary
`chain4-log.txt`; load 0.58 at the start, 1.38 at the end).

| Set | Result |
|---|---|
| `tests/test_b103_inc9_*.py` (12 files, `-m "not serial_timing and not slow"`; the timing / slow nodes ran alone above) | **316 passed**, 0 failed |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed |
| Laws: `test_id_registry`, `test_suite_hygiene`, `test_requirements_canon`, `test_address_census`, `test_deps_seam_law`, `test_no_private_tokens`, `test_engine_unchanged` | **117 passed, 3 skipped, 2 failed** - both base-identical as MW9 lists: `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors` (`test_b103_a2l_refresh.py`, `test_b103_picker_model.py`) |

`test_r_tst_070_2` (inside `test_suite_hygiene`) is GREEN: no record of this step spells the runner HOME basename.

## Files
- `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (F-MW9-1; the only source file)
- `tests/test_b103_inc9_w_jobs.py` (F-MW9-2 instrument)
- `.dev-flow/2026-11-05-batch-103/inc-9/E4-fixes-fx9.md`, `steps.log`, `evidence-e4/fixes-fx9/` (probes, scripts,
  `mutant-stall.diff`, transcripts)

## Commits
`10a15f91` step 1 (F-MW9-1), `1d805115` step 2 (F-MW9-2), the record commit after it. No push.

## Evidence checklist
- [x] Tests: each result above is one complete run's own output (`executed`); the timing verdicts were read at load < 2
  before each node (`chain2-log.txt`); RED states are `failed` on `a8c936ee` and on the control mutant.
- [x] No secrets; records redacted (`~`, `<user>`, `<runner-home>`); the redaction needles scanned: 0 hits.
- [x] No destructive command; rtx scratch deleted by explicit list (below); no push.
- [x] File count: 1 source file + 1 test file.
- [x] 0 CR in the committed diffs.

## Scratch deleted (explicit list, only paths I created)
`~/work/zq-fx9/`: `base fix1 fix2 fix2m clone out home x tmp fx9.bundle run.sh launch.sh chain1.sh chain2.sh chain3.sh
chain4.sh`, then the empty folder. Local: the FX9 work folder outside the repo (bundle, mutant copy, probe sources).
