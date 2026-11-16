# E5 WinCI on 53bd5fc8, round 2 (N=10): R-PASTE.13/101 diagnostic tally (P-001, HT-07)

## Verdict

R-PASTE.13/101 failed in 2 of 10 valid runs (43548702062 and 43548712365), so the diagnostic caught the failure twice. RR-1 is **confirmed**: in both failing captures `notify` had returned, but `Notifications.add` had not yet run when the first (and the second) snapshot was taken.

N = 10: no run is infrastructure. The clipboard probe passed in all ten (every run reports 260 tests, 44 skipped, 28/28 acceptance tests; no `powershell-read-exception`). The second failure (43548712365) is the same node as the first, not infrastructure: one failed test, `test_r_paste_13_101_held_row_copy_warns_within_bound`, obligations 107/108, gate `FAIL violations=3` (PYTEST_EXIT, FAILURE node, REQUIRED_NOT_PASSED R-PASTE.13/101). Artifact-safety check passed (violations=0) in the failing runs.

Base: 53bd5fc8 on branch `b103-inc1b` (repo jav201/s19_app), workflow `clipboard-windows`, dispatched 2026-11-13 20:52 CST. No `src/` change versus round 1. Host load not controlled (HT-08).

## Per-run results

| run | conclusion | failed / passed / skipped | FAILED node ids | obligations | valid |
|---|---|---|---|---|---|
| 43548669695 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548674644 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548679911 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548685996 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548691482 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548696683 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548702062 | failure | 1 / 215 / 44 | r_paste_13_101 | 107/108 | yes |
| 43548707633 | success | 0 / 216 / 44 | - | 108/108 | yes |
| 43548712365 | failure | 1 / 215 / 44 | r_paste_13_101 | 107/108 | yes |
| 43548717495 | success | 0 / 216 / 44 | - | 108/108 | yes |

## Per-node rates (valid runs = 10)

| node | failures / valid | worst lateness |
|---|---|---|
| R-PASTE.14/101 (key) | 0/10 | not recorded in the artifact (pass/fail only) |
| R-PASTE.14/102 (right) | 0/10 | not recorded |
| R-PASTE.14/103 (row) | 0/10 | not recorded |
| R-PASTE.14/C1[key], [right], [row] | 0/10 each | not recorded |
| R-PASTE.14/1, /2 (held write) | 0/10 | not recorded |
| R-PASTE.13/1.2 [single], [multi] | 0/10 each | not recorded |
| **R-PASTE.13/101** | **2/10** | n/a (notice-presence assertion, not a lateness bound) |
| R-PASTE.14/C2 (report-only) | 0/10 (report-only) | see below |

C2 `c2_max_lateness_s` per run (order as the run table): 0.450, 0.403, 0.372, 0.388, 0.325, 0.465, 0.075, 0.075, 0.341, 0.403 s; `c2_ticks` 18, 22, 21, 22, 22, 18, 26, 26, 19, 20. Eight of 10 exceed 0.200 s (0.325 to 0.465 s); the two runs at 0.075 s are 43548702062 and 43548707633 (the latter passed R-PASTE.13/101). Report-only: nothing is asserted on the bound. In the two inspected runs (43548702062, 43548707633) the `c2_gc_events` lists show only collections that start and stop in the same clock tick (zero measured duration); I did not tabulate GC for the other eight.

## R-PASTE.13/101 diagnostic, every valid run

Offsets in seconds from install. `n-a` = add minus notify; `p-a` = first snapshot (`pre_observe`) minus add (negative = snapshot taken before the add); `raw` = `raw_count` at `snap_pre`; `q` = `queue_size` at `snap_pre`.

| run | result | notify | add | n-a | pre | p-a | add before pre | raw / q at pre |
|---|---|---|---|---|---|---|---|---|
| 43548669695 | pass | 1.734 | 1.734 | 0 | 1.750 | +0.016 | yes | 1 / 0 |
| 43548674644 | pass | 1.515 | 1.515 | 0 | 1.546 | +0.031 | yes | 1 / 0 |
| 43548679911 | pass | 1.875 | 1.875 | 0 | 1.922 | +0.047 | yes | 1 / 0 |
| 43548685996 | pass | 1.547 | 1.563 | +0.016 | 1.610 | +0.047 | yes | 1 / 0 |
| 43548691482 | pass | 1.547 | 1.547 | 0 | 1.563 | +0.016 | yes | 1 / 0 |
| 43548696683 | pass | 1.625 | 1.625 | 0 | 1.640 | +0.015 | yes | 1 / 0 |
| **43548702062** | **FAIL** | 1.937 | 2.203 | **+0.266** | 1.937 | **-0.266** | **no** | **0 / 2** |
| 43548707633 | pass | 1.750 | 1.750 | 0 | 1.765 | +0.015 | yes | 1 / 0 |
| **43548712365** | **FAIL** | 1.703 | 2.296 | **+0.593** | 1.703 | **-0.593** | **no** | **0 / 2** |
| 43548717495 | pass | 1.625 | 1.625 | 0 | 1.656 | +0.031 | yes | 1 / 0 |

In all eight passing runs: add at the same instant as notify (7 of 8) or one 15.6 ms clock tick later (1 of 8), always before the first snapshot by 15 to 47 ms; `raw_count=1`, `queue_size=0`, not expired; one `notify` (warning, timeout 6.0, `raised` null), `writer written=False`, events `tail_start, writer_start, writer_end, tail_end, wait_returned`, `same_app=true` (checked in the first passing run's full JSON; the table fields are computed for all eight). The passing margin is therefore 1 to 3 clock ticks.

### Failing capture 1: 43548702062 (full `r13_101_diag`, as recorded)

```json
{"events":[["tail_start",0.125,{"same_app":true}],["writer_start",0.125,{}],["writer_end",1.937,{}],["tail_end",1.937,{}],["wait_returned",1.937,{}]],"notify":[{"mono":1.937,"wall":1794626222.2917929,"msg":"Clipboard write failed \u2014 copied inside t","sev":"warning","timeout":6.0,"screen":"Screen","app_id":2281003231632,"returned_mono":1.937}],"added":[{"mono":2.203,"msg":"Clipboard write failed \u2014 copied inside t","raised_at":1794626222.2917929,"timeout":6.0}],"writer":["written=False"],"snap_pre":{"label":"pre_observe","mono":1.937,"wall":1794626222.2940748,"raw_count":0,"raw":[],"reaped_rows":[],"queue_size":2,"screen":"Screen","app_id":2281003231632},"snap_observe":{"label":"post_observe","mono":2.203,"wall":1794626222.5555534,"raw_count":0,"raw":[],"reaped_rows":[],"queue_size":2,"screen":"Screen","app_id":2281003231632},"snap_settled":{"label":"settled","mono":2.469,"wall":1794626222.8329246,"raw_count":1,"raw":[["Clipboard write failed \u2014 copied inside t",1794626222.2917929,6.0,5.4589,false]],"reaped_rows":[["Clipboard write failed \u2014 copied inside t","warning",6.0]],"queue_size":0,"screen":"Screen","app_id":2281003231632}}
```

### Failing capture 2: 43548712365 (full `r13_101_diag`, as recorded)

```json
{"events":[["tail_start",0.125,{"same_app":true}],["writer_start",0.14,{}],["writer_end",1.687,{}],["tail_end",1.703,{}],["wait_returned",1.703,{}]],"notify":[{"mono":1.703,"wall":1794626336.1404705,"msg":"Clipboard write failed \u2014 copied inside t","sev":"warning","timeout":6.0,"screen":"Screen","app_id":2050655140432,"returned_mono":1.703}],"added":[{"mono":2.296,"msg":"Clipboard write failed \u2014 copied inside t","raised_at":1794626336.1404705,"timeout":6.0}],"writer":["written=False"],"snap_pre":{"label":"pre_observe","mono":1.703,"wall":1794626336.142492,"raw_count":0,"raw":[],"reaped_rows":[],"queue_size":2,"screen":"Screen","app_id":2050655140432},"snap_observe":{"label":"post_observe","mono":1.953,"wall":1794626336.4019594,"raw_count":0,"raw":[],"reaped_rows":[],"queue_size":2,"screen":"Screen","app_id":2050655140432},"snap_settled":{"label":"settled","mono":2.562,"wall":1794626337.0112617,"raw_count":1,"raw":[["Clipboard write failed \u2014 copied inside t",1794626336.1404705,6.0,5.1292,false]],"reaped_rows":[["Clipboard write failed \u2014 copied inside t","warning",6.0]],"queue_size":0,"screen":"Screen","app_id":2050655140432}}
```

(The JUnit failure message carries the same JSON truncated; the lines above are the complete property.)

## RR-1 and H1 to H5 from the failing captures

Both failing captures show the same ledger order: `tail_end` = `notify` = `wait_returned` = `snap_pre` at one instant (1.937 s in the first, 1.703 s in the second), and the add much later (2.203 s, 2.296 s).

- **RR-1 confirmed.** First capture: `notify[0].returned_mono=1.937`, `added[0].mono=2.203`, `snap_pre`: `mono=1.937, raw_count=0, raw=[], queue_size=2`; `snap_observe`: `mono=2.203, raw_count=0, queue_size=2`. Notify was called, `Notifications.add` had not run at either of the first two snapshots; it ran 0.266 s after notify. Second capture: `returned_mono=1.703`, `added.mono=2.296`, `snap_pre` raw_count 0 / queue_size 2 at 1.703, `snap_observe` raw_count 0 / queue_size 2 at 1.953 (still before the add at 2.296). The notice appears only at `snap_settled` (2.469 s and 2.562 s: `raw_count=1`, `queue_size=0`). The test asserts on `snap_observe` (`observed_warnings=[]`, `notices_seen=[]`), so it reads notices before the Notify message is handled.
- **H5 (add deferred behind a queued Notify message): confirmed.** `queue_size=2` at the first and second snapshot in both captures (0 in all eight passing runs) is the queued backlog; it drains to 0 only at `snap_settled`, with the add in between.
- **H1 (writer path): refuted.** `writer=["written=False"]` and exactly one notify call, same as passing runs; `writer_end` precedes `tail_end` normally (1.937 / 1.937; 1.687 / 1.703).
- **H2 (notify raised): refuted.** `returned_mono` is set and equals `mono`; `raised` absent.
- **H3 (expiry): refuted.** At `snap_settled` the notice has 5.4589 s and 5.1292 s of the 6.0 s left, not expired; at the earlier snapshots it was not in the list at all, so it was never expired, only absent.
- **H4 (app mismatch): refuted.** `app_id` is identical across notify and all three snapshots (2281003231632; 2050655140432), `same_app=true`.

Mechanism (reading from the fields only): `notify` returns at `tail_end`, but the toast is added only when the app's message pump handles the queued Notify, and on a loaded runner that handling lagged 0.27 to 0.59 s, past the immediate snapshots. Passing runs pass because the pump handles it within about one clock tick of `tail_end`.

## PP-04: FAILED set versus round 1

| item | round 1 (N=9 valid) | round 2 (N=10 valid) | delta |
|---|---|---|---|
| R-PASTE.13/101 | 0 | 2 (43548702062, 43548712365) | **new** (was gone in round 1) |
| runner_clipboard_probe + 28 setup errors | 1 run (infrastructure) | 0 | gone |
| all other nodes | 0 | 0 | same |

## Combined rate across both rounds

- Valid runs with diagnostic (53bd5fc8): round 1 0/9 + round 2 2/10 = **2/19** (0.105).
- Including the earlier undiagnosed sets (3c064348, 7804b500: 3 failures in 20, per the round-1 record): 3 + 0 + 2 = **5/39** (0.128). Check: the round-1 record states 3/29 overall (3/20 + 0/9); 29 + 10 = 39 valid runs, 3 + 2 = 5 failures.
- Round 1's 0/9 was consistent with a true rate near 0.13 to 0.15 (P(0 in 9) about 0.23 at 0.15), as the round-1 record warned. The diagnostic does not appear to hide the failure.

## Proposal (unchanged from round 1, now supported by failing captures)

In `test_r_paste_13_101_held_row_copy_warns_within_bound`, replace the immediate snapshot used by the assertion with a bounded wait (poll with `pilot.pause()` inside the existing 10 s budget) on "the write-failure notice is present in `app._notifications`", then take the snapshot the assertion uses. Assertions on text, severity, timeout and "exactly one" stay unchanged and still fail if the notice never arrives. The captured lags (0.27 and 0.59 s) are well inside a 10 s budget. This record applies no change.

## Evidence (redacted)

- JUnit property `r13_101_diag` and `c2_*` of artifact `b103-winci-outcomes` in all ten runs; gate lines `WINCI_GATE tests=260 passed=215 failed=1 ... obligations_passed=107/108` and `WINCI_GATE_RESULT FAIL violations=3 pytest_exit=1 gate_exit=1` for the two failing runs; `WINCI_GATE_RESULT PASS violations=0` for the other eight.
- Failure tracebacks contain the runner account name and temp paths and are not reproduced here.
