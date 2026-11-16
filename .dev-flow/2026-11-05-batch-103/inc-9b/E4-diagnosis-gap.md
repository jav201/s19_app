# Inc 9b E4 Q9b — key-to-job gap diagnosis

## Scope and provenance

This is a measurement-only record. The product tree is the exact Inc 9b tip `31f28f5e9209eb6eaa7957a0362656fa30973df9`; no product code or timing bound is changed. The reviewed probe is `evidence-e4/q9b/test_q9b_gap.py`, run in the real `S19TuiApp` through `run_test` on Linux `<runner>`, never through the prototype driver. The pre-existing smoke tree and its smoke transcript are not counted.

The scratch root is `~/work/zq-q9b`. Each process uses the isolated environment, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `-p no:cacheprovider`, `-n 0`, closed stdin and `timeout 300`. `s19_app.__file__`, the full source HEAD and `uptime` appear in every transcript. A run starts only when the one-minute load is below 1.0; the runner retries every two minutes for up to 60 minutes.

## Validity and segment definitions

A valid gap run has process exit 0, exactly one `Q9BGAP` JSON payload, no probe error, and all seven required markers in both the marker set and event list: `key`, `action_move`, `selection_changed`, `enqueue_decode`, `active_job`, `run_job`, and `paint_busy`. A timeout, failed test, missing payload or empty trace is not a PASS. `validate_q9b.py` enforces these rules; its three known-bad controls are in `evidence-e4/q9b/validator-self-test.txt`.

All durations below are seconds derived from adjacent `time.perf_counter()` stamps. p50 is the median over the ten valid runs and max is their maximum. Shares are the p50 segment duration divided by the p50 key→`run_job` duration, not a claim that the probe can separate causes inside a segment.

| Segment | Probe interval | Diagnostic meaning |
|---|---|---|
| key→action | `key`→`action_move` | application key dispatch to the sheet action |
| action→selection | `action_move`→`selection_changed` | synchronous move plus posted selection-message latency; K3 and K4 are not separable inside this interval |
| selection→enqueue | `selection_changed`→`enqueue_decode` | bench selection-handler work before queue insertion |
| enqueue→active | `enqueue_decode`→`active_job` | K2 queue/active-job wait |
| active→run | `active_job`→`run_job` | worker scheduling until the thread body starts |
| run→busy paint | `run_job`→`paint_busy` | time to the first compositor update containing the LARGE decode cue; outside key→job start |

Scenario `b` additionally separates the artificial gate hold from gate release→`active_job`. Scenario `d` pairs GC start/stop callbacks and measures their overlap with key→`run_job`; callbacks before the key are reported separately. The busy-paint interval is a user-visible cue measurement, not part of the key→job-start total.

## Measured results

The 50/50 valid runs are listed in `evidence-e4/q9b/status-checkpoint-1.tsv`; every payload and load is in `evidence-e4/q9b/transcripts/gap-tip-*.txt`. `gap-summary.json` contains the unrounded per-run values and `gap-tables.md` is the generated form of the following tables. The smoke run is excluded.

### Totals

| Scenario | Valid | key→run p50 s | max s | key→busy paint p50 s | max s | Pre-run loads |
|---|---:|---:|---:|---:|---:|---|
| a | 10 | 0.005043 | 0.009076 | 0.258626 | 0.310807 | 0.13–0.99 |
| b | 10 | 1.130722 | 1.210959 | 0.293453 | 0.340159 | 0.13–0.99 |
| c-press | 10 | 0.008803 | 0.010590 | 0.261881 | 0.302232 | 0.13–0.99 |
| c-post | 10 | 0.054862 | 0.055695 | 0.361974 | 0.404346 | 0.14–0.99 |
| d | 10 | 0.006958 | 0.009481 | 0.277913 | 0.300883 | 0.13–0.99 |

### Per-segment p50 / max

| Scenario | Segment | p50 s | max s | p50 share of key→run |
|---|---|---:|---:|---:|
| a | key_to_action | 0.000965 | 0.000974 | 19.14% |
| a | action_to_selection | 0.001338 | 0.001367 | 26.54% |
| a | selection_to_enqueue | 0.000038 | 0.000041 | 0.76% |
| a | enqueue_to_active_K2 | 0.000022 | 0.000023 | 0.43% |
| a | active_to_run | 0.002663 | 0.006701 | 52.81% |
| a | run_to_busy_paint | 0.253642 | 0.305838 | — |
| b | key_to_action | 0.000953 | 0.000991 | 0.08% |
| b | action_to_selection | 0.001284 | 0.001328 | 0.11% |
| b | selection_to_enqueue | 0.000040 | 0.000042 | 0.00% |
| b | enqueue_to_active_K2 | 1.123782 | 1.203403 | 99.39% |
| b | active_to_run | 0.005337 | 0.006570 | 0.47% |
| b | run_to_busy_paint | -0.835545 | -0.792002 | — |
| c-press | key_to_action | 0.000964 | 0.000974 | 10.96% |
| c-press | action_to_selection | 0.001347 | 0.001365 | 15.31% |
| c-press | selection_to_enqueue | 0.000039 | 0.000040 | 0.44% |
| c-press | enqueue_to_active_K2 | 0.000022 | 0.000028 | 0.25% |
| c-press | active_to_run | 0.006451 | 0.008267 | 73.28% |
| c-press | run_to_busy_paint | 0.252686 | 0.297174 | — |
| c-post | key_to_action | 0.045529 | 0.046327 | 82.99% |
| c-post | action_to_selection | 0.001432 | 0.001457 | 2.61% |
| c-post | selection_to_enqueue | 0.000039 | 0.000047 | 0.07% |
| c-post | enqueue_to_active_K2 | 0.000022 | 0.000028 | 0.04% |
| c-post | active_to_run | 0.007833 | 0.007851 | 14.28% |
| c-post | run_to_busy_paint | 0.306740 | 0.349481 | — |
| d | key_to_action | 0.000966 | 0.000985 | 13.88% |
| d | action_to_selection | 0.001344 | 0.001404 | 19.32% |
| d | selection_to_enqueue | 0.000038 | 0.000039 | 0.54% |
| d | enqueue_to_active_K2 | 0.000022 | 0.000026 | 0.31% |
| d | active_to_run | 0.004567 | 0.007096 | 65.63% |
| d | run_to_busy_paint | 0.272489 | 0.292058 | — |

The negative run→paint durations in `b` are expected: the queued LARGE cue paints before its worker starts. That interval is outside the key→run total and therefore has no share cell.

### Scenario b gate split

| Interval | p50 s | max s | p50 share of key→run |
|---|---:|---:|---:|
| gate_hold_inside_K2 | 1.049454 | 1.054614 | 92.81% |
| post_gate_to_active | 0.073258 | 0.151669 | 6.48% |

### Scenario d GC

| Runs with overlap | GC overlap p50 s | max s | p50 share of key→run | GC before key p50 s | max s |
|---|---:|---:|---:|---:|---:|
| 5/10 | 0.000114 | 0.000275 | 1.64% | 4.512685 | 4.659512 |

## Causes and dispositions

- **K1 — the old prototype-driver observation is a measurement artifact.** The real app's idle key→worker-start p50 is 0.005043 s in `a` and 0.008803 s in `c-press`; even `c-post` is 0.054862 s p50 / 0.055695 s max. None reproduces 0.9–2.5 s. The old interval included driver idle waits/polling after the actual start; this probe timestamps the actual worker. The old driver's exact percentage is not claimed because Q9b deliberately does not rerun that driver.
- **K2 — the single-job queue is the measured product cause when another job holds it.** Idle enqueue→active is 0.000022 s p50. In `b` it is 1.123782 s, **99.39%** of key→run. The deliberate gate contributes 1.049454 s (**92.81%** of the total); after release, summary completion and queue handoff contribute 0.073258 s p50 (**6.48%**), max 0.151669 s. The cue still paints at 0.293453 s p50 / 0.340159 s max, before the worker starts. Existing R-PE-BENCH.94 case 4 already covers this visible queued-cue behavior, so no new requirement row or finding is proposed.
- **K3/K4 — selection posting and synchronous selection work are millisecond-scale, not the old seconds-long cause.** Action→selection is 0.001284–0.001432 s p50 across the scenarios and selection→enqueue is 0.000038–0.000040 s. The probe cannot split K3 from K4 inside action→selection. Posting the input key itself adds 0.045529 s p50 in `c-post` (82.99% of that 0.054862 s total); this is the test's input-delivery arm, not SelectionChanged handler time.
- **K5 — no multi-second GIL effect appears in these key paths.** Gated `b` key→action is 0.000953 s p50, comparable to idle `a` at 0.000965 s. The gate waits before the summary decode computes, so this experiment does not isolate active-compute GIL contention; the O-E `.29/2` measurement remains the relevant encode-window observation.
- **K6 — GC is not a material key→job-start share here.** Five of ten `d` runs have a GC pass overlapping key→run, but overlap is 0.000114 s p50 / 0.000275 s max, **1.64%** of the total. Deselect-time GC before the key is substantial (4.512685 s p50), but it is outside the measured key→job interval and is reported rather than hidden or reassigned.

No product cause lacking an existing visible bound was found. No product code, test bound or interface is changed.
