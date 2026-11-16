## Gap totals
| Scenario | Valid | key→run p50 s | max s | key→busy paint p50 s | max s | Pre-run loads |
|---|---:|---:|---:|---:|---:|---|
| a | 10 | 0.005043 | 0.009076 | 0.258626 | 0.310807 | 0.13–0.99 |
| b | 10 | 1.130722 | 1.210959 | 0.293453 | 0.340159 | 0.13–0.99 |
| c-press | 10 | 0.008803 | 0.010590 | 0.261881 | 0.302232 | 0.13–0.99 |
| c-post | 10 | 0.054862 | 0.055695 | 0.361974 | 0.404346 | 0.14–0.99 |
| d | 10 | 0.006958 | 0.009481 | 0.277913 | 0.300883 | 0.13–0.99 |

## Gap segments
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

## Scenario b gate split
| Interval | p50 s | max s | p50 share of key→run |
|---|---:|---:|---:|
| gate_hold_inside_K2 | 1.049454 | 1.054614 | 92.81% |
| post_gate_to_active | 0.073258 | 0.151669 | 6.48% |

## Scenario d GC
| Runs with overlap | GC overlap p50 s | max s | p50 share of key→run | GC before key p50 s | max s |
|---|---:|---:|---:|---:|---:|
| 5/10 | 0.000114 | 0.000275 | 1.64% | 4.512685 | 4.659512 |
## O-E nodes
| Node | Side | n / PASS | p50 s | max s | <0.4 s | Pre-run loads |
|---|---|---:|---:|---:|---:|---|
| 29_1 | base | 5 / 5 | 0.165 | 0.173 | 5/5 | 0.96, 0.92, 0.89, 0.91, 0.89 |
| 29_1 | tip | 5 / 5 | 0.224 | 0.254 | 5/5 | 0.45, 0.84, 0.94, 0.20, 0.81 |
| 29_2 | base | 5 / 5 | 0.487 | 0.515 | 1/5 | 0.92, 0.96, 0.84, 0.93, 0.92 |
| 29_2 | tip | 5 / 5 | 0.634 | 0.830 | 0/5 | 0.91, 0.85, 0.98, 0.14, 0.73 |
| 82_1 | base | 5 / 2 | 1.008 | 1.035 | 0/5 | 0.91, 0.14, 0.97, 0.17, 0.88 |
| 82_1 | tip | 5 / 5 | 0.645 | 0.773 | 0/5 | 0.91, 0.99, 0.13, 0.89, 0.95 |
| 20_1 | base | 5 / 5 | 0.145 | 0.151 | 5/5 | 0.97, 0.02, 0.17, 0.30, 0.35 |
| 20_1 | tip | 5 / 5 | 0.146 | 0.174 | 5/5 | 0.94, 0.95, 0.96, 0.96, 0.97 |
## FX9c parts
| Side | Part | Start s | Duration s |
|---|---|---:|---:|
| base | stage_record | 36.906 | 0.020 |
| base | serialize_change_document | 36.944 | 0.179 |
| base | _render_before_after_card | 37.130 | 0.065 |
| base | find_matching_bracket | 37.257 | 0.000 |
| base | load_text | 37.196 | 0.141 |
| base | _show_document | 37.194 | 0.144 |
| base | set_document | 37.338 | 0.264 |
| base | _refresh_patch_history_view | 36.944 | 0.663 |
| base | _stage_bench_record | 36.906 | 0.701 |
| base | _render_before_after_card | 37.946 | 0.102 |
| base | `_paint` callbacks over 0.05 s: n=74, total=4.975 s, max=0.238 s | — | — |
| tip | stage_record | 40.286 | 0.019 |
| tip | _stage_bench_record | 40.285 | 0.037 |
| tip | serialize_change_document | 40.323 | 0.178 |
| tip | _render_before_after_card | 40.618 | 0.072 |
| tip | find_matching_bracket | 40.753 | 0.000 |
| tip | load_text | 40.692 | 0.139 |
| tip | _show_document | 40.690 | 0.142 |
| tip | _render_before_after_card | 40.863 | 0.075 |
| tip | set_document | 41.056 | 0.250 |
| tip | `_paint` callbacks over 0.05 s: n=49, total=4.151 s, max=0.316 s | — | — |
## Inc 9b timing cases
| Case | Metric | Executed / PASS | p50 s | max s | Bound s | Worst margin | Within bound | Pre-run loads |
|---|---|---:|---:|---:|---:|---:|---:|---|
| 94_1 | R-PE-BENCH.94/1 cue after the key | 5 / 5 | 0.287 | 0.307 | 0.500 | 38.6% | 5/5 | 0.14, 0.60, 0.85, 0.14, 0.60 |
| 94_2 | R-PE-BENCH.94/2 preview cue after Enter | 5 / 5 | 0.259 | 0.306 | 0.500 | 38.8% | 5/5 | 0.81, 0.84, 0.85, 0.96, 0.96 |
| 94_3 | R-PE-BENCH.94/3 stage cue after alt+s | 5 / 5 | 0.266 | 0.315 | 0.500 | 36.9% | 5/5 | 0.97, 0.97, 0.90, 0.91, 0.92 |
| 97_1 | executed assertions | 5 / 5 | — | — | — | — | — | 0.85, 0.93, 0.97, 0.99, 0.13 |
| 97_3 | R-PE-BENCH.97/3 max gap | 5 / 5 | 0.206 | 0.236 | 0.500 | 52.8% | 5/5 | 0.59, 0.85, 0.93, 0.16, 0.61 |
| 97_3 | R-PE-BENCH.97/3 median gap | 5 / 5 | 0.098 | 0.100 | 0.200 | 50.0% | 5/5 | 0.59, 0.85, 0.93, 0.16, 0.61 |
| 98_1 | R-PE-BENCH.98/1 max gap write-to-leave | 5 / 5 | 0.377 | 0.470 | 0.500 | 5.9% | 5/5 | 0.84, 0.97, 0.13, 0.83, 0.95 |
| 99_1 | R-PE-BENCH.99/1 key at the write step | 5 / 5 | 0.280 | 0.664 | 1.000 | 33.6% | 5/5 | 0.95, 0.15, 0.89, 0.96, 0.94 |
