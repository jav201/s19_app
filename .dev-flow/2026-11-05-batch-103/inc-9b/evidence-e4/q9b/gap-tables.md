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
