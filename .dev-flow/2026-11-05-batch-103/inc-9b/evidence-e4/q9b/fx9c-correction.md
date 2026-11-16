| Side | Part | Start s | Duration s |
|---|---|---:|---:|
| base | **whole write+refresh, stage entry→record_done** | 35.974 | **0.701** |
| base | stage_record | 35.974 | 0.039 |
| base | serialize_change_document | 36.030 | 0.169 |
| base | _render_before_after_card | 36.205 | 0.065 |
| base | find_matching_bracket | 36.333 | 0.000 |
| base | load_text | 36.272 | 0.140 |
| base | _show_document | 36.271 | 0.143 |
| base | set_document | 36.414 | 0.257 |
| base | refresh_entries | 36.200 | 0.471 |
| base | _refresh_patch_history_view | 36.030 | 0.645 |
| base | _stage_bench_record | 35.974 | 0.701 |
| base | record_done | 36.675 | 0.047 |
| base | _render_before_after_card | 37.002 | 0.104 |
| base | `_paint` callbacks over 0.05 s: n=52, total=4.244 s, max=0.277 s | — | — |
| tip | **whole write+refresh, stage entry→record_done** | 29.992 | **1.146** |
| tip | stage_record | 29.993 | 0.026 |
| tip | _stage_bench_record | 29.992 | 0.042 |
| tip | serialize_change_document | 30.034 | 0.167 |
| tip | _render_before_after_card | 30.438 | 0.069 |
| tip | find_matching_bracket | 30.569 | 0.000 |
| tip | load_text | 30.508 | 0.141 |
| tip | _show_document | 30.506 | 0.144 |
| tip | refresh_entries | 30.432 | 0.218 |
| tip | _render_before_after_card | 30.665 | 0.066 |
| tip | set_document | 30.772 | 0.254 |
| tip | _patch_refresh_tail | 31.135 | 0.004 |
| tip | record_done | 31.138 | 0.046 |
| tip | `_paint` callbacks over 0.05 s: n=47, total=2.998 s, max=0.239 s | — | — |

Corrected probes: 2/2 PASS; loads 0.10 / 0.13.
