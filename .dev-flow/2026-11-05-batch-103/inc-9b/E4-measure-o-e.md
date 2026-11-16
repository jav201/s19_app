# Inc 9b E4 Q9b — O-E timing measurement

## Scope and protocol

This is a measurement-only record; no product code, requirement, test bound or operator decision is changed. The exact base is `e4485817d7ac3706c77f14a4c2a8cf784fe35038` and the exact Inc 9b tip is `31f28f5e9209eb6eaa7957a0362656fa30973df9`. Both clones came from a fresh bundle containing the named branches `b103-inc9b` and `main`; the pre-existing smoke tree was preserved and excluded.

Every node runs alone on Linux `<runner>` with `-n 0`, the isolated environment, closed stdin and `timeout 300`. Each transcript starts with the imported `s19_app.__file__`, records the full HEAD and prints `uptime` before pytest. The one-minute load must be below 1.0, with two-minute retries for up to 60 minutes. Exit 0 alone is insufficient: the validator also requires the one-test PASS summary and the node's emitted QC-TM margin. A timing assertion failure with a complete QC-TM record remains in the distribution and counts as FAIL; a timeout, collection error or marker-empty run does not. The FX9c probe must emit a non-empty `FX9CPARTS` payload containing the stage block. Committed `.97/1` emits no QC-TM margin, so its result is limited to its executed assertions and process verdict; no substitute timing is invented.

The four O-E nodes are run five times per side. The seven Inc 9b timing nodes are run five times each at the tip. p50 is the median of the emitted per-run measurements and max is their maximum. All times and margins come from the transcripts, not from pytest's whole-process duration. The unchanged bounds are 0.5 s for `.20/1` and `.29/1`, 1.0 s for `.29/2` and `.82/1`, 0.5 s for the three `.94` cue latencies, 0.2/0.5 s for `.97/3` median/max gaps, 0.5 s for `.98/1`, and 1.0 s for `.99/1`.

The FX9c probe and its two helper dependencies are the committed files under `../inc-9/evidence-e4/fixes-fx9c/probes/` and `../inc-9/evidence-e4/fixes-fx9b/probes/`, copied only into the scratch clones. No `FX9C_NOBRACKET` or switch-interval override is set.

## O-E results: base versus tip

The complete ledger is `evidence-e4/q9b/status.tsv`; unrounded values and margins are in `summary.json`, and the generated table is `tables.md`. Failed timing assertions with complete measurements remain in the distributions. Every pre-run one-minute load is below 1.0.

| Node | Side | Executed / PASS | p50 s | max s | Under 0.4 s | Pre-run loads |
|---|---|---:|---:|---:|---:|---|
| 29_1 | base | 5 / 5 | 0.165 | 0.173 | 5/5 | 0.96, 0.92, 0.89, 0.91, 0.89 |
| 29_1 | tip | 5 / 5 | 0.224 | 0.254 | 5/5 | 0.45, 0.84, 0.94, 0.20, 0.81 |
| 29_2 | base | 5 / 5 | 0.487 | 0.515 | 1/5 | 0.92, 0.96, 0.84, 0.93, 0.92 |
| 29_2 | tip | 5 / 5 | 0.634 | 0.830 | 0/5 | 0.91, 0.85, 0.98, 0.14, 0.73 |
| 82_1 | base | 5 / 2 | 1.008 | 1.035 | 0/5 | 0.91, 0.14, 0.97, 0.17, 0.88 |
| 82_1 | tip | 5 / 5 | 0.645 | 0.773 | 0/5 | 0.91, 0.99, 0.13, 0.89, 0.95 |
| 20_1 | base | 5 / 5 | 0.145 | 0.151 | 5/5 | 0.97, 0.02, 0.17, 0.30, 0.35 |
| 20_1 | tip | 5 / 5 | 0.146 | 0.174 | 5/5 | 0.94, 0.95, 0.96, 0.96, 0.97 |

### Verdicts and operator proposal

- **`.82/1`:** O-E improves the median by 0.363 s (1.008→0.645 s) and the maximum by 0.262 s (1.035→0.773 s). The base breaches the unchanged 1.0 s bound in 3/5 runs; the tip passes 5/5. However, the tip is **0/5 under 0.4 s**, not the required 5/5. **Do not propose restoring R-PE-BENCH.82/1 to 0.5 s (DF-09).** Keep 1.0 s.
- **`.29/2`:** the tip passes the unchanged 1.0 s bound 5/5 but does not improve (0.634 s p50 / 0.830 s max versus base 0.487 / 0.515 s) and is **0/5 under 0.4 s**. **Do not propose restoring it to 0.5 s.** Keep 1.0 s; O-A remains in the backlog.
- **`.29/1` and `.20/1`:** all 20 runs pass their unchanged 0.5 s bounds. `.29/1` moves from 0.165 to 0.224 s p50 and `.20/1` from 0.145 to 0.146 s p50; neither is an operator-proposal candidate.

The harness-window interruption preserved every completed row and the partial `20_1` run 2 separately as `interrupted-oe-base-20_1-02.txt`; the partial has no PASS status. Replacement run 2 was then executed once. No completed gap or O-E row was rerun.

## Seven Inc 9b timing cases

| Case | Metric | Executed / PASS | p50 s | max s | Bound s | Worst margin | Within bound | Pre-run loads |
|---|---|---:|---:|---:|---:|---:|---:|---|
| 94_1 | cue after the key | 5 / 5 | 0.287 | 0.307 | 0.500 | 38.6% | 5/5 | 0.14, 0.60, 0.85, 0.14, 0.60 |
| 94_2 | preview cue after Enter | 5 / 5 | 0.259 | 0.306 | 0.500 | 38.8% | 5/5 | 0.81, 0.84, 0.85, 0.96, 0.96 |
| 94_3 | stage cue after alt+s | 5 / 5 | 0.266 | 0.315 | 0.500 | 36.9% | 5/5 | 0.97, 0.97, 0.90, 0.91, 0.92 |
| 97_1 | executed painted-title assertions | 5 / 5 | — | — | — | — | — | 0.85, 0.93, 0.97, 0.99, 0.13 |
| 97_3 | maximum gap | 5 / 5 | 0.206 | 0.236 | 0.500 | 52.8% | 5/5 | 0.59, 0.85, 0.93, 0.16, 0.61 |
| 97_3 | median gap | 5 / 5 | 0.098 | 0.100 | 0.200 | 50.0% | 5/5 | 0.59, 0.85, 0.93, 0.16, 0.61 |
| 98_1 | maximum write-to-leave gap | 5 / 5 | 0.377 | 0.470 | 0.500 | 5.9% | 5/5 | 0.84, 0.97, 0.13, 0.83, 0.95 |
| 99_1 | key at the write step | 5 / 5 | 0.280 | 0.664 | 1.000 | 33.6% | 5/5 | 0.95, 0.15, 0.89, 0.96, 0.94 |

All **35/35** runs passed. No 9b timing case exceeded its bound, so there is no MAJOR timing breach. `.98/1` remains PASS but its worst run leaves only 5.9% margin; this is recorded as a low-margin observation, not hidden or used to change the bound. `.97/1` has no QC-TM margin in the committed node; its 5/5 painted-title assertion results are reported without inventing a duration.

## FX9c refresh parts and whole block

The original committed `test_probe_parts` passed once per side at pre-run loads 0.97 (base) and 0.98 (tip). Its base `_stage_bench_record` / `_refresh_patch_history_view` durations are 0.701 / 0.663 s; on the tip it records `_stage_bench_record` 0.037 s, serialize 0.178 s, `_show_document` 0.142 s and `set_document` 0.250 s. See `fx9c-{base,tip}-parts-01.txt` and `tables.md`.

That original wrapper has a known measurement limitation on the tip: `_stage_bench_record` now ends before the timed refresh chain, so 0.037 s is **write-only, not the whole block**. The scratch-only correction `test_fx9c_q9b_probe.py` uses the same committed dependencies and adds hooks for `refresh_entries`, `_patch_refresh_tail` when present, and the `record_done` endpoint. It does not change product behavior or any bound. Both corrected probes passed at loads 0.10 / 0.13 and required a non-null `refresh_block`; see `fx9c-correction.{md,json}`, `fx9c-correction-status.tsv` and the run-02 transcripts.

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

The whole tip chain is longer than base (1.146 versus 0.701 s) because it includes the deliberate 0.1 s event-loop gaps; this is not a key-latency measurement. The individual tip steps are serialize 0.167 s, ledger `refresh_entries` 0.218 s, sheet `set_document` 0.254 s and tail 0.004 s. Nested wrapper durations must not be summed as though disjoint. The corrected whole-block result does not satisfy the 0.4 s operator-proposal condition and does not change the verdicts above; the unchanged `.98/1` and `.99/1` cases independently prove cue and key progress during the chain.

## Completeness

The required matrix is complete: **50 gap runs**, **40 O-E runs**, **2 original FX9c probes**, and **35 Inc 9b timing runs**, plus **2 corrected FX9c probes**. The main analyzer reports 127 measurement rows, 124 PASS and three measured base `.82/1` failures, with no errors. Both corrected probes pass. No timeout or empty trace is counted as PASS, and no product code, requirement, bound or interface is changed.
