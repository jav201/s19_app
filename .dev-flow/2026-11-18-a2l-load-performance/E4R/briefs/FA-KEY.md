# Unit FA-KEY — the key-acknowledgement instrument, capture bound and capture cadence [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`35d69a03`** (orchestrator fills in; HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed diagnosis (DX-F2, re-checked in code by the architect; do not re-diagnose)
- `tests/test_alp_inc2_a2l_attach.py:602-612` `_key_latency` and the capture arm's `press_key_from` (`:1189-1197`) time `await pilot.press(key)`.
- Textual 8.2.8 `App._press_keys` sends the key and then awaits `wait_for_idle(0)` twice (`textual/app.py:2066-2069`). `textual/_wait.py` waits up to 1 s each time, until `process_time()` stops advancing.
- While any thread is busy, every press therefore costs ≥ 2.0 s whatever the app does. On Linux the case_06 arms read 2.1 s, while the real acknowledgement is 4–58 ms.
- So the instrument is wrong, not the product. The capture arm (`request-snapshot`) records its latencies without a bound. Operator D-11 restores the 1.0 s bound there (R-A2L-REFRESH.049).

## Files you may edit
`tests/test_alp_inc2_a2l_attach.py` only.

## Rows
| row | change | negative control (scratch copy) |
|---|---|---|
| 1 | Replace `_key_latency` with `async def _key_ack_latency(pilot, app, key, acked, *, bound, timeout=20.0) -> float` (see "Helper" below for the body). Keep `_key_latency` as a thin alias only if other code calls it (grep). | In the scratch copy, add `time.sleep(1.5)` at the top of `S19TuiApp.step_busy` (`s19_app/tui/app/…`, grep `def step_busy`) and run `test_r033_key_latency[parse]` → RED with a latency ≥ 1.5 s |
| 2 | `_focus_key_pair` uses the helper. The held arms, the `case06-full-processing` arm and `test_at_alp_i2_2_case06_keys_and_progress` keep their intent and bound `timing_bound(1.0)`. Docstrings cite R-A2L-REFRESH.033 (E4R). | covered by row 1 |
| 3 | `request-snapshot` arm: drop `press_key_from`. Post `tab` with the helper's delivery call immediately **before** `app.load_a2l_from_path(old)` and start polling after the call returns, from the delivery time; then do the same for `shift+tab`. Assert each latency ≤ `timing_bound(1.0)`. Keep every phase assertion (parse held, `enrich_calls == []`, busy line visible) and the mapping-independence assertions. Docstring cites R-A2L-REFRESH.049 (capture) and .030 (mapping). | Scratch: in `s19_app/tui/app/file_load.py` `_start_a2l_load`, add `time.sleep(1.2)` right after `image_mem_map = MappingProxyType(dict(current_file.mem_map))` → `[request-snapshot]` RED |
| 4 | `test_r034_progress_throughout`, capture arm: assert every interval between visible progress updates that spans the capture is ≤ `timing_bound(1.0)` (today it is recorded only). The case_06 arm's window ends when installation is dispatched; the refresh gap stays recorded and unasserted (D-12). Docstrings cite R-A2L-REFRESH.034 (E4R). | same 1.2 s capture delay → the r034 capture arm RED |
| 5 | New test `test_r033_key_ack_instrument_controls`, parametrized `["ui-block-detected", "busy-worker-not-penalized"]`, `@pytest.mark.serial_timing`, docstring citing the R-A2L-REFRESH.033 negative control. Arm 1: a UI-thread `time.sleep(1.5)` scheduled with `app.call_later` right after delivery → the helper reports ≥ 1.5 s (lower bound, robust to load). Arm 2: a daemon thread runs a pure-Python loop for 3 s (it holds the GIL; DX's synthetic case) while `tab` is delivered → the helper reports ≤ `timing_bound(1.0)`. | Scratch: make the helper call `await pilot.press(key)` instead of posting → arm 2 RED (≈ 2.1 s) |
| 6 | The helper reports the upper-bound margin with `report_margin` from `tests/support/timing.py` (read its signature and one existing caller). This absorbs FA-2 row 3, the `:609` law finding. | covered by `tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported` (the checker runs it) |

## Helper
- **Read `App._press_keys` in the installed Textual** (`/data/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/app.py`, around line 2043). Build the key event exactly as it does (`events.Key(key, character)` with the same character rule) and deliver it the same way (`driver.send_message(...)`, or `app.post_message(...)` if that is what it uses for the headless driver), but **without** `wait_for_idle` and without the animator wait.
- **Then poll:** `t0` = the time just before delivery; loop `while not acked(): await asyncio.sleep(0.005)`; fail at `timeout`; return `time.monotonic() - t0`; assert ≤ `bound` with the existing message format.
- **Never** call `pilot.press` or `pilot.pause()` without a delay inside the helper.

## Nodes you may run (`-n 0`, `timeout 300`, serially)
- `tests/test_alp_inc2_a2l_attach.py::test_r033_key_latency` arms `copy`, `parse`, `enrichment`, `definitions` and `request-snapshot` (NOT `case06-full-processing`);
- `::test_r034_progress_throughout` arms without case_06 (see its ids with `--collect-only -q`);
- `::test_r033_key_ack_instrument_controls`;
- `--collect-only -q` on the file.

Your GREEN results are indicative; the orchestrator decides timing (M1) on the quiet host. Do NOT run the case_06 arms or `test_at_alp_i2_2`.

## Report extras
In REPORT.md, list every latency you measured, the host load (`uptime`) at each run, and the exact delivery call you chose, with the Textual source lines you read.
