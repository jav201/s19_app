# Unit FA-2 — timing-arm markers, the two new law failures, and `slow` on heavy case_06 arms [deepseek-v4-pro · high]

Supersedes `frontA\FA2-brief.md`. Rows 1, 2 and 4 are unchanged in substance. Row 3 moved to FA-KEY (verify only here). Row 5 is new (operator D11).
Tree: `alp-e4r` at **`<sha after FA-KEY>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed diagnosis (R5-F4, R6-F3; do not re-diagnose)
1. **Law `test_r_tst_002`** fails because the Inc 2 timing arms `test_r033_key_latency`, `test_r034_progress_throughout` and `test_at_alp_i2_2_case06_keys_and_progress` carry wall-clock bounds but no `serial_timing`.
   - The law also names `test_r_a2l_def_158_1`, `158_2` and `164_1` (`tests/test_alp_a2l_occupancy_perf.py`) as marked `serial_timing` without being timing arms.
   - Read the law's code (`tests/test_suite_hygiene.py`) to learn what it counts as a timing arm. Fix the tests to the law's rule, never the law.
2. **Law `test_r_tst_040_041`** named the upper timing bound at the old `:609`. FA-KEY replaced that helper with `_key_ack_latency`, which calls `report_margin`. Here you only verify that the law passes. If it still names a line in this file, fix that line with the repo helper.
3. **`tests/test_address_census.py` also names `tests/test_alp_inc2_a2l_attach.py:408`** (now possibly shifted; find it by running the census). Make that line conform to the census rule. The pre-existing `main` hit is not yours.
4. **Operator D11: heavy case_06 arms leave the PR lanes.** CI's PR timing lane runs `-m "serial_timing and not slow"`, and the PR lean lane `-m "not slow and not serial_timing"`.

## Files you may edit
`tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_a2l_occupancy_perf.py`. Never the law files, never product code.

## Rows
| row | what | proof |
|---|---|---|
| 1 | Add `serial_timing` to the three Inc 2 timing arms, the same way the Inc 1/Inc 3 files do it (decorator or `pytestmark`) | `--collect-only -q -m "not serial_timing" tests/test_alp_inc2_a2l_attach.py` lists none of them |
| 2 | Resolve the `158_1`/`158_2`/`164_1` complaint per the law's rule (they are counters or memory arms, not wall-clock) | law `test_r_tst_002` passes |
| 3 | Verify only: law `test_r_tst_040_041` passes; if not, fix in this file with `report_margin` | law passes |
| 4 | Make the address-census line in `test_alp_inc2_a2l_attach.py` census-conform | `tests/test_address_census.py` no longer names this file |
| 5 | Add `@pytest.mark.slow` (on top of their existing markers) to:<br>- `test_r033_key_latency` param `case06-full-processing` only, via `pytest.param("case06-full-processing", marks=pytest.mark.slow)` so the id stays `case06-full-processing`;<br>- the case_06 param of `test_r034_progress_throughout`;<br>- `test_at_alp_i2_2_case06_keys_and_progress`;<br>- in the perf file, every node that reads the case_06 file (`grep -n CASE06`: `test_r_a2l_def_162_1`, `163_1`, `164_1`, `165_1`).<br>`164_1` ends with `slow` and no `serial_timing` if row 2 removes it. | `--collect-only -q -m "serial_timing and not slow"` on both files lists none of the case_06 nodes and still lists the held-phase Inc 2 arms and the `158_*` counters if they keep a marker; `--collect-only -q -m "slow"` lists exactly the heavy nodes (paste both lists) |

Negative control:
- For rows 1–4 the "product" is the law: copy `git show HEAD:<file>` into `../scratch/nc-<row>/`, show the law RED on the unmodified file and GREEN on yours, and paste both lines.
- For row 5 the collect-only lists are the evidence: paste them before and after.

## Nodes you may run (each `timeout 300`, `-n 0`)
- `tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing`
- `tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported`
- `tests/test_address_census.py` (whole file, about 1–2 min)
- `--collect-only -q` on your two files, with the marker expressions above.

Do NOT run the timing or `slow` tests themselves.
