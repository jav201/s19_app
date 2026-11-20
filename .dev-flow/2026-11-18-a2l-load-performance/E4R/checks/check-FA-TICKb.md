# CHECK — FA-TICKb (mechanical, DeepSeek v4-pro; verifier did not write this unit)

- unit: FA-TICKb
- tree: ~/work/zq-fa/FA-TICKb/repo
- HEAD sha: b5bc470b700228de68836639ec5debf7a53e340b
- start time: Fri Nov 20 01:27:34 AM CST 2026
- host: <host>

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-TICKb/repo ~/work/zq-fa/chk-FA-TICKb`; in the copy `git diff > ../chk-FA-TICKb.diff`.

- Files changed (4):
  - s19_app/tui/a2l_definition.py
  - s19_app/tui/services/a2l_service.py
  - tests/test_alp_a2l_occupancy.py
  - tests/test_alp_inc3_load_responsiveness.py
- All 4 are within the brief's "Files you may edit": YES
- `git diff --stat`: 4 files changed, 190 insertions(+), 0 deletions
- CR count (`tr -cd '\r' < chk-FA-TICKb.diff | wc -c`): 0
- added `skip`/`skipif`/`xfail`/`sleep(` lines: none
- `def test_` names removed and not re-added: none

STEP1_OK

CHK_EXIT=124 — the DeepSeek check timed out (2700 s) during its later steps and wrote nothing after STEP1_OK. It checked the worker's frozen diff (`diffs/FA-TICKb.frozen.diff`), not the integrated one.

## Orchestrator-scripted mechanical check on the integrated diff (Opus, relevo-25)
Replaces CHK-ds steps 2–5 after its timeout. Deterministic script (no model judgement in the run): `tools25/chk_tickb.sh` + `chk_tickb_mut.py` (orchestrator tools, outside the repo), on a fresh clone of `alp-e4r` b5bc470b with `diffs/FA-TICKb.diff` applied (md5 cfda92e2 = the frozen diff + orchestrator fixes 1–2), host `<host>` (rtx), HT-02 environment, load 0.66 at start, 02:12–02:40.
- **Step 1 (integrated diff):** the same 4 files (`a2l_definition.py`, `services/a2l_service.py`, `tests/test_alp_a2l_occupancy.py`, `tests/test_alp_inc3_load_responsiveness.py`), 207 insertions, 0 deletions, CR 0, 0 added `skip`/`xfail`/`sleep(` lines, 0 test names removed.
- **Step 2 (GREEN vs base):**
  - `.050/1-2` (`-n 0`): `2 passed`;
  - `tests/test_alp_a2l_occupancy.py tests/test_alp_inc3_snapshot_parity.py` (`-n 4 -m "not serial_timing and not slow"`): `64 passed`;
  - the 24 other test files that name `describe_definitions` or `enrich_tags_and_render` (`-n 8 -m "not serial_timing and not slow"`): `1 failed, 856 passed, 1 skipped`; the failure, `test_a2l_inline_axis_length.py::test_tc136_post_axis_pass_ordering_and_precedence`, also fails on the base clone b5bc470b (`1 failed`) → inherited;
  - `tests/test_suite_hygiene.py -k "040 or 041 or 002"` (`-n 0`): `9 passed`;
  - `tests/test_b103_a2l_refresh.py` (the worker's 300 s TIMEOUT; its orphaned 600 s re-run died at ~80 % with no summary): re-run on the reference laptop on a tree with the same diff md5 (`-n 4`, load 0.66 at start): `103 passed in 614.95s`.
- **Step 3 (controls, scratch copy, `-n 0`):**
  - c1 — the `describe_definitions` release call deleted → `.050/1` RED: `producer describe returned with local 'definitions' still holding 8000 entries`;
  - c2 — the `enrich_tags_and_render` release call deleted → `.050/2` RED: `producer enrich returned with local 'source_tags' still holding 8000 entries`;
  - c3 — `requested_set` dropped from the describe release (orchestrator fix 1) → `.050/1` RED: `producer describe returned with local 'requested_set' still holding 8000 entries`.
- **Step 4 (six laws, `-n 0`):** `4 failed, 111 passed, 2 skipped` = the inherited set (070_2, canon obligation word, at_b83_08, no_private_tokens); laws 002 and 040_041 GREEN; canon 3356 rows checked, offenders R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008 only (inherited, none new).
- **Step 5 (claims):** the timing claims are the orchestrator's own laptop measurements (P-242/P-243), not re-checked here: `.050/3` describe gap 0.049/0.047/0.048 s vs the 0.075 s bound, `.050/4` enrich 0.0002 s; they are decided again in M2.
- Verdict: **MECH-GO** (steps 1–4 pass; no new RED).

## Orchestrator intent review (Opus, relevo-24)
GO after two orchestrator fixes in the unit tree, made before integration and measured on the quiet laptop (precedent: FA-D11b). The worker timed out (PI_EXIT=124) with a complete diff; the MD-06 report-only session also timed out after writing rows, controls and the regression table (`FA-TICKb-REPORT.md`; tree md5 099306ad = the frozen diff `diffs/FA-TICKb.frozen.diff`). The integrated diff is `diffs/FA-TICKb.diff` (frozen + the two fixes below).
- **Rows 1–3 (FA-TICK culprit 1, return-time frees).** `release_in_slices` empties private containers in 4096-item steps just before `return` in `describe_definitions` and `enrich_tags_and_render`. Privacy checked (HT-13): both readers return fresh lists of fresh dicts (`a2l.py:4097`/`:4775`, one return each); nothing read from `a2l_data` is released; `shared_with` is an eager `str`, so no returned `Definition` keeps a reference to a released container.
- **Row 4 (PR lane):** locals empty at the return event + result equality with the release no-op'd + `a2l_data["tags"]` intact; controls RED.
- **Row 5 (slow, `serial_timing`):** case_06 return→resume gap. Laptop (load < 1.0 at start): enrich 0.000 s; describe 0.070/0.058/0.060 s with the worker's diff.
- **Fix 1 (orchestrator):** a return-event probe found four more private 220k-item locals (`requested` list, `requested_set` set, `mod_common_of`, `tag_consumed` dicts). The helper also empties sets and `describe_definitions` releases them; the PR oracle lists them. Describe gap → 0.049/0.047/0.048 s.
- **Fix 2 (orchestrator ruling):** the gap is a component proxy for R-A2L-REFRESH.050, so its bound derives from the row: 0.075 s = 3/4 of the 0.10 s tick bound (one GIL hold that long leaves 25 ms for jitter). FA-TICK's 0.05 s had no derivation. The control still measures ~0.18 s, so the oracle keeps its power. The remaining ~0.05 s teardown is not attributed (likely the request-local index's tuple fields): backlog.
- After the fixes (laptop): `.050/1-2` + hygiene `-k "050 or 040 or 041 or 002"` 12 passed; `.050/3` 3/3 GREEN (≈ 35 % margin); `.050/4` GREEN.
- Regression (rtx, report-only session): all listed files GREEN except `test_a2l_inline_axis_length.py::test_tc136_post_axis_pass_ordering_and_precedence` (inherited: fails on base b5bc470b) and `test_b103_a2l_refresh.py` (300 s TIMEOUT; its re-run on the laptop: 103 passed, recorded above).
