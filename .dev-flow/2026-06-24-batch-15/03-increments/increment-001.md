# Increment 1 — Red regression test (US-016, LLR-016.3) — TDD red-first

> Phase 3, batch-15. Toolchain gate PASS (python 3.14.4 / pytest 9.0.3 / ruff 0.8.4; base aeb8da0). 1 file, 0 production edits. **R-2 resolved: REACHABLE.**

## 1. What changed
Added the black-box regression test `tests/test_tui_diff_compare_realpath.py` — 4 acceptance tests (AT-016.1/.2/.3/.4) driving the **real** `#diff_compare_button` via Textual Pilot, **no `compare_images` monkeypatch**. First empirically resolved R-2 (the reachability gate), then captured AT-016.2 as the pre-fix RED. No production code touched (the fix is Inc 2).

## 2. Files modified
- `tests/test_tui_diff_compare_realpath.py` (NEW, +213 lines). Degenerate + well-formed fixtures inline via `tmp_path` (no `examples/` asset, no `conftest.py` change).

## 3. How to test
- `python -m pytest tests/test_tui_diff_compare_realpath.py -v` (pre-fix tree).
- R-2 verification (software-dev throwaway snippet): write `"S1ZZGARBAGE\nNOTANSREC\nS1!!!!\n"` to a tmp file, then `S19File(<that path>)` → no raise, `get_memory_map() == {}`, `records == []`; `compare_images(degenerate, wellformed)` → `refused is False`, 1 `only_b` run. *(Correction, qa Phase-5: `S19File` takes a PATH, not content — the original snippet `S19File("S1ZZ…")` would raise `OSError`; the verification was actually run by writing the content to a tmp path, which is what the test does. C-8 now asserts this empty-map precondition inline in AT-016.2.)*

## 4. Test results (pre-fix — the gate evidence)
```
test_at_016_1_two_wellformed_images_show_changed_runs    PASSED
test_at_016_2_degenerate_image_is_flagged_not_silent     FAILED  <-- captured RED
test_at_016_3_unresolvable_path_refuses_without_crash    PASSED
test_at_016_4_legit_small_valid_image_is_not_flagged     PASSED
1 failed, 3 passed
```
AT-016.2 RED (verbatim): `AssertionError: an empty-map image vs a full image must surface a sev-error status, not a silent sev-ok; status was 'Compared degenerate.s19 vs full.s19: 1 runs.'` — the `reached_display_path` pre-condition PASSED (`_diff_last_result.refused is False`), proving the bug is exercised through the silent display branch, not the refusal branch.
- Orchestrator independently reproduced: 3 passed / 1 failed; ruff clean; collection 894→898 (+4); frozen guards pass (test_engine_unchanged 1 + tc031 3); 0 production edits (`git diff --name-only -- 's19_app/**'` empty).
- code-reviewer: **APPROVE** (0 HIGH / 0 MED / 2 LOW, both "no change required"); all 5 rule-ons PASS (black-box purity, AT-016.2 non-vacuity, over-correction guards distinct, conventions, fixtures).

## 5. Risks
- AT-016.2's `"degenerate.s19" in status_text` clause encodes the post-fix UX expectation that the diagnostic NAMES the failed side — Inc 2 must honor "name the side" (LLR-016.1 D-4 / F-S-03 plain-text) or the AT needs adjusting when it goes green.
- `app._diff_last_result` is a documented grey-box hook (the F-Q-03 mandated pre-condition) inside an otherwise black-box test — intentional, minimal (only AT-016.2 asserts on it).

## 6. Pending items
- **Inc 2 (the fix):** in `_diff_load_maps` + its caller, detect "source path non-empty AND map empty" (predicate `records==[]`, F-A-04) per side and surface `sev-error` naming the side, via an out-of-band carrier (no maps-tuple mutation; report-path ripple F-A-05), plain-text (`#diff_status` stays `markup=False`). Flip AT-016.2 → GREEN (4/4); keep AT-016.1/.3/.4 GREEN; full suite no regression.
- LOW F1/F2 (reuse `make_large_s19` / `asyncio.run` idiom): no change required; noted for reconciliation.

## 7. Suggested next task
Inc 2 — production fix in `s19_app/tui/app.py` per LLR-016.1, then re-run this file (4/4) + `tests/test_tui_diff_screen.py` (no regression on existing refused/render branches).

## Ledger
collection 894 → 898 (D0 / A4 EXACT: AT-016.1/.2/.3/.4). AT-016.2 currently RED by design (the captured escaped-bug evidence).
