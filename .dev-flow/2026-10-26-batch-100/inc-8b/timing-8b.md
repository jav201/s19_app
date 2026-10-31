# Inc 8b — timing (from `steps.log`, UTC)

Wall: 01:26:46 → 07:40:21 = **374 min** for **37 single-shall requirements** (strict EARS split) → **10.1 min per requirement**.
Inc 8a: 267 min for 11 requirements (24.3 min each, pre-strict granularity) — the per-requirement figures are not like for like: 8b's requirements are the strict split (one "shall" each).

| Stage | Window | min | % | Model |
|---|---|---|---|---|
| E1 requirements + rulings + apply (E2 baseline in parallel) | 01:26–01:44 | 18 | 5 | Opus |
| E2 graph prototype (2 groups) | 01:45–01:57 | 12 | 3 | Opus ×2 |
| E3 PDR: r1, fix1, r2, fix2, r3 verify | 01:58–02:58 | 59 | 16 | Opus |
| E4 build ∥ tester | 02:59–03:34 | 35 | 9 | Opus ×3 |
| E4 integration (D-5, D-3, re-pins, 13 gap nodes) | 03:35–04:47 | 72 | 19 | Opus |
| E5 reviews ∥ mutants | 04:48–05:27 | 39 | 10 | Opus ×2 ∥ DeepSeek |
| E5 corrective pass 1 | 05:28–07:01 | 93 | 25 | Opus |
| E5 r2 re-review + E13 | 07:01–07:12 | 11 | 3 | Opus |
| Close records ∥ commit, merge, validate, push | 07:12–07:40 | 28 | 8 | DeepSeek → Opus |

## Where the time went
- **Corrective pass (93 min, 25 %).** The GREEN module set (31 modules that exercise the changed functions) took 62 min alone and ran twice (restart when F2 was approved mid-run). Item fixes were ~30 min.
- **Integration (72 min, 19 %).** Two seams the graph had left to rulings (D-5 painted A2L slot, D-3 composer step) became a 4th source file and 5 re-pins.
- **PDR (59 min).** Caught C-7, a pre-existing bug (open-project save wrote an empty `batch`), and the copy-under-link MAJOR before code.

## Models (living rule)
- DeepSeek v4 Pro (pi): mutants 72 rows in 38 min, 0 invalid, spot-check 4/4 valid; close records 22 min, one V4 threshold left for the orchestrator. Keep for mechanical work.
- Opus: all design, review, integration, corrective work. No content loss.

## For the next increment
- Do not change scope while the GREEN module set runs (F2's mid-run approval cost a ~30 min restart).
- The split requirements must list only ledger entries that name them (V26), and LED entries name ids one by one, not ranges.
