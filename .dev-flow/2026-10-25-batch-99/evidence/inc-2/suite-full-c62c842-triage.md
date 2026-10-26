# Full-suite triage — main at c62c842 (after Inc-2), against the batch baseline at a293213

`suite-full-c62c842.txt`: **18 failed, 3621 passed, 3 skipped, 3 xfailed** (2:09:54). Baseline: 11 failed, 3617 passed.

| Node | In baseline? | Classification | Evidence |
|---|---|---|---|
| `test_tui_directionb::test_tc031_engine_modules_have_no_diff_vs_main` (×2), `test_tui_issues_triage_b94::test_tc_b94_18_curated_set_and_engine_freeze` | no | environment: they diff the worktree against the local branch `main`, which moved past `c62c842` (Inc-10, Inc-11 landed) while the suite ran | re-run in the main checkout at `793c477`: passed |
| `test_id_registry::test_tc607_scanned_corpus_matches_the_declared_bound` | no | **real**: batch-99 added test modules without bumping `EXPECTED_SCANNED_TEST_FILES` (199 → 206 measured) | fixed in the commit that adds this file; re-run: 13 passed |
| `test_before_after_report::test_tc330_*` | no | known flake: Inc-9's reviewer measured 3/5 failures on main without batch-99 changes | Inc-9 review round 1 |
| `test_tui_patch_glyphs::test_at077c_stale_provenance`, `test_tui_patch_editor_v2::test_verify_quiet_pass_on_faithful_hex_save` | no | known flakes (batch-97 inc-1/inc-4/inc-6 records; Inc-11's reviewer saw at077c fail 3/6 at HEAD) | batch-97 records; Inc-11 review |
| `test_tui_patch_editor_v2::test_at057b_*`, `test_tui_patch_history_strip::test_tc081_1_derived` | no | **pre-existing flakes**: each fails about 1 run in 3 at the batch base `a293213` too (3 runs there: 2 pass, 1 fail; same at `c62c842` and at main `793c477`) | orchestrator re-runs, 2026-10-25 |
| `test_tui_patch_variant::test_tc_035_4_routing_guards` | no | flake: 4 isolated re-runs on main all passed | orchestrator re-runs |
| baseline nodes `test_tc024`, `test_tc328`, `test_at063c` | yes | passed in this run (order-flaky in the baseline) | — |

**Verdict:** one real failure (`tc607`, the scanned-module bound), fixed in this commit; every other non-baseline node is either environmental (freeze guards against a moving `main`) or a flake reproduced on the batch base. No regression attributable to Inc-2.
