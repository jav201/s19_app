# Kimi brief — batch-99 Increment 8 · review round 2 fix (N1)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc8`. Do not commit.

- **N1 [MEDIUM] — a PATCH block with `notices` paints red in Flow Builder.** The notices arm puts its not-applied lines in `diagnostics` (`flow_execution_service.py:≈600`), and Flow Builder paints diagnostics as `sev-error` (`flow_screens.py:≈2203`). Follow the funnel arm's way instead:
  - put the not-applied lines of a `notices` PATCH in `findings` with `FINDING_WARN`;
  - keep `diagnostics` for the `error` arm, whose cause stays last (UX-C2).

  Check that the chain-set report, the flow report and the Flow Execution lane log line still list every non-applied address and refusal (LLR-156.1/156.3/156.4, UX-C1). If any reader took them from `diagnostics`, make it read `findings` too.
  - Add a test arm (a sub-node of TC-B99-17 or AT-B99-07): the partial lane's PATCH lines paint with the warning severity class, never `sev-error`.
  - Mutation: put them back in `diagnostics` → RED.

Run `tests/test_b99_patch_truth.py`, `tests/test_tui_flow_execution_b94.py`, `tests/test_flow_chainset_b94.py`, the Flow Builder tests (`grep -rln "sev-error\|FINDING_WARN" tests/`) and `tests/test_address_census.py`. Update the packet ("Review round 2 fix"). Finish with `HANDOFF-fix2.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
