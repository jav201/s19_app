# Inc 3a E4 common brief — arrays and axes

Base: `aa7f871c` (`batch-103`, Inc 11 integrated). Approved graph: `codewire/graph-inc3.md` (34 nodes). E3 is PASS-WITH-NOTES by ruling; do not reopen design unless a finding proves the approved graph wrong. Inc 3a has 71 rows / 280 cases in scope (223 requirement cases + 53 cited + 4 acceptance; the earlier 253 was the round-4 count). H3e (AXIS_DESCR header on its `/begin` line) is in scope.

## Roles and ownership

- **Implementer (DeepSeek v4 Pro):** only `s19_app/tui/a2l_definition.py` and `tools/synth/make_release_case.py`. No tests or records.
- **Independent tester:** only test files and `inc-3/02-test-cases.md`. No product edits. Write/adjust the case ledger before tests and prove relevant RED on the base.
- The orchestrator owns integration, records, merges and final reviews.

## Environment and evidence

- Runner: `<runner>@<runner-ip>` (<runner>), Python `/home/<runner>/miniconda3/envs/s19ci/bin/python` 3.11.18.
- Implementer scratch: `/tmp/b103-e4-3a-impl/tree`.
- Tester scratch: `/tmp/b103-e4-3a-tests/tree`.
- Use `python -I -B` with explicit `sys.path.insert(0, scratch)`, isolated HOME/XDG/LOCALAPPDATA under `zq_iso_user`, closed stdin, `PYTHONDONTWRITEBYTECODE=1`. Print `s19_app.__file__` at the start of every transcript.
- No clipboard, no proprietary A2L material, no public-corpus text in new records, no operator name or LAN address in new evidence. Use synthetic A2L fixtures.
- No git mutations on the real worktree, no child agents, no stale writers. Each agent works only in its own scratch and returns file lists, commands and evidence paths. Do not commit.

## Implementation obligations

- Implement the approved graph and E3 rulings, including exact FIX point arithmetic, fail-closed datatypes/counts, shared read forms keyed by kind and section identity, reduced immutable forms, and one-lookup-per-element decoding.
- Keep the pure model API compatible with Inc 2a and Inc 11 consumers. No UI changes.
- Preserve H3e: AXIS_DESCR header words on its `/begin` line are read correctly.
- Do not weaken bounds or remove negative controls. Record any graph deviation instead of silently changing the contract.

## Test obligations

- Cover every 3a requirement with the approved examples and exact expected values, including H3e, failure paths, scaling and immutability.
- Prove discriminating RED on the base for behavioral changes; no vacuous checks or expected values derived from the artifact under test.
- Run the new/modified tests and relevant law guards on Linux. Keep RED/GREEN transcripts and report anything not run.
- Do not treat static presence as verified or edit results to match current behavior without a requirement basis.
