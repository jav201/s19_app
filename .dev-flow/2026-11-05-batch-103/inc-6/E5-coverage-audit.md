# Inc 6 — E5 independent coverage audit

**Verdict: PASS-WITH-NOTES.** All 21 requirements and 77 threshold alternatives map to real on-disk test nodes and are GREEN. Final coverage: **75 full, 2 partial; 75 covered, 2 partial; 77 verified; 0 gaps/conflicts.**

Accepted corrections:

- `.011/1` explicitly proves the visible enabled include control before Space/Enter toggles.
- `.019/2` measures `row_count` after every one of 20 real rebuilds and asserts every count ≤200, with zero describes and stable formats.
- `.007/1` and `.009/1` remain valid preservation arms, not downgraded merely for passing on base.
- `.019/1` uses the real 13,990-object corpus and meets the 2.0 s budget.
- `.020` verifies actual Textual geometry and complete over-cap text at both widths.

**Only note:** `.021/1-2` are `partial`. The synchronous real handler test verifies exact status, zero actions, zero image reads, zero writes and preservation of ARR12, but uses an unmounted panel and a substituted status label. Repeated mounted `run_test` attempts stalled, so that acceptance route is not claimed. The limitation is explicit in `02-test-cases.md:94-95,102` and in the test docstring.
