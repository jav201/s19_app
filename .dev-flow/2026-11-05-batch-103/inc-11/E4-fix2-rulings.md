# Inc 11 E4: rulings after the implementation fix pass (orchestrator, 2026-11-08)

- **Memory: accepted.** Fresh-process peak is 610 MB on case_06 (1.14×) and 98 MB on software_a (1.03×), within ≤ 2×. The 6.43 GB in the perf arms came from `_peak_mb` inheriting the forked parent's memory, so it is a test fault: measure each peak in a fresh subprocess.
- **READ.52 time: still a real gap, not accepted.** The run gives 2.0× on case_06 (11.7 s) and 2.1× on software_a, against the bound of ≤ 1.5× ruled at E3. **Perf pass (implementer, DeepSeek), on `a2l.py` only:**
  - Profile with `cProfile` on the runner for both files. Save the top 25 entries by cumulative time as `inc-11/evidence-e4/perf-profile.txt`.
  - Remove the hot spots without changing any output. The equality guard is the tester's reference fixture `tests/fixtures/b103_i11/e07fb00_tags.jsonl` plus the reader tests.
  - Prefer a fast path for lines that hold no quote, no comment and no hex-like word: one compiled `split` per line, with the slow path only when needed.
  - **If ≤ 1.5× is not reachable** after the profile-guided pass, report the best ratio with the profile. The orchestrator will then rule on the bound with the operator, based on measured data.
- **Test faults:** run a tester pass (DeepSeek, tester role) on the list in `evidence-e4/test-faults.md`, including `_peak_mb` and the 24 Inc 2a expectations that Inc 11's rows change on purpose. Each re-pointed expectation names its Inc 11 row. Edit test files only.
- Both passes run in parallel: the implementer owns `a2l.py`, the tester owns `tests/`. Each commits its own files. Then the orchestrator re-runs integration run 3.
