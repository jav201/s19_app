# Inc 13 - E4 tester notes

Independent tester. Base = `origin/main` 7add3d63 (merge-base of the branch with main is `b7b77c4`; the three source files are identical between them). All runs on the LAN Linux host, py3.11 env `s19ci`, detached worktree (removed at the end). No pytest on the Windows PC. Implementation source was not read. Transcript: `evidence/inc-13/red-01-tester-base.txt`.

## Files
- New: `tests/test_b101_designer_recompute.py`, `tests/test_b101_split_join_band.py`, `tests/test_b101_inc13_perf.py` (4 nodes, all `serial_timing`, bounds through `timing_bound` + `report_margin`).
- Support: `tests/support/b101_designer.py` (counter fixture, `wait_designer_recompute`, fixture images), `tests/support/b101_demo_image.py`, `tests/support/b101_inc13_reference.py` (base `_sweep` / `_conflict_marks` verbatim).
- Edited: `tests/test_crc_designer_view.py`: 15 sites (12 nodes, 3 helpers) get the snapshot `recomputes_before = designer_recomputes()` and `await wait_designer_recompute(...)`; plus `import pytest`, the fixture import and `pytestmark`. The snapshot is named `recomputes_before` (several nodes already own `before`). The AST check in the new file reports no other difference.

## Test -> case mapping
See the Tests column of `02-test-cases.md` (updated). Full only where the product itself produces what the test asserts. Partial: 001.2.2/3 (constant), 002.2/2 (read count, not time), 001.3/2 (base behaviour). R-SEG-PREV.7/1 and the state-line half of R-SEG-PREV.20/1 are NOT expressible as written (ambiguity 1).

## RED on base (behavioural reasons)
- Designer file: 15 nodes RED (matrix 25 and 001.8 inverted GREEN by design): 001.2.2 text edit (a recompute at once, count 1), image change (nothing pending), constant absent (`None`), burst (5 recomputes), template load (9), preset (8), image set (preview keeps the empty-state note), stale display (no recompute on display), 5 of 6 read-count states (6 reads), cap (no refusal), out-of-order Ranges (1257406 glyphs).
- Timing arms (alone, host load ~10): 28.4 s, 531.7 s, 60.3 s, 198.9 s vs 3.0 / 3.0 / 3.0 / 2.5 s. All RED.
- GREEN on base by design (they pin unchanged behaviour; teeth shown with mutants of the base source, see transcript): 001.2.1 dropdown/toggle, the 24+1 matrix, 001.8 inverted, all 11 Split/Join nodes, the AST check and its control, the 12 edited-module nodes (full module passes with the waits on base).
- Not run on base: `..._001_12_hostile_three_range_input_...` (about 4.29 G glyphs on base).
- Mutants of base source: M-13 8/11 RED, M-14 7/11 RED, pad-mask 1 RED, M-9 11 RED, M-10 1 RED. Mutants of the NEW code (M-1..M-8, M-12, M-15..M-25) need the implemented tree: owed at E5.

## Ambiguities (not resolved by reading the implementation)
1. R-SEG-PREV.20/1 and R-SEG-PREV.7/1 expect the state line `<size> would clobber source`, but in the F-23 Split/Join scene the span guard has priority and the base paints `GUARD  9.20 MiB span - e will ask` (stats line `packed 1.26 MiB / span 9.20 MiB / fill 56.22%` matches the independent derivation). I pinned the base rendering (design says no render change). qa-reviewer / architect: correct the case text or the scene.
2. Slice section 3 omits a text-edit site: `test_three_warn_conditions_through_view` also sets Pad byte `""` (text) before its first read; I added a wait there too (4 inserted statements in that node).
3. Case 001.2.1 and others use a 10 s quiet time with the image set before key `0`; a pending on-display timer is expected to be stopped by the dropdown (E1-D2 text). Confirm at E5 on the implemented tree.
4. `_pending_recompute` is read with `getattr(..., None)` so the helper also works on base.

## Not covered / limits
- Mutants of the new code and the 5-run QC-TM lane (M-3, M-4 head side) not run: implementation in flight.
- Timing numbers on base are inflated by host load (9-12); head margins must be taken on a quiet host.
- `EXPECTED_SCANNED_TEST_FILES` (test_id_registry) not bumped (integration owns it). New files contain no AT-/TC- tokens.
- 02-test-cases Coverage/Result columns untouched.
