# Inc 13 - E5 code review

Reviewer: E5 code reviewer (independent of the E4 implementers, tester and integrator). Branch `b101-inc13`, head `a086fa5`, scope `git diff main...HEAD -- s19_app tests` (11 files, +2356 / -110). Read-only review: no test or probe was run on the review PC (operator rule). Run evidence is the integrator's transcripts in `../evidence/inc-13/`: `int-lane1-r2.txt` (804 passed, 16 skipped, exit 0), `int-ast-r1.txt` (both D-2 nodes PASSED, not skipped), `int-serial-r1..r3.txt` (4 timing nodes, 3/3).

## Verdict

**PASS-WITH-NOTES.** The three slice files match the graph and the binding E3 rulings (round 1 and round 2). I found no correctness defect in the diff. The tests assert exact expected values and can fail. The AST check guards the whole edited module, and the integrator's `[1:2]` predicate is not weaker than the original.

One MAJOR design-gap stays open: E5-CR-1 (E4-F1). The defect is real and is older than this increment, so it does not block the diff. But rows R-SEG-PREV.7 and R-SEG-PREV.20 cannot be recorded as met while it stays open. I recommend fixing it in the E5 corrective pass. The fix is small and safe; the conditions are in E5-CR-1.

## Findings

### E5-CR-1 - `_state_text` paints the GUARD chip over the clobber line (E4-F1 confirmed) [design-gap, MAJOR]
- **Where:** `s19_app/tui/segment_split_view.py:1773-1785` (`SplitJoinWindow._state_text`). This line is outside the slice; it shipped with batch-95 `42b7bf4`.
- **Canon:** R-SEG-PREV.7 says: if the plan has a conflict byte, show `⚠ <size> would clobber source — abort on export`. R-SEG-PREV.8 shows the GUARD chip only when there is a guard file *and no conflict byte*. So when both are present, the clobber line comes first. `docs/requirements/review/S17-ears-strict.md:279-280` already records this as "Partly", and `docs/requirements/review/CODE-CHANGES.md:397` (D17-27, open) asks for "conflict before guard in the state line".
- **Code:** the `if plan.guard:` branch returns before `if plan.conflicts:` is ever tested.
- **Scenario:** the F-23 Split/Join scene (join fill, span 9.20 MiB, fill above 50 %, `gap_conflict` > 0). The state line reads `⚠ GUARD  9.20 MiB span — e will ask`. The export action refuses on conflicts before it reaches the guard gate (`:2061` before `:2075`), so the state line names a different outcome than the one `e` will produce.
- **Impact on this increment:** R-SEG-PREV.20 is one of this increment's own rows, and its text asks for the clobber line. The arm in `tests/test_b101_inc13_perf.py:294` pins the GUARD chip, on purpose and with a written note (OR-1). So R-SEG-PREV.20/1 is partial and R-SEG-PREV.7/1 is blocked. The "holds on base: Yes" claim for R-SEG-PREV.7 in `01-requirements.md:102` is wrong.
- **Is it small and safe for the E5 corrective pass? Yes, under these conditions:**
  - The change is the same file and adds no fifth source file. Move the `if plan.conflicts:` block (7 lines) above `if plan.guard:`, and update the docstring order.
  - The returned `bool` (two-step confirm) is discarded by both callers (`:1811`, `:1840`: `state, _ = ...`), so the move changes nothing beyond the painted line. Arming stays in `action_export` (`:2075`), and that path already refuses on conflicts first.
  - The existing GUARD assertions use `_guard_case` (`tests/test_segment_split_window.py:247-265`). Its source sits only in the two end islands, with no byte in the gap, so it has no conflicts and its GUARD chip is unchanged.
  - Owed with the fix:
    - an orchestrator ruling that adds `_state_text` to `E1-slice.md` §1 and to the graph;
    - a direct node with exact strings: a plan with guard + conflicts must paint the clobber line, and a plan with guard only must paint the GUARD chip;
    - flip the R-SEG-PREV.20/1 state-line assertion to `⚠ {fmtB(conflicts)} would clobber source — abort on export` and close R-SEG-PREV.7/1;
    - a re-run of `tests/test_segment_split_window.py`, `tests/test_b97_key_bar.py` and the law guards on the LAN host.
  - Only the state-line half of D17-27 closes. The notice half (R-SEG-EXP.3) stays open.

### E5-CR-2 - the `_sweep` skip of empty, inverted and out-of-window marks has no direct node [impl (test), MINOR]
- **Where:** `s19_app/tui/segment_split_view.py:310` (`if cs >= ce: continue`). The tests are in `tests/test_b101_split_join_band.py:245-262`.
- **Scenario:** remove the skip, then pass an inverted mark `(3, 1, "data")`. Its end is processed at 1, before its start at 3, so `counts[cls] -= 1` raises `KeyError` (or, with a prior same-class mark, leaves a wrong count). The 5000-mark node draws only non-empty marks inside `[0, 1 000 000)`. The three hand examples of graph R-SEG-PREV.2/4 are not encoded (`_sweep(0, 4, [(-5, 1, "fill"), (3, 9, "conflict"), (2, 2, "data"), (3, 1, "data")])` → `[fill 1, none 2, conflict 1]`). The build_plan differential covers out-of-window marks. It is not shown to produce empty or inverted ones.
- **The equivalence itself holds** (argued below). The gap is only that this mutant would not turn a test red.
- **Fix:** add one node with the three graph examples (exact `Block` lists), compared to the expected lists and to `reference_sweep`.

### E5-CR-3 - the preview has no `crc_error` branch outside the refused and eval-error states [design-gap, NIT]
- **Where:** `s19_app/tui/crc_designer_view.py:1167-1210`.
- **Scenario:** suppose `evaluate_target` succeeds, is not refused, and then the other policy's `compute_target_crc` raises `ValueError`. Then `_format_hex(None, …)` raises `TypeError` in the preview. This is unreachable today: the only `ValueError` on that path is the width check of `crc_lut`, and the evaluation raises it first (`eval_error`). The graph's invariant ("crc_error, invalid, size_cap all None ⇒ both CRCs are ints") holds, and the code matches the graph.
- **Fix (optional):** test `run.crc_error` before the three lines (`Cannot preview: <reason>`). No action is needed for this increment.

### E5-CR-4 - the AST check strips a snapshot bound to any name [impl (test), NIT]
- **Where:** `tests/test_b101_designer_recompute.py:846-855` (`_is_snapshot`).
- **Scenario:** an inserted `expected = designer_recomputes()` that rebinds a name a later assertion reads would be stripped, and the check would not see it. The tester used only `recomputes_before` (`E4-tester-notes.md`), so nothing is hidden today.
- **Fix:** require `node.targets[0].id == "recomputes_before"`.

### E5-CR-5 - the coverage is computed before the other surfaces update [impl, NIT]
- **Where:** `s19_app/tui/crc_designer_view.py:1370`.
- **What changed:** `run = self._compute_coverage(algo)` now runs before the verdict, custom-vector, JSON and warnings updates. On base, an unexpected exception from the coverage left only the two coverage surfaces stale. Now it would leave all six stale.
- **Why it is only a NIT:** no reachable exception is known (`ValueError` and `KeyError` are caught), and the graph's wording allows this order.
- **Fix (optional):** move the line just before `coverage.update(...)`.

## Check 1 - code against the graph (all match; evidence state `approved` by reading)

| Item | Graph / ruling | Code |
|---|---|---|
| Timer lifecycle | `_schedule_recompute`: stop the pending timer, then `set_timer(CRC_RECOMPUTE_S, self._recompute)`, constant read at schedule time | `crc_designer_view.py:738-761`, exact |
| `_pending_recompute = None` first (SEC-8) | first statement of `_recompute`, then stop, then clear the dirty flag | `:1340-1343`, exact |
| `prevent` during fills | preset fill and the three template fills inside `prevent(Input.Changed, Switch.Changed)`, then one `_recompute()` | `:653-654`, `:1538-1542`, exact |
| Watcher + dirty-while-hidden (A-6) | `watch(app, "current_file", _on_image_changed, init=False)`; on screen → schedule, else set the flag; `on_show` schedules only when dirty | `:677`, `:679-702`, `:704-724`, exact |
| Cap + exact text (round 2) | `16 * 1024 * 1024`, read per call; size = range sum + forward gaps in written order (equals `gather_target`'s fill window, `crc_designer_model.py:206-210`); `>`; `Cannot preview: coverage exceeds <cap> bytes` on both surfaces, window line 1 still drawn | `:136`, `:1121-1131`, `:1198-1199`, `:1281-1285`, exact. The graph's 64 MiB examples are superseded (SR-1, E4 item 4) |
| Shared run | evaluate once; active CRC taken from the evaluation; other policy computed; refused → both computed; one `try` | `:1132-1165`, exact; ≤ 2 `gather_target` calls in every state |
| Line-1 scale (SEC-1, N-4) | `max(end) - min(start)`, no per-run cap | `:1260-1262`, exact |
| `crc_lut` | `bytes(memoryview(data)).translate(_REFLECT8)` once when `refin` | `crc_kernel.py:255-256`, table at `:78`, exact |
| `_conflict_marks` | `bytes(map(mem_map.get, range, repeat(pad)))` + `re.compile(b"[^" + re.escape(bytes([pad])) + b"]+")`, no flags, merge when touching, docstring precondition stated | `segment_split_view.py:374-393`, exact |
| `_sweep` | count per class over sorted cuts, skip empty marks | `:304-338`, exact |

## Check 2 - correctness scenarios (evidence state `approved` by reading)

- **Template load with a timer pending (text edit or image change):** `_apply_template` calls `_recompute()`, and its first statements stop and clear the timer. That recompute reads the live form and `app.current_file`. No stale result is possible: every recompute is argument-less and reads live state (SEC-4). The worst a missed stop could cause is an extra, identical recompute.
- **Image swap with a text-edit timer pending:** `_on_image_changed` reschedules, so one recompute runs over the new image. Hidden → the flag is set; a timer that was already pending still fires, computes over the current image and clears the flag. Correct either way.
- **Project load that assigns twice (`None`, then the image):** both assignments land inside one quiet time, so there is one recompute over the final image.
- **Dropdown with an on-display timer pending (tester ambiguity 3 / integrator item 5):** confirmed by the code. `on_select_changed` → `_recompute` → `:1340-1342` stops the pending timer.
- **`_sweep` equivalence with the reference:** on the reference, an empty or inverted mark can only satisfy `s < b and e > a` if both of its clamped ends lie strictly inside `(a, b)`. But those ends are cuts, so they cannot. Such marks cover nothing on base, and skipping them is exact. A mark that reaches past the window is clamped, which gives the same interval coverage as the base predicate on cut-aligned intervals. Ends are processed before starts at each cut, and `cs < ce` guarantees that a mark's start comes before its end. With ≤ 4 classes alive, taking the maximum priority over the live classes equals the base scan.
- **`_conflict_marks` equivalence with the reference:** an absent address reads as the pad, so "absent" and "equal to pad" are both non-conflict, which is the base predicate. `finditer` runs are maximal inside a window. Touching runs across windows merge with the same `marks[-1][1] == a` test the base applied per address, and window order is unchanged. `re.escape` covers `\ ] ^ -`, and NUL and bytes ≥ 0x80 are literal in a bytes class. The 256-pad node pins this. A value outside 0..255 raises (fail loud, documented). That is a deliberate narrowing from base (SEC-6).
- **`crc_lut`:** the output is identical for `bytes`, `bytearray` and `memoryview`. A list of ints with `refin` set now raises `TypeError`, but no caller passes one (I-7).

## Check 3 - tests (evidence state `executed` on the LAN host, from the transcripts)

- **Exact and able to fail:**
  - the matrix asserts the full preview text, window lines 2 onward and the glyph presence for the 24 states plus the hostile state;
  - the cap node asserts the exact text, 48 glyphs, no line 3 and 0 window reads, with the boundary pinned at 23 and 24;
  - line 1 is pinned exactly at 15, 24, 49 and 51 glyphs;
  - counts are pinned exactly (+1, and 0 while hidden);
  - the band nodes compare to the verbatim base reference. I diffed `tests/support/b101_inc13_reference.py` against `b7b77c4:segment_split_view.py:288-351`: identical apart from the two names.
- **The AST check guards the 12 nodes and more:** it compares every top-level base statement of `tests/test_crc_designer_view.py` with `ast.dump`, after stripping only the snapshot and wait shapes and the three allowed module additions. A deleted or renamed test, a changed constant and an extra statement are each named. Its control node proves all four cases. `int-ast-r1.txt` shows PASSED, not skipped (N-5). Narrowing: E5-CR-4.
- **The `split("\n")[1:2]` fix is not weaker:** with two or more lines it is the same comparison as `[1] == …`. On the one-line pending state it yields `[]`, so the wait keeps polling instead of aborting with `IndexError`. The case still passes only when line 2 equals the exact CRC.

## Owed (not this reviewer's lane; recorded as `not-run`)

- Mutants M-1..M-25 on the implemented tree, and the 5/5 QC-TM runs of the four timing cases (integrator item 2).
- The one-off `test_tc_b97_69_page_keys_do_nothing_where_disabled` timeout under `-n 12` (integrator item 3). By reading, the watcher costs only an `is_on_screen` check and a flag or a timer inside the assignment. That makes a link unlikely but does not exclude it, so the node needs a re-run in the full battery.

## Evidence checklist

- ✓ Diff read in full: `crc_designer_view.py` (+390/-110), `crc_kernel.py` (+17), `segment_split_view.py` (+70); all test files surveyed, and the designer test file read at `:1-160` and `:430-1019`.
- ✓ Correctness pass (None, empty and error paths): E5-CR-3, E5-CR-5; the scenarios above.
- ✓ Simplicity pass: no premature abstraction; `_CoverageRun` is a local only.
- ✓ Reuse checked: the debounce mirrors `screens.SAVE_RECOMPUTE_S`; the model functions are reused unchanged.
- ✓ Tests reviewed for intent: E5-CR-2, E5-CR-4.
- ✓ Verdict explicit: PASS-WITH-NOTES, no HIGH or BLOCKER open; E5-CR-1 is MAJOR and recommended for the corrective pass.

## Re-review (2026-11-06)

Scope: E5-CR-1 as fixed by ruling C-1, the CR-3 to CR-5 fixes (C-8), and any new product defect. Read-only: `git diff a086fa5..3e01603 -- s19_app tests` (head `3e01603`), `E5-rulings.md`, `E5-corrective-notes.md`, transcripts `e5c-c1-red`, `e5c-c1-green`, `e5c-mut-NC-SEG-PREV-7`, `e5c-cr3-red`, `e5c-cr3-green-and-ats`, `e5c-lane1`, `e5c-serial-r1..r5`. Nothing was run on the review PC.

### Verdict

**PASS.** E5-CR-1 is closed: the fix is applied and verified on the diff. No new defect was found in product code. Two LOW notes below; neither blocks.

### E5-CR-1 (C-1): `approved` by reading, `executed` on the LAN host

- **Order matches canon .7 / .8 exactly.** `segment_split_view.py:1776-1788`: `if plan.conflicts:` returns the clobber line before `if plan.guard:` is tested. So the GUARD chip shows only with a guard and no conflict byte (R-SEG-PREV.8), and the clobber line shows whenever a conflict byte exists (R-SEG-PREV.7). The empty-file and ready branches are unchanged and still come after.
- **Texts, styles and the flag are unchanged.** The block was moved verbatim. The conflict branch still returns `False` and the guard branch `True`.
- **Both callers.** `_stats_text` compact (`:1814`) and wide (`:1843`) both read `state, _ = ...`, so the flag is still discarded. The painted line is the only change, on both layouts. The line now agrees with `action_export`, which refuses on conflicts (`:2064`) before the arming gate (`:2078`).
- **Guard alone still shows the chip.** Node `test_r_seg_prev_7_8_state_line_priority_conflict_over_guard` arm (b) asserts `(guard, conflicts) == (True, 0)` and the exact `⚠ GUARD  <fmtB(span)> span — e will ask`. The existing `_guard_case` tests in `test_segment_split_window.py` (no gap bytes) stay GREEN in `e5c-c1-green` (108 passed: band file, `test_segment_split_window.py`, `test_b97_key_bar.py`).
- **The RED fails for the right reason.** `e5c-c1-red` (fingerprint start = end): both new nodes fail on the state-line equality alone, with the shipped GUARD chip in place of the expected clobber line (`⚠ 2.77 MiB would clobber source …` vs `⚠ GUARD  9.20 MiB span — e will ask`; `⚠ 4 B …` vs `⚠ GUARD  1.00 MiB span …`). The stats line and the plan-field asserts before it passed. So the failure is the branch order, not a scene or setup fault. The hand-examples node in the same run passed, as expected.
- **The new nodes pin the canon line.** The F-23 node asserts `guard is True` and `plan.conflicts ==` the engine detector's count, then the exact `⚠ {fmtB(conflicts)} would clobber source — abort on export`. The priority node pins both arms with exact strings. The R-SEG-PREV.20/1 flip (`test_b101_inc13_perf.py:287-290`) replaces the GUARD chip with the same canon line and drops the OR-1 hold. It ran 5/5 in `e5c-serial-r1..r5` at fingerprint `e7d6e2ef3b63a343`, which equals the final lane's.
- **The R-SEG-PREV.7 control is real.** `e5c-mut-NC-SEG-PREV-7` (census counted per block, not per byte) killed the F-23 node, the priority node and TC-710.

### C-8: CR-3, CR-4, CR-5

- **CR-3 (`crc_designer_view.py:1209-1210`).** The only behaviour change is one state: evaluation not refused, other-policy CRC faulted. Before, it raised `TypeError` inside `_recompute`. Now the preview reads `Cannot preview: <reason>`. Every other state renders as before: `eval_error` returns earlier, and a refused run still shows the refusal notice because that branch comes first. Node `test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named` pins both surfaces with exact strings. Its RED is the `TypeError` (`e5c-cr3-red`), and its GREEN is in `e5c-cr3-green-and-ats`. The node builds the run directly. That is acceptable, because no form reaches the state today (E5-CR-3). **No uncovered behaviour change.**
- **CR-4 (test only).** `_is_snapshot` now also requires `targets[0].id == "recomputes_before"`. This is as recommended, and `e5c-mut-NC-CR4` killed it.
- **CR-5 (`:1373-1377`).** `_compute_coverage` now runs after the four non-coverage updates, as recommended. The surfaces do not read `run`, so nothing observable changes on any reachable path. The one behaviour change is that an unexpected exception from the coverage would now leave only the two coverage surfaces stale. No exception is known to be reachable, so no test is owed (`n/a — unreachable`).
- **No other product change.** The diff touches only `segment_split_view.py` (`_state_text` and its docstring) and `crc_designer_view.py` (CR-3, CR-5).

### Notes (LOW, not blocking)

- **RR-1 (pre-existing, unreachable).** In a refused run that also has `crc_error`, the preview checks `refused` first (refusal notice) but the window checks `crc_error` first (`Cannot compute`), so the two surfaces would disagree. No form reaches this state: the width `ValueError` is raised by the evaluation first. Record it only; no action.
- **RR-2 (records, outside this scope).** `docs/requirements/review/S17-ears-strict.md:279` ("Partly: a guard file hides it") and `CODE-CHANGES.md` D17-27 still describe the old order. The corrective notes route this to the requirements session. The notice half of D17-27 (R-SEG-EXP.3) stays open, as E5-CR-1 said.

### Evidence checklist

- ✓ Diff read in full (`s19_app` 2 files, +23/-14; tests at the C-1, CR-3, CR-4 and R-SEG-PREV.20/1 sites).
- ✓ Correctness pass: branch order, flag, both callers, export path; CR-3 state table.
- ✓ Simplicity: a pure move plus one guard clause; nothing added.
- ✓ Reuse: n/a, nothing new.
- ✓ Tests for intent: exact canon strings, a negative arm for the guard alone, a RED on the old order, and a killed control.
- ✓ Verdict explicit: PASS. No HIGH or MAJOR is open, and E5-CR-1 is applied and verified.
