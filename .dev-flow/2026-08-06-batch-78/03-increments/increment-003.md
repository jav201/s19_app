# Increment 003 — LLR-122.4, report completeness through the written file

> **Scope:** §7 Inc-3 · HLR-122 / LLR-122.4 · one node, one file, no production change
> **Nodes:** `AT-B78-31`
> **Gate:** C-34 (full `tests/test_tui_directionb.py`) + the increment's own file; the declared mutation executed and pasted
> Branch `claude/batch-78-cmdbar-a2bdiff` · base `aaa382d` · artifact language: English.

---

## BLUF

**`AT-B78-31` exists, it is green on the shipped tree, and it reddens on its own
completeness assertion when the report is routed off the panel's capped view.
No production change was needed. The spec's declared mutation, executed
literally, does not compile — and that is the increment's finding.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **§4's `LLR-122.4` names a mutation that cannot be applied: `generate_diff_report()` has no `runs` parameter.** Substituting `runs=panel._runs` into the report `kwargs` raises `TypeError: generate_diff_report() got an unexpected keyword argument 'runs'`, which the worker's own `except Exception` swallows into a status line. The node reddens — **but in the driver, on "no file was written", not on its assertion.** By the project's own control (*a counterfactual must fail on its ASSERTION*) that is not a discharge. Executed transcript in §4.3, mutation **A**. | ❌ **spec defect — found only by executing it** |
| **F-2** | **§5.3's wording of the same mutation IS executable and is the one that discharges the node.** Row `AT-B78-31` says *"route the report off `panel._runs`"* — a **semantic** instruction, not a kwarg. Expressed type-preservingly (`dataclasses.replace(result, runs=[DiffRun(*t) for t in panel._runs])` ahead of the worker call) the report writes normally and holds **128 of 200** runs; the node reddens on `the written Markdown report must list EVERY run`, first missing start `0x00000800` = `2048` = `128 × 16`. **Exactly `LLR-122.4`'s declared threshold, "200 run entries against 128 painted".** | ✅ **discharged, mutation B** |
| **F-3** | **`P-50` reproduced. The report path needed no production change.** `on_ab_diff_panel_report_requested` reads `self._diff_last_result` and passes it whole; `panel._runs` never enters the report kwargs. The written files hold all 200 runs on the shipped tree, first run to last, in order. | ✅ **PIN, green today, as specified** |
| **F-4** | **The node observes TWO written files, and the second clause is independently live.** `LLR-004.3` (Markdown) and `LLR-004.7` (HTML) both promise a COMPLETE document, and the handler feeds both from the same `result`. A mutation capping **only** `generate_diff_report_html`'s input leaves the Markdown clause green and reddens the HTML clause on its own message (mutation **C**). Without that arm the HTML assertion would have been an unverified extra. | ✅ **both clauses are gates** |
| **F-5** | **`Button.press()` + `workers.wait_for_complete()` is `C-78-xii` one layer out, and it is already on disk in `TC-024`.** `press()` only *posts* `Pressed`; the handler that starts the `@work(thread=True)` worker has not run, so the worker set is **empty** and the wait returns instantly. `TC-024`'s two nodes pass only because their generators are monkeypatched to be instant. Inc-3 does not reuse that shape — it waits on the status the worker marshals back **after both files are closed**. Recorded as a carry, not fixed here (it would touch nodes Inc-3 does not own). | ⚠️ **carry `C-78-xiv`** |

---

## 1. What changed

**One new acceptance node and its driver. Zero production edits.**

`AT-B78-31` is the only observer of `LLR-122.4` in the suite. G-9's caps
(`DISPLAY_MAX_RUNS = 128`, `DISPLAY_MAX_TOTAL_BYTES = 2_097_152`) bound the
**panel**; Inc-2 hardened that side with `AT-B78-18` and the rewritten
`test_tc029`. The **report** side had no observer at all, so the single shortest
edit that would break it — feeding the generators the panel's stored runs — was
invisible to the entire 2 625-node suite.

**C-12, output-then-consume, is what makes this a control rather than a
citation.** `P-50` establishes report completeness by reading two lines of
`app.py`. A node that asserted the same thing by inspecting `_diff_last_result`,
or by counting `len(result.runs)`, would be a consumer-contract guard on the
same in-memory object the requirement is about — it could not distinguish
"the report is complete" from "the object we intended to pass is complete". The
node therefore:

1. drives a real comparison through the shipped **Compare** button (Inc-2's
   `_b78_drive_compare` + `_b78_press_compare`),
2. types a destination into the shipped `#diff_report_dest` input and presses
   the shipped **Report** button,
3. lets the **real** `generate_diff_report` / `generate_diff_report_html` run —
   neither is monkeypatched,
4. **re-reads both written files from disk** and parses the run tables out of
   them,
5. compares the parsed start addresses against **the fixture's own run list**,
   authored by the test before the app ever saw it.

Nothing in the expectation comes from `panel._runs`, from the generators, or
from `DISPLAY_MAX_RUNS`.

### The one node

| Node | Kind | Clause | Reddened by |
|---|---|---|---|
| `test_at_b78_31_written_report_is_complete_under_display_caps` | **PIN → discharged as a GATE-shaped predicate** | (a) the written **Markdown** run table lists every fixture run, in order · (b) the written **HTML** run table does too · (c) the panel painted **strictly fewer** in the same run · (d) the fixture exceeds the cap | (a) ← mutation **B** · (b) ← mutation **C** |

### Three deliberate choices

1. **The oracle is a start-address LIST, not a count.** `== expected_starts`
   fails with *which* run went missing (`first missing start address: 2048`),
   and it also catches reordering and de-duplication, which a count cannot. The
   fixture's addresses are `i * 16`, so the first missing address under a cap is
   `cap × 16` — the transcript reads `2048` and that number is itself evidence
   the drop was the display cap and not something else.
2. **The run table is parsed inside its own section.** Both documents dump hex
   windows further down, and those rows also carry `0x`-prefixed addresses. The
   parser slices `## Runs` → next `## ` (Markdown) and `<h2>Runs</h2>` →
   `</table>` (HTML) first. A whole-document regex would have counted rows that
   are not run entries and the count would have been wrong in the *safe*
   direction — larger, i.e. still passing under the mutation.
3. **The constant-quoting guard is asserted LAST.** Inc-2's `F-1`: a guard
   placed ahead of the substantive clauses reddens first and the subject never
   runs. `assert total > AbDiffPanel.DISPLAY_MAX_RUNS` is the final line of the
   node.

### The completion wait (`C-78-xii` / `C-78-xiii`)

`_b78_press_report` is a **new** driver, not a third copy of an existing one.
The carry `F9` forbids duplicating `_b78_press_compare` / `_press_compare`; this
waits on a different signal for a different handler and shares nothing with
them but the discipline.

**Why not `await app.workers.wait_for_complete()`.** `Button.press()` posts a
`Pressed` message and returns. `on_ab_diff_panel_report_requested` has not run,
so `@work(thread=True)` has not been reached, so the worker set is **empty** and
`wait_for_complete()` returns immediately. This is exactly `C-78-xii`'s shape
one layer out: Inc-2 found the queue idle while a coroutine was suspended; here
the *worker set* is empty while the message that creates the worker is still
queued.

**What it waits on instead.** `_start_diff_report_worker` writes the panel
status through `call_from_thread`, and `call_from_thread` blocks the worker
until the callback has executed on the UI thread. Reaching
`"Diff report written:"` therefore *happens-after* both files are written and
closed — which is precisely the precondition a re-read needs.

**The wait is TOTAL.** All four failure surfaces of that handler
(`Report refused:`, `HTML report refused:`, `Diff report failed:`,
`No comparison yet`) are named and raise loudly with the status text. A node
built on this driver cannot proceed on a missing or stale file, and cannot time
its budget out and then fail on a confusing `FileNotFoundError`.

**`C-78-xiii` is honoured in the driver, not in a sibling clause.** The
lost-race state here is *no file at all*, in which a completeness predicate
written as an absence clause would pass vacuously. The positive co-assertion
lives in `_b78_press_report`, so nodes not yet written inherit it.

---

## 2. Files modified

| File | Change | Lines |
|---|---|---|
| `tests/test_tui_diff_screen.py` | new Inc-3 section: 2 module constants, 4 helpers (`_b78_press_report`, `_b78_section`, `_b78_md_report_run_starts`, `_b78_html_report_run_starts`), 1 test node | +199 / −0 |

**1 file. §7 planned 1. No production file was touched** — `git diff --stat --
s19_app/ tests/` reports `tests/test_tui_diff_screen.py | 199 ++++`, one file,
199 insertions, zero deletions.

**Nothing else in the tree was touched.** A parallel session is writing
`prototypes/memmap2.*` in this checkout; those files are untracked and were not
staged, read into, or modified. No `git add -A` was run.

**C-26 reverse-grep, whole tree.** Every symbol this increment mints —
`_B78_REPORT_OK`, `_B78_REPORT_FAILED`, `_b78_press_report`, `_b78_section`,
`_b78_md_report_run_starts`, `_b78_html_report_run_starts`,
`test_at_b78_31_...` — resolves **only** inside
`tests/test_tui_diff_screen.py` (one `.pyc` byproduct aside). No consumer
anywhere else, no collision with an existing name.

---

## 3. How to test

```bash
cd C:/Users/jjgh8/Github/s19_app

# the increment's own node
python -m pytest tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps -v

# the C-34 gate: the increment's file + the full guard host, ONE run, FULL form
python -m pytest tests/test_tui_diff_screen.py tests/test_tui_directionb.py -q

# the expected drift - DO NOT regenerate locally (C9; Inc-12 owns regen)
python -m pytest tests/test_tui_snapshot.py -q

# the declared mutation, applied-checked and sha-restored
python <scratchpad>/mutate_inc3.py
```

The mutation harness is a throwaway in the session scratchpad, not committed;
its three substitutions and their transcripts are reproduced verbatim in §4.3.

---

## 4. Test results

### 4.1 The increment's own node

```
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps PASSED [100%]
============================== 1 passed in 1.48s ==============================
```

### 4.2 C-34 gate — ONE run, FULL form

```
$ python -m pytest tests/test_tui_diff_screen.py tests/test_tui_directionb.py -q --no-header
........................................................................ [ 34%]
........................................................................ [ 69%]
...............................................................          [100%]
207 passed in 265.07s (0:04:25)
```

**Form stated:** FULL (no `-m "not slow"` filter). 207 passed, 0 failed,
0 skipped, 0 errors — read from this single run's own output (C-19).

### 4.3 Counterfactuals — three mutations, each applied-checked, each sha-restored

Discipline: the anchor matches **exactly once**; the post-image is asserted
**absent before** and **present after** the write (`C-78-viii` as amended);
the mutated sha is compared against the fixed tree's **and against every
previous mutation of this run**; restore is verified by the sha returning to its
pre-mutation value. All three targeted `s19_app/tui/app.py`.

```
############ BASELINE (fixed tree, sha 21e3ad53c3c687b9) ############
  VERDICT: GREEN
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps PASSED [100%]
============================== 1 passed in 1.45s ==============================

############ MUTATION A  runs=panel._runs INTO THE REPORT KWARGS (spec LLR-122.4, literal) ############
  anchor matches      : 1
  post-image absent-before/present-after : True/True
  sha fixed -> mutated: 21e3ad53c3c687b9 -> d4bf542c5d095621  moved=True
  VERDICT: RED
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps FAILED [100%]
            for arm in _B78_REPORT_FAILED:
E                   AssertionError: the report worker took a FAILURE arm, so no complete file exists to observe; #diff_status reads "Diff report failed: TypeError: generate_diff_report() got an unexpected keyword argument 'runs'"
FAILED tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps
============================== 1 failed in 1.68s ==============================
############ A ... REVERTED - sha MATCH=True ############

############ MUTATION B  route the report off panel._runs (spec Sec.5.3, type-preserving) ############
  anchor matches      : 1
  post-image absent-before/present-after : True/True
  sha fixed -> mutated: 21e3ad53c3c687b9 -> 268bdc55f7a3fad9  moved=True
  vs previous mutation A: d4bf542c5d095621  distinct=True
  VERDICT: RED
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps FAILED [100%]
E       AssertionError: the written Markdown report must list EVERY run of the comparison, in order; it lists 128 of 200. First missing start address: 2048
E       assert [0, 16, 32, 48, 64, 80, ...] == [0, 16, 32, 48, 64, 80, ...]
E         Right contains 72 more items, first extra item: 2048
FAILED tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps
============================== 1 failed in 1.68s ==============================
############ B ... REVERTED - sha MATCH=True ############

############ MUTATION C  cap ONLY the HTML generator's input (html clause liveness) ############
  anchor matches      : 1
  post-image absent-before/present-after : True/True
  sha fixed -> mutated: 21e3ad53c3c687b9 -> c61d5739a0ef2783  moved=True
  vs previous mutation A: d4bf542c5d095621  distinct=True
  vs previous mutation B: 268bdc55f7a3fad9  distinct=True
  VERDICT: RED
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps FAILED [100%]
E       AssertionError: the written HTML report must list EVERY run of the comparison, in order; it lists 128 of 200. First missing start address: 2048
E       assert [0, 16, 32, 48, 64, 80, ...] == [0, 16, 32, 48, 64, 80, ...]
E         Right contains 72 more items, first extra item: 2048
FAILED tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps
############ C ... REVERTED - sha MATCH=True ############

############ FINAL sha 21e3ad53c3c687b9 == baseline 21e3ad53c3c687b9: True ############
```

**The exact substitutions, recorded as VALUES (the `record-the-substituted-value`
control), not as "drop the X":**

| Mut | Anchor (exactly 1 match in `s19_app/tui/app.py`) | Substituted value |
|---|---|---|
| **A** | the `kwargs = dict(...)` tail `a2l_records=a2l_tags,` / `mac_records=mac_records,` / `)` | the same tail **plus** `runs=panel._runs,` |
| **B** | `        self._start_diff_report_worker(panel, result, kwargs, diff_source)` | the same line, preceded by `result = dataclasses.replace(result, runs=[DiffRun(s, e, k) for (s, e, k) in panel._runs])` |
| **C** | `            html = generate_diff_report_html(result, **kwargs)` | the same call with its first argument replaced by `dataclasses.replace(result, runs=[DiffRun(s, e, k) for (s, e, k) in panel._runs])` |

**Restore proof.** `git status --short` after the run lists exactly one modified
file, `tests/test_tui_diff_screen.py`, and `git diff --stat -- s19_app/ tests/`
shows `1 file changed, 199 insertions(+)`. `s19_app/tui/app.py` is byte-identical
to the baseline, verified by sha, not by `git status` alone.

**Verdict on A.** RED, but **not a discharge**. It reddens in the driver's
failure arm — no file was ever written — so the node's own assertion never ran.
A mutation that prevents the subject from executing certifies the driver, not
the predicate. `LLR-122.4`'s wording is corrected by execution; §5.3's wording
stands.

### 4.4 Snapshot drift — recorded, NOT regenerated

```
$ python -m pytest tests/test_tui_snapshot.py -q --no-header
1 snapshot failed. 28 snapshots passed.
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
1 failed, 31 passed, 1 warning in 70.07s (0:01:10)
```

**The single `[diff-comfortable-120x30]` cell, and only that cell** — the same
drift Inc-1/Inc-2 introduced and Inc-12 owns. Inc-3 is test-only, so this is the
expected no-change result: **no second cell moved**. Regen is CI-only (C9);
nothing was regenerated locally.

### 4.5 Ledger

| Point | Passed | Notes |
|---|---|---|
| Baseline | 2607 | / 2 / 3 |
| Inc-0 | 2608 | |
| Inc-1 | 2612 | |
| Inc-2 | 2625 | honestly 2624 + the one drifted snapshot cell |
| **Inc-3** | **2626** | `post = 2625 − D + A` with **D = 0, A = 1** |

**Honest form: 2625 passing + the one drifted `[diff-comfortable-120x30]` cell**,
which stays red locally until Inc-12's CI regen.

**Corroborated, not merely arithmetic.** `pytest --collect-only -q` reports
**2631 tests collected**, and `2626 + 2 + 3 = 2631` reconciles exactly against
the baseline's `/2/3` non-passing tail. The full 26-minute suite was **not** run
(C-19 guidance for this increment); the 2626 figure is the arithmetic
projection, corroborated by the collection count, and is labelled as such.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | **The node runs the REAL report generators over 200 runs.** It is the only node in the diff suite that does. Runtime measured at **1.48 s** end to end, so it is not `slow`-marked — but it is the node that would notice a report-service performance regression, and it would notice it as a 750-turn timeout with a confusing message rather than as a timing failure. | low | Accepted. The timeout message names the status text, so the cause would be visible. |
| **R-2** | **The Markdown parser depends on the run table's column format** (`\| 0x%08X \| 0x%08X \|`). A cosmetic change to `_run_table_lines` would redden this node with a `0 of 200` message that reads like a completeness failure. | medium | Deliberate: the node is an acceptance on the written artifact, so a format change to that artifact **should** stop it. The failure message prints `len(md_starts)`, and `0` vs `128` distinguishes "format moved" from "runs were capped". |
| **R-3** | **The 750-turn / 20 ms budget in `_b78_press_report` is a wall-clock bound (~15 s) on a thread whose work is real I/O.** On a heavily loaded CI box it could in principle exhaust. | low | Measured margin is ~10×. The failure is a named `AssertionError`, never a silent green. |
| **R-4** | **`TC-024`'s two report nodes still use the `press()` + `wait_for_complete()` shape F-5 identifies as unsound.** They pass only because their generators are monkeypatched instant. They were not touched — they are not Inc-3's nodes and changing them would exceed the increment's scope. | medium | Carried as `C-78-xiv` (§6b). Not a live defect today; a latent one the moment anyone makes those generators non-instant. |
| **R-5** | **A parallel session is writing `prototypes/memmap2.*` in this checkout.** | low | Nothing outside `tests/test_tui_diff_screen.py` was read into, staged or modified; no `git add -A`. Verified by `git status --short`. |

---

## 6. Pending items

1. **The increment is NOT committed.** The working tree carries
   `tests/test_tui_diff_screen.py` modified and nothing else. Committing was not
   requested and is not done without asking. **Owed: a go/no-go on the commit.**
2. **`LLR-122.4`'s mutation wording is wrong on disk** (F-1). `01-requirements.md`
   is off-limits to this increment, so the correction lives here and in the
   carry list. §5.3's row for `AT-B78-31` is already correct and needs nothing.
3. **The snapshot cell stays red locally** until Inc-12 regenerates in canonical
   CI. Unchanged by this increment.

## 6b. Batch carry list (additions)

| Carry | Statement | Due |
|---|---|---|
| **🆕 `C-78-xiv`** | **`Button.press()` followed by `workers.wait_for_complete()` is not a completion wait.** `press()` posts a message; the handler that *creates* the worker has not run, so the worker set is empty and the wait returns at once. It is `C-78-xii` one layer out — Inc-2 found the message **queue** idle while a coroutine was suspended; this is the **worker set** empty while the message that starts the worker is still queued. Wait on a signal the worker itself emits after its effect is complete, and make every failure arm a named raise. **Two nodes on disk (`test_tc024_report_trigger_surfaces_paths`, `test_tc024_report_trigger_invalid_dest_refused`) carry the unsound shape and are green only because their generators are monkeypatched instant.** | batch close |
| **🆕 `C-78-xv`** | **A declared mutation must be stated as a value substitution that TYPE-CHECKS, or it is a wish rather than a control.** `LLR-122.4`'s `runs=panel._runs` into the report kwargs raises `TypeError` at the call boundary, is swallowed by the handler's `except Exception`, and reddens the node in its driver instead of on its assertion. Two sections of the same document worded the same mutation differently and only one was executable. **The requirement author must execute the mutation they declare, not only name it.** | batch close |
| **`F9`** *(carried forward, unchanged)* | `_b78_press_compare`/`_press_compare` and `_b78_run_list_text`/`_run_list_text` remain duplicated near-copies. Inc-3 added no third copy: `_b78_press_report` waits on a different signal for a different handler. | batch close |

---

## 7. Suggested next task

**§7 Inc-4 — HLR-123: the windows follow the selection, and the row count
derives from the pane height.** `AT-B78-20…22`, files
`s19_app/tui/screens_directionb.py` + `tests/test_tui_diff_screen.py` (2). Its
gate is `AT-B78-21`'s strict inequality green at **132×44 vs 132×60** and
`AT-B78-22` reddening **on its assertion** under the implementation mutation
`high = end + ctx → high = end` — note the spec already records that the
*constant* mutation raises in the guard and never reaches the assertion (NEW-3),
which is the same family as this increment's F-1.

---

## Evidence checklist

- [x] **Tests / type checks / lint pass.** C-34 gate: `207 passed in 265.07s`,
      FULL form, one run (§4.2). The increment's own node: `1 passed in 1.48s`
      (§4.1). Snapshot: the single known `[diff-comfortable-120x30]` drift and
      no other (§4.4).
- [x] **No secrets in code or output.** The node writes two report files into
      `tmp_path`; no credential, token, env file or host path outside `tmp_path`
      appears in any transcript.
- [x] **No destructive commands run without approval.** No `git stash`, no
      `git add -A`, no reset, no force. The three mutations were applied to a
      tracked file and **restored by sha** in the same process
      (`FINAL sha 21e3ad53c3c687b9 == baseline: True`, §4.3).
- [x] **File count within cap.** 1 file modified, §7 planned 1, cap 5.
      `git diff --stat` = `1 file changed, 199 insertions(+)`.
- [x] **Review packet attached.** This document, §§1–7.
