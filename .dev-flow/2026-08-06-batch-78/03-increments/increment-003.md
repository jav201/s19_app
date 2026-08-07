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

> ⚠️ **Amended by the addendum (LOW-3).** The two `git` readings above describe
> the tree **at the gate**, before the increment was committed. It is now
> `c88b0ad`, so `git status` is clean of it and `1 file changed, 199
> insertions(+)` is a historical reading, not a live one. The load-bearing half
> is unchanged and was re-executed against the amended driver: `app.py` returns
> to sha `21e3ad53c3c687b9` after every mutation (§A.4).

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

1. ~~**The increment is NOT committed.**~~ **CLOSED — committed as `c88b0ad`**
   by the coordinator at the Inc-3 gate. *(Amended by the addendum, LOW-3: this
   item and its "working tree carries one modified file" reading described the
   pre-commit tree and no longer hold.)*
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

---
---

# ADDENDUM — Inc-3 gate review fixes (F1/F2 MEDIUM, four LOW)

> **Verdict received:** Inc-3 PASSED — 0 HIGH · 2 MEDIUM · 4 LOW, committed as `c88b0ad`.
> **Both MEDIUMs are about the DRIVER, not the node.** The node's predicate, its three mutations and its ledger are unchanged and were re-executed against the amended driver.
> **Scope of this addendum:** `tests/test_tui_diff_screen.py` (1) + this document. No production file touched, then or now.

---

## A.1 BLUF — the review was right, and executing its fix found a second instance of the same defect one clause further down

**`_b78_press_report` waited on a LEVEL and I sold it as an inheritable
guarantee. Fixing that exposed that my own file-existence check had the
identical shape — and that the review's "no false green" mitigation does not
hold in the arrangement the defect actually occurs in.**

| # | Finding | Verdict |
|---|---|---|
| **A-1** | **The review's F1 is confirmed, and it is worse than MEDIUM-as-scoped in one arrangement.** The review judged the level wait non-HIGH because `len(written_md) == 1` catches it loudly (`md=[]`, `html=[]`). That holds for a **fresh** destination. In the arrangement the bug actually occurs in — a **second press into the same destination** — the destination already holds one md and one html, so the glob finds exactly one of each, **passes**, and hands back the FIRST press's file. Executed: press 2 returned in **1 ms** against 800 ms of generator work, `md1 == md2 == 20260807T013431Z-diff-report.md`, one file on disk. **Silent false green, not a loud catch.** | ❌ **confirmed, and the mitigation is narrower than stated** |
| **A-2** | **My file check was a LEVEL assertion too, and only the F1 fix could reveal it.** `assert len(written_md) == 1` encodes "the destination started empty". With the wait correctly edge-triggered, the second press wrote its own file and the assertion **fired on a correct press** (`md=[…013353Z…, …013354Z…]`). Both clauses are now armed on a pre-press snapshot. **The same defect, twice, ten lines apart — I fixed the one the review named and walked straight into the other.** | ❌ **my defect, found by executing the fix** |
| **A-3** | **F2 is confirmed as a fair charge and the census passes with a real control.** I discharged a newly minted completion wait with `call_from_thread` reasoning — F-1's own lesson turned on its author. Executed: 3 treatment arms (0 / 50 / 500 ms per generator) **all GREEN**, 3 control arms with the wait removed **all RED**. The 500 ms treatment arm takes **2.29 s** against the 0 ms arm's **1.25 s**, so the injected delay is demonstrably reaching the code the wait is about — the census is not green by not perturbing anything. | ✅ **discharged by execution** |
| **A-4** | **Design-choice-2's stated reason is empirically false, exactly as the review says.** Measured on a real 82 157-byte report with **non-empty** memory maps so the hex windows actually render: whole-document **200**, section-scoped **200**, in both documents. The `###` window headers do carry `0x` addresses, but nothing there can match a pattern anchored on line-initial `\| 0x` / `<tr><td>0x`. **The choice is kept; the reason is replaced with one that survives measurement.** | ⚠️ **reason corrected, choice unchanged** |
| **A-5** | **The three mutations reproduce unchanged on the amended driver.** A still reddens in the driver (now on the emitted message rather than the polled level), B on the Markdown clause, C on the HTML clause, all at `128 of 200`, first missing start `2048`. Same shas. **The driver rewrite did not weaken the discharge.** | ✅ **re-executed** |

---

## A.2 F1 — level vs edge, executed on both forms

**The scenario both arms run:** one comparison, **two sequential Report presses
into one destination directory**, both generators slowed to 400 ms each (so
800 ms of real work per press).

```
---- LEVEL form (c88b0ad) (generators sleep 400 ms EACH) ----
  press1_s      : 0.898
  press2_s      : 0.001            <- returned in 1 ms against 800 ms of work
  md1           : 20260807T013431Z-diff-report.md
  md2           : 20260807T013431Z-diff-report.md      <- THE SAME FILE
  md_on_disk    : ['20260807T013431Z-diff-report.md']
  md1_runs      : 200
  md2_runs      : 200              <- press 2 "verified" press 1's output

---- EDGE form (addendum) (generators sleep 400 ms EACH) ----
  press1_s      : 0.918
  press2_s      : 0.933            <- waited out its OWN generators
  md1           : 20260807T013433Z-diff-report.md
  md2           : 20260807T013434Z-diff-report.md      <- distinct
  md_on_disk    : ['20260807T013433Z-diff-report.md', '20260807T013434Z-diff-report.md']
  md1_runs      : 200
  md2_runs      : 200
```

**The correction to the review's severity reasoning.** The review reports the
level form failing loudly with `md=[]`, `html=[]` — true for a **fresh**
destination, where press 2 returns before press 2's files exist and the glob
finds nothing. But the destination is the natural place a second report lands,
and there it already holds press 1's pair: the glob finds `len == 1` of each,
**passes**, and returns press 1's path. The consumer then re-reads a **stale but
perfectly complete** file and goes green. `md2_runs: 200` in the transcript above
is that false green, printed. The severity call (MEDIUM, not HIGH) is still right
— nothing in this batch presses twice — but the reason has to be *"no node does
this yet"*, not *"the glob catches it"*.

### The fix

Armed on an **edge**: a strictly increasing count of status messages emitted
**after** an observer is installed, which happens after the comparison and
immediately before the press.

```python
emitted: list[str] = []
shipped_set_status = panel.set_status

def _observe(message, *args, **kwargs):
    emitted.append(str(message))
    return shipped_set_status(message, *args, **kwargs)

md_before = set(dest_dir.glob("*-diff-report.md"))       # A-2: the FILE check
html_before = set(dest_dir.glob("*-diff-report.html"))   #      is an edge too

panel.set_status = _observe
try:
    before = len(emitted)
    app.query_one("#diff_report_button").press()
    for _ in range(750):
        if len(emitted) > before:
            break
        await pilot.pause(0.02)
    else:
        raise AssertionError(...)      # names the STALE line it is still seeing
finally:
    del panel.set_status
```

**The observer substitutes nothing** — it appends and delegates, and the app
still writes its own `#diff_status`. `set_status` is the right signal because
`_start_diff_report_worker` marshals it through `call_from_thread`, which blocks
the worker until the callback has run on the UI thread; observing the message
therefore *happens-after* both files are written and closed.

**Why an edge is categorically better here, not just safer.** A line written by
an earlier press is not merely *unlikely* to satisfy this wait — it is
**unreachable** by it, because it was emitted before the observer existed. That
is a structural guarantee rather than a probabilistic one, which is the whole
difference the review is pointing at.

### The docstring now states what it holds, and no more

> *For each call, this driver either returns the two paths written by THAT
> call's worker, or raises. It holds per press and is re-armed on every call, so
> repeated presses against one panel are covered. It does NOT serialise
> concurrent presses: the group is `exclusive=True`, so a second press while the
> first worker runs cancels the first, and this driver would report the surviving
> worker's message. Nothing in this suite presses twice concurrently, and a
> caller that needs that must arm its own wait rather than assume this one covers
> it.*

The `exclusive=True` limitation is stated because it is real and I could not
discharge it — not as a hedge. The review's point stands and is the reason this
paragraph exists: **a driver whose promise exceeds its delivery is worse than
one that promises nothing, because the next author reads the promise.**

---

## A.3 F2 — the `C-78-xii` perturbation census, with its control arm

`C-78-xii` sets the bar: *a perturbation census at two delays an order of
magnitude apart, with a control arm.* Inc-3 minted a new completion wait and
discharged it by argument. Here it is executed. Both generators are wrapped with
a sleep at the app's import site and otherwise untouched, so every arm still
writes a real, complete report and the node's own 200-of-200 clauses are what go
green.

```
=== TREATMENT: the driver's wait INTACT (tests file sha 6b7da5a1671c9a54) ===
  generator delay    0 ms x2  ->  GREEN   1 passed in 1.25s
  generator delay   50 ms x2  ->  GREEN   1 passed in 1.40s
  generator delay  500 ms x2  ->  GREEN   1 passed in 2.29s

=== CONTROL: the driver's wait REMOVED ===
  substitution: 'for _ in range(750):'  ->  'for _ in range(0):'
  post-image absent-before/present-after : True/True
  sha fixed -> mutated: 6b7da5a1671c9a54 -> 1bdf4574073b64bb  moved=True
  generator delay    0 ms x2  ->  RED     1 failed in 1.43s   E  AssertionError: the report worker never completed: `panel.set_status` was not called once across 750 pumped turns after the Report pre…
  generator delay   50 ms x2  ->  RED     1 failed in 1.37s   E  AssertionError: the report worker never completed: …
  generator delay  500 ms x2  ->  RED     1 failed in 1.36s   E  AssertionError: the report worker never completed: …
=== CONTROL REVERTED - sha MATCH=True ===
```

**Delays are two orders of magnitude apart** (0 → 50 → 500 ms), exceeding the
control's "one order" floor.

**The census is not vacuously green.** The 500 ms arm runs in **2.29 s** against
the 0 ms arm's **1.25 s** — a ~1.0 s difference that is exactly the two injected
500 ms sleeps. The perturbation demonstrably reaches the code the wait is about,
so a green arm means the wait absorbed it rather than that nothing changed.

**The control arm is what makes the treatment arms mean anything.** With
`range(750) → range(0)` the driver has no wait at all and every arm goes RED on
the driver's own named message — including the **0 ms** arm, which proves the
node cannot pass without the wait even when the generators are as fast as they
ever get. Recorded as a **VALUE** substitution (`750 → 0`), not as "drop the
loop".

**The control's ordering was checked, not assumed.** It reddens on the driver's
timeout message, not on a downstream `FileNotFoundError` — i.e. the control fails
*at the wait*, which is the thing under test.

---

## A.4 The three original mutations, re-executed on the amended driver

The driver changed, so the discharge had to be re-run. All three reproduce, at
identical shas.

```
############ BASELINE (fixed tree, sha 21e3ad53c3c687b9) ############   GREEN   1 passed in 1.60s

############ MUTATION A  runs=panel._runs INTO THE REPORT KWARGS (spec LLR-122.4, literal) ############
  anchor matches: 1 | post-image absent-before/present-after: True/True
  sha 21e3ad53c3c687b9 -> d4bf542c5d095621  moved=True
  VERDICT: RED
E  AssertionError: the report worker took a FAILURE arm, so no complete file exists to observe;
   it emitted "Diff report failed: TypeError: generate_diff_report() got an unexpected keyword argument 'runs'"
############ A REVERTED - sha MATCH=True ############

############ MUTATION B  route the report off panel._runs (spec Sec.5.3, type-preserving) ############
  sha 21e3ad53c3c687b9 -> 268bdc55f7a3fad9  moved=True | vs A d4bf542c5d095621  distinct=True
  VERDICT: RED
E  AssertionError: the written Markdown report must list EVERY run of the comparison, in order;
   it lists 128 of 200. First missing start address: 2048
############ B REVERTED - sha MATCH=True ############

############ MUTATION C  cap ONLY the HTML generator's input (html clause liveness) ############
  sha 21e3ad53c3c687b9 -> c61d5739a0ef2783  moved=True | vs A distinct=True | vs B distinct=True
  VERDICT: RED
E  AssertionError: the written HTML report must list EVERY run of the comparison, in order;
   it lists 128 of 200. First missing start address: 2048
############ C REVERTED - sha MATCH=True ############

############ FINAL sha 21e3ad53c3c687b9 == baseline: True ############
```

**A's message changed shape and its verdict did not.** It now reads the emitted
message rather than the polled level, so the transcript names the `TypeError`
directly. It still reddens **in the driver**, so it is still **not a discharge** —
`LLR-122.4`'s literal wording remains uncorrected on disk (`C-78-xv`).

---

## A.5 The four LOWs — three landed, one carried

| LOW | Disposition | Evidence |
|---|---|---|
| **`_b78_section` raises a bare `ValueError` on a heading change; R-2's mitigation covers only row-format changes** | ✅ **LANDED** | `text.index` → `text.find` + a named assertion: *"the written report does not contain the section heading `## Runs`, so this node cannot locate the run table. The report layout has changed and this parser must be updated before its verdict means anything"*, printing the first 200 bytes of the document. R-2 is amended below to cover **both** failure modes. |
| **Design-choice-2's rationale is empirically false** | ✅ **LANDED (reason replaced, choice kept)** | Measured: 82 157-byte report, non-empty maps so the windows render, whole-document **200** == section-scoped **200** in both documents. The comment now states this as a measurement and gives the reason that survives it: the scoping **bounds what the node can be reading to the one table the requirement is about**, so a future layout growing a second address table cannot inflate the count into a false pass. Defence in depth, not a correction of a real over-count. **The vacuous-fixture trap was avoided deliberately** — an empty memory map would have made the two counts agree for the wrong reason, so the check used populated maps. |
| **§6.1/§4.3 describe an uncommitted tree that no longer exists** | ✅ **LANDED** | §4.3's restore proof and §6 item 1 are amended in place with dated notes pointing at `c88b0ad`; the load-bearing half (app.py returns to sha `21e3ad53c3c687b9`) is re-verified in §A.4 rather than merely re-asserted. |
| **`LLR-122.4`'s "128 painted" half is asserted nowhere green; §4 ↔ §5.1 rule 4 tension** | ⏭ **CARRIED, deliberately** | The node asserts `0 < painted < total`, which is the *property*; it does **not** assert the literal `128`, because §5.1 rule 4 forbids an acceptance from quoting a value it could read from the class under test — that is precisely the `AT-B78-18` / F-6 defect. So the node is right and `LLR-122.4`'s numeric threshold is unsatisfiable as literally worded. **This is a requirements-document reconciliation, not a test fix**, and `01-requirements.md` is off-limits here. Registered as a batch-close item below. |

---

## A.6 Files modified (addendum)

| File | Change | Lines |
|---|---|---|
| `tests/test_tui_diff_screen.py` | `_b78_press_report` re-armed on an edge (status observer + pre-press file snapshot) and its docstring rewritten to state the exact guarantee; `_b78_section` given a named failure and a measured rationale | +109 / −40 |
| `.dev-flow/2026-08-06-batch-78/03-increments/increment-003.md` | this addendum + two in-place amendments (§4.3 restore proof, §6 item 1) | — |

**2 files, cap 5. No production file touched.** `git diff --stat` reports
`tests/test_tui_diff_screen.py | 149 ++++--- , 1 file changed, 109 insertions(+),
40 deletions(-)`. Nothing outside these two paths was staged or modified; the
parallel session's `prototypes/memmap2.*` files are untouched; no `git add -A`,
no `git stash`.

**C-26 reverse-grep:** the addendum mints **no new module-level symbol**, so the
Inc-3 census stands — every `_b78_*` name this increment owns resolves only in
`tests/test_tui_diff_screen.py`.

---

## A.7 Test results (addendum)

### A.7.1 The node

```
tests/test_tui_diff_screen.py::test_at_b78_31_written_report_is_complete_under_display_caps PASSED [100%]
============================== 1 passed in 1.42s ==============================
```

### A.7.2 C-34 gate + the registry guard — ONE run, FULL form

```
$ python -m pytest tests/test_tui_diff_screen.py tests/test_tui_directionb.py tests/test_id_registry.py -q --no-header
........................................................................ [ 32%]
........................................................................ [ 65%]
........................................................................ [ 98%]
....                                                                     [100%]
220 passed in 276.49s (0:04:36)
```

**220 passed, 0 failed, 0 skipped**, FULL form, read from this single run's own
output (C-19). `test_id_registry.py` G1–G7 is folded into the same run at the
reviewer's prompting — **13 nodes, all green**, so `AT-B78-31` introduces no
registry drift for Inc-11.

### A.7.3 Snapshot — unchanged

```
1 failed, 31 passed, 1 warning in 68.62s (0:01:08)
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[diff-comfortable-120x30]
```

The same single known cell. **No second cell moved.** Regen stays CI-only (C9);
nothing regenerated locally.

### A.7.4 Ledger — unchanged

**2626 passed** (honestly 2625 + the one drifted snapshot cell). The addendum
adds and deletes **no** node: `D = 0, A = 0`. Corroborated unchanged —
`pytest --collect-only -q` still reports **2631 tests collected**, and
`2626 + 2 + 3 = 2631`.

---

## A.8 Risks (amended)

| # | Risk | Change |
|---|---|---|
| **R-2** *(amended)* | The parsers depend on the written documents' layout — **both** the section headings and the run-table column format. | **Widened per LOW-1.** A heading change now fails with a named assertion that says the layout moved and prints the document head; a row-format change still fails with `0 of 200`, distinguishable from a capped `128 of 200`. Both failure modes are now named rather than one being a bare `ValueError`. |
| **R-3** *(amended)* | The 750-turn / 20 ms budget is a wall-clock bound on real I/O. | **Now measured, not estimated.** §A.3: the node completes in 2.29 s with 1.0 s of injected delay, against a ~15 s budget — a ~6× margin at the 500 ms arm and ~12× at 0 ms. The failure remains a named `AssertionError`. |
| **🆕 R-6** | `_b78_press_report` does not serialise **concurrent** presses (`@work(exclusive=True, group="diff_report")` cancels the in-flight worker). | Stated in the docstring rather than mitigated. Nothing in the suite presses twice concurrently. A caller that needs it must arm its own wait. |
| **R-4** *(amended)* | `TC-024`'s two nodes still carry the `press()` + `wait_for_complete()` shape. | **Left in place, and the review agrees that is right** — they are *fragile, not false* (their assertions fail loudly under a lost race), out of §7's scope, and load-bearing for nothing this batch ships. `C-78-xiv` is sharpened below to name the **comment**, not only the call. |

---

## A.9 Carries (amended / added)

| Carry | Statement | Due |
|---|---|---|
| **`C-78-xiv`** *(amended per the coordinator)* | **`Button.press()` followed by `workers.wait_for_complete()` is not a completion wait** — `press()` only posts a message, so the worker that the handler creates does not exist yet and the wait returns on an empty set. Measured: worker set **0** right after `press()`; `wait_for_complete()` returning in **0.8 ms** against 1000 ms of generator sleep. ⚠️ **The load-bearing half of this carry is the FALSE COMMENT, not the call.** `tests/test_tui_diff_screen.py:458-461` reads *"the two generators now run on a worker thread, so the status is written after this handler returns. A bare `pause()` passed only because the fake generators are instant — a race this suite must not depend on."* It **names the race correctly and then asserts a remedy that is not there**. A wrong call is one reader away from being caught; a comment claiming the check was already done is what makes the next reader skip it. Both `TC-024` nodes carry it. | batch close |
| **`C-78-xv`** *(unchanged, reviewer recommends ENCODING)* | **A declared mutation must be stated as a value substitution that TYPE-CHECKS, or it is a wish rather than a control.** `LLR-122.4`'s `runs=panel._runs` into the report kwargs raises `TypeError` at the call boundary, is swallowed by the handler's `except Exception`, and reddens the node **in its driver** instead of on its assertion. Two sections of one document worded the same mutation differently and only §5.3's was executable. Independently reproduced by the reviewer at the same shas. | batch close |
| **🆕 `C-78-xvi`** | **A completion wait must be armed on an EDGE, and so must every clause that consumes its result.** A level ("the surface currently reads DONE") is satisfied by the *previous* operation's result, so the wait returns before its own work and hands back a stale-but-well-formed artifact — a silent false green, not a loud failure, whenever the output directory is reused. Inc-3 shipped this twice ten lines apart: the status poll **and** the `len(glob) == 1` file check, the second of which only became visible once the first was fixed. **Snapshot before the trigger; require a transition.** | batch close |
| **🆕 `C-78-xvii`** | **A newly minted completion wait owes the `C-78-xii` census on itself, including the control arm.** Inc-3 minted one and discharged it with `call_from_thread` reasoning — which is `C-78-xv`'s defect (*a wish rather than a control*) applied to a wait instead of a mutation. The census is cheap: three delays two orders of magnitude apart plus the wait removed. **The control arm is not optional** — without it, treatment arms cannot distinguish "the wait absorbed the perturbation" from "nothing was perturbed", and the wall-clock delta between arms is the evidence that the perturbation landed. | batch close |
| **🆕 batch-close reconciliation item** | **`LLR-122.4`'s numeric threshold ("the written file holds 200 run entries against 128 painted") is unsatisfiable as literally worded**, because §5.1 rule 4 forbids an acceptance from quoting a value readable from the class under test — the literal `128` is `DISPLAY_MAX_RUNS`. `AT-B78-31` asserts the property (`0 < painted < total`) and is correct to. **§4 and §5.1 must be reconciled at batch close**; no test change is owed. | batch close |
| **`F9`** *(carried forward, unchanged)* | `_b78_press_compare`/`_press_compare` and `_b78_run_list_text`/`_run_list_text` remain duplicated near-copies. The addendum added no copy. | batch close |

---

## A.10 Evidence checklist (addendum)

- [x] **Tests pass.** `220 passed in 276.49s` (C-34 + registry, one run, FULL
      form, §A.7.2); node `1 passed in 1.42s`; snapshot unchanged at the one
      known cell.
- [x] **The F1 fix is proven, not asserted.** Both driver forms executed against
      the same two-press scenario; level returns in 1 ms with a stale file, edge
      waits 933 ms and returns its own (§A.2).
- [x] **The F2 census is complete, control arm included.** 3 treatment GREEN /
      3 control RED, delays two orders of magnitude apart, perturbation
      demonstrated to land by a 1.0 s wall-clock delta (§A.3).
- [x] **The three mutations re-executed on the amended driver**, identical shas,
      identical verdicts; `app.py` restored to `21e3ad53c3c687b9` (§A.4).
- [x] **No secrets** in code or transcripts; all report output under `tmp_path`.
- [x] **No destructive commands.** No `git add -A`, no `git stash`, no reset, no
      force. Every mutation restored and sha-verified in-process.
- [x] **File count within cap.** 2 files (1 test + this document), cap 5, no
      production file.
