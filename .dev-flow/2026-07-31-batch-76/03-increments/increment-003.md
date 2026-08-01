# Inc-3 — `HLR-110`: an internal failure is attributed to the tool (review packet)

**BLUF.** `generate_project_report` sat **inside** a `try` whose `except ValueError` surfaces
`"Report rejected: …"` — the operator-input rejection path. Any `ValueError` escaping the generator,
for any internal reason, therefore told the operator that **they** had typed something invalid.
Generation now sits outside that span, and the tool-failure branch is a single shared helper.
**8 nodes, 5 counterfactual mutations, INERT: none.**

---

## 1 · What changed

| Clause | Implementation |
|---|---|
| `LLR-110.1` | the `try` is split: the first guards the **operator-input span** (execution + `ReportOptions` construction) with `except ValueError` → *rejected*; generation runs after it, under `except Exception` → *failed* |
| `LLR-110.2` | the tool-failure branch is one local `report_failed(exc)` helper, invoked by **both** handlers |
| `LLR-110.3` | both branches `return` before any report path is surfaced (P-12) |

**Re-routed by CALL SITE, not by cause** — non-claim (g). A `ValueError` is not intrinsically an
operator error, so no analysis of the exception could have made this decision; only its position
could. `TC-570` therefore asserts a *structural* property and is honestly labelled a snapshot of
where the call sits, not a proof about causes.

### The increment ordering was load-bearing, and this is where it paid

Before Inc-2 there was a natural `Length`-driven `ValueError` to trigger this with. `_format_length`
removed it. So Inc-3 must **inject** its fault — which makes `AT-260` a **general** attribution
property ("a `ValueError` from the generator is the tool's fault") instead of one welded to the D2
bug that happened to expose it. **Inverting the order would have produced a weaker acceptance that
passed for an accidental reason.** The injected exception is deliberately a `ValueError` — the same
type the rejection branch legitimately catches; a `RuntimeError` fixture already takes the
tool-failure arm on the base tree and would prove nothing.

---

## 2 · Files modified

| File | Change |
|---|---|
| `s19_app/tui/app.py` | `try` split · `report_failed` local helper · both handlers routed to it |
| `tests/test_tui_report_attribution.py` | **NEW** — 8 nodes: `AT-260…AT-263` · `TC-570…TC-572` · `TC-578` |
| `tests/test_id_registry.py` | `EXPECTED_SCANNED_TEST_FILES` 151 → 152, same PR as its guard requires |
| `.dev-flow/2026-07-31-batch-76/03-increments/increment-003.md` | this packet |

**2 deliverable files.** Frozen set untouched.

---

## 3 · How to test

```bash
python -m pytest tests/test_tui_report_attribution.py -q
```

---

## 4 · Test results

**8 passed.** With Inc-1 + Inc-2 + the id guard: **67 passed**. The pre-existing TUI report suites
(`test_report_logging`, `test_report_progress`, `test_report_off_ui_thread`, `test_tui_report_seam`)
ran **42 passed** against the changed `app.py` — no regression on the surfaces that already observe
this worker.

### 4.1 Counterfactual matrix — executed, restored, hash-verified (`0c878df8…5062`)

| # | Substituted expression | Gates | RED? |
|---|---|---|---|
| M1a | generation's handler surfaces `Report rejected:` (the pre-fix observable) | AT-260 | ✅ |
| M1b | generation's `except Exception` → `except ValueError` (re-enters the span) | TC-570 | ✅ |
| M2 | `f"Report rejected: {exc}"` → `f"Report failed: {exc}"` | AT-261 | ✅ |
| M3 | the shared helper inlined at one site (the two branches can drift) | TC-572 | ✅ |
| M4 | the progress reset dropped from the helper | AT-263 | ✅ |

### 4.2 The harness failed again, in a new way — and it is the same lesson

Inc-2 recorded that an **ambiguous** anchor fails open. Inc-3 produced two more mis-specified
mutants, both reporting **INERT** for reasons that had nothing to do with the predicates:

| # | What the mutant actually did | Why it read as INERT |
|---|---|---|
| M1 (first attempt) | inserted the generation call **after a `return`** — dead code | the program was unchanged in behaviour, so nothing could redden |
| M2 (first attempt) | changed the **log** message while `AT-261` asserts the **status** | the mutation and the assertion were about different observables |

**The generalisation, now three instances deep:** *a mutation must be shown to change the thing the
predicate reads, not merely to change the file.* `applied = True` only proves bytes moved. All three
failures — Inc-2's ambiguous anchor, and these two — were caught by re-reading the mutant against
the node's declared subject, never by a test. This is a genuine gap in how C-40 is discharged in
practice and it is routed to Lane B in §7.

---

## 5 · Risks

| # | Risk | Disposition |
|---|---|---|
| r-1 | The rejection span still covers `execute_project_variants`, so a `ValueError` from execution is still reported as a rejection. | **Deliberate and unchanged.** P-11 scopes operator-input `ValueError` to `ReportOptions.__post_init__` + the scope guard; this batch moved only what it was chartered to move. Narrowing the span further is a separate requirement, not a silent widening of this one. |
| r-2 | `TC-570`/`TC-572` are static censuses over `app.py`'s source text. | Both carry positive controls or exact counts; `TC-578` plants a nesting and proves the walk can see it. |
| r-3 | `AT-262`/`AT-263` are **PINs** — green on the base tree. | Labelled as PINs, not counted as discriminating coverage. `AT-262` was initially folded as an assertion inside `AT-260`; that is *coverage in parts* and C-18 forbids it, so it now owns a distinct node. |
| r-4 | The scaffold passes `last=` to skip `execute_project_variants`. | It skips the *fresh-run* path only; the worker under test runs in full, through `run_test()`, on a real app. |

---

## 6 · Pending items

- **`REQUIREMENTS.md`, the TC-610 amendment, and the `RESERVED`→`LIVE` flip remain OWED**, in that
  order — the guard still blocks the other two. This is now the **only** unfinished increment work.
- Reported as found, not fixed (Inc-2): pre-existing `ruff F821` at `s19_app/tui/app.py:5682`,
  verified against a pristine `origin/main` copy. → `BACKLOG-CODE.md`.
- Backlog reconciliation and the `R-TUI-101` wording carve-outs.

---

## 7 · Suggested next task

**Land the owed half**: amend `TC-610` → update `REQUIREMENTS.md` → flip the spent ids to `LIVE`.

**Lane B control candidate, now three-instance evidenced — *a counterfactual must be shown to move
the predicate's declared subject, not merely to modify the file*.** C-40 already requires confirming
"the mutation actually applied", and all three of this batch's harness failures **satisfied that
check** while proving nothing: an ambiguous anchor hit the wrong function, a mutant landed after a
`return`, and a mutant changed the log while the node read the status. Proposed discharge, all
mechanical: (1) the anchor must match **exactly once**; (2) the mutated region must be **reachable**
(not dead code); (3) the mutated expression must name an observable the node actually reads.
