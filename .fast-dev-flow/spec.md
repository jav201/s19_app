# Quick Spec — s19_app · batch-84 · classifying the bare-name address arguments

- **Branch:** `claude/blind-spot-assembled-selector-c2c117` (base = `origin/main` `1afccb0`)
- **Flow:** `/fast-dev-flow` · supervised, no self-merge · artifact language English
- **Flow revision (C-45 PULL):** `2026.08.15-rev33` · `flow_hash d851576cfe8f60b3` · 24/24 tabled
  files agree · all 3 declared checkouts clean and `0/0` against `origin`, refs refreshed at the
  cut with `--fetch`. Verified, not assumed.
- **Entry document:** `.dev-flow/design/BLIND-SPOT-assembled-selector.md` (batch-83 handoff). Its
  §0 figures were re-executed at this cut and all reproduce; see §6 below.
- **Predecessor spec:** batch-83, CLOSED, archived to
  `.fast-dev-flow/archive/2026-08-15-batch-83-address-census-spec.md`.

> **Every number in this spec is reproducible by a command named next to it.** Where a figure came
> from a throwaway probe rather than a committed artifact, it is labelled **provisional** and the
> batch's job is to replace it with a derived one. Nothing here is copied from a prior document —
> that is the failure mode this project has found seven times.

---

## 1. Objective

Classify each of the 41 bare-name address arguments by **where its value comes from**, so the P2
assembled-selector blind spot is sized by a command instead of assumed, and the `56` computed
addresses can be quoted with a definition.

---

## 2. User stories

- As a **batch-82 planner**, I want the assembled selectors counted or proven absent, so that I
  size the Lane A retrofit from a number that is complete rather than a known lower bound.
- As a **batch reviewer**, I want each of the 41 sites to carry a classification with its evidence
  from a committed command, so that a new assembled selector is visible on the day it appears
  rather than at the next audit.

---

## 3. Acceptance criteria

Each criterion names its **kill mutation** — the change that must turn the guard red. A criterion
whose guard cannot be shown red is not accepted (batch-83 defect B4).

| id | Criterion | Kill mutation |
|---|---|---|
| `AT-B84-01` | When run over the tree, the resolver shall emit exactly one row per candidate, and the set of its site keys shall be **set-equal** to `bare_name_candidates()`'s | drop one site → set inequality (not a count) |
| `AT-B84-02` | Every emitted row shall carry non-empty evidence: the binding's `file:line` and its kind | blank the evidence field → red |
| `AT-B84-03` | Given a fixture holding all four outcomes, the resolver shall return `A`/`B`/`C`/`D` respectively | mutate the `B` branch → red |
| `AT-B84-04` | Given **escape 1** (`sel = f"{prefix}{name}"; query_one(sel)`) and **escape 2** (`sel = "#" + wid; query_one(sel)`), the resolver shall classify both as **`B`** | remove `BinOp` from the assembled set → red |
| `AT-B84-05` | Given a binding written in an **unrelated function of the same file**, the resolver shall still report it | make the walk scope-precise → red |
| `AT-B84-06` | Given a candidate with no in-file binding, the resolver shall emit it under its own outcome and never drop it | hide it → red |
| `AT-B84-07` | `address_origin.bare_name_candidates` shall be the **same object** as `address_census.bare_name_candidates` | reimplement the filter locally → red |

**Why `AT-B84-05` is a criterion and not an implementation detail.** The resolver over-collects: it
reports any binding of the name anywhere in the file, including in functions that never reach the
site. This is deliberate. The batch's expected headline is a **negative** result (`B` is empty), and
a negative result is only sound if the search was over-broad. A later "improvement" to scope-precise
resolution would silently weaken every `B = 0` claim derived from it, and nothing would fail. This
guard is what makes that trade visible.

**No guard asserts a count over the tree** (handoff §4.5). `AT-B84-01` asserts set equality against
a derived set, so it survives every legitimate change to the tree and still fails on a dropped site.

### Classification rule, fixed before the data is trusted

A name may carry several bindings. Tie-break, biased toward *finding* the blind spot rather than
toward a clean answer:

| Condition | Outcome |
|---|---|
| **any** binding is assembled (`JoinedStr`, `BinOp`, `.format()`, `%`) | **B** — the blind spot, confirmed |
| else, **any** binding is a function parameter | **C** — the caller decides |
| **all** bindings are `Constant[str]` | **A** — resolvable by grep |
| otherwise | **D** — sub-kind named individually, never lumped (handoff §3) |

---

## 4. Validation strategy

`tests/test_address_origin.py` carries `AT-B84-01`..`-07` in the PR lane (not `slow`). Criteria
`-03`..`-06` run against **synthetic fixtures** parsed in-memory, so they state a property of the
resolver rather than a property of today's tree. `-01`, `-02` and `-07` run against the real tree.
Every guard is shown red under its kill mutation before it is accepted, and the red output is
quoted in the increment's review packet — a guard accepted only green is a guard nobody tested.

Closing evidence: the gate suite green, plus the classification table re-derived by the committed
command and pasted into the close with the command that produced it.

---

## 5. Non-goals

- **batch-82's Lane A retrofit.** This batch produces the number that batch-82 sizes itself from.
- **Refactoring the 41 sites into a registry.** The operator's dictionary-plus-existence-check
  proposal is batch-82's and is better decided with this number in hand (handoff §5).
- **A fourth net keyed on selector shape.** Explicitly forbidden by handoff §4.1 — shape-keying is
  what left the hole. This resolver keys on origin.
- **The producer side and `.tcss`** — `id=f"log_line_{i}"`, `add_class`, stylesheet selectors.
  Registered P3, untouched.
- **Chains longer than one hop.** A `C`/`D` site whose value comes from a collection is classified
  by that fact; the collection's contents are not followed.

---

## 6. Premise table (C-43)

| Premise | Tier | Verdict | Executed evidence |
|---|---|---|---|
| The census reproduces at this cut | PREMISE | ✅ TRUE | `python tools/address_census.py` → `literal 1335 · name 183 · fstring 56`, 16 loose, 0 indirect |
| batch-83's guards are green | PREMISE | ✅ TRUE | `python -m pytest tests/test_address_census.py -q` → `23 passed in 18.28s` |
| The candidate population is 41 | PREMISE | ✅ TRUE | handoff §3 snippet → `TOTAL 41`; groups identical to §3 (`_B78_RUN_ENTRY` 12 · `selector` 8 · `target` 4 · `select_id` 3 · `row` 3 · `_B78_RUN_NOTE` 2 + 9 singletons) |
| `AT-B83-08` does **not** cover escape 2 | HYPOTHESIS (inherited from the handoff — written down ≠ verified) | ✅ TRUE | re-executed, not copied: `sel = "#" + wid; query_one(sel)` → `forms=['name'] loose=0 indirect=0`. Control `sel = f"#{x}"` → `loose=1 indirect=1`, so the probe discriminates and is not vacuous |
| Both escapes land as an argument of form `name` | PREMISE | ✅ TRUE | same run → `shapes=['sel']` for both escapes |
| `AT-B84-*` owes no registry reservation | PREMISE | ✅ TRUE | `.dev-flow/AT-TC-REGISTRY-SPEC.md` §2.3: batch-scoped ids are "**Outside** the allocation authority and outside the guard". `grep -rn "AT-B84-"` → one hit, the handoff's own §6 line |
| batch-83's spec is closed and safe to archive | PREMISE | ✅ TRUE | archived file §11 → `Current phase \| **CLOSED**` |
| The flow is current | PREMISE | ✅ TRUE | `devflow-validate.py --map --fetch` → `rev33` · `d851576cfe8f60b3` · 24/24 agree · 3 checkouts clean `0/0` |
| **Outcome `B` is empty at this cut** | HYPOTHESIS | ✅ **TRUE — decided at Inc-1** | `python tools/address_origin.py` → `A 14 · B 0 · C 14 · D 13 · U 0`. The provisional scratchpad figure recorded at Phase A said `C 12 · D 15`; **the committed tool disagreed, and the disagreement was chased rather than overwritten.** Cause: the probe did not walk `ast.Lambda`, so the two `row` sites at `tests/test_map_click_chain.py:183,204` — parameters of `lambda pilot, row: pilot.click(row)` — were misfiled as `D`. The committed tool is strictly more complete and `B` did not move. Guarded against regression by `AT-B84-06`'s lambda case |

---

## 7. Information Flow Contract — Part A (C-54)

```
SOURCE  the repository's .py files on disk (230 scanned)
  → N1  census()                  AddressSite records          owned by AT-B83-*
  → N2  bare_name_candidates()    the bare-name non-class-like subset   AT-B84-01, -07
  → N3  resolve_origins()         binding kinds + evidence per candidate  AT-B84-02, -05, -06
  → N4  classify()                A / B / C / D                AT-B84-03, -04
SINK    the printed classification, and the BACKLOG-CODE.md line that sizes the P2
```

Every node names the criterion that owns it; a node nobody owns is work nobody asked for.

⚠ **`230`, not the `229` this section said at Phase A.** The batch's own new test file moved the
count, and the spec was closed at Inc-2 without re-deriving it — the exact defect §4.6 of the entry
document names, committed in the one file that quotes the rule. Found by the Inc-3 review, corrected
before the batch reached history. Re-derive: `python tools/address_census.py`, first line.

**Escalation check (Part B trigger).** Does this change alter *how a consumer reaches* something —
a selector, an index, a channel, an offset — rather than what it carries? **No.** It adds a
read-only static analysis over the repository's own source and changes no address in `s19_app`.
Part B is not owed and the batch stays in `/fast-dev-flow`.

---

## 8. Detected security flags

- [ ] Auth / identity
- [ ] Secrets / config
- [ ] External integrations
- [ ] Sensitive data
- [ ] Destructive DB
- [x] ⚠ Input / attack surface — **lexical match only, declared not dropped**
- [ ] Network / exposure

**`security_required`:** `false`

The scan fires on `form`, which occurs throughout this spec as *"argument form"* — an AST node
category, not a UI form. The batch adds a read-only analyser over files already in the repository:
no input surface, no network call, no credential, no database, no new route. The flag is recorded
rather than suppressed so the next reader sees why it did not escalate.

---

## 9. Increments

| # | Content | Source files |
|---|---|---|
| Inc-1 | `bare_name_candidates()` added to `tools/address_census.py`; new `tools/address_origin.py`; new `tests/test_address_origin.py` (`AT-B84-01`..`-07`, each shown red under its mutation) | 2 |
| Inc-2 | Re-derive the classification from the committed command; reconcile `.dev-flow/BACKLOG-CODE.md` (both P2 items); repoint the two references to batch-83's `.fast-dev-flow/spec.md §9` at the archived path; close this spec | 0 |

Source-file count is **2**, under the ≤4 cap; no ⚠ owed.

**Known dangling state during Inc-1, fixed in Inc-2 (approved at the Phase A gate).** Archiving
batch-83's spec breaks two live pointers that cite `.fast-dev-flow/spec.md §9`: the handoff's §6
table and `.dev-flow/BACKLOG-CODE.md`'s P3 by-design-risks entry. Both are repointed in Inc-2 and
travel in the same commit, so no dangling reference reaches history.

---

## 10. Success criterion

Each of the 41 candidates carries a classification with its evidence, produced by a committed
command. The report either counts the confirmed assembled selectors alongside the 56 or states why
it cannot. **If `B` is confirmed empty, the P2 closes and the `56` becomes quotable with its
definition** — and `AT-B84-04` is what keeps that true tomorrow, because it fails on the day an
assembled selector enters the tree.

---

## 11. Batch status

| Field | Value |
|-------|-------|
| Current phase | **CLOSED** |
| Cut against | `origin/main` `1afccb0` |
| Started | 2026-08-16 |
| Closed | 2026-08-16 |
| Promoted to /dev-flow | no |
| Notes | Two increments, both gated by the operator. No scope drift, no promotion trigger fired |

---

## 12. Close

### What changed

`tools/address_origin.py` resolves each of the 41 bare-name address arguments to the bindings of
its name in its own file and classifies it `A`/`B`/`C`/`D`/`U`, printing the binding's `file:line`
on the row. `tools/address_census.py` gained `bare_name_candidates()`, which is now the single home
of the candidate predicate — the census's own class-like note is derived as its complement rather
than by a second filter. `tests/test_address_origin.py` carries `AT-B84-01`..`AT-B84-07`.

**The measurement, re-derived from the committed command at the close:**

```
A 14   every binding is a string literal      _B78_RUN_ENTRY x12, _B78_RUN_NOTE x2
B  0   ASSEMBLED -- the blind spot            none
C 14   a function or lambda parameter         selector x6, select_id x3, row x2, +3
D 13   something else, sub-kind named         target x4, selector x2, widget_id, +6
U  0   no binding in the file                 none
```

**No bare-name address argument in the tree is assembled.** The census's `56` is complete with
respect to this population. That bound is the claim; it is not a claim about the whole tree, and
the tool prints its own three exclusions rather than letting a reader assume otherwise.

### How it was tested

- `python -m pytest tests/test_address_origin.py -q` → **21 passed** (16 at Inc-1, +3 at Inc-3,
  +2 at Inc-4 after a second adversarial pass).
- **11 kill mutations applied and reverted, 11 red, none vacuous** — drop a candidate (`-01`), emit
  a binding with no location (`-02`), delete the `B` branch (`-03`), remove `concat` from
  `ASSEMBLED_KINDS` (`-04`), make the walk scope-precise (`-05`), stop walking `ast.Lambda`, fold
  `U` into `D`, **silently drop every `U` row from `resolve_origins`** and **ignore the augmented
  operator** (`-06`, `-04`), re-implement the filter locally (`-07`). Source restored byte-identical
  after every one.
- ⚠ **Two of those ten did not exist until Inc-3, and one of them was a real vacuity.**
  `AT-B84-06`'s "never drop it" half was asserted only against `classify`, so
  `return [r for r in rows if r.bindings]` in `resolve_origins` passed all sixteen guards — it
  dropped nothing, because the tree holds zero `U` rows today. A guard that holds only because
  today's tree is empty of the case it names is the defect class this project ranks first. Found by
  an adversarial review at Inc-3, reproduced independently before being accepted, now guarded by a
  synthetic-tree arm that goes red under exactly that mutation.
- ⚠ **A SECOND adversarial pass found the same defect class one arm over, and its proposed fix was
  itself wrong.** `AT-B84-07`'s census half promised to guard the `report()` complement rewrite
  while asserting only non-degeneracy; reverting that rewrite to a second local filter kept all 42
  guards green. The review proposed a printed-line assertion. **It was written, executed, and
  stayed green** — because the two expressions are the same set counted from opposite ends, so no
  assertion over any output can separate them. The invariant is structural, so the guard is: parse
  `address_census.py` and assert `resolves_to_class_like` is called from exactly
  `["bare_name_candidates"]`. That one goes red. **Recorded because "the reviewer said so" was not
  enough twice in a row** — running the proposed fix is what showed it did not work.
- ⚠ **The kill matrix itself was re-run PER ARM, and the first two attempts at that were wrong.**
  The original matrix derived one verdict per mutant **from the pytest exit code**, over a node set
  containing parametrized tests — which is precisely the defect `tools/mutation_harness.py`
  (batch-76, already on `main`) was built to eliminate: *an inert arm hides behind a sibling that
  failed*. `AT-B84-04`'s mutation printed `2 failed, 3 passed` and was recorded as RED without
  anyone asking which three stayed green. That harness is hard-wired to batch-76's own target, so
  it is not a drop-in here, but its principle is not optional. Re-running per arm then found two
  defects in the re-run itself: `-v` with `-q` suppressed every node line, so the baseline resolved
  **0** arms and the all-green assert compared `0 == 0` and passed — a vacuity detector, vacuous;
  and a whitespace-delimited node pattern silently dropped every **parametrized** arm, reporting a
  live mutation as INERT. Final matrix, with an `EXPECTED_ARMS` assert so an unparsed arm aborts:
  **44 baseline arms, 11 mutations, 11 RED, no inert arm** — and each mutation now names the arms
  it reddens.
- `python -m pytest tests/test_address_census.py -q` → **23 passed**; the census's printed output is
  unchanged, `NOTE on 'name': 142 of 183`.
- `python -m pytest -q` → **2730 passed / 2 skipped / 3 xfailed**, 29 snapshots, exit 0, 31:13,
  **run on the tree that is being merged**. The total moved three times as arms were added —
  2725 (Inc-1) → 2728 (Inc-3, +3) → 2730 (Inc-4, +2) — and each earlier figure was written into
  this file while it was true and had to be re-derived when it stopped being. An independent
  reviewer reproduced the 2728 stage exactly; the 2730 is this session's, on the final tree. Wall
  clock is machine noise, not a signal.
- `ruff check` → clean.
- Manual smoke: `python tools/address_origin.py`, output read end to end.

### Open risks / pending

All four are registered in `.dev-flow/BACKLOG-CODE.md` under the batch-84 close, each with a
reopening criterion; none blocks:

1. **(P2)** 27 of the 41 (`C` + `D`) remain unresolved at one hop. **This is batch-82's real
   sizing number**, not `56` and not `41`.
2. **(P3)** `str.join` / `.replace` are outside `ASSEMBLED_KINDS` — the approved rule named four
   forms and the code ships exactly those. No candidate binds to either today.
3. **(P3)** The negative result depends on the walk over-collecting; `AT-B84-05` is the only guard
   protecting it.
4. **(P3, found in passing, not this batch's)** `.fast-dev-flow/ADR-flow-builder-tracer.md:171`
   points at `.fast-dev-flow/spec.md` for batch-69's rationale, which batch-83 archived elsewhere.
   Reported as found, not folded into this diff.

### Security flags — handling

`security_required` was **false**. The single lexical match (`form`, as *"argument form"*) is
recorded in §8 rather than suppressed; nothing in this batch reads input, opens a route, or touches
a credential.

### Suggested commit message

```
batch-84 - the assembled selector, measured: 41 sites classified by origin, B is empty

tools/address_origin.py resolves each bare-name address argument to the bindings
of its name and classifies it A/B/C/D/U with its file:line evidence. Result over
the tree: A 14 - B 0 - C 14 - D 13 - U 0. No address argument is assembled, so
the census's 56 computed addresses is complete with respect to this population.

The escape is now positively detected, not declared absent: AT-B84-04 classifies
all four assembly forms as B on synthetic fixtures, so the guard fails the day
one enters the tree. AT-B84-05 pins the walk as deliberately scope-insensitive,
because the negative result is only sound if the search was too wide.

bare_name_candidates() gives the candidate predicate one home; the census's own
class-like note is derived as its complement. EXPECTED_SCANNED_TEST_FILES 154 ->
155, measured by two independent paths.

Closes two P2 items from the batch-83 close. Carries forward the 27 C+D sites
that remain unresolved at one hop - which is batch-82's sizing number.
```
