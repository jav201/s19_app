# batch-73 — `_first_intersecting_symbol` soundness (`/fast-dev-flow`)

- **Route:** `/fast-dev-flow` — Lane A (code). One production file, one new test file.
- **Branch:** `claude/batch-73-linkage-fix-0372a0`, cut off `origin/main` **`d81cb3d`**.
  **RC-1 PASS** — `HEAD == merge-base == origin/main` tip, tree clean.
- **Flow revision:** `2026.07.28-rev1` · `flow_hash 0127a2767ff11c8a` — re-derived, **current** (C-45 PULL).
- **Plan of record:** `.dev-flow/HANDOFF-2026-07-31.md` §"PLAN — batch-73". Treated as a
  **hypothesis** per its own §0.1; premises re-executed below.
- **Approval:** **autonomous + merge** — asked at THIS kickoff (`AskUserQuestion`, 2026-07-31),
  not inherited from the plan or the launch prompt. Merge is gated on CI green **and** an
  independent review returning no HIGH finding.
- **Ids:** `AT-220`..`AT-223`, `TC-521`..`TC-524`. Measured prior max `AT-219` / `TC-520`
  (`TC-1728` is the known legacy stray series, not the max — confirmed at
  `.dev-flow/2026-07-28-batch-65/PLAN.md:90`).
- **security_required:** **false** — see §7.

---

## 1. Objective

`_first_intersecting_symbol` (`s19_app/tui/changes/apply.py:470` @`d81cb3d`) resolves an address to
a linkage **symbol name** with a one-candidate bisect (`:513-518`). Over **overlapping** indexed
ranges it returns the wrong symbol, or "no linkage" for an address that plainly sits inside a named
region. **The linkage is displayed to the operator**, which is what makes this MAJOR.

Make the probe sound over overlapping ranges **without changing any answer it gives today over
disjoint ranges**.

---

## 2. Base correction — `origin/main` moved

The plan is stamped against `6524afd`. **`origin/main` is `d81cb3d`**: PR #168 (batch-72 sync) and
PR #169 (the handoff itself) both merged between authoring and execution.

```
git rev-parse origin/main   -> d81cb3d269aeb4f17ad7587db1c58028c427d07a
git diff --stat 6524afd..d81cb3d
  .dev-flow/BACKLOG-CODE.md | .dev-flow/BACKLOG-PROCESS.md
  .dev-flow/HANDOFF-2026-07-31.md | .dev-flow/state.json     (4 files, docs only)
```

**Zero source files changed**, so every `@6524afd` address still resolves — but each was
re-derived rather than copied (§3).

**Consequence for the plan's rule 5** (*"do not touch `state.json` while PR #168 is open"*):
#168 is **MERGED**, so that specific block is lifted. The live hazard is now **batch-74**, which
the plan pre-allocates to a parallel agent. `state.json` is re-read immediately before any write.

---

## 3. Premise table (C-43)

| Premise | Tier | Verdict | Executed evidence |
|---|---|---|---|
| **P-1** Base is `origin/main` = `6524afd` | Premise | ❌ **FALSE** | `git rev-parse origin/main` → `d81cb3d`. RC-1 re-run and passes on the newer base; delta is docs-only. |
| **P-2** Every `@6524afd` line number still resolves | Premise | ✅ TRUE | `_linkage_index:438`, `_first_intersecting_symbol:470`, bisect `:513-518`, docstring caveat `:491-496`, callers `apply.py:316/317` + `check.py:293/294`, import `check.py:46` — all re-derived at `d81cb3d`, all exact. |
| **P-3** The backlog names the wrong function | Hypothesis | ✅ TRUE | `BACKLOG-CODE.md:96` says *"`_linkage_index` carries its OWN copy of the one-candidate bisect"*. `_linkage_index` spans `:438-467` and contains **no bisect** — it sorts and delegates to `build_sorted_range_index`. The plan's correction is right. |
| **P-4** The `report_filter.py` fix pattern would lose the symbol | Hypothesis | ✅ TRUE | `_merge_ranges` coalesces to `(start, end)` pairs with no symbol channel; this probe returns a name. Not adopted. |
| **P-5** The counterexample reproduces | Premise | ✅ TRUE | executed: `[(4096,36864,'BIG_ARRAY'),(8192,8208,'INNER')]`, addr `0x5000` → `(False, None)`; ground truth `BIG_ARRAY`. |
| **P-6** `apply.py` is outside the engine-frozen set | Premise | ✅ TRUE | `tests/test_engine_unchanged.py:120-130` — `_ENGINE_PATHS` lists `core.py`, `hexfile.py`, `range_index.py`, `validation`, `tui/a2l.py`, `tui/mac.py`. `tui/changes/apply.py` is absent. |
| **P-7** No batch-73/74 name collision | Premise | ✅ TRUE | `git ls-remote --heads origin \| grep -E 'batch-7[34]'` → 0 hits; no `.dev-flow/*batch-7[34]*` directory. |
| **P-8** The local flow is current | Premise | ✅ TRUE | aggregate `sha256` over the 12 manifest files → `0127a2767ff11c8a` = `FLOW-VERSION 2026.07.28-rev1`. |
| **P-9** (plan §6, `[ASSUMED]`) **No committed golden with a `Linkage` column moves** | Hypothesis | ✅ **TRUE** | §4 — measured, not reasoned. **No STOP condition.** |
| **P-10** The index is consumed only by the probe | Premise | ✅ TRUE | `_linkage_index`'s output reaches `_classify_linkage` → `_first_intersecting_symbol` and nothing else (`apply.py:316-327`, `check.py:293-347`); repo-wide grep finds no other importer of either symbol. This is what makes §5's design possible. |
| **P-11** Overlaps are unreachable in practice ("informative-only" defence) | Hypothesis | ❌ **FALSE** | `examples/professional_validation/case_07_cross_reference_inconsistencies/firmware.mac:6-7` declares `ALIAS_1=80200010` and `ALIAS_2=80200010`. Two MAC point ranges at the same address **are** an overlap (`ends[0]=a+1 > starts[1]=a`). See §6. |

**Two premises came back FALSE (P-1, P-11) and both changed the batch** — P-1 moved the base,
P-11 added `AT-223`. Neither blocks.

---

## 4. §6 pre-flight — executed, CLEAN

The plan makes this load-bearing: *"If any golden changes, STOP and report it."*

Method: wrap the live probe so every call computes **both** its current answer and a linear-scan
ground truth, then drive the four `Linkage`-bearing goldens through it
(`tests/goldens/batch35/at054b-before-after-report.{md,html}`, `batch35/at055b-project-report.md`,
`batch64/addendum-below-bound.md`) via the seven test modules that consume them.

```
baseline first        : 134 passed in 229.73s          (goldens green before instrumenting)
instrumented run      : 134 passed, exit 0
probe calls           : 490
calls over an index that actually contains an overlap : 0
divergences from ground truth                         : 0
```

**Verdict: no golden moves. P-9 TRUE. Proceed.** The result is doubly established — the goldens
never build an overlapping index at all (0/490), and §5's design is separately measured
byte-identical to today's on disjoint input across 48 000 probes.

**Stored evidence is uncontaminated**, so this stays a code fix and does not escalate.

---

## 5. Design — D-1 = (a), implemented as a disjoint cover

**D-1 is settled: (a) fix the probe.** Inherited from the operator's 2026-07-31 ruling, not re-opened.

The plan §4 prescribes *prefix-max over `ends` carrying an argmax*. Measurement found an
alternative with **identical output and a third of the blast radius**, and the operator selected it:

| Option | Expected result | Consequences |
|---|---|---|
| ✅ **(B) Disjoint cover in `_linkage_index`** | Probe precondition **restored**, so the bisect at `:513-518` becomes sound as written | Touches **`apply.py` only**; `_linkage_index` keeps its 2-tuple signature so `check.py` needs no edit |
| ❌ (A) Prefix-max inside the probe | Same answers (measured) | Needs a 3rd return value from `_linkage_index` → signature change → drags in `check.py:293-294`; 3 files instead of 1 |

Viable only because of **P-10**: the index has exactly one consumer.

**Mechanism.** `_linkage_index` sweeps its start-sorted triples once and emits a disjoint cover,
each piece carrying the symbol of the **first-by-start** range covering it:

```
frontier = None
for (start, end, name) in ordered:          # already sorted by start, stable
    if end <= start: continue               # defensive; both sources guarantee end > start
    lo = start if frontier is None else max(start, frontier)
    if end > lo:
        emit (lo, end, name); frontier = end
```

The cover never grows the index (≤1 piece per input range) and is exactly the input when the
input is already disjoint — which is why AT-221 is a true no-op guarantee rather than a hope.

### D-2 — overlap tie-break = **first-by-start** (operator, 2026-07-31)

The plan's counterexample does **not** disambiguate this: only `BIG_ARRAY` covers `0x5000`. Nested
ranges and MAC aliases do. Chosen semantics: **the intersecting range with the smallest start wins;
ties break to declaration order.** This is what the function's own name (`_first_intersecting_symbol`)
and docstring (*"the first intersection"*) already promise, so the fix makes the code honest rather
than redefining it. The rejected alternative (innermost / most-specific) is a different feature and
is carried to the backlog, not smuggled in here.

### Measurement backing the design

```
counterexample      today=(False,None)   cover=(True,'BIG_ARRAY')   truth=(True,'BIG_ARRAY')
disjoint sweep      48 000 probes  ->  cover mismatches vs today = 0
overlapping sweep   48 000 probes  ->  today wrong = 12 123 (25.3%),  cover wrong = 0
```

---

## 6. P-11 — a behaviour change AT-221 cannot see

Duplicate MAC point addresses are overlaps, and they ship in the repo:

```
examples/professional_validation/case_07_cross_reference_inconsistencies/firmware.mac
  6: ALIAS_1=80200010
  7: ALIAS_2=80200010
```

`bisect_right(starts, a) - 1` lands on the **last** duplicate, so today the operator is shown
`ALIAS_2`. Under D-2 the answer becomes `ALIAS_1`. This is a **deliberate, disclosed** consequence
of fixing the probe — the current answer is an artifact of the bisect, not a decision anyone made.

`AT-221` runs over **disjoint** input by construction and therefore **cannot** observe this, so it
gets its own acceptance criterion, `AT-223`. This is the reason the criterion exists; it is not
padding.

---

## 7. Acceptance criteria — observable, each able to go RED

Every criterion states the mutation that reddens it, and every mutation is **executed** (§8).

| Id | Criterion (When … the system shall …) | Reddening mutation |
|---|---|---|
| **AT-220** | When the probe is given `[(4096,36864,'BIG_ARRAY'),(8192,8208,'INNER')]` and the span `[0x5000,0x5001)`, it shall return `(True, 'BIG_ARRAY')`. | Restore the pre-fix `_linkage_index` body (drop the cover sweep) → `(False, None)`. |
| **AT-221** | When the indexed ranges are **pairwise disjoint**, the probe's answer shall equal **both** the frozen pre-fix implementation's answer **and** the linear-scan ground truth, over a deterministic generated sweep. | Corrupt the cover so it coalesces adjacent-but-disjoint ranges (drop the `max(start, frontier)` clamp) → attribution shifts and the differential assert fails. |
| **AT-222** | AT-220 and AT-223's observations shall hold when driven through `check.py`'s public entry point, not `apply.py`'s — the probe is shared and a fix proven through one consumer is proven for half of them. | Same as AT-220; the assertion is on `check_change_document`'s emitted linkage symbol. |
| **AT-223** | When two MAC records declare the **same** address (`ALIAS_1`, `ALIAS_2`), the reported linkage symbol shall be the **first-declared** one. | Reverse the cover's tie-break to keep the last duplicate → returns `ALIAS_2`. |

**AT-221's differential oracle is not a tautology.** It embeds a clearly-labelled frozen copy of the
`@d81cb3d` algorithm and asserts *new == frozen == ground-truth* **on the disjoint domain only**,
where all three provably agree. It is the literal form of the plan's *"identical to today's"*, and a
broken cover reddens it.

### Counterfactual protocol (C-31 / C-40)

Run on a **copy of the fixed tree** in an isolated export — **never on `main`**, where an assertion
may fail for the wrong reason and prove nothing
(`feedback_counterfactual_must_fail_on_its_assertion`). Each mutation must fail on **its own
assertion line**, not with an error.

## 8. Security

`security_required: **false**`. Scanned the objective + criteria against the flow's pattern list:
no auth/identity, secrets, external integration, PII, destructive-DB, upload/escape or network term
applies. The change is a pure in-memory index transform over already-parsed artifacts, adds no
input surface, no I/O, and no new dependency. The one adjacent concern — the symbol is rendered
into reports — is **unchanged**: escaping stays where batch-62 put it, and this batch alters which
symbol is selected, never how it is emitted.

## 9. Out of scope

- **Innermost / most-specific attribution** (D-2's rejected arm) — carried to `BACKLOG-CODE.md`.
- `report_service.py` and its tests — **batch-74's** files. Not touched.
- The engine-frozen set, `range_index.py` included: the shared primitives keep their disjointness
  contract; the fix is caller-local, which is exactly why `range_index.py` needs no unfreeze.
