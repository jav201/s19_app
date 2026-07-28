# Phase-2 RE-GATE — QA lane — batch-64

> **Reviewing:** `.dev-flow/2026-07-28-batch-65/01-requirements.md` **revision 2** (2 620 lines),
> commit `b09ae9a` on `claude/batch-64-addendum-producer-bound`.
> **Against:** this lane's first gate, `02-review-qa.md` (B-1, M-1…M-4, m-1…m-4).
> **Independence:** every transcript below was executed by **this** lane in the pristine
> `git archive 082ada9` export at `…/scratchpad/exp64`, probes `qa3_b1.py`, `qa3_inc1verdicts.py`,
> `qa3_tc498.py`, `qa3_scope.py` (plus the retained `qa2_arms.py` arm library). **The worktree was
> not mutated.**
> **Scope:** (1) discharge of this lane's nine findings; (2) new-defect check on what revision 2
> **changed**. Items §12 of the first gate marked ✅ are **not** re-litigated.

---

## 0. Verdict

**The nine findings are 9/9 CLOSED. `FIX-H` was rebuilt and now goes RED — executed, §2.
Revision 2 is NOT yet ready for implementation: the fold planted four new majors, all of them in
§11 / §11.1 and in the two brand-new nodes' *instrumentation*, none of them in the requirement text.**

| | count |
|---|---|
| prior findings **CLOSED** | **9** (B-1, M-1, M-2, M-3, M-4, m-1, m-2, m-3, m-4) |
| prior findings partially closed | **0** |
| new findings | **4 major · 5 minor**, all confined to §11/§11.1, `TC-498`'s seam, and the S3 scope predicate |

The requirements themselves (§3 `R-TUI-098` / `HLR-103`, §4 `LLR-103.1…103.6`) are sound and I raise
nothing against them. What is not yet runnable is the **plan to run them**: §11.1 mislabels four nodes'
Inc-1 verdicts, `TC-498` has no seam that reads the quantity it asserts, the addendum-scope predicate is
open-ended at EOF on the ordinary report, and the Inc-1 nodes cannot import the constants they are
required to quote. All four are mechanical and none reopens a design question.

---

## 1. Discharge table — this lane's nine findings

| # | finding | ruling | evidence |
|---|---|---|---|
| **B-1** | `AT-197`'s `⊇` is a representation check; `FIX-H` GREEN on the whole acceptance set | **CLOSED** | §2 below — `FIX-H` **RED** on the repaired `AT-197` and **RED** on the new `AT-202`, executed. All three sub-folds landed: set equality (§4 `LLR-103.5`, §7 T-5), `FIX-H` a named RED arm (§7 T-5, §6.2), its own node `AT-202` (§5.1 row 12, §6.2, §11.1) |
| **M-1** | `TC-495`'s benign direction false-fails a correct implementation; provenance false | **CLOSED** | §4 `LLR-103.5` pastes the `md_safe` refutation grid verbatim, restates the invariant as *notice-rendering == hit-line-rendering byte for byte*, and **strikes** the "(qa §5.14)" attribution in writing (`:857-861`). Flagged `NOT EXECUTABLE PRE-FIX` in §6.2's ledger. *One observation, not a finding, at §4* |
| **M-2** | notice REGION attribution unasserted; `FIX-I` GREEN on everything | **CLOSED** | Given its **own** node `AT-203` (not bolted onto `AT-197`), `FIX-I` named as its RED arm, `R ≥ 2` fixture pinned. Re-executed this gate against the first-class node: `FIX-A` **GREEN**, `FIX-I` **RED**, `SHIP` **RED** — §3 |
| **M-3** | Layer labels swapped; `AT-195` duplicates `TC-488` | **CLOSED** | `AT-195` **retired in place** (§5.2), `TC-496 → AT-200` promoted (§5.1 row 15), `AT-196` added to §5.1 row 3, §6.1 states the layer rule and its one declared exception (`AT-194`). **The retirement-in-place is adequate — ruled at §5.** Grep executed: 24 `AT-195`/`TC-496` mentions in the document, **0 live bindings** — every one is a retirement or history row. *One correction to my own finding at §6* |
| **M-4** | `AT-198` binds three observables to one id (C-18) | **CLOSED** | Arm 3 split to `AT-201` with `FIX-G` as its RED arm and its own §7 T-5 threshold; arms 1–2 kept under `AT-198`, which is **exactly what I recommended** ("Keep arms 1–2 under `AT-198`"). Re-executed: `FIX-G` **RED** on `AT-201`, **GREEN** on `AT-202` — the two controls are genuinely independent. *One consequence at §7 NEW-9* |
| **m-1** | `TC-489`'s rationale only true at `R = 1` | **CLOSED** | The "restate" option taken (as the finding anticipated the alternative would be declined as expensive). §7 T-2 now carries *"Stealth-early-exit detection lives HERE, on the overlapping arm"*; §12 X-3 restates `TC-489` as a **geometry control only** and says *"do not strike; do not overrate"*; §5.2's retirement row moves the detection claim onto `TC-488` |
| **m-2** | §13 row 11 overclaimed; catalog honesty flag dropped | **CLOSED** | Row 11 qualified to *"whose subject exists on this tree"* with `TC-490`/`TC-492`/`TC-495` **named** rather than covered; new §6.2 pre-fix executability ledger; `LLR-103.6` carries its own executability flag. Row 11b added for the fixture-specificity of RED figures |
| **m-3** | golden diff indices 7/4/10 vs 3/5/10 | **CLOSED — and resolved correctly, not by picking one** | §7 T-4 now carries a two-lane index table (`FIX-B` @3/@7, `FIX-E` @5/@4, `FIX-G` @10/@10), labels the indices **illustrative**, records *"RED both"* per row, and states *"**No test asserts on a first-diff index**; Inc-1 re-derives them from the committed golden."* That is the right resolution: the *direction* is the invariant, the index is fixture-determined, and the document neither averages nor arbitrates |
| **m-4** | `TC-492` / `TC-497` have no runnable node | **CLOSED** | `TC-492` changed from `inspection` to `test (unit) + inspection` with a named node (`pytest -q tests/test_report_addendum_bound.py -k tc492` under `monkeypatch.setattr(report_service, "MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", 37)`). `TC-497` gains the explicit 7-string verbatim grep list in `R-TUI-098` and its judgement half is **flagged as a judgement with a named reviewer** |

**No partials.** Every fold was executed against, not read.

---

## 2. `B-1` — `FIX-H` REBUILT and RUN against the repaired `AT-197`

This is the item the re-gate exists for, so it was executed rather than inspected. `FIX-H` is the same
arm from the first gate: identical to `FIX-A` in every respect except that `{variants}` lists every
variant that **contributed** to the cut class rather than every variant whose hits were **dropped**
(`qa2_arms.py::FIX_H`, `_core(..., variants_from_all=True)`).

Both expected values are **derived from the fixture by the probe**, never hardcoded — which is what
§7 T-5's *"derived by the test from its fixture"* demands:

```
FIXTURE TRUTH at flood = K = 200 (derived, not hardcoded):
  contributed to change-file issue : {'v1': 200, 'v2': 1, 'v3': 1}
  ADMITTED                          : {'v1': 200}
  DROPPED                           : {'v2': 1, 'v3': 1}
  => AT-197 expected dropped count  : 2
  => AT-197 expected variant SET    : ['v2', 'v3']
  => AT-202 fully-admitted variants : ['v1']

=== AT-197  REVISION 2 (set EQUALITY) - flood = K ===
  SHIP    RED    notices=[]
  FIX-A   GREEN  notices=[('change-file issue', 2, ['v2', 'v3'])]
  FIX-A2  RED    notices=[]
  FIX-B   GREEN  notices=[('change-file issue', 2, ['v2', 'v3'])]
  FIX-E   GREEN  notices=[('change-file issue', 2, ['v2', 'v3'])]
  FIX-G   GREEN  notices=[('change-file issue', 2, ['v2', 'v3'])]
  FIX-H   RED    notices=[('change-file issue', 2, ['v1', 'v2', 'v3'])]     <-- WAS GREEN

=== AT-197  REVISION 1 (superset, the retired form) - flood = K ===
  FIX-H   GREEN  notices=[('change-file issue', 2, ['v1', 'v2', 'v3'])]     <-- the blocker

=== AT-202  (NEW: no fully-admitted variant is named) - flood = K ===
  SHIP    RED    named=[]              must-not-contain=['v1']  no notice at all
  FIX-A   GREEN  named=['v2', 'v3']    must-not-contain=['v1']
  FIX-A2  RED    named=[]              must-not-contain=['v1']  no notice at all
  FIX-G   GREEN  named=['v2', 'v3']    must-not-contain=['v1']
  FIX-H   RED    named=['v1','v2','v3'] must-not-contain=['v1']

=== AT-201 (class-axis control) on the SAME fixture ===
  FIX-G   RED    named_classes=['change-file issue', 'modification']
  FIX-H   GREEN  named_classes=['change-file issue']
```

**Ruling: B-1 CLOSED.**

1. The **identity** predicate goes RED on `FIX-H` where the superset predicate went GREEN. The mutation
   reaches the predicate; the change is load-bearing, not cosmetic.
2. `AT-202`'s threshold holds **from both directions**: `FIX-A` GREEN (the correct implementation is not
   false-failed), `FIX-H` RED (the over-naming mutant is caught).
3. The spec's own claim that `AT-202` needs its **own** node is executed-true: **`FIX-G` is GREEN on
   `AT-202`** and **`FIX-H` is GREEN on `AT-201`**. Neither control substitutes for the other. This is
   the P-6 gap the first gate found one level down, and it is now closed at both levels.
4. `AT-197` is now **strictly stronger** than its catalog ancestor, not merely restored: the catalog had
   a boundary bullet; revision 2 has an identity predicate, a named RED arm, and a first-class node.

---

## 3. The five new nodes — each given the same scrutiny as an acceptance

| node | can it go RED? | does the mutation reach the predicate? | threshold from both directions? | verdict |
|---|---|---|---|---|
| **`AT-202`** variant control | **yes** — `FIX-H` RED, executed §2 | yes — the arm differs only in the variant list, and only this node sees it | yes — `FIX-A` GREEN, `FIX-H` RED, `FIX-G` GREEN (control is necessary) | ✅ **sound** |
| **`AT-203`** region control | **yes** — `FIX-I` RED, executed below | yes — `FIX-I` differs only in filing, and only this node sees it | yes — `FIX-A` GREEN / `FIX-I` RED / `SHIP` RED | ✅ **sound**, with one authoring trap — **NEW-7** |
| **`AT-200`** notice reaches the file | yes at Inc-1 (no notice exists) | — | RED→GREEN across the increment boundary | ⚠️ its *stated rationale and RED arm are executed-false* — **NEW-6** |
| **`TC-499`** scope positive control | yes | yes — fires `:1134` with 0 addendum notices, executed below | pre-conditions hold on a real report | ✅ **sound**, but depends on the scope predicate — **NEW-3** |
| **`TC-498`** region-ops counter | **only with an instrument the spec does not name; both available seams invert its verdicts** | **no** | no | ❌ **NEW-2** |

### `AT-203`, re-executed as a first-class node

```
=== AT-203: notice under the FLOODED region ONLY ===
    fixture: Bquiet declared FIRST (no hits), Aflood second and flooded to K+2
  SHIP    RED    under Aflood=False under Bquiet=False
  FIX-A   GREEN  under Aflood=True  under Bquiet=False
  FIX-G   GREEN  under Aflood=True  under Bquiet=False
  FIX-H   GREEN  under Aflood=True  under Bquiet=False
  FIX-I   RED    under Aflood=False under Bquiet=True
```

### `TC-499`, executed end-to-end through `generate_project_report`

```
=== TC-499 fixture: fire :1134 with NO addendum hit ===
    report-wide '> TRUNCATED:' lines : 1
       > TRUNCATED: 1 of 201 declaration errors omitted (cap: 200 issues per variant).
    addendum section body            : ['### zone (0x1000-0x2000)', 'None.']
    '> TRUNCATED:' INSIDE the addendum: 0
    TC-499 pre-conditions hold? True
```

---

## 4. Ruling on `TC-498`'s equality form — **the FORM is upheld; the NODE is not yet writable**

**On the question asked — brittle, or precisely the point?**

**The exact equality is the right form and I uphold it.** The spec's argument is executed-correct: at
`R = 256` under `huge+tiny`, `A = 128 000` while `N + hits = 1 000`, so no constant `c` in
`A ≤ c × (N + hits)` that is independent of `R` can pass against the adopted prefix-max array. A bound
is therefore *unwritable*, and writing one anyway is the gate-that-cannot-pass defect the spec names.
A disclosure counter whose whole value is that **§10.7's number cannot go stale silently** must be an
equality — a `≤` would be satisfied by the very structure being disclosed and would say nothing. The
brittleness is the mechanism: if a later batch swaps in an output-sensitive structure, `TC-498` fails
loudly and forces §10.7 to be rewritten rather than left over-claiming. That is a feature.

**But brittleness has to be scoped to a quantity the spec defines, and it is not.** Executed:

```
huge+tiny geometry, N = 500 candidates, all inside the huge region

    R | A (explicit walk counter) |    R x N | A == RxN? | contains() on SHIP | contains() on FIX-A
    1 |                       500 |      500 |      True |                500 |                   0
    8 |                      4000 |     4000 |      True |               4000 |                   0
   64 |                     32000 |    32000 |      True |              32000 |                   0
  256 |                    128000 |   128000 |      True |             128000 |                   0
```

The **law reproduces exactly** — `500 / 4000 / 32000 / 128000` is bit-for-bit the architect lane's
`p2_cost.py` grid, independently rebuilt here. The law is not in doubt. Two things about *measuring* it
are — see **NEW-2**. My recommended fold is therefore **not** to change the equality: keep `A == R × N`,
and add two sentences pinning (i) the seam that exposes `A` and (ii) what counts as one region op.

---

## 5. Ruling on M-3's declined half — **the retirement-in-place is ADEQUATE**

I recommended *"re-label `AT-195 → TC-498`, or fold it into `TC-488`"*. Revision 2 retires the id in
place instead, because `TC-498` is now the region-ops counter and re-pointing would bind two observables
to one id.

**That reasoning is correct and I accept the variation.** My recommendation was written before
`TC-498` existed as an ops counter; re-pointing it now would recreate exactly the C-18 defect M-3 was
raised about, and §5.2's own rule (applied to batch-63's `AT-164..167`) forbids it. Executed check on
whether the retirement leaks: 24 `AT-195` / `TC-496` mentions across the document, **every one a
retirement row, a history row, or an amendment row — 0 live bindings**; both ids are absent from both
§6.2 tables and from §11/§11.1. The id ledger states the non-contiguity deliberately rather than
hiding it. A grep for either id lands on the retirement, which is what the fold promised.

One residue: **§13 row 8a was not updated** — see NEW-8.

---

## 6. A correction to my own M-3, surfaced rather than buried

My M-3 asserted that `OBS-notice-reaches-the-file` *"is the only node that closes the `emit()`-byte-budget
hole for US-B64-2"*. Revision 2 copied that mechanism verbatim into §4 `LLR-103.5` and §5.1 row 15.
**Executed on `082ada9`, there is no such hole:**

```
=== (a) AT-200 RED arm: can emit() drop a batch on 082ada9? ===
def emit(batch: Sequence[str]) -> None:
    lines.extend(batch)
    budget.consume(_line_bytes(batch))
    'fits' referenced inside emit()? False
    budget.fits() call sites in generate_project_report: NONE
    budget.fits() call sites repo-wide: ['        if not budget.fits(_line_bytes(block)):']
```

`emit()` **unconditionally** extends `lines` and merely *accounts* bytes; the only `budget.fits` gate in
the module is inside `_hexdump_section`. `emit` is also a **closure local to
`generate_project_report`**, so the stated RED arm ("an `emit()` path that drops it") is not
constructible from a test without editing production code.

**The fold is still right** — promoting `TC-496 → AT-200` is correct on Layer-B grounds (it is genuinely
observed through the written file **and** the `ReportViewerScreen` seam), and `AT-200`'s falsifiability
is carried by RED→GREEN across the Inc-1/Inc-2 boundary, not by the mutant arm. Only the *justification*
is wrong, and it is wrong because it is mine. Recorded here in the §17.5 spirit: the direction is right,
the stated mechanism would mislead Phase 3 if copied. → **NEW-6.**

---

## 7. New findings — defects the fold planted

### **NEW-1 `major`** — §11.1 marks four nodes expected-RED at Inc-1 that are GREEN on the shipped producer

**Where:** §11.1 row *"`TC-480…TC-489`, `TC-491`, `TC-493`, `TC-494` → **RED**, except `TC-491`"*; §11
Inc-1 gate; §6.2's executability ledger row *"everything else → expected RED at Inc-1"*.

Executed against the **real** `report_service._addendum_lines` (imported, not copied):

```
SHIPPED producer = s19_app.tui.services.report_service | tree = 082ada9 export

--- TC-486  nested overlap outer(0x1000-0x2000) > inner(0x1500-0x1600) ---
    '### outer (0x1000-0x2000)'
    '- modification @ 0x1800 (variant v1)'
    '- modification @ 0x2000 (variant v1)'
    0x1800 present? True   0x2000 present? True
    TC-486 verdict on SHIP -> GREEN

--- TC-487  duplicate + equal-start-nested regions ---
    hit lines: 0x1550 x3  0x1900 x3   (3 regions all contain both)
    TC-487 verdict on SHIP -> GREEN

--- TC-484  N = 0 / issue.address is None / 1-byte region ---
    N=0, no variants   -> [... '### empty (0x5000-0x5FFF)', 'None.', '']
    issue.address None -> [... '### empty (0x5000-0x5FFF)', 'None.', '']
    1-byte region      -> [... '- modification @ 0x7000 (variant v1)', '']   (0x7001 absent)
    TC-484 verdict on SHIP -> GREEN

--- TC-485  R = 0 guard at :1719 ---
    guard source: ['if options.declared_regions:']
    TC-485 verdict on SHIP -> GREEN
```

All four are **GREEN by construction**: the shipped producer already tests each region independently
with `DeclaredRegion.contains`, so it is *correct* on nested and duplicate geometry, and it already
emits `None.` and skips `issue.address is None`. `TC-484…TC-487` are **regression guards** protecting
those properties across the loop inversion — which is a real and valuable job, and exactly the category
§11.1 was created to name for `AT-196` / `TC-491` / `AT-198` arms 1–2.

**Why this is the same defect class as `ARCH-B-3`, in the table that discharges `ARCH-B-3`.** §11's
Inc-1 gate reads *"the per-node expected-verdict table below is reproduced exactly … Every expected-RED
node RED on the failing side of its threshold by ≥ 50 %"*. An author meeting that literally for
`TC-486` must manufacture a RED — and the only way to do so is to write the test against the *future*
implementation's private membership helper rather than against the observable, which is precisely the
weakening §11.1's preamble warns about for the golden.

**Compounding: none of the four has a mutant arm assigned.** `AT-196`'s row names
`FIX-B`/`FIX-E`/`FIX-G`; the TC block says only *"as noted"*. `TC-486`'s natural mutant **exists and is
already in the document** — `FIX-E` (raw `range_index` membership) is executed-RED on `FIX-GOLD` and is
exactly the implementation this LLR forbids.

**Recommended fold.** Move `TC-484`, `TC-485`, `TC-486`, `TC-487` into §11.1's *expected GREEN at Inc-1 —
regression guard* class beside `AT-196` / `TC-491`, and name their Inc-2 mutant arms: **`FIX-E` for
`TC-486`/`TC-487`** (raw single-interval membership), and a **drop-the-`None.`-branch** arm for
`TC-484`. Update §6.2's ledger row so *"everything else → expected RED"* is no longer false.

---

### **NEW-2 `major`** — `TC-498` has no named instrument, and both available seams invert its verdicts

**Where:** §6.2 table 2 (`TC-498`, `test (unit)`); §7 T-9 threshold; §11.1 (`RED` @ Inc-1, `GREEN` @ Inc-2).

`TC-488`'s instrument is **named by the spec** — *"an injected re-iterable counting sequence"* over
`variant_results`, which works because the production code iterates the passed-in sequence. `TC-498`'s
is not named anywhere. Executed, every candidate seam:

```
R = 64, N = 500, R x N = 32000
  A) count DeclaredRegion.contains, SHIP  -> 32000
  A) count DeclaredRegion.contains, FIX-A -> 0
  B) counting re-iterable over REGIONS, FIX-A reads -> 2
  B) counting re-iterable over REGIONS, SHIP  reads -> 1
  C) explicit ops counter inside the walk -> 32000 (needs production code to expose it;
                                                    082ada9 exposes nothing)

--- Verdicts §11.1 claims vs what each instrument yields ---
  R=  1: instrument A on SHIP:  A=500    == RxN=500    ? True  -> GREEN at Inc-1  (§11.1 says RED)
  R=  8: instrument A on SHIP:  A=4000   == RxN=4000   ? True  -> GREEN at Inc-1  (§11.1 says RED)
  R= 64: instrument A on SHIP:  A=32000  == RxN=32000  ? True  -> GREEN at Inc-1  (§11.1 says RED)
  R=256: instrument A on SHIP:  A=128000 == RxN=128000 ? True  -> GREEN at Inc-1  (§11.1 says RED)
  R=  8: instrument A on FIX-A: A=0      == RxN=4000   ? False -> RED   at Inc-2  (§11.1 says GREEN)
```

**Both of `TC-498`'s stated verdicts invert under the obvious instrument.** The shipped producer calls
`DeclaredRegion.contains` exactly `R × N` times — it *is* the `O(R)` shape — so `A == R × N` is
**already true today**, contradicting §11.1's *"RED (`SHIP` has no attribution walk to count)"*. The
adopted design calls `contains` **zero** times, because it walks caller-local `starts`/`ends`/`prefix_max`
arrays, so the same instrument reads `0` after the fix. Instrument (B) reads the region sequence once at
resolver construction — `1` / `2`, not `R × N`. Only an explicit counter wired into the production walk
reads the quantity, and nothing in `LLR-103.1` or `LLR-103.2` requires one to exist.

**Second half — "region op" is undefined, and the equality is not stable under benign variation:**

```
--- Is the exact equality stable under benign variation? ---
  counting the reject pre-filter too : 32500  (== RxN? False)
  one candidate outside every region : 31936  (== RxN? False)
```

Counting the coalesced-cover reject probe as one region op gives `32 500`; a single candidate outside
every region gives `31 936`. §7 T-9 pins the *geometry* (which covers the second) but never says whether
the pre-filter probe counts (which covers the first).

**Recommended fold — do NOT change the equality (see §4).** Add to `LLR-103.1` or `LLR-103.2`:
(i) the walk shall expose its per-call region-op count through a **named test seam** (an injectable
counter callback, or a module-level `_LAST_REGION_OPS` the test reads — either is fine, but one must be
named, as `TC-488`'s counting sequence is); (ii) **one region op = one iteration of the prefix-max
descent; the reject pre-filter probe is excluded**; (iii) restate `TC-498`'s Inc-1 verdict — with the
seam absent pre-fix, its honest pre-fix status is **`NOT EXECUTABLE PRE-FIX`**, alongside
`TC-490`/`TC-492`/`TC-495`, not `RED`.

---

### **NEW-3 `major`** — the addendum-scope predicate has no EOF arm, and the addendum is the LAST section

**Where:** §7 T-5 preamble; §3 US-B64-2 *"Notice counting is ADDENDUM-SCOPED"*; §12 X-9 — all of which
define the scope as *"between the `## Addendum: declared regions` heading and the next `^## `"*.

Executed on a real report from `generate_project_report`:

```
=== (b) addendum scope boundary on a real report ===
    '## ' headings in order: ['## Variant inventory', '## Consolidated overview', '## Legend',
                              '## Variant: a', '## Addendum: declared regions']
    addendum is heading #5 of 5;  next '## ' after it: NONE - EOF
    bytes after the addendum heading: 63;  contains '\n## '? False

=== The EOF hazard: 'between the heading and the next ^## ' on a real report ===
  literal 'heading .. next ^## '   -> match=False -> addendum notices seen = 0
  '.. next ^## OR EOF'             -> match=True  -> addendum notices seen = 1
```

The addendum is the **last** `## ` section. `## Truncation appendix` is emitted after it **only if
`notes` is non-empty**, and `notes` is populated exclusively by `_hexdump_section` — so on every fixture
that does not truncate a hexdump (which is every notice fixture in §7 T-5), there is no next `^## `.

A literal implementation of the stated predicate finds **no scope at all** and therefore reads **0
addendum notices on every report**. That makes `AT-197`, `AT-198`, `AT-199`, `AT-201`, `AT-202`,
`AT-203` and `TC-499` **all vacuously "0 notices"** — GREEN on `AT-198`'s absence arms and RED on
everything else regardless of what the producer does. This is a defect **planted by revision 2's S3
fold**: revision 1's report-wide count had the security defect S3 named, but it did not have this one.

**Recommended fold.** One clause in §7 T-5's preamble and §12 X-9: *"…and the next `^## ` **or
end-of-file, whichever comes first**"*, and require the Inc-1 harness to assert the scope is non-empty
before evaluating any notice count — a scope-extraction helper that returns an empty scope must **fail
the test**, not report zero notices.

---

### **NEW-4 `major`** — the Inc-1 nodes cannot import the constants they are required to quote

**Where:** §4 `LLR-103.5` acceptance (*"The AT **quotes the constants** … Boundary fixtures derive `E` as
`K-1`/`K`/`K+1` from the imported constant"*); §6.2 executability ledger; §11 Inc-1 gate; §11.1.

```
--- LLR-103.6 constants on 082ada9 (Inc-1 nodes must import these) ---
    hasattr(report_service, 'MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION') -> False
    hasattr(report_service, 'ADDENDUM_CLASS_LABELS')                  -> False
    hasattr(report_service, 'ADDENDUM_NOTICE_VARIANTS_MAX')           -> False
    hasattr(report_service, 'ADDENDUM_TRUNCATION_NOTICE_FMT')         -> False
    module-level import -> ImportError: cannot import name
        'MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION' from 's19_app.tui.services.report_service'
```

The executability ledger names only `TC-490`, `TC-492`, `TC-495` as `NOT EXECUTABLE PRE-FIX`. But
`AT-197`, `AT-198`, `AT-201`, `AT-202`, `TC-481`, `TC-482`, `TC-483` all derive their fixtures from `K`,
and `AT-197`/`AT-199`/`AT-201`/`AT-202`/`AT-203`/`TC-499` all parse against
`ADDENDUM_TRUNCATION_NOTICE_FMT`'s rendered shape. Every one of them needs a constant that does not
exist on `082ada9`.

Two consequences, both bad for the Inc-1 gate:

1. A **module-level** import in `tests/test_report_addendum_bound.py` is a **collection error**, which
   `xfail` does **not** cover — it takes down every node in the file, including the ones whose RED is
   meaningful. The three `xfail(strict=True)` nodes do not protect the other fifteen.
2. Even with in-test imports, the resulting RED is an `ImportError`, not a predicate failure. A
   RED-by-import proves nothing about whether the predicate reaches the behaviour — it is a vacuous RED,
   and §6.3 requires the opposite (*"RED strictly on the failing side"*).

**Recommended fold.** State in §11's Inc-1 row how the constants are obtained pre-fix — the cheapest
honest form is `K = getattr(report_service, "MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", 200)` **at Inc-1
only**, with Inc-2 gated on the fallback being **removed** (a one-line grep in the Inc-2 gate). That
keeps "an AT quotes the constant, never its value" true from Inc-2 onward — which is where it matters —
without making Inc-1's RED an import error. Whatever form is chosen, §6.2's ledger must stop claiming
*"everything else → expected RED at Inc-1"* without qualification.

---

### **NEW-5 `minor`** — the Inc-1 RED gate's "≥ 50 % margin" is undefined for the boolean nodes

§11 Inc-1 gate / §6.3: *"Every expected-RED node RED **on the failing side of its threshold by ≥ 50 %**,
on its own named fixture."*

That form is well-defined for the ratio and count thresholds — `AT-194` (`≤ 1.30`), `TC-493` (`≤ 1.25`),
`TC-483` (line-count bound), `TC-488` (`consumed == N`), `TC-498` (`A == R × N`). It is **undefined**
for the ~12 boolean nodes: `AT-197`, `AT-199`, `AT-200`, `AT-201`, `AT-202`, `AT-203`, `TC-484…TC-487`,
`TC-494`, `TC-499` all evaluate to RED or GREEN with nothing to take 50 % of. `AT-197` on `SHIP` is
`notices=[]` — there is no failing-side magnitude.

The gate's *intent* (architect M-4: do not chase another lane's verbatim figure) is right and should be
kept. It just needs two clauses: *"for a **numeric** threshold, RED on the failing side by ≥ 50 %; for a
**boolean** predicate, RED with the observed value pasted (e.g. `notices=[]`) and the named arm stated."*

---

### **NEW-6 `minor`** — `AT-200`'s stated rationale and RED arm are executed-false

See §6 above for the transcript and for the fact that this is **my own inherited claim**. `emit()` on
`082ada9` never drops; the only `budget.fits` gate is in `_hexdump_section`; and `emit` is a closure, so
the stated RED arm is not constructible. **Fold:** restate `AT-200`'s justification as *"the only node
that observes the notice through the written file **and** the `ReportViewerScreen` seam, i.e. the only
Layer-B node for US-B64-2's delivery"*, drop the `:1720` byte-budget claim (or restate it as *"guards a
hole the batch-63 `_ByteBudget` carry would open"* — which is honest and forward-looking), and replace
the RED arm with *"pre-fix: no notice exists — RED at Inc-1, GREEN at Inc-2"*.

---

### **NEW-7 `minor`** — `AT-203`'s sub-section split must key on the `md_safe`-**escaped** region name

Executed, and I walked into it building the probe: `DeclaredRegion("B_quiet", …)` renders its heading as
`### B\_quiet (0x1000-0x1FFF)`, because `_addendum_lines` applies
`md_safe(region.name, limit=DECLARED_REGION_NAME_MAX)`. A test that splits on `### B_quiet ` finds **no
sub-section**, and the "absent from every other region's sub-section" half then passes **vacuously**.

My first run reported `FIX-A` RED for exactly this reason before I renamed the fixture regions.

**Fold:** one sentence under `AT-203`'s threshold — *"the fixture's region names are drawn from
`[A-Za-z0-9 ]` so the `### ` split is unambiguous, **or** the test derives the heading through
`md_safe`; and the test asserts both sub-sections were **found** before asserting on their contents."*

---

### **NEW-8 `minor`** — §13 row 8a is stale: it cites the retired `AT-195` and omits `AT-200…AT-203`

Row 8a still reads *"§3 'Acceptance (black-box) — US-B64-1' (`AT-194/195/196`) and '— US-B64-2'
(`AT-197/198/199`)"*. `AT-195` is retired (§5.2) and `AT-200`, `AT-201`, `AT-202`, `AT-203` are missing.
This is the one place in the document where a grep for the retired id would land on something that looks
live rather than on the retirement row §5.2 promises. One-line edit.

---

### **NEW-9 `minor`** — `AT-198` now carries three §11.1 rows with three different Inc-1 verdicts under one id

§11.1 lists `AT-198` arm 1 (**GREEN by vacuity**), arm 1b (**RED**), arm 2 (**GREEN by vacuity**). One
collected pytest node has one verdict, so "the table is reproduced exactly" requires `AT-198` to be at
least three separately-collected nodes.

This is not a reopening of M-4 — I explicitly recommended keeping arms 1–2 under `AT-198`, and revision 2
did that. Making the arms' verdicts explicit is an *improvement*. But the plan should say **how** they
are collected: *"`AT-198` is a parametrised family — `test_at198[le_K]`, `test_at198[K_plus_1]`,
`test_at198[interior]` — one collected node per arm, one id."* Otherwise the Inc-1 gate cannot be
checked against the table.

---

## 8. One observation on M-1's replacement predicate (not a finding)

`TC-495`'s new invariant — *the notice's rendering of a value equals the neighbouring hit line's
rendering of the same value, byte for byte* — cannot false-fail and is the right repair. It is,
however, also satisfied by an implementation that escapes **neither** side. What actually forbids that
is `AT-199` (a hostile id cannot forge a notice line, executed-cleared by the security lane) plus
`AT-196`'s byte identity on the hit-line side. **The pair is sufficient; the spec should say so in one
clause** so a Phase-3 reader does not treat `TC-495` as the whole escaping story. Not blocking.

---

## 9. Checks re-confirmed this gate — recorded so they are not re-litigated

| check | verdict | evidence |
|---|---|---|
| `FIX-H` RED on the repaired `AT-197` | ✅ | §2, executed |
| `AT-202` falsifiable both directions; `FIX-G` GREEN on it | ✅ | §2, executed |
| `AT-201` falsifiable; `FIX-H` GREEN on it | ✅ | §2, executed |
| `AT-203` falsifiable; `FIX-I` RED, `FIX-A` GREEN, `SHIP` RED | ✅ | §3, executed |
| `TC-499` pre-conditions hold end-to-end (`:1134` fires, 0 addendum notices) | ✅ | §3, executed |
| `TC-498`'s **law** `A == R × N` reproduces at `R ∈ {1,8,64,256}` | ✅ | §4 — `500/4000/32000/128000`, bit-for-bit with the architect lane |
| `A ≤ c × (N + hits)` genuinely cannot pass | ✅ | §4 — `128 000` vs `1 000` at `R = 256` |
| every live `AT`/`TC` authored in exactly ONE increment and gated in exactly ONE (C-18/C-21) | ✅ | enumerated: 9 ATs + 18 TCs at Inc-1 (gated Inc-2), `TC-497` at Inc-3 (gated Inc-3); §11.1's rows partition `TC-480…TC-495` with no node in two rows; `AT-195`/`TC-496` absent from both |
| retired ids never re-pointed | ✅ | 24 mentions, 0 live bindings (one stale prose row — NEW-8) |
| m-3's index resolution neither averages nor arbitrates | ✅ | §7 T-4 records both lanes and forbids the assertion |
| no real PII / secrets / credentials | ✅ | every fixture synthetic; `TemporaryDirectory` only; worktree unmutated |
| counterfactuals run in an export, not the worktree | ✅ | `git archive 082ada9` → `…/scratchpad/exp64`; the only file written under the repo is this review |

**Not re-litigated (verified green at the first gate):** the `K−1/K/K+1` escape from the in-domain max
of 2 · the `E == K` interior conjunction · test homes routing around `_ENGINE_TEST_FILES` · the
"order is pinned by nothing" greps · `X-2`'s closure.

---

## 10. Exit criteria for this re-gate

1. **NEW-1** — the four `TC-484…TC-487` rows moved to the *expected GREEN, regression guard* class, with
   `FIX-E` named as `TC-486`/`TC-487`'s Inc-2 mutant arm. *Blocking.*
2. **NEW-2** — `TC-498` gains a **named seam** and a **definition of one region op**; its Inc-1 status
   restated as `NOT EXECUTABLE PRE-FIX`. The `A == R × N` equality is **kept**. *Blocking.*
3. **NEW-3** — the addendum scope gains its **`or EOF`** arm, and an empty scope must fail rather than
   report zero. *Blocking.*
4. **NEW-4** — §11 states how Inc-1 obtains the four constants, and §6.2's ledger stops claiming
   *"everything else → expected RED"*. *Blocking.*
5. **NEW-5…NEW-9** folded or declined **in writing** with a reason (§5.2's retirement rows are the model).
6. `04-validation.md` filled **by execution**, never from this file's numbers or the spec's.

**Nothing here reopens B-1, M-1, M-2, M-3, M-4 or m-1…m-4. Nothing here challenges the design.**

---

## 11. Evidence checklist (this re-gate)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use an observable / mutation / boundary triple | ✓ | every new finding names the node, the arm, and the direction |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | each fold in §7 states the exact clause to write |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | §7 NEW-1 executes empty (`N = 0`), boundary (1-byte region), invalid (`issue.address is None`), degenerate (`R = 0`); §4 executes the ops equality's two off-nominal variations |
| 4 | Regression checklist exists | ✓ | NEW-1 is *about* the regression-guard class; §6.3's regression set re-read unchanged |
| 5 | Exit criteria stated | ✓ | §10 |
| 6 | No real PII / secrets | ✓ | synthetic `SimpleNamespace` / dataclass fixtures, `TemporaryDirectory`, no `examples/` image read |
| 7 | Test-results section left blank unless actually run | ✓ | every transcript here was executed by this lane; nothing projected |
| 8 | Layer B — the shipped surface observed with boundary + negative evidence | ✓ | §3 and §7 NEW-3 drive `generate_project_report` end-to-end and read the **written report file**; §7 NEW-1 drives the real `_addendum_lines` |
| 9 | Bidirectional surface-reachability | ✓ | **inputs**: region count `R ∈ {1,8,64,256}`, huge+tiny / nested / duplicate / disjoint / equal-start geometry, `E` at `K`, `K−1`, `K+1`, `N = 0`, `R = 0`, 1-byte region, `address is None`, `> MAX_REPORT_ISSUES_PER_VARIANT` issues. **outputs**: rendered hit lines, `None.`, parsed `(class, dropped, variants)` triples, `### ` sub-section attribution, report-wide vs addendum-scoped `> TRUNCATED:` counts, region-op counts |
| 10 | No unfilled template | ✓ | no placeholders; every finding carries an executed transcript or a `file:line` |
| 11 | Every finding's mutation was EXECUTED, not described | ✓ | `FIX-H` (B-1), `FIX-I` (AT-203), `FIX-A`/`SHIP` contains-counting (NEW-2), real `_addendum_lines` (NEW-1), real report file (NEW-3), real `ImportError` (NEW-4) |
| 12 | Counterfactuals run in an export, not the worktree | ✓ | `…/scratchpad/exp64`; only this file written under the repo |
