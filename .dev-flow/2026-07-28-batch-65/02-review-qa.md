# Phase-2 review — QA lane — batch-64

> **Reviewing:** `.dev-flow/2026-07-27-batch-64/01-requirements.md` (consolidated, 1213 lines).
> **Supporting:** `PLAN.md`, `01-requirements-architect.md`, `01b-qa-catalog.md`.
> **Independence:** this lane did not write the Phase-1 qa catalog. Every number below was executed by
> **this** lane in a pristine `git archive` export of `082ada9` at
> `…/scratchpad/exp64` (probes `qa2_arms.py`, `qa2_predicates.py`, `qa2_traversal.py`,
> `qa2_memory.py`, `qa2_rest.py`, `qa2_region_attr.py`). The worktree was not mutated.
> **Scope:** testability and vacuity only.

---

## 0. Verdict

**BLOCK — 1 blocker, 4 majors, 4 minors.** The spec is 90 % of the way to being testable as written:
the traversal, memory, byte-identity, boundary and class-level notice acceptances all reach the
behaviour, go RED on the shipped tree and GREEN on a conforming fix with margin. **X-2 is CLOSED by
measurement** (below) and the `OBS-traversal-early-exit` retirement is **UPHELD with stronger evidence
than the spec gives for it**.

The blocker is that the batch's flagship acceptance — `AT-197`, the one the spec argues at length is
"not `AT-165` again" — **is `AT-165` again, one axis over**. Its variant threshold is a *representation*
check (`⊇`), not an *identity* check, and this lane built an implementation arm (`FIX-H`) that is
**GREEN on every stated acceptance in the document** while telling the operator that the attacker's
evidence was dropped when the attacker lost nothing. Executed proof in §1.

None of the findings challenge the design. All five folds are edits to predicates and fixtures.

---

## 1. `blocker` — B-1: `AT-197`'s variant threshold is a representation check; `FIX-H` is GREEN on the entire acceptance set

**Where:** §4 `LLR-103.5` "Numeric pass threshold"; §7 T-5 `AT-197` threshold; §6.2 behavioral row for
`AT-197`; §5.1 rows 11–12.

**The predicate as written** (§7 T-5): *"at `flood = K` → exactly **1** notice line for `change-file
issue`, `{dropped} == 2` …, `{variants} ⊇ {v2, v3}`"*.

`⊇` asserts that the cut variants are **among** those named. It does not assert that the named variants
are **only** those cut. That is structurally the same predicate as batch-63's `AT-165`
("every producing hit-class is **represented**") with `variant` substituted for `class`.

**Executed.** This lane added a new arm, `FIX-H` — identical to `FIX-A` in every respect except that
`{variants}` lists every variant that **contributed** to the cut class rather than every variant whose
hits were **dropped**. Fixture = the spec's own batch-63 A2/A3 attack (`v1` floods
`CHG-ADDRESS-SYNTAX` to `K`; `v2` and `v3` each carry one ERROR `CHG-COLLISION`; `v1` also contributes
3 uncut modifications):

```
=== AT-197 threshold as written  (flood = K) ===
  SHIP    RED    notices=[]
  FIX-A   GREEN  notices=[('change-file issue', 2, ['v2', 'v3'])]
  FIX-G   GREEN  notices=[('modification', 0, []), ('change-file issue', 2, ['v2', 'v3'])]
  FIX-H   GREEN  notices=[('change-file issue', 2, ['v1', 'v2', 'v3'])]      <-- v1 lost NOTHING

=== AT-198 arm 3 (uncut CLASS not named) ===
  FIX-G   RED    named=['change-file issue', 'modification']
  FIX-H   GREEN  named=['change-file issue']

=== AT-198 arm 1 (class total == K -> 0 notices anywhere) ===
  FIX-G   RED    n=2
  FIX-H   GREEN  n=0

=== AT-198 arm 1b (class total == K+1 -> exactly 1) ===
  FIX-H   GREEN  n=1 [('change-file issue', 1, ['v1', 'v2', 'v3'])]

=== AT-196 / TC-494: byte identity vs SHIP over the hostile FIX-GOLD ===
  FIX-B   RED  at index 7        FIX-E   RED  at index 4        FIX-G   RED  at index 10
  FIX-H   GREEN
```

`FIX-H` is additionally GREEN on `AT-194` / `AT-195` / `TC-488` / `TC-489` / `TC-481-483` / `TC-493`
by construction (it differs from `FIX-A` only in the notice's variant list).

**Why this is operator-relevant, not pedantic.** In the fixture, `v1` is the attacker: its flood is
exactly what evicted `v2`'s and `v3`'s collisions, and every one of `v1`'s own hits was **admitted**.
`FIX-H`'s notice reads *"variants affected: v1, v2, v3"*. The operator reading an evidentiary report
concludes that `v1`'s evidence did not fit — when `v1`'s evidence is precisely what is on the page.
US-B64-2 exists to let the operator "distinguish 'there is no evidence' from 'the evidence did not
fit'"; `FIX-H` makes that distinction wrong for a third of the named variants and ships GREEN.

**The consolidation lost this, and the catalog had it.** `01b-qa-catalog.md:466-467` (§5.12
"Boundary") explicitly required *"a variant that contributed hits and was **not** cut (must not
appear)"*. In the consolidated document that survives **only as prose** in §3's US-B64-2 boundary
catalog, bound to `AT-198` — with no threshold in §4, no row in §7, and **no named RED arm**. The three
notice arms the spec does carry (`SHIP` no notice, `FIX-C` `(variants ?)`, `FIX-F` no variant list) all
attack the *under*-naming direction. **Nothing in the document attacks the over-naming direction on the
variant axis.** That is the P-6 gap the spec closed at the class axis (`AT-198` arm 3 / `FIX-G`) left
open one level down.

**Recommended fold (edit §4 `LLR-103.5`, §7 T-5, §6.2, §5.1 rows 11-12):**
1. Change the threshold from `{variants} ⊇ {v2, v3}` to **set equality**: the parsed variant list of
   the `change-file issue` notice **equals** `{v2, v3}` — derived by the test from its own fixture as
   *the set of variants with ≥ 1 dropped hit*, not as *the set of variants contributing to the class*.
2. Add `FIX-H` (as defined above) to the named RED arms of `AT-197`, beside `SHIP` / `FIX-C` / `FIX-F`,
   with the transcript above.
3. Promote the variant-level false-positive to its **own** boundary arm with the same status
   `AT-198` arm 3 has at the class level, and say in the row that `FIX-G` does **not** cover it
   (executed: `FIX-G` is GREEN on it).

---

## 2. `major` — M-1: `TC-495`'s benign-direction threshold false-fails a correct implementation, and its cited provenance does not exist

**Where:** §4 `LLR-103.5` "Numeric pass threshold" (last sentence); §7 T-5 last bullet; §5.1 row 14;
§9 A-5.

**Stated threshold:** *"a **benign** variant id renders with **0** escape artefacts (qa §5.14 negative
direction)"*.

**Executed** (`md_safe` from `report_service`, `limit=REPORT_CELL_CHARS`):

```
=== TC-495 benign direction ===
  md_safe('v1')        -> 'v1'            artefact-free? True
  md_safe('variant_a') -> 'variant\\_a'    artefact-free? False
  md_safe('v-2.1')     -> 'v-2\\.1'        artefact-free? False
  md_safe('cal zone')  -> 'cal zone'      artefact-free? True
```

`_` and `.` are in `MD_ESCAPE`, so **any** variant id containing them renders with an escape artefact
under a **correct** implementation. The repo already documents this — `tests/test_report_service.py`
carries the comment *"the declared-region name is a Mode-A field, so `_` carries an escape and renders
invisibly"* beside `assert "empty\\_zone" in addendum`. As written the threshold is satisfied or
violated purely by the unpinned choice of "benign" id: pick `v1` and it is vacuous, pick `variant_a`
and it false-fails the conforming fix. This is the batch-63 `<1.5` shape on the escaping axis.

**Second half — the provenance is false.** The threshold is attributed to "qa §5.14 negative
direction". `01b-qa-catalog.md:496-497` states the negative direction as a **requirement** and gives no
transcript; its only `Executed:` line points at §3.4, which is the **hostile** direction. The document's
own provenance rule (line 7: *"every threshold below carries its executed RED and GREEN from **this**
tree"*) and evidence-checklist row 11 are therefore overclaimed for this threshold.

**Recommended fold:** restate as *"a benign variant id drawn from `[A-Za-z0-9-]` renders **byte-identical**
in the notice and in the neighbouring hit line; an id containing `_` or `.` renders escaped in **both**"* —
i.e. make the invariant *notice-escaping equals hit-line-escaping on the same value*, which is the
property that actually matters and cannot false-fail. Drop the "(qa §5.14)" attribution or mark it
`NOT EXECUTED — derive at Inc-1`.

---

## 3. `major` — M-2: the notice's REGION attribution is unasserted; a misfiling implementation is GREEN

**Where:** §4 `LLR-103.5` Statement (*"immediately after that region's hit list"*) vs §7 T-5, §6.2, §3
US-B64-2 boundary catalog — all of which scan the report **report-wide**.

Every stated notice predicate counts notice lines *anywhere in the report* (`AT-198`: "0 notice lines
**anywhere**"; `AT-197`: "the written report contains exactly 1 notice line for the class"). Every
notice fixture in the document is `R = 1` (the flood fixture) or below-bound (`FIX-GOLD`). **No
acceptance ever has a cap fire with `R > 1`**, so nothing observes *which region's sub-section* the
notice lands in.

**Executed.** Arm `FIX-I` = `FIX-A` with every notice re-emitted under the **first** region's
sub-section. Fixture: two disjoint regions, `B_quiet` declared first, `A_flood` second and flooded.

```
  FIX-A  AT-197=GREEN AT-198a3=GREEN || notice under flooded region? True    under quiet region? False
  FIX-I  AT-197=GREEN AT-198a3=GREEN || notice under flooded region? False   under quiet region? True
```

In an evidentiary report over several declared calibration regions, `FIX-I` tells the operator that the
*quiet* region lost evidence and the *flooded* region lost none — inverting US-B64-2 — and passes every
acceptance in the document.

**Recommended fold:** add an `R ≥ 2` arm to `AT-197`: exactly one region is flooded; assert the notice
is present inside the **flooded** region's sub-section (split on `### `) and **absent** from every other
region's sub-section. Name `FIX-I` as its RED arm. This is one extra fixture on an existing test.

---

## 4. `major` — M-3: the Layer-A / Layer-B labels are swapped between two slugs, and `AT-195` duplicates `TC-488`

**Where:** §1.3 definition of `AT`; §6.1; §6.2 table 1 row 2; §5.1 rows 6 and 15; §6.3.

§1.3 defines `AT` as *"Layer-B black-box acceptance test: drives `generate_project_report`, reads the
**written report file**"*, and §6.3 requires *"every user story by ≥ 1 passing AT observing the outcome
through the **written report file**"*.

- **`AT-195`** observes *"`consumed == N` via an injected re-iterable counting sequence"*. That number
  is not in the report file and cannot be. §6.2 lists its shipped surface as
  "`generate_project_report` + injected re-iterable counting sequence" — the injection *is* the
  observation, which makes it a mechanism test. The Phase-1 catalog ruled on exactly this
  (`01b-qa-catalog.md:748`, evidence row 9): *"**Mechanism-only** observables (consumed count,
  `_addendum_lines` peak) are labelled white-box, **never counted as Layer B**"*. The consolidation
  promoted it anyway. **An observable got weaker in the merge in the sense that matters here: the
  Layer-B bar for US-B64-1 is now met by 2 real nodes (`AT-194`, `AT-196`) plus one that does not
  qualify.**
- **`TC-496`** (`OBS-notice-reaches-the-file`) is the mirror error: the catalog classes it black-box
  through the file **and** the TUI seam (§5.15, §9), and it is the only node that closes the
  `emit()`-byte-budget hole for US-B64-2. It carries a `TC` id, so under §6.3's wording it does not
  count toward US-B64-2's Layer-B obligation either.
- **C-18 duplicate.** `AT-195` and `TC-488` assert the *same* predicate (`consumed == N`,
  `R ∈ {1,8,64}`, overlapping geometry) on the *same* instrument. Either they collapse to one on-disk
  node — in which case `AT-195` does not map to a distinct node — or `AT-195` is a verbatim copy of
  `TC-488` under a different id.
- Related, same class: §5.1 row 3 binds `OBS-overlap-membership-preserved` to `TC-486`/`TC-487` only,
  though the catalog (§5.3) calls it *black-box through the file*. It **is** covered black-box via
  `AT-196`'s `FIX-GOLD` (`FIX-E` RED at index 4, executed above), but the binding row does not say so.

**Recommended fold:** re-label `AT-195 → TC-498` (or fold it into `TC-488` and delete the id) and
promote `TC-496 → AT-195`, which makes US-B64-2's file-reaching observable a first-class Layer-B node
and leaves US-B64-1 with `AT-194` + `AT-196`, both genuinely file-observed. Add `AT-196` to §5.1 row 3's
bound ids.

---

## 5. `major` — M-4: `AT-198` binds three distinct observables to one id (C-18)

**Where:** §3 US-B64-2 "Acceptance test(s)"; §5.1 rows 4, 5, 13; §7 T-5.

`AT-198` currently carries: **arm 1** (class total `≤ K` → 0 notices anywhere; total `K+1` → exactly
one), **arm 2** (the `E == K` interior conjunction, shared with `TC-482`), and **arm 3** (the P-6
positive control — an uncut class is not named). §5.1 row 13 itself argues arm 3 is *"distinct from
`AT-198` arms 1–2"* and then binds it to the same id. C-18 requires each `AT-NNN` to map to exactly one
distinct on-disk acceptance node; three arms map to one id or one node maps to three ids.

This also degrades the failure report: `FIX-G` is RED on arms 1 and 3 for two different reasons
(executed above: `n=2` on arm 1, `named=[…, 'modification']` on arm 3) and a single collected node
reports one of them.

**Recommended fold:** split arm 3 into **`AT-200`** (free per §5.1's union check) as the named P-6
positive control, with `FIX-G` as its RED arm and the §7 T-5 arm-3 threshold moved under it. Keep arms
1–2 under `AT-198`. Add the B-1 variant-level control as `AT-201`.

---

## 6. `minor` — m-1: `TC-489`'s stated rationale is only true in its `R = 1` arm

**Where:** §4 `LLR-103.1` first acceptance-criteria bullet; §5.1 row 6; §5.2 (the retirement row);
§9 A-7; §12 X-3 — all of which claim the disjoint arm *"makes `TC-489` a positive control against a
stealth early exit"*.

**Executed** (real per-class early exit that `break`s the leaf loop, not one that skips):

```
--- E=300  geometry=overlapping  N=300  K=200 ---
  SHIP    consumed R=1/8/64 -> [300, 2400, 19200]   consumed==N ? RED
  FIX-A   consumed R=1/8/64 -> [300, 300, 300]      consumed==N ? GREEN
  FIX-A2  consumed R=1/8/64 -> [201, 201, 201]      consumed==N ? RED

--- E=300  geometry=disjoint  N=300  K=200 ---
  FIX-A2  consumed R=1/8/64 -> [201, 300, 300]      consumed==N ? RED
--- E=500  geometry=disjoint  N=500  K=200 ---
  FIX-A2  consumed R=1/8/64 -> [201, 500, 500]      consumed==N ? RED

>>> the exit cannot fire until N > R*K:  R=1 -> 200 · R=8 -> 1600 · R=64 -> 12800
--- E=20000 geometry=disjoint ---
  FIX-A2  consumed R=1/8/64 -> [201, 1601, 12801]   consumed==N ? RED
```

At the spec's own fixture scale (`N = 300` architect / `E = 500` qa) the disjoint `R=8` and `R=64` arms
read exactly `N` under the stealth early exit — **two thirds of the control is dead**. Separately,
`TC-488` (overlapping) already catches `FIX-A2` at **every** `R` (`201/201/201`), so `TC-489` adds no
early-exit detection at all. Its real and defensible value is as a **geometry** control: it catches an
implementation whose R-independence holds only for the overlapping fixture.

**Recommended fold:** either pin `N > R × K` per `R` in `TC-489`'s fixture (needs `N > 12800` at
`R = 64` — expensive), or restate the rationale in §4 / §9 A-7 / §12 X-3 as *"a control that the
R-independence property is not geometry-dependent"*, and move the stealth-early-exit claim onto
`TC-488`, where it is executed-true at every `R`. The confirmed SHIP RED figures `300/2400/19200`
reproduce exactly.

## 7. `minor` — m-2: evidence-checklist row 11 is overclaimed; the catalog's honesty flag was dropped

§13 row 11 asserts *"Every threshold carries executed RED **and** GREEN from **this** tree ✓"*.

- `TC-492`'s `K → 37` re-valuation is an **executed mutation with no transcript**. The catalog was
  explicit about this (`01b-qa-catalog.md:750`, evidence row 11): *"`OBS-cap-constant-quoted` (§5.10) is
  the one whose mutation is **described** rather than run, because the constant does not exist yet;
  **flagged as such rather than claimed**."* The consolidation dropped the qualifier and marked the row
  a flat ✓.
- `TC-490` (`> ADDENDUM_NOTICE_VARIANTS_MAX` → `+N more`) has **no row in §7** and therefore no RED and
  no GREEN. It cannot have one (the constant is `NEW`), which is fine — but it should be flagged, not
  covered by a blanket ✓.

**Recommended fold:** amend row 11 to *"every threshold **whose subject exists on this tree**"* and add
an explicit `NOT EXECUTABLE PRE-FIX — derive at Inc-1` marker to `TC-490` and `TC-492` (and to M-1's
benign direction).

## 8. `minor` — m-3: §7 T-4's golden diff indices are fixture-determined and do not reproduce

`§7 T-4` records `FIX-B` RED **@3**, `FIX-E` RED **@5**, `FIX-G` RED **@10**. Rebuilding `FIX-GOLD`
independently from the catalog's §7.1 dump, this lane measured `FIX-B` **@7**, `FIX-E` **@4**,
`FIX-G` **@10**. The *direction* reproduces perfectly (all three RED, `SHIP`/`FIX-A`/`FIX-A2`/`FIX-H`
GREEN); the indices are a property of the exact fixture, not of the defect.

**Recommended fold:** mark the indices as illustrative in §7 T-4 and forbid any test asserting on the
first-diff index. Inc-1 must re-derive them from the committed golden, not copy them.

## 9. `minor` — m-4: `TC-492` and `TC-497` have no runnable node

`LLR-103.6`'s "Executed verification" is an `rg` invocation; the `K → 37` suite re-run has no named
command or pytest node, and §6.2 lists `TC-492` as `inspection`. `TC-497`'s second half — *"**0**
occurrences of a whole-report-peak closure claim"* — has no pattern to grep and is therefore a human
judgement, not a check. Both are legitimate as **inspection**, but §11's Inc-3 gate says
*"`TC-497` inspection passes"* with no defined pass procedure.

**Recommended fold:** give `TC-492` a concrete command (`pytest -q tests/test_report_addendum_bound.py`
run under a `monkeypatch.setattr(report_service, "MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", 37)`
fixture, i.e. make it a **test**, not an inspection) and give `TC-497` an explicit grep list for the
four residual figures plus a named reviewer for the non-claim half.

---

## 10. Ruling — the `OBS-traversal-early-exit` retirement

**UPHELD, and the spec under-argues its own case.**

The spec's reason (§5.2, §12 X-1) is that `LLR-103.5` needs `{dropped}` and `{variants}`, which a
truncated traversal cannot derive, and that US-B64-2 outranks the optimisation. Sound and correctly
attributed — including the correction of the architect lane's over-stated *"not removable"* claim
(qa executed `consumed = 200` of `E = 4000`; this lane reproduced it: `201` at `R=1`).

This lane found **direct** executed evidence the spec does not cite. Running the spec's own flood
fixture against a real per-class early exit:

```
=== AT-197 threshold as written  (flood = K) ===
  FIX-A2  RED    notices=[]
=== AT-198 arm 1b (class total == K+1 -> exactly 1) ===
  FIX-A2  RED    n=0 []
```

`FIX-A2` emits **no notice at all** on an attack where two variants' `CHG-COLLISION` evidence was
evicted, because it stops iterating before it ever reaches `v2` and `v3`. That is not "cannot derive
the count" — it is "cannot detect that anything was cut". The incompatibility with US-B64-2 is total,
not partial, and `AT-197`/`AT-198` catch it directly without needing the traversal counter.

**Fold (optional, strengthening):** cite this transcript in §5.2's retirement row. It converts the
retirement from a stated trade into an executed impossibility-under-US-B64-2, which is a stronger
record for the postmortem.

The observable is also **not** lost: `consumed == N` (equality, not `≤`) in `TC-488` catches it at every
`R` — see m-1.

---

## 11. `X-2` — CLOSED by measurement

The spec's open obligation: `AT-194`'s adopted GREEN (`1.002`) was measured on `FIX-A2`, which includes
the per-class early exit this document **retires**, so it had never been measured on the implemented
shape (`FIX-A`, no early exit). This lane measured it, at the **shipped surface**, on `082ada9`, with
every fixture built outside the traced window (inherited finding #7), monkeypatching each arm into
`generate_project_report`:

```
--- AT-194 (black-box marginal delta), arm = SHIP (shipped producer) ---
  E= 2000  no_reg=   731170  with_reg=  1195793  delta=   464623
  E= 4000  no_reg=  1447289  with_reg=  2499665  delta=  1052376
  delta ratio E:2000->4000 = 2.265   threshold <= 1.30 -> RED

--- AT-194, arm = FIX-A  (IMPLEMENTED shape, NO early exit)   <-- X-2 ---
  E= 2000  no_reg=   669401  with_reg=   721827  delta=    52426
  E= 4000  no_reg=  1447289  with_reg=  1499633  delta=    52344
  delta ratio E:2000->4000 = 0.998   threshold <= 1.30 -> GREEN

--- AT-194, arm = FIX-A2 (retired shape, WITH early exit) ---
  delta ratio E:2000->4000 = 1.000   threshold <= 1.30 -> GREEN

--- TC-493 (white-box _addendum_lines peak), arm = SHIP ---
  E= 1000  peak=    92936     E= 2000  peak=   184232
  peak ratio E:1000->2000 = 1.982   threshold <= 1.25 -> RED

--- TC-493, arm = FIX-A  (IMPLEMENTED shape) ---
  E= 1000  peak=    21410     E= 2000  peak=    21306
  peak ratio E:1000->2000 = 0.995   threshold <= 1.25 -> GREEN
```

**Both directions, both thresholds, with margin.**

| threshold | shipped tree (must be RED) | conforming `FIX-A` (must be GREEN) | headroom |
|---|---|---|---|
| `AT-194` `≤ 1.30` (T-1) | **2.265** — fails by 74 % | **0.998** — 23 % below the bar | wide |
| `TC-493` `≤ 1.25` (T-3) | **1.982** — fails by 59 % | **0.995** — 20 % below the bar | wide |

The spec's own anti-widening trigger at T-3 (*"if Inc-2 measures GREEN > 1.10, the threshold returns to
Phase 1"*) is **not** tripped: `0.995`. T-1's trigger (*"if GREEN > 1.30"*) is **not** tripped: `0.998`.
`SHIP` reproduces the spec's recorded RED figures to three significant digits (`2.265` vs `2.27`;
`1.982` vs `1.98`), which independently corroborates the qa lane's grid.

**Recommended fold:** close `X-2` in §12 and delete the Inc-2 re-derivation obligation from §11 and
§7 T-1, replacing it with the transcript above and its provenance (Phase-2 qa lane, `082ada9`,
`qa2_memory.py`). Keep the anti-widening rule — it is good policy — but it now has nothing pending.

---

## 12. Checks that PASSED — recorded so the gate is not re-litigated

| check | verdict | evidence |
|---|---|---|
| **`K−1 / K / K+1` fixtures reach the behaviour** | ✅ | executed: `SHIP` `hits=199/200` `notice=False` → GREEN on `hits ≤ K` at `K−1` **and** `K`; `hits=201` at `K+1` and `4000` → RED. The in-domain max of 2 is genuinely escaped. |
| **`E = K` interior asserts BOTH count and marker absence** | ✅ | `TC-482` + `AT-198` arm 2. Executed: `FIX-G` is GREEN on the count-only predicate at every `E` including `K−1`, and RED only on the conjunction (`hits=199 notice=True interior=N`). The conjunction is load-bearing and the spec keeps it. |
| **The `≤ K` bound predicate is not vacuous in-domain** | ✅ | `SHIP` GREEN at `K−1`/`K`, RED at `K+1` — C-31 discharged. |
| **Overlap is actually introduced by the fixtures** | ✅ | all `DeclaredRegion(...)` constructions in `tests/` enumerate to single or disjoint regions (executed sort/uniq) — the landmine is real. `FIX-GOLD` introduces `outer(0x1000-0x2000) ⊃ inner(0x1500-0x1600)`, and `FIX-E` goes RED on it (index 4, executed). |
| **`AT-196` can go RED** | ✅ | `FIX-B` / `FIX-E` / `FIX-G` all RED on an independently rebuilt `FIX-GOLD`; `FIX-A` GREEN. |
| **`AT-198` arm 3 is shaped to the RULE and can fail** | ✅ at the class axis | `FIX-G` RED (`named=['change-file issue','modification']`) while GREEN on `AT-197`, on the bound predicate at every `E`, and on traversal. The measurement the spec cites reproduces. **Fails at the variant axis — see B-1.** |
| **Test homes route around the freeze** | ✅ | `_ENGINE_TEST_FILES` read at `tests/test_tui_directionb.py:5458-5468`: no report test. `report_service.py` absent from `_ENGINE_PATHS`. `tests/test_report_addendum_bound.py` and `tests/goldens/batch64/` are new. |
| **Id space is free** | ✅ | `grep -rn "AT-19[4-9]\|TC-4[89][0-9]" REQUIREMENTS.md tests/` → 0 hits. |
| **Order is pinned by nothing today** | ✅ | `grep -c "Addendum" tests/goldens/batch35/at055b-project-report.md` → **0**; `grep -rn "_addendum_lines" tests/` → **0**; `canonical_report_bytes` exists at `tests/conftest.py:970`. All three spec claims reproduce. |
| **Golden captured pre-fix (C-12)** | ✅ | §11 Inc-1 places the capture before the producer edit, and both lanes flagged it. |
| **Dual traceability, no gaps** | ✅ | §6.2 both tables complete; every `LLR-103.x` appears; every US has ≥ 1 AT. The defects are in the **labels** (M-3) and **cardinality** (M-4) of the mapping, not in coverage. |
| **No unfilled template** | ✅ | no `<…>`, no literal `TC-NNN`, no empty required cell. |
| **No real PII / secrets / credentials** | ✅ | every fixture synthetic; no `examples/` image read; temp trees under `TemporaryDirectory`; worktree unmutated. |
| **Test-results sections left blank** | ✅ | the spec states no Phase-4 result; §6.3 requires `04-validation.md` be filled by execution. |

---

## 13. Consolidation faithfulness — the P-7 audit

16 slugs in, 15 bound, 1 retired. **The union is preserved at the level of slugs. Three lost strength
in the merge:**

| slug | catalog | consolidated | verdict |
|---|---|---|---|
| `OBS-notice-names-cut-variants` (#12) | §5.12 carries an explicit **false-positive boundary**: *"a variant that contributed hits and was not cut (must not appear)"* | prose only in §3's boundary catalog; **no threshold, no id, no RED arm**; the §7 threshold uses `⊇` | **WEAKENED → B-1** |
| `OBS-traversal-R-multiplier-gone` (#6) | §5.6 + §12 row 9: *mechanism-only, **never counted as Layer B*** | promoted to `AT-195`, a Layer-B id, and counted toward US-B64-1's Layer-B obligation | **WEAKENED → M-3** |
| `OBS-notice-reaches-the-file` (#15) | §5.15 + §9: black-box, file **and** TUI seam | demoted to `TC-496` | **WEAKENED → M-3** |
| `OBS-cap-constant-quoted` (#10) | §12 row 11 flags it explicitly as *described, not run* | §13 row 11 flat ✓ | **honesty regression → m-2** |
| `OBS-overlap-membership-preserved` (#3) | §5.3 black-box through the file | bound to `TC-486`/`TC-487` only | cosmetic; covered via `AT-196` — note in §5.1 row 3 |
| the other 11 | — | bound faithfully, several **strengthened** (`TC-486` gains the catalog's named lost hits `0x1800`/`0x2000`; `TC-492` gains the catalog's `K → 37` mutation over the architect lane's grep count; `TC-494` and `TC-496` and `TC-497` are ids the architect lane did not have) | ✅ |

**On the retirement:** upheld, §10. It is the *good* kind of retirement — the reason is stated, the
executed evidence that the optimisation works is retained, and the observable is inverted into a
control rather than deleted. Nothing vanished silently, which is the batch-63 failure mode this
document was written to avoid.

**Net judgement of the merge.** This is a far better consolidation than batch-63's (which dropped 8 of
~18 union observables, 6 silently). Nothing vanished. But the single most important observable in the
batch — the identity of what the operator lost — is the one that came out of the merge weaker than it
went in, and it is weaker in exactly the direction batch-63's `AT-165` was weak.

---

## 14. Exit criteria for this gate

1. **B-1 folded** — `AT-197`'s variant threshold is set **equality**, `FIX-H` is a named RED arm, and
   the variant-level false-positive has its own arm. *Blocking.*
2. **M-1 folded** — `TC-495`'s benign direction restated as *notice-escaping equals hit-line-escaping*,
   or the benign fixture pinned to `[A-Za-z0-9-]`; the false "(qa §5.14)" attribution removed.
3. **M-2 folded** — `AT-197` gains an `R ≥ 2` arm asserting the notice sits under the flooded region's
   sub-section and nowhere else; `FIX-I` named as its RED arm.
4. **M-3 folded** — `AT-195` ↔ `TC-496` re-labelled so every `AT` reads the written file.
5. **M-4 folded** — `AT-198` arm 3 split to `AT-200`; the B-1 control to `AT-201`.
6. **m-1…m-4** folded or explicitly declined **in writing** with a reason (the retirement row in §5.2 is
   the model).
7. **`X-2` closed** in §12 and §7 T-1 with §11's transcript. *Already satisfied by this review — no
   action beyond recording it.*
8. `04-validation.md` filled **by execution**, never from this file's numbers or the spec's.

---

## 15. Evidence checklist (this review)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then or an equivalent observable/mutation/boundary triple | ✓ | reviewing a spec that uses the AT/TC form; every finding names the observable, the mutation, and the boundary |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | every fold in §1-§9 states the exact predicate to write |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | §12 rows 1-5 verify the spec's empty / `K±1` / overlap / hostile-markdown coverage by execution |
| 4 | Regression checklist exists | ✓ | §6.3 of the spec, verified: `_ENGINE_TEST_FILES` has no report test; `tests/goldens/batch35/at055b-project-report.md` carries 0 addendum bytes |
| 5 | Exit criteria stated | ✓ | §14 |
| 6 | No real PII / secrets | ✓ | all fixtures synthetic `SimpleNamespace` / dataclasses; temp dirs auto-removed; export at `…/scratchpad/exp64`, worktree unmutated |
| 7 | Test-results section left blank unless actually run | ✓ | every transcript in this file was executed by this lane; nothing is projected |
| 8 | Layer B — the shipped surface observed with boundary + negative evidence | ✓ | §11 drives `generate_project_report` end-to-end for both arms; §1/§3 read the rendered addendum block; §12 confirms the spec's own Layer-B nodes reach the file |
| 9 | Bidirectional surface-reachability | ✓ | **inputs** driven through the handler: region count, overlapping/disjoint/nested geometry, `E` at `K±1`/`4000`, variant count, class mix, hostile + benign variant ids. **outputs** observed: rendered hit lines, `None.`, the notice line and its parsed `(class, dropped, variants)` triple, whole-report peak delta. Mechanism-only observables labelled as such — which is the substance of M-3 |
| 10 | No unfilled template | ✓ | no placeholders; every finding carries an executed transcript or a `file:line` |
| 11 | Every finding's mutation was EXECUTED, not described | ✓ | `FIX-H` (B-1), `md_safe` grid (M-1), `FIX-I` (M-2), `FIX-A2` real-break traversal (m-1), `FIX-A` at the shipped surface (X-2) — all run in the export |
| 12 | Counterfactuals run in an export, not the worktree | ✓ | `git archive 082ada9` → `…/scratchpad/exp64`; the only file written under the repo is this review |
