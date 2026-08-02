# Phase-2 FINAL RE-GATE — ARCHITECT lane — batch `2026-08-01-batch-77`, revision 4

**Under review:** `01-requirements.md` **revision 4** (749 lines) @ `cf92618`
**Scope:** my three blockers (RC-1/2/3), my two majors (RC-M1/M2), the §6.4a propagation sweep, and rev-4 debris.
Security returned CLEAN and QA returned no blockers on rev 3 — **not re-opened.**
**Method:** rev-4 producer implemented and rendered through the shipped surface; the shipped (unbounded)
producer implemented alongside for the RC-M2 comparison. `PYTHONDONTWRITEBYTECODE=1` (C-46).
Probes: `scratchpad/arch3_rev2.py`, `arch4_rev3.py`, `arch5_rev4.py`.

---

## VERDICT: **1 blocker, 1 major, 1 minor. Both substantive items are EDITS. No design work remains.**

Four of my five items are closed and I verified each by execution rather than by reading. RC-M2's figures
are independently confirmed to the digit. The one blocker is a half-vacuous acceptance arm that needs one
sentence; the one major is a missing measurement that needs one row and one sentence.

**Blunt answer to your question: this batch does not need re-scoping. It needs an edit pass.**

---

## 1 · My five items — status

| # | Item | Status | Proof |
|---|---|---|---|
| **RC-1** | Domain not propagated to `LLR-111.7` / `LLR-111.3` | ✅ **CLOSED** | §2.1 |
| **RC-2** | `HLR-112` had no domain; `LLR-112.2` leaned on withdrawn aggregation | ✅ **CLOSED** — reasoning verified sound | §2.2 |
| **RC-3** | Inc-2's gate vacuous | ⚠️ **HALF-CLOSED** — fixed at 120×30, **still vacuous at 80×24** | §2.3 → **RC4-1** |
| **RC-M1** | BLUF row 7 stale `[50,16]` | ✅ **CLOSED** | §2.5 |
| **RC-M2** | Out-of-domain figures unlabelled / wrong producer | ✅ **CLOSED — figures independently confirmed** | §2.4 |

---

## 2 · Executed transcripts

### 2.1 — RC-1: both children scoped, satisfiable in domain, no falsehood out of it

`LLR-111.7:352` and `LLR-111.3:391` now open *"While the image satisfies `n_runs + n_gaps ≤ bar.region.width`…"*
and each carries an else-clause. `LLR-111.7`'s threshold reads *"every **IN-DOMAIN** suite fixture (16 of the
17 shipped)"*.

- **In domain, satisfiable:** all 16 fixtures, both regimes — `Σ widths = bar` **exactly**, `outside = 0`,
  all runs visible, monotone ∀, strict ∃ (re-confirmed from my gate-2 sweep, unchanged by rev 4).
- **Out of domain, no falsehood asserted:** on `case_08` the else-clause is *"the allocator shall return a
  width for every run without raising"* — executed, no exception at either regime, minimum emitted width 1.
  The old unconditional conjunct A (`1601 ≤ 66` / `1601 ≤ 50`, both **False**) is no longer claimed.

### 2.2 — RC-2: the retained universals are satisfiable, and the new sufficiency argument stands alone

```
RC-2  HLR-112 DOMAIN: n_ticks <= ruler.region.width / label_width (8)
  measured ruler width: 66 @80x24, 50 @120x30
  domain ceiling = ruler_width // 8 = 8 @66 and 6 @50

  retained universals on case_08 out of domain (first + last label):
    first run start  0x00000000 mapped=True
    last mapped byte 0x8030C7C3 mapped=True
    ascending=True unique=True  legible: 2 labels in 50 cols -> 25 cols/tick
```

**The "invariants cost nothing" reasoning holds.** All three retained universals — no unmapped address,
strictly ascending, unique — are satisfiable on `case_08` under the out-of-domain branch, and the retained
pair is legible at 25 columns per tick against an 8-character label.

**The new sufficiency argument stands without the withdrawn aggregation clause.** Its two stated figures
verify exactly (`8 @66`, `6 @50`), and it rests only on `ruler_width ÷ label_width` and on what `1fr` does by
default — silent degradation to zero width, which I reproduced at gate 2 (`N=60, W=50 → 10 zero-width,
0 overlaps`). Nothing in it depends on run counts being lowered by aggregation. **This is a genuine
re-derivation, not a re-wording.**

### 2.3 — RC-3: fixed at 120×30, **still vacuous at 80×24**

```
RC-3  Inc-2 gate: can a real click make the arms NON-VACUOUS?
  (80, 24)  before='Click a region to inspect it - double-click to'
            after ='Click a region to inspect it - double-click to'
            populated by click: False   file-derived content present: False
  (120, 30) before='Click a region to inspect it - double-click to'
            after ='Status: VALID\nCell: 0x00000000-0x0000000E\nRegi'
            populated by click: True    file-derived content present: True
```

Root cause located, and it is **not** an artefact of my patch — reproduced on the **unpatched shipped tree**:

```
UNPATCHED shipped tree (no batch-77 changes at all):
  size=(80, 24)  widget under row0 coords: Container    detail='Click a region to inspect it - double-cl'
  size=(120, 30) widget under row0 coords: RegionRow    detail='Status: VALID\nCell: 0x00000000-0x0000000'

size=(80,24)  row0.region=Region(x=8, y=19, width=66, height=1)  click point=(10,19) -> Container
size=(120,30) row0.region=Region(x=26, y=17, width=50, height=1) click point=(28,17) -> RegionRow
```

At 80×24 the point inside the row's **own reported region** resolves to a `Container`, so the click never
reaches the `RegionRow`. Two click strategies (`pilot.click(RegionRow, offset)` and
`scroll_visible` + `pilot.click(row0, offset)`) both fail; both succeed at 120×30.

**The control-byte limb's fail and pass directions are otherwise both real:**

```
  FAIL direction (today, no LLR-116.7 scrub):
    ESC U+001B survives : True
    CSI U+009B survives : True
    OSC U+009D survives : True
    spans == []         : True
  PASS direction (LLR-116.7 byte-class filter as specified):
    result = 'sensor[31m_evil[red]BADOSC'
    any C0/C1/DEL left  : False
    non-control chars verbatim ('[red]' kept): True
```

This also **vindicates `LLR-116.7`'s byte-class form**: `U+009B` and `U+009D` survive `safe_text` today and a
filter written against `ESC`-introduced sequences would miss both. The *"payload verbatim" →
"non-control characters verbatim"* correction is right — `[red]` is preserved while the control bytes go.

### 2.4 — RC-M2: both producers re-measured independently

```
RC-M2  RE-MEASURE BOTH PRODUCERS on case_08 (independent)

  producer = SHIPPED (unbounded, _BAND_BAR_WIDTH)
    (80, 24)  bar=66  content=1660  invisible=797 of 801 (99.5%)  outside=1594  rows=801
    (120, 30) bar=50  content=1660  invisible=800 of 801 (99.9%)  outside=1600  rows=801

  producer = BATCH-77 (LLR-111.7 bounded)
    (80, 24)  bar=66  content=1601  invisible=768 of 801 (95.9%)  outside=1535  rows=801
    (120, 30) bar=50  content=1601  invisible=776 of 801 (96.9%)  outside=1551  rows=801
```

**Rev-4's corrected figures are confirmed to the digit.** `95.9 %` is the shipping number **at 80×24**;
the shipping number **at 120×30 is 96.9 %** (776 of 801). Both should travel to the post-mortem and to
batch-78 — a single "95.9 %" understates the wide regime by a point.

*"Not made worse — identical"* was indeed wrong and *"measurably better"* is right: **−29** invisible runs
at 80×24 and **−24** at 120×30, with `content` falling 1660 → 1601 and `outside` 1594 → 1535 / 1600 → 1551.
Region-list rows are **801** in all four cells — the else-clause holds under both producers.

Declaring the degradation rule **unspecified** and the figures **observations rather than a contract** is
the correct disposition: my allocator floors every run at 1 column and lets the sum overflow; an
implementation that instead honoured the sum would produce different invisible counts. Nothing in the
requirement picks between them, and rev 4 now says so.

### 2.5 — RC-M1 and the fourth 60-basis sweep

`:32` now reads *"rev-1's `[45,15]` summed to **60** … rev-2's `[50,16]` was the right basis but **the wrong
method** … Through the mandated `LLR-111.7` allocator it is **`[49,17]` @bar=66**"*. Closed.

```
every number summing to 60 (4th pass)
    32  [45,15]     labelled-as-retired: True
   395  [30,30]     labelled-as-retired: True
   396  [45,15]     labelled-as-retired: True
   404  [45, 15]    labelled-as-retired: True
   673  [30,30]     labelled-as-retired: (reconciliation row, carries [33,33]/[25,25] alongside)
   717  [45,15]     labelled-as-retired: True
```

All six carry their basis. No unlabelled 60-basis payload remains.

---

## 3 · BLOCKER

### RC4-1 — Inc-2's gate is still vacuous at 80×24, and the arm does not verify its own precondition

**Where:** §7 Inc-2 gate — *"`AT-B77-15a` + `AT-B77-15b`, **per limb per size**"*, driven by a real
`pilot.click` on the pre-auto-select path.
**Evidence:** §2.3, reproduced on the **unpatched shipped tree**. At 80×24 the click resolves to a
`Container`, `#map_detail_body` keeps `_DETAIL_HINT`, and no file-derived string is rendered.

`AT-B77-15a` asserts the payload renders literal with no spans; `AT-B77-15b` asserts no control byte reaches
the painted strip. With no payload rendered, **both are green on any implementation at 80×24** — which is
precisely the `P-55` vacuity the a/b split was created to fix, surviving at one of the two size arms the gate
explicitly names.

The batch already holds the lesson: **F-1(e)** records *"the R-6 probe's `pilot.click` did not land …
`AT-B77-13`/`14` must assert their own precondition — a setup gesture that silently misses turns a gate into
a tautology."* That rule was applied to `AT-B77-13`/`14` and not carried to the new Inc-2 arms — the same
propagation miss the revision is named after.

**Fix — one sentence, an EDIT:** require the Inc-2 arms to assert the precondition (that `#map_detail_body`
actually names the hostile payload) **before** the safety limbs, and to fail loudly rather than pass when the
gesture does not land. If 80×24 cannot be driven by a click at all, the arm must say so and use whatever
route does populate the inspector there — but it must never assert safety over a strip it never populated.

---

## 4 · MAJOR

### RC4-2 — `HLR-112`'s domain membership was never measured, and `prg.s19` falls outside it

**Where:** `HLR-112:216` domain `n_ticks ≤ ruler.region.width ÷ label_width`; the ⭐ callout at `:217`
discusses **only** `case_08`; sweep rows 607/608.
**Evidence:** §2.2 and:

```
  fixture                                          runs  n_ticks  in@66  in@50
    case_00_public/prg.s19                         14    15       False  False   <== OUT
    ... 15 other shipped fixtures                  2–5   3–6      True   True
    case_08_heavy_fragmentation/firmware.s19       801   802      False  False   <== OUT
```

**`prg.s19` — the batch's showcase fixture, the one `LLR-111.7`'s threshold names specifically, the one every
`HLR-111` demonstration uses — is out of `HLR-112`'s domain at both regimes**, needing 15 ticks against a
ceiling of 8 and 6. The document never says so; its callout names only `case_08`, and a reader would
reasonably conclude `case_08` is the sole exclusion.

Nothing stated is false, and the out-of-domain branch is satisfiable, so this is not a blocker. But two
consequences matter:

1. **`AT-072b` carries the in-domain clause** *"∧ no elided tick"*. Run on `prg.s19` it would go **RED on
   correct code**. The trap is latent, not live — `test_at072b_ruler:129` uses `_load_case_02()` (4 runs →
   5 ticks, in domain) — but Inc-4 will re-derive that node and `prg.s19` is the obvious fixture to reach for.
2. **US-77-2's delivered outcome on the showcase fixture is weaker than the story implies.** Every emitted
   label still names a mapped address, so the invariant holds; but the operator sees at most 8 of 15 run
   starts at 80×24 and 6 of 15 at 120×30.

**This is also the C-31 answer on §6.4a.** The sweep's row set is **hand-listed, not derived** — 32 rows the
author enumerated, all inside one file. Rows 607/608 verify that `HLR-112`'s domain clause *was added*;
**no row asks what the new domain excludes.** For `HLR-111` the author did measure membership (16 of 17);
for `HLR-112`, added a revision later, membership was never measured. That asymmetry is the tell, and it is
how `prg.s19` fell out unnoticed. **A derived row set would ask, for every domain introduced: which fixtures
does it admit, and is any artefact of this batch built on one it excludes?**

**Fix — one row and one sentence, an EDIT:** state `HLR-112`'s membership (15 of 17 in domain; `prg.s19` and
`case_08` out), name an in-domain fixture for `AT-072b`'s legibility clause, and add a *domain-membership*
row to the sweep so the next domain gets measured rather than merely inserted.

---

## 5 · MINOR

**Rm — §6.4's `arch B-1/B-2` reconciliation row (`:647`) still records the landed body edits as
*"§4 `LLR-111.7`/**.8**/.9; `AT-B77-17`"***, both withdrawn. Carried unchanged from my gate-3 review. It is a
historical row and the R-10 row at `:667` supersedes it, so it misleads rather than instructs — but it
survived the sweep because **no sweep row covers §6.4's own historical rows**, which is a small instance of
the same hand-listed-row-set point.

---

## 6 · Rev-4 debris check — clean

| Check | Verdict | Evidence |
|---|---|---|
| §5.3 restored correctly | ✅ | Carries the frozen-engine dual guard, `TC-011`, the 2514/2/3 FULL baseline, 0-blockers-at-merge, the four labelled AT exceptions, and a descope-specific clause. **It also discloses that the deletion was accidental** — the right way to record it |
| `LLR-116.7` byte-class `shall` | ✅ | `:478` names C0 `U+0000`–`U+001F`, DEL `U+007F`, C1 `U+0080`–`U+009F`, *"as a byte CLASS, not by matching an escape-sequence pattern"*; `:479` names `U+009B` (single-byte CSI) and `U+009D` (single-byte OSC). **Executed: both survive `safe_text` today**, so the normative byte-class form is load-bearing, not decorative |
| Orphaned / unreachable acceptances after the Inc-2 change | ✅ **none** | `AT-B77-01…16` + `AT-B77-18` all owned in §7 (slash-notation groups `05/06/07`, `11/12/13/14`, `15a/b`); `AT-B77-17` withdrawn and its id not reused |
| Increment file counts | ✅ | 4 / 3 / 3 / 4 / 5 / 4 / 4 / 4 / 1 — all ≤ 5 |
| Live dangling `LLR-111.8` reference | ✅ **0** | Census of all 17 occurrences: withdrawal record, struck rows, sweep rows, charter, quoted retraction, historical log. The rev-3 dependency in `LLR-112.2` is genuinely gone |
| `should` / `debería` | ✅ **0** | |
| Two security minors | ✅ | `LLR-117.2` excludes inverting text style; the byte-class filter is normative |

**On the sweep's external scope:** I checked `PLAN.md`, `.dev-flow/state.json` and
`.dev-flow/BACKLOG-CODE.md` for R-9/R-10 residue. `PLAN.md` is clean. `state.json` carries R-7 as
*"widen the bar first, then aggregate"* and R-9's `+N more` note — but those are **accurate records of what
was ruled at the time**, and R-10 has its own entry at `:146`. A decision log is supposed to keep superseded
entries. **Not a finding** — I raise it only to say I looked, because the sweep's one-file scope invited it.

---

## 7 · What I am NOT flagging

- **The propagation sweep as a control.** It is the right mechanism, it caught a real residue (`P-50`'s
  disposition) that would otherwise have cost a fourth round, and recording the bad probe alongside the true
  failure is exactly the honesty this batch has been converging on. RC4-2 is one missing *kind* of row, not
  a verdict on the sweep.
- **`HLR-112`'s domain design.** Applying `HLR-111`'s pattern was right, and the retained/scoped split is
  well judged — I verified the retained universals are satisfiable rather than taking the "costs nothing"
  claim on trust.
- **The `LLR-112.2` sufficiency re-derivation.** Genuinely independent of aggregation; verified.
- **RC-M2's disposition.** Naming the producer, declaring the degradation rule unspecified, and demoting the
  figures to observations is the correct handling of a number that had been reported wrong three times.
- **Anything QA or security cleared on revision 3.** Not re-opened.

---

## 8 · Disposition — edit or design work?

**Both remaining items are EDITS. Neither reopens a ruling. No design work remains.**

| # | Fix | Kind | Size |
|---|---|---|---|
| **RC4-1** | Inc-2's arms assert their precondition before the safety limbs and fail loudly if the gesture does not land | **edit** | one sentence in §7 + `LLR-116.6`'s acceptance |
| **RC4-2** | State `HLR-112`'s domain membership (15 of 17; `prg.s19` and `case_08` out), name an in-domain fixture for `AT-072b`'s legibility clause, add a domain-membership row to §6.4a | **edit** | one row, two sentences |
| Rm | Correct §6.4's `arch B-1/B-2` row | **edit** | one row |

**Recommendation:** one edit pass, then approve. RC4-1 is the only item I would insist lands before Phase 3
begins, because it is an acceptance that would ship green over an unexercised code path at one of the two
supported terminal sizes — the defect class this batch has spent four rounds eliminating. RC4-2 can land in
the same pass; if it did not, the concrete risk is that Inc-4 writes `AT-072b` against `prg.s19` and it goes
RED on correct code.

---

## 9 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| RC-1 verified by execution, in and out of domain | ✓ | §2.1 |
| RC-2 retained universals tested on `case_08`, not assumed | ✓ | §2.2 — first/last mapped, ascending, unique, legible |
| RC-2 new sufficiency argument checked for independence from aggregation | ✓ | §2.2 — ceiling 8/6 measured; rests only on ruler width ÷ label width |
| RC-3 checked in **both** directions | ✓ | §2.3 — fail (ESC/CSI/OSC survive) and pass (filter removes, `[red]` kept) |
| RC-M2 both producers re-measured independently, not accepted | ✓ | §2.4 — all eight cells |
| RC-M1 + fourth 60-sweep | ✓ | §2.5 — 6 occurrences, all basis-labelled |
| C-31 applied to §6.4a: row set derived or hand-listed? | ✓ | §4 — **hand-listed**; uncovered surface found (domain membership) |
| Uncovered dependent surface actually demonstrated, not asserted | ✓ | §4 — `prg.s19` 15 ticks vs ceiling 8/6, executed across all 17 fixtures |
| Rev-4 debris checked | ✓ | §6 — §5.3, `LLR-116.7`, orphans, file counts, dangling refs |
| External surfaces checked and honestly dispositioned | ✓ | §6 — looked, found nothing that is a defect, said so |
| Edit-vs-design stated bluntly | ✓ | §8 — both edits |
| Nothing manufactured | ✓ | §7 |
