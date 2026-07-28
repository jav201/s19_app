# batch-64 — Phase-2 RE-GATE: SECURITY lane

**Reviewer:** the lane that filed `02-review-security.md` (BLOCK, S1 blocker + S2–S5 major + S6 minor).
**Base:** `claude/batch-64-addendum-producer-bound` @ `b09ae9a`.
**Under re-gate:** `.dev-flow/2026-07-28-batch-65/01-requirements.md` **revision 2** (2620 lines).
**Scope:** narrow. (1) discharge of my own six findings; (2) new defects planted by what revision 2
CHANGED. I did **not** re-litigate the `LLR-103.2` soundness clearance, the notice's
unforgeability/non-leakage clearance, or the F2 non-claim — all cleared at the first gate and unchanged.

**Probe discipline.** Every counterfactual ran in a `git archive HEAD s19_app tests examples` export at
`…/scratchpad/b64regate`. In the worktree, `git status --porcelain` is **empty** and
`git diff --numstat origin/main -- s19_app/ tests/` is **empty** — no production source touched.

---

## 1. BLUF — verdict: **OK to ship. Unconditional.**

**All six findings are CLOSED. None partially.** No new blocker, no new major. Five LOW/nit observations
follow the table and none of them gate.

I am stating this without a condition, without a requested signature, and without a risk acceptance.
The S1 blocker was a requirement asserting a bound the design does not provide; revision 2 does not
accept that risk, it **retracts the claim, names the residual with both lanes' numbers, and builds the
oracle that was missing**. That is a fix, not an acceptance, so there is nothing left to sign.

Two rulings the re-gate was specifically asked for, up front:

- **I SUSTAIN the rejection of my S5 fold 2.** The stated reason is factually correct on disk and my
  original finding was over-general. Detail at §4.
- **`screens_directionb.py:1889` is NOT a second live defect.** Its range set **cannot** overlap — proven
  by construction and by execution (206 fixtures, 0 overlapping pairs; 89 032 addresses swept, 0
  attribution mismatches). Detail at §5.

---

## 2. Discharge table

| # | finding | orig. severity | verdict | evidence |
|---|---|---|---|---|
| **S1** | `R-TUI-098` over-claims on the traversal-cost axis; the `R` multiplier is relocated into `LLR-103.2`'s attribution walk where no acceptance looks | **blocker · HIGH** | **CLOSED** | G-1 arm (a) + G-2 both landed. Statement narrowed to *"whose **candidate consumption** is independent of the declared-region count"* (`:332`); **non-claim (e)** (`:356-363`) carries `500 / 4000 / 32000 / 128000` **and** my `153 600 @ R=512` / `19 200 @ R=64`; §14 diagram now `O(V x E x (log R + A) + R x 3K)` with `A` drawn as a labelled cost **on the hot path** (`:2411-2416`); §7 **T-9** new; §10.7 new residual; **`TC-498`** new, with `A` given a *defined term* (§1.3 `:144`) and a *named instrument* (`LLR-103.1`: *"counts region comparisons at the attribution call"*, `:591-592`) — the second counter my G-1(b) said `AT-195` could not express; `TC-497`'s verbatim set gains `500 → 128000` (`:380`); `BACKLOG-CODE.md` carry stated (`:2178-2180`); §15 item 7 = named reversal trigger. **Completeness checked, not assumed:** `grep` for every surviving *"independent of R / the declared-region count"* string returns 6 live sites — 3 narrowed to candidate consumption, 2 explicit disclaimers, 1 fixture note. **No stale work-axis claim survives anywhere in the document.** |
| **S2** | *"the affected variants"* vs the cap of 8 | major · MED | **CLOSED** | All three parts. `R-TUI-098` Statement (`:336-337`) and `HLR-103` Statement (`:396-397`) both narrowed to *"up to `ADDENDUM_NOTICE_VARIANTS_MAX` of the variants … with an explicit count of the remainder"*; **non-claim (f)** added (`:364-369`) with my executed `affected = 20 → v1…v8, +12 more`; §10.9 new. Selection order **pinned twice** — `LLR-103.5` Statement *"in first-drop traversal order"* (`:817`) and §10.9 (`:2212-2213`). The cap is kept, as I endorsed. |
| **S3** | notice predicates not decidable by counting `> TRUNCATED:` | major · MED | **CLOSED** | All three parts, and part 3 came back **stronger than I asked for**. Predicate rebound to `ADDENDUM_TRUNCATION_NOTICE_FMT`'s rendered shape, class alternation built from `ADDENDUM_CLASS_LABELS`, *"never from a literal"*, scoped **between the `## Addendum: declared regions` heading and the next `^## `** (`:486-512`, restated at `:1377-1379`). The three emitters recorded with my firing table (`:489-499`) and in §12 **X-9** (`:2356`). **`TC-499`** created (`:1432-1435`): the fixture must read **0** addendum notices **and ≥ 1 report-wide `> TRUNCATED:` line** — the second clause is theirs, and it is what stops the control passing vacuously by simply never firing `:1134`. Re-verified on disk: `grep -n TRUNCATED report_service.py` → `:1134`, `:1383`, `:1403` (+ docstring mentions `:29`, `:1317`, which revision 2 lists and I had missed). |
| **S4** | §10.5's consumer carry copied from a docstring | major · MED | **CLOSED** | §10.5 rewritten as the executed census verbatim (`:2096-2132`). The live consumer is now named correctly — `changes/apply.py:438 _linkage_index` / `:470 _first_intersecting_symbol`, own copy of the shape at `:513-520` — **re-verified on disk** (`_linkage_index` def `:438`, index build `:465`, `_first_intersecting_symbol` def `:470`, `bisect_right` `:513`). `validation/engine.py` and `tui/hexview.py` are **CLEARED and the blanket withdrawn in writing** (`:2129-2130`). `report_filter.py:598 _merge_ranges` / `:737` cited as the precedent Phase 3 must reuse — **both verified on disk**, and `LLR-103.2` now *requires* reuse or a docstring reason (`:677-683`). Re-executed: the defect is still live (probe P3 below). |
| **S5** | §10.4 overstates the residual; §8.3 never prices the cheap prevention | major · MED | **CLOSED** (folds 1 + 3 in full; fold 2 rejected — **rejection sustained**) | Fold 1: §10.4 rewritten (`:2051-2088`) with all four of my transcripts and the residual **renamed** to *"suppression of the SEVERITY SIGNAL — not of the evidence's existence"*. Fold 3: §8.2 now carries severity-priority admission as a **priced** row with three reasons (`:1488`, `:1491-1509`) and §8.3 says *"**Two** alternatives … priced … and rejected"*. Fold 2 rejected at §17.4 / §12 X-8 with executed reasons and a MED backlog carry covering **both** fold 2 and fold 3's implementation. **The pricing in reason 2 is correct** — analysis at §4. |
| **S6** | §10.3's `11.6 kB/region` measured with no cap firing | minor · LOW | **CLOSED** | §10.3 now a **range table** (`:2026-2029`): `≈ 11.6 kB/region` no-cap vs `≈ 20 kB/region` all-three-caps-firing at `ADDENDUM_NOTICE_VARIANTS_MAX` with worst-case escaped ids, carrying my `+8.3 kB/region`. Both rows labelled **lower bounds** with the reason each is a lower bound, and revision 1's single figure explained rather than quietly replaced. |

**Gate conditions G-1 … G-6 from the first gate: 6 of 6 discharged.** My one non-gating note (`TC-495`'s
benign-direction fixture false-failing on `variant_A-1`) was also folded, via QA-M-1, and the fix chosen
— *notice-rendering == hit-line-rendering, byte for byte* — is better than the fixture swap I suggested,
because it cannot false-fail on **any** id rather than on one hand-picked id.

---

## 3. The three rulings on S1's fold

### 3.1 The disclosure-counter reasoning is **SOUND**

`TC-498` asserts `A == R × N` under `huge+tiny` as a recorded value, not a pass/fail bound. The argument
for refusing the bound form is correct on both halves:

- **`A ≤ c × (N + hits)` genuinely cannot pass.** Under `huge+tiny` the output is `R`-independent — one
  region matches at every `R` (architect: `matches = 1` at `R = 1/8/64/256`; mine: `emitted hits = 300` at
  every `R`). So `N + hits` is **fixed** while `A = R × N` grows without bound in `R`. No constant `c`
  exists. Writing that bound would produce either a permanently-RED test (unshippable) or a `c` large
  enough to be vacuous — and a vacuous bound is the exact defect the batch is repairing.
- **`A == R × N` is falsifiable in both directions.** A regression to worse-than-`R × N` fails it; a
  structural *improvement* also fails it, **by design** (§15 item 7, §11.1 `:2299`), forcing §10.7 and
  non-claim (e) to be rewritten rather than left silently over-claiming in the other direction. That is a
  characterization oracle, and it is the correct instrument for a residual you are disclosing rather than
  fixing.

The instrument is specified, which is what makes this more than a slogan: `A` is a **defined term**
(§1.3 `:144` — *"the number of `(candidate, declared-region)` comparisons performed by the attribution
walk of `LLR-103.2`, summed over the call"*) and the counter has a **named site** (*"at the attribution
call"*). Revision 1's failure was not that it chose the wrong threshold — it had **no term** for this
quantity, which is why it had no oracle. Revision 2 names the quantity first. That is the right repair
order.

### 3.2 Pinning the prefix-max array is **HONEST**, not a blessing of the defect

I looked for the three things that separate an accepted reversible choice from a laundered defect. All
three are present:

1. **The residual is quantified and named** — §10.7, two lanes, two fixtures, same law, with the
   attacker model stated precisely (operator owns `R`, attacker owns the addresses, one enclosing region
   suffices).
2. **The alternative is named with its cost** — max-segment-tree over `ends`, `O((1 + k) log R)`,
   `LLR-103.2` `:684-700`, with the tradeoff argued rather than asserted.
3. **The reversal has a written trigger and an oracle that fires on it** — §15 item 7, and `TC-498`
   *"**will fail** — which is by design"*.

It would have been a blessing if the array were pinned **without** §10.7, or if §10.7 existed **without**
`TC-498`. Neither is the case. And the pin is itself a security improvement over revision 1: revision 1
said only *"prefix-max-of-ends structure"*, which admits both structures, so an implementer could have
shipped either and the document would have been silently wrong about §10.7 in one of the two worlds.
`LLR-103.2` `:698-700` says this in the document's own words — *"§10.7 is an accepted implementation
choice, not an inherent limit of the problem. An output-sensitive structure removes it. Revision 1 could
not say which, because it had not chosen."*

The one weak spot is the trigger's form, not its existence — see N3.

### 3.3 The `all-nested` carve-out is correct and worth keeping

§7 T-9 and §10.7 both record that under `all-nested` the `R × N` work is **output-proportional and
irreducible**, forced by `LLR-103.5`'s per-(region, class) `{dropped}` obligation, and warn that an
implementer who "optimises" it breaks the dropped counts. This is a real trap and revision 1 did not
have it. It also correctly explains why my `TC-488` observation (*"`R` comparisons produce `R` output
lines, which is legitimate"*) is not the same defect as `huge+tiny`.

---

## 4. S5 fold 2 — **I SUSTAIN THE REJECTION**

I was asked to verify reason (a) against the model on disk and to say so if I still believed the
finding. I verified it, and I do not.

**Executed** (`probe_regate.py` P2, in the export):

```
P2  SEC-S5 fold 2 rejection reason (a): does ChangeSummaryEntry carry a severity?
  dataclasses.fields(ChangeSummaryEntry) ->
     - entry_type
     - address_start
     - address_end
     - before_bytes
     - after_bytes
     - disposition
     - linkage
     - linkage_symbol
  'severity' in field set : False
  any field containing 'sev' : []
  ChangeSummaryEntry.__slots__ : ['entry_type', 'address_start', 'address_end', 'before_bytes',
                                  'after_bytes', 'disposition', 'linkage', 'linkage_symbol']
  ValidationIssue fields : ['code', 'severity', 'message', 'artifact', 'symbol', 'address',
                            'line_number', 'related_artifacts', 'details']
  'severity' in ValidationIssue : True
```

`s19_app/tui/changes/model.py:321` `ChangeSummaryEntry` — `@dataclass(slots=True)`, 8 fields, **no
severity**, and `grep -n severity` over the module returns hits only in `ChangeSummary`'s
`ValidationIssue` handling. The field set §17.4 lists matches the disk **exactly**.

**My finding was over-general and the rejection is right.** I wrote *"Severity is available at the
admission point"* on the strength of probe D3, which sampled a `ValidationIssue`. That is true for hit
classes 1 and 2 and **false for class 3**. A histogram would have to branch by class and print an empty
or meaningless bucket for `modification` — a notice field that is undefined for a third of what it
describes is worse than no field, in a document whose entire purpose is to be trustworthy about what it
cut. Reason (b) (widening `AT-197` to a quadruple in the same revision that repairs its identity
predicate) is also sound: the node under repair is the wrong place to add an unvalidated dimension.

**The rejection is also handled the right way procedurally**, which matters as much as the reason:
the underlying point is *accepted and recorded* (§10.4 renames the residual to suppression of the
**severity signal**), it is carried at MED with the analysis attached, and it is a named row in §8.3's
*"does not do"* table — so it cannot vanish. A rejected finding whose substance is recorded three times
is not a dropped finding.

### The §8.2 pricing of severity-priority admission is **CORRECT**

I was asked to rule on this specifically. The claim is that prevention on the severity axis costs the
`V`-independence claim on the memory axis. It does.

- **Under first-`K` admission with `variant_results` outermost**, a candidate's dropped/admitted status
  is decided at the moment it is examined, and all of a variant's candidates for a given (region, class)
  are **contiguous** in traversal order. So an `O(1)` per-(region, class) last-seen sentinel is
  sufficient to emit both the distinct named list and the `+N more` count.
- **Under severity-priority admission**, an already-admitted hit can be **evicted later** by a
  higher-severity arrival. The evicted hit's variant becomes affected *after* later variants have already
  been recorded, so additions are no longer contiguous per variant. Deduplicating the distinct-affected
  count then requires a **membership set** of up to `min(V, drops)` identifiers per (region, class) —
  `O(R × 3 × V)` resident, which puts `V` back into the exact bound `LLR-103.3` exists to establish.
- Reason 3 is correct too: emitting in document order after severity-ranked admission needs a stored
  document index per admitted hit plus a sort at emission — extra resident state in a change whose
  purpose is to shrink resident state.

§15 item 9 states the consequence properly for a future batch (*"`LLR-103.3`'s `V`-independence claim
must be **re-derived, not assumed**"*) rather than leaving it to be rediscovered. One wording nit at N4.

---

## 5. `screens_directionb.py:1889` — **NOT a second live defect**

§10.5's census row for this consumer reads *"NO — runs are documented and constructed disjoint"*, and
that cell was the weakest evidence in a table whose whole point is that a docstring is not evidence
(the sentence is mine, carried verbatim from my first-gate table, where it rested on the docstring).
It is nonetheless **correct**, and here is the proof it was missing.

**The construction.** `_a2l_region_symbol_counts` (`screens_directionb.py:1886-1898`) builds
`region_ranges = [(start, start + run_bytes) for _band, run_bytes, start in runs]` over
`_merge_band_runs` output, then attributes each hit with the one-candidate shape
`slot = bisect_right(starts, addr) - 1` — the same shape that is wrong in `apply.py`. It is safe here
because the range set cannot overlap, and that is forced by two invariants, not by convention:

1. `compute_entropy` (`entropy_service.py:258-275`) emits `sample_count = window_end - window_start`
   and steps `window_start = window_end` within each range from `_derive_ranges(mem_map)` ⇒ windows tile
   each range **disjointly and ascending**, and `end - start == sample_count` **by construction**.
2. `_merge_band_runs` (`screens_directionb.py:430-484`) extends a run **only** on
   `run_start + run_total == window.start` (exact adjacency) and starts a new run on a band change **or**
   an address discontinuity ⇒ a run's `summed_bytes` equals its span exactly, and the next run starts at
   or after the previous run's end.

**Executed** (`probe_regate.py` P1/P1b/P1c, in the export):

```
P1  screens_directionb.py:1889 - CAN the region_ranges set overlap?
  single contiguous 4k constant                runs=   1  overlapping pairs=0  out-of-order=0
  alternating bands, ADJACENT windows          runs=  16  overlapping pairs=0  out-of-order=0
  40 fragmented blocks, same band, gaps        runs=  40  overlapping pairs=0  out-of-order=0
  overlapping-ish strides, partial final windows runs= 12  overlapping pairs=0  out-of-order=0
  single-byte islands                          runs= 200  overlapping pairs=0  out-of-order=0
  two touching same-band blocks                runs=   1  overlapping pairs=0  out-of-order=0
  randomised sweep                             (200 cases)  overlapping pairs=0  out-of-order=0
  TOTAL overlapping pairs across ALL 206 cases: 0
  TOTAL out-of-order pairs  across ALL 206 cases: 0

P1b  the invariant that forces disjointness (checked, not assumed)
  windows with sample_count != (end - start), or overlapping a successor : 0
  runs where run_start + run_bytes  >  next run_start                    : 0

P1c  the :1889 bisect_right-1 attribution vs ground truth
  addresses swept: 89032   attribution mismatches vs ground truth: 0
```

**Verdict: CLEARED, now on a construction proof rather than a docstring.** The `partial final windows`
and `two touching same-band blocks` cases are the two that would have broken it (a window whose
`sample_count` under-reports its extent, and a merge that must extend across an exact boundary); both
are clean. `§10.5`'s row is right; only its evidence column was thin, and this section supplies the
missing half. Non-gating — see N-obs at §6.

**By contrast, `apply.py` is still live.** Executed:

```
P3  SEC-S4 carry: is apply.py::_linkage_index STILL the live at-risk consumer?
  addr=0x5000   probe=(False, None)          truth=['BIG_ARRAY']              WRONG
  addr=0x2008   probe=(True, 'INNER')        truth=['BIG_ARRAY', 'INNER']     partial
  addr=0x1000   probe=(True, 'BIG_ARRAY')    truth=['BIG_ARRAY']              ok
  addr=0x8FFF   probe=(False, None)          truth=['BIG_ARRAY']              WRONG
  -> a candidate inside the ENCLOSING range only is reported as NO LINKAGE.
```

§10.5 points at the right consumer, at the right severity (MED), with the right note (**own copy of the
shape ⇒ a `range_index.py` unfreeze would not repair it**).

---

## 6. New-defect check on what revision 2 CHANGED

I checked the four highest-risk changed surfaces. **No new blocker, no new major.** Five LOW/nit items:

| # | observation | sev | where |
|---|---|---|---|
| **N1** | **Freeze-set citation is off by one.** Revision 2 cites `tests/test_engine_unchanged.py:122` for `range_index.py` being engine-frozen, at two sites in **rewritten** text (§10.5 `:2093`, `LLR-103.2` `:666`). Executed: `_ENGINE_PATHS` opens at `:120`; `:121` is `core.py`, **`:122` is `hexfile.py`**, `range_index.py` is at **`:123`**. The *fact* is right (it is frozen); the *pointer* is wrong, in a fold whose lesson was "cite what you verified". | LOW | non-gating |
| **N2** | **`HLR-103`'s threshold bullet leads with the form that was NOT adopted.** `:416` opens *"**region ops `A ≤ c × (N + total_hits)`**"* in bold and only then disclaims it as *"not a pass/fail gate"*, deferring the real assertion to §7 T-9. A reader skimming the "Numeric pass threshold" list — which is what a gate reader reads — sees a criterion the spec does not use. Suggest leading with the adopted form: *"region ops `A` recorded and asserted `== R × N` at `R ∈ {1,8,64,256}` under `huge+tiny` (disclosure counter, §7 T-9)"*, and keeping the `c`-bound as the stated-and-rejected alternative underneath. | LOW | non-gating |
| **N3** | **§15 item 7's reversal trigger is a field complaint, not a measurable threshold** — *"measured to matter in the field … and reporting a slow report"*. Every other reversal trigger in §15 is structural or numeric. A residual whose reversal depends on a user complaining is one nobody owns. Suggest adding a measurable arm, e.g. *"or `R × N` on a real project exceeds ⟨n⟩ ops"*. Mitigated by §10.3's carry, which correctly notes that **capping `R` bounds §10.3 and §10.7 in one change** — so a prevention path is already named and carried. | LOW | non-gating |
| **N4** | **§8.2 reason 2's "monotone" is the wrong word.** *"the affected-variant set is not monotone in traversal order"* — the set is still monotone (it only ever grows); what eviction destroys is **per-variant contiguity**, which is what the `O(1)` last-seen sentinel actually depends on. The conclusion (`O(V)` membership set) is correct; only the term is loose, and a future batch reading §15 item 9 will need the precise reason. | nit | non-gating |
| **N5** | **The same figure is rendered two ways, and one gate greps for it.** `19200` (13×) and `19 200` (7×) both appear; `TC-497` demands the literal `19200 → 300` in `REQUIREMENTS.md` + the PR body, while §10.7 and non-claim (e) write `19 200`. `500 → 128000` is consistent (`128 000` never appears). The grep list at `:378-381` is explicit enough that an implementer copying from it is safe — flagged only so the `REQUIREMENTS.md` author copies from the code block, not from the prose. | nit | non-gating |

**What I checked and found clean:**

- **The escaping pin (`LLR-103.5` `:876-886`).** Escaping `result.variant_id` **at the recording site
  inside the traversal** stores an already-escaped string; nothing re-escapes it, and `TC-495`'s
  *notice-rendering == hit-line-rendering* equality catches any divergence from the hit lines. The larger
  resident string this implies (worst-case escaped id `1024` chars at `REPORT_CELL_CHARS = 512`) is
  exactly what §10.3's new `≈ 20 kB/region` row prices — the two folds are **consistent with each other**,
  which is the thing a two-place amendment usually gets wrong.
- **§17.5 correction 1, verified on disk.** `("md_safe", "result.variant_id"): "planted (variant_id, 7 sites)"`
  **is** already an entry in `_ESCAPED_EXPRESSIONS` (`tests/test_report_field_census.py:344`), and the
  census key **is** `(node.func.id, ast.unparse(node.args[0]))` (`:362-364`). The correction is right,
  and revision 2 folding the finding **anyway** — pinning the spelling *and* owning the file — is the
  correct call: a spec must not leave a guard's verdict to an implementer's incidental spelling.
- **`AT-197` set-equality (A-12) vs the cap of 8 (A-13).** No contradiction planted: `AT-197`'s fixture
  has 2 affected variants, well under `ADDENDUM_NOTICE_VARIANTS_MAX`, and the `> 8` behaviour is covered
  by `TC-490` + non-claim (f).
- **`+N more` counting under the new *"exactly those variants that contributed at least one DROPPED
  hit"*** (`LLR-103.5` `:815-819`). Still `O(1)`: variant-major traversal keeps a variant's drops
  contiguous, so last-seen sentinel + a remainder counter suffices. Consistent with `LLR-103.1`'s M-2
  invariant and with §14's `A7` node. No `V` term reintroduced.
- **No new external surface.** Unchanged from the first gate: four module constants, a coalescing helper,
  one rewritten private producer, all inside `report_service.py`; one import of a frozen module, which
  the `git diff --name-only` guards cannot trip. No file, socket, or subprocess opened. `range_index.py`
  read-only.
- **Fold completeness across the document, not just at the headline site** — the `grep` in the S1 row.
  This is the check that most often turns a "closed" into a "partially closed", and it passes.

---

## 7. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | §2 discharge table (per-finding evidence with `file:line`), §6 N1–N5 each with a suggested fix |
| 2 | Each finding has a severity rating | ✓ | §2 carries the original severity; §6 rates each new observation LOW/nit |
| 3 | **No secret value appears in this output** | ✓ | no `.env`, key, token or credential read or quoted; only `s19_app/` + `tests/` source lines, `.dev-flow/` spec lines, and synthetic in-memory fixtures |
| 4 | Verdict explicit and **unconditional** | ✓ | §1 — **OK to ship**. No signature requested, no risk acceptance required, no condition attached |
| 5 | Every one of my six findings ruled CLOSED / PARTIAL / NOT CLOSED | ✓ | §2 — **6 CLOSED, 0 partial, 0 open** |
| 6 | S1's disclosure-counter reasoning judged | ✓ | §3.1 — **sound**, with the proof that no constant `c` exists |
| 7 | Pinning the array judged honest vs blessing | ✓ | §3.2 — **honest**; three separating criteria checked, all present |
| 8 | S5 fold-2 rejection verified against the model on disk | ✓ | §4 — **sustained**; `dataclasses.fields` executed, 8 fields, no severity |
| 9 | §8.2's `O(1) → O(V)` pricing judged | ✓ | §4 — **correct**; contiguity, not monotonicity, is what eviction destroys (N4) |
| 10 | `screens_directionb.py:1889` overlap determined | ✓ | §5 — **cannot overlap**; 206 fixtures / 0 pairs, 89 032 addresses / 0 mismatches, plus the two structural invariants |
| 11 | S4's corrected carry re-verified on disk | ✓ | §2 S4 row + §5 P3 — `apply.py:438/:465/:470/:513`, `report_filter.py:598/:737`, all confirmed |
| 12 | New-defect check on changed surfaces | ✓ | §6 — 4 surfaces checked clean, 5 LOW/nit raised, 0 blocker, 0 major |
| 13 | Executed probes paste **real** output | ✓ | §4 P2, §5 P1/P1b/P1c/P3 — every block copied from a run, none reconstructed |
| 14 | Counterfactuals ran in an **export**, never the worktree | ✓ | `git archive HEAD s19_app tests examples` → `…/scratchpad/b64regate`; worktree `git status --porcelain` empty, `git diff --numstat origin/main -- s19_app/ tests/` empty |
| 15 | New tool/integration scope + blast radius | ✓ | §6 — none added; unchanged from the first gate |
| 16 | Frozen set untouched | ✓ | no production source edited; `range_index.py` read-only (and see N1 on the citation) |
| 17 | Claims corrected where the evidence contradicted my own prior review | ✓ | §4 — my S5 fold 2 was over-general and I say so; §5 — my own §10.5 census cell rested on a docstring and I supply the proof it lacked |

---

## 8. Verdict

- [x] **OK to ship**
- [ ] OK to ship with the listed mitigations applied first
- [ ] Block

**Unconditional.** Phase 3 may open.

**Recommended to fold at Phase 3, none gating:** N1 (freeze-set line `:122` → `:123`, two sites) · N2
(`HLR-103`'s threshold bullet leads with the adopted form) · N3 (a measurable arm on §15 item 7's
trigger) · N4 (*contiguity*, not *monotonicity*, in §8.2 reason 2) · N5 (copy `TC-497`'s strings from the
code block, not the prose).

**One thing worth recording for the postmortem.** The blocker was not that revision 1 picked a wrong
threshold — it was that revision 1 had **no defined term** for the quantity its requirement claimed, and
you cannot build an oracle for a quantity you have not named. Revision 2 fixes it in the right order:
define `A` (§1.3), instrument it (`LLR-103.1`), assert it (`TC-498`), disclose it (§10.7), and name what
would reverse the choice (§15 item 7). That sequence — **name, instrument, assert, disclose, reverse** —
is a stronger general control than *"add a fixture for geometry X"*, which is all my G-2 asked for.
