# batch-64 — TRIM-C variant measurement (Phase 2, independent measurer, run 2)

> **Measurement only. I did not edit the spec and I did not draft any control text.**
> Harness: my own `rq_arms2.py`, extending the `rq_arms.py` used in `02-review-qa.md` — parses C-40 by
> its own `**LIMB n` / `**DISCHARGE` structural markers, executes each code-backed corpus member under
> the real text-mode→byte-mode writer change on an LF and a CRLF host.
> Nothing here is copied from `01c`, `01d`, `02-review-architect.md`, or the fold.

---

## 0. BLUF — four findings

**(1) TRIM-C has no text. It is a shape, and it is disqualified twice over without reaching a byte
count.** It drops security F1's mutation-hygiene bound (Check 1 — disqualifying by the stated rule)
and it is a **one-limb** form (Check 2). Measured against the corrected 9-member corpus it is
**6/9**, losing **V-4, V-5 and V-8**.

**(2) The variant table is no longer flat, and that is the change from last time.** In fold 1 all
three variants measured 6/6 and the byte question could not be decided on detection. **Now they
separate: 9/9 · 8/9 · 6/9.** There is a real detection gradient, and it runs the same direction as the
byte count.

**(3) Only 440 B of the +1 204 B growth is priced by the arms — and it buys exactly one corpus member.**
A-23 (my own M-2) is what converts `8/9` into `9/9` by catching `V-8`. A-25's 496 B and the Origin
rewrite's 268 B buy **nothing measurable on the arms** — which is not an argument against them (A-25 is
a mandated safety clause whose value is not detection), but it is the honest decomposition.

**(4) A finding the fold has not recorded: `S-3` is now flagged by the shipped control.** A-23 makes
the CI-inclusive domain normative, and under it `S-3` — still listed among the six sound negative
controls — is flagged. Per my fold-1 M-1 that is a **true** positive: `S-3` is inert on
`ubuntu-latest`. So **the negative arm is `1/6`, not `0/6`, under the domain the control now
mandates.** The defect is in the control *group*, not in C-40. Reclassify `S-3` and it is `0/5`.

---

## 1. Harness integrity — does the marker mutation still bite after the rewrite?

The text changed by 1 204 B, so the fold-1 integrity discharge does not transfer.

```
V-FULL-2 read from spec §3.1: 6219 B  sha=5cb146e980deb639
  clauses detected: limb1=DECLARED | limb1_static pin domain_ruling limb2_general
                    limb2_instances hygiene relations
  domain=CI       POSITIVE 9/9
  MARKER-CORRUPTION MUTATION: 9/9 -> 0/9  BITES (harness reads the bytes)
```

**Still bites.** The verdict remains a function of the variant's bytes.

---

## 2. The corpus facts, re-executed

Every flag below traces to one of two executed facts. **The semantic test is applied to each
predicate's OWN declared subject** — not to the writer for all of them, which would wrongly flag the
`_line_bytes` PIN.

```
id    declared subject mutated                  moves on CI?  moves on FULL?
V-1   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
V-2   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
V-3   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
V-6   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
V-7   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
V-8   the writer (text->byte mode)                     False            True   <- INERT ON THE MERGE GATE
V-9   the writer (text->byte mode)                     False           False   <- INERT ON THE MERGE GATE
S-1   the writer (text->byte mode)                      True            True
S-2   the writer (text->byte mode)                      True            True
S-3   the writer (text->byte mode)                     False            True   <- INERT ON THE MERGE GATE
S-4   a text-mode write reintroduced                    True            True
S-6   _line_bytes redefined as len(join)                True            True
S-5   cap-without-break (inspection, not shipped)       True            True

LIMB-1 SEMANTIC FLAGS (A-23 ruling active):
  CI domain  : ['V-1','V-2','V-3','V-6','V-7','V-8','V-9','S-3']
  FULL domain: ['V-1','V-2','V-3','V-6','V-7','V-9']
```

`V-4` and `V-5` are limb-2 members (set drawn from the implementation) and are flagged by limb 2 alone.

---

## 3. The variant table

```
variant                                     bytes  xC-39  domain   pos  neg fp  members LOST
V-FULL-2  (spec §3.1 as it now stands)       6219  2.56x      CI   9/9     1/6  none   FP=['S-3']
                                             6219           FULL   8/9     0/6  ['V-8']
V-FULL-1  (the 5 015 B text D-9 ruled on)    5015  2.07x   (n/a)   8/9     0/6  ['V-8']
TRIM-C    (SHAPE ONLY — no text exists)        ~?      ?   (n/a)   6/9     0/6  ['V-4','V-5','V-8']
```

| variant | bytes | ×C-39 | positive arm | negative arm | **members lost** |
|---|---|---|---|---|---|
| **V-FULL-2** | **6 219 B** | **2.56×** | **9/9** (CI, the domain A-23 mandates) · 8/9 (full) | **1/6** (`S-3`) · 0/6 (full) | **none** |
| **V-FULL-1** | 5 015 B | 2.07× | **8/9** | 0/6 | **`V-8`** |
| **TRIM-C** | *shape only* | *see §4* | **6/9** | 0/6 | **`V-4`, `V-5`, `V-8`** |

**The load-bearing column.**

- **V-FULL-2 loses nothing.** It is the only variant that catches `V-8`, and it catches it *because*
  A-23 rules that the semantic test governs and its domain includes the platform.
- **V-FULL-1 loses `V-8`** — `tests/test_report_document_bytes.py:221`, live on `main`. `V-8`'s writer
  is syntactically present in its expression, so only the semantic-plus-platform reading catches it.
  Without A-23 the arm's own figure was ambiguous between `8/9` and `9/9`; **A-23's 440 B is what
  makes it determinate.**
- **TRIM-C loses three.** `V-4` and `V-5` are the P-6/P-7 absorption content the operator ruled must
  live inside C-40 — a one-limb form cannot see them, exactly as the fold-1 `4/6` showed on the
  smaller corpus. `V-8` goes with the missing domain ruling.

### 3.1 What each byte block buys, measured

```
  +  496 B   A-25 mutation-hygiene bound     arms delta: NONE   (safety, not detection)
  +  440 B   A-23 semantic/syntactic ruling  arms delta: +1 member (V-8), 8/9 -> 9/9
  +  268 B   Origin rewrite                  arms delta: NONE   (removed the encoded counts)
  ------
  + 1204 B   5 015 -> 6 219
```

**440 of 1 204 B are arm-priced. 764 B are not.** That is not a case for cutting them — A-25 is a
mandated security clause and detection is not its job — but it is the number the R-c conversation
needs, and it is the one the arms can actually supply.

---

## 4. TRIM-C — measuring a shape without drafting one

**No drafted TRIM-C text exists.** Five occurrences across the batch, all prose:

```
  01-requirements-architect.md:454     "...roughly one third the bytes. I did not take that route..."
  01-requirements-consolidated.md:725  "...one new static subject-naming sentence — roughly one third the bytes."
  01d-union-ledger.md:299              "...RESTORED-THIS-FOLD | D-08 — restored as spec prose"
  02-review-architect.md:96            "...No. §9.1 offers only trims (a) and (b)"
  02-review-architect.md:490           "MAJOR-5 | §G's 'one third the bytes' alternative (D-08) dropped..."
```

**I did not draft it.** What I measured instead: the shape names exactly two components, both of which
exist on disk, so their bytes are measurable and its implied clause set is derivable.

```
  component 1: the '## Objective exit criteria' *Certainty* clause, dev-flow.md:99      299 B
  component 2: subject-naming sentence  (present in V-FULL-2)                           130 B
  component 2: static-half sentence     (present in V-FULL-2)                           106 B
  FLOOR of the shape's named components: 535 B = 0.22x C-39

  the shape claims "roughly one third the bytes":
     one third of V-FULL-1 (5 015) = 1672 B ;  one third of V-FULL-2 (6 219) = 2073 B
```

**Read this carefully: the floor is 0.22×, and the shape's own claim is ~0.33× of a much larger
block.** The named components come to **535 B**, roughly a quarter of what the "one third" estimate
implies. So the shape is either cheaper than advertised or — far more likely — **it silently includes
discharge wording it does not name.** A shape whose stated components price at a quarter of its stated
total is not a costed option; it is an intention. **That, not its arm figures, is the honest reason it
could not have been a third menu item at D-9 without being drafted first.**

---

## 5. The two specific checks

### Check 1 — does TRIM-C retain security F1's mutation-hygiene clause? **NO. DISQUALIFYING.**

```
                                 in V-FULL-2 DISCHARGE span   in the Certainty clause on disk
  restore-before-next-gate                 True                          False
  where-it-runs bound                      True                          False
  contamination rationale                  True                          False
  mutation-actually-applied                True                          False
```

The bound lives entirely in C-40's **DISCHARGE** span. TRIM-C's shape names the *Certainty* clause and
one static sentence — **neither is the DISCHARGE span**, and the Certainty clause carries **0 of 4**
needles. TRIM-C therefore drops the `restore` and where-it-runs bound.

**Stated as instructed, not traded off: this is disqualifying regardless of its arm figures.** A form
that drops the restore obligation lets a mutation stay applied in a tree other sessions are reading,
which is indistinguishable from a real defect to everyone else — the exact hazard F1 raised.

### Check 2 — does TRIM-C retain both limbs? **NO. It is a one-limb form.**

```
  Certainty clause contains 'drawn from the rule':        False
  Certainty clause contains 'quantifies over':            False
  Certainty clause contains 'positive control shaped':    False
  Certainty clause contains 'consolidation that drops':   False
```

Limb 2 has no carrier in either named component. **Measured against the 9-member corpus: 6/9**, losing
`V-4`, `V-5` (limb-2 members) and `V-8`. The fold-1 reference figure for a one-limb form was `4/6`
against the 6-member corpus; the corrected corpus does not rescue it — it loses the same two limb-2
members plus one more.

---

## 6. The three confirmations

### C-1 — 32 encoded ids across 3 declaration shapes. **CONFIRMED.**

```
    S1 '## C-NN --'        11 ids
    S2 bullet '(C-NN)'     20 ids
    S3 bold '**C-NN --'     1 ids
    UNION = 32 ids  -> CONFIRMED
```

Independently derived with `re.MULTILINE` applied. I note the fold's self-reported omission is **the
same defect class I raised as m-1, committed while fixing m-1** — and that I hit a sibling of it myself
in fold 1 (my first census regex missed shape S3 / `C-33`). Three independent agents have now
mis-scoped this census in three different ways; that is a signal about the census, not about any one
author. It is caught here only because the union has a known-plausible size — the same "impossible
value" luck C-42's mechanic 3 warns about.

### C-2 — two independent RED carriers. **CONFIRMED.**

```
    C-29  encoded=True  registered=False -> ENCODED, NOT REGISTERED
    C-1   encoded=False registered=True  -> REGISTERED, NOT ENCODED
    independent carriers = 2 ['C-29', 'C-1'] -> CONFIRMED
    drop C-29 -> remaining carriers ['C-1'] -> still RED: True
```

My fold-1 m-2 (the AT was `1/3`, single-carrier, and would re-vacuate if `C-29` were dropped) is
**discharged**: the carriers now run in **opposite directions**, so no single re-scope can green it.

### C-3 — the exception is `C-1` alone, not `C-1…C-9`. **CONFIRMED.**

```
    C-1   encoded=False registered=True   CARRIES SIGNAL (registered, unencoded)
    C-2 … C-9  encoded=False registered=False   absent BOTH sides - no signal
    => exception set = ['C-1'] -> CONFIRMED
```

This supersedes the coordinator's Phase-0 claim a second time and it is **verified, not inherited**:
`C-2…C-9` are absent from the lineage record *and* from every destination, so they are consistent-by-
absence and contribute no signal in either direction. Only `C-1` is asserted with nothing behind it.

---

## 7. What I did not do, and one caveat that survives

- **I did not draft TRIM-C.** §4 measures its named components and derives its clause set; it does not
  invent wording. Any byte figure for a *finished* TRIM-C would be a number about text I wrote, which
  is not a measurement.
- **`S-3`'s status is a live inconsistency, not a rounding note.** The spec reports the negative arm as
  `0/6`. Under the CI-inclusive domain A-23 now mandates, it is `1/6`. Both figures are correct about
  different domains; only one domain is normative. **Either `S-3` moves out of the control group (my
  reading — it is genuinely inert on the merge gate), or the arm's reported figure must name its
  domain.** This is the 5-of-6-sound caveat applied, and it is the one number in the fold I could not
  reproduce as stated.
- **`S-5` is still not a shipped test** (fold-1 m-3), so "six sound controls" is six predicates, five of
  them running code.
- I re-derived nothing from `01c`/`01d`/the fold. Where my figures agree with theirs — 6 219 B, 2.56×,
  `8/9` full-domain, `9/9` CI-only, 32 ids — that is independent confirmation.

---

## 8. Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Explicit Expected, not vague "works" | ✓ | every arm states domain + figure before its transcript (§3) |
| Edge cases: empty, boundary, invalid, error | ✓ | boundary = `V-8`/`S-3`, the two CI-only members; invalid = marker corruption (§1); error = the shape with no text (§4); empty = `C-2…C-9` absent both sides (§6) |
| Results left blank unless actually run | ✓ | every block is command output from this session |
| No real PII / secrets | ✓ | inputs are batch artifacts, `~/.claude` command/skill text, and the lineage memory |
| Layer B — observed through the shipped surface | ✓ | variants measured as the literal bytes that would be pasted into `dev-flow.md`; §1's mutation proves the harness reads them |
| Bidirectional surface-reachability | ✓ | inputs: 3 variants × 2 domains, 9 positives, 6 negatives, 3 declaration shapes, 2 hosts, 2 writers. outputs: positive arm, negative arm, lost-members, bytes, ratio, carrier set — each observed per variant |
| No unfilled template | ✓ | no placeholders; TRIM-C's missing text is reported as a finding, not left as a blank |
| C-40 applied to this document's own predicate | ✓ | declared subject = the variant's bytes; §1's marker corruption reddens 9/9 → 0/9, so the predicate is not inert. My own fold-1 census false negative on `C-33` is restated at §6 C-1 rather than quietly dropped |
