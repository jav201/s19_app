# batch-76 — Post-mortem

**Requirement:** `R-TUI-102` (`HLR-108`/`109`/`110`) · **PR** [#184](https://github.com/jav201/s19_app/pull/184)
**Base:** `origin/main` = `291bb76` · **Closing commit:** `fd9124a`

---

## §1 BLUF — where the risk actually lived

**Across this batch, fourteen defects were found — six by the implementer, four by the independent
reviewer, four by me at the merge-gate closure. Not one was in shipped production code.** Every single
one was in an acceptance, a derivation, or the verification harness.

That is not a coincidence and it is the batch's principal finding. `R-TUI-102`'s production change —
gate every emission seam, apportion per variant, disclose once — was correct on first implementation
and survived three independent adversarial passes. What repeatedly failed was **the apparatus that
was supposed to prove it correct.**

The single most consequential defect in the whole batch was not in the report generator. It was
**one line of harness design**: deriving a verdict from a process exit code over parametrized nodes.

---

## §2 The mechanism that hid four defects, stated exactly

```
M1  gate disabled   AT-250/251/252   applied=True   RED   3 failed, 4 passed
```

recorded as **"RED · INERT: none"**.

`pytest` exits non-zero if *any* arm fails. The harness read the exit code. Four arms survived a
**fully removed byte gate**, and the string `4 passed` was sitting in the transcript, unread.

**Why an aggregate cannot express what a counterfactual is for.** The question a counterfactual asks
is not "did this mutation break something" but "**which** assertions does this mutation break". Those
have different types: the first is a boolean over the whole node set, the second is a map from arm to
verdict. Collapsing the map to a boolean with `any()` discards exactly the information being sought,
and it does so *silently and optimistically* — the aggregate is RED whenever a single arm is RED, so
the more arms a node has, the more inert ones it can hide. A representative arm is not a sample; it
is a mask.

**And the four hidden arms were not random.** They were precisely the four where `raw > ceiling` was
false — a single systematic calibration error, uniformly distributed over the arms it affected. The
aggregate turned one systematic error into "no finding".

---

## §3 Premise table (C-43) — the hand-off's own propositions, re-executed

The hand-off was unusually accurate. It was not uniformly accurate, and the divergences were only
found by executing it.

| # | Proposition (source) | Verdict | Evidence |
|---|---|---|---|
| P-1 | §3: the harness hid four green arms behind an exit code | ✅ **TRUE** | reproduced verbatim: 3 RED / 4 GREEN, and the green set is exactly the `raw > ceiling = NO` set |
| P-2 | H-1: `TC-552` guards the limit where the AT asserts the ceiling | ✅ **TRUE** | `raw` 6 939/13 465/20 936 vs ceiling 52 698 |
| P-3 | H-1: *"fixture must grow **or** `_SHRUNK_LIMIT` shrink; derive which"* | ⚠️ **HALF FALSE** | shrinking cannot work at all — `allowance(1) = 48 602` is limit-independent, so even `limit=0` leaves the ceiling above every AT-252 arm. Only one branch existed |
| P-4 | H-2: the ceiling has no oracle — *"it is the product's own function"* | ⚠️ **TRUE BUT UNDERSTATED** | `_disclosure_allowance` has **zero production call sites**. It is a test-consumed constant inside the product module, so mutating it cannot change any document — which is *why* 1 GB passed 27 nodes |
| P-5 | H-2: *"make the ceiling ATs compare against an independently derived bound"* | ❌ **REJECTED on measurement** | a per-term-sound independent derivation is **2.5–3×** the product value; adopting it as the ceiling would triple the bound and weaken all 7 ceiling ATs. Sandwiched the constant instead |
| P-6 | H-3: the stated ceiling is measurably violated | ✅ **TRUE** | +3 747 / +54 200 / +356 922 at V=50/100/400; flat 1 009.1 B/variant |
| P-7 | H-3: `md_safe('"'*2000, limit=512)` → 2.03× | ❌ **FALSE** | `"` ∉ `MD_ESCAPE`; measured **1.03×**. The 2.03× characters are the `MD_ESCAPE` members (spec P-3 used a backslash) |
| P-8 | §6 charter: the pin *"pins 2.03×"* | ❌ **UNDER-DERIVED** | worst case is **4.03×** — an unescaped non-BMP code point is 4 bytes where an escaped ASCII member is 2. The charter's own constant was half the truth |
| P-9 | H-3: reachable worst case keeps the heading *"just inside its term"* via a 255-unit cap | ⚠️ **RIGHT CONCLUSION, WRONG WITNESS** | emoji cost **2** UTF-16 units, so only 127 fit (520 B). The byte-maximising reachable id is a **3-byte BMP** character: 255 units, **777 B** |
| P-10 | H-3: the runtime violation is constructor-domain | ✅ **TRUE, and now provable** | supremum `12 + 3×255 = 777` vs 1 068 B allocated; measured margin negative and **growing** in `V` |
| P-11 | H-4: `AT-253` asserts presence, not equality | ✅ **TRUE** | `f"bytes {sections}"` → 27 passed |
| P-12 | §4.3: registry is at `.dev-flow/AT-TC-REGISTRY.jsonl` | ❌ **FALSE** | repo **root**. C-39 again, in the document warning about C-39 |

**Four of twelve propositions did not survive execution, and two of them were the hand-off's own
supporting measurements.** None changed the disposition of any finding — every HIGH was real. What
they changed was the *fix*: P-3 eliminated a branch, P-5 reversed a design, P-9 replaced the witness,
P-8 doubled a constant.

---

## §4 The recursion, again — and this time it closed on me

batch-76's standing motif is that the defect reproduces inside its own fix. It did so twice more here.

**(1) In my own new test.** `TC-612` asserts "adding a label to the closed set must move the
allowance". My first draft used the label `an-extra-refusal-kind` — **21 characters against an
18-character maximum**. So it moved the *widest-label* term, not the cardinality term, and passed
even with the cardinality factor replaced by the literal `1`. Executed (M6): **GREEN**. A
discriminating arm that cannot discriminate between the two terms it ranges over is the same defect
class as the node it was written to replace. Fixed by probing with a **1-character** label, so only
cardinality can move the number — plus a separate arm for the width term, so neither can stand in for
the other.

**(2) In my own new floor.** `TC-555`'s measured floor was one-sided-sound but **arm-dependent**: M5
(drop the marker terms) reddened only `V=400` and stayed green at `V=0/1/10/100`, because at small `V`
the constant block and appendix terms dominate and swallow a wrong slope. A total bound cannot police
a rate. Fixed by asserting the **slope** separately, which is `V`-independent.

**Both were found by the harness, not by review** — which is the only reason this post-mortem can
claim the harness works. A tool whose first two runs found defects in the tests written alongside it
has demonstrated something; one that returned all-green would have demonstrated nothing.

**And the harness's own contract broke under it.** Its guarantee is a byte-exact restore verified by
SHA-256. Its first restore **failed that check** — `read_text`/`write_text` translate newlines on
Windows, so round-tripping an LF file rewrote it as CRLF: content-equal, not byte-equal. The check it
carries for the code under test caught a defect in itself. It now operates in bytes.

---

## §5 What generalises

1. **A verdict must have the same shape as the question.** "Which arms does this mutation redden" is a
   map; an exit code is a boolean. Reducing the former to the latter with `any()` loses precisely the
   inert arms, and loses them optimistically. *Registered as a control candidate — see §7.*
2. **A guard must be calibrated against the number its subject asserts, not a number in its
   neighbourhood.** `TC-552` compared to the limit; its ATs compared to the ceiling. Both are "the
   budget" in prose and they differ by 48 602 B. **This is the second time in this batch that an
   English phrase — "its own effective limit" — hid a factor-of-ten ambiguity between two real
   quantities.**
3. **A total bound cannot police a rate.** If a derivation has a constant term and an `O(V)` term,
   assert them separately: at small `V` the constant hides an arbitrary slope error.
4. **A discriminating arm must vary exactly one term.** If the probe moves two terms at once, the node
   cannot attribute the change, and it passes when either is broken.
5. **An unreferenced derivation is a spec constant, not code.** `_disclosure_allowance` sits in the
   product module with zero production callers. Nothing enforced it; tests only *read* it as their
   expectation, so every mutation to it loosened the very assertions meant to constrain it. **Ask of
   any derived constant: who consults it at runtime? If nobody, no behavioural test can guard it and
   it needs a two-sided bound.**
6. **"Sound by construction" and "sound by compensation" are different properties and only one
   survives editing.** The allowance was correct in total while two of its terms were under-derived,
   covered by slack in a third. Nothing was wrong with the output; the *structure* was one edit away
   from wrong. Option 3 made each term carry its own weight.
7. **Prefer the tight bound plus a two-sided guard over the generous bound.** The reviewer's literal
   remedy would have tripled the ceiling — buying derivational purity by weakening seven acceptances.
   The document is not safer for a looser claim about it.

---

## §6 Process

**What worked.** The hand-off. It was self-contained, its repros were executed rather than reasoned,
it named the four constraints that mattered, and it put §3 first with an explicit warning that
re-running the old way would re-hide the defects. That warning is the reason this session started by
building a harness instead of by fixing tests. **A hand-off that ranks its contents by consequence is
worth more than one that merely contains them.**

**What the operator's Option-3 fork bought.** The hand-off's literal H-3(b) instruction (re-derive at
emitted-byte width) was measurably the wrong trade. Stopping to measure before deciding surfaced a
third option — derive from the *reachable* bound — that is sound by construction **and** tight. The
measurement took minutes; adopting the literal instruction would have weakened seven ATs permanently.

**Carry — the one thing this session did not settle.** `REPORT_VARIANT_RESERVATION_FLOOR_BYTES`
(`report_service.py:412`) uses the same `REPORT_CELL_CHARS`-as-byte-bound pattern H-3 names, and its
guard `TC-556` measures the marginal cost of a **2-character** variant id (`"v0"`/`"v1"`). It is
therefore the same *narrow-fixture* class as the finding this batch opened with. It is **not** a live
defect (the guard asserts a relation and passes), and fixing it was outside the approved scope, so it
is registered rather than patched. → `BACKLOG-CODE.md`.

---

## §7 Control candidates (NOT encoded — each needs its own approval)

| # | Candidate | Evidence |
|---|---|---|
| **CC-1** | **A counterfactual verdict is reported per resolved node id, never per mutant.** A mutation is RED only for the arms that actually failed; an aggregate over parametrized nodes is inadmissible. | Cost this batch **four hidden inert arms under a fully removed byte gate**, in the artifact written to prevent exactly that. Strongest single-occurrence evidence in the project. |
| **CC-2** | **A guard cites the quantity its subject asserts against, by name and value.** | `TC-552` vs limit/ceiling — 48 602 B apart, both called "the budget". Second occurrence in this batch of an English phrase masking two real quantities. |
| **CC-3** | **A derived constant with no runtime consumer requires a two-sided bound.** One-sided guards on an expectation-only constant are unfalsifiable upward. | `_disclosure_allowance`, 0 production call sites, 1 GB substitution → 27 passed. |
| **CC-4** | **A discriminating arm varies exactly one term of the derivation it probes.** | `TC-612`'s 21-vs-18-character label moved the width term instead of cardinality and passed a gutted cardinality factor. |
| **CC-5** | **Assert the rate separately from the total.** | `TC-555`'s total floor was inert on 4 of 5 arms against a 2× slope error. |

`CC-1` is §3's item 1 and is the one to encode first. Items 2–4 of §3 (single-match anchor, reachable
region, observable the node reads) are already registered as a Lane B candidate and are now
**mechanically enforced** by `tools/mutation_harness.py` rather than remembered.
