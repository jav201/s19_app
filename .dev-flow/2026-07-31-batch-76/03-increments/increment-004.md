# Increment 004 — the merge-gate HIGH closures (H-1 … H-4)

**Base:** `origin/main` = `291bb76` · **Branch HEAD in:** `2f4a99f` · **out:** `fd9124a`
**Authorization:** autonomous + merge authorized, with one declared stop for the H-3(b) decision.
**Files:** 5 — `tests/test_report_document_bound.py`, `tools/mutation_harness.py` (new),
`AT-TC-REGISTRY.jsonl`, `s19_app/tui/services/report_service.py`, `REQUIREMENTS.md`.

---

## 1 · BLUF

Four HIGH findings, all in **acceptance strength**. All four closed, each with a counterfactual
executed **per parametrized arm**. Inc-3 / `HLR-110` untouched, per the hand-off.

**The hand-off's §3 was the load-bearing instruction and it was right.** Re-running M1 the old way
would have reported `RED` again. Per-arm it reports **3 RED, 4 GREEN**, and the four green arms are
*exactly* the four arms where `raw > ceiling` was false. That correspondence is what turned H-1 from
a claim into a diagnosis.

| # | Finding | Closed by | Counterfactual |
|---|---|---|---|
| H-1 | `TC-552` calibrated to the AT's **limit**, not its **ceiling** | guard every arm against its own ceiling; widen the cells | M1 → **7/7 arms RED** (was 3/7) |
| H-2 | `TC-555` asserted the allowance *from* the allowance | two-sided sandwich + O(V) slope floor; `TC-612` for the chartered label arm | M2 → 5/5 · M5 → 5/5 · M6 → 1/1 |
| H-3 | allowance derived from a **character** cap as a **byte** bound | `TC-611` restores §6's chartered pin; `REPORT_VARIANT_ID_MAX_BYTES` (Option 3); non-claim (h) | M4 → 2/2 |
| H-4 | `AT-253` asserted presence, not **equality** | parse the rendering; weigh refused bytes independently at the seam | M3 → 1/1 |

**21 of 21 arms RED across 6 mutations.**

---

## 2 · H-1 — the calibration, and why only the fixtures could move

`TC-552` guarded `raw > limit` where `limit = _SHRUNK_LIMIT = 4096`. Its ATs assert
`size <= limit + _disclosure_allowance(V)`. Measured, per arm:

| arm | raw | limit | ceiling | `raw > limit` | `raw > ceiling` | M1 verdict |
|---|---:|---:|---:|---|---|---|
| AT-250 | 4 404 410 | 2 097 152 | 2 155 366 | yes | **YES** | RED |
| AT-251[1] | 10 239 | 4 096 | 52 698 | yes | **NO** | **GREEN** |
| AT-251[10] | 102 390 | 4 096 | 62 310 | yes | YES | RED |
| AT-251[100] | 1 023 900 | 4 096 | 158 430 | yes | YES | RED |
| AT-252[1] | 6 939 | 4 096 | 52 698 | yes | **NO** | **GREEN** |
| AT-252[3] | 13 465 | 4 096 | 52 698 | yes | **NO** | **GREEN** |
| AT-252[10] | 20 936 | 4 096 | 52 698 | yes | **NO** | **GREEN** |

The green set and the `raw > ceiling = NO` set are **the same four rows**. The falsifiability
threshold is the ceiling; the guard was reading the limit.

**Shrinking the limit cannot fix it — derived, not assumed.** `allowance(1) = 48 602 B` has no
dependence on the limit, so at `limit = 0` the V=1 ceiling is still 48 602 B, above every AT-252 arm.
The only free variable is the fixture. Cells widened to `REPORT_BYTES_PER_CELL`; **rows left at 60/40**
so they stay under `MAX_REPORT_ROWS_PER_VARIANT = 200` and batch-74's row cap still never fires —
preserving AT-252's stated rationale that the byte gate is the only available bound.

`TC-552` is now parametrized over **all 7 resolved arms**, not 3 representatives. "AT-252" is not an
assertion; `AT-252[1]`, `[3]`, `[10]` are three, with three fixtures.

---

## 3 · H-2 — and a sharpening the review did not have

The shipped node asserted `slope_1 == slope_10`, `a0 > len(REPORT_SECTION_KINDS)` (`47534 > 8`) and
`a(100) > a(10)` — all properties of `_disclosure_allowance` computed from `_disclosure_allowance`.

**Sharpening: `_disclosure_allowance` has ZERO production call sites.** Executed census — the only
non-docstring occurrences outside tests are its own `def`. So it is not "the product's function used
as its own oracle"; it is a **test-consumed constant that happens to live in the product module**.
That is the mechanical reason a 1 GB substitution passed 27 nodes: mutating a function no production
path calls cannot change any emitted document, and its only readers use it as their *expectation*, so
raising it purely **loosens** every assertion.

**Design chosen, and the one rejected.** The reviewer offered "compare against an independently
derived bound". Measured, a per-term-sound independent derivation (4 B/char) runs **2.5–3×** the
product's value:

| V | product | independent cap | ratio |
|---:|---:|---:|---:|
| 0 | 47 534 | 145 838 | 3.07 |
| 100 | 154 334 | 406 238 | 2.63 |
| 400 | 474 734 | 1 187 438 | 2.50 |

Substituting that *as* the ceiling would have **tripled** the bound and weakened all 7 ceiling ATs.
So `_ceiling` keeps the tight product value and `TC-555` **sandwiches** it:

* **floor** — measured: saturated `_disclosure_lines` (905 B) + measured header (181 B) + `V ×`
  measured worst reachable heading (777 B).
* **cap** — independently derived at 4 UTF-8 bytes per permitted character.
* **slope floor** — `allowance(V+1) − allowance(V) >= 777`.

**The slope floor exists because the harness proved the total floor insufficient.** M5 (drop the
marker terms → 524 B/variant) reddened **only V=400** and stayed green at V=0/1/10/100: at small `V`
the constant block and appendix terms dominate and a wrong slope hides inside them. The slope is
`V`-independent and cannot hide. After adding it: **5/5 arms RED.**

`TC-612` carries §6's chartered discriminating arm, split from `TC-555` because C-18 binds one id to
one node and `TC-555` is now parametrized. **The split is declared here and in §9** — which is
precisely what `TC-556`'s repurposing did not do.

---

## 4 · H-3 — measured, and the operator's Option 3

**The violation is real** (constructor-injected `chr(0x1F600) * 600`, `CAP = 4096`):

| V | size | stated ceiling | delta |
|---:|---:|---:|---|
| 50 | 108 777 | 105 030 | **+3 747** |
| 100 | 212 630 | 158 430 | **+54 200** |
| 400 | 835 752 | 478 830 | **+356 922** |

Excess is a flat **1 009.1 B/variant** at both steps → the `V`-invariance clause failing, not slack
absorption. (My figures sit 9–10 B under the hand-off's; it did not state its `rows`, so these are
cited with their fixture per C-39.)

**Through the shipped surface the bound HOLDS, and provably.** `variant_id` is a filename component
(`workspace.py:485`), capped at 255 UTF-16 units. Max UTF-8 bytes per unit is 3 (a 4-byte code point
is non-BMP and costs 2 units, so only 127 fit), giving a **supremum of 777 B** for the heading:

| candidate id | units | emitted heading |
|---|---:|---:|
| 255 × U+4E00 | 255 | **777 B** |
| 255 × escaped backtick | 255 | 522 B |
| 127 × U+1F600 | 254 | 520 B |

Measured whole-document margin at that worst id is negative at every `V` **and grows**: −40 646 (V=10),
−16 052 (50), −15 364 (100), −82 242 (400).

**Two corrections to the hand-off's own figures.** (a) It cites `md_safe('"'*2000)` as the 2.03× case,
but `"` is not in `MD_ESCAPE` — measured 1.03×. The 2.03× characters are the `MD_ESCAPE` members
(spec P-3 used a backslash). (b) 2.03× is **not** the worst case: an unescaped non-BMP code point
gives **4.03×**, because an escaped `MD_ESCAPE` member is ASCII + backslash = 2 bytes while a non-BMP
code point is 4. **§6's chartered pin ("pins 2.03×") was itself under-derived**, so `TC-611` carries
both arms.

**Operator decision: Option 3.** `note`/`headings` now derive from
`REPORT_VARIANT_ID_MAX_BYTES = 3 × 255 = 765` — the reachable bound — rather than
`REPORT_CELL_CHARS`. Slope moves 1068 → 1321, and the heading portion becomes `12 + 765 = 777`,
**exactly** the measured supremum: sound *by construction* and tight. Option 2 (4 B/char) was
rejected on the measurement above.

**What Option 3 actually bought, stated precisely.** Before it the terms were under-derived (524 B
allocated for a cell emitting up to 2 063 B) and held only by **compensation** from the 542 B of
marker slack. After it, the heading term covers the heading on its own.

**An honest limit, so the division of labour is not mistaken for a gap.** Reverting *only* the byte
derivation (back to `REPORT_CELL_CHARS`, markers kept) gives slope 1068 ≥ 777 and reddens **nothing** —
because with the markers present it is not a behavioural defect. `TC-611` therefore pins the
*constant's* soundness (`REPORT_VARIANT_ID_MAX_BYTES >= ` the widest rendered reachable id) rather
than pretending a behavioural node can catch it.

`TC-611` takes the next free registry id because `TC-556` is `LIVE` against a different node and
re-pointing it would redden G2. **Registry path note (C-39):** the hand-off cites
`.dev-flow/AT-TC-REGISTRY.jsonl`; the file is at the **repo root**.

---

## 5 · H-4

Shipped `AT-253` asserted a number follows `bytes ` and that the sum is `> 0`. `TC-560` guards the
*accumulator*. Nothing compared the **rendering** to the bytes it names, so
`f"bytes {sections}"` — a section count under the "bytes" label — passed 27 nodes.

`AT-253` now wraps `_EmissionGate.emit`, weighs each refused batch with `_line_bytes` **in the test**,
parses the rendered block per kind with a positional regex (the number must be the one introduced by
the word `bytes`), and asserts **dict equality**. Comparing against `_Refusals.byte_count` would have
restated `TC-560`.

---

## 6 · The harness (`tools/mutation_harness.py`)

Replaces the exit-code-per-mutant harness. §3's item 1 is implemented; items 2–4 are enforced rather
than remembered.

* **Per-arm verdicts** from resolved node ids. The aggregate `3 failed, 4 passed` is never parsed.
* **Anchor must match exactly once**, with a CRLF-mismatch hint so a 0-match is not mistaken for a typo.
* **Reachability probe, only where an arm stayed green.** A RED arm already proves reachability — a
  substitution that moved an asserted observable must have executed. A green arm with no
  position-valid `probe=` is an **abort**, not a pass. (The probe must be syntactically valid in the
  anchor's position: M3's anchor is an f-string argument, where a bare `raise` is a `SyntaxError`.)
* **Isolation by construction:** mutates a throwaway `git worktree`, so it cannot contaminate a gate
  run. This removes the class that produced batch-76's discarded run A rather than sequencing around it.
* **Byte-exact restore, verified by SHA-256** — and it operates in **bytes** because it caught its own
  text-mode round-trip rewriting an LF file as CRLF. Found by the hash check, not by review.

**Positive-controlled, TC-554-style.** A substitution placed *after* the `return` is correctly
reported **inert on all 5 arms AND "region NEVER EXECUTED"**. A harness that cannot distinguish dead
code from a passing guard is the tool version of the vacuous check it exists to find.

---

## 7 · Evidence

```
tests/test_report_document_bound.py + tests/test_id_registry.py   51 passed
report suite (-k report)                                         676 passed, 1843 deselected
mutation matrix, per-arm, with probes                            21/21 arms RED, 6 mutations
harness positive control (dead code)                             inert + unreachable  [expected]
C-27 frozen SOURCE diff vs origin/main and working tree          empty
C-27 frozen TEST guard (test_engine_unchanged.py)                1 passed
G1–G7 registry guard (tests/test_id_registry.py)                 13 passed
```

`markdown_safety.py` is **unedited** (spec P-4); it is mutated only inside the throwaway worktree,
which is a counterfactual, not an edit.

---

## 8 · Ledger

`TC-552` 3 → 7 arms (+4) · `TC-555` 1 → 5 arms (+4) · `TC-612` +1 · `TC-611` +2 = **+11**, so the file
moves 27 → 38. Full-suite reconciliation is in `04-validation.md`.

**Registry:** `TC-611`, `TC-612` added; `high_water.TC` 610 → 612, `next_free.TC` 611 → **613**.
`TC-552`/`TC-555` rows re-pointed to their renamed nodes. `EXPECTED_SCANNED_TEST_FILES` stays **152** —
no new test module.
