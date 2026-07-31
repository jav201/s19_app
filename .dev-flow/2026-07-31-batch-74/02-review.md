# batch-74 — Phase 2 cross-agent review (iteration 1) → **ITERATE**

**Three independent lanes, all ITERATE.** architect 5 blockers / 12 major / 6 minor · qa 4 blockers /
4 major / 6 minor · security 3 blockers / 3 major / 2 minor.

> **BLUF — the review paid for itself on its first finding, and all three lanes found it independently.**
> `HLR-106` claimed the written document would be bounded by `REPORT_MAX_TOTAL_BYTES + O(V × 5 lines)`.
> It is not, and `AT-227` — the AT that gates it — **stays RED after a fully correct implementation**.
> The requirement applied P-23's own argument (an out-of-scope unbounded producer makes a whole-report
> claim unsatisfiable) to the *residency* axis and then failed to apply it to the *emitted-bytes* axis.
> **Convergent rediscovery by three lanes that could not see each other is what upgrades this from
> opinion to measurement.**

## Deduplicated blockers (12 raw → 7 distinct)

| # | Distinct blocker | Raised by | Orchestrator's independent verification |
|---|---|---|---|
| **BL-1** | **`HLR-106`/`AT-227` over-claim the document bound.** `_declaration_error_lines` (`:1114`) and four other producers go through the ungated `emit` (`:2215-2217`). | arch B-1 · qa F-1,F-2 · **sec F1** | ✅ **CONFIRMED, executed by me:** `_declaration_error_lines` emits **315,912 B/variant** at 500-char issue fields, capped at 200 *issues* but not at *bytes*. Document floor = `2,097,152 + V×315,912` → **1.15× at V=1, 2.51× at V=10, 16.06× at V=100.** AT-227 is **unsatisfiable**. |
| **BL-2** | **`LLR-105.3` ∧ `LLR-107.2` ∧ `AT-231` are mutually unsatisfiable on `Length`.** A 3572-digit length is ~2966 hex chars, 5.8× `REPORT_CELL_CHARS`. Truncating reddens AT-231; not truncating violates LLR-105.3. | arch B-2 · sec F4 | ✅ Arithmetic re-derived. One rule per column; `Length` must leave the width list. |
| **BL-3** | **`Address` is a `shall` with no LLR, AT, TC or increment — and truncating it is a silent numeric forgery.** A truncated hex address still matches `^0x[0-9A-F]+$`, so a truncated cell is indistinguishable from a complete one; security measured a true address understated by **2^12248**. | arch B-3 · **sec F2** | ✅ And it is the **only wire-reachable** oversized field (`_ADDRESS_RE` has no digit limit, `changes/io.py:235`). |
| **BL-4** | **Budget-driven eviction has no disclosure requirement and no AT.** `LLR-105.5`'s notice is cap-shaped; a row dropped by `budget.fits` was not dropped by a cap. `AT-228` is anchored to no LLR. Security adds: this permits **deterministic, silent suppression** of a later variant's evidence. | arch B-4 · sec F3 | ✅ Requirement-internal; confirmed by reading §3/§4. |
| **BL-5** | **`US-B74-3` restates a premise the same document marks FALSE (P-20), and its threat is unreachable through the shipped ingestion path.** `addressed_range = (address, address + len(encoded_bytes))` bounds `Length` at `MF_RUN_LENGTH_CEILING` → **7 decimal digits** vs a 4300-digit limit. | arch B-5 · sec F7 | ✅ `changes/model.py:173-185`. D2 is **constructor-domain hardening**, not a wire threat — and the wire-reachable oversized field is the **Address** (BL-3), which I orphaned. |
| **BL-6** | **`AT-224`/`AT-225`/`TC-523`/`TC-524` are VACUOUS.** My claim "the only predicate that catches cap-and-break" is false: `total = sum(len(s.entries) …)` is `O(1)` per summary and never traverses entries, so a **cap-and-break** implementation states `dropped = 137` correctly and passes. | **qa F-3** (executed) | ✅ Confirmed by inspection — `len()` on a list does not traverse. The declared subject (traversal continuation) is absent from the predicate's expression. |
| **BL-7** | **`AT-231` admits a sign-dropping implementation.** `f"0x{abs(n):X}"` renders a *positive* token for a negative length and satisfies the regex — precisely the defect `HLR-107` exists to prevent. `lambda n: "0"` also passes. | **qa F-4** (executed) | ✅ Regex membership is the wrong shape; token **equality** against an independently derived string is required. |

## Majors folded in the same pass

arch M-1 (D-4's rationale is factually wrong — `fits()` needs the row **formatted** first, so the gate
closes the *emitted* and *appended* axes, not transient formatting) · M-2 (per-check-file empty tables
under saturation) · M-3/M-7 (`max_bytes` required + Inc-1 must update all four call sites) · M-4 (strike
the "off-by-one sentinel is a feature" framing; record the coupling in the constant's docstring) ·
M-5/qa F-9 (`AT-228`'s `## Variant:` clause is invariant — emitted at `:2241` outside both producers) ·
M-6/qa F-8 (`LLR-106.2` double-charge has no gate, **and its violation makes the document smaller,
i.e. loosens its own acceptance** — the canonical vacuous shape) · M-8 (`AT-232` mis-traced to story 3
and mis-sequenced to Inc-4, leaving Inc-1/2/3 with no byte-identity gate) · M-9/sec F6 (`test_f17`'s
amendment shape must **widen a closed alphabet**, not relax to a blacklist — it is a batch-62 escaping
guard) · M-10 (no TC assigned to any increment) · M-11 (`3·171−1 = 512` **already equals** the cap
before the cue is appended) · M-12 (§7 incomplete) · qa F-5 (`≤32 B` picked not derived; RED after a
correct fix on an unconstrained fixture) · **qa F-6 (the memory oracle states a threshold with no
defined ratio)** · qa F-7 (C-12 ordering enforced by prose only) · sec F5 (`LLR-105.2`'s premise
defeats `LLR-106.3`'s ungated per-check-file structural lines).

## Axes the lanes independently certified CLEAN — recorded so no later pass re-opens them

- **Normative language** — `grep -i '\bshould\b'` → **0 matches**; all 3 HLRs and 11 LLRs use `shall`.
- **`LLR-107.4` does not invert the defect** — architect executed the sweep: the only `raise ValueError`
  in `variant_execution_service.py` is `:650` (unreachable, `app.py:4127` passes the constant); every
  `ValueError` in `report_service.py` is inside `ReportOptions.__post_init__`; malformed operator files
  are **collected** as `ValidationIssue`s, never raised. **No legitimate operator-input `ValueError` is
  re-routed.** Bonus: it also fixes the `:4144` tuple-unpack arity error surfacing as "Report rejected".
- **No new information exposure** (sec) — both arms interpolate the same `str(exc)`; the failure arm adds
  only a class name. Net effect on the metadata-only audit log is a **reduction**. No D-11-class exposure.
- **D2 sign placement + the `0x` prefix genuinely disambiguates** — `str(n)` can never contain `x`, so
  the two predicate branches are provably disjoint.
- **`REPORT_BYTES_PER_CELL` derivation exact** — `(512+1)//3 = 171`; `3·171−1 = 512`; `3·172−1 = 515` overflows.
- **Cue vs `TRUNCATION_MARKER` distinct**, cannot break the table, inert against `MD_ESCAPE`.
- **`TC-531`'s process-global `set_int_max_str_digits`** — `pytest-xdist` not installed, no `addopts`,
  CI installs plain pytest → sequential. `try/finally` sufficient.
- **Engine-freeze compliance**; **increment file counts** all ≤5; **no orphan ATs**.
- **`_applied_regions` exclusion is honest** — ~6 MB resident, real, disclosed, not DoS-class (sec).
- **20 line citations spot-checked, all exact** (qa).

## Ruling

**ITERATE to Phase 1** on BL-1…BL-7, majors folded in the same pass. Recorded as **Phase-2 iteration 1,
Phase-1 iteration 2**. The 3-iteration soft cap is live: **one more Phase-1 iteration remains before I
escalate to the operator rather than loop** (the plan's explicit instruction — this area hit the cap in
both Phase 1 and Phase 2 of batch-63).

---

# Phase-2 RE-GATE (iteration 2, discharge form) → **ITERATE — and the iteration cap is now REACHED**

**Score: 3 DISCHARGED (BL-2, BL-4, partial-credit aside) · 4 PARTIAL · 3 NEW blockers introduced by the fold.**

**The diagnosable pattern:** revision 2 tightened the *requirement* text and left the *AT predicate* at
the old scope — so three ATs (AT-222/223, AT-227, AT-231) are now RED after a **correct** implementation.
That is the BL-1 defect reproduced three more times, one level down. The reviewer's highest-leverage
observation: the single rule *"when a requirement's scope moves, the AT predicate moves with it"* closes
4 of the 7 open items.

## Two executed refutations, both re-verified by the orchestrator

1. **`LLR-105.7`'s reassurance is FALSE — the fold closed a forgery hole by re-opening a memory hole.**
   I wrote that the Address cell is "already bounded in aggregate … 3574 B × 200 ≈ 715 kB/variant".
   Executed: `_ADDRESS_RE` matches `'0x' + 'F'*100000`; **`int(raw, 16)` parses — CPython's
   `int_max_str_digits` limit does not apply to base-16 parsing** (`changes/io.py:953`); the cell renders
   **100,000 chars**. The real ceiling is `READ_SIZE_CAP_BYTES = 268,435,456` (`changes/io.py:224`).
   **3574 is what a decimal-limited value happens to render to; it was never a ceiling.** At 200 rows ×
   1 MB addresses, resident ≈ **200 MB** — and the cap lands in Inc-1 while the gate lands in Inc-3, so
   between those increments nothing bounds it at all.
2. **`BL-6`'s fix does not work.** `_checklist_lines:1243-1248` **already** computes
   `kept = sum(1 for … if _matches_entry(...))` — lazily, per variant — whenever a filter is present. An
   implementation that keeps that line, caps-and-**breaks** in the render loop, and reports
   `dropped = kept − CAP` states the **true** count and passes AT-225 with zero traversal continuation.
   **Deeper:** `LLR-105.4`'s declared subject ("traversal shall not terminate") has **no observable
   consequence** — one-pass and precount-plus-break produce byte-identical documents *and* identical
   `tracemalloc` ratios. **It is unfalsifiable as stated**, which means it is either not a requirement or
   needs a different justification than the one I gave it.

## New blockers created by the fold

| # | Defect |
|---|---|
| **N-1** | `AT-222`/`AT-223` require *"widest cell ≤ `REPORT_CELL_CHARS`"*, but new `LLR-105.9` declares `3·171−1 = 512` **already equals** it, so a truncated cell is `512 + cue`. **Every cell AT-222 tests is truncated by construction — Inc-1's own gate is RED after a correct Inc-1.** |
| **N-2** | `LLR-105.2` (Inc-2: a saturated check file **shall omit** header/rule) ⊥ `LLR-106.3` (Inc-3: header/rule **shall** be emitted outside the gate). Two unconditional `shall`s over the same lines, in different increments, with no precedence — they will be resolved differently. And the new clause has no AT and no TC. |
| **N-3** | `HLR-106` now asserts `≤ REPORT_MAX_TOTAL_BYTES` with **no** overshoot term, while `LLR-106.3` asserts one and §7 names the check-file count `F` uncapped. The fold removed a *correct* qualifier while fixing an *incorrect* scope, and AT-227 inherited the tight form — still unsatisfiable, with a smaller coefficient. |

Plus N-4…N-10: `HLR-105` now over-claims vs its own LLR set (the identical class the fold just fixed in
HLR-106); `US-B74-3`'s text was never actually edited and still carries the premise P-20 marks FALSE;
`LLR-105.9` has **no AT, no TC, no increment** and is contradicted by the only AT touching cell width;
6 LLR→TC coverage gaps concentrated precisely in the LLRs the fold added.

## Iteration accounting — **CAP REACHED, ESCALATING**

Phase-1 iterations: 1 (initial) → **2** (the BL fold) → a third would be revision 3.
Phase-2 iterations: 1 (cross-review) → **2** (this re-gate).

`PLAN.md` §5 and the operator's launch instruction are explicit: *"Si topas el cap, escala conmigo — no
hagas loop."* **This is the cap. Escalating to the operator rather than spending the last autonomous
pass.** The fix list is small and surgical and no new measurement is required — but the decision to
spend the final iteration, or to re-scope instead, is the operator's.
