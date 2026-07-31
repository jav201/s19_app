# batch-75 — Phase 2 cross-agent review

**VERDICT: ❌ BLOCK → `iterate-to-refine` (Phase 2 iteration 1).**
Lanes: `security-reviewer`, `qa-reviewer`. (The `architect` lane ran at Phase 1 and its central
new claim, P-14, was executed and came out **FALSE** — recorded in `01-requirements.md` §2.2.)

**3 blockers · 9 major · 9 minor.** The two lanes ran independently and **found the same three core
defects**, which is the strongest corroboration available here. Two of the three are in clauses **I
authored**, and one of those is the house defect landing in the artifact whose job was to prevent it.

---

## §1 BLUF — the three blockers

| # | Defect | Found by | Verified by me |
|---|---|---|---|
| **B-1** | **`HLR-102`/`LLR-102.x` are LIVE ids owned by batch-63's `R-TUI-097`**, cited in the very file batch-75 edits | security **F3** + qa **B-1**, independently | ✅ `report_service.py:608` (`LLR-102.2`), `:622` (`LLR-102.1`), `REQUIREMENTS.md:4945` |
| **B-2** | **The refusal disclosure is `O(V)` and unbudgeted** — `HLR-102`'s own disclosure clause contradicts its `V`-invariance clause | security **F2** + qa **B-2**, independently | ✅ by construction from `LLR-102.1` + `.2` + `.6` |
| **B-3** | **`_hexdump_section`'s `put()` never gates**, so my named exemption `LLR-102.4` rests on a false premise and leaves an ungated `O(V)` term | security **F1** | ✅ `report_service.py:1748-1750` — `out.extend(...); budget.consume(...)`, no `fits`; 5 ungated `put()` sites |
| **B-4** | **`AT-252` is vacuous** — its fixture cannot reach the budget, so it is green on base, fixed, and stubbed | qa **B-3** | ✅ 10 files × 8 lines × ~50 B ≈ 4 kB vs a 2,097,152 B budget |

### B-1 — the id namespace I never derived

I re-derived the **AT/TC** high-water because the operator explicitly required it, then **assumed the
HLR/LLR namespace tracked the `R-TUI-` number.** It does not — they are separate counters.

| id | already means (shipped) | batch-75 proposed |
|---|---|---|
| `LLR-102.1` | `document_bytes` is the single encoder seam | `emit` shall gate on `fits` |
| `LLR-102.2` | `_line_bytes` is partition-invariant; redefining it is **prohibited** | refusal shall not latch |
| `LLR-102.4` | **golden neutrality — no stored golden shall move** | `_hexdump_section` keeps its own budget |

The `LLR-102.4` collision is the sharpest: batch-75's `AT-255` **is** a golden-neutrality PIN, sitting
beside a re-used id that already means golden neutrality. Post-merge, a grep for `LLR-102.2` in
`report_service.py` returns two mutually exclusive contracts from 20 lines of the same file.

**This is the *"an unstated grep pattern is an unstated definition"* lesson, one level up: I derived the
namespace I was told to derive and inherited the one I was not.**

**Resolution:** high-water in `s19_app/` + `REQUIREMENTS.md` is **`HLR-106`/`LLR-106`** (batch-74);
batch-74's own artifacts carry `HLR-107`/`LLR-107`. Renumber to **`HLR-108`/`109`/`110`** and
**`LLR-108.x`/`109.x`/`110.x`**, and **add the HLR/LLR derivation to `00-measurements.md` §8** so the
next batch does not repeat it.

### B-2 — the disclosure clause contradicts the invariance clause

Read together: `LLR-102.1` (*"on refusal it shall append **one disclosure line**"*) + `LLR-102.2`
(*refusal is per-call and **shall not latch***) + `LLR-102.6` (allowance is a **constant**, derived from
a *closed* set).

`generate_project_report` makes ~4 preamble + **6 per variant** + 2 tail gated calls. At `V = 100` that
is ~606 calls; `AT-251`'s own fixture exhausts the budget around variant 7, so **~558 calls each append
a disclosure line** ≈ **45–65 kB of ungated disclosure** against an allowance of ~1 kB.

**`AT-251` at `V = 100` goes RED for a *correct* implementation.** The number of disclosure lines is
`O(V)`, so `HLR-102`'s *"independently of the variant count `V`"* is contradicted by `HLR-102`'s own
disclosure clause. The attacker converts the gate into a per-variant emitter: **the more it refuses, the
more the document grows** — a fail-open shaped exactly like a gate.

**Resolution — aggregate the disclosure.** At most **one disclosure line per section label**, carrying
cumulative counts; the line count is then bounded by the cardinality of the closed label tuple, the
allowance derivation becomes total, and `V`-invariance becomes true rather than asserted.

### B-3 — my own exemption rested on a false premise

`LLR-102.4` exempted `_hexdump_section` *"on the grounds that it keeps consuming through its existing
internal gate"*. Executed: `put()` (`:1748-1750`) **consumes unconditionally and never calls `fits`**.
Only the block loop at `:1785` gates. Five `put()` sites are outside every gate — the `### Memory
regions` heading (unconditional, **every variant**), two early-return notices, and two `> TRUNCATED:`
lines — ≈ **178 B/variant**, i.e. ~17.8 kB at `V = 100`, past the ceiling, unrefusable.

This is the defect the batch was chartered to fix, surviving **inside the batch's own named exception**.

**Resolution:** `put()` gates exactly as `emit` does. `LLR-102.4`'s exemption narrows to the block
loop's existing `fits` gate only. `TC-553`'s census must extend to `out.extend`/`put` inside
`_hexdump_section` — **as worded it walks the wrong function and would score this hole green.**

### B-4 — the house defect, in my artifact

`AT-252` (the `F` axis) specifies *"few rows per file … so batch-74's cap never fires"*. Measured: 10
check files × 8 structural lines × ~50 B ≈ **4 kB** against a **2,097,152 B** budget. Nothing is ever
dropped, so `len(bytes) <= CEILING` is satisfied by the base tree, the fixed tree, **and a gate stubbed
to `return True`.** It cannot go RED for the change it gates, and unlike `AT-255` it is not labelled a
PIN — it is §3.1's *only* `F`-axis acceptance.

I claimed `TC-558` guarded this fixture. It does not: `TC-558` measures structural lines *per arm*,
which says nothing about whether the fixture approaches the budget. The correct control, `TC-552`, is
scoped to `AT-250`'s producers only. **Exactly the batch-74 vacuous-fixture class the operator flagged.**

**Resolution:** every ceiling AT asserts its own Σ`_line_bytes` **exceeds the effective limit**; and
`AT-252` must state its mechanism — raise `F` into the thousands, **or** shrink `_ByteBudget.limit`
(supported: `:664` says the limit is read at call time so tests can shrink it) and express the ceiling
as `effective_limit + ALLOWANCE`.

---

## §2 The two UNDECIDABLEs — both RESOLVED by the qa lane, by execution

| # | Proposition | Verdict |
|---|---|---|
| **P-18** | `AT-262`'s operator-rejection arm is reachable from the shipped dialog | ✅ **TRUE — reachable.** `screens.py:1569`: `#report_context_bytes` is a bare `OsClipboardInput` — **no `type=`, no validator, no `restrict`, no clamp**. `screens.py:1714-1719`: `int(raw)` is the only parse and accepts *any* integer. `-1` → `ReportOptions(context_bytes=-1)` → raises → `Report rejected: context_bytes must be an integer in 0..4096, got -1`. **`AT-262` stays a black-box AT; `HLR-104` keeps its black-box negative.** |
| — | Does `TC-558`'s **8-arm** exist, or is it a phantom I inferred? | ✅ **EXISTS**, verified against `_checklist_lines`' conditionals: 4 base + 2 (`not (saturated and file_kept)`) + 1 (`file_dropped`) + 1 trailing = **8** at mid-file saturation. Constructible: one check file with 250 entries at cap 200. A **fourth** arm exists too (`saturated and file_kept == 0` → 7, numerically colliding with the unsaturated arm but a distinct branch). |

**P-16** (can uniform gating drop the preamble?) is **superseded** — under B-2's aggregation fix and B-3's
`put()` fix the preamble question is re-opened at Inc-1 with different arithmetic. Carried forward.

---

## §3 Major findings requiring a normative clause or an explicit non-claim

| # | Finding | Lane | Disposition |
|---|---|---|---|
| **M-1** | **Three more ATs are PINs counted as coverage** — `AT-254`, `AT-260`, `AT-261` are all **green on the base tree** (`AT-260`: fail-closed already holds by construction per my own P-12; `AT-261`: `app.py:4163` **and** `:4176` already reset progress today). Only `AT-250`/`251`/`253` and `AT-259`/`262` discriminate. | qa | **ACCEPT** — carry `AT-255`'s explicit PIN label onto all three and state the discriminating count per story. |
| **M-2** | **`TC-555` is a tautology risk.** If the code is `ALLOWANCE = _derive()` and the test asserts `ALLOWANCE == _derive()`, it cannot fail — the same shape I explicitly refused for `AT-256/257` two sections earlier. | qa | **ACCEPT** — `TC-555` recomputes the allowance independently in the test, never calling the product helper, plus a discriminating arm. |
| **M-3** | **`TC-560` has no positive control** and asserts the census is **empty** — *a broken AST walk returns zero and passes.* `TC-567`'s walk ("reachable from the guarded span") is **not statically computable** as worded. | qa | **ACCEPT** — `TC-560` gains a `TC-554`-shaped planted-violation control; `TC-567` defines its walk as a lexical scan over a recorded tuple of functions. |
| **M-4** | **4 orphan LLRs** (`102.2` non-latching — *nothing verifies it*; `102.5` appendix cap — orphan **and inert**, since today's note count is 3→4 so a cap above never fires; `103.6` cue alphabet; `104.2` single helper) + **2 mis-traced TCs** (`TC-558`/`TC-559` both cite `LLR-102.5`, neither tests it). | qa | **ACCEPT** — add nodes or retire the clauses; re-trace. |
| **M-5** | **My mutation cells violate the project's own substituted-value rule two lines after citing it.** *"drop the `0x`"* names three different mutants. Same defect in `AT-251`, `AT-252`, `AT-260`. | qa | **ACCEPT** — every mutation cell records a substituted **expression** (`f"0x{value:X}"` → `f"{value:X}"`). |
| **F4** | **`LLR-102.5` is an attacker-controlled disclosure-suppression channel.** Notes accumulate in traversal order; the natural `notes[:CAP]` retains the **earliest**. An attacker authors `CAP` filler variants each tripping the region-cap note (>128 regions, a low bar), naming them to sort ahead, so **the note identifying their target variant falls past the cap**. The auditor sees a tidy appendix and cannot reconcile. | security | **ACCEPT** — retention must be round-robin by variant; the summary tail must state **distinct variants** with un-itemised notes; `TC-559` gains a last-variant-at-risk arm. Also: `REPORT_MAX_TRUNCATION_NOTES` is **chosen, not derived** — state its basis. |
| **F5** | **`LLR-102.3`'s "no operator-derived string" is a sizing constraint wearing an injection constraint's clothes**, and it is *stricter than the shipped appendix*, which already interpolates `md_safe(variant_id, …)` at `:1776`/`:1796`. It buys anonymity at the cost of reconciliation: *"3 Modifications sections dropped"* checks against nothing. | security | **ACCEPT** — replace the blanket ban with the **integer index** of the variant in `variant_results`: literals + integers only, satisfies the letter, reconcilable against the Inventory. Bound the index list. |
| **F6** | **`AT-253`'s "counts sum to what was actually cut" has no UNIT.** Sections? Lines? Bytes? An implementation emitting `"3 sections omitted"` satisfies it while telling the auditor nothing — three sections could be 40 B or 900 kB. **The canonical vacuous shape, on the one acceptance carrying the batch's evidentiary integrity.** | security | **ACCEPT** — fix the unit normatively: each disclosure carries `(sections, lines, bytes)`; `AT-253` asserts the **byte** sum equals `Σ _line_bytes(refused)`. |
| **F7** | **Emission order decides *whose* audit record survives, and order is attacker-steerable.** Variant 1 with 200 declaration errors × 500-char messages (**311,625 B**, measured, schema-legal, wire-reachable) exhausts the budget by variant 7; variants 8–100 are refused entirely. The attacker chooses which variant is documented and which is blank. `HLR-102`'s third clause is a *liveness* property and says nothing about **fairness**; first-fit over attacker-ordered input means attacker-chosen. | security | **⚠️ OPERATOR DECISION OWED** — per-variant reservation vs. first-fit with a stated non-claim. Both defensible; **silence is not.** Escalated below. |

**Minors accepted without discussion:** F8 (US-B75-1's *"a report I can open"* over-reaches where the HLR
does not — add a completion caveat), F9 (`LLR-102.6`'s derivation is not total while the count field is
unbounded — state the max count width, read at call time), F10 (the decimal forgery **is** closed — good
construction; and the **negative** `Length` is *also* constructor-only, since `len(encoded_bytes) ≥ 0`, so
§7(i) must not imply the negative case is the live arm), F11 (`|` is redundant — it is already in
`MD_ESCAPE`; and the clause should cover the whole emitted token, not just the cue), F12 (`HLR-104` moves
`ValueError` onto a path that writes a **full traceback with host paths** to `s19tui.log` — matches every
other exception type and is deliberate, but must be **said** in non-claim (g)), m-1 (`TC-558` needs a
fourth arm and must state whether the per-variant `### Checklists` header is in its count), m-2, m-3.

**Non-findings recorded so they are not re-argued:** fail-closed holds by construction (single
`write_bytes` after composition); `_line_bytes` over-accounts by exactly 1 B/document — **conservative**,
no undercount to exploit; section labels are section *kinds* and leak no operator data; counts are
integers and not an injection vector; the `Length` token alphabet cannot reach a cell separator;
`MemoryError` is caught by `app.py:4166` and degrades to a message rather than hanging; **`HLR-102`
contains no memory wording** — finding F-4 from Phase 1 is being honoured.

---

## §4 Escalation to the operator — one decision, per non-negotiable #4

**F7 (fairness) is a policy decision I will not absorb.** Under a budget gate, *who gets documented* is an
integrity property of an evidentiary record, and an attacker who controls content controls the order.

| Option | Result | Consequence |
|---|---|---|
| **Per-variant reservation** | each variant is guaranteed `REPORT_MAX_TOTAL_BYTES / max(V,1)` (floored) | ✅ no variant can starve another; makes `V`-invariance structural rather than emergent · ⚠️ small variants waste their share; more implementation |
| **First-fit + stated non-claim** | earlier variants may consume the whole budget | ✅ simplest, matches `_hexdump_section`'s existing convention · ❌ an attacker chooses whose record is complete — must be written as an explicit non-claim so nobody reads `HLR-102` as an integrity guarantee |

---

## §5 Gate decision

**Exit-criteria axes unmet:**
- **Certainty** — `AT-252` is vacuous (B-4); `AT-254`/`260`/`261` are PINs counted as gates (M-1); `TC-555` is a tautology (M-2); `TC-560` passes on a broken walk (M-3); four mutation cells are ambiguous (M-5).
- **Coverage** — 4 orphan LLRs, 2 mis-traced TCs (M-4).
- **Evidence** — B-2 and B-3 mean `AT-250`/`AT-251` are **unsatisfiable by a correct implementation**, so no evidence they could produce would mean what the gate reads it as.

**Decision: `iterate-to-refine` → Phase 1, iteration 1.** Amendments recorded in `01-requirements.md`
§6.5 (Before/After · Deleted/New).

**Iteration budget (operator non-negotiable #4):** this area hit the 3-cap in Phase 1 **and** Phase 2
across b63 and b74. This is **Phase 2 iteration 1**. At iteration 3 I escalate rather than loop.
