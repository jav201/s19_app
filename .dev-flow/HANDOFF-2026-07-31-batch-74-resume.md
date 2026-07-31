# HANDOFF — batch-74 resume, written 2026-07-31

> **What this is.** batch-74 (`report_service` producer bounding) is **mid-Phase-3**: Phases 0-2 are
> approved, **Inc-0 and Inc-1 are committed and pushed**, **Inc-2 and Inc-3 remain**, then Phases 4-6.
> Written because the authoring session's context was heavily consumed and Inc-2 carries the batch's
> newest and least-exercised requirement. Companion to `.dev-flow/HANDOFF-2026-07-31.md`, whose
> §"PLAN — batch-74" is now **superseded** by the operator re-scope recorded below.

## 0. Read these, in this order, before touching anything

1. `.dev-flow/2026-07-31-batch-74/PLAN.md` — §9 is the resumption checklist.
2. `.dev-flow/2026-07-31-batch-74/01-requirements.md` — **revision 3 is the authority.** §4 LLRs, §5
   acceptance, §5.1 the memory oracle, §7 the increment cut.
3. `.dev-flow/2026-07-31-batch-74/03-increments/increment-001.md` — what Inc-1 did and what it cost.
4. `.dev-flow/2026-07-31-batch-74/02-review.md` — the three review cycles. **Read the "axes certified
   CLEAN" lists** so you do not re-open settled questions.

**The original handoff plan's §"PLAN — batch-74" is a HYPOTHESIS and large parts of it are now FALSE.**
Do not implement from it. Its OB-4 constant, its `_ByteBudget` framing and its D2 framing were all
falsified by measurement — details in §3.

## 1. State

| | |
|---|---|
| **Branch** | `claude/batch-74-s19-app-a693ff` — **13 commits, pushed, clean, no PR yet** |
| **Base** | `origin/main` = `d81cb3d` at cut. **Re-fetch and rebase if it moved.** |
| **Phase** | 3, in progress. Inc-0 ✅ · Inc-1 ✅ · **Inc-2 and Inc-3 remain** |
| **Iterations** | Phase 1: **3** · Phase 2: **3** — both hit the soft cap and escalated once |
| **Tests** | 82 passing across the batch's four affected files; engine-frozen guard green |
| **C-44 sweep** | project repo clean, 0 unpushed; `~/.claude` clean, 0 unpushed |

**Authorization: "Full autonomy + merge", granted 2026-07-31. A resumed session MUST ASK AGAIN.**
It is never inherited — not from the operator's launch prompt, not from `state.json`, and not from
this file. Ask before Inc-2.

## 2. The re-scope (operator decision at the iteration cap)

Phases 1 and 2 each burned their full 3-iteration budget; the escalation was per the operator's
standing rule (*"si topas el cap, escala conmigo — no hagas loop"*). The operator chose to re-scope.

| | |
|---|---|
| **KEPT** | **OB-4** (producer bound: cardinality cap + byte-run width) and **US-B74-2, the `Address` cell** — a story that was in **nobody's** charter until Phase-2 measurement found it |
| **SPLIT to batch-75** | **F4** (the `_ByteBudget` per-row gate) and **D2** (`_format_length` + the `app.py` error re-attribution) |
| **Surface** | 3 HLR / 20 LLR / 18 AT → **2 HLR / 9 LLR / 10 AT** |

**Why the split is safe, and what makes it unsafe if you forget:** every measurement behind F4 and D2
is written into `01-requirements.md` §6. **Inc-3 must land those into `.dev-flow/BACKLOG-CODE.md`.**
If Inc-3 skips that, the split silently becomes a deletion.

## 3. Premises that came back FALSE — do not re-inherit them

Seven, each with an executed counterexample. Full table in `01-requirements.md` §2.7.

| Premise | Reality |
|---|---|
| OB-4 costs a flat **988 B/entry** | `≈ 92 + 6·L` — **linear in byte-run length**; 988 is its value at `L≈149` |
| Charging the tables to `_ByteBudget` closes F4 | `emit()` **accounts, never gates** — it closes nothing |
| A cap < 415 re-baselines a golden | 415 was a **file-wide sum over 6 documents**. Max single table = **200** |
| `md_safe` on byte cells drifts nothing | `md_safe("-")` → `'\-'`; **3/3** goldens carry a bare `-`. Also a *sink* bound |
| "A huge **address** denies the report" | False — a huge address renders fine; the raise keys on **`Length`**'s decimal digits |
| The `Address` cell is bounded at 3574 chars *(my own revision-2 claim)* | **`int('0x'+'F'*100000, 16)` PARSES** — the digit limit does not apply to base 16. Cell = **100,000 chars**; ceiling `READ_SIZE_CAP_BYTES` = **268 MB** |
| "Traversal shall not terminate" is a requirement | **UNFALSIFIABLE** — one-pass and precount-then-break produce byte-identical documents *and* identical memory ratios. Withdrawn; replaced by a requirement on the **count's correctness** |

## 4. Inc-2 — what to build, and the three traps

**Files (≤5):** `report_service.py`, `tests/test_report_producer_bound.py`.
**Nodes:** AT-241, AT-243 (full), AT-245, AT-246, AT-249 · TC-546…TC-551.

**(a) `_checklist_lines` cardinality cap** — LLR-105.2. Cap is `MAX_REPORT_ROWS_PER_VARIANT` **summed
across all of the variant's check files**, not per check-file table: the check-file count `F` has no cap
anywhere, so a per-table cap leaves `F × C` unbounded. Once saturated, a later check file renders
heading + aggregates + its own `> TRUNCATED:` line and **omits the table header and rule** — a reader of
check file 3 must not meet an empty table with no local explanation.

**(b) The `Address` bound** — LLR-106.1…106.4. This is the newest requirement in the batch and the
least exercised.

> ### ⚠ TRAP 1 — derive `REPORT_ADDRESS_CHARS` TOP-DOWN or AT-246 goes RED on correct code
> `REPORT_ADDRESS_CHARS = len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue at max elided count)`.
> The **policy number is `REPORT_ADDRESS_HEX_DIGITS`**; the cell width is its consequence. Deriving it
> bottom-up from the golden census (widest golden Address cell = 10 chars) puts it near 10-32, and
> AT-246 requires the *whole truncated cell including the cue* to fit — so a correct implementation
> fails its own acceptance. This exact defect already happened once at Inc-1 (revision 2's AT-222).

> ### ⚠ TRAP 2 — truncating the Address without changing its FORM is a forgery, not a bound
> A truncated hex address is still a well-formed `^0x[0-9A-F]+$` numeral, so a shortened cell is
> **indistinguishable from a complete one** — measured understatement `2^12248`. The truncated form
> **must fail** that regex and **must state the elided digit count**, computed as
> `(n.bit_length()+3)//4 − REPORT_ADDRESS_HEX_DIGITS` — **not** `len(raw) − 2`, because
> `int('0x0FF…', 16)` discards wire leading zeros and the two differ.

> ### ⚠ TRAP 3 — bound at the SOURCE, and prove it with a residency oracle, not an output predicate
> **This is the finding that blocked Inc-1, and it will recur verbatim on the Address axis.** Every
> output-shaped predicate is blind to *format-then-slice*: it emits **byte-identical output**. At Inc-1,
> seven output-shaped nodes — including the positive control and `test_f17` — stayed GREEN under that
> mutation while the implementation peaked at **56,683,416 B vs 9,490 B (5,973×)**. Only the residency
> oracle caught it. **AT-249 is the Address-axis equivalent and is not optional.** Derive the leading
> digits arithmetically (`n >> 4*(total−K)`); `bit_length()` is O(1) and the shift is O(result) —
> measured 0.000002 s vs 0.0014 s at 10⁶ hex digits.
>
> Do **not** use a consumption counter as the oracle. It was rejected for the cardinality axis (P-25),
> and on the width axis it goes RED on *correct* code, because `_format_bytes` deliberately drains the
> iterator to count elided values. **Residency is the only honest oracle here.**

**(c) The cue must be inert** — LLR-106.4. The Address cell is emitted **unescaped** (`:1104`, `:1276`)
and `CUE_ALPHABET` covers `_format_bytes` only. The natural first spelling contains `.`, **which is in
`MD_ESCAPE`**. Use `…` (U+2026), already precedented by `TRUNCATION_MARKER`, and extend the inertness
claim to cover this cue.

## 5. Inc-3 and beyond

**Inc-3** (`REQUIREMENTS.md`, `.dev-flow/BACKLOG-CODE.md`): write R-TUI-101 with its non-claims; amend
R-TUI-097's "scope carried" paragraph (**remove** its stale `031ca8d` line numbers, do not update them);
correct R-TUI-098 non-claim (a)'s `988 B/entry` figure; and **land the batch-75 split with every
measurement from §6**. Two wording carve-outs found by implementing are still owed: **LLR-105.5's "the
total"** is ambiguous (resolved in code as the *kept* total — say so), and **LLR-105.7's set-inclusion is
literally false for `values=None`** (`"-"` is in none of the three sets; needs a non-`None` carve-out).

**Then Phases 4-6.** Phase 4's gate suite is **orchestrator-run, never delegated** (C-25) — it exceeds
the tool cap and a sub-agent that launches it will exit before it finishes.

## 6. Concurrency — batch-73 is LIVE

`claude/batch-73-linkage-fix-0372a0` exists and is running in parallel.

- **File-disjoint on code**: it owns `changes/apply.py` + `tests/test_linkage_soundness.py`. Verified
  zero overlap with `report_service.py` / `tests/test_report*`.
- **Shared at close**: `REQUIREMENTS.md` and `.dev-flow/BACKLOG-CODE.md`. **Whoever closes second
  rebases.**
- ⚠ **It already caused the THIRD id collision in this repo** (after 64→65 and 66→67), consuming
  AT-219…223 and TC-520…524 — exactly batch-74's Phase-0 allocation. batch-74's live set was renumbered
  to **AT-240…249 / TC-540…551**. **Re-run the ID census before authoring any new node.**
- `state.json` is last-writer-wins with no owner field. **Re-read it immediately before every write.**

## 7. Conventions this batch is being held to

- **C-40 both limbs, executed.** For every predicate answer *"can it go RED?"* **separately** from
  *"is it correct?"*, name the mutation, **run it**, and paste the transcript. Run mutations on a copy
  of the **fixed** tree in an export — never `main` (an `ImportError` RED proves nothing) and never a
  tree another session reads. **Restore and verify by file hash.** An apply-check is mandatory: a
  typo'd mutation also "fails", for the wrong reason — that guard fired once at Inc-1 and saved a false
  discharge.
- **C-39.** Any number a gate keys on is executed and pasted, never predicted or inherited. Inc-1 found
  §5.1's `CAP-ONLY = 1.921` unreproducible (measured 2.224) because the counterfactual shape was never
  *defined*; it now lives in code as `_shipped_body` / `_cap_only_body`.
- **CI is not a gate you may cite silently.** `tui-ci` runs `ubuntu-latest` (structurally blind to
  newline defects) and the **blocking job installs plain `pytest`, so snapshot cells are SKIPPED**; only
  the advisory `continue-on-error` job exercises them. Say this explicitly whenever citing CI.
- **Engine-frozen set is off-limits**, source *and* test files — run both guards.
- **≤5 files per increment**; a review packet per increment; independent `code-reviewer` at every
  increment gate (it is what caught Inc-1's HIGH).

## 8. Honest assessment of what is left

The specification is the expensive part and it is **done and thrice-reviewed**. Inc-1 proved the shape
works: single-pass producer, source-bounded formatter, residency oracle. **Inc-2 is the same shape
applied to a second producer plus one new column** — mechanically similar, but the Address axis has no
prior art in this batch and all three traps above are live on it.

The recurring lesson, stated plainly for whoever picks this up: **in this module the defects are in the
specifications and the acceptances, not in the code.** Every real defect this batch found — seven false
premises, an unsatisfiable AT, an unfalsifiable requirement, a vacuous width axis — was found by
*executing* something someone had *written down and believed*. Budget accordingly.
