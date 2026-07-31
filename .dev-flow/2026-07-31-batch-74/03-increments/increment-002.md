# batch-74 — Inc-2 review packet

**LLR-105.2 · 105.4′ · 106.1 · 106.2 · 106.3 · 106.4** · ATs **241, 243 (promoted), 245, 246, 249** ·
TCs **546-551**

> **BLUF — the batch's central lesson held on BOTH sides of the gate.** I authored TRAP 3's falsifier
> before writing the code, and it paid: executed on a copy of the fixed tree, a `format-then-slice`
> `_format_address` emits a **byte-identical cell**, **AT-246 — the forgery gate, all three conjuncts —
> stays GREEN** under it (M6b), and only residency moves, **1.000 → 9.976**. AT-249's existence is now a
> measured fact rather than a spec paragraph.
>
> **And then the independent review ran 16 mutations of its own and FIVE SURVIVED my suite** — every one
> of them the *same defect class I had just congratulated myself on closing*, one level down. The
> sharpest: every Address fixture I wrote was all-`F`, and on an all-`F` value **rendering the trailing
> digits instead of the leading ones is byte-identical**, as is dropping the `+3` from the very ceiling
> formula `TC-549` quotes. The shipped code was correct at every site; **nothing I wrote could have
> failed if it had not been.** All five now redden. This is the third consecutive increment in this
> module where the defect was in the *acceptance*, not the code.

## 1. What changed

| File | Change |
|---|---|
| `s19_app/tui/services/report_service.py` | `REPORT_ADDRESS_HEX_DIGITS = 16` (**the policy number**) · `REPORT_ADDRESS_TRUNCATION_CUE_FMT` · `REPORT_ADDRESS_MAX_ELIDED_DIGITS` (derived from `READ_SIZE_CAP_BYTES`) · `REPORT_ADDRESS_CHARS` (**derived top-down**, evaluates to 49) · new `_format_address` · `_checklist_lines` cardinality cap summed across check files + saturated-file rendering · both `Address` call sites routed through `_format_address` |
| `tests/test_report_producer_bound.py` | AT-241/245/246/249 + TC-546…551; AT-243 promoted from its Inc-1 partial with a composition arm; `TC-544` extended producer-side |

**Two files, both in `01-requirements.md` §7's Inc-2 row. ≤5 honoured.**

### The Address bound, and why its shape is the requirement

`_format_address` derives the kept digits **arithmetically** — `magnitude >> (4 * (total - kept))` —
never by formatting and slicing. `bit_length()` is `O(1)` and the shift allocates only the result's
limbs, so residency is independent of the value's size. The truncated form is deliberately **not** a
numeral: it carries `…` and a stated elided count, so it **fails** `^-?0x[0-9A-F]+$`. A truncated
address that still parsed as hex would understate the true value by `2**(4·elided)` with nothing in the
document to say so — closing a memory hole by opening a forgery hole.

The elided count is `(n.bit_length() + 3) // 4 − REPORT_ADDRESS_HEX_DIGITS`, **not** `len(raw) − 2`:
`int('0x0FF…', 16)` discards the wire's leading zeros, so the two differ. TC-549's leading-zero arm
asserts the fixture makes them differ before asserting the count, so the arm cannot pass vacuously.

### The checklist cap, and why it is summed

`MAX_REPORT_ROWS_PER_VARIANT` is spent **across all of the variant's check files**. The check-file count
`F` has no cap anywhere in the system, so a per-table cap would leave `F × CAP` unbounded — a bound in
name only. A file arriving already saturated renders heading + aggregates + its own `> TRUNCATED:` line
and **omits the table header and rule**.

## 2. Independent review — **BLOCK**, then discharged

**The reviewer ran 16 mutations of its own and FIVE SURVIVED.** All five were on the Address axis or on
design ruling 3 — the checklist *cardinality* half it certified as genuinely guarded. Every survivor is
the same class as Inc-1's F1 and as this batch's diagnosed pattern: **the shipped code is correct at
both call sites; what was missing is any predicate that could fail if it were not.**

| id | sev | Finding | Disposition |
|---|---|---|---|
| **F1** | **HIGH** | **`LLR-106.1/106.2`'s scope is BOTH producers; every Address predicate exercised only `### Modifications`.** Reverting *only* the checklist call site to the shipped `f"0x{…:08X}"` left the checklist `Address` cell **100,002 characters** wide and forgeable — **with all 29 nodes green**. Check entries carry the same unbounded address (`changes/check.py` ← `_parse_address` ← `_ADDRESS_RE`, no digit limit), so the site is equally wire-reachable, and §5.2 had *already registered* "one AT covering both sites" as vacuous | **FIXED** — AT-246 gained a second-site arm. Mutation now RED on `the CHECKLIST Address cell is 100002 chars, over the … = 45 bound` |
| **F2** | **HIGH** | **Every Address fixture was `F`-uniform, hiding two independent defects.** (a) `magnitude & ((1<<4·kept)−1)` renders the **trailing** digits while the cue claims the leading ones — on all-`F` input the two strings are identical. (b) `bit_length()//4` instead of `(bit_length()+3)//4` — **the `+3` is a no-op whenever the top nibble is ≥ 8**, which every `F`-leading value satisfies; the floor variant renders **17** digits, one over the bound. **TC-549 is the node that QUOTES that formula and its own fixture could not exercise it** | **FIXED** — TC-549 gained a non-uniform, top-nibble-`<8` arm with both fixture preconditions asserted. Both mutations now RED |
| **F3** | MEDIUM | **Design ruling 3 had no falsifier** — relaxing the guard to `if not saturated:` passed all 29 while rendering a saturated zero-kept file as heading + aggregates and **nothing else**. *(This is the gap I had self-caught and recorded as defect (m) before the review returned; the reviewer found it independently and, more usefully, executed it)* | **FIXED** — `TC-547b`. Mutation now RED |
| **F4** | LOW | The negative-address branch was **entirely uncovered** | **FIXED, not deleted** — `TC-549b`. Deleting the branch does not remove the case: `value >> k` on a negative is an *arithmetic* shift, so a signless implementation renders a different magnitude silently |
| **F5** | LOW | **My "14 occurrences" figure does not reproduce — the AST walk finds 26** | **CORRECTED below.** The ruling stands; the number was mine and it was wrong |
| **F6** | LOW | `REPORT_ADDRESS_CHARS` has **zero production consumers** | **Noted, no code change** — see §4 (n) |

**Design rulings: all five ACCEPTED**, one with a caveat that has been actioned — ruling 5 subtracts a
*digit* count from a *byte* count, which is a valid upper bound but was not said out loud. The unit
conflation is now named in the constant's docstring rather than left for the next reader to re-derive.

**Verification that the fixes are fixes.** Each of the five survivors was re-run against the patched
tree (`mutate3.py`, export at `C:\…\Temp\b74fix`, apply-check + hash-verified restore, baseline and
post-restore both green):

```
BASELINE on the patched tree: rc=0 :: 31 passed
  F1/M1 checklist Address reverted to the shipped rendering  -> RED (fixed)
  F2a/M2 render the TRAILING kept digits                     -> RED (fixed)
  F2b/M9 floor division instead of the ceiling               -> RED (fixed)
  F3/M4 saturation guard ignores file_kept                   -> RED (fixed)
  F4/M8 drop the sign on a negative address                  -> RED (fixed)
STILL SURVIVING: none — all five reddened
```

The original 11 were re-run on the patched tree too and **all still redden**, including **M6b, which
correctly still passes**: AT-246 remains blind to format-then-slice even with its second-site arm,
because both sites are output-equivalent under that mutation. **AT-249 is still the only falsifier**,
which is the point the arm does not change.

**What the reviewer independently reproduced rather than trusted:** 29/29 green, the residency
transcript `1.000` vs `9.976` to three decimals, the engine-frozen guard, and 102 nodes of
golden/census non-drift. It also flagged, correctly, that `REQUIREMENTS.md` / `BACKLOG-CODE.md` /
`increment-002.md` were dirty in the same tree — that is **Inc-3 scope and was not reviewed here**; the
two Inc-2 files it reviewed were byte-for-byte the ones in the diffstat.

## 3. Evidence

**All 31 nodes in the file pass; 389 pass across all 12 `test_report*.py` files plus the engine-frozen
guard; the second engine guard (`test_tui_directionb.py::test_tc031_*`) passes.** Ledger: **18 → 31
(+13, −0)** — 11 authored, plus `TC-547b` and `TC-549b` added to discharge the review. `ruff check`
clean on both files (courtesy only — the repo configures no linter and `tui-ci` has no lint step).

**Whole lean suite, run locally:** `pytest -q -m "not slow"` → **2411 passed, 2 skipped, 21 deselected,
3 xfailed in 27m13s**, exit 0, plus **29 snapshots passed**.

> ⚠ **Stated explicitly, because citing this as "CI green" would be false.** The blocking `tui-ci` job
> installs plain `pytest` and never the `[dev]` extra, so **those 29 snapshot cells are SKIPPED there**;
> only the advisory `continue-on-error: true` `snapshot` job exercises them, and it cannot fail the
> workflow. `tui-ci` also runs `ubuntu-latest`, structurally blind to newline-keyed defects. The local
> run above is therefore *stronger* than the blocking gate on snapshots and *weaker* on nothing —
> but it is a LOCAL run, not CI.

**Order-independence is not a live risk here and the reason is mechanical, not virtuous:**
`pytest-randomly` is **not installed** in this environment, so the `-p no:randomly` flags used during
development were no-ops and collection order is declaration order.

### 3.1 The §5.1 oracles, re-derived on this tree (C-39)

```
AT-242b width oracle (L: 2·B -> 20·B)
  SOURCE-BOUNDED (shipped) : 1.000
  FORMAT-THEN-SLICE        : 9.941
  gate                     : <= 1.15

§5.1 oracle re-derivation (E: 2·CAP -> 20·CAP)
  SHIPPED  : 9.836
  CAP-ONLY : 2.224
  FUSED    : 1.000
  gate     : <= 1.15

AT-249 Address oracle (D: 1000·K -> 10000·K hex digits)
  SOURCE-BOUNDED (shipped) : 1.000
  FORMAT-THEN-SLICE        : 9.976
  gate                     : <= 1.15
```

### 3.2 Counterfactuals — 11 mutations, on a COPY of the FIXED tree

Harness in the session scratchpad; export at a short root (`C:\...\Temp\b74exp`) because the scratchpad
path plus `tests/__snapshots__/...` overruns Windows `MAX_PATH` — **a copy that silently loses files is
not the fixed tree**, so the prune list is explicit rather than incidental. Every mutation carries an
**apply-check** (anchor present · content changed · hash changed) and a **restore-check** (hash equals
the pristine `7465c3de0904959a`). Baseline and post-restore both GREEN.

| # | Mutation | Verdict | Failed on |
|---|---|---|---|
| M1 | cap PER CHECK FILE instead of per variant | RED | `the cap must be summed across check files: … total 400, expected exactly 200` |
| M2 | emit the table header even when saturated | RED | `a saturated check file emitted a table header with no rows under it` |
| M3 | notice states the PRE-FILTER population as its total | RED | `must state its KEPT overshoot (137) of its KEPT total (337); a population-based count would state 196 of 396` |
| M4 | **the forgery** — truncate without changing the form | RED | `the truncated Address '0xFFFFFFFFFFFFFFFF' still matches the COMPLETE-address form` |
| M5 | state a wrong elided count | RED | width conjunct (`46 chars, over the … = 45 bound`) + TC-549's count |
| M6 | **format-then-slice the address (TRAP 3)** | RED | `residency scales with the digit count: … ratio=9.976 > 1.15` |
| M7 | `REPORT_ADDRESS_CHARS` derived bottom-up | RED | `= 32 but its stated derivation yields 49` |
| M8 | cue spelled `...` instead of `…` | RED | `carries Markdown-active characters ['.']` |
| M9 | width bound dropped on the checklist capped path | RED | `Expected cell is 2051 chars, over the … = 532 bound` |
| **M10** | count perturbed with the cue LENGTH held constant | RED | `the cell must state the elided digit count 99984` |
| **M6b** | **AT-246 under format-then-slice** | **GREEN — by design** | *nothing. This is the finding.* |

**M10 and M6b exist because the first pass left two gaps, and the gaps were only visible by reading
which assertion fired.** M5 reddened AT-246 on its **width** conjunct — a larger elided number makes a
longer cue — so AT-246's **count** conjunct was never reached and had no falsifier. M10 perturbs the
count from `99984` to `99983`, holding the cue's length fixed, and reddens the count clause alone.

**M6b is the load-bearing one.** It executes the claim that would otherwise be an argument: under
format-then-slice, AT-246's three conjuncts — width, form, count — are **all satisfied**, because they
constrain only the emitted token and the emitted token is byte-identical. Without AT-249 this increment
would ship the exact defect Inc-1 shipped and had caught for it.

### 3.3 Byte-identity and hot path

`AT-247` (positive control against the Inc-0 golden, captured from the **shipped** producer) is green,
so no in-domain report drifts. Golden census re-executed rather than inherited: the widest `Address`
cell in any golden is **10 chars** (`0x00000000`), against a bound of `len("0x") + 16 = 18` before the
cue — the bound cannot fire on any golden row. Hot-path cost measured, not assumed: `_format_address`
adds **77 ns/row** over the shipped f-string (180 → 256 ns), i.e. **~15 µs per 200-row variant**.

## 4. Spec defects and design rulings found by implementing

| # | Item | Disposition |
|---|---|---|
| **h** | **`REPORT_ADDRESS_HEX_DIGITS = 16` is a NEW policy number the spec deliberately left unchosen** (§5.3: *"`REPORT_ADDRESS_CHARS` is NEW and its value is not yet chosen"*). Ruled on policy grounds — a 64-bit address space is the widest any target in this domain uses — **not** from the golden census, which bounds what is REACHED, never what is ALLOWED | **RULED (autonomous, flagged inline)**. `REPORT_ADDRESS_CHARS = 49` follows as its consequence; TC-550 executes the equality and the anti-bottom-up arm |
| **i** | **LLR-106.3's derivation has an undefined term.** *"len(cue at the maximum elided count)"* never says what the maximum elided count IS. Left undefined, `REPORT_ADDRESS_CHARS` is not reproducible — the same class of defect as §5.1's CAP-ONLY figure at Inc-1 | Defined in code as `REPORT_ADDRESS_MAX_ELIDED_DIGITS = READ_SIZE_CAP_BYTES − REPORT_ADDRESS_HEX_DIGITS`, i.e. **derived from the wire ceiling**. Costs a new `services → changes.io` import. **Owed to Inc-3's requirement write-up** |
| **j** | **Checklist notices are PER CHECK FILE**, stating that file's own dropped count and own kept total. LLR-105.2 mandates a per-file line but never says whose numbers it carries | **RULED (autonomous, flagged inline)**: a variant-wide count repeated under three headings reads as three separate drops. Per-file counts are locally verifiable and sum to the variant's drop. **Owed to Inc-3** |
| **k** | **LLR-105.7's `CUE_ALPHABET` covers `_format_bytes` only**, and widening it to carry the Address cue's `h/x/d/i/g` would **weaken** `test_f17`'s byte-cell alphabet — a batch-62 escaping guard — for characters that can never appear in a byte cell | Separate `REPORT_ADDRESS_TRUNCATION_CUE_FMT`, with TC-551 asserting inertness against the **real `MD_ESCAPE`** rather than a hand-copied whitelist. Stronger than a whitelist: it cannot drift from the escaper it protects |
| **l** | **LLR-105.6's file-wide bare-literal ban degrades on a two-digit constant.** Measured: banning `REPORT_ADDRESS_HEX_DIGITS` across the test file flags **26** occurrences, every one an address stride, an `int(x, 16)` base or a byte offset — a coincidence detector, not a policy-coupling detector. ⚠ **This packet first said 14. That number was measured on the Inc-1 file BEFORE the Inc-2 block was appended, then quoted as current — this batch's own C-39 rule (*a carried number is re-derived, not copied*) broken on my own figure, caught by the independent reviewer (F5), re-executed at 26** | `TC-544` extended **producer-side only** (now also covering `_format_address`); the file-wide ban stays on LLR-105.6's own subject. The property is enforced for the Address axis by construction instead — AT-246 and TC-550 quote the **derivation**, never a value. **Recorded so it is not read as a silent exemption** |
| **m** | **Self-caught gap:** a check file arriving **saturated with zero kept rows** is reachable under a filter (the zero-match early return only fires when the WHOLE variant keeps nothing) and had no test arm | **Closed by `TC-547b`.** Recorded honestly: I caught it and deferred the fix to avoid editing the tree under the running review — **the reviewer found it independently (F3) and, unlike me, executed it.** Noticing a hole and executing it are not the same act, and only the second one produced the failure message the arm now carries |
| **n** | **`REPORT_ADDRESS_CHARS` has zero production consumers** (reviewer F6) — grep finds it only in its own definition and in TC-550's self-equality | **Kept deliberately, and said so here so a later reader does not "clean it up".** `LLR-106.3` mandates the constant, and `AT-246` quotes the *derivation* rather than the constant on purpose (re-gate F-2: quoting the value would go RED after a correct implementation). It is a **declared bound**, not a computation input |
| **o** | **`LLR-106.3`'s derivation mixes units** (reviewer, ruling-5 caveat) — a *digit* count subtracted from a *byte* count | Sound as an **upper bound** (one hex digit occupies ≥ 1 byte of file text) and the looseness is free downstream, since the consumer needs only the cue's decimal-field *width*, flat across `[1e8, 1e9)`. **Named in the constant's docstring** rather than left to be re-derived. Also owed to Inc-3 |

## 5. Risks

- **`REPORT_ADDRESS_HEX_DIGITS` has no in-domain exercise.** Every real address is 8 digits; the bound
  only ever fires on wire-forged values. Its correctness rests on the executed golden census and on
  AT-247, not on production traffic.
- **The `services → changes.io` import is new.** It is the price of making defect (i)'s derivation
  reproducible; it is a constant-only import with no cycle, but it is a coupling that did not exist.
- The batch-64 golden's zero-drift property remains **exactly** spent (Inc-1 defect b), unchanged here.

## 6. Pending

**Inc-3** — `REQUIREMENTS.md` (R-TUI-101 + its non-claims; the R-TUI-097 stale-line-number removal;
R-TUI-098's `988 B/entry` correction) and `.dev-flow/BACKLOG-CODE.md` (**the batch-75 split with every
measurement from §6 — if this is skipped the split silently becomes a deletion**). Carries the wording
carve-outs owed from Inc-1 (defects d, e) and from this increment (defects i, j, l).

Then **Phases 4-6**. Phase 4's gate suite is orchestrator-run, never delegated (C-25).

## 7. Suggested next task

**Inc-3.** It is the increment that makes the operator's re-scope safe rather than lossy.
