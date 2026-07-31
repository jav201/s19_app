# batch-74 — Requirements (Phase 1)

**Requirement id:** `R-TUI-101` · **Base:** `origin/main` = `d81cb3d` · **Lane A** · 2026-07-31

> **BLUF.** Three defects, three axes, **three separate mechanisms** — and that is the batch's central
> finding, executed rather than argued. The cardinality cap bounds the **entry count `E`**, the width
> bound bounds the **byte-run length `L`**, and a per-row `_ByteBudget` **gate** bounds the **variant
> count `V`**. **No two of them substitute for each other**: a cap-only fix leaves the width ratio at
> **1.9476** (vs shipped 1.9433) and a width-only fix leaves the cardinality ratio at **2.00**. The
> inherited plan proposed one mechanism; one mechanism closes at most one axis.

---

## 1. Scope

**In:** `s19_app/tui/services/report_service.py` — `_modifications_lines` (`:1031`) and
`_checklist_lines` (`:1203`) — plus the report worker's error routing in `s19_app/tui/app.py`
(`_start_generate_report_worker`, `:4069`).

**Out, explicitly:** D-11 host-path redaction · `diff_report_service` · `_applied_regions` (`:1288`,
a *third* unbounded producer, newly measured — see §7) · `options.declared_regions` cardinality ·
batch-73's `changes/apply.py`.

**Engine-frozen, untouched:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
`tui/mac.py`, `tui/color_policy.py`, and the frozen test files.

---

## 2. User stories

**US-B74-1 (OB-4) — resident memory.** *As the operator generating a report from a change file I did
not author, I need the row producers to bound their own resident allocation, so a wire-legal file
cannot exhaust process memory* **before any output exists** *and take the TUI down.*
Threat quantities, executed: `MF_ENTRY_COUNT_CEILING = 100_000` (`changes/io.py:226`) entries/file ×
`MF_RUN_LENGTH_CEILING = 1_048_576` (`:232`) bytes/run.

**US-B74-2 (F4) — emitted bytes.** *As the operator, I need the written report to honour the byte
budget it declares, so generating one cannot fill my disk or produce a document no editor will open.*

**US-B74-3 (D2) — a legal address must not deny the report, and a refusal must not blame me.** *As the
operator, when my change file carries a wire-legal address the report cannot render, I need it
rendered in a form that cannot be mistaken for a different number — and if generation does fail, the
message must say the tool failed, not that my input was rejected.*

### 2.6 Refinement (Definition of Ready)

| Story | INVEST | Status |
|---|---|---|
| US-B74-1 | Valuable ✅ · Testable ✅ (Layer A narrow-window oracle, §6.2) · Small ✅ | **READY** |
| US-B74-2 | Valuable ✅ · Testable ✅ (emitted file size) · Independent ⚠️ — depends on US-B74-1's bounded producer existing first | **READY**, sequenced after Inc-1/2 |
| US-B74-3 | Valuable ✅ · Testable ✅ · Small ✅ | **READY** |

### 2.7 Premise evaluation (C-43)

Phase-0 recorded 17 premises (16 TRUE / 1 FALSE). **Phase 1's cross-derivation falsified three
Phase-0 results that were recorded as TRUE.** They are corrected here rather than quietly amended —
a premise table that cannot record its own author's errors is decoration.

| # | Premise | Phase-0 | **Phase-1 verdict** | Executed evidence |
|---|---|---|---|---|
| P-14 | OB-4 costs a flat `988 B/entry` | ❌ FALSE | ❌ **FALSE** (stands) | `≈ 92 + 6·L` B/entry; 988 is the value at `L≈149` |
| **P-6** | "Charging these tables to `_ByteBudget` closes F4 and leaves OB-4 intact" | ✅ TRUE | ❌ **FALSE on its first conjunct** | `emit()` (`:2215-2217`) calls `consume` only; the sole `fits()` gate is `_hexdump_section:1455`. **Accounting closes NOTHING.** Charging closes *neither* axis; only "OB-4 untouched" holds. The plan built its whole framing on this and it is half wrong **in the direction that matters for D-4** |
| **P-18** | A cap < 415 re-baselines `batch64/addendum-below-bound.md` | (Phase-0 §4) | ❌ **FALSE** | The golden holds **6 documents**; 415 is the **file-wide** sum. The cap is **per variant**. Per-`(document, variant)` counts: `1, 5, 5, 66, 66, 66, 200, 3, 3` → **max = 200**. A cap of 200 with a `>` comparison **fires nowhere → 0 goldens drift.** D-2's dilemma dissolves |
| **P-19** | Reusing `md_safe(limit=REPORT_CELL_CHARS)` on the byte cells drifts nothing | (Phase-0 D-3 candidate) | ❌ **FALSE, twice over** | (i) `md_safe("-")` → `'\-'` (`-` ∈ `_LEADING_BLOCK_CHARS`); bare-`-` byte cells exist in **3 of 3** goldens → drifts **3/3**. (ii) `md_safe` is a **sink** bound (`str(value)[: limit*8]`) — it runs *after* `_format_bytes` has materialised the ~6 MiB string, so it cannot close axis (b) at all |
| **P-20** | "A schema-legal huge **address** denies the report" (the backlog's framing) | implied by P-7/P-8 | ❌ **FALSE** | `entry(10**4300, 10**4300+4)` → report **written**; the Address column is `:08X` and hex never raises. **The boundary is the decimal digit count of `Length`**, not of the address. An AT phrased on the address would pass on the pre-fix tree |
| P-15 | batch-65's shape transfers | ⚠️ with adaptation | ⚠️ **CONFIRMED, and one mechanism is now REJECTED** | The `ops_counter` seam is **vacuous here**: traversal must continue past saturation (to count drops), so consumption is `N` pre- **and** post-fix. Its declared subject (residency) is absent from its expression |
| **P-21** | Axis (b) concerns the byte cells | (Phase-0 D-1) | ⚠️ **TRUE BUT UNDER-SCOPED** | `f"0x{addr:08X}"` — `:08X` is a **minimum** width. A schema-legal address renders a **3574-char** Address cell. **Four** unbounded cells per Modifications row, **five** per Checklist row |
| **P-22** | The two axes are separable | new | ✅ **TRUE, executed** | Cap-only fix → width ratio **1.9476** (shipped 1.9433). Width-only fix → cardinality ratio **2.00**. **Mutually invariant** |
| **P-23** | A whole-report residency AT is authorable | new | ❌ **FALSE — unsatisfiable** | `_applied_regions` (`:1288`) is a **third** unbounded producer, out of scope: peak `16,128 → 160,992` at `N=2000→4000`. An `AT-194`-shaped whole-report memory gate would stay **RED after a correct fix**. OB-4's residency is gated at **Layer A**; Layer B observes emitted bytes |
| P-16/P-17 | Not frozen · no test names either function | ✅ | ✅ **stand** | re-confirmed |

---

## 3. High-level requirements + acceptance

### HLR-105 ← US-B74-1
> `_modifications_lines` and `_checklist_lines` **shall** bound their own resident allocation on **two**
> axes — admitted row cardinality and rendered row width — independently of the per-variant entry
> count `E` and the per-entry byte-run length `L`; **shall** materialise no intermediate full-population
> list; **shall not** terminate traversal on saturation; and **shall** disclose every bound that fires
> inside the document.

### HLR-106 ← US-B74-2
> The two bounded producers **shall** gate row admission on the shared `_ByteBudget`, so the written
> document is bounded by `REPORT_MAX_TOTAL_BYTES` plus a per-variant structural overshoot that is
> stated explicitly; and a variant **shall never** vanish because an earlier variant was expensive.

### HLR-107 ← US-B74-3
> The `Length` column **shall** render every value in the entry domain without raising, in a form that
> cannot be read as a decimal numeral when it is not one; and a failure originating inside report
> composition **shall** be reported as a tool failure, preserving the fail-closed no-partial-file
> guarantee.

### Acceptance blocks (Layer B — black-box through `generate_project_report`)

All ATs drive the shipped surface and observe the **written report file**. Every one carries its
reddening mutation, to be **executed** on a copy of the fixed tree (C-40).

| AT | Story | Observable outcome (shipped surface) | Reddening mutation |
|---|---|---|---|
| **AT-220** | 1 | `E = CAP+1` in one variant → exactly `CAP` `^\| 0x` rows in that variant's `### Modifications` scope + exactly 1 notice | `>` → `>=`; or raise `CAP` above `E` |
| **AT-221** | 1 | Same, `### Checklists`, **disjoint** `check_results[].entries` fixture (P-12) | same |
| **AT-222** | 1 | An entry with a `4·WIDTH` run → widest `Before`/`After` cell ≤ `REPORT_CELL_CHARS`, **and** the cue states the true dropped byte count | Remove `max_bytes` → cell returns to `3·run−1` (executed: **1537** chars at run=512) |
| **AT-223** | 1 | Same for `Expected`/`Actual` | same |
| **AT-224** | 1 | **Disclosure integrity, mods:** at `E = CAP+137` the notice states dropped `= 137` | `break` on saturation → 137 is a number only a full traversal knows. **The only predicate that catches cap-and-break** |
| **AT-225** | 1 | Same, checklist, summed across ≥2 check files | same |
| **AT-226** | 2 | Emitted bytes flat past the cap: `|Δ size|` between `E=2·CAP+10` and `E=2·CAP+1010` ≤ 32 B | Remove the cap arm → Δ ≈ 92 kB |
| **AT-227** | 2 | Under a shrunken `REPORT_MAX_TOTAL_BYTES` with `V` variants, written size ≤ limit + `V×O(5 lines)` | Revert the gate to bare `consume` → unbounded in `V` |
| **AT-228** | 2 | Under a **saturated** budget **every** variant still has exactly one `## Variant:` heading and one notice | Move the structural lines inside the gate → a variant vanishes |
| **AT-229** | 3 | Fixture width derived from `sys.get_int_max_str_digits()` (**never** 3572) → the report **is written** and the row is present. **RED today** | Restore `f"{end-start}"` → `ValueError`, no file |
| **AT-230** | 3 | Same at the **checklist** site, change-free fixture (P-12). **RED today** | same |
| **AT-231** | 3 | Every emitted `Length` token matches `^-?0x[0-9A-F]+$` **or** `^-?[0-9]+$`; a negative length renders `-0x…` and the forged `0x-…` never appears | `f"0x{n:X}"` → emits `0x-1000`, rejected by the predicate |
| **AT-232** | 3 | **Positive control** — an under-cap, in-domain, sub-width report is **byte-identical** to today (golden captured from the **shipped** producer *before* Inc-1, per C-12) | Set `CAP=1` → bytes differ |
| **AT-233** | 3 | **Attribution:** an out-of-domain `context_bytes` still says `Report rejected:`; an internal composition `ValueError` says `Report failed:` | Widen the `try` back → both say "rejected" |
| **AT-234** | 3 | **Fail-closed:** on any composition raise, `reports/` contains no new file | Move `write_bytes` before composition |

---

## 4. Low-level requirements

| LLR | Statement | Touched symbol (C-26) |
|---|---|---|
| **LLR-105.1** | `_modifications_lines` **shall** admit at most `MAX_REPORT_ROWS_PER_VARIANT` rows per variant, counted **at admission**, and **shall** build no intermediate full-population list — the `entries` flattening (`:1071-1075`) and the `kept` filter (`:1080-1082`) **shall** be fused into the single admission pass. | `_modifications_lines` |
| **LLR-105.2** | `_checklist_lines` **shall** admit at most `MAX_REPORT_ROWS_PER_VARIANT` rows **summed across all of the variant's check files**, not per check-file table. A per-table cap is not a bound: the check-file count has no cap anywhere, so `N_files × C` is unbounded. | `_checklist_lines` |
| **LLR-105.3** | Every unbounded-width cell — `Address`, `Length`, `Before`/`After`, `Expected`/`Actual` — **shall** render at most `REPORT_CELL_CHARS` characters. Byte-run cells **shall** be bounded **at the source**, by the count of byte values consumed (`REPORT_BYTES_PER_CELL`), **never** by slicing an already-rendered string — the rendered string *is* the allocation being bounded. | `_format_bytes` (**signature**) |
| **LLR-105.4** | Traversal **shall not** terminate on saturation: the producer **shall** stop formatting and appending but **shall** keep counting, so the notice states the true dropped count. | both producers |
| **LLR-105.5** | Every bound that fires **shall** emit one in-document `> TRUNCATED:` notice naming the section, the cap value, the dropped count and the total; every width bound that fires **shall** emit an in-cell cue naming how many byte values were not rendered. A silently shortened byte run in an evidentiary document is a **correctness** defect, not a cosmetic one. | new format constants |
| **LLR-105.6** | The bounds **shall** be module-level named constants; no bare literal of any cap value **shall** appear in either producer body. | new constants |
| **LLR-106.1** | Both producers **shall** take the live `_ByteBudget` as a **required, keyword-only** parameter (mirroring `_hexdump_section(result, options, budget)`, `:1369`) and **shall** admit a row only while `budget.fits(...)`, charging each admitted row with `consume`. An optional-with-`None` budget is **prohibited** — a silent bypass of the control. | both producers (**signature**) |
| **LLR-106.2** | `generate_project_report` **shall** consume their output with a bare `lines.extend`, **not** `emit`, so no batch is charged twice. | `generate_project_report` (`:2243`, `:2245`) |
| **LLR-106.3** | Each section's **structural** lines — heading, table header/rule, zero-population line, truncation notice — **shall** be emitted **outside** the gate and charged, so a variant is never silently absent. The permitted overshoot is `O(V × ~5 lines)` and **shall** be stated as a non-claim. | both producers |
| **LLR-106.4** | With no cap and no gate firing, both producers **shall** be **byte-identical** to the shipped output. | both producers |
| **LLR-107.1** | Both `Length` sites (`:1104`, `:1279`) **shall** route through one shared `_format_length(length: int) -> str`. Two independent formatters over disjoint inputs is how one site gets fixed and the other does not. | new `_format_length` |
| **LLR-107.2** | `_format_length` **shall** return the decimal form whenever CPython can produce it (EAFP: `try: return str(length)` / `except ValueError:`), otherwise `f"{sign}0x{abs(length):X}"`. The alternative form **shall** match `^-?0x[0-9A-F]+$`. `f"0x{length:X}"` on a negative value is **prohibited** — it renders `0x-1000`, which the predicate rejects, while the correct `-0x1000` passes. | new `_format_length` |
| **LLR-107.3** | `_format_length` **shall not** change the rendering of any in-domain length. `MF_RUN_LENGTH_CEILING` bounds an in-domain length at 7 decimal digits — the alternative form is unreachable in-domain by ~4293 digits. | — |
| **LLR-107.4** | `_start_generate_report_worker` (`app.py:4069`) **shall** narrow its `except ValueError` rejection arm (`:4158` → `:4164`) to the **`ReportOptions` construction** (`:4145`) only. A `ValueError` from `execute_project_variants` (`:4133`) or `generate_project_report` (`:4155`) **shall** route to the failure arm (`:4166` → `:4178`). Fail-closed **shall** be asserted, not assumed: the write happens at `:2261` after all composition. | `_start_generate_report_worker` |

---

## 5. Decisions (option tables)

### D-2 — cardinality cap value → **RULED: 200**

Decided by the corrected census (P-18): max single `(document, variant)` Modifications table = **200**.

| Option | Expected result | Consequences |
|---|---|---|
| ✅ **200** — mirror `MAX_REPORT_ISSUES_PER_VARIANT` (`:96`) / `MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION` (`:111`) | Cap never fires on any golden → **0 re-baselined**, matching batch-65's cited property. One number governs all caps in the module | ⚠️ Boundary-exact: the golden's largest table **equals** the cap. **This is a feature — it makes that golden an off-by-one sentinel that goes RED on `>=` for `>`** — but it must be *declared* as such, or a later reader reads the zero-drift as slack |
| ⚠️ 500 | Also 0 goldens; more evidence retained | ❌ A third cap number, against the module's twice-stated one-number policy (`:93-95`, `:107-110`) |
| ❌ 415 | 0 goldens | ❌ **An artifact of my own miscount** — encoding it would put a constant in the tree whose recorded justification is false |
| ❌ 128 | Tightest | ❌ Drifts `batch64/addendum-below-bound.md` (200 > 128) |

**On the semantic objection** — *is 200 defensible for an evidentiary record when it was chosen for
diagnostics?* The asymmetry is real (losing a Modifications row loses the only in-report statement
that address *X* was written with bytes *B*), and it argues for a different **disclosure**, not a
different number: the change/check file is retained and `ChangeSummary.to_dict` serialises every
entry. **The honest qualifier, which must be stated:** unlike the addendum, the Modifications table
has **no second sink inside the report**, so eviction *is* evidence loss within the document.
**The price is paid in the notice, not in the number.**

### D-3 — per-row width bound → **RULED: source-bound, constant reused, mechanism rejected**

My Phase-0 candidate is **rejected on executed evidence** (P-19).

| Option | Consequences |
|---|---|
| ❌ Route byte cells through `md_safe(REPORT_CELL_CHARS)` | Drifts **3/3** goldens (`-` → `\-`); bounds the **sink**, leaving axis (b) open; breaks `test_f17`'s reason-for-existing |
| ✅ **Reuse the CONSTANT, reject the MECHANISM** — `REPORT_BYTES_PER_CELL = (REPORT_CELL_CHARS + 1) // 3` = **171**, with `_format_bytes(values, *, max_bytes)` stopping **consumption of the iterable** | Bounds resident **and** emitted in one place. A **derived** constant, not a new policy number. `3n−1 ≤ 512 ⟺ n ≤ 171`. Zero golden drift. Finally makes `REPORT_CELL_CHARS`'s docstring claim true for the cells it currently excludes |
| ⚠️ New dedicated constant (e.g. 64) | A fourth unmoored number; low enough to truncate a plausible 128-byte calibration array — a bound becoming routine data loss |

**Cue form:** `01 AB … (+837 more bytes)`. **Must not** reuse `markdown_safety.TRUNCATION_MARKER`
(batch-62 M-3 pinned the two markers distinct); **must not** contain `|`; **must** state a **count** —
in an evidentiary document the reader needs to know the run was 1008 bytes, not that it was "long".
Verified inert: `…`, `(`, `)`, `+`, digits are outside `MD_ESCAPE` and outside `_LEADING_BLOCK_CHARS`
in non-leading position.

### D-4 — what exactly closes F4 → **RULED: per-row gate on `_ByteBudget`, continue-not-break**

Worst-case per-variant emitted bytes **after** the D-2/D-3 bounds ≈ **1.6 MB** against a **2 MiB**
budget, and **`V` has no cap anywhere**. At `V=10` the document is ~16 MB — **8× the declared budget**.

| Option | Consequences |
|---|---|
| ❌ Producer bound only | Closes the chartered `E`-axis (208 MB → 634 kB) but the document stays `O(V)`. Would force R-TUI-101 to claim F4 closed while the budget is exceeded 8× — over-claiming |
| ❌ Gate `emit()` at section granularity | **Does not close OB-4** — the producer is fully evaluated before the gate sees it (P-6). Strictly worse |
| ✅ **Per-row gate inside the producer** | Both axes by one mechanism: a row failing `fits` is never formatted, appended or emitted. Partial evidence preserved. **Two in-repo precedents:** `_hexdump_section:1451-1458` gates per block on this same budget; `flow_fused_report_service:301-367` gates per section on the shared `_ByteBudget` |
| ❌ Cap the variant count | Drops whole variants from an evidentiary document — the worst available loss, and out of charter |

⚠️ **Disclosed consequences of the ruling:** output becomes **position-dependent** (an early expensive
variant reduces a later one's rows), and a truncated table leaves *more* budget for hexdumps, so
hexdump output can change **in already-saturated documents only**. Both stated in §7.

### D-5 — D2's fix shape → **RULED: EAFP**

| Option | Consequences |
|---|---|
| ✅ **EAFP** `try: return str(length)` / `except ValueError:` hex form | **The predicate *is* the operation**, so it can never disagree with CPython's rule. Self-adjusting under `-X int_max_str_digits=1000` and under a disabled limit. No new constant. Zero in-domain change |
| ⚠️ `bit_length`-derived predicate | ❌ ~10% **over-trigger band** (executed: 4763 vs true ≈4302) — the code's rule would not be CPython's rule |
| ❌ `sys.set_int_max_str_digits()` around the call | ❌ Process-global state mutated from a **worker thread** — a cross-call race dressed as a fix; and it renders a 1 MB decimal cell |

**Binding constraint on the acceptance, not the code:** the AT **shall** derive its fixture width from
`sys.get_int_max_str_digits()` and **shall not** hard-code 3572. `TC-531` enforces this by re-running
the boundary under `sys.set_int_max_str_digits(640)` (the floor — `sys.int_info.str_digits_check_threshold`
= 640), restoring in `finally` because the setting is process-global.

---

## 6. Validation strategy

### 6.1 Layer A (white-box) — TC-521…TC-536
Cap arms at `{CAP−1, CAP, CAP+1}` (TC-521/522) · non-termination via dropped-count at `CAP+137`
(TC-523/524) · **the anti-intermediate gate** (TC-525/526) · width formatter in/out of cap (TC-527/528)
· `_format_length` over a **derived** value set (TC-529) · sign placement with the four counterexamples
(TC-530) · **the derivation gate under a moved limit** (TC-531) · error-arm routing (TC-532) ·
no-partial-file (TC-533) · **constant-quoting gate** — no bare `200`/`171`/`3572` literal in any new
test (TC-534) · filter interaction: the cap applies to **kept** rows and the zero-match notice still
wins when kept == 0 (TC-535) · **TC-536, labelled a PIN not a gate** — `batch64/addendum-below-bound.md`
stays byte-identical.

### 6.2 The memory oracle — **narrow-window `tracemalloc`, threshold 1.05**

| Mechanism | Deterministic | Sees the intermediates | Can go RED | Verdict |
|---|---|---|---|---|
| **`tracemalloc`, narrow window around the producer, fixture built outside** | ✅ spread **0**/5 trials | ✅ (the 17 kB delta *is* the `entries` list) | ✅ 2.0008 → 1.0000 | ✅ **ADOPT** |
| `sys.getsizeof` of the returned list | ✅ | ❌ **blind to `entries`/`kept`** | ✅ | ⚠️ secondary only — **a cap-only fix passes it** |
| Whole-report `tracemalloc` (AT-194 shape) | ⚠️ | diluted | ❌ **cannot go GREEN** (P-23) | ❌ **REJECT — unsatisfiable** |
| batch-65's `ops_counter` seam | ✅ | n/a | ❌ **invariant** — traversal must continue, so consumption is `N` either way | ❌ **REJECT as vacuous here** |
| Peak RSS / wall-clock | ❌ | — | — | ❌ **REJECT — flaky**; batch-64 measured cap-and-break vs cap-and-continue indistinguishable (19019/19019) |

**Threshold 1.05, justified by execution, not taste:** FUSED **1.0000** · CAP-ONLY **1.1971** ·
SHIPPED **2.0008** → 5% headroom above correct, 14% margin below the nearest defective. The fixture
precondition `N_low ≥ 2·CAP` **shall** be asserted in the test body, or the ratio measures fixture luck.
**Re-measure on the CI runner (ubuntu / py3.11) before the gate is claimed (C-39).**

### 6.3 Rejected-as-vacuous register (the valuable half of C-40)

`raw == document_bytes(raw.decode())` (batch-63's identity — do not reproduce) · consumption counters
as the OB-4 gate (invariant) · whole-report residency (unsatisfiable, P-23) · *"a huge **address**
denies the report"* (**factually false**, P-20 — would have passed pre-fix) · `Length.startswith("0x")`
(accepts `0x-1000`, rejects `-0x1000`) · `Length.isdigit()` (a bare-hex forgery satisfies it) ·
hard-coded 3572 (passes at 4300, untested elsewhere) · **one AT covering both axes** (executed
refutation: each fix leaves the other ratio untouched) · **one AT covering both sites** (disjoint
inputs).

### 6.4 Test placement — none frozen
`tests/test_report_producer_bound.py` (**new**) for AT-220…AT-232 + TC-521…TC-531, TC-534, TC-535 ·
`tests/test_tui_report_seam.py` (existing) for AT-233/234 + TC-532/533 · `tests/goldens/batch74/` for
AT-232's golden · TC-536 stays in `tests/test_report_addendum_bound.py:793` — **batch-64's file, do
not touch**. Verified against the frozen test set (`test_tui_directionb.py:5495-5503`): none is frozen.

### 6.5 Counterfactual protocol
Mutate a copy of the **FIXED** tree in a `git worktree add --detach` **export under the session
scratchpad** — never `main` (an `ImportError` RED proves nothing) and never this worktree (batch-62
cost a review four spurious failures). One mutation per run; record the **exact assertion text** that
fired, plus confirmation the mutation applied; restore and verify by **file hash**.

---

## 7. Residual discharge (mandatory — this batch closes OB-4/F4/D2 and no more)

**CLOSED:** R-TUI-098 non-claim (a) — *and its stated figure is corrected*: not 988 B/entry but
`≈ 92 + 6·L`. R-TUI-097's "scope carried, not closed" paragraph (its stale `031ca8d` line numbers to
be **removed**, not updated).

**NOT CLOSED — stated as R-TUI-101 non-claims:**

| Residual | Why our change does not close it |
|---|---|
| `options.declared_regions` has **no cardinality cap** (`≈11.6 kB/region`) | `_addendum_lines` untouched; `R` is a different axis |
| The relocated `O(R)` attribution walk | Same |
| Intra-class eviction **disclosed, not prevented** | Our caps inherit the same first-`K` shape — **and it worsens in one direction we must state:** the Modifications table has no second sink in the report |
| Traversal below one pass | LLR-105.4 deliberately keeps the full `V×E` pass |
| **`_applied_regions` (`:1288`) is a THIRD unbounded producer** — newly measured, peak `16,128 → 160,992` at `N=2000→4000` | **Out of scope. This is why no whole-report memory claim is made** (P-23) |
| Truncation notices not reaching `## Truncation appendix` — **our two new emitters make it 3 → 5** | Following `_declaration_error_lines`'s inline-only convention; unification stays carried. Stated so the residual does not silently grow |
| **NEW, created by our own fix:** the document is `REPORT_MAX_TOTAL_BYTES + O(V × ~5 lines)`, not `≤` | LLR-106.3 deliberately emits structural lines outside the gate so no variant vanishes |
| **NEW:** above the cap the report is not a **complete** record of a variant's modifications | The consequence of D-2; the notice says so |
| **NEW:** output is **position-dependent** under a saturated budget; hexdump output can change in already-saturated documents | The consequence of D-4 |
| `diff_report_service` · D-11 · batch-73's `apply.py` | Fenced out |

---

## 8. Increment cut (C-21: re-cut against the final LLR set)

| Inc | Files (≤5) | Content |
|---|---|---|
| **1** | `report_service.py`, `tests/test_report_producer_bound.py` (new), `tests/test_report_field_census.py` | Constants; `_format_bytes(values, *, max_bytes)`; `_modifications_lines` rewritten single-pass (fuse `entries`+`kept`). **Third file is forced:** `test_f17` (`:927`, `_format_bytes(range(256))`) goes RED at a 171-byte cap. AT-220/222/224 |
| **2** | `report_service.py`, `tests/test_report_producer_bound.py` | `_checklist_lines`, cap spanning all check files. **Not merged with Inc-1** — different shape, disjoint input. AT-221/223/225 |
| **3** | `report_service.py`, `tests/test_report_producer_bound.py` | The F4 gate: budget as required kwarg, `emit`→`extend`, structural lines outside. AT-226/227/228 |
| **4** | `report_service.py`, `tests/test_report_producer_bound.py`, `tests/goldens/batch74/` | `_format_length` + both sites + the positive-control golden. AT-229/230/231/232 |
| **5** | `app.py`, `tests/test_tui_report_seam.py` | Attribution + fail-closed. AT-233/234 |
| **6** | `REQUIREMENTS.md` | R-TUI-101 + non-claims + the R-TUI-097/098 amendments |

**Pre-flight before Inc-1** (not an increment): re-run the per-`(document,variant)` golden census and
capture AT-232's golden from the **shipped** producer *before* any edit (C-12 — otherwise it certifies
the rewrite against itself).
