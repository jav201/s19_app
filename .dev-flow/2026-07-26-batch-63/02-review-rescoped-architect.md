# batch-63 (RE-SCOPED) — Phase-2 review, architecture lens

**Reviewer:** independent architect lane (did not author the requirements).
**Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`, worktree
`…/.claude/worktrees/backlog-review-6b06f7`. **Artifact language:** English.
**Under review:** `01-requirements-rescoped-architect.md` (primary) · `01b-qa-catalog-rescoped.md`
(as the co-delivered Phase-1 half) · against `01-requirements-rescoped.md` (operator scope ruling)
and `00b-measurements-rescoped.md` (C-39 transcript).
**Probe discipline:** every counterfactual executed in-process at the short root
`C:/Users/jjgh8/AppData/Local/Temp/claude/b63/r1`, deleted at close. No fixture exceeded 8 000
synthetic hits (~19 KB peak). `/b63/{a,b,qa,arch,archb,r2,r3}` untouched. **Zero production source
edits; zero edits to the Phase-1 artifacts.**

---

## 1. BLUF — **BLOCKED**

**4 blockers · 3 majors · 5 minors.**

The three defects are real, the measurements hold up, and the D2 fix-shape elimination survives
independent execution. But the **normative layer does not express the design the measurements
selected**, and in two places it asserts properties the design cannot deliver.

**The single most consequential finding (B-1):** `LLR-102.2` / `AT-174` — the `>=` upper-bound form
— is **satisfied by the very design `00b` M-6 and the qa lane refuted by measurement**. Executed on
6 line-sequence cases including N = 0: `_line_bytes(l) >= len(encoder(l))` is **green on all 6 under
`_line_bytes := len(encoder(...))`**. No LLR in the artifact states partition-invariance, so Phase 3
can implement the refuted design, satisfy every LLR and every AT, and ship an allocator whose
undercount **grows with the variant count** (executed: 11 B at 12 batches, 99 B at 100 batches).
The orchestrator's own M-7 ruling re-keyed `AT-174` to `== len(report_bytes(l)) + 1` *specifically*
because `>=` cannot pin the `+1`; the artifact rebuts M-5's superseded form (§5.3) and never engages
M-7.

Second: **`LLR-100.2` (bounded traversal) is unobservable by the entire D1 acceptance set**, and
`HLR-100`'s traversal claim is false for any region matching fewer entries than the cap — including
the zero-match case, which is the attacker-selectable one.

Third: the two Phase-1 lanes **allocated the same `AT-164..175` and `TC-440..479` ranges
independently**; 9 of 12 AT ids and TC-453..466 carry different content in the two documents.

Answers to the four questions the brief posed are in §5.

---

## 2. Blockers

### B-1 — `LLR-102.2` / `AT-174` admit the design that was measured to be worse than the defect

**What it is.** `HLR-102`, `LLR-102.1`, `LLR-102.2` and `AT-174` are jointly satisfied by
`_line_bytes := len(report_bytes(lines))` — the "shared encoder" reading that `00b` M-6 retracted
(C-3 RETRACTED) and that the qa lane refuted end-to-end (`01b` §5, "11 bytes UNDER the file").

- `LLR-102.1` requires one encoder and forbids the writers doing their own joining — **silent on
  `_line_bytes`.**
- `LLR-102.2` requires `_line_bytes(lines) >= len(<encoder>(lines))` "for every line sequence,
  including the empty sequence" — quantified over **line sequences**, never over **partitions**.
  The refuted design satisfies it with equality everywhere.
- `AT-174` asserts the same `>=` predicate.
- **No LLR anywhere in the artifact states that `_line_bytes` is unchanged, or that the accounting
  must be partition-invariant / batch-composable.** `00b` M-6's terminology ruling is explicit:
  *"The requirement text must say 'one encoder for the WRITERS; `_line_bytes` unchanged'."* The
  artifact does not say it.

**Evidence (executed, `…/b63/r1/p1.py`):**

```
=== Q1: does LLR-102.2 / AT-174  '_line_bytes(l) >= len(encoder(l))'  EXCLUDE the refuted design? ===
case              shipped  refuted    enc  arch_AT174(shipped)  arch_AT174(REFUTED)
N=0                     0        0      0                 True                 True
N=1                     4        3      3                 True                 True
N=1 empty str           1        0      0                 True                 True
N=3 ascii               9        8      8                 True                 True
N=3 non-ascii          13       12     12                 True                 True
N=200                1690     1689   1689                 True                 True
--> architect AT-174 is GREEN under the REFUTED design on ALL cases: True

=== Q1b: orchestrator M-7 ruling form  '_line_bytes(l) == len(encoder(l)) + 1  (N>=1)' ===
  holds for SHIPPED _line_bytes (surviving design): True
  holds for REFUTED _line_bytes                   : False   <-- M-7 form EXCLUDES the refuted design
```

**Why it matters, quantified.** `generate_project_report` accounts in `emit()` batches
(`s19_app/tui/services/report_service.py:1636`, call sites `:1641-1679`) — **7 fixed batches plus
~6 per variant** (`:1660-1672`), not the flat "~12" both `00b` and `01b` state. The refuted
design's undercount equals *(batch count − 1)*, so it is **linear in the variant count** — a
file-fed axis. That is strictly worse than the CRLF bug it replaces, which is bounded by N − 2 and
is zero on Linux:

```
=== Q2: partition-invariance vs the emit() batch COUNT ===
  true on-disk (LF) bytes                 = 2049
     1 batches | sum(shipped)=  2050 | sum(REFUTED)=  2049 | refuted undercount vs disk =     0
     2 batches | sum(shipped)=  2050 | sum(REFUTED)=  2048 | refuted undercount vs disk =     1
    12 batches | sum(shipped)=  2050 | sum(REFUTED)=  2038 | refuted undercount vs disk =    11
    37 batches | sum(shipped)=  2050 | sum(REFUTED)=  2013 | refuted undercount vs disk =    36
   100 batches | sum(shipped)=  2050 | sum(REFUTED)=  1950 | refuted undercount vs disk =    99
```

This is aggravated by `00b`'s own C-26 reverse census: `_line_bytes` has **0 test references**, so
its `+1` convention can be changed today with a fully green suite.

**Concrete fix (Phase 1 iterate):**
1. Add a normative clause to `LLR-102.2` or a new `LLR-102.5`: *"`_line_bytes` **shall** retain its
   per-line `+1` convention and **shall** be partition-invariant:
   `sum(_line_bytes(b) for b in P) == _line_bytes(whole)` for every partition `P` of a line
   sequence. The accounting **shall not** be redefined in terms of the encoder."*
2. Re-key `AT-174` to the M-7 ruling form — `_line_bytes(l) == len(report_bytes(l)) + 1` for
   N ≥ 1, plus `_line_bytes([]) == 0 and report_bytes([]) == b""` — and add a second AT for
   partition-invariance (the qa lane's `AT-174`/`TC-472` already specify it; adopt it rather than
   re-derive it).
3. Delete or rewrite §5.2's heading and body text — *"RULING D3-A — the writer and the accounting
   share ONE encoder"* is the exact phrase `00b` M-6 ruled must never appear, verbatim, twice
   (§5.2 heading and §5.2 body). Marking the paragraph "informative" does not neutralise it for a
   Phase-3 implementer who reads the heading.

---

### B-2 — no AT observes bounded traversal; `LLR-100.2` is unobservable by its own acceptance set

**What it is.** `LLR-100.2` states the traversal bound and ends *"Bounding output alone **shall
not** be treated as satisfying LLR-100.2."* The artifact then claims `AT-166` makes it observable:

> `AT-166` … *bites because:* "A notice that quoted a total would prove traversal was not bounded
> (LLR-100.2). **This is the AT that makes LLR-100.2 non-vacuous from black-box observation alone.**"
> — `01-requirements-rescoped-architect.md:133`

**That inference runs backwards, and it is false by execution.** Absence of a total is not evidence
of a stopped scan. I implemented both designs — `scan_all_store_K` (traverses everything, stores
`CAP`, emits an "at least K" notice: **violates LLR-100.2**) and `bounded` (breaks out: satisfies
it) — and ran the architect's entire D1 AT set against both:

```
impl                    E    peak B  lines   scanned
scan-all/store-K      500     18743    201       500
scan-all/store-K     2000     18711    201      2000
scan-all/store-K     8000     18711    201      8000
                   AT-164 (peak flat when E x4): x1.00, x1.00  -> AT-164 PASSES: True
                   AT-165 (hits <= CAP): True | AT-166 (notice, no total): True

bounded (LLR-100.2)    500     18711    201       399
bounded (LLR-100.2)   2000     18711    201       399
bounded (LLR-100.2)   8000     18711    201       399
                   AT-164 (peak flat when E x4): x1.00, x1.00  -> AT-164 PASSES: True
                   AT-165 (hits <= CAP): True | AT-166 (notice, no total): True

--> BOTH designs pass AT-164/165/166/167. No architect AT observes 'scanned'.
```

`AT-164` keys on **resident peak**, which a store-K design flattens by construction. `AT-165`
keys on the line count, also flattened. `AT-167` keys on the under-cap arm, identical in both. So
**every one of `AT-164/165/166/167` is green under a design that violates `LLR-100.2`.** The
artifact's own §6.4 probe printed `scanned = 201` as the evidence of bounded traversal — that
number lives in a probe transcript and in **no acceptance criterion**.

This is the project's named dominant defect class (the vacuous check) landing on the LLR the
requirement author explicitly hardened against vacuity.

**Concrete fix.** Add an AT that observes traversal directly and can only be satisfied by a break —
e.g. instrument the per-region candidate iterator (a counting wrapper over
`result.change_summaries` / `summary.entries` / `check.issues`) and assert
`visited <= MAX_ADDENDUM_HITS_PER_REGION + <bounded slack>` at E ≫ CAP, with the shipped code as the
RED counterfactual (`visited == R·V·E`). Wall-clock is the alternative but is flaky; the counting
wrapper is deterministic. Note the qa lane's `G-5` already names this gap and declines to close it
("AT-166 keys on *resident* peak … does **not** key on wall time") — the architect lane adopted the
gap without adopting the flag.

---

### B-3 — `HLR-100` asserts a traversal bound the LLRs cannot deliver

**What it is.** `HLR-100` states the cap exists

> "…so that the addendum's resident cost **and its traversal cost** are both **independent of the
> per-variant entry count and of the variant count**."

Read the shipped producer (`s19_app/tui/services/report_service.py:1467-1539`): the per-region loop
appends only when `region.contains(...)` is true (`:1517`, `:1523`, `:1531`). A cap on `len(hits)`
can therefore short-circuit **only after CAP matches have accumulated**. For any region matching
fewer than CAP entries — including the zero-match region — the scan is still O(V×E):

```
=== Q4: HLR-100 claims traversal cost is independent of V and E. Zero-match region: ===
  R=1 V=1 E=   500 -> items traversed =      500  (cap never fires)
  R=1 V=2 E=   500 -> items traversed =     1000  (cap never fires)
  R=1 V=4 E=   500 -> items traversed =     2000  (cap never fires)
  R=1 V=1 E=  2000 -> items traversed =     2000  (cap never fires)
  R=1 V=1 E=  8000 -> items traversed =     8000  (cap never fires)
--> traversal is STILL O(RxVxE) whenever a region matches fewer than CAP entries.
```

The worst case is also the attacker-selectable one: declare R narrow regions that match nothing,
feed V×E entries, and the addendum pays the full product for zero output. Memory stays flat (the
defect the scope ruling actually names), so the *fix* is sound — but the **HLR over-claims**.

**Why it matters beyond pedantry.** This batch's founding thesis, restated in its own scope ruling
(`01-requirements-rescoped.md:104-108`), is that *a document must not assert a bound it does not
honour*. `HLR-100` is that failure inside the batch's own normative text, and `§9 OB-1` obliges the
PR to say the same thing about the truncation marker.

**Concrete fix.** Restrict the clause to what the design delivers:
*"…so that the addendum's **resident** cost is independent of the per-variant entry count and of the
variant count, and its traversal cost is bounded **once a region reaches the cap**."* Then carry the
residual — *"a region matching fewer than `MAX_ADDENDUM_HITS_PER_REGION` entries still traverses
O(V×E) candidates; bounding that requires an address-indexed candidate set and belongs to
batch-64"* — into `§9` as a stated risk and into `.dev-flow/BACKLOG.md` alongside the R-axis carry
(`§5.5`). `range_index.py::build_sorted_range_index` is the existing primitive that would close it;
naming it makes the carry actionable.

---

### B-4 — the two Phase-1 lanes collided on the `AT-164..175` and `TC-440..479` namespaces

**What it is.** Both `01-requirements-rescoped-architect.md` and `01b-qa-catalog-rescoped.md`
allocated inside the same orchestrator-fixed *ranges* independently. **9 of 12 AT ids carry
different content:**

| id | architect (§3.4/§4.4/§5.8, §7) | qa catalog (§3) | same? |
|---|---|---|---|
| AT-164 | peak memory flat in entry count | bounded hit lines per region | **no** |
| AT-165 | hits ≤ cap constant | `≥K` honest count | **no** |
| AT-166 | capped region notice, no total | resident cost stops tracking R×V×E | **no** |
| AT-167 | byte-identical under cap | golden neutrality below cap | yes |
| AT-168 | 3572 → report, not `ValueError` | wide address does not crash | yes |
| AT-169 | 3571 → exact decimal cell | the checklist twin is fixed too | **no** |
| AT-170 | checklist twin | fail-closed, never partial | **no** |
| AT-171 | fail-closed | wide cell honest / narrow unchanged | **no** |
| AT-172 | replacing the encoder changes report bytes | AST census: no text-mode writer | **no (different method)** |
| AT-173 | same, for the flow report | `len(report_bytes) == _line_bytes − 1` | **no** |
| AT-174 | `_line_bytes >= len(encoder)` | **`_line_bytes` is batch-composable** | **no** |
| AT-175 | Windows-only: no `\r` | `st_size == used − 1` **and** no `\r` | partial |

**And the TC ranges disagree on story boundaries.** Architect `§7` assigns D1 = TC-440…452,
D2 = TC-453…465, D3 = TC-466…479. The qa catalog `§4` assigns D1 = TC-440…453, D2 = TC-454…466,
D3 = TC-467…479. **Every id from TC-453 through TC-466 is bound to a different story by the two
documents** — e.g. `TC-453` is D2/`LLR-101.1` in the traceability matrix and a D1 through-the-surface
test in the registry that actually owns the content. The architect's `§7` header states
"**content owned by the qa-reviewer lane**" while assigning ranges the qa lane did not use.

The qa lane's `G-1` anticipated an LLR-binding reconciliation but not an AT/TC collision, because
its header read the range as fixed rather than the assignment (`01b-qa-catalog-rescoped.md:5`).

**Why it matters.** Phase 3 and Phase 4 receive two documents in which "AT-174" names two different
predicates — and one of them (**qa's batch-composability AT**) is the only acceptance in either
document that excludes the refuted D3 design (B-1). Handing this to implementation guarantees either
a silent drop or a wrong binding. This is the same failure mode `01b` `G-1` says it was written to
avoid ("the REV-4 collision").

**Concrete fix.** The orchestrator issues a single merged `AT-164..AT-175` / `TC-440..TC-479`
allocation before Phase 3, and both artifacts are re-emitted against it. Recommended basis: the qa
catalog's assignment (it carries the RED counterfactual per row and the executed pre-fix
transcripts), with the architect's `AT-172` (monkeypatch-the-encoder) **added** rather than
substituted — the two `AT-172` forms are complementary, not duplicative: the census is structural
and the monkeypatch is behavioural, and both are RED pre-fix on CI.

---

## 3. Majors

### MAJ-1 — D2's "observable outcome (black-box)" is stated at a seam the operator never sees

`§4.4` says: *"Today the tool raises `ValueError` and leaves `reports/` empty."* At the shipped
surface it does not. `s19_app/tui/app.py:4031-4041`:

```python
            report_path = generate_project_report(
                project_dir, results, options, variant_set=variant_set
            )
        except ValueError as exc:
            self._log_report_event(
                "project", project_dir.name, "-", f"rejected: {exc}", ok=False
            )
            ...
            self.call_from_thread(self.set_status, f"Report rejected: {exc}")
```

The TUI **catches** it and routes it into the branch reserved for *operator-input rejections*. What
an operator actually observes is a status line reading
`Report rejected: Exceeds the limit (4300 digits) for integer string conversion` and no file —
a CPython internals message presented as a validation verdict on their data. The scope ruling's
"CRASHES report generation" (`01-requirements-rescoped.md:21`) and the artifact's `§4` framing are
both wrong at that surface.

This weakens nothing about the fix — it **strengthens** the case — but the Acceptance block is
supposed to be first-class black-box, and `§4.4`'s "Shipped surface producing it" stops at a
service function. No AT or TC in either lane observes `app.py`. (The qa catalog cites `app.py:4031`
once, in evidence-checklist row 9, as a reachability argument only.)

**Fix.** Restate `§4.4`'s observable at the app surface, and add one AT: *pre-fix the status reads
`Report rejected: Exceeds the limit …` and no file appears; post-fix the report path is returned
and `_finish_generate_report` runs.* Alternatively, scope the Acceptance explicitly to the service
seam and say so — but do not describe a crash the operator does not get.

### MAJ-2 — widening to `flow_report_service.py` is technically justified but was never put to the operator, and its decisive claim is unquantified

**The factual base checks out.** Verified independently:
- `s19_app/tui/services/flow_report_service.py:69-74` — `from .report_service import (…, _ByteBudget, _line_bytes, _report_filename)`. Shared primitive, confirmed.
- `:308-315` — `put()` calls `budget.fits(_line_bytes(batch))` and, on failure, appends to
  `truncated_sections` and returns `False` **without appending the batch**. It gates *emission*, confirmed.
- `:456` — `target.write_text(compose_flow_report(...), encoding="utf-8")`. Text mode, confirmed.
- `report_service`'s only `fits()` is `:1347`, inside `_hexdump_section`. The asymmetry claim is
  confirmed.
- Neither module is in either `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120`,
  `tests/test_tui_directionb.py:5443`). Confirmed.

**So: load-bearing, not scope creep with a good story.** `LLR-102.1`'s "one encoder" would be
self-contradicting if a caller of that encoder's own budget bypassed it — reason #1 alone carries
the inclusion.

**Two defects remain.**

1. **Reason #2 is asserted without a magnitude, in a batch whose rule is "quantify, don't
   hand-wave."** `FLOW_REPORT_MAX_TOTAL_BYTES = REPORT_MAX_TOTAL_BYTES = 2_097_152`
   (`flow_report_service.py:80`, `report_service.py:122`). The undercount is N − 2 on Windows and
   **0 on Linux**. So "an undercounting allocator there decides *emission*" is true only for a
   document within ~N bytes of 2 MB, on Windows. The artifact never states that. Reason #2 as
   written reads as a large correctness delta; measured, it is a narrow one.
2. **The operator was not asked.** `01-requirements-rescoped.md` names only
   `report_service.py:394` / `:1682` for D3. `00b` C-4 is the orchestrator's finding, not the
   operator's ruling, and the artifact's own precedence table (`§`preamble) places a *measurement
   transcript* **above** the operator scope ruling — measurements are authoritative for numbers,
   not for scope. The project's standing rule is that autonomy is never carried across a batch.
   `R-4` records the batch-62 restoration cost honestly but resolves the question itself.

**Fix.** Add `Q-3` to `§9` as an **operator decision point**, carrying the verified evidence
(`:69-74`, `:308-315`, `:456`, 155/155 both arms) and the quantified magnitude from #1 above. Keep
the recommendation; do not keep it as a self-issued ruling.

### MAJ-3 — `HLR-101`'s universal is broader than its LLRs deliver, and the site set is grep-derived, not derivation-derived

`HLR-101`: *"For **every** address value `_parse_address` accepts, `generate_project_report`
**shall** produce a report file rather than raise."* `LLR-101.1`/`.2` deliver only the two decimal
`Length` sites. The universal is not testable as stated (`_ADDRESS_RE = ^0x[0-9A-Fa-f]+$`,
`s19_app/tui/changes/io.py:235`, admits unbounded width), and the artifact's own `R-2` concedes the
resulting cell is unbounded — so the HLR quantifies over a domain in which it also has an
acknowledged unbounded-output failure mode it is not closing.

Separately, `§4.1` presents the crash-site set as C-31-derived and `§10` row 12 marks it ✓, but the
derivation is a **hand-chosen grep pattern list**
(`"{entry.address\|{issue.address\|{region.start\|{region.end\|{low\|{high"`) over two files. A site
that binds the difference to a local first (`length = e.address_end - e.address_start` then
`f"| {length} "`) is invisible to it, and `diff_report_service.py` is outside the searched set with
no stated exclusion. The qa lane's `TC-459` does the genuine derivation (AST walk for
`FormattedValue` with empty `format_spec` over `X.address_end - X.address_start`, across all three
modules) and reaches the same two sites — so the **answer** is right and the **claim of derivation**
is overstated. Under this batch's own rule ("a predicate must test what its LABEL claims"), a
checklist row marked ✓ for C-31 on a hand-written pattern list is the finding.

Minor sub-gap: the architect AT set has no `W + 100` negative; the qa lane's `AT-168` does ("the fix
must not be a one-width special case"). Adopt it.

**Fix.** Narrow `HLR-101` to the decimal-rendering sites the LLRs cover, or add an explicit
in-scope/out-of-scope clause naming the unbounded-cell carry. Replace `§4.1`'s grep with the qa
lane's AST census as the cited derivation, or downgrade `§10` row 12's ✓ for this item.

---

## 4. Minors

| id | finding | evidence | fix |
|---|---|---|---|
| **m-1** | D2's candidate labels run **(a), (b), (d)** — no `(c)` is defined or eliminated (`§6.2`). Separately, the qa lane's `G-4` left three fix shapes open — "hex fallback past the limit", "`>10^K` marker", "raise `sys.set_int_max_str_digits`" — and `§6.2` evaluates only the first; the marker and the process-wide limit raise are never assessed. | `01-requirements-rescoped-architect.md:411-422` vs `01b-qa-catalog-rescoped.md:442` | Restore/record `(c)`, or renumber. Add one line dismissing the process-wide `set_int_max_str_digits` raise (a global side effect on every consumer) so `G-4` is visibly closed. |
| **m-2** | `file:line` drift the artifact flags in one place and not others. `_line_bytes` is cited at `report_service.py:392` (`§5.1`) vs `00b`'s `:394` — the same def-vs-body split the artifact **does** flag for `_parse_address` (`§9`), left unflagged here. `canonical_report_bytes` cited at `tests/conftest.py:1009` (`LLR-102.4`, `§10` row 11) — the def is `:970`, `:1009` is the `raw.replace(b"\r\n", b"\n")` line. The truncation marker cited at `:1355` (`§9` OB-1) — the cap text is `:1354`, the `> TRUNCATED` emit is `:1356`. | verified by `sed`/`grep` on `031ca8d` | Normalise to the `def` line, or state the convention once and apply it. |
| **m-3** | "`generate_project_report` accounts in **~12** separate `emit()` batches" (inherited from `00b` M-6 and `01b` §5) is a 1-variant figure. Actual: **7 fixed + ~6 per variant** (`report_service.py:1641-1679`), i.e. variant-dependent. This is exactly the "a carried number is re-derived, not copied" rule the batch enforces elsewhere — and it matters, because it is what makes B-1's failure mode unbounded rather than an 11-byte constant. | `sed -n '1641,1679p' s19_app/tui/services/report_service.py` | State the batch count as a formula and use it in the B-1 fix's rationale. |
| **m-4** | `LLR-102.1` mandates that `report_service.py` expose the encoder and `flow_report_service` import it, deepening an existing cross-module dependency on **four underscore-private symbols** (`_ByteBudget`, `_line_bytes`, `_report_filename`, and now the encoder). Extracting them into a neutral module is not recorded as a considered alternative, though the batch is already opening both files. `§10` row 2 claims ≥2 alternatives ✓ for D3 on the *assertion shapes*, not on the *module structure*. | `flow_report_service.py:69-74` | Record the extraction as considered-and-deferred with a reason, and carry it to `.dev-flow/BACKLOG.md`. |
| **m-5** | `§10` row 6 marks the diagram ✗ "deliberately omitted … the three defects are point defects in one call chain". That was true of the scope ruling; it is no longer true of `HLR-102`, whose seam now spans two modules, one shared budget consumed in two accounting styles, two writers, and one encoder. | `§5.4`, `§5.6`, `§5.7` | One small mermaid flow for the D3 seam only. D1/D2 genuinely need none. |

---

## 5. Direct answers to the four questions in the brief

**1. Is the `flow_report_service` scope ruling (§5.4) load-bearing or scope creep with a good
story?** — **Load-bearing.** Every factual claim in it verified on `031ca8d`: the shared import
(`:69-74`), the emission gate (`put()` at `:308-315` drops a section on `fits()` false), the
text-mode writer (`:456`), and the asymmetry with `report_service`'s hexdump-only `fits()`
(`:1347`). Reason #1 — a "one encoder" requirement cannot coherently skip a caller of that
encoder's own budget — carries the inclusion by itself. **But** the decisive-sounding reason #2 is
unquantified against a 2 MB budget and a Windows-only N−2 undercount, and the widening beyond the
operator's named scope was resolved by the architect rather than referred. See **MAJ-2**.

**2. Is the D2 elimination real — does "cap the rendered width" still raise?** — **Yes, verified
independently.** `f"{n}"[:32]` evaluates the conversion before the slice:

```
  (b) f'{n}'[:32] at W-1 = 3571: ok len=32
  (b) f'{n}'[:32] at W   = 3572: RAISES ValueError
  (d) guarded at W-1 len=4300 ; at W len=3574
```

Shape (b) is eliminated by output, not argument, and shape (d)'s in-domain byte-identity is
reproduced. This part of the artifact is sound. The residual is the missing `(c)` and the two
unassessed qa-flagged options (**m-1**).

**3. Does `HLR-102`/`LLR-102.1`/`LLR-102.2` express the surviving design unambiguously, or does it
still admit the refuted reading?** — **It still admits the refuted reading**, executed and confirmed
green on all six cases including N = 0. The `>=` form cannot distinguish
`_line_bytes := len(encoder(...))` from the shipped `+1`-per-line convention, and no LLR requires
partition-invariance or states that `_line_bytes` is unchanged. §5.2's heading additionally
reproduces `00b` M-6's forbidden phrase verbatim. See **B-1** — this is the most consequential
finding in the review.

**4. Does the LLR set actually bound the *scan*, and is the reported count honest?** — **Partly, and
unobservably.** `LLR-100.2` states the bound correctly and even pre-empts the "output-only"
misreading in its own text, and `LLR-100.3`'s "at least K" notice is the right honesty property.
But (a) **no AT can observe it** — a scan-all/store-K implementation passes `AT-164/165/166/167`
identically (**B-2**), and `AT-166`'s stated rationale is a backwards inference; and (b)
**`HLR-100` over-claims** — the cap cannot fire below CAP matches, so a low- or zero-match region
still traverses O(V×E) (**B-3**). The *count* is honest as specified; the *bound* is not delivered
in the case that matters most.

---

## 6. What is sound (recorded so iterate does not re-litigate it)

- **`shall`/`should` discipline: clean.** `grep -n "should"` returns 4 hits, all outside normative
  blocks (a quoted code comment `:471`, increment-order prose `:605`, risk row `Q-1` `:628`,
  checklist row 7 `:653`). `grep -n "shall"` outside `>`-prefixed lines returns exactly one hit —
  checklist row 9 describing the rule. `§10` row 9's ✓ is earned.
- **Identifier allocation: sound.** `HLR-`/`LLR-` ≥ 100 appear nowhere on the tree except this
  batch's own artifacts. Highest tracked outside `.dev-flow`: `AT-163`, `TC-398`. `R-TUI-089..094`
  appear only in superseded `.dev-flow` artifacts, so the RESERVED claim holds.
- **Frozen-engine exclusion: verified independently.** `tests/test_engine_unchanged.py:120` and
  `tests/test_tui_directionb.py:5443` define `_ENGINE_PATHS`; neither lists `report_service.py`
  or `flow_report_service.py`.
- **`LLR-100.1`'s cited precedent is real.** `REPORT_MAX_TOTAL_BYTES` is a module global read at
  call time (`report_service.py:1632`; the convention is documented at `:406`), so
  "read at call time so tests can shrink it" is an existing convention, not an invention.
- **`LLR-101.2`'s predicate-is-the-conversion ruling is correct** and `R-6` pre-empts the
  code-smell objection with the right reason (`sys.get_int_max_str_digits()` is
  interpreter-configurable; the qa lane executed the boundary moving to 4153 at limit 5000).
- **`LLR-101.4` (fail-closed) is a genuine regression guard**, and the single-`write_text` position
  (`report_service.py:1682`, after all composition) is verified.
- **`§9` OB-1 is correct and should survive iterate unchanged.** The `> TRUNCATED … (report size
  cap: N bytes)` marker is at `report_service.py:1354-1356` and none of D1/D2/D3 bounds the
  document. The PR must not claim M-2 closed.

---

## 7. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | All four required inputs read in full | ✓ | `01-requirements-rescoped.md` (109 L) · `00b-measurements-rescoped.md` (359 L) · `01-requirements-rescoped-architect.md` (671 L) · `01b-qa-catalog-rescoped.md` (472 L) |
| 2 | `flow_report_service` scope ruling interrogated against source | ✓ | `flow_report_service.py:69-74` import · `:308-315` `put()` emission gate · `:456` `write_text` · `report_service.py:1347` sole `fits()` — all read, not inferred → **MAJ-2** |
| 3 | D2 elimination of "cap the rendered width" independently executed | ✓ | `…/b63/r1/p2.py` Q5: `f"{n}"[:32]` raises at 3572, `len=32` at 3571 → elimination **real** |
| 4 | `HLR-102`/`LLR-102.1`/`LLR-102.2` tested against the refuted design | ✓ | `…/b63/r1/p1.py` Q1: `>=` green on 6/6 under `_line_bytes := len(encoder)`; M-7 `== +1` form red → **B-1** |
| 5 | `LLR-100.2` traversal bound tested for observability | ✓ | `…/b63/r1/p2.py` Q3: scan-all/store-K passes `AT-164/165/166/167` identically → **B-2** |
| 6 | `HLR-100`'s traversal claim tested at the low-match case | ✓ | `…/b63/r1/p2.py` Q4: zero-match region traverses V×E at every grid point; producer read at `report_service.py:1509-1537` → **B-3** |
| 7 | `LLR-100.3` "at least K" honesty assessed | ✓ | Correct as specified; unobservable per **B-2**. Reported in §5 answer 4. |
| 8 | Every `shall`/`should` usage checked | ✓ | 4 `should` hits, all non-normative (`:471`, `:605`, `:628`, `:653`); `shall` only inside `>` blocks. §6 bullet 1. |
| 9 | Unverified/unflagged claims hunted | ✓ | **MAJ-3** (grep presented as C-31 derivation) · **m-2** (three `file:line` drifts) · **m-3** ("~12 batches" is variant-dependent) |
| 10 | Cross-lane consistency checked (AT/TC namespaces) | ✓ | 12-row comparison table in **B-4**; TC story boundaries differ across TC-453…466 |
| 11 | Every finding classified with what/evidence/why/fix | ✓ | §2 (4 blockers, prose form) · §3 (3 majors) · §4 (5 minors, table form) |
| 12 | Probe safety honoured — bounded, short root, deleted | ✓ | Max fixture 8 000 synthetic hits (~19 KB peak, `p2.py` output); root `…/Temp/claude/b63/r1`; `/b63/{a,b,qa,arch,archb,r2,r3}` never touched; tree deleted at close |
| 13 | Probe scripts written to file and run by path (no heredoc-into-python) | ✓ | `p1.py`, `p2.py` written via heredoc-to-file, invoked as `python <path>` |
| 14 | No production source edited; no Phase-1 artifact edited | ✓ | `git status --porcelain` shows only `.dev-flow/state.json` (pre-existing) and the untracked `.dev-flow/2026-07-26-batch-63/` tree; this review is the only file this lane wrote |
| 15 | Superseded artifacts consulted for history only, not reviewed | ✓ | `01-requirements-architect.md`, `-rev5*.md`, `02-review*.md` referenced only for the R-TUI-089..094 reservation check (§6 bullet 2) |
| 16 | Positive findings recorded so iterate does not regress them | ✓ | §6 — six sound properties with citations |

---

## 8. Recommended disposition

**`iterate` to Phase 1**, scoped to four normative edits and one orchestrator action. None of them
requires re-measuring: every threshold in the artifacts survives review.

1. **B-1** — add the partition-invariance / `_line_bytes`-unchanged LLR; re-key `AT-174` to M-7's
   `== +1` form; adopt the qa lane's composability AT; strike §5.2's forbidden phrasing.
2. **B-2** — add a traversal-observing AT (counting wrapper over the candidate iterators).
3. **B-3** — narrow `HLR-100`'s traversal clause; carry the low-match residual to `§9` + BACKLOG,
   naming `range_index.py` as the closing primitive.
4. **B-4** — *orchestrator action*: issue one merged `AT-164..175` / `TC-440..479` allocation; both
   Phase-1 artifacts re-emitted against it.
5. **MAJ-1/2/3** foldable into the same pass; the minors are editorial and can fold or carry.

**Do not** reopen: the D2 fix shape (d), the cap value 200, the boundary pair 3571/3572, the
identifier ranges, the frozen-set analysis, or `OB-1`.
