# batch-63 (RE-SCOPED) — Phase-2 independent review, testability lens

**Reviewer:** independent qa lane (did **not** author `01b`, `01-requirements-rescoped-architect.md`,
or `00b`). **Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`.
**Artifact language:** English. **Constraint honoured: zero production-source edits.** All
counterfactuals ran in a `git archive` export at the short root
`C:/Users/jjgh8/AppData/Local/Temp/claude/b63/r2`, deleted at close (`r2 removed: YES`);
`.../b63/{a,b,qa,r1,r3}` were never touched. Every probe was written to a file and invoked by path.
Fixture ceiling actually used: **4 000 hits / < 1 MB peak** — three orders below the 200 000-hit cap.

---

## 1. BLUF — verdict: **BLOCKED** (4 blockers, 5 majors, 5 minors)

**The orchestrator's own M-7 ruling is the first blocker, and I can refute it by execution.**
Re-keying `AT-174` to `_line_bytes(lines) == len(report_bytes(lines)) + 1` is RED pre-fix **only
because the symbol is missing**. Once the symbol exists it asserts nothing about D3. I built the
minimal wrong implementation — add `report_bytes`, leave `write_text` at `report_service.py:1682` —
and the ruled predicate passed **6/6 cases, 0 RED**, on a tree that still writes CRLF. The ruling
correctly diagnoses that both lanes' invariants were vacuous; its replacement is vacuous in a
different way. It is a useful *pin on the `+1` convention* (which nothing pins today) and must be
labelled as that, not as the D3 gate.

**The second blocker is structural and would corrupt Phase 3 silently.** The two Phase-1 lanes
independently assigned the SAME `AT-164..175` and `TC-440..479` ids to **different tests**. 10 of 12
AT ids and roughly 26 of 40 TC ids carry two incompatible meanings. G-1 anticipated a clause→LLR
reconciliation; the actual collision is one level worse than G-1 predicted, and it is what makes the
M-7 ruling ambiguous (under qa numbering, applying it **deletes** batch-composability — the batch's
own sharpest finding).

**The third and fourth blockers are in D1's cost layer:** the resident-memory AT cannot separate
bounded traversal from bounded materialisation (both arms measured identical peaks), so `LLR-100.2`
has no node that can go RED; and the R-axis threshold **false-fails a correct implementation**
(measured 1.89 against a `< 1.5` gate) — the exact C-39 failure mode, in a catalog that states the
reason it will fail one sentence before requiring it to pass.

What is **sound** and should survive unchanged: qa `AT-172` (structural census) and architect
`AT-172/173` (encoder-mutation) — I ran the same wrong implementation against both and **both went
RED, correctly**. The D2 boundary derivation is correct and reproduces 3572 from the API. The D2
census is reproducible under its own stated predicate. Probe hygiene in both lanes is exemplary.

---

## 2. Blockers

### BLK-1 — the M-7 `AT-174` ruling is vacuous as a D3 gate (RED for a trivial reason)

**Claim under test** (`00b` M-7): *"`report_bytes` does not exist on `031ca8d`, so the assertion
cannot bind pre-fix and is RED on every platform including CI."*

**Refutation, executed.** I patched the export with the smallest implementation that satisfies the
ruled predicate while fixing **nothing**: add

```python
def report_bytes(lines: Sequence[str]) -> bytes:
    return "\n".join(lines).encode("utf-8")
```

and leave `target.write_text("\n".join(lines), encoding="utf-8")` (`report_service.py:1682`) in
place. Executed against that tree:

```
host os.linesep = '\r\n'
writer still text-mode?  True

=== (a) ORCHESTRATOR M-7 RULED AT-174, vs the WRONG implementation ===
case                N  _line_bytes  len(rb)  ruled-predicate
N=0 empty           0            0        0  PASS
N=1 ascii           1            6        5  PASS
N=1 empty str       1            1        0  PASS
N=3 table           3           30       29  PASS
N=3 non-ascii       3           15       14  PASS
N=64 bulk          64         1378     1377  PASS

  RED cases against the WRONG implementation: 0  -> ruling is VACUOUS as a D3 gate
```

and on that same tree the report on disk is still CRLF:

```
  bytes written: b'# report\r\n\r\n| a | b |\r\nrow'
  CR present on this host? True
```

**Why it matters.** The ruled predicate is a function of `_line_bytes` and `report_bytes` **only**.
D3 lives in the *writer*. No predicate over two pure functions can bind a writer that does not call
either of them. "Cannot bind pre-fix" is satisfied by any assertion mentioning a new symbol — it is a
property of the *symbol*, not of the *defect*. The identical argument would make
`assert hasattr(rs, "report_bytes")` a D3 gate.

**Both lanes already had the right gate, and both survive the same probe:**

```
=== (b) ARCHITECT AT-172 (mutation): replace the encoder, file must change ===
  encoder mutation changes the written bytes? False  -> AT-172 RED (correctly rejects the wrong fix)

=== (c) QA AT-172 structural census (no text-mode writer in the derived set) ===
  derived set = ['s19_app/tui/services/flow_report_service.py',
                 's19_app/tui/services/report_service.py']
  text-mode writers still present = ['flow_report_service.py:456', 'report_service.py:1687']
  -> qa AT-172 RED (correctly rejects the wrong fix)
```

**Fix.** Keep the ruled identity, **re-label it**: it is a *convention pin on `_line_bytes`'s `+1`*
(genuinely valuable — the C-26 census found 0 test references, so `+1 → +2` is a green-suite change
today), and it is **not** the D3 gate. State in the requirement that the D3 gate is the pair
{structural census, encoder-mutation}, both of which were shown RED against a wrong fix here.
Additionally the identity must carry the writer-binding clause the ruling drops: *the writer's output
bytes equal `report_bytes(lines)`*, asserted by mutation, not by re-deriving the same join.

### BLK-2 — the two Phase-1 lanes assigned the same AT/TC ids to different tests

`01b` §3 vs `01-requirements-rescoped-architect.md` §5.8/§7, read side by side:

| id | qa lane (`01b`) | architect lane |
|---|---|---|
| AT-164 | bounded hit lines per region | peak memory flat in entry count |
| AT-165 | truncated count is honest `≥K` | hit lines ≤ cap constant |
| AT-166 | resident cost stops tracking R×V×E | honest notice, no total |
| AT-167 | golden neutrality below cap | golden neutrality (**agrees**) |
| AT-168 | wide address does not crash | 3572-digit address yields a report (**agrees in substance**) |
| AT-169 | the **checklist twin** is fixed | 3571-digit address → exact decimal cell |
| AT-170 | **fail-closed**, never partial | the checklist twin |
| AT-171 | the wide-address **Length cell is honest** | fail-closed |
| AT-172 | structural census: no text-mode writer | mutation: replacing the encoder changes report bytes |
| AT-173 | encoder identity `len(rb) == acc − 1` | mutation, for `write_flow_report` |
| AT-174 | **batch-composability** of `_line_bytes` | `_line_bytes >= len(encoder)`, N=0 included |
| AT-175 | on-disk agreement (Windows-only) | no `\r` on disk (Windows-only) (**agrees**) |

TC ranges collide the same way, off by one story boundary: qa assigns `TC-440..453` to D1,
`TC-454..466` to D2, `TC-467..479` to D3; the architect assigns `TC-440..452` / `TC-453..465` /
`TC-466..479`. **`TC-453` is a D1 surface test in one artifact and a D2 rendering test in the
other**, and every D2/D3 id downstream is shifted.

**Why it matters — this is not cosmetic.** Phase 3 implements against one artifact; Phase 4 validates
against the other; the postmortem cites ids. A green `TC-461` proves nothing when the two artifacts
disagree about what `TC-461` is. It also renders the M-7 ruling **ambiguous in a damaging direction**:
"re-key `AT-174` to the encoder" reads, under the architect registry, as an upgrade of the `>=` form;
under the qa registry it **deletes batch-composability**, the property whose absence was measured at
**11 bytes under the file** end-to-end.

**Fix.** Before Phase 3: publish one merged registry as an orchestrator artifact, with each id bound
to exactly one surface+observable, and re-point both Phase-1 documents' cross-references at it. Do not
resolve by "the architect's numbering wins" — qa's `AT-171` (honest Length cell) and `AT-174`
(composability) have **no counterpart** in the architect registry and would be lost.

### BLK-3 — `LLR-100.2` (bounded traversal) has no verifying node that can go RED

`LLR-100.2` says traversal must stop at the cap and *"Bounding output alone **shall not** be treated
as satisfying LLR-100.2."* Its verifying ATs are `AT-164` and `AT-166` (architect §7) — both
**resident-memory** properties. I implemented both candidate fixes and measured them:

```
arm        axis              peak lo    peak hi   ratio  t lo (ms)  t hi (ms)  t ratio  '<1.5'
shipped    E 1000->2000        93879     186207    1.98       9.45      18.23     1.93  RED
cap+break  E 1000->2000        19019      19019    1.00       1.77       1.77     1.00  PASS
cap,NObreak E 1000->2000       19019      19019    1.00       1.84       1.92     1.04  PASS
shipped    V 1->2 @E500        46739      93879    2.01       4.92       9.54     1.94  RED
cap+break  V 1->2 @E500        19019      19019    1.00       1.78       1.81     1.02  PASS
cap,NObreak V 1->2 @E500       19019      19019    1.00       1.98       1.83     0.93  PASS
```
*(stable across two runs; `cap,NObreak` = cap the hit list, `continue` instead of `break` — i.e.
bounded materialisation, unbounded traversal, exactly what `LLR-100.2` forbids.)*

`cap+break` and `cap,NObreak` are **byte-identical in peak** on the E and V axes (19 019 both), and
the wall-time ratios (1.00 vs 1.04, 1.02 vs 0.93) do not separate them either — string formatting
dominates, and the skipped-entry path is nearly free at these sizes. **A `LLR-100.2`-violating
implementation passes every proposed node.** `01b` G-5 half-anticipates this ("AT-166 keys on
*resident* peak … does not key on wall time") but files it as a limit rather than as a missing gate.

**Fix.** Verify traversal with a **counting instrument**, not with a resource ratio: feed
`_addendum_lines` a fixture whose entry sequence is an object that counts `__iter__`/`__next__`
consumption (or raises past index `CAP + m`), and assert the consumed count is `O(CAP)`, not `O(E)`.
That predicate is RED against `cap,NObreak` by construction and is platform- and timing-independent.
Bind it to `LLR-100.2` and give it its own TC.

### BLK-4 — the R-axis memory threshold false-fails a **correct** implementation

`01b` `AT-166` boundary and `TC-451` require peak ratio `< 1.5` for `R 1→2` at `E=500`. Measured
against the *fixed* implementation:

```
cap+break  R 1->2 @E500        19019      35970    1.89   RED
```

A **per-region** cap materialises `R × CAP` hit lines by construction, so peak is linear in R for any
conforming fix. `TC-451` is unsatisfiable.

This is self-contradictory inside `01b` itself: `AT-166`'s own boundary text says *"a fix that bounds
only the per-region list still scales with R"* — and then requires ratio `< 1.5` on that axis. The
architect lane is consistent here: `HLR-100` claims independence of *entry count and variant count*
only, and §1 states plainly that R stays unbounded and is carried to batch-64.

**Fix.** Drop the R axis from the ratio assertion; replace with the honest property —
`peak(R=2) / peak(R=1) ≈ 2` **and** `peak/region` is flat and bounded by `CAP` — and record R as an
open axis carried to batch-64, matching the architect's §1. Do not silence it by widening the
threshold to 2.0: that would also stop `TC-450`/`TC-452` from failing the shipped code (1.98 / 2.01).

---

## 3. Majors

### MAJ-1 — the architect lane's D2 ATs carry the literal 3571/3572; the literal is not stable

`AT-168`/`AT-169` (architect) name **3572** and **3571** directly, and its evidence checklist item 13
justifies it: *"properties of the CPython interpreter limit, not of a constant this batch defines."*
That justification is wrong — the limit is settable per process:

```
$ python -X int_max_str_digits=1000 -c "..."      -> limit 1000  -> W  831
$ PYTHONINTMAXSTRDIGITS=2000 python -c "..."      -> limit 2000  -> W 1661
$ python (default)                                 -> limit 4300  -> W 3572
```

Under any non-default limit a literal-3572 AT is GREEN while the tool crashes at 831. The qa lane got
this right — `W = floor(sys.get_int_max_str_digits() / log10(16)) + 1`, and I verified the derivation
reproduces the measured boundary and that both halves bite:

```
sys.get_int_max_str_digits() = 4300 ; floor(lim/log10(16)) + 1 = 3572  -> reproduces 3572: True
  3571 hex digits -> decimal OK (4300 digits)
  3572 hex digits -> DECIMAL RAISES (Exceeds the limit (4300 digits) ...)
```

**Fix.** Adopt qa's derived form in the merged registry; delete the literals from the architect's ATs;
retain `TC-460` (limit moved → the guard follows), which is the test that fails a literal
implementation. Correct architect checklist item 13 to ✗.

### MAJ-2 — "exactly ONE encoder" is not achievable as specified: `compose_flow_report` returns `str`

`R-TUI-097` demands *"Exactly **one** encoder turns a report's lines into the bytes written"* and
qa `AT-172`'s observable is *"every document-writing call in that set is
`write_bytes(report_bytes(...))`"*. But:

- `report_service.generate_project_report` holds `lines: List[str]` and writes at `:1682`. ✓ fits a
  `report_bytes(lines: Sequence[str]) -> bytes` encoder.
- `flow_report_service.compose_flow_report(state, generated_at) -> str` (`:273`) joins internally at
  `:405` (`return "\n".join(lines)`); `write_flow_report` writes that **string** at `:456`. There is
  no line list at the writer.

So a lines-typed encoder cannot serve both writers without changing `compose_flow_report`'s public
return type — a signature covered by 39 tests (`tests/test_flow_report_service.py`, per `01b`
TC-478's own measurement). Neither lane records this. The architect's `AT-173` ("the same, for
`write_flow_report`") is shape-agnostic and survives; qa's `AT-172` observable does not.

**Fix.** Define the encoder contract over **text** (`report_bytes(text: str) -> bytes`) with a thin
lines overload, or state explicitly that "one encoder" means *one encoding function*, reachable from
two call shapes, and re-word `AT-172`'s observable to "no member of the derived set writes in text
mode; every member's bytes come from the shared encoder" (mutation-checked). Do **not** change
`compose_flow_report`'s return type inside a defect batch.

### MAJ-3 — batch-composability has no requirement backing it

qa `AT-174`/`TC-472` pin `sum(_line_bytes(batch)) == _line_bytes(whole)`, backed by two measurements
(`len(join)` reads 230 vs a true 242 at 12-batch granularity; the allocator lands **11 bytes under**
the file end-to-end). This is the property that makes `report_service.py:1636-1679`'s ~12-`emit()`
accounting correct. **No HLR or LLR states it.** `LLR-102.2` states only `_line_bytes >= len(encoder)`
— which the non-composable `len(join)` redefinition also satisfies per batch while under-counting the
document.

**Fix.** Add `LLR-102.5 — Partition invariance`: *"`_line_bytes` shall satisfy
`Σ _line_bytes(bᵢ) == _line_bytes(concat(bᵢ))` for every partition, because
`generate_project_report` accounts the document in ~12 independent batches."* Bind qa's
`AT-174`/`TC-472` to it. Without this, the M-7 ruling's re-key would silently remove the only node
guarding the defect that was actually measured at 11 bytes.

### MAJ-4 — `TC-459`'s derived set is syntactic, mutation-blind in the removal direction, and not mechanically assertable

I reproduced the catalog's own predicate exactly and it is honest:

```
CATALOG-EXACT predicate sites:
   s19_app/tui/services/report_service.py:996   entry.address_end - entry.address_start
   s19_app/tui/services/report_service.py:1171  entry.address_end - entry.address_start
count = 2   (catalog claims 2)
```

Two weaknesses:
1. The predicate keys on the **syntactic shape** `X.address_end - X.address_start`. A future site
   written as `f"| {_span(entry)} |"` or over a locally-bound pair is invisible; a *refactor* shrinks
   the derived set and the assertion passes **more** easily. A wider net (any unformatted
   `FormattedValue` over an address/length-ish expression across the three report modules) returns
   **17** sites, of which `diff_report_service.py:1000` / `:1675` render `run.length` in decimal —
   those are `DiffRun`s from `s19_app.compare` (32-bit-bounded addresses), so **correctly excluded**,
   but only by a judgement no test encodes.
2. "*assert every derived site is covered by a TC in this batch*" is not a machine-checkable
   predicate. Implemented literally it becomes a pinned literal set — i.e. hand-listing reintroduced
   through the back door, and line-number-brittle.

**Fix.** After the D2 fix introduces the guarded-length helper (architect §6.2 shape (d), 0/9
in-domain renderings changed), invert the census: assert **zero** unformatted decimal renders of an
address-derived span survive **anywhere** in the three report modules outside the helper, and assert
the helper's call count is ≥ 2. That form is RED when a new raw site is added *and* when the existing
sites are refactored away from the helper.

### MAJ-5 — `TC-473`/`TC-474`'s census cannot detect a dropped set element

Executed set-mutation on the accounting-sharing census:

```
full set ['flow_report_service.py','report_service.py'] -> offenders 2  => RED
drop flow_report_service.py -> offenders 1 => RED   (RED for the OTHER member's reason)
drop report_service.py      -> offenders 1 => RED   (same)
```

Pre-fix the mutation is masked (the survivor is still an offender). Post-fix, dropping a member makes
`TC-473` pass **more** easily — the removal direction is exactly what `TC-473` cannot see, and
`TC-474`'s guard (*"non-empty and contains `flow_report_service`"*) is itself a hand-listed anchor
covering only the one member known today. A third future accounting-sharing module is protected by
neither. I also confirmed the derivation is complete **today** by a second independent walk: there are
**0** attribute-style `module._line_bytes` / `module._ByteBudget` accesses anywhere in `s19_app/`, so
the `ImportFrom` walk is not currently missing anything.

**Fix.** Assert the census **cardinality against an independently derived count** (e.g. a grep-based
derivation cross-checked against the AST derivation, asserted equal), and make `TC-474` assert *the
AST set equals the grep set*, so a walk that silently narrows goes RED without a hand-list.

---

## 4. Minors

| # | Finding | Evidence | Fix |
|---|---|---|---|
| MIN-1 | qa `AT-172`'s second clause ("no text-mode `open(...)`") is inert — there are **zero** `open(mode='w')` text-mode calls in the derived set today, so that half of the predicate cannot fail. | probe: `open(...)` branch of the census returned `[]` on both members | Keep it (future-proofing) but label it as a forward guard, not as current evidence. |
| MIN-2 | `AT-166`'s traced window is unspecified. If `make_addendum_results` is constructed inside `tracemalloc.start()/stop()`, peak grows with E for **any** implementation and the AT can never go green. | my measurement only produced 1.00 ratios because the fixture was built **outside** the window | State in the AT: "fixture construction precedes `tracemalloc.start()`". |
| MIN-3 | `01b` G-7 marks the `< 1.5` threshold `assumed` (never measured against a fixed impl). **Now measured by this review:** `cap+break` yields **1.00** on the E and V axes vs shipped 1.98/2.01. | §BLK-3 table | Promote G-7 from `assumed` to measured, citing this transcript; margin is ~2× on both retained axes. |
| MIN-4 | Requirement gaps (no LLR): 095(c) escaping preservation (`TC-448`/`449`), 096(f) address cell intact (`TC-464`), 096(g) parser unchanged (`TC-465`), 097(a) the `+1`-per-line convention pin (`TC-468`). All are valuable TCs with no requirement to trace to. | §5 matrix | Add them as regression clauses under `LLR-100.4` / `LLR-101.3` / `LLR-102.2`, or mark them explicitly "regression guard, no LLR". |
| MIN-5 | `LLR-102.3` ("size equals encoder output, independent of `os.linesep`") lists `AT-175` (Windows-only, non-gating) among its verifiers, which reads as coverage it does not have. `AT-172`'s mutation form does carry it, but only implicitly. | architect §7 row `LLR-102.3 → AT-172, AT-175` | Make the `AT-172` mutation assert **size**, not just "bytes changed", so `LLR-102.3` has an explicit platform-independent verifier. |

---

## 5. Dual-traceability matrix (reconciled clause → LLR), with gaps named

`01b` G-1 asked for this reconciliation at Phase 2. Performed:

| qa clause (`01b` §4) | architect LLR | verifying AT (merged intent) | status |
|---|---|---|---|
| 095 (a) per-region hit bound | LLR-100.1 materialisation cap | qa AT-164 / arch AT-165 | ✓ |
| 095 (b) truncation marker, `≥K` | LLR-100.3 honest notice | qa AT-165 / arch AT-166 | ✓ |
| 095 (c) empty region + escaping preserved | LLR-100.4 in-domain identity | qa AT-167 / arch AT-167 | **partial** — escaping (`TC-448`/`449`) traces to no clause (MIN-4) |
| 095 (d) resident cost | *(none — LLR-100.2 is about traversal)* | qa AT-166 / arch AT-164 | **GAP** — a cost clause exists in neither LLR set |
| *(no qa clause)* | **LLR-100.2 bounded traversal** | arch AT-164, AT-166 | **BLK-3 — orphan requirement; no node can fail it** |
| 096 (a) boundary derivation + surface | LLR-101.2 predicate = conversion | qa AT-168 / arch AT-168 | ✓ (literal vs derived → MAJ-1) |
| 096 (b) modifications + checklist twin | LLR-101.1 guarded rendering | qa AT-169 / arch AT-170 | ✓ |
| 096 (c) guard quotes the API | LLR-101.2 | qa TC-460 | ✓ (architect side ✗ — MAJ-1) |
| 096 (d) golden neutrality | LLR-101.3 in-domain identity | qa AT-167 / arch AT-169 | ✓ |
| 096 (e) fail-closed | LLR-101.4 | qa AT-170 / arch AT-171 | ✓ |
| 096 (f) address cell intact | *(none)* | qa AT-171 | **GAP** — no LLR; **no architect AT at all** |
| 096 (g) parser unchanged | *(none)* | qa TC-465 | **GAP** (MIN-4) |
| 097 (a) `+1` convention pinned | LLR-102.2 (only as `>=`) | qa TC-467/468/469 | **partial** — `>=` does not pin `+1` |
| 097 (b) encoder identity + N=0 domain | LLR-102.2 | qa AT-173 / arch AT-174 | ✓ *but* see BLK-1: it is a pin, not the gate |
| 097 (c) batch-composability | *(none)* | qa AT-174 / `TC-472` | **GAP → MAJ-3** |
| 097 (d) derived census, one encoder | LLR-102.1 | qa AT-172 / arch AT-172, AT-173 | ✓ — **the load-bearing D3 gate, verified RED against a wrong fix here** |
| 097 (e) writer output / on-disk size | LLR-102.3 | qa AT-175 / arch AT-172, AT-175 | ✓ (MIN-5) |
| 097 (f) golden neutrality | LLR-102.4 | qa TC-478 / arch AT-167, AT-169 | ✓ |

**Orphan tests** (no requirement): `TC-448`, `TC-449`, `TC-464`, `TC-465`, `TC-468`, `TC-472`.
**Requirements with no node that can fail**: `LLR-100.2`.
**Unsatisfiable test**: qa `TC-451` (BLK-4).
**Id-space integrity**: broken across artifacts (BLK-2) — this matrix is written against *intent*,
not against ids, and cannot be mechanised until BLK-2 is resolved.

---

## 6. What I could not falsify (holds up under adversarial probing)

- **qa `AT-172` / `TC-473` structural census** — RED against the wrong implementation; derivation
  reproduces `{report_service, flow_report_service}` exactly; no attribute-style access escapes it
  today. This is the D3 gate CI can actually run, and the claim survives.
- **architect `AT-172`/`AT-173` encoder-mutation** — RED against the wrong implementation. Strictly
  stronger than any predicate over pure functions, because it binds the *writer*.
- **D2 boundary** — `W = floor(get_int_max_str_digits()/log10(16)) + 1` reproduces 3572; both halves
  of the pair bite (3571 renders 4300 digits, 3572 raises). Independently re-derived here.
- **D2 census under its own predicate** — exactly 2 sites, `report_service.py:996` and `:1171`;
  `diff_report_service`'s decimal `run.length` renders are `compare`-derived and correctly out of scope.
- **`canonical_report_bytes` neutrality mechanism** — `tests/conftest.py:1009`
  `raw.replace(b"\r\n", b"\n")` confirmed by reading; the golden-neutrality argument is sound.
- **Constant provenance** — `MAX_REPORT_ISSUES_PER_VARIANT=200` (`:90`), `REPORT_CELL_CHARS=512`
  (`:115`), `REPORT_MAX_TOTAL_BYTES=2_097_152` (`:122`), `DECLARED_REGION_NAME_MAX=80`
  (`report_addendum.py:26`) all verified at the cited lines.
- **`None.` negative case** — `report_service.py:1537` `lines.extend(hits if hits else ["None."])`
  confirmed; `AT-164`'s negative is real.

---

## 7. Required actions before Phase 3 (gate conditions)

1. **BLK-1** — re-label the M-7 identity as a `_line_bytes` convention pin; name
   {structural census, encoder-mutation} as the D3 gate in the requirement text, with the wrong-fix
   RED evidence from §2 pasted.
2. **BLK-2** — orchestrator publishes ONE merged `AT-164..175` / `TC-440..479` registry; both Phase-1
   documents re-point at it. Nothing from either lane's unique ATs may be dropped silently.
3. **BLK-3** — add a consumption-counting node for `LLR-100.2`; the memory ratio is retained only as
   a `LLR-100.1` materialisation check.
4. **BLK-4** — remove the R axis from the `< 1.5` ratio assertion; replace with `peak/region` flat +
   `≈2×` in R, and record R as a batch-64 axis.
5. **MAJ-1** — delete literal 3571/3572 from the architect ATs; adopt the derived `W`.
6. **MAJ-2** — settle the encoder contract against `compose_flow_report -> str` before Inc-1.
7. **MAJ-3** — add `LLR-102.5` partition invariance.
8. **MAJ-4 / MAJ-5** — invert the D2 census post-fix; cross-derive the D3 census cardinality.

---

## 8. Evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then or an equivalent surface/observable/counterfactual triple | ✓ | Both artifacts use the triple form consistently (`01b` §3, architect §3.4/§4.4/§5.8) |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | `01b` §4 "Asserts" column is a predicate in all 40 rows; architect §7 binds each LLR to an AT with a stated observable |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | empty `TC-447/467/471`; boundary `TC-442`, `W-1`/`W`; invalid `TC-460`; error `TC-463`/`AT-170` |
| 4 | Regression checklist exists | ✓ | `AT-167`, `TC-448/449/462/465/466/478` — though 4 of them are requirement-orphans (MIN-4) |
| 5 | Exit criteria stated | ✓ | `01b` §5 items 1–5; architect §9 OB-1. **Both correctly refuse to claim M-2 closed** (`01b` G-9, architect §1) |
| 6 | No real PII / secrets / operator firmware | ✓ | all fixtures synthetic; no `examples/` image read by either catalog or by this review |
| 7 | Test-results section left blank unless actually run | ✓ | no TC marked passing in either artifact; results shown are labelled probe transcripts. This review's own transcripts are labelled with the tree they ran against |
| 8 | **Layer B (black-box):** every output-producing story observed through the SHIPPED surface with boundary + negative evidence | ✓ | D1 → `TC-453` (file on disk, pre-fix 800 lines / 0 markers); D2 → `TC-461` (`ValueError`, `reports/=[]`); D3 → `TC-475/476/477` + the encoder-mutation ATs. I re-verified the D3 surface path myself (§2 BLK-1 (b)) |
| 9 | **Bidirectional surface-reachability:** every named input dimension AND every named output observed through the handler | ✗ | Inputs R/V/E, address width and line-partition are all driven — **but** `LLR-100.2`'s output (traversal count) is observed through **no** node (BLK-3), and the R input's assertion is unsatisfiable (BLK-4) |
| 10 | **No unfilled template** — no placeholders, no unallocated id stub | ✓ | Both artifacts are fully specified; the only bracketed tokens are C-36 `NEW — created in Phase 3` markers. **However** the ids themselves are double-allocated (BLK-2), which is worse than an unfilled stub |
| 11 | **C-39:** every threshold executed, transcript pasted | ✗ | `01b` and `00b` execute their own thresholds diligently — but the `< 1.5` ratio was never executed against a *fixed* implementation (`01b` G-7), and doing so here found it **false-fails on R** (BLK-4). Fixed by MIN-3 + BLK-4 |
| 12 | **C-31:** universals' input sets DERIVED, not hand-listed | ✗ | Derivations are genuine and I reproduced all three — but the D3 census is blind to element removal (MAJ-5) and the D2 census is syntactic and blind to refactoring (MAJ-4). Derivation ≠ mutation-resistance |
| 13 | **C-36:** every literal resolves to a defined constant or is flagged NEW | ✗ | qa side ✓; **architect side ✗** — `AT-168`/`AT-169` carry literal 3571/3572 and item 13 defends it (MAJ-1, executed refutation) |
| 14 | **An AT quotes the CONSTANT, never its value** | ✗ | Same as 13. qa's derived `W` verified to reproduce 3572; architect's literal breaks under `-X int_max_str_digits=1000` (→ 831) and `PYTHONINTMAXSTRDIGITS=2000` (→ 1661) |
| 15 | **Every guard shown able to fail** | ✗ | Most are — and I executed the two D3 census/mutation guards going RED against a deliberately wrong fix. But the M-7-ruled `AT-174` is **0 RED** against that same wrong fix (BLK-1), `LLR-100.2` has no failing node (BLK-3), and `TC-451` fails a *correct* one (BLK-4) |
| 16 | **A predicate tests what its LABEL claims** | ✗ | `AT-174` (M-7 ruling) is labelled a D3 gate and tests two pure functions (BLK-1). `AT-164`/`AT-166` are labelled bounded-traversal verifiers and measure resident memory (BLK-3). `TC-459` is labelled "every decimal address render" and tests one syntactic shape (MAJ-4) |
| 17 | Review constraint: no production source edited, no Phase-1 artifact edited | ✓ | `git status --porcelain` on the worktree shows only `.dev-flow/2026-07-26-batch-63/02-review-rescoped-qa.md` added; all patching in the deleted export at `…/b63/r2` |
| 18 | Probe hygiene: bounded fixtures, temp trees deleted, short export root | ✓ | max 4 000 hits / < 1 MB peak (ceiling 200 000 / 50 MB); `r2 removed: YES`; temp report tree `exists=False`; export at `…/Temp/claude/b63/r2`; `.../b63/{a,b,qa,r1,r3}` untouched |
