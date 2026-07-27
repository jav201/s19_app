# batch-63 (RE-SCOPED) — CONSOLIDATED requirements, revision 4 (D3-ONLY)

> ## REVISION 4 — SCOPE REDUCED TO D3 (operator ruling 2026-07-27)
>
> The Phase-2 **re-gate returned NOT-DISCHARGED**: 4 of 10 blockers genuinely closed, 6 partial, and
> the revision-3 fold introduced 5 new defects of its own. Rather than a fourth Phase-1 iteration the
> operator ruled **ship D3 alone**.
>
> **IN SCOPE:** `US-B63-D3` / `R-TUI-097` / `HLR-102` / `LLR-102.1..4` / `AT-172`, `AT-173`,
> `AT-174`, `AT-175`, **`AT-193`** and `TC-470..479`.
>
> **WITHDRAWN to `.dev-flow/BACKLOG.md`, with every measurement as its input:**
> - **D1** (`US-B63-D1` / `R-TUI-095` / `HLR-100` / `LLR-100.*` / `AT-164..167` / `TC-440..454`) —
>   §3 below is **no longer normative**. Its two security blockers (F1 residual: intra-class and
>   cross-variant eviction, with `AT-165` structurally blind to both; F2: the resident-memory axis)
>   are not closable inside batch-63, because both depend on bounding the neighbouring uncapped
>   tables — which is batch-64.
> - **D2** (`US-B63-D2` / `R-TUI-096` / `HLR-101` / `LLR-101.*` / `AT-168..171` / `TC-455..469`) —
>   §4 below is **no longer normative**. It is bounded and tractable but carried three unfixed
>   predicate defects (`AT-171` unsatisfiable on the constructible negative domain; the `:1171`
>   checklist-twin site unbound by any AT; `LLR-101.4` asserting a fail-closed property measured
>   FALSE).
>
> §3 and §4 are **retained below, struck from normativity but not deleted**, so the reversal stays
> traceable and batch-64 inherits the derivation rather than repeating it.
>
> ### Two revision-3 defects fixed here, both the orchestrator's
>
> **(1) `AT-173`'s patch target was unstated, and the obvious reading is vacuous.**
> `flow_report_service.py:69-74` binds its `report_service` symbols with `from .report_service import
> (...)`, so rebinding `report_service.document_bytes` does **not** reach the name
> `flow_report_service` already holds. `AT-173` **shall** patch `flow_report_service.document_bytes`
> — the binding in the module under test, the standard *patch-where-it-is-used* rule — and the
> requirement now says so. Keeping the `from . import` style matches the module's existing
> convention rather than forcing a call-through-module refactor.
>
> **(2) The AST structural census was SUBSTITUTED when the architect review said to ADD it.**
> Revision 3 replaced a 40-row TC layer with three id ranges and silently dropped 6 union
> observables, the census among them — the qa lane called it *"the D3 gate CI can actually run"*.
> It is **restored as `AT-193`** (a genuinely free id: `AT-176` is taken by the REV-5 design carried
> to batch-64, and reusing an ambiguous id is the exact defect this batch is closing).

---

## Superseded header — revision 3

> **BLUF: one document, one id registry with per-id semantics, and D1 re-scoped so it claims only
> what it delivers.** This supersedes `01-requirements-rescoped-architect.md` and
> `01b-qa-catalog-rescoped.md` as the normative spec. Both are retained on disk — the reversal stays
> traceable, and every amendment below is Before → After.

**Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`.
**Supersedes:** the two parallel Phase-1 lane artifacts (normative content only; their executed
transcripts remain valid evidence and are cited, not re-derived).
**Discharges:** all 10 Phase-2 blockers + the majors named in §5.
**Operator rulings folded:** *fold completo con D1 re-alcanzado* · *registry → BACKLOG, not this batch*.

---

## 1. Why this document exists as a single file

Three independent Phase-2 lanes found the same defect: the two parallel Phase-1 authors
double-allocated the id space — **9–10 of 12 AT ids and ~26 of 40 TC ids bind to different
observables** (`TC-453` is a D1 surface test in one artifact and a D2 rendering test in the other;
*fail-closed* is `AT-171` in one and `AT-170` in the other). ~17 distinct observables were competing
for 12 ids, so reconciling by picking one list would have silently dropped coverage.

**The orchestrator's Phase-1 mitigation was necessary and not sufficient.** Fixing the id *ranges*
before dispatch prevented range overlap; it did not assign per-id *semantics*, so both authors filled
the same range with different content. The Phase-1 gate packet's claim that the REV-4 collision was
"removed by construction" is **falsified** and withdrawn here.

**Root cause is structural, and it is not this batch's to fix.** Measured (M-8): "the next free `TC`
id" evaluates to **345 / 398 / 479** depending on whether you grep `REQUIREMENTS.md`, `+ tests/`, or
`+ .dev-flow/` — a 134-id spread, so two authors consulting different subsets both believe they are
in free space. `REQUIREMENTS.md` registers 20 of 73 live `AT` ids (**73 % unregistered**) and 97 of
188 live `TC` ids (**52 % unregistered**), while carrying **6 phantom `TC` ids**
(`TC-319/320/324/325/326/327`) that exist in neither `TC-NNN` nor `def test_tcNNN` form —
`TC-319` being the very node `CLAUDE.md` cites as the origin of control C-26. Per operator ruling the
registry is carried to `.dev-flow/BACKLOG.md` as its own batch with M-8 as its evidence; **this
document fixes the symptom in-batch by being the single normative registry for batch-63.**

---

## 2. Identifier registry — per-id semantics, normative

Every id below binds to exactly ONE observable. Any Phase-3/4 reference resolves here.

| id | binds to | layer |
|---|---|---|
| `US-B63-D1` | the declared-region addendum stops consuming memory proportional to R×V×E | story |
| `US-B63-D2` | a schema-legal address no longer denies the report | story |
| `US-B63-D3` | the byte accounting never undercounts the file it accounts for | story |
| `R-TUI-095` / `HLR-100` / `LLR-100.1..4` | D1 | requirement |
| `R-TUI-096` / `HLR-101` / `LLR-101.1..4` | D2 | requirement |
| `R-TUI-097` / `HLR-102` / `LLR-102.1..4` | D3 | requirement |
| **`AT-164`** | *(WITHDRAWN — see A-06)* | — |
| **`AT-165`** | every producing hit-class is represented in a capped region's addendum | D1 black-box |
| **`AT-166`** | the addendum's own resident cost stops tracking V×E | D1 black-box |
| **`AT-167`** | a capped region's notice reads "at least K" and states no total | D1 black-box |
| **`AT-168`** | a report EXISTS for an address width that denies one today | D2 black-box |
| **`AT-169`** | the narrow case renders byte-identically to today | D2 black-box |
| **`AT-170`** | no report file is left behind when generation aborts (fail-closed) | D2 black-box |
| **`AT-171`** | the guarded `Length` cell is unambiguous — `0x`-prefixed, never a bare decimal | D2 black-box |
| **`AT-172`** | replacing the shared encoder changes the bytes `generate_project_report` writes | D3 black-box |
| **`AT-173`** | replacing the shared encoder changes the bytes `write_flow_report` writes | D3 black-box |
| **`AT-174`** | **PIN, not a D3 gate** — `_line_bytes`'s `+1`-per-line convention and its partition-invariance | D3 regression pin |
| **`AT-175`** | *supplementary, Windows-only, NOT verified by the merge gate* — a written report contains no `\r` | D3 informative |
| `TC-440..454` | D1 white-box | functional |
| `TC-455..469` | D2 white-box | functional |
| `TC-470..479` | D3 white-box | functional |

`R-TUI-089..094` and `TC-399..439` stay **RESERVED** for the deferred batch-64 designs.

---

## 3. US-B63-D1 — the addendum's cost, honestly bounded

### 3.1 What Phase 2 proved wrong about revision 2

- **F1 (security, HIGH).** A per-*region* cap is a first-K cut in **producer order**, and that order
  (`report_service.py:1518` modification hits → `:1524` summary-issue hits → `:1532` check-issue hits)
  puts the **100 %-attacker-supplied class first** and the tool's own findings last. Executed: at
  `mods=200, cap=200`, **0 of 5 validation issues survive**. The selectability did not disappear — it
  moved from the region axis to the hit-class axis, where it is worse.
- **F2 (security, HIGH).** `_modifications_lines` (`:963`) and `_checklist_lines` (`:1095`) carry no
  cap at all, at a measured **988 B/entry** marginal (~11× the addendum's 89 B/hit). With `R=0` the
  document's peak still tracks E. **A correct D1 fix leaves the old `AT-164` RED.**
- **B-2 / BLK-3 (architect + qa).** Bounded traversal had no node able to fail: `cap+break` and
  `cap+NO-break` gave identical peaks (19019/19019, ratio 1.00); wall time did not separate them
  (1.00 vs 1.04).
- **BLK-4 (qa).** The `<1.5` R-axis peak ratio **false-fails a correct fix** — measured **1.89**,
  because a per-region cap materialises R×CAP by construction.

### 3.2 HLR-100 — re-scoped

> **HLR-100 — Bounded addendum, per hit-class.**
> The declared-region addendum **shall** contribute at most a bounded number of rendered lines per
> region **per producing hit-class**, and **shall** stop traversing a class once that class's bound is
> reached. The addendum's resident cost **shall not** grow with the variant count or the per-variant
> entry count once every class is at its bound.

**What this requirement deliberately does NOT claim** (A-05): it does not bound the *document*, and it
does not bound the *process*. `_modifications_lines` and `_checklist_lines` remain uncapped at
988 B/entry and are batch-64's subject; `options.declared_regions` has no cardinality cap anywhere
(the only cap is `DECLARED_REGION_NAME_MAX = 80` on a region's **name** —
`report_addendum.py:26`). R-TUI-095 reduces a product of three file-fed axes to one linear
manifest-fed axis. That is a real fix and **not** a document bound.

### 3.3 LLRs

> **LLR-100.1 — Per-class bound.** `_addendum_lines` **shall** bound each of its three producing
> classes independently against `MAX_ADDENDUM_HITS_PER_REGION` (`NEW — created in Phase 3`), read at
> call time. Worst-case cost **shall** be `O(R × 3K)`.

> **LLR-100.2 — Bounded traversal, countably.** Once a class has reached its bound,
> `_addendum_lines` **shall not** consume further candidates of that class. The number of candidates
> consumed **shall** be observable to a test through an injected counting iterable.

> **LLR-100.3 — Honest notice.** When any class is cut, the region's notice **shall** state a lower
> bound (`at least K`) and **shall not** state a total, because the scan stopped and no total was
> computed.

> **LLR-100.4 — In-domain byte identity.** For inputs at or below the bound in every class, the
> rendered addendum **shall** be byte-identical to `031ca8d`.

### 3.4 Acceptance

| AT | observable, through `generate_project_report` → the `.md` on disk | counterfactual |
|---|---|---|
| `AT-165` | With 200 attacker-supplied modification entries and ≥1 validation issue in the same region, **the issue still appears**. | Revision 2's single per-region cap: 0 of 5 survive (executed). RED on every platform. |
| `AT-166` | Addendum resident peak is flat across V and E once bounded. | Unbounded producer: ×3.99/×4.01 (executed). Keyed to the **addendum only**, not the document — that is what makes it satisfiable. |
| `AT-167` | A cut region's notice contains `at least` and no total. | A scan-all/store-K implementation can still print a total → RED. |

`TC-441` is the consumption counter that makes `LLR-100.2` falsifiable: it injects a counting iterable
and asserts `consumed ≤ 3K + ε`, which `cap,NO-break` fails and `cap+break` passes — the resource-ratio
form could not separate them.

---

## 4. US-B63-D2 — a schema-legal address denies the report

### 4.1 What Phase 2 proved wrong about revision 2

- **The word "crashes" is false at the shipped surface.** `s19_app/tui/app.py:4034` catches the
  `ValueError` and returns `Report rejected: <CPython internals string>`, in the
  **operator-input-rejection** branch. The tool does not crash; it declines, and blames the operator
  for an internal failure. The Phase-1 probe called `generate_project_report` directly, bypassing the
  handler — C-35 applied to the orchestrator's own measurement.
- **F3 (security, MED).** A bare-hex fallback is **forgeable**: `int('9'*3572, 16)` renders a `Length`
  cell of `'9'×3572` whose `isdigit()` is `True`, understating the true length by ~10^730× in a
  document whose purpose is correlating symbols to addresses.
- **MAJ-1 (qa).** Literal `3571`/`3572` in an acceptance is wrong: the boundary moves with the
  interpreter (`-X int_max_str_digits=1000` → 831; `PYTHONINTMAXSTRDIGITS=2000` → 1661).

### 4.2 HLR-101

> **HLR-101 — Every schema-legal address renders.**
> Report generation **shall** produce a report for every address the change-file schema accepts. A
> length that cannot be rendered as a decimal numeral under the interpreter's digit limit **shall** be
> rendered in an unambiguous alternative form, and **shall not** raise.

### 4.3 LLRs

> **LLR-101.1 — Guarded rendering.** Both decimal `Length` renderers — `report_service.py:996`
> (`_modifications_lines`) and `report_service.py:1171` (`_checklist_lines`), the exact two-member set
> derived by AST census — **shall** route the value through one shared helper that returns a decimal
> numeral when the interpreter can produce one and an unambiguous alternative otherwise.

> **LLR-101.2 — Unambiguous alternative.** The alternative form **shall** carry a `0x` prefix, so it
> can never be read as a decimal numeral, and **shall not** be confusable with `_format_bytes(None)`'s
> `-`.

> **LLR-101.3 — Derived boundary.** No acceptance **shall** hard-code the raising width. The width
> **shall** be derived from `sys.get_int_max_str_digits()` at test time.

> **LLR-101.4 — Fail-closed preserved.** Generation **shall** continue to write the report in a single
> terminal write, so an abort leaves no file.

### 4.4 Acceptance

| AT | observable | counterfactual |
|---|---|---|
| `AT-168` | At width `W` (derived), a report **file exists**; today none does. | Pre-fix: `reports/` empty (executed). |
| `AT-169` | At width `W-1`, the report is byte-identical to `031ca8d`. | A hex-everywhere fix changes 9/9 in-domain renderings (executed) → RED. |
| `AT-170` | On abort, no file matching `REPORT_FILENAME_REGEX` remains. | Covers F6's residue; the label is narrowed to what the predicate tests. |
| `AT-171` | The guarded cell **starts with `0x`** and is not `-`. | `'9'×3572` forgery passes revision 2's "non-empty, not `-`" and fails this. |

---

## 5. US-B63-D3 — the accounting must not undercount

### 5.1 What Phase 2 proved wrong about revision 2

- **B-1 (architect), MAJ-3 (qa), F4 (security) — the same defect from three angles.** `LLR-102.2`'s
  `>=` form is **satisfied by the very design `00b` M-6 refuted**: nothing in revision 2 states that
  `_line_bytes` is unchanged or that accounting is partition-invariant, so Phase 3 could ship
  `_line_bytes := len(encoder(...))`, pass every LLR and every AT, and undercount **linearly in the
  variant count** (7 fixed `emit()` batches + ~6 per variant) — strictly worse than the CRLF bug,
  which is bounded at N−2 and zero on Linux. The retracted phrase *"the writer and the accounting
  share ONE encoder"* also survived as a ruling heading.
- **The orchestrator's `AT-174` replacement was refuted too.** Against the minimal wrong
  implementation (add `report_bytes`, leave `write_text`) it passed **0 RED** on a tree still writing
  CRLF, because the predicate relates two pure functions of `lines` and the writer never appears in it.
- **MAJ-2 (qa).** "Exactly one encoder" typed on `lines` is unachievable: `compose_flow_report`
  returns `str` (`flow_report_service.py:273`, joining at `:405`) and is covered by 39 tests.

### 5.2 HLR-102

> **HLR-102 — One place bytes are made; accounting is an unchanged upper bound.**
> Every report writer that consults a `_ByteBudget` **shall** obtain the bytes it writes from one
> shared encoder and **shall not** encode or newline-translate on its own. `_line_bytes` **shall**
> remain exactly as shipped at `031ca8d` — charging one byte per line, which is **partition-invariant**
> and therefore correct under the composer's multi-batch accounting — and **shall** remain an upper
> bound of the encoder's output.

### 5.3 LLRs

> **LLR-102.1 — One encoder, typed to serve both writers.** `report_service` **shall** expose a single
> function `document_bytes(text: str) -> bytes` (`NEW — created in Phase 3`).
> `generate_project_report` (`:1682`) and `write_flow_report` (`flow_report_service.py:456`)
> **shall** both obtain their written bytes from it and **shall not** call `write_text`. It takes
> `str`, so `compose_flow_report`'s public `-> str` return type is unchanged.

> **LLR-102.2 — `_line_bytes` is unchanged and partition-invariant.** `_line_bytes` **shall** be
> byte-identical to `031ca8d`. For every partition of a document into emit batches,
> `sum(_line_bytes(batch))` **shall** be independent of the partition. Redefining it in terms of the
> encoder is **prohibited**: measured 182 under every partition for the shipped form versus 170
> against a true 181 at composer granularity for the `len(join)` form.

> **LLR-102.3 — Platform-independent file size.** A written report's size **shall** equal
> `len(document_bytes(...))` regardless of `os.linesep`.

> **LLR-102.4 — Golden neutrality.** No stored golden or snapshot **shall** move. Measured over the
> whole suite, not assumed: 2188 passed, 29 snapshots, 0 goldens moved, with the 3 export-only
> failures proven environmental in both arms.

### 5.4 Acceptance

| AT | observable | counterfactual |
|---|---|---|
| `AT-172` | Monkeypatch `document_bytes`; **the bytes on disk from `generate_project_report` follow**. | Pre-fix there is no encoder to bind → RED on every platform **including CI**. The file is in the expression, which is what the two refuted invariants lacked. |
| `AT-173` | The same for `write_flow_report`, **patching `flow_report_service.document_bytes`** — the binding in the module under test. | Enforces the D3-C scope ruling; that module's `fits()` (`:310`) gates **emission**. **The patch target is normative:** `flow_report_service.py:69-74` uses `from .report_service import (...)`, so patching `report_service.document_bytes` leaves the already-bound name untouched. **Corrected at the PR gate:** the wrong target is a **false-NEGATIVE** — measured RED against a *correct* writer — so it blocks a good change rather than passing a bad one. The ruling stands; only this justification was wrong. |
| **`AT-193`** | **RESTORED (rev 4).** No module sharing the `_ByteBudget` accounting writes its document in text mode. The module set is **derived by import-graph walk**, not hand-listed, and asserted non-empty. | Pre-fix **RED on every platform including CI** — `report_service.py:1682` and `flow_report_service.py:456` both call `write_text` today. This is the structural gate that survives CI's blindness to D3's *behaviour*; the architect review said to ADD it and revision 3 substituted it away. Input set derived per C-31, so dropping a real member turns it RED. |
| `AT-174` | **PIN, not a gate.** `_line_bytes` charges `+1`/line and is partition-invariant across ≥3 partitions of one document. | Changing `+1`→`+2`, or redefining it as `len(join)`, goes RED. Worth keeping because the C-26 census found `_line_bytes` has **zero** test references today. |
| `AT-175` | *Supplementary, Windows-only:* a written report contains no `\r`. | **Explicitly NOT verified by the merge gate** — pre-fix it is green on `ubuntu-latest` (`tui-ci.yml:25,:61`). Recorded so the batch cannot imply CI covers D3. |

---

## 6. Amendment log (Before → After)

| # | Before (revision 2) | After (this revision) | Discharges |
|---|---|---|---|
| A-01 | Two lane artifacts, overlapping ids | One normative document, per-id semantics (§2) | arch B-4 · qa BLK-2 · sec F5 |
| A-02 | `LLR-102.2`: `_line_bytes >= len(encoder)` | `_line_bytes` **unchanged + partition-invariant**; redefinition prohibited | arch B-1 · qa MAJ-3 · sec F4 |
| A-03 | Ruling heading reproduced the retracted phrase | Phrase removed; HLR-102 says "one place bytes are made" | sec F4 |
| A-04 | `AT-174` = a D3 gate | `AT-174` = a **pin**; `AT-172/173` are the gates | qa BLK-1 (the orchestrator's own ruling) |
| A-05 | `HLR-100` asserted a document/process memory bound | Scoped to the **addendum**; what it does not close is stated | sec F2 · arch B-3 |
| A-06 | `AT-164` (document peak) | **WITHDRAWN** — unsatisfiable while the neighbours are uncapped (988 B/entry) | sec F2 |
| A-07 | Per-**region** cap | Per-**hit-class** cap, `O(R×3K)` | sec F1 |
| A-08 | `LLR-100.2` unobservable | Consumption counter via injected counting iterable (`TC-441`) | arch B-2 · qa BLK-3 |
| A-09 | `<1.5` R-axis peak ratio | Withdrawn (measured 1.89 for a correct fix) | qa BLK-4 |
| A-10 | "D2 CRASHES the tool" | Report **denial** + error misclassified as operator input rejection | arch MAJ-1 |
| A-11 | Bare-hex fallback | Mandatory `0x` prefix, asserted | sec F3 |
| A-12 | Literal `3571`/`3572` in acceptances | Derived from `sys.get_int_max_str_digits()` | qa MAJ-1 |
| A-13 | Encoder typed on `lines` | `document_bytes(text: str)` — serves both writers, no public signature change | qa MAJ-2 |
| A-14 | "fail-closed / never partial" | Narrowed to what the predicate tests (`AT-170`) | sec F6 |

---

## 7. Increment cut (≤5 files each, dependency order)

| inc | files | delivers |
|---|---|---|
| 1 | `report_service.py`, `flow_report_service.py`, + 2 test files | D3 — `document_bytes`, both writers, `AT-172/173/174/175` |
| 2 | `report_service.py`, + 1 test file | D2 — the shared guarded renderer at both sites, `AT-168..171` |
| 3 | `report_service.py`, + 2 test files | D1 — per-class cap + counted traversal, `AT-165..167` |

D3 first: it is the only one that touches a second module, and `AT-174`'s pin protects the accounting
the other two increments rely on.

## 8. Obligations carried

- **OB-1 (extended per sec F2).** The PR **shall** state that batch-63 closes neither M-2 nor the
  document's resident-memory axis. The `> TRUNCATED … (report size cap: N bytes)` marker still asserts
  a bound the document violates.
- **OB-2 (new).** The AT/TC **registry** goes to `.dev-flow/BACKLOG.md` as its own batch, with M-8 as
  evidence: 73 % of `AT` and 52 % of `TC` live nodes unregistered, 6 phantom `TC` ids, and a 134-id
  spread in "next free id" depending on which subset is grepped.
- **OB-3.** `diff_report_service`'s two text-mode writers (no budget, so not D3) → BACKLOG as a
  consistency follow-up.
