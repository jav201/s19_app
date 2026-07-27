> **SUPERSEDED.** The normative spec is `01-requirements-rescoped-consolidated.md`
> (revision 4, D3-ONLY). This artifact's SS4 `TC-467..479` semantics are **RETIRED**:
> every id in `TC-470..479` binds a different observable here than the shipped nodes
> carry, and `TC-467..469` have no shipped node at all. The live per-id table is
> `04-validation-rescoped.md` SS2b. Retained for traceability, not for reference.

# batch-63 (RE-SCOPED) — Phase-1 QA catalog: validation strategy + AT/TC registry

**Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main` (RC-1 verified).
**Scope input:** `01-requirements-rescoped.md` (D1/D2/D3). **Authoritative numbers:** `00b-measurements-rescoped.md`.
**Registry (orchestrator-fixed):** `US-B63-D1/D2/D3` · `R-TUI-095/096/097` · `AT-164..AT-175` · `TC-440..TC-479`.
**Language:** English. **Phase-1 constraint honoured: no production source was edited.**

---

## 1. BLUF

The strategy is **three-layer per defect**: a *white-box unit layer* that pins the primitive
(`_addendum_lines`, the two decimal `Length` renderers, `_line_bytes`), a *black-box surface layer*
that observes the deliverable **through the shipped writer** (`generate_project_report` /
`write_flow_report` → the file on disk), and a *derived-census layer* (C-31) whose input set is
produced by an AST/import-graph walk rather than hand-listed, because all three defects are
universals over a set of call sites that a human list has already got wrong once (D2's twin was
found by execution, not by reading). Every threshold in this catalog was executed on `031ca8d`
before it was written, and every AT/TC below names the counterfactual that turns it RED.

**The hardest testing problem is D3, and it is worse than the brief states.** CI is `ubuntu-latest`,
where the *unpatched* writer already emits LF — so **no purely behavioral assertion about the
written file can be non-vacuous on CI**, because on Linux the pre-fix and post-fix behaviors are
byte-identical. Worse, I executed the invariant the measurement transcript proposed and **it is
false at N=0** (`_line_bytes([]) == 0`, so `0 == 0 - 1` is False), and I executed the "one shared
encoder" fix shape the transcript derived and **it introduces a new, larger error**: redefining
`_line_bytes` as `len("\n".join(lines).encode())` destroys batch-composability, and
`generate_project_report` accounts in ~12 separate `emit()` batches, so the allocator ended up
**11 bytes UNDER** the file at every fixture size — a worse defect than the one being fixed, in the
same direction as the original bug. §5 gives the full resolution.

---

## 2. Validation method per requirement

| Req | Story | Method | Justification |
|---|---|---|---|
| **R-TUI-095** (D1 `_addendum_lines`) | US-B63-D1 | **Test** (unit + surface) **+ Analysis** (bounded resource grid) | The functional part — "at most K hit lines per region, plus an honest `≥` marker" — is fully observable in the written document, so it is Test. The *cost* claim ("resident memory stops tracking R×V×E") is not observable in the document at all; it needs a measured grid. Analysis, not Demo, because the declared-domain fixture is the one the scope ruling says *building it is what crashes* — the grid extrapolates from a measured per-hit constant instead. |
| **R-TUI-096** (D2 decimal `Length`) | US-B63-D2 | **Test** (unit + surface), boundary pair both sides | The defect is a raised exception on a schema-legal input, and both the raise and the fail-closed consequence (`reports/` empty) are directly observable. No inspection needed: the boundary is computable and was executed. |
| **R-TUI-097** (D3 `_line_bytes` vs the writer) | US-B63-D3 | **Test** (platform-neutral algebraic properties) **+ Inspection** (AST structural census) **+ one platform-conditional Test** | The behavioral difference **does not exist on the CI platform**. Certifying it by Test alone would be a vacuous pass on exactly the gate that decides the merge. Inspection (an AST assertion that no accounting-sharing module writes its document in text mode) is RED pre-fix on *every* platform and is therefore the load-bearing gate; the on-disk equality Test is retained but explicitly labelled Windows-only. |

Nothing here is validated by **Demo**: all three defects are invisible in a screenshot and two of
them are only visible at input sizes an operator will not type by hand.

---

## 3. AT registry (`AT-164` .. `AT-175`)

Each AT names the SHIPPED surface it drives, the observable it asserts, its representative /
boundary / negative inputs, its RED counterfactual, and the platform on which that RED is reachable.

### US-B63-D1 → R-TUI-095

#### AT-164 — the addendum emits a bounded number of hit lines per region
- **Surface:** `generate_project_report(...)` → the `.md` file under `reports/`, read from disk.
- **Observable:** the count of lines matching `- modification @` / `- issue [` inside one
  `### <region>` block is `<= MAX_ADDENDUM_HITS_PER_REGION`. **`NEW — created in Phase 3`**
  (C-36; recommendation: mirror the existing `MAX_REPORT_ISSUES_PER_VARIANT = 200`,
  `report_service.py:90`, exactly as that constant mirrors
  `flow_report_service.MAX_REPORT_FINDINGS_PER_BLOCK = 200`, `flow_report_service.py:88` — a reader
  comparing the three bounded sections should not have to learn three numbers).
- **Representative:** R=1, V=1, E=10 → 10 lines, no marker.
- **Boundary:** E = CAP−1 (all lines, no marker) · E = CAP (all lines, **no marker** — the interior
  case, asserted for both the count *and* the marker's absence) · E = CAP+1 (CAP lines + marker).
- **Negative:** a region with zero hits still renders exactly `None.` (`report_service.py:1537`).
- **RED counterfactual:** on `031ca8d`, E=CAP+1 emits CAP+1 hit lines and no marker. Executed today
  at a smaller scale: R=2, V=1, E=400 → **800 hit lines in the file, 0 truncation markers**
  (probe D-3). **Platform: any.**

#### AT-165 — the truncated count is reported honestly as `≥K`, never as an exact total
- **Surface:** same file on disk.
- **Observable:** when the marker fires, its text contains the `≥` (or ASCII `>=`) token adjacent to
  the count, and does **not** contain an exact-total phrasing (`of N`, `N total`).
- **Why this AT exists:** lane A's finding, carried in the scope ruling — bounding *output* does not
  bound *traversal*. If the producer stops scanning at the bound (which is the whole point of D1's
  fix), the tool **cannot know** the true total, so a marker stating one would be the same class of
  defect this batch was founded to remove: a document asserting what it does not honour.
- **Representative / boundary:** E = CAP+1 (smallest truncating input) and E = 4×CAP.
- **Negative:** E = CAP → **no marker at all**, so an implementation that always emits `≥CAP` fails.
- **RED counterfactual:** a marker copied from `_hexdump_section`'s wording
  (`report_service.py:1333`, `"{omitted} of {total} modified regions omitted"`) states an exact
  total → RED. **Platform: any.**

#### AT-166 — resident cost stops tracking R×V×E on all three axes
- **Surface:** `_addendum_lines` under `tracemalloc`, on a **bounded** grid (see §6).
- **Observable:** peak traced bytes when *any one* of R, V, E doubles grows by a factor `< 1.5`.
- **Representative:** E 1000→2000, R fixed 1, V fixed 1.
- **Boundary:** the same ratio for R 1→2 and V 1→2 (the product law was confirmed on all three axes
  independently, so a fix that bounds only the per-region list still scales with R).
- **Negative:** a fixture with zero hits must not trip the harness (peak ratio undefined → the test
  asserts the axis grid only over non-empty fixtures, explicitly).
- **RED counterfactual — executed today:** `peak(E=1000) = 93 937 B`, `peak(E=2000) = 186 265 B`,
  **ratio 1.98** (probe D-2). Measured per-hit constant across the grid: **89.2–93.9 B/hit**,
  consistent with the transcript's 87–94. **Platform: any.** Marked `slow`.

#### AT-167 — golden neutrality below the cap
- **Surface:** `generate_project_report` → `canonical_report_bytes` (`tests/conftest.py:970`).
- **Observable:** for a fixture whose every region is under the cap, the canonical bytes are
  identical to the pre-fix output.
- **Representative:** the existing 2-variant fixture in `tests/test_report_service.py::test_full_report_content`.
- **Boundary:** E = CAP−1 (largest untruncated input).
- **Negative:** E = CAP+1 → bytes **differ** (otherwise the cap did nothing, and AT-167 would be a
  test that cannot fail).
- **RED counterfactual:** an implementation that reformats the hit line (e.g. renumbering, or moving
  the `(variant …)` suffix) drifts the canonical bytes → RED. **Platform: any.**

### US-B63-D2 → R-TUI-096

Throughout D2, `W` denotes the **first hex width whose decimal rendering raises**, *derived* as
`floor(sys.get_int_max_str_digits() / log10(16)) + 1`. Executed: derivation yields **3572**, which
reproduces the transcript's measured boundary exactly (probe B). **An AT must quote
`sys.get_int_max_str_digits()`, never the literal 3572** — executed proof that the literal is not
stable: under `sys.set_int_max_str_digits(5000)` the boundary moves to **4153** (probe B-3).

#### AT-168 — a schema-legal wide address does not crash report generation
- **Surface:** `generate_project_report(...)`.
- **Observable:** the call returns a `Path`, that path exists, and the file is non-empty.
- **Representative:** an ordinary 8-hex-digit address (unchanged behavior).
- **Boundary pair:** width `W-1` (survives today) / width `W` (raises today) — **both must bite**.
- **Negative:** width `W + 100` also survives (the fix must not be a one-width special case).
- **RED counterfactual — executed today:** at `W = 3572`,
  `ValueError: Exceeds the limit (4300 digits) for integer string conversion`, `reports/ = []`
  (probe C-1). **Platform: any.**

#### AT-169 — the checklist twin is fixed too
- **Surface:** `generate_project_report(...)` driven with a `CheckRunResult`, not a `ChangeSummary`
  — i.e. the `_checklist_lines` path (`report_service.py:1171`), independently of
  `_modifications_lines` (`report_service.py:996`).
- **Observable:** identical to AT-168, on the checklist-only fixture.
- **Boundary pair:** `W-1` / `W`.
- **RED counterfactual — executed today:** the checklist path raises at exactly the same widths and
  leaves `reports/ = []` (probe C-1b). **A fix applied only to `_modifications_lines` leaves AT-169
  RED.** This AT exists because REV-4's catalog shipped a predicate that tested less than its label
  claimed; here the label is "the Length column is safe" and only two call sites make that true.
  **Platform: any.**

#### AT-170 — fail-closed is preserved: never a partial document
- **Surface:** `reports/` directory contents after a generation that raises.
- **Observable:** when composition raises for *any* reason, `reports/` contains **no** report file;
  when composition succeeds, the file contains every mandated top-level heading through the last
  section (no truncated tail).
- **Representative:** injected exception during composition (monkeypatched renderer).
- **Boundary:** exception raised on the *last* variant's last section (the latest possible point
  before the single `write_text`, `report_service.py:1682`).
- **Negative:** a successful run leaves exactly one file.
- **RED counterfactual:** an implementation that writes incrementally, or that catches the
  `ValueError` and writes what it has, leaves a partial file → RED. Today's behavior is the
  *correct* one and is a **regression guard**, not a new capability
  (measured: `files left in reports/: []`, transcript M-3). **Platform: any.**

#### AT-171 — the wide-address cell is honest and the narrow case is unchanged
- **Surface:** the report file's `| Address | Length | …` row.
- **Observable:** at width `W` the `Length` cell is **non-empty** and **distinguishable from
  `_format_bytes(None)`'s `-`** (`report_service.py:448`) — a reader must be able to tell "this
  length was too large to render in decimal" from "no value was captured". The Address cell at the
  same width is rendered **in full** (hex is exempt from the digit limit — executed: a 4072-hex-digit
  value formats fine, probe B-2), so the fix must not truncate the address to dodge the length.
- **Representative:** width 8 → the plain decimal, byte-identical to today.
- **Boundary:** `W-1` → plain decimal of exactly `sys.get_int_max_str_digits()` digits (executed:
  4300 digits at width 3571, probe B-1).
- **Negative:** width `W` → **not** `-`, **not** empty.
- **RED counterfactual:** rendering `-` on overflow → RED (indistinguishable from no-value);
  rendering the length in hex unconditionally → RED against the width-8 representative, because it
  drifts every stored golden. **Platform: any.**

### US-B63-D3 → R-TUI-097

#### AT-172 — one encoder: no accounting-sharing module writes its document in text mode
- **Surface:** the module set **derived** by an import-graph walk of `s19_app/` for
  `ImportFrom` of `_line_bytes` / `_ByteBudget`, **plus the definer**. Executed (probe E-2): the set
  is exactly `{report_service.py, flow_report_service.py}` — `flow_report_service.py:69`.
- **Observable:** every document-writing call in that set is `write_bytes(report_bytes(...))`;
  no `write_text` and no text-mode `open(...)` survives in the set. `report_bytes` is
  **`NEW — created in Phase 3`** (C-36).
- **Representative:** `report_service.generate_project_report`'s writer (`:1682`).
- **Boundary:** the derived set must be asserted **non-empty and containing
  `flow_report_service`** — a census that silently returns `{}` passes vacuously (see TC-474).
- **Negative:** `diff_report_service.py:1393,:2063` uses `write_text` and is **correctly excluded**
  — it has no byte accounting to be wrong against (transcript C-4). The AT must not flag it.
- **RED counterfactual — verifiable today by reading the tree:** both members of the derived set use
  `write_text` on `031ca8d` (`report_service.py:1682`, `flow_report_service.py:456`).
  **Platform: any, INCLUDING CI. This is the D3 gate that CI can actually run.**

#### AT-173 — the accounting and the encoder agree, by construction
- **Surface:** `report_bytes` + `_line_bytes`, pure functions.
- **Observable:** `len(report_bytes(lines)) == _line_bytes(lines) - 1` for every `N >= 1`, and
  `_line_bytes([]) == 0`.
- **Representative:** a 64-line ASCII list.
- **Boundary:** `N=1`; `N=1` where the single line is `""`; **`N=0`, where the identity does NOT hold
  and the test says so explicitly** — executed: `_line_bytes([]) = 0`, joined bytes `= 0`,
  `0 == 0-1` → **False** (probe A-2). *The measurement transcript proposed this identity as the
  D3 acceptance criterion without its arity guard; it is false at N=0.*
- **Negative:** non-ASCII — `_line_bytes` must count **bytes**, not characters
  (executed: `["áé","中文","ok"]` → joined 14 B, accounted 15, identity holds, probe A-1).
- **RED counterfactual:** changing the `+1` in `report_service.py:394` to `+2` (or dropping it)
  → RED. Nothing pins that constant today — executed reverse census: `_line_bytes` appears in
  **0 test files** (probe E-4). **Platform: any, including CI.**

#### AT-174 — `_line_bytes` is batch-composable
- **Surface:** `_line_bytes`, over partitions of one line list.
- **Observable:** `sum(_line_bytes(b) for b in partition) == _line_bytes(whole)` for every partition.
- **Representative:** a 3-batch partition. **Boundary:** the 1-batch and the singleton
  (`N`-batch) partitions. **Negative:** a partition containing an empty batch.
- **Why this AT exists — and this is the batch's sharpest finding:** `generate_project_report`
  accounts the document in **~12 separate `emit()` batches** (`report_service.py:1636-1679`), so a
  non-composable definition under-counts by one byte per batch boundary. I applied the transcript's
  own "one shared encoder" fix shape to a `git archive` export and measured the result:
  **`budget.used` was 11 bytes UNDER the file at every fixture size** (2 / 20 / 200 entries → delta
  `+11` constant, probe F pre-correction), i.e. a **worse** under-account than the CRLF bug, in the
  same direction. Executed algebraic confirmation: the shipped `+1/line` form is composable over
  1/2/3/12-batch partitions; `len(join)` is composable **only** over the 1-batch partition
  (probe G).
- **RED counterfactual:** redefine `_line_bytes` as `len("\n".join(lines).encode())` → RED at every
  partition of size > 1. **Platform: any, including CI.**

#### AT-175 — the written file agrees with the allocator on disk ⚠ **WINDOWS-ONLY RED**
- **Surface:** `generate_project_report` → `path.stat().st_size`, vs the `_ByteBudget.used` the
  composer finished with.
- **Observable:** `st_size == budget.used - 1`, and the file contains no `\r` byte.
- **Representative / boundary:** 2, 20 and 200 modification entries (N = 74 / 92 / 272 lines).
- **RED counterfactual:** the shipped writer. Executed on this Windows host:
  `on_disk - used = +72 / +90 / +270`, i.e. exactly `N-2` (probe C-2), confirming the transcript's
  N−2 correction and refuting both REV-5 lanes' N−1.
- **⚠ PLATFORM:** RED **only on Windows**. On Linux the unpatched writer already emits LF, so
  `st_size == used - 1` is **GREEN pre-fix** — executed: the LF-equivalent length is `used - 1` at
  all three sizes (probe C-2, `linux_disk` column). **CI cannot fail this AT.** See §5.

---

## 4. TC registry (`TC-440` .. `TC-479`)

Binding note: HLR/LLR numbering is being derived in parallel by the architect against this same
registry. To avoid the REV-4 collision, **every TC below binds to its requirement id plus a named
behavioral clause**, not to an LLR number I would have to guess. Reconcile clause → LLR at Phase 2.

### US-B63-D1 / R-TUI-095 — TC-440 .. TC-453

| TC | Verifies (clause) | Asserts | Counterfactual → RED |
|---|---|---|---|
| TC-440 | R-TUI-095 (a) per-region hit bound | `_addendum_lines` returns `<= MAX_ADDENDUM_HITS_PER_REGION` hit lines for one region at E=CAP+1 | shipped code returns E lines |
| TC-441 | 095 (a) below the bound | E=CAP−1 → exactly E hit lines **and** no marker line | a cap that always emits a marker |
| TC-442 | 095 (a) **at** the bound (interior case) | E=CAP → exactly CAP hit lines **and** `not any("≥" in ln)` — both halves asserted | an off-by-one cap (`< CAP`) or a marker that fires at equality |
| TC-443 | 095 (b) truncation marker | E=CAP+1 → CAP hit lines + exactly one marker containing `≥` | marker absent, or marker stating an exact total |
| TC-444 | 095 (a) cap is **per region** | R=2, each with E=CAP+1 → 2×CAP hit lines and 2 markers | a document-wide cap emits CAP total |
| TC-445 | 095 (a) cap spans variants | V=2, E=CAP (so 2×CAP hits target one region) → CAP lines + 1 marker | a per-variant cap emits 2×CAP |
| TC-446 | 095 (a) cap covers **all three** hit producers | fixture mixing modification hits (`:1518`), summary-issue hits (`:1524`) and check-issue hits (`:1532`); total > CAP → CAP lines | a cap applied to the modification branch only — the "predicate must test what its LABEL claims" trap |
| TC-447 | 095 (c) empty region unchanged | zero-hit region renders exactly `None.` | a cap rewrite that emits `≥0` or an empty block |
| TC-448 | 095 (c) escaping preserved | region name still passes `md_safe(..., limit=DECLARED_REGION_NAME_MAX)` — `DECLARED_REGION_NAME_MAX = 80`, `report_addendum.py:26` | a rewrite that drops the escape (batch-62 D-5 regression) |
| TC-449 | 095 (c) escaping preserved | `variant_id` still passes `md_safe(..., limit=REPORT_CELL_CHARS)` — `REPORT_CELL_CHARS = 512`, `report_service.py:115` | same |
| TC-450 `slow` | 095 (d) cost — E axis | tracemalloc peak ratio `< 1.5` for E 1000→2000 | shipped ratio **1.98** (executed) |
| TC-451 `slow` | 095 (d) cost — R axis | peak ratio `< 1.5` for R 1→2 at E=500 | shipped **1.91** (transcript M-4) |
| TC-452 `slow` | 095 (d) cost — V axis | peak ratio `< 1.5` for V 1→2 at E=500 | shipped **2.01** (transcript M-4) |
| TC-453 | 095 (a)(b) **through the shipped surface** | `generate_project_report` with `declared_regions` and E>CAP → the file on disk has CAP hit lines + marker | executed pre-fix: **800 hit lines, 0 markers** at R=2/E=400 (probe D-3) |

### US-B63-D2 / R-TUI-096 — TC-454 .. TC-466

| TC | Verifies (clause) | Asserts | Counterfactual → RED |
|---|---|---|---|
| TC-454 | 096 (a) boundary derivation | `W = floor(sys.get_int_max_str_digits()/log10(16)) + 1` is the smallest width whose `str()` raises (the derivation is itself tested, not assumed) | a hardcoded 3572 |
| TC-455 | 096 (b) modifications, below | `_modifications_lines` at width `W-1` renders the row; the Length cell has exactly `sys.get_int_max_str_digits()` digits | a fix that clamps early and truncates a legal value |
| TC-456 | 096 (b) modifications, at | `_modifications_lines` at width `W` raises nothing | shipped: `ValueError` (executed) |
| TC-457 | 096 (b) checklist twin, below | `_checklist_lines` at width `W-1` renders the row | — |
| TC-458 | 096 (b) checklist twin, at | `_checklist_lines` at width `W` raises nothing | shipped: `ValueError` (executed, probe C-1b) |
| TC-459 | 096 (b) **C-31 derived census** | AST walk of `report_service.py`, `flow_report_service.py`, `diff_report_service.py` for `FormattedValue` with empty `format_spec`, no conversion, over `X.address_end - X.address_start`; assert **every** derived site is covered by a TC in this batch | executed today: the derived set is exactly `{report_service.py:996, report_service.py:1171}` (probe E-1). Adding a third such site later without a TC → RED |
| TC-460 | 096 (c) the guard quotes the API, not a literal | under `sys.set_int_max_str_digits(1000)` the guard fires at the correspondingly smaller width and not before | a literal-3572 guard is GREEN here while the tool crashes (executed: limit 5000 → boundary 4153, probe B-3) |
| TC-461 | 096 (a) **shipped surface**, at | `generate_project_report` at width `W` returns an existing, non-empty path | executed pre-fix: `ValueError`, `reports/ = []` |
| TC-462 | 096 (d) golden neutrality | at width `W-1` and at width 8, `canonical_report_bytes` matches the pre-fix output | a fix that changes the narrow-case rendering |
| TC-463 | 096 (e) fail-closed preserved | with a composition error injected at the last section, `reports/` is empty | an incremental writer leaves a partial file |
| TC-464 | 096 (f) address cell intact | at width `W`, the Address cell renders the full `0x…` hex with no truncation | a fix that shortens the address to dodge the length (hex is exempt — probe B-2) |
| TC-465 | 096 (g) parser unchanged | `_parse_address` (`changes/io.py`, `_ADDRESS_RE = ^0x[0-9A-Fa-f]+$`) still accepts the `W`-width literal | a fix pushed into the parser instead of the renderer would silently narrow the accepted schema |
| TC-466 | 096 (d) ordinary widths | width 8 → the Length cell is the plain decimal, byte-for-byte | any unconditional reformat |

### US-B63-D3 / R-TUI-097 — TC-467 .. TC-479

| TC | Verifies (clause) | Asserts | Counterfactual → RED | CI? |
|---|---|---|---|---|
| TC-467 | 097 (a) convention pinned | `_line_bytes([]) == 0` | `+1` changed | yes |
| TC-468 | 097 (a) | `_line_bytes(["a"]) == 2` — the `+1`-per-line convention, which **0 tests pin today** (probe E-4) | `+1` → `+2` | yes |
| TC-469 | 097 (a) bytes not chars | `_line_bytes(["中文"]) == 7` | a `len(str)` implementation | yes |
| TC-470 | 097 (b) encoder identity | `len(report_bytes(l)) == _line_bytes(l) - 1` over ≥6 arities incl. `[""]`, non-ASCII, 64-line bulk | either side changed unilaterally | yes |
| TC-471 | 097 (b) **the identity's domain** | `report_bytes([]) == b""`, `_line_bytes([]) == 0`, and the −1 identity explicitly does **not** hold at N=0 | shipping the unguarded identity — which is what the transcript proposed (probe A-2) | yes |
| TC-472 | 097 (c) batch-composability | `sum(_line_bytes(b)) == _line_bytes(whole)` over 1-, 2-, 3- and singleton partitions | `len(join)` redefinition: off by 11 on a 12-batch partition (probe G) and **11 bytes under the file** end-to-end (probe F) | yes |
| TC-473 | 097 (d) **C-31 derived census** | derive the accounting-sharing module set by import-graph walk; assert no member's document writer is `write_text`/text-mode `open` | shipped: both members use `write_text` (`:1682`, `:456`) | **yes — RED pre-fix on CI** |
| TC-474 | 097 (d) census anti-vacuity | the derived set is non-empty and contains `flow_report_service` | a walk that silently returns `{}` passes TC-473 vacuously | yes |
| TC-475 | 097 (e) report writer output | written bytes `== report_bytes(lines)`; no `\r` | text-mode writer | ⚠ **vacuous on Linux** |
| TC-476 | 097 (e) on-disk agreement | `path.stat().st_size == budget.used - 1` | executed pre-fix Windows: delta `+72/+90/+270 == N-2` | ⚠ **Windows-only RED** |
| TC-477 | 097 (e) flow writer output | `write_flow_report` file size `== len(compose_flow_report(...).encode())`; no `\r` | text-mode writer at `flow_report_service.py:456` | ⚠ **vacuous on Linux** |
| TC-478 | 097 (f) golden neutrality | the derived observer set passes unchanged, **including `tests/test_flow_report_service.py`** — the observer the Phase-0 M-2 arm recorded as omitted | a fix that changes emitted content | yes |
| TC-479 | 097 (e) **positive control** | a control file written with `newline="\r\n"` **is** detected as containing `\r` by the same helper TC-475/477 use | a broken detector would make TC-475/477 pass for the wrong reason on *every* platform | **yes** |

**TC-478 status: already measured on a `git archive` export of `031ca8d` patched writer-only (both
modules): `39 passed in 1.23s` for `tests/test_flow_report_service.py`.** This closes the gap the
measurement transcript recorded against itself ("I derived the observer set from
`generate_project_report` callers, which omits `tests/test_flow_report_service.py`").

---

## 5. The D3 platform problem — full resolution

**Statement.** `tui-ci` and `snapshot-regen` run `ubuntu-latest`
(`.github/workflows/tui-ci.yml:25,61`). On Linux, `Path.write_text` in text mode translates `"\n"`
to `os.linesep`, which **is** `"\n"`. Therefore on Linux the shipped writer and any fixed writer
produce **byte-identical output**. D3 has no behavioral manifestation on the CI platform. This is
not a gap in the test design; it is a property of the defect.

**Consequence 1 — the obvious assertion is vacuous.** "The written report contains no CR byte" is
GREEN on CI *before* the fix. So is "written bytes equal the LF join". So is
`st_size == budget.used - 1` (executed: the LF-equivalent length is exactly `used - 1` at all three
fixture sizes — probe C-2). **Any purely behavioral assertion about the written file is vacuous on
CI.** No wording rescues it.

**Consequence 2 — the transcript's proposed invariant is not sufficient, and is not even true.**
The transcript proposes `len(LF.join(lines).encode()) == _line_bytes(lines) - 1` on the grounds that
it "holds by construction everywhere". Executed (probe A):

```
case                      N  joined B  _line_bytes  holds
N=0 (empty)               0         0            0  False      <-- the proposal is FALSE here
N=1 ascii                 1         1            2   True
N=1 empty str             1         0            1   True
N=3 non-ascii             3        14           15   True
N=64 bulk                64       629          630   True
```

It is universal for `N >= 1` only. **Adopted with an explicit arity guard**, and the N=0 exception
is itself asserted by TC-471 so the domain lives in a test rather than a comment. The two-sided form
`len(join) + (1 if lines else 0) == _line_bytes(lines)` is universal including N=0 (executed, probe
A-3) and is an acceptable alternative — but it hides the arity split rather than documenting it, so
I recommend the guarded form plus TC-471.

**Consequence 3 — and this is the one nobody has recorded: the derived fix shape is wrong.** The
transcript concludes "the writer and the accounting share ONE encoder so they cannot diverge". I
implemented exactly that in a `git archive` export at a short path — `report_bytes(lines) =
"\n".join(lines).encode("utf-8")`, `_line_bytes = len(report_bytes(...))`, `write_bytes(report_bytes(...))`
— and measured the end-to-end result:

```
 entries  budget.used    on disk   delta    CR?
       2         2495       2506     +11  False
      20         3325       3336     +11  False
     200        11607      11618     +11  False
```

The allocator is now **11 bytes UNDER the file, constant across fixture size** — a *worse*
under-account than the CRLF bug, in the same direction. Cause: `generate_project_report` accounts
the document in ~12 separate `emit()` batches (`report_service.py:1636-1679`), and `len(join)` loses
one byte per batch boundary. The shipped `+1`-per-line form is **batch-composable**; `len(join)` is
not (executed, probe G):

```
shipped  (+1/line): _line_bytes(whole) = 242      naive (len(join)): whole = 241
     1 batches -> 242  composable = True               1 batches -> 241  True
     2 batches -> 242  composable = True               2 batches -> 240  False
     3 batches -> 242  composable = True               3 batches -> 239  False
    12 batches -> 242  composable = True              12 batches -> 230  False
```

**Therefore the fix shape this catalog validates is: keep `_line_bytes`'s `+1`-per-line convention
untouched, introduce `report_bytes()` as the single encoder, and route BOTH accounting-sharing
writers through `write_bytes(report_bytes(...))`.** Verified on a writer-only export:

```
 entries  budget.used    on disk   delta    CR?
       2         2507       2506      -1  False
      20         3337       3336      -1  False
     200        11619      11618      -1  False
```

`delta == -1` exactly, batch-count-independent — i.e. the accounting is **1 byte conservative**
(the safe direction), and the artifact says so rather than claiming exactness. AT-174/TC-472 exist
specifically so the composability property cannot be broken again silently.

**The resolution, stated plainly.**

1. The **load-bearing D3 gate is structural, not behavioral**: AT-172 / TC-473+TC-474 assert, via a
   derived import-graph census, that no accounting-sharing module writes its document in text mode.
   This is **RED pre-fix on every platform including CI**, because `write_text` is in the source on
   `031ca8d` at `report_service.py:1682` and `flow_report_service.py:456`.
2. The **algebraic gates** (AT-173, AT-174 / TC-467..TC-472) never consult the host newline and are
   RED on CI against a wrong `_line_bytes`. They are what stops the regression class, since
   `_line_bytes` has **0 test references today** (executed, probe E-4).
3. The **behavioral gate AT-175 / TC-476 can only go RED on Windows.** It ships anyway, but is
   labelled `platform: windows` in the test docstring and is **not** counted toward CI coverage. Its
   RED evidence is captured as an operator-run transcript on the Windows host and pasted into the
   Phase-4 validation artifact — the pre-fix run is already captured here (probe C-2:
   `+72 / +90 / +270 == N-2`) and the post-fix run is already captured (writer-only export:
   `-1 / -1 / -1`). Phase 4 re-runs both on the merge candidate and pastes them.
4. TC-475 and TC-477 are retained but **explicitly annotated "vacuous on Linux"** in their
   docstrings, and TC-479 is a **positive control** proving the CR detector they rely on can
   actually fail. Without TC-479 those two tests would be indistinguishable from tests that assert
   nothing.
5. **This artifact does not claim CI verifies D3's behavior.** It claims CI verifies D3's
   *structure* and its *arithmetic*, and that D3's *behavior* is verified on Windows by a recorded,
   re-runnable transcript. Any PR text stating otherwise contradicts this section.

---

## 6. Fixture plan

**Reused as-is (no new code):**
- `tests/test_report_service.py` module-local builders — `_applied_entry`, `_summary`, `_check`,
  `_variant_set`, `_issue`, `_fixed_clock` (`tests/test_report_service.py:214-240` and the helpers
  above them). These are already the report suite's canonical shape and produce
  `VariantExecutionResult` objects directly.
- `tests/conftest.py::canonical_report_bytes` (`:970`) for every byte-identity assertion
  (AT-167, TC-462, TC-478). Confirmed by reading it that it undoes CRLF (`:1009`
  `raw.replace(b"\r\n", b"\n")`) — this is why the writer fix is golden-neutral.
- `s19_app/tui/services/report_addendum.py::DeclaredRegion` for D1 regions.

**Explicitly NOT reused, with justification:** `tests/conftest.py`'s `large_s19` / `large_a2l` /
`large_mac` / `large_project` generators are parser-stress fixtures — they produce *files*, not
`VariantExecutionResult` objects, so they cannot reach `_addendum_lines` at all. Using them would
require an execution round-trip that dominates the measurement and hides the cost law.

**New fixture (one), with its size bound stated:**
- `make_addendum_results(regions: int, variants: int, entries: int)` — a deterministic builder
  producing `regions` `DeclaredRegion`s and `variants` `VariantExecutionResult`s each carrying
  `entries` applied entries, all inside every region. **Hard bound: `regions × variants × entries
  <= 8_000` hits**, asserted inside the factory so no future test can widen it by accident.
  Measured cost at that ceiling: **713 223 B peak, 89.2 B/hit** (probe D-1) — i.e. **~0.7 MB**.
  This is 25× below the measurement transcript's own 200 000-hit ceiling and ~4 orders of magnitude
  below the declared-domain fixture the scope ruling says *building it is what crashes*, which is
  **never built by anything in this catalog**.
- D2 needs no fixture builder: one `ChangeSummaryEntry` / one `CheckRunEntry` whose `address_end`
  is `int("F" * W, 16)`. Size: a single ~1.8 KB integer.

**Probe hygiene applied while producing this catalog:** every temp tree was created under
`tempfile.mkdtemp` and deleted in a `finally` (verified `exists=False` in each transcript); both
`git archive` exports were taken at the short root
`C:/Users/jjgh8/AppData/Local/Temp/claude/b63/qa/` and deleted afterward; `.../b63/a` and
`.../b63/b` were never touched; every probe was written to a file and invoked by path.

---

## 7. Gaps / `assumed`

| # | Item | Status |
|---|---|---|
| G-1 | **LLR/HLR numbering.** TCs bind to `R-TUI-09x` + a named clause, not to LLR ids, because the architect is deriving those in parallel against this same registry. Reconcile clause→LLR at Phase 2. | **Deliberate**, to avoid the REV-4 collision |
| G-2 | `MAX_ADDENDUM_HITS_PER_REGION` — the *value* is the architect's call. I recommend 200 to mirror `MAX_REPORT_ISSUES_PER_VARIANT` (`report_service.py:90`), but the AT quotes the constant, never the value. | **`NEW — created in Phase 3`** |
| G-3 | `report_bytes()` — the single encoder. Does not exist on `031ca8d`. | **`NEW — created in Phase 3`** |
| G-4 | **D2's fix shape is not specified by the scope ruling.** AT-171 constrains it (non-empty, distinguishable from `-`, address intact, narrow case byte-identical) but does not choose between "hex fallback past the limit", "`>10^K` marker", or "raise `sys.set_int_max_str_digits`". Choosing it is a Phase-2 decision; raising the limit process-wide would be a global side effect and is flagged as the option most likely to break other consumers. | **Open — architect decision** |
| G-5 | **D1's honest count.** AT-165 requires `≥K`. If Phase 2 chooses to keep scanning (bounding output but not traversal), an exact total becomes knowable and AT-165's assertion must be re-derived — but then D1's *memory* claim (AT-166) is only partly delivered, since the scan still visits R×V×E items even if it stores few. **Bounding output does not bound traversal**; AT-166 keys on *resident* peak, which a streaming producer fixes, and does **not** key on wall time. | **Named, deliberate limit of the AT** |
| G-6 | **Test-execution time for AT-166/TC-450..452.** The grid runs `_addendum_lines` 6× at up to 8 000 hits. Not yet timed under pytest. Marked `slow` so `-m "not slow"` (the documented fast path) skips it. | **`assumed` — verify at Phase 3** |
| G-7 | `tracemalloc` peak ratios are stable across the runs I did (1.98 here vs 1.98–2.01 in the transcript), but the `< 1.5` threshold has **not** been measured against a *fixed* implementation, which does not exist yet. If a fixed implementation lands at ratio 1.4 the threshold is uncomfortably tight. | **`assumed` — re-derive the threshold at Phase 3 against the real fix, per C-39** |
| G-8 | M-2's golden-neutrality evidence (116 passed both arms) covers the **writer-only** patch. It does **not** cover any change to `_line_bytes`. Since §5 concludes `_line_bytes` must **not** change, this is consistent — but if Phase 2 deviates, the neutrality claim must be re-executed. | **Flagged** |
| G-9 | This batch closes none of the twelve unbounded document axes. Per the scope ruling, the PR **must not** claim M-2 closed, and the `> TRUNCATED … (report size cap: N bytes)` marker still asserts a bound the document violates. No AT here asserts otherwise. | **Carried, by design** |

---

## 8. Evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then **or** an equivalent surface/observable/counterfactual triple | ✓ | §3 — every AT names surface · observable · representative/boundary/negative · RED counterfactual. The triple form was chosen over G/W/T because "the counterfactual that turns it RED" is the control this batch is keyed on |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | §4 — every row's "Asserts" column is a predicate over a count, a byte length, or a derived set |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | empty: TC-447, TC-467, TC-471 · boundary: TC-442 (interior), TC-455/456/457/458 (`W-1`/`W`) · invalid: TC-460 (moved limit) · error: TC-463, AT-170 |
| 4 | Regression checklist exists | ✓ | AT-167, TC-448, TC-449, TC-462, TC-465, TC-466, TC-478 |
| 5 | Exit criteria stated | ✓ | §5 items 1–5 for D3; AT-164..171 all-green for D1/D2; plus G-9's prohibition on claiming M-2 |
| 6 | No real PII / secrets / operator firmware | ✓ | every fixture is a synthetic in-memory byte run or a `tests/` generator product; no `examples/` operator image is read |
| 7 | Test-results section left blank unless actually run | ✓ | no TC is marked passing. The only results asserted are **pre-fix probe transcripts** (§3, §5) and one post-fix export run (TC-478: `39 passed in 1.23s`), each labelled with what was patched |
| 8 | **Layer B (black-box):** every output-producing story observed through the SHIPPED surface with boundary + negative evidence | ✓ | D1 → TC-453 + AT-164/165/167 (file on disk; executed pre-fix: 800 hit lines / 0 markers) · D2 → TC-461/462/463 + AT-168/169/170 (executed pre-fix: `ValueError`, `reports/ = []`) · D3 → TC-475/476/477 (executed pre-fix `+72/+90/+270`, post-fix `-1/-1/-1`) |
| 9 | **Bidirectional surface-reachability:** every named input dimension AND every named output observed through the handler | ✓ | inputs R (TC-444/451), V (TC-445/452), E (TC-440-443/450), address width (TC-455-458, TC-461), line-batch partition (TC-472) — all driven; outputs: hit lines + marker (TC-453), report file existence + Length cell + Address cell (TC-461/464), file bytes + size (TC-475/476), flow report file (TC-477). `generate_project_report` is reached from the shipped app at `s19_app/tui/app.py:4031`; `write_flow_report` from `flow_execution_service.py:409` |
| 10 | **No unfilled template** — no angle-bracket placeholders, no unallocated id stub, no empty required cell | ✓ | all 12 ATs and all 40 TCs (`TC-440`..`TC-479`) are specified; the only bracketed tokens are `NEW — created in Phase 3` markers (G-2, G-3) required by C-36 |
| 11 | **C-39:** every threshold executed, transcript pasted | ✓ | D2 boundary `W=3572` derived + executed (§3 D2 preamble, probe B) · D1 ratio 1.98 / 89.2 B-per-hit (§3 AT-166, probe D) · D3 `N-2` = `+72/+90/+270` (§5, probe C-2) · composability 242 vs 230 (§5, probe G) · post-fix `-1` (§5) · N=0 falsification (§5, probe A) |
| 12 | **C-31:** universals' input sets DERIVED, not hand-listed | ✓ | TC-459 (AST walk → `{report_service.py:996, :1171}`, probe E-1) · TC-473/474 (import-graph walk → `{report_service, flow_report_service}`, probe E-2) · writer census (13 writers, probe E-3) · reverse test census (probe E-4) |
| 13 | **C-36:** every literal resolves to a defined constant or is flagged NEW | ✓ | defined: `REPORT_MAX_TOTAL_BYTES=2_097_152` (`report_service.py:122`) · `MAX_REPORT_ISSUES_PER_VARIANT=200` (`:90`) · `REPORT_CELL_CHARS=512` (`:115`) · `REPORT_MAX_REGIONS_PER_VARIANT=128` (`:77`) · `DECLARED_REGION_NAME_MAX=80` (`report_addendum.py:26`) · `FLOW_REPORT_MAX_TOTAL_BYTES` (`flow_report_service.py:80`) · `sys.get_int_max_str_digits()` (stdlib). Flagged NEW: `MAX_ADDENDUM_HITS_PER_REGION`, `report_bytes` |
| 14 | **An AT quotes the CONSTANT, never its value** | ✓ | AT-164 quotes `MAX_ADDENDUM_HITS_PER_REGION`; D2's ATs quote `sys.get_int_max_str_digits()` and derive `W` from it — TC-460 is the test that **fails a literal-3572 implementation**, with the executed proof that the literal moves (limit 5000 → 4153) |
| 15 | **Every guard shown able to fail** | ✓ | every AT/TC row carries a counterfactual; 11 of them were **executed**, not argued (probes A–G). TC-479 is a dedicated positive control for the two assertions that cannot fail on CI |
| 16 | **A predicate tests what its LABEL claims** | ✓ | TC-442 asserts both halves of "at the cap, interior" (count **and** marker-absence) · TC-446 forces the cap across all three hit producers · AT-169 forces the D2 twin · TC-474 stops a vacuous census |
| 17 | Phase-1 constraint: no production source edited | ✓ | `git status --porcelain` on the worktree shows only `.dev-flow/` paths; all patching was done in deleted `git archive` exports under `…/Temp/claude/b63/qa/` |
