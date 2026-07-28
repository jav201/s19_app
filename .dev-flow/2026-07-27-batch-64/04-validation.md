# batch-64 — Phase 4 — Validation

> **Verdict: VALIDATED.** `R-TUI-098` / `HLR-103` / `LLR-103.1…103.6` are realized on this tree.
> Layer A and Layer B both pass, traceability closes in **both** directions with **0 gaps**, and every
> one of the **9 live `AT`s reconciles to exactly one distinct on-disk node driving its whole named
> chain** (C-18 REALIZED, 9/9). Neither `iterate-to-refine` nor `iterate-to-fix` is triggered.
>
> **Four defects are reported, all documentation-side, none gating** (§7): a stale node count in the
> shipped `Validation:` row, a mutant-arm roster in `REQUIREMENTS.md` that lists three arms belonging
> to nodes outside the guard class, one Inc-3 transcript count that does not reproduce, and the fact
> that the ten mutant arms are **not re-runnable from the repo**.

- **Batch:** `2026-07-27-batch-64` · **Branch:** `claude/batch-64-addendum-producer-bound`
- **HEAD:** `22c5ab7` · **Base:** `082ada9` · **Working tree:** clean (`git status --porcelain` → empty)
- **Requirement under validation:** `R-TUI-098` — the declared-region addendum is a bounded,
  order-preserving, self-disclosing producer.
- **Language:** English. **Reviewer:** qa-reviewer (Phase 4).

---

## 0. Provenance of the evidence in this document

Two classes of citation appear below and they are **not** mixed:

| class | meaning | how to re-run |
|---|---|---|
| **CONSUMED** | from the orchestrator's single complete gate-suite run, quoted verbatim | `pytest -q -m "not slow"` (~28 min) — **not re-launched by this phase**, by explicit instruction |
| **EXECUTED HERE** | run by this phase against `22c5ab7`, output pasted | the command in the row |

The gate-suite run, CONSUMED:

```
2233 passed, 2 skipped, 21 deselected, 3 xfailed in 1659.77s (0:27:39)
29 snapshots passed.
exit 0
```

**Independent reconciliation of the `+32` against the batch-63 close baseline of `2201`
(EXECUTED HERE).** The delta is not accepted on assertion; it is derived:

| source | base `082ada9` | HEAD `22c5ab7` | delta |
|---|---|---|---|
| `tests/test_report_addendum_bound.py` | did not exist | **29 collected** | +29 |
| `tests/test_tui_report_seam.py` | 27 test functions | 28 (`AT-200`) | +1 |
| `tests/test_report_field_census.py` | 17 functions / 32 collected | 18 functions / **34 collected** | +2 |
| | | | **+32** |

`2201 + 32 = 2233`. **The suite figure reconciles exactly to the three files this batch touched.**
Commands: `python -m pytest tests/test_report_addendum_bound.py --collect-only -q` → `29 tests
collected`; `git show 082ada9:tests/test_report_field_census.py` / `:tests/test_tui_report_seam.py`
parsed with `ast` for the base counts; `python -m pytest -q tests/test_report_field_census.py` →
`34 passed in 2.05s`.

---

## 1. Layer A — functional, white-box (`TC-NNN` ↔ LLR / HLR)

**Method.** Each `TC` asserts against the mechanism, either through `_addendum_text()` (a thin wrapper
over the real `report_service._addendum_lines`, `tests/test_report_addendum_bound.py:779-784`) or a
direct `_addendum_lines` / `generate_project_report` call. This is the correct layer for
mechanism-only observables — candidate consumption, region ops, direct producer peak — which are
readable only through an injected instrument.

**Result: 19/19 live `TC` ids GREEN.**

| `TC` | parent | collected node (re-runnable citation) | verdict | evidence |
|---|---|---|---|---|
| TC-480 | HLR-103 | `test_tc480_addendum_end_to_end_shape_at_the_boundary` | ✓ | heading + sub-headings + ≤ K hits + ≥ 1 notice, via `_write_report` |
| TC-481 | LLR-103.3 | `test_tc481_below_the_bound_renders_every_hit_and_no_notice` | ✓ | `K-1`: 199 hits, 0 notices |
| TC-482 | LLR-103.3 | `test_tc482_exactly_at_the_bound_renders_k_hits_and_no_notice` | ✓ | `K`: 200 hits, 0 notices |
| TC-483 | LLR-103.3 | `test_tc483_above_the_bound_is_capped_and_line_count_is_bounded` | ✓ | `K+1` and 3000 both ≤ K; addendum 208 lines ≤ bound 607 |
| TC-484 | LLR-103.3 | `test_tc484_empty_and_negative_domain_renders_none_without_notice` | ✓ | `None.` on 3 empty sub-cases; 1-byte region → 1 hit; `issue.address is None` skipped |
| TC-485 | LLR-103.3 | `test_tc485_addendum_is_guarded_by_a_non_empty_declared_region_set` | ✓ | `R = 0` guard, asserted on `inspect.getsource(generate_project_report)` (`:2020-2027`) |
| TC-486 | LLR-103.2 | `test_tc486_membership_is_sound_over_nested_overlapping_regions` | ✓ | `0x5000` inside outer beyond inner end → 1 hit; `0x2000` emitted twice |
| TC-487 | LLR-103.2 | `test_tc487_duplicate_and_equal_start_nested_regions_each_emit` | ✓ | duplicate ×3 → 3 hits; equal-start-nested → 2 |
| TC-488 | LLR-103.1 | `test_tc488_candidate_consumption_is_r_independent_overlapping` | ✓ | `consumed == N` = `900/900` at `R = 1/8/64` |
| TC-489 | LLR-103.1 | `test_tc489_candidate_consumption_is_r_independent_disjoint` | ✓ | `consumed == N` = `300/300` at `R = 1/8/64` |
| TC-490 | LLR-103.5 | `test_tc490_notice_caps_the_variant_list_with_a_plus_n_more_remainder` | ✓ | 8 named + `+32 more` over 40 distinct affected variants, **read from the written file** |
| TC-491 | LLR-103.4 | `test_tc491_golden_capture_harness_is_deterministic` | ✓ | two run roots → identical, and equal to the committed golden |
| TC-492 | LLR-103.6 | `test_tc492_cap_labels_and_notice_format_are_module_constants` | ✓ | four constants present; no bare `200` in the body; `K → 37` green over the `K`-derived nodes |
| TC-493 | LLR-103.3 | `test_tc493_addendum_producer_peak_is_flat_in_the_candidate_count` | ✓ | `peak(E=1000)=19801 peak(E=2000)=19802 ratio=1.0001 ≤ 1.25` |
| TC-494 | LLR-103.4 | `test_tc494_emission_order_is_result_summary_interleaved` | ✓ | `['modification','issue','modification','issue','issue']`, fixture precondition `S ≥ 2` |
| TC-495 | LLR-103.5 | `test_tc495_notice_renders_a_variant_id_exactly_as_a_hit_line_does` | ✓ | notice rendering == hit-line rendering over 5 ids incl. the hostile string |
| TC-497 | R-TUI-098 | `test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers` | ✓ | **EXECUTED HERE**: `1 passed, 28 deselected in 0.24s` |
| TC-498 | LLR-103.1 | `test_tc498_region_ops_equal_r_times_n_under_huge_tiny_geometry` | ✓ | `A == R × N` = `300/2400/19200/76800` at `R = 1/8/64/256`, `N = 300` |
| TC-499 | LLR-103.5 | `test_tc499_report_wide_truncation_is_not_an_addendum_notice` | ✓ | report-wide `> TRUNCATED:` fires; 0 addendum notices |

**Whole-file run, EXECUTED HERE:**

```
$ python -m pytest tests/test_report_addendum_bound.py -q
.............................                                            [100%]
29 passed in 1.23s
```

29 collected nodes = 26 single-node ids + `AT-198`'s three parametrised arms (§3 note).

**LLR coverage — every LLR has ≥ 1 passing TC.** `LLR-103.1` → TC-488/489/498 · `LLR-103.2` →
TC-486/487 · `LLR-103.3` → TC-481/482/483/484/485/493 · `LLR-103.4` → TC-491/494 · `LLR-103.5` →
TC-490/495/499 · `LLR-103.6` → TC-492 · `HLR-103` → TC-480 · `R-TUI-098` → TC-497. **0 gaps.**

---

## 2. Layer B — behavioral, black-box (`AT-NNN` ↔ user story, through the shipped surface)

**Method, verified rather than assumed.** Every `AT` in `tests/test_report_addendum_bound.py` reaches
the shipped surface through `_write_report()` (`:723-774`), which calls the real
`generate_project_report(...)` and then `path.read_text(encoding="utf-8")` — the **written report
file**, not a service return value. `AT-200` drives the **TUI seam** and compares the on-disk bytes to
the `ReportViewerScreen`'s rendered text. Verified by AST walk over every `test_` function in the file
(EXECUTED HERE) and by reading `tests/test_tui_report_seam.py:486-515`.

**Result: 9/9 live `AT` ids GREEN, all with a black-box deliverable observation. No story lacks one.**

| US | Observable outcome | Shipped surface driven | `AT` | collected node | verdict + observed |
|----|---|---|---|---|---|
| US-B64-1 | memory attributable to the addendum stops growing with the candidate count | `generate_project_report` (both configurations) **+ a written-file co-assertion** | **AT-194** | `test_at194_addendum_marginal_resident_cost_flat_in_candidate_count` | ✓ ratio `1.00` ≤ `1.30`; `delta(2000)=52296 delta(4000)=52247` |
| US-B64-1 | an untruncated report is unchanged, byte for byte | `generate_project_report` → file → `canonical_report_bytes` | **AT-196** | `test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden` | ✓ **6/6 shapes byte-identical, 0 differing bytes** |
| US-B64-2 | the operator can name what was cut — class, count, **exactly** which variants | `generate_project_report` → file | **AT-197** | `test_at197_notice_names_cut_class_dropped_count_and_exact_variant_set` | ✓ class `change-file issue`, dropped `2`, variants **== {v2, v3}** (set equality) |
| US-B64-2 | no notice when nothing was cut; exactly one when something was | `generate_project_report` → file | **AT-198** | `test_at198_notice_presence_keys_on_the_class_total[le_K \| interior \| K_plus_1]` | ✓ 199→0 · 200→0 (+200 hit lines) · 201→exactly 1 |
| US-B64-2 | a notice cannot be forged from document-derived text | `generate_project_report` → file | **AT-199** | `test_at199_document_derived_text_cannot_forge_a_notice` | ✓ 1 notice not 2; injected `>` escaped; `\r\n\t` collapsed |
| US-B64-2 | the notice is **delivered** — file **and** the screen the operator reads | `generate_project_report` → file **and** `ReportViewerScreen` | **AT-200** | `tests/test_tui_report_seam.py::test_at200_truncation_notice_reaches_the_file_and_the_viewer` | ✓ **EXECUTED HERE**: `1 passed in 7.99s`; `in_viewer == in_file`, `len(in_file) >= 1` |
| US-B64-2 | a class that lost nothing is never named | `generate_project_report` → file | **AT-201** | `test_at201_a_class_that_lost_nothing_is_never_named` | ✓ named classes == cut classes |
| US-B64-2 | a variant that lost nothing is never named | `generate_project_report` → file | **AT-202** | `test_at202_a_variant_that_lost_nothing_is_never_named` | ✓ named variants == variants with ≥ 1 dropped hit |
| US-B64-2 | the notice tells the operator WHICH region lost evidence | `generate_project_report` → file, `R ≥ 2` | **AT-203** | `test_at203_notice_sits_under_the_flooded_regions_subsection` | ✓ under the flooded `### `, absent from the quiet one |

### 2.1 The deliverable, observed on disk rather than described

The strongest Layer-B artefact is the committed golden, and it is a **shipped-surface deliverable**:
`tests/goldens/batch64/addendum-below-bound.md` is six complete reports produced by
`generate_project_report` and canonicalized. **EXECUTED HERE**, read straight out of the committed
bytes:

```
### outer zone (0x1000-0x9000)
- modification @ 0x2000 (variant variant\_a)
- modification @ 0x3000 (variant variant\_a)
- issue [CHG-COLLISION] @ 0x2010 (variant variant\_a)
- issue [CHG \> TRUNCATED] @ 0x2011 (variant variant\_a)
- modification @ 0x5000 (variant variant\_a)
- issue [CHG-SYNTAX] @ 0x1800 (variant variant\_a)
- issue [CHK-FAIL] @ 0x2000 (variant variant\_a)
...
### empty zone (0xF000-0xF0FF)
None.
```

Six things this **single on-disk artefact** proves black-box, each of which the spec elsewhere asserts
only white-box:

1. **`LLR-103.2`'s nested-overlap soundness reaches the file.** `0x1800` and `0x2000` — §2.6's two
   named lost hits — are present under `outer zone`. The raw `range_index` primitive answers `False`
   for `0x5000` on the uncoalesced set (§11.1 subject check); the shipped addendum emits it.
2. **The empty-domain `None.`** is rendered in the shipped document (3 occurrences across the shapes),
   so `TC-484`'s observable is not white-box-only.
3. **The 1-byte inclusive-edge region** (`edge zone (0x3000-0x3000)`) is exercised through the surface.
4. **`md_safe` escaping of hostile file-derived text**: `variant\_a` (15×), `v-2\.1`, and the injected
   issue code `CHG \> TRUNCATED` (6×) — the `AT-199` forgery defense, visible in the deliverable.
5. **Emission order is interleaved per summary**, not per class — `mod, mod, issue, issue, mod, issue,
   issue` — which is precisely the sequence `FIX-B` (per-class concatenation) destroys.
6. **`TC-499`'s scope predicate is corroborated by the golden itself**: exactly **one** line begins
   `> TRUNCATED:` in the whole file, and it is the pre-existing `:1134` declaration-error emitter
   (`> TRUNCATED: 200 of 400 declaration errors omitted (cap: 200 issues per variant).`) — **zero**
   addendum notices below the bound.

Re-run: `python -m pytest tests/test_report_addendum_bound.py -q -k "at196 or tc491"`; the raw
inspection is `tests/goldens/batch64/addendum-below-bound.md:2802` for the `> TRUNCATED:` line.

---

## 3. C-18 spec-AT realization gate — per `AT`

**Rule applied:** every `AT-NNN` in §6.2 must reconcile to **exactly one distinct on-disk node driving
the whole named chain**. An `AT` satisfied only in parts is UNREALIZED and blocks.

| `AT` | distinct nodes | drives the whole named chain in ONE node? | **REALIZED** |
|---|---|---|---|
| AT-194 | 1 | yes — fixture → `generate_project_report` ×4 → `tracemalloc` delta **and** `_write_report` deliverable co-assertion (`:1336-1339`) in the same node | ✓ |
| AT-196 | 1 | yes — all 6 shapes generated and compared inside the one node | ✓ |
| AT-197 | 1 | yes — the `(class, dropped-count, variant-set)` **triple** is asserted in one node, not split | ✓ |
| AT-198 | 1 function / **3 parametrised arms** | yes — **each arm independently drives fixture → file → assert**; the chain is not split across arms | ✓ (see note) |
| AT-199 | 1 | yes | ✓ |
| AT-200 | 1 | yes — **both** halves of the delivery claim (`in_file` and `in_viewer == in_file`) in one node | ✓ |
| AT-201 | 1 | yes | ✓ |
| AT-202 | 1 | yes | ✓ |
| AT-203 | 1 | yes — flooded-region presence **and** quiet-region absence in one node | ✓ |

**Result: 9/9 REALIZED. 0 UNREALIZED. 0 satisfied-in-parts.**

**Note on `AT-198`.** Three collected nodes for one id is the one deviation from "exactly one node",
and it is **declared in writing in advance** (§11.1 note 2: one pytest node reports one verdict, and
the three arms carry three different Inc-1 verdicts — GREEN / GREEN / RED). The defect C-18 exists to
catch is an `AT` whose named chain is **split** so that no single node drives it end to end. That is
not the case here: each arm builds its own fixture, calls `generate_project_report`, reads the file,
and asserts the complete predicate for its boundary. **Ruled REALIZED**, with the parametrisation
recorded rather than waived.

### 3.1 Retired ids — `AT-195` and `TC-496`

Both are RETIRED IN PLACE and **bind nothing live** (EXECUTED HERE):

```
$ grep -rn "AT-195" tests/ s19_app/ --include=*.py   -> no matches (exit 1)
$ grep -rn "TC-496" tests/ s19_app/ --include=*.py   -> no matches (exit 1)
$ grep -n "AT-195\|TC-496" REQUIREMENTS.md
4986:  `AT-195` and `TC-496` are **retired ids and are not reused**: ...
4987:  black-box id and was withdrawn; `TC-496` was file-observed under a white-box id and was promoted to
```

**No traceability row depends on either.** `REQUIREMENTS.md`'s `AT-194…AT-203` / `TC-480…TC-499`
mapping table (`REQUIREMENTS.md:4964-4985`) contains **no row** for `AT-195` or `TC-496`; the only
mentions are the retirement sentence itself, which is the intended grep landing site. The observables
survive under live ids: candidate consumption → `TC-488`/`TC-489`/`TC-498`;
`OBS-notice-reaches-the-file` → **`AT-200`**, which is a real collected node.
**✓ CONFIRMED — retired, not reused, nothing orphaned.**

---

## 4. Bidirectional surface-reachability matrix

**Rule applied:** every named **input dimension** AND every named **output / deliverable** must be
exercised or observed **through the shipped surface** — not only through the service API. A dimension
reachable only via `_addendum_lines` is a white-box-only dimension and is called out as such.

### 4.1 Inputs → surface

| named input dimension | exercised through the shipped surface? | node / artefact |
|---|---|---|
| region count `R` (0, 1, 2, 3, 4) | ✓ | `TC-485` (`R = 0`, real `generate_project_report`) · `AT-203` (`R = 2`) · golden shapes `R1V1E1`, `R3V2E5`, `FIXGOLD` (`R = 4`) |
| variant count `V` (1 … 40) | ✓ | golden `V2` shapes · `AT-197` (`v1/v2/v3`) · **`TC-490` at 40 variants, read from the written file** |
| candidate count `E` (0 … 4000) | ✓ | `AT-194` at `E = 2000 / 4000` through `generate_project_report` · `AT-198` arms at class total `K-1 / K / K+1` |
| **nested / overlapping** regions | ✓ | golden `FIXGOLD` shape: `outer (0x1000-0x9000) ⊃ inner (0x2000-0x2010)`; `0x1800` + `0x2000` present in the file |
| duplicate / equal-start-nested regions | **white-box only** (`TC-487`) | see §7 gap G-1 — *non-gating; the shipped emission count is a preservation property already pinned byte-for-byte by `AT-196`* |
| 1-byte inclusive-edge region | ✓ | golden `edge zone (0x3000-0x3000)` |
| **empty region / `N = 0`** | ✓ | golden `empty zone (0xF000-0xF0FF)` → `None.` in the shipped document |
| `issue.address is None` | ✓ | golden `FIXGOLD` plants `CHG-NULL` with `address=None`; the shipped document skips it |
| hostile, markdown-escapable ids and codes | ✓ | golden `variant\_a`, `v-2\.1`, `CHG \> TRUNCATED` · `AT-199` · census `PLANTED("notice_variant")` rendered through markdown-it |
| affected variants **above** `ADDENDUM_NOTICE_VARIANTS_MAX` | ✓ | `TC-490` — `+32 more` over 40, via `_write_report` |
| a competing report-wide `> TRUNCATED:` emitter | ✓ | `TC-499` (via `_write_report`) **and** the golden's line `:2802` |
| operator-typed region text (TUI entry path) | ✓ | `AT-200` types the region into the report dialog and drives the worker |

### 4.2 Outputs / deliverables → observation

| named output / deliverable | observed through the shipped surface? | node / artefact |
|---|---|---|
| the **written report file** exists and is non-empty | ✓ | `AT-194`'s §3 Deliverable co-assertion (`path.is_file() and text.strip()`) |
| byte identity below the bound | ✓ | `AT-196` — 6/6 shapes vs the committed golden, 0 differing bytes |
| addendum heading + per-region `### ` sub-headings | ✓ | `TC-480` (via `_write_report`) · golden (6 headings, 106 `### `) |
| hit lines with `(variant <id>)` attribution | ✓ | golden, verbatim |
| `None.` for a region with no hits | ✓ | golden (3×) |
| the notice: **cut class** | ✓ | `AT-197` · `AT-201` |
| the notice: **dropped count** | ✓ | `AT-197` |
| the notice: **exact variant set** (no over-naming) | ✓ | `AT-197` (set equality) · `AT-202` |
| the notice: `+N more` remainder | ✓ | `TC-490`, read from the file |
| the notice: **region placement** | ✓ | `AT-203` |
| the notice: **delivered to the operator's screen** | ✓ | `AT-200` (`in_viewer == in_file`) |
| the notice is **inert at the reader**, not merely escaped at the writer | ✓ | `tests/test_report_field_census.py` `PLANTED("notice_variant")` under `AT-157` / `AT-158` — markdown-it |
| notice **absent** when nothing was cut | ✓ | `AT-198[le_K]`, `AT-198[interior]` · golden (0 addendum notices) |
| addendum line-count bound | **white-box only** (`TC-483`) | see §7 gap G-2 — *non-gating* |
| candidate consumption / region ops / producer peak | **white-box by design** (`TC-488/489/493/498`) | §6.1 assigns mechanism-only observables to Layer A; this is correct, not a gap |

**Matrix result: 12/13 input dimensions and 13/15 output rows surface-reachable.** The three
white-box-only rows are (i) three mechanism-only instruments that §6.1 **requires** to be Layer A, and
(ii) two preservation properties (`TC-483`'s line-count bound, `TC-487`'s duplicate-region emission
count) whose *document-level* consequence is already pinned byte-for-byte by `AT-196`. **No named
deliverable is unobserved. No blocker.**

---

## 5. The four brief-specified checks

### 5.1 `AT-195` / `TC-496` — RETIRED, unreused, nothing depends on them

**✓ CONFIRMED.** Evidence in §3.1. Both greps return no match in `tests/` and `s19_app/`; neither
appears as a row in the shipped traceability table; the observables live under `TC-488`/`TC-489`/
`TC-498` and `AT-200` respectively.

### 5.2 The eleven GREEN regression guards and their Inc-2 mutant arms

**✓ CONFIRMED, with one roster imprecision reported (F-2, §7).**

Eleven live ids were GREEN at Inc-1 (twelve §11.1 rows — `AT-198` occupies two of them). Each carries
a named arm driven RED **against the implemented producer**, except `TC-485`, declared in writing as a
pure guard over unchanged code:

| Inc-1 GREEN guard | Inc-2 arm(s) driven RED | pasted observation (`increment-002.md` §4.2) |
|---|---|---|
| `AT-196` | `FIX-B`, `FIX-E`, `FIX-E(b)`, `FIX-G` | `R3V2E5` drifted at an unchanged 8625 bytes; `FIXGOLD` 5064 vs golden 5260 |
| `AT-198[le_K]`, `AT-198[interior]` | `FIX-G` | a notice for every class |
| `TC-481` | `FIX-C`, `FIX-G` | `FIX-C`: 197 of 199 hits rendered |
| `TC-482` | `FIX-G` | — |
| `TC-484` | **`FIX-NONE`** *(first execution ever)* | `an empty region must render an explicit 'None.'` |
| `TC-485` | **none — declared pure guard, in writing** | §11.1 row; `:2020-2027` asserts on unchanged source |
| `TC-486` | `FIX-E`, `FIX-E(b)` | the `0x5000` candidate reported `[]` |
| `TC-487` | **`FIX-E(b)`** | three identical regions collapse to one |
| `TC-491` | `FIX-B`, `FIX-E`, `FIX-G` | — |
| `TC-494` | `FIX-B` | observed `['modification','modification','issue','issue','issue']`, first diff at position 1 |
| `TC-499` | **`FIX-SCOPE`** *(first execution ever)* | counts the `:1134` emitter as an addendum notice |

**The two knowingly-open arms were closed.** `FIX-NONE` and `FIX-SCOPE` were specified at Phase 2 and
never executed by any lane (§11.1 note 1, C-39). Both were built and driven RED at Inc-2. `FIX-SCOPE`
additionally **read GREEN on its first build and that was reported rather than accepted**
(`increment-002.md:220-226`) — the arm was rebuilt to the coarser predicate §11.1 actually specifies.
That is the correct handling of a mutant that passes for the wrong reason.

**A spec defect was found and reported, not worked around.** §11.1 assigned `TC-487` the arm `FIX-E`;
executed, `FIX-E` is **GREEN** there (both sub-fixtures survive an uncoalesced bisect by accident).
Inc-2 changed neither the test nor the spec, built the arm that does bite (`FIX-E(b)`), and Inc-3
recorded it as amendment **A-43**. `TC-486`'s `FIX-E` assignment is correct and stands.

**Roster reconciliation against `REQUIREMENTS.md`.** The guards' arms are **seven** distinct mutants:
`FIX-B`, `FIX-C`, `FIX-E`, `FIX-E(b)`, `FIX-G`, `FIX-NONE`, `FIX-SCOPE`. `REQUIREMENTS.md:4989-4996`
lists **ten**, adding `FIX-H`, `FIX-I` and `FIX-A2` — which are real, executed arms, but belong to
`AT-202`, `AT-203` and `AT-197`/`TC-488`, all of which were **genuinely RED at Inc-1** and are not in
the guard class. See **F-2**.

### 5.3 The six non-claims — accuracy against the code, and `TC-497`

**`TC-497` passes against the text as shipped (EXECUTED HERE):**

```
$ python -m pytest tests/test_report_addendum_bound.py -q -k tc497
1 passed, 28 deselected in 0.24s
```

**Independent count of the seven greped figures in the shipped `REQUIREMENTS.md` (EXECUTED HERE):**

```
  3  '988 B/entry'          (2 inside the R-TUI-098 section, 1 in the §0/BLUF-style lead-in)
  1  '\xd71.68'
  1  '\xd71.81'
  1  '\xd71.94'
  1  '19200 → 300'
  2  '500 → 128000'
  2  '+N more'
non-claim letters present: ['a', 'b', 'c', 'd', 'e', 'f']
exotic whitespace (U+00A0/202F/2009/2007/2060/FEFF) in the section: []
```

The narrow-space hazard does **not** obtain — independently re-verified, not taken from the packet.

**Accuracy of each non-claim against the shipped code:**

| non-claim | what it says | verified against | verdict |
|---|---|---|---|
| **(a)** memory axis NOT closed; `_modifications_lines` / `_checklist_lines` uncapped at **988 B/entry**, ~11× the addendum's 86.5–93.9 B/hit | both functions | ✓ **ACCURATE.** Read `report_service.py:1031-1120` and `:1203-1290` — both iterate all entries with only `report_filter` skipping; **no cap constant, no slice**. The `988` and `86.5–93.9` are Phase-1/2 measurements (disclosure figures), not re-executed here |
| **(b)** traversal below one pass not claimed; per-class early exit **refused on purpose** | `_addendum_lines` Data Flow | ✓ **ACCURATE.** `report_service.py:1951-1953`: *"Traversal is NOT terminated on saturation. A run that stopped looking could not report the dropped count or the affected variants"* — the code's own contract, and `FIX-A2` RED on `TC-488`/`AT-197` proves the alternative is detectable |
| **(c)** resident cost **not** independent of `R` — `O(R × 3K)`, `R` uncapped | the implementation shape | ✓ **ACCURATE.** One `_AddendumRegionHits` per region, each admitting up to `MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION` per class over 3 classes; **no `MAX_DECLARED_REGIONS` exists** (grep: only `REPORT_MAX_REGIONS_PER_VARIANT = 128`, a different axis) |
| **(d)** eviction **DISCLOSED via the notice, NOT prevented**; the evidence survives elsewhere under `MAX_REPORT_ISSUES_PER_VARIANT = 200` | `report_service.py:96, :1151-1153, :1195` | ✓ **ACCURATE.** The 200-cap and its own `> TRUNCATED:` emitter are exactly where the non-claim says. The genuinely-lost case (same variant past both caps, neither notice naming a severity) is stated, not hidden |
| **(e)** the `R` multiplier is **RELOCATED, not removed** — `500 → 128000` at `R = 1/8/64/256` | `TC-498` | ✓ **ACCURATE, and re-derivable.** `TC-498` pins the *law* `A == R × N`, executed at `N = 300` → `300/2400/19200/76800`. The requirement's `128000` is `256 × 500`, i.e. the same law at `N = 500`. The figure is a **carried** measurement, but it is derived from a law the shipped suite asserts — not a copied constant |
| **(f)** the notice does **not** name all affected variants above `ADDENDUM_NOTICE_VARIANTS_MAX = 8` | `report_service.py:129, :1849` | ✓ **ACCURATE.** `if len(self.named[hit_class]) < ADDENDUM_NOTICE_VARIANTS_MAX` is the cut; `TC-490` observes `8 named + '+32 more'` over 40 in the written file |
| **B-3(b) reduced `R×V×E → V×E`, not eliminated** | Statement + `TC-488`/`TC-489` | ✓ **ACCURATE.** `consumed == N` at every `R` proves the `R` factor is gone from candidate consumption; the surviving `V×E` single pass is stated and is exactly what non-claim (b) refuses to remove |

**No non-claim over-states what the code does. One under-states nothing but is under-guarded:**
non-claim (c)'s figures `≈ 11.6 kB/region` and `≈ 20 kB/region`, and (a)'s `86.5–93.9 B/hit`, are
**not** in `_RESIDUAL_FIGURES` and are therefore not protected by `TC-497` against silent decay.
Inc-3 already records this class of exposure as its own Finding 2 (*"`TC-497` is only as good as the
list it greps, and the list is hand-maintained"*), so it is a **disclosed** residual, not a new one.

### 5.4 The two Inc-3 reporting corrections

**Both landed. ✓ CONFIRMED (EXECUTED HERE, `REQUIREMENTS.md` read at `22c5ab7`).**

**(a) The `Status:` line no longer claims the six residuals are already carried.**
`REQUIREMENTS.md:4997-4999` reads only *"Added in batch `2026-07-27-batch-64` … Frozen-engine diff = 0;
`tests/goldens/` unchanged"* — **no backlog claim**. A separate bullet at `:5000-5012` states it
correctly: non-claim (a) *"was already a `.dev-flow/BACKLOG-CODE.md` item before this batch"*, and the
remaining six are *"**stated here and OWED to `BACKLOG-CODE.md`** as this batch's mandatory Lane-A
close step; until that reconciliation lands they are recorded in this entry and in
`01-requirements.md` §10, and nowhere else."* This is the accurate statement of an **open obligation**,
and it matches `increment-003.md` §6 item 1, which stops at the boundary rather than absorbing it.

**(b) The `Code:` row lists BOTH production files.** `REQUIREMENTS.md:4944-4955`:
`s19_app/tui/services/report_service.py` (constants + the six new symbols + the rewritten
`_addendum_lines`, **line numbers deliberately omitted** with the batch-63 staleness reason given) and
`s19_app/tui/services/report_addendum.py` — *"docstring only: `DeclaredRegion.contains` is no longer
the addendum's membership path but remains the oracle its tests compare against."*
Cross-checked against the real diff (EXECUTED HERE):

```
$ git diff --stat 082ada9..HEAD -- s19_app/
 s19_app/tui/services/report_addendum.py |   7 +-
 s19_app/tui/services/report_service.py  | 598 +++++++++++++++++++++++++++--
```

Two production files in the diff; two production files in the `Code:` row. This closes the
mis-statement Inc-3 reported in its own §5 Finding 1 (Inc-2's packet claimed the `s19_app/` diff
*"touches `report_service.py` only"*, which is false).

---

## 6. Byte identity, goldens, and the frozen engine

**All EXECUTED HERE at `22c5ab7`.**

| check | command | observed |
|---|---|---|
| byte identity below the bound | `pytest -q tests/test_report_addendum_bound.py -k "at196 or tc491"` (part of the `29 passed` run) | **6/6 shapes byte-identical to the Inc-1 golden, 0 differing bytes** |
| **zero golden re-baselines** | `git status --porcelain tests/goldens/` | **empty** — neither `tests/goldens/batch64/` nor `tests/goldens/batch35/at055b-project-report.md` changed |
| engine-freeze **path** guard | `pytest -q tests/test_engine_unchanged.py` | **`1 passed in 0.07s`** |
| engine-freeze **test-file** guard | `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` | **`6 passed, 168 deselected in 0.49s`** |
| **zero diff over all seven frozen paths** | `git diff --name-only main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py` | **empty** |
| regression subset 2 | `pytest -q tests/test_report_service.py tests/test_report_addendum.py` | **`44 passed in 1.67s`** — the §6.3 baseline, unchanged |
| census file | `pytest -q tests/test_report_field_census.py` | **`34 passed in 2.05s`** |
| `AT-200` seam | `pytest -q tests/test_tui_report_seam.py::test_at200_...` | **`1 passed in 7.99s`** |
| working tree | `git status --porcelain` | **empty** |

**The golden is a C-12 output-then-consume artefact.** It was captured from the **shipped** producer on
`082ada9` at Inc-1, **before** any production code was touched, and the producer was then rewritten to
reproduce it. `range_index.py` is **consumed, never modified** — the new import is a frozen-module
consume, and the guards test by `git diff --name-only`, which the zero-diff row above confirms
directly rather than by argument.

---

## 7. Gaps, findings, and what is NOT validated

### Gaps (non-gating, named rather than absorbed)

**G-1 — duplicate / equal-start-nested region geometry is white-box only.** `TC-487` observes the
`M`-times emission through `_addendum_lines`, not through the written file. **Non-gating:** it is a
*preservation* property, and the document-level consequence of any change to it would break
`AT-196`'s byte identity on a golden shape. It is also the node whose spec-assigned arm was found
wrong and re-derived (A-43), so its falsifiability is now demonstrated rather than assumed.

**G-2 — the addendum's line-count bound is white-box only.** `TC-483` asserts `addendum 208 lines ≤
bound 607` through `_addendum_text`. **Non-gating:** the *behavioural* consequence (≤ K hit lines at
`K+1` and at 3000) is observed through the file by `AT-198[K_plus_1]` and `TC-480`.

**G-3 — three disclosed residual figures are outside `TC-497`'s grep list.** `≈ 11.6 kB/region`,
`≈ 20 kB/region` (non-claim (c)) and `86.5–93.9 B/hit` (non-claim (a)) can decay silently. **Already
disclosed** by `increment-003.md` §5 Finding 2 as the node's known limit; recorded here so the Lane-A
reconciliation can decide whether to extend the list.

### Findings

**F-1 — MINOR, documentation. The shipped `Validation:` row states a stale node count.**
`REQUIREMENTS.md:4956` reads *"`tests/test_report_addendum_bound.py` (28 nodes)"*. Executed:
`python -m pytest tests/test_report_addendum_bound.py --collect-only -q` → **`29 tests collected`**.
`28` was the Inc-1/Inc-2 node set; `TC-497` is the 29th and is authored in the same increment that
wrote this row. `increment-003.md` §4.3 explicitly says *"`29`, not `28`"* for its own run, so the
count was known and the row was not updated. Neither `28` nor `29` equals the file's **live-id** count
either (27 — `AT-200` lives in the seam file, `AT-198` contributes three collected nodes).
**Fix:** one word — `(29 collected nodes)`.

**F-2 — MINOR, documentation. The mutant-arm roster mis-attributes three arms to the guard class.**
`REQUIREMENTS.md:4989-4996` reads *"Eleven of the 28 nodes are regression guards … so **each names a
mutant arm** driven RED against the implemented producer — `FIX-B` …, `FIX-E`/`FIX-E(b)` …, `FIX-G` …,
`FIX-H` …, `FIX-I` …, `FIX-A2` …, `FIX-C` …, `FIX-NONE` and `FIX-SCOPE`."* That is the batch's **whole
ten-arm roster**. The eleven guards' arms are **seven** of them; `FIX-H`, `FIX-I` and `FIX-A2` belong
to `AT-202`, `AT-203` and `AT-197`/`TC-488` — all **genuinely RED at Inc-1** and outside the guard
class. **Nothing is over-claimed** (all ten arms were executed RED, `increment-002.md` §4.2), but a
reader reconstructing the guard→arm binding from `REQUIREMENTS.md` alone gets the wrong map. **Fix:**
split the sentence, or point it at `increment-002.md`'s guard→arm table.

**F-3 — MINOR, evidence. One Inc-3 transcript count does not reproduce.** `increment-003.md` §4.1
pastes `4  '988 B/entry'`; counted here against the shipped `REQUIREMENTS.md` at `22c5ab7` the value
is **3** (2 inside the `R-TUI-098` section, 1 in the lead-in at `:4870`). `REQUIREMENTS.md` is
unmodified in the working tree, so this is a transcript/document mismatch, not drift. **Non-gating:**
`TC-497` asserts **presence**, not count, and it passes. Recorded because a pasted number that does
not reproduce is exactly the class of evidence this batch spent three revisions removing.

**F-4 — MINOR, evidence durability. The ten mutant arms are not re-runnable from the repo.**
`increment-002.md` §3 documents `scratchpad/mutant_plugin.py` as the harness; that path does not exist
on this tree (`ls scratchpad/` → *No such file or directory*) and nothing equivalent is committed. The
arms' REDs are therefore a **one-time pasted transcript** — C-39-compliant, executed, and honestly
reported, but not reproducible by a later reader, and §6.3 makes their reproduction a **gate
condition**. Contrast Inc-3, which made its equivalent control permanent as
`test_head_of_line_guard_detects_a_planted_violation`. **Non-gating for this batch** (the arms were
executed and the transcripts are specific enough to be checkable by re-implementation); flagged as a
process carry.

### Explicitly NOT validated by this phase

1. **The full non-slow suite was not re-run.** The `2233 passed / exit 0` figure is CONSUMED from the
   orchestrator's single run, per explicit instruction, and is reconciled to `2201 + 32` in §0. This
   phase ran targeted subsets only.
2. **The mutant arms were not re-executed** — see F-4. Their verdicts are CONSUMED from
   `increment-002.md` §4.2.
3. **The disclosure measurements** `988 B/entry`, `86.5–93.9 B/hit`, `×1.68 / ×1.81 / ×1.94 / ×1.77`,
   `≈ 11.6 kB/region`, `≈ 20 kB/region` are Phase-1/2 executed figures carried into the shipped
   requirement. This phase verified they are **present, correctly spelled, and directionally correct
   against the code** (§5.3); it did not re-measure them.
4. **`TC-497`'s inspection half carries ONE signature** — the Inc-3 author's (`increment-003.md` §4.4),
   which satisfies "named" and not "independent". **This phase supplies the second, independent
   signature:** reviewer **qa-reviewer (Phase 4)**. Read the whole `R-TUI-098` section as shipped;
   recorded **0** whole-report-peak closure claims and **0** `R`-independence claims on the work axis;
   every independence claim in the Statement and in the mapping table is qualified to *candidate
   consumption*, and the `TC-498` row calls its number *"the §10.7 disclosure, non-claim (e)"* rather
   than a bound. **Concur with Inc-3's finding.**
5. **`.dev-flow/BACKLOG-CODE.md` and `PLAN.md` are NOT written** — `increment-003.md` §6 item 1 stops
   at the ≤ 5 file boundary and says so. **The six residuals are OWED, not carried.** This is an open
   obligation of the batch's own mandatory Lane-A close step; it is correctly disclosed in
   `REQUIREMENTS.md:5000-5012` and is **not** a Phase-4 blocker (nothing is claimed to be carried that
   is not), but the batch **cannot close** until it lands.

---

## 8. Layer-A / Layer-B divergence analysis

**None.** The disposition rule the brief sets is not triggered:

- Layer B does **not** fail while Layer A passes → **no `iterate-to-refine`**. The requirement is not
  wrong: every user story has ≥ 1 black-box node observing its outcome through the written report file
  (US-B64-1: `AT-194`, `AT-196`; US-B64-2: `AT-197`…`AT-203`), each with boundary evidence (`K-1`/`K`/
  `K+1`, `≤ 8` / `> 8` variants) and negative evidence (`AT-201`/`AT-202` over-naming controls,
  `AT-199` forgery, `TC-499` scope).
- Layer B does **not** fail because an LLR is implemented wrong → **no `iterate-to-fix`**. All 19 live
  `TC`s and all 9 live `AT`s are GREEN in one run each, and every Inc-1 expected verdict matched the
  §11.1 table with **no divergence** at Inc-2.

The three divergences that **were** found during the batch were all found and reported by the
increments themselves — two Inc-1 fixture defects (`AT-194`'s warm-up window, `TC-488`'s leaf size:
A-42) and one **spec** defect (`FIX-E` has no detection power on `TC-487`: A-43). None weakened a
predicate; all three are recorded as Before → After amendments in `01-requirements.md` §9d.

---

## 9. QA evidence checklist

Each row carries a re-runnable citation. ✗ items are named, not absorbed.

- [x] **Acceptance criteria use Given/When/Then.** Carried in `01-requirements.md` §6.2's behavioural
      chain as `US → AT → observed outcome (RED → GREEN)`, which is the project's established
      equivalent form; each row states pre-condition (fixture/shape), action (shipped surface driven)
      and observable outcome. `01-requirements.md:96-106`.
- [x] **Test cases have explicit Expected, not vague "works".** Every row of §1 and §2 above carries a
      value or a set (`ratio ≤ 1.30` / `0 differing bytes` / `{v2, v3}` set equality / `A == R × N` /
      `+32 more`). No node asserts "renders correctly".
- [x] **Edge cases include empty, boundary, invalid, error.** Empty: `TC-484`, golden `empty zone`,
      `N = 0`, `R = 0` (`TC-485`), `issue.address is None`. Boundary: `K-1`/`K`/`K+1`/`3000`
      (`TC-481/482/483`, `AT-198` ×3), `V = 8` / `V = 40` (`TC-490`), 1-byte region. Invalid/hostile:
      `AT-199` forgery, `CHG \> TRUNCATED`, `variant\_a`, `v-2\.1`. Error/negative controls: `AT-201`
      (class over-naming), `AT-202` (variant over-naming), `TC-499` (scope confusion).
- [x] **Regression checklist exists and was executed per subset, not merged.** §6 table: subset 2
      `44 passed`; census `34 passed`; both frozen guards; goldens unchanged; full suite CONSUMED and
      reconciled in §0.
- [x] **Exit criteria stated.** §10.
- [x] **No real PII / secrets.** Every fixture is a synthetic in-memory object graph under `tmp_path`;
      `canonical_report_bytes` runs `_assert_no_host_path_residue` (`test_report_addendum_bound.py:1409`);
      the committed golden was scanned by that same canonicaliser; `git status --porcelain` empty.
- [x] **Test results filled by execution.** Every ✓ in §1/§2/§6 traces to a pasted command output,
      labelled CONSUMED or EXECUTED HERE per §0. Nothing is filled from `01-requirements.md`'s numbers.
- [x] **Layer B (black-box):** every output-producing story's deliverable is observed through the
      SHIPPED surface. Verified by AST walk, not by docstring: all `AT`s reach the file via
      `_write_report` → `generate_project_report` → `path.read_text` (`:723-774`); `AT-200` reaches the
      `ReportViewerScreen`. Boundary + negative evidence per §2 and the checklist row above.
- [x] **Bidirectional surface-reachability:** §4. 12/13 input dimensions and 13/15 output rows
      surface-reachable; the exceptions are three mechanism-only instruments that §6.1 **requires** to
      be Layer A, plus G-1 and G-2, both named and both non-gating.
- [x] **No unfilled template.** This artifact contains no `<...>`, no `TC-NNN` placeholder, and no
      empty required row. Every id in it is a real collected node reconciled to disk.
- [x] **C-18 realization applied per `AT`.** §3 — 9/9 REALIZED, `AT-198`'s three-arm parametrisation
      ruled REALIZED with its declaration cited.
- [x] **Every provisional id reconciled to a real collected node name.** §1 and §2 tables; retired ids
      confirmed binding nothing (§3.1).

---

## 10. Exit criteria and verdict

| criterion (`01-requirements.md` §6.3) | met? | evidence |
|---|---|---|
| every LLR covered by ≥ 1 passing TC | ✓ | §1 |
| every US by ≥ 1 passing AT observing the outcome through the **written report file**, with boundary + negative evidence | ✓ | §2 |
| every AT whose observable the pre-fix producer can exhibit shown RED before the fix, per its **threshold family** | ✓ | `increment-002.md` §4.1 — 13 RED → GREEN, all 13 matched §11.1 |
| the eleven Inc-1 GREEN regression guards each carry a named Inc-2 mutant arm driven RED against the **implemented** producer (`TC-485` the declared exception) | ✓ | §5.2 |
| regression set green **per subset**, not merged | ✓ | §6 |
| `tests/goldens/` unchanged | ✓ | `git status --porcelain tests/goldens/` → empty |
| both frozen guards pass; zero diff over all seven frozen paths | ✓ | §6 |
| full non-slow suite green | ✓ | CONSUMED: `2233 passed … exit 0`; reconciled `2201 + 32` in §0 |
| no requirement without a validation method | ✓ | `R-TUI-098` → `TC-497` + the `AT`/`TC` mapping table |
| `TC-497`'s 7-string grep passes; judgement half signed by a named reviewer | ✓ | §5.3; **second, independent signature supplied in §7 item 4** |

### VERDICT: **VALIDATED**

`R-TUI-098` is realized. Layer A (19/19 `TC`) and Layer B (9/9 `AT`) both pass. Traceability closes in
both directions with **0 gaps**: every live `AT` has a US and a distinct on-disk node; every live `TC`
has a parent LLR/HLR; every `LLR-103.1…103.6` has ≥ 1 passing TC; every named input dimension and every
named deliverable is exercised or observed, with three white-box-only rows named and justified. C-18
realization is **9/9**. The two retired ids bind nothing. Byte identity holds below the bound with
**zero** golden re-baselines, and the frozen engine shows a **zero diff** across all seven paths.

**Neither `iterate-to-refine` nor `iterate-to-fix` is triggered.**

**Conditions on close — one is mandatory:**

1. **BLOCKING FOR BATCH CLOSE (not for Phase 4): the Lane-A backlog reconciliation is OWED.**
   `.dev-flow/BACKLOG-CODE.md` must gain the six carries — §10.3, §10.5, §10.7, §10.8, §10.9, §12 X-8 —
   each with its number, plus D1 marked closed with its residuals restated and F2/OB-4 left explicitly
   open. `increment-003.md` §6 item 1 stopped at the file cap and said so; `REQUIREMENTS.md:5000-5012`
   states the obligation accurately. **The requirement's own text is honest about this; the work is
   simply not done.** Authorize as Inc-4.
2. **Recommended before merge (documentation only, ~3 lines):** F-1 (`28 nodes` → `29 collected
   nodes`) and F-2 (split the guard→arm roster sentence). Both are one-line edits to `REQUIREMENTS.md`
   and neither touches a predicate, a test, or production code.
3. **Process carry:** F-4 — the mutant harness is not committed, so a gate condition of §6.3 is not
   reproducible from the repo. Worth a `BACKLOG-PROCESS.md` item; not this batch's to fix.

---

*Phase 4 executed 2026-07-27 against `22c5ab7` by qa-reviewer. Targeted subsets EXECUTED HERE; the
full-suite figure CONSUMED from the orchestrator's single run and independently reconciled.*
