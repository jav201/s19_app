# batch-63 — QA catalog (validation strategy)

> **Phase 1, QA lane.** Validation method per requirement · Layer B (`AT-NNN`, black-box through
> the shipped surface) · Layer A (`TC-NNN`, white-box per LLR) · boundary + negative matrix per cap.
>
> **Everything numeric below was executed on this tree** (branch `claude/batch-63-report-table-caps`
> @ `031ca8d`, Python 3.14.4). Report generation ran into `tempfile.mkdtemp()` roots only — nothing
> was written into the worktree a reviewer is reading (PLAN §6 risk 5). Probe scripts live in the
> session scratchpad, not in the repo.
>
> **REV 2 (amendment) — 2026-07-26.** Extended for the two accepted scope amendments **A-1**
> (byte-run bound on `_format_bytes`) and **A-2** (`_declaration_error_lines` registers no
> truncation-appendix note), for the four-mechanism appendix-coexistence gap, and re-parameterized
> on the cap constants ahead of the architect's cap re-derivation. All REV-2 content is marked
> **[A-1]**, **[A-2]**, **[COEX]** or **[PARAM]**; every changed REV-1 statement carries an explicit
> **Before → After**. §10 is the new amendment section and carries the measurements the rest of the
> document now cites. **Two corrections to statements handed to me are recorded in §10.0 — read
> those first: one figure attributed to me is not mine, and one REV-1 figure of my own is now
> superseded.**

---

## 0. ID reservations — VERIFIED on disk, not inherited

| series | highest consumed | derivation | this batch reserves (**REV 2 — final**) |
|---|---:|---|---|
| `AT-` | **163** | repo-wide scan of every `.py`/`.md`: `AT-163` at `tests/test_report_symbol_escape.py:24` + `REQUIREMENTS.md:4794` (batch-62). No `AT-164` anywhere. | **AT-164 … AT-175** (12 nodes) |
| `TC-` | **398** | same scan; batch-62 ended at `TC-398`. | **TC-399 … TC-410** (12 nodes) |
| `R-TUI-` | **078** (withdrawn) | `REQUIREMENTS.md:4770-4804`. `R-TUI-079` is free. | **R-TUI-079** (row caps) · **R-TUI-080** (byte-run bound, A-1) · **R-TUI-081** (appendix completeness, A-2) |

The brief's "start at AT-164" is **confirmed correct** — but it was verified, not assumed.

> **Before → After (id reservations).**
> **Before (REV 1):** AT-164…AT-171 (8) · TC-399…TC-405 (7) · `R-TUI-079` only. Ledger `A = 15`.
> **After (REV 2):** AT-164…**AT-175** (12) · TC-399…**TC-410** (12) · `R-TUI-079` **+ R-TUI-080
> + R-TUI-081**. Ledger **`A = 24`**, `D = 0`.
> **Final ranges to hand the implementer: `AT-164`–`AT-175`, `TC-399`–`TC-410`.**
> AT-172…AT-175 and TC-406…TC-410 are new in REV 2; **AT-171 is amended in place, not renumbered**,
> because it names the same chain ("one variant at cap, worst case, stays inside budget") — minting
> a second node for it would be two nodes claiming one outcome (C-18).

**Frozen test files — live list read from source, not from the brief.**
`tests/test_tui_directionb.py:5457-5468` defines `_ENGINE_TEST_FILES`:
`test_core_srecord_validation.py`, `test_hexfile.py`, `test_range_index.py`, `test_validation_a2l.py`,
`test_validation_engine.py`, `test_validation_mac.py`, `test_tui_a2l.py`, `test_tui_mac.py`,
`test_color_policy_round_trip.py` — 9 files, matching the brief exactly. **None of them is a report
test**, so nothing in this batch is blocked by the freeze.
`_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120` and `test_tui_directionb.py:5442`) likewise
contains no `services/` path — `report_service.py` is freely editable.

**Test home for this batch:** a new NON-frozen file **`tests/test_report_table_caps.py`**
(confirmed absent today). Rationale: it mirrors batch-62's `tests/test_report_symbol_escape.py`
pattern, keeps `tests/test_report_service.py` (1 400+ lines, 12 LLR lanes) from absorbing another
concern, and gives the reviewer one file to read for the whole batch. TCs that must monkeypatch
`report_service` module globals live in the same file.

---

## 1. Requirements → validation method

Phase 1 has not locked the requirement text yet; the ids below are the QA lane's **proposal** to it.
`shall` wording is Phase 1's to write — this table states only *how each one gets validated*.

| req (proposed) | statement (behavioral) | method | justification |
|---|---|---|---|
| **R-TUI-079** | When `generate_project_report` emits a variant's Modifications or Checklist table, the number of data rows emitted for that variant shall not exceed a declared per-variant row cap; any cut shall be stated in the document with the exact omitted count and the cap that caused it. | **Test** (Layer B, AT-164…AT-168, AT-170) | The whole requirement is observable in the written `.md`. No part of it needs inspection: rows are countable and the marker is a literal string. |
| **LLR-079.1** | `_modifications_lines` keeps the first `CAP` entries in document order and appends the shipped `> TRUNCATED: …` form + a truncation-appendix note. | **Test** (TC-399, TC-400, TC-402) | Order preservation and marker composition are unit-observable; the marker must be composed *from the constant*, which only a monkeypatch TC can prove. |
| **LLR-079.2** | `_checklist_lines` applies the cap to the variant's **flattened** row population across all `check_results`, not per check run; per-file aggregate counts stay **pre-cap**. | **Test** (TC-401, AT-167) | The per-variant-vs-per-run distinction is invisible to a single-run fixture — it needs both a dedicated white-box node and a black-box node. |
| **LLR-079.3** | The cut is stated once per table per variant, in the appendix as well as in place, with `M` = the variant's **pre-cap** total. | **Test** (AT-165, AT-168, TC-402) | Literal string equality. |
| **LLR-079.4** | A variant at or under the cap produces a **byte-identical** document to the pre-change composer. | **Test** (AT-169) — golden captured from a `git archive` export of `031ca8d` | This is a regression claim about *bytes*, so only a byte comparison validates it. See §4 for why the fixture must sit at `CAP−1` and not at 2 rows. |
| **LLR-079.5** | The declared cap value is `> 133`. | **Inspection + Test** (TC-403) | 133 is the largest per-variant modifications population any existing test produces (measured, §4). A cap at or below it silently drifts three shipped tests. The *reason* is an inspection finding; the *guard* is a test. |
| **(analysis, no requirement)** | Post-cap, a single variant's worst-case contribution is bounded; the **document** is still unbounded on the variant axis. | **Analysis** (§6) + **Test** (AT-171, per-variant only) | Deliberately **not** promoted to a requirement. Asserting a document-wide byte bound is the exact false claim this batch exists to remove. |

**Nothing is validated by "demo" in this batch.** The composer is headless
(`test_generation_is_headless_no_app`) and every outcome lands in a file on disk, so a demo would be
strictly weaker than the AT that already reads that file.

---

## 2. Layer B — acceptance tests (black-box, shipped surface)

**Shipped surface for every AT below:** build `VariantExecutionResult` fixtures → call
`generate_project_report(root, results, ReportOptions(...), variant_set=…, now_fn=_fixed_clock)` →
**re-read the returned `.md` from disk** → assert on its text/bytes. No AT reads a helper's return
value. This is the same chain `test_region_cap_marker_exact_omitted_count`
(`tests/test_report_service.py:436`) already drives.

**C-18:** each AT below is **one** `def test_at_NNN_*` in `tests/test_report_table_caps.py` driving
that whole chain end-to-end. No AT is "covered by the combination of" anything.

**Emitted-encoding pins — executed, not predicted** (probe output, this tree):

```
'### Modifications'
'| Address | Length | Before | After | Linkage | Symbol |'
'|---|---|---|---|---|---|'
'| 0x00001000 | 2 | 00 00 | AA BB | a2l-linked | ASAM.C.… |'
'### Checklists'                       <- PLURAL section heading
'#### Checklist: `chk0.json`'          <- Mode-B CODE SPAN, not the bare name
'Passed: 3 - Failed: 0 - Uncheckable: 0'
'| Address | Length | Expected | Actual | Result |'
'|---|---|---|---|---|'
'| 0x00001000 | 2 | AA BB | AA BB | pass |'
'> TRUNCATED: 73 of 201 modified regions omitted (cap: 128 regions per variant).'
'## Truncation appendix'
"- Variant 'a': 73 of 201 modified regions omitted (cap: 128 regions per variant)."
'No change entries were executed for this variant.'
'No checklists were executed for this variant.'
'filter matched 0 of {total} items'
```

> ⚠ **The trap that would have produced a vacuous suite.** At **201 applied** modification entries on
> **today's** tree, the document **already contains** `> TRUNCATED: …` and
> `## Truncation appendix` — because 201 applied entries make 201 regions, which trips
> `REPORT_MAX_REGIONS_PER_VARIANT = 128`. Measured:
> `'> TRUNCATED: 73 of 201 modified regions omitted (cap: 128 regions per variant).'`
> A cap AT written as `assert "> TRUNCATED" in text` or `assert "## Truncation appendix" in text`
> is therefore **GREEN before the feature is written**. Every AT below asserts the **exact
> table-specific marker string**, and AT-164/AT-165 additionally build their fixture from a
> **non-applied** disposition so the region cap cannot fire at all (measured: `skipped-outside` at
> 201 entries → 201 modification rows, **0** `TRUNCATED` markers, no appendix).

**Row-count helper (shared, defined once in the new file):** count lines that start with `|` and are
not the `|---` separator, between a named heading and the next `#`-prefixed line, minus 1 for the
column-header row. Counting `text.count("|")` or comparing table *shape* is forbidden here — a GFM
shape comparison is the batch-62 vacuous guard (equality held by construction).

### [PARAM] Fixture parameterization — binding on every node below

The cap value is being re-derived (field datum: a real campaign is *tens to ~200 entries*, so the
REV-1 working value of 200 would cut a legitimate 205-entry campaign). **Nothing in this catalog may
contain a bare cap literal.** Every node opens with:

```python
from s19_app.tui.services import report_service
from s19_app.tui.services.report_service import (
    MAX_REPORT_TABLE_ROWS_PER_VARIANT as CAP,   # name is the architect's to fix
    REPORT_CELL_BYTES as CELL_BYTES,            # A-1
    MAX_REPORT_ISSUES_PER_VARIANT,              # A-2
)

FAR_OVER = 3 * CAP            # 3.0x the cap
JUST_OVER = CAP + 1           # 1 row over — the off-by-one point
JUST_UNDER = CAP - 1          # the maximal legal document
RUNS = 4
PER_RUN = FAR_OVER // RUNS    # = 0.75 * CAP per run; 4 runs = 3.0x the cap
```

**Degeneracy guard (C-31 applied to a parameterized fixture).** A fixture derived from a constant can
silently stop testing what it claims when the constant moves. Every multi-arm node therefore asserts
its own preconditions *before* generating anything:

```python
assert PER_RUN < CAP, "AT-167 fixture degenerate: a single run must stay UNDER the cap"
assert RUNS * PER_RUN > CAP, "AT-167 fixture degenerate: the variant total must exceed the cap"
assert FAR_OVER > CAP and JUST_UNDER < CAP
```

Same for A-1: `assert CELL_BYTES + 1 > CELL_BYTES` is trivial, so the real guard is
`assert CELL_BYTES < MF_RUN_LENGTH_CEILING`, which is what makes the far-over arm meaningful.
A cap fixture that no longer straddles its boundary must **fail loudly**, never pass quietly.

**Deliberately pinned numbers (the only ones allowed):** `TC-403`'s `CAP > 133` row-drift floor and
`TC-406`'s `CELL_BYTES` drift floor — both are measured properties of the *existing suite*, not of
the new constants, so they must not track the constant. Each states its derivation in its docstring.

`CAP` below = the constant read from `report_service` (single-source coupling: an intentional retune
must not require editing 12 tests). Its *declared value* is pinned exactly once, in TC-403.

---

### AT-164 — the Modifications table stops at the cap
*US-B63-1 AC-1.* `tests/test_report_table_caps.py::test_at164_modifications_table_stops_at_cap`

- **Given** one variant whose change summaries carry `3 × CAP` entries (**600 rows = 3.0× the cap**;
  the multiple goes in the docstring, C-31), all with disposition `skipped-outside` so the region
  cap cannot fire,
- **When** a report is generated and re-read from disk,
- **Then** the `### Modifications` table contains **exactly `CAP` data rows**, and the rows are the
  **first `CAP` in document order** (assert the first and last emitted `0x%08X` address against the
  fixture's entries 0 and `CAP-1`).
- **Second arm, same node:** `CAP + 1` entries → still exactly `CAP` rows.
- **Counterfactual (turns it RED):** change the slice to `entries[: CAP + 1]` → 201 rows ≠ 200.
  Deleting the cap entirely → 600 rows. Slicing from the tail (`entries[-CAP:]`) → the last-address
  assertion fails.

### AT-165 — the Modifications cut is stated, exactly
*US-B63-1 AC-2.* `…::test_at165_modifications_cut_is_stated_with_exact_counts`

- **Given** the same `3 × CAP` fixture,
- **Then** the document contains the **exact** in-place marker
  `> TRUNCATED: {3*CAP - CAP} of {3*CAP} modification rows omitted (cap: {CAP} rows per variant).`
  *(final wording is Phase 1's; the AT asserts whatever Phase 1 locks, character for character, and
  the string is built in the test from the same f-string shape, never pasted)*
  **and** the appendix entry `- Variant 'a': {same text}.` under `## Truncation appendix`.
- **Isolation:** because the fixture uses `skipped-outside`, `text.count("> TRUNCATED")` must be
  **exactly 1** — this is what separates the new marker from the pre-existing region marker.
- **Counterfactual:** drop the `if omitted:` block → both strings absent. Emit `M` as the post-cap
  total (`200`) instead of the pre-cap total (`600`) → exact-string mismatch. Forget the appendix
  `notes.append` → the `- Variant 'a': …` assertion fails while the in-place one still passes.

### AT-166 — the Checklist table stops at the cap
*US-B63-2 AC-1.* `…::test_at166_checklist_table_stops_at_cap`

- **Given** one variant with **one** check result carrying `3 × CAP` entries (**3.0× the cap**),
- **Then** the summed data rows across every `#### Checklist: …` block = exactly `CAP`.
- **Counterfactual:** off-by-one slice; cap removed → 600 rows.

### AT-167 — the Checklist cap is PER VARIANT, not per check run
*US-B63-2 AC-4 — the story's real trap.* `…::test_at167_checklist_cap_is_per_variant_across_runs`

- **Given** one variant with **four** check results of `¾ × CAP` entries each — `4 × 150 = 600` rows,
  **3.0× the cap**, while **no single run exceeds it** (150 = 0.75×),
- **Then** the summed data rows across all four `#### Checklist:` blocks = exactly `CAP`.
- **Measured on today's tree (RED evidence):** 2 runs × 150 → **300** rows, 4 runs × 150 → **600**
  rows, **0** truncation markers.
- **Why a separate node (C-18):** the mutation `for check in result.check_results:
  for entry in check.entries[:CAP]:` — a per-run cap — leaves **AT-166 GREEN** (its single run is
  over cap and gets sliced correctly) and only AT-167 goes RED. A single-run AT cannot see this.
- **Counterfactual:** per-run slicing → 600 rows. Resetting the running counter between runs → 600.

### AT-168 — the Checklist cut is stated once, with the summed pre-cap total
*US-B63-2 AC-2.* `…::test_at168_checklist_cut_stated_once_with_summed_total`

- **Given** the AT-167 fixture (4 runs × 150),
- **Then** exactly **one** checklist truncation marker appears in the whole document (not one per
  run), its `M` is **600** (the variant's summed pre-cap population, not 150 and not 200), and the
  appendix carries the matching `- Variant 'a': …` line.
- **And** the per-file `Passed: … - Failed: … - Uncheckable: …` aggregates stay **pre-cap** — the
  audit header must still disclose what the table hid (this mirrors the shipped filter behavior,
  `report_service.py:1105-1110`).
- **Counterfactual:** emit the marker inside the per-check loop → 4 markers. Compute `M` per run →
  `150`. Recompute aggregates from the emitted rows → `Passed: 200` instead of `600`.

### AT-169 — at/under the cap, the document is byte-identical
*US-B63-1 AC-3 **and** US-B63-2 AC-3 (one observable, one node).*
`…::test_at169_under_cap_document_is_byte_identical`

- **Given** a variant with **`CAP − 1` modification entries and `CAP − 1` checklist entries**
  (the *maximal* under-cap point),
- **When** the report is generated with `now_fn=_fixed_clock`,
- **Then** `canonical_report_bytes(written, tmp_path) == canonical_report_bytes(golden.read_bytes())`
  against **`tests/goldens/batch63/at169-under-cap-project-report.md`**, captured from a
  **`git archive` export of `031ca8d`** (never from the working worktree — PLAN §6 risk 5) *before
  any source edit lands*.
- **Why `CAP − 1` and not a 2-row fixture — this is the C-31 point for AC-3.** A 2-row golden sits
  **100× under** the cap; a cap that erroneously fires at `≥ 199` (off-by-one in the wrong
  direction), or one hard-coded to `128`, leaves a 2-row document **byte-identical** and the guard
  never fires. At `CAP − 1` the golden is one row away from the boundary in the direction the bug
  actually goes.
- **Counterfactual:** cap fires at `>= CAP-1` instead of `> CAP` → 198 rows in the document → byte
  mismatch. Any change to a row's spacing, the marker's blank line, or column order → mismatch.
- **Golden hygiene:** the capture fixture uses relative source paths (`chg.json` / `chk.json`) and a
  fixed clock; `canonical_report_bytes`' `_assert_no_host_path_residue` guard
  (`tests/conftest.py:1040`) runs on the *written* side and would fail on any host-path leak.

### AT-170 — empty and all-filtered-out sections are untouched
*Negative / regression node.* `…::test_at170_empty_and_zero_match_sections_emit_no_cap_marker`

- **Arm 1 — zero entries:** a variant with no change summaries and no check results →
  `'No change entries were executed for this variant.'` and
  `'No checklists were executed for this variant.'` present verbatim; **no** `> TRUNCATED`, **no**
  `## Truncation appendix` (measured today: 0 markers, 2 438 B document).
- **Arm 2 — all rows filtered out:** a `3 × CAP` fixture plus a `ReportFilterMatcher` matching
  nothing → `'filter matched 0 of 600 items'` present, and **no** cap marker: the cap must be
  applied to the **kept** rows, after filtering, so a section that renders zero rows can never
  claim it withheld any.
- **Arm 3 — filter reduces an over-cap section to under-cap:** `3 × CAP` entries, filter keeps
  `CAP − 1` → `CAP − 1` rows, **no** cap marker.
- **Counterfactual:** cap applied *before* the filter → arm 3 emits a marker for rows the filter
  already removed, and the stated `M` contradicts the filter's own `0 of 600` notice. Emitting a
  marker with `omitted == 0` → arms 1 and 2 go RED.

### AT-171 — a single variant's worst-case contribution is bounded  **[AMENDED IN REV 2 — A-1]**
*Closes the M-2 contradiction, deliberately scoped to ONE variant.*
`…::test_at171_single_variant_at_cap_worst_case_stays_small` — marked `@pytest.mark.slow`.

> **Before → After (fixture).**
> **Before (REV 1):** both tables at `CAP` rows, text cells at `REPORT_CELL_CHARS = 512`, byte runs
> left at the fixture default (4 bytes). Measured worst case **123 176 B = 0.059×** budget.
> **After (REV 2):** byte runs are **not** a free variable any more — A-1 gives them a bound, and the
> worst case is every cell at *its own* bound. All four byte cells (`before`/`after` on
> modifications, `expected`/`actual` on checklist) sit at `CELL_BYTES`, text cells at
> `REPORT_CELL_CHARS`. **Re-measured at `CAP=200, CELL_BYTES=256`: 733 576 B = 0.350× budget** —
> **6.0× larger** than the REV-1 figure. REV 1 was not wrong, it was *incomplete*: it varied the
> text cell and left the byte cell at its default, so it measured a regime A-1 now makes
> unreachable in one direction and much more expensive in the other.

- **Given** one variant with both tables at exactly `CAP` rows, every text cell at
  `REPORT_CELL_CHARS`, and **every byte cell at exactly `CELL_BYTES`** (post-A-1 this *is* the
  ceiling — no cell can exceed it),
- **Then** the generated document is **under `REPORT_MAX_TOTAL_BYTES`**, with the measured size and
  its multiple of the budget printed for the review packet.
- **Measured surface** (§10.3) — the constraint is satisfiable but **not slack**:

  | `CAP` \ `CELL_BYTES` | 16 | 32 | 64 | 128 | 256 |
  |---:|---:|---:|---:|---:|---:|
  | 200 | 0.075× | 0.093× | 0.130× | 0.203× | **0.350×** |
  | 300 | 0.112× | 0.140× | 0.194× | 0.304× | 0.524× |
  | 500 | 0.186× | 0.232× | 0.323× | 0.506× | **0.873×** |

  At `CELL_BYTES=256` the single-variant constraint alone caps the row cap at **≈570**; measured
  directly, `CAP=1000` gives **1.744× budget for ONE variant**. The architect's stated constraint
  ("a single variant at cap stays inside 2 MiB post-A-1") is therefore a **live, binding ceiling on
  the cap value**, not a formality — it must be re-checked against whatever pair is chosen.
- **⚠ What this AT must NOT say (unchanged from REV 1, and now more important).** It must not be
  written as `assert document_size <= REPORT_MAX_TOTAL_BYTES` **as a general claim**. That claim is
  still false, and A-1 makes it *more* false: see the Before → After in §6 — the variants-to-breach
  count drops from ≈17.3 to **2.9**. Writing the general form here re-commits M-2.
- **Counterfactual:** raise `CAP` past the measured ceiling for the chosen `CELL_BYTES` (e.g. 1000 at
  256) → the single-variant document exceeds the budget → RED. Remove the `CELL_BYTES` clamp → the
  1-row `MF_RUN_LENGTH_CEILING` case alone reaches 3.00× budget → RED.

---

### AT-172 — a byte run over the bound is truncated, and the cut is visible  **[A-1]**
*New in REV 2. R-TUI-080.* `…::test_at172_oversized_byte_run_is_bounded_and_states_the_cut`

- **Given** one variant with a **single** modification entry whose `before_bytes` and `after_bytes`
  are `MF_RUN_LENGTH_CEILING` long (`1 048 576` — **4 096× the working `CELL_BYTES` of 256**; the
  multiple goes in the docstring, C-31), i.e. the largest run the change schema itself permits
  (`s19_app/tui/changes/io.py:232`),
- **When** a report is generated and re-read from disk,
- **Then** no single line of the document exceeds a bound derived from `CELL_BYTES` (each byte
  renders as 3 characters, so the byte cells contribute `≤ 3 * CELL_BYTES` each), **and** the cell
  states that it was cut — the row must not silently present a truncated run as if it were the whole
  run.
- **Measured RED on today's tree:** that single row produces a **6 291 562-character line** and a
  **6 294 029 B document = 3.00× the entire 2 MiB budget**, with **0** truncation markers anywhere
  (§10.2). One entry. The 200-row cap is irrelevant to it.
- **Second arm, same node — the row cap genuinely does not bound the table:** `35` entries with
  `10 000`-byte runs → **2 106 272 B = 1.00× budget** with the row cap never firing (34 entries =
  0.98×). This arm is what proves A-1 is not redundant with R-TUI-079.
- **Counterfactual:** remove the bound from `_format_bytes` → the line-length assertion fails by
  three orders of magnitude. Apply the bound to `before_bytes` only → the `after` cell still blows
  the line. Truncate silently (no indicator) → the "states the cut" assertion fails.

### AT-173 — a byte run at or under the bound survives VERBATIM  **[A-1]**
*New in REV 2. The direction that matters most.*
`…::test_at173_in_bound_byte_run_is_byte_faithful`

An over-broad bound that silently corrupts real byte evidence is a **worse** failure than an
unbounded one: the unbounded case produces an unopenable file (loud), the over-broad case produces a
plausible file with wrong bytes (silent). This node is the guard against the fix.

- **Given** three arms in one node — runs of `CELL_BYTES - 1`, exactly `CELL_BYTES`, and a realistic
  short run (4 bytes) — on **all four** byte cells (`before_bytes`, `after_bytes` on the
  modifications row; `expected_bytes`, `actual_bytes` on the checklist row),
- **Then** each cell renders the **complete** run, byte for byte, in the shipped
  `"%02X" `-joined form, with **no** truncation indicator and no ellipsis: the expected cell text is
  built in the test from the fixture's own byte tuple, so a single dropped or reordered byte fails.
- **And** the `Length` column keeps stating the **true** run length (`address_end - address_start`),
  not the rendered length — a truncated *display* must never be mistaken for a shorter *change*.
  This is the specific way a byte bound can make an evidentiary document lie.
- **Counterfactual:** implement the bound as `values[:CELL_BYTES]` with a `>=` comparison → the
  exactly-`CELL_BYTES` arm loses its last byte → RED. Derive `Length` from the rendered string → the
  length assertion fails on the over-bound fixture in AT-172. Apply the bound to only 2 of the 4
  cells → the checklist arms fail.
- **Drift note (§10.1):** the largest byte run anywhere in the existing suite is **exactly 256**, at
  `tests/test_report_field_census.py:835` (`_format_bytes(range(256))`). `CELL_BYTES = 256` therefore
  has **zero headroom** over the existing maximum — unlike the row cap's 1.50×. Whether that call
  truncates depends entirely on `>` vs `>=`. TC-406 pins it.

### AT-174 — a fired declaration-error cap registers its appendix note  **[A-2]**
*New in REV 2. R-TUI-081.* `…::test_at174_declaration_error_cap_registers_appendix_note`

- **Given** one variant carrying `MAX_REPORT_ISSUES_PER_VARIANT + 50` declaration errors and
  **nothing else that truncates** (few entries, no region overflow, default budget),
- **Then** the document contains the in-place marker **and** a `## Truncation appendix` section
  carrying the matching `- Variant 'a': … declaration errors omitted …` entry.
- **Measured RED on today's tree (§10.4) — worse than reported to me:** the in-place marker fires
  (`> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).`) while the
  `## Truncation appendix` heading is **entirely ABSENT** from the document. It is not that the
  entry is missing from a present appendix — with only this mechanism firing there is no appendix at
  all, so a reader who checks the appendix for cuts finds *nothing* and concludes *nothing was cut*,
  while 50 issues were dropped. Same class as M-2, one step more misleading.
- **Mechanism the fix must change (for the implementer, not asserted by this AT):**
  `_declaration_error_lines` returns `List[str]` and is consumed by
  `emit(_declaration_error_lines(result))` (`report_service.py:1663`), which has no notes channel.
  `_hexdump_section` is the shipped pattern — it returns `Tuple[List[str], List[str]]` and the caller
  does `notes.extend(dump_notes)`. The two new caps need the same plumbing, so A-2 is retro-wiring,
  not new machinery.
- **Counterfactual:** land the row caps' notes plumbing but skip the retro-wire → AT-174 alone stays
  RED while AT-165/AT-168 go green. That asymmetry is why it is its own node.

### AT-175 — four truncation mechanisms coexist without conflating their counts  **[COEX]**
*New in REV 2. The gap neither lane had covered.*
`…::test_at175_concurrent_truncation_mechanisms_each_state_their_own_count`

Post-batch the document has **five** independent truncation mechanisms — modifications rows,
checklist rows, declaration errors, regions, byte budget — all writing into **one** shared appendix
list. A shared sink is exactly where one entry overwrites another, or two counts get conflated.

- **Given** a **two-variant** fixture where, for each variant, **at least four** mechanisms fire
  simultaneously: `FAR_OVER` modification entries with `applied` disposition (trips both the
  modifications cap **and** the region cap), `MAX_REPORT_ISSUES_PER_VARIANT + 50` declaration errors,
  `RUNS × PER_RUN` checklist entries, and a monkeypatched `REPORT_MAX_TOTAL_BYTES` small enough to
  omit hexdump blocks (the shipped technique from
  `tests/test_report_service.py::test_total_bytes_cap_marker:478`),
- **Then**, in the single written document:
  1. each mechanism's in-place marker appears with **its own** correct `N of M` — five distinct
     strings, no two sharing a count;
  2. the appendix contains **exactly one entry per fired mechanism per variant** (`2 × 5 = 10`),
     counted with `text.count(...)` per exact string, so a lost or duplicated note fails;
  3. every appendix entry carries **its own variant id** — variant `a`'s counts never appear under
     variant `b` (the fixture gives the two variants **deliberately different** populations, e.g.
     `FAR_OVER` vs `FAR_OVER + 7`, so a cross-variant conflation cannot hide behind equal numbers);
  4. appendix order is **emission order** — per variant: modifications → declaration errors →
     checklist → regions → byte budget — asserted as an index sequence, not a set.
- **Measured on today's tree (§10.4), 3 mechanisms firing:** 3 in-place markers, **2** appendix
  entries. The two present entries each state their own count correctly and do not overwrite each
  other (the appendix is a `list.append`, which is sound) — **the plumbing is fine; the registration
  is what is missing.** That is a useful negative result: this AT is guarding registration
  completeness and attribution, not a list bug.
- **Counterfactual:** register the checklist note with the modifications' count → assertion 1 fails.
  Build the appendix from a `dict` keyed by variant id → assertion 2 fails (5 entries collapse to 1
  per variant). Hoist `notes` outside the per-variant loop without the variant prefix → assertion 3
  fails. Sort the notes → assertion 4 fails.
- **Why one node and not five (C-18):** the named chain is *"multiple mechanisms in one document do
  not interfere"*. It is a single interaction property; splitting it into pairwise nodes would
  produce five tests none of which observes the interaction.

---

## 3. Layer A — white-box tests (per LLR)

Home: same new file (unit-level nodes may call the private helpers directly).

| TC | LLR | what it pins | counterfactual |
|---|---|---|---|
| **TC-399** | 079.1 | `_modifications_lines` over `3 × CAP` entries returns a line list whose data rows number exactly `CAP`, in input order; the returned list ends with the marker + trailing `""`. | off-by-one slice; `sorted()` applied to entries. |
| **TC-400** | 079.1 / 079.3 | **The marker is composed from the constant, not from a literal.** `monkeypatch.setattr(report_service, "<CAP_CONST>", 5)`, feed 12 entries → 5 rows and `…(cap: 5 rows per variant).` The `5`/`12` here are **local to the monkeypatch**, not the real cap, so they do not violate §2 [PARAM] — the point is that the emitted text tracks whatever the constant says. Mirrors `test_total_bytes_cap_marker` (`tests/test_report_service.py:478`), which monkeypatches `REPORT_MAX_TOTAL_BYTES` to 10. | hard-code the cap in the f-string → the marker states the real cap while 5 rows render. **This TC is the only node that catches a hard-coded cap**, since every AT reads the constant. |
| **TC-401** | 079.2 | `_checklist_lines` with `RUNS × PER_RUN` entries emits `CAP` rows **total**; the last run's block renders its heading + aggregates but **zero** data rows (or is elided — Phase 1 rules which; the TC asserts the ruled shape). Aggregates stay pre-cap. | per-run slicing; aggregates recomputed post-cap. |
| **TC-402** | 079.3 | The appendix note is escaped through `md_safe(result.variant_id, limit=REPORT_CELL_CHARS)` like the region note (`report_service.py:1338`) — a variant id of `a_[x](http://e)` must not become a link in the appendix. Mirrors `test_report_field_census.py::test_tc389_truncation_appendix_note_is_escaped`. | interpolate `result.variant_id` raw → the linkify sink fires. Assert the **emitted** escaped token, not the rendered text (P-3). |
| **TC-403** **[PARAM, rewritten in REV 2]** | 079.5 | **Before (REV 1):** `CAP == 200` and `CAP > 133`. **After:** the equality assert is **removed** — the value is being re-derived and pinning it here would make TC-403 the one node that has to be edited when the architect's number lands, which is precisely what §2 [PARAM] forbids. What remains are the two **derived** bounds, each with its derivation in the docstring: **(a) `CAP > 133`** — the row-drift floor, the largest per-variant modifications population in the existing suite (§5); **(b) `CAP` ≥ the field maximum plus headroom** — a real campaign is *tens to ~200 entries*, so a cap at 200 would cut a legitimate 205-entry campaign. **(c)** the single-variant budget ceiling is asserted by AT-171, not duplicated here. | set the cap to 128 → (a) fires **before** three other tests drift, naming the reason. Set it to 200 → (b) fires, naming the field datum. |
| **TC-404** | 079.1 / 079.2 | Empty-input branches unchanged: `_modifications_lines` on a result with no entries returns exactly the 3-line "No change entries…" form; `_checklist_lines` with no `check_results` returns the "No checklists…" form. No marker, no note. | a cap check placed before the empty guard emits `0 of 0 omitted`. |
| **TC-405** | 079.1 / 079.2 | **Cap-after-filter ordering** at the unit level: with a `report_filter` keeping `CAP − 1` of `3 × CAP` rows, the returned notes list is empty and no marker line is present. | cap before filter. |
| **TC-406** **[A-1]** | 080.1 | `_format_bytes` bound, unit level, three arms: `CELL_BYTES - 1` → verbatim; `CELL_BYTES` → **verbatim** (the `>` vs `>=` pin); `CELL_BYTES + 1` → bounded + indicator. Plus the **drift floor**, deliberately pinned: `CELL_BYTES >= 256`, with the docstring stating that 256 is the largest run the existing suite renders (`test_report_field_census.py:835`, measured §10.1) and that the value has **zero** headroom — unlike `CAP`'s 1.50×. | `>=` comparison → the exactly-`CELL_BYTES` arm drops a byte. Bound below 256 → the drift-floor assert fires *before* other tests move, naming the reason. |
| **TC-407** **[A-1]** | 080.1 | **Single-site coupling:** all four byte cells route through `_format_bytes` — `monkeypatch` it to a sentinel and assert the sentinel appears in the modifications `Before`/`After` and checklist `Expected`/`Actual` columns (4 hits). Bounding one call site instead of the shared helper is the realistic partial fix. | inline `" ".join(...)` at any one of the four sites → that column shows real hex, not the sentinel. |
| **TC-408** **[A-1]** | 080.2 | **`Length` is not derived from the rendered cell.** With a run at `CELL_BYTES + 1`, the `Length` column still equals `address_end - address_start`. Unit-level companion to AT-173's black-box arm. | compute `Length` from `len(rendered.split())` → the truncated row understates the change. |
| **TC-409** **[A-1]** | 080.1 | **The F-17 inertness pin survives.** `test_report_field_census.py::test_f17_format_bytes_is_inert_by_construction:836` asserts `set(rendered) <= set("0123456789ABCDEF ")` — a batch-62 *escaping* guard. If A-1's truncation indicator introduces any character outside that alphabet, F-17 breaks and a security pin gets weakened to accommodate a resource fix. TC-409 asserts the chosen indicator's character set against the same alphabet, or — if Phase 1 rules the indicator must be human-readable — records a §6.5 Before/After amending F-17 **deliberately**, never as collateral. | an indicator like `… +N more` → F-17 RED; discovering that during implementation instead of design is how a security pin gets silently relaxed. |
| **TC-410** **[A-2] [COEX]** | 081.1 | **Notes plumbing + attribution at the unit level:** `_declaration_error_lines` returns `(lines, notes)` with exactly one note when the cap fires and **zero** when it does not; the note is escaped via `md_safe(result.variant_id, …)` like the region note (`report_service.py:1338`); `generate_project_report` extends the shared `notes` list in emission order. | return a bare `List[str]` → the caller silently drops the note (this is today's bug). Emit a note with `omitted == 0` → the no-cap arm fails. |

---

## 4. Boundary + negative matrix (per cap)

> **Before → After.** REV 1 stated this matrix in literals against `CAP = 200`. **REV 2 states it in
> terms of the constants**, and adds a **second matrix** for the A-1 byte-run bound. The rows are
> unchanged in meaning; only the notation and the two new tables are new.

### 4.1 Row cap (`CAP`) — applied **independently to each table**

| point | modifications fixture | checklist fixture | expected in the written `.md` | node |
|---|---|---|---|---|
| **zero entries** | no change summaries | no check results | `No change entries were executed for this variant.` / `No checklists were executed for this variant.`; **0** markers, no appendix | AT-170 arm 1 · TC-404 |
| **all filtered out** | `FAR_OVER`, filter matches none | same | `filter matched 0 of {FAR_OVER} items`; **0** cap markers | AT-170 arm 2 · TC-405 |
| **under (`CAP − 1`)** | `JUST_UNDER` | `JUST_UNDER` | `CAP − 1` rows each; **no** cap marker; document **byte-identical** to the `031ca8d` golden | AT-169 |
| **exactly at (`CAP`)** | `CAP` | `CAP` | `CAP` rows each; **no** cap marker (a marker here is an off-by-one) | AT-171 (its arm asserts marker absence) |
| **exactly over (`CAP + 1`)** | `JUST_OVER` | `JUST_OVER` | `CAP` rows; marker `1 of {CAP+1} …` | AT-164 arm 2 · AT-166 arm 2 |
| **far over (`3 × CAP`)** | `FAR_OVER` | `FAR_OVER` (1 run) | `CAP` rows; marker `{2*CAP} of {FAR_OVER} …` | AT-164 · AT-165 · AT-166 |
| **far over, multi-run** | — | `RUNS × PER_RUN` (4 × 0.75·CAP) | `CAP` rows **total**; **one** marker, `M = FAR_OVER` | AT-167 · AT-168 · TC-401 |
| **pathological cell width** | `CAP` rows, text at `REPORT_CELL_CHARS`, bytes at `CELL_BYTES` | same | document < `REPORT_MAX_TOTAL_BYTES`, **single variant only** | AT-171 |

### 4.2 [A-1] Byte-run bound (`CELL_BYTES`) — applied to **all four** byte cells

Cells: `before_bytes`, `after_bytes` (modifications) · `expected_bytes`, `actual_bytes` (checklist).
Every arm must be run against all four — a bound on two of four is the realistic partial fix.

| point | run length | expected | node |
|---|---|---|---|
| **`None` (no value captured)** | `None` | renders `-` exactly as today; the bound must not touch the `None` branch (`report_service.py:445`) | AT-173 · TC-406 |
| **zero-length run** | `()` | renders the empty cell as today; no indicator | TC-406 |
| **realistic** | 4 bytes (1 192 of 1 196 census calls, §10.1) | **verbatim**, no indicator | AT-173 |
| **under (`CELL_BYTES − 1`)** | 255 @ working value | **verbatim**, no indicator | AT-173 · TC-406 |
| **exactly at (`CELL_BYTES`)** | 256 @ working value | **verbatim**, no indicator — the `>` vs `>=` pin, and the point of zero headroom vs the existing suite | AT-173 · TC-406 |
| **exactly over (`CELL_BYTES + 1`)** | 257 @ working value | bounded to `CELL_BYTES` rendered bytes + the cut stated; `Length` column unchanged | AT-172 · TC-406 · TC-408 |
| **far over** | `MF_RUN_LENGTH_CEILING` = 1 048 576 (**4 096×** the working bound) | bounded; line length `≤ ~3·CELL_BYTES` per cell. **Today: 6 291 562-char line, 3.00× budget, 0 markers** | AT-172 |
| **row cap cannot substitute** | 35 rows × 10 000 B | **today 1.00× budget with the row cap never firing** — proves A-1 is not redundant with R-TUI-079 | AT-172 arm 2 |

### 4.3 [A-2] [COEX] Appendix completeness

| point | fixture | expected | node |
|---|---|---|---|
| **no mechanism fires** | small variant | **no** `## Truncation appendix` section at all (today's correct behavior — preserve it) | AT-170 |
| **only declaration errors fire** | `MAX_REPORT_ISSUES_PER_VARIANT + 50` issues | appendix **present** with its entry. **Today: appendix entirely ABSENT** | AT-174 |
| **4+ mechanisms, 1 variant** | see AT-175 | one appendix entry per fired mechanism, each with its own count | AT-175 |
| **4+ mechanisms, 2 variants, different populations** | AT-175 fixture | `2 × 5` entries, no cross-variant conflation, emission order preserved | AT-175 |

**C-31 compliance rule for this batch (binding on the implementer):** every fixture in the
"over" rows above **must state its multiple of the bound in the test docstring** — `3.0× the cap`,
`4 runs × 0.75× = 3.0× the cap`, `4 096× the byte bound`. A cap fixture with no stated multiple does
not pass review. Rationale on the record: batch-62 shipped a byte-budget test sitting **2.8× under**
its own limit, and deleting the guard left 38 tests green. **[PARAM] addendum:** because the
multiples are now computed from constants, each node must also assert its degeneracy guard (§2
[PARAM]) — a fixture that stops straddling its boundary when the constant moves must fail loudly.

---

## 5. Byte-identity drift set — DERIVED BY EXECUTION (C-39)

**Question:** which existing tests/goldens does a 200-row cap drift?
**Answer, measured: none. The drift set is empty.**

**Method.** A pytest plugin wrapped `report_service._modifications_lines` and `_checklist_lines`,
recording the per-variant row population fed to each, then ran every test file that reaches
`generate_project_report` (grep-derived: `test_report_service.py`, `test_report_field_census.py`,
`test_report_progress.py`, `test_report_symbol_escape.py`, `test_tui_report_seam.py`,
`test_tui_report_view.py`) plus the golden consumers `test_tui_report_filter_surface.py` and the
neighbours `test_report_filter.py`, `test_report_markup_safety.py`, `test_report_logging.py`,
`test_report_addendum.py`, `test_variant_execution.py`.

```
376 passed in 297.47s
[CAPPROBE] {"mod_max": 133, "chk_max": 3, "chk_runs_max": 2,
            "mod_calls": 74, "chk_calls": 74, "mod_over": [], "chk_over": []}
```

Attribution of the top populations (second, narrowed run):

| population | site |
|---:|---|
| **133** | `tests/test_report_field_census.py::test_tc389_truncation_appendix_note_is_escaped` |
| 130 | `tests/test_report_service.py::test_region_cap_marker_exact_omitted_count` |
| 128 | `tests/test_report_service.py::test_measure_report_caps_on_large_s19` (×2 regimes) |
| 3 | max checklist population anywhere in the suite (2 check runs max) |

**Consequences.**
1. `CAP = 200` → **zero** existing documents change → **zero** golden drift. Headroom 200/133 = **1.50×**.
   **[REV 2]** The cap is expected to **rise** (field campaigns reach ~200 entries), and the drift
   floor is one-sided: a *higher* cap only widens the headroom, so the empty drift set holds for any
   `CAP ≥ 134`. **This conclusion is safe against the pending re-derivation in the raising
   direction only** — TC-403 (a) is what keeps it true if anyone ever lowers it.
2. `tests/goldens/batch35/at055b-project-report.md` carries **2** modification rows and **0**
   checklist rows — 100× under any plausible cap. It cannot drift, and equally **it cannot validate
   AC-3**; hence the dedicated `CAP − 1` golden in AT-169.
3. `at054b-before-after-report.{md,html}` belong to `diff_report_service` (a different composer) and
   contain neither table — untouched.
4. **A cap ≤ 133 drifts three tests**, one of which (`test_tc389_…`) is a batch-62 escaping guard.
   That is why TC-403 pins `CAP > 133` with the reason in its docstring rather than leaving the
   next retune to discover it.
5. `test_measure_report_caps_on_large_s19` (`tests/test_report_service.py:666`) feeds **128**
   entries and asserts `size <= REPORT_MAX_TOTAL_BYTES` when the byte-cap marker did not fire.
   128 < 200 → its behavior is unchanged and it stays green. **Confirmed by the run above** (it
   executed inside the 376 and printed `size=108561 … byte-cap fired=no`).

---

## 6. Analysis — what the caps do NOT fix (must stay out of the requirement text)

> ### ⚠ Before → After — the REV-1 figure in this section is SUPERSEDED
>
> **Before (REV 1):** at-cap pathological = 200 rows/table with 512-char text cells and the fixture's
> default **4-byte** runs → 123 176 B/variant, marginal 121 171 B, **≈ 17.3 variants to breach**.
> **After (REV 2):** that shape is not the worst case once A-1 exists. A-1's own bound
> (`CELL_BYTES`, working value 256) sets a *floor* under every byte cell's cost: 4 cells ×
> 256 bytes × 3 chars = **3 072 characters per row from the byte columns alone**, six times the
> 512-char symbol cell. Re-measured with every cell at its bound (§10.3):
> **733 576 B/variant, marginal 731 571 B, ≈ 2.9 variants to breach.**
>
> **The variant-axis carry got ~6× sharper, not softer.** I flagged 17.3 in REV 1 and the coordinator
> has adopted it for the BACKLOG — **that number must be replaced before it ships**, or the carry
> understates the residual by a factor of six. This is the same failure mode as measuring a cap
> fixture under its own limit: the REV-1 measurement varied the axis I was thinking about and left
> the other at its default.

Executed on this tree, **post-A-1 worst case** (both tables at `CAP` rows, text cells at
`REPORT_CELL_CHARS = 512`, **all four byte cells at `CELL_BYTES = 256`**, `skipped-outside` so region
dumps do not confound):

| variants | document size | marginal |
|---:|---:|---:|
| 1 | 733 576 B | — |
| 2 | 1 465 147 B | 731 571 B |

Marginal cost is exactly constant, so the breach point is a clean linear solve:
**≈ 2.9 at-cap worst-case variants** exceed `REPORT_MAX_TOTAL_BYTES`. Sensitivity across the
candidate pairs is the second grid in §10.3 — it ranges from **13.5** variants (`CAP=200`,
`CELL_BYTES=16`) down to **1.1** (`CAP=500`, `CELL_BYTES=256`).

In the realistic regime (63-char symbols, 4-byte runs — 1 192 of 1 196 census calls) one at-cap
variant costs **20 976 B** → ≈ 100 variants. Both numbers are true; the honest carry cites the
worst case, because the whole point of a bound is what happens at the bound.

**QA ruling for Phase 1 (unchanged, and reinforced):** the batch may **not** state, in a requirement,
a comment, or a test name, that the document is bounded by `REPORT_MAX_TOTAL_BYTES` after this
change. It is not. The honest claim is *per-variant contribution is bounded*. The residual — the M-5
variant axis — carries to `BACKLOG.md` **with the number ≈2.9 attached** (worst case) alongside the
≈100 realistic figure, because "unbounded variant count" reads as theoretical while "**three**
worst-case variants break the stated cap" reads as what it is.

**Second-order note for the architect.** A-1 and R-TUI-079 interact **multiplicatively**: the
document's worst case is `CAP × (4 × 3 × CELL_BYTES + REPORT_CELL_CHARS + overhead)`. Raising the row
cap to accommodate a 205-entry field campaign and setting `CELL_BYTES` generously are not independent
decisions. §10.3 gives the measured joint surface so the pair can be chosen against data.

---

## 7. Traceability

| story | AC | AT (Layer B) | LLR | TC (Layer A) |
|---|---|---|---|---|
| US-B63-1 | AC-1 | AT-164 | 079.1 | TC-399, TC-400 |
| US-B63-1 | AC-2 | AT-165 | 079.3 | TC-402 |
| US-B63-1 | AC-3 | AT-169 | 079.4 | — (byte-level only) |
| US-B63-2 | AC-1 | AT-166 | 079.2 | TC-401 |
| US-B63-2 | AC-2 | AT-168 | 079.3 | TC-402 |
| US-B63-2 | AC-3 | AT-169 (shared observable) | 079.4 | — |
| US-B63-2 | AC-4 | **AT-167** | 079.2 | TC-401 |
| both | negative/empty | AT-170 | 079.1/079.2 | TC-404, TC-405 |
| both | resource claim | AT-171 *(amended)* | (analysis) | TC-403 |
| **A-1** | over-bound run is cut, cut is visible | **AT-172** | 080.1 | TC-406, TC-407 |
| **A-1** | in-bound run is verbatim; `Length` unaffected | **AT-173** | 080.1 / 080.2 | TC-406, TC-408, TC-409 |
| **A-2** | a fired decl-error cap registers its appendix note | **AT-174** | 081.1 | TC-410 |
| **COEX** | 4+ mechanisms, 2 variants, no conflation | **AT-175** | 079.3 / 081.1 | TC-410 |

Every AT row names exactly one node. No row says "combination of".

---

## 8. Execution protocol for Phase 3 (binding)

1. **Every AT is shown RED before its fix.** AT-164/165/166/167/168/170-arm-3 **and the REV-2 nodes
   AT-172/173-`Length`-arm/174/175** must be run on the unmodified tree and the failure output pasted
   into the increment packet. AT-169's golden must be captured **before** the first source edit, from
   a `git archive` export.
   *Exception, stated rather than hidden:* AT-173's verbatim arms are **GREEN today** (nothing
   truncates yet) — they are regression guards on the fix, not defect demonstrations. Their RED proof
   is the mutation in §2, executed during implementation.
2. **Ledger.** `post = base − D + A`, `D = 0` expected (no test is deleted),
   **`A = 12 AT + 12 TC = 24`** *(Before: 15)*. Base is re-confirmed from this batch's own first
   complete run (C-19), not inherited from batch-62's 2 213.
3. **Guard-can-fail demonstration.** For AT-165, AT-167, AT-169 **and AT-173** the packet carries the
   counterfactual actually executed (mutate → observe RED → revert), not merely described. Batch-62
   shipped two guards that three review passes cleared and neither could fire. **AT-173 is on this
   list specifically because it is green before and after** — the only evidence it can fire is the
   executed mutation.
4. **No cap literal in any AT.** Read the constants (§2 [PARAM]). **TC-400, TC-403 and TC-406** are
   the only nodes that may name a value, and each states why in its docstring.
5. **≤5 files per increment.** The suggested split, so no increment mixes concerns:
   **Inc-1** notes plumbing + A-2 retro-wire (AT-174, TC-410) · **Inc-2** row caps (AT-164…AT-169,
   TC-399…TC-405) · **Inc-3** A-1 byte-run bound (AT-172, AT-173, TC-406…TC-409) · **Inc-4**
   coexistence + AT-171 re-measure (AT-175). A-2 goes **first**: the other two amendments register
   appendix notes through the machinery it fixes, so building on the broken plumbing would bake the
   defect in.
6. **REQUIREMENTS.md**: add `R-TUI-079` (row caps), **`R-TUI-080`** (byte-run bound) and
   **`R-TUI-081`** (appendix completeness) with `Automated` status and the `AT-`/`TC-` lists; add the
   §6.5 Before/After amendment if any locked requirement's wording changes — **specifically check
   R-TUI-077**, whose `_format_bytes` exclusion (correct on *grammar* grounds) is what left the field
   with no *length* bound. That is an amendment to make explicitly, not a silent narrowing.
7. **BACKLOG:** replace the ≈17.3 variant-axis figure with **≈2.9 (worst case) / ≈100 (realistic)**
   before it ships (§6).

---

## 9. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Acceptance criteria in Given/When/Then | ✓ | §2, AT-164…AT-171 |
| 2 | Test cases have explicit Expected, never "works" | ✓ | §2 exact strings; §4 matrix "expected" column |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | §4: zero · all-filtered · 199 · 200 · 201 · 600 · multi-run · 512-char cells |
| 4 | Regression checklist exists | ✓ | §5 (drift set), §4 rows 1-3, AT-170 |
| 5 | Exit criteria stated | ✓ | §8 (RED-first, ledger, counterfactuals executed) |
| 6 | No real PII / secrets / client data | ✓ | every fixture synthetic; reports written to `tempfile.mkdtemp()`; `_assert_no_host_path_residue` (`tests/conftest.py:1040`) guards the golden |
| 7 | Results section left blank | ✓ | no AT/TC is reported as passing — none exists yet |
| 8 | **Layer B black-box through the shipped surface, with boundary + negative evidence** | ✓ | every AT calls `generate_project_report` and re-reads the `.md` from disk; §4 gives boundary + negative per cap |
| 9 | **Bidirectional surface-reachability** | ✓ | inputs (entry count, check-run count, cell width, filter, disposition) and outputs (row count, marker text, appendix line, aggregates, document bytes, document size) are each exercised/observed through `generate_project_report`, not a helper |
| 10 | **No unfilled template** | ✓ | no `<...>`, no `TC-NNN`; the one deferred item is the marker's final wording, explicitly delegated to Phase 1 in AT-165 |
| 11 | AT/TC/R ids verified on disk, not assumed | ✓ | §0 — repo-wide scan: AT max 163 (`tests/test_report_symbol_escape.py:24`), TC max 398, `R-TUI-079` free |
| 12 | Frozen-file list read from source | ✓ | `tests/test_tui_directionb.py:5457-5468` `_ENGINE_TEST_FILES` (9 files); no report test frozen |
| 13 | C-31 — every cap fixture provably over cap, multiple stated | ✓ | §4 binding rule; 3.0× / 1.005× / 4×0.75× named per AT |
| 14 | Every AT names a counterfactual mutation | ✓ | §2, one per AT |
| 15 | Emitted encoding verified by execution, not prediction | ✓ | §2 probe block — `#### Checklist: \`chk0.json\`` (Mode-B span), `### Checklists` plural, `\|---\|` separator form |
| 16 | Pre-existing-marker trap identified | ✓ | §2 ⚠ box — measured `'> TRUNCATED: 73 of 201 modified regions omitted (cap: 128 regions per variant).'` already present at 201 applied entries |
| 17 | AC-3 golden drift derived by execution (C-39) | ✓ | §5 — `[CAPPROBE] mod_max=133, chk_max=3` over 376 passing tests; drift set empty at CAP=200 |
| 18 | Multi-run checklist trap has its own node | ✓ | AT-167 + the stated mutation that leaves AT-166 green |
| 19 | No document-wide byte claim asserted | ✓ | §6 ruling; AT-171 scoped to one variant; ≈17.3-variant breach measured |
| 20 | Probes ran outside the reviewer's worktree | ✓ | all report roots `tempfile.mkdtemp()`; scripts in the session scratchpad; `git status` unchanged apart from this file |
| **21** | **[A-1] verified independently, not accepted on report** | ✓ | §10.2 — 1 row @ `MF_RUN_LENGTH_CEILING` → **6 294 029 B = 3.00× budget**, 0 markers; **35 rows × 10 000 B = 1.00× budget** with the row cap never firing |
| **22** | **[A-1] byte-run drift floor derived, not assumed** | ✓ | §10.1 — census over 376 tests: **1 196 `_format_bytes` calls, max run length exactly 256** at `tests/test_report_field_census.py:835`. `CELL_BYTES=256` has **zero** headroom |
| **23** | **[A-1] the fix's own failure mode has a node** | ✓ | AT-173 (verbatim at/under the bound) + TC-408 (`Length` not derived from the rendered cell) — an over-broad bound silently corrupting byte evidence is the worse failure |
| **24** | **[A-1] interaction with the batch-62 security pin checked** | ✓ | TC-409 — `test_f17_format_bytes_is_inert_by_construction:836` asserts `set(rendered) <= set("0123456789ABCDEF ")`; a non-hex truncation indicator breaks a batch-62 escaping guard |
| **25** | **[A-2] verified independently** | ✓ | §10.4 — decl-error cap alone: in-place marker fires, `## Truncation appendix` **entirely absent** from the document (worse than "entry missing") |
| **26** | **[COEX] multi-mechanism interaction measured before designing the AT** | ✓ | §10.4 — 3 mechanisms firing → 3 in-place markers, **2** appendix entries; the two present ones keep their own counts and do not overwrite (append-list, sound) |
| **27** | **[PARAM] no bare cap literal survives; deliberate pins justified** | ✓ | §2 [PARAM] import block + degeneracy guards; the only pinned numbers are TC-403 (`CAP > 133`) and TC-406 (`CELL_BYTES ≥ 256`), each a measured property of the *existing suite* |
| **28** | **Superseded own figure corrected, not quietly re-stated** | ✓ | §6 Before → After: REV-1's ≈17.3 variants → **≈2.9**; §10.0 records why REV 1 measured the wrong worst case |
| **29** | **Figure attributed to me but not mine is flagged** | ✓ | §10.0 — I produced no "1 147-call census"; my own is **1 196** calls over a named file set. The 256 value must not rest on a number neither lane can reproduce |
| **30** | Amendment marked with Before → After throughout | ✓ | header REV 2 note · §0 · §4 · AT-171 · §6 · §8 items 2 and 5 |

---

## 10. [REV 2] Amendment measurements — executed transcript

All figures below were produced on this tree (`claude/batch-63-report-table-caps` @ `031ca8d`,
Python 3.14.4) with report roots in `tempfile.mkdtemp()`. Nothing in the worktree was mutated.

### 10.0 Two corrections — read before using any number in this document

**(a) A figure was attributed to me that I did not produce.** The brief cites *"your own 1147-call
census"* as the basis for `REPORT_CELL_BYTES = 256`. **I produced no such census in REV 1** — REV 1
censused *table rows* (`mod_max=133`), never `_format_bytes`. I have now run the byte census for the
first time (§10.1): over the same 12 report-touching test files it is **1 196 calls** (1 193
value-bearing, 3 `None`), not 1 147. The gap is almost certainly a different file set, which is
exactly why it matters: a threshold justified by a census is only as good as the census's scope, and
neither of us can currently say what scope produced 1 147. **The 256 value should rest on §10.1's
stated file set, or on the architect's own census with its scope named — not on a number with no
reproducible derivation.** Flagging rather than adopting: an unearned credit becomes an unearned
premise one revision later.

**(b) One of my own REV-1 figures is superseded.** The ≈17.3-variants-to-breach number has been
adopted for the BACKLOG carry. It measured the wrong worst case — see §6's Before → After. The
correct worst-case figure is **≈2.9**. It must be replaced before it ships.

### 10.1 `_format_bytes` census — call count and byte-run drift floor

Same plugin technique as §5, wrapping `report_service._format_bytes` across the 12 report-touching
test files.

```
376 passed in 271.34s
[FBCENSUS] {"calls": 1196, "none_calls": 3, "max_len": 256,
            "max_site": "tests/test_report_field_census.py::test_f17_format_bytes_is_inert_by_construction (call)",
            "over_64": 1, "over_256": 0,
            "hist": {"1-4": 1192, "65-256": 1}}
```

| finding | value | consequence |
|---|---|---|
| value-bearing calls | 1 193 | the four byte cells are the hottest formatting path in the composer |
| **realistic run length** | **1 192 of 1 193 calls are 1–4 bytes** | any bound ≥ 16 is invisible to every realistic case |
| **maximum run length in the suite** | **exactly 256** | `CELL_BYTES = 256` sits **exactly at** the existing maximum — **zero headroom**, vs the row cap's 1.50× |
| that maximum's site | `tests/test_report_field_census.py:835`, `_format_bytes(range(256))` | a **direct unit call**, not through the composer → **no golden drifts** at any bound |
| calls over 256 | 0 | nothing in the suite exceeds the working bound |

**The consequence the number hides.** Because 256 is the maximum and not merely below it, the `>` vs
`>=` choice decides whether that call truncates. `test_f17_…` is self-referential
(`rendered = _format_bytes(range(256))`, then asserts on `rendered`), so it survives truncation
itself — **but line 836 asserts `set(rendered) <= set("0123456789ABCDEF ")`**. If the bound fires
there *and* the truncation indicator uses any non-hex character, that batch-62 escaping-inertness
pin goes RED. → TC-406 (the `>`/`>=` pin) and TC-409 (the indicator's alphabet).

### 10.2 [A-1] the row cap bounds neither table — independently reproduced

`MF_RUN_LENGTH_CEILING = 1 048 576` (`s19_app/tui/changes/io.py:232`);
budget `REPORT_MAX_TOTAL_BYTES = 2 097 152`.

```
rows=   1 run=1,048,576 B -> doc=   6,294,029 B ( 3.00x budget)  longest_line= 6,291,562  markers=0
rows=   1 run=   10,000 B -> doc=      62,573 B ( 0.03x budget)  longest_line=    60,106  markers=0
rows=  34 run=   10,000 B -> doc=   2,046,163 B ( 0.98x budget)  longest_line=    60,107  markers=0
rows=  35 run=   10,000 B -> doc=   2,106,272 B ( 1.00x budget)  longest_line=    60,107  markers=0
rows= 200 run=   10,000 B -> doc=  12,024,359 B ( 5.73x budget)  longest_line=    60,108  markers=0
rows= 200 run=      256 B -> doc=     331,559 B ( 0.16x budget)  longest_line=     1,644  markers=0
rows= 200 run=        4 B -> doc=      29,159 B ( 0.01x budget)  longest_line=       163  markers=0
```

Both architect figures reproduce exactly: **one** schema-legal entry reaches **3.00×** the budget, and
**35 rows** exhaust it while a 200-row cap never fires. `markers=0` throughout — the document does
not even claim a cut. The causal chain is worth pinning in the requirement text as the architect
noted: batch-62 excluded `_format_bytes` from escaping on correct *grammar* grounds (R-TUI-077,
`REQUIREMENTS.md:4781`), which is right — and left the field with no *length* limit, which is this
defect. An exclusion justified on one axis is not an exclusion on every axis.

### 10.3 [A-1 × R-TUI-079] the joint constraint surface

Post-A-1 single-variant worst case — both tables at `CAP` rows, text cells at `REPORT_CELL_CHARS`,
**all four byte cells at `CELL_BYTES`**. This is the true ceiling once A-1 lands.

**Multiple of the 2 MiB budget, ONE variant:**

```
 CAP\CELL_BYTES           16           32           64          128          256
            200       0.075x       0.093x       0.130x       0.203x       0.350x
            300       0.112x       0.140x       0.194x       0.304x       0.524x
            500       0.186x       0.232x       0.323x       0.506x       0.873x
```

**Variants-to-breach at each pair:**

```
 CAP\CELL_BYTES           16           32           64          128          256
            200         13.5         10.8          7.7          4.9          2.9
            300          9.0          7.2          5.2          3.3          1.9
            500          5.4          4.3          3.1          2.0          1.1
```

Single-variant scaling in `CAP` at `CELL_BYTES = 256`, measured directly:

| `CAP` | 1 variant | × budget | marginal/variant | variants to breach |
|---:|---:|---:|---:|---:|
| 200 | 733 576 B | 0.350× | 731 571 B | 2.9 |
| 256 | 938 256 B | 0.447× | 936 251 B | 2.2 |
| 400 | 1 464 576 B | 0.698× | 1 462 571 B | 1.4 |
| 500 | 1 830 076 B | 0.873× | 1 828 071 B | 1.1 |
| 1000 | 3 657 580 B | **1.744×** | 3 655 575 B | 0.6 |
| 2000 | 7 312 580 B | 3.487× | 7 310 575 B | 0.3 |

**Two things this gives the cap re-derivation:**
1. The stated constraint *"a single variant at cap stays inside 2 MiB post-A-1"* is a **binding
   ceiling**, not a formality: at `CELL_BYTES = 256` it caps the row cap at **≈570**. `CAP = 1000`
   breaches the budget with **one** variant.
2. The field datum (campaigns of *tens to ~200 entries*) sets the **floor** — comfortably above 200.
   Floor ≈ 200-plus-headroom, ceiling ≈ 570 at `CELL_BYTES = 256`. **The window is real but narrow,
   and it widens fast as `CELL_BYTES` drops**: at `CELL_BYTES = 64` the ceiling moves past 1 500.
   Given that **1 192 of 1 193** observed runs are 1–4 bytes (§10.1), a smaller `CELL_BYTES` costs
   almost nothing in fidelity and buys most of the cap window. That is the architect's call — this
   lane's contribution is that the two constants are **not independent** and the tradeoff is now
   measured rather than argued.

### 10.4 [A-2] [COEX] the shared appendix, today

```
=== decl-error cap ALONE: entries=10 issues=250 budget=2,097,152
  in-place markers:
    '> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).'
  appendix:
    <ABSENT>

=== regions + decl-errors: entries=200 issues=250 budget=2,097,152
  in-place markers:
    '> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).'
    '> TRUNCATED: 72 of 200 modified regions omitted (cap: 128 regions per variant).'
  appendix:
    '## Truncation appendix'
    "- Variant 'a': 72 of 200 modified regions omitted (cap: 128 regions per variant)."

=== regions + decl-errors + byte budget: entries=200 issues=250 budget=4,000
  in-place markers:
    '> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).'
    '> TRUNCATED: 72 of 200 modified regions omitted (cap: 128 regions per variant).'
    '> TRUNCATED: 1 hexdump block(s) omitted (report size cap: 4000 bytes).'
  appendix:
    '## Truncation appendix'
    "- Variant 'a': 72 of 200 modified regions omitted (cap: 128 regions per variant)."
    "- Variant 'a': 1 hexdump block(s) omitted (report size cap: 4000 bytes)."
```

**A-2 confirmed, and one degree worse than described.** With only the declaration-error cap firing,
the `## Truncation appendix` heading is **absent from the document entirely** — the appendix is
emitted only `if notes:` (`report_service.py:1674`), and `notes` is fed exclusively by
`_hexdump_section`. A reader who checks the appendix for cuts finds no appendix and concludes nothing
was cut, while 50 issues were dropped.

**COEX, the useful negative result.** With three mechanisms firing: **3** in-place markers, **2**
appendix entries. The two present entries each carry their own correct count and their own variant
prefix, and neither overwrites the other — `notes` is a plain `list.append`, which is sound. So
AT-175 is guarding **registration completeness and cross-variant attribution**, not a list bug. Worth
stating, because an AT written against an imagined list bug would assert the wrong property.

**Post-batch the document has five mechanisms** — modifications rows, checklist rows, declaration
errors, regions, byte budget — all writing into one appendix. Two variants × five mechanisms = ten
entries, and AT-175's fixture gives the two variants **different** populations so a cross-variant
conflation cannot hide behind equal numbers.

### 10.5 Emitted-encoding pins added in REV 2

Verified by running the composer, per the standing discipline:

```
'> TRUNCATED: 50 of 250 declaration errors omitted (cap: 200 issues per variant).'
'> TRUNCATED: 1 hexdump block(s) omitted (report size cap: 4000 bytes).'
"- Variant 'a': 72 of 200 modified regions omitted (cap: 128 regions per variant)."
```

Note the appendix entry is `- Variant 'a': …` — **single** quotes, and the trailing period belongs to
the note text, not the list item. The hexdump marker says `block(s)`, with the literal parenthesised
plural. Neither is guessable from the requirement prose; both are asserted verbatim by AT-174 and
AT-175.
