# Increment Plan — s19_app — batch-03

> **Phase 3 (Implementation) — increment plan.** Functional Patch Editor +
> ASAM CDFX (`.cdfx`) read/write. Source contract:
> [`01-requirements.md`](../01-requirements.md) — 7 US / 8 HLR / **44 LLR / 47 TC**.
> Phase 2 closure: [`02-review.md`](../02-review.md) — verdict **pass**;
> CV-01..CV-04 folded into increment 1 / increment 6.
>
> **Branch:** `dev-flow/batch-02-direction-b-restyle` (work continues here).
> **Test baseline (batch-02):** 419 passed / 2 skipped / 3 xfailed / 0 failed.
> **Test baseline after increment 4 (current head):** 499 passed / 2 skipped /
> 3 xfailed / 0 failed.
> Every increment keeps `s19tui` runnable and the full suite green.

---

> ## ⚠ Phase-3 amendment — re-plan from increment 5 (2026-05-21)
>
> A Phase-3 requirements amendment changed the CDFX contract **after**
> increments 1–4 had shipped. The amendment is now folded into
> [`01-requirements.md`](../01-requirements.md) (44 LLR / 47 TC). The four
> changes that force a re-plan:
>
> 1. **`ChangeListEntry.array_index` becomes `Optional[int]`** (LLR-001.1
>    rewritten). `None` ≙ scalar / ASCII-string entry; an integer *k* ≙
>    element *k* of a 1-D array. The iteration-3 model used `int` with default
>    `0`, which made a scalar entry and element 0 of an array
>    indistinguishable — the writer could not pick `VALUE`-vs-`VAL_BLK`. This
>    reopens the **already-shipped** increment-1 model (`changelist.py`) and
>    ripples to the resolver (`resolve.py`, LLR-002.3 — only an integer index
>    is range-checked) and the writer (`writer.py`).
> 2. **New LLR-004.9 — writer coalesces array entries.** The writer must
>    collapse all integer-`array_index` entries that share a `parameter_name`
>    into **one** `VAL_BLK` `SW-INSTANCE` (one `VG` of ascending positional
>    `V`), and **reject** a sparse / non-zero-based array group as one
>    `W-ARRAY-SPARSE` warning with no `SW-INSTANCE`. Increment 4's writer
>    emits one `SW-INSTANCE` per entry — this is the exact "structural
>    divergence" increment 4's review packet §5 flagged for `architect`. The
>    amendment is the architect's resolution: **the writer coalesces.**
> 3. **New LLR-005.6 — reader expands `VAL_BLK`.** The reader must expand a
>    `VAL_BLK` instance with an *N*-`V` `VG` back into *N* entries
>    `(name, 0…N-1)`, a `VALUE`/`BOOLEAN` instance into one `array_index=None`
>    entry, an `ASCII` instance into one `array_index=None` string entry — the
>    read-side inverse of LLR-004.9.
> 4. **Two new test cases** — `TC-038` (writer coalescing + `W-ARRAY-SPARSE`),
>    `TC-039` (reader `VAL_BLK`/`VALUE`/`ASCII` expansion); the new code
>    `W-ARRAY-SPARSE` joins the `W-*` set; `TC-024` round-trip is extended to
>    assert the coalesce→expand `Optional[int]`-key shape.
>
> **Why the original 9-increment plan no longer fits.** The original plan
> assumed increments 1–4 were frozen and only increments 5–9 remained. The
> amendment reopens `changelist.py` + `resolve.py` + `writer.py` — three
> already-shipped production files plus their three test files = **six files
> of migration work** that did not exist as a planned increment. Folding the
> migration into the original increment 5 (reader, already 3 files) would
> break the ≤5-file cap and mix a model migration with new reader code. The
> re-plan therefore **inserts a dedicated migration increment** and renumbers
> the reader/safety/UI/hardening work after it. **Increments 1–4 are
> unchanged history** and recorded below as **DONE**; the new sequence is
> **increments 5–11** (was 5–9).
>
> The §0–§4 sections below the "Increments 1–4 — shipped record" heading are
> the **superseded original plan** kept for provenance; the **authoritative
> remaining plan is §A onward.**

---

## Increments 1–4 — shipped record (DONE — do not re-open except per the amendment)

| # | Title | LLRs | Files shipped | Status | Review packet |
|---|-------|------|---------------|--------|---------------|
| 1 | Change-list model | LLR-001.1..001.4, LLR-003.3 (model arm) | `cdfx/__init__.py`, `cdfx/changelist.py`, `tests/test_cdfx_changelist.py` | **DONE** — 16 tests, suite 435 green | [increment-001.md](./increment-001.md) |
| 2 | A2L parameter resolution | LLR-002.1..002.4 | `cdfx/resolve.py`, `tests/test_cdfx_resolve.py` | **DONE** — 14 tests, suite 449 green | [increment-002.md](./increment-002.md) |
| 3 | Type-driven value display | LLR-003.1, LLR-003.2, LLR-003.3 (display arm) | `cdfx/display.py`, `tests/test_cdfx_display.py` | **DONE** — 17 tests, suite 466 green | [increment-003.md](./increment-003.md) |
| 4 | CDFX writer + `W-*` validator | LLR-004.1..004.8, LLR-006.1 (partial) | `cdfx/writer.py`, `tests/test_cdfx_writer.py`, `tests/test_cdfx_w_rules.py` | **DONE** — 33 tests, suite 499 green | [increment-004.md](./increment-004.md) |

**Amendment impact on the shipped record.** Three shipped production files are
re-opened by the Phase-3 amendment — this is expected and is the whole reason
for the re-plan, not a regression:

- `cdfx/changelist.py` — `array_index` `int`→`Optional[int]`; `EntryKey`
  becomes `tuple[str, int | None]`; `add`/`edit`/`remove`/`get` default
  `array_index` `0`→`None`. **Re-opened by increment 5.**
- `cdfx/resolve.py` — LLR-002.3 range-check applies only when `array_index`
  is an integer; a `None`-index entry resolves on name alone. **Re-opened by
  increment 5.**
- `cdfx/writer.py` — LLR-004.2/.3/.9: coalesce integer-`array_index` entries
  into one `VAL_BLK` `SW-INSTANCE`; `None`-index ⇒ scalar/string; reject
  sparse arrays (`W-ARRAY-SPARSE`). **Re-opened by increment 7.**

Increment 4's review packet §5 explicitly flagged "VAL_BLK serialization is
one `SW-INSTANCE` per change-list entry … Decision needed before increment 8:
either the reader treats repeated `SHORT-NAME`s as array elements, or the
writer coalesces same-name entries — surface to `architect`." The Phase-3
amendment **is** that architect decision: the writer coalesces (LLR-004.9),
the reader expands (LLR-005.6). The re-plan executes it.

---

# §A. Authoritative remaining plan — increments 5–11

## A.0 Module placement (unchanged from the original plan)

The decision of the original §0 stands: the CDFX concern is a package
`s19_app/tui/cdfx/` (`__init__.py` / `changelist.py` / `resolve.py` /
`display.py` / `writer.py` / `reader.py`), with a thin
`tui/services/cdfx_service.py` added in the UI increment. No new convention is
introduced. `ValidationIssue` carries `artifact="cdfx"` — no model change.

## A.1 Increment summary — increments 5–11

**Seven increments.** The Phase-3 amendment splits the original 5-increment
tail (5–9) into seven: a dedicated **model+resolver migration** increment is
inserted first (the amendment's `Optional[int]` ripple), and the **writer
coalescing rework** is its own increment (LLR-004.9 + `W-ARRAY-SPARSE`)
instead of being folded into the reader. Dependency-ordered, each ≤5 files,
each leaving the suite green.

| # | Title | LLRs | TC count | Files |
|---|-------|------|----------|-------|
| 5 | `Optional[int]` model + resolver migration | LLR-001.1, 001.3, 002.3 *(re-stated)* | 3 *(re-verified: TC-001, TC-002, TC-006)* | 4 |
| 6 | Writer coalescing rework + `W-ARRAY-SPARSE` | LLR-004.2, 004.3, 004.9; LLR-006.1 *(extended)* | 4 *(TC-012, TC-013 re-verified; TC-038 new; TC-019h re-verified)* | 3 |
| 7 | CDFX reader + `R-*` validation + `VAL_BLK` expansion | LLR-005.1..005.4, 005.6, LLR-006.2/.3/.4/.5/.7, LLR-008.1..008.3 | 15 | 4 |
| 8 | XML-safety + load/write path containment | LLR-005.5, 006.6, 006.8, 007.7 | 6 | 5 |
| 9 | Functional Patch Editor screen | LLR-007.1..007.6 | 4 | 5 |
| 10 | Round-trip + adversarial-float hardening | LLR-004.8, 004.9, 005.1, 005.6 *(round-trip verdict)* | 2 *(TC-024, TC-033 read-back)* | 2 |
| 11 | Integration save/load + containment UI tests | LLR-007.3, 007.4, 007.7 *(integration)* | 3 | 3 |

**LLR coverage check (all 44).** Increments 1–4 (shipped) claim
LLR-001.x, 002.x, 003.x, 004.1..004.8, 006.1 (partial). The remaining LLRs:

- LLR-004.9 → increment 6.
- LLR-005.1..005.4, 005.6 → increment 7; LLR-005.5 → increment 8.
- LLR-006.1 (final, incl. `W-ARRAY-SPARSE`) → increment 6;
  LLR-006.2/.3/.4/.5/.7 → increment 7; LLR-006.6, 006.8 → increment 8.
- LLR-007.1..007.6 → increment 9; LLR-007.7 → increment 8.
- LLR-008.1..008.3 → increment 7.

Increment 5 re-states LLR-001.1/001.3/002.3 (no new LLR — it migrates the
already-claimed ones to the amended contract). Increments 10–11 add no new
LLR — they deepen the test verdict for LLRs already implemented (TC-024
round-trip, TC-026/036 integration).

**TC coverage check (all 47).** TC-001..TC-018, TC-019a..h, TC-020..TC-026,
TC-027a/b, TC-028..TC-039 = 47. Increments 1–4 shipped TC-001..TC-014,
TC-019a..h, TC-032, TC-033 (writer arm). Increment 5 re-verifies
TC-001/002/006 against the migrated model. Increment 6 ships TC-038 and
re-verifies TC-012/013/019h. Increment 7 ships TC-015..TC-018, TC-020..TC-023,
TC-029..TC-031, TC-034, TC-039. Increment 8 ships TC-027a/b, TC-035, TC-036
(function arm), TC-037. Increment 9 ships TC-025, TC-026, TC-028, TC-027a
(integration arm). Increment 10 ships TC-024 and TC-033's read-back arm.
Increment 11 deepens TC-026 / TC-036 / TC-027a integration.

## A.2 Per-increment one-line scope — increments 5–11

5. **`Optional[int]` model + resolver migration** — migrate
   `ChangeListEntry.array_index` to `Optional[int]` (`None` = scalar/string,
   integer = array element), `EntryKey` to `tuple[str, int | None]`,
   `add`/`edit`/`remove`/`get` defaults `0`→`None`; update the resolver so the
   LLR-002.3 range check applies only to integer indices; re-verify
   TC-001/002/006 and the four already-shipped test files for the new shape.
6. **Writer coalescing rework + `W-ARRAY-SPARSE`** — rework `writer.py` so
   integer-`array_index` entries sharing a `parameter_name` coalesce into one
   `VAL_BLK` `SW-INSTANCE` (one ascending-index `VG`), `None`-index entries
   stay one-`SW-INSTANCE`-each scalar/string; reject sparse / non-zero-based
   array groups as `W-ARRAY-SPARSE`; TC-038 new, TC-012/013/019h re-verified.
7. **CDFX reader + `R-*` validation + `VAL_BLK` expansion** — `read_cdfx`:
   namespace-tolerant, instance-tree-scoped `SW-INSTANCE` lookup, `V`/`VG`/`VT`
   decode, `VAL_BLK`→*N* entries / `VALUE`→one `None`-index / `ASCII`→one
   `None`-index expansion (LLR-005.6), all core `R-*` codes, version /
   tool-note tolerance, A2L name + array-length cross-checks.
8. **XML-safety + path containment** — DOCTYPE/`<!ENTITY>` rejection via an
   `expat`-level hook (CV-04), 256 MB / nesting-depth bounds, load-path
   `resolve_input_path`, write-path `copy_into_workarea` containment.
9. **Functional Patch Editor screen** — replace the inert `PatchEditorPanel`:
   change-list rows, wired add/edit/remove inputs, save/load actions, empty
   state; `cdfx_service` orchestration; `app.py` holds UI wiring only.
10. **Round-trip + adversarial-float hardening** — TC-024 write→read
    structural equality including the `Optional[int]` key shape (scalar →
    `None`, *N*-array → `(name,0)…(name,N-1)`) and the three adversarial
    IEEE floats.
11. **Integration save/load + containment UI tests** — drive save/load and the
    work-area containment / dedup / reparse-point rejection through
    `App.run_test()`.

---

## A.3 Increment 5 — `Optional[int]` model + resolver migration — FULL DETAIL

### Number & title
**Increment 5 — `Optional[int]` change-list model + resolver migration.**

### Purpose
Execute the Phase-3 amendment's foundational contract change before any new
code is written on top of it. The amendment makes
`ChangeListEntry.array_index` `Optional[int]` — `None` for a scalar/string
parameter, an integer *k* for element *k* of a 1-D array (LLR-001.1 rewritten)
— so the writer (increment 6) and reader (increment 7) have an unambiguous
scalar-vs-array discriminator. This is a **migration of already-shipped code**,
not a greenfield increment: it re-opens increment 1's `changelist.py` and
increment 2's `resolve.py` and their test modules. It deliberately ships
**before** the writer rework so the coalescing increment builds on the final
model. No reader, no XML, no UI — the increment is fully unit-testable and the
app runs unchanged (the model is still unreachable from the UI).

This increment also applies **CV-01..CV-03** (the Phase-2 closure cosmetic
doc / test-comment items still open from increment 1) where the migration
already edits the relevant files — opportunistically, consuming no extra slot.

### LLRs implemented *(re-stated to the amended contract — no new LLR number)*
- **LLR-001.1** *(rewritten)* — `array_index` is `Optional[int]`: `None` for a
  scalar (`VALUE`/`BOOLEAN`) and for an ASCII string parameter; a non-negative
  integer *k* for element *k* of a 1-D array (`VAL_BLK`).
- **LLR-001.3** *(rewritten)* — entry identity is `(parameter_name,
  array_index)` with `array_index` `Optional[int]`; `(name, None)` and
  `(name, 0)` are now **distinct** identities (scalar entry vs. array element
  0); a re-add on an existing identity still updates in place.
- **LLR-002.3** *(rewritten)* — the array-index range check applies **only**
  when `array_index` is an integer; an entry whose `array_index` is `None`
  (scalar/string) is not range-checked and resolves on name alone.

> No LLR number is added in increment 5 — LLR-004.9 and LLR-005.6 (the two
> genuinely new LLRs) land in increments 6 and 7. Increment 5 only migrates
> already-claimed LLRs to the amended statements.

### Test cases — *re-verification*, not new TCs
- **TC-001** *(re-verified)* — entry construction: an entry built with
  name+index reports its four fields; a **scalar** entry and an **ASCII**
  entry each carry `array_index is None`; an array-element entry carries an
  integer index; `(name, None)` and `(name, 0)` are **distinct** identities.
  *(method U.)* The increment-1 `test_cdfx_changelist.py` TC-001 tests asserted
  the old `array_index == 0` scalar default — those assertions are **updated**
  to the `None` contract in this increment.
- **TC-002** *(re-verified)* — add / edit / remove and identity dedup: the
  increment-1 tests are re-run against the migrated `add`/`edit`/`remove`
  signatures (default `array_index` `None`); the dedup test that distinguished
  array index is extended to assert `(name, None)` ≠ `(name, 0)`.
- **TC-006** *(re-verified)* — array-index range check: integer index `5` on a
  3-element array parameter is `index-out-of-range`; a **scalar** entry
  (`array_index is None`) against a scalar A2L parameter (`element_count == 1`)
  resolves normally and is **not** range-checked. The increment-2
  `test_cdfx_resolve.py` TC-006 test is updated to the `Optional[int]`
  contract.

> Why no new TC: the Phase-3 amendment did not add a TC for the model
> migration — TC-001/002/006 already exist and the §5.3/§5.7 catalogue
> rows for them were rewritten to the `Optional[int]` contract. Increment 5's
> verdict is that those existing TCs are green against the migrated code. The
> two genuinely new TCs (TC-038, TC-039) land with their LLRs in increments
> 6 / 7.

### Files (4, all ≤5)
| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/changelist.py` | **modified** | Migrate `array_index` `int`→`Optional[int]` (default `None`); `EntryKey` `tuple[str, int]`→`tuple[str, int | None]`; `PhysicalValue` docstring unchanged; `add`/`edit`/`remove`/`get` default `array_index` `0`→`None`; update `ChangeListEntry`/`ChangeList` docstrings (Args, Data Flow, Example) to the `None`-is-scalar contract. No behavior change to dedup/ordering beyond the key-type widening. |
| `s19_app/tui/cdfx/resolve.py` | **modified** | `_resolve_entry`: range-check `array_index` only when it is an `int` — a `None` index skips the LLR-002.3 check and resolves on name alone; update `_resolve_entry`/`resolve_against_a2l` docstrings. `_element_count_of` unchanged. |
| `tests/test_cdfx_changelist.py` | **modified** | Update TC-001/002/003/010 assertions to the `Optional[int]` contract; extend the dedup TC to assert `(name, None)` ≠ `(name, 0)`; migrate the `change_list_factory` helper so a scalar/string entry is built with `array_index=None` and an array parameter is the per-element `(name, k)` set. Apply CV-02 (test-comment tightening) here. |
| `tests/test_cdfx_resolve.py` | **modified** | Update TC-006 so the scalar arm uses `array_index=None`; re-confirm TC-004/005/007 still pass under the migrated model. Apply CV-03 (TC-row-comment tightening) here. |

> `cdfx/writer.py`, `tests/test_cdfx_writer.py`, `tests/test_cdfx_w_rules.py`
> are **not** touched by increment 5 — they keep building entries with the old
> positional `array_index=0` calls, which still type-check (`0` is a valid
> `int` for `Optional[int]`) and still pass. The writer's *behavior* migration
> (coalescing) is increment 6; increment 5 only widens the model so increment
> 6 can rely on the discriminator. This keeps increment 5 at exactly 4 files.
> `tests/test_cdfx_display.py` is likewise untouched — `display.py` reads
> `value`/`datatype`/`char_type`, never `array_index`.

### Dependencies
Increments 1–2 (the files being migrated). Pure stdlib (`dataclasses`, `enum`,
`typing`) — no `a2l.py`, `ElementTree`, or Textual import added.

### Risks
- **`array_index=0` callers in increment-4 writer tests.** The increment-4
  writer test files build entries with positional `array_index=0` for what
  were "scalar" entries. After the migration, `0` means **array element 0**,
  not scalar. Those tests **still pass** in increment 5 (the writer still emits
  one `SW-INSTANCE` per entry — coalescing is increment 6), but they are
  **semantically stale**. *Mitigation:* increment 5 does **not** touch the
  writer test files (keeps the 4-file cap and the increment-6 boundary clean);
  increment 6's writer rework is where those tests are rewritten to
  `array_index=None` for scalars. This is recorded as a **planned, deferred
  test correction**, surfaced in both increment-5 and increment-6 review
  packets so Phase 4 does not read a stale `array_index=0` scalar as a defect.
- **`EntryKey` widening and `dict` hashing.** `tuple[str, None]` and
  `tuple[str, int]` are both hashable and never collide, so the backing `dict`
  is correct without change. *Mitigation:* TC-002's dedup test explicitly
  asserts `(name, None)` and `(name, 0)` are distinct keys — a regression here
  fails loudly.
- **Resolver `None`-index arithmetic.** The current `_resolve_entry` does
  `entry.array_index < 0 or entry.array_index >= count` — `None < 0` raises
  `TypeError` in Python 3. *Mitigation:* the migration guards the comparison
  with `isinstance(entry.array_index, int)`; TC-006's scalar-`None` arm proves
  the guard (without it, every scalar entry would crash resolution).
- **`change_list_factory` shape drift.** The factory currently lives in
  `tests/test_cdfx_changelist.py` and builds array entries; migrating it to the
  `(name, k)` integer-index / `None`-scalar shape must not break the writer
  tests that import nothing from it (they use local `_resolved_change_list`
  helpers — confirmed in increment-4 packet §6). *Mitigation:* factory change
  is contained to `test_cdfx_changelist.py`; the `conftest.py` relocation
  stays an increment-10 call (it is where the adversarial-float arm is added).

### Stop boundary
Increment 5 ends when `tests/test_cdfx_changelist.py` and
`tests/test_cdfx_resolve.py` are green against the migrated model, the full
suite is still 499 green (no count change — the migration re-verifies existing
tests, it adds none), and `s19tui` launches unchanged. Deliver the 7-section
review packet. **Do not** start the writer rework (increment 6).

---

## A.4 Increments 6–11 — scope, LLRs, TCs, files, deps, risks

### Increment 6 — Writer coalescing rework + `W-ARRAY-SPARSE`
- **LLRs:** LLR-004.2 *(rewritten — one `SW-INSTANCE` per distinct resolved
  `parameter_name`, not per entry)*, LLR-004.3 *(rewritten — `None`-index ⇒
  bare `V` / `VT`; integer-index group ⇒ one `VG`)*, **LLR-004.9 (new —
  coalesce array entries; reject sparse arrays)**, LLR-006.1 *(extended — the
  `W-ARRAY-SPARSE` writer-behavior code joins the `W-*` set)*.
- **TCs:** **TC-038 (new)** — writer coalescing + sparse-array rejection;
  **TC-012, TC-013** re-verified (one `SW-INSTANCE` per *parameter*, not per
  entry; the `VG` carries one `V` per element); **TC-019h** re-verified (a
  change-list whose only entries are a sparse group yields backbone-only +
  `W-ARRAY-SPARSE` + `W-EMPTY-CHANGELIST`). 4 TCs.
- **Files (3):**
  - `s19_app/tui/cdfx/writer.py` *(modified)* — before emitting `SW-INSTANCE`
    elements, **group** resolved entries by `parameter_name`: a group of
    integer-`array_index` entries coalesces into one `VAL_BLK` `SW-INSTANCE`
    with one `VG` of positional `V` ordered ascending by `array_index`
    (LLR-004.9); a `None`-index entry stays its own `VALUE`/`BOOLEAN`
    (bare `V`) or `ASCII` (`VT`) instance (LLR-004.3). A group whose integer
    indices are **not** the contiguous gapless zero-based sequence
    `0…N-1` is rejected: no `SW-INSTANCE`, one `W-ARRAY-SPARSE` warning naming
    the parameter, no synthesized `V` (LLR-004.9 sparse rule). `W-ARRAY-SPARSE`
    exclusion feeds the LLR-004.6 zero-writable accounting exactly as
    `W-INSTANCE-EXCLUDED` does.
  - `tests/test_cdfx_writer.py` *(modified)* — rewrite the increment-4 scalar
    tests to build scalars with `array_index=None`; add the TC-013 array arm
    that asserts three `(PARAM, 0..2)` entries → one `VAL_BLK` instance with a
    three-`V` `VG`; re-verify TC-012 ("one instance per parameter").
  - `tests/test_cdfx_w_rules.py` *(modified)* — add TC-038's `W-ARRAY-SPARSE`
    cases (gap group, non-zero-based group, sparse-only change-list →
    backbone-only + `W-ARRAY-SPARSE` + `W-EMPTY-CHANGELIST`); re-verify
    TC-019h.
- **Dependencies:** increment 5 (the migrated `Optional[int]` model — the
  coalescing **depends** on `None`-vs-integer being the discriminator);
  increment 4's writer (the file being reworked).
- **Risks:**
  - **Grouping must not break insertion-order determinism (LLR-001.4).** The
    writer currently iterates `ChangeList.entries` (insertion order) with no
    second rule. Coalescing introduces grouping — the `SW-INSTANCE` order must
    still be deterministic. *Mitigation:* emit one `SW-INSTANCE` per
    `parameter_name` in the order of **first appearance** of that name in
    `ChangeList.entries`; within a group the `V` order is ascending
    `array_index`. Two rules, both deterministic, both pinned by a re-verified
    TC-012 byte-identical assertion.
  - **A `None`-index entry and an integer-index entry under the same name.**
    LLR-001.3's rationale says a parameter is either scalar or array, never
    both, and resolution confirms which — so `(PARAM, None)` and `(PARAM, 0)`
    never legitimately coexist. But the model *allows* it. *Mitigation:* the
    writer treats them as two separate groups (a scalar group and an array
    group) and emits each per its category; it does **not** invent a merge
    rule. If this produces two same-`SHORT-NAME` instances that is a
    resolution-stage inconsistency, not a writer bug — recorded, not
    speculatively handled (engineering rule 2).
  - **Sparse detection vs. the round-trip guarantee.** LLR-004.9's round-trip
    clause requires coalesce-on-write then expand-on-read to reproduce the key
    set exactly. The sparse rule is what makes this safe (no gap-filling).
    *Mitigation:* TC-038 asserts the writer never emits a `V` for a missing
    index; the full round-trip verdict is TC-024 (increment 10).
- **Handoff:** the `W-ARRAY-SPARSE` exclusion is a fail-loud calibration-safety
  decision (rejecting rather than gap-filling an unintended ECU value) — note
  it for `qa-reviewer` as part of the increment-9 acceptance criteria, and
  flag the writer-behavior-code addition to `security-reviewer` only if they
  are already reviewing increment 8 (no standalone review needed — it is a
  pure structural rule, no I/O).

### Increment 7 — CDFX reader + `R-*` validation + `VAL_BLK` expansion
- **LLRs:** LLR-005.1..005.4, **LLR-005.6 (new — expand `VAL_BLK`/`VALUE`/
  `ASCII` into the `Optional[int]` entry shape)**, LLR-006.2, 006.3, 006.4,
  006.5, 006.7, LLR-008.1..008.3. *(LLR-005.5, 006.6, 006.8 — the path/safety
  layer — are increment 8.)*
- **TCs:** TC-015, TC-016, TC-017, TC-018, TC-020, TC-021, TC-022, TC-023,
  TC-029, TC-030, TC-031, TC-034, **TC-039 (new)** — 13 here. (TC-027a/b,
  TC-035, TC-037 are increment 8; TC-024 is increment 10.) **15 TCs across
  inc7+8** for the LLR-005.x/006.x/008.x band.
- **Files (4):**
  - `s19_app/tui/cdfx/reader.py` *(new)* — `read_cdfx(path_or_bytes,
    a2l_data=None)`: `ElementTree` parse, namespace-stripping local-name match
    (`_local_name` helper, A-06/RK-3), `SW-INSTANCE` lookup **scoped to the
    `SW-INSTANCE-TREE` backbone** (S-006), `V`/`VG`/`VT` decode
    (decimal/exp/hex; `0b` tolerant-superset, OQ-7), the **`VAL_BLK` expansion**
    of LLR-005.6 — a `VAL_BLK` instance with an *N*-`V` `VG` → *N* entries
    `(name, 0…N-1)`, a `VALUE`/`BOOLEAN` instance → one entry
    `array_index=None`, an `ASCII` instance → one string entry
    `array_index=None` — all core `R-*` codes, `R-VERSION-UNKNOWN` tolerance,
    `R-CATEGORY-UNSUPPORTED` read-only handling, tool-note tolerance, and the
    A2L name / array-length cross-checks. *(This file is extended by
    increment 8 with the safety layer.)*
  - `s19_app/tui/cdfx/__init__.py` *(modified)* — re-export `read_cdfx` so the
    increment-9 service has one import surface. (The `write_cdfx` /
    `validate_w_rules` re-export the original plan deferred is also added here,
    folding that pending item in — one cohesive `__init__` edit.)
  - `tests/test_cdfx_reader.py` *(new)* — TC-015..TC-018, TC-022, TC-034,
    **TC-039** (the `VAL_BLK`→*N*-entry / `VALUE`→`None` / `ASCII`→`None`
    expansion).
  - `tests/test_cdfx_r_rules.py` *(new)* — TC-020, TC-021, TC-023, TC-029,
    TC-030, TC-031; adds `make_minimal_cdfx`, `make_malformed_cdfx`,
    `make_variant_cdfx`, `make_tool_note_cdfx`, `make_rule_violation_cdfx`
    (each violation fixture carries a valid sibling instance — Q-04).
- **Dependencies:** increment 5 (the migrated `Optional[int]` model — the
  reader **produces** `None`-index scalars and integer-index array entries),
  increment 6 (the reworked writer — `make_minimal_cdfx`'s `VAL_BLK` shape
  must match what the coalescing writer emits, so the increment-10 round-trip
  closes); increments 1–2 (model + A2L for the cross-check).
- **Risks:**
  - **LLR-005.6 expansion must mirror LLR-004.9 coalescing exactly.** A reader
    that expanded a `VAL_BLK` to `(name, 1..N)` instead of `(name, 0..N-1)`, or
    gave a `VALUE` instance `array_index=0` instead of `None`, would break the
    round-trip silently. *Mitigation:* TC-039 pins all three shapes
    explicitly; the increment-10 TC-024 round-trip is the end-to-end
    cross-check against the increment-6 writer.
  - **Namespace handling** — a default `xmlns` makes `ElementTree` return
    `{uri}Local` tags. *Mitigation:* `_local_name()` strips `{...}`; every
    match goes through it; TC-017 feeds a namespaced fixture.
  - **Collect-don't-abort** — a violating instance must not abort the tree
    (Q-04). *Mitigation:* the reader loops instances, appends a
    `ValidationIssue` per violation, continues; every `make_rule_violation_cdfx`
    variant carries a valid sibling TC-020 asserts is recovered.
  - **Cross-check skipped cleanly when `a2l_data is None`** (LLR-008.3) —
    TC-031 pins it.
  - **A foreign `VAL_BLK` whose `V` count ≠ A2L `element_count`** is still
    expanded positionally (LLR-005.6) and the mismatch is a separate
    `R-ARRAY-LEN-MISMATCH` warning (LLR-008.2) — the two concerns must not be
    conflated. *Mitigation:* expansion is unconditional; the cross-check is a
    separate pass; TC-030 + TC-039 cover the two independently.

### Increment 8 — XML-safety + load/write path containment
- **LLRs:** LLR-005.5 (load-path `resolve_input_path`), LLR-006.6
  (DOCTYPE/`<!ENTITY>` rejection), LLR-006.8 (256 MB / nesting-depth bound),
  LLR-007.7 (write-path `copy_into_workarea` containment).
- **TCs:** TC-027a, TC-027b, TC-035, TC-036 (unit/seam arm — the integration
  arm is increment 11), TC-037 — 6 (counting TC-027a/b unit arms and the
  TC-036 containment-function arm).
- **Files (5):**
  - `s19_app/tui/cdfx/reader.py` *(extended)* — pre-parse size check
    (injectable `size_probe` seam, `DEFAULT_COPY_SIZE_CAP_BYTES`), an
    `XMLParser` whose **`expat`-level `StartDoctypeDeclHandler` / entity-decl
    handler raises before any entity expansion** (CV-04 hand-off — the hook
    must fire *before* expansion, not after), nesting-depth bound, all surfaced
    as one `R-XML-PARSE` issue; the `resolve_input_path` call on the load path
    (LLR-005.5).
  - `s19_app/tui/cdfx/writer.py` *(extended)* — `write_cdfx` resolves and
    containment-validates its target by **reusing** `workspace.copy_into_workarea`
    / `_path_traverses_reparse_point` (no re-implementation): target under
    `.s19tool/workarea/`, reparse-point rejection, dedup-suffix on collision;
    rejections surfaced as a write-side `ValidationIssue`.
  - `tests/test_cdfx_safety.py` *(new)* — TC-027a, TC-027b (sentinel-file
    no-read detection), TC-035 (size-probe seam + deep-nest arm); adds
    `make_billion_laughs_cdfx`, `make_external_entity_cdfx`,
    `make_oversized_cdfx`.
  - `tests/test_cdfx_path_containment.py` *(new)* — TC-036 (write-target
    containment / dedup / reparse-point rejection at the function level),
    TC-037 (load-path `resolve_input_path` + no-open spy).
- **Dependencies:** increments 6–7 (writer + reader to harden);
  `s19_app/tui/workspace.py` (`copy_into_workarea`,
  `_path_traverses_reparse_point`, `resolve_input_path`,
  `DEFAULT_COPY_SIZE_CAP_BYTES` — all read-only reuse).
- **Risks:**
  - **CV-04 hook ordering** — stdlib `ElementTree` expands internal entities;
    the DOCTYPE handler must be wired at the `expat` parser level
    (`parser.parser.StartDoctypeDeclHandler` / `EntityDeclHandler`) so it
    raises on the *declaration*, **before** any entity is expanded. A handler
    attached too late would let billion-laughs amplify. *Mitigation:* implement
    and verify with TC-027a asserting no entity text appears in any node; the
    implementer confirms the chosen `expat` hook (explicit CV-04 hand-off).
  - **`copy_into_workarea` is a *copy* helper (source→dest)** — the writer
    produces bytes, not a source file. *Mitigation:* writer writes to a
    workarea temp path, then either calls `copy_into_workarea` for the
    containment-checked final placement, or factors the containment guard
    (`_find_workarea_root` + `_path_traverses_reparse_point` + dedup) into a
    small reused `resolve_workarea_target` helper — **decide at implementation,
    surface in the review packet**; **no new write path** (DD-10). *If
    `copy_into_workarea` cannot be reused as-is, raise the "extract a
    `resolve_workarea_target` helper vs. write-then-copy" choice to `architect`
    before implementing.*
  - **TC-036's reparse-point arm** needs a visible `skipif`/`xfail` on CI
    images lacking symlink privilege (CV-03).
- **Handoff:** **security-reviewer** — this whole increment (the
  DOCTYPE/`<!ENTITY>` rejection, the CV-04 `expat` hook ordering, the
  size/depth bounds, the `copy_into_workarea` write-path reuse) is
  security-sensitive; **request review before it merges.** TC-027a/b are
  explicitly Phase-2-security-reviewed (§5.9 #6).

### Increment 9 — Functional Patch Editor screen
- **LLRs:** LLR-007.1 (render the change-list), 007.2 (wire add/edit/remove),
  007.3 (save action), 007.4 (load action), 007.5 (handler outside `app.py`),
  007.6 (empty state).
- **TCs:** TC-025 (render/edit/empty-state), TC-026 (save/load), TC-028
  (inspection — handler outside `app.py`), TC-027a integration arm — 4.
- **Files (5):**
  - `s19_app/tui/screens_directionb.py` *(modified)* — replace
    `PatchEditorPanel`'s inert shell with: a change-list rows region (a row per
    entry showing name, **array index — blank for a `None`-index scalar**,
    displayed value, status), name/index/value `Input`s wired to
    add/edit/remove, save/load action buttons, the neutral empty-state line
    (LLR-007.6). The index input maps an empty string to `array_index=None`
    and a typed integer to an array element.
  - `s19_app/tui/services/cdfx_service.py` *(new)* — thin service
    orchestrating app↔`cdfx` package calls (build/resolve/format/write/read),
    mirroring `a2l_service.enrich_tags_and_render`. Keeps `app.py` free of
    handler logic.
  - `s19_app/tui/app.py` *(modified)* — UI-state wiring only:
    `_compose_screen_patch` docstring, save/load action handlers calling
    `cdfx_service`, status-path surfacing of `ValidationIssue`s. **No XML / no
    model logic** (LLR-007.5 / TC-028).
  - `tests/test_tui_patch_editor.py` *(new)* — TC-025, TC-026, TC-028, TC-027a
    integration arm; via `App.run_test()` + `pilot`.
  - `tests/test_tui_directionb.py` *(modified)* — the batch-02 tests asserting
    the *inert* `PatchEditorPanel` shell (the `R-TUI-027` deferral-notice
    assertions) are updated, since LLR-007.1 removes that notice. This is a
    requirement-driven test change, not a regression.
- **Dependencies:** increments 5–8 (the whole `cdfx` package);
  `s19_app/tui/app.py` screen-compose surface.
- **Risks:**
  - **5-file cap is exactly hit.** If `app.py` + `screens_directionb.py`
    wiring proves to need a 6th file, **stop and request approval** rather than
    splitting silently.
  - **The index input's `None`-vs-integer mapping** is the new UX surface the
    `Optional[int]` migration created — an empty index field must produce a
    scalar entry, not `array_index=0`. *Mitigation:* TC-025 asserts that
    submitting a blank index yields a `None`-index row.
  - **Textual `Input.on_input_submitted` / focus wiring** is the established
    risk area — reuse the batch-02 Direction-B handler pattern, do not invent
    new event flow.
- **Handoff:** **qa-reviewer** — this increment ships the functional screen (a
  new feature surface); propose the TC-025/026/028 acceptance criteria and the
  manual Patch-Editor test plan (including the `W-ARRAY-SPARSE` fail-loud
  behavior from increment 6) to `qa-reviewer`.

### Increment 10 — Round-trip + adversarial-float hardening
- **LLRs:** no new LLR — deepens the round-trip verdict of LLR-004.8 *(float
  precision)*, **LLR-004.9** *(coalesce-on-write)*, **LLR-005.6** *(expand-on-
  read)* and LLR-005.1 (the §5.5 round-trip strategy; TC-024 is the
  corroborating verdict for HLR-004/HLR-005 and the primary verdict for
  LLR-005.1).
- **TCs:** TC-024 (write→read structural equality), TC-033 read-back arm.
- **Files (2):**
  - `tests/test_cdfx_roundtrip.py` *(new)* — TC-024: a change-list of
    `None`-index scalar + `None`-index ASCII + an *N*-element 1-D array (the
    per-element `(name, 0..N-1)` entry set) **plus the three adversarial IEEE
    floats** (`0.1`, denormal `5e-324`, a 17-significant-digit value) written
    then read; structural equality with **exact `==`, no float tolerance** —
    asserting the recovered key set including the `Optional[int]` shape
    (scalar/string → `array_index is None`; the array → exactly the keys
    `(name, 0)…(name, N-1)`), proving coalesce-on-write (LLR-004.9) →
    expand-on-read (LLR-005.6) is lossless.
  - `tests/conftest.py` *(modified)* — relocate and extend `change_list_factory`
    with the adversarial float entries and the §5.4-specified final shape
    (`None`-scalar, integer-index array, sparse-array group); the §5.4 factory
    relocation the earlier increments deferred lands here.
- **Dependencies:** increments 6–7 (the reworked writer + the reader). Placed
  after increment 8 so the writer/reader are in their final form (safety layer
  included).
- **Risks:**
  - **A tautological test if the float fixtures are "nice" values** (Q-03).
    *Mitigation:* the three fixtures are adversarial by construction — a
    denormal truncates to `0.0` under any fixed-width format, the 17-digit
    value loses its tail under `%g`/`str()`; the test fails on any lossy
    writer.
  - **The array round-trip is the LLR-004.9/005.6 cross-check.** A writer that
    failed to coalesce, or a reader that failed to expand, fails TC-024's
    key-set assertion — this is the single test that catches a coalesce/expand
    mismatch end-to-end. *Mitigation:* TC-024 asserts the exact
    `(name, 0..N-1)` key set, not just "N entries".
  - **`conftest.py` is a shared fixture file** — extending/relocating
    `change_list_factory` must not perturb existing fixtures. *Mitigation:*
    purely additive plus a move; run the full suite.

### Increment 11 — Integration save/load + containment UI tests
- **LLRs:** no new LLR — the integration arm of LLR-007.3 / 007.4 / 007.7
  (§5.2 HLR-007 integration arm, §5.7 TC-036 method `I`).
- **TCs:** TC-026 save/load integration depth, TC-036 (containment/dedup/
  reparse-point through the screen), TC-027a Patch-Editor-load integration arm.
- **Files (3):**
  - `tests/test_tui_patch_editor.py` *(modified)* — drive save → file appears
    under `.s19tool/workarea/`; load → rows populate (including a `VAL_BLK`
    `.cdfx` loading back as the per-element rows); issues on the status path.
  - `tests/test_tui_patch_containment.py` *(new)* — TC-036: save resolves under
    `.s19tool/workarea/`, reparse-point target rejected with a
    `ValidationIssue` (not a crash), existing-filename save dedup-suffixes;
    reparse-point arm carries a recorded-reason `skipif`/`xfail` (CV-03).
  - `s19_app/tui/screens_directionb.py` *or* `app.py` *(modified — only if a
    UI defect surfaces while writing the integration tests)* — otherwise this
    slot is unused and the increment is 2 files. Listed for headroom, not as a
    planned change.
- **Dependencies:** increment 9 (the functional screen) + increment 8 (the
  containment guards).
- **Risks:**
  - **Integration tests are flaky if they assume a writable
    `.s19tool/workarea/`** — use `tmp_path` as the app base dir, the
    established harness pattern.
  - **Reparse-point creation needs OS privilege** — gated by `skipif` (CV-03).
  - **If increment 11 surfaces a real UI bug**, fixing it may push past the
    file count — *stop and request approval.*

---

## §A.5 Cross-cutting notes

- **Green between increments.** Increments 5–8 migrate/extend library code not
  yet reachable from the UI — the app runs unchanged and the suite stays green
  (increment 5 re-verifies existing tests at 499; increments 6–8 add new
  tests). Increment 9 is the single increment that mutates running UI
  behavior; its risk section calls out the batch-02 inert-shell test updates.
- **No new dependency.** Every increment uses only stdlib
  (`xml.etree.ElementTree`, `dataclasses`, `enum`, `typing`) plus existing
  `rich` / `textual`. `pyproject.toml` / `requirements.txt` stay
  byte-unchanged (C-2 / acceptance gate §5.9 #8 / TC-028 checklist).
- **`ValidationIssue` reuse.** All CDFX findings are `ValidationIssue` with
  `artifact="cdfx"` (DD-5 / LLR-006.3). No new issue model. `W-ARRAY-SPARSE`
  (increment 6) is a new *code*, not a new model — a writer-behavior code
  alongside `W-INSTANCE-EXCLUDED`.
- **The amendment's stale-test note.** Increment 4's writer tests build
  scalars with positional `array_index=0`; after increment 5's migration this
  means "array element 0". Those tests stay green through increment 5 (the
  writer is untouched) and are **rewritten in increment 6** to use
  `array_index=None` for scalars. Recorded so Phase 4 reads the staleness as a
  planned, deferred correction, not a defect.
- **Handoffs.**
  - **security-reviewer** — increment 8 (DOCTYPE/`<!ENTITY>` rejection, CV-04
    `expat` hook ordering, size/depth bounds, `copy_into_workarea` write-path
    reuse) is security-sensitive; request review before it merges.
  - **qa-reviewer** — increment 9 ships the functional screen; propose the
    TC-025/026/028 acceptance criteria and the manual Patch-Editor test plan,
    including the increment-6 `W-ARRAY-SPARSE` fail-loud behavior.
  - **architect** — if increment 8 reveals `copy_into_workarea` cannot be
    reused as-is for a bytes-producing writer, raise the
    "`resolve_workarea_target` helper vs. write-then-copy" choice to
    `architect` before implementing — do not invent a new write path. The
    increment-6 coalescing itself needs no architect input — it *is* the
    architect's amendment decision.
- **Per-increment exit.** Each increment ends with: full suite green (≥ 499
  baseline, no regression), `s19tui` launches, the 7-section review packet
  delivered, and a stop at the increment boundary for approval.

---

## Appendix — superseded original 9-increment plan (provenance only)

> The sections below are the **original Phase-3 increment plan** as written
> before the Phase-3 array-coalescing amendment. They are kept verbatim for
> provenance. **They are superseded by §A above** — do not plan from them.
> Increments 1–4 of the original plan shipped as recorded in the "Increments
> 1–4 — shipped record" table; the original increments 5–9 are replaced by
> §A's increments 5–11.

### [superseded] 0. Module placement decision

The change-list model and the CDFX read/write handler are data-processing
logic, not view code. The architecture is **parsers → engine → tui** and
`tui/a2l.py` / `tui/mac.py` establish that format handlers live under `tui/`
as peer modules — hence the package `s19_app/tui/cdfx/`
(`__init__.py` / `changelist.py` / `resolve.py` / `display.py` / `writer.py` /
`reader.py`), with a thin `tui/services/cdfx_service.py` for orchestration.
*(This decision is carried forward unchanged into §A.0.)*

### [superseded] 1. Original increment summary

Nine increments, dependency-ordered: model → resolution → display → writer →
reader+safety → path containment → UI → test/round-trip hardening. The
original table:

| # | Title | LLRs | TC count | Files |
|---|-------|------|----------|-------|
| 1 | Change-list model | LLR-001.1..001.4, LLR-003.3 | 4 | 3 |
| 2 | A2L parameter resolution | LLR-002.1..002.4 | 4 | 2 |
| 3 | Type-driven value display | LLR-003.1, LLR-003.2 | 2 | 2 |
| 4 | CDFX writer + `W-*` validator | LLR-004.1..004.8, LLR-006.1 | 14 | 3 |
| 5 | CDFX reader + `R-*` validation | LLR-005.1..005.4, 006.2..006.7, 008.1..008.3 | 16 | 3 |
| 6 | XML-safety + load/write path containment | LLR-005.5, 006.6, 006.8, 007.7 | 6 | 4 |
| 7 | Functional Patch Editor screen | LLR-007.1..007.6 | 4 | 5 |
| 8 | Round-trip + adversarial-float hardening | LLR-004.8, 005.1 (round-trip) | 2 | 2 |
| 9 | Integration save/load + containment UI tests | LLR-007.3, 007.4, 007.7 (integration) | 3 | 3 |

> **Superseded because:** the original plan was written for a 42-LLR / 45-TC
> contract with `array_index: int`. The Phase-3 amendment (44 LLR / 47 TC,
> `array_index: Optional[int]`, new LLR-004.9 / LLR-005.6) reopens the shipped
> increment-1 model and increment-4 writer, which the original increments 5–9
> had no slot for. §A renumbers the tail as increments 5–11: a dedicated
> migration increment (5) and a dedicated writer-coalescing increment (6) are
> inserted, and the original increments 5/6/7/8/9 become §A's 7/8/9/10/11.
