# Increment 006 — Writer coalescing rework + `W-ARRAY-SPARSE`

> **Phase 3 · batch-03 · Increment 6.** Reworks the already-shipped CDFX
> writer so it coalesces array-element change-list entries into one
> `VAL_BLK` `SW-INSTANCE` and rejects sparse arrays with a `W-ARRAY-SPARSE`
> warning. Spec: increment-plan §A.4 — Increment 6; requirements LLR-004.2 /
> LLR-004.3 (amended), LLR-004.9 (new), LLR-006.1 (extended); TC-038 (new),
> TC-012 / TC-013 / TC-019h (re-verified). Branch:
> `dev-flow/batch-02-direction-b-restyle`.

## 1. What changed

`write_cdfx` was reworked from **one `SW-INSTANCE` per change-list entry** to
**one `SW-INSTANCE` per distinct resolved `parameter_name`** (LLR-004.2 /
LLR-004.9). Before emitting instances, the writer now partitions the writable
(`RESOLVED`) entries into "writable" vs "excluded" exactly as before, then
**groups** the writable entries by `parameter_name`. Each group is emitted by a
new `_append_group` dispatcher:

- A `None`-`array_index` entry — a scalar (`VALUE` / `BOOLEAN`) or ASCII-string
  parameter (LLR-001.1) — is emitted as its own single `SW-INSTANCE` with a
  bare `V` (`VALUE`) or a `VT` (`ASCII`) — `_append_scalar_instance`.
- A group of integer-`array_index` entries sharing one `parameter_name` is
  **coalesced** into one `VAL_BLK` `SW-INSTANCE` carrying **one `VG`** of one
  positional `V` per element, ordered **ascending by `array_index`** — the
  writer sorts the group, so a change-list that inserts the elements out of
  index order still produces ascending `V` positions — `_append_array_instance`
  (LLR-004.9 coalescing clause, LLR-004.3).
- A group of integer-`array_index` entries whose sorted indices are **not** the
  contiguous gapless zero-based sequence `0, 1, …, N-1` — a gap, a non-zero
  lowest index, or a duplicate — is a **sparse array**: the writer emits **no
  `SW-INSTANCE`** for that parameter and exactly **one** warning
  `ValidationIssue` with the new code `W-ARRAY-SPARSE` naming the parameter
  (`_sparse_array_issue`). The writer never synthesizes a `V` for a missing
  index (LLR-004.9 sparse rule — `_is_contiguous_zero_based` is the check).

**Ordering determinism (LLR-001.4).** Grouping introduces a second ordering
concern, resolved with two deterministic rules: groups are emitted in the order
of the **first appearance** of their `parameter_name` in `ChangeList.entries`
(`_group_writable_entries` walks `entries` once and `dict.setdefault` fixes the
group order to insertion order); within an array group the `V` order is
**ascending `array_index`**. Two writes of the same change-list stay
byte-identical — the re-verified `test_tc012_instance_order_*` asserts
`first == second`.

**Zero-writable accounting (LLR-004.6).** A `W-ARRAY-SPARSE` exclusion feeds the
LLR-004.6 zero-writable count exactly as a `W-INSTANCE-EXCLUDED` exclusion does:
`write_cdfx` counts `SW-INSTANCE` elements actually written, and when that count
is zero — whether the change-list was empty, every entry was unresolved, or
every array group was sparse — it still emits a valid backbone-only `.cdfx`
plus one `W-EMPTY-CHANGELIST` warning. A sparse-only change-list therefore
yields `W-ARRAY-SPARSE` **and** `W-EMPTY-CHANGELIST`.

**Mixed `None`/integer under one name.** The model *permits* a `(PARAM, None)`
scalar entry and a `(PARAM, 0)` array entry to coexist (it is a
resolution-stage inconsistency per LLR-001.3's rationale, never legitimate).
`_append_group` treats them as two independent sub-groups — the `None`-index
entries become scalar instances and the integer-index entries become an array
group — and invents **no merge rule** (engineering rule 2). If that produces two
same-`SHORT-NAME` instances, that is a resolution defect, not a writer bug.

**Stale-test correction (increment-5 risk note, now cleared).** The increment-4
writer tests built "scalar" entries with positional `array_index=0`; after the
increment-5 `Optional[int]` migration `0` means array element 0. Both writer
test files were rewritten so scalar / ASCII fixtures use `array_index=None`;
integer indices are kept only for genuine array-element fixtures. This clears
the planned, deferred test correction recorded in the increment-5 packet §5.

`changelist.py`, `resolve.py`, `display.py`, `reader.py` are **byte-unchanged**
(no reader exists yet). `cdfx/__init__.py` is unchanged — the `write_cdfx`
re-export stays an increment-7 item per the plan. `pyproject.toml` /
`requirements.txt` byte-unchanged — no new dependency, stdlib
`xml.etree.ElementTree` only (C-2).

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/writer.py` | modified | `write_cdfx` reworked to group writable entries by `parameter_name`; new private helpers `_group_writable_entries`, `_append_group`, `_is_contiguous_zero_based`, `_append_scalar_instance`, `_append_array_instance`, `_sparse_array_issue`; `_append_instance` (one-per-entry) removed; module + `write_cdfx` docstrings updated to the coalescing contract. LLR-004.2/004.3/004.9, LLR-006.1. |
| `tests/test_cdfx_writer.py` | modified | Scalar / ASCII fixtures migrated `array_index=0`→`None`; `_resolved_change_list` helper signature widened to `int \| None`; TC-012 split — `test_tc012_one_instance_per_resolved_parameter` + new `test_tc012_array_entries_of_one_name_coalesce_to_one_instance`; TC-013 array arm rewritten — `test_tc013_array_value_is_one_vg_of_positional_v` (one instance, one 3-`V` `VG`) + new `test_tc013_array_vg_v_order_is_ascending_array_index`; module docstring updated. |
| `tests/test_cdfx_w_rules.py` | modified | Scalar fixtures migrated `array_index=0`→`None`; `_resolved_change_list` helper signature widened to `int \| None`; new **TC-038** section — 5 cases (contiguous coalesce, gap rejection, non-zero-based rejection, sparse-only → backbone + `W-EMPTY-CHANGELIST`, sparse group does not block a valid sibling); module docstring updated. |

3 files — within the ≤5 cap and matching the increment-6 spec exactly.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -m py_compile s19_app/tui/cdfx/writer.py tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py
```

Round-trip-parse the coalesced output (one `SW-INSTANCE` per parameter, one
`VG` of ascending `V`):

```
python -c "from xml.etree import ElementTree as ET; from s19_app.tui.cdfx.changelist import ChangeList, ResolutionStatus; from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType; from s19_app.tui.cdfx.writer import write_cdfx; cl=ChangeList(); [cl.add('TABLE',k,v,ResolutionStatus.RESOLVED) for k,v in [(2,2.2),(0,0.1),(1,1.1)]]; r=ResolutionResult(change_list=cl); [r.resolved_types.__setitem__(e.key, ResolvedType('VAL_BLK','FLOAT32_IEEE',3)) for e in cl.entries]; d,i=write_cdfx(cl,r); root=ET.fromstring(d); print('instances', len([e for e in root.iter() if e.tag.rsplit('}',1)[-1]=='SW-INSTANCE']))"
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the three files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py`** →
  `40 passed in 0.09s`. Baseline for these two files was 33 (18 writer + 15
  w-rules); now 40 (19 writer + 21 w-rules) — `+7` net new test functions.
- **`pytest -q` (full suite)** → `509 passed, 2 skipped, 3 xfailed in 184.39s`,
  `27 snapshots passed`, **0 failed**. Baseline was 502 passed / 2 skipped /
  3 xfailed; 502 + 7 = 509 — exact, no regression, skip/xfail counts unchanged.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK` (clean exit).
- **`python -m py_compile`** on the three files → `PY_COMPILE_OK`.
- **Round-trip `ElementTree` parse** of a mixed change-list (a 4-element array
  inserted out of index order `2,0,3,1` + a scalar + an ASCII string):
  `ROUNDTRIP_PARSE_OK root= MSRSW instances= 3 issues= []` — three
  `SW-INSTANCE`s (`TABLE`, `IGN`, `LBL`), one per distinct `parameter_name`;
  `TABLE` is `CATEGORY=VAL_BLK` with **exactly one `VG`** whose `V` text is
  `['0.1', '1.1', '2.2', '5e-324']` — ordered ascending by `array_index` (not
  insertion order) and at full `repr()` float precision (LLR-004.8 carried
  through coalescing).

### The +7 net count delta

The brief's expected file count is 3 (met). The increment plan §A.4 explicitly
instructs adding TC-038 and re-verifying TC-012 / TC-013 / TC-019h; that work
necessarily adds `pytest` *functions* even though TC numbers are amended, not
created:

- `tests/test_cdfx_writer.py` 18 → 19 (+1): TC-012 gained
  `test_tc012_array_entries_of_one_name_coalesce_to_one_instance`; TC-013's
  array arm was rewritten as `test_tc013_array_value_is_one_vg_of_positional_v`
  **and** a new `test_tc013_array_vg_v_order_is_ascending_array_index`; the old
  3-instance `test_tc013_array_value_is_vg_of_positional_v` was rewritten, not
  kept. Net +1 (one removed-and-renamed, two added).
- `tests/test_cdfx_w_rules.py` 15 → 21 (+6): the new TC-038 section adds 5
  cases plus the existing 15 stay; the 6th is the sibling-isolation case
  `test_tc038_sparse_group_does_not_block_a_valid_sibling_parameter`.

The 5 catalogue TC-038 acceptance criteria (contiguous coalesce, gap, non-zero
lowest index, sparse-only zero-writable, never-synthesize-a-`V`) are all pinned;
the 6th is a collect-don't-abort isolation check. This is the §A.4 instruction
set, not scope creep — flagged so Phase 4 reads it as a planned re-verification.

### New / reworked tests by TC

**`tests/test_cdfx_writer.py` (19 tests):**
- **TC-011** — 2 tests, unchanged behaviour (scalar fixture now `None`-index).
- **TC-012** — 4 tests: scalar → `VALUE` instance; **3 distinct parameters →
  3 instances**; **3 array-element entries of one name → exactly 1 instance**
  (the increment-6 coalescing); instance order = first-appearance, byte-stable.
- **TC-013** — 5 tests: scalar → one bare `V`; **3-element array → 1 `VAL_BLK`
  instance with 1 `VG` of 3 `V`**; **out-of-order insert still yields ascending
  `V`**; string → one `VT`; no `SW-ARRAY-INDEX` anywhere.
- **TC-014 / TC-032 / TC-033** — 8 tests, unchanged behaviour (fixtures
  migrated to `None`-index scalars).

**`tests/test_cdfx_w_rules.py` (21 tests):**
- **TC-019a..TC-019h** — 15 tests, unchanged behaviour (scalar fixtures
  migrated to `None`-index).
- **TC-038** — 6 tests: `PARAM[0..2]` coalesce to one `VAL_BLK` (one 3-`V`
  `VG`, zero issues); a gap group → no instance + one `W-ARRAY-SPARSE` + zero
  `V` synthesized; a non-zero-based group → no instance + one `W-ARRAY-SPARSE`;
  a sparse-only change-list → backbone-only + `W-ARRAY-SPARSE` +
  `W-EMPTY-CHANGELIST` (2 issues); a sparse group does not block a valid
  contiguous-array + scalar sibling (one `W-ARRAY-SPARSE`, siblings written in
  first-appearance order).

No code defect was found during the run — the writer and both test files
passed on the first full-suite run after implementation.

## 5. Risks

- **`W-ARRAY-SPARSE` is a new issue code, not a new model.** It joins
  `W-INSTANCE-EXCLUDED` as a writer **behavior** code (a writer decision to
  drop input that has no positional CDF encoding), distinct from the eight
  structural `W-*` *rule* codes. This matches LLR-006.1's amended statement and
  the requirements §4 rationale. It is a `ValidationIssue` with `artifact="cdfx"`
  and `severity=WARNING` — no new issue model (DD-5).
- **`_append_scalar_instance` ignores a `VAL_BLK` `char_type` on a `None`-index
  entry.** A `None`-index entry has no array elements to coalesce, so even if
  its resolved `char_type` is `VAL_BLK` the writer emits a scalar `VALUE`
  instance with a bare `V` rather than an empty `VG`. This is deliberate — a
  `None`-index entry is never an array element (LLR-001.1) — and keeps the
  output `W-CATEGORY-VALUE-CONSISTENT`. `_category_for` only ever yields
  `VALUE` / `VAL_BLK` / `ASCII`; the scalar branch always writes `VALUE`. A
  parameter genuinely resolved as `VAL_BLK` but carrying a `None`-index entry
  is a resolution inconsistency, recorded not speculatively merged.
- **The sparse rule rejects, never gap-fills.** A sparse / non-zero-based array
  group produces no `.cdfx` output for that parameter — this is the
  calibration-safety decision of LLR-004.9 (gap-filling would ship a physical
  value the engineer never entered). It is a fail-loud behaviour: a sparse-only
  change-list silently looks "empty" until the engineer reads the
  `W-ARRAY-SPARSE` + `W-EMPTY-CHANGELIST` warnings. The UI increment (9) must
  surface these warnings on the status path so the engineer sees the rejection.
- **Coalescing depends on the increment-5 `Optional[int]` discriminator.** The
  whole rework relies on `array_index is None` ≙ scalar/string and
  `isinstance(array_index, int)` ≙ array element. If a future change reverts the
  model to `int`-with-default-0, `_append_group` would mis-route every scalar
  into the array branch. The model contract is pinned by the increment-5 tests;
  this increment adds no further model-shape assertion.
- **Round-trip not yet closed.** The coalesce→expand round-trip (LLR-004.9
  round-trip clause) is only half-built — the reader (increment 7) and the
  end-to-end TC-024 round-trip (increment 10) are not in scope here. This
  increment proves the **write** half: one `SW-INSTANCE` per parameter, one
  `VG` of ascending `V`, no `V` synthesized for a missing index. The read-side
  positional expansion to `(name, 0..N-1)` (LLR-005.6) must mirror this exactly.

## 6. Pending items

- **Increment 7 — CDFX reader + `R-*` validation + `VAL_BLK` expansion.** The
  reader must expand a `VAL_BLK` `SW-INSTANCE` with an *N*-`V` `VG` back into
  *N* entries `(name, 0..N-1)`, a `VALUE`/`BOOLEAN` instance into one
  `array_index=None` entry, an `ASCII` instance into one `array_index=None`
  string entry — the exact read-side inverse of this increment's coalescing
  (LLR-005.6). Not started — increment 6 stops at its boundary.
- **`cdfx/__init__.py` re-export of `write_cdfx` / `validate_w_rules`** stays an
  increment-7 item per the plan (one cohesive `__init__` edit with `read_cdfx`).
- **TC-024 round-trip** (write→read structural equality including the
  `Optional[int]` key shape) is increment 10 — it is the single test that
  catches a coalesce/expand mismatch end-to-end.
- **CV-01..CV-03** Phase-2 closure cosmetic items: CV-02 / CV-03 were applied in
  increment 5; CV-01 (and any residual) has no natural touch-point in these 3
  files — surfaced again so it is not lost.

## 7. Suggested next task

**Increment 7 — CDFX reader + `R-*` validation + `VAL_BLK` expansion.** Create
`s19_app/tui/cdfx/reader.py` (`read_cdfx` — `ElementTree` parse, namespace-
stripping local-name match, `SW-INSTANCE` lookup scoped to the
`SW-INSTANCE-TREE` backbone, `V`/`VG`/`VT` decode, the LLR-005.6
`VAL_BLK`→*N*-entry / `VALUE`→`None` / `ASCII`→`None` expansion, all core `R-*`
codes, version / tool-note tolerance, A2L name + array-length cross-checks),
`tests/test_cdfx_reader.py`, `tests/test_cdfx_r_rules.py`, and the
`cdfx/__init__.py` re-export. 13 TCs (TC-015..018, TC-020..023, TC-029..031,
TC-034, TC-039), 4 files. The reader's `VAL_BLK` expansion **must mirror this
increment's coalescing exactly** — `0..N-1` positional keys, `VALUE`/`ASCII`
→ `array_index=None` — or the increment-10 TC-024 round-trip will not close.

---

**Stop boundary reached.** Increment 6 is complete: the writer coalesces
integer-`array_index` entries into one `VAL_BLK` `SW-INSTANCE` per
`parameter_name` and rejects sparse arrays with `W-ARRAY-SPARSE`; the two
writer test modules are green (40 passed, 33 → 40 = +7 net); the full suite is
509 passed / 2 skipped / 3 xfailed / 0 failed (502 baseline + 7); the coalesced
output round-trip-parses as well-formed CDF 2.0 with one `SW-INSTANCE` per
parameter and one ascending-`V` `VG`; `s19_app.tui.cdfx` imports unchanged; no
UI behaviour changed. Awaiting approval before starting increment 7.
