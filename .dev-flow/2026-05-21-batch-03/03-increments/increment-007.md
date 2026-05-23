# Increment 007 — CDFX reader + `R-*` validation + `VAL_BLK` expansion

> **Phase 3 · batch-03 · Increment 7.** Adds the CDFX reader — the read-side
> half of the CDF 2.0 handler. Parses a well-formed `.cdfx` into a change-list,
> applies the read-time `R-*` structural rules, expands a `VAL_BLK` instance
> back into array-element entries (the inverse of increment 6's writer
> coalescing), and cross-checks instances against the loaded A2L. Spec:
> increment-plan §A.4 — Increment 7; requirements LLR-005.1..005.4, LLR-005.6
> (new), LLR-006.2/.3/.4/.5/.7, LLR-008.1..008.3; TC-015..018, TC-020..023,
> TC-029..031, TC-034, TC-039 (new). Branch:
> `dev-flow/batch-02-direction-b-restyle`.

## 1. What changed

A new module `s19_app/tui/cdfx/reader.py` was created with the public entry
point `read_cdfx(source, a2l_tags=None) -> (ChangeList, list[ValidationIssue])`.
It parses a well-formed `.cdfx` document with stdlib `xml.etree.ElementTree`
only (constraint C-2 — no new dependency) and follows the project's
collect-don't-abort culture: a bad instance is skipped and flagged, never
thrown.

The reader does four things:

- **Namespace-tolerant parse (LLR-005.3 / RK-3).** A default `xmlns` makes
  `ElementTree` namespace-qualify every tag as `{uri}LocalName`. Every match
  goes through `_local_name`, which strips the `{...}` prefix — a namespaced
  `.cdfx` reads exactly like a bare one. The `SW-INSTANCE` lookup is **scoped
  to the direct children of the `SW-INSTANCE-TREE` backbone** (`_find_instance_tree`
  + `_direct_instances`), so an instance crafted outside the backbone (for
  example inside `ADMIN-DATA`) is **not** absorbed into the change-list (S-006).

- **`VAL_BLK` / `VALUE` / `ASCII` expansion (LLR-005.6) — the exact inverse of
  increment 6's coalescing.** A `VAL_BLK` instance whose `SW-VALUE-CONT/`
  `SW-VALUES-PHYS` carries a `VG` of *N* `V` elements is expanded into *N*
  change-list entries `(name, 0)…(name, N-1)` — positional, zero-based,
  contiguous (`_add_array_entries`). A `VALUE` / `BOOLEAN` instance with a `V`
  becomes one scalar entry with `array_index = None` (`_add_scalar_entry`); an
  `ASCII` instance with a `VT` becomes one string entry with `array_index =
  None` (`_add_string_entry`). `V` text is decoded by `_decode_numeric` —
  decimal / exponential `float`, decimal / `0x`-hex `int`, with `0b` accepted
  only as a tolerant superset (OQ-7, not a normative form). A non-numeric `V`
  is kept as raw text and flagged.

- **The read-time `R-*` rule set (LLR-006.2/.4/.5).** `R-XML-PARSE` (a
  `ParseError` → one error issue, empty change-list), `R-ROOT-MSRSW` (a
  non-`MSRSW` root), `R-VERSION-UNKNOWN` (an info issue on a non-`CDF20`
  `MSRSW/CATEGORY`, file still read — LLR-006.4), `R-BACKBONE-MISSING` (no
  locatable instance-tree), `R-INSTANCE-NO-NAME` / `R-INSTANCE-NO-VALUE` (the
  instance is skipped, others continue), `R-CATEGORY-UNSUPPORTED` (a `MAP` /
  `STRUCTURE` / `*_ARRAY` category loads as one read-only `UNRESOLVED` entry —
  LLR-006.5), `R-CATEGORY-VALUE-MISMATCH` (a category↔value-shape mismatch is
  flagged, the value still read), `R-VALUE-NOT-NUMERIC` (a non-numeric `V`).
  Every finding is a `ValidationIssue` with `artifact="cdfx"` (LLR-006.3 /
  DD-5) — no new issue model.

- **The A2L cross-check (LLR-008.1..008.3).** When enriched A2L tags are passed
  as `a2l_tags`, each instance is checked: a name absent from the A2L is
  `R-NAME-NOT-IN-A2L` (LLR-008.1); a `VAL_BLK` instance whose `V` count differs
  from the A2L `element_count` is `R-ARRAY-LEN-MISMATCH` (LLR-008.2). The
  cross-check reads only the `name` and `element_count` fields of each tag and
  is **skipped entirely** when `a2l_tags` is `None`/empty (LLR-008.3) —
  `_index_a2l_tags` returns `None` and `_cross_check_instance` short-circuits.

A leading or embedded writer- / tool-identification XML comment (for example
`Created with CANape … CDF 2.0 Writer`) is non-significant content:
`ElementTree` discards comments on parse, so the reader tolerates and ignores
them with no issue (LLR-006.7).

`cdfx/__init__.py` was extended to re-export `read_cdfx`, `write_cdfx` and
`validate_w_rules` so the increment-9 CDFX service has one import surface —
folding in the `write_cdfx` re-export the increment-6 packet flagged as a
deferred item.

`changelist.py`, `resolve.py`, `display.py`, `writer.py` and `validation/` are
**byte-unchanged**. `pyproject.toml` / `requirements.txt` are byte-unchanged —
no new dependency, stdlib `xml.etree.ElementTree` only (C-2).

**XML safety is explicitly out of scope here (increment 8).** DOCTYPE /
`<!ENTITY>` rejection, the 256 MB size cap, the nesting-depth bound and the
`resolve_input_path` load-path resolution (LLR-005.5, LLR-006.6, LLR-006.8) are
increment 8. This module assumes well-formed, non-malicious input and surfaces
only a plain `ParseError` as `R-XML-PARSE`; the module docstring states this
boundary so Phase 4 does not read the absent entity defense as a defect. The
`read_cdfx` signature accepts `bytes | str | Path` — a path is read directly
with `Path.read_bytes`; the `resolve_input_path` wiring is the increment-8 add.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/reader.py` | **new** | `read_cdfx` — namespace-tolerant `ElementTree` parse, `SW-INSTANCE` lookup scoped to the `SW-INSTANCE-TREE` backbone, `V`/`VG`/`VT` decode, the LLR-005.6 `VAL_BLK`→*N*-entry / `VALUE`→`None` / `ASCII`→`None` expansion, all core `R-*` codes, version / tool-note tolerance, the LLR-008 A2L name + array-length cross-check. Private helpers: `_read_instance`, `_check_value_shape`, `_add_scalar_entry`, `_add_string_entry`, `_add_array_entries`, `_decode_numeric`, `_try_parse_number`, `_index_a2l_tags`, `_cross_check_instance`, `_element_count_of`, `_read_bytes`, `_find_instance_tree`, `_direct_instances`, `_values_phys_of`, `_collect_values`, `_first_child`, `_child_text`, `_local_name`, `_r_issue`, `_parse_issue`. LLR-005.1..005.4, LLR-005.6, LLR-006.2/.3/.4/.5/.7, LLR-008.1..008.3. |
| `s19_app/tui/cdfx/__init__.py` | modified | Re-export `read_cdfx`, `write_cdfx`, `validate_w_rules` (added to `__all__` and the imports); module docstring updated to note the read/write entry points are the package's public import surface. |
| `tests/test_cdfx_reader.py` | **new** | TC-015 (parse to entries), TC-016 (malformed XML), TC-017 (namespaced + extra siblings + backbone-scoping), TC-018 (numeric notations), TC-022 (`ValidationIssue` reuse + severity round-trip), TC-034 (tool-note tolerance), TC-039 (`VAL_BLK`/`VALUE`/`ASCII`/`BOOLEAN` expansion). In-test synthetic fixtures `make_minimal_cdfx`, `make_variant_cdfx`, `make_tool_note_cdfx`. 19 tests. |
| `tests/test_cdfx_r_rules.py` | **new** | TC-020 (each `R-*` structural rule + valid-sibling recovery), TC-021 (version tolerance), TC-023 (unsupported-category read-only), TC-029/030/031 (A2L name / array-length cross-check + no-A2L skip). Parametrized `make_rule_violation_cdfx` generator — each variant carries a valid sibling instance (Q-04). 20 tests. |

4 files — exactly the expected count, within the ≤5 cap.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_reader.py tests/test_cdfx_r_rules.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -m py_compile s19_app/tui/cdfx/reader.py s19_app/tui/cdfx/__init__.py tests/test_cdfx_reader.py tests/test_cdfx_r_rules.py
```

Write-then-read round-trip check (build a change-list, `write_cdfx`,
`read_cdfx`, confirm the entries come back):

```
python -c "
from s19_app.tui.cdfx.changelist import ChangeList, ResolutionStatus
from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType
from s19_app.tui.cdfx import write_cdfx, read_cdfx
cl=ChangeList()
cl.add('IGN',None,12.5,ResolutionStatus.RESOLVED)
cl.add('LBL',None,'REV_C',ResolutionStatus.RESOLVED)
[cl.add('TABLE',k,v,ResolutionStatus.RESOLVED) for k,v in [(2,25),(0,23),(1,24)]]
r=ResolutionResult(change_list=cl)
[r.resolved_types.__setitem__(e.key, ResolvedType('VAL_BLK','UWORD',3) if e.parameter_name=='TABLE' else (ResolvedType('ASCII',None,8) if e.parameter_name=='LBL' else ResolvedType('VALUE','FLOAT32_IEEE',1))) for e in cl.entries]
data,_=write_cdfx(cl,r); back,issues=read_cdfx(data)
print(sorted((e.key,e.value) for e in back.entries), issues)
"
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the four files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_reader.py tests/test_cdfx_r_rules.py`** →
  `39 passed in 0.11s` — 19 reader tests + 20 `R-*`-rule tests.
- **`pytest -q` (full suite)** → `548 passed, 2 skipped, 3 xfailed in 170.92s`,
  `27 snapshots passed`, **0 failed**. Baseline was 509 passed / 2 skipped /
  3 xfailed; 509 + 39 = 548 — exact, no regression, skip/xfail counts
  unchanged.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK ['ChangeList',
  'ChangeListEntry', 'ResolutionStatus', 'read_cdfx', 'validate_w_rules',
  'write_cdfx']` (clean exit) — the three new re-exports are present.
- **`python -m py_compile`** on the four files → `PY_COMPILE_OK`.
- **Write-then-read round-trip** of a change-list (a 3-element array inserted
  out of index order `2,0,1` + a `None`-index scalar `float` + a `None`-index
  ASCII string): `WRITE_THEN_READ_OK` — `write issues: []`, `read issues: []`,
  recovered keys/values `('IGN', None) = 12.5`, `('LBL', None) = 'REV_C'`,
  `('TABLE', 0) = 23`, `('TABLE', 1) = 24`, `('TABLE', 2) = 25` —
  `ROUNDTRIP_KEYS_AND_VALUES_MATCH`. The coalesce-on-write → expand-on-read
  cycle reproduces the `(parameter_name, array_index)` `Optional[int]` key set
  and the per-key values exactly: a scalar/string recovers `array_index = None`
  and a 3-element array recovers exactly `(TABLE,0)…(TABLE,2)` — the
  increment-10 TC-024 verdict is structurally pre-confirmed.

### New tests by TC

**`tests/test_cdfx_reader.py` (19 tests):**
- **TC-015** — 2 tests: a `make_minimal_cdfx` (one `VALUE`, one 3-`V`
  `VAL_BLK`, one `ASCII`) parses to five entries with correct names/values;
  every parsed entry is stamped `RESOLVED`.
- **TC-016** — 2 tests: a truncated file → one `R-XML-PARSE` error issue +
  empty change-list, no crash; non-XML garbage bytes do not raise.
- **TC-017** — 2 tests: a namespaced `.cdfx` (`xmlns` on `MSRSW`) with
  `ADMIN-DATA` / `SW-CS-HISTORY` / `SW-CS-FLAGS` siblings still reads its
  instance; a `SW-INSTANCE` placed inside `ADMIN-DATA` is **not** absorbed
  (S-006 backbone-scoping).
- **TC-018** — 4 tests: `<V>0x17</V>`→23, `<V>1.5e1</V>`→15.0 (a `float`),
  plain decimal→`int`, `0b101` accepted as a tolerant superset only (OQ-7 — the
  assertion documents tolerance, does not require it).
- **TC-022** — 2 tests: a read finding is a `ValidationIssue` with
  `artifact == "cdfx"`; its severity round-trips through
  `color_policy.css_class_for_severity` to a valid `sev-*` class.
- **TC-034** — 1 test: a leading `Created with CANape … CDF 2.0 Writer` XML
  comment is non-significant — same five entries, zero issues.
- **TC-039** — 4 tests: a `VAL_BLK` `VG` of *N* `V` expands to keys
  `(name, 0)…(name, N-1)`; a `VALUE` instance → one `array_index is None`
  scalar; an `ASCII` instance → one `array_index is None` string; a `BOOLEAN`
  instance → one `array_index is None` scalar.

**`tests/test_cdfx_r_rules.py` (20 tests):**
- **TC-020** — 9 tests: each of the six structural `R-*` codes
  (`R-ROOT-MSRSW`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`,
  `R-INSTANCE-NO-VALUE`, `R-CATEGORY-VALUE-MISMATCH`, `R-VALUE-NOT-NUMERIC`) is
  provoked with its documented severity (parametrized); for the four
  instance-level rules the valid sibling instance is recovered (parametrized,
  Q-04 collect-don't-abort); the two whole-document rules return an empty
  change-list; a non-numeric `V` is kept as raw text.
- **TC-021** — 2 tests: a `CDF21` file reads its instances + one info-level
  `R-VERSION-UNKNOWN`; a `CDF20` file emits no version issue.
- **TC-023** — 2 tests: a `MAP` instance loads as one read-only `UNRESOLVED`
  entry + one `R-CATEGORY-UNSUPPORTED` warning; a `MAP` instance does not block
  a valid sibling.
- **TC-029** — 2 tests: a name absent from the A2L → one `R-NAME-NOT-IN-A2L`
  warning; a matched name → no name cross-check issue.
- **TC-030** — 2 tests: a 4-element array against a 3-element A2L parameter →
  one `R-ARRAY-LEN-MISMATCH` warning; a matched length → no mismatch issue.
- **TC-031** — 1 test: with no A2L, a `.cdfx` parses into entries and emits
  zero `R-NAME-NOT-IN-A2L` / `R-ARRAY-LEN-MISMATCH` issues.

No code defect was found during the run — the reader and both test files
passed on the first full-suite run after implementation.

## 5. Risks

- **LLR-005.6 expansion mirrors LLR-004.9 coalescing — verified, not just
  asserted.** TC-039 pins the three shapes (`VAL_BLK`→`0…N-1`, `VALUE`→`None`,
  `ASCII`→`None`) and the write-then-read round-trip check (§4) confirms the
  end-to-end cycle reproduces the `Optional[int]` key set and values exactly.
  The increment-10 TC-024 round-trip is the formal verdict; this increment's
  manual check already shows it closes for a mixed scalar + array + string
  change-list. A future regression in either the writer's `VG` ordering or the
  reader's positional expansion would fail TC-024.
- **Reader expands a foreign `VAL_BLK` positionally regardless of A2L
  `element_count`.** Per LLR-005.6 the `VG`→*N*-entry expansion is
  **unconditional** — a `VAL_BLK` whose `V` count disagrees with the A2L is
  still expanded to *N* entries; the disagreement is a *separate*
  `R-ARRAY-LEN-MISMATCH` cross-check (LLR-008.2). The two concerns are not
  conflated: `_add_array_entries` does not consult the A2L, and
  `_cross_check_instance` runs as an independent pass. A foreign producer's
  1-based or sparse `VG` would still be read as `0…N-1` — that is the CDF
  positional contract (research §3), not a reader bug.
- **`R-CATEGORY-UNSUPPORTED` entry carries only the first raw value.** An
  unsupported category (`MAP`, `STRUCTURE`, `*_ARRAY`) is multi-dimensional;
  the change-list model has no multi-dimensional row, so the read-only entry
  keeps only the first `V`/`VT` text as a visible placeholder. This matches
  LLR-006.5 ("surfaced read-only and excluded from the editable change-list") —
  the entry is `UNRESOLVED`, so the increment-9 UI shows it but the writer's
  `RESOLVED`-only gate (LLR-004.5) excludes it from any re-write. It is not a
  faithful representation of a 2-D map and is not meant to be.
- **`a2l_tags` is a `list[dict]`, not the resolver's typed object.** The
  cross-check reads only `name` and `element_count`, so the reader accepts the
  enriched-tag list directly (the same shape `resolve_against_a2l` consumes) —
  the R-rules tests build minimal `{"name", "element_count"}` dicts. If a
  future caller passes a different tag shape, a missing `element_count` falls
  back to `1` (`_element_count_of`, mirroring `resolve._element_count_of`) — no
  crash, but a silent default. The increment-9 service must pass the genuine
  `enrich_a2l_tags_with_values` output.
- **XML safety is absent by design.** A malicious `.cdfx` (billion-laughs,
  external entity, oversized, deeply nested) is **not** defended here —
  increment 8 adds the DOCTYPE/`<!ENTITY>` rejection, the 256 MB cap and the
  depth bound. Until increment 8 ships, `read_cdfx` must not be wired to an
  untrusted file path. The module docstring states this boundary explicitly.

## 6. Pending items

- **Increment 8 — XML-safety + load/write path containment.** The reader gains
  the `expat`-level DOCTYPE/`<!ENTITY>`-rejection hook (CV-04), the pre-parse
  256 MB size check (`DEFAULT_COPY_SIZE_CAP_BYTES`, injectable `size_probe`
  seam), the nesting-depth bound, and the `resolve_input_path` load-path
  resolution (LLR-005.5/006.6/006.8). `read_cdfx` already accepts `bytes | str
  | Path` so increment 8 only inserts the resolution + bounds before
  `_read_bytes`/`ET.fromstring`. **This is security-sensitive — request
  `security-reviewer` review before increment 8 merges** (DOCTYPE rejection,
  `expat` hook ordering, size/depth bounds, `copy_into_workarea` write-path
  reuse).
- **TC-024 round-trip** (write→read structural equality including the
  `Optional[int]` key shape and the three adversarial IEEE floats) is
  increment 10 — the formal end-to-end verdict for the coalesce/expand cycle
  this increment's manual check already shows closing.
- **CV-01** Phase-2 closure cosmetic item has no natural touch-point in these 4
  files — surfaced again so it is not lost (CV-02/CV-03 were applied in
  increment 5).

## 7. Suggested next task

**Increment 8 — XML-safety + load/write path containment.** Extend
`reader.py` with an `xml.etree.ElementTree.XMLParser` whose `expat`-level
`StartDoctypeDeclHandler` / entity-declaration handler raises **before** any
entity expansion (CV-04 hand-off — the hook must fire on the declaration, not
after), a pre-parse 256 MB size check with an injectable `size_probe` seam, a
nesting-depth bound, and the `resolve_input_path` load-path call; extend
`writer.py` to resolve and containment-validate its write target by reusing
`workspace.copy_into_workarea` / `_path_traverses_reparse_point`; add
`tests/test_cdfx_safety.py` and `tests/test_cdfx_path_containment.py`. 6 TCs
(TC-027a/b, TC-035, TC-036 function arm, TC-037), 5 files.
**security-reviewer review required before merge.** If `copy_into_workarea`
cannot be reused as-is for a bytes-producing writer, raise the
"`resolve_workarea_target` helper vs. write-then-copy" choice to `architect`
before implementing — do not invent a new write path.

---

**Stop boundary reached.** Increment 7 is complete: `s19_app/tui/cdfx/reader.py`
parses a well-formed `.cdfx` namespace-tolerantly, locates `SW-INSTANCE`
elements only under the `SW-INSTANCE-TREE` backbone, applies all core `R-*`
read-time rules collecting `ValidationIssue`s without aborting, expands a
`VAL_BLK` `VG` into *N* `(name, 0…N-1)` entries / a `VALUE`/`BOOLEAN`/`ASCII`
instance into one `array_index=None` entry (the exact inverse of increment 6's
coalescing), and cross-checks instances against the loaded A2L; `cdfx/__init__.py`
re-exports `read_cdfx` / `write_cdfx` / `validate_w_rules`; the two new test
modules are green (39 passed); the full suite is 548 passed / 2 skipped /
3 xfailed / 0 failed (509 baseline + 39); a write→read round-trip of a mixed
change-list closes exactly on keys and values; `s19_app.tui.cdfx` imports
unchanged; no UI behaviour changed. XML safety (DOCTYPE rejection, size/depth
bounds, path resolution) is deferred to increment 8 as planned. Awaiting
approval before starting increment 8.
