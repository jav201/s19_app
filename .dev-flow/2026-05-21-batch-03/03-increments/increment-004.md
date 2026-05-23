# Increment 004 — CDFX writer + `W-*` validator — Review Packet

> **Batch:** 2026-05-21-batch-03 · **Phase 3 (Implementation), Increment 4 of 9.**
> **Branch:** `dev-flow/batch-02-direction-b-restyle`.
> Spec: [`increment-plan.md` §4 — Increment 4](./increment-plan.md) · Requirements:
> [`01-requirements.md`](../01-requirements.md) LLR-004.1..004.8, LLR-006.1;
> design-input [`cdfx-research.md`](../design-input/cdfx-research.md) §3/§5/§7.

---

## 1. What changed

Created `s19_app/tui/cdfx/writer.py` — the CDFX writer and the standalone
write-time `W-*` validator. The public surface is three functions:

- **`write_cdfx(change_list, resolution)`** — serializes a resolved
  `ChangeList` to a CDF 2.0 `.cdfx` byte stream with stdlib
  `xml.etree.ElementTree` only (constraint C-2 — no new dependency). It builds
  the `MSRSW` root with `SHORT-NAME` + `CATEGORY=CDF20` (LLR-004.1), the
  `SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE` backbone (LLR-004.1),
  one `SW-INSTANCE` per **writable** entry (LLR-004.2), the
  `SW-VALUE-CONT/SW-VALUES-PHYS` value encoding — `V` for a scalar, `VG` of
  positional `V` for a 1-D array, `VT` for an ASCII string (LLR-004.3) — the
  leading `Created with s19_app CDF 2.0 Writer` tool-identification XML comment
  (LLR-004.7), and `repr()`-precision float `V` text (LLR-004.8). It returns
  `(bytes, list[ValidationIssue])`.
- **`validate_w_rules(root)`** — the standalone `W-*` validator on an
  already-parsed element tree: checks `W-ROOT-MSRSW`, `W-BACKBONE`,
  `W-INSTANCE-NAME`, `W-INSTANCE-CATEGORY`, `W-VALUE-PRESENT`,
  `W-CATEGORY-VALUE-CONSISTENT` (LLR-006.1) and returns one `ValidationIssue`
  per violation. Testable in isolation (Phase-2 Q-05) — crafted broken trees
  provoke the codes a correct writer can never emit.
- **`validate_w_rules_bytes(data)`** — the byte-stream entry point that adds
  `W-XML-WELLFORMED` (well-formedness is a property of bytes, not of a parsed
  tree) on top of `validate_w_rules`.

**Writable-entry gating (LLR-004.5, increment-2 risk note).** A writable entry
is one whose resolution `status` is `RESOLVED`. `UNRESOLVED` and
`INDEX_OUT_OF_RANGE` entries are excluded, each producing one warning
`ValidationIssue` (code `W-INSTANCE-EXCLUDED`). The writer gates on the entry
`status`, **not** on "is a resolved type present" — an `INDEX_OUT_OF_RANGE`
entry still has a `ResolvedType` in `ResolutionResult.resolved_types`, so a
type-presence gate would wrongly write it. `test_tc019d_index_out_of_range_*`
pins this.

**Zero-writable handling (LLR-004.6 / finding A-05).** When zero entries are
writable — a literally-empty change-list or one where every entry was excluded
— the writer still emits a valid backbone-only document plus exactly one
`W-EMPTY-CHANGELIST` warning, *in addition* to any per-entry exclusion
warnings. Two all-unresolved entries therefore yield three warnings total (two
`W-INSTANCE-EXCLUDED` + one `W-EMPTY-CHANGELIST`).

**Ordering (increment-1 risk note).** The writer iterates `ChangeList.entries`
(insertion order) and introduces **no second ordering rule**. Two writes of
the same change-list are byte-identical — `test_tc012_instance_order_*` asserts
`first == second` byte-for-byte.

**Tool-comment placement (increment-4 risk note).** The leading XML comment is
composed as raw text *between* the `<?xml ...?>` declaration and the `<MSRSW>`
root, so the document stays well-formed and re-parseable. `ElementTree`
discards the comment on re-parse, so the tests assert the comment against the
**raw bytes** and separately re-parse for well-formedness.

**Float serialization (LLR-004.8 / finding Q-10).** A `float` `V` value is
rendered with `repr()` — the shortest text that round-trips the binary64 value
exactly — so the adversarial `0.1` / denormal `5e-324` / 17-digit cases
survive without tolerance. An `int` is rendered with `str()` directly (never
routed through `float`), so a large `A_UINT64` above `2**53` keeps every digit.

All CDFX issues are `ValidationIssue` with `artifact="cdfx"` (LLR-006.3 /
DD-5), reusing the existing `validation/model.py` — no new issue model.
`cdfx/__init__.py`, `changelist.py`, `resolve.py`, `display.py`, `a2l.py` are
**byte-unchanged**; the increment plan schedules the `__init__.py` re-export
extension for increment 7. `pyproject.toml` / `requirements.txt` are
byte-unchanged — no new dependency.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/writer.py` | new | `write_cdfx` (CDF 2.0 backbone + `SW-INSTANCE` + `V`/`VG`/`VT` + tool note + `repr()` floats), `validate_w_rules` / `validate_w_rules_bytes` (standalone `W-*` validator), and the private helpers. LLR-004.1..004.8, LLR-006.1. |
| `tests/test_cdfx_writer.py` | new | TC-011..TC-014, TC-032, TC-033 — 18 tests exercising the writer end-to-end. |
| `tests/test_cdfx_w_rules.py` | new | TC-019a..TC-019h — 15 tests: the standalone `W-*` validator fed crafted broken trees, the writer-provokable exclusion / empty paths, and the four `analysis` writer-cannot-provoke records. |

3 files — within the ≤5 cap and matching the increment-4 spec exactly.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -c "import s19_app.tui.cdfx.writer"             # writer module imports
python -m py_compile s19_app/tui/cdfx/writer.py tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py
```

Round-trip well-formedness check (the writer output re-parses cleanly):

```
python -c "from xml.etree import ElementTree as ET; from s19_app.tui.cdfx.changelist import ChangeList, ResolutionStatus; from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType; from s19_app.tui.cdfx.writer import write_cdfx; cl=ChangeList(); e=cl.add('IGN',0,12.5,ResolutionStatus.RESOLVED); r=ResolutionResult(change_list=cl); r.resolved_types[e.key]=ResolvedType('VALUE','FLOAT32_IEEE',1); d,i=write_cdfx(cl,r); print(ET.fromstring(d).tag)"
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the three new files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_writer.py tests/test_cdfx_w_rules.py`** →
  `33 passed in 0.09s`.
- **`pytest -q` (full suite)** → `499 passed, 2 skipped, 3 xfailed in 184.65s`,
  `27 snapshots passed`, **0 failed**. Baseline was 466 passed / 2 skipped /
  3 xfailed; 466 + 33 new = 499 — exact, no regression.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK` (clean exit).
- **`python -c "import s19_app.tui"`** → `IMPORT_TUI_OK` (clean exit).
- **`python -m py_compile` on the 3 new files** → `PY_COMPILE_OK`.
- **Round-trip parse** → `ROUNDTRIP_PARSE_OK root= MSRSW issues= 0`; the
  emitted document matches the research §5 minimal-example shape
  (declaration → `<!-- Created with s19_app CDF 2.0 Writer -->` → `MSRSW`
  backbone → `SW-INSTANCE`s with `V`/`VT`).

One bug was found and fixed during the run, not shipped silently:
`test_tc019g` initially failed because `_category_value_consistent` accepted a
`CATEGORY=VALUE` instance whose single `V` was nested inside a `VG`. Research
§7's "`VALUE` has exactly one `V`" means one **bare** `V` directly under
`SW-VALUES-PHYS`; the fix adds `vg_count == 0` to the `VALUE`/`BOOLEAN` arm so
a `VG` shape is correctly flagged inconsistent. Re-run → 33 passed.

The 33 new tests by TC:

**`tests/test_cdfx_writer.py` (18 tests):**
- **TC-011** (CDF 2.0 backbone, LLR-004.1) — 2 tests: root is `MSRSW` with a
  non-empty `SHORT-NAME` and `CATEGORY=CDF20`; the
  `SW-SYSTEMS→SW-SYSTEM→SW-INSTANCE-SPEC→SW-INSTANCE-TREE` chain is present
  with `SHORT-NAME`s.
- **TC-012** (one `SW-INSTANCE` per resolved entry, LLR-004.2) — 3 tests:
  scalar entry → `SW-INSTANCE` `CATEGORY=VALUE` with `SHORT-NAME` = parameter
  name; three resolved entries → three instances; instance order = change-list
  insertion order and two writes are byte-identical.
- **TC-013** (scalar / array / string encoding, LLR-004.3) — 4 tests: scalar →
  one `V`; 3-element array → `VG` of positional `V`; string → one `VT`; no
  `SW-ARRAY-INDEX` element anywhere (finding A-09).
- **TC-014** (well-formed UTF-8 XML + tool note, LLR-004.4/004.7) — 2 tests:
  output has an XML declaration and re-parses; the leading tool comment is
  present, precedes `<MSRSW>`, and the document still re-parses.
- **TC-032** (dedicated tool-note check, LLR-004.7) — 2 tests: the tool note is
  a leading XML comment placed after the declaration and before the root; the
  note is present even on an empty-change-list write.
- **TC-033** (round-trip-safe float emission, LLR-004.8) — 5 tests: `0.1` → V
  text `repr(0.1)`; the denormal `5e-324` survives (text re-parses `== 5e-324`,
  `!= 0.0`); a 17-significant-digit float keeps its tail; a large integer
  (`2**64-1`) renders exact decimal text (never via `float`).

**`tests/test_cdfx_w_rules.py` (15 tests):**
- **TC-019a** (`W-XML-WELLFORMED`, invariant) — 2 tests: `validate_w_rules_bytes`
  on non-well-formed bytes → one `W-XML-WELLFORMED` error; **analysis** — the
  real writer's output passes `validate_w_rules_bytes` with zero issues.
- **TC-019b** (`W-ROOT-MSRSW`, invariant) — 2 tests: validator on a non-`MSRSW`
  root → one `W-ROOT-MSRSW` error; **analysis** — the real writer always roots
  at `MSRSW`.
- **TC-019c** (`W-BACKBONE`, invariant) — 3 tests: validator on a missing
  backbone and on a partial backbone → one `W-BACKBONE` error each; **analysis**
  — the real writer always emits the full backbone (even on an empty write).
- **TC-019d** (`W-INSTANCE-NAME` + exclusion, LLR-006.1/004.5) — 3 tests:
  validator on an empty-`SHORT-NAME` instance → one `W-INSTANCE-NAME` error;
  an `UNRESOLVED` entry is excluded with one warning while a valid sibling is
  still written; an `INDEX_OUT_OF_RANGE` entry is excluded (status-gated, not
  type-gated).
- **TC-019e** (`W-INSTANCE-CATEGORY`) — 1 test: validator on a `MAP`-category
  instance → one `W-INSTANCE-CATEGORY` error.
- **TC-019f** (`W-VALUE-PRESENT`) — 1 test: validator on an instance with an
  empty `SW-VALUES-PHYS` → a `W-VALUE-PRESENT` error.
- **TC-019g** (`W-CATEGORY-VALUE-CONSISTENT`, invariant) — 2 tests: validator
  on a `CATEGORY=VALUE` instance carrying a `VG` → one
  `W-CATEGORY-VALUE-CONSISTENT` error; **analysis** — the real writer always
  matches value shape to category across scalar / array / string writes.
- **TC-019h** (`W-EMPTY-CHANGELIST`, LLR-006.1/004.6) — 2 tests: an empty
  change-list → valid backbone-only file + one `W-EMPTY-CHANGELIST` warning;
  two all-unresolved entries → two `W-INSTANCE-EXCLUDED` + one
  `W-EMPTY-CHANGELIST` = three warnings total.

## 5. Risks

- **VAL_BLK serialization is one `SW-INSTANCE` per change-list entry.** The
  increment-1 model keys each entry by `(parameter_name, array_index)`, so a
  3-element array characteristic is **three separate entries** (`P[0]`, `P[1]`,
  `P[2]`). This increment's writer emits **one `SW-INSTANCE` per entry**, each
  a `VAL_BLK` with a `VG` holding that entry's single `V` — it does **not**
  coalesce the three entries into one `SW-INSTANCE` with a 3-`V` `VG`. The
  research §5 example shows one `SW-INSTANCE` with a `VG` of three `V`. This is
  a **structural divergence** flagged for increment 5/8: the round-trip test
  (TC-024, increment 8) will read back three instances of the same name, not
  one array. The plan's increment-4 LLR scope (LLR-004.3 "an array value as a
  `VG` containing one positional `V` per element") is satisfied per *entry*,
  but the per-array coalescing is not specified by any LLR-004.x statement and
  was **not** invented here. **Decision needed before increment 8:** either the
  reader treats repeated `SHORT-NAME`s as array elements, or the writer
  coalesces same-name entries — surface to `architect`. No coalescing was added
  speculatively (engineering rule 2).
- **`W-INSTANCE-EXCLUDED` is a new issue code not in research §7's `W-*` list.**
  Research §7 enumerates eight `W-*` codes; LLR-004.5 requires "one
  warning-level `ValidationIssue` per excluded entry" but does not name a code.
  This increment uses `W-INSTANCE-EXCLUDED` for that warning. It is a writer
  *behavior* code (the LLR-004.5 exclusion path), distinct from the eight `W-*`
  *rule* codes — consistent with how §7 itself separates the tool-note /
  float-precision *behaviors* from the issue-emitting *rules*. Flagged so the
  code name is an explicit choice, not silent drift; rename is a one-liner if
  Phase 4 wants `W-ENTRY-EXCLUDED` or similar.
- **`validate_w_rules` short-circuits after `W-ROOT-MSRSW` / `W-BACKBONE`.**
  When the root is not `MSRSW` or the backbone is incomplete, the validator
  returns after that single issue rather than also walking instances — the
  tree shape is unknown, so per-instance checks would be noise. This means a
  doubly-broken tree (wrong root *and* bad instances) reports only the root
  issue. Acceptable — fix the structural break first — but recorded so the
  collect-all behavior is understood as scoped to a recognizable tree.
- **The tool comment is asserted against raw bytes, not the parsed tree.**
  `ElementTree` discards comments on `fromstring`. TC-014/TC-032 therefore
  check the comment in the decoded byte string and re-parse separately for
  well-formedness. A future change that serializes via `ElementTree.write`
  (which can carry comment nodes) would need the tests revisited — the current
  raw-text composition is deliberate and the simplest stdlib path.
- **`W-CATEGORY-VALUE-CONSISTENT` bug fixed mid-increment.** The
  `VALUE`/`BOOLEAN` consistency arm now requires `vg_count == 0`. A `VG`-shaped
  scalar is flagged. This was caught by TC-019g and is the correct §7 reading;
  noted because it is a logic change relative to the first-written draft.

## 6. Pending items

- **`cdfx/__init__.py` re-export of `write_cdfx` / `validate_w_rules`** is
  deferred to increment 7, per the increment plan. This increment's tests
  import from `s19_app.tui.cdfx.writer` directly, keeping the increment at
  exactly the 3 spec'd files.
- **TC-003's "byte-identical `SW-INSTANCE`" verdict** — staged from increment 1
  — is now closed by `test_tc012_instance_order_matches_changelist_insertion_order`
  (asserts `first == second` byte-for-byte through the real writer). Recorded
  so Phase 4 sees TC-003 fully covered across increments 1 and 4.
- **TC-024 (write→read round-trip) and TC-033's read-back arm** are increment
  8, per the plan. This increment lands only the writer-side float emission;
  the read-back proof needs the reader (increment 5). The VAL_BLK
  one-instance-per-entry divergence (risk §5) must be resolved before TC-024.
- **`CV-01..CV-03`** (Phase-2 closure cosmetic doc / test-comment items) —
  carried over from increments 1–3; still open. No natural touch-point arose
  in these 3 new files. Surfaced again so they are not lost.
- **`change_list_factory` / `make_patch_a2l` relocation to `conftest.py`** —
  the writer tests build resolved change-lists with local helpers
  (`_resolved_change_list`) rather than the factory, mirroring the display
  tests' approach. The §5.4 factory relocation stays an increment-5/8 call.

## 7. Suggested next task

**Increment 5 — CDFX reader + `R-*` validation + A2L cross-checks.** Create
`s19_app/tui/cdfx/reader.py` (`read_cdfx` — `ElementTree` parse,
namespace-stripping local-name match, `SW-INSTANCE` lookup scoped to the
`SW-INSTANCE-TREE` backbone, `V`/`VG`/`VT` decode, all core `R-*` codes,
version tolerance, tool-note tolerance, A2L name / array-length cross-checks),
`tests/test_cdfx_reader.py` and `tests/test_cdfx_r_rules.py`. 12 TCs
(TC-015..018, TC-020..023, TC-029..031, TC-034), 3 files. **Before increment 8
the VAL_BLK one-`SW-INSTANCE`-per-entry vs. one-per-array divergence (risk §5)
must be decided** — raise it to `architect`: the reader's "repeated
`SHORT-NAME`" handling and the writer's coalescing choice are two sides of the
same decision and TC-024's round-trip depends on it.

---

**Stop boundary reached.** Increment 4 is complete: the two new test modules
are green (33 passed), the full suite is 499 passed / 0 failed (466 baseline +
33), `s19_app.tui.cdfx` imports unchanged, the writer output round-trip-parses
as well-formed CDF 2.0, and no UI behavior changed. Awaiting approval before
starting increment 5.
