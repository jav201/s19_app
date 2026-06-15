# Increment I1 — Intel HEX emitter (HLR-001 / LLR-001.1..4)

Batch 2026-06-13-batch-10 · Phase 3 · branch `claude/batch-09` (worktree `competent-clarke-1e8940`).

> **STATUS (redo R2): RESOLVED — lean suite GREEN, 0 failures.** The §5 BLOCKER
> below was a spec/code contradiction: the original I1 placed the emitter in the
> frozen engine module `s19_app/hexfile.py`, tripping the three "engine unchanged
> vs main" guards. The operator chose **R2: relocate the emitter to
> `s19_app/tui/changes/io.py`** (next to `emit_s19_from_mem_map`,
> emission-purpose cohesion; io.py is not a frozen engine module → zero guards).
> This redo reverted `hexfile.py` to pristine and moved the emitter to io.py.
> The 3 engine-frozen guards are now GREEN, the lean suite has 0 failures. The
> original blocker write-up (§5) is retained below for the record; see the
> **Redo (R2 relocation)** section immediately following for the current state.

---

## 0. Redo (R2 relocation) — current state

**Decision:** operator picked **R2** (relocate emitter), NOT R1 (un-freeze
`hexfile.py`). Spec `.dev-flow/2026-06-13-batch-10/01-requirements.md` amended:
LLR-001.1 now names `s19_app/tui/changes/io.py`; D-A resolves to format/emission
cohesion alongside the S19 emitter.

**What the redo did (2 files touched + 1 reverted to pristine):**

- **`s19_app/hexfile.py` — REVERTED to pristine** via `git checkout -- ` (net
  zero diff vs HEAD/main; NOT a touched file). This is what un-trips the three
  engine-frozen guards. `git diff --stat s19_app/hexfile.py` → **empty**.
- **`s19_app/tui/changes/io.py` — ADD** `emit_intel_hex_from_mem_map` +
  `_intel_hex_record` + `HEX_DATA_BYTES_PER_RECORD`, placed after
  `emit_s19_from_mem_map`/`_s19_record` (the S19 emitter at `io.py:1298`).
  Re-exported via `__all__` for symmetry with `emit_s19_from_mem_map`. Same
  proven algorithm as the prior location (10 tests passed there) — a
  relocation, not a rewrite. Style adapted to io.py: lowercase `dict`/`list`
  builtins (matching `emit_s19_from_mem_map`), no `Dict`/`List`. +123 lines
  (1232 → 1337 io.py LOC). No `textual` import, no new dependency.
- **`tests/test_hex_emit.py` — RE-POINTED** import: `HEX_DATA_BYTES_PER_RECORD`
  and `emit_intel_hex_from_mem_map` now from `s19_app.tui.changes.io`;
  `IntelHexFile` (the read oracle) still from `s19_app.hexfile`. All 10 nodes +
  assertions kept verbatim; module docstring updated to name the relocated home.

**Redo verification results (exact numbers):**

| # | Verification | Result |
|---|---|---|
| 1 | `git diff --stat s19_app/hexfile.py` | **EMPTY** (pristine — engine-frozen guards satisfied) |
| 2 | `pytest -q tests/test_hex_emit.py` | **10 passed** in 0.47s |
| 3 | 3 engine-frozen guards (`test_engine_unchanged.py` + 2× `test_tc031_*`) | **3 passed** in 0.50s — the original blocker is GONE |
| 4 | 2 allowlist guards (`test_tc028_*` + `_inc10`) | **2 passed** in 0.42s (io.py is neither root nor engine → trips nothing) |
| 5 | `pytest -q tests/test_changes_apply.py` (io.py round-trip regression) | **16 passed** in 0.43s |
| 6 | `pytest -q -m "not slow"` (GATE) | **739 passed, 29 skipped, 21 deselected, 3 xfailed, 0 FAILED** in 215.17s |
| 7 | `pytest -q --collect-only` last line | **792 tests collected** (782 baseline + 10 new) |
| 8 | `rg "import textual\|from textual" s19_app/tui/changes/io.py` | **0 matches** (V-4 purity holds) |
| 9 | node ids + file name | 10 nodes (listed in A-3/V-5 below), file `tests/test_hex_emit.py` — MATCH |

**Collection ledger:** 782 → 792 (+10). **Lean suite: 3 failed → 0 failed.**

**Deviation from prior I1:** the prior +119-line emitter lived in `hexfile.py`
with `Dict`/`List` typing; the redo carries the identical algorithm in io.py with
lowercase `dict`/`list` builtins to match `emit_s19_from_mem_map`'s style. No
algorithm change. `REQUIREMENTS.md` R-* row still deferred (out of 2-file scope;
the increment is now landable so the orchestrator may add it at the gate).

---

## 1. What changed

Added a headless, pure Intel HEX emitter to the format module that already
*reads* Intel HEX. `emit_intel_hex_from_mem_map(mem_map, ranges) -> str`
serializes a sparse memory map into structurally valid Intel HEX text:
type-0x04 Extended-Linear-Address records whenever the active upper-16 bits of
the address change (including the first address above 0xFFFF), type-0x00 data
records of ≤16 bytes each, and exactly one type-0x01 EOF record
(`:00000001FF`). Each record carries the Intel HEX two's-complement-of-sum
checksum, matching the reader oracle at `hexfile.py:66-74`. Output is
deterministic (ranges sorted ascending). Empty input emits the EOF record
alone. No I/O, stdlib-only, no `textual` import. A private `_intel_hex_record`
builder mirrors `_s19_record` (`io.py:1370`). Added `tests/test_hex_emit.py`
(10 nodes) covering low-address round-trip, 16-byte/checksum, ELA high-address
(≥0x10000), second-boundary ELA, empty/EOF, public-example round-trip, and a
byte-stability MEASURE (informative, not gated).

## 2. Files modified (2 — within cap)

- `s19_app/hexfile.py` — ADD `emit_intel_hex_from_mem_map` + `_intel_hex_record`
  + `HEX_DATA_BYTES_PER_RECORD` constant (+119 lines, purely additive; no
  existing reader line touched).
- `tests/test_hex_emit.py` — NEW; 10 test nodes (HLR-001 round-trip suite +
  byte-stability MEASURE). Module docstring maps test→TC→LLR.

> Note: the I1 plan in 01-requirements.md §6.3 listed 3 files including a
> `REQUIREMENTS.md` R-* row. I did NOT touch `REQUIREMENTS.md` this increment
> because the spec gave it as optional traceability and the blocker (§5) means
> the increment is not landable as-is — deferring the R-* update avoids
> recording a passing claim that the suite does not yet support (F-X1
> discipline). Flagged as pending (§6).

## 3. How to test

```
python -m pytest -q tests/test_hex_emit.py
python -m pytest -q tests/test_hexfile.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only
rg -n "import textual|from textual" s19_app/hexfile.py
python -m pytest -q tests/test_tui_directionb.py::test_tc028_no_new_processing_module_added_outside_view_layer tests/test_tui_directionb.py::test_tc028_no_new_processing_module_added_outside_view_layer_inc10 tests/test_tui_directionb.py::test_tc028_processing_libs_absent_from_pyproject
```

## 4. Test results (exact numbers)

| # | Verification | Result |
|---|---|---|
| 1 | `pytest -q tests/test_hex_emit.py` | **10 passed** in 0.14s |
| 2 | `pytest -q tests/test_hexfile.py` (reader regression) | **14 passed** in 0.15s |
| 3 | `pytest -q -m "not slow"` | **3 failed, 736 passed, 29 skipped, 21 deselected, 3 xfailed** in 211.06s |
| 4 | `pytest -q --collect-only` last line | **792 tests collected** (= 782 baseline + 10 new; D=0, N_new=10) |
| 5 | `rg "import textual\|from textual" s19_app/hexfile.py` | **0 matches** (purity holds) |
| 6 | census guards `test_tc028_*` (both) | **2 passed** (+ dep guard `test_tc028_processing_libs_absent_from_pyproject` passed → 3 passed total). G-1's zero-census-trip claim holds for the package-root/dep guards. |
| 7 | No new dep (bincopy/crcmod/pya2l) | confirmed — emitter is hand-rolled stdlib only; dep guard GREEN |

**Collection ledger:** 782 → 792 (+10, no regression; signed balance `792 == 782 − 0 + 10`).

**ELA record-type==0x04 assertion (LLR-001.3):** GREEN —
`sum(1 for r in IntelHexFile(written).records if r.record_type == 0x04) >= 1`
holds for the `0x08040000` span (test_ela_high_address_roundtrip); a
two-boundary span asserts `>= 2` (test_ela_record_emitted_per_upper16_change).
High address survives in `.memory` (`base in reread.memory`).

**Byte-stability MEASURE value:** `emit(parse(emit(x))) == emit(x)` → **True**
(recorded via `record_property("emit_parse_emit_byte_stable", True)`). Both
emissions consume the same canonical mem_map, so identity is expected and held.
This is the achievable in-test MEASURE; the spec's looser
`emit(parse(file)) == file` against a foreign-authored HEX file is NOT
assertable here because examples/ has zero `.hex` files (A5) — there is no
foreign HEX file to canonicalize-compare against. Recorded, not gated.

### The 3 failures (verification #3) — all the SAME root cause

```
FAILED tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main
FAILED tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main
FAILED tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main
```

All three are "engine modules unchanged / zero-diff vs `main`" guards whose
`_ENGINE_PATHS` set **lists `s19_app/hexfile.py` by name**
(`test_engine_unchanged.py:120-127`; `test_tui_directionb.py:3738-3744`). They
run `git diff main -- <engine paths>` and assert empty. My +119-line emitter
addition to `hexfile.py` makes that diff non-empty, so they fail. `git diff
--stat main` over the full engine set shows the emitter is the ONLY engine-path
change (`s19_app/hexfile.py | 119 +++…`, 1 file changed, 119 insertions(+)) —
purely additive, no existing reader line modified.

## 5. Risks / the BLOCKER (loud)

**BLOCKER — spec/code contradiction at G-1/D-A.** Decision D-A=(a) (§6.2) and
gate-confirmable G-1 placed the emitter in `hexfile.py` and asserted it "trips
ZERO guards" — but the census (§6.3 P-5, risk R-10-CENSUS) only enumerated the
two `test_tc028_*` package-root **allowlist** guards and the purity guard. It
did **not** enumerate the THREE engine-**read-only** guards
(`test_tc027_engine_modules_unchanged_vs_main`,
`test_tc031_engine_modules_have_no_diff_vs_main`,
`test_tc031_engine_modules_have_no_name_only_diff_vs_main`) which freeze
`hexfile.py` (and `core.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
`tui/mac.py`, `tui/color_policy.py`) at zero-diff-vs-main. ANY edit to
`hexfile.py` — even a pure additive emitter — trips all three. So the spec's
"zero guard trips" claim for D-A=(a) is **incorrect for these three guards.**

This is squarely a boundary stop: resolving it is OUTSIDE HLR-001's LLRs and
OUTSIDE my 2-file scope. The viable resolutions all need orchestrator/operator
sign-off because they change a standing read-only-engine contract three batches
(04/07/09) have relied on, or they relocate the emitter against D-A:

- **(R1) Amend the guard contract** — remove `s19_app/hexfile.py` from
  `_ENGINE_PATHS` in BOTH `test_engine_unchanged.py:120` and
  `test_tui_directionb.py:3738` (and reconcile the LLR-014.1 docstring text at
  `test_tui_directionb.py:67,4230`). This formalizes that `hexfile.py` is no
  longer frozen now that it legitimately owns the writer. Touches 1 extra test
  file beyond my budget (2 guard files) and edits a cross-batch contract →
  needs approval. The batch-09 precedent for `compare.py` is the analogue, but
  `compare.py` was a NEW root module added to allowlists, not the un-freezing of
  an already-frozen engine module — a stronger contract change.
- **(R2) Relocate the emitter to a new module** (`hexemit.py` or fold into the
  I2 verify module) — but this is exactly D-A option (b), which the spec
  REJECTED for tripping the two `test_tc028_*` allowlist guards (R-10-CENSUS),
  and which contradicts the operator's "divide by purpose / format-cohesion"
  rationale. Trades one guard problem for another.
- **(R3) Reopen G-1 at the gate** with this measured evidence and let the
  operator pick.

I recommend **R1 + reopening G-1** (the operator explicitly chose
format-cohesion; un-freezing `hexfile.py` honors that intent and is the minimal
change), but I am NOT executing it — it is a contract/scope decision for the
gate.

**Other risks (low):** the emitter assumes every address in `ranges` is present
in `mem_map` (same contract as the S19 emitter; raises `KeyError` otherwise —
a caller bug, not data quality). No coverage of addresses ≥ 0x1_0000_0000
(beyond 32-bit) — out of Intel HEX's 32-bit address space and out of scope.

## 6. Pending items

- **Resolve the §5 BLOCKER** (gate decision R1/R2/R3) before this increment can
  land — the lean suite is RED until then.
- `REQUIREMENTS.md` R-* traceability row for HLR-001 (deferred per §2 until the
  increment is landable; F-X1 discipline).
- I2–I4 are untouched (verify-on-save engine, HEX save-back, TUI surfacing +
  hygiene) — by design, this increment is HLR-001 only.

## 7. Suggested next task

Take the §5 blocker to the gate (reopen G-1 with the measured 3-guard
evidence). On approval of R1, the follow-up increment is a 2-file change:
remove `s19_app/hexfile.py` from `_ENGINE_PATHS` in `test_engine_unchanged.py`
and `test_tui_directionb.py` (+ reconcile the LLR-014.1 docstring text), which
turns the lean suite GREEN and makes I1 landable. THEN proceed to I2
(verify-on-save engine, HLR-003).

---

## A-3 / V-5 reconciliation — actual node ids + file name vs provisional spec names

**File created:** `tests/test_hex_emit.py` (spec provisional name was
`tests/test_hex_emit.py` — **MATCH, no drift**).

**Actual pytest node ids (10):**

| Node id | TC (provisional) | LLR |
|---|---|---|
| `tests/test_hex_emit.py::test_low_address_roundtrip[single-byte]` | TC-001/TC-004 | LLR-001.1/.2/.4 |
| `tests/test_hex_emit.py::test_low_address_roundtrip[multi-row-contiguous]` | TC-001/TC-004 | LLR-001.1/.2/.4 |
| `tests/test_hex_emit.py::test_low_address_roundtrip[two-disjoint-ranges]` | TC-001/TC-004 | LLR-001.1/.2/.4 |
| `tests/test_hex_emit.py::test_data_records_max_16_bytes_and_checksum` | TC-002 | LLR-001.2 |
| `tests/test_hex_emit.py::test_ela_high_address_roundtrip` | TC-003 | LLR-001.3 |
| `tests/test_hex_emit.py::test_ela_record_emitted_per_upper16_change` | TC-003 | LLR-001.3 |
| `tests/test_hex_emit.py::test_empty_mem_map_emits_eof_only` | TC-004 | LLR-001.4 |
| `tests/test_hex_emit.py::test_output_terminates_with_single_eof` | TC-004 | LLR-001.4 |
| `tests/test_hex_emit.py::test_public_example_roundtrips_as_hex` | TC-001/TC-004 | LLR-001.4 |
| `tests/test_hex_emit.py::test_byte_stability_measure` | (MEASURE, informative) | — |

**Drift:** the spec used `-k` shorthand fragments (`data_record or checksum`,
`ela or extended or above_64k`, `roundtrip or eof`) as provisional node
selectors; actual node names differ in wording but each `-k` fragment still
matches ≥1 real node:
- `-k "data_record or checksum"` → matches `test_data_records_max_16_bytes_and_checksum`
- `-k "ela or extended or above_64k"` → matches `test_ela_high_address_roundtrip`, `test_ela_record_emitted_per_upper16_change`
- `-k "roundtrip or eof"` → matches `test_low_address_roundtrip[*]`, `test_empty_mem_map_emits_eof_only`, `test_public_example_roundtrips_as_hex`, `test_output_terminates_with_single_eof`

New public symbols created (vs §4 symbol-citation key):
`emit_intel_hex_from_mem_map` (signature `(mem_map: Dict[int,int], ranges:
List[tuple[int,int]]) -> str`), `_intel_hex_record(record_type, address, data)`,
`HEX_DATA_BYTES_PER_RECORD = 16` (constant, not in the spec key — minor,
internal). The spec key also named `_emit_ela_record`; I did NOT create a
separate ELA builder — ELA records are emitted through the single
`_intel_hex_record` builder (one record-builder for all three types is simpler
and the reviewer's "mirror `_s19_record`" intent is preserved). **Drift noted:
`_emit_ela_record` symbol not created; folded into `_intel_hex_record`.**
