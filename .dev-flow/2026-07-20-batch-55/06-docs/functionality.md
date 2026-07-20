# The inline-axis length summer — how it works (batch-55)

> **Audience:** engineers and technical reviewers working on the A2L parsing layer. **Purpose:** understand what the summer computes, the safety contract it honors, and its known limitation.
> **Scope:** `s19_app/tui/a2l.py` — `_record_layout_full_span`, `_inline_axis_counts`, the axis-kind census constants, the post-axis-walk length pass, and the `_extract_raw_bytes` DoS clamp.

## BLUF

A CURVE or MAP calibration object in an A2L file is an **array** — a 1-D or 2-D table of values plus its axis points, all stored contiguously on the ECU image. Before batch-55, the parser could not compute how many bytes such an object occupies, so it left `length = None`. The A2L view then rendered the row **grey** ("not memory-checked"): with no byte span, the memory-coverage check cannot run, even when the object's address is perfectly valid.

batch-55 adds a **summer** that derives the correct byte span for CURVE/MAP objects whose axes are stored **inline** (STD_AXIS / FIX_AXIS), by summing the on-disk sizes declared in the object's RECORD_LAYOUT, scaled by the axis point-counts. Objects whose axes live in a **separate record** (COM_AXIS / RES_AXIS / CURVE_AXIS, or any `AXIS_PTS_REF`) are left `length = None` on purpose — their storage is not resolvable from the tag alone, and guessing would risk a **false-green** (a too-short length that wrongly passes the memory check on a safety artifact).

On the demo (`examples/case_00_public/ASAP2_Demo_V161.a2l`): of the 12 CURVE/MAP objects, **8 now derive a correct byte length** and become memory-checkable; **4 stay honestly grey** (external axis); **0 derive a wrong value**.

---

## 1. The problem

The A2L (ASAM MCD-2 MC) format describes each calibration object with two things:

- a **CHARACTERISTIC** block — its type (`VALUE`, `CURVE`, `MAP`, …), address, and a reference to a RECORD_LAYOUT; plus one `AXIS_DESCR` per axis;
- a **RECORD_LAYOUT** block — the on-disk byte layout, one component per line (e.g. `AXIS_PTS_X 2 SBYTE …`, `FNC_VALUES 3 SWORD …`).

For a scalar `VALUE`, the byte span is a single datatype size — already handled before this batch. For a **CURVE** (1 axis) or **MAP** (2 axes), the span is the sum of:

- each axis's stored points (`AXIS_PTS_X` = `n_x` elements, `AXIS_PTS_Y` = `n_y` elements),
- one count byte per axis (`NO_AXIS_PTS_X`, `NO_AXIS_PTS_Y`),
- the function values table (`FNC_VALUES` = `n_x` for a CURVE, `n_x · n_y` for a MAP),

each multiplied by its datatype size. Deriving this requires reading the RECORD_LAYOUT body and knowing each axis's point-count. batch-54 (the prerequisite) made the parser populate `char_type`, `record_layout_name`, and per-axis `axis_meta` (kind, `max_axis_points`, `external` flag). batch-55 consumes those fields to compute the span.

**Why grey matters:** a grey row is not a cosmetic default — it means the tool cannot tell the calibration engineer whether that object's bytes are actually present in the loaded firmware image. For array objects (the bulk of a real calibration dataset), that was a real coverage blind spot.

---

## 2. The solution

Two private module-level helpers plus a wiring block, all in `a2l.py` (the frozen A2L oracle, unfrozen for this batch and re-frozen post-merge).

### 2.1 `_inline_axis_counts(axis_meta)` — the axis resolver + external gate

Returns the ordered list of integer axis point-counts, **or `None`** if the object is not derivable. It returns `None` when:

- there is no axis (`axis_meta == []`),
- any axis kind is outside `_DERIVABLE_AXIS_KINDS` (i.e. it is COM_AXIS / RES_AXIS / CURVE_AXIS),
- any axis carries the `external` flag (an `AXIS_PTS_REF` — storage lives in a separate AXIS_PTS record),
- any `max_axis_points` is missing, non-numeric, or `≤ 0`.

`max_axis_points` is a **string** (`axis_tokens[3]`, a spec decimal). It is cast with a **base-10** `int(str(mp).strip())` inside a `try/except (ValueError, TypeError)` that returns `None` on failure. Base-10 is deliberate:

- **not base-0** — base-0 would widen the grammar to `0x`/`0o`/`0b` and, worse, *raise* on a leading-zero decimal like `'08'`; a legitimate `'08'` must parse to `8`, not crash the load;
- **not an `isdigit()`/regex pre-predicate** — `'08'.isdigit()` is `True` but a mismatched predicate/cast could still raise; the guard is the `try/except` around the real `int()` call, honoring the parser's collect-don't-abort contract.

### 2.2 `_record_layout_full_span(layout, axis_counts)` — the component summer

Iterates the RECORD_LAYOUT body lines and returns `Σ (datatype_size × element_count)`, **or `None`** (full-span-or-None).

Per line, the component name is `token[0]` and the **datatype is `token[2]`**. Critically, `token[1]` is the ASAM **position index** (an ordering field), **not a count** — reading it as a count is the classic bug this design guards against (a position-as-count mutation turns the CURVE oracle from 25 into 9).

Element count per component (the §2.5 taxonomy, keyed on `axis_counts = [n_x, n_y, n_z]`):

| Component | Element count |
|-----------|---------------|
| `NO_AXIS_PTS_X` / `_Y` / `_Z`, `NO_RESCALE_X` | `1` (a scalar count byte) |
| `AXIS_PTS_X` | `n_x` = `axis_counts[0]` |
| `AXIS_PTS_Y` | `n_y` = `axis_counts[1]` |
| `AXIS_PTS_Z` | `n_z` = `axis_counts[2]` |
| `FNC_VALUES` | `math.prod(axis_counts)` (CURVE → `n_x`; MAP → `n_x·n_y`) |
| **any other non-empty line** | **→ whole span returns `None`** |

Datatype size comes from `DATATYPE_SIZES.get(token[2])` (`.get`, never a subscript — a subscript would raise `KeyError` instead of failing closed).

### 2.3 The full-span-or-None safety contract

The summer returns a byte total **only if every component and every needed axis count is classifiable**; otherwise `None`. This is not defensiveness for its own sake — it enforces **never under-report**. A too-short length would let an array's byte-range memory check pass over bytes that are not actually there — a false-green on a safety artifact. Grey (honest "unknown") is always preferable to a wrong-but-plausible number.

Concretely, any of these degrade the whole span to `None`:

- an axis is external (handled upstream by `_inline_axis_counts`);
- a RECORD_LAYOUT line's `token[0]` is not a recognized summable component;
- a recognized component is missing its datatype token (`< 3` tokens);
- a datatype is unknown to `DATATYPE_SIZES`;
- a needed axis count is absent (`AXIS_PTS_Y` present but only one axis count);
- no component contributed;
- the running total exceeds `MAX_A2L_DECODE_BYTES` (the DoS cap).

### 2.4 ALIGNMENT directives → `None` (amendment A4)

A subtle case caught by the independent code review: an `ALIGNMENT_BYTE/WORD/LONG/…` directive is a **2-token** line that induces inter-component padding the summer does not model. An earlier "skip lines with fewer than 3 tokens as structural" filter would have **silently swallowed** such a directive and under-reported the span — the exact false-green the contract exists to prevent.

The shipped code (`a2l.py:1159-1165`) fixes this: **only a genuinely empty/whitespace line is skipped**. Every other non-empty line must classify as a summable component or force `None`. So an alignment-bearing CURVE/MAP degrades safely to grey today. Modeling the padding correctly (to *cover* those objects rather than grey them) is **batch-56** (see §5).

### 2.5 The DoS clamp

`MAX_A2L_DECODE_BYTES = 1_048_576` (1 MiB) bounds the byte-decode work against a hostile or malformed A2L. It is applied in two places:

- **`_record_layout_full_span`** — a running total exceeding the cap returns `None` (a pure-arithmetic compare; no allocation);
- **`_extract_raw_bytes`** — before the per-byte `range(byte_size)` loop (`a2l.py:1212`), a `byte_size > MAX_A2L_DECODE_BYTES` returns the unavailable result (`raw_available=False`) without allocating a byte_size-length list.

Placing the clamp in `_extract_raw_bytes` covers **both** the new CURVE/MAP path and the pre-existing scalar `element × matrix` path. 1 MiB is far above any legitimate single-CHARACTERISTIC span on these ECU images (the largest realistic inline map is tens of KB) while making a hostile record cheaply refused. This is a local self-DoS bound only — there is no remote, exec, or exfil surface. (It is distinct from batch-54's `R-A2L-013`, which bounds the comment-stripper.)

### 2.6 Wiring: the post-axis-walk length pass

The summer runs as a distinct block in `extract_a2l_tags`, placed **after** `tag["axis_meta"]` is fully built (`a2l.py:1454-1465`), gated on:

```
name == "CHARACTERISTIC" and tag["char_type"] in ("CURVE", "MAP") and tag["length"] is None
```

It computes `axis_counts = _inline_axis_counts(...)`, and if that is not `None`, resolves the layout via `record_layouts_by_name.get(...)` and sets `tag["length"] = _record_layout_full_span(layout, axis_counts)`.

Two ordering facts matter:

- **R2 ordering** — the summer needs `axis_meta`, which is populated *after* the earlier scalar/VALUE inference. Hence a separate post-walk pass, not a change to the existing `_infer_length_characteristic`.
- **`length is None` guard** — the pass only fills a still-empty length, so an explicit `LENGTH` / `MATRIX_DIM` / name-encoded-deposit value is never overwritten.

Everything downstream already reads `tag["length"]`: `enrich_tags_and_render` → the A2L view row severity. A derived length makes the byte-range memory check *applicable*, so a row that was grey (NEUTRAL) becomes green/checked when the image covers those bytes.

---

## 3. Worked oracle examples (executed over the real demo)

All values were reproduced by running `parse_a2l_file` over `ASAP2_Demo_V161.a2l` at design time (C-35) and again at implementation — identical results.

| Object | char_type | RECORD_LAYOUT breakdown | length |
|--------|-----------|-------------------------|--------|
| `ASAM.C.CURVE.STD_AXIS` | CURVE (1 axis, n_x=8) | `NO_AXIS_PTS_X` 1×UBYTE = 1 · `AXIS_PTS_X` 8×SBYTE = 8 · `FNC_VALUES` 8×SWORD = 16 | **25** |
| `ASAM.C.MAP.STD_AXIS.STD_AXIS` | MAP (2 axes, n_x=4, n_y=5) | `NO_AXIS_PTS_X` 1 + `NO_AXIS_PTS_Y` 1 + `AXIS_PTS_X` 4×SBYTE=4 + `AXIS_PTS_Y` 5×SBYTE=5 + `FNC_VALUES` (4·5)×SWORD = 40 | **51** |
| `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` | CURVE, FIX_AXIS (n_x=6) | `FNC_VALUES` 6×SWORD = 12 — **no on-disk AXIS_PTS line** (FIX_AXIS points are not stored) | **12** |
| `ASAM.C.CURVE.COM_AXIS` | CURVE, external `AXIS_PTS_REF` | axis storage in a separate AXIS_PTS record | **None** |
| `ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS` | CUBOID (3 axes) | excluded by the `char_type ∈ {CURVE, MAP}` gate | **None** |

The FIX_AXIS case (12) is worth noting: its RECORD_LAYOUT carries **only** `FNC_VALUES` — FIX_AXIS axis points are computed from parameters, not stored on the image, so the layout has no `AXIS_PTS` line. This distinct layout shape is why AT-107 pins it as a separate gate-blocking value oracle.

---

## 4. What is deliberately NOT touched (no-regression)

The summer never alters `length` for MEASUREMENT tags, scalar VALUE CHARACTERISTICs, VAL_BLK, ASCII, `char_type`-`None` records, the 3-axis CUBOID, or any CHARACTERISTIC whose `length` was already non-`None`. On the demo, only the 8 inline CURVE/MAP rows change (grey → int); every other tag field is byte-identical to pre-batch output. Full suite: 0 fail, 0 snapshot drift.

---

## 5. Known limitation & follow-up (batch-56)

The summer does **not** model the inter-component padding that `ALIGNMENT_BYTE/WORD/LONG/INT64/FLOAT16/FLOAT32/FLOAT64` directives induce. Today, any summable CURVE/MAP layout carrying such a directive is forced to `length = None` (safe grey, no false-green). The demo corpus is alignment-free, so its coverage is complete; alignment-bearing real-world A2Ls degrade safely to grey rather than deriving a wrong span.

**batch-56 = alignment-aware padding sizing** (operator-approved): extend `_record_layout_full_span` with a running-offset + alignment-rounding pass so alignment-bearing layouts derive a *correct* span instead of grey. batch-55 made them **safe**; batch-56 makes them **covered**.

---

## 6. Assumptions · risks · next steps

**Assumptions (verified by the §2.5 draft-time probe):**
- batch-54 populates `char_type`, `record_layout_name`, and `axis_meta[i].{max_axis_points (STR), external}` for these tags.
- `record_layouts_by_name[name]["lines"]` carries the full component body.
- FIX_AXIS axis points are not stored on-disk (layout omits `AXIS_PTS_*`).

**Risks (all mitigated — see `01-requirements.md §6.3`):** false-green (full-span-or-None + external gate + AT-106 anchor); ordering (post-walk placement, TC-136); DoS (1 MiB clamp, TC-138/AT-111); taxonomy/alignment incompleteness (full-span-or-None + batch-56); snapshot false-regression (expected-drift census — 0 drift materialized).

**Next steps:** (1) commit-hygiene `git add tests/test_a2l_inline_axis_length.py`; (2) post-merge PR-B re-freezes `a2l.py` into both `_ENGINE_PATHS`; (3) batch-56 alignment-aware sizing.
