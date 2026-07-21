# CRC Algorithm Designer — Requirements (v1 draft)

**Status:** Draft for approval · **Date:** 2026-07-20 · **Worktree:** `crc-algorithm-designer`
**Author:** requirements pass (pre-/dev-flow). Governs a NEW TUI view + a width-general engine rewrite.

---

## 1. BLUF

Add a **CRC Algorithm Designer** view that lets an operator *tailor* a CRC variant from basic
building blocks (width, polynomial, seed, reflection, final XOR) plus firmware-domain coverage
(**multiple memory ranges** with independent **intra-range** and **inter-range** gap policies,
storage endianness), **prove it correct against a known-answer test vector**, and **save/load it
as JSON**. Two artifacts: a reusable, **placement-free algorithm template** (the pure math), and a
per-firmware **job** (algorithm-ref + multi-range coverage + placement) that the CRC operation and
Flow-Builder CRC block consume. The **chosen view (Variant B)** authors a job and previews its CRC
over the loaded image — but never writes firmware. The **first template shipped is today's `zlib`
CRC-32** expressed in the new format — a fidelity test that the designer reproduces the current
engine byte-for-byte.

Two deliverables follow approval of this doc: a runnable **/prototype** (centerpiece = live
known-answer verification) and a **/tui-design** HTML mockup.

---

## 2. The separation (architecture decision)

Today `crc_config.json` couples *the algorithm* (`polynomial/init/reverse/final_xor`) with *the
placement* (`regions`, `groups`, `output_address`). The Designer splits these into three layers:

| Layer | Owns | Artifact | Consumed by |
|---|---|---|---|
| **Algorithm template** (NEW) | The pure math only (width/poly/init/refin/refout/xorout). Placement-free, reusable, KAT-verifiable. | `*.crc.json` template | jobs, CRC operation, Flow-Builder CRC block |
| **Job** (evolved) | An `algorithm_ref` (or inline algorithm) + one or more **targets**: multi-range `coverage` (intra/join gap policy) + `serialization` (output address, store width/endianness). Per-firmware. | `crc_config.json` (evolved, back-compat) | CRC operation |
| **Run** (exists) | Compute over a loaded image; check / inject / verify. | — | TUI report |

The Designer (Variant B) authors a **job** and previews it over the loaded image; the pure
`algorithm` block within it is savable to the reusable template lib.

The Designer authors and verifies **only the template layer**. Placement stays where it is
(`operations/crc.py` check/inject + the Flow-Builder CRC block). This keeps the pure algorithm
independently known-answer-testable and lets one template serve many placements.

---

## 3. The building blocks (parametric model)

The canonical parametric CRC ("Rocksoft") model, plus the firmware-domain extras you named.
Split into `algorithm` (pure math, exercised by the known-answer test) and `serialization`
(how the result and the input window are materialized).

### 3.1 `algorithm` — pure math (KAT-verifiable)

| Field | Type | Meaning | Your term |
|---|---|---|---|
| `width` | int (1–64) | CRC register size in bits → the result word size (8/16/32/64 typical). | **"byte-window length"** — the length of the CRC result |
| `poly` | hex | Generator polynomial, normal (un-reflected) form, `width` bits. | polynomial |
| `init` | hex | Initial register value (seed). | **start value** |
| `refin` | bool | Reflect each input byte (bit-reverse) before feeding it. | endianness (bit) |
| `refout` | bool | Reflect the final register before the final XOR. | endianness (bit) |
| `xorout` | hex | Value XORed into the final register. | **finish value** |
| `check` | hex (optional) | Expected CRC of the 9 ASCII bytes `"123456789"`. Self-verification anchor. | — |

- **On "the operation (XOR)":** a CRC's accumulation *is* XOR (polynomial division mod-2) — not a
  user knob. The two XOR knobs you actually set are `init` (seed) and `xorout` (final). The block
  model reserves an `operation: "crc"` discriminator so a future additive/summing **checksum**
  operation can slot in beside CRC without breaking templates (§9 extension point).
- **On reflection vs endianness:** `refin`/`refout` are *bit* endianness (reflection). *Byte/word*
  endianness — how a multi-byte result is written to memory — is a serialization knob (§3.2),
  disambiguated deliberately because they are independent.

### 3.2 `coverage` — the multi-range window & its two gap levels

A CRC **target** covers one or more memory ranges. The flexibility knob you asked for is **two
independent gap policies** — the space *inside* a range and the space *between* ranges are
controlled separately, per target.

| Field | Type | Meaning | Your term |
|---|---|---|---|
| `ranges` | list of `{start,end}` | One or more half-open ranges, digested **in declared order** (never address-sorted — parity with today's `groups`). | **memory range(s)** |
| `intra_gap` | `"skip"` \| `"fill"` | Holes **inside** a range: `skip` = present bytes only (today's behavior); `fill` = absent addresses take `pad_byte`. | **fill of gaps** (within) |
| `join` | `"concat"` \| `"fill"` | Space **between** consecutive ranges: `concat` = butt the present ranges together (today's `groups`); `fill` = pad `[prev_end, next_start)` with `pad_byte` so the CRC sees one contiguous window across the ranges. | **fill of gaps** (between) |
| `pad_byte` | hex (0–255) | Fill value for either policy (e.g. `0xFF` erased flash, `0x00`). | fill value |
| `on_gap_conflict` | `"abort"` \| `"warn"` \| `"ignore"` | **Safety gate.** How the run path reacts when the real image contradicts a gap the target promised was empty. Default `abort`. | (new — obs #2) |

**Gap safety (obs #2).** `join="fill"` pads `[prev_end, next_start)` with `pad_byte` *without consulting the image* — so if real data actually sits in that "erased" span, the previewed CRC silently diverges from what the device computes. Before filling, the engine runs `gap_conflict(mem_map, target)`: any present byte in the filled span that isn't `pad_byte` is a conflict. `on_gap_conflict` then decides — `abort` (default, mandatory on the write path), `warn` (proceed + diagnostic), or `ignore`. Verified in `crc_designer_model.gap_conflict` (clean → `[]`; a stray `0x800A=0x99` → `[0x800A]`; `join="concat"` never conflicts).

Every combination is reachable — e.g. *skip holes inside each range but pad the gap between them*
(`intra_gap="skip"`, `join="fill"`). This is a **strict superset of today's `groups`**, which are
hardwired to `intra_gap="skip"`, `join="concat"`.

**Verified numbers** (prototype, two ranges `0x8000-0x8008` + `0x8010-0x8018`, 8-byte gap):
`concat` → 16 B → `0x9C5BCBBD`; `join=fill(0xFF)` → 24 B → `0x2A8A3950`.

### 3.3 `serialization` — how the result word is stored

| Field | Type | Meaning | Your term |
|---|---|---|---|
| `output_address` | hex | Where the CRC is read (check) / written (inject) — per target. | — |
| `store_width` | int bytes | Bytes the stored CRC occupies (`ceil(width/8)`; may be padded larger, e.g. a 16-bit CRC in a 4-byte field). | — |
| `store_endianness` | `"little"` \| `"big"` | Byte order of the stored result word. Today = little only (RK-4). | **endianness (byte)** |

- **`store_width ≥ ceil(width/8)`.** Wider zero-extends; narrower is rejected (silent truncation of
  detection strength).
- **Coverage + serialization are per-firmware** (they name real addresses), so they live on the
  **job**, not the reusable algorithm template (§2). The pure `algorithm` block stays reusable and
  KAT-verifiable on its own.

---

## 4. JSON schemas (v1)

Two artifacts. **(a)** the reusable, placement-free **algorithm template** (the template library);
**(b)** the per-firmware **job** that references an algorithm and adds coverage + placement.

**(a) Algorithm template** — `*.crc.json` in the template lib:

```json
{
  "schema_version": 1,
  "name": "CRC-32/ISO-HDLC",
  "aliases": ["zlib", "PKZIP", "CRC-32"],
  "operation": "crc",
  "algorithm": {
    "width": 32, "poly": "0x04C11DB7", "init": "0xFFFFFFFF",
    "refin": true, "refout": true, "xorout": "0xFFFFFFFF", "check": "0xCBF43926"
  }
}
```

**(b) Job** — the evolved `crc_config.json`, one CRC per target:

```json
{
  "schema_version": 1,
  "algorithm_ref": "CRC-32/ISO-HDLC",
  "targets": [
    {
      "ranges": [
        { "start": "0x8000", "end": "0x8008" },
        { "start": "0x8010", "end": "0x8018" }
      ],
      "intra_gap": "skip",
      "join": "fill",
      "pad_byte": "0xFF",
      "output_address": "0x8018",
      "store_width": 4,
      "store_endianness": "little"
    }
  ]
}
```

- **`name` is required, unique in the template lib, and normalized** through the existing
  `sanitize_project_name` idiom (it becomes a filename).
- **The template (a) is the seed — it reproduces the current `zlib.crc32` default byte-for-byte**
  (`init/refin/refout/xorout` all match `crc.py`'s `DEFAULT_*`) → AT-CRC-DSN-010.
- **`algorithm_ref` may instead be an inline `algorithm` object** (a self-contained job), so a job
  is runnable without the lib present. Back-compat: today's flat `crc_config` (poly/init/reverse/
  final_xor + regions/groups) is accepted and up-converted, so existing configs keep working.

---

## 5. Seed preset library

Ship a small, self-verifying set (each `check` = CRC of `"123456789"`, so a bad engine fails
loudly at load). These are well-known catalogue values; the engine validates against them in a KAT
table test (§8).

| `name` | width | poly | init | refin | refout | xorout | check |
|---|---|---|---|---|---|---|---|
| CRC-8/SMBUS | 8 | `0x07` | `0x00` | false | false | `0x00` | `0xF4` |
| CRC-16/CCITT-FALSE | 16 | `0x1021` | `0xFFFF` | false | false | `0x0000` | `0x29B1` |
| CRC-16/MODBUS | 16 | `0x8005` | `0xFFFF` | true | true | `0x0000` | `0x4B37` |
| CRC-16/XMODEM | 16 | `0x1021` | `0x0000` | false | false | `0x0000` | `0x31C3` |
| CRC-32/ISO-HDLC (seed) | 32 | `0x04C11DB7` | `0xFFFFFFFF` | true | true | `0xFFFFFFFF` | `0xCBF43926` |
| CRC-32C/Castagnoli | 32 | `0x1EDC6F41` | `0xFFFFFFFF` | true | true | `0xFFFFFFFF` | `0xE3069283` |
| CRC-64/XZ | 64 | `0x42F0E1EBA9EA3693` | `0xFFFF…FFFF` | true | true | `0xFFFF…FFFF` | `0x995DC9BBDF1939FA` |

Presets are read-only starting points: selecting one populates the form; the operator edits and
saves under a new `name`. (`RK` — values are transcribed from the public CRC catalogue; the KAT
table test is the guard, not a claim of hand-verification.)

---

## 6. Engine changes (`operations/crc.py`, non-frozen)

The current `crc32_stream` is hardwired to 32 bits (`_MASK32`, `byte << 24`, `_reflect(reg, 32)`)
and one `reverse` bool. v1 replaces it with a **width-general reference** while preserving every
existing call.

| # | Change | Compatibility guard |
|---|---|---|
| E1 | New `crc_stream(data, *, width, poly, init, refin, refout, xorout)` — table-less bitwise, any width 8–64, independent `refin`/`refout`. | New symbol; old `crc32_stream` kept as a thin wrapper (`width=32`, `refin=refout=reverse`) so all current callers + tests are byte-identical. |
| E1-note | **Shift family (obs #1).** The parametric params fully determine the result; shift direction is an *implementation* choice, **not** a template field. The shipped kernel uses *reflect-data + MSB-first left-shift* (verified against the catalogue). Production may switch reflected variants to the idiomatic *LSB-first right-shift* form. Document in the engine docstring/LLR only. | Result-identical — guarded by the KAT table (E2). |
| E2 | KAT table test over the §5 presets + `zlib.crc32` oracle for the CRC-32 row. | New `tests/test_crc_engine_parametric.py`. |
| E3 | Multi-range coverage in segment assembly: `intra_gap="fill"` materializes each `[start,end)` with `pad_byte`; `join="fill"` pads `[prev_end,next_start)` between ranges. `intra_gap="skip"` + `join="concat"` stay the defaults and are byte-identical to today's region/group path. | Defaults unchanged → existing region/group tests untouched; superset of `compute_group_crc`. |
| E6 | Job/`targets` model + up-converter: parse the evolved `crc_config` (`algorithm_ref`/inline + `targets[]`) AND accept today's flat `crc_config` (poly/init/reverse/final_xor + regions/groups), normalizing both into the same internal target list. | Existing `crc_config.json` fixtures parse unchanged (back-compat test). |
| E7 | **LUT fast path (obs #4).** Generate a 256-entry table per algorithm at init (from `poly` + reflection) and run the fast inner loop over image bytes; keep the bit-by-bit form as the KAT oracle. Not a template field — same result, engine-internal (the shipped `crc.py` already delegates the default case to `zlib.crc32`, a C table impl). | Result-identical to the bitwise reference (differential test LUT vs bitwise). |
| E8 | **Gap-safety (obs #2).** `on_gap_conflict` on `CrcTarget` + `gap_conflict(mem_map, target)` detector; the run/preview path enforces the policy (`abort` default on write). **DONE (headless):** `crc_designer_model` + tests. | Additive; existing coverage tests unchanged. |
| E4 | `store_endianness="big"` + `store_width` in `encode_le`/`decode_le` (rename to `encode_word`/`decode_word` with `endianness` param; keep `encode_le`/`decode_le` wrappers). | LE wrappers preserve current inject/check bytes. |
| E5 | Template loader `crc_template.py` (mirrors `crc_config.py` read posture): `resolve_input_path` → 256 MB size cap → `json.loads` → typed `CrcTemplate` → **collect-don't-abort** (returns `(None, [one error])`, never raises). | Reuses `READ_SIZE_CAP_BYTES`; no new untrusted-loader posture invented. |

**Independent `refin ≠ refout`** has no catalogue KAT vector (every standard preset has them equal),
so it is *supported but KAT-unverified* — flagged like the existing RK-3, exercised only by a
round-trip-consistency test, not an external oracle.

---

## 7. The Designer view (new TUI screen)

A new rail screen `CRC Designer` (own `#screen_crc_designer`, modeled on the Flow-Builder rail-8
pattern; data-driven `.hidden` routing, no new `action_show_screen` handler).

| ID | Requirement (EARS) |
|---|---|
| R-CRC-DSN-001 | The view SHALL present the §3 building blocks as an editable form: a **preset selector**, the `algorithm` fields, and the `serialization` fields. |
| R-CRC-DSN-002 | When any field changes, the view SHALL recompute the CRC of `"123456789"` and display **computed vs expected `check`** with an explicit match / mismatch / no-expected state — the live known-answer verification (prototype centerpiece). |
| R-CRC-DSN-003 | The view SHALL let the operator enter a **custom test vector** (hex or ASCII) and show its computed CRC, so a variant can be checked against a device-supplied reference. |
| R-CRC-DSN-004 | The view SHALL render a **live JSON preview** of the current template that round-trips (the previewed text parses back to the same template). |
| R-CRC-DSN-005 | The view SHALL **Load** a template from JSON (through the collect-don't-abort loader E5) and **Save** the current template to the library, normalizing `name`; a load/parse fault is one surfaced error, never a crash. |
| R-CRC-DSN-006 | Selecting a preset SHALL populate the form without overwriting the saved library entry (edits save under a new `name`). |
| R-CRC-DSN-007 | The view SHALL warn (not block) on: `intra_gap/join="fill"` with no `pad_byte`, `store_width < ceil(width/8)`, and a `check` mismatch. On **save**, a template's `check` SHALL be validated to equal `compute("123456789")` — the standard KAT (obs #3), never the job's memory result. Warnings render `markup=False` (untrusted-text posture). |
| R-CRC-DSN-011 | **(obs #2)** For a target with `join="fill"`, the view SHALL run `gap_conflict` against the loaded image and surface any conflict; the run/preview path SHALL honor `on_gap_conflict` (`abort` refuses the run, `warn` proceeds with a diagnostic, `ignore` is silent). |
| R-CRC-DSN-008 | **(Variant B, chosen)** The view SHALL let the operator define a target's **coverage**: an ordered list of one or more `ranges`, the `intra_gap` toggle (skip/fill), the `join` toggle (concat/fill), and `pad_byte` (§3.2). |
| R-CRC-DSN-009 | **(Variant B)** When an image is loaded, the view SHALL **preview** the target's CRC over the real bytes for the active gap policy, and show the alternative policy's value alongside, so the effect of each toggle is visible before anything is written. |
| R-CRC-DSN-010 | The Designer SHALL **preview only** — it never writes CRC bytes into firmware. Inject/write stays in the (work-area-contained) CRC operation / Flow-Builder CRC block, which consume the saved job. |

**Chosen boundary: Variant B** (authoring bench + multi-range coverage preview). The reusable
**algorithm template** is still savable on its own; the **job** (algorithm-ref + coverage +
placement) is what Variant B previews. **Layout intent** (see tui-design deliverable): left =
parameter form + the coverage strip (range list + gap toggles + live per-policy CRC); right = the
live KAT verdict panel + custom-vector box; bottom = JSON preview + Load/Save. Honors the
`width-narrow` / `density-compact` reflow classes; no column measuring.

---

## 8. Acceptance tests & known-answer vectors

| AT | Statement | Method |
|---|---|---|
| AT-CRC-DSN-010 | The seed CRC-32/ISO-HDLC template, run through the new engine, equals `zlib.crc32` and today's `crc32_stream` output over the same bytes. | Automated (oracle) |
| AT-CRC-DSN-011 | Every §5 preset's engine output over `"123456789"` equals its `check`. | Automated (KAT table) |
| AT-CRC-DSN-012 | A template saved then loaded yields an identical typed template (round-trip). | Automated |
| AT-CRC-DSN-013 | A single-range target with `intra_gap="skip"` equals today's region CRC; `intra_gap="fill"` equals the CRC of the pad-filled contiguous bytes. | Automated |
| AT-CRC-DSN-013b | A two-range target: `join="concat"` equals today's `group` CRC (butt present bytes); `join="fill"` equals the CRC with `[prev_end,next_start)` padded by `pad_byte`. Verified oracle: `concat=0x9C5BCBBD`, `fill=0x2A8A3950` for the §3.2 vector. | Automated |
| AT-CRC-DSN-014 | `store_endianness="big"` writes the result word MSB-first; `"little"` is byte-identical to today's `encode_le`. | Automated |
| AT-CRC-DSN-015 | A malformed template file (bad JSON, over-cap, missing field) surfaces exactly one error and no crash. | Automated |
| AT-CRC-DSN-016 | Editing a field in the view updates the live check verdict within the same interaction (no Run needed). | Pilot AT (TUI) |
| AT-CRC-DSN-017 | For a `join="fill"` target, a clean gap yields no `gap_conflict`; a stray non-`pad_byte` present byte in the filled span is returned, and `on_gap_conflict="abort"` refuses the run. `join="concat"` never conflicts. | Automated (`gap_conflict`) |

**KAT anchor:** `check(CRC-32/ISO-HDLC) == 0xCBF43926` over `b"123456789"` (already asserted in
`test_crc_engine.py`); the parametric table extends it to all §5 rows.

---

## 9. Extension points (designed-for, not built in v1)

- **`operation` discriminator** (`"crc"` today) → a future `"checksum"` (additive/sum) operation
  reusing the same template envelope, gap policy, and serialization. This is the "basic blocks /
  flexibility" you asked for, kept open without speculative code.
- **Input block alignment / padding to a boundary** (the other reading of "byte window") — an
  optional `serialization.align` knob; **deferred** unless a real device needs it.
- **Reflected-form poly entry** (accept `0xEDB88320` and normalize) — convenience, deferred.

---

## 10. Security & risks

- **Template file = new untrusted surface.** The loader (E5) **reuses** the `crc_config.py` /
  `read_change_document` posture verbatim: `resolve_input_path`, 256 MB pre-read cap (injectable
  probe), `json` fault → one collected error, top-level-object guard, never raises. No new posture
  invented. Any template-derived text shown in the TUI renders `markup=False`.
- **RK-3 (carried):** a non-catalogue / `refin≠refout` variant has no external KAT vector — the
  engine is proven to reproduce the seeded catalogue + zlib, not an arbitrary device convention;
  an operator reference vector is still required to trust a bespoke variant.
- **RK-4 (closing):** byte-storage endianness/width, previously out of scope, is now a designed
  knob (E4) — the risk narrows to "big-endian store path needs a device fixture."
- **RK-6 — performance (obs #4):** the bit-by-bit kernel is fine for the KAT window and the designer
  preview, but too slow for MB-scale firmware. Closed by the E7 LUT fast path (256-entry table at
  init); the bitwise form stays as the oracle. Result-identical, so no correctness risk.
- **RK-7 — silent gap divergence (obs #2):** `join="fill"` over a wrongly-assumed-erased span would
  emit a CRC the device never agrees with. Closed by `on_gap_conflict`/`gap_conflict` (E8, default
  `abort` on write) — **DONE** headless.
- **Scope guard:** the Designer authors + verifies; it does **not** run over firmware or write
  files. That stays in the (already work-area-contained) CRC operation.

---

## 11. Open items / next steps

1. **Approve this doc** (or redline §2 separation / §5 preset set / §7 view scope).
2. **/prototype** — runnable, centerpiece = live known-answer verification (R-CRC-DSN-002).
3. **/tui-design** — HTML mockup of the §7 layout.
4. Implementation lands via **/dev-flow** (width-general engine + loader + view), engine first
   (E1–E5, headless, KAT-tested) then the view — mirroring the Flow-Builder tracer's "keel first"
   increment order.
