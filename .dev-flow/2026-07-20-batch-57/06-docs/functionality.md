# batch-57 — Functionality (CRC Algorithm Designer, headless keel)

## What it does
Provides the reusable, verified foundation the CRC Algorithm Designer view (batch-58) will sit on:
a parametric CRC engine and a template/job model that let an operator tailor a CRC variant, prove it
correct, cover multiple memory ranges with fine-grained gap control, and refuse to emit a CRC that
would silently disagree with the device. All headless (no Textual), additive (the shipped 32-bit
`crc.py` operation and the engine-frozen set are untouched).

## The two modules

### `s19_app/tui/operations/crc_kernel.py` — the math
- **`crc_stream(data, *, width, poly, init, refin, refout, xorout)`** — width-general (8–64) bitwise
  parametric CRC (the Rocksoft model) with *independent* input/output reflection. The **oracle**.
- **`make_crc_table` / `crc_lut`** — the table-driven fast path (256-entry LUT cached per `(width,poly)`),
  byte-identical to `crc_stream` (it is the tabelization of the same bit loop). `CrcAlgorithm.compute`
  routes through it — MB-scale firmware no longer pays the bit-by-bit cost.
- **`CrcAlgorithm`** — a named variant (`width/poly/init/refin/refout/xorout/check`); `kat_ok()` is the
  tri-state (MATCH / MISMATCH / no-expected) against the `"123456789"` known-answer.
- **`PRESETS`** — 7 catalogue variants (CRC-8/SMBUS, CRC-16 CCITT-FALSE/MODBUS/XMODEM, CRC-32/ISO-HDLC =
  seed = zlib, CRC-32C, CRC-64/XZ), each self-verifying via its published `check`.

### `s19_app/tui/operations/crc_designer_model.py` — the model
- **`CrcTemplate`** (reusable algorithm, `*.crc.json`) / **`CrcJob`** (per-firmware: `algorithm_ref` or
  inline + `targets[]`) / **`CrcTarget`** (a target's coverage + serialization + policy).
- **`gather_target`** — multi-range coverage with two independent gap levels: `intra_gap` (skip|fill,
  holes inside a range) × `join` (concat|fill, space between ranges). Superset of the shipped `groups`.
- **`gap_conflict` + `evaluate_target`** — the safety gate: a `join="fill"` gap that actually holds
  real data would make the CRC diverge from the device's; `on_gap_conflict` decides — `abort` (default,
  refuses), `warn` (proceeds + diagnostic), `ignore` (silent).
- **`store_word`** — encode the result at `store_width` bytes, little/big-endian.
- **`parse_template`/`emit_template`/`read_template`/`parse_job`** — JSON round-trip, collect-don't-abort
  (reuses `resolve_input_path` + `READ_SIZE_CAP_BYTES` from the shipped `crc_config.py` posture).

## Verified oracles (asserted in the suite)
- Every preset reproduces its catalogue `check`; seed CRC-32 == `zlib.crc32`.
- `crc_lut ≡ crc_stream` over 45 vectors × 7 presets + odd widths (12/24) + `refin≠refout`.
- Two-range coverage: `join=concat` → `0x9C5BCBBD`; `join=fill(0xFF)` → `0x2A8A3950`.
- Gap-safety: clean → no conflict; stray `0x800A=0x99` in a filled gap → conflict; `abort` refuses.

## Boundaries (→ batch-58)
The Variant B TUI view, the legacy-`crc_config` up-converter (E6), a whole-job serializer (`emit_job`),
and wiring the width-general kernel into the shipped `crc.py` operation are deferred — this batch is the
tested keel they build on.
