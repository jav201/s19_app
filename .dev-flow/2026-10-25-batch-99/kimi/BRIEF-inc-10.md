# Kimi brief — batch-99 Increment 10 · US-147 + US-152 / HLR-158 · A2L values encode and decode as the A2L declares

Read `BRIEF-COMMON.md` first.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-158 (D2 `asam`, D3 `modulo`, D4 `rechazar`; final), LLR-158.1..158.3; TC-B99-23..25; AT-B99-09 (US-147, decode in the A2L window), AT-B99-14 (US-152, the codec API's return value). Map row B99-I4. PDR conditions:
- **PQ-5:** assert the CONTENT of flags and reasons (the named values / range), never mere presence. HEAD already returns non-fatal "outside limits" flags, so `flags != []` is vacuous.
- **UX-C8:** `n/a` placement. The Physical cell reads `n/a`, and the characteristic description modal (`render_curve_description`) reads `Scalar value: n/a (<reason>)`, with a short, enum-derived reason. Keep `n/a` distinct from blank (no bytes). It must not be clipped at width 118 or 80. No new column or pane.
- **UX-C10:** no unsanitised A2L text in the reason.

## SOURCE files (max 2)
`s19_app/tui/a2l.py` (frozen engine — the crossing is named in LLR-158.1), `s19_app/tui/app.py` (the Physical cell `n/a`, near `app.py:12522-12543`; the modal text if it lives there — find `render_curve_description`). If the modal lives in a third file, it is allowed: 3 files maximum.

## What to build
1. **Effective byte order:** tag → RECORD_LAYOUT → tag endian → `MOD_COMMON BYTE_ORDER` → little. Encode and decode both use it. ASAM tokens: `MSB_FIRST` / `BIG_ENDIAN` = big; `MSB_LAST` / `LITTLE_ENDIAN` = little.
2. **RAT_FUNC:** encode computes INT = f(PHYS) = (a·P² + b·P + c) / (d·P² + e·P + f) with COEFFS a b c d e f. Decode solves for P. Take the root inside the tag's limits when exactly one is inside, else the smaller-magnitude root; no real root → a decode failure reason, shown as `n/a`. The corpus A2L (Inc 1) holds `RAT_FUNC_SYM` with raw 300 ↔ physical 30.
3. **COMPU_TAB:**
   - `TAB_NOINTP`: refuse any value that is not exactly a table value, naming the two nearest.
   - `TAB_INTP`: refuse a value outside the table's physical range, naming the range. Inside it, return the nearest raw value plus a flag naming the written physical value whenever it differs from the typed one.

   The corpus manifest `a2l_expect` (Inc 1, `tests/fixtures/synth/manifest.json`) records the exact expected values. Use them.

## Tests — `tests/test_b99_a2l_encode.py`
- **TC-B99-23:** byte order. MSB_FIRST 2-byte: 4113 ↔ `10 11`; the `MSB_LAST` control keeps `0F 00`.
- **TC-B99-24:** RAT_FUNC. 30 → 300, 25 → 250, raw 300 → 30.0; a quadratic coefficient set → the root inside the limits; a no-real-root raw value → failure; LINEAR unchanged.
- **TC-B99-25:** COMPU_TAB exact content (PQ-5). `TAB_NOINTP` 13.0 → error naming 10.0 and 15.0; `TAB_INTP` 500 / −50 → error naming the range; off-grid 3.4 → raw 1 and a flag naming 2.5; grid 5.0 → raw 2, no flag.
- **AT-B99-09** (pilot): load the corpus A2L + S19; the A2L window's Physical column shows 30 for `RAT_FUNC_SYM` and 4113 for `SYM_U16_MSB`; an undecodable value shows `n/a` (UX-C8). RED today (P-7, P-17).
- **AT-B99-14** (codec API, US-152's surface): `encode_physical_to_raw_bytes` on the corpus tags returns raw 300 for 30, `10 11` for 4113, and an error naming the range for 500 on the `TAB_INTP` symbol. Assert only the returned `(raw_bytes, error, flags)`. RED today (P-17, P-8).
- Mutations: the `little` fallback skipping MOD_COMMON (TC-23 RED); the old RAT_FUNC direction (TC-24 RED); nearest / clamp with no flag (TC-25 RED). Revert each one.

## Reverse census
`grep -rln "effective_byte_order\|_apply_compu_method\|_invert_rat_func\|encode_physical_to_raw_bytes\|COMPU_TAB\|RAT_FUNC\|physical_value" tests/`. Existing tests whose RAT_FUNC values used the old direction must be re-pinned with old → new → LLR-158.2. The repo's example A2L states the direction in its own text: "impl = f(phys) = phys * 10".

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-010.md`, REQ-ID `HLR-158`.
