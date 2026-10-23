# Code-Wire graph F4: A2L physical → raw encode (Patch Editor symbol picker) and raw → physical decode (data audit, reverse)

> Format B, Code-Wire v2.6. Reverse direction from `s19_app` `9793fcd`. Node name = code qualname.
> Thread T4: `cwaudit/test_t4_a2l_encode.py` (recorded: `trace-t4.json`, CW_MAX 300). Data: `examples/case_00_public/ASAP2_Demo_V161.a2l`, characteristic `ASAM.C.SCALAR.SWORD.RAT_FUNC_DIV_10` (address `0x810004`, SWORD, `MOD_COMMON BYTE_ORDER MSB_LAST`), COMPU_METHOD `CM.RAT_FUNC.DIV_10` = `COEFFS 0 10 0 0 0 1` with the file's own text "rational function with parameter set for impl = f(phys) = phys * 10". Control: `ASAM.C.SCALAR.SWORD.LINEAR_MUL_2` ("phys = f(int) = 2*int + 0"). The decode thread puts raw `300` (`2C 01`) at `0x810004`; that image byte pair is synthetic, the A2L is real.
> Known H-5 (MSB_FIRST) and H-6 (COMPU_TAB) are not repeated here.

## Nodes

resolve_symbol_entry
req: LLR-141.2, HLR-141
in: str symbol_text; str value_text; dict? a2l_data; str value_mode = 'text'
out: SymbolPickResult result {entry, issues}
func: the picker backend: symbol + physical value in, one bytes entry or a named refusal out
module: s19_app/tui/services/change_service.py
inner: encode_physical_to_raw_bytes
examples: (T4, t4a) symbol_text "ASAM.C.SCALAR.SWORD.RAT_FUNC_DIV_10"; value_text "30" → entry {address `8454148`, encoded_bytes [`3`, `0`]}, issues []
examples: (T4, t4a) value_text "25" → entry None; issue "the converted raw value 2.5 is not integral"

encode_physical_to_raw_bytes
req: LLR-141.1
in: dict tag; Any physical_value; dict? compu_methods_by_name = None; dict? compu_tabs_by_name = None; dict? record_layouts_by_name = None
out: tuple(tuple[int, ...]? raw_bytes, str? reason, list[str] flags)
func: physical to raw bytes: invert the COMPU_METHOD, check integral and range, pack in the tag byte order
module: s19_app/tui/a2l.py
inner: _invert_physical_to_raw
examples: (T4, t4a) tag "ASAM.C.SCALAR.SWORD.RAT_FUNC_DIV_10"; physical_value (30.0, a float: C16 cannot anchor it) → raw_bytes [`3`, `0`]
examples: (T4, t4a) tag "ASAM.C.SCALAR.SWORD.LINEAR_MUL_2"; physical_value (30.0) → raw_bytes [`15`, `0`] (correct: phys = 2·int)

_invert_physical_to_raw
req: LLR-141.1, REQUIREMENTS.md:217-228 (COMPU_METHOD Execution, no id)
in: float physical; dict? method; dict? compu_tabs_by_name
out: tuple(float? raw, str? reason)
func: one inversion per COMPU_METHOD kind. RAT_FUNC solves phys = f(raw) for raw
module: s19_app/tui/a2l.py
examples: (T4, t4a) physical (30.0); method {name "CM.RAT_FUNC.DIV_10", conversion_type "RAT_FUNC"} → raw (3.0) (the A2L text gives impl = phys · 10 = 300)

_apply_compu_method
req: REQUIREMENTS.md:217-228 (COMPU_METHOD Execution, no id)
in: Any raw_value; dict? method; dict[str, dict] compu_tables_by_name
out: tuple(Any physical, str status, str message)
func: raw to physical. RAT_FUNC computes phys = (a·x² + b·x + c) / (d·x² + e·x + f) with x = raw
module: s19_app/tui/a2l.py
examples: (T4, t4b) raw_value `300`; method {name "CM.RAT_FUNC.DIV_10", unit "km/h"} → physical (3000.0), status "ok" (the A2L text gives 30 km/h)
examples: (T4, t4b) raw_value `300`; method {name "CM.LINEAR.MUL_2", unit "m/s"} → physical (600.0), status "ok" (correct)

## Entities

[I/O: A2L file]
in: str
desc: the ASAP2 description (thread: ASAP2_Demo_V161.a2l)

[Data: ChangeService.document]
in: ChangeDocument
desc: the Patch Editor document that receives the picked entry

## Edges

[I/O: A2L file] ──▶ resolve_symbol_entry.a2l_data
resolve_symbol_entry ──▶ encode_physical_to_raw_bytes.physical_value
encode_physical_to_raw_bytes ──▶ _invert_physical_to_raw.physical
_invert_physical_to_raw.raw ──▶ encode_physical_to_raw_bytes
resolve_symbol_entry.result ──▶ [Data: ChangeService.document]
[I/O: A2L file] ──▶ _apply_compu_method.method

## Boundary

[Outside: symbol picker] ──▶ resolve_symbol_entry.symbol_text
[Outside: symbol picker] ──▶ resolve_symbol_entry.value_text
[Outside: tag view] ──▶ _apply_compu_method.raw_value
discarded: _apply_compu_method.physical — the tag view and the reports paint it; outside this slice

## Findings

CW-D-10
anchor: _invert_physical_to_raw
what: RAT_FUNC runs in the wrong direction, on both sides. ASAP2 RAT_FUNC gives the internal value from the physical value (INT = f(PHYS)); the example file says so in its own text. The code treats the coefficients as PHYS = f(INT)
evidence: T4 t4a: 30 km/h → bytes 03 00 (file says 300 = 2C 01); 25 km/h is refused as "2.5 is not integral" (valid: 250). T4 t4b: raw 300 → 3000 (file says 30). LINEAR control is correct both ways
consequence: the Patch Editor writes wrong bytes for every non-identity RAT_FUNC parameter, and the views and reports show wrong physical values. The requirement says only "apply rational polynomial from coefficients" (no direction); LLR-141.1 checks the encode against the decode, which shares the error. The ASAM text is not in the repo: confirm against ASAM MCD-2 MC before the fix
