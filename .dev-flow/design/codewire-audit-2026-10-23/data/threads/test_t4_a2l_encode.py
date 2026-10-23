"""T4 threads: A2L physical -> raw encode (Patch Editor symbol picker) and raw -> physical decode."""
from cwh import C3, PUB, out

DEMO = PUB / "ASAP2_Demo_V161.a2l"
RAT = "ASAM.C.SCALAR.SWORD.RAT_FUNC_DIV_10"
LIN = "ASAM.C.SCALAR.SWORD.LINEAR_MUL_2"


def _tag(a2l, name):
    return next(t for t in a2l["tags"] if t.get("name") == name)


def test_t4a_rat_func_encode_demo():
    """T4a: picker encode of physical 30.0 km/h into RAT_FUNC_DIV_10 ("int = f(phys) = phys * 10")."""
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.tui.services.change_service import resolve_symbol_entry
    a2l = parse_a2l_file(DEMO)
    t = _tag(a2l, RAT)
    for phys in ("30", "25"):
        res = resolve_symbol_entry(RAT, phys, a2l)
        e = res.entry
        out("T4a", symbol=RAT, physical=phys, method=t.get("compu_method_name"), order=t.get("effective_byte_order"),
            entry_bytes=(None if e is None else " ".join(f"{b:02X}" for b in e.encoded_bytes)),
            address=(None if e is None else hex(e.address)), issues=[i.message for i in res.issues])
    res = resolve_symbol_entry(LIN, "30", a2l)
    out("T4a-lin", symbol=LIN, physical="30", entry_bytes=" ".join(f"{b:02X}" for b in res.entry.encoded_bytes))


def test_t4b_rat_func_decode_demo():
    """T4b: decode raw 300 (0x012C, MSB_LAST) at 0x810004 through the tag enrichment."""
    from s19_app.tui.a2l import parse_a2l_file, enrich_a2l_tags_with_values
    a2l = parse_a2l_file(DEMO)
    mem = {0x810004: 0x2C, 0x810005: 0x01}
    rows = enrich_a2l_tags_with_values(a2l, mem)
    for name in (RAT, LIN):
        r = next(x for x in rows if x.get("name") == name)
        out("T4b", symbol=name, raw=r.get("raw_value"), physical=r.get("physical_value"),
            status=r.get("conversion_status") or r.get("physical_status"), unit=r.get("unit"))


def test_t4c_case03_msb_first_encode():
    """T4c (known H-5, one line): case_03 OVER_A, MOD_COMMON BYTE_ORDER MSB_FIRST."""
    from s19_app.tui.a2l import parse_a2l_file
    a2l = parse_a2l_file(C3 / "firmware.a2l")
    names = [t.get("name") for t in a2l["tags"]]
    t = a2l["tags"][0]
    out("T4c", tags=names[:4], first=t.get("name"), datatype=t.get("datatype"), length=t.get("length"),
        order=t.get("effective_byte_order"))
