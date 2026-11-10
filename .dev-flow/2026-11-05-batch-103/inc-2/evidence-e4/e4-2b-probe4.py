import sys
from pathlib import Path
sys.path.insert(0, ".")
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definition
print("s19_app.__file__ =", __import__("s19_app").__file__)
V = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
for n in ["ASAM.C.SCALAR.SBYTE.IDENTICAL", "ASAM.C.SCALAR.UBYTE.IDENTICAL",
          "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE",
          "ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE",
          "ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE",
          "ASAM.C.SCALAR.SWORD.VTAB_RANGE_NO_DEFAULT_VALUE",
          "ASAM.M.SCALAR.UBYTE.IDENTICAL",
          "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0"]:
    d = describe_definition(n, V)
    print(f"{n}: limits=({d.limits.lower},{d.limits.upper}) ext=({d.extended_limits.lower if d.extended_limits else None},{d.extended_limits.upper if d.extended_limits else None}) datatype={d.datatype} addr=0x{d.address:X}")
