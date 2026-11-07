"""Diagnosis of the 4 Inc 2a integration failures (read-only probes)."""
import sys
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
import test_b103_a2l_definition as T
from s19_app.tui import a2l_definition as M
import re

print("== 1: side table sections and first COMPU_VTAB_RANGE in the section tree")
soft = T._load("software_a.a2l")
print("side-table section values:", sorted({t["section"] for t in soft["compu_tabs_by_name"].values()}))
first = []
def walk(ns):
    for n in ns:
        if n.get("name") == "COMPU_VTAB_RANGE": first.append(n)
        walk(n.get("children") or [])
walk(soft["sections"])
print("COMPU_VTAB_RANGE sections in tree:", len(first))
name = M.parse_begin_meta(first[0]["meta"])[0]
print("first range table:", name)
r = M._read_enum_table(name, {name: first[0]})
print("entries:", len(r[1]), r[1][0])
defs = M.describe_definitions([t["name"] for t in soft["tags"]], soft)
users = [d for d in defs.values() if d.enum_table == name]
print("objects using it:", len(users))
if users: print(users[0].kind, len(users[0].enum_entries), users[0].enum_entries[0])

print("== 2: EXTENDED_LIMITS 0 + FORMAT")
print("body tokens consumed:", M._flatten_body_tokens(["XL1 \"\" UWORD NM 0 0 0 65535", 'EXTENDED_LIMITS 0', 'FORMAT "%5.0"']))
import tempfile
tp = Path(tempfile.mkdtemp(prefix="diag2a_"))
a2l = T._inline(tp, T._val("XL1", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "EXTENDED_LIMITS 0", 'FORMAT "%5.0"'))
d = M.describe_definition("XL1", a2l)
print("display_format:", d.display_format, "ext:", d.extended_limits)
a2l = T._inline(tp, T._val("XL1", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", 'FORMAT "%5.0"', "EXTENDED_LIMITS 0"))
print("FORMAT first:", M.describe_definition("XL1", a2l).display_format)

print("== 3/4: decimals 17 on 0.1")
print("float round trip   :", f"{float(f'{0.1:.15g}'):.17f}")
from decimal import Decimal
print("Decimal of 15g text:", format(Decimal(f"{0.1:.15g}"), ".17f"))
print("4.1 d=15 float     :", f"{float(f'{4.1:.15g}'):.15f}", " Decimal:", format(Decimal(f"{4.1:.15g}"), ".15f"))
print("1e20 d=17 Decimal  :", format(Decimal(f"{1e20:.15g}"), ".17f"))
