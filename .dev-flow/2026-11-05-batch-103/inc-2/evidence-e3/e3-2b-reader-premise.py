from __future__ import annotations

import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import s19_app
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definition

ROOT = Path(__file__).resolve().parent
failures: list[str] = []


def check(ok: bool, label: str, detail: object = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'} {label} {detail}")
    if not ok:
        failures.append(label)


check(False, "SELFTEST expected failure")
failures.pop()
print("PASS SELFTEST red-proof")

HDR = (
    "ASAP2_VERSION 1 71\n"
    "/begin PROJECT P \"\"\n"
    "/begin MODULE M \"\"\n"
    "/begin MOD_COMMON \"\"\n"
    "BYTE_ORDER MSB_FIRST\n"
    "/end MOD_COMMON\n"
    "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n"
    "/end COMPU_METHOD\n"
    "/begin RECORD_LAYOUT RL_U8\nFNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin RECORD_LAYOUT RL_U32\nFNC_VALUES 1 ULONG ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
)
TAIL = "/end MODULE\n/end PROJECT\n"
counter = 0
scratch = tempfile.TemporaryDirectory(prefix="b103-e3-2b-probe-")
tmp = Path(scratch.name)


def parse(text: str) -> dict:
    global counter
    counter += 1
    path = tmp / f"shape-{counter}.a2l"
    path.write_text(HDR + text + "\n" + TAIL, encoding="utf-8")
    return parse_a2l_file(path)


def meas(name: str, *body: str, hdr: str = "UWORD CM_ID 0 0 0 65535") -> str:
    return f'/begin MEASUREMENT {name} ""\n{hdr}\n' + "\n".join(body) + "\n/end MEASUREMENT"


def char(name: str, kind: str, addr: str, layout: str, *body: str) -> str:
    return (
        f'/begin CHARACTERISTIC {name} ""\n{kind} {addr} {layout} 0 CM_ID 0 65535\n'
        + "\n".join(body)
        + "\n/end CHARACTERISTIC"
    )


def tag(data: dict, name: str) -> dict:
    return next(t for t in data["tags"] if t["name"] == name)


print("PACKAGE", s19_app.__file__)
print("PLATFORM", platform.platform(), platform.python_version())

v171 = parse_a2l_file(ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
spans = {s["name"]: s for s in v171["declared_spans"]}
for name, address, length in (
    ("ASAM_I_SCALAR_VALUE_UWORD_SINGLE", 0x810000, 2),
    ("ASAM_I_SCALAR_VALUE_UWORD_ARRAY_5", 0x810002, 10),
):
    span = spans.get(name, {})
    check(
        (span.get("address"), span.get("length")) == (address, length),
        f"V171 span {name}",
        (span.get("address"), span.get("length")),
    )
check(spans.get("ASAM_S_EXAMPLE", {}).get("address") == 0x811000, "V171 structure address")

pairs = (
    (
        "C1 one-line IF_DATA",
        char("N", "VALUE", "0x10", "RL_U16", "/begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", "BYTE_ORDER MSB_LAST", "BIT_MASK 0x0F00"),
        "little",
    ),
    (
        "C2 commented BYTE_ORDER",
        char("N", "VALUE", "0x10", "RL_U16", "BYTE_ORDER MSB_LAST", "/*", "BYTE_ORDER MSB_FIRST", "*/", "BIT_MASK 0x0F00"),
        "little",
    ),
    (
        "C3 commented module BYTE_ORDER",
        char("N", "VALUE", "0x10", "RL_U16", "BIT_MASK 0x0F00"),
        "big",
    ),
)
for label, block, expected in pairs:
    data = parse(block)
    n = tag(data, "N")
    check(n["effective_byte_order"] == expected and n["address"] == 0x10, label, (n["effective_byte_order"], n["address"]))

for label, directive, expected in (
    ("include", '/include "x.a2l"', "/include x.a2l is not read"),
    ("stray comment close", "*/", "*/ without /*"),
    ("unclosed comment", "/* never closed", "comment not closed"),
    ("unclosed quote", char("Q", "ASCII", "0x10", "RL_U8", 'FORMAT "%5.0'), "quoted string not closed"),
):
    data = parse(directive)
    check(any(expected in e for e in data["errors"]), f"parse error {label}", data["errors"][:3])

cap = parse("\n".join(["/end X"] * 101))
check(
    len(cap["errors"]) == 101
    and cap["errors"][-1].startswith("… ")
    and cap["errors"][-1].endswith(" more parse errors"),
    "parse error cap",
    cap["errors"][-1:],
)

hostile = (
    ("H1 NUMBER", char("H1", "ASCII", "0x10", "RL_U8", "NUMBER 1000000000000"), "H1"),
    ("H2 MATRIX_DIM", meas("H2", "MATRIX_DIM 4294967296", "ECU_ADDRESS 0x10"), "H2"),
    ("H3 LENGTH", char("H3", "VALUE", "0x10", "RL_U16", "LENGTH 99999999999"), "H3"),
    ("H4 DATA_SIZE", meas("H4", "DATA_SIZE 0x7FFFFFFFFFFF", "ECU_ADDRESS 0x10"), "H4"),
)
started = time.perf_counter()
for label, block, name in hostile:
    data = parse(block)
    t = tag(data, name)
    d = describe_definition(name, data)
    check(t["length"] is None and d.refusal is not None, f"hostile length {label}", (t["length"], d.refusal))
check(time.perf_counter() - started < 2.0, "hostile length describe time", round(time.perf_counter() - started, 4))

masked = parse(char("M", "VALUE", "0x10", "RL_U16", "BIT_MASK 0x000F/* nibble */0"))
m = tag(masked, "M")
d = describe_definition("M", masked)
check(
    d.bit_mask == 0x000F and d.refusal is not None,
    "commented mask word is read but the tag fails closed",
    (m.get("bit_org"), d.bit_mask, d.refusal),
)

old = "\n".join(("/*", meas("X", "ECU_ADDRESS 0x10"), "*/"))
data = parse(old + "\n" + meas("X", "ECU_ADDRESS 0x20"))
d = describe_definition("X", data)
check(len(data["tags"]) == 1 and d.address == 0x20 and d.refusal is None, "commented object is not duplicate", (len(data["tags"]), d.address, d.refusal))

unknown = parse('/begin INSTANCE IU "" T_NONE 0x10\n/end INSTANCE')
span = unknown["declared_spans"][0]
check(span["address"] == 0x10 and span["length"] is None, "unsized INSTANCE keeps declared address", span)

print("RESULT", "PASS" if not failures else f"FAIL {failures}")
scratch.cleanup()
raise SystemExit(1 if failures else 0)
