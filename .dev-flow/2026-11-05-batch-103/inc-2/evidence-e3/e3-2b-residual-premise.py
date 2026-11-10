from __future__ import annotations

import platform
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import s19_app
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definition

failures: list[str] = []


def check(ok: bool, label: str, detail: object = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'} {label} {detail}")
    if not ok:
        failures.append(label)


check(False, "SELFTEST expected failure")
failures.pop()
print("PASS SELFTEST red-proof")
print("PACKAGE", s19_app.__file__)
print("PLATFORM", platform.platform(), platform.python_version())

scratch = tempfile.TemporaryDirectory(prefix="b103-e3-2b-residual-")
path = Path(scratch.name) / "shape.a2l"
HEAD = (
    "ASAP2_VERSION 1 71\n/begin PROJECT P \"\"\n/begin MODULE M \"\"\n"
    "/begin MOD_COMMON \"\"\n{common}\n/end MOD_COMMON\n"
    "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
    "/begin RECORD_LAYOUT RL_U8\nFNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
)
TAIL = "/end MODULE\n/end PROJECT\n"


def char(name: str, kind: str, addr: str, layout: str, *body: str) -> str:
    return (
        f'/begin CHARACTERISTIC {name} ""\n{kind} {addr} {layout} 0 CM_ID 0 65535\n'
        + "\n".join(body)
        + "\n/end CHARACTERISTIC"
    )


def parse(body: str, common: str = "BYTE_ORDER MSB_FIRST") -> dict:
    path.write_text(HEAD.format(common=common) + body + "\n" + TAIL, encoding="utf-8")
    return parse_a2l_file(path)


data = parse(char("M", "VALUE", "0x10", "RL_U16", "BIT_MASK 0x000F", "BIT_MASK 0x000F"))
d = describe_definition("M", data)
check(
    any("BIT_MASK" in e and "twice" in e for e in data["errors"]),
    "same BIT_MASK twice reports an error",
    data["errors"],
)
check(d.refusal is None and d.bit_mask == 0x000F, "same BIT_MASK twice needs the new definition guard", (d.refusal, d.bit_mask))

data = parse(
    char("M", "VALUE", "0x10", "RL_U16", "BIT_MASK 0x000F"),
    common="BYTE_ORDER MSB_LAST\nBYTE_ORDER MSB_FIRST",
)
d = describe_definition("M", data)
check(
    d.byte_order == "little" and d.refusal is None,
    "duplicate MOD_COMMON BYTE_ORDER is currently last-wins",
    (d.byte_order, d.refusal, data["errors"]),
)

data = parse(
    char("N", "VALUE", "0xF000", "RL_U16", "BIT_MASK 0x0F00")
    + "\n"
    + char("N", "VALUE", "0x10", "RL_U16", "BIT_MASK 0x000F")
)
d = describe_definition("N", data)
check(
    len(data["tags"]) == 2 and d.refusal is not None and d.refusal.code == "A2L-DEF-NAME",
    "duplicate neighbour has no clean mask",
    (len(data["tags"]), d.refusal),
)

body = (
    char("X", "VALUE", "0x10", "RL_U16")
    + '\n/begin BLOB B1 "" 0x20 2\n/end BLOB'
    + '\n/begin INSTANCE I1 "" T_U16 0x30\n/end INSTANCE'
)
data = parse(body)
check(
    [s["kind"] for s in data["declared_spans"]] == ["BLOB", "INSTANCE"],
    "declared_spans keeps section order",
    data["declared_spans"],
)
sections: list[str] = []


def walk(nodes: list[dict]) -> None:
    for node in nodes:
        if node["name"] in ("MEASUREMENT", "CHARACTERISTIC", "BLOB", "INSTANCE"):
            sections.append(node["name"])
        walk(node.get("children") or [])


walk(data["sections"])
check(sections == ["CHARACTERISTIC", "BLOB", "INSTANCE"], "section walk supplies cross-kind file order", sections)

print("RESULT", "PASS" if not failures else f"FAIL {failures}")
scratch.cleanup()
raise SystemExit(1 if failures else 0)
