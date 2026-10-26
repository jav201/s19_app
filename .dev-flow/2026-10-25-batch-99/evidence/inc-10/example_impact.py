"""F4 evidence — user-visible impact of the inc-10 engine fixes on the repo examples.

Two measurements, reproducing the independent reviewer's counts:

1. examples/**/case_06* — how many tags NOW decode big-endian that did not
   under the pre-inc-10 resolution (tag BYTE_ORDER → RECORD_LAYOUT → little;
   MOD_COMMON never read). Byte order only bites on multi-byte datatypes
   (a UBYTE decodes the same either way), so the count covers tags whose
   datatype is wider than one byte: measured 71,513 of 220,040 (the other
   110,020 are UBYTE). OLD effective byte order is re-derived here from the
   parsed tag (tag endian / layout byte order, else little); NEW is the
   shipped extract_a2l_tags result.

2. RAT_FUNC tags in examples/**/software_a.a2l whose decode direction
   changed (the decode now solves INT = f(PHYS) for PHYS instead of
   evaluating f on the raw value) — every tag carrying a RAT_FUNC
   COMPU_METHOD decodes in the new direction, so the count is the number of
   tags whose conversion is RAT_FUNC. Measured 1,640.

Read-only: parses example A2L files; writes nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from s19_app.tui.a2l import DATATYPE_SIZES, parse_a2l_file  # noqa: E402


def _old_effective_byte_order(tag: dict, layouts: dict) -> str:
    """The pre-inc-10 resolution: RECORD_LAYOUT, then tag endian, then little
    (MOD_COMMON was never read)."""
    layout = layouts.get(str(tag.get("record_layout_name") or ""))
    if layout and layout.get("byte_order"):
        return layout["byte_order"]
    endian = tag.get("endian")
    if endian in ("big", "little"):
        return endian
    return "little"


def _is_multi_byte(tag: dict) -> bool:
    size = tag.get("byte_size")
    if not isinstance(size, int):
        size = DATATYPE_SIZES.get(tag.get("datatype"))
    if not isinstance(size, int):
        length = tag.get("length")
        size = length if isinstance(length, int) and length > 0 else None
    return isinstance(size, int) and size >= 2


def main() -> None:
    examples = _ROOT / "examples"

    # 1 — case_06 big-endian decode impact (multi-byte tags only)
    newly_big = 0
    total = 0
    multi_byte = 0
    for a2l in sorted(examples.glob("**/case_06*/**/*.a2l")):
        payload = parse_a2l_file(a2l)
        layouts = payload["record_layouts_by_name"]
        for tag in payload["tags"]:
            total += 1
            if not _is_multi_byte(tag):
                continue
            multi_byte += 1
            if (
                tag.get("effective_byte_order") == "big"
                and _old_effective_byte_order(tag, layouts) != "big"
            ):
                newly_big += 1
    print(f"case_06 tags total: {total} (multi-byte: {multi_byte})")
    print(f"case_06 multi-byte tags now decoding big-endian "
          f"(were not on main): {newly_big}")

    # 2 — software_a RAT_FUNC direction change
    for a2l in sorted(examples.glob("**/software_a.a2l")):
        payload = parse_a2l_file(a2l)
        methods = payload["compu_methods_by_name"]
        rat_func = [
            tag
            for tag in payload["tags"]
            if str(
                (methods.get(str(tag.get("compu_method_name"))) or {}).get(
                    "conversion_type"
                )
            ).upper()
            == "RAT_FUNC"
        ]
        print(f"{a2l.relative_to(_ROOT)}: tags {len(payload['tags'])}, "
              f"RAT_FUNC tags whose decode direction changed: {len(rat_func)}")


if __name__ == "__main__":
    main()
