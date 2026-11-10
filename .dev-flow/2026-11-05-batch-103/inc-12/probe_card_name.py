"""Inspect the full-name painted sequence in the Inc 12 detail card."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    scratch = Path(sys.argv[2]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from tests.test_b103_inc12_tag_table import (
        _explore,
        _painted_lines,
        longname,
        page_long,
    )

    print(s19_app.__file__)

    async def check(app, pilot, table) -> None:
        card = app.query_one("#a2l_detail_card")
        lines = [line.rstrip() for line in _painted_lines(card) if line.strip()]
        joined = "".join(lines)
        for index, line in enumerate(lines):
            print(f"painted_{index}_len={len(line)} text={line!r}")
        expected = longname(48)
        print(f"expected_len={len(expected)} joined_len={len(joined)}")
        print(f"expected={expected!r}")
        print(f"joined={joined!r}")
        print(f"expected_at_1={expected in joined} index={joined.find(expected)}")
        actual = joined[1:1 + len(expected)]
        print(f"actual_name={actual!r} actual_name_len={len(actual)}")
        for index, (left, right) in enumerate(zip(expected, actual)):
            if left != right:
                print(f"first_difference={index} expected={left!r} actual={right!r}")
                break
        else:
            print("common_prefix_length=", min(len(expected), len(actual)))
        print(f"scroll={card.scroll_y}/{card.max_scroll_y} wrap={card.wrap} min_width={card.min_width}")
        raw = card._card_text.plain
        print(f"raw_len={len(raw)} raw={raw!r}")
        print(f"expected_in_raw={expected in raw}")
        for index, strip in enumerate(card.lines):
            print(f"strip_{index}_len={len(strip.text)} text={strip.text!r}")

    _explore(scratch, page_long(48), (118, 54), check)


if __name__ == "__main__":
    main()
