"""Inc 12 E2 (batch-103), runner only: the cut of graph-inc12.md's `_shorten_tag_name` on names with no fixture in the
cases: tracked V161 names that share a prefix, a double-width name, and the edges of w. Imports rich only (no s19_app);
the function body is the measurement prototype of i12e2-mkproto.py, copied verbatim.

    python -I i12e2-shorten.py
"""
from rich.cells import cell_len, set_cell_size


def _shorten_tag_name(name: str, width: int) -> str:
    if cell_len(name) <= width:
        return name
    width = max(1, width)
    head = (width - 1) // 2
    tail = width - 1 - head
    suffix = ""
    for char in reversed(name):
        if cell_len(char + suffix) > tail:
            break
        suffix = char + suffix
    return set_cell_size(name, head) + "…" + " " * (tail - cell_len(suffix)) + suffix


import rich  # noqa: E402
print("rich", getattr(rich, "__version__", "?"))
names = ["ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR",
         "ＡＢＣＤＥＦＧＨＩＪ",  # ten fullwidth letters, 20 cells
         "SYN_MAP_" + "L" * 36 + "_END"]
for name in names:
    for w in (34, 31, 25, 22, 20, 17, 14, 12, 9, 5, 1, 0):
        out = _shorten_tag_name(name, min(34, w))
        print(f"[shorten] len={len(name)} cells={cell_len(name)} w={w:>2} -> {out!r} ({cell_len(out)} cells)")
