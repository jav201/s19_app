"""Inc 8b E1 (batch-103): F-R14-1 cause probe on the real Windows Terminal capture.

Reads the PNG of the shipped sheet (proto8 baseline, unpatched 7c8bda05) and prints, for the three
array rows' Current cells, one character per terminal cell per sampled pixel row: `#` bright (RGB sum
> 600), `+` mid, `.` ground. Reads the PNG only; needs Pillow. Run:

    python -I -B f_r14_1_probe.py <path to base.off.sheet.118x54.png> > f_r14_1_probe-transcript.txt

Geometry (from the capture): 118 columns over x 34..1069 (8.77 px per cell), the CURVE_DEF_0001 row at
y 315..334, MAP_DEF_0001 334..353, VAL_BLK_DEF_0001 353..372 (19 px per row; text rows of the sidecar
`base.off.sheet.118x54.png.txt` lines 19-21 place the strips in the Current column, cells 0..4).
"""
import sys

from PIL import Image

X0, CELL, ROWS = 331, 9, (("CURVE_DEF_0001", 315), ("MAP_DEF_0001", 334), ("VAL_BLK_DEF_0001", 353))


def tone(pixel) -> str:
    total = sum(pixel[:3])
    return "#" if total > 600 else "+" if total > 150 else "."


def main(path: str) -> None:
    image = Image.open(path).convert("RGB")
    print(f"png = {path.replace(chr(92), '/').split('/')[-1]}")
    for name, top in ROWS:
        print(f"row {name} (y {top}..{top + 19}), cells 0..4 of the strip, each cell 9 px wide:")
        for y in range(top, top + 19, 2):
            line = "".join(tone(image.getpixel((X0 + c * CELL + 4, y))) for c in range(5))
            print(f"  y{y:4d} {line}")
    # The cell centre of each strip cell: the colour the glyph actually shows.
    for name, top in ROWS:
        centres = [image.getpixel((X0 + c * CELL + 4, top + 16)) for c in range(5)]
        print(f"bottom-centre RGB {name} = {centres}")
    # The boundary rows: a strip cell that is bright on the last pixel row of its text row AND on the
    # first pixel row of the next text row joins the next row's strip (no ground between them).
    for (upper, top_u), (lower, top_l) in zip(ROWS, ROWS[1:]):
        joined = [c for c in range(5)
                  if tone(image.getpixel((X0 + c * CELL + 4, top_l - 1))) == "#"
                  and tone(image.getpixel((X0 + c * CELL + 4, top_l))) == "#"]
        print(f"joined cells {upper} -> {lower} = {joined}")


if __name__ == "__main__":
    main(sys.argv[1])
