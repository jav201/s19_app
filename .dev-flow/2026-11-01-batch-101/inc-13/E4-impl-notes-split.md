# Inc 13 — E4 implementation notes: Split/Join (G2)

Unit: E4 IMPLEMENTER, group G2 (`s19_app/tui/segment_split_view.py`).
Design: `01-requirements.md`, `E1-slice.md`, `codewire/graph-inc13.md`,
`E1-rulings.md`, `E3-rulings.md` (round 1 + round 2 addenda). No deviation
from the graph.

## Functions / constants changed (file:name)

- `s19_app/tui/segment_split_view.py:_sweep` — changed.
  Was: for each elementary interval, scan every mark (O(intervals × marks)).
  Now: one pass over the sorted boundaries with a live count per class
  (O(m log m)); identical blocks (same priorities, same merge of equal
  neighbours; empty/inverted marks and marks wholly outside `[lo, hi)` add
  nothing).
- `s19_app/tui/segment_split_view.py:_conflict_marks` — changed.
  Was: per-address Python loop (`for addr in range(lo, hi)` with
  `addr in mem_map and mem_map[addr] != pad_byte`).
  Now: per source∩gap window,
  `bytes(map(mem_map.get, range(lo, hi), repeat(pad_byte, hi - lo)))`, and
  the non-pad runs of one compiled pattern
  `re.compile(b"[^" + re.escape(bytes([pad_byte])) + b"]+")` with no flags;
  adjacent runs merge as before. The docstring's false pin claim (that
  TC-710 pins the equivalence) is replaced by the R-SEG-PREV.2/2,
  R-SEG-PREV.2/3 and R-SEG-PREV.2/5 nodes; the 0 … 255 precondition (image
  values and `pad_byte`) is now stated.
- `s19_app/tui/segment_split_view.py` (imports) — `re` and
  `itertools.repeat` added. No other change.

## Deviations from the graph

None.

Non-material implementation notes (no graph deviation):
- The window expression is wrapped across two lines for readability; it is
  the same expression as the graph.
- The pattern is compiled once per call (the pad byte is fixed per call),
  the natural reading of "one compiled pattern".
- The `if lo >= hi: continue` guard is the graph's "non-empty `[lo, hi)`".

## Verification

- `python -m py_compile s19_app/tui/segment_split_view.py` → OK (exit 0).
- CRLF line endings preserved (the file keeps its line endings; no layout
  change).
- A standalone differential check (the two functions extracted from the
  file via AST, never importing the package) reproduced the graph examples
  and matched the base reference on 20 000 randomized `_sweep` cases and
  256 pads × 200 randomized `_conflict_marks` cases, all pads 0 … 255
  included.
