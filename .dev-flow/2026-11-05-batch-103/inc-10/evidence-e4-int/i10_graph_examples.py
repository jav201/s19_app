"""Inc 10 E4 integrator: the graph-example check C10 ran by hand on G3, as a script (run from a tree root).

Examples (``codewire/graph-inc10.md``, node ``emit_intel_hex_from_mem_map``; R-HEX-EMIT-001.11):
  1. x64u (32 bytes 0x00..0x1F at 0x0000FFF8) -> the six lines of ``tests/fixtures/b103_inc10/x64u.hex``,
     line for line (the stdlib oracle of ``inc-10/data/x64u_make.py``).
  2. x64 (36 bytes at 0x0000FFF0) -> two type-04 records; data rows unchanged by the fix (16, 16, 4 bytes).
  3. No data record of either output crosses a multiple of 0x10000.
  4. The function's own docstring example (doctest).
Exit 0 when every example holds; prints one line per example.
"""
import doctest
import sys
from pathlib import Path

from s19_app.tui.changes import io as chg_io

FIX = Path("tests/fixtures/b103_inc10")


def records(text):
    out, upper = [], 0
    for line in text.splitlines():
        raw = bytes.fromhex(line[1:])
        count, offset, rtype = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        if rtype == 0x04:
            upper = int.from_bytes(raw[4:6], "big") << 16
        out.append((rtype, upper + offset, count))
    return out


def crosses(text):
    return [(a, n) for t, a, n in records(text) if t == 0 and n and (a >> 16) != ((a + n - 1) >> 16)]


def main():
    ok = True
    x64u = {0xFFF8 + i: i for i in range(0x20)}
    got = chg_io.emit_intel_hex_from_mem_map(dict(x64u), [(0xFFF8, 0x10018)])
    want = (FIX / "x64u.hex").read_text().splitlines()
    ex1 = got.splitlines() == want
    print("EX1 x64u line for line:", ex1)
    x64 = {0xFFF0 + i: i & 0xFF for i in range(36)}
    got64 = chg_io.emit_intel_hex_from_mem_map(dict(x64), [(0xFFF0, 0xFFF0 + 36)])
    recs = records(got64)
    ex2 = [t for t, _a, _n in recs].count(0x04) == 2 and [n for t, _a, n in recs if t == 0] == [16, 16, 4]
    print("EX2 x64 two type-04, rows 16/16/4:", ex2, recs)
    ex3 = crosses(got) == [] and crosses(got64) == []
    print("EX3 no record crosses 0x10000:", ex3)
    finder = doctest.DocTestFinder()
    tests = [t for t in finder.find(chg_io) if t.name.endswith("emit_intel_hex_from_mem_map")]
    runner = doctest.DocTestRunner()
    for test in tests:
        runner.run(test)
    ex4 = bool(tests) and runner.failures == 0 and runner.tries > 0
    print("EX4 docstring example:", ex4, f"(tries={runner.tries}, failures={runner.failures})")
    ok = ex1 and ex2 and ex3 and ex4
    print("ALL HELD" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
