"""Inc 11 E3 architect round 2: peak memory of the quoted-string pattern on the E3S-14 file (one string over 200,000
lines), one fresh process per pattern. Run on <runner> only.

    python -I e3a2-strmem.py <file> alt|unrolled|perline|base <repo>

alt       the E2 pilot's tier-3 string alternative, '"(?:[^"\\\\]|\\\\.)*"' with re.S, over the whole text (pilot2.TOK);
unrolled  the same language written unrolled, '"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"', over the whole text;
perline   the graph's line-driven contract (DE-1, DE-2, E3S-14): lines read one by one, an open string's parts kept in a
          list and joined once when it closes;
base      the e07fb00 reader's parse_a2l_file.
Prints the time and the peak RSS (ru_maxrss). Synthetic file only.
"""
import re
import resource
import sys
import time
from pathlib import Path

f, mode = Path(sys.argv[1]), sys.argv[2]
if mode == "base":
    sys.path.insert(0, sys.argv[3])
    import s19_app.tui.a2l as a  # noqa: E402
t0 = time.perf_counter()
if mode == "base":
    data = a.parse_a2l_file(f)
    out = len(data["tags"])
elif mode in ("alt", "unrolled"):
    text = f.read_text(encoding="utf-8")
    pat = re.compile(r'"(?:[^"\\]|\\.)*"' if mode == "alt" else r'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)
    m = pat.match(text, text.index('   "line 1 ') + 3)  # the 200,000-line string itself
    out = len(m.group(0)) if m else -1
else:
    parts, open_s, out = [], False, 0
    with f.open(encoding="utf-8", newline=None) as h:
        for line in h:
            if not open_s:
                k = line.find('"')
                if k < 0:
                    continue
                rest = line[k + 1:]
                j = rest.find('"')
                if j >= 0:
                    out = max(out, j)
                    continue
                parts, open_s = [rest], True
            else:
                j = line.find('"')
                if j < 0:
                    parts.append(line)
                    continue
                parts.append(line[:j])
                out = max(out, len("".join(parts)))
                parts, open_s = [], False
dt = time.perf_counter() - t0
print(f"[{mode}] {f.name}: {dt:.3f} s, result {out}, peak RSS {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.1f} MB")
