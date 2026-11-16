"""i7e1-pilot.py -- batch-103 Inc 7 E1 pilot (throwaway; evidence, not product code).

Runs on the Linux runner against an exact clone of b103-inc7 (2dbd7d5a). It computes, with the
SHIPPED I-3 matcher (s19_app.tui.services.label_match) and the SHIPPED I-5 parser
(parse_parameter_list), the example values the Inc 7 rows and cases cite, so no expected value is
typed by hand:

  1  case 08 (tools/synth/make_release_case.py --seed 20260001): the tag names the reader lists
  2  the dropdown examples of the approved G2 scenes (av-sub "0017", av-typo "cuvre_00",
     av-modal add line "0042 val") and the other queries the rows use, rank(q, index, 20)
  3  the paste-modal list of the G2 scenes resolved by the rows' definition (exact, case-sensitive,
     pasted order, first occurrence found / repeat = duplicate)
  4  closest names (rank limit 3) of each missing name, and of a case variant
  5  hostile sizes: a 65,536-character paste (the I-1 cap) over case 08 and over software_a.a2l:
     parse + resolve time, token count, joined filter-text length
  6  the keys: Textual's own input parser maps the legacy and the kitty sequences of alt+p,
     alt+f, alt+a to the key names the rows bind (Linux parser only; Windows Terminal is P-1)
  7  a headless Input with a tab binding: tab reaches the box binding before the app's focus_next
"""
from __future__ import annotations

import asyncio
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(REPO))

import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("python =", sys.version.split()[0])
print("repo HEAD =", subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short=8", "HEAD"],
                                    capture_output=True, text=True).stdout.strip())
print("load before =", os.getloadavg())

from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_parameter_picker import parse_parameter_list  # noqa: E402
from s19_app.tui.services.label_match import build_label_index, rank  # noqa: E402


def fmt(m) -> str:
    spans = ",".join(f"({s},{e})" for s, e in m.spans)
    edits = f" · e{m.edits}" if m.rule.value == "fuzzy" else ""
    return f"{m.name} · {m.rule.value} · {spans}{edits}"


def names_of(path: Path) -> list:
    data = parse_a2l_file(path)
    return [str(t.get("name") or "") for t in data.get("tags", [])]


# 1 ---------------------------------------------------------------------------------
print("\n=== 1. case 08")
gen = subprocess.run([sys.executable, str(REPO / "tools/synth/make_release_case.py"), "--out", str(OUT / "case08"),
                      "--seed", "20260001"], capture_output=True, text=True)
print("make_release_case rc =", gen.returncode)
C08 = names_of(OUT / "case08" / "firmware.a2l")
print("case08 names =", len(C08), "distinct =", len(set(C08)))
kinds = {}
for n in C08:
    k = n.rsplit("_", 1)[0]
    kinds[k] = kinds.get(k, 0) + 1
print("by kind =", dict(sorted(kinds.items())))
idx = build_label_index(C08)
print("index len =", len(idx))

# 2 ---------------------------------------------------------------------------------
print("\n=== 2. dropdown rankings over case 08, limit 20 (rank(q, index, 20))")
for q in ("0017", "cuvre_00", "0042 val", "value_0002", "VALUE_0002", "map_002", "zzzz", "   ", "x" * 257):
    res = rank(q, idx, 20)
    shown = q if len(q) < 40 else f"'x'*{len(q)}"
    print(f"-- q={shown!r}: {len(res)} entries")
    for i, m in enumerate(res):
        print(f"   {i + 1:2d} {fmt(m)}")
for q, lim in (("cuvre_00", 21), ("cuvre_00", 100), ("0017", 100)):
    print(f"-- q={q!r} limit {lim}: {len(rank(q, idx, lim))} entries")

# 3 ---------------------------------------------------------------------------------
print("\n=== 3. paste-modal list of the G2 scenes, resolved (exact, case-sensitive, pasted order)")
LIST_TEXT = ("VALUE_0002\nCURVE_0001, MAP_0003\nMEASUREMENT_0005\nVALUE_0042, CURVE_0017\nMAP_0024\nMAP_0001\n"
             "MEASUREMENT_0012, VALUE_0002\nCURVE_0071\nVALUE_0118\n")
tokens = parse_parameter_list(LIST_TEXT)
present = set(C08)
first: dict = {}
found = missing = dup = 0
rows = []
for pos, tok in enumerate(tokens, 1):
    if tok in first:
        dup += 1
        rows.append((pos, tok, f"dup of #{first[tok]}"))
        continue
    first[tok] = pos
    if tok in present:
        found += 1
        rows.append((pos, tok, "found"))
    else:
        missing += 1
        rows.append((pos, tok, "not in A2L"))
print("tokens =", len(tokens))
for r in rows:
    print("  ", r)
print(f"counts: {len(tokens)} pasted · {found} found · {missing} missing · {dup} duplicate")
print("joined filter text =", repr(", ".join(tokens)))

# 4 ---------------------------------------------------------------------------------
print("\n=== 4. closest names (rank limit 3)")
for q in ("MAP_0024", "CURVE_0071", "value_0002", "VALUE_002", "x" * 300):
    shown = q if len(q) < 40 else f"'x'*{len(q)}"
    print(f"-- {shown!r}:", [fmt(m) for m in rank(q, idx, 3)])

# 5 ---------------------------------------------------------------------------------
print("\n=== 5. hostile size: a 65,536-character paste")
SWA = names_of(REPO / "examples/case_00_public/software_a.a2l")
print("software_a names =", len(SWA))


def build_paste(pool: list, cap: int = 65536) -> str:
    parts, size, i = [], 0, 0
    while True:
        name = pool[i % len(pool)] if i % 3 else f"MISSING_{i:06d}"
        if size + len(name) + 1 > cap:
            break
        parts.append(name)
        size += len(name) + 1
        i += 1
    return "\n".join(parts)


for label, pool in (("case08", C08), ("software_a", SWA)):
    text = build_paste(pool)
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        toks = parse_parameter_list(text)
        names = set(pool)
        seen = set()
        stat = []
        for t in toks:
            stat.append("dup" if t in seen else ("found" if t in names else "missing"))
            seen.add(t)
        times.append(time.perf_counter() - t0)
    print(f"{label}: paste chars = {len(text)}, tokens = {len(toks)}, joined = {len(', '.join(toks))} chars, "
          f"missing = {stat.count('missing')}, dup = {stat.count('dup')}, parse+resolve median of 5 = "
          f"{statistics.median(times) * 1000:.1f} ms")
sidx = build_label_index(SWA)
miss = [f"MISSING_{i:06d}" for i in range(0, 30, 3)]
times = []
for _ in range(3):
    t0 = time.perf_counter()
    for m in miss:
        rank(m, sidx, 3)
    times.append(time.perf_counter() - t0)
print(f"software_a: closest names for 10 missing names (limit 3 each): median of 3 = "
      f"{statistics.median(times) * 1000:.1f} ms")

# 6 ---------------------------------------------------------------------------------
print("\n=== 6. Textual input parser: key names")
import textual  # noqa: E402
from textual._xterm_parser import XTermParser  # noqa: E402

print("textual =", textual.__version__)
for seq in ("\x1bp", "\x1bf", "\x1ba", "\x1b[112;3u", "\x1b[102;3u", "\x1b[97;3u", "\t", "\x1b[9u"):
    parser = XTermParser(debug=False)
    keys = [getattr(e, "key", type(e).__name__) for e in parser.feed(seq)]
    keys += [getattr(e, "key", type(e).__name__) for e in parser.feed("")]
    print(f"   {seq!r:20} -> {keys}")

# 7 ---------------------------------------------------------------------------------
print("\n=== 7. headless: a box-level tab binding runs before the app's focus_next")
from textual.app import App  # noqa: E402
from textual.binding import Binding  # noqa: E402
from textual.widgets import Input  # noqa: E402

hits = []


class Box(Input):
    BINDINGS = [Binding("tab", "complete", show=False)]

    def action_complete(self) -> None:
        hits.append(("complete", self.id))


class Probe(App):
    def compose(self):
        yield Box(id="a")
        yield Input(id="b")


async def run() -> None:
    app = Probe()
    async with app.run_test() as pilot:
        app.query_one("#a").focus()
        await pilot.press("tab")
        await pilot.pause()
        print("   hits =", hits, "focused =", app.focused.id if app.focused else None)
        app.query_one("#b").focus()
        await pilot.press("tab")
        await pilot.pause()
        print("   from #b: focused =", app.focused.id if app.focused else None)


asyncio.run(run())
print("load after =", os.getloadavg())
