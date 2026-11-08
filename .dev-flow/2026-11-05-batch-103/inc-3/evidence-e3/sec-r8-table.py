"""E3 round 8: turn sec-r8-scale.py transcript lines into the Markdown rows of E3-security.md (text only, no s19_app).
Usage: python -I -B sec-r8-table.py <transcript>..."""
import re
import sys

S_RE = re.compile(r"^\[S (?P<pid>[A-Z]+-\d+)\](?P<label>.*?) (?P<users>[A-Z]{2}) (?P<what>.*?) \((?P<owner>[^()]*(?:\([^()]*\)[^()]*)*)\): "
                  r"sizes \[(?P<sizes>[^\]]*)\] KiB; runs (?P<runs>\d+); T400\(S\) (?P<t400>[\d.]+) s; describe per object "
                  r"(?P<dv>[\d. /]+) us \(2S x(?P<d2>[\d.]+)(?:, 8S x(?P<d8>[\d.]+))?\); message max/mean chars (?P<msg>[^;]*); "
                  r"codes (?P<codes>\[[^\]]*\]); same at every size (?P<same>\w+); carried table forms (?P<forms>\[[^\]]*\]); "
                  r"_TabForm in reads (?P<tir>\[[^\]]*\]); table-form builds per walk (?P<builds>\[[^\]]*\]); "
                  r"scalar conv checked/differ (?P<sc>\d+/\d+)"
                  r"(?: \| decode per object (?P<cv>[\d. /]+) us \(2S x(?P<c2>[\d.]+)(?:, 8S x(?P<c8>[\d.]+))?\); "
                  r"text/obj [^;]*; distinct long text objects (?P<objs>\[[^\]]*\]); element refusals (?P<eref>\[[^\]]*\]))?"
                  r" \| load (?P<load>[\d. ]+) => (?P<verdict>.*)$")
E_RE = re.compile(r"^\[EN (?P<pid>EN-\d)\](?P<label>.*?) (?P<users>[A-Z]{2}) .*?decode per ELEMENT (?P<cv>[\d. /]+) us "
                  r"\(2S x(?P<c2>[\d.]+), 8S x(?P<c8>[\d.]+)\); message kept per element (?P<kept>[\d /]+) chars; .* => (?P<verdict>.*)$")


def us(v):
    v = float(v)
    return f"{v / 1000:.1f} ms" if v >= 1000 else (f"{v:.1f}" if v < 10 else f"{v:.0f}")


def triple(vals, r2, r8):
    return " / ".join(us(x.strip()) for x in vals.split("/")) + f" (×{r2}{', ×' + r8 if r8 else ''})"


for path in sys.argv[1:]:
    for ln in open(path, encoding="utf-8"):
        ln = ln.rstrip("\n")
        mo = S_RE.match(ln)
        if mo:
            g = mo.groupdict()
            mx = " / ".join(x.split("/")[0] for x in g["msg"].split(" / "))
            mx = mx.split(" / ")[0] if len(set(mx.split(" / "))) == 1 else mx
            dec = "—"
            if g["cv"]:
                dec = "refused" if "None" not in g["codes"] else triple(g["cv"], g["c2"], g["c8"])
                if g["objs"] and g["objs"] not in ("[0, 0, 0]", "[0, 0]"):
                    dec += f"; long text objects {g['objs']}"
            extra = []
            if g["forms"] not in ("[0, 0, 0]", "[0, 0]"):
                extra.append(f"carried forms {g['forms']}")
            if g["sc"] != "0/0":
                extra.append(f"scalar 3a/2a refusals compared {g['sc'].replace('/', ', differ ')}")
            verdict = g["verdict"]
            verdict = f"**{verdict}**" if "RED" in verdict else verdict
            print(f"| {g['pid']} | {g['users']} | {g['what']}{'; ' + '; '.join(extra) if extra else ''} | {g['owner']} | "
                  f"{triple(g['dv'], g['d2'], g['d8'])} | {dec} | {mx} | {verdict} |")
            continue
        mo = E_RE.match(ln)
        if mo:
            g = mo.groupdict()
            verdict = f"**{g['verdict']}**" if "RED" in g["verdict"] else g["verdict"]
            print(f"| {g['pid']} | {g['users']} | one VAL_BLK of 64 elements, NAME long | 3a | — (one object) | "
                  f"{triple(g['cv'], g['c2'], g['c8'])} per element; {g['kept'].split(' / ')[0]} characters kept | — | "
                  f"{verdict} |")
            continue
        if ln.startswith("[S ") or ln.startswith("[EN "):
            print("UNPARSED:", ln[:200])
