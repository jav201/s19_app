"""E3 round 7: turn sec-r7-scale.py transcripts into the Markdown rows of E3-security.md (text only, no s19_app).
Usage: python -I -B sec-r7-table.py <transcript>..."""
import re, sys


def us(v):
    v = float(v)
    return f"{v / 1000:.1f} ms" if v >= 1000 else f"{v:.0f}"


def triple(vals, r2, r8):
    vs = [x.strip() for x in vals.split("/")]
    body = " / ".join(us(x) for x in vs)
    return f"{body} (×{r2}{', ×' + r8 if r8 else ''})"


S_RE = re.compile(r"^\[S (?P<pid>[A-Z]+-\d+)\](?P<label>.*?) (?P<users>[A-Z]{2}) (?P<rest>.*): sizes \[(?P<sizes>[^\]]*)\] KiB; "
                  r"T400\(S\) (?P<t400>[\d.]+) s; describe per object (?P<dv>[\d. /]+) us \(2S x(?P<d2>[\d.]+)"
                  r"(?:, 8S x(?P<d8>[\d.]+))?\); message max/mean chars (?P<msg>[^;]*); codes (?P<codes>\[[^\]]*\]); "
                  r"same at every size (?P<same>\w+); NaN-x passes per walk (?P<nan>\[[^\]]*\])"
                  r"(?: \| decode per object (?P<cv>[\d. /]+) us \(2S x(?P<c2>[\d.]+)(?:, 8S x(?P<c8>[\d.]+))?\); "
                  r"text/obj [^;]*; distinct long text objects (?P<objs>\[[^\]]*\]); element refusals (?P<eref>\[[^\]]*\]))?"
                  r" => (?P<verdict>.*)$")
E_RE = re.compile(r"^\[EN (?P<pid>EN-\d)\](?P<label>.*?) (?P<users>[A-Z]{2}) (?P<what>.*): name [^;]*; decode per ELEMENT "
                  r"(?P<cv>[\d. /]+) us \(2S x(?P<c2>[\d.]+), 8S x(?P<c8>[\d.]+)\); message kept per element (?P<kept>[\d /]+) "
                  r"chars; element \[1\] message (?P<sample>.*?); describe refusal (?P<dref>\S+) => (?P<verdict>.*)$")

for path in sys.argv[1:]:
    for ln in open(path, encoding="utf-8"):
        ln = ln.rstrip("\n")
        mo = S_RE.match(ln)
        if mo:
            g = mo.groupdict()
            what, owner = g["rest"].rsplit(" (", 1)
            owner = owner.rstrip(")").replace(" | ", "; ")
            what = what.replace(" | ", "; ")
            mx = " / ".join(x.split("/")[0] for x in g["msg"].split(" / "))
            dec = triple(g["cv"], g["c2"], g["c8"]) if g["cv"] else "—"
            if g["cv"] and "None" not in g["codes"]:
                dec = "refused"
            if g["cv"] and g["objs"] and g["objs"] != "[0, 0, 0]":
                dec += f"; long text objects {g['objs']}"
            label = g["label"].strip()
            verdict = g["verdict"].replace("RED", "**RED").replace(")", ")**") if "RED" in g["verdict"] else g["verdict"]
            extra = f" NaN-x passes per walk {g['nan']}" if g["nan"] != "[0, 0, 0]" and g["nan"] != "[0, 0]" else ""
            print(f"| {g['pid']}{(' ' + label) if label else ''} | {g['users']} | {what}{(';' + extra) if extra else ''} | "
                  f"{owner} | {triple(g['dv'], g['d2'], g['d8'])} | {dec} | {mx} | {verdict} |")
            continue
        mo = E_RE.match(ln)
        if mo:
            g = mo.groupdict()
            label = g["label"].strip()
            verdict = "**RED**" if g["verdict"].startswith("RED") else g["verdict"]
            print(f"| {g['pid']}{(' ' + label) if label else ''} | {g['users']} | {g['what']} | 3a | — (one object) | "
                  f"{triple(g['cv'], g['c2'], g['c8'])} per element; kept {g['kept']} characters per element | "
                  f"{g['sample'].split(',')[0]} | {verdict} |")
            continue
        if ln.startswith("[S ") or ln.startswith("[EN "):
            print("UNPARSED:", ln[:160])
