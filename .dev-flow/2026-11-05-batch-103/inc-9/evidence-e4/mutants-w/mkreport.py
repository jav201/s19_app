import json
import re
import sys

sys.path.insert(0, ".")
from mw9_spec import M

BAR = chr(92) + "|"


def short(first):
    m = re.search(r"::(\S+)", first or "")
    return m.group(1)[:95] if m else ""


def load(f):
    out = {}
    for line in open(f, encoding="utf-8"):
        r = json.loads(line)
        out[r["id"]] = r
    return out


orig = {}
for f in ("logs/sh0.jsonl", "logs/sh1.jsonl", "logs/sh2.jsonl"):
    orig.update(load(f))
for line in open("logs/sweep-w15b.txt", encoding="utf-8"):
    m = re.match(r"^(w\d+\w*) (rc\d+|survived|killed|timeout) (\d+) s ?(.*)$", line.strip())
    if m and m.group(1) not in orig and not line.startswith("w15b"):
        i, st, sec, rest = m.groups()
        orig[i] = {"id": i, "status": "survived" if st == "survived" else "killed", "sec": int(sec), "first": rest}
new = {}
for f in ("logs/newt.jsonl", "logs/nx.jsonl", "logs/ny.jsonl", "logs/nz.jsonl", "logs/nc.jsonl", "logs/ns.jsonl"):
    new.update(load(f))
cs = {}
for line in open("logs/cs.log", encoding="utf-8"):
    m = re.match(r"^(c\d+) (rc\d+|survived) (\d+) s ?(.*)$", line.strip())
    if m:
        cs[m.group(1)] = (m.group(2), m.group(4))
EQUIV = {
    "w22e": "order of two independent queued jobs (decode, preview) that both end before the sheet settles; no settled output differs",
    "w25b": "the delta cell and the `staged` word read `row.is_staged` (the document), which an undo clears; a stale `staged` on a row that is not selected is rebuilt by the decode job at its next selection, so every observable output is equal",
    "w51b": "`event.stop()`: the apply request has no handler above the sheet, so bubbling it changes nothing a user or the document sees",
    "s07": "`staged` None versus equal to the current values for a row no entry overlaps: every reader of `staged` first needs `row.is_staged`, which needs an overlapping entry",
}
rows = []
n = k = s = 0
orig_surv = []
for mid, req, f, old, nw in M:
    if mid in ("tfix", "t26", "t26b"):
        continue
    n += 1
    if mid.startswith("c"):
        st, first = cs.get(mid, ("?", ""))
        ostat = "killed" if st.startswith("rc") else "survived"
        ofirst = short(first)
    else:
        o = orig[mid]
        ostat = "survived" if o["status"] == "survived" else "killed"
        ofirst = short(o.get("first"))
    final, by = ostat, ofirst
    if ostat == "survived":
        orig_surv.append(mid)
        nr = new.get(mid)
        if mid == "w15b":
            final, by = "killed (Inc 8 node)", "test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_24_3_a_text_row_left_with_its_row_fill_unchanged_is_not_pend..."
        elif nr and nr["status"] != "survived":
            final, by = "killed (new node)", short(nr["first"])
        elif mid in EQUIV:
            final, by = "survived, argued equivalent", EQUIV[mid]
        else:
            final, by = "SURVIVED (open)", ""
    if final.startswith("killed"):
        k += 1
    else:
        s += 1
    rows.append((mid, req, f.split("/")[-1], ostat, final, by))
print("TOTAL", n, "killed", k, "survived", s)
print(len(orig_surv), "survived the original nodes:", " ".join(orig_surv))
with open("table.md", "w", encoding="utf-8") as fh:
    fh.write("| Id | Requirement / code | File | Original nodes | Final | Killing node (or note) |\n|---|---|---|---|---|---|\n")
    for r in rows:
        fh.write("| " + " | ".join(x.replace("|", BAR) for x in r) + " |\n")
for r in rows:
    if r[4].startswith("SURV") or r[4].startswith("survived"):
        print(r[0], r[4])
