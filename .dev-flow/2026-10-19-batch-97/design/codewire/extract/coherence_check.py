"""Mechanical part of C2, C3, C4, C5, C6, C7, C10 over the five batch-97 graphs (annex §4).
Run from anywhere: python coherence_check.py. Uses the Code-Wire parser."""
import sys, collections
from pathlib import Path
sys.path.insert(0, r"C:\Users\jjgh8\Github\code-wire\tools")
import codewire_extract as cw
base = Path(__file__).resolve().parent.parent
texts = [(base / f"{f}.md").read_text(encoding="utf-8") for f in
         ["graph-patch-json", "graph-chip-open", "graph-nul-refusal", "graph-confirm-key", "graph-width"]]
nodes, edges, ents, conf = cw.load_graphs(texts)
N = {n["name"]: n for n in nodes}
print("nodes", len(nodes), "edges", len(edges), "entities", len(ents), "conflicts", conf)
print("C7 duplicate names", [k for k, v in collections.Counter([n["name"] for n in nodes] + ents).items() if v > 1])
inc_port, inc_node = set(), set()
for e in edges:
    d = e["dst"]
    if d.get("node"):
        (inc_port.add((d["node"], d["port"].split(".")[0])) if d.get("port") else inc_node.add(d["node"]))
strict = [(n["name"], p["name"]) for n in nodes for p in n["in"] if p["kind"] != "self" and (n["name"], p["name"]) not in inc_port]
conv = [x for x in strict if x[0] not in inc_node]
print("C2 inputs with no edge to their port:", len(strict), "| with no edge at all (M-3 convention applied):", len(conv))
for x in conv: print("   ", x)
used = {(e["src"]["node"], (e["src"].get("port") or "").split(".")[0]) for e in edges if e["src"].get("node")}
c3 = [(n["name"], o) for n in nodes for o in n["out"]["names"] if (n["name"], o) not in used]
print("C3 outputs with no outgoing edge:", len(c3)); [print("   ", x) for x in c3]
mods = {t for n in nodes for t in n["modify"] if t.startswith("[")}
reads = {e["src"]["entity"] for e in edges if e["src"].get("entity")}
writes = {e["dst"]["entity"] for e in edges if e["dst"].get("entity")} | mods
print("C10 undeclared modify targets", sorted(mods - set(ents)), "| orphan entities", [e for e in ents if e not in reads | writes])
adj = collections.defaultdict(set)
for e in edges:
    a = e["src"].get("node") or e["src"].get("entity"); b = e["dst"].get("node") or e["dst"].get("entity")
    if a and b: adj[a].add(b)
for n in nodes:
    adj[n["name"]] |= set(n["inner"]) | {t for t in n["modify"] if t.startswith("[")}
radj = collections.defaultdict(set)
for a, bs in adj.items():
    for b in bs: radj[b].add(a)
def reach(start, g):
    seen, st = set(start), list(start)
    while st:
        for y in g[st.pop()]:
            if y not in seen: seen.add(y); st.append(y)
    return seen
print("C4 not reached from an entity", [n for n in N if n not in reach(ents, adj)])
print("C4 reaching no entity", [n for n in N if n not in reach(ents, radj)])
print("C5 nodes without req", [n["name"] for n in nodes if not n["reqs"]])
print("C6 LLRs traced", sorted({r for n in nodes for r in n["reqs"] if r.startswith("LLR")}))
