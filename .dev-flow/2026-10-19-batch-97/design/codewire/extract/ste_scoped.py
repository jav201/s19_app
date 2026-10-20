"""C17 with the scope rule of Language-STE.md §2: structured graph lines are not prose.
In a graph file, each node/entity/finding block keeps only the values of its prose fields
(func, desc, what, consequence, decision) as one paragraph each; every other structured line
(name, in, out, req, module, modify, inner, open, examples, contract, sequence, edges, anchor,
evidence) is blanked. Non-graph prose (the `>` header is already skipped by the tool) is kept."""
import re, sys
sys.path.insert(0, r"C:\Users\jjgh8\Github\code-wire\tools")
import codewire_ste as ste
PROSE = ("func", "desc", "what", "consequence", "decision")
GRAPH_SECTIONS = ("## Nodes", "## Entities", "## Edges", "## Findings")
def scoped(text):
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line.strip() in GRAPH_SECTIONS
            out.append(line); continue
        if not inside:
            out.append(line); continue
        m = re.match(r"(\w+):\s*(.*)$", line)
        if m and m.group(1) in PROSE:
            v = m.group(2)
            v = v[0].upper() + v[1:] if v else v
            out += ["", v.replace("; ", ". ") if False else v, ""]
        else:
            out.append("")
    return "\n".join(out)
g = ste.load_glossary(sys.argv[1])
errs = 0; found_all = []
for p in sys.argv[2:]:
    t = open(p, encoding="utf-8").read()
    f = ste.check_text(scoped(t), g, p.split("/")[-1])
    found_all += f
for name, line, rule, level, msg in found_all:
    print(f"{name}:{line}: {rule} {level}: {msg}")
e = sum(x[3] == "error" for x in found_all)
print(f"{e} errors, {len(found_all)-e} warnings")
