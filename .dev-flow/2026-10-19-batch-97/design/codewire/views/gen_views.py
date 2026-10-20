"""Generate the Code-Wire views of the batch-97 graphs as SVG, from the graph text only (C14).

Low level  = every node with its contract (name, in, out, req, module, modify, first example line).
High level = node names, arrows and entities only.
Visual codes and their text source (Texto-Canonico.md §2):
  background colour  <- `module:` (one colour per file, legend at the bottom)
  bold name          <- a dot in the name (`Class.method`)
  shaded band        <- an input with the prefix `(Callable)`
  dashed purple edge <- an edge with `when:`
  dashed red box     <- a `## Findings` block (anchored to its node or edge); it states what each finding receives
  dashed grey box    <- a node of another graph file that an edge of this file names (a stub, no contract)
The overview (`overview.svg`) is a review view, not a graph view: it adds the status of each node
(NEW = no def in the code, CHANGED = a synthetic example on a node with code or a signature drift,
SHIPPED = neither), read from `../extract/marks.json`, `../extract/extract.json` and the example markers.

    python gen_views.py   (from this folder; reads ../graph-*.md; writes *.svg here)
Stdlib only. The graph parser is the Code-Wire extractor (`codewire_extract.py`).
"""
import html
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, r"C:\Users\jjgh8\Github\code-wire\tools")
import codewire_extract as cw  # noqa: E402

PALETTE = ["#dbeafe", "#dcfce7", "#fef3c7", "#fce7f3", "#e0e7ff", "#ccfbf1", "#ffedd5", "#ede9fe", "#f1f5f9", "#ecfccb"]
MODULE_COLOR = {}
CHAR_W, LINE_H = 6.6, 14


def color(module):
    if module not in MODULE_COLOR:
        MODULE_COLOR[module] = PALETTE[len(MODULE_COLOR) % len(PALETTE)]
    return MODULE_COLOR[module]


def wrap(text, width):
    out, line = [], ""
    for word in text.split(" "):
        if len(line) + len(word) + 1 > width and line:
            out.append(line)
            line = "  " + word
        else:
            line = (line + " " + word).strip(" ") if line else word
    if line:
        out.append(line)
    return out


def field_lines(md_text, name):
    """Raw `field: value` lines of one node block (the parser keeps types, the view keeps the words)."""
    for block in re.split(r"\n\s*\n", cw.section(md_text, "Nodes")):
        lines = [l for l in block.strip().splitlines() if l.strip()]
        if lines and lines[0].strip() == name:
            return lines[1:]
    return []


def findings(md_text):
    out = []
    for block in re.split(r"\n\s*\n", cw.section(md_text, "Findings")):
        lines = [l for l in block.strip().splitlines() if l.strip()]
        if len(lines) < 2:
            continue
        f = {"id": lines[0].strip()}
        for l in lines[1:]:
            m = re.match(r"(\w+):\s*(.*)$", l)
            if m:
                f[m.group(1)] = m.group(2)
        out.append(f)
    return out


def layers(names, rel):
    """Longest-path layering over parent->child relations, cycles cut by visit order."""
    depth = {n: 0 for n in names}
    for _ in range(len(names)):
        changed = False
        for a, b in rel:
            if a in depth and b in depth and a != b and depth[b] < depth[a] + 1 and depth[a] < len(names):
                depth[b] = depth[a] + 1
                changed = True
        if not changed:
            break
    return depth


def render(md_text, title, subtitle, only=None, level="low", status=None, out=None):
    nodes_all = cw.parse_graph(md_text)
    node_by = {n["name"]: n for n in nodes_all}
    names = [n["name"] for n in nodes_all if only is None or n["name"] in only]
    known = set(names)
    edges = cw.parse_edges(md_text, list(node_by) + list(EXTERNAL))
    ents = cw.parse_entities(md_text)
    rel = []
    for n in names:
        for c in node_by[n]["inner"]:
            rel.append((n, c))
    for e in edges:
        s, d = e["src"], e["dst"]
        if s.get("node") and d.get("node"):
            rel.append((s["node"], d["node"]))
    stubs = sorted({x for a, b in rel for x in (a, b) if x not in known and (a in known or b in known)})
    depth = layers(names + stubs, rel)
    # entities: sources left (column -1), sinks right
    ent_src = {e["src"]["entity"] for e in edges if e["src"].get("entity")}
    modified = {}
    for n in names:
        for t in node_by[n]["modify"]:
            if t.startswith("["):
                modified.setdefault(t, []).append(n)
    ent_in = {e["dst"]["entity"] for e in edges if e["dst"].get("entity")}
    ent_show = [e for e in ents if e in ent_src or e in modified or e in ent_in]
    maxd = max(depth.values()) if depth else 0
    col_of = {}
    for e in ent_show:
        col_of[e] = -1 if (e in ent_src and e not in modified and e not in ent_in) else maxd + 1

    box_w = 430 if level == "low" else 250
    wchars = int((box_w - 16) / CHAR_W)
    content = {}
    for n in names + stubs:
        if n in stubs:
            content[n] = [n, "(declared in another graph file)"]
            continue
        lines = [n]
        if level == "low":
            raw = field_lines(md_text, n)
            ex_done = False
            for l in raw:
                k = l.split(":", 1)[0]
                if k in ("func", "open", "contract", "sequence"):
                    continue
                if k == "examples":
                    if ex_done:
                        continue
                    ex_done = True
                if k == "module":
                    l = "module: " + l.split(":", 1)[1].strip().replace("s19_app/tui/", "")
                lines += wrap(l, wchars)
        content[n] = lines
    for e in ent_show:
        content[e] = [e]
    # positions
    col_x = {}
    gap_x = 90
    cols = sorted(set(list(depth.values()) + list(col_of.values())))
    for i, c in enumerate(cols):
        col_x[c] = 30 + i * (box_w + gap_x)
    pos, col_y = {}, {}
    order = sorted(names + stubs, key=lambda n: (depth[n], (names + stubs).index(n)))
    for n in order + ent_show:
        c = depth[n] if n in depth else col_of[n]
        y = col_y.get(c, 90)
        h = 12 + LINE_H * len(content[n])
        pos[n] = (col_x[c], y, box_w if n not in ent_show else min(box_w, 30 + CHAR_W * len(n)), h)
        col_y[c] = y + h + 26
    fnds = findings(md_text)
    width = max(x + w for x, y, w, h in pos.values()) + 40
    height = max(y + h for x, y, w, h in pos.values()) + 70
    red = []
    if fnds:
        red_y = height
        for f in fnds:
            body = [f"{f['id']} · {f.get('anchor', '')}", "what: " + f.get("what", ""), "decision: " + f.get("decision", "")]
            lines = []
            for b in body:
                lines += wrap(b, int((width - 80) / CHAR_W))
            red.append((f, red_y, lines))
            red_y += 16 + LINE_H * len(lines) + 14
        height = red_y + 20
    legend_y = height
    height += 30 + 18 * ((len(MODULE_COLOR) + len({node_by[n]['modulo_file'] for n in names})) // 3 + 1)

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" font-family="Consolas, monospace" font-size="11">',
           '<defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 z" fill="#334155"/></marker>'
           '<marker id="p" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 z" fill="#7c3aed"/></marker></defs>',
           f'<rect width="100%" height="100%" fill="#ffffff"/>',
           f'<text x="30" y="32" font-family="Segoe UI, sans-serif" font-size="18" fill="#0f172a">{html.escape(title)}</text>',
           f'<text x="30" y="54" font-family="Segoe UI, sans-serif" font-size="12" fill="#475569">{html.escape(subtitle)}</text>']

    def anchor_pt(n, side):
        x, y, w, h = pos[n]
        return (x + w, y + 14) if side == "out" else (x, y + 14)

    def arrow(a, b, dashed=False, purple=False, label=""):
        x1, y1 = anchor_pt(a, "out")
        x2, y2 = anchor_pt(b, "in")
        if x2 <= x1:  # backwards or same column: route below
            x1, y1 = pos[a][0] + pos[a][2] / 2, pos[a][1] + pos[a][3]
            x2, y2 = pos[b][0] + pos[b][2] / 2, pos[b][1]
            if y2 < y1:
                y2 = pos[b][1] + pos[b][3]
        col = "#7c3aed" if purple else "#334155"
        dash = ' stroke-dasharray="6,4"' if dashed or purple else ""
        mx = (x1 + x2) / 2
        svg.append(f'<path d="M{x1:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}" fill="none" stroke="{col}" stroke-width="1.2"{dash} marker-end="url(#{"p" if purple else "a"})"/>')
        if label:
            svg.append(f'<text x="{mx:.0f}" y="{(y1 + y2) / 2 - 3:.0f}" fill="{col}" font-size="10">{html.escape(label)}</text>')

    drawn = set()
    for e in edges:
        s, d = e["src"], e["dst"]
        a = s.get("node") or s.get("entity")
        b = d.get("node") or d.get("entity")
        if a in pos and b in pos and (a, b) not in drawn:
            drawn.add((a, b))
            arrow(a, b, purple=bool(e["when"]), label=(d.get("port") or "") if level == "low" else "")
    for n in names:
        for c in node_by[n]["inner"]:
            if c in pos and (n, c) not in drawn:
                drawn.add((n, c))
                arrow(n, c, dashed=True, label="inner" if level == "low" else "")
        for t in node_by[n]["modify"]:
            if t in pos and (n, t) not in drawn:
                drawn.add((n, t))
                arrow(n, t, dashed=True, label="modify")
    for n, lines in content.items():
        if n not in pos:
            continue
        x, y, w, h = pos[n]
        if n in ent_show:
            svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#f8fafc" stroke="#64748b"/>')
        elif n in stubs:
            svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#f8fafc" stroke="#94a3b8" stroke-dasharray="4,3"/>')
        else:
            fill = color(node_by[n]["modulo_file"])
            st = status.get(n) if status else None
            stroke = {"NEW": "#16a34a", "CHANGED": "#d97706", "SHIPPED": "#334155"}.get(st, "#334155")
            svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}" stroke-width="{2.5 if st else 1}"/>')
            svg.append(f'<line x1="{x + 3}" y1="{y}" x2="{x + 3}" y2="{y + h}" stroke="#0f172a" stroke-width="1.5"/>')
            svg.append(f'<line x1="{x + w - 3}" y1="{y}" x2="{x + w - 3}" y2="{y + h}" stroke="#0f172a" stroke-width="1.5"/>')
            if level == "low":
                for i, l in enumerate(lines):
                    if "(Callable)" in l:
                        svg.append(f'<rect x="{x + 6}" y="{y + 6 + LINE_H * i}" width="{w - 12}" height="{LINE_H}" fill="#fcd34d" opacity="0.45"/>')
        for i, l in enumerate(lines):
            weight = "bold" if i == 0 and "." in n and not n.startswith("[") else "normal"
            fillc = "#166534" if l.startswith("examples:") else "#0f172a"
            label = l + (f"  [{status[n]}]" if i == 0 and status and n in status else "")
            svg.append(f'<text x="{x + 10}" y="{y + 18 + LINE_H * i}" font-weight="{weight}" fill="{fillc}">{html.escape(label)}</text>')
    for f, ry, lines in red:
        hgt = 10 + LINE_H * len(lines)
        svg.append(f'<rect x="30" y="{ry}" width="{width - 60}" height="{hgt}" fill="#fef2f2" stroke="#dc2626" stroke-dasharray="6,4"/>')
        for i, l in enumerate(lines):
            svg.append(f'<text x="40" y="{ry + 16 + LINE_H * i}" fill="#b91c1c">{html.escape(l)}</text>')
    lx, ly = 30, legend_y + 10
    mods = sorted({node_by[n]["modulo_file"] for n in names})
    for i, m in enumerate(mods):
        cx = lx + (i % 3) * 360
        cy = ly + (i // 3) * 18
        svg.append(f'<rect x="{cx}" y="{cy}" width="14" height="12" fill="{color(m)}" stroke="#334155"/>')
        svg.append(f'<text x="{cx + 20}" y="{cy + 10}" fill="#334155">{html.escape(m)}</text>')
    svg.append("</svg>")
    (HERE / out).write_text("\n".join(svg), encoding="utf-8")
    return out


EXTERNAL = set()


def render_overview(graphs, status, out):
    """Batch overview: one box per flow (a subsystem at high level), its nodes by status, the
    cross-flow edges and calls, and the entities that two flows share. Status comes from extract/
    (a review view, not a graph view)."""
    flows = {stem: [n["name"] for n in cw.parse_graph(text)] for stem, text in graphs.items()}
    owner = {n: f for f, ns in flows.items() for n in ns}
    ents = {}
    for stem, text in graphs.items():
        for e in cw.parse_entities(text):
            ents.setdefault(e, set()).add(stem)
    shared = {e: fs for e, fs in ents.items() if len(fs) > 1}
    cross = set()
    for stem, text in graphs.items():
        for e in cw.parse_edges(text, list(owner)):
            a, b = e["src"].get("node"), e["dst"].get("node")
            if a in owner and b in owner and owner[a] != owner[b]:
                cross.add((owner[a], owner[b], f"{a} → {b}"))
        for n in cw.parse_graph(text):
            for c in n["inner"]:
                if c in owner and owner[c] != stem:
                    cross.add((stem, owner[c], f"{n['name']} → {c} (inner)"))
    W, x0 = 520, 30
    body, pos = [], {}
    for i, f in enumerate(flows):
        x = x0 + (i % 3) * (W + 60)
        lines = [f.replace("graph-", "") + "  (subsystem)"]
        for st in ("NEW", "CHANGED", "SHIPPED"):
            ns = [n for n in flows[f] if status.get(n) == st]
            lines.append(f"{st} {len(ns)}")
            for chunk in wrap(", ".join(ns), int((W - 30) / CHAR_W)):
                lines.append("  " + chunk)
        h = 14 + LINE_H * len(lines)
        pos[f] = (x, i // 3, W, h)
    row_h = {r: max(h for (x, rr, w, h) in pos.values() if rr == r) for r in {p[1] for p in pos.values()}}
    for i, f in enumerate(flows):
        x, r, w, h = pos[f]
        y = 80 + sum(row_h[k] + 40 for k in range(r))
        lines = [f.replace("graph-", "") + "  (subsystem)"]
        for st in ("NEW", "CHANGED", "SHIPPED"):
            ns = [n for n in flows[f] if status.get(n) == st]
            lines.append(f"{st} {len(ns)}")
            for chunk in wrap(", ".join(ns), int((W - 30) / CHAR_W)):
                lines.append("  " + chunk)
        body.append(f'<rect x="{x}" y="{y}" width="{W}" height="{h}" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>')
        body.append(f'<rect x="{x + 4}" y="{y + 4}" width="{W - 8}" height="{h - 8}" fill="none" stroke="#0f172a"/>')
        for j, l in enumerate(lines):
            col = {"NEW": "#15803d", "CHANGED": "#b45309", "SHIPPED": "#334155"}.get(l.split(" ")[0], "#0f172a")
            body.append(f'<text x="{x + 12}" y="{y + 20 + LINE_H * j}" fill="{col}" font-weight="{"bold" if j == 0 else "normal"}">{html.escape(l)}</text>')
    ey = 80 + sum(row_h[k] + 40 for k in row_h) + 10
    body.append(f'<text x="30" y="{ey}" font-family="Segoe UI, sans-serif" font-size="13" fill="#0f172a">Cross-flow edges and calls</text>')
    for k, (a, b, lab) in enumerate(sorted(cross)):
        body.append(f'<text x="40" y="{ey + 20 + 15 * k}" fill="#334155">{html.escape(a.replace("graph-", ""))} ──▶ {html.escape(b.replace("graph-", ""))} : {html.escape(lab)}</text>')
    ey2 = ey + 40 + 15 * len(cross)
    body.append(f'<text x="30" y="{ey2}" font-family="Segoe UI, sans-serif" font-size="13" fill="#0f172a">Entities in more than one flow</text>')
    for k, (e, fs) in enumerate(sorted(shared.items())):
        body.append(f'<text x="40" y="{ey2 + 20 + 15 * k}" fill="#334155">{html.escape(e)} : {html.escape(", ".join(sorted(f.replace("graph-", "") for f in fs)))}</text>')
    height = ey2 + 40 + 15 * len(shared)
    width = x0 + 3 * (W + 60)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="Consolas, monospace" font-size="11">',
           '<rect width="100%" height="100%" fill="#ffffff"/>',
           '<text x="30" y="32" font-family="Segoe UI, sans-serif" font-size="18" fill="#0f172a">batch-97 · Code-Wire overview of the five flows (review view)</text>',
           '<text x="30" y="54" font-family="Segoe UI, sans-serif" font-size="12" fill="#475569">one double-framed box per flow · NEW = no def in the code · CHANGED = a synthetic example or a signature drift on a node with code · SHIPPED = neither · read from extract/, not from the graph text</text>']
    (HERE / out).write_text("\n".join(svg + body + ["</svg>"]), encoding="utf-8")
    return out


def main():
    graphs = {p.stem: p.read_text(encoding="utf-8") for p in sorted(HERE.parent.glob("graph-*.md")) if p.stem != "graph-batch97-overview"}
    all_nodes = {}
    for t in graphs.values():
        for n in cw.parse_graph(t):
            all_nodes.setdefault(n["name"], n)
    EXTERNAL.update(all_nodes)
    common = "colour = file · bold = method · dashed purple = when: · dashed = inner/modify · red dashed = finding · generated from the graph text (C14)"
    outs = []
    split = {"graph-patch-json": [
        ("low-app", {"S19TuiApp.on_patch_editor_panel_action_requested", "S19TuiApp.action_patch_undo", "S19TuiApp.action_patch_redo",
                     "S19TuiApp._apply_entry_json_edit", "S19TuiApp._refresh_patch_history_view", "S19TuiApp._patch_editor_load",
                     "S19TuiApp._patch_editor_load_tail", "S19TuiApp._apply_prepared_load", "S19TuiApp._patch_document_view",
                     "serialize_change_document"}),
        ("low-panel", {"PatchEditorPanel.refresh_entries", "PatchEditorPanel._refresh_dirty_indicator", "json_stamp_text",
                       "PatchEditorPanel.mark_saved", "PatchEditorPanel.mark_loaded", "PatchEditorPanel.request_action",
                       "PatchEditorPanel.on_text_area_changed"})]}
    for stem, text in graphs.items():
        flow = stem.replace("graph-", "")
        outs.append(render(text, f"{flow} · high level", common, level="high", out=f"{flow}.high.svg"))
        for part, only in split.get(stem, [("low", None)]):
            outs.append(render(text, f"{flow} · {part.replace('-', ' ')}", common, only=only, level="low", out=f"{flow}.{part}.svg"))
    # overview: status from the extractor and the example markers (review view)
    marks = json.loads((HERE.parent / "extract" / "marks.json").read_text(encoding="utf-8"))
    missing = {m["name"] for m in marks["missing"]}
    ext = json.loads((HERE.parent / "extract" / "extract.json").read_text(encoding="utf-8"))
    sig = {f["where"].split(":")[0] for f in ext["findings"] if f["kind"] in ("input_missing_in_code", "input_type_mismatch")}
    drift_nodes = set()
    for f in ext["findings"]:
        if f["kind"] == "input_missing_in_code":
            drift_nodes.add(re.search(r"of `([^`]+)`", f["msg"]).group(1))
    status = {}
    for name, n in all_nodes.items():
        if name in missing:
            status[name] = "NEW"
        elif name in drift_nodes or any("synthetic" in e[:60] for e in n["examples"]):
            status[name] = "CHANGED"
        else:
            status[name] = "SHIPPED"
    (HERE / "status.json").write_text(json.dumps(status, indent=1), encoding="utf-8")
    outs.append(render_overview(graphs, status, out="overview.svg"))
    print("\n".join(outs))
    counts = {}
    for s in status.values():
        counts[s] = counts.get(s, 0) + 1
    print(counts)


if __name__ == "__main__":
    main()
