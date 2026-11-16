from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "codewire" / "graph-app.md").read_text(encoding="utf-8")
clip = (ROOT / "codewire" / "graph-clipboard.md").read_text(encoding="utf-8")


def between(text: str, start: str, end: str | None) -> str:
    head = text.split(f"## {start}", 1)
    if len(head) != 2:
        raise ValueError(f"missing section {start}")
    if end is None:
        return head[1]
    body = head[1].split(f"## {end}", 1)
    if len(body) != 2:
        raise ValueError(f"missing section {end}")
    return body[0]


app_pre = app.split("## Nodes", 1)[0]
app_pre = app_pre.replace("## 1. Delta, ownership and pinned interfaces", "### Delta, ownership and pinned interfaces")
app_pre = app_pre.replace("## 2. Baseline and real callers (static re-check)", "### Baseline and real callers (static re-check)")
clip_pre = clip.split("## Nodes", 1)[0].splitlines()
clip_pre[0] = "### Group B — os_clipboard_input.py"
app_nodes = between(app, "Nodes", "Entities")
app_node_blocks = re.split(r"\n\s*\n", app_nodes)
duplicate_tail = [
    block for block in app_node_blocks
    if (block.strip().splitlines() or [""])[0].strip() == "_mirror_and_write_os_clipboard"
]
if len(duplicate_tail) != 1:
    raise ValueError("expected one group-A tail context block")
app_nodes = "\n\n".join(
    block for block in app_node_blocks
    if (block.strip().splitlines() or [""])[0].strip() != "_mirror_and_write_os_clipboard"
)
clip_nodes = between(clip, "Nodes", "Edges")
app_entities = between(app, "Entities", "Acceptance examples (downstream, no additional nodes)")
app_acceptance = between(app, "Acceptance examples (downstream, no additional nodes)", "Findings")
app_findings = between(app, "Findings", None)
clip_edges = between(clip, "Edges", None)

parts = [
    app_pre,
    "\n".join(clip_pre) + "\n",
    "### Integrated node census\n\n24 unique function nodes: 12 implementation (10 app + 2 clipboard) and 12 context (6 app + 6 clipboard). The group-A tail context block is omitted because group B owns the changed node of the same name; Code-Wire's first-node-wins merge must not hide that delta.\n",
    "### Acceptance examples (downstream, no additional nodes)\n" + app_acceptance,
    "## Nodes\n" + app_nodes + "\n" + clip_nodes,
    "## Entities\n" + app_entities,
    "## Edges\n" + clip_edges,
    "## Findings\n" + app_findings,
]
result = "\n".join(parts)
result = result.replace("# Code-Wire graph — Inc 1b, group A (`app.py`), batch-103", "# Code-Wire graph — Inc 1b, batch-103", 1)
for heading in re.findall(r"^## (.+)$", result, re.MULTILINE):
    if heading not in {"Nodes", "Entities", "Edges", "Findings"}:
        raise ValueError(f"unreadable level-2 section: {heading}")
for stale in ("Nothing is selected, so Ctrl+C asks to quit", "O-1=A", "q3_body=A", "q4_q=A"):
    if stale in result:
        raise ValueError(f"stale G2 decision: {stale}")
(ROOT / "codewire" / "graph-inc1b.md").write_text(result, encoding="utf-8")
print(f"wrote graph-inc1b.md: {len(result.splitlines())} lines, {len(result.encode('utf-8'))} bytes")
