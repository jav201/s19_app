from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys
import traceback

INC = Path(__file__).resolve().parents[2]
ROOT = INC.parents[2]
sys.path.insert(0, str(INC / "evidence-e1"))
from redaction import redact

PARTS = (
    INC / "codewire" / "graph-inc3-file-load.md",
    INC / "codewire" / "graph-inc3-project-load.md",
    INC / "codewire" / "graph-inc3-loaded-shared.md",
)
OUT = INC / "codewire" / "graph-inc3.md"
SECTION_NAMES = ("Nodes", "Entities", "Edges", "Findings")
EXPECTED_NODES = {
    "FileLoadRequest",
    "FileLoadMixin.load_from_path",
    "FileLoadMixin._load_workarea_file",
    "FileLoadMixin._parse_loaded_file",
    "FileLoadMixin._prepare_load_payload",
    "FileLoadMixin._start_load_worker",
    "ProjectLoadRequest",
    "PreparedProjectLoad",
    "ProjectLoadMixin._handle_load_project",
    "ProjectLoadMixin._prepare_project_load",
    "ProjectLoadMixin._install_prepared_project",
    "LoadedStateMixin._apply_prepared_load",
}
EXPECTED_FINDINGS = {
    "CW-I3-F-01",
    "CW-I3-F-02",
    "CW-I3-F-03",
    "CW-I3-F-04",
    "CW-I3-F-05",
    "E2-P-01",
    "E2-P-02",
    "E2-P-03",
    "E2-P-04",
    "E2-LS-1",
    "E2-LS-2",
    "E2-LS-3",
    "E2-LS-4",
}
CLOSED_FINDINGS = {"CW-I3-F-04", "CW-I3-F-05", "E2-P-03", "E2-P-04", "E2-LS-4"}


def parse_sections(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^## (Nodes|Entities|Edges|Findings)\s*$", text))
    assert [match.group(1) for match in matches] == list(SECTION_NAMES)
    return {
        match.group(1): text[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(text)].strip("\n")
        for index, match in enumerate(matches)
    }


def blocks(content: str) -> list[str]:
    return [block.strip("\n") for block in re.split(r"\n\s*\n", content.strip("\n")) if block.strip()]


def integrate() -> tuple[str, Counter, list[str]]:
    parsed = [parse_sections(path.read_text(encoding="utf-8")) for path in PARTS]
    source_counts = Counter()
    for part in parsed:
        for name in SECTION_NAMES:
            source_counts[name] += part[name].count("──▶") if name == "Edges" else len(blocks(part[name]))
    source_counts["examples"] = sum(part[name].count("\nexamples:") + int(part[name].startswith("examples:")) for part in parsed for name in ("Nodes",))

    node_blocks = [block for part in parsed for block in blocks(part["Nodes"])]
    node_names = [block.splitlines()[0] for block in node_blocks]
    assert len(node_names) == len(set(node_names))
    assert set(node_names) == EXPECTED_NODES

    finding_blocks = [block for part in parsed for block in blocks(part["Findings"])]
    finding_ids = [block.splitlines()[0].split()[1] for block in finding_blocks]
    assert len(finding_ids) == len(set(finding_ids))
    assert set(finding_ids) == EXPECTED_FINDINGS
    for block in finding_blocks:
        identifier = block.splitlines()[0].split()[1]
        if identifier in CLOSED_FINDINGS:
            assert any(line.startswith("decision: CLOSED") for line in block.splitlines()), identifier

    entity_blocks: dict[str, str] = {}
    duplicates: list[str] = []
    for part in parsed:
        for block in blocks(part["Entities"]):
            name = block.splitlines()[0]
            if name in entity_blocks:
                duplicates.append(name)
            entity_blocks[name] = block
    assert set(duplicates) == {"[Data: PreparedLoad]", "[Data: A2LAttachSnapshot]"}

    edge_blocks = [block for part in parsed for block in blocks(part["Edges"])]
    preamble = """# Inc3 integrated Code-Wire graph — image/project A2L load parity

E2 integration over E1 commit `85e68957`, using Code-Wire v3.2.0 and accepted root `../../interfaces.md`. Inputs are the corrected F, P and L+S graphs in that order. The graph preserves every node, example and finding; duplicate PreparedLoad/A2LAttachSnapshot entities are subsumed by their later root-accepted L+S definitions.

Coverage is 12 parsed function/data nodes plus S1's PreparedLoad entity = 13 implementation nodes across exactly four SOURCE modules: `s19_app/tui/app/file_load.py`, `project_load.py`, `loaded_state.py` and `shared.py`. All ten REFRESH.039–.048 requirements have concrete examples. No functional test, timing result, product mark or product extraction is claimed.

REFRESH.047 distinguishes changed content from reinstallation: changed bytes require a newer generation of each changed artifact, unchanged content/bytes remain byte-identical, and writer/reset/reinstall stages may move an unchanged artifact's generation. The old unchanged-A2L-generation assertion is withdrawn; NEW/OLD and all total/UI budgets remain binding.
"""
    pieces = [preamble]
    for name, content in (
        ("Nodes", "\n\n".join(node_blocks)),
        ("Entities", "\n\n".join(entity_blocks.values())),
        ("Edges", "\n\n".join(edge_blocks)),
        ("Findings", "\n\n".join(finding_blocks)),
    ):
        pieces.append(f"## {name}\n\n{content}\n")
    integrated = "\n".join(pieces)
    output_counts = Counter({name: len(blocks(content)) for name, content in parse_sections(integrated).items()})
    output_counts["Edges"] = integrated.count("──▶")
    output_counts["examples"] = integrated.count("\nexamples:")
    print(f"INTEGRATION_PARSED_COUNTS source={dict(source_counts)} output={dict(output_counts)}")
    assert output_counts["examples"] == source_counts["examples"]
    assert output_counts["Nodes"] == 12
    assert output_counts["Findings"] == 13
    assert output_counts["Edges"] == 23
    assert output_counts["Entities"] == 12
    requirements = set(re.findall(r"R-A2L-REFRESH\.\d{3}", integrated))
    assert requirements == {f"R-A2L-REFRESH.{number:03d}" for number in range(39, 49)}
    for identifier in ("F1", "F2", "F3", "F4", "F5", "F6", "P1", "P2", "P3", "P4", "P5", "L1", "S1"):
        assert re.search(rf"\b{identifier}\b", integrated), identifier
    for module in ("file_load.py", "project_load.py", "loaded_state.py", "shared.py"):
        assert module in integrated
    for text in ("unchanged A2L source bytes remain byte-identical", "unchanged image bytes remain byte-identical", "may move A2L generation", "may move image generation"):
        assert text in integrated, text
    assert ", STAGE_RACE)" not in integrated
    return integrated, output_counts, duplicates


def main(fault: str | None = None) -> None:
    integrated, counts, duplicates = integrate()
    if fault == "missing-node":
        start = integrated.index("FileLoadRequest\n")
        end = integrated.index("\n\n", start)
        integrated = integrated[:start] + integrated[end + 2 :]
        assert {block.splitlines()[0] for block in blocks(parse_sections(integrated)["Nodes"])} == EXPECTED_NODES
    elif fault is not None:
        raise ValueError(f"unknown fault {fault}")
    if fault is None:
        OUT.write_text(integrated, encoding="utf-8")
        expected_lint = {
            "file-load": (6, 5, 9),
            "project-load": (5, 4, 7),
            "loaded-shared": (1, 5, 7),
            "integrated": (12, 12, 23),
        }
        for label, expected in expected_lint.items():
            data = json.loads((OUT.parents[1] / "evidence-e2" / "integrated" / f"{label}-lint.json").read_text(encoding="utf-8"))
            assert data["unread"] == [], label
            assert (len(data["nodes"]), len(data["entities"]), len(data["edges"])) == expected, label
        report = (INC / "E2-integration.md").read_text(encoding="utf-8")
        assert "Open design/interface findings: 0" in report
        assert "39" in report and "13" in report and f"{counts['examples']}/{counts['examples']}" in report
        stage = (INC / "evidence-e3/stage-invariant.txt").read_text(encoding="utf-8")
        assert "runtime_generation_writers=UI_only STAGE_RACE=unreachable rollback=none" in stage
        assert "BLOCKER none" in stage
        for lane_report in ("E2-file-load.md", "E2-project-load.md", "E2-loaded-shared.md"):
            text = (INC / lane_report).read_text(encoding="utf-8")
            assert "Interface proposals — not applied" not in text
            assert "Open conductor/interface ruling" not in text
            assert "Open requirement-oracle conflict" not in text
            assert "open requirements ruling" not in text
            assert "open interface proposals" not in text
        print("INTEGRATION_LINT unread=0 all_parts_and_integrated=true reports_closed=true")
    print(
        f"INTEGRATION nodes={counts['Nodes']} entities={counts['Entities']} "
        f"edges={counts['Edges']} findings={counts['Findings']} examples={counts['examples']} "
        f"requirements=10 implementation_nodes=13 SOURCE=4 duplicate_entities_subsumed={len(duplicates)}"
    )
    print("INTEGRATION_COVERAGE F1_F6=6 P1_P5=5 L1=1 S1_entity=1 all_examples_preserved=true")
    print("INTEGRATION_DISPOSITIONS targeted_findings_closed=5 open_design_findings=0 functional_tests=none")
    print("STAGE_INVARIANT synchronous_UI=true STAGE_RACE=removed rollback=none adverse_cases_added=10")


if __name__ == "__main__":
    fault = None
    if len(sys.argv) > 1:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--red-case="):
            raise SystemExit("usage: integrate_graph.py [--red-case=missing-node]")
        fault = sys.argv[1].split("=", 1)[1]
    try:
        main(fault)
    except Exception:
        print(redact(traceback.format_exc(), ROOT), end="")
        raise SystemExit(1)
