from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import re
import sys

EXPECTED_COUNTS = {
    "029": 3,
    "030": 3,
    "031": 3,
    "032": 2,
    "033": 6,
    "034": 4,
    "035": 3,
    "036": 2,
    "037": 5,
    "038": 3,
}
EXPECTED_MODULES = {
    "FileLoadMixin._start_a2l_load": "s19_app/tui/app/file_load.py",
    "FileLoadMixin._a2l_attach_worker": "s19_app/tui/app/file_load.py",
    "FileLoadMixin._prepare_a2l_attach_snapshot": "s19_app/tui/app/file_load.py",
    "FileLoadMixin._install_attached_a2l": "s19_app/tui/app/file_load.py",
    "A2LParameterPicker.set_parameters": "s19_app/tui/a2l_parameter_picker.py",
    "CheckEditorPanel.set_a2l_parameters": "s19_app/tui/screens_directionb/check_editor.py",
    "A2lPickerMixin.set_a2l_parameters": "s19_app/tui/screens_directionb/patch_editor/a2l_picker.py",
}
EXPECTED_A3_INPUTS = [
    ("self", "FileLoadMixin"),
    ("a2l_path", "Path"),
    ("a2l_data", "dict"),
    ("image_mem_map", "Optional[Mapping[int, int]]"),
    ("expected_a2l_generation", "int"),
    ("expected_image_generation", "int"),
]
EXPECTED_ENTITIES = {
    "[Data: A2L busy run]",
    "[I/O: workarea A2L copy]",
    "[Data: Current A2L]",
    "[Data: A2L view caches]",
    "[Data: Picker population]",
    "[Data: Check picker population]",
    "[Data: Patch picker population]",
    "[Data: A2L attach request]",
    "[Data: A2L attach result]",
    "[Data: A2L attach snapshot]",
    "[Data: A2L picker snapshot]",
    "[Data: Accepted A2L picker snapshots]",
}
EXAMPLE_ID = re.compile(r"^\((R-A2L-REFRESH\.(\d{3})/(\d+))(?:,|\))")


def validate(data: dict) -> list[str]:
    errors: list[str] = []
    if data.get("unread") != []:
        errors.append("unread is not empty")

    nodes = {node["name"]: node for node in data.get("nodes", [])}
    if set(nodes) != set(EXPECTED_MODULES):
        errors.append("node set differs from A1-A4/P1/C1/PA1")
    for name, module in EXPECTED_MODULES.items():
        if nodes.get(name, {}).get("module") != module:
            errors.append(f"wrong module for {name}")
    if len(set(EXPECTED_MODULES.values())) != 4:
        errors.append("source budget oracle is not four files")
    a3 = nodes.get("FileLoadMixin._prepare_a2l_attach_snapshot", {})
    a3_inputs = [(item["name"], item["type"]) for item in a3.get("in", [])]
    if a3_inputs != EXPECTED_A3_INPUTS or any(
        item.get("default") is not None for item in a3.get("in", [])
    ):
        errors.append("A3 signature is not the route-neutral explicit-input contract")

    entities = {entity["name"]: entity for entity in data.get("entities", [])}
    if set(entities) != EXPECTED_ENTITIES:
        errors.append("entity set differs from the seven baseline and five hand-off entities")

    expected_ids = {
        f"R-A2L-REFRESH.{number}/{alternative}"
        for number, count in EXPECTED_COUNTS.items()
        for alternative in range(1, count + 1)
    }
    example_links = []
    for node in data.get("nodes", []):
        for line in node.get("examples", []):
            match = EXAMPLE_ID.match(line)
            if match:
                example_links.append(match.group(1))
    actual_ids = set(example_links)
    for missing in sorted(expected_ids - actual_ids):
        errors.append(f"missing example {missing}")
    for extra in sorted(actual_ids - expected_ids):
        errors.append(f"unexpected example {extra}")
    if len(example_links) != 45:
        errors.append(f"example link count {len(example_links)} != 45")

    active_reqs = {f"R-A2L-REFRESH.{number}" for number in EXPECTED_COUNTS}
    node_reqs = {req for node in data.get("nodes", []) for req in node.get("reqs", [])}
    for missing in sorted(active_reqs - node_reqs):
        errors.append(f"missing requirement owner {missing}")

    for name in ("CheckEditorPanel.set_a2l_parameters", "A2lPickerMixin.set_a2l_parameters"):
        function = nodes.get(name, {}).get("func", "")
        if "unmounted" not in function or "a2l_data None" not in function or "preserves its identity" not in function:
            errors.append(f"headless adapter guard missing from {name}")
    for node in data.get("nodes", []):
        for line in node.get("examples", []):
            if line.startswith("(R-A2L-REFRESH.038/") and "Workarea Files" not in line:
                errors.append(f"Workarea Files failure behavior missing from {line.split(')')[0]})")
    workarea = entities.get("[I/O: workarea A2L copy]", {})
    workarea_sequences = {item["event"]: item["steps"] for item in workarea.get("sequence", [])}
    failure_steps = workarea_sequences.get("preparation_failure", [])
    if [step["node"] for step in failure_steps] != [
        "FileLoadMixin._a2l_attach_worker",
        "FileLoadMixin._on_a2l_attach_failed",
    ]:
        errors.append("Workarea Files preparation_failure sequence missing")

    current = entities.get("[Data: Current A2L]", {})
    sequences = {item["event"]: item["steps"] for item in current.get("sequence", [])}
    accepted = sequences.get("accepted", [])
    expected_accepted = [
        "FileLoadMixin._install_attached_a2l",
        "FileLoadMixin._install_attached_a2l",
        "A2lViewMixin._refresh_a2l_dependent_views",
        "ShellMixin.end_busy",
    ]
    if [step["node"] for step in accepted] != expected_accepted:
        errors.append("accepted sequence is not preflight-install-refresh-outcome")
    elif not accepted[0].get("early") or not accepted[1].get("wins"):
        errors.append("accepted sequence does not distinguish preflight read from winning install")
    for event in ("stale_a2l", "stale_image"):
        steps = sequences.get(event, [])
        if [step["node"] for step in steps] != [
            "FileLoadMixin._install_attached_a2l",
            "ShellMixin.end_busy",
        ] or any(step.get("wins") for step in steps):
            errors.append(f"{event} does not reject before install")
    return errors


def self_test(data: dict) -> list[str]:
    outcomes = []
    unread = deepcopy(data)
    unread["unread"] = [{"line": 1, "text": "bad"}]
    outcomes.append("unread RED" if validate(unread) else "unread SURVIVED")

    missing = deepcopy(data)
    for node in missing["nodes"]:
        node["examples"] = [
            line for line in node["examples"] if not line.startswith("(R-A2L-REFRESH.029/1)")
        ]
    outcomes.append(
        "missing-alternative RED"
        if any("R-A2L-REFRESH.029/1" in error for error in validate(missing))
        else "missing-alternative SURVIVED"
    )

    wrong_sequence = deepcopy(data)
    for entity in wrong_sequence["entities"]:
        if entity["name"] == "[Data: Current A2L]":
            for item in entity["sequence"]:
                if item["event"] == "accepted":
                    item["steps"][2], item["steps"][3] = item["steps"][3], item["steps"][2]
    outcomes.append(
        "outcome-before-refresh RED"
        if any("accepted sequence" in error for error in validate(wrong_sequence))
        else "outcome-before-refresh SURVIVED"
    )
    route_bound = deepcopy(data)
    for node in route_bound["nodes"]:
        if node["name"] == "FileLoadMixin._prepare_a2l_attach_snapshot":
            node["in"][1] = {
                "kind": "value",
                "type": "A2LAttachRequest",
                "name": "request",
                "default": None,
            }
    outcomes.append(
        "route-bound-A3 RED"
        if any("A3 signature" in error for error in validate(route_bound))
        else "route-bound-A3 SURVIVED"
    )

    headless = deepcopy(data)
    for node in headless["nodes"]:
        if node["name"] == "CheckEditorPanel.set_a2l_parameters":
            node["func"] = node["func"].replace("an unmounted panel", "a mounted panel")
    outcomes.append(
        "unmounted-guard RED"
        if any("headless adapter guard" in error for error in validate(headless))
        else "unmounted-guard SURVIVED"
    )

    failure = deepcopy(data)
    for entity in failure["entities"]:
        if entity["name"] == "[I/O: workarea A2L copy]":
            entity["sequence"] = [
                item for item in entity["sequence"] if item["event"] != "preparation_failure"
            ]
    outcomes.append(
        "failure-refresh RED"
        if any("Workarea Files preparation_failure" in error for error in validate(failure))
        else "failure-refresh SURVIVED"
    )
    return outcomes


def main() -> int:
    source = Path(__file__).with_name("codewire-lint.json")
    data = json.loads(source.read_text(encoding="utf-8"))
    errors = validate(data)
    example_ids = [
        match.group(1)
        for node in data["nodes"]
        for line in node["examples"]
        if (match := EXAMPLE_ID.match(line))
    ]
    unique_counts = Counter(example_id.split("/")[0].rsplit(".", 1)[1] for example_id in set(example_ids))
    if errors:
        for error in errors:
            print(f"RED {error}")
    else:
        print(
            "PASS nodes=7 entities=12 source_files=4 requirements=10 "
            f"alternatives={sum(EXPECTED_COUNTS.values())} example_links=45 "
            "route_neutral_a3=1 unread=0"
        )
        print(
            "alternative_counts "
            + " ".join(f"{key}={unique_counts[key]}" for key in sorted(EXPECTED_COUNTS))
        )
    if "--self-test" in sys.argv:
        outcomes = self_test(data)
        for outcome in outcomes:
            print(outcome)
        if any(not outcome.endswith("RED") for outcome in outcomes):
            errors.append("self-test survivor")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
