"""Batch-91 foundation adoption completeness — AT-284.

HLR-122's acceptance: the foundation's behaviors trace id -> statement ->
verifier. This module is the batch's own guard over its reserved range,
TC-617 through TC-648 (LLR-122.1..122.5): every one of those ids must be
LIVE in ``AT-TC-REGISTRY.jsonl`` with a non-empty ``nodes`` list, and every
named node must exist on disk — a node that does not exist is a lie the
registry cannot carry.

The generic registry guard (``tests/test_id_registry.py`` G2) already checks
every LIVE entry's nodes; this module adds the batch-scoped completeness
direction: no TC in the batch's adopted range may be left RESERVED, dropped,
or bound to nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set

from tools.id_registry import defined_names, load_registry, read_text, registry_path, repo_root

ROOT = repo_root(Path(__file__))

#: The batch-91 foundation-adoption range (LLR-122.1..122.5). TC-649/650 stay
#: RESERVED for the batch's later increments and are deliberately out of scope.
BATCH91_TC_STEMS = range(617, 649)


def _batch91_entries():
    registry = load_registry(registry_path(ROOT))
    by_key = registry.by_key()
    return {f"TC-{stem}": by_key.get(f"TC-{stem}") for stem in BATCH91_TC_STEMS}


def test_at284_every_batch91_tc_is_live_with_nodes() -> None:
    """AT-284 — every adopted TC in the batch's range is LIVE with nodes."""
    problems: List[str] = []
    for key, entry in sorted(_batch91_entries().items()):
        if entry is None:
            problems.append(f"{key} is not in the registry at all")
        elif entry.status != "LIVE":
            problems.append(f"{key} is {entry.status}, not LIVE — the adoption is incomplete")
        elif not entry.nodes:
            problems.append(f"{key} is LIVE with an empty 'nodes' list")
    assert not problems, "batch-91 adoption incomplete:\n  - " + "\n  - ".join(problems)


def test_at284_every_named_node_exists_on_disk() -> None:
    """AT-284 — every node named by a batch-91 LIVE entry exists on disk."""
    defined_cache: Dict[str, Set[str]] = {}
    problems: List[str] = []
    for key, entry in sorted(_batch91_entries().items()):
        if entry is None or entry.status != "LIVE":
            continue  # the sibling test names this offender
        for ref in entry.nodes:
            rel, _, name = ref.partition("::")
            path = ROOT / rel
            if not path.is_file():
                problems.append(f"{key} names {ref!r} but {rel} is not a file")
                continue
            if rel not in defined_cache:
                defined_cache[rel] = defined_names(read_text(path))
            if name not in defined_cache[rel]:
                problems.append(f"{key} names {ref!r} but {name!r} is not defined in {rel}")
    assert not problems, "batch-91 nodes missing on disk:\n  - " + "\n  - ".join(problems)
