"""Batch-91 registry hygiene — AT-286.

HLR-124's acceptance: every LIVE registry id greps to its verifier, and AT-043
is one thing in the registry. Three arms:

(a) every LIVE entry's dash-form token occurs — as a token, per the library's
    maximal-munch TOKEN_RE, not as a substring — in at least one file its
    ``nodes`` name. Substring matching is exactly the disagreement the registry
    exists to close (``TC-041.1`` rides inside ``TC-041.10``, ``TC-062`` inside
    ``TC-062.a``); the token reading is the one that reproduced the survey's
    44 token-invisible ids, all adopted in this increment (LLR-124.2).
(b) AT-043's entry exists and carries a status the grammar accepts
    (LLR-124.1 — resolved LIVE: the declaration in REQUIREMENTS.md's batch-29
    US-043 update describes shipped behavior the verifier pins).
(c) the cross-artifact census: no id declared in REQUIREMENTS.md is absent
    from the registry — every governed token cited there has a registry entry
    under its normalized key, in some status.

The generic guard (``tests/test_id_registry.py``) enforces the rules over the
whole corpus; this module is the batch's own acceptance that the hygiene
landed, stated over the shipped surface (the registry file itself).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set

from tools.id_registry import (
    STATUSES,
    iter_tokens,
    load_registry,
    read_text,
    registry_path,
    repo_root,
    requirements_path,
)

ROOT = repo_root(Path(__file__))


def test_at286_every_live_id_token_occurs_in_its_nodes_file() -> None:
    """AT-286 (a) — every LIVE id's dash token occurs in a file its nodes name."""
    registry = load_registry(registry_path(ROOT))
    tokens_cache: Dict[str, Set[str]] = {}
    problems: List[str] = []
    for entry in registry.entries:
        if entry.status != "LIVE":
            continue
        named_files = sorted({ref.split("::", 1)[0] for ref in entry.nodes})
        for rel in named_files:
            if rel not in tokens_cache:
                path = ROOT / rel
                tokens_cache[rel] = (
                    {t.raw for t, _ in iter_tokens(read_text(path))}
                    if path.is_file()
                    else set()
                )
        if not any(entry.id in tokens_cache[rel] for rel in named_files):
            problems.append(
                f"{entry.id} is LIVE but its dash token occurs in none of {named_files}"
            )
    assert not problems, "token-invisible LIVE ids:\n  - " + "\n  - ".join(problems)


def test_at286_at043_is_resolved_with_a_grammar_valid_status() -> None:
    """AT-286 (b) — AT-043's entry exists with a status the grammar accepts."""
    registry = load_registry(registry_path(ROOT))
    entries = [e for e in registry.entries if e.id == "AT-043"]
    assert len(entries) == 1, (
        f"AT-043 must be one thing in the registry; found {len(entries)} entries"
    )
    assert entries[0].status in STATUSES, (
        f"AT-043's status {entries[0].status!r} is not one of {STATUSES}"
    )


def test_at286_no_declared_id_is_absent_from_the_registry() -> None:
    """AT-286 (c) — the REQUIREMENTS.md <-> registry cross-artifact census."""
    registry = load_registry(registry_path(ROOT))
    known = set(registry.by_key())
    problems: List[str] = []
    for token, line in iter_tokens(read_text(requirements_path(ROOT))):
        if not token.governed or token.key is None:
            continue
        if token.key not in known:
            problems.append(f"{token.raw} declared at REQUIREMENTS.md:{line} is not registered")
    assert not problems, "declared-but-unregistered ids:\n  - " + "\n  - ".join(
        sorted(set(problems))
    )
