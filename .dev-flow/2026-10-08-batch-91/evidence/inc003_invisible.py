"""inc-003 derivation — AT-043's nodes and the token-invisible LIVE ids.

LLR-124.2's list is DERIVED with the shared library (``tools/id_registry.py``),
never hand-copied: a LIVE registry id is token-invisible when its dash-form
token (the entry's verbatim ``id``) does not occur in ANY file its ``nodes``
name. Run from the repo root:

    python .dev-flow/2026-10-08-batch-91/evidence/inc003_invisible.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tools.id_registry import (  # noqa: E402
    derive_named_nodes,
    iter_tokens,
    load_registry,
    read_text,
    registry_path,
    requirements_path,
    scanned_test_files,
)


def main() -> None:
    registry = load_registry(registry_path(ROOT))
    files = scanned_test_files(ROOT)

    # --- AT-043 (key AT-43): the nodes derive_named_nodes binds to it, with
    # the same `attested` set the guard uses (every cited key + every
    # registered key) so the digits_digits disambiguation reads identically.
    attested = set(registry.by_key())
    for path in files:
        for token, _ in iter_tokens(read_text(path)):
            if token.governed and token.key is not None:
                attested.add(token.key)
    for token, _ in iter_tokens(read_text(requirements_path(ROOT))):
        if token.governed and token.key is not None:
            attested.add(token.key)
    named = derive_named_nodes(files, ROOT, attested=attested)
    print("AT-43 derived nodes:", sorted(named.get("AT-43", set())))
    at43_entries = [e for e in registry.entries if e.key == "AT-43"]
    for e in at43_entries:
        print(f"  registry entry id={e.id!r} status={e.status} nodes={sorted(e.nodes)}")

    # --- The token-invisible LIVE ids. Token-exact, not substring: a plain
    # grep reads "TC-041.1" inside "TC-041.10" and "TC-062" inside "TC-062.a",
    # which is the disagreement the registry exists to close — occurrence is
    # judged by the library's own maximal-munch TOKEN_RE. Measured against the
    # pre-increment tree this lists exactly 44 ids (the survey's figure).
    cache: dict[str, set[str]] = {}

    def tokens_of(rel: str) -> set[str]:
        if rel not in cache:
            cache[rel] = {t.raw for t, _ in iter_tokens(read_text(ROOT / rel))}
        return cache[rel]

    invisible = []
    for entry in registry.entries:
        if entry.status != "LIVE":
            continue
        named_files = sorted({ref.split("::", 1)[0] for ref in entry.nodes})
        if not any(entry.id in tokens_of(rel) for rel in named_files):
            invisible.append((entry.id, named_files, sorted(entry.nodes)))

    print(f"\ntoken-invisible LIVE ids: {len(invisible)}")
    for ident, named_files, nodes in invisible:
        print(f"{ident} -> {', '.join(named_files)}")
        for node in nodes:
            print(f"    {node}")


if __name__ == "__main__":
    main()
