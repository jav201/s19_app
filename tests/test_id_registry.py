"""
AT/TC id registry guard — ``AT-TC-REGISTRY.jsonl`` vs the repository.

The registry is the single authority for AT/TC id allocation
(`.dev-flow/AT-TC-REGISTRY-SPEC.md`). A document that claims that authority and
is not enforced is worse than no document: it drifts silently while everyone
believes it. This module is the enforcement — seven rules, G1..G7, each of which
fails **loud** and **names every offender with its locus** rather than asserting
a count (spec §5.4).

Rules, and the failure each one closes::

    G1  node -> registry      an id on a test node that nobody registered
    G2  registry -> node      a LIVE entry naming a node that does not exist
    G3  citation -> registry  an id in circulation the registry never saw
    G4  citation -> liveness  a phantom: REQUIREMENTS.md citing a dead verifier
    G5  grammar               a NEW legacy-shaped token
    G6  uniqueness            AT-065b and AT-65b both allocated
    G7  monotonicity          an id minted above the high-water mark

G1+G2 alone are what the backlog item asked for, and they are **not enough**:
the six phantoms the item presents as its own headline evidence are
``REQUIREMENTS.md`` <-> ``tests/`` divergences, and a registry<->``tests/``
guard never looks at ``REQUIREMENTS.md``. G3 and G4 are the minimum that
catches the cited evidence (spec §5.2).

Every rule is a plain function returning a list of problem strings, so the same
code path is used twice: the ``TC-6xx`` tests assert it is empty on the real
tree, and ``AT-281`` feeds each rule a deliberately broken input and asserts it
is **not** empty. A guard that has never been observed to fail is
indistinguishable from one that cannot fail.

This module carries **no** ``slow`` marker: it must run in the PR lane, because
PRs are where ids get minted (spec §7.4).
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import pytest

from tools.id_registry import (
    CONFORMING_BODY_RE,
    Registry,
    RegistryEntry,
    defined_names,
    derive_named_nodes,
    iter_tokens,
    load_registry,
    normalize,
    read_text,
    registry_path,
    repo_root,
    requirements_path,
    scanned_test_files,
)

# ---------------------------------------------------------------------------
# §7.3 — the CI budget as an executable threshold.
#
# A wall-clock assertion would be flaky and would fail on unrelated PRs. This
# bounds the thing that actually drives cost: how many files the guard opens.
# Pointing the guard at `.dev-flow/` (865 files) or adding a directory moves
# this number immediately, so the threshold can genuinely go red.
# ---------------------------------------------------------------------------
EXPECTED_SCANNED_TEST_FILES = 152
"""Test modules scanned at the seed commit, including this one."""

EXPECTED_SCANNED_TOTAL = EXPECTED_SCANNED_TEST_FILES + 1  # + REQUIREMENTS.md

#: A citation of a non-LIVE id is legitimate only under one of these headings
#: (spec §5.3). The list is DATA, reviewable in the PR diff, not logic buried in
#: a rule. Its refutation trigger is declared in advance: if it ever needs more
#: than five anchors, G4's model of REQUIREMENTS.md is wrong and the rule should
#: be weakened to G3-only rather than grown.
MAX_EXEMPT_ANCHORS = 5

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")


# ---------------------------------------------------------------------------
# Corpus loading — done once, reused by every rule.
# ---------------------------------------------------------------------------


class _Corpus:
    """Everything the seven rules read, gathered in one pass."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.registry: Registry = load_registry(registry_path(root))
        self.by_key: Dict[str, RegistryEntry] = self.registry.by_key()

        self.test_files: List[Path] = scanned_test_files(root)
        self.test_sources: Dict[str, str] = {
            path.relative_to(root).as_posix(): read_text(path) for path in self.test_files
        }
        self.requirements: str = read_text(requirements_path(root))

        # Every governed citation, with where it was seen.
        self.test_citations: Dict[str, List[str]] = {}
        self.requirement_citations: Dict[str, List[Tuple[str, int]]] = {}
        self.nonconforming: Dict[str, List[str]] = {}

        for rel, text in self.test_sources.items():
            self._scan(text, rel, self.test_citations, None)
        self._scan(
            self.requirements, "REQUIREMENTS.md", None, self.requirement_citations
        )

        attested = set(self.test_citations) | set(self.requirement_citations)
        self.named_nodes: Dict[str, Set[str]] = derive_named_nodes(
            self.test_files, root, attested=attested | set(self.by_key)
        )
        self.defined: Dict[str, Set[str]] = {
            rel: defined_names(src) for rel, src in self.test_sources.items()
        }
        self.sections: Dict[int, str] = _heading_of_each_line(self.requirements)
        self.asserts_verifier: Dict[int, bool] = _validation_bullet_lines(self.requirements)

    def _scan(
        self,
        text: str,
        rel: str,
        into_simple: Optional[Dict[str, List[str]]],
        into_located: Optional[Dict[str, List[Tuple[str, int]]]],
    ) -> None:
        if "AT-" not in text and "TC-" not in text:
            return
        for token, line in iter_tokens(text):
            if not token.governed or token.key is None:
                continue
            if into_simple is not None:
                into_simple.setdefault(token.key, []).append(f"{rel}:{line}")
            if into_located is not None:
                into_located.setdefault(token.key, []).append((rel, line))
            if not token.conforming:
                self.nonconforming.setdefault(token.raw, []).append(f"{rel}:{line}")


def _heading_of_each_line(text: str) -> Dict[int, str]:
    """Map every 1-based line number to the nearest preceding markdown heading."""
    out: Dict[int, str] = {}
    current = ""
    for number, line in enumerate(text.splitlines(), start=1):
        match = _HEADING_RE.match(line)
        if match:
            current = match.group(2).strip()
        out[number] = current
    return out


_BULLET_RE = re.compile(r"^\s*[-*]\s+\**\s*(?P<label>[A-Za-z][A-Za-z /-]*)\s*\**\s*:")


def _validation_bullet_lines(text: str) -> Dict[int, bool]:
    """
    Summary:
        Map every 1-based line number to whether it lies inside a
        ``- Validation:`` bullet — the *verifier column* G4 polices.

    Args:
        text (str): The ``REQUIREMENTS.md`` contents.

    Returns:
        Dict[int, bool]: ``True`` for the bullet's own line and each of its
        continuation lines, up to the next bullet or blank line.

    Data Flow:
        - Walks the document once, tracking the label of the most recent
          ``- <Label>:`` bullet; a blank line closes the bullet.

    Dependencies:
        Used by:
            - g4_requirement_citations_are_live
    """
    out: Dict[int, bool] = {}
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        match = _BULLET_RE.match(line)
        if match:
            inside = match.group("label").strip().lower() == "validation"
        elif not line.strip():
            inside = False
        out[number] = inside
    return out


@pytest.fixture(scope="module")
def corpus() -> _Corpus:
    """The scanned corpus and the parsed registry, built once per module."""
    return _Corpus(repo_root(Path(__file__)))


# ---------------------------------------------------------------------------
# The seven rules. Each returns a list of human-locatable problem strings.
# ---------------------------------------------------------------------------


def g1_named_nodes_are_registered(corpus: _Corpus, registry: Registry) -> List[str]:
    """G1 — every id derivable from a test node name is registered."""
    known = set(registry.by_key())
    problems = []
    for key, refs in sorted(corpus.named_nodes.items()):
        if key not in known:
            problems.append(f"{key} carried by {sorted(refs)} is not in the registry")
    return problems


def g2_live_entries_have_nodes(corpus: _Corpus, registry: Registry) -> List[str]:
    """G2 — every LIVE entry's declared nodes exist.

    ``RESERVED`` / ``RETIRED`` / ``BURNED`` are exempt **by status, not by
    absence**: the exemption is a recorded decision, so a node that quietly
    vanishes still fails rather than being read as an intentional reservation.
    """
    problems = []
    for entry in registry.entries:
        if entry.status != "LIVE":
            continue
        if not entry.nodes:
            problems.append(f"{entry.id} is LIVE with an empty 'nodes' list")
            continue
        for ref in entry.nodes:
            rel, _, name = ref.partition("::")
            if rel not in corpus.defined:
                problems.append(f"{entry.id} names node {ref!r} but {rel} is not a scanned test file")
            elif name not in corpus.defined[rel]:
                problems.append(f"{entry.id} names node {ref!r} but {name!r} is not defined in {rel}")
    return problems


def g3_citations_are_registered(corpus: _Corpus, registry: Registry) -> List[str]:
    """G3 — every governed id cited in the scanned corpus is registered somehow."""
    known = set(registry.by_key())
    problems = []
    seen = dict(corpus.test_citations)
    for key, located in corpus.requirement_citations.items():
        seen.setdefault(key, []).extend(f"REQUIREMENTS.md:{line}" for _, line in located)
    for key, locations in sorted(seen.items()):
        if key not in known:
            problems.append(f"{key} is cited at {sorted(set(locations))[:3]} but is not registered")
    return problems


def g4_requirement_citations_are_live(corpus: _Corpus, registry: Registry) -> List[str]:
    """G4 — an id **asserted as a verifier** in ``REQUIREMENTS.md`` is LIVE,
    unless the citation sits under a declared exempt anchor.

    This is the rule that catches a phantom, and the only one that reads
    ``REQUIREMENTS.md``'s structure rather than just its tokens.

    RECORDED PREMISE CORRECTION (spec §5.3). The spec words G4 over *every*
    citation, escaped only by an exempt heading anchor. Implemented that way it
    fires on 28 citations at the seed commit, and inspection shows two different
    populations:

    * 17 sit in ``- Validation:`` bullets — the **verifier column**, a document
      actively advertising a test that does not exist. Those are the phantoms.
    * 11 sit in ``- Status:`` / ``**SUPERSEDED**`` prose that *already says the
      verifier was deleted*, e.g. line 3839's "``tests/test_tui_entropy_viewer.py``
      (AT-062a/b, TC-324/325) is deleted".

    Firing on the second population would force honest history to be stripped of
    its ids to stay green, which is a worse document. Escaping it via anchors is
    not available either: these notes live inside ordinary feature sections, so
    exempting their headings would exempt the live citations beside them — and
    the spec's own refutation trigger caps the anchor list at five.

    So G4 is scoped to the **verifier-asserting** line, which is what the defect
    actually is: §6.1 describes it as prose saying "is deleted" *"while the
    verifier column keeps citing the ids"*. The rule still catches every one of
    the phantoms the backlog item cites as evidence — all seven are in
    ``- Validation:`` bullets — and the anchor mechanism is retained on top.
    """
    by_key = registry.by_key()
    exempt = {str(a).strip().lstrip("#").strip() for a in registry.meta.get("g4_exempt_anchors", [])}
    problems = []
    for key, located in sorted(corpus.requirement_citations.items()):
        entry = by_key.get(key)
        if entry is None or entry.status == "LIVE":
            continue
        for _, line in located:
            if not corpus.asserts_verifier.get(line, False):
                continue
            heading = corpus.sections.get(line, "")
            if heading not in exempt:
                problems.append(
                    f"REQUIREMENTS.md:{line} asserts {entry.id} ({entry.status}) as a live "
                    f"verifier under heading {heading!r}, which is not a declared exempt anchor"
                )
    return problems


def g5_grammar_holds(corpus: _Corpus, registry: Registry) -> List[str]:
    """G5 — a governed token either parses per the grammar or is a registered
    ``conforming: false`` entry. Freezes the legacy mess at its current size."""
    legacy = {e.id for e in registry.entries if not e.conforming}
    legacy_keys = {e.key for e in registry.entries if not e.conforming}
    problems = []
    for raw, locations in sorted(corpus.nonconforming.items()):
        if raw in legacy:
            continue
        space, _, body = raw.partition("-")
        if normalize(space, body) in legacy_keys:
            continue
        problems.append(
            f"{raw} at {sorted(set(locations))[:3]} does not parse per the grammar and is "
            f"not a registered conforming:false entry"
        )
    return problems


def g6_keys_are_unique(corpus: _Corpus, registry: Registry) -> List[str]:
    """G6 — no two entries share a normalized key (zero-padding aliases)."""
    seen: Dict[str, str] = {}
    problems = []
    for entry in registry.entries:
        first = seen.get(entry.key)
        if first is not None:
            problems.append(f"{entry.id} and {first} normalize to the same key {entry.key!r}")
        else:
            seen[entry.key] = entry.id
    return problems


def g7_no_stem_exceeds_high_water(corpus: _Corpus, registry: Registry) -> List[str]:
    """G7 — no entry's stem exceeds the recorded high-water mark for its space."""
    declared = registry.meta.get("high_water", {})
    problems = []
    for space in ("AT", "TC"):
        mark = declared.get(space)
        if mark is None:
            problems.append(f"the registry _meta declares no high_water for {space}")
            continue
        for entry in registry.entries:
            if entry.space != space or not entry.conforming or entry.stem is None:
                continue
            if entry.stem > mark:
                problems.append(
                    f"{entry.id} has stem {entry.stem}, above the declared {space} "
                    f"high-water mark {mark} — minted out of band"
                )
    return problems


RULES = (
    ("G1", g1_named_nodes_are_registered),
    ("G2", g2_live_entries_have_nodes),
    ("G3", g3_citations_are_registered),
    ("G4", g4_requirement_citations_are_live),
    ("G5", g5_grammar_holds),
    ("G6", g6_keys_are_unique),
    ("G7", g7_no_stem_exceeds_high_water),
)


def _report(rule: str, problems: Sequence[str]) -> str:
    listed = "\n  - ".join(problems[:40])
    tail = f"\n  ... and {len(problems) - 40} more" if len(problems) > 40 else ""
    return f"{rule} failed with {len(problems)} offender(s):\n  - {listed}{tail}"


# ---------------------------------------------------------------------------
# G1..G7 on the real tree.
# ---------------------------------------------------------------------------


def test_tc600_g1_every_named_node_id_is_registered(corpus: _Corpus) -> None:
    """TC-600 / G1 — no test node carries an id the registry has never seen."""
    problems = g1_named_nodes_are_registered(corpus, corpus.registry)
    assert not problems, _report("G1 (node -> registry)", problems)


def test_tc601_g2_live_entries_name_existing_nodes(corpus: _Corpus) -> None:
    """TC-601 / G2 — every LIVE entry's nodes exist; non-LIVE is exempt by status."""
    problems = g2_live_entries_have_nodes(corpus, corpus.registry)
    assert not problems, _report("G2 (registry -> node)", problems)


def test_tc602_g3_every_citation_is_registered(corpus: _Corpus) -> None:
    """TC-602 / G3 — no id circulates in tests/ or REQUIREMENTS.md unregistered."""
    problems = g3_citations_are_registered(corpus, corpus.registry)
    assert not problems, _report("G3 (citation -> registry)", problems)


def test_tc603_g4_requirements_citations_are_live(corpus: _Corpus) -> None:
    """TC-603 / G4 — REQUIREMENTS.md does not advertise a dead verifier as live."""
    problems = g4_requirement_citations_are_live(corpus, corpus.registry)
    assert not problems, _report("G4 (citation -> liveness)", problems)


def test_tc604_g5_grammar_holds_or_is_registered_legacy(corpus: _Corpus) -> None:
    """TC-604 / G5 — no NEW legacy-shaped token enters the corpus."""
    problems = g5_grammar_holds(corpus, corpus.registry)
    assert not problems, _report("G5 (grammar)", problems)


def test_tc605_g6_normalized_keys_are_unique(corpus: _Corpus) -> None:
    """TC-605 / G6 — AT-065b and AT-65b cannot both be allocated."""
    problems = g6_keys_are_unique(corpus, corpus.registry)
    assert not problems, _report("G6 (uniqueness)", problems)


def test_tc606_g7_no_stem_exceeds_the_high_water_mark(corpus: _Corpus) -> None:
    """TC-606 / G7 — nothing is minted above the recorded high-water mark."""
    problems = g7_no_stem_exceeds_high_water(corpus, corpus.registry)
    assert not problems, _report("G7 (monotonicity)", problems)


# ---------------------------------------------------------------------------
# Cost bound, grammar unit-checks, file well-formedness.
# ---------------------------------------------------------------------------


def test_tc607_scanned_corpus_matches_the_declared_bound(corpus: _Corpus) -> None:
    """TC-607 — the guard's corpus is bounded by a declared, executable constant.

    Asserting *how many files the guard opens* is deterministic where a
    wall-clock budget would be flaky. Widening the scan — most obviously to
    ``.dev-flow/``, which would make the guard's verdict depend on batch prose —
    moves this count and turns the threshold red immediately.
    """
    actual = len(corpus.test_files)
    assert actual == EXPECTED_SCANNED_TEST_FILES, (
        f"the guard scanned {actual} test modules, not the declared "
        f"{EXPECTED_SCANNED_TEST_FILES}. If tests/ legitimately grew, bump "
        f"EXPECTED_SCANNED_TEST_FILES in the same PR so the bound stays a "
        f"decision rather than a rubber stamp."
    )
    assert EXPECTED_SCANNED_TOTAL == actual + 1
    # Compare REPO-RELATIVE parts: this checkout itself lives under a directory
    # named ``s19_app``, so an absolute-path test would always trip on it.
    relative = [p.relative_to(corpus.root).parts for p in corpus.test_files]
    assert all(parts[0] == "tests" for parts in relative), (
        "the guard's corpus must stay inside tests/ — spec §7.1"
    )
    for excluded in ("goldens", "__snapshots__", "_artifacts", "__pycache__"):
        assert not any(excluded in parts for parts in relative), (
            f"tests/{excluded}/ carries no ids and must stay out of the corpus — spec §7.1"
        )


def test_tc608_tokenizer_and_normalizer_edge_cases() -> None:
    """TC-608 — the attested tokenizer/normalizer edge cases resolve as specified.

    Every case below was observed in this repository before it was written down;
    the two node-name cases are the ones an earlier draft got wrong, which is why
    they are pinned rather than assumed.
    """
    assert normalize("AT", "065b") == normalize("AT", "65b") == "AT-65b"
    assert normalize("TC", "046.1") == normalize("TC", "46.1") == "TC-46.1"

    def toks(text: str) -> List[str]:
        return [t.raw for t, _ in iter_tokens(text)]

    # A range must yield its endpoints, not one malformed token.
    assert toks("see TC-001..TC-004") == ["TC-001", "TC-004"]
    # A sentence period is prose, not part of the id.
    assert toks("as required by AT-039e.") == ["AT-039e"]
    # A dotted stem survives; the trailing sentence period does not.
    assert toks("pinned at TC-078.4.") == ["TC-078.4"]
    # Legacy tails stay attached rather than silently truncating to TC-024.
    assert toks("legacy TC-024-color") == ["TC-024-color"]

    from tools.id_registry import classify

    assert classify("AT", "B64-04").governed is False, "batch-scoped ids are ungoverned"
    assert classify("AT", "NNN").governed is False, "prose placeholders are ungoverned"
    assert classify("TC", "024-color").conforming is False
    assert classify("TC", "1728").conforming is True, (
        "TC-1728 parses fine — it is excluded from allocation by its registry "
        "entry's conforming:false, not by the grammar"
    )


def test_tc609_registry_file_is_well_formed(corpus: _Corpus) -> None:
    """TC-609 — the authority is structurally sound and status-complete."""
    registry = corpus.registry
    assert registry.meta.get("schema") == 1
    assert registry.entries, "the registry is empty"

    anchors = registry.meta.get("g4_exempt_anchors", [])
    assert 0 < len(anchors) <= MAX_EXEMPT_ANCHORS, (
        f"G4 declares {len(anchors)} exempt anchors; the spec's refutation trigger "
        f"says that above {MAX_EXEMPT_ANCHORS} the rule's model of REQUIREMENTS.md "
        f"is wrong and G4 should be weakened to G3-only rather than grown"
    )

    problems: List[str] = []
    for entry in registry.entries:
        if entry.status not in ("LIVE", "RESERVED", "RETIRED", "BURNED"):
            problems.append(f"{entry.id}: unknown status {entry.status!r}")
        if entry.space not in ("AT", "TC") or not entry.id.startswith(entry.space + "-"):
            problems.append(f"{entry.id}: space {entry.space!r} disagrees with the id")
        if entry.status in ("LIVE", "RESERVED") and not entry.statement:
            problems.append(f"{entry.id}: {entry.status} requires a 'statement'")
        if entry.status == "RESERVED" and not entry.reserved_by:
            problems.append(f"{entry.id}: RESERVED requires 'reserved_by'")
        if entry.status == "RETIRED" and not entry.retired_reason:
            problems.append(f"{entry.id}: RETIRED requires 'retired_reason'")
        if entry.status == "BURNED" and not entry.provenance:
            problems.append(f"{entry.id}: BURNED requires 'provenance'")
        if entry.conforming and entry.stem is not None:
            body = entry.id.partition("-")[2]
            if not CONFORMING_BODY_RE.fullmatch(body):
                problems.append(f"{entry.id}: marked conforming but does not parse")
    assert not problems, _report("registry well-formedness", problems)


def test_tc610_reservations_are_recorded_and_respected(corpus: _Corpus) -> None:
    """TC-610 — the batch-75 block is reserved, and nothing was minted inside it.

    The registry had to be BORN knowing this reservation. batch-75 is chartered
    and may be running concurrently; a registry seeded without its block would
    put ``next_free`` below work already in flight and then redden against it.
    A guard that fires on legitimate work is worse than no guard, because it
    teaches everyone to wave it through.
    """
    reserved = {
        e.key: e for e in corpus.registry.entries if e.status == "RESERVED"
    }
    for space, low, high in (("AT", 250, 279), ("TC", 552, 599)):
        for stem in range(low, high + 1):
            key = f"{space}-{stem}"
            assert key in reserved, f"{key} must be RESERVED for batch-75"
            assert reserved[key].reserved_by == "batch-75", (
                f"{key} is reserved by {reserved[key].reserved_by!r}, not batch-75"
            )


# ---------------------------------------------------------------------------
# AT-280 / AT-281 — the black-box acceptances.
# ---------------------------------------------------------------------------


def test_at280_registry_and_repository_agree_in_both_directions(corpus: _Corpus) -> None:
    """AT-280 — the registry and the repository agree, both ways at once.

    The two directions are asserted together here, as one observable, because
    that is the property the backlog item actually asks for. The individual
    ``TC-6xx`` rules localise a failure; this one states the outcome.
    """
    failures = {
        name: rule(corpus, corpus.registry)
        for name, rule in RULES
        if rule(corpus, corpus.registry)
    }
    assert not failures, "\n\n".join(
        _report(name, problems) for name, problems in failures.items()
    )


def _mutate(registry: Registry, **_: object) -> Registry:
    """Return a deep copy of ``registry`` so a mutation cannot leak between cases."""
    return copy.deepcopy(registry)


def test_at281_every_guard_rule_can_fail(corpus: _Corpus) -> None:
    """AT-281 — each of G1..G7 goes red under one targeted mutation.

    A rule that has never been observed to fail is indistinguishable from one
    that cannot. Each case below **records the substituted value**, not "the
    check was removed": ``max(a, b)`` has two one-token mutations and naming the
    deleted operator identifies neither.

    Every mutation is applied to a deep copy of the *passing* state, never to a
    pre-fix tree — an error raised on an old tree proves nothing about the rule.
    """
    baseline = {name: rule(corpus, corpus.registry) for name, rule in RULES}
    assert not any(baseline.values()), (
        "the counterfactual is only meaningful from a green baseline; "
        f"these rules were already red: {[n for n, p in baseline.items() if p]}"
    )

    survived: List[str] = []

    # G1 — substitute: drop one registered id that a node name carries, so a
    # live node becomes unregistered. (registry entry for the id -> absent)
    victim = next(
        e for e in corpus.registry.entries
        if e.status == "LIVE" and e.key in corpus.named_nodes
    )
    broken = _mutate(corpus.registry)
    broken.entries = [e for e in broken.entries if e.key != victim.key]
    if not g1_named_nodes_are_registered(corpus, broken):
        survived.append(f"G1 stayed green after removing entry {victim.id}")

    # G2 — substitute: node ref "tests/<file>.py::<name>" -> the same file with
    # name "test_this_node_does_not_exist_anywhere".
    broken = _mutate(corpus.registry)
    target = next(e for e in broken.entries if e.status == "LIVE" and e.nodes)
    rel = target.nodes[0].split("::", 1)[0]
    target.nodes = [f"{rel}::test_this_node_does_not_exist_anywhere"]
    if not g2_live_entries_have_nodes(corpus, broken):
        survived.append("G2 stayed green after repointing a LIVE entry at a missing node")

    # G3 — substitute: drop a registered id that is CITED in the corpus, so a
    # circulating id has no registry row at all.
    cited_key = next(iter(sorted(corpus.test_citations)))
    broken = _mutate(corpus.registry)
    broken.entries = [e for e in broken.entries if e.key != cited_key]
    if not g3_citations_are_registered(corpus, broken):
        survived.append(f"G3 stayed green after removing cited entry {cited_key}")

    # G4 — substitute: status "LIVE" -> "RETIRED" on an id REQUIREMENTS.md cites
    # outside any exempt anchor, i.e. manufacture one phantom.
    broken = _mutate(corpus.registry)
    phantom = next(
        e for e in broken.entries
        if e.status == "LIVE"
        and e.key in corpus.requirement_citations
        and any(
            corpus.sections.get(line, "") not in
            {str(a).strip().lstrip("#").strip() for a in broken.meta.get("g4_exempt_anchors", [])}
            for _, line in corpus.requirement_citations[e.key]
        )
    )
    phantom.status = "RETIRED"
    if not g4_requirement_citations_are_live(corpus, broken):
        survived.append(f"G4 stayed green after retiring cited id {phantom.id}")

    # G5 — substitute: conforming false -> true on a legacy token, so the
    # corpus's non-conforming spelling loses its registered exemption.
    broken = _mutate(corpus.registry)
    legacy = next(
        e for e in broken.entries
        if not e.conforming and e.id in corpus.nonconforming
    )
    legacy.conforming = True
    if not g5_grammar_holds(corpus, broken):
        survived.append(f"G5 stayed green after un-exempting legacy token {legacy.id}")

    # G6 — substitute: append a duplicate of an existing entry whose id is
    # zero-padded differently ("AT-065b" alongside "AT-65b").
    broken = _mutate(corpus.registry)
    original = next(e for e in broken.entries if e.stem is not None and e.conforming)
    twin = copy.deepcopy(original)
    twin.id = f"{original.space}-{original.stem:04d}"
    broken.entries.append(twin)
    if not g6_keys_are_unique(corpus, broken):
        survived.append(f"G6 stayed green after adding padding alias {twin.id}")

    # G7 — substitute: high_water[TC] -> 1, so every real TC entry is above it.
    broken = _mutate(corpus.registry)
    broken.meta = dict(broken.meta)
    broken.meta["high_water"] = dict(broken.meta["high_water"])
    broken.meta["high_water"]["TC"] = 1
    if not g7_no_stem_exceeds_high_water(corpus, broken):
        survived.append("G7 stayed green after lowering the TC high-water mark to 1")

    assert not survived, (
        "these guard rules did NOT go red under a mutation that should break "
        "them, so they are vacuous:\n  - " + "\n  - ".join(survived)
    )
