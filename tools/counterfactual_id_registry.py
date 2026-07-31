"""
Recorded counterfactual evidence for the AT/TC registry guard (spec §5.5).

Runs one targeted mutation per rule G1..G7 and prints, for each, **the value it
substituted** and whether the rule went red. The same seven mutations are
executed in CI by ``tests/test_id_registry.py::test_at281_every_guard_rule_can_fail``;
this script exists so the evidence can be regenerated and pasted into a review
packet without reading pytest internals::

    python tools/counterfactual_id_registry.py

Two properties this deliberately preserves:

* **The baseline is the FIXED tree.** Every mutation is applied to a deep copy
  of the currently-green state. A test that errors on the *pre-fix* tree proves
  nothing about the rule — it only proves the old tree was broken.
* **The substituted VALUE is recorded, not the deleted operator.** "Drop the
  clamp" does not identify a mutation when ``max(a, b)`` has two one-token
  edits. Each row below names what the field became.

Nothing here mutates the working tree: the registry is mutated in memory only,
so this is safe to run while another session is reading the checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.test_id_registry import (  # noqa: E402
    RULES,
    _Corpus,
    g1_named_nodes_are_registered,
    g2_live_entries_have_nodes,
    g3_citations_are_registered,
    g4_requirement_citations_are_live,
    g5_grammar_holds,
    g6_keys_are_unique,
    g7_no_stem_exceeds_high_water,
)
from tools.id_registry import repo_root  # noqa: E402

import copy  # noqa: E402


def main() -> int:
    root = repo_root(Path(__file__))
    corpus = _Corpus(root)

    baseline = {name: rule(corpus, corpus.registry) for name, rule in RULES}
    red = [name for name, problems in baseline.items() if problems]
    print("BASELINE (the fixed tree, unmutated)")
    for name, problems in baseline.items():
        print(f"  {name}: {'RED - ' + str(len(problems)) + ' problem(s)' if problems else 'green'}")
    if red:
        print(f"\nABORT: the baseline is not green ({red}); a counterfactual from a red "
              f"baseline proves nothing.")
        return 1

    rows = []

    def case(rule_name: str, substitution: str, mutate) -> None:
        broken = copy.deepcopy(corpus.registry)
        rule = mutate(broken)
        problems = rule(corpus, broken)
        rows.append((rule_name, substitution, len(problems),
                     problems[0] if problems else "(none)"))

    def m1(reg):
        victim = next(e for e in reg.entries
                      if e.status == "LIVE" and e.key in corpus.named_nodes)
        m1.value = f"registry entry {victim.id!r} -> absent (row deleted)"
        reg.entries = [e for e in reg.entries if e.key != victim.key]
        return g1_named_nodes_are_registered

    def m2(reg):
        target = next(e for e in reg.entries if e.status == "LIVE" and e.nodes)
        rel = target.nodes[0].split("::", 1)[0]
        m2.value = (f"{target.id}.nodes[0] -> "
                    f"{rel!r} + '::test_this_node_does_not_exist_anywhere'")
        target.nodes = [f"{rel}::test_this_node_does_not_exist_anywhere"]
        return g2_live_entries_have_nodes

    def m3(reg):
        key = sorted(corpus.test_citations)[0]
        m3.value = f"registry entry for cited id {key!r} -> absent (row deleted)"
        reg.entries = [e for e in reg.entries if e.key != key]
        return g3_citations_are_registered

    def m4(reg):
        exempt = {str(a).strip().lstrip("#").strip()
                  for a in reg.meta.get("g4_exempt_anchors", [])}
        victim = next(
            e for e in reg.entries
            if e.status == "LIVE" and e.key in corpus.requirement_citations
            and any(corpus.asserts_verifier.get(line, False)
                    and corpus.sections.get(line, "") not in exempt
                    for _, line in corpus.requirement_citations[e.key])
        )
        m4.value = f"{victim.id}.status -> 'RETIRED' (was 'LIVE')"
        victim.status = "RETIRED"
        return g4_requirement_citations_are_live

    def m5(reg):
        victim = next(e for e in reg.entries
                      if not e.conforming and e.id in corpus.nonconforming)
        m5.value = f"{victim.id}.conforming -> True (was False)"
        victim.conforming = True
        return g5_grammar_holds

    def m6(reg):
        original = next(e for e in reg.entries if e.stem is not None and e.conforming)
        twin = copy.deepcopy(original)
        twin.id = f"{original.space}-{original.stem:04d}"
        m6.value = f"appended row id -> {twin.id!r} (padding alias of {original.id!r})"
        reg.entries.append(twin)
        return g6_keys_are_unique

    def m7(reg):
        reg.meta = dict(reg.meta)
        reg.meta["high_water"] = dict(reg.meta["high_water"])
        was = reg.meta["high_water"]["TC"]
        m7.value = f"_meta.high_water['TC'] -> 1 (was {was})"
        reg.meta["high_water"]["TC"] = 1
        return g7_no_stem_exceeds_high_water

    for name, mutate in (("G1", m1), ("G2", m2), ("G3", m3), ("G4", m4),
                         ("G5", m5), ("G6", m6), ("G7", m7)):
        case(name, "", mutate)
        rows[-1] = (name, mutate.value, rows[-1][2], rows[-1][3])

    print("\nCOUNTERFACTUALS (each applied to a deep copy of the green baseline)")
    print(f"{'rule':5} {'verdict':8} {'n':>4}  substituted value")
    print("-" * 100)
    failed = []
    for name, value, count, first in rows:
        verdict = "RED" if count else "still green"
        if not count:
            failed.append(name)
        print(f"{name:5} {verdict:8} {count:>4}  {value}")
        if count:
            print(f"{'':19}  first offender: {first[:120]}")

    if failed:
        print(f"\nVACUOUS: {failed} did not go red under a mutation that should break them.")
        return 1
    print("\nAll seven rules went RED under their mutation; none is vacuous.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
