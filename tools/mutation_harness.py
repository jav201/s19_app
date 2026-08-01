"""
Per-ARM counterfactual harness (batch-76 merge gate, §3 of the hand-off).

**Why this file exists.** batch-76's first matrix derived **one verdict per
mutant from the process exit code**, over a node list that included
*parametrized* tests. ``pytest`` exits non-zero if ANY arm fails, so::

    M1  gate disabled  AT-250/251/252  applied=True  RED   3 failed, 4 passed

was recorded as "RED · INERT: none". Four arms survived a **fully removed byte
gate** and the string ``4 passed`` sat unread in the transcript. An aggregate
verdict over a parametrized node set cannot express the thing a counterfactual
is for: *which* arms the mutation reddens. This harness reports one verdict per
resolved node id, so an inert arm cannot hide behind a sibling that failed.

Four properties it enforces, each earned by a defect this batch actually hit:

* **Per-arm verdicts.** The unit of judgement is the resolved node id
  (``test_x[3]``), never the mutant. ``INERT`` names the exact arms that stayed
  green.
* **The anchor matches exactly once.** batch-76 mutated the wrong function
  because ``_format_address`` and ``_format_length`` carry byte-identical
  ``return`` blocks. A 0- or 2-match anchor is a hard abort, never a red.
* **The mutated region is reachable** (``--probe``). One batch-76 mutant landed
  after a ``return`` and could not have changed any observable. The probe
  substitutes the same anchor for a raising sentinel: an arm that does not error
  never executed the region, so a green verdict for it is meaningless. It runs
  only for mutations that LEFT an arm green — a red arm is already proof of
  reachability, since a substitution that moved an observable must have
  executed — and a mutation that leaves an arm green without carrying a
  position-valid ``probe=`` is an abort, not a pass.
* **The baseline is the FIXED tree**, and the restore is verified by SHA-256
  returning to its pre-mutation value — ``git status`` is not sufficient.

**Isolation.** ``--tree`` points at a throwaway checkout (``git worktree add``).
Mutating the tree a concurrent gate run is reading is what contaminated
batch-76's run A; pointing this at a scratch worktree removes that class rather
than relying on sequencing.

Usage::

    python tools/mutation_harness.py --tree /path/to/scratch/worktree
    python tools/mutation_harness.py --tree ... --only H1 --probe
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

_TARGET = "tests/test_report_document_bound.py"
_SERVICE = "s19_app/tui/services/report_service.py"

#: A resolved pytest verdict line: ``path::name[arm] PASSED``.
_VERDICT = re.compile(r"^(?P<node>\S+::\S+)\s+(?P<outcome>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)")


@dataclass(frozen=True)
class Mutation:
    """One substitution, recording the VALUE it substitutes (C-40 / A-13).

    ``anchor`` must occur exactly once in ``path``; ``nodes`` are the pytest
    selectors whose arms this mutation is claimed to redden.
    """

    label: str
    finding: str
    path: str
    anchor: str
    replacement: str
    nodes: Tuple[str, ...]
    claim: str
    #: A substitution for the SAME anchor that raises when the region executes,
    #: written to be syntactically valid in this anchor's position — a statement
    #: for a statement anchor, a raising expression for an expression anchor.
    #: Only consulted when an arm stays green; see :func:`evaluate`.
    probe: Optional[str] = None


@dataclass
class ArmResult:
    """Per-arm outcome, plus the reachability probe when one was run."""

    baseline: Dict[str, str] = field(default_factory=dict)
    mutated: Dict[str, str] = field(default_factory=dict)
    probed: Dict[str, str] = field(default_factory=dict)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(tree: Path, nodes: Sequence[str]) -> Dict[str, str]:
    """Run ``nodes`` and return ``{resolved_node_id: outcome}``.

    ``-v`` is what makes this per-arm: the summary line ``3 failed, 4 passed``
    is exactly the aggregate that hid four inert arms, so it is never parsed.
    ``-p no:randomly`` keeps arm order stable across the baseline/mutated pair.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *nodes, "-v", "--tb=no", "-p", "no:randomly", "--no-header"],
        cwd=tree,
        capture_output=True,
        text=True,
    )
    outcomes: Dict[str, str] = {}
    for line in proc.stdout.splitlines():
        match = _VERDICT.match(line.strip())
        if match:
            outcomes[match.group("node")] = match.group("outcome")
    if not outcomes:
        raise SystemExit(
            f"ABORT: no per-arm verdict parsed for {list(nodes)}. A harness that "
            f"cannot see arms is the defect this file exists to prevent.\n"
            f"--- stdout tail ---\n{proc.stdout[-2000:]}"
        )
    return outcomes


def _substitute(target: Path, anchor: str, replacement: str) -> bytes:
    """Apply one substitution; abort unless the anchor matches EXACTLY once.

    Deliberately BYTES, not text. ``read_text``/``write_text`` apply newline
    translation on Windows, so a text-mode round-trip of an LF file rewrites it
    with CRLF — the restore is then content-equal but not byte-equal, and this
    file's whole contract is a byte-exact restore verified by hash. Caught by
    that very check rather than by review.
    """
    source = target.read_bytes()
    encoded = anchor.encode("utf-8")
    count = source.count(encoded)
    if count != 1:
        # An anchor whose newlines do not match the file's is a 0-match, and
        # reporting it as "not found" alone would send the reader hunting for a
        # typo, so say which it is.
        crlf = source.count(encoded.replace(b"\n", b"\r\n"))
        hint = f" (but matches {crlf}x with CRLF newlines)" if crlf else ""
        raise SystemExit(
            f"ABORT: anchor matched {count} time(s) in {target.name}, expected 1"
            f"{hint}. A multi-match anchor is how batch-76 mutated _format_address "
            f"while believing it had mutated _format_length.\nanchor: {anchor!r}"
        )
    target.write_bytes(source.replace(encoded, replacement.encode("utf-8")))
    return source


def _apply_and_run(
    tree: Path, mutation: Mutation, replacement: str
) -> Dict[str, str]:
    """Substitute, run the nodes, restore, and verify the restore by hash."""
    target = tree / mutation.path
    before_hash = _sha256(target)
    original = _substitute(target, mutation.anchor, replacement)
    try:
        return _run(tree, mutation.nodes)
    finally:
        target.write_bytes(original)
        after_hash = _sha256(target)
        if after_hash != before_hash:
            raise SystemExit(
                f"ABORT: {mutation.path} did not restore. "
                f"pre={before_hash[:12]} post={after_hash[:12]}"
            )


def evaluate(tree: Path, mutation: Mutation, probe: bool) -> ArmResult:
    """Baseline, then mutate, then optionally probe reachability."""
    result = ArmResult()
    result.baseline = _run(tree, mutation.nodes)
    green = [n for n, o in result.baseline.items() if o != "PASSED"]
    if green:
        raise SystemExit(
            f"ABORT: baseline is not green for {mutation.label}: {green}. "
            f"A counterfactual from a red baseline proves nothing about the rule."
        )
    result.mutated = _apply_and_run(tree, mutation, mutation.replacement)
    inert = [n for n, o in result.mutated.items() if o not in ("FAILED", "ERROR")]
    # Probe ONLY the mutations that left an arm green. A RED arm is already proof
    # of reachability: a substitution that changed an observable the node asserts
    # on must have executed. Probing a fully-red mutation would add a run that
    # cannot change any conclusion — and, because the sentinel has to be
    # syntactically valid in the anchor's position, it would abort on
    # expression-level anchors for no gain.
    if probe and inert:
        if mutation.probe is None:
            raise SystemExit(
                f"{mutation.label} left {len(inert)} arm(s) green and carries no "
                f"probe= for its anchor position, so reachability cannot be "
                f"settled. Add one before trusting the green verdicts: {inert}"
            )
        result.probed = _apply_and_run(tree, mutation, mutation.probe)
    return result


#: The mutations that reproduce the four merge-gate HIGH findings, and that must
#: redden EVERY arm once the findings are closed. Each records the substituted
#: value, never "delete the check".
MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        label="M1",
        finding="H-1",
        path=_SERVICE,
        anchor=(
            "        if not self._budget.fits(cost):\n"
            "            return False\n"
            "        if self._reservation is not None and not self._reservation.fits(cost):\n"
            "            return False\n"
            "        return True"
        ),
        replacement="        return True",
        nodes=(
            f"{_TARGET}::test_at250_document_never_exceeds_the_stated_ceiling",
            f"{_TARGET}::test_at251_ceiling_holds_across_the_variant_count",
            f"{_TARGET}::test_at252_ceiling_holds_across_the_check_file_count",
        ),
        claim="the byte gate is removed; every ceiling arm must redden",
        probe='        raise AssertionError("__MUTATION_PROBE_REACHED__")',
    ),
    # M2 is listed against TC-555 ALONE, deliberately. The ceiling ATs cannot
    # detect an inflated allowance and it would be dishonest to claim they do:
    # the allowance IS their expectation, so raising it only loosens them. That
    # asymmetry is the finding — before TC-555 bounded the constant from above,
    # nothing in the file could refuse a 1 GB ceiling.
    Mutation(
        label="M2",
        finding="H-2",
        path=_SERVICE,
        anchor="    return block + appendix + headings + header",
        replacement="    return 1_000_000_000 + variant_count",
        nodes=(
            f"{_TARGET}::test_tc555_allowance_is_bounded_on_both_sides_by_test_owned_derivations",
        ),
        claim="a ~1 GB allowance must redden TC-555's independently derived CAP",
        probe='    raise AssertionError("__MUTATION_PROBE_REACHED__")',
    ),
    Mutation(
        label="M5",
        finding="H-2",
        path=_SERVICE,
        anchor=(
            "    headings = variant_count * (\n"
            "        len(\"## Variant: \") + REPORT_VARIANT_ID_MAX_BYTES + 2 + 2 * (marker + 1)\n"
            "    )"
        ),
        # Reverts BOTH the emitted-byte derivation and the marker terms, giving a
        # 524 B slope. Reverting only the byte derivation (REPORT_CELL_CHARS with
        # the markers kept) yields 1068 B, which still clears the 777 B floor —
        # the marker slack covers it, and that compensation is exactly what
        # Option 3 removed. It is therefore NOT a behavioural defect and no
        # behavioural node can redden for it; TC-611 pins the constant's
        # soundness instead. Stated so the division of labour is not mistaken for
        # a gap that was missed.
        replacement="    headings = variant_count * (len(\"## Variant: \") + REPORT_CELL_CHARS)",
        nodes=(
            f"{_TARGET}::test_tc555_allowance_is_bounded_on_both_sides_by_test_owned_derivations",
        ),
        claim=(
            "dropping the marker terms puts the per-variant slope at 524 B, below the "
            "777 B a widest-reachable-id heading measures — TC-555's FLOOR must redden"
        ),
        probe='    raise AssertionError("__MUTATION_PROBE_REACHED__")',
    ),
    Mutation(
        label="M6",
        finding="H-2",
        path=_SERVICE,
        anchor="    block = (\n        len(\"## Omitted content\") + 2\n        + len(REPORT_SECTION_KINDS) * (row + 1)\n        + 2\n    )",
        replacement="    block = len(\"## Omitted content\") + 2 + 1 * (row + 1) + 2",
        nodes=(f"{_TARGET}::test_tc612_allowance_is_driven_by_the_closed_label_set",),
        claim="decoupling the block term from the label set must redden TC-612",
        probe='    raise AssertionError("__MUTATION_PROBE_REACHED__")',
    ),
    Mutation(
        label="M3",
        finding="H-4",
        path=_SERVICE,
        anchor='            f"bytes {refusals.byte_count.get(kind, 0)}{suffix}"',
        replacement='            f"bytes {sections}{suffix}"',
        nodes=(f"{_TARGET}::test_at253_every_drop_is_disclosed_with_its_byte_total",),
        claim="a SECTION count rendered under the 'bytes' label must redden AT-253",
        # Expression position, inside an implicit f-string concatenation: a bare
        # `raise` would be a SyntaxError, so the sentinel stays an f-string whose
        # evaluation raises.
        probe=(
            '            f"bytes {(_ for _ in ()).throw('
            "AssertionError('__MUTATION_PROBE_REACHED__'))}{suffix}\""
        ),
    ),
    # M4 mutates markdown_safety.py, which spec P-4 forbids EDITING. Mutating a
    # throwaway copy to obtain a counterfactual is not an edit, and TC-611's
    # property is a property of md_safe, so this is the only substitution that
    # can falsify it. Byte-bounding the output is exactly the world in which
    # reading REPORT_CELL_CHARS as a byte bound WOULD have been sound.
    Mutation(
        label="M4",
        finding="H-3",
        path="s19_app/tui/services/markdown_safety.py",
        anchor="    return _escape_leading_block_starter(text) or EMPTY_MARKER",
        replacement=(
            "    text = _escape_leading_block_starter(text) or EMPTY_MARKER\n"
            "    return text.encode('utf-8')[:limit].decode('utf-8', 'ignore')"
        ),
        nodes=(f"{_TARGET}::test_tc611_cell_allowance_must_not_be_derived_from_input_chars",),
        claim="a byte-bounded md_safe must redden BOTH arms of the expansion pin",
        probe='    raise AssertionError("__MUTATION_PROBE_REACHED__")',
    ),
)


def report(mutation: Mutation, result: ArmResult) -> bool:
    """Print the per-arm table. Returns True when every arm reddened."""
    print(f"\n{mutation.label} · {mutation.finding} · {mutation.path}")
    print(f"  substituted: {mutation.anchor.strip()!r}")
    print(f"           ->: {mutation.replacement.strip()!r}")
    print(f"  claim: {mutation.claim}")
    inert: List[str] = []
    unreachable: List[str] = []
    for node in sorted(result.mutated):
        outcome = result.mutated[node]
        arm = node.split("::", 1)[1]
        detected = outcome in ("FAILED", "ERROR")
        flag = "RED " if detected else "GREEN"
        note = ""
        if not detected:
            inert.append(arm)
        if result.probed:
            reached = result.probed.get(node) in ("FAILED", "ERROR")
            if not reached:
                unreachable.append(arm)
                note = "  [!] region NEVER EXECUTED by this arm"
        print(f"    {flag}  {arm}{note}")
    if unreachable:
        print(f"  [!] UNREACHABLE for: {unreachable} — a green verdict there is uninformative")
    if inert:
        print(f"  [X] INERT arms ({len(inert)}): {inert}")
    else:
        print(f"  [OK] every arm ({len(result.mutated)}) reddened")
    return not inert


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", required=True, help="throwaway checkout to mutate")
    parser.add_argument("--only", default=None, help="run one mutation by label, e.g. M1")
    parser.add_argument("--probe", action="store_true", help="also probe reachability")
    args = parser.parse_args()

    tree = Path(args.tree).resolve()
    root = Path(__file__).resolve().parent.parent
    if tree == root:
        raise SystemExit(
            "ABORT: refusing to mutate the working checkout. Pass a throwaway "
            "worktree — mutating a tree a gate run is reading is what "
            "contaminated batch-76's run A."
        )

    selected = [m for m in MUTATIONS if args.only in (None, m.label)]
    if not selected:
        raise SystemExit(f"no mutation labelled {args.only!r}")

    all_red = True
    for mutation in selected:
        all_red &= report(mutation, evaluate(tree, mutation, args.probe))
    print("\n" + ("ALL ARMS RED" if all_red else "INERT ARMS PRESENT — see above"))
    return 0 if all_red else 1


if __name__ == "__main__":
    raise SystemExit(main())
