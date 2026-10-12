"""batch-91 inc-001 — executed RED counterfactuals for AT-284's two arms.

The mutations are applied to the arm's INPUT (a corrupted in-memory view of the
registry), never to the shipped file: `AT-TC-REGISTRY.jsonl` is hash-pinned
before and after and is never written. The arm FUNCTIONS under test are the
shipped ones, imported unmodified from `tests/test_batch91_adoption.py`; only
their `_batch91_entries` data source is redirected at the corrupted copy.

  M1 (RESERVED-flip):  TC-617's entry flipped LIVE -> RESERVED
                       -> arm (a) must redden, naming TC-617.
  M2 (phantom node):   TC-618 gains a node that does not exist on disk
                       -> arm (b) must redden, naming the phantom.

Run from the repo root:

    python .dev-flow/2026-10-08-batch-91/evidence/inc001_counterfactuals.py
"""
import dataclasses
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tools.id_registry import load_registry, registry_path  # noqa: E402
from tests import test_batch91_adoption as arm  # noqa: E402

REG = ROOT / "AT-TC-REGISTRY.jsonl"


def digest() -> str:
    return hashlib.sha256(REG.read_bytes()).hexdigest()


def entries_view(mutate):
    """The arm's data source over a corrupted COPY of the live registry."""
    registry = load_registry(registry_path(ROOT))
    by_key = registry.by_key()
    view = {}
    for stem in arm.BATCH91_TC_STEMS:
        entry = by_key.get(f"TC-{stem}")
        if entry is not None:
            entry = mutate(f"TC-{stem}", entry)
        view[f"TC-{stem}"] = entry
    return view


def run_arm(fn):
    """Return (verdict, detail): RED if the shipped arm raises AssertionError."""
    try:
        fn()
    except AssertionError as exc:
        first = str(exc).splitlines()[1].strip() if "\n" in str(exc) else str(exc)
        return "RED", first
    return "GREEN", "the arm passed"


def main() -> None:
    before = digest()
    print(f"shipped registry sha256 BEFORE: {before}")
    print(f"arms resolved at baseline: 2 "
          f"({arm.test_at284_every_batch91_tc_is_live_with_nodes.__name__}, "
          f"{arm.test_at284_every_named_node_exists_on_disk.__name__})")

    # Positive control: the unmutated view must keep both arms GREEN.
    real = arm._batch91_entries
    v_a, _ = run_arm(arm.test_at284_every_batch91_tc_is_live_with_nodes)
    v_b, _ = run_arm(arm.test_at284_every_named_node_exists_on_disk)
    print(f"positive control (unmutated registry): arm (a) {v_a} · arm (b) {v_b}")
    assert v_a == v_b == "GREEN", "baseline must be green before any mutation is believed"

    # M1 — RESERVED-flip on TC-617.
    def m1(key, entry):
        if key == "TC-617":
            return dataclasses.replace(entry, status="RESERVED")
        return entry

    arm._batch91_entries = lambda: entries_view(m1)
    v_a, d_a = run_arm(arm.test_at284_every_batch91_tc_is_live_with_nodes)
    v_b, _ = run_arm(arm.test_at284_every_named_node_exists_on_disk)
    print(f"M1 RESERVED-flip TC-617: arm (a) {v_a} — {d_a}")
    print(f"M1 arm (b) stayed {v_b} (named, not hidden behind the process exit code)")
    assert v_a == "RED" and "TC-617" in d_a, "M1 did not redden arm (a) on TC-617"

    # M2 — phantom node appended to TC-618.
    phantom = "tests/test_hexfile.py::test_phantom_node_does_not_exist"

    def m2(key, entry):
        if key == "TC-618":
            return dataclasses.replace(entry, nodes=[*entry.nodes, phantom])
        return entry

    arm._batch91_entries = lambda: entries_view(m2)
    v_b, d_b = run_arm(arm.test_at284_every_named_node_exists_on_disk)
    v_a, _ = run_arm(arm.test_at284_every_batch91_tc_is_live_with_nodes)
    print(f"M2 phantom node on TC-618: arm (b) {v_b} — {d_b}")
    print(f"M2 arm (a) stayed {v_a}")
    assert v_b == "RED" and "test_phantom_node_does_not_exist" in d_b

    arm._batch91_entries = real
    after = digest()
    print(f"shipped registry sha256 AFTER:  {after}")
    assert before == after, "the shipped registry moved — the restore failed"
    print("restore proven by hash: shipped bytes identical before/after "
          "(mutations lived in memory only)")
    print("VERDICT: M1 KILLED by arm (a) · M2 KILLED by arm (b) · 0 SURVIVED")


if __name__ == "__main__":
    main()
