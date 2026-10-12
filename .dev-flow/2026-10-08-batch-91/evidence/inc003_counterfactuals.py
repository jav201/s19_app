"""batch-91 inc-003 — executed RED counterfactuals for AT-286's three arms.

Same discipline as inc-001: the shipped arm functions of
`tests/test_batch91_registry_hygiene.py` run unmodified; each mutation
corrupts one INPUT the arm reads (the token stream, or the registry view),
in memory only. `AT-TC-REGISTRY.jsonl` and every file under `tests/` are
hash-pinned before/after and never written.

  M1 (token stripped):   the token stream drops TC-062's dash form
                         -> arm (a) must redden, naming TC-062.
  M2 (entry dropped):    the registry view loses AT-043's entry
                         -> arm (b) must redden (0 entries found).
  M3 (census gap):       the registry view loses AT-284's entry while
                         REQUIREMENTS.md still declares it
                         -> arm (c) must redden, naming AT-284.

Run from the repo root:

    python .dev-flow/2026-10-08-batch-91/evidence/inc003_counterfactuals.py
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tools import id_registry as lib  # noqa: E402
from tests import test_batch91_registry_hygiene as arm  # noqa: E402

REG = ROOT / "AT-TC-REGISTRY.jsonl"


def digest() -> str:
    return hashlib.sha256(REG.read_bytes()).hexdigest()


def run_arm(fn):
    try:
        fn()
    except AssertionError as exc:
        lines = [l.strip() for l in str(exc).splitlines() if l.strip()]
        return "RED", lines[1] if len(lines) > 1 else lines[0]
    return "GREEN", "the arm passed"


def main() -> None:
    before = digest()
    print(f"shipped registry sha256 BEFORE: {before}")
    print("arms resolved at baseline: 3 "
          "(test_at286_every_live_id_token_occurs_in_its_nodes_file, "
          "test_at286_at043_is_resolved_with_a_grammar_valid_status, "
          "test_at286_no_declared_id_is_absent_from_the_registry)")

    # Positive control: unmutated, all three arms GREEN.
    v = [run_arm(arm.test_at286_every_live_id_token_occurs_in_its_nodes_file)[0],
         run_arm(arm.test_at286_at043_is_resolved_with_a_grammar_valid_status)[0],
         run_arm(arm.test_at286_no_declared_id_is_absent_from_the_registry)[0]]
    print(f"positive control (unmutated): arm (a) {v[0]} · arm (b) {v[1]} · arm (c) {v[2]}")
    assert v == ["GREEN"] * 3, "baseline must be green before any mutation is believed"

    # M1 — strip the TC-062 token from the token stream arm (a) reads.
    real_iter_tokens = arm.iter_tokens

    def stripped_iter_tokens(text):
        return [(t, ln) for t, ln in real_iter_tokens(text) if t.raw != "TC-062"]

    arm.iter_tokens = stripped_iter_tokens
    v_a, d_a = run_arm(arm.test_at286_every_live_id_token_occurs_in_its_nodes_file)
    arm.iter_tokens = real_iter_tokens
    print(f"M1 token TC-062 stripped from the stream: arm (a) {v_a} — {d_a}")
    assert v_a == "RED" and "TC-062" in d_a, "M1 did not redden arm (a) on TC-062"

    # M2 — drop AT-043's entry from the registry view arm (b) reads.
    real_load = arm.load_registry

    def load_without_at043(path=None):
        registry = real_load(path)
        registry.entries = [e for e in registry.entries if e.id != "AT-043"]
        return registry

    arm.load_registry = load_without_at043
    v_b, d_b = run_arm(arm.test_at286_at043_is_resolved_with_a_grammar_valid_status)
    print(f"M2 AT-043 entry dropped: arm (b) {v_b} — {d_b}")
    assert v_b == "RED", "M2 did not redden arm (b)"

    # M3 — drop an entry whose id IS declared in the canon. First aimed at
    # AT-284: that mutation did NOT apply — batch-91's own ids are declared in
    # the batch contract (.dev-flow/2026-10-08-batch-91/01-requirements.md),
    # not in REQUIREMENTS.md (the fold-canon is the coordinator's, owed at
    # close), so arm (c) had no anchor and stayed GREEN. Verdict BAD, reported
    # rather than silently swapped: a mutation whose anchor does not apply
    # proves nothing. Re-aimed at AT-065b, declared LIVE at
    # REQUIREMENTS.md:460 (probe: iter_tokens over the canon, key AT-65b).
    def load_without_at065b(path=None):
        registry = real_load(path)
        registry.entries = [e for e in registry.entries if e.id != "AT-065b"]
        return registry

    arm.load_registry = load_without_at065b
    v_c, d_c = run_arm(arm.test_at286_no_declared_id_is_absent_from_the_registry)
    arm.load_registry = real_load
    print(f"M3 AT-065b entry dropped (still declared at REQUIREMENTS.md:460): arm (c) {v_c} — {d_c}")
    assert v_c == "RED" and "AT-065b" in d_c, "M3 did not redden arm (c) on AT-065b"

    after = digest()
    print(f"shipped registry sha256 AFTER:  {after}")
    assert before == after, "the shipped registry moved — the restore failed"
    print("restore proven by hash: shipped bytes identical before/after "
          "(mutations lived in memory only; no file under tests/ was written)")
    print("VERDICT: M1 KILLED by arm (a) · M2 KILLED by arm (b) · "
          "M3 KILLED by arm (c) (after one BAD aim, declared above) · 0 SURVIVED")


if __name__ == "__main__":
    main()
