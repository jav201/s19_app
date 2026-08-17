"""Guards for the bare-name address origin resolver (batch-84, `AT-B84-01`..`AT-B84-07`).

batch-83 shipped a census that recognises the SITE of an unresolvable address. All three
of its nets key on the SHAPE of the selector, so a selector assembled from parts where no
part has selector shape escapes every one of them. That blind spot was registered P2 and
**unmeasured**. This module's subject is the measurement: for the one population an
assembled selector can hide in, resolve where each value comes from.

Two populations of test, deliberately separated because they age differently:

* **Synthetic fixtures** — Python source in strings, parsed in memory. They pin the
  *criterion* and never go stale, because they do not depend on the tree.
* **Tree guards** — run over the repository. They assert set equality and non-emptiness,
  never a count: `== 41` breaks on every legitimate change and proves nothing.

`AT-B84-05` is the load-bearing one and is easy to mistake for an implementation detail.
The resolver's answer today is a NEGATIVE one — no candidate is assembled — and a negative
result is only worth having if the search that produced it was too WIDE. Make the walk
scope-precise and every such claim silently weakens while every other test stays green.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tools.address_census import (
    AddressSite,
    Census,
    bare_name_candidates,
    census,
    report,
)
from tools.address_origin import (
    ASSEMBLED_KINDS,
    Binding,
    OriginRow,
    classify,
    collect_bindings,
    kind_of_value,
    resolve_origins,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- helpers

def _classify_source(source: str, name: str) -> str:
    """Classify `name` as the resolver would, from source text."""
    outcome, _ = classify(collect_bindings(ast.parse(source), name, "fixture.py"))
    return outcome


@pytest.fixture(scope="module")
def tree_rows() -> list[OriginRow]:
    """Resolve the whole tree once — the walk parses every candidate's file."""
    return resolve_origins(REPO_ROOT)


# ----------------------------------------------------------------- AT-B84-01

def test_at_b84_01_rows_are_set_equal_to_the_candidate_population(
    tree_rows: list[OriginRow],
) -> None:
    """AT-B84-01 — one row per candidate, compared as a SET of site identities.

    A count would be satisfied by a resolver that dropped one site and invented
    another. The kill mutation is dropping any candidate from `resolve_origins`;
    set inequality names the missing `file:line` instead of printing a smaller number
    that still looks plausible.
    """
    candidates = bare_name_candidates(census(REPO_ROOT))
    expected = {(s.file, s.line, s.shape or "") for s in candidates}
    actual = {row.key() for row in tree_rows}

    assert actual == expected, (
        f"missing from the resolver: {sorted(expected - actual)}; "
        f"invented by the resolver: {sorted(actual - expected)}"
    )
    assert len(tree_rows) == len(candidates), "a candidate was resolved twice"
    assert candidates, "the candidate population is empty -- the census changed shape"


# ----------------------------------------------------------------- AT-B84-02

def test_at_b84_02_every_row_carries_non_empty_evidence(
    tree_rows: list[OriginRow],
) -> None:
    """AT-B84-02 — every classification is readable back to its source lines.

    batch-83 shipped a field nobody filled and it printed `0 of 183` -- a plausible
    number from an empty string. A classification without its evidence has exactly
    that failure mode, so the evidence is asserted, not assumed.
    """
    for row in tree_rows:
        assert row.outcome in {"A", "B", "C", "D", "U"}, row
        for binding in row.bindings:
            evidence = binding.evidence()
            assert binding.kind, f"binding with no kind at {row.key()}"
            assert binding.file, f"binding with no file at {row.key()}"
            assert binding.line > 0, f"binding at line 0 for {row.key()}"
            assert f"{binding.file}:{binding.line}" in evidence, evidence
        if row.outcome == "D":
            assert row.detail, f"D row without its sub-kind: {row.key()}"


# ----------------------------------------------------------------- AT-B84-03

def test_at_b84_03_the_four_outcomes_are_distinguished() -> None:
    """AT-B84-03 — a fixture holding all four outcomes classifies as A, B, C, D.

    Kill mutation: mutate any one branch of `classify` and exactly one assertion
    here turns red, which is what makes the branches separable rather than a single
    catch-all that happens to agree with today's tree.
    """
    source = """
CONST = "#run_entry"

def uses_param(sel):
    app.query_one(sel)

def builds():
    made = "#" + wid
    app.query_one(made)

def other(rows):
    picked = rows[0]
    app.query_one(picked)
"""
    assert _classify_source(source, "CONST") == "A"
    assert _classify_source(source, "made") == "B"
    assert _classify_source(source, "sel") == "C"
    assert _classify_source(source, "picked") == "D"


def test_at_b84_03_d_names_its_sub_kind_and_never_lumps() -> None:
    """AT-B84-03 — a D row says WHICH other thing it is."""
    _, detail = classify(collect_bindings(ast.parse("picked = rows[0]"), "picked", "f.py"))
    assert detail == "Subscript"

    both = "a = rows[0]\nfor a in items:\n    pass\n"
    _, detail = classify(collect_bindings(ast.parse(both), "a", "f.py"))
    assert "Subscript" in detail and "," in detail, detail


# ----------------------------------------------------------------- AT-B84-04

@pytest.mark.parametrize(
    "label, source",
    [
        ("escape 1 -- f-string with no selector shape",
         'prefix = "#panel_"\nsel = f"{prefix}{name}"\napp.query_one(sel)\n'),
        ("escape 2 -- concatenation assigned before use",
         'sel = "#" + widget_id\napp.query_one(sel)\n'),
        ("escape 3 -- percent formatting",
         'sel = "#%s" % widget_id\napp.query_one(sel)\n'),
        ("escape 4 -- str.format",
         'sel = "#{}".format(widget_id)\napp.query_one(sel)\n'),
        ("escape 5 -- augmented concatenation",
         'sel = "#panel_"\nsel += widget_id\napp.query_one(sel)\n'),
        ("escape 6 -- augmented percent formatting",
         'sel = "#%s"\nsel %= widget_id\napp.query_one(sel)\n'),
    ],
)
def test_at_b84_04_the_escapes_are_positively_classified_as_assembled(
    label: str, source: str
) -> None:
    """AT-B84-04 — the blind spot is DETECTED, not merely absent from the tree.

    This is the criterion the batch exists for. Every one of these forms passes
    batch-83's three nets green -- verified in the spec's premise table by executing
    `census_source` and `find_indirect_addresses` on them -- so a resolver that
    returned "nothing found" on all of them would agree with today's tree and be
    worthless. Kill mutation: remove any member of `ASSEMBLED_KINDS`, and the matching
    case turns red.
    """
    assert _classify_source(source, "sel") == "B", label


def test_at_b84_04_assembled_wins_over_every_other_binding() -> None:
    """AT-B84-04 — one assembled binding out of many still makes the site a B.

    The tie-break is biased toward finding the blind spot. A rule that took the
    majority, or the first binding, would classify this site A and hide the one
    assignment that matters.
    """
    source = 'sel = "#static"\nif cond:\n    sel = f"{prefix}{suffix}"\napp.query_one(sel)\n'
    assert _classify_source(source, "sel") == "B"
    assert {"fstring", "concat", "percent-format", "call:.format"} <= ASSEMBLED_KINDS


# ----------------------------------------------------------------- AT-B84-05

def test_at_b84_05_the_walk_is_scope_insensitive_on_purpose() -> None:
    """AT-B84-05 — a binding in an unrelated function of the same file is reported.

    **This guard protects a negative result, not a feature.** The batch's finding is
    that no candidate is assembled; that finding is only sound because the search was
    deliberately too wide. Narrow the walk to the site's own scope and this test is the
    only thing that fails -- every other guard here, and all 23 of batch-83's, stay
    green while every "no assembled selector found" claim quietly gets weaker.

    Kill mutation: restrict `collect_bindings` to the enclosing function.
    """
    source = """
def unrelated():
    sel = f"{prefix}{suffix}"

def the_site(sel):
    app.query_one(sel)
"""
    kinds = {b.kind for b in collect_bindings(ast.parse(source), "sel", "f.py")}
    assert "assign" in kinds, "the binding in the unrelated function was not reported"
    assert "param" in kinds
    assert _classify_source(source, "sel") == "B", (
        "over-collection must reach the classification, not stop at collection"
    )


# ----------------------------------------------------------------- AT-B84-06

def test_at_b84_06_a_candidate_with_no_binding_is_reported_not_dropped() -> None:
    """AT-B84-06 — an unresolvable name gets outcome U and survives to the report.

    The tempting failure is to skip what cannot be resolved, which shrinks the
    measured blind spot in the one direction that must never shrink silently.
    """
    assert collect_bindings(ast.parse("app.query_one(imported_id)"), "imported_id", "f.py") == []
    assert classify([]) == ("U", "")


def test_at_b84_06_a_u_row_survives_the_resolver_not_only_the_classifier(tmp_path) -> None:
    """AT-B84-06 — "never drop it" is asserted against `resolve_origins`, not just `classify`.

    **This arm exists because its absence was invisible.** The other AT-B84-06 tests
    exercise `collect_bindings` and `classify` on fixtures, and AT-B84-01 compares row
    identities against the candidate set — but the tree currently holds ZERO U rows, so
    `return [r for r in rows if r.bindings]` in `resolve_origins` dropped nothing, kept
    the set equality intact, and passed all sixteen guards. A guard that holds only
    because today's tree is empty of the case it names is not a guard, and this project
    calls that its top defect class.

    Kill mutation: filter unresolved rows out of `resolve_origins`'s return; this arm is
    the only thing that goes red.
    """
    (tmp_path / "s19_app").mkdir()
    (tmp_path / "tests").mkdir()
    # No import, no assignment: the name is bound nowhere in this module, which is the
    # only way to reach U. An `import` line would make it a D -- collect_bindings finds
    # imports -- and the arm would then pass for the wrong reason.
    (tmp_path / "s19_app" / "mod.py").write_text(
        "def go(app):\n    app.query_one(imported_id)\n",
        encoding="utf-8",
    )

    rows = resolve_origins(tmp_path)

    unresolved = [r for r in rows if r.outcome == "U"]
    assert len(unresolved) == 1, (
        f"the unresolvable site was dropped instead of reported: {[r.key() for r in rows]}"
    )
    assert unresolved[0].site.shape == "imported_id"
    assert unresolved[0].bindings == [], "a U row must carry no binding, not a fabricated one"


def test_at_b84_06_binding_forms_beyond_plain_assignment_are_found() -> None:
    """AT-B84-06 — the forms that would otherwise fall through to a false U.

    Each of these was found by running the resolver against the tree, not by
    imagining it: the lambda parameter is why two real `row` sites moved from D to C
    between a throwaway probe and the committed tool.
    """
    cases = {
        "lambda parameter": ("run(lambda pilot, row: pilot.click(row))", "row", "param"),
        "for target": ("for wid in ids:\n    pass", "wid", "for-target"),
        "comprehension": ("[x for sel in ids]", "sel", "comp-target"),
        "tuple unpack": ("a, row = pair", "row", "unpack"),
        "with as": ("with ctx() as sel:\n    pass", "sel", "with-as"),
        "walrus": ("if (sel := compute()):\n    pass", "sel", "walrus"),
        "import": ("from mod import sel", "sel", "import"),
        "annotated": ("sel: str = '#x'", "sel", "assign"),
    }
    for label, (source, name, expected) in cases.items():
        kinds = {b.kind for b in collect_bindings(ast.parse(source), name, "f.py")}
        assert expected in kinds, f"{label}: got {sorted(kinds)}, expected {expected!r}"


# ----------------------------------------------------------------- AT-B84-07

def test_at_b84_07_the_candidate_filter_has_exactly_one_home() -> None:
    """AT-B84-07 — `address_origin` calls the census's filter, it does not re-implement it.

    batch-83 lost time to one filter living in two places: it ran in one derivation
    pass and not the other, three private methods walked back in, and nothing failed.
    Identity, not equality -- a copy that happens to agree today satisfies equality and
    is exactly the defect.
    """
    import tools.address_census as census_mod
    import tools.address_origin as origin_mod

    assert origin_mod.bare_name_candidates is census_mod.bare_name_candidates

    source = Path(origin_mod.__file__).read_text(encoding="utf-8")
    assert "resolves_to_class_like" not in source, (
        "address_origin re-derives the candidate predicate; it must call the census's"
    )


def test_at_b84_07_the_candidate_split_over_the_tree_is_not_degenerate() -> None:
    """AT-B84-07 — the tree really does hold both kinds of bare name.

    This arm asserts non-degeneracy and NOTHING MORE — it is deliberately named for
    what it checks, after an adversarial pass found its predecessor promising to guard
    the census's complement rewrite while asserting only this. The complement itself is
    guarded by the arm below, which reads the printed line.
    """
    data = census(REPO_ROOT)
    names = [s for s in data.sites if s.form == "name"]
    candidates = bare_name_candidates(data)
    assert 0 < len(candidates) < len(names), (
        "the split collapsed -- every name is class-like, or none is"
    )


def test_at_b84_07_the_predicate_is_called_from_exactly_one_place() -> None:
    """AT-B84-07 — `resolves_to_class_like` is CALLED only inside `bare_name_candidates`.

    **This arm is structural because the invariant is, and finding that out cost a
    wrong fix.** The rewrite it guards replaced a second local `resolves_to_class_like`
    filter in `report()` with `names - len(bare_name_candidates(...))`. Reverting it is
    **behaviour-preserving on every possible input** — the two expressions are the same
    set, counted from opposite ends — so no assertion over any output, synthetic or real,
    can tell them apart. An adversarial pass proposed a printed-line assertion for this;
    it was written, executed, and stayed green under the mutation.

    What actually differs is the number of places the predicate is called from, so that
    is what is asserted. Kill mutation: restore the second local filter in `report()`.
    """
    import tools.address_census as census_mod

    tree = ast.parse(Path(census_mod.__file__).read_text(encoding="utf-8"))
    callers: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "resolves_to_class_like"
            ):
                callers.append(node.name)

    assert callers == ["bare_name_candidates"], (
        f"the candidate predicate is called from {sorted(set(callers))}; it must have one "
        f"home, and every other consumer must derive from bare_name_candidates()"
    )


def test_at_b84_07_report_prints_the_note_from_the_complement(capsys) -> None:
    """AT-B84-07 — `report()`'s class-like note counts what the complement says.

    Not a guard against the two-homes mutation — the arm above owns that, and this one
    stays green under it by construction. Its value is that **nothing executed `report()`
    at all** before this batch: `grep -n "report(" tests/` found no caller, so the
    rewrite shipped into a function with zero coverage. This pins its arithmetic on a
    synthetic census whose split is known and is not the tree's.
    """
    data = Census(sites=[
        AddressSite(file="f.py", line=1, api="query_one", form="name", shape="Input"),
        AddressSite(file="f.py", line=2, api="query_one", form="name", shape="selector"),
        AddressSite(file="f.py", line=3, api="query_one", form="name", shape="wid"),
    ], files=1)

    report(data)
    printed = capsys.readouterr().out

    assert "NOTE on 'name': 1 of 3 resolve to a class-like symbol" in printed, printed
    assert len(bare_name_candidates(data)) == 2


# --------------------------------------------------------- supporting criterion

def test_kind_of_value_names_assembly_without_proving_operand_types() -> None:
    """The bias is one-directional and asserted, not left to a comment.

    `+` and `%` are called assembly without checking the operands are strings. A wrong
    B prints its evidence and is dismissed by reading it; a wrong A is a blind spot
    that looks measured. This module exists because of the second kind.
    """
    assert kind_of_value(ast.parse('f"{a}{b}"', mode="eval").body) == "fstring"
    assert kind_of_value(ast.parse('"#" + wid', mode="eval").body) == "concat"
    assert kind_of_value(ast.parse('"#%s" % wid', mode="eval").body) == "percent-format"
    assert kind_of_value(ast.parse('"#x"', mode="eval").body) == "literal"
    assert kind_of_value(ast.parse("rows[0]", mode="eval").body) == "Subscript"


def test_evidence_is_a_location_a_reader_can_open() -> None:
    """`Binding.evidence` is what turns a classification into something checkable."""
    assert Binding("assign", "concat", "t/f.py", 12).evidence() == (
        "assign->concat at t/f.py:12"
    )
    assert Binding("param", "", "t/f.py", 3).evidence() == "param at t/f.py:3"
