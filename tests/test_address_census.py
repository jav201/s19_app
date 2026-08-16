"""Guards for the computed-address census (batch-83, `AT-B83-01`..`AT-B83-09`).

These tests exist because a hand-written `ADDRESS_APIS` was wrong in two ways at once —
it held `query_exactly`, which is not a Textual API, and missed 16 that are — and **the
census output was identical either way**. No reading of the numbers could have caught it;
only an oracle that asks Textual itself can.

Two populations, deliberately separated because they age differently:

* **Synthetic fixtures** — Python source in strings, parsed in memory. They pin the
  *criterion* and never go stale, because they do not depend on the tree.
* **Introspection guards** — run against the installed Textual, whose version is printed
  on failure. They fail on a dependency bump **by design**; the batch that bumps Textual
  owns re-deriving the set (spec §8).

**No test asserts a count over the tree.** `== 56` breaks on every legitimate change and
proves nothing; what is asserted is shape, membership and completeness.
"""

from __future__ import annotations

import ast
import inspect
import pkgutil
import importlib
import re
from typing import Any, List, Tuple

import pytest
import textual

from tools.address_census import (
    ADDRESS_APIS,
    ADDRESS_PARAMS,
    FIRST_POSITIONAL_SELECTOR,
    census_source,
    derive_address_params,
    find_indirect_addresses,
    is_candidate_method,
    is_selector,
    resolves_to_class_like,
)

#: The six APIs that were a hand-maintained list until the taint derivation replaced it.
#: Kept here as a REGRESSION anchor, not as configuration: if a future change to the
#: derivation stops reaching them, the list must not come back silently.
_FORMERLY_HAND_DECLARED = frozenset({
    "get_child_by_id", "get_widget_by_id", "action_add_class",
    "action_remove_class", "action_toggle_class", "action_focus",
})


# --------------------------------------------------------------------------- helpers

def _forms(source: str) -> List[Tuple[str, str | None]]:
    """Return ``(form, shape)`` for every address-argument row in `source`."""
    sites, _ = census_source(source, "fixture.py")
    return [(s.form, s.shape) for s in sites]


def _loose_shapes(source: str) -> List[str | None]:
    _, loose = census_source(source, "fixture.py")
    return [s.shape for s in loose]


# --------------------------------------------------------------- AT-B83-01 · the site

def test_at_b83_01_computed_address_is_recognised() -> None:
    """A selector built with an f-string in an address argument is reported.

    Kill mutation: drop `JoinedStr` handling from `_argument_form` -> the row's form
    stops being 'fstring' and the shape is never captured.
    """
    sites, _ = census_source('app.query_one(f"#{panel_id}")', "fixture.py")
    assert len(sites) == 1
    assert sites[0].form == "fstring"
    assert sites[0].shape == "#{}"
    assert sites[0].api == "query_one"
    assert sites[0].line == 1


# ------------------------------------------------------- AT-B83-02 · format spec ≠ selector

def test_at_b83_02_format_spec_is_not_a_selector() -> None:
    """`f"{value:#x}"` holds a nested JoinedStr — the `:#x` spec — that reads as '#x'.

    Kill mutation: remove the `format_spec_nodes` exclusion -> this fixture reports a
    phantom '#x' loose row (12 of them exist tree-wide).
    """
    src = 'msg = f"value {v:#x} out of range"\n'
    assert _loose_shapes(src) == []


def test_at_b83_02_hex_colour_is_classified_not_dropped() -> None:
    """A hex colour is reported and labelled, never silently discarded.

    A census that hides rows it judged uninteresting is indistinguishable from one with
    a blind spot. Kill mutation: drop the `note` -> the label disappears and the row
    becomes an unexplained selector.
    """
    _, loose = census_source('c = f"#{r:02x}{g:02x}{b:02x}"', "fixture.py")
    assert len(loose) == 1
    assert loose[0].note == "hex colour"


# ------------------------------------------------------------- AT-B83-03 · prose ≠ selector

@pytest.mark.parametrize(
    "source",
    [
        'title = f"## Variant: {name}"',
        'msg = f"... {n} more ranges (see log)"',
        'head = f"# Report {name}"',
    ],
)
def test_at_b83_03_prose_is_not_a_selector(source: str) -> None:
    """Markdown headings and prose ellipsis are not selectors.

    Kill mutation: relax `SELECTOR_RE` to a bare `startswith('#')` -> all three report,
    and the tree-wide selector-shaped population goes 72 -> 98.
    """
    assert _loose_shapes(source) == []


def test_at_b83_03_criterion_requires_identifier_or_interpolation() -> None:
    """The criterion itself, stated as a table so the boundary is visible."""
    assert is_selector("#{}") is True
    assert is_selector("#log_line_{}") is True
    assert is_selector(".{}") is True
    assert is_selector("## Variant: {}") is False
    assert is_selector("... {} more") is False
    assert is_selector("# Report {}") is False


# ------------------------------------------------------------- AT-B83-04 · the taxonomy

def test_at_b83_04_taxonomy_does_not_collapse_the_hard_cases() -> None:
    """strict / non-Name interpolation / extra-literal must stay three buckets.

    Kill mutation: group by `shape` alone, dropping the interpolation-kind check -> the
    Subscript row merges into strict and the partition reads 2/0/1 instead of 1/1/1.

    Why it matters: the computed CLASS selector is the address form that a detector keyed
    on `f"#{var}"` alone would skip -- the hardest case it exists to catch.
    """
    src = (
        'a = app.query_one(f"#{widget_id}")\n'
        'b = app.query_one(f"#{_WINDOW_BODY[win_id]}")\n'
        'c = app.query_one(f"#legend_key_pane .{cls}")\n'
    )
    sites, _ = census_source(src, "fixture.py")
    strict = [s for s in sites if s.shape == "#{}" and s.interp == ["Name"]]
    non_name = [s for s in sites if s.shape == "#{}" and s.interp != ["Name"]]
    extra = [s for s in sites if s.shape != "#{}"]
    assert len(strict) == 1
    assert len(non_name) == 1 and non_name[0].interp == ["Subscript"]
    assert len(extra) == 1 and extra[0].shape == "#legend_key_pane .{}"


# ------------------------------------------------- AT-B83-05 · the API set, by SET EQUALITY

def test_at_b83_05_address_params_equals_the_live_derivation() -> None:
    """The snapshot IS the derivation — set equality, both directions, params included.

    Revision 1 of the spec asserted only `derived <= set`, and a phantom name walked
    straight through: that limb says nothing about a member of `set` which is neither
    derived nor declared. `query_exactly` was exactly such a member.

    Kill mutation: add 'query_exactly' to ADDRESS_PARAMS -> limb 2 goes red.
    """
    derived, first_pos = derive_address_params()

    assert set(derived) <= ADDRESS_APIS, (
        f"textual {textual.__version__} exposes address APIs the snapshot lacks: "
        f"{sorted(set(derived) - ADDRESS_APIS)}"
    )
    assert ADDRESS_APIS <= set(derived), (
        f"the snapshot holds names textual {textual.__version__} does not derive: "
        f"{sorted(ADDRESS_APIS - set(derived))}"
    )
    for name, params in derived.items():
        assert ADDRESS_PARAMS[name] == params, (
            f"{name}: snapshot says {sorted(ADDRESS_PARAMS[name])}, textual "
            f"{textual.__version__} derives {sorted(params)}"
        )
    assert FIRST_POSITIONAL_SELECTOR == first_pos, (
        "the first-positional set drifted: "
        f"snapshot-only {sorted(FIRST_POSITIONAL_SELECTOR - first_pos)}, "
        f"derived-only {sorted(first_pos - FIRST_POSITIONAL_SELECTOR)}"
    )


def test_at_b83_05_derivation_is_not_empty() -> None:
    """Zero derived APIs is never a pass -- it means the oracle stopped working.

    Same shape as the `_pair_drift({}, {})` defect the flow's own V15 shipped with: a
    comparison over nothing reports agreement.
    """
    derived, _ = derive_address_params()
    assert derived, (
        f"the oracle derived NOTHING from textual {textual.__version__} -- it broke, "
        "it did not pass"
    )


# ------------------------------------------- AT-B83-06 · the non-derivable list is honest

def test_at_b83_06_derivation_still_reaches_the_formerly_hand_declared_six() -> None:
    """The six that used to be a maintained list must stay derivable.

    They annotate their parameter as a plain `str`, so annotation shape alone finds none
    of them -- it takes the taint pass, seeded by the annotation pass. Measured: seeding
    taint from `parse_selectors`/`DOMQuery` alone reaches 1 of 6; seeding from the
    annotation pass reaches 6 of 6.

    This is a REGRESSION anchor. If a future change to the derivation stops reaching
    them, the hand-maintained list must not come back silently.

    Kill mutation: seed taint from the raw sinks only -> 5 of the 6 go missing.
    """
    derived, _ = derive_address_params()
    missing = sorted(_FORMERLY_HAND_DECLARED - set(derived))
    assert not missing, (
        f"the derivation no longer reaches {missing} on textual {textual.__version__} "
        "-- do not re-add a hand-written list; fix the derivation"
    )


def test_at_b83_06_type_addressing_is_not_an_address() -> None:
    """`get_child_by_type` takes a TYPE and must never enter the set.

    It was got wrong twice during this batch's design -- once called nonexistent (it
    exists, on App and every Widget subclass), once called a plain-`str` API (its only
    parameter is `type[ExpectType]`). It is type-addressing, which the report itself
    declares is not a computed address.

    Kill mutation: drop the str-annotation filter from `_textual_methods` -> the taint
    pass promotes it and this goes red.
    """
    derived, _ = derive_address_params()
    assert "get_child_by_type" not in derived, (
        "get_child_by_type was derived as an address API; its parameter is a type, "
        "not a selector"
    )
    assert "get_child_by_type" not in ADDRESS_APIS


# ------------------------------------------------------------ AT-B83-07 · keyword arguments

@pytest.mark.parametrize(
    "source",
    [
        'app.query_one(selector=f"#{widget_id}")',
        'await pilot.click(widget=f"#{button_id}")',
    ],
)
def test_at_b83_07_keyword_arguments_are_scanned(source: str) -> None:
    """A selector passed by keyword is an address, and must be reported.

    Kill mutation: iterate `node.args` only -> both fixtures vanish. The tool carried
    exactly this defect (`address_census.py:370`), invisible because the tree happens to
    hold 0 such calls today.
    """
    sites, _ = census_source(source, "fixture.py")
    assert len(sites) == 1, f"keyword selector not seen in: {source}"
    assert sites[0].form == "fstring"
    assert sites[0].shape == "#{}"


# ------------------------------------------------- AT-B83-08 · the no-flow-tracking premise

@pytest.mark.parametrize(
    "source, expected",
    [
        ('app.query_one("#" + name)', "other:BinOp"),
        ('app.query_one("#%s" % n)', "other:BinOp"),
        ('app.query_one("#{}".format(n))', "other:Call"),
    ],
)
def test_at_b83_08_assembled_selectors_are_flagged_on_a_fixture(
    source: str, expected: str
) -> None:
    """RED FIRST: the detector must SEE an assembled selector, on a fixture.

    Without this, the tree-wide assertion below is the canonical vacuous check -- an
    invariant over a tree with zero violations passes identically whether the detection
    logic is correct, broken, or unwritten.
    """
    forms = [f for f, _ in _forms(source)]
    assert forms == [expected]


def test_at_b83_08_tree_holds_no_assembled_selectors() -> None:
    """The premise that makes the detector cheap: no flow tracking is needed.

    Meaningful only because the fixture above proves detection works. If this ever goes
    red, 'recognise the site' has stopped being sufficient and the design needs revisiting
    -- which is the point of the guard.
    """
    from pathlib import Path
    from tools.address_census import census

    root = Path(__file__).resolve().parent.parent
    data = census(root)
    odd = [s for s in data.sites if s.form.startswith("other:")]
    assert not odd, (
        "address arguments outside {literal, name, fstring} appeared: "
        + ", ".join(f"{s.file}:{s.line} {s.form}" for s in odd[:10])
    )


# ------------------------------------------------------- AT-B83-09 · the name split, measured

def test_at_b83_10_indirect_address_is_detected_on_a_fixture() -> None:
    """RED FIRST: an f-string reaching a query through a variable must be reported.

    The census follows zero hops by design, so this pattern otherwise reports as an
    unrelated loose f-string PLUS a bare-name argument, and neither row says "computed
    address". This detector recognises the one shape that matters: assign, then use,
    inside one function.

    Kill mutation: drop the `assigned` lookup -> the row vanishes and the pattern goes
    back to being invisible.
    """
    src = (
        "def build(app, panel_id):\n"
        '    sel = f"#{panel_id}"\n'
        "    return app.query_one(sel)\n"
    )
    rows = find_indirect_addresses(src, "fixture.py")
    assert len(rows) == 1
    assert rows[0].form == "fstring-via-name"
    assert rows[0].shape == "#{}"
    assert rows[0].api == "query_one"
    assert "sel" in rows[0].note


def test_at_b83_10_tree_holds_no_indirect_addresses() -> None:
    """The zero-hops premise, made checkable instead of merely declared.

    Meaningful only because the fixture above proves detection works. Measured today: 0.
    The day this goes red, the census's own numbers are undercounting and the design
    needs revisiting -- which is exactly what a declared blind spot cannot tell you.
    """
    from pathlib import Path
    from tools.address_census import iter_python_files

    root = Path(__file__).resolve().parent.parent
    hits: List[Any] = []
    for path in iter_python_files(root):
        hits += find_indirect_addresses(
            path.read_text(encoding="utf-8"), path.relative_to(root).as_posix()
        )
    assert not hits, (
        "f-strings now reach an address through a variable; the census undercounts: "
        + ", ".join(f"{h.file}:{h.line} ({h.note})" for h in hits[:10])
    )


def test_at_b83_11_every_derived_name_obeys_the_exclusion_rules() -> None:
    """No entry may violate the rules that were supposed to have filtered it.

    **This guard exists because its absence let a real defect through.** The candidate
    filter was applied in the collection pass but NOT in the annotation pass, so three
    private methods (`_move_focus`, `_post_mouse_events`, `_find_mount_point`) walked
    back in through the second door. Nothing failed. It surfaced only because the rule
    predicted 40 entries and the output showed 43 -- an arithmetic check a human did
    once, by hand, and would not do again.

    A criterion applied in one of two places is not a criterion, and a rule with no
    assertion over its own output is a comment.

    Kill mutation: drop the `is_candidate_method` call from the annotation pass ->
    3 private names reappear and this goes red.
    """
    offenders = sorted(n for n in ADDRESS_PARAMS if not is_candidate_method(n))
    assert not offenders, (
        f"the snapshot holds names the exclusion rules forbid: {offenders}"
    )

    derived, _ = derive_address_params()
    live_offenders = sorted(n for n in derived if not is_candidate_method(n))
    assert not live_offenders, (
        f"the live derivation produces names its own rules forbid: {live_offenders} "
        "-- a filter is being applied in one pass and not another"
    )


def test_at_b83_12_bare_name_rows_carry_their_identifier() -> None:
    """A `name` row must record WHICH name, or every reading of it is silently empty.

    **This guard exists because its absence would have shipped a lie.** `AddressSite.shape`
    was populated for f-strings but not for bare names, so the report's class-like split
    computed `resolves_to_class_like("")` for all 183 rows and would have printed
    `0 of 183` -- a plausible-looking number, produced by a field nobody filled.

    It was caught by writing the line that prints it, not by any assertion.

    Kill mutation: stop assigning `site.shape = arg.id` -> the fixture's shapes go None.
    """
    src = "app.query_one(Input)\napp.query_one(selector)\n"
    sites, _ = census_source(src, "fixture.py")
    assert [s.form for s in sites] == ["name", "name"]
    assert [s.shape for s in sites] == ["Input", "selector"], (
        "bare-name rows lost their identifier; any split computed from `shape` "
        "silently reads empty"
    )

    from pathlib import Path
    from tools.address_census import census

    data = census(Path(__file__).resolve().parent.parent)
    unnamed = [s for s in data.sites if s.form == "name" and not s.shape]
    assert not unnamed, (
        f"{len(unnamed)} bare-name rows carry no identifier tree-wide, e.g. "
        f"{unnamed[0].file}:{unnamed[0].line}"
    )


def test_at_b83_09_bare_names_are_split_by_measurement() -> None:
    """`name` arguments split into class-like (type-addressing) and everything else.

    Revision 1 called this bucket 'overwhelmingly type-addressing' -- an adverb standing
    in for a number. A lowercase name is the population most likely to hold a computed
    selector one assignment away, and it must not hide inside the type-addressing count.

    Kill mutation: return a single 'name' bucket -> the split disappears.
    """
    src = (
        "app.query_one(Input)\n"
        "app.query_one(selector)\n"
        "app.query_one(_B78_RUN_ENTRY)\n"
    )
    sites, _ = census_source(src, "fixture.py")
    assert [s.form for s in sites] == ["name", "name", "name"]
    assert resolves_to_class_like("Input") is True
    assert resolves_to_class_like("selector") is False
    assert resolves_to_class_like("_B78_RUN_ENTRY") is False
