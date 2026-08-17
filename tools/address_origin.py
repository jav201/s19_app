"""Where does a bare-name widget address actually come from?

``tools/address_census.py`` answers *what an address argument looks like*. That is the
question that left a hole: an assembled selector has no selector shape, so every net
keyed on shape misses it. This module answers the other question — *where the value
came from* — for exactly the population in which an assembled selector can hide.

That population is not the tree. It is
:func:`tools.address_census.bare_name_candidates`: the address arguments written as a
bare identifier that is not a widget class. Both escapes an assembled selector can take
land there, and nowhere else::

    prefix = "#panel_"
    sel = f"{prefix}{name}"      # shape is "{}{}" -- matches no selector pattern
    app.query_one(sel)           # argument is a bare Name

    sel = "#" + widget_id        # a BinOp, but not IN an address argument
    app.query_one(sel)           # argument is a bare Name

Each candidate is resolved to the bindings of its name in its own file, and classified:

    A  every binding is a string literal          resolvable by grep, not a blind spot
    B  some binding is assembled                  the blind spot, confirmed
    C  some binding is a function parameter       the caller decides
    D  anything else                              sub-kind named, never lumped
    U  no binding in the file at all              reported, never dropped

**The walk is deliberately scope-insensitive.** It reports a binding written anywhere in
the file, including in a function that can never reach the site. That over-collects, and
that is the point: this module's expected answer is a NEGATIVE one — that no candidate is
assembled — and a negative result is only worth having if the search that produced it was
too wide rather than too narrow. Making the walk scope-precise would silently weaken every
such claim, so ``AT-B84-05`` fails if anyone does.

Run it::

    python tools/address_origin.py

Guards: ``tests/test_address_origin.py`` (``AT-B84-01``..``AT-B84-07``).
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):  # pragma: no cover - direct `python tools/...` run
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.address_census import (  # noqa: E402
    AddressSite,
    bare_name_candidates,
    census,
)

__all__ = [
    "ASSEMBLED_KINDS",
    "Binding",
    "OriginRow",
    "bare_name_candidates",
    "classify",
    "collect_bindings",
    "kind_of_value",
    "report",
    "resolve_origins",
]

#: Value kinds that mean the string was BUILT rather than written. The membership test
#: for outcome B, kept as data so ``AT-B84-04``'s kill mutation is a one-line edit that
#: turns the guard red instead of a refactor that hides it.
ASSEMBLED_KINDS: frozenset[str] = frozenset(
    {"fstring", "concat", "percent-format", "call:.format"}
)


@dataclass
class Binding:
    """One place a candidate's name is given a value.

    Attributes:
        kind: How the name was bound — ``assign``, ``param``, ``for-target``,
            ``unpack``, ``comp-target``, ``with-as``, ``import``, ``walrus``,
            ``except-as``.
        value: For binding forms that carry an expression, what that expression is
            (see :func:`kind_of_value`). Empty for forms that do not, such as a
            parameter, where the value is the caller's.
        file: Repo-relative path of the binding.
        line: 1-indexed line of the binding.
    """

    kind: str
    value: str
    file: str
    line: int

    def evidence(self) -> str:
        """One line naming this binding and where to read it.

        Returns:
            ``'<kind>-><value> at <file>:<line>'``, or ``'<kind> at <file>:<line>'``
            when the form carries no expression.

        Dependencies:
            Used by: :func:`report`, and ``AT-B84-02``, which fails on an empty one.
        """
        what = f"{self.kind}->{self.value}" if self.value else self.kind
        return f"{what} at {self.file}:{self.line}"


@dataclass
class OriginRow:
    """One candidate address site, resolved and classified.

    Attributes:
        site: The address site, straight from the census.
        bindings: Every binding of its name found in its file, in source order.
        outcome: ``'A'``, ``'B'``, ``'C'``, ``'D'`` or ``'U'``.
        detail: For ``D``, the distinct value kinds that put it there, so the row
            says WHICH other thing it is; empty otherwise.
    """

    site: AddressSite
    bindings: list[Binding] = field(default_factory=list)
    outcome: str = "U"
    detail: str = ""

    def key(self) -> tuple[str, int, str]:
        """The site's identity, for set comparison against the census.

        Returns:
            ``(file, line, name)`` — a tuple rather than a count, because a count
            over the tree breaks on every legitimate change and proves nothing.

        Dependencies:
            Used by: ``AT-B84-01``.
        """
        return (self.site.file, self.site.line, self.site.shape or "")


def kind_of_value(node: ast.expr) -> str:
    """Name the kind of expression a binding assigns.

    Args:
        node: The right-hand side of a binding.

    Returns:
        ``'literal'`` for a string constant, ``'fstring'``, ``'concat'`` for ``+``,
        ``'percent-format'`` for ``%``, ``'call:.<attr>'`` / ``'call:<name>'`` for a
        call, otherwise the AST node type (``'Subscript'``, ``'IfExp'``, ...).

    Data Flow:
        binding RHS -> kind string -> ASSEMBLED_KINDS membership -> :func:`classify`

    Dependencies:
        Uses: :data:`ASSEMBLED_KINDS` (by producing the strings it holds).
        Used by: :func:`collect_bindings`.

    Note:
        ``+`` and ``%`` are reported as assembly without first proving the operands are
        strings. The bias is deliberate and one-directional: a wrong B is a row that
        prints its own evidence and can be dismissed by reading it, while a wrong A or D
        is a blind spot that looks measured. This module exists because of the second
        kind, so it errs into the first.

    Example:
        >>> kind_of_value(ast.parse('f"{a}{b}"', mode="eval").body)
        'fstring'
        >>> kind_of_value(ast.parse('"#" + wid', mode="eval").body)
        'concat'
    """
    if isinstance(node, ast.Constant):
        return "literal" if isinstance(node.value, str) else f"const:{type(node.value).__name__}"
    if isinstance(node, ast.JoinedStr):
        return "fstring"
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return "concat"
        if isinstance(node.op, ast.Mod):
            return "percent-format"
        return f"binop:{type(node.op).__name__}"
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            return f"call:.{func.attr}"
        if isinstance(func, ast.Name):
            return f"call:{func.id}"
        return "call:?"
    return type(node).__name__


def _targets_name(target: ast.expr, name: str) -> str:
    """Does an assignment target bind ``name``, and how?

    Args:
        target: An assignment / loop / with target expression.
        name: The identifier being resolved.

    Returns:
        ``'direct'`` when the target IS the name, ``'unpack'`` when the name sits
        inside a tuple or list target, ``''`` when it does not bind at all.

    Dependencies:
        Used by: :func:`collect_bindings`.

    Note:
        Unpacking is separated from a direct bind because the value is then an ELEMENT
        of the right-hand side, not the right-hand side — reporting ``a, b = x`` as
        ``assign->Name`` would be a true statement about the wrong expression.
    """
    if isinstance(target, ast.Name):
        return "direct" if target.id == name else ""
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in ast.walk(target):
            if isinstance(element, ast.Name) and element.id == name:
                return "unpack"
    if isinstance(target, ast.Starred):
        return _targets_name(target.value, name)
    return ""


def collect_bindings(tree: ast.AST, name: str, filename: str) -> list[Binding]:
    """Find every binding of one identifier anywhere in one module.

    Args:
        tree: The parsed module.
        name: The identifier to resolve.
        filename: Repo-relative path, carried into each :class:`Binding` as evidence.

    Returns:
        Every binding found, sorted by line. Empty when the name is bound nowhere in
        this file — which is a result (outcome ``U``), not a failure.

    Data Flow:
        module AST -> ast.walk -> binding nodes naming `name` -> [Binding]

    Dependencies:
        Uses: :func:`kind_of_value`, :func:`_targets_name`.
        Used by: :func:`resolve_origins`.

    Note:
        **Scope-insensitive on purpose, and guarded as such by ``AT-B84-05``.** A binding
        in an unrelated function of the same file is reported. This over-collects; see
        this module's docstring for why the negative result depends on it.

    Example:
        >>> t = ast.parse('sel = "#" + wid')
        >>> [b.kind + "->" + b.value for b in collect_bindings(t, "sel", "p.py")]
        ['assign->concat']
    """
    found: list[Binding] = []

    def add(kind: str, value: str, node: ast.AST) -> None:
        found.append(Binding(kind, value, filename, getattr(node, "lineno", 0)))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                how = _targets_name(target, name)
                if how == "direct":
                    add("assign", kind_of_value(node.value), node)
                elif how == "unpack":
                    add("unpack", kind_of_value(node.value), node)
        elif isinstance(node, ast.AnnAssign):
            if _targets_name(node.target, name) and node.value is not None:
                add("assign", kind_of_value(node.value), node)
        elif isinstance(node, ast.AugAssign):
            if _targets_name(node.target, name) == "direct":
                # `sel += x` IS `sel = sel + x`. Reporting the right-hand OPERAND would
                # name a true thing about the wrong expression and hide the assembly,
                # so the operator decides the kind and the operand only breaks the tie.
                augmented = {ast.Add: "concat", ast.Mod: "percent-format"}.get(type(node.op))
                add("augassign", augmented or kind_of_value(node.value), node)
        elif isinstance(node, ast.NamedExpr):
            if _targets_name(node.target, name) == "direct":
                add("walrus", kind_of_value(node.value), node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            slots = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            slots += [a for a in (args.vararg, args.kwarg) if a is not None]
            for arg in slots:
                if arg.arg == name:
                    add("param", "", arg)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            how = _targets_name(node.target, name)
            if how:
                add("for-target" if how == "direct" else "unpack", kind_of_value(node.iter), node)
        elif isinstance(node, ast.comprehension):
            how = _targets_name(node.target, name)
            if how:
                add("comp-target", kind_of_value(node.iter), node.iter)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None and _targets_name(node.optional_vars, name):
                add("with-as", kind_of_value(node.context_expr), node.context_expr)
        elif isinstance(node, ast.ExceptHandler):
            if node.name == name:
                add("except-as", "", node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == name:
                    add("import", "", node)

    return sorted(found, key=lambda b: b.line)


def classify(bindings: list[Binding]) -> tuple[str, str]:
    """Turn a candidate's bindings into one outcome.

    Args:
        bindings: Output of :func:`collect_bindings`.

    Returns:
        ``(outcome, detail)``. Outcome is ``'A'``, ``'B'``, ``'C'``, ``'D'`` or ``'U'``;
        detail names the distinct value kinds behind a ``'D'`` and is empty otherwise.

    Data Flow:
        [Binding] -> ASSEMBLED_KINDS test -> param test -> all-literal test -> outcome

    Dependencies:
        Uses: :data:`ASSEMBLED_KINDS`.
        Used by: :func:`resolve_origins`.

    Note:
        The order of the tests IS the tie-break rule for a name bound more than once,
        and it is biased toward B: one assembled binding out of five still makes the
        site a confirmed blind spot, because the question this module answers is
        "can an assembled selector reach here", not "does it usually".

    Example:
        >>> classify([Binding("assign", "literal", "p.py", 1)])
        ('A', '')
        >>> classify([Binding("assign", "literal", "p.py", 1),
        ...           Binding("assign", "concat", "p.py", 2)])
        ('B', '')
    """
    if not bindings:
        return "U", ""
    if any(b.value in ASSEMBLED_KINDS for b in bindings):
        return "B", ""
    if any(b.kind == "param" for b in bindings):
        return "C", ""
    if all(b.kind == "assign" and b.value == "literal" for b in bindings):
        return "A", ""
    kinds = sorted({b.value or b.kind for b in bindings})
    return "D", ",".join(kinds)


def resolve_origins(root: Path) -> list[OriginRow]:
    """Classify every bare-name address candidate in the tree.

    Args:
        root: Repository root.

    Returns:
        One :class:`OriginRow` per candidate, in census order. The row set is
        one-to-one with :func:`tools.address_census.bare_name_candidates` — asserted
        by ``AT-B84-01`` as set equality, never as a count.

    Raises:
        SyntaxError: If a candidate's file does not parse. Not caught — a resolver
            that silently skips a file it could not read reports a smaller blind
            spot than exists, which is the one direction that must never happen.

    Data Flow:
        census -> bare_name_candidates -> collect_bindings -> classify -> [OriginRow]

    Dependencies:
        Uses: :func:`tools.address_census.census`,
            :func:`tools.address_census.bare_name_candidates`,
            :func:`collect_bindings`, :func:`classify`.
        Used by: :func:`report`, :func:`main`.
    """
    data = census(root)
    trees: dict[str, ast.AST] = {}
    rows: list[OriginRow] = []
    for site in bare_name_candidates(data):
        if site.file not in trees:
            trees[site.file] = ast.parse((root / site.file).read_text(encoding="utf-8"))
        bindings = collect_bindings(trees[site.file], site.shape or "", site.file)
        outcome, detail = classify(bindings)
        rows.append(OriginRow(site=site, bindings=bindings, outcome=outcome, detail=detail))
    return rows


_LEGEND: tuple[tuple[str, str], ...] = (
    ("A", "every binding is a string literal -- resolvable by grep, not a blind spot"),
    ("B", "some binding is ASSEMBLED -- the blind spot, confirmed"),
    ("C", "some binding is a function parameter -- the caller decides"),
    ("D", "something else -- sub-kind named on the row, never lumped"),
    ("U", "no binding anywhere in the file -- reported, never dropped"),
)


def report(rows: list[OriginRow]) -> None:
    """Print the classification, every row carrying its evidence.

    Args:
        rows: Output of :func:`resolve_origins`.

    Returns:
        None. Writes to stdout, ASCII only — this repo is developed on a cp1252
        console and a UnicodeEncodeError in a measurement tool is a measurement that
        did not happen.

    Data Flow:
        [OriginRow] -> Counter by outcome -> per-outcome sections -> stdout

    Dependencies:
        Uses: :meth:`Binding.evidence`.
        Used by: :func:`main`.
    """
    tally = Counter(row.outcome for row in rows)
    print("=" * 74)
    print("ADDRESS ORIGIN -- %d bare-name candidates" % len(rows))
    print("=" * 74)
    for code, meaning in _LEGEND:
        print("  %s %4d   %s" % (code, tally.get(code, 0), meaning))
    print()
    for code, _ in _LEGEND:
        section = [row for row in rows if row.outcome == code]
        if not section:
            continue
        print("--- %s (%d) ---" % (code, len(section)))
        for row in section:
            head = "%s:%d  %s(%s)" % (
                row.site.file,
                row.site.line,
                row.site.api,
                row.site.shape,
            )
            print("  %s%s" % (head, ("  [%s]" % row.detail) if row.detail else ""))
            for binding in row.bindings:
                print("        %s" % binding.evidence())
            if not row.bindings:
                print("        no binding in this file")
        print()
    assembled = tally.get("B", 0)
    if assembled:
        print("%d candidate(s) are ASSEMBLED. Each is a computed address the census's" % assembled)
        print("f-string count does NOT include -- add them to it, with this definition.")
    else:
        print("No candidate is assembled. Every escape an assembled selector can take")
        print("ends as one of the rows above, and none of them is built -- so the")
        print("census's f-string count is complete WITH RESPECT TO THIS POPULATION.")
        print("That bound is the claim; it is not a claim about the whole tree.")
    print()
    print("What this does NOT resolve, stated so nobody reads it as resolved:")
    print("  - where a C's caller gets its argument (one hop, not followed)")
    print("  - what a D's collection holds (its elements are not read)")
    print("  - a value built INSIDE a conditional or boolean expression: the row is")
    print("    named by its node (IfExp, BoolOp) and its branches are not read")
    print("  - an address argument that is not a bare name -- self._sel and friends")
    print("    are form 'other:Attribute', outside this population entirely")
    print("  - anything bound in another file (outcome U)")


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Unused; accepted so the signature matches
            :func:`tools.address_census.main`.

    Returns:
        0 always. This is a measurement, not a gate — the gate is
        ``tests/test_address_origin.py``.

    Dependencies:
        Uses: :func:`resolve_origins`, :func:`report`.
    """
    report(resolve_origins(Path(".")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
