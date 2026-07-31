"""
AT/TC id registry — the shared corpus/grammar library.

This module is the **single implementation** of every definition that
``AT-TC-REGISTRY.jsonl`` (the allocation authority) and
``tests/test_id_registry.py`` (its guard) both depend on: what an id token is,
how two spellings of one id compare, which files are scanned, and how a test
node is derived from the source tree.

Why it is one module and not two: the defect this registry exists to close is
*"an unstated grep pattern is an unstated definition"* — the design spec
(`.dev-flow/AT-TC-REGISTRY-SPEC.md` §1.2) measured two honest greps disagreeing
by 46 ids on the same commit. A seeder and a guard carrying private copies of
the pattern would reproduce that failure inside the fix. They import from here.

Grammar (spec §2.1)::

    id      ::= space "-" stem [ suffix ]
    space   ::= "AT" | "TC"
    stem    ::= digit+ [ "." digit+ ]
    suffix  ::= lowercase-letter+

Tokenisation is deliberately **wider** than the grammar: :data:`TOKEN_RE`
matches every ``AT-``/``TC-`` token in the corpus, and
:func:`classify` then sorts each one into governed-conforming,
governed-non-conforming, or ungoverned. A tokeniser narrowed to the grammar
would make non-conforming legacy tokens invisible, and invisible is precisely
what G5 exists to prevent.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

__all__ = [
    "TOKEN_RE",
    "CONFORMING_BODY_RE",
    "REGISTRY_FILENAME",
    "STATUSES",
    "IdToken",
    "RegistryEntry",
    "Registry",
    "classify",
    "normalize",
    "repo_root",
    "scanned_test_files",
    "requirements_path",
    "registry_path",
    "iter_tokens",
    "derive_named_nodes",
    "derive_citation_nodes",
    "defined_names",
    "load_registry",
]


# ---------------------------------------------------------------------------
# Tokenisation
# ---------------------------------------------------------------------------

#: Maximal-munch id token.
#:
#: The body may contain ``.`` or ``-`` **only when followed by an alphanumeric**.
#: That single restriction is what makes the pattern correct on the real corpus:
#:
#: * ``TC-001..TC-004``   -> two tokens ``TC-001`` and ``TC-004`` (``..`` stops the
#:   munch instead of being swallowed into a bogus ``TC-001..TC`` body);
#: * ``AT-039e.`` at the end of a sentence -> ``AT-039e`` (the period is prose);
#: * ``TC-078.4.``        -> ``TC-078.4`` (dotted stem kept, sentence period dropped);
#: * ``TC-024-color``     -> one token, not ``TC-024`` plus noise;
#: * ``AT-B64-04``        -> one token whose body starts with a letter, i.e. a
#:   batch-scoped id that spec §2.3 puts outside the allocation authority.
TOKEN_RE = re.compile(r"\b(AT|TC)-([A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)")

#: A governed body that conforms to the §2.1 grammar.
CONFORMING_BODY_RE = re.compile(r"\d+(?:\.\d+)?[a-z]*\Z")

#: Function-name form (§2.4 form 1).
#:
#: All four attested spellings are covered, and the corpus was enumerated before
#: this pattern was written rather than after:
#:
#: * ``test_at001_...``      — the common form;
#: * ``test_at_033a_...``    — underscore-separated (54 nodes use it, and an
#:   earlier draft of this pattern silently reported every one of them as a
#:   phantom, which is the exact defect the registry exists to prevent);
#: * ``test_tc46_1_...``     — dotted stem written with ``_``;
#: * ``test_at220_tc521_...``— **two ids on one node**, hence :func:`re.finditer`
#:   at every call site rather than ``search``.
_FUNC_ID_RE = re.compile(r"(?:^|_)(at|tc)_?(\d+(?:_\d+)?)([a-z]+)?(?=_|\Z)", re.IGNORECASE)

#: Class-name form (§2.4 form 2): ``class TestTc307ValidRoundTrip``. ``TC-310`` is
#: carried by four such classes, which is why the mapping is N:M (spec §8.1).
_CLASS_ID_RE = re.compile(r"(?:^|Test)(At|Tc)(\d+(?:_\d+)?)([a-z]*?)(?=[A-Z_]|\Z)")

_NORM_RE = re.compile(r"(\d+)(?:\.(\d+))?([a-z]*)\Z")

REGISTRY_FILENAME = "AT-TC-REGISTRY.jsonl"

STATUSES = ("LIVE", "RESERVED", "RETIRED", "BURNED")


@dataclass(frozen=True)
class IdToken:
    """One tokenised ``AT-``/``TC-`` occurrence, already classified.

    Attributes:
        raw: The verbatim token as it appears in the corpus, e.g. ``"TC-046.1"``.
        space: ``"AT"`` or ``"TC"``.
        body: Everything after the space and its hyphen, e.g. ``"046.1"``.
        governed: ``True`` when the body starts with a digit. A letter-initial
            body (``AT-B64-04``, ``AT-CRC-DSN-010``, the ``AT-NNN`` prose
            placeholder) is a §2.3 batch-scoped / named-subspace / placeholder
            token and is outside the allocation authority entirely.
        conforming: ``True`` when the body parses per the §2.1 grammar. Only
            meaningful for governed tokens.
        key: The normalised comparison key (see :func:`normalize`), or ``None``
            for ungoverned tokens, which have no allocation identity.
    """

    raw: str
    space: str
    body: str
    governed: bool
    conforming: bool
    key: Optional[str]


def normalize(space: str, body: str) -> str:
    """
    Summary:
        Reduce an id to its comparison key by stripping leading zeros from every
        numeric component and lower-casing the suffix, so ``AT-065b`` and
        ``AT-65b`` are recognised as the *same* id rather than two allocations
        (spec §2.2, zero-padding ruling).

    Args:
        space (str): ``"AT"`` or ``"TC"``.
        body (str): The token body, e.g. ``"065b"`` or ``"046.1"``.

    Returns:
        str: The normalised key, e.g. ``"AT-65b"`` or ``"TC-46.1"``. A body that
        does not parse as a stem is lower-cased and returned as-is, which keeps
        non-conforming legacy tokens comparable without pretending they parse.

    Data Flow:
        - Splits ``body`` into integer stem, optional dotted sub-stem and suffix,
          re-renders each numeric part through ``int()`` to drop padding.

    Dependencies:
        Used by:
            - classify
            - derive_named_nodes
            - Registry.key_for

    Example:
        >>> normalize("AT", "065b")
        'AT-65b'
        >>> normalize("TC", "046.1")
        'TC-46.1'
    """
    match = _NORM_RE.fullmatch(body)
    if match is None:
        return f"{space}-{body.lower()}"
    whole, sub, suffix = match.group(1), match.group(2), match.group(3)
    stem = str(int(whole)) + (f".{int(sub)}" if sub is not None else "")
    return f"{space}-{stem}{suffix}"


def classify(space: str, body: str) -> IdToken:
    """
    Summary:
        Turn a raw ``(space, body)`` pair into a classified :class:`IdToken`,
        deciding in one place whether the token is governed by the registry and
        whether it conforms to the §2.1 grammar.

    Args:
        space (str): ``"AT"`` or ``"TC"``.
        body (str): The token body as matched by :data:`TOKEN_RE`.

    Returns:
        IdToken: The classified token.

    Data Flow:
        - ``body[0].isdigit()`` decides *governed*; :data:`CONFORMING_BODY_RE`
          decides *conforming*; :func:`normalize` supplies the key.

    Dependencies:
        Uses:
            - normalize
        Used by:
            - iter_tokens

    Example:
        >>> classify("AT", "B64-04").governed
        False
        >>> classify("TC", "024-color").conforming
        False
    """
    governed = bool(body) and body[0].isdigit()
    conforming = governed and CONFORMING_BODY_RE.fullmatch(body) is not None
    return IdToken(
        raw=f"{space}-{body}",
        space=space,
        body=body,
        governed=governed,
        conforming=conforming,
        key=normalize(space, body) if governed else None,
    )


def iter_tokens(text: str) -> Iterator[Tuple[IdToken, int]]:
    """
    Summary:
        Yield every classified id token in ``text`` together with its 1-based
        line number.

    Args:
        text (str): The file contents to scan.

    Returns:
        Iterator[Tuple[IdToken, int]]: ``(token, line_number)`` pairs in source
        order.

    Data Flow:
        - Drives :data:`TOKEN_RE` over ``text``; the line number is derived by
          counting newlines before each match start.

    Dependencies:
        Uses:
            - classify
        Used by:
            - derive_citation_nodes
            - the G3/G4/G5 rules in tests/test_id_registry.py
    """
    # Precompute line starts once so the scan stays linear rather than counting
    # newlines from position 0 for every match.
    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)

    import bisect

    for match in TOKEN_RE.finditer(text):
        line = bisect.bisect_right(line_starts, match.start())
        yield classify(match.group(1), match.group(2)), line


# ---------------------------------------------------------------------------
# Corpus bounds (spec §7.1)
# ---------------------------------------------------------------------------

_EXCLUDED_TEST_DIRS = ("goldens", "__snapshots__", "_artifacts", "__pycache__")


def repo_root(start: Optional[Path] = None) -> Path:
    """
    Summary:
        Resolve the repository root — the directory carrying both ``.git`` and
        ``pyproject.toml`` — by walking up from ``start``.

    Args:
        start (Optional[Path]): Where to begin the walk. Defaults to this
            module's directory, so the answer is independent of the caller's
            working directory.

    Returns:
        Path: The absolute repository-root path.

    Raises:
        RuntimeError: When no ancestor carries both markers.

    Dependencies:
        Used by:
            - scanned_test_files
            - registry_path
            - requirements_path
    """
    here = (start or Path(__file__)).resolve()
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists() and (candidate / "pyproject.toml").exists():
            return candidate
    raise RuntimeError(
        "could not locate the repository root — the id registry needs the "
        "source checkout, not an installed distribution"
    )


def scanned_test_files(root: Optional[Path] = None) -> List[Path]:
    """
    Summary:
        Return the ``tests/`` Python files the registry scans, sorted, with the
        binary/golden subtrees of spec §7.1 excluded.

    Args:
        root (Optional[Path]): Repository root; resolved via :func:`repo_root`
            when omitted.

    Returns:
        List[Path]: Absolute paths, sorted, of every scanned test module.

    Data Flow:
        - Globs ``tests/**/*.py`` and drops any path with an excluded directory
          component.

    Dependencies:
        Uses:
            - repo_root
        Used by:
            - the G1/G2/G3 rules and the §7.3 corpus-bound assertion
    """
    base = (root or repo_root()) / "tests"
    return sorted(
        path
        for path in base.rglob("*.py")
        if not any(part in _EXCLUDED_TEST_DIRS for part in path.relative_to(base).parts)
    )


def requirements_path(root: Optional[Path] = None) -> Path:
    """Return the absolute path of ``REQUIREMENTS.md``."""
    return (root or repo_root()) / "REQUIREMENTS.md"


def registry_path(root: Optional[Path] = None) -> Path:
    """Return the absolute path of ``AT-TC-REGISTRY.jsonl``."""
    return (root or repo_root()) / REGISTRY_FILENAME


def read_text(path: Path) -> str:
    """Read ``path`` as UTF-8, replacing undecodable bytes rather than raising."""
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Node derivation (spec §2.4)
# ---------------------------------------------------------------------------


def _node_defs(tree: ast.AST) -> List[Tuple[str, int, int]]:
    """Return ``(name, lineno, end_lineno)`` for every function/class in ``tree``."""
    out: List[Tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            out.append((node.name, node.lineno, end))
    return out


def defined_names(source: str) -> Set[str]:
    """
    Summary:
        Return the set of every function and class name defined in ``source`` —
        the existence oracle a node reference is checked against by G2.

    Args:
        source (str): Python source text.

    Returns:
        Set[str]: All ``def`` / ``async def`` / ``class`` names, at any nesting
        depth. Methods are included under their bare name because a node
        reference names *a name in a file*, never a parametrised case
        (spec §2.4, closing paragraph).

    Raises:
        SyntaxError: Propagated from :func:`ast.parse`.

    Dependencies:
        Uses:
            - ast.parse
        Used by:
            - the G2 rule in tests/test_id_registry.py
    """
    return {name for name, _, _ in _node_defs(ast.parse(source))}


def derive_named_nodes(
    files: Sequence[Path], root: Path, attested: Optional[Set[str]] = None
) -> Dict[str, Set[str]]:
    """
    Summary:
        Derive id -> node bindings from **node names** — spec §2.4 forms 1 and 2,
        the two machine-derivable forms.

    Args:
        files (Sequence[Path]): Test modules to scan.
        root (Path): Repository root, used to render node refs repo-relative.
        attested (Optional[Set[str]]): Normalised keys known to be cited
            somewhere in the corpus. Used to disambiguate ``digits_digits``
            names — see the note below. When ``None`` every such name is read
            as a dotted stem.

    Returns:
        Dict[str, Set[str]]: Normalised id key -> set of ``path::name`` refs.
        The mapping is N:M in both directions by construction: one id may be
        carried by several nodes (``TC-310`` is carried by four classes) and one
        node may carry several ids (``test_at220_tc521_...`` carries two).

    Data Flow:
        - ``ast.parse`` each file -> walk function/class defs -> ``finditer``
          :data:`_FUNC_ID_RE` / :data:`_CLASS_ID_RE` over the name ->
          :func:`normalize` each captured id.

    Dependencies:
        Uses:
            - normalize
        Used by:
            - the G1 rule in tests/test_id_registry.py
            - tools/seed_id_registry.py

    Note:
        ``test_tc078_1_...`` means ``TC-078.1``, but ``test_at_058_01_...`` means
        the batch-scoped ``AT-058-01`` — the same shape, two different ids, and
        no spelling rule separates them. Rather than guess, the dotted reading is
        taken **only when that dotted id is actually cited somewhere in the
        corpus**; otherwise the trailing group is treated as prose and the bare
        stem is used. Inventing ``AT-58.1``, an id no document has ever
        contained, would put a fabricated allocation into the authority.
    """
    bindings: Dict[str, Set[str]] = {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(read_text(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                pattern = _FUNC_ID_RE
            elif isinstance(node, ast.ClassDef):
                pattern = _CLASS_ID_RE
            else:
                continue
            for match in pattern.finditer(node.name):
                space = match.group(1).upper()
                digits = match.group(2)
                suffix = (match.group(3) or "").lower()
                key = normalize(space, digits.replace("_", ".") + suffix)
                if "_" in digits and attested is not None and key not in attested:
                    key = normalize(space, digits.split("_")[0] + suffix)
                bindings.setdefault(key, set()).add(f"{rel}::{node.name}")
    return bindings


def _module_docstring_end(tree: ast.Module) -> int:
    """Return the last line of the module docstring, or 0 when there is none."""
    body = getattr(tree, "body", None)
    if not body:
        return 0
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(
        first.value.value, str
    ):
        return getattr(first, "end_lineno", None) or first.lineno
    return 0


def derive_citation_nodes(files: Sequence[Path], root: Path) -> Dict[str, Set[str]]:
    """
    Summary:
        Derive id -> node bindings from **citations that are not part of a node
        name** — spec §2.4 form 3, the form the spec calls "not derivable" and
        requires to be declared explicitly. It is derivable after all, in two
        attested shapes, and this function proposes those bindings for the seed.

    Args:
        files (Sequence[Path]): Test modules to scan.
        root (Path): Repository root, used to render node refs repo-relative.

    Returns:
        Dict[str, Set[str]]: Normalised id key -> set of ``path::name`` refs.

    Data Flow:
        Two shapes, applied in order, both verified against the corpus before
        being encoded:

        1. **Enclosing** — the citation falls inside a node's line span, e.g. an
           id named in a test's docstring
           (``tests/test_report_service.py::test_report_includes_legend_with_documented_rows``
           carries ``AT-022a`` that way). Binds to the innermost such node.
        2. **Banner** — the citation sits in the gap *between* nodes, in the
           section-header comment the repo uses consistently::

               # -------------------------------------------------
               # AT-220 / TC-521 — the overlap counterexample
               # -------------------------------------------------
               def test_at220_tc521_overlap_counterexample_...

           Binds to the next node defined after the citation.

        Citations inside the **module docstring** are deliberately excluded from
        the banner shape: a module docstring enumerating a file's ids is a
        summary, not a binding, and binding it to whichever function happens to
        come first would invent a relationship the source never asserted. Those
        ids stay unbound here and are dispositioned explicitly instead — which
        is the honest outcome, and needs no window constant to justify.

    Dependencies:
        Uses:
            - iter_tokens
        Used by:
            - tools/seed_id_registry.py

    Note:
        This is a *seeding aid*, not a guard rule. It proposes the bindings the
        seed writes into ``nodes``; once written they are data the guard checks,
        so a later rename fails G2 loudly rather than being silently re-derived
        into a different answer.
    """
    bindings: Dict[str, Set[str]] = {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        text = read_text(path)
        if "AT-" not in text and "TC-" not in text:
            continue
        tree = ast.parse(text)
        spans = _node_defs(tree)
        docstring_end = _module_docstring_end(tree)
        for token, line in iter_tokens(text):
            if not token.governed or token.key is None:
                continue
            containing = [s for s in spans if s[1] <= line <= s[2]]
            if containing:
                name = max(containing, key=lambda s: s[1])[0]
            elif line > docstring_end:
                following = [s for s in spans if s[1] > line]
                if not following:
                    continue
                name = min(following, key=lambda s: s[1])[0]
            else:
                continue
            bindings.setdefault(token.key, set()).add(f"{rel}::{name}")
    return bindings


# ---------------------------------------------------------------------------
# Registry I/O
# ---------------------------------------------------------------------------


@dataclass
class RegistryEntry:
    """One allocation record — a single line of ``AT-TC-REGISTRY.jsonl``."""

    id: str
    space: str
    status: str
    origin: str
    conforming: bool
    statement: Optional[str] = None
    nodes: List[str] = field(default_factory=list)
    reserved_by: Optional[str] = None
    retired_reason: Optional[str] = None
    provenance: Optional[str] = None
    raw: Dict[str, object] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """The normalised comparison key for this entry's id."""
        space, _, body = self.id.partition("-")
        return normalize(space, body)

    @property
    def stem(self) -> Optional[int]:
        """The integer stem, or ``None`` when the body does not start with digits."""
        _, _, body = self.id.partition("-")
        match = re.match(r"\d+", body)
        return int(match.group(0)) if match else None


@dataclass
class Registry:
    """The parsed registry: its metadata header plus every allocation entry."""

    meta: Dict[str, object]
    entries: List[RegistryEntry]

    def by_key(self) -> Dict[str, RegistryEntry]:
        """Return ``normalised key -> entry``; duplicates keep the first seen."""
        out: Dict[str, RegistryEntry] = {}
        for entry in self.entries:
            out.setdefault(entry.key, entry)
        return out

    def high_water(self, space: str) -> int:
        """
        Summary:
            Return the allocation high-water mark for ``space`` — the largest
            stem among **conforming** entries (spec §4.1).

        Args:
            space (str): ``"AT"`` or ``"TC"``.

        Returns:
            int: The high-water stem, or ``0`` when the space is empty.

        Note:
            ``conforming`` gates the maximum precisely because ``TC-1728`` is a
            real corpus token 1177 above its neighbour. Including it would set
            the next free TC id to 1729 on day one.
        """
        stems = [
            entry.stem
            for entry in self.entries
            if entry.space == space and entry.conforming and entry.stem is not None
        ]
        return max(stems) if stems else 0

    def next_free(self, space: str) -> int:
        """Return the next mintable stem for ``space`` — monotonic, no gap-filling."""
        return self.high_water(space) + 1


def load_registry(path: Optional[Path] = None) -> Registry:
    """
    Summary:
        Parse ``AT-TC-REGISTRY.jsonl`` into a :class:`Registry`.

    Args:
        path (Optional[Path]): Registry path; resolved via :func:`registry_path`
            when omitted.

    Returns:
        Registry: The metadata header and every allocation entry, in file order.

    Raises:
        ValueError: When the first line is not a ``_meta`` header, when a line is
            not valid JSON, or when an entry omits a required key. The registry
            is an authority; a silently half-parsed authority is worse than none.

    Data Flow:
        - Reads the file line by line; line 1 must carry ``_meta``; every
          subsequent non-blank line becomes a :class:`RegistryEntry`.

    Dependencies:
        Uses:
            - registry_path
        Used by:
            - every rule in tests/test_id_registry.py
    """
    target = path or registry_path()
    lines = [line for line in read_text(target).splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"{target} is empty — the registry must carry a _meta header")

    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError as exc:  # pragma: no cover - malformed authority
        raise ValueError(f"{target}:1 is not valid JSON: {exc}") from exc
    if "_meta" not in header:
        raise ValueError(f"{target}:1 must be the '_meta' header line")

    entries: List[RegistryEntry] = []
    for number, line in enumerate(lines[1:], start=2):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{target}:{number} is not valid JSON: {exc}") from exc
        missing = [k for k in ("id", "space", "status", "origin", "conforming") if k not in record]
        if missing:
            raise ValueError(f"{target}:{number} missing required key(s): {missing}")
        entries.append(
            RegistryEntry(
                id=record["id"],
                space=record["space"],
                status=record["status"],
                origin=record["origin"],
                conforming=bool(record["conforming"]),
                statement=record.get("statement"),
                nodes=list(record.get("nodes", [])),
                reserved_by=record.get("reserved_by"),
                retired_reason=record.get("retired_reason"),
                provenance=record.get("provenance"),
                raw=record,
            )
        )
    return Registry(meta=dict(header["_meta"]), entries=entries)


def dump_entry(record: Dict[str, object]) -> str:
    """Render one registry record as a canonical single JSONL line."""
    ordered = {}
    for key in (
        "id",
        "space",
        "status",
        "conforming",
        "origin",
        "statement",
        "nodes",
        "reserved_by",
        "retired_reason",
        "provenance",
    ):
        if key in record and record[key] is not None:
            ordered[key] = record[key]
    return json.dumps(ordered, ensure_ascii=False, sort_keys=False)


def sort_key(record: Dict[str, object]) -> Tuple[str, float, int, str]:
    """Sort key implementing spec §3.1: ``(space, normalised stem, suffix)``."""
    identifier = str(record["id"])
    space, _, body = identifier.partition("-")
    match = re.match(r"(\d+)(?:\.(\d+))?", body)
    if match:
        whole = int(match.group(1))
        sub = int(match.group(2)) if match.group(2) else 0
        rest = body[match.end():]
    else:
        whole, sub, rest = 10**9, 0, body
    return (space, whole, sub, rest)


def iter_corpus(root: Path, include_devflow: bool = False) -> Iterable[Tuple[str, str]]:
    """Yield ``(repo-relative path, text)`` for the scanned corpus."""
    for path in scanned_test_files(root):
        yield path.relative_to(root).as_posix(), read_text(path)
    req = requirements_path(root)
    if req.exists():
        yield "REQUIREMENTS.md", read_text(req)
    if include_devflow:
        for folder in (".dev-flow", ".fast-dev-flow"):
            base = root / folder
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    yield path.relative_to(root).as_posix(), read_text(path)
