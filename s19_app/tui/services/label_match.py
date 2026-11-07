"""batch-103 Inc 4 — label similarity matcher (pure module).

Headless module that ranks A2L tag names against a typed query, for the A2L
Viewer's autocomplete and paste modal (Inc 7). It prepares a name list once
(:func:`build_label_index`) and ranks it per keystroke (:func:`rank`), each
result a :class:`LabelMatch` carrying the first rule the name meets, its total
edits (fuzzy only) and its match spans.

The match rules, in rank order, are exact · prefix · substring · token ·
fuzzy · subsequence (R-A2L-MATCH.5 … .10). Matching folds ``A``–``Z`` only
(:func:`_fold`), compares every other character by code point, and scores
fuzzy candidates with the banded optimal-string-alignment prefix distance
(:func:`_prefix_distance`). The module imports the standard library only
(``array``, ``bisect``, ``dataclasses``, ``enum``, ``typing``), keeps no state
between calls and performs no I/O, so a prepared :class:`LabelIndex` is safe
to share with a worker thread. Deterministic: no ``hash()``-dependent order.
"""

from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Mapping, NamedTuple, Sequence

# The six CTX-A2L-MATCH whitespace characters. Never a bare ``str.strip``,
# which also strips U+001C … U+001F, U+0085 and U+00A0 (E2-5).
_WHITESPACE = " \t\n\r\v\f"

# A-Z -> a-z translation table for _fold; every other character is kept, so a
# folded string is exactly as long as its source and spans index the source.
_FOLD_TABLE = str.maketrans({c: c + 32 for c in range(65, 91)})

# The trie needs each token's first 258 characters only: a prefix test needs
# at most 256 and a prefix distance of at most 2 needs at most 258 (E3S-03).
_TRIE_PREFIX = 258

# The fuzzy tier's switch (E5S-01, variant C): once at most this many
# candidates remain and they hold at most this many name-token occurrences in
# all, each remaining distinct query token is computed with _prefix_distance
# on those candidates' token ids only (one call per (query token, token id)).
_FUZZY_SWITCH_CAP = 512

# The fuzzy tier's cap (E5S-07, R-A2L-MATCH.41): a query holding more than
# this many distinct query tokens gets no fuzzy name at all — the tier is
# skipped and the subsequence tier still runs (a pasted name is found by the
# cheap text and token tiers). N = 20 by measurement (graph E5-2).
_FUZZY_TOKEN_CAP = 20


class MatchRule(str, Enum):
    """Rank order of the match rules; declaration order == rank order (D-3 B)."""

    EXACT = "exact"
    PREFIX = "prefix"
    SUBSTRING = "substring"
    TOKEN = "token"
    FUZZY = "fuzzy"
    SUBSEQUENCE = "subsequence"


_RULE_RANK = {rule: pos for pos, rule in enumerate(MatchRule)}
_RULE_BY_POS = tuple(MatchRule)


@dataclass(frozen=True, slots=True)
class LabelMatch:
    """One ranked suggestion: a name with its rule, fuzzy edits and spans.

    Compares by value, so a test can assert a whole ranked list with ``==``.
    """

    name: str
    rule: MatchRule
    edits: int
    spans: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class LabelIndex:
    """A prepared name list, built once and read-only afterwards.

    ``eq=False`` makes equality identity; ``repr=False`` keeps a 50,000-name
    index out of logs and tracebacks. The private fields are set once by
    :func:`build_label_index` through the generated ``__init__`` and are never
    written again (E3S-07).
    """

    names: tuple[str, ...]
    _folded: tuple[str, ...]
    _masks: array
    _tokens: tuple[str, ...]
    _name_token_ids: array
    _name_token_starts: array
    _postings: array
    _posting_starts: array
    _trie_chars: str
    _trie_depth: array
    _trie_first: array
    _trie_end: array

    def __len__(self) -> int:
        """Return the number of distinct names the index holds."""
        return len(self.names)


class _Query(NamedTuple):
    """The parsed query: folded text, folded token strings, folded key chars."""

    text: str
    tokens: tuple[str, ...]
    keys: str


def build_label_index(names: Iterable[str]) -> LabelIndex:
    """
    Summary:
        Prepare a name list once for ranking: de-duplicate, fold, tokenise and
        index the names into a read-only :class:`LabelIndex`.

    Args:
        names (Iterable[str]): The names to index. A name longer than 1,024
            characters is left out (R-A2L-MATCH.39); each distinct name is
            kept once at its first occurrence (R-A2L-MATCH.17).

    Returns:
        LabelIndex: The prepared index. ``len(index)`` is the number of
            distinct names kept.

    Raises:
        TypeError: ``label names must be an iterable of str, got <type>`` for
            a ``str`` or ``bytes`` argument; ``label names must be str,
            got <type>`` for an element that is not a ``str``.

    Data Flow:
        - Validate the argument and each element; drop names over 1,024 chars.
        - De-duplicate in first-occurrence order; fold each name and set its
          character mask.
        - Cut each name into tokens; assign every distinct folded token an id
          in code-point order and record each name's token ids.
        - Build the CSR postings (token id -> names holding it) and the
          pre-order array trie of the sorted distinct tokens.

    Dependencies:
        Uses:
            - _fold
            - _char_mask
            - _tokens
            - _build_trie
        Used by:
            - s19_app.tui.services.label_match.rank
            - (Inc 7) the A2L Viewer autocomplete and paste modal
    """
    if isinstance(names, (str, bytes)):
        raise TypeError(
            f"label names must be an iterable of str, got {type(names).__name__}"
        )
    uniq: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not isinstance(name, str):
            raise TypeError(f"label names must be str, got {type(name).__name__}")
        if len(name) > 1024:
            continue
        if name not in seen:
            seen.add(name)
            uniq.append(name)
    del seen

    names_tuple = tuple(uniq)
    del uniq
    count = len(names_tuple)
    folded = tuple(_fold(name) for name in names_tuple)
    masks = array("Q", (_char_mask(text) for text in folded))

    # Compact staging (E5S-08, graph D2 p_build2): one tokenising pass collects
    # every distinct folded token in a set and keeps each occurrence's start and
    # end in two flat array('I') buffers; the set is sorted into the token tuple
    # and dropped (with its bound add method, which otherwise keeps the set
    # alive); each occurrence's id is then bisect_left(tokens, folded[start:end])
    # and the span buffers are dropped. No token-to-id dict, no per-name token
    # tuple (the 77.9 MiB of v3; E2-1).
    distinct: set[str] = set()
    add = distinct.add
    span_start = array("I")
    span_end = array("I")
    name_token_starts = array("I", [0])
    for i in range(count):
        text = folded[i]
        for start, end in _tokens(names_tuple[i]):
            add(text[start:end])
            span_start.append(start)
            span_end.append(end)
        name_token_starts.append(len(span_start))
    del add
    tokens = tuple(sorted(distinct))
    del distinct
    find = bisect_left
    name_token_ids = array("I", [0]) * len(span_start)
    for i in range(count):
        text = folded[i]
        for j in range(name_token_starts[i], name_token_starts[i + 1]):
            name_token_ids[j] = find(tokens, text[span_start[j]:span_end[j]])
    del span_start, span_end

    ntok = len(tokens)
    posting_starts = array("I", [0]) * (ntok + 1)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            posting_starts[token_id + 1] += 1
    for token_id in range(ntok):
        posting_starts[token_id + 1] += posting_starts[token_id]
    postings = array("I", [0]) * posting_starts[ntok]
    cursor = array("I", posting_starts)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            postings[cursor[token_id]] = i
            cursor[token_id] += 1
    del cursor

    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tokens)

    return LabelIndex(
        names=names_tuple,
        _folded=folded,
        _masks=masks,
        _tokens=tokens,
        _name_token_ids=name_token_ids,
        _name_token_starts=name_token_starts,
        _postings=postings,
        _posting_starts=posting_starts,
        _trie_chars=trie_chars,
        _trie_depth=trie_depth,
        _trie_first=trie_first,
        _trie_end=trie_end,
    )


def rank(query: str, index: LabelIndex, limit: int) -> list[LabelMatch]:
    """
    Summary:
        Rank the prepared names of ``index`` for one query, best first, up to
        ``limit`` entries.

    Args:
        query (str): The text the operator typed. Leading and trailing
            whitespace is stripped; a stripped query longer than 256 characters
            or holding no letter and no digit gives an empty list.
        index (LabelIndex): The prepared name list.
        limit (int): The largest number of names to return. Below 1 the result
            is empty.

    Returns:
        list[LabelMatch]: The first ``limit`` listed names in rank order, each
            with its rule, its total edits (fuzzy only) and its match spans.

    Raises:
        TypeError: ``query must be str, got <type>`` for a non-``str`` query
            (checked first); ``limit must be int, got <type>`` for a ``limit``
            that is not an ``int`` or is a ``bool``.

    Data Flow:
        - Type checks; strip; length cap; parse the query (fold, tokens, keys).
        - Run the rule tiers in rank order — text (exact / prefix / substring),
          token, fuzzy (skipped for a query of more than 20 distinct query
          tokens, R-A2L-MATCH.41) and subsequence — stopping after the tier at
          which ``limit`` names are found, each name grouped by rule, key and
          length.
        - Order each group by case-exactness and name, then emit ``LabelMatch``
          entries with ``_classify`` spans until ``limit``.

    Dependencies:
        Uses:
            - _parse_query
            - _text_tiers
            - _token_tier
            - _fuzzy_tier
            - _subsequence_tier
            - _cut
        Used by:
            - (Inc 7) the A2L Viewer autocomplete and paste modal
    """
    if not isinstance(query, str):
        raise TypeError(f"query must be str, got {type(query).__name__}")
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError(f"limit must be int, got {type(limit).__name__}")
    if limit < 1:
        return []
    raw = query.strip(_WHITESPACE)
    if len(raw) > 256:
        return []
    parsed = _parse_query(raw)
    if parsed is None:
        return []

    groups: dict[tuple, list[int]] = {}
    taken: set[int] = set()

    def add_group(rule: MatchRule, key: int, name_id: int) -> None:
        groups.setdefault(
            _order_key(rule, key, index.names[name_id], False)[:3], []
        ).append(name_id)

    found = _text_tiers(parsed, index, taken, add_group)
    if found < limit and parsed.tokens:
        found += _token_tier(parsed, index, taken, add_group)
    tables: dict[str, tuple[list[int], list[int], list[int]]] = {}
    if found < limit and parsed.tokens:
        fuzzy, tables = _fuzzy_tier(parsed, index, taken)
        for name_id, total in fuzzy.items():
            add_group(MatchRule.FUZZY, total, name_id)
            taken.add(name_id)
            found += 1
    if found < limit and parsed.keys:
        found += _subsequence_tier(parsed, index, taken, add_group)
    return _cut(parsed, raw, index, groups, tables, limit)


def _text_tiers(
    parsed: _Query,
    index: LabelIndex,
    taken: set[int],
    add_group: Callable[[MatchRule, int, int], None],
) -> int:
    """
    Summary:
        Run the exact, prefix and substring tiers and return the number of
        names listed (R-A2L-MATCH.5–.7, .21). One pass over the folded names:
        a name that contains the query text is EXACT (equal), PREFIX (starts
        with it) or SUBSTRING, whose key is 0 when an occurrence sits at a
        boundary offset, else 1.

    Args:
        parsed (_Query): The parsed query.
        index (LabelIndex): The prepared name list.
        taken (set[int]): Name ids already listed.
        add_group (Callable[[MatchRule, int, int], None]): Records a listed
            name under its (rule, key, length) group.

    Returns:
        int: The number of names listed by these tiers.
    """
    names = index.names
    folded = index._folded
    count = len(names)
    text = parsed.text
    text_len = len(text)
    exact: list[int] = []
    prefix: list[int] = []
    subs: list[int] = []
    for i in range(count):
        name_folded = folded[i]
        if text in name_folded:
            if name_folded.startswith(text):
                (exact if len(name_folded) == text_len else prefix).append(i)
            else:
                subs.append(i)
    for i in exact:
        add_group(MatchRule.EXACT, 0, i)
        taken.add(i)
    for i in prefix:
        add_group(MatchRule.PREFIX, 0, i)
        taken.add(i)
    for i in subs:
        key = 1
        name_folded = folded[i]
        p = name_folded.find(text)
        while p >= 0:
            if _at_boundary(names[i], p):
                key = 0
                break
            p = name_folded.find(text, p + 1)
        add_group(MatchRule.SUBSTRING, key, i)
        taken.add(i)
    return len(exact) + len(prefix) + len(subs)


def _token_tier(
    parsed: _Query,
    index: LabelIndex,
    taken: set[int],
    add_group: Callable[[MatchRule, int, int], None],
) -> int:
    """
    Summary:
        Run the token tier and return the number of names listed
        (R-A2L-MATCH.8, .30): a name whose tokens start with each distinct
        query token, one range per distinct token, intersected by postings
        (A-2).

    Args:
        parsed (_Query): The parsed query.
        index (LabelIndex): The prepared name list.
        taken (set[int]): Name ids already listed.
        add_group (Callable[[MatchRule, int, int], None]): Records a listed
            name under its (rule, key, length) group.

    Returns:
        int: The number of names listed by this tier.
    """
    distinct = list(dict.fromkeys(parsed.tokens))
    ranges = [_token_range(index._tokens, token) for token in distinct]
    if not ranges or not all(lo < hi for lo, hi in ranges):
        return 0
    posting_starts = index._posting_starts
    postings = index._postings
    order = sorted(
        range(len(ranges)),
        key=lambda j: posting_starts[ranges[j][1]] - posting_starts[ranges[j][0]],
    )
    lo, hi = ranges[order[0]]
    candidates = set(postings[posting_starts[lo]:posting_starts[hi]])
    candidates.difference_update(taken)
    for j in order[1:]:
        if not candidates:
            break
        lo, hi = ranges[j]
        candidates.intersection_update(
            postings[posting_starts[lo]:posting_starts[hi]]
        )
    added = 0
    for name_id in candidates:
        add_group(MatchRule.TOKEN, 0, name_id)
        taken.add(name_id)
        added += 1
    return added


def _subsequence_tier(
    parsed: _Query,
    index: LabelIndex,
    taken: set[int],
    add_group: Callable[[MatchRule, int, int], None],
) -> int:
    """
    Summary:
        Run the subsequence tier and return the number of names listed
        (R-A2L-MATCH.9, .31): each name not yet listed whose mask holds every
        key-character bit and whose folded text holds the keys in order.

    Args:
        parsed (_Query): The parsed query.
        index (LabelIndex): The prepared name list.
        taken (set[int]): Name ids already listed.
        add_group (Callable[[MatchRule, int, int], None]): Records a listed
            name under its (rule, key, length) group.

    Returns:
        int: The number of names listed by this tier.
    """
    key_mask = _char_mask(parsed.keys)
    folded = index._folded
    count = len(index.names)
    added = 0
    for i in range(count):
        if i in taken or key_mask & ~index._masks[i]:
            continue
        if _subsequence(parsed.keys, folded[i]) is not None:
            add_group(MatchRule.SUBSEQUENCE, 0, i)
            taken.add(i)
            added += 1
    return added


def _cut(
    parsed: _Query,
    raw: str,
    index: LabelIndex,
    groups: dict[tuple, list[int]],
    tables: Mapping[str, tuple[Sequence[int], Sequence[int], Sequence[int]]],
    limit: int,
) -> list[LabelMatch]:
    """
    Summary:
        Order the found names and emit the ranked list (``rank`` step 6,
        R-A2L-MATCH.18–.25): groups by rule, key and length; within a group
        case-exactness (computed only for exact / prefix / substring) and then
        the name; each entry's rule and edits are its group's, and its spans
        come from ``_classify`` (no listed name is classified again, E5S-01).

    Args:
        parsed (_Query): The parsed query.
        raw (str): The stripped-but-unfolded query, for case-exactness.
        index (LabelIndex): The prepared name list.
        groups (dict[tuple, list[int]]): Name ids grouped by (rule, key, length).
        tables (Mapping[str, tuple[Sequence[int], Sequence[int], Sequence[int]]]):
            The fuzzy tier's per-token range tables (step 4); empty for the
            other rules.
        limit (int): The largest number of names to return.

    Returns:
        list[LabelMatch]: The first ``limit`` entries in rank order.
    """
    names = index.names
    starts = index._name_token_starts
    ids_all = index._name_token_ids
    result: list[LabelMatch] = []
    for group_key in sorted(groups):
        rule = _RULE_BY_POS[group_key[0]]
        keyed: list[tuple[tuple, int]] = []
        for name_id in groups[group_key]:
            name = names[name_id]
            if rule is MatchRule.EXACT:
                case_exact = name == raw
            elif rule is MatchRule.PREFIX:
                case_exact = name.startswith(raw)
            elif rule is MatchRule.SUBSTRING:
                case_exact = raw in name
            else:
                case_exact = False
            keyed.append((_order_key(rule, group_key[1], name, case_exact)[3:], name_id))
        keyed.sort(key=lambda item: item[0])
        for _, name_id in keyed:
            token_ids = ids_all[starts[name_id]:starts[name_id + 1]]
            spans = _classify(parsed, names[name_id], rule, token_ids, tables)
            result.append(
                LabelMatch(
                    name=names[name_id],
                    rule=rule,
                    edits=group_key[1] if rule is MatchRule.FUZZY else 0,
                    spans=spans,
                )
            )
            if len(result) >= limit:
                return result
    return result


def _fuzzy_tier(
    query: _Query, index: LabelIndex, taken: set[int]
) -> tuple[dict[int, int], dict[str, tuple[list[int], list[int], list[int]]]]:
    """
    Summary:
        Run the fuzzy tier (R-A2L-MATCH.10–.13, .33, .40, .41; E5S-01 variant C,
        E5S-07): a query of more than ``_FUZZY_TOKEN_CAP`` distinct query tokens
        gets no fuzzy name (the tier is skipped and the subsequence tier still
        runs); otherwise walk each distinct query token in ascending allowed
        edits, intersect the candidates by postings, and return each candidate's
        total edits plus the per-token range tables ``rank`` step 6 reads the
        spans from. The walk returns sorted, disjoint runs ``(lo, hi, d)`` — one
        CSR postings slice per run, never one entry per token id — and the totals
        are counted at C level: the names whose smallest distance is ``d >= 1``
        go into one ``Counter`` per weight ``d * count`` (``Counter.update``), so
        a repeated query token still counts its edits once per occurrence. Once
        at most ``_FUZZY_SWITCH_CAP`` candidates remain holding at most that many
        name-token occurrences in all, each remaining token's table is computed
        with ``_prefix_distance`` on those candidates' token ids only (one call
        per (query token, token id), each kept id as a run of one).

    Args:
        query (_Query): The parsed query.
        index (LabelIndex): The prepared name list.
        taken (set[int]): Name ids already listed by an earlier tier.

    Returns:
        tuple[dict[int, int], dict[str, tuple[list[int], list[int], list[int]]]]:
            ``(name id -> total edits, distinct query token -> (los, his, ds))``.
            The three parallel lists of each table cover the token ids at a
            prefix distance of at most the token's allowed edits; a token id
            ``t`` is at distance ``ds[i]`` when ``los[i] <= t < his[i]``. Both
            are empty when the tier finds nothing (including past the cap).
    """
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    if len(counts) > _FUZZY_TOKEN_CAP:
        return {}, {}
    distinct = sorted(counts, key=_allowed_edits)

    posting_starts = index._posting_starts
    postings = index._postings
    starts = index._name_token_starts
    ids_all = index._name_token_ids
    tokens = index._tokens

    tables: dict[str, tuple[list[int], list[int], list[int]]] = {}
    candidates: set[int] | None = None
    totals: dict[int, int] = {}
    weights: dict[int, Counter] = {}
    switched = False

    for token in distinct:
        allowed = _allowed_edits(token)
        count = counts[token]
        if (
            not switched
            and candidates is not None
            and len(candidates) <= _FUZZY_SWITCH_CAP
            and sum(starts[n + 1] - starts[n] for n in candidates)
            <= _FUZZY_SWITCH_CAP
        ):
            switched = True
        if switched:
            seen: dict[int, int] = {}
            kept: set[int] = set()
            for name_id in candidates:
                best: int | None = None
                for token_id in ids_all[starts[name_id]:starts[name_id + 1]]:
                    value = seen.get(token_id)
                    if value is None:
                        value = _prefix_distance(token, tokens[token_id], allowed)
                        seen[token_id] = value
                    if value <= allowed and (best is None or value < best):
                        best = value
                if best is not None:
                    kept.add(name_id)
                    totals[name_id] = totals.get(name_id, 0) + best * count
            kept_ids = sorted(t for t, v in seen.items() if v <= allowed)
            tables[token] = (
                kept_ids,
                [t + 1 for t in kept_ids],
                [seen[t] for t in kept_ids],
            )
            candidates = kept
            if not candidates:
                return {}, tables
            continue
        runs = _fuzzy_token_distances(index, token, allowed)
        if not runs:
            return {}, tables
        tables[token] = (
            [run[0] for run in runs],
            [run[1] for run in runs],
            [run[2] for run in runs],
        )
        layers = [set() for _ in range(allowed + 1)]
        for lo, hi, d in runs:
            layers[d].update(postings[posting_starts[lo]:posting_starts[hi]])
        reached = layers[0].union(*layers[1:])
        if candidates is None:
            candidates = reached
            candidates.difference_update(taken)
        else:
            candidates &= reached
        if not candidates:
            return {}, tables
        lower = layers[0]
        for d in range(1, allowed + 1):
            diff = (layers[d] & candidates) - lower
            if diff:
                weights.setdefault(d * count, Counter()).update(diff)
            if d < allowed:
                lower = lower | layers[d]
    if weights:
        return (
            {
                name_id: totals.get(name_id, 0)
                + sum(weight * counter[name_id] for weight, counter in weights.items())
                for name_id in candidates
            },
            tables,
        )
    return {name_id: totals.get(name_id, 0) for name_id in candidates}, tables


def _fold(text: str) -> str:
    """
    Summary:
        Fold ``A``–``Z`` to ``a``–``z``, keeping every other character, so the
        result is exactly as long as ``text`` and spans index ``text`` directly
        (R-A2L-MATCH.3, .4). Never ``str.lower``/``casefold``.

    Args:
        text (str): The text to fold.

    Returns:
        str: The folded text.
    """
    return text.translate(_FOLD_TABLE)


def _char_mask(text: str) -> int:
    """
    Summary:
        OR one bit per character of an already folded ``text`` (R-A2L-MATCH.9,
        .36): ``a``–``z`` bits 0–25, ``0``–``9`` bits 26–35, any other
        character ``c`` bit ``36 + ord(c) % 27`` (at most 62, fitting
        ``array('Q')``).

    Args:
        text (str): The folded text.

    Returns:
        int: The character bitmask.
    """
    mask = 0
    for ch in text:
        o = ord(ch)
        if "a" <= ch <= "z":
            bit = o - 97
        elif "0" <= ch <= "9":
            bit = o - 48 + 26
        else:
            bit = (o % 27) + 36
        mask |= 1 << bit
    return mask


def _is_word_char(ch: str) -> bool:
    """Whether ``ch`` is a CTX-A2L-MATCH letter or digit (by code point, E2-5)."""
    return (
        ("a" <= ch <= "z")
        or ("A" <= ch <= "Z")
        or ("0" <= ch <= "9")
        or ord(ch) > 0x7F
    )


def _tokens(text: str) -> tuple[tuple[int, int], ...]:
    """
    Summary:
        The ``[start, end)`` spans of the CTX-A2L-MATCH tokens of ``text``,
        read on the unfolded text (the case cuts need the case). A token starts
        at each offset that is not a separator and where ``_at_boundary`` holds,
        and runs up to the next separator or the next such offset (R-A2L-MATCH.8).

    Args:
        text (str): The unfolded text.

    Returns:
        tuple[tuple[int, int], ...]: The token spans in offset order.
    """
    n = len(text)
    spans: list[tuple[int, int]] = []
    i = 0
    while i < n:
        ch = text[i]
        if not _is_word_char(ch):
            i += 1
            continue
        start = i
        i += 1
        while i < n:
            ch = text[i]
            if not _is_word_char(ch) or _at_boundary(text, i):
                break
            i += 1
        spans.append((start, i))
    return tuple(spans)


def _allowed_edits(token: str) -> int:
    """
    Summary:
        The allowed edits of a query token (R-A2L-MATCH.11–.13): 0 for a digit
        token or 1–2 letters, 1 for 3–5 letters, 2 for 6 or more letters.

    Args:
        token (str): A folded query token.

    Returns:
        int: The allowed edits (0, 1 or 2).
    """
    if "0" <= token[0] <= "9":
        return 0
    n = len(token)
    if n <= 2:
        return 0
    if n <= 5:
        return 1
    return 2


def _prefix_distance(query_token: str, name_token: str, cap: int) -> int:
    """
    Summary:
        The smallest optimal-string-alignment distance between ``query_token``
        and a prefix of ``name_token`` (the empty prefix included) when it is
        at most ``cap``, else ``cap + 1`` (R-A2L-MATCH.10, .40). Computed only
        on the band ``|i - j| <= cap`` of the alignment, so one call costs at
        most ``(2 * cap + 1)`` cells per query character (A-3, E3S-11).

    Args:
        query_token (str): The folded query token.
        name_token (str): The folded name token.
        cap (int): The allowed edits (0, 1 or 2); values above it report as
            ``cap + 1``.

    Returns:
        int: The prefix distance, at most ``cap``, else ``cap + 1``.
    """
    m = len(query_token)
    if cap == 0:
        return 0 if name_token.startswith(query_token) else 1
    n = len(name_token)
    limit = cap + 1
    prev = [i if i < limit else limit for i in range(m + 1)]
    prev2: list[int] | None = None
    best = m if m < limit else limit
    for j in range(1, min(n, m + cap) + 1):
        c = name_token[j - 1]
        new = [limit] * (m + 1)
        new[0] = j if j < limit else limit
        lo = j - cap if j - cap > 1 else 1
        hi = j + cap if j + cap < m else m
        for i in range(lo, hi + 1):
            qi = query_token[i - 1]
            value = prev[i - 1] + (0 if qi == c else 1)
            alt = prev[i] + 1
            if alt < value:
                value = alt
            alt = new[i - 1] + 1
            if alt < value:
                value = alt
            if i >= 2 and prev2 is not None and qi == name_token[j - 2] and query_token[i - 2] == c:
                alt = prev2[i - 2] + 1
                if alt < value:
                    value = alt
            if value > limit:
                value = limit
            new[i] = value
        best = new[m] if new[m] < best else best
        prev2 = prev
        prev = new
    return best if best <= cap else cap + 1


def _join_spans(spans: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """
    Summary:
        The fewest spans in offset order covering the same offsets: sort, then
        join each span that starts at or before the end of the one before it
        (R-A2L-MATCH.34).

    Args:
        spans (list[tuple[int, int]]): The spans to join.

    Returns:
        tuple[tuple[int, int], ...]: The joined spans in offset order.
    """
    if not spans:
        return ()
    ordered = sorted(spans)
    result: list[tuple[int, int]] = [ordered[0]]
    for start, end in ordered[1:]:
        prev_start, prev_end = result[-1]
        if start <= prev_end:
            if end > prev_end:
                result[-1] = (prev_start, end)
        else:
            result.append((start, end))
    return tuple(result)


def _at_boundary(name: str, offset: int) -> bool:
    """
    Summary:
        Whether ``offset`` of ``name`` is a CTX-A2L-MATCH boundary offset:
        offset 0, a separator, or the first offset of a token read on the
        unfolded name from its neighbours (R-A2L-MATCH.21, .28, .29). This is
        the single source of the token cut rules.

    Args:
        name (str): The unfolded name.
        offset (int): The offset to test.

    Returns:
        bool: True when the offset is a boundary offset.
    """
    if offset == 0:
        return True
    c = name[offset]
    b = name[offset - 1]
    if not _is_word_char(c):
        return True
    if not _is_word_char(b):
        return True
    if ("0" <= c <= "9") != ("0" <= b <= "9"):
        return True
    if "A" <= c <= "Z":
        if "a" <= b <= "z":
            return True
        if "A" <= b <= "Z" and offset + 1 < len(name) and "a" <= name[offset + 1] <= "z":
            return True
    return False


def _subsequence(keys: str, text: str) -> tuple[int, ...] | None:
    """
    Summary:
        The leftmost offsets of the key characters in ``text``, each after the
        one before (``str.find`` from the previous offset + 1), or ``None``
        when one is missing (R-A2L-MATCH.9, .31).

    Args:
        keys (str): The key characters, in order.
        text (str): The folded text to search.

    Returns:
        tuple[int, ...] | None: The offsets, or ``None``.
    """
    offsets: list[int] = []
    pos = 0
    for ch in keys:
        found = text.find(ch, pos)
        if found < 0:
            return None
        offsets.append(found)
        pos = found + 1
    return tuple(offsets)


def _parse_query(query: str) -> _Query | None:
    """
    Summary:
        Strip exactly the six CTX-A2L-MATCH whitespace characters from both
        ends — never a bare ``str.strip`` (E2-5) — and parse what is left into a
        ``_Query``; ``None`` when no letter and no digit remains (R-A2L-MATCH.1,
        .2, .8).

    Args:
        query (str): The raw query.

    Returns:
        _Query | None: ``text`` folded, ``tokens`` the folded token strings of
            the stripped query, ``keys`` the letters and digits of ``text`` in
            order; ``None`` when the stripped query holds no letter or digit.
    """
    stripped = query.strip(_WHITESPACE)
    has_alnum = False
    for ch in stripped:
        if _is_word_char(ch):
            has_alnum = True
            break
    if not has_alnum:
        return None
    text = _fold(stripped)
    tokens = tuple(text[start:end] for start, end in _tokens(stripped))
    keys = "".join(
        ch for ch in text if ("a" <= ch <= "z") or ("0" <= ch <= "9") or ord(ch) > 0x7F
    )
    return _Query(text=text, tokens=tokens, keys=keys)


def _classify(
    query: _Query,
    name: str,
    rule: MatchRule,
    token_ids: Sequence[int],
    tables: Mapping[str, tuple[Sequence[int], Sequence[int], Sequence[int]]],
) -> tuple[tuple[int, int], ...]:
    """
    Summary:
        The match spans of one listed name for the ``rule`` its tier found
        (``rank`` step 6, R-A2L-MATCH.26–.32): it tests no other rule, never
        decides the rule or the key (the tiers do), and calls no
        ``_prefix_distance``. ``name`` is folded here; ``query.text`` and
        ``query.tokens`` are already folded. Case-exactness is decided in
        ``rank`` step 6 by string comparison on the raw texts, not here.

    Args:
        query (_Query): The parsed query.
        name (str): The unfolded name.
        rule (MatchRule): The rule the name's tier found.
        token_ids (Sequence[int]): The name's token ids, in name order.
        tables (Mapping[str, tuple[Sequence[int], Sequence[int], Sequence[int]]]):
            The fuzzy tier's per-token range tables (step 4), each
            ``(los, his, ds)``; empty for the other rules.

    Returns:
        tuple[tuple[int, int], ...]: The joined match spans.

    Raises:
        ValueError: When ``name`` does not meet ``rule`` — a defect of the
            tiers, never a skipped entry.
    """
    folded = _fold(name)
    text = query.text
    if rule is MatchRule.EXACT:
        return ((0, len(name)),)
    if rule is MatchRule.PREFIX:
        return ((0, len(text)),)
    if rule is MatchRule.SUBSTRING:
        p = folded.find(text)
        if p < 0:
            raise ValueError(f"substring: {name!r} does not meet its tier")
        span = (p, p + len(text))
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        return (span,)

    name_spans = _tokens(name)
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1

    if rule is MatchRule.TOKEN:
        token_spans: list[tuple[int, int]] = []
        for query_token in counts:
            match_span: tuple[int, int] | None = None
            for start, end in name_spans:
                if folded[start:end].startswith(query_token):
                    match_span = (start, start + len(query_token))
                    break
            if match_span is None:
                raise ValueError(f"token: {name!r} does not meet its tier")
            token_spans.append(match_span)
        return _join_spans(token_spans)

    if rule is MatchRule.FUZZY:
        first_pos: dict[int, int] = {}
        for pos, token_id in enumerate(token_ids):
            if token_id not in first_pos:
                first_pos[token_id] = pos
        fuzzy_spans: list[tuple[int, int]] = []
        for query_token in counts:
            table = tables.get(query_token)
            if table is None:
                raise ValueError(f"fuzzy: {name!r} does not meet its tier")
            los, his, ds = table
            best: int | None = None
            best_pos: int | None = None
            for token_id, pos in first_pos.items():
                i = bisect_right(los, token_id) - 1
                if i >= 0 and token_id < his[i]:
                    value = ds[i]
                    if best is None or value < best or (
                        value == best and pos < best_pos
                    ):
                        best = value
                        best_pos = pos
            if best is None:
                raise ValueError(f"fuzzy: {name!r} does not meet its tier")
            fuzzy_spans.append(name_spans[best_pos])
        return _join_spans(fuzzy_spans)

    offsets = _subsequence(query.keys, folded)
    if offsets is None:
        raise ValueError(f"subsequence: {name!r} does not meet its tier")
    return _join_spans([(o, o + 1) for o in offsets])


def _order_key(
    rule: MatchRule, key: int, name: str, case_exact: bool
) -> tuple[int, int, int, int, str]:
    """
    Summary:
        The total rank-order key of one listed name (R-A2L-MATCH.20–.25):
        ``(position of rule in MatchRule, key, len(name), 0 if case_exact else
        1, name)``. Tuple and ``str`` comparison give the rank order, code-point
        order last, so the order is total over distinct names.

    Args:
        rule (MatchRule): The rule the name meets.
        key (int): The rule key (fuzzy: total edits; substring: 0/1 boundary).
        name (str): The name as listed, case kept.
        case_exact (bool): Whether the name is case-exact.

    Returns:
        tuple[int, int, int, int, str]: The five-part order key.
    """
    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)


def _token_range(tokens: tuple[str, ...], prefix: str) -> tuple[int, int]:
    """
    Summary:
        The ids ``lo`` … ``hi - 1`` of the sorted distinct ``tokens`` that start
        with ``prefix`` (contiguous in code-point order): ``bisect_left`` for
        ``prefix``, then ``bisect_left`` of the successor string from ``lo``; a
        prefix ending in U+10FFFF scans forward instead (R-A2L-MATCH.8, .11, .30).

    Args:
        tokens (tuple[str, ...]): The sorted distinct folded tokens.
        prefix (str): The folded prefix.

    Returns:
        tuple[int, int]: The inclusive-exclusive id range (possibly empty).
    """
    lo = bisect_left(tokens, prefix)
    last = ord(prefix[-1])
    if last < 0x10FFFF:
        hi = bisect_left(tokens, prefix[:-1] + chr(last + 1), lo)
    else:
        hi = lo
        while hi < len(tokens) and tokens[hi].startswith(prefix):
            hi += 1
    return (lo, hi)


def _build_trie(tokens: tuple[str, ...]) -> tuple[str, array, array, array]:
    """
    Summary:
        The pre-order array trie of the sorted distinct ``tokens``
        (R-A2L-MATCH.35–.37): one node per distinct non-empty prefix, in
        pre-order (= the tokens' code-point order); ``chars[j]`` is its last
        character, ``depth[j]`` its length, ``first[j]`` the id of the first
        token under it and ``end[j]`` the index after its subtree. ``first``
        ends with one sentinel, ``len(tokens)``; the tokens under node ``j``
        are the ids ``first[j]`` … ``first[end[j]] - 1``. Only each token's
        first ``_TRIE_PREFIX`` characters are used (E3S-03).

    Args:
        tokens (tuple[str, ...]): The sorted distinct folded tokens.

    Returns:
        tuple[str, array, array, array]: ``(chars, depth, first, end)``; the
            arrays are ``array('I')``.
    """
    chars: list[str] = []
    depth = array("I")
    first = array("I")
    end = array("I")
    stack: list[int] = []
    prev = ""
    for token_id, token in enumerate(tokens):
        token = token[:_TRIE_PREFIX]
        lim = len(prev) if len(prev) < len(token) else len(token)
        common = 0
        while common < lim and prev[common] == token[common]:
            common += 1
        for d in range(common + 1, len(token) + 1):
            node = len(depth)
            while stack and depth[stack[-1]] >= d:
                end[stack.pop()] = node
            chars.append(token[d - 1])
            depth.append(d)
            first.append(token_id)
            end.append(0)
            stack.append(node)
        prev = token
    node_count = len(depth)
    while stack:
        end[stack.pop()] = node_count
    first.append(len(tokens))
    return "".join(chars), depth, first, end


def _fuzzy_token_distances(
    index: LabelIndex, query_token: str, allowed: int
) -> list[tuple[int, int, int]]:
    """
    Summary:
        The sorted, disjoint runs ``(lo, hi, d)`` that cover every distinct
        token of ``index`` at a prefix distance ``d`` of at most ``allowed``
        from ``query_token`` (R-A2L-MATCH.10–.13, .36, .40): the ids
        ``lo`` … ``hi − 1`` are each at distance ``d``; a run that ends where
        the next one starts with the same ``d`` is joined to it. For ``allowed``
        0 the one run of ``_token_range`` with distance 0 (none when the range
        is empty); otherwise one walk of the trie arrays in pre-order, each
        node's alignment column from its parent's (and its grandparent's, for a
        transposition), capped at ``allowed + 1`` on the band
        ``|row − depth| <= allowed``; the best prefix distance carried down the
        path; when the column minimum is above ``allowed`` or not below the
        best, every token under the node is the run ``(first[j],
        first[end[j]], best)`` (when the best is at most ``allowed``) and the
        walk jumps to ``end[j]``; a token that ends at a node the walk enters
        is the run of its one id. Pre-order keeps the runs sorted and disjoint.

    Args:
        index (LabelIndex): The prepared index.
        query_token (str): The folded query token.
        allowed (int): The allowed edits (0, 1 or 2).

    Returns:
        list[tuple[int, int, int]]: The runs ``(lo, hi, d)``, sorted and
            disjoint (possibly empty).
    """
    if allowed == 0:
        lo, hi = _token_range(index._tokens, query_token)
        return [(lo, hi, 0)] if lo < hi else []

    chars = index._trie_chars
    depth = index._trie_depth
    first = index._trie_first
    end = index._trie_end
    tokens = index._tokens
    q = query_token
    m = len(q)
    k = allowed
    limit = k + 1
    result: list[tuple[int, int, int]] = []

    def emit(lo: int, hi: int, d: int) -> None:
        if result and result[-1][1] == lo and result[-1][2] == d:
            result[-1] = (result[-1][0], hi, d)
        else:
            result.append((lo, hi, d))

    node_count = len(depth)

    cols: list[list[int] | None] = [None] * 66
    best: list[int] = [0] * 66
    prev_char: list[str] = [""] * 66
    cols[0] = [i if i < limit else limit for i in range(m + 1)]
    best[0] = m if m < limit else limit

    j = 0
    while j < node_count:
        dep = depth[j]
        if dep + 1 >= len(cols):
            cols.extend([None] * dep)
            best.extend([0] * dep)
            prev_char.extend([""] * dep)
        c = chars[j]
        prev = cols[dep - 1]
        new = [limit] * (m + 1)
        low = new[0] = dep if dep < limit else limit
        lo_r = dep - k if dep - k > 1 else 1
        hi_r = dep + k if dep + k < m else m
        if dep >= 2:
            prev2 = cols[dep - 2]
            pchar = prev_char[dep - 1]
            for ii in range(lo_r, hi_r + 1):
                qi = q[ii - 1]
                value = prev[ii - 1] + (0 if qi == c else 1)
                alt = prev[ii] + 1
                if alt < value:
                    value = alt
                alt = new[ii - 1] + 1
                if alt < value:
                    value = alt
                if ii > 1 and qi == pchar and q[ii - 2] == c:
                    alt = prev2[ii - 2] + 1
                    if alt < value:
                        value = alt
                if value > limit:
                    value = limit
                new[ii] = value
                if value < low:
                    low = value
        else:
            for ii in range(lo_r, hi_r + 1):
                value = prev[ii - 1] + (0 if q[ii - 1] == c else 1)
                alt = prev[ii] + 1
                if alt < value:
                    value = alt
                alt = new[ii - 1] + 1
                if alt < value:
                    value = alt
                if value > limit:
                    value = limit
                new[ii] = value
                if value < low:
                    low = value
        bd = best[dep - 1]
        b2 = bd if bd < new[m] else new[m]
        if low > k or low >= b2:
            if b2 <= k:
                emit(first[j], first[end[j]], b2)
            j = end[j]
            continue
        cols[dep] = new
        best[dep] = b2
        prev_char[dep] = c
        if b2 <= k and len(tokens[first[j]]) == dep:
            emit(first[j], first[j] + 1, b2)
        j += 1
    return result
