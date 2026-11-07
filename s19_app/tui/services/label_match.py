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
from bisect import bisect_left
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, NamedTuple

# The six CTX-A2L-MATCH whitespace characters. Never a bare ``str.strip``,
# which also strips U+001C … U+001F, U+0085 and U+00A0 (E2-5).
_WHITESPACE = " \t\n\r\v\f"

# A-Z -> a-z translation table for _fold; every other character is kept, so a
# folded string is exactly as long as its source and spans index the source.
_FOLD_TABLE = str.maketrans({ord(chr(c)): chr(c + 32) for c in range(65, 91)})

# The trie needs each token's first 258 characters only: a prefix test needs
# at most 256 and a prefix distance of at most 2 needs at most 258 (E3S-03).
_TRIE_PREFIX = 258


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

    names_tuple = tuple(uniq)
    count = len(uniq)
    folded = tuple(_fold(name) for name in uniq)
    masks = array("Q", (_char_mask(text) for text in folded))

    token_map: dict[str, int] = {}
    name_token_ids = array("I")
    name_token_starts = array("I", [0])
    for i in range(count):
        for start, end in _tokens(uniq[i]):
            token = folded[i][start:end]
            token_id = token_map.get(token)
            if token_id is None:
                token_id = len(token_map)
                token_map[token] = token_id
            name_token_ids.append(token_id)
        name_token_starts.append(len(name_token_ids))

    tokens_sorted = sorted(token_map)
    remap = array("I", bytes(4 * len(tokens_sorted)))
    for sorted_id, token in enumerate(tokens_sorted):
        remap[token_map[token]] = sorted_id
    del token_map
    for j in range(len(name_token_ids)):
        name_token_ids[j] = remap[name_token_ids[j]]
    del remap

    ntok = len(tokens_sorted)
    posting_starts = array("I", bytes(4 * (ntok + 1)))
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            posting_starts[token_id + 1] += 1
    for token_id in range(ntok):
        posting_starts[token_id + 1] += posting_starts[token_id]
    postings = array("I", bytes(4 * posting_starts[ntok]))
    cursor = array("I", posting_starts)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            postings[cursor[token_id]] = i
            cursor[token_id] += 1
    del cursor

    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tuple(tokens_sorted))

    return LabelIndex(
        names=names_tuple,
        _folded=folded,
        _masks=masks,
        _tokens=tuple(tokens_sorted),
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
        - Collect exact / prefix / substring names in one pass over the folded
          names; then token, fuzzy and subsequence tiers while fewer than
          ``limit`` names are found.
        - Order the found names by rule, key, length, case-exactness and name;
          emit ``LabelMatch`` entries from ``_classify`` until ``limit``.

    Dependencies:
        Uses:
            - _parse_query
            - _at_boundary
            - _token_range
            - _fuzzy_tier
            - _subsequence
            - _order_key
            - _classify
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

    names = index.names
    folded = index._folded
    count = len(names)
    text = parsed.text
    text_len = len(text)
    groups: dict[tuple, list[int]] = {}

    def add_group(rule: MatchRule, key: int, name_id: int) -> None:
        groups.setdefault(_order_key(rule, key, names[name_id], False)[:3], []).append(name_id)

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
    for i in prefix:
        add_group(MatchRule.PREFIX, 0, i)
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

    found = len(exact) + len(prefix) + len(subs)
    taken = set(exact)
    taken.update(prefix)
    taken.update(subs)

    if found < limit and parsed.tokens:
        distinct: dict[str, int] = {}
        for token in parsed.tokens:
            distinct[token] = distinct.get(token, 0) + 1
        ranges = [_token_range(index._tokens, token) for token in distinct]
        if ranges and all(lo < hi for lo, hi in ranges):
            order = sorted(
                range(len(ranges)),
                key=lambda j: index._posting_starts[ranges[j][1]]
                - index._posting_starts[ranges[j][0]],
            )
            lo, hi = ranges[order[0]]
            candidates = set(
                index._postings[index._posting_starts[lo]:index._posting_starts[hi]]
            )
            candidates.difference_update(taken)
            for j in order[1:]:
                if not candidates:
                    break
                lo, hi = ranges[j]
                candidates.intersection_update(
                    index._postings[index._posting_starts[lo]:index._posting_starts[hi]]
                )
            for name_id in candidates:
                add_group(MatchRule.TOKEN, 0, name_id)
                taken.add(name_id)
                found += 1

    if found < limit and parsed.tokens:
        for name_id, total in _fuzzy_tier(parsed, index, taken).items():
            if name_id in taken:
                continue
            add_group(MatchRule.FUZZY, total, name_id)
            taken.add(name_id)
            found += 1

    if found < limit and parsed.keys:
        key_mask = _char_mask(parsed.keys)
        for i in range(count):
            if i in taken:
                continue
            if key_mask & ~index._masks[i]:
                continue
            if _subsequence(parsed.keys, folded[i]) is not None:
                add_group(MatchRule.SUBSEQUENCE, 0, i)

    result: list[LabelMatch] = []
    for group_key in sorted(groups):
        rule = _RULE_BY_POS[group_key[0]]
        members = groups[group_key]
        keyed: list[tuple[tuple, int]] = []
        for name_id in members:
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
            classified = _classify(parsed, names[name_id])
            if classified is None:
                continue
            classified_rule, classified_key, spans = classified
            edits = classified_key if classified_rule is MatchRule.FUZZY else 0
            result.append(
                LabelMatch(
                    name=names[name_id],
                    rule=classified_rule,
                    edits=edits,
                    spans=spans,
                )
            )
            if len(result) >= limit:
                return result
    return result


def _fuzzy_tier(
    query: _Query, index: LabelIndex, taken: set[int]
) -> dict[int, int]:
    """Return ``{name id: total edits}`` for the fuzzy tier, or an empty dict.

    Collapses duplicate query tokens (A-2), walks one distinct token at a time
    in ascending allowed edits, intersects the candidate postings after each
    walk and stops when the set is empty or at most 300 candidates remain; the
    remaining distinct tokens are then checked per candidate with the banded
    ``_prefix_distance`` (memoised per token id), stopping a candidate at the
    first query token it fails (E3A-14).
    """
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    distinct = sorted(counts, key=_allowed_edits)

    maps: dict[str, dict[int, int]] = {}
    candidates: set[int] | None = None
    for token in distinct:
        allowed = _allowed_edits(token)
        distances = _fuzzy_token_distances(index, token, allowed)
        maps[token] = distances
        if not distances:
            return {}
        postings: set[int] = set()
        for token_id in distances:
            lo = index._posting_starts[token_id]
            hi = index._posting_starts[token_id + 1]
            postings.update(index._postings[lo:hi])
        if candidates is None:
            candidates = postings
        else:
            candidates &= postings
        candidates.difference_update(taken)
        if not candidates:
            return {}
        if len(candidates) <= 300:
            break

    result: dict[int, int] = {}
    memo: dict[tuple[str, int], int] = {}
    for name_id in candidates:
        start = index._name_token_starts[name_id]
        end = index._name_token_starts[name_id + 1]
        ids = index._name_token_ids[start:end]
        total = 0
        ok = True
        for token in distinct:
            count = counts[token]
            allowed = _allowed_edits(token)
            distances = maps.get(token)
            best: int | None = None
            if distances is not None:
                for token_id in ids:
                    value = distances.get(token_id)
                    if value is not None and (best is None or value < best):
                        best = value
            else:
                for token_id in ids:
                    memo_key = (token, token_id)
                    if memo_key not in memo:
                        memo[memo_key] = _prefix_distance(
                            token, index._tokens[token_id], allowed
                        )
                    value = memo[memo_key]
                    if value <= allowed and (best is None or value < best):
                        best = value
            if best is None:
                ok = False
                break
            total += best * count
        if ok:
            result[name_id] = total
    return result


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
        is_sep = not (
            ("a" <= ch <= "z")
            or ("A" <= ch <= "Z")
            or ("0" <= ch <= "9")
            or ord(ch) > 0x7F
        )
        if is_sep or not _at_boundary(text, i):
            i += 1
            continue
        start = i
        i += 1
        while i < n:
            ch = text[i]
            is_sep = not (
                ("a" <= ch <= "z")
                or ("A" <= ch <= "Z")
                or ("0" <= ch <= "9")
                or ord(ch) > 0x7F
            )
            if is_sep or _at_boundary(text, i):
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
    for j in range(1, n + 1):
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
    if not (
        ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or ord(c) > 0x7F
    ):
        return True
    if not (
        ("a" <= b <= "z") or ("A" <= b <= "Z") or ("0" <= b <= "9") or ord(b) > 0x7F
    ):
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
        if (
            ("a" <= ch <= "z")
            or ("A" <= ch <= "Z")
            or ("0" <= ch <= "9")
            or ord(ch) > 0x7F
        ):
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


def _classify(query: _Query, name: str) -> tuple[MatchRule, int, tuple[tuple[int, int], ...]] | None:
    """
    Summary:
        The first rule in rank order that ``name`` (folded internally;
        ``query.text`` and ``query.tokens`` are already folded) meets for
        ``query``, with its rule key and its match spans, or ``None``
        (R-A2L-MATCH.5–.10, .15, .16, .21, .26–.33). Case-exactness is decided
        in :func:`rank`, not here.

    Args:
        query (_Query): The parsed query.
        name (str): The unfolded name.

    Returns:
        tuple[MatchRule, int, tuple[tuple[int, int], ...]] | None: The rule,
            its key (fuzzy: total edits; substring: 0/1 boundary) and the
            joined match spans; ``None`` when the name meets no rule.
    """
    folded = _fold(name)
    text = query.text
    text_len = len(text)
    if folded == text:
        return (MatchRule.EXACT, 0, ((0, len(name)),))
    if folded.startswith(text):
        return (MatchRule.PREFIX, 0, ((0, text_len),))
    p = folded.find(text)
    if p >= 0:
        key = 1
        span = (p, p + text_len)
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                key = 0
                span = (cursor, cursor + text_len)
                break
            cursor = folded.find(text, cursor + 1)
        return (MatchRule.SUBSTRING, key, (span,))

    name_spans = _tokens(name)
    if name_spans and query.tokens:
        token_spans: list[tuple[int, int]] = []
        token_ok = True
        for query_token in query.tokens:
            match_span: tuple[int, int] | None = None
            for start, end in name_spans:
                if folded[start:end].startswith(query_token):
                    match_span = (start, start + len(query_token))
                    break
            if match_span is None:
                token_ok = False
                break
            token_spans.append(match_span)
        if token_ok:
            return (MatchRule.TOKEN, 0, _join_spans(token_spans))

        total = 0
        fuzzy_spans: list[tuple[int, int]] = []
        for query_token in query.tokens:
            allowed = _allowed_edits(query_token)
            best: int | None = None
            best_span: tuple[int, int] | None = None
            for start, end in name_spans:
                distance = _prefix_distance(query_token, folded[start:end], allowed)
                if distance <= allowed and (best is None or distance < best):
                    best = distance
                    best_span = (start, end)
            if best is None:
                total = -1
                break
            total += best
            fuzzy_spans.append(best_span)
        if total >= 0:
            return (MatchRule.FUZZY, total, _join_spans(fuzzy_spans))

    if query.keys:
        offsets = _subsequence(query.keys, folded)
        if offsets is not None:
            return (
                MatchRule.SUBSEQUENCE,
                0,
                _join_spans([(o, o + 1) for o in offsets]),
            )
    return None


def _order_key(rule: MatchRule, key: int, name: str, case_exact: bool) -> tuple:
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
        tuple: The five-part order key.
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
    if not prefix:
        return (0, len(tokens))
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


def _fuzzy_token_distances(index: LabelIndex, query_token: str, allowed: int) -> dict[int, int]:
    """
    Summary:
        ``{token id: prefix distance}`` for every distinct token of ``index``
        at a prefix distance of at most ``allowed`` from ``query_token``
        (R-A2L-MATCH.10–.13, .36, .40). For ``allowed`` 0 every id of
        ``_token_range`` with distance 0; otherwise one walk of the trie arrays
        in pre-order, each node's alignment column from its parent's (and its
        grandparent's, for a transposition), capped at ``allowed + 1`` on the
        band ``|row - depth| <= allowed``; the best prefix distance carried
        down the path; when the column minimum is above ``allowed`` or not below
        the best, every token under the node gets the best and the walk jumps
        to ``end[j]``.

    Args:
        index (LabelIndex): The prepared index.
        query_token (str): The folded query token.
        allowed (int): The allowed edits (0, 1 or 2).

    Returns:
        dict[int, int]: Token id to prefix distance (at most ``allowed``).
    """
    if allowed == 0:
        lo, hi = _token_range(index._tokens, query_token)
        return {token_id: 0 for token_id in range(lo, hi)}

    chars = index._trie_chars
    depth = index._trie_depth
    first = index._trie_first
    end = index._trie_end
    tokens = index._tokens
    q = query_token
    m = len(q)
    k = allowed
    limit = k + 1
    result: dict[int, int] = {}
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
                for token_id in range(first[j], first[end[j]]):
                    result[token_id] = b2
            j = end[j]
            continue
        cols[dep] = new
        best[dep] = b2
        prev_char[dep] = c
        if b2 <= k and len(tokens[first[j]]) == dep:
            result[first[j]] = b2
        j += 1
    return result
