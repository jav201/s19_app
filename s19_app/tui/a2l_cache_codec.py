"""Record codec of the A2L parse cache: a stored parse as bounded marshal records."""

from __future__ import annotations

import marshal
import sys
from typing import Any, Iterable, Iterator

CHUNK_BOUND = 2_097_152
_SLICE = 1024
_BRANCH_CHILDREN = 16
_DICT, _LIST = 0, 1


class RecordDamaged(ValueError):
    """A record that is not usable marshal data or does not fit the records before it."""


def _loads(data: bytes) -> Any:
    try:
        if sys.version_info >= (3, 13):
            return marshal.loads(data, allow_code=False)
        return marshal.loads(data)
    except Exception as exc:
        raise RecordDamaged(f"record is not marshal data: {type(exc).__name__}") from exc


def _is_section(value: Any) -> bool:
    return type(value) is dict and type(value.get("children")) is list


def _is_branch(value: Any) -> bool:
    if not _is_section(value):
        return False
    children = value["children"]
    if sum(1 for c in children if _is_section(c)) > _BRANCH_CHILDREN:
        return True
    return any(_is_section(c) and c["children"] for c in children)


def _opens(value: Any, forced: bool) -> bool:
    if type(value) is dict:
        return len(value) > _SLICE or _is_branch(value)
    if type(value) is list:
        return forced or len(value) > _SLICE or any(_is_branch(item) for item in value)
    return False


def _placeholder(value: Any) -> Any:
    return {} if type(value) is dict else []


def encode_records(stored_parse: dict, bound: int = CHUNK_BOUND) -> Iterator[bytes]:
    """
    Summary:
        Yield the stored parse as an ordered stream of marshal records, each
        at most ``bound`` bytes unless it holds a single str or bytes.

    Args:
        stored_parse (dict): The parse to store: dicts (str keys), lists, tuples,
            str, bytes, int, float, bool and None only.
        bound (int): Largest record size in bytes; round-trip needs 1,024 or more.

    Returns:
        Iterator[bytes]: The marshal bytes of ``(path, kind, items)``, one record
            per item; a split container shows as an empty placeholder in its parent
            and is filled by later records naming its path.

    Raises:
        ValueError: A tuple whose marshal is larger than ``bound`` (a tuple is
            never split).

    Data Flow:
        - The root is always opened; so is every dict or list of more than 1,024
          items and every branch section, by length probes, never a trial dump.
        - Slices of at most 1,024 items are dumped and halved until each fits.
        - Opened children follow their parent's records, depth first.

    Dependencies:
        Uses:
            - ``marshal.dumps``; the ``_emit`` / ``_slice`` / ``_split`` helpers
        Used by:
            - ``a2l_cache._write_entry`` (streams the records into an entry file)
    """
    yield from _emit(stored_parse, (), bound)


def _emit(container: Any, path: tuple, bound: int) -> Iterator[bytes]:
    if type(container) is dict:
        kind, entries = _DICT, list(container.items())
    else:
        kind, entries = _LIST, list(container)
    forced = "children" if _is_branch(container) else None
    for start in range(0, len(entries), _SLICE):
        yield from _slice(kind, entries[start:start + _SLICE], start, path, bound, forced)


def _split(kind: int, entries: list, base: int, forced: Any) -> tuple[list, list]:
    shown, holes = [], []
    for offset, entry in enumerate(entries):
        key, value = entry if kind == _DICT else (base + offset, entry)
        if _opens(value, key == forced if kind == _DICT else False):
            shown.append((key, _placeholder(value)) if kind == _DICT else _placeholder(value))
            holes.append((key, value))
        else:
            shown.append(entry)
    return shown, holes


def _slice(kind: int, entries: list, base: int, path: tuple, bound: int, forced: Any) -> Iterator[bytes]:
    shown, holes = _split(kind, entries, base, forced)
    data = marshal.dumps((path, kind, shown))
    if len(data) <= bound or (len(entries) == 1 and not holes and _atomic(entries[0], kind)):
        yield data
        for key, value in holes:
            yield from _emit(value, path + (key,), bound)
        return
    if len(entries) > 1:
        half = len(entries) // 2
        yield from _slice(kind, entries[:half], base, path, bound, forced)
        yield from _slice(kind, entries[half:], base + half, path, bound, forced)
        return
    yield from _single(kind, entries[0], base, path, bound)


def _atomic(entry: Any, kind: int) -> bool:
    value = entry[1] if kind == _DICT else entry
    if type(value) is tuple:
        raise ValueError("a tuple larger than the chunk bound cannot be split")
    return type(value) not in (dict, list)


def _single(kind: int, entry: Any, base: int, path: tuple, bound: int) -> Iterator[bytes]:
    key, value = entry if kind == _DICT else (base, entry)
    shown = [(key, _placeholder(value))] if kind == _DICT else [_placeholder(value)]
    yield marshal.dumps((path, kind, shown))
    yield from _emit(value, path + (key,), bound)


def decode_records(chunks: Iterable[bytes]) -> dict:
    """
    Summary:
        Rebuild the stored parse from its records: the inverse of
        ``encode_records``, one ``marshal.loads`` per chunk.

    Args:
        chunks (Iterable[bytes]): The record bytes, in the order written.

    Returns:
        dict: The stored parse; values keep their types and the order of dict keys
            and list items is kept.

    Raises:
        RecordDamaged: A chunk is not marshal data (code objects refused on
            Python 3.13+), or a record does not fit the records before it.

    Data Flow:
        - Each chunk is loaded and applied to the container its path names.
        - Nothing decoded is imported, evaluated or called.
        - Any ``TypeError`` / ``KeyError`` / ``IndexError`` / ``AttributeError`` of
          applying a record becomes ``RecordDamaged``.

    Dependencies:
        Uses:
            - ``_loads`` and ``_apply`` of this module
        Used by:
            - ``a2l_cache._decode_entry`` (fed by ``_chunks``)
    """
    root: dict = {}
    for chunk in chunks:
        record = _loads(chunk)
        try:
            _apply(root, record)
        except (TypeError, KeyError, IndexError, AttributeError) as exc:
            raise RecordDamaged(f"record does not fit: {type(exc).__name__}") from exc
    return root


def _target(root: dict, path: Any) -> Any:
    if type(path) is not tuple:
        raise RecordDamaged("record path is not a tuple")
    node: Any = root
    for key in path:
        if type(node) is dict and type(key) in (str, int):
            node = node[key]
        elif type(node) is list and type(key) is int and 0 <= key < len(node):
            node = node[key]
        else:
            raise RecordDamaged("record path names no container")
    return node


def _apply(root: dict, record: Any) -> None:
    if type(record) is not tuple or len(record) != 3:
        raise RecordDamaged("record is not a (path, kind, items) triple")
    path, kind, items = record
    node = _target(root, path)
    if type(items) is not list or type(kind) is not int:
        raise RecordDamaged("record items are not a list")
    if kind == _DICT and type(node) is dict:
        for pair in items:
            if type(pair) is not tuple or len(pair) != 2:
                raise RecordDamaged("record pair is malformed")
            node[pair[0]] = pair[1]
    elif kind == _LIST and type(node) is list:
        node.extend(items)
    else:
        raise RecordDamaged("record kind does not match its container")
