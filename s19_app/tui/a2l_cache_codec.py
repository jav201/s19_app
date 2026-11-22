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
