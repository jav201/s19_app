"""Observation helpers for the CRC Designer recompute tests (batch-101 Inc 13).

One definition of "the recompute count" and of "wait for the recompute", used
by the new Inc 13 nodes and by the waits inserted into the existing nodes of
``tests/test_crc_designer_view.py``.

- ``designer_recompute_counter`` (fixture) installs, before the app starts, a
  class-level wrapper of ``CrcDesignerPanel._recompute`` that counts calls. It
  counts every call, whichever path made it (mount, a change event, a timer, a
  button), so a count is a count of recomputes and not of one trigger.
- ``designer_recomputes()`` reads that count.
- ``designer_pending(app)`` reads the panel's pending-recompute timer, or
  ``None`` when the panel has no such attribute (the base tree recomputes at
  once and has none).
- ``wait_designer_recompute(pilot, app, before)`` waits (Inc 2's yielding
  ``wait_until``, ``pause_first=True``) until the count is above ``before``
  and no recompute is pending. A count that never advances times out and
  raises: fail loud.

The image helpers build the small fixture image the CRC Designer tests share
(two ranges with an erased gap between them) without importing a test module.
"""
from __future__ import annotations

import zlib
from pathlib import Path
from typing import Dict, Optional

import pytest

from s19_app.tui.crc_designer_view import CrcDesignerPanel
from s19_app.tui.models import LoadedFile
from tests.support.timing import wait_until

#: Calls of ``CrcDesignerPanel._recompute`` since the fixture last reset it.
_RECOMPUTES = [0]

#: Wall-clock ceiling of one wait for a recompute, in seconds. Generous: the
#: base tree computes a 10 MB-scene recompute in about 10 s.
RECOMPUTE_WAIT_S = 90.0

#: Oracles of the fixture image under the first-shown form (CRC-32/ISO-HDLC,
#: Ranges ``0x00008000-0x00008008, 0x00008010-0x00008018``, pad ``0xFF``).
FIXTURE_CONCAT = zlib.crc32(bytes(range(8)) + bytes(range(0x10, 0x18)))
FIXTURE_FILL = zlib.crc32(bytes(range(8)) + b"\xff" * 8 + bytes(range(0x10, 0x18)))

#: The three preview lines of the fixture image under the first-shown form.
FIXTURE_PREVIEW = (
    "Active policy: join=concat\n"
    f"concat: 0x{FIXTURE_CONCAT:08X}\n"
    f"fill:   0x{FIXTURE_FILL:08X}"
)

#: The shipped empty-state note (no image loaded).
EMPTY_STATE = "Load an image to preview coverage CRCs over real bytes."


@pytest.fixture
def designer_recompute_counter(monkeypatch):
    """Count the calls of ``CrcDesignerPanel._recompute`` (reset per test)."""
    _RECOMPUTES[0] = 0
    original = CrcDesignerPanel._recompute

    def counted(self, *args, **kwargs):
        _RECOMPUTES[0] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(CrcDesignerPanel, "_recompute", counted)
    yield
    _RECOMPUTES[0] = 0


def designer_recomputes() -> int:
    """The recompute count since the fixture last reset it."""
    return _RECOMPUTES[0]


def designer_pending(app) -> Optional[object]:
    """The panel's pending-recompute timer; ``None`` when none (or no such
    attribute, as on the base tree)."""
    panel = app.query_one(CrcDesignerPanel)
    return getattr(panel, "_pending_recompute", None)


async def wait_designer_recompute(
    pilot, app, before: int, *, timeout: float = RECOMPUTE_WAIT_S
) -> None:
    """Wait until the recompute count is above ``before`` and none is pending."""
    await wait_until(
        pilot,
        lambda: designer_recomputes() > before and designer_pending(app) is None,
        lambda: (
            f"no settled recompute: count {designer_recomputes()} "
            f"(snapshot {before}), pending {designer_pending(app)!r}"
        ),
        timeout=timeout,
        pause_first=True,
    )


def fixture_mem() -> Dict[int, int]:
    """The canonical two-range image: ``0x8000-0x8008`` = ``00..07``,
    ``0x8010-0x8018`` = ``10..17``, ``0x8008-0x8010`` absent (erased)."""
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return mem


def dirty_mem() -> Dict[int, int]:
    """The fixture image plus one present byte (``0x99``) in the erased gap."""
    mem = fixture_mem()
    mem[0x800B] = 0x99
    return mem


def loaded(mem_map: Dict[int, int]) -> LoadedFile:
    """Wrap ``mem_map`` in a minimal loaded-image snapshot."""
    return LoadedFile(
        path=Path("preview.s19"),
        file_type="s19",
        mem_map=dict(mem_map),
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
