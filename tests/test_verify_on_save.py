"""HLR-003 — verify-on-save engine tests.

The unit under test is ``s19_app.tui.changes.verify.verify_written_image``
(NEW this batch, G-3 resolved to a dedicated headless helper module in the
``changes`` package, next to ``io.py``/``apply.py``). It re-reads a just-written
image with the parser matching its ``file_type`` and diffs the re-read map
against the *intended* map via the batch-09 ``compare.diff_mem_maps`` engine,
returning a ``VerifyResult`` (``verified`` / ``mismatch`` + runs + stats).

Each test WRITES a real image with the I1 emitters (``emit_intel_hex_from_mem_map``
for hex, ``emit_s19_from_mem_map`` for s19), then verifies against an intended
map. The fault is planted in the *intended* vs *written-from* map so the asserted
run kind matches the planted fault (Rule 9, H-4):
- identity  → written-from == intended → empty diff → ``verified``.
- MUTATION  → intended holds value X, file holds value Y at the same addr →
              exactly one ``changed`` run of length 1 → ``mismatch``.
- DROP      → intended holds an addr the file omits → exactly one ``only_a``
              run of length 1 → ``mismatch`` (intended is diff map A).

Test → TC → LLR map (provisional TC ids per V-5):
- test_identity_write_is_verified[hex|s19]      → TC-006 → LLR-003.1/.2
- test_mutated_byte_is_mismatch_changed[hex|s19]→ TC-007 → LLR-003.2
- test_dropped_byte_is_mismatch_only_a[hex|s19] → TC-008 → LLR-003.2/.3
- test_unsupported_file_type_raises             → (guard) LLR-003.1
- test_written_path_is_stamped                  → (guard) C-10 carrier field
"""
from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.compare import KIND_CHANGED, KIND_ONLY_A
from s19_app.tui.changes.io import (
    emit_intel_hex_from_mem_map,
    emit_s19_from_mem_map,
)
from s19_app.tui.changes.verify import (
    STATUS_MISMATCH,
    STATUS_VERIFIED,
    verify_written_image,
)


def _ranges_from_mem(mem_map: dict[int, int]) -> list[tuple[int, int]]:
    """Contiguous half-open ``(start, end)`` ranges from a sparse map's keys."""
    addresses = sorted(mem_map)
    if not addresses:
        return []
    ranges: list[tuple[int, int]] = []
    start = prev = addresses[0]
    for addr in addresses[1:]:
        if addr == prev + 1:
            prev = addr
        else:
            ranges.append((start, prev + 1))
            start = prev = addr
    ranges.append((start, prev + 1))
    return ranges


def _write_image(mem_map: dict[int, int], file_type: str, tmp_path: Path) -> Path:
    """Serialize ``mem_map`` with the I1 emitter for ``file_type`` and write it."""
    ranges = _ranges_from_mem(mem_map)
    if file_type == "hex":
        text = emit_intel_hex_from_mem_map(mem_map, ranges)
    else:
        text = emit_s19_from_mem_map(mem_map, ranges)
    target = tmp_path / f"written.{file_type}"
    target.write_text(text, encoding="utf-8")
    return target


# A small contiguous block; addresses stay <=0xFFFF so neither format needs the
# extended-address machinery to round-trip (that is exercised in test_hex_emit).
_BASE = 0x1000
_INTENDED = {_BASE + offset: (offset * 5) & 0xFF for offset in range(0x20)}
_FAULT_ADDR = _BASE + 0x10


@pytest.mark.parametrize("file_type", ["hex", "s19"])
def test_identity_write_is_verified(file_type: str, tmp_path: Path) -> None:
    """TC-006 (LLR-003.1/.2): a faithful write yields an empty diff, status
    verified, and all per-kind run/byte counts zero."""
    written = _write_image(_INTENDED, file_type, tmp_path)

    result = verify_written_image(written, _INTENDED, file_type)

    assert result.status == STATUS_VERIFIED
    assert len(result.runs) == 0
    assert all(count == 0 for count in result.stats.run_counts.values())
    assert all(count == 0 for count in result.stats.byte_counts.values())


@pytest.mark.parametrize("file_type", ["hex", "s19"])
def test_mutated_byte_is_mismatch_changed(file_type: str, tmp_path: Path) -> None:
    """TC-007 (LLR-003.2): a byte written with the wrong value (same address)
    yields exactly one ``changed`` run of length 1, status mismatch."""
    written_from = dict(_INTENDED)
    # Mutate the value the FILE will carry, leaving the address present in both.
    written_from[_FAULT_ADDR] = (_INTENDED[_FAULT_ADDR] ^ 0xFF) & 0xFF
    assert written_from[_FAULT_ADDR] != _INTENDED[_FAULT_ADDR]
    written = _write_image(written_from, file_type, tmp_path)

    result = verify_written_image(written, _INTENDED, file_type)

    assert result.status == STATUS_MISMATCH
    assert len(result.runs) == 1
    assert result.runs[0].kind == KIND_CHANGED
    assert result.runs[0].length == 1
    assert result.runs[0].start == _FAULT_ADDR


@pytest.mark.parametrize("file_type", ["hex", "s19"])
def test_dropped_byte_is_mismatch_only_a(file_type: str, tmp_path: Path) -> None:
    """TC-008 (LLR-003.2/.3): a byte the file failed to persist (present in the
    intended map, absent from the file) yields exactly one ``only_a`` run of
    length 1 (intended is diff map A), status mismatch."""
    written_from = dict(_INTENDED)
    # Drop a byte at a range BOUNDARY so its absence is one isolated only_a run
    # rather than splitting an interior run into neighbours.
    drop_addr = max(_INTENDED)
    del written_from[drop_addr]
    written = _write_image(written_from, file_type, tmp_path)

    result = verify_written_image(written, _INTENDED, file_type)

    assert result.status == STATUS_MISMATCH
    assert len(result.runs) == 1
    assert result.runs[0].kind == KIND_ONLY_A
    assert result.runs[0].length == 1
    assert result.runs[0].start == drop_addr


def test_unsupported_file_type_raises(tmp_path: Path) -> None:
    """LLR-003.1 guard: a file_type the save-back never writes is a caller
    programming error, surfaced as ValueError (not a silent empty diff)."""
    written = _write_image(_INTENDED, "hex", tmp_path)
    with pytest.raises(ValueError):
        verify_written_image(written, _INTENDED, "mac")


def test_written_path_is_stamped(tmp_path: Path) -> None:
    """C-10 carrier guard: the result stamps the verified path so a mismatch
    notice (LLR-004.2) can name the file."""
    written = _write_image(_INTENDED, "hex", tmp_path)
    result = verify_written_image(written, _INTENDED, "hex")
    assert result.written_path == written
