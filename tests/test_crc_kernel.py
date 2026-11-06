"""
Tests for the width-general CRC kernel (batch-52 designer building block).

Intent (why these matter, not just what):
  - The kernel REPLACES a 32-bit-only engine with a width-general one, so the
    load-bearing guarantee is that every published catalogue variant reproduces
    its ``check`` value — a single wrong shift/mask silently weakens firmware
    integrity checks, so the KAT table is the correctness oracle.
  - The seed algorithm must equal ``zlib.crc32`` byte-for-byte, or the
    "first template == current implementation" fidelity claim (AT-CRC-DSN-010)
    is false.

Batch-91 contract adoption (HLR-122):
# TC-629 — this module pins the parameterized Rocksoft CRC kernel, width 8-64, with its catalogue presets (LLR-122.4).
"""

from __future__ import annotations

import zlib

import pytest

import random

from s19_app.tui.operations.crc_kernel import (
    KAT_MESSAGE,
    PRESETS,
    SEED_ALGORITHM,
    CrcAlgorithm,
    crc_lut,
    crc_stream,
    make_crc_table,
    preset_by_name,
    reflect,
)


@pytest.mark.parametrize("preset", PRESETS, ids=[p.name for p in PRESETS])
def test_every_preset_reproduces_its_catalogue_check(preset: CrcAlgorithm) -> None:
    # AT-CRC-DSN-011: the KAT table. A wrong kernel fails loudly here.
    assert preset.kat() == preset.check
    assert preset.kat_ok() is True


def test_seed_algorithm_equals_zlib_crc32_over_many_vectors() -> None:
    # AT-CRC-DSN-010: the fidelity anchor — seed CRC-32 == zlib.crc32.
    vectors = [
        b"",
        KAT_MESSAGE,
        b"The quick brown fox jumps over the lazy dog",
        bytes(range(256)),
        b"\x00" * 300,
    ]
    for data in vectors:
        assert SEED_ALGORITHM.compute(data) == zlib.crc32(data) & 0xFFFFFFFF


def test_kat_ok_is_none_without_a_pinned_check() -> None:
    # The tri-state the live-verify surface renders as "no expected".
    custom = CrcAlgorithm("custom", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, check=None)
    assert custom.kat_ok() is None


def test_kat_ok_false_on_a_diverged_variant() -> None:
    # Flipping refout off breaks CCITT-FALSE — verify catches it (the whole
    # point of live known-answer verification).
    ccitt = preset_by_name("CRC-16/CCITT-FALSE")
    assert ccitt is not None
    diverged = CrcAlgorithm(ccitt.name, ccitt.width, ccitt.poly, ccitt.init,
                            ccitt.refin, refout=not ccitt.refout,
                            xorout=ccitt.xorout, check=ccitt.check)
    assert diverged.kat_ok() is False


def test_reflect_reverses_low_bits() -> None:
    assert reflect(0x01, 8) == 0x80
    assert reflect(0x80, 8) == 0x01
    assert reflect(0b1011, 4) == 0b1101


def test_crc_stream_rejects_out_of_range_width() -> None:
    with pytest.raises(ValueError):
        crc_stream(b"x", width=4, poly=0x3, init=0, refin=False, refout=False, xorout=0)
    with pytest.raises(ValueError):
        crc_stream(b"x", width=128, poly=0x3, init=0, refin=False, refout=False, xorout=0)


def test_independent_refin_refout_is_wired() -> None:
    # No catalogue vector exists for refin != refout (RK-3), but the params must
    # be independently honored: flipping only refout changes the result.
    base = dict(width=16, poly=0x1021, init=0xFFFF, refin=False, xorout=0x0000)
    a = crc_stream(KAT_MESSAGE, refout=False, **base)
    b = crc_stream(KAT_MESSAGE, refout=True, **base)
    assert a != b


def test_preset_by_name_is_case_insensitive_and_misses_return_none() -> None:
    assert preset_by_name("crc-32c/castagnoli") is preset_by_name("CRC-32C/Castagnoli")
    assert preset_by_name("nope") is None


# ── E7: table-driven fast path (batch-57) ───────────────────────────────────
def _diff_vectors() -> list[bytes]:
    rng = random.Random(20260720)
    fixed = [b"", KAT_MESSAGE, bytes(range(256)), b"\x00" * 257, b"\xff" * 130]
    rnd = [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(40)]
    return fixed + rnd


def test_lut_matches_bitwise_oracle_over_presets_and_random_vectors() -> None:
    # TC-E7-LUT: the table-driven fast path is byte-identical to the crc_stream
    # oracle for every catalogue preset (widths 8/16/32/64) over 45 vectors.
    for preset in PRESETS:
        params = dict(
            width=preset.width, poly=preset.poly, init=preset.init,
            refin=preset.refin, refout=preset.refout, xorout=preset.xorout,
        )
        for data in _diff_vectors():
            assert crc_lut(data, **params) == crc_stream(data, **params), preset.name


def test_lut_matches_oracle_for_non_catalogue_refin_ne_refout() -> None:
    # RK-3 combo (no catalogue vector): the LUT must still track the oracle.
    odd = dict(width=16, poly=0x1021, init=0xFFFF, refin=True, refout=False, xorout=0x0000)
    for data in _diff_vectors():
        assert crc_lut(data, **odd) == crc_stream(data, **odd)


def test_lut_matches_oracle_for_non_byte_aligned_widths() -> None:
    # F2: exercise the shift = width-8 arithmetic on non-multiple-of-8 widths;
    # no catalogue check pins these, so the crc_stream oracle is the only guard.
    cases = [dict(width=12, poly=0x80F, init=0x000), dict(width=24, poly=0x864CFB, init=0xB704CE)]
    for case in cases:
        for refin in (False, True):
            for refout in (False, True):
                params = dict(**case, refin=refin, refout=refout, xorout=0)
                for data in _diff_vectors():
                    assert crc_lut(data, **params) == crc_stream(data, **params), case


def test_r_crc_designer_001_1_lut_matches_oracle_200_vectors_and_widths_9_to_63() -> None:
    # batch-101 Inc 13 E5 corrective (C-6): the threshold of R-CRC-DESIGNER-001.1
    # as written. (1) every catalogue preset over the 5 fixed vectors plus 200
    # random ones (length 0-199, seed 20261105); (2) every width from 9 to 63
    # that is not a multiple of 8 (49 widths), with all four refin/refout pairs,
    # a seeded odd polynomial with its top bit set, a seeded init and xorout,
    # over the 5 fixed vectors plus 20 random ones. The table-driven engine
    # reflects input bytes through _REFLECT8 (Inc 13); one wrong entry of that
    # table (M-11: _REFLECT8[1] = 0x01) makes a refin case differ.
    rng = random.Random(20261105)
    fixed = [b"", KAT_MESSAGE, bytes(range(256)), b"\x00" * 257, b"\xff" * 130]
    many = fixed + [
        bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(200)
    ]
    assert len(many) == 205
    for preset in PRESETS:
        params = dict(
            width=preset.width, poly=preset.poly, init=preset.init,
            refin=preset.refin, refout=preset.refout, xorout=preset.xorout,
        )
        for data in many:
            assert crc_lut(data, **params) == crc_stream(data, **params), preset.name
    few = fixed + many[5:25]
    widths = [w for w in range(9, 64) if w % 8]
    assert len(widths) == 49
    for width in widths:
        poly = rng.getrandbits(width) | 1 | (1 << (width - 1))
        init, xorout = rng.getrandbits(width), rng.getrandbits(width)
        for refin in (False, True):
            for refout in (False, True):
                params = dict(
                    width=width, poly=poly, init=init,
                    refin=refin, refout=refout, xorout=xorout,
                )
                for data in few:
                    assert crc_lut(data, **params) == crc_stream(data, **params), params


def test_compute_routes_through_lut_and_preserves_kat() -> None:
    # compute() now uses crc_lut; the KAT values must be byte-identical.
    for preset in PRESETS:
        assert preset.compute(KAT_MESSAGE) == preset.check


def test_crc_table_is_cached_per_width_poly() -> None:
    a = make_crc_table(32, 0x04C11DB7)
    b = make_crc_table(32, 0x04C11DB7)
    assert a is b and len(a) == 256  # lru_cache returns the identical built table
