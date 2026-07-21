"""
Tests for the E6 flat-config up-converter + job serializer (batch-58, Inc-3).

Intent (why these matter, not just what):
  - A shipped ``crc_config.json`` (the flat ``polynomial``/``regions``/``groups``
    schema) must keep working after the job model evolved — an operator's real
    per-firmware config parsing to an ERROR would be a silent regression, so the
    up-convert is pinned to the SAME digest semantics as today's
    ``crc.compute_group_crc`` (LLR-E6.1/E6.2).
  - A whole job must be writable and reloadable without drift, so authoring a
    job in the view and re-reading it is lossless (LLR-E6.3 round-trip).
  - The loader stays collect-don't-abort: a bad flat field is one error, never a
    crash (the ``crc_config`` posture).
"""

from __future__ import annotations

from s19_app.tui.operations import crc
from s19_app.tui.operations.crc_config import DUMMY_CONFIG_TEXT
from s19_app.tui.operations.crc_designer_model import (
    CrcJob,
    CrcTarget,
    compute_target_crc,
    emit_job,
    parse_job,
    parse_template,
    emit_template,
    seed_template,
)
from s19_app.tui.operations.crc_kernel import SEED_ALGORITHM

# A representative flat config with ONE region and ONE two-span group, distinct
# non-default algorithm params, so the up-convert field mapping is observable.
_FLAT_TEXT = """{
  "polynomial": "0x04C11DB7",
  "init": "0xFFFFFFFF",
  "reverse": true,
  "final_xor": "0xFFFFFFFF",
  "regions": [
    { "start": "0x8000", "end": "0x8008", "output_address": "0x8FFC" }
  ],
  "groups": [
    {
      "regions": [
        { "start": "0x9000", "end": "0x9008" },
        { "start": "0x9010", "end": "0x9018" }
      ],
      "output_address": "0x9FFC",
      "output_bytes": 2
    }
  ]
}
"""


def _two_range_mem() -> dict[int, int]:
    # NOTE (Inc-3 code-review F1): the group under test spans 0x9000/0x9010, so the
    # fixture MUST populate those addresses — else both digests see b'' and the
    # equivalence assertion collapses to 0x0==0x0 (vacuous). The byte VALUES match
    # the §3.2 oracle vector, so concat digests to 0x9C5BCBBD.
    mem = {0x9000 + i: i for i in range(8)}
    mem.update({0x9010 + i: 0x10 + i for i in range(8)})
    return mem


# ── LLR-E6.1: flat up-convert correctness ───────────────────────────────────
def test_llr_e6_1_flat_dummy_config_parses_with_zero_errors() -> None:
    # Pre-state (RED probe) was exactly 1 error; the up-convert clears it.
    job, errors = parse_job(DUMMY_CONFIG_TEXT)
    assert errors == []
    assert job is not None
    # regions=2 + groups=1 -> 3 targets, in file order.
    assert len(job.targets) == 3


def test_llr_e6_1_algorithm_field_mapping() -> None:
    # reverse -> refin==refout; polynomial->poly; init->init; final_xor->xorout;
    # width fixed 32; no published check on a flat config.
    job, errors = parse_job(_FLAT_TEXT)
    assert errors == []
    assert job is not None
    a = job.algorithm
    assert a.width == 32
    assert a.poly == 0x04C11DB7
    assert a.init == 0xFFFFFFFF
    assert a.refin is True and a.refout is True
    assert a.xorout == 0xFFFFFFFF
    assert a.check is None


def test_llr_e6_1_region_becomes_single_range_skip_concat_target() -> None:
    job, errors = parse_job(_FLAT_TEXT)
    assert errors == []
    assert job is not None
    region_target = job.targets[0]
    assert region_target.ranges == ((0x8000, 0x8008),)
    assert region_target.intra_gap == "skip"
    assert region_target.join == "concat"
    assert region_target.store_width == 4
    assert region_target.store_endianness == "little"
    assert region_target.output_address == 0x8FFC


def test_llr_e6_1_group_becomes_multi_range_target_with_output_bytes_width() -> None:
    job, errors = parse_job(_FLAT_TEXT)
    assert errors == []
    assert job is not None
    group_target = job.targets[1]
    assert group_target.ranges == ((0x9000, 0x9008), (0x9010, 0x9018))
    assert group_target.intra_gap == "skip"
    assert group_target.join == "concat"
    # output_bytes -> store_width.
    assert group_target.store_width == 2
    assert group_target.output_address == 0x9FFC


def test_llr_e6_1_upconvert_digest_matches_compute_group_crc_semantics() -> None:
    # The up-converted target must digest identically to today's engine over the
    # same spans/params (the back-compat guarantee that motivates E6).
    job, errors = parse_job(_FLAT_TEXT)
    assert errors == []
    assert job is not None
    mem = _two_range_mem()
    group_target = job.targets[1]
    expected = crc.compute_group_crc(
        mem,
        [(0x9000, 0x9008), (0x9010, 0x9018)],
        polynomial=0x04C11DB7,
        init=0xFFFFFFFF,
        reverse=True,
        final_xor=0xFFFFFFFF,
    )
    # Pin the §3.2 concat oracle so a dropped/reordered range goes RED (not 0x0==0x0).
    assert compute_target_crc(mem, job.algorithm, group_target) == expected == 0x9C5BCBBD


def test_llr_e6_1_groups_only_flat_config_up_converts() -> None:
    # Boundary: a flat config with groups and NO regions.
    groups_only = """{
      "polynomial": "0x04C11DB7", "init": "0xFFFFFFFF",
      "reverse": true, "final_xor": "0xFFFFFFFF",
      "groups": [ { "regions": [ { "start": "0x0", "end": "0x4" } ],
                   "output_address": "0x100" } ]
    }"""
    job, errors = parse_job(groups_only)
    assert errors == []
    assert job is not None
    assert len(job.targets) == 1
    assert job.targets[0].ranges == ((0x0, 0x4),)


# ── LLR-E6.2: back-compat — evolved shape + collect-don't-abort ─────────────
def test_llr_e6_2_evolved_algorithm_ref_job_unchanged() -> None:
    # Pin an evolved fixture: it must still parse to a job (no flat branch taken).
    text = (
        '{"algorithm_ref":"CRC-32/ISO-HDLC",'
        '"targets":[{"ranges":[{"start":0,"end":1}],"output_address":0}]}'
    )
    job, errors = parse_job(text)
    assert errors == []
    assert job is not None
    assert job.algorithm.name == "CRC-32/ISO-HDLC"
    assert job.targets[0].intra_gap == "skip" and job.targets[0].join == "concat"


def test_llr_e6_2_evolved_inline_algorithm_job_unchanged() -> None:
    text = """{
      "algorithm": { "name": "custom", "width": 16, "poly": "0x1021",
                     "init": "0xFFFF", "refin": false, "refout": false,
                     "xorout": "0x0000", "check": "0x29B1" },
      "targets": [ { "ranges": [ { "start": "0x0", "end": "0x8" } ],
                     "join": "fill", "output_address": "0x100" } ]
    }"""
    job, errors = parse_job(text)
    assert errors == []
    assert job is not None
    assert job.algorithm.width == 16
    assert job.targets[0].join == "fill"


def test_llr_e6_2_malformed_flat_field_is_one_error_not_a_raise() -> None:
    # reverse as a string (not bool) -> exactly one collected error, no exception.
    bad = """{
      "polynomial": "0x04C11DB7", "init": "0xFFFFFFFF",
      "reverse": "yes", "final_xor": "0xFFFFFFFF",
      "regions": [ { "start": "0x0", "end": "0x4", "output_address": "0x100" } ]
    }"""
    job, errors = parse_job(bad)
    assert job is None
    assert len(errors) == 1


def test_llr_e6_2_flat_config_with_neither_regions_nor_groups_is_one_error() -> None:
    # Boundary parity with crc_config._build_config's at-least-one-of rule.
    empty = (
        '{"polynomial":"0x04C11DB7","init":"0xFFFFFFFF",'
        '"reverse":true,"final_xor":"0xFFFFFFFF"}'
    )
    job, errors = parse_job(empty)
    assert job is None
    assert len(errors) == 1


# ── LLR-E6.3 + AT-058-01: job serializer round-trip ─────────────────────────
def test_at_058_01_flat_upconvert_round_trips_through_emit_job() -> None:
    # AT-058-01: flat crc_config -> parse_job -> emit_job -> parse_job == equal job.
    first, errors = parse_job(DUMMY_CONFIG_TEXT)
    assert errors == []
    assert first is not None
    round_tripped, errors2 = parse_job(emit_job(first))
    assert errors2 == []
    assert round_tripped == first


def test_llr_e6_3_emit_round_trip_two_targets_mixed_join() -> None:
    # A hand-built job with two targets (one fill, one concat) + a checked
    # algorithm exercises every emitted field incl. check + big endianness.
    concat_target = CrcTarget(
        ranges=((0x100, 0x108),),
        intra_gap="skip",
        join="concat",
        pad_byte=0xFF,
        output_address=0x1FC,
        store_width=4,
        store_endianness="little",
    )
    fill_target = CrcTarget(
        ranges=((0x200, 0x204), (0x210, 0x214)),
        intra_gap="fill",
        join="fill",
        pad_byte=0x00,
        output_address=0x2FC,
        store_width=8,
        store_endianness="big",
        on_gap_conflict="warn",
    )
    job = CrcJob(algorithm=SEED_ALGORITHM, targets=(concat_target, fill_target))
    parsed, errors = parse_job(emit_job(job))
    assert errors == []
    assert parsed == job


# ── AT-CRC-DSN-012: template round-trip (facade-independent) ─────────────────
def test_at_crc_dsn_012_template_round_trip_is_identical() -> None:
    template = seed_template()
    reparsed, errors = parse_template(emit_template(template))
    assert errors == []
    assert reparsed == template
