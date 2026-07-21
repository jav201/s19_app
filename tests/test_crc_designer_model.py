"""
Tests for the CRC Designer template / job / coverage model (batch-52).

Intent:
  - The two-level gap model (intra_gap x join) is the operator's flexibility
    requirement; the tests pin the VERIFIED oracle values so a future refactor
    that silently changes what bytes get digested fails here (AT-CRC-DSN-013b).
  - JSON round-trip + collect-don't-abort mirror the shipped crc_config
    contract: a malformed template/job is one error and never a crash.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.operations.crc_designer_model import (
    CrcTarget,
    compute_target_crc,
    emit_template,
    evaluate_target,
    gap_conflict,
    gather_target,
    parse_job,
    parse_template,
    read_template,
    seed_template,
    store_word,
)
from s19_app.tui.operations.crc_kernel import SEED_ALGORITHM


# ── multi-range coverage: the verified oracles ──────────────────────────────
def _two_range_mem() -> dict[int, int]:
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return mem


def test_join_concat_matches_group_behavior_oracle() -> None:
    # intra=skip, join=concat == today's group (butt present bytes) -> 0x9C5BCBBD.
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "concat", 0xFF, 0x8018, 4, "little")
    window = gather_target(_two_range_mem(), target)
    assert len(window) == 16
    assert compute_target_crc(_two_range_mem(), SEED_ALGORITHM, target) == 0x9C5BCBBD


def test_join_fill_pads_between_ranges_oracle() -> None:
    # join=fill pads the 8-byte inter-range gap with 0xFF -> 24 bytes -> 0x2A8A3950.
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "fill", 0xFF, 0x8018, 4, "little")
    window = gather_target(_two_range_mem(), target)
    assert len(window) == 24
    assert window[8:16] == b"\xff" * 8
    assert compute_target_crc(_two_range_mem(), SEED_ALGORITHM, target) == 0x2A8A3950


def test_intra_skip_vs_fill_differ_only_when_a_range_has_holes() -> None:
    mem = {0: 0x00, 1: 0x01, 3: 0x03}  # 0x02 absent inside [0,4)
    skip = CrcTarget(((0, 4),), "skip", "concat", 0xFF, 0x10, 4, "little")
    fill = CrcTarget(((0, 4),), "fill", "concat", 0xFF, 0x10, 4, "little")
    assert gather_target(mem, skip) == b"\x00\x01\x03"
    assert gather_target(mem, fill) == b"\x00\x01\xff\x03"


def test_declared_range_order_is_authoritative() -> None:
    # Ranges are NOT address-sorted (parity with the group contract).
    mem = {0: 0xAA, 1: 0xBB, 4: 0xCC, 5: 0xDD}
    forward = CrcTarget(((0, 2), (4, 6)), "skip", "concat", 0xFF, 0x10, 4, "little")
    reverse = CrcTarget(((4, 6), (0, 2)), "skip", "concat", 0xFF, 0x10, 4, "little")
    assert gather_target(mem, forward) == b"\xaa\xbb\xcc\xdd"
    assert gather_target(mem, reverse) == b"\xcc\xdd\xaa\xbb"


# ── gap safety (obs #2) ─────────────────────────────────────────────────────
def test_gap_conflict_clean_fill_has_no_conflict() -> None:
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "fill", 0xFF, 0x8018, 4, "little")
    assert gap_conflict(_two_range_mem(), target) == []


def test_gap_conflict_flags_stray_data_in_a_filled_gap() -> None:
    # A byte present in the "erased" inter-range gap that isn't the pad value:
    # filling would digest 0xFF over real data → the device's CRC would differ.
    dirty = _two_range_mem()
    dirty[0x800A] = 0x99
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "fill", 0xFF, 0x8018, 4, "little")
    assert gap_conflict(dirty, target) == [0x800A]


def test_gap_conflict_ignores_pad_valued_present_bytes() -> None:
    # A present byte in the gap that EQUALS pad_byte is consistent — no conflict.
    padded = _two_range_mem()
    padded[0x800A] = 0xFF
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "fill", 0xFF, 0x8018, 4, "little")
    assert gap_conflict(padded, target) == []


def test_gap_conflict_is_empty_for_concat_join() -> None:
    # concat never fabricates bytes, so there is nothing to contradict.
    dirty = _two_range_mem()
    dirty[0x800A] = 0x99
    target = CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "concat", 0xFF, 0x8018, 4, "little")
    assert gap_conflict(dirty, target) == []


def test_on_gap_conflict_parses_and_defaults_to_abort() -> None:
    default_job, errors = parse_job(
        '{"algorithm_ref":"CRC-32/ISO-HDLC","targets":[{"ranges":[{"start":0,"end":1}],"output_address":0}]}'
    )
    assert errors == []
    assert default_job is not None
    assert default_job.targets[0].on_gap_conflict == "abort"

    warn_job, errors2 = parse_job(
        '{"algorithm_ref":"CRC-32/ISO-HDLC","targets":[{"ranges":[{"start":0,"end":1}],"on_gap_conflict":"warn","output_address":0}]}'
    )
    assert errors2 == []
    assert warn_job is not None
    assert warn_job.targets[0].on_gap_conflict == "warn"


def test_invalid_on_gap_conflict_is_one_collected_error() -> None:
    bad, errors = parse_job(
        '{"algorithm_ref":"CRC-32/ISO-HDLC","targets":[{"ranges":[{"start":0,"end":1}],"on_gap_conflict":"nuke","output_address":0}]}'
    )
    assert bad is None and len(errors) == 1


# ── E8: on_gap_conflict enforcement (batch-57) ──────────────────────────────
def _dirty_fill_target(policy: str) -> CrcTarget:
    return CrcTarget(((0x8000, 0x8008), (0x8010, 0x8018)), "skip", "fill", 0xFF, 0x8018, 4, "little", policy)


def _dirty_mem() -> dict[int, int]:
    mem = _two_range_mem()
    mem[0x800A] = 0x99  # stray real byte in the "erased" filled gap
    return mem


def test_evaluate_target_aborts_on_conflict() -> None:
    # AT-E8-abort: abort policy + a dirty filled gap → refused, no CRC, addresses named.
    ev = evaluate_target(_dirty_mem(), SEED_ALGORITHM, _dirty_fill_target("abort"))
    assert ev.refused is True
    assert ev.crc is None
    assert ev.conflicts == (0x800A,)
    assert len(ev.diagnostics) == 1 and "refused" in ev.diagnostics[0]
    assert "0x800A" in ev.diagnostics[0]


def test_evaluate_target_warn_proceeds_with_diagnostic() -> None:
    # AT-E8-warn: warn policy → CRC computed, conflict surfaced, not refused.
    ev = evaluate_target(_dirty_mem(), SEED_ALGORITHM, _dirty_fill_target("warn"))
    assert ev.refused is False
    assert ev.crc == 0x2A8A3950  # same padded-window CRC as the clean oracle (fill ignores mem in the gap)
    assert ev.conflicts == (0x800A,)
    assert len(ev.diagnostics) == 1 and "warn" in ev.diagnostics[0]


def test_evaluate_target_ignore_is_silent() -> None:
    # AT-E8-ignore: ignore policy → CRC computed, no diagnostic (conflict still recorded).
    ev = evaluate_target(_dirty_mem(), SEED_ALGORITHM, _dirty_fill_target("ignore"))
    assert ev.refused is False
    assert ev.crc == 0x2A8A3950
    assert ev.conflicts == (0x800A,)
    assert ev.diagnostics == ()


def test_evaluate_target_clean_computes_under_every_policy() -> None:
    # A conflict-free target computes normally regardless of policy.
    for policy in ("abort", "warn", "ignore"):
        ev = evaluate_target(_two_range_mem(), SEED_ALGORITHM, _dirty_fill_target(policy))
        assert ev.refused is False
        assert ev.conflicts == ()
        assert ev.diagnostics == ()
        assert ev.crc == 0x2A8A3950  # the join=fill oracle over the clean image


# ── serialization ───────────────────────────────────────────────────────────
def test_store_word_endianness() -> None:
    le = CrcTarget(((0, 1),), "skip", "concat", 0xFF, 0x10, 4, "little")
    be = CrcTarget(((0, 1),), "skip", "concat", 0xFF, 0x10, 4, "big")
    assert store_word(0x04030201, le) == b"\x01\x02\x03\x04"
    assert store_word(0x04030201, be) == b"\x04\x03\x02\x01"


def test_store_word_narrow_and_wide_fields() -> None:
    narrow = CrcTarget(((0, 1),), "skip", "concat", 0xFF, 0x10, 2, "little")
    wide = CrcTarget(((0, 1),), "skip", "concat", 0xFF, 0x10, 8, "little")
    assert store_word(0x1234, narrow) == b"\x34\x12"
    assert store_word(0xCBF43926, wide) == b"\x26\x39\xf4\xcb\x00\x00\x00\x00"


# ── template round-trip ─────────────────────────────────────────────────────
def test_template_round_trips_through_json() -> None:
    original = seed_template()
    reparsed, errors = parse_template(emit_template(original))
    assert errors == []
    assert reparsed == original


def test_seed_template_is_the_current_implementation() -> None:
    # AT-CRC-DSN-010 at the template layer.
    assert seed_template().algorithm == SEED_ALGORITHM
    assert seed_template().algorithm.kat_ok() is True


def test_parse_template_collects_faults_without_raising() -> None:
    for bad in ["{not json", "[]", '{"name": "x"}', '{"name":"","algorithm":{}}']:
        template, errors = parse_template(bad)
        assert template is None
        assert len(errors) == 1


# ── job parsing (algorithm_ref + inline) ────────────────────────────────────
def test_parse_job_resolves_algorithm_ref_against_presets() -> None:
    text = """
    {
      "algorithm_ref": "CRC-32/ISO-HDLC",
      "targets": [
        {"ranges": [{"start": "0x8000", "end": "0x8008"}],
         "output_address": "0x8008"}
      ]
    }
    """
    job, errors = parse_job(text)
    assert errors == []
    assert job is not None
    assert job.algorithm == SEED_ALGORITHM
    assert job.targets[0].intra_gap == "skip" and job.targets[0].join == "concat"


def test_parse_job_accepts_inline_algorithm() -> None:
    text = """
    {
      "algorithm": {"width": 16, "poly": "0x1021", "init": "0x0000",
                    "refin": false, "refout": false, "xorout": "0x0000",
                    "check": "0x31C3"},
      "algorithm_name": "CRC-16/XMODEM",
      "targets": [
        {"ranges": [{"start": "0x0", "end": "0x8"}, {"start": "0x10", "end": "0x18"}],
         "intra_gap": "skip", "join": "fill", "output_address": "0x18"}
      ]
    }
    """
    job, errors = parse_job(text)
    assert errors == []
    assert job is not None
    assert job.algorithm.name == "CRC-16/XMODEM"
    assert job.targets[0].join == "fill"


def test_parse_job_reports_unknown_ref_and_bad_targets() -> None:
    unknown, errors = parse_job('{"algorithm_ref":"nope","targets":[{"ranges":[{"start":0,"end":1}],"output_address":0}]}')
    assert unknown is None and len(errors) == 1

    inverted, errors2 = parse_job(
        '{"algorithm_ref":"CRC-32/ISO-HDLC","targets":[{"ranges":[{"start":"0x10","end":"0x8"}],"output_address":"0x0"}]}'
    )
    assert inverted is None and len(errors2) == 1

    bad_policy, errors3 = parse_job(
        '{"algorithm_ref":"CRC-32/ISO-HDLC","targets":[{"ranges":[{"start":0,"end":1}],"join":"weird","output_address":0}]}'
    )
    assert bad_policy is None and len(errors3) == 1


def test_parse_job_non_object_inline_algorithm_is_collected_not_raised() -> None:
    # F1 regression: a string/list where an 'algorithm' object is expected (the
    # classic 'meant algorithm_ref' typo) must collect-don't-abort, never raise.
    for bad_algo in ('"CRC-32/ISO-HDLC"', "[1, 2]", "5"):
        job, errors = parse_job(
            '{"algorithm": ' + bad_algo + ', "targets":[{"ranges":[{"start":0,"end":1}],"output_address":0}]}'
        )
        assert job is None and len(errors) == 1


def test_parse_job_null_algorithm_name_does_not_become_literal_none() -> None:
    # F1 rider: "algorithm_name": null must fall back to the inline name, not "None".
    text = (
        '{"algorithm_name": null, "algorithm": {"name": "MyCRC", "width": 16, '
        '"poly": "0x1021", "init": "0x0", "refin": false, "refout": false, "xorout": "0x0"}, '
        '"targets":[{"ranges":[{"start":0,"end":1}],"output_address":0}]}'
    )
    job, errors = parse_job(text)
    assert errors == []
    assert job is not None and job.algorithm.name == "MyCRC"


def test_read_template_faults_are_collected(tmp_path: Path) -> None:
    missing, errors = read_template("does-not-exist.crc.json", base_dir=tmp_path)
    assert missing is None and len(errors) == 1

    over_cap = tmp_path / "big.crc.json"
    over_cap.write_text("{}", encoding="utf-8")
    template, errors2 = read_template(
        "big.crc.json", base_dir=tmp_path, size_probe=lambda _p: 999_999_999_999
    )
    assert template is None and len(errors2) == 1
    assert "read cap" in errors2[0]


def test_read_template_round_trips_a_written_file(tmp_path: Path) -> None:
    path = tmp_path / "seed.crc.json"
    path.write_text(emit_template(seed_template()), encoding="utf-8")
    template, errors = read_template("seed.crc.json", base_dir=tmp_path)
    assert errors == []
    assert template == seed_template()
