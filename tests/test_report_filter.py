"""Batch-35 Inc-1 — report filter parse + match engine (HLR-053).

TC-307: valid round-trip incl. hex/int equivalence (LLR-053.1).
TC-308: one-error-per-fault rejection matrix (LLR-053.1).
TC-309: read-path hostile corpus + ceilings boundary (LLR-053.2 / LLR-053.3).
TC-310: (a)/(b)/(c) match truth table + F-1/F-2/Q-9/Q-10 pins through the
        resolved-matcher API (LLR-053.4 / LLR-053.7).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from s19_app.tui.services.report_filter import (
    ADDRESS_RANGE_CEILING,
    REPORT_FILTER_FORMAT_ID,
    REPORT_FILTER_FORMAT_VERSION,
    REPORT_FILTER_SIZE_CAP_BYTES,
    SYMBOL_PATTERN_CEILING,
    ReportFilter,
    parse_report_filter,
    read_report_filter_text,
    resolve_report_filter,
)


def _doc(symbols=None, addresses=None, **overrides) -> str:
    """Build a valid filter JSON document, then apply top-level overrides."""
    data = {
        "format": REPORT_FILTER_FORMAT_ID,
        "version": REPORT_FILTER_FORMAT_VERSION,
        "include": {
            "symbols": symbols if symbols is not None else [],
            "addresses": addresses if addresses is not None else [],
        },
    }
    data.update(overrides)
    return json.dumps(data)


def _parse_ok(text: str) -> ReportFilter:
    flt, errors = parse_report_filter(text)
    assert errors == []
    assert flt is not None
    return flt


# ---------------------------------------------------------------------------
# TC-307 — valid round-trip (LLR-053.1)
# ---------------------------------------------------------------------------


class TestTc307ValidRoundTrip:
    """TC-307 — LLR-053.1: the envelope accepts the documented shape."""

    def test_full_valid_document_round_trips(self) -> None:
        """TC-307 / LLR-053.1: symbols + hex/int addresses parse to the typed form."""
        flt = _parse_ok(
            _doc(
                symbols=["CAL_*", "PAR[0]"],
                addresses=[
                    {"start": "0x10", "end": 32},
                    {"start": 100, "end": 101},
                ],
            )
        )
        assert flt.symbols == ("CAL_*", "PAR[0]")
        assert flt.addresses == ((16, 32), (100, 101))

    def test_hex_and_int_addresses_are_equivalent(self) -> None:
        """TC-307 / LLR-053.1 (Q-10): "0x10" and 16 parse to the same range."""
        hex_form = _parse_ok(_doc(addresses=[{"start": "0x10", "end": "0x20"}]))
        int_form = _parse_ok(_doc(addresses=[{"start": 16, "end": 32}]))
        assert hex_form == int_form

    def test_single_byte_range_is_valid(self) -> None:
        """TC-307 / LLR-053.1 boundary: start == end-1 single-byte range."""
        flt = _parse_ok(_doc(addresses=[{"start": 5, "end": 6}]))
        assert flt.addresses == ((5, 6),)

    def test_end_exactly_at_address_space_boundary_is_valid(self) -> None:
        """TC-307 / LLR-053.1: end == 2^32 is inside the pinned domain."""
        flt = _parse_ok(_doc(addresses=[{"start": 0, "end": 0x1_0000_0000}]))
        assert flt.addresses == ((0, 0x1_0000_0000),)

    def test_empty_include_lists_are_valid_and_match_nothing(self) -> None:
        """TC-307 / LLR-053.1 (D-10): empty include lists = valid, zero-match."""
        flt = _parse_ok(_doc(symbols=[], addresses=[]))
        matcher = resolve_report_filter(
            flt,
            [{"name": "CAL_X", "address": 0x10, "byte_size": 4}],
            [{"name": "MAC_Y", "address": 0x20}],
        )
        assert matcher.matches_item("CAL_X", 0x10, 0x14) is False
        assert matcher.matches_item(None, 0, 0x1_0000_0000) is False

    def test_file_round_trip_through_read_then_parse(self, tmp_path: Path) -> None:
        """TC-307 / LLR-053.2: read_report_filter_text feeds parse_report_filter."""
        path = tmp_path / "filter.json"
        path.write_text(_doc(symbols=["CAL_*"]), encoding="utf-8")
        text, read_errors = read_report_filter_text(str(path))
        assert read_errors == []
        assert text is not None
        flt = _parse_ok(text)
        assert flt.symbols == ("CAL_*",)


# ---------------------------------------------------------------------------
# TC-308 — one-error-per-fault rejection matrix (LLR-053.1)
# ---------------------------------------------------------------------------


class TestTc308RejectionMatrix:
    """TC-308 — LLR-053.1: one named diagnostic per fault, never raises."""

    def _errors(self, text: str) -> list[str]:
        flt, errors = parse_report_filter(text)
        assert flt is None
        assert errors, "expected at least one diagnostic"
        return errors

    def test_wrong_format(self) -> None:
        """TC-308 / LLR-053.1: wrong 'format' → one diagnostic naming it."""
        errors = self._errors(_doc(format="s19app-changeset"))
        assert len(errors) == 1
        assert "'format'" in errors[0]

    def test_missing_format(self) -> None:
        """TC-308 / LLR-053.1: missing 'format' → diagnostic naming it."""
        data = json.loads(_doc())
        del data["format"]
        errors = self._errors(json.dumps(data))
        assert len(errors) == 1
        assert "'format'" in errors[0]

    def test_wrong_version(self) -> None:
        """TC-308 / LLR-053.1: wrong 'version' → diagnostic naming it."""
        errors = self._errors(_doc(version="2.0"))
        assert len(errors) == 1
        assert "'version'" in errors[0]

    def test_missing_version(self) -> None:
        """TC-308 / LLR-053.1: missing 'version' → diagnostic naming it."""
        data = json.loads(_doc())
        del data["version"]
        errors = self._errors(json.dumps(data))
        assert len(errors) == 1
        assert "'version'" in errors[0]

    def test_unknown_top_level_key(self) -> None:
        """TC-308 / LLR-053.1: unknown top-level key → diagnostic naming it."""
        errors = self._errors(_doc(exclude={"symbols": []}))
        assert len(errors) == 1
        assert "'exclude'" in errors[0]

    def test_unknown_include_key(self) -> None:
        """TC-308 / LLR-053.1: unknown 'include' key → diagnostic naming it."""
        data = json.loads(_doc())
        data["include"]["names"] = []
        errors = self._errors(json.dumps(data))
        assert len(errors) == 1
        assert "'names'" in errors[0]

    def test_non_list_symbols(self) -> None:
        """TC-308 / LLR-053.1: non-list 'symbols' → diagnostic naming it."""
        errors = self._errors(_doc(symbols="CAL_*"))
        assert len(errors) == 1
        assert "include.symbols" in errors[0]

    def test_non_list_addresses(self) -> None:
        """TC-308 / LLR-053.1: non-list 'addresses' → diagnostic naming it."""
        errors = self._errors(_doc(addresses={"start": 0, "end": 1}))
        assert len(errors) == 1
        assert "include.addresses" in errors[0]

    def test_non_string_pattern_names_its_index(self) -> None:
        """TC-308 / LLR-053.1: non-string pattern → diagnostic naming index."""
        errors = self._errors(_doc(symbols=["CAL_*", 3]))
        assert len(errors) == 1
        assert "include.symbols[1]" in errors[0]

    def test_non_parsable_address_names_its_key(self) -> None:
        """TC-308 / LLR-053.1: non-'0x' string address → diagnostic naming key."""
        errors = self._errors(_doc(addresses=[{"start": "10", "end": 32}]))
        assert len(errors) == 1
        assert "include.addresses[0].start" in errors[0]

    def test_missing_address_key_names_its_key(self) -> None:
        """TC-308 / LLR-053.1: missing 'end' → diagnostic naming the key."""
        errors = self._errors(_doc(addresses=[{"start": 0}]))
        assert len(errors) == 1
        assert "include.addresses[0].end" in errors[0]

    def test_negative_start_rejected(self) -> None:
        """TC-308 / LLR-053.1 (Q-10): start < 0 is outside the pinned domain."""
        errors = self._errors(_doc(addresses=[{"start": -1, "end": 4}]))
        assert len(errors) == 1
        assert "include.addresses[0].start" in errors[0]

    def test_end_over_address_space_rejected(self) -> None:
        """TC-308 / LLR-053.1 (Q-10): end > 2^32 is outside the pinned domain."""
        errors = self._errors(_doc(addresses=[{"start": 0, "end": 0x1_0000_0001}]))
        assert len(errors) == 1
        assert "include.addresses[0].end" in errors[0]

    def test_start_equal_to_end_rejected(self) -> None:
        """TC-308 / LLR-053.1: start >= end rejected (end is exclusive)."""
        errors = self._errors(_doc(addresses=[{"start": 8, "end": 8}]))
        assert len(errors) == 1
        assert "include.addresses[0]" in errors[0]

    def test_start_greater_than_end_rejected(self) -> None:
        """TC-308 / LLR-053.1: inverted range rejected."""
        errors = self._errors(_doc(addresses=[{"start": 9, "end": 8}]))
        assert len(errors) == 1
        assert "include.addresses[0]" in errors[0]

    def test_n_fault_file_yields_at_least_n_diagnostics(self) -> None:
        """TC-308 / LLR-053.1: N distinct faults → >= N diagnostics, each named."""
        text = json.dumps(
            {
                "format": "wrong",  # fault 1
                "version": "9.9",  # fault 2
                "surplus": True,  # fault 3
                "include": {
                    "names": [],  # fault 4
                    "symbols": ["ok", 7],  # fault 5 (index 1)
                    "addresses": [
                        {"start": -1, "end": 4},  # fault 6
                        {"start": "zz", "end": 4},  # fault 7
                    ],
                },
            }
        )
        flt, errors = parse_report_filter(text)
        assert flt is None
        assert len(errors) >= 7
        joined = "\n".join(errors)
        for token in (
            "'format'",
            "'version'",
            "'surplus'",
            "'names'",
            "include.symbols[1]",
            "include.addresses[0].start",
            "include.addresses[1].start",
        ):
            assert token in joined, f"missing diagnostic for {token}"

    def test_unbalanced_bracket_pattern_is_accepted(self) -> None:
        """TC-308 / LLR-053.1 (Q-10): 'CAL_[' is VALID — never a parse rejection."""
        flt = _parse_ok(_doc(symbols=["CAL_["]))
        assert flt.symbols == ("CAL_[",)


# ---------------------------------------------------------------------------
# TC-309 — read-path hostile corpus + ceilings boundary (LLR-053.2 / .3)
# ---------------------------------------------------------------------------


class TestTc309ReadPathAndCeilings:
    """TC-309 — LLR-053.2 read faults never raise; LLR-053.3 ceilings exact."""

    def test_over_cap_file_rejected_before_read(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2: size probed BEFORE read; over 4 MiB → refusal.

        crc_config size-probe idiom: the probe reports an over-cap size so
        no real 4 MiB file is written.
        """
        path = tmp_path / "filter.json"
        path.write_text(_doc(), encoding="utf-8")
        oversized_probe = lambda _candidate: REPORT_FILTER_SIZE_CAP_BYTES + 1  # noqa: E731

        text, errors = read_report_filter_text(str(path), size_probe=oversized_probe)

        assert text is None
        assert len(errors) == 1
        assert "was not read" in errors[0]

    def test_file_exactly_at_cap_is_read(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2 boundary: size == cap is NOT over the cap."""
        path = tmp_path / "filter.json"
        path.write_text(_doc(), encoding="utf-8")
        at_cap_probe = lambda _candidate: REPORT_FILTER_SIZE_CAP_BYTES  # noqa: E731

        text, errors = read_report_filter_text(str(path), size_probe=at_cap_probe)

        assert errors == []
        assert text is not None

    def test_unresolvable_path_is_one_error(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2: unresolvable path → (None, [1 error]), no raise."""
        text, errors = read_report_filter_text(
            str(tmp_path / "missing.json"), base_dir=tmp_path
        )
        assert text is None
        assert len(errors) == 1

    def test_directory_path_refused_as_non_regular_file(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2 (S-F2): a directory is not a regular file."""
        text, errors = read_report_filter_text(str(tmp_path))
        assert text is None
        assert len(errors) == 1
        assert "not a regular file" in errors[0]

    def test_symlink_refused_at_read_time(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2 (S-F2): a symlinked filter file is refused."""
        real = tmp_path / "real_filter.json"
        real.write_text(_doc(), encoding="utf-8")
        link = tmp_path / "linked_filter.json"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError) as exc:
            # Windows requires Developer Mode or admin for symlinks; skip cleanly.
            pytest.skip(f"symlink creation unsupported here: {exc}")

        text, errors = read_report_filter_text(str(link))

        assert text is None
        assert len(errors) == 1
        assert "symlink" in errors[0]

    def test_non_utf8_bytes_is_one_error_no_exception(self, tmp_path: Path) -> None:
        """TC-309 / LLR-053.2: non-UTF-8 bytes → (None, [errors]), no raise."""
        path = tmp_path / "filter.json"
        path.write_bytes(b"\xff\xfe\x00\x01 not utf-8")

        text, errors = read_report_filter_text(str(path))

        assert text is None
        assert len(errors) == 1
        assert "UTF-8" in errors[0]

    def test_malformed_json_is_errors_no_exception(self) -> None:
        """TC-309 / LLR-053.2: malformed JSON → (None, [errors]), no raise."""
        flt, errors = parse_report_filter("{not json")
        assert flt is None
        assert len(errors) == 1

    def test_empty_file_text_is_errors_no_exception(self) -> None:
        """TC-309 / LLR-053.2: empty file text → (None, [errors]), no raise."""
        flt, errors = parse_report_filter("")
        assert flt is None
        assert len(errors) == 1

    def test_non_object_top_level_is_errors_no_exception(self) -> None:
        """TC-309 / LLR-053.2: a JSON array top level → (None, [errors])."""
        flt, errors = parse_report_filter("[1, 2]")
        assert flt is None
        assert len(errors) == 1

    def test_symbols_ceiling_boundary_exact(self) -> None:
        """TC-309 / LLR-053.3 (D-8): 4096 patterns OK; 4097 → 1 named ceiling."""
        ok = _parse_ok(_doc(symbols=["s"] * SYMBOL_PATTERN_CEILING))
        assert len(ok.symbols) == SYMBOL_PATTERN_CEILING

        flt, errors = parse_report_filter(
            _doc(symbols=["s"] * (SYMBOL_PATTERN_CEILING + 1))
        )
        assert flt is None
        assert len(errors) == 1
        assert str(SYMBOL_PATTERN_CEILING) in errors[0]
        assert "include.symbols" in errors[0]

    def test_addresses_ceiling_boundary_exact(self) -> None:
        """TC-309 / LLR-053.3 (D-8): 4096 ranges OK; 4097 → 1 named ceiling."""
        ranges_ok = [
            {"start": i * 2, "end": i * 2 + 1} for i in range(ADDRESS_RANGE_CEILING)
        ]
        ok = _parse_ok(_doc(addresses=ranges_ok))
        assert len(ok.addresses) == ADDRESS_RANGE_CEILING

        ranges_over = ranges_ok + [{"start": 0x900000, "end": 0x900001}]
        flt, errors = parse_report_filter(_doc(addresses=ranges_over))
        assert flt is None
        assert len(errors) == 1
        assert str(ADDRESS_RANGE_CEILING) in errors[0]
        assert "include.addresses" in errors[0]


# ---------------------------------------------------------------------------
# TC-310 — match semantics through the resolved matcher (LLR-053.4 / .7)
# ---------------------------------------------------------------------------


def _matcher(symbols, addresses, a2l_records=(), mac_records=()):
    """Build a resolved matcher through the public parse + resolve API."""
    flt = _parse_ok(_doc(symbols=symbols, addresses=addresses))
    return resolve_report_filter(flt, list(a2l_records), list(mac_records))


class TestTc310TruthTable:
    """TC-310 — LLR-053.4 (a)/(b)/(c) truth table via the LLR-053.7 matcher.

    Matched address set: explicit [0x100, 0x110) ∪ TAG_A extent
    [0x200, 0x204) (name-matched 4-byte A2L record).
    """

    def _table_matcher(self):
        return _matcher(
            symbols=["CAL_*", "TAG_A"],
            addresses=[{"start": "0x100", "end": "0x110"}],
            a2l_records=[{"name": "TAG_A", "address": 0x200, "byte_size": 4}],
        )

    @pytest.mark.parametrize(
        ("symbol", "start", "end", "expected", "combo"),
        [
            ("CAL_X", 0x100, 0x210, True, "a=T b=T c=T"),
            ("CAL_X", 0x100, 0x108, True, "a=T b=T c=F"),
            ("CAL_X", 0x200, 0x204, True, "a=T b=F c=T"),
            ("CAL_X", 0x300, 0x304, True, "a=T b=F c=F"),
            ("other", 0x10F, 0x201, True, "a=F b=T c=T"),
            (None, 0x10F, 0x110, True, "a=F b=T c=F (symbol None, range-only)"),
            ("other", 0x203, 0x204, True, "a=F b=F c=T (extent tail byte)"),
            ("other", 0x110, 0x200, False, "a=F b=F c=F (abuts both, exclusive)"),
        ],
    )
    def test_truth_table(self, symbol, start, end, expected, combo) -> None:
        """TC-310 / LLR-053.4: 8-combination (a)/(b)/(c) truth table."""
        matcher = self._table_matcher()
        assert matcher.matches_item(symbol, start, end) is expected, combo

    def test_fnmatchcase_is_case_sensitive(self) -> None:
        """TC-310 / LLR-053.4: pattern 'CAL_*' must NOT match 'cal_x'."""
        matcher = _matcher(symbols=["CAL_*"], addresses=[])
        assert matcher.matches_symbol("CAL_x") is True
        assert matcher.matches_symbol("cal_x") is False


class TestTc310ExtentPins:
    """TC-310 — LLR-053.4 F-1 extent semantics + Q-9 discriminators."""

    def test_tail_byte_of_four_byte_a2l_record_matches(self) -> None:
        """TC-310 / LLR-053.4 (F-1): tail byte of a matched 4-byte extent hits."""
        matcher = _matcher(
            symbols=["PARAM4"],
            addresses=[],
            a2l_records=[{"name": "PARAM4", "address": 0x400, "byte_size": 4}],
        )
        assert matcher.matches_range(0x403, 0x404) is True

    def test_entry_starting_exactly_at_extent_end_does_not_match(self) -> None:
        """TC-310 / LLR-053.4 (Q-9): end-exclusive negative twin — addr+byte_size misses."""
        matcher = _matcher(
            symbols=["PARAM4"],
            addresses=[],
            a2l_records=[{"name": "PARAM4", "address": 0x400, "byte_size": 4}],
        )
        assert matcher.matches_range(0x404, 0x405) is False

    @pytest.mark.parametrize(
        ("byte_size", "label"),
        [(None, "None"), (0, "zero"), (-3, "negative"), ("4", "non-int")],
    )
    def test_non_positive_or_missing_byte_size_falls_back_to_extent_one(
        self, byte_size, label
    ) -> None:
        """TC-310 / LLR-053.4 (Q-9): byte_size not a positive int → extent 1."""
        record = {"name": "P", "address": 0x500}
        if byte_size is not None:
            record["byte_size"] = byte_size
        matcher = _matcher(symbols=["P"], addresses=[], a2l_records=[record])
        assert matcher.matches_range(0x500, 0x501) is True, label
        assert matcher.matches_range(0x501, 0x502) is False, label

    def test_mac_point_vs_a2l_extent_divergence(self) -> None:
        """TC-310 / LLR-053.4 (Q-9): same name/address in both artifacts —
        only the A2L byte_size extent reaches the tail byte; the MAC record
        stays a point (no byte_size key)."""
        a2l = [{"name": "SHARED", "address": 0x600, "byte_size": 4}]
        mac = [{"name": "SHARED", "address": 0x600}]

        a2l_only = _matcher(symbols=["SHARED"], addresses=[], a2l_records=a2l)
        mac_only = _matcher(symbols=["SHARED"], addresses=[], mac_records=mac)
        both = _matcher(
            symbols=["SHARED"], addresses=[], a2l_records=a2l, mac_records=mac
        )

        assert a2l_only.matches_range(0x603, 0x604) is True
        assert mac_only.matches_range(0x603, 0x604) is False
        assert mac_only.matches_range(0x600, 0x601) is True
        assert both.matches_range(0x603, 0x604) is True


class TestTc310MetacharacterPins:
    """TC-310 — LLR-053.4 F-2 equality short-circuit + Q-10 bracket pins."""

    def test_literal_metacharacter_symbol_matches_itself_via_equality(self) -> None:
        """TC-310 / LLR-053.4 (F-2): symbol 'PAR[0]' + pattern 'PAR[0]' matches."""
        matcher = _matcher(symbols=["PAR[0]"], addresses=[])
        assert matcher.matches_symbol("PAR[0]") is True

    def test_metacharacter_pattern_keeps_glob_meaning(self) -> None:
        """TC-310 / LLR-053.4 (F-2 informative): 'PAR[0]' also matches 'PAR0'."""
        matcher = _matcher(symbols=["PAR[0]"], addresses=[])
        assert matcher.matches_symbol("PAR0") is True
        assert matcher.matches_symbol("PAR1") is False

    def test_unbalanced_bracket_pattern_matches_only_its_literal(self) -> None:
        """TC-310 / LLR-053.4 (Q-10): 'CAL_[' matches literal 'CAL_[' and nothing else."""
        matcher = _matcher(symbols=["CAL_["], addresses=[])
        assert matcher.matches_symbol("CAL_[") is True
        assert matcher.matches_symbol("CAL_x") is False
        assert matcher.matches_symbol("CAL_") is False


class TestTc310NeverRaise:
    """TC-310 — LLR-053.7 (S-F4): resolution + classification never raise."""

    def test_resolution_survives_hostile_record_shapes(self) -> None:
        """TC-310 / LLR-053.7 (S-F4): non-dict records, non-int addresses,
        and non-list collections are skipped, never an exception."""
        flt = _parse_ok(_doc(symbols=["CAL_*"], addresses=[]))
        matcher = resolve_report_filter(
            flt,
            [
                None,
                42,
                "junk",
                {"address": "not-an-int", "name": "CAL_A"},
                {"address": True, "name": "CAL_B"},
                {"name": "CAL_C"},
                {"address": 0x700},
                {"address": 0x710, "name": 12345},
                {"address": 0x720, "name": "CAL_OK", "byte_size": "wide"},
            ],
            "not-a-list-at-all",
        )
        assert matcher.matches_range(0x720, 0x721) is True
        assert matcher.matches_range(0x700, 0x701) is False

    def test_classification_survives_hostile_arguments(self) -> None:
        """TC-310 / LLR-053.7 (S-F4): hostile matcher arguments → False, no raise."""
        matcher = _matcher(symbols=["CAL_*"], addresses=[{"start": 0, "end": 16}])
        assert matcher.matches_item(b"CAL_X", "0", None) is False
        assert matcher.matches_item(None, None, None) is False
        assert matcher.matches_item(12345, 3.5, object()) is False
        assert matcher.matches_range(True, 16) is False
        assert matcher.matches_range(8, 4) is False
        assert matcher.matches_range(8, 8) is False

    def test_resolution_with_none_collections(self) -> None:
        """TC-310 / LLR-053.7 (S-F4): None artifact collections resolve fine."""
        flt = _parse_ok(_doc(symbols=[], addresses=[{"start": 0, "end": 4}]))
        matcher = resolve_report_filter(flt, None, None)
        assert matcher.matches_range(0, 1) is True
        assert matcher.matches_range(4, 5) is False


# ---------------------------------------------------------------------------
# D-10a — missing-key pin (batch-35 Inc-1 gate ratification, rides Inc-2)
# ---------------------------------------------------------------------------


def test_d10a_missing_include_keys_parse_ok_and_match_only_present() -> None:
    """D-10a / LLR-053.1: a missing ``include`` key — or a missing
    ``symbols``/``addresses`` sub-key — is accepted as the empty list (same
    semantics as explicitly empty, D-10 loud zero-match): parse OK with zero
    diagnostics; matching happens ONLY via the present list.
    """
    a2l = [{"name": "CAL_X", "address": 0x10, "byte_size": 4}]

    # format + version only: valid, matches nothing.
    envelope_only = json.dumps(
        {
            "format": REPORT_FILTER_FORMAT_ID,
            "version": REPORT_FILTER_FORMAT_VERSION,
        }
    )
    flt, errors = parse_report_filter(envelope_only)
    assert errors == []
    assert flt is not None
    assert flt.symbols == () and flt.addresses == ()
    matcher = resolve_report_filter(flt, a2l, [])
    assert matcher.matches_item("CAL_X", 0x10, 0x14) is False

    # include.symbols only: valid, matches via symbols (and their extents),
    # never via the absent addresses list.
    symbols_only = json.dumps(
        {
            "format": REPORT_FILTER_FORMAT_ID,
            "version": REPORT_FILTER_FORMAT_VERSION,
            "include": {"symbols": ["CAL_*"]},
        }
    )
    flt2, errors2 = parse_report_filter(symbols_only)
    assert errors2 == []
    assert flt2 is not None
    assert flt2.addresses == ()
    matcher2 = resolve_report_filter(flt2, a2l, [])
    assert matcher2.matches_symbol("CAL_X") is True
    assert matcher2.matches_range(0x10, 0x14) is True  # CAL_X extent
    assert matcher2.matches_range(0x100, 0x104) is False  # no explicit ranges
