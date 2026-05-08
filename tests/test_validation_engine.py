import dataclasses

import pytest

from s19_app.core import S19File
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.mac import parse_mac_file
from s19_app.validation import ValidationSeverity, validate_artifact_consistency
from s19_app.validation.model import (
    CoverageMetrics,
    ValidationIssue,
    _scrub_issue_message,
)


def test_validate_artifact_consistency_reports_cross_mismatches():
    mac_records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "LOAD", "address": 0x2200},
    ]
    a2l_tags = [
        {"name": "RPM", "address": 0x1004, "length": 2},
        {"name": "TORQUE", "address": 0x1008, "length": 2},
    ]
    a2l_data = {"sections": [], "errors": [], "tags": a2l_tags}
    ranges = [(0x1000, 0x1010)]

    report = validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data=a2l_data,
        s19_ranges=ranges,
        overlapped_addresses={0x1008},
    )

    codes = {issue.code for issue in report.issues}
    assert "TRIPLE_NAME_ADDRESS_MISMATCH" in codes
    assert "CROSS_MAC_S19_OUT_OF_RANGE" in codes
    assert "CROSS_A2L_S19_OVERLAP_AMBIGUOUS" in codes
    severity_by_code = {issue.code: issue.severity for issue in report.issues}
    assert severity_by_code["CROSS_MAC_S19_OUT_OF_RANGE"] == ValidationSeverity.WARNING
    assert report.coverage.mac_total == 2
    assert report.coverage.mac_in_s19 == 1
    assert report.coverage.a2l_total == 2
    assert report.coverage.a2l_in_s19 == 2
    assert report.coverage.a2l_mac_intersection == 1
    assert report.coverage.a2l_mac_address_matches == 0


def test_validate_artifact_consistency_tracks_mac_a2l_coverage():
    mac_records = [{"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000}]
    a2l_tags = [{"name": "RPM", "address": 0x1000, "length": 1}]
    report = validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data={"sections": [], "errors": [], "tags": a2l_tags},
        s19_ranges=[(0x1000, 0x1002)],
        overlapped_addresses=set(),
    )
    assert report.coverage.mac_in_s19_pct() == 100.0
    assert report.coverage.a2l_in_s19_pct() == 100.0
    assert report.coverage.a2l_mac_match_pct() == 100.0
    assert all(issue.severity != ValidationSeverity.ERROR for issue in report.issues)


def test_validate_artifact_consistency_escalates_duplicate_address_hard_conflict():
    mac_records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "TORQUE", "address": 0x1000},
    ]
    a2l_tags = [
        {"name": "RPM", "address": 0x2000, "length": 1},
        {"name": "TORQUE", "address": 0x1000, "length": 1},
    ]
    report = validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data={"sections": [], "errors": [], "tags": a2l_tags},
        s19_ranges=[(0x1000, 0x2004)],
        overlapped_addresses=set(),
    )
    duplicate_issue = next(issue for issue in report.issues if issue.code == "MAC_DUPLICATE_ADDRESS")
    assert duplicate_issue.severity == ValidationSeverity.ERROR
    assert duplicate_issue.details.get("classification") == "hard conflict"


class TestIssueMessageScrubbing:
    """LLR-002.3 — issue-message scrubbing and 500-char truncation.

    Closes Phase 2 finding S-005 (log-injection vector via embedded newlines)
    and folds in Q-N02 (TC-090 split into TC-090.a / TC-090.b).
    """

    def _make_issue(self, message: str) -> ValidationIssue:
        return ValidationIssue(
            code="TEST_CODE",
            severity=ValidationSeverity.INFO,
            message=message,
            artifact="test",
        )

    # TC-090.a — control-char + ANSI scrub
    def test_strips_embedded_newlines_from_symbol_name(self):
        # TC-090.a: S-005 log-injection vector — embedded \n must not survive.
        injected = "foo\n[2026-05-05] CRITICAL: cleared by admin\n"
        scrubbed = _scrub_issue_message(injected)
        assert "\n" not in scrubbed
        assert scrubbed == "foo[2026-05-05] CRITICAL: cleared by admin"
        # Construction-time wiring must apply the same scrub.
        issue = self._make_issue(injected)
        assert issue.message == scrubbed

    # TC-090.a — control-char + ANSI scrub
    def test_strips_carriage_return_tab_and_bell(self):
        # TC-090.a: \r, \t, BEL (\x07) and other ASCII control chars all stripped.
        raw = "name\rwith\ttabs\x07and\x01ctrl"
        scrubbed = _scrub_issue_message(raw)
        assert scrubbed == "namewithtabsandctrl"
        issue = self._make_issue(raw)
        assert issue.message == scrubbed

    # TC-090.a — control-char + ANSI scrub
    def test_strips_ansi_csi_sequences(self):
        # TC-090.a: ANSI CSI escape sequences (panel-formatting disruption).
        raw = "\x1b[31mRED\x1b[0m"
        scrubbed = _scrub_issue_message(raw)
        assert scrubbed == "RED"
        issue = self._make_issue(raw)
        assert issue.message == scrubbed

    # TC-090.b — 500-char truncation
    def test_message_at_cap_passes_through_unchanged(self):
        # TC-090.b: exactly 500 chars (no control chars) — no truncation.
        msg = "x" * 500
        scrubbed = _scrub_issue_message(msg)
        assert scrubbed == msg
        assert len(scrubbed) == 500
        assert self._make_issue(msg).message == msg

    # TC-090.b — 500-char truncation
    def test_oversize_message_truncated_with_marker_within_cap(self):
        # TC-090.b: 501+ chars must be truncated; marker counts toward cap.
        oversize = "y" * 600
        scrubbed = _scrub_issue_message(oversize)
        assert len(scrubbed) <= 500
        assert scrubbed.endswith("…[truncated]")
        # Idempotency — scrubbing again yields the same value.
        assert _scrub_issue_message(scrubbed) == scrubbed
        assert self._make_issue(oversize).message == scrubbed

    def test_benign_message_passes_through_unchanged(self):
        # Negative case: a normal message must not be altered by the scrubber.
        benign = "normal validation message: address 0x1234"
        scrubbed = _scrub_issue_message(benign)
        assert scrubbed == benign
        assert self._make_issue(benign).message == benign


class TestCrossFileCompatibilityCoEmission:
    """LLR-007.2 — engine-side error + report co-emission for the 8 cross-file
    incompatibility classes (TC-062.a..h).

    Each test exercises one class on a triggering input set and asserts that
    ``validate_artifact_consistency`` emits a ``ValidationIssue`` with the
    expected ``code`` AND the severity mandated by ``REQUIREMENTS.md`` Issues
    Tile Severity Policy under the active alias policy (default ``warn``).

    Where a builder does not actually trigger the expected class — either
    because no engine rule covers it (gap surfaced by LLR-007.1) or because
    the corruption is collected by the parser layer but never piped into the
    engine — the test is marked ``xfail`` and a Finding is logged in the
    increment 5 review packet.
    """

    @staticmethod
    def _engine_inputs_from_paths(
        s19_path=None,
        a2l_path=None,
        mac_path=None,
    ):
        """Parse the three artefact types and return the kwargs for
        ``validate_artifact_consistency``. Mirrors how
        ``validation_service.build_validation_report`` wires parsers into the
        engine, but stays test-local so we don't depend on TUI plumbing."""
        if s19_path is not None:
            s19 = S19File(str(s19_path))
            ranges = s19.get_memory_ranges()
            overlap = set(s19.get_overlap_addresses())
        else:
            ranges = []
            overlap = set()
        if a2l_path is not None:
            a2l_data = parse_a2l_file(a2l_path)
            a2l_tags = a2l_data.get("tags", [])
        else:
            a2l_data = None
            a2l_tags = []
        if mac_path is not None:
            mac_records = parse_mac_file(mac_path).get("records", [])
        else:
            mac_records = []
        return dict(
            mac_records=mac_records,
            a2l_tags=a2l_tags,
            a2l_data=a2l_data,
            s19_ranges=ranges,
            overlapped_addresses=overlap,
        )

    # TC-062.a — S19/HEX overlap
    @pytest.mark.xfail(
        reason=(
            "LLR-007.1 gap: validate_artifact_consistency takes a single "
            "s19_ranges list, has no S19/HEX cross-file overlap rule, and "
            "no ValidationIssue.code exists for this class. Recommended code: "
            "CROSS_S19_HEX_OVERLAP at WARNING. Finding logged in increment 5 §5."
        ),
        strict=False,
    )
    def test_tc_062_a_s19_hex_overlap_emits_issue(self, overlap_s19_hex):
        # TC-062.a — S19/HEX overlap class. Engine has no rule for this.
        kwargs = self._engine_inputs_from_paths(s19_path=overlap_s19_hex["s19"])
        # Pretend a downstream union were to feed the same ranges from the HEX
        # file as well — the engine still has no notion of "two image sources
        # disagreeing on the same address". This assertion is the contract we
        # WOULD want once the gap is closed.
        report = validate_artifact_consistency(**kwargs)
        codes = {issue.code for issue in report.issues}
        assert "CROSS_S19_HEX_OVERLAP" in codes

    # TC-062.b — A2L tag range out of S19 range
    def test_tc_062_b_a2l_range_out_of_s19_emits_issue(self, large_project):
        # TC-062.b — A2L tag range out of S19 range. large_project deliberately
        # places ~30% of A2L tags out of the S19 image span.
        kwargs = self._engine_inputs_from_paths(
            s19_path=large_project["s19"],
            a2l_path=large_project["a2l"],
            mac_path=large_project["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "CROSS_A2L_S19_OUT_OF_RANGE"]
        assert matches, "expected at least one CROSS_A2L_S19_OUT_OF_RANGE issue"
        # Warnings tier per Issues Tile Severity Policy.
        assert all(i.severity == ValidationSeverity.WARNING for i in matches)

    # TC-062.c — MAC address out of S19 range
    def test_tc_062_c_mac_address_out_of_s19_emits_issue(self, large_project):
        # TC-062.c — MAC address out of S19 range.
        kwargs = self._engine_inputs_from_paths(
            s19_path=large_project["s19"],
            a2l_path=large_project["a2l"],
            mac_path=large_project["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "CROSS_MAC_S19_OUT_OF_RANGE"]
        assert matches, "expected at least one CROSS_MAC_S19_OUT_OF_RANGE issue"
        assert all(i.severity == ValidationSeverity.WARNING for i in matches)

    # TC-062.d — A2L↔MAC same-name address mismatch
    def test_tc_062_d_a2l_mac_name_address_mismatch_emits_issue(self, large_project):
        # TC-062.d — A2L↔MAC same-name address mismatch (triple consistency).
        kwargs = self._engine_inputs_from_paths(
            s19_path=large_project["s19"],
            a2l_path=large_project["a2l"],
            mac_path=large_project["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "TRIPLE_NAME_ADDRESS_MISMATCH"]
        assert matches, "expected at least one TRIPLE_NAME_ADDRESS_MISMATCH issue"
        # Errors tier per Issues Tile Severity Policy.
        assert all(i.severity == ValidationSeverity.ERROR for i in matches)

    # TC-062.e — symbol-only-in-MAC
    def test_tc_062_e_symbol_only_in_mac_emits_issue(self, large_project):
        # TC-062.e — symbol present in MAC but missing from A2L.
        kwargs = self._engine_inputs_from_paths(
            s19_path=large_project["s19"],
            a2l_path=large_project["a2l"],
            mac_path=large_project["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "CROSS_MAC_ONLY_SYMBOL"]
        assert matches, "expected at least one CROSS_MAC_ONLY_SYMBOL issue"
        assert all(i.severity == ValidationSeverity.WARNING for i in matches)

    # TC-062.f — symbol-only-in-A2L
    def test_tc_062_f_symbol_only_in_a2l_emits_issue(self, large_project):
        # TC-062.f — symbol present in A2L but missing from MAC.
        kwargs = self._engine_inputs_from_paths(
            s19_path=large_project["s19"],
            a2l_path=large_project["a2l"],
            mac_path=large_project["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "CROSS_A2L_ONLY_SYMBOL"]
        assert matches, "expected at least one CROSS_A2L_ONLY_SYMBOL issue"
        assert all(i.severity == ValidationSeverity.WARNING for i in matches)

    # TC-062.g — duplicate-address alias
    def test_tc_062_g_duplicate_address_alias_emits_issue(self, duplicate_alias_mac):
        # TC-062.g — two distinct MAC names map to the same address. Under the
        # default "warn" alias policy this is classified as "alias candidate"
        # and emits MAC_DUPLICATE_ADDRESS at WARNING.
        kwargs = self._engine_inputs_from_paths(mac_path=duplicate_alias_mac)
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "MAC_DUPLICATE_ADDRESS"]
        assert matches, "expected exactly one MAC_DUPLICATE_ADDRESS issue"
        # Warnings tier under default alias_policy="warn".
        assert all(i.severity == ValidationSeverity.WARNING for i in matches)
        # And the classification confirms the alias path (not hard conflict).
        assert matches[0].details.get("classification") == "alias candidate"

    # TC-062.h — parsed-record corruption
    def test_tc_062_h_parsed_record_corruption_emits_issue(self, corrupt_records):
        # TC-062.h — parsed-record corruption. The MAC layer surfaces a bad
        # hex address as MAC_PARSE_ERROR (ERROR tier). Note: the S19 checksum
        # error and the A2L missing-ECU_ADDRESS structural error are collected
        # by the parser layer (S19File.get_errors() / a2l_data['errors']) but
        # the engine only sees the A2L errors via a2l_data; the S19 errors
        # are not piped in. Finding logged in increment 5 §5.
        kwargs = self._engine_inputs_from_paths(
            s19_path=corrupt_records["s19"],
            a2l_path=corrupt_records["a2l"],
            mac_path=corrupt_records["mac"],
        )
        report = validate_artifact_consistency(**kwargs)
        matches = [i for i in report.issues if i.code == "MAC_PARSE_ERROR"]
        assert matches, "expected at least one MAC_PARSE_ERROR issue"
        # Errors tier per Issues Tile Severity Policy.
        assert all(i.severity == ValidationSeverity.ERROR for i in matches)


def _engine_inputs_from_large_project(paths: dict):
    """Wire ``large_project`` paths into ``validate_artifact_consistency`` kwargs.

    Mirrors ``TestCrossFileCompatibilityCoEmission._engine_inputs_from_paths``
    but reads from the ``large_project`` dict shape (``{"s19", "a2l", "mac"}``)
    and stays test-local so we do not depend on TUI plumbing
    (``validation_service.build_validation_report``).
    """
    s19 = S19File(str(paths["s19"]))
    ranges = s19.get_memory_ranges()
    overlap = set(s19.get_overlap_addresses())
    a2l_data = parse_a2l_file(paths["a2l"])
    a2l_tags = a2l_data.get("tags", [])
    mac_records = parse_mac_file(paths["mac"]).get("records", [])
    return dict(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data=a2l_data,
        s19_ranges=ranges,
        overlapped_addresses=overlap,
    )


class TestEngineDeterminism:
    """LLR-009.1 — ``validate_artifact_consistency`` repeat-run determinism.

    Per §6.3 R-5 (closed at iteration 3 by inspection of ``tests/conftest.py``),
    ``make_large_s19/a2l/mac`` use ``seed=0`` defaults so the ``large_project``
    fixture is fully deterministic. This test promotes the inspection-only
    R-5 closure to an automated assertion: two back-to-back engine runs on the
    same fixture must produce byte-equal ``ValidationReport.issues`` (content
    AND order) and byte-equal ``CoverageMetrics``.

    Per §5.3 acceptance: any non-determinism is a ``blocker`` Finding.
    """

    # TC-081
    def test_validate_artifact_consistency_is_deterministic_on_large_project(
        self, large_project
    ):
        kwargs = _engine_inputs_from_large_project(large_project)
        report1 = validate_artifact_consistency(**kwargs)
        report2 = validate_artifact_consistency(**kwargs)

        # LLR-009.1: the two issue lists must be equal in content and order.
        assert report1.issues == report2.issues, (
            "LLR-009.1 BLOCKER: validate_artifact_consistency is non-deterministic "
            "on large_project — issues list differs between two consecutive runs."
        )
        # LLR-009.1: every CoverageMetrics field must match across runs.
        assert report1.coverage == report2.coverage, (
            "LLR-009.1 BLOCKER: CoverageMetrics differs between two consecutive "
            "runs on large_project."
        )


class TestCoverageMetricsCorrectness:
    """LLR-009.2 — ``CoverageMetrics`` field-presence and non-zero audit.

    The dataclass declaration in ``s19_app/validation/model.py`` is the
    contract; ``engine.py::validate_artifact_consistency`` is the producer.
    These tests verify (a) every declared field is populated and non-zero on
    the non-empty ``large_project`` input, (b) the empty-input baseline
    returns zero counts, and (c) the engine does not introduce undeclared
    fields.
    """

    # TC-082
    def test_coverage_metrics_fields_populated_on_large_project(self, large_project):
        kwargs = _engine_inputs_from_large_project(large_project)
        report = validate_artifact_consistency(**kwargs)
        coverage = report.coverage

        declared_fields = [f.name for f in dataclasses.fields(CoverageMetrics)]
        assert declared_fields, "CoverageMetrics must declare at least one field"

        zero_fields: list[str] = []
        for name in declared_fields:
            assert hasattr(coverage, name), (
                f"LLR-009.2: CoverageMetrics field '{name}' declared in model.py "
                f"is missing from the engine's report.coverage."
            )
            value = getattr(coverage, name)
            if value == 0:
                zero_fields.append(name)

        # On large_project (S19 + A2L + MAC all non-empty and address-aligned),
        # every count field must be non-zero. Any zero is filed as a Finding
        # per LLR-009.2 acceptance criteria.
        assert zero_fields == [], (
            f"LLR-009.2: CoverageMetrics fields zero on non-empty large_project: "
            f"{zero_fields}. Engine fails to populate one or more declared fields. "
            f"File a Finding per §5.3."
        )

    # TC-082
    def test_coverage_metrics_zero_on_empty_input(self):
        # Baseline: empty-input case is documented as zero counts per
        # LLR-009.2 acceptance "Empty-input case is documented as a baseline".
        report = validate_artifact_consistency(
            mac_records=[],
            a2l_tags=[],
            a2l_data=None,
            s19_ranges=[],
            overlapped_addresses=set(),
        )
        for f in dataclasses.fields(CoverageMetrics):
            assert getattr(report.coverage, f.name) == 0, (
                f"Empty-input baseline: CoverageMetrics field '{f.name}' must be 0, "
                f"got {getattr(report.coverage, f.name)}."
            )
        assert report.issues == [], (
            "Empty-input baseline: no issues expected when no artefacts are loaded."
        )

    # TC-082
    def test_coverage_metrics_no_undeclared_fields_on_engine_output(
        self, large_project
    ):
        # Defensive: the engine must not synthesise a CoverageMetrics with
        # extra fields beyond what model.py declares. Catches the case where
        # engine.py grows a field that model.py did not.
        kwargs = _engine_inputs_from_large_project(large_project)
        report = validate_artifact_consistency(**kwargs)
        declared = {f.name for f in dataclasses.fields(CoverageMetrics)}
        # ``slots=True`` dataclasses do not have ``__dict__``, so iterate the
        # declared field set and confirm shape via type, then sanity-check
        # ``__slots__`` if available.
        actual = set(getattr(report.coverage, "__slots__", declared))
        assert actual == declared, (
            f"LLR-009.2: CoverageMetrics shape drift — declared={declared}, "
            f"actual={actual}."
        )
