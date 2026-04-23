from s19_app.validation import ValidationSeverity, validate_artifact_consistency


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
