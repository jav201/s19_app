from s19_app.validation import ValidationSeverity, validate_mac_records


def test_validate_mac_records_detects_duplicate_address_alias_candidate():
    records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "LOAD", "address": 0x1004},
        {"parse_ok": True, "line_number": 3, "name": "TORQUE", "address": 0x1004},
    ]
    issues = validate_mac_records(records, alias_policy="warn")
    codes = {issue.code for issue in issues}
    assert "MAC_DUPLICATE_ADDRESS" in codes
    duplicate_issue = next(issue for issue in issues if issue.code == "MAC_DUPLICATE_ADDRESS")
    assert duplicate_issue.severity == ValidationSeverity.WARNING
    assert duplicate_issue.details.get("classification") == "alias candidate"


def test_validate_mac_records_duplicate_name_remains_hard_error():
    records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "RPM", "address": 0x1004},
    ]
    issues = validate_mac_records(records, alias_policy="warn")
    duplicate_name_issue = next(issue for issue in issues if issue.code == "MAC_DUPLICATE_NAME")
    assert duplicate_name_issue.severity == ValidationSeverity.ERROR


def test_validate_mac_records_reports_parse_and_empty_fields():
    records = [
        {"parse_ok": False, "line_number": 1, "parse_error": "invalid hex address"},
        {"parse_ok": True, "line_number": 2, "name": "", "address": 0x1000},
        {"parse_ok": True, "line_number": 3, "name": "LOAD", "address": None},
    ]
    issues = validate_mac_records(records)
    codes = {issue.code for issue in issues}
    assert "MAC_PARSE_ERROR" in codes
    assert "MAC_EMPTY_NAME" in codes
    assert "MAC_INVALID_ADDRESS" in codes


def test_validate_mac_records_duplicate_address_hard_conflict_from_a2l():
    records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "TORQUE", "address": 0x1000},
    ]
    a2l_tags = [
        {"name": "RPM", "address": 0x2000, "length": 1},
        {"name": "TORQUE", "address": 0x1000, "length": 1},
    ]
    issues = validate_mac_records(records, alias_policy="warn", a2l_tags=a2l_tags)
    duplicate_issue = next(issue for issue in issues if issue.code == "MAC_DUPLICATE_ADDRESS")
    assert duplicate_issue.severity == ValidationSeverity.ERROR
    assert duplicate_issue.details.get("classification") == "hard conflict"


def test_validate_mac_records_duplicate_address_info_when_allow_policy():
    records = [
        {"parse_ok": True, "line_number": 10, "name": "", "address": 0x2222},
        {"parse_ok": True, "line_number": 11, "name": "", "address": 0x2222},
    ]
    issues = validate_mac_records(records, alias_policy="allow")
    duplicate_issue = next(issue for issue in issues if issue.code == "MAC_DUPLICATE_ADDRESS")
    assert duplicate_issue.severity == ValidationSeverity.INFO
    assert duplicate_issue.details.get("classification") == "valid unresolved"
