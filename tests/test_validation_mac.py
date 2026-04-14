from s19_app.validation import validate_mac_records


def test_validate_mac_records_detects_duplicate_name_and_alias():
    records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "RPM", "address": 0x1004},
        {"parse_ok": True, "line_number": 3, "name": "TORQUE", "address": 0x1004},
    ]
    issues = validate_mac_records(records, alias_policy="warn")
    codes = {issue.code for issue in issues}
    assert "MAC_DUPLICATE_NAME" in codes
    assert "MAC_DUPLICATE_ADDRESS" in codes


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
