from s19_app.validation import validate_a2l_structure


def test_validate_a2l_structure_detects_unrecognized_and_duplicate_symbols():
    a2l_data = {
        "errors": [],
        "sections": [
            {"name": "PROJECT", "start_line": 1, "lines": [], "children": []},
            {"name": "UNKNOWN_BLOCK", "start_line": 2, "lines": [], "children": []},
        ],
        "tags": [
            {"name": "RPM", "address": 0x1000},
            {"name": "RPM", "address": 0x1002},
        ],
    }
    issues = validate_a2l_structure(a2l_data)
    codes = {issue.code for issue in issues}
    assert "A2L_UNRECOGNIZED_BLOCK" in codes
    assert "A2L_DUPLICATE_SYMBOL" in codes


def test_validate_a2l_structure_detects_broken_references():
    a2l_data = {
        "errors": [],
        "sections": [
            {
                "name": "GROUP",
                "start_line": 10,
                "lines": ["REF_MEASUREMENT RPM MISSING_MEAS"],
                "children": [],
            }
        ],
        "tags": [{"name": "RPM", "address": 0x1000}],
    }
    issues = validate_a2l_structure(a2l_data)
    assert any(issue.code == "A2L_BROKEN_REFERENCE" for issue in issues)
