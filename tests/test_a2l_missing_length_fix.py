"""A2L missing-length is spec-valid, not a schema ERROR (a2l-missing-length-fix).

Batch: a2l-missing-length-fix. Under ASAM MCD-2 MC a MEASUREMENT/CHARACTERISTIC
size is *derived* (Datatype / RECORD_LAYOUT), so a record with a valid address
whose length could not be derived is spec-valid — it must render white/grey
("valid, not memory-checked"), never red. Before the fix,
``_tag_schema_and_applicability`` conflated missing-length with missing-address
and returned ``schema_ok=False`` -> ERROR (red) for both.

These tests pin the fixed contract at two layers:
- the parse/enrich verdict (``validate_a2l_tags`` / ``_tag_schema_and_applicability``)
- the row-severity mapping that drives the A2L table colour (``_a2l_tag_row_severity``)

The missing-*address* arm is asserted unchanged so the fix is a strict split, not
a relaxation of address checking.
"""

from s19_app.tui.a2l import validate_a2l_tags
from s19_app.tui.app import _a2l_tag_row_severity
from s19_app.validation.model import ValidationSeverity


# ---------------------------------------------------------------------------
# AC-1 — valid address + underivable length is schema_ok, not memory-checkable.
# ---------------------------------------------------------------------------


def test_ac1_valid_address_missing_length_is_schema_ok() -> None:
    tags = [{"section": "CHARACTERISTIC", "name": "NOLEN", "address": 0x1008, "length": None}]

    results = validate_a2l_tags(tags, {0x1008: 0x01})

    result = results[0]
    assert result["schema_ok"] is True, "underivable length must NOT fail schema"
    assert result["valid"] is True
    assert result["memory_checked"] is False, "no length -> range check does not apply"
    assert result["in_memory"] is None
    assert result["reason"] == "", "a spec-valid record carries no failure reason"


# ---------------------------------------------------------------------------
# AC-2 — that tag maps to NEUTRAL (grey), never ERROR (red).
# ---------------------------------------------------------------------------


def test_ac2_missing_length_row_severity_is_not_error() -> None:
    tag = {
        "name": "NOLEN",
        "schema_ok": True,
        "memory_checked": False,
        "in_memory": None,
        "virtual": False,
    }

    severity = _a2l_tag_row_severity(tag, {})

    assert severity is not ValidationSeverity.ERROR, "missing length must not paint the row red"
    assert severity is ValidationSeverity.NEUTRAL


# ---------------------------------------------------------------------------
# AC-3 — missing ADDRESS is unchanged: still a schema failure, still red.
# ---------------------------------------------------------------------------


def test_ac3_missing_address_still_schema_fail() -> None:
    tags = [{"section": "CHARACTERISTIC", "name": "NOADDR", "address": None, "length": 4}]

    result = validate_a2l_tags(tags, {0x1008: 0x01})[0]

    assert result["schema_ok"] is False, "missing address must remain a schema concern"
    assert result["valid"] is False
    assert result["reason"] == "missing address/length"

    severity = _a2l_tag_row_severity(
        {"name": "NOADDR", "schema_ok": False, "memory_checked": False}, {}
    )
    assert severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# AC-4 — a virtual tag with no address/length is unchanged (still schema_ok).
# ---------------------------------------------------------------------------


def test_ac4_virtual_without_address_still_schema_ok() -> None:
    tags = [
        {
            "section": "CHARACTERISTIC",
            "name": "VIRT",
            "virtual": True,
            "address": None,
            "length": None,
        }
    ]

    result = validate_a2l_tags(tags, {0x1008: 0x01})[0]

    assert result["schema_ok"] is True
    assert result["memory_checked"] is False
    assert result["in_memory"] is None


# ---------------------------------------------------------------------------
# Guard corroboration — both present still memory-checks (no accidental
# short-circuit of the applicable path).
# ---------------------------------------------------------------------------


def test_both_present_still_memory_checks() -> None:
    tags = [{"section": "MEASUREMENT", "name": "OK", "address": 0x1000, "length": 2}]

    result = validate_a2l_tags(tags, {0x1000: 0x01, 0x1001: 0x02})[0]

    assert result["schema_ok"] is True
    assert result["memory_checked"] is True
    assert result["in_memory"] is True
