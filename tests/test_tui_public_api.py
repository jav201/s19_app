from pathlib import Path

import pytest

from s19_app import tui
from s19_app.tui.a2l import (
    get_physical_value,
    get_raw_value,
    parse_a2l_file,
    validate_a2l_tags,
    validate_characteristic,
)


def test_tui_public_api_exports_main_helpers_and_constants():
    expected = {
        "A2L_EXTENSIONS",
        "FOCUS_CONTEXT_ROWS",
        "HEX_WIDTH",
        "LOG_FILENAME",
        "LOGS_SUBDIR",
        "MAX_HEX_BYTES",
        "MAX_HEX_ROWS",
        "S19TuiApp",
        "WORKAREA_TEMP",
        "copy_into_workarea",
        "main",
        "parse_a2l_file",
        "render_hex_view",
        "resolve_input_path",
        "setup_logging",
    }

    assert expected.issubset(set(tui.__all__))
    assert callable(tui.main)
    assert callable(tui.render_hex_view)
    assert callable(tui.setup_logging)


# ---------------------------------------------------------------------------
# Phase 3 increment 7 -- LLR-006.1 accessor-contract confirmation (TC-051/052)
# ---------------------------------------------------------------------------
#
# REQUIREMENTS.md §Output API documents three public accessors:
#     get_raw_value(name) / get_physical_value(name) / validate_characteristic(name)
# plus the field set
#     {raw_value, decode_error, physical_value, conversion_status, conversion_error,
#      schema_ok, memory_checked, in_memory}.
#
# Audit verdict (TC-051): the three accessors are present in s19_app/tui/a2l.py
# at module level. Their actual signature takes (name, a2l_data, mem_map), not
# the documented bare (name, ). The schema_ok/memory_checked/in_memory triplet
# is exposed by ``validate_a2l_tags`` (the bulk-tag validator), not by the
# per-tag ``validate_characteristic`` accessor. We lock the de-facto shapes
# here and file the doc/code drift as Finding F-7.7-06.


def _build_a2l_with_tag(tmp_path: Path) -> tuple[dict, dict]:
    """Build a small parsed-A2L payload with one decodable UBYTE tag at 0x4000."""
    a2l_path = tmp_path / "accessor.a2l"
    a2l_path.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        "/begin MEASUREMENT MEAS_OK\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "ECU_ADDRESS 0x4000\n"
        "/end MEASUREMENT\n"
        "/begin MEASUREMENT MEAS_MISSING\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "ECU_ADDRESS 0x9000\n"
        "/end MEASUREMENT\n"
        "/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    data = parse_a2l_file(a2l_path)
    mem_map = {0x4000: 0x42}
    return data, mem_map


def test_tc_051_get_raw_value_returns_documented_fields(tmp_path: Path):
    # TC-051 -- get_raw_value(name) payload shape per REQUIREMENTS.md §Output API.
    data, mem_map = _build_a2l_with_tag(tmp_path)

    raw = get_raw_value("MEAS_OK", data, mem_map)
    # Fields locked by the LLR-006.1 contract.
    for field in ("name", "ok", "raw_value", "decode_error", "errors"):
        assert field in raw, f"get_raw_value missing field {field!r}"
    assert raw["name"] == "MEAS_OK"
    assert raw["raw_value"] == 0x42
    # decode_error is the empty string on success (not None) per the
    # _decode_raw_value implementation; lock that contract here.
    assert raw["decode_error"] == ""


def test_tc_051_get_physical_value_returns_documented_fields(tmp_path: Path):
    # TC-051 -- get_physical_value(name) payload shape per REQUIREMENTS.md.
    data, mem_map = _build_a2l_with_tag(tmp_path)

    phys = get_physical_value("MEAS_OK", data, mem_map)
    for field in (
        "name",
        "ok",
        "physical_value",
        "conversion_status",
        "conversion_error",
        "errors",
    ):
        assert field in phys, f"get_physical_value missing field {field!r}"
    # NO_COMPU_METHOD -> identity_fallback per _apply_compu_method; lock that.
    assert phys["conversion_status"] in {"identity_fallback", "ok", "array"}
    assert isinstance(phys["conversion_error"], str)


def test_tc_051_validate_characteristic_returns_documented_fields(tmp_path: Path):
    # TC-051 -- validate_characteristic(name) payload shape. The actual return
    # is {ok, name, errors, tag} where ``tag`` carries the decode/conversion
    # fields. The schema_ok / memory_checked / in_memory triplet is on the
    # bulk validate_a2l_tags() output, not on validate_characteristic, which
    # is documented as an accessor in REQUIREMENTS.md but does not currently
    # surface those three fields. Finding F-7.7-06 captures that drift.
    data, mem_map = _build_a2l_with_tag(tmp_path)

    result = validate_characteristic("MEAS_OK", data, mem_map)
    for field in ("ok", "name", "errors", "tag"):
        assert field in result, f"validate_characteristic missing field {field!r}"
    # Decode/conversion fields appear nested under ``tag``.
    nested = result["tag"]
    for field in (
        "raw_value",
        "decode_error",
        "physical_value",
        "conversion_status",
        "conversion_error",
    ):
        assert field in nested, f"enriched tag missing field {field!r}"

    # The schema_ok/memory_checked/in_memory triplet is on validate_a2l_tags.
    bulk = validate_a2l_tags(data["tags"], mem_map)
    sample = next(t for t in bulk if t.get("name") == "MEAS_OK")
    for field in ("schema_ok", "memory_checked", "in_memory"):
        assert field in sample, f"validate_a2l_tags missing field {field!r}"


def test_tc_052_unknown_name_returns_error_payload(tmp_path: Path):
    # TC-052 -- error semantics: an unknown tag name produces a non-ok result
    # with a populated ``errors`` list; do not raise.
    data, mem_map = _build_a2l_with_tag(tmp_path)

    result = validate_characteristic("NOT_A_TAG", data, mem_map)
    assert result["ok"] is False
    assert result.get("name") == "NOT_A_TAG"
    assert result.get("errors")  # at least one error message

    raw = get_raw_value("NOT_A_TAG", data, mem_map)
    assert raw["ok"] is False
    assert raw["raw_value"] is None

    phys = get_physical_value("NOT_A_TAG", data, mem_map)
    assert phys["ok"] is False
    assert phys["physical_value"] is None


@pytest.mark.xfail(
    reason=(
        "Finding F-7.7-07: validate_characteristic() spreads ``**a2l_data`` AFTER "
        "the single-tag ``[tag]`` list, so the data['tags'] key overwrites the "
        "filtered list and enrich_a2l_tags_with_values()[0] returns the FIRST "
        "tag's enrichment instead of the requested one. The accessor's name "
        "filter is therefore effectively ignored when the requested tag is not "
        "the first in the parsed file. Recommended fix: build ``{**a2l_data, "
        "'tags': [tag]}`` so the override order is correct. Will land in a "
        "follow-up product increment."
    ),
    strict=False,
)
def test_tc_052_address_outside_memory_marks_failure(tmp_path: Path):
    # TC-052 -- decode failure path: a tag whose address is not in mem_map
    # surfaces via the ``errors`` collection; raw_value is None.
    data, mem_map = _build_a2l_with_tag(tmp_path)
    # MEAS_MISSING points at 0x9000 which is outside ``mem_map``. With the
    # bug above this returns MEAS_OK's enrichment (raw_value=0x42, ok=True),
    # so the assertions fail -- which is the xfail signal. Closing the
    # Finding will turn this xfail into pass without further test edits.
    raw = get_raw_value("MEAS_MISSING", data, mem_map)
    assert raw["ok"] is False
    assert raw["raw_value"] is None
    assert any("not in S19" in e or "address" in e.lower() for e in raw["errors"])


def test_tc_052_validate_a2l_tags_schema_triplet_round_trips(tmp_path: Path):
    # TC-052 -- the schema_ok/memory_checked/in_memory triplet is the field-set
    # downstream consumers rely on for row colouring; lock its types and
    # interaction with mem_map.
    tags_in_memory = [
        {"section": "MEASUREMENT", "name": "X", "address": 0x1000, "length": 1},
    ]
    tags_outside_memory = [
        {"section": "MEASUREMENT", "name": "Y", "address": 0x9000, "length": 1},
    ]
    mem_map = {0x1000: 0xAA}

    in_mem = validate_a2l_tags(tags_in_memory, mem_map)[0]
    assert in_mem["schema_ok"] is True
    assert in_mem["memory_checked"] is True
    assert in_mem["in_memory"] is True

    out_mem = validate_a2l_tags(tags_outside_memory, mem_map)[0]
    assert out_mem["schema_ok"] is True
    assert out_mem["memory_checked"] is True
    assert out_mem["in_memory"] is False

    # mem_map=None -> the memory check is skipped: memory_checked False, in_memory None.
    no_mem = validate_a2l_tags(tags_in_memory, None)[0]
    assert no_mem["memory_checked"] is False
    assert no_mem["in_memory"] is None
