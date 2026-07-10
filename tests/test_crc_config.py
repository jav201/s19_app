"""
Unit tests for the external CRC config reader (batch-12 CRC_F2, HLR-004 /
LLR-004.1, increment I2).

Covers TC-113 (params loaded from a synthetic JSON via ``resolve_input_path``),
TC-114 (config-never-in-repo: only the dummy example template is committed and
it parses), and the LLR-004.1 collect-don't-abort failure modes (unresolvable
path, malformed JSON, over-cap). All config values used here are SYNTHETIC —
no real firmware config is ever referenced.
"""

from __future__ import annotations

import json as _json
from pathlib import Path

from unittest import mock

import pytest

from s19_app.tui.operations.crc_config import (
    ALLOWED_OUTPUT_BYTES,
    CRC_SPAN_COUNT_CEILING,
    DUMMY_CONFIG_TEXT,
    CrcConfig,
    CrcGroup,
    CrcRegion,
    parse_crc_config,
    read_crc_config,
    read_crc_config_text,
)


def _repo_root() -> Path:
    """Walk up from this test file to the repo root (carries pyproject.toml)."""
    current = Path(__file__).resolve().parent
    for _ in range(6):
        if (current / "pyproject.toml").exists() or (current / "project.toml").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    raise AssertionError("repo root (pyproject.toml/project.toml) not found")


# ---------------------------------------------------------------------------
# TC-113 — params loaded from a synthetic JSON
# ---------------------------------------------------------------------------


def test_params_loaded_from_synthetic_json(tmp_path: Path) -> None:
    """TC-113: a synthetic config JSON parses into a fully-populated CrcConfig.

    Encodes WHY: LLR-004.1 requires every algorithm parameter and region
    geometry field to be sourced from the operator file and parsed from
    hex-string-or-int. If hex parsing or field wiring regresses, the typed
    config carries wrong/null values and this fails.
    """
    config_path = tmp_path / "synthetic_crc.json"
    config_path.write_text(
        """
        {
          "polynomial": "0x04C11DB7",
          "init": "0xFFFFFFFF",
          "reverse": true,
          "final_xor": "0xFFFFFFFF",
          "regions": [
            { "start": "0x00001000", "end": "0x00002000", "output_address": "0x00001FFC" },
            { "start": 8192, "end": 12288, "output_address": 12284 }
          ]
        }
        """,
        encoding="utf-8",
    )

    config, errors = read_crc_config(str(config_path))

    assert errors == []
    assert isinstance(config, CrcConfig)
    assert config.polynomial == 0x04C11DB7
    assert config.init == 0xFFFFFFFF
    assert config.reverse is True
    assert config.final_xor == 0xFFFFFFFF
    assert config.regions == [
        CrcRegion(start=0x1000, end=0x2000, output_address=0x1FFC),
        CrcRegion(start=8192, end=12288, output_address=12284),
    ]


# ---------------------------------------------------------------------------
# TC-114 — config never committed to the repo (only the dummy template)
# ---------------------------------------------------------------------------


def test_no_real_config_required() -> None:
    """TC-114: only crc_config.example.json exists under examples/, and it parses.

    Encodes WHY: real per-firmware CRC params must never live in version
    control (§1.2 out-of-scope, §6.3 RK-5). This fails the instant any real
    ``crc*.json`` config is committed under ``examples/``, and also proves the
    in-repo dummy template parses with the documented dummy hex values.
    """
    examples = _repo_root() / "examples"
    found = sorted(p.name for p in examples.glob("**/crc*.json"))
    assert found == ["crc_config.example.json"]

    template = examples / "crc_config.example.json"
    config, errors = read_crc_config(str(template))

    assert errors == []
    assert isinstance(config, CrcConfig)
    assert config.polynomial == 0x04C11DB7
    assert config.init == 0xFFFFFFFF
    assert config.reverse is True
    assert config.final_xor == 0xFFFFFFFF
    assert config.regions == [
        CrcRegion(start=0x00010000, end=0x00020000, output_address=0x0001FFFC),
        CrcRegion(start=0x00020000, end=0x00030000, output_address=0x0002FFFC),
    ]


# ---------------------------------------------------------------------------
# LLR-004.1 collect-don't-abort failure modes — each → (None, [1 error])
# ---------------------------------------------------------------------------


def test_unresolvable_path_collects_one_error(tmp_path: Path) -> None:
    """Unresolvable path → (None, [1 error]); no raise (collect-don't-abort).

    Encodes WHY: LLR-004.1 mandates a single collected error and zero compute
    on a bad path. A raise here would abort the operation instead of reporting.
    """
    missing = tmp_path / "does_not_exist.json"

    config, errors = read_crc_config(str(missing))

    assert config is None
    assert len(errors) == 1


def test_malformed_json_collects_one_error(tmp_path: Path) -> None:
    """Malformed JSON → (None, [1 error]); no raise.

    Encodes WHY: LLR-004.1 requires a parse fault to surface as exactly one
    collected error, not an unhandled JSONDecodeError.
    """
    bad = tmp_path / "broken.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")

    config, errors = read_crc_config(str(bad))

    assert config is None
    assert len(errors) == 1


def test_over_size_cap_collects_one_error_without_reading(tmp_path: Path) -> None:
    """Over-cap → (None, [1 error]) via the size probe seam; file never read.

    Encodes WHY: LLR-004.1 enforces READ_SIZE_CAP_BYTES BEFORE reading, so an
    oversized declaration cannot force an unbounded read. A deterministic
    over-cap probe drives this without manufacturing a 256 MB file. The file
    content is deliberately well-formed so a regression that reads-then-checks
    would NOT error — only the pre-read cap can produce the error here.
    """
    config_path = tmp_path / "synthetic_crc.json"
    config_path.write_text(
        '{"polynomial":"0x1","init":"0x0","reverse":false,"final_xor":"0x0",'
        '"regions":[{"start":"0x0","end":"0x4","output_address":"0x0"}]}',
        encoding="utf-8",
    )

    oversized_probe = lambda _candidate: 1 << 40  # noqa: E731 — 1 TiB stub

    config, errors = read_crc_config(str(config_path), size_probe=oversized_probe)

    assert config is None
    assert len(errors) == 1


def test_missing_field_collects_one_error(tmp_path: Path) -> None:
    """A config missing a required field → (None, [1 error]); no raise.

    Encodes WHY: LLR-004.1 treats a missing/invalid field as a data-quality
    fault that must be collected, not raised — guards the typed-build path.
    """
    config_path = tmp_path / "incomplete.json"
    config_path.write_text(
        '{"polynomial":"0x04C11DB7","init":"0xFFFFFFFF","reverse":true,'
        '"regions":[{"start":"0x0","end":"0x4","output_address":"0x0"}]}',
        encoding="utf-8",
    )

    config, errors = read_crc_config(str(config_path))

    assert config is None
    assert len(errors) == 1


# ---------------------------------------------------------------------------
# parse_crc_config — the text-level seam the TUI editor routes through
# (LLR-004.2). read_crc_config delegates here after resolve+size-cap+read,
# so its tests above stay green via delegation.
# ---------------------------------------------------------------------------


def test_parse_crc_config_valid_text_populates_config() -> None:
    """Valid JSON text parses into a fully-populated CrcConfig, no error.

    Encodes WHY: LLR-004.2 routes the operator's EDITED config text (never
    written to disk) through parse_crc_config; if hex parsing or field wiring
    regresses on the text path, the TUI surface computes against wrong/null
    values. Mirrors the TC-113 field assertions on in-memory text.
    """
    text = """
    {
      "polynomial": "0x04C11DB7",
      "init": "0xFFFFFFFF",
      "reverse": true,
      "final_xor": "0xFFFFFFFF",
      "regions": [
        { "start": "0x00001000", "end": "0x00002000", "output_address": "0x00001FFC" }
      ]
    }
    """

    config, errors = parse_crc_config(text)

    assert errors == []
    assert isinstance(config, CrcConfig)
    assert config.polynomial == 0x04C11DB7
    assert config.init == 0xFFFFFFFF
    assert config.reverse is True
    assert config.final_xor == 0xFFFFFFFF
    assert config.regions == [
        CrcRegion(start=0x1000, end=0x2000, output_address=0x1FFC),
    ]


def test_parse_crc_config_dummy_prefill_is_valid() -> None:
    """The DUMMY_CONFIG_TEXT pre-fill itself parses cleanly (no error).

    Encodes WHY: the TUI editor (LLR-004.2) pre-fills DUMMY_CONFIG_TEXT for
    format guidance; if the embedded template ever drifts to invalid JSON the
    operator would see a parse error on an untouched dummy. This pins the
    pre-fill as valid config text with the documented dummy values.
    """
    config, errors = parse_crc_config(DUMMY_CONFIG_TEXT)

    assert errors == []
    assert isinstance(config, CrcConfig)
    assert config.regions == [
        CrcRegion(start=0x00010000, end=0x00020000, output_address=0x0001FFFC),
        CrcRegion(start=0x00020000, end=0x00030000, output_address=0x0002FFFC),
    ]


def test_parse_crc_config_malformed_text_collects_one_error() -> None:
    """Malformed JSON text → (None, [1 error]); no raise (collect-don't-abort).

    Encodes WHY: LLR-004.2 mandates a config-load fault on the edited text
    surface to a single collected error and run NO computation — never an
    unhandled JSONDecodeError that would crash the operation.
    """
    config, errors = parse_crc_config("{ this is not valid json")

    assert config is None
    assert len(errors) == 1


def test_parse_crc_config_non_object_top_level_collects_one_error() -> None:
    """A JSON array (not an object) → (None, [1 error]); no raise.

    Encodes WHY: a structurally valid JSON that is not the expected config
    object is still a data-quality fault that must be collected, not raised.
    """
    config, errors = parse_crc_config("[1, 2, 3]")

    assert config is None
    assert len(errors) == 1


# ---------------------------------------------------------------------------
# TC-202 — read_crc_config_text: raw-text reader seam (LLR-013.2 / LLR-013.3)
# returns the file's RAW text WITHOUT parsing, collect-don't-abort on fault.
# ---------------------------------------------------------------------------


def test_read_crc_config_text_returns_raw_text_without_parsing(
    tmp_path: Path,
) -> None:
    """TC-202: read_crc_config_text returns (raw_text, []) and never parses.

    Encodes WHY (LLR-013.2): the CRC "Load config" surface populates the
    editable TextArea with the file's RAW text — the editor stays the single
    source of truth and the run parses on Execute. So the load seam must return
    the byte-equal file text and MUST NOT invoke parse_crc_config. We patch
    parse_crc_config to a sentinel that fails the test if it is ever called on
    the load path; the returned text must equal the file content verbatim.
    """
    config_path = tmp_path / "synthetic_crc.json"
    file_text = (
        '{"polynomial":"0x04C11DB7","init":"0xFFFFFFFF","reverse":true,'
        '"final_xor":"0xFFFFFFFF",'
        '"regions":[{"start":"0x1000","end":"0x2000","output_address":"0x1FFC"}]}'
    )
    config_path.write_text(file_text, encoding="utf-8")

    with mock.patch(
        "s19_app.tui.operations.crc_config.parse_crc_config"
    ) as parse_spy:
        raw_text, errors = read_crc_config_text(str(config_path))

    assert errors == []
    assert raw_text == file_text
    parse_spy.assert_not_called()


def test_read_crc_config_text_unresolvable_path_collects_one_error(
    tmp_path: Path,
) -> None:
    """TC-202 fault: an unresolvable path → (None, [1 error]); no raise.

    Encodes WHY (LLR-013.3): a bad load path must surface exactly one collected
    error and leave the caller free to keep the editor unchanged — never a
    raise that would abort the surface (collect-don't-abort).
    """
    missing = tmp_path / "does_not_exist.json"

    raw_text, errors = read_crc_config_text(str(missing))

    assert raw_text is None
    assert len(errors) == 1


def test_read_crc_config_text_over_cap_collects_one_error_without_reading(
    tmp_path: Path,
) -> None:
    """TC-202 fault: over-cap via the size probe → (None, [1 error]); not read.

    Encodes WHY (LLR-013.2): the READ_SIZE_CAP_BYTES cap is enforced BEFORE the
    read on the raw-text seam exactly as on read_crc_config — an oversized
    declaration cannot force an unbounded read. The file content is well-formed
    so only the pre-read cap can produce the error here.
    """
    config_path = tmp_path / "synthetic_crc.json"
    config_path.write_text("{}", encoding="utf-8")

    oversized_probe = lambda _candidate: 1 << 40  # noqa: E731 — 1 TiB stub

    raw_text, errors = read_crc_config_text(
        str(config_path), size_probe=oversized_probe
    )

    assert raw_text is None
    assert len(errors) == 1


def test_read_crc_config_text_returns_unparsed_invalid_json(tmp_path: Path) -> None:
    """TC-202: a readable-but-invalid-JSON file still returns (raw_text, []).

    Encodes WHY (LLR-013.2): the load seam does NOT parse — a syntactically
    invalid file is loaded into the editor verbatim and the JSON fault surfaces
    only later at parse-on-run. This pins that the reader is read-only, not a
    validator, so a regression that re-added a parse on load would fail here.
    """
    bad = tmp_path / "broken.json"
    bad.write_text("{ not valid json", encoding="utf-8")

    raw_text, errors = read_crc_config_text(str(bad))

    assert errors == []
    assert raw_text == "{ not valid json"


def test_parse_crc_config_missing_field_collects_one_error() -> None:
    """Text missing a required field → (None, [1 error]); no raise.

    Encodes WHY: the typed-build path must collect a missing/invalid field on
    the text seam exactly as the file path does (LLR-004.2 / LLR-004.1 parity).
    """
    text = (
        '{"polynomial":"0x04C11DB7","init":"0xFFFFFFFF","reverse":true,'
        '"regions":[{"start":"0x0","end":"0x4","output_address":"0x0"}]}'
    )

    config, errors = parse_crc_config(text)

    assert config is None
    assert len(errors) == 1


# ---------------------------------------------------------------------------
# batch-32 (R-CRC-GROUP-001 / R-CRC-WIDTH-001) - `groups` schema parsing.
#
# TC-201-family: AT-044b value round-trip; AT-044d parametrized parse
# rejections (LLR-GRP-001.2/.3/.14/.15 incl. the N5/N6 REJECT decisions, the
# span-count ceiling and the 32-bit bounds). All values SYNTHETIC.
# ---------------------------------------------------------------------------

def _groups_config_text(groups, regions=None):
    """Build synthetic config JSON text with the standard dummy params."""
    payload = {
        "polynomial": "0x04C11DB7",
        "init": "0xFFFFFFFF",
        "reverse": True,
        "final_xor": "0xFFFFFFFF",
        "groups": groups,
    }
    if regions is not None:
        payload["regions"] = regions
    return _json.dumps(payload)


def test_at044b_group_values_round_trip_hex_and_int() -> None:
    """AT-044b: a parsed group round-trips its declared values (TC-201.1).

    Intent: "populated + no errors" alone cannot fail against a
    field-dropping parser - the span list (declared order preserved),
    output_address and output_bytes must all round-trip, with numeric
    fields accepted BOTH as hex strings and as native ints.
    """
    text = _groups_config_text(
        [
            {
                "regions": [
                    {"start": "0x00030000", "end": "0x00034000"},
                    {"start": 0x00040000, "end": 0x00042000},
                ],
                "output_address": "0x00042000",
                "output_bytes": 8,
            }
        ]
    )
    config, errors = parse_crc_config(text)
    assert errors == []
    assert config is not None
    assert config.groups == [
        CrcGroup(
            spans=((0x30000, 0x34000), (0x40000, 0x42000)),
            output_address=0x42000,
            output_bytes=8,
        )
    ]
    assert config.regions == []


def test_at044b_output_bytes_defaults_to_4_when_omitted() -> None:
    """AT-046c (parse half): an omitted output_bytes parses as 4 (TC-201.2)."""
    text = _groups_config_text(
        [
            {
                "regions": [{"start": "0x100", "end": "0x200"}],
                "output_address": "0x1FC",
            }
        ]
    )
    config, errors = parse_crc_config(text)
    assert errors == []
    assert config is not None and config.groups[0].output_bytes == 4


def test_legacy_only_config_still_parses_with_empty_groups() -> None:
    """Compat sanity (feeds AT-044a): legacy-only text parses; groups == [].

    Uses a legacy-only literal — since Inc-4 the DUMMY pre-fill deliberately
    demonstrates BOTH forms (AT-044e), so it is no longer legacy-only.
    """
    legacy_only = _json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": True,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {"start": "0x100", "end": "0x200", "output_address": "0x1FC"}
            ],
        }
    )
    config, errors = parse_crc_config(legacy_only)
    assert errors == []
    assert config is not None and config.groups == []


def test_at044e_dummy_prefill_demonstrates_both_forms() -> None:
    """AT-044e: the updated DUMMY pre-fill parses cleanly AND demonstrates
    both a legacy region and a group (format guidance self-validating;
    extends — never replaces — the existing dummy-prefill mirror test)."""
    config, errors = parse_crc_config(DUMMY_CONFIG_TEXT)
    assert errors == []
    assert config is not None
    assert len(config.regions) >= 1, "the pre-fill must keep a legacy region"
    assert len(config.groups) >= 1, "the pre-fill must demonstrate a group"
    assert len(config.groups[0].spans) >= 2, (
        "the demo group should show the multi-span shape"
    )


@pytest.mark.parametrize(
    "mutate, expect_fragment",
    [
        pytest.param(
            "drop_both_keys",
            "at least one of",
            id="at044d-a-neither-key",
        ),
        pytest.param(
            "both_keys_empty",
            "at least one of",
            id="at044d-a-both-empty",
        ),
        pytest.param(
            "empty_group_regions",
            "must not be empty",
            id="at044d-b-empty-group-spans",
        ),
        pytest.param("output_bytes_0", "output_bytes", id="at044d-c-bytes-0"),
        pytest.param("output_bytes_3", "output_bytes", id="at044d-c-bytes-3"),
        pytest.param(
            "output_bytes_negative", "output_bytes", id="at044d-c-bytes-neg"
        ),
        pytest.param(
            "output_bytes_nonint",
            "output_bytes",
            id="at044d-c-bytes-nonint",
        ),
        pytest.param(
            "output_bytes_bool",
            "output_bytes",
            id="at044d-c-bytes-bool",
        ),
        pytest.param(
            "span_inverted",
            "must be greater than",
            id="at044d-n5-inverted-span",
        ),
        pytest.param(
            "span_zero_length",
            "must be greater than",
            id="at044d-n5-zero-length-span",
        ),
        pytest.param(
            "span_stray_output_address",
            "not allowed inside a group span",
            id="at044d-n6-stray-output-address",
        ),
        pytest.param(
            "span_count_over_ceiling",
            "span ceiling",
            id="at044d-d-span-ceiling",
        ),
        pytest.param(
            "start_negative", "must be non-negative", id="at044d-e-neg-start"
        ),
        pytest.param(
            "end_over_32bit",
            "exceeds the 32-bit address space",
            id="at044d-e-end-over-space",
        ),
        pytest.param(
            "output_window_over_32bit",
            "exceeds the 32-bit",
            id="at044d-e-window-over-space",
        ),
    ],
)
def test_at044d_parse_rejections_one_named_error(
    mutate: str, expect_fragment: str
) -> None:
    """AT-044d: each faulty shape yields (None, [exactly one error naming the
    offending rule]) without raising (TC-201.3, parametrized per branch so
    one passing case cannot mask another; LLR-GRP-001.2/.3/.14/.15).
    """
    base_span = {"start": "0x100", "end": "0x200"}
    payload = {
        "polynomial": "0x04C11DB7",
        "init": "0xFFFFFFFF",
        "reverse": True,
        "final_xor": "0xFFFFFFFF",
        "groups": [
            {
                "regions": [dict(base_span)],
                "output_address": "0x1FC",
                "output_bytes": 4,
            }
        ],
    }
    group = payload["groups"][0]
    if mutate == "drop_both_keys":
        payload.pop("groups")
    elif mutate == "both_keys_empty":
        payload["groups"] = []
        payload["regions"] = []
    elif mutate == "empty_group_regions":
        group["regions"] = []
    elif mutate == "output_bytes_0":
        group["output_bytes"] = 0
    elif mutate == "output_bytes_3":
        group["output_bytes"] = 3
    elif mutate == "output_bytes_negative":
        group["output_bytes"] = -1
    elif mutate == "output_bytes_nonint":
        group["output_bytes"] = "four"
    elif mutate == "output_bytes_bool":
        group["output_bytes"] = True
    elif mutate == "span_inverted":
        group["regions"][0] = {"start": "0x200", "end": "0x100"}
    elif mutate == "span_zero_length":
        group["regions"][0] = {"start": "0x100", "end": "0x100"}
    elif mutate == "span_stray_output_address":
        group["regions"][0] = {
            "start": "0x100",
            "end": "0x200",
            "output_address": "0x1FC",
        }
    elif mutate == "span_count_over_ceiling":
        group["regions"] = [
            {"start": hex(0x1000 + 16 * i), "end": hex(0x1000 + 16 * i + 8)}
            for i in range(CRC_SPAN_COUNT_CEILING + 1)
        ]
    elif mutate == "start_negative":
        group["regions"][0] = {"start": -1, "end": "0x200"}
    elif mutate == "end_over_32bit":
        group["regions"][0] = {"start": "0x100", "end": "0x100000001"}
    elif mutate == "output_window_over_32bit":
        group["output_address"] = "0xFFFFFFFD"
        group["output_bytes"] = 8
    else:  # pragma: no cover - guard against a typo'd param
        raise AssertionError(f"unknown mutation {mutate}")

    config, errors = parse_crc_config(_json.dumps(payload))
    assert config is None
    assert len(errors) == 1, f"exactly one collected error; got {errors}"
    assert expect_fragment in errors[0], (
        f"error must name the offending rule; got {errors[0]!r}"
    )


def test_at044b_allowed_output_bytes_all_parse() -> None:
    """N3 boundary: every allowed width in {1,2,4,8} parses cleanly (TC-201.4)."""
    for width in ALLOWED_OUTPUT_BYTES:
        text = _groups_config_text(
            [
                {
                    "regions": [{"start": "0x100", "end": "0x200"}],
                    "output_address": "0x300",
                    "output_bytes": width,
                }
            ]
        )
        config, errors = parse_crc_config(text)
        assert errors == [], f"width {width} must parse; got {errors}"
        assert config is not None and config.groups[0].output_bytes == width
