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

from pathlib import Path

from s19_app.tui.operations.crc_config import (
    CrcConfig,
    CrcRegion,
    read_crc_config,
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
