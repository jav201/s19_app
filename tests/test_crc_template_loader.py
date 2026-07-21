"""
Tests for the E5 template-loader facade (``operations/crc_template.py``).

Two intents (batch-58 HLR-E5):

- **Facade identity (LLR-E5.1):** the facade re-exports by object identity, so a
  future re-implementation that drifts the logic away from the canonical
  ``crc_designer_model`` loader would fail here.
- **Collect-don't-abort through the facade (LLR-E5.2 / AT-CRC-DSN-015):** driving
  the facade's ``read_template`` over each fault class (malformed JSON, over-cap,
  non-object top level, missing required field) returns ``(None, [one error])``
  and never raises; a valid file returns ``(CrcTemplate, [])``.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.operations import crc_designer_model, crc_template

# A minimal, structurally valid CRC-16/XMODEM template (parses with 0 errors).
_VALID_TEMPLATE_JSON = """{
  "name": "CRC-16/XMODEM",
  "algorithm": {
    "width": 16,
    "poly": "0x1021",
    "init": "0x0000",
    "refin": false,
    "refout": false,
    "xorout": "0x0000",
    "check": "0x31C3"
  }
}
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ── Facade identity (LLR-E5.1) ────────────────────────────────────────────────
def test_facade_identity_reexports_by_object_identity() -> None:
    """Every facade symbol is the SAME object as the canonical loader's."""
    assert crc_template.read_template is crc_designer_model.read_template
    assert crc_template.parse_template is crc_designer_model.parse_template
    assert crc_template.emit_template is crc_designer_model.emit_template
    assert crc_template.CrcTemplate is crc_designer_model.CrcTemplate
    # The re-exported read-posture siblings are the same objects too.
    assert crc_template.READ_SIZE_CAP_BYTES is crc_designer_model.READ_SIZE_CAP_BYTES
    assert crc_template.SizeProbe is crc_designer_model.SizeProbe


# ── Collect-don't-abort through the facade (LLR-E5.2 / AT-CRC-DSN-015) ─────────
def test_collect_dont_abort_malformed_json(tmp_path: Path) -> None:
    """(a) Malformed JSON → (None, [one error]), no raise."""
    path = _write(tmp_path, "bad.crc.json", "{not valid json")
    template, errors = crc_template.read_template(str(path), base_dir=tmp_path)
    assert template is None
    assert len(errors) == 1


def test_collect_dont_abort_over_cap(tmp_path: Path) -> None:
    """(b) Over-cap via the injectable size probe → one error, file never parsed."""
    path = _write(tmp_path, "big.crc.json", _VALID_TEMPLATE_JSON)

    def over_cap(candidate: Path) -> int:
        return crc_template.READ_SIZE_CAP_BYTES + 1

    template, errors = crc_template.read_template(
        str(path), base_dir=tmp_path, size_probe=over_cap
    )
    assert template is None
    assert len(errors) == 1


def test_collect_dont_abort_non_object_top_level(tmp_path: Path) -> None:
    """(c) A JSON array top level → one error, no raise."""
    path = _write(tmp_path, "array.crc.json", "[1, 2, 3]")
    template, errors = crc_template.read_template(str(path), base_dir=tmp_path)
    assert template is None
    assert len(errors) == 1


def test_collect_dont_abort_missing_required_field(tmp_path: Path) -> None:
    """(d) A template missing the required 'algorithm' object → one error."""
    path = _write(tmp_path, "missing.crc.json", '{"name": "X"}')
    template, errors = crc_template.read_template(str(path), base_dir=tmp_path)
    assert template is None
    assert len(errors) == 1


def test_valid_template_reads_clean(tmp_path: Path) -> None:
    """A valid template file → (CrcTemplate, []) through the facade."""
    path = _write(tmp_path, "good.crc.json", _VALID_TEMPLATE_JSON)
    template, errors = crc_template.read_template(str(path), base_dir=tmp_path)
    assert errors == []
    assert isinstance(template, crc_template.CrcTemplate)
    assert template.algorithm.name == "CRC-16/XMODEM"
