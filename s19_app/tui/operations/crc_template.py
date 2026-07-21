"""
CRC template loader facade (batch-58 E5, HLR-E5 / LLR-E5.1-E5.2).

A thin re-export surface for the ``*.crc.json`` algorithm-template loader that
already ships inside :mod:`s19_app.tui.operations.crc_designer_model`. The design
doc names a ``crc_template.py`` module; the keel put the implementation in
``crc_designer_model``. This facade reconciles the two (the a2l-facade
convention: add public symbols to the canonical module, re-export from the
narrow facade) so callers import ``from ..operations.crc_template import
read_template`` while the parsing/validation logic stays single-sourced.

Every symbol below is re-exported by object identity — this module contains
ZERO parsing, validation, or file-read logic of its own. It therefore mirrors
the ``crc_config.py`` collect-don't-abort read posture verbatim: a path is
resolved via ``resolve_input_path``, the ``READ_SIZE_CAP_BYTES`` size cap is
enforced BEFORE reading, and every data-quality fault returns ``(None, [one
error string])`` and NEVER raises. No untrusted-loader posture is re-invented
here.
"""

from __future__ import annotations

from .crc_designer_model import (
    READ_SIZE_CAP_BYTES,
    CrcTemplate,
    SizeProbe,
    emit_template,
    parse_template,
    read_template,
)

__all__ = [
    "READ_SIZE_CAP_BYTES",
    "CrcTemplate",
    "SizeProbe",
    "emit_template",
    "parse_template",
    "read_template",
]
