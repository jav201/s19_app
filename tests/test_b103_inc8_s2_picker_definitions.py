"""Batch-103 Inc 8 E4, group S2, node S22: ``A2LParameterPicker.definitions``.

R-PE-DEF.11 (E3R1 E3A-04, E3R2 E3A-13): the picker keeps, at each real population, the
``describe_definitions`` result it already computes (``definitions``) and the A2L payload
that describe used (``definitions_source``), so the staging sheet builds its rows with
zero further describes. Cases /4../9 are this node's alternatives of that row
(``inc-8/02-test-cases-S2.md``).

Expected values are I-2's own ``describe_definitions`` run here on the same names, never
read back from the picker. The file runs on the base revision, where ``definitions`` is
absent (RED).
"""
from __future__ import annotations

import sys

if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

import pytest

from s19_app.tui import a2l_parameter_picker as picker_module
from s19_app.tui.a2l_definition import describe_definitions
from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
from tests.support.b103_inc8_s2 import DEFC_NAMES, defc, no_os_clipboard, variant  # noqa: F401


def _rows(case):
    return [
        {"name": n, "address": case.defs[n].address, "length": case.defs[n].byte_length}
        for n in DEFC_NAMES
    ]


def _populate(picker, case, signature):
    return picker.set_parameters(_rows(case), signature, a2l_data=case.a2l)


def test_r_pe_def_11_4_definitions_equal_the_i2_describe_of_the_population(defc):
    picker = A2LParameterPicker()
    assert _populate(picker, defc, "sig-1") is True
    expected = describe_definitions(list(DEFC_NAMES), defc.a2l)
    assert dict(picker.definitions) == expected
    assert list(picker.definitions) == list(DEFC_NAMES)


def test_r_pe_def_11_5_definitions_source_is_the_populating_payload(defc):
    picker = A2LParameterPicker()
    _populate(picker, defc, "sig-1")
    assert picker.definitions_source is defc.a2l


def test_r_pe_def_11_6_an_equal_signature_keeps_both_and_describes_nothing(defc, monkeypatch):
    picker = A2LParameterPicker()
    _populate(picker, defc, "sig-1")
    kept_definitions, kept_source = picker.definitions, picker.definitions_source
    calls = []
    real = picker_module.describe_definitions
    monkeypatch.setattr(
        picker_module, "describe_definitions", lambda *a, **k: calls.append(a) or real(*a, **k)
    )
    assert _populate(picker, defc, "sig-1") is False
    assert calls == []
    assert picker.definitions is kept_definitions
    assert picker.definitions_source is kept_source


def test_r_pe_def_11_7_a_changed_signature_replaces_both(defc, tmp_path):
    changed = variant(defc, tmp_path, ('1 "IDLE"', '1 "IDLEX"'))
    picker = A2LParameterPicker()
    _populate(picker, defc, "sig-1")
    assert _populate(picker, changed, "sig-2") is True
    assert picker.definitions_source is changed.a2l
    texts = [e.text for e in picker.definitions["ENUM_0001"].enum_entries]
    assert "IDLEX" in texts and "IDLE" not in texts


def test_r_pe_def_11_8_without_a2l_data_the_pair_is_empty_and_none(defc):
    picker = A2LParameterPicker()
    assert picker.definitions == {} and picker.definitions_source is None
    _populate(picker, defc, "sig-1")
    assert picker.set_parameters(_rows(defc), "sig-2") is True
    assert dict(picker.definitions) == {}
    assert picker.definitions_source is None


def test_r_pe_def_11_9_definitions_are_read_only(defc):
    picker = A2LParameterPicker()
    _populate(picker, defc, "sig-1")
    with pytest.raises(AttributeError):
        picker.definitions = {}
    with pytest.raises(AttributeError):
        picker.definitions_source = None
