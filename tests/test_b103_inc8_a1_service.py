"""Batch-103 Inc 8, group A: ``ChangeService.stage_definition`` and ``_stage_encoded`` (E4, tester ``test-a``).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md`` rows R-PE-DEF.50 ... .59, .61
(the service side) and ``codewire/graph-inc8.md`` I-8.1 (consumed) and I-8.2 (produced). Cases:
``inc-8/02-test-cases-A.md``. Every expected byte, text and message is computed through I-2
(``encode_definition`` / ``decode_definition``) over the DEFC image or the V171 hand image, or is the literal
the requirement row prints; none is hand-counted.

The tests drive the shipped service surface only: ``stage_definition`` (the public entry), ``document.entries``,
``history_depths``, ``undo``, ``serialize_change_document`` and ``parse_change_document``. ``_stage_encoded`` is
named directly only where the interface I-8.2 pins it as Inc 9's seam (the 300-character shown text).

``ChangeService`` exists on base ``d5d48685`` but ``stage_definition`` and ``_stage_encoded`` do not, so these
tests have no RED on base (an AttributeError proves nothing); the negative control at the end shows the oracle
can fail.
"""
from __future__ import annotations

import pytest

from s19_app.tui.a2l_definition import Encoded, Refusal, decode_definition, encode_definition
from s19_app.tui.changes.io import parse_change_document, serialize_change_document
from s19_app.tui.changes.model import ChangeEntry
from s19_app.tui.services.change_service import ChangeService
from tests.b103_inc8_a_support import (
    DISPLAY_ADDRESS,
    MASK_WORD,
    V171_ASCII,
    V171_ASCII_ADDRESS,
    build_defc,
    entry_tuples,
    overlay_of,
    v171,
)


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    return build_defc(tmp_path_factory.mktemp("b103_inc8_a1_defc"))


@pytest.fixture(scope="module")
def va():
    return v171()


def stage(service, defc, name, text, image=None):
    return service.stage_definition(defc["defs"][name], defc["a2l"], text, defc["image"] if image is None else image)


def encode(defc, name, text, image=None):
    result = encode_definition(defc["defs"][name], defc["a2l"], text, defc["image"] if image is None else image)
    assert isinstance(result, Encoded), result
    return result


def undo_depth(service) -> int:
    return service.history_depths()["back"]


# ---------------------------------------------------------------- R-PE-DEF.50: the stage writes the span


def test_r_pe_def_50_1_display_25_5_stages_one_bytes_entry(defc):
    service = ChangeService()
    result = stage(service, defc, "DISPLAY_0001", "25.5")
    expected = encode(defc, "DISPLAY_0001", "25.5")
    assert result.ok
    assert [(e.entry_type, e.address, bytes(e.encoded_bytes)) for e in service.document.entries] == [
        ("bytes", expected.address, expected.data)
    ]
    assert expected.address == DISPLAY_ADDRESS


def test_r_pe_def_50_2_enum_run_stages_02(defc):
    service = ChangeService()
    assert stage(service, defc, "ENUM_0001", "RUN").ok
    expected = encode(defc, "ENUM_0001", "RUN")
    assert [(e.address, bytes(e.encoded_bytes)) for e in service.document.entries] == [(expected.address, expected.data)]
    assert expected.address == defc["defs"]["ENUM_0001"].address == 0x800000


def test_r_pe_def_50_3_masked_field_255_stages_1f_f7(defc):
    service = ChangeService()
    assert stage(service, defc, "MASK_FIELD_0001", "255").ok
    (entry,) = service.document.entries
    # the independent oracle: the image word with the field's bits set, the other bits kept
    word = (defc["image"][MASK_WORD] << 8) | defc["image"][MASK_WORD + 1]
    mask = defc["defs"]["MASK_FIELD_0001"].bit_mask
    shift = (mask & -mask).bit_length() - 1
    want = (word & ~mask & 0xFFFF) | (255 << shift)
    assert (entry.address, bytes(entry.encoded_bytes)) == (MASK_WORD, want.to_bytes(2, "big"))
    # and it is the pre-I-2 encode's mistake that this would not have been: the entry is the whole word
    assert len(entry.encoded_bytes) == defc["defs"]["MASK_FIELD_0001"].byte_length == 2


def test_r_pe_def_50_4_v171_ascii_abc_stages_42_bytes(va):
    service = ChangeService()
    result = service.stage_definition(va["defs"][V171_ASCII], va["a2l"], "ABC", va["image"])
    assert result.ok
    (entry,) = service.document.entries
    assert entry.address == V171_ASCII_ADDRESS
    assert bytes(entry.encoded_bytes) == b"ABC" + bytes(39)


# ---------------------------------------------------------------- R-PE-DEF.51: encode over the staged overlay


def _two_stage_word(defc, first, second):
    service = ChangeService()
    for name, text in (first, second):
        assert stage(service, defc, name, text).ok
    return service


def _decode_text(defc, name, service):
    view = overlay_of(defc["image"], service.document.entries)
    decoded = decode_definition(defc["defs"][name], defc["a2l"], view)
    assert not isinstance(decoded, Refusal), decoded
    return decoded.text


def test_r_pe_def_51_1_field_then_bit_decode_as_typed(defc):
    service = _two_stage_word(defc, ("MASK_FIELD_0001", "255"), ("MASK_BIT_0001", "0"))
    assert _decode_text(defc, "MASK_FIELD_0001", service) == "255"
    assert _decode_text(defc, "MASK_BIT_0001", service) == "0"
    (entry,) = service.document.entries
    assert (entry.address, bytes(entry.encoded_bytes)) == (MASK_WORD, bytes([0x1F, 0xF6]))


def test_r_pe_def_51_2_bit_then_field_decode_as_typed(defc):
    service = _two_stage_word(defc, ("MASK_BIT_0001", "0"), ("MASK_FIELD_0001", "255"))
    assert _decode_text(defc, "MASK_FIELD_0001", service) == "255"
    assert _decode_text(defc, "MASK_BIT_0001", service) == "0"
    (entry,) = service.document.entries
    assert (entry.address, bytes(entry.encoded_bytes)) == (MASK_WORD, bytes([0x1F, 0xF6]))


def test_r_pe_def_51_3_apply_remove_then_bit_over_the_source_view(defc):
    """E3S-01: the stage encodes over the SOURCE view of the image (the image before any apply), so after
    Apply and Remove the first staged field's bits do not come back."""
    service = ChangeService()
    assert stage(service, defc, "MASK_FIELD_0001", "255").ok
    live = dict(defc["image"])
    service.apply(live, [(min(live), max(live) + 1)], None, None)
    assert (live[MASK_WORD], live[MASK_WORD + 1]) == (0x1F, 0xF7), "arm setup: the apply wrote the live map"
    service.remove_entry(f"0x{MASK_WORD:X}")
    assert not service.document.entries
    source = service.source_image_view(live)
    assert source[MASK_WORD + 1] == defc["image"][MASK_WORD + 1], "arm setup: the source view holds the old byte"

    assert stage(service, defc, "MASK_BIT_0001", "0", image=source).ok
    (entry,) = service.document.entries
    assert bytes(entry.encoded_bytes) == bytes([0x1A, 0xE6])
    assert _decode_text(defc, "MASK_FIELD_0001", service) == "174"

    # negative control inside the case: the same stage over the LIVE (applied) map resurrects the removed field
    other = ChangeService()
    assert stage(other, defc, "MASK_BIT_0001", "0", image=live).ok
    assert bytes(other.document.entries[0].encoded_bytes) == bytes([0x1F, 0xF6])


# ---------------------------------------------------------------- R-PE-DEF.52 .. .54: replace, append, keep


def test_r_pe_def_52_1_second_stage_of_one_span_replaces_the_entry(defc):
    service = ChangeService()
    assert stage(service, defc, "DISPLAY_0001", "25.5").ok
    assert stage(service, defc, "DISPLAY_0001", "30").ok
    expected = encode(defc, "DISPLAY_0001", "30")
    assert [(e.address, bytes(e.encoded_bytes)) for e in service.document.entries] == [(expected.address, expected.data)]


def test_r_pe_def_52_2_two_masked_fields_make_one_entry(defc):
    service = _two_stage_word(defc, ("MASK_FIELD_0001", "255"), ("MASK_BIT_0001", "0"))
    assert len(service.document.entries) == 1
    assert service.document.entries[0].address == MASK_WORD


def test_r_pe_def_52_3_string_entry_replaced_by_bytes_entry_round_trips(va):
    service = ChangeService()
    service.document.entries.append(
        ChangeEntry("string", V171_ASCII_ADDRESS, tuple(b"Q" * 42), value="Q" * 42, symbol=V171_ASCII)
    )
    assert service.stage_definition(va["defs"][V171_ASCII], va["a2l"], "XYZ", va["image"]).ok
    (entry,) = service.document.entries
    assert entry.entry_type == "bytes" and entry.value is None
    wire = serialize_change_document(service.document).decode("utf-8")
    assert '"type": "bytes"' in wire and '"type": "string"' not in wire
    document = parse_change_document(wire, va["a2l"])
    (read_back,) = document.entries
    view = overlay_of(va["image"], [read_back])
    decoded = decode_definition(va["defs"][V171_ASCII], va["a2l"], view)
    assert not isinstance(decoded, Refusal) and decoded.text == "XYZ"


def test_r_pe_def_53_1_no_intersect_appends_with_the_row_name_as_symbol(defc):
    service = ChangeService()
    assert stage(service, defc, "DISPLAY_0001", "25.5").ok
    (entry,) = service.document.entries
    assert entry.entry_type == "bytes"
    assert entry.symbol == "DISPLAY_0001"


def test_r_pe_def_54_1_replace_keeps_the_old_symbol(defc):
    service = _two_stage_word(defc, ("MASK_FIELD_0001", "255"), ("MASK_BIT_0001", "0"))
    assert service.document.entries[0].symbol == "MASK_FIELD_0001"


# ---------------------------------------------------------------- R-PE-DEF.55: partial overlap refuses


def _overlap_case(defc, address, data):
    service = ChangeService()
    service.document.entries.append(ChangeEntry("bytes", address, tuple(data)))
    before = entry_tuples(service)
    depth = undo_depth(service)
    result = stage(service, defc, "DISPLAY_0001", "25.5")
    assert not result.ok
    assert entry_tuples(service) == before, "the document changed on a refused stage"
    assert undo_depth(service) == depth, "a refused stage pushed history"
    return result


def test_r_pe_def_55_1_entry_inside_the_span_refuses(defc):
    result = _overlap_case(defc, DISPLAY_ADDRESS + 1, (0x11,))
    assert result.message == (
        f"Patch Editor: DISPLAY_0001 overlaps the entry at 0x{DISPLAY_ADDRESS + 1:X} — remove that entry first."
    )


def test_r_pe_def_55_2_entry_straddling_the_start_refuses(defc):
    result = _overlap_case(defc, DISPLAY_ADDRESS - 1, (0x11, 0x22))
    assert result.message == (
        f"Patch Editor: DISPLAY_0001 overlaps the entry at 0x{DISPLAY_ADDRESS - 1:X} — remove that entry first."
    )


# ---------------------------------------------------------------- R-PE-DEF.56 / .57: a refusal writes nothing


def _refused(defc, name, text):
    service = ChangeService()
    refusal = encode_definition(defc["defs"][name], defc["a2l"], text, defc["image"])
    assert isinstance(refusal, Refusal), "arm setup: I-2 refuses this text"
    result = stage(service, defc, name, text)
    assert not result.ok
    assert service.document.entries == []
    assert undo_depth(service) == 0
    assert result.message == f"Patch Editor: {refusal.message}"
    return result


def test_r_pe_def_56_1_abc_leaves_the_document_unchanged(defc):
    _refused(defc, "DISPLAY_0001", "abc")


def test_r_pe_def_56_2_250_leaves_the_document_unchanged(defc):
    result = _refused(defc, "DISPLAY_0001", "250")
    assert result.message == "Patch Editor: DISPLAY_0001: 250 is outside the extended limits -50..200"


def test_r_pe_def_56_3_walk_leaves_the_document_unchanged(defc):
    _refused(defc, "ENUM_0001", "WALK")


# ---------------------------------------------------------------- R-PE-DEF.58: the message


def test_r_pe_def_58_1_message_of_a_display_stage(defc):
    result = stage(ChangeService(), defc, "DISPLAY_0001", "25.5")
    assert result.message == "Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020)."


def test_r_pe_def_58_2_message_of_an_enum_stage(defc):
    result = stage(ChangeService(), defc, "ENUM_0001", "RUN")
    assert result.message == "Patch Editor: ENUM_0001 staged as RUN (1 B at 0x800000)."


def test_r_pe_def_58_3_shown_text_of_300_chars_is_clipped_to_256_and_an_ellipsis(va):
    service = ChangeService()
    encoded = Encoded(V171_ASCII_ADDRESS, b"x" * 42, ())
    result = service._stage_encoded(V171_ASCII, encoded, "x" * 300)
    assert result.ok
    assert f"staged as {'x' * 256}… (42 B at 0x{V171_ASCII_ADDRESS:X})." in result.message
    assert "x" * 257 not in result.message


# ---------------------------------------------------------------- R-PE-DEF.59: the notice


def test_r_pe_def_59_1_notice_is_in_notices_not_in_issues(defc):
    expected = encode(defc, "DISPLAY_0001", "175")
    assert len(expected.notices) == 1, "arm setup: I-2 gives one notice for 175"
    result = stage(ChangeService(), defc, "DISPLAY_0001", "175")
    assert result.ok
    assert tuple(result.notices) == (f"Patch Editor: {expected.notices[0]}",)
    assert list(result.issues) == []
    assert expected.notices[0] not in result.message


# ---------------------------------------------------------------- R-PE-DEF.61: one undo step


def test_r_pe_def_61_1_stage_adds_one_undo_step_and_undo_restores(defc):
    service = ChangeService()
    assert stage(service, defc, "ENUM_0001", "RUN").ok
    before = entry_tuples(service)
    depth = undo_depth(service)
    assert stage(service, defc, "DISPLAY_0001", "25.5").ok
    assert undo_depth(service) == depth + 1
    service.undo()
    assert entry_tuples(service) == before
    # an equal-span replacement is also one step
    assert stage(service, defc, "DISPLAY_0001", "25.5").ok
    depth = undo_depth(service)
    assert stage(service, defc, "DISPLAY_0001", "30").ok
    assert undo_depth(service) == depth + 1


# ---------------------------------------------------------------- negative control (oracle can fail)


def test_control_the_pre_i2_symbol_add_cannot_produce_the_masked_word(defc):
    """The oracle of R-PE-DEF.50/3 and .51 is not vacuous: staging through today's ``add_symbol_entry`` (the
    pre-I-2 encode, which ignores the BIT_MASK) does not give the word ``stage_definition`` must give, so the
    assertions above go RED on that implementation. Runs on base."""
    service = ChangeService()
    try:
        service.add_symbol_entry("MASK_FIELD_0001", "255", defc["a2l"])
    except Exception:  # a refusal or a collision is also a different outcome
        got = None
    else:
        got = [(e.address, bytes(e.encoded_bytes)) for e in service.document.entries]
    assert got != [(MASK_WORD, bytes([0x1F, 0xF7]))]
