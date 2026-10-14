"""Change-5 BACKEND tests — batch-95 increment 003a (HLR-141/142, P-16..P-23),
extended at increment 004b (HLR-143, the report attribution — LLR-143.1/.2).

# TC-712 — the symbol-reference form in the v2 wire (LLR-141.1): symbol
  resolution == the tag map (0 drift); the canonical entry carries the symbol
  field AND the resolved address; the shipped v2.0 reader applies it
  byte-identically; the physical→raw encode round-trips the shipped decode;
  the unresolved symbol is refused at load naming the symbol, 0 bytes applied.
# TC-713 — the Patch Editor picker's BACKEND (LLR-141.2): picking/typing a
  symbol resolves address/length/datatype live into a bytes-form entry; an
  unknown symbol or an unencodable value refuses the add naming it; the
  out-of-limits limb flags (proceeds); no A2L refuses named.
# TC-714 — the flow blocks' A2L reference (LLR-142.1): the Load block's
  a2l_ref resolves through the manifest containment guard; the Patch-block
  override wins for its change-set only; the flow JSON round-trips both
  fields; no declared reference refuses symbol entries named (no implicit
  A2L).
# TC-715 — the A2L reference's source homes (LLR-142.2): project mode
  resolves the project-root A2L; no-project mode resolves under the
  .s19tool\\workarea\\ containment root; a reference in neither home refuses
  the run naming it.
# TC-716 — the report attribution (LLR-143.1): the apply summary carries the
  entry's own symbol; the project report's Modifications table, the diff
  report's Change-entry linkage table and the FLOW report's Change
  attribution section name every change by its symbol when present AND
  always by its resolved address (before/after bytes == the applied bytes;
  zero applied changes renders the section empty, never absent).
# TC-717 — the A2B diff reference-all law (LLR-143.2): a diff over an image
  a flow produced references 100% of the flow's changes — each differing run
  attributed to the entries that produced it, applied entries with no diff
  as explicit no-diff references, named refusals listed as such; a B that is
  NOT a flow product renders the shipped report unchanged.
# TC-718 — the change-5 negative-control battery (the 5a/5b/5c arms): the
  unresolved-symbol refusal names the symbol; the shipped v2.0 reader on
  canonical symbol entries (leniency); the symbol-replaces-address wire form
  dropped CHG-ADDRESS-SYNTAX; every refused encode limb named; the diff block
  omitting one flow change — the census predicate goes RED.

RED counterfactuals (executed, per family — see the increment packet):
  wire — stubbing the ``symbol`` read in ``changes/io.py::_parse_entry``
  reddens the TC-712 resolution/refusal arms; picker — breaking the signed
  range limb in ``a2l.py::encode_physical_to_raw_bytes`` reddens the
  TC-713/718 out-of-range arm; flow — forcing ``a2l_context=None`` in
  ``flow_execution_service.py`` reddens the TC-714 declared-ref arm;
  census — dropping one record from the attribution enumeration in
  ``diff_report_service.py::_flow_change_attribution_lines`` reddens the
  TC-717 reference-all arm (sha256-verified restore).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.tui.a2l import (
    _apply_compu_method,
    _decode_scalar,
    encode_physical_to_raw_bytes,
)
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.changes import (
    CHG_ADDRESS_SYNTAX,
    CHG_SYMBOL_UNRESOLVED,
    CHG_SYMBOL_VALUE,
    ChangeDocument,
    ChangeEntry,
    apply_change_document,
    read_change_document,
    serialize_change_document,
)
from s19_app.tui.changes.io import parse_change_document
from s19_app.tui.changes.model import (
    DISPOSITION_DOMAIN,
    ChangeSummary,
    ChangeSummaryEntry,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.change_service import (
    ChangeService,
    list_a2l_symbol_names,
    resolve_symbol_entry,
)
from s19_app.tui.services.compare_service import (
    SOURCE_EXTERNAL,
    ImageSource,
    compare_images,
)
from s19_app.tui.services.diff_report_service import (
    FlowChangeAttribution,
    _flow_change_attribution_lines,
    flow_change_attribution,
    flow_change_census_complete,
    generate_diff_report,
    generate_diff_report_html,
)
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.flow_persistence_service import (
    FLOW_BAD_FIELD,
    FLOW_UNSAFE_REF,
    dict_to_flow,
    flow_to_dict,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.report_service import (
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    VariantExecutionResult,
)
from s19_app.validation.model import ValidationSeverity

#: Minimal CLEAN S19 — 4 bytes (01 02 03 04) at 0x1000 (checksum-verified),
#: the image every flow test patches.
_S19_CLEAN = "S107100001020304DE\nS9030000FC\n"

#: The change-5 fixture A2L — one COMPU_METHOD per conversion limb plus the
#: tags the battery addresses. Speed @0x1000 is the canonical resolution
#: target (UWORD, CM_double: physical = 2·raw + 10).
_A2L_TEXT = (
    "/begin PROJECT P\n"
    "/begin MODULE M\n"
    "/begin COMPU_METHOD CM_double\n"
    '"phys = 2 raw + 10"\n'
    'LINEAR "%" "u"\n'
    "COEFFS_LINEAR 2.0 10.0\n"
    "/end COMPU_METHOD\n"
    "/begin COMPU_METHOD CM_ident\n"
    '"ident"\n'
    'IDENTICAL "%" "u"\n'
    "/end COMPU_METHOD\n"
    "/begin COMPU_METHOD CM_triple\n"
    '"phys = 3 raw"\n'
    'LINEAR "%" "u"\n'
    "COEFFS_LINEAR 3.0 0.0\n"
    "/end COMPU_METHOD\n"
    "/begin COMPU_METHOD CM_form\n"
    '"form"\n'
    'FORM "X1" "u"\n'
    "/end COMPU_METHOD\n"
    "/begin COMPU_TAB CT1\n"
    "TAB_NOINTP\n"
    "3\n"
    "0 0\n"
    "1 10\n"
    "2 20\n"
    "/end COMPU_TAB\n"
    "/begin COMPU_METHOD CM_tab\n"
    '"tab"\n'
    'TAB_NOINTP "%" "u"\n'
    "COMPU_TAB_REF CT1\n"
    "/end COMPU_METHOD\n"
    "/begin MEASUREMENT Speed\n"
    "UWORD CM_double 0 0 0 65535\n"
    "ECU_ADDRESS 0x00001000\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT RawByte\n"
    "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
    "ECU_ADDRESS 0x00001002\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT IdentVal\n"
    "UWORD CM_ident 0 0 0 65535\n"
    "ECU_ADDRESS 0x00001004\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Limited\n"
    "UBYTE CM_ident 0 0 0 100\n"
    "ECU_ADDRESS 0x00001006\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Gain\n"
    "SBYTE CM_double 0 0 -1000 1000\n"
    "ECU_ADDRESS 0x00001008\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Trippy\n"
    "UWORD CM_triple 0 0 0 65535\n"
    "ECU_ADDRESS 0x0000100A\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Arr\n"
    "UWORD CM_double 0 0 0 65535\n"
    "ECU_ADDRESS 0x0000100C\n"
    "MATRIX_DIM 2\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT FormVal\n"
    "UWORD CM_form 0 0 0 65535\n"
    "ECU_ADDRESS 0x0000100E\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT TabVal\n"
    "UBYTE CM_tab 0 0 0 20\n"
    "ECU_ADDRESS 0x00001010\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Drifty\n"
    "UWORD CM_double 0 0 0 65535\n"
    "ECU_ADDRESS 0x00001012\n"
    "DATA_SIZE 4\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT Half\n"
    "FLOAT16_IEEE NO_COMPU_METHOD 0 0 0 1\n"
    "ECU_ADDRESS 0x00001014\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT NoAddr\n"
    "UWORD CM_double 0 0 0 65535\n"
    "/end MEASUREMENT\n"
    "/begin MEASUREMENT BigSpeed\n"
    "UWORD CM_double 0 0 0 65535\n"
    "ECU_ADDRESS 0x00001016\n"
    "BYTE_ORDER MSB_FIRST\n"
    "/end MEASUREMENT\n"
    "/end MODULE\n"
    "/end PROJECT\n"
)


@pytest.fixture()
def a2l_payload(tmp_path: Path) -> dict:
    """The parsed change-5 fixture A2L (tag map + COMPU_METHOD side tables)."""
    path = tmp_path / "cal.a2l"
    path.write_text(_A2L_TEXT, encoding="utf-8")
    return parse_a2l_file(path)


def _tags(payload: dict) -> dict[str, dict]:
    return {tag["name"]: tag for tag in payload["tags"]}


def _change_doc(entries: list[dict]) -> str:
    """A v2 ``s19app-changeset`` change document JSON string."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _symbol_entry(symbol: str, address: int, raw_bytes: tuple[int, ...]) -> dict:
    return {
        "type": "bytes",
        "address": f"0x{address:08X}",
        "bytes": " ".join(f"{byte:02X}" for byte in raw_bytes),
        "symbol": symbol,
    }


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        target = project_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return project_dir


def _write_alt_a2l(project: Path, name: str, address: int) -> None:
    """An A2L defining ``Speed`` at another address (the override limb)."""
    (project / name).write_text(
        _A2L_TEXT.replace(
            "ECU_ADDRESS 0x00001000", f"ECU_ADDRESS 0x{address:08X}", 1
        ),
        encoding="utf-8",
    )


def _reload_s19(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


# ===========================================================================
# TC-712 — the wire's symbol form (LLR-141.1)
# ===========================================================================


def test_tc712_symbol_resolution_matches_tag_map_zero_drift(a2l_payload: dict) -> None:
    """TC-712 (LLR-141.1): a symbol entry resolves through the tag map with
    0 drift — address/length/datatype come back exactly, the canonical tag
    name is stamped, no findings fire."""
    doc = parse_change_document(
        _change_doc([_symbol_entry("Speed", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert not doc.has_errors
    assert len(doc.entries) == 1
    entry = doc.entries[0]
    tag = _tags(a2l_payload)["Speed"]
    assert entry.address == tag["address"] == 0x1000
    assert entry.symbol == "Speed"
    assert len(entry.encoded_bytes) == tag["length"] == 2
    # case-insensitive as-typed spelling, canonical name stamped
    doc_mixed = parse_change_document(
        _change_doc([_symbol_entry("sPeEd", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert doc_mixed.entries[0].symbol == "Speed"


def test_tc712_physical_raw_encode_roundtrips_shipped_decode(
    a2l_payload: dict,
) -> None:
    """TC-712 (LLR-141.1 numeric threshold): the physical→raw encode
    round-trips the shipped decode — raw → physical → raw, 0 diffs — over
    every supported conversion limb (linear, identical, no-compu, table,
    big-endian)."""
    payload = a2l_payload
    methods = payload["compu_methods_by_name"]
    tabs = payload["compu_tabs_by_name"]
    cases = [
        ("Speed", 100),        # LINEAR 2x+10, little-endian UWORD
        ("RawByte", 200),      # no COMPU_METHOD → identity
        ("IdentVal", 4321),    # IDENTICAL
        ("TabVal", 2),         # TAB_NOINTP exact reverse
        ("BigSpeed", 1234),    # LINEAR, big-endian UWORD
    ]
    for name, raw_seed in cases:
        tag = _tags(payload)[name]
        size = 2 if tag["datatype"] == "UWORD" else 1
        endian = tag["effective_byte_order"]
        prefix = ">" if endian == "big" else "<"
        code = "H" if tag["datatype"] == "UWORD" else "B"
        raw_bytes = struct.pack(f"{prefix}{code}", raw_seed)
        raw_value = _decode_scalar(raw_bytes, tag["datatype"], endian)
        method_name = str(tag.get("compu_method_name") or "")
        # mirror the encode helper's method resolution: NO_COMPU_METHOD /
        # an unknown name is the identity limb (the decode's own fallback).
        method = (
            methods.get(method_name)
            if method_name and method_name != "NO_COMPU_METHOD"
            else None
        )
        physical, status, _ = _apply_compu_method(raw_value, method, tabs)
        assert status in {"ok", "identity_fallback"}, (
            f"{name}: shipped decode refused its own raw ({status})"
        )
        encoded, error, flags = encode_physical_to_raw_bytes(
            tag, physical, methods, tabs,
            payload.get("record_layouts_by_name"),
        )
        assert error is None, f"{name}: encode refused a decodable value"
        assert encoded == tuple(raw_bytes), f"{name}: round-trip drift"
        assert flags == [], f"{name}: in-range value must not flag"


def test_tc712_canonical_writer_emits_symbol_and_resolved_address() -> None:
    """TC-712 (LLR-141.1): the canonical writer emits the symbol AFTER the
    canonical three fields — the wire entry carries BOTH the symbol and the
    resolved address, and re-reading it with the context round-trips."""
    document = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry("bytes", 0x1000, (0x64, 0x00), symbol="Speed")],
    )
    wire_entry = json.loads(serialize_change_document(document))["entries"][0]
    assert wire_entry == {
        "type": "bytes",
        "address": "0x1000",
        "bytes": "64 00",
        "symbol": "Speed",
    }
    # an address-only entry's wire form is byte-identical to pre-change-5
    plain = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry("bytes", 0x1000, (0x64, 0x00))],
    )
    plain_wire = json.loads(serialize_change_document(plain))["entries"][0]
    assert plain_wire == {"type": "bytes", "address": "0x1000", "bytes": "64 00"}


def test_tc712_shipped_v20_reader_applies_symbol_entry_byte_identically(
    tmp_path: Path, a2l_payload: dict
) -> None:
    """TC-712 (LLR-141.1 leniency law, P-19): the shipped v2.0 reader reads
    ``type``/``address``/``value``/``bytes`` by ``.get`` and ignores the
    extra ``symbol`` key — the entry it applies is the entry the symbol-free
    wire describes, byte for byte. The NEW reader with the declared context
    resolves to the same applied bytes."""
    document = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry("bytes", 0x1000, (0x64, 0x00), symbol="Speed")],
    )
    symbol_wire = json.loads(serialize_change_document(document))["entries"][0]
    # What a shipped v2.0 reader sees: the same object minus the ignored key.
    v20_wire = {key: value for key, value in symbol_wire.items() if key != "symbol"}
    shipped = parse_change_document(_change_doc([v20_wire]))
    assert not shipped.has_errors
    resolved = parse_change_document(
        _change_doc([symbol_wire]), a2l_context=a2l_payload
    )
    assert not resolved.has_errors
    shipped_entry, resolved_entry = shipped.entries[0], resolved.entries[0]
    assert (shipped_entry.address, shipped_entry.encoded_bytes) == (
        resolved_entry.address,
        resolved_entry.encoded_bytes,
    )
    assert resolved_entry.symbol == "Speed"
    # ... and the applied result over an image is identical either way.
    mem_map = {0x1000: 1, 0x1001: 2}
    doc_a = parse_change_document(_change_doc([v20_wire]))
    doc_b = parse_change_document(_change_doc([symbol_wire]), a2l_context=a2l_payload)
    map_a, map_b = dict(mem_map), dict(mem_map)
    apply_change_document(doc_a, map_a, [(0x1000, 0x1004)], None, None)
    apply_change_document(doc_b, map_b, [(0x1000, 0x1004)], None, None)
    assert map_a == map_b == {0x1000: 0x64, 0x1001: 0x00}


def test_tc712_unresolved_symbol_refused_at_load_naming_it(
    a2l_payload: dict,
) -> None:
    """TC-712 (LLR-141.1 refusal): an unknown symbol is REFUSED at load —
    one CHG-SYMBOL-UNRESOLVED naming the symbol, the entry skipped, 0 bytes
    applied (has_errors blocks the document)."""
    doc = parse_change_document(
        _change_doc([_symbol_entry("Nope", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert doc.entries == []
    assert doc.has_errors
    assert [issue.code for issue in doc.issues] == [CHG_SYMBOL_UNRESOLVED]
    assert "'Nope'" in doc.issues[0].message


def test_tc712_no_context_refuses_symbol_entry_no_implicit_a2l() -> None:
    """TC-712/LLR-142.1 (the no-implicit-A2L law): with NO declared context
    even a perfectly canonical symbol entry is refused named — the resolved
    address on the wire is not authority to skip resolution."""
    doc = parse_change_document(
        _change_doc([_symbol_entry("Speed", 0x1000, (0x64, 0x00))])
    )
    assert doc.entries == []
    assert [issue.code for issue in doc.issues] == [CHG_SYMBOL_UNRESOLVED]
    assert "'Speed'" in doc.issues[0].message
    assert "no A2L context" in doc.issues[0].message


def test_tc712_tag_without_address_or_length_refused_named(
    a2l_payload: dict,
) -> None:
    """TC-712 (LLR-141.1 boundary): a symbol naming a tag with no address
    refuses named — the tag-map half of the unresolved limb."""
    doc = parse_change_document(
        _change_doc([_symbol_entry("NoAddr", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert doc.entries == []
    assert [issue.code for issue in doc.issues] == [CHG_SYMBOL_UNRESOLVED]
    assert "'NoAddr'" in doc.issues[0].message


def test_tc712_symbol_on_string_entry_and_drift_refused_named(
    a2l_payload: dict,
) -> None:
    """TC-712 (LLR-141.1 value/drift limbs): a symbol on a STRING entry and a
    declared address/length that drift from the resolved tag both refuse
    with CHG-SYMBOL-VALUE naming the symbol."""
    string_form = {
        "type": "string",
        "address": "0x00001000",
        "value": "210",
        "symbol": "Speed",
    }
    doc = parse_change_document(
        _change_doc([string_form]), a2l_context=a2l_payload
    )
    assert doc.entries == []
    assert [issue.code for issue in doc.issues] == [CHG_SYMBOL_VALUE]
    assert "'Speed'" in doc.issues[0].message

    drifted_address = parse_change_document(
        _change_doc([_symbol_entry("Speed", 0x2000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert drifted_address.entries == []
    assert [
        issue.code for issue in drifted_address.issues
    ] == [CHG_SYMBOL_VALUE]
    assert "'Speed'" in drifted_address.issues[0].message

    drifted_length = parse_change_document(
        _change_doc([_symbol_entry("Speed", 0x1000, (0x64,))]),
        a2l_context=a2l_payload,
    )
    assert drifted_length.entries == []
    assert [
        issue.code for issue in drifted_length.issues
    ] == [CHG_SYMBOL_VALUE]


def test_tc712_address_only_entries_read_and_write_byte_identically(
    tmp_path: Path,
) -> None:
    """TC-712 (LLR-141.1 regression limb): address-only documents — the
    shipped majority — read and write byte-identically to pre-change-5,
    including through the FILE seam with a context threaded."""
    document = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[
            ChangeEntry("bytes", 0x1000, (0xDE, 0xAD)),
            ChangeEntry("string", 0x2000, (0x41, 0x42), value="AB"),
        ],
    )
    path = tmp_path / "changes.json"
    path.write_bytes(serialize_change_document(document))
    reread = read_change_document(str(path), tmp_path, a2l_context={"tags": []})
    assert not reread.has_errors
    assert len(reread.entries) == 2
    assert reread.entries[0].symbol is None
    assert serialize_change_document(reread) == serialize_change_document(document)


# ===========================================================================
# TC-713 — the Patch Editor picker's backend (LLR-141.2)
# ===========================================================================


def test_tc713_picker_lists_loaded_tag_names(a2l_payload: dict) -> None:
    """TC-713 (LLR-141.2): the picker's list source is exactly the loaded
    A2L's canonical tag names, sorted; no A2L → an empty list (the UI limb:
    the symbol input stays absent, never a dead control)."""
    names = list_a2l_symbol_names(a2l_payload)
    assert names == sorted(tag["name"] for tag in a2l_payload["tags"])
    assert "Speed" in names
    assert list_a2l_symbol_names(None) == []
    assert list_a2l_symbol_names({}) == []


def test_tc713_picking_resolves_address_length_datatype_zero_drift(
    a2l_payload: dict,
) -> None:
    """TC-713 (LLR-141.2): picking a symbol and setting a physical value
    resolves the entry live — 0 drift from the tag map, bytes-form, the
    physical→raw conversion applied (Speed 210 → raw 100 → 64 00 LE)."""
    result = resolve_symbol_entry("Speed", "210", a2l_payload)
    assert result.ok
    assert result.entry is not None
    entry = result.entry
    tag = _tags(a2l_payload)["Speed"]
    assert entry.address == tag["address"] == 0x1000
    assert entry.symbol == "Speed"
    assert entry.encoded_bytes == (0x64, 0x00)
    assert len(entry.encoded_bytes) == tag["length"] == 2
    assert entry.entry_type == "bytes"
    assert result.issues == []


def test_tc713_resolve_is_case_insensitive_canonical_name_stamped(
    a2l_payload: dict,
) -> None:
    """TC-713 (LLR-141.2): as-typed spelling resolves case-insensitively (the
    shipped name-index idiom); the stamped symbol is the canonical tag name
    so the canonical wire form round-trips."""
    result = resolve_symbol_entry("sPeEd", "210", a2l_payload)
    assert result.ok
    assert result.entry is not None
    assert result.entry.symbol == "Speed"


def test_tc713_unknown_symbol_refuses_add_naming_it(a2l_payload: dict) -> None:
    """TC-713 (LLR-141.2 refusal): an unknown symbol refuses the add — the
    status message names the symbol, 0 entries added."""
    service = ChangeService()
    result = service.add_symbol_entry("Nope", "210", a2l_payload)
    assert not result.ok
    assert service.document.entries == []
    assert [issue.code for issue in result.issues] == [CHG_SYMBOL_UNRESOLVED]
    assert "'Nope'" in result.message


def test_tc713_no_a2l_refuses_named() -> None:
    """TC-713 (LLR-141.2 boundary): with no A2L loaded the picker refuses
    named — the backend half of 'the symbol input is absent with no A2L'."""
    result = resolve_symbol_entry("Speed", "210", None)
    assert not result.ok
    assert [issue.code for issue in result.issues] == [CHG_SYMBOL_UNRESOLVED]
    assert "'Speed'" in result.issues[0].message
    assert "no A2L" in result.issues[0].message


def test_tc713_out_of_limits_flags_and_proceeds(a2l_payload: dict) -> None:
    """TC-713 (LLR-141.2 boundary catalog): a value outside the tag's limits
    FLAGs (one WARNING) and the write PROCEEDS — the recorded P3 limb."""
    result = resolve_symbol_entry("Limited", "150", a2l_payload)
    assert result.ok
    assert result.entry is not None
    assert result.entry.encoded_bytes == (150,)
    assert len(result.issues) == 1
    assert result.issues[0].severity is ValidationSeverity.WARNING
    assert "outside" in result.issues[0].message


def test_tc713_add_symbol_entry_appends_and_serializes_with_symbol(
    a2l_payload: dict,
) -> None:
    """TC-713 (LLR-141.2 + LLR-141.1): the service append lands the entry and
    the canonical save carries symbol + resolved address; the duplicate
    address rule of the interactive add holds."""
    service = ChangeService()
    added = service.add_symbol_entry("Speed", "210", a2l_payload)
    assert added.ok
    assert len(service.document.entries) == 1
    wire = json.loads(serialize_change_document(service.document))["entries"][0]
    assert wire["symbol"] == "Speed"
    assert wire["address"] == "0x1000"
    with pytest.raises(ValueError, match="already exists"):
        service.add_symbol_entry("Speed", "220", a2l_payload)
    assert len(service.document.entries) == 1


# ===========================================================================
# TC-718 — the change-5 negative-control battery (5a/5b arms)
# ===========================================================================


def test_tc718_battery_unresolved_symbol_refusal_names_itself(
    a2l_payload: dict,
) -> None:
    """TC-718 (battery arm): every unresolved-symbol refusal — wire read with
    context, wire read without context, picker — names the symbol in the
    finding (1/1)."""
    with_context = parse_change_document(
        _change_doc([_symbol_entry("Ghost", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    assert "'Ghost'" in with_context.issues[0].message
    without_context = parse_change_document(
        _change_doc([_symbol_entry("Ghost", 0x1000, (0x64, 0x00))])
    )
    assert "'Ghost'" in without_context.issues[0].message
    picked = resolve_symbol_entry("Ghost", "1", a2l_payload)
    assert "'Ghost'" in picked.issues[0].message


def test_tc718_battery_symbol_replaces_address_dropped_by_address_syntax() -> None:
    """TC-718 (battery arm, the untouched law): a wire form where ``symbol``
    REPLACES ``address`` is dropped by CHG-ADDRESS-SYNTAX exactly as
    pre-change-5 — the leniency law protects the ADDED field only."""
    replaced = {
        "type": "bytes",
        "symbol": "Speed",
        "bytes": "64 00",
    }
    doc = parse_change_document(_change_doc([replaced]))
    assert doc.entries == []
    assert [issue.code for issue in doc.issues] == [CHG_ADDRESS_SYNTAX]


@pytest.mark.parametrize(
    ("symbol", "value", "limb_fragments"),
    [
        # non-numeric value
        ("Speed", "abc", (CHG_SYMBOL_VALUE, "not a number")),
        # non-integral raw: 10 / 3 is not representable
        ("Trippy", "10", (CHG_SYMBOL_VALUE, "not integral")),
        # raw out of range: (300 - 10) / 2 = 145 > SBYTE max 127
        ("Gain", "300", (CHG_SYMBOL_VALUE, "outside the SBYTE range")),
        # length drift: DATA_SIZE 4 vs UWORD size 2
        ("Drifty", "210", (CHG_SYMBOL_VALUE, "drifts")),
        # arrays: MATRIX_DIM 2
        ("Arr", "210", (CHG_SYMBOL_VALUE, "array")),
        # unsupported conversion: FORM
        ("FormVal", "210", (CHG_SYMBOL_VALUE, "'FORM'")),
        # unsupported datatype: FLOAT16_IEEE
        ("Half", "1", (CHG_SYMBOL_VALUE, "FLOAT16")),
        # tag without an address
        ("NoAddr", "210", (CHG_SYMBOL_UNRESOLVED, "without an address")),
    ],
)
def test_tc718_battery_refused_encode_limbs_named(
    a2l_payload: dict, symbol: str, value: str, limb_fragments: tuple[str, ...]
) -> None:
    """TC-718 (battery arm): every refused encode/value limb names itself in
    the CHG-SYMBOL-VALUE finding; the add lands 0 entries."""
    result = resolve_symbol_entry(symbol, value, a2l_payload)
    assert not result.ok
    assert result.entry is None
    issue = result.issues[0]
    assert issue.code == limb_fragments[0]
    for fragment in limb_fragments[1:]:
        assert fragment in issue.message
    service = ChangeService()
    refused = service.add_symbol_entry(symbol, value, a2l_payload)
    assert not refused.ok
    assert service.document.entries == []


def test_tc718_battery_codes_mode_document_refuses(a2l_payload: dict) -> None:
    """TC-718 (battery arm): the codes-mode limb — a physical scalar has no
    meaning in a code-point document; the picker refuses named."""
    result = resolve_symbol_entry("Speed", "210", a2l_payload, value_mode="codes")
    assert not result.ok
    assert [issue.code for issue in result.issues] == [CHG_SYMBOL_VALUE]
    assert "'Speed'" in result.issues[0].message
    service = ChangeService()
    service.document.value_mode = "codes"
    refused = service.add_symbol_entry("Speed", "210", a2l_payload)
    assert not refused.ok
    assert service.document.entries == []


# ===========================================================================
# TC-714 — the flow blocks' A2L reference (LLR-142.1)
# ===========================================================================


def _flow_files(symbol_raw: tuple[int, ...], address: int = 0x1000) -> dict[str, str]:
    return {
        "prg.s19": _S19_CLEAN,
        "cal.a2l": _A2L_TEXT,
        "changes.json": _change_doc([_symbol_entry("Speed", address, symbol_raw)]),
    }


def test_tc714_source_a2l_ref_resolves_symbols_through_guard(tmp_path: Path) -> None:
    """TC-714 (LLR-142.1): a Load block declaring the project-root A2L
    resolves the change-set's symbol entries 100% — the run applies the
    entry through the declared reference."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    flow = Flow(
        name="a2l-ref",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_OK
    assert patch.summary == "applied 1 entry"
    written = _reload_s19(result.written_paths[0])
    assert written[0x1000] == 0x64 and written[0x1001] == 0x00


def test_tc714_no_declared_ref_refuses_symbol_entries_no_implicit_a2l(
    tmp_path: Path,
) -> None:
    """TC-714/LLR-142.1 (no-implicit law): a flow whose blocks declare NO
    a2l_ref applies 0 of the symbol entry's bytes even with a loaded project
    A2L on the context — and the read refusal names the symbol."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    flow = Flow(
        name="no-ref",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(
        flow, FlowContext(project_dir=project, a2l_data=parse_a2l_file(project / "cal.a2l"))
    )
    patch = result.block_results[1]
    assert patch.summary == "applied 0 entries"
    written = _reload_s19(result.written_paths[0])
    assert written[0x1000] == 0x01  # untouched
    refused = read_change_document(
        str(project / "changes.json"), project, a2l_context=None
    )
    assert refused.has_errors
    assert "'Speed'" in refused.issues[0].message


def test_tc714_patch_override_wins_for_its_change_set_only(tmp_path: Path) -> None:
    """TC-714 (LLR-142.1 override limb): the Patch block's own a2l_ref wins
    for ITS change-set only — sibling patches still resolve against the Load
    block's declared reference (the override never leaks)."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "cal.a2l": _A2L_TEXT,
            # Patch 1: no override → Speed resolves against cal.a2l @0x1000.
            "changes1.json": _change_doc([_symbol_entry("Speed", 0x1000, (0x64, 0x00))]),
            # Patch 2: override → Speed resolves against alt.a2l @0x1002.
            "changes2.json": _change_doc([_symbol_entry("Speed", 0x1002, (0x07, 0x00))]),
        },
    )
    _write_alt_a2l(project, "alt.a2l", 0x1002)
    flow = Flow(
        name="override",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("changes1.json"),
            PatchBlock("changes2.json", a2l_ref="alt.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    assert result.block_results[1].summary == "applied 1 entry"
    assert result.block_results[2].summary == "applied 1 entry"
    written = _reload_s19(result.written_paths[0])
    assert written[0x1000] == 0x64  # Load-declared reference
    assert written[0x1002] == 0x07  # the patch's overriding reference
    # the drift guard proves the override actually governed: had changes2
    # resolved against cal.a2l, Speed would be 0x1000 ≠ the declared 0x1002
    # and the entry would have been refused (applied 0 entries).


def test_tc714_flow_json_round_trips_a2l_ref(tmp_path: Path) -> None:
    """TC-714 (LLR-142.1 round-trip): the flow JSON carries both a2l_ref
    fields byte-identically; an absent a2l_ref stays absent (default None)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN, "cal.a2l": _A2L_TEXT})
    flow = Flow(
        name="roundtrip",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("changes.json", a2l_ref="cal.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )
    payload = flow_to_dict(flow)
    source_wire, patch_wire = payload["blocks"][0], payload["blocks"][1]
    assert source_wire["a2l_ref"] == "cal.a2l"
    assert patch_wire["a2l_ref"] == "cal.a2l"
    assert "a2l_ref" not in flow_to_dict(
        Flow(name="plain", blocks=[SourceBlock("prg.s19"), PatchBlock("changes.json")])
    )["blocks"][0]
    loaded, findings = dict_to_flow(payload, project)
    assert findings == []
    assert loaded is not None
    assert loaded.blocks[0].a2l_ref == "cal.a2l"
    assert loaded.blocks[1].a2l_ref == "cal.a2l"
    plain, plain_findings = dict_to_flow(
        flow_to_dict(Flow(name="p", blocks=[SourceBlock("prg.s19")])),
        project,
    )
    assert plain_findings == []
    assert plain.blocks[0].a2l_ref is None


def test_tc714_loader_rejects_unsafe_a2l_ref(tmp_path: Path) -> None:
    """TC-714 (LLR-142.1 boundary): an escaping a2l_ref is refused like any
    other ref — the reused containment guard and the drive-relative pre-reject
    both fire; a non-string a2l_ref is a field fault."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})

    def _payload(ref: object) -> dict:
        return {
            "schema_version": 1,
            "name": "f",
            "blocks": [
                {"kind": "source", "image_ref": "prg.s19", "a2l_ref": ref}
            ],
        }

    escaping, findings = dict_to_flow(_payload("../cal.a2l"), project)
    assert escaping is None
    assert [f.code for f in findings] == [MANIFEST_PATH_ESCAPE]
    drive, drive_findings = dict_to_flow(_payload("C:cal.a2l"), project)
    assert drive is None
    assert [f.code for f in drive_findings] == [FLOW_UNSAFE_REF]
    non_string, ns_findings = dict_to_flow(_payload(7), project)
    assert non_string is None
    assert [f.code for f in ns_findings] == [FLOW_BAD_FIELD]


def test_tc714_dangling_override_refuses_run_naming_it(tmp_path: Path) -> None:
    """TC-714 (LLR-142.1 refusing limb): a Patch a2l_ref resolving to nothing
    refuses the run, naming the reference; downstream blocks skip."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    flow = Flow(
        name="dangling-override",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("changes.json", a2l_ref="missing.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_ERROR
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_ERROR
    assert patch.summary == "a2l reference unresolved"
    assert any("'missing.a2l'" in line for line in patch.diagnostics)
    assert result.block_results[2].status == "skipped"
    assert result.written_paths == []


# ===========================================================================
# TC-715 — the A2L reference's source homes (LLR-142.2)
# ===========================================================================


def test_tc715_project_mode_resolves_project_root_a2l(tmp_path: Path) -> None:
    """TC-715 (LLR-142.2, project arm): the reference resolves against the
    PROJECT FOLDER first — the shipped home of the loaded project's A2L
    (saved flat at the project root)."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    flow = Flow(
        name="project-home",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    assert result.block_results[1].summary == "applied 1 entry"


def test_tc715_no_project_mode_resolves_under_workarea_root(tmp_path: Path) -> None:
    """TC-715 (LLR-142.2, no-project arm): with the run not bound to a saved
    project (the context's project dir IS the .s19tool\\workarea containment
    root), the reference resolves against the organized workspace tree."""
    workarea = tmp_path / ".s19tool" / "workarea"
    nested = workarea / "a2l"
    nested.mkdir(parents=True)
    (nested / "cal.a2l").write_text(_A2L_TEXT, encoding="utf-8")
    (workarea / "prg.s19").write_text(_S19_CLEAN, encoding="utf-8")
    (workarea / "changes.json").write_text(
        _change_doc([_symbol_entry("Speed", 0x1000, (0x64, 0x00))]),
        encoding="utf-8",
    )
    flow = Flow(
        name="workspace-home",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="a2l/cal.a2l"),
            PatchBlock("changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=workarea))
    assert result.status == FLOW_STATUS_OK
    assert result.block_results[1].summary == "applied 1 entry"
    written = _reload_s19(result.written_paths[0])
    assert written[0x1000] == 0x64


def test_tc715_reference_in_neither_home_refuses_run_naming_it(
    tmp_path: Path,
) -> None:
    """TC-715 (LLR-142.2 refusing limb): a reference present in neither home
    refuses the run, the error naming the reference; 0 entries applied."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    flow = Flow(
        name="dangling",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="ghost.a2l"),
            PatchBlock("changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_ERROR
    source = result.block_results[0]
    assert source.status == BLOCK_STATUS_ERROR
    assert source.summary == "a2l reference unresolved"
    assert any("'ghost.a2l'" in line for line in source.diagnostics)
    assert result.block_results[1].status == "skipped"
    assert result.written_paths == []


def test_tc715_reference_outside_guard_refused_like_any_ref(tmp_path: Path) -> None:
    """TC-715 (LLR-142.2 negative control): a reference escaping the
    containment root is refused by the guard itself — the run applies 0
    entries and names the reference; the two homes are not second-guessed
    against outside paths."""
    project = _make_project(tmp_path, _flow_files((0x64, 0x00)))
    outside = tmp_path / "outside.a2l"
    outside.write_text(_A2L_TEXT, encoding="utf-8")
    absolute_ref = str(outside).replace("\\", "/")
    flow = Flow(
        name="escape",
        blocks=[
            SourceBlock("prg.s19", a2l_ref=absolute_ref),
            PatchBlock("changes.json"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_ERROR
    assert "MANIFEST-PATH-ESCAPE" in result.block_results[0].diagnostics[0]


# ===========================================================================
# TC-716 — the report attribution (LLR-143.1): every change named by its
# symbol when present AND always by its resolved address
# ===========================================================================


def test_tc716_summary_entry_carries_symbol(a2l_payload: dict) -> None:
    """TC-716 (LLR-143.1, the summary seat): the apply summary carries the
    entry's OWN A2L symbol — stamped from the resolved wire entry, serialized
    in ``to_dict`` — while the reverse linkage limb stays separate."""
    doc = parse_change_document(
        _change_doc([_symbol_entry("Speed", 0x1000, (0x64, 0x00))]),
        a2l_context=a2l_payload,
    )
    mem_map = {0x1000: 1, 0x1001: 2}
    summary = apply_change_document(doc, mem_map, [(0x1000, 0x1004)], None, None)
    entry = summary.entries[0]
    assert entry.symbol == "Speed"
    assert entry.linkage_symbol is None
    assert summary.to_dict()["entries"][0]["symbol"] == "Speed"
    # an address-form entry keeps the byte-stable ``None``.
    plain_doc = parse_change_document(
        _change_doc([{"type": "bytes", "address": "0x00001000", "bytes": "64 00"}])
    )
    plain_map = {0x1000: 1, 0x1001: 2}
    plain = apply_change_document(plain_doc, plain_map, [(0x1000, 0x1004)], None, None)
    assert plain.entries[0].symbol is None
    assert plain.to_dict()["entries"][0]["symbol"] is None


def test_tc716_project_report_modifications_attribute_symbol_and_address(
    tmp_path: Path,
) -> None:
    """TC-716 (LLR-143.1, the project-report seat): every Modifications row
    names the change by its OWN symbol when present AND always by its resolved
    address; the address-only row keeps the shipped best-effort linkage
    fallback (and its address)."""
    symbol_entry = ChangeSummaryEntry(
        entry_type="bytes",
        address_start=0x1000,
        address_end=0x1002,
        before_bytes=(0x01, 0x02),
        after_bytes=(0x64, 0x00),
        disposition="applied",
        linkage="a2l",
        linkage_symbol="ZRev",   # reverse linkage — must LOSE to the own symbol
        symbol="Speed",
    )
    address_entry = ChangeSummaryEntry(
        entry_type="bytes",
        address_start=0x2000,
        address_end=0x2001,
        before_bytes=(0x07,),
        after_bytes=(0x08,),
        disposition="applied",
        linkage="standalone",
        linkage_symbol=None,
        symbol=None,
    )
    counts = {
        token: (2 if token == "applied" else 0) for token in DISPOSITION_DOMAIN
    }
    summary = ChangeSummary(
        source_path=Path("changes.json"),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-10-13T12:00:00+00:00",
        variant_id=None,
        counts=counts,
        entries=[symbol_entry, address_entry],
    )
    results = [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            change_summaries=[summary],
        )
    ]
    variant_set = ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(variant_id="a", path=Path("a.s19"), file_type="s19"),
        ),
        active_id="a",
    )
    path = generate_project_report(
        tmp_path, results, ReportOptions(), variant_set=variant_set
    )
    text = path.read_text(encoding="utf-8")
    section = text.split("### Modifications")[1]
    rows = [ln for ln in section.splitlines() if ln.startswith("| 0x")]
    assert len(rows) == 2, "one row per applied entry — 0 unlisted"
    speed_row = next(ln for ln in rows if "0x00001000" in ln)
    cells = [cell.strip() for cell in speed_row.strip("|").split("|")]
    assert cells[0] == "0x00001000", "the resolved address is always named"
    assert cells[5] == "Speed", "the OWN symbol wins over the reverse linkage"
    address_row = next(ln for ln in rows if "0x00002000" in ln)
    cells = [cell.strip() for cell in address_row.strip("|").split("|")]
    assert cells[0] == "0x00002000"
    assert cells[5] == "-", "an address-only change renders no symbol"


def test_tc716_diff_linkage_table_prefers_entry_symbol() -> None:
    """TC-716 (LLR-143.1, the diff linkage seat): the Change-entry linkage
    table names the change by its OWN symbol when present (md + html), the
    shipped reverse linkage remains the fallback for address-only entries."""
    from s19_app.tui.services.diff_report_service import (
        _html_linkage,
        _linkage_table_lines,
    )

    def _entry(symbol: str | None, linkage_symbol: str | None) -> ChangeSummaryEntry:
        return ChangeSummaryEntry(
            entry_type="bytes",
            address_start=0x1000,
            address_end=0x1002,
            before_bytes=(0x01, 0x02),
            after_bytes=(0x64, 0x00),
            disposition="applied",
            linkage="a2l",
            linkage_symbol=linkage_symbol,
            symbol=symbol,
        )

    row = next(
        ln
        for ln in _linkage_table_lines([_entry("Speed", "ZRev")])
        if ln.startswith("| 1 |")
    )
    assert "Speed" in row and "ZRev" not in row
    row = next(
        ln
        for ln in _linkage_table_lines([_entry(None, "ZRev")])
        if ln.startswith("| 1 |")
    )
    assert "ZRev" in row, "the shipped fallback holds for address-only entries"
    # the HTML twin carries the same preference (md/html pair consistency).
    html_row = next(
        ln
        for ln in _html_linkage([_entry("Speed", "ZRev")])
        if ln.startswith("<tr><td>")
    )
    assert "Speed" in html_row and "ZRev" not in html_row


def test_tc716_flow_report_change_attribution_section(tmp_path: Path) -> None:
    """TC-716 (LLR-143.1, the flow-report seat): the Change attribution
    section lists every change the flow's patch arms applied — one row per
    applied entry (0 unlisted), each naming the symbol when present AND the
    resolved address, with the exact before/after bytes and the A2L reference
    the entry resolved against."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "cal.a2l": _A2L_TEXT,
            "c1.json": _change_doc(
                [
                    _symbol_entry("Speed", 0x1000, (0x64, 0x00)),
                    {"type": "bytes", "address": "0x00001002", "bytes": "03"},
                ]
            ),
            "c3.json": _change_doc(
                [{"type": "bytes", "address": "0x00002000", "bytes": "AA"}]
            ),
        },
    )
    flow = Flow(
        name="attribution",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("c1.json"),
            PatchBlock("c3.json"),
            WriteOutBlock("out.s19"),
            ReportBlock(),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    reports = sorted((project / "reports").glob("*.md"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")
    assert "## Change attribution" in text
    section = text.split("## Change attribution")[1]
    rows = [ln for ln in section.splitlines() if ln.startswith("| #")]
    assert len(rows) == 2, "rows == the applied entries (0 unlisted)"
    speed_row = next(ln for ln in rows if "0x00001000" in ln)
    assert "| #2 |" in speed_row, "the row names the patch arm that applied it"
    assert "Speed" in speed_row, "the symbol when present"
    assert "01 02" in speed_row and "64 00" in speed_row, "the before/after bytes"
    assert "cal\\.a2l" in speed_row, "the A2L reference it resolved against"
    noop_row = next(ln for ln in rows if "0x00001002" in ln)
    assert "03" in noop_row
    assert "0x00002000" not in section, (
        "a skipped-outside entry is not an applied row (the census lists it)"
    )
    # the section sits between the ledger and the footprint, per SECTION_HEADINGS
    assert text.find("## Change attribution") > text.find("## Pipeline ledger")
    assert text.find("## Change attribution") < text.find("## Image footprint")


def test_tc716_change_attribution_empty_renders_never_absent(
    tmp_path: Path,
) -> None:
    """TC-716 (LLR-143.1 boundary): a flow that applied nothing renders the
    section EMPTY — the header and an explicit none-marker, never absent, and
    no attribution table at all."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    flow = Flow(
        name="no-changes",
        blocks=[SourceBlock("prg.s19"), ReportBlock()],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    reports = sorted((project / "reports").glob("*.md"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")
    assert "## Change attribution" in text
    section = text.split("## Change attribution")[1]
    assert "- (no changes applied)" in section
    assert "| Patch |" not in section, "the empty case grows no table rows"


# ===========================================================================
# TC-717 — the A2B diff reference-all law (LLR-143.2): a diff over an image
# a flow produced references 100% of the flow's changes
# ===========================================================================


def _census_flow_result(tmp_path: Path):
    """Run the census fixture flow and diff its source against the output.

    The flow: Speed @0x1000 (produces the run), a no-op address entry
    @0x1002 (applied, no diff), a refused Ghost entry (dropped at read) and
    a skipped-outside entry @0x2000 — so the census sees every disposition.
    """
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "cal.a2l": _A2L_TEXT,
            "c1.json": _change_doc(
                [
                    _symbol_entry("Speed", 0x1000, (0x64, 0x00)),
                    {"type": "bytes", "address": "0x00001002", "bytes": "03"},
                ]
            ),
            "c2.json": _change_doc([_symbol_entry("Ghost", 0x1003, (0x09,))]),
            "c3.json": _change_doc(
                [{"type": "bytes", "address": "0x00002000", "bytes": "AA"}]
            ),
        },
    )
    flow = Flow(
        name="census",
        blocks=[
            SourceBlock("prg.s19", a2l_ref="cal.a2l"),
            PatchBlock("c1.json"),
            PatchBlock("c2.json"),
            PatchBlock("c3.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    out_path = result.written_paths[0]
    comparison = compare_images(
        ImageSource(
            SOURCE_EXTERNAL, raw_path=str(project / "prg.s19"), label="prg.s19"
        ),
        ImageSource(SOURCE_EXTERNAL, raw_path=str(out_path), label="out.s19"),
    )
    assert not comparison.refused
    return project, result, comparison


def _census_maps(project: Path, result) -> tuple[dict[int, int], dict[int, int]]:
    return (
        _reload_s19(project / "prg.s19"),
        _reload_s19(result.written_paths[0]),
    )


def test_tc717_flow_produced_image_diff_references_all_flow_changes(
    tmp_path: Path,
) -> None:
    """TC-717 (LLR-143.2, the law): the A2B diff over the flow's output
    references 100% of the flow's changes — each differing run attributed to
    the entries that produced it, the no-diff entry explicit, the skipped
    record and the named refusal listed as such (0 unreferenced, 0 dropped)."""
    project, result, comparison = _census_flow_result(tmp_path)
    attribution = flow_change_attribution(result)
    assert len(attribution.records) == 3, "Speed + no-op + skipped-outside"
    assert len(attribution.refusals) == 1
    mem_a, mem_b = _census_maps(project, result)
    md = generate_diff_report(
        comparison,
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=project,
        flow_changes=attribution,
    )
    assert md.written
    text = md.path.read_text(encoding="utf-8")
    assert "## Flow change attribution" in text
    section = text.split("## Flow change attribution")[1]
    # the census predicate over the SHIPPED document: 100% referenced.
    assert flow_change_census_complete(attribution, section.splitlines())
    # the differing run names its producing entry (and only that entry).
    speed_row = next(ln for ln in section.splitlines() if "| Speed |" in ln)
    assert "0x00001000–0x00001002" in speed_row
    noop_row = next(ln for ln in section.splitlines() if "| 0x00001002 |" in ln)
    assert "(no diff)" in noop_row, "an applied entry with no diff is explicit"
    assert "0x00001000–0x00001002" not in noop_row, (
        "exactness: the run names an entry IFF its range produced run bytes"
    )
    skipped_row = next(ln for ln in section.splitlines() if "| 0x00002000 |" in ln)
    assert "skipped-outside" in skipped_row, "a skipped record is listed as such"
    refusal_line = next(
        ln for ln in section.splitlines() if ln.startswith("- refused:")
    )
    assert "c2.json" in refusal_line
    assert "CHG-SYMBOL-UNRESOLVED" in refusal_line
    assert "'Ghost'" in refusal_line, "the named refusal names the symbol"
    assert ": no flow change" not in section, (
        "the single differing run is attributed — no orphan run"
    )


def test_tc717_non_flow_b_renders_the_shipped_report_unchanged(
    tmp_path: Path,
) -> None:
    """TC-717 (LLR-143.2 boundary): when B is NOT a flow product (no
    flow_changes passed) the diff renders byte-identically in both formats —
    no attribution section at all."""
    from datetime import datetime, timezone

    project, result, comparison = _census_flow_result(tmp_path)
    mem_a, mem_b = _census_maps(project, result)
    clock = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
    plain = generate_diff_report(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=project, now_fn=lambda: clock,
    )
    explicit_none = generate_diff_report(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=project, now_fn=lambda: clock, flow_changes=None,
    )
    text = plain.path.read_text(encoding="utf-8")
    assert "## Flow change attribution" not in text
    assert "## Runs" in text and "## Hex windows" in text, (
        "the shipped sections are untouched"
    )
    assert plain.path.read_bytes() == explicit_none.path.read_bytes(), (
        "flow_changes=None is byte-identical to the shipped call shape"
    )
    html = generate_diff_report_html(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=project, now_fn=lambda: clock,
    )
    assert "Flow change attribution" not in html.path.read_text(encoding="utf-8")


def test_tc717_html_flow_change_attribution_pairs_the_markdown(
    tmp_path: Path,
) -> None:
    """TC-717 (LLR-143.2, the HTML twin): the self-contained HTML report
    carries the same census — every change referenced, the refusal named."""
    project, result, comparison = _census_flow_result(tmp_path)
    attribution = flow_change_attribution(result)
    mem_a, mem_b = _census_maps(project, result)
    html = generate_diff_report_html(
        comparison,
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=project,
        flow_changes=attribution,
    )
    assert html.written
    text = html.path.read_text(encoding="utf-8")
    assert "<h2>Flow change attribution</h2>" in text
    assert "Speed" in text and "0x00001002" in text and "0x00002000" in text
    assert "CHG-SYMBOL-UNRESOLVED" in text and "Ghost" in text


# ===========================================================================
# TC-718 — the change-5 negative-control battery: the 5c arm
# ===========================================================================


def test_tc718_battery_diff_block_omitting_one_flow_change_red(
    tmp_path: Path,
) -> None:
    """TC-718 (battery 5c arm): the reference-all law is a live guard — drop
    ONE flow change from the block's enumeration and the census predicate
    goes RED; the shipped generator's section passes the same predicate."""
    project, result, comparison = _census_flow_result(tmp_path)
    attribution = flow_change_attribution(result)
    full = _flow_change_attribution_lines(attribution, comparison.runs)
    assert flow_change_census_complete(attribution, full)
    dropped = FlowChangeAttribution(
        records=attribution.records[:-1], refusals=attribution.refusals
    )
    incomplete = _flow_change_attribution_lines(dropped, comparison.runs)
    assert not flow_change_census_complete(attribution, incomplete), (
        "a block omitting one flow change must fail the census"
    )
    # the hardest omission: a no-diff entry whose address recurs inside the
    # producing run's range cell — the predicate pins the row's OWN cells.
    noop = next(r for r in attribution.records if r.address_start == 0x1002)
    rest = tuple(r for r in attribution.records if r is not noop)
    masked = _flow_change_attribution_lines(
        FlowChangeAttribution(records=rest, refusals=attribution.refusals),
        comparison.runs,
    )
    assert not flow_change_census_complete(attribution, masked), (
        "even a change whose address recurs in a run-range cell must not "
        "vanish from the census"
    )
    mem_a, mem_b = _census_maps(project, result)
    md = generate_diff_report(
        comparison,
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=project,
        flow_changes=attribution,
    )
    section = md.path.read_text(encoding="utf-8").split(
        "## Flow change attribution"
    )[1]
    assert flow_change_census_complete(attribution, section.splitlines())
