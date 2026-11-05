"""Batch-101 Inc 8 (G1) — the CRC model with reverse, and the CRC config reasons.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-8/01-requirements.md``
rows R-CRC-ENGINE-001.1, R-CRC-ENGINE-002.2, R-CRC-DESIGNER-001.1 (the cited
oracle), R-CRC-CONFIG-001.10, .11, .16, .17 — one test per case of
``inc-8/02-test-cases.md``. The Designer engine (``crc_kernel.crc_stream``) is
the model oracle of every engine row; the published catalogue check values pin
it. The Operations-dialog cases drive the shipped screen through keys with a
Textual pilot. No source file is edited here.

Traceability (E4): test names start ``test_r_<row id>_…`` so the registry
binds them; no AT-/TC- tokens.
"""
from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

import pytest
from textual.widgets import Input, ListView, Static, TextArea

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.operations.crc import check_regions, crc32_stream, write_crc_image
from s19_app.tui.operations.crc_config import parse_crc_config
from s19_app.tui.operations.crc_designer_model import emit_template, seed_template
from s19_app.tui.operations.crc_kernel import crc_stream
from s19_app.tui.operations.model import OperationInput
from s19_app.tui.screens import OperationsScreen
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    FLOW_STATUS_ISSUES,
    CrcBlock,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_s19

# --- shared fixtures of inc-8/02-test-cases.md -------------------------------
KAT = b"123456789"
_POLY = 0x04C11DB7

# Config K: the D13-20 case (reverse true, init not bit-symmetric).
_CONFIG_K = {
    "polynomial": "0x04C11DB7",
    "init": "0x12345678",
    "reverse": True,
    "final_xor": "0xFFFFFFFF",
    "regions": [{"start": "0x1000", "end": "0x1009", "output_address": "0x1010"}],
}
# Config V: valid base for the reason cases (init bit-symmetric on purpose, so
# the reason tests never ride the D13-20 value change).
_CONFIG_V = {
    "polynomial": "0x04C11DB7",
    "init": "0xFFFFFFFF",
    "reverse": True,
    "final_xor": "0xFFFFFFFF",
    "regions": [{"start": "0x0", "end": "0x4", "output_address": "0x10"}],
}
_CONFIG_VG_GROUP = {
    "regions": [{"start": "0x20", "end": "0x24"}],
    "output_address": "0x30",
}

# Image K: the KAT message at 0x1000..0x1008.
_IMAGE_K = {0x1000 + i: byte for i, byte in enumerate(KAT)}
_RANGES_K = [(0x1000, 0x1009)]


def _kat_image_s19() -> str:
    """Image K emitted by the production emitter (one contiguous range)."""
    from s19_app.tui.changes.io import emit_s19_from_mem_map

    return emit_s19_from_mem_map(dict(_IMAGE_K), list(_RANGES_K))


def _op_input() -> OperationInput:
    return OperationInput(
        mem_map=dict(_IMAGE_K),
        ranges=list(_RANGES_K),
        input_path=None,
        variant_id=None,
        file_type="s19",
    )


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        target = project_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return project_dir


def _reload_mem(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


# ---------------------------------------------------------------------------
# R-CRC-ENGINE-001.1 — the operation engine takes init as given when reverse
# ---------------------------------------------------------------------------


def test_r_crc_engine_001_1_1_reverse_takes_init_as_given() -> None:
    """KAT, poly 0x04C11DB7, init 0x12345678, reverse true, xorout 0xFFFFFFFF
    → 0x0F8B7431 (base seeds the register with the reflected init →
    0x18026B2A)."""
    assert (
        crc32_stream(
            KAT, polynomial=_POLY, init=0x12345678, reverse=True, final_xor=0xFFFFFFFF
        )
        == 0x0F8B7431
    )


def test_r_crc_engine_001_1_2_bit_reversed_inits_stay_distinct() -> None:
    """Two inits that are each other's bit reversal give different CRCs with
    reverse true (base swaps the two values)."""
    first = crc32_stream(
        KAT, polynomial=_POLY, init=0x00000001, reverse=True, final_xor=0x00000000
    )
    second = crc32_stream(
        KAT, polynomial=_POLY, init=0x80000000, reverse=True, final_xor=0x00000000
    )
    assert (first, second) == (0x334D3950, 0x3A8639CB)


@pytest.mark.parametrize(
    "name,reverse,final_xor,expected",
    [
        ("MPEG-2", False, 0x00000000, 0x0376E6E7),  # case /3
        ("JAMCRC", True, 0x00000000, 0x340BC6D9),  # case /4
    ],
    ids=["MPEG-2", "JAMCRC"],
)
def test_r_crc_engine_001_1_catalogue_32_bit_checks(
    name: str, reverse: bool, final_xor: int, expected: int
) -> None:
    """The catalogue check values with a bit-symmetric init hold either way —
    the D13-20 fix must not move them."""
    assert (
        crc32_stream(
            KAT,
            polynomial=_POLY,
            init=0xFFFFFFFF,
            reverse=reverse,
            final_xor=final_xor,
        )
        == expected
    )


def test_r_crc_engine_001_1_5_operations_check_gives_model_value() -> None:
    """Config K over image K through ``check_regions`` (the call the Operations
    check makes) → the one region's computed CRC is 0x0F8B7431."""
    config, errors = parse_crc_config(json.dumps(_CONFIG_K))
    assert config is not None and errors == [], errors
    regions = check_regions(_op_input(), config)
    assert len(regions) == 1
    assert regions[0].computed_crc == 0x0F8B7431


def test_r_crc_engine_001_1_6_operations_write_stores_model_value(tmp_path: Path) -> None:
    """The Operations write route ``write_crc_image`` writes the model value:
    the written file holds 31 74 8B 0F at 0x1010..0x1013."""
    config, errors = parse_crc_config(json.dumps(_CONFIG_K))
    assert config is not None and errors == [], errors
    written = write_crc_image(_op_input(), config, workarea_base=tmp_path)
    assert written.findings == [] and written.written_path is not None
    mem = _reload_mem(written.written_path)
    assert [mem[0x1010 + i] for i in range(4)] == [0x31, 0x74, 0x8B, 0x0F]


def test_r_crc_engine_001_1_7_flow_crc_block_injects_model_value(tmp_path: Path) -> None:
    """Flow LOAD k.s19 → CRC templates/k.json (Config K) → WRITE-OUT: the CRC
    block injects 1 region and out.s19 holds 31 74 8B 0F at 0x1010..0x1013.

    E4 integration seam SR-1: the flow has no PATCH, so R-FLOW-CRC.7 (canon,
    unchanged) ends the CRC block `notices` with its one CRC-before-PATCH
    finding and the run `completed-with-issues`; the case's "CRC block ok"
    reads as "the block injects", the value is the D13-20 oracle."""
    project = _make_project(
        tmp_path, {"k.s19": _kat_image_s19(), "templates/k.json": json.dumps(_CONFIG_K)}
    )
    flow = Flow(
        name="crc",
        blocks=[
            SourceBlock("k.s19"),
            CrcBlock("templates/k.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_ISSUES
    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK,
        BLOCK_STATUS_NOTICES,
        BLOCK_STATUS_OK,
    ]
    crc_block = result.block_results[1]
    assert crc_block.summary == "injected 1 CRC region"
    assert [f.message for f in crc_block.findings] == [
        "CRC before PATCH: the image is finalized before any patch is applied"
    ]
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1010 + i] for i in range(4)] == [0x31, 0x74, 0x8B, 0x0F]


# ---------------------------------------------------------------------------
# R-CRC-ENGINE-002.2 — the operation and the Designer agree
# ---------------------------------------------------------------------------

_ENGINE_GRID_INITS = (0x00000000, 0xFFFFFFFF, 0x12345678, 0x00000001, 0x80000000, 0xB2AAB2AA)


def test_r_crc_engine_002_2_1_operation_equals_designer_grid() -> None:
    """24/24 parameter sets: ``crc32_stream`` == the Designer engine at width
    32 with refin=refout=reverse (base: the 4 non-bit-symmetric inits with
    reverse true differ — 8/24)."""
    for init in _ENGINE_GRID_INITS:
        for reverse in (True, False):
            for final_xor in (0x00000000, 0xFFFFFFFF):
                operation = crc32_stream(
                    KAT, polynomial=_POLY, init=init, reverse=reverse, final_xor=final_xor
                )
                designer = crc_stream(
                    KAT,
                    width=32,
                    poly=_POLY,
                    init=init,
                    refin=reverse,
                    refout=reverse,
                    xorout=final_xor,
                )
                assert operation == designer, (
                    f"init {init:#010x} reverse {reverse} xorout {final_xor:#010x}: "
                    f"{operation:#010x} != {designer:#010x}"
                )


def test_r_crc_engine_002_2_2_operation_equals_designer_random() -> None:
    """50/50 random sets (seed 7): random 0..1023 bytes, random odd poly,
    init, final_xor, reverse — the two engines agree."""
    rng = random.Random(7)
    for _ in range(50):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1024)))
        poly = rng.getrandbits(32) | 1
        init = rng.getrandbits(32)
        final_xor = rng.getrandbits(32)
        reverse = rng.choice((True, False))
        operation = crc32_stream(
            data, polynomial=poly, init=init, reverse=reverse, final_xor=final_xor
        )
        designer = crc_stream(
            data,
            width=32,
            poly=poly,
            init=init,
            refin=reverse,
            refout=reverse,
            xorout=final_xor,
        )
        assert operation == designer


# ---------------------------------------------------------------------------
# R-CRC-DESIGNER-001.1 — the catalogue pins the Designer engine (the oracle)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,width,poly,init,refin,refout,xorout,expected",
    [
        ("ARC", 16, 0x8005, 0x0000, True, True, 0x0000, 0xBB3D),
        ("MODBUS", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
        ("RIELLO", 16, 0x1021, 0xB2AA, True, True, 0x0000, 0x63D0),
        ("TMS37157", 16, 0x1021, 0x89EC, True, True, 0x0000, 0x26B1),
        ("ISO-HDLC", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926),
        ("MPEG-2", 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000, 0x0376E6E7),
    ],
    ids=["ARC", "MODBUS", "RIELLO", "TMS37157", "ISO-HDLC", "MPEG-2"],
)
def test_r_crc_designer_001_1_catalogue_checks(
    name: str, width: int, poly: int, init: int, refin: bool, refout: bool,
    xorout: int, expected: int,
) -> None:
    """The Designer engine gives the published catalogue check over the KAT
    message (unchanged by Inc 8 — the oracle of the D13-20 rows)."""
    assert (
        crc_stream(
            KAT, width=width, poly=poly, init=init, refin=refin, refout=refout, xorout=xorout
        )
        == expected
    )


# ---------------------------------------------------------------------------
# R-CRC-CONFIG-001.10 — a missing required field names the field
# ---------------------------------------------------------------------------


def _without(mapping: dict, key: str) -> dict:
    clone = dict(mapping)
    del clone[key]
    return clone


def _missing_field_cases() -> list[tuple[str, dict, str]]:
    region_no_start = [_without(_CONFIG_V["regions"][0], "start")]
    group_no_output = [_without(_CONFIG_VG_GROUP, "output_address")]
    group_no_regions = [_without(_CONFIG_VG_GROUP, "regions")]
    span_no_end = [
        {"regions": [_without(_CONFIG_VG_GROUP["regions"][0], "end")], "output_address": "0x30"}
    ]
    region_no_end = [_without(_CONFIG_V["regions"][0], "end")]
    region_no_output = [_without(_CONFIG_V["regions"][0], "output_address")]
    span_no_start = [
        {"regions": [_without(_CONFIG_VG_GROUP["regions"][0], "start")], "output_address": "0x30"}
    ]
    vg = lambda regions, groups: {**_CONFIG_V, "groups": groups}  # noqa: E731
    return [
        ("reverse", _without(_CONFIG_V, "reverse"), "reverse"),
        ("polynomial", _without(_CONFIG_V, "polynomial"), "polynomial"),
        ("init", _without(_CONFIG_V, "init"), "init"),
        ("final_xor", _without(_CONFIG_V, "final_xor"), "final_xor"),
        ("region-start", {**_CONFIG_V, "regions": region_no_start}, "start"),
        (
            "group-output_address",
            vg(None, group_no_output),
            "output_address",
        ),
        ("group-regions", vg(None, group_no_regions), "regions"),
        ("span-end", vg(None, span_no_end), "end"),
        # E5 C-6: the remaining required fields of the definition
        ("region-end", {**_CONFIG_V, "regions": region_no_end}, "end"),
        (
            "region-output_address",
            {**_CONFIG_V, "regions": region_no_output},
            "output_address",
        ),
        ("span-start", vg(None, span_no_start), "start"),
    ]


@pytest.mark.parametrize(
    "case,config,field", _missing_field_cases(),
    ids=[case for case, _, _ in _missing_field_cases()],
)
def test_r_crc_config_001_10_missing_field_is_named(case: str, config: dict, field: str) -> None:
    """Each missing required field gives exactly
    ``CRC config is structurally invalid: field '<name>' is missing``."""
    parsed, errors = parse_crc_config(json.dumps(config))
    assert parsed is None
    assert errors == [
        f"CRC config is structurally invalid: field '{field}' is missing"
    ], errors


# ---------------------------------------------------------------------------
# R-CRC-CONFIG-001.11 — a non-number field names the field and the value
# ---------------------------------------------------------------------------


def _non_number_cases() -> list[tuple[str, dict, str, str]]:
    def with_field(container: dict, key: str, value) -> dict:
        clone = json.loads(json.dumps(container))
        clone[key] = value
        return clone

    def region_with(key: str, value) -> dict:
        clone = json.loads(json.dumps(_CONFIG_V))
        clone["regions"][0][key] = value
        return clone

    def group_with(key: str, value) -> dict:
        clone = json.loads(json.dumps(_CONFIG_V))
        clone["groups"] = [json.loads(json.dumps(_CONFIG_VG_GROUP))]
        clone["groups"][0][key] = value
        return clone

    def span_with(key: str, value) -> dict:
        clone = json.loads(json.dumps(_CONFIG_V))
        clone["groups"] = [json.loads(json.dumps(_CONFIG_VG_GROUP))]
        clone["groups"][0]["regions"][0][key] = value
        return clone

    return [
        ("init-zz", with_field(_CONFIG_V, "init", "zz"), "init", '"zz"'),
        ("init-true", with_field(_CONFIG_V, "init", True), "init", "true"),
        ("polynomial-1.5", with_field(_CONFIG_V, "polynomial", 1.5), "polynomial", "1.5"),
        ("final_xor-null", with_field(_CONFIG_V, "final_xor", None), "final_xor", "null"),
        ("region-end", region_with("end", "0xQ"), "end", '"0xQ"'),
        ("span-start", span_with("start", "x"), "start", '"x"'),
        # E5 C-6: the remaining number fields of the definition
        ("region-start", region_with("start", "0xG"), "start", '"0xG"'),
        ("region-output_address", region_with("output_address", [1]), "output_address", "[1]"),
        ("group-output_address", group_with("output_address", {"a": 1}), "output_address", '{"a": 1}'),
        ("span-end", span_with("end", False), "end", "false"),
    ]


@pytest.mark.parametrize(
    "case,config,field,value", _non_number_cases(),
    ids=[case for case, _, _, _ in _non_number_cases()],
)
def test_r_crc_config_001_11_non_number_is_named(
    case: str, config: dict, field: str, value: str
) -> None:
    """Each non-number value gives exactly
    ``CRC config is structurally invalid: field '<name>' is not a number: <value>``
    with the value as JSON text."""
    parsed, errors = parse_crc_config(json.dumps(config))
    assert parsed is None
    assert errors == [
        f"CRC config is structurally invalid: field '{field}' is not a number: {value}"
    ], errors


def test_r_crc_config_001_11_7_value_is_clipped() -> None:
    """[S-1] A huge value is clipped: 64 characters of the JSON text + …."""
    prefix = "CRC config is structurally invalid: field '{}' is not a number: "
    # (a) a 1 000 000-character non-hex string [N-1: `z`, not a hex digit]
    huge_string = json.loads(json.dumps(_CONFIG_V))
    huge_string["init"] = "z" * 1_000_000
    parsed, errors = parse_crc_config(json.dumps(huge_string))
    assert parsed is None
    expected_a = prefix.format("init") + '"' + "z" * 63 + "…"
    assert errors == [expected_a], errors
    # (b) a 10 000-element list
    huge_list = json.loads(json.dumps(_CONFIG_V))
    huge_list["polynomial"] = [0] * 10_000
    parsed, errors = parse_crc_config(json.dumps(huge_list))
    assert parsed is None
    expected_b = prefix.format("polynomial") + json.dumps([0] * 10_000)[:64] + "…"
    assert errors == [expected_b], errors
    # each reason is at most the fixed text + 64 + 1 characters
    for reason in (expected_a, expected_b):
        field_part = reason.split("is not a number: ")[0]
        assert len(reason) <= len(field_part) + len("is not a number: ") + 65


_NESTING_REASON = "CRC config is not valid JSON: nesting too deep"
#: The R-CRC-CONFIG-001.11 reason for an `init` that is a list nested deeper
#: than 64 levels: its JSON text starts with 64 `[`, so <value> is exactly
#: 64 `[` then the ellipsis.
_DEEP_INIT_REASON = (
    "CRC config is structurally invalid: field 'init' is not a number: "
    + "[" * 64
    + "…"
)


def _deep_init_text(depth: int) -> str:
    """Config V with `init` = a list nested `depth` levels deep."""
    text = json.dumps(_CONFIG_V)
    plain = '"init": "0xFFFFFFFF"'
    assert text.count(plain) == 1
    return text.replace(plain, '"init": ' + "[" * depth + "]" * depth)


def test_r_crc_config_001_11_9_deep_value_gives_the_reason_not_a_raise() -> None:
    """E5 F1: a number field holding a list that the JSON reader still
    accepts, nested just under its limit, gives the R-CRC-CONFIG-001.11
    reason — the echo of the value never recurses past the reader.

    The reader's limit depends on the stack depth of the caller, so every
    depth of a band around it is tried: each one gives exactly one of the two
    reasons, and the band holds both (the number-field path is reached at
    its deepest)."""
    seen = set()
    for depth in range(800, 1001):
        parsed, errors = parse_crc_config(_deep_init_text(depth))
        assert parsed is None, depth
        assert errors in ([_DEEP_INIT_REASON], [_NESTING_REASON]), (depth, errors)
        seen.add(errors[0])
    assert seen == {_DEEP_INIT_REASON, _NESTING_REASON}, seen


# ---------------------------------------------------------------------------
# R-CRC-CONFIG-001.16 — a CRC Designer template is named as such
# ---------------------------------------------------------------------------

_TEMPLATE_REASON = (
    "CRC config is structurally invalid: a CRC Designer template is not a "
    "CRC config - it has no regions or groups"
)


@pytest.mark.parametrize(
    "case,text",
    [
        ("saved", None),  # the Designer's own Save output, built below
        (
            "width16",
            json.dumps(
                {
                    "name": "T16",
                    "algorithm": {
                        "width": 16,
                        "poly": "0x1021",
                        "init": "0xFFFF",
                        "refin": False,
                        "refout": False,
                        "xorout": "0x0000",
                        "check": None,
                    },
                }
            ),
        ),
        ("algorithm-not-object", json.dumps({"algorithm": 5})),
    ],
    ids=["saved", "width16", "algorithm-not-object"],
)
def test_r_crc_config_001_16_designer_template_is_named(case: str, text: str | None) -> None:
    """A Designer-template-shaped object gives exactly the template reason."""
    if text is None:
        text = emit_template(seed_template())
        assert '"algorithm"' in text and "polynomial" not in text
    parsed, errors = parse_crc_config(text)
    assert parsed is None
    assert errors == [_TEMPLATE_REASON], errors


def test_r_crc_config_001_16_4_config_with_algorithm_key_still_parses() -> None:
    """An object with BOTH `algorithm` and `polynomial` is read as a CRC
    config (the shape, not the key, is the test)."""
    config = {**_CONFIG_V, "algorithm": {"width": 32}}
    parsed, errors = parse_crc_config(json.dumps(config))
    assert errors == [], errors
    assert parsed is not None and parsed.polynomial == 0x04C11DB7


# ---------------------------------------------------------------------------
# R-CRC-CONFIG-001.17 — nesting too deep is a reason, not a raise
# ---------------------------------------------------------------------------


def test_r_crc_config_001_17_1_deep_nesting_is_a_reason() -> None:
    """``parse_crc_config('[' * 100000)`` returns (None, [the one reason])."""
    parsed, errors = parse_crc_config("[" * 100000)
    assert parsed is None
    assert errors == ["CRC config is not valid JSON: nesting too deep"], errors


# ---------------------------------------------------------------------------
# Operations-dialog cases (black box, through keys)
# ---------------------------------------------------------------------------


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain + worker run."""
    for _ in range(count):
        await pilot.pause()


async def _load_file(app: S19TuiApp, pilot, path: Path) -> None:
    app.load_from_path(path)
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


async def _focus_by_tab(app: S19TuiApp, pilot, widget_id: str, limit: int = 20) -> None:
    """Move the focus to ``#widget_id`` with the tab key only."""
    for _ in range(limit):
        if app.focused is not None and app.focused.id == widget_id:
            return
        await pilot.press("tab")
        await pilot.pause()
    assert app.focused is not None and app.focused.id == widget_id, (app.focused, widget_id)


async def _open_crc_screen_by_keys(app: S19TuiApp, pilot) -> OperationsScreen:
    """Press `x` (the app's Operations binding); the dialog opens with the
    focus on the list, its first row (crc, registry order) highlighted."""
    await pilot.press("x")
    await _flush(pilot)
    screen = app.screen
    assert isinstance(screen, OperationsScreen), screen
    assert screen.query_one("#operations_list", ListView).index == 0
    assert screen.options[0][0] == "crc", screen.options
    return screen


async def _load_config_by_keys(app: S19TuiApp, pilot, screen: OperationsScreen, path: str) -> str:
    """Type ``path`` into the empty config path field, then Load config by
    `enter`; return the editor text."""
    await _focus_by_tab(app, pilot, "operation_config_path")
    assert screen.query_one("#operation_config_path", Input).value == ""
    await pilot.press(*path)
    await _focus_by_tab(app, pilot, "operation_config_load")
    await pilot.press("enter")
    await _flush(pilot)
    return screen.query_one("#operation_config", TextArea).text


async def _execute_by_keys(app: S19TuiApp, pilot, screen: OperationsScreen) -> str:
    """Execute by `enter` on the Execute button; return the result status."""
    await _focus_by_tab(app, pilot, "operations_execute")
    await pilot.press("enter")
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)
    return str(screen.query_one("#operation_result_status", Static).content)


def _drive_crc(tmp_path: Path, config_text: str) -> tuple[str, str, str]:
    """Load image K as the primary, then by keys only: `x` opens the
    Operations dialog on the crc row, the config file's path is typed and
    loaded into the editor (Load config, `enter`), Execute (`enter`); then a
    later key (`tab`) — return (status, hex, the widget focused after it).

    E5 C-7: the editor is filled through the Load config route because a
    typed or pasted text cannot carry these inputs (the paste cap is 64 KiB;
    100 000 brackets typed one by one would take minutes)."""
    (tmp_path / "config.json").write_text(config_text, encoding="utf-8")

    async def _drive() -> tuple[str, str, str]:
        s19_path = tmp_path / "k.s19"
        s19_path.write_text(_kat_image_s19(), encoding="utf-8")
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen_by_keys(app, pilot)
            loaded = await _load_config_by_keys(app, pilot, screen, "config.json")
            assert loaded == config_text
            status = await _execute_by_keys(app, pilot, screen)
            hex_content = screen.query_one("#operation_result_hex", Static).content
            hex_text = getattr(hex_content, "plain", str(hex_content))
            # the app keeps running: a later key still acts
            await pilot.press("tab")
            await _flush(pilot)
            focused = app.focused.id if app.focused is not None else ""
            return status, hex_text, focused

    return asyncio.run(_drive())


def test_r_crc_config_001_11_8_markup_value_shown_plain(tmp_path: Path) -> None:
    """[S-7] Through keys: a markup-looking value is shown as plain text —
    the result area carries NO_CONFIG_TEXT then the exact reason, no markup
    error and no hex view."""
    config = json.loads(json.dumps(_CONFIG_V))
    config["init"] = "[/]"
    status, hex_text, _ = _drive_crc(tmp_path, json.dumps(config))
    expected = (
        f"{OperationsScreen.NO_CONFIG_TEXT}\n"
        'CRC config is structurally invalid: field \'init\' is not a number: "[/]"'
    )
    assert expected in status, status
    assert status == expected, status
    assert "markup" not in status.lower()
    assert hex_text == "", repr(hex_text)


def test_r_crc_config_001_16_5_operations_dialog_names_template(tmp_path: Path) -> None:
    """Through keys: Load config with the Designer's saved file path, Execute
    — the result area names the template."""
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "demo-crc32.crc.json").write_text(
        emit_template(seed_template()), encoding="utf-8"
    )

    async def _drive() -> tuple[str, str, str]:
        s19_path = tmp_path / "k.s19"
        s19_path.write_text(_kat_image_s19(), encoding="utf-8")
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen_by_keys(app, pilot)
            loaded = await _load_config_by_keys(
                app, pilot, screen, "templates/demo-crc32.crc.json"
            )
            status = await _execute_by_keys(app, pilot, screen)
            hex_content = screen.query_one("#operation_result_hex", Static).content
            hex_text = getattr(hex_content, "plain", str(hex_content))
            return loaded, status, hex_text

    loaded, status, hex_text = asyncio.run(_drive())
    assert "polynomial" not in loaded and '"algorithm"' in loaded
    expected = f"{OperationsScreen.NO_CONFIG_TEXT}\n{_TEMPLATE_REASON}"
    assert expected in status, status
    assert status == expected, status
    assert hex_text == "", repr(hex_text)


def test_r_crc_config_001_17_2_operations_execute_survives_deep_nesting(
    tmp_path: Path,
) -> None:
    """[S-6] Through keys: the editor text nests too deep; Execute shows the
    reason and the app keeps running."""
    status, hex_text, focused_after = _drive_crc(tmp_path, "[" * 100000)
    expected = (
        f"{OperationsScreen.NO_CONFIG_TEXT}\n"
        "CRC config is not valid JSON: nesting too deep"
    )
    assert expected in status, status
    assert status == expected, status
    assert hex_text == "", repr(hex_text)
    # E5 C-7: the later key acted - `tab` moved the focus from Execute past
    # the disabled Write CRC to Close
    assert focused_after == "operations_close", focused_after


def test_r_crc_config_001_11_10_operations_execute_survives_deep_value(
    tmp_path: Path,
) -> None:
    """E5 F1, through keys: a config whose `init` nests just under the JSON
    reader's limit is loaded and executed in the Operations dialog. The app
    stays up and shows the malformed-config reason for every depth tried.

    The reader's limit inside the dialog depends on the handler's stack, so
    the test searches it by bisection between a depth the reader accepts and
    one it refuses: the search ends on the first depth the number-field path
    does not answer, which on the defect is the first depth whose echo
    raises (the app exits there)."""
    config_path = tmp_path / "deep.json"
    field_status = f"{OperationsScreen.NO_CONFIG_TEXT}\n{_DEEP_INIT_REASON}"
    nesting_status = f"{OperationsScreen.NO_CONFIG_TEXT}\n{_NESTING_REASON}"

    async def _drive() -> dict[int, str]:
        s19_path = tmp_path / "k.s19"
        s19_path.write_text(_kat_image_s19(), encoding="utf-8")
        app = S19TuiApp(base_dir=tmp_path)
        statuses: dict[int, str] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen_by_keys(app, pilot)
            await _focus_by_tab(app, pilot, "operation_config_path")
            await pilot.press(*config_path.name)

            async def probe(depth: int) -> str:
                text = _deep_init_text(depth)
                config_path.write_text(text, encoding="utf-8")
                await _focus_by_tab(app, pilot, "operation_config_load")
                await pilot.press("enter")
                await _flush(pilot)
                assert screen.query_one("#operation_config", TextArea).text == text
                statuses[depth] = await _execute_by_keys(app, pilot, screen)
                return statuses[depth]

            low, high = 500, 1000
            assert await probe(low) == field_status
            assert await probe(high) == nesting_status
            while high - low > 1:
                middle = (low + high) // 2
                if await probe(middle) == field_status:
                    low = middle
                else:
                    high = middle
            assert app.is_running
        return statuses

    statuses = asyncio.run(_drive())
    assert set(statuses.values()) == {field_status, nesting_status}, statuses
    deepest = max(depth for depth, status in statuses.items() if status == field_status)
    assert statuses[deepest + 1] == nesting_status, statuses
