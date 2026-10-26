"""Batch-99 HLR-160: exports stay inside their destination and invent no byte.

TC-B99-28 (LLR-160.1) — one sanitiser builds every export name: ASCII
``[A-Za-z0-9_-]`` only, Windows reserved device names defused (superscript
digits included), the segment part capped at 100, the stem clipped so the
final basename (``_<N>`` and extension included) stays <= 200, and an empty
result becoming ``segment_<index>``.

TC-B99-29 (LLR-160.2) — containment anchored to the work-area root: a
junction destination is refused, a link/reparse point at a final name is
refused (its target untouched), and the whole hostile set of HLR-160 writes
nothing outside the destination. The refusal renders the segment name
literally (UX-C10): ``[red]x[/red]`` survives as text, zero markup spans.

TC-B99-30 (LLR-160.3) — a MAC-only session exports header-only S19/HEX: the
writer takes its bytes from the image's DECLARED ranges, never from MAC
placeholder entries.

TC-B99-31 (LLR-160.4) — a second export with changed bytes takes the next
free ``_<N>``; a BIN and its ``.addr`` sidecar are placed as ONE group (B99-
I2a): both names claimed before either is written (PQ-2), reuse only when
every member is identical, and a part-way failure rolls back every own
claim.

TC-B99-41 (LLR-160.5) — the plan-time pass: case-folded collisions
(``SegA``/``sega``) refuse the whole export before any byte, one refused
name refuses the set, and an over-long full path refuses at plan time.

AT-B99-11 (US-149) — black-box Textual pilot through the Split / Join /
Export window (SegmentSplitView) export action: ONE joined node drives
all three clauses of HLR-160's outcome in a single pilot session — a
hostile A2L ``MEMORY_SEGMENT`` name lands inside the destination under a
sanitised name, a MAC-only export carries no data record, and a second
export after a patch takes ``_<N>`` while the first file stays intact.
Two TC sub-arms ride the same shipped surface: TC-B99-41's part-way
failure status (F3) and TC-B99-29's junctioned project home refusal (F6).
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.segment_split_view import SegRow
from s19_app.tui.screens import LoadProjectScreen
from tests.support.independent_reader import read_hex, read_s19

ROOT = Path(__file__).resolve().parents[1]
CASE00 = ROOT / "examples" / "case_00_public"
PRG_S19 = CASE00 / "prg.s19"
DEMO_A2L = CASE00 / "ASAP2_Demo_V161.a2l"
FIRMWARE_MAC = ROOT / "examples" / "case_01_basic_valid" / "firmware.mac"


def _home(tmp_path: Path, name: str = "splits") -> Path:
    """A work-area-contained export destination."""
    return tmp_path / ".s19tool" / "workarea" / name


def _island_map() -> Dict[int, int]:
    return {0x1000 + i: (0xA0 + i) & 0xFF for i in range(8)}


def _snapshot(root: Path) -> Set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


def _write_hostile_segment_a2l(dest_dir: Path, new_name: str) -> Path:
    """The demo A2L with its first ``MEMORY_SEGMENT`` renamed (AT-B99-11)."""
    lines = DEMO_A2L.read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip().startswith("/begin MEMORY_SEGMENT "):
            old = line.split()[2]
            lines[index] = line.replace(old, new_name, 1)
            break
    else:  # pragma: no cover - the demo file always holds one
        raise AssertionError("no MEMORY_SEGMENT in the demo A2L")
    path = dest_dir / "hostile.a2l"
    path.write_text("".join(lines), encoding="utf-8")
    return path


#: HLR-160's hostile set and the exact sanitiser output each must produce.
HOSTILE_CASES: List[Tuple[str, str]] = [
    ("../", "___"),
    ("..\\", "___"),
    ("/abs/posix/path", "_abs_posix_path"),
    ("C:\\win\\abs", "C__win_abs"),
    ("C:x", "C_x"),
    ("\\\\host\\share", "__host_share"),
    ("seg:stream", "seg_stream"),
    ("seg::$DATA", "seg___DATA"),
    ('<>|?*"', "______"),
    ("seg\x00name", "seg_name"),
    ("seg\u202ename", "seg_name"),
    ("CON", "_CON"),
    ("NUL", "_NUL"),
    ("AUX", "_AUX"),
    ("PRN", "_PRN"),
    ("COM0", "_COM0"),
    ("COM1", "_COM1"),
    ("COM9", "_COM9"),
    ("LPT0", "_LPT0"),
    ("LPT9", "_LPT9"),
    ("COM¹", "_COM1"),
    ("LPT²", "_LPT2"),
    ("CONIN$", "_CONIN_"),
    ("CONOUT$", "_CONOUT_"),
    ("prn", "_prn"),
    ("CON.txt", "CON_txt"),
    ("name. ", "name__"),
    ("x" * 300, "x" * 100),
    ("ECU_Code", "ECU_Code"),
]

#: The Windows reserved device names (compared case-insensitively, before any
#: extension) — a sanitised part must never equal one.
_RESERVED_DEVICES = (
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
)


# --------------------------------------------------------------------------- #
# TC-B99-28 — LLR-160.1: one sanitiser over the hostile set
# --------------------------------------------------------------------------- #


def test_tc_b99_28_sanitiser_hostile_set_and_boundaries() -> None:
    from s19_app.tui.segment_split_view import (
        build_export_basename,
        sanitize_export_segment,
    )

    for raw, expected in HOSTILE_CASES:
        got = sanitize_export_segment(raw, 0)
        assert got == expected, f"{raw!r} -> {got!r}, want {expected!r}"
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,100}", got), (raw, got)
        assert got.upper() not in _RESERVED_DEVICES, (raw, got)
    # Boundary catalog: 100 kept, 101 capped.
    assert sanitize_export_segment("b" * 100, 0) == "b" * 100
    assert sanitize_export_segment("b" * 101, 0) == "b" * 100
    # An empty result becomes segment_<index>.
    assert sanitize_export_segment("", 5) == "segment_5"
    # HLR-160's stem limb: a 250-character loaded-file stem clips so the
    # final basename (the worst-case `_99` suffix and extension included)
    # stays <= 200 — TWO digits reserved, so the tenth collision's longer
    # suffix still fits the cap. The returned name carries the stem + part
    # only; the extension is the caller's suffix.
    name = build_export_basename("x" * 250, "seg", ".s19", 0)
    assert len(name) == 193, (len(name), name)
    assert len(name) + len(".s19") + len("_99") == 200
    assert len(name) + len(".s19") + len("_10") == 200
    # The BIN pair reserves room for the longer ".addr" member too.
    pair = build_export_basename("x" * 250, "seg", ".addr", 0)
    assert len(pair) + len(".addr") + len("_99") <= 200


# --------------------------------------------------------------------------- #
# TC-B99-29 — LLR-160.2: containment anchored to the work-area root
# --------------------------------------------------------------------------- #


def _export_capture(ssv, mem_map, rows, home: Path, **overrides):
    """Run the writer, returning the raised exception (None when it wrote)."""
    kwargs = dict(
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="t",
        dest_dir=home,
    )
    kwargs.update(overrides)
    try:
        ssv.write_split_join_export(mem_map, rows, **kwargs)
    except Exception as exc:  # noqa: BLE001 - the refusal type is asserted
        return exc
    return None


def test_tc_b99_29_junction_destination_is_refused(tmp_path: Path) -> None:
    """A junction at the destination escapes the work-area root: the export
    refuses, writing nothing. RED at HEAD: the writer follows the junction
    and the file lands outside (P-11's family)."""
    from tests.b97_fixtures import make_junction

    target = tmp_path / "escaped_home"
    link = _home(tmp_path)
    link.parent.mkdir(parents=True)
    kind = make_junction(link, target)

    from s19_app.tui import segment_split_view as ssv
    from s19_app.tui.workspace import WorkareaContainmentError

    rows = [SegRow("isle", "manual", 0x1000, 8)]
    raised = _export_capture(ssv, _island_map(), rows, link)
    assert isinstance(raised, WorkareaContainmentError), (
        f"the junction destination ({kind}) must refuse; got {raised!r}"
    )
    assert list(target.rglob("*")) == [], "the refusal wrote nothing anywhere"
    assert list(tmp_path.rglob("t_isle.s19")) == []


def test_tc_b99_29_existing_symlink_at_final_name_is_refused(
    tmp_path: Path,
) -> None:
    """A link already sitting at a final name is never written through: the
    export refuses and the link's target keeps its bytes. RED at HEAD:
    ``write_text`` follows the link and clobbers the target."""
    home = _home(tmp_path)
    home.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("SENTINEL", encoding="ascii")
    link = home / "t_isle.s19"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"file symlinks are not permitted in this environment: {exc}")

    from s19_app.tui import segment_split_view as ssv

    rows = [SegRow("isle", "manual", 0x1000, 8)]
    raised = _export_capture(ssv, _island_map(), rows, home)
    assert raised is not None, "the export must refuse the link at a final name"
    assert outside.read_text(encoding="ascii") == "SENTINEL", (
        "the link's target was written through"
    )
    assert os.path.islink(link), "the link itself must be left untouched"
    assert list(home.iterdir()) == [link]


def test_tc_b99_29_hostile_set_writes_nothing_outside(tmp_path: Path) -> None:
    """HLR-160's threshold: every hostile name exports INSIDE its destination
    under an allowlist name; no byte appears anywhere else."""
    from s19_app.tui import segment_split_view as ssv

    for index, (raw, _expected) in enumerate(HOSTILE_CASES):
        home = _home(tmp_path / f"case_{index:02d}")
        before = _snapshot(tmp_path)
        written = ssv.write_split_join_export(
            _island_map(),
            [SegRow(raw, "a2l", 0x1000, 8)],
            mode="split",
            gap="skip",
            pad_byte=0,
            fmt="s19",
            stem="t",
            dest_dir=home,
        )
        after = _snapshot(tmp_path)
        created = after - before
        assert created, f"{raw!r}: the export must write its sanitised file"
        assert all(p.is_relative_to(home.resolve()) for p in created), (
            f"{raw!r}: a file landed outside the destination: "
            f"{sorted(str(p) for p in created if not p.is_relative_to(home.resolve()))}"
        )
        assert {p.path.name for p in written} == {p.name for p in created}
        for path in created:
            part = path.name[len("t_") : -len(".s19")]
            assert re.fullmatch(r"[A-Za-z0-9_-]{1,100}", part), path.name
            assert part.upper() not in _RESERVED_DEVICES, path.name


def test_tc_b99_29_hostile_segment_name_renders_literally(tmp_path: Path) -> None:
    """UX-C10: the refusal renders the raw segment name literally
    (``safe_text``, clipped to 80 characters) next to the sanitised name —
    ``[red]x[/red]`` / ``[@click=app.quit]`` survive as text and paint ZERO
    markup spans."""
    from s19_app.tui import segment_split_view as ssv

    raw_a = "b99[red]x[/red]y[@click=app.quit]z"
    raw_b = "B99[RED]X[/RED]Y[@CLICK=APP.QUIT]Z"  # case-folded twin
    rows = [
        SegRow(raw_a, "manual", 0x1000, 8),
        SegRow(raw_b, "manual", 0x1000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, _home(tmp_path))
    assert isinstance(raised, ssv.ExportRefusedError), raised

    text = ssv._refusal_text(raised.reason, raised.pairs)
    plain = str(text)
    assert raw_a in plain, plain
    assert "[red]" in plain and "[/red]" in plain, plain
    assert "[@click=app.quit]" in plain, plain
    assert text.spans == [], f"markup spans leaked: {text.spans}"
    # Both colliding segments are named next to their sanitised names.
    assert raised.pairs and all(len(pair) == 2 for pair in raised.pairs)
    # The raw name is clipped to 80 characters.
    long_raw = "Q" * 120
    clipped = ssv._refusal_text("reason", [(long_raw, "safe")])
    assert "Q" * 80 in str(clipped)
    assert "Q" * 81 not in str(clipped)


# --------------------------------------------------------------------------- #
# TC-B99-30 — LLR-160.3: a MAC-only export is header-only
# --------------------------------------------------------------------------- #


def test_tc_b99_30_mac_only_export_writes_no_data_record(tmp_path: Path) -> None:
    """The writer takes its bytes from the image's DECLARED ranges: a MAC
    placeholder byte is never data, so the session's export is header-only.
    RED at HEAD: the placeholder is written as a data record (P-18)."""
    from s19_app.tui import segment_split_view as ssv

    # A MAC-only session's image: ONE placeholder byte, NO declared ranges.
    placeholder = {0x80000000: 0x00}
    rows = [SegRow("locality_00", "manual", 0x80000000, 0x10)]

    home = _home(tmp_path)
    written = ssv.write_split_join_export(
        placeholder,
        rows,
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="mac",
        dest_dir=home,
        zero_coverage_empty=True,
        declared_ranges=[],
    )
    assert [p.path.name for p in written] == ["mac_locality_00.s19"]
    image = read_s19(written[0].path)
    assert image.data == {}, f"MAC placeholder bytes became data: {image.data}"
    assert image.eof_seen and image.errors == []

    home_hex = _home(tmp_path / "hex")
    written_hex = ssv.write_split_join_export(
        placeholder,
        rows,
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="hex",
        stem="mac",
        dest_dir=home_hex,
        zero_coverage_empty=True,
        declared_ranges=[],
    )
    image_hex = read_hex(written_hex[0].path)
    assert image_hex.data == {}, f"MAC placeholder bytes became data: {image_hex.data}"
    assert image_hex.eof_seen

    # The declared shape of the defect (P-18): WITHOUT the declared-ranges
    # filter the same call writes the placeholder byte as one data record.
    control_home = _home(tmp_path / "control")
    control = ssv.write_split_join_export(
        placeholder,
        rows,
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="mac",
        dest_dir=control_home,
        zero_coverage_empty=True,
    )
    assert read_s19(control[0].path).data == placeholder


# --------------------------------------------------------------------------- #
# TC-B99-31 — LLR-160.4: a second export takes the next free `_<N>`
# --------------------------------------------------------------------------- #


def test_tc_b99_31_changed_bytes_take_the_next_free_name(tmp_path: Path) -> None:
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    rows = [SegRow("isle", "manual", 0x1000, 8)]
    first = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="s19", stem="t", dest_dir=home,
    )
    assert [p.path.name for p in first] == ["t_isle.s19"]
    assert read_s19(first[0].path).data == _island_map()

    # Identical bytes at the requested name: REUSED, no new name appears.
    again = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="s19", stem="t", dest_dir=home,
    )
    assert [p.path.name for p in again] == ["t_isle.s19"]
    assert all(p.action == "reused" for p in again)
    assert sorted(p.name for p in home.iterdir()) == ["t_isle.s19"]

    # Changed bytes: the next free `_<N>`; the first file is intact.
    changed = {0x1000 + i: 0xFF for i in range(8)}
    snapshot = first[0].path.read_bytes()
    second = ssv.write_split_join_export(
        changed, rows, mode="split", gap="skip", pad_byte=0,
        fmt="s19", stem="t", dest_dir=home,
    )
    assert [p.path.name for p in second] == ["t_isle_1.s19"]
    assert all(p.action == "wrote" for p in second)
    # The first file is intact (its bytes never moved).
    assert first[0].path.read_bytes() == snapshot
    assert read_s19(second[0].path).data == changed

    # A further export of the SAME changed bytes is byte-identical to
    # t_isle_1: the widened B100-I6 reuse (batch-100 Inc 1, LLR-163.4)
    # REUSES it — no third file appears, and the export reports the reuse.
    third = ssv.write_split_join_export(
        changed, rows, mode="split", gap="skip", pad_byte=0,
        fmt="s19", stem="t", dest_dir=home,
    )
    assert [p.path.name for p in third] == ["t_isle_1.s19"]
    assert all(p.action == "reused" for p in third)
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.s19",
        "t_isle_1.s19",
    ]


def test_tc_b99_31_bin_pair_placed_under_one_suffix(tmp_path: Path) -> None:
    """The BIN and its .addr sidecar are placed as ONE group: the second
    export takes `<name>_1` for BOTH, never a mixed pair."""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    rows = [SegRow("isle", "manual", 0x1000, 8)]
    first = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    assert sorted(p.path.name for p in first) == ["t_isle.addr", "t_isle.bin"]
    # Identical re-export: the whole pair at the requested names is reused.
    again = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    assert sorted(p.path.name for p in again) == ["t_isle.addr", "t_isle.bin"]
    assert all(p.action == "reused" for p in again)
    # Changed bytes: the pair takes `<name>_1` for BOTH, never a mixed pair.
    changed = {0x1000 + i: 0x5A for i in range(8)}
    second = ssv.write_split_join_export(
        changed, rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    assert sorted(p.path.name for p in second) == ["t_isle_1.addr", "t_isle_1.bin"]
    assert all(p.action == "wrote" for p in second)
    # The first pair is intact.
    assert (home / "t_isle.bin").read_bytes() == bytes(_island_map()[a] for a in sorted(_island_map()))
    assert (home / "t_isle.addr").read_text(encoding="ascii") == "0x00001000\n"
    assert (home / "t_isle_1.addr").read_text(encoding="ascii") == "0x00001000\n"
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.addr",
        "t_isle.bin",
        "t_isle_1.addr",
        "t_isle_1.bin",
    ]


def test_tc_b99_31_orphan_sidecar_claims_the_pair_suffix(tmp_path: Path) -> None:
    """PQ-2(a): `<name>.bin`/`.addr` exist with different bytes AND an orphan
    `<name>_1.addr` sits on disk — the pair takes `_2` for BOTH names. (The
    per-file `_<N>` mutant would split the pair: `_1.bin` + `_2.addr`.)"""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    home.mkdir(parents=True)
    # A diverging pair already present (reuse must not fire) ...
    (home / "t_isle.bin").write_bytes(b"\xEE" * 8)
    (home / "t_isle.addr").write_text("0x00009999\n", encoding="ascii")
    # ... plus the orphan half-pair.
    (home / "t_isle_1.addr").write_text("0xDEADBEEF\n", encoding="ascii")

    written = ssv.write_split_join_export(
        _island_map(),
        [SegRow("isle", "manual", 0x1000, 8)],
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="bin",
        stem="t",
        dest_dir=home,
    )
    assert sorted(p.path.name for p in written) == ["t_isle_2.addr", "t_isle_2.bin"], (
        f"the pair must share ONE fresh suffix: {sorted(p.path.name for p in written)}"
    )
    assert (home / "t_isle_1.addr").read_text(encoding="ascii") == "0xDEADBEEF\n", (
        "the orphan was touched"
    )
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.addr",
        "t_isle.bin",
        "t_isle_1.addr",
        "t_isle_2.addr",
        "t_isle_2.bin",
    ]


def test_tc_b99_31_mismatched_sidecar_never_reuses_the_pair(tmp_path: Path) -> None:
    """PQ-2(b): the BIN is byte-identical but the .addr carries another base
    — the pair is NOT reused; a fresh `_1` pair is claimed, never a reused
    `.bin` beside a `_1.addr`."""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    rows = [SegRow("isle", "manual", 0x1000, 8)]
    first = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    bin_bytes = (home / "t_isle.bin").read_bytes()

    # Drift the sidecar: same BIN, different base.
    (home / "t_isle.addr").write_text("0x00002000\n", encoding="ascii")
    again = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    assert sorted(p.path.name for p in again) == ["t_isle_1.addr", "t_isle_1.bin"]
    assert all(p.action == "wrote" for p in again)
    assert (home / "t_isle.bin").read_bytes() == bin_bytes
    assert (home / "t_isle_1.addr").read_text(encoding="ascii") == "0x00001000\n"
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.addr",
        "t_isle.bin",
        "t_isle_1.addr",
        "t_isle_1.bin",
    ]

    # Restore the sidecar: the whole pair at the requested names is identical
    # now — the group is reused and no third name appears.
    (home / "t_isle.addr").write_text("0x00001000\n", encoding="ascii")
    reused = ssv.write_split_join_export(
        _island_map(), rows, mode="split", gap="skip", pad_byte=0,
        fmt="bin", stem="t", dest_dir=home,
    )
    assert sorted(p.path.name for p in reused) == ["t_isle.addr", "t_isle.bin"]
    assert all(p.action == "reused" for p in reused)
    assert len(list(first)) == 2


def test_tc_b99_31_forced_failure_rolls_back_every_own_claim(
    tmp_path: Path, monkeypatch
) -> None:
    """PQ-2(c): a failure on the second member's fill rolls back EVERY own
    claim and placed file — no orphan BIN, no 0-byte claim, the pre-existing
    files intact."""
    from s19_app.tui import workspace
    from s19_app.tui.workspace import (
        WorkareaPlacementError,
        place_group_into_workarea,
    )

    home = _home(tmp_path)
    home.mkdir(parents=True)
    # A diverging pair so the placement must claim fresh `_1` names.
    (home / "t_isle.bin").write_bytes(b"\xEE" * 8)
    (home / "t_isle.addr").write_text("0x00009999\n", encoding="ascii")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "t_isle.bin").write_bytes(b"\x01\x02\x03\x04")
    (src_dir / "t_isle.addr").write_text("0x00001000\n", encoding="ascii")

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(source, dest):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise PermissionError("forced failure on the second fill")
        return real_replace(source, dest)

    monkeypatch.setattr(workspace.os, "replace", flaky_replace)
    try:
        place_group_into_workarea(
            [src_dir / "t_isle.bin", src_dir / "t_isle.addr"], home
        )
        raised = None
    except WorkareaPlacementError as exc:
        raised = exc
    assert isinstance(raised, WorkareaPlacementError), raised
    # Both claims removed: nothing at `_1`, nothing 0-byte, staging empty.
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.addr",
        "t_isle.bin",
    ]
    assert (home / "t_isle.bin").read_bytes() == b"\xEE" * 8
    assert (home / "t_isle.addr").read_text(encoding="ascii") == "0x00009999\n"
    staging = tmp_path / ".s19tool" / "workarea" / "temp" / ".staging"
    if staging.exists():
        assert list(staging.iterdir()) == [], "own staging directories remain"


def test_tc_b99_31_fill_failure_names_the_failing_member(
    tmp_path: Path, monkeypatch
) -> None:
    """F7 arm: a fill failure on the FIRST member of the pair names that
    member — the rollback loop's variable must not shadow the failing name
    with the group's last claim. RED before the fix: the message named
    ``t_isle_1.addr`` (the last claim in the rollback loop) although
    ``t_isle_1.bin`` was the fill that failed."""
    from s19_app.tui import workspace
    from s19_app.tui.workspace import (
        WorkareaPlacementError,
        place_group_into_workarea,
    )

    home = _home(tmp_path)
    home.mkdir(parents=True)
    # A diverging pair so the placement must claim fresh `_1` names.
    (home / "t_isle.bin").write_bytes(b"\xEE" * 8)
    (home / "t_isle.addr").write_text("0x00009999\n", encoding="ascii")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "t_isle.bin").write_bytes(b"\x01\x02\x03\x04")
    (src_dir / "t_isle.addr").write_text("0x00001000\n", encoding="ascii")

    real_replace = os.replace

    def _fail_first_fill(source, dest):
        if Path(dest).name == "t_isle_1.bin":
            raise OSError("forced failure on the first fill")
        return real_replace(source, dest)

    monkeypatch.setattr(workspace.os, "replace", _fail_first_fill)
    raised = None
    try:
        place_group_into_workarea(
            [src_dir / "t_isle.bin", src_dir / "t_isle.addr"], home
        )
    except WorkareaPlacementError as exc:
        raised = exc
    assert isinstance(raised, WorkareaPlacementError), raised
    message = str(raised)
    assert "t_isle_1.bin" in message, message
    assert "could not be written" in message, message


# --------------------------------------------------------------------------- #
# TC-B99-41 — LLR-160.5: the plan-time collision and refusal pass
# --------------------------------------------------------------------------- #


def test_tc_b99_41_case_folded_collision_refuses_before_any_write(
    tmp_path: Path,
) -> None:
    """`SegA` / `sega` sanitise to distinct names that collide case-folded:
    the whole export refuses, naming the segments, BEFORE any byte — the
    destination folder is never even created."""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    rows = [
        SegRow("SegA", "manual", 0x1000, 8),
        SegRow("sega", "manual", 0x1000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, home)
    assert isinstance(raised, ssv.ExportRefusedError), raised
    message = str(raised)
    assert "SegA" in message and "sega" in message, message
    assert "t_SegA.s19" in message and "t_sega.s19" in message, message
    assert not home.exists(), "the refusal happened before the mkdir"


def test_tc_b99_41_one_refused_name_refuses_the_whole_set(tmp_path: Path) -> None:
    """A set with ONE refused name (a link at a final name): the whole export
    refuses, 0 files — the sibling name is not written either."""
    home = _home(tmp_path)
    home.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("SENTINEL", encoding="ascii")
    link = home / "t_segb.s19"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"file symlinks are not permitted in this environment: {exc}")

    from s19_app.tui import segment_split_view as ssv

    rows = [
        SegRow("SegA", "manual", 0x1000, 8),
        SegRow("segb", "manual", 0x1000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, home)
    assert isinstance(raised, ssv.ExportRefusedError), raised
    assert "t_segb.s19" in str(raised), str(raised)
    assert outside.read_text(encoding="ascii") == "SENTINEL"
    assert os.path.islink(link)
    assert list(home.iterdir()) == [link], "a sibling file was written"


def test_tc_b99_41_over_long_full_path_refused_at_plan_time(tmp_path: Path) -> None:
    """A full path over the platform limit refuses at plan time, 0 files;
    the same home accepts an in-limit name (the boundary)."""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    stem = "x" * 250
    segment = "s" * 100
    planned = ssv.build_export_basename(stem, segment, ".s19", 0)
    assert len(planned) + len("_1") <= 200, planned
    assert len(str(home / planned)) > ssv._MAX_FULL_PATH, (
        f"precondition: this run's tmp home ({len(str(home))} chars) plus the "
        f"clipped name must exceed the platform limit; got "
        f"{len(str(home / planned))}"
    )

    rows = [SegRow(segment, "manual", 0x1000, 8)]
    raised = _export_capture(ssv, _island_map(), rows, home, stem=stem)
    assert isinstance(raised, ssv.ExportRefusedError), raised
    assert planned in str(raised), str(raised)
    assert not home.exists(), "the refusal happened before the mkdir"

    # Boundary: an in-limit name in the SAME home writes.
    written = ssv.write_split_join_export(
        _island_map(),
        [SegRow("ok", "manual", 0x1000, 8)],
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="t",
        dest_dir=home,
    )
    assert [p.path.name for p in written] == ["t_ok.s19"]


def test_tc_b99_41_collision_reason_is_scrubbed_clipped_and_indexed(
    tmp_path: Path,
) -> None:
    """F2 arm: the collision reason embeds only the sanitised names plus
    each raw name through ``safe_text`` clipped to 80 characters — an ESC
    byte never reaches the notice or the status line, a 300-character raw
    name is clipped, not embedded, and the pair carries the row's OWN
    sanitised part (no index-0 rebuild). RED before the fix: the raw names
    rode into the reason unscrubbed and unclipped."""
    from s19_app.tui import segment_split_view as ssv

    # Both parts are 100 case-folded-equal characters: the first raw name
    # is 300 characters long; the second hides an ESC byte and markup past
    # the 100-character cap, where the sanitiser clips them away — so the
    # parts still collide and the refusal must handle both hostile shapes.
    raw_a = "A" * 300
    raw_b = "a" * 100 + "\x1b[31m"
    rows = [
        SegRow(raw_a, "manual", 0x1000, 8),
        SegRow(raw_b, "manual", 0x1000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, _home(tmp_path))
    assert isinstance(raised, ssv.ExportRefusedError), raised
    reason = str(raised)
    assert "\x1b" not in reason, f"the ESC byte reached the reason: {reason!r}"
    # Each raw name rides through safe_text clipped to 80 characters — the
    # "(segment …)" clause carries exactly 80 characters, never the full
    # 300-character name, and the ESC byte is scrubbed by safe_text.
    assert f'(segment {"A" * 80})' in reason, reason
    assert f'(segment {"A" * 81})' not in reason, reason
    assert f'(segment {"a" * 80})' in reason, reason
    assert f'(segment {"a" * 81})' not in reason, reason
    assert raw_a not in reason and raw_b not in reason
    # The final (sanitised) names still identify the colliding pair.
    assert "t_" + "A" * 100 + ".s19" in reason, reason
    # The refusal text renders each raw name literally, scrubbed, clipped
    # to 80 next to its sanitised name, with zero markup spans.
    text = ssv._refusal_text(raised.reason, raised.pairs)
    plain = str(text)
    assert "\x1b" not in plain, f"the ESC byte reached the notice: {plain!r}"
    assert "A" * 80 + " → " + "A" * 100 in plain, plain
    assert "a" * 80 + " → " + "a" * 100 in plain, plain
    assert raw_a not in plain and raw_b not in plain
    assert text.spans == [], f"markup spans leaked: {text.spans}"
    # The pairs carry the row's own sanitised part.
    assert raised.pairs == [(raw_a, "A" * 100), (raw_b, "a" * 100)], raised.pairs


def test_tc_b99_41_collision_reason_scrubs_an_in_range_esc(
    tmp_path: Path,
) -> None:
    """Review round 2 (MEDIUM): an ESC byte INSIDE the 80-character clip
    must still be scrubbed. ``ab`` sanitises to ``a_b`` and collides
    case-folded with ``A_B``; the refusal reason and the painted refusal
    text carry no ESC. Without ``safe_text`` on the raw name this arm goes
    RED (the earlier arm hid its ESC past the clip)."""
    from s19_app.tui import segment_split_view as ssv

    rows = [
        SegRow("ab", "manual", 0x1000, 8),
        SegRow("A_B", "manual", 0x1000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, _home(tmp_path))
    assert isinstance(raised, ssv.ExportRefusedError), raised
    assert "" not in str(raised), repr(str(raised))
    plain = str(ssv._refusal_text(raised.reason, raised.pairs))
    assert "" not in plain, repr(plain)


def test_tc_b99_41_over_long_second_segment_refuses_before_any_write(
    tmp_path: Path,
) -> None:
    """F4 arm: a 300-character name as the SECOND segment refuses at plan
    time — the worst-case `_99` suffix measured, 0 files, the in-limit
    first name not written either. RED before the fix: the base-name-only
    check passed (260 characters, exactly at the limit) and both files
    were written."""
    from s19_app.tui import segment_split_view as ssv

    home = _home(tmp_path)
    # Pad the home so the first name's base path fits EXACTLY (260
    # characters) and the second name's worst-case `_99` path does not
    # (263) — a window the old base-name-only check could not see. The
    # joiner adds one separator character, hence pad 152 for a 153-char
    # home string.
    pad = 152 - len(str(home))
    assert pad >= 0, (
        "precondition: this run's tmp home must allow a 152-character home"
    )
    home = home / ("d" * pad)
    rows = [
        SegRow("ok", "manual", 0x1000, 8),
        SegRow("x" * 300, "manual", 0x2000, 8),
    ]
    raised = _export_capture(ssv, _island_map(), rows, home)
    assert isinstance(raised, ssv.ExportRefusedError), raised
    assert "t_" + "x" * 100 + ".s19" in str(raised), str(raised)
    assert "263 characters" in str(raised), str(raised)
    assert not home.exists(), "0 files — the refusal happened before the mkdir"


def test_tc_b99_41_payload_is_staged_inside_the_workarea(
    tmp_path: Path, monkeypatch
) -> None:
    """F5 arm: the staged payload rides through the work area's own private
    staging helper (LLR-155.1), never a directory in the system temp. RED
    before the fix: the writer staged under ``%TEMP%`` and this seam was
    never called."""
    from s19_app.tui import segment_split_view as ssv

    calls: List[Path] = []
    real_stage = ssv._private_stage_dir

    def _spy_stage(workarea_root: Path) -> Path:
        stage_dir = real_stage(workarea_root)
        calls.append(stage_dir)
        return stage_dir

    monkeypatch.setattr(ssv, "_private_stage_dir", _spy_stage)
    written = ssv.write_split_join_export(
        _island_map(),
        [SegRow("isle", "manual", 0x1000, 8)],
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="bin",
        stem="t",
        dest_dir=_home(tmp_path),
    )
    assert sorted(p.path.name for p in written) == ["t_isle.addr", "t_isle.bin"]
    assert len(calls) == 1, f"expected exactly one private staging call: {calls}"
    root = (tmp_path / ".s19tool" / "workarea").resolve()
    assert calls[0].resolve().is_relative_to(root), calls[0]
    assert calls[0].parent.name == ".staging", calls[0]


def test_tc_b99_41_part_way_failure_reports_written_and_reused(
    tmp_path: Path, monkeypatch
) -> None:
    """F3 arm: a failure on the second file reports truthfully — the reused
    file is named under ``reused:``, never conflated with ``Already
    written:``. RED before the fix: the message claimed "files already
    written: t_alpha.s19" although that file was only reused."""
    from s19_app.tui import segment_split_view as ssv
    from s19_app.tui import workspace

    home = _home(tmp_path)
    rows = [
        SegRow("alpha", "manual", 0x1000, 8),
        SegRow("beta", "manual", 0x2000, 8),
    ]
    kwargs = dict(
        mode="split", gap="skip", pad_byte=0, fmt="s19", stem="t", dest_dir=home
    )
    first = ssv.write_split_join_export(_island_map(), rows, **kwargs)
    assert [p.path.name for p in first] == ["t_alpha.s19", "t_beta.s19"]
    alpha_bytes = first[0].path.read_bytes()
    for placed in first:
        placed.path.unlink()
    # Re-place the first file's bytes: the retry REUSES it (writes nothing)
    # and then the second file's fill is forced to fail.
    (home / "t_alpha.s19").write_bytes(alpha_bytes)

    real_replace = os.replace

    def _fail_second_fill(source, dest):
        if Path(dest).name == "t_beta.s19":
            raise OSError("forced failure on the second file")
        return real_replace(source, dest)

    monkeypatch.setattr(workspace.os, "replace", _fail_second_fill)
    raised = _export_capture(ssv, _island_map(), rows, home)
    assert isinstance(raised, ssv.ExportWriteError), raised
    message = str(raised)
    assert message.startswith("Export stopped:"), message
    assert "Already written: nothing" in message, message
    assert "reused: t_alpha.s19" in message, message
    assert "files already written" not in message, message
    assert list(raised.written) == [], "a reused file is not a written file"


# --------------------------------------------------------------------------- #
# AT-B99-11 — US-149: black-box pilot through the Split / Join / Export window
# --------------------------------------------------------------------------- #


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


async def _wait_for(pilot, predicate, description: str, attempts: int = 100):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


async def _open_split_join_window(app: S19TuiApp, pilot) -> None:
    """Open the window the palette's way: ctrl+k, filter, enter."""
    await pilot.press("ctrl+k")
    await _wait_for(
        pilot,
        lambda: not app.query_one("#command_palette").has_class("hidden"),
        "the command palette",
    )
    assert await pilot.click("#palette_input"), "click missed #palette_input"
    await pilot.press(*"Split / Join")
    await _wait_for(
        pilot,
        lambda: len(app.query("#palette_list ListItem")) == 1,
        "the palette filtered to one entry",
    )
    await pilot.press("enter")
    await _wait_for(
        pilot,
        lambda: not app.query_one("#screen_split_join").has_class("hidden"),
        "the Split / Join / Export window",
    )


async def _load_project_pilot(app: S19TuiApp, pilot, name: str) -> None:
    """Load a project through the Load project dialog (rail key ``p``)."""
    from textual.widgets import Label

    await pilot.press("p")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog",
    )
    row = next(
        row
        for row in app.screen.query("#project_list ListItem")
        if name in str(row.query_one(Label).render())
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: f"Loaded project '{name}'" in _status_text(app),
        "the project-load status line",
        attempts=200,
    )


def test_at_b99_11_sanitised_mac_only_second_export_takes_suffix(
    tmp_path: Path,
) -> None:
    """AT-B99-11 (HLR-160) end to end in ONE pilot session, all three
    clauses in sequence through the shipped Split / Join / Export window
    (SegmentSplitView) export action.

    HLR-160's Observable outcome: "with an A2L whose segment is named
    `x/../../../ESCAPED`, the export writes its file inside the
    destination under a sanitised name, and nothing appears outside it. A
    MAC-only export writes a file holding no data record. A second export
    after a patch writes `<name>_1`, the status names it, and the first
    file is intact."

    Clause (a) — the hostile-segment A2L project exports INSIDE the
    destination under ``prg_x__________ESCAPED.s19`` and nothing appears
    outside it. Clause (b) — every artifact is unloaded and
    ``firmware.mac`` is loaded on its own, so the session is genuinely
    MAC-only: a manual-range export writes ``firmware_locality_00.s19``
    holding NO data record (independent reader). Clause (c) — the project
    is reloaded, one byte is patched through the Patch Editor, and the
    second export lands as ``_<N>``, named in the painted status
    (wrote/reused), while the first file's bytes stay intact.
    """
    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj1"
    project_dir.mkdir(parents=True)
    shutil.copyfile(PRG_S19, project_dir / "prg.s19")
    _write_hostile_segment_a2l(project_dir, "x/../../../ESCAPED")
    mac_src = tmp_path / "firmware.mac"
    shutil.copyfile(FIRMWARE_MAC, mac_src)
    oracle = read_s19(PRG_S19)
    patch_addr = min(oracle.data)
    patch_value = 0x5A if oracle.data[patch_addr] != 0x5A else 0xC3
    dest = project_dir / "splits"

    async def _drive():
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            await _load_project_pilot(app, pilot, "proj1")

            # ---- Clause (a): hostile A2L segment name stays inside dest.
            await _open_split_join_window(app, pilot)
            before_a = _snapshot(tmp_path)
            # Entering the manual tab hands focus to its TextArea (by
            # design) — click the table back so the window bindings, not
            # the box, take the letters.
            await pilot.press("t")  # ranges -> manual (focus -> TextArea)
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("t")  # manual -> a2l (focus -> table)
            await pilot.press("a")  # select all (2 A2L segments, 0 coverage)
            await pilot.press("e")  # arm: empty files behind the confirm
            await pilot.press("e")  # confirm
            await _wait_for(
                pilot,
                lambda: "xported" in _status_text(app).lower(),
                "the clause-a export status line",
                attempts=200,
            )
            status_a = _status_text(app)
            after_a = _snapshot(tmp_path)
            created_a = sorted(
                str(p.relative_to(tmp_path)) for p in after_a - before_a
            )

            # ---- Clause (b): a MAC-only export writes no data record.
            # Unload every artifact first — loading the MAC beside prg.s19
            # would merely attach it (the coexistence model) and the clause
            # would not be a MAC-ONLY session. Focus is on the table (the
            # a2l tab), so the rail keys below bubble to the app.
            await pilot.press("escape")  # close the window
            await pilot.press("U")  # unload all artifacts
            await _wait_for(
                pilot,
                lambda: "nloaded" in _status_text(app),
                "the unload-all status line",
            )
            await pilot.press("l")
            await _wait_for(
                pilot,
                lambda: "LoadFileScreen" in type(app.screen).__name__
                and len(app.screen.query("#load_path")) > 0,
                "the Load file dialog",
            )
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(mac_src))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _wait_for(
                pilot,
                lambda: "firmware.mac" in _status_text(app),
                "the MAC load status line",
                attempts=200,
            )
            await _open_split_join_window(app, pilot)
            await pilot.press("t")  # a2l -> ranges (focus -> table)
            await pilot.press("t")  # ranges -> manual (focus -> TextArea)
            await pilot.press(*"0x80000000-0x8000000F")
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("a")  # select all (parses the manual box)
            await pilot.press("e")  # arm: the session holds 0 declared bytes
            await pilot.press("e")  # confirm
            await _wait_for(
                pilot,
                lambda: "xported" in _status_text(app).lower(),
                "the clause-b export status line",
                attempts=200,
            )

            # ---- Clause (c): patch, export again -> <name>_1, first intact.
            # Leave the window on a table-focused tab BEFORE closing it: a
            # hidden manual TextArea keeps focus and would swallow the next
            # key (it is the one widget that eats letters).
            await pilot.press("t")  # manual -> a2l (focus -> table)
            await pilot.press("escape")  # close the window
            await _load_project_pilot(app, pilot, "proj1")
            await _open_split_join_window(app, pilot)
            await pilot.press("t")  # a2l -> ranges (focus -> table)
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("a")  # ranges tab: all rows
            await pilot.press("e")
            await _wait_for(
                pilot,
                lambda: "xported" in _status_text(app).lower(),
                "the first (clause-c) export status line",
                attempts=200,
            )
            before_c = {p.name: p.read_bytes() for p in dest.iterdir()}

            # Patch one byte through the Patch Editor (rail key ``6``).
            await pilot.press("escape")  # close the window
            await pilot.press("6")
            await _wait_for(
                pilot,
                lambda: len(app.query("#patch_editor_panel")) > 0,
                "the Patch Editor",
            )
            assert await pilot.click(
                "#patch_entry_address_input"
            ), "click missed #patch_entry_address_input"
            await pilot.press(*f"0x{patch_addr:X}")
            assert await pilot.click(
                "#patch_entry_bytes_input"
            ), "click missed #patch_entry_bytes_input"
            await pilot.press(*f"0x{patch_value:02X}")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "the add status line",
            )
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "Apply:" in _status_text(app),
                "the apply status line",
            )

            await _open_split_join_window(app, pilot)
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("a")
            await pilot.press("e")
            # Wait for the SECOND export's status: it names the `_1` write
            # and the reused siblings (UX-C11).
            status_c = ""
            for _ in range(200):
                await pilot.pause()
                status_c = _status_text(app)
                if "xported" in status_c.lower() and "reused" in status_c:
                    break
            after_c = {p.name: p.read_bytes() for p in dest.iterdir()}
            return status_a, created_a, before_c, after_c, status_c

    status_a, created_a, before_c, after_c, status_c = asyncio.run(_drive())

    # Clause (a) — the sanitised name lands inside the destination and
    # nothing appears outside it. "x/../../../ESCAPED" — 4 slashes + 6
    # dots, every one mapped to "_".
    expected_name = "prg_x__________ESCAPED.s19"
    assert (dest / expected_name).exists(), f"{created_a} (status: {status_a})"
    escape_landing = f"proj1{os.sep}ESCAPED.s19"
    assert escape_landing not in [c.replace("/", os.sep) for c in created_a], (
        f"the escape path appeared: {created_a}"
    )
    assert not (dest.parent / "ESCAPED.s19").exists(), (
        "HEAD's escape landing exists"
    )
    inside = f".s19tool{os.sep}workarea{os.sep}proj1{os.sep}splits{os.sep}"
    assert all(
        c.replace("/", os.sep).startswith(inside) for c in created_a
    ), created_a
    assert expected_name in status_a, status_a
    # The sanitised export is header-only (0 coverage) and parses clean.
    image_a = read_s19(dest / expected_name)
    assert image_a.data == {} and image_a.eof_seen and image_a.errors == []

    # Clause (b) — the MAC-only export's file holds no data record (the
    # project is still active, so the file lands in the project's splits).
    mac_file = dest / "firmware_locality_00.s19"
    assert mac_file.exists(), f"{sorted(p.name for p in dest.iterdir())}"
    image_b = read_s19(mac_file)
    assert image_b.data == {}, f"the MAC placeholder became data: {image_b.data}"
    assert image_b.eof_seen and image_b.errors == []

    # Clause (c) — the second export takes `_1`, the status names it, and
    # the first file's bytes are intact.
    new_names = sorted(set(after_c) - set(before_c))
    overwritten = [n for n in before_c if after_c[n] != before_c[n]]
    assert overwritten == [], f"the first export was clobbered: {overwritten}"
    assert len(new_names) == 1 and new_names[0].endswith("_1.s19"), (
        f"expected exactly one `_1` file; new={new_names}"
    )
    stem_name = new_names[0][: -len("_1.s19")] + ".s19"
    assert stem_name in before_c, (stem_name, sorted(before_c))
    assert after_c[stem_name] == before_c[stem_name], "the first file changed"
    assert "_1" in status_c and "wrote" in status_c and "reused" in status_c, (
        status_c
    )
    # The independent reader sees the patch only in the `_1` file.
    image_new = read_s19(dest / new_names[0])
    image_old = read_s19(dest / stem_name)
    assert image_new.data[patch_addr] == patch_value
    assert image_old.data[patch_addr] == oracle.data[patch_addr]


def test_tc_b99_41_part_way_failure_status_names_the_first_file(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-B99-41 sub-arm through the shipped window (AT-B99-11's surface):
    F3 arm (painted status) — an export whose SECOND file's fill fails
    paints a status that names the first file under ``Already written:``
    and never claims the failed file was written. RED before the fix: the
    status contradicted itself ("Nothing written. — files already
    written: ...")."""
    from s19_app.tui import workspace

    src = tmp_path / "firmware.mac"
    shutil.copyfile(FIRMWARE_MAC, src)
    app = S19TuiApp(base_dir=tmp_path)

    real_replace = os.replace

    def _fail_second_fill(source, dest):
        if Path(dest).name == "firmware_locality_01.s19":
            raise OSError("forced failure on the second fill")
        return real_replace(source, dest)

    monkeypatch.setattr(workspace.os, "replace", _fail_second_fill)

    async def _drive():
        # A wide terminal: the truthful part-way message is long (it names
        # the destination), and this arm asserts on the painted tail —
        # "Already written: …" must be visible, not clipped away.
        async with app.run_test(size=(320, 54)) as pilot:
            await pilot.pause()
            await pilot.press("l")
            await _wait_for(
                pilot,
                lambda: "LoadFileScreen" in type(app.screen).__name__
                and len(app.screen.query("#load_path")) > 0,
                "the Load file dialog",
            )
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(src))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _wait_for(
                pilot,
                lambda: "firmware.mac" in _status_text(app),
                "the MAC load status line",
                attempts=200,
            )
            await _open_split_join_window(app, pilot)
            await pilot.press("t")  # ranges -> manual (focus -> TextArea)
            await pilot.press(*"0x80000000-0x8000000F")
            await pilot.press("enter")
            await pilot.press(*"0x80000010-0x8000001F")
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("a")  # select all (parses the manual box)
            await pilot.press("e")  # arm: two zero-coverage files
            await pilot.press("e")  # confirm
            await _wait_for(
                pilot,
                lambda: "xport" in _status_text(app).lower()
                and "topped" in _status_text(app),
                "the part-way failure status line",
                attempts=200,
            )
            return _status_text(app)

    status = asyncio.run(_drive())
    assert "Export failed: Export stopped:" in status, status
    assert "Already written: firmware_locality_00.s19" in status, status
    assert "firmware_locality_01.s19" not in status.split("Already written:")[1], (
        status
    )
    dest = _home(tmp_path)
    written = sorted(dest.iterdir()) if dest.exists() else []
    assert [p.name for p in written] == ["firmware_locality_00.s19"], (
        f"{written} (status: {status})"
    )


def test_tc_b99_29_junctioned_project_home_shows_refusal(tmp_path: Path) -> None:
    """TC-B99-29 sub-arm through the shipped window (AT-B99-11's surface):
    F6 arm — a project dir swapped for a junction escaping the work area
    makes the scoped destination resolution refuse — the refusal is painted
    and the app does not crash. RED before the fix: ``_dest_dir()`` raised
    OUTSIDE the handler's try, so the key press propagated the exception
    and the pilot run errored."""
    from tests.b97_fixtures import make_junction

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj1"
    project_dir.mkdir(parents=True)
    shutil.copyfile(PRG_S19, project_dir / "prg.s19")

    async def _drive():
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            await _load_project_pilot(app, pilot, "proj1")
            # Swap the loaded project's dir for a junction whose target
            # sits OUTSIDE the work-area root: the scoped project home can
            # no longer be resolved inside it.
            for child in project_dir.iterdir():
                child.unlink()
            project_dir.rmdir()
            make_junction(project_dir, tmp_path / "escaped_home")
            await _open_split_join_window(app, pilot)
            assert await pilot.click("#sje_table"), "click missed #sje_table"
            await pilot.press("a")  # ranges tab: all rows
            await pilot.press("e")
            await _wait_for(
                pilot,
                lambda: "xport" in _status_text(app).lower(),
                "the export outcome status line",
                attempts=200,
            )
            return _status_text(app)

    status = asyncio.run(_drive())
    assert "Export refused" in status, status
    escaped = tmp_path / "escaped_home"
    assert list(escaped.rglob("*")) == [], "the refusal wrote nothing anywhere"
