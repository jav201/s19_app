"""Batch-100 project builders (enabler E4, first slice at Inc 6).

The Inc 6 slice builds:

  - the ``p02`` A/B save-back names: a save-back typed as the source's own
    name (``firmware.s19``, which lands as ``firmware_1.s19`` because the
    project already holds a different ``firmware.s19``) and one that keeps
    the panel's default suggestion (``firmware-patched.s19``);
  - a project folder seeded on disk with every manifest key a writer does
    not own (``batch``, ``assignments``, ``declared_regions``, ``gathered``),
    written in compact JSON so any rewrite through the manifest seam (which
    writes ``indent=2``) is visible in the bytes even when the keys are
    unchanged.

Corrective pass 1 adds the Load-result panel helpers: its painted text
(``load_result_panel_text``, ``read_load_result_panel``, ``painted_lines``,
``flat``) and its
dismissal with an asserted close (``dismiss_load_result_panel``).

Corrective pass 3 adds ``create_junction_loop`` (a junction that points to
itself) and ``OVERLONG_INT_MANIFEST`` (an integer over Python's digit limit).

Inc 7 adds the ``p04`` cases 2/5/6/7/9, a legacy project and a hand-copied
variant (``build_p04_case``), built over a project saved by the shipped Save
project handler (``save_case01_project``, LED .42). Nothing here imports
``s19_app``'s loaders: the builders copy example files and write JSON with
the stdlib only, and drive the app only to save.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parents[2]
CASE01_DIR = ROOT / "examples" / "case_01_basic_valid"
CASE02_DIR = ROOT / "examples" / "case_02_gaps_and_patch_targets"

#: ``p02`` A/B: the name typed into the save-back prompt -> the file the
#: placement lands on in a project that already holds case_01's
#: ``firmware.s19`` (``None`` typed = keep the prompt's default suggestion).
P02_SAVEBACK = {
    "A": ("firmware.s19", "firmware_1.s19"),
    "B": (None, "firmware-patched.s19"),
}

#: The keys a variant append / MAC sync / A2L sync / save-back does not own
#: (B100-I7), as seeded by :func:`seed_project_with_every_key`. ``variant``
#: is the id the ``assignments`` row is keyed by.
SEEDED_PATCH = "patches/cs_seed.json"
SEEDED_CHECK = "checks/ck_seed.json"


def seeded_keys(variant: str = "firmware") -> dict:
    """The not-owned manifest keys, in the project-relative POSIX form the
    serializer writes."""
    return {
        "batch": [SEEDED_PATCH],
        "assignments": {variant: [SEEDED_CHECK]},
        "declared_regions": [
            {"name": "cal_block", "start": 0x80000040, "end": 0x8000007F}
        ],
        "gathered": {"patches": [SEEDED_PATCH], "checks": [SEEDED_CHECK]},
    }


def copy_sources(folder: Path, source_dir: Path, *names: str) -> Path:
    """Scratch copies of example files; returns the folder."""
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(source_dir / name, folder / name)
    return folder


def seed_project_with_every_key(
    workarea: Path,
    name: str = "P",
    *,
    data_files: Iterable[str] = ("firmware.s19",),
    active_variant: str = "firmware",
) -> Path:
    """A project folder holding case_01's data files, the two seeded
    documents and a ``project.json`` carrying every not-owned key."""
    project_dir = workarea / name
    copy_sources(project_dir, CASE01_DIR, *data_files)
    for relative in (SEEDED_PATCH, SEEDED_CHECK):
        target = project_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"entries": []}', encoding="utf-8")
    manifest = {"schema_version": 1, "active_variant": active_variant}
    manifest.update(seeded_keys(active_variant))
    (project_dir / "project.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )
    return project_dir


#: A ``project.json`` holding a 5 000-digit integer: ``json.load`` raises a
#: plain ``ValueError`` (Python's int-digit limit, 4 300), not a
#: ``JSONDecodeError`` (SEC6-8).
OVERLONG_INT_MANIFEST = '{"schema_version": 1, "pad": ' + "9" * 5000 + "}"


def create_junction_loop(link: Path) -> Path:
    """A Windows directory junction at ``link`` that points to itself, so
    ``Path.resolve()`` through it raises ``RuntimeError`` (symlink loop,
    SEC6-7). Built with ``cmd /c mklink /J`` (no elevation). The caller
    removes it with ``os.rmdir`` (never a recursive delete through it), and
    skips off Windows (``b100_links.require_junctions``)."""
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(link)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise OSError(f"mklink /J failed: {result.stdout} {result.stderr}")
    return link


#: The security probe T2's folder chain (Inc 7 corrective pass 2,
#: SEC7-R2-2): 31 short folder names, so an entry under it has 32
#: components, the deepest the reader walks.
CHAIN = tuple(chr(ord("a") + i % 26) + ("" if i < 26 else "2") for i in range(31))


def real_files_under_a_chain(project_dir: Path, count: int = 1000) -> list:
    """``count`` real change files at the end of :data:`CHAIN` under
    ``project_dir`` (the security probe T2's shape); returns their
    project-relative names."""
    chain = project_dir.joinpath(*CHAIN)
    chain.mkdir(parents=True, exist_ok=True)
    relative = "/".join(CHAIN)
    names = []
    for index in range(count):
        (chain / f"f{index}.json").write_text('{"entries": []}', encoding="utf-8")
        names.append(f"{relative}/f{index}.json")
    return names


def read_manifest(project_dir: Path) -> dict:
    """``project.json`` parsed with the stdlib (never the app's reader)."""
    return json.loads((project_dir / "project.json").read_text(encoding="utf-8"))


def not_owned(manifest: dict) -> dict:
    """The four not-owned keys of a parsed manifest (absent -> missing)."""
    return {
        key: manifest[key]
        for key in ("batch", "assignments", "declared_regions", "gathered")
        if key in manifest
    }


def absolute_strings(value: object) -> list:
    """Every string anywhere in ``value`` that is an absolute path under
    either separator convention."""
    found: list = []

    def _walk(item: object) -> None:
        if isinstance(item, str):
            if PureWindowsPath(item).is_absolute() or PurePosixPath(item).is_absolute():
                found.append(item)
        elif isinstance(item, dict):
            for key, inner in item.items():
                _walk(key)
                _walk(inner)
        elif isinstance(item, list):
            for inner in item:
                _walk(inner)

    _walk(value)
    return found


def landed_name(case: str) -> str:
    """The file a ``p02`` case's save-back lands on."""
    return P02_SAVEBACK[case][1]


def typed_name(case: str) -> Optional[str]:
    """The name a ``p02`` case types (``None`` = the default suggestion)."""
    return P02_SAVEBACK[case][0]


# ---------------------------------------------------------------------------
# The Load-result panel (Inc 6, HLR-178 / LLR-178.3), as painted
# ---------------------------------------------------------------------------

#: The panel's Close button; present on the active screen only while the
#: panel is open.
LOAD_RESULT_CLOSE = "#result_ok"


def painted_lines(widget) -> list:
    """One widget's painted lines (its rendered strips, right-trimmed), so a
    row that wraps reads as the lines the user sees."""
    return [widget.render_line(y).text.rstrip() for y in range(widget.size.height)]


def load_result_panel_text(app) -> str:
    """Every painted line of the open Load-result panel: the title, the
    summary grid, the problem heading and each problem row."""
    lines: list = []
    for widget in app.screen.query("#load_result_dialog .modal-title, #result_body Static"):
        lines += painted_lines(widget)
    return "\n".join(lines)


async def read_load_result_panel(pilot, app, attempts: int = 200) -> str:
    """The open panel's painted text, once it is laid out and painted (the
    summary has a height): a panel read the instant it is pushed paints
    nothing yet."""
    for _ in range(attempts):
        summary = app.screen.query("#result_summary")
        if len(summary) > 0 and summary.first().size.height > 0:
            return load_result_panel_text(app)
        await pilot.pause()
    raise AssertionError("the Load-result panel was not painted")


def flat(text: str) -> str:
    """``text`` with every run of white space (wraps and hanging indents
    included) collapsed to one space, for phrase oracles."""
    return " ".join(text.split())


async def dismiss_load_result_panel(pilot, app, attempts: int = 200) -> None:
    """Wait for the Load-result panel that the Load project dialog opens,
    close it with its shown key ``esc``, and assert that it closed — a panel
    that does not close fails HERE, not at a later, less clear step."""
    for _ in range(attempts):
        if len(app.screen.query(LOAD_RESULT_CLOSE)) > 0:
            break
        await pilot.pause()
    assert len(app.screen.query(LOAD_RESULT_CLOSE)) > 0, "the Load-result panel did not open"
    await pilot.press("escape")
    for _ in range(attempts):
        if len(app.screen.query(LOAD_RESULT_CLOSE)) == 0:
            return
        await pilot.pause()
    raise AssertionError("the Load-result panel did not close on esc")


# ---------------------------------------------------------------------------
# Inc 7 (E4): the ``p04`` cases, a legacy project and a hand-copied variant
# ---------------------------------------------------------------------------
#
# LED .42: a case that consumes a SAVED project takes its ``project.json``
# from the shipped Save project handler (``save_case01_project`` drives it);
# only the damaged (case 7), legacy and hostile cases write ``project.json``
# by hand. The builders import the app only to drive that handler.

CASE00_DIR = ROOT / "examples" / "case_00_public"

#: The ``p04`` cases of P-4 / P-5 this slice builds, plus the two extra
#: kinds of HLR-169's threshold, each with the one problem kind it must
#: produce and the file that problem names.
P04_CASES = {
    "clean": (None, None),
    "2-image-edited": ("changed on disk", "firmware.s19"),
    "5-image-deleted": ("missing", "firmware.s19"),
    "6-image-corrupt": ("not readable", "firmware.s19"),
    "7-manifest-corrupt": ("manifest damaged", "project.json"),
    "9-no-manifest-two-variants": ("no project.json", "project.json"),
    "legacy": ("no digests saved", "project.json"),
    "hand-copied": ("not recorded", "firmware_9.s19"),
}


def save_case01_project(
    base: Path,
    name: str = "P",
    files: Iterable[str] = ("firmware.s19", "firmware.mac", "firmware.a2l"),
) -> Path:
    """Save project ``name`` holding case_01's ``files`` through the shipped
    Save project handler, in an app of its own; returns the project folder."""
    import asyncio

    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.screens import SaveProjectPayload

    source = copy_sources(base.parent / f"{base.name}_src", CASE01_DIR, *files)

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            for item in files:
                path = source / item
                if path.suffix.lower() == ".a2l":
                    app.load_a2l_from_path(path)
                    done = lambda: app.current_a2l_path is not None  # noqa: E731
                else:
                    app._load_path_from_user_input(path)
                    done = lambda: app.current_file is not None and (  # noqa: E731
                        app.current_file.path.name == item
                        or (app.current_file.mac_path is not None
                            and app.current_file.mac_path.name == item)
                    )
                for _ in range(400):
                    if done():
                        break
                    await pilot.pause()
                else:
                    raise AssertionError(f"the load of {item} did not land")
            app._handle_save_dialog(
                SaveProjectPayload(parent_folder=str(app.workarea), project_name=name)
            )
            for _ in range(400):
                if app.current_project == name:
                    break
                await pilot.pause()
            else:
                raise AssertionError(f"Save project {name} did not land")
            return app.workarea / name

    return asyncio.run(_drive())


def flip_data_byte(path: Path) -> None:
    """Change one data byte of the first S3 record of an S19 file and fix
    the record checksum, so the size is unchanged and only the digest tells
    (the P-4 case 2 edit)."""
    lines = path.read_text(encoding="ascii").splitlines()
    index = next(n for n, line in enumerate(lines) if line.startswith("S3"))
    raw = bytearray(bytes.fromhex(lines[index][2:]))
    raw[6] ^= 0xFF
    raw[-1] = (~sum(raw[:-1])) & 0xFF
    lines[index] = lines[index][:2] + raw.hex().upper()
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def build_p04_case(base: Path, case: str) -> Path:
    """Project ``P`` in ``base``'s work area in the state ``case`` names
    (:data:`P04_CASES`); returns the project folder."""
    project_dir = save_case01_project(base)
    manifest_path = project_dir / "project.json"
    if case == "2-image-edited":
        flip_data_byte(project_dir / "firmware.s19")
    elif case == "5-image-deleted":
        (project_dir / "firmware.s19").unlink()
    elif case == "6-image-corrupt":
        (project_dir / "firmware.s19").write_text("S3FFgarbage\n", encoding="ascii")
    elif case == "7-manifest-corrupt":
        manifest_path.write_text("{not json", encoding="utf-8")
    elif case == "9-no-manifest-two-variants":
        shutil.copyfile(CASE00_DIR / "prg.s19", project_dir / "aaa.s19")
        manifest_path.unlink()
    elif case == "legacy":
        manifest = read_manifest(project_dir)
        manifest.pop("files", None)
        manifest.pop("derived_from", None)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    elif case == "hand-copied":
        shutil.copyfile(CASE02_DIR / "firmware.s19", project_dir / "firmware_9.s19")
    elif case != "clean":
        raise ValueError(f"unknown p04 case {case!r}")
    return project_dir


def append_variant(base: Path, source: Path, name: str = "P") -> None:
    """Open project ``name`` and load ``source`` into it, so the shipped
    variant append places it and rewrites ``project.json`` through the
    manifest seam (it becomes the recorded active variant)."""
    import asyncio

    from s19_app.tui.app import S19TuiApp

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        statuses: list = []
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app._handle_load_project(name)
            await pilot.pause()
            app.load_from_path(source)
            for _ in range(400):
                if any("manifest verified" in line for line in statuses):
                    return
                await pilot.pause()
            raise AssertionError(f"the variant append of {source.name} did not land: {statuses}")

    asyncio.run(_drive())


def file_records(project_dir: Path) -> dict:
    """The ``files`` map an oracle expects for ``project_dir``: every
    top-level file with a data or A2L suffix -> size and SHA-256 of its
    bytes, computed with ``hashlib`` (never the app's own code)."""
    import hashlib

    suffixes = {".s19", ".srec", ".hex", ".ihex", ".mac", ".a2l"}
    return {
        path.name: {
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(project_dir.iterdir(), key=lambda item: item.name)
        if path.is_file() and path.suffix.lower() in suffixes
    }
