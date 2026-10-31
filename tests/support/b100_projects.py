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


# ---------------------------------------------------------------------------
# Inc 8a (E4): projects that record an ``active_document`` (HLR-170), a
# junction home, a file held open by another program, and one app session
# driver with a full ``set_status`` log.
# ---------------------------------------------------------------------------

#: The default recorded document and its one address entry, inside
#: case_01's image (``0x80000010`` is ``CAL_BLOCK_A``).
DOCUMENT_TEXT = "patches/boost.json"
DOCUMENT_ADDRESS = 0x80000010
DOCUMENT_BYTES = (0xDE, 0xAD)


def address_entry(address: int, run) -> dict:
    return {
        "type": "bytes",
        "address": f"0x{address:08X}",
        "bytes": " ".join(f"{byte:02X}" for byte in run),
    }


def symbol_entry(symbol: str, address: int, run) -> dict:
    entry = address_entry(address, run)
    entry["symbol"] = symbol
    return entry


def change_document_bytes(entries=None, kind: str = "change") -> bytes:
    """A v2 change (or check) document; by default one address entry at
    :data:`DOCUMENT_ADDRESS`."""
    if entries is None:
        entries = [address_entry(DOCUMENT_ADDRESS, DOCUMENT_BYTES)]
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": list(entries),
        },
        indent=2,
    ).encode("utf-8")


def file_record_of(path: Path) -> dict:
    """``{"size", "sha256"}`` of ``path``'s bytes, computed with hashlib."""
    import hashlib

    data = path.read_bytes()
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


_SAME = object()


def seed_document_project(
    workarea: Path,
    name: str = "P",
    *,
    document: str = DOCUMENT_TEXT,
    body: Optional[bytes] = b"",
    data_files: Iterable[str] = ("firmware.s19",),
    record_document: bool = True,
    active_document: object = _SAME,
    extra: Optional[dict] = None,
) -> Path:
    """A project folder holding case_01's ``data_files``, the document file
    ``document`` with ``body`` (``b""`` = the default one-entry document,
    ``None`` = no file), and a hand-written ``project.json`` recording
    ``active_variant`` ``firmware``, the ``files`` digests (hashlib) of the
    data files and — when ``record_document`` and the file exists — of the
    document, and ``active_document`` (``document`` unless given; any JSON
    value, so the reader's hostile arms can be seeded)."""
    project_dir = workarea / name
    copy_sources(project_dir, CASE01_DIR, *data_files)
    target = project_dir / document
    if body is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body or change_document_bytes())
    files = {item: file_record_of(project_dir / item) for item in data_files}
    if record_document and body is not None:
        files[document] = file_record_of(target)
    manifest = {
        "schema_version": 1,
        "active_variant": "firmware",
        "files": files,
        "active_document": document if active_document is _SAME else active_document,
    }
    manifest.update(extra or {})
    (project_dir / "project.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return project_dir


def junction_home(project_dir: Path, home: str, private: Path, name: str = "boost.json") -> Path:
    """Replace ``project_dir/home`` with a directory junction to ``private``
    (created, holding a valid one-entry document ``name``). Returns the
    private file. Windows only: the caller runs ``require_junctions``."""
    from tests.support.b100_links import create_junction

    private.mkdir(parents=True, exist_ok=True)
    secret = private / name
    secret.write_bytes(change_document_bytes())
    home_dir = project_dir / home
    if home_dir.exists():
        shutil.rmtree(home_dir)
    create_junction(home_dir, private)
    return secret


class held_exclusively:
    """Context manager: ``path`` open by "another program" with share mode
    0 (``CreateFileW``), so any open for reading fails with a sharing
    violation while ``os.lstat`` still answers. Windows only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None

    def __enter__(self):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel32.CreateFileW
        create.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        create.restype = wintypes.HANDLE
        handle = create(str(self.path), 0x80000000, 0, None, 3, 0x80, None)
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "could not hold the file", str(self.path))
        self.handle = handle
        self._close = kernel32.CloseHandle
        self._close.argtypes = [wintypes.HANDLE]
        return self

    def __exit__(self, *exc) -> None:
        if self.handle is not None:
            self._close(self.handle)
            self.handle = None


class StatusLog:
    """Every ``set_status`` message, in full, while painting it for real."""

    def __init__(self, app) -> None:
        self.messages: list = []
        original = app.set_status

        def _record(message, *args, **kwargs):
            self.messages.append(str(message))
            return original(message, *args, **kwargs)

        app.set_status = _record

    def since(self, mark: int) -> list:
        return self.messages[mark:]


def run_app(base: Path, scenario, size: tuple = (160, 50)):
    """Run ``await scenario(app, pilot, log)`` in a fresh app rooted at
    ``base``; return what it returns."""
    import asyncio

    from s19_app.tui.app import S19TuiApp

    async def _drive():
        app = S19TuiApp(base_dir=base)
        log = StatusLog(app)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await scenario(app, pilot, log)

    return asyncio.run(_drive())


async def wait_for(pilot, predicate, description: str, attempts: int = 400) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def load_image(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_for(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == path.name,
        f"the load of {path.name}",
    )


async def load_project(pilot, app, name: str = "P") -> float:
    """Open project ``name`` through the shipped handler; returns the
    handler's wall time in seconds (the reopen runs inside it)."""
    import time

    start = time.perf_counter()
    app._handle_load_project(name)
    elapsed = time.perf_counter() - start
    await wait_for(
        pilot,
        lambda: app.current_project == name and app.current_file is not None,
        f"the project load of {name}",
    )
    for _ in range(6):
        await pilot.pause()
    return elapsed


SAVE_OUTCOMES = ("Saved project to", "NOT saved", "could not save", "Could not save", "was not written")


async def save_project(pilot, app, log: StatusLog, name: str = "P") -> list:
    """Run the shipped Save project handler for ``name`` and wait for its
    outcome line; returns every status message the save painted."""
    from s19_app.tui.screens import SaveProjectPayload

    mark = len(log.messages)
    app._handle_save_dialog(
        SaveProjectPayload(parent_folder=str(app.workarea), project_name=name)
    )
    await wait_for(
        pilot,
        lambda: any(
            outcome in message for message in log.since(mark) for outcome in SAVE_OUTCOMES
        ),
        f"the Save project outcome for {name}",
    )
    for _ in range(6):
        await pilot.pause()
    return log.since(mark)


def tree_files(root: Path) -> dict:
    """Every file under ``root`` (relative POSIX text) -> its bytes."""
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# ---------------------------------------------------------------------------
# Inc 8b (E4): save-as trees — sub-folders at depth, links and junctions at
# depth, a links-only folder, bulk files for the copy ceiling, nested empty
# folders for the entry ceiling, a deep path, Windows-unreadable names, an
# own A2L, a second MAC / A2L, an oversize file. Stdlib only; junctions
# through ``b100_links.create_junction``; Save project only through the
# shipped handler (``save_case01_project``, LED .42).
# ---------------------------------------------------------------------------

#: One file in each project home of LLR-171.1 plus a nested one: relative
#: POSIX path -> distinct bytes (a wrong copy is visible by digest).
SUBFOLDER_FILES = {
    "flows/f1.json": b'{"blocks": [], "tag": "f1"}',
    "flowsets/s1.json": b'{"set": "s1"}',
    "patches/boost.json": b'{"entries": [], "tag": "boost"}',
    "checks/ck.json": b'{"entries": [], "tag": "ck"}',
    "reports/r.md": b"# report r\n",
    "templates/t.json": b'{"template": "t"}',
    "splits/part.bin": bytes(range(64)),
    "reports/2026/r2.md": b"# nested report r2\n",
}

#: AT-B100-09's three named files.
AT09_FILES = {
    key: SUBFOLDER_FILES[key] for key in ("flows/f1.json", "patches/boost.json", "reports/r.md")
}


def write_tree(project_dir: Path, files: dict) -> dict:
    """Write ``files`` (relative POSIX -> bytes) under ``project_dir``."""
    for relative, payload in files.items():
        target = project_dir.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return files


def build_save_as_project(
    base: Path,
    name: str = "P",
    *,
    sub_files: Optional[dict] = None,
    top_files: Optional[dict] = None,
    data_files: Iterable[str] = ("firmware.s19",),
) -> Path:
    """Project ``name`` saved by the shipped Save project (case_01's
    ``data_files``), then ``sub_files`` (default :data:`SUBFOLDER_FILES`)
    and ``top_files`` written beside it on disk. Returns the folder."""
    project_dir = save_case01_project(base, name, files=tuple(data_files))
    write_tree(project_dir, SUBFOLDER_FILES if sub_files is None else sub_files)
    write_tree(project_dir, top_files or {})
    return project_dir


def outside_folder(base: Path, name: str = "outside") -> Path:
    """A plain folder outside every work area holding ``secret.txt`` and
    ``secret.json``."""
    folder = base.parent / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "secret.txt").write_bytes(b"outside secret")
    (folder / "secret.json").write_bytes(b'{"outside": true}')
    return folder


def add_junctions(project_dir: Path, target: Path, names: Iterable[str]) -> list:
    """One directory junction to ``target`` per relative name."""
    from tests.support.b100_links import create_junction

    made = []
    for relative in names:
        link = project_dir.joinpath(*PurePosixPath(relative).parts)
        link.parent.mkdir(parents=True, exist_ok=True)
        create_junction(link, target)
        made.append(relative)
    return made


def add_three_links(project_dir: Path, outside: Path) -> tuple:
    """LLR-171.1a/b/c's three links: the top-level junction ``linked`` and
    the nested junction ``reports/j`` to ``outside``, and the file symbolic
    link ``patches/l.json`` to ``outside/secret.json``. Raises ``OSError``
    when a link cannot be made (the caller reports the arm as not run)."""
    import os

    add_junctions(project_dir, outside, ["linked", "reports/j"])
    (project_dir / "patches").mkdir(exist_ok=True)
    os.symlink(outside / "secret.json", project_dir / "patches" / "l.json")
    return ("linked", "reports/j", "patches/l.json")


def bulk_files(project_dir: Path, folder: str, count: int, start: int = 0) -> list:
    """``count`` one-byte files ``<folder>/b<NNNNN>.txt``."""
    home = project_dir.joinpath(*PurePosixPath(folder).parts)
    home.mkdir(parents=True, exist_ok=True)
    names = []
    for index in range(start, start + count):
        (home / f"b{index:05d}.txt").write_bytes(b"x")
        names.append(f"{folder}/b{index:05d}.txt")
    return names


def nested_empty_folders(project_dir: Path, total: int, folder: str = "reports") -> None:
    """``total`` empty folders below ``project_dir/folder`` (created, not
    counted), nested two levels — groups ``g<NNN>`` of up to 100 leaves —
    so a walk must OPEN folders, not only list one (R16)."""
    root = project_dir / folder
    root.mkdir(parents=True, exist_ok=True)
    made = 0
    group = 0
    while made < total:
        group_dir = root / f"g{group:03d}"
        group_dir.mkdir()
        made += 1
        leaf = 0
        while made < total and leaf < 100:
            (group_dir / f"d{leaf:03d}").mkdir()
            made += 1
            leaf += 1
        group += 1


def _is_link(entry) -> bool:
    # ``DirEntry.is_junction`` is 3.12+; on 3.11 a junction is read from
    # the reparse-point attribute of ``os.lstat``.
    import os
    import stat

    if entry.is_symlink():
        return True
    attributes = getattr(os.lstat(entry.path), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def walked_entries(project_dir: Path) -> int:
    """Entries below ``project_dir`` (folders, files, links; the root not
    counted), never following a link — the entry-ceiling fixture's oracle."""
    import os

    count = 0
    stack = [project_dir]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                count += 1
                if not _is_link(entry) and entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
    return count


def deep_file(project_dir: Path, components: int, folder: str = "reports") -> str:
    """A file whose project-relative path has exactly ``components`` parts."""
    parts = [folder] + ["a"] * (components - 2) + ["f.md"]
    target = project_dir.joinpath(*parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"deep")
    return "/".join(parts)


EXTENDED_PREFIX = "\\\\?\\"


def write_unnormalised(path: Path, payload: bytes = b"{}") -> None:
    """Write a file Windows cannot open by its normal path (a trailing dot,
    a reserved device stem) through the extended-length form. Raises
    ``OSError`` where the platform refuses the name."""
    with open(EXTENDED_PREFIX + str(path), "wb") as handle:
        handle.write(payload)


def remove_unnormalised(path: Path) -> None:
    import os

    try:
        os.remove(EXTENDED_PREFIX + str(path))
    except OSError:
        pass


def tree_digests(root: Path) -> dict:
    """Every regular file under ``root`` reached without a link (relative
    POSIX -> SHA-256): LLR-171.1f's (path, digest) set."""
    import hashlib
    import os

    found = {}
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                if _is_link(entry):
                    continue
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    found[path.relative_to(root).as_posix()] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
    return found


def save_as_total(sizes: Iterable[int], new_target: bool = True) -> int:
    """R7's free-space total, computed independently of the app: each size
    rounded up to a multiple of 4 096, plus 65 536 once for a new target."""
    total = sum(-(-size // 4096) * 4096 for size in sizes)
    return total + (65536 if new_target else 0)


def other_work_area_project(base: Path, name: str = "R") -> Path:
    """A project ``name`` saved in ANOTHER app root's work area (``base``
    must differ from the test's app root); returns its folder."""
    return save_case01_project(base, name, files=("firmware.s19",))
