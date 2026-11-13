"""s19_app.tui.app.deps — test seam (D1) (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
from datetime import datetime
from typing import Optional, Tuple
from textual.widgets import Label, ListItem
from ...core import S19File
from ...hexfile import IntelHexFile
from ..a2l_parse import parse_a2l_file
from ..changes.verify import verify_written_image
from ...render.hexview import find_string_in_mem, render_hex_view_text
from ..changes.apply import render_patched_image, save_patched_image
from ..changes.io import parse_change_document, write_change_document
from ..os_clipboard_input import _mirror_and_write_os_clipboard
from ..services.before_after_service import compose_before_after_report
from ..services.compare_service import compare_images
from ..services.diff_report_service import generate_diff_report, generate_diff_report_html
from ..services.load_service import build_loaded_s19
from ..services.report_service import generate_project_report
from ..services.manifest_writer import (
    check_project_files,
    verify_written_manifest,
    write_project_manifest,
)
from ..services.project_gather_service import (
    SavePlan,
    gather_project_artifacts,
    inventory_project_tree,
    plan_project_save,
)
from ..a2l import A2LProgress
from ..services.variant_execution_service import (
    _KEY_ACTIVE_DOCUMENT,
    compose_load_announcement,
    read_project_manifest,
)
from ..workspace import (
    _is_reparse_point,
    _private_stage_dir,
    HEX_EXTENSIONS,
    S19_EXTENSIONS,
    copy_into_workarea,
    place_into_workarea,
    resolve_input_path,
    validate_project_files,
)
from .shared import (
    A2LCacheEntry,
    _LOG,
    REOPEN_MAX_BYTES,
    REOPEN_MAX_ENTRIES,
    DOCUMENT_OK,
    DOCUMENT_MISSING,
    DOCUMENT_LINK,
    DOCUMENT_TOO_LARGE,
    DOCUMENT_UNREADABLE,
    DOCUMENT_IO_ERROR,
    _DOCUMENT_FILE_FAULT_CODES,
    _DOCUMENT_PARSE_ERRORS,
    RecordedDocumentState,
)


def parse_a2l_cached(
    path: Path,
    cached: Optional[A2LCacheEntry],
    progress: Optional[A2LProgress] = None,
) -> A2LCacheEntry:
    """Parse an A2L once per unchanged file, else return the cached entry.

    Summary:
        The 12b cache seam (S-h, LLR-177.1d / .1e): stat the file, return
        the given entry unchanged on a key match (a hit, no parse), else
        parse with ``parse_a2l_file`` — with ``progress=`` only when a
        callback is given (fixed Q-f2: the no-callback call is the real
        main-thread / file-load path). Pure and module-level: it reads no
        ``self`` and writes nothing; an exception from ``stat`` or the parse
        propagates to the caller.

    Args:
        path (Path): The A2L file.
        cached (Optional[A2LCacheEntry]): The current entry, or ``None``.
        progress (Optional[A2LProgress]): The worker-side byte callback.

    Returns:
        A2LCacheEntry: ``((resolved path, mtime_ns, size), parsed payload)``.

    Data Flow:
        - ``key = (str(path.resolve()), st.st_mtime_ns, st.st_size)``.
        - A matching ``cached[0]`` returns ``cached`` itself (``is``).
        - Else parse and return ``(key, parse_a2l_file(...))``.

    Dependencies:
        Uses:
            - parse_a2l_file (the app module's global; tests monkeypatch it)
        Used by:
            - _prepare_project_load / _parse_loaded_file / _a2l_attach_worker
    """
    st = path.stat()
    key = (str(path.resolve()), st.st_mtime_ns, st.st_size)
    if cached is not None and cached[0] == key:
        _LOG.info("A2L cache hit: path=%s size_bytes=%d", path, st.st_size)
        return cached
    _LOG.info("A2L cache miss: path=%s size_bytes=%d", path, st.st_size)
    data = (
        parse_a2l_file(path, progress=progress)
        if progress is not None
        else parse_a2l_file(path)
    )
    return (key, data)
#: The full-path limit the Save project name check guards (LLR-164.3, the
#: ``_MAX_FULL_PATH`` idiom): ``len(workarea) + 1 + len(name) + 53`` must
#: stay at or under this bound.
_SAVE_FULL_PATH_LIMIT = 259


def _image_map(path: Path) -> dict[int, int]:
    """
    Summary:
        The data of one S19 or HEX image file, read with the core parsers —
        the base side of a ``derived_from`` count (LLR-168.4).

    Args:
        path (Path): The image file.

    Returns:
        dict[int, int]: Address -> byte.

    Raises:
        OSError: The file cannot be read.
        ValueError: The suffix is not an S19 or HEX one.
    """
    suffix = path.suffix.lower()
    if suffix in S19_EXTENSIONS:
        return S19File(str(path)).get_memory_map()
    if suffix in HEX_EXTENSIONS:
        return dict(IntelHexFile(str(path)).memory)
    raise ValueError(f"not an S19 or HEX image: {path.name}")


def _file_digest(path: Path) -> Tuple[str, int]:
    """
    Summary:
        The SHA-256 hex digest and size of one file a Save project copies —
        the plan's input (LLR-167.6), computed by the app so the planner
        hashes nothing.

    Args:
        path (Path): The file.

    Returns:
        Tuple[str, int]: ``(digest, size)``.

    Raises:
        OSError: The file cannot be read. A read error that names no file
            (a byte-range lock fails the read, not the open) is given
            ``path`` as its ``filename``, so the refusal can name it.
    """
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        if exc.filename is None:
            exc.filename = str(path)
        raise
    return digest.hexdigest(), size


def _plan_without_document_key(plan: SavePlan) -> SavePlan:
    """The save plan once the change document is known not to be
    recorded (LLR-167.6, review F4): the same rows, ``project.json``'s keys
    without ``active_document``, so the plan lists the keys the save
    writes."""
    return replace(
        plan,
        manifest_keys=tuple(
            key for key in plan.manifest_keys if key != _KEY_ACTIVE_DOCUMENT
        ),
    )


def _is_link_stat(result: os.stat_result) -> bool:
    """True when an ``os.lstat`` result is a symbolic link or a reparse
    point (a junction on Windows)."""
    attributes = getattr(result, "st_file_attributes", 0)
    return stat.S_ISLNK(result.st_mode) or bool(
        attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def recorded_document_state(
    project_dir: Path, text: str, a2l_context: Optional[dict] = None
) -> RecordedDocumentState:
    """
    Summary:
        The ONE classifier of a recorded ``active_document`` (E3 R10,
        LLR-170.3, LLR-164.2): reads the file once and says whether it is a
        change or check document the app can reopen. Load reopens through
        it and Save project decides its drop with it, so a file Load lists
        as ``not readable`` is the same file Save project judges. Holds no
        app state, never touches a ``ChangeService`` and never raises.

    Args:
        project_dir (Path): The project folder (unresolved; never
            ``resolve()``-d here).
        text (str): The recorded project-relative POSIX text, one the
            reader accepted (``is_active_document_form`` True), e.g.
            ``"patches/boost.json"``.
        a2l_context (Optional[dict]): The project's parsed A2L payload, so
            symbol entries resolve; ``None`` for Save project. The outcome
            never depends on it (it only changes entry-level findings).

    Returns:
        RecordedDocumentState: ``ok`` with the parsed document, or
            ``missing``, ``link``, ``too_large``, ``unreadable``,
            ``io_error`` with no document.

    Data Flow:
        - ``os.lstat`` of the home, then of the file, on the absolute
          textual path: absent -> ``missing``; a link or reparse point ->
          ``link`` (0 bytes read); the home not a folder or the file not a
          regular file -> ``unreadable``; any other ``OSError`` ->
          ``io_error``.
        - ``st_size`` over :data:`REOPEN_MAX_BYTES` -> ``too_large``.
        - One bounded read of at most ``REOPEN_MAX_BYTES + 1`` bytes;
          ``OSError`` -> ``io_error``; more than the cap -> ``too_large``.
        - A guarded ``json.loads`` of THOSE bytes: an exception ->
          ``unreadable``; not an object or ``entries`` not a list ->
          ``unreadable``; more than :data:`REOPEN_MAX_ENTRIES` entries ->
          ``too_large``.
        - ``parse_change_document`` of the same bytes under the same catch
          set; a file-level code (E3 R17) -> ``unreadable``; else ``ok``.

    Dependencies:
        Uses:
            - changes.io.parse_change_document
        Used by:
            - S19TuiApp._reopen_active_document (Load)
            - S19TuiApp._handle_save_dialog (Save project's drop test)
    """
    home_name, _, file_name = text.partition("/")
    home = project_dir.absolute() / home_name
    path = home / file_name
    for item, expect_dir in ((home, True), (path, False)):
        try:
            found = os.lstat(item)
        except FileNotFoundError:
            return RecordedDocumentState(DOCUMENT_MISSING, detail="FileNotFoundError")
        except OSError as exc:
            return RecordedDocumentState(DOCUMENT_IO_ERROR, detail=type(exc).__name__)
        if _is_link_stat(found):
            return RecordedDocumentState(DOCUMENT_LINK, detail=f"link: {item.name}")
        is_expected = (
            stat.S_ISDIR(found.st_mode) if expect_dir else stat.S_ISREG(found.st_mode)
        )
        if not is_expected:
            return RecordedDocumentState(
                DOCUMENT_UNREADABLE, detail=f"not a regular entry: {item.name}"
            )
    if found.st_size > REOPEN_MAX_BYTES:
        return RecordedDocumentState(DOCUMENT_TOO_LARGE, detail=f"{found.st_size} bytes")
    try:
        with open(path, "rb") as handle:
            data = handle.read(REOPEN_MAX_BYTES + 1)
    except OSError as exc:
        return RecordedDocumentState(DOCUMENT_IO_ERROR, detail=type(exc).__name__)
    if len(data) > REOPEN_MAX_BYTES:
        return RecordedDocumentState(DOCUMENT_TOO_LARGE, detail="grew past the cap")
    try:
        top = json.loads(data)
    except _DOCUMENT_PARSE_ERRORS as exc:
        return RecordedDocumentState(DOCUMENT_UNREADABLE, detail=type(exc).__name__)
    entries = top.get("entries") if isinstance(top, dict) else None
    if not isinstance(entries, list):
        return RecordedDocumentState(
            DOCUMENT_UNREADABLE, detail="no entries list at the top level"
        )
    if len(entries) > REOPEN_MAX_ENTRIES:
        return RecordedDocumentState(
            DOCUMENT_TOO_LARGE, detail=f"{len(entries)} entries"
        )
    try:
        document = parse_change_document(data, a2l_context=a2l_context)
    except _DOCUMENT_PARSE_ERRORS as exc:
        return RecordedDocumentState(DOCUMENT_UNREADABLE, detail=type(exc).__name__)
    faults = sorted(
        {issue.code for issue in document.issues} & _DOCUMENT_FILE_FAULT_CODES
    )
    if faults:
        return RecordedDocumentState(DOCUMENT_UNREADABLE, detail=", ".join(faults))
    return RecordedDocumentState(DOCUMENT_OK, document=document)
