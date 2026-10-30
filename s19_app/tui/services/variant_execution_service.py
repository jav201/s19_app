"""
Variant execution service — batch / per-variant change+check execution (E6).

This module is the batch-07 E6 execution layer (HLR-006): it owns the
project **manifest** io (LLR-006.1 — placed here rather than in
``workspace.py`` because this service is the manifest's primary consumer and
the project-load override in ``app.py`` can import it without widening the
workspace surface), the **deterministic execution plan** (LLR-006.2), and
the **per-variant isolated execution loop** (LLR-006.3/006.4).

Manifest (``.s19tool/workarea/<project>/project.json``, LLR-006.1 + F-S-03):

- Read through a CAPPED path: an on-disk size probe and a bounded read
  (1 MiB, LLR-169.4) precede the parse, every manifest array is capped at
  1 000 entries, and the parse arm catches ``RecursionError`` alongside
  ``JSONDecodeError`` / ``UnicodeDecodeError`` — the ``changes/io.py``
  read-path pattern.
- ``batch`` / ``assignments`` entries resolve AGAINST THE PROJECT DIRECTORY
  ONLY — never through ``workspace.resolve_input_path``. An absolute path
  (either separator convention), a path resolving outside the project
  directory, or a path traversing a symlink / NTFS reparse point is ONE
  ERROR ``ValidationIssue`` and the entry is skipped (collect-don't-abort).
- A manifest that is absent yields ``None`` from
  :func:`read_project_manifest` — the caller falls back to batch mode over
  all variants (the LLR-006.1 default).

Execution (LLR-006.3..006.5):

- Each variant's image is parsed INSIDE the execution call via
  ``build_loaded_s19`` / ``build_loaded_hex`` — the TUI's active
  ``LoadedFile`` is never read or mutated. Variants run sequentially, one
  parsed image at a time; the image reference is dropped before the next
  variant parses.
- The service computes NO linkage and NO verdicts itself: every per-file
  outcome is the ``apply_change_document`` / ``run_check_document`` output,
  kind-discriminated (``kind == "check"`` runs checks; everything else goes
  to the apply engine, whose gate blocks non-``"change"`` documents). The
  ``variant_id`` is stamped through the engines' existing parameter.
- One failing variant never aborts the rest (LLR-006.4):
  ``len(results) == planned variant count`` always.
- Save-back is headless (LLR-002.7 headless parameter): when a change file
  applies ≥1 entry on an S19 variant, the patched image is written to the
  project directory under the default ``<variant_id>-patched.s19`` filename
  — no prompt in batch mode. HEX variants record a diagnostic instead (D-1).

This module imports stdlib + the parse layer + the ``changes`` package +
sibling services + ``validation.model`` only — **no Textual import**
(service-layer contract, constraint C-7; verified by the grep probe in the
E6 verification list and by ``tests/test_variant_execution.py``).
"""

from __future__ import annotations

import functools
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Callable, Optional, Sequence, Tuple, Union

from ...core import S19File
from ...hexfile import IntelHexFile
from ...validation.model import ValidationIssue, ValidationSeverity
from ..a2l_parse import parse_a2l_file
from ..changes import (
    ChangeSummary,
    apply_change_document,
    read_change_document,
    save_patched_image,
)
from ..changes.check import run_check_document
from ..changes.model import CheckRunResult
from ..mac import parse_mac_file
from ..models import ProjectVariantSet, VariantDescriptor
from .report_addendum import DeclaredRegion
from ..workspace import (
    A2L_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    _path_traverses_reparse_point,
    is_windows_device_name,
    validate_project_files,
)
from .a2l_service import enrich_tags_and_render
from .load_service import build_loaded_hex, build_loaded_s19

#: The on-disk manifest filename inside a project directory (LLR-006.1).
#: ``.json`` is already ignored by ``workspace.validate_project_files``, so
#: the manifest never registers as project data.
PROJECT_MANIFEST_NAME = "project.json"

#: The manifest read cap (LLR-169.4): ``project.json`` is untrusted input,
#: and 1 MiB holds far more than any project the app writes.
MANIFEST_SIZE_CAP_BYTES = 1 << 20

#: The most entries the reader parses in each manifest array (``batch``,
#: ``declared_regions``, ``gathered``, ``files``, ``derived_from``) and in
#: all ``assignments`` lists together, and the most ``assignments`` keys
#: (LLR-169.4; P-40: an uncapped array of 75 677 entries read in 14.92 s).
MANIFEST_ENTRY_CAP = 1000

#: The most skipped manifest entries a read reports one by one; the rest
#: are folded into one finding that counts them (SEC6-5).
MANIFEST_ENTRY_ROWS = 100

#: The most distinct FOLDERS one manifest read (or one serialize) checks
#: with a filesystem call (SEC6-5, SEC7-1, R2-2). Each distinct folder or
#: file an entry names costs at most one ``os.lstat`` per read; the file an
#: entry ends on is always checked (the entry caps bound those calls), and
#: only an entry that needs a folder check past this ceiling is skipped
#: unchecked and counted in the fold finding.
MANIFEST_FOLDER_CHECK_CAP = MANIFEST_ENTRY_CAP

#: The most problem rows a Load announcement lists one by one (F2, SEC6-5):
#: the reader's entry rows, its fold row and one manifest-level row always
#: fit; any further problem is counted in one more row.
LOAD_PROBLEM_ROWS = MANIFEST_ENTRY_ROWS + 2

#: The project files ``files`` and ``derived_from`` may name: top-level
#: files with a project data or A2L suffix (O-2).
PROJECT_RECORDED_SUFFIXES = frozenset(PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS)

#: The two modes of :func:`_resolve_manifest_entry` (B100-I21). The
#: manifest-keys mode also refuses drive-relative, stream and device names;
#: only the manifest reader and the writer's refusal predicate use it, so
#: flow references keep the default (P-41).
ENTRY_MODE_DEFAULT = "default"
ENTRY_MODE_MANIFEST_KEYS = "manifest-keys"

#: The top-level keys this version reads and carries; any other key is
#: recorded in ``ProjectManifest.unknown_keys`` so no rewrite drops it
#: silently (SEC6-2).
KNOWN_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "active_variant",
        "batch",
        "assignments",
        "declared_regions",
        "gathered",
        "files",
        "derived_from",
    }
)

#: The ``schema_version`` this version writes; a manifest carrying another
#: one is never rewritten by an in-project writer (SEC6-2).
SUPPORTED_SCHEMA_VERSION = 1

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

#: ``ValidationIssue.artifact`` tag for every manifest finding.
MANIFEST_ARTIFACT = "manifest"

#: Manifest read-path: the file exceeds the pre-parse size cap.
MANIFEST_SIZE_CAP = "MANIFEST-SIZE-CAP"
#: Manifest read-path: not well-formed JSON (including parser recursion
#: overflow) or unreadable.
MANIFEST_JSON_PARSE = "MANIFEST-JSON-PARSE"
#: Manifest read-path: well-formed JSON whose structure is not the manifest
#: envelope (non-object top level, non-array ``batch``, non-object
#: ``assignments``, non-string entry).
MANIFEST_BAD_STRUCTURE = "MANIFEST-BAD-STRUCTURE"
#: Manifest read-path: a ``batch`` / ``assignments`` entry is absolute,
#: resolves outside the project directory, or traverses a reparse point
#: (F-S-03) — the entry is skipped.
MANIFEST_PATH_ESCAPE = "MANIFEST-PATH-ESCAPE"

#: ``ValidationIssue.details`` marks of a manifest finding (LLR-178.1): the
#: ``"entry"`` a skipped entry recorded, so the Load-result panel names it,
#: and ``"scope": "manifest"`` on the one structure finding that voids the
#: whole manifest (a top level that is not an object), so the finding is
#: recognised by a mark, never by its message text.
_ISSUE_ENTRY = "entry"
_ISSUE_SCOPE = "scope"
_SCOPE_MANIFEST = "manifest"
#: The user-term reason a finding carries when its code alone would word
#: it wrongly (a device name is not "outside the project"; an over-cap
#: array is not "not an object"), so the panel never parses a message.
_ISSUE_REASON = "reason"
#: The user-term reason of an entry that is no usable plain path in the
#: project (a NUL, a drive or stream name, a device name, a path too long).
_REASON_UNUSABLE = "a file path is not a plain name in the project"
#: The longest recorded entry a finding keeps (characters, ellipsis
#: included): a manifest entry is any JSON value, so the panel row naming it
#: stays one readable row (SEC6-7).
_ENTRY_CLIP = 120
#: The longest entry a manifest may record (characters): the Windows path
#: maximum. A longer entry is skipped on the text, before any filesystem
#: call, so the decision is the same on every platform (CI-6-1: on Linux
#: ``resolve()`` does not raise for a 40 000-character entry).
MANIFEST_ENTRY_MAX_CHARS = 32_767
#: The most path components a manifest entry may have in the manifest-keys
#: mode (SEC7-1): a deeper entry is refused on the text, so a manifest of
#: very deep entries costs one count per entry, not work per component.
MANIFEST_ENTRY_MAX_PARTS = 32

#: The three execution scopes of the E6 TUI trigger (LLR-006.6).
SCOPE_ACTIVE = "active"
SCOPE_ALL = "all"
SCOPE_ASSIGNMENTS = "assignments"
EXECUTION_SCOPES: tuple[str, ...] = (SCOPE_ACTIVE, SCOPE_ALL, SCOPE_ASSIGNMENTS)

#: Per-variant outcome tokens (LLR-006.4).
VARIANT_STATUS_OK = "ok"
VARIANT_STATUS_ERROR = "error"

#: The size-probe seam — injectable so a test can report an over-cap byte
#: size without manufacturing a real 256 MB file (the ``changes/io.py``
#: ``SizeProbe`` pattern).
SizeProbe = Callable[[Path], int]

#: The between-variant status sink (F-Q-18): the TUI worker passes a
#: ``call_from_thread``-wrapped ``set_status``; headless callers pass None.
StatusCallback = Callable[[str], None]


def _manifest_issue(
    code: str,
    message: str,
    severity: ValidationSeverity = ValidationSeverity.ERROR,
    details: Optional[dict[str, str]] = None,
) -> ValidationIssue:
    """
    Summary:
        Build one manifest ``ValidationIssue`` tagged
        ``artifact=MANIFEST_ARTIFACT``.

    Args:
        code (str): The ``MANIFEST-*`` rule code.
        message (str): Human-readable finding — names paths and counts only.
        severity (ValidationSeverity): Defaults to ERROR (every manifest
            read rule is an ERROR per F-S-03).
        details (Optional[dict[str, str]]): The finding's marks
            (``_ISSUE_ENTRY`` / ``_ISSUE_SCOPE``); ``None`` -> none.

    Returns:
        ValidationIssue: The finding.

    Dependencies:
        Used by:
            - read_project_manifest / _resolve_manifest_entry
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=MANIFEST_ARTIFACT,
        details=dict(details or {}),
    )


@dataclass(frozen=True)
class FileRecord:
    """
    Summary:
        One ``files`` record of ``project.json`` (LLR-169.1, B100-I1): the
        size and the SHA-256 file digest of a project file as the manifest
        seam found it on disk.

    Args:
        size (int): The file size in bytes.
        sha256 (str): 64 lowercase hex characters.
    """

    size: int
    sha256: str


@dataclass(frozen=True)
class DerivedFrom:
    """
    Summary:
        One ``derived_from`` record (LLR-168.4, B100-I16): the base image a
        patched variant was derived from, by file name and file digest, and
        how many bytes of data differ from it — computed at the write, so it
        survives without the base.

    Args:
        base (str): The base image's file name (one path component).
        sha256 (str): The base file's SHA-256, 64 lowercase hex characters.
        differ (int): How many addresses hold a different byte, or exist in
            only one of the two images.
    """

    base: str
    sha256: str
    differ: int


@dataclass(slots=True)
class ProjectManifest:
    """
    Summary:
        The parsed per-project manifest (LLR-006.1) — the schema version,
        the recorded active variant, the project-wide ``batch`` file list,
        and the per-variant ``assignments`` map, plus every finding the
        capped read collected.

    Args:
        schema_version (Union[int, float, str, None]): The
            ``schema_version`` scalar as found (a ``bool`` included);
            ``None`` when absent or not a scalar.
        active_variant (Optional[str]): The recorded active variant id, or
            ``None`` when absent — the project-load override of LLR-005.6.
        batch (list[Path]): Resolved, project-contained change/check file
            paths in MANIFEST ORDER (LLR-006.2 inner order, first half).
            Entries that failed containment are skipped, not carried.
        assignments (dict[str, list[Path]]): Per-variant resolved file paths
            in manifest order (LLR-006.2 inner order, second half), keyed by
            ``variant_id``.
        declared_regions (Tuple[DeclaredRegion, ...]): The operator-declared
            memory regions (LLR-026.1).
        gathered (dict[str, list[Path]]): The change-1 gather rows (HLR-138)
            — project home -> resolved paths in manifest order (LLR-168.1,
            B100-I2), so a writer can rewrite the manifest with them
            carried.
        issues (list[ValidationIssue]): Every collected size / parse /
            structure / containment finding (collect-don't-abort).
        files (dict[Path, FileRecord]): The ``files`` records (LLR-169.4),
            keyed by the resolved project file.
        derived_from (dict[Path, DerivedFrom]): The ``derived_from``
            records (LLR-168.4), keyed by the resolved variant file.
        unknown_keys (Tuple[str, ...]): Top-level keys this version does
            not read, so an in-project rewrite never drops them silently
            (SEC6-2).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`read_project_manifest`.
        - Consumed by :func:`plan_variant_executions` (file mapping) and by
          ``app.py::_handle_load_project`` (the ``active_variant`` override).

    Dependencies:
        Used by:
            - read_project_manifest
            - plan_variant_executions
            - s19_app.tui.app.S19TuiApp (project load + execute_scope)
    """

    schema_version: Union[int, float, str, None]
    active_variant: Optional[str]
    batch: list[Path] = field(default_factory=list)
    assignments: dict[str, list[Path]] = field(default_factory=dict)
    declared_regions: Tuple[DeclaredRegion, ...] = ()
    gathered: dict[str, list[Path]] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)
    files: dict[Path, FileRecord] = field(default_factory=dict)
    derived_from: dict[Path, DerivedFrom] = field(default_factory=dict)
    unknown_keys: Tuple[str, ...] = ()


def _entry_mark(entry: str) -> dict[str, str]:
    """The ``details`` mark naming a skipped entry, clipped to
    ``_ENTRY_CLIP`` characters with an ellipsis (SEC6-7)."""
    return {_ISSUE_ENTRY: _clip(entry, _ENTRY_CLIP)}


def _manifest_key_refusal(entry: str) -> Optional[str]:
    """
    Summary:
        The manifest-keys mode's extra rule (LLR-169.8, S-09): why ``entry``
        is not a plain project-relative name, or ``None`` when it is.

    Args:
        entry (str): The entry exactly as recorded (not stripped, so a
            trailing space is seen).

    Returns:
        Optional[str]: The refusal in log terms, or ``None``.

    Data Flow:
        - A drive or a root (``PureWindowsPath``), so ``C:x.s19``, UNC and
          ``\\\\?\\`` names are refused on every platform.
        - A ``:`` anywhere (a drive or an alternate stream name).
        - Per path component (either separator): a trailing dot or space,
          or a Windows device name with or without an extension
          (``is_windows_device_name``). ``.`` and ``..`` are left to the
          containment check, which reports an escape as an escape.

    Dependencies:
        Uses:
            - workspace.is_windows_device_name
        Used by:
            - _resolve_manifest_entry (manifest-keys mode only)
    """
    windows = PureWindowsPath(entry)
    if windows.drive or windows.root:
        return "has a drive or a root"
    if ":" in entry:
        return "carries a ':' (a drive or a stream name)"
    for component in re.split(r"[\\/]", entry):
        refusal = _component_refusal(component)
        if refusal is not None:
            return refusal
    return None


@functools.lru_cache(maxsize=8192)
def _component_refusal(component: str) -> Optional[str]:
    """:func:`_manifest_key_refusal`'s rule for one path component, cached:
    folder names repeat across a manifest's entries (SEC7-R2-2)."""
    if component in (".", ".."):
        # left to the containment check, which words an escape as one
        return None
    if component.endswith((".", " ")):
        return f"has a path component ending in a dot or a space: {component!r}"
    if is_windows_device_name(component):
        return f"names a device: {component!r}"
    return None


def _climbs_above_root(entry: str) -> bool:
    """True when the ``..`` components of ``entry`` climb above the folder
    it is relative to — an escape decided on the text alone, so a hostile
    manifest of escaping entries costs no filesystem call (SEC6-5)."""
    depth = 0
    for component in re.split(r"[\\/]", entry):
        if component in ("", "."):
            continue
        depth += -1 if component == ".." else 1
        if depth < 0:
            return True
    return False


#: What :class:`_EntryWalk` found for one entry.
_PATH_PRESENT = "present"
_PATH_MISSING = "missing"
_PATH_LINK = "link"
_PATH_UNUSABLE = "unusable"
_PATH_UNCHECKED = "unchecked"


def _lstat_state(path: Path) -> str:
    """One ``os.lstat`` of ``path``: present, missing, a link or junction,
    or unusable (any other error)."""
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return _PATH_MISSING
    except (OSError, ValueError):
        return _PATH_UNUSABLE
    if stat.S_ISLNK(info.st_mode) or (
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return _PATH_LINK
    return _PATH_PRESENT


class _EntryWalk:
    """
    Summary:
        The filesystem side of one manifest read's entry checks (SEC6-5,
        SEC7-1). An entry is walked from the project folder one component at
        a time with ``os.lstat``, never ``resolve()``: the walk stops at the
        first missing component (nothing below it exists, so the entry
        stays inside) and refuses at the first link or junction. Each
        distinct folder or file costs at most one call per read, so a
        junction loop costs one call. The cache keys a component by its
        exact text, never case-folded: a case-sensitive folder holds
        ``sub`` and ``SUB`` as two objects (SEC7-R2-1). At most
        :data:`MANIFEST_FOLDER_CHECK_CAP` folder calls are made; the file
        an entry ends on is always checked.

    Args:
        project_root (Path): The resolved project folder.
    """

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.folder_calls = 0
        self.unchecked = 0
        # node 0 is the project folder; per node, its component -> child node
        self._children: list[dict[str, int]] = [{}]
        self._states: list[str] = [_PATH_PRESENT]
        self._paths: list[Path] = [project_root]

    def check(self, parts: Sequence[str]) -> Tuple[str, Optional[Path]]:
        """The state of the first component of ``parts`` that is not a
        present folder or file, else present; unchecked when a needed call
        is past the folder ceiling. With it, the project folder joined
        with ``parts`` when the state is present or missing."""
        node = 0
        last = len(parts) - 1
        for index, part in enumerate(parts):
            children = self._children[node]
            child = children.get(part)
            if child is None:
                if index < last:
                    if self.folder_calls >= MANIFEST_FOLDER_CHECK_CAP:
                        return _PATH_UNCHECKED, None
                    self.folder_calls += 1
                child = len(self._states)
                path = self._paths[node] / part
                self._states.append(_lstat_state(path))
                self._paths.append(path)
                self._children.append({})
                children[part] = child
            state = self._states[child]
            if state == _PATH_MISSING:
                if index == last:
                    return state, self._paths[child]
                return state, self._paths[child].joinpath(*parts[index + 1 :])
            if state != _PATH_PRESENT:
                return state, None
            node = child
        return _PATH_PRESENT, self._paths[node]


def _entry_text(
    raw_entry: object,
    context: str,
    issues: list[ValidationIssue],
    mode: str,
) -> Optional[str]:
    """
    Summary:
        Every check of one manifest entry that needs no filesystem call
        (F-S-03, LLR-169.8, CI-6-1, SEC6-5): the entry text to resolve, or
        ``None`` with one finding appended.

    Args:
        raw_entry (object): The JSON entry value.
        context (str): Display context for the finding message.
        issues (list[ValidationIssue]): Appended in place.
        mode (str): :data:`ENTRY_MODE_DEFAULT` or
            :data:`ENTRY_MODE_MANIFEST_KEYS`.

    Returns:
        Optional[str]: The stripped entry, or ``None`` when refused.

    Dependencies:
        Used by:
            - _resolve_manifest_entry / _recorded_file
    """
    if not isinstance(raw_entry, str) or not raw_entry.strip():
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                f"manifest {context} entry is not a path string - entry "
                "skipped",
                details=_entry_mark(json.dumps(raw_entry)),
            )
        )
        return None
    if len(raw_entry) > MANIFEST_ENTRY_MAX_CHARS:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry is longer than "
                f"{MANIFEST_ENTRY_MAX_CHARS} characters - entry skipped",
                details={**_entry_mark(raw_entry), _ISSUE_REASON: _REASON_UNUSABLE},
            )
        )
        return None
    if (
        mode == ENTRY_MODE_MANIFEST_KEYS
        and raw_entry.count("/") + raw_entry.count("\\") >= MANIFEST_ENTRY_MAX_PARTS
    ):
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry has more than "
                f"{MANIFEST_ENTRY_MAX_PARTS} path components - entry skipped",
                details={**_entry_mark(raw_entry), _ISSUE_REASON: _REASON_UNUSABLE},
            )
        )
        return None
    if mode == ENTRY_MODE_MANIFEST_KEYS and "\x00" not in raw_entry:
        refusal = _manifest_key_refusal(raw_entry)
        if refusal is not None:
            issues.append(
                _manifest_issue(
                    MANIFEST_PATH_ESCAPE,
                    f"manifest {context} entry {refusal} - entry skipped: "
                    f"{raw_entry!r}",
                    details={**_entry_mark(raw_entry), _ISSUE_REASON: _REASON_UNUSABLE},
                )
            )
            return None
    text = raw_entry.strip()
    if mode == ENTRY_MODE_MANIFEST_KEYS and _climbs_above_root(text):
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry escapes the project directory - "
                f"entry skipped: {text!r}",
                details=_entry_mark(text),
            )
        )
        return None
    if "\x00" in text:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry carries a NUL character - not a "
                f"path; entry skipped: {text!r}",
                details={**_entry_mark(text), _ISSUE_REASON: _REASON_UNUSABLE},
            )
        )
        return None
    # PurePosixPath(text).is_absolute() is exactly text.startswith("/").
    if PureWindowsPath(text).is_absolute() or text.startswith("/"):
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry is an absolute path - entries "
                f"resolve against the project directory only; entry "
                f"skipped: {text!r}",
                details=_entry_mark(text),
            )
        )
        return None
    return text


def _walk_manifest_entry(
    walk: _EntryWalk,
    text: str,
    context: str,
    issues: list[ValidationIssue],
) -> Optional[Path]:
    """
    Summary:
        The manifest-keys mode's filesystem check of one entry whose text
        passed (SEC7-1): ``.`` and ``..`` are applied to the text (they
        cannot climb above the project, :func:`_climbs_above_root`), then
        the components are walked with :class:`_EntryWalk`.

    Args:
        walk (_EntryWalk): The read's walk (cache, folder count, ceiling).
        text (str): The entry as :func:`_entry_text` returned it.
        context (str): Display context for the finding message.
        issues (list[ValidationIssue]): Appended in place.

    Returns:
        Optional[Path]: The project folder joined with the components, or
            ``None``: a link or junction on the way or an unusable name ->
            one ``MANIFEST-PATH-ESCAPE``; past the folder ceiling -> no
            finding, counted in ``walk.unchecked`` for the fold finding.

    Dependencies:
        Uses:
            - _EntryWalk
        Used by:
            - _resolve_manifest_entry / _recorded_file
    """
    parts: list[str] = []
    for component in re.split(r"[\\/]", text):
        if component in ("", "."):
            continue
        if component == "..":
            parts.pop()
        else:
            parts.append(component)
    state, path = walk.check(parts)
    if state == _PATH_UNCHECKED:
        walk.unchecked += 1
        return None
    if state == _PATH_LINK:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry traverses a symbolic link or "
                f"reparse point - entry skipped: {text!r}",
                details={
                    **_entry_mark(text),
                    _ISSUE_REASON: "a file path goes through a link or junction",
                },
            )
        )
        return None
    if state == _PATH_UNUSABLE:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry is not a usable path - entry skipped",
                details={**_entry_mark(text), _ISSUE_REASON: _REASON_UNUSABLE},
            )
        )
        return None
    return path


def _resolve_manifest_entry(
    project_root: Path,
    raw_entry: object,
    context: str,
    issues: list[ValidationIssue],
    mode: str = ENTRY_MODE_DEFAULT,
    walk: Optional[_EntryWalk] = None,
) -> Optional[Path]:
    """
    Summary:
        Resolve one ``batch`` / ``assignments`` entry against the project
        directory ONLY, enforcing the F-S-03 containment rules — an unsafe
        entry records exactly one ERROR finding and is skipped.

    Args:
        project_root (Path): The resolved project directory the entry must
            stay inside.
        raw_entry (object): The JSON entry value — must be a relative path
            string.
        context (str): Display context for the finding message (``"batch"``
            or ``"assignments[<id>]"``).
        issues (list[ValidationIssue]): The manifest's finding collector —
            appended in place.
        mode (str): :data:`ENTRY_MODE_DEFAULT` (flow references) or
            :data:`ENTRY_MODE_MANIFEST_KEYS` (the manifest reader and the
            writer's refusal predicate only, B100-I21).
        walk (Optional[_EntryWalk]): The manifest read's walk, shared by
            every entry of one read (manifest-keys mode); ``None`` -> a
            fresh one for this entry.

    Returns:
        Optional[Path]: The resolved absolute path inside the project
        directory, or ``None`` when the entry was skipped.

    Data Flow:
        - Non-string entry → one ``MANIFEST-BAD-STRUCTURE``.
        - An entry longer than :data:`MANIFEST_ENTRY_MAX_CHARS` → one
          ``MANIFEST-PATH-ESCAPE``, decided on the text in every mode and on
          every platform (CI-6-1).
        - Manifest-keys mode: :func:`_manifest_key_refusal` on the entry as
          recorded → one ``MANIFEST-PATH-ESCAPE`` (LLR-169.8); an entry
          whose ``..`` components climb above the project
          (:func:`_climbs_above_root`) is refused on the text alone.
        - An entry carrying a NUL character → one ``MANIFEST-PATH-ESCAPE``,
          before any ``resolve()`` (which would raise ``ValueError``;
          batch-97 LLR-146.14).
        - Absolute under EITHER separator convention (``PureWindowsPath`` /
          ``PurePosixPath``) → one ``MANIFEST-PATH-ESCAPE`` — checked before
          any filesystem touch so a drive-qualified path is refused on every
          platform.
        - Manifest-keys mode: more than :data:`MANIFEST_ENTRY_MAX_PARTS`
          path components → one ``MANIFEST-PATH-ESCAPE`` on the text
          (SEC7-1).
        - Every check above needs no filesystem call (:func:`_entry_text`).
        - Manifest-keys mode: the components are walked with ``os.lstat``
          (:func:`_walk_manifest_entry`, SEC7-1) — no ``resolve()``; a link
          or junction on the way, or an unusable name, gives one
          ``MANIFEST-PATH-ESCAPE``; an entry past the read's folder ceiling is
          skipped unchecked and counted in the fold finding.
        - Default mode: ``(project_root / entry).resolve()`` escaping
          ``project_root`` → one ``MANIFEST-PATH-ESCAPE``.
        - The resolved path traversing a symlink / NTFS reparse point below
          the project root → one ``MANIFEST-PATH-ESCAPE``
          (``workspace._path_traverses_reparse_point``, security finding
          S-N01 reuse).
        - ``resolve()`` or the reparse walk raising ``OSError`` /
          ``ValueError`` / ``RuntimeError`` (a path the OS cannot take, or a
          symlink / junction loop) → one ``MANIFEST-PATH-ESCAPE``, never an
          exception (SEC6-7; the fallback behind the length rule).
        - Every finding marks the recorded entry, clipped to
          ``_ENTRY_CLIP`` characters (:func:`_entry_mark`).
        - Existence is NOT checked here: a missing file surfaces later as
          the per-file ``MF-PATH-UNRESOLVED`` finding of the shared reader.

    Dependencies:
        Uses:
            - workspace._path_traverses_reparse_point
            - _manifest_issue
        Used by:
            - read_project_manifest
    """
    text = _entry_text(raw_entry, context, issues, mode)
    if text is None:
        return None
    if mode == ENTRY_MODE_MANIFEST_KEYS:
        return _walk_manifest_entry(
            walk if walk is not None else _EntryWalk(project_root), text, context, issues
        )
    try:
        resolved = (project_root / text).resolve()
        escapes = not resolved.is_relative_to(project_root)
        traverses = not escapes and _path_traverses_reparse_point(
            resolved, stop_at=project_root
        )
    except (OSError, ValueError, RuntimeError) as exc:
        # SEC6-7: an entry the OS cannot resolve (on Windows a path over
        # ~32 760 characters raises ValueError; a junction that points to
        # itself raises RuntimeError) is skipped, never raised.
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry is not a usable path "
                f"({type(exc).__name__}) - entry skipped",
                details={**_entry_mark(text), _ISSUE_REASON: _REASON_UNUSABLE},
            )
        )
        return None
    if escapes:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry escapes the project directory - "
                f"entry skipped: {text!r}",
                details=_entry_mark(text),
            )
        )
        return None
    if traverses:
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry traverses a symbolic link or "
                f"reparse point - entry skipped: {text!r}",
                details={
                    **_entry_mark(text),
                    _ISSUE_REASON: "a file path goes through a link or junction",
                },
            )
        )
        return None
    return resolved


def _parse_manifest_declared_regions(
    raw: object,
    issues: list[ValidationIssue],
) -> Tuple[DeclaredRegion, ...]:
    """
    Summary:
        Parse the OPTIONAL ``declared_regions`` manifest key (LLR-026.1) into
        :class:`DeclaredRegion` rows. Absent/empty → ``()`` with no finding
        (back-compat). A non-array value, or a malformed/invalid entry (not an
        object, missing/ill-typed ``name``/``start``/``end``, or rejected by
        ``DeclaredRegion`` validation), emits one ``MANIFEST-BAD-STRUCTURE``
        finding and is skipped — collect-don't-abort, matching ``batch`` /
        ``assignments`` parsing.

    Args:
        raw (object): The value of the manifest ``declared_regions`` key
            (``payload.get("declared_regions", [])``).
        issues (list[ValidationIssue]): The accumulating finding list; mutated.

    Returns:
        Tuple[DeclaredRegion, ...]: The successfully parsed regions, in order.

    Dependencies:
        Uses:
            - DeclaredRegion / _manifest_issue
        Used by:
            - read_project_manifest
    """
    if not isinstance(raw, list):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest declared_regions is not an array - ignored",
            )
        )
        return ()
    regions: list[DeclaredRegion] = []
    for entry in raw:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not isinstance(entry.get("start"), int)
            or isinstance(entry.get("start"), bool)
            or not isinstance(entry.get("end"), int)
            or isinstance(entry.get("end"), bool)
        ):
            issues.append(
                _manifest_issue(
                    MANIFEST_BAD_STRUCTURE,
                    f"manifest declared_regions entry is malformed - "
                    f"ignored: {entry!r}",
                )
            )
            continue
        try:
            regions.append(
                DeclaredRegion(entry["name"], entry["start"], entry["end"])
            )
        except ValueError:
            issues.append(
                _manifest_issue(
                    MANIFEST_BAD_STRUCTURE,
                    f"manifest declared_regions entry is invalid - "
                    f"ignored: {entry!r}",
                )
            )
    return tuple(regions)


def _over_cap_issues(payload: dict) -> list[ValidationIssue]:
    """
    Summary:
        One finding per manifest array over :data:`MANIFEST_ENTRY_CAP`
        (LLR-169.4), counted before any entry is resolved, so a hostile
        manifest costs a length check and not one path resolution per entry.

    Args:
        payload (dict): The parsed top-level manifest object.

    Returns:
        list[ValidationIssue]: One ``MANIFEST-BAD-STRUCTURE`` per over-cap
            array, marked as voiding the whole manifest (it is read as
            damaged and never rewritten by an in-project writer).

    Data Flow:
        - ``batch`` / ``declared_regions``: the list length.
        - ``files`` / ``derived_from``: the key count.
        - ``gathered``: the entries of every home together, and the homes.
        - ``assignments``: the entries of every list together, and the keys
          (SEC PDR-C2: the cap is in total, not per list).

    Dependencies:
        Used by:
            - read_project_manifest
    """
    counts: list[tuple[str, int]] = []
    for key in ("batch", "declared_regions"):
        value = payload.get(key)
        if isinstance(value, list):
            counts.append((key, len(value)))
    for key in ("files", "derived_from"):
        value = payload.get(key)
        if isinstance(value, dict):
            counts.append((key, len(value)))
    for key in ("gathered", "assignments"):
        value = payload.get(key)
        if isinstance(value, dict):
            counts.append((f"{key} keys", len(value)))
            counts.append(
                (key, sum(len(v) for v in value.values() if isinstance(v, list)))
            )
    return [
        _manifest_issue(
            MANIFEST_BAD_STRUCTURE,
            f"manifest {key} holds {count} entries, over the "
            f"{MANIFEST_ENTRY_CAP}-entry cap - defaults used",
            details={
                _ISSUE_SCOPE: _SCOPE_MANIFEST,
                _ISSUE_REASON: "too many recorded entries - defaults used",
            },
        )
        for key, count in counts
        if count > MANIFEST_ENTRY_CAP
    ]


def _recorded_file(
    raw_key: object,
    context: str,
    issues: list[ValidationIssue],
    walk: _EntryWalk,
) -> Optional[Path]:
    """
    Summary:
        Check one ``files`` / ``derived_from`` key in the manifest-keys mode
        and require the O-2 scope: one top-level name with a project data or
        A2L suffix (LLR-169.4). The scope is decided on the text, before
        any filesystem call (SEC7-1).

    Args:
        raw_key (object): The recorded key.
        context (str): ``"files"`` or ``"derived_from"``.
        issues (list[ValidationIssue]): Appended in place.
        walk (_EntryWalk): The read's walk.

    Returns:
        Optional[Path]: The file in the project, or ``None`` when refused
            (one ``MANIFEST-PATH-ESCAPE`` from the text or the walk, one
            ``MANIFEST-BAD-STRUCTURE`` for a key out of scope) or unchecked.

    Dependencies:
        Uses:
            - _entry_text / _walk_manifest_entry (manifest-keys mode)
        Used by:
            - _parse_manifest_files / _parse_manifest_derived_from
    """
    text = _entry_text(raw_key, context, issues, ENTRY_MODE_MANIFEST_KEYS)
    if text is None:
        return None
    key = str(raw_key)
    if (
        len(re.split(r"[\\/]", key)) != 1
        or Path(key).suffix.lower() not in PROJECT_RECORDED_SUFFIXES
    ):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                f"manifest {context} key is not a top-level data or A2L file "
                f"- entry skipped: {key!r}",
                details=_entry_mark(key),
            )
        )
        return None
    return _walk_manifest_entry(walk, text, context, issues)


def _is_count(value: object) -> bool:
    """True for an ``int`` >= 0 that is not a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_digest(value: object) -> bool:
    """True for 64 lowercase hex characters."""
    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


def _parse_manifest_files(
    raw: object,
    issues: list[ValidationIssue],
    walk: _EntryWalk,
) -> dict[Path, FileRecord]:
    """
    Summary:
        Parse the ``files`` key (LLR-169.4, B100-I2) into records: every
        malformed or unsafe record is reported once and skipped.

    Args:
        raw (object): The value of ``files``.
        issues (list[ValidationIssue]): Appended in place.
        walk (_EntryWalk): The read's walk.

    Returns:
        dict[Path, FileRecord]: The accepted records by resolved file.

    Data Flow:
        - Not an object → one ``MANIFEST-BAD-STRUCTURE``.
        - Each key through :func:`_recorded_file`.
        - A value that is not ``{"size": int >= 0 (never a bool),
          "sha256": 64 lowercase hex}`` → one ``MANIFEST-BAD-STRUCTURE``.

    Dependencies:
        Uses:
            - _recorded_file / _is_count / _is_digest
        Used by:
            - read_project_manifest
    """
    if not isinstance(raw, dict):
        issues.append(
            _manifest_issue(MANIFEST_BAD_STRUCTURE, "manifest files is not an object - ignored")
        )
        return {}
    records: dict[Path, FileRecord] = {}
    for key, value in raw.items():
        resolved = _recorded_file(key, "files", issues, walk)
        if resolved is None:
            continue
        if (
            not isinstance(value, dict)
            or not _is_count(value.get("size"))
            or not _is_digest(value.get("sha256"))
        ):
            issues.append(
                _manifest_issue(
                    MANIFEST_BAD_STRUCTURE,
                    f"manifest files record is malformed - entry skipped: {key!r}",
                    details=_entry_mark(key),
                )
            )
            continue
        records[resolved] = FileRecord(value["size"], value["sha256"])
    return records


def _parse_manifest_derived_from(
    raw: object,
    issues: list[ValidationIssue],
    walk: _EntryWalk,
) -> dict[Path, DerivedFrom]:
    """
    Summary:
        Parse the ``derived_from`` key (LLR-168.4, B100-I16) into records;
        an unsafe or malformed record gives one finding and no entry.

    Args:
        raw (object): The value of ``derived_from``.
        issues (list[ValidationIssue]): Appended in place.
        walk (_EntryWalk): The read's walk.

    Returns:
        dict[Path, DerivedFrom]: The accepted records by resolved variant.

    Data Flow:
        - Not an object → one ``MANIFEST-BAD-STRUCTURE``.
        - Each key through :func:`_recorded_file`.
        - The value must be ``{"base": str, "sha256": 64 lowercase hex,
          "differ": int >= 0}``; ``base`` must be one plain name, checked in
          the manifest-keys mode (``../x.s19`` → ``MANIFEST-PATH-ESCAPE``).

    Dependencies:
        Uses:
            - _recorded_file / _resolve_manifest_entry / _is_count /
              _is_digest
        Used by:
            - read_project_manifest
    """
    if not isinstance(raw, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE, "manifest derived_from is not an object - ignored"
            )
        )
        return {}
    records: dict[Path, DerivedFrom] = {}
    for key, value in raw.items():
        resolved = _recorded_file(key, "derived_from", issues, walk)
        if resolved is None:
            continue
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("base"), str)
            or not _is_digest(value.get("sha256"))
            or not _is_count(value.get("differ"))
        ):
            issues.append(
                _manifest_issue(
                    MANIFEST_BAD_STRUCTURE,
                    f"manifest derived_from record is malformed - entry skipped: {key!r}",
                    details=_entry_mark(key),
                )
            )
            continue
        base = value["base"]
        probe: list[ValidationIssue] = []
        unchecked = walk.unchecked
        if (
            len(re.split(r"[\\/]", base)) != 1
            or _resolve_manifest_entry(
                walk.project_root,
                base,
                "derived_from base",
                probe,
                mode=ENTRY_MODE_MANIFEST_KEYS,
                walk=walk,
            )
            is None
        ):
            if walk.unchecked > unchecked:
                continue  # past the folder ceiling: counted in the fold finding
            issues.append(
                _manifest_issue(
                    MANIFEST_PATH_ESCAPE,
                    f"manifest derived_from base is not a plain file name - "
                    f"entry skipped: {base!r}",
                    details=_entry_mark(key),
                )
            )
            continue
        records[resolved] = DerivedFrom(base, value["sha256"], value["differ"])
    return records


def _bound_entry_findings(issues: list[ValidationIssue], unchecked: int = 0) -> None:
    """
    Summary:
        Keep at most :data:`MANIFEST_ENTRY_ROWS` skipped-entry findings one
        by one and fold the rest, with the entries skipped unchecked past
        the folder ceiling, into one finding that counts them (SEC6-5: the
        load and the Load-result panel stay bounded however many entries a
        manifest records; nothing is dropped unreported).

    Args:
        issues (list[ValidationIssue]): The read's findings, edited in
            place.
        unchecked (int): Entries the read skipped without a check
            (:data:`MANIFEST_FOLDER_CHECK_CAP`).

    Returns:
        None

    Dependencies:
        Used by:
            - read_project_manifest
    """
    marked = [issue for issue in issues if _ISSUE_ENTRY in issue.details]
    extra = max(0, len(marked) - MANIFEST_ENTRY_ROWS)
    if extra + unchecked == 0:
        return
    folded = {id(issue) for issue in marked[MANIFEST_ENTRY_ROWS:]}
    issues[:] = [issue for issue in issues if id(issue) not in folded]
    count = extra + unchecked
    issues.append(
        _manifest_issue(
            MANIFEST_BAD_STRUCTURE,
            f"{count} more manifest entries were skipped"
            + (
                f" ({unchecked} unchecked: over {MANIFEST_FOLDER_CHECK_CAP} "
                "folder checks)"
                if unchecked
                else ""
            ),
            details={
                _ISSUE_ENTRY: f"{count} more recorded entries",
                _ISSUE_REASON: (
                    "skipped like the entries above"
                    if not unchecked
                    else "skipped - more entries than one load checks"
                ),
            },
        )
    )


def read_project_manifest(
    project_dir: Path,
    size_probe: Optional[SizeProbe] = None,
) -> Optional[ProjectManifest]:
    """
    Summary:
        Read ``<project_dir>/project.json`` into a :class:`ProjectManifest`
        through the capped, collect-don't-abort path (LLR-006.1 + F-S-03).
        An ABSENT manifest returns ``None`` — the caller's signal to default
        to batch mode over all variants.

    Args:
        project_dir (Path): The project directory
            (``.s19tool/workarea/<project>/``).
        size_probe (Optional[SizeProbe]): On-disk byte-size measurement
            seam; ``None`` resolves to ``Path.stat().st_size``. Injectable
            so a test can report an over-cap size without a real 256 MB
            file.

    Returns:
        Optional[ProjectManifest]: ``None`` when no manifest file exists;
        otherwise a manifest whose ``issues`` carry every size / parse /
        structure / containment finding — a faulted manifest comes back
        with empty ``batch`` / ``assignments`` rather than raising.

    Raises:
        None: Every failure mode is a collected ``ValidationIssue``.

    Data Flow:
        - Probe the size BEFORE ``json.load`` (over cap → one
          ``MANIFEST-SIZE-CAP``, empty manifest).
        - Parse catching ``JSONDecodeError`` / ``RecursionError`` /
          ``UnicodeDecodeError`` / ``OSError`` → one
          ``MANIFEST-JSON-PARSE``; a plain ``ValueError`` (an integer over
          Python's digit limit, SEC6-8) is caught the same way, so the
          manifest reads as damaged.
        - Non-object top level → one ``MANIFEST-BAD-STRUCTURE``.
        - ``batch`` (array), ``assignments`` and ``gathered`` (objects of
          arrays) entries each resolve through
          :func:`_resolve_manifest_entry`; unsafe entries are skipped with
          one ERROR each, a malformed ``gathered`` value with one
          ``MANIFEST-BAD-STRUCTURE`` (LLR-168.1).

    Dependencies:
        Uses:
            - _resolve_manifest_entry / _manifest_issue
            - json.load
        Used by:
            - execute_project_variants
            - s19_app.tui.app.S19TuiApp._handle_load_project
            - tests/test_variant_execution.py

    Example:
        >>> manifest = read_project_manifest(project_dir)  # doctest: +SKIP
    """
    manifest_path = project_dir / PROJECT_MANIFEST_NAME
    if not manifest_path.exists():
        return None
    issues: list[ValidationIssue] = []
    empty = ProjectManifest(
        schema_version=None, active_variant=None, issues=issues
    )
    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size)
        if size_probe is None
        else size_probe
    )
    def _over_size(size_bytes: int) -> ProjectManifest:
        issues.append(
            _manifest_issue(
                MANIFEST_SIZE_CAP,
                f"the project manifest is {size_bytes} bytes, over the "
                f"{MANIFEST_SIZE_CAP_BYTES}-byte read cap - the file was "
                f"not loaded",
            )
        )
        return empty

    try:
        size_bytes = probe(manifest_path)
    except OSError:
        size_bytes = 0  # the open below reports the unreadable file
    if size_bytes > MANIFEST_SIZE_CAP_BYTES:
        return _over_size(size_bytes)
    try:
        with manifest_path.open("rb") as handle:
            # LLR-169.4: never read past the cap, even if the file grew
            # after the size probe.
            data = handle.read(MANIFEST_SIZE_CAP_BYTES + 1)
        if len(data) > MANIFEST_SIZE_CAP_BYTES:
            return _over_size(len(data))
        payload = json.loads(data)
    except (
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        UnicodeDecodeError,
        OSError,
    ) as exc:
        issues.append(
            _manifest_issue(
                MANIFEST_JSON_PARSE,
                f"the project manifest is not readable well-formed JSON - "
                f"ignored: {type(exc).__name__}",
            )
        )
        return empty
    if not isinstance(payload, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "the project manifest top level is not a JSON object - "
                "ignored",
                details={
                    _ISSUE_SCOPE: _SCOPE_MANIFEST,
                    _ISSUE_REASON: "not a manifest object - defaults used",
                },
            )
        )
        return empty
    over_cap = _over_cap_issues(payload)
    if over_cap:
        issues.extend(over_cap)
        return empty

    project_root = project_dir.resolve()
    walk = _EntryWalk(project_root)
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, (int, float, str)) and schema_version is not None:
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest schema_version is neither a number nor a string",
            )
        )
        schema_version = None
    active_raw = payload.get("active_variant")
    active_variant = active_raw if isinstance(active_raw, str) else None
    if active_raw is not None and not isinstance(active_raw, str):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest active_variant is not a string - ignored",
            )
        )

    batch: list[Path] = []
    batch_raw = payload.get("batch", [])
    if not isinstance(batch_raw, list):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest batch is not an array - ignored",
            )
        )
    else:
        for entry in batch_raw:
            resolved = _resolve_manifest_entry(
                project_root, entry, "batch", issues, ENTRY_MODE_MANIFEST_KEYS, walk
            )
            if resolved is not None:
                batch.append(resolved)

    assignments: dict[str, list[Path]] = {}
    assignments_raw = payload.get("assignments", {})
    if not isinstance(assignments_raw, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest assignments is not an object - ignored",
            )
        )
    else:
        for variant_id, entries in assignments_raw.items():
            if not isinstance(entries, list):
                issues.append(
                    _manifest_issue(
                        MANIFEST_BAD_STRUCTURE,
                        f"manifest assignments[{variant_id!r}] is not an "
                        "array - ignored",
                    )
                )
                continue
            resolved_entries: list[Path] = []
            for entry in entries:
                resolved = _resolve_manifest_entry(
                    project_root,
                    entry,
                    f"assignments[{variant_id!r}]",
                    issues,
                    ENTRY_MODE_MANIFEST_KEYS,
                    walk,
                )
                if resolved is not None:
                    resolved_entries.append(resolved)
            assignments[str(variant_id)] = resolved_entries

    # LLR-168.1 (B100-I2): the gather rows, read like ``assignments`` so a
    # writer can carry them through a rewrite.
    gathered: dict[str, list[Path]] = {}
    gathered_raw = payload.get("gathered", {})
    if not isinstance(gathered_raw, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest gathered is not an object - ignored",
            )
        )
    else:
        for home, entries in gathered_raw.items():
            if not isinstance(entries, list):
                issues.append(
                    _manifest_issue(
                        MANIFEST_BAD_STRUCTURE,
                        f"manifest gathered[{home!r}] is not an array - "
                        "ignored",
                    )
                )
                continue
            resolved_entries = []
            for entry in entries:
                resolved = _resolve_manifest_entry(
                    project_root,
                    entry,
                    f"gathered[{home!r}]",
                    issues,
                    ENTRY_MODE_MANIFEST_KEYS,
                    walk,
                )
                if resolved is not None:
                    resolved_entries.append(resolved)
            gathered[str(home)] = resolved_entries

    declared_regions = _parse_manifest_declared_regions(
        payload.get("declared_regions", []), issues
    )
    files = _parse_manifest_files(payload.get("files", {}), issues, walk)
    derived_from = _parse_manifest_derived_from(
        payload.get("derived_from", {}), issues, walk
    )
    _bound_entry_findings(issues, walk.unchecked)
    return ProjectManifest(
        schema_version=schema_version,
        active_variant=active_variant,
        batch=batch,
        assignments=assignments,
        declared_regions=declared_regions,
        gathered=gathered,
        issues=issues,
        files=files,
        derived_from=derived_from,
        unknown_keys=tuple(
            str(key) for key in payload if key not in KNOWN_MANIFEST_KEYS
        ),
    )


#: Why a project load opened the variant it did (LLR-178.1). The ids are
#: internal; the panel and the status line show :data:`LOAD_REASON_TEXT`.
LOAD_REASON_RECORDED = "recorded"
LOAD_REASON_NONE_RECORDED = "none-recorded"
LOAD_REASON_MANIFEST_DAMAGED = "manifest-damaged"
LOAD_REASON_NO_MANIFEST = "no-manifest"
LOAD_REASON_NEXT_VALID = "next-valid"

#: The user-term wording of each reason. "latest" is reserved for the
#: variant the app's last recorded write made active (HLR-178), which is
#: what the manifest's ``active_variant`` records.
LOAD_REASON_TEXT: dict[str, str] = {
    LOAD_REASON_RECORDED: "recorded as the active variant (the latest saved)",
    LOAD_REASON_NONE_RECORDED: (
        "the first variant by name (the manifest records no active variant)"
    ),
    LOAD_REASON_MANIFEST_DAMAGED: (
        "the first variant by name (the manifest could not be read)"
    ),
    LOAD_REASON_NO_MANIFEST: (
        "the first variant by name (the project has no project.json)"
    ),
    LOAD_REASON_NEXT_VALID: (
        "the next valid variant (the recorded one is missing or not readable)"
    ),
}

#: The problem kinds of a project load (HLR-169, LLR-169.5 / LLR-169.9):
#: each kind is also the painted reason token (§3 refusal-token table).
PROBLEM_MANIFEST_DAMAGED = "manifest damaged"
PROBLEM_NO_MANIFEST = "no project.json"
PROBLEM_MISSING = "missing"
PROBLEM_NOT_READABLE = "not readable"
PROBLEM_CHANGED = "changed on disk"
PROBLEM_NOT_RECORDED = "not recorded"
PROBLEM_NO_DIGESTS = "no digests saved"

#: The precedence (lower wins) that keeps one problem per file (LLR-169.9).
PROBLEM_PRECEDENCE: dict[str, int] = {
    PROBLEM_MANIFEST_DAMAGED: 0,
    PROBLEM_NO_MANIFEST: 0,
    PROBLEM_MISSING: 1,
    PROBLEM_NOT_READABLE: 2,
    PROBLEM_CHANGED: 3,
    PROBLEM_NOT_RECORDED: 4,
    PROBLEM_NO_DIGESTS: 5,
}

#: Each kind's next-step token (§3 refusal-token table).
PROBLEM_NEXT_STEP: dict[str, str] = {
    PROBLEM_MANIFEST_DAMAGED: "Save project rewrites it",
    PROBLEM_NO_MANIFEST: "Save project writes it",
    PROBLEM_MISSING: "restore the file, or Save project to drop it",
    PROBLEM_NOT_READABLE: "replace the file, or Save project to drop it",
    PROBLEM_CHANGED: "Save project records the new state",
    PROBLEM_NOT_RECORDED: "Save project records it",
    PROBLEM_NO_DIGESTS: "Save project records them",
}

#: Manifest finding code -> what is wrong, in user terms; the code itself
#: goes to the log only (HLR-169). A finding may carry its own reason mark.
_MANIFEST_REASON: dict[str, str] = {
    MANIFEST_SIZE_CAP: "too large to read - defaults used",
    MANIFEST_JSON_PARSE: "not valid JSON - defaults used",
    MANIFEST_BAD_STRUCTURE: "a recorded entry has the wrong shape",
    MANIFEST_PATH_ESCAPE: "a file path points outside the project",
}

#: The reference width the status summary line is composed for (the
#: 118-column reference terminal); names are clipped so "details: p" stays
#: on screen.
LOAD_SUMMARY_WIDTH = 118


@dataclass(frozen=True)
class ProjectFileProblem:
    """
    Summary:
        One problem a project check found (B100-I3): its kind, the file it
        concerns, what is wrong in user terms, and the internal code that
        goes to the log only.

    Args:
        kind (str): One of the ``PROBLEM_*`` kinds.
        file (str): The project file or recorded entry concerned;
            ``project.json`` for a manifest-level problem.
        reason (str): What is wrong, in user terms ("" when the kind says
            it all).
        code (Optional[str]): The internal finding code, for the log.
    """

    kind: str
    file: str
    reason: str = ""
    code: Optional[str] = None


@dataclass(frozen=True)
class LoadProblem:
    """
    Summary:
        One problem a project load found, as the panel paints it (HLR-169 /
        LLR-178.1): its label (the kind token), the file it concerns, and
        what happened with the next step.

    Args:
        label (str): The problem kind as the user reads it.
        file (str): The file (or recorded entry) concerned.
        detail (str): What happened and what to do next.
        rank (int): Precedence; lower sorts first.
    """

    label: str
    file: str
    detail: str
    rank: int


def merge_load_problems(
    problems: Sequence[ProjectFileProblem],
) -> list[ProjectFileProblem]:
    """
    Summary:
        Keep one problem per file — its highest by :data:`PROBLEM_PRECEDENCE`
        — and so at most one manifest-level problem (LLR-169.9).

    Args:
        problems (Sequence[ProjectFileProblem]): Every problem found, from
            the project check, the install and the composer.

    Returns:
        list[ProjectFileProblem]: At most one per file, in precedence order;
            equal ranks keep their first-seen order.

    Data Flow:
        - Group by ``file`` (every manifest-level problem names
          ``project.json``); the lowest precedence wins, the first seen on a
          tie.
        - Sort the winners by precedence, stable.

    Dependencies:
        Used by:
            - compose_load_announcement
    """
    best: dict[str, ProjectFileProblem] = {}
    for problem in problems:
        kept = best.get(problem.file)
        if kept is None or (
            PROBLEM_PRECEDENCE[problem.kind] < PROBLEM_PRECEDENCE[kept.kind]
        ):
            best[problem.file] = problem
    return sorted(best.values(), key=lambda item: PROBLEM_PRECEDENCE[item.kind])


@dataclass(frozen=True)
class LoadAnnouncement:
    """
    Summary:
        What a project load opened and why (LLR-178.1) — the input of the
        status summary line, the final file-state line and the Load-result
        panel.

    Args:
        project (str): The project name.
        opened (Optional[str]): The opened variant's file name, or ``None``
            when the project holds no openable image.
        position (int): The opened variant's 1-based position among the
            project's variants (``0`` when nothing opened).
        count (int): How many variants the project holds.
        reason (str): One of the ``LOAD_REASON_*`` ids.
        latest (bool): True only when the opened variant is the one the
            app's last recorded write made active.
        others (Tuple[str, ...]): The other variants' file names.
        mac (Optional[str]): The MAC file that loaded, if any.
        a2l (Optional[str]): The A2L file that loaded, if any.
        problems (Tuple[LoadProblem, ...]): Every problem, in precedence
            order.
        relation (Optional[str]): How the opened variant relates to its
            recorded base (``derived_from``), or ``None``.
        unreadable (Tuple[str, ...]): The variants the install could not
            read; the panel marks them in the error colour.
        hidden (int): How many problems the last row counts instead of
            listing (:data:`LOAD_PROBLEM_ROWS`); ``0`` when every problem
            has its own row.
    """

    project: str
    opened: Optional[str]
    position: int
    count: int
    reason: str
    latest: bool
    others: Tuple[str, ...] = ()
    mac: Optional[str] = None
    a2l: Optional[str] = None
    problems: Tuple[LoadProblem, ...] = ()
    relation: Optional[str] = None
    unreadable: Tuple[str, ...] = ()
    hidden: int = 0

    @property
    def problem_count(self) -> int:
        """Every problem found: the listed rows, with the counting row
        standing for the ``hidden`` problems it counts."""
        return len(self.problems) - (1 if self.hidden else 0) + self.hidden

    @property
    def reason_text(self) -> str:
        """The reason in user terms (:data:`LOAD_REASON_TEXT`)."""
        return LOAD_REASON_TEXT[self.reason]

    @property
    def target(self) -> str:
        """The opened image and the MAC that loaded with it, as one name."""
        names = [name for name in (self.opened, self.mac) if name]
        return " + ".join(names) if names else "(no image)"

    def status_line(self) -> str:
        """The final file-state line: the project and the opened file."""
        return f"Loaded project '{self.project}' -> {self.target}"

    def summary_line(self, width: int = LOAD_SUMMARY_WIDTH) -> str:
        """
        Summary:
            The one status-log summary line (LLR-178.2): the project and the
            opened file, ``variant k of n``, the problem count, then
            ``details: p`` — composed to fit ``width`` by clipping the
            names, never the counts.

        Args:
            width (int): The column budget (the 118-column reference).

        Returns:
            str: The line.

        Dependencies:
            Uses:
                - ``target`` / ``_clip``
            Used by:
                - s19_app.tui.app.S19TuiApp._handle_load_project
        """
        problems = self.problem_count
        counts = (
            f"variant {self.position} of {self.count}"
            if self.opened
            else f"{self.count} variants"
        )
        tail = (
            f" - {counts}, {problems} problem{'' if problems == 1 else 's'}"
            " - details: p"
        )
        project, target = self.project, self.target
        overflow = len(f"Loaded project '{project}' -> {target}{tail}") - width
        if overflow > 0:
            target = _clip(target, max(8, len(target) - overflow))
            overflow = len(f"Loaded project '{project}' -> {target}{tail}") - width
        if overflow > 0:
            project = _clip(project, max(8, len(project) - overflow))
        return f"Loaded project '{project}' -> {target}{tail}"


def _clip(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters, ending in an ellipsis."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def manifest_problems(manifest: ProjectManifest) -> list[ProjectFileProblem]:
    """
    Summary:
        One ``manifest damaged`` problem per manifest finding (HLR-169
        wording): the reason comes from the finding's reason mark or code;
        the code goes to the log only and the finding message (which can
        name an exception class) never reaches a problem.

    Args:
        manifest (ProjectManifest): The read manifest.

    Returns:
        list[ProjectFileProblem]: One problem per finding, in finding order.

    Data Flow:
        - A skipped entry names the entry it recorded (the ``_ISSUE_ENTRY``
          mark), so thirty skipped entries are thirty distinct rows; any
          other finding names ``project.json`` (manifest-level).

    Dependencies:
        Uses:
            - ``_MANIFEST_REASON``
        Used by:
            - manifest_writer.check_project_files
    """
    return [
        ProjectFileProblem(
            PROBLEM_MANIFEST_DAMAGED,
            issue.details.get(_ISSUE_ENTRY, PROJECT_MANIFEST_NAME),
            issue.details.get(_ISSUE_REASON)
            or _MANIFEST_REASON.get(issue.code, "a recorded entry has the wrong shape"),
            issue.code,
        )
        for issue in manifest.issues
    ]


def manifest_is_damaged(manifest: ProjectManifest) -> bool:
    """
    Summary:
        True when ``project.json`` exists but could not be read as a
        manifest at all: over the size cap, not well-formed JSON (an
        ``OSError`` on open included), a top level that is not an object, or
        an array over the entry cap (LLR-178.1, LLR-169.4, and the OQ-1
        ruling (b) for the in-project writers).

    Args:
        manifest (ProjectManifest): The read manifest.

    Returns:
        bool: True for those whole-file cases; a manifest with only
            skipped entries is readable and returns False.

    Dependencies:
        Used by:
            - compose_load_announcement (the ``manifest-damaged`` reason)
            - manifest_rewrite_refusal
            - manifest_writer.check_project_files
    """
    return any(
        issue.code in (MANIFEST_SIZE_CAP, MANIFEST_JSON_PARSE)
        or issue.details.get(_ISSUE_SCOPE) == _SCOPE_MANIFEST
        for issue in manifest.issues
    )


def manifest_keep_reason(manifest: ProjectManifest) -> Optional[str]:
    """
    Summary:
        Why rewriting this ``project.json`` from app state would lose what
        it holds, or ``None`` (SEC6-2, SEC7-3): it is damaged, its
        ``schema_version`` is not this version's, or it holds top-level keys
        this version does not know.

    Args:
        manifest (ProjectManifest): The read manifest.

    Returns:
        Optional[str]: The status phrase ("is damaged", "was written by a
            newer version", "was written by an unknown version", "holds
            keys this version does not know"), or ``None``.

    Data Flow:
        - Only the integer ``1`` (never ``True``, ``"1"`` or ``1.0``) or an
          absent key is this version (F8, SEC7-4 (a)); an integer above 1
          is a newer version, any other value an unknown one.

    Dependencies:
        Uses:
            - manifest_is_damaged
        Used by:
            - manifest_rewrite_refusal
            - s19_app.tui.app.S19TuiApp._handle_save_dialog (SEC7-3)
    """
    if manifest_is_damaged(manifest):
        return "is damaged"
    version = manifest.schema_version
    if version is not None and not (
        type(version) is int and version == SUPPORTED_SCHEMA_VERSION
    ):
        if type(version) is int and version > SUPPORTED_SCHEMA_VERSION:
            return "was written by a newer version"
        return "was written by an unknown version"
    if manifest.unknown_keys:
        return "holds keys this version does not know"
    return None


def manifest_rewrite_refusal(manifest: ProjectManifest) -> Optional[str]:
    """
    Summary:
        Why an in-project writer must not rewrite this ``project.json``, or
        ``None`` when it may (LED .67 (b), SEC6-2): a rewrite can only carry
        what this version reads, so a manifest it cannot carry whole is left
        as it is and Save project stays the recovery.

    Args:
        manifest (ProjectManifest): The read manifest.

    Returns:
        Optional[str]: :func:`manifest_keep_reason`'s phrase, or "holds
            entries that were skipped", or ``None``.

    Data Flow:
        - :func:`manifest_keep_reason` first, then any skipped entry.

    Dependencies:
        Uses:
            - manifest_keep_reason
        Used by:
            - s19_app.tui.app.S19TuiApp._rewrite_project_manifest
    """
    reason = manifest_keep_reason(manifest)
    if reason is None and manifest.issues:
        return "holds entries that were skipped"
    return reason


def _relation_line(
    opened: Optional[VariantDescriptor], manifest: Optional[ProjectManifest]
) -> Optional[str]:
    """
    Summary:
        How the opened variant relates to its base, from its ``derived_from``
        record (LLR-178.1, B100-I16) — never from the first variant by name.

    Args:
        opened (Optional[VariantDescriptor]): The opened variant.
        manifest (Optional[ProjectManifest]): The read manifest.

    Returns:
        Optional[str]: ``"patched, N bytes differ from <base>"`` when a
            project file has the recorded name and digest, ``"patched from
            <base> (not in this project); N bytes differ from it"`` when
            none has; ``None`` when the variant has no record.

    Dependencies:
        Used by:
            - compose_load_announcement
    """
    if opened is None or manifest is None:
        return None
    record = next(
        (
            item
            for path, item in manifest.derived_from.items()
            if path.name == opened.path.name
        ),
        None,
    )
    if record is None:
        return None
    count = f"{record.differ} byte" + ("" if record.differ == 1 else "s")
    in_project = any(
        path.name == record.base and item.sha256 == record.sha256
        for path, item in manifest.files.items()
    )
    if in_project:
        return f"patched, {count} differ from {record.base}"
    return f"patched from {record.base} (not in this project); {count} differ from it"


def _missing_recorded(manifest: ProjectManifest, recorded: str) -> str:
    """The file a missing recorded variant id names: the image ``files``
    key with that stem or name, else the id itself."""
    return next(
        (
            path.name
            for path in manifest.files
            if recorded in (path.stem, path.name)
            and path.suffix.lower() not in MAC_EXTENSIONS | A2L_EXTENSIONS
        ),
        recorded,
    )


def compose_load_announcement(
    project_name: str,
    variant_set: ProjectVariantSet,
    manifest: Optional[ProjectManifest],
    *,
    mac_name: Optional[str] = None,
    a2l_name: Optional[str] = None,
    problems: Sequence[ProjectFileProblem] = (),
    unreadable: Sequence[str] = (),
) -> LoadAnnouncement:
    """
    Summary:
        Compose what a project load announces (LLR-178.1, LLR-169.9): the
        variant it opened, the variant count, why that one opened, whether
        it is the latest saved, how it relates to its recorded base, the
        other variants (those not readable marked), the MAC and A2L that
        loaded, and one problem per file in precedence order. Pure: reads no
        file and no clock — "latest" comes from the recorded
        ``active_variant``, never from file times.

    Args:
        project_name (str): The project name.
        variant_set (ProjectVariantSet): The project's variants with the
            ``active_id`` the load opened.
        manifest (Optional[ProjectManifest]): The read manifest; ``None``
            when the project has no ``project.json``.
        mac_name (Optional[str]): The MAC file that loaded, if any.
        a2l_name (Optional[str]): The A2L file that loaded, if any.
        problems (Sequence[ProjectFileProblem]): The problems the project
            check and the install found (``check_project_files``, which
            holds the manifest's own problems, plus ``not readable``) — the
            one source of every problem but the missing recorded variant
            (F6).
        unreadable (Sequence[str]): The variant files the install could
            not read.

    Returns:
        LoadAnnouncement: The announcement.

    Data Flow:
        - Reason: no manifest -> ``no-manifest``; a manifest that could not
          be read -> ``manifest-damaged``; no ``active_variant`` recorded ->
          ``none-recorded``; the recorded id is the opened one ->
          ``recorded``; otherwise ``next-valid``, with a ``missing`` problem
          when the recorded id is no variant of the project.
        - Problems: the missing recorded variant and ``problems``, merged to
          one per file (:func:`merge_load_problems`) and worded as the kind
          token, the reason and the next step.
        - At most :data:`LOAD_PROBLEM_ROWS` rows are listed, in precedence
          order; the rest are counted in one more row (F2, SEC6-5), so the
          panel holds at most ``LOAD_PROBLEM_ROWS + 1`` problem rows.
        - The relation line comes from ``derived_from``
          (:func:`_relation_line`).

    Dependencies:
        Uses:
            - LOAD_REASON_TEXT / manifest_is_damaged / merge_load_problems /
              _relation_line
        Used by:
            - s19_app.tui.app.S19TuiApp._handle_load_project
            - s19_app.tui.screens.LoadResultScreen (renders it)
    """
    variants = variant_set.variants
    opened_variant = next(
        (v for v in variants if v.variant_id == variant_set.active_id), None
    )
    found: list[ProjectFileProblem] = []
    if manifest is None:
        reason = LOAD_REASON_NO_MANIFEST
    else:
        recorded = manifest.active_variant
        if manifest_is_damaged(manifest):
            reason = LOAD_REASON_MANIFEST_DAMAGED
        elif recorded is None:
            reason = LOAD_REASON_NONE_RECORDED
        elif opened_variant is not None and recorded == opened_variant.variant_id:
            reason = LOAD_REASON_RECORDED
        else:
            reason = LOAD_REASON_NEXT_VALID
            if recorded not in {v.variant_id for v in variants}:
                found.append(
                    ProjectFileProblem(
                        PROBLEM_MISSING,
                        _missing_recorded(manifest, recorded),
                        "recorded as the active variant",
                    )
                )
    found.extend(problems)
    merged = merge_load_problems(found)
    hidden = max(0, len(merged) - LOAD_PROBLEM_ROWS)
    painted = tuple(
        LoadProblem(
            problem.kind,
            problem.file,
            " - ".join(
                part for part in (problem.reason, PROBLEM_NEXT_STEP[problem.kind]) if part
            ),
            PROBLEM_PRECEDENCE[problem.kind],
        )
        for problem in merged[:LOAD_PROBLEM_ROWS]
    )
    if hidden:
        painted += (
            LoadProblem(
                "more problems",
                f"{hidden} more files",
                "not listed one by one - each has one of the problems above",
                max(PROBLEM_PRECEDENCE.values()) + 1,
            ),
        )
    position = (
        variants.index(opened_variant) + 1 if opened_variant is not None else 0
    )
    return LoadAnnouncement(
        project=project_name,
        opened=opened_variant.path.name if opened_variant is not None else None,
        position=position,
        count=len(variants),
        reason=reason,
        latest=reason == LOAD_REASON_RECORDED,
        others=tuple(v.path.name for v in variants if v is not opened_variant),
        mac=mac_name,
        a2l=a2l_name,
        problems=painted,
        relation=_relation_line(opened_variant, manifest),
        unreadable=tuple(unreadable),
        hidden=hidden,
    )


@dataclass(slots=True)
class VariantExecutionResult:
    """
    Summary:
        The isolated outcome of executing one variant's file list
        (LLR-006.4). Lists (not single optionals) carry the per-file engine
        outputs — the documented E6 design choice, because the manifest can
        map MULTIPLE change/check files onto one variant (``batch`` plus
        ``assignments``); each engine output keeps its own ``variant_id``
        stamp and ``source_path``.

    Args:
        variant_id (str): The executed variant's id.
        status (str): ``"ok"`` when every file produced an engine output;
            ``"error"`` when an exception interrupted this variant — the
            other variants still execute (LLR-006.4 isolation).
        change_summaries (list[ChangeSummary]): One per executed change
            file, in execution (plan) order.
        check_results (list[CheckRunResult]): One per executed check file,
            in execution (plan) order.
        diagnostics (list[str]): Human-readable notes — the failure text on
            an ``"error"`` status, save-back refusals, and the HEX
            save-back-unsupported note.
        mem_map (Optional[dict[int, int]]): The variant's POST-CHANGE
            address-to-byte map — the E7 report generator's hexdump input
            (LLR-007.8, additive E7 extension). Captured only when the
            caller requested ``capture_mem_maps=True``; ``None`` otherwise,
            preserving the LLR-006.3 release-each-image memory profile for
            callers that produce no report.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`execute_variant_plan`, one per planned variant —
          ``len(results)`` always equals the planned variant count.
        - Consumed by the E6 TUI status reporting and the E7 report
          generator (``services/report_service.py``).

    Dependencies:
        Used by:
            - execute_variant_plan / execute_project_variants
            - s19_app.tui.app.S19TuiApp (execute_scope reporting)
            - s19_app.tui.services.report_service.generate_project_report
    """

    variant_id: str
    status: str
    change_summaries: list[ChangeSummary] = field(default_factory=list)
    check_results: list[CheckRunResult] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    mem_map: Optional[dict[int, int]] = None


def plan_variant_executions(
    variant_set: ProjectVariantSet,
    manifest: Optional[ProjectManifest],
    scope: str = SCOPE_ALL,
    fallback_batch: Sequence[Path] = (),
) -> list[Tuple[VariantDescriptor, Tuple[Path, ...]]]:
    """
    Summary:
        Build the deterministic execution plan (LLR-006.2): variants in
        ``ProjectVariantSet`` order (outer), and per variant the manifest
        ``batch`` list order followed by the ``assignments[variant_id]``
        order (inner). A pure function — two calls over the same inputs
        return identical plans.

    Args:
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.
        manifest (Optional[ProjectManifest]): The parsed manifest, or
            ``None`` when absent — the LLR-006.1 default: batch mode over
            all variants using ``fallback_batch``.
        scope (str): One of :data:`EXECUTION_SCOPES` — ``"active"`` plans
            only the active variant, ``"all"`` every variant,
            ``"assignments"`` only variants holding a non-empty manifest
            assignment (and only their assignment files, no batch).
        fallback_batch (Sequence[Path]): The file list applied to every
            in-scope variant when no manifest exists (e.g. the TUI's
            currently loaded change/check file).

    Returns:
        list[Tuple[VariantDescriptor, Tuple[Path, ...]]]: One
        ``(descriptor, files)`` pair per in-scope variant in variant-set
        order; ``files`` in the LLR-006.2 inner order.

    Raises:
        ValueError: When ``scope`` is not one of :data:`EXECUTION_SCOPES`.

    Data Flow:
        - Select the in-scope descriptors from ``variant_set.variants``
          (set order preserved).
        - Map files: manifest present → ``batch + assignments[id]``
          (``assignments`` only for the ``"assignments"`` scope); manifest
          absent → ``fallback_batch`` (empty for the ``"assignments"``
          scope, which has nothing to assign).

    Dependencies:
        Used by:
            - execute_project_variants
            - tests/test_variant_execution.py (determinism, LLR-006.2)
    """
    if scope not in EXECUTION_SCOPES:
        raise ValueError(f"unknown execution scope {scope!r}")
    if scope == SCOPE_ACTIVE:
        selected = [
            variant
            for variant in variant_set.variants
            if variant.variant_id == variant_set.active_id
        ]
    elif scope == SCOPE_ALL:
        selected = list(variant_set.variants)
    else:
        assignments = manifest.assignments if manifest is not None else {}
        selected = [
            variant
            for variant in variant_set.variants
            if assignments.get(variant.variant_id)
        ]
    plan: list[Tuple[VariantDescriptor, Tuple[Path, ...]]] = []
    for variant in selected:
        if manifest is None:
            files: Tuple[Path, ...] = (
                () if scope == SCOPE_ASSIGNMENTS else tuple(fallback_batch)
            )
        elif scope == SCOPE_ASSIGNMENTS:
            files = tuple(manifest.assignments.get(variant.variant_id, ()))
        else:
            files = tuple(manifest.batch) + tuple(
                manifest.assignments.get(variant.variant_id, ())
            )
        plan.append((variant, files))
    return plan


def _execute_one_variant(
    variant: VariantDescriptor,
    files: Sequence[Path],
    project_dir: Path,
    mac_records: Optional[Sequence[dict]],
    a2l_data: Optional[dict],
    capture_mem_map: bool = False,
) -> VariantExecutionResult:
    """
    Summary:
        Execute one variant's file list against a FRESH parse of its image
        (LLR-006.3/006.5): change files ride ``apply_change_document`` with
        headless save-back, check files ride ``run_check_document`` — the
        service computes no linkage or verdict of its own.

    Args:
        variant (VariantDescriptor): The variant to execute.
        files (Sequence[Path]): The planned change/check files in
            LLR-006.2 inner order.
        project_dir (Path): The project directory — the change-file
            resolution base and the save-back destination.
        mac_records (Optional[Sequence[dict]]): Parsed project MAC records
            (shared linkage source), or ``None``.
        a2l_data (Optional[dict]): Parsed project A2L payload (shared
            linkage source), or ``None`` — enriched against THIS variant's
            memory map before use.
        capture_mem_map (bool): When ``True``, the variant's memory map is
            referenced on ``result.mem_map`` — the apply engine mutates it
            in place, so the reference IS the post-change map the E7
            report generator consumes (LLR-007.8). Defaults to ``False``
            (the LLR-006.3 release-each-image profile).

    Returns:
        VariantExecutionResult: ``status="ok"`` with the per-file engine
        outputs, or ``status="error"`` carrying the failure diagnostic
        (the caller continues with the next variant — LLR-006.4).

    Data Flow:
        - Parse the image via ``build_loaded_s19`` / ``build_loaded_hex``
          (``variant.file_type`` discriminates) — never the TUI snapshot.
        - Per file: ``read_change_document(file, project_dir)``;
          ``kind == "check"`` → check engine; anything else → apply engine
          (its gate blocks non-change documents).
        - A change apply with ``counts["applied"] > 0`` on an S19 variant
          saves back headlessly as ``<variant_id>-patched.s19`` into
          ``project_dir`` (LLR-002.7 headless parameter; the engine's
          F-S-01 sanitizer and dedup-on-collision apply); a HEX variant
          records the unsupported-save diagnostic (D-1).
        - Any exception → ``status="error"``, diagnostics carry the text.

    Dependencies:
        Uses:
            - build_loaded_s19 / build_loaded_hex
            - read_change_document / apply_change_document /
              run_check_document / save_patched_image
            - enrich_tags_and_render
        Used by:
            - execute_variant_plan
    """
    result = VariantExecutionResult(
        variant_id=variant.variant_id, status=VARIANT_STATUS_OK
    )
    try:
        if variant.file_type == "hex":
            loaded = build_loaded_hex(
                variant.path, IntelHexFile(str(variant.path)), None, a2l_data
            )
        else:
            loaded = build_loaded_s19(
                variant.path, S19File(str(variant.path)), None, a2l_data
            )
        if capture_mem_map:
            result.mem_map = loaded.mem_map
        a2l_tags = (
            enrich_tags_and_render(a2l_data, loaded.mem_map)[0]
            if a2l_data
            else None
        )
        for file_path in files:
            document = read_change_document(str(file_path), project_dir)
            if document.kind == "check":
                result.check_results.append(
                    run_check_document(
                        document,
                        loaded.mem_map,
                        loaded.ranges,
                        mac_records,
                        a2l_tags,
                        variant_id=variant.variant_id,
                    )
                )
                continue
            summary = apply_change_document(
                document,
                loaded.mem_map,
                loaded.ranges,
                mac_records,
                a2l_tags,
                variant_id=variant.variant_id,
            )
            result.change_summaries.append(summary)
            if summary.counts.get("applied", 0) > 0:
                if variant.file_type == "s19":
                    saved_path, save_issues = save_patched_image(
                        loaded.mem_map,
                        loaded.ranges,
                        project_dir,
                        f"{variant.variant_id}-patched.s19",
                        source_kind="s19",
                        bytes_per_line=32,
                    )
                    summary.saved_path = saved_path
                    if saved_path is None:
                        result.diagnostics.extend(
                            f"[{issue.code}] {issue.message}"
                            for issue in save_issues
                        )
                else:
                    result.diagnostics.append(
                        "HEX save-back not supported this batch - patched "
                        "image not persisted"
                    )
    except Exception as exc:  # noqa: BLE001 — LLR-006.4 isolation boundary
        result.status = VARIANT_STATUS_ERROR
        result.diagnostics.append(f"{type(exc).__name__}: {exc}")
    return result


def execute_variant_plan(
    plan: Sequence[Tuple[VariantDescriptor, Tuple[Path, ...]]],
    project_dir: Path,
    *,
    mac_path: Optional[Path] = None,
    a2l_path: Optional[Path] = None,
    status_callback: Optional[StatusCallback] = None,
    capture_mem_maps: bool = False,
) -> list[VariantExecutionResult]:
    """
    Summary:
        Execute a planned variant list sequentially — one parsed image at a
        time, each variant isolated (LLR-006.3/006.4), with a between-
        variant status line per F-Q-18.

    Args:
        plan (Sequence[Tuple[VariantDescriptor, Tuple[Path, ...]]]): The
            :func:`plan_variant_executions` output.
        project_dir (Path): The project directory — change-file resolution
            base and save-back destination.
        mac_path (Optional[Path]): The project's MAC overlay, parsed ONCE
            and shared across variants as the linkage source.
        a2l_path (Optional[Path]): The project's A2L file, parsed ONCE; the
            per-variant enrichment happens inside each variant's execution.
        status_callback (Optional[StatusCallback]): Receives one line as
            each variant starts and one as it finishes — the TUI worker
            passes a ``call_from_thread``-wrapped ``set_status``.
        capture_mem_maps (bool): When ``True``, every result retains its
            variant's post-change memory map for the E7 report generator
            (LLR-007.8) — N maps stay alive for the caller's lifetime.
            Defaults to ``False``: the LLR-006.3 one-image-at-a-time
            memory profile is preserved.

    Returns:
        list[VariantExecutionResult]: Exactly ``len(plan)`` results in plan
        order — a failing variant yields its ``"error"`` result and the
        loop continues (LLR-006.4).

    Data Flow:
        - Parse the shared MAC / A2L linkage sources once.
        - Loop the plan; each iteration delegates to
          :func:`_execute_one_variant` and drops the variant's parsed image
          before the next iteration begins (one image at a time) — unless
          ``capture_mem_maps`` pins each map onto its result.

    Dependencies:
        Uses:
            - parse_mac_file / parse_a2l_file
            - _execute_one_variant
        Used by:
            - execute_project_variants
            - tests/test_variant_execution.py
    """
    mac_records = (
        parse_mac_file(mac_path)["records"] if mac_path is not None else None
    )
    a2l_data = parse_a2l_file(a2l_path) if a2l_path is not None else None
    results: list[VariantExecutionResult] = []
    for variant, files in plan:
        if status_callback is not None:
            status_callback(
                f"Executing variant '{variant.variant_id}' "
                f"({len(files)} file(s))..."
            )
        result = _execute_one_variant(
            variant,
            files,
            project_dir,
            mac_records,
            a2l_data,
            capture_mem_map=capture_mem_maps,
        )
        results.append(result)
        if status_callback is not None:
            status_callback(
                f"Variant '{variant.variant_id}': {result.status} - "
                f"{len(result.change_summaries)} change, "
                f"{len(result.check_results)} check"
            )
    return results


def execute_project_variants(
    project_dir: Path,
    variant_set: ProjectVariantSet,
    *,
    scope: str = SCOPE_ALL,
    fallback_batch: Sequence[Path] = (),
    status_callback: Optional[StatusCallback] = None,
    capture_mem_maps: bool = False,
) -> Tuple[list[VariantExecutionResult], list[ValidationIssue]]:
    """
    Summary:
        The one-call E6 entry point: read the manifest (capped), locate the
        project's shared MAC / A2L overlays, build the deterministic plan,
        and execute it variant-by-variant (HLR-006).

    Args:
        project_dir (Path): The project directory
            (``.s19tool/workarea/<project>/``).
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.
        scope (str): One of :data:`EXECUTION_SCOPES`; see
            :func:`plan_variant_executions`.
        fallback_batch (Sequence[Path]): The manifest-absent default file
            list (LLR-006.1 batch mode over all variants).
        status_callback (Optional[StatusCallback]): Forwarded to
            :func:`execute_variant_plan` (F-Q-18).
        capture_mem_maps (bool): Forwarded to
            :func:`execute_variant_plan` — ``True`` retains each variant's
            post-change memory map for the E7 report generator
            (LLR-007.8).

    Returns:
        Tuple[list[VariantExecutionResult], list[ValidationIssue]]: The
        per-variant results (``len == planned variant count``) plus the
        manifest's collected findings (empty when the manifest is absent or
        clean) so the caller can surface containment skips.

    Data Flow:
        - ``read_project_manifest`` → manifest or ``None`` (default mode).
        - ``validate_project_files`` locates the single MAC / A2L overlays
          (a cardinality-faulted project yields no overlays rather than
          aborting the execution).
        - ``plan_variant_executions`` → ``execute_variant_plan``.

    Dependencies:
        Uses:
            - read_project_manifest / plan_variant_executions /
              execute_variant_plan
            - validate_project_files
        Used by:
            - s19_app.tui.app.S19TuiApp._start_execute_scope_worker
            - tests/test_variant_execution.py
    """
    manifest = read_project_manifest(project_dir)
    manifest_issues = list(manifest.issues) if manifest is not None else []
    data_files, a2l_files, error = validate_project_files(project_dir)
    if error is not None:
        data_files = []
        a2l_files = []
    mac_path = next(
        (
            item
            for item in data_files
            if item.suffix.lower() in MAC_EXTENSIONS
        ),
        None,
    )
    a2l_path = a2l_files[0] if a2l_files else None
    plan = plan_variant_executions(
        variant_set, manifest, scope=scope, fallback_batch=fallback_batch
    )
    results = execute_variant_plan(
        plan,
        project_dir,
        mac_path=mac_path,
        a2l_path=a2l_path,
        status_callback=status_callback,
        capture_mem_maps=capture_mem_maps,
    )
    return results, manifest_issues
