"""Batch-97 frozen literals and fixture builders (appendix A.2 / A.5).

The literals are committed verbatim from ``01-requirements-appendix.md`` A.2,
each with its own length guard, so a drifted copy fails at import rather than
silently weakening every test that reads it. The builders grow per increment
(design-proposal §5.1); Inc-1 adds the project builder, the app's own project
load and the junction arm; Inc-2 the NUL flow and set; Inc-3 the demo A2L,
``hostile.a2l``, an image covering the A2L, the staging block and the Check
Editor opener.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples" / "case_00_public"

# --------------------------------------------------------------------------- #
# A.2 frozen literals
# --------------------------------------------------------------------------- #

ES_MARKER = (
    r"[áéíóúñÁÉÍÓÚÑ¿¡]|\bde\b|\b(?i:del|la|las|los|el|una|para|con|sin|tras|"
    r"paso|bloque|pendiente|esperando|humano|guardar|cargar|ejecutar|archivo|"
    r"carpeta|salida|entrada|hay|ninguno|ninguna|cadena|cadenas|copiar|pegar|"
    r"borrar|limpiar|correr|confirmar|registro|falta|faltan|ya|desde|hasta|"
    r"cada|valor|sustituir|pegado|comando|instruccion|pendientes|sesion)\b"
)
ES_MARKER_RE = re.compile(ES_MARKER)

#: (scope, value) — the 48 painted Spanish constants on 9c7beaf.
ES_48_9C7BEAF: tuple[tuple[str, str], ...] = (
    ("FlowBuilderPanel", " — al confirmar, la SALIDA se copia aquí"),
    ("FlowBuilderPanel", "sesión: "),
    ("FlowBuilderPanel", "comando exacto (terminal) / instrucción (manual)"),
    ("FlowBuilderPanel", "LOG — obligatorio (texto de constancia)"),
    ("FlowBuilderPanel", "SALIDA — path absoluto preferido"),
    ("FlowBuilderPanel", "sesión: (sin proyecto activo — el directorio de sesión se muestra al cargar un proyecto)"),
    ("FlowBuilderPanel", "valor a sustituir"),
    ("FlowBuilderPanel", "Añadir var"),
    ("FlowBuilderPanel", "Copiar"),
    ("FlowBuilderPanel", "Pegar"),
    ("FlowBuilderPanel", "(funnel vacío — los ${NAME} de los change-docs pasan intactos)"),
    ("FlowBuilderPanel", "funnel rechazado: el nombre debe ser un placeholder [A-Z0-9_] (p.ej. BOOST) — sin minúsculas ni espacios."),
    ("FlowBuilderPanel", "funnel rechazado: el valor no puede estar vacío."),
    ("FlowBuilderPanel", " (hay "),
    ("FlowBuilderPanel", "copiar rechazado: no hay bloque nº "),
    ("FlowBuilderPanel", "copiar rechazado: el canvas está vacío."),
    ("FlowBuilderPanel", "pegar: el portapapeles está vacío — nada que pegar."),
    ("FlowBuilderPanel", "pegar rechazado: cargue un proyecto (se valida contra el directorio de sesión)."),
    ("FlowBuilderPanel", "bloque inválido"),
    ("FlowBuilderPanel", "pegar rechazado: "),
    ("FlowBuilderPanel", "pegado: "),
    ("FlowBuilderPanel", "el comando exacto"),
    ("FlowBuilderPanel", "la instrucción"),
    ("FlowBuilderPanel", " a correr fuera de la app."),
    ("FlowBuilderPanel", "paso externo rechazado: falta "),
    ("FlowBuilderPanel", "paso externo rechazado: el LOG es OBLIGATORIO (texto de constancia, nunca opcional)."),
    ("FlowBuilderPanel", "paso externo rechazado: falta el ARCHIVO DE SALIDA (path absoluto preferido)."),
    ("FlowExecutionPanel", "✓ Confirmar paso externo"),
    ("FlowExecutionPanel", "(sin proyecto activo)"),
    ("FlowExecutionPanel", "sesión: "),
    ("FlowExecutionPanel", "' pendiente"),
    ("FlowExecutionPanel", "⚠ SALIDA sin confirmar - esperando humano"),
    ("FlowExecutionPanel", "ESPERANDO HUMANO"),
    ("FlowExecutionPanel", " · ESPERANDO HUMANO — paso externo (block "),
    ("FlowExecutionPanel", "' pendiente\n"),
    ("FlowExecutionPanel", " · re-run tras confirmar paso externo\n"),
    ("module:235", "PAUSED - ESPERANDO HUMANO"),
    ("flow_execution_service", "} no declarada en el flow — el placeholder queda intacto"),
    ("flow_execution_service", "comando"),
    ("flow_execution_service", "instruccion"),
    ("flow_execution_service", "' + SALIDA '"),
    ("flow_execution_service", "' pendientes"),
    ("flow_execution_service", "paused - esperando humano: "),
    ("flow_execution_service", "' no existe - la constancia es obligatoria, nunca opcional"),
    ("flow_execution_service", "' no existe - correr el paso externo antes de confirmar"),
    ("flow_execution_service", "salida '"),
    ("flow_execution_service", " (sesion)"),
    ("flow_execution_service", "' recibido · salida copiada a "),
)

HOSTILE_NAME = "b97[bold]x[red]y[link=e]z[@click=app.quit]w"
HOSTILE_CONTENT = "b97[bold]x[/]y[red]z[link=https://e.invalid]l[/link][@click=app.quit]q\x07"
#: The batch-77 ``_HOSTILE`` (tests/test_tui_check_editor.py:54-56) minus NUL.
HOSTILE_C1 = "b77hostilemark\x1b[31m_evil[red]\x9b1m\x9d8;;u\x07\x7f"
HOSTILE_NUL = "calib\x00hotfix.json"

PE_IDS_9C7BEAF: frozenset[str] = frozenset(
    """
    patch_before_after_button patch_before_after_buttons patch_before_after_card
    patch_before_after_row patch_checks_controls patch_checks_help
    patch_checks_results patch_checks_run_button patch_checks_section_label
    patch_checks_status patch_checks_strip patch_doc_apply_button
    patch_doc_controls patch_doc_empty_state patch_doc_entries_table
    patch_doc_entry_buttons patch_doc_entry_inputs patch_doc_file_line1
    patch_doc_file_line2 patch_doc_file_row patch_doc_file_select
    patch_doc_issue_count patch_doc_issues patch_doc_load_button
    patch_doc_path_input patch_doc_refresh_button patch_doc_save_button
    patch_doc_validate_button patch_edit_json_button patch_editor_panel
    patch_entry_add_button patch_entry_address_input patch_entry_bytes_input
    patch_entry_edit_button patch_entry_edit_json_button patch_entry_remove_button
    patch_entry_value_input patch_execute_buttons patch_execute_row
    patch_execute_run_button patch_execute_scope_button patch_history_controls
    patch_history_strip patch_pane_entries patch_paste_controls patch_paste_gauge
    patch_paste_parse_button patch_paste_row patch_paste_text patch_redo_button
    patch_saveback_buttons patch_saveback_confirm_button
    patch_saveback_decline_button patch_saveback_name_input patch_saveback_row
    patch_saveback_width_button patch_scope_line patch_script_section_label
    patch_undo_button patch_win_checks patch_win_checks_body patch_win_json
    patch_win_json_body patch_win_json_dock_spacer patch_win_script
    patch_win_script_body
    """.split()
)

CE_IDS_9C7BEAF: frozenset[str] = frozenset(
    """
    check_actions_row check_actions_row2 check_addendum_preview check_apply_ghost
    check_apply_hint check_columns check_editor_panel check_fields_count
    check_file_name_input check_left_column check_mem_add_button
    check_mem_address_input check_mem_controls check_mem_inputs
    check_mem_label_input check_mem_remove_button check_mem_size_input
    check_mem_table check_param_controls check_param_filter
    check_param_include_button check_param_table check_preview
    check_preview_toggle_button check_results check_right_column
    check_spec_file_row check_spec_file_select check_status
    check_validate_button check_write_button
    """.split()
)

# The literals' own guards (A.2): a drifted copy fails at import.
assert len(ES_48_9C7BEAF) == 48, len(ES_48_9C7BEAF)
assert len(PE_IDS_9C7BEAF) == 66, len(PE_IDS_9C7BEAF)
assert len(CE_IDS_9C7BEAF) == 31, len(CE_IDS_9C7BEAF)
assert "\x00" not in HOSTILE_C1 and "\x00" in HOSTILE_NUL
assert "/" not in HOSTILE_NAME

# --------------------------------------------------------------------------- #
# A.5 builders — Inc-1: project, the app's own project load, junction
# --------------------------------------------------------------------------- #


def make_project(app, name: str = "proj1") -> Path:
    """Create ``<workarea>/<name>/`` holding a copy of the tracked ``prg.s19``.

    The project is not loaded here; :func:`load_project` opens it through the
    app's own load so ``current_project_dir`` is the resolved directory (P-58).
    """
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(EXAMPLES_DIR / "prg.s19", project_dir / "prg.s19")
    return project_dir


def load_project(app, name: str = "proj1") -> Path:
    """Open the project through the app's own load path (``app.py:8200``).

    Returns the directory the app now holds as the trust anchor, never one set
    by hand. Fails loud when the load did not take.
    """
    app._handle_load_project(name)
    held = app.active_project_dir()
    assert held is not None and app.current_project == name, (
        f"the project load did not take: {list(app.log_lines)}"
    )
    return held


def unload_project(app) -> None:
    """Drop the active project and run the app's one project-refresh seam.

    The app has no unload action; this clears the two fields
    ``_active_project_dir`` reads and calls ``update_project_labels`` — the
    seam every project-context change goes through (it re-resolves every
    mounted chip), so a chip sees the transition a user-caused change makes.
    """
    app.current_project = None
    app.current_project_dir = None
    app.update_project_labels()
    assert app.active_project_dir() is None


def make_junction(link: Path, target: Path) -> str:
    """Make ``link`` a directory junction to ``target`` (P-34).

    On Windows this is a real NTFS junction (``is_symlink()`` is False, the
    reparse attribute is set). Elsewhere a symlink stands in, and the returned
    kind says so, so a POSIX run never claims to have tested a junction.
    """
    target.mkdir(parents=True, exist_ok=True)
    if sys.platform.startswith("win"):
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return "junction"
    os.symlink(target, link, target_is_directory=True)
    return "symlink (non-Windows stand-in for a junction)"


# --------------------------------------------------------------------------- #
# A.5 builders — Inc-2: the NUL flow and the NUL set (P-36)
# --------------------------------------------------------------------------- #


def patch_chain_blocks(change_doc_ref: str = "calib_hotfix.json") -> list:
    """The ``patch_chain`` demo block list: source, patch, check, write_out."""
    from s19_app.tui.services.flow_model import (
        CheckBlock,
        PatchBlock,
        SourceBlock,
        WriteOutBlock,
    )

    return [
        SourceBlock("prg.s19"),
        PatchBlock(change_doc_ref),
        CheckBlock("baseline.chk.json"),
        WriteOutBlock("out.s19"),
    ]


def nul_flow(project_dir: Path) -> Path:
    """Write ``flows/nul_flow.json``: ``patch_chain`` with ``change_doc_ref =
    HOSTILE_NUL``, serialised by the shipped ``flow_to_dict``."""
    import json

    from s19_app.tui.services.flow_model import Flow
    from s19_app.tui.services.flow_persistence_service import (
        FLOWS_SUBDIR,
        flow_to_dict,
    )

    flows_dir = project_dir / FLOWS_SUBDIR
    flows_dir.mkdir(parents=True, exist_ok=True)
    path = flows_dir / "nul_flow.json"
    payload = flow_to_dict(Flow(name="nul_flow", blocks=patch_chain_blocks(HOSTILE_NUL)))
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def nul_set(project_dir: Path) -> Path:
    """Write ``flowsets/nul_set.json``: one chain whose template is
    ``patch\x00chain``, serialised by the shipped ``chain_set_to_dict``."""
    import json

    from s19_app.tui.services.flow_persistence_service import (
        FLOWSETS_SUBDIR,
        ChainSet,
        ChainSetEntry,
        chain_set_to_dict,
    )

    sets_dir = project_dir / FLOWSETS_SUBDIR
    sets_dir.mkdir(parents=True, exist_ok=True)
    path = sets_dir / "nul_set.json"
    entry = ChainSetEntry(
        chain="lane0", template="patch\x00chain", inputs=((0, "prg.s19"),)
    )
    payload = chain_set_to_dict(ChainSet(name="nul_set", chains=(entry,)))
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# A.5 builders — Inc-3: the A2L, hostile.a2l, an image under the A2L, the
# staging block (P-24, P-28, P-51)
# --------------------------------------------------------------------------- #

DEMO_A2L = EXAMPLES_DIR / "ASAP2_Demo_V161.a2l"

#: The six parameters that share ``0x00013A00`` (A.1 P-38): only the name tells
#: their REPORT FIELDS lines apart.
SIX_13A00: tuple[str, ...] = (
    "ASAM.M.SCALAR.UBYTE.IDENTICAL",
    "ASAM.M.SCALAR.UBYTE.TAB_VERB_DEFAULT_VALUE",
    "ASAM.M.SCALAR.UBYTE.TAB_VERB_NO_DEFAULT_VALUE",
    "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_DEFAULT_VALUE",
    "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE",
    "ASAM.M.SCALAR.UBYTE.TAB_INTP_DEFAULT_VALUE",
)

#: One of the demo's 47-cell names, the widest real parameter name.
LONGEST_NAME = "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE"
assert len(LONGEST_NAME) == 47


#: Inc-3 gate fold (code-reviewer F1 / F2): a dotted name far wider than any
#: Parameter column of the range (165 cells; the 260x70 column is narrower), so
#: the ledger clip, the full-name line clip and the Fields tail clip all fire at
#: every LLR-149.2 size. Its tail ``_TAIL_MARK`` is what the clips must keep.
LONG_NAME = (
    "ASAM.M.SCALAR.UBYTE."
    + "_".join(f"LONG_SEGMENT_{i:02d}" for i in range(9))
    + "_TAIL_MARK"
)
assert len(LONG_NAME) > 160


def _renamed_a2l(dest_dir: Path, new_name: str, file_name: str) -> Path:
    """The demo A2L with its first CHARACTERISTIC renamed ``new_name``. Only the
    ``/begin`` line is rewritten."""
    lines = DEMO_A2L.read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip().startswith("/begin CHARACTERISTIC "):
            old = line.split()[2]
            lines[index] = line.replace(old, new_name, 1)
            break
    else:  # pragma: no cover - the demo file always holds one
        raise AssertionError("no CHARACTERISTIC in the demo A2L")
    path = dest_dir / file_name
    path.write_text("".join(lines), encoding="utf-8")
    return path


def hostile_a2l(dest_dir: Path) -> Path:
    """Write ``hostile.a2l``: the demo A2L with its first CHARACTERISTIC renamed
    ``HOSTILE_CONTENT`` (A.5, P-28)."""
    return _renamed_a2l(dest_dir, HOSTILE_CONTENT, "hostile.a2l")


def long_name_a2l(dest_dir: Path) -> Path:
    """Write ``long_name.a2l``: the demo A2L with its first CHARACTERISTIC
    renamed :data:`LONG_NAME` (Inc-3 gate fold, F1 / F2)."""
    return _renamed_a2l(dest_dir, LONG_NAME, "long_name.a2l")


def write_cover_s19(path: Path, tags) -> Path:
    """Write an S19 image holding one byte pattern under every A2L field.

    Measured 2026-10-20: ``prg.s19`` covers 0 of the demo A2L's 75 addresses,
    so a written ``.chk.json`` over included parameters would hold no entry
    (the writer skips a field outside the loaded image). This image puts
    ``byte_size`` bytes under each tag's address, S2 records, so a write
    declares every included field.
    """
    mem = {}
    for tag in tags:
        address = tag.get("address")
        if not isinstance(address, int):
            continue
        for offset in range(int(tag.get("byte_size") or 1)):
            mem[address + offset] = (address + offset) & 0xFF
    lines = ["S0030000FC"]
    for address in sorted(mem):
        payload = [3 + 1 + 1] + list((address).to_bytes(3, "big")) + [mem[address]]
        count = payload[0]
        body = payload[1:]
        checksum = (~(count + sum(body))) & 0xFF
        lines.append("S2" + f"{count:02X}" + "".join(f"{b:02X}" for b in body) + f"{checksum:02X}")
    lines.append("S804000000FB")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def staging_block(base_dir: Path, spec_name: str, kind: str) -> Path:
    """Block the Write's staging seam (P-51) at the batch-99 Inc-3a location
    (HLR-155 / LLR-155.1): the retired shared ``temp/<name>`` staging path is
    gone — every write stages in a private ``mkdtemp`` directory under
    ``temp/.staging/`` and places through an exclusive claim, so a planted
    file can no longer collide with a staged file and a read-only target can
    no longer block anything (the new writer never overwrites an existing
    name). ``kind="dir"`` plants a FILE at ``temp/.staging`` (wrong type at
    the staging home); ``kind="readonly"`` plants a SYMLINK (a reparse
    point) at ``temp/.staging`` — LLR-155.1's reparse check refuses either
    blocker, so the Write reports ``MF-WRITE-CONTAINMENT``. ``spec_name`` is
    kept for signature compatibility."""
    from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

    workarea = base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    temp = workarea / "temp"
    temp.mkdir(parents=True, exist_ok=True)
    target = temp / ".staging"
    # the home may already exist (the first placement — e.g. the A2L load —
    # creates it and it persists); clear it, then plant the blocker
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    if kind == "dir":
        # wrong type at the staging home: a file where the home belongs
        target.write_text("{}", encoding="utf-8")
    else:
        # a reparse point at the staging home (LLR-155.1's reparse check) —
        # the retired read-only-FILE seam is gone with the shared staging
        # path: the new writer never overwrites an existing name, so a
        # read-only file can no longer block anything
        os.symlink(workarea / "nowhere", target, target_is_directory=True)
    return target


async def open_check_editor(app, pilot, *, a2l=DEMO_A2L, cover_image: bool = False) -> object:
    """Load ``a2l`` (and an image covering it) through the app's own loaders,
    then show the Check Editor through ``action_show_screen`` (the rail path
    that prefills the panel). Returns the panel."""
    from tests.b97_probes import settle

    await settle(pilot)
    if a2l is not None:
        app.load_a2l_from_path(Path(a2l))
        await settle(pilot)
        tags = app._compute_a2l_enriched_tags()
        assert tags, f"the A2L did not load: {list(app.log_lines)[-3:]}"
        if cover_image:
            image = write_cover_s19(app.base_dir / "a2l_cover.s19", tags)
            app.load_from_path(image)
            for _ in range(100):
                if app.current_file is not None:
                    break
                await pilot.pause(0.05)
            assert app.current_file is not None, "the cover image did not load"
    app.action_show_screen("check_editor")
    await settle(pilot, 6)
    return app.query_one("#check_editor_panel")


# --------------------------------------------------------------------------- #
# A.5 builders — Inc-4: the change-sets of the Patch Editor (P-5, P-27, P-29)
# --------------------------------------------------------------------------- #

#: ``calib_hotfix.json`` — six ``bytes`` entries inside ``prg.s19`` (A.5). The
#: third is the 11-byte run at ``0xEC00`` the design budget reads (§3), the
#: ASCII of ``CAL-2026-10``.
CALIB_ENTRIES: tuple[tuple[int, tuple[int, ...]], ...] = (
    (0xEB10, (0xDE, 0xAD, 0xBE, 0xEF)),
    (0xEB40, (0x00, 0x00, 0x00, 0x01)),
    (0xEC00, tuple(b"CAL-2026-10")),
    (0xECA0, (0xA5,) * 8),
    (0xED00, (0x7F, 0xFF)),
    (0xED40, (0x01, 0x02, 0x03, 0x04, 0x05, 0x06)),
)
CALIB_ADDRESSES = ["0xEB10", "0xEB40", "0xEC00", "0xECA0", "0xED00", "0xED40"]
assert len(CALIB_ENTRIES) == 6


def _document(entries) -> object:
    from s19_app.tui.changes.model import ChangeDocument

    return ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=list(entries),
    )


def _bytes_entry(address: int, run) -> object:
    from s19_app.tui.changes.model import ChangeEntry

    return ChangeEntry(entry_type="bytes", address=address, encoded_bytes=tuple(run))


def write_changeset(path: Path, entries) -> Path:
    """Serialise ``entries`` with the shipped serialiser into ``path``."""
    from s19_app.tui.changes.io import serialize_change_document

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(serialize_change_document(_document(entries)))
    return path


def calib_hotfix(dest_dir: Path, name: str = "calib_hotfix.json") -> Path:
    """``calib_hotfix.json`` (A.5): the six entries of :data:`CALIB_ENTRIES`."""
    return write_changeset(dest_dir / name, [_bytes_entry(a, r) for a, r in CALIB_ENTRIES])


def empty_changeset(dest_dir: Path) -> Path:
    """``empty.json`` (A.5): the serialiser over 0 entries."""
    return write_changeset(dest_dir / "empty.json", [])


def legacy_v1(dest_dir: Path) -> Path:
    """``legacy_v1.json`` (A.5): a literal batch-04 v1 unified dict — the v1
    format token and its ``parameters`` / ``memory`` shape (loads as the empty
    document plus one ``CHG-V1-FORMAT`` ERROR, LLR-003.5)."""
    import json

    path = dest_dir / "legacy_v1.json"
    path.write_text(json.dumps({"format": "s19app-unified-changeset", "parameters": [], "memory": [{"address": "0xEB10", "bytes": "DE AD"}]}), encoding="utf-8")
    return path


def hostile_name_changeset(dest_dir: Path) -> Path:
    """``HOSTILE_NAME.json`` (A.5, P-27): calib_hotfix under the hostile name."""
    return calib_hotfix(dest_dir, f"{HOSTILE_NAME}.json")


def hostile_content_changeset(dest_dir: Path) -> Path:
    """``hostile_content.json`` (A.5, P-29): a ``string`` entry whose value is
    ``HOSTILE_CONTENT + HOSTILE_C1`` and a ``bytes`` entry whose ``symbol`` is
    ``HOSTILE_CONTENT`` (refused with an echoing finding — no A2L context)."""
    import json

    payload = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [
            {"type": "string", "address": "0xEC00", "value": HOSTILE_CONTENT + HOSTILE_C1},
            {"type": "bytes", "address": "0xEB10", "bytes": "DE AD", "symbol": HOSTILE_CONTENT},
        ],
    }
    path = dest_dir / "hostile_content.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


async def open_patch_editor(app, pilot, *, image: bool = True) -> object:
    """Load ``prg.s19`` (when ``image``) through the app's own loader, then show
    the Patch Editor through ``action_show_screen``. Returns the panel."""
    from tests.b97_probes import settle

    await settle(pilot)
    if image:
        copy = app.base_dir / "prg.s19"
        shutil.copyfile(EXAMPLES_DIR / "prg.s19", copy)
        app.load_from_path(copy)
        for _ in range(100):
            if app.current_file is not None:
                break
            await pilot.pause(0.05)
        assert app.current_file is not None, "prg.s19 did not load"
    app.action_show_screen("patch")
    await settle(pilot, 6)
    return app.query_one("#patch_editor_panel")


async def load_change_file(app, pilot, panel, path: Path) -> None:
    """Type ``path`` beside Load and press Load (the shipped control)."""
    from textual.widgets import Button, Input

    from tests.b97_probes import settle

    panel.query_one("#patch_doc_path_input", Input).value = str(path)
    panel.query_one("#patch_doc_load_button", Button).press()
    await settle(pilot, 6)


# --------------------------------------------------------------------------- #
# A.5 builders — Inc-5: the Flow Builder chains (P-31, P-41, P-45, P-36)
# --------------------------------------------------------------------------- #

#: ``baseline.chk.json`` (A.5): a check document over 4 fields. Three hold the
#: bytes ``calib_hotfix.json`` writes; the fourth (``0xFCB0``) does not, so the
#: advisory check block of ``patch_chain`` ends with notices (``ok ok notices
#: ok``, P-31) and the run banner reads ``NOTICES`` (``ISSUES`` before the Inc-5 gate fold).
CHECK_ENTRIES: tuple[tuple[int, tuple[int, ...]], ...] = (
    (0xEB10, (0xDE, 0xAD, 0xBE, 0xEF)),
    (0xEB40, (0x00, 0x00, 0x00, 0x01)),
    (0xED00, (0x7F, 0xFF)),
    (0xFCB0, (0x00, 0x00)),
)

PATCHED_OUTPUT = "fw_app_patched.s19"


def baseline_check(dest_dir: Path) -> Path:
    """``baseline.chk.json``: the shipped serialiser over :data:`CHECK_ENTRIES`
    with ``kind = check``."""
    from dataclasses import replace

    from s19_app.tui.changes.io import serialize_change_document

    path = dest_dir / "baseline.chk.json"
    document = replace(_document([_bytes_entry(a, r) for a, r in CHECK_ENTRIES]), kind="check")
    path.write_bytes(serialize_change_document(document))
    return path


def write_flow(project_dir: Path, name: str, blocks) -> Path:
    """Write ``flows/<name>.json`` with the shipped ``save``-side serialiser."""
    import json

    from s19_app.tui.services.flow_model import Flow
    from s19_app.tui.services.flow_persistence_service import FLOWS_SUBDIR, flow_to_dict

    flows_dir = project_dir / FLOWS_SUBDIR
    flows_dir.mkdir(parents=True, exist_ok=True)
    path = flows_dir / f"{name}.json"
    path.write_text(json.dumps(flow_to_dict(Flow(name=name, blocks=list(blocks)))), encoding="utf-8")
    return path


def patch_chain_demo() -> list:
    """``patch_chain`` (A.5): load ``prg.s19`` → patch ``calib_hotfix.json`` →
    advisory check ``baseline.chk.json`` → write ``fw_app_patched.s19``."""
    from s19_app.tui.services.flow_model import WriteOutBlock

    return patch_chain_blocks()[:3] + [WriteOutBlock(PATCHED_OUTPUT)]


def flash_chain_demo(project_dir: Path) -> list:
    """``flash_chain`` (A.5): load → patch → EXT-STEP (terminal) → write-out;
    the step's log and output paths lie inside the project (P-31: ``ok ok
    waiting skipped``)."""
    from s19_app.tui.services.flow_model import (
        EXTERNAL_MODE_TERMINAL,
        ExternalStepBlock,
        WriteOutBlock,
    )

    return patch_chain_blocks()[:2] + [
        ExternalStepBlock(
            mode=EXTERNAL_MODE_TERMINAL,
            instruction="./flash.sh fw_app_patched.s19",
            log_ref="flash_log.txt",
            output_path=str(project_dir / "fw_app_flashed.s19"),
        ),
        WriteOutBlock("fw_app_flashed_copy.s19"),
    ]


def crc_chain_demo() -> list:
    """A Builder chain holding a CRC card (TC-B97-18 paint arm): load → patch
    → CRC ``crc.json`` → write-out."""
    from s19_app.tui.services.flow_model import CrcBlock, WriteOutBlock

    return patch_chain_blocks()[:2] + [CrcBlock("crc.json"), WriteOutBlock(PATCHED_OUTPUT)]


def hostile_flow_demo(project_dir: Path) -> list:
    """``hostile_flow`` (A.5, P-30, P-45): ``flash_chain`` with
    ``change_doc_ref``, ``instruction`` and ``log_ref`` = ``HOSTILE_CONTENT +
    HOSTILE_C1`` and ``output_path`` = ``HOSTILE_NAME`` (slash-free)."""
    from dataclasses import replace

    blocks = flash_chain_demo(project_dir)
    payload = HOSTILE_CONTENT + HOSTILE_C1
    blocks[1] = replace(blocks[1], change_doc_ref=payload)
    blocks[2] = replace(blocks[2], instruction=payload, log_ref=payload, output_path=HOSTILE_NAME)
    return blocks


def flow_project(app, name: str = "proj1") -> Path:
    """A project opened through the app's own load (P-58) holding ``prg.s19``,
    ``calib_hotfix.json``, ``baseline.chk.json``, ``crc.json`` and the saved
    flows ``patch_chain``, ``flash_chain`` and ``crc_chain``."""
    make_project(app, name)
    project_dir = load_project(app, name)
    calib_hotfix(project_dir)
    baseline_check(project_dir)
    # batch-99 Inc-5 (HLR-159): the fixture CRC config covers bytes prg.s19
    # actually holds (0xEB08-0xFA00, output at 0x10000). The example config's
    # regions hold no image byte of prg.s19 and now refuse the CRC block —
    # these FX fixtures test execution mechanics, not coverage refusals.
    (project_dir / "crc.json").write_text(
        json.dumps(
            {
                "polynomial": "0x04C11DB7",
                "init": "0xFFFFFFFF",
                "reverse": True,
                "final_xor": "0xFFFFFFFF",
                "regions": [
                    {
                        "start": "0x0000EB08",
                        "end": "0x0000FA00",
                        "output_address": "0x00010000",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    write_flow(project_dir, "patch_chain", patch_chain_demo())
    write_flow(project_dir, "flash_chain", flash_chain_demo(project_dir))
    write_flow(project_dir, "crc_chain", crc_chain_demo())
    return project_dir


async def open_flow_builder(app, pilot) -> object:
    """Show the Flow Builder through ``action_show_screen`` and return the panel."""
    from tests.b97_probes import settled

    app.action_show_screen("flow")
    panel = app.query_one("#flow_panel")
    await settled(pilot, lambda: panel.region.height > 0, "the Flow Builder panel is laid out")
    return panel


async def load_flow(app, pilot, stem: str) -> None:
    """Load ``flows/<stem>.json`` through ``#flow_load`` and the picker (the
    shipped controls), then wait until the panel shows it or a refusal."""
    from textual.widgets import Button, ListView

    from tests.b97_probes import settled

    panel = app.query_one("#flow_panel")
    panel.query_one("#flow_load", Button).press()
    await settled(
        pilot,
        lambda: stem in [item.name for item in app.screen.query("#flow_list ListItem")],
        f"the flow picker lists {stem}",
    )
    names = [item.name for item in app.screen.query("#flow_list ListItem")]
    listing = app.screen.query_one("#flow_list", ListView)
    target = names.index(stem)

    def highlighted() -> bool:
        # Load reads the HIGHLIGHTED item, which follows ``index`` a tick
        # later; an index set while the list still mounts is re-applied.
        child = listing.highlighted_child
        if child is not None and child.name == stem:
            return True
        listing.index = target
        return False

    await settled(pilot, highlighted, f"{stem} highlighted in the flow picker")
    app.screen.query_one("#flow_load_ok", Button).press()
    await settled(
        pilot,
        lambda: panel._flow_name == stem or bool(panel.query("#flow_result .flow-quarantine")),
        f"flows/{stem}.json loaded or refused",
    )


# --------------------------------------------------------------------------- #
# A.5 builders — Inc-6: the Flow Execution sets (P-31, P-41, P-50, P-60)
# --------------------------------------------------------------------------- #

#: The external-step evidence of ``flash_chain`` (its ``log_ref`` and the file
#: name of its ``output_path``, both inside the project).
FLASH_LOG = "flash_log.txt"
FLASH_OUT = "fw_app_flashed.s19"
#: ``flash2_chain``'s two external steps (A.5): (log, output file name).
FLASH2_STEPS = (("step1_log.txt", "ext1_out.s19"), ("step2_log.txt", "ext2_out.s19"))


#: ``err_chain``'s change doc: never written, so the patch block errs.
ERR_CHANGE_DOC = "err_missing.json"


def err_chain_demo() -> list:
    """``err_chain`` (A.5, P-31: ``ok error skipped skipped``): ``patch_chain``
    whose patch ref names a change doc that does not exist.

    Deviation from A.5, recorded in the Inc-6 packet: A.5 builds the error
    with one entry at ``0x00020000`` (outside ``prg.s19``); on HEAD
    ``b514b07`` such a patch reports ``ok`` — ``applied 0 entries`` — so the
    chain never errs. A missing change doc is the error the run log's
    ``'<ref>' missing`` line names.

    batch-99 Inc 3b re-pin (HLR-155 D7 / LLR-155.5): the err lane keeps its
    OWN output name — the THREE set pairs this chain with ``patch_chain``,
    and two lanes resolving to one WRITE-OUT name refuse the set at start
    now, before the err lane's missing-doc error can even paint.
    """
    from s19_app.tui.services.flow_model import WriteOutBlock

    return patch_chain_blocks(ERR_CHANGE_DOC)[:3] + [
        WriteOutBlock("fw_err.s19")
    ]


def crc_wait_chain_demo(project_dir: Path) -> list:
    """``crc_wait_chain`` (A.5, P-41): load → CRC ``crc.json`` → EXT-STEP →
    write-out (``ok notices waiting skipped``): a CRC card beside the
    waiting card."""
    from s19_app.tui.services.flow_model import CrcBlock

    flash = flash_chain_demo(project_dir)
    return [flash[0], CrcBlock("crc.json"), flash[2], flash[3]]


def six_ok_demo(output: str) -> list:
    """``six_ok_a`` / ``six_ok_b`` (A.5, P-41): load → patch → check → CRC →
    CRC → write-out ``output``."""
    from s19_app.tui.services.flow_model import CrcBlock, WriteOutBlock

    return patch_chain_blocks()[:3] + [CrcBlock("crc.json"), CrcBlock("crc.json"), WriteOutBlock(output)]


def six_wait_demo(project_dir: Path) -> list:
    """``six_wait`` (A.5, P-41): load → patch → check → CRC → EXT-STEP →
    write-out, waiting at block 4 (0-based)."""
    from s19_app.tui.services.flow_model import CrcBlock

    flash = flash_chain_demo(project_dir)
    return patch_chain_blocks()[:3] + [CrcBlock("crc.json"), flash[2], flash[3]]


def flash2_chain_demo(project_dir: Path) -> list:
    """``flash2_chain`` (A.5, P-60): load → patch → EXT-STEP → EXT-STEP →
    write-out; each step's log and output file inside the project."""
    from s19_app.tui.services.flow_model import (
        EXTERNAL_MODE_TERMINAL,
        ExternalStepBlock,
        WriteOutBlock,
    )

    steps = [
        ExternalStepBlock(
            mode=EXTERNAL_MODE_TERMINAL,
            instruction=f"./step{n}.sh",
            log_ref=log,
            output_path=str(project_dir / out),
        )
        for n, (log, out) in enumerate(FLASH2_STEPS, start=1)
    ]
    return patch_chain_blocks()[:2] + steps + [WriteOutBlock("fw_two_steps.s19")]


def flip_one_data_byte(source: Path, dest: Path, avoid: tuple = ()) -> int:
    """Copy an S19 image flipping the first data byte of the first data
    record whose span holds none of ``avoid``; the record's checksum is
    recomputed. Returns the flipped byte's address (``prg_v2.s19``, A.5)."""
    lines = source.read_text(encoding="ascii").splitlines()
    widths = {"S1": 2, "S2": 3, "S3": 4}
    for row, line in enumerate(lines):
        kind = line[:2]
        if kind not in widths:
            continue
        raw = bytes.fromhex(line[2:])
        aw = widths[kind]
        address = int.from_bytes(raw[1:1 + aw], "big")
        data = bytearray(raw[1 + aw:-1])
        if not data or any(address <= a < address + len(data) for a in avoid):
            continue
        data[0] ^= 0xFF
        body = bytes([raw[0]]) + raw[1:1 + aw] + bytes(data)
        checksum = (~sum(body)) & 0xFF
        lines[row] = kind + (body + bytes([checksum])).hex().upper()
        dest.write_text("\n".join(lines) + "\n", encoding="ascii")
        return address
    raise AssertionError("no data record to flip")


def fx_project(app, name: str = "proj1") -> Path:
    """A project opened through the app's own load (P-58) holding every
    Flow Execution fixture of A.5: ``patch_chain``, ``flash_chain``,
    ``err_chain``, ``crc_wait_chain``, ``six_ok_a``, ``six_ok_b``,
    ``six_wait``, ``flash2_chain``, ``patch_chain_b`` and ``prg_v2.s19``."""
    from dataclasses import replace

    project_dir = flow_project(app, name)
    write_flow(project_dir, "err_chain", err_chain_demo())
    write_flow(project_dir, "crc_wait_chain", crc_wait_chain_demo(project_dir))
    write_flow(project_dir, "six_ok_a", six_ok_demo("six_a.s19"))
    write_flow(project_dir, "six_ok_b", six_ok_demo("six_b.s19"))
    write_flow(project_dir, "six_wait", six_wait_demo(project_dir))
    write_flow(project_dir, "flash2_chain", flash2_chain_demo(project_dir))
    # batch-99 Inc 3b (HLR-155 D7 re-pins): the twin lanes of the TWO_WAIT /
    # DEEP sets keep their OWN output names — two lanes resolving to one
    # WRITE-OUT name refuse the set at start now (LLR-155.5), so the
    # second lane of each pair rides its own template differing only in
    # the WRITE-OUT name.
    flash_b = flash_chain_demo(project_dir)
    flash_b[-1] = replace(flash_b[-1], output_name="fw_app_flashed_copy_b.s19")
    write_flow(project_dir, "flash_b", flash_b)
    write_flow(project_dir, "six_ok_c", six_ok_demo("six_c.s19"))
    write_flow(project_dir, "six_ok_d", six_ok_demo("six_d.s19"))
    chain_b = patch_chain_demo()
    chain_b[3] = replace(chain_b[3], output_name="fw_b.s19")
    write_flow(project_dir, "patch_chain_b", chain_b)
    patched = [a + i for a, run in CALIB_ENTRIES for i in range(len(run))]
    flip_one_data_byte(project_dir / "prg.s19", project_dir / "prg_v2.s19", tuple(patched))
    return project_dir


def flash_evidence(project_dir: Path, steps=((FLASH_LOG, FLASH_OUT),)) -> None:
    """The human ran the external step(s) outside the app: each log and
    output file now exists inside the project."""
    for log, out in steps:
        (project_dir / log).write_text("flashed OK\n", encoding="utf-8")
        shutil.copyfile(project_dir / "prg.s19", project_dir / out)


def hostile_flow_file(project_dir: Path) -> Path:
    """``hostile_flow`` (A.5): ``flows/<HOSTILE_NAME>.json`` holding
    ``hostile_flow_demo`` under a safe flow name (a payload name is refused,
    P-30)."""
    import json

    from s19_app.tui.services.flow_model import Flow
    from s19_app.tui.services.flow_persistence_service import FLOWS_SUBDIR, flow_to_dict

    path = project_dir / FLOWS_SUBDIR / f"{HOSTILE_NAME}.json"
    payload = flow_to_dict(Flow(name="hostile_flow", blocks=hostile_flow_demo(project_dir)))
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def hostile_set_file(project_dir: Path) -> Path:
    """``flowsets/<HOSTILE_NAME>.json`` (A.5, P-37): the 3-lane set saved by
    the shipped serialiser under the hostile file name."""
    import json

    from s19_app.tui.services.flow_persistence_service import (
        FLOWSETS_SUBDIR,
        ChainSet,
        ChainSetEntry,
        chain_set_to_dict,
    )

    sets_dir = project_dir / FLOWSETS_SUBDIR
    sets_dir.mkdir(parents=True, exist_ok=True)
    chains = tuple(
        ChainSetEntry(chain=stem, template=stem, inputs=((0, "prg.s19"),))
        for stem in ("patch_chain", "flash_chain", "err_chain")
    )
    path = sets_dir / f"{HOSTILE_NAME}.json"
    path.write_text(json.dumps(chain_set_to_dict(ChainSet(name="three", chains=chains))), encoding="utf-8")
    return path


async def open_flow_execution(app, pilot) -> object:
    """Show Flow Execution through ``action_show_screen``; return the panel
    once it is laid out."""
    from tests.b97_probes import settled

    app.action_show_screen("flow_execution")
    panel = app.query_one("#fx_panel")
    await settled(pilot, lambda: panel.region.height > 0, "the Flow Execution panel is laid out")
    return panel


async def import_flow(app, pilot, stem: str) -> None:
    """Import ``flows/<stem>.json`` as a lane through ``#fx_import`` and the
    picker (the shipped controls); wait until the lane is mounted or the
    import is refused."""
    from textual.widgets import Button, ListView

    from tests.b97_probes import settled

    panel = app.query_one("#fx_panel")
    before = panel.lane_count()
    panel.query_one("#fx_import", Button).press()
    await settled(
        pilot,
        lambda: stem in [item.name for item in app.screen.query("#flow_list ListItem")],
        f"the flow picker lists {stem}",
    )
    names = [item.name for item in app.screen.query("#flow_list ListItem")]
    listing = app.screen.query_one("#flow_list", ListView)
    target = names.index(stem)

    def highlighted() -> bool:
        child = listing.highlighted_child
        if child is not None and child.name == stem:
            return True
        listing.index = target
        return False

    await settled(pilot, highlighted, f"{stem} highlighted in the flow picker")
    app.screen.query_one("#flow_load_ok", Button).press()
    await settled(
        pilot,
        lambda: (panel.lane_count() == before + 1 and bool(app.query(f"#fx_lane_{before}")))
        or panel.query_one("#fx_notice").display,
        f"flows/{stem}.json imported or refused",
    )


async def import_lanes(app, pilot, *stems: str) -> object:
    """Open Flow Execution and import each stem in order; return the panel
    once every lane is laid out (its first card painted, or on ``main`` its
    lane box)."""
    from tests.b97_probes import settled

    panel = await open_flow_execution(app, pilot)
    for stem in stems:
        await import_flow(app, pilot, stem)
    await settled(
        pilot,
        lambda: all(app.query_one(f"#fx_lane_{i}").region.width > 0 for i in range(len(stems))),
        "every lane is laid out",
    )
    return panel


async def run_lanes(app, pilot, panel, *, key: bool = False) -> None:
    """Press ``#fx_run`` (``press()``, or ``enter`` with the focus on it when
    ``key``) and wait until the run's record is painted and Run is enabled
    again."""
    from tests.b97_probes import settled

    before = panel.last_run_record
    run = panel.query_one("#fx_run")
    if key:
        run.focus()
        await settled(pilot, lambda: app.focused is run, "Run focused")
        await pilot.press("enter")
    else:
        run.press()
    await settled(
        pilot,
        lambda: panel.last_run_record is not before and not run.disabled,
        "the run is painted and Run is enabled again",
        attempts=200,
    )
