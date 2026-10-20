"""Batch-97 frozen literals and fixture builders (appendix A.2 / A.5).

The literals are committed verbatim from ``01-requirements-appendix.md`` A.2,
each with its own length guard, so a drifted copy fails at import rather than
silently weakening every test that reads it. The builders grow per increment
(design-proposal §5.1); Inc-1 adds the project builder, the app's own project
load and the junction arm.
"""
from __future__ import annotations

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
