from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from flask import (
    Flask,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from s19_app.tui.hexview import find_string_in_mem, format_hex_row_lines, row_index_for_address
from s19_app.tui.workspace import WORKAREA_TEMP, ensure_workarea

from .loader import load_data_and_a2l
from .mac_display import mac_table_rows
from .session_store import SessionStore, ViewerSession


def _viewer_store() -> SessionStore:
    return current_app.config["VIEWER_STORE"]


def _parse_goto_address(text: str) -> Optional[int]:
    text = (text or "").strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _current_viewer() -> Optional[ViewerSession]:
    vid = session.get("viewer_id")
    if not vid:
        return None
    return _viewer_store().get(str(vid))


def _require_viewer() -> Optional[ViewerSession]:
    vs = _current_viewer()
    return vs


def register_routes(app: Flask) -> None:
    """Attach URL rules to the Flask application."""

    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/upload", methods=["POST"])
    def upload() -> Any:
        data = request.files.get("data_file")
        if not data or not data.filename:
            flash("Choose a data file (.s19, .hex, or .mac).", "error")
            return redirect(url_for("index"))
        base_dir = Path.cwd()
        workarea = ensure_workarea(base_dir)
        temp_dir = workarea / WORKAREA_TEMP
        temp_dir.mkdir(parents=True, exist_ok=True)

        safe_name = secure_filename(data.filename)
        if not safe_name:
            flash("Invalid file name.", "error")
            return redirect(url_for("index"))
        data_path = temp_dir / safe_name
        data.save(str(data_path))

        a2l_path: Optional[Path] = None
        a2l_upload = request.files.get("a2l_file")
        if a2l_upload and a2l_upload.filename:
            a2l_name = secure_filename(a2l_upload.filename)
            if a2l_name.lower().endswith(".a2l"):
                a2l_path = temp_dir / a2l_name
                a2l_upload.save(str(a2l_path))

        st = _viewer_store()
        old_id = session.get("viewer_id")
        if old_id:
            st.delete(str(old_id))

        result = load_data_and_a2l(data_path, a2l_path)
        vs = st.new_session()
        vs.loaded = result.loaded
        vs.errors = result.errors
        vs.a2l_summary_lines = result.a2l_summary_lines
        vs.enriched_tags = result.enriched_tags
        session["viewer_id"] = vs.session_id

        if result.loaded is None:
            flash("Load failed: " + "; ".join(result.errors) if result.errors else "Unknown error", "error")
            st.delete(vs.session_id)
            session.pop("viewer_id", None)
            return redirect(url_for("index"))

        if result.errors:
            flash("Warnings: " + "; ".join(result.errors[:5]), "warning")
        return redirect(url_for("view"))

    @app.route("/view")
    def view() -> Any:
        vs = _require_viewer()
        if not vs or not vs.loaded:
            flash("No file loaded. Upload from the home page.", "error")
            return redirect(url_for("index"))
        loaded = vs.loaded
        assert loaded is not None
        initial_lines, total_rows = format_hex_row_lines(
            loaded.mem_map, loaded.row_bases, 0, app.config.get("HEX_INITIAL_ROWS", 128)
        )
        mac_rows: list[dict[str, Any]] = []
        mac_counts: dict[str, int] = {}
        if loaded.file_type == "mac":
            mac_rows, mac_counts = mac_table_rows(loaded, loaded.a2l_data)

        sections = list(zip(loaded.ranges, loaded.range_validity)) if loaded.ranges else []

        return render_template(
            "view.html",
            loaded=loaded,
            initial_lines=initial_lines,
            total_hex_rows=total_rows,
            initial_row_count=len(initial_lines),
            a2l_summary_lines=vs.a2l_summary_lines,
            enriched_tags=vs.enriched_tags,
            mac_rows=mac_rows,
            mac_counts=mac_counts,
            sections=sections,
        )

    @app.route("/api/hex-rows")
    def api_hex_rows() -> Any:
        vs = _require_viewer()
        if not vs or not vs.loaded:
            return jsonify({"error": "no_session"}), 401
        loaded = vs.loaded
        assert loaded is not None
        try:
            start = int(request.args.get("start", "0"))
            count = int(request.args.get("count", "128"))
        except ValueError:
            return jsonify({"error": "bad_params"}), 400
        count = max(1, min(count, int(app.config.get("HEX_MAX_ROWS_PER_REQUEST", 512))))
        lines, total = format_hex_row_lines(loaded.mem_map, loaded.row_bases, start, count)
        return jsonify({"start": start, "total_rows": total, "lines": lines})

    @app.route("/api/search", methods=["POST"])
    def api_search() -> Any:
        vs = _require_viewer()
        if not vs or not vs.loaded:
            return jsonify({"error": "no_session"}), 401
        loaded = vs.loaded
        assert loaded is not None
        payload = request.get_json(silent=True) or {}
        q = str(payload.get("q") or "").strip()
        if not q:
            return jsonify({"error": "empty_query"}), 400
        start_addr: Optional[int] = None
        if vs.last_search_query == q and vs.last_search_address is not None:
            start_addr = vs.last_search_address + 1
        addr = find_string_in_mem(loaded.mem_map, q, start_addr)
        if addr is None:
            vs.last_search_address = None
            vs.last_search_query = q
            return jsonify({"found": False})
        vs.last_search_query = q
        vs.last_search_address = addr
        ri = row_index_for_address(loaded.row_bases, addr)
        return jsonify({"found": True, "address": addr, "row_index": ri})

    @app.route("/api/goto", methods=["POST"])
    def api_goto() -> Any:
        vs = _require_viewer()
        if not vs or not vs.loaded:
            return jsonify({"error": "no_session"}), 401
        loaded = vs.loaded
        assert loaded is not None
        payload = request.get_json(silent=True) or {}
        addr = _parse_goto_address(str(payload.get("addr") or ""))
        if addr is None:
            return jsonify({"error": "bad_address"}), 400
        ri = row_index_for_address(loaded.row_bases, addr)
        if ri < 0:
            return jsonify({"found": False, "address": addr})
        return jsonify({"found": True, "address": addr, "row_index": ri})

    @app.route("/clear", methods=["POST"])
    def clear() -> Any:
        vid = session.get("viewer_id")
        if vid:
            _viewer_store().delete(str(vid))
        session.pop("viewer_id", None)
        flash("Session cleared.", "info")
        return redirect(url_for("index"))
