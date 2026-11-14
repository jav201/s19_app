"""Scratch negative control (not committed): the R-PASTE.13/101 diagnostic reaches the deps seam."""

from s19_app.tui import app as app_module
from s19_app.tui.app import S19TuiApp
from tests.test_b103_clipboard_tail import _r13_diag_install


def test_zq_diag_tail_mark_reaches_the_seam_the_product_calls(tmp_path, monkeypatch) -> None:
    app = S19TuiApp(base_dir=tmp_path)
    _r13_diag_install(app, None, monkeypatch)
    patched = app_module.deps._mirror_and_write_os_clipboard
    assert getattr(patched, "__name__", "") == "tail_mark", patched
