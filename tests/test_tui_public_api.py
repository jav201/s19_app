from s19_app import tui


def test_tui_public_api_exports_main_helpers_and_constants():
    expected = {
        "A2L_EXTENSIONS",
        "FOCUS_CONTEXT_ROWS",
        "HEX_WIDTH",
        "LOG_FILENAME",
        "LOGS_SUBDIR",
        "MAX_HEX_BYTES",
        "MAX_HEX_ROWS",
        "S19TuiApp",
        "WORKAREA_TEMP",
        "copy_into_workarea",
        "main",
        "parse_a2l_file",
        "render_hex_view",
        "resolve_input_path",
        "setup_logging",
    }

    assert expected.issubset(set(tui.__all__))
    assert callable(tui.main)
    assert callable(tui.render_hex_view)
    assert callable(tui.setup_logging)
