"""i15c probe: block OS clipboard writes; hold one product handler (I15_HOLD) by I15_HOLD_S s."""
import os
import platform
import sys


def _blocked(*_a, **_k):
    raise RuntimeError("i15c guard: OS clipboard write blocked")


def pytest_configure(config):
    from s19_app.tui import os_clipboard_input as oci

    oci.write_os_clipboard = _blocked
    oci._write_via_ctypes = _blocked
    oci._write_via_tk = _blocked
    oci._write_via_powershell = _blocked
    oci._WRITE_STRATEGIES = (("blocked", _blocked),)


def pytest_report_header(config):
    import s19_app
    import textual

    return [
        f"i15c: s19_app.__file__ = {s19_app.__file__}",
        f"i15c: python {sys.version.split()[0]} on {platform.system()}; textual {textual.__version__}",
        f"i15c: NO_COLOR set = {'NO_COLOR' in os.environ}",
        f"i15c: hold = {os.environ.get('I15_HOLD', '')} action = {os.environ.get('I15_HOLD_ACTION', '')} s = {os.environ.get('I15_HOLD_S', '1.5')}",
    ]


def _install_hold():
    mode = os.environ.get("I15_HOLD", "")
    if not mode:
        return None
    only = os.environ.get("I15_HOLD_ACTION", "")
    delay = float(os.environ.get("I15_HOLD_S", "1.5"))
    from s19_app.tui.app import S19TuiApp

    def _defer(name, match):
        real = getattr(S19TuiApp, name)

        def held(self, event):
            if match(event):
                self.set_timer(delay, lambda: real(self, event))
                return None
            return real(self, event)

        setattr(S19TuiApp, name, held)

    if mode == "patch_action":
        _defer("on_patch_editor_panel_action_requested", lambda e: not only or e.action == only)
    elif mode == "change_file":
        _defer("on_patch_editor_panel_change_file_selected", lambda e: True)
    elif mode == "save_back":
        kinds = {"decline": lambda e: e.filename is None, "confirm": lambda e: e.filename is not None, "": lambda e: True}
        _defer("on_patch_editor_panel_save_back_decision", kinds[only])
    else:
        raise RuntimeError(f"unknown I15_HOLD={mode}")
    return f"{mode}[{only or '*'}] {delay}s"


_HOLD = None


def pytest_sessionstart(session):
    global _HOLD
    _HOLD = _install_hold()


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(f"i15c: hold installed = {_HOLD}")
