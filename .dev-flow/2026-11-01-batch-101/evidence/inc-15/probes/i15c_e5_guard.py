"""i15c probe (Inc 15 E5 corrective): block OS clipboard writes, print the
provenance header, and optionally hold one product step or force one wait
never to settle. Runs from outside the tree (-p i15c_e5_guard); changes no
file. Derived from the E4 probe i15int_guard.py; adds the fx_import hold.

I15_HOLD=fx_bind|fx_import|patch_action|change_file|save_back  (I15_HOLD_S, default 1.5)
  fx_import: FlowExecutionPanel.add_lane runs 1.5 s late (the import's result
             step, wait D9, E5 C-10); the picker itself closes at once
I15_HOLD_ACTION=<filter>  patch_action: the action name; save_back: decline | confirm
I15_NEVER=<table-D description>  that wait's predicate never holds; the wait
                          keeps the real settled -> wait_until path with a
                          3 s bound, so it fails with `did not settle: ...`
"""
import os
import platform
import subprocess
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


def _git_head():
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"n/a ({type(exc).__name__})"


def pytest_report_header(config):
    import s19_app
    import textual

    return [
        f"i15c: commit under test = {os.environ.get('I15C_COMMIT', '?')} "
        f"(tree = {os.environ.get('I15C_TREE', '?')}; git HEAD here = {_git_head()})",
        f"i15c: s19_app.__file__ = {s19_app.__file__}",
        f"i15c: python {sys.version.split()[0]} on {platform.system()}; textual {textual.__version__}",
        f"i15c: NO_COLOR set = {'NO_COLOR' in os.environ}; "
        f"LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}; APPDATA = {os.environ.get('APPDATA')}",
        f"i15c: TEMP = {os.environ.get('TEMP')}; TMP = {os.environ.get('TMP')}",
        "i15c: OS clipboard writers replaced by a raising guard",
        f"i15c: hold = {os.environ.get('I15_HOLD', '')} action = {os.environ.get('I15_HOLD_ACTION', '')} "
        f"s = {os.environ.get('I15_HOLD_S', '1.5')}; never = {os.environ.get('I15_NEVER', '')!r}",
    ]


def _install_hold():
    mode = os.environ.get("I15_HOLD", "")
    if not mode:
        return None
    only = os.environ.get("I15_HOLD_ACTION", "")
    delay = float(os.environ.get("I15_HOLD_S", "1.5"))
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.flow_screens import FlowExecutionPanel

    def _defer(cls, name, match):
        real = getattr(cls, name)

        def held(self, event):
            if match(event):
                self.set_timer(delay, lambda: real(self, event))
                return None
            return real(self, event)

        setattr(cls, name, held)

    if mode == "fx_bind":
        # Class level, ABOVE the arm's instance recorder on _rebind (E3 F5).
        _defer(FlowExecutionPanel, "on_button_pressed",
               lambda e: (e.button.id or "").startswith("fx_bind_"))
    elif mode == "fx_import":
        real_add = FlowExecutionPanel.add_lane

        def held_add(self, template, flow):
            self.set_timer(delay, lambda: real_add(self, template, flow))

        FlowExecutionPanel.add_lane = held_add
    elif mode == "patch_action":
        _defer(S19TuiApp, "on_patch_editor_panel_action_requested",
               lambda e: not only or e.action == only)
    elif mode == "change_file":
        _defer(S19TuiApp, "on_patch_editor_panel_change_file_selected", lambda e: True)
    elif mode == "save_back":
        kinds = {
            "decline": lambda e: e.filename is None,
            "confirm": lambda e: e.filename is not None,
            "": lambda e: True,
        }
        _defer(S19TuiApp, "on_patch_editor_panel_save_back_decision", kinds[only])
    else:
        raise RuntimeError(f"unknown I15_HOLD={mode}")
    return f"{mode}[{only or '*'}] {delay}s"


def _install_never():
    target = os.environ.get("I15_NEVER", "")
    if not target:
        return None
    import tests.b97_probes as probes

    real = probes.wait_until

    async def never(pilot, predicate, failure, *, timeout=None, pause_first=False):
        if failure == f"did not settle: {target}":
            predicate = lambda: False  # noqa: E731
            timeout = 3.0
        kwargs = {"pause_first": pause_first}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await real(pilot, predicate, failure, **kwargs)

    probes.wait_until = never
    return target


_STATE = {}


def pytest_sessionstart(session):
    _STATE["hold"] = _install_hold()
    _STATE["never"] = _install_never()


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(
        f"i15c: hold installed = {_STATE.get('hold')}; never installed = {_STATE.get('never')!r}"
    )
