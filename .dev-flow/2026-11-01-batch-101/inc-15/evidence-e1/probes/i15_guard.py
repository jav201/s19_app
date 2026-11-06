"""i15 run guard: block every OS clipboard write and report what is imported."""
import os
import platform
import sys


def _blocked(*_args, **_kwargs):
    raise RuntimeError("i15 guard: OS clipboard write blocked")


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
        f"i15: s19_app.__file__ = {s19_app.__file__}",
        f"i15: python {sys.version.split()[0]} on {platform.system()} {platform.release()}; textual {textual.__version__}",
        f"i15: NO_COLOR set = {'NO_COLOR' in os.environ}; LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}",
        f"i15: TEMP = {os.environ.get('TEMP')}; USERPROFILE = {os.environ.get('USERPROFILE')}",
        "i15: OS clipboard writers replaced by a raising guard",
    ]


# --- pause probes (I15_PAUSE): emulate how early pilot.pause() returns -------
# quantized: textual._wait reads a process clock that moves in 15.625 ms steps
#            (the Windows GetProcessTimes tick) on any host.
# zero:      pilot.pause() with no delay yields the loop once (sleep(0)) and
#            returns, the shortest settle a pause can give.
def _install_pause_probe():
    mode = os.environ.get("I15_PAUSE", "")
    if not mode:
        return "native"
    import asyncio
    import math
    import time

    import textual._wait as tw
    import textual.pilot as tp

    if mode == "quantized":
        tick = 0.015625
        tw.process_time = lambda: math.floor(time.process_time() / tick) * tick
    elif mode == "zero":
        async def _zero(min_sleep=0, max_sleep=1):
            await asyncio.sleep(0)

        tp.wait_for_idle = _zero
    else:
        raise RuntimeError(f"unknown I15_PAUSE={mode}")
    return mode


_PAUSE_MODE = None


def pytest_sessionstart(session):
    global _PAUSE_MODE
    _PAUSE_MODE = _install_pause_probe()


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(f"i15: pause probe = {_PAUSE_MODE}")


# --- affinity (I15_AFFINITY=<mask>, Windows only): pin this process to CPUs --
def _pin_affinity():
    mask = os.environ.get("I15_AFFINITY")
    if not mask or sys.platform != "win32":
        return None
    import ctypes

    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    ok = k32.SetProcessAffinityMask(ctypes.c_void_p(k32.GetCurrentProcess()), ctypes.c_size_t(int(mask, 0)))
    return f"{mask} ok={bool(ok)}"


# --- trace (I15_TRACE_FILE=<path>): when each step of the two nodes runs -----
_T0 = None
_TRACE = None


def _t(msg):
    if _TRACE is None:
        return
    import time

    _TRACE.write(f"{time.perf_counter() - _T0:9.4f} {msg}\n")
    _TRACE.flush()


def _install_trace():
    global _T0, _TRACE
    path = os.environ.get("I15_TRACE_FILE")
    if not path:
        return False
    import functools
    import time

    _T0 = time.perf_counter()
    _TRACE = open(path, "a", encoding="utf-8")

    import textual.pilot as tp
    from textual.app import App
    from textual.widgets import Button
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.flow_screens import FlowExecutionPanel

    real_pause = tp.Pilot.pause

    async def pause(self, delay=None):
        _t(f"pause enter delay={delay}")
        await real_pause(self, delay)
        _t("pause exit")

    tp.Pilot.pause = pause

    real_press = Button.press

    def press(self):
        _t(f"press id={self.id} disabled={self.disabled} display={self.display} mounted={self.is_mounted}")
        return real_press(self)

    Button.press = press

    real_obp = FlowExecutionPanel.on_button_pressed

    def obp(self, event):
        _t(f"fx on_button_pressed id={event.button.id}")
        return real_obp(self, event)

    FlowExecutionPanel.on_button_pressed = obp

    real_rebind = FlowExecutionPanel._rebind

    def rebind(self, lane_index, src_index):
        from textual.widgets import Input

        value = self.query_one(f"#fx_in_{lane_index}_{src_index}", Input).value
        _t(f"fx _rebind lane={lane_index} src={src_index} value={value!r} effective={self._effective_ref(self._lanes[lane_index], src_index)!r}")
        out = real_rebind(self, lane_index, src_index)
        _t(f"fx _rebind done bindings={dict(self._lanes[lane_index].bindings)}")
        return out

    FlowExecutionPanel._rebind = rebind

    real_par = S19TuiApp.on_patch_editor_panel_action_requested

    def par(self, event):
        try:
            stack = len(self.screen_stack)
            n = len(self.screen.children)
        except Exception as exc:  # noqa: BLE001
            stack, n = f"err {exc!r}", -1
        _t(f"app action_requested action={event.action} running={self._running} stack={stack} screen_children={n}")
        return real_par(self, event)

    S19TuiApp.on_patch_editor_panel_action_requested = par

    real_shutdown = App._shutdown

    async def shutdown(self):
        _t("app _shutdown begin")
        await real_shutdown(self)
        _t("app _shutdown end")

    App._shutdown = shutdown
    return True


_EXTRA = {}


def pytest_sessionstart(session):  # noqa: F811  (replaces the earlier hook)
    global _PAUSE_MODE
    _PAUSE_MODE = _install_pause_probe()
    _EXTRA["affinity"] = _pin_affinity()
    _EXTRA["trace"] = _install_trace()


import pytest  # noqa: E402


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _t(f"=== call begin {item.nodeid}")
    outcome = yield
    _t(f"=== call end {item.nodeid} excinfo={outcome.excinfo[0].__name__ if outcome.excinfo else None}")


def pytest_terminal_summary(terminalreporter):  # noqa: F811
    terminalreporter.write_line(f"i15: pause probe = {_PAUSE_MODE}; affinity = {_EXTRA.get('affinity')}; trace = {_EXTRA.get('trace')}")


# --- held handler (I15_HOLD=fx_bind|patch_action): a forced slow step --------
# The press is handled, unchanged, I15_HOLD_S seconds later (default 1.5 s):
# a test that reads the state after one pause reads it before the handler.
def _install_hold():
    mode = os.environ.get("I15_HOLD", "")
    if not mode:
        return None
    delay = float(os.environ.get("I15_HOLD_S", "1.5"))
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.flow_screens import FlowExecutionPanel

    if mode == "fx_bind":
        real = FlowExecutionPanel.on_button_pressed

        def held(self, event):
            if (event.button.id or "").startswith("fx_bind_"):
                _t(f"hold: fx_bind press {event.button.id} deferred {delay}s")
                self.set_timer(delay, lambda: real(self, event))
                return None
            return real(self, event)

        FlowExecutionPanel.on_button_pressed = held
    elif mode == "patch_action":
        real = S19TuiApp.on_patch_editor_panel_action_requested

        def held(self, event):
            _t(f"hold: patch action {event.action} deferred {delay}s")
            self.set_timer(delay, lambda: real(self, event))

        S19TuiApp.on_patch_editor_panel_action_requested = held
    else:
        raise RuntimeError(f"unknown I15_HOLD={mode}")
    return f"{mode} {delay}s"


def pytest_sessionstart(session):  # noqa: F811  (replaces the earlier hooks)
    global _PAUSE_MODE
    _PAUSE_MODE = _install_pause_probe()
    _EXTRA["affinity"] = _pin_affinity()
    _EXTRA["trace"] = _install_trace()
    _EXTRA["hold"] = _install_hold()


def pytest_terminal_summary(terminalreporter):  # noqa: F811
    terminalreporter.write_line(
        f"i15: pause probe = {_PAUSE_MODE}; affinity = {_EXTRA.get('affinity')}; "
        f"trace = {_EXTRA.get('trace')}; hold = {_EXTRA.get('hold')}"
    )
