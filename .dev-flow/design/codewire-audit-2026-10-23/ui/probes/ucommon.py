"""Shared helpers for the Code-Wire UI audit threads (throwaway, read-only toward the repo).

Run with S19_WT=<detached checkout at 9793fcd>, interpreter s19env,
PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1, NO_COLOR unset. Each probe makes its own
temp base dir and passes it as S19TuiApp(base_dir=...), so nothing is written in
the repo or under the home `.s19tool`.

The recorder keeps three channels per step, which are the literal anchors of the
threads: the status/log lines the app shows, the notifications, and the widget
text that a step reads back from the screen.
"""
import os, sys, tempfile, hashlib, asyncio, json
from pathlib import Path

WT = Path(os.environ["S19_WT"])
sys.path.insert(0, str(WT))
EX = WT / "examples"
C1 = EX / "case_01_basic_valid"
C2 = EX / "case_02_gaps_and_patch_targets"
C3 = EX / "case_03_overlapping_records"

SIZE = (160, 50)


def new_base(prefix="cwui_"):
    base = Path(tempfile.mkdtemp(prefix=prefix))
    os.chdir(base)
    return base


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:12]


def mem_digest(mem):
    if not mem:
        return "none"
    h = hashlib.sha256()
    for a in sorted(mem):
        h.update(a.to_bytes(8, "big")); h.update(bytes([mem[a] & 0xFF]))
    return f"{len(mem)}B/{h.hexdigest()[:12]}"


def new_app(base):
    from s19_app.tui.app import S19TuiApp
    app = S19TuiApp(base_dir=base)
    app._rec = []
    orig_append = app._append_log_line

    def rec_log(msg):
        app._rec.append(("log", str(msg)))
        return orig_append(msg)

    app._append_log_line = rec_log
    orig_file = app.set_file_status

    def rec_file(msg):
        app._rec.append(("file_status", str(msg)))
        return orig_file(msg)

    app.set_file_status = rec_file
    orig_notify = app.notify

    def rec_notify(message, *a, **k):
        app._rec.append(("notify:" + str(k.get("severity", "information")), str(message)))
        return orig_notify(message, *a, **k)

    app.notify = rec_notify
    return app


def take(app):
    out = list(app._rec)
    app._rec.clear()
    return out


async def settle(app, pilot, n=8):
    for _ in range(n):
        await pilot.pause()
        try:
            await app.workers.wait_for_complete()
        except Exception:
            pass
    await pilot.pause()


def text_of(widget):
    """Plain text that a widget paints (Label / Static / Button)."""
    try:
        r = widget.render()
        return str(getattr(r, "plain", r))
    except Exception as exc:  # noqa: BLE001
        return f"<render failed: {exc}>"


def q_text(app, selector):
    try:
        return text_of(app.query_one(selector))
    except Exception as exc:  # noqa: BLE001
        return f"<no {selector}: {type(exc).__name__}>"


def screen_lines(app):
    """Status line + the four log lines, as painted."""
    keys = ["#status_text", "#log_line_1", "#log_line_2", "#log_line_3", "#log_line_4"]
    return {k: q_text(app, k) for k in keys}


def listview_items(app, selector):
    from textual.widgets import ListView, Label
    try:
        lv = app.query_one(selector, ListView)
    except Exception as exc:  # noqa: BLE001
        return f"<no {selector}: {type(exc).__name__}>"
    items = []
    for li in lv.children:
        try:
            items.append(text_of(li.query_one(Label)))
        except Exception:
            items.append(text_of(li))
    return items


def p(*a):
    print(*a, flush=True)


def run(coro_fn):
    asyncio.run(coro_fn())
