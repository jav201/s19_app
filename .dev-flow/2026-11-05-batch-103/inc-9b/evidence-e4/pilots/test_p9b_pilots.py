"""Inc 9b E4 prep (P9b): the three pilots of `E1-slice.md` §4 and the graph examples that need no 9b code.

A probe, not a test of the product: it runs only in a scratch copy of the tree (copied to `tests/` there so the
suite's conftest applies), never in the repository's `tests/`. It changes no product code; every hook below wraps
a method on the instance or the app for the probe's own duration. Each node prints one `P9B <name> <json>` line;
the record `inc-9b/E4-pilots.md` is written from those lines.

- P1  `call_after_refresh` vs `set_timer(0, ...)`: three 0.3 s UI-thread steps, a 0.1 s tick that writes the window
      title, a `down` key sent from another thread during step 1; per gap: ticks, compositor updates, the title the
      compositor holds, the key's handling time.
- P2  `#patch_sheet_win` inline busy border, then: (A) `styles.clear_rule("border")`, (B) clear the four edge rules,
      (C) set `("round", <rule colour>)` back; read `styles.border_top` and the painted corner colour, focus outside
      and within; count `StagingSheet._paint` calls (Inc 8b's `on_resize`) while the border toggles.
- P3  room B: a 400-character `Text` title on the window at 80x24, 118x54, 220x60; the painted top border row read
      from the compositor; plus the pill style on the painted cells.
- EX  EX-BC1 (`BenchState.job` at the ask), EX-BC10 (a scalar row has no bench state), EX-BC12 (`name_echo`),
      EX-BC14 (the document token across a stage and an Undo), EX-BC6 (the refresh parts' times on LARGE).
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest
from rich.style import Style
from rich.text import Text
from textual import events

from s19_app.tui.definition_bench_view import EDIT
from s19_app.tui.definition_sheet import name_echo
from s19_app.tui.insight_style import DEPTH_BG
from tests.b97_probes import painted_rows, painted_style
from tests.support.b103_inc8_p import MIN_SIZE, SIZE, WIDE
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    LARGE_COUNT, Gate, apply_tool, big_case, defc_dir, entries_of, open_bench, pick, run, sheet_of, st, wait_for,
)

WIN, BODY = "#patch_sheet_win", "#patch_sheet_body"
#: EDIT is a style string ("bold #f5c26b"), not a colour: the busy colour is its foreground (P9b finding).
BUSY = Style.parse(EDIT).color.triplet.hex


def out(name: str, data) -> None:
    print(f"P9B {name} " + json.dumps(data, default=str, ensure_ascii=False), flush=True)


def load() -> list:
    return [round(x, 2) for x in os.getloadavg()]


def top_line(app, win) -> str:
    return painted_rows(app, win)[0] if win.region.height else ""


# ------------------------------------------------------------------ P1 a frame between steps


@pytest.mark.parametrize("chain", ["after_refresh", "after_refresh_tick", "timer0", "timer_20ms", "timer_100ms"])
@pytest.mark.parametrize("trial", [1, 2, 3])
def test_p1_frame_between_steps(tmp_path, defc_dir, chain, trial):
    async def body(app, pilot, panel):
        sheet, win = sheet_of(panel), app.screen.query_one(WIN)
        sheet.query_one(BODY).focus()
        await pilot.pause(0.2)
        t0, log, n = time.monotonic(), [], [0]

        def stamp(kind, **extra):
            log.append(dict(kind=kind, t=round(time.monotonic() - t0, 4), **extra))

        screen = app.screen
        real_refresh = screen._compositor_refresh

        def compositor_refresh():
            real_refresh()
            stamp("paint", title=top_line(app, win)[:40])

        screen._compositor_refresh = compositor_refresh
        real_move = sheet.action_move

        def move(*a):
            real_move(*a)
            stamp("key")

        sheet.action_move = move
        body_widget = sheet.query_one(BODY)
        real_app_event, real_body_event = app.on_event, body_widget.on_event

        async def app_event(event):
            if isinstance(event, events.Key):
                stamp("app_key")
            return await real_app_event(event)

        async def body_event(event):
            if isinstance(event, events.Key):
                stamp("body_key")
            return await real_body_event(event)

        app.on_event, body_widget.on_event = app_event, body_event

        def tick():
            n[0] += 1
            win.border_title = Text(f"STAGING SHEET  tick {n[0]:03d}")
            stamp("tick", n=n[0])

        timer = app.set_interval(0.1, tick)
        done = threading.Event()

        def step(k):
            stamp("step_start", k=k)
            if k == 1:
                threading.Timer(0.05, lambda: app._driver.send_message(events.Key("down", None))).start()
            time.sleep(0.3)
            stamp("step_end", k=k)
            if k < 3:
                if chain == "after_refresh":
                    app.call_after_refresh(step, k + 1)
                elif chain == "after_refresh_tick":  # the step ends with a cue tick (the window dirty), as the product would
                    tick()
                    app.call_after_refresh(step, k + 1)
                elif chain == "timer0":
                    app.set_timer(0, lambda: step(k + 1))
                else:
                    app.set_timer(0.02 if chain == "timer_20ms" else 0.1, lambda: step(k + 1))
            else:
                done.set()

        await pilot.pause(0.35)
        step(1)
        end = time.monotonic() + 10
        while not done.is_set() and time.monotonic() < end:
            await pilot.pause(0.02)
        await pilot.pause(0.3)
        timer.stop()
        del screen._compositor_refresh
        del sheet.action_move
        del app.on_event, body_widget.on_event
        ends = {e["k"]: e["t"] for e in log if e["kind"] == "step_end"}
        starts = {e["k"]: e["t"] for e in log if e["kind"] == "step_start"}
        gaps = []
        for k in (1, 2):
            a, b = ends.get(k), starts.get(k + 1)
            inside = [e for e in log if a is not None and b is not None and a <= e["t"] <= b]
            gaps.append(dict(
                gap=f"{k}->{k + 1}", s=None if a is None or b is None else round(b - a, 4),
                ticks=sum(e["kind"] == "tick" for e in inside), paints=sum(e["kind"] == "paint" for e in inside),
                titles=sorted({e["title"].strip("╭─╮ ") for e in inside if e["kind"] == "paint"}),
                key=any(e["kind"] == "key" for e in inside)))
        keys = [e["t"] for e in log if e["kind"] == "key"]
        out("P1", dict(chain=chain, trial=trial, load=load(), steps=len(ends), gaps=gaps, key_at=keys,
                       paints_total=sum(e["kind"] == "paint" for e in log), ticks_total=n[0],
                       app_key_at=[e["t"] for e in log if e["kind"] == "app_key"],
                       body_key_at=[e["t"] for e in log if e["kind"] == "body_key"],
                       step_starts=starts, step_ends=ends))
        assert len(ends) == 3, "the chain did not run its three steps"

    run(tmp_path, defc_dir, body)


# ------------------------------------------------------------------ P2 clearing the inline border


def test_p2_clear_inline_border(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet, win = sheet_of(panel), app.screen.query_one(WIN)
        paints = [0]
        real_paint = sheet._paint

        def paint():
            paints[0] += 1
            real_paint()

        def read(label):
            corner = painted_style(app, win.region.x, win.region.y)
            return dict(label=label, border_top=str(win.styles.border_top),
                        corner=str(corner.color.triplet.hex if corner and corner.color and corner.color.triplet else corner),
                        corner_char=top_line(app, win)[:1], inline=sorted(k for k in win.styles.inline.get_rules() if k.startswith("border")),
                        focus_within=win.has_focus_within, size=list(win.size), sheet_size=list(sheet.size))

        rule_border = win.styles.border_top  # the stylesheet's value while the focus is outside
        results = []
        for focus in ("outside", "within"):
            if focus == "within":
                sheet.query_one(BODY).focus()
            else:
                app.set_focus(None)
            await pilot.pause(0.2)
            sheet._paint = paint
            paints[0] = 0
            seq = [read(f"{focus}: idle")]
            for variant in ("A clear_rule('border')", "B clear four edges", "C set ('round', rule colour)",
                            "D clear four edges + refresh()"):
                win.styles.border = ("round", BUSY)
                await pilot.pause(0.15)
                seq.append(read(f"{focus}: busy before {variant[0]}"))
                if variant[0] == "A":
                    cleared = win.styles.clear_rule("border")
                elif variant[0] in "BD":
                    cleared = [win.styles.clear_rule(f"border_{e}") for e in ("top", "right", "bottom", "left")]
                    if variant[0] == "D":
                        win.refresh()
                else:
                    win.styles.border = ("round", rule_border[1])
                    cleared = "set"
                await pilot.pause(0.15)
                seq.append(dict(read(f"{focus}: after {variant}"), cleared=cleared))
                # the focus moves after the idle look: does the stylesheet's :focus-within still apply?
                if focus == "outside":
                    sheet.query_one(BODY).focus()
                    await pilot.pause(0.15)
                    seq.append(read(f"{focus}: after {variant[0]}, then focus within"))
                    app.set_focus(None)
                    await pilot.pause(0.15)
                for e in ("top", "right", "bottom", "left"):
                    win.styles.clear_rule(f"border_{e}")
                win.refresh()
                await pilot.pause(0.1)
            del sheet._paint
            results.append(dict(focus=focus, paint_calls_during_toggles=paints[0], seq=seq))
        out("P2", dict(load=load(), edit=EDIT, busy=BUSY, rule_border=str(rule_border), results=results))

    run(tmp_path, defc_dir, body)


# ------------------------------------------------------------------ P3 the title room B


@pytest.mark.parametrize("size", [MIN_SIZE, SIZE, WIDE], ids=["80x24", "118x54", "220x60"])
def test_p3_title_room(tmp_path, defc_dir, size):
    probe = "STAGING SHEET  " + "".join(chr(ord("a") + i % 26) for i in range(385))
    pill = " ◐ BUSY · decode N · 1.7 s · keys still work "

    async def body(app, pilot, panel):
        win = app.screen.query_one(WIN)
        win.scroll_visible(animate=False)
        await pilot.pause(0.2)
        idle = top_line(app, win)
        win.border_title = Text(probe)
        await pilot.pause(0.2)
        line = top_line(app, win)
        shown = 0
        while shown < len(probe) and probe[: shown + 1] in line:
            shown += 1
        tail = line[line.find(probe[:shown]) + shown:] if shown else line
        fits = {}
        for cut in (6, 5, 4, 3):  # a title of (content width - cut) characters: shown whole, or cropped with "…"?
            text = probe[: win.size.width - cut]
            win.border_title = Text(text)
            await pilot.pause(0.1)
            fits[len(text)] = text in top_line(app, win)
        short = Text("STAGING SHEET  ")
        short.append(pill, style=f"bold {DEPTH_BG} on {BUSY}")
        win.border_title = short
        await pilot.pause(0.2)
        short_line = top_line(app, win)
        at = short_line.find("BUSY")
        style = painted_style(app, win.region.x + at, win.region.y) if at >= 0 else None
        out("P3", dict(
            size=list(size), load=load(), win_width=win.size.width, win_region=list(win.region),
            idle_line=idle, line=line, room_B=shown, after_title=tail[:6],
            title_start=line.find(probe[:1]), whole_by_length=fits, pill_whole=pill in short_line, short_line=short_line,
            pill_style=str(style), pill_bg=str(style.bgcolor.triplet.hex if style and style.bgcolor else None),
            pill_fg=str(style.color.triplet.hex if style and style.color else None), pill_bold=bool(style and style.bold)))

    run(tmp_path, defc_dir, body, size=size)


# ------------------------------------------------------------------ examples with no 9b code


def test_ex_bc12_name_echo():
    a, b = name_echo("A\x1b[2J"), name_echo("B\x85C")
    out("EX-BC12", dict(esc=a, nel=b, ok=[a == "A�[2J", b == "B�C"]))
    assert a == "A�[2J" and b == "B�C"


def test_ex_bc1_bc10_job_at_the_ask(tmp_path, defc_dir, monkeypatch):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=("LARGE",))
    gate = Gate(monkeypatch, "decode_values", hold={"LARGE"})

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        names = [r.name for r in sheet.rows]
        await pick(pilot, sheet, "LARGE")
        job_after_key = st(sheet, "LARGE").job
        active = sheet._active_job
        await wait_for(pilot, gate.entered.is_set, "LARGE's decode entered", 20)
        job_running = st(sheet, "LARGE").job
        await pick(pilot, sheet, "SMALL_BLK")
        small = st(sheet, "SMALL_BLK")
        job_large_left = st(sheet, "LARGE").job
        gate.release()
        await wait_for(pilot, lambda: sheet._active_job is None, "the queue idle", 60)
        out("EX-BC1/BC10", dict(names=names, job_after_key=job_after_key, active_after_key=active,
                                job_while_running=job_running, job_of_large_after_leaving=job_large_left,
                                small_state=None if small is None else small.job))

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)


def test_ex_bc10_scalar_row_has_no_state(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, "DISPLAY_0001")
        out("EX-BC10", dict(selected=sheet.selected_name, state=sheet.states.get("DISPLAY_0001")))
        assert sheet.states.get("DISPLAY_0001") is None

    run(tmp_path, defc_dir, body)


def test_ex_bc6_bc14_stage_token_undo(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet, service = sheet_of(panel), app._change_service

        def token():
            return (id(service.document), json.dumps(service.history_depths(), sort_keys=True), id(app.current_file))

        await open_bench(pilot, sheet, "VAL_BLK_DEF_0001")
        await apply_tool(pilot, sheet, "s", "10")
        t_before = token()
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the record stage", 30)
        t_staged, t_again = token(), token()
        entry = entries_of(app)[0]
        app.action_patch_undo()
        await pilot.pause(0.3)
        t_undone = token()
        out("EX-BC6/BC14", dict(entry_address=hex(entry[0]), entry_len=len(entry[1]),
                                stage_changes_token=t_before != t_staged, stable=t_staged == t_again,
                                undo_changes_token=t_staged != t_undone, entries_after_undo=len(entries_of(app)),
                                depths=[t_before[1], t_staged[1], t_undone[1]]))

    run(tmp_path, defc_dir, body)


@pytest.mark.parametrize("trial", [1, 2, 3])
def test_ex_bc6_refresh_parts_on_large(tmp_path, defc_dir, trial):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=("LARGE",))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, "LARGE")
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        await apply_tool(pilot, sheet, "s", "7")
        await wait_for(pilot, lambda: st(sheet, "LARGE").preview is not None
                       and not isinstance(st(sheet, "LARGE").preview, str), "the preview", 240)
        parts = []

        def timed(owner, name):
            real = getattr(owner, name)

            def wrapper(*a, **k):
                t = time.perf_counter()
                try:
                    return real(*a, **k)
                finally:
                    parts.append((name, round(time.perf_counter() - t, 4)))

            setattr(owner, name, wrapper)

        for owner, name in ((app, "_stage_bench_record"), (app, "_refresh_patch_history_view"),
                            (app, "_patch_document_view"), (panel, "refresh_entries"), (sheet, "set_document"),
                            (app._change_service, "stage_record")):
            timed(owner, name)
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the record stage", 240)
        await pilot.pause(0.5)
        d = {}
        for name, s in parts:
            d.setdefault(name, []).append(s)
        first = {k: v[0] for k, v in d.items()}
        refresh, view = first.get("_refresh_patch_history_view", 0), first.get("_patch_document_view", 0)
        entries, sheet_doc = first.get("refresh_entries", 0), first.get("set_document", 0)
        out("EX-BC6", dict(trial=trial, load=load(), calls=d, step_write=round(
            first.get("_stage_bench_record", 0) - refresh, 4), step1_serialize=view,
            step2_ledger_card_json=round(entries - sheet_doc, 4), step3_sheet=sheet_doc,
            step4_rest=round(refresh - view - entries, 4), block=first.get("_stage_bench_record")))

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
