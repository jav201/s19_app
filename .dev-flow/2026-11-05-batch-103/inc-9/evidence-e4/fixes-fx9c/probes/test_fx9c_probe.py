"""FX9c probe (scratch only, never committed to tests/): FX9b's record-stage parts probe (``test_probe_parts`` of
``test_fx9b_probe2``) measured the same way on each option's tree, plus
- the keys typed for 4 s after the stage (the per-key cost of a staged LARGE row with no edit, O-D),
- a digest of every before/after card text painted (plain + spans), so two trees' painted cards can be compared (O-C),
- env FX9C_NOBRACKET=1: the O-B what-if, the JSON view's ``find_matching_bracket`` stubbed to return None.
"""
import hashlib
import json
import os
import threading
import time

import s19_app.tui.app.patch as app_patch
import s19_app.tui.definition_bench as db
import s19_app.tui.definition_sheet as ds
import s19_app.tui.screens_directionb.patch_editor.shared as pe_shared
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, big_case, defc_dir, entries_of, large_with_selection, previewed, run, sheet_of, wait_for  # noqa: F401
from tests.test_fx9b_probe import _keys, _split_keys, _typed
from tests.test_fx9b_probe2 import _timer

NOBRACKET = os.environ.get("FX9C_NOBRACKET") == "1"


def _digest(text):
    h = hashlib.sha256(text.plain.encode("utf-8"))
    h.update(repr([(s.start, s.end, str(s.style)) for s in text.spans]).encode("utf-8"))
    return h.hexdigest()[:16]


def test_probe_parts(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    cards = []
    real_card = pe_shared.before_after_card_text

    def card_text(*a, **k):
        text = real_card(*a, **k)
        lines = text.plain.splitlines()
        cards.append({"digest": _digest(text), "lines": len(lines), "last": lines[-1] if lines else ""})
        return text
    pe_shared.before_after_card_text = card_text

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        view = panel.query_one("#patch_json_view")
        if NOBRACKET:
            view.find_matching_bracket = lambda *a, **k: None
        t0, log = [time.perf_counter()], []
        w = _timer(log, t0)
        w(app, "_stage_bench_record"); w(app, "_refresh_patch_history_view"); w(panel, "_show_document")
        w(panel, "_render_before_after_card"); w(sheet, "set_document"); w(sheet, "_paint")
        w(app._change_service, "stage_record"); w(app_patch, "serialize_change_document")
        w(db, "_max_staged_delta"); w(ds, "_staged_by_bytes"); w(ds, "build_row")
        w(view, "find_matching_bracket"); w(view, "load_text")
        starts, ends = _split_keys(sheet, "action_move", t0)
        stop = threading.Event()
        sent, th = _typed(app, "down", starts, ends, stop)
        await pilot.press("alt+s")
        t0[0] = time.perf_counter()
        th.start()
        end = time.monotonic() + 180
        while len(entries_of(app)) != 1 and time.monotonic() < end:
            await pilot.pause(0.05)
        staged_at = time.perf_counter() - t0[0]
        await pilot.pause(4.0)
        stop.set(); th.join()
        for _ in range(200):
            if len(ends) >= len(sent):
                break
            await pilot.pause(0.05)
        keys = _keys(sent, starts, ends, t0[0])
        stage = [p for p in log if p[0] == "_stage_bench_record"]
        block_end = stage[-1][1] + stage[-1][2] if stage else staged_at
        after = sorted(k[1] + k[2] for k in keys if k[0] > block_end + 0.05)
        print("FX9CPARTS " + json.dumps({
            "nobracket": NOBRACKET, "n_keys": len(keys), "max": max(k[1] + k[2] for k in keys),
            "keys_over_0.3": [k for k in keys if k[1] + k[2] > 0.3],
            "after_stage": {"n": len(after), "p50": after[len(after) // 2] if after else None,
                            "max": after[-1] if after else None},
            "cards": cards,
            "parts": [p for p in log if p[0] != "_paint" or p[2] > 0.05]}))

    try:
        run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    finally:
        pe_shared.before_after_card_text = real_card
