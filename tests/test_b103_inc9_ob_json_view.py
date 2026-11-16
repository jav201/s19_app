"""Batch-103 Inc 9 FX9d (O-B): the read-only JSON view does no bracket scan; editable text areas still do.

Textual's ``TextArea._watch_selection`` calls ``find_matching_bracket`` whatever ``match_cursor_bracket`` says, and the
scan over a large document is ~0.46 s on the UI thread at the record stage (FX9c). The read-only ``#patch_json_view``
therefore answers ``None`` itself; ``#patch_paste_text`` (editable) keeps Textual's behaviour.
"""
from __future__ import annotations

from textual.widgets import TextArea

from tests.support.b103_inc8_p import SIZE, drive

TEXT = '{"a": [1, 2], "b": {"c": 3}}\n'


def _count_base_scans(monkeypatch):
    calls = []
    real = TextArea.find_matching_bracket

    def counted(self, bracket, search_from):
        calls.append(self.id)
        return real(self, bracket, search_from)

    monkeypatch.setattr(TextArea, "find_matching_bracket", counted)
    return calls


def test_ob_1_the_read_only_json_view_runs_no_bracket_scan(tmp_path, monkeypatch):
    """Load a document, then put the cursor on a `[` and then on a `{`: Textual's own scan is never entered."""
    calls = _count_base_scans(monkeypatch)

    async def body(app, pilot, panel):
        view = panel.query_one("#patch_json_view", TextArea)
        assert view.read_only
        view.load_text(TEXT)
        view.move_cursor((0, 6))
        await pilot.pause(0.1)
        view.move_cursor((0, 0))
        await pilot.pause(0.1)
        return view.cursor_location

    assert drive(tmp_path, SIZE, body) == (0, 0)
    assert "patch_json_view" not in calls


def test_ob_2_an_editable_text_area_still_matches_brackets(tmp_path, monkeypatch):
    """The paste buffer (editable) with the cursor on a `{`: the scan runs and finds the closing `}` (no leak)."""
    calls = _count_base_scans(monkeypatch)

    async def body(app, pilot, panel):
        buffer = panel.query_one("#patch_paste_text", TextArea)
        buffer.load_text(TEXT)
        buffer.move_cursor((0, 6))
        await pilot.pause(0.1)
        buffer.move_cursor((0, 0))
        await pilot.pause(0.1)
        return buffer.find_matching_bracket("{", (0, 0))

    assert drive(tmp_path, SIZE, body) == (0, len(TEXT.rstrip("\n")) - 1)
    assert "patch_paste_text" in calls
