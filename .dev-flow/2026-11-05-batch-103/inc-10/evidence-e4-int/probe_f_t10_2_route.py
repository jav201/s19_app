"""F-T10-2 probe (integrator I10): is the apply arm's I-10.1 call a product route to a prompt that is shown
while the document holds an entry not applied before the save?

Route, through the app's own controls: case01 loaded, two entries added in the Inspector pane (one inside the
image, one outside it), Apply pressed. The apply arm applies one and skips one, so it calls I-10.1
(``show_save_prompt``) with an entry outside the applied set; ``Write file`` must then name that entry with the
F3 clause. Run from a tree root as a copy under ``tests/`` (it uses ``tests.support.b103_inc10``).
"""
from __future__ import annotations

from tests.support import b103_inc10 as t

OUTSIDE = "0x00000010"


def test_probe_partial_apply_shows_the_prompt_with_an_unapplied_entry(tmp_path):
    async def body(app, pilot):
        await t.add_entry(pilot, app)
        await t.add_entry(pilot, app, OUTSIDE, "01")
        apply_status = await t.press_apply(pilot, app)
        shown = t.prompt_is_shown(app)
        saved = await t.write_file(pilot, app)
        return apply_status, shown, saved

    apply_status, shown, saved = t.run_loaded(tmp_path, t.SIZE, "firmware.s19", body)
    print("PROBE apply:", apply_status)
    print("PROBE prompt shown after the apply:", shown)
    print("PROBE save:", saved)
    assert apply_status == "Apply: 1 applied, 1 skipped, 0 blocked"
    assert shown
    assert "includes 1 entry not applied before this save (0x00000010)" in saved
