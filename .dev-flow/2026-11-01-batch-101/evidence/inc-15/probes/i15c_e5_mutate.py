"""i15c mutator (Inc 15 E5 corrective): apply one named control to a COPY of
the tree (argv[1]); every edit must match exactly once or it aborts.
argv[2:] are control names; "base_b94" / "base_hygiene" restore the b94
module / the hygiene module to their form before this pass (5054743) from the
files named by I15C_B94_BASE / I15C_HY_BASE."""
import os
import pathlib
import sys

FX = "s19_app/tui/flow_screens.py"
PE = "tests/test_tui_patch_editor_v2.py"
B94 = "tests/test_tui_flow_execution_b94.py"


def once(tree, rel, old, new):
    p = tree / rel
    raw = p.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")
    assert text.count(old) == 1, (rel, text.count(old), old[:80])
    text = text.replace(old, new)
    if crlf:
        text = text.replace("\n", "\r\n")
    p.write_bytes(text.encode("utf-8"))


def every(tree, rel, old, new, count):
    p = tree / rel
    raw = p.read_bytes().decode("utf-8")
    assert raw.count(old) == count, (rel, raw.count(old), old)
    p.write_bytes(raw.replace(old, new).encode("utf-8"))


def base_b94(tree):
    src = pathlib.Path(os.environ["I15C_B94_BASE"])
    (tree / B94).write_bytes(src.read_bytes())


def base_hygiene(tree):
    src = pathlib.Path(os.environ["I15C_HY_BASE"])
    (tree / "tests/test_suite_hygiene.py").write_bytes(src.read_bytes())


D7_PRED = (
    '            app.query_one("#patch_saveback_decline_button", Button).press()\n'
    "            await settled(\n"
    "                pilot,\n"
    '                lambda: prompt.has_class("hidden"),\n'
)

CONTROLS = {
    # C-2: D6's predicate made vacuous -> the guard must go RED.
    "c2_d6_true": lambda t: once(
        t, PE,
        '                    lambda: not prompt.has_class("hidden"),\n'
        '                    "TC-051: the apply showed the save-back prompt",\n',
        "                    lambda: True,\n"
        '                    "TC-051: the apply showed the save-back prompt",\n',
    ),
    # C-2, reviewer case (b): D7 polls D6's sign (holds at once).
    "c2_d7_swap": lambda t: once(
        t, PE, D7_PRED,
        D7_PRED.replace('lambda: prompt.has_class("hidden")', 'lambda: not prompt.has_class("hidden")'),
    ),
    # C-7: the b94 module's own _wait_for called inside TC-B94-27.
    "c7_wait_for": lambda t: once(
        t, B94,
        '            before_b = panel.lane_bindings("base_2")\n',
        '            await _wait_for(app, pilot, "#fx_in_1_0")\n'
        '            before_b = panel.lane_bindings("base_2")\n',
    ),
    # C-9 (163/1): a site's helper not found -> the guard fails, never skips.
    "c9_rename_confirm": lambda t: every(t, PE, "_confirm_with(", "_confirm_by(", 4),
    # C-10: D9 removed (the pre-corrective one-pause form) -> the guard RED.
    "c10_remove_d9": lambda t: once(
        t, B94,
        "            await settled(\n"
        "                pilot,\n"
        "                lambda: (\n"
        '                    panel.lane_names() == ["base", "base_2"]\n'
        '                    and bool(app.query("#fx_in_1_0"))\n'
        '                    and bool(app.query_one("#fx_in_1_0").region)\n'
        "                ),\n"
        '                "TC-B94-27: the panel mounted lanes base and base_2",\n'
        "            )\n",
        "            await pilot.pause()\n",
    ),
    "base_b94": base_b94,
    "base_hygiene": base_hygiene,
    # Re-confirmation on the changed TC-B94-27 arm (E4 m152 / m153b, same edits).
    "m152": lambda t: once(
        t, FX,
        "        if value == self._effective_ref(lane, src_index):\n            return\n",
        "        pass  # i15c m152\n",
    ),
    "m153b": lambda t: once(
        t, FX,
        "        lane.bindings[src_index] = value\n",
        "        for _l in self._lanes:  # i15c m153b\n            _l.bindings[src_index] = value\n",
    ),
}

if __name__ == "__main__":
    tree = pathlib.Path(sys.argv[1])
    for name in sys.argv[2:]:
        CONTROLS[name](tree)
        print(f"i15c_e5_mutate: applied {name} to {tree.name}")
