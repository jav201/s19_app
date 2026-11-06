"""i15int mutator: apply one named product mutant or static-guard control to a
COPY of the tree (argv[1]); every edit must match exactly once or it aborts."""
import pathlib
import sys

APP = "s19_app/tui/app.py"
FX = "s19_app/tui/flow_screens.py"
APPLY = "s19_app/tui/changes/apply.py"
PE = "tests/test_tui_patch_editor_v2.py"
B94 = "tests/test_tui_flow_execution_b94.py"

GUARD_LINE = "        panel.set_edit_json_enabled(service.document.source_path is None)\n"

D1_WAIT = '''            await settled(
                pilot,
                lambda: (
                    app._change_service.document.source_path is not None
                    and app._change_service.document.source_path.name
                    == "f.json"
                ),
                "TC-331: the load of f.json reached the change document",
            )
'''
D1_READ = '            outcomes["file_disabled"] = button.disabled\n'


def by_line(tree, rel, lineno, must_contain, new):
    p = tree / rel
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    assert must_contain in lines[lineno - 1], (rel, lineno, lines[lineno - 1])
    lines[lineno - 1] = new
    p.write_text("".join(lines), encoding="utf-8", newline="")


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


MUTANTS = {
    # R-TST-150 (b): both load-path writers of the Edit JSON guard removed.
    "m150b": lambda t: (
        by_line(t, APP, 4929, "set_edit_json_enabled", "        pass  # i15int m150b\n"),
        by_line(t, APP, 7191, "set_edit_json_enabled", "        pass  # i15int m150b\n"),
    ),
    # R-TST-151 (b): only the end-of-handler writer removed.
    "m151b": lambda t: by_line(t, APP, 4929, "set_edit_json_enabled", "        pass  # i15int m151b\n"),
    # R-TST-152 vacuity: the rebind-to-same early return removed.
    "m152": lambda t: once(
        t, FX,
        "        if value == self._effective_ref(lane, src_index):\n            return\n",
        "        pass  # i15int m152\n",
    ),
    # R-TST-153 (b): the bind writes every lane's record.
    "m153b": lambda t: once(
        t, FX,
        "        lane.bindings[src_index] = value\n",
        "        for _l in self._lanes:  # i15int m153b\n            _l.bindings[src_index] = value\n",
    ),
    # R-TST-161 (b): Don't save writes the image under the name box's text.
    "m161b": lambda t: once(
        t, APP,
        '        if event.filename is None:\n'
        '            self.set_status("Patch Editor: save-back declined")\n'
        '            return\n',
        '        if event.filename is None:  # i15int m161b\n'
        '            event.filename = panel.query_one("#patch_saveback_name_input").value\n',
    ),
    # R-TST-162 (b): the reserved-device-name refusal removed.
    "m162b": lambda t: once(
        t, APPLY,
        '    if bare.split(".", 1)[0].strip().upper() in _WINDOWS_RESERVED_BASENAMES:\n',
        '    if False:  # i15int m162b\n',
    ),
    # Static-guard controls (R-TST-154, 155, 163).
    "g_remove_d1": lambda t: once(t, PE, D1_WAIT, ""),
    "g_move_d1": lambda t: once(t, PE, D1_WAIT + D1_READ, D1_READ + D1_WAIT),
    "g_fstring_d3": lambda t: once(
        t, B94,
        '                "TC-B94-27: the panel handled the Bind to the same ref",\n',
        '                f"TC-B94-27: the panel handled the Bind to the same ref",\n',
    ),
    "g_desc_d5": lambda t: once(
        t, PE,
        '                "AT-030c: the load of dropped.json reached the change document",\n',
        '                "AT-030c: the dropped file loaded",\n',
    ),
    "g_range_loop": lambda t: once(
        t, PE,
        '            outcomes["paste_enabled"] = not button.disabled\n',
        '            for _ in range(50):\n                await pilot.pause()\n'
        '            outcomes["paste_enabled"] = not button.disabled\n',
    ),
    "g_local_settled": lambda t: once(
        t, B94,
        "from tests.b97_probes import settled\n",
        "from tests.b97_probes import settled\n\n\n"
        "async def settled(pilot, predicate, description):  # i15int local wait\n"
        "    await pilot.pause()\n",
    ),
}

if __name__ == "__main__":
    tree = pathlib.Path(sys.argv[1])
    for name in sys.argv[2:]:
        MUTANTS[name](tree)
        print(f"i15int_mutate: applied {name} to {tree.name}")
