"""Inc 8 E4 negative controls as literal source mutations (applied to a COPY of the tree only, HT-09).

Each entry: key -> (description, [(path, old, new), ...]). ``old`` must occur exactly once in ``path``.
Key ``R-...`` is a requirement row; ``R-...#a`` / ``#b`` are the sub-controls of a row that names two.
Rows whose control cannot be written as a code edit carry ``None`` and a reason in NOT_EXPRESSIBLE.
"""

DS = "s19_app/tui/definition_sheet.py"
SH = "s19_app/tui/screens_directionb/patch_editor/sheet.py"
PN = "s19_app/tui/screens_directionb/patch_editor/panel.py"
AM = "s19_app/tui/screens_directionb/patch_editor/a2l_picker.py"
LY = "s19_app/tui/screens_directionb/patch_editor/layout.py"
CS = "s19_app/tui/services/change_service.py"
AP = "s19_app/tui/app/patch.py"
CORE = "s19_app/tui/app/core.py"
PK = "s19_app/tui/a2l_parameter_picker.py"
TCSS = "s19_app/tui/styles.tcss"
WH = "s19_app/tui/window_help.py"

_SHEET_BLOCK = (
    '        with Container(id="patch_sheet_win") as sheet_win:\n'
    '            sheet_win.border_title = "STAGING SHEET"\n'
    '            sheet_win.border_subtitle = "enter edit · ↑↓ row"\n'
    '            yield self._sheet\n'
)
_DESCRIBE_EACH = (
    '            {n: __import__("s19_app.tui.a2l_definition", fromlist=["x"]).describe_definition('
    'n, picker.definitions_source) for n in picker.visible_params} if picker.definitions_source '
    'else picker.definitions,\n'
)
_TEXT_DECODE_ALWAYS = (
    DS,
    "    return _decode_scalar(definition, a2l_data, image) if _text_editable(definition) else None\n",
    "    return _decode_scalar(definition, a2l_data, image)\n",
)

M = {}


def m(key, desc, *edits):
    M[key] = (desc, list(edits))


# ---- layout and chrome
m("R-TUI-063.1", "move the staging-sheet block after the landing pane in compose",
  (LY, _SHEET_BLOCK, ""),
  (LY, "                    yield from self._compose_checks_pane()\n",
   "                    yield from self._compose_checks_pane()\n" + _SHEET_BLOCK))
m("R-PE-DEF.1.1", "sheet window height 1fr -> fixed 30",
  (TCSS, "    height: 1fr;\n    min-height: 12;\n    padding: 0;\n    border: round $rule;",
   "    height: 30;\n    min-height: 12;\n    padding: 0;\n    border: round $rule;"))
m("R-PE-DEF.1.2", "delete the .-bench rule",
  (TCSS, "#patch_editor_panel.-bench #patch_inspector {\n    height: 6;\n}\n", ""))
m("R-PE-DEF.74", "delete min-height: 12 of the sheet window",
  (TCSS, "    height: 1fr;\n    min-height: 12;\n    padding: 0;\n    border: round $rule;",
   "    height: 1fr;\n    padding: 0;\n    border: round $rule;"))
m("R-TUI-063.3", "keep the A2L chip in _TABS",
  (PN, '        ("patch_tab_checks", "Checks", "patch_win_checks", "LANDS IN"),\n',
   '        ("patch_tab_checks", "Checks", "patch_win_checks", "LANDS IN"),\n'
   '        ("patch_tab_a2l", "A2L", "patch_win_a2l", "A2L"),\n'))
m("R-TUI-063.4", "initial pane patch_pane_inspector",
  (LY, 'initial="patch_win_script", id="patch_tab_switcher"', 'initial="patch_pane_inspector", id="patch_tab_switcher"'))
m("R-TUI-063.6", "Inspector tab keeps its own title INSPECTOR",
  (PN, '("patch_tab_inspector", "Inspector", "patch_pane_inspector", "LANDS IN")',
   '("patch_tab_inspector", "Inspector", "patch_pane_inspector", "INSPECTOR")'))
m("R-PE-041", "no subtitle on the landing pane for Patch script / Inspector",
  (PN, '            subtitle = self.query_one("#patch_win_script", Container).border_subtitle or ""\n',
   '            subtitle = ""\n'))
m("R-PE-DEF.2", "compose the picker inside the Inspector tab, not on the filter row",
  (LY, '        with Horizontal(id="patch_filter_row"):\n            yield from self._compose_filter_row()\n',
   '        with Horizontal(id="patch_filter_row"):\n            pass\n'),
  (LY, "                    yield from self._compose_entry_form()\n",
   "                    yield from self._compose_entry_form()\n                    yield from self._compose_filter_row()\n"))
m("R-PICKER-CORRECT.011", "the bulk button takes the include button's id (duplicate id)",
  (PK, 'bulk=f"{id_prefix}_bulk_button",', 'bulk=f"{id_prefix}_include_button",'))
m("R-PICKER-CORRECT.020", "the filter row fixed 90 cells wide",
  (TCSS, "#patch_editor_panel #patch_filter_row {\n    layout: horizontal;\n    height: 1;\n    padding: 0 1;\n}",
   "#patch_editor_panel #patch_filter_row {\n    layout: horizontal;\n    width: 90;\n    height: 1;\n    padding: 0 1;\n}"))
m("R-PE-DEF.3", "the Use row sits in a hidden container",
  (LY, "                    yield from self._compose_use_row()\n",
   '                    with Container(id="patch_use_hidden") as hidden:\n'
   "                        hidden.display = False\n"
   "                        yield from self._compose_use_row()\n"))
m("R-PE-DEF.4", "no :focus-within border rule",
  (TCSS, "#patch_editor_panel #patch_sheet_win:focus-within,\n#patch_editor_panel #patch_inspector:focus-within {",
   "#patch_editor_panel #patch_sheet_never_focus {"))

# ---- widths and cells
m("R-PE-DEF.5", "swap the New and Current header labels",
  (DS, '("Parameter", widths.name), ("Kind", widths.kind), ("Current", widths.current),\n        ("New", widths.new),',
   '("Parameter", widths.name), ("Kind", widths.kind), ("New", widths.current),\n        ("Current", widths.new),'))
m("R-PE-DEF.6", "widths computed for a fixed 118-column table",
  (DS, "        if width >= low:\n            others", "        if 118 >= low:\n            others"),
  (DS, "limits = max(0, min(64, width - 2 - others - 1))", "limits = max(0, min(64, 118 - 2 - others - 1))"))
m("R-PE-DEF.7#a", "drop the Limits cap (64)",
  (DS, "limits = max(0, min(64, width - 2 - others - 1))", "limits = max(0, min(10**6, width - 2 - others - 1))"))
m("R-PE-DEF.7#b", "clip counts characters (len), not cells",
  (DS, "        total += cell_len(char)\n", "        total += 1\n"))
m("R-PE-DEF.10", "rows from filtered_params instead of the shown page",
  (AM, "            picker.visible_params,\n            picker.definitions,", "            picker.filtered_params,\n            picker.definitions,"))
m("R-PE-DEF.11#a", "describe every shown name at each page change",
  (AM, "            picker.definitions,\n            picker.definitions_source,\n", _DESCRIBE_EACH + "            picker.definitions_source,\n"))
m("R-PE-DEF.11#b", "definitions kept across a signature change (first population wins)",
  (PK, "        self._definitions = MappingProxyType(definitions)\n",
   "        self._definitions = self._definitions or MappingProxyType(definitions)\n"))
m("R-PE-DEF.11#c", "the app's A2L read at paint time: rows re-described from it, not the picker's own describe",
  (AM, "            picker.definitions,\n            picker.definitions_source,\n",
   '            {n: __import__("s19_app.tui.a2l_definition", fromlist=["x"]).describe_definition(n, self.app.current_a2l_data)'
   " for n in picker.visible_params} if self.app.current_a2l_data else picker.definitions,\n"
   "            self.app.current_a2l_data,\n"))
m("R-PE-DEF.12#a", "one describe_definition per row at each page change (in show_page)",
  (SH, "                definition = definitions.get(name)\n",
   '                definition = __import__("s19_app.tui.a2l_definition", fromlist=["x"]).describe_definition(name, a2l_data)\n'))
m("R-PE-DEF.12#b", "full decode of every text span (no span bound)", _TEXT_DECODE_ALWAYS)
m("R-PE-DEF.13", "empty sheet when a filter matches nothing",
  (SH, "Text(_NO_A2L if self.a2l_data is None else _NO_ROWS, no_wrap=True)",
   'Text(_NO_A2L if self.a2l_data is None else "", no_wrap=True)'))
m("R-PE-DEF.14", "paint the no-page line when no A2L is loaded",
  (SH, "Text(_NO_A2L if self.a2l_data is None else _NO_ROWS, no_wrap=True)", "Text(_NO_ROWS, no_wrap=True)"))
m("R-PE-DEF.15", "cells parsed as markup",
  (DS, "    return _fit(Text(clip(text, width, clean=True), style=style), width)\n",
   "    return _fit(Text.from_markup(clip(text, width, clean=True), style=style), width)\n"))
m("R-PE-DEF.16", "Kind column shows I-2 kind word",
  (DS, '    return definition.char_type or "?"\n', '    return definition.kind or "?"\n'))
m("R-PE-DEF.17", "number Current shows the stored value",
  (DS, "    return gap if gap is not None else decoded.text\n\n\ndef _value_enum",
   "    return gap if gap is not None else _stored_text(decoded)\n\n\ndef _value_enum"))
m("R-PE-DEF.18", "zero-fill the byte an image lacks",
  (DS, "    return decode_definition(definition, a2l_data or {}, image if image is not None else {})\n",
   '    z = type("Z", (dict,), {"__missing__": lambda s, k: 0, "get": lambda s, k, d=None: 0,'
   ' "__contains__": lambda s, k: True})\n'
   "    return decode_definition(definition, a2l_data or {}, z(image if image is not None else {}))\n"))
m("R-PE-DEF.75", "fallback rows decode through I-2 and read as numbers",
  (DS, '    "", _never, _decode_none, _value_fallback, _staged_by_bytes,',
   '    "", _never, _decode_scalar, _value_number, _staged_by_bytes,'))
m("R-PE-DEF.88", "decode text spans over 4096 bytes", _TEXT_DECODE_ALWAYS)
m("R-PE-DEF.19", "a refused definition is decoded through I-2 (fallback decode = scalar decode)",
  (DS, '    "", _never, _decode_none, _value_fallback, _staged_by_bytes,',
   '    "", _never, _decode_scalar, _value_fallback, _staged_by_bytes,'))
m("R-PE-DEF.19#x", "EXTRA (not the control text): no refused branch in _missing (dead for refused rows)",
  (DS, '    if row.definition.refusal is not None:\n        return "refused"\n    return None if isinstance',
   '    return None if isinstance'))
m("R-PE-DEF.20", "raw unit (no control-character cleaning)",
  (DS, '    unit_c = _text_cell(row.definition.unit or "", widths.unit)\n',
   '    unit_c = _fit(Text(row.definition.unit or ""), widths.unit)\n'))
m("R-PE-DEF.21", "ruler dot placed by the stored value",
  (DS, "    return _numeric(decoded.value if row.kind == \"number\" else decoded.stored)\n",
   "    return _numeric(decoded.stored)\n"))
m("R-PE-DEF.76", "no guard for limits that do not ascend (plain division)",
  (DS, "    if not upper > lower or track < 6:\n", "    if track < 6:\n"))
m("R-PE-DEF.77", "no guard for limits that do not ascend in the percent",
  (DS, "    if lower is None or upper is None or not upper > lower:\n        return text\n",
   "    if lower is None or upper is None:\n        return text\n"))
m("R-PE-DEF.22", "mark every row with the pointer",
  (DS, '    mark = Text("▶" if selected else " ", style=_ACCENT if selected else "")\n',
   '    mark = Text("▶", style=_ACCENT if selected else "")\n'))
m("R-PE-DEF.23#a", "New read from the formula input text, not the row's pending text",
  (SH, '                    self.pending.get(item.name, ""),\n',
   '                    (self._input.value if shown and self._input is not None else ""),\n'))
m("R-PE-DEF.23#b", "staged state of a fallback row from a value-text decode",
  (DS, "    return replace(row, is_staged=ops.staged(row, image, overlay))\n",
   "    return replace(row, is_staged=(_staged_by_text(row, image, overlay) if ops is _FALLBACK_OPS"
   " else ops.staged(row, image, overlay)))\n"))
m("R-PE-DEF.24#a", "New echoes the typed text",
  (DS, "    if isinstance(new, Decoded):\n        return value_text(row, new)\n",
   "    if isinstance(new, Decoded):\n        return pending if is_pending else value_text(row, new)\n"))
m("R-PE-DEF.24#b", "pending = any formula text",
  (DS, "    return bool(pending) and pending != _base_text(row)\n", "    return bool(pending)\n"))
m("R-PE-DEF.25", "New shows the refusal code",
  (DS, '    return pending if is_pending else "·"\n',
   '    return (new.code if hasattr(new, "code") else pending) if is_pending else "·"\n'))
m("R-PE-DEF.26", "percent taken over the extended limits",
  (DS, "    limits = row.definition.limits\n    lower, upper = limits.lower, limits.upper\n    if lower is None or upper is None or not upper > lower:",
   "    limits = row.definition.extended_limits or row.definition.limits\n    lower, upper = limits.lower, limits.upper\n    if lower is None or upper is None or not upper > lower:"))
m("R-PE-DEF.27", "a refused preview keeps the previous delta",
  (DS, "    if is_pending:\n        return delta_text(row, preview, False) if preview is not None else \"\"\n",
   "    if is_pending and not (preview is not None and isinstance(preview.result, Refusal)):\n"
   "        return delta_text(row, preview, False) if preview is not None else \"\"\n"))
m("R-PE-DEF.28", "New shows the current value for an untouched row",
  (DS, '    return pending if is_pending else "·"\n',
   '    return pending if is_pending else value_text(row, row.current)\n'))
m("R-PE-DEF.30", "every row keeps its expanded detail",
  (SH, "            if shown:\n                lines.extend(detail)\n", "            lines.extend(detail)\n"))
m("R-PE-DEF.31#a", "leave out '>> <shift>' of the mask formula",
  (DS, '        raw = f"(word & {_mask_text(definition)}) >> {_mask_shift(definition.bit_mask)}"\n',
   '        raw = f"(word & {_mask_text(definition)})"\n'))
m("R-PE-DEF.31#b", "drop the record layout word",
  (DS, "        if d.record_layout:\n            head.append(plain(d.record_layout))\n",
   "        if False:\n            head.append(plain(d.record_layout))\n"))
m("R-PE-DEF.32", "a refused row shows the definition line, not its message",
  (DS, "    if d.refusal is not None:\n        return Text(\"└ \" + plain(d.refusal.message))\n",
   "    if False:\n        return Text(\"└ \" + plain(d.refusal.message))\n"))
m("R-PE-DEF.33", "mark the current entry after a choice (ignore the preview)",
  (DS, "    if preview is not None and isinstance(preview.decoded, Decoded):\n        return preview.decoded.stored\n",
   "    if False:\n        return preview.decoded.stored\n"))
m("R-PE-DEF.34", "bit strip's after word is the before word",
  (DS, "    after = _after_bytes(row, preview, count)\n    shown = after if None not in after else before\n",
   "    after = before\n    shown = after if None not in after else before\n"))
m("R-PE-DEF.35", "text rows show 8 bytes per row",
  (DS, "    for offset in range(0, shown, 16):\n", "    for offset in range(0, shown, 8):\n"),
  (DS, "        for index in range(offset, min(offset + 16, shown)):\n",
   "        for index in range(offset, min(offset + 8, shown)):\n"))
m("R-PE-DEF.36#a", "formula input enabled for a row with no editor",
  (SH, "        if ops_for(row.kind).editable(row.definition):\n            self._input.disabled = False\n        else:\n            self._disable_input()\n",
   "        self._input.disabled = False\n"))
m("R-PE-DEF.36#b", "no span bound on a text row's editor",
  (DS, "    return length is not None and length <= _TEXT_EDIT_MAX\n", "    return length is not None\n"))
m("R-PE-DEF.37", "one label for every kind",
  (SH, "self._label_label.update(Text(ops.label, no_wrap=True))", 'self._label_label.update(Text("new =", no_wrap=True))'))
m("R-PE-DEF.38#a", "text row fill left empty",
  (DS, "    text = pending if pending is not None else _base_text(row)\n", '    text = pending if pending is not None else ""\n'))
m("R-PE-DEF.38#b", "fill is always the current text",
  (DS, "    text = pending if pending is not None else _base_text(row)\n", "    text = _base_text(row)\n"))
m("R-PE-DEF.39", "pending text cleared when the selection moves",
  (SH, "        before = self.selected_name\n        self.selected = index\n",
   "        before = self.selected_name\n        self.pending.pop(before, None)\n        self.selected = index\n"))
m("R-PE-DEF.40", "preview over the image, not the overlay",
  (SH, "preview = ops.preview(row.definition, self.a2l_data, text, self._overlay)",
   "preview = ops.preview(row.definition, self.a2l_data, text, self._image)"))
m("R-PE-DEF.41", "the bar's tail is not cut at its edge",
  (DS, "def _cut(line: Text, width: int) -> Text:\n    return _trim(line, width)\n",
   "def _cut(line: Text, width: int) -> Text:\n    return line\n"))
m("R-PE-DEF.42", "formula input without max_length",
  (SH, "OsClipboardInput(max_length=FORMULA_MAX, id=\"patch_sheet_input\")", 'OsClipboardInput(id="patch_sheet_input")'))
m("R-PE-DEF.78", "a row with no editor fills the current (decoded) text",
  (DS, '    if not ops_for(row.kind).editable(row.definition):\n        return ""\n    text = pending',
   '    text = pending'),
  _TEXT_DECODE_ALWAYS)
m("R-PE-DEF.79", "text rows paint every row of the span",
  (DS, "    shown = min(span, _TEXT_ROWS_BYTES)\n", "    shown = span\n"))
m("R-PE-DEF.80", "fill is not capped (direct value =)",
  (DS, "    return text[:_FILL_MAX]\n", "    return text\n"))

# ---- keys and window
m("R-PE-DEF.45", "selection wraps around",
  (SH, "        self._select(min(len(self.rows) - 1, max(0, self.selected + int(delta))))\n",
   "        self._select((self.selected + int(delta)) % len(self.rows))\n"))
m("R-PE-DEF.46", "no enter binding on the sheet",
  (SH, '        Binding("enter", "edit", "Edit", show=False),\n', ""))
m("R-PE-DEF.47", "enum choice sets the stored value as the formula text",
  (SH, "        self._set_formula_text(row, target[:FORMULA_MAX])\n",
   "        self._set_formula_text(row, str(int(row.definition.enum_entries[texts.index(target)].raw)))\n"))
m("R-PE-DEF.48", "escape keeps the pending text",
  (SH, "        if row is not None:\n            self.pending.pop(row.name, None)\n            self._previews.pop(row.name, None)\n        self._fill_input()\n        if self._body is not None:",
   "        if row is not None:\n            self._previews.pop(row.name, None)\n        self._fill_input()\n        if self._body is not None:"))
m("R-PE-DEF.49", "picker cursor left at row 0",
  (AM, "            row=names.index(event.name)\n", "            row=0\n"))
m("R-PE-DEF.81#a", "paint every row from row 0 (no row window top)",
  (DS, "    return max(0, top), painted\n", "    return 0, painted\n"))
m("R-PE-DEF.81#b", "the detail is not cut to the window (row_window paints every detail line)",
  (DS, "    painted = max(0, min(detail, visible - 1))\n", "    painted = max(0, detail)\n"))
m("R-PE-DEF.81#x", "EXTRA (not the control text): detail_lines does not cut to the room",
  (DS, "        lines = lines[: max(room, 0)]\n", "        lines = lines\n"))

# ---- staging service
m("R-PE-DEF.50", "stage through add_symbol_entry (the pre-I-2 encode)",
  (CS, "        entries = [\n            (entry.address, entry.encoded_bytes)\n            for entry in self.document.entries\n        ]\n        encoded = encode_definition(",
   "        return self.add_symbol_entry(definition.name, text, a2l_data)\n        entries = [\n            (entry.address, entry.encoded_bytes)\n            for entry in self.document.entries\n        ]\n        encoded = encode_definition("))
m("R-PE-DEF.51#a", "encode over the image, not the overlay",
  (CS, "definition, a2l_data, text, StagedOverlay(image, entries)\n", "definition, a2l_data, text, image\n"))
m("R-PE-DEF.51#b", "stage over the live (applied) map",
  (AP, "            self._strip_source_map(self.current_file),\n",
   "            (self.current_file.mem_map if self.current_file is not None else None),\n"))
m("R-PE-DEF.52#a", "append a second entry for an equal span",
  (CS, "        if equal_index is None:\n            self.document.entries.append(", "        if True:\n            self.document.entries.append("))
m("R-PE-DEF.52#b", "replace only the bytes of the old entry (a string entry keeps its type and value)",
  (CS, 'ChangeEntry(\n                "bytes", start, tuple(encoded.data), symbol=old.symbol\n            )',
   '__import__("dataclasses").replace(old, encoded_bytes=tuple(encoded.data))'))
m("R-PE-DEF.53", "appended entry carries symbol None",
  (CS, 'ChangeEntry("bytes", start, tuple(encoded.data), symbol=name)', 'ChangeEntry("bytes", start, tuple(encoded.data), symbol=None)'))
m("R-PE-DEF.54", "replace overwrites the symbol with the row name",
  (CS, "tuple(encoded.data), symbol=old.symbol\n            )", "tuple(encoded.data), symbol=name\n            )"))
m("R-PE-DEF.55", "a partial overlap replaces the entry instead of refusing",
  (CS, "            if (low, high) != (start, end):\n", "            if False:\n"))
m("R-PE-DEF.56", "a refusal stages the image bytes of the span",
  (CS, '            return ChangeActionResult(\n                message=f"Patch Editor: {encoded.message}", issues=[], ok=False\n            )\n',
   "            return self._stage_encoded(definition.name, Encoded(definition.address, bytes("
   "(image or {}).get(definition.address + i, 0) for i in range(definition.byte_length or 1)), ()), text)\n"))
m("R-PE-DEF.57", "refusal status shows the code only",
  (CS, 'message=f"Patch Editor: {encoded.message}", issues=[], ok=False', 'message=f"Patch Editor: {encoded.code}", issues=[], ok=False'))
m("R-PE-DEF.58#a", "success status reads 'entry added.'",
  (CS, '            message=(\n                f"Patch Editor: {name_echo(name)} staged as "\n                f"{name_echo(shown)} ({len(encoded.data)} B at 0x{start:X})."\n            ),',
   '            message="Patch Editor: entry added.",'))
m("R-PE-DEF.58#b", "the shown <text> is not bounded",
  (CS, 'f"{name_echo(shown)} ({len(encoded.data)} B at 0x{start:X})."', 'f"{shown} ({len(encoded.data)} B at 0x{start:X})."'))
m("R-PE-DEF.59#a", "drop the encode notices",
  (CS, '            result.notices = tuple(\n                f"Patch Editor: {notice}" for notice in encoded.notices\n            )\n',
   "            result.notices = ()\n"))
m("R-PE-DEF.59#b", "report the notices as issues",
  (CS, '            result.notices = tuple(\n                f"Patch Editor: {notice}" for notice in encoded.notices\n            )\n',
   '            result.issues = [f"Patch Editor: {notice}" for notice in encoded.notices]\n'))
m("R-PE-DEF.60#a", "no advance of the selection after a stage",
  (PN, "        if advance:\n            self._sheet.select_after(name)", "        if False:\n            self._sheet.select_after(name)"))
m("R-PE-DEF.60#b", "advance from the current selection, not the staged row",
  (SH, "self._select(min(len(self.rows) - 1, index + 1))", "self._select(min(len(self.rows) - 1, self.selected + 1))"))
m("R-PE-DEF.82", "keep the staged row's pending text",
  (SH, "        self.pending.pop(name, None)\n        self._previews.pop(name, None)\n        index = next(",
   "        self._previews.pop(name, None)\n        index = next("))
m("R-PE-DEF.61", "no history step on a stage",
  (CS, "        self._push_history()\n        if equal_index is None:", "        if equal_index is None:"))
m("R-PE-034", "no dirty writer for the stage",
  (PN, "        self._dirty = True\n        self._refresh_dirty_indicator()\n        if advance:", "        if advance:"))
m("R-PE-035", "set the dirty flag before the encode",
  (AP, "        definition = describe_definition(event.name, a2l_data)\n",
   '        self.query_one("#patch_editor_panel", PatchEditorPanel)._dirty = True\n'
   "        definition = describe_definition(event.name, a2l_data)\n"))
m("R-PE-DEF.62#a", "the sheet tracks staged rows itself (no set_document on a ledger refresh)",
  (PN, "        super().refresh_entries(rows, mem_map, document)\n        self._sheet.set_document(self._sheet_entries(rows), self._mem_map)\n",
   "        super().refresh_entries(rows, mem_map, document)\n"))
m("R-PE-DEF.62#b", "keep the rows of the old image (no set_document on a new map)",
  (PN, "        self._sheet.set_document(self._sheet_entries(self._entry_rows), mem_map)\n", "        pass\n"))
m("R-PE-110", "no busy check in the stage handler",
  (AP, "        if self._refuse_if_busy():\n            return\n        a2l_data = self.current_a2l_data\n",
   "        a2l_data = self.current_a2l_data\n"))
m("R-PE-DEF.63", "stage with the old (sheet's) A2L when the app has none",
  (AP, "        a2l_data = self.current_a2l_data\n        if not a2l_data:\n",
   '        a2l_data = self.current_a2l_data or self.query_one("#patch_editor_panel", PatchEditorPanel)._sheet.a2l_data\n'
   "        if not a2l_data:\n"))
m("R-PE-DEF.64", "stage with the page's definition, not a fresh describe",
  (AP, "        definition = describe_definition(event.name, a2l_data)\n",
   '        definition = next(r.definition for r in self.query_one("#patch_editor_panel", PatchEditorPanel)._sheet.rows'
   " if r.name == event.name)\n"))

# ---- markup and plain text
m("R-PE-DEF.70#a", "one Current cell rendered as a markup str",
  (DS, "        _text_cell(ops.value_text(row, row.current), widths.current),\n",
   "        _fit(Text.from_markup(clip(ops.value_text(row, row.current), widths.current, clean=True)), widths.current),\n"))
m("R-PE-DEF.70#b", "the bar's name label updated with a markup str",
  (SH, 'self._name_label.update(Text(plain(name_text), no_wrap=True, overflow="ellipsis"))', "self._name_label.update(plain(name_text))"))
m("R-PE-DEF.71", "plain() leaves control characters in",
  (DS, "    return _CONTROLS.sub(_FFFD, text)\n", "    return text\n"))
m("R-PE-DEF.72", "name_echo not bounded",
  (DS, "    head = plain(text[:_ECHO_LIMIT])\n", "    head = plain(text)\n"))
m("R-PE-DEF.73", "status line label with markup=True",
  (CORE, 'deps.Label("", id="log_line_4", markup=False),', 'deps.Label("", id="log_line_4", markup=True),'))

# ---- help text
m("R-PE-DEF.83", "keep the pre-Inc-8 step 1 text",
  (WH, '            "Edit a change-set: the filter row narrows the loaded A2L\'s "\n            "parameters, the STAGING SHEET lists them one row each to stage "\n'
   '            "an edit, and LANDS IN holds the Patch script, Inspector, JSON "\n            "and Checks tabs. Load an S19/HEX image first (`^L`) to see the "\n'
   '            "bytes an entry replaces.",\n',
   '            "Edit a change-set: the PATCH SCRIPT ledger on the left lists its "\n            "entries; the inspector on the right shows the highlighted entry "\n'
   '            "and holds the Inspector, JSON, Checks and A2L tabs. Load an "\n            "S19/HEX image first (`^L`) to see the bytes an entry replaces.",\n'))
m("R-PE-DEF.84", "delete the Patch script help line",
  (WH, '            "Patch script — the ledger of the document\'s entries, one row "\n            "each, with the highlighted entry\'s BEFORE → AFTER bytes.",\n', ""))
m("R-PE-DEF.85", "delete the STAGING SHEET help line",
  (WH, '            "STAGING SHEET — ↑↓ select a row, enter moves to the formula "\n            "input, ←→ choose an enum entry, esc returns from the formula "\n            "input to the sheet.",\n', ""))
m("R-PE-DEF.86", "delete the field = help line (only the new = line stays)",
  (WH, '            "field = — the formula input of a bit mask row; enter stages the "\n            "typed field value.",\n', ""))
m("R-PE-DEF.87", "keep the pre-Inc-8 Use parameter line",
  (WH, '            "Use parameter — on the Inspector tab, uses the staging sheet\'s "\n            "selected row: copies its address and the loaded image\'s current "\n'
   '            "bytes into the entry form; the document changes only through "\n            "Add or Edit.",\n',
   '            "Use parameter — on the A2L tab, copies the highlighted "\n            "parameter\'s address and the loaded image\'s current bytes into "\n'
   '            "the entry form; the document changes only through Add or Edit.",\n'))

NOT_EXPRESSIBLE = {}
