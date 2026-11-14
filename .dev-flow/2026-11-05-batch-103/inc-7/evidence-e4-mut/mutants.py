import json, io
LL = "s19_app/tui/a2l_label_list.py"
AV = "s19_app/tui/app/a2l_view.py"
CS = "s19_app/tui/app/compose_screens.py"
M = []


def m(id, file, old, new, req, k, extra=""):
    M.append(dict(id=id, file=file, old=old, new=new, req=req, k=k, extra=extra))


m("MU01a", LL, "        if len(all_missing) > SIMILAR_MAX:", "        if False:", "R-A2L-LIST.051 cap line removed", "051")
m("MU01b", LL, "        if len(all_missing) > SIMILAR_MAX:", "        if len(all_missing) >= SIMILAR_MAX:", "R-A2L-LIST.051 cap line off by one (at exactly 10)", "051")
m("MU01c", LL, "        missing = all_missing[:SIMILAR_MAX]", "        missing = all_missing[:SIMILAR_MAX + 1]", "R-A2L-LIST.051 cap 11 lines", "051")
m("MU02", LL, "    found = res.count(FOUND) + hidden", "    found = res.count(FOUND)", "R-A2L-LIST.017 found count without hidden", "017 or 021")
m("MU03", LL, "    if entry.status == MISSING or entry.tag is None:", "    if entry.status == MISSING:", "R-A2L-LIST.015 tag-is-None branch (duplicate of a missing name)", "015 or 078")
m("MU04", AV, "            # Text mode again: repaint the mode tag and chips (R-A2L-LIST.008/3, E3A-08).\n            self._paint_a2l_filter_chips()\n", "            pass\n", "R-A2L-LIST.008/3 .023/2 chips and FILTER tag not repainted on unload", "008 or 023 or 007")
m("MU05a", LL, "        if not self._app.is_running:\n            return\n        if generation != self._generation:", "        if generation != self._generation:", "R-A2L-LIST.084 is_running check in _install dropped", "084 or 085 or 087")
m("MU05b", LL, "        if not self._app.is_running:\n            return\n        self._running.discard(key)", "        self._running.discard(key)", "R-A2L-LIST.084/.085 is_running check in _deliver dropped", "084 or 085 or 087")
m("MU05c", LL, "        if not self.is_attached or not self.app.is_running:", "        if not self.is_attached:", "R-A2L-LIST.085/.086 is_running check of the paste window painters dropped", "084 or 085 or 086")
m("MU06a", AV, "            if not self.is_running:\n                return\n            self._refresh_a2l_filtered_tags(preserve_anchor=False)", "            self._refresh_a2l_filtered_tags(preserve_anchor=False)", "P-002 guard in _schedule_a2l_filter_refresh dropped", "", "tests/test_b103_a2l_filter_teardown.py")
m("MU06b", AV, "        if not self.is_running:\n            return\n        names = self._a2l_list_names()\n        self._mark_a2l_filter_mode()", "        names = self._a2l_list_names()\n        self._mark_a2l_filter_mode()", "row-17 guard of _paint_a2l_filter_chips dropped", "", "tests/test_tui_app.py::test_refresh_a2l_filtered_tags_resets_anchor")
m("MU07", LL, 'LIST_COLUMNS = ("#", "Tag", "Status", "Kind", "Address", "Len", "Physical", "Unit", "Limits")', 'LIST_COLUMNS = ("Address", "Len", "#", "Tag", "Status", "Kind", "Physical", "Unit", "Limits")', "R-A2L-LIST.009/.010 D-4 B: Address/Len first again", "010 or 009", "tests/test_b103_inc12_tag_table.py")
m("MU08a", CS, '            Static("", id="a2l_list_chips", markup=False),', '            Static("", id="a2l_list_chips"),', "R-A2L-LIST.076 markup=False dropped on the viewer chips", "076 or 077")
m("MU08b", CS, '            Static("", id="a2l_list_missing", markup=False),\n            A2LTagTable(', '            Static("", id="a2l_list_missing"),\n            A2LTagTable(', "R-A2L-LIST.076 markup=False dropped on the viewer missing line", "076 or 077")
m("MU08c", LL, '            yield Static("", id="a2l_list_missing", markup=False)', '            yield Static("", id="a2l_list_missing")', "R-A2L-LIST.076 markup=False dropped on the window missing line", "076 or 077")
m("MU08d", LL, '            yield Static("", id="a2l_list_similar", markup=False)', '            yield Static("", id="a2l_list_similar")', "R-A2L-LIST.076/.077 markup=False dropped on the similar line", "076 or 077")
m("MU08e", LL, '        line.update(Text("\\n".join(parts)))', '        line.update("\\n".join(parts))', "R-A2L-LIST.076 similar line painted as a str", "076 or 077")
m("MU08f", LL, '            " · ".join(f"#{e.pos} {display_text(e.name, SHORT_AT)}" for e in shown),\n            style=RED,', '            " · ".join(f"#{e.pos} {e.name}" for e in shown),\n            style=RED,', "R-A2L-LIST.076/.077 missing line paints the raw name", "076 or 077 or 024")
m("MU09", LL, "            first_tag[name] = tag", "            first_tag[name.lower()] = tag", "R-A2L-LIST.002 name matched case-folded (tag side)", "002 or 003 or 004")
m("MU10", LL, "        if first is not None:\n            tag = first_tag.get(name)", "        if False:\n            tag = first_tag.get(name)", "R-A2L-LIST.003 no duplicate check", "003 or 017")
m("MU11", LL, "entries.append(LabelListEntry(pos, name, MISSING, None, None))", "entries.append(LabelListEntry(pos, name, FOUND, None, None))", "R-A2L-LIST.004 missing treated as found", "004 or 017")
m("MU12", LL, "        elif hidden is not None and hidden(tag):", "        elif False:", "R-A2L-LIST.005 mode ignored in list mode", "005 or 017")
m("MU13", LL, "    if char_type:\n        return str(char_type)", "    if False:\n        return str(char_type)", "R-A2L-LIST.013 Kind: char_type ignored", "013")
m("MU14", LL, "    missing = res.count(MISSING)\n    dup", "    missing = res.count(MISSING) + hidden\n    dup", "R-A2L-LIST.017 hidden counted as missing", "017")
m("MU15", LL, '    if 2 * n <= budget:\n        for entry in entries:\n            text.append(GLYPH[entry.status], style=_STATUS_STYLE[entry.status])\n            text.append(" ")\n    else:', '    if True:\n        for entry in entries:\n            text.append(GLYPH[entry.status], style=_STATUS_STYLE[entry.status])\n            text.append(" ")\n    else:', "R-A2L-LIST.018 ribbon with no budget", "018 or 046")
m("MU16a", LL, "        shown = missing[:MISSING_MAX]", "        shown = missing", "R-A2L-LIST.024 missing line with no cap", "024")
m("MU16b", LL, "        shown = dupes[:MISSING_MAX]", "        shown = dupes", "R-A2L-LIST.024 duplicates line with no cap", "024")
m("MU17", LL, "VIEWER_RIBBON = 80", "VIEWER_RIBBON = 60", "R-A2L-LIST.046 viewer ribbon budget 80 -> 60", "046 or 018")
m("MU18a", LL, "DROPDOWN_ROWS = 8", "DROPDOWN_ROWS = 20", "R-A2L-LIST.063 dropdown 20 rows", "063 or 065")
m("MU18b", LL, '        total = "20+" if self._total == RANK_LIMIT else str(self._total)', "        total = str(self._total)", "R-A2L-LIST.065 total never 20+", "065")
m("MU19a", LL, "        self.dismiss(names if names else None)", "        self.dismiss(names)", "R-A2L-LIST.054 apply with no names dismisses []", "053 or 054")
m("MU19b", LL, "            suggest.close()\n            return\n        self.dismiss(None)", "            suggest.close()\n        self.dismiss(None)", "R-A2L-LIST.070 esc closes the dropdown and the window", "055 or 070")
m("MU20", LL, '        if text and not text.endswith("\\n"):\n            text += "\\n"\n        ta.text = text + name + "\\n"', '        ta.text = text + name + "\\n"', "R-A2L-LIST.057 appended without a new line", "057 or 058")
m("MU21a", LL, "    return len(parse_parameter_list(text)) >= 2", "    return len(parse_parameter_list(text)) >= 1", "R-A2L-LIST.001/.006 list text from one name", "001 or 006 or 062 or r_a2l_007")
m("MU21b", LL, "    return len(parse_parameter_list(text)) >= 2", "    return len(parse_parameter_list(text)) >= 3", "R-A2L-LIST.001/.006 list text needs three names", "001 or 006 or 062 or r_a2l_007")
m("MU22a", LL, "WIDE_AT = 180", "WIDE_AT = 160", "R-A2L-LIST.082 wide regime from 160", "080 or 081 or 082 or 083")
m("MU22b", LL, "STACK_MIN_HEIGHT = 32", "STACK_MIN_HEIGHT = 28", "R-A2L-LIST.083/R-TUI-037 short body below 28", "083 or r_tui_037 or r_tui_069")
m("MU22c", LL, "STACK_MIN_WIDTH = 110", "STACK_MIN_WIDTH = 100", "R-A2L-LIST.080/R-TUI-037 short body below 100", "080 or r_tui_037")
m("MU23", LL, "SHORT_AT = 64", "SHORT_AT = 80", "R-A2L-LIST.077 short text cap 64 -> 80", "077 or 076")
m("MU24", LL, '    s = "" if dup == 1 else "s"', '    s = "s"', "R-A2L-LIST.017 plural of duplicate always", "017")
m("MU25", AV, "            self._a2l_list_resolution = None\n            self._update_a2l_summary_buffer()", "            self._update_a2l_summary_buffer()", "R-A2L-LIST.008 kept resolution after the unload", "008 or 023")
m("MU26", AV, "        self._set_a2l_table_columns(a2l_table, label_list.LIST_COLUMNS)\n        a2l_table.clear(columns=False)", "        a2l_table.clear(columns=False)", "R-A2L-LIST.009 list columns not set", "009 or 010 or 011")
m("MU27", AV, "                hidden=lambda tag: not self._a2l_mode_keeps(tag, mode),\n            )\n            self._a2l_list_resolution = resolution\n            return list(resolution.rows)", "                hidden=None,\n            )\n            self._a2l_list_resolution = resolution\n            return list(resolution.rows)", "R-A2L-LIST.005 viewer resolves without the mode predicate", "005 or 017 or r_a2l_007")
m("MU28", LL, "WINDOW_RIBBON = 50", "WINDOW_RIBBON = 40", "R-A2L-LIST.046/.018 window ribbon budget 50 -> 40", "046 or 018")
m("MU29", LL, "PREVIEW_MAX = 200", "PREVIEW_MAX = 300", "R-A2L-LIST.019 preview cap 200 -> 300", "019 or 078")
m("MU30", LL, "MISSING_MAX = 20", "MISSING_MAX = 30", "R-A2L-LIST.024 missing cap 20 -> 30", "024")
m("MU31", LL, "RANK_LIMIT = 20", "RANK_LIMIT = 30", "R-A2L-LIST.063 rank limit 20 -> 30", "063 or 065")
m("MU32", LL, "CLOSEST_LIMIT = 3", "CLOSEST_LIMIT = 4", "R-A2L-LIST.059/.049 closest names 3 -> 4", "049 or 050 or 059")

if __name__ == "__main__":
    ok = True
    for x in M:
        s = io.open("<repo>/" + x["file"], encoding="utf-8", newline="").read().replace("\r\n", "\n")
        c = s.count(x["old"])
        if c != 1:
            print("BAD", x["id"], c)
            ok = False
        assert x["old"] != x["new"]
    print(len(M), "mutants", "ok" if ok else "BAD")
    json.dump(M, open("<scratch>/mutants.json", "w"), indent=1)
