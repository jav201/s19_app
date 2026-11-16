"""M8b mutant driver: runs on rtx. One fresh hard-link copy of the pristine tree per mutant."""
import io, os, re, shutil, subprocess, sys, json, time

HOME = os.path.expanduser("~")
S = os.path.join(HOME, "work", "zq-m8b")
PRIST = os.path.join(S, "pristine")
OUT = os.path.join(S, "out")
PY = os.path.join(HOME, "miniconda3", "envs", "s19ci", "bin", "python")

DS = "s19_app/tui/definition_sheet.py"
SH = "s19_app/tui/screens_directionb/patch_editor/sheet.py"
BS = "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
DB = "s19_app/tui/definition_bench.py"
DV = "s19_app/tui/definition_bench_view.py"
PK = "s19_app/tui/a2l_parameter_picker.py"
WH = "s19_app/tui/window_help.py"
CSS = "s19_app/tui/styles.tcss"

T = "tests/test_b103_"
FAST = ([T + "inc8b_%s.py" % n for n in ("s1", "s2")]
        + [T + "inc8_%s.py" % n for n in ("s1_detail", "s1", "s2_sheet_rows", "s2_sheet_formula", "s2_sheet_keys")])
BWF = T + "inc8b_bw.py"
ATF = T + "inc8b_at.py"
BENCHF = [T + "inc9_%s.py" % n for n in ("b_cells", "b_detail", "b_canvas")]
BW_KS = ("r_pe_def_101_", "r_pe_def_113_", "r_pe_def_81_", "r_pe_def_85_", "r_pe_def_92_", "r_pe_bench_36_",
         "r_pe_bench_107_", "r_pe_bench_108_", "r_pe_bench_11_", "r_pe_bench_17_")
AT_KS = {  # AT nodes added to a mutant whose row has no test of its own
    "N-94a": "at_b103_i8b_1_ or at_b103_i8b_2_ or at_b103_i8b_3_", "N-94b": "at_b103_i8b_1_ or at_b103_i8b_2_ or at_b103_i8b_3_",
    "N-94c": "at_b103_i8b_1_ or at_b103_i8b_2_ or at_b103_i8b_3_", "N-95": "at_b103_i8b_9_", "P-AT4": "at_b103_i8b_4_",
}

M = []  # (id, rows, k-expression rows, edits, files-override)


def m(mid, rows, ks, edits):
    M.append(dict(id=mid, rows=rows, ks=ks, edits=edits))


# every edit: (file, old, new, count)
m("N-5", "R-PE-DEF.5", ["r_pe_def_5_"], [(DS,
  '        line.append_text(_fit(Text(clip(label, width), style=f"bold {_DIM}"), width))\n        line.append("│", style=_RULE)\n',
  '        line.append_text(_fit(Text(clip(label, width), style=f"bold {_DIM}"), width))\n        if label != "Kind":\n            line.append("│", style=_RULE)\n', 1)])
m("N-89", "R-PE-DEF.89", ["r_pe_def_89_"], [(DS, "    return _GRID_WIDTHS\n", "    return _GRID_WIDTHS._replace(kind=0) if width < 100 else _GRID_WIDTHS\n", 1)])
m("N-90", "R-PE-DEF.90", ["r_pe_def_90_"], [(DS,
  '        line.append_text(cell)\n        line.append("│", style=_RULE)\n',
  '        line.append_text(cell)\n        if not cell.plain.rstrip().endswith("…"):\n            line.append("│", style=_RULE)\n', 1)])
m("N-91", "R-PE-DEF.91", ["r_pe_def_91_"], [(SH, "lines = [header_line(widths), header_rule(widths)]", "lines = [header_line(widths)]", 1)])
m("N-92a", "R-PE-DEF.92", ["r_pe_def_92_"], [(SH, "overflow-x: auto;", "overflow-x: hidden;", 1)])
m("N-92b", "R-PE-DEF.92,33", ["r_pe_def_92_", "r_pe_def_33_"], [
  (SH, "from textual.containers import Container, Horizontal, Vertical", "from textual.containers import Container, Horizontal, ScrollableContainer, Vertical", 1),
  (SH, 'self._grid = Container(self._body, id="patch_sheet_grid")', 'self._grid = ScrollableContainer(self._body, id="patch_sheet_grid")', 1)])
m("N-93", "R-PE-DEF.93", ["r_pe_def_92_", "r_pe_def_93_"], [(SH, "overflow-x: auto;", "overflow-x: scroll;", 1)])
m("N-94a", "R-PE-DEF.94", ["r_pe_def_94_"], [
  (SH, '        Binding("home", "scroll_grid(\'home\')", "Grid start", show=False),\n', "", 1),
  (SH, '        Binding("end", "scroll_grid(\'end\')", "Grid end", show=False),\n', "", 1)])
m("N-94b", "R-PE-DEF.94", ["r_pe_def_94_"], [(SH, 'x = 0 if where == "home" else max(0, GRID_WIDTH - self._view_width())', 'x = 0 if where == "home" else 1', 1)])
m("N-94c", "R-PE-DEF.94", ["r_pe_def_94_"], [(SH, "animate=False, immediate=True", "animate=True", 1)])
m("N-95", "R-PE-DEF.95", ["r_pe_def_95_"], [(SH, "StagingSheet > #patch_sheet_bar { height: 1; }", "StagingSheet > #patch_sheet_bar { height: 1; width: 143; }", 1)])
m("N-96a", "R-PE-DEF.96", ["r_pe_def_96_"], [(DS, "        total += cell_len(char)\n", "        total += 1\n", 1)])
m("N-96b", "R-PE-DEF.96", ["r_pe_def_96_"], [(DS, "        head = plain(head)\n", "        head = plain(text)\n", 1)])
m("N-96c", "R-PE-DEF.96", ["r_pe_def_96_"], [(DS, "    return head[:keep] + _ELLIPSIS if cut else head\n", "    return head[:keep] + _ELLIPSIS\n", 1)])
m("N-81a", "R-PE-DEF.81", ["r_pe_def_81_"], [(SH, "visible = max(1, height - 2)", "visible = max(1, height - 1)", 1)])
m("N-81b", "R-PE-DEF.81", ["r_pe_def_81_"], [(SH,
  "        self.top, painted = row_window(self.selected, self.top, visible, len(detail))\n        detail = detail[:painted]\n",
  "        _, painted = row_window(self.selected, 0, visible, len(detail))\n        self.top = 0\n        detail = detail[:painted]\n", 1)])
m("N-81c", "R-PE-DEF.81", ["r_pe_def_81_"], [(SH, "#patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }", "#patch_sheet_grid > #patch_sheet_body { height: auto; width: auto; }", 1)])
m("N-97a", "R-PE-DEF.97", ["r_pe_def_97_"], [(DS, '        line.append_text(cell)\n        line.append("│", style=_RULE)\n', '        line.append_text(cell)\n        line.append("│", style=_DIM)\n', 1)])
m("N-97b", "R-PE-DEF.97", ["r_pe_def_97_"], [(DS, "else _ODD_GROUND if odd else None", "else None if odd else None", 1)])
m("N-97c", "R-PE-DEF.97", ["r_pe_def_97_"], [(DS, "ground = _SELECTED_GROUND if selected else", "ground = None if selected else", 1)])
m("N-98a", "R-PE-DEF.98", ["r_pe_def_98_"], [(DS, '_GLYPH_STYLES = {"●": _STAGED_STYLE,', '_GLYPH_STYLES = {"●": "green",', 1)])
m("N-98b", "R-PE-DEF.98", ["r_pe_def_98_"], [(DS, "    return _STAGED_STYLE if row.is_staged else \"\"\n", "    return \"\"\n", 1)])
m("N-99", "R-PE-DEF.99", ["r_pe_def_99_"], [(DS, "_PENDING = PURPLE\n", "_PENDING = HILITE\n", 1)])
m("N-100", "R-PE-DEF.100", ["r_pe_def_100_"], [(DS, "        return _REFUSED_STYLE if refused else _PENDING_STYLE\n", "        return _PENDING_STYLE\n", 1)])
m("N-101", "R-PE-DEF.101", ["r_pe_def_101_"], [(DS, 'glyph = "●" if staged else "◆" if pending else " "', 'glyph = " " if staged else "◆" if pending else " "', 1)])
m("N-102a", "R-PE-DEF.102", ["r_pe_def_102_"], [(DS, "_CHANGED_STYLE if None not in (was, now) and was != now else ink", "_CHANGED_STYLE if masked else ink", 1)])
m("N-102b", "R-PE-DEF.102", ["r_pe_def_102_"], [(DS, '_CHANGED_STYLE = f"{_PENDING_STYLE} underline"', "_CHANGED_STYLE = _PENDING_STYLE", 1)])
m("N-103", "R-PE-DEF.103", ["r_pe_def_103_"], [(DS,
  '    mark.append(glyph, style=_GLYPH_STYLES.get(glyph, ""))\n',
  '    if glyph == "◆":\n        mark.append(" ", style=f"on {_PENDING}")\n    else:\n        mark.append(glyph, style=_GLYPH_STYLES.get(glyph, ""))\n', 1)])
m("N-21", "R-PE-DEF.21", ["r_pe_def_21_"], [(DS, '    return _numeric(decoded.value if row.kind == "number" else decoded.stored)\n', "    return _numeric(decoded.stored)\n", 1)])
m("N-104a", "R-PE-DEF.104", ["r_pe_def_104_"], [
  (DS, "return text[:-1].rjust(_SLOT - 1) + text[-1]", "return text[:-1].ljust(_SLOT - 1) + text[-1]", 1),
  (DS, 'return text.rjust(_SLOT - 1) + " "', 'return text.ljust(_SLOT - 1) + " "', 1)])
m("N-104b", "R-PE-DEF.104", ["r_pe_def_104_"], [(DS, "index = index + 1 if index + 1 <= _TRACK - 2 else index - 1", "index = index + 1", 1)])
m("N-105a", "R-PE-DEF.105", ["r_pe_def_105_"], [(DS, "    if len(text) > 6:\n        text = _exponent_form(x)\n", "    if False:\n        text = _exponent_form(x)\n", 1)])
m("N-105b", "R-PE-DEF.105", ["r_pe_def_105_"], [(DS, "        text = _exponent_form(x)\n    if text[-1:]", '        text = text[:5] + "…"\n    if text[-1:]', 1)])
m("N-106", "R-PE-DEF.106", ["r_pe_def_106_"], [(DS, "if not (isfinite(lower) and isfinite(upper) and upper > lower):", "if not (upper > lower):", 1)])
m("N-114a", "R-PE-DEF.114", ["r_pe_def_114_"], [(DS, "    if not all(_has_position(number, lower, upper) for number, _glyph, _style in marks):", "    if False:", 1)])
m("N-114b", "R-PE-DEF.114", ["r_pe_def_114_"], [(DS, "    if not isfinite(value):\n        return False\n", "    if value != value:\n        return False\n", 1)])
m("N-76", "R-PE-DEF.76", ["r_pe_def_76_"], [(DS, "if not (isfinite(lower) and isfinite(upper) and upper > lower):", "if not (isfinite(lower) and isfinite(upper)):", 1)])
m("N-B17", "R-PE-BENCH.17", ["r_pe_bench_17_"], [(DB, "    limits_text = range_cell(definition.limits.lower, definition.limits.upper)\n",
  '    limits_text = (Text(f"{short_number(definition.limits.lower)} … {short_number(definition.limits.upper)}")\n                   if definition.limits.lower is not None and definition.limits.upper is not None else Text("-"))\n', 1)])
m("N-107a", "R-PE-DEF.107", ["r_pe_def_107_"], [(DS, "line.append_text(_trim(content, cap - 4))", "line.append_text(content)", 1)])
m("N-107b", "R-PE-DEF.107", ["r_pe_def_107_"], [(DS, 'line = Text("  ┊ ", style=_RULE)', 'line = Text("    ", style=_RULE)', 1)])
m("N-107c", "R-PE-DEF.107", ["r_pe_def_107_"], [(DS, '        line.pad_right(cap - line.cell_len)\n        line.stylize_before(f"on {_EXPANDED_GROUND}")\n', '        line.stylize_before(f"on {_EXPANDED_GROUND}")\n        line.pad_right(cap - line.cell_len)\n', 1)])
m("N-B5a", "R-PE-BENCH.5", ["r_pe_bench_5_"], [(DS, "detail(row, preview, width - 4, state,", "detail(row, preview, max(GRID_WIDTH, width) - 4, state,", 1)])
m("N-108", "R-PE-DEF.108", ["r_pe_def_108_"], [(DS, '"number": _scalar_ops("new =", _value_number, _detail_definition),', '"number": _scalar_ops("new =", _value_number, _detail_enum),', 1)])
m("N-33", "R-PE-DEF.33", ["r_pe_def_33_"], [(DS, "    if preview is not None and isinstance(preview.decoded, Decoded):\n        return preview.decoded.stored\n", "    if False:\n        return preview.decoded.stored\n", 1)])
m("N-34", "R-PE-DEF.34", ["r_pe_def_34_"], [(DS, "            if bit % 4 == 0:\n", "            if False:\n", 1)])
m("N-35a", "R-PE-DEF.35", ["r_pe_def_35_"], [(DS, '            line.append(chr(byte) if printable else "·", style=style)\n', "            pass\n", 1)])
m("N-35b", "R-PE-DEF.35", ["r_pe_def_35_"], [(DS, "    for offset in range(0, shown, 16):\n", "    for offset in range(0, shown, 8):\n", 1)])
m("N-109", "R-PE-DEF.109", ["r_pe_def_109_"], [
  (DS, "for high in range(8 * count - 1, -1, -16):", "for high in range(8 * count - 1, -1, -64):", 1),
  (DS, "for bit in range(high, max(-1, high - 16), -1):", "for bit in range(high, max(-1, high - 64), -1):", 1)])
m("N-110", "R-PE-DEF.110", ["r_pe_def_110_"], [(DS, '            else:\n                line.append("   ")\n', "            else:\n                pass\n", 1)])
m("N-111", "R-PE-DEF.111", ["r_pe_def_111_"], [(DS, "printable = byte is not None and 0x20 <= byte <= 0x7E", "printable = byte is not None", 1)])
m("N-112", "R-PE-DEF.112", ["r_pe_def_112_"], [(DS, "inner = min(cap - 2, max([r.cell_len for r in cleaned] + [cell_len(title) + 4]) + 2)", "inner = max([r.cell_len for r in cleaned] + [cell_len(title) + 4]) + 2", 1)])
m("N-115a", "R-PE-DEF.115", ["r_pe_def_115_"], [(DS, "    title = plain(title)\n", "    title = title\n", 1)])
m("N-115b", "R-PE-DEF.115", ["r_pe_def_115_"], [(DS, "    row.plain = plain(row.plain)\n", "    row.plain = row.plain\n", 1)])
m("N-116", "R-PE-DEF.116", ["r_pe_def_116_"], [(DS, "max([r.cell_len for r in cleaned] + [cell_len(title) + 4])", "max([len(r.plain) for r in cleaned] + [len(title) + 4])", 1)])
m("N-117a", "R-PE-DEF.117", ["r_pe_def_117_"], [(DS, "    return (value / 2 - lower / 2) / (upper / 2 - lower / 2)\n", "    return (value - lower) / (upper - lower)\n", 1)])
m("N-117b", "R-PE-DEF.117", ["r_pe_def_117_"], [(DS, '    except OverflowError:\n        return float("inf") if x > 0 else float("-inf")\n', "    except OverflowError:\n        raise\n", 1)])
m("N-113a", "R-PE-DEF.113", ["r_pe_def_113_"], [(PK, '"▽ Pick" if compact', '"Pick" if compact', 1)])
m("N-85", "R-PE-DEF.85", ["r_pe_def_85_"], [
  (WH, '"input, ←→ choose an enum entry, home end scroll the grid to its "\n            "first and last columns, esc returns from the formula input to "', '"input, ←→ choose an enum entry, esc returns from the formula input to "', 1)])
m("N-B11", "R-PE-BENCH.11", ["r_pe_bench_11_"], [(DB, '        current = strip.copy()\n        current.append(f" {count}")\n', '        current = Text(f"{count}")\n', 1)])
m("N-B107", "R-PE-BENCH.107,11", ["r_pe_bench_107_", "r_pe_bench_11_"], [
  (DB, '_BLOCKS = "▁▂▃▄▅▆▇"', '_BLOCKS = "▁▂▃▄▅▆▇█"', 1),
  (DB, "round(t * 6)", "round(t * 7)", 2)])
m("N-B108", "R-PE-BENCH.108", ["r_pe_bench_108_"], [(DB,
  "        t = 0.0 if lo == hi else (total / count - lo) / (hi - lo)\n        line.append(_BLOCKS[round(t * 6)], style=DGRAY)\n",
  "        t = 0.0 if lo == hi else (total / count - lo) / (hi - lo)\n        line.append(_BLOCKS[round(t * 6)], style=ramp_style(ramp_step(total / count, lo, hi)))\n", 1)])
m("N-B36a", "R-PE-BENCH.36", ["r_pe_bench_36_"], [(BS,
  "        width, room = self._detail_geometry()\n        _, rows_shown, cols_shown = canvas_shape(width, grid, state.origin, room)\n",
  "        body = self._body\n        width = body.content_size.width if body is not None and body.content_size.width > 0 else 118\n"
  "        height = body.content_size.height if body is not None and body.content_size.height > 0 else 20\n"
  "        visible = max(1, height - 1)\n        _, rows_shown, cols_shown = canvas_shape(width, grid, state.origin, visible - 1)\n", 1)])
m("N-B36b", "R-PE-BENCH.36", ["r_pe_bench_36_"], [
  (DB, "        origin_row = row - rows_shown + 1\n", "        origin_row = row - rows_shown // 2\n", 1),
  (DB, "        origin_col = col - cols_shown + 1\n", "        origin_col = col - cols_shown // 2\n", 1)])
# the proposed mutants of the integrator's record that are not the same run as a row control above
m("P-113b", "R-PE-DEF.113 (proposed)", ["r_pe_def_113_"], [(CSS, None, "\n#patch_editor_panel #patch_param_bulk_button { display: none; }\n", "append")])
m("P-B5_5", "R-PE-BENCH.5 (proposed)", ["r_pe_bench_5_"], [(DV,
  '    """The selected bench row\'s detail lines, cut to ``room`` and the sheet width."""\n    if room < 1:\n        return []\n',
  '    """The selected bench row\'s detail lines, cut to ``room`` and the sheet width."""\n', 1)])
m("P-81_6", "R-PE-DEF.81/6 (proposed)", ["r_pe_def_81_"], [(SH,
  '    def on_resize(self, event: events.Resize) -> None:\n        """A width-only', '    def _off_resize(self, event: events.Resize) -> None:\n        """A width-only', 1)])
m("P-117_lo", "R-PE-DEF.117/1_3 (proposed)", ["r_pe_def_117_"], [(DS, "max(1, 1 + int(round(pos * (track - 3))))", "max(2, 1 + int(round(pos * (track - 3))))", 1)])
m("P-AT4", "AT-B103-I8B-4 (proposed)", [], [
  (SH, 'Binding("home", "scroll_grid(\'home\')", "Grid start", show=False)', 'Binding("home", "scroll_grid(\'home\')", "Grid start", show=False, priority=True)', 1),
  (SH, 'Binding("end", "scroll_grid(\'end\')", "Grid end", show=False)', 'Binding("end", "scroll_grid(\'end\')", "Grid end", show=False, priority=True)', 1)])

# a row's -k also takes the AT nodes of the increment
AT_K = "at_b103_i8b"


def apply(root, edits):
    lines = []
    for f, old, new, cnt in edits:
        p = os.path.join(root, f)
        with io.open(p, encoding="utf-8", newline="") as h:
            text = h.read()
        if "\r\n" in text:
            old = old.replace("\n", "\r\n") if old else old
            new = new.replace("\n", "\r\n")
        if cnt == "append":
            out = text + new
            lines.append("%s: appended at line %d" % (f, text.count("\n") + 1))
        else:
            if text.count(old) != cnt:
                raise SystemExit("EDIT-MISS %s count=%d expected=%d old=%r" % (f, text.count(old), cnt, old[:60]))
            at = text.index(old)
            lines.append("%s:%d" % (f, text.count("\n", 0, at) + 1))
            out = text.replace(old, new)
        tmp = p + ".m8b.tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="") as h:
            h.write(out)
        os.replace(tmp, p)  # a new inode: the hard-linked pristine file is untouched
    return lines


def env(tag):
    base = os.path.join(S)
    e = {
        "PATH": "/usr/bin:/bin", "HOME": os.path.join(S, "home", "runner" "_iso"),
        "XDG_CONFIG_HOME": os.path.join(S, "x", "config"), "XDG_CACHE_HOME": os.path.join(S, "x", "cache"),
        "XDG_DATA_HOME": os.path.join(S, "x", "data"), "TMPDIR": os.path.join(S, "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8", "PYTHONPATH": ".",
    }
    return e


def run_one(mut, baseline=False):
    mid = "BASELINE-" + mut["id"] if baseline else mut["id"]
    root = os.path.join(S, "m", mid)
    if os.path.isdir(root):
        shutil.rmtree(root)
    subprocess.check_call(["cp", "-al", PRIST, root])
    edits = [] if baseline else mut["edits"]
    where = apply(root, edits)
    ks = list(mut["ks"])
    files = list(FAST)
    if any(k in BW_KS for k in ks):
        files.append(BWF)
    if any(k.startswith("r_pe_bench") for k in ks):
        files += BENCHF
    atk = AT_KS.get(mut["id"])
    if atk:
        files.append(ATF)
        ks = ks + [atk]
    if mut.get("only_at"):
        files, ks = [ATF], [mut["only_at"]]
    if mut.get("only_bw"):
        files, ks = [BWF], list(BW_KS)
    kexpr = " or ".join(ks) if ks else "at_b103_i8b_4_"
    e = env(mid)
    head = ["# mutant %s  rows: %s" % (mid, mut["rows"]), "# edits: %s" % "; ".join(where) if where else "# edits: none (unmutated baseline)",
            "# -k: %s" % kexpr,
            "# uptime: " + subprocess.check_output(["uptime"], text=True).strip()]
    fp = subprocess.run([PY, "-c", "import s19_app;print('s19_app.__file__ =', s19_app.__file__)"], cwd=root, env=e, capture_output=True, text=True)
    head.append(fp.stdout.strip() or fp.stderr.strip())
    cmd = ["timeout", "300", PY, "-m", "pytest", "-p", "no:cacheprovider", "-n", "2", "-q", "-k", kexpr, "-rf", "--no-header"] + files
    head.append("# cmd: " + " ".join(cmd[:11]) + " ... <files>")
    r = subprocess.run(cmd, cwd=root, env=e, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    body = r.stdout + r.stderr
    tail = body.strip().splitlines()[-1] if body.strip() else ""
    failed = sorted(set(re.findall(r"^FAILED (\S+)", body, re.M)))
    with io.open(os.path.join(OUT, mid + ".txt"), "w", encoding="utf-8", newline="\n") as h:
        h.write("\n".join(head) + "\n" + body + "\n# exit=%d\n" % r.returncode)
    shutil.rmtree(root)
    return dict(id=mid, rows=mut["rows"], where=where, rc=r.returncode, tail=tail, failed=failed)


def _main():
    os.makedirs(OUT, exist_ok=True)
    only = sys.argv[1:]
    if only and only[0] == "WIDE":
        for x in M:
            if x["id"] in only[1:]:
                print(run_wide(x))
        return
    results = []
    sel = [x for x in M if not only or x["id"] in only or (only == ["BASELINES"])]
    if only == ["BASELINES"]:
        union = []
        for x in M:
            for k in x["ks"]:
                if k not in union:
                    union.append(k)
        results.append(run_one(dict(id="fast-union", rows="all rows (fast files)", ks=union, edits=[]), baseline=True))
        results.append(run_one(dict(id="bw-union", rows="bw rows", ks=[], edits=[], only_bw=True), baseline=True))
        results.append(run_one(dict(id="at-union", rows="AT 1,2,3,4,9", ks=[], edits=[], only_at="at_b103_i8b_1_ or at_b103_i8b_2_ or at_b103_i8b_3_ or at_b103_i8b_4_ or at_b103_i8b_9_"), baseline=True))
    else:
        for x in sel:
            results.append(run_one(x))
    with io.open(os.path.join(OUT, "results-%d.json" % int(time.time())), "w", encoding="utf-8", newline="\n") as h:
        json.dump(results, h, ensure_ascii=False, indent=1)
    for r in results:
        print(r["id"], r["rc"], "|", r["tail"], "|", ",".join(f.split("::")[-1][:60] for f in r["failed"][:3]))


# ---- wide mode: a survivor of the narrow row selection is re-run against whole files, group by group
WIDE_GROUPS = [
    ("fast+bench", FAST + BENCHF), ("inc8b_bw", [BWF]), ("inc8b_at", [ATF]),
    ("inc8_a2_app", [T + "inc8_a2_app.py"]), ("inc8_at", [T + "inc8_at.py"]),
    ("inc8_p_layout+p_wiring", [T + "inc8_p_layout.py", T + "inc8_p_wiring.py"]),
    ("inc9_w_keys+w_select", [T + "inc9_w_keys.py", T + "inc9_w_select.py"]),
    ("inc9_w_stage+w_mutants", [T + "inc9_w_stage.py", T + "inc9_w_mutants.py"]),
]


def run_wide(mut):
    mid = "W-" + mut["id"]
    root = os.path.join(S, "m", mid)
    if os.path.isdir(root):
        shutil.rmtree(root)
    subprocess.check_call(["cp", "-al", PRIST, root])
    where = apply(root, mut["edits"])
    e = env(mid)
    out = ["# WIDE re-run of mutant %s  rows: %s" % (mut["id"], mut["rows"]), "# edits: " + "; ".join(where),
           "# uptime: " + subprocess.check_output(["uptime"], text=True).strip()]
    fp = subprocess.run([PY, "-c", "import s19_app;print('s19_app.__file__ =', s19_app.__file__)"], cwd=root, env=e, capture_output=True, text=True)
    out.append(fp.stdout.strip())
    verdict, killer = "SURVIVED-WIDE", ""
    for label, files in WIDE_GROUPS:
        cmd = ["timeout", "300", PY, "-m", "pytest", "-p", "no:cacheprovider", "-n", "2", "-q", "-rf", "--no-header"] + files
        r = subprocess.run(cmd, cwd=root, env=e, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        body = r.stdout + r.stderr
        tail = body.strip().splitlines()[-1] if body.strip() else ""
        failed = sorted(set(re.findall(r"^FAILED (\S+)", body, re.M)))
        out.append("## group %s: exit=%d | %s" % (label, r.returncode, tail))
        out += ["   FAILED " + f for f in failed[:8]]
        if r.returncode == 1:
            verdict, killer = "KILLED-WIDE", label + ": " + (failed[0] if failed else tail)
            break
        if r.returncode not in (0,):
            verdict = "INCONCLUSIVE(exit %d in %s)" % (r.returncode, label)
            break
    out.append("# verdict: %s %s" % (verdict, killer))
    with io.open(os.path.join(OUT, mid + ".txt"), "w", encoding="utf-8", newline="\n") as h:
        h.write("\n".join(out) + "\n")
    shutil.rmtree(root)
    return mid, verdict, killer


if __name__ == "__main__":
    _main()
