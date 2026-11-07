"""E3 round-6 census (read-only, derived counts only): (a) COMPU_TABs a TAB_INTP / TAB_NOINTP method names that hold a
non-numeric y, and the case points at which the frozen lookup returns text (display_text then raises); (b) a plain
bisect over COMPU_VTAB_RANGE ranges sorted by their min (the last range whose min <= v, then its max) against Inc 2a's
first-in-file-order lookup. Usage: python -I -B sec-r6-census.py <inc2a tree> <lists>..."""
import bisect, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402
from concurrent.futures import ProcessPoolExecutor


def one(p):
    try:
        data = a.parse_a2l_file(pathlib.Path(p))
    except Exception as ex:
        return {"error": type(ex).__name__}
    tabs = data.get("compu_tabs_by_name") or {}
    out = {"named": 0, "named_str": 0, "str_points": 0, "points": 0, "ranges": 0, "naive_diff_tables": 0,
           "naive_diffs": 0, "range_points": 0}
    for cm in (data.get("compu_methods_by_name") or {}).values():
        t = str(cm.get("conversion_type") or "").upper()
        tab = tabs.get(cm.get("compu_tab_ref") or "")
        if t not in ("TAB_INTP", "TAB_NOINTP") or not tab or not tab.get("entries"):
            continue
        out["named"] += 1
        ents = tab["entries"]
        out["named_str"] += any(not isinstance(e[1], (int, float)) for e in ents)
        xs = [e[0] for e in ents]
        vals = set(xs) | {xs[j] + (xs[j + 1] - xs[j]) / 4 for j in range(len(xs) - 1)} | {xs[0] - 1, xs[-1] + 1}
        for v in vals:
            out["points"] += 1
            r = a._table_lookup(v, tab, t == "TAB_INTP")
            out["str_points"] += isinstance(r[0], str)
    ct = {}

    def w(nodes):
        for n in nodes:
            if n.get("name") == "COMPU_VTAB_RANGE":
                ct.setdefault(a.parse_begin_meta(n.get("meta", "") or "")[0], n)
            w(n.get("children") or [])
    w(data.get("sections") or [])
    for name in ct:
        tab = D._read_enum_table(name, ct)
        if not tab or not tab[1]:
            continue
        out["ranges"] += 1
        rs = sorted(range(len(tab[1])), key=lambda i: tab[1][i].raw)
        mins = [tab[1][i].raw for i in rs]
        d = D.Definition(**{**{f.name: None for f in __import__("dataclasses").fields(D.Definition)},
                            "enum_entries": tab[1], "name": "x"})
        diffs = 0
        for e in tab[1]:
            for v in (e.raw, e.raw_max, (e.raw + e.raw_max) / 2):
                out["range_points"] += 1
                j = bisect.bisect_right(mins, v) - 1
                naive = tab[1][rs[j]].text if j >= 0 and v <= tab[1][rs[j]].raw_max else None
                diffs += naive != D._enum_entry_text(d, v)
        out["naive_diffs"] += diffs
        out["naive_diff_tables"] += diffs > 0
    return out


files = [ln.strip() for lf in sys.argv[2:] for ln in open(lf) if ln.strip()]
with ProcessPoolExecutor(8) as ex:
    res = [r for r in ex.map(one, files)]
ok = [r for r in res if "error" not in r]
s = lambda k: sum(r[k] for r in ok)
print(f"[C] files {len(files)}, errors {len(res) - len(ok)}; COMPU_TABs named by a TAB_INTP / TAB_NOINTP method "
      f"{s('named')}, with a non-numeric y {s('named_str')}; case points {s('points')}, at which the frozen lookup "
      f"returns text {s('str_points')}", flush=True)
print(f"[C] COMPU_VTAB_RANGE tables {s('ranges')}; a plain bisect on the ranges sorted by min differs from the "
      f"first-in-file-order lookup on {s('naive_diffs')} of {s('range_points')} points, in {s('naive_diff_tables')} tables",
      flush=True)
