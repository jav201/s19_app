"""Inc 2a E5 gap probe (batch-103): R-A2L-DEF.149 -- describe time against the size of the sections objects share.

Current code = Inc 2a as merged (`a2l_definition.py` md5 f7fa38a5, branch b103-inc2a-code 82f5f8e5): `_describe_one`
calls `_read_method_record`, `_read_enum_table` and `_resolve_datatype` once per object, each re-reading the shared
COMPU_METHOD, COMPU_VTAB / COMPU_VTAB_RANGE or RECORD_LAYOUT first line (E3S3-13 COMPU part, E3S3-18).
Model = the corrected design of `codewire/graph-inc2.md` (E5 gap pass): one `reads` map per walk, keyed by `id()` of
the COMPU_METHOD / COMPU_VTAB / COMPU_VTAB_RANGE section or of the `record_layouts_by_name` entry; the method record
stored as its 6 fields (read-only mapping, tuple coefficients); the enum table stored once and held by reference;
the layout's resolved datatype (a str or None) stored once. The model replaces the three readers of the REAL module
(module globals, so `_describe_one` calls them); every other line of `describe_definitions` runs as merged.
Negative controls: one kind's stored form switched off (that read per object again), and the current code.
THROWAWAY; read-only. Usage: python -I gap-2a-probe.py scale <tree> <scratch>
                                    python -I gap-2a-probe.py equal <tree> <scratch> <list of .a2l paths> <fixture root>
(<tree> holds a /tmp copy of the integrated tree's `s19_app/` only: /tmp was full -- tmpfs 16 G, 138 MB free -- so the
35 tracked fixtures are read in place from the integrated tree, read-only.)
"""
import gc, pathlib, signal, sys, time, types

MODE, TREE, S = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
sys.path.insert(0, TREE)
import s19_app  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
MP = types.MappingProxyType
SIZES = D.DATATYPE_SIZES
ORIG = {n: getattr(D, n) for n in ("describe_definitions", "_read_method_record", "_read_enum_table",
                                   "_resolve_datatype")}
ST = {"reads": None, "off": frozenset(), "stats": None, "last": None}


# ------------------------------------------------------------------ the model of the corrected design
def m_describe_definitions(names, a2l_data):
    ST["reads"], ST["stats"] = {}, {"method": 0, "table": 0, "layout": 0}   # one map per walk
    try:
        return ORIG["describe_definitions"](names, a2l_data)
    finally:
        ST["last"], ST["reads"] = ST["stats"], None


def m_read_method_record(method_name, compu_methods_by_name):
    section = compu_methods_by_name.get(method_name)
    if section is None:
        return None
    reads, key = ST["reads"], id(section)
    if "method" not in ST["off"] and key in reads:
        return reads[key]
    ST["stats"]["method"] += 1
    r = ORIG["_read_method_record"](method_name, compu_methods_by_name)
    form = MP({"conversion_type": r["conversion_type"], "format": r["format"], "unit": r["unit"],
               "coeffs_linear": None if r["coeffs_linear"] is None else tuple(r["coeffs_linear"]),
               "coeffs": None if r["coeffs"] is None else tuple(r["coeffs"]),
               "compu_tab_ref": r["compu_tab_ref"]})               # 6 fields; no `lines`, `formula`, name, long id
    reads[key] = form
    return form


def m_read_enum_table(table_name, compu_tables_by_name):
    section = compu_tables_by_name.get(table_name)
    if section is None:
        return None
    reads, key = ST["reads"], id(section)
    if "table" not in ST["off"] and key in reads:
        return reads[key]
    ST["stats"]["table"] += 1
    form = ORIG["_read_enum_table"](table_name, compu_tables_by_name)   # (kind, tuple of frozen EnumEntry, default)
    reads[key] = form
    return form


def m_resolve_datatype(tag, a2l_data):
    datatype = tag.get("datatype")
    if datatype in SIZES:
        return datatype
    layouts = a2l_data.get("record_layouts_by_name") or {}
    layout_name = tag.get("record_layout_name") or tag.get("deposit")
    entry = layouts.get(layout_name) if layout_name else None
    if entry is not None:
        reads, key = ST["reads"], id(entry)
        if "layout" not in ST["off"] and key in reads:
            dt = reads[key]
        else:
            ST["stats"]["layout"] += 1
            lay = D._resolve_record_layout(layout_name, layouts)      # the frozen helper, once per layout per walk
            dt = None
            if lay is not None:
                d0 = lay.get("decode_type")
                if d0 and d0 in SIZES and any(t in SIZES for t in (entry.get("tokens") or [])):
                    dt = d0
            reads[key] = dt
        if dt is not None:
            return dt
    upper = str(tag.get("deposit") or "").upper()
    for dt in SIZES:
        if f"__{dt}_Z" in upper or upper == dt:
            return dt
    return None


MODEL = {"describe_definitions": m_describe_definitions, "_read_method_record": m_read_method_record,
         "_read_enum_table": m_read_enum_table, "_resolve_datatype": m_resolve_datatype}


def use(which, off=()):
    for n, f in (MODEL if which == "model" else ORIG).items():
        setattr(D, n, f)
    ST["off"] = frozenset(off)


class Cap(Exception):
    pass


def capped(fn, cap=60.0):
    def h(*_):
        raise Cap()
    old = signal.signal(signal.SIGALRM, h)
    signal.setitimer(signal.ITIMER_REAL, cap)
    try:
        gc.collect(); t0 = time.perf_counter(); r = fn(); return time.perf_counter() - t0, r
    except Cap:
        return None, None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, old)


def least(fn, k, cap=60.0):
    best, res = None, None
    for _ in range(k):
        dt, r = capped(fn, cap)
        if dt is None:
            return None, None
        if best is None or dt < best:
            best, res = dt, r
    return best, res


# ------------------------------------------------------------------ the INLINE files of R-A2L-DEF.149/1 ... /4
def a2l_text(case, kib, n=400):
    target = kib * 1024
    rl = '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
    extra, conv, layout = "", "", "RL_U8"
    if case.startswith("method"):
        fill = (" DEPOSIT ABSOLUTE\n" * (target // 18) if case == "method"
                else "/* " + ("x" * 78 + "\n") * (target // 79) + " */\n")
        extra = '/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n' + fill + '/end COMPU_METHOD\n'
        conv = "CM_L"
    elif case.startswith("vtab"):
        if case == "vtab":
            lines, k, size = [], 0, 0
            while size < target:
                ln = f' {k} "v{k}"\n'; lines.append(ln); size += len(ln); k += 1
            body, m = "".join(lines), k
        else:
            body, m = ' 0 "zero"\n 1 "one"\n' + "/* " + ("x" * 78 + "\n") * (target // 79) + " */\n", 2
        extra = ('/begin COMPU_METHOD CM_V "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
                 f'/begin COMPU_VTAB VT "" TAB_VERB {m}\n' + body + '/end COMPU_VTAB\n')
        conv = "CM_V"
    elif case == "range":
        lines, k, size = [], 0, 0
        while size < target:
            ln = f' {2 * k} {2 * k + 1} "r{k}"\n'; lines.append(ln); size += len(ln); k += 1
        extra = ('/begin COMPU_METHOD CM_R "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VR\n/end COMPU_METHOD\n'
                 f'/begin COMPU_VTAB_RANGE VR "" {k}\n' + "".join(lines) + '/end COMPU_VTAB_RANGE\n')
        conv = "CM_R"
    elif case == "layout":
        extra = ('/begin RECORD_LAYOUT RL_LONG\n FNC_VALUES 1 ' + "X " * (target // 2) + 'UBYTE ROW_DIR DIRECT\n'
                 '/end RECORD_LAYOUT\n')
        conv, layout = "NO_COMPU_METHOD", "RL_LONG"
    objs = "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{0x1000 + i:X} {layout} 0 {conv} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(n))
    return ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
            f'/end MOD_COMMON\n{rl}{extra}{objs}/end MODULE\n/end PROJECT\n')


OFF_OF = {"method": "method", "method-comment": "method", "vtab": "table", "vtab-comment": "table",
          "range": "table", "layout": "layout"}
CASE_ID = {"method": ".149/1", "vtab": ".149/2", "range": ".149/3", "layout": ".149/4",
           "method-comment": "extra (E3S3-13 shape)", "vtab-comment": "extra (E3S3-13 shape)"}


def sig(res):
    return [(d.kind, d.datatype, d.refusal.code if d.refusal else None) for d in res.values()]


def scale():
    W = S / "work"; W.mkdir(parents=True, exist_ok=True)
    verdicts = []
    for case in ("method", "vtab", "range", "layout", "method-comment", "vtab-comment"):
        per = {}
        for kib in (256, 512):
            p = W / f"gap_{case}_{kib}.a2l"
            p.write_text(a2l_text(case, kib), encoding="utf-8")
            t0 = time.perf_counter(); data = parse_a2l_file(p); tp = time.perf_counter() - t0
            names = [t["name"] for t in data["tags"] if t.get("char_type") == "VALUE"]
            assert len(names) == 400, len(names)
            row = {"file_kib": p.stat().st_size / 1024, "parse": tp}
            # model
            use("model")
            ta, res = least(lambda: D.describe_definitions(names, data), 7)
            stats = dict(ST["last"])
            t1, _ = least(lambda: D.describe_definitions(names[:1], data), 7)
            first = D.describe_definition(names[0], data); last = D.describe_definition(names[-1], data)
            fresh_ok = first == res[names[0]] and last == res[names[-1]]
            tuples = len({id(d.enum_entries) for d in res.values()})
            row["model"] = (ta, t1, stats, sig(res), fresh_ok, tuples)
            model_res = res
            # negative control: this case's stored form switched off (read per object again)
            use("model", off=(OFF_OF[case],))
            ta_n, res_n = capped(lambda: D.describe_definitions(names, data), 60.0)
            t1_n, _ = least(lambda: D.describe_definitions(names[:1], data), 3)
            row["neg"] = (ta_n, t1_n, dict(ST["last"]) if ta_n is not None else None)
            # current code (Inc 2a as merged)
            use("cur")
            ta_c, res_c = capped(lambda: D.describe_definitions(names, data), 60.0)
            t1_c, _ = least(lambda: D.describe_definitions(names[:1], data), 3)
            row["cur"] = (ta_c, t1_c, None if res_c is None else (res_c == model_res),
                          None if res_c is None else len({id(d.enum_entries) for d in res_c.values()}))
            per[kib] = row
            del data, res, res_n, res_c, model_res
            gc.collect()
        for kib in (256, 512):
            r = per[kib]
            ta, t1, stats, sg, fresh_ok, tuples = r["model"]
            ta_n, t1_n, st_n = r["neg"]; ta_c, t1_c, eq_c, tup_c = r["cur"]
            fmt = lambda x: "past 60 s cap" if x is None else f"{x:.3f} s"
            print(f"[{case} {kib} KiB] {CASE_ID[case]}: file {r['file_kib']:.0f} KiB, parse {r['parse']:.3f} s | "
                  f"MODEL 400 names {fmt(ta)}, first name {fmt(t1)}, beyond {ta - t1:.4f} s, reads {stats}, "
                  f"first/last == describe_definition alone {fresh_ok}, distinct enum_entries tuples {tuples}, "
                  f"(kind, datatype, refusal) {sorted(set(sg))} | NEG ({OFF_OF[case]} per object) 400 names "
                  f"{fmt(ta_n)}, first {fmt(t1_n)}, reads {st_n} | CURRENT 400 names {fmt(ta_c)}, first {fmt(t1_c)}, "
                  f"result == model {eq_c}, distinct enum_entries tuples {tup_c}", flush=True)
        a, b = per[256], per[512]
        bm = (a["model"][0] - a["model"][1], b["model"][0] - b["model"][1])
        ratio = bm[1] / bm[0] if bm[0] > 0 else float("inf")
        tot = b["model"][0] / a["model"][0]
        same = a["model"][3] == b["model"][3]
        green = a["model"][0] <= 0.5 and ratio <= 1.3 and same and a["model"][4] and b["model"][4]
        out = f"[{case}] MODEL: 256 KiB total {a['model'][0]:.3f} s (bound 0.5 s); beyond the first name " \
              f"{bm[0]:.4f} -> {bm[1]:.4f} s, x{ratio:.2f} (bound 1.3); total x{tot:.2f}; same at both sizes {same}" \
              f" -> {'GREEN' if green else 'RED'}"
        for lab, key in (("NEG", "neg"), ("CURRENT", "cur")):
            ta_a, t1_a = a[key][0], a[key][1]; ta_b, t1_b = b[key][0], b[key][1]
            if ta_a is None:
                out += f" | {lab}: 256 KiB past 60 s cap -> RED"
                continue
            ba = ta_a - t1_a
            if ta_b is None:
                out += f" | {lab}: 256 KiB {ta_a:.2f} s, 512 KiB past 60 s cap -> RED"
                continue
            bb = ta_b - t1_b
            red = ta_a > 0.5 or bb / ba > 1.3
            out += f" | {lab}: 256 KiB {ta_a:.2f} s, beyond {ba:.3f} -> {bb:.3f} s, x{bb / ba:.2f} -> " \
                   f"{'RED' if red else 'GREEN (control did not fail!)'}"
        print(out, flush=True)
        verdicts.append((case, green))
    print("SUMMARY", verdicts, flush=True)


def walk(data):
    stack = list(data.get("sections") or [])
    while stack:
        s = stack.pop(); yield s; stack.extend(s.get("children") or [])


def immut():
    """The stored forms refuse a write (E3S3-14 for 2a's three kinds)."""
    W = S / "work"
    use("model")
    forms = []
    for case in ("method", "vtab", "range", "layout"):
        data = parse_a2l_file(W / f"gap_{case}_256.a2l")
        names = [t["name"] for t in data["tags"] if t.get("char_type") == "VALUE"]
        ST["reads"], ST["stats"] = {}, {"method": 0, "table": 0, "layout": 0}
        ORIG["describe_definitions"](names[:3], data)        # the patched readers fill this walk's map
        forms += [(case, f) for f in ST["reads"].values()]
        ST["reads"] = None
    use("cur")
    out = []
    for case, form in forms:
        kind = type(form).__name__
        tries = []
        if isinstance(form, MP):
            tries = [lambda: form.__setitem__("unit", "x"), lambda: form["coeffs_linear"].__setitem__(0, 9.0)]
        elif isinstance(form, tuple):
            tries = [lambda: form[1].append(None), lambda: setattr(form[1][0], "text", "x")]
        elif form is None or isinstance(form, str):
            tries = []                                   # a str / None is immutable by type
        refused = 0
        for t in tries:
            try:
                t()
            except (TypeError, AttributeError):
                refused += 1
        out.append((case, kind, f"{refused}/{len(tries)} writes refused"))
    print("[immutable] stored forms refuse a write:", out, flush=True)


def equal(listfile, root):
    paths = [ln.strip() for ln in pathlib.Path(listfile).read_text().splitlines() if ln.strip()]
    tot_defs = tot_diff = 0
    for rel in paths:
        p = pathlib.Path(root) / rel                     # fixtures read in place, read-only
        t0 = time.perf_counter(); data = parse_a2l_file(p); tp = time.perf_counter() - t0
        names = list(dict.fromkeys(t["name"] for t in data["tags"]))
        use("cur"); t0 = time.perf_counter(); cur = D.describe_definitions(names, data); tc = time.perf_counter() - t0
        use("model"); t0 = time.perf_counter(); mod = D.describe_definitions(names, data); tm = time.perf_counter() - t0
        st = dict(ST["last"])
        diff = sum(1 for n in names if cur[n] != mod[n])
        n_meth = sum(1 for s in walk(data) if s.get("name") == "COMPU_METHOD")
        n_tab = sum(1 for s in walk(data) if s.get("name") in ("COMPU_VTAB", "COMPU_VTAB_RANGE"))
        n_rl = len(data.get("record_layouts_by_name") or {})
        tot_defs += len(names); tot_diff += diff
        print(f"[equal] {rel}: {len(names)} names, parse {tp:.2f} s, current {tc:.3f} s, model {tm:.3f} s, "
              f"differences {diff}; model reads {st} (sections: {n_meth} COMPU_METHOD, {n_tab} tables, "
              f"{n_rl} layouts)", flush=True)
        del data, cur, mod
        gc.collect()
    use("cur")
    print(f"[equal] TOTAL {len(paths)} files, {tot_defs} definitions, {tot_diff} differences", flush=True)


if MODE == "scale":
    scale()
    immut()
elif MODE == "immut":          # the immutability check alone, on the files `scale` wrote
    immut()
elif MODE == "equal":
    equal(sys.argv[4], sys.argv[5])
