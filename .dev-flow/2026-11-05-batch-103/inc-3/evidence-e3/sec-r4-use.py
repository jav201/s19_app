"""E3 round-4 security probe, Inc 3a (batch-103): the per-object USE of a read form read once per walk.
[U] ALIGNMENT lines: a RECORD_LAYOUT's own (`_place_components` per object, `_check_module_alignment`) and a
    MOD_COMMON's (`_check_module_alignment` per object and per COM axis object) -- graph-literal read forms keep
    every ALIGNMENT pair, so each object's placement walks all of them; frozen parse cost for comparison.
[R] the fix model: each read form keeps one ALIGNMENT entry per class (the frozen walker's last-wins; for
    MOD_COMMON the first unreadable word in file order, R-A2L-DEF.144) -- timing, and equality with the
    graph-literal reading over the 35 fixtures and 168 public files (worker per file).
[F] Inc 2a's `_resolve_datatype`: the layout's first-line tokens scanned per object (VAL_BLK: the parse does not;
    the frozen enrich with an image does).
THROWAWAY; read-only. Usage: sec-r4-use.py main <tree> <scratch> | corpus <tree> <scratch> <list>... |
       worker <tree> <scratch> <file>
"""
import gc, importlib.util, json, os, pathlib, subprocess, sys, time

MODE, TREE, S = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
B, R3, MP = m.B, m.R3, m.MP
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- the fix model: one ALIGNMENT entry per class
REDUCE = {"on": False}
_orig_freeze, _orig_modc, _orig_check = m._freeze_layout, m.module_common, m.check_module_alignment


def freeze_reduced(r):
    f = _orig_freeze(r)
    if isinstance(f, tuple) or not REDUCE["on"]:
        return f
    last = {}
    for w in f["alignment"]:                      # every kept layout ALIGNMENT number is valid (else a part)
        last[w[0]] = w
    return MP({**f, "alignment": tuple(last.values())})


def modc_reduced(section, maps):
    if not REDUCE["on"]:
        return _orig_modc(section, maps)
    mc = maps["mod_common_of"].get(id(section))
    if mc is None:
        return None
    reads = maps["reads"]
    if id(mc) not in reads:
        maps["stats"]["modc_reads"] += 1
        per = {}
        for i, w in enumerate(w for w in B.clean_lines(mc.get("lines")) if w and w[0] in B.ALIGN_WORDS):
            word = w[1] if len(w) > 1 else None
            n = B.whole(word) if word is not None else None
            e = per.setdefault(w[0], {"bad": None, "last": None})
            if n is None or n < 1:
                if e["bad"] is None:
                    e["bad"] = (i, word if word is not None else "(none)")
            else:
                e["last"] = word
        reads[id(mc)] = MP({"per_class": MP({k: MP(v) for k, v in per.items()}),
                            "byte_order": a._byte_order_from_section_lines(mc.get("lines") or [])})
    return reads[id(mc)]


def check_reduced(layout, counts, mcr, maps=None):
    if not REDUCE["on"]:
        return _orig_check(layout, counts, mcr, maps)
    if mcr is None:
        return None
    declared = {w[0] for w in layout["alignment"]}
    classes = {B.ALIGN_CLASS.get(c[2]) for c in layout["components"] if len(c) > 2}
    rel = [(k, v) for k, v in mcr["per_class"].items() if k not in declared and k in classes]
    bads = sorted((v["bad"][0], k, v["bad"][1]) for k, v in rel if v["bad"] is not None)
    if bads:
        return (bads[0][1], bads[0][2])
    extra = [(k, v["last"]) for k, v in rel if v["last"] is not None]
    if not extra:
        return None
    own = B.place_components(layout, counts)
    moved = B.place_components(layout, counts, extra)
    if own is not None and moved is not None:
        for c in layout["components"]:
            if own[0][c[0]] != moved[0][c[0]]:
                return (c[0], own[0][c[0]], moved[0][c[0]])
    return None


m._freeze_layout = freeze_reduced
m.module_common = R3.module_common = modc_reduced
m.check_module_alignment = R3.check_module_alignment = check_reduced

HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
TAIL = "/end MODULE\n/end PROJECT\n"
KB = 256
ALIGN_B = "ALIGNMENT_BYTE 1\n" * (KB * 1024 // 17)


def parse(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    t0 = time.perf_counter(); data = a.parse_a2l_file(p); tp = time.perf_counter() - t0
    return data, tp, p.stat().st_size


def timed(fn):
    gc.collect(); t0 = time.perf_counter(); r = fn(); return r, time.perf_counter() - t0


def texts(kind, n):
    mc_fill = ALIGN_B if kind in ("modcommon", "modcommon-com") else ""
    mc = f'/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n{mc_fill}/end MOD_COMMON\n'
    if kind == "layout":
        rl = "/begin RECORD_LAYOUT RL\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n" + ALIGN_B + "/end RECORD_LAYOUT\n"
        objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} RL 0 NO_COMPU_METHOD 0 255\n'
                       f' NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))
    elif kind == "layout-curve":
        rl = ("/begin RECORD_LAYOUT RL\n AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n"
              + ALIGN_B + "/end RECORD_LAYOUT\n")
        objs = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL 0 NO_COMPU_METHOD 0 255\n'
                       f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 4 0 255\n /end AXIS_DESCR\n'
                       f'/end CHARACTERISTIC\n' for i in range(n))
    elif kind == "modcommon":
        rl = "/begin RECORD_LAYOUT RL\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} RL 0 NO_COMPU_METHOD 0 255\n'
                       f' NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))
    elif kind == "modcommon-com":       # the COM path: each referencing axis checks the axis object's layout too
        rl = ('/begin RECORD_LAYOUT RL\n FNC_VALUES 1 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
              '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
              '/end RECORD_LAYOUT\n/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 NO_COMPU_METHOD 4 0 255\n'
              '/end AXIS_PTS\n')
        objs = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL 0 NO_COMPU_METHOD 0 255\n'
                       f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 4 0 255\n  AXIS_PTS_REF AXO\n'
                       f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(n))
    return HEAD + mc + rl + objs + TAIL


def main():
    print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
          sys.version.split()[0], flush=True)
    for kind in ("layout", "modcommon", "modcommon-com", "layout-curve"):
        for n in (100, 400, 1600):
            data, tp, size = parse(f"use_{kind}_{n}", texts(kind, n))
            names = [t["name"] for t in data["tags"]]
            _, t2a = timed(lambda: m.describe_e5(names, data))
            row = []
            for red in (False, True):
                REDUCE["on"] = red
                if n == 1600 and not red and kind != "layout-curve":
                    row.append(None); continue
                (res, maps), t3a = timed(lambda: m.describe_all(data))
                refs = {}
                for v in res.values():
                    refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
                row.append((t3a, refs, {k: v for k, v in maps["stats"].items() if v and k != "conv_calls"}))
            REDUCE["on"] = False
            lit = (f"graph-literal 3a {row[0][0]:.3f} s ({row[0][0] / n * 1e3:.2f} ms/object) {row[0][1]}"
                   if row[0] else "graph-literal not run")
            print(f"[U-{kind}] n={n}: file {size / 1024:.0f} KiB, frozen parse {tp:.3f} s ({tp / n * 1e3:.2f} ms/object); "
                  f"Inc 2a describe {t2a:.3f} s; {lit}; one entry per class {row[1][0]:.3f} s {row[1][1]}; "
                  f"reads {row[1][2]}", flush=True)
    # [F] Inc 2a's _resolve_datatype on VAL_BLKs (3a's kinds): parse, frozen enrich with an image, 2a describe
    junk = " ".join("X" for _ in range(KB * 1024 // 2))
    for n in (100, 400):
        rl = f"/begin RECORD_LAYOUT RL_LONG\n FNC_VALUES 1 {junk} UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} RL_LONG 0 NO_COMPU_METHOD '
                       f'0 255\n NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))
        data, tp, size = parse(f"first_vb_{n}", HEAD + '/begin MOD_COMMON ""\n/end MOD_COMMON\n' + rl + objs + TAIL)
        names = [t["name"] for t in data["tags"]]
        _, t2a = timed(lambda: m.describe_e5(names, data))
        image = {0x1000 + k: 1 for k in range(16 * n)}
        _, te = timed(lambda: a.enrich_a2l_tags_with_values(data, image))
        (res, _), t3a = timed(lambda: m.describe_all(data))
        refs = {}
        for v in res.values():
            refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
        print(f"[F] {n} VAL_BLKs sharing RL_LONG (first line {KB} KiB, datatype word last): file {size / 1024:.0f} KiB; "
              f"frozen parse {tp:.3f} s; frozen enrich_a2l_tags_with_values with an image {te:.3f} s; Inc 2a "
              f"describe_definitions {t2a:.3f} s ({t2a / n * 1e3:.2f} ms/object); 3a reads {t3a:.3f} s {refs}", flush=True)


# ---------------------------------------------------------------- [R] equality of the fix model over real files
def worker(path):
    rec = {"file": os.path.basename(path)}
    t0 = time.perf_counter()
    try:
        data = a.parse_a2l_file(pathlib.Path(path))
        out = {}
        for red in (False, True):
            REDUCE["on"] = red
            res, maps = m.describe_all(data)
            out[red] = {k: m.public(v) for k, v in res.items()}
        REDUCE["on"] = False
        diff = [k for k in out[False] if out[False][k] != out[True].get(k)]
        al = sum(1 for v in out[False].values() if v[0] == "A2L-DEF-ALIGNMENT")
        rec.update(objects=len(out[False]), diff=len(diff), ex=diff[:2], alignment_refusals=al)
    except Exception as e:  # noqa: BLE001
        rec["exception"] = f"{type(e).__name__}: {str(e)[:160]}"
    rec["s"] = round(time.perf_counter() - t0, 2)
    print(json.dumps(rec))


def corpus(lists):
    files = [ln.strip() for lf in lists for ln in open(lf) if ln.strip()]
    from concurrent.futures import ThreadPoolExecutor

    def one(f):
        try:
            p = subprocess.run([sys.executable, "-I", __file__, "worker", TREE, str(S), f], capture_output=True,
                               text=True, timeout=1200, stdin=subprocess.DEVNULL)
            line = (p.stdout.strip().splitlines() or [""])[-1]
            return json.loads(line) if line.startswith("{") else {"file": os.path.basename(f), "worker_error":
                                                                  (p.stderr.strip().splitlines() or ["?"])[-1][:200]}
        except subprocess.TimeoutExpired:
            return {"file": os.path.basename(f), "worker_error": "timeout"}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(one, files))
    errs = [r for r in res if "worker_error" in r or "exception" in r]
    print(f"[R] files {len(files)}, errors {len(errs)}, objects {sum(r.get('objects', 0) for r in res)}, "
          f"A2L-DEF-ALIGNMENT refusals {sum(r.get('alignment_refusals', 0) for r in res)}, objects differing between "
          f"every-pair and one-entry-per-class read forms {sum(r.get('diff', 0) for r in res)}, wall "
          f"{time.perf_counter() - t0:.0f} s", flush=True)
    for e in errs[:5]:
        print("   ERR", e)
    for r in res:
        if r.get("diff"):
            print("   DIFF", r)


if MODE == "main":
    main()
elif MODE == "worker":
    worker(sys.argv[4])
else:
    corpus(sys.argv[4:])
