"""E3 round-4 security probe, Inc 3a (batch-103): E3S3-14 as corrected -- can anything change a cached read form?
[I1] every read form `maps["reads"]` holds after one walk (V171, the round-3 P1 ... P5 shapes, a TAB_VERB file):
     its type, and every mutation tried on it and on each value inside (setitem, delitem, append, extend, setattr).
[I2] Inc 2a's real Definitions (V171, software_a; describe memoised once per walk = 2a's E5): any mutable container
     reachable from a field; hash(), deepcopy, pickle; shared enum_entries across objects.
[I3] the decode paths on the shared forms: Inc 2a's decode_definition / display_text / _enum_text over every
     definition, a2l._apply_compu_method (TAB_INTP / TAB_NOINTP through compu_tabs_by_name), the model's
     _fixed_points on every FIX rule -- digests of a2l_data, the definitions and the read forms before and after.
[D] (outside round-4 scope) per-element decode cost against the size of a shared table: Inc 2a's _enum_text and the
     frozen _table_lookup, per call, for tables of 1,000 ... 100,000 entries.
THROWAWAY; read-only. Usage: python -I sec-r4-immut.py <tree> <scratch> <fixtures list>
"""
import copy, dataclasses, gc, hashlib, importlib.util, pathlib, pickle, sys, time, types
from collections.abc import Mapping

TREE, S, FIX = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
B, R3 = m.B, m.R3
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
files = {pathlib.Path(p.strip()).name: p.strip() for p in open(FIX) if p.strip()}


def parse_text(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    return a.parse_a2l_file(p)


def digest_obj(o):
    return hashlib.sha256(pickle.dumps(o, protocol=4)).hexdigest()[:16]


def plain(o):
    """A picklable deep copy of a read form (MappingProxyType -> dict) for digests."""
    if isinstance(o, (types.MappingProxyType, dict)):
        return {k: plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return type(o)(plain(v) for v in o)
    return o


MUTABLE = (list, dict, set, bytearray)


def mutations(form):
    """Try every mutation on the form and on each value inside; return the ones that SUCCEED (then undone)."""
    ok = []

    def attempt(label, fn, undo=None):
        try:
            fn()
        except Exception:  # noqa: BLE001
            return
        ok.append(label)
        if undo:
            undo()

    if isinstance(form, (types.MappingProxyType, dict)):
        attempt("form[new] = 1", lambda: form.__setitem__("__x", 1), lambda: form.__delitem__("__x"))
        for k, v in list(form.items()):
            attempt(f"del form[{k!r}]", lambda k=k: form.__delitem__(k), lambda k=k, v=v: form.__setitem__(k, v))
            if isinstance(v, list):
                attempt(f"form[{k!r}].append", lambda v=v: v.append("__x"), lambda v=v: v.pop())
            if isinstance(v, dict):
                attempt(f"form[{k!r}][new] = 1", lambda v=v: v.__setitem__("__x", 1), lambda v=v: v.pop("__x"))
            if isinstance(v, types.MappingProxyType):
                attempt(f"form[{k!r}][new] = 1", lambda v=v: v.__setitem__("__x", 1))
            if isinstance(v, tuple):
                for i, x in enumerate(v):
                    if isinstance(x, MUTABLE):
                        ok.append(f"form[{k!r}][{i}] is a {type(x).__name__}")
    elif isinstance(form, tuple):
        attempt("form.append", lambda: form.append(1))
        for i, x in enumerate(form):
            if isinstance(x, MUTABLE):
                ok.append(f"form[{i}] is a {type(x).__name__}")
            if isinstance(x, tuple):
                for j, y in enumerate(x):
                    if dataclasses.is_dataclass(y):
                        attempt(f"form[{i}][{j}].text = 'x'", lambda y=y: object.__setattr__(y, "text", y.text)
                                if False else setattr(y, "text", "x"))
    return ok


def kind_of(form):
    if isinstance(form, types.MappingProxyType):
        keys = set(form)
        return ("layout" if "components" in keys else "mod_common" if "alignment" in keys
                else "method record" if "conversion_type" in keys else "mapping")
    if isinstance(form, tuple) and len(form) == 3 and form[0] in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
        return "enum table"
    if isinstance(form, tuple):
        return "refusal (layout)"
    return type(form).__name__


ENUM_TXT = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n/end MOD_COMMON\n'
            '/begin RECORD_LAYOUT RL_C\n AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n'
            '/end RECORD_LAYOUT\n/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
            '/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n/end COMPU_METHOD\n'
            '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n/end COMPU_VTAB\n'
            + "".join(f'/begin CHARACTERISTIC C{i} ""\n CURVE 0x{0x100 + 16 * i:X} RL_C 0 {cm} 0 255\n /begin AXIS_DESCR\n'
                      f'  STD_AXIS NO_INPUT_QUANTITY {cm} 4 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n'
                      for i, cm in enumerate(("CM_V", "CM_V", "CM_L", "CM_L")))
            + '/end MODULE\n/end PROJECT\n')

src = (S / "sec-r3-poison.py").read_text()
ns = {}
exec(compile(src[src.index("INLINE = {"):src.index("def inline(")], "poison", "exec"), ns)
inputs = {"V171": a.parse_a2l_file(pathlib.Path(files["ASAP2_Demo_V171.a2l"])), "TAB_VERB curves": parse_text("im_enum", ENUM_TXT)}
for k, (body, mc) in ns["INLINE"].items():
    inputs[k[:2]] = parse_text(f"im_{k[:2]}", f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
                               f'/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n{mc}\n/end MOD_COMMON\n{body}/end MODULE\n'
                               f'/end PROJECT\n')
inputs["P3"] = parse_text("im_P3", ns["P3"])

# ---------------------------------------------------------------- [I1]
tally = {}
for label, data in inputs.items():
    res, maps = m.describe_all(data)
    for key, form in maps["reads"].items():
        kd = kind_of(form)
        t = tally.setdefault(kd, {"forms": 0, "mutable": {}})
        t["forms"] += 1
        for okm in mutations(form):
            t["mutable"][okm] = t["mutable"].get(okm, 0) + 1
    for h in maps["axis_pts_hdr"].values():
        t = tally.setdefault("AXIS_PTS header", {"forms": 0, "mutable": {}})
        t["forms"] += 1
        for okm in mutations(h):
            t["mutable"][okm] = t["mutable"].get(okm, 0) + 1
    for bo in maps["axo_bo"].values():
        t = tally.setdefault("axis object byte order", {"forms": 0, "mutable": {}})
        t["forms"] += 1
        if not isinstance(bo, str):
            t["mutable"]["not a str"] = t["mutable"].get("not a str", 0) + 1
for kd, t in sorted(tally.items()):
    print(f"[I1] {kd}: {t['forms']} stored forms; mutations that succeed: {t['mutable'] or 'none'}", flush=True)

data = inputs["TAB_VERB curves"]
res, maps = m.describe_all(data)
cm = maps["cm_by_name"]["CM_V"]
rec = maps["reads"][id(cm)]
print(f"[I1] the stored CM_V record: keys {sorted(rec)}; type(rec['lines']) {type(rec['lines']).__name__}; "
      f"rec['lines'] is the parse payload's own list: {rec['lines'] is cm['lines']}", flush=True)
before = list(cm["lines"])
rec["lines"].append(" COMPU_TAB_REF VT_GONE")
fresh = D._read_method_record("CM_V", {"CM_V": cm})
print(f"[I1] after rec['lines'].append(...) through the stored record: the payload's section lines grew "
      f"{len(before)} -> {len(cm['lines'])}; a fresh read of CM_V now gives compu_tab_ref {fresh['compu_tab_ref']!r} "
      f"(was 'VT'); the cached record still says {rec['compu_tab_ref']!r}", flush=True)
cm["lines"][:] = before

# ---------------------------------------------------------------- [I2]
for fname in ("ASAP2_Demo_V171.a2l", "software_a.a2l"):
    if fname not in files:
        continue
    data = a.parse_a2l_file(pathlib.Path(files[fname]))
    names = [t["name"] for t in data["tags"]]
    defs = m.describe_e5(names, data)
    found = {}

    def walk(o, path, depth=0):
        if depth > 6:
            return
        if isinstance(o, MUTABLE + (types.MappingProxyType,)):
            found[path] = found.get(path, 0) + 1
            return
        if dataclasses.is_dataclass(o):
            for f in dataclasses.fields(o):
                walk(getattr(o, f.name), f"{path}.{f.name}", depth + 1)
        elif isinstance(o, tuple):
            for x in o:
                walk(x, f"{path}[]", depth + 1)

    unhash = 0
    for d in defs.values():
        walk(d, "Definition")
        try:
            hash(d)
        except TypeError:
            unhash += 1
    copy.deepcopy(list(defs.values())); pickle.dumps(list(defs.values()))
    share = {}
    for d in defs.values():
        if d.enum_entries:
            share.setdefault(d.enum_table, set()).add(id(d.enum_entries))
    multi = sum(1 for v in share.values() if len(v) > 1)
    print(f"[I2] {fname}: {len(defs)} definitions; mutable containers reachable from a field: {found or 'none'}; "
          f"unhashable {unhash}; deepcopy and pickle ok; enum tables shared by >1 object {len(share)}, of which "
          f"with more than one tuple {multi} (read once: one tuple per table)", flush=True)

# ---------------------------------------------------------------- [I3]


class AllOnes(Mapping):
    def __getitem__(self, k):
        return 0x01

    def __contains__(self, k):
        return isinstance(k, int) and 0 <= k <= 0xFFFFFFFF

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


img = AllOnes()
for label in ("V171", "TAB_VERB curves", "P2", "P5"):
    data = inputs[label]
    names = [t["name"] for t in data["tags"]]
    m.STATS.clear()
    defs = m.describe_e5(names, data)
    res, maps = m.describe_all(data)
    d0 = (digest_obj(data), digest_obj(list(defs.values())), digest_obj({k: plain(v) for k, v in maps["reads"].items()}),
          digest_obj(plain(maps["axis_pts_hdr"])))
    n_dec = n_err = n_fix = 0
    for d in defs.values():
        r = D.decode_definition(d, data, img)
        n_dec += 1
        if isinstance(r, D.Decoded) and isinstance(r.stored, (int, float)) and d.kind in ("number", "enum"):
            D.display_text(d, r.value if isinstance(r.value, (int, float)) else r.stored)
            if d.kind == "enum":
                D._enum_text(d, r.stored)
        elif not isinstance(r, (D.Decoded, D.Refusal)):
            n_err += 1
    tabs = [d for d in defs.values() if d.conversion_type in ("TAB_INTP", "TAB_NOINTP")]
    for d in tabs:
        for v in (0, 1, 1e9):
            a._apply_compu_method(v, {"conversion_type": d.conversion_type, "compu_tab_ref": d.compu_tab_ref},
                                  data.get("compu_tabs_by_name") or {})
    for v in res.values():
        for ax in v.get("axes") or []:
            if ax.get("fixed_rule"):
                pts = R3.fixed_points(ax["fixed_rule"])
                n_fix += 1
                assert isinstance(pts, tuple)
    d1 = (digest_obj(data), digest_obj(list(defs.values())), digest_obj({k: plain(v) for k, v in maps["reads"].items()}),
          digest_obj(plain(maps["axis_pts_hdr"])))
    print(f"[I3] {label}: {n_dec} decode_definition (+ display_text / _enum_text), {len(tabs)} TAB objects x 3 "
          f"_apply_compu_method, {n_fix} _fixed_points; digests a2l_data / definitions / read forms / headers "
          f"unchanged: {[x == y for x, y in zip(d0, d1)]}; unexpected results {n_err}", flush=True)

# ---------------------------------------------------------------- [D] outside scope: per-element cost vs table size
base = next(iter(m.describe_e5(["C0"], inputs["TAB_VERB curves"]).values()))
for n in (1_000, 10_000, 100_000):
    ent = tuple(D.EnumEntry(float(1000 + k), None, f"t{k}") for k in range(n))
    d = dataclasses.replace(base, kind="enum", enum_entries=ent, default_text=None, refusal=None)
    reps = max(3, 200_000 // n)
    t0 = time.perf_counter()
    for _ in range(reps):
        D._enum_text(d, 7)
    te = (time.perf_counter() - t0) / reps
    tab = {"entries": [(float(k), float(k)) for k in range(n)]}
    t0 = time.perf_counter()
    for _ in range(reps):
        a._table_lookup(n - 1.5, tab, True)
    ti = (time.perf_counter() - t0) / reps
    t0 = time.perf_counter()
    for _ in range(reps):
        a._table_lookup(n + 0.25 - n, tab, False) if False else a._table_lookup(0.5, tab, False)
    tn = (time.perf_counter() - t0) / reps
    print(f"[D] table of {n} entries: _enum_text (no entry matches) {te * 1e6:.0f} us per element, _table_lookup "
          f"TAB_INTP (last interval) {ti * 1e6:.0f} us, TAB_NOINTP (no exact entry) {tn * 1e6:.0f} us; a 1,048,576-"
          f"element array therefore ~{te * 1048576 / 3600:.2f} h / {ti * 1048576 / 3600:.2f} h / "
          f"{tn * 1048576 / 3600:.2f} h", flush=True)
