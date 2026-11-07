"""E3 round-3 security probe, Inc 3a (batch-103): can the once-per-walk `maps["reads"]` (E3S3-11) be poisoned --
one object's read or refusal changing another object's definition?

The graph's reading (owner-free read form, `<name>` put in at use; the alignment check run per object on the
MOD_COMMON read form) is modelled as MUTANT None. Three implementation slips the cache makes possible are modelled
as mutants (they were harmless in the round-2 graph, where every call re-read its section):
  owner-leak  -- the first object's refusal message is cached with its name;
  mutate      -- `_check_module_alignment` adds the MOD_COMMON lines to the cached layout in place;
  cache-check -- the alignment verdict is cached per layout, not per object (its shape differs).
Oracle: `describe_definitions` in one walk (tag order, and reversed) must equal `describe_definition` per name
(a fresh walk). Part `inline`: five INLINE3 shapes. Part `corpus`: the same oracle over real files, to see whether
any tracked fixture (and so any case on it) would expose a mutant.
THROWAWAY; read-only. Usage: sec-r3-poison.py inline <tree> <scratch> | corpus <tree> <scratch> <list>... |
       worker <tree> <scratch> <file>
"""
import importlib.util, json, os, pathlib, subprocess, sys, time

MUTANTS = (None, "owner-leak", "mutate", "cache-check")


def load(tree, scratch):
    sys.path.insert(0, tree)
    import s19_app.tui.a2l as a
    spec = importlib.util.spec_from_file_location("m3r3", str(pathlib.Path(scratch) / "sec-r3-m3a.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
    return a, m


def oracle(a, m, data):
    """{mutant: (objects differing from the fresh per-name describe, forward / reversed, examples)}"""
    base = m.new_maps(data)
    secs = m.object_sections(data)
    tags = {}
    for t in data.get("tags") or []:
        tags.setdefault(t.get("name"), t)
    names = [nm for nm in tags if len(secs.get(nm) or []) == 1 and m.is_array_kind(tags[nm], secs[nm][0])]

    def fresh_maps():
        mp = dict(base)
        mp["reads"], mp["axo_bo"] = {}, {}
        mp["stats"] = {k: 0 for k in base["stats"]}
        return mp

    m.MUTANT = None
    ref = {nm: m.public(m.describe_array(tags[nm], secs[nm][0], data, fresh_maps())) for nm in names}
    out = {}
    for mu in MUTANTS:
        m.MUTANT = mu
        row = []
        for order in (names, names[::-1]):
            mp = fresh_maps()
            got = {nm: m.public(m.describe_array(tags[nm], secs[nm][0], data, mp)) for nm in order}
            diff = [nm for nm in names if got[nm] != ref[nm]]
            ex = [(nm, ref[nm][:2] + ref[nm][5:6], got[nm][:2] + got[nm][5:6]) for nm in diff[:3]]
            row.append((len(diff), ex))
        out[str(mu)] = row
    m.MUTANT = None
    return len(names), out


INLINE = {
    "P1 two VAL_BLKs share RL_BAD (a RESERVED part)": (
        '/begin RECORD_LAYOUT RL_BAD\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n RESERVED 2 BYTE\n/end RECORD_LAYOUT\n'
        '/begin CHARACTERISTIC VA ""\n VAL_BLK 0x100 RL_BAD 0 NO_COMPU_METHOD 0 255\n NUMBER 4\n/end CHARACTERISTIC\n'
        '/begin CHARACTERISTIC VB ""\n VAL_BLK 0x200 RL_BAD 0 NO_COMPU_METHOD 0 255\n NUMBER 4\n/end CHARACTERISTIC\n',
        "ALIGNMENT_WORD 2"),
    "P2 two curves (max 8) share RL_C under MOD_COMMON ALIGNMENT_WORD 2": (
        '/begin RECORD_LAYOUT RL_C\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT\n'
        ' FNC_VALUES 3 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
        + "".join(f'/begin CHARACTERISTIC {n} ""\n CURVE 0x{ad:X} RL_C 0 NO_COMPU_METHOD 0 255\n /begin AXIS_DESCR\n'
                  f'  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 8 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n'
                  for n, ad in (("CA", 0x100), ("CB", 0x200))),
        "ALIGNMENT_WORD 2"),
    "P4 curves of max 8 and 7 share RL_C under ALIGNMENT_WORD 2 (one moved, one not)": (
        '/begin RECORD_LAYOUT RL_C\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT\n'
        ' FNC_VALUES 3 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
        + "".join(f'/begin CHARACTERISTIC {n} ""\n CURVE 0x{ad:X} RL_C 0 NO_COMPU_METHOD 0 255\n /begin AXIS_DESCR\n'
                  f'  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD {mx} 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n'
                  for n, ad, mx in (("CA", 0x100, 8), ("CC", 0x200, 7))),
        "ALIGNMENT_WORD 2"),
    "P5 two COM curves share AXO (RL_AXO: UBYTE count, UWORD points) under ALIGNMENT_WORD 2": (
        '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n'
        '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
        '/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 NO_COMPU_METHOD 4 0 255\n/end AXIS_PTS\n'
        + "".join(f'/begin CHARACTERISTIC {n} ""\n CURVE 0x{ad:X} RL_U8 0 NO_COMPU_METHOD 0 255\n /begin AXIS_DESCR\n'
                  f'  COM_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 4 0 255\n  AXIS_PTS_REF AXO\n /end AXIS_DESCR\n'
                  f'/end CHARACTERISTIC\n' for n, ad in (("CR1", 0x200), ("CR2", 0x300))),
        "ALIGNMENT_WORD 2"),
}
P3 = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n'
      '/begin MODULE M1 ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\nALIGNMENT_WORD 2\n/end MOD_COMMON\n'
      '/begin RECORD_LAYOUT RL_C\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT\n'
      ' FNC_VALUES 3 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
      '/begin CHARACTERISTIC CA ""\n CURVE 0x100 RL_C 0 NO_COMPU_METHOD 0 255\n /begin AXIS_DESCR\n'
      '  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 8 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n/end MODULE\n'
      '/begin MODULE M2 ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
      '/begin CHARACTERISTIC CB ""\n CURVE 0x200 RL_C 0 NO_COMPU_METHOD 0 255\n /begin AXIS_DESCR\n'
      '  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 8 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n/end MODULE\n'
      '/end PROJECT\n')


def inline(tree, scratch):
    a, m = load(tree, scratch)
    import s19_app
    print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
          sys.version.split()[0], flush=True)
    W = pathlib.Path(scratch) / "work"; W.mkdir(parents=True, exist_ok=True)
    texts = {k: (f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n'
                 f'BYTE_ORDER MSB_FIRST\n{mc}\n/end MOD_COMMON\n{body}/end MODULE\n/end PROJECT\n')
             for k, (body, mc) in INLINE.items()}
    texts["P3 CA in M1 (ALIGNMENT_WORD 2) and CB in M2 (none) share RL_C"] = P3
    for i, (label, txt) in enumerate(sorted(texts.items())):
        p = W / f"poison{i}.a2l"
        p.write_text(txt, encoding="utf-8")
        data = a.parse_a2l_file(p)
        n, out = oracle(a, m, data)
        m.MUTANT = None
        ref = {nm: m.public(d) for nm, d in m.describe_all(data)[0].items()}
        print(f"[{label}] {n} objects; graph reading, one walk: " +
              "; ".join(f"{nm} refusal {r[0]} msg {r[1]!r} values_offset {r[5]}" for nm, r in ref.items()), flush=True)
        for mu, ((nf, exf), (nr, exr)) in out.items():
            print(f"    mutant {mu:<11}: objects differing from describe_definition per name: forward {nf}, "
                  f"reversed {nr}" + (f"; e.g. {exf or exr}" if (nf or nr) else ""), flush=True)


def worker(tree, scratch, path):
    a, m = load(tree, scratch)
    t0 = time.perf_counter()
    rec = {"file": os.path.basename(path)}
    try:
        data = a.parse_a2l_file(pathlib.Path(path))
        n, out = oracle(a, m, data)
        rec.update(objects=n, diff={mu: [r[0][0], r[1][0]] for mu, r in out.items()},
                   ex={mu: str(r[0][1][:1] or r[1][1][:1])[:300] for mu, r in out.items() if r[0][0] or r[1][0]})
    except Exception as e:
        rec["exception"] = f"{type(e).__name__}: {str(e)[:160]}"
    rec["s"] = round(time.perf_counter() - t0, 2)
    print(json.dumps(rec))


def corpus(tree, scratch, lists):
    files = [ln.strip() for lf in lists for ln in open(lf) if ln.strip()]
    from concurrent.futures import ThreadPoolExecutor

    def one(f):
        try:
            p = subprocess.run([sys.executable, "-I", __file__, "worker", tree, scratch, f], capture_output=True,
                               text=True, timeout=1200, stdin=subprocess.DEVNULL)
            line = (p.stdout.strip().splitlines() or [""])[-1]
            return json.loads(line) if line.startswith("{") else {"file": os.path.basename(f), "worker_error":
                                                                  (p.stderr.strip().splitlines() or ["?"])[-1][:200]}
        except subprocess.TimeoutExpired:
            return {"file": os.path.basename(f), "worker_error": "timeout 1200 s"}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(one, files))
    objs = sum(r.get("objects", 0) for r in res)
    errs = [r for r in res if "worker_error" in r or "exception" in r]
    print(f"[Z0] files {len(files)}, errors {len(errs)}, array/curve/map objects {objs}, wall "
          f"{time.perf_counter() - t0:.0f} s", flush=True)
    for e in errs[:10]:
        print("   ERR", e)
    for mu in map(str, MUTANTS):
        hit = [r for r in res if r.get("diff") and (r["diff"][mu][0] or r["diff"][mu][1])]
        nobj = sum(max(r["diff"][mu]) for r in hit)
        print(f"[Z1] mutant {mu:<11}: files where one walk != describe_definition per name: {len(hit)} "
              f"({nobj} objects, max of the two orders)", flush=True)
        for r in hit[:8]:
            print(f"      {r['file']}: forward/reversed {r['diff'][mu]}; e.g. {r['ex'].get(mu, '')[:220]}", flush=True)
    for key in ("ASAP2_Demo_V171", "software_a", "case_08", "defin"):
        for r in res:
            if key.lower() in r["file"].lower() and r.get("diff"):
                print(f"[Z2] {r['file']}: {r['objects']} objects; differing per mutant (forward, reversed) "
                      f"{r['diff']}", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "inline":
        inline(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "worker":
        worker(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        corpus(sys.argv[2], sys.argv[3], sys.argv[4:])
