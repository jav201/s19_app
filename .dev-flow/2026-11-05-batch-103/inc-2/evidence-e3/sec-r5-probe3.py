"""E3 round-5 security probe 3, Inc 2 (batch-103): fixture cost of the guards proposed in round 5. Base parser only
(clone e07fb00), read-only. Imports the helpers of sec-r5-probe.py (its Parts 1-3 do not run on import).

Counts over the 35 tracked fixture files, per MEASUREMENT / CHARACTERISTIC (text of the object = reading W, comments
and quoted strings included, as R-A2L-DEF.19's letters clause):
  ecu-letters>1          the letters ECU_ADDRESS more than once
  ecu-letters-unread     the letters once while the tag table read no address (a MEASUREMENT), or an address
                         that differs from the word after ECU_ADDRESS read with each comment as a word break
  bo-letters             the letters BYTE_ORDER more than once, or once while no own line starts with BYTE_ORDER
  mod-bo                 a MOD_COMMON whose text holds the letters BYTE_ORDER more than once
  mask-word-glued        a mask read by the record whose word differs from the C-rule word after BIT_MASK
  matrix-multi           a MATRIX_DIM line with more than one number whose product differs from the first; of
                         them, kind number by the tag (matrix_dim 1) = edited as a scalar
"""
import collections, pathlib, subprocess, sys
here = pathlib.Path(__file__).resolve().parent
repo = pathlib.Path(sys.argv[1])
src = (here / "sec-r5-probe.py").read_text(encoding="utf-8")
cut = src.index("# ------------------------------------------------------------------------------------------------ Part 1")
ns = {"__name__": "probe", "__file__": str(here / "sec-r5-probe.py")}
exec(compile(src[:cut], "sec-r5-probe.py(helpers)", "exec"), ns)
a = ns["a"]; model = ns["model"]; walk = ns["walk"]; text_W = ns["text_W"]; ref_tokens = ns["ref_tokens"]
readable = ns["readable"]; num = ns["num"]; DEC = ns["DEC"]

files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
T = collections.Counter(); L = collections.defaultdict(list)
for f in files:
    data = a.parse_a2l_file(repo / f)
    try: objs = model(data)
    except AssertionError: print(f"[FX3] {f}: mismatch, skipped"); continue
    secs = list(walk(data["sections"]))
    for s in secs:
        if s["name"] == "MOD_COMMON":
            t = "\n".join([s.get("meta", "")] + list(s.get("lines") or []))
            if t.upper().count("BYTE_ORDER") > 1: T["mod-bo"] += 1; L["mod-bo"].append(f)
    msecs = [s for s in secs if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    for o, s in zip(objs, msecs):
        tw = text_W(s); up = tw.upper()
        ids = [v for k, v in ref_tokens(tw) if k == "ID"]
        n = up.count("ECU_ADDRESS")
        if n > 1: T["ecu-letters>1"] += 1; L["ecu>1"].append((f, o["name"], n))
        cw = [ids[j + 1] for j, v in enumerate(ids[:-1]) if v == "ECU_ADDRESS"]
        if n == 1 and o["sec"] == "MEASUREMENT" and (o["addr"] is None or not cw or not readable(cw[0]) or num(cw[0]) != o["addr"]):
            T["ecu-letters-unread"] += 1; L["ecu-unread"].append((f, o["name"], o["addr"], cw[:1]))
        b = up.count("BYTE_ORDER")
        if b > 1 or (b == 1 and not any(ln.strip().split()[:1] == ["BYTE_ORDER"] for ln in s["lines"])):
            T["bo-letters"] += 1; L["bo"].append((f, o["name"], b))
        if o["mask"] is not None:
            T["masks"] += 1
            mw = [ids[j + 1] for j, v in enumerate(ids[:-1]) if v == "BIT_MASK"]
            if not mw or not readable(mw[0]) or num(mw[0]) != o["mask"]:
                T["mask-word-glued"] += 1; L["glued"].append((f, o["name"], hex(o["mask"]), mw[:1]))
        for ln in s["lines"]:
            p = ln.split()
            if p[:1] == ["MATRIX_DIM"]:
                nums = [x for x in p[1:] if DEC.fullmatch(x)]
                prod = 1
                for x in nums: prod *= int(x)
                if len(nums) > 1 and prod != int(nums[0]):
                    T["matrix-multi"] += 1
                    if o["kind"] == "number/enum": T["matrix-multi-edited-as-scalar"] += 1; L["scalar"].append((f, o["name"], nums))
    T["objects"] += len(objs)
print("[FX3-total] " + " ".join(f"{k}={v}" for k, v in sorted(T.items())))
for k, v in L.items(): print(f"[FX3-{k}] {len(v)}: {v[:8]!r}")
