"""E3 round-5 security probe, Inc 3a (batch-103): census of the longest file words that a describe or a decode echoes
or scans per object, over the 35 fixtures and 168 public files -- to size a bound on them (E3S3-22, -23).
Words: a COMPU_METHOD's type, format, unit and COMPU_TAB_REF; a RECORD_LAYOUT line's words; a MOD_COMMON ALIGNMENT
word; a COMPU_VTAB / COMPU_VTAB_RANGE entry text and DEFAULT_VALUE text; the entries per table.
THROWAWAY; read-only. Usage: python -I sec-r5-census.py <inc2a tree> <list>...
"""
import pathlib, sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, sys.argv[1])
import s19_app.tui.a2l as a  # noqa: E402

KEYS = ("cm_type", "cm_format", "cm_unit", "cm_tabref", "rl_word", "mc_align_word", "vt_text", "vt_default",
        "vt_entries", "ct_entries", "any_word")


def one(path_):
    out = {k: (0, "") for k in KEYS}

    def put(k, v, where):
        if v > out[k][0]:
            out[k] = (v, where)

    try:
        data = a.parse_a2l_file(pathlib.Path(path_))
    except Exception as ex:                       # noqa: BLE001
        return {"error": f"{type(ex).__name__}"}
    name = pathlib.Path(path_).name
    stack = list(data.get("sections") or [])
    while stack:
        node = stack.pop()
        stack.extend(node.get("children") or [])
        nm = node.get("name")
        toks = a._flatten_body_tokens([node.get("meta") or ""] + (node.get("lines") or []))
        for t in toks:
            put("any_word", len(t), name)
        if nm == "COMPU_METHOD":
            for i, k in ((2, "cm_type"), (3, "cm_format"), (4, "cm_unit")):
                if len(toks) > i:
                    put(k, len(toks[i]), name)
            if "COMPU_TAB_REF" in toks[:-1]:
                put("cm_tabref", len(toks[toks.index("COMPU_TAB_REF") + 1]), name)
        elif nm == "RECORD_LAYOUT":
            for t in toks[1:]:
                put("rl_word", len(t), name)
        elif nm == "MOD_COMMON":
            for i, t in enumerate(toks[:-1]):
                if t.startswith("ALIGNMENT_"):
                    put("mc_align_word", len(toks[i + 1]), name)
        elif nm in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
            step, pos = (2, 4) if nm == "COMPU_VTAB" else (3, 3)
            body = toks[pos:]
            if "DEFAULT_VALUE" in body[:-1]:
                put("vt_default", len(body[body.index("DEFAULT_VALUE") + 1]), name)
                body = body[:body.index("DEFAULT_VALUE")]
            for j in range(step - 1, len(body), step):
                put("vt_text", len(body[j]), name)
            put("vt_entries", len(body) // step, name)
        elif nm == "COMPU_TAB":
            put("ct_entries", max(0, (len(toks) - 4) // 2), name)
    return out


files = [ln.strip() for lf in sys.argv[2:] for ln in open(lf) if ln.strip()]
with ProcessPoolExecutor(8) as ex:
    res = list(ex.map(one, files))
errs = [r for r in res if "error" in r]
print(f"[W] files {len(files)}, parse errors {len(errs)}", flush=True)
for k in KEYS:
    best = max((r[k] for r in res if "error" not in r), default=(0, ""))
    print(f"[W] longest {k}: {best[0]} ({best[1]})", flush=True)
