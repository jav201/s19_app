"""Print Code-Wire `in:`/`out:`/`module:` lines for qualnames (throwaway helper)."""
import importlib, inspect, sys, re, typing
def fmt(a):
    s = a if isinstance(a, str) else inspect.formatannotation(a)
    s = re.sub(r"Optional\[(.*)\]$", r"\1?", s)
    s = re.sub(r"^(.*) \| None$", r"\1?", s)
    return s.replace("typing.", "")
for spec in sys.argv[1:]:
    mod, qual = spec.split(":")
    obj = importlib.import_module(mod)
    for p in qual.split("."):
        obj = getattr(obj, p)
    sig = inspect.signature(obj)
    ins = []
    for n, p in sig.parameters.items():
        t = fmt(p.annotation) if p.annotation is not inspect._empty else "?"
        d = "" if p.default is inspect._empty else f" = {p.default!r}"
        ins.append(f"{t} {n}{d}")
    out = fmt(sig.return_annotation) if sig.return_annotation is not inspect._empty else "?"
    print(qual); print("in: " + "; ".join(ins)); print("out: " + out); print("module: " + mod.replace(".", "/") + ".py"); print()
