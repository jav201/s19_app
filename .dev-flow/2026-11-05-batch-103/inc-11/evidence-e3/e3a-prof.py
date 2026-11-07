"""Inc 11 E3 architect: where the e07fb00 parse of one large file spends its time (cProfile, top 14 by cumulative and
by own time). Run on cachyos-rtx only: python -I e3a-prof.py <repo> <file>. Prints function names and times only."""
import cProfile, io, pathlib, pstats, sys
repo = pathlib.Path(sys.argv[1]); f = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
pr = cProfile.Profile(); pr.enable(); d = a.parse_a2l_file(f); pr.disable()
print("tags", len(d["tags"]), "errors", len(d["errors"]))
for key in ("cumulative", "tottime"):
    s = io.StringIO(); pstats.Stats(pr, stream=s).sort_stats(key).print_stats(14)
    print("\n".join(ln for ln in s.getvalue().splitlines() if ln.strip())[:4000])
