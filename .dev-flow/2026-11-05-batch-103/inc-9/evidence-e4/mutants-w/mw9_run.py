"""MW9 mutant driver. check <tree> | run <pristine> <mut> <outdir> <tests...> (ids via MUT_IDS, timeout via MUT_TO)"""
import ast, os, shutil, subprocess, sys, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mw9_spec import M
def apply(src, old, new):
    n = src.count(old)
    if n != 1:
        raise SystemExit(f"old occurs {n}x: {old[:70]!r}")
    return src.replace(old, new)
def check(tree):
    bad = 0
    for mid, req, f, old, new in M:
        src = open(os.path.join(tree, f), encoding="utf-8", newline="").read()
        try:
            out = apply(src, old, new); ast.parse(out); assert out != src
        except BaseException as e:
            bad += 1; print("BAD", mid, e)
    print("checked", len(M), "bad", bad)
def run(pristine, mut, outdir, tests):
    S = os.path.expanduser("~/work/zq-mw9")
    env = {"PATH": "/usr/bin:/bin", "HOME": S + "/home/<runner-home>", "XDG_CONFIG_HOME": S + "/x/config", "XDG_CACHE_HOME": S + "/x/cache",
           "XDG_DATA_HOME": S + "/x/data", "TMPDIR": S + "/tmp", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8", "PYTHONPATH": "."}
    py = os.path.expanduser("~/miniconda3/envs/s19ci/bin/python")
    ids = os.environ.get("MUT_IDS", "").split()
    to = os.environ.get("MUT_TO", "900")
    extra = os.environ.get("MUT_ARGS", "").split()
    if os.environ.get("MUT_MARK"):
        extra += ["-m", os.environ["MUT_MARK"]]
    files = sorted({f for _, _, f, _, _ in M})
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(outdir, "mut-log.jsonl"), "a")
    for mid, req, f, old, new in M:
        if (ids and mid not in ids) or (not ids and mid.startswith("t")):
            continue
        for g in files:
            shutil.copyfile(os.path.join(pristine, g), os.path.join(mut, g))
        src = open(os.path.join(pristine, f), encoding="utf-8", newline="").read()
        open(os.path.join(mut, f), "w", encoding="utf-8", newline="").write(apply(src, old, new))
        load0 = open("/proc/loadavg").read().split()[0]
        t0 = time.time()
        cmd = ["timeout", to, py, "-m", "pytest", "-p", "no:cacheprovider", "-n", os.environ.get("MUT_N", "2"), "-x", "-q", "--tb=line", "-rf"] + extra + tests
        p = subprocess.run(cmd, cwd=mut, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        dt = time.time() - t0
        out = p.stdout + p.stderr
        open(os.path.join(outdir, mid + ".txt"), "w").write(out)
        first = next((l for l in out.splitlines() if l.startswith("FAILED") or l.startswith("ERROR")), "")
        status = "timeout" if p.returncode == 124 else "survived" if p.returncode == 0 else "killed" if p.returncode == 1 else f"rc{p.returncode}"
        rec = {"id": mid, "req": req, "status": status, "rc": p.returncode, "sec": round(dt), "load0": load0, "load1": open("/proc/loadavg").read().split()[0], "first": first[:300], "tail": out.strip().splitlines()[-1][:200] if out.strip() else ""}
        log.write(json.dumps(rec) + "\n"); log.flush()
        print(mid, status, rec["sec"], "s", first[:120], flush=True)
    for g in files:
        shutil.copyfile(os.path.join(pristine, g), os.path.join(mut, g))
if __name__ == "__main__":
    if sys.argv[1] == "check": check(sys.argv[2])
    else: run(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
