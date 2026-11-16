"""Mutant driver (M9). Usage: mut_run.py check <tree>   |   mut_run.py run <pristine_tree> <mut_tree> <outdir> [ids...]
check: each old string occurs exactly once and the mutated source parses (ast only).
run: per mutant, copy the two sources from pristine into the mutant tree, apply, run pytest on the group B files with -x, restore.
"""
import ast, os, shutil, subprocess, sys, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutants_spec import MUTANTS

FILES = ["s19_app/tui/definition_bench.py", "s19_app/tui/definition_bench_view.py"]
TESTS = ["tests/test_b103_inc9_b_canvas.py", "tests/test_b103_inc9_b_detail.py", "tests/test_b103_inc9_b_model.py",
         "tests/test_b103_inc9_b_tools.py", "tests/test_b103_inc9_b_cells.py"]
if os.environ.get("MUT_TESTS"):
    TESTS = os.environ["MUT_TESTS"].split()
CRLF = chr(13) + chr(10)
LF = chr(10)


def apply(src, old, new):
    if CRLF in src:
        old = old.replace(LF, CRLF)
        new = new.replace(LF, CRLF)
    n = src.count(old)
    if n != 1:
        raise SystemExit(f"old string occurs {n} times: {old[:60]!r}")
    return src.replace(old, new)


def check(tree):
    bad = 0
    for mid, req, f, old, new, occ in MUTANTS:
        src = open(os.path.join(tree, f), encoding="utf-8", newline="").read()
        try:
            out = apply(src, old, new)
            ast.parse(out)
            assert out != src
        except BaseException as e:
            bad += 1
            print("BAD", mid, e)
    print("checked", len(MUTANTS), "bad", bad)


def run(pristine, mut, outdir, ids):
    home = os.path.expanduser("~/work/zq-m9")
    env = {"PATH": "/usr/bin:/bin", "HOME": home + "/home/" + os.environ["RUNNER_HOME_NAME"], "XDG_CONFIG_HOME": home + "/x/config",
           "XDG_CACHE_HOME": home + "/x/cache", "XDG_DATA_HOME": home + "/x/data", "TMPDIR": home + "/tmp",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8", "PYTHONPATH": "."}
    py = os.path.expanduser("~/miniconda3/envs/s19ci/bin/python")
    os.makedirs(outdir, exist_ok=True)
    results = {}
    for mid, req, f, old, new, occ in MUTANTS:
        if ids and mid not in ids:
            continue
        for g in FILES:
            shutil.copyfile(os.path.join(pristine, g), os.path.join(mut, g))
        src = open(os.path.join(pristine, f), encoding="utf-8", newline="").read()
        open(os.path.join(mut, f), "w", encoding="utf-8", newline="").write(apply(src, old, new))
        t0 = time.time()
        cmd = ["timeout", "300", py, "-m", "pytest", "-p", "no:cacheprovider", "-n", "2", "-x", "-q", "--tb=line", "-rf"] + TESTS
        p = subprocess.run(cmd, cwd=mut, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        dt = time.time() - t0
        out = p.stdout + p.stderr
        open(os.path.join(outdir, mid + ".txt"), "w", encoding="utf-8").write(out)
        failed = [l for l in out.splitlines() if l.startswith("FAILED")]
        if p.returncode == 124:
            res = "timeout"
        elif p.returncode == 0:
            res = "survived"
        elif failed:
            res = "killed"
        else:
            res = "error"
        results[mid] = {"req": req, "result": res, "rc": p.returncode, "secs": round(dt), "first": failed[0][:230] if failed else out.strip().splitlines()[-1][:200] if out.strip() else ""}
        print(mid, res, round(dt), results[mid]["first"][:150], flush=True)
        for g in FILES:
            shutil.copyfile(os.path.join(pristine, g), os.path.join(mut, g))
    json.dump(results, open(os.path.join(outdir, "results-%d.json" % int(time.time())), "w"), indent=1, ensure_ascii=False)


if __name__ == "__main__":
    if sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        run(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
