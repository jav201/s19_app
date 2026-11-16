# -*- coding: utf-8 -*-
"""Mutant driver (runs on the runner, on the COPY ~/work/zq-mu10/tree).
usage: mu.py check            -> every `old` occurs exactly once in the pristine file
       mu.py run ID [ID...]   -> apply, run the primary tests, restore, append to results.jsonl
       mu.py wide ID [ID...]  -> as run, with the whole Inc 10 file set (for survivors)
"""
# RUNNER_HOME_NAME = the HT-02 HOME basename, exported by the caller (kept out of the repo, PP-03).
import json, os, shutil, subprocess, sys, time
sys.dont_write_bytecode = True
S = os.path.expanduser("~/work/zq-mu10")
TREE, PRIS, LOGS = S + "/tree", S + "/pristine_s19_app", S + "/logs"
sys.path.insert(0, S)
from mutants import M, G1P, G1C, G2A, G2W, G3, S0

ENV = dict(PATH="/usr/bin:/bin", HOME=S + "/home/" + os.environ["RUNNER_HOME_NAME"], XDG_CONFIG_HOME=S + "/x/config",
           XDG_CACHE_HOME=S + "/x/cache", XDG_DATA_HOME=S + "/x/data", TMPDIR=S + "/tmp",
           PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", LANG="C.UTF-8", PYTHONPATH=".")
PY = os.path.expanduser("~/miniconda3/envs/s19ci/bin/python")


def pristine(rel):
    return os.path.join(S, "pristine_s19_app", rel[len("s19_app/"):])


def read(p):
    with open(p, encoding="utf-8", newline="") as f:
        return f.read()


def check():
    bad = 0
    for mu in M:
        n = read(pristine(mu["file"])).count(mu["old"])
        if n != 1:
            bad += 1
            print("BAD", mu["id"], "occurs", n)
    print("check done, bad =", bad, "of", len(M))


def pytest(label, args):
    cmd = [PY, "-m", "pytest", "-p", "no:cacheprovider", "-n", "2", "-q", "-rf"] + ([] if os.environ.get("MU_ALL") else ["--maxfail=1"]) + args
    t0 = time.time()
    try:
        r = subprocess.run(["timeout", "300"] + cmd, cwd=TREE, env=ENV, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True)
        rc, out = r.returncode, r.stdout + r.stderr
    except Exception as exc:  # pragma: no cover
        rc, out = 99, repr(exc)
    with open(f"{LOGS}/{label}.txt", "w", encoding="utf-8") as f:
        f.write(f"# load {open('/proc/loadavg').read().split()[:3]} rc={rc} secs={time.time()-t0:.0f}\n# args: {args}\n{out}")
    return rc, out, time.time() - t0


def verdict(rc, out):
    if rc == 124:
        return "timeout"
    if rc == 0:
        return "survived"
    if rc in (1, 2) and "FAILED" in out:
        return "killed"
    return f"error-rc{rc}"


def run(ids, wide):
    for mu in M:
        if mu["id"] not in ids:
            continue
        target = os.path.join(TREE, mu["file"])
        src = read(pristine(mu["file"]))
        assert src.count(mu["old"]) == 1, mu["id"]
        mutated = src.replace(mu["old"], mu["new"])
        try:
            with open(target, "w", encoding="utf-8", newline="") as f:
                f.write(mutated)
            if wide == "retest":
                runs = [("retest-" + mu["id"], ["tests/test_b103_inc10_mu_survivors.py"])]
            elif wide:
                runs = [("wide-" + mu["id"] + "-" + os.path.basename(t)[16:-3], [t]) for t in (G1P, G1C, G2A, G2W, G3, S0)]
            else:
                runs = [(mu["id"], mu["tests"])]
            verdicts = []
            for label, args in runs:
                rc, out, secs = pytest(label, args)
                v = verdict(rc, out)
                fails = [l.strip()[:200] for l in out.splitlines() if l.startswith("FAILED")][:3]
                verdicts.append(dict(label=label, verdict=v, secs=round(secs), failed=fails))
                if v in ("killed", "timeout") or v.startswith("error"):
                    break
        finally:
            shutil.copyfile(pristine(mu["file"]), target)
        rec = dict(id=mu["id"], rows=mu["rows"], wide=str(wide), runs=verdicts)
        with open(S + "/results.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(json.dumps(rec, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "check":
        check()
    else:
        ids = sys.argv[2:] or [m["id"] for m in M]
        run(set(ids), {"wide": True, "retest": "retest"}.get(sys.argv[1], False))
