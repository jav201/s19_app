"""Mutant driver (runner side). usage: drive.py ID [ID...] | ALL ; env RUNNER_HOME_NAME set by the caller (HT-11).
Each mutant runs on a copy of the tree (HT-09); pytest -n 2, timeout 300; waits while the 1-min load > 4 (HT-08)."""
import json, os, shutil, subprocess, sys, time

W = os.path.expanduser("~/work/zq-mu7")
TREE = W + "/tree"
PY = os.path.expanduser("~/miniconda3/envs/s19ci/bin/python")
HOME = W + "/home/" + os.environ["RUNNER_HOME_NAME"]
ENV = dict(PATH="/usr/bin:/bin", HOME=HOME, XDG_CONFIG_HOME=W + "/x/config", XDG_CACHE_HOME=W + "/x/cache",
           XDG_DATA_HOME=W + "/x/data", TMPDIR=W + "/tmp", PYTHONDONTWRITEBYTECODE="1",
           PYTHONIOENCODING="utf-8", LANG="C.UTF-8", PYTHONPATH=".")
L = "tests/test_b103_label_list.py"
V = "tests/test_b103_a2l_list_view.py"
OUT = W + "/logs/results.tsv"


def load1():
    return float(open("/proc/loadavg").read().split()[0])


def wait_quiet():
    while load1() > 4.0:
        with open(OUT, "a") as f:
            f.write("#\tpause\tload %.2f\n" % load1())
        time.sleep(60)


def pytest(cwd, args, log):
    wait_quiet()
    ld = load1()
    t = time.time()
    p = subprocess.run(["timeout", "300", PY, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-n", "2",
                        "--tb=line", "-x"] + args, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    open(log, "w").write(p.stdout)
    lines = [x for x in p.stdout.splitlines() if x.strip()]
    failed = [x for x in lines if x.startswith("FAILED") or x.startswith("ERROR")]
    return p.returncode, (failed[0] if failed else ""), (lines[-1] if lines else ""), ld, time.time() - t


def kexpr(k):
    return ["-k", k] if k else []


def run(m):
    d = W + "/runs/" + m["id"]
    shutil.rmtree(d, ignore_errors=True)
    subprocess.run(["cp", "-a", TREE, d], check=True)
    p = d + "/" + m["file"]
    s = open(p, encoding="utf-8", newline="").read()
    nl = "\r\n" if "\r\n" in s else "\n"
    old, new = m["old"].replace("\n", nl), m["new"].replace("\n", nl)
    if old != new:
        assert s.count(old) == 1, m["id"]
    open(p, "w", encoding="utf-8", newline="").write(s.replace(old, new))
    for f2, o2, n2 in m.get("also", []):
        p2 = d + "/" + f2
        s2 = open(p2, encoding="utf-8", newline="").read()
        nl2 = "\r\n" if "\r\n" in s2 else "\n"
        o2, n2 = o2.replace("\n", nl2), n2.replace("\n", nl2)
        assert s2.count(o2) == 1, m["id"]
        open(p2, "w", encoding="utf-8", newline="").write(s2.replace(o2, n2))
    steps = []
    if m["extra"]:
        steps.append(("extra", m["extra"].split()))
    if m["k"]:
        steps.append(("L", [L] + kexpr(m["k"])))
        steps.append(("V", [V] + kexpr(m["k"])))
    result = "survived"
    for name, args in steps:
        rc, first, last, ld, secs = pytest(d, args, W + "/logs/%s-%s.txt" % (m["id"], name))
        with open(OUT, "a") as f:
            f.write("%s\t%s\trc=%s\tload=%.2f\t%ds\t%s\t%s\n" % (m["id"], name, rc, ld, secs, first[:200], last[:120]))
        if rc == 124:
            result = "timeout"
            break
        if rc != 0 and rc != 5:
            result = "killed"
            break
    with open(OUT, "a") as f:
        f.write("%s\tRESULT\t%s\n" % (m["id"], result))
    shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    ms = json.load(open(W + "/" + os.environ.get("MUT", "mutants.json")))
    ms.append(dict(id="BASE", file="s19_app/__init__.py", old="", new="", req="baseline", k="051 or 017", extra=""))
    ids = sys.argv[1:]
    for m in ms:
        if (ids == ["ALL"] and m["id"] != "BASE") or m["id"] in ids or (ids[:1] == ["FROM"] and m["id"] != "BASE" and m["id"] >= ids[1]):
            run(m)
