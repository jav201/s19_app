"""Shared helpers for the Inc 7 security probes (security-reviewer)."""
import hashlib, os, subprocess, sys, time
from pathlib import Path
WT = Path(os.environ.get("PROBE_TREE", r"C:\Users\jjgh8\Github\s19_app-b100-inc7"))
sys.path.insert(0, str(WT))
import s19_app
print("# s19_app import:", s19_app.__file__)
print("# NO_COLOR present:", "NO_COLOR" in os.environ, "| python", sys.version.split()[0])
SCR = Path(__file__).resolve().parent / "runs"
SCR.mkdir(exist_ok=True)

def fresh(tag):
    d = SCR / f"{tag}_{int(time.time()*1000)}"
    d.mkdir(parents=True)
    return d

def wa(base):
    return Path(base) / ".s19tool" / "workarea"

def junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stdout + r.stderr)

def rm_junction(link):
    try:
        os.rmdir(link)
    except OSError as e:
        print("  (rmdir junction failed:", e, ")")

def snap(root):
    """lstat walk that never descends a reparse point: path -> sha256|kind."""
    out = {}
    root = Path(root)
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in dirnames:
            p = Path(dirpath) / d
            st = os.lstat(p)
            if getattr(st, "st_file_attributes", 0) & 0x400:
                out[str(p.relative_to(root))] = "<reparse>"
            else:
                keep.append(d)
        dirnames[:] = keep
        for f in filenames:
            p = Path(dirpath) / f
            try:
                out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            except OSError as e:
                out[str(p.relative_to(root))] = f"<unreadable {e.__class__.__name__}>"
    return out

def diff(a, b):
    return {"created": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in a.keys() & b.keys() if a[k] != b[k])}
