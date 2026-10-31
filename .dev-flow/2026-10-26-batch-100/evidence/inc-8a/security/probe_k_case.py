"""Inc 8a probe K: classify_active_document in a case-sensitive work area
holding P and p (two projects whose names differ only in case)."""
import os, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app-b100-inc8a")
import s19_app; print("# s19_app import:", s19_app.__file__)
from s19_app.tui.services import project_gather_service as G
root = Path(__file__).resolve().parent / "runs" / f"K_{time.time_ns()}"
wa = root / ".s19tool" / "workarea"; wa.mkdir(parents=True)
r = subprocess.run(["fsutil", "file", "setCaseSensitiveInfo", str(wa), "enable"], capture_output=True, text=True)
print("fsutil:", r.returncode, r.stdout.strip()[-40:], r.stderr.strip()[-80:])
(wa / "P" / "patches").mkdir(parents=True); (wa / "p" / "patches").mkdir(parents=True)
print("work area entries:", sorted(os.listdir(wa)))
(wa / "p" / "patches" / "x.json").write_bytes(b'{"lower p": 1}')
src = wa / "p" / "patches" / "x.json"
print("source in p, save into P (P/patches/x.json absent):", G.classify_active_document(wa / "P", src, "patches"))
(wa / "P" / "patches" / "x.json").write_bytes(b'{"upper P, different": 2}')
print("source in p, save into P (P/patches/x.json present, other bytes):", G.classify_active_document(wa / "P", src, "patches"))
print("control, source in p, save into Q:", G.classify_active_document(wa / "Q", src, "patches"))
