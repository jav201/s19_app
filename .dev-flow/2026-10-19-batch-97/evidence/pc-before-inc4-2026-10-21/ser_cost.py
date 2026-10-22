"""Throwaway (PC-21 / H-P2): what one D1 document push costs on the UI thread.
Builds an n-entry document by replicating the 6-entry fixture's parsed entries
(serialisation does not re-validate), then times serialize -> decode -> cap,
next to service.rows(None), which every refresh_entries site already pays."""
import sys, json, time, statistics
sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app")
from s19_app.tui.services.change_service import ChangeService
from s19_app.tui.changes.io import serialize_change_document
from s19_app.tui.screens_directionb import cap_json_lines
FX = r"C:\Users\jjgh8\Github\s19_app\prototypes\b94_polish\demo_project\.s19tool\workarea\patches\calib_hotfix.json"
svc = ChangeService(); svc.load_text(open(FX, encoding="utf-8").read())
six = list(svc.document.entries); assert len(six) == 6, len(six)
def med(fn, reps):
    xs = []
    for _ in range(reps):
        a = time.perf_counter(); fn(); xs.append(time.perf_counter() - a)
    return statistics.median(xs) * 1000
for n in (6, 1000, 10000, 100000):
    svc.document.entries = (six * (n // 6 + 1))[:n]
    reps = 15 if n <= 10000 else 3
    wire = serialize_change_document(svc.document); text = wire.decode("ascii")
    ser = med(lambda: serialize_change_document(svc.document), reps)
    push = med(lambda: cap_json_lines(serialize_change_document(svc.document).decode("ascii")), reps)
    rows = med(lambda: svc.rows(None), reps)
    print(f"n={n:>6}  bytes={len(wire):>10,}  lines={text.count(chr(10)):>8,}  serialize={ser:8.2f} ms  serialize+decode+cap={push:8.2f} ms  rows()={rows:8.2f} ms")
