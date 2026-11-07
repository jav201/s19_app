"""E5-3 measure probe, Inc 2a (batch-103), code-reviewer agent.

Compares, on the same files and in the same process, the two ways of measuring the per-object part of
R-A2L-DEF.149 (cases .149/6 FORMAT word and .149/7 type word, files from the perf test's own ``_gp2_text``):

  A  (as the tests do today) least of 31 interleaved rounds of describe_definitions(400 names) MINUS the least of
     31 rounds of describe_definitions(names[:1]) -- the difference of two separate walks;
  B  (proposed) ONE fresh walk per round, describe_definitions(<generator>), the clock read when the walk asks for
     the 2nd name (the 1st name has reduced every shared section) and when the names run out: the 399 names
     described for the first time in that walk (E3S3-34's form), a single interval, no subtraction.

Each under two host conditions: quiet, and loaded by LOAD_WORKERS busy-loop processes started here and killed by
PID in a finally block.  Negative control: the mutant "reduction per object" (``_read_method_record`` given a fresh
``reads`` at every call) must turn B's ratios RED.

Run from a COPY of the integrated tree (cwd = its root), isolated HOME / XDG / LOCALAPPDATA.
"""
from __future__ import annotations

import gc
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

import s19_app  # noqa: E402
from s19_app.tui import a2l_definition as defmod  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
import tests.test_b103_a2l_definition_perf as perf  # noqa: E402

print("[M0] s19_app.__file__ =", s19_app.__file__)
print("[M0] python", sys.version.split()[0], "cpus", os.cpu_count())

ROUNDS = 31
TRIALS = 3
LOAD_WORKERS = (os.cpu_count() or 16) + 2   # more runnable processes than cores: real contention (this whole
                                            # probe runs under `nice -n 19`, so other sessions keep priority)
SIZES = (256, 512, 2048)
OUT = ROOT.parent / "out" / "measure"
OUT.mkdir(parents=True, exist_ok=True)


def load(case: str, kib: int):
    path = OUT / f"{case}_{kib}.a2l"
    if not path.exists():
        path.write_text(perf._gp2_text(case, kib), encoding="utf-8")
    a2l = parse_a2l_file(path)
    names = [f"S{i:05d}" for i in range(perf.N_OBJECTS)]
    return a2l, names


def cpu(fn):
    gc.collect()
    gc.disable()
    try:
        t0 = time.process_time()
        result = fn()
        return time.process_time() - t0, result
    finally:
        gc.enable()


def steady(a2l, names):
    """B: the CPU time of names[1:] inside one fresh walk."""
    marks = []

    def gen():
        yield names[0]
        marks.append(time.process_time())
        yield from names[1:]
        marks.append(time.process_time())

    gc.collect()
    gc.disable()
    try:
        result = defmod.describe_definitions(gen(), a2l)
    finally:
        gc.enable()
    assert len(marks) == 2 and len(result) == len(names)
    return marks[1] - marks[0]


def measure(loaded, how: str) -> dict:
    best_all = {k: float("inf") for k in SIZES}
    best_first = {k: float("inf") for k in SIZES}
    best_steady = {k: float("inf") for k in SIZES}
    for _ in range(ROUNDS):
        slow = False
        for kib in SIZES:                        # interleaved S, 2S, 8S
            a2l, names = loaded[kib]
            if how == "A":
                t1, _ = cpu(lambda: defmod.describe_definitions(names[:1], a2l))
                ta, _ = cpu(lambda: defmod.describe_definitions(names, a2l))
                best_first[kib] = min(best_first[kib], t1)
                best_all[kib] = min(best_all[kib], ta)
                slow = slow or ta > 2.0
            else:
                ts = steady(a2l, names)
                best_steady[kib] = min(best_steady[kib], ts)
                slow = slow or ts > 2.0
        if slow:                                 # as the tests: one round only once a run exceeds 2 s
            break
    if how == "A":
        return {k: max(best_all[k] - best_first[k], 1e-3) for k in SIZES}
    return {k: best_steady[k] for k in SIZES}


def line(tag, case, cond, how, trial, part):
    r2, r8 = part[512] / part[256], part[2048] / part[256]
    verdict = "GREEN" if (r2 <= 1.5 and r8 <= 2.0) else "RED"
    print(f"[{tag}] {case:5s} {cond:6s} {how} trial {trial}: part ms "
          f"{part[256] * 1e3:7.2f} {part[512] * 1e3:7.2f} {part[2048] * 1e3:7.2f}  x2S {r2:5.2f}  x8S {r8:5.2f}  {verdict}",
          flush=True)
    return verdict


def run_block(tag, cond, cases, hows=("A", "B"), trials=TRIALS):
    tally = {}
    for case in cases:
        loaded = {kib: load(case, kib) for kib in SIZES}
        for trial in range(1, trials + 1):
            for how in hows:
                v = line(tag, case, cond, how, trial, measure(loaded, how))
                tally.setdefault((case, how), []).append(v)
    return tally


def start_load(n):
    procs = [subprocess.Popen([sys.executable, "-c", "while True: pass"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(n)]
    print(f"[M0] load workers started, PIDs {[p.pid for p in procs]}", flush=True)
    time.sleep(20)                               # let the 1-minute load average rise
    print(f"[M0] load average now {os.getloadavg()}", flush=True)
    return procs


def stop_load(procs):
    for p in procs:
        p.kill()                                 # by PID (the Popen handle), never by pattern
    for p in procs:
        p.wait(timeout=10)
    print(f"[M0] load workers killed by PID: {[p.pid for p in procs]}; returncodes {[p.returncode for p in procs]}",
          flush=True)


CASES = ("fmt", "type")
print(f"[M0] quiet start, load average {os.getloadavg()}", flush=True)
quiet = run_block("M1", "quiet", CASES)

loaded_tally: dict = {}
if "--load" in sys.argv:                         # opt-in: never while another session measures on the host
    procs = start_load(LOAD_WORKERS)
    try:
        loaded_tally = run_block("M2", "loaded", CASES)
        print(f"[M0] load average at the end of the loaded block {os.getloadavg()}", flush=True)
    finally:
        stop_load(procs)
else:
    print("[M0] loaded block skipped (no --load: another session's timing probe shares the host)", flush=True)

# negative control for B: the reduction redone per object (the class .149 guards against)
orig = defmod._read_method_record


def per_object(method_name, methods, tables, tabs, reads):
    return orig(method_name, methods, tables, tabs, {})


defmod._read_method_record = per_object
try:
    print(f"[M0] mutant 'reduction per object' active; load average {os.getloadavg()}", flush=True)
    neg = run_block("M3", "mutant", CASES, hows=("B",), trials=1)
finally:
    defmod._read_method_record = orig

print("\n[M9] summary (GREEN count / trials):")
for label, tally in (("quiet", quiet), ("loaded", loaded_tally), ("mutant", neg)):
    for (case, how), vs in sorted(tally.items()):
        print(f"[M9] {label:6s} {case:5s} {how}: {vs.count('GREEN')}/{len(vs)} GREEN")
print("[END] measure probe done")
