"""Measure the observable step of process_time and of asyncio.sleep(1/50) on this host."""
import asyncio, platform, sys, time

def process_time_steps(n=2000):
    steps = set(); last = time.process_time(); t_end = time.perf_counter() + 1.0
    while time.perf_counter() < t_end:
        now = time.process_time()
        if now != last:
            steps.add(round(now - last, 4)); last = now
    return sorted(steps)[:6]

def busy_reads(ms):
    out = []
    for _ in range(20):
        c0 = time.process_time(); t0 = time.perf_counter()
        while time.perf_counter() - t0 < ms / 1000: pass
        out.append(round((time.process_time() - c0) * 1000, 2))
    return out

async def sleeps():
    out = []
    for _ in range(20):
        t0 = time.perf_counter(); await asyncio.sleep(1 / 50); out.append(round((time.perf_counter() - t0) * 1000, 1))
    return out

print("platform", platform.system(), platform.release(), "python", sys.version.split()[0])
print("process_time clock info", time.get_clock_info("process_time"))
print("observed process_time steps (s)", process_time_steps())
print("cpu ms read after 5 ms of busy work, 20 tries:", busy_reads(5))
print("cpu ms read after 1 ms of busy work, 20 tries:", busy_reads(1))
print("asyncio.sleep(0.02) wall ms, 20 tries:", asyncio.run(sleeps()))
