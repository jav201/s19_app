"""CPU burner pinned to one CPU mask; exits by itself after N seconds (cap 120)."""
import ctypes, sys, time
mask, secs = int(sys.argv[1], 0), min(float(sys.argv[2]), 120.0)
k32 = ctypes.windll.kernel32
k32.GetCurrentProcess.restype = ctypes.c_void_p
k32.SetProcessAffinityMask(ctypes.c_void_p(k32.GetCurrentProcess()), ctypes.c_size_t(mask))
end = time.monotonic() + secs
x = 0
while time.monotonic() < end:
    x += 1
