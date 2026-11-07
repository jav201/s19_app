"""Inc 10 E1 census A — save-back conversion S19 <-> Intel HEX through the shipped engine (base e07fb00).

Read-only toward the product: calls the shipped emitters / save_patched_image / verify_written_image the way
the save-back handler does (app.py:5026-5050), with ``source_kind`` set to the OUTPUT format, which is what
Inc 10 will pass. Run on <runner> with HOME/XDG/LOCALAPPDATA under /tmp/b103-e1-10/. No clipboard, no app.
"""
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path("/home/<user>/work/s19_app")  # absolute: HOME is isolated
sys.path.insert(0, str(ROOT))
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from s19_app.core import S19File  # noqa: E402
from s19_app.hexfile import IntelHexFile  # noqa: E402
from s19_app.tui.services.load_service import build_loaded_s19, build_loaded_hex  # noqa: E402
from s19_app.tui.changes.apply import save_patched_image  # noqa: E402
from s19_app.tui.changes.verify import verify_written_image  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map, emit_intel_hex_from_mem_map  # noqa: E402

W = Path(os.environ["CENSUS"])
SRC = W / "src"
SRC.mkdir(parents=True, exist_ok=True)
WA = W / "base" / ".s19tool" / "workarea"
WA.mkdir(parents=True, exist_ok=True)


def ranges_of(keys):
    ks = sorted(keys)
    out, s, p = [], None, None
    for k in ks:
        if s is None:
            s = p = k
        elif k == p + 1:
            p = k
        else:
            out.append((s, p + 1))
            s = p = k
    if s is not None:
        out.append((s, p + 1))
    return out


def load(path):
    if path.suffix.lower() == ".hex":
        return build_loaded_hex(path, IntelHexFile(path), None, None)
    return build_loaded_s19(path, S19File(str(path)), None, None)


def synth(name):  # app.py:689-690 (_synth_s0_header_from_filename)
    return name.encode("ascii", errors="ignore")[:252]


def rec_types(lines):
    c = Counter()
    for ln in lines:
        if ln.startswith(":"):
            c["HEX%s" % ln[7:9]] += 1
        else:
            c[ln[:2]] += 1
    return dict(sorted(c.items()))


def max_data(lines):
    best = 0
    for ln in lines:
        if ln.startswith(":") and ln[7:9] == "00":
            best = max(best, int(ln[1:3], 16))
        elif ln[:2] in ("S1", "S2", "S3"):
            alen = {"S1": 2, "S2": 3, "S3": 4}[ln[:2]]
            best = max(best, int(ln[2:4], 16) - alen - 1)
    return best


def s0_text(lines):
    for ln in lines:
        if ln.startswith("S0"):
            n = int(ln[2:4], 16)
            data = bytes.fromhex(ln[8:8 + 2 * (n - 3)])
            return data
    return None


# --- sources -------------------------------------------------------------------------------------
sources = []
s1 = ROOT / "examples" / "case_00_public" / "s19_sample.s19"
s3 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
s2_map = {a: (a * 7) & 0xFF for a in list(range(0x012340, 0x012368)) + list(range(0x020000, 0x020011))}
s2 = SRC / "s2_source.s19"
s2.write_text(emit_s19_from_mem_map(dict(s2_map), ranges_of(s2_map), 16, b"S2SRC"))
x64_map = {a: a & 0xFF for a in range(0x0000FFF0, 0x00010014)}
x64 = SRC / "cross64k.s19"
x64.write_text(emit_s19_from_mem_map(dict(x64_map), ranges_of(x64_map), 32, b"X64"))
for p in (s1, s2, s3, x64):
    sources.append(p)
    lf = load(p)
    h = SRC / (p.stem + ".hex")
    h.write_text(emit_intel_hex_from_mem_map(dict(lf.mem_map), list(lf.ranges)))
    sources.append(h)

for src in sources:
    lf = load(src)
    hi = max(e - 1 for _, e in lf.ranges)
    print("=== SOURCE", src.name, "kind", lf.file_type, "bytes", len(lf.mem_map), "ranges", len(lf.ranges),
          "highest 0x%X" % hi, "s0", lf.source_s0_header, "entry_point",
          None if lf.entry_point is None else "0x%X" % lf.entry_point,
          "src_types", rec_types(src.read_text().splitlines()))
    for out_kind, width in (("s19", 32), ("s19", 16), ("hex", 32), ("hex", 16)):
        name = "%s-patched.%s" % (src.stem, out_kind)
        if out_kind == "s19":
            s0 = (lf.source_s0_header or synth(name)) if width == 32 else None
        else:
            s0 = (lf.source_s0_header or synth(name)) if width == 32 else None
        dest = WA
        path, issues = save_patched_image(dict(lf.mem_map), list(lf.ranges), dest, name,
                                          source_kind=out_kind, bytes_per_line=width, s0_header=s0,
                                          workarea_root=WA)
        if path is None:
            print("  ->", out_kind, width, "REFUSED", [i.code for i in issues])
            continue
        lines = path.read_text().splitlines()
        v = verify_written_image(path, dict(lf.mem_map), out_kind)
        reread = load(path)
        print("  ->", out_kind, "w%d" % width, "file", path.name, "lines", len(lines),
              "types", rec_types(lines), "max_data", max_data(lines),
              "first", lines[0][:24], "last", lines[-1][:24],
              "s0", s0_text(lines), "verify", v.status,
              "reread_equal", dict(reread.mem_map) == dict(lf.mem_map),
              "reread_entry", None if reread.entry_point is None else "0x%X" % reread.entry_point)
        path.unlink()
    # negative control for the verify reader: read the written file with the OTHER reader
    other = "hex" if lf.file_type == "s19" else "s19"
    name = "%s-neg.%s" % (src.stem, other)
    path, _ = save_patched_image(dict(lf.mem_map), list(lf.ranges), WA, name, source_kind=other,
                                 bytes_per_line=32, s0_header=None, workarea_root=WA)
    try:
        v = verify_written_image(path, dict(lf.mem_map), lf.file_type)
        print("  NEG verify written=%s read-as=%s -> %s runs=%d" % (other, lf.file_type, v.status, len(v.runs)))
    except Exception as exc:  # noqa: BLE001
        print("  NEG verify written=%s read-as=%s -> %s: %s" % (other, lf.file_type, type(exc).__name__, exc))
    path.unlink()

# --- the file-name suffix rule (R-HEX-SAVE-001.2) with a name of the other format's suffix ----------
lf = load(s3)
for typed, kind in (("firmware-patched.s19", "hex"), ("firmware-patched.HEX", "hex"),
                    ("firmware-patched", "hex"), ("firmware-patched.hex", "s19")):
    path, issues = save_patched_image(dict(lf.mem_map), list(lf.ranges), WA, typed, source_kind=kind,
                                      bytes_per_line=32, s0_header=None, workarea_root=WA)
    print("NAME typed=%r out=%s -> %s" % (typed, kind, None if path is None else path.name))
    if path is not None:
        path.unlink()
print("END")
