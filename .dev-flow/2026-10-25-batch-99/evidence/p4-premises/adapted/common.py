"""Shared helpers for the read/write integrity probes (throwaway)."""
import os, sys, shutil, tempfile, json
from pathlib import Path
def _find_root():
    if os.environ.get("S19_WT"):
        return Path(os.environ["S19_WT"])
    for parent in Path(__file__).resolve().parents:
        if (parent / "s19_app" / "core.py").exists():
            return parent
    raise SystemExit("set S19_WT to a checkout of s19_app (run probes against a detached worktree)")
WT = _find_root()
sys.path.insert(0, str(WT)); sys.path.insert(0, str(WT / "tests"))
EX = WT / "examples"

def new_project(name="proj", src=EX / "case_00_public" / "prg.s19", dst_name="prg.s19"):
    base = Path(tempfile.mkdtemp(prefix="rwprobe_"))
    proj = base / ".s19tool" / "workarea" / name
    proj.mkdir(parents=True)
    if src is not None:
        shutil.copyfile(src, proj / dst_name)
    return proj

def write_doc(path, entries, kind="change"):
    """entries: list of (address:int, bytes tuple)"""
    from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
    from s19_app.tui.changes.io import serialize_change_document
    doc = ChangeDocument(format="s19app-changeset", version="2.0", kind=kind,
                         encoding="utf-8", value_mode="text",
                         entries=[ChangeEntry(entry_type="bytes", address=a, encoded_bytes=tuple(b)) for a, b in entries])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(serialize_change_document(doc))
    return path

def mini_s19(path):
    """Independent minimal S19 parser: data records S1/S2/S3 only, checksum checked.
    Returns (mem dict, errors list, meta dict)."""
    mem, errs, meta = {}, [], {"s0": None, "term": None, "types": set(), "maxlen": 0}
    alen = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        t = line[1]; raw = bytes.fromhex(line[2:])
        cnt = raw[0]
        if cnt != len(raw) - 1:
            errs.append((n, "count")); continue
        if (sum(raw[:-1]) + raw[-1]) & 0xFF != 0xFF:
            errs.append((n, "checksum"))
        a = int.from_bytes(raw[1:1 + alen[t]], "big"); data = raw[1 + alen[t]:-1]
        meta["types"].add("S" + t); meta["maxlen"] = max(meta["maxlen"], len(line))
        if t in "123":
            for i, b in enumerate(data):
                if a + i in mem:
                    errs.append((n, f"dup {a+i:#x}"))
                mem[a + i] = b
        elif t == "0":
            meta["s0"] = bytes(data)
        elif t in "789":
            meta["term"] = ("S" + t, a)
    return mem, errs, meta

def mini_hex(path):
    """Independent minimal Intel HEX parser (types 00,01,02,04,05,03)."""
    mem, errs = {}, []
    upper = 0; seg = 0; mode = "lin"
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        raw = bytes.fromhex(line[1:])
        if sum(raw) & 0xFF:
            errs.append((n, "checksum"))
        cnt, addr, typ = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        data = raw[4:4 + cnt]
        if typ == 0:
            for i, b in enumerate(data):
                full = (upper << 16) + addr + i if mode == "lin" else seg + ((addr + i) & 0xFFFF)
                if full in mem:
                    errs.append((n, f"dup {full:#x}"))
                mem[full] = b
        elif typ == 1:
            break
        elif typ == 4:
            upper = int.from_bytes(data, "big"); mode = "lin"
        elif typ == 2:
            seg = int.from_bytes(data, "big") << 4; mode = "seg"
    return mem, errs

def ranges_of(mem):
    ks = sorted(mem); out = []
    for k in ks:
        if out and out[-1][1] == k:
            out[-1][1] = k + 1
        else:
            out.append([k, k + 1])
    return [tuple(r) for r in out]
