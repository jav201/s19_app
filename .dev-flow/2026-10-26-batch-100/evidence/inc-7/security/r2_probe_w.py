"""R2-W: attacks on the cp1 lstat-walk reader (_EntryWalk) - security-reviewer round 2.
W1 a junction at an INTERMEDIATE component, reached by several spellings.
W2 a case-sensitive project folder: 'sub' and 'SUB' are two objects; the
   walk's cache key is os.path.normcase(component).
W3 an 8.3 short name of a junction; an ADS / trailing-dot / trailing-space key.
W4 the 2 000-call ceiling: do entries past it reach the parsed manifest?"""
import ctypes, hashlib, json, os, subprocess, sys
from pathlib import Path
from common import *
from s19_app.tui.services import variant_execution_service as V
from s19_app.tui.services.variant_execution_service import (
    read_project_manifest, manifest_rewrite_refusal, manifest_keep_reason)
from s19_app.tui.services.manifest_writer import check_project_files

S19 = b"S00600004844521B\nS9030000FC\n"


def setup(tag, case_sensitive=False):
    root = fresh(tag)
    P = wa(root / "app") / "P"
    P.mkdir(parents=True)
    if case_sensitive:
        r = subprocess.run(["fsutil", "file", "setCaseSensitiveInfo", str(P), "enable"],
                           capture_output=True, text=True)
        print("   fsutil:", (r.stdout or r.stderr).strip()[-40:])
    out = root / "outside"
    out.mkdir()
    (out / "secret.json").write_text('{"outside": true}')
    (out / "secret.s19").write_bytes(S19)
    return root, P, out


def write(P, payload):
    (P / "project.json").write_text(json.dumps(payload), encoding="utf-8")


def accepted(m):
    return (list(m.batch) + [p for v in m.assignments.values() for p in v]
            + [p for v in m.gathered.values() for p in v] + list(m.files) + list(m.derived_from))


def report(tag, m, P):
    print(f"[{tag}] issues: {[(i.code, i.details.get('entry')) for i in m.issues]}")
    root = Path(os.path.realpath(P))
    for p in accepted(m):
        real = Path(os.path.realpath(p))
        where = "INSIDE" if real.is_relative_to(root) else f"OUTSIDE -> {real}"
        print(f"   accepted: {str(Path(p).relative_to(P))!r:34} {where} exists={os.path.exists(p)}")


links = []
which = sys.argv[1:] or ["W1", "W2", "W3", "W4"]
try:

    if "W1" in which:
        root, P, out = setup("W1")
        (P / "real").mkdir()
        (P / "real" / "a.json").write_text("{}")
        junction(P / "jdir", out); links.append(P / "jdir")
        junction(P / "real" / "inner", out); links.append(P / "real" / "inner")
        write(P, {"schema_version": 1,
                  "batch": ["jdir/secret.json", "./jdir/secret.json", "real/../jdir/secret.json",
                            "real\\..\\jdir\\secret.json", "JDIR/secret.json", "real/inner/secret.json",
                            "real/./inner/secret.json", "real/a.json"],
                  "assignments": {"firmware": ["jdir/secret.json"]},
                  "gathered": {"patches": ["real/inner/secret.json"]}})
        m = read_project_manifest(P)
        report("W1 intermediate junction", m, P)

    if "W2" in which:
        cases = ((["sub/a.json", "SUB/secret.json"], "W2a real-then-junction"),
                 (["SUB/secret.json", "sub/a.json"], "W2b junction-first"),
                 (["sub/missing.json", "SUB/secret.json"], "W2c missing-name-then-junction"))
        for order, tag in cases:
            root, P, out = setup(tag.split()[0], case_sensitive=True)
            if "missing" not in tag:
                (P / "sub").mkdir()
                (P / "sub" / "a.json").write_text("{}")
            junction(P / "SUB", out); links.append(P / "SUB")
            write(P, {"schema_version": 1, "batch": order,
                      "assignments": {"firmware": list(order)}, "gathered": {"patches": list(order)}})
            m = read_project_manifest(P)
            print(f"   folder entries: {sorted(os.listdir(P))}")
            report(tag, m, P)
            print("   rewrite refusal:", manifest_rewrite_refusal(m))
        root, P, out = setup("W2d", case_sensitive=True)
        (P / "a.s19").write_bytes(S19 * 2)
        try:
            os.symlink(out / "secret.s19", P / "A.s19"); links.append(P / "A.s19")
            sym = True
        except OSError as e:
            sym = False
            print("   symlink not available:", e)
        if sym:
            od = hashlib.sha256((out / "secret.s19").read_bytes()).hexdigest()
            idg = hashlib.sha256((P / "a.s19").read_bytes()).hexdigest()
            write(P, {"schema_version": 1,
                      "files": {"a.s19": {"size": (P / "a.s19").stat().st_size, "sha256": idg},
                                "A.s19": {"size": len(S19), "sha256": od}},
                      "derived_from": {"a.s19": {"base": "A.s19", "sha256": od, "differ": 0}}})
            m = read_project_manifest(P)
            print(f"   folder entries: {sorted(os.listdir(P))}")
            report("W2d files key through a file symlink (case-sensitive)", m, P)
            print("   check_project_files problems:", [(p.kind, p.file) for p in check_project_files(P, m)])
            write(P, {"schema_version": 1,
                      "files": {"A.s19": {"size": len(S19), "sha256": od},
                                "a.s19": {"size": (P / "a.s19").stat().st_size, "sha256": idg}}})
            m = read_project_manifest(P)
            report("W2e control: symlink key first", m, P)

    if "W3" in which:
        root, P, out = setup("W3")
        long = P / "a_long_junction_name_here"
        junction(long, out); links.append(long)
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetShortPathNameW(str(long), buf, 1024)
        short = Path(buf.value).name if n else None
        print("   8.3 name of the junction:", short)
        (P / "f.s19").write_bytes(S19)
        entries = ["f.s19:secret", "f.s19::$DATA", "a_long_junction_name_here./secret.json",
                   "a_long_junction_name_here /secret.json", "a_long_junction_name_here　/secret.json"]
        if short and short != long.name:
            entries += [f"{short}/secret.json", f"{short.lower()}/secret.json"]
        write(P, {"schema_version": 1, "batch": entries})
        m = read_project_manifest(P)
        report("W3 short name / ADS / dots / spaces", m, P)

    if "W4" in which:
        root, P, out = setup("W4")
        junction(P / "jdir", out); links.append(P / "jdir")
        (P / "keep.json").write_text("{}")
        (P / "firmware.s19").write_bytes(S19)
        write(P, {"schema_version": 1, "batch": [f"m{i}.json" for i in range(1000)],
                  "assignments": {"firmware": [f"n{i}.json" for i in range(1000)]},
                  "gathered": {"patches": ["jdir/secret.json", "keep.json"]},
                  "files": {"firmware.s19": {"size": 1, "sha256": "0" * 64}},
                  "derived_from": {"firmware.s19": {"base": "keep.s19", "sha256": "0" * 64, "differ": 0}}})
        calls = []
        real_lstat = V.os.lstat

        def counting(p, *a, **k):
            calls.append(str(p))
            return real_lstat(p, *a, **k)
        V.os.lstat = counting
        try:
            m = read_project_manifest(P)
        finally:
            V.os.lstat = real_lstat
        rel = lambda xs: [str(Path(x).relative_to(P)) for x in xs]
        print(f"[W4 ceiling] lstat calls={len(calls)} batch={len(m.batch)} assignments={ {k: len(v) for k, v in m.assignments.items()} } "
              f"gathered={ {k: rel(v) for k, v in m.gathered.items()} } files={rel(m.files)} derived_from={rel(m.derived_from)}")
        print("   fold:", [i.message for i in m.issues if 'more manifest entries' in i.message])
        print("   any lstat of jdir:", any('jdir' in c for c in calls), "| rewrite refusal:",
              manifest_rewrite_refusal(m), "| keep reason (Save project):", manifest_keep_reason(m))


finally:
    for l in reversed(links):
        try:
            if os.path.isdir(l) and not os.path.islink(l):
                os.rmdir(l)
            else:
                os.unlink(l)
        except OSError as e:
            print("  cleanup failed:", l, e)
    print("# links created:", len(links), "| removed:", sum(not os.path.lexists(l) for l in links))
