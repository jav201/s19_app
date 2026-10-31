"""Inc 8a security probe U: recorded_document_state, classify_active_document,
the form predicate and writer/reader symmetry, on the Inc 8a tree.
U1 hostile documents under the caps (time + outcome, 0 raises)
U2 parse fuzz: field values that might raise outside the classifier's catch set
U3 links / held file / swap between lstat and open
U4 form + writer/reader symmetry matrix
U5 classify_active_document: link source, junction parent under the work area"""
import ctypes, json, os, subprocess, sys, time, shutil, itertools
from pathlib import Path

WT = Path(r"C:\Users\jjgh8\Github\s19_app-b100-inc8a")
sys.path.insert(0, str(WT))
import s19_app
print("# s19_app import:", s19_app.__file__)
print("# NO_COLOR present:", "NO_COLOR" in os.environ, "| python", sys.version.split()[0])
from s19_app.tui import app as A
from s19_app.tui.services import variant_execution_service as V
from s19_app.tui.services import manifest_writer as MW
from s19_app.tui.services import project_gather_service as G
from tests.support.b100_projects import change_document_bytes, address_entry, held_exclusively

SCR = Path(__file__).resolve().parent / "runs"
SCR.mkdir(exist_ok=True)
which = sys.argv[1:] or ["U1", "U2", "U3", "U4", "U5"]
created_links = []


def fresh(tag):
    d = SCR / (tag.split()[0] + f"_{time.time_ns()}")
    d.mkdir(parents=True)
    return d


def junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stdout + r.stderr)
    created_links.append(Path(link))


def symlink(link, target):
    try:
        os.symlink(target, link)
        created_links.append(Path(link))
        return True
    except OSError as e:
        print("  (symlink not permitted:", type(e).__name__, e.winerror if hasattr(e, "winerror") else "", ")")
        return False


def project(root, body):
    p = root / ".s19tool" / "workarea" / "P"
    (p / "patches").mkdir(parents=True)
    if body is not None:
        (p / "patches" / "boost.json").write_bytes(body)
    return p


def classify(tag, body, a2l=None):
    p = project(fresh(tag), body)
    t = time.perf_counter()
    try:
        st = A.recorded_document_state(p, "patches/boost.json", a2l)
        out = f"outcome={st.outcome} detail={st.detail[:60]!r} entries={len(st.document.entries) if st.document else '-'}"
    except BaseException as e:  # noqa
        out = f"RAISED {type(e).__name__}: {str(e)[:80]}"
    dt = time.perf_counter() - t
    print(f"  {tag:<34} bytes={len(body) if body is not None else '-':>8} {out} t={dt:.3f}s")
    return out


def doc(entries):
    return json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change",
                       "encoding": "utf-8", "value_mode": "text", "entries": entries},
                      separators=(",", ":")).encode()


if "U1" in which:
    print("== U1 hostile documents under / at the caps")
    classify("U1a 1 MiB of [", b"[" * 1_048_576)
    classify("U1b entries + 1e6 [", b'{"entries":' + b"[" * 1_000_000)
    classify("U1c 5000-digit int", b'{"format":"s19app-changeset","entries":[' + b"1" * 5000 + b"]}")
    classify("U1d entries: 5", b'{"entries": 5}')
    classify("U1e 1 MiB + 1 byte", b" " * 1_048_577)
    big = doc([address_entry(0x80000000 + 4 * i, (1, 2)) for i in range(20_000)])
    classify("U1f 20 000 entries", big)
    small = doc([{"type": "bytes"} for _ in range(1001)])
    classify("U1g 1 001 tiny entries", small)
    # 1 000 entries filling ~1 MiB, disjoint and all-overlapping
    run = tuple(range(256)) + tuple(range(70))
    disjoint = doc([address_entry(0x80000000 + 0x1000 * i, run) for i in range(1000)])
    classify("U1h 1 000 x 326 B disjoint", disjoint)
    overl = doc([address_entry(0x80000000, run) for _ in range(1000)])
    classify("U1i 1 000 x 326 B overlapping", overl)
    sym = doc([dict(address_entry(0x80000000 + 4 * i, (1,)), symbol=f"S{i}") for i in range(1000)])
    classify("U1j 1 000 symbol entries no A2L", sym)
    classify("U1k UTF-16 BOM document", "\ufeff".encode("utf-16-le") + doc([]).decode().encode("utf-16-le"))
    classify("U1l UTF-8 BOM document", b"\xef\xbb\xbf" + doc([address_entry(0x80000000, (1,))]))
    classify("U1m deep nested object in entry", doc([{"type": "bytes", "address": "0x0", "bytes": "01", "x": None}]).replace(b'null', b'[' * 900 + b']' * 900))
    classify("U1n 999 deep nesting value", doc([address_entry(0, (1,))]).replace(b'"0x00000000"', b'[' * 200000 + b']' * 200000)[:1_048_576])

if "U2" in which:
    print("== U2 parse fuzz: per-field hostile values (only exceptions outside the catch set matter)")
    base = address_entry(0x80000010, (0xDE, 0xAD))
    values = [None, True, False, 0, -1, 1.5, 1e308, "1e400", 10**300, "", "x" * 2000, [], {}, [1], {"a": 1},
              "0x" + "F" * 400, "-0x10", "0x", " 0x10", "0x10\u0000", "\ud800", "NaN", float("nan") if False else 0.0]
    top_fields = ["format", "version", "kind", "encoding", "value_mode", "entries"]
    entry_fields = ["type", "address", "bytes", "symbol", "value", "length", "text", "mode", "note", "offset", "size",
                    "value_mode", "encoding", "expected", "mask", "id", "label"]
    escapes = {}
    count = 0
    for field in top_fields:
        for v in values:
            d = {"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8",
                 "value_mode": "text", "entries": [base]}
            d[field] = v
            try:
                data = json.dumps(d).encode()
            except (ValueError, TypeError):
                continue
            count += 1
            p = project(fresh("U2"), data) if False else None
            try:
                st = A.parse_change_document(data)
            except A._DOCUMENT_PARSE_ERRORS:
                pass
            except BaseException as e:  # noqa
                escapes.setdefault(type(e).__name__, []).append(f"top {field}={str(v)[:30]!r}")
    for kind in ("bytes", "text", "u8", "u16", "u32", "float", "string", "symbol", "fill", "check", "crc"):
        for field in entry_fields:
            for v in values:
                e = dict(base, type=kind)
                e[field] = v
                d = {"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8",
                     "value_mode": "text", "entries": [e]}
                try:
                    data = json.dumps(d).encode()
                except (ValueError, TypeError):
                    continue
                count += 1
                try:
                    A.parse_change_document(data)
                except A._DOCUMENT_PARSE_ERRORS:
                    pass
                except BaseException as ex:  # noqa
                    escapes.setdefault(type(ex).__name__, []).append(f"entry type={kind} {field}={str(v)[:30]!r}")
    # entries that are not objects
    for v in values:
        d = {"format": "s19app-changeset", "version": "2.0", "kind": "change", "entries": [v]}
        try:
            data = json.dumps(d).encode()
        except (ValueError, TypeError):
            continue
        count += 1
        try:
            A.parse_change_document(data)
        except A._DOCUMENT_PARSE_ERRORS:
            pass
        except BaseException as ex:  # noqa
            escapes.setdefault(type(ex).__name__, []).append(f"entry itself={str(v)[:30]!r}")
    # kind check
    for k in ("check", "change", "CHECK", "unknown"):
        d = {"format": "s19app-changeset", "version": "2.0", "kind": k, "entries": [base]}
        count += 1
        try:
            A.parse_change_document(json.dumps(d).encode())
        except A._DOCUMENT_PARSE_ERRORS:
            pass
        except BaseException as ex:  # noqa
            escapes.setdefault(type(ex).__name__, []).append(f"kind={k}")
    print(f"  documents parsed: {count}; exception classes escaping the classifier's catch set: "
          f"{ {k: len(v) for k, v in escapes.items()} }")
    for k, v in escapes.items():
        for line in v[:6]:
            print(f"    {k}: {line}")
    # does any of those reach recorded_document_state as a raise?
    if escapes:
        k, v = next(iter(escapes.items()))
        print("  (see U2b for an end-to-end raise through recorded_document_state)")

if "U3" in which:
    print("== U3 links, held file, swap between lstat and open")
    good = change_document_bytes()
    root = fresh("U3")
    priv = root / "private"
    priv.mkdir()
    (priv / "boost.json").write_bytes(change_document_bytes([address_entry(0x90000000, (0x11,))]))
    # a) home junction
    p = project(root / "a", None)
    os.rmdir(p / "patches")
    junction(p / "patches", priv)
    print("  U3a home is a junction ->", A.recorded_document_state(p, "patches/boost.json").outcome)
    # b) file symlink
    p = project(root / "b", None)
    if symlink(p / "patches" / "boost.json", priv / "boost.json"):
        print("  U3b file is a symlink ->", A.recorded_document_state(p, "patches/boost.json").outcome)
    # c) held exclusively
    p = project(root / "c", good)
    with held_exclusively(p / "patches" / "boost.json"):
        st = A.recorded_document_state(p, "patches/boost.json")
        print("  U3c held (share mode 0) ->", st.outcome, st.detail)
    # d) folder at the file name
    p = project(root / "d", None)
    (p / "patches" / "boost.json").mkdir()
    print("  U3d a folder named boost.json ->", A.recorded_document_state(p, "patches/boost.json").outcome)
    # e) home is a file
    p = root / "e" / ".s19tool" / "workarea" / "P"
    p.mkdir(parents=True)
    (p / "patches").write_bytes(b"x")
    print("  U3e patches is a file ->", A.recorded_document_state(p, "patches/boost.json").outcome)
    # f) swap the home for a junction between the 2nd lstat and the open (accepted ruling-11 class)
    p = project(root / "f", good)
    real_lstat = os.lstat
    calls = {"n": 0}

    def swapping_lstat(path, *a, **k):
        r = real_lstat(path, *a, **k)
        calls["n"] += 1
        if calls["n"] == 2:
            shutil.rmtree(p / "patches")
            junction(p / "patches", priv)
        return r
    A.os.lstat = swapping_lstat
    try:
        st = A.recorded_document_state(p, "patches/boost.json")
    finally:
        A.os.lstat = real_lstat
    addr = [hex(e.address) for e in st.document.entries] if st.document else None
    print(f"  U3f home swapped for a junction after the lstat checks -> {st.outcome}, entries {addr} "
          f"(0x90000000 = the private file was read; ruling 11 window)")
    # g) swap the file for a 20 000-entry file after lstat (bounded read)
    p = project(root / "g", good)
    calls["n"] = 0
    big = doc([address_entry(0x80000000 + 4 * i, (1, 2)) for i in range(20_000)])

    def growing_lstat(path, *a, **k):
        r = real_lstat(path, *a, **k)
        calls["n"] += 1
        if calls["n"] == 2:
            (p / "patches" / "boost.json").write_bytes(big)
        return r
    A.os.lstat = growing_lstat
    t = time.perf_counter()
    try:
        st = A.recorded_document_state(p, "patches/boost.json")
    finally:
        A.os.lstat = real_lstat
    print(f"  U3g file grown to {len(big)} B after the size check -> {st.outcome} ({st.detail}) t={time.perf_counter()-t:.3f}s")
    # h) device-name forms
    p = project(root / "h", good)
    for name in ("CON.json", "NUL.json", "COM1.json", "AUX.json", "con.json", "CONIN$.json", "boost.json::$DATA"):
        text = f"patches/{name}"
        form = V.is_active_document_form(text)
        try:
            st = A.recorded_document_state(p, text).outcome if form else "-"
        except BaseException as e:  # noqa
            st = f"RAISED {type(e).__name__}"
        print(f"  U3h form({text!r})={form} state={st}")

if "U4" in which:
    print("== U4 writer/reader symmetry of active_document")
    root = fresh("U4")
    p = root / ".s19tool" / "workarea" / "P"
    (p / "patches").mkdir(parents=True)
    (p / "checks").mkdir()
    (p / "firmware.s19").write_bytes(b"S00600004844521B\n")
    (p / "patches" / "boost.json").write_bytes(change_document_bytes())
    priv = root / "priv"
    priv.mkdir()
    (priv / "x.json").write_bytes(b"{}")
    (p / "jhome").mkdir()
    texts = ["patches/boost.json", "patches/BOOST.JSON", "patches/boost.JSON", "checks/a.json", "templates/a.json",
             "Patches/boost.json", "patches/a/b.json", "../patches/a.json", "/patches/a.json", "patches\\a.json",
             "patches/a.json\u001b", "patches/a\u0085.json", "patches/a\u007f.json", "patches/.json", "patches/ .json",
             "patches/a.json ", "patches/a.json.", "patches/CON.json", "patches/a:b.json", "patches/a?.json",
             "patches/a*.json", "patches/" + "a" * 250 + ".json", "patches/" + "a" * 32760 + ".json",
             "patches/" + "a" * 40000 + ".json", "", "patches/", 7, None, ["patches/a.json"], "patches/\u202eosj.exe.json"]
    for t in texts:
        writer_text, findings = None, None
        try:
            from s19_app.tui.models import ProjectVariantSet
            from s19_app.tui.workspace import build_variant_set
            vs = build_variant_set("P", [p / "firmware.s19"])
            text, issues = MW.serialize_manifest(vs, p, active_document=t) if False else (None, None)
        except Exception:
            pass
        # writer: serialize with the value
        try:
            import inspect
            sig = inspect.signature(MW.serialize_manifest)
            vs = A.build_variant_set("P", [p / "firmware.s19"])
            out = MW.serialize_manifest(vs, p, active_document=t)
            if isinstance(out, tuple):
                text, issues = out
            else:
                text, issues = out, []
            w = "accept" if text is not None and '"active_document"' in text else f"refuse({len(issues)})"
        except Exception as e:  # noqa
            w = f"RAISE {type(e).__name__}"
        man = {"schema_version": 1, "active_variant": "firmware", "active_document": t}
        (p / "project.json").write_text(json.dumps(man), encoding="utf-8")
        try:
            m = V.read_project_manifest(p)
            r = "accept" if m.active_document is not None else "refuse"
            codes = sorted({i.code for i in m.issues})
        except Exception as e:  # noqa
            r, codes = f"RAISE {type(e).__name__}", []
        sym = "OK " if (w == "accept") == (r == "accept") else "ASYM"
        print(f"  {sym} {str(t)[:40]!r:<44} writer={w:<10} reader={r:<7} {codes}")

if "U5" in which:
    print("== U5 classify_active_document")
    root = fresh("U5")
    wa = root / ".s19tool" / "workarea"
    P, Q = wa / "P", wa / "Q"
    (P / "patches").mkdir(parents=True)
    Q.mkdir(parents=True)
    priv = root / "private"
    priv.mkdir()
    (priv / "settings.json").write_bytes(b'{"secret": 1}')
    (P / "patches" / "settings.json").write_bytes(change_document_bytes())
    src = P / "patches" / "settings.json"
    print("  U5a regular source, save into Q ->", G.classify_active_document(Q, src, "patches"))
    print("  U5a' regular source, save into P ->", G.classify_active_document(P, src, "patches"))
    os.remove(src)
    if symlink(src, priv / "settings.json"):
        print("  U5b source is a file symlink, into Q ->", G.classify_active_document(Q, src, "patches"))
        os.remove(src); created_links.remove(src)
    shutil.rmtree(P / "patches")
    junction(P / "patches", priv)
    print("  U5c P/patches is a junction (R18), into Q ->", G.classify_active_document(Q, src, "patches"))
    print("  U5c' same, into P ->", G.classify_active_document(P, src, "patches"))
    # outside any work area through a junction (design choice: supported common library)
    lib = root / "lib"
    lib.mkdir()
    junction(lib / "patches", priv)
    print("  U5d source outside any work area via a junction folder ->",
          G.classify_active_document(Q, lib / "patches" / "settings.json", "patches"))
    # 8.3 / case spelling of the work area anchor
    up = Path(str(src).upper())
    print("  U5e upper-case spelling of the junctioned source, into Q ->", G.classify_active_document(Q, up, "patches"))

for link in reversed(created_links):
    try:
        if link.is_dir() and not link.is_symlink():
            os.rmdir(link)
        else:
            os.remove(link)
    except OSError as e:
        print("  (could not remove", link, e, ")")
left = [str(x) for x in SCR.rglob("*") if (getattr(os.lstat(x), "st_file_attributes", 0) & 0x400) or x.is_symlink()]
print("# links left in runs/:", left)
