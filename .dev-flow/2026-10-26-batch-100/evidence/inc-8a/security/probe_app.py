"""Inc 8a security probe APP: the real handlers in Textual run_test.
W  pasted-document write (containment, _N, rollback, never deleting a user file)
S  Save project R8 drop/keep on a hostile merge target (no write/copy/delete)
G  gather classifier R11/R18 (source swapped for a link, parent a junction)
D  DoS at the caps (Load handler + panel, Save project)
Painted text is scanned in every scenario (codes, class names, control chars)."""
import json, os, re, shutil, subprocess, sys, time, hashlib
from pathlib import Path

WT = Path(r"C:\Users\jjgh8\Github\s19_app-b100-inc8a")
sys.path.insert(0, str(WT))
import s19_app
print("# s19_app import:", s19_app.__file__)
print("# NO_COLOR present:", "NO_COLOR" in os.environ, "| python", sys.version.split()[0])
import s19_app.tui.app as A
from tests.support import b100_projects as projects
from tests.support.b100_projects import (change_document_bytes, address_entry, held_exclusively,
                                         seed_document_project, read_manifest)

SCR = Path(__file__).resolve().parent / "runs"
SCR.mkdir(exist_ok=True)
which = sys.argv[1:] or ["W", "S", "G", "D"]
CODE = re.compile(r"\b(MF|CHG|MANIFEST|GATHER|WORKAREA)-[A-Z0-9-]+")
EXC = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
PATCH_ADDRESS, PATCH_BYTES = 0x8000007C, (0xDE, 0xAD, 0xBE, 0xEF)
links = []
painted_all = []


def fresh(tag):
    d = SCR / f"{tag}_{time.time_ns()}"
    d.mkdir(parents=True)
    return d


def junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stdout + r.stderr)
    links.append(Path(link))


def symlink(link, target):
    try:
        os.symlink(target, link)
        links.append(Path(link))
        return True
    except OSError as e:
        print("   (symlink not permitted:", type(e).__name__, ")")
        return False


def snap(root):
    out = {}
    root = Path(root)
    if not root.exists():
        return out
    for dp, dns, fns in os.walk(root, followlinks=False):
        keep = []
        for d in dns:
            p = Path(dp) / d
            if getattr(os.lstat(p), "st_file_attributes", 0) & 0x400:
                out[str(p.relative_to(root))] = "<reparse>"
            else:
                keep.append(d)
                out[str(p.relative_to(root)) + "/"] = "<dir>"
        dns[:] = keep
        for f in fns:
            p = Path(dp) / f
            if os.path.islink(p):
                out[str(p.relative_to(root))] = "<symlink>"
                continue
            try:
                out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            except OSError as e:
                out[str(p.relative_to(root))] = f"<unreadable {e.__class__.__name__}>"
    return out


def diff(a, b):
    return {"created": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in a.keys() & b.keys() if a[k] != b[k])}


def scan(tag, lines):
    painted_all.extend(lines)
    codes = sorted({m.group(0) for l in lines for m in CODE.finditer(l)})
    excs = sorted({m.group(0) for l in lines for m in EXC.finditer(l)})
    ctrl = sum(1 for l in lines if CTRL.search(l))
    print(f"   painted[{tag}]: lines={len(lines)} codes={codes} class_names={excs} control_lines={ctrl}")


def show(lines, n=6):
    for l in lines[-n:]:
        print("     |", l[:200])


def src_image(base):
    return projects.copy_sources(base / "sources", projects.CASE01_DIR, "firmware.s19") / "firmware.s19"


def add_entry(app, address=PATCH_ADDRESS, run=PATCH_BYTES):
    app._change_service.add_entry(f"0x{address:08X}", "", " ".join(f"{b:02X}" for b in run))


def doc(entries):
    return json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change",
                       "encoding": "utf-8", "value_mode": "text", "entries": entries},
                      separators=(",", ":")).encode()


# ------------------------------------------------------------------ W
if "W" in which:
    print("== W pasted-document write")
    # W1 baseline
    base = fresh("W1")
    src = src_image(base)

    async def w1(app, pilot, log):
        await projects.load_image(pilot, app, src)
        add_entry(app)
        msgs = await projects.save_project(pilot, app, log, "P")
        return msgs, app._change_service.document.source_path
    msgs, sp = projects.run_app(base / "app", w1)
    P = base / "app" / ".s19tool" / "workarea" / "P"
    print("  W1 new P: files", sorted(snap(P)), "| active_document", read_manifest(P).get("active_document"))
    print("     bound source_path", sp, "| textual (not resolved):", str(sp) == str(P / "patches" / "changes.json"))
    scan("W1", msgs)

    # W2 P exists, P/patches is a junction to Q/patches (another project in the work area)
    base = fresh("W2")
    src = src_image(base)
    wa = base / "app" / ".s19tool" / "workarea"
    Q = wa / "Q"
    (Q / "patches").mkdir(parents=True)
    (Q / "patches" / "changes.json").write_bytes(b'{"q": "own file"}')
    P = wa / "P"
    P.mkdir(parents=True)
    shutil.copy2(src, P / "firmware.s19")
    junction(P / "patches", Q / "patches")
    before_q = snap(Q)

    async def w2(app, pilot, log):
        await projects.load_image(pilot, app, src)
        add_entry(app)
        msgs = await projects.save_project(pilot, app, log, "P")
        return msgs, app._change_service.document.source_path
    msgs, sp = projects.run_app(base / "app", w2)
    print("  W2 P/patches junction -> Q/patches: Q diff", diff(before_q, snap(Q)), "| source_path", sp)
    print("     P manifest active_document:", read_manifest(P).get("active_document") if (P / "project.json").exists() else "<no project.json>")
    show(msgs, 4)
    scan("W2", msgs)

    # W3 _N clash and reuse
    for tag, body in (("W3a different", b'{"user": "different bytes"}'), ("W3b identical", None)):
        base = fresh("W3")
        src = src_image(base)
        wa = base / "app" / ".s19tool" / "workarea"
        P = wa / "P"
        (P / "patches").mkdir(parents=True)
        shutil.copy2(src, P / "firmware.s19")

        async def w3(app, pilot, log, body=body, P=P):
            await projects.load_image(pilot, app, src)
            add_entry(app)
            if body is None:
                (P / "patches" / "changes.json").write_bytes(A.serialize_change_document(app._change_service.document))
            else:
                (P / "patches" / "changes.json").write_bytes(body)
            pre = snap(P)
            msgs = await projects.save_project(pilot, app, log, "P")
            return msgs, pre
        msgs, pre = projects.run_app(base / "app", w3)
        d = diff(pre, snap(P))
        print(f"  {tag}: P diff {d} | active_document {read_manifest(P).get('active_document')}")
        scan(tag, msgs)

    # W4 rollback: manifest write fails after the document write
    for tag, setup in (("W4a fresh P", None), ("W4b P with identical changes.json", "identical"),
                       ("W4c P without patches/", "nopatches")):
        base = fresh("W4")
        src = src_image(base)
        wa = base / "app" / ".s19tool" / "workarea"
        P = wa / "P"
        if setup is not None:
            P.mkdir(parents=True)
            shutil.copy2(src, P / "firmware.s19")
            (P / "user_notes.txt").write_bytes(b"user file")

        async def w4(app, pilot, log, setup=setup, P=P):
            await projects.load_image(pilot, app, src)
            add_entry(app)
            if setup == "identical":
                (P / "patches").mkdir()
                (P / "patches" / "changes.json").write_bytes(A.serialize_change_document(app._change_service.document))
            pre = snap(P)

            def boom(*a, **k):
                raise OSError(28, "No space left on device (injected)")
            app._write_and_verify_manifest = boom
            msgs = await projects.save_project(pilot, app, log, "P")
            return msgs, pre
        msgs, pre = projects.run_app(base / "app", w4)
        print(f"  {tag}: P exists={P.exists()} diff {diff(pre, snap(P))}")
        show(msgs, 2)
        scan(tag, msgs)

# ------------------------------------------------------------------ S
if "S" in which:
    print("== S Save project into a hostile merge target Q (R8 drop/keep)")
    big20k = doc([address_entry(0x80000000 + 4 * i, (1, 2)) for i in range(20_000)])
    cases = [
        ("S1 absent", None, None),
        ("S2 20 000 entries (too_large)", big20k, None),
        ("S3 1 MiB of [ (unreadable)", b"[" * 1_048_576, None),
        ("S4 5000-digit int (unreadable)", b'{"format":"s19app-changeset","entries":[' + b"1" * 5000 + b"]}", None),
        ("S5 held (io_error)", change_document_bytes(), "held"),
        ("S6 Q/patches junction -> private (link)", None, "junction"),
        ("S7 valid 1-entry (ok)", change_document_bytes(), None),
        ("S8 1 001 tiny entries (too_large)", doc([{"type": "bytes"} for _ in range(1001)]), None),
    ]
    for tag, body, mode in cases:
        base = fresh("S")
        src = src_image(base)
        wa = base / "app" / ".s19tool" / "workarea"
        wa.mkdir(parents=True)
        Q = seed_document_project(wa, "Q", body=body if body is not None else None)
        priv = base / "private"
        if mode == "junction":
            projects.junction_home(Q, "patches", priv)
            links.append(Q / "patches")
        pre_q, pre_priv = snap(Q), snap(priv)
        pre_doc = (Q / "patches" / "boost.json").read_bytes() if body is not None and mode != "junction" else None

        async def s(app, pilot, log, mode=mode, Q=Q):
            await projects.load_image(pilot, app, src)
            t = time.perf_counter()
            if mode == "held":
                with held_exclusively(Q / "patches" / "boost.json"):
                    msgs = await projects.save_project(pilot, app, log, "Q")
            else:
                msgs = await projects.save_project(pilot, app, log, "Q")
            return msgs, time.perf_counter() - t
        msgs, dt = projects.run_app(base / "app", s)
        d = diff(pre_q, snap(Q))
        d = {k: [x for x in v if x != "project.json" and not x.startswith("project.json.previous")] for k, v in d.items()}
        doc_same = (Q / "patches" / "boost.json").read_bytes() == pre_doc if pre_doc is not None else "-"
        print(f"  {tag}: save {dt:.2f}s | active_document after = {read_manifest(Q).get('active_document')!r} "
              f"| Q diff (excl. project.json) {d} | doc bytes unchanged {doc_same} | private diff {diff(pre_priv, snap(priv))}")
        show([m for m in msgs if "hange document" in m or "NOT" in m or "could not" in m], 3)
        scan(tag, msgs)

    # S9 refused active_document in the target (R5)
    base = fresh("S9")
    src = src_image(base)
    wa = base / "app" / ".s19tool" / "workarea"
    wa.mkdir(parents=True)
    Q = seed_document_project(wa, "Q", active_document="patches/x\u001b]0;pwn\u0007" + "A" * 300 + ".json")

    async def s9(app, pilot, log):
        await projects.load_image(pilot, app, src)
        return await projects.save_project(pilot, app, log, "Q")
    msgs = projects.run_app(base / "app", s9)
    print("  S9 refused value (ESC/BEL + 300 chars): kept copies", sorted(x.name for x in Q.glob("project.json.previous*")),
          "| longest painted line", max(len(m) for m in msgs))
    show([m for m in msgs if "dropped" in m], 2)
    scan("S9", msgs)

# ------------------------------------------------------------------ G
if "G" in which:
    print("== G gather classifier: reopened P document, then Save project into Q")
    for tag, mode in (("G0 control (no swap)", None), ("G1 file swapped for a symlink", "symlink"),
                      ("G2 P/patches swapped for a junction (R18)", "junction"),
                      ("G3 P/patches junction, save into P", "junction-P")):
        base = fresh("G")
        wa = base / "app" / ".s19tool" / "workarea"
        wa.mkdir(parents=True)
        P = seed_document_project(wa, "P", document="patches/settings.json")
        priv = base / "private"
        priv.mkdir()
        secret = priv / "settings.json"
        secret.write_bytes(change_document_bytes([address_entry(0x80000040, (0x5E, 0xC2))]) + b"\n PRIVATE-MARKER")
        state = {}

        async def g(app, pilot, log, mode=mode, P=P):
            await projects.load_project(pilot, app, "P")
            state["source"] = app._change_service.document.source_path
            state["entries"] = len(app._change_service.document.entries)
            if mode == "symlink":
                os.remove(P / "patches" / "settings.json")
                if not symlink(P / "patches" / "settings.json", secret):
                    return ["<skipped>"]
            elif mode in ("junction", "junction-P"):
                shutil.rmtree(P / "patches")
                junction(P / "patches", priv)
            target = "P" if mode == "junction-P" else "Q"
            state["pre"] = snap(wa / target)
            msgs = await projects.save_project(pilot, app, log, target)
            return msgs
        msgs = projects.run_app(base / "app", g)
        target = wa / ("P" if mode == "junction-P" else "Q")
        files = snap(target)
        leaked = [k for k in files if k.startswith("patches") and k.endswith(".json") and not files[k].startswith("<")
                  and b"PRIVATE-MARKER" in (target / k).read_bytes()]
        print(f"  {tag}: reopened {state.get('entries')} entries from {state.get('source')}")
        print(f"     target diff {diff(state.get('pre', {}), files)} | files holding the private marker: {leaked} "
              f"| active_document {read_manifest(target).get('active_document') if (target/'project.json').exists() else '-'}")
        show([m for m in msgs if "hange document" in m], 2)
        scan(tag, msgs)

# ------------------------------------------------------------------ D
if "D" in which:
    print("== D DoS at the caps: Load handler + panel, Save project")
    run = tuple(range(256)) + tuple(range(70))
    for tag, body in (("D1 1 000 x 326 B (~1 MiB, ok)", doc([address_entry(0x80000000 + 0x1000 * i, run) for i in range(1000)])),
                      ("D2 1 000 overlapping", doc([address_entry(0x80000000, run) for _ in range(1000)])),
                      ("D3 20 000 entries (too_large)", doc([address_entry(0x80000000 + 4 * i, (1, 2)) for i in range(20_000)])),
                      ("D4 1 MiB of [", b"[" * 1_048_576)):
        base = fresh("D")
        wa = base / "app" / ".s19tool" / "workarea"
        wa.mkdir(parents=True)
        seed_document_project(wa, "P", body=body)
        res = {}

        async def dd(app, pilot, log):
            t0 = time.perf_counter()
            res["handler"] = await projects.load_project(pilot, app, "P")
            res["to_idle"] = time.perf_counter() - t0
            res["entries"] = len(app._change_service.document.entries)
            panel_text = projects.load_result_panel_text(app) if app.screen.query("#load_result_dialog") else ""
            res["panel"] = panel_text
            try:
                await projects.dismiss_load_result_panel(pilot, app)
            except Exception:
                pass
            t1 = time.perf_counter()
            msgs = await projects.save_project(pilot, app, log, "P")
            res["save"] = time.perf_counter() - t1
            return log.messages
        msgs = projects.run_app(base / "app", dd)
        print(f"  {tag}: load handler {res['handler']:.2f}s (to settled {res['to_idle']:.2f}s), editor entries {res['entries']}, "
              f"Save project {res['save']:.2f}s")
        scan(tag, msgs + res["panel"].splitlines())

for link in reversed(links):
    try:
        if os.path.isdir(link) and not os.path.islink(link):
            os.rmdir(link)
        elif os.path.lexists(link):
            os.remove(link)
    except OSError as e:
        print("  (could not remove", link, e, ")")
left = []
for dp, dns, fns in os.walk(SCR, followlinks=False):
    for n in dns + fns:
        p = Path(dp) / n
        if os.path.islink(p) or getattr(os.lstat(p), "st_file_attributes", 0) & 0x400:
            left.append(str(p))
print("# links created:", len(links), "| reparse points left under runs/:", left)
scan("ALL", painted_all)
