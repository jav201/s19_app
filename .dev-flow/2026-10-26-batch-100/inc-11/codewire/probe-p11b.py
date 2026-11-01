"""Inc 11 E2 baseline probe p11b, on a throwaway copy of 8947666 (work/tree).

Run: python -I probe-p11b.py <tree> <work>
Arms:
  U1  F-fresh direct save: call counts of the save helpers per save, wall time.
  U2  F-open P, save "P" (open project): call counts (R2-2: two save-as-source reads).
  U3  F5 remainder: P records patches/changes.json and holds an identical
      patches/changes_1.json; save as Q: the plan's document row vs the landing.
  U4  LLR-175.1n reachability: a MAC-only session with 1 change entry.
  U5  nothing loaded: direct save status.
  U6  name refusals through the handler (status text per arm).
  U7  dialog contract on the base (constructor, BINDINGS, AUTO_FOCUS, ids).
"""
import asyncio, inspect, shutil, sys, time
from pathlib import Path

tree = Path(sys.argv[1]); work = Path(sys.argv[2])
sys.path.insert(0, str(tree))
import s19_app
print("import:", s19_app.__file__)
import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import SaveProjectPayload, SaveProjectScreen
from tests.support import b100_projects as projects

CASE01 = tree / "examples" / "case_01_basic_valid"


def fresh(name):
    base = work / "p11b" / name
    shutil.rmtree(base.parent / (name + "_src"), ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    return base


class Counter:
    def __init__(self, app):
        self.n = {}
        self.app = app
        for meth in ("_save_as_source_for", "_decide_project_image", "_plan_project_save",
                     "_project_folder_refusal"):
            orig = getattr(app, meth)
            def wrap(*a, _o=orig, _m=meth, **k):
                self.n[_m] = self.n.get(_m, 0) + 1
                return _o(*a, **k)
            setattr(app, meth, wrap)
        orig_fd = app_module._file_digest
        def fd(path, _o=orig_fd):
            self.n["_file_digest"] = self.n.get("_file_digest", 0) + 1
            return _o(path)
        app_module._file_digest = fd
        self._restore = lambda: setattr(app_module, "_file_digest", orig_fd)


def save(app, name):
    app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=name))


async def settle(pilot, n=8):
    for _ in range(n):
        await pilot.pause()


def tree_names(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()) if root.exists() else []


# U1 -------------------------------------------------------------------------
async def u1(app, pilot, log):
    await projects.load_image(pilot, app, CASE01 / "firmware.s19")
    c = Counter(app)
    mark = len(log.messages)
    t0 = time.perf_counter(); save(app, "fresh1"); dt = time.perf_counter() - t0
    await settle(pilot)
    c._restore()
    print("== U1 fresh1 status", log.since(mark))
    print("== U1 counts", dict(sorted(c.n.items())), f"handler_ms={dt*1000:.1f}")
    print("== U1 tree", tree_names(app.workarea / "fresh1"))

# U2 -------------------------------------------------------------------------
async def u2(app, pilot, log):
    await projects.load_project(pilot, app, "P")
    c = Counter(app)
    mark = len(log.messages)
    save(app, "P")
    await settle(pilot)
    c._restore()
    print("== U2 open-project save status", log.since(mark))
    print("== U2 counts", dict(sorted(c.n.items())))
    c = Counter(app)
    mark = len(log.messages)
    save(app, "Q2")
    await settle(pilot)
    c._restore()
    print("== U2 save-as Q2 status", log.since(mark)[:1])
    print("== U2 save-as counts", dict(sorted(c.n.items())))

# U3 -------------------------------------------------------------------------
async def u3(app, pilot, log):
    await projects.load_project(pilot, app, "P")
    plans = []
    orig = app._plan_project_save
    def spy(*a, **k):
        plan = orig(*a, **k); plans.append(plan); return plan
    app._plan_project_save = spy
    mark = len(log.messages)
    save(app, "Q")
    await settle(pilot)
    plan = plans[-1]
    print("== U3 status", log.since(mark))
    print("== U3 plan rows", [(r.role, r.landing.name, r.action) for r in plan.rows])
    print("== U3 plan copies", [e.relative for e in plan.copies])
    q = app.workarea / "Q"
    print("== U3 Q tree", tree_names(q))
    print("== U3 Q active_document", projects.read_manifest(q).get("active_document"))
    print("== U3 document source_path", app._change_service.document.source_path)

# U4 -------------------------------------------------------------------------
async def u4(app, pilot, log):
    app._load_path_from_user_input(CASE01 / "firmware.mac")
    await projects.wait_for(pilot, lambda: app.current_file is not None, "mac load")
    cf = app.current_file
    print("== U4 file_type", cf.file_type, "mem_map", {hex(k): v for k, v in list(cf.mem_map.items())[:4]}, "ranges", cf.ranges)
    entry = app._change_service.add_entry("0x80000000", "", "5A")
    print("== U4 entries", len(app._change_service.document.entries), "kind", app._change_service.document.kind)
    step = app._decide_project_image()
    print("== U4 decide emit", step.emit, "refusal", step.refusal)
    mark = len(log.messages)
    save(app, "macsave")
    await settle(pilot)
    print("== U4 save status", log.since(mark))
    print("== U4 folder exists", (app.workarea / "macsave").exists())

# U5 -------------------------------------------------------------------------
async def u5(app, pilot, log):
    mark = len(log.messages)
    save(app, "nothing")
    await settle(pilot)
    print("== U5 status", log.since(mark), "folder", (app.workarea / "nothing").exists())

# U6 -------------------------------------------------------------------------
async def u6(app, pilot, log):
    await projects.load_image(pilot, app, CASE01 / "firmware.s19")
    for name in ("", "   ", "!!!", "con.txt", "CON", "Reports", "a" * 65, "a b", "AB"):
        mark = len(log.messages)
        save(app, name)
        await settle(pilot, 3)
        print(f"== U6 {name[:12]!r}", log.since(mark))
    print("== U6 folders", sorted(p.name for p in app.workarea.iterdir() if p.is_dir()))

# U7 -------------------------------------------------------------------------
def u7():
    print("== U7 __init__", inspect.signature(SaveProjectScreen.__init__))
    print("== U7 BINDINGS", [getattr(b, "key", b) for b in SaveProjectScreen.__dict__.get("BINDINGS", [])],
          "AUTO_FOCUS", SaveProjectScreen.__dict__.get("AUTO_FOCUS"))
    print("== U7 plan attr", hasattr(SaveProjectScreen, "plan"))
    src = (tree / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8")
    print("== U7 id=\"load_dialog\" count in screens.py", src.count('id="load_dialog"'))
    print("== U7 payload fields", list(SaveProjectPayload.__dataclass_fields__))


def run(name, scenario, prep=None):
    base = fresh(name)
    if prep:
        prep(base)
    projects.run_app(base, scenario)


def prep_ab(base):
    projects.save_case01_project(base, "ab", files=("firmware.s19",))


def prep_p(base):
    projects.save_case01_project(base, "P")


def prep_doc(base):
    wa = base / ".s19tool" / "workarea"
    wa.mkdir(parents=True, exist_ok=True)
    pd = projects.seed_document_project(wa, "P", document="patches/changes.json")
    shutil.copyfile(pd / "patches" / "changes.json", pd / "patches" / "changes_1.json")


run("u1", u1)
run("u2", u2, prep_p)
run("u3", u3, prep_doc)
run("u4", u4)
run("u5", u5)
run("u6", u6, prep_ab)
u7()
