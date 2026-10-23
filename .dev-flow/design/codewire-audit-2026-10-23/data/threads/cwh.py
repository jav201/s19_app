"""Code-Wire data audit (2026-10-23): shared helpers for the thread tests (throwaway, evidence only).

Each thread test builds its own temp base dir (`<tmp>/.s19tool/workarea`) and never writes in the
checkout. Example data comes from `examples/` only. `mini_s19` is an independent reader that shares
no code with the repo (copied from the integrity investigation's `common.py`).
"""
import asyncio
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

WT = Path(__file__).resolve().parents[1]
EX = WT / "examples"
C1 = EX / "case_01_basic_valid"
C2 = EX / "case_02_gaps_and_patch_targets"
C3 = EX / "case_03_overlapping_records"
PUB = EX / "case_00_public"


def new_base(prefix="cwaudit_"):
    base = Path(tempfile.mkdtemp(prefix=prefix))
    (base / ".s19tool" / "workarea").mkdir(parents=True)
    os.chdir(base)
    return base


def new_project(base, name="P", files=()):
    proj = base / ".s19tool" / "workarea" / name
    proj.mkdir(parents=True, exist_ok=True)
    for src in files:
        shutil.copyfile(src, proj / Path(src).name)
    return proj


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:12]


def mini_s19(path):
    """Independent S19 reader: S1/S2/S3 data only, checksum checked -> (mem, errors, meta)."""
    mem, errs, meta = {}, [], {"s0": None, "term": None}
    alen = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        t = line[1]
        raw = bytes.fromhex(line[2:])
        if raw[0] != len(raw) - 1:
            errs.append((n, "count"))
            continue
        a = int.from_bytes(raw[1:1 + alen[t]], "big")
        data = raw[1 + alen[t]:-1]
        if t in "123":
            for i, b in enumerate(data):
                mem[a + i] = b
        elif t == "0":
            meta["s0"] = bytes(data)
        elif t in "789":
            meta["term"] = ("S" + t, a)
    return mem, errs, meta


def new_app(base):
    from s19_app.tui.app import S19TuiApp
    app = S19TuiApp(base_dir=base)
    app._probe_status = []
    app._probe_notes = []
    orig_status = app.set_status

    def rec_status(msg):
        app._probe_status.append(msg)
        orig_status(msg)

    app.set_status = rec_status
    orig_notify = app.notify

    def rec_notify(message, *a, **k):
        app._probe_notes.append((k.get("severity", "information"), str(message)))
        return orig_notify(message, *a, **k)

    app.notify = rec_notify
    return app


async def settle(app, pilot, n=6):
    for _ in range(n):
        await pilot.pause()
        try:
            await app.workers.wait_for_complete()
        except Exception:
            pass
    await pilot.pause()


async def load_path(app, pilot, path):
    app._load_path_from_user_input(Path(path))
    await settle(app, pilot)


def patch_action(app, action, **kw):
    from s19_app.tui.screens_directionb import PatchEditorPanel as P
    app.on_patch_editor_panel_action_requested(P.ActionRequested(action, **kw))


def run_app(coro_fn, base):
    app = new_app(base)

    async def main():
        async with app.run_test(size=(200, 60)) as pilot:
            await settle(app, pilot)
            await coro_fn(app, pilot)

    asyncio.run(main())
    return app


def out(tag, **kv):
    """One evidence line, flushed to stdout (captured by `-s`)."""
    print(f"[{tag}] " + " | ".join(f"{k}={v}" for k, v in kv.items()), flush=True)
