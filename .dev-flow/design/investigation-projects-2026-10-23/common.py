"""Shared helpers for the project round-trip probes (throwaway, read-only toward the repo).

Run any probe with S19_WT=<snapshot of the tree under test> (a `git archive HEAD`
extract, so the live tree another agent edits is never imported), interpreter
s19env, PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1. Every probe builds its own
temp base dir (``<tmp>/.s19tool/workarea``), chdirs into it (some services
default to ``Path.cwd()``), and passes it as ``S19TuiApp(base_dir=...)``, so
nothing is written under the operator's home or the repo's workarea.
"""
import os, sys, shutil, tempfile, json, hashlib, asyncio
from pathlib import Path


def _find_root():
    if os.environ.get("S19_WT"):
        return Path(os.environ["S19_WT"])
    for parent in Path(__file__).resolve().parents:
        if (parent / "s19_app" / "core.py").exists():
            return parent
    raise SystemExit("set S19_WT to a checkout of s19_app")


WT = _find_root()
sys.path.insert(0, str(WT)); sys.path.insert(0, str(WT / "tests"))
EX = WT / "examples"
C1 = EX / "case_01_basic_valid"


def new_base(prefix="projprobe_"):
    base = Path(tempfile.mkdtemp(prefix=prefix))
    os.chdir(base)
    return base


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:12]


def tree(root):
    """Sorted list of 'relpath  size  sha' for every file under root."""
    root = Path(root)
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append(f"{p.relative_to(root).as_posix()}  {p.stat().st_size}  {sha(p)}")
    return out


def mem_digest(mem):
    if not mem:
        return "none"
    h = hashlib.sha256()
    for a in sorted(mem):
        h.update(a.to_bytes(8, "big")); h.update(bytes([mem[a] & 0xFF]))
    return f"{len(mem)}B/{h.hexdigest()[:12]}"


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
        app._probe_notes.append((k.get("severity", "information"), k.get("title"), str(message)))
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
    """The real Load-file route: dialog callback -> _load_path_from_user_input."""
    app._load_path_from_user_input(Path(path))
    await settle(app, pilot)


def save_project(app, parent, name, batch=(), assignments=None):
    """Drive the real save callback. An exception escaping it is returned (and
    printed) instead of raised: in the running app it would escape a dismiss
    callback."""
    from s19_app.tui.screens import SaveProjectPayload
    try:
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(parent), project_name=name,
                                                   batch=tuple(batch), assignments=dict(assignments or {})))
    except Exception as exc:  # noqa: BLE001
        print(f"   !! _handle_save_dialog RAISED {type(exc).__name__}: {exc}")
        return exc
    return None


def patch_apply(app, address, bytes_text):
    """The Patch Editor's own handler: add an entry, then apply it to the loaded image."""
    from s19_app.tui.screens_directionb import PatchEditorPanel as P
    app.on_patch_editor_panel_action_requested(P.ActionRequested("add_entry", address_text=address, bytes_text=bytes_text))
    app.on_patch_editor_panel_action_requested(P.ActionRequested("apply_doc"))


def snapshot(app):
    f = app.current_file
    cs = app._change_service
    return {
        "file": f.path.name if f else None,
        "file_dir": f.path.parent.name if f else None,
        "mem": mem_digest(f.mem_map) if f else None,
        "mac_path": (f.mac_path.name if f and f.mac_path else None),
        "mac_records": (len(f.mac_records) if f and f.mac_records else 0),
        "a2l_path": (str(app.current_a2l_path.name) if app.current_a2l_path else None),
        "a2l_dir": (app.current_a2l_path.parent.name if app.current_a2l_path else None),
        "a2l_tags": len(app._a2l_enriched_tags or []) if hasattr(app, "_a2l_enriched_tags") else None,
        "project": app.current_project,
        "variants": [v.variant_id for v in app._variant_set.variants] if app._variant_set else None,
        "active_variant": app._variant_set.active_id if app._variant_set else None,
        "change_entries": len(cs.document.entries),
        "change_source": (cs.document.source_path.name if cs.document.source_path else None),
        "declared_regions": len(app._declared_regions),
    }


def run(coro_fn):
    from s19_app.tui.app import S19TuiApp  # noqa: F401 (import before chdir side effects)
    asyncio.run(coro_fn())
