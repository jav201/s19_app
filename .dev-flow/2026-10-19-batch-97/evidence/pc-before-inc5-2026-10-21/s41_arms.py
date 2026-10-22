"""Throwaway spike (PC before Inc-5, S4-1): a NUL pasted into each Builder add
input at HEAD — is the block added, and what does Run paint?"""
import asyncio, sys, tempfile
from pathlib import Path
REPO = Path(r"C:\Users\jjgh8\Github\s19_app")
sys.path.insert(0, str(REPO))
from textual import events
from textual.widgets import Input, Select, Button
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import make_project, load_project

NUL = "x\x00y.s19"
ARMS = [  # (arm, kind, {input_id: value}, paste_into)
    ("source.image_ref", "source", {}, "#flow_ref"),
    ("patch.change_doc_ref", "patch", {}, "#flow_ref"),
    ("check.check_doc_ref", "check", {}, "#flow_ref"),
    ("crc.config_ref", "crc", {}, "#flow_ref"),
    ("write_out.output_name", "write_out", {}, "#flow_ref"),
    ("a2b.image_a.ref", "a2b", {"#flow_ref_b": "#1"}, "#flow_ref_a"),
    ("a2b.image_b.ref", "a2b", {"#flow_ref_a": "#1"}, "#flow_ref_b"),
    ("external_step.log_ref", "external_step", {"#flow_ext_instruction": "echo hi", "#flow_ext_output": "o.s19"}, "#flow_ext_log"),
    ("external_step.output_path", "external_step", {"#flow_ext_instruction": "echo hi", "#flow_ext_log": "r.log"}, "#flow_ext_output"),
]

async def settled(pilot, n=6):
    for _ in range(n):
        await pilot.pause()

def texts(widget):
    out = []
    for w in widget.walk_children():
        try:
            t = str(w.render())
        except Exception:
            continue
        if t.strip() and not t.startswith("<textual"):
            out.append(t)
    return out

async def arm(name, kind, others, target):
    with tempfile.TemporaryDirectory(dir=".", ignore_cleanup_errors=True) as td:
        app = S19TuiApp(base_dir=Path(td))
        async with app.run_test(size=(118, 54)) as pilot:
            make_project(app); load_project(app)
            app.action_show_screen("flow"); await settled(pilot)
            panel = app.query_one("FlowBuilderPanel")
            panel.query_one("#flow_kind", Select).value = "source"; await settled(pilot)
            panel.query_one("#flow_ref", Input).value = "prg.s19"
            panel.query_one("#flow_add", Button).press(); await settled(pilot)
            panel.query_one("#flow_kind", Select).value = kind; await settled(pilot)
            for wid, val in others.items():
                panel.query_one(wid, Input).value = val
            inp = panel.query_one(target, Input); inp.focus(); await settled(pilot)
            inp.post_message(events.Paste(NUL)); await settled(pilot)
            pasted = "\x00" in inp.value
            n0 = len(panel._blocks)
            panel.query_one("#flow_add", Button).press(); await settled(pilot)
            added = len(panel._blocks) > n0
            notice = panel.query_one("#flow_wiring_notice")
            ntext = str(notice.render()) if notice.display else ""
            raised = None
            try:
                panel.query_one("#flow_run", Button).press(); await settled(pilot, 12)
            except Exception as exc:  # pragma: no cover
                raised = repr(exc)
            res = texts(panel.query_one("#flow_result"))
            raw = [t for t in res if "ValueError" in t or "\x00" in t or "embedded null" in t]
            codes = [t for t in res if "UNSAFE" in t or "ESCAPE" in t]
            print(f"{name:28s} pasted_nul={pasted} added={added} notice={ntext!r} raised={raised} raw={raw[:2]} codes={codes[:2]}")

async def main():
    for a in ARMS:
        await arm(*a)
asyncio.run(main())
