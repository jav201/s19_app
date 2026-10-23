"""Thread U4: Flow Execution import -> Run -> lane status / run log / report link -> Confirm.

Uses the repo's own A.5 fixtures (tests/b97_fixtures.py) for the project
(prg.s19 + calib_hotfix.json + flows), plus two lanes written here:
  outside_chain   : PATCH with one entry at 0x00020000 (outside prg.s19)
  malformed_chain : PATCH with a change doc that is not JSON
Run is pressed by `enter` with the focus on #fx_run (the repo's run_lanes helper).
"""
import json
from ucommon import *  # noqa: F403
sys.path.insert(0, str(WT / "tests"))


def plain(w):
    try:
        r = w.render()
        return str(getattr(r, "plain", r))
    except Exception as exc:  # noqa: BLE001
        return f"<{exc}>"


def lane_dump(panel, i):
    out = {"head": plain(panel.query_one(f"#fx_lane_{i}_head"))}
    cards = []
    j = 0
    while True:
        try:
            c = panel.query_one(f"#fx_card_{i}_{j}")
        except Exception:
            break
        cards.append(" ¦ ".join(plain(ch) for ch in c.children if hasattr(ch, "render")).replace("\n", " / "))
        j += 1
    out["cards"] = cards
    try:
        out["confirm_visible"] = panel.query_one(f"#fx_confirm_{i}").display
    except Exception:
        out["confirm_visible"] = None
    return out


async def main():
    from tests.b97_fixtures import fx_project, write_flow, write_changeset, _bytes_entry, patch_chain_blocks, \
        import_lanes, run_lanes, flash_evidence
    from s19_app.tui.services.flow_model import WriteOutBlock
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 60)) as pilot:
        await settle(app, pilot)
        pdir = fx_project(app)
        write_changeset(pdir / "outside.json", [_bytes_entry(0x00020000, (0xAA, 0xBB))])
        (pdir / "malformed.json").write_text("{not json", encoding="utf-8")
        write_flow(pdir, "outside_chain", patch_chain_blocks("outside.json")[:2] + [WriteOutBlock("out_outside.s19")])
        write_flow(pdir, "malformed_chain", patch_chain_blocks("malformed.json")[:2] + [WriteOutBlock("out_malformed.s19")])
        take(app)
        panel = await import_lanes(app, pilot, "patch_chain", "outside_chain", "malformed_chain", "flash_chain")
        p("== U4.0 imported; recorded =", take(app))
        p("   notice =", plain(panel.query_one("#fx_notice")))
        await run_lanes(app, pilot, panel, key=True)
        await settle(app, pilot, 4)
        p("== U4.1 after Run")
        p("   recorded =", take(app))
        for i, name in enumerate(["patch_chain", "outside_chain", "malformed_chain", "flash_chain"]):
            p(f"   lane {i} {name} =", lane_dump(panel, i))
        p("   fx_log =", plain(panel.query_one("#fx_log")).replace("\n", " / "))
        p("   fx_notice =", plain(panel.query_one("#fx_notice")))
        p("   fx_required =", plain(panel.query_one("#fx_required")))
        rec = panel.last_run_record
        p("   record lanes status =", [(o.chain, o.status, [(b.kind if hasattr(b, 'kind') else type(b).__name__, b.status, b.summary) for b in o.block_results]) for o in rec.outcomes] if hasattr(rec, "outcomes") else rec)
        reports = sorted((pdir / "reports").glob("*.md")) if (pdir / "reports").exists() else []
        p("   reports =", [r.name for r in reports])
        for r in reports:
            txt = r.read_text(encoding="utf-8")
            p(f"   report {r.name} lines with lane rows =", [ln for ln in txt.splitlines() if ln.startswith("|")][:8])
        out_o = pdir / "out_outside.s19"
        p("   out_outside.s19 written? =", out_o.exists(), "| out_malformed.s19 written? =", (pdir / "out_malformed.s19").exists())
        p("== U4.2 Confirm the waiting lane without the evidence files")
        try:
            panel.query_one("#fx_confirm_3").press(); await settle(app, pilot, 6)
        except Exception as exc:  # noqa: BLE001
            p("   confirm press failed:", exc)
        p("   recorded =", take(app)); p("   lane 3 =", lane_dump(panel, 3))
        p("   fx_log =", plain(panel.query_one("#fx_log")).replace("\n", " / "))
        p("== U4.3 evidence written, `c` pressed")
        flash_evidence(pdir)
        await pilot.pause(0.7)
        await pilot.press("c"); await settle(app, pilot, 6)
        p("   recorded =", take(app)); p("   lane 3 =", lane_dump(panel, 3))
        p("   fx_log =", plain(panel.query_one("#fx_log")).replace("\n", " / "))


run(main)
