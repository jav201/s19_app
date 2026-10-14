"""Batch-95 visual verdict sheet: real captures of the shipped surfaces, in color.

Drives the real S19TuiApp headless (the App.run_test pilot pattern of the batch's
own tests), captures the Split/Join/Export window at both contracted regimes, the
guard state, the open-folder chips and the usage-help modal, and emits the
accept/adjust sheet with the download-JSON script (the batch-06/93 precedent).

The shell exports NO_COLOR=1 / TERM=dumb -- without the color-env fix the SVGs
ship greyscale (the design-notes' incident; the batch's own tests carry the same
``_fix_color_env`` helper).
"""
import asyncio
import base64
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path("C:/Users/jjgh8/Github/s19_app")
OUT = ROOT / ".dev-flow/2026-10-13-batch-95/evidence"
EXAMPLE_PRG = ROOT / "examples" / "case_00_public" / "prg.s19"

#: The batch-95 demo A2L segments (the extracted rows the round signed on),
#: injected as parsed-A2L sections (the hardened extractor's input shape) --
#: the same fixture the batch's own window tests drive.
DEMO_A2L_SECTIONS = [
    {"name": "MEMORY_SEGMENT", "meta": "'AscetCode'",
     "lines": ["CODE FLASH 0x0 0x08000000 0xF800 0x0"], "children": []},
    {"name": "MEMORY_SEGMENT", "meta": "'AscetCalibrationRom'",
     "lines": ["DATA ROM 0x0 0x0800F800 0x800 0x0"], "children": []},
    {"name": "MEMORY_SEGMENT", "meta": "'Variables'",
     "lines": ["DATA RAM 0x0 0x20000000 0x2800 0x0"], "children": []},
]


def _fix_color_env() -> None:
    """The shot path must see a color terminal or the SVG ships greyscale."""
    os.environ.pop("NO_COLOR", None)
    os.environ.pop("CLICOLOR", None)
    os.environ["TERM"] = "xterm-256color"
    os.environ["COLORTERM"] = "truecolor"


def _demo_loaded() -> "object":
    """prg.s19 wrapped the way the load pipeline wraps it (test idiom)."""
    from s19_app.tui.app import LoadedFile
    from s19_app.core import S19File

    s19 = S19File(str(EXAMPLE_PRG))
    return LoadedFile(
        path=EXAMPLE_PRG,
        file_type="s19",
        mem_map=s19.get_memory_map(),
        row_bases=[],
        ranges=s19.get_memory_ranges(),
        range_validity=[True] * len(s19.get_memory_ranges()),
        errors=[],
        a2l_path=None,
        a2l_data={"sections": DEMO_A2L_SECTIONS},
    )


async def _pause(pilot) -> None:
    for _ in range(4):
        await pilot.pause()


async def main() -> None:
    _fix_color_env()
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.segment_split_view import SplitJoinWindow
    from s19_app.tui.window_help import WindowHelpChip

    tmp = Path(tempfile.mkdtemp(prefix="b95-verdict-"))
    caps: dict[str, Path] = {}

    async def sje_split(app: S19TuiApp, pilot) -> None:
        loaded = _demo_loaded()
        app.current_file = loaded
        app.current_a2l_data = loaded.a2l_data
        await _pause(pilot)
        app.action_open_split_join_export()
        await _pause(pilot)
        window = app.query_one("#screen_split_join", SplitJoinWindow)
        window.action_cycle_tab()  # ranges -> manual
        window.action_cycle_tab()  # manual -> a2l
        await _pause(pilot)
        window.action_select_all()
        await _pause(pilot)

    # B95-1: the wide regime -- split, the A2L source selected, gantt visible.
    app = S19TuiApp(base_dir=tmp / "w1")
    async with app.run_test(size=(120, 36)) as pilot:
        await sje_split(app, pilot)
        p = tmp / "sje-120x36.svg"
        p.write_text(app.export_screenshot(title="s19tui - Split/Join/Export 120x36 (batch-95)"), encoding="utf-8")
        caps["sje-120x36"] = p
    print("captured: sje-120x36")

    # B95-2: the floor -- same state at 80x24 (pane 30, gantt hidden by CSS).
    app = S19TuiApp(base_dir=tmp / "w2")
    async with app.run_test(size=(80, 24)) as pilot:
        await sje_split(app, pilot)
        p = tmp / "sje-80x24.svg"
        p.write_text(app.export_screenshot(title="s19tui - Split/Join/Export 80x24 (batch-95)"), encoding="utf-8")
        caps["sje-80x24"] = p
    print("captured: sje-80x24")

    # B95-3: the guard state -- join=fill over the demo A2L, first ^E arms only.
    app = S19TuiApp(base_dir=tmp / "w3")
    async with app.run_test(size=(120, 36)) as pilot:
        loaded = _demo_loaded()
        app.current_file = loaded
        app.current_a2l_data = loaded.a2l_data
        await _pause(pilot)
        app.action_open_split_join_export()
        await _pause(pilot)
        window = app.query_one("#screen_split_join", SplitJoinWindow)
        window.action_cycle_tab()
        window.action_cycle_tab()
        await _pause(pilot)
        window.action_select_all()
        window.action_toggle_mode()   # split -> join
        window.action_cycle_gap()     # concat -> fill
        await _pause(pilot)
        await pilot.press("e")        # first ^E: arm only, 0 bytes
        await _pause(pilot)
        p = tmp / "sje-guard.svg"
        p.write_text(app.export_screenshot(title="s19tui - SJE guard armed 120x36 (batch-95)"), encoding="utf-8")
        caps["sje-guard"] = p
    print("captured: sje-guard")

    # B95-4: the open-folder chip on the Patch Editor header (the other three
    # windows carry the same chip on the same row).
    app = S19TuiApp(base_dir=tmp / "w4")
    async with app.run_test(size=(120, 36)) as pilot:
        await _pause(pilot)
        app.action_show_screen("patch")
        await _pause(pilot)
        p = tmp / "chips-patch.svg"
        p.write_text(app.export_screenshot(title="s19tui - Patch Editor, open-folder chip (batch-95)"), encoding="utf-8")
        caps["chips-patch"] = p
    print("captured: chips-patch")

    # B95-5: the usage-help modal from the SJE window's ? chip (the ninth
    # authored section, mounted by inc-004).
    app = S19TuiApp(base_dir=tmp / "w5")
    async with app.run_test(size=(120, 36)) as pilot:
        loaded = _demo_loaded()
        app.current_file = loaded
        app.current_a2l_data = loaded.a2l_data
        await _pause(pilot)
        app.action_open_split_join_export()
        await _pause(pilot)
        window = app.query_one("#screen_split_join", SplitJoinWindow)
        window.query_one("#window_help_split_join_export", WindowHelpChip).press()
        await _pause(pilot)
        p = tmp / "help-sje.svg"
        p.write_text(app.export_screenshot(title="s19tui - SJE usage help (batch-95)"), encoding="utf-8")
        caps["help-sje"] = p
    print("captured: help-sje")

    def b64(p: Path) -> str:
        return base64.b64encode(p.read_bytes()).decode("ascii")

    figs = "".join(
        f'<figure><figcaption>{cap}</figcaption><img src="data:image/svg+xml;base64,{b64(svg)}"></figure>'
        for cap, svg in caps.items())

    SECTIONS = [
        ("B95-1", "La ventana Split/Join/Export a 120x36 -- el regimen amplio (visor 58, banda 54, gantt por archivo visible)"),
        ("B95-2", "La misma ventana a 80x24 -- el piso (pane 30, gantt oculto, las cuatro clases del visor)"),
        ("B95-3", "El estado GUARD -- join=fill sobre los 3 MEMORY_SEGMENT del demo A2L; el primer ^E solo arma (0 bytes escritos)"),
        ("B95-4", "El chip de abrir carpeta en el header del Patch Editor (Checks / CRC Designer / Reports llevan el mismo chip)"),
        ("B95-5", "La ayuda de uso de la ventana (la seccion Split / Join / Export, montada por inc-004)"),
    ]
    sections = "".join(
        f'<section><h3>{sid} -- {label}</h3>'
        f'<label><input type="radio" name="{sid}" value="accept"> Aceptar</label> · '
        f'<label><input type="radio" name="{sid}" value="adjust"> Ajustar (nota abajo)</label></section>'
        for sid, label in SECTIONS)

    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Veredicto — batch-95 (Split/Join/Export + cambios 10-12)</title>
<style>body{{font-family:system-ui;margin:2rem auto;max-width:960px;color:#e6edf3;background:#0d1117}}
figure{{margin:1rem 0}}figcaption{{color:#8b98a5;font-size:.85rem;margin-bottom:.3rem}}
img{{max-width:100%;border:1px solid #30363d;border-radius:6px;background:#000}}
section{{border-top:1px solid #30363d;padding:1rem 0}}
button{{font-size:1rem;padding:.6rem 1.2rem;border-radius:6px;border:0;background:#2dd4bf;color:#0d1117;font-weight:600;cursor:pointer}}
textarea{{width:100%;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:6px}}</style></head><body>
<h1>Veredicto — batch-95: Split/Join/Export + save-gather + chips de carpeta + ayuda por ventana + cambios A2L</h1>
<p>Capturas REALES de la app embarcada (prg.s19 del caso 00 + los MEMORY_SEGMENT del demo A2L, a color) —
las cinco superficies que el batch tocó. Mira cada una y elige; al final pulsa Descargar y pásame el JSON
(como los veredictos anteriores).</p>
{figs}
{sections}
<p><label>Notas / ajustes:<br><textarea id="notes" rows="3"></textarea></label></p>
<p><button onclick="download()">Descargar veredicto JSON</button></p>
<script>function download(){{const a={{}};document.querySelectorAll('section').forEach(s=>{{const id=s.querySelector('h3').textContent.split(' ')[0];const p=s.querySelector('input:checked');a[id]={{choice:p?p.value:"",label:p?p.nextSibling.textContent.trim():""}}}});a.notes=document.getElementById('notes').value;const b=new Blob([JSON.stringify({{batch:"2026-10-13-batch-95",exported:new Date().toISOString(),answers:a}},null,2)],{{type:"application/json"}});const e=document.createElement("a");e.href=URL.createObjectURL(b);e.download="veredicto-batch95.json";e.click()}}</script>
</body></html>"""
    (OUT / "veredicto-batch95.html").write_text(html, encoding="utf-8")
    print("sheet:", OUT / "veredicto-batch95.html", f"({len(html)} bytes)")
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
