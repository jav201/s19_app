"""Batch-93 visual verdict sheet: real captures of the shipped app + the charter.

Captures the Memory Map screen and the legend sheet from the real S19TuiApp
(driven headless over examples/case_07_stress_smoke, the house fixture policy),
embeds them beside the charter's chosen variant-C / legend-A captures and the
baseline reference, and emits the accept/adjust sheet with the download-JSON
script (the batch-06 precedent).
"""
import asyncio
import base64
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path("C:/Users/jjgh8/Github/s19_app")
OUT = ROOT / ".dev-flow/2026-10-11-batch-93/evidence"
FIXTURE = ROOT / "examples/case_07_stress_smoke"


async def capture(svg_path: Path, size: tuple[int, int], keys: list[str],
                  title: str, tmp: Path) -> None:
    from s19_app.tui.app import S19TuiApp
    ws = tmp / f"ws-{size[0]}x{size[1]}-{len(keys)}"
    ws.mkdir(parents=True, exist_ok=True)
    for f in FIXTURE.iterdir():
        if f.is_file():
            shutil.copy(f, ws / f.name)
    app = S19TuiApp(base_dir=ws)
    async with app.run_test(size=size) as pilot:
        for k in keys:
            await pilot.press(k)
            for _ in range(4):
                await pilot.pause()
        svg_path.write_text(app.export_screenshot(title=title), encoding="utf-8")


def b64(p: Path) -> str:
    return base64.b64encode(p.read_bytes()).decode("ascii")


async def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="b93-verdict-", dir=str(OUT)))
    caps = {}
    jobs = [
        ("map-120x36", (120, 36), ["4"], "s19tui - Memory Map 120x36 (batch-93)"),
        ("map-80x24", (80, 24), ["4"], "s19tui - Memory Map 80x24 stacked (batch-93)"),
        ("legend-120x36", (120, 36), ["4", "k"], "s19tui - the k legend spec sheet (batch-93)"),
    ]
    for stem, size, keys, title in jobs:
        p = tmp / f"{stem}.svg"
        await capture(p, size, keys, title, tmp)
        caps[stem] = p
        print("captured:", stem)

    protos = {
        "charter-map-C": ROOT / "prototypes/memmap2_map_C_160x48.120w.svg",
        "charter-legend-A": ROOT / "prototypes/memmap2_legend_A.120w.svg",
        "charter-baseline-map": ROOT / "prototypes/memmap2_baseline_map.120w.svg",
    }
    figs = "".join(
        f'<figure><figcaption>{cap}</figcaption><img src="data:image/svg+xml;base64,{b64(svg)}"></figure>'
        for cap, svg in caps.items())
    figs += "".join(
        f'<figure><figcaption>charter: {name}</figcaption><img src="data:image/svg+xml;base64,{b64(p)}"></figure>'
        for name, p in protos.items() if p.is_file())

    SECTIONS = [
        ("B93-1", "El mapa a 120x36 -- la cabina: lista de regiones scrolleable + inspector de altura completa"),
        ("B93-2", "El mapa a 80x24 -- el regimen apilado (list sobre inspector)"),
        ("B93-3", "La leyenda k -- la spec sheet agrupada con la band key viva"),
        ("B93-4", "Contra la varianza C del charter y la linea base (referencia)"),
    ]
    sections = "".join(
        f'<section><h3>{sid} -- {label}</h3>'
        f'<label><input type="radio" name="{sid}" value="accept"> Aceptar</label> · '
        f'<label><input type="radio" name="{sid}" value="adjust"> Ajustar (nota abajo)</label></section>'
        for sid, label in SECTIONS)

    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Veredicto — batch-93 (Memory Map cockpit + legend A)</title>
<style>body{{font-family:system-ui;margin:2rem auto;max-width:960px;color:#e6edf3;background:#0d1117}}
figure{{margin:1rem 0}}figcaption{{color:#8b98a5;font-size:.85rem;margin-bottom:.3rem}}
img{{max-width:100%;border:1px solid #30363d;border-radius:6px;background:#000}}
section{{border-top:1px solid #30363d;padding:1rem 0}}
button{{font-size:1rem;padding:.6rem 1.2rem;border-radius:6px;border:0;background:#2dd4bf;color:#0d1117;font-weight:600;cursor:pointer}}
textarea{{width:100%;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:6px}}</style></head><body>
<h1>Veredicto — batch-93: la cabina del Memory Map + la leyenda spec sheet</h1>
<p>Capturas REALES de la app embarcada (fixture case_07, a color) contra el charter y la linea base. Mira cada una y elige; al final pulsa Descargar y pasame el JSON (como los veredictos anteriores).</p>
{figs}
{sections}
<p><label>Notas / ajustes:<br><textarea id="notes" rows="3"></textarea></label></p>
<p><button onclick="download()">Descargar veredicto JSON</button></p>
<script>function download(){{const a={{}};document.querySelectorAll('section').forEach(s=>{{const id=s.querySelector('h3').textContent.split(' ')[0];const p=s.querySelector('input:checked');a[id]={{choice:p?p.value:"",label:p?p.nextSibling.textContent.trim():""}}}});a.notes=document.getElementById('notes').value;const b=new Blob([JSON.stringify({{batch:"2026-10-11-batch-93",exported:new Date().toISOString(),answers:a}},null,2)],{{type:"application/json"}});const e=document.createElement("a");e.href=URL.createObjectURL(b);e.download="taskboard-veredicto-batch93.json";e.click()}}</script>
</body></html>"""
    (OUT / "veredicto-batch93.html").write_text(html, encoding="utf-8")
    print("sheet:", OUT / "veredicto-batch93.html", f"({len(html)} bytes)")
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
