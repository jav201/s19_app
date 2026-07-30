#!/usr/bin/env python
"""THROWAWAY builder — assembles prototypes/p1-design-defects-review.html.

Inlines the captured Textual SVG frames (namespaced per file so their CSS
classes / clip-path ids cannot collide on one page, cdnjs @font-face stripped —
textLength pins the grid regardless of font) into a single self-contained
review page with variant tabs, state chips and a zoom control.

Rebuild: PYTHONUTF8=1 python prototypes/p1_review_build.py
"""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "p1-design-defects-review.html"

# (section, variant key, variant label, [(state label, filename), ...])
FRAMES = {
    "crc": [
        ("actual", "Actual (defecto)", [
            ("160×44 · cargado", "crc_p1.shipped.160x44.loaded.svg"),
            ("120×30 · bench", "crc_p1.shipped.120x30.bench.svg"),
        ]),
        ("a", "A · Guard rails", [
            ("160×44 · cargado", "crc_p1.variant_A.160x44.loaded.svg"),
            ("120×30 · bench", "crc_p1.variant_A.120x30.bench.svg"),
            ("120×30 · inválido", "crc_p1.variant_A.120x30.invalid.svg"),
            ("80×24 · piso", "crc_p1.variant_A.80x24.bench.svg"),
        ]),
        ("b", "B · Paired + KAT demovido", [
            ("160×44 · cargado", "crc_p1.variant_B.160x44.loaded.svg"),
            ("120×30 · bench", "crc_p1.variant_B.120x30.bench.svg"),
            ("120×30 · inválido", "crc_p1.variant_B.120x30.invalid.svg"),
            ("80×24 · piso", "crc_p1.variant_B.80x24.bench.svg"),
        ]),
        ("c", "C · Vocabulario + strip", [
            ("160×44 · cargado", "crc_p1.variant_C.160x44.loaded.svg"),
            ("120×30 · bench", "crc_p1.variant_C.120x30.bench.svg"),
            ("120×30 · inválido", "crc_p1.variant_C.120x30.invalid.svg"),
            ("80×24 · piso", "crc_p1.variant_C.80x24.bench.svg"),
        ]),
    ],
    "leg": [
        ("actual", "Actual", [
            ("MAC · 160×44", "legend_p1.shipped.mac.160x44.svg"),
            ("MAC · 120×30", "legend_p1.shipped.mac.120x30.svg"),
        ]),
        ("a", "A · Tabs", [
            ("MAC · 160×44", "legend_p1.variant_A.mac.160x44.svg"),
            ("Workspace · 160×44", "legend_p1.variant_A.workspace.160x44.svg"),
            ("MAC · 120×30", "legend_p1.variant_A.mac.120x30.svg"),
            ("MAC · 80×24 piso", "legend_p1.variant_A.mac.80x24.svg"),
        ]),
        ("b", "B · Dos paneles", [
            ("MAC · 160×44", "legend_p1.variant_B.mac.160x44.svg"),
            ("Workspace · 160×44", "legend_p1.variant_B.workspace.160x44.svg"),
            ("MAC · 120×30", "legend_p1.variant_B.mac.120x30.svg"),
            ("MAC · 80×24 piso", "legend_p1.variant_B.mac.80x24.svg"),
        ]),
        ("c", "C · Clave primero", [
            ("MAC · 160×44", "legend_p1.variant_C.mac.160x44.svg"),
            ("Workspace · 160×44", "legend_p1.variant_C.workspace.160x44.svg"),
            ("MAC · 120×30", "legend_p1.variant_C.mac.120x30.svg"),
            ("MAC · 80×24 piso", "legend_p1.variant_C.mac.80x24.svg"),
        ]),
    ],
}

_FONT_FACE = re.compile(r"@font-face\s*\{[^}]*\}", re.S)
_PROLOG = re.compile(r"<\?xml[^>]*\?>")


def inline_svg(path: Path, ns: str) -> str:
    svg = path.read_text(encoding="utf-8")
    svg = _PROLOG.sub("", svg)
    svg = _FONT_FACE.sub("", svg)
    prefixes = set(re.findall(r"terminal-\d+", svg))
    for prefix in prefixes:
        svg = svg.replace(prefix, ns)
    # Drop fixed pixel width/height on the root so CSS scales it (viewBox stays).
    svg = re.sub(r'(<svg[^>]*?)\swidth="[^"]*"', r"\1", svg, count=1)
    svg = re.sub(r'(<svg[^>]*?)\sheight="[^"]*"', r"\1", svg, count=1)
    return svg.strip()


def build() -> None:
    sections_html = []
    counter = 0
    for sec_key, variants in FRAMES.items():
        var_tabs, var_panels = [], []
        for v_key, v_label, states in variants:
            vid = f"{sec_key}-{v_key}"
            var_tabs.append(
                f'<button class="tab" data-sec="{sec_key}" data-panel="{vid}">{v_label}</button>'
            )
            chips, frames = [], []
            for idx, (s_label, fname) in enumerate(states):
                counter += 1
                ns = f"t{counter}"
                fid = f"{vid}-f{idx}"
                chips.append(
                    f'<button class="chip" data-panel="{vid}" data-frame="{fid}">{s_label}</button>'
                )
                frames.append(
                    f'<div class="frame" id="{fid}"><div class="framewrap">'
                    + inline_svg(HERE / fname, ns)
                    + "</div></div>"
                )
            var_panels.append(
                f'<div class="variant-panel" id="{vid}">'
                f'<div class="chiprow">{"".join(chips)}</div>{"".join(frames)}</div>'
            )
        sections_html.append((sec_key, "".join(var_tabs), "".join(var_panels)))

    crc_tabs, crc_panels = sections_html[0][1], sections_html[0][2]
    leg_tabs, leg_panels = sections_html[1][1], sections_html[1][2]

    html = HTML_TEMPLATE
    html = html.replace("<!--CRC_TABS-->", crc_tabs).replace("<!--CRC_PANELS-->", crc_panels)
    html = html.replace("<!--LEG_TABS-->", leg_tabs).replace("<!--LEG_PANELS-->", leg_panels)
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT.name} ({OUT.stat().st_size // 1024} KiB, {counter} frames)")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>P1 design defects — revisión de prototipos TUI (s19_app)</title>
<style>
:root{
  --bg:#f6f7fb;--panel:#ffffff;--fg:#1c2130;--muted:#5b6478;--rule:#d8dce8;
  --accent:#3b5bd6;--good:#177a4b;--warn:#8a6d00;--bad:#b3323b;--chipbg:#eceffa;
}
html[data-theme="dark"]{
  --bg:#0a0e1b;--panel:#0f1525;--fg:#e9e9e9;--muted:#969aad;--rule:#1b233a;
  --accent:#91abec;--good:#54efae;--warn:#f6ff8f;--bad:#fd8383;--chipbg:#131a2c;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:10px;
  padding:10px 18px;background:var(--panel);border-bottom:1px solid var(--rule)}
.topbar h1{font-size:16px;margin:0;flex:1}
.btn{background:var(--chipbg);color:var(--fg);border:1px solid var(--rule);
  border-radius:8px;padding:6px 12px;cursor:pointer;font-size:13px}
.btn:hover{border-color:var(--accent)}
main{max-width:1600px;margin:0 auto;padding:18px}
section{background:var(--panel);border:1px solid var(--rule);border-radius:12px;
  padding:18px 20px;margin-bottom:18px}
h2{margin:0 0 8px;font-size:19px}
h3{margin:14px 0 6px;font-size:15px;color:var(--accent)}
p{margin:6px 0}
.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13.5px}
th,td{border:1px solid var(--rule);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--chipbg)}
.callout{border-left:4px solid var(--warn);background:var(--chipbg);
  padding:8px 12px;border-radius:0 8px 8px 0;margin:10px 0;font-size:13.5px}
.callout.good{border-left-color:var(--good)}
.tabrow,.chiprow{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
.tab{background:var(--chipbg);border:1px solid var(--rule);color:var(--fg);
  border-radius:9px;padding:7px 14px;cursor:pointer;font-size:14px;font-weight:600}
.tab.active{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.chip{background:var(--chipbg);border:1px solid var(--rule);color:var(--muted);
  border-radius:999px;padding:4px 12px;cursor:pointer;font-size:12.5px}
.chip.active{color:var(--fg);border-color:var(--accent)}
.variant-panel{display:none}
.variant-panel.active{display:block}
.frame{display:none;overflow-x:auto;border:1px solid var(--rule);border-radius:10px;
  background:#0d1117;padding:8px}
.frame.active{display:block}
.framewrap{width:var(--zoom,100%);min-width:320px}
.framewrap svg{width:100%;height:auto;display:block}
.zoomrow{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--muted)}
.zoomrow input{width:180px}
code,pre{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12.5px}
pre{background:var(--chipbg);border:1px solid var(--rule);border-radius:8px;
  padding:10px 12px;overflow-x:auto}
.pill{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;
  font-weight:700;margin-right:4px}
.pill.rec{background:var(--good);color:#08110c}
.bluf{font-size:14.5px}
@media print{
  html,html[data-theme="dark"]{--bg:#fff;--panel:#fff;--fg:#111;--muted:#444;
    --rule:#bbb;--accent:#233a8f;--chipbg:#eee}
  .topbar .btn,.zoomrow,.chiprow,.tabrow{display:none!important}
  .variant-panel,.frame{display:block!important;page-break-inside:avoid}
  section{break-inside:avoid;border:none}
  .frame{border:1px solid #999}
}
</style>
</head>
<body>
<div class="topbar">
  <h1>P1 design defects — prototipos TUI · s19_app · 2026-07-30</h1>
  <span class="zoomrow">zoom <input id="zoom" type="range" min="60" max="220" value="100">
  <span id="zoomval">100%</span></span>
  <button class="btn" id="themebtn">🌓 Tema</button>
  <button class="btn" onclick="window.print()">🖨️ Imprimir / PDF</button>
</div>
<main>

<section>
  <h2>Qué se decide aquí (BLUF)</h2>
  <p class="bluf">Cuatro defectos de diseño marcados el 2026-07-28 pasaron por
  <code>/tui-design</code> (modo PROTOTYPE). Esta página muestra los frames capturados
  headless (pin <code>textual 8.2.8</code> — el mismo motor de render que los snapshot
  tests) para que elijas variante. <b>Gates:</b> ① variante CRC ·
  ② KAT: demover vs eliminar · ③ variante Legend · ④ orden de batches.
  Recomendación: <span class="pill rec">CRC B</span> (par Reflection + KAT demovido bajo
  Check) y <span class="pill rec">Legend B</span> (clave siempre visible; C en el piso
  80×24). El plan técnico completo: <code>prototypes/p1_design_defects.HANDOFF-PLAN.md</code>;
  el veredicto se llena en <code>p1_design_defects.NOTES.md §7</code>.</p>
  <table>
    <tr><th>Defecto</th><th>Mecanismo medido</th><th>Dónde se ve abajo</th></tr>
    <tr><td>Dos switches se ven como uno</td>
        <td><code>.crc-field-switch {border:none; height:1}</code> sin margen de fila —
        dos filas de 1 celda se funden</td>
        <td>CRC → «Actual» → 120×30 bench (Reflect in/out pegados)</td></tr>
    <tr><td>Faltan guardas de diseño</td>
        <td>las ATs de batch-59 verifican estructura (3 columnas), nada de separabilidad
        ni densidad de affordances</td>
        <td>plan §5: guardas G-1…G-4 como ATs</td></tr>
    <tr><td>Campo KAT cuestionado</td>
        <td>valida la <i>definición</i> del algoritmo vs <code>123456789</code>
        (self-test estándar), no tus datos</td>
        <td>CRC → B (demovido) vs C (eliminado)</td></tr>
    <tr><td>Legend pop-ups sin reorganizar</td>
        <td>2 pases aditivos (N1 filtro + N8 cards) sin pase de layout — la clave real
        queda bajo ~29 líneas de scroll</td>
        <td>Legend → «Actual» vs A/B/C</td></tr>
  </table>
  <div class="callout">⚠ <b>Hallazgo gratis de las capturas:</b> a 120×30 la pantalla CRC
  actual muestra SOLO el hero — todos los controles quedan bajo el fold, y cada
  <code>Select</code> de 3 filas cuesta ~5-6 filas. Los prototipos ya incluyen el pulido
  <code>Select {height: 3}</code> (sin explosión de wrap); compara «Actual» vs cualquier
  variante en el bench 120×30.</div>
</section>

<section>
  <h2>CRC Designer — variantes</h2>
  <p class="muted">Sub-shape A: cada variante monta DENTRO de la app real y todos los
  ids <code>#crc_*</code> siguen vivos (KAT / coverage / JSON / Load-Save reales — los
  CRCs del hero están computados sobre el fixture, no mockeados). Estados: cargado ·
  bench (zona del defecto) · inválido (width=999) · piso 80×24.</p>
  <div class="tabrow"><!--CRC_TABS--></div>
  <!--CRC_PANELS-->
  <h3>Qué mirar por variante</h3>
  <table>
    <tr><th></th><th>Fix de switches</th><th>KAT</th><th>Costo</th></tr>
    <tr><td><b>A</b></td><td>track visible + palabra on/off + gap de 1 fila</td>
        <td>queda como hero (solo baseline — ya lo rechazaste)</td>
        <td>✅ mínimo drift ❌ no cierra el bullet KAT</td></tr>
    <tr><td><b>B</b> <span class="pill rec">rec</span></td>
        <td>1 fila «Reflection in ⇄ out» — el par se lee como par</td>
        <td><b>demovido</b>: fila «Self-test ✓ MATCH» bajo Check; Warnings ocupa la
        columna derecha del hero</td>
        <td>✅ cirugía de ATs mínima (id vivo) ⚠ drift moderado</td></tr>
    <tr><td><b>C</b></td><td>Select «none/in/out/both» — 0 switches visibles</td>
        <td><b>eliminado</b> (nota apunta a la validación en Save)</td>
        <td>⚠ editar <code>_recompute</code> + retirar AT-058-08 ⚠ Select 3 filas donde
        había 2×1 ❓ vocabulario no estándar</td></tr>
  </table>
</section>

<section>
  <h2>Legend modal — variantes</h2>
  <p class="muted">Las tres reusan el pipeline de datos intacto
  (<code>LEGEND_EXAMPLES</code> + clave de colores, incl. la fila naranja MAC). El modal
  NO está capturado por snapshots → cero drift de baselines: la superficie más barata.</p>
  <div class="tabrow"><!--LEG_TABS--></div>
  <!--LEG_PANELS-->
  <h3>Qué mirar por variante</h3>
  <table>
    <tr><th></th><th>Estructura</th><th>Pro / contra</th></tr>
    <tr><td><b>A</b></td><td>un tab por sección del card + tab «Key»</td>
        <td>✅ nada scrollea más de una pantalla ⚠ la clave queda a 1 click</td></tr>
    <tr><td><b>B</b> <span class="pill rec">rec @120+</span></td>
        <td>card izquierda ∥ clave derecha, scrolls independientes</td>
        <td>✅ la clave SIEMPRE visible ⚠ diálogo al 96% de ancho; se apila en el piso</td></tr>
    <tr><td><b>C</b></td><td>clave arriba fija + secciones como Collapsibles</td>
        <td>✅ el mejor en 80×24 ✅ jerarquía invertida correcta ⚠ chrome por sección</td></tr>
  </table>
  <div class="callout good">Híbrido defendible: <b>B en ancho, orden de C (clave primero)
  al apilarse en el piso.</b></div>
</section>

<section>
  <h2>Cómo correr los prototipos en vivo</h2>
  <pre>PYTHONPATH=. PYTHONUTF8=1 python prototypes/crc_designer.p1.inapp_prototype.py A|B|C   # tecla 0 → CRC
PYTHONPATH=. PYTHONUTF8=1 python prototypes/legend_p1.inapp_prototype.py A|B|C         # tecla k → Legend
# regenerar frames:  … shot     · regenerar esta página:  python prototypes/p1_review_build.py</pre>
  <p class="muted">Veredicto: <code>p1_design_defects.NOTES.md §7</code> · Plan de
  implementación: <code>p1_design_defects.HANDOFF-PLAN.md</code> · PR
  <a href="https://github.com/jav201/s19_app/pull/164">#164</a>.</p>
</section>

</main>
<script>
"use strict";
var READY=false;
function activate(list,el){for(var i=0;i<list.length;i++)list[i].classList.remove("active");el.classList.add("active");}
function showPanel(sec,pid){
  try{
    var panels=document.querySelectorAll('.variant-panel[id^="'+sec+'-"]');
    for(var i=0;i<panels.length;i++)panels[i].classList.remove("active");
    var p=document.getElementById(pid);if(p)p.classList.add("active");
    var tabs=document.querySelectorAll('.tab[data-sec="'+sec+'"]');
    for(var j=0;j<tabs.length;j++)tabs[j].classList.toggle("active",tabs[j].getAttribute("data-panel")===pid);
    var chips=p?p.querySelectorAll(".chip"):[];
    if(chips.length&&!p.querySelector(".chip.active"))chips[0].click();
  }catch(e){console.warn(e);}
}
function wire(){
  var tabs=document.querySelectorAll(".tab");
  for(var i=0;i<tabs.length;i++)tabs[i].addEventListener("click",function(){
    showPanel(this.getAttribute("data-sec"),this.getAttribute("data-panel"));
  });
  var chips=document.querySelectorAll(".chip");
  for(var k=0;k<chips.length;k++)chips[k].addEventListener("click",function(){
    try{
      var panel=document.getElementById(this.getAttribute("data-panel"));
      activate(panel.querySelectorAll(".chip"),this);
      var frames=panel.querySelectorAll(".frame");
      var fid=this.getAttribute("data-frame");
      for(var m=0;m<frames.length;m++)frames[m].classList.toggle("active",frames[m].id===fid);
    }catch(e){console.warn(e);}
  });
  var zoom=document.getElementById("zoom");
  zoom.addEventListener("input",function(){
    document.documentElement.style.setProperty("--zoom",this.value+"%");
    document.getElementById("zoomval").textContent=this.value+"%";
  });
  document.getElementById("themebtn").addEventListener("click",function(){
    var h=document.documentElement;
    h.setAttribute("data-theme",h.getAttribute("data-theme")==="dark"?"light":"dark");
  });
  window.addEventListener("beforeprint",function(){
    document.documentElement.setAttribute("data-theme","light");
  });
}
wire();
showPanel("crc","crc-b");
showPanel("leg","leg-b");
READY=true;
</script>
</body>
</html>
"""

if __name__ == "__main__":
    build()
