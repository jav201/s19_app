from __future__ import annotations

import base64
import html
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BATCH = ROOT / ".dev-flow" / "2026-11-05-batch-103"
OUT = Path(__file__).with_name("g3-review.html")
COMMIT = "bcc97d2b5a11c74c0ce30655e98684ab55c06307"

INCREMENTS = [
    ("1a", "Clipboard core: instant paste", "PASS-WITH-NOTES", "122 passed / 75 skipped; límites Windows y AT manuales declarados."),
    ("1b", "Copy from every view", "PASS-WITH-NOTES", "Linux 122/19; WinCI final 216/44, 108/108 y 28/28; AT-I1b-8 not_run."),
    ("2", "A2L definition model", "PASS-WITH-NOTES", "322 passed; 34/34 mutantes killed; full-suite y canon quedaban para G3."),
    ("3", "A2L definition writes (3a+3b)", "PASS-WITH-NOTES", "668 passed funcionales; 28/28 mutantes; redaction heredada separada."),
    ("4", "Label similarity matcher", "PASS-WITH-NOTES", "145 behaviour + 20 perf; 53/53 mutantes killed; Windows no ejecutado."),
    ("5", "A2L refresh", "PASS-WITH-NOTES", "112 passed; 28/28 mutantes; fallo de redaction heredado, no del incremento."),
    ("6", "Picker correctness", "PASS-WITH-NOTES", "77 passed + 304 históricos; 21/21 mutantes; 2 casos partial declarados."),
    ("7", "A2L list, filtro y vistas", "PASS-WITH-NOTES", "50 mutantes: 42 killed, 7 equivalentes, 1 MINOR; residuos base identificados."),
    ("8", "Patch Editor: definiciones", "PASS-WITH-NOTES", "14 archivos, 371 passed; 106/106 controles E4; MINOR pendientes."),
    ("8b", "Patch Editor: correcciones y widgets", "PASS-WITH-NOTES", "Archivos propios GREEN; 70/70 mutantes en sus pruebas; capturas registradas."),
    ("9", "Patch Editor: bench", "PASS-WITH-NOTES", "Cierre FX9f: 327 Inc 9 + 371 Inc 8 passed; margen 82_1 de 8,4 % visible."),
    ("9b", "Bench: busy y trabajo en curso", "PASS-WITH-NOTES", "W 25/25, S 10/10, AT 10/10; mutantes no-kill explicados, sin renombrarlos."),
    ("10", "Exportación y escritura S19/HEX", "PASS-WITH-NOTES", "58 killed + 1 equivalente; fallos esperados/base y sensibilidad a carga separados."),
    ("11", "A2L reader", "PASS-WITH-NOTES", "271 casos + 2 AT covered/verified; 42 killed y 1 no realizable por vía pública."),
    ("12", "A2L tag table", "PASS-WITH-NOTES", "112 passed; 20/20 mutantes; aceptación visual; timing case-06 heredado abierto."),
]

CAPTURES = [
    ("copy-notice", "Aviso de copia", "OS write succeeds: information notice `Copied 1 line to the clipboard.` (R-COPY.7)."),
    ("write-fail", "Fallo de escritura", "OS write fails: warning `Clipboard write failed - copied inside the app only.` (R-PASTE.9)."),
    ("nul-refusal", "Rechazo de NUL", "Payload con U+0000: warning de rechazo; no hay escritura (R-COPY.25)."),
    ("quit-dialog", "Diálogo de salida", "Ctrl+C sin selección: `Quit?`, texto B, `Quit (y)` y `Stay (n)` enfatizado."),
]

TEMPLATE = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Batch 103 · Revisión G3 — PASS-WITH-NOTES</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--surface:#111c2e;--surface2:#17243a;--text:#edf3fb;--muted:#b7c5d8;--line:#33445e;--accent:#7dd3fc;--ok:#86efac;--warn:#fcd34d;--bad:#fda4af;--focus:#fef08a}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:7rem}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}a{color:var(--accent);text-underline-offset:.2em}a:hover{text-decoration-thickness:2px}a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,summary:focus-visible{outline:3px solid var(--focus);outline-offset:3px}.skip{position:fixed;top:.5rem;left:.5rem;z-index:20;transform:translateY(-200%);background:var(--focus);color:#111;padding:.7rem 1rem}.skip:focus{transform:none}.topbar{position:sticky;top:0;z-index:10;background:#0b1220f5;border-bottom:1px solid var(--line)}.topbar-inner{max-width:1240px;margin:auto;display:flex;align-items:center;gap:1rem;padding:.65rem 1.25rem}.brand{font-weight:800;white-space:nowrap}.nav{display:flex;flex-wrap:wrap;gap:.2rem .75rem}.nav a{font-size:.9rem;text-decoration:none;padding:.25rem}.wrap{max-width:1240px;margin:auto;padding:0 1.25rem}header.hero{padding:2.4rem 0 1.4rem}.eyebrow{color:var(--accent);font-size:.8rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.08;margin:.45rem 0 1rem;max-width:18ch}h2{font-size:clamp(1.55rem,3vw,2.1rem);line-height:1.2;margin:0 0 1rem}h3{line-height:1.3;margin:.3rem 0 .8rem}p{max-width:82ch}.lead{font-size:1.12rem;color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.badge{display:inline-flex;align-items:center;gap:.35rem;border:1px solid currentColor;border-radius:999px;padding:.18rem .6rem;font-size:.78rem;font-weight:800;letter-spacing:.03em}.badge.blocked{color:var(--bad);background:#4c1522}.badge.ok{color:var(--ok);background:#103523}.badge.pending{color:var(--warn);background:#3b2d0b}.badge.neutral{color:var(--muted);background:var(--surface2)}.hero .badge{font-size:1rem;padding:.35rem .85rem}.alert{border:1px solid #a8495d;border-left:5px solid var(--bad);background:#2b1521;padding:1rem 1.1rem;border-radius:.5rem;margin:1rem 0}.alert strong{color:#fecdd3}.note{border-left:4px solid var(--accent);background:#102538;padding:.85rem 1rem;border-radius:.35rem;color:var(--text)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem}.card{background:var(--surface);border:1px solid var(--line);border-radius:.65rem;padding:1rem;min-width:0}.card .label{display:block;color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.06em}.card strong{display:block;font-size:1.2rem;margin:.2rem 0;overflow-wrap:anywhere}.card p{font-size:.9rem;color:var(--muted);margin:.3rem 0}section{padding:2.2rem 0;border-top:1px solid var(--line)}.section-intro{color:var(--muted);margin-top:-.4rem}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:.6rem}table{border-collapse:collapse;width:100%;background:var(--surface)}th,td{text-align:left;vertical-align:top;padding:.7rem .75rem;border-bottom:1px solid var(--line)}th{background:var(--surface2);color:var(--text);font-size:.82rem;letter-spacing:.03em}td{color:var(--muted)}td strong,td a{color:var(--text)}tbody tr:last-child td{border-bottom:0}.inc-table{min-width:850px}.inc-table td:nth-child(3){white-space:nowrap}.source-list{display:grid;gap:.45rem;padding-left:1.2rem}details{border:1px solid var(--line);border-radius:.55rem;background:var(--surface);padding:.7rem .9rem;margin:.8rem 0}summary{cursor:pointer;font-weight:750;color:var(--text)}details[open] summary{margin-bottom:.7rem}.capture-group{padding:.8rem}.capture-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}figure{margin:0;background:#080e18;border:1px solid var(--line);border-radius:.5rem;overflow:hidden}figure img{display:block;width:100%;height:auto;background:#000}figcaption{padding:.7rem;color:var(--muted);font-size:.85rem}figcaption strong{display:block;color:var(--text)}.capture-note{font-size:.9rem;color:var(--muted)}.checklist{list-style:none;padding:0;margin:1rem 0;display:grid;gap:.7rem;counter-reset:step}.checklist li{display:grid;grid-template-columns:auto 1fr;gap:.75rem;align-items:start;background:var(--surface);border:1px solid var(--line);border-radius:.55rem;padding:.9rem;counter-increment:step}.checklist li::before{content:counter(step);font-weight:900;color:var(--accent);font-size:1.2rem}.checklist input{grid-column:1;width:1.35rem;height:1.35rem;margin:.2rem 0 0;grid-row:1}.checklist label{grid-column:2;grid-row:1;cursor:pointer}.step-number{display:inline-block;color:var(--accent);font-weight:800;margin-right:.4rem}.exact{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9rem;white-space:normal;overflow-wrap:anywhere}.tabs{display:flex;flex-wrap:wrap;gap:.35rem;border-bottom:1px solid var(--line);margin-bottom:1rem}.tab{border:1px solid var(--line);background:var(--surface);color:var(--muted);padding:.65rem .9rem;border-radius:.45rem .45rem 0 0;cursor:pointer;font:inherit}.tab[aria-selected="true"]{background:var(--surface2);color:var(--text);border-bottom-color:var(--accent)}.tabpanel{min-height:12rem}.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem}.metric-grid .card strong{font-size:1.6rem}.risk-list{display:grid;gap:.75rem}.risk{display:grid;grid-template-columns:minmax(150px,.65fr) 2fr;gap:1rem;padding:1rem;border:1px solid var(--line);border-radius:.55rem;background:var(--surface)}.risk strong{color:var(--text)}.risk p{margin:0;color:var(--muted)}form{background:var(--surface);border:1px solid var(--line);border-radius:.7rem;padding:1.1rem}fieldset{border:0;padding:0;margin:0 0 1rem}legend{font-weight:800;margin-bottom:.6rem}.choices{display:grid;gap:.55rem}.choice{display:flex;gap:.65rem;align-items:flex-start;padding:.75rem;border:1px solid var(--line);border-radius:.45rem;background:var(--surface2)}.choice:has(input:disabled){opacity:.72}.choice input{width:1.2rem;height:1.2rem;margin-top:.2rem}.choice label{cursor:pointer}.choice input:disabled+label{cursor:not-allowed}.choice small{display:block;color:var(--muted)}label[for="notes"]{display:block;font-weight:800;margin:.8rem 0 .35rem}textarea{width:100%;min-height:8rem;resize:vertical;background:#0a1424;color:var(--text);border:1px solid var(--line);border-radius:.45rem;padding:.75rem;font:inherit}.actions{display:flex;flex-wrap:wrap;gap:.7rem;margin-top:1rem}.button{border:1px solid var(--accent);border-radius:.45rem;background:#123b55;color:var(--text);padding:.7rem 1rem;font:inherit;font-weight:800;cursor:pointer}.button.secondary{background:transparent;color:var(--accent)}.button:hover{filter:brightness(1.16)}#form-status{min-height:1.6rem;color:var(--ok);font-weight:700}.footer{color:var(--muted);font-size:.85rem;padding:1.5rem 0 2.5rem;border-top:1px solid var(--line)}[hidden]{display:none!important}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.metric-grid{grid-template-columns:1fr}.topbar-inner{align-items:flex-start;flex-direction:column;gap:.3rem}.nav{gap:.1rem .55rem}html{scroll-padding-top:10rem}}
@media(max-width:620px){.wrap{padding:0 .85rem}.grid,.capture-grid{grid-template-columns:1fr}header.hero{padding-top:1.5rem}.risk{grid-template-columns:1fr;gap:.3rem}.inc-table{min-width:760px}.topbar-inner{padding:.55rem .85rem}.brand{font-size:.9rem}.nav a{font-size:.82rem}.actions .button{width:100%}section{padding:1.7rem 0}}
@media print{:root{color-scheme:light}*{box-shadow:none!important}body{background:#fff;color:#111;font-size:10pt}.topbar{position:static;background:#fff;border:0}.nav,.skip,.actions{display:none!important}.topbar-inner{padding:0 0 .5rem}.wrap{max-width:none;padding:0}.hero{padding:0 0 1rem}h1{font-size:25pt}h2{font-size:17pt;break-after:avoid}.card,details,figure,form,.risk,.checklist li{background:#fff;color:#111;border-color:#888;break-inside:avoid}.card p,.lead,.section-intro,td,figcaption,.risk p,.choice small,.footer{color:#333}.badge{background:#fff!important;color:#111!important}.grid{grid-template-columns:repeat(2,1fr)}.capture-grid{grid-template-columns:repeat(2,1fr)}.tabpanel[hidden]{display:block!important}.tabs{display:none}.tabpanel{min-height:0;margin-bottom:1rem}.tabpanel::before{content:attr(data-print-title);display:block;font-size:14pt;font-weight:800;margin:.5rem 0}.alert,.note{background:#fff;color:#111;border-color:#888}a{color:#111;text-decoration:none}section{break-before:auto;padding:1rem 0}textarea{min-height:4rem;background:#fff;color:#111;border-color:#888}}
</style>
</head>
<body>
<a class="skip" href="#contenido">Saltar al contenido</a>
<div class="topbar"><div class="topbar-inner"><a class="brand" href="#resumen">B103 · G3</a><nav class="nav" aria-label="Secciones"><a href="#resumen">Resumen</a><a href="#incrementos">15 incrementos</a><a href="#capturas">8 capturas</a><a href="#at-i1b-8">AT-I1b-8</a><a href="#resultados">Resultados</a><a href="#riesgos">Riesgos</a><a href="#decision">Decisión</a></nav></div></div>
<div class="wrap">
<header class="hero" id="resumen">
<div class="eyebrow">Revisión de integración · evidencia en bcc97d2b</div>
<h1>Batch 103 · puerta G3</h1>
<span class="badge ok" data-gate-status>PASS-WITH-NOTES · aceptada con notas</span>
<span class="badge ok" data-operator-decision>APROBACIÓN PROVISIONAL · decisiones y página</span>
<p class="lead"><strong>Operador:</strong> «Por ahora todo está aprobado. Durante el uso y priebas de usuario espero ver si se sostienen las decisiones tomadas.»</p>
<p class="lead">La full-suite <code>13b1e522</code> está completa y clasificada: <strong>364 RED = 298 main + 66 serial</strong>, con 346 persistentes reglados y 18 nuevos antes del A/B. <code>last18</code> concluye 16 contexto y 2 instrumento, <strong>0 regresiones reales abiertas</strong>. Esta página no declara full-suite GREEN: acepta G3 con notas y deja el proyecto listo para promoción. AT-I1b-8 queda <strong>deferred-to-user-validation / not_run</strong>.</p>
<div class="alert" role="status"><strong>PASS-WITH-NOTES:</strong> approve está habilitado porque la full-suite está completa y clasificada y no hay regresiones abiertas. Es aceptación con notas, no GREEN. La aprobación provisional del operador se mantiene y AT-I1b-8 sigue diferida a validación de usuario, no es ejecución previa.</div>
<div class="grid" aria-label="Datos de cabecera">
<div class="card"><span class="label">Commit revisado</span><strong><code>bcc97d2b</code></strong><p><code>bcc97d2b5a11c74c0ce30655e98684ab55c06307</code></p></div>
<div class="card"><span class="label">Traza G3 final</span><strong>0 gaps</strong><p>14 US · US/CASE/TEST/SLICE/EVID/CANON · exit 0.</p></div>
<div class="card"><span class="label">CANON</span><strong>752 activos</strong><p>10 withdrawn; fold y traza sin gaps, no equivale a suite GREEN.</p></div>
<div class="card"><span class="label">Full-suite 13b1e522</span><strong>RED CLASIFICADA</strong><p>364 fallos clasificados · 0 regresiones abiertas · <a href="../full-suite/local-runs/RULINGS.md">RULINGS final</a>.</p></div>
</div>
<details><summary>Fuentes primarias del estado G3</summary><ul class="source-list">
<li><a href="../full-suite/RESULT.md">full-suite/RESULT.md</a> — estado PASS-WITH-NOTES.</li>
<li><a href="../full-suite/local-runs/RULINGS.md">local-runs/RULINGS.md</a> — censo final, last18 y doce objetivos PASS.</li>
<li><a href="../full-suite/local-runs/comparison-85ed7210-13b1e522.tsv">comparison-85ed7210-13b1e522.tsv</a> — 17 resolved, 346 persistent, 18 new.</li>
<li><a href="../full-suite/g3-batch-trace-final.txt">g3-batch-trace-final.txt</a> — 752 activos, 10 withdrawn, 0 gaps.</li>
<li><a href="../canon/RECORD.md">canon/RECORD.md</a> — fold, precedencia y reconciliación del canon.</li>
<li><a href="../../inc-1b/04-validation.md">inc-1b/04-validation.md</a> — WinCI, mutantes, capturas y pendientes.</li>
</ul></details>
</header>
<main id="contenido">
<section id="incrementos" aria-labelledby="incrementos-title">
<h2 id="incrementos-title">Los 15 incrementos</h2>
<p class="section-intro">Estado final escrito en cada <code>04-validation.md</code>; no es un veredicto agregado de G3. Los enlaces abren los registros relativos del checkout. «No presente» describe el archivo en este commit, no una cobertura inferida.</p>
<div class="table-wrap" tabindex="0" aria-label="Tabla desplazable de incrementos"><table class="inc-table"><thead><tr><th>Inc.</th><th>Alcance</th><th>Estado del registro</th><th>Resultado citado</th><th>04-validation</th><th>REVIEW-PACKET</th></tr></thead><tbody>
%%INCREMENT_ROWS%%
</tbody></table></div>
</section>
<section id="capturas" aria-labelledby="capturas-title">
<h2 id="capturas-title">Capturas reales Inc 1b</h2>
<p class="section-intro"><span class="badge ok">P-059 + 8 capturas · aprobadas por operador</span></p>
<p>Cuatro superficies de Windows Terminal, cada una a <strong>118×54</strong> y <strong>220×60</strong>. Los ocho PNG originales están incrustados en este HTML; no se modificaron ni se necesitan archivos de imagen externos para verlos.</p>
<div class="note"><strong>Limitaciones de la evidencia visual:</strong> una imagen fija no muestra right-click, drag ni otros gestos. El driver sustituyó escritura de clipboard y OSC 52 por stubs; la entrada de copia de fila se llamó directamente, sin publicar el right-click. Estas capturas no ejecutan ni aprueban AT-I1b-8.</div>
%%CAPTURE_GROUPS%%
<details><summary>Registro de procedencia</summary><p>Fuente: <a href="../../inc-1b/04-validation.md">Inc 1b · 04-validation · “Real captures (HT-10)”</a>. Aprobación visual limitada a P-059 y a estas ocho capturas; no es aceptación de release.</p></details>
</section>
<section id="at-i1b-8" aria-labelledby="at-title">
<h2 id="at-title">AT-I1b-8 · aceptación manual del operador</h2>
<span class="badge pending" data-at-status>deferred-to-user-validation · not_run · 0/6 ejecutados</span>
<p class="section-intro">El operador difiere la comprobación de AT-I1b-8 al uso y las pruebas de usuario. El texto literal procede de <a href="../../inc-1b/02-test-cases.md">02-test-cases.md</a>, con el contexto de <a href="../../inc-1b/01-requirements.md">01-requirements.md</a>. Los checkboxes son sólo ayuda local: no cambian los estados <code>deferred-to-user-validation</code> y <code>not_run</code>, no se guardan y no desbloquean G3.</p>
<details open><summary>Precondiciones literales</summary><p class="exact">%%AT_PRECONDITIONS%%</p><p>La ejecución queda diferida a la validación de usuario; ningún agente la marca como realizada ni toca el clipboard del operador. Si se ejecuta después, Pass exige <strong>6/6</strong>; el estado actual sigue <code>not_run</code>.</p></details>
<ol class="checklist" aria-label="Checklist AT-I1b-8 de seis pasos">
%%AT_STEPS%%
</ol>
<details><summary>Diagnóstico literal asociado al caso</summary><p>Si falla (1) o (3) con (2) pasando, el caso señala right-click pass-through (P-2). Si falla el primer diálogo de (5), señala Ctrl+C pass-through (P-1). Si falla <code>q</code> en (4)/(5) o se duplica con el segundo <code>q</code>, señala el binding de q o el one-instance guard. El nodo automatizado es un skip obligatorio y nunca aporta cobertura.</p></details>
</section>
<section id="resultados" aria-labelledby="resultados-title">
<h2 id="resultados-title">Resultados clave y sus límites</h2>
<p class="section-intro">Son resultados de Inc 1b y sus registros vinculados, no una full-suite del batch. Los fallos heredados se mantienen separados de los resultados aceptados.</p>
<div class="tabs" role="tablist" aria-label="Familias de resultados">
<button class="tab" id="tab-linux" role="tab" aria-selected="true" aria-controls="panel-linux" data-tab="panel-linux">Linux / WinCI</button>
<button class="tab" id="tab-mutantes" role="tab" aria-selected="false" aria-controls="panel-mutantes" data-tab="panel-mutantes" tabindex="-1">Mutantes</button>
<button class="tab" id="tab-heredados" role="tab" aria-selected="false" aria-controls="panel-heredados" data-tab="panel-heredados" tabindex="-1">Fallos heredados</button>
</div>
<div class="tabpanel" id="panel-linux" role="tabpanel" aria-labelledby="tab-linux" data-print-title="Linux / WinCI">
<div class="metric-grid"><div class="card"><span class="label">Linux E4</span><strong>122 / 19</strong><p>passed / skipped; 141 nodos. Los skips no son cobertura.</p></div><div class="card"><span class="label">Linux final dirigido</span><strong>246 / 2</strong><p>passed / skipped; seis familias: 160 passed / 96 skipped.</p></div><div class="card"><span class="label">WinCI ronda final</span><strong>10/10</strong><p>Cada una: 216 passed / 44 skipped; 108/108 obligaciones y 28/28 AT automáticas.</p></div></div>
<p>R-PASTE.13/101 quedó 0/10 tras el fix de prueba en la ronda final; el ledger conserva <code>partial / intermittent</code>. Esto no prueba una tasa de fallo cero. Los 74 <code>partial</code> no se promueven sin mapping por fila.</p>
</div>
<div class="tabpanel" id="panel-mutantes" role="tabpanel" aria-labelledby="tab-mutantes" data-print-title="Mutantes" hidden>
<div class="metric-grid"><div class="card"><span class="label">Killed</span><strong>71</strong><p>67 Linux + 4 WinCI; baseline y post-restore PASS en la cola WinCI.</p></div><div class="card"><span class="label">Equivalente</span><strong>1</strong><p>GA-A11 SURVIVED, argumentado como equivalente; no se cuenta como killed.</p></div><div class="card"><span class="label">BAD por diseño</span><strong>1</strong><p>GC-C14 bloqueado por diseño; no es un kill ni una prueba superada.</p></div></div>
<p>Los cuatro mutantes WinCI GW-W01…04 fueron ejecutados y killed. Fuente: <a href="../../inc-1b/evidence-e5/mutants/VALIDATION.md">mutants/VALIDATION.md</a>.</p>
</div>
<div class="tabpanel" id="panel-heredados" role="tabpanel" aria-labelledby="tab-heredados" data-print-title="Fallos heredados" hidden>
<ul><li><strong>Law guards Inc 1b:</strong> 6 failed / 671 passed / 3 skipped. Cinco fallos ya estaban en la base corregida; TC-B97-69 fue el sexto, intermitente y no atribuido a Inc 1b, sin etiquetarlo flaky.</li><li><strong>R-PASTE.13/101:</strong> fallos históricos 2/10 antes del fix de prueba; 0/10 después. El estado conservador sigue partial/intermittent.</li><li><strong>Otros incrementos:</strong> Inc 12 conserva el timing case-06 heredado y dos mismatches Patch de snapshots; Inc 10 separa fallos esperados/base y sensibilidad a carga.</li><li><strong>Intento full-suite histórico:</strong> terminó por infraestructura (/tmp lleno), sin tally completo. El intento actual distribuido es NOT RUN por SSH; son eventos distintos.</li></ul>
</div>
</section>
<section id="riesgos" aria-labelledby="riesgos-title">
<h2 id="riesgos-title">Notas y evidencia que permanece visible</h2>
<div class="risk-list">
<div class="risk"><strong>Full-suite 13b1e522</strong><p><span class="badge ok">COMPLETA · CLASIFICADA</span> 364 RED = 298 main + 66 serial; 269 guards literales, 19 plataforma, 58 residuales y 18 nuevos antes del A/B. Los 346 persistentes están reglados y last18 deja 0 regresiones abiertas. No es full-suite GREEN.</p></div>
<div class="risk"><strong>AT-I1b-8</strong><p><span class="badge pending">deferred-to-user-validation / not_run</span> El operador difiere la comprobación al uso y las pruebas de usuario. No está ejecutada y no bloquea la aceptación con notas.</p></div>
<div class="risk"><strong>74 partial</strong><p>El agregado WinCI 108/108 no tiene mapping por fila en el manifest. No promover esos casos sin esa correspondencia auditable.</p></div>
<div class="risk"><strong>GC-C14</strong><p>Mutante BAD/bloqueado por diseño. Mantenerlo visible como no ejecutado válidamente; no convertirlo en killed ni en PASS.</p></div>
<div class="risk"><strong>Promoción</strong><p><span class="badge ok">LISTA</span> El estado es listo para promoción a main. No se ha realizado merge a main ni se afirma full-suite GREEN.</p></div>
</div>
</section>
<section id="decision" aria-labelledby="decision-title">
<h2 id="decision-title">Decisión de revisión G3</h2>
<p class="section-intro">La aprobación provisional del operador y la corrida final clasificada ya constan en esta página. La exportación crea un JSON local en este equipo; no envía datos, no usa servicios y no modifica los registros del batch.</p>
<form id="decision-form">
<fieldset aria-describedby="approve-reason"><legend>Decisión</legend><div class="choices">
<div class="choice"><input type="radio" name="decision" value="approve" id="approve"><label for="approve">Aceptar G3 con notas <small>Disponible porque la full-suite está completa y clasificada y no hay regresiones abiertas. No declara GREEN.</small></label></div>
<div class="choice"><input type="radio" name="decision" value="reject" id="reject"><label for="reject">Rechazar <small>Registra una decisión negativa para esta revisión.</small></label></div>
<div class="choice"><input type="radio" name="decision" value="request-changes" id="request-changes"><label for="request-changes">Solicitar cambios <small>Registra trabajo pendiente sin cerrar la puerta.</small></label></div>
</div><p id="approve-reason" class="note"><strong>Regla de aprobación:</strong> approve está habilitado porque la full-suite está completa y clasificada y last18 deja 0 regresiones abiertas. AT-I1b-8 queda <code>deferred-to-user-validation / not_run</code>: no se exige como ejecución previa para esta aceptación con notas, pero tampoco se marca ejecutada. Marcar el checklist visual no cambia ninguna evidencia.</p></fieldset>
<label for="notes">Notas de revisión</label><textarea id="notes" name="notes" maxlength="12000" placeholder="Describe evidencia pendiente, cambios solicitados o motivo de rechazo."></textarea>
<div class="actions"><button class="button" type="submit" id="export-json">Exportar decisión JSON</button><button class="button secondary" type="button" id="print-page">Imprimir / guardar PDF</button></div>
<p id="form-status" role="status" aria-live="polite"></p>
</form>
</section>
</main>
<footer class="footer">Página autocontenida generada desde evidencia del commit <code>bcc97d2b</code>. CSS, JavaScript y ocho imágenes van inline. Sin red, CDN, almacenamiento ni dependencias de render. Los enlaces Markdown son referencias opcionales al checkout.</footer>
</div>
<script>
(() => {
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  const activate = (tab, focus = false) => {
    for (const item of tabs) {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      const panel = document.getElementById(item.dataset.tab);
      if (panel) panel.hidden = !selected;
    }
    if (focus) tab.focus();
  };
  for (const tab of tabs) {
    tab.addEventListener('click', () => activate(tab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const index = tabs.indexOf(tab);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      activate(tabs[next], true);
    });
  }
  const form = document.getElementById('decision-form');
  if (form) form.addEventListener('submit', event => {
    event.preventDefault();
    const selected = form.querySelector('input[name="decision"]:checked');
    const status = document.getElementById('form-status');
    if (!selected) {
      status.textContent = 'Selecciona approve, reject o request-changes antes de exportar.';
      return;
    }
    const payload = {
      schema: 's19.batch103.g3-review.v1',
      commit: 'bcc97d2b5a11c74c0ce30655e98684ab55c06307',
      gate: 'G3',
      gate_status: 'PASS-WITH-NOTES',
      operator_decision: 'provisional_approval',
      decision: selected.value,
      notes: document.getElementById('notes').value,
      exported_at: new Date().toISOString(),
      pending: {full_suite: 'COMPLETE_CLASSIFIED_RED', distributed_self_test: 'NOT_RUN', 'AT-I1b-8': 'deferred-to-user-validation/not_run'},
      release_authorized: true
    };
    const blob = new Blob([JSON.stringify(payload, null, 2) + '\n'], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'g3-decision-bcc97d2b.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = 'JSON local generado. PASS-WITH-NOTES; listo para promoción, no se envió información.';
  });
  const printButton = document.getElementById('print-page');
  if (printButton) printButton.addEventListener('click', () => window.print());
})();
</script>
</body>
</html>
"""


def png_data(path: Path) -> tuple[str, int, int]:
    raw = path.read_bytes()
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"No PNG: {path.name}")
    width, height = struct.unpack(">II", raw[16:24])
    return base64.b64encode(raw).decode("ascii"), width, height


def build() -> str:
    increment_rows = []
    for inc, scope, state, result in INCREMENTS:
        directory = BATCH / f"inc-{inc}"
        validation = directory / "04-validation.md"
        packet = directory / "REVIEW-PACKET.md"
        if not validation.is_file():
            raise FileNotFoundError(validation)
        first = validation.read_text(encoding="utf-8").splitlines()[0]
        if state not in validation.read_text(encoding="utf-8"):
            raise ValueError(f"Estado no encontrado en Inc {inc}: {state}")
        packet_cell = f'<a href="../../inc-{inc}/REVIEW-PACKET.md">Abrir packet</a>' if packet.is_file() else '<span class="badge neutral">No presente</span>'
        increment_rows.append(
            f'<tr><td><strong>{html.escape(inc)}</strong></td><td>{html.escape(scope)}</td>'
            f'<td><span class="badge neutral">{html.escape(state)}</span></td><td>{html.escape(result)}</td>'
            f'<td><a href="../../inc-{inc}/04-validation.md">Abrir validación</a></td><td>{packet_cell}</td></tr>'
        )

    capture_groups = []
    capture_count = 0
    for slug, title, description in CAPTURES:
        figures = []
        for size in ("118x54", "220x60"):
            path = BATCH / "inc-1b" / "evidence-e5" / "captures" / f"{slug}.{size}.png"
            encoded, width, height = png_data(path)
            capture_count += 1
            figures.append(
                f'<figure><img data-capture="{html.escape(slug)}" data-size="{size}" '
                f'src="data:image/png;base64,{encoded}" width="{width}" height="{height}" loading="eager" '
                f'alt="Captura real {html.escape(title)} en Windows Terminal, {size}; aprobada por el operador.">'
                f'<figcaption><strong>{html.escape(title)} · {size}</strong>'
                f'<span class="badge ok">Aprobada · P-059</span><br>{html.escape(description)}<br>'
                f'<span class="capture-note">PNG {width}×{height} px · geometría de terminal {size}.</span></figcaption></figure>'
            )
        capture_groups.append(
            f'<details class="capture-group" open><summary>{html.escape(title)} · 2 capturas</summary>'
            f'<div class="capture-grid">{"".join(figures)}</div></details>'
        )
    if capture_count != 8:
        raise AssertionError(capture_count)

    requirements = (BATCH / "inc-1b" / "01-requirements.md").read_text(encoding="utf-8")
    cases = (BATCH / "inc-1b" / "02-test-cases.md").read_text(encoding="utf-8")
    if "AT-I1b-8 (manual, 6 steps)" not in requirements:
        raise ValueError("No se encontró la AT manual de seis pasos en 01-requirements.md")
    at_line = next(line for line in cases.splitlines() if line.startswith("**AT-I1b-8 (addendum)"))
    preconditions = at_line.split("Preconditions: ", 1)[1].split(" Steps and expected results:", 1)[0]
    steps = [match.group(2) for match in re.finditer(r"\(([1-6])\) (.*?)(?=; \([1-6]\) |\. Pass =)", at_line)]
    if len(steps) != 6 or "Result `not_run` until the operator reports" not in at_line:
        raise ValueError("La AT fuente no contiene seis pasos y estado not_run")
    step_html = "".join(
        f'<li><input type="checkbox" id="at-step-{index}" data-at-step="{index}">'
        f'<label for="at-step-{index}"><span class="step-number">Paso {index}</span>'
        f'<span class="exact">{html.escape(step)}</span></label></li>'
        for index, step in enumerate(steps, 1)
    )

    page = TEMPLATE.replace("%%INCREMENT_ROWS%%", "\n".join(increment_rows))
    page = page.replace("%%CAPTURE_GROUPS%%", "\n".join(capture_groups))
    page = page.replace("%%AT_PRECONDITIONS%%", html.escape(preconditions))
    page = page.replace("%%AT_STEPS%%", step_html)
    if COMMIT not in page or page.count('data-capture="') != 8 or not page.endswith("</html>\n"):
        raise AssertionError("Contrato estructural incompleto")
    if re.search(r'(?:src|href)=["\'](?:https?:)?//', page):
        raise AssertionError("Dependencia externa detectada")
    if "%%" in page:
        raise AssertionError("Placeholder sin resolver")
    return page


def main() -> None:
    rendered = build()
    if OUT.exists() and OUT.read_text(encoding="utf-8") == rendered:
        print("g3-review.html: sin cambios")
        return
    OUT.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"g3-review.html: generado ({len(rendered.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()
