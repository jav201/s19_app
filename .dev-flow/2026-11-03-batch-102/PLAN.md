# PLAN — s19_app — Batch 2026-11-03-batch-102 (hot-fixes)

## Contexto

El operador pidió cinco hot-fixes sobre la TUI actual:

1. Copy/paste no funciona de forma fiable en Workspace, A2L y Load bajo Windows 11/PowerShell.
2. Load/reload carga el A2L pero a veces el A2L Viewer no muestra etiquetas hasta una acción manual de refresh.
3. El A2L Viewer/Check Editor debe admitir una lista de labels/parámetros, no solo inclusión uno por uno.
4. El Check Editor es demasiado lento para usarlo con A2L grandes.
5. El Patch Editor debe tener el mismo selector de parámetros que Check Editor, también usable y con pantallas coherentes; se aplica `/skill:tui-design`.

Rama de trabajo: `batch-102-hotfixes` desde `2f2f932` (batch-101 sigue abierto en `main`; este batch es una rama lateral de hot-fixes y no reemplaza su estado).

## Hallazgos iniciales

- Clipboard: `OsClipboardInput` ya implementa lectura OS en cascada tkinter → Win32 → PowerShell, con timeout PowerShell de 0.5 s (`s19_app/tui/os_clipboard_input.py:66-75`, `:277-324`). No hay escritura al portapapeles OS desde copia de inputs; el fallback interno explica por qué copiar fuera puede no llegar.
- A2L attach/reload: `_install_attached_a2l` siempre llama `update_a2l_view()` (`s19_app/tui/app.py:15314-15356`), pero el caché usa `(id(current_a2l_data), mem_size)` (`app.py:19027-19031`), clave que puede reutilizar identidad de objeto tras GC, y el viewer reaplica un filtro persistente (`app.py:19163-19166`).
- Lista múltiple: el ledger actual solo alterna la fila resaltada (`s19_app/tui/screens_directionb.py:7610-7626`).
- Rendimiento: cada entrada al Check Editor reconstruye todas las filas (`s19_app/tui/app.py:6896-6914`; `screens_directionb.py:7085-7107`, `:7166-7173`), y cada pulsación del filtro vuelve a montar el ledger completo (`:7720-7728`).
- Paridad: Patch Editor no tiene selector A2L actual; su composición actual empieza en `PatchEditorPanel` (`screens_directionb.py:4366`) y no dispone de una población equivalente a `set_a2l_parameters` del Check Editor.

## Split aprobado para ejecución

| Inc | Título | Tipo | Historia | Alcance y archivos fuente previstos | Est. Code-Wire | Depende |
|---|---|---|---|---|---:|---|
| 1 | Clipboard OS copy/paste | defecto | US-102-01 | Hacer confiables copiar/pegar OS en todos los inputs y áreas de texto; robustecer timeout/fallback Windows. Archivos: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py` si aplica. | 5-7 nodos | — |
| 2 | A2L load/reload siempre refresca viewer | defecto | US-102-02 | Invalidar correctamente enriquecimiento/filtro al cambiar A2L o imagen; el viewer refleja el resultado final sin refresh manual. Archivos: `s19_app/tui/app.py`. | 5-8 nodos | — |
| 3 | Selector A2L compartido y Check Editor usable | rendimiento/arquitectura | US-102-03 | Extraer un selector/ledger A2L paginado con filtro debounce e integrarlo en Check Editor; mantener picks y comportamiento observable. Archivos: módulo nuevo bajo `s19_app/tui/`, `screens_directionb.py`, `app.py` en integración. | 8-10 nodos | — |
| 4 | Bulk add de labels/parámetros | feature | US-102-04 | Aceptar lista multilínea/separada por comas o espacios, incluir válidos y reportar no resueltos sin duplicar. Archivos: selector compartido y Check Editor. | 4-6 nodos | Inc 3 |
| 5 | Paridad Patch Editor | feature/coherencia | US-102-05 | Integrar el mismo selector usable en Patch Editor, con misma gramática visual, foco y estados. Archivos: selector compartido, `PatchEditorPanel`, `app.py` en prefill/acción. | 7-9 nodos | Inc 3 |

Orden recomendado: 1 y 2 pueden avanzar en paralelo porque no comparten archivos fuente; 3 es la base de 4 y 5. La política de trabajo es una sola escritura concurrente por archivo fuente.

## Decisiones de diseño TUI (`tui-design`)

- **Postura:** pantalla operada, no leída. El objetivo es seleccionar muchos parámetros rápido con teclado.
- **Coherencia:** reutilizar la gramática existente (`patch-chip`, `tab-chip`, ledger `DataTable`, jerarquía de columnas y textos de estado). No se introduce un nuevo lenguaje visual.
- **Jerarquía:** el ledger A2L es la región principal (área); botones y contadores secundarios quedan en dim; la acción primaria de documento conserva `fill-accent`.
- **Navegación:** una sola tabla enfocable por panel; `Tab` sigue el orden de composición; `space`/`enter` alterna inclusión; `esc` no roba contexto; al cargar/reemplazar datos se conserva foco sano y el estado vacío nombra la recuperación (^L).
- **Feedback:** una sola región de resultado por panel; el bulk add informa `incluidos / ya presentes / no encontrados` en ese orden, con el primer ejemplo discriminable cuando quepa.
- **Presupuesto:** `DataTable` es de clase derive-cara (~6 µs/celda content-cold en textual 8.2.8 según `tui-design/BUDGET.md`). Por eso el selector monta una página acotada (objetivo inicial: 200 filas visibles, coherente con A2L Viewer), aplica debounce al filtro y no reconstruye la vista por pulsación. La meta funcional es que 10 000 parámetros no creen una pausa perceptible al entrar, filtrar o incluir en bloque; el umbral exacto se fija en E1 con medición local.

## Riesgos / vigilancia

- `app.py` es un punto de serialización: Inc 2, 3 y 5 lo tocan; no se paralelizan esas escrituras.
- `s19_app/tui/a2l.py` sigue congelado; ningún incremento debería modificarlo.
- Windows-only clipboard puede requerir pruebas con estrategias inyectadas; el CI Linux no ejecutará Win32 real.
- El cambio de caché A2L debe probar el caso de `id()` reutilizado y también conservar el rendimiento del filtrado.
- El selector compartido no debe mezclar documentos Patch/Check: ambos paneles conservan sus propios picks y contratos de mensajes.

## Fuera de alcance

- No se rediseña toda la app ni se cambia la gramática `.json` de specs.
- No se modifica el parser A2L.
- No se empuja a remoto ni se fusiona hasta el review packet del batch.
