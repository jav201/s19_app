# E1 — Inc 4 — Bulk add de labels/parámetros en Check Editor

## User story

- **US-102-04:** Como operador, quiero pegar una lista de labels/parámetros A2L e incluirlos de una vez, en lugar de buscarlos uno por uno.

## Alcance

- Botón `Add list` en el selector/Check Editor.
- Modal con entrada multilínea para pegar nombres separados por nueva línea, coma, punto y coma o espacios.
- Inclusión de coincidencias exactas por nombre, sin duplicar picks existentes, con resumen de no encontrados.
- Archivos fuente previstos: `s19_app/tui/a2l_parameter_picker.py`, `s19_app/tui/screens.py` o módulo nuevo de modal, `s19_app/tui/screens_directionb.py`, estilos/help según censo.

## Requisitos EARS

1. **R-B102-BULK-001** — Event. When the operator activates the parameter bulk-add control, the system shall open a modal containing a multiline text area, the instruction `Separate names with new lines, commas, semicolons or spaces.`, an include action and a close action.
   - Umbral: 2/2 aperturas desde Check Editor y con selección vacía.
   - Mutante negativo: se reutiliza el input de filtro de una línea o falta la instrucción exacta.

2. **R-B102-BULK-002** — Event. When the operator confirms a bulk list, the system shall split the text on new lines, commas, semicolons and whitespace, trim each token and ignore empty tokens.
   - Umbral: 4/4 separadores combinados.
   - Mutante negativo: solo se acepta una línea o se trata la lista como una sola cadena.

3. **R-B102-BULK-003** — Event. When one or more parsed names exactly match available A2L parameter names, the system shall include each matching name once, preserving the list order and existing picks, and shall not duplicate an already included name.
   - Umbral: 3/3 (nuevos, duplicados internos, ya incluidos).
   - Mutante negativo: se duplican nombres o se reemplaza la selección existente.

4. **R-B102-BULK-004** — Event. When a bulk list completes, the system shall paint the summary `Included <n> · already included <n> · not found <n>` and, when not-found count is non-zero, append ` — first missing: <name>`.
   - Umbral: 2/2 con y sin no encontrados.
   - Mutante negativo: se omite el resumen o se altera el orden de los conteos.

5. **R-B102-BULK-005** — Unwanted. If the pasted buffer parses to zero parameter names, then the system shall paint `No listed parameters found.` and shall not change the included parameters. When names were parsed but none match, the summary required by R-B102-BULK-004 shall name the first missing parameter instead.
   - Umbral: 2/2 (lista vacía y nombres ausentes).
   - Mutante negativo: se limpian picks, se cierra sin feedback o se suprime el resumen de no encontrados.

6. **R-B102-BULK-006** — Ubiquitous. The bulk-add modal shall treat pasted names as literal text and shall paint file-derived names with zero markup spans.
   - Umbral: 1/1 payload hostil.
   - Mutante negativo: el payload pasa por markup o se pierden bytes de control sin scrub.

7. **R-B102-BULK-007** — Event. When the operator closes the bulk-add modal after a successful include, the system shall update the Check Editor preview and picked count without rebuilding the parameter ledger page unless the page content changed.
   - Umbral: 2/2 cierres tras incluir y sin incluir.
   - Mutante negativo: todo cierre reconstruye el ledger.

## Diseño TUI (`tui-design`)

- **Postura:** tarea de pegado masivo; el foco inicial es el área multilínea y `Enter` no confirma accidentalmente.
- **Jerarquía:** el área de texto es la figura; resumen y acciones secundarias quedan debajo en dim.
- **Feedback:** un solo dueño del resumen dentro del modal; el resultado primero (`Included…`), luego detalle (`first missing`).
- **Presupuesto:** la operación actúa sobre picks y celdas visibles afectadas; no monta filas nuevas ni rehace la página.

## Decisiones

- Se usa coincidencia exacta sensible a mayúsculas/minúsculas igual que el contrato actual de nombres A2L.
- El modal permanece abierto tras incluir, para permitir corregir la lista sin perder el resumen.
- `esc` cierra sin aplicar; el botón/acción explícita aplica.
