# E1 — Inc 5 — Paridad Patch Editor con selector A2L

## User story

- **US-102-05:** Como operador, quiero usar el mismo selector A2L usable dentro del Patch Editor para elegir un parámetro y precargar sus datos de parcheo sin reconstruir todo a mano.

## Alcance

- Nueva pestaña **A2L** en el inspector del Patch Editor.
- Reutilización de `A2LParameterPicker` con ids con prefijo `patch_param_*` para evitar duplicados con Check Editor, que está montado simultáneamente.
- Modo de selección por fila resaltada; acción `Use parameter` para poblar Address/Bytes del formulario de entrada.
- Archivos fuente previstos: `s19_app/tui/a2l_parameter_picker.py` (modo/prefijo), `s19_app/tui/screens_directionb.py` (`PatchEditorPanel`), `s19_app/tui/app.py` (prefill), estilos/help.

## Requisitos EARS

1. **R-B102-PE-001** — Event. When the Patch Editor is activated, the system shall populate the Patch A2L picker from the loaded measurable A2L parameters using the same 200-row page size and the current A2L signature.
   - Umbral: 2/2 activaciones con A2L de 10 000 parámetros.
   - Mutante negativo: se montan todas las filas o se usa una población distinta a Check.

2. **R-B102-PE-002** — Ubiquitous. The Patch A2L picker shall use ids prefixed with `patch_param_` and shall not duplicate any `check_param_*` id while both panels are mounted.
   - Umbral: 1/1 censo de ids en el árbol compuesto.
   - Mutante negativo: se reutilizan ids de Check.

3. **R-B102-PE-003** — Event. When the operator activates `Use parameter` with a highlighted A2L row, the system shall populate the Address input with the parameter address and the Bytes input with the current image bytes for the parameter size, and shall not modify the patch document.
   - Umbral: 3/3 tamaños 1/2/4 y documento sin cambios.
   - Mutante negativo: se añade una entrada directamente o no se respetan los bytes actuales.

4. **R-B102-PE-004** — Unwanted. If the highlighted A2L parameter has no readable current image bytes, then the system shall populate Address and clear Bytes and shall paint `Parameter address loaded; image bytes unavailable.`
   - Umbral: 1/1 sin imagen.
   - Mutante negativo: se escriben bytes cero como si fueran imagen real.

5. **R-B102-PE-005** — State. While the same A2L signature remains active, re-entering the Patch Editor shall preserve the picker filter, page and highlighted parameter.
   - Umbral: 2/2 reentradas.
   - Mutante negativo: la activación de pantalla resetea filtro/página/highlights.

6. **R-B102-PE-006** — Ubiquitous. The Patch A2L picker shall preserve the shared visual grammar: filter, ledger columns, status/full-name line, page controls and literal safe rendering of parameter names.
   - Umbral: 1/1 comparación de superficie con Check y payload hostil.
   - Mutante negativo: se usa otra gramática o se pinta markup.

## Diseño TUI (`tui-design`)

- **Ubicación:** pestaña `A2L` junto a Inspector / JSON / Checks; no se añade una columna nueva ni se reduce el ledger principal del patch.
- **Jerarquía:** el selector es la figura dentro de la pestaña; `Use parameter` es la acción contextual primaria de esa pestaña.
- **Estados:** sin A2L muestra la instrucción compartida de carga; filtro sin resultados conserva el mensaje compartido.
- **Presupuesto:** se hereda la paginación/debounce de Inc 3; no se monta más de una página.

## Decisiones

- Patch usa el componente en modo **highlight**, no como collector de picks: el valor se transfiere al formulario y el documento cambia solo con Add/Edit del Patch Editor.
- Los ids nuevos usan prefijo `patch_param_`; Check conserva los ids públicos existentes.
- La acción usa la fila resaltada, no los picks de Check.
