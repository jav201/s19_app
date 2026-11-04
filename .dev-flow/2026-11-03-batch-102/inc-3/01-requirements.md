# E1 — Inc 3 — Selector A2L compartido y Check Editor usable

## User story

- **US-102-03:** Como operador, quiero seleccionar parámetros A2L desde un ledger rápido, paginado y coherente, para trabajar con A2L grandes sin bloqueos ni pérdida de selección.

## Alcance

- Nuevo componente reutilizable `A2LParameterPicker` bajo `s19_app/tui/`.
- Integración inicial en Check Editor conservando ids, mensajes y comportamiento observable existentes.
- Paginación de 200 filas, debounce de filtro, preservación por firma y actualización parcial de inclusiones.
- Archivos fuente previstos: `s19_app/tui/a2l_parameter_picker.py` (nuevo), `s19_app/tui/screens_directionb.py`, integración menor en `s19_app/tui/app.py`.

## Requisitos EARS

1. **R-B102-SEL-001** — Event. When the Check Editor receives A2L parameters, the system shall store them in the shared picker and render at most 200 parameter rows for the current filter and page.
   - Umbral: 3/3 tamaños (0, 199, 10 000 parámetros).
   - Mutante negativo: el ledger vuelve a montar todas las filas filtradas.

2. **R-B102-SEL-002** — Event. When the operator changes the parameter filter, the system shall debounce the rebuild for 150 ms and then render the first matching page with the count `<shown> of <total> shown — refine filter.` when the result exceeds 200.
   - Umbral: 2/2 (match con >200 y match con ≤200).
   - Mutante negativo: se reconstruye por pulsación o se omite el debounce.

3. **R-B102-SEL-003** — Event. When the operator activates include on a highlighted picker row, the system shall toggle only that row's mark and refresh the collected-fields preview without rebuilding the parameter ledger.
   - Umbral: 3/3 activaciones consecutivas.
   - Mutante negativo: cada toggle reconstruye todas las filas visibles.

4. **R-B102-SEL-004** — State. While the Check Editor is reopened with the same A2L signature, the system shall preserve the current filter page and included parameters and shall not repopulate the picker.
   - Umbral: 2/2 reentradas.
   - Mutante negativo: la entrada a la pantalla resetea picks o vuelve a montar el ledger.

5. **R-B102-SEL-005** — Event. When a filtered result has more than 200 rows and the operator activates next or previous, the system shall render the adjacent page and disable previous on the first page and next on the last page.
   - Umbral: 4/4 transiciones (first→second→first, last boundary).
   - Mutante negativo: los controles no cambian página o permiten salir del rango.

6. **R-B102-SEL-006** — State. While no A2L parameters are available, the picker shall render `No A2L parameters — load an A2L (^L) to list them.`; while a non-empty filter has no matches, the picker shall render `No parameter matches the filter.`
   - Umbral: 2/2 estados vacíos.
   - Mutante negativo: se pinta una tabla vacía sin instrucción o se invierten los mensajes.

7. **R-B102-SEL-007** — Ubiquitous. The picker shall paint file-derived parameter names as literal text with zero markup spans.
   - Umbral: 1/1 payload hostil.
   - Mutante negativo: el nombre pasa por markup o se truncan bytes de control sin `safe_text`.

## Diseño TUI (`tui-design`)

- **Postura:** operada con teclado; se conserva `space`/`enter` para incluir y `Tab` sigue el orden visual.
- **Jerarquía:** el ledger conserva el área principal; filtro y paginación quedan en dim; el conteo de picks es información secundaria.
- **Presupuesto:** montar como máximo 200 filas (derive-class) en lugar de miles; el filtro tiene debounce para no pagar una reconstrucción content-cold por tecla. La paginación preserva la capacidad de recorrer el A2L completo sin devolver la lentitud.
- **Coherencia:** mismos chips/botones y columnas actuales; se reutiliza el vocabulario visual Check/Patch.

## Decisiones

- El componente conserva ids existentes (`#check_param_filter`, `#check_param_table`, `#check_param_include_button`) para no romper help, tests y keybar.
- `IncludeTable` se mueve al módulo compartido y se re-exporta desde `screens_directionb` para mantener imports públicos.
- La firma la provee `app._a2l_enriched_key`, ya calculada y segura tras Inc 2.
