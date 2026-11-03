# E3 rulings — Inc 5

Fecha: 2026-11-03

## Veredictos

- Arquitectura: PASS-WITH-NOTES (el hallazgo “implementación ausente” es esperado en E3; no aplica como defecto de diseño).
- Seguridad: PASS-WITH-NOTES.

## Rulings obligatorios de E4

1. **Layout proporcional.** El picker Patch recibe un `layout_provider` derivado de `patch_layout`/anchura real del inspector; no puede usar el default de 118 columnas. Verificar 80x24 y 118x54.
2. **Highlight real.** En modo `highlight`, la tabla no activa include con `space`/`enter`, no muta `_picked_params` y no postea `SelectionChanged`; la selección útil es la fila resaltada expuesta por `highlighted_parameter`.
3. **Ids por prefijo en todo el componente.** Todas las referencias internas (compose, routing de eventos, queries, comparaciones de ids, helpers de repaint) se derivan de `id_prefix`; nada queda hardcodeado a `check_param_*` salvo el default público de Check.
4. **Mem map fresco.** Al descargar imagen primaria (`_apply_unload` primary/all), el app empuja `mem_map=None` al Patch panel. Añadir TC load→unload→Use parameter: Bytes vacío y status exacto.
5. **Tamaño acotado.** Si `byte_size > MAX_A2L_DECODE_BYTES`, no se prefilla Bytes y se pinta un status propio; no se itera un rango gigante ni se trunca silenciosamente.
6. **Cobertura parcial = no disponible.** Si falta cualquier byte en `[address, address+size)`, Address se carga, Bytes queda vacío y se pinta `Parameter address loaded; image bytes unavailable.`; prohibido zero-fill.
7. **Surface del status.** La línea `Parameter address loaded; image bytes unavailable.` y `No parameter highlighted.` se pintan en una sola superficie del Patch A2L/host, marcada en tests; no se interpola texto file-derived sin `safe_text`.
8. **Censos/help/width.** Añadir la pestaña `A2L` a censos de tabs/anchos relevantes y al help de Patch; el owner `#patch_param_table` entra al help/keybar si aplica.
9. **address=None defensivo.** `highlighted_parameter` con dirección no entera se trata como fila no usable y no intenta formatear `0x%08X`.
10. **Sin logs nuevos.** No loguear nombres de parámetros, bytes de imagen ni paths en las rutas nuevas.

## Actualización de alcance de tests

E4 añade al menos: transición unload, mapa parcial, tamaño A2L sobre capa y contención 80x24 de la pestaña Patch A2L.
