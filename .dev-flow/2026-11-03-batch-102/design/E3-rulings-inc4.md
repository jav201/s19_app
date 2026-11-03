# E3 rulings — Inc 4

Fecha: 2026-11-03

## Veredictos

- Arquitectura: PASS-WITH-NOTES.
- Seguridad: PASS-WITH-NOTES.

## Addendas obligatorias de E4

1. **Censos/help.** Al añadir `#check_param_bulk_button`, actualizar `CE_IDS_9C7BEAF` (35→36 y su assert), TC-B97-45/61 y el texto/help de Check Editor si enumera controles.
2. **Resumen seguro y acotado.** El `first missing` se pinta como `Text` literal, pasa por `safe_text` y se recorta al ancho disponible del modal; el resumen nunca usa markup. Añadir/ajustar un TC de contención del modal a 80x24.
3. **Conteos por nombre único.** Los conteos `included` / `already_included` / `not_found` clasifican nombres únicos tras parsear; duplicados internos no incrementan `not_found` dos veces. Ejemplo: `Gamma\nGamma` faltante => `not_found 1`.
4. **`include_names` emite `SelectionChanged`.** El mensaje del picker sigue siendo el único contrato de “picks changed”; el cierre del modal solo evita rebuild.
5. **Dueño del botón.** El picker compone `#check_param_bulk_button` y emite `BulkAddRequested`; el host (CheckEditorPanel, más adelante PatchEditorPanel) empuja el modal. Esto preserva C-7 y facilita Inc 5.
6. **Cierre/cancelación.** `escape` y cancel => `dismiss(None)` sin reaplicar y sin refresh. `Close` después de una inclusión en esa sesión => dismiss con resumen/flag de cambio; cierre sin cambios => `None` y sin refresh de preview.
7. **Coste.** `include_names` usa dict/set para membresía; no `list.index` ni `in` sobre lista creciente dentro del bucle de miles de tokens.
8. **Cap de entrada.** Documentar que el área usa el cap de 64 KiB; si el buffer fue truncado por ese cap, el modal lo indica en el resumen (por ejemplo `Input truncated at 65536 chars.`).
9. **Prohibido refrescar vía `load_spec` al cerrar.** Ese camino reconstruye el ledger; el cierre del modal debe limitarse a preview/count y no rebuild.
10. **Sin logging de contenido.** Ni el buffer pegado ni nombres file-derived se loguean; solo conteos/disponibilidad.

## Corrección de artefacto

El prototipo debe usar la instrucción contractual exacta: `Separate names with new lines, commas, semicolons or spaces.`
