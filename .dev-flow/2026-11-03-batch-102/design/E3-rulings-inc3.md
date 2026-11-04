# E3 rulings — Inc 3

Fecha: 2026-11-03

## Veredictos

- Arquitectura: PASS-WITH-NOTES.
- Seguridad: PASS-WITH-NOTES.

No hay BLOCKER. Las notas siguientes son obligatorias para E4 y corrigen detalles del prototipo inicial.

## Rulings de diseño

1. **Sin ciclo de imports.** `A2LParameterPicker` define su propio `PickerLayout` y recibe un `layout_provider` desde el host. `screens_directionb` conserva `check_layout`, `clip_param`, `clip_tail` y helpers existentes para compatibilidad con tests/importadores; no los importa de vuelta desde el picker.
2. **Filas con clave.** El renderer usa `table.add_row(..., key=name)` por fila, nunca `add_rows` sin clave: `_apply_layout` y los tests existentes dependen de la clave nombre. Con 200 filas el coste sigue dentro del presupuesto.
3. **Línea de estado separada.** Se añade `#check_param_status` para conteo/truncado (`200 of 10000 shown — refine filter.`). La línea `#check_full_name_line` conserva su contrato LLR-145.3 (nombre completo de la fila resaltada) y no se reutiliza como conteo.
4. **Frontera del componente.** El picker compone: filtro, tabla, full-name line, status line, Include y paginación. Emite `SelectionChanged` (picks/items) y `ViewChanged` (filtro/página/conteo) para que el host refresque previews/count sin alcanzar widgets internos por ids arbitrarios.
5. **Compatibilidad de API.** El host conserva propiedades `_param_rows`, `_visible_params` y `_picked_params` con getters/setters explícitos que delegan al picker; `load_spec` usa `picker.clear_picks()` en lugar de asignar la lista directamente.
6. **Paginación visible y ids.** Se añaden `#check_param_page_prev_button`, `#check_param_page_label`, `#check_param_page_next_button`. E4 actualiza los censos/constantes afectados (`CE_IDS_9C7BEAF`, TC-B97-45/61) y verifica 80x24.
7. **Debounce y tests existentes.** E4 migra los tests b97 que filtran con `settle()` a una espera real o seam de delay inyectable, concretamente AT-B97-05, AT-B97-18 y AT-B97-21.
8. **Timers.** `set_parameters` cancela un debounce pendiente antes de reemplazar la fuente; los callbacks de timer verifican `is_mounted` antes de tocar widgets.
9. **Firma nula.** La preservación exige `signature is not None and signature == self._signature and self._populated`; sin A2L no se aplica no-op accidental por `None == None`.
10. **Coste por toggle.** `_fmt_longest` se cachea en `set_parameters`; `_toggle_highlighted` no reescanea los miles de parámetros fuente.
11. **Seguridad.** Los nombres A2L siguen pasando por `safe_text`/Text literal; el status de conteo sólo interpola enteros. No se añade markup en celdas, status ni full-name.

## Notas para E5/backlog

- Duplicados de nombres A2L siguen colapsados por nombre (comportamiento preexistente); contar duplicados puede ir a backlog.
- Atajos de teclado para paginar dentro de la tabla son opcionales; si se añaden, actualizar help/keybar.
- `docs/user-guide/DOSSIER.md` referencia `IncludeTable` en `screens_directionb`; tras mover la clase, actualizar referencia o conservar re-export documentado.
