# E3 rulings — Inc 6

Fecha: 2026-11-03

## Veredictos

- Arquitectura: PASS-WITH-NOTES.
- Seguridad: PASS-WITH-NOTES.

## Rulings obligatorios de E4

1. **Vacío = inválido para Edit/Remove.** `_selected_block` rechaza entrada vacía para ambas acciones y pinta `Edit/Remove needs a block # between 1 and <N>.`; “empty = last” sigue vigente solo en Copy. Actualizar censos/placeholder para que Edit/Remove no hereden el affordance `last`.
2. **Merge del wire original.** Al guardar una edición, el candidato se construye copiando el wire dict canónico del bloque original y sobrescribiendo solo los campos expuestos por el modal; nunca se reconstruye desde cero. Esto preserva `file_type`, `a2l_ref`, `fmt` y cualquier campo futuro no expuesto.
3. **Coordinación por mensajes.** `FlowBuilderPanel` no empuja modales directamente. Postea `EditRequested(index, block, base_dir)` / `RemoveRequested(index, block)`; `S19TuiApp` resuelve la base como en Paste y empuja `FlowBlockEditScreen` o `ConfirmQuestionScreen`; los callbacks llaman métodos públicos del panel (`replace_block`, `remove_block`). Se documenta esta excepción/alineación con Save/Load.
4. **Base de contención explícita.** `FlowBlockEditScreen` recibe `project_dir` resuelto. Sin base, Save se niega y pinta el refusal en el modal; no se guarda un ref hostil para fallar después.
5. **Parsing defensivo.** El índice se parsea con `try/except ValueError` y rango; prohibido `isdigit()` como guarda previa a `int()`. Añadir TC con `'²'` y un entero de >4300 dígitos.
6. **A2B round-trip canónico.** El modal muestra bindings como `#n` 1-based y guarda la forma wire 0-based (`{source, ref}`), usando `parse_a2b_binding`/proyección canónica; no la forma de display.
7. **Negativa markup-safe y completa.** El modal pinta título, campos prefilled y refusal con texto literal/`safe_text`; el refusal lista todos los findings relevantes o un resumen con count, nunca markup.
8. **Confirm seguro.** Remove reutiliza `ConfirmQuestionScreen` o patrón equivalente: foco inicial en Cancel, `escape` cancela, índice capturado al abrir, re-chequeo de rango inmediato antes de mutar.
9. **Mutación mínima y dirty honesto.** `replace_block`/`remove_block` tocan exactamente un índice; funnel y clipboard se preservan; dirty solo si el candidato difiere del original.
10. **Sin logs de contenido.** Prohibido loguear refs, instrucciones, paths o nombres de archivos en las rutas nuevas.
11. **Censos/help/layout.** Actualizar los censos de foco/grupo/flow_clip_row afectados y verificar 80x24/118x54 con los dos chips nuevos.

## Actualización de alcance de tests

E4 añade: brazo vacío para Edit/Remove, parsing defensivo, ausencia de base, spans del modal bajo payload hostil, preservación de campos no expuestos (`file_type`/`a2l_ref`/`fmt`) y contención de la fila extendida.
