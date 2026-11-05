# E3 rulings — Inc 7

Fecha: 2026-11-03

## Veredictos

- Arquitectura: NO-GO inicial → corregido con estos rulings.
- Seguridad: PASS-WITH-NOTES condicionado a R1–R4.

## Decisiones de diseño corregidas

1. **Temp/loaded seleccionables mediante importación ejecutable.** Un candidato temp o loaded que no resuelva ya dentro del proyecto activo se copia a `<proyecto>/external/` con la misma vía segura que un external; el campo recibe `external/<nombre>`. Si el artefacto cargado ya está dentro del proyecto, se escribe su ref relativa directa. Así todo valor producido por Browse es ejecutable por `run_flow`.
2. **Browse lo coordina la app.** `FlowBuilderPanel` postea `BrowseRequested(input_id)`; `S19TuiApp` construye candidatos (proyecto/temp/loaded) y empuja `FileRefChooserScreen`. El resultado vuelve al host correcto: el add-field del panel o el campo del `FlowBlockEditScreen` activo. El panel nunca empuja el modal.
3. **Destino exacto.** Todo import externo/temp/loaded aterriza en `<proyecto_activo>/external/`; ese mismo project dir es la base de resolución del flow. Prohibido escribir en la raíz del workarea o fuera del proyecto.
4. **Colocación endurecida.** El import usa la tubería de `workspace.py` (`place_into_workarea`/`copy_into_workarea`) o réplica exacta de sus guards: rechazo de fuentes link/dangling, staging, tope de tamaño, claim atómico `O_CREAT|O_EXCL`, re-lstat y replace. Reuse por contenido idéntico deshabilitado para este flujo; colisión con contenido distinto genera sufijo `-1`, `-2`, … sin sobrescribir.
5. **Clasificador textual.** `resolve_flow_ref_source` compara strings normalizados contra listas; jamás toca filesystem ni une paths. Absoluto/drive-relative/`..`/NUL/desconocido => `missing`.
6. **Anotación de lectura solamente.** Se anota SOURCE/PATCH/CHECK/CRC y bindings file de A2B. WRITE_OUT, logs, outputs de EXT-STEP y bindings `#n` no reciben anotación de archivo. Precedencia: `external` > `project` > `temp` > `loaded`.
7. **Pipeline con contexto.** La anotación entra por `pipeline_text`/render con un resolver contextual opcional; si no hay contexto, la tarjeta conserva su forma actual.
8. **Cero logs de paths.** No se loguean refs, nombres ni paths completos. Los refusals y etiquetas usan `safe_text`/markup=False.

## Addendas de tests obligatorias

- TC-03 incluye ejecutabilidad: pick temp/loaded externo al proyecto => campo `external/<nombre>` y archivo copiado.
- TC-04 cubre colisión con contenido distinto, symlink/dangling source y ausencia de mutación del campo en fallo.
- TC-07 añade brazo de logs: captura de logger y ausencia del path completo.
- Nuevos casos: ref absoluto/`..`/drive-relative se anota `missing`; links del project dir no aparecen en el chooser; matriz por kind confirma que WRITE_OUT no se anota como missing.
