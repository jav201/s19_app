# E3 rulings — Inc 1 e Inc 2

Fecha: 2026-11-03

## Veredictos

- **Inc 1 — Clipboard OS copy/paste:** PASS-WITH-NOTES (arquitectura y seguridad).
- **Inc 2 — A2L load/reload refresh:** PASS-WITH-NOTES (arquitectura y seguridad); el BLOCKER de la clave `(id, size)` y la ventana worker→apply quedó cerrado con `(a2l_view_generation, image_generation, mem_size)` y snapshots en `PreparedLoad`.

## Addendas obligatorias de E4

### Inc 1

1. Actualizar los docstrings que aún prometen 0.5 s / “well under one second” al nuevo presupuesto PowerShell de 2.0 s.
2. Añadir un test para `OsClipboardInput.action_cut` con selección vacía: debe hacer `SkipAction` y no borrar el portapapeles interno con `""`.
3. Fijar que el cap de 65,536 caracteres aplica igual al payload OS y al espejo interno.
4. Serializar con un lock de módulo los subprocessos PowerShell de clipboard para evitar procesos concurrentes ante spam de teclas.
5. En los tests de PowerShell, asertar comando estático, `shell=False`, timeout y ventana oculta/`creationflags` cuando aplica.
6. Renombrar o documentar el alias del cap si se usa para escritura, evitando que el nombre `READ_CAP` contradiga el contrato.

### Inc 2

1. Incluir `_start_load_worker` en el slice y fijar la regla de predicción: la imagen precalculada usa `image_generation + 1`; A2L usa `a2l_view_generation + 1` solo cuando `loaded.a2l_data` existe. Predicción errónea = descarte seguro y recompute UI.
2. Enrutar el clear de `_reset_project_session` por `_replace_current_a2l` o declararlo reset secundario permitido; no dejar una escritura fuera del seam sin ruling.
3. Pintar `No A2L tags match '<filter>'.` vía `safe_text`/Text literal y añadir un caso con filtro hostil (`[red]` o escape) para demostrar que no se interpreta markup.
4. Usar `Optional[str]` para `empty_message`.
5. Actualizar el diagnóstico/comentario que describe la forma vieja `(id, mem_size)` de `_a2l_enriched_key`.

## No acción

- Se acepta la materialización sin cota previa al cap de 64 KiB en lectura: es el comportamiento existente, se documenta y no se amplía el alcance del hot-fix.
- Se acepta que una comilla simple en el filtro rompa estéticamente el patrón `'<filter>'`; el contrato exige texto literal seguro, no una gramática de quoting.
