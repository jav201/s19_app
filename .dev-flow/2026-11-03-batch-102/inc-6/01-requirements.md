# E1 — Inc 6 — Flow Builder: editar y borrar bloques individualmente

## User story

- **US-102-06:** Como operador, quiero editar o borrar un bloque existente sin perder todo el flow, para corregir una referencia o quitar un paso sin rehacer la cadena.

## Alcance

- Selección de bloque por número (el mismo esquema que Copy).
- Acciones `Edit` y `Remove` para un bloque concreto.
- Modal de edición por tipo de bloque con validación equivalente a Add/Paste.
- Remove con confirmación y efecto limitado al bloque.
- Archivos fuente previstos: `s19_app/tui/flow_screens.py`, `s19_app/tui/screens.py` (modal), estilos/help.

## Requisitos EARS

1. **R-B102-FB-001** — Event. When the operator activates edit with a valid block number, the system shall open a modal initialized with that block's kind and current field values.
   - Umbral: 8/8 tipos de bloque.
   - Mutante negativo: el modal abre vacío o con el tipo incorrecto.

2. **R-B102-FB-002** — Event. When the operator saves an edited block, the system shall validate the replacement against the current flow, replace only the selected block, refresh pipeline/ribbon and set the dirty flag.
   - Umbral: 3/3 rutas (SOURCE, A2B, External step).
   - Mutante negativo: se reemplaza todo el flow o no se marca dirty.

3. **R-B102-FB-003** — Unwanted. If an edited block fails validation, then the system shall keep the original block, paint the refusal in the modal and leave the flow unchanged.
   - Umbral: 2/2 (A2B downstream inválido, external step sin log).
   - Mutante negativo: el bloque inválido reemplaza al original.

4. **R-B102-FB-004** — Event. When the operator confirms remove for a valid block, the system shall remove only that block, preserve variables and clipboard, refresh pipeline/ribbon and set the dirty flag.
   - Umbral: 3/3 posiciones (primero, medio, último).
   - Mutante negativo: se borran variables/clipboard o toda la cadena.

5. **R-B102-FB-005** — Unwanted. If the block number is empty, non-numeric or outside `1..N`, then the system shall paint `Edit/Remove needs a block # between 1 and <N>.` and shall not open a modal or remove anything.
   - Umbral: 3/3 entradas inválidas para ambas acciones.
   - Mutante negativo: una entrada inválida borra el último bloque o abre el modal.

6. **R-B102-FB-006** — Ubiquitous. The block edit/remove surfaces shall render file-derived refs and instructions as literal text with zero markup spans.
   - Umbral: 1/1 payload hostil.
   - Mutante negativo: se pinta markup o se loguea el contenido del bloque.

## Diseño TUI (`tui-design`)

- Se extiende la fila Copy/Paste existente con `Edit` y `Remove`; es el lugar descubierto donde el operador ya aprendió a seleccionar `#`.
- El modal usa la gramática de campos del add-row, pero fija el tipo al bloque editado; `Save` y `Cancel` son los verbos.
- El feedback de validación vive en el modal; el pipeline nunca muestra un bloque inválido.

## Decisiones

- La edición reemplaza el objeto del bloque tras validar contra la cadena actual, nunca muta el objeto vivo.
- Remove pide confirmación porque destruye una posición de la cadena y puede romper bindings `#n` posteriores; tras confirmar, no se reescriben referencias automáticamente (se preserva el contrato actual de no renumerar silenciosamente).
