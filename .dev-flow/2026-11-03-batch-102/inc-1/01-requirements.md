# E1 — Inc 1 — Clipboard OS copy/paste

## User story

- **US-102-01:** Como operador en Windows 11/PowerShell, quiero copiar y pegar texto entre aplicaciones y todos los campos de la TUI para no reescribir rutas, filtros ni documentos JSON.

## Alcance

- Lectura OS robusta de Ctrl+V en `OsClipboardInput` y `CappedTextArea`.
- Escritura OS robusta de Ctrl+C y Ctrl+X desde `OsClipboardInput` y `CappedTextArea`.
- Mantener el portapapeles interno de Textual como fallback y acotar payloads a 64 KiB.
- Archivos fuente: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`.

## Requisitos EARS

1. **R-B102-CLIP-001** — Event. When the operator activates the paste action in an `OsClipboardInput` or a `CappedTextArea`, the system shall insert text from the current OS clipboard at the current selection, capped at 65,536 characters.
   - Umbral: 3/3 superficies representativas (Load, A2L filter, Patch paste buffer).
   - Mutante negativo: la acción vuelve a leer solo `App.clipboard` interno.

2. **R-B102-CLIP-002** — Event. When the operator activates the copy action with a non-empty selection in an `OsClipboardInput` or a `CappedTextArea`, the system shall write the selected text to the OS clipboard and shall not modify the editable text.
   - Umbral: 3/3 superficies representativas.
   - Mutante negativo: la acción solo escribe en `App.clipboard` interno.

3. **R-B102-CLIP-003** — Event. When the operator activates the cut action with a non-empty selection in an `OsClipboardInput` or a `CappedTextArea`, the system shall write the selected text to the OS clipboard and remove it from the editable text.
   - Umbral: 2/2 clases de widget.
   - Mutante negativo: corta localmente sin escribir al portapapeles OS.

4. **R-B102-CLIP-004** — Unwanted. If every OS write strategy fails during copy or cut, then the system shall retain Textual's internal clipboard and shall paint the warning `Clipboard write failed — copied inside the app only.`
   - Umbral: 2/2 clases de widget.
   - Mutante negativo: se omite el aviso.

5. **R-B102-CLIP-005** — Unwanted. If the Win32 and Tk clipboard strategies fail on Windows, then the PowerShell rescue strategy shall receive up to 2.0 seconds before the system treats it as failed.
   - Umbral: 2/2 (lectura y escritura) con una estrategia simulada de 1.5 s.
   - Mutante negativo: el timeout vuelve a 0.5 s.

6. **R-B102-CLIP-006** — State. While no OS clipboard value is available during paste, the system shall try Textual's internal clipboard and, when it is also empty, shall select the current field text and paint `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`
   - Umbral: 1/1 camino de fallo total.
   - Mutante negativo: se quita `select_all()` o el aviso.

## Defectos de requisitos existentes

- El requisito universal de paste batch-67 sigue vigente; este incremento lo extiende a TextArea y añade escritura OS. No se reescribe la fila canónica existente hasta el batch end.

## Slice de funciones

- Nuevas: `write_os_clipboard`, estrategias de escritura Tk/Win32/PowerShell, handlers de copy/cut en `CappedTextArea`.
- Cambiadas: constante/estrategia de timeout PowerShell, `OsClipboardInput.action_copy`, `OsClipboardInput.action_cut`, `CappedTextArea.action_paste`, `CappedTextArea.action_copy`, `CappedTextArea.action_cut`.
- Estimación Code-Wire: 6-8 nodos.

## Decisiones

- El copy/cut con selección vacía conserva el comportamiento Textual (`SkipAction`) para no interferir con bindings de aplicación.
- La escritura OS usa las mismas tres capas conceptuales que la lectura, con Win32 antes que Tk si el singleton Tk no existe; al estar en el hilo UI no requiere executor.
- `App.copy_to_clipboard` (OSC52) se conserva como escritura interna/adicional, pero ya no es la única vía en Windows.
