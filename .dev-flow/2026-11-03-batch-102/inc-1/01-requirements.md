# E1 — Inc 1 — Clipboard OS copy/paste

## User story

- **US-102-01:** Como operador en Windows 11/PowerShell, quiero copiar y pegar texto entre aplicaciones y todos los campos de la TUI para no reescribir rutas, filtros ni documentos JSON.

## Alcance

- Lectura OS robusta de Ctrl+V en `OsClipboardInput` y `CappedTextArea`.
- Escritura OS robusta de Ctrl+C y Ctrl+X desde `OsClipboardInput` y `CappedTextArea`.
- Mantener el portapapeles interno de Textual como fallback y acotar payloads de portapapeles a 65,536 caracteres.
- Archivos fuente: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`.

## Requisitos EARS

1. **R-B102-CLIP-001** — Event. When the operator activates the paste action in an `OsClipboardInput` or a `CappedTextArea`, the system shall insert text from the current OS clipboard at the current selection, capped at 65,536 characters.
   - Umbral: 3/3 superficies representativas (Load, A2L filter, Patch paste buffer).
   - Mutante negativo: la acción vuelve a leer solo `App.clipboard` interno.

2. **R-B102-CLIP-002** — Event. When the operator activates the copy action with a non-empty selection in an `OsClipboardInput` or a `CappedTextArea`, the system shall write the selected text, capped at 65,536 characters, to the OS and internal clipboards and shall not modify the editable text.
   - Umbral: 3/3 superficies representativas.
   - Mutante negativo: la acción solo escribe en `App.clipboard` interno.

3. **R-B102-CLIP-003** — Event. When the operator activates the cut action with a non-empty selection in an `OsClipboardInput` or a `CappedTextArea`, the system shall write the selected text, capped at 65,536 characters, to the OS and internal clipboards and remove it from the editable text.
   - Umbral: 2/2 clases de widget.
   - Mutante negativo: corta localmente sin escribir al portapapeles OS.

4. **R-B102-CLIP-004** — Unwanted. If every OS write strategy fails during copy or cut, then the system shall retain Textual's internal clipboard and shall paint the warning `Clipboard write failed — copied inside the app only.`
   - Umbral: 2/2 clases de widget.
   - Mutante negativo: se omite el aviso.

5. **R-B102-CLIP-005** — Unwanted. If the Win32 and Tk clipboard strategies fail on Windows, then the PowerShell rescue strategy shall receive up to 2.0 seconds before the system treats it as failed.
   - Umbral: 2/2 (lectura y escritura); el test ejerce el timeout real de la capa PowerShell.
   - Mutante negativo: el timeout vuelve a 0.5 s.

6. **R-B102-CLIP-006** — State. While no OS clipboard value is available during paste, the system shall try Textual's internal clipboard and, when it is also empty, shall select the current field text and paint `Clipboard read failed — try Ctrl+Shift+V or type the path manually.`
   - Umbral: 1/1 camino de fallo total en ambas clases de widget.
   - Mutante negativo: se quita `select_all()` o el aviso.

## Defectos de requisitos existentes

- El requisito universal de paste batch-67 sigue vigente; este incremento lo extiende a TextArea y añade escritura OS. No se reescribe la fila canónica existente hasta el batch end.

## Slice de funciones

- Nuevas: `write_os_clipboard`, estrategias de escritura Win32/Tk/PowerShell, handlers de copy/cut en `CappedTextArea`.
- Cambiadas: presupuesto/estrategia PowerShell, `OsClipboardInput.action_copy`, `OsClipboardInput.action_cut`, `CappedTextArea.action_paste`, `CappedTextArea.action_copy`, `CappedTextArea.action_cut`.
- Estimación Code-Wire: 8-10 nodos.

## Decisiones corregidas tras E3

- La cascada de escritura es **Win32 → Tk → PowerShell**. Win32 entrega el contenido al sistema de forma persistente; Tk queda como rescate porque su contenido puede desaparecer al destruir el root al salir.
- Copy/cut son `async` y ejecutan la cascada en el executor; antes se hace `_prime_tk_root()` en el hilo UI. Así el presupuesto de 2.0 s no congela la interfaz.
- `OsClipboardInput.action_cut` con selección vacía usa `SkipAction` y no borra el portapapeles interno con una cadena vacía.
- `CappedTextArea.action_cut` preserva el corte de línea de Textual cuando no hay selección: obtiene el texto reemplazado por `_delete_cursor_line()` y lo escribe a OS/interno.
- `CappedTextArea.action_paste` hace `_prime_tk_root()` antes del executor y, en fallo total, selecciona todo el buffer antes del aviso.
- La capa PowerShell de escritura usa un comando estático y pasa el payload por stdin UTF-8; nunca interpola texto copiado en `-Command`, no usa `shell=True` y solicita ventana oculta en Windows.
