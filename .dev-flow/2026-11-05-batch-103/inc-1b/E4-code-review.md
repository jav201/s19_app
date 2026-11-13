# Inc 1b — E4 static code review

## Alcance y veredicto

Revisión estática independiente del HEAD `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`. El delta de producto revisado es `e2e93548..63f2bff0`, contrastado con el contenido final en `29ce6448`, contra `codewire/graph-inc1b.md`, `01-requirements.md`, `02-test-cases.md`, `E2-interfaces.md` y `E3-rulings.md`. Se inspeccionaron también los oráculos E4 pertinentes, sin ejecutarlos.

**Veredicto: FAIL / NO PASS.** Hay un defecto funcional **MAJOR impl** en la cancelación del gesto y una inconsistencia **MINOR impl** en docstrings. El GREEN Linux comunicado no cubre el primero: los casos de drag solo envían `MouseMove` no reenviados.

No se ejecutaron tests, aplicación, probes ni clipboard en Windows. No se modificó producto, tests, ledger ni ningún otro archivo distinto de este reporte.

## Hallazgos

### E4CR-01 — MAJOR — `s19_app/tui/app.py:23345` — `impl`

**Un `MouseMove` reenviado con otro offset no invalida el candidato y permite copiar un gesto cancelado.**

El guard es:

```python
elif isinstance(event, events.MouseMove) and not event.is_forwarded:
```

Por tanto, con un candidato capturado en A, un `MouseMove` reenviado a B no cambia `candidate.valid`. Si después se vuelve a A y llega un `MouseUp(3)` no reenviado con la misma pantalla y widget, las condiciones de `app.py:23352-23365` siguen siendo ciertas y se llama una vez a `copy_to_clipboard` con el snapshot anterior.

Esto contradice contratos explícitos que no limitan la invalidación a eventos no reenviados:

- `codewire/graph-inc1b.md:29` y `:212`: **cualquier** `MouseMove` cuyo offset cambie invalida permanentemente; solo `MouseDown` y `MouseUp` tienen la restricción `not-forwarded`.
- `E2-interfaces.md:30` y `02-test-cases.md:19`: **cualquier** `MouseMove` con offset distinto cancela, incluso al volver al punto inicial.
- `E3-rulings.md:12`, R-COPY.13/7…8 y R-COPY.14/7…8: drag y exit-return no pueden producir copia, sinks ni notices.

El propio docstring de `on_event` (`app.py:23313-23315`) también promete invalidación ante cualquier cambio de offset, sin la excepción implementada.

**Oráculo insuficiente:** `_right_drag` (`tests/test_b103_copy_views.py:291-300`) construye eventos nuevos mediante `_mouse` (`:243-247`) y nunca los marca como reenviados. Los casos R-COPY.11/5 y R-COPY.13/7…8 ejercitan así únicamente la rama que el producto ya maneja. No hay un brazo con `is_forwarded=True` que haga RED este mutante; un GREEN de esos casos no demuestra el contrato.

**Propuesta:** en la rama `MouseMove`, eliminar únicamente `and not event.is_forwarded`, conservando los filtros de `MouseDown`/`MouseUp`, el consumo antes de copiar y el único `await super().on_event(event)`. Añadir brazos A → B reenviado → A → release no reenviado, y A → B reenviado → release en B, exigiendo cero entry/tail/base/writer/OSC 52/notices, semillas intactas y un forward de cada evento. Mantener los brazos no reenviados existentes como controles.

### E4CR-02 — MINOR — `s19_app/tui/app.py:1512-1513`, `:1535-1537` — `impl`

**Los resúmenes de `_CopyRowTable` y `on_click` describen el comportamiento contrario al implementado para padding.**

Ambos resúmenes dicen que `out_of_bounds=True` “keep[s] their existing behaviour”. Sin embargo, el cuerpo (`app.py:1566-1569`) llama `event.prevent_default()` y retorna antes de mover el cursor, y su propia sección Data Flow (`:1547-1550`) sí describe esa supresión. El cuerpo coincide con `graph-inc1b.md:241`, E3A-02 y R-COPY.13/9: el padding debe prevenir el default y no producir cursor, `RowSelected` ni salto hex.

El defecto es documental, pero es normativo para mantenimiento: seguir el resumen reintroduciría exactamente el comportamiento prohibido.

**Propuesta:** corregir ambos resúmenes para distinguir que solo los left clicks in-bounds conservan la ruta toolkit; todo click con `out_of_bounds=True` previene el default sin mover cursor ni emitir `RowSelected`. No cambiar el cuerpo, que ya implementa lo aprobado.

## Contratos revisados sin otro hallazgo concreto

- `SkipAction` real y texto vacío: importación desde `textual.actions` (`app.py:19`) y `raise SkipAction` antes de construir coroutine/worker (`:23196-23198`). La ruta no vacía usa una sola vez inherited `run_worker` con el texto original, sin `super()`, cap, writer ni notice en el override.
- Extracción: exclusión temprana por tipo o ancestor de `OsClipboardInput`/`CappedTextArea` (`:23243-23247`); selección JSON y selección completa solo para un widget presente en `screen.selections`; A2L por row key y `_a2l_row_key_to_tag`; MAC mediante Rich `Text.plain`/`str` y retirada de un único prefijo productor conocido (`:23249-23291`). Los productores conservan el nombre completo fuera de la proyección pintada.
- Estado restante del gesto: captura en press sin copia, sustitución en un nuevo press, consumo antes de copiar, identidad de screen/widget, no revalidación al volver y un único forward léxico por evento (`:23330-23366`), salvo la aceptación incorrecta de movimientos reenviados de E4CR-01.
- Tablas y bounds: `A2LTagTable → _CopyRowTable → DataTable`, MAC como `_CopyRowTable`, composición A2L sin cambio de clase, movimiento de cursor en non-left válido, default izquierdo conservado y padding suprimido (`:1504-1582`, `:8991-8993`). Solo sus resúmenes son incorrectos (E4CR-02).
- Quit/palette: `q → help_quit`, proyección única `PaletteEntry("Quit", "quit")`, cuerpo de `action_quit` sin cambios, busy con `_QuitQuestionScreen`, idle con body B y `_CopyQuitScreen` sin métodos (`:3028`, `:482-491`, `:10356-10374`, `:23368-23443`).
- Clipboard tail: `_copy_notice_text` aplica over-cap antes de contar líneas, excluye un LF final y conserva el N original agrupado (`os_clipboard_input.py:698-737`). El tail deriva una vez el cap de 65,536 y comprueba NUL antes de base/writer/helper; NUL dentro del cap produce solo el warning fijo de 6 s y el WARNING sin payload; NUL exclusivamente posterior al cap sigue la ruta normal con cut notice original (`:740-836`). La ruta no NUL mantiene una base unbound, un writer en default executor y un único resultado, sin reentrar al override ni sanitizar otros C0/markup.
- Los oráculos tail inspeccionados para cap/NUL/cardinalidad/notices/logs sí contienen controles discriminantes: límites exactos 65,536/65,537, N original, seeds, conteos de sinks/helper/proceso/OSC 52, mensajes exactos y ausencia de payload (`tests/test_b103_clipboard_tail.py:222-281`, `:768-832`, `:900-950`). Esto no subsana la brecha de E4CR-01 ni convierte esta revisión estática en evidencia WinCI.

## Verificación estática y límites

- `git rev-parse HEAD` confirmó `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`; el árbol estaba limpio al inicio.
- `git diff --check e2e93548 63f2bff0 -- s19_app/tui/app.py s19_app/tui/os_clipboard_input.py` terminó sin errores ni salida.
- Se comprobó el diff de ambos archivos y las rutas finales citadas. No se ejecutó ningún comando de test ni se afirma comportamiento runtime, cobertura WinCI, lectura OS separada o aceptación manual.
