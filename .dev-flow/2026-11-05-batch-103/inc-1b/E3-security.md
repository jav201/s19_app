# Inc 1b — E3 Security

## Veredicto

**FAIL — cambios de diseño requeridos.** Hay **0 BLOCKER, 0 HIGH, 2 MAJOR y 1 minor** abiertos. No corresponde emitir PASS-WITH-NOTES mientras E3-01 y E3-02 permanezcan abiertos. E2 está cerrado como etapa, pero estos dos hallazgos exigen corregir el diseño afectado y volver a E3 antes de implementar o aceptar E4.

La revisión es independiente de los `decision: covered` del grafo y de cualquier lint/reporte de autores. Se revisaron los 24 nodos integrados (12 de implementación y 12 de contexto), los requisitos y casos finales, I-1/I-12.2, los rulings y el veredicto G2 vigente. Se confirma **body B**, `q3_body=B`, `q4_q=B`, `q5_ctrlc_sel=approve` y `q6_notices=approve` en `../evidence/G2/veredicto-b103-r2.json:6-17`.

## Alcance y método

- HEAD verificado: `6adb633711661f072113ffd601cf90ac34d2c26c`.
- Lectura estática de `s19_app/tui/app.py`, `s19_app/tui/os_clipboard_input.py` y `s19_app/tui/capped_text_area.py`. Los tres archivos son idénticos entre la referencia del grafo `59d467ff7390` y HEAD (`git diff --quiet` terminó con código 0).
- Textual **8.2.8**, instalado en `C:/Users/<user>/anaconda3/Lib/site-packages/textual`, confirmado con `python -m pip show textual`.
- No se ejecutó pytest, la aplicación, probes ni escrituras de clipboard en Windows. Los casos de `02-test-cases.md` continúan `not_run`; este informe no convierte ejemplos E2 en evidencia de ejecución.
- No se modificaron producto, tests, grafos, requirements, interfaces, rulings o steps. Este informe es el único archivo escrito.

## Hallazgos

### E3-01 — MAJOR — `design-gap`: un right-drag copia antes de saber si es un clic

**Evidencia.**

- N3 agenda la copia en todo `MouseDown` derecho no reenviado que produzca texto; no conserva un candidato ni examina `MouseMove` o `MouseUp`: `codewire/graph-inc1b.md:185-196`, especialmente `:191`. La secuencia de entidades también va directamente de `MouseDown` a `copy_to_clipboard`: `codewire/graph-inc1b.md:453-460`.
- La definición aprobada de right-click exige press y release sobre una celda: `01-requirements.md:26-27`. R-COPY.11 exige que seleccionar texto no cambie el clipboard y R-COPY.12 limita la copia al right-click sobre una selección: `01-requirements.md:93-94`.
- El riesgo estaba señalado pero se descartó como “Harmless”: `E1-rulings.md:155`.
- Textual inicia `_select_state` en `MouseDown` sin distinguir el botón y extiende esa selección en `MouseMove`: `textual/screen.py:1885-1922` y `textual/screen.py:1828-1854`.

**Escenario y consecuencia.** Con una selección anterior presente, el operador pulsa botón 3 dentro de ella y arrastra para seleccionar otro texto. Antes del primer movimiento y sin esperar release, N2 devuelve la selección antigua y N1 ya ha iniciado la escritura al clipboard de la aplicación, OSC 52 y el clipboard de Windows. En una tabla basta iniciar el arrastre sobre una fila para copiar su nombre. Un arrastre que sale y vuelve a la celda inicial tampoco queda distinguido por el diseño actual.

Esto es una escritura no autorizada por el gesto, no solo un defecto visual. Puede reemplazar datos previos y dejar texto antiguo en el historial/sincronización de Windows, riesgo de privacidad ya reconocido en `E1-rulings.md:97`. También hace insuficiente el actual ejemplo back-to-back como prueba de todos los gestos.

**Propuesta concreta obligatoria.** Separar **captura temprana** de **efecto de copia**, sin reintroducir la carrera press/release:

1. En el `MouseDown` derecho no reenviado, N3 llama a N2 y guarda en un único estado privado de gesto el snapshot de texto, `screen_offset`, pantalla y widget. No llama todavía a N1 y siempre reenvía el evento una vez.
2. Un `MouseMove` que cambie `screen_offset` invalida ese candidato; por tanto, salir y volver a la celda tampoco copia. Un nuevo `MouseDown`, cambio de pantalla o cancelación del gesto reemplaza/elimina el candidato anterior.
3. En `MouseUp` derecho no reenviado, copiar solo si existe candidato válido, no hubo movimiento y press/release tienen el mismo `screen_offset` y contexto. Consumir y limpiar el candidato **antes** de llamar una vez a N1, para impedir doble disparo por eventos reenviados. Reenviar siempre el release exactamente una vez.
4. Mantener intacta la exclusión temprana de `OsClipboardInput`/`CappedTextArea`, la captura previa de JSON/selecciones y el comportamiento posterior de highlight. El estado del gesto no es un guard global de escrituras ni añade procesos, workers o writers.

**Oráculo de cierre.** Añadir a E4, sin alterar ahora los casos aprobados: (a) selección previa con marcador secreto, `MouseDown(3)`, movimiento y `MouseUp(3)` en otra celda; (b) salida y regreso a la celda inicial; (c) press/release back-to-back en la misma celda. En (a) y (b): cero llamadas N1/tail/base/writer/OSC 52/notices y ambas semillas intactas. En (c): exactamente `1/1/1/1/1`, payload igual al snapshot previo y una notificación. Repetir el control negativo sobre una fila A2L/MAC y el positivo sobre selección y fila.

### E3-02 — MAJOR — `design-gap`: NUL puede producir una copia truncada con aviso de éxito

**Evidencia.**

- N2 toma el nombre completo directamente del modelo A2L, no la proyección pintada: `codewire/graph-inc1b.md:173-175`. El modelo se conserva en `_a2l_row_key_to_tag`: `s19_app/tui/app.py:21490-21494`. La proyección que reemplaza caracteres fuera de U+0021–U+007E pertenece solo a `_shorten_tag_name`: `s19_app/tui/app.py:1328-1375`.
- R-COPY.4 exige escribir el nombre completo de la fila en el clipboard de Windows: `01-requirements.md:86`. El riesgo de C0 en el nombre completo quedó explícitamente re-scopeado para E3: `E1-rulings.md:285`.
- El writer Win32 codifica el texto como UTF-16LE, añade el terminador NUL y publica `CF_UNICODETEXT`: `s19_app/tui/os_clipboard_input.py:335-374` y `:401-412`. Un NUL ya presente en el nombre queda por tanto dentro de un formato de texto terminado en NUL.
- La propia lectura Win32 del producto descarta todo lo posterior al primer NUL: `s19_app/tui/os_clipboard_input.py:261-264`. Sin embargo, una escritura Win32 satisfactoria devuelve `True`, y la cascada propaga éxito: `s19_app/tui/os_clipboard_input.py:683-687`. El diseño nuevo convertiría ese `True` en una notificación ordinaria o de corte: `codewire/graph-inc1b.md:368-372`.

**Consecuencia.** Para un nombre como `VISIBLE\x00SECRET-SUFFIX`, la aplicación/OSC 52 pueden conservar el string Python completo, pero la ruta de texto Win32 no ofrece un round-trip del sufijo; el lector del propio producto lo elimina. Aun así, el diseño puede anunciar `Copied 1 line…`. Es pérdida silenciosa de datos y un resultado distinto entre superficies, no una razón para sustituir arbitrariamente el nombre por `U+FFFD`.

**Propuesta concreta obligatoria.** Cerrar fail-closed el carácter no representable, en la cola compartida para que también queden cubiertas las entradas directas de text boxes:

1. Conservar `original_text` y calcular `capped_text` como ya fija I-1. Si `capped_text` contiene U+0000, no llamar a la base, al writer ni a `_copy_notice_text`: cero OSC 52, cero procesos y ambos clipboards previos intactos.
2. Emitir una única advertencia fija de 6 s, por ejemplo `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.`, y un WARNING fijo sin payload ni prefijo. No informar éxito y no escribir una versión sanitizada/truncada.
3. Si el NUL está únicamente después del carácter 65,536, no afecta al payload y no debe activar el rechazo; se conserva el aviso de corte basado en la longitud original.
4. Esta rama es una excepción estrecha a I-1/R-COPY.4 y requiere ruling explícito del orchestrator antes de E4, porque el requisito actual no contempla un dato que el formato de texto de Windows no puede representar. **No** se propone sanitizar markup, ESC, LF u otros C0 representables, ni cambiar globalmente el significado aprobado de *full name*.

**Oráculo de cierre.** Con semilla en ambos clipboards y `A\0B` dentro del cap: base/tail-writer/OSC 52 = `0/0/0`, cero notices de éxito, una advertencia de rechazo, semillas intactas y ausencia del payload en logs. Repetir por N1 y por entrada directa de un text box. Con NUL solo después del cap: una escritura del prefijo capado y una cut notice con el total original. El intento de volver a llamar al writer o de emitir éxito debe hacer RED.

### E3-03 — minor — brecha de verificación: el fixture hostil no llega a los sinks de clipboard

**Etiqueta:** no es un `design-gap` de transporte para controles representables; es una brecha del oráculo E2/E4.

**Evidencia.** El único ejemplo hostil comprueba la celda pintada con U+FFFD y dice que N2 usa el nombre del modelo, pero no observa el payload copiado: `codewire/graph-inc1b.md:229`. R-TUI-043.13/101 exige ausencia del texto en logs, pero no fija un nombre con markup/C0: `02-test-cases.md:113`. Tampoco R-COPY.4/1…3 usa un nombre hostil: `02-test-cases.md:37-39`.

El transporte ya contiene mitigaciones concretas que no deben confundirse con este gap: OSC 52 usa Base64 (`textual/app.py:1780-1786`) y PowerShell recibe el payload por `stdin`, con comando estático y `shell=False` (`s19_app/tui/os_clipboard_input.py:120-131` y `:441-456`). Por ello no se afirma una inyección de markup/OSC/PowerShell sin evidencia.

**Propuesta concreta.** Incorporar en E4 un nombre A2L de modelo que combine `[red]`, ESC, BEL, una secuencia con apariencia OSC y LF, **sin NUL**. Copiar por N2 y comprobar independientemente: nombre completo exacto en app clipboard, OSC 52 decodificado y lectura separada de Windows; una sola petición/escritura; ninguna secuencia terminal adicional; ningún argumento de proceso construido con el payload; notices limitados al conteo; logs sin nombre ni prefijo. Conservar también un brazo con writer forzado a PowerShell. No reutilizar la celda U+FFFD como expected, porque eso ocultaría precisamente la ruta raw que debe probarse.

## Cobertura revisada

| Área | Resultado estático y evidencia |
|---|---|
| Privacidad y destinos | **E3-01 abierto.** Tras corregirlo, la copia queda limitada a Ctrl+C con selección o right-click confirmado; no se propone limpiar historial/cloud sync ni el clipboard al salir, pues sería una superficie destructiva nueva. OS clipboard y OSC 52 son destinos explícitos de R-COPY.1/.10, no una duplicación accidental. |
| Nombres completos, markup y C0 | **E3-02 y E3-03 abiertos.** La copia raw es necesaria para cumplir *full name*; Base64 y `stdin` evitan interpretar markup/controles como comandos. NUL necesita fallo explícito, no sanitización silenciosa. |
| Selección/highlight sin copia | **E3-01 abierto para right-drag.** Drag izquierdo, F7, teclas y left-click no entran en N3; N5 solo mueve highlight y no llama a N1: `codewire/graph-inc1b.md:191-218`. |
| Right-click vacío y text boxes | Sin hallazgo adicional. N2 exige selección contenida o fila válida, devuelve `None` en header/vacío y excluye widget o ancestro text-box antes de leer otra selección: `codewire/graph-inc1b.md:173-183`. Las rutas directas de los boxes están en `os_clipboard_input.py:861-944` y `capped_text_area.py:242-335`. |
| Reentrada y doble escritura | Diseño aceptable salvo el gesto espurio de E3-01. N1 agenda una cola; la cola llama a la base **desvinculada**, evitando reentrar en el override, y ejecuta una cascada: `codewire/graph-inc1b.md:72-79`. Los cuatro copy/cut de boxes entran directamente, sin pasar por N1: `codewire/graph-inc1b.md:81-90`. |
| Cap 65,536 y longitud original | Correcto en el diseño: N1 no corta; la cola conserva `original_text`, deriva una sola `capped_text`, y el helper usa la longitud original solo para el aviso: `codewire/graph-inc1b.md:149-166`, `:353-372`. El cap defensivo existente está en `os_clipboard_input.py:679-695`. Los límites `65,536/65,537` y el marcador en 65,535/65,536 son discriminantes: `codewire/graph-inc1b.md:95`, `:106-107`. |
| Secretos en logs/notices | Sin interpolación nueva del payload: notices con líneas/longitud; writer existente registra estrategia y longitud, y PowerShell registra solo código/`stderr_len`: `os_clipboard_input.py:638-695`, `:458-471`. La ausencia debe probarse también con el fixture hostil de E3-03 y en éxito/fallo, no inferirse del lint. |
| Fallo y timing | La cola conserva mirror aun con fallo, espera el booleano antes de notificar y mantiene warning fijo de 6 s: `codewire/graph-inc1b.md:372`, `:385-397`. Una cascada tiene presupuestos propios de 0.1 s Win32 + 2.0 s PowerShell y corre fuera del event loop: `os_clipboard_input.py:88-97`, `:638-695`, `:740-754`. No se midió timing en esta revisión; E4 debe conservar held-clipboard, latencia de timer y thread del writer. E3-02 cubre el fallo de representabilidad que hoy no existe. |
| q/modal/busy y proyecto parcial | Sin hallazgo. q/Ctrl+C no inspeccionan ni copian selección en N8; busy usa la pregunta existente y el callback compartido difiere la salida hasta terminar la acción: `codewire/graph-inc1b.md:241-257`, `:320-329`; `s19_app/tui/app.py:23037-23045`. La cadena modal corta q/Ctrl+C (`textual/screen.py:448-455`) y N9 hereda el guard de `_QuitQuestionScreen`. Idle Ctrl+Q/palette conserva `action_quit`; no se añade escritura de proyecto. |
| Procesos y superficies externas | No se añade un proceso nuevo: se reutiliza `_WRITE_STRATEGIES` Win32 → PowerShell (`os_clipboard_input.py:489-492`), con ruta absoluta del sistema (`:184-196`), `shell=False`, comando estático y lock de procesos (`:115-131`, `:441-456`). Las propuestas E3-01/E3-02 solo añaden validación/estado interno y no abren otra superficie. |

## Condición de cierre E3

Revisar de nuevo este carril solo cuando el diseño incorpore E3-01 y el ruling/rama de E3-02, con sus oráculos negativos. E3-03 puede cerrarse al incorporar el fixture hostil a E4. No hay evidencia runtime que permita bajar ninguno de esos hallazgos por los reportes existentes.
