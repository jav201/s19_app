# E5 — Revisión independiente FINAL: transporte y sincronización

Base revisada: HEAD `305e5892` más el working tree actual. Alcance limitado a los cierres TR-01…TR-04, B1/B2/B5 y SEC-01 en:

- `s19_app/tui/os_clipboard_input.py`;
- `tests/test_b103_clipboard_tail.py`;
- `tests/test_b103_clipboard_windows.py`.

Contrasté `E5-rereview-transport.md`, `E5-fix-transport.md` y `E5-fix-windows-safety.md` con el contenido actual. Las referencias siguientes son actuales. Revisión estática independiente; no soy autor de las correcciones.

## Veredicto del área

**NO-GO para transporte/sincronización.**

Persisten un HIGH de cleanup SEC-01 (TR-01), un HIGH de transporte CR/LF en la capa `subprocess` que impide cerrar TR-02/B2, y un HIGH nuevo en el brazo WinCI del reader, introducido por su corrección (TR-05). TR-03 también sigue abierto como MEDIUM de oráculo: varios controles conocidos malos no discriminan el proceso vivo que deben acotar.

B1 y B5 quedan cerrados estáticamente. TR-04 ya tiene brazos forzados, exactos y no vacuos en su alcance de oráculo, pero su ejecución WinCI sigue siendo sólo una ruta escrita y el defecto de transporte B2 permanece abierto.

## Hallazgos abiertos

### TR-01 — HIGH · impl · residual — cleanup todavía incompleto en caminos de error

Ubicaciones:

- `tests/test_b103_clipboard_tail.py:1343-1372`, `:1375-1396`, `:1446-1465`;
- `tests/test_b103_clipboard_windows.py:386-418`, `:421-438`, `:500-519`.

Hay tres residuales concretos del bloqueo anterior:

1. En ambos holders, el `try` de adquisición empieza después de `Popen`, creación de la cola y `reader.start()` (`tail:1446-1465`; `windows:500-519`). Si la construcción/inicio del reader falla tras crear el hijo, no se entra en el `except` que reapsa: el holder queda vivo. Los controles nuevos no inyectan este fallo.
2. Windows ejecuta un único `wait(timeout=3.0)` antes de cerrar y comprobar muerte (`windows:398-413`). Si ese wait expira con el proceso aún vivo, no hay el kill/wait final de último recurso que sí se añadió a tail. Además, `_release_clipboard()` mantiene `release.set()`, join y comprobaciones en una secuencia (`windows:423-438`): un fallo de `set` o del primer join impide cualquier join posterior del supervisor; el `finally` sólo reapsa el proceso. Un supervisor vivo tampoco se vuelve a unir/comprobar después de ese reap.
3. Tail sí intenta kill/wait finales, pero si cualquier fase falla relanza en `:1370-1371` antes del `poll()` final de `:1372`. `_release_clipboard()` también condiciona sus comprobaciones de supervisor/proceso a que no exista ya un fallo (`:1389-1394`). Por tanto, el camino que más necesita la comprobación explícita de muerte puede omitirla.

El camino normal está mejor acotado y los fallos ya no se enmascaran sistemáticamente, pero una excepción no equivale a cleanup completo: estos caminos pueden terminar con el holder o supervisor vivo y contaminar el siguiente acceso OS.

**Desbloqueo:** cubrir todo lo posterior a un `Popen` exitoso con el `try` de adquisición; ejecutar siempre último kill/wait acotado, cierre y comprobación final de muerte; hacer independientes las acciones de release y terminar con join/comprobación del supervisor. Conservar el fallo primario y añadir los de cleanup como notas, sin declarar cleanup cumplido con un holder vivo.

### TR-02 / B2 — HIGH · impl · residual — `text=True` impide exactitud CR/LF de extremo a extremo

Ubicaciones:

- reader: `s19_app/tui/os_clipboard_input.py:306-313`, `:341-342`;
- writer: `s19_app/tui/os_clipboard_input.py:454-469`;
- dobles que no atraviesan el transporte real: `tests/test_b103_clipboard_tail.py:1081-1102`, `:1234-1247`;
- únicos payloads exactos nuevos, sin CR/CRLF: `tests/test_b103_clipboard_tail.py:1175-1176`, `tests/test_b103_clipboard_windows.py:2112-2129`.

Eliminar `rstrip("\r\n")` corrige el recorte final explícito: ahora se devuelve `result.stdout` y se conserva `"" → None` (`os_clipboard_input.py:341-342`). Sin embargo, ambos procesos siguen usando el modo texto de `subprocess`:

- En el reader, `text=True` construye un `TextIOWrapper` con newline universal por defecto. Antes de devolver la cadena, CR y CRLF de stdout se normalizan a LF. Así, `result.stdout` ya no es una representación exacta de CR/CRLF aunque ya no se aplique `rstrip`.
- En el writer, `input=text` junto con `text=True` atraviesa el `TextIOWrapper` de stdin. En Windows, su newline de salida por defecto traduce LF a `os.linesep` (CRLF) antes de codificar. `[Console]::In.ReadToEnd()` y `SetText($text)` ya no reconstruyen líneas, pero reciben el resultado de esa conversión; no pueden recuperar el LF original.

Esto es una conclusión estática de la semántica de `subprocess`/`TextIOWrapper`, no un resultado WinCI observado. El `fake_run` de Linux recibe directamente la cadena en `kwargs["input"]` o devuelve directamente una cadena en `stdout`: se salta la codificación y newline translation de `Popen`. Por eso los brazos simulados pueden estar verdes con este defecto. Los brazos WinCI reales sí son la ruta adecuada para falsificarlo, pero no se aporta su ejecución y no contienen un caso CR/CRLF exacto.

**Desbloqueo:** transportar bytes por stdin/stdout binarios y hacer UTF-8 explícito fuera del modo newline universal; mantener el separate read Base64 como observador exacto. Ejecutar en WinCI payload forzado con LF interno, CR/CRLF y LF final, tanto en reader como en writer. No cerrar B2 sólo por la igualdad previa a `Popen` de `kwargs["input"]`.

### TR-05 — HIGH · impl · nuevo por la corrección TR-02 — el brazo WinCI compara LF en una caja que contractualmente los elimina

Ubicaciones:

- superficie usada: `tests/test_b103_clipboard_windows.py:97-100`, `:2106-2129`;
- comportamiento de producto: `s19_app/tui/os_clipboard_input.py:1041-1110`, especialmente `:1097-1110`;
- caso existente que confirma el contrato: `tests/test_b103_clipboard_windows.py:956-972`.

El nuevo `test_r_paste_16_1_read_rescue_starts_system_powershell` siembra `expected = "PS-READ\nL2\n"`, pega mediante `_box_a()` y exige `widget.value == expected`. Pero `_box_a()` devuelve `#a2l_tags_filter_input`, un `Input` de una línea. Su `action_paste()` toma deliberadamente `text.splitlines()[0]` y reemplaza la selección sólo con esa primera línea. El caso R-TUI-043.4/1 ya fija ese comportamiento.

Por tanto, incluso con un reader PowerShell perfecto, el `value` observado no puede conservar el LF interno/final esperado. El brazo WinCI escrito queda estructuralmente RED por observar la superficie equivocada; no es evidencia de una regresión del reader ni una prueba ejecutable válida de su exactitud. No se ha ejecutado WinCI: ésta es una incompatibilidad estática entre oráculo y ruta.

**Desbloqueo:** separar la exactitud del reader de la regla de pegado. Comparar directamente `read_os_clipboard(strategies=...)` con el payload exacto y, si se conserva el recorrido UI en `_box_a`, exigir sólo la primera línea; alternativamente usar una superficie multilínea (`_box_m`/`widget.text`) para un brazo UI independiente.

### TR-03 — MEDIUM · design-gap · residual — los controles conocidos malos no siempre ejercitan el holder vivo

Ubicaciones:

- dobles y control tail: `tests/test_b103_clipboard_tail.py:1560-1586`, `:1671-1682`;
- dobles/oráculos Windows: `tests/test_b103_clipboard_windows.py:608-644`, `:738-743`, `:776-829`.

Los brazos no son globalmente vacuos: tienen deadline externo, comprueban llamadas acotadas, cierre, identidad del fallo primario y ramas de readiness/release. No obstante, los casos centrales heredados de SEC-01 conservan estas lagunas:

1. En tail, `ProcessDouble.kill()` asigna inmediatamente `returncode = 0` (`:1572-1577`). `wait_timeout()` instala timeouts, pero el primer kill ya ha marcado el proceso muerto antes del primer wait (`:1671-1682`). Por ello no ejercita «wait expira con proceso aún vivo», no obliga al kill final y no discrimina la omisión de ese kill.
2. Windows sí deja `waiting.returncode is None`, pero el oráculo lo acepta explícitamente mediante `_assert_cleaned(waiting, dead=False)` y una aserción final de que sigue vivo (`:788-798`). Repite esa aceptación en release (`:800-813`). El control prueba preservación del timeout y cierre, no la condición SEC-01 de cero procesos vivos ni un último reap.
3. `supervisor_does_not_finish()` acepta un supervisor que permanece vivo y exige únicamente `joins == [5.0]` (`:815-829`), por lo que fija como suficiente la ausencia de join posterior señalada en TR-01.

**Desbloqueo:** usar dobles con estado en los que wait timeout mantenga vivo al hijo hasta un kill/wait final exitoso; exigir los reintentos, cierre y muerte final. Añadir fallo de inicio del reader y hacer que release intente sus acciones aunque `set`/join fallen. Si se conserva un doble imposible de matar, el oráculo debe exigir detección explícita del holder vivo y no presentarlo como cleanup con cero procesos.

## Cierres estáticos aceptados

### B1 — cerrado en el alcance

El reader de producto emite UTF-8 sin BOM mediante `UTF8Encoding($false)` y `Console.Out.Write` (`s19_app/tui/os_clipboard_input.py:322-323`). El separate read de tail transporta Base64 y decodifica UTF-8 estricto con `validate=True` (`tests/test_b103_clipboard_tail.py:227-264`), por lo que su observación no pasa el payload por newline universal ni por `rstrip`. No reabro B1; TR-02/B2 se refiere a la capa de texto de producto, no al BOM.

### TR-04 — brazo escrito correctamente; ejecución WinCI pendiente

`final_lf` contiene dos LF y termina en LF (`tests/test_b103_clipboard_tail.py:1175-1176`). `hostile-no-final-lf` y `hostile-final-lf` se invocan realmente (`:1325-1329`), fuerzan exclusivamente PowerShell (`:1070-1077`) y exigen app/OS/OSC/payloads exactos mediante `_success`, además de stdin, argv y proceso (`:1181-1216`). No es un brazo vacuo de conteos o de mera presencia estructural.

Esto cierra la laguna de diseño TR-04. No cierra la conversión `text=True` descrita en B2 ni convierte la ruta WinCI en ejecutada.

### B5 — barreras copy→observe conservadas

`_wait_copy_tail()` exige `tail_done` (`tests/test_b103_clipboard_tail.py:90-92`), publicado en el `finally` del tail (`:167-173`); producto espera el writer en executor antes de terminar ese tail (`s19_app/tui/os_clipboard_input.py:828-830`). Las tres omisiones originales siguen corregidas: injected hex (`tail:591-605`), line cut (`:1919-1930`) y unrelated view/box (`:1934-1972`). Held view/row liberan en `finally` antes de `_observe` (`:513-525`, `:578-586`), y las rutas held/responsiveness conservan sus barreras (`:1818-1830`, `:1863-1882`). No encontré una regresión B5 introducida por esta corrección.

### SEC-01 — partes no reabiertas

Se conservan los prototipos DLL, `kernel32.Sleep`, cierre/destrucción del hijo, readiness con timeout y verificación del hold en `tail:1403-1490` y `windows:454-541`. El cierre SEC-01 completo sigue bloqueado exclusivamente por TR-01/TR-03; no abro otros mecanismos ya corregidos.

## Estado de bloqueos y evidencia

- **TR-01:** abierto, HIGH impl.
- **TR-02:** el `rstrip` está corregido; exactitud CR/LF de producto aún abierta, HIGH impl.
- **TR-03:** abierto, MEDIUM design-gap.
- **TR-04:** laguna de brazo cerrada estáticamente; WinCI no ejecutado.
- **TR-05:** nuevo, HIGH impl, directamente introducido por el cierre del reader WinCI.
- **B1:** cerrado estáticamente.
- **B2:** comando PowerShell mejorado, pero transporte exacto aún abierto por TR-02/B2.
- **B5:** cerrado estáticamente.
- **SEC-01:** no cerrado mientras TR-01/TR-03 permanezcan abiertos.

El caller aporta una batería Linux de seis familias **160 passed / 96 skipped en 1863.17 s** y una selección correctiva **44 passed / 2 skipped**. Los registro como resultados ajenos aportados, no reproducidos por esta revisión y sin desglose por nodeid. No constituyen veredicto WinCI ni prueban los bytes reales de `Popen`, los holders reales ni los brazos Windows escritos.

Yo sólo ejecuté comprobaciones Git de lectura: HEAD confirmado como `305e5892` y `git diff --check` sobre los tres archivos, sin errores. No ejecuté pytest, probes, aplicación, PowerShell, clipboard, workflow ni mutantes de producto; no hice mutaciones Git ni modifiqué producto/tests/workflow/evidencia.

**AT-I1b-8 sigue manual y no queda cerrado.** Tampoco se declara WinCI GREEN, cobertura completa ni mutantes ejecutados. Las rutas WinCI descritas son rutas escritas pendientes de resultado real, no resultados observados.
