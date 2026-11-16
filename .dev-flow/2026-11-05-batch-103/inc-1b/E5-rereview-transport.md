# E5 — Re-review A: transporte y sincronización

Base revisada: rama `b103-inc1b-integration`, HEAD `305e5892`, más los cambios E5 sin commit presentes en el working tree. Se revisó el contenido actual y el diff de:

- `s19_app/tui/os_clipboard_input.py`;
- `tests/test_b103_clipboard_tail.py`;
- `tests/test_b103_clipboard_windows.py`.

También se contrastaron selectivamente el handoff E5 y `E5-winci-review.md`, `E5-pre-ci-review.md` y `E5-pre-ci-security.md`. Las líneas de esos informes son históricas; todas las referencias siguientes corresponden al árbol actual.

Revisión exclusivamente estática. No ejecuté pytest, probes, aplicación, PowerShell, clipboard, workflow ni mutantes; no repetí la batería Linux. `git diff --check` sobre los tres archivos terminó sin errores. El tally ajeno **160 passed / 96 skipped** queda limitado a Linux: no es evidencia WinCI. No hay veredicto WinCI ni mutantes de producto ejecutados derivados de esta revisión.

## Veredicto del área A

**NO-GO para transporte/sincronización.** B1, B2 y B5 de `E5-pre-ci-review.md` están corregidos estáticamente en el alcance asignado. SEC-01 está mejorado, pero conserva un camino de cleanup que puede terminar en fallo con el holder todavía vivo (**TR-01, HIGH**). Además, el reader PowerShell de producto sigue eliminando CR/LF finales pertenecientes al payload (**TR-02, HIGH**). Quedan dos lagunas MEDIUM de oráculo: los controles de fallo exigidos por SEC-01 no tienen nodos en estos archivos (**TR-03**) y el writer PowerShell forzado no tiene un brazo exacto con LF final (**TR-04**).

Este NO-GO es una conclusión estática del área, no una predicción de que WinCI vaya a fallar ni una ejecución de sus rutas.

## Hallazgos abiertos

### TR-01 — HIGH · impl — SEC-01 residual: reap/release no garantizan cero holders en sus caminos de error

Ubicaciones actuales:

- `tests/test_b103_clipboard_tail.py:1209-1223`, `:1321-1332`;
- `tests/test_b103_clipboard_windows.py:344-358`, `:461-474`.

En ambos `_reap_holder`, `proc.wait(timeout=3.0)` puede lanzar `TimeoutExpired`; el `finally` sólo cierra `stdout`. No hay un último reap acotado ni una comprobación de muerte que siga ejecutándose tras esa excepción. En la ruta normal de timeout del supervisor, la excepción termina ese hilo; después `_release_clipboard()` puede observar que el supervisor ya no vive y fallar en `proc.poll() is not None`, pero esa aserción no mata ni reapsa el proceso. Si el supervisor sigue vivo tras `join(timeout=5.0)`, la primera aserción falla igualmente sin cleanup de último recurso.

Tail tiene además una diferencia en readiness: en `tests/test_b103_clipboard_tail.py:1329-1332`, si `_reap_holder(proc)` lanza, no se alcanza `reader.join(timeout=1.0)`. Windows sí protege ese join con `finally` en `tests/test_b103_clipboard_windows.py:469-474`, pero comparte el residual de proceso vivo descrito arriba.

Por tanto, los timeouts acotan la espera principal, pero no cumplen todavía la condición SEC-01 «fallar acotadamente, nunca colgar el step ni dejar proceso». Es un camino de error, no un fallo determinista del camino normal; aun así puede contaminar el siguiente acceso OS con un holder vivo.

**Desbloqueo:** propagar el error del supervisor al estado, y hacer que release/cleanup tenga un `finally` de último recurso que intente reap acotado, cierre recursos sin ocultar el fallo primario y compruebe explícitamente la muerte antes del siguiente acceso OS. Aplicar el mismo patrón a ambos holders y al `reader.join` de tail.

### TR-02 — HIGH · impl — el reader PowerShell de producto todavía trunca todos los CR/LF finales del contenido

Ubicaciones actuales: `s19_app/tui/os_clipboard_input.py:322-323` y `:341-342`; cobertura insuficiente en `tests/test_b103_clipboard_windows.py:1755-1777` y `tests/test_b103_clipboard_tail.py:1112-1150`.

El nuevo `[Console]::Out.Write((Get-Clipboard -Raw))` ya no añade un salto de transporte. Sin embargo, inmediatamente después, Python ejecuta:

```python
text = result.stdout.rstrip("\r\n")
```

Eso no distingue un salto añadido por el proceso —que ahora no existe— de los saltos reales del clipboard. Una lectura forzada por PowerShell de `"L1\nL2\n"` devuelve `"L1\nL2"`, y también elimina varios LF/CRLF finales. La ruta ctypes no aplica esa transformación, de modo que la cascada cambia el contenido según la estrategia que responda.

El test real forzado R-PASTE.16/1 sólo usa `PS-READ`, sin LF, y el test estático E5 comprueba comandos/encoding, no el valor devuelto por este reader. Ninguno puede exponer esta pérdida. No reabro el BOM de B1: éste es un defecto distinto de exactitud, ya presente en el `rstrip` heredado y todavía vigente en el árbol actual.

**Desbloqueo:** conservar `result.stdout` íntegro —manteniendo sólo la conversión de cadena vacía a `None`— y añadir una ruta real forzada ctypes→fallo / PowerShell→lectura con LF interno y LF final, con comparación exacta. La ejecución Windows posterior debe demostrarlo; el GREEN Linux actual no lo demuestra.

### TR-03 — MEDIUM · design-gap — faltan los controles negativos de holder exigidos por SEC-01

Ubicaciones de los mecanismos sin controles específicos: `tests/test_b103_clipboard_tail.py:1209-1332` y `tests/test_b103_clipboard_windows.py:344-474`.

En los dos archivos de alcance no hay nodos que inyecten:

1. hijo que muere después de anunciar `HOLDING`;
2. hijo que nunca anuncia readiness;
3. `kill`/`wait` que expira o falla;
4. supervisor que no termina, con comprobación posterior de cero procesos vivos.

Las ramas `poll()`, `queue.get(timeout=5.0)`, `join(timeout=...)` y `wait(timeout=3.0)` existen, pero su presencia estática no prueba que el instrumento falle acotadamente ni que limpie bajo esas condiciones. Esto era parte explícita del desbloqueo SEC-01, no una ampliación nueva de alcance. TR-01 muestra además la mutación concreta que estos controles deben discriminar: `wait` que expira con proceso aún vivo.

**Desbloqueo:** añadir controles con dobles de proceso/hilo para cada fallo, con deadline externo y aserción final de reap/cierre. No contarlos como ejecutados hasta disponer de resultados reales por nodo.

### TR-04 — MEDIUM · design-gap — no hay brazo exacto de LF final a través del writer PowerShell forzado

Ubicaciones actuales: `tests/test_b103_clipboard_tail.py:52`, `:740-751`, `:1048-1095`, `:1112-1150` y `:1153-1165`; conversión a writer real por defecto en `:128-133`.

`test_e5_powershell_preserves_lf_and_emits_bom_free_readers` es un guarda estructural útil: exige `ReadToEnd`, `SetText($text)` y UTF-8 sin BOM. No ejecuta ni compara un payload con LF final. El brazo hostile sí fuerza PowerShell y compara exactamente, pero `HOSTILE_NAME` contiene un único LF interno y termina en `SUFFIX`, no en LF. R-COPY.7/5 sí tiene `final-lf`, pero usa `_box_observation` con la cascada normal; en Windows puede tener éxito Win32 antes de PowerShell, por lo que no fija el brazo forzado.

En consecuencia, una transformación conceptual que eliminara sólo el LF final dentro de `_write_via_powershell` podría conservar verdes el guarda estático, el hostile y R-COPY.7/5 cuando Win32 tenga éxito. Es un ejemplo de falsificabilidad pendiente, no un mutante ejecutado ni un resultado observado.

**Desbloqueo:** añadir a la ruta `strategies=(("powershell", ...),)` un payload que contenga LF interno y termine en LF, exigiendo app/OSC/separate read exactos. Mantener también el brazo sin LF final para distinguir ambos casos.

## Bloqueos anteriores corregidos estáticamente

### B1 — BLOCKER anterior · impl — corregido en los readers del alcance

- Producto usa `[System.Text.UTF8Encoding]::new($false)` y `[Console]::Out.Write(...)` en `s19_app/tui/os_clipboard_input.py:322-323`.
- El separate read de tail usa el mismo encoding sin BOM y codifica el texto en Base64 en `tests/test_b103_clipboard_tail.py:226-255`; comprueba exit/stderr y decodifica con `validate=True` y UTF-8 estricto en `:256-263`.
- El guarda estático recorre ambos readers en `tests/test_b103_clipboard_tail.py:1123-1148`.

Ya no aparece `Encoding.UTF8` como `OutputEncoding` en estos readers ni `Get-Clipboard` emitido por el pipeline con BOM. La conservación exacta del separate read no se degrada con `rstrip`. Este cierre no certifica readers de otros archivos fuera del alcance A ni sustituye TR-02 en el reader de producto.

### B2 — BLOCKER anterior · impl — corregido estructuralmente; queda la cobertura de TR-04

- `_POWERSHELL_WRITE_COMMAND` lee stdin completo con `[Console]::In.ReadToEnd()` y llama a `[Windows.Clipboard]::SetText($text)` en `s19_app/tui/os_clipboard_input.py:130-137`.
- La entrada sigue siendo UTF-8 sin BOM y el payload viaja por `input`, no por argv, en `s19_app/tui/os_clipboard_input.py:454-479`.
- El hostile fuerza exclusivamente esa estrategia en `tests/test_b103_clipboard_tail.py:1058-1065`, espera el tail antes de observar en `:1092-1095` y exige payload/argv/proceso exactos en `:1153-1196`.

La antigua reconstrucción `$input | Set-Clipboard` ya no está en el writer. La implementación actual no divide ni reconstruye líneas, por lo que cierra estáticamente el defecto B2 de LF interno. La comparación real escrita sigue pendiente de WinCI y el LF final forzado queda acotado por TR-04.

### B5 — HIGH anterior · impl — corregido en las tres rutas y sin ruta copy→observe descubierta sin barrera

- `_injected_hex_key_observation`: espera en `tests/test_b103_clipboard_tail.py:591-593`.
- `_line_cut_observation`: espera en `tests/test_b103_clipboard_tail.py:1464-1467`.
- `_unrelated_view_box_observation`: espera en `tests/test_b103_clipboard_tail.py:1497-1506`.

`_wait_copy_tail()` espera `tail_done` y estabiliza en `tests/test_b103_clipboard_tail.py:89-91`. `tail_done` se publica en `finally` al terminar el tail (`:166-172`), y `writer_done` al terminar el writer (`:174-187`). En producto, el tail espera el `run_in_executor` del writer en `s19_app/tui/os_clipboard_input.py:828-830`; por tanto, `tail_done` no se adelanta al writer en la ruta normal.

También se comprobaron las demás rutas copy→`_observe`: view/box/row esperan en `tests/test_b103_clipboard_tail.py:501-574`, hostile en `:1092-1095`, R-PASTE.13 espera explícitamente writer y tail antes de medir/liberar/leer en `:1355-1367`, y responsiveness espera `marker["ended"]` más `tail_done` en `:1391-1419`. En este último, el `finally` exterior de `marked_writer` (`:1393-1399`) termina después del `writer_spy`, por lo que `marker["ended"]` implica también `writer_done`. Las rutas deliberadamente sin copia no necesitan un `tail_done` inexistente.

No encontré en estas rutas normales un nuevo deadlock ni una lectura OS anterior al release/reap. El residual de sincronización/cleanup está en TR-01, no en las tres omisiones originales de B5.

## SEC-01: partes corregidas que no deben reabrirse

- Ambos hijos usan `kernel32.Sleep`, no `user32.Sleep`: `tests/test_b103_clipboard_tail.py:1233-1250` y `tests/test_b103_clipboard_windows.py:374-392`.
- `CreateWindowExW`, `GetModuleHandleW`, `OpenClipboard`, `CloseClipboard`, `DestroyWindow` y `Sleep` tienen `argtypes`/`restype` en esos mismos rangos.
- Readiness usa cola con timeout, comprueba anuncio y vida posterior: tail `tests/test_b103_clipboard_tail.py:1282-1304`; Windows `tests/test_b103_clipboard_windows.py:425-450`.
- El padre verifica que el hold impide abrir el clipboard: tail `:1306-1317`; Windows `:451-457` y `:477-494`.
- Los hijos cierran clipboard/destruyen ventana en sus salidas normales por excepción: tail `:1258-1270`; Windows `:401-413`.
- Los supervisores tienen espera de release acotada y los callers unen/comprueban antes de seguir: tail `:1319-1327` y `:1219-1223`; Windows `:459-467` y `:354-358`.
- Las 13 llamadas léxicas a `_hold_clipboard` del archivo Windows tienen release en `finally`; las rutas held de tail liberan antes de `_observe` en `:503-513`, `:567-574`, `:1355-1367` y `:1400-1419`.

Esto cierra los defectos principales de DLL, prototipos, readiness bloqueante y falta sistemática de join del informe anterior. No convierte los helpers en ejecutados ni elimina TR-01/TR-03.

## Condiciones para cambiar este área a GO

1. Cerrar TR-01 con cleanup de último recurso común a ambos holders y comprobación de cero procesos vivos en todos los caminos.
2. Eliminar la pérdida de CR/LF finales de TR-02 y dejar una comparación exacta del reader forzado.
3. Implementar los controles negativos de TR-03 exigidos por SEC-01.
4. Añadir el brazo forzado con LF final de TR-04 o registrar una decisión explícita de alcance que explique por qué no se exige esa exactitud en PowerShell.
5. Ejecutar posteriormente la selección WinCI serial y los controles negativos, con resultados reales por nodo/brazo. Hasta entonces, todo lo anterior es sólo revisión estática.

No procede declarar WinCI GREEN, cobertura completa, AT-I1b-8 verificado ni mutantes de producto ejecutados a partir de este informe.
