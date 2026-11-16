# Inc 1b — E5 final review: aislamiento y procesos

Base revisada: HEAD `305e5892` más el working tree actual. Revisión independiente limitada a C-01…C-04 y SEC-02/04/05 en `tests/support/b103_clipboard.py`, `tests/test_b103_clipboard_windows.py`, `tests/test_b103_copy_quit_dialog.py`, `tests/test_b103_copy_paste_matrix.py`, las rutas necesarias de `tests/test_b103_clipboard_tail.py`, `tests/test_b103_e5_safety.py`, `tests/conftest.py` y `s19_app/tui/os_clipboard_input.py`.

Revisión sólo estática mediante lecturas acotadas, búsquedas y `git diff/status` de sólo lectura. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto, tests, workflow o evidencia. La única escritura de esta revisión es este informe.

Resultados comunicados, **no repetidos por esta revisión**: seis familias en Linux, `160 passed / 96 skipped` en `1863.17 s`; selección correctiva en Linux, `44 passed / 2 skipped`. **No hay veredicto WinCI ni mutantes de producto ejecutados.** Ninguna ruta escrita se promueve aquí a resultado Windows.

## Veredicto del área

**NO-GO para aislamiento/procesos.** El BLOCKER de assembly de C-01 está corregido y el censo decoy de C-03 ya cubre los launchers conservados. Persisten dos hallazgos MEDIUM: C-02 no prueba Unicode ni CR a través del reader externo independiente de tail, y C-04 deja el holder de tail sin guarda intrínseca antes de crear un proceso y abrir clipboard. Queda además un MINOR de cobertura estática sobre la dependencia de assembly corregida.

No encontré un PATH hijack nuevo ni una regresión nueva en los ataques decoy añadidos. La ausencia de resultados WinCI y de mutantes mantiene además abiertas las puertas de ejecución; no se presenta como evidencia de un defecto observado en Windows.

## Estado de los controles anteriores

| Control | Estado en el árbol actual |
|---|---|
| C-01 / SEC-02, assembly | **Implementación corregida** en `tests/support/b103_clipboard.py:660-668`; queda C-01R, MINOR `design-gap`, por falta del oracle estático pedido. |
| C-02 / SEC-02, seed externa exacta | **Parcial**: shared tiene las cuatro formas escritas; tail conserva un reader separado sin round-trip Unicode/CR. MEDIUM `design-gap`. |
| C-03 / SEC-04, decoy de cada launcher | **Cerrado en ruta escrita** para producto, launcher compartido usado por matrix/quit y reader local de tail. Resultado WinCI pendiente. |
| C-04 / SEC-05, guards intrínsecos | **Parcial**: shared y helpers directos de Windows están guardados; falta `_hold_clipboard` de tail y su control negativo. MEDIUM `impl`. |
| AT-I1b-8 | **Sigue manual y excluida** en `tests/test_b103_copy_paste_matrix.py:437-444`; esta revisión no la cierra ni la ejecuta. |

## Hallazgos restantes

### C-04 — MEDIUM — `impl` — SEC-05: el holder local de tail crea proceso sin guarda intrínseca

`tests/test_b103_clipboard_tail.py:1399-1446` entra en `_hold_clipboard()`, construye el script y llega a `subprocess.Popen` sin llamar antes a `require_isolated_clipboard`. El hijo ejecuta `OpenClipboard` en el script (`tests/test_b103_clipboard_tail.py:1431-1437`) y el padre vuelve a abrir clipboard para verificar el hold (`tests/test_b103_clipboard_tail.py:1479-1488`), también sin una guarda propia previa en este entry point.

La omisión contrasta con:

- el reader local de tail, que sí exige aislamiento antes de resolver PowerShell o lanzar proceso (`tests/test_b103_clipboard_tail.py:227-235`);
- el holder de Windows, ahora guardado antes de `Popen` (`tests/test_b103_clipboard_windows.py:441-451`, `:500-508`);
- el launcher compartido, guardado antes de resolver/ejecutar PowerShell (`tests/support/b103_clipboard.py:615-646`).

El censo negativo nuevo incluye el holder de Windows y nueve entry points, pero no el holder de tail (`tests/test_b103_e5_safety.py:106-156`, censo concreto en `:134-144`). Por tanto, no demuestra cero proceso/clipboard para este helper.

Los llamadores ordinarios revisados sí conservan barreras previas: `_instrument()` invoca `_winci_ready_or_skip()` en Windows (`tests/test_b103_clipboard_tail.py:129-132`) antes de los usos held de `_view_observation`/`_row_observation` (`:513-515`, `:578-580`), y los tests held directos también arman WinCI (`:1807-1809`, `:1896-1898`). **No afirmo una escritura desprotegida ya alcanzada en el call graph pytest normal.** La severidad MEDIUM corresponde a defensa en profundidad: el helper reutilizado directamente no impone el invariante y su hijo no heredaría los stand-ins del proceso pytest.

**Desbloqueo:** llamar a `require_isolated_clipboard("windows")` al inicio de `_hold_clipboard`, antes de cualquier preparación de recursos/proceso, y añadir tail al control negativo con dobles que prueben cero `Popen`, user32 y kernel32 cuando la guarda rechaza. Mantener explícitos los permisos simulados en los controles inertes de cleanup.

### C-02 — MEDIUM — `design-gap` — SEC-02: Unicode y CR no atraviesan el reader externo conservado de tail

La seed compartida sí tiene una ruta WinCI escrita para los cuatro valores conocidos: Unicode (`SEED-Ω-漢字-🙂`), CR, LF y LF final en `tests/test_b103_copy_quit_dialog.py:132-146`, invocada sólo en Windows en `:1033-1034`. El writer compartido realiza además su propia lectura separada exacta (`tests/support/b103_clipboard.py:653-679`). El control Linux con proceso simulado cubre las mismas cuatro formas y Base64 fuera de argv (`tests/test_b103_e5_safety.py:159-193`), pero no es una ejecución del clipboard Windows.

Tail conserva una implementación distinta, `other_program_read()` (`tests/test_b103_clipboard_tail.py:227-264`). Su único round-trip externo discriminating nuevo siembra `final_lf = HOSTILE_NAME + "\n"` y compara ese reader (`:1175-1176`, `:1254`, `:1309-1312`). `HOSTILE_NAME` contiene ASCII de control y LF, pero no Unicode no ASCII ni CR (`:53`). El otro uso del writer compartido siembra el ASCII `SEED-OS-1b` (`:42-43`, `:129-132`). No hay una ruta equivalente que haga pasar Unicode y CR por el reader local de tail.

Esto no demuestra que el reader de tail corrompa esos valores; demuestra que el requisito anterior de valores conocidos Unicode/CR/LF/LF final **para cada implementación externa conservada** sigue incompleto.

**Desbloqueo:** repetir los cuatro valores conocidos mediante `other_program_write()` y el `other_program_read()` local de tail, con igualdad exacta y sin sustituir el brazo WinCI por mocks. Puede reutilizarse el ataque decoy ya escrito, siempre que cada valor llegue efectivamente al reader local.

### C-01R — MINOR — `design-gap` — SEC-02: la dependencia de assembly corregida no queda fijada por un oracle estático

La corrección funcional es visible: `other_program_write()` carga `PresentationCore` inmediatamente antes de `[Windows.Clipboard]::SetText($text)` (`tests/support/b103_clipboard.py:660-668`), igual que el writer de producto (`s19_app/tui/os_clipboard_input.py:130-137`). Ya no carga `System.Windows.Forms`. **El antiguo C-01 BLOCKER de implementación está cerrado; no afirmo un fallo runtime actual.**

Sin embargo, el desbloqueo anterior también pedía una comprobación estática de esa dependencia. El oracle `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` examina el writer de producto y los readers de producto/tail, no el comando del writer compartido (`tests/test_b103_clipboard_tail.py:1128-1166`). El round-trip con `fake_run` intercepta el proceso y seguiría pasando si se retirara `PresentationCore` del comando (`tests/test_b103_e5_safety.py:167-189`). No hay en tests una aserción que vincule el comando compartido con su assembly.

**Desbloqueo:** añadir una aserción estática sobre el comando real de `other_program_write`: `PresentationCore` presente antes de `Windows.Clipboard.SetText` y la dependencia incompatible ausente. Mantener la ejecución WinCI como prueba funcional separada.

## Controles cerrados en ruta escrita

### SEC-02: proceso externo y transporte compartido

- Writer y reader compartidos llaman cada uno a `_run_system_powershell()`; cada llamada ejecuta un `subprocess.run` nuevo y síncrono (`tests/support/b103_clipboard.py:615-668`, `:682-703`). La escritura ya no se fabrica con ctypes dentro de pytest.
- El writer transporta Base64 de UTF-16LE por stdin, sin payload en argv (`:657-668`). El reader emite Base64 de UTF-8 sin BOM y decodifica con `validate=True`, sin `rstrip` sobre el payload (`:686-706`).
- Quit ya no conserva un launcher PowerShell duplicado: sus lecturas/escrituras delegan en shared (`tests/test_b103_copy_quit_dialog.py:122-140`). Matrix usa los mismos entry points (`tests/test_b103_copy_paste_matrix.py:52-57`).

Estas son conclusiones de estructura y cobertura escrita, no un round-trip WinCI observado.

### SEC-04: decoy efectivo para todos los launchers conservados

- **Producto lectura/escritura:** se compila un `powershell.exe` real con marcador y se instala tanto en cwd como al frente de PATH (`tests/test_b103_clipboard_windows.py:2173-2219`). Se fuerzan ambos rescates (`:2221-2232`), se exigen valores exactos, arranques y sólo el `argv[0]` del sistema, y marcador ausente (`:2260-2274`). Ya no se acepta `started=[]`.
- **Launcher compartido, incluido matrix/quit:** `other_program_read()` se ejecuta después de restaurar el spy pero mientras cwd/PATH siguen hostiles (`tests/test_b103_clipboard_windows.py:2254-2260`); su igualdad exacta y el marcador final (`:2262-2274`) hacen el brazo no vacuo. Reader y writer comparten el único launcher guardado de `tests/support/b103_clipboard.py:615-646`.
- **Reader local de tail:** el brazo WinCI crea sus propios decoys en cwd/PATH (`tests/test_b103_clipboard_tail.py:1254-1300`), ejecuta producto y reader local bajo el ataque, exige exactamente dos arranques con el PowerShell del sistema, igualdad exacta y marcador ausente (`:1301-1323`).

En Linux, `forced_reader()` retorna tras el brazo simulado (`tests/test_b103_clipboard_tail.py:1230-1252`), antes del ataque real de `:1254-1323`. Por ello los GREEN Linux comunicados no cierran la ejecución decoy WinCI.

### SEC-05 y holders: correcciones presentes fuera de la omisión tail

- `_run_system_powershell`, `other_program_write/read`, `_own_write`, `own_read` y `clipboard_sequence_number` tienen guards antes de sus boundaries (`tests/support/b103_clipboard.py:615-620`, `:653-656`, `:682-685`, `:709-714`, `:749-753`, `:784-790`).
- Los cinco helpers directos censados antes en Windows tienen ahora guarda antes de ctypes/proceso (`tests/test_b103_clipboard_windows.py:304-310`, `:441-451`, `:570-580`, `:917-921`, `:1153-1159`). El control negativo escrito prueba rechazo antes de user32/kernel32/proceso (`tests/test_b103_e5_safety.py:106-156`).
- Los reaps/releases acotados y sus dobles de fallo están escritos para Windows y tail (`tests/test_b103_clipboard_windows.py:386-438`, `:593-594`; `tests/test_b103_clipboard_tail.py:1343-1396`, `:1546-1795`). No se reclama aquí el resultado WinCI de holders vivos cero.

## Puerta para cambiar el veredicto

1. Corregir C-04 en el holder de tail y añadir su control negativo de cero recurso/proceso.
2. Completar C-02 con Unicode y CR —conservando LF y LF final— a través del reader local de tail.
3. Fijar C-01R con el oracle estático de la dependencia del writer compartido.
4. Ejecutar WinCI sobre las rutas reales: assembly/seed externa exacta, decoys, guards y holders con cleanup verificado. Los resultados Linux y esta lectura estática no sustituyen esa evidencia.
5. Ejecutar los mutantes de producto previstos antes de cualquier promoción final. Mantener AT-I1b-8 como aceptación manual separada; no cerrarla desde esta revisión.
