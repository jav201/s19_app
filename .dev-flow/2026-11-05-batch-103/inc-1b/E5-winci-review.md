# E5 — Revisión WinCI readiness (Inc 1b)

Commit revisado: `25563883f24ad96ee52881628bb06d56b4e0c597` (`25563883`).

Alcance: revisión estática de `.github/workflows/clipboard-windows.yml`, los cuatro tests Inc 1b incluidos allí, sus fixtures/helpers y las rutas de producto necesarias para interpretar la sincronización. No leí ni edité `02-test-cases.md`. No ejecuté tests, colección de pytest, aplicación, probes, mutantes ni clipboard; tampoco ejecuté WinCI. Los conteos siguientes son estáticos, no resultados de ejecución.

## Veredicto

**NO-GO para declarar WinCI listo o GREEN.** El workflow sí selecciona los cuatro archivos, pero:

1. El holder tiene un fallo Win32 probablemente determinista y puede anunciar `HOLDING` justo antes de morir.
2. Las rutas held leen el clipboard antes de liberarlo y una de ellas no espera el fin del writer; hay riesgo alto de falsos fallos y de un job colgado hasta 60 minutos.
3. Faltan **11 rutas WinCI obligatorias**: **2 tail + 9 quit**. La ruta hostile/forced-PowerShell real está explícitamente sin implementar.
4. La lectura PowerShell compartida elimina todos los CR/LF finales, incompatible con el brazo `final-lf` que sí se ejecuta en WinCI.
5. Las 14 celdas P2 tienen la cadena real copy → separate read → `events.Paste`, pero la sincronización y la guarda de aislamiento de matrix todavía no son suficientemente robustas.

## 1. Censo y cableado del workflow

El censo estático de los cuatro archivos es **141 nodos = 112 casos de requisitos + 28 celdas AT + 1 manual**. Hay **108 obligaciones automatizadas WinCI** (80 de requisitos + 28 AT): **97 tienen ruta real escrita y 11 no**. Esto describe código presente, no pasadas.

| Archivo | Nodos estáticos | Obligaciones WinCI | Sin ruta WinCI real |
|---|---:|---:|---:|
| `tests/test_b103_copy_views.py` | 54 | 46 | 0 |
| `tests/test_b103_clipboard_tail.py` | 30 | 25 | 2 |
| `tests/test_b103_copy_quit_dialog.py` | 28 | 9 | 9 |
| `tests/test_b103_copy_paste_matrix.py` | 29 (28 AT + manual) | 28 | 0 |
| **Total** | **141** | **108** | **11** |

Cableado correcto:

- `workflow_dispatch`, `push` y `pull_request` están declarados en `.github/workflows/clipboard-windows.yml:6-33`.
- Los cuatro tests aparecen tanto en `push.paths` (`:16-19`) como en `pull_request.paths` (`:29-32`).
- El job usa `windows-latest`, Python 3.11 y una sola invocación serial de pytest (`:40-51,63-64`).
- El comando incluye los cuatro tests nuevos y los dos heredados de Inc 1a, seis archivos en total (`:64`).
- `permissions: contents: read` y `persist-credentials: false` son adecuados (`:35-36,43-46`).

Límites del cableado:

- Sólo hay `timeout-minutes: 60` a nivel job (`:41`); no hay timeout de step ni de cada test. Esto importa porque el holder usa un `readline()` sin timeout.
- Las listas `paths` tienen 11 entradas, pero omiten dependencias que cambian el resultado: `tests/conftest.py` (aislamiento global), `tests/support/timing.py`, `examples/case_00_public/*`, `requirements.txt` y `pyproject.toml`. Un cambio exclusivo en cualquiera de ellos no dispara WinCI. Tampoco están las demás rutas de producto importadas por `app.py`.
- `requirements.txt:3-5` y `pyproject.toml:46-58` dejan Textual en `>=8.2.8,<9`; el workflow lo imprime pero no lo fija (`.github/workflows/clipboard-windows.yml:60-61`). Los tests usan numerosas APIs privadas (`_notifications`, `_driver`, `screen.selections`), así que una nueva 8.x puede romper colección o fixtures sin cambio del repo.
- Las líneas `run` actuales son compatibles con el `pwsh` predeterminado de GitHub Windows; no encontré un error de quoting/shell en ellas. Los imports internos comprobados existen, `tmp_path`/`monkeypatch` son fixtures de pytest y los tests async se envuelven con `asyncio.run`, sin necesidad de otro plugin. Esto no sustituye una colección real, que no se ejecutó.

## 2. Fallos probables de CI

### B1 — El holder llama a una API en la DLL equivocada

`tests/test_b103_clipboard_tail.py:1040-1094` crea el proceso que mantiene abierto el clipboard. El hijo:

1. abre el clipboard e imprime `HOLDING` (`:1054-1059`);
2. entra en el bucle y llama a `user32.Sleep(20)` (`:1060-1062`).

`Sleep` es exportada por **kernel32**, no por user32. En Windows, la resolución de `ctypes.windll.user32.Sleep` debe producir `AttributeError`; como el anuncio se hace antes, el padre puede aceptar el holder en `:1071-1074` justo cuando el hijo ya está saliendo y liberando el clipboard. Después, la comprobación `:1081-1086` puede fallar con `clipboard hold not effective`, o el writer puede tener éxito donde el test exige fallo.

Afecta a **5 nodos WinCI**:

- R-PASTE.13/101 (`:1105-1129`).
- R-PASTE.14/101…103 (`:1188-1209`).
- El brazo `failed-over-cap-write` de R-COPY.9/1 (`:782-797`), que activa `held=True`.

Además:

- `proc.stdout.readline()` no tiene timeout (`:1071`). Si el hijo no llega a imprimir una línea, sólo el timeout global de 60 minutos detiene el job.
- `CreateWindowExW` y `GetModuleHandleW` se usan sin `argtypes`/`restype` (`:1050`), otro riesgo de handle inválido en Windows de 64 bits.

### B2 — Held se observa antes de liberar y R-PASTE.13 no espera el writer

Incluso con un holder corregido quedan dos problemas independientes:

- R-PASTE.13 evalúa `_observe(...)` en `:1122` y sólo después ejecuta `held["release"].set()` en `:1124`.
- Las tres rutas R-PASTE.14 hacen lo mismo: `_observe(...)` en `:1173`, liberación en `:1175`.

`_observe` llama a `_read_os`, que termina en `other_program_read()` (`:210-218,221-243`). Ésa es otra operación sobre el mismo clipboard todavía retenido. El helper PowerShell no comprueba `returncode` y devuelve `stdout.rstrip(...)` (`tests/support/b103_clipboard.py:584-595`), de modo que un `Get-Clipboard` fallido puede convertirse en `""` y fallar la seed esperada, no en un diagnóstico de infraestructura.

Además, R-PASTE.13 mide sólo alrededor de `_right_click` (`tests/test_b103_clipboard_tail.py:1119-1122`). Ese helper hace pausas fijas (`:110-117`), pero no espera un marcador de writer/tail. El producto sí espera `run_in_executor` dentro del tail (`s19_app/tui/os_clipboard_input.py:815-835`), y el writer puede reintentar ctypes y PowerShell hasta aproximadamente 2,1 s (`:88-97`). Por tanto, el elapsed y `_observe` pueden adelantarse al notice/fallo final. R-PASTE.14 sí tiene un wait por `marker["ended"]` (`tests/test_b103_clipboard_tail.py:1167-1171`), pero sigue leyendo antes de liberar.

Matrix tiene una carrera análoga en casos normales: `_right_click` sólo espera 12 pausas de 0,05 s (`tests/test_b103_copy_paste_matrix.py:294-316`) y luego exige notice y separate read (`:386-397`). No espera `tail_done`/writer. `copy_views` sí muestra el patrón correcto con `_wait_copy_tail` (`tests/test_b103_copy_views.py:136-144`).

### B3 — El separate read no conserva un LF final

`other_program_read()` termina con `result.stdout.rstrip("\r\n")` (`tests/support/b103_clipboard.py:588-595`). Eso no elimina únicamente el salto que pueda añadir el proceso: elimina también todos los saltos que pertenecen al payload.

R-COPY.7/5 ejecuta en WinCI dos brazos, `L1\nL2\nL3` y `L1\nL2\nL3\n` (`tests/test_b103_clipboard_tail.py:666-677`). `_success` exige `obs["os"] == original[:CAP]` (`:257-275`). El brazo `final-lf` es, por tanto, un fallo probable de WinCI aunque app/writer/OSC conserven el texto. El reader de matrix sí evita esta ambigüedad codificando el texto en Base64 (`tests/test_b103_copy_paste_matrix.py:99-108`).

### B4 — La guarda de matrix no es la guarda completa y su PowerShell viene de PATH

La guarda compartida exige plataforma, `GITHUB_ACTIONS`, `RUNNER_ENVIRONMENT=github-hosted` y cuenta `runneradmin` (`tests/support/b103_clipboard.py:105-143`). En cambio, `_is_winci()` de matrix omite la cuenta (`tests/test_b103_copy_paste_matrix.py:20-25`) y autoriza la seed PowerShell en `:373-374`.

La fixture global sí calcula la guarda completa, pero sus stand-ins protegen el boundary de producto; no sustituyen el `subprocess.run` directo de matrix. En un Windows que declare GitHub hosted pero tenga otra cuenta, matrix podría escribir mediante su propio PowerShell en vez de fallar antes de abrir el clipboard. En el runner estándar se espera `runneradmin`, así que esto es principalmente una brecha de seguridad/aislamiento, no una predicción de fallo en todo run.

Además, `_powershell()` acepta el primer `powershell.exe`/`powershell` de `PATH` (`tests/test_b103_copy_paste_matrix.py:49-56`). Obtener una ruta absoluta con `resolve()` no demuestra que sea la del sistema. El resolver de producto sí deriva `GetSystemDirectoryW` y construye la ruta WindowsPowerShell (`s19_app/tui/os_clipboard_input.py:157-196`). La seed Base64 evita interpolar el payload en `-Command`, pero no corrige la procedencia del ejecutable.

### B5 — Los thresholds comprobados en CI no son los números nominales

`timing_bound` duplica el límite cuando `CI` es truthy (`tests/support/timing.py:36-42`), como ocurre en GitHub Actions:

- R-PASTE.13 comprueba **5,0 s**, no 2,5 s (`tests/test_b103_clipboard_tail.py:1128-1129`).
- R-PASTE.14 comprueba latencia máxima **0,2 s**, no 0,1 s (`:1183-1185`).
- Los límites de salida de 1 s del archivo quit pasan a **2 s** (`tests/test_b103_copy_quit_dialog.py:129-137,386-395`).

Puede ser una decisión de margen CI, pero una pasada no demostraría el threshold nominal sin registrar esta conversión.

## 3. Seed/read/write reales por archivo

### Views/gestures

La fixture exige aislamiento y probe en Windows (`tests/test_b103_copy_views.py:65-76`), y el spy delega en el writer real (`:78-87`). `_arm` siembra app y OS (`:181-188`); `_assert_os` y `_assert_no_os_write` usan una lectura PowerShell separada (`:221-256`). El skip `R-COPY.2/4` de `:488-489` es un brazo Linux-only de writer fallido, no una de las 11 rutas ausentes.

Precisión sobre la seed: `other_program_write()` toca el OS real, pero ya no es otro proceso; delega en `_own_write` ctypes y se autoverifica con `own_read` (`tests/support/b103_clipboard.py:553-581`). La independencia fuerte está en la lectura PowerShell posterior, no en la escritura de la seed.

### Clipboard/tail

`_instrument` activa guarda/probe, seed OS y writer real en Windows (`tests/test_b103_clipboard_tail.py:120-125,161-182`). `_read_os` restaura temporalmente el proceso real y llama al separate reader (`:210-218`). Hay **7 skips condicionados por Windows**:

- 5 brazos Linux-only previstos: R-COPY.7/8, R-PASTE.9/101…103 y R-PASTE.10/101 (`:729-734,889-923`).
- 2 obligaciones WinCI todavía sin ruta: R-TUI-043.13/101 y /102 (`:926-951,1008-1027`).

Sumando el skip Linux-only `R-COPY.2/4` de views, los cuatro archivos tienen **8 skips por plataforma: 6 previstos + 2 rutas WinCI ausentes**. AT-I1b-8 añade un skip manual independiente.

### Quit/dialog y seeds R-COPY.16/.20

La fixture sustituye reader/writer en **todas** las plataformas (`tests/test_b103_copy_quit_dialog.py:68-96`); `write` sólo cambia `recorder.os_value`. `_assert_no_copy_effects` comprueba ese recorder (`:300-314`). El propio docstring declara que ningún test abre un clipboard real (`:1-7`). No hay guarda WinCI, seed OS ni `other_program_read` en el archivo.

Faltan exactamente **9 obligaciones**, no 10:

- R-COPY.16/1…6: 6 nodos (`:452-559`). Falta OS=seed con body B abierto y después de Stay, incluidos los armings materializados y los dos tamaños de `/1`.
- R-COPY.20/1…3: 3 nodos (`:643-706`). Falta OS=seed antes/después de Ctrl+C y en el cierre modal correspondiente.
- R-COPY.20/4 (`:709-733`) es el brazo Linux-only busy; no se cuenta como ruta WinCI ausente aunque también use recorder.

R-COPY.6/1…5 de tail sí contiene lecturas OS reales con diálogo abierto y tras `n` (`tests/test_b103_clipboard_tail.py:524-637`), pero eso no añade las seeds a los armings materializados/multilínea/modales ni completa los otros oráculos de estos 9 nodos.

### Acceptance matrix y P2

Las **28 celdas automatizadas** tienen ruta escrita: 14 P1 y 14 P2. En WinCI, matrix siembra con `Set-Clipboard` y verifica la seed (`tests/test_b103_copy_paste_matrix.py:89-96,373-374`), copia mediante right-click (`:380-382`) y exige separate read igual al texto capturado (`:392-397`).

En las **14 P2**, el valor publicado es precisamente `os_artifact` de ese separate read, no `expected`: `app.post_message(events.Paste(os_artifact))` (`:398-403`). T1 exige la primera línea y T2 todo el texto una sola vez (`:405-413`). Por tanto, P2 no es una ruta ausente; sus riesgos abiertos son la carrera de finalización, la guarda y el origen de PowerShell descritos arriba.

AT-I1b-8 permanece correctamente excluido de automatización (`:456-463`): es una aceptación manual del operador y WinCI no la sustituye.

## 4. Hostile PowerShell: lo probado y lo que falta

El ensayo actual es un unitario Linux útil: comprueba argv estático, `shell=False`, `cwd`, payload sólo en stdin y ausencia en argv/logs (`tests/test_b103_clipboard_tail.py:1008-1027`). Pero simula el entorno parcheando `sys`, executable, directorio y proceso (`:954-991`) y en Windows hace skip explícito porque la lectura WinCI no está implementada (`:1011-1012`).

En WinCI hay, por tanto, **0 copias hostiles escritas por el PowerShell real forzado**. Las lecturas PowerShell de matrix o las escrituras normales por la cascada Win32→PowerShell no demuestran este caso. Falta una rama pass-through que fuerce `strategies=(("powershell", _write_via_powershell),)`, mantenga executable/proceso reales, y exija app/OSC/separate read exactamente iguales a `HOSTILE_NAME`, un solo proceso y logs limpios.

## 5. Desbloqueo mínimo, sin editar en esta revisión

1. Corregir el holder y sus prototipos Win32; acotar `readline`/esperas y comprobar que el proceso sigue vivo durante todo el ensayo.
2. Esperar el writer/tail antes de medir o assertar, liberar y hacer join del holder antes del separate read; comprobar `returncode` del reader.
3. Usar una lectura exacta para copias con CR/LF finales, como la variante Base64 ya presente en matrix.
4. Implementar las 2 ramas tail y las 9 ramas quit que faltan; no convertir sus skips/recorders en evidencia WinCI.
5. Aplicar la guarda completa en matrix, resolver PowerShell del sistema y sincronizar las 28 celdas antes del notice/read/paste.
6. Añadir timeout de step/test, ampliar los `paths` de dependencias y fijar la versión Textual usada para la evidencia.

Hasta esos cambios y una ejecución posterior con resultados por nodeid y brazo, este documento no declara WinCI ejecutado, mutantes ejecutados ni cobertura GREEN.
