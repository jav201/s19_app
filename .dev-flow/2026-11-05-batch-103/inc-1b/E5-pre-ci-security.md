# Inc 1b — E5 pre-CI security review

Base revisada: HEAD `0d4d4e7c` más los cambios E5 sin commit. Revisión estática del diff, `E5-winci-review.md`, `E5-coverage-plan.md`, los seis archivos que ejecuta el workflow, los helpers de clipboard y las rutas de producto necesarias para interpretar PowerShell. También se inspeccionaron los reportes y la evidencia E5 con búsquedas acotadas de credenciales y canarios.

No ejecuté tests, colección de pytest, aplicación, probes, PowerShell, clipboard, workflow ni mutantes. **No declaro CI ni mutantes ejecutados.** No modifiqué producto, tests, workflow ni ledger. `git diff --check` terminó sin errores; Git sólo emitió avisos de conversión LF→CRLF para dos archivos ya modificados.

## Veredicto

**NO-GO para push como batería pre-CI segura/lista.** Los bloqueos son SEC-01 a SEC-04:

1. El holder heredado que sí forma parte del workflow sigue roto y tiene esperas sin cota.
2. Views, tail y quit no siembran mediante el proceso separado que exige el contrato.
3. Los caminos de fallo pueden republicar clipboard/payload en transcripts y JUnit.
4. La prueba que afirma cubrir un PowerShell decoy en cwd/PATH no ejercita ese ataque.

SEC-05 es un riesgo medio de defensa en profundidad, no una escritura desprotegida en el call graph actual. Las rutas WinCI nuevas están escritas, pero no se cuentan como ejecutadas, GREEN ni cobertura completa.

## Hallazgos

### SEC-01 — ALTA — `impl` — `tests/test_b103_clipboard_windows.py:297-395`

El holder heredado, usado por numerosos tests del archivo incluido en `.github/workflows/clipboard-windows.yml:77`, conserva tres defectos:

- El hijo ejecuta `user32.Sleep(10)` en `tests/test_b103_clipboard_windows.py:360`. `Sleep` pertenece a `kernel32`, no a `user32`; puede morir inmediatamente después de anunciar `HOLDING` en `:343`. El holder nuevo de tail sí usa `kernel32.Sleep` (`tests/test_b103_clipboard_tail.py:1183-1204`), pero no repara este otro holder.
- `proc.stdout.readline()` no tiene timeout (`tests/test_b103_clipboard_windows.py:370`), y el `proc.wait()` de la rama de anuncio inesperado tampoco (`:372-373`). Un hijo que no emite línea, o que emite otra y permanece vivo, puede consumir el timeout de 45 minutos del step.
- El supervisor mata y espera en un hilo daemon (`:388-395`), pero los tests sólo hacen `release.set()` —por ejemplo `:289-294`— sin join ni comprobación de muerte. Una vez corregido `Sleep`, el siguiente test puede competir con un holder todavía vivo.

El probe inicial de hold evita algunos falsos positivos, pero no proporciona disponibilidad ni cleanup acotado. Esto bloquea aunque el holder nuevo de tail esté mejorado.

**Antes de push:** unificar o equiparar este holder con el patrón acotado de tail; usar la DLL correcta, cerrar/destruir recursos, acotar readiness y wait, comprobar vida después de `HOLDING` y hacer join/reap antes del siguiente acceso OS. Ejecutar todos los nodos held de `test_b103_clipboard_windows.py` y los cuatro nodos R-PASTE.13/.14 de tail, con cero holders vivos al terminar cada nodo. Añadir controles de fallo para hijo que muere tras `HOLDING`, hijo que nunca anuncia y kill/wait que expira; deben fallar acotadamente, nunca colgar el step ni dejar proceso.

### SEC-02 — ALTA — `design-gap` — `tests/support/b103_clipboard.py:559-580`

El contrato común dice: «Before each case the **separate process** writes `SEED-1b`» (`.dev-flow/2026-11-05-batch-103/inc-1b/02-test-cases.md:12`). Sin embargo, `other_program_write()` ejecuta `_own_write()` y `own_read()` dentro del proceso pytest (`tests/support/b103_clipboard.py:578-587`). No hay `Popen` ni `subprocess.run` en esa escritura.

Esta helper siembra las rutas de:

- views: `tests/test_b103_copy_views.py:181-188`;
- tail: `tests/test_b103_clipboard_tail.py:128-132`;
- quit: `tests/test_b103_copy_quit_dialog.py:165-167`.

Es una implementación Win32 independiente del writer de producto, pero **no es un programa/proceso externo**. La lectura separada posterior sí existe y matrix sí siembra con otro proceso PowerShell (`tests/test_b103_copy_paste_matrix.py:88-95`); eso no corrige la seed de views/tail/quit. Las nueve ramas quit y las ramas tail antes ausentes no deben promoverse a rutas WinCI conformes conservando esta seed.

**Antes de push:** sembrar desde un proceso distinto, resuelto sin PATH y con transporte exacto, y comprobar el valor mediante la lectura PowerShell separada. Registrar en la prueba que writer y reader son procesos distintos de pytest. Ejercitar seed intacta en todos los rechazos/fallos, y round-trip con Unicode, CR, LF y LF final; una seed fabricada o leída sólo dentro de pytest no cierra este hallazgo.

### SEC-03 — ALTA — `impl` — `tests/support/b103_clipboard.py:198-203`, `tests/test_b103_clipboard_tail.py:355-359`

Hay canales concretos de filtración hacia evidencia precisamente cuando un test falla:

- Si el nonce del probe no coincide, `_probe_once()` devuelve `read_back!r` completo (`tests/support/b103_clipboard.py:201-203`). Ese resultado llega al fallo de `test_runner_clipboard_probe` (`tests/test_b103_clipboard_windows.py:140-145`) o al skip de la fixture (`tests/support/b103_clipboard.py:223-226`). Un clipboard inesperado puede terminar íntegro en el log CI. El round-trip de escritura también incluye los primeros 20 caracteres de ambos valores (`tests/support/b103_clipboard.py:581-587`).
- `_no_secret()` construye una lista de coincidencias, pero usa `messages` como mensaje de la aserción (`tests/test_b103_clipboard_tail.py:355-359`). Si producto registra el secreto, el test lo detecta **y pytest lo vuelve a imprimir**. Otras aserciones hostile incluyen `obs["processes"]` o `kwargs` (`tests/test_b103_clipboard_tail.py:1118-1124`); esos diccionarios contienen `input=HOSTILE_NAME`.
- El handler sólo conserva `record.getMessage()` (`tests/support/b103_clipboard.py:434-442`). No examina `exc_info`/traceback ni `stack_info`, de modo que «cero records con el payload» no cubre todo el contenido que otro handler puede emitir.

Las búsquedas estáticas en `evidence-e5/` no encontraron tokens GitHub, claves privadas, Authorization/Bearer, contraseñas, patrones AWS/JWT ni nonce de probe almacenados. `SECRET-COPY-43` aparece en `evidence-e5/integration-pre-ci.patch:349` como literal del diff fuente, no como salida de un test. Esto no elimina el riesgo de generar un transcript filtrado en el primer fallo WinCI.

**Antes de push:** no devolver contenido del clipboard en probe/round-trip; usar sólo resultado, longitudes y códigos de error. Eliminar payloads y `kwargs` completos de mensajes de aserción, y redactar también logs capturados al fallar. Cubrir `exc_info` y la salida completa de pytest. Añadir pruebas outer/pytester que fuercen mismatch del probe, un log con canario, cardinalidad hostile incorrecta y cwd incorrecto: stdout, stderr y JUnit deben quedar sin payload, prefijo, `repr` ni forma escapada. Repetir la búsqueda de secretos sobre los artefactos finales antes de publicarlos.

### SEC-04 — MEDIA — `design-gap` — `tests/test_b103_clipboard_windows.py:1721-1738`

`test_r_paste_16_3_decoy_powershell_never_runs` afirma probar «a decoy `powershell.exe` in cwd/PATH», pero:

- no crea un decoy ni un marcador de ejecución;
- no cambia cwd ni prepende ninguna carpeta a PATH;
- no fuerza el fallo de ctypes para exigir el rescate PowerShell;
- acepta `started=[]`, porque `not any(...)` también es cierto cuando PowerShell nunca arranca.

Por tanto, la cobertura anti-PATH-hijack es vacua. La implementación actual sí deriva la ruta con `GetSystemDirectoryW` y construye el ejecutable absoluto (`s19_app/tui/os_clipboard_input.py:157-196`), y el writer usa esa ruta y cwd del sistema (`:437-456`). **No encontré un PATH hijack en esa implementación**; el bloqueo es la ausencia de una prueba efectiva del requisito y de protección frente a regresiones.

**Antes de push:** crear un decoy con marcador en cwd y en una carpeta prependida a PATH; forzar por separado los rescates real de lectura y escritura PowerShell. Exigir que el marcador no exista, que cada `argv[0]` sea exactamente el PowerShell absoluto del sistema, que haya al menos un arranque y que el payload/leído sea exacto. Repetir el control con la lectura separada usada por matrix/quit/tail.

### SEC-05 — MEDIA — `impl` — `tests/support/b103_clipboard.py:544-546,559-580,590-600,622-692`

La documentación afirma que ningún helper abre clipboard sin que `require_isolated_clipboard` haya pasado (`tests/support/b103_clipboard.py:17-18,167-168`), pero `other_program_write()`, `other_program_read()`, `_own_write()` y `own_read()` sólo llaman `_require_windows()`. Éste comprueba plataforma, no aislamiento. `_own_write()` puede llegar a `EmptyClipboard` y `SetClipboardData` (`:652-658`).

En el call graph E5 actual sí hay guardas previas: fixtures de views/quit, `_winci_ready_or_skip` de tail, `_coverage_or_skip` de matrix y la fixture global con stand-ins (`tests/conftest.py:65-183`). No identifiqué una escritura E5 actual que las omita. El riesgo es que la helper pública, reutilizada sin esas fixtures o fuera de pytest, no impone por sí misma el invariante que documenta.

**Prueba necesaria:** invocar directamente cada helper en un pytester Windows simulado como no aislado y comprobar fallo antes de cualquier `OpenClipboard`, `EmptyClipboard` o proceso. Mantener los controles actuales para cuenta distinta de `runneradmin`, `GITHUB_ACTIONS` falso y `RUNNER_ENVIRONMENT` no hosted. Conviene cerrar esta defensa antes de reutilizar las helpers; no es la causa principal del NO-GO actual.

## Controles que sí están presentes, sin elevarlos a ejecución

- La guarda compartida exige Windows, GitHub Actions hosted y cuenta `runneradmin` (`tests/support/b103_clipboard.py:105-143`). El workflow usa `windows-latest`, `contents: read` y `persist-credentials: false` (`.github/workflows/clipboard-windows.yml:43-59`).
- La fixture global sustituye los boundaries de producto y `OpenClipboard` en Windows no aislado (`tests/conftest.py:65-183`). AT-I1b-8 permanece skip/manual y no autoriza clipboard del operador (`tests/test_b103_copy_paste_matrix.py:479-486`).
- El writer PowerShell de producto tiene comando estático, `shell=False`, payload por stdin y ruta del sistema (`s19_app/tui/os_clipboard_input.py:415-457`). La rama WinCI hostile fuerza ese writer y comprueba argv/stdin/cardinalidad (`tests/test_b103_clipboard_tail.py:1045-1130`); sus diagnósticos deben corregirse según SEC-03.
- La lectura separada compartida transporta Base64 UTF-8, comprueba `returncode` y ya no aplica `rstrip` al payload (`tests/support/b103_clipboard.py:590-619`). Tail tiene además comprobación de `stderr` (`tests/test_b103_clipboard_tail.py:226-263`). R-COPY.7/5 conserva los dos brazos, sin y con LF final (`:737-748`). Está escrita la ruta de exactitud, no un resultado Windows.
- Matrix espera el tail antes de notice/read/paste (`tests/test_b103_copy_paste_matrix.py:374-420`), y las nuevas rutas held de tail esperan writer/tail y liberan/reapsan antes del separate read (`tests/test_b103_clipboard_tail.py:1277-1354`).

## Cobertura parcial y rutas todavía abiertas

`E5-winci-review.md` revisa `25563883` y `E5-coverage-plan.md` revisa `e8f8e3d`; sus «11 rutas ausentes» no describen literalmente el working tree actual. Las dos ramas tail (`tests/test_b103_clipboard_tail.py:1001-1130`) y las nueve ramas quit (`tests/test_b103_copy_quit_dialog.py:537-797`) ya tienen código WinCI. Se clasifican aquí sólo como **rutas escritas, no ejecutadas**; SEC-02 impide llamarlas conformes sin cambiar la seed.

Siguen sin ruta completa o sin ruta ejecutable:

- La seed realmente externa de SEC-02, la evidencia de fallo sin secretos de SEC-03 y el ataque decoy efectivo de SEC-04.
- **GC-C14**, deliberadamente pendiente hasta disponer de cota externa de tiempo y workers/iteraciones con captura de cardinalidad (`E5-mutant-plan.md:13`). No se lo convierte en ejecutado ni en kill.
- **AT-I1b-8**, que sigue siendo aceptación manual del operador; no debe crearse una ruta automatizada contra su clipboard (`tests/test_b103_copy_paste_matrix.py:479-486`).
- Las lagunas ya inventariadas en `E5-coverage-plan.md:152-186` no se cierran con este diff. En particular, detail-card sigue materializando cinco líneas y declara parcial el brazo de dos (`tests/test_b103_copy_views.py:404-418`), y R-COPY.25/1 sigue sustituyendo `get_selected_text` en el arming view-key (`tests/test_b103_clipboard_tail.py:576-590`). Los controles E3-01, segunda respuesta, cardinalidad de palette y conversiones/selecciones dudosas del plan deben permanecer abiertos hasta sus oráculos específicos.

## Puerta mínima antes de push

1. Corregir SEC-01 a SEC-04 y decidir la guarda intrínseca de SEC-05 sin debilitar las guardas actuales.
2. Ejecutar en Linux la batería completa prevista sobre el árbol integrado, con el censo y skips exactos admitidos; esta revisión no anticipa su resultado.
3. Ejecutar después WinCI serial con los seis archivos del workflow y resultados por nodeid/brazo. Deben quedar explícitos los holders heredados y nuevos, ambos brazos LF, hostile PowerShell real, las nueve rutas quit y las 28 celdas AT. Ningún skip nuevo, timeout o fallo de infraestructura cuenta como cobertura.
4. Archivar los controles negativos de aislamiento, decoy PATH, lifetime/cleanup y redacción de stdout/stderr/JUnit. Publicar sólo artefactos sin contenido del clipboard ni secretos.
5. Mantener AT-I1b-8 como ejecución manual separada y GC-C14 como pendiente hasta que tenga una ruta acotada.

Hasta entonces, no hay base para GO, WinCI GREEN ni cobertura completa.
