# Batch-103 Inc1b E5 — Carril C: Windows safety

Base: `305e5892` más el trabajo no commitido ya presente. Alcance exclusivo aplicado a `tests/test_b103_clipboard_windows.py` y al nuevo `tests/test_b103_e5_safety.py`; este informe es la única escritura bajo `.dev-flow`. No se editaron producto, `support`, tail, ledger, canon ni evidencia previa.

## Cambios

### TR-01 / TR-03 — holder y cleanup

- `tests/test_b103_clipboard_windows.py:386`: `_reap_holder()` intenta poll/kill, reap acotado, cierre de stdout y comprobación final de muerte aunque falle una etapa. Conserva como primaria la primera excepción y añade las posteriores sólo como notas por etapa/tipo.
- `tests/test_b103_clipboard_windows.py:421`: `_release_clipboard()` ejecuta cleanup final incluso si fallan `release.set()`, join, la comprobación del supervisor o el error propagado por éste. El cleanup final no sustituye la excepción primaria.
- `tests/test_b103_clipboard_windows.py:441`: el supervisor guarda y propaga su error; la salida por error de readiness conserva el fallo original mientras intenta reap, cierre y join del reader.
- `tests/test_b103_clipboard_windows.py:593`: cuatro controles con dobles inertes y deadline externo de 2 s: muerte tras `HOLDING`, ausencia de readiness, fallos de `kill`/`wait` —incluida preservación de la primaria— y supervisor que no termina. Comprueban reap/cierre/poll final y, cuando el doble permite morir, ausencia de proceso vivo.
- Los cuatro controles se invocan dentro del nodo ya existente `test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails` (`tests/test_b103_clipboard_windows.py:2320`). No se añadieron funciones `test_*`, parametrizaciones ni decoradores al archivo WinCI.

### D-02 / D-05 — logs y clasificación

- `tests/test_b103_clipboard_windows.py:143`: censo común de formas full, prefijo, `repr`, `unicode_escape`, XML textual, XML con CR numérico y XML de atributo con CR/LF/TAB numéricos, incluidos prefijos derivados.
- `tests/test_b103_clipboard_windows.py:165`: los `LogRecord` se formatean con `logging.Formatter`, incorporando mensaje, `exc_info` y `stack_info`; las tuplas heredadas siguen aceptándose mediante su tercer campo.
- `tests/test_b103_clipboard_windows.py:173`: `_assert_log_excludes()` busca todas las formas en la entrada formateada y su assertion informa sólo etiqueta, índices, conteos y nombres de formas, nunca el canario ni fragmentos del log.
- Los dos consumidores WinCI devuelven los records a `_assert_log_excludes()` en vez de descartar previamente su estructura.
- `tests/test_b103_clipboard_windows.py:188`: el clasificador reconoce el prefijo real `win32 write ok; PowerShell read mismatch;` y devuelve `stage=round-trip-mismatch` con longitud, sin copiar el detalle.

### C-04 y lectura PowerShell forzada

- Guardas intrínsecas antes de ctypes/proceso en `_write_nontext_clipboard` (`:304`), `_hold_clipboard` (`:441`), `_open_clipboard_probe` (`:570`), `_write_empty_unicode_text` (`:917`) y `_own_write_no_terminator` (`:1153`).
- `test_r_paste_16_1_read_rescue_starts_system_powershell` (`:2106`) conserva su nodeid y ahora fuerza la lectura PowerShell con `PS-READ\nL2\n`, comparando exactamente LF interno y LF final. Es un brazo escrito, no un resultado Windows observado.

## Archivo nuevo Linux-safe

`tests/test_b103_e5_safety.py` no pertenece a las seis familias WinCI y no abre clipboard ni crea procesos OS en sus controles directos:

- `:45`: clasificación del mismatch y metadata sin canario.
- `:83`: registros formateados known-bad en mensaje, excepción y stack, recorriendo todas las formas derivadas; también audita que el mensaje de assertion no las repita.
- `:106`: guardas negativas para los cinco helpers directos del archivo Windows y para `_run_system_powershell`, `_own_write`, `own_read` y `clipboard_sequence_number` de `support`, usando dobles que fallan si se alcanza user32/kernel32/proceso.
- `:159`: transporte mock de seeds Unicode, CR, LF y LF final; decodifica la entrada Base64 UTF-16LE, ejecuta el round-trip mock y exige lectura exacta sin payload en argv ni stdin en claro.
- `:428`: control outer/`pytester` con un hijo deliberadamente RED de 12 nodos: probe mismatch, round-trip, excepciones encadenadas de lectura/escritura, mensaje/`exc_info`/`stack_info`, `_counts()` dentro de `_run_arms()`, y cardinalidad/argv/cwd/`kwargs["input"]` hostile. El oráculo exige código no cero y el censo exacto de 12 fallos sin errores de colección.
- El outer audita stdout, stderr, JUnit crudo y una superficie parseada de tags, atributos, texto y tails. Busca full/prefijo/`repr`/escape/formas XML y emite assertions estructuradas sin copiar el canario. También exige marcadores genéricos que discriminan la ruta prevista, incluidos `stage=round-trip-mismatch` y los tres canales de log.

## Verificación estática realizada

- `compile()` sobre `tests/test_b103_clipboard_windows.py`: correcto.
- `compile()` sobre `tests/test_b103_e5_safety.py`: correcto.
- Extracción AST de `_KNOWN_BAD_SOURCE`, sustitución del canario y `compile()` de la fuente efectiva del hijo: correcto.
- Censo AST del hijo: 12 nodos escritos, exactamente los 12 esperados; sin faltantes ni inesperados.
- Censo AST del archivo WinCI contra `HEAD`: 51 tests antes/después; `REMOVED []`, `ADDED []`, `DECORATOR_CHANGES []`.
- `git diff --check -- tests/test_b103_clipboard_windows.py`: terminó sin errores.
- Chequeo directo de trailing whitespace, marcadores de conflicto y LF final en `tests/test_b103_e5_safety.py` y este informe: correcto. El intento `git diff --no-index` sobre el archivo untracked sólo produjo el aviso de conversión LF→CRLF, sin warnings de whitespace ni marcadores de conflicto; no se usó como evidencia de ejecución.

No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflows, batería Linux ni mutantes. No hice commits ni otras mutaciones Git. Por tanto, este informe no atribuye resultados de ejecución, resultados WinCI ni resultados de mutantes; las rutas y controles quedan pendientes de ejecución por el orquestador y de la posterior integración de los demás carriles.

## Continuación acotada tras la ejecución Linux aportada

El caller comunicó `8 failed / 4 passed` en el hijo outer, frente a los 12 fallos deliberados requeridos. Sin repetir esa ejecución, se aplicaron dos correcciones en `tests/test_b103_e5_safety.py`:

- El doble hostile usa ahora la costura real `_powershell_transport_observation(tmp_path, monkeypatch, payload)` y genera un ledger específico para cada payload. Las sustituciones externas se hacen por asignación directa con restauración en `finally`, de modo que sobreviven a los `monkeypatch.undo()` de `_run_arms()` entre los brazos hostile. El marcador seguro esperado refleja el fallo agregado real `clipboard arm failures: hostile-no-final-lf, hostile-final-lf`.
- El brazo `stack_info` construye un `logging.LogRecord` real con `sinfo="frame\n" + CANARY` y lo emite mediante `logger.handle(record)`. Ya no depende del comportamiento de `logger.error(stack_info=<str>)` en Python 3.11.

Se conservan los 12 nodeids known-bad, el requisito de hijo deliberadamente RED y las auditorías de stdout, stderr, JUnit crudo y JUnit parseado. No se modificó tail ni el workflow.

Verificación de esta continuación: `compile()` correcto del archivo y de la fuente efectiva del hijo; censo AST de 12/12; ausencia de la costura antigua; presencia de la costura nueva; comprobación AST de `LogRecord(sinfo=...)` y `logger.handle(record)`; higiene de whitespace y LF final correcta. No ejecuté pytest ni realicé mutaciones Git en esta continuación, por lo que no se añade ningún resultado Linux/WinCI nuevo.
