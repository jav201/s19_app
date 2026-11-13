# Batch-103 Inc1b E5 — Carril B: helper compartido de clipboard

Base: HEAD `305e5892` más el trabajo E5 no commitido ya presente. Se conservaron los cambios anteriores de `tests/support/b103_clipboard.py`; no se revirtió ni reescribió trabajo de otros carriles.

Alcance exclusivo: `tests/support/b103_clipboard.py` y este informe. Se revisaron los hallazgos C-01/C-04 de `E5-rereview-isolation.md` y D-02/D-05 de `E5-rereview-disclosure.md`, junto con los consumidores necesarios para mantener compatibilidad.

## Resultado y límites

Las cuatro correcciones asignadas quedan implementadas y comprobadas **sólo estáticamente** en el helper. No se declara GREEN, GO, WinCI, cobertura funcional ni muerte de mutantes. No se ejecutaron pytest, colección, probes, aplicación, PowerShell, clipboard, workflow, batería Linux ni mutantes; tampoco se hicieron commits ni otras mutaciones Git.

Quedan para la integración/orquestador las ejecuciones Linux y WinCI y los controles outer/known-bad de los demás carriles. C-02, C-03, D-01, D-03 y D-04 no pertenecen a este archivo y no se declaran cerrados aquí. Los helpers Win32 duplicados en otros archivos tests tampoco fueron modificados.

## Cambios

### C-01 — assembly WPF de la seed externa

- `other_program_write()` carga ahora `PresentationCore` antes de `[Windows.Clipboard]::SetText($text)` (`tests/support/b103_clipboard.py:653-666`). Se eliminó la carga incompatible de `System.Windows.Forms`.
- Se conservaron el transporte UTF-16LE como Base64 por stdin, la ausencia del payload en argv, `-NoProfile`, la comprobación de `returncode`, la lectura independiente y la comparación exacta.
- Los diagnósticos siguen limitados a códigos, tipos y longitudes; no se añadió contenido del clipboard a excepciones.

### C-04 — censo de entry points y guardas intrínsecas

Todas las rutas del helper que pueden abrir clipboard, resolver PowerShell o delegar un lanzamiento tienen una guarda intrínseca. `_require_windows()` conserva el skip fuera de Windows donde ya existía; la guarda de aislamiento se ejecuta antes del primer recurso. Las guardas repetidas entre capas son deliberadas: un llamador directo no depende de que su consumidor actual también esté guardado.

| Entry point | Recurso posterior protegido | Guarda | Cambio |
|---|---|---|---|
| `_probe_once()` | `_own_write`, `other_program_read` | `tests/support/b103_clipboard.py:218` | Ya existía; confirmada antes del nonce y de los recursos. |
| `clipboard_probe()` | `_probe_once`, incluso con caché ya poblada | `:261` | **Nueva**, antes de consultar/ejecutar el probe. |
| `os_clipboard_ready()` | `clipboard_probe` | `:273` | Ya existía; confirmada. |
| `install_process_spy()` → `_spy()` | llamada a `original(argv, **kwargs)` | `:457` | **Nueva** en el momento del lanzamiento, no al instalar el espía. |
| `_system_powershell_path()` | importación/resolución mediante `mod._system_powershell()` | `:604` | **Nueva**, antes de resolver. |
| `_run_system_powershell()` | `_system_powershell_path`, `subprocess.run` | `:620` | **Nueva**, antes de resolver o crear proceso. |
| `other_program_write()` | launcher PowerShell y lectura separada | `:656` | Ya existía; confirmada. |
| `other_program_read()` | launcher PowerShell | `:685` | Ya existía; confirmada. |
| `_own_write()` | carga de ctypes, `GlobalAlloc/Lock`, `OpenClipboard`, `EmptyClipboard`, `SetClipboardData` | `:713` | **Nueva**, antes de cualquier acceso Win32 del writer. |
| `own_read()` | carga de ctypes, `OpenClipboard`, `GetClipboardData`, `GlobalLock` | `:752` | **Nueva**, antes de cualquier acceso Win32 del reader. |
| `clipboard_sequence_number()` | `GetClipboardSequenceNumber` | `:787` | **Nueva**, antes de la llamada Win32. |

Censo: 11 entry points protegidos; siete guardas nuevas y cuatro preexistentes verificadas. La auditoría AST exigió una población de recursos no vacía para cada fila y comprobó que todas sus llamadas estén después de la guarda.

`_logged_account()` permanece como dependencia interna de la propia evaluación de aislamiento: obtiene la cuenta para decidir si se permite continuar, pero no abre clipboard ni resuelve/crea procesos. Añadirle `require_isolated_clipboard()` sería recursivo. Los callers pueden seguir pasando `account=` a `clipboard_isolated()` para mantener la evaluación pura en tests. Los helpers de eventos Textual no entran en este censo porque no acceden directamente al OS clipboard ni crean procesos; así se conservan sus usos Linux.

La posibilidad de pruebas Linux con mocks se mantiene: no se abre ningún recurso al definir/importar estos helpers, y los tests pueden sustituir la guarda, el resolver, el probe o el proceso como ya hacen los consumidores revisados. El guard nuevo de `clipboard_probe()` es compatible con el pytester Linux existente, que proporciona entorno aislado simulado y `_logged_account` sin tocar Win32.

### D-02 — superficie completa de logging

- `_LogCapture.emit()` conserva la tupla `(logger, level, message)` pero guarda ahora `self.format(record)` como tercer elemento (`tests/support/b103_clipboard.py:486-494`).
- El formatter predeterminado de `logging.Handler` empieza con `record.getMessage()` y añade el texto completo de `exc_info` y `stack_info`; no hay truncado ni sustitución por `repr` parcial. Por tanto, los consumidores que examinan `row[2]` reciben también excepciones y stacks sin cambiar aridad ni claves.
- Para records sin `exc_info`/`stack_info`, la forma sigue siendo el mensaje normal. No se añadieron payloads a ninguna excepción nueva.

### D-05 — clasificación del probe y metadata estructurada

- Se añadió `_ProbeDetail(str)` (`tests/support/b103_clipboard.py:186-212`), por lo que `(usable, result)` sigue siendo desempaquetable y `result` conserva el comportamiento textual de los consumidores.
- `result.stage` y `result.metadata` ofrecen `stage`, `expected_chars`, `actual_chars`, `error_type` y `result_chars`. Los valores son etiquetas, enteros o tipo de excepción; nunca nonce ni contenido leído.
- Los estados escritos son `win32-write`, `powershell-read-exception`, `round-trip-ok` y `round-trip-mismatch`.
- El mismatch usa el prefijo legacy `win32 write ok, PowerShell read ` (`:246-253`), que el clasificador actual de `tests/test_b103_clipboard_windows.py:149-159` reconoce como `round-trip-mismatch`. La metadata estructurada evita acoplar futuros consumidores al resto del texto, pero no exige cambiar ahora ese consumidor.

## Verificación estática realizada

1. `py_compile` sobre `tests/support/b103_clipboard.py`: **OK**. El `.pyc` temporal se escribió fuera del caché normal y se eliminó en el mismo comando.
2. Auditoría AST del archivo resultante: **OK** para los 11 entry points del censo; 26 llamadas de recurso censadas después de sus guardas, con listas de recursos no vacías. El wrapper `_spy` se resolvió por su función padre para no confundirlo con los espías OSC 52/notice homónimos.
3. Comprobación estática C-01: `PresentationCore` y `Windows.Clipboard` presentes juntos; `System.Windows.Forms` ausente: **OK**.
4. Comprobación estática D-02: `_LogCapture.emit` usa `self.format(record)` y ya no reduce el record a `record.getMessage()`: **OK**.
5. Comprobación estática D-05: subclase de `str`, cinco claves de metadata y prefijo legacy de mismatch presentes: **OK**.
6. `git diff --check -- tests/support/b103_clipboard.py`: **OK**, sin errores de whitespace.
7. No se añadieron, renombraron ni eliminaron funciones `test_*`; este carril no editó los seis archivos WinCI ni cambió sus nodeids. No se eliminaron tests ni oráculos.

Estas comprobaciones no ejecutan el comportamiento Windows ni sustituyen los brazos negativos dinámicos de cero llamadas OS/proceso, los records known-bad con `exc_info`/`stack_info`, la batería Linux posterior a integración, WinCI o los mutantes.

## Nota posterior al outer Linux — causas de excepciones

El outer known-bad demostró que los tracebacks de `test_read_exception_chaining` y `test_write_exception_chaining` exponían el valor de la excepción original aunque el nuevo `AssertionError` ya estuviera sanitizado. El censo completo de `from exc` del helper encontró exactamente dos vías:

- `_run_system_powershell()` al convertir `OSError`, `UnicodeError` o `subprocess.TimeoutExpired` (`tests/support/b103_clipboard.py:647-650`).
- `other_program_read()` al convertir `ValueError` o `UnicodeError` de Base64/UTF-8 (`:703-706`).

Ambas usan ahora `raise AssertionError(...) from None`, que suprime tanto la causa como el contexto del traceback. Se conservan exactamente los tipos capturados, el tipo de excepción de proceso como diagnóstico y el texto genérico de salida Base64 inválida; no se captura ninguna excepción adicional. La auditoría AST de todos los handlers confirmó que éstos eran los únicos dos `raise` dentro de `except` y que no queda otro relanzamiento con causa o contexto visible.

Verificación de esta continuación: censo AST **2/2** con `from None`, cero `from exc` y cero relanzamientos implícitos dentro de `except`; `py_compile` **OK** con salida temporal eliminada; `git diff --check` **OK**. No repetí tests ni outer en Windows. La repetición Linux del outer known-bad queda pendiente del orquestador, por lo que esta nota no declara su resultado dinámico.

## Nota de transporte binario PowerShell

Para satisfacer los mocks disclosure de transporte binario, `_run_system_powershell()` ya no pasa `text`, `encoding`, `errors` ni `newline` a `subprocess.run`. `input_text` conserva su firma `str`, pero se codifica explícitamente con `input_text.encode("utf-8")` antes de asignarlo a `kwargs["input"]`; con entrada ausente se mantiene `stdin=DEVNULL`. Al no activarse modo texto, `stdout` y `stderr` permanecen como bytes y no hay conversión universal de newlines (`tests/support/b103_clipboard.py:615-647`).

`other_program_read()` reúne ahora la salida con `b"".join(result.stdout.split())`, aplica `base64.b64decode(..., validate=True)` directamente sobre bytes y decodifica el resultado con UTF-8 cuyo modo predeterminado es estricto. El `from None` del fallo Base64/UTF-8 se conserva (`:679-703`). Los dos diagnósticos de `stderr` usan fallback `b''` y mantienen sus claves y longitudes.

No cambiaron guards, argv estático, comandos PowerShell ni transporte del contenido: el payload sigue fuera de argv y su representación Base64 ASCII produce los mismos bytes al codificarla como UTF-8. La auditoría AST comprobó estructuralmente estas propiedades, incluidos el nodo `bytes` del join, `validate=True`, UTF-8 sin relajación y la lista exacta de kwargs; `py_compile` y `git diff --check` terminaron **OK**, con el `.pyc` temporal eliminado. No ejecuté tests; la validación dinámica queda para el orquestador en el clon exacto.
