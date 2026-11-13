# E5 LEGACY WINDOWS — corrección y validación

## Alcance

- Base: HEAD `0d4d4e7c` con los cambios E5 sin commit ya presentes.
- Fuente editada únicamente: `tests/test_b103_clipboard_windows.py`.
- Evidencia añadida únicamente en esta carpeta `legacy/`.
- No se editó soporte compartido, producto, workflow, requisitos ni otras familias. No hubo commit ni push.
- No se ejecutó clipboard, PowerShell, Python Windows, tests Windows ni WinCI en el PC del operador.

## Correcciones

### SEC-01 — holder heredado acotado

- `kernel32.Sleep(20)` con prototipo Win32; se eliminó `user32.Sleep`.
- Prototipos de ventana/clipboard y `finally` con `CloseClipboard` + `DestroyWindow`.
- Readiness mediante hilo/cola con `get(timeout=5.0)`, comprobación de lectura y de vida después de `HOLDING`.
- Verificación conservada de hold cruzado y segunda comprobación de vida.
- `_reap_holder`: kill cuando sigue vivo, `wait(timeout=3.0)` y cierre de stdout.
- `_release_clipboard`: evento, `join(timeout=5.0)`, supervisor terminado y proceso reapsado obligatorios.
- Los 13 `finally` de nodos held llaman ahora a `_release_clipboard`; no queda `_held["release"].set()` directo.

### SEC-03 local — fallos sin contenido del clipboard

- El fallo del probe conserva el prefijo `runner clipboard unusable`, pero sustituye el resultado crudo por etapa clasificada y longitud.
- Las comparaciones exactas de contenido usan `_assert_content_equal`; el oráculo no cambia, pero sus fallos informan sólo etiqueta, caracteres, saltos y cardinalidades.
- `_wait_for_box`, lecturas copy/cut/paste, listas de cinco copias, Unicode, warning y fallback ya no incluyen el valor observado en sus mensajes.
- `_assert_log_excludes` informa cantidad e índices de registros coincidentes, nunca los mensajes capturados ni el canario.
- La salida inesperada del holder se informa por longitud/estado, no por su contenido.

Esto cierra los canales dentro de esta familia; no se reclama la corrección de helpers compartidos ni de otras familias.

### SEC-04 local — anti-PATH-hijack efectivo

- El único nodo R-PASTE.16/3 existente sigue siendo un único nodo; no se parametrizó ni se añadió otro test.
- Compila un decoy `.exe` real con `csc.exe` absoluto de .NET Framework. El decoy crea un marcador si se ejecuta.
- Copia ese ejecutable como `powershell.exe` tanto en el cwd alterado como en la carpeta prependida a `PATH`.
- Fuerza por separado, dentro del mismo nodo, las cascadas reales de lectura y escritura PowerShell; ctypes queda como fallo controlado y el proceso permanece real/pass-through.
- Exige lectura y escritura exactas, `started` no vacío, todos los `argv[0]` iguales al PowerShell absoluto del sistema y ausencia del marcador.
- La lectura separada posterior también ocurre con cwd/PATH hostiles y con el marcador armado.

## Censo

- Contrato previo y posterior: 51 funciones `test_*`; no se añadieron funciones ni parámetros.
- Colección Linux posterior: **77 tests collected**. El caso decoy conserva su nodeid sin sufijo.
- No se cambiaron requisitos, umbrales ni nombres de nodos. No se declara cobertura nueva ni WinCI GREEN.

## Validación ejecutada

Entorno: WSL Ubuntu, Linux `<KERNEL_VERSION>-microsoft-standard-WSL2`, Python `3.12.7`, pytest `9.2.0`, Textual `8.2.8`. Se reutilizó `$HOME/s19venv`; no se instalaron dependencias.

1. `contract_probe.py` sobre el archivo previo: **RED esperado, 0/15**, exit 1; salida en `pre-fix-contract.txt`.
2. El mismo contrato sobre el entregable: **15/15 PASS**, exit 0; salida en `post-fix-contract.txt`. El contrato parsea AST/texto y no importa el módulo ni ejecuta clipboard.
3. `compile(...)` del archivo completo en WSL: `compile_ok`, exit 0, sin bytecode ni llamadas OS.
4. `python -B -m pytest --collect-only -q -p no:cacheprovider tests/test_b103_clipboard_windows.py`: **77 collected**, exit 0; `linux-collect.txt`.
5. `python -B -m pytest -q -rs -p no:cacheprovider tests/test_b103_clipboard_windows.py`: **77 skipped**, exit 0; `linux-pytest.txt`. Todos son skips `Windows only` de la fixture autouse, no pasadas funcionales ni cobertura WinCI.
6. `redaction_runtime_probe.py`: **4/4 PASS**, exit 0; `linux-redaction.txt`. Fuerza mismatch de contenido, canario en log, mismatch del probe y controles de éxito usando sólo datos sintéticos. El transcript contiene únicamente metadatos; `clipboard_calls=0`, `powershell_calls=0`.
7. `git diff --check -- tests/test_b103_clipboard_windows.py`: exit 0.

`PYTHONDONTWRITEBYTECODE=1`, `python -B` y `no:cacheprovider` evitaron artefactos de bytecode/pytest cache en estas ejecuciones.

## Bloqueos y validación pendiente

- **WinCI `not_run`**: el holder Win32, sus 13 caminos de liberación, la compilación/ejecución del decoy, los rescates PowerShell reales y los transcripts/JUnit WinCI deben validarse en el runner Windows aislado. Nada de ello se afirma ejecutado aquí.
- El control decoy falla cerrado con metadatos si el runner no tiene el `csc.exe` absoluto de .NET Framework; esa disponibilidad sólo puede confirmarse en WinCI.
- Los hallazgos de producto, soporte compartido, workflow y otras familias permanecen bajo sus respectivas propiedades. Esta entrega no cambia el veredicto global NO-GO por sí sola.
- Un `git diff --check` global mostró trailing whitespace preexistente en dos `evidence-e4/*/SHA256SUMS` fuera de esta propiedad; no se editaron. El chequeo acotado al archivo LEGACY sí pasa.
