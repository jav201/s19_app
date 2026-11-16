# E5-fix2 — Carril A: transporte PowerShell y tail

Base: HEAD `305e5892` más el working tree recibido. Alcance limitado a `s19_app/tui/os_clipboard_input.py`, `tests/test_b103_clipboard_tail.py` y este informe. Se conservaron los cambios previos y los nodeids existentes; no se añadieron parametrizaciones ni se renombraron tests.

## Cierres de implementación

### TR-02 / B2 — transporte binario y UTF-8 explícito

- `_read_via_powershell()` ya no pasa `text`, `encoding`, `errors` ni `newline` a `subprocess.run`. Captura stdout/stderr como bytes y decodifica stdout con UTF-8 y `errors="replace"`, fuera de newline universal (`s19_app/tui/os_clipboard_input.py:280-340`). Se conserva `b"" → "" → None` y el tratamiento previo de timeout, `OSError` y salida no cero.
- `_write_via_powershell()` envía `text.encode("utf-8", errors="replace")` por stdin binario y tampoco activa modo texto (`s19_app/tui/os_clipboard_input.py:423-455`). Se mantiene el comando estático, `PresentationCore`, `[Console]::In.ReadToEnd()` y `SetText($text)`.
- Docstrings y comentarios afectados describen ahora bytes, UTF-8 explícito y conservación exacta de CR, CRLF y LF.
- Los dobles de tail devuelven bytes y los oráculos exigen stdin binario y ausencia de claves de modo texto. El oráculo AST existente, sin cambiar su nodeid, también rechaza esas claves y exige `encode`/`decode` (`tests/test_b103_clipboard_tail.py:1172-1242`).

### TR-01 / TR-03 / C-04 — adquisición, reap y release acotados

- `_hold_clipboard()` llama a `require_isolated_clipboard("windows")` antes de cualquier preparación, `Popen` o Win32. El `try` empieza inmediatamente después de `Popen` y cubre cola, creación e inicio del reader, readiness, Win32 y supervisor (`tests/test_b103_clipboard_tail.py:1559-1719`).
- `_reap_holder()` intenta siempre kill/wait inicial, kill/wait final acotados (3 s/1 s), cierre y `poll()` final. Los fallos posteriores se añaden como notas sin sustituir el primario; un proceso vivo produce fallo explícito (`tests/test_b103_clipboard_tail.py:1459-1504`).
- `_release_clipboard()` ejecuta de forma independiente `set`, ambos joins, reap, comprobación del supervisor y `poll()` final del holder. Un holder o supervisor vivo nunca se acepta como PASS (`tests/test_b103_clipboard_tail.py:1507-1556`).
- Los controles inertes incluyen rechazo de guarda con cero `Popen`/Win32, fallo de `reader.start()`, timeout con proceso vivo hasta el kill final, reintento de kill, holder imposible de matar, supervisor colgado y holder vivo durante release. El doble de timeout registra estados vivo→muerto y exige dos kills, ambos waits, cierre, muerte real y poll posterior al cierre (`tests/test_b103_clipboard_tail.py:1748-2150`).

### C-02 y brazos WinCI de reader/writer

El nodeid existente `tests/test_b103_clipboard_tail.py::test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs` conserva sus brazos hostiles LF/LF final y añade Unicode, CR y CRLF (`tests/test_b103_clipboard_tail.py:1245-1446`):

- writer: cinco recorridos forzados por `_write_via_powershell`, con igualdad exacta de app/OS/OSC y lectura OS separada;
- reader: cinco recorridos forzados por `_read_via_powershell`, comparados directamente con el payload y con `other_program_read()` Base64, sin usar el `Input` de una línea como oráculo;
- WinCI: siembra real mediante `other_program_write()` para cada valor y conserva cwd/PATH hostiles, PowerShell absoluto del sistema y marcador decoy ausente;
- Linux: mocks binarios para los mismos valores y `empty → None`, sin suplantar la ejecución WinCI.

### D-02 tail y marca de timing

- `_no_secret()` usa las mismas formas directas, `repr`, escape y XML (texto, prefijos, CR numérico y atributo) que el detector Windows, manteniendo un mensaje de fallo sin payload (`tests/test_b103_clipboard_tail.py:368-398`).
- Un known-bad dentro del nodeid `test_r_tui_043_13_101_no_copied_text_or_prefix_in_logs` exige rechazo de cada forma XML y comprueba que ninguna coincida accidentalmente con una forma plana (`tests/test_b103_clipboard_tail.py:1066-1100`).
- `test_r_paste_13_101_held_row_copy_warns_within_bound` lleva ahora `@pytest.mark.serial_timing` directamente, sin `pytestmark` de módulo ni cambio de nodeid (`tests/test_b103_clipboard_tail.py:2156-2157`).

## Verificación realizada

Sólo comprobaciones estáticas en Windows:

- `python -B -c` con `ast.parse` de los dos archivos Python: **AST OK** para ambos; no importó módulos del proyecto ni creó bytecode.
- `git diff --check -- s19_app/tui/os_clipboard_input.py tests/test_b103_clipboard_tail.py`: **exit 0**, sin errores.
- `git status --short`: confirmó el working tree compartido con numerosos cambios ajenos; no se modificaron ni limpiaron esos archivos.

No ejecuté pytest, colección, probes, baterías, aplicación, PowerShell, clipboard, WinCI, workflow ni mutantes. No hice mutaciones Git.

## Puertas que permanecen abiertas

Estas son correcciones de implementación y rutas de prueba escritas, **no resultados ejecutados**. El orquestador debe ejecutar el árbol exacto en el clon Linux y después las rutas WinCI reales para cambiar los veredictos de ejecución. No se declara WinCI GREEN, cleanup real de holders verificado, mutantes ejecutados ni cobertura final de las seis familias. **AT-I1b-8 sigue manual y no queda cerrada por este carril.**
