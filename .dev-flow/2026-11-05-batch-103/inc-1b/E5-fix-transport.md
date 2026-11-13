# E5 — Corrección carril A: transporte y sincronización tail

Base de trabajo: `305e5892` más los cambios no commitidos ya presentes. Se conservaron esos cambios y los demás carriles. Esta intervención escribió únicamente:

- `s19_app/tui/os_clipboard_input.py`;
- `tests/test_b103_clipboard_tail.py`;
- este informe, `.dev-flow/2026-11-05-batch-103/inc-1b/E5-fix-transport.md`.

No se editaron `tests/support/b103_clipboard.py`, los otros cinco archivos WinCI, ledger, canon ni evidencia previa. No hubo commits ni otras mutaciones Git.

## Cambios por hallazgo

### TR-02 — reader PowerShell de producto

- `s19_app/tui/os_clipboard_input.py:341-342` elimina `rstrip("\r\n")` y devuelve `result.stdout` íntegro.
- Se conserva la conversión de cadena vacía a `None`; no se altera el resto de la cascada ni el encoding.
- El brazo `forced-reader-final-lf-and-tail-decoy` dentro de `test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs` fuerza ctypes→`None` y PowerShell como rescate. Compara exactamente un payload con LF interno y LF final y, en el brazo simulado, comprueba también `""`→`None` (`tests/test_b103_clipboard_tail.py:1219-1252`).

### TR-04 — writer PowerShell forzado con LF final

- `_hostile_powershell_observation()` conserva su nombre y firma; delega en un helper nuevo parametrizado por payload sin cambiar el comportamiento del brazo original (`tests/test_b103_clipboard_tail.py:1060-1114`).
- El mismo nodeid hostile contiene ahora `hostile-no-final-lf` y `hostile-final-lf` (`tests/test_b103_clipboard_tail.py:1179-1217`, `:1325-1329`). Ambos fuerzan exclusivamente la estrategia PowerShell y exigen:
  - app, OS/separate read, OSC y payloads de cada sink exactos mediante `_success`;
  - `kwargs["input"]` exacto;
  - argv estático del sistema, `shell=False` y cwd del sistema;
  - ausencia del payload y de su prefijo en argv y en logs.
- El payload final conserva el LF interno original y añade LF final. No se añadieron parametrizaciones pytest ni nodeids.

### TR-01 — cleanup de holders

- `_reap_holder()` mantiene su firma y ahora intenta kill cuando sigue vivo, wait inicial acotado, kill/wait finales y cierre de stdout incluso cuando una fase anterior falla. Conserva y relanza el primer fallo (`tests/test_b103_clipboard_tail.py:1343-1372`).
- `_release_clipboard()` mantiene su firma e intenta siempre `release.set()`, ambos joins acotados y reap/cierre. Relee `supervisor_failure` después de los joins para no perder un fallo publicado durante el primero, comprueba supervisor/proceso y preserva el fallo primario (`tests/test_b103_clipboard_tail.py:1375-1396`).
- El supervisor publica errores de `release.wait()` y de reap en el estado. La salida por error de `_hold_clipboard()` intenta reap/cierre y `reader.join()` sin reemplazar la excepción que motivó la salida (`tests/test_b103_clipboard_tail.py:1492-1520`).
- El diagnóstico de readiness ya no incluye `repr` de la salida del hijo.

### TR-03 — controles negativos tail

Se añadieron brazos con dobles dentro del nodeid hostile existente, no tests nuevos. `_run_holder_control()` proporciona un deadline externo de 2 s por control (`tests/test_b103_clipboard_tail.py:1523-1543`). Los controles de `tests/test_b103_clipboard_tail.py:1546-1795` cubren:

1. ausencia de readiness mediante `queue.Empty`, con fallo de join del reader durante cleanup;
2. muerte del proceso después de anunciar `HOLDING`;
3. `wait()` inicial y final con `TimeoutExpired`, conservando la primera instancia de error;
4. fallo de `kill()` y reintento, seguido de wait/cierre;
5. supervisor que permanece vivo tras los joins, comprobando kill/reap/cierre posteriores;
6. fallo de `release.set()` sin omitir joins ni reap;
7. fallo de `join()` sin enmascararlo con el join final;
8. fallo de `release.wait()` publicado por el supervisor durante el primer join.

Los oráculos exigen procesos dobles muertos, waits acotados ejecutados, stdout cerrado, joins intentados y conservación por identidad del fallo primario cuando corresponde. Son controles escritos, no resultados ejecutados en esta intervención.

### D-01 — agregación y observation ledgers

- Se añadió `_require()` para que las comparaciones exactas produzcan sólo mensajes fijos y no introspection de valores sensibles (`tests/test_b103_clipboard_tail.py:278-280`).
- `_counts`, `_success`, `_failure`, `_refusal` y las aserciones directas sobre `obs`, payloads, notices, OSC, procesos y logs conservan sus oráculos exactos pero ya no usan `obs`, `kwargs`, payloads, prefijos ni `repr` como diagnóstico (`tests/test_b103_clipboard_tail.py:283-374` y censo de llamadas posterior).
- `_run_arms()` ya no serializa `str(exc)`: agrega únicamente etiquetas estáticas de brazo y emite un mensaje final genérico (`tests/test_b103_clipboard_tail.py:377-386`).
- También se retiraron `repr(selected)`, `repr(unrelated)` y `repr(widget)` de diagnósticos de selección/click. `_no_secret()` mantiene `repr(secret)` sólo como aguja de búsqueda, nunca como mensaje.

### C-03 — decoy del separate reader tail

No se consolidó sobre `tests/support/b103_clipboard.py::other_program_read`: en el árbol asignado ese helper sólo rechaza `returncode` no cero, mientras el reader local de tail exige también `stderr` vacío. Consolidar directamente habría perdido ese oráculo y editar `support` estaba fuera de este carril.

En su lugar, el brazo WinCI `forced-reader-final-lf-and-tail-decoy` ejercita el reader local bajo un `powershell.exe` señuelo real tanto en cwd como al frente de PATH (`tests/test_b103_clipboard_tail.py:1254-1323`). El brazo:

- siembra el payload LF antes de instalar el ataque;
- fuerza la lectura de producto por PowerShell y llama al separate reader local bajo el mismo ataque;
- exige igualdad exacta en ambas lecturas;
- exige exactamente dos arranques, ambos con el `argv[0]` absoluto del PowerShell del sistema;
- exige que el marcador del decoy no exista;
- conserva la validación estricta local de exit y `stderr`.

Esto cubre tail mediante el ataque directo permitido por el desbloqueo C-03, sin tocar el launcher compartido.

## Estabilidad de la superficie pytest

- Los 31 nombres `test_*` y su orden son exactamente los presentes antes de esta corrección.
- No se añadieron decoradores ni parametrizaciones; todos los brazos nuevos están dentro de `test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs`.
- No se eliminaron tests ni oráculos.
- Una comprobación AST confirmó además las firmas de `other_program_read`, `_hostile_powershell_observation`, `_reap_holder`, `_release_clipboard`, `_hold_clipboard` y `_run_arms`.
- Los otros cinco archivos WinCI no fueron editados por este carril.

## Verificación estática realizada

1. `git diff --check -- s19_app/tui/os_clipboard_input.py tests/test_b103_clipboard_tail.py`
   - Resultado: exit 0, sin errores de whitespace.
2. `compile()` incorporado de Python sobre los dos archivos, leyendo texto UTF-8 sin importar ni ejecutar los módulos:
   - Resultado: `static compile: 2 files OK`.
3. Análisis AST del archivo tail:
   - Resultado: `31 nodeids unchanged; no test decorators; 6 helper signatures unchanged; no obs/kwargs asserts`.
   - La primera invocación del comprobador tuvo que ajustar únicamente el espacio esperado por `ast.unparse()` alrededor de `=` en un default; la comparación final usa la forma canonizada por AST y terminó en exit 0.
4. Búsqueda estática final:
   - No queda `rstrip("\r\n")` en el reader de producto ni agregación `str(exc)` en `_run_arms`.
   - No quedan `assert` con `obs[...]`, `kwargs` o `processes` cuya introspección pueda republicar el ledger.

## No ejecutado / pendiente de integración

No se ejecutaron pytest, colección pytest, probes, aplicación, PowerShell, clipboard, batería Linux, workflow ni mutantes. Tampoco se ejecutaron los nuevos brazos WinCI ni los controles con dobles. El orquestador deberá ejecutar la selección correspondiente después de integrar todos los carriles; este informe sólo documenta cambios y verificación estática.
