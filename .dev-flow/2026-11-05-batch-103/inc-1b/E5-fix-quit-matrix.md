# E5 fix — Carril E: quit y matrix

Base: `305e5892` más los cambios no commitidos ya presentes. Se conservó todo el trabajo preexistente. Este carril sólo editó `tests/test_b103_copy_quit_dialog.py` y añadió este informe; no modificó el helper compartido, ledger, canon, evidencia anterior ni archivos de otros carriles.

## Resultado y alcance

Cierre **estático** de C-02/C-03 en quit. Queda pendiente la ejecución posterior que hará el orquestador sobre el árbol integrado. No se declara GREEN, veredicto WinCI ni ejecución de mutantes.

Archivos del carril:

- `tests/test_b103_copy_quit_dialog.py`: modificado de forma acotada.
- `tests/test_b103_copy_paste_matrix.py`: dejado intacto **en este carril**; sus cambios preexistentes se conservaron.
- `.dev-flow/2026-11-05-batch-103/inc-1b/E5-fix-quit-matrix.md`: este informe nuevo.

## C-03 — launchers duplicados eliminados en quit

En `tests/test_b103_copy_quit_dialog.py:122-129`:

- `_read_os_clipboard_exact()` delega ahora en `tests.support.b103_clipboard.other_program_read()`.
- `_seed_os_clipboard()` delega en `other_program_write(SEED)` y conserva su read-back exacto con fallo explícito antes del escenario.
- Se eliminaron `_winci_powershell_path()` y `_separate_powershell()`, junto con los imports locales `base64` y `subprocess` que sólo servían a esos launchers.

Con ello, seed/read de quit y matrix comparten el único launcher conservado. En el helper ya existente, cada escritura y lectura usa un proceso PowerShell separado, la guarda `require_isolated_clipboard("windows")`, PowerShell absoluto del sistema y fallos por invocación/exit/Base64; no hay conversión a skip en las rutas WinCI obligatorias. El writer transporta UTF-16LE en Base64 por stdin y el reader devuelve Base64 UTF-8 sin BOM, decodificado con `validate=True` y sin `rstrip` (`tests/support/b103_clipboard.py:600-653`). El helper no fue editado aquí.

Las lecturas de no-copia de las nueve rutas quit siguen pasando por `_read_os_clipboard_exact()`, por lo que conservan el oráculo OS exacto y fallan si cambia `SEED-1b`.

## C-02 — round-trips exactos añadidos sin nuevos nodeids

Se añadió `_check_winci_external_round_trips()` en `tests/test_b103_copy_quit_dialog.py:132-146`, con cuatro brazos conocidos:

- Unicode: `SEED-Ω-漢字-🙂`;
- CR interno: `L1\rL2`;
- LF interno: `L1\nL2`;
- LF final: `L1\nL2\n`.

Cada brazo ejecuta el writer externo conservado y después una lectura externa adicional con `other_program_read()`, exigiendo igualdad exacta. Un mismatch falla con etiqueta y longitudes, sin volcar el contenido. No hay `skip` en el brazo WinCI.

El brazo se invoca bajo `sys.platform == "win32"` dentro del nodo ya existente `test_r_dlg_14_101_copy_quit_has_reachable_shared_opener` (`tests/test_b103_copy_quit_dialog.py:996-1034`). Sus aserciones R-DLG.14/101 originales permanecen; su docstring también registra el nuevo brazo. No se añadió ninguna función de test, decorador de parametrización ni ID AT.

## Preservación de quit y matrix

- No edité los cuerpos de los nueve tests R-COPY.16/1…6 y R-COPY.20/1…3. La comprobación AST confirmó que los nueve conservan `winci_seed=True`.
- No cambié la ubicación de las esperas, observaciones con diálogo abierto, Stay/cierre modal ni lecturas OS; en éstas últimas sólo se sustituyó el launcher duplicado por el helper común.
- `tests/test_b103_copy_paste_matrix.py` no necesitó diff de este carril: ya delegaba seed/read en `other_program_write/read`, conservaba `await wait_for_copy_tail(pilot, tail_marker)` y publicaba P2 mediante `app.post_message(events.Paste(os_artifact))`.
- Se conservaron los 28 IDs AT y su orden: 14 P1 + 14 P2. AT-I1b-8 sigue manual y sin cambios.
- No se eliminaron tests ni oráculos y no se añadieron parametrizaciones en las seis familias WinCI. Los otros cuatro archivos WinCI no fueron editados.

## Verificación estática realizada

No se ejecutó pytest ni colección pytest. Las comprobaciones fueron:

1. `python -m py_compile tests/test_b103_copy_quit_dialog.py tests/test_b103_copy_paste_matrix.py` — exit 0.
2. `git diff --check -- tests/test_b103_copy_quit_dialog.py tests/test_b103_copy_paste_matrix.py` — exit 0.
3. Script Python AST de sólo lectura, sin importar la aplicación ni los tests, comparando working tree con `git show HEAD:<path>`:
   - quit: 28 definiciones `test_*`, mismos nombres que HEAD;
   - matrix: 2 definiciones `test_*`, mismos nombres que HEAD, y los mismos 28 `pytest.param(id=...)` en el mismo orden;
   - nueve rutas R-COPY.16/.20 con `winci_seed=True`;
   - delegación seed/read en helpers compartidos y ausencia de los dos launchers locales;
   - presencia literal de los cuatro casos Unicode/CR/LF/LF final dentro del nodo R-DLG.14/101 existente;
   - 28 AT únicos, 14 P1 + 14 P2, espera tail y `events.Paste(os_artifact)` presentes.
4. Búsqueda estática en quit: ya no quedan referencias a PowerShell, Base64 o `subprocess`; sí aparecen las delegaciones `other_program_read/write` y las nueve activaciones `winci_seed=True`.

`git status --short` se usó sólo para inspeccionar el árbol. Mostró el trabajo preexistente de otros carriles y no se usó para revertir, limpiar ni alterar ningún archivo.

## No ejecutado / integración pendiente

Por instrucción expresa no ejecuté pytest, probes, aplicación, PowerShell, clipboard, workflow, batería Linux ni mutantes; tampoco hice commits ni otras mutaciones Git. Las comprobaciones anteriores demuestran estructura, sintaxis y preservación estática, no comportamiento Windows observado.

C-01 del helper compartido y los hallazgos de otros alcances pertenecen a sus respectivos carriles. La validación dinámica de C-02/C-03 debe hacerse después de integrar esas correcciones, con la selección WinCI serial y los controles previstos por el orquestador.
