# E5 TAIL — correcciones pre-CI y RED pendiente

## Alcance

- Base: HEAD `0d4d4e7c` con los cambios E5 sin commit ya presentes.
- Propiedad editada: `tests/test_b103_clipboard_tail.py` y esta carpeta de evidencia.
- No se editó producto, helpers compartidos, workflow ni otras familias; no se hizo commit ni push.
- No se ejecutó clipboard, PowerShell ni WinCI en el PC del operador. Las dos ejecuciones del nuevo oráculo en Windows fueron únicamente estáticas (AST y constantes); la batería comportamental se ejecutó en Linux/WSL.
- El archivo TAIL validado tiene SHA-256 `cf597223d2c119cdbfe43d3a8bd8276e7375a324d96ffaee5cc678994ec2b5d9`, idéntico al registrado por el runner Linux.

## Cambios

1. `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` (`tests/test_b103_clipboard_tail.py:1112`) exige estáticamente:
   - `[Console]::In.ReadToEnd()` y `.NET [Windows.Clipboard]::SetText($text)` en `_POWERSHELL_WRITE_COMMAND`;
   - ausencia de `Set-Clipboard` en ese writer, para no recomponer líneas ni convertir LF a CRLF;
   - `[Console]::OutputEncoding` con `UTF8Encoding($false)` en `_read_via_powershell` de producto y en `other_program_read` local de TAIL.
2. El reader Base64 local usa `[System.Text.UTF8Encoding]::new($false)` para stdout (`tests/test_b103_clipboard_tail.py:241`). La conversión a bytes Base64 se mantiene estricta; no se añadió `rstrip` ni se relajó LF.
3. `_injected_hex_key_observation`, `_line_cut_observation` y `_unrelated_view_box_observation` esperan `_wait_copy_tail(...)`/`tail_done` antes de `_observe()` (`tests/test_b103_clipboard_tail.py:592`, `:1466`, `:1499`).
4. `_no_secret` ya no usa los mensajes capturados como diagnóstico de aserción (`tests/test_b103_clipboard_tail.py:355`). Las comprobaciones hostile conservan sus oráculos exactos, pero los fallos de payload, argv, stdin, cwd, cardinalidad y `_success` emiten diagnósticos genéricos o sólo numéricos, no `HOSTILE_NAME`, `obs["processes"]` ni `kwargs` con `input` (`tests/test_b103_clipboard_tail.py:1153`).

## RED estático archivado

Comando:

```text
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider tests/test_b103_clipboard_tail.py::test_e5_powershell_preserves_lf_and_emits_bom_free_readers
```

- `red-powershell-exact-transport.txt`: primer RED, ejecutado antes de las demás correcciones. Exit 1 esperado; mostró las tres carencias del writer y BOM en los dos readers.
- `red-powershell-exact-transport-final.txt`: estado final de esta propiedad. Exit 1 esperado; el reader TAIL ya no falla y quedan únicamente cuatro carencias de producto: `ReadToEnd`, `SetText`, eliminación de `Set-Clipboard` y BOM en `_read_via_powershell`.

Estos RED son el handoff deliberado al implementador de producto, no regresiones introducidas por los waits ni evidencia de un fallo Linux comportamental.

## Validación

### Regresión Linux TAIL

Runner: `run_linux_tail_e5_fixes.sh` / `run_linux_tail_e5_fixes.py`.

```text
MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash <HOME>/Github/s19_app-b103-inc1b-integration/.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/tail/run_linux_tail_e5_fixes.sh
```

Entorno: Ubuntu/WSL, Python 3.12.7, pytest 9.2.0, Textual 8.2.8, HOME/TMP/XDG/LOCALAPPDATA neutros, DISPLAY/WAYLAND_DISPLAY eliminados, stdin cerrado, `-I -B`, pytest cache desactivado y timeout externo de 900 s.

Resultado en `linux-tail-e5-fixes.txt`:

```text
26 passed, 4 skipped, 1 deselected in 269.46s (0:04:29)
```

Exit 0. Se deseleccionó únicamente el nuevo RED estático; los otros 30 nodos TAIL conservan el resultado previo de 26 pass + 4 skips WinCI-only. Los cuatro skips son R-PASTE.13/101 y R-PASTE.14/101–103. No hay skips nuevos. Esta ejecución no repite ni reemplaza la batería integrada 122/19 y no promueve cobertura.

### Estático y redacción

- `static-e5-fixes.txt`: AST parse OK; tres barreras presentes antes de `_observe()`; `git diff --check` OK; hash TAIL coincidente con Linux.
- `redaction-e5-fixes.txt`: un canario detectado por `_no_secret` no aparece en `str(AssertionError)` en ninguna de sus formas comprobadas; no quedan `assert` hostile sobre `argv`/`kwargs`.

## Intentos de transporte sin resultado pytest

`linux-tail-e5-fixes-transport1.txt` a `transport4.txt` documentan fallos anteriores a colección: ruta de worktree Git Windows dentro de WSL, archive/stdin de tar, quoting anidado de variables y conversión MSYS de `/mnt/c`. Ninguno produjo RED, GREEN, skips ni cobertura. El runner script y `MSYS_NO_PATHCONV=1` resolvieron el transporte; el transcript válido es `linux-tail-e5-fixes.txt`.

## Bloqueos y trabajo pendiente

1. **Producto, fuera de esta edición:** `s19_app/tui/os_clipboard_input.py:125-130` todavía usa `$input | Set-Clipboard`. El implementador debe leer stdin como una sola cadena con `[Console]::In.ReadToEnd()` y escribir `$text` mediante .NET `[Windows.Clipboard]::SetText($text)`, manteniendo payload fuera de argv.
2. **Producto, fuera de esta edición:** `_read_via_powershell` todavía usa `[System.Text.Encoding]::UTF8` para stdout (`s19_app/tui/os_clipboard_input.py:312`). Debe usar UTF-8 sin BOM mediante `UTF8Encoding($false)`.
3. El nuevo nodo permanece **RED intencionalmente** hasta cerrar los dos puntos anteriores. No se relajó su oráculo ni se editó producto para hacerlo verde.
4. No se ejecutó WinCI ni clipboard real: el reader TAIL sin BOM, la ruta hostile PowerShell real y los cuatro nodos WinCI siguen sin evidencia de ejecución Windows. Los NO-GO globales de otras familias también permanecen fuera de esta propiedad.
