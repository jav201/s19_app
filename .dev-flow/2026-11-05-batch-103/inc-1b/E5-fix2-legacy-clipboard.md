# E5 fix2 — carril F: contratos legacy de clipboard PowerShell

Base: HEAD `305e5892` más el working tree existente. Se conservaron el trabajo previo y los demás carriles. Esta intervención escribió únicamente:

- `tests/test_b102_clipboard.py`;
- `tests/test_loadfilescreen_input.py`;
- este informe.

No se editó producto, helpers, workflow, evidencia previa ni ninguno de los seis archivos de familias WinCI. No hubo commits ni otras mutaciones Git.

## Hallazgo y norma aplicada

Los contratos legacy todavía modelaban `subprocess.run` en modo texto: los dobles devolvían `str`, los expected eliminaban CRLF, el writer exigía `Set-Clipboard` y stdin `str`, y otro oráculo exigía `encoding`/`errors` como kwargs de texto. Eso contradice el desbloqueo TR-02/B2 de `E5-final-review-transport.md`: stdout/stdin deben ser binarios para que CR, LF y CRLF no atraviesen newline universal.

Los tests ahora fijan la norma exacta solicitada: `[Console]::Out.Write((Get-Clipboard -Raw))` no añade newline, el reader conserva los CR/LF presentes en el payload, y el writer transporta UTF-8 explícito como bytes hacia `[Console]::In.ReadToEnd()` + `[Windows.Clipboard]::SetText($text)`. Se rechazan `text`/`universal_newlines` activos y `encoding`/`errors` de `subprocess`, porque cualquiera de esas opciones reactiva el modo texto. No se restauró ni permitió el antiguo `rstrip` del reader.

## Cambios

### `tests/test_b102_clipboard.py`

- `_FakeCompleted` modela resultados binarios: `stdout` y `stderr` son `bytes` y sus defaults son `b""` (`tests/test_b102_clipboard.py:99-107`).
- El docstring de TC-B102-04/05 describe transporte binario, `Out.Write`, UTF-8 por stdin y WPF `SetText`, en vez del viejo protocolo de texto (`tests/test_b102_clipboard.py:20-26`).
- TC-B102-04 devuelve `b"OK_FROM_PS\r\n"` y exige exactamente `"OK_FROM_PS\r\n"`; ya no acepta que se pierda el CRLF. Exige `Out.Write((Get-Clipboard -Raw))`, rechaza `Out.WriteLine` y exige captura binaria sin newline universal (`tests/test_b102_clipboard.py:570-634`).
- TC-B102-05 usa `payload-Ñ\r\n` y exige `input == payload.encode("utf-8")`, de modo que el oráculo discrimina tanto UTF-8 como conservación exacta de CRLF. El comando debe contener `ReadToEnd` y WPF `SetText($text)`, y no debe contener `Set-Clipboard`; stdout/stderr del fake también son bytes (`tests/test_b102_clipboard.py:637-709`).
- Se conservaron los asserts de timeout >= 2 s, argv absoluto, payload fuera de argv, `shell=False` y `creationflags`/ventana oculta. El `rstrip` de la prueba de corte de línea en `:861` pertenece a otro contrato de `TextArea`, no al reader PowerShell, y no se utilizó para relajar el transporte.

### `tests/test_loadfilescreen_input.py`

- El fake de R-TUI-043-m devuelve bytes UTF-8 con `Ñ`, CRLF y un byte final inválido `0xff`. El expected conserva `Ñ` y `\r\n`, y exige U+FFFD sólo para el byte inválido; así se mantienen los antiguos oráculos de Unicode y decodificación tolerante sin requerir modo texto de `subprocess` (`tests/test_loadfilescreen_input.py:463-521`).
- El mismo nodo exige `Out.Write((Get-Clipboard -Raw))`, rechaza `Out.WriteLine` y newline universal, y mantiene timeout y argv absoluto del PowerShell del sistema, con la prohibición explícita de `wt`, `pwsh` o nombre bare en el diagnóstico.
- El docstring ya no describe el comportamiento de recorte/normalización anterior.

## Estabilidad de nodeids

Una comparación AST contra `HEAD` obtuvo superficies idénticas de funciones `test_*` y decoradores:

- `tests/test_b102_clipboard.py`: 12 definiciones, sin cambios de nombres ni decoradores;
- `tests/test_loadfilescreen_input.py`: 32 definiciones, sin cambios de nombres ni decoradores.

Por tanto, las parametrizaciones y nodeids de estos archivos permanecen intactos. Los seis archivos WinCI no fueron editados por este carril.

## Verificación estática

1. `compile()` incorporado de Python con `python -B`, sin importar módulos del proyecto: **OK** en ambos archivos.
2. Comparación AST de nombres/decoradores contra `HEAD`: **OK**, 12 y 32 superficies idénticas.
3. `git diff --check -- tests/test_b102_clipboard.py tests/test_loadfilescreen_input.py`: **exit 0**, sin errores de whitespace.
4. Búsqueda estática final: no quedan los antiguos fakes `stdout`/`stderr` de texto, expected sin CRLF, igualdad `input == "payload"` ni asserts positivos de `Set-Clipboard`/`encoding='utf-8'`/`errors='replace'` en los contratos actualizados.

## No ejecutado y cierre pendiente

No se ejecutaron pytest, colección, probes, aplicación, PowerShell, clipboard, baterías, workflow WinCI ni mutantes; tampoco se hizo aceptación manual. El orquestador debe ejecutar el clon Linux EXACTO del árbol integrado y, por las puertas que correspondan, WinCI y los demás controles.

Este informe documenta únicamente la corrección escrita y su validación estática. **No declara GREEN dinámico, WinCI, mortalidad de mutantes ni cierre de AT-I1b-8; la AT manual permanece pendiente.**
