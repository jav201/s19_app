# E5 matrix/support/workflow — corrección posterior al NO-GO

Base: `0d4d4e7c800b27040769a1a10117e62884cc7326`. Sin commits ni push. Alcance limitado a matrix, soporte, gate/workflow y esta evidencia. No se editaron tail, quit, producto ni requisitos.

## Cambios entregados

- `tests/test_b103_copy_paste_matrix.py`
  - `_seed_os_clipboard()` delega en `other_program_write(SEED)`; se eliminó el writer/reader PowerShell duplicado y sus conversiones de errores WinCI a `skip`.
  - Se conservan la espera del tail, la lectura OS independiente posterior a copy, los oráculos T1/T2 y las 28 celdas AT únicas. AT-I1b-8 sigue manual.
- `tests/support/b103_clipboard.py`
  - `other_program_read/write` llaman intrínsecamente a `require_isolated_clipboard("windows")` antes de resolver o iniciar procesos.
  - `other_program_write` usa un PowerShell absoluto externo, payload UTF-16LE Base64 por stdin, lectura stdin completa y `[Windows.Clipboard]::SetText($text)` sobre una sola cadena. Autoverifica mediante un segundo proceso `other_program_read`; un mismatch informa sólo longitudes.
  - `other_program_read` usa `[Text.UTF8Encoding]::new($false)` y `[Console]::Out.Write(Base64)`; no BOM, sin `rstrip` del payload y con CR/LF/LF final intactos. Los errores de proceso informan códigos y longitudes, no stderr ni contenido.
  - `_probe_once` ya no devuelve nonce, clipboard, prefijos ni excepciones con contenido: sólo resultado, tipos de error y longitudes.
- `tests/support/b103_winci_gate.py` (nuevo)
  - Audita cada testcase JUnit; rechaza failure, error, contadores inconsistentes, censo AT distinto de 28 y skips no permitidos.
  - Permite únicamente los brazos explícitos Linux-only existentes (`Linux-only`, `Linux only`, `Linux failing-writer arm`) y el skip AT-I1b-8 en su nodo manual exacto. No imprime los motivos de skip.
  - Recibe `--pytest-exit`: cualquier exit original no cero se devuelve sin enmascararlo; con pytest 0, una violación produce gate 1 y XML ilegible produce 2.
- `.github/workflows/clipboard-windows.yml`
  - Pytest escribe JUnit y stdout/stderr mediante `Tee-Object`; el gate recibe el exit capturado inmediatamente.
  - Se conservan transcript, JUnit y transcript del gate con `upload-artifact` e `if: always()`. El step termina con el resultado del gate, que preserva el exit original de pytest.

## Validación Linux/estática

Entorno scratch Linux: Python 3.11.16, pytest 9.2.0, Textual 8.2.8, `DISPLAY`/`WAYLAND_DISPLAY` ausentes y HOME/TMP/XDG/LOCALAPPDATA neutrales. El scratch partió del HEAD indicado más el diff de tests/workflow y el gate nuevo. **No se ejecutó PowerShell real, aplicación Windows, probe de clipboard ni clipboard del operador.** Los procesos PowerShell de los contratos son sustitutos en memoria.

1. `contract_probe.py`: **7/7 PASS**, `CONTRACT_FAILURES=0`, `CONTRACT_EXIT=0` y ejecución directa posterior `DIRECT_CONTRACT_EXIT=0`. Cubre writer externo/autoverificación con Unicode, CRLF, LF final y 70 000 caracteres, ausencia de writer/reader Win32 en pytest, mismatch redactado, probe redactado, guardas previas a proceso, rechazo de BOM, gate positivo/negativo y workflow. Resultado: `post-fix-contract-v3.txt`.
2. Colección real matrix: **29 nodos = 28 AT + 1 manual**, `collect-e5-fix.txt`.
3. Batería Linux serial de views/tail/quit/matrix: **122 passed, 19 skipped, 1 failed en 1094.03 s**, 142 nodos por el nuevo test estático de tail. Salida y JUnit: `linux-inc1b-e5-fix-transcript.txt`, `linux-inc1b-e5-fix-junit.xml`.
   - Matrix dentro de esa ejecución: **14 passed + 15 skipped**, sin failure/error. Las 14 P1 ejecutadas pasaron; las 14 P2 y AT-I1b-8 permanecen no ejecutadas.
   - El único fallo fue `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` de tail, descrito en Bloqueos.
4. Smoke final posterior al ajuste `.NET` de soporte: `AT-I1b-1/1-T1-P1`, **1 passed**, `PYTEST_EXIT=0`, `linux-p1-final-smoke.txt`.
5. Gate sobre el JUnit Linux real, usado deliberadamente como control negativo: detectó **1 failure + 18 skips no permitidos en un hipotético contexto WinCI + PYTEST_EXIT=1**, permitió sólo AT-I1b-8 y devolvió el exit original 1. Aserciones del control: PASS. `linux-junit-gate-negative.txt` no es un resultado WinCI ni un GO.
6. `matrix-support-workflow-e5-fix.patch` contiene sólo los cuatro archivos fuente propios. `git apply --check --whitespace=error-all --reverse` sobre el scratch final: **PASS**. El `git diff --check` acotado a propiedad también pasa.

## Bloqueos y límites

- **Producto sigue NO-GO, fuera de esta propiedad.** Con tail actualizado, `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` sigue fallando únicamente porque `s19_app/tui/os_clipboard_input.py` conserva `$input | Set-Clipboard` y `[System.Text.Encoding]::UTF8`: faltan `ReadToEnd`, `.NET SetText` y `UTF8Encoding($false)`. Resultado acotado: `tail-static-current.txt`. No se editó producto.
- La batería completa usó el snapshot de tail anterior a una corrección concurrente de su regex; por eso su fallo incluye también `other_program_read` local de tail. El smoke acotado posterior con tail actual confirma que esa parte local ya no falla y quedan sólo las cuatro observaciones de producto. **No se repitió la batería completa tras ese cambio concurrente de tail.**
- `tests/test_b103_clipboard_matrix.py`, archivo heredado fuera de esta asignación, tiene ocho sitios con `pytest.skip("Windows only")` que se activan al no ser Linux. Esos motivos no son Linux-only ni AT-I1b-8 y el nuevo gate los rechazará en WinCI hasta que su propietario los corrija.
- WinCI real no fue ejecutado. La semilla PowerShell, el reader/writer real, las 14 P2 y AT-I1b-8 siguen pendientes de su entorno/procedimiento autorizado. **Cobertura OS nueva demostrada aquí: 0/28; no se declara WinCI GREEN ni cobertura completa.**
- El `git diff --check` global del working tree está bloqueado por trailing whitespace preexistente en `.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e4/matrix/SHA256SUMS` y `evidence-e4/tail/SHA256SUMS`, fuera de propiedad. El chequeo acotado sí pasa.

## Evidencia principal

- `REPORT.md`, `post-fix-contract-v3.txt`, `collect-e5-fix.txt`.
- `linux-inc1b-e5-fix-transcript.txt`, `linux-inc1b-e5-fix-junit.xml`, `linux-p1-final-smoke.txt`.
- `linux-junit-gate-negative.txt`, `tail-static-current.txt`.
- `matrix-support-workflow-e5-fix.patch` (cuatro archivos propios), `integration-e5-fix.patch` (diff tracked histórico de tests/workflow; la copia conservada aquí está redactada y marcada como no aplicable).
- `contract_probe.py`, `pytest_runner.py`, `redact_and_hash.py`, `SHA256SUMS.txt`.

El redactor común sustituye cuentas/hogares/hosts y usa `<HOST>` para nuevos `hostname` XML; conserva los `[HOST]` ya presentes en esta evidencia histórica. Los hashes se generan después de redactar.
