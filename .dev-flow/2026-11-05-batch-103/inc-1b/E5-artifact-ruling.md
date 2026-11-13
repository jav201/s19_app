# E5 artifact ruling — addendum limitado a Inc 1b

Base: HEAD `305e5892` más el working tree actual. Este ruling resuelve el conflicto entre la prohibición de artefactos de Inc 1a y la evidencia WinCI exigida por E5. Es una decisión de diseño limitada al árbol Inc 1b; no edita ni reinterpreta retroactivamente los registros sellados de Inc 1a.

Trabajo exclusivamente estático. No ejecuté pytest, colección, probes, PowerShell, clipboard, workflow, baterías ni mutantes. Este ruling no declara GREEN, publicación WinCI, escáner ejecutado, mortalidad de mutantes ni aceptación manual AT.

## Regla anterior: E3S-07(b) de Inc 1a

Inc 1a E3S-07(b) (`.dev-flow/2026-11-05-batch-103/inc-1a/E3-security.md:39`) observó que un artefacto podía contener payloads del clipboard y que el job público no planeaba publicar ninguno. Su corrección aceptada exigió `no upload-artifact`; la misma ley quedó en el ejemplo del workflow (`inc-1a/codewire/graph-inc1a.md:722`) y en el expected de R-PASTE.20/1 (`inc-1a/02-test-cases.md:241`). El cierre histórico figura en `inc-1a/E3-security.md:123`.

Esos registros permanecen intactos. La regla era coherente con el diseño anterior: sin artefactos no había publicación que auditar ni necesidad de conservar JUnit/transcripts como evidencia.

## Reemplazo E5 y su justificación

E5 exige auditar en WinCI la población exacta de 256 testcases y las 108 obligaciones, no sólo aceptar un código agregado de pytest (`E5-fix-winci-gate.md:9-38`; `E5-final-review-winci-gate.md:15-21`). Para ello deben conservarse el transcript pytest, el JUnit y los transcripts del gate y de seguridad. La antigua prohibición absoluta impediría preservar esa evidencia.

En consecuencia, **sólo para `.github/workflows/clipboard-windows.yml` en el árbol Inc 1b**, E3S-07(b) queda reemplazada por la siguiente barrera de publicación:

1. `tests/support/b103_artifact_safety.py` se ejecuta antes de cualquier upload y examina transcript pytest, JUnit y transcript del gate. Archivos ausentes, vacíos o ilegibles y cualquier canario conocido producen fallo; no se publica el valor detectado.
2. La única publicación permitida usa `actions/upload-artifact@v4` y exige literalmente `if: always() && steps.artifact_safety.outcome == 'success'`. Un outcome distinto de `success`, incluido un known-bad que hace fallar el escáner, impide que el step de upload se ejecute.
3. `if-no-files-found: error` es obligatorio: la evidencia requerida no puede desaparecer silenciosamente.
4. Un fallo funcional con artefactos limpios permite conservar evidencia, pero no convierte el job en éxito: el step final conserva `WINCI_GATE_EXIT`. Un fallo del escáner impide el upload y mantiene el job rojo.
5. Permanecen las prohibiciones de `secrets.`, `cache:`, `pull_request_target` y `workflow_run`, junto con `permissions: contents: read`, `persist-credentials: false` y las demás guardas del workflow. Este addendum no autoriza artefactos arbitrarios ni otros workflows.

El workflow actual ya implementa el escáner en `.github/workflows/clipboard-windows.yml:100-111`, el upload condicionado en `.github/workflows/clipboard-windows.yml:113-123` y la salida preservada en `.github/workflows/clipboard-windows.yml:125-133`; no necesitó ningún cambio para este addendum.

## Oráculos y trazabilidad

- `tests/test_b103_clipboard_core.py::test_r_paste_20_1_windows_workflow_runs_os_clipboard_tests` sustituye `assert "upload-artifact" not in text` por una única aparición de `uses: actions/upload-artifact@v4`, orden escáner antes de upload, condición exacta de outcome y `if-no-files-found: error`. Conserva las demás guardas y su nodeid.
- `tests/test_b103_winci_gate.py::test_workflow_upload_is_blocked_unless_artifact_scanner_passed` queda enlazado a R-TUI-043.13/102 como oracle estático **partial**. Los controles known-bad del escáner ya pertenecen a `tests/test_b103_winci_gate.py`; no se afirma aquí una nueva ejecución.
- `01-requirements.md` amplía únicamente el contexto de R-TUI-043.13/102: transcript/JUnit sólo tras escáner exitoso y known-bad sin upload. No añade filas, casos ni conteos.
- `02-test-cases.md` amplía Expected y Tests de /102 y añade una nota E5 al final. Conserva Coverage `partial`, Result `verified`, la historia E4 y los totales 112/28/1; el `verified` histórico no se presenta como ejecución del nuevo addendum.
- `codewire/graph-inc1b.md` añade la barrera al ejemplo existente /102, sin crear ni modificar nodos.

## Condición de evidencia

El orquestador debe ejecutar en el clon Linux exacto los guardas y las familias previstas. La publicación real WinCI, el comportamiento del escáner sobre sus artefactos reales y el gate de 108 obligaciones siguen requiriendo ejecución. AT-I1b-8 permanece manual y fuera de este ruling.
