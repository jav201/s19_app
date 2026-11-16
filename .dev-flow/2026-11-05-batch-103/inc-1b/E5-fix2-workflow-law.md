# E5 fix2 — Carril E: triggers y addendum de artefactos

Base: HEAD `305e5892` más el working tree existente. Se conservó todo el trabajo previo y no se hicieron commits ni otras mutaciones Git. La primera corrección restauró rutas en `.github/workflows/clipboard-windows.yml`; el addendum E5 posterior actualizó el guarda y la trazabilidad Inc 1b indicados abajo. No se editó ningún registro sellado de Inc 1a ni se cambiaron nodeids o identificadores de las seis familias.

Trabajo exclusivamente estático. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow, baterías ni mutantes. No declaro GREEN, cierre WinCI, publicación real de artefactos, mortalidad de mutantes ni aceptación manual AT.

## 1. Corrección acotada de triggers

Se restauraron las entradas literales siguientes en **ambos** filtros de rutas:

- `s19_app/tui/os_clipboard_input.py`;
- `s19_app/tui/capped_text_area.py`.

Ubicación resultante: `push.paths` en `.github/workflows/clipboard-windows.yml:10-11` y `pull_request.paths` en `.github/workflows/clipboard-windows.yml:30-31`. Las cuatro entradas preceden al glob `s19_app/**/*.py`, que se conservó junto con los demás globs y rutas de tests.

No se alteraron el gate del manifiesto/JUnit, la selección de las seis familias, el escáner de seguridad, la condición de publicación de artefactos ni los steps que preservan y aplican los códigos de salida.

## 2. Addendum E5: incompatibilidad `upload-artifact` resuelta

La antigua prohibición procedía de Inc 1a E3S-07(b), que evitaba publicar artefactos por el riesgo de divulgar payloads del clipboard. E5 necesita conservar transcript/JUnit para auditar 108 obligaciones y ya incorpora un escáner fail-closed. El reemplazo actual, limitado al árbol Inc 1b, quedó formalizado en `.dev-flow/2026-11-05-batch-103/inc-1b/E5-artifact-ruling.md`; los registros Inc 1a permanecen intactos.

En `tests/test_b103_clipboard_core.py:1752-1758`, el guarda `test_r_paste_20_1_windows_workflow_runs_os_clipboard_tests` ya no prohíbe `upload-artifact`. Ahora exige:

- exactamente una aparición de `uses: actions/upload-artifact@v4`;
- presencia del escáner `tests/support/b103_artifact_safety.py` antes del upload;
- `if: always() && steps.artifact_safety.outcome == 'success'`;
- `if-no-files-found: error`.

Se conservaron las guardas de `secrets.`, `pull_request_target`, `workflow_run`, `cache:`, la única sección `permissions:` y el resto del test. El nodeid no cambió.

El workflow actual ya cumple esas aserciones: escáner antes del upload en `.github/workflows/clipboard-windows.yml:100-111` y upload en `.github/workflows/clipboard-windows.yml:113-123`, con outcome `success`, acción v4 y archivos obligatorios. Por ello **el addendum no hizo ningún cambio adicional al workflow** y mantuvo el step final de exit en `.github/workflows/clipboard-windows.yml:125-133`.

## 3. Trazabilidad de diseño actualizada

- `01-requirements.md:131`: amplía el contexto R-TUI-043.13/102 para exigir transcript/JUnit sólo tras escáner exitoso y bloqueo de upload ante un known-bad, sin nuevas filas, casos o conteos.
- `02-test-cases.md:127`: amplía Expected y añade `tests/test_b103_winci_gate.py::test_workflow_upload_is_blocked_unless_artifact_scanner_passed` como **partial**. Coverage `partial` y Result `verified` se conservan como valores históricos, sin afirmar una nueva ejecución.
- `02-test-cases.md`: una nota E5 añadida al final registra el reemplazo limitado, la barrera y la invariancia de los totales 112/28/1 y 108 obligaciones, sin reescribir la historia.
- `codewire/graph-inc1b.md:203`: el ejemplo existente /102 incorpora la barrera de artefactos; no se añadió ni modificó ningún nodo.
- `E5-artifact-ruling.md`: cita E3S-07(b), justifica la nueva necesidad E5 y delimita la sustitución al workflow del árbol Inc 1b.

Archivos modificados por este carril: `.github/workflows/clipboard-windows.yml`, `tests/test_b103_clipboard_core.py`, los tres documentos de diseño anteriores, `E5-artifact-ruling.md` y este informe. No se tocó ningún otro archivo.

## 4. Verificación estática realizada

1. La primera edición sustituyó exactamente las dos apariciones del glob de producto, una por evento, añadiendo delante las mismas dos rutas explícitas en cada caso.
2. Una búsqueda localizó las cuatro entradas y confirmó la presencia continuada del gate, escáner, condición `artifact_safety` y salida final mediante `WINCI_GATE_EXIT`.
3. El diff del guarda muestra únicamente la sustitución de la prohibición obsoleta por las seis líneas de oracle/variables del addendum; las prohibiciones de seguridad anteriores permanecen.
4. Se comprobó estáticamente que las cadenas exigidas por el nuevo guarda ya existen en el workflow y en el orden escáner → upload; no fue necesario adaptar YAML.
5. `git diff --check` sobre workflow, guarda y documentos de diseño terminó sin errores de whitespace. Git emitió únicamente avisos informativos de conversión LF→CRLF para archivos del working copy.
6. La revisión de diff confirma que el resto de cambios frente a HEAD pertenece al trabajo previo conservado; no se revirtieron ni reescribieron esos cambios.

## 5. Pendiente

La incompatibilidad estática quedó resuelta en el árbol, pero sin ejecución no se declara el guarda GREEN. El orquestador debe ejecutar en el clon Linux exacto `test_r_paste_20_1`, el oracle de upload del gate y las comprobaciones integradas que correspondan, conservando los nodeids de las seis familias. La ejecución WinCI real, sus artefactos y cualquier mutante siguen pendientes de evidencia; AT-I1b-8 permanece manual y no se cierra aquí.
