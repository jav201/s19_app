# E5 — Revisión independiente FINAL del gate y cobertura WinCI

Base revisada: HEAD `305e5892` más el working tree actual. Alcance limitado a WG-01…WG-03 y a defectos introducidos directamente por su corrección en `tests/support/b103_winci_gate.py`, `tests/support/b103_winci_manifest.json`, `tests/support/b103_artifact_safety.py`, `tests/test_b103_winci_gate.py` y `.github/workflows/clipboard-windows.yml`.

Revisión independiente estática. No ejecuté pytest, colección, probes, PowerShell, clipboard, workflow, WinCI ni mutantes; tampoco modifiqué producto, tests, workflow o evidencia. Usé sólo lecturas y scripts stdlib `python -B` de AST/JSON/XML, sin importar módulos del proyecto. Los resultados Linux `160 passed / 96 skipped` en 1863,17 s y `44 passed / 2 skipped` de la selección correctiva son los comunicados para esta revisión, no ejecuciones repetidas por mí.

## Veredicto

**NO-GO para declarar cobertura WinCI o cerrar E5 por esta área.** WG-01, WG-02 y WG-03 están corregidos en la ruta escrita y no encontré defectos nuevos de implementación dentro del alcance revisado. El único hallazgo restante es la ausencia de ejecución WinCI real, una brecha de evidencia que impide convertir el censo estático y los controles Linux en un veredicto Windows.

La ruta escrita sí está lista para someterse al runner: un `WINCI_GATE_RESULT PASS` real exigiría los 256 nodos exactos, 212 passed, 44 skips permitidos, 108/108 obligaciones y 28/28 AT (14/14 P1 y 14/14 P2). Todavía no existe ese resultado. AT-I1b-8 permanece manual y **no se cierra** con esta revisión.

## Hallazgo restante

### WINCI-RUN — HIGH · design-gap (evidencia) — No hay ejecución ni veredicto WinCI

La ruta que puede producir la evidencia está escrita en `.github/workflows/clipboard-windows.yml:73-127`, pero no se ha ejecutado el workflow Windows ni se ha conservado un resultado real del gate. El JUnit known-good de las pruebas se construye desde el mismo manifiesto que se audita (`tests/test_b103_winci_gate.py:42-56,65-68,122-139`); es un control útil del algoritmo, no una ejecución de las obligaciones ni una prueba independiente del runner.

Los GREEN Linux comunicados no miden las copias Windows, los holders, PowerShell real, las 28 cadenas AT en WinCI ni la semántica efectiva de GitHub Actions/upload. La selección correctiva prueba controles en Linux; **no son mutantes de producto ejecutados** y no se infiere de ella mortalidad de mutantes ni cobertura Windows.

**Desbloqueo:** ejecutar el workflow real en el runner aislado y conservar transcript pytest, JUnit, transcript del gate y transcript de seguridad. Aceptar esta área sólo con `pytest_exit=0`, `gate_exit=0`, población exacta 256/212/44, 108/108 obligaciones, AT 28/28 y P1/P2 14/14, sin nodos ausentes, extras, duplicados ni skips no permitidos. Un resultado distinto deja el área en NO-GO.

## Cierre de los bloqueos anteriores

### WG-01 — cerrado en implementación escrita: población y 108 obligaciones

- El manifiesto enumera los seis archivos y fija **77 + 37 + 54 + 31 + 28 + 29 = 256 nodeids únicos** (`tests/support/b103_winci_manifest.json:46-369`). El cargador exige exactamente esos seis archivos, unicidad y los totales 256/108, con 46 views + 25 tail + 9 quit + 28 AT (`tests/support/b103_winci_gate.py:239-289`).
- Las 108 obligaciones equivalen a 80 casos de requisitos + 28 AT, no a 108 testcases. Cada entrada tiene requisito, nodeid y brazos internos no vacíos; se rechazan obligaciones duplicadas, fuera de población o asociadas a un skip (`tests/support/b103_winci_gate.py:185-245`). AT-I1b-8 no pertenece a ese conjunto.
- El gate rechaza ausencias, extras y duplicados de cualquier nodo (`tests/support/b103_winci_gate.py:360-409`) y exige outcome `passed` para cada obligación (`tests/support/b103_winci_gate.py:415-434`). Los 104 nodos auxiliares required-passed completan los 212 passed esperados; un skip auxiliar no listado también es violación.

Contraste independiente realizado, sin importar tests:

1. AST del árbol actual: los nombres de funciones del manifiesto coinciden con los seis archivos y los 132 IDs parametrizados literalmente derivables coinciden exactamente; las razones de skip asociadas también coinciden con sus funciones.
2. Los 37 IDs dinámicos heredados restantes coinciden con una colección pytest real ya archivada, sin faltantes, extras ni duplicados (`.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/mutants/linux/static-attempt2/collection/collect.txt:3851-3887`). Esta lectura de una colección previa no es una ejecución de mutantes.
3. La colección real archivada de `test_b103_clipboard_windows.py` coincide 77/77 con el manifiesto (`evidence-e5/legacy/linux-collect.txt:1-79`).
4. Un JUnit pytest real de las cuatro familias Inc 1b contiene 142/142 nodeids esperados, sin faltantes, extras ni duplicados (`evidence-e5/matrix/linux-inc1b-e5-fix-junit.xml:1,47`). Ese XML histórico contiene un fallo y se usó exclusivamente para contrastar identidad/formato, nunca como evidencia GREEN.

### WG-02 — cerrado en implementación escrita: skips exactos por nodo y razón

Ya no existe una exención global por prefijo. El gate busca el nodeid en `skip_rules`, exige igualdad literal de `skipped.message` con la razón del manifiesto y emite `DISALLOWED_SKIP` o `SKIP_REASON` en cualquier otro caso (`tests/support/b103_winci_gate.py:379-389`). Un nodo obligatorio omitido además genera `REQUIRED_NOT_PASSED`; un skip permitido que pasa genera `EXPECTED_SKIP` (`tests/support/b103_winci_gate.py:390-420`). El propio cargador prohíbe declarar una obligación como skip (`tests/support/b103_winci_gate.py:245`).

La partición WinCI escrita es exactamente:

| Categoría | N. | Identidad y razón |
|---|---:|---|
| `linux-only` | 6 | R-COPY.2/4; R-COPY.7/8; R-PASTE.9/101…103; R-PASTE.10/101 (`tests/support/b103_winci_manifest.json:151-158,255,263-266`) |
| `legacy-linux-h` | 37 | Todos los nodos de `test_b103_clipboard_matrix.py`, razón exacta `Windows only` (`tests/support/b103_winci_manifest.json:105-131`) |
| `manual` | 1 | Sólo `test_manual_windows_terminal_operator_acceptance`, AT-I1b-8, con su razón íntegra (`tests/support/b103_winci_manifest.json:358-365`) |
| **Total** | **44** | **212 passed + 44 skipped = 256** |

Las seis razones Linux-only y la manual coinciden literalmente con los `pytest.skip`/`mark.skip` actuales (`tests/test_b103_copy_views.py:486-489`; `tests/test_b103_clipboard_tail.py:815-818,979-1006`; `tests/test_b103_copy_paste_matrix.py:437-444`). Las ocho funciones heredadas que generan los 37 nodos contienen `pytest.skip("Windows only")` (`tests/test_b103_clipboard_matrix.py:154-159,218-224,269-272,297-300,334-340,384-387,413-416,444-447`).

El JUnit real disponible confirma la convención relevante de pytest: `classname="tests.test_…"`, `name` conserva los corchetes/IDs y `skipped.message` contiene la razón sin el prefijo archivo:línea del cuerpo. En particular, el mensaje manual real coincide exactamente con el manifiesto (`evidence-e5/matrix/linux-p1-junit.xml:1`). No encontré el mismatch classname/nodeid ni el desajuste de razón buscados. Los demás skips de infraestructura o plataforma no listados serían rechazados.

El tally Linux 96 es una partición distinta —77 Windows-only + 4 WinCI-only tail + 14 AT P2 + 1 manual— y no debe sustituirse por el 6+37+1 esperado en WinCI.

### WG-03 — cerrado en implementación escrita: AT canónicos, integridad JUnit y exit

- Los IDs AT se validan contra la forma canónica y contra la correspondencia celda/target/ruta (`tests/support/b103_winci_gate.py:202-214`). Las particiones se comparan como conjuntos y el censo exige 28 AT únicos (`:247-258,283-288`); el gate cuenta AT passed, no simples entradas presentes, y exige 14 P1 + 14 P2 (`:411-434`).
- Se rechazan outcomes ambiguos, failures/errors y skips indebidos (`:362-399`). Se reconcilian `tests`, `skipped`, `failures` y `errors` con los testcase observados, tanto en `testsuite` como en suites directas de `testsuites` y en atributos agregados de raíz si existen (`:321-340,436-439`). El JUnit real consultado tiene precisamente raíz `testsuites` con una suite hija, forma cubierta por esta lógica.
- `pytest_exit` distinto de cero es violación y conserva prioridad como código de salida, incluso con XML/manifiesto ilegible (`:349-353,465-493`). Un gate con violaciones y pytest 0 devuelve 1; sólo devuelve PASS con pytest 0 y cero violaciones.

Los controles known-good/known-bad cubren ausencias tail/quit, AT renombrado/P2 ausente, duplicado no AT, skip obligatorio con prefijo Linux, razón alterada, los cuatro contadores, XML vacío/malformed y exit 7 (`tests/test_b103_winci_gate.py:94-239`). Su GREEN Linux comunicado apoya el algoritmo, pero no sustituye WINCI-RUN.

## Preservación de exit y publicación de artefactos

No encontré una conversión de fallo en éxito en el cableado actual:

1. El workflow captura `$LASTEXITCODE` inmediatamente después de pytest y del gate, exporta ambos valores y termina el step con `$gateExit` (`.github/workflows/clipboard-windows.yml:77-92`).
2. `continue-on-error: true` está limitado al step de outcomes (`:77-80`) para permitir inspección/publicación de evidencia. El step final, con `always()`, falla cerrado con 2 si falta `WINCI_GATE_EXIT` y en otro caso sale con ese código (`:119-127`). Como el gate da prioridad al exit de pytest, se preserva el resultado funcional.
3. El escáner se ejecuta con `always()` pero **sin** `continue-on-error` (`:94-105`). El único upload exige `steps.artifact_safety.outcome == 'success'` y usa `if-no-files-found: error` (`:107-117`). Por tanto, un fallo funcional con artefactos limpios puede publicar evidencia y aun así terminar rojo; un fallo del escáner impide el upload y mantiene el job rojo aunque el step final salga 0. Un fallo del propio upload tampoco se convierte en éxito.
4. El escáner falla ante archivos ausentes, ilegibles o vacíos y ante JUnit malformed (`tests/support/b103_artifact_safety.py:178-213`), y devuelve 1 ante cualquier violación (`:216-230`). Sus diagnósticos contienen artefacto/categoría/regla, no el valor detectado. Esta conclusión se limita a la barrera revisada, no reabre las áreas de redacción de producto/tests.

## Condición de cierre y AT-I1b-8

Para cambiar este veredicto se necesita una única ejecución WinCI real y sus cuatro artefactos, con el resultado exacto descrito en WINCI-RUN. Los mutantes de producto permanecen fuera de lo demostrado por esta revisión.

AT-I1b-8 sigue siendo un skip manual permitido, fuera de las 108 obligaciones automatizadas y de las 28 celdas AT. No lo ejecuté, no lo marco passed y no lo cierro: requiere la aceptación separada del operador, 6/6, con su propio clipboard y sin automatización del agente.
