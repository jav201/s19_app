# E5 revisión final 3 independiente — divulgación y evidencia

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. Revisión independiente posterior a fix3 y a la incorporación de los resultados finales.

No ejecuté pytest, colección, probes, producto, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto, tests, workflow, ledger, canon o evidencia. La revisión usó lectura estática y búsquedas sobre los bytes actuales. La única escritura es este informe.

Se aceptan como datos del orquestador: full exacto **160 passed / 96 skipped, exit 0**; selección **246 passed / 2 skipped**; recheck de leyes **5 failed / 1 passed**, igual que en base `e2e93548`; y corrección de B97. Esos resultados no se reinterpretan como ejecuciones propias.

## Veredicto

**NO-GO para divulgación/evidencia del árbol actual.**

D-06 está cerrado, el outer 14/14 queda archivado mediante su nodo padre y D-01/D-02/D-05 no muestran regresiones. El bloqueo es nuevo y concreto: después del PASS de redacción y manifests 6/78 se añadieron `full-six-families-final.txt` y `law-recheck.txt` sin aplicarles esa redacción ni incluirlos en el manifest. Ambos contienen rutas personales sin redactar; el segundo también reproduce identidades y una dirección LAN procedentes de los fallos históricos.

| ID | Severidad | Estado | Hallazgo |
|---|---|---|---|
| D-06 | HIGH previa | CERRADO | Valores omitidos incorporados; censo AST independiente con known-present; 180 known-bad por familia/forma/superficie. |
| D-03 | MEDIUM previa | CERRADO en su alcance original | Selección final y JUnit copiados y redactados; nodo outer PASS con assertions exactas 14/14. |
| D-04 | MINOR previa | ABIERTO, REGRESIÓN | El manifest raíz tiene 20 entradas, pero el árbol actual exige 22; el agregado actual es 80 archivos, no 78. |
| F3-01 | HIGH | ABIERTO | Los dos transcripts añadidos después contienen datos personales sin redactar y no están cubiertos por el censo/manifest vigente. |
| D-01 | HIGH previa | CERRADO | Diagnósticos agregados y hostile sin serializar observaciones o excepciones. |
| D-02 | HIGH previa | CERRADO | Logs completos y formas XML/escapadas; causas de proceso/Base64 suprimidas. |
| D-05 | MINOR previa | CERRADO | El clasificador consume el `stage` del `_ProbeDetail` producido por `_probe_once()`. |

## F3-01 — HIGH · los nuevos artefactos finales no son divulgables en su forma actual

- `evidence-e5/full-six-families-final.txt:1` contiene una ruta de hogar Unix con cuenta, sin el placeholder usado por la copia histórica redactada `evidence-e5/full-six-families.txt:1`.
- `evidence-e5/law-recheck.txt:1,8-17,724-740` contiene rutas de hogar Unix/Windows, identidades de cuenta y una dirección LAN. Este informe no reproduce sus valores.
- El redactor tiene reglas para esas categorías (`evidence-e5/redact_e5.py:33-91`) y recorre recursivamente los archivos, salvo el propio redactor y el censo (`:247-258`). Sus únicas excepciones son los tres controles ejecutables declarados (`:12-16`); ninguna cubre estos transcripts.
- El censo almacenado sigue describiendo la pasada anterior: 156 archivos y modificaciones únicamente en `final-targeted.txt`/JUnit (`evidence-e5/redaction-census.json:31,37-50`). No registra una pasada posterior sobre los dos archivos nuevos.

El recheck sí tiene **0 hits reportados** en `inc-1b/E5*` e `inc-1b/evidence-e5`: sus hallazgos E5 nombrados pertenecen a otros incrementos o a E3/E4/evidence-e2 (`law-recheck.txt:724-740`). Ese hecho no sanea el archivo copiado después de la ejecución: el propio `law-recheck.txt` conserva en `evidence-e5` los datos que su redactor debía sustituir.

No afirmo que estos bytes se hayan publicado externamente. El defecto confirmado es que están almacenados sin redactar dentro de la evidencia E5 preparada para divulgación y quedan fuera del PASS archivado.

## D-04 — MINOR · el PASS 6/78 es histórico, no el estado del árbol actual

`E5-redaction-final.md:46-63` registra correctamente el estado verificado en aquella pasada: raíz de 20 archivos y total de 78. El `evidence-e5/SHA256SUMS.txt:1-20` actual conserva esas 20 entradas, pero no contiene `full-six-families-final.txt` ni `law-recheck.txt`.

El verificador enumera **todo archivo directo** y exige igualdad exacta entre mapa y bytes (`evidence-e5/refresh_manifests.py:24-37,59-104`). Por inspección directa, la raíz actual tiene 22 archivos esperados —las 20 entradas anteriores más esos dos transcripts— y el esquema agregado suma 80. Por tanto, el 6/78 comunicado no puede atribuirse al working tree actual, sin necesidad de ejecutar el verificador para deducir la discrepancia.

**Cierre requerido de F3-01/D-04:** redactar los dos transcripts, repetir el censo de redacción sobre el árbol resultante, reconstruir los seis manifests desde los bytes redactados y verificar integridad/cobertura exactas. El full 160/96 y el recheck 5/1 siguen siendo resultados aceptados; lo bloqueado es divulgar sus artefactos actuales.

## D-06 — cerrado

- `tests/support/b103_artifact_safety.py:15-46` declara 18 familias. Incluye `transport-cr`, `transport-crlf`, `powershell-read` y `powershell-write`, y también los valores descubiertos por el censo para `external-round-trip`, `xml-secret`, `paste-payload` y `os-state`. Los valores CR/CRLF y PowerShell tienen orígenes reales en `tests/test_b103_clipboard_tail.py:1253-1259` y `tests/test_b103_clipboard_windows.py:2309-2311,2371`.
- El esperado ya no nace de una segunda tabla manual. `_ast_payload_census()` deriva valores del helper y de las rutas recibidas (`tests/test_b103_winci_gate.py:483-495`); el test alimenta esas rutas desde `gate.EXPECTED_FILES` (`:533-544`), cuyas seis fuentes están fijadas en `tests/support/b103_winci_gate.py:19-28`.
- `_census_misses()` exige declaración literal y detección de raw/prefix/repr/escape/XML para cada valor derivado (`tests/test_b103_winci_gate.py:512-530`). El known-present sintético crea un payload ausente del escáner y exige tanto su descubrimiento AST como un miss `declaration` (`:547-564`). Así, una omisión futura dentro del perímetro estático declarado tiene un brazo capaz de ponerse rojo.
- Los known-bad parametrizan las 18 familias × 5 formas × transcript/JUnit = **180 casos** (`:584-622`). Cada caso exige `CONTROL_CANARY`, salida del CLI igual a 1 y ausencia del payload en el diagnóstico. El censo comprueba además las formas de todos los valores de cada familia, no sólo del representante elegido para la parametrización (`:512-530,567-581`).
- La selección archivada incluye los módulos completos de seguridad y gate (`evidence-e5/run_e5_final_targeted.py:18-19`). Su JUnit declara 248 tests, 0 failures y 0 errors, e incluye como PASS los nodos del censo, el known-present y el outer (`evidence-e5/final-targeted-junit.xml:1`). Con el 246/2 aceptado, D-06 queda cerrado dinámicamente en ese árbol.

El cierre se limita al perímetro explícito del derivador: expresiones dinámicas no resolubles, cadenas vacías/whitespace, valores de menos de cuatro caracteres y payloads generados de más de 256 quedan declarados como exclusiones en `tests/test_b103_winci_gate.py:304-311`. No lo presento como censo universal de valores sólo existentes en runtime.

## D-03 — outer 14/14 y selección final archivados

El outer conserva exactamente 14 nombres esperados (`tests/test_b103_e5_safety.py:516-531`), exige hijo no cero, 14 testcases, el conjunto exacto de 14 fallos y cero errores (`:543-577`). Audita stdout, stderr, JUnit crudo y una superficie XML parseada que recorre tags, texto, tails y atributos (`:534-540,579-587`).

`evidence-e5/final-targeted.txt:7` archiva **246 passed, 2 skipped**. El JUnit padre contiene `test_e5_outer_known_bad_child_is_red_without_transcript_or_junit_disclosure` sin fallo y declara 248/0/0/2 en tests/failures/errors/skipped (`evidence-e5/final-targeted-junit.xml:1`). Por tanto, el PASS archivado del padre aporta la trazabilidad de sus assertions 14/14; no se afirma que exista un JUnit hijo separado.

Los dos artefactos `final-targeted` están redactados: sus rutas/hostname usan `<HOME>`/`<HOST>` (`final-targeted.txt:1,6`; `final-targeted-junit.xml:1`) y las búsquedas estáticas de las rutas e identidades conocidas no dieron hits. D-03 queda cerrado; F3-01 afecta a los otros dos transcripts, no a éstos.

## D-01/D-02/D-05 — sin regresiones

- **D-01:** `_counts()` emite mensajes fijos (`tests/test_b103_clipboard_tail.py:309-317`), `_run_arms()` agrega sólo labels (`:400-409`) y los fallos hostile de éxito/cardinalidad/argv/cwd/input usan mensajes fijos o `from None` (`:1269-1308`). El outer ejercita estas vías.
- **D-02:** `_LogCapture.emit()` conserva `self.format(record)` (`tests/support/b103_clipboard.py:486-494`); Windows y tail mantienen las formas directa/prefijo/repr/escape/XML (`tests/test_b103_clipboard_windows.py:143-185`; `tests/test_b103_clipboard_tail.py:368-397`). Las conversiones de excepciones de proceso y Base64 usan `from None` (`tests/support/b103_clipboard.py:644-647,696-703`). Los controles directos cubren mensaje/excepción/stack y el outer añade XML (`tests/test_b103_e5_safety.py:101-124`).
- **D-05:** `_probe_once()` produce `stage="round-trip-mismatch"` y longitudes (`tests/support/b103_clipboard.py:186-210,246-252`); `_probe_failure_metadata()` prefiere ese stage (`tests/test_b103_clipboard_windows.py:188-206`). El control obtiene el detalle del productor real (`tests/test_b103_e5_safety.py:46-72`).

## Resultados y puertas que permanecen separadas

- El full exacto **160/96 exit 0** se acepta como dato del orquestador; `full-six-families-final.txt:14` coincide con 160/96. Su contenido no es divulgable hasta cerrar F3-01/D-04.
- El recheck archiva cinco nodos failed y el total **5 failed, 1 passed** (`law-recheck.txt:786-791`), con equivalencia aceptada respecto de `e2e93548`. No son cinco regresiones E5 nuevas ni una suite verde. B97 queda corregido y su nodo también aparece PASS en la selección final.
- **WinCI real sigue sin ejecutarse.** La selección Linux no sustituye esa puerta.
- **Los mutantes de producto siguen sin ejecutarse.** El censo AST, known-present, known-bad y outer no son mortalidad de producto.
- **AT-I1b-8 sigue manual/no verificada.** El manifest conserva su razón y categoría (`tests/support/b103_winci_manifest.json:359-364`) y el gate mantiene esa única excepción (`tests/support/b103_winci_gate.py:260-264`).

Para cambiar esta revisión a **GO de divulgación/evidencia** basta con cerrar F3-01 y la regresión D-04 sobre los bytes actuales. Ese GO futuro no cerraría WinCI, mutantes de producto ni AT-I1b-8.
