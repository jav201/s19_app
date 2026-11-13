# E5 revisión final 2 independiente — divulgación y evidencia

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. Revisión independiente de D-01…D-06 tras fix2 y de los defectos directamente introducidos por esas correcciones.

No ejecuté pytest, colección, probes, producto, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto, tests, workflow, ledger, canon, evidencia o divulgaciones preexistentes. Las comprobaciones dinámicas se limitaron a los verificadores read-only de redacción y manifests. La única escritura es este informe.

## Veredicto

**NO-GO para divulgación/evidencia.**

Persiste un **HIGH de implementación** en D-06: el censo del escáner sigue incompleto y los known-bad sólo prueban la población declarada, no toda la población real de las seis familias. D-03 conserva un **MEDIUM de design-gap**: el outer 14/14 está bien construido y su PASS queda comunicado por la selección final, pero el resultado final no está archivado localmente. Hay además una regresión **MINOR de implementación** en D-04: el launcher final nuevo deja el manifest raíz desactualizado y su verificador en rojo.

No encontré un BLOCKER o MAJOR adicional dentro del alcance permitido. D-01, D-02 y D-05 sí están cerrados en implementación, con la evidencia dinámica comunicada y los límites expresados abajo.

| ID | Severidad | Clase | Estado | Resumen |
|---|---|---|---|---|
| D-06 | HIGH | impl | ABIERTO, PARCIAL | Se añadieron las familias antes omitidas, pero faltan payloads reales CR/CRLF y `PS-READ…`; el known-bad no puede detectar esa omisión. |
| D-03 | MEDIUM | design-gap | PARCIAL | Outer exacto 14/14 y cuatro superficies; selección Linux comunicada 164/2, sin transcript/JUnit final copiado y redactado localmente. |
| D-04 | MINOR | impl | PARCIAL, REGRESIÓN | Redacción actual PASS con excepciones declaradas; manifest raíz FAIL, 17 archivos esperados frente a 16 entradas. |
| D-01 | HIGH previa | impl | CERRADO | El agregador ya no serializa excepciones ni el ledger y los diagnósticos hostile son fijos. |
| D-02 | HIGH previa | impl | CERRADO | Logs completos, formas XML en Windows/tail, outer XML y conversiones `from None`. |
| D-05 | MINOR previa | impl | CERRADO | El clasificador usa el `stage` del `_ProbeDetail` real y el control obtiene ese detalle del productor real. |

El resultado `164 passed / 2 skipped` es un dato del orquestador sobre el clon Linux exacto, no una ejecución de esta revisión ni evidencia local archivada. No es un veredicto WinCI, no es la batería full de seis familias/leyes todavía en ejecución y no demuestra mortalidad de mutantes de producto.

## D-06 — HIGH · impl · el censo ampliado aún no es completo

La corrección incorpora `SECRET-TEXT`, `SECRET-RC`, `SECRET-SUFFIX` y las demás categorías declaradas en `tests/support/b103_artifact_safety.py:15-32`. `_forms()` deriva valor, representaciones, escapes, XML y prefijos en `:141-159`. Los known-bad recorren las diez categorías declaradas × cinco formas × transcript/JUnit en `tests/test_b103_winci_gate.py:331-369`. Esto cierra las omissiones concretas señaladas en la revisión anterior, pero no el bloqueo de censo completo.

Hay contradicciones directas con la población actual:

- Los brazos CR y CRLF añadidos a una de las seis familias usan payloads `SEED-CR…` y `SEED-CRLF…` en `tests/test_b103_clipboard_tail.py:1253-1259`. La propia intervención los declara añadidos en `E5-fix2-transport.md:21-28`. No existe ninguna de esas familias en `CONTROL_CANARIES` ni en `_REQUIRED_CONTROL_CANARIES`.
- El nuevo reader exacto siembra un payload `PS-READ…` con Unicode y saltos en `tests/test_b103_clipboard_windows.py:2303-2311`; tampoco está censado. Además, la ruta WinCI conserva una llamada directa con literal `PS-READ` en `:2371`, que proporciona una vía concreta de aparición en el source de un traceback.
- El oráculo de censo compara dos tablas manuales equivalentes (`tests/test_b103_winci_gate.py:277-300`), no una derivación de las seis fuentes. Por eso puede terminar verde con esas omissiones. Los 100 brazos parametrizados de `:331-369` prueban cada familia/forma **declarada**, pero no los valores ausentes. El PASS comunicado 164/2 no resuelve este falso negativo.

El workflow conserva stdout/stderr, JUnit y gate (`.github/workflows/clipboard-windows.yml:83-98`), y permite el upload cuando el escáner termina success (`:100-123`). Si uno de los payloads no censados aparece en un fallo, el escáner no tiene una regla que lo marque y la barrera puede quedar verde. Es el mismo impacto de publicación que motivó D-06, ahora demostrado también sobre valores introducidos por fix2. No afirmo que el producto haya emitido esos valores; el defecto confirmado es que la última barrera no los reconocería.

**Cierre requerido:** completar el censo desde las seis fuentes —incluidos los payloads CR/CRLF y `PS-READ…`—, añadir known-bad de cada familia/forma/superficie omitida y repetir la selección aplicable en el árbol resultante. El censo debe tener un control contra la población real, no sólo igualdad con una segunda tabla manual.

## D-03 — MEDIUM · design-gap · outer 14/14 escrito y comunicado; evidencia final aún fuera del archivo local

### La ruta outer sí es exigente

- `_EXPECTED_KNOWN_BAD` enumera exactamente 14 nombres, incluidos `test_log_xml` y `test_hostile_log_xml` (`tests/test_b103_e5_safety.py:516-531`).
- El padre ejecuta un pytest hijo y exige retorno no cero (`:543-560`).
- Exige 14 testcases, el conjunto exacto de 14 fallos y cero errores (`:562-577`). Un PASS del padre demuestra 14/14 RED deliberado, no un fallo genérico ni una colección parcial.
- Audita stdout, stderr, JUnit crudo y una superficie parseada que recorre tags, texto, tails y nombres/valores de atributos (`:534-540,579-587`). `_assert_no_canary()` usa las formas derivadas completas (`:38-43`).
- Los brazos cubren probe real, round-trip, encadenamiento de lectura/escritura, mensaje/excepción/stack/XML, `_counts()` dentro de `_run_arms()` y cardinalidad/argv/cwd/input/XML hostile (`:278-512`). También exige marcadores seguros (`:589-602`).

`evidence-e5/run_e5_final_targeted.py:18-19` incluye los dos módulos completos que contienen el outer y los known-bad del escáner. Por tanto, **si el árbol es exactamente éste, como comunica el orquestador, el resultado 164/2 implica que el nodo outer pasó y que sus assertions 14/14 y de no divulgación se cumplieron**. Lo acepto como resultado ejecutado comunicado, no como ejecución propia.

### Lo que sigue sin estar archivado localmente

El único artefacto final localizado es el launcher. `run_e5_final_targeted.py:17` nombra `evidence-e5/final-targeted-junit.xml`, pero ese archivo no existe en este working tree. Tampoco hay transcript final, resumen archivado del outer ni ocurrencias locales de `164 passed` en `evidence-e5`. El JUnit que el orquestador indica conservar en el clon **no se cuenta como evidencia local copiada, redactada o cubierta por manifests**.

`evidence-e5/full-six-families.txt:14` sigue siendo el resultado histórico `160 passed, 96 skipped in 1449.12s`; no lo presento como la ejecución full actualmente en curso ni como un resultado nuevo de esta revisión.

**Cierre requerido:** copiar desde el clon el transcript y JUnit de la selección 164/2, redactarlos y cubrirlos con manifests. El JUnit/transcript padre debe conservar el nodo outer; su PASS archivado, junto con las assertions actuales, aporta la trazabilidad 14/14. No se debe afirmar que existe un JUnit hijo archivado si no se conservó. La full de seis familias/leyes necesita su propia evidencia cuando termine.

## D-04 — MINOR · impl · redacción vigente PASS, integridad de manifests FAIL

Ejecuté únicamente los verificadores read-only existentes:

```text
python -B evidence-e5/redact_e5.py --check
REDACTION_CHECK PASS files=153 residual=0 exceptions=8

python -B evidence-e5/refresh_manifests.py --check
MANIFEST_VERIFY PASS legacy files=8
MANIFEST_VERIFY PASS matrix files=22
MANIFEST_VERIFY PASS mutants files=5
MANIFEST_VERIFY PASS quit files=7
MANIFEST_VERIFY FAIL evidence-e5/SHA256SUMS.txt expected_files=17 actual_files=16
MANIFEST_VERIFY PASS tail files=16
MANIFEST_VERIFY_RESULT FAIL manifests=6 files=75
```

El PASS de redacción conserva ocho ocurrencias explícitas en tres controles, no significa `0 hits` absoluto: cinco en `matrix/contract_probe.py`, dos en `quit/validate_routes.py` y una en `legacy/redaction_runtime_probe.py`. No encontré un residuo nuevo bajo las reglas y excepciones ya declaradas.

La regresión concreta es `evidence-e5/run_e5_final_targeted.py`: existe como archivo directo nuevo, pero no aparece entre las 16 entradas de `evidence-e5/SHA256SUMS.txt:1-16`. El verificador exige exactamente todos los archivos directos (`refresh_manifests.py:24-37,68-104`), por lo que el cierre previo de integridad ya no describe el árbol actual. Esto fue introducido al añadir el launcher sin reconstruir el manifest; no invalida los hashes que sí pasan, pero deja la barrera agregada en FAIL.

**Cierre requerido:** al incorporar los resultados finales, repetir redacción, reconstruir los manifests desde los bytes almacenados y obtener PASS global. Los archivos todavía ausentes de D-03 no se cuentan como limpios ni como archivados.

## D-01 — cerrado

`_counts()` emite diagnósticos fijos y ya no incorpora `obs` (`tests/test_b103_clipboard_tail.py:309-317`). `_run_arms()` captura `AssertionError` sin `str(exc)` y agrega únicamente labels (`:400-409`). El fallo de `_success()` se reemplaza por un mensaje genérico con `from None`, y cardinalidad, argv, cwd e input tienen mensajes fijos (`:1269-1308`). El outer ejercita tanto `_counts()` como los fallos hostile (`tests/test_b103_e5_safety.py:405-512`). Con el PASS outer comunicado, cierro la vía D-01; esto no compensa el falso negativo independiente D-06.

## D-02 — cerrado

- `_LogCapture.emit()` conserva `self.format(record)`, incluidos exception text y stack text (`tests/support/b103_clipboard.py:486-494`).
- Windows y tail comparten formas directa/prefijo/`repr`/escape/XML, con CR numérico y atributos (`tests/test_b103_clipboard_windows.py:143-185`; `tests/test_b103_clipboard_tail.py:368-397`).
- Los controles directos recorren mensaje, excepción y stack para todas las formas en ambos detectores (`tests/test_b103_e5_safety.py:101-124`). El outer añade XML de log y el brazo hostile XML (`:401-402,511-512`).
- Las conversiones de excepciones de proceso y Base64 usan `raise AssertionError(...) from None` (`tests/support/b103_clipboard.py:644-647,696-703`).

No queda la laguna XML de tail ni la pérdida de causa/contexto señaladas antes. El outer y los controles directos están incluidos en el PASS comunicado, sin elevarlo a ejecución propia.

## D-05 — cerrado

El productor real devuelve `_ProbeDetail.stage="round-trip-mismatch"` y metadata de longitudes (`tests/support/b103_clipboard.py:186-210,246-252`). El clasificador prefiere ese stage y conserva fallback seguro (`tests/test_b103_clipboard_windows.py:188-206`). El control directo ejecuta `_probe_once()` con boundaries inertes y reutiliza el stage/metadata reales (`tests/test_b103_e5_safety.py:46-72`); el brazo outer hace lo mismo antes de atravesar `test_runner_clipboard_probe()` (`:278-292`). Ya no depende de reproducir manualmente coma o punto y coma, y la salida contiene sólo stage/longitud.

## Redacción actual revisada, sin editarla

- `E5-fix2-disclosure.md:7-13` describe correctamente las intenciones de outer, `_ProbeDetail`, XML y transporte. Su afirmación de **“censo completo”** en `:9`, y el resumen `missing=[]` en `:42-49`, quedan refutados por D-06: el censo estático no cubrió todos los payloads reales añadidos a las seis familias.
- Sus comprobaciones se declaran estáticas y no dinámicas (`:32-51`); no las he reinterpretado como el 164/2 posterior. El 164/2 procede únicamente de la comunicación del orquestador.
- La reserva de D-03 en `:59-67` sigue siendo pertinente para el archivo local: el launcher no es transcript ni JUnit. La ejecución final comunicada mejora el estado dinámico, pero no archiva sus bytes.
- La divulgación previa `E5-final-review-disclosure.md` describe el estado anterior a fix2; este informe la sustituye para el árbol actual sin modificarla.

## Puertas separadas y límites

- No hay veredicto WinCI real. Las rutas y el workflow escritos no se convierten en ejecución por el 164/2 Linux.
- AT-I1b-8 permanece manual y **no verificada**: el manifiesto conserva su nodo, razón y categoría `manual` (`tests/support/b103_winci_manifest.json:359-364`), y el gate mantiene esa única excepción (`tests/support/b103_winci_gate.py:260-264`).
- No se ejecutaron mutantes de producto. Los artefactos estáticos/self-tests del harness no son mortalidad de producto.
- La full de seis familias y leyes sigue en ejecución en otro clon; no declaro su resultado ni sustituyo su evidencia por la selección 164/2.
- Para cambiar esta área a GO deben cerrarse D-06, D-03 y la regresión D-04 sobre el árbol resultante. WinCI, AT-I1b-8 y mutantes continúan como puertas independientes.
