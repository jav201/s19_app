# E5 fix — Carril D: WinCI gate y publicación de artefactos

Base: `305e5892` más los cambios no commitidos presentes. Se conservó el trabajo de los demás carriles; no se hicieron commits ni otras mutaciones Git. Este carril sólo modificó `.github/workflows/clipboard-windows.yml` y `tests/support/b103_winci_gate.py`, creó `tests/support/b103_winci_manifest.json`, `tests/support/b103_artifact_safety.py` y `tests/test_b103_winci_gate.py`, y añadió este informe.

Trabajo exclusivamente estático. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow, batería Linux ni mutantes. No declaro GREEN, resultado WinCI ni mutantes eliminados.

## Cambios y cierre estático de WG-01/WG-02/WG-03

### WG-01 — población y 108 obligaciones

`tests/support/b103_winci_manifest.json` fija la población completa sin importar módulos de test en runtime. Cada entrada contiene archivo, nombre de test e IDs de parametrización; `load_manifest()` compone y valida los nodeids en `tests/support/b103_winci_gate.py:112`.

- 256 testcases: 77 clipboard Windows + 37 clipboard matrix + 54 views + 31 tail + 28 quit + 29 acceptance matrix/manual.
- 108 obligaciones automatizadas, no confundidas con el total JUnit: 46 views + 25 tail + 9 quit + 28 AT.
- Cada obligación tiene correspondencia requisito → nodeid → lista de brazos internos. Esto incluye los cuatro brazos WinCI de R-TUI-043.13/101, la ruta PowerShell de /102, los cuatro armings de R-COPY.16/1 y los brazos modales de R-COPY.20/1…3.
- AT-I1b-8 está fuera de las obligaciones automatizadas y conserva su nodo manual independiente.

`audit_junit()` (`tests/support/b103_winci_gate.py:343`) exige una sola aparición de cada nodo esperado, rechaza nodos ausentes, duplicados o inesperados y exige `passed` para las 108 obligaciones. Los nodos auxiliares también tienen outcome esperado: passed, salvo las exclusiones explícitas del manifiesto.

### WG-02 — skips por identidad y razón exactas

Desapareció la autorización global por prefijo regex. Cada skip se contrasta por nodeid y razón completa; cualquier skip de una obligación es violación aunque empiece por `Linux`.

El manifiesto contiene exactamente:

- seis skips `linux-only`: R-COPY.2/4, R-COPY.7/8, R-PASTE.9/101…103 y R-PASTE.10/101;
- un skip `manual`: AT-I1b-8, con su razón íntegra y nodo exacto;
- 37 exclusiones heredadas `legacy-linux-h` de `test_b103_clipboard_matrix.py`, separadas de las seis anteriores, con razón exacta `Windows only`. Son los casos que ese archivo omite deliberadamente en Windows y forman parte de la población WinCI real de los seis archivos; no se ocultan dentro del conteo de seis.

Un skip permitido que pasa, cambia de razón o cambia de nodo también produce violación.

### WG-03 — AT canónicos e integridad JUnit

- Se validan los 28 IDs AT completos, su numeración T1/T2–P1/P2 y la partición exacta 14 P1 + 14 P2. Las 28 obligaciones AT deben estar passed, no simplemente presentes.
- Se reconcilian `tests`, `skipped`, `failures` y `errors` con los `testcase` observados, tanto para un `testsuite` como para suites directas bajo `testsuites` y el agregado raíz cuando existe.
- Se rechazan outcomes ambiguos, XML vacío/ilegible y población distinta de la esperada.
- Un `pytest_exit` distinto de cero es violación y conserva prioridad como código de salida, también si el manifiesto o XML es ilegible.
- `--validate-manifest` valida el oráculo independiente sin sustituirlo por colección pytest ni importar los seis módulos.

## D-03 — barrera fail-closed antes de upload

`tests/support/b103_artifact_safety.py` revisa transcript, JUnit y salida del gate antes de cualquier publicación:

- lectura como bytes y fallo ante ausencia, archivo vacío o JUnit ilegible; incluye vistas UTF-8 y UTF-16 cuando corresponde;
- canarios de control y seeds, incluidos hostile/OSC, con formas directa, `repr`, `unicode_escape`, JSON, entidades XML nombradas/decimales/hexadecimales y prefijos discriminantes;
- nonce del probe, tokens GitHub/AWS/JWT, Bearer, claves privadas, credenciales en URL y asignaciones de secretos;
- rutas personales Windows, WSL, Unix y macOS, incluidas formas escapadas/XML;
- diagnósticos sólo por artefacto, categoría e ID de regla, sin reproducir el valor detectado.

En `.github/workflows/clipboard-windows.yml`, el step de tests conserva `pytest_exit` mediante el gate y pasa los códigos al entorno del job. El escáner se ejecuta con `always()` después del gate. `actions/upload-artifact@v4` exige `steps.artifact_safety.outcome == 'success'` y `if-no-files-found: error`; por tanto, si el escáner falla no se suben transcript, JUnit, gate ni salida de seguridad. Un step final restaura el código preservado del gate. Un fallo funcional con artefactos limpios puede conservar evidencia; un fallo del escáner no la publica.

Esta barrera complementa, no sustituye, la prevención de divulgación en consola y los controles D-01/D-02 de los otros carriles.

## Controles añadidos

`tests/test_b103_winci_gate.py` contiene un JUnit sintético known-good de 256 nodos y controles known-bad para:

- nodo tail y nodo quit ausentes;
- AT renombrado y P2 ausente;
- duplicado no AT;
- skip de obligación con prefijo `Linux-only`;
- seis skips Linux-only, 37 exclusiones heredadas y AT-I1b-8 manual en el known-good, además de razón permitida alterada;
- cada contador JUnit `tests/skipped/failures/errors` inconsistente;
- XML vacío y malformed;
- pytest exit 7 con XML válido e ilegible;
- escáner known-good y canarios raw/repr/escape/XML tanto en transcript como en JUnit;
- credenciales y rutas personales directas/escapadas/XML, archivos ausentes/vacíos/malformed;
- cableado estático que impide upload sin éxito del escáner y ausencia de imports `tests.test_*` en el gate.

Estos tests están escritos pero **no fueron ejecutados** en este carril.

## Reconciliación del tally y verificación estática real

El tally Linux `160 passed + 96 skipped` implica **256 testcases**, no 218. La composición estática de los 96 skips Linux es 77 Windows-only + 4 WinCI-only tail + 14 AT P2 + 1 manual = 96. Para la ejecución WinCI esperada por el manifiesto, la partición estática es 212 passed + 44 skipped (37 legacy LinuxH + 6 Linux-only + 1 manual); no es un resultado observado.

Verificación realizada:

1. Script stdlib AST/JSON, sin importar tests: comparó manifest ↔ funciones/decoradores actuales. Resultado: `STATIC_NODEIDS_OK` para los seis archivos, conteos 77/37/54/31/28/29, cero faltantes/extras/duplicados y `STATIC_ALL_SIX_NODEIDS_OK total=256`. El primer extractor no resolvió el nombre `AT_CELLS`; se corrigió el extractor y se repitió la comparación completa.
2. Script stdlib JSON de invariantes: `STATIC_MANIFEST_OK 256 108`, skips `legacy-linux-h=37`, `linux-only=6`, `manual=1`, AT `P1=14/P2=14`, y obligaciones presentes exactamente una vez en la población.
3. `python -m py_compile tests/support/b103_winci_gate.py tests/support/b103_artifact_safety.py tests/test_b103_winci_gate.py`: terminó 0. Tras el último ajuste del test, su compilación individual también terminó 0.
4. `git diff --check` sobre los cinco archivos de código/configuración del carril: sin errores de whitespace; Git sólo informó la conversión LF→CRLF prevista para el workflow.
5. Los `.pyc` nuevos temporales del escáner y del test fueron eliminados. El `.pyc` preexistente del gate no se borró. No se eliminaron tests ni oráculos.

Queda pendiente la ejecución de los self-tests por el orquestador, la batería Linux integrada y el workflow Windows real. Sólo esas ejecuciones podrán aportar resultados de controles, WinCI o mutantes; este informe limita su conclusión al cierre estático de WG-01/WG-02/WG-03 y a la barrera D-03 implementada.
