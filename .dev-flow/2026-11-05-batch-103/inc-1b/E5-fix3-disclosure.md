# E5 fix3 — Carril C: censo AST independiente de divulgación

Base: HEAD `305e5892` más el working tree integrado. Alcance exclusivo: `tests/support/b103_artifact_safety.py`, `tests/test_b103_winci_gate.py` y este informe nuevo. Se conservaron el trabajo previo y los nodeids de las seis familias; no se editó ninguna de esas fuentes.

## 1. Qué cambió

D-06 queda corregido en implementación mediante dos cambios distintos:

1. El escáner incorpora los payloads reales señalados por la revisión en las familias `transport-cr`, `transport-crlf`, `powershell-read` y `powershell-write`, además del hostile con LF final. El censo AST descubrió también valores reales aún no declarados y ahora cubiertos por `external-round-trip`, `xml-secret`, `paste-payload` y `os-state`. Hay **18 familias**, cada una con known-bad raw/prefix/repr/escape/XML sobre transcript y JUnit: **180 combinaciones**.
2. Se eliminó la comparación de dos tablas manuales. `tests/test_b103_winci_gate.py` deriva ahora los candidatos desde el AST de las seis rutas de `gate.EXPECTED_FILES`. Exige que cada candidato esté explícitamente declarado y que `safety._scan_text()` detecte sus cinco formas. Un known-present sintético, ausente del escáner, demuestra que el derivador encuentra y señala un payload no declarado.

### Regla de derivación

- Resuelve constantes `SEED*`/`HOSTILE*`/`SECRET*`, payloads `P*` compartidos, imports del helper y asignaciones cuyo nombre contiene `payload`.
- Examina el argumento literal de `other_program_write`, `_assert_log_excludes` y `_no_secret`, valores con CR y familias `powershell-read`/`powershell-write`.
- Resuelve concatenación y multiplicación estáticas, ámbitos locales/cierres, aliases de imports y bucles `for` sobre tuplas/listas literales. En pares etiqueta/payload selecciona el segundo elemento, no la etiqueta.
- Los mensajes de diagnóstico `NUL_*` no se clasifican como payloads por su nombre. La primera pasada detectó esa sobreinclusión y se corrigió la regla, no se añadieron mensajes al escáner.
- Exclusiones explícitas y mínimas: expresiones dinámicas no resolubles, cadenas vacías o sólo whitespace, valores de menos de 4 caracteres y payloads generados de más de 256 caracteres. Estas exclusiones impiden censar fragmentos triviales y los grandes corpus de estrés; no se afirma cobertura AST de esos casos.

Cada valor derivado debe estar registrado literalmente en `CONTROL_CANARIES`; después se comprueba detección raw/prefix/repr/escape/XML. El conjunto esperado no se obtiene de `CONTROL_CANARIES` ni de una segunda lista manual. Los diagnósticos de fallo incluyen sólo forma, origen y longitud, no el contenido del payload.

## 2. Archivos modificados

- `tests/support/b103_artifact_safety.py` — valores reales añadidos y nuevas familias de escaneo.
- `tests/test_b103_winci_gate.py` — derivador AST, oráculo de declaración/formas, known-present y 180 known-bad de familia/forma/superficie.
- `.dev-flow/2026-11-05-batch-103/inc-1b/E5-fix3-disclosure.md` — este informe.

## 3. Cómo probar

En el clon Linux EXACTO, sin cambiar el árbol:

```bash
python -m pytest -q tests/test_b103_winci_gate.py
```

El censo debe terminar sin omisiones; el known-present debe encontrar el valor sintético y clasificarlo como `declaration` faltante. Las 180 combinaciones known-bad deben producir `CONTROL_CANARY` y salida redactada.

## 4. Resultados de verificación

No ejecuté pytest, tests, colección pytest, probes, producto, PowerShell, clipboard, workflow, baterías ni mutantes. Las comprobaciones fueron compilación y análisis AST de sólo lectura; el known-present se evaluó en memoria, sin crear archivos.

Primera pasada del derivador sobre las seis fuentes:

```text
AST census values=33 misses=5
```

Dos diferencias eran mensajes `NUL_*` incorrectamente clasificados; tres eran payloads reales no declarados. Tras corregir la regla y completar el escáner:

```text
AST census values=31 misses=0
Known-present synthetic AST discovery OK; undeclared payload remains visible to census
Declared families=18
AST census values=31; declared families=18; known-bad surface cases=180
tail-cr: AST present + scanner declared
tail-crlf: AST present + scanner declared
windows-read-full: AST present + scanner declared
windows-read-first-line: AST present + scanner declared
windows-read-literal: AST present + scanner declared
tests/support/b103_artifact_safety.py: compile/whitespace OK
tests/test_b103_winci_gate.py: compile/whitespace OK
Six-family manifest test-name surfaces unchanged: [51, 8, 13, 31, 28, 2]
git diff --check -- <dos archivos Python>: exit 0
```

Los cinco valores señalados por la revisión tienen orígenes AST en `clipboard_tail.py:1253/1421` y `clipboard_windows.py:2309-2311/2371`. Estos resultados son estáticos; no son un PASS de pytest ni evidencia WinCI.

## 5. Riesgos

- El censo deliberadamente no afirma cubrir payloads construidos sólo en runtime, f-strings no resolubles, valores triviales de menos de 4 caracteres ni corpus generados de más de 256 caracteres. Ampliar esas clases requiere otra regla y oráculos de falsos positivos.
- Algunos controles contienen caracteres inválidos para XML 1.0 y pueden añadir `JUNIT_XML_UNREADABLE`; la exigencia sigue siendo la presencia de `CONTROL_CANARY` y la ausencia del valor en diagnósticos.
- La parametrización known-bad usa las familias declaradas, pero la completitud de esa población ya no depende de ella: el AST independiente es la barrera contra omisiones futuras.
- No hay resultado dinámico de este incremento ni veredicto WinCI, de mutantes o de aceptación manual.

## 6. Pendientes

- El orquestador debe repetir la selección en el clon EXACTO y archivar stdout/stderr/JUnit aplicables.
- D-03, D-04, WinCI real, mutantes y AT-I1b-8 permanecen fuera de este carril y no se cierran por este informe.

## 7. Siguiente tarea

**Validación orquestada de D-06:** ejecutar `tests/test_b103_winci_gate.py` en el clon Linux EXACTO y conservar sus artefactos para revisión independiente.
