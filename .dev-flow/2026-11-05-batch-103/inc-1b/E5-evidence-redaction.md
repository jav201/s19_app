# E5 — corrección D-04 de redacción de evidencia

## Resultado y límites

Se aplicó la corrección D-04 dentro de `evidence-e5/**` y se creó este informe. No se editaron producto, tests, workflow, ledger, canon ni evidencia de otros incrementos; no hubo mutaciones Git. No ejecuté pytest, probes de producto, clipboard, PowerShell, WinCI, mutantes ni las leyes del proyecto.

El resultado mecánico es **PASS_WITH_DECLARED_CONTROL_EXCEPTIONS**: cero residuos detectados fuera de las excepciones escritas abajo. No significa `0 hits` absoluto, no es un veredicto WinCI y **no declaro resuelto el fallo heredado de redacción**: las leyes se ejecutarán después.

Los transcripts de la batería actual todavía no estaban copiados al aplicar esta pasada. El orquestador debe repetir el redactor al incorporarlos; la orden estándar ya vuelve a redactar, reconstruye manifests y los verifica.

## Mecánica modificada

- `evidence-e5/redact_e5.py`
  - Recorre recursivamente todos los archivos de texto por bytes, incluidos `txt`, `md`, `sh`, `py`, `patch`, `json` y `xml`; no descarta históricos ni fallos de transporte.
  - Cubre hogares Windows, rutas mixtas MSYS/WSL, `/mnt/<drive>/Users/<...>`, `/home/<...>` y `/Users/<...>`, asignaciones de cuenta/host, `hostname` XML e IPv4 privadas RFC1918.
  - Deriva identidades de esas superficies y las sustituye también cuando aparecen aisladas. Los patrones no contienen las identidades personales anteriores.
  - Sustituye canarios conocidos y nonces concretos con placeholders. Las asignaciones hostile en diffs quedan cubiertas.
  - Marca cualquier patch que haya necesitado redacción como copia histórica no aplicable. Los dos patches requeridos se marcan incluso en ejecuciones idempotentes posteriores.
  - Incluye censo sintético known-present, censo previo/posterior, modo `--check` de sólo lectura y veredicto con excepciones explícitas.
- `evidence-e5/refresh_manifests.py`
  - Reconstruye cada manifest desde los archivos actualmente almacenados, en vez de limitarse a actualizar líneas antiguas.
  - Añade el manifest raíz y conserva el formato de cobertura directa por directorio.
  - `--check` comprueba conjunto de archivos, duplicados, formato, orden y SHA-256 sin escribir.
- `evidence-e5/matrix/redact_and_hash.py`
  - Se eliminó la tabla incrustada de identidades. El wrapper delega en el redactor común y mantiene su manifest histórico.

El propio `redact_e5.py` es la única exclusión estructural de escritura/escaneo: contiene las definiciones de detectores y entradas sintéticas del self-census que se autoemparejarían. Está explícitamente declarado en `redaction-census.json`; no contiene las antiguas identidades incrustadas.

## Censo y conteos

El censo detallado quedó en `evidence-e5/redaction-census.json`.

- **Known-present sintético:** 15/15 casos pasaron. Cada detector produjo una sustitución y no volvió a reconocer el resultado como pendiente. Incluye Windows, MSYS/WSL, Unix, cuenta/host, XML, IPv4 privada, nonce y familias de canarios.
- **Known-present real previo:** 24 hits de detector fuera de excepciones: 10 de canarios, 6 de identidades derivadas, 7 prefijos de hogar y 1 coincidencia IPv4 inicial. Los prefijos/identidades y la ruta MSYS/WSL se solapan; no son 24 secretos independientes.
- **Sustituciones aplicadas:** 19 en 8 artefactos: 10 canarios, 6 prefijos de hogar, 2 cabeceras de patch y 1 coincidencia IPv4 inicial. La última fue posteriormente reclasificada como versión de kernel; véase la incidencia declarada.
- **Known-absent final:** `REDACTION_CHECK PASS files=152 residual=0 exceptions=8`. El primer barrido aplicado cubrió 151 archivos; el control final cubre también el nuevo manifest raíz y excluye el censo generado y el propio redactor.
- **Archivos binarios omitidos por NUL:** 0.
- **Residuos de identidades conocidas, nonces y la familia de canarios redactada:** 0 en las búsquedas independientes.
- **Rutas personales Windows/WSL/Unix detectadas al cierre:** 0. Una coincidencia adicional en prosa se revisó y era el texto `cuentas/home/host`, no una ruta; el límite del patrón evitó redactarla.

No se usa una regla genérica de email: produjo falsos positivos con decoradores en patches y con cuatro formas email-like que son parámetros sintéticos de nodeids históricos. Esos nodeids se conservan para no romper su correlación; no son identidades personales ni se contabilizan como canarios de clipboard.

## Archivos redactados por la pasada automática

| Archivo | Sustituciones | Resultado |
|---|---:|---|
| `integration-pre-ci.patch` | 2 | 1 canario + cabecera de copia redactada no aplicable. |
| `matrix/integration-e5-fix.patch` | 10 | 9 canarios + cabecera de copia redactada no aplicable. |
| `legacy/REPORT.md` | 1 | Coincidencia IPv4 inicial; corrección de precisión documentada abajo. |
| `tail/E5-FIXES.md` | 1 | Prefijo de hogar WSL. |
| `tail/linux-tail-e5-fixes-transport1.txt` | 1 | Prefijo de hogar WSL en fallo histórico de transporte. |
| `tail/linux-tail-e5-fixes-transport4.txt` | 1 | Prefijo mixto Windows/MSYS/WSL en fallo histórico. |
| `tail/linux-tail-e5-fixes.txt` | 1 | Prefijo de hogar WSL. |
| `tail/run_linux_tail_e5_fixes.sh` | 2 | Prefijos WSL y Unix. |

Los dos patches conservan su histórico y sus verdicts, pero sus primeras cuatro líneas ahora declaran `REDACTED-EVIDENCE-COPY`, `APPLICABLE: false`, `DO-NOT-APPLY` y `HISTORICAL-COPY` (`integration-pre-ci.patch:1-4`, `matrix/integration-e5-fix.patch:1-4`). No deben usarse con `git apply`.

También se actualizó `matrix/REPORT.md:49,52` para describir la copia redactada no aplicable y el placeholder `<HOST>` actual. No se cambió ningún verdict.

## Excepciones conservadas y justificadas

Hay **8 ocurrencias de canarios** retenidas en tres archivos de código de control. No se cuentan como ausencia ni se ocultan en el censo:

| Archivo | Ocurrencias | Justificación |
|---|---:|---|
| `matrix/contract_probe.py` | 5 | Controles ejecutables de mismatch, probe y salida del gate. |
| `quit/validate_routes.py` | 2 | Control ejecutable de redacción del probe en las rutas QUIT. |
| `legacy/redaction_runtime_probe.py` | 1 | Control ejecutable LEGACY de redacción. |

Las excepciones son sólo para canarios: rutas, cuentas, hosts e IP siguen redactándose en esos archivos. El self-census sintético del propio redactor se documenta por separado y no forma parte de estas ocho ocurrencias.

## Incidencia de precisión declarada

La primera regla IPv4 era demasiado amplia y reconoció como IP una versión de kernel en `legacy/REPORT.md:50`. Se corrigió el detector para aceptar únicamente RFC1918 y se añadió un known-present específico.

No fue posible recuperar el literal original de esa versión de forma verificable: los candidatos comprobados no reprodujeron el SHA-256 histórico, ni siquiera con variante CRLF. En consecuencia, la línea conserva `<KERNEL_VERSION>-microsoft-standard-WSL2`, no una versión inventada ni una IP atribuida incorrectamente. Este placeholder queda declarado y no altera el resultado de tests ni el verdict histórico del informe.

## Manifests y verificación de bytes almacenados

Se reconstruyeron seis manifests: el nuevo `evidence-e5/SHA256SUMS.txt` y los cinco ya existentes en `legacy`, `matrix`, `mutants`, `quit` y `tail`. Cubren **74 archivos directos** según el esquema histórico por directorio; el censo de redacción, en cambio, recorre recursivamente 152 archivos.

| Manifest | Archivos | SHA-256 del manifest almacenado |
|---|---:|---|
| raíz | 16 | `d6b3f3a22f6743aad3a6939b23e5ce18af19e27a59e94155824cd6e1c88f821c` |
| `legacy/SHA256SUMS.txt` | 8 | `e2cb121de3705e3c535d51c4b3be77c23959adec733748028089abc839db9b3b` |
| `matrix/SHA256SUMS.txt` | 22 | `bda39b7ba5edd017a8496d5fbd06420aaa0d800895f0c82d370f73e3143c94e5` |
| `mutants/SHA256SUMS.txt` | 5 | `ea65e0527b0918f5cd978628622b3f6d0269adeb086e9274a57884609404f0bd` |
| `quit/SHA256SUMS.txt` | 7 | `159f97ae9859c97a5b66f51e0af64c1016696da15e24bef07f1cad9bffaa3ed8` |
| `tail/SHA256SUMS.txt` | 16 | `0f4c3412f43b8630c55348ec8a6e0f1a09db4b601dd10e167f9a1d70e67e7134` |

Verificaciones realizadas, todas sobre mecánica de evidencia:

1. `python -B evidence-e5/redact_e5.py --check` — PASS, 152 archivos, 0 residuos fuera de excepciones, 8 ocurrencias permitidas.
2. `python -B evidence-e5/refresh_manifests.py --check` — `MANIFEST_VERIFY_RESULT PASS manifests=6 files=74`.
3. `sha256sum -c --quiet SHA256SUMS.txt` desde cada uno de los seis directorios — exit 0 para las 74 entradas, independiente del verificador Python.
4. Búsquedas independientes de identidades anteriores, rutas personales, nonces y canarios redactados — sin residuos; excepciones contadas aparte.
5. Búsqueda de `__pycache__` bajo `evidence-e5` — ninguno creado.

## Inventario completo de escrituras

Dentro de `evidence-e5/**` se modificaron o crearon 19 archivos:

- 3 de mecánica: `redact_e5.py`, `refresh_manifests.py`, `matrix/redact_and_hash.py`.
- 8 redactados automáticamente, enumerados en la tabla anterior.
- 1 documentación adicional: `matrix/REPORT.md`.
- 1 censo nuevo: `redaction-census.json`.
- 6 manifests: el nuevo manifest raíz y los cinco existentes reconstruidos.

La escritura 20 y única fuera de ese árbol es este informe, `E5-evidence-redaction.md`.

## Paso pendiente del orquestador

Al copiar los transcripts de la batería activa, ejecutar desde la raíz del repositorio:

```text
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/redact_e5.py
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/redact_e5.py --check
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/refresh_manifests.py --check
```

La primera orden redacta, genera un censo nuevo, reconstruye los seis manifests y verifica sus hashes. Las dos siguientes son sólo lectura. Después deben ejecutarse las leyes en su fase autorizada; esta corrección no anticipa su resultado.
