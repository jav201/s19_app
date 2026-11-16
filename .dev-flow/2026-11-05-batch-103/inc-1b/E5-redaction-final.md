# E5 — redacción final de artefactos actuales

## Alcance y resultado

Se aplicó el redactor sobre los artefactos E5 actualmente presentes, incluidos `final-targeted.txt`, `final-targeted-junit.xml` y los nuevos launchers. No se editaron tests, producto, workflow, E3/E4 ni evidencia de otros incrementos; no hubo mutaciones Git. No ejecuté pytest, probes de producto, clipboard, PowerShell ni leyes.

Resultado de la mecánica actual: **PASS_WITH_DECLARED_CONTROL_EXCEPTIONS**. Al cierre, **no queda ningún hit nuevo E5 detectado fuera de las excepciones declaradas**. Esto no anticipa el resultado de una ley que no ejecuté ni cubre transcripts que todavía no se hayan incorporado.

## Corrección del self-census

`evidence-e5/redact_e5.py:220-222` ya no contiene la IP sintética completa. El ejemplo RFC1918 se construye dinámicamente uniendo la representación ASCII de sus cuatro octetos numéricos.

El known-present se conserva: **15/15 casos**, incluida la sustitución de IPv4 privada y la comprobación de que el placeholder no vuelve a ser detectado. Una búsqueda independiente del literal anterior en todo `evidence-e5`, incluido el propio source, terminó sin hits.

## Artefactos nuevos procesados

El censo previo encontró pendientes únicamente en dos archivos:

| Archivo | Sustituciones aplicadas |
|---|---|
| `final-targeted.txt` | 2 prefijos de hogar Unix. |
| `final-targeted-junit.xml` | 2 prefijos de hogar Unix + 1 `hostname` XML. |

Fueron **5 sustituciones efectivas**. El censo previo contó 10 hits de detector —4 hogares, 5 identidades derivadas y 1 hostname— porque las identidades contenidas en esas rutas se contabilizan también por separado.

Los nuevos `run_e5_final_targeted.py` y `run_e5_law_failures.py` fueron incluidos en el censo y en el manifest raíz; no necesitaron cambios de contenido. Los demás launchers presentes también fueron recorridos.

## Censo final y excepciones

`evidence-e5/redaction-census.json` registra:

- 156 archivos revisados recursivamente.
- 2 archivos modificados en esta pasada y 5 sustituciones.
- 0 archivos omitidos por contener NUL.
- 0 residuos posteriores fuera de excepciones.
- 15/15 controles known-present.
- 8 ocurrencias permitidas en los mismos tres controles ejecutables ya declarados:
  - `matrix/contract_probe.py`: 5.
  - `quit/validate_routes.py`: 2.
  - `legacy/redaction_runtime_probe.py`: 1.

La exclusión estructural del propio redactor sigue documentada. No se añadió ninguna excepción nueva para `final-targeted`, launchers o el ejemplo IP dinámico.

Las búsquedas independientes posteriores no encontraron el literal sintético anterior, identidades conocidas, rutas personales Windows/WSL/Unix, nonces concretos, la familia de canarios redactada ni `hostname` XML crudo. Los placeholders y las ocho ocurrencias de control no se presentan como `0 hits` absoluto.

## Manifests y verificaciones

Se reconstruyeron los seis manifests. El manifest raíz pasó de 16 a 20 archivos para incluir los dos `final-targeted` y los dos launchers nuevos. La cobertura total del esquema directo por directorio es ahora **78 archivos**.

| Manifest | Archivos | SHA-256 almacenado |
|---|---:|---|
| raíz | 20 | `5ee760fa156f985f4e0b39537ef300925763b5b8675c40a69200b60cb6adbb27` |
| `legacy/SHA256SUMS.txt` | 8 | `e2cb121de3705e3c535d51c4b3be77c23959adec733748028089abc839db9b3b` |
| `matrix/SHA256SUMS.txt` | 22 | `bda39b7ba5edd017a8496d5fbd06420aaa0d800895f0c82d370f73e3143c94e5` |
| `mutants/SHA256SUMS.txt` | 5 | `ea65e0527b0918f5cd978628622b3f6d0269adeb086e9274a57884609404f0bd` |
| `quit/SHA256SUMS.txt` | 7 | `159f97ae9859c97a5b66f51e0af64c1016696da15e24bef07f1cad9bffaa3ed8` |
| `tail/SHA256SUMS.txt` | 16 | `0f4c3412f43b8630c55348ec8a6e0f1a09db4b601dd10e167f9a1d70e67e7134` |

Resultados exigidos:

1. `python -B evidence-e5/redact_e5.py --check` — **PASS**, `files=156 residual=0 exceptions=8`.
2. `python -B evidence-e5/refresh_manifests.py --check` — **PASS**, `manifests=6 files=78`.
3. Verificación independiente `sha256sum -c --quiet SHA256SUMS.txt` en los seis directorios — exit 0 para las 78 entradas.
4. Búsqueda de `__pycache__` bajo `evidence-e5` — ninguno.

## Archivos escritos en esta corrección

Cambios de contenido dentro de `evidence-e5/**`:

- `redact_e5.py`.
- `final-targeted.txt`.
- `final-targeted-junit.xml`.
- `redaction-census.json`.
- `SHA256SUMS.txt` raíz.

Los otros cinco manifests fueron reconstruidos y reverificados sin cambiar su hash de contenido. La única escritura fuera de `evidence-e5/**` es este informe, `E5-redaction-final.md`.

## Trabajo posterior pendiente

Los transcripts full/leyes adicionales todavía no estaban copiados. Al incorporarlos, el orquestador debe repetir:

```text
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/redact_e5.py
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/redact_e5.py --check
python -B .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/refresh_manifests.py --check
```

La primera orden aplica la redacción y actualiza censo/manifests; las otras dos son sólo lectura. El resultado de las leyes se registrará cuando se ejecuten en su fase autorizada.
