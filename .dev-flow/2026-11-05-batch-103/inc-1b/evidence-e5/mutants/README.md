# Runner mecánico E5 — Inc 1b

Estado: **listo para validación y ejecución posterior en copias Linux; 0/71 mutantes de producto ejecutados**.

## Contenido

- `manifest.json`: baseline `0d4d4e7c800b27040769a1a10117e62884cc7326`, 71 mutantes, anchors `old`/`new`, node IDs completos y los 19 skips nominales.
- `run_mutants.py`: runner Linux aislado y self-test del harness.
- `validate_manifest.py`: validación estática, cruce con el plan original y colección de los cuatro archivos sin ejecutar sus tests.
- `linux/`: transcripts y reportes de la validación realizada.

Conteos: GA 16 + GT 8 + GQ 15 + GC 19 + GN 9 + GW 4 = 71. Hay 67 L, de los cuales 66 son ejecutables y GC-C14 está pendiente; los cuatro GW son WinCI-only. Las ocho correcciones contienen 23 expansiones por fila (19 node IDs distintos). Las 60 rutas abreviadas se resuelven como `app.py` → `s19_app/tui/app.py` (40) y `os_clipboard_input.py` → `s19_app/tui/os_clipboard_input.py` (20).

## Validación ya ejecutada en Linux

Desde este directorio, con el Python `s19ci` y un checkout pristine del hash fijado:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 <S19CI>/bin/python -I -B \
  validate_manifest.py --repo-root <TREE> --collect --output <OUT>/static

PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 <S19CI>/bin/python -I -B \
  run_mutants.py self-test --work-dir <OUT>/self-test
```

La primera orden sólo hace análisis estático y `pytest --collect-only`; no ejecuta tests de producto ni mutantes. La segunda usa únicamente `sample.py`/`test_sample.py` desechables y debe observar KILLED, SURVIVED, CRASH y BAD, comprobar restores por SHA-256 y dejar cada fixture verde tras restaurar.

## Ejecución posterior de mutantes

Requisitos: Linux, `<TREE>` limpio y detached en el hash fijado, directorio de trabajo nuevo/vacío fuera de `/tmp` si falta espacio, y ningún display/clipboard del operador. El runner nunca debe apuntar al árbol de integración.

```bash
# Sólo admisión pristine, una batería completa por grupo seleccionado.
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 <S19CI>/bin/python -I -B \
  run_mutants.py run --source-repo <TREE> --work-dir <OUT>/baselines \
  --baseline-only --groups GA,GT,GQ,GC,GN

# Batería completa L; registra GC-C14 como BAD/pendiente y devuelve 1 mientras lo esté.
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 <S19CI>/bin/python -I -B \
  run_mutants.py run --source-repo <TREE> --work-dir <OUT>/all --all

# Selección acotada.
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 <S19CI>/bin/python -I -B \
  run_mutants.py run --source-repo <TREE> --work-dir <OUT>/one --only GA-A04
```

Cada grupo clona una copia pristine y ejecuta una sola admisión de 141 nodos: deben obtenerse 122 passed y los 19 skipped exactos declarados en el manifiesto. Cada mutante usa otra copia, con HOME/TMP/XDG/LOCALAPPDATA propios, `DISPLAY` y `WAYLAND_DISPLAY` sin definir, stdin cerrado, `-B`, `PYTHONDONTWRITEBYTECODE=1` y pytest sin cacheprovider.

Para cada mutante ejecutable:

1. Los node IDs objetivo pasan antes del cambio y su conjunto JUnit coincide exactamente con el manifiesto.
2. `old` aparece exactamente una vez en todo el archivo; se hace un único `replace` y se registra `applied_count=1`. Cero, múltiples o no-op es BAD antes de escribir.
3. Se ejecutan los mismos node IDs con timeout externo y cancelación del grupo de procesos.
4. Se restauran los bytes originales, se comprueba SHA-256, se exige ausencia de bytecode nuevo, el árbol tracked queda limpio y los objetivos vuelven a pasar.

Veredictos: KILLED = assertion failure en el conjunto completo; SURVIVED = todos pasan; CRASH = error, colección rota, señal o timeout; BAD = parche/selección/baseline/restore/harness inválido o cualquier skip. Un timeout, skip o fallo de colección nunca es KILLED.

## Bloqueos deliberados

- **GC-C14:** no se aplica hasta disponer de una cota externa concreta de tiempo y workers/iteraciones, captura `override/tail` al alcanzarla y cancelación del árbol. El runner devuelve BAD con `applied_count=0`; un timeout desnudo no cierra este bloqueo.
- **GW-W01–W04:** el runner Linux los rechaza. Requieren el ejecutor WinCI aislado y no convierten sus skips Linux en muertes.

Los resultados futuros se escriben por grupo/ID en `result.json`, con `baseline.json` por grupo y `summary.json` agregado. Ninguno de esos resultados existe todavía: los reportes actuales sólo certifican la mecánica y la colección estática.
