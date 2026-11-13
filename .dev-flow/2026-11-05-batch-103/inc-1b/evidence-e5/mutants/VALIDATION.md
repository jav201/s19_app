# Validación Linux — mutant selectors

## Resultado final

Baseline fijado y comprobado en el clon aislado: `0d4d4e7c800b27040769a1a10117e62884cc7326`.

- `linux/static-final2/static-validation.json`: **PASS**. 71 mutantes/IDs únicos; grupos GA 16, GT 8, GQ 15, GC 19, GN 9, GW 4; 67 L + 4 W; 66 L ejecutables y cinco bloqueos declarados (GC-C14 + cuatro GW).
- 71/71 anchors aparecen exactamente una vez en el HEAD fijado. No hay rutas de producto ni alias de tests sin expandir en el manifiesto.
- Ocho filas corregidas, **23 expansiones por fila y 19 node IDs distintos**. `pytest --collect-only` de los cuatro archivos devolvió **141 nodos** y contiene todos los seleccionados.
- Manifiesto: **129 referencias de tests, 76 node IDs distintos y 57 funciones**. La comparación con `git show 0d4d4e7c:…/E5-mutant-plan.md` confirma que no se añadió ni eliminó ninguna función.
- Alias de producto confirmados: 40 `app.py` + 20 `os_clipboard_input.py` = 60. Inserción Q10 fijada entre `g` y `q`.
- Los tres controles corruptos del validador fueron rechazados: anchor inexistente, selector eliminado y baseline incorrecto.
- `linux/harness-self-test-final/self-test.json`: **PASS**. Fixtures desechables observaron KILLED, SURVIVED, CRASH y BAD; `applied_count=1` en los tres cambios aplicables, `applied_count=0` en el anchor ausente, todos los restores SHA-256 correctos, objetivos verdes tras restore y cero bytecode nuevo.
- `linux/empty-group-control.txt`: un grupo desconocido devuelve BAD exit 2; una selección vacía ya no puede producir un PASS vacío.

Alcance real: **0/71 mutantes de producto ejecutados, 0 tests de producto ejecutados, 0 accesos a clipboard**. La colección importa los módulos de tests pero no ejecuta los tests. No se repitió la admisión 122 passed/19 skipped y no se ejecutó WinCI.

## RED del propio tooling conservados

1. `linux/static-validation-attempt1-import-red.txt`: `python -I` no resolvía el sibling `run_mutants`; se cambió a carga desde `__file__`.
2. `linux/static-validation-attempt2.txt` y `linux/static-attempt2/`: el validador contó 19 IDs distintos en vez de 23 expansiones y coleccionó todo el repo (8.237 nodos). Se fijó 23/19 y se limitó la colección a los cuatro archivos.
3. `linux/static-validation-attempt3.txt` y `linux/static/`: primera validación PASS, antes del último ajuste del clasificador y del campo 19-distinct.
4. `linux/harness-self-test.txt` y `linux/harness-self-test-attempt1/`: pytest devolvió exit 4 para sintaxis rota y el runner la clasificó BAD. Tras una fase previa válida, ese resultado posterior al cambio se clasifica CRASH, nunca KILLED.
5. `linux/harness-self-test-attempt2.txt` y `linux/harness-self-test/`: self-test PASS previo al endurecimiento de selección; `linux/harness-self-test-final.txt` y `linux/harness-self-test-final/` contienen el PASS con el runner definitivo.

Las copias locales están redactadas con `<SCRATCH>`, `<S19CI>`, `<BASE_REPO>`, `<HOME>`, `<USER>` y `<RUNNER_IP>`. El bundle de transporte era temporal y no forma parte de la evidencia.

## SHA-256 de los bytes almacenados

- `manifest.json`: `30800c2fe65bc6444505b981e28a15e2d51ba9de576b3856d2aef1596336425d`
- `run_mutants.py`: `abf79bb2569d9c179c1cc584fb41189d2c713682e3a825f77ff429f28145b545`
- `validate_manifest.py`: `2ff157e8948e1fe72541ae83ebc177eecdcc0247ab6f31044c533f60057a1632`
- `linux/static-final2/static-validation.json`: `bd87302a72ee7e4da4c666adfd9f16d332abd74c4c343244da70806d7dd395b6`
- `linux/harness-self-test-final/self-test.json`: `43cace153e5cfcfd041f8852d9ed848f65345cfa7f5e65ba62e0793c12246dba`

Los hashes del manifiesto, runner y validador coinciden con los registrados dentro del reporte estático final.

## Pendiente

- Ejecutar la admisión pristine 122/19 una vez por grupo antes de cualquier mutante.
- GC-C14 permanece BAD/pendiente, sin aplicar, hasta tener cota de tiempo y workers/iteraciones con captura `override/tail` al alcanzarla.
- GW-W01–W04 permanecen fuera de Linux y sujetos al ejecutor WinCI aislado; su NO-GO no se altera aquí.

## Ejecución Linux de mutantes sobre 287b9dc3 (E5)

Evidencia en `linux/run-287b9dc3/` (redactada). Árbol de harness con `manifest.json` sha256 `2d96df60e7544885cbbc270e8ee4c87ffc7c8015c2c9e0dfb87b5f3656efd543` y `run_mutants.py` `23dd145ee0cd16d0c9dc9ad1d93f29b40fc865b917c4ef91be3abeb6383aaddb` (idénticos a los de la rama); `--source-repo` en `287b9dc3`; entorno aislado (HOME `zq_iso_user`, TMPDIR propio, `PYTHONDONTWRITEBYTECODE=1`, stdin cerrado, sin DISPLAY).

### Tabla final (69 mutantes L; los 4 GW son WinCI-only y no se ejecutaron aquí)

| Grupo | Baseline (123 passed / 19 skipped) | KILLED | SURVIVED | BAD / bloqueado |
|---|---|---|---|---|
| GA (16) | PASS | 15 | 1 (GA-A11) | 0 |
| GT (8) | PASS en la 3.ª corrida | 8 (GT-T06 en la corrida 4) | 0 | 0 |
| GQ (15) | PASS | 15 | 0 | 0 |
| GC (21) | PASS | 20 | 0 | 1 (GC-C14, bloqueado por diseño) |
| GN (9) | PASS | 9 | 0 | 0 |
| **Total (69)** | | **67** | **1** | **1 bloqueado** |

### Corridas y por qué hubo repeticiones

- **Corrida 1** (`run1-*`): GA/GQ/GC/GN PASS en ~1520–1580 s cada baseline. **GT: baseline BAD por timeout externo** (2400 s, `returncode=-15`, 0 passed/0 failed/0 skipped, progreso 85/141 en el transcript) y GN-N06..N09 **BAD por timeout de 180 s en el `pre`** (mismo 0/0/0, `returncode=-15`). Ambas son mediciones de tiempo, no veredictos de tests. El host estaba compartido (carga 13–17 en 8 núcleos, presión CPU `some` 55–60 %).
- **Corrida 2** (`run2-loaded-*`, timeouts 7200 s / 900 s, otra vez con el host cargado, carga 16–17): los baselines terminaron en ~4100 s con **9 failed / 114 passed / 19 skipped**, y el conjunto de nodos fallidos **distinto en GT y GN** (p. ej. `R-COPY.15/1` vs `/2`, `07_4` solo en GT, `09_1` solo en GN): fallos de aserciones sobre secuencia de notificaciones/escrituras de portapapeles dentro de la ventana de espera real de los tests. Baseline BAD, ningún mutante aplicado. Inestabilidad dependiente de carga, no un defecto reproducible de un nodo.
- **Corrida 3** (`run3-*`, host con carga ~2, timeouts 7200 s / 900 s): GT y GN baseline **PASS 123/19 con los 19 skips exactos**; GT 7 KILLED + 1 SURVIVED; GN-N06..N09 los cuatro KILLED.
- No se modificó ningún archivo del harness ni del manifiesto: los conteos y skips esperados (123/19) se cumplieron tal cual en las seis admisiones PASS. Solo cambiaron los argumentos `--timeout 900 --baseline-timeout 7200`.
- Los GN-N06..N09 **no** son los WinCI-only (esos son GW-W01..W04, no ejecutados en Linux); son mutantes L normales de texto/log de la ruta NUL.

### No-KILLED

| Id | Veredicto | Clasificación |
|---|---|---|
| GA-A11 | SURVIVED | **Equivalente.** Cambia `valid=False` por `valid=event.screen_offset == candidate.screen_offset` dentro de la rama cuya guarda es `event.screen_offset != candidate.screen_offset` (`app.py` `S19TuiApp.on_event`, rama `MouseMove`). Offset es una tupla con nombre: `==` y `!=` son complementarios y sin efectos laterales, así que la expresión siempre vale `False` en esa rama; no hay entrada que distinga el mutante del original. |
| GT-T06 | SURVIVED en la corrida 3 -> **KILLED en la corrida 4** | **Hueco de selección del manifiesto, corregido.** Con la selección original (`R-COPY.22/2`) el mutante sobrevivía; la sonda ad hoc `linux/run-287b9dc3/GT-T06-adhoc-selection-probe.txt` (no es veredicto del runner) mostró que `test_r_copy_13_empty_and_cancelled_gestures[R-COPY.13/9]` lo mata. Decisión del operador: añadir ese nodo a `tests` de GT-T06 y repetir. Corrida 4 (`linux/run-287b9dc3/run4-GT-T06/`): ver sección siguiente. |
| GC-C14 | BAD (bloqueado) | Pendiente por diseño: falta cota externa de tiempo y workers/iteraciones con captura `override/tail`; `applied_count=0`. |

### Corrida 4 — solo GT-T06 con selección corregida

- Cambio único en el manifiesto: `tests` de GT-T06 pasa de `[R-COPY.22/2]` a `[R-COPY.22/2, R-COPY.13/9]`; nada más del manifiesto ni del runner cambió. `manifest.json` sha256 `6a41d7c6702d9f7aa82d33b4cf04ec76f77ce458039f7af1e976ef5eb0aea47a`; `run_mutants.py` sha256 `23dd145ee0cd16d0c9dc9ad1d93f29b40fc865b917c4ef91be3abeb6383aaddb` (sin cambios).
- Comando: `run --source-repo <TREE en 287b9dc3> --work-dir <OUT> --only GT-T06 --timeout 900 --baseline-timeout 7200`, mismo entorno aislado de la corrida 3 (HOME `zq_iso_user`, TMPDIR propio, `PYTHONDONTWRITEBYTECODE=1`, stdin cerrado, sin DISPLAY). Carga del host durante la corrida: 0,5–1,5 (8 núcleos).
- Baseline GT: **PASS 123 passed / 19 skipped** (1416,59 s). Antes del cambio los dos nodos seleccionados pasan (2 passed); con el mutante aplicado (`applied_count=1`): `R-COPY.13/9` **failed**, `R-COPY.22/2` passed; restore SHA-256 correcto, sin bytecode nuevo.
- Veredicto: **GT-T06 KILLED** (`summary.json`: KILLED 1, SURVIVED 0, CRASH 0, BAD 0). Total Linux L: **67 KILLED, 1 SURVIVED (GA-A11, equivalente), 1 bloqueado (GC-C14)**.
- Evidencia: `linux/run-287b9dc3/run4-GT-T06/` (`summary.json`, `GT/baseline.json`, `GT/baseline-junit.xml`, `GT/baseline-pytest.txt`, `GT/GT-T06/result.json`); el `.log` del lanzador (`run4-GT-T06.log`) queda ignorado por git, igual que los anteriores.
- Redacción de la corrida 4: `redact_e5.py` reemplazó 44 ocurrencias en 5 archivos nuevos; `redact_e5.py --check` PASS (`files=304 residual=0 exceptions=8`). `redaction-census.json` se conserva como el censo de la redacción original (102 archivos); la pasada de la corrida 4 no lo reescribe, porque una segunda pasada sin cambios lo había sobrescrito con un censo vacío.
