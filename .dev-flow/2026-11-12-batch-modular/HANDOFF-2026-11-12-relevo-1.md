# HANDOFF relevo-1 — s19 batch-modular + cierre b103 (2026-11-12 23:25 CST)

Orquestador saliente: Opus 5.5 (sesión principal). el operador está DORMIDO y delegó la orquestación completa. Tú eres el orquestador ahora. Chat en español; código, commits y registros en inglés.

## 0. Reglas que debes seguir (léelas antes de actuar)

1. **Relevo al 55 %:** cuando tu contexto llegue a ~55 %, escribe un handoff como éste (estado, rutas absolutas, procesos corriendo, siguiente paso exacto, ESTAS MISMAS REGLAS) y lanza tú mismo la siguiente sesión desde `C:\Users\<user>\clde`:
   `claude --bg --permission-mode auto --model opus -n "s19-modular-relevo-<n+1>" "Lee y ejecuta el handoff <ruta absoluta del handoff nuevo>"`
   Después deja de orquestar. Memoria: `handoff-al-55-por-ciento.md`.
2. **Modelos:** clasificar ANTES de cada lanzamiento (memoria `modelos-por-tarea-devflow.md`): texto fijado/registros/mutantes → `deepseek/deepseek-flash` thinking off|low; implementar desde spec, tests desde casos → `deepseek/deepseek-v4-pro` thinking medium|high; necesita herramientas del arnés → agente Sonnet; diseño, revisión, correcciones de diseño, integración difícil → Opus. **Si DeepSeek responde sin cuota/tokens → Kimi K2.8** (`kimi -m kimi-code/kimi-for-coding -p "<brief>"` en el worktree; memoria `kimi-via-cli.md`).
3. **DeepSeek:** `timeout 3600 pi -p --no-session --model deepseek/deepseek-v4-pro --thinking high "<brief>" < /dev/null > <log> 2>&1`, una unidad por llamada, en su propio worktree; vigía con `bash ~/clde/scripts/watch-pi.sh <log> <worktree> <label> none` (sale STALLED a los 20 min sin cambios). Nunca esperar en silencio. Verificar SIEMPRE su diff (en esta sesión: dejó un JSON con CRLF y un validador con constantes viejas).
4. Toda `description` de tarea/agente en segundo plano empieza con `[modelo · esfuerzo]`.
5. **Nada de push** a ningún remoto sin OK de el operador. El push a WinCI de Inc 1b NO está autorizado todavía.
6. **Pruebas solo en Linux** (runners CachyOS; memoria `<runner-hosts-note>.md`): laptop `<laptop>` (8 núcleos, python `/data/miniconda3/envs/s19ci/bin/python`), rtx `<rtx>` (16 núcleos, `~/miniconda3/envs/s19ci`). Shell fish → `bash -lc '…'`. HOME aislado con basename `zq_iso_user` (nunca `home`/`neutral`), stdin cerrado, `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`. En la PC Windows solo lectura/AST/py_compile; nada de portapapeles real.
7. dev-flow (skill `dev-flow`): `steps.log` una línea por etapa con modelo; commit por etapa; `git add <carpeta>` + `git add -f <ruta>/steps.log`; revisar `git status`; nunca `git checkout -- .`/`reset --hard`/`clean`. Horas de `date`, nunca tecleadas.
8. Decide y registra (memoria `confio-en-tu-juicio-decidir-y-registrar.md`); para dudas de producto visibles al operador, anota la pregunta para el operador y sigue con lo demás.
9. Scratch de runners: borrar al terminar con lista explícita de directorios (rtx `/tmp` es tmpfs 16 GB).

## 1. Estado al relevo

### batch-modular (prioridad de el operador: modularizar para paralelizar)
- Worktree `C:\Users\<user>\Github\s19_app-modular`, rama `batch-modular`, HEAD `001bb2e6`. Base de producto `4f721985` (= `287b9dc3` en producto).
- G1 aprobado: A en todo (`design/G1-verdict.json`, página `design/plan-g1.html`, artifact https://claude.ai/artifact/EZWxAXAc5QgBMCUDvq8kn2).
- **E1+E2 HECHOS** (Opus): `01-requirements.md` (42 filas R-MOD), `02-test-cases.md`, `E2-module-graph.md`, `design/{module-map.json,test-patch-census.json,interfaces.md,hazards.md,spec-move.md,spec-verify.md,spec-retarget-tests.md}`, tools `tools/modularize/{census.py,plan_map.py,test_patch_census.py,run_suite.sh}`.
  - app → paquete: `core` (1281) + `deps` + `shared` + `shared_io` + 18 mixins; screens_directionb → 8 módulos. D1: 37 nombres app + 1 sdb (151 sitios de patch en tests). Hazards ruled H-1…H-23 (handlers duplicados por MRO, super(), reactives, copy/quit quedan en core; `CSS_PATH` → `"../styles.tcss"`; ids de `test_universal_paste` cambian → comparar esa familia como grupo, regla B4).
  - Tests que leen fuente: 34 archivos / 81 funciones en 4 grupos (7/10/9/8 archivos); primero el helper `tests/support/package_source.py`. Defecto preexistente H-23 (`test_at_b94_08…` lee el archivo equivocado) se arregla en grupo 3.
- **Suite ANTES corriendo** en rtx: `~/work/zq-mod/before/` (`suite.txt`, al final `junit.xml`, `outcomes.tsv`, línea `SUITE_DONE`). Lanzada 22:59 con `-n 12`; iba en 53 % a las 23:22. Los ~13 brazos con cota de tiempo pueden fallar bajo xdist: compararlos re-corriendo en serie en ambos árboles.

### Inc 1b (batch-103) — en E5
- Integración: `C:\Users\<user>\Github\s19_app-b103-inc1b-integration`, rama `b103-inc1b-integration`, HEAD `4f721985` (commits de esta sesión: `287b9dc3` preserva trabajo de Kimi; `4f721985` fallo B97-69 = no es regresión, 20/20 + 5/5 en head y base).
- Plan de mutantes actualizado en rama `b103-inc1b-mutplan` (`ce4b5732`, worktree `C:\Users\<user>\Github\s19_app-b103-inc1b-mutplan`): 73 mutantes (GC-C20/21 nuevos), validador PASS en Linux, self-test PASS. **Falta fusionarla a `b103-inc1b-integration`** (merge sin fast-forward forzado).
- **Mutantes L corriendo** en la laptop desde ~22:45: `~/work/zq-mut/GA-GT-GQ/` y `~/work/zq-mut/GC-GN/`, logs `~/work/zq-mut/*.log` (línea `EXIT=` al terminar; el runner escribe JSON por mutante en su work-dir). Esperado: GC-C14 BAD (pendiente por diseño), 4 GW WinCI-only. Al terminar: copiar resultados a `inc-1b/evidence-e5/mutants/linux/run-287b9dc3/`, correr `redact_e5.py` + `--check` y `refresh_manifests.py --check`, actualizar `VALIDATION.md`; SURVIVED → analizar (oráculo débil vs mutante equivalente) y decidir.
- Pendiente para el operador: OK del push a WinCI (fusionar en worktree limpio `C:\Users\<user>\Github\s19_app-b103-wci` rama `b103-wci-2`, push, seguir `clipboard-windows`, comparar con 17 fallos baseline). Luego ledger/canon/capturas/04-validation/review packet (handoff de Kimi §6: `.dev-flow/2026-11-05-batch-103/HANDOFF-2026-11-12-KIMI-INC1B-E5-EXACT-VALIDATION.md` en la integración).

### Inc 10 (batch-103)
- Rama `b103-inc10`, worktree `C:\Users\<user>\Github\s19_app-b103-inc10`, HEAD `4a02073a`: G2 aplicado, E2 (20 nodos, lint 0), E3 FAIL → fallado y corregido (R-PE-EXPORT.17, R-HEX-EMIT-001.11, fixture x64u). **Estacionado**: su E4 se hace sobre la estructura modular. Preguntas O-1…O-6 para el operador DESPUÉS de la modularización (lista en `inc-10/E2-rulings.md` §4). Backlog E3-8 ALTA (S0 filtra nombre de cuenta).

## 2. Siguiente paso exacto (batch-modular)

1. **P0 en paralelo, tres worktrees desde `001bb2e6`** (`git worktree add -b mod-mover ../s19_app-mod-mover 001bb2e6`, ídem `mod-verify`, `mod-retarget`):
   - mover `tools/modularize/move.py` según `design/spec-move.md` → DeepSeek v4 Pro, thinking high.
   - verificador `tools/modularize/verify_identity.py` según `design/spec-verify.md` → **implementador independiente del mover**: agente Sonnet (o Kimi K2.8 si no hay Sonnet).
   - retargeter `tools/modularize/retarget_tests.py` según `design/spec-retarget-tests.md` → DeepSeek v4 Pro, thinking medium.
   Cada brief: solo su archivo (+ sus tests propios si la spec los pide), sin git writes, pegar la salida de aceptación de su spec.
2. Revisar los tres diffs (CRLF, constantes, alcance), fusionarlos a `batch-modular`; una revisión Opus (agente `code-reviewer`, una pasada) del mover + verificador.
3. Aplicar: rama `batch-modular-apply`; correr mover sobre el árbol; correr verificador (old = `4f721985:s19_app/tui/app.py` y `…/screens_directionb.py`); correr retargeter; commit del paquete generado. Si algo falla, corregir la herramienta, no el resultado a mano.
4. P1c: helper `tests/support/package_source.py`, luego 4 workers DeepSeek v4 Pro (grupos 1–4 de `design/hazards.md` H-12/H-13, archivos disjuntos) en paralelo, cada uno en su worktree; cada test adaptado conserva su control negativo (debe poder fallar).
5. P2: suite DESPUÉS en rtx con `tools/modularize/run_suite.sh <bundle> <rev> ~/work/zq-mod/after 12`; comparar `outcomes.tsv` con `before` (regla B4 para `test_universal_paste`); diferencias → re-correr en serie en ambos árboles; toda diferencia real se corrige en la herramienta o en el test adaptado.
6. E5: un revisor, una pasada (memoria `revisiones-al-minimo-version-pronto.md`); registros de cierre y review packet; commit. NO push.
7. Luego: plan de P3 (partir métodos > 40 líneas y módulos > 300, un worker por módulo, en paralelo), y Inc 10 E4 sobre la estructura nueva (re-extraer slice/anclas).
8. Mantener al día la memoria `s19-b103-estado.md` con commits y estado.

## 3. Lectura recomendada al empezar
`design/interfaces.md`, `design/hazards.md`, `design/spec-*.md`, `01-requirements.md` (este batch); memorias `handoff-al-55-por-ciento`, `modelos-por-tarea-devflow`, `vigilar-trabajos-en-segundo-plano`, `<runner-hosts-note>`, `deepseek-via-opencode`, `kimi-via-cli`, `s19-b103-estado`.
