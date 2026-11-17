# Transformación e integridad de las copias

## Fuentes y alcance

Se archivaron cinco ejecuciones completas:

- `run-35fabb25/`: commit `35fabb25c42d752216433c095eb0d29024027294`, tree `048519b1229500912c2a65dd2b4c4f21ef70aa5f`.
- `run-795779ad/`: commit `795779add81875976ac3651f8862498426d45abf`, tree `090f2ece76f75d517a16416508273de96dd0da72`.
- `run-33028542/`: commit `3302854210a8a62637c37f9d59745d70ae8c8a2a`, tree `2153727b91759626caae028068ee85933d99fa61`.
- `run-85ed7210/`: commit `85ed72102479585728b7dd8210b98b8d7639eef9`, tree `280ec19ef3e2c547d743eb24f1f0b06523537941`.
- `run-13b1e522/`: commit `13b1e52257b381a4a091e253b49dd9b58aaf0fcd`, tree `4e134bd2f08b3212e2b15515051b7aedf5a8b6c5`.

Cada paquete incluye main/serial JUnit y transcript, `environment.txt`, `completion.txt`, `main-exit.txt`, `serial-exit.txt`, `full-suite-exit.txt` y un `MANIFEST.tsv` de sus nueve artefactos.

Los probes se almacenan bajo `probes/`:

- `functional/`, `visual/`, `a2l/`, `residual/` y `new2/`: JUnit, logs, comparaciones y selecciones base/head/control.
- `final-timing/`: comparación, JUnit/log/run y listas base/head/control; conservado sin duplicar.
- `last23/`: 25 artefactos esenciales de los 23 nuevos de 330.
- `last13/`: 25 artefactos esenciales de los 13 nuevos de 85ed.
- `last18/`: 38 artefactos esenciales de los 18 nuevos de cierre, incluidos head/base/control y la repetición head/base del instrumento.

No se copiaron árboles, homes, `tmp/`, `zq_local_g3/`, caches ni OUT masivos. Los originales permanecen fuera del repositorio y no fueron modificados.

## Transformación aplicada sólo a las copias

1. Lectura de bytes originales y SHA-256 antes de cualquier cambio.
2. UTF-8 con reemplazo explícito de bytes inválidos, eliminación ANSI CSI/OSC y escapes residuales, normalización CRLF/CR a LF.
3. Eliminación de espacios/tabs finales y líneas blank adicionales al EOF.
4. Sustitución de rutas personales —incluidas formas simple, doble y cuádruple escapadas—, cuentas, hosts, IP y UNC/extended Windows por placeholders XML-safe como `[USER_HOME]`, `[ACCOUNT]`, `[HOST]`, `[IP]`, `[HOME]`, `[UNC]` y `[WIN_PATH]`. Los UNC ficticios de fixtures no son endpoints reales.
5. SHA-256 de la copia almacenada.

No se editaron nodeids, estados, conteos ni firmas para cambiar verdicts. La normalización ANSI permite parsear los JUnit almacenados; los hashes originales auditan los bytes anteriores.

## Manifests y comparaciones

`MANIFEST.tsv` contiene `stored_path`, `source_ref`, `original_sha256` y `stored_sha256`. Los manifests por corrida y por `last23`/`last13`/`last18` usan las mismas columnas. Los artefactos generados se identifican como `generated-from-archived-junit` o `generated-record`.

- `comparison-35fabb25-795779ad.tsv`: 522→372, 170 fixed, 352 persistent, 20 new.
- `comparison-795779ad-33028542.tsv`: 372→372, 23 resolved, 349 persistent, 23 new.
- `comparison-33028542-85ed7210.tsv`: 372→363, 22 resolved, 350 persistent, 13 new.
- `comparison-85ed7210-13b1e522.tsv`: 363→364, 17 resolved, 346 persistent, 18 new.

Todas las comparaciones tienen una fila por nodeid y se generaron desde JUnit normalizados almacenados. La verificación comprende hashes originales/almacenados, parseo XML, censos, escaneo estático y `git diff --check`. Ningún archivo del clon de cierre se modificó durante el empaquetado.
