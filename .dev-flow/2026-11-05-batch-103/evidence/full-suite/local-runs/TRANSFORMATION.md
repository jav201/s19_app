# Transformación e integridad de las copias

## Fuentes y alcance

Se archivaron dos ejecuciones completas previas:

- `run-35fabb25/`: fuente `<run-35fabb25-SOURCE>`, commit `35fabb25c42d752216433c095eb0d29024027294`, tree `048519b1229500912c2a65dd2b4c4f21ef70aa5f`.
- `run-795779ad/`: fuente `<run-795779ad-SOURCE>`, commit `795779add81875976ac3651f8862498426d45abf`, tree `090f2ece76f75d517a16416508273de96dd0da72`.

Cada paquete incluye main/serial JUnit y transcript, `environment.txt`, `completion.txt`, `main-exit.txt`, `serial-exit.txt`, `full-suite-exit.txt` y un `MANIFEST.tsv` de sus nueve artefactos.

Los probes se almacenan bajo `probes/`:

- `functional/`: JUnit/log/exit base y head, `comparison.tsv` y `junit-results.json`; los intentos incompletos iniciales no se presentan como verdict.
- `visual/`: JUnit/log/exit de color-head, possible-base/head y clipboard-base/head, selecciones y `signature-comparison.txt`.
- `a2l/`: los 36 JUnit, sus 36 logs y 36 códigos de salida, más `comparison.tsv` generado desde los JUnit almacenados.
- `residual/`: comparación, censo, selección, listas por nodeid y JUnit/log/exit base/head main/serial, incluidas las colecciones base.
- `new2/`: JUnit/log/exit base/head/control, comparación JSON/TSV, entorno y nodeids.
- `final-timing/`: comparación, JUnit/log/run y listas de nodos base/head/control.

No se copiaron árboles de trabajo, homes, `tmp/`, `zq_local_g3/`, caches ni OUT masivos. Los originales permanecen fuera del repositorio y no fueron modificados.

## Transformación aplicada sólo a las copias

1. Lectura de los bytes originales y cálculo de SHA-256 antes de cualquier cambio.
2. Decodificación como UTF-8 con reemplazo explícito de bytes inválidos, eliminación de secuencias ANSI CSI/OSC y normalización CRLF/CR a LF.
3. Eliminación de espacios/tabs al final de línea para que las copias superen `git diff --check`.
4. Sustitución de rutas personales, cuentas, hosts, direcciones IP y rutas UNC/extended Windows por placeholders XML-safe entre corchetes, por ejemplo `[USER_HOME]`, `[ACCOUNT]`, `[HOST]`, `[IP]`, `[HOME]`, `[UNC]` y `[WIN_PATH]`.
5. Cálculo de SHA-256 de la copia almacenada.

No se editaron nodeids, estados, conteos ni firmas para cambiar verdicts. La normalización ANSI es necesaria para que los JUnit almacenados sean parseables; los hashes originales permiten auditar los bytes anteriores a esa normalización.

## Manifests y comparaciones

`MANIFEST.tsv` contiene una fila por artefacto almacenado con `stored_path`, `source_ref`, `original_sha256` y `stored_sha256`. Los manifests por corrida usan las mismas columnas. Los artefactos generados localmente se identifican como `generated-from-archived-junit` o `generated-record`.

`comparison-35fabb25-795779ad.tsv` se generó desde los cuatro JUnit normalizados almacenados. Sus conteos mecánicos son 522 fallos en la primera corrida, 372 en la segunda, 170 fixed, 352 persistent y 20 new.

La verificación posterior comprende todos los pares de hashes, el parseo de todos los XML almacenados, el censo de la comparación, el escaneo estático de rutas/identidades y `git diff --check`. Ningún archivo del clon de la full-suite final forma parte de este paquete.
