# E5 — Revisión independiente FINAL 2: transporte y holders

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. No soy autor de las correcciones fix2. Contrasté `E5-fix2-transport.md` y `E5-fix2-windows.md` con el contenido actual de:

- `s19_app/tui/os_clipboard_input.py`;
- `tests/test_b103_clipboard_tail.py`;
- `tests/test_b103_clipboard_windows.py`.

Alcance limitado a TR-01…TR-05, C-02/C-04 y D-02 tail, y a defectos directamente introducidos por sus correcciones. Las referencias siguientes son actuales.

## Veredicto del área

**GO para transporte/holders, exclusivamente como cierre estático de implementación y diseño.** Los bloqueos previos están corregidos en el árbol y no encontré un defecto nuevo directamente introducido por fix2. No queda un BLOCKER/HIGH/MEDIUM abierto en este alcance.

Este GO no certifica ejecución WinCI, cleanup de procesos reales, cobertura final de seis familias/leyes, mortalidad de mutantes ni aceptación manual. Las rutas WinCI citadas abajo están **escritas**, no promovidas a verificadas por esta revisión.

| Hallazgo previo | Severidad / clase | Disposición actual |
|---|---|---|
| TR-01 | HIGH / `impl` | **Cerrado estáticamente**: adquisición cubierta desde justo después de `Popen`, reap/release independientes y rechazo de vivos en ambos archivos. |
| TR-02 / B2 | HIGH / `impl` | **Cerrado estáticamente**: stdin/stdout binarios, UTF-8 explícito y sin `rstrip` ni newline universal en producto. |
| TR-03 | MEDIUM / `design-gap` | **Cerrado estáticamente**: controles acotados que discriminan estados vivos, reintentos, joins, cierre y polls; ejecución real de holders todavía separada. |
| TR-04 | MEDIUM / `design-gap` | **Cerrado estáticamente**: writer forzado con LF final y oráculos exactos de bytes/app/OS/OSC. |
| TR-05 | HIGH / `impl`, introducido por la corrección anterior | **Cerrado estáticamente**: reader directo exacto y pegado `Input` de primera línea son oráculos separados. |
| C-02 | MEDIUM / `design-gap` | **Cerrado estáticamente** para tail: Unicode, CR, CRLF, LF interno y LF final atraviesan la ruta WinCI escrita del reader externo. |
| C-04 | MEDIUM / `impl` | **Cerrado estáticamente** para tail: guarda intrínseca primera y control de rechazo sin `Popen` ni Win32. |
| D-02 tail | MEDIUM / `impl` | **Cerrado estáticamente**: formas XML y known-bad no vacuo incorporados. |

## TR-02 / B2 / TR-04 — transporte binario y exactitud CR/LF

### Producto

- El reader construye kwargs sin `text`, `encoding`, `errors` ni `newline` (`s19_app/tui/os_clipboard_input.py:307-312`), captura bytes en `subprocess.run` (`:314-325`) y decodifica stdout con UTF-8/`errors="replace"` (`:339-340`). Conserva `b"" → "" → None` y ya no aplica `rstrip`.
- El comando del reader emite mediante `Console.Out.Write` y `UTF8Encoding($false)` (`s19_app/tui/os_clipboard_input.py:320-321`); no añade salto de transporte.
- El writer codifica antes de llamar a `subprocess`: `text.encode("utf-8", errors="replace")` (`s19_app/tui/os_clipboard_input.py:454-459`) y ejecuta sin claves de modo texto (`:463-467`). El comando estático lee una vez con `ReadToEnd()` y usa `SetText($text)` (`:132-140`).
- Por tanto, la conversión CR/CRLF→LF de `TextIOWrapper` y la traducción LF→CRLF de stdin ya no forman parte de esta ruta. Es una conclusión de semántica estática, no un round-trip Windows observado aquí.

### Mocks y rutas que sí discriminan

- Los cinco payloads son LF interno, LF final, Unicode, CR interno y CRLF interno (`tests/test_b103_clipboard_tail.py:1251-1259`). El reader simulado entrega **bytes** UTF-8, incluido `b""` (`:1322-1333`), exige igualdad con cada cadena y `empty is None` (`:1339-1343`), y rechaza claves de modo texto (`:1353-1363`). Devolver `str`, omitir `decode` o normalizar CR/CRLF cambia estos oráculos.
- El writer exige exactamente `payload.encode("utf-8", errors="replace")` en stdin y ausencia de `text`/`encoding`/`errors`/`newline` (`tests/test_b103_clipboard_tail.py:1294-1299`). Su doble devuelve stdout/stderr binarios (`:1125-1128`).
- El guarda AST también rechaza esas claves y exige `encode`/`decode` (`tests/test_b103_clipboard_tail.py:1210-1240`). No sustituye por sí solo a los mocks anteriores.
- En la ruta WinCI escrita, el writer se limita a la estrategia PowerShell (`tests/test_b103_clipboard_tail.py:1114-1121`); la lectura OS separada usa Base64 y decodificación estricta (`:228-265`), y `_success` exige app/OS/OSC/payloads exactos (`:320-338`).
- Para C-02, la ruta WinCI escrita siembra cada uno de los cinco valores con `other_program_write()`, lee producto y `other_program_read()` local, y compara ambos exactamente (`tests/test_b103_clipboard_tail.py:1420-1426`). Exige dos arranques del PowerShell absoluto del sistema y ausencia del marcador decoy (`:1427-1440`). Esto cubre Unicode/CR/CRLF además de LF/LF final en el reader externo conservado.

El `text=True` que permanece en el `Popen` de readiness ASCII del holder tail (`tests/test_b103_clipboard_tail.py:1610-1618`) no pertenece al transporte PowerShell de producto de TR-02/B2; sus dobles de readiness también usan `str`. No lo contabilizo como reapertura ni como evidencia de exactitud de payloads.

## TR-05 — reader directo frente a `Input` de una línea

`test_r_paste_16_1_read_rescue_starts_system_powershell` siembra `PS-READ-Ñ\rL2\r\nL3\n` (`tests/test_b103_clipboard_windows.py:2309-2311`), fuerza ctypes a fallar y obtiene primero `reader_value = read_os_clipboard()` (`:2312-2316`). Después recorre por separado el `Input` real (`:2318-2326`) y exige:

- `reader_value == expected`, incluidos Unicode, CR, CRLF y LF final (`:2329`);
- `value == first_line`, es decir sólo `PS-READ-Ñ` (`:2330`);
- exactamente dos arranques, ambos del PowerShell del sistema (`:2331-2336`).

Esto concuerda con el contrato de producto `text.splitlines()[0]` (`s19_app/tui/os_clipboard_input.py:1094`) y con el caso contractual previo (`tests/test_b103_clipboard_windows.py:1153-1169`). El oráculo incompatible anterior queda corregido sin debilitar la exactitud directa del reader. Sigue siendo una ruta WinCI pendiente de resultado real.

## TR-01 — cleanup y ausencia de éxito con vivos

### Tail

- El `try` empieza inmediatamente después de `Popen` (`tests/test_b103_clipboard_tail.py:1610-1620`), por lo que cola, creación/inicio del reader, readiness, Win32 y supervisor quedan cubiertos. La salida por error intenta reap, joins y comprobaciones de reader/supervisor, y termina con otro poll del holder (`:1677-1718`).
- `_reap_holder()` intenta independientemente kill/wait inicial, kill/wait final, cierre y poll (`tests/test_b103_clipboard_tail.py:1468-1495`). Un `returncode is None` genera fallo explícito (`:1497-1504`).
- `_release_clipboard()` ejecuta de forma independiente `set`, join de 5 s, reap, join final de 1 s (`tests/test_b103_clipboard_tail.py:1518-1527`), conserva el fallo del supervisor y rechaza supervisor o holder vivo (`:1528-1556`).

### Windows

- `_reap_holder()` contiene las seis etapas independientes, incluidos waits 3 s/1 s, cierre y `death check` (`tests/test_b103_clipboard_windows.py:394-429`).
- `_release_clipboard()` no condiciona una etapa al éxito de la anterior: ejecuta `set`, ambos joins, reap y checks de supervisor/holder (`tests/test_b103_clipboard_windows.py:432-471`).
- El `try` de adquisición comienza justo después del `Popen` binario (`tests/test_b103_clipboard_windows.py:536-543`). Su `except` conserva el primario, intenta reap y joins/checks de ambos hilos (`:599-624`). El supervisor reapsa en `finally` incluso si falla su espera de release (`:579-593`).

Las funciones ya no presentan el camino anterior que omitía el segundo kill/wait, el join final o la comprobación de muerte tras un fallo. Esto cierra el defecto escrito; no equivale a haber matado holders reales en WinCI.

## TR-03 / C-04 — controles no vacuos y guarda tail

- Ambos arneses imponen deadline externo de 2 s (`tests/test_b103_clipboard_tail.py:1721-1741`; `tests/test_b103_clipboard_windows.py:775-789`) y son llamados efectivamente (`tests/test_b103_clipboard_tail.py:1442-1446`, `:2131-2145`; `tests/test_b103_clipboard_windows.py:1025-1036`, `:2557-2558`).
- Tail inyecta `reader.start()` fallido y exige reap y join (`tests/test_b103_clipboard_tail.py:1896-1915`). Su `ProcessDouble` registra estado vivo en cada wait y no muere en el primer kill cuando `defer_first_kill=True` (`:1761-1804`). El control de timeout exige dos kills, waits `[3.0, 1.0]` y estados `[True, False]` (`:1972-1987`); el de kill fallido exige el reintento (`:1989-2003`).
- El oráculo común tail exige cierre, ambos waits, número de kills, poll final y un poll **posterior al cierre** (`tests/test_b103_clipboard_tail.py:1851-1859`). Los casos de holder imposible de matar y holder vivo durante release deben fallar explícitamente; no se aceptan como cleanup (`:2005-2020`, `:2108-2129`). Supervisor colgado, fallo de `release.set` y fallos de join también tienen oráculos (`:2060-2106`).
- Windows mantiene bytes en stream/readiness (`tests/test_b103_clipboard_windows.py:654-710`) y rechaza modo texto en el `Popen` doblado (`:842-850`). Su wait timeout conserva vivo al proceso hasta un wait posterior a kill efectivo (`:700-710`); los oráculos exigen muerte en el segundo kill y nota de `death check` para el incunable (`:926-979`). Reader start, supervisor vivo, `release.set` y ambos joins están controlados (`:908-924`, `:981-1023`).
- La guarda tail es la primera operación de `_hold_clipboard`, antes de construir el script, `Popen` o tocar Win32 (`tests/test_b103_clipboard_tail.py:1559-1563`). `guard_rejected` instala un rechazo, prohíbe `Popen`/`ctypes.windll` y exige identidad del error y cero recursos (`:1861-1895`). La guarda permitida se comprueba antes de aceptar el `Popen` doblado (`:1835-1849`).

Los dobles ya no fijan como suficiente un holder/supervisor vivo. No afirmo mortalidad de mutantes: ésta es falsificabilidad estática de los controles, no ejecución de mutantes de producto.

## D-02 tail y marca de timing

- `_disclosure_forms()` incluye directo/prefijo/`repr`/escape y las formas XML textual, prefijos, CR numérico y atributo (`tests/test_b103_clipboard_tail.py:368-387`); `_no_secret()` las aplica sin incluir el payload en el mensaje de fallo (`:390-397`).
- `xml_known_bad` comprueba que cada forma XML no sea accidentalmente detectada por una forma plana y exige que `_no_secret()` la rechace (`tests/test_b103_clipboard_tail.py:1066-1084`). El brazo se añade realmente a `_run_arms` (`:1100-1101`).
- `@pytest.mark.serial_timing` está directamente sobre el nodo R-PASTE.13/101 (`tests/test_b103_clipboard_tail.py:2156-2157`). No derivo de ello un resultado de las leyes completas.

## Verificación y límites

Revisión exclusivamente estática mediante lecturas acotadas, búsquedas y Git de sólo lectura. Confirmé el HEAD indicado y `git diff --check -- s19_app/tui/os_clipboard_input.py tests/test_b103_clipboard_tail.py tests/test_b103_clipboard_windows.py` terminó con exit 0. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto/tests/workflow/ledger/canon/evidencia. La única escritura es este informe.

Registro como dato del caller, no reproducido por mí, la selección exacta Linux **164 passed / 2 skipped**. La batería full de seis familias y las leyes estaban corriendo en otro clon exacto: no las contabilizo como terminadas ni como evidencia de este veredicto. Ninguno de esos resultados Linux sustituye WinCI ni demuestra bytes reales de `Popen`/holders Windows.

**No hay mutantes de producto ejecutados. AT-I1b-8 sigue manual, pendiente y no verificada.** Para una promoción final siguen siendo necesarias las puertas WinCI reales y las ejecuciones completas previstas; este GO sólo cierra los bloqueos estáticos del área asignada.
