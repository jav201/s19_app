# Code-Wire prototype — Inc 9a, group G1 (`workspace.py`)

Stage E2 of the design-first pipeline for Inc 9a. Graph only: no stub, mark or other change in `s19_app/` (`git diff --stat -- s19_app` stays empty). New functions and data types are nodes whose `func:` starts with "new"; unchanged context nodes say "unchanged". The shared interfaces are those of `interfaces-9a.md` (binding); where a node needs more than that file fixes, the node says "(proposed P9a-G1-n)" and the change is appended to `interfaces-9a.md` §Proposals for the orchestrator. G2 (`app.py`) prototypes in parallel; the seams are under "Seams with G2".

**E3 round 1 applied (`../E3-rulings.md` R1–R13, LED .83).** A ruling wins over any older line of this file. G1 now records `os.path.abspath` and de-duplicates on its `normcase` (R1; G2 P-1 revoked); writes nothing over an unreadable store (LLR-172.1k) and records no path the read would drop (LLR-172.1l); keeps the 65 536-byte writer cap as LLR-172.1m (R10); refuses a linked store file or folder on read (R6, LLR-172.2c); creates only `s19_app`, never the parents of `LOCALAPPDATA` (R7); has no lock (P9a-G1-4 rejected, R8) and logs nothing at WARNING or above (P9a-G1-1 rejected; G2 logs the 1 warning, S6); and the seam ids S1–S10 mean the same in G1 and G2 (R8).

**Base and inputs.** Code at `4fef292`: `_is_reparse_point` (`workspace.py:207`), `contained_in_workarea` (`:618`), `is_windows_device_name` (`:1833`), `resolve_input_path` (`:2020`), `RESERVED_WORKAREA_HOMES` (`:43`), the extension sets (`:107-110`), `WORKAREA_TEMP` (`:23`), `WORKAREA_STAGING_DIRNAME` (`:27`), the `s19tui` logger (`:164`); `safe_text` (`utils.py:44`, `_CONTROL_SCRUB` = U+0000–U+001F and U+007F–U+009F, `utils.py:41`). Rulings: `../E1-rulings.md` Q1–Q9, C1–C8. Requirements: `01-requirements.md` HLR-172, HLR-172b, LLR-172.1 … .1m, LLR-172.2 … .2j, LLR-172.3, LLR-172.4 … .4c (after LED .83); LLR-172.1d, .1e, .6, .6a only at their G1 seam. HLR-172a and LLR-172.5 … .5g are G2's (typed routing; G1 contributes only the unchanged `RESERVED_WORKAREA_HOMES`).

**Example sources and conventions.** Each example names its requirement id (or a ruling, seam or probe) and says "target (9a)" (asked for; no code exists at `4fef292`) or "holds" (unchanged behaviour G1 relies on). Fixture names used throughout (Windows text):
- `<lad>` = the test's `LOCALAPPDATA`, written `C:\t\lad` here for readability; in a test it always derives from `tmp_path`, never a literal drive path (off Windows `C:\t\lad` passes the drive test and names a relative folder; E3 S9-3, R5); the store = `<lad>\s19_app\recent_sources.json`; the store folder = `<lad>\s19_app`.
- `<src>` = an outside folder `C:\t\src`; `<wa>` = the test work area `C:\t\base\.s19tool\workarea`; `<base>` = `C:\t\base`.
- Store bytes are written as `json.dumps(doc, ensure_ascii=True, separators=(",", ":"))` encoded ASCII (decision D-3); sizes below use that form.

**Probe p9a-g1 (executed, this session).** Python 3.12.7 on win32, `python -I`, a scratch script outside the repository (no repository code imported). Output used by the examples:
- `PureWindowsPath(t).drive` / `.root`, and the regex `^[A-Za-z]:[\\/]`: `x.s19` → `''`/`''`, no match; `C:x.s19` → `C:`/`''`, no match; `\x.s19` → `''`/`\`, no match; `\\host\share\x.s19` → `\\host\share`/`\`, no match; `\\?\GLOBALROOT\x.s19` → `\\?\GLOBALROOT`/`\`, no match; `\\.\C:\x.s19` → `\\.\C:`/`\`, no match; `C:\x\a.s19` and `C:/x/a.s19` → `C:`/`\`, match.
- `PureWindowsPath(...).suffix`: `a.s19:ads` → `.s19:ads`; `a.s19.` → `''`; `A.SREC` → `.SREC`; `a.s19 ` → `.s19 `; `a.a2l.json` → `.json`. `PureWindowsPath("C:\CON\a.s19").parts` → `('C:\\', 'CON', 'a.s19')`.
- `json.loads("[" * 65536)` → raises `RecursionError`, which is **not** a `ValueError`.
- `json.loads('{"schema_version": true, "sources": []}')` → loads; `True == 1` → `True`; `json.loads("1.0") == 1` → `True`.
- Encoded size of 1 entry `C:\.s19` → 65 bytes; formula `32 + k × (33 + n)` for k entries of `C:\` + n×`p` + `.s19`: n = 3 240, k = 20 → 65 492; n = 3 245, k = 20 → 65 592; n = 3 245, k = 19 → 62 314.
- `json.dumps("a\udc80b")` → `"a\udc80b"` and round-trips (a lone surrogate stays valid JSON under `ensure_ascii=True`).
- `Path("G:\My Drive").resolve()` → `G:\My Drive` (this machine's G: is a virtual drive, not an SMB share; a mapped network drive was not available: R-6 not run).
- `.github/workflows/tui-ci.yml`: `runs-on: ubuntu-latest` (CI is Linux; R-1).

**Counts.** 11 nodes — 9 owned, all new (5 functions: `recent_store_path`, `recent_kind`, `read_recent_sources`, `record_recent_source`, `list_workarea_files`; 2 helpers: `_recent_entry_ok`, `_encode_recent_store`; 2 data types: `RecentEntry`, `RecentSources`) and 2 unchanged context nodes (`_is_reparse_point`, `is_windows_device_name`). 1 entity (the `_RECENT_LOCK` entity removed by E3 R8). 106 example lines (94 at E2; after E3 r1). 11 design risks (R-1 … R-11), 8 undecidable points (U-1 … U-8), 6 proposals (P9a-G1-1 … P9a-G1-6). Requirements in G1's scope without an example: 0 (table at the end).

## Nodes

recent_store_path
req: LLR-172.1, LLR-172.1f, LLR-172.2d, HLR-172
in:
out: Optional[Path] store
func: new. Reads `os.environ.get("LOCALAPPDATA")` once per call (never `APPDATA`, never `Path.home()`, never the base folder; seam S9: read at call time, never at import). `None` when the value is missing, empty, or its text does not match `^[A-Za-z]:[\\/]` on every platform (a drive letter followed by a root: the same drive-rooted test as LLR-172.2e, decision D-1; E3 R5); otherwise `Path(value) / RECENT_STORE_DIRNAME / RECENT_STORE_FILENAME` with the new module constants `RECENT_STORE_DIRNAME = "s19_app"` and `RECENT_STORE_FILENAME = "recent_sources.json"`. Pure: touches no file and creates no folder. Never raises. Seam S4: `None` means "no store" to every caller.
module: s19_app/tui/workspace.py
examples: (LLR-172.1) `LOCALAPPDATA` = `C:\t\lad` → `C:\t\lad\s19_app\recent_sources.json`; `0` files or folders created by the call (target (9a))
examples: (LLR-172.1f) `LOCALAPPDATA` unset → `None`; `""` → `None`; `relative\lad` → `None` (3 of 3) (target (9a))
examples: (LLR-172.1f, D-1) `C:lad` (drive, no root) → `None`; `\\host\profiles\lad` (UNC) → `None`; `C:/t/lad` → `C:\t\lad\s19_app\recent_sources.json` (target (9a))
examples: (LLR-172.1 negative control) `LOCALAPPDATA` unset and `APPDATA` = `C:\t\roam` → `None`, `0` files under `C:\t\roam` (a mutation reading `APPDATA` → a path → RED) (target (9a))
examples: (LLR-172.1f negative control) `LOCALAPPDATA` unset → `None`, not `Path.home() / "s19_app" / …` (a `home()` fallback mutant → 1 file → RED) (target (9a))
examples: (LLR-172.1f, R5, R-1) `LOCALAPPDATA` = `/tmp/pytest-of-ci/lad` (the Linux CI `tmp_path`) → `None` on every platform; `/tmp/lad` → `None` (target (9a))
examples: (S9) the test sets `LOCALAPPDATA` after `import s19_app.tui.workspace` → the next call returns the new value's store path (a module-level cache mutant → the old path → RED) (target (9a))

recent_kind
req: LLR-172.1a, LLR-172.2h, HLR-172
in: Path path
out: Optional[str] kind
func: new (interfaces-9a.md; ruling C6). `suffix = PureWindowsPath(str(path)).suffix.casefold()` (Windows suffix rules on every host, R-1); `"s19"` when the suffix is in `S19_EXTENSIONS`, `"hex"` in `HEX_EXTENSIONS`, `"mac"` in `MAC_EXTENSIONS`, `"a2l"` in `A2L_EXTENSIONS`; any other suffix, the empty suffix included → `None`. One table: the loader's own sets (`workspace.py:107-110`), read at call time, so a suffix the loader gains later is recorded with the same kind. Shared by `record_recent_source` (writer) and `_recent_entry_ok` (reader), so a `.srec` written as `s19` is never dropped on read (baseline C6). Pure, never raises.
module: s19_app/tui/workspace.py
examples: (LLR-172.1a) `a.s19` → "s19"; `a.srec` → "s19"; `a.hex` → "hex"; `a.ihex` → "hex"; `a.mac` → "mac"; `a.a2l` → "a2l" (6 of 6) (target (9a))
examples: (LLR-172.1a, LLR-172.2h boundary) `C:\t\A.SREC` → "s19"; `C:\x\A.SREC` → "s19" (target (9a))
examples: (LLR-172.2h, probe p9a-g1) `C:\x\a.exe` → `None`; `C:\x\a.s19:ads` → `None` (suffix `.s19:ads`); `C:\x\a.s19.` → `None` (suffix `''`); `C:\x\a.s19 ` → `None` (suffix `.s19 `); `C:\x\firmware` → `None` (5 of 5) (target (9a))
examples: (ruling C7, probe p9a-g1) `x.a2l.json` (the A2L dump) → `None` (suffix `.json`) (target (9a))
examples: (LLR-172.2h negative control) a mutation mapping `.srec` to "srec" → `C:\x\A.SREC` with `kind: s19` dropped on read → RED (target (9a))

RecentEntry
req: LLR-172.1a, LLR-172.2, HLR-172
in: str path; str kind
out: RecentEntry entry
func: new, frozen dataclass (interfaces-9a.md). `path`: the absolute source path as recorded (the text `os.path.abspath(str(source))` produced at record time, E3 R1: lexical, no link resolved, no network call; never re-normalised on read, so a store read touches no source and no network path, LLR-173.4's rule); `kind`: `recent_kind(path)`. Invariant for every instance `read_recent_sources` returns: `_recent_entry_ok` accepted it.
module: s19_app/tui/workspace.py
examples: (LLR-172.1a, AT-B100-12) the example `C:\repo\examples\case_01_basic_valid\firmware.s19` → path "C:\repo\examples\case_01_basic_valid\firmware.s19", kind "s19" (target (9a))
examples: (LLR-172.1a) `<src>\m.a2l` → path "C:\t\src\m.a2l", kind "a2l" (target (9a))

RecentSources
req: LLR-172.2, LLR-172.2a, LLR-172.2c, LLR-172.2d, HLR-172
in: tuple[RecentEntry, ...] entries; Optional[str] problem
out: RecentSources sources
func: new, frozen dataclass (interfaces-9a.md). `entries`: accepted entries, newest first (stored order), at most `RECENT_LIMIT` (20). `problem`: `None`, `RECENT_PROBLEM_TOO_LARGE` = "too large" (LLR-172.2a) or `RECENT_PROBLEM_UNREADABLE` = "could not be read" (LLR-172.2c; ruling Q6); new module constants (proposed P9a-G1-3, seam S5). Invariant: `problem is not None` ⇒ `entries == ()`. A wrong shape (LLR-172.2b) and a missing store (LLR-172.2d) are `((), None)`: no problem word.
module: s19_app/tui/workspace.py
examples: (LLR-172.2a) a 65 537-byte store → entries `()`, problem "too large" (target (9a))
examples: (LLR-172.2c) a directory at the store path → entries `()`, problem "could not be read" (target (9a))
examples: (LLR-172.2d) no store file → entries `()`, problem `None` (target (9a))

_recent_entry_ok
req: LLR-172.2e, LLR-172.2f, LLR-172.2g, LLR-172.2h, LLR-172.2i, LLR-172.2j, LLR-172.1j, LLR-172.1l
in: object raw
out: Optional[RecentEntry] entry
func: new (E1 guess G2, kept as a node: the writer and the reader share it, LLR-172.1l). One decoded JSON value → a `RecentEntry`, or `None` when any check fails. Checks in this order, the first failure decides (order chosen so no check can raise on what an earlier check let through): (1) LLR-172.2i — `raw` is a `dict` and `raw["path"]`, `raw["kind"]` are both `str` (`type(...) is str`); extra keys are ignored (U-4); (2) LLR-172.2g — the path holds no character in U+0000–U+001F or U+007F–U+009F (the `_CONTROL_SCRUB` range of `utils.py:41`; tested, not scrubbed); (3) LLR-172.2e — the path text matches `^[A-Za-z]:[\\/]`, which refuses a relative path, a drive without root, a root without drive, UNC, `\\?\` and `\\.\` forms (probe p9a-g1); (4) LLR-172.2f — no component of `PureWindowsPath(path).parts[1:]` satisfies `is_windows_device_name` (folders and file); (5) LLR-172.2h — `raw["kind"] == recent_kind(Path(path))` and that kind is not `None`. Pure (no filesystem access), never raises (LLR-172.2j).
module: s19_app/tui/workspace.py
examples: (LLR-172.2e, probe p9a-g1) path `x.s19`, `C:x.s19`, `\x.s19`, `\\host\share\x.s19`, `\\?\GLOBALROOT\x.s19`, `\\.\C:\x.s19`, each with kind "s19" → `None` (6 of 6) (target (9a))
examples: (LLR-172.2e) `{"path": "C:\\x\\a.s19", "kind": "s19"}` → RecentEntry("C:\x\a.s19", "s19") (target (9a))
examples: (LLR-172.2e negative control, S-07) a mutation using `PureWindowsPath(p).is_absolute()` → `\\host\share\x.s19` accepted → RED (target (9a))
examples: (LLR-172.2f) `C:\x\NUL.s19`, `C:\CON\a.s19`, `C:\x\com1.s19` → `None` (3 of 3); `C:\x\console.s19` → accepted (target (9a))
examples: (LLR-172.2f negative control) a mutation checking the last component only → `C:\CON\a.s19` accepted → RED (target (9a))
examples: (LLR-172.2g) `C:\x\a` + U+0000 + `.s19`, `C:\x\` + `\x1b[2J` + `a.s19`, `C:\x\a` + U+007F + `.s19`, `C:\x\a` + U+009B + `.s19` → `None` (4 of 4) (target (9a))
examples: (LLR-172.2g negative control, S-06) a mutation refusing U+0000 only → the `\x1b[2J` path accepted → RED (target (9a))
examples: (LLR-172.2h) kind "exe" on `C:\x\a.s19`; `C:\x\a.s19` with "a2l"; `C:\x\a.s19:ads` with "s19"; `C:\x\a.s19.` with "s19"; `C:\x\a.exe` with "s19" → `None` (5 of 5); `C:\x\A.SREC` with "s19" → accepted (target (9a))
examples: (LLR-172.2i) `null`, `"C:\\x.s19"`, `{"path": 7, "kind": "s19"}`, `{"path": "C:\\x.s19"}` → `None` (4 of 4), `0` raises (target (9a))
examples: (U-4) `{"path": "C:\\x\\a.s19", "kind": "s19", "note": 1}` → accepted, `note` dropped (target (9a))
examples: (LLR-172.2j) `{"path": ["C:\\x"], "kind": {"k": 1}}` → `None`, `0` raises (target (9a))

read_recent_sources
req: LLR-172.2, LLR-172.2a, LLR-172.2b, LLR-172.2c, LLR-172.2d, LLR-172.2j, LLR-172.3, HLR-172
in:
out: RecentSources sources
func: new (interfaces-9a.md). No lock (P9a-G1-4 rejected: every call runs on the UI thread). Steps: (1) `store = recent_store_path()`; `None` → `((), None)`, nothing created (LLR-172.2d). (1b) link check before any open (E3 R6, LLR-172.2c): `_is_reparse_point(store.parent)` or `_is_reparse_point(store)` → `((), "could not be read")`, 0 bytes read (a missing folder or file is not a link: `_is_reparse_point` gives `False`, and step 2 reports it missing). (2) `open(store, "rb")`: `FileNotFoundError` or `NotADirectoryError` → `((), None)` (missing, LLR-172.2d); any other `OSError` — `PermissionError`, a directory at the path (Windows raises `PermissionError`, POSIX `IsADirectoryError`) — → `((), "could not be read")` (LLR-172.2c). (3) exactly one `f.read(RECENT_STORE_MAX_BYTES + 1)` (65 537); a read `OSError` → "could not be read"; more than 65 536 bytes returned → `((), "too large")` (LLR-172.2a; no `stat` first, no full read: S-12). (4) `bytes.decode("utf-8")` strict; `UnicodeDecodeError` → `((), None)` (LLR-172.2b). (5) `json.loads`; `ValueError` **or `RecursionError`** → `((), None)` (LLR-172.2b, LLR-172.2j; R-4: a deeply nested array raises `RecursionError`, probe p9a-g1). (6) shape: a `dict` whose `schema_version` satisfies `type(v) is int and v == 1` (so `true` and `1.0` are refused, R-5) and whose `sources` is a `list`; else `((), None)` (LLR-172.2b). (7) walk `sources` in order, keep each value `_recent_entry_ok` accepts, stop once 20 are kept (LLR-172.2); problem `None`. Logs nothing that holds an entry's text: at most 1 debug line with the counts (accepted, refused) and the problem word (LLR-172.3, R-9). Never raises (LLR-172.2j): the body sits inside one `except Exception` that returns `((), "could not be read")` and logs the exception class only, as the last guard behind the explicit catches above.
module: s19_app/tui/workspace.py
modify: [I/O: recent-sources store] (read)
examples: (LLR-172.2) a store of `1 000` distinct accepted entries `C:\000.s19` … `C:\999.s19` (about 41 KB) → exactly the first `20` (`C:\000.s19` … `C:\019.s19`), in order, problem `None` (target (9a))
examples: (LLR-172.2) 5 accepted entries with 2 refused ones (`\\host\share\x.s19`, `kind: exe`) between them → the `5`, in stored order, problem `None` (target (9a))
examples: (LLR-172.2 negative control) a mutation without the cap → `1 000` entries → RED; a mutation sorting the entries → the order arm RED (target (9a))
examples: (LLR-172.2a) exactly `65 536` bytes of a valid store (padded with trailing spaces) → parsed; `65 537` bytes → entries `()`, problem "too large"; the read spy sees `1` read call of size `65 537` (target (9a))
examples: (LLR-172.2a negative control) `>=` instead of `>` → the 65 536-byte arm "too large" → RED; `stat` then a full read → the read-size spy sees a size other than 65 537 → RED (target (9a))
examples: (LLR-172.2b) `{not json`, the bytes `b"\xff\xfe"`, `[]`, `{"schema_version": 2, "sources": []}`, `{"schema_version": 1, "sources": "C:\\x.s19"}` → entries `()`, problem `None`, `0` raises (5 of 5) (target (9a))
examples: (LLR-172.2b, R-5, probe p9a-g1) `{"schema_version": true, "sources": [<1 accepted entry>]}` → entries `()`; `{"schema_version": 1.0, …}` → entries `()` (target (9a))
examples: (U-4) a store written with a UTF-8 BOM (`b"\xef\xbb\xbf{..."`) → entries `()`, problem `None` (json refuses the BOM) (target (9a))
examples: (LLR-172.2c) `open` raising `PermissionError` (injected) → entries `()`, problem "could not be read"; a directory at `<lad>\s19_app\recent_sources.json` → entries `()`, problem "could not be read" (2 of 2), `0` raises (target (9a))
examples: (LLR-172.2c negative control) a mutation without the catch → `PermissionError` raised → RED; a mutation returning problem `None` → RED (target (9a))
examples: (LLR-172.2c, R6) the store file a symbolic link to `C:\t\other.json` (a valid store with 2 entries) → entries `()`, problem "could not be read", `0` opens (a spy on `open`); `<lad>\s19_app` a junction to `C:\t\elsewhere` holding a valid store → the same (2 of 2); the file-link arm reported not run when the platform refuses the link (target (9a))
examples: (LLR-172.2c negative control, R6) a mutation without step (1b) → the link arms return the target's 2 entries → RED (target (9a))
examples: (LLR-172.2d) `<lad>` holds no `s19_app` folder → entries `()`, problem `None`; `LOCALAPPDATA` unset → entries `()`, problem `None`, `0` files or folders created under `<lad>`, the working folder or `<base>` (2 of 2) (target (9a))
examples: (LLR-172.2d negative control) a mutation reporting "could not be read" for a missing file → RED; a mutation raising `FileNotFoundError` → RED (target (9a))
examples: (LLR-172.2j, R-4, probe p9a-g1) a store of `65 536` bytes of `[` → entries `()`, problem `None`, `0` raises (a catch of `ValueError` alone lets `RecursionError` out → RED) (target (9a))
examples: (LLR-172.2j) the stores of LLR-172.2a … .2i plus `200` seeded random byte strings of `0` to `70 000` bytes → `0` raises; every result satisfies `problem is not None ⇒ entries == ()` and `len(entries) ≤ 20` (target (9a))
examples: (LLR-172.2j negative control) a mutation without the decode guard → the `b"\xff\xfe"` store raises → RED (target (9a))
examples: (LLR-172.3 arm 1, R-9) a store with 3 entries under `C:\t\m4rk3r-9a\` read once → `0` log lines holding `m4rk3r-9a`; `0` files written anywhere (target (9a))

_encode_recent_store
req: LLR-172.1m, LLR-172.1h, LLR-172.1c, LLR-172.2a, LLR-172.1j
in: Sequence[RecentEntry] entries
out: bytes payload
func: new (P9a-G1-3 accepted; kept by E3 R10 as LLR-172.1m, whose note holds the arithmetic). Builds `{"schema_version": 1, "sources": [{"path": …, "kind": …}, …]}` from at most the first `RECENT_LIMIT` entries, serialised `json.dumps(doc, ensure_ascii=True, separators=(",", ":"))` and encoded ASCII (decision D-3: `ensure_ascii=True` keeps a lone surrogate in a Windows file name valid JSON, probe p9a-g1, R-11; compact separators fix the byte counts below). Size rule: while the payload is longer than `RECENT_STORE_MAX_BYTES` (65 536) and more than one entry remains, drop the oldest (last) entry and re-encode; a payload of one entry still too long → returns `b""` and the caller writes nothing. So the writer never produces a store the reader refuses as "too large" (R-3). Pure.
module: s19_app/tui/workspace.py
examples: (LLR-172.1a, probe p9a-g1) `[RecentEntry("C:\.s19", "s19")]` → the `65` bytes `{"schema_version":1,"sources":[{"path":"C:\\.s19","kind":"s19"}]}` (target (9a))
examples: (LLR-172.1c) 21 entries → the first `20` encoded, the 21st (oldest) absent (target (9a))
examples: (LLR-172.1m, R-3, probe p9a-g1) 20 entries `C:\` + `3 240`×`p` + `.s19` → `65 492` bytes, `20` entries kept; 20 entries of `3 245`×`p` → `19` entries kept, `62 314` bytes, the oldest dropped (target (9a))
examples: (LLR-172.1m) 1 entry whose path is `C:\` + `11 000`×`é` + `.s19` (each `é` encodes as 6 bytes) → `b""` (target (9a))
examples: (LLR-172.1m negative control) a mutation without the size loop → the `3 245` arm encodes `65 592` bytes, which the next read reports "too large" → RED; dropping the first (newest) entry → the new entry missing → RED (target (9a))

record_recent_source
req: HLR-172, LLR-172.1a, LLR-172.1b, LLR-172.1c, LLR-172.1f, LLR-172.1g, LLR-172.1h, LLR-172.1i, LLR-172.1j, LLR-172.1k, LLR-172.1l, LLR-172.1m, LLR-172.1d, LLR-172.1e, LLR-172.3
in: Path path
out: bool written
func: new (interfaces-9a.md, as amended by E3 r1). Records one source the caller has already found outside the work area (seam S2) and has already copied (seam S1). Never raises; `True` only when the store was replaced. No lock (P9a-G1-4 rejected; every call runs on the UI thread, `app.py:12765`, `:7225-7227`). Steps: (1) `store = recent_store_path()`; `None` → `False`, nothing created (LLR-172.1f). (2) `kind = recent_kind(path)`; `None` → `False` (ruling C6; unreachable from G2, whose loaders accept only these suffixes, seam S10). (3) `text = os.path.abspath(str(path))` (E3 R1: lexical — folds `.` and `..`, resolves no link, makes no network call, so a mapped drive keeps its letter; a relative `path` from `resolve_input_path` is made absolute against the working folder, where it was found); `ValueError` (an embedded NUL) or `OSError` → `False`. (4) `new = _recent_entry_ok({"path": text, "kind": kind})`; `None` → `False`, nothing written (LLR-172.1l: a UNC source, a name with a control character, a device component). (5) `folder = store.parent`; `folder.mkdir(parents=False, exist_ok=True)` (E3 R7: only `s19_app` is created; a missing `LOCALAPPDATA` folder raises `FileNotFoundError` → `False`, nothing created, LLR-172.1f); then `_is_reparse_point(folder)` → `False`, nothing written (LLR-172.1g; checked after `mkdir`, so a pre-existing junction is caught and a fresh folder is checked too). (6) `current = read_recent_sources()`; `current.problem == "could not be read"` → `False`, store left as it was (LLR-172.1k; this also covers a linked store file, R6); "too large" and a wrong shape give `()` and the record goes on (LLR-172.1j: 1 entry). (7) `entries = [new] + [e for e in current.entries if os.path.normcase(e.path) != os.path.normcase(text)]` (LLR-172.1b: compared with `normcase` after `abspath`; stored texts are not re-normalised), cut to `RECENT_LIMIT` (LLR-172.1c). (8) `payload = _encode_recent_store(entries)`; `b""` → `False` (LLR-172.1m). (9) `fd, staging = tempfile.mkstemp(prefix=".recent_sources-", suffix=".tmp", dir=folder)` (a unique name in the store folder; never named `recent_sources.json`), write `payload`, flush, close, `os.replace(staging, store)` (LLR-172.1h). Any `OSError` in (5) or (9) → unlink `staging` when it exists, `False` (LLR-172.1i). Logging (seam S6; P9a-G1-1 rejected, G2 P-2 accepted): every G1 line is DEBUG, failures included — 1 debug line per failed write or skip naming the step and the exception class, never a path; success logs nothing; the caller's 1 warning on `False` is the only warning. No log line holds any store entry (LLR-172.3, R-9). The outer guard: an unexpected `Exception` → 1 debug line with the class, `False`.
module: s19_app/tui/workspace.py
modify: [I/O: recent-sources store] (replace)
examples: (AT-B100-12, LLR-172.1a, HLR-172) `<lad>` holds nothing; `record_recent_source(Path(r"C:\repo\examples\case_01_basic_valid\firmware.s19"))` → `True`; the store reads `{"schema_version":1,"sources":[{"path":"C:\\repo\\examples\\case_01_basic_valid\\firmware.s19","kind":"s19"}]}` (1 entry); the folder `<lad>\s19_app` created (target (9a))
examples: (LLR-172.1a) then `<src>\m.a2l`, `<src>\m.mac`, `<src>\m.hex` → `4` entries, kinds "hex", "mac", "a2l", "s19" in that order (target (9a))
examples: (LLR-172.1a boundary) `C:\t\A.SREC` → entry kind "s19" (target (9a))
examples: (LLR-172.1a, seam S7) `Path("firmware.s19")` with the working folder `<src>` → entry path "C:\t\src\firmware.s19" (`abspath`, not the typed relative text) (target (9a))
examples: (LLR-172.1a, R1) `C:\t\j\x.s19` with `C:\t\j` a junction to `C:\t\real` → entry path "C:\t\j\x.s19" (no link resolved); reported not run when no junction can be made (target (9a))
examples: (LLR-172.1a negative control, R1) a mutation recording `Path(path).resolve()` → the junction arm records "C:\t\real\x.s19" → RED (on a mapped SMB drive the same mutation gives `\\server\share\…`, which LLR-172.1l then refuses: E3 A9-1; no SMB drive available, not run) (target (9a))
examples: (LLR-172.1a negative control, seam S7) a mutation recording the work copy `<wa>\temp\firmware.s19` → the path arm RED (target (9a))
examples: (LLR-172.1a negative control) a mutation appending the new entry last → the order arm (`hex` first) RED (target (9a))
examples: (LLR-172.1b) the same file twice → `1` entry; `C:\t\src\A.s19` then `C:\T\SRC\a.S19` (one file) → `1` entry, its text the second call's `abspath` result "C:\T\SRC\a.S19" (Windows only, R12); `C:\t\src\sub\..\A.s19` after `C:\t\src\A.s19` → `1` entry; A, then B, then A → `2` entries, A first (target (9a))
examples: (LLR-172.1b negative control) a mutation without the de-duplication → `2` entries for the same file → RED; keeping the old position → B first → RED; comparing without `normcase` → `2` entries for the case arm → RED (target (9a))
examples: (LLR-172.1c) 20 distinct sources s1 … s20 recorded → `20` entries, s1 last; s21 → `20` entries, s1 gone, s21 first; s22 … s25 → `20` entries, entry 1 = s25, entry 20 = s6 (target (9a))
examples: (LLR-172.1c negative control) a cap of 21, or none → `21` entries after s21 → RED; dropping the newest → s21 missing → RED (target (9a))
examples: (LLR-172.1f) `LOCALAPPDATA` unset, `""`, `relative\lad`, working folder `C:\t` → `False` each; `0` files named `recent_sources.json` under `C:\t` and `<base>`; `0` folders created; `0` raises (3 of 3) (target (9a))
examples: (LLR-172.1f negative control) a mutation using `relative\lad` as a folder → `C:\t\relative\lad\s19_app\recent_sources.json` written → RED (target (9a))
examples: (LLR-172.1f, R7) `LOCALAPPDATA` = `C:\t\absent` (no such folder) → `False`; `0` folders created (`C:\t\absent` still absent); `0` raises (target (9a))
examples: (LLR-172.1f negative control, R7) a mutation with `mkdir(parents=True)` → `C:\t\absent\s19_app\recent_sources.json` written → RED (target (9a))
examples: (LLR-172.1g) `<lad>\s19_app` a junction to `C:\t\elsewhere` → `False`; `0` files in `C:\t\elsewhere`; `0` G1 log lines at WARNING or above (1 debug line; G2 logs the 1 warning, S6); `0` raises (target (9a))
examples: (LLR-172.1g negative control) a mutation without the reparse check → `1` file in `C:\t\elsewhere` → RED (target (9a))
examples: (LLR-172.1h) `100` distinct records → `100` distinct staging names (a spy on `tempfile.mkstemp`), each with `dir` = `<lad>\s19_app`; `100` `os.replace` calls with target the store; `0` files matching `.recent_sources-*.tmp` left (target (9a))
examples: (LLR-172.1h, S-12, R9) a read of the store file after each of `100` distinct records → it parses as schema 1 every time (`100` of `100`), `0` partial files: a reader sees the old or the new file (no thread arm: every record runs on the UI thread) (target (9a))
examples: (LLR-172.1h negative control) a fixed staging name → `1` distinct name in 100 → RED; writing the store in place → `0` `os.replace` calls → RED (target (9a))
examples: (LLR-172.1i) `os.replace` raising `PermissionError` (injected) → `False`; the store's SHA-256 unchanged; `0` staging files left; `0` G1 warnings (G2 logs 1, S6); `0` raises (target (9a))
examples: (LLR-172.1i) `tempfile.mkstemp` raising `OSError` (injected) → `False`; the store's SHA-256 unchanged; `0` staging files; `0` G1 warnings (G2 logs 1, S6); `0` raises (target (9a))
examples: (LLR-172.1i negative control) a mutation letting the `OSError` out → the call raises (and G2's load stops before the install) → RED (target (9a))
examples: (LLR-172.1j) a store with 2 accepted entries and 3 refused ones (`\\host\share\x.s19`, `kind: exe`, a path holding `\x1b[2J`), then 1 record of `<src>\n.s19` → `3` entries, `<src>\n.s19` first, `0` refused (target (9a))
examples: (LLR-172.1j) an unparseable store `{not json` → after 1 record: `1` entry; a 65 537-byte store → after 1 record: `1` entry (target (9a))
examples: (LLR-172.1j negative control) a mutation carrying the raw entries forward → the UNC entry written back → RED (target (9a))
examples: (LLR-172.1k, U-2, R-2) a store with 3 entries; `open` of the store raising `PermissionError` (injected, as a transient sharing violation), then the read raising `OSError` (injected) → `False` each; the store's SHA-256 unchanged (not overwritten with 1 entry); `0` staging files; `1` debug line each (2 of 2) (target (9a))
examples: (LLR-172.1k negative control) a mutation treating "could not be read" as `()` → the store rewritten with `1` entry → RED (target (9a))
examples: (LLR-172.1l, U-1) a store with 1 entry; `record_recent_source(Path(r"\\host\share\x.s19"))`, a source `C:\t\src\a` + U+009B + `.s19` and `C:\CON\a.s19` → `False` each, the store's SHA-256 unchanged, `0` staging files (3 of 3); `C:\t\src\b.s19` → `True`, `2` entries (control) (target (9a))
examples: (LLR-172.1l negative control) a mutation skipping step (4) → the UNC entry is written (SHA-256 changed) and dropped again by the next read → RED (target (9a))
examples: (LLR-172.1m) a store with 19 entries of `3 245`×`p`, then 1 record of a 20th such path → `True`, `19` entries, the oldest dropped, file ≤ `65 536` bytes; 1 record of `C:\` + `11 000`×`é` + `.s19` → `False`, the store's SHA-256 unchanged (target (9a))
examples: (LLR-172.1i, never raises) `Path("C:\\t\\a\x00.s19")` → `os.path.abspath` raises `ValueError` (embedded NUL) → `False`, `0` raises (target (9a))
examples: (LLR-172.1d, seam S1) G1 cannot see a copy; the 4 failure arms (a missing path, an unsupported suffix, an over-cap source, a project already holding an A2L) reach no call of `record_recent_source` (a spy: `0` calls) → the store's SHA-256 unchanged; the arm belongs to G2's call order (target (9a))
examples: (LLR-172.1e, seam S2) `record_recent_source(Path(r"C:\t\base\.s19tool\workarea\ab\firmware.s19"))` called directly → `True`, `1` entry (G1 does not check "inside"); the requirement's `0` entries for the 3 inside arms holds through G2: `0` calls (a spy) (target (9a))
examples: (LLR-172.3 arm 1, R-9) a store with 3 entries under `C:\t\m4rk3r-9a\`, then 1 record of `<src>\b.s19` → `4` entries in the store (outside `<base>`); `0` log lines holding `m4rk3r-9a`; `0` files written under `<base>` by G1 (target (9a))
examples: (LLR-172.3 arm 2) 1 record of `C:\t\m4rk3r-9b\firmware.s19` → `m4rk3r-9b` written only to `<lad>\s19_app\recent_sources.json`; `0` files written under `<base>` by G1; `0` G1 log lines holding it (success logs nothing) (target (9a))
examples: (HLR-172) 25 distinct outside sources → `20` entries, newest first, at `<lad>\s19_app\recent_sources.json`; `0` files named `recent_sources.json` under `<base>` (`.s19tool` included) (target (9a))

list_workarea_files
req: LLR-172.4, LLR-172.4a, LLR-172.4b, LLR-172.4c, HLR-172b, LLR-172.6, LLR-172.6a
in: Path workarea
out: list[Path] files
func: new (interfaces-9a.md). The one enumeration of the temp folder (LLR-172.4). `temp_dir = workarea / WORKAREA_TEMP`; `_is_reparse_point(temp_dir)` → `[]` (P9a-G1-5 accepted; LLR-172.4c after E3 R11); `with os.scandir(temp_dir) as it:` keep each entry with `entry.is_file(follow_symlinks=False)` (a directory, `.staging` included, and a symbolic link are out by the cached type) **and** `not _is_reparse_point(Path(entry.path))` (a non-symlink reparse point is out too; two gates so a failed `lstat`, which `_is_reparse_point` reports as `False`, still cannot let a symbolic link through, LLR-172.4b). Any `OSError` from `scandir` or the iteration — missing folder, `NotADirectoryError`, `PermissionError` — → `[]`, never a partial list (LLR-172.4c). Returns `Path(entry.path)` objects with the on-disk name untouched (no scrub, no `safe_text`: seam S3; the label is G2's), sorted by `(name.casefold(), name)` (U-3). Not recursive. Logs nothing. Never raises. Census shape: the `os.scandir` call takes `temp_dir`, a name bound to `workarea / WORKAREA_TEMP` in the same function, so the AST census of TC-B100-37 counts it (seam S8).
module: s19_app/tui/workspace.py
modify: [I/O: workarea temp] (read)
examples: (LLR-172.4a) `temp` holds `b.s19`, `a.hex`, `c.a2l` → `[<wa>\temp\a.hex, <wa>\temp\b.s19, <wa>\temp\c.a2l]` (target (9a))
examples: (LLR-172.4a) `temp\.staging\` holding 1 file and `temp\sub\x.s19` → `0` of them returned; an empty `temp` → `[]` (target (9a))
examples: (LLR-172.4a negative control) a recursive listing → the `.staging` file and `sub\x.s19` returned → RED; no sort → the order arm RED (target (9a))
examples: (LLR-172.4b) `temp\l.s19`, a file symbolic link to `C:\t\out.s19`, beside `a.s19` → `[<wa>\temp\a.s19]`; reported not run when the platform refuses to create the link (target (9a))
examples: (LLR-172.4b negative control) a mutation using `Path.is_file()` (follows the link) without the link gate → `l.s19` returned → RED (target (9a))
examples: (LLR-172.4c) `temp` removed → `[]`, `0` raises; `os.scandir` raising `PermissionError` (injected) → `[]`, `0` raises; `temp` a regular file → `[]` (target (9a))
examples: (LLR-172.4c negative control) a mutation without the catch → the injected arm raises → RED (target (9a))
examples: (LLR-172.4, seam S8) the AST census of `s19_app/` after 9a → `1` function, `list_workarea_files` in `workspace.py`; `_private_stage_dir` (`workspace.py:566`) builds a temp path but enumerates nothing → not counted (target (9a))
examples: (HLR-172b, LLR-172.6, seam S3, AT-B100-13) `temp` holds `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, `x` + U+009B + `.s19`, `x` + U+202E + `gpj.s19` and `a` + U+DC80 + `b.s19` → `6` paths whose `.name` equals each on-disk name exactly, the U+009B, U+202E and U+DC80 included (G2 paints `painted_names([p.name])`, E3 R4) (target (9a))
examples: (LLR-172.6a, seam S3) the U+009B path's `.name` is the text G2 puts in `item.data`; `<wa>\temp\` + that name exists → the pick loads the file of that exact name (target (9a))
examples: (U-3) `B.s19`, `a.hex` → `[a.hex, B.s19]` (case-folded order, as the base `sorted(Path)` gives on Windows) (target (9a))
examples: (LLR-172.4c, R11, U-6) `temp` itself a junction to `C:\t\elsewhere` holding `z.s19` → `[]`; reported not run when no junction can be made (target (9a))
examples: (LLR-172.4c negative control, R11) a mutation without the `temp_dir` link check → `[<wa>\temp\z.s19]` → RED (target (9a))
examples: (ruling C7) `temp` holds `x.a2l` and its dump `x.a2l.json` → both returned (today's file set kept) (target (9a))

_is_reparse_point
req: LLR-172.1g, LLR-172.4b
in: Path path
out: bool is_link
func: unchanged (`workspace.py:207`). `Path.is_symlink()`, then on win32 the `FILE_ATTRIBUTE_REPARSE_POINT` bit of `os.lstat`; a missing path or an `OSError` → `False`. Used by `record_recent_source` on the store folder and by `list_workarea_files` on `temp` and each entry. Its `OSError → False` is why the lister keeps a second gate (`is_file(follow_symlinks=False)`).
module: s19_app/tui/workspace.py
examples: (LLR-172.1g) `<lad>\s19_app` a junction → `True` (holds)
examples: (LLR-172.4b) `temp\l.s19` a file symbolic link → `True`; `temp\a.s19` a regular file → `False`; a missing path → `False` (holds)

is_windows_device_name
req: LLR-172.2f
in: str name
out: bool is_device
func: unchanged (`workspace.py:1833`). The shared device-name predicate (stem before the first dot, trailing spaces and dots stripped, case-folded, superscript digits mapped). `_recent_entry_ok` calls it for every component after the drive.
module: s19_app/tui/workspace.py
examples: (LLR-172.2f) `NUL.s19` → `True`; `CON` → `True`; `com1.s19` → `True`; `console.s19` → `False` (holds, HLR-164 tests)

## Entities

[I/O: recent-sources store]
desc: `%LOCALAPPDATA%\s19_app\recent_sources.json`, per user, outside every base folder; schema `{"schema_version": 1, "sources": [{"path", "kind"}, …]}`, at most 20 entries and 65 536 bytes; written only by `record_recent_source`, read only by `read_recent_sources` (G2 reads nothing at 9a; 9b's dialog reads it)
sequence:
  record: record_recent_source → recent_store_path → recent_kind → os.path.abspath → _recent_entry_ok (refuse a path the read would drop) → mkdir(parents=False) → _is_reparse_point (refuse a link) → read_recent_sources (refuse "could not be read") → _encode_recent_store (≤ 65 536 bytes) → mkstemp → os.replace (!) (the one write; UI thread only, no lock)
  read: read_recent_sources → recent_store_path → _is_reparse_point (folder, file) → open → read(65 537) → decode → json.loads → shape → _recent_entry_ok × n (!) (returns; never writes)

## Seams with G2 (`app.py`)

| Id | Seam | G1 promise | G2 duty | Examples naming it |
|---|---|---|---|---|
| S1 | record call after copy | `record_recent_source` is safe on the calling (main) thread: one bounded read (≤ 65 537 bytes), one write (≤ 65 536 bytes), one lexical `abspath` (no source I/O, no network call); never raises | call it only after `copy_into_workarea` returned, in `load_from_path` and `load_a2l_from_path` (ruling Q1/C1); never before the copy (LLR-172.1d) | record: LLR-172.1d |
| S2 | "inside the work area" = caller | no inside check in G1; an inside path given directly is recorded | `if not contained_in_workarea(source, self.workarea)` before the call (LLR-172.1e: typed `<wa>\ab\firmware.s19`, the `.a2l` work-copy pick, the variant switch → 0 calls) | record: LLR-172.1e |
| S3 | lister returns Paths; caller uses `.name` | `list_workarea_files` returns `Path`s with the raw on-disk name, sorted, links and folders out | label `painted_names([p.name])` with markup off (E3 R4); `item.data = p.name`; the pick reads `item.data` (ruling C5) | lister: HLR-172b, LLR-172.6, LLR-172.6a |
| S4 | `None` store path = no write, no status | `recent_store_path()` → `None`; `record_recent_source` → `False` with no file, no folder, 1 debug line | paint no status line; log the 1 warning of S6 (G2 P-2 accepted) | recent_store_path: LLR-172.1f; record: LLR-172.1f |
| S5 | store problem word | `RECENT_PROBLEM_TOO_LARGE`, `RECENT_PROBLEM_UNREADABLE` exported (P9a-G1-3) | none at 9a (no G2 reader); 9b paints them | RecentSources: LLR-172.2a, .2c |
| S6 | who logs a failed record | `record_recent_source` logs nothing at WARNING or above, and no line that holds a path (P9a-G1-1 rejected) | `if not record_recent_source(...)`: exactly 1 warning (G2 P-2 accepted) — the "1 log warning" of LLR-172.1i | record: LLR-172.1g, .1i |
| S7 | the argument of the record call | records `os.path.abspath(str(arg))` (E3 R1; G2 P-1 revoked) | pass the source G2 copied from (`normalized`), never `copied` (the work copy) | record: LLR-172.1a |
| S8 (test seam) | the TC-B100-37 census shape | the only temp enumeration is `os.scandir(temp_dir)` with `temp_dir = workarea / WORKAREA_TEMP` in `list_workarea_files` | remove `temp_dir.glob("*")` from `refresh_files` (`app.py:7313`); the census test must count `os.scandir` on a name bound to a `WORKAREA_TEMP` path | lister: LLR-172.4 |
| S9 | `LOCALAPPDATA` read at call time | `recent_store_path` reads `os.environ` on every call, never at import (G2 P-3 accepted) | the C8 autouse fixture in `tests/conftest.py` relies on it | recent_store_path: S9 |
| S10 | every suffix G2 routes has a kind | `recent_kind` maps exactly `SUPPORTED_EXTENSIONS` ∪ `A2L_EXTENSIONS` (`workspace.py:107-111`) | G2 sends only those suffixes to the load functions | recent_kind: LLR-172.1a |

## Findings

### Design decisions taken inside the interface (no interface change)

- **D-1** `recent_store_path` uses the same drive-rooted regex as LLR-172.2e for "absolute drive-rooted" (LLR-172.1f), so a UNC `LOCALAPPDATA` is unusable too.
- **D-2** `recent_kind` and `_recent_entry_ok` use `PureWindowsPath` rules on every host, so the read-side checks give the Windows answer on the Linux CI (R-1).
- **D-3** Store bytes: `json.dumps(..., ensure_ascii=True, separators=(",", ":"))`, ASCII. `ensure_ascii=True` keeps a lone-surrogate file name valid JSON (probe p9a-g1); `ensure_ascii=False` would raise `UnicodeEncodeError` on encode.
- **D-4** `read_recent_sources` maps `FileNotFoundError` and `NotADirectoryError` to "missing" (no problem) and every other open/read `OSError` to "could not be read".

### Design risks. R-1 to R-11. Seams with G2 are marked "seam".

finding R-1 The CI runs on Linux, where the store is off by requirement (seam: tests)
anchor: recent_store_path; LLR-172.1f; `.github/workflows/tui-ci.yml:25` `runs-on: ubuntu-latest`
seen: LLR-172.1f refuses a `LOCALAPPDATA` that is not drive-rooted. The autouse fixture of ruling C8 sets `LOCALAPPDATA` to `tmp_path`, which on Linux is `/tmp/…` → `None` → every write arm of TC-B100-34 and AT-B100-12's store half writes nothing on CI. `os.path.normcase` is the identity on Linux, so the case arm of LLR-172.1b cannot hold there either.
cause: the requirement is Windows-only by construction (`%LOCALAPPDATA%`); the CI host is not.
effect: on CI the write arms fail, or they are skipped. Read-side arms (LLR-172.2*) can still run on CI by patching `recent_store_path` to a `tmp_path` file, because D-2 makes the entry checks host-independent.
decision: proposed P9a-G1-6 — the write arms carry a `win32` skip reported as "not run" on CI (never passed) and are executed on Windows for the gate; the read arms and the lister arms run everywhere. Alternative for the orchestrator: an E1 amendment accepting a POSIX absolute `LOCALAPPDATA` off Windows (wider; the product is a Windows tool).

finding R-2 A transient read failure would wipe the store to one entry
anchor: record_recent_source step (6); LLR-172.1j
seen: LLR-172.1j writes back "only those existing entries that the store read returns"; a read that reports "could not be read" returns `()`.
cause: on Windows a reader in another process (an editor, a backup tool, a second app instance) can make the open fail with a sharing violation for a moment.
effect: written literally, the next record replaces 20 entries with 1. The requirement's thresholds cover only the unparseable and the oversized store (both → 1 entry), not the unreadable one.
decision: P9a-G1-2 accepted, stated as LLR-172.1k (E3 R1) — on "could not be read" the record writes nothing and returns `False`. Unparseable / oversized keep LLR-172.1j's 1-entry rewrite.

finding R-3 The writer can produce a store the reader refuses
anchor: _encode_recent_store; LLR-172.1c, LLR-172.2a
seen: 20 entries is the only bound on the writer; 20 long paths encode above 65 536 bytes (probe: n = 3 245 → 65 592 bytes), and with `ensure_ascii=True` each non-ASCII character costs 6 bytes, so 20 paths of about 550 non-ASCII characters are enough.
cause: no requirement ties the writer's output to the reader's cap.
effect: the next read returns "too large" with 0 entries, and the next record (LLR-172.1j) keeps 1: the whole history is lost on an ordinary load.
decision: P9a-G1-3 accepted and kept by E3 R10 as LLR-172.1m — drop the oldest entries until the payload fits; a single entry that cannot fit is not recorded. The arithmetic (the read has no per-entry length bound; a long-path entry escapes far beyond the 3 250 bytes per entry that 20 entries allow) is that requirement's note.

finding R-4 `json.loads` raises `RecursionError` on a deep array (executed)
anchor: read_recent_sources step (5); LLR-172.2j
seen: probe p9a-g1: `json.loads("[" * 65536)` → `RecursionError`, not a `ValueError` subclass.
cause: the stdlib decoder recurses per nesting level; 65 536 bytes is enough nesting.
effect: a reader that catches `ValueError` only (the usual `JSONDecodeError` idiom) raises out of every read and, through the record, out of the load — LLR-172.2j and LLR-172.1i fail. The 200 random strings of LLR-172.2j's threshold almost never produce this shape, so the threshold alone would not catch it.
decision: catch `(ValueError, RecursionError)`, plus the outer `except Exception` guard; the example "65 536 bytes of `[`" is added to TC-B100-35's hostile set.

finding R-5 `schema_version == 1` accepts `true` and `1.0` (executed)
anchor: read_recent_sources step (6); LLR-172.2b
seen: probe p9a-g1: `True == 1` and `json.loads("1.0") == 1` are both `True`.
cause: Python's numeric equality.
effect: a store with `"schema_version": true` passes a naive check; harmless today, but a future schema 2 that encodes its version as `2.0` or a hostile `true` would be read as 1.
decision: `type(v) is int and v == 1`; two examples added.

finding R-6 Sources on a mapped network drive are never remembered (not run) — CLOSED by E3 R1
anchor: record_recent_source steps (3)–(4); LLR-172.1a (now "absolute path", `abspath`) with LLR-172.2e (drive-rooted)
seen: `Path.resolve()` on Windows asks for the final path; for a mapped SMB drive it can return the UNC form `\\server\share\…`. This machine's `G:` is a virtual drive and resolves to `G:\My Drive` (executed); no SMB drive was available, so the UNC outcome is not run.
cause: LLR-172.1a records the resolved path; LLR-172.2e drops every UNC path.
effect: an engineer loading from a mapped drive gets no recent entry (with P9a-G1-2), or an entry that is written and then dropped on every read (without it). Consistent with S-07's intent (no network touch), but surprising.
decision (superseded by E3 R1): the record uses `os.path.abspath`, which keeps `Z:\…` (it passes LLR-172.2e), so a mapped-drive source is remembered; only a source typed as UNC is refused (LLR-172.1l, declared). A 9a test with a real SMB drive stays "not run"; the junction arm of LLR-172.1a is the executed RED for the `resolve()` mutant.

finding R-7 Cloud placeholder files carry the reparse attribute (not run)
anchor: list_workarea_files; `_is_reparse_point`
seen: OneDrive "Files On-Demand" files carry `FILE_ATTRIBUTE_REPARSE_POINT`.
cause: `_is_reparse_point` treats every reparse point as a link (the HLR-171b stance).
effect: a base folder inside a OneDrive-synced folder would show an empty Workarea Files list. The same predicate already refuses such paths in the placement guards, so this is a pre-existing class, not a 9a regression.
decision: keep the shared predicate (LLR-172.4b names it); note for BACKLOG-CODE; no 9a change.

finding R-8 Two app instances can lose an entry
anchor: record_recent_source; LLR-172.1h
seen: there is no lock (P9a-G1-4 rejected); within one process every record runs on the UI thread, and two processes each read, add, replace.
cause: no cross-process lock.
effect: last writer wins; one recent entry may be lost, and a writer whose `os.replace` meets the other's open handle returns `False` (G2's 1 warning). A reader that meets a replace sees "could not be read" and the record writes nothing (LLR-172.1k). Never a broken store (one-step replace).
decision: accept; the store is a convenience (ruling Q5). LLR-172.1h's thread arm is removed (E3 R9); its whole-file arm stays.

finding R-9 Log lines must never carry store entries
anchor: record_recent_source, read_recent_sources; LLR-172.3 arm 1
seen: the app log lives under `<base>\.s19tool\logs\`, inside the base folder that LLR-172.3 arm 1 scans, log included.
cause: a natural debug line ("store holds …") or a warning that prints the refused entry would copy entries under the base folder.
effect: arm 1 RED.
decision: G1 logs counts, step names, problem words and exception classes only; success logs nothing; no path in any G1 log line (examples on both nodes).

finding R-10 A `LOCALAPPDATA` inside the base folder puts the store under it
anchor: recent_store_path; LLR-172.1 ("0 under base"), LLR-172.3
seen: G1 has no base-folder input; a base folder that is `C:\Users\<user>` or `LOCALAPPDATA` itself contains the store.
cause: the requirement fixes the location; the base folder is the engineer's choice.
effect: the store file is "a file under the base folder" holding entries. Unusual setup; the test fixtures keep the two apart.
decision: n/a at 9a — documented (U-7); no guard, since refusing would need `base_dir` in the store API.

finding R-11 A lone surrogate in a file name
anchor: _encode_recent_store; D-3
seen: Windows file names can hold unpaired UTF-16 surrogates; Python maps them to lone surrogate code points.
cause: UTF-8 cannot encode them.
effect: with `ensure_ascii=False` + UTF-8 the encode raises and the record fails (caught → `False`); with `ensure_ascii=True` they become `\udXXX` escapes and round-trip (probe p9a-g1).
decision: D-3.

### Undecidable points the requirements leave open (each with the recommendation the graph follows)

- **U-1** A source whose absolute path the read would drop (UNC, a control character, a device component). Decided: not recorded (LLR-172.1l, E3 R1).
- **U-2** The record over an unreadable store. Decided: no write (LLR-172.1k, E3 R1).
- **U-3** "Sorted by name" (LLR-172.4a) does not say case-sensitive or not. Recommendation: `(name.casefold(), name)`, which matches the base `sorted(Path)` on Windows and is deterministic on Linux.
- **U-4** Schema details LLR-172.2b/.2i leave open: `schema_version` `true` / `1.0` (refused, R-5); extra keys in an entry (ignored); a UTF-8 BOM (0 entries, no problem).
- **U-5** Duplicates inside a hand-edited store: the read returns both (LLR-172.2 says "in stored order", no de-dup); the record removes only entries equal to the new path. Recommendation: keep (no requirement asks for more).
- **U-6** The temp folder itself a link or junction. Decided: `[]` (P9a-G1-5 accepted; LLR-172.4c's statement after E3 R11).
- **U-7** `LOCALAPPDATA` inside the base folder (R-10): n/a at 9a.
- **U-8** The store file itself a file symbolic link. Reversed by E3 R6: the read refuses a linked store file or folder with "could not be read" and opens nothing (LLR-172.2c); the record then writes nothing (LLR-172.1k).

### Proposals

P9a-G1-1 … P9a-G1-6 are appended to `interfaces-9a.md` §Proposals; the orchestrator's rulings follow them there (P9a-G1-1 and P9a-G1-4 rejected; P9a-G1-2, -3, -5, -6 accepted), and the E3 r1 changes are under "Applied after E3 r1".

## Requirement coverage (G1 scope)

| Requirement | Examples (node) |
|---|---|
| HLR-172 | record (25 → 20, AT-B100-12), RecentEntry |
| HLR-172b | list_workarea_files (4 hostile names) |
| LLR-172.1 | recent_store_path (path, `APPDATA` control) |
| LLR-172.1a | recent_kind (6 kinds, `A.SREC`), RecentEntry, _encode_recent_store, record (4 kinds, `abspath` of a relative path, junction arm, 3 controls) |
| LLR-172.1b | record (4 arms incl. `..`, controls) |
| LLR-172.1c | record (20 / 21 / 25, controls), _encode_recent_store |
| LLR-172.1d | record (seam S1: 0 calls) |
| LLR-172.1e | record (seam S2) |
| LLR-172.1f | recent_store_path (3 arms + forms + POSIX `/tmp/lad` + `home()` control), record (3 arms, missing folder, relative and `parents=True` controls) |
| LLR-172.1g | record (junction, control), _is_reparse_point |
| LLR-172.1h | record (100 names, read after each record, controls) |
| LLR-172.1i | record (2 injected arms, control, `ValueError` arm) |
| LLR-172.1j | record (2 + 3, unparseable, oversized, control) |
| LLR-172.1k | record (2 injected arms, control) |
| LLR-172.1l | record (3 refused paths + 1 kept, control), _recent_entry_ok |
| LLR-172.1m | _encode_recent_store (65 492 / 65 592, one entry too large, control), record (19-entry arm, too-large arm) |
| LLR-172.2 | read (1 000 → 20, order, controls) |
| LLR-172.2a | read (65 536 / 65 537, read size, controls), RecentSources |
| LLR-172.2b | read (5 shapes, `true` / `1.0`, BOM) |
| LLR-172.2c | read (2 arms + 2 link arms, controls), RecentSources |
| LLR-172.2d | read (2 arms, controls), RecentSources |
| LLR-172.2e | _recent_entry_ok (6 forms, 1 kept, control) |
| LLR-172.2f | _recent_entry_ok (3 + `console`, control), is_windows_device_name |
| LLR-172.2g | _recent_entry_ok (4, control) |
| LLR-172.2h | _recent_entry_ok (5 + `A.SREC`), recent_kind |
| LLR-172.2i | _recent_entry_ok (4 malformed) |
| LLR-172.2j | read (`[`×65 536, random set, control), _recent_entry_ok |
| LLR-172.3 | read (arm 1), record (arm 1, arm 2) |
| LLR-172.4 | list_workarea_files (census) |
| LLR-172.4a | list_workarea_files (3 rows, `.staging` / `sub`, empty, control) |
| LLR-172.4b | list_workarea_files (file link, control), _is_reparse_point |
| LLR-172.4c | list_workarea_files (3 arms + junctioned `temp`, 2 controls) |
| LLR-172.6 | list_workarea_files (seam S3: 6 raw names for `painted_names`) |
| LLR-172.6a | list_workarea_files (seam S3: `.name` = `item.data`) |

Out of G1 scope (G2 owns them; no G1 node): HLR-172a, LLR-172.5, LLR-172.5a … LLR-172.5g (`RESERVED_WORKAREA_HOMES` is read unchanged by G2).
