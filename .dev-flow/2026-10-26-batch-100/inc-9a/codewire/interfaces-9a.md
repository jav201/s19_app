# Inc 9a — shared interfaces between G1 (`workspace.py`) and G2 (`app.py`)

Fixed by the orchestrator before E2. A group proposes a change in §Proposals; it never changes an interface alone.

```python
# workspace.py (G1 owns)
RECENT_LIMIT: int = 20

def recent_store_path() -> Optional[Path]:
    """%LOCALAPPDATA%\s19_app\recent_sources.json; None when LOCALAPPDATA is unset, empty or not drive-rooted. Never raises."""

def recent_kind(path: Path) -> Optional[str]:
    """Kind from the loader's own extension sets; None for any other suffix."""

def record_recent_source(path: Path) -> bool:
    """Record one OUTSIDE source (the caller has already checked it is outside the work area).
    Kind via recent_kind; de-dup by normcase(resolve()); newest first; cap RECENT_LIMIT;
    atomic write (mkstemp + os.replace); refuses a link/junction store folder.
    True when written; False on any failure — never raises."""

@dataclass(frozen=True)
class RecentEntry:
    path: str   # absolute source path as recorded
    kind: str   # recent_kind(path)

@dataclass(frozen=True)
class RecentSources:
    entries: tuple[RecentEntry, ...]   # sanitised, newest first
    problem: Optional[str]            # None, or the problem word ("could not be read", …)

def read_recent_sources() -> RecentSources:
    """Bounded read, shape and entry checks; never raises."""

def list_workarea_files(workarea: Path) -> list[Path]:
    """Regular, non-link direct children of workarea/temp, sorted by name; missing/unlistable → []."""
```

```python
# app.py (G2 owns) — consumers
# load_from_path / load_a2l_from_path: after copy_into_workarea succeeds and
#   not contained_in_workarea(source): ok = record_recent_source(source); if not ok: 1 log warning.
# refresh_files: rows from list_workarea_files(self.workarea); label safe_text(p.name); item.data = p.name.
# _load_path_from_user_input: typed routing (§1.3 project definition, link check before resolve) → _route_load_project.
# _handle_load_project: reserved home (case-folded) refused before _project_folder_refusal.
```

Seams (both groups cite these ids in examples): S1 record call after copy · S2 who checks "inside the work area" = caller (G2) · S3 lister returns Paths, caller uses `.name` · S4 `None` store path = no write, no status · S5 store problem word.

## Proposals
*(groups append here; the orchestrator rules)*

### From G1 (`workspace.py`, `proto-9a-workspace.md`)

- **P9a-G1-1 (seam S6, changes the G2 consumer comment)** `record_recent_source` owns the store log: exactly 1 warning per failed write (link folder, `OSError` in mkdir / mkstemp / write / `os.replace`), 1 debug line per skip (no usable `LOCALAPPDATA`, unknown kind, entry the read would drop, unreadable store), nothing on success, never a path. G2 logs nothing on `False`. Why: the bool cannot tell "no store" from "write failed"; the current comment ("if not ok: 1 log warning") gives 2 warnings on a failed write (LLR-172.1i wants 1) and a warning on every load where the store is off (Linux CI, S4).
- **P9a-G1-2 (behaviour inside `record_recent_source`; decides U-1, U-2)** Return `False` and write nothing when (a) the read reports `could not be read` (a transient sharing violation must not wipe 20 entries to 1, R-2), or (b) the new entry fails the read's own entry checks (UNC / mapped drive resolved to UNC, control character, device component: an entry the read would drop on every read, U-1, R-6). Unparseable and oversized stores keep LLR-172.1j's 1-entry rewrite.
- **P9a-G1-3 (new exports + an unstated rule; needs an E1 requirement line)** Add `RECENT_STORE_MAX_BYTES = 65_536`, `RECENT_PROBLEM_TOO_LARGE = "too large"`, `RECENT_PROBLEM_UNREADABLE = "could not be read"` (S5), and a writer size rule: drop the oldest entries until the encoded store is at most 65 536 bytes; one entry that cannot fit is not recorded. Why: 20 long or non-ASCII paths encode above the reader's cap (probe: 20 × 3 245-char paths → 65 592 bytes), and the next record then keeps 1 entry (R-3). No LLR states this today.
- **P9a-G1-4 (internal, but tests rely on it)** A module-level `threading.RLock` held by `record_recent_source` (read-modify-write) and `read_recent_sources`. Makes LLR-172.1h's 2 × 50-thread arm deterministic (100 `True`, 20 entries) and avoids same-process `os.replace` against an open read handle on Windows. Cross-process remains last-writer-wins (R-8).
- **P9a-G1-5 (decides U-6)** `list_workarea_files` returns `[]` when `workarea/temp` itself is a link or junction, as `_private_stage_dir` already refuses to stage there. Not stated by LLR-172.4b (entries only).
- **P9a-G1-6 (test platform; R-1)** CI is `ubuntu-latest`; LLR-172.1f makes the store off for a POSIX `LOCALAPPDATA`, so TC-B100-34's write arms and AT-B100-12's store half cannot pass on CI. Proposal: those arms carry a `win32` skip reported as "not run" on CI and are executed on Windows for the gate; read arms (LLR-172.2*) patch `recent_store_path` and run everywhere (entry checks use `PureWindowsPath`); lister arms run everywhere. Alternative: an E1 amendment accepting a POSIX absolute `LOCALAPPDATA` off Windows.

### From G2 (`proto-9a-app.md`, E2)
- **P-1 (S1).** `record_recent_source` stores `str(path.resolve())` as `RecentEntry.path` (LLR-172.1a "the resolved absolute path"). G2 passes `normalized` from `resolve_input_path`, which can be a working-folder-relative spelling.
- **P-2 (new seam S6).** `record_recent_source` logs nothing at WARNING or above. The caller's single warning on `False` is the "1 log warning" of LLR-172.1i.
- **P-3 (new seam S8).** `recent_store_path()` reads `os.environ["LOCALAPPDATA"]` when called, never at import. The C8 autouse fixture in `tests/conftest.py` depends on this.
- **P-4 (G2 consumers block; finding F-2).** Two lines change.
  - The `_handle_load_project` line becomes: "reserved home (`_is_reserved_home`: trailing dots and spaces stripped, then case-folded) refused before `_project_folder_refusal`". Win32 opens `W/temp.` as `W/temp`; this was executed with a scratch OS probe.
  - The `_load_path_from_user_input` line gains: "via `_typed_load_route`; a reserved name is refused there before any folder listing".
- New seam S7 (no change asked): every suffix G2 routes to a load (`.s19 .srec .hex .ihex .mac .a2l`) has a `recent_kind`.

## Orchestrator rulings on the E2 proposals (pre-E3)

| Proposal | Ruling | Why |
|---|---|---|
| P9a-G1-1 (logging inside `record_recent_source`, S6) | **Rejected** in favour of G2 P-2. | One warning, owned by the caller; the function returns `bool`. |
| G2 P-2 (record logs nothing at WARNING+) | **Accepted.** | Same. |
| P9a-G1-2 (no write when the read reported a problem, or when the new entry would be dropped on the next read) | **Accepted.** `record_recent_source` returns `False` then. | A transient read failure must not wipe the history (R-2/R-3). |
| P9a-G1-3 (writer drops oldest until the encoded store ≤ 65 536 bytes) | **Accepted**; E3 fix adds one ubiquitous LLR in the 172.1 family with a numeric threshold. | The writer must never produce a store the bounded reader refuses. |
| P9a-G1-4 (one lock shared by record and read) | **Rejected.** | Both run on the UI thread; a thread lock does not protect two processes; `mkstemp` + `os.replace` already gives a whole file. Prefer removing to guarding. |
| P9a-G1-5 (lister returns `[]` when `temp` itself is a link) | **Accepted**; E3 fix adds the arm to LLR-172.4*. | Consistent with HLR-171b. |
| P9a-G1-6 (store-write tests run on Windows only; CI Linux skips them) | **Accepted.** The store-off arm (LLR-172.1f) runs on every platform; each Windows-only skip names its reason; the packet declares it. | LLR-172.1f turns the store off without a drive-rooted `LOCALAPPDATA`. |
| G2 P-1 (store keeps `path.resolve()`) | **Accepted.** | De-dup already uses the resolved form. |
| G2 P-3 (`LOCALAPPDATA` read at call time) | **Accepted.** | The C8 fixture depends on it. |
| G2 P-4 (reserved-home check strips trailing dots and spaces before case-folding) | **Accepted**; E3 fix adds `temp.` / `temp ` arms to LLR-172.5g. | Windows opens `W/temp.` as `W/temp` (F-2, OS probe). |
| G2 F-5 / R-6 (a relative typed path resolved by the base fallback follows a junction before the link check) | **Ruled: the project route applies only to an ABSOLUTE typed path**, checked on its lexical form (no `resolve()`) before anything else. A relative typed path keeps today's file route unchanged. E3 fix states this in LLR-172.5/.5a. | Removes the junction-follow path instead of guarding it; Q4 already types absolute paths. |
| G2 F-3 (the over-cap test must patch `copy_into_workarea`'s default) | Tester note. | — |
| G2 R-1 (a project path on the command line opens the Load-result panel at startup) | **Accepted behaviour** (Q2 + Q3). | Same route. |

## Applied after E3 r1

From `../E3-rulings.md` R1–R13 (LED .83). Where a line above disagrees, this section wins; the interfaces above are not edited in place.

```python
# workspace.py (G1 owns) — changes
RECENT_STORE_MAX_BYTES: int = 65_536          # writer cap kept as LLR-172.1m (R10)
RECENT_PROBLEM_TOO_LARGE = "too large"         # S5
RECENT_PROBLEM_UNREADABLE = "could not be read"  # S5

def recent_store_path() -> Optional[Path]:
    """None unless LOCALAPPDATA matches ^[A-Za-z]:[\\/] on every platform (R5); read at call time (S9)."""

def record_recent_source(path: Path) -> bool:
    """Records os.path.abspath(str(path)) (R1; G2 P-1 revoked) — lexical, no link resolved, no network call;
    de-dup by normcase(abspath). Returns False and writes nothing when: no store path (LLR-172.1f);
    the LOCALAPPDATA folder is missing — mkdir(parents=False) creates only s19_app (R7);
    the store folder is a link (LLR-172.1g); the path fails LLR-172.2e/.2f/.2g (LLR-172.1l);
    the read reports "could not be read" (LLR-172.1k); one entry cannot fit 65 536 bytes (LLR-172.1m);
    any OSError in mkdir / mkstemp / write / os.replace (LLR-172.1i). No lock (P9a-G1-4 rejected).
    Logs nothing at WARNING or above, never a path (S6). Never raises."""

def read_recent_sources() -> RecentSources:
    """As above, plus: the store folder or file a link or reparse point -> ((), "could not be read"), 0 bytes read (R6)."""

def list_workarea_files(workarea: Path) -> list[Path]:
    """As above; workarea/temp itself a link or junction -> [] (LLR-172.4c after R11)."""
```

```python
# app.py (G2 owns) — consumers, changes
# load_from_path / load_a2l_from_path: unchanged call; if not ok: exactly 1 log warning (S6, G2 P-2).
# refresh_files: label Label(safe_text(painted_names([p.name]))) (R4); item.data = p.name (C5).
# _typed_load_route step 0: Path(text).is_absolute() false -> file branch only; a folder ->
#   ("refuse", "not a supported file") (R2, LLR-172.5h). Absolute: abspath -> link walk ->
#   name matched by normcase against list_projects(); the on-disk name is routed (R3);
#   old step 10 (_project_folder_refusal again) removed (R13).
# _handle_load_project: after _project_folder_refusal and exists(), a name list_projects does not
#   list (normcase) -> "not a project" / "pick a project in the list"; a match continues with the
#   on-disk name (R3). _is_reserved_home and the trailing-dot strip of P-4 are removed.
```

- **R3 check (`4fef292`, code read):** `list_projects` (`app.py:12057-12087`) skips every entry whose case-folded on-disk name is in `RESERVED_WORKAREA_HOMES` (`workspace.py:43-53`, 9 names), and `iterdir` yields long names only — it already excludes every reserved home, so no reserved arm stays.
- **Seams renumbered (R8), one meaning in both graphs:** S1 record after copy · S2 inside test = caller · S3 lister returns `Path`s · S4 `None` store path · S5 problem word · S6 who logs (G2's 1 warning only) · S7 argument of the record call (`normalized`, recorded as `abspath`) · S8 TC-B100-37 census shape · S9 `LOCALAPPDATA` read at call time (G2 P-3; was G2 "S8") · S10 every routed suffix has a kind (was G2 "S7"). The E2 texts above that say "S6 / S7 / S8" keep their E2 numbering.
- **Requirements added:** LLR-172.1k, LLR-172.1l, LLR-172.1m, LLR-172.5h. **Requirements changed:** HLR-172, HLR-172a, LLR-172.1a, .1b, .1f, .1h, .1j, LLR-172.2c, LLR-172.4c, LLR-172.5, .5a, .5b, .5c, .5d, .5g, LLR-172.6, .6a.
- **Dropped:** the C8 edits to `tools/e13/run.py` and `docs/images/capture_readme_media.py` (R13); the 2 × 50-thread arm of LLR-172.1h (R9); G1's `_RECENT_LOCK` and its own warnings (R8).
- **Census:** `_handle_load_project` is called from 20 test files at `4fef292` (G2 F-1); E1-scope §3's "13" is stale.
