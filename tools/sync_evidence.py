"""
Visual-evidence sync — the vault gallery refresh, as code instead of prose.

This module copies the generated pilot evidence (`tests/_artifacts/{svgs,gifs}/`)
into the Obsidian vault gallery that `visual-evidence.md` indexes, and it exists
because **every guard below is a failure that already happened.** The helper it
replaces lived as PowerShell quoted inside `visual-evidence.md` §5, and §6 of that
same note records the verdict this module is the answer to: *"a warning in prose
next to the helper is not a guard on the helper."* Six syncs have now had to
remember a rule that was written down beside the code rather than inside it, and
two of them forgot.

It does **not** regenerate. `pytest -m slow tests/test_examples_pilot_gifs.py`
regenerates; this module syncs. Keeping the two apart is what lets
:func:`assert_capture_coherent` mean anything at all — a helper that regenerates
and then copies can only ever find the capture it just made.

The seven guards, each named with the failure it prevents:

1. :func:`assert_capture_coherent` — **the half-capture.** `tests/_artifacts/`
   once held 65 SVGs dated 2026-08-13 and exactly 15 dated 2026-08-24, every one
   of the 15 a `frame_00_Loaded.svg`: the signature of the render loop writing
   frame 00 and then dying on a missing Pillow import before frame 01. Copying
   that set publishes an incoherent gallery in which two thirds of the frames
   show one UI and one third shows another. The guard clusters source mtimes by
   gap and refuses a set that spans more than one run.

2. :func:`assert_cases_complete` — **the same failure, caught by a second and
   independent property.** A mtime threshold is a tunable number; "every live
   case carries exactly its five frames and one gif" is not. The 2026-08-24
   remnant fails this one with no threshold to argue about.

3. :func:`verify_landed` — **the vacuous verification.** Checking that the copy
   worked by comparing GIFs proves nothing: measured three separate times, the
   15 GIFs come back byte-identical while 75 of 75 SVGs change, because the GIFs
   render narrative state counters rather than rasterising the UI. Timestamps are
   worse than useless — the copy rewrites the mtime whether or not it wrote the
   bytes it meant to. So verification is a per-file content hash **re-read from
   disk after writing**, and the report separates SVG from GIF so that a
   GIF-shaped answer can never stand in for an SVG-shaped question.

4. :func:`flat_destination` — **the duplicate layout that drifted.** The frames
   were once stored twice, flat and nested under `svgs/<case>/`, because a sync
   reached for a recursive copy. That happened three times against a §6 warning
   written specifically to prevent it, and by the time the nested set was deleted
   on 2026-08-31 five of the eighty pairs had already diverged. The vault layout
   is flat, and this function refuses to produce any destination outside the one
   flat directory. The source walk is one level deep by construction.

5. :func:`count_evidence` — **the count that lied by 18 days.** A directory
   listing of the gallery reported "195 files, newest 2026-08-25"; 19 of those
   files were `desktop.ini` and only 176 were evidence. Counting is by extension,
   never by listing, and `desktop.ini` is excluded by name and reported
   separately so that its absence from the count is visible rather than assumed.

6. :data:`RETIRED_CASES` — **the retired case re-stamped as fresh.** The pilot
   suite stopped generating `pv__case_06_large_nested_a2l` at batch-36 (a ~490 s
   runtime, a perf exclusion), but `tests/_artifacts/` is gitignored and nothing
   cleans it, so the 2026-07-08 output is still physically on disk. A blanket
   glob copies it and re-dates a retired asset as current. The exclusion is an
   exact-name set, **never a glob**: `case_06_large_nested_a2l` without the
   `pv__` prefix is a LIVE case with live evidence, and a careless `*case_06*`
   deletes it.

7. :func:`reject_check` — **the gallery that froze for six weeks.** From
   2026-05-22 to 2026-07-02 the gallery was stale and nothing noticed, because
   the copy was an unverified manual side-channel. The check fails the process
   (non-zero exit) when any live vault asset predates the merge date it is given.

And one thing that is not a guard but a debt being paid: every overwrite copies
the previous bytes aside first (:func:`backup_path`). Six syncs in a row recorded
the same regret — the vault copies were overwritten in place, so all that could
ever be shown afterwards was a pair of hashes, never a textual old-vs-new diff of
the same file. The backups make the next refresh able to answer *what* changed.

Nothing here deletes. Overwrite only.

Scope: the **pilot** evidence (`assets/pilot/{svgs,gifs}`). The baseline snapshots
under `assets/snapshots/` are deliberately out — `/dev-flow-sync` §5.5 rules them
out of the sync step because they are canonical-CI artifacts and env-sensitive.

A note on the failure this rewrite retires structurally rather than by guarding:
the PowerShell helper silently copied nothing when `-LiteralPath` was omitted,
because the frame filenames contain `[...]` which PowerShell parses as a wildcard.
Prose warned about it four times. `pathlib` does no glob expansion on a path
object, so in this module the failure class does not exist to be warned about.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import shutil
import sys
from pathlib import Path
from typing import NamedTuple, Sequence

# --- Domain constants -------------------------------------------------------
#
# These are the facts the copy is built on. They are constants and not arguments
# because every one of them was, at some point, a thing a sync had to remember.

#: Pilot cases the suite no longer generates. Matched by EXACT equality, never by
#: glob. `tests/test_examples_smoke.py:244` actively asserts this id stays out of
#: the discovered set, so the suite cannot regenerate this evidence even if asked;
#: the 2026-07-08 output nonetheless sits in the gitignored `_artifacts/` forever.
#: DO NOT turn this into a pattern: `case_06_large_nested_a2l` (no `pv__`) is LIVE.
RETIRED_CASES = frozenset({"pv__case_06_large_nested_a2l"})

#: Files that are on disk in the evidence folders and are not evidence. Windows
#: writes `desktop.ini` into any folder Explorer has touched; nineteen of them
#: once inflated a gallery count by 19 files and its "newest asset" date by 18
#: days. Counted separately, never as evidence.
NON_EVIDENCE_NAMES = frozenset({"desktop.ini"})

#: The two evidence extensions. Counting is by these, never by directory listing.
EVIDENCE_SUFFIXES = (".svg", ".gif")

#: Every live case renders exactly this many SVG frames and exactly one GIF.
#: The half-run of 2026-08-24 produced 1 frame per case; this is the property
#: that rejects it without appeal to any tunable threshold.
FRAMES_PER_CASE = 5
GIFS_PER_CASE = 1

#: Two source assets written more than this many seconds apart belong to
#: different runs. Derived, not typed: the whole 15-case suite takes ~57 s and its
#: slowest single case ~9.4 s, so the largest gap possible *inside* one run is
#: bounded by one case's render time. 60 s is six times the observed within-run
#: maximum and four orders of magnitude below the smallest real cross-run gap
#: seen (11 days, 2026-08-13 to 2026-08-24).
DEFAULT_MAX_GAP_SECONDS = 60.0


class SyncError(Exception):
    """A guard refused. The message names the offending files."""


class Plan(NamedTuple):
    """One file to copy, with its source and its single legal destination."""

    src: Path
    dst: Path
    case: str
    kind: str  # "svg" | "gif"


class Outcome(NamedTuple):
    """What a single planned copy turned out to be, decided by content hash."""

    plan: Plan
    status: str  # "new" | "changed" | "identical" | "FAILED"
    src_hash: str
    dst_hash_before: str | None
    dst_hash_after: str | None
    backup: Path | None


# --- Counting ---------------------------------------------------------------


def count_evidence(root: Path, recursive: bool = False) -> dict[str, int]:
    """Count evidence **by extension**, and report the non-evidence separately.

    The failure this replaces: a directory listing of the gallery reported "195
    files, newest 2026-08-25" and 19 of them were `desktop.ini`. Only 176 were
    evidence, and the newest evidence was 18 days older than the reported date.

    A second, tool-shaped half of the same trap, recorded in the note: `desktop.ini`
    is a HIDDEN system file, so PowerShell's `Get-ChildItem` omits it unless passed
    `-Force` while `find`, `ls -a` and Explorer all see it — *which tool you count
    with changes the answer*. `Path.iterdir` sees hidden files, so this function
    counts the same way regardless of who asks.
    """
    walker = root.rglob("*") if recursive else root.iterdir()
    counts = {"svg": 0, "gif": 0, "non_evidence": 0, "other": 0}
    for entry in walker:
        if not entry.is_file():
            continue
        if entry.name in NON_EVIDENCE_NAMES:
            counts["non_evidence"] += 1
        elif entry.suffix.lower() == ".svg":
            counts["svg"] += 1
        elif entry.suffix.lower() == ".gif":
            counts["gif"] += 1
        else:
            counts["other"] += 1
    return counts


def is_evidence(path: Path) -> bool:
    """True for a file that counts as evidence: right extension, not `desktop.ini`."""
    return path.name not in NON_EVIDENCE_NAMES and path.suffix.lower() in EVIDENCE_SUFFIXES


def is_retired(case: str) -> bool:
    """Exact-name membership. See :data:`RETIRED_CASES` for why never a glob."""
    return case in RETIRED_CASES


# --- Guard 1 & 2: the capture must be one coherent run ----------------------


def _cluster_by_gap(
    stamped: Sequence[tuple[float, Path]], max_gap: float
) -> list[list[tuple[float, Path]]]:
    """Split mtime-sorted files wherever consecutive writes are more than `max_gap` apart."""
    clusters: list[list[tuple[float, Path]]] = []
    for item in sorted(stamped):
        if clusters and item[0] - clusters[-1][-1][0] <= max_gap:
            clusters[-1].append(item)
        else:
            clusters.append([item])
    return clusters


def assert_capture_coherent(
    plans: Sequence[Plan],
    max_gap: float = DEFAULT_MAX_GAP_SECONDS,
    allow_recapture: bool = False,
) -> list[list[tuple[float, Path]]]:
    """Refuse a source set that was written by more than one run.

    Returns the mtime clusters when it accepts, so the caller can print them —
    a guard that reports only "ok" teaches the reader nothing about what it saw.

    `allow_recapture` is **not** a blanket override, because a blanket override is
    how a guard becomes decoration. It permits several clusters only when each
    cluster is *case-complete*: every case a cluster touches is wholly inside it,
    all five frames and its gif. That is exactly the shape of a deliberate re-run
    of one case (which happens — `case_00_public` was re-captured on 2026-08-31 to
    prove the SVG delta was real drift and not run-to-run noise), and it is
    exactly NOT the shape of the 2026-08-24 half-run, whose second cluster held
    one frame for each of fifteen cases and completed none of them.
    """
    stamped = [(p.src.stat().st_mtime, p.src) for p in plans]
    clusters = _cluster_by_gap(stamped, max_gap)
    if len(clusters) == 1:
        return clusters

    def _fmt(ts: float) -> str:
        return _dt.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")

    summary = "\n".join(
        f"  run {i + 1}: {len(c)} file(s), {_fmt(c[0][0])} .. {_fmt(c[-1][0])}"
        f"\n    {', '.join(sorted(p.name for _, p in c)[:8])}"
        + ("  ..." if len(c) > 8 else "")
        for i, c in enumerate(clusters)
    )

    if not allow_recapture:
        raise SyncError(
            f"INCOHERENT CAPTURE: source assets span {len(clusters)} separate runs "
            f"(gap threshold {max_gap:g}s). Copying this publishes a gallery whose "
            f"frames disagree with each other. Re-run the suite, or pass "
            f"--allow-recapture if every extra run re-captured whole cases.\n" + summary
        )

    # Case-complete check, per cluster.
    by_cluster_case: list[dict[str, int]] = []
    for cluster in clusters:
        seen: dict[str, int] = {}
        paths = {p for _, p in cluster}
        for plan in plans:
            if plan.src in paths:
                seen[plan.case] = seen.get(plan.case, 0) + 1
        by_cluster_case.append(seen)

    expected = FRAMES_PER_CASE + GIFS_PER_CASE
    partial = [
        f"  run {i + 1}: case {case!r} has {n} of {expected} assets in this run"
        for i, seen in enumerate(by_cluster_case)
        for case, n in sorted(seen.items())
        if n != expected
    ]
    if partial:
        raise SyncError(
            "INCOHERENT CAPTURE: --allow-recapture was given, but a run is not "
            "case-complete — this is the half-run signature, not a re-capture.\n"
            + "\n".join(partial)
            + "\n"
            + summary
        )
    return clusters


def assert_cases_complete(plans: Sequence[Plan]) -> dict[str, dict[str, int]]:
    """Refuse unless every live case carries exactly 5 frames and 1 gif.

    The second, threshold-free half of the half-capture guard. The 2026-08-24
    remnant had fifteen cases holding one frame each; no argument about how many
    seconds a run may span is needed to reject that.
    """
    tally: dict[str, dict[str, int]] = {}
    for plan in plans:
        tally.setdefault(plan.case, {"svg": 0, "gif": 0})[plan.kind] += 1
    bad = [
        f"  {case}: {t['svg']} frame(s) (want {FRAMES_PER_CASE}), "
        f"{t['gif']} gif(s) (want {GIFS_PER_CASE})"
        for case, t in sorted(tally.items())
        if t["svg"] != FRAMES_PER_CASE or t["gif"] != GIFS_PER_CASE
    ]
    if bad:
        raise SyncError(
            "INCOMPLETE CAPTURE: case(s) do not carry a full frame set. This is the "
            "signature of a run that died partway (the render loop writes frame 00, "
            "then fails before frame 01).\n" + "\n".join(bad)
        )
    return tally


# --- Guard 4: the layout is flat ------------------------------------------------


def flat_destination(svgs_root: Path, case: str, filename: str) -> Path:
    """The one legal destination for a frame, and a refusal for anything else.

    The vault layout is flat: `pilot_<case>_frame_NN_<State>.svg`, directly under
    `assets/pilot/svgs/`. The nested `svgs/<case>/` layout was pruned at batch-47,
    re-created by a recursive copy, warned against in §6, re-created again at
    batch-77, and deleted a second time on 2026-08-30 — four occurrences of one
    cause. §6's own closing line asks for exactly this: *"closed by making the
    helper itself refuse to write into `svgs/<case>/`, not by another warning."*
    """
    dst = svgs_root / f"pilot_{case}_{filename}"
    resolved_root = svgs_root.resolve()
    if dst.resolve().parent != resolved_root:
        raise SyncError(
            f"NESTED LAYOUT REFUSED: destination {dst} does not sit directly in "
            f"{svgs_root}. The vault layout is flat; a nested svgs/<case>/ tree is "
            f"the duplicate that drifted (5 of 80 pairs diverged before it was removed)."
        )
    return dst


def build_plan(artifacts_root: Path, vault_assets: Path) -> list[Plan]:
    """Enumerate exactly what to copy. One level deep, retired cases dropped by name.

    The source walk is non-recursive **by construction**, not by a flag that a
    later author can flip: `iterdir()` over the case directories, then `glob` (not
    `rglob`) inside each. There is no `-Recurse` here to reach for.
    """
    svgs_src = artifacts_root / "svgs"
    gifs_src = artifacts_root / "gifs"
    svgs_dst = vault_assets / "pilot" / "svgs"
    gifs_dst = vault_assets / "pilot" / "gifs"
    for required in (svgs_src, gifs_src, svgs_dst, gifs_dst):
        if not required.is_dir():
            raise SyncError(f"missing directory: {required}")

    plans: list[Plan] = []
    for case_dir in sorted(d for d in svgs_src.iterdir() if d.is_dir()):
        case = case_dir.name
        if is_retired(case):
            continue
        for svg in sorted(f for f in case_dir.glob("*.svg") if is_evidence(f)):
            plans.append(
                Plan(svg, flat_destination(svgs_dst, case, svg.name), case, "svg")
            )
    for gif in sorted(f for f in gifs_src.glob("*.gif") if is_evidence(f)):
        case = gif.stem
        if is_retired(case):
            continue
        plans.append(Plan(gif, gifs_dst / gif.name, case, "gif"))
    if not plans:
        raise SyncError(f"nothing to copy: no live evidence under {artifacts_root}")
    return plans


# --- Guard 3: verify by content, re-read from disk ------------------------------


def file_hash(path: Path) -> str:
    """SHA-256 of the bytes on disk. The only evidence that a copy landed."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_path(backup_root: Path, dst: Path, vault_assets: Path) -> Path:
    """Where the bytes about to be overwritten are kept.

    Six consecutive syncs recorded the same regret in `visual-evidence.md`: *"the
    vault copies were overwritten in place, so the previous bytes are gone and no
    textual old-vs-new diff of the same file is possible."* Only the before/after
    hash pair survived, which answers *whether* a frame changed and never *what*
    changed in it. Backups are taken only when the bytes actually differ — an
    identical overwrite has nothing to diff.
    """
    try:
        rel = dst.resolve().relative_to(vault_assets.resolve())
    except ValueError:
        rel = Path(dst.name)
    return backup_root / rel


def execute(
    plans: Sequence[Plan],
    vault_assets: Path,
    backup_root: Path | None,
    dry_run: bool,
) -> list[Outcome]:
    """Copy, then **re-read the destination from disk** and compare hashes.

    Never a timestamp: the copy rewrites the mtime whether or not the bytes it
    intended to write arrived. Never the GIFs alone: measured three times, all 15
    GIFs come back byte-identical across a UI change that moved 75 of 75 SVGs,
    because they render narrative state counters rather than the UI.
    """
    outcomes: list[Outcome] = []
    for plan in plans:
        src_hash = file_hash(plan.src)
        before = file_hash(plan.dst) if plan.dst.exists() else None
        backup: Path | None = None

        if before is None:
            status = "new"
        elif before == src_hash:
            status = "identical"
        else:
            status = "changed"

        if not dry_run:
            if status == "changed" and backup_root is not None:
                backup = backup_path(backup_root, plan.dst, vault_assets)
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(plan.dst, backup)
            plan.dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(plan.src, plan.dst)
            after: str | None = file_hash(plan.dst)
            if after != src_hash:
                status = "FAILED"
        else:
            after = before

        outcomes.append(Outcome(plan, status, src_hash, before, after, backup))
    return outcomes


# --- Guard 7: the freshness reject-check ----------------------------------------


def live_vault_assets(vault_assets: Path) -> list[Path]:
    """Every LIVE gallery asset: flat frames + gifs, by extension, retired excluded.

    Flat means `maxdepth 1` — the nested tree, when one exists, is §6 history and
    is never live evidence. `desktop.ini` never appears here: :func:`is_evidence`
    drops it by name, which is why the empty `svgs/case_03_overlapping_records/`
    remnant folder contributes exactly 0 to every figure this module prints.
    """
    out: list[Path] = []
    for sub, suffix in (("pilot/svgs", ".svg"), ("pilot/gifs", ".gif")):
        d = vault_assets / sub
        if not d.is_dir():
            continue
        for f in sorted(d.glob(f"*{suffix}")):
            if not is_evidence(f):
                continue
            if any(r in f.name for r in RETIRED_CASES):
                continue
            out.append(f)
    return out


def reject_check(vault_assets: Path, merge_date: _dt.date) -> tuple[bool, list[Path]]:
    """No live asset may predate the batch merge date. Stale => the caller exits non-zero.

    The gallery froze from 2026-05-22 to 2026-07-02 and nothing noticed, because
    the refresh was a manual side-channel with no check attached to it. This is
    that check, and the caller turns a FAIL into a non-zero exit so it cannot be
    read past.
    """
    stale = [
        f
        for f in live_vault_assets(vault_assets)
        if _dt.date.fromtimestamp(f.stat().st_mtime) < merge_date
    ]
    return (not stale), stale


# --- Reporting & CLI --------------------------------------------------------


def _report(
    outcomes: Sequence[Outcome], clusters, tally, counts_before, counts_after, backup_root
) -> None:
    def n(status: str, kind: str) -> int:
        return sum(1 for o in outcomes if o.status == status and o.plan.kind == kind)

    print("  source capture:")
    for i, c in enumerate(clusters):
        lo = _dt.datetime.fromtimestamp(c[0][0]).isoformat(sep=" ", timespec="seconds")
        hi = _dt.datetime.fromtimestamp(c[-1][0]).isoformat(sep=" ", timespec="seconds")
        print(f"    run {i + 1}: {len(c)} file(s)  {lo} .. {hi}")
    print(f"  live cases: {len(tally)}  (each {FRAMES_PER_CASE} frames + {GIFS_PER_CASE} gif)")
    print(f"  retired, excluded BY NAME: {', '.join(sorted(RETIRED_CASES))}")
    print()
    print("  result, by content hash re-read from disk (never by timestamp):")
    print(f"    {'':10}  {'svg':>7} {'gif':>7}")
    for status in ("new", "changed", "identical", "FAILED"):
        print(f"    {status:10}  {n(status, 'svg'):>7} {n(status, 'gif'):>7}")
    print(
        "    NOTE: GIF equality is a VACUOUS signal (measured 3x: 15/15 gifs identical "
        "while 75/75 svgs changed). Read the svg column."
    )
    backups = [o.backup for o in outcomes if o.backup is not None]
    print(f"  previous bytes kept aside before overwrite: {len(backups)} file(s)")
    if backups:
        print(f"    under {backup_root}  <- diff these against the vault for old-vs-new")
    print(
        f"  counted BY EXTENSION (desktop.ini never counted): "
        f"before svg={counts_before['svg']} gif={counts_before['gif']} "
        f"(+{counts_before['non_evidence']} non-evidence) -> "
        f"after svg={counts_after['svg']} gif={counts_after['gif']} "
        f"(+{counts_after['non_evidence']} non-evidence)"
    )


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sync_evidence",
        description=(
            "Sync generated pilot evidence into the Obsidian vault gallery. "
            "Does NOT regenerate: run "
            "`pytest -m slow tests/test_examples_pilot_gifs.py` for that."
        ),
    )
    ap.add_argument("--artifacts", type=Path, required=True, help="tests/_artifacts")
    ap.add_argument("--vault-assets", type=Path, required=True, help="vault <project>/assets")
    ap.add_argument(
        "--merge-date",
        help="YYYY-MM-DD; no live vault asset may predate it. Omit to skip the reject-check.",
    )
    ap.add_argument("--dry-run", action="store_true", help="run every guard, write nothing")
    ap.add_argument(
        "--allow-recapture",
        action="store_true",
        help="permit >1 run window ONLY if every window is case-complete",
    )
    ap.add_argument("--max-gap-seconds", type=float, default=DEFAULT_MAX_GAP_SECONDS)
    ap.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="default: <artifacts>/_sync_backup/<utc-stamp>",
    )
    ap.add_argument(
        "--reject-check-only",
        action="store_true",
        help="run only the freshness check against the vault; copy nothing",
    )
    args = ap.parse_args(argv)

    merge_date = None
    if args.merge_date:
        try:
            merge_date = _dt.date.fromisoformat(args.merge_date)
        except ValueError:
            print(f"FAIL: --merge-date {args.merge_date!r} is not YYYY-MM-DD", file=sys.stderr)
            return 2

    if args.reject_check_only:
        if merge_date is None:
            print("FAIL: --reject-check-only needs --merge-date", file=sys.stderr)
            return 2
        ok, stale = reject_check(args.vault_assets, merge_date)
        live = live_vault_assets(args.vault_assets)
        print(f"reject-check: {len(live) - len(stale)}/{len(live)} live assets fresh")
        for f in stale:
            print(f"  STALE {_dt.date.fromtimestamp(f.stat().st_mtime)}  {f.name}")
        print("reject-check: PASS" if ok else "reject-check: FAIL")
        return 0 if ok else 3

    try:
        plans = build_plan(args.artifacts, args.vault_assets)
        clusters = assert_capture_coherent(
            plans, args.max_gap_seconds, args.allow_recapture
        )
        tally = assert_cases_complete(plans)
    except SyncError as exc:
        print(f"ABORT (nothing copied)\n{exc}", file=sys.stderr)
        return 1

    backup_root = args.backup_dir
    if backup_root is None:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_root = args.artifacts / "_sync_backup" / stamp

    svgs_dst = args.vault_assets / "pilot" / "svgs"
    gifs_dst = args.vault_assets / "pilot" / "gifs"
    before = count_evidence(svgs_dst)
    before = {k: before[k] + count_evidence(gifs_dst)[k] for k in before}

    print(f"sync_evidence {'(DRY RUN — nothing written)' if args.dry_run else ''}")
    outcomes = execute(plans, args.vault_assets, None if args.dry_run else backup_root, args.dry_run)

    after = count_evidence(svgs_dst)
    after = {k: after[k] + count_evidence(gifs_dst)[k] for k in after}
    _report(outcomes, clusters, tally, before, after, backup_root)

    nested = [d for d in svgs_dst.iterdir() if d.is_dir() and count_evidence(d)["svg"]]
    if nested:
        print(f"  WARN: nested svg dirs present (not written by this tool): {nested}")

    failed = [o for o in outcomes if o.status == "FAILED"]
    if failed:
        print("\nFAIL: destination bytes do not match source after writing:", file=sys.stderr)
        for o in failed:
            print(f"  {o.plan.dst}", file=sys.stderr)
        return 2

    if merge_date is not None and not args.dry_run:
        ok, stale = reject_check(args.vault_assets, merge_date)
        live = live_vault_assets(args.vault_assets)
        print(f"\nreject-check vs {merge_date}: {len(live) - len(stale)}/{len(live)} live fresh")
        for f in stale:
            print(f"  STALE {_dt.date.fromtimestamp(f.stat().st_mtime)}  {f.name}")
        if not ok:
            print("reject-check: FAIL", file=sys.stderr)
            return 3
        print("reject-check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
