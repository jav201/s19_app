"""Guards for `tools/sync_evidence.py` — each one with a fixture that reddens it.

Every test here is paired: a RED case that constructs the exact failure the guard
exists to prevent and asserts it is refused, and a GREEN case that differs from it
in one property and asserts it passes. The pairing is the point. A test that only
shows the happy path cannot fail when the guard is deleted, and this module's
whole subject is guards that were deleted into prose and then forgotten.

The fixtures are not invented. Each one reconstructs a state that was actually on
disk, taken from the record in the vault's `visual-evidence.md`:

* `half_run_capture` — 2026-08-24: fifteen `frame_00_Loaded.svg` written after a
  full 2026-08-13 set, the render loop dying on a missing Pillow import.
* `recapture_capture` — 2026-08-31: `case_00_public` re-run wholly, on purpose,
  to prove the SVG delta was drift and not run-to-run noise.
* the `desktop.ini` fixture — Windows Explorer's leavings, 19 of which once
  inflated a gallery count and moved its "newest asset" date by 18 days.
* the nested-layout fixture — `svgs/<case>/`, pruned at batch-47 and re-created
  by a recursive copy three times since.
"""

from __future__ import annotations

import datetime as _dt
import os
import time
from pathlib import Path

import pytest

from tools.sync_evidence import (
    DEFAULT_MAX_GAP_SECONDS,
    RETIRED_CASES,
    Plan,
    SyncError,
    assert_capture_coherent,
    assert_cases_complete,
    build_plan,
    count_evidence,
    execute,
    flat_destination,
    live_vault_assets,
    main,
    reject_check,
)

FRAMES = (
    "frame_00_Loaded.svg",
    "frame_01_View_Main.svg",
    "frame_02_View_Alt.svg",
    "frame_03_View_MAC.svg",
    "frame_04_Hex_page+.svg",
)
LIVE_CASES = ("case_00_public", "case_01_basic_valid", "pv__case_01_baseline_valid")
RETIRED = "pv__case_06_large_nested_a2l"


def _stamp(path: Path, when: float) -> None:
    os.utime(path, (when, when))


def _make_source(root: Path, cases, at: float, frames=FRAMES, with_gif=True) -> None:
    """Write a capture: `frames` per case plus a gif, all stamped near `at`."""
    (root / "svgs").mkdir(parents=True, exist_ok=True)
    (root / "gifs").mkdir(parents=True, exist_ok=True)
    offset = 0.0
    for case in cases:
        d = root / "svgs" / case
        d.mkdir(exist_ok=True)
        for name in frames:
            f = d / name
            f.write_text(f"<svg>{case}/{name}</svg>", encoding="utf-8")
            _stamp(f, at + offset)
            offset += 0.4
        if with_gif:
            g = root / "gifs" / f"{case}.gif"
            g.write_bytes(b"GIF89a" + case.encode())
            _stamp(g, at + offset)
            offset += 0.4


def _make_vault(root: Path) -> Path:
    assets = root / "assets"
    (assets / "pilot" / "svgs").mkdir(parents=True)
    (assets / "pilot" / "gifs").mkdir(parents=True)
    return assets


# --------------------------------------------------------------------------
# Guard 1+2 — the half-capture. The failure: 65 SVGs at 2026-08-13 and exactly
# 15 at 2026-08-24, every one of the 15 a frame_00. Copying it publishes a
# gallery whose frames disagree.
# --------------------------------------------------------------------------


def test_coherent_single_run_capture_is_accepted(tmp_path):
    """GREEN side. Without this the RED test below could pass on a broken guard
    that simply refuses everything."""
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    plans = build_plan(src, vault)
    clusters = assert_capture_coherent(plans)
    assert len(clusters) == 1
    assert len(plans) == len(LIVE_CASES) * 6


def test_two_run_mtime_spread_is_refused_and_names_the_files(tmp_path):
    """RED side — the 2026-08-24 half-run, reconstructed.

    A full set eleven days old, then one frame per case written today. The guard
    must refuse and must name what it saw, because a refusal that does not say
    which files are the second run leaves the operator to re-derive it by hand.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    old = time.time() - 11 * 86400
    _make_source(src, LIVE_CASES, at=old)
    # ...then the crashed re-run: frame 00 only, one per case, today.
    now = time.time() - 60
    for case in LIVE_CASES:
        f = src / "svgs" / case / "frame_00_Loaded.svg"
        f.write_text("<svg>half run</svg>", encoding="utf-8")
        _stamp(f, now)

    plans = build_plan(src, vault)
    with pytest.raises(SyncError) as exc:
        assert_capture_coherent(plans)
    msg = str(exc.value)
    assert "INCOHERENT CAPTURE" in msg
    assert "2 separate runs" in msg
    assert "frame_00_Loaded.svg" in msg


def test_allow_recapture_still_refuses_the_half_run(tmp_path):
    """The escape hatch must not be a blanket override.

    `--allow-recapture` exists for a whole case deliberately re-captured. Given
    the half-run it must still refuse, because the second window completes no
    case. If this test goes green on the flag alone, the flag has turned the
    guard into decoration.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 11 * 86400)
    now = time.time() - 60
    for case in LIVE_CASES:
        _stamp(src / "svgs" / case / "frame_00_Loaded.svg", now)

    plans = build_plan(src, vault)
    with pytest.raises(SyncError) as exc:
        assert_capture_coherent(plans, allow_recapture=True)
    assert "not case-complete" in str(exc.value)
    assert "1 of 6" in str(exc.value)


def test_allow_recapture_accepts_a_whole_case_recaptured(tmp_path):
    """GREEN counterpart — the real 2026-08-31 `case_00_public` re-run.

    All six of that case's assets move into the second window together. Without
    the flag it is still refused; that assertion is what keeps the default strict.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    later = time.time() - 3600 + 5 * DEFAULT_MAX_GAP_SECONDS
    for name in FRAMES:
        _stamp(src / "svgs" / "case_00_public" / name, later)
    _stamp(src / "gifs" / "case_00_public.gif", later + 1)

    plans = build_plan(src, vault)
    with pytest.raises(SyncError):
        assert_capture_coherent(plans)
    clusters = assert_capture_coherent(plans, allow_recapture=True)
    assert len(clusters) == 2


def test_incomplete_case_is_refused_without_any_mtime_threshold(tmp_path):
    """RED side of the threshold-free half.

    Same half-run signature, but stamped inside one window so the mtime guard
    has nothing to say. Completeness must still reject it — a guard that depends
    on a tunable number is a guard someone will tune.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600, frames=("frame_00_Loaded.svg",))
    plans = build_plan(src, vault)
    assert len(assert_capture_coherent(plans)) == 1, "mtimes are coherent by construction"
    with pytest.raises(SyncError) as exc:
        assert_cases_complete(plans)
    assert "INCOMPLETE CAPTURE" in str(exc.value)
    assert "1 frame(s) (want 5)" in str(exc.value)


def test_complete_capture_passes_the_completeness_guard(tmp_path):
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    tally = assert_cases_complete(build_plan(src, vault))
    assert set(tally) == set(LIVE_CASES)
    assert all(t == {"svg": 5, "gif": 1} for t in tally.values())


# --------------------------------------------------------------------------
# Guard 4 — the flat layout. The failure: the frames stored twice, and 5 of the
# 80 pairs already diverged before the nested set was deleted.
# --------------------------------------------------------------------------


def test_nested_destination_is_refused(tmp_path):
    """RED side: any filename that would land outside the one flat directory."""
    svgs = tmp_path / "svgs"
    svgs.mkdir()
    with pytest.raises(SyncError) as exc:
        flat_destination(svgs, "case_00_public", "sub/frame_00_Loaded.svg")
    assert "NESTED LAYOUT REFUSED" in str(exc.value)
    with pytest.raises(SyncError):
        flat_destination(svgs, "case_00_public", "../escaped.svg")


def test_flat_destination_is_the_vault_naming_convention(tmp_path):
    svgs = tmp_path / "svgs"
    svgs.mkdir()
    dst = flat_destination(svgs, "case_00_public", "frame_04_Hex_page+.svg")
    assert dst == svgs / "pilot_case_00_public_frame_04_Hex_page+.svg"
    assert dst.parent == svgs


def test_a_sync_creates_no_subdirectory_even_when_the_source_is_nested(tmp_path):
    """RED side of the *cause*, not the symptom.

    The three real recurrences came from a recursive walk, so the fixture puts a
    second level under a case directory. The walk must not descend into it, and
    the vault must end the sync with zero subdirectories.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    deeper = src / "svgs" / "case_00_public" / "nested"
    deeper.mkdir()
    (deeper / "frame_99_Ghost.svg").write_text("<svg>ghost</svg>", encoding="utf-8")

    plans = build_plan(src, vault)
    assert not any("frame_99_Ghost" in p.src.name for p in plans), "recursed into svgs/<case>/"
    execute(plans, vault, tmp_path / "bak", dry_run=False)
    assert [d for d in (vault / "pilot" / "svgs").iterdir() if d.is_dir()] == []
    assert (vault / "pilot" / "svgs" / "pilot_case_00_public_frame_00_Loaded.svg").exists()


# --------------------------------------------------------------------------
# Guard 5 — counting. The failure: "195 files, newest 2026-08-25" when 19 were
# desktop.ini and only 176 were evidence.
# --------------------------------------------------------------------------


def test_desktop_ini_is_never_counted_as_evidence(tmp_path):
    """RED side is the naive count, asserted explicitly so the test cannot pass
    vacuously on an empty directory."""
    d = tmp_path / "svgs"
    d.mkdir()
    (d / "pilot_case_00_public_frame_00_Loaded.svg").write_text("<svg/>", encoding="utf-8")
    (d / "case_00_public.gif").write_bytes(b"GIF89a")
    (d / "desktop.ini").write_text("[.ShellClassInfo]", encoding="utf-8")

    naive = len([p for p in d.iterdir() if p.is_file()])
    counts = count_evidence(d)
    assert naive == 3, "fixture must actually contain the trap"
    assert counts["svg"] == 1 and counts["gif"] == 1
    assert counts["svg"] + counts["gif"] == 2 != naive
    assert counts["non_evidence"] == 1


def test_desktop_ini_never_reaches_the_live_asset_list(tmp_path):
    """The same trap one level up: the reject-check must not date a gallery by a
    `desktop.ini`, which is how "newest 2026-08-25" was 18 days wrong."""
    vault = _make_vault(tmp_path / "vault")
    svgs = vault / "pilot" / "svgs"
    (svgs / "pilot_case_00_public_frame_00_Loaded.svg").write_text("<svg/>", encoding="utf-8")
    ini = svgs / "desktop.ini"
    ini.write_text("[.ShellClassInfo]", encoding="utf-8")
    _stamp(ini, time.time())
    live = live_vault_assets(vault)
    assert [f.name for f in live] == ["pilot_case_00_public_frame_00_Loaded.svg"]


# --------------------------------------------------------------------------
# Guard 6 — the retired case, by name. The failure: a blanket glob re-stamping a
# 2026-07-08 asset as fresh; and the mirror failure, a careless `*case_06*`
# taking the LIVE case with it.
# --------------------------------------------------------------------------


def test_retired_case_is_excluded_and_the_live_lookalike_is_not(tmp_path):
    """Both halves in one fixture, because either alone is a half-guard.

    `pv__case_06_large_nested_a2l` is retired. `case_06_large_nested_a2l`, the
    same name without the `pv__` prefix, is LIVE and has fresh evidence — a glob
    cannot tell them apart and would delete live evidence.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, ("case_06_large_nested_a2l", RETIRED), at=time.time() - 3600)
    plans = build_plan(src, vault)
    cases = {p.case for p in plans}
    assert RETIRED not in cases, "retired case was copied"
    assert "case_06_large_nested_a2l" in cases, "a glob took the LIVE lookalike"
    assert not any(RETIRED in p.dst.name for p in plans)


def test_the_exclusion_is_an_exact_name_set_not_a_pattern(tmp_path):
    """A structural assertion on the constant itself: if a future author turns it
    into a pattern this fails, which is the only moment anyone would notice."""
    assert RETIRED_CASES == frozenset({RETIRED})
    assert not any(ch in name for name in RETIRED_CASES for ch in "*?[]")


def test_retired_leftovers_in_the_vault_are_not_flagged_as_stale(tmp_path):
    """The retired files are dated 2026-07-08 forever. The reject-check must not
    report them, or every sync reports a permanent failure and the check gets
    ignored — a rule that cries wolf is how people learn to skip the gate."""
    vault = _make_vault(tmp_path / "vault")
    svgs = vault / "pilot" / "svgs"
    old = (svgs / f"pilot_{RETIRED}_frame_00_Loaded.svg")
    old.write_text("<svg/>", encoding="utf-8")
    _stamp(old, time.mktime(_dt.date(2026, 7, 8).timetuple()))
    fresh = svgs / "pilot_case_00_public_frame_00_Loaded.svg"
    fresh.write_text("<svg/>", encoding="utf-8")
    ok, stale = reject_check(vault, _dt.date(2026, 8, 1))
    assert ok and stale == []


def test_the_vault_side_filter_also_keeps_the_live_lookalike(tmp_path):
    """The mirror of the build-plan test, on the reject-check side.

    `live_vault_assets` drops the retired frames by matching the retired id inside
    the flattened filename. The `pv__` prefix is what makes that substring safe —
    `pilot_case_06_large_nested_a2l_*` does not contain `pv__case_06_...`. If a
    future author widens that match to `case_06`, the LIVE case silently stops
    being checked for freshness and can rot unnoticed, which is precisely the
    six-week freeze this whole module exists to prevent.
    """
    vault = _make_vault(tmp_path / "vault")
    svgs = vault / "pilot" / "svgs"
    for name in (
        f"pilot_{RETIRED}_frame_00_Loaded.svg",
        "pilot_case_06_large_nested_a2l_frame_00_Loaded.svg",
    ):
        (svgs / name).write_text("<svg/>", encoding="utf-8")
    names = [f.name for f in live_vault_assets(vault)]
    assert names == ["pilot_case_06_large_nested_a2l_frame_00_Loaded.svg"]


# --------------------------------------------------------------------------
# Guard 3 — verification by content hash, re-read after writing. The failure:
# checking the GIFs (15/15 identical while 75/75 SVGs changed) or the timestamps
# (rewritten by the copy regardless).
# --------------------------------------------------------------------------


def test_first_sync_reports_new_second_reports_identical(tmp_path):
    """Idempotence, asserted rather than assumed."""
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    plans = build_plan(src, vault)

    first = execute(plans, vault, tmp_path / "bak1", dry_run=False)
    assert {o.status for o in first} == {"new"}
    second = execute(plans, vault, tmp_path / "bak2", dry_run=False)
    assert {o.status for o in second} == {"identical"}
    assert not (tmp_path / "bak2").exists(), "an identical overwrite took a backup"


def test_a_changed_svg_is_reported_changed_while_an_identical_gif_is_not(tmp_path):
    """The vacuity guard, made concrete.

    Reproduces the measured shape — every SVG changes, every GIF is byte-identical
    — and asserts the two are reported apart. If the tool ever collapsed them into
    one "verified" figure, the GIF column would drown the SVG column exactly as it
    did the three times this was measured by hand.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    plans = build_plan(src, vault)
    execute(plans, vault, tmp_path / "bak1", dry_run=False)

    for p in plans:  # a UI change: svgs move, gifs do not
        if p.kind == "svg":
            p.src.write_text("<svg>new ui</svg>", encoding="utf-8")

    out = execute(plans, vault, tmp_path / "bak2", dry_run=False)
    svg = [o for o in out if o.plan.kind == "svg"]
    gif = [o for o in out if o.plan.kind == "gif"]
    assert {o.status for o in svg} == {"changed"}
    assert {o.status for o in gif} == {"identical"}
    assert len(svg) == 15 and len(gif) == 3


def test_timestamps_alone_would_certify_a_copy_that_never_happened(tmp_path):
    """RED side for *why* verification is by content.

    The destination is touched to now — newer than the source, which is what a
    timestamp comparison reads as "fresh" — while its bytes are wrong. A
    timestamp check passes here. The content check must not.
    """
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, ("case_00_public",), at=time.time() - 3600)
    plans = build_plan(src, vault)
    stale_dst = plans[0].dst
    stale_dst.write_text("<svg>WRONG BYTES</svg>", encoding="utf-8")
    _stamp(stale_dst, time.time())

    assert stale_dst.stat().st_mtime > plans[0].src.stat().st_mtime, (
        "the timestamp check this test exists to discredit must actually pass here"
    )
    out = execute([plans[0]], vault, tmp_path / "bak", dry_run=True)
    assert out[0].status == "changed"
    assert out[0].dst_hash_before != out[0].src_hash


def test_dry_run_writes_nothing(tmp_path):
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    plans = build_plan(src, vault)
    out = execute(plans, vault, tmp_path / "bak", dry_run=True)
    assert {o.status for o in out} == {"new"}
    assert list((vault / "pilot" / "svgs").iterdir()) == []


# --------------------------------------------------------------------------
# The backup — six syncs recorded the same regret: overwritten in place, so only
# a hash pair survived and no textual old-vs-new diff was ever possible.
# --------------------------------------------------------------------------


def test_previous_bytes_are_kept_aside_before_an_overwrite(tmp_path):
    """The backup must hold the OLD bytes. Asserting it merely exists would pass
    on a backup taken after the write, which preserves nothing."""
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, ("case_00_public",), at=time.time() - 3600)
    plans = build_plan(src, vault)
    old = "<svg>the previous gallery</svg>"
    plans[0].dst.write_text(old, encoding="utf-8")

    bak = tmp_path / "bak"
    out = execute([plans[0]], vault, bak, dry_run=False)
    assert out[0].status == "changed"
    assert out[0].backup is not None and out[0].backup.exists()
    assert out[0].backup.read_text(encoding="utf-8") == old
    assert plans[0].dst.read_text(encoding="utf-8") == plans[0].src.read_text(encoding="utf-8")


def test_nothing_is_ever_deleted(tmp_path):
    """An unrelated file in the gallery survives a sync. The tool overwrites; it
    does not reconcile, and it does not prune."""
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    orphan = vault / "pilot" / "svgs" / "pilot_some_old_case_frame_00_Loaded.svg"
    orphan.write_text("<svg>orphan</svg>", encoding="utf-8")
    execute(build_plan(src, vault), vault, tmp_path / "bak", dry_run=False)
    assert orphan.exists() and orphan.read_text(encoding="utf-8") == "<svg>orphan</svg>"


# --------------------------------------------------------------------------
# Guard 7 — the reject-check. The failure: the gallery froze 2026-05-22 to
# 2026-07-02 and no check was attached to notice.
# --------------------------------------------------------------------------


def test_stale_asset_fails_the_reject_check_and_exits_non_zero(tmp_path, capsys):
    """RED side, through the CLI, because the exit code is the part that matters:
    a FAIL that returns 0 is a FAIL nobody sees."""
    vault = _make_vault(tmp_path / "vault")
    svgs = vault / "pilot" / "svgs"
    fresh = svgs / "pilot_case_00_public_frame_00_Loaded.svg"
    fresh.write_text("<svg/>", encoding="utf-8")
    stale = svgs / "pilot_case_01_basic_valid_frame_00_Loaded.svg"
    stale.write_text("<svg/>", encoding="utf-8")
    _stamp(stale, time.mktime(_dt.date(2026, 5, 22).timetuple()))

    rc = main(
        [
            "--artifacts", str(tmp_path / "unused"),
            "--vault-assets", str(vault),
            "--merge-date", "2026-08-01",
            "--reject-check-only",
        ]
    )
    out = capsys.readouterr().out
    assert rc != 0, "a stale gallery must not exit 0"
    assert "reject-check: FAIL" in out
    assert "pilot_case_01_basic_valid_frame_00_Loaded.svg" in out
    assert "1/2 live assets fresh" in out


def test_fresh_gallery_passes_the_reject_check(tmp_path, capsys):
    vault = _make_vault(tmp_path / "vault")
    (vault / "pilot" / "svgs" / "pilot_case_00_public_frame_00_Loaded.svg").write_text(
        "<svg/>", encoding="utf-8"
    )
    rc = main(
        [
            "--artifacts", str(tmp_path / "unused"),
            "--vault-assets", str(vault),
            "--merge-date", "2026-08-01",
            "--reject-check-only",
        ]
    )
    assert rc == 0
    assert "reject-check: PASS" in capsys.readouterr().out


def test_cli_aborts_the_whole_sync_on_an_incoherent_capture(tmp_path, capsys):
    """End to end: the guard must stop the copy, not warn beside it. Nothing may
    reach the vault."""
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 11 * 86400)
    for case in LIVE_CASES:
        _stamp(src / "svgs" / case / "frame_00_Loaded.svg", time.time() - 60)

    rc = main(["--artifacts", str(src), "--vault-assets", str(vault)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "ABORT (nothing copied)" in err
    assert list((vault / "pilot" / "svgs").iterdir()) == []


def test_cli_happy_path_is_idempotent(tmp_path, capsys):
    src, vault = tmp_path / "src", _make_vault(tmp_path / "vault")
    _make_source(src, LIVE_CASES, at=time.time() - 3600)
    args = [
        "--artifacts", str(src),
        "--vault-assets", str(vault),
        "--merge-date", "2026-01-01",
    ]
    assert main(args) == 0
    first = capsys.readouterr().out
    assert main(args) == 0
    second = capsys.readouterr().out
    assert "reject-check: PASS" in second
    assert "new" in first and "identical" in second
    counts = count_evidence(vault / "pilot" / "svgs")
    assert counts["svg"] == 15 and counts["non_evidence"] == 0
