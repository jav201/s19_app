"""Batch-101 Inc 9 (G-T1) - the flow and chain-set saves: names, homes, claims.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-9/01-requirements.md``
rows R-FLOW-FILE.11 .. .14 and R-FLOW-SET.7 .. .10, one node per case of
``inc-9/02-test-cases.md`` assigned to G-T1, plus the E3 round-2 addendum R2-1
(the real-path, home-swap arm of the check after the claim, case /5 of
R-FLOW-FILE.14). The service is driven through its public calls
``save_flow_json`` and ``save_chain_set`` and read back through
``load_flow_json`` / ``load_chain_set`` and the bytes on disk. The link cases
use ``tests/b97_fixtures.make_junction`` (a junction on Windows, a symlink
elsewhere) and ``os.symlink``; the claim primitive is wrapped at ``os.open``
(graph interface I-7) for the Create spy, the emulated Windows link-follow and
the home swap. No source file is edited here.

E5 corrective (``inc-9/E5-rulings.md``): cases R-FLOW-FILE.14/7 … /11 and
R-FLOW-SET.8/6 … /9 drive each clause of the check after the claim and of its
cleanup alone (a link to a sibling inside the home, the claim's error arms,
a home re-pointed before the cleanup, another file and a hard link at the
name); every symbolic link goes through a named skip, so an account without
the Windows symlink privilege reports the node not run instead of failing.

Traceability (E4): node names start ``test_r_<row id>_...``.
"""
from __future__ import annotations

import errno
import json
import os
import re
from dataclasses import replace
from pathlib import Path

import pytest

from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import Flow, SourceBlock
from s19_app.tui.services.flow_persistence_service import (
    CHAIN_SET_BAD_FIELD,
    ChainSet,
    ChainSetEntry,
    load_chain_set,
    load_flow_json,
    save_chain_set,
    save_flow_json,
)
from s19_app.tui.workspace import WorkareaContainmentError
from tests.b97_fixtures import make_junction

F1 = Flow(name="a", blocks=[SourceBlock("prg.s19")])
C1 = ChainSet(
    name="s",
    chains=(ChainSetEntry(chain="x", template="x", inputs=((0, "prg.s19"),), outputs=()),),
)


# ----------------------------------------------------------------- fixtures --


@pytest.fixture
def area(tmp_path):
    """Work area root R, project W (holding prg.s19) and folder O (outside)."""
    root = tmp_path / ".s19tool" / "workarea"
    project = root / "p"
    project.mkdir(parents=True)
    (project / "prg.s19").write_text("S9030000FC\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    return root, project, outside


def _name_in(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["name"]


def _entries(folder: Path) -> list:
    return sorted(entry.name for entry in folder.iterdir())


def _save_kind(project: Path, kind: str):
    """``(home, stem, save)`` of the flow save (``flows/``, ``z``) or the set save
    (``flowsets/``, ``s``); ``save(name)`` calls the service with the derived root."""
    if kind == "flow":
        return project / "flows", "z", lambda name: save_flow_json(F1, name, project)
    return project / "flowsets", "s", lambda name: save_chain_set(C1, name, project)


def _symlink_or_skip(link: Path, target: Path) -> None:
    """``os.symlink`` or a named skip (E5 CR-04, the house pattern of
    ``tests/test_b100_load_dialog.py``): a symbolic link needs a privilege on
    Windows that an account may not hold, which is no product failure."""
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"os.symlink is unavailable here (reported not run): {exc}")


def _require_symlinks(scratch: Path) -> None:
    """Skip by name before any wrapper is patched when this account cannot make a
    symbolic link (E5 CR-04): the wrappers make their links inside the product's
    own ``os.open`` call, where a raise would read as a product failure."""
    probe = scratch / "symlink-probe"
    _symlink_or_skip(probe, scratch / "symlink-probe-target")
    probe.unlink()


def _link_points_at(link: Path, target: Path) -> bool:
    """True when ``link`` is still a symbolic link to ``target`` (``os.readlink``,
    without the ``\\\\?\\`` prefix Windows adds to an absolute target)."""
    if not link.is_symlink():
        return False
    raw = os.readlink(link)
    return Path(raw[4:] if raw.startswith("\\\\?\\") else raw) == target


def _spy_on_open(monkeypatch) -> list:
    """Create spy: record every path ``os.open`` is called with, then call through."""
    calls: list = []
    real_open = os.open

    def spy(path, flags, *args, **kwargs):
        calls.append(os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    return calls


def _follow_at_create(monkeypatch, home: Path, target: Path, put) -> None:
    """Emulate Windows ``O_CREAT|O_EXCL`` following an entry put in at the free name.

    The first ``os.open`` on a ``*.json`` directly in ``home`` creates and opens
    ``target``, calls ``put(candidate)`` to put an entry at the candidate and
    returns the descriptor of ``target`` (house finding S-F1).
    """
    real_open = os.open
    state = {"done": False}

    def follow(path, flags, *args, **kwargs):
        candidate = Path(os.fspath(path))
        if not state["done"] and candidate.parent == home and candidate.suffix == ".json":
            state["done"] = True
            fd = real_open(target, os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o666)
            put(candidate)
            return fd
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", follow)


def _windows_follow(monkeypatch, home: Path, outside: Path, target: Path | None = None) -> None:
    """The emulated follow through a file link put in at the free name, to
    ``target`` (default ``<outside>/followed.json``)."""
    _require_symlinks(outside)
    followed = target if target is not None else outside / "followed.json"
    _follow_at_create(monkeypatch, home, followed, lambda candidate: os.symlink(followed, candidate))


def _swap_home_for_link(monkeypatch, home: Path, aside: Path, outside: Path) -> None:
    """Between the name check and the create, replace ``home`` by a link to ``outside``."""
    _require_symlinks(outside)
    real_open = os.open
    state = {"done": False}

    def swap(path, flags, *args, **kwargs):
        candidate = Path(os.fspath(path))
        if not state["done"] and candidate.parent == home and candidate.suffix == ".json":
            state["done"] = True
            home.rename(aside)
            os.symlink(outside, home, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)


def _repoint_home_at_close(monkeypatch, home: Path, parked: Path, elsewhere: Path) -> None:
    """At the first ``os.close`` after ``home`` became a link, once the descriptor
    is closed: move that link to ``parked`` and link ``home`` to ``elsewhere``
    (probe P9: the home re-pointed between the close and the cleanup)."""
    real_close = os.close
    state = {"done": False}

    def close(fd):
        real_close(fd)
        if not state["done"] and home.is_symlink():
            state["done"] = True
            home.rename(parked)
            os.symlink(elsewhere, home, target_is_directory=True)

    monkeypatch.setattr(os, "close", close)


# ------------------------------------------------- R-FLOW-FILE.12 / .13 names --


def test_r_flow_file_12_2_clash_file_holds_its_stem(area):
    """R-FLOW-FILE.12/2: a clash file holds its own stem as its name."""
    _root, project, _out = area
    (project / "flows").mkdir()
    (project / "flows" / "tune_b.json").write_text("{}", encoding="utf-8")
    saved = save_flow_json(Flow(name="tune_a", blocks=[SourceBlock("prg.s19")]), "tune_b", project)
    assert saved is not None and saved.stem != "tune_b"
    assert saved.stem.startswith("tune_b")
    assert _name_in(saved) == saved.stem


def test_r_flow_file_12_3_cleaned_name_is_written(area):
    """R-FLOW-FILE.12/3: a cleaned typed name is the file stem and the name."""
    _root, project, _out = area
    saved = save_flow_json(F1, "Nightly Release!  ", project)
    assert saved == project / "flows" / "NightlyRelease.json"
    assert _name_in(saved) == "NightlyRelease"


def test_r_flow_file_12_4_stem_of_64_is_whole(area):
    """R-FLOW-FILE.12/4: a 64-character stem is written whole and loads clean."""
    _root, project, _out = area
    saved = save_flow_json(F1, "A" * 64, project)
    assert saved.stem == "A" * 64
    assert _name_in(saved) == "A" * 64
    flow, findings = load_flow_json(saved, project)
    assert flow is not None and findings == []


def test_r_flow_file_13_1_long_stem_is_cut_to_64(area):
    """R-FLOW-FILE.13/1: a 65-character stem names the file whole, the name is cut to 64."""
    _root, project, _out = area
    saved = save_flow_json(F1, "B" * 65, project)
    assert saved == project / "flows" / ("B" * 65 + ".json")
    assert _name_in(saved) == "B" * 64
    flow, findings = load_flow_json(saved, project)
    assert flow is not None and findings == []


def test_r_flow_file_13_1_control_whole_65_name_is_refused_by_loader(area):
    """R-FLOW-FILE.13/1 negative control (standing guard): the loader refuses a 65-character name.

    This is the reason the cut exists; it shows the zero-findings assertion of
    the node above can fail when the name is written whole.
    """
    _root, project, _out = area
    saved = save_flow_json(F1, "ok", project)
    envelope = json.loads(saved.read_text(encoding="utf-8"))
    envelope["name"] = "B" * 65
    saved.write_text(json.dumps(envelope), encoding="utf-8")
    _flow, findings = load_flow_json(saved, project)
    assert any("FLOW-BAD-FIELD" in str(getattr(f, "code", f)) for f in findings)


def test_r_flow_file_13_2_clash_suffix_is_cut(area):
    """R-FLOW-FILE.13/2: when a clash suffix makes the stem longer than 64, the name is still cut."""
    _root, project, _out = area
    (project / "flows").mkdir()
    (project / "flows" / ("C" * 64 + ".json")).write_text("{}", encoding="utf-8")
    saved = save_flow_json(F1, "C" * 64, project)
    assert saved.stem.startswith("C" * 64) and len(saved.stem) > 64
    assert _name_in(saved) == "C" * 64
    flow, findings = load_flow_json(saved, project)
    assert flow is not None and findings == []


# --------------------------------------------- R-FLOW-SET.9 / .10 set names --


def test_r_flow_set_9_1_cleaned_name_is_written(area):
    """R-FLOW-SET.9/1: a saved set holds its cleaned file stem as its name."""
    _root, project, _out = area
    saved = save_chain_set(replace(C1, name="Nightly Set!"), "Nightly Set!  ", project)
    assert saved == project / "flowsets" / "NightlySet.json"
    assert _name_in(saved) == "NightlySet"
    loaded, findings = load_chain_set(saved, project)
    assert loaded is not None and findings == []
    assert loaded.name == "NightlySet"


def test_r_flow_set_9_2_clash_file_holds_its_stem(area):
    """R-FLOW-SET.9/2: a clash set file holds its own stem as its name."""
    _root, project, _out = area
    (project / "flowsets").mkdir()
    (project / "flowsets" / "s.json").write_text("{}", encoding="utf-8")
    saved = save_chain_set(C1, "s", project)
    assert saved.stem != "s"
    assert _name_in(saved) == saved.stem


def test_r_flow_set_10_1_long_stem_is_cut_to_64(area):
    """R-FLOW-SET.10/1: a 65-character set stem names the file whole, the name is cut to 64."""
    _root, project, _out = area
    saved = save_chain_set(replace(C1, name="D" * 65), "D" * 65, project)
    assert saved == project / "flowsets" / ("D" * 65 + ".json")
    assert _name_in(saved) == "D" * 64
    loaded, findings = load_chain_set(saved, project)
    assert loaded is not None and findings == []


def test_r_flow_set_10_1_control_whole_65_name_is_refused_by_loader(area):
    """R-FLOW-SET.10/1 negative control (standing guard): the loader refuses a 65-character set name."""
    _root, project, _out = area
    saved = save_chain_set(C1, "ok", project)
    envelope = json.loads(saved.read_text(encoding="utf-8"))
    envelope["name"] = "D" * 65
    saved.write_text(json.dumps(envelope), encoding="utf-8")
    loaded, findings = load_chain_set(saved, project)
    assert loaded is None
    assert any(CHAIN_SET_BAD_FIELD in str(getattr(f, "code", f)) for f in findings)


# ------------------------------------------------ homes: .11 (flows) / .7 (sets) --


def test_r_flow_file_11_1_home_linked_outside_saves_nothing(area):
    """R-FLOW-FILE.11/1: a flows home linked outside the work area saves nothing."""
    root, project, outside = area
    make_junction(project / "flows", outside / "flows")
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "x", project, workarea_root=root)
    assert _entries(outside / "flows") == []


def test_r_flow_file_11_2_home_linked_inside_saves_nothing(area):
    """R-FLOW-FILE.11/2: a flows home linked inside the project saves nothing."""
    root, project, _out = area
    (project / "patches").mkdir()
    make_junction(project / "flows", project / "patches")
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "x", project, workarea_root=root)
    assert _entries(project / "patches") == []


def test_r_flow_file_11_3_linked_project_folder_saves_nothing(area):
    """R-FLOW-FILE.11/3: a flows home under a linked project folder saves nothing (E3A-06)."""
    root, _project, _out = area
    real = root / "q"
    real.mkdir()
    (real / "prg.s19").write_text("S9030000FC\n", encoding="utf-8")
    make_junction(root / "pl", real)
    before = _entries(real)
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "x", root / "pl", workarea_root=root)
    assert not (real / "flows").exists()
    assert _entries(real) == before


def test_r_flow_set_7_1_home_linked_outside_saves_nothing(area):
    """R-FLOW-SET.7/1: a flowsets home linked outside the work area saves nothing."""
    root, project, outside = area
    make_junction(project / "flowsets", outside / "flowsets")
    with pytest.raises(WorkareaContainmentError):
        save_chain_set(C1, "s", project, workarea_root=root)
    assert _entries(outside / "flowsets") == []


def test_r_flow_set_7_2_home_linked_inside_saves_nothing(area):
    """R-FLOW-SET.7/2: a flowsets home linked inside the project saves nothing."""
    root, project, _out = area
    (project / "patches").mkdir()
    make_junction(project / "flowsets", project / "patches")
    with pytest.raises(WorkareaContainmentError):
        save_chain_set(C1, "s", project, workarea_root=root)
    assert _entries(project / "patches") == []


# ------------------------------------- R-FLOW-FILE.14 / R-FLOW-SET.8 file links --


def _link_file(home: Path, name: str, target: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    _symlink_or_skip(home / name, target)


def test_r_flow_file_14_1_dangling_link_gets_no_file(area):
    """R-FLOW-FILE.14/1: a link named like the file, target missing, gets no file."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flows", "z.json", outside / "dangling" / "z.json")
    saved = save_flow_json(F1, "z", project)
    assert not (outside / "dangling" / "z.json").exists()
    assert _link_points_at(project / "flows" / "z.json", outside / "dangling" / "z.json")
    assert saved.parent == project / "flows" and re.fullmatch(r"z_\d+\.json", saved.name)
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_file_14_2_link_to_file_is_not_written(area):
    """R-FLOW-FILE.14/2: a link named like the file, target a file, is not written."""
    _root, project, outside = area
    (outside / "z.json").write_bytes(b"KKK")
    _link_file(project / "flows", "z.json", outside / "z.json")
    saved = save_flow_json(F1, "z", project)
    assert (outside / "z.json").read_bytes() == b"KKK"
    assert _link_points_at(project / "flows" / "z.json", outside / "z.json")
    assert saved.parent == project / "flows" and re.fullmatch(r"z_\d+\.json", saved.name)
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_file_14_3_no_create_on_a_taken_name(area, monkeypatch):
    """R-FLOW-FILE.14/3: no create is attempted on a candidate name that exists (E3 S-2 a)."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flows", "z.json", outside / "dangling" / "z.json")
    calls = _spy_on_open(monkeypatch)
    saved = save_flow_json(F1, "z", project)
    taken = str(project / "flows" / "z.json")
    assert calls.count(taken) == 0
    assert calls.count(str(saved)) == 1
    assert re.fullmatch(r"z_\d+\.json", saved.name) and saved.is_file() and not saved.is_symlink()


def test_r_flow_file_14_4_followed_create_gets_no_byte(area, monkeypatch):
    """R-FLOW-FILE.14/4: a link put in at the free name gets no byte (E3 S-2 b)."""
    _root, project, outside = area
    home = project / "flows"
    home.mkdir()
    _windows_follow(monkeypatch, home, outside)
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "z", project)
    assert (outside / "followed.json").read_bytes() == b""
    assert (home / "z.json").is_symlink()
    assert _entries(home) == ["z.json"]


def test_r_flow_file_14_5_swapped_home_gets_no_byte(area, monkeypatch):
    """R-FLOW-FILE.14/5 (E3 R2-1; E5 SE5-2, CR-09): a home swapped for a link after the name
    check gets no byte, and the empty claim at the link's target is left where it is.

    Under the swap the created file is regular and the same file as the
    descriptor, so only the real-path clause of the check after the claim
    refuses it. Its name now resolves outside the approved home, so the
    cleanup does not unlink through it (E5 SE5-2): Folder O holds exactly the
    empty claim (BL-I9-4; mutant M25, the cleanup's real-parent clause
    dropped, removes it → RED). The swap puts in a directory symbolic link
    (``os.symlink``): it runs on Linux, and on Windows only where that link is
    permitted (a named skip otherwise).
    """
    _root, project, outside = area
    home = project / "flows"
    home.mkdir()
    _swap_home_for_link(monkeypatch, home, project / "flows_aside", outside)
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "z", project)
    assert _entries(outside) == ["z.json"]
    assert (outside / "z.json").read_bytes() == b""


def test_r_flow_set_8_1_dangling_link_gets_no_file(area):
    """R-FLOW-SET.8/1: a link named like the set file, target missing, gets no file."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flowsets", "s.json", outside / "dangling" / "s.json")
    saved = save_chain_set(C1, "s", project)
    assert not (outside / "dangling" / "s.json").exists()
    assert _link_points_at(project / "flowsets" / "s.json", outside / "dangling" / "s.json")
    assert saved.parent == project / "flowsets" and re.fullmatch(r"s_\d+\.json", saved.name)
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_set_8_2_link_to_file_is_not_written(area):
    """R-FLOW-SET.8/2: a link named like the set file, target a file, is not written."""
    _root, project, outside = area
    (outside / "s.json").write_bytes(b"KKK")
    _link_file(project / "flowsets", "s.json", outside / "s.json")
    saved = save_chain_set(C1, "s", project)
    assert (outside / "s.json").read_bytes() == b"KKK"
    assert _link_points_at(project / "flowsets" / "s.json", outside / "s.json")
    assert saved.parent == project / "flowsets" and re.fullmatch(r"s_\d+\.json", saved.name)
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_set_8_3_no_create_on_a_taken_name(area, monkeypatch):
    """R-FLOW-SET.8/3: no create is attempted on a set candidate name that exists (E3 S-2 a)."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flowsets", "s.json", outside / "dangling" / "s.json")
    calls = _spy_on_open(monkeypatch)
    saved = save_chain_set(C1, "s", project)
    taken = str(project / "flowsets" / "s.json")
    assert calls.count(taken) == 0
    assert calls.count(str(saved)) == 1
    assert re.fullmatch(r"s_\d+\.json", saved.name) and saved.is_file() and not saved.is_symlink()


def test_r_flow_set_8_4_followed_create_gets_no_byte(area, monkeypatch):
    """R-FLOW-SET.8/4: a link put in at the free set name gets no byte (E3 S-2 b)."""
    _root, project, outside = area
    home = project / "flowsets"
    home.mkdir()
    _windows_follow(monkeypatch, home, outside)
    with pytest.raises(WorkareaContainmentError):
        save_chain_set(C1, "s", project)
    assert (outside / "followed.json").read_bytes() == b""
    assert (home / "s.json").is_symlink()
    assert _entries(home) == ["s.json"]


# ------------------------------------------------ E4-R3: the saved file's mode --


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows ignores the execute bits")
@pytest.mark.parametrize("kind", ["flow", "set"])
def test_r_flow_file_14_6_saved_file_mode_matches_write_text(area, kind):
    """R-FLOW-FILE.14/6, R-FLOW-SET.8/5 (E4 ruling E4-R3): the exclusive create keeps
    the mode a plain ``write_text`` gives a sibling file in the same folder, so a
    saved flow or chain set is never created executable (negative control: the
    claim without a mode argument gives ``0o777`` less the umask → RED)."""
    _root, project, _out = area
    if kind == "flow":
        saved = save_flow_json(F1, "m", project)
    else:
        saved = save_chain_set(C1, "m", project)
    sibling = saved.parent / "sibling.txt"
    sibling.write_text("x", encoding="utf-8")
    assert oct(saved.stat().st_mode & 0o777) == oct(sibling.stat().st_mode & 0o777)
    assert saved.stat().st_mode & 0o111 == 0


# --------------------------- E5 corrective: each clause of the claim alone --


@pytest.mark.parametrize("kind", ["flow", "set"])
def test_r_flow_file_14_7_link_to_a_sibling_in_the_home_gets_no_byte(area, monkeypatch, kind):
    """R-FLOW-FILE.14/7 [flow], R-FLOW-SET.8/6 [set] (E5 QA-3): a link put in at the free
    name whose target is a sibling INSIDE the home gets no byte.

    The followed create opens ``<home>/other.json``; the candidate's real
    parent is then the approved home, so the real-path clause passes and only
    the link clauses of the check after the claim (a regular file, the same
    file as the descriptor, no reparse point) refuse it. The link is left (it
    is not the claim) and nothing else is created (mutant M14b, the check
    reduced to its one-link and real-path clauses → the payload lands in
    ``other.json`` → RED).
    """
    _root, project, outside = area
    home, stem, save = _save_kind(project, kind)
    home.mkdir()
    sibling = home / "other.json"
    _windows_follow(monkeypatch, home, outside, target=sibling)
    with pytest.raises(WorkareaContainmentError):
        save(stem)
    assert sibling.read_bytes() == b""
    assert _link_points_at(home / f"{stem}.json", sibling)
    assert _entries(home) == sorted(["other.json", f"{stem}.json"])


class _FullDisk:
    """A text handle whose ``write`` fails as a full disk does; it closes the
    real handle it wraps on exit, as the ``with`` block of the save does."""

    def __init__(self, handle):
        self._handle = handle

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._handle.close()
        return False

    def write(self, text):
        raise OSError(errno.ENOSPC, "No space left on device")


@pytest.mark.parametrize("arm", ["render", "write", "lstat", "taken-by-folder"])
def test_r_flow_file_14_8_claim_error_arms(area, monkeypatch, arm):
    """R-FLOW-FILE.14/8 (E5 CR-03, QA-4; E3 S-3, R2-2, house F1): the error arms of the claim.

    - ``render``: the serialiser raises → no create is attempted in the home
      and no file is made (mutant M26, the payload rendered after the claim →
      an empty ``z.json`` → RED).
    - ``write``: the write through the claim fails with ``ENOSPC`` → that
      ``OSError`` is re-raised and the claim removed, no cut-off file under
      the name (mutant M27, the cleanup of the write arm dropped → RED).
    - ``lstat``: the check's ``lstat`` fails → ``WorkareaContainmentError``,
      nothing written, the claim removed (mutant M28, the check's reads
      outside the ``try`` → the raw ``OSError`` escapes → RED).
    - ``taken-by-folder``: the create raises ``PermissionError`` with a folder
      now at the name (Windows) → the name is taken and the next one claimed
      (mutant M29, every non-``FileExistsError`` re-raised → RED).
    """
    _root, project, _out = area
    home = project / "flows"
    home.mkdir()
    candidate = home / "z.json"
    real_open = os.open
    if arm == "render":
        def explode(_flow):
            raise RuntimeError("serialiser fails")

        monkeypatch.setattr(fps, "flow_to_dict", explode)
        calls = _spy_on_open(monkeypatch)
        with pytest.raises(RuntimeError, match="serialiser fails"):
            save_flow_json(F1, "z", project)
        assert [c for c in calls if Path(c).parent == home] == []
        assert _entries(home) == []
    elif arm == "write":
        real_fdopen = os.fdopen
        monkeypatch.setattr(os, "fdopen", lambda fd, *a, **k: _FullDisk(real_fdopen(fd, *a, **k)))
        with pytest.raises(OSError) as raised:
            save_flow_json(F1, "z", project)
        assert raised.value.errno == errno.ENOSPC
        assert _entries(home) == []
    elif arm == "lstat":
        real_lstat = os.lstat
        state = {"claimed": False, "failed": False}

        def claim(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            state["claimed"] = state["claimed"] or Path(os.fspath(path)) == candidate
            return fd

        def flaky_lstat(path, *args, **kwargs):
            if state["claimed"] and not state["failed"] and Path(os.fspath(path)) == candidate:
                state["failed"] = True
                raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", claim)
        monkeypatch.setattr(os, "lstat", flaky_lstat)
        with pytest.raises(WorkareaContainmentError):
            save_flow_json(F1, "z", project)
        assert state["failed"]
        assert _entries(home) == []
    else:
        def racing_folder(path, flags, *args, **kwargs):
            if Path(os.fspath(path)) == candidate:
                os.mkdir(candidate)
                raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", racing_folder)
        saved = save_flow_json(F1, "z", project)
        assert saved == home / "z_2.json"
        assert _name_in(saved) == "z_2"
        assert candidate.is_dir()


@pytest.mark.parametrize("kind", ["flow", "set"])
def test_r_flow_file_14_9_repointed_home_keeps_the_file_elsewhere(area, monkeypatch, kind):
    """R-FLOW-FILE.14/9 [flow], R-FLOW-SET.8/7 [set] (E5 SE5-2, probe P9): a home re-pointed
    between the close and the cleanup never makes the cleanup delete a file outside.

    The home is swapped for a link to Folder O at the create (the refusal of
    /14/5); after the claim's descriptor is closed, the home is re-pointed at
    a folder V that holds a file of the claimed name. The cleanup re-reads the
    entry at the name: it is not the claim's file, so nothing is unlinked; V's
    file keeps its bytes and the empty claim stays in O (mutant M24, the
    cleanup unlinks by name without the re-read → V's file deleted → RED).
    """
    _root, project, outside = area
    home, stem, save = _save_kind(project, kind)
    home.mkdir()
    victim = outside.parent / "victim"
    victim.mkdir()
    (victim / f"{stem}.json").write_bytes(b"VICTIM")
    _swap_home_for_link(monkeypatch, home, project / f"{home.name}_aside", outside)
    _repoint_home_at_close(monkeypatch, home, project / f"{home.name}_to_o", victim)
    with pytest.raises(WorkareaContainmentError):
        save(stem)
    # RR-3: the re-point at the close ran, so this is not /14/5 again.
    assert Path(os.path.realpath(home)) == victim.resolve()
    assert (victim / f"{stem}.json").read_bytes() == b"VICTIM"
    assert _entries(victim) == [f"{stem}.json"]
    assert (outside / f"{stem}.json").read_bytes() == b""


@pytest.mark.parametrize("kind", ["flow", "set"])
def test_r_flow_file_14_10_other_file_at_the_name_gets_no_byte(area, monkeypatch, kind):
    """R-FLOW-FILE.14/10 [flow], R-FLOW-SET.8/8 [set] (E5 CR-02): a followed create, then the
    link replaced by a regular file before the check, gets no byte.

    The entry at the name is a regular file with one link, no reparse point,
    directly in the home, so only the same-file clause of the check after the
    claim refuses it: nothing goes through the descriptor into the followed
    target, and the planted file is neither written nor removed (mutant M22,
    the same-file clause dropped → the payload lands in ``followed.json`` →
    RED). No symbolic link is made, so the node needs no privilege.
    """
    _root, project, outside = area
    home, stem, save = _save_kind(project, kind)
    home.mkdir()
    followed = outside / "followed.json"
    _follow_at_create(monkeypatch, home, followed, lambda candidate: candidate.write_bytes(b"PLANTED"))
    with pytest.raises(WorkareaContainmentError):
        save(stem)
    assert followed.read_bytes() == b""
    assert (home / f"{stem}.json").read_bytes() == b"PLANTED"
    assert _entries(home) == [f"{stem}.json"]


@pytest.mark.parametrize("kind", ["flow", "set"])
def test_r_flow_file_14_11_hard_link_at_the_name_gets_no_byte(area, monkeypatch, kind):
    """R-FLOW-FILE.14/11 [flow], R-FLOW-SET.8/9 [set] (E5 SE5-1, probe P4): a followed create,
    then the link replaced by a hard link to the followed target, gets no byte.

    The entry at the name is a regular file, the same file as the descriptor,
    no reparse point, directly in the home, so only the one-link clause of
    the check after the claim refuses it: the target outside gets no byte
    (mutant M23, ``st_nlink == 1`` dropped → the payload lands outside →
    RED). The hard-link name is the claim's own file in the approved home, so
    the cleanup removes it and the home holds no entry. No symbolic link is
    made, so the node needs no privilege.
    """
    _root, project, outside = area
    home, stem, save = _save_kind(project, kind)
    home.mkdir()
    followed = outside / "followed.json"
    _follow_at_create(monkeypatch, home, followed, lambda candidate: os.link(followed, candidate))
    with pytest.raises(WorkareaContainmentError):
        save(stem)
    assert followed.read_bytes() == b""
    assert _entries(home) == []
