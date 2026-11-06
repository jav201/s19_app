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

Traceability (E4): node names start ``test_r_<row id>_...``.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

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


def _spy_on_open(monkeypatch) -> list:
    """Create spy: record every path ``os.open`` is called with, then call through."""
    calls: list = []
    real_open = os.open

    def spy(path, flags, *args, **kwargs):
        calls.append(os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    return calls


def _windows_follow(monkeypatch, home: Path, outside: Path) -> None:
    """Emulate Windows ``O_CREAT|O_EXCL`` through a link put in at the free name.

    The first ``os.open`` on a ``*.json`` directly in ``home`` creates
    ``<outside>/followed.json``, puts a file link to it at the candidate and
    returns the descriptor of ``followed.json`` (house finding S-F1).
    """
    real_open = os.open
    state = {"done": False}

    def follow(path, flags, *args, **kwargs):
        candidate = Path(os.fspath(path))
        if not state["done"] and candidate.parent == home and candidate.suffix == ".json":
            state["done"] = True
            target = outside / "followed.json"
            fd = real_open(target, os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o666)
            os.symlink(target, candidate)
            return fd
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", follow)


def _swap_home_for_link(monkeypatch, home: Path, aside: Path, outside: Path) -> None:
    """Between the name check and the create, replace ``home`` by a link to ``outside``."""
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
    os.symlink(target, home / name)


def test_r_flow_file_14_1_dangling_link_gets_no_file(area):
    """R-FLOW-FILE.14/1: a link named like the file, target missing, gets no file."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flows", "z.json", outside / "dangling" / "z.json")
    saved = save_flow_json(F1, "z", project)
    assert not (outside / "dangling" / "z.json").exists()
    assert (project / "flows" / "z.json").is_symlink()
    assert saved.parent == project / "flows" and saved.name.startswith("z_")
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_file_14_2_link_to_file_is_not_written(area):
    """R-FLOW-FILE.14/2: a link named like the file, target a file, is not written."""
    _root, project, outside = area
    (outside / "z.json").write_bytes(b"KKK")
    _link_file(project / "flows", "z.json", outside / "z.json")
    saved = save_flow_json(F1, "z", project)
    assert (outside / "z.json").read_bytes() == b"KKK"
    assert saved.name.startswith("z_") and saved.is_file() and not saved.is_symlink()


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
    assert saved.name.startswith("z_") and saved.is_file() and not saved.is_symlink()


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
    """R-FLOW-FILE.14/5 (E3 R2-1): a home swapped for a link after the name check gets no byte.

    Under the swap the created file is regular and the same file as the
    descriptor, so only the real-path clause of the check after the claim
    refuses it. The swap puts in a directory symbolic link (``os.symlink``):
    it runs on Linux, and on Windows only where that link is permitted.
    """
    _root, project, outside = area
    home = project / "flows"
    home.mkdir()
    _swap_home_for_link(monkeypatch, home, project / "flows_aside", outside)
    with pytest.raises(WorkareaContainmentError):
        save_flow_json(F1, "z", project)
    landed = outside / "z.json"
    assert (not landed.exists()) or landed.stat().st_size == 0
    assert [e for e in _entries(outside) if e != "z.json"] == []


def test_r_flow_set_8_1_dangling_link_gets_no_file(area):
    """R-FLOW-SET.8/1: a link named like the set file, target missing, gets no file."""
    _root, project, outside = area
    (outside / "dangling").mkdir()
    _link_file(project / "flowsets", "s.json", outside / "dangling" / "s.json")
    saved = save_chain_set(C1, "s", project)
    assert not (outside / "dangling" / "s.json").exists()
    assert saved.parent == project / "flowsets" and saved.name.startswith("s_")
    assert saved.is_file() and not saved.is_symlink()


def test_r_flow_set_8_2_link_to_file_is_not_written(area):
    """R-FLOW-SET.8/2: a link named like the set file, target a file, is not written."""
    _root, project, outside = area
    (outside / "s.json").write_bytes(b"KKK")
    _link_file(project / "flowsets", "s.json", outside / "s.json")
    saved = save_chain_set(C1, "s", project)
    assert (outside / "s.json").read_bytes() == b"KKK"
    assert saved.name.startswith("s_") and saved.is_file() and not saved.is_symlink()


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
    assert saved.name.startswith("s_") and saved.is_file() and not saved.is_symlink()


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
