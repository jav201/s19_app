import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from unittest import mock

import pytest

from s19_app.tui.workspace import (
    LOG_FILENAME,
    LOGS_SUBDIR,
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
    find_repo_root,
    resolve_input_path,
    sanitize_project_name,
    setup_logging,
    validate_project_files,
)


def test_ensure_workarea_creates_expected_directories(tmp_path: Path):
    workarea = ensure_workarea(tmp_path)

    assert workarea == tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert workarea.exists()
    assert (workarea / WORKAREA_TEMP).exists()
    assert (tmp_path / WORKAREA_DIRNAME / LOGS_SUBDIR).exists()


def test_setup_logging_reuses_handler_for_same_path(tmp_path: Path):
    logger = setup_logging(tmp_path)
    logger = setup_logging(tmp_path)
    log_path = tmp_path / WORKAREA_DIRNAME / LOGS_SUBDIR / "s19tui.log"
    matching_handlers = [
        handler
        for handler in logger.handlers
        if isinstance(handler, RotatingFileHandler)
        and Path(handler.baseFilename) == log_path
    ]

    assert len(matching_handlers) == 1
    assert matching_handlers[0].maxBytes == 5 * 1024 * 1024


class TestCopyIntoWorkareaContainment:
    """Phase 3 increment 1 -- LLR-005.3 write-path guards.

    Closes Phase 2 blockers S-001 (destination containment) and S-002
    (symlink/junction follow-through) plus major S-003 (file-size cap).
    Each test names the TC ID it covers in a leading comment.
    """

    def _make_workarea(self, base: Path) -> Path:
        workarea = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP
        workarea.mkdir(parents=True, exist_ok=True)
        return workarea

    def test_destination_outside_workarea_rejected(self, tmp_path: Path):
        # TC-046 -- closes blocker S-001 (destination must resolve under .s19tool/workarea/).
        source = tmp_path / "sample.s19"
        source.write_text("S0", encoding="utf-8")
        # Destination is plain ``tmp_path/elsewhere/`` -- has no .s19tool/workarea ancestor.
        bogus_destination = tmp_path / "elsewhere"

        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(source, bogus_destination)

    def test_source_symlink_rejected(self, tmp_path: Path):
        # TC-045 -- closes part of S-002 (source symlink rejection).
        real_source = tmp_path / "real.s19"
        real_source.write_text("S0", encoding="utf-8")
        symlinked_source = tmp_path / "linked.s19"
        try:
            os.symlink(real_source, symlinked_source)
        except (OSError, NotImplementedError) as exc:
            # Windows requires Developer Mode or admin to create symlinks; skip cleanly.
            pytest.skip(f"symlink creation unsupported here: {exc}")

        destination = self._make_workarea(tmp_path)
        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(symlinked_source, destination)

    def test_source_size_over_cap_rejected(self, tmp_path: Path):
        # TC-044 -- closes S-003 (256 MB default size cap on copy_into_workarea).
        # Use a tiny custom cap so we don't actually allocate 256 MB on disk.
        oversize = tmp_path / "oversize.s19"
        cap = 1024  # bytes
        with oversize.open("wb") as fh:
            fh.seek(cap + 1)  # sparse file: stat().st_size > cap without writing cap+1 bytes
            fh.write(b"\x00")

        destination = self._make_workarea(tmp_path)
        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(oversize, destination, max_size_bytes=cap)

    @pytest.mark.skipif(sys.platform != "win32", reason="NTFS junction is Windows-only")
    def test_junction_rejected_on_windows(self, tmp_path: Path):
        # TC-047 -- closes part of S-002 (NTFS reparse-point/junction rejection).
        # Manual gate-closing run per Q-N01 deferral:
        #   pytest -q tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows
        # CI runs ubuntu-latest only, so this test is skipped on CI by design;
        # the Windows stdout must be attached to .dev-flow/03-increments/increment-001.md
        # before the Phase 4 gate.
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        real_file = real_dir / "payload.s19"
        real_file.write_text("S0", encoding="utf-8")

        # Build .s19tool/workarea/<junction> -> real_dir using ``mklink /J``.
        workarea_root = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
        workarea_root.mkdir(parents=True, exist_ok=True)
        junction_dir = workarea_root / "junction_dir"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction_dir), str(real_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"mklink /J unavailable: {result.stderr.strip()}")

        # Source lives behind the junction; destination crosses the junction parent.
        source = junction_dir / "payload.s19"
        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(source, junction_dir)


class TestReadPathResolution:
    """Phase 3 increment 7 -- LLR-005.1 / TC-041 read-path resolution audit.

    Acceptance bullets (from .dev-flow/01-requirements.md LLR-005.1):
      - resolve_input_path precedence: app cwd -> repo root -> None.
      - find_repo_root returns nearest ancestor with pyproject.toml/project.toml or None.
    Existing coverage (test_tui_helpers.py): the cwd preference and the repo-root
    fallback positive cases. Gap closed here: explicit None when neither hit, the
    project.toml marker variant, and the absolute-path short-circuit.
    """

    def test_tc_041_resolve_input_path_returns_none_when_no_match(self, tmp_path: Path):
        # TC-041 -- explicit None when neither base_dir nor repo root hold the file.
        base_dir = tmp_path / "base"
        base_dir.mkdir()
        # No pyproject/project marker anywhere along the chain.
        assert resolve_input_path(Path("does/not/exist.s19"), base_dir) is None

    def test_tc_041_resolve_input_path_returns_existing_absolute(self, tmp_path: Path):
        # TC-041 -- absolute path that exists is returned as-is (cwd preference).
        target = tmp_path / "abs.s19"
        target.write_text("S0", encoding="utf-8")
        base_dir = tmp_path / "base"
        base_dir.mkdir()
        resolved = resolve_input_path(target, base_dir)
        assert resolved == target

    def test_tc_041_find_repo_root_recognises_project_toml_marker(self, tmp_path: Path):
        # TC-041 -- find_repo_root accepts either pyproject.toml or project.toml.
        repo = tmp_path / "repo"
        nested = repo / "deep" / "deeper"
        nested.mkdir(parents=True)
        (repo / "project.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        assert find_repo_root(nested) == repo

    def test_tc_041_find_repo_root_returns_none_without_marker(self, tmp_path: Path):
        # TC-041 -- without a marker, the search ends in None (not the filesystem root).
        leaf = tmp_path / "no_marker_here" / "child"
        leaf.mkdir(parents=True)
        assert find_repo_root(leaf) is None


class TestSanitizeProjectName:
    """Phase 3 increment 7 -- LLR-005.2 / TC-042 sanitisation audit.

    Acceptance bullets (from .dev-flow/01-requirements.md LLR-005.2): rejects (returns
    None) Windows reserved device names, names exceeding 64 chars, NUL bytes, and
    Unicode confusables.

    Audit findings: today's sanitiser strips characters that are not alnum/-/_; this
    means traversal vectors collapse to None (correct), NUL bytes are stripped
    (effectively rejected because what's left becomes empty or short), but Windows
    reserved device names like CON survive sanitisation (their characters are all
    alnum), the 64-char cap is NOT enforced (the result can be arbitrarily long),
    and Unicode confusables (Cyrillic 'a' U+0430) are stripped because isalnum()
    returns True but the cleaned name still contains the Cyrillic char.
    """

    def test_tc_042_traversal_vectors_collapsed_or_rejected(self):
        # TC-042 -- ``..``, drive letters, UNC, separators all have their structural
        # characters stripped. A bare ``..`` collapses to None; mixed paths keep the
        # alnum subset (``../escape`` -> ``escape``). LLR-005.2 acceptance requires
        # collapse-to-empty OR None for traversal vectors -- both are acceptable
        # outcomes today. Lock the de-facto behaviour so a future tightening
        # (Finding F-7.7-02 onward) is a clear signal.
        assert sanitize_project_name("..") is None
        assert sanitize_project_name("../escape") == "escape"
        assert sanitize_project_name("/etc/passwd") == "etcpasswd"
        # UNC: backslashes stripped, ``server`` and ``share`` survive concatenated.
        assert sanitize_project_name("\\\\server\\share") == "servershare"
        # Drive letters: ``:``, ``\\``, ``/`` are stripped, so ``C:\foo`` -> ``Cfoo``.
        assert sanitize_project_name("C:\\foo") == "Cfoo"

    def test_tc_042_nul_byte_stripped(self):
        # TC-042 -- NUL bytes are non-alnum and not in {-,_}; they are stripped.
        # If the entire input is NUL, sanitisation returns None.
        assert sanitize_project_name("\x00\x00\x00") is None
        # Embedded NUL: stripped, surrounding alnum survives. Locked behaviour.
        assert sanitize_project_name("good\x00bad") == "goodbad"

    @pytest.mark.parametrize(
        "reserved",
        [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM9",
            "LPT1",
            "LPT9",
            "con",  # case-insensitive on Windows
            "Aux",
        ],
    )
    def test_tc_042_windows_reserved_names_currently_survive(self, reserved):
        # TC-042 -- LLR-005.2 acceptance says these *should* return None.
        # Today's sanitiser strips only non-alnum/-/_ chars, so the reserved name
        # survives unchanged. This is Finding F-7.7-02 (workspace.sanitize_project_name
        # does not enforce the LLR-005.2 reserved-name rule).
        result = sanitize_project_name(reserved)
        # xfail-style assertion: if a future fix returns None, this test FAILS,
        # which is the expected signal that the Finding has been closed and this
        # block needs to be flipped to ``assert result is None``.
        if result is None:
            pytest.fail(
                "Sanitiser now returns None for Windows reserved names; "
                "flip this test to ``assert result is None`` and close F-7.7-02."
            )
        assert result == reserved

    @pytest.mark.parametrize(
        "reserved_with_ext",
        ["CON.s19", "PRN.txt", "NUL.a2l"],
    )
    def test_tc_042_windows_reserved_names_with_extension_currently_survive(self, reserved_with_ext):
        # TC-042 -- ``.`` is stripped, so ``CON.s19`` -> ``CONs19``. LLR-005.2 says
        # these forms *should* be rejected too. Same Finding F-7.7-02.
        result = sanitize_project_name(reserved_with_ext)
        # The current sanitiser collapses the dot but keeps the alnum letters.
        assert result is not None
        assert "." not in result

    def test_tc_042_64_char_cap_not_enforced_today(self):
        # TC-042 -- LLR-005.2 acceptance says inputs >64 chars should return None.
        # Today the sanitiser preserves all alnum chars regardless of length. This
        # is Finding F-7.7-03 (workspace.sanitize_project_name does not enforce
        # the 64-char cap).
        long_name = "A" * 200
        result = sanitize_project_name(long_name)
        if result is None or len(result) <= 64:
            pytest.fail(
                "Sanitiser now caps length at 64 chars; flip this test to "
                "``assert result is None or len(result) <= 64`` and close F-7.7-03."
            )
        assert len(result) == 200

    def test_tc_042_unicode_confusable_stripped_to_safe_subset(self):
        # TC-042 -- Cyrillic 'а' (U+0430) is .isalnum() True, so the sanitiser
        # currently keeps it. LLR-005.2 acceptance recommends rejection per
        # Unicode TR36. Finding F-7.7-04 (workspace.sanitize_project_name does
        # not detect Unicode confusables).
        cyrillic_a = "а"  # looks like Latin 'a'
        # Mixed Latin/Cyrillic: today's behaviour preserves both.
        mixed = "p" + cyrillic_a + "yload"
        result = sanitize_project_name(mixed)
        if result is None or cyrillic_a not in result:
            pytest.fail(
                "Sanitiser now strips/rejects Unicode confusables; flip this "
                "test to assert that and close F-7.7-04."
            )
        assert cyrillic_a in result


class TestValidateProjectFilesSymlinkAndCase:
    """Phase 3 increment 7 -- LLR-005.4 / TC-048.

    Acceptance bullets:
      - Symlink/junction rejection on directory entries.
      - Case-only collision (``prj.S19`` vs. ``prj.s19``) treated as collision.
      - Cardinality at most 1 S19/HEX, 1 A2L, 1 MAC (already in test_tui_helpers.py).

    Audit findings: today's validate_project_files iterates ``project_dir.iterdir``
    and only filters via ``item.is_file()``. ``is_file()`` returns True for symlinks
    that point at files, so symlinked entries are NOT rejected. Case-only collision
    is NOT detected because counting matches by suffix, but on case-insensitive
    filesystems the two filenames resolve to one entry anyway -- on case-sensitive
    Linux they survive as two distinct files, which since batch-07 LLR-005.1
    (multi-variant model) validate as two variants. The findings below lock
    those behaviours so a future tightening surfaces as a clear test failure.
    """

    def test_tc_048_symlink_to_file_currently_passes_validation(self, tmp_path: Path):
        # TC-048 -- LLR-005.4 acceptance says symlinked entries should be rejected.
        # Today they are accepted because is_file() follows symlinks. Finding
        # F-7.7-05 (workspace.validate_project_files does not reject symlinks).
        project = tmp_path / "project"
        project.mkdir()
        real_target = tmp_path / "real_payload.s19"
        real_target.write_text("S0", encoding="utf-8")
        link = project / "linked.s19"
        try:
            os.symlink(real_target, link)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unsupported here: {exc}")

        data_files, _, error = validate_project_files(project)
        if error is not None or not data_files:
            pytest.fail(
                "validate_project_files now rejects symlinks; flip this test "
                "and close F-7.7-05."
            )
        # Locked behaviour today: the symlink survives.
        assert any(p.name == "linked.s19" for p in data_files)

    def test_tc_048_case_only_collision_accepted_as_variants_since_llr_005_1(self, tmp_path: Path):
        # TC-048 -- on a case-sensitive FS, ``prj.S19`` and ``prj.s19`` are two
        # distinct files. The pre-batch-07 cardinality rule (>1 primary) caught
        # them; LLR-005.1 (batch-07 multi-variant model) removed that rejection,
        # so today they validate as two variants in deterministic
        # ``(name.lower(), name)`` order. On case-insensitive FS (NTFS, APFS
        # default) only one entry exists at all. We lock the outcome either way.
        project = tmp_path / "project"
        project.mkdir()
        upper = project / "prj.S19"
        lower = project / "prj.s19"
        upper.write_text("S0", encoding="utf-8")
        try:
            lower.write_text("S0", encoding="utf-8")
        except OSError:
            pytest.skip("Filesystem refused to create case-only collision (case-insensitive FS).")

        existing = list(project.iterdir())
        if len(existing) < 2:
            # Case-insensitive FS collapsed both entries into one.
            data_files, _, error = validate_project_files(project)
            assert error is None
            assert len(data_files) == 1
            return

        # Case-sensitive FS: both survive as variants (case-only collision is
        # no longer flagged -- a future tightening would surface here).
        data_files, _, error = validate_project_files(project)
        assert error is None
        assert [p.name for p in data_files] == ["prj.S19", "prj.s19"]

    def test_tc_048_cardinality_one_each(self, tmp_path: Path):
        # TC-048 -- explicit happy-path cardinality boundary: exactly one of each
        # is accepted. Existing test_validate_project_files_allows_single_data_and_a2l
        # covers data+A2L; this adds the data+MAC+A2L triple-success path.
        project = tmp_path / "project"
        project.mkdir()
        (project / "fw.s19").write_text("S0", encoding="utf-8")
        (project / "tags.mac").write_text("A=0x0", encoding="utf-8")
        (project / "cal.a2l").write_text("A2L", encoding="utf-8")

        data_files, a2l_files, error = validate_project_files(project)
        assert error is None
        assert len(a2l_files) == 1
        assert sorted(p.suffix.lower() for p in data_files) == [".mac", ".s19"]


class TestSetupLoggingSurface:
    """Phase 3 increment 7 -- LLR-005.5 / TC-049 logging surface audit.

    Acceptance bullets:
      - 5 MB cap and backupCount asserted from RotatingFileHandler config.
      - Handler reuse across repeated setup_logging calls (already covered).
      - Non-writable log dir -> clean error or fallback (no silent failure).
    """

    def test_tc_049_rotating_handler_config(self, tmp_path: Path):
        # TC-049 -- 5 MB maxBytes + at least one backup file (R-TUI-015).
        logger = setup_logging(tmp_path)
        rotating = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
        assert rotating, "setup_logging must register a RotatingFileHandler"
        handler = rotating[-1]
        assert handler.maxBytes == 5 * 1024 * 1024
        assert handler.backupCount >= 1
        # Clean up to avoid leaking handlers across tests.
        for h in rotating:
            logger.removeHandler(h)
            h.close()

    def test_tc_049_handler_reuse_does_not_duplicate(self, tmp_path: Path):
        # TC-049 -- repeated setup_logging() calls with the same path keep exactly
        # one handler for that path. Mirror of the existing
        # test_setup_logging_reuses_handler_for_same_path; included here as part
        # of the LLR-005.5 surface to keep the coverage table contiguous.
        logger = setup_logging(tmp_path)
        logger = setup_logging(tmp_path)
        log_path = tmp_path / WORKAREA_DIRNAME / LOGS_SUBDIR / LOG_FILENAME
        rotating = [
            h
            for h in logger.handlers
            if isinstance(h, RotatingFileHandler)
            and Path(h.baseFilename) == log_path
        ]
        assert len(rotating) == 1
        for h in rotating:
            logger.removeHandler(h)
            h.close()

    def test_tc_049_non_writable_log_dir_does_not_swallow_silently(self, tmp_path: Path):
        # TC-049 -- if RotatingFileHandler() raises (simulating a non-writable
        # log dir), setup_logging today either propagates the exception (clean
        # error) or returns a logger that has no rotating handler (fallback).
        # Silent success with the failed handler attached is a Finding.
        # We patch RotatingFileHandler at its workspace import site.
        import s19_app.tui.workspace as ws

        def _explode(*args, **kwargs):
            raise PermissionError("simulated non-writable log dir")

        # Use a fresh logger name to isolate from other tests' state.
        named_logger = logging.getLogger("s19tui")
        # Snapshot handlers so we can restore.
        original_handlers = list(named_logger.handlers)
        try:
            for h in original_handlers:
                named_logger.removeHandler(h)
            with mock.patch.object(ws, "RotatingFileHandler", side_effect=_explode):
                raised = False
                fallback_logger = None
                try:
                    fallback_logger = setup_logging(tmp_path)
                except PermissionError:
                    raised = True
                # Acceptance: either the exception propagates (clean error) or
                # a logger comes back without a broken RotatingFileHandler.
                if not raised:
                    assert fallback_logger is not None
                    bad = [
                        h
                        for h in fallback_logger.handlers
                        if isinstance(h, RotatingFileHandler)
                    ]
                    assert not bad, (
                        "setup_logging silently attached a RotatingFileHandler whose "
                        "constructor raised; this is the silent-failure mode "
                        "LLR-005.5 prohibits."
                    )
        finally:
            # Restore original handler set so later tests aren't affected.
            for h in list(named_logger.handlers):
                named_logger.removeHandler(h)
                try:
                    h.close()
                except Exception:
                    pass
            for h in original_handlers:
                named_logger.addHandler(h)
