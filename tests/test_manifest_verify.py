"""Manifest verify-on-write tests (batch-11 I3, HLR-003).

Maps each test to its TC id and LLR:

- TC-003a / LLR-003.1 — ``verify_written_manifest`` re-reads a faithfully
  written ``project.json`` (via the CANONICAL fixed name) and compares it
  key-wise against intent IN THE C-1 CANONICAL COMPARISON FORM (intent resolved
  against ``project_root``): a faithful write → status VERIFIED with empty
  drift and empty issues.
- TC-003b / LLR-003.2 — tampering the on-disk manifest's ``active_variant``
  after write → status MISMATCH whose ``drift`` is exactly ``["active_variant"]``
  (the single drifting key named); no false-verify.
- TC-003c / LLR-003.3 — a manifest the reader degrades (an escaping ``batch``
  entry the reader skips with a ``MANIFEST-PATH-ESCAPE`` issue) → status
  MISMATCH even though the surviving fields compare equal: the R-1
  false-verify guard. Non-empty re-read ``issues`` force MISMATCH and are
  carried on the result.
- Canonical-path test / LLR-003.1 (M-1) — a stray ``project_1.json`` carrying a
  DIFFERENT ``active_variant`` must NOT be what verify reads; verify reads
  ``project.json`` by the canonical fixed name and returns VERIFIED. A reader
  that opened the suffixed file would falsely mismatch (or, in the reverse
  hazard, falsely verify a stale manifest) — this pins the M-1 fix.

These tests encode WHY: verify-on-write is the manifest analogue of batch-10's
``verify_written_image`` — the written file must be re-read through the reader
ORACLE and judged against intent, so a write the reader can't use (degraded
issues) or a tampered/stale file can never silently "verify." The reader-issue
guard (R-1) closes the false-verify hole where a file lands but the reader
rejects its contents.
"""
from __future__ import annotations

import json
from pathlib import Path

from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.manifest_writer import (
    MANIFEST_MISMATCH,
    MANIFEST_VERIFIED,
    write_project_manifest,
    verify_written_manifest,
)
from s19_app.tui.services.variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    PROJECT_MANIFEST_NAME,
)


def _variant_set(active_id: str | None, *ids: str) -> ProjectVariantSet:
    """Build a ProjectVariantSet with placeholder variant descriptors."""
    variants = tuple(
        VariantDescriptor(variant_id=vid, path=Path(f"{vid}.s19"), file_type="s19")
        for vid in ids
    )
    return ProjectVariantSet(
        project_name="proj", variants=variants, active_id=active_id
    )


def _project_dir(tmp_path: Path, name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` — the reader-visible home.

    Mirrors ``test_manifest_writer.py``'s ``_project_dir`` so a written
    manifest passes containment and ``read_project_manifest`` finds it there.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


# --------------------------------------------------------------------------- #
# TC-003a / LLR-003.1 — faithful write -> VERIFIED, empty drift, empty issues
# --------------------------------------------------------------------------- #


def test_faithful_write_verifies(tmp_path: Path) -> None:
    """A faithfully written manifest re-reads as intent -> status VERIFIED.

    Intent (LLR-003.1): verify-on-write must confirm the written file re-reads
    through the reader oracle as the intended composition (C-1 canonical form),
    with empty drift and no reader issues.
    """
    project_dir = _project_dir(tmp_path)
    vset = _variant_set("b", "a", "b")
    batch = ["doc.json"]
    assignments = {"b": ["extra.json"]}

    written, write_issues = write_project_manifest(
        vset, project_dir, tmp_path, batch=batch, assignments=assignments
    )
    assert write_issues == []
    assert written is not None

    result = verify_written_manifest(
        project_dir, vset, project_dir, batch=batch, assignments=assignments
    )

    assert result.status == MANIFEST_VERIFIED
    assert result.drift == []
    assert result.issues == []
    assert result.written_path == project_dir / PROJECT_MANIFEST_NAME


# --------------------------------------------------------------------------- #
# TC-003b / LLR-003.2 — tampered active_variant -> MISMATCH naming the key
# --------------------------------------------------------------------------- #


def test_tampered_active_variant_mismatches_naming_the_key(tmp_path: Path) -> None:
    """Tampering active_variant on disk -> MISMATCH, drift == [active_variant].

    Intent (LLR-003.2): a re-read that differs from intent must be MISMATCH and
    must NAME the drifting key, and ONLY that key, so a consumer can report
    exactly what failed. The fault planted (flip active_variant) matches the
    asserted single-key drift (Rule 9).
    """
    project_dir = _project_dir(tmp_path)
    vset = _variant_set("b", "a", "b")

    written, write_issues = write_project_manifest(vset, project_dir, tmp_path)
    assert write_issues == []
    assert written is not None

    # Tamper the on-disk manifest: flip active_variant b -> a, leave the rest.
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["active_variant"] == "b"
    payload["active_variant"] = "a"
    written.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    result = verify_written_manifest(project_dir, vset, project_dir)

    assert result.status == MANIFEST_MISMATCH
    assert result.drift == ["active_variant"]
    assert result.issues == []  # the file still parses cleanly; only intent drifts


# --------------------------------------------------------------------------- #
# TC-003c / LLR-003.3 — reader-degraded write -> MISMATCH (R-1 false-verify guard)
# --------------------------------------------------------------------------- #


def test_reader_issues_force_mismatch_even_if_surviving_keys_match(
    tmp_path: Path,
) -> None:
    """A manifest the reader degrades -> MISMATCH carrying the reader issue.

    Intent (LLR-003.3 / R-1): if the reader collects ANY issue on the re-read
    (here an escaping ``batch`` entry it skips with ``MANIFEST-PATH-ESCAPE``),
    verify must classify MISMATCH even though the surviving fields compare
    equal to intent. The escaping entry is skipped by the reader, so re-read
    ``batch`` is empty; intent's ``batch`` is also empty (we never claimed the
    escaping entry as intent) — the keys MATCH, but the reader-issue alone must
    force MISMATCH and carry the issue. This closes the false-verify hole.

    The fault is planted by writing ``project.json`` DIRECTLY (the writer would
    refuse the escaping entry up front, LLR-001.5), so the reader degrades it on
    re-read exactly as asserted (Rule 9).
    """
    project_dir = _project_dir(tmp_path)
    vset = _variant_set("a", "a")

    # Write a manifest the reader degrades: an escaping batch entry. active_variant
    # and assignments are faithful; only the reader-skipped entry yields an issue.
    poisoned = {
        "schema_version": 1,
        "active_variant": "a",
        "batch": ["../../escape.json"],
        "assignments": {},
    }
    (project_dir / PROJECT_MANIFEST_NAME).write_text(
        json.dumps(poisoned, indent=2), encoding="utf-8"
    )

    # Intent claims NO batch entry (we never intended the escaping one), so the
    # surviving compared fields all match — only the reader issue should fail it.
    result = verify_written_manifest(project_dir, vset, project_dir, batch=[])

    assert result.status == MANIFEST_MISMATCH
    assert result.drift == []  # surviving keys compared equal
    assert len(result.issues) >= 1
    assert any(i.code == MANIFEST_PATH_ESCAPE for i in result.issues)
    assert result.written_path == project_dir / PROJECT_MANIFEST_NAME


# --------------------------------------------------------------------------- #
# Canonical-path test / LLR-003.1 (M-1) — verify reads project.json, not a stray
# --------------------------------------------------------------------------- #


def test_verify_reads_canonical_name_not_a_stray_suffixed_file(
    tmp_path: Path,
) -> None:
    """A stray project_1.json must NOT be what verify reads (the M-1 fix).

    Intent (LLR-003.1 / M-1): verify re-reads by the CANONICAL fixed name
    ``project_dir / PROJECT_MANIFEST_NAME``. A stray ``project_1.json`` carrying
    a DIFFERENT active_variant is planted alongside the faithful ``project.json``;
    verify must read ``project.json`` and return VERIFIED, proving it never
    honors the suffixed file (which would let a stale manifest drive the verdict).
    """
    project_dir = _project_dir(tmp_path)
    vset = _variant_set("b", "a", "b")

    written, write_issues = write_project_manifest(vset, project_dir, tmp_path)
    assert write_issues == []
    assert written is not None
    assert written.name == PROJECT_MANIFEST_NAME

    # Plant a stray dedup-suffixed file with a DIFFERENT active_variant. If verify
    # ever read this instead of the canonical name, it would mismatch on
    # active_variant. A passing VERIFIED proves verify ignores the stray file.
    stray = {
        "schema_version": 1,
        "active_variant": "a",  # deliberately != intended "b"
        "batch": [],
        "assignments": {},
    }
    (project_dir / "project_1.json").write_text(
        json.dumps(stray, indent=2), encoding="utf-8"
    )

    result = verify_written_manifest(project_dir, vset, project_dir)

    assert result.status == MANIFEST_VERIFIED
    assert result.drift == []
    assert result.written_path == project_dir / PROJECT_MANIFEST_NAME
