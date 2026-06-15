"""Manifest serializer tests (batch-11 I1, HLR-001).

Maps each test to its TC id and LLR:

- TC-001a / LLR-001.1 — ``serialize_manifest`` builds the 4-key envelope
  ``{schema_version, active_variant, batch, assignments}`` with
  ``active_variant == ProjectVariantSet.active_id``, JSON-parseable output.
- TC-001b / LLR-001.2 — ``batch`` / ``assignments`` entries are emitted as
  project-relative forward-slash strings that the reader's
  ``_resolve_manifest_entry`` accepts with zero ``MANIFEST-PATH-ESCAPE``.
- TC-001c / LLR-001.3 — round-trip: serialize → write to a tmp project dir →
  ``read_project_manifest`` → re-read ``active_variant`` / ``batch`` /
  ``assignments`` equal intent IN THE C-1 CANONICAL COMPARISON FORM (intent
  resolved against the project dir, the ``test_variant_execution.py:163``
  idiom) with zero reader issues.
- TC-001d / LLR-001.4 — byte-deterministic: serializing the same composition
  twice yields byte-identical text.
- TC-001e / LLR-001.5 — security gate: a composition with a ``../../x`` entry
  AND an absolute-path entry → ``serialize_manifest`` returns
  ``(None, [finding, ...])`` and emits no text; on a clean composition
  findings are empty.

These tests encode WHY: the reader is the schema oracle, so correctness is
defined as "the reader reads our output back as intent, with no findings"
(round-trip fidelity), and a path the reader would reject must never be
written (the silent-divergence security hazard).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.manifest_writer import (
    MANIFEST_WRITE_ESCAPE,
    serialize_manifest,
)
from s19_app.tui.services.variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    PROJECT_MANIFEST_NAME,
    _resolve_manifest_entry,
    read_project_manifest,
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


# --------------------------------------------------------------------------- #
# TC-001a / LLR-001.1 — envelope keys + active_variant
# --------------------------------------------------------------------------- #


def test_envelope_keys_and_active_variant(tmp_path: Path) -> None:
    """Serialized dict has the 4 canonical keys; active_variant == active_id.

    Intent (LLR-001.1): the writer must emit exactly the key set the reader
    parses (``payload.get("schema_version"|"active_variant"|"batch"|
    "assignments")``) so the round-trip can succeed; ``active_variant`` is
    sourced from ``ProjectVariantSet.active_id``, not re-derived.
    """
    vset = _variant_set("b", "a", "b")
    text, issues = serialize_manifest(vset, tmp_path)

    assert issues == []
    assert text is not None
    payload = json.loads(text)  # JSON-serializable / parseable (LLR-001.1 AC)
    assert set(payload) >= {
        "schema_version",
        "active_variant",
        "batch",
        "assignments",
    }
    assert payload["active_variant"] == "b"
    assert payload["schema_version"] == 1


def test_envelope_empty_project_active_variant_is_null(tmp_path: Path) -> None:
    """An empty project (active_id None) serializes active_variant as null.

    Intent (LLR-001.1 AC): ``active_id is None`` round-trips through the reader
    as ``None`` — JSON ``null``.
    """
    vset = _variant_set(None)
    text, issues = serialize_manifest(vset, tmp_path)

    assert issues == []
    assert text is not None
    payload = json.loads(text)
    assert payload["active_variant"] is None


# --------------------------------------------------------------------------- #
# TC-001b / LLR-001.2 — project-relative POSIX paths, 0 escapes
# --------------------------------------------------------------------------- #


def test_relative_paths_resolve_with_no_escape(tmp_path: Path) -> None:
    """Every emitted entry resolves in-project with 0 MANIFEST-PATH-ESCAPE.

    Intent (LLR-001.2): the writer's entries must satisfy the reader's
    ``_resolve_manifest_entry`` (non-None Path, no appended issue) so the
    reader resolves them inside the project root.
    """
    vset = _variant_set("a", "a")
    text, issues = serialize_manifest(
        vset,
        tmp_path,
        batch=["doc.json"],
        assignments={"a": ["sub/extra.json"]},
    )

    assert issues == []
    assert text is not None
    payload = json.loads(text)
    emitted = payload["batch"] + payload["assignments"]["a"]
    assert emitted  # the test is non-vacuous
    escape_count = 0
    for entry in emitted:
        assert "\\" not in entry  # forward-slash only (LLR-001.2)
        probe: list = []
        resolved = _resolve_manifest_entry(tmp_path.resolve(), entry, "batch", probe)
        assert resolved is not None
        escape_count += sum(1 for i in probe if i.code == MANIFEST_PATH_ESCAPE)
    assert escape_count == 0


def test_windows_backslashes_normalized_to_forward_slash(tmp_path: Path) -> None:
    """A back-slash entry is normalized to POSIX before emission (LLR-001.2 AC)."""
    vset = _variant_set("a", "a")
    text, issues = serialize_manifest(
        vset, tmp_path, batch=["sub\\nested\\doc.json"]
    )

    assert issues == []
    assert text is not None
    payload = json.loads(text)
    assert payload["batch"] == ["sub/nested/doc.json"]


# --------------------------------------------------------------------------- #
# TC-001c / LLR-001.3 — round-trip equality, issues == 0 (C-1 canonical form)
# --------------------------------------------------------------------------- #


def test_roundtrip_equals_intent_in_canonical_form(tmp_path: Path) -> None:
    """serialize -> write -> read_project_manifest yields intent, 0 issues.

    Intent (LLR-001.3): correctness is round-trip fidelity to the reader
    oracle. Equality is asserted in the C-1 canonical comparison form — the
    intended entries are RESOLVED against the project dir (the
    ``test_variant_execution.py:163`` idiom), so both sides are
    resolved-absolute ``Path`` objects; ``active_variant`` is the raw string.
    """
    project_dir = tmp_path
    intended_batch = ["doc.json"]
    intended_assignments = {"b": ["extra.json"]}
    vset = _variant_set("b", "a", "b")

    text, issues = serialize_manifest(
        vset,
        project_dir,
        batch=intended_batch,
        assignments=intended_assignments,
    )
    assert issues == []
    assert text is not None
    (project_dir / PROJECT_MANIFEST_NAME).write_text(text, encoding="utf-8")

    manifest = read_project_manifest(project_dir)

    assert manifest is not None
    assert manifest.issues == []
    assert manifest.active_variant == "b"  # raw string (C-1)
    assert manifest.batch == [(project_dir / e).resolve() for e in intended_batch]
    assert manifest.assignments == {
        "b": [(project_dir / e).resolve() for e in intended_assignments["b"]]
    }


def test_roundtrip_schema_version_survives(tmp_path: Path) -> None:
    """schema_version survives the round-trip as the same int (LLR-001.3 AC)."""
    project_dir = tmp_path
    vset = _variant_set("a", "a")
    text, issues = serialize_manifest(vset, project_dir, schema_version=1)
    assert issues == []
    assert text is not None
    (project_dir / PROJECT_MANIFEST_NAME).write_text(text, encoding="utf-8")

    manifest = read_project_manifest(project_dir)
    assert manifest is not None
    assert manifest.schema_version == 1


# --------------------------------------------------------------------------- #
# TC-001d / LLR-001.4 — byte-deterministic output
# --------------------------------------------------------------------------- #


def test_deterministic_byte_identical_output(tmp_path: Path) -> None:
    """Two serializations of the same composition are byte-identical.

    Intent (LLR-001.4): a no-change re-save must be a no-op and the verify
    step deterministic, so the encoder uses stable key/list order.
    """
    vset = _variant_set("b", "a", "b")
    kwargs = {
        "batch": ["doc.json", "more.json"],
        "assignments": {"a": ["x.json"], "b": ["y.json"]},
    }
    first, issues_first = serialize_manifest(vset, tmp_path, **kwargs)
    second, issues_second = serialize_manifest(vset, tmp_path, **kwargs)

    assert issues_first == [] and issues_second == []
    assert first is not None
    assert first == second


# --------------------------------------------------------------------------- #
# TC-001e / LLR-001.5 — refuse absolute/escaping entry -> (None, finding)
# --------------------------------------------------------------------------- #


def test_refuse_escape_and_absolute_entries_writes_nothing(tmp_path: Path) -> None:
    """A ../../x entry AND an absolute entry are both refused, no text emitted.

    Intent (LLR-001.5 / M-3): the serializer must REFUSE — return
    ``(None, [finding, ...])`` and emit nothing — for any entry the reader
    would reject, so the tool never writes a manifest the reader can't use.
    """
    abs_entry = str((tmp_path / "outside.json").resolve())
    vset = _variant_set("a", "a")

    text, issues = serialize_manifest(
        vset,
        tmp_path,
        batch=["../../escape.json"],
        assignments={"a": [abs_entry]},
    )

    assert text is None
    assert len(issues) >= 1
    assert all(i.code == MANIFEST_WRITE_ESCAPE for i in issues)
    # The finding names each offending entry so a consumer can report it.
    joined = " ".join(i.message for i in issues)
    assert "escape.json" in joined
    assert "outside.json" in joined


def test_clean_composition_passes_the_gate(tmp_path: Path) -> None:
    """A clean composition yields 0 findings and serialization proceeds.

    Intent (LLR-001.5 threshold): the gate must not be a false positive — a
    safe composition serializes normally.
    """
    vset = _variant_set("a", "a")
    text, issues = serialize_manifest(
        vset, tmp_path, batch=["ok.json"], assignments={"a": ["also/ok.json"]}
    )
    assert issues == []
    assert text is not None


def test_refusal_emits_no_file_when_caller_would_write(tmp_path: Path) -> None:
    """The refusal path returns None text so no file can be written (LLR-001.5).

    Intent: verify the HLR-002-side write-refusal invariant at the serialize
    boundary — a refused serialize gives the caller nothing to write.
    """
    vset = _variant_set("a", "a")
    text, issues = serialize_manifest(vset, tmp_path, batch=["../../x.json"])
    assert text is None
    assert issues
    # Simulate the caller's guard: nothing is written on a None text.
    if text is not None:  # pragma: no cover - defensive
        (tmp_path / PROJECT_MANIFEST_NAME).write_text(text, encoding="utf-8")
    assert not (tmp_path / PROJECT_MANIFEST_NAME).exists()
