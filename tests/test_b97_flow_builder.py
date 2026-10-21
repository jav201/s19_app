"""Batch-97 Flow Builder arms (HLR-146).

Inc-2 arms only: the NUL refusal of LLR-146.14 (TC-B97-62, 15 arms plus the
manifest and A2L arms the Code-Wire graph names) and the token half of
LLR-146.6 (TC-B97-18 token arm). The TCSS mirror arm of TC-B97-18 moves to
Inc-5 with ``styles.tcss`` (PDR condition PC-12); the CRC card paint lands
there too.

Where each NUL check sits (design-proposal I-6, PDR condition PC-17):

* ``dict_to_flow`` — the five single-ref fields and ``a2l_ref`` →
  ``FLOW-UNSAFE-REF`` (before the guard and before the ``output_name`` shape
  check, so a NUL ``output_name`` is ``FLOW-UNSAFE-REF``).
* ``_parse_a2b_entry`` — each binding ``ref`` → ``FLOW-UNSAFE-REF``.
* ``_parse_external_step_entry`` — ``log_ref`` and ``output_path`` →
  ``FLOW-UNSAFE-REF`` (both were accepted on ``main``, not raised).
* ``dict_to_chain_set`` — the template (``_is_plain_template_stem``) and each
  input ref → ``CHAIN-SET-UNSAFE-REF``.
* ``_resolve_manifest_entry`` — every other caller (manifest entries, run-time
  refs, a bound lane input) → ``MANIFEST-PATH-ESCAPE``.
* the ``stat()`` guards of ``load_flow_json`` / ``load_chain_set`` catch
  ``ValueError`` → ``FLOW-JSON-PARSE`` / ``CHAIN-SET-JSON-PARSE``.

Every call is wrapped so a raise is counted, never propagated: on ``main`` the
arms fail at the named ``0 exceptions`` / ``refused`` assertion, not at an
import (PC-11). Each test names the mutation that turns it RED.
"""
from __future__ import annotations

import colorsys
import json
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

import pytest

from s19_app.tui import insight_style
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services import variant_execution_service as ves
from s19_app.tui.services.flow_execution_service import (
    ChainSpec,
    run_chain_set,
    run_flow,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    EXTERNAL_MODE_TERMINAL,
    A2BBlock,
    A2BInputBinding,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    FlowContext,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from tests.b97_fixtures import HOSTILE_NUL, nul_flow, nul_set, patch_chain_blocks

FLOW_UNSAFE_REF = "FLOW-UNSAFE-REF"
CHAIN_SET_UNSAFE_REF = "CHAIN-SET-UNSAFE-REF"
MANIFEST_PATH_ESCAPE = "MANIFEST-PATH-ESCAPE"


def _project(tmp_path: Path) -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    return project_dir


def _call(fn: Callable[..., Any], *args: Any) -> Tuple[Any, Optional[BaseException]]:
    """Run ``fn``; return ``(result, None)`` or ``(None, the exception)``."""
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001 - the arm counts the raise
        return None, exc


def _assert_refused(
    outcome: Tuple[Any, Optional[BaseException]], code: str, field: str
) -> None:
    """0 exceptions, no artifact, exactly one finding of ``code`` naming ``field``."""
    result, exc = outcome
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    artifact, findings = result
    assert artifact is None, f"a NUL in {field} was accepted: {artifact!r}"
    assert len(findings) == 1, [(f.code, f.message) for f in findings]
    assert findings[0].code == code, (findings[0].code, findings[0].message)
    assert field in findings[0].message, findings[0].message


def _arms_flow() -> Flow:
    """One block of every kind that carries a path-bearing field."""
    return Flow(
        name="nul_arms",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("calib_hotfix.json"),
            CheckBlock("baseline.chk.json"),
            CrcBlock("crc.json"),
            A2BBlock(
                image_a=A2BInputBinding("file", "other.s19"),
                image_b=A2BInputBinding("flow", "0"),
            ),
            ExternalStepBlock(
                mode=EXTERNAL_MODE_TERMINAL,
                instruction="python flash.py",
                log_ref="run.log",
                output_path="ext_out.s19",
            ),
            WriteOutBlock("out.s19"),
        ],
    )


def _write_flow(project_dir: Path, payload: dict) -> Path:
    path = project_dir / fps.FLOWS_SUBDIR / "arms.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# (arm id, path into the payload's blocks, the field name the finding names)
# flow_model.py:229, 250, 267, 289, 315, 338, 505, 506 — the eight fields of
# LLR-146.14, in that order.
_FIELD_ARMS: List[Tuple[str, Tuple[Any, ...], str]] = [
    ("image_ref", (0, "image_ref"), "image_ref"),
    ("change_doc_ref", (1, "change_doc_ref"), "change_doc_ref"),
    ("output_name", (6, "output_name"), "output_name"),
    ("check_doc_ref", (2, "check_doc_ref"), "check_doc_ref"),
    ("config_ref", (3, "config_ref"), "config_ref"),
    ("a2b_binding_ref", (4, "image_a", "ref"), "image_a.ref"),
    ("log_ref", (5, "log_ref"), "log_ref"),
    ("output_path", (5, "output_path"), "output_path"),
]


# --------------------------------------------------------------------------- #
# TC-B97-62 — LLR-146.14, a NUL in a ref is refused, never raised
# --------------------------------------------------------------------------- #


def test_tc_b97_62_clean_arms_flow_loads(tmp_path: Path) -> None:
    """Positive control: the envelope every field arm mutates loads clean, so
    a refusal in an arm below is caused by its NUL and nothing else.

    Reddening mutation: none in the source; a fixture edit that makes the
    envelope invalid (e.g. a downstream A2B flow index) turns it RED.
    """
    project_dir = _project(tmp_path)
    path = _write_flow(project_dir, fps.flow_to_dict(_arms_flow()))
    flow, findings = fps.load_flow_json(path, project_dir)
    assert findings == [] and flow is not None


@pytest.mark.parametrize(
    "keys,field", [(keys, field) for _, keys, field in _FIELD_ARMS],
    ids=[arm for arm, _, _ in _FIELD_ARMS],
)
def test_tc_b97_62_nul_in_each_block_field_refuses_the_flow(
    tmp_path: Path, keys: Tuple[Any, ...], field: str
) -> None:
    """One ``load_flow_json`` arm per enumerated block field (8): a NUL in the
    field refuses the whole file with one ``FLOW-UNSAFE-REF`` naming it.

    Reddening mutations: the NUL pre-reject removed from ``dict_to_flow``
    (image_ref / change_doc_ref / output_name / check_doc_ref / config_ref
    are refused under the wrong code — the guard's own NUL arm answers
    ``MANIFEST-PATH-ESCAPE`` — or, for ``output_name``, load), from
    ``_parse_a2b_entry`` (the binding raises) or from
    ``_parse_external_step_entry`` (``log_ref`` / ``output_path`` load).
    """
    project_dir = _project(tmp_path)
    payload = fps.flow_to_dict(_arms_flow())
    target = payload["blocks"]
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = "arm\x00.bin"
    path = _write_flow(project_dir, payload)
    _assert_refused(_call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, field)


def test_tc_b97_62_nul_a2l_ref_refuses_the_flow(tmp_path: Path) -> None:
    """The optional ``a2l_ref`` rides the same grammar as the other read refs,
    so a NUL in it gets the same ``FLOW-UNSAFE-REF``.

    Reddening mutation: the V6b NUL branch removed (the ref is refused under
    the wrong code, the guard's ``MANIFEST-PATH-ESCAPE``).
    """
    project_dir = _project(tmp_path)
    payload = fps.flow_to_dict(_arms_flow())
    payload["blocks"][0]["a2l_ref"] = "demo\x00.a2l"
    path = _write_flow(project_dir, payload)
    _assert_refused(_call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, "a2l_ref")


def test_tc_b97_62_p36_nul_flow_file_refused(tmp_path: Path) -> None:
    """P-36 arm 1: the ``nul_flow`` fixture (``patch_chain`` with
    ``change_doc_ref = HOSTILE_NUL``) is refused by ``load_flow_json``.

    Reddening mutation: the ``dict_to_flow`` NUL pre-reject removed.
    """
    project_dir = _project(tmp_path)
    path = nul_flow(project_dir)
    _assert_refused(
        _call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, "change_doc_ref"
    )


def test_tc_b97_62_p36_run_flow_over_nul_ref_is_a_block_error(tmp_path: Path) -> None:
    """P-36 arm 2: ``run_flow`` over a flow built in memory with the NUL
    ``change_doc_ref`` records a block error carrying ``MANIFEST-PATH-ESCAPE``
    and never raises.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``
    (its ``resolve()`` raises ``ValueError``).
    """
    project_dir = _project(tmp_path)
    _copy_prg(project_dir)
    flow = Flow(name="nul_mem", blocks=patch_chain_blocks(HOSTILE_NUL))
    result, exc = _call(run_flow, flow, FlowContext(project_dir=project_dir))
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_ERROR, (patch.status, patch.summary)
    assert any(MANIFEST_PATH_ESCAPE in line for line in patch.diagnostics), patch.diagnostics


def test_tc_b97_62_p36_nul_template_refuses_the_set(tmp_path: Path) -> None:
    """P-36 arm 3: the ``nul_set`` fixture (template ``patch\\x00chain``) is
    refused with one ``CHAIN-SET-UNSAFE-REF`` naming the template. On ``main``
    it loads and the later template load raises.

    Reddening mutation: the NUL term removed from ``_is_plain_template_stem``.
    """
    project_dir = _project(tmp_path)
    path = nul_set(project_dir)
    _assert_refused(
        _call(fps.load_chain_set, path, project_dir), CHAIN_SET_UNSAFE_REF, "template"
    )


def test_tc_b97_62_p36_nul_input_ref_refuses_the_set(tmp_path: Path) -> None:
    """P-36 arm 4: a NUL in a chain-set input ref is refused with one
    ``CHAIN-SET-UNSAFE-REF`` naming the inputs ref.

    Reddening mutation: the input-ref NUL branch removed from
    ``dict_to_chain_set`` (the guard's ``resolve()`` raises).
    """
    project_dir = _project(tmp_path)
    entry = fps.ChainSetEntry(chain="lane0", template="patch_chain", inputs=((0, "base\x00.s19"),))
    payload = fps.chain_set_to_dict(fps.ChainSet(name="s", chains=(entry,)))
    path = project_dir / fps.FLOWSETS_SUBDIR / "nul_input.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    _assert_refused(
        _call(fps.load_chain_set, path, project_dir), CHAIN_SET_UNSAFE_REF, "inputs"
    )


def test_tc_b97_62_p36_p50_manifest_guard_refuses_nul_entry(tmp_path: Path) -> None:
    """P-36 arm 5 (also the bound-lane-input path of P-50): the shared guard
    resolves no path for a NUL entry and appends one ``MANIFEST-PATH-ESCAPE``
    naming the context.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path).resolve()
    issues: list = []
    resolved, exc = _call(
        ves._resolve_manifest_entry, project_dir, "base\x00.s19", "SourceBlock.image_ref", issues
    )
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    assert resolved is None
    assert [i.code for i in issues] == [MANIFEST_PATH_ESCAPE], issues
    assert "SourceBlock.image_ref" in issues[0].message


def test_tc_b97_62_p50_bound_lane_input_is_a_block_error(tmp_path: Path) -> None:
    """P-50 at the service: a lane whose SOURCE is bound to ``base\\x00.s19``
    runs to a ``source unresolved`` block error naming ``MANIFEST-PATH-ESCAPE``
    — through ``run_flow`` and the provenance seam ``_chain_inputs`` — and
    never raises. The UI half (``#fx_bind_0_0``) is AT-B97-23, Inc-6.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path)
    _copy_prg(project_dir)
    spec = ChainSpec(
        name="lane0",
        template="patch_chain",
        flow=Flow(name="patch_chain", blocks=patch_chain_blocks()),
        bindings={0: "base\x00.s19"},
    )
    record, exc = _call(run_chain_set, [spec], FlowContext(project_dir=project_dir))
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    source = record.outcomes[0].block_results[0]
    assert source.status == BLOCK_STATUS_ERROR and source.summary == "source unresolved"
    assert any(MANIFEST_PATH_ESCAPE in line for line in source.diagnostics), source.diagnostics


def test_tc_b97_62_manifest_nul_entry_skipped_others_kept(tmp_path: Path) -> None:
    """The Code-Wire ``read_project_manifest`` example: a NUL batch entry is
    skipped with one ``MANIFEST-PATH-ESCAPE``; the other entry is kept.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path)
    manifest = {"schema_version": 1, "batch": ["a\x00.s19", "prg.s19"]}
    (project_dir / ves.PROJECT_MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    loaded, exc = _call(ves.read_project_manifest, project_dir)
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    assert [p.name for p in loaded.batch] == ["prg.s19"]
    assert [i.code for i in loaded.issues] == [MANIFEST_PATH_ESCAPE], loaded.issues


@pytest.mark.parametrize(
    "loader,code",
    [(fps.load_flow_json, fps.FLOW_JSON_PARSE), (fps.load_chain_set, fps.CHAIN_SET_JSON_PARSE)],
    ids=["load_flow_json", "load_chain_set"],
)
def test_tc_b97_62_nul_in_the_file_path_is_refused_at_stat(
    tmp_path: Path, loader: Callable[..., Any], code: str
) -> None:
    """A NUL in the file path handed to each ``stat()`` guard (2 arms): the
    ``ValueError`` is caught like an ``OSError`` — no artifact, one finding.

    Reddening mutation: the guard narrowed back to ``except OSError`` (the
    shipped shape, P-36 F).
    """
    project_dir = _project(tmp_path)
    result, exc = _call(loader, project_dir / "flows" / "x\x00.json", project_dir)
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    artifact, findings = result
    assert artifact is None
    assert [f.code for f in findings] == [code], findings
    assert "ValueError" in findings[0].message


def _copy_prg(project_dir: Path) -> None:
    from tests.b97_fixtures import EXAMPLES_DIR

    (project_dir / "prg.s19").write_bytes((EXAMPLES_DIR / "prg.s19").read_bytes())


# --------------------------------------------------------------------------- #
# TC-B97-18 — LLR-146.6, token arm (the TCSS mirror and the paint: Inc-5)
# --------------------------------------------------------------------------- #


def _hue(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)[0] * 360.0


def _hue_distance(a: str, b: str) -> float:
    d = abs(_hue(a) - _hue(b)) % 360.0
    return min(d, 360.0 - d)


def test_tc_b97_18_waiting_and_crc_tokens_declared_apart() -> None:
    """The two role tokens exist with their decided values (ledger .3,
    operator decision 1) and lie 23.0° apart, at least the 20° the waiting
    role needs (P-40). The in-test control shows the predicate can fail: the
    prototype amber ``#e8a33d`` sits 19.5° from the CRC hue.

    Reddening mutations: ``WAITING_HUMAN = "#e8a33d"`` (19.5°, RED) or either
    token removed / changed.
    """
    assert hasattr(insight_style, "WAITING_HUMAN"), "no WAITING_HUMAN token"
    assert hasattr(insight_style, "CRC_FAMILY"), "no CRC_FAMILY token"
    assert insight_style.WAITING_HUMAN == "#e8ad3d"
    assert insight_style.CRC_FAMILY == "#c9562b"
    distance = _hue_distance(insight_style.WAITING_HUMAN, insight_style.CRC_FAMILY)
    assert distance >= 20.0, distance
    assert round(distance, 1) == 23.0, distance
    assert round(_hue_distance("#e8a33d", "#c9562b"), 1) == 19.5
