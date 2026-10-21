"""Inc-2 mutation battery (the Inc-1 runner, one edit per mutant).

One edit per mutant, one node per run, restore proven by SHA-256 after every arm.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-2/mutate.py
"""
import hashlib
import os
import pathlib
import subprocess
import sys

PS = pathlib.Path("s19_app/tui/services/flow_persistence_service.py")
VES = pathlib.Path("s19_app/tui/services/variant_execution_service.py")
FES = pathlib.Path("s19_app/tui/services/flow_execution_service.py")
IS = pathlib.Path("s19_app/tui/insight_style.py")
B = "tests/test_b97_flow_builder.py::"
X = "tests/test_b97_flow_execution.py::"
NUL = b'"\\x00"'


def nul_off(anchor: bytes, what: bytes) -> tuple:
    return anchor, anchor.replace(b"if " + NUL + b" in " + what + b":", b"if False:", 1)


FIELD = B + "test_tc_b97_62_nul_in_each_block_field_refuses_the_flow"
MUTANTS = [
    ("M1-flow-ref-nul-off", PS,
     *nul_off(b'if "\\x00" in ref:\r\n                findings.append(\r\n                    _finding(', b"ref"),
     [FIELD + "[change_doc_ref]", FIELD + "[output_name]", FIELD + "[image_ref]",
      B + "test_tc_b97_62_p36_nul_flow_file_refused"]),
    ("M2-a2b-nul-off", PS,
     *nul_off(b'        if "\\x00" in ref:\r\n            findings.append(', b"ref"),
     [FIELD + "[a2b_binding_ref]"]),
    ("M3-log-ref-nul-off", PS, *nul_off(b'if "\\x00" in log_ref:', b"log_ref"),
     [FIELD + "[log_ref]"]),
    ("M4-output-path-nul-off", PS, *nul_off(b'if "\\x00" in output_path:', b"output_path"),
     [FIELD + "[output_path]"]),
    ("M5-a2l-nul-off", PS, *nul_off(b'if "\\x00" in a2l_ref:', b"a2l_ref"),
     [B + "test_tc_b97_62_nul_a2l_ref_refuses_the_flow"]),
    ("M6-flow-stat-oserror-only", PS,
     b"size = flow_path.stat().st_size\r\n    except (OSError, ValueError) as exc:",
     b"size = flow_path.stat().st_size\r\n    except OSError as exc:",
     [B + "test_tc_b97_62_nul_in_the_file_path_is_refused_at_stat[load_flow_json]"]),
    ("M7-set-stat-oserror-only", PS,
     b"size = set_path.stat().st_size\r\n    except (OSError, ValueError) as exc:",
     b"size = set_path.stat().st_size\r\n    except OSError as exc:",
     [B + "test_tc_b97_62_nul_in_the_file_path_is_refused_at_stat[load_chain_set]"]),
    ("M8-template-nul-term-off", PS,
     b'        "\\x00" in ref\r\n        or "/" in ref',
     b'        False\r\n        or "/" in ref',
     [B + "test_tc_b97_62_p36_nul_template_refuses_the_set"]),
    ("M9-set-input-nul-off", PS,
     *nul_off(b'if "\\x00" in ref:\r\n                findings.append(\r\n                    _chain_set_finding(', b"ref"),
     [B + "test_tc_b97_62_p36_nul_input_ref_refuses_the_set"]),
    ("M10-guard-nul-off", VES, *nul_off(b'if "\\x00" in text:', b"text"),
     [B + "test_tc_b97_62_p36_p50_manifest_guard_refuses_nul_entry",
      B + "test_tc_b97_62_p36_run_flow_over_nul_ref_is_a_block_error",
      B + "test_tc_b97_62_p50_bound_lane_input_is_a_block_error",
      B + "test_tc_b97_62_manifest_nul_entry_skipped_others_kept"]),
    ("M11-noun-instruccion", FES, b'else "instruction"', b'else "instruccion"',
     [X + "test_tc_b97_25_service_constants_carry_no_spanish",
      X + "test_tc_b97_25_pause_summary_in_english[manual-instruction]"]),
    ("M12-missing-output-es", FES, b'"run the external step before confirming"',
     b'"correr el paso externo antes de confirmar"',
     [X + "test_tc_b97_25_service_constants_carry_no_spanish",
      X + "test_tc_b97_25_confirm_and_refusal_lines_in_english"]),
    ("M13-waiting-prototype-amber", IS, b'WAITING_HUMAN = "#e8ad3d"', b'WAITING_HUMAN = "#e8a33d"',
     [B + "test_tc_b97_18_waiting_and_crc_tokens_declared_apart"]),
    ("M14-crc-is-waiting", IS, b'CRC_FAMILY = "#c9562b"', b'CRC_FAMILY = "#e8ad3d"',
     [B + "test_tc_b97_18_waiting_and_crc_tokens_declared_apart"]),
    ("M15-funnel-notice-es", FES, b'"the placeholder stays intact"', b'"el placeholder queda intacto"',
     [X + "test_tc_b97_25_funnel_notice_in_english",
      X + "test_tc_b97_25_service_constants_carry_no_spanish"]),
]

if len(sys.argv) > 1:
    MUTANTS = [m for m in MUTANTS if m[0].split("-")[0] in sys.argv[1:]]

env = dict(os.environ, PY_COLORS="0", PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
env.pop("NO_COLOR", None)
print("arms:", sum(len(m[4]) for m in MUTANTS), flush=True)
bad = 0
for mid, f, old, new, nodes in MUTANTS:
    src = f.read_bytes()
    h0 = hashlib.sha256(src).hexdigest()
    assert src.count(old) == 1, f"{mid}: BAD (anchor found {src.count(old)} times)"
    for node in nodes:
        try:
            f.write_bytes(src.replace(old, new, 1))
            if hashlib.sha256(f.read_bytes()).hexdigest() == h0:
                print(f"{mid} {node}: BAD (the edit did not apply)")
                sys.exit(1)
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", "--tb=line", node],
                env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        finally:
            f.write_bytes(src)
        h1 = hashlib.sha256(f.read_bytes()).hexdigest()
        assert h1 == h0, "the restore is not proven"
        verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(r.returncode)
        bad += verdict is None
        tail = [ln for ln in r.stdout.splitlines() if "Error" in ln or "passed" in ln or "failed" in ln][-2:]
        print(f"{mid} [{f.name}] {node.split('::')[1]}: {verdict or 'CRASH/BAD (exit %d)' % r.returncode}")
        print(f"    restore sha256 {h1} == before {h0}")
        for ln in tail:
            print("    | " + ln.strip())
        sys.stdout.flush()
sys.exit(1 if bad else 0)
