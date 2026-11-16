"""Exercise legacy redaction helpers on Linux without touching the clipboard."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def assert_redacted(message: str, canary: str, label: str) -> None:
    escaped = canary.encode("unicode_escape").decode("ascii")
    forbidden = (canary, canary[:16], repr(canary), escaped)
    assert not any(token and token in message for token in forbidden), label
    assert any(token in message for token in ("chars=", "captured messages", "stage=")), label


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: redaction_runtime_probe.py REPO", file=sys.stderr)
        return 2
    repo = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(repo))
    namespace = runpy.run_path(str(repo / "tests" / "test_b103_clipboard_windows.py"))
    canary = "LOCAL-ONLY-CANARY\nsecond-line-☃"

    try:
        namespace["_assert_content_equal"](canary, "expected", "synthetic")
    except AssertionError as exc:
        assert_redacted(str(exc), canary, "content mismatch redaction")
        content_message = str(exc)
    else:
        raise AssertionError("synthetic content mismatch did not fail")

    try:
        namespace["_assert_log_excludes"]([canary], canary, "synthetic")
    except AssertionError as exc:
        assert_redacted(str(exc), canary, "log mismatch redaction")
        log_message = str(exc)
    else:
        raise AssertionError("synthetic log leak did not fail")

    probe_result = "win32 write ok, PowerShell read " + repr(canary)
    probe_message = namespace["_probe_failure_metadata"](probe_result)
    assert_redacted(probe_message, canary, "probe result redaction")
    assert "stage=round-trip-mismatch" in probe_message

    namespace["_assert_content_equal"]("same", "same", "synthetic success")
    namespace["_assert_log_excludes"](["clean"], canary, "synthetic success")
    print("PASS content mismatch redacted; metadata:", content_message)
    print("PASS log mismatch redacted; metadata:", log_message)
    print("PASS probe mismatch redacted; metadata:", probe_message)
    print("summary total=4 passed=4 failed=0 clipboard_calls=0 powershell_calls=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
