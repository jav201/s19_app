"""No private account, host or LAN-address token in any tracked text file.

Why: this repository is public. Run records (``.dev-flow/``), test docstrings and
compiled ``.pyc`` files once carried the operator's local account names, the
Linux runners' accounts and LAN addresses, and a runner host name; they were
redacted forward (the history keeps them). This law keeps them from coming back.

The tokens themselves must not be written here, so the test keeps only their
sha256 digests and lengths: every tracked text file is split into words
(letters, digits, ``_ . -``), each word of a listed length is hashed, and a
digest match is a failure naming the file and line. A token glued to a longer
word (``xjjgh8``) is not seen; the redaction covered every whole-word form
found at the time, and new records are written with ``~`` / ``<user>`` /
``<host>`` placeholders.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# sha256(token) -> token length. Accounts, LAN addresses and host names of the
# operator's machines (redacted 2026-11-13).
FORBIDDEN_DIGESTS: dict[str, int] = {
    "1cdf92120cc9fd75e8fd07d7459b21227030acc96c19c8777dce130ad859ce71": 8,
    "c4bae0a25aacc7b82c55e64d64c816cd8e31a24a671cc1b1caf38f499835f3ad": 7,
    "7cfbb18a006ee085295121ce0139a59f4e8abde1beaaff2f1dfc80dd09eaf1e1": 5,
    "dd39ce1fea64ef386a915fc862bc287d57bb7629a960ebc69ec9b8f3a122299b": 12,
    "4a41fa5f84749be160db00f6a73370cfbcc4da931fa0053ed46b5d757cd46867": 14,
    "fbc3db768e89dbab8da11350faa84d0061545b7c653858f3fa6595302934c8df": 11,
    "037e406699771565d701ea9f793e936cc900e5c9620e1dcf6da0b7832ec5a07e": 11,
}

_WORD = re.compile(rb"[A-Za-z0-9_.-]+")


def find_forbidden_tokens(
    name: str, data: bytes, digests: dict[str, int]
) -> list[str]:
    """Return ``<name>:<line>`` for every word of ``data`` whose sha256 is listed."""
    lengths = set(digests.values())
    hits: list[str] = []
    for lineno, line in enumerate(data.splitlines(), 1):
        for match in _WORD.finditer(line):
            word = match.group()
            # A dotted or dashed word may hold the token as one part
            # (``ssh user@host`` splits on ``@``; ``pytest-of-<user>`` does not).
            for part in {word, *re.split(rb"[-]", word)}:
                if len(part) in lengths and (
                    hashlib.sha256(part).hexdigest() in digests
                ):
                    hits.append(f"{name}:{lineno}")
    return hits


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git ls-files is not available in this checkout")
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def test_no_tracked_file_holds_a_private_token() -> None:
    files = _tracked_files()
    assert len(files) > 500, f"only {len(files)} tracked files: the scan would be vacuous"
    hits: list[str] = []
    for rel in files:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        hits.extend(find_forbidden_tokens(rel, path.read_bytes(), FORBIDDEN_DIGESTS))
    assert not hits, (
        "private account / host / LAN-address token in tracked files "
        f"(write ~, <user>, <host> instead): {sorted(set(hits))[:20]}"
    )


def test_the_scan_finds_a_listed_token_in_each_form() -> None:
    """Negative control: with a stand-in token listed, every spelling a record
    uses is reported, and an unlisted word is not."""
    token = b"zqfaketok"
    digests = {hashlib.sha256(token).hexdigest(): len(token)}
    text = b"\n".join(
        [
            b"ssh zqfaketok@host",
            b"path /home/zqfaketok/work",
            b"C:\\Users\\zqfaketok\\Github",
            b"tmp/pytest-of-zqfaketok/x",
            b"clean line zqfaketoken",
        ]
    )
    assert find_forbidden_tokens("f.txt", text, digests) == [
        "f.txt:1",
        "f.txt:2",
        "f.txt:3",
        "f.txt:4",
    ]
