"""Fail closed before publishing WinCI transcripts or JUnit artifacts."""

from __future__ import annotations

import argparse
import html
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

HOSTILE_CANARY = "[red]\x1b\x07\x1b]52;c;U0VFRF9PU0M=\x07\nSUFFIX"
CONTROL_CANARIES = {
    "copy-secret": ("SECRET-COPY-43", "SECRET-COPY-46", "SECRET-COPY-"),
    "xml-secret": ("<&>\"'\r\n\tSECRET-COPY-43",),
    "text-secret": ("SECRET-TEXT-42", "SECRET-TEXT-45", "SECRET-TEXT-"),
    "right-click-secret": ("SECRET-RC-44", "SECRET-RC-"),
    "selection-secret": ("SECRET-SELECTION-MARKER", "SECRET-SELECTION"),
    "nul-suffix": ("VISIBLE\x00SECRET-SUFFIX", "SECRET-SUFFIX"),
    "seed": ("SEED-1b", "SEED-APP-1b", "SEED-OS-1b", "SEED-Ω-漢字-🙂"),
    "os-state": ("OS-BEFORE",),
    "transport-cr": ("SEED-CR\rNEXT",),
    "transport-crlf": ("SEED-CRLF\r\nNEXT",),
    "external-round-trip": ("L1\rL2", "L1\nL2", "L1\nL2\n"),
    "hostile": (
        HOSTILE_CANARY,
        HOSTILE_CANARY + "\n",
        HOSTILE_CANARY[:16],
        "U0VFRF9PU0M=",
    ),
    "matrix-p1": ("COPY-1 Ñoño Ж 漢字 😀", "COPY-1 Ñoño"),
    "matrix-p2": ("L1 Ñ€\nL2 漢",),
    "paste-payload": ("P1 line\nsecond",),
    "powershell-read": ("PS-READ-Ñ\rL2\r\nL3\n", "PS-READ-Ñ", "PS-READ"),
    "powershell-write": ("PS-WRITE",),
    "control-payload": (
        "A\x1b[13DB\x00C\u202e\ud800",
        "A\x1b[13DBC",
        "L1\x1b[2J\nL2",
        "A\x1b[13DB\x00C\tD\r\nE\u202e\ud800",
        "A\x1b[13DBC\tD\r\nE\u202e\ud800",
        "L1 Ñ€\x1b[2J\nL2 漢",
    ),
}
CREDENTIAL_PATTERNS = {
    "github-token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
        re.IGNORECASE,
    ),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
    "bearer": re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    "private-key": re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    "secret-assignment": re.compile(
        r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|"
        r"client[_-]?secret|auth[_-]?token|secret)[\w-]*\s*[:=]\s*"
        r"(?:'[^'\r\n]{4,}'|\"[^\"\r\n]{4,}\"|[^\s,;<]{8,})"
    ),
    "probe-nonce": re.compile(r"\bb103-probe-[0-9a-f]{32}\b", re.IGNORECASE),
}
PERSONAL_PATH_PATTERNS = {
    "windows-user-path": re.compile(
        r"(?i)\b[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\\/\s<>\"']+"
    ),
    "wsl-user-path": re.compile(r"(?i)/mnt/[a-z]/users/[^/\s<>\"']+"),
    "unix-home-path": re.compile(r"(?i)/(?:home|root)/[^/\s<>\"']+"),
    "macos-user-path": re.compile(r"(?i)/users/[^/\s<>\"']+"),
}
BACKSLASH_ESCAPE = re.compile(
    r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|([abfnrtv\\/'\"]))"
)
XML_NUMERIC_REFERENCE = re.compile(r"&#(?:x([0-9a-fA-F]+)|([0-9]+));")
SURROGATE_PAIR = re.compile("([\ud800-\udbff])([\udc00-\udfff])")
SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "/": "/",
    "'": "'",
    '"': '"',
}


@dataclass
class SafetyAudit:
    files: int = 0
    bytes: int = 0
    violations: list[str] = field(default_factory=list)


def _character(code: int) -> str:
    return chr(code) if 0 <= code <= 0x10FFFF else "\ufffd"


def _decode_backslash_escapes(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        unicode_short, unicode_long, hexadecimal, simple = match.groups()
        if unicode_short is not None:
            return _character(int(unicode_short, 16))
        if unicode_long is not None:
            return _character(int(unicode_long, 16))
        if hexadecimal is not None:
            return _character(int(hexadecimal, 16))
        return SIMPLE_ESCAPES[simple]

    value = BACKSLASH_ESCAPE.sub(replace, value)
    return SURROGATE_PAIR.sub(
        lambda match: _character(
            0x10000 + ((ord(match[1]) - 0xD800) << 10) + ord(match[2]) - 0xDC00
        ),
        value,
    )


def _decode_xml_references(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        hexadecimal, decimal = match.groups()
        return _character(int(hexadecimal, 16) if hexadecimal is not None else int(decimal))

    return XML_NUMERIC_REFERENCE.sub(replace, value)


def _haystacks(value: str) -> frozenset[str]:
    variants = {value}
    for _ in range(3):
        for current in tuple(variants):
            variants.add(_decode_xml_references(current))
            variants.add(html.unescape(current))
            variants.add(_decode_backslash_escapes(current))
    return frozenset(variants)


def _numeric_xml(value: str, *, hexadecimal: bool = False) -> str:
    pieces: list[str] = []
    for character in html.escape(value, quote=True):
        code = ord(character)
        if code < 32 or code > 126 or 0xD800 <= code <= 0xDFFF:
            pieces.append(f"&#x{code:X};" if hexadecimal else f"&#{code};")
        else:
            pieces.append(character)
    return "".join(pieces)


@lru_cache(maxsize=None)
def _forms(value: str) -> frozenset[str]:
    represented = repr(value)
    escaped = value.encode("unicode_escape").decode("ascii")
    json_escaped = json.dumps(value)
    forms = {
        value,
        represented,
        represented[1:-1],
        escaped,
        json_escaped,
        json_escaped[1:-1],
        json.dumps(value, ensure_ascii=False),
        html.escape(value, quote=True),
        _numeric_xml(value),
        _numeric_xml(value, hexadecimal=True),
    }
    forms.update(form[:16] for form in tuple(forms) if form)
    return frozenset(form for form in forms if form)


def _scan_text(label: str, value: str, audit: SafetyAudit) -> None:
    haystacks = _haystacks(value)
    for canary_id, values in CONTROL_CANARIES.items():
        for canary in values:
            if any(any(form in haystack for haystack in haystacks) for form in _forms(canary)):
                violation = f"CONTROL_CANARY artifact={label} id={canary_id}"
                if violation not in audit.violations:
                    audit.violations.append(violation)
                break
    for category, pattern in CREDENTIAL_PATTERNS.items():
        if any(pattern.search(haystack) for haystack in haystacks):
            audit.violations.append(f"CREDENTIAL artifact={label} id={category}")
    for category, pattern in PERSONAL_PATH_PATTERNS.items():
        if any(pattern.search(haystack) for haystack in haystacks):
            audit.violations.append(f"PERSONAL_PATH artifact={label} id={category}")


def _decoded_views(data: bytes) -> list[str]:
    encodings = ["utf-8"]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data[:4096]:
        encodings.extend(("utf-16", "utf-16-le", "utf-16-be"))
    return [data.decode(encoding, errors="replace") for encoding in encodings]


def audit_artifacts(
    transcript: Path,
    junit_xml: Path,
    gate_transcript: Path | None = None,
) -> SafetyAudit:
    """Scan raw and normalized artifact forms without reproducing findings."""
    audit = SafetyAudit()
    artifacts = [("transcript", transcript), ("junit", junit_xml)]
    if gate_transcript is not None:
        artifacts.append(("gate-transcript", gate_transcript))
    for label, path in artifacts:
        try:
            data = path.read_bytes()
        except OSError as exc:
            audit.violations.append(
                f"ARTIFACT_UNREADABLE artifact={label} error={type(exc).__name__}"
            )
            continue
        audit.files += 1
        audit.bytes += len(data)
        if not data:
            audit.violations.append(f"ARTIFACT_EMPTY artifact={label}")
        for view in _decoded_views(data):
            _scan_text(label, view, audit)
        if label == "junit":
            try:
                root = ET.fromstring(data)
            except (ET.ParseError, ValueError) as exc:
                audit.violations.append(f"JUNIT_XML_UNREADABLE error={type(exc).__name__}")
            else:
                parsed_text = "\n".join(
                    [value for element in root.iter() for value in element.attrib.values()]
                    + [element.text or "" for element in root.iter()]
                )
                _scan_text(label, parsed_text, audit)
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transcript", type=Path, required=True)
    parser.add_argument("--junit-xml", type=Path, required=True)
    parser.add_argument("--gate-transcript", type=Path)
    args = parser.parse_args(argv)
    audit = audit_artifacts(args.transcript, args.junit_xml, args.gate_transcript)
    print(f"ARTIFACT_SAFETY files={audit.files} bytes={audit.bytes}")
    for violation in audit.violations:
        print(f"VIOLATION {violation}")
    print(
        f"ARTIFACT_SAFETY_RESULT {'PASS' if not audit.violations else 'FAIL'} "
        f"violations={len(audit.violations)}"
    )
    return 1 if audit.violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
