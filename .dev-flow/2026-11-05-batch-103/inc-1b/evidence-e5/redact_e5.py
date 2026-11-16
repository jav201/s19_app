from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SELF = Path(__file__).resolve()
CENSUS_PATH = ROOT / "redaction-census.json"
CANARY_EXCEPTIONS = {
    ROOT / "matrix" / "contract_probe.py": "executable mismatch/probe/gate controls",
    ROOT / "quit" / "validate_routes.py": "executable probe-redaction route control",
    ROOT / "legacy" / "redaction_runtime_probe.py": "executable legacy redaction control",
}
REQUIRED_REDACTED_PATCHES = {
    ROOT / "integration-pre-ci.patch",
    ROOT / "matrix" / "integration-e5-fix.patch",
}
PATCH_MARKER = (
    b"REDACTED-EVIDENCE-COPY: true\n"
    b"APPLICABLE: false\n"
    b"DO-NOT-APPLY: identities or control canaries were replaced with placeholders.\n"
    b"HISTORICAL-COPY: retained for review only; no execution verdict changed.\n\n"
)


def _literal(value: bytes):
    return lambda match: value


PATH_RULES = (
    (
        "windows_msys_home",
        re.compile(
            rb"(?i)[A-Za-z]:[\\/][^\r\n\"']*?/mnt/[a-z]/Users/(?P<user>[A-Za-z0-9._-]+)"
        ),
        _literal(b"<HOME>"),
    ),
    (
        "wsl_home",
        re.compile(
            rb"(?i)/mnt/[a-z]/(?:Users|Documents and Settings)/(?P<user>[A-Za-z0-9._-]+)"
        ),
        _literal(b"<HOME>"),
    ),
    (
        "windows_home",
        re.compile(
            rb"(?i)[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/](?P<user>[A-Za-z0-9._-]+)"
        ),
        _literal(b"<HOME>"),
    ),
    (
        "unix_home",
        re.compile(
            rb"(?i)(?<![A-Za-z0-9_.-])/(?:home|Users)/(?P<user>[A-Za-z0-9._-]+)"
        ),
        _literal(b"<HOME>"),
    ),
)

GENERAL_RULES = PATH_RULES + (
    (
        "neutral_state_dir",
        re.compile(rb"[a-z][0-9][a-z][0-9]-state"),
        _literal(b"<NEUTRAL_STATE>"),
    ),
    (
        "pytest_temp_account",
        re.compile(rb"(?i)pytest-of-(?P<user>[A-Za-z0-9._-]+)"),
        _literal(b"pytest-of-<USER>"),
    ),
    (
        "xml_hostname",
        re.compile(
            rb"hostname=\"(?P<host>(?!<HOST>|\[HOST\])[^\"]*)\""
        ),
        _literal(b'hostname="<HOST>"'),
    ),
    (
        "account_assignment",
        re.compile(
            rb"(?im)\b(?P<key>USER|USERNAME|LOGNAME|GITHUB_ACTOR)=(?P<user>[A-Za-z0-9._-]+)"
        ),
        lambda match: match.group("key") + b"=<USER>",
    ),
    (
        "hostname_assignment",
        re.compile(rb"(?im)\bHOSTNAME=(?P<host>[A-Za-z0-9._-]+)"),
        _literal(b"HOSTNAME=<HOST>"),
    ),
    (
        "ip_address",
        re.compile(
            rb"(?<![0-9.])(?:10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2})(?![0-9.])"
        ),
        _literal(b"<HOST_IP>"),
    ),
)

CANARY_RULES = (
    (
        "hostile_assignment",
        re.compile(
            rb"(?m)^(?P<prefix>[+-]\s*HOSTILE_NAME\s*=\s*)(?!\s*[\"']?<REDACTED_CANARY>)[^\r\n]+"
        ),
        lambda match: match.group("prefix") + b'"<REDACTED_CANARY>"',
    ),
    (
        "probe_nonce",
        re.compile(rb"b103-probe-[0-9a-f]{32}"),
        _literal(b"<REDACTED_PROBE_NONCE>"),
    ),
    (
        "canary_prefix",
        re.compile(rb"SECRET-[A-Z0-9-]+"),
        _literal(b"<REDACTED_CANARY>"),
    ),
    (
        "canary_suffix",
        re.compile(rb"[A-Z0-9]+(?:-[A-Z0-9]+)*-(?:SECRET|CANARY)\b"),
        _literal(b"<REDACTED_CANARY>"),
    ),
    (
        "clipboard_content_canary",
        re.compile(rb"[A-Z0-9]+(?:-[A-Z0-9]+)*-CLIPBOARD-CONTENT\b"),
        _literal(b"<REDACTED_CANARY>"),
    ),
    (
        "standalone_secret",
        re.compile(rb"(?<![A-Z0-9-])SECRET(?![A-Z0-9-])"),
        _literal(b"<REDACTED_CANARY>"),
    ),
)
ALL_RULES = GENERAL_RULES + CANARY_RULES


def _usable_identity(value: bytes) -> bool:
    if len(value) < 3:
        return False
    if value.lower() in {b"localhost", b"root", b"user", b"host"}:
        return False
    return not (
        (value.startswith(b"<") and value.endswith(b">"))
        or (value.startswith(b"[") and value.endswith(b"]"))
    )


def _collect_identities(records) -> set[bytes]:
    identities = set()
    for _path, _relative, data, _canary_allowed in records:
        for _name, pattern, _replacement in GENERAL_RULES:
            for match in pattern.finditer(data):
                for group in ("user", "host"):
                    try:
                        value = match.group(group)
                    except IndexError:
                        continue
                    if value and _usable_identity(value):
                        identities.add(value)
    return identities


def _identity_pattern(identity: bytes):
    return re.compile(
        rb"(?<![A-Za-z0-9._-])" + re.escape(identity) + rb"(?![A-Za-z0-9._-])"
    )


def _scan(data: bytes, identities: set[bytes], canary_allowed: bool) -> dict[str, int]:
    counts = {}
    rules = GENERAL_RULES if canary_allowed else ALL_RULES
    for name, pattern, _replacement in rules:
        count = len(pattern.findall(data))
        if count:
            counts[name] = count
    identity_hits = sum(
        len(_identity_pattern(identity).findall(data)) for identity in identities
    )
    if identity_hits:
        counts["discovered_identity"] = identity_hits
    return counts


def _canary_scan(data: bytes) -> dict[str, int]:
    counts = {}
    for name, pattern, _replacement in CANARY_RULES:
        count = len(pattern.findall(data))
        if count:
            counts[name] = count
    return counts


def _redact_bytes(
    data: bytes, identities: set[bytes], canary_allowed: bool
) -> tuple[bytes, dict[str, int]]:
    counts = {}
    rules = GENERAL_RULES if canary_allowed else ALL_RULES
    for name, pattern, replacement in rules:
        data, count = pattern.subn(replacement, data)
        if count:
            counts[name] = count
    identity_hits = 0
    for identity in sorted(identities):
        data, count = _identity_pattern(identity).subn(b"<USER>", data)
        identity_hits += count
    if identity_hits:
        counts["discovered_identity"] = identity_hits
    return data, counts


def _merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for name, count in source.items():
        target[name] = target.get(name, 0) + count


def _self_census() -> dict[str, int]:
    user = b"example-user"
    host = b"example-host"
    cases = {
        "windows_msys_home": b"C:/Program Files/Git/mnt/c/Users/" + user + b"/repo",
        "wsl_home": b"/mnt/c/Users/" + user + b"/repo",
        "windows_home": b"C:\\Users\\" + user + b"\\repo",
        "unix_home": b"/home/" + user + b"/repo",
        "neutral_state_dir": bytes((122, 52, 110, 56)) + b"-state",
        "pytest_temp_account": b"pytest-of-" + user,
        "xml_hostname": b'hostname="' + host + b'"',
        "account_assignment": b"USER=" + user,
        "hostname_assignment": b"HOSTNAME=" + host,
        "ip_address": b".".join(
            str(octet).encode("ascii") for octet in (192, 168, 255, 254)
        ),
        "hostile_assignment": b'+HOSTILE_NAME = "synthetic"',
        "probe_nonce": b"b103-probe-" + b"0" * 32,
        "canary_prefix": b"SECRET-" + b"COPY-999",
        "canary_suffix": b"LOCAL-ONLY-" + b"CANARY",
        "clipboard_content_canary": b"PRIVATE-CLIPBOARD-" + b"CONTENT",
        "standalone_secret": b"SECRET",
    }
    passed = 0
    for name, pattern, replacement in ALL_RULES:
        source = cases[name]
        redacted, count = pattern.subn(replacement, source)
        if count != 1 or pattern.search(redacted):
            raise AssertionError(f"known-present redactor census failed: {name}")
        passed += 1
    source = b"/home/" + user + b"/repo\n" + user + b"\n" + host
    records = [(SELF, SELF.name, source, False)]
    identities = _collect_identities(records)
    redacted, counts = _redact_bytes(source, identities | {host}, False)
    if counts.get("discovered_identity", 0) < 2 or user in redacted or host in redacted:
        raise AssertionError("known-present discovered-identity census failed")
    passed += 1
    return {"cases": len(cases) + 1, "passed": passed}


def redact_tree(root: Path, *, write: bool) -> dict:
    self_census = _self_census()
    records = []
    binary_files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() == SELF or path == CENSUS_PATH:
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            binary_files.append(path.relative_to(root).as_posix())
            continue
        records.append((path, path.relative_to(root).as_posix(), data, path in CANARY_EXCEPTIONS))

    missing_patches = REQUIRED_REDACTED_PATCHES - {path for path, _r, _d, _a in records}
    if root.resolve() == ROOT and missing_patches:
        raise FileNotFoundError(f"required historical patches missing: {len(missing_patches)}")

    identities = _collect_identities(records)
    pre_hits = {}
    post_hits = {}
    modified_files = {}
    marked_patches = []
    pending_patch_headers = []
    exceptions = []

    for path, relative, original, canary_allowed in records:
        _merge_counts(pre_hits, _scan(original, identities, canary_allowed))
        data, replacements = _redact_bytes(original, identities, canary_allowed)
        is_patch = path.suffix == ".patch"
        if is_patch and (path in REQUIRED_REDACTED_PATCHES or data != original):
            marked_patches.append(relative)
            if not data.startswith(PATCH_MARKER):
                data = PATCH_MARKER + data
                replacements["non_applicable_header"] = 1
                if write:
                    pending_patch_headers.append(relative)
        _merge_counts(post_hits, _scan(data, identities, canary_allowed))
        if data != original:
            modified_files[relative] = replacements
            if write:
                path.write_bytes(data)

    for path, reason in CANARY_EXCEPTIONS.items():
        data = path.read_bytes()
        hits = _canary_scan(data)
        exceptions.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "reason": reason,
                "retained_canary_hits": sum(hits.values()),
                "rules": hits,
            }
        )

    result = {
        "schema": 1,
        "scope": "evidence-e5 bytes; NUL-containing files skipped",
        "files_scanned": len(records),
        "binary_files_skipped": binary_files,
        "known_present_self_census": self_census,
        "pre_hits_outside_exceptions": pre_hits,
        "post_hits_outside_exceptions": post_hits,
        "known_absent_pass": not post_hits,
        "modified_files": modified_files,
        "modified_file_count": len(modified_files),
        "replacement_count": sum(sum(item.values()) for item in modified_files.values()),
        "redacted_non_applicable_patches": sorted(set(marked_patches)),
        "redactor_exclusion": {
            "path": SELF.relative_to(ROOT).as_posix(),
            "reason": "generic detector definitions are not rewritten or scanned as payload",
        },
        "control_canary_exceptions": exceptions,
        "retained_exception_hits": sum(item["retained_canary_hits"] for item in exceptions),
        "redaction_verdict": "PASS_WITH_DECLARED_CONTROL_EXCEPTIONS" if not post_hits else "FAIL",
    }
    if not write:
        result["pending_patch_headers"] = pending_patch_headers
        result["check_pass"] = not pre_hits and not modified_files and not pending_patch_headers
    return result


def _load_refresh_module():
    path = ROOT / "refresh_manifests.py"
    spec = importlib.util.spec_from_file_location("e5_refresh_manifests", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="static read-only redaction census")
    args = parser.parse_args()
    result = redact_tree(ROOT, write=not args.check)
    if args.check:
        for name, count in sorted(result["pre_hits_outside_exceptions"].items()):
            print(f"PRE_RULE {name} hits={count}")
        for relative, counts in sorted(result["modified_files"].items()):
            print(f"PENDING {relative} replacements={sum(counts.values())}")
        for item in result["control_canary_exceptions"]:
            print(
                f"EXCEPTION {item['path']} "
                f"retained={item['retained_canary_hits']}"
            )
        print(
            "REDACTION_CHECK "
            f"{'PASS' if result['check_pass'] else 'FAIL'} "
            f"files={result['files_scanned']} residual={sum(result['pre_hits_outside_exceptions'].values())} "
            f"exceptions={result['retained_exception_hits']}"
        )
        return 0 if result["check_pass"] else 1

    CENSUS_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    for relative, counts in sorted(result["modified_files"].items()):
        print(f"REDACTED {relative} replacements={sum(counts.values())}")
    print(
        f"REDACTION_CENSUS files={result['files_scanned']} "
        f"modified={result['modified_file_count']} "
        f"replacements={result['replacement_count']} "
        f"residual={sum(result['post_hits_outside_exceptions'].values())} "
        f"exceptions={result['retained_exception_hits']}"
    )
    refresh = _load_refresh_module()
    return 0 if refresh.refresh_all() and result["known_absent_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
