#!/usr/bin/env python3
"""Structural completeness detector for /dev-flow phase artifacts (RC-1 shift-left).

Summary:
    Re-implements the `/dev-flow-sync` template-completeness DETECT as a fast,
    dependency-free (stdlib-only) pre-commit gate so an incomplete phase artifact
    is caught at COMMIT time, not only at end-of-batch sync. Runs a STRUCTURAL
    detect (empty required structure + live placeholder tokens) over the batch
    directory named by `.dev-flow/state.json`, only when `current_phase >= 4`.

    Two entry modes:
      * standalone CLI  -> prints `file:line` blockers, exit 1 on a real blocker.
      * `--hook`        -> Claude Code PreToolUse wrapper: reads the tool call on
                          stdin, and if it is a `git commit`, blocks (exit 2) when
                          the in-scope artifacts are structurally incomplete.

    It deliberately matches unfilled *structure*, not token substrings: placeholder
    tokens inside a backtick span, a fenced code block, or YAML frontmatter are
    treated as quoted guidance and are NOT blockers (the batch-15 `<P>` / `TC-NNN`
    false-positive lesson).

Data Flow:
    stdin/argv -> locate project root (walk up for .dev-flow/state.json)
              -> read state.json -> gate on current_phase
              -> for each in-scope artifact: classify lines (fence / frontmatter),
                 strip inline backticks, run the four structural checks
              -> emit blockers -> exit code.

Dependencies:
    Uses: stdlib only (json, os, re, sys, subprocess, pathlib, argparse).
    Used by: .claude/settings.json PreToolUse hook (`--hook`); manual CLI runs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# --- Artifact set + phase gating -------------------------------------------------
# Each artifact is only checked once its owning phase should be complete. The hook
# only fires at current_phase >= 4, so 01/02/04 are effectively always in scope;
# 05 joins at phase 5, the 06-docs/*.md at phase 6. A file that does not yet exist
# is simply skipped (we never require existence -- we only flag files that ARE
# present but structurally blank).
_ARTIFACTS: tuple[tuple[str, int], ...] = (
    ("01-requirements.md", 1),
    ("02-review.md", 2),
    ("04-validation.md", 4),
    ("05-postmortem.md", 5),
)
_DOCS_DIR = "06-docs"  # every *.md inside is in scope at phase >= 6

# Live placeholder tokens (the ACTUAL value of a heading / field / cell is a
# blocker; the same token inside a backtick / fence / frontmatter is guidance).
_PLACEHOLDER_TOKENS: tuple[str, ...] = (
    "<PROJECT>",
    "<BATCH_ID>",
    "<Short title>",
    "<role>",
    "<goal>",
    "<str>",
    "<N>",
    "<YYYY-MM-DD>",
    "TC-NNN",
    "AT-NNN",
)
_TOKEN_RE = re.compile("|".join(re.escape(t) for t in _PLACEHOLDER_TOKENS))

_VERDICT_RE = re.compile(r"\b(PASS-WITH-NOTES|PASS|FAIL)\b")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_HEADING_RE = re.compile(r"^\s*(#{1,6})\s+\S")
_GUIDANCE_RE = re.compile(r"^\s*\*\(.*\)\*\s*$")  # template italic guidance *(...)*
_HR_RE = re.compile(r"^\s*-{3,}\s*$")
_BACKTICK_SPAN_RE = re.compile(r"`[^`]*`")
_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$")  # |---|:--:|-- row


@dataclass
class Line:
    """One source line with its structural context.

    Summary:
        Carries the classification needed by every detector so line scanning is
        done once, not per-check.

    Args:
        no: 1-based line number.
        raw: the original line text (newline stripped).
        in_fence: True if inside a ``` / ~~~ fenced code block.
        in_frontmatter: True if inside leading YAML frontmatter (--- ... ---).
    """

    no: int
    raw: str
    in_fence: bool
    in_frontmatter: bool

    @property
    def protected(self) -> bool:
        """True when the line is a fenced-code or frontmatter line (quoted guidance)."""
        return self.in_fence or self.in_frontmatter

    @property
    def live_text(self) -> str:
        """The line with inline backtick spans removed (blank on protected lines)."""
        if self.protected:
            return ""
        return _BACKTICK_SPAN_RE.sub(" ", self.raw)


@dataclass
class Blocker:
    """A single real completeness failure, reported as file:line + reason."""

    file: Path
    line: int
    reason: str


def classify(text: str) -> list[Line]:
    """Split source text into classified Line records (fence + frontmatter aware).

    Args:
        text: full artifact contents.

    Returns:
        List of Line, one per source line, in order.
    """
    lines: list[Line] = []
    in_fence = False
    in_frontmatter = False
    seen_content = False
    fm_open = False

    raw_lines = text.splitlines()
    # Detect leading YAML frontmatter: first non-blank line is exactly '---'.
    for idx, raw in enumerate(raw_lines):
        stripped = raw.strip()

        # Frontmatter open/close (only before any real content, delimiter == ---).
        if not seen_content and stripped == "---":
            if not fm_open:
                fm_open = True
                in_frontmatter = True
                lines.append(Line(idx + 1, raw, in_fence=False, in_frontmatter=True))
                continue
            # closing delimiter
            lines.append(Line(idx + 1, raw, in_fence=False, in_frontmatter=True))
            in_frontmatter = False
            fm_open = False
            seen_content = True
            continue

        if in_frontmatter:
            lines.append(Line(idx + 1, raw, in_fence=False, in_frontmatter=True))
            continue

        if stripped:
            seen_content = True

        if _FENCE_RE.match(raw):
            # The fence delimiter line itself belongs to the block boundary.
            lines.append(Line(idx + 1, raw, in_fence=True, in_frontmatter=False))
            in_fence = not in_fence
            continue

        lines.append(Line(idx + 1, raw, in_fence=in_fence, in_frontmatter=False))

    return lines


def _is_content(ln: Line) -> bool:
    """True if the line carries real (non-blank, non-guidance, non-divider) content.

    Fenced-code and frontmatter lines count as content (a diagram-only or
    metadata-only section is legitimately non-empty).
    """
    if ln.protected:
        return bool(ln.raw.strip())
    s = ln.raw.strip()
    if not s:
        return False
    if _GUIDANCE_RE.match(ln.raw):
        return False
    if _HR_RE.match(ln.raw):
        return False
    return True


def detect_empty_sections(lines: list[Line]) -> list[tuple[int, str]]:
    """Flag headings whose body is empty or only template italic-guidance.

    A heading that is a pure container (immediately deeper child heading follows,
    e.g. `##` -> `###`) is NOT flagged -- its content lives in the children, which
    are checked in their own right.

    Returns:
        List of (line_no, reason).
    """
    heads = [(i, len(_HEADING_RE.match(ln.raw).group(1)))
             for i, ln in enumerate(lines)
             if not ln.protected and _HEADING_RE.match(ln.raw)]
    out: list[tuple[int, str]] = []
    for pos, (start_idx, level) in enumerate(heads):
        end_idx = heads[pos + 1][0] if pos + 1 < len(heads) else len(lines)
        next_level = heads[pos + 1][1] if pos + 1 < len(heads) else None
        body = lines[start_idx + 1:end_idx]
        has_content = any(_is_content(b) for b in body)
        has_child = next_level is not None and next_level > level
        if not has_content and not has_child:
            title = lines[start_idx].raw.strip()
            out.append((lines[start_idx].no,
                        f"required section is empty / only template guidance: {title!r}"))
    return out


def detect_empty_tables(lines: list[Line]) -> list[tuple[int, str]]:
    """Flag markdown tables reduced to header + separator with zero data rows.

    Returns:
        List of (line_no, reason) pointing at the separator row.
    """
    out: list[tuple[int, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        if ln.protected or not ln.raw.lstrip().startswith("|"):
            i += 1
            continue
        # Start of a pipe-run. Collect consecutive pipe lines.
        run = []
        j = i
        while j < n and not lines[j].protected and lines[j].raw.lstrip().startswith("|"):
            run.append(lines[j])
            j += 1
        # A valid table = header, separator, then >=1 data row.
        if len(run) >= 2 and _TABLE_SEP_RE.match(run[1].raw):
            data_rows = [r for r in run[2:] if r.raw.strip()]
            if not data_rows:
                out.append((run[1].no, "required table has header + separator but no data rows"))
        i = j
    return out


def detect_live_tokens(lines: list[Line]) -> list[tuple[int, str]]:
    """Flag placeholder tokens surviving as live field values (not quoted guidance).

    Tokens inside backtick spans, fenced code, or frontmatter are stripped before
    matching and are recorded as checked-false-positive (see summary()).

    Returns:
        List of (line_no, reason).
    """
    out: list[tuple[int, str]] = []
    for ln in lines:
        # Pure template-guidance lines are handled by detect_empty_sections;
        # a token there is guidance, not a live field -> do not double-report.
        if _GUIDANCE_RE.match(ln.raw):
            continue
        for m in _TOKEN_RE.finditer(ln.live_text):
            out.append((ln.no, f"live placeholder token {m.group(0)!r} in a filled field"))
    return out


def count_false_positive_tokens(lines: list[Line]) -> int:
    """Count placeholder-token hits that resolve to quoted guidance (for the report)."""
    fp = 0
    for ln in lines:
        if not ln.protected and not _GUIDANCE_RE.match(ln.raw):
            # subtract the live hits; anything else on this raw line was quoted
            live = len(_TOKEN_RE.findall(ln.live_text))
            total = len(_TOKEN_RE.findall(ln.raw))
            fp += max(0, total - live)
        else:
            fp += len(_TOKEN_RE.findall(ln.raw))
    return fp


def has_data_table(lines: list[Line]) -> bool:
    """True if any non-empty data-row table exists (used for the 04 verdict rule)."""
    i, n = 0, len(lines)
    while i < n:
        if not lines[i].protected and lines[i].raw.lstrip().startswith("|"):
            run = []
            j = i
            while j < n and not lines[j].protected and lines[j].raw.lstrip().startswith("|"):
                run.append(lines[j])
                j += 1
            if len(run) >= 3 and _TABLE_SEP_RE.match(run[1].raw):
                if any(r.raw.strip() for r in run[2:]):
                    return True
            i = j
        else:
            i += 1
    return False


def detect_validation_verdict(lines: list[Line]) -> list[tuple[int, str]]:
    """Flag a 04-validation.md with no verdict token AND no per-requirement table.

    Returns:
        List with a single (line_no=1, reason) blocker, or empty.
    """
    live_text = "\n".join(ln.live_text for ln in lines)
    if _VERDICT_RE.search(live_text):
        return []
    if has_data_table(lines):
        return []
    return [(1, "04-validation.md has no verdict token (PASS / FAIL / PASS-WITH-NOTES) "
                "and no per-requirement results table")]


def check_file(path: Path) -> list[Blocker]:
    """Run all structural detectors over one artifact file.

    Args:
        path: artifact path (must exist).

    Returns:
        List of Blocker (possibly empty).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = classify(text)
    findings: list[tuple[int, str]] = []
    findings += detect_empty_sections(lines)
    findings += detect_empty_tables(lines)
    findings += detect_live_tokens(lines)
    if path.name == "04-validation.md":
        findings += detect_validation_verdict(lines)
    findings.sort()
    return [Blocker(path, no, reason) for no, reason in findings]


def in_scope_artifacts(batch_dir: Path, phase: int) -> list[Path]:
    """Resolve the artifact files to check for a batch at a given phase.

    Args:
        batch_dir: `.dev-flow/<batch_id>/`.
        phase: current_phase.

    Returns:
        Existing artifact paths whose owning phase <= `phase`.
    """
    paths: list[Path] = []
    for name, owner_phase in _ARTIFACTS:
        if phase >= owner_phase:
            p = batch_dir / name
            if p.is_file():
                paths.append(p)
    if phase >= 6:
        docs = batch_dir / _DOCS_DIR
        if docs.is_dir():
            paths.extend(sorted(docs.rglob("*.md")))
    return paths


def run_detect(batch_dir: Path, phase: int) -> tuple[list[Blocker], list[Path], int]:
    """Detect over all in-scope artifacts of a batch.

    Returns:
        (blockers, files_checked, false_positive_count).
    """
    blockers: list[Blocker] = []
    checked: list[Path] = []
    fp = 0
    for path in in_scope_artifacts(batch_dir, phase):
        checked.append(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        fp += count_false_positive_tokens(classify(text))
        blockers.extend(check_file(path))
    return blockers, checked, fp


# --- Project / state resolution --------------------------------------------------

def find_project_root(start: Path) -> Path | None:
    """Walk up from `start` to the nearest dir containing `.dev-flow/state.json`."""
    cur = start.resolve()
    for cand in (cur, *cur.parents):
        if (cand / ".dev-flow" / "state.json").is_file():
            return cand
    return None


def load_state(root: Path) -> dict | None:
    """Read + parse `.dev-flow/state.json`; None on any failure (fail-open)."""
    try:
        return json.loads((root / ".dev-flow" / "state.json").read_text(encoding="utf-8"))
    except Exception:
        return None


def _rel(paths: Iterable[Path], root: Path) -> str:
    return ", ".join(str(p.relative_to(root)) for p in paths)


# --- Reporting -------------------------------------------------------------------

def render_report(blockers: list[Blocker], checked: list[Path], root: Path,
                  fp: int, batch_id: str) -> str:
    """Human-readable summary of a detect run."""
    lines = [f"dev-flow artifact completeness check  (batch {batch_id}, "
             f"{len(checked)} artifact(s) checked, {fp} quoted-token false-positive(s) skipped)"]
    if not blockers:
        lines.append("  OK - no structural blockers.")
        return "\n".join(lines)
    lines.append(f"  {len(blockers)} BLOCKER(S) - incomplete phase artifact(s):")
    for b in blockers:
        rel = b.file.relative_to(root)
        lines.append(f"    BLOCKER  {rel}:{b.line}  {b.reason}")
    return "\n".join(lines)


# --- Command sniffing (hook mode) ------------------------------------------------

_GIT_COMMIT_RE = re.compile(r"\bgit\b[^;&|]*\bcommit\b")
_COMMIT_ALL_RE = re.compile(r"\bcommit\b[^;&|]*\s-\w*a")  # -a / -am / -a ...


def is_git_commit(command: str) -> bool:
    """True if the shell command invokes `git commit` (best-effort, per-segment)."""
    return bool(_GIT_COMMIT_RE.search(command or ""))


def _git_names(root: Path, *args: str) -> list[str] | None:
    """Run `git -C root <args>` returning name-only lines, or None on failure."""
    try:
        out = subprocess.run(["git", "-C", str(root), *args],
                             capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]


def commit_touches_devflow(root: Path, command: str) -> bool:
    """Best-effort: does this commit include `.dev-flow/` changes?

    Returns True when it provably does, OR when it cannot be determined (so the
    detect still runs -- a complete batch passes instantly, an incomplete one is
    caught). Returns False only when git positively reports no `.dev-flow/` paths.
    """
    def has_devflow(names: list[str] | None) -> bool | None:
        if names is None:
            return None
        return any(n.startswith(".dev-flow/") for n in names)

    staged = has_devflow(_git_names(root, "diff", "--cached", "--name-only"))
    if staged is True:
        return True
    if _COMMIT_ALL_RE.search(command):
        unstaged = has_devflow(_git_names(root, "diff", "--name-only"))
        if unstaged is True:
            return True
        if unstaged is None:
            return True  # cannot tell -> check anyway
    if staged is None:
        return True  # cannot tell -> check anyway
    return False  # git positively reports nothing dev-flow


# --- Entry points ----------------------------------------------------------------

_BYPASS_HINT = (
    "To bypass in a genuine emergency: finish the artifact, or run the commit "
    "outside Claude Code's Bash tool (a plain terminal `git commit` is not "
    "intercepted by this hook). See .dev-flow/tools/README.md."
)


def _resolve_phase(state: dict) -> int:
    try:
        return int(state.get("current_phase", 0))
    except (TypeError, ValueError):
        return 0


def run_standalone(root: Path | None, batch_dir_override: Path | None,
                   phase_override: int | None) -> int:
    """CLI mode: detect and print; exit 1 on a real blocker, else 0."""
    if batch_dir_override is not None:
        phase = phase_override if phase_override is not None else 6
        blockers, checked, fp = run_detect(batch_dir_override, phase)
        base = batch_dir_override.parent
        print(render_report(blockers, checked, base, fp,
                            batch_dir_override.name))
        return 1 if blockers else 0

    if root is None:
        root = find_project_root(Path.cwd())
    if root is None:
        print("no .dev-flow/state.json found - not a dev-flow project (skipping).")
        return 0
    state = load_state(root)
    if state is None:
        print(".dev-flow/state.json unreadable - skipping (fail-open).")
        return 0
    phase = phase_override if phase_override is not None else _resolve_phase(state)
    if phase < 4:
        print(f"current_phase={phase} (<4) - artifacts not expected filled yet; skipping.")
        return 0
    batch_id = state.get("batch_id", "")
    batch_dir = root / ".dev-flow" / batch_id
    if not batch_dir.is_dir():
        print(f"batch dir {batch_dir} missing - skipping (fail-open).")
        return 0
    blockers, checked, fp = run_detect(batch_dir, phase)
    print(render_report(blockers, checked, root, fp, batch_id))
    return 1 if blockers else 0


def run_hook() -> int:
    """PreToolUse mode: read the tool call on stdin; block a git commit that would
    include incomplete phase artifacts. Fail-OPEN on anything unexpected.

    Returns:
        0 to allow the tool call, 2 to block it (message on stderr).
    """
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # can't parse -> never block

    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if not is_git_commit(command):
        return 0

    try:
        start = Path((payload.get("cwd") or os.getcwd()))
        root = find_project_root(start)
        if root is None:
            return 0  # not a dev-flow project -> never block
        state = load_state(root)
        if state is None:
            return 0
        phase = _resolve_phase(state)
        if phase < 4:
            return 0
        batch_id = state.get("batch_id", "")
        batch_dir = root / ".dev-flow" / batch_id
        if not batch_dir.is_dir():
            return 0
        if not commit_touches_devflow(root, command):
            return 0
        blockers, checked, _ = run_detect(batch_dir, phase)
        if not blockers:
            return 0
        lines = [
            "BLOCKED: this commit would include incomplete /dev-flow phase artifacts.",
            f"Batch {batch_id} (phase {phase}) has {len(blockers)} structural blocker(s):",
        ]
        for b in blockers:
            lines.append(f"  - {b.file.relative_to(root)}:{b.line}  {b.reason}")
        lines.append("")
        lines.append("Fill the artifact(s) above, then commit again.")
        lines.append(_BYPASS_HINT)
        print("\n".join(lines), file=sys.stderr)
        return 2
    except Exception as exc:  # never block on an internal bug
        print(f"artifact hook internal error (allowing commit): {exc}", file=sys.stderr)
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Structural completeness detector for /dev-flow phase artifacts.")
    parser.add_argument("--hook", action="store_true",
                        help="Claude Code PreToolUse mode (reads JSON on stdin).")
    parser.add_argument("--batch-dir", type=Path, default=None,
                        help="Check this batch dir directly (bypass state.json; for tests).")
    parser.add_argument("--phase", type=int, default=None,
                        help="Override current_phase (default: from state.json, or 6 with --batch-dir).")
    args = parser.parse_args(argv)

    if args.hook:
        return run_hook()
    return run_standalone(None, args.batch_dir, args.phase)


if __name__ == "__main__":
    sys.exit(main())
