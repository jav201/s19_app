#!/usr/bin/env python
"""Wall-clock attribution for batch-100 Increment 7 (dev-flow) from Claude Code JSONL transcripts.

Read-only on the transcripts; writes report.md + data.json beside this script.
Method summary (full text in report.md):
 * per actor, walk timestamped events in order; the gap before an event is charged to
   - the pending tool call's bucket (event = tool_result),
   - 'model' (event = assistant block),
   - 'wait' (event = anything else: notification, queued command, human message).
 * Bash polling loops (until ...; sleep) and Monitor are 'wait' (idle on background compute).
 * dedup across actors: sweep line over elementary segments; every foreground activity active in
   the segment gets an equal share; with none, waits share it (as "waiting on bg compute");
   with none, the segment is 'uncovered'.
"""
import json, re, sys, os, glob, collections
from datetime import datetime, timezone, timedelta

ROOT = "C:/Users/jjgh8/.claude/projects/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2"
SUB = ROOT + "/subagents/"
MAIN = ROOT + ".jsonl"
EV = ""
SCR = "C:/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/"
OUT = SCR + "timing8a/"

AGENTS = [  # id, label, role, step
    ('a9ffa1014f86ac9a6', 'E1 requirements', 'impl'),
    ('a846184e7be2163d4', 'E2-baseline Code-Wire', 'impl'),
    ('a846d466d1f622604', 'E2 prototype A', 'impl'),
    ('af6b84eed9deec302', 'E2 prototype B', 'impl'),
    ('a569897db450d492e', 'E2 prototype C', 'impl'),
    ('a78d3bd3486bc92c5', 'E3 r1 architect', 'rev'),
    ('ab359899b74a75259', 'E3 r1 security', 'rev'),
    ('acf078aaecc4e07a1', 'E3 design pass 1 (Sonnet)', 'impl'),
    ('a4c8fe028c12637be', 'E3 r2 architect', 'rev'),
    ('a5218196216da83bc', 'E3 r2 security', 'rev'),
    ('a44af38e51f3dc75f', 'E3 design pass 2', 'impl'),
    ('a24f8d76ac052c990', 'E3 r3 architect', 'rev'),
    ('aeb47ee6ad8235ea4', 'E3 r3 security', 'rev'),
    ('afe880d788efd981a', 'E4 implementer A', 'impl'),
    ('a2bc9cde0a1035623', 'E4 implementer B', 'impl'),
    ('a93d5cd372e6c5ed4', 'E4 implementer C', 'impl'),
    ('a98d7f72e1d7801c4', 'E4 tester', 'impl'),
    ('a8b27a8fb499df412', 'E4 integration', 'impl'),
    ('aa876710e81a323d0', 'E5 mutants', 'impl'),
    ('a81a2be2abed7ebd9', 'E5 code review', 'rev'),
    ('a153398426b34907c', 'E5 security review', 'rev'),
    ('a1247acabf65ddd90', 'E5 corrective pass 1', 'impl'),
    ('a952ee4f03f9c4fa0', 'E5 code review r2', 'rev'),
]
BN = {
    1: "Reading context", 2: "Source code edits", 3: "Tests/fixtures edits",
    4: "RED runs on base/pre-fix tree", 5: "GREEN / targeted pytest", 6: "Mutation runs",
    7: "Reverse census runs", 8: "Guards / snapshot runs", 9: "Reviewer probes",
    10: "Packet/HANDOFF/review-record/evidence tool/hash", 11: "Orchestrator (brief/rulings/coordination)",
    12: "Other tool work", 13: "Model reasoning/writing", 14: "Idle wait (notification/human)",
}


def ts(s):
    return datetime.strptime(s[:23], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def secs(a, b):
    return (b - a).total_seconds()


WRITE_RE = re.compile(r">>|cat\s*>|open\([^)]*['\"]w|write\(|write_text|sed -i|\.replace\(|\bedit\(|git apply|patch ", re.I)
TARGET_RE = re.compile(r"tests[/\\]\w|s19_app[/\\]\w|increment-0\d\d|handoff|section\d\.md|checklist\.md|pkt_|review[/\\]|security[/\\]", re.I)


def target_bucket(text):
    m = TARGET_RE.search(text)
    if not m:
        return None
    g = m.group(0).lower()
    if g.startswith("tests"):
        return 3
    if g.startswith("s19_app"):
        return 2
    return 10


def wait_kind(cmd):
    c = cmd.lower()
    for k, b in (("census", 7), ("mut", 6), ("green", 5), ("guard", 8), ("red", 4)):
        if k in c:
            return b
    return 0  # generic / chain


def classify_bash(inp, role, script_map):
    cmd = inp.get("command", "") or ""
    desc = inp.get("description", "") or ""
    low = (desc + " " + cmd).lower()
    cl = cmd.lower()
    if (re.search(r"\buntil\b", cl) and "sleep" in cl) or (re.search(r"\bwait|\bcontinue waiting", desc.lower()) and "sleep" in cl):
        return ("wait", wait_kind(desc + cmd))
    if re.match(r"\s*sleep\s+\d", cl):
        return ("wait", 0)
    runlike = re.search(r"pytest|run_pytest|run\.sh|chain|mutate|python", cl)
    if "devflow-evidence" in low or (("sha256sum" in low or "git hash-object" in low) and not runlike):
        return ("fg", 10)
    # scratch scripts that were written earlier by this agent
    for base, b in script_map.items():
        if base in cmd and not re.search(r"mutate|run_pytest|chain|run\.sh", base):
            return ("fg", b)
    w = bool(WRITE_RE.search(cmd))
    if "mutate" in low or "mutant" in low or re.search(r"mut-", low):
        return ("fg", 6)
    if re.search(r"guards(-census)?(-cp\d)?\.txt|whole-tree guards|run guards|census sweep guard|guards on", low):
        return ("fg", 8)
    if "census" in low and re.search(r"isolation|known-vs-base|flake|reverse|census-tree|census run", low):
        return ("fg", 7)
    if re.search(r"git worktree add|\bred\b|red-|vs base|vs pre|pre-fix|on base|pre tree|pre-cp1|on the base|base worktree", low):
        return ("fg", 4)
    if "census" in low:
        return ("fg", 7)
    if "pytest" in low or "run_pytest" in low or "run.sh" in low or "chain" in low:
        if role == "rev":
            return ("fg", 9)
        return ("fg", 5)
    if w:
        b = target_bucket(cmd)
        if b:
            return ("fg", b)
        return ("fg", 9 if role == "rev" else 12)
    if role == "rev" and re.search(r"probe", low):
        return ("fg", 9)
    if re.search(r"powershell|get-ciminstance|stop-process|tasklist|taskkill|remove-item|git worktree remove", low):
        return ("fg", 12)
    if re.search(r"\b(grep|sed -n|cat|head|tail|ls|wc|find|git (log|diff|status|show)|rg|awk|sort|cut|diff|comm)\b", cl) or "read" in desc.lower():
        return ("fg", 1)
    if role == "rev" and re.search(r"python", cl):
        return ("fg", 9)
    return ("fg", 12)


def classify_tool(name, inp, role, script_map):
    """-> (kind, bucket, sublabel)"""
    if name == "Monitor":
        return ("wait", wait_kind(json.dumps(inp)))
    if name in ("ToolSearch", "TaskStop"):
        return ("fg", 12)
    if name in ("Read", "Grep", "Glob"):
        return ("fg", 1)
    if name in ("Write", "Edit"):
        p = (inp.get("file_path") or "").replace("\\", "/")
        content = (inp.get("content") or inp.get("new_string") or "")
        low = p.lower()
        base = os.path.basename(low)
        if "/tests/" in low:
            return ("fg", 3)
        if "/s19_app/s19_app/" in low or re.search(r"s19_app-b100-inc(7|8a)/s19_app/", low):
            return ("fg", 2)
        if low.endswith(".md") or "handoff" in low or "/.dev-flow/" in low or "/review/" in low or "/security/" in low:
            if role == "rev" and "probe" in low:
                return ("fg", 9)
            return ("fg", 10)
        if low.endswith(".py") or low.endswith(".sh"):
            if role == "rev":
                return ("fg", 9)
            if re.search(r"prof|time_|lstat|try", base):
                return ("fg", 12)
            if re.search(r"run_pytest|mutate|chain|run\.sh", base):
                return ("fg", 6 if "mutate" in base else 12)
            if base.startswith("patch_t") or "tests" in base:
                return ("fg", 3)
            b = target_bucket(content)
            if "pkt" in base or "section" in base:
                b = 10
            return ("fg", b or 12)
        return ("fg", 12)
    if name == "Bash":
        return classify_bash(inp, role, script_map)
    if name == "PowerShell":
        return ("fg", 12)
    if name in ("SubagentHandback",):
        return ("fg", 10)
    return ("fg", 12)


def load_events(path, start=None):
    ev = []
    for l in open(path, encoding="utf8"):
        try:
            d = json.loads(l)
        except Exception:
            continue
        t = d.get("type")
        if "timestamp" not in d:
            continue
        if t == "attachment" and d["attachment"].get("type") == "queued_command":
            if start is None or ts(d["timestamp"]) >= start:
                ev.append(("queued", ts(d["timestamp"]), d))
            continue
        if t not in ("assistant", "user"):
            continue
        tt = ts(d["timestamp"])
        if start and tt < start:
            continue
        ev.append((t, tt, d))
    return ev


def walk(path, role, start=None, is_main=False, end=None):
    """Return intervals [(t0,t1,kind,bucket,sub)] and per-tool records."""
    ev = load_events(path, start)
    ev.sort(key=lambda x: x[1])
    if end:
        ev = [e for e in ev if e[1] <= end]
    uses = {}
    script_map = {}
    # message id -> first tool bucket (for 'model' next-bucket attribution)
    msg_next = {}
    intervals = []
    tools = []
    prev = None
    pend_tool_end = {}
    # pre-pass: script map from Writes
    for t, tt, d in ev:
        if t == "assistant":
            for b in d["message"]["content"]:
                if b["type"] == "tool_use" and b["name"] == "Write":
                    k, bk = classify_tool("Write", b["input"], role, {})
                    base = os.path.basename((b["input"].get("file_path") or "").replace("\\", "/"))
                    if base.endswith((".py", ".sh")):
                        script_map[base] = bk
    for t, tt, d in ev:
        if t == "assistant":
            mid = d["message"].get("id")
            for b in d["message"]["content"]:
                if b["type"] == "tool_use":
                    msg_next.setdefault(mid, b)
    prevmid = None
    for t, tt, d in ev:
        if prev is None:
            prev = tt
            if t != "assistant":
                pass
            continue
        gap = secs(prev, tt)
        c = d["message"]["content"] if t in ("assistant", "user") else []
        if isinstance(c, str):
            c = [{"type": "text", "text": c}]
        if t == "assistant":
            mid = d["message"].get("id")
            nb = msg_next.get(mid)
            nxt = None
            if nb:
                if is_main:
                    nxt = 11
                else:
                    nxt = classify_tool(nb["name"], nb["input"], role, script_map)[1]
            intervals.append((prev, tt, "orch" if is_main else "fg", 11 if is_main else 13, nxt))
            for b in c:
                if b["type"] == "tool_use":
                    uses[b["id"]] = (b, tt)
        elif t == "user" and any(b.get("type") == "tool_result" for b in c):
            # attribute to the earliest pending tool of this result (first block)
            b = [x for x in c if x.get("type") == "tool_result"][0]
            u = uses.get(b["tool_use_id"])
            if u:
                ub, ut = u
                if is_main:
                    kind, bk = "orch", 11
                else:
                    kind, bk = classify_tool(ub["name"], ub["input"], role, script_map)
                # for parallel results: charge from max(prev, tool_use time)
                intervals.append((prev, tt, kind, bk, None))
                tools.append(dict(name=ub["name"], kind=kind, bucket=bk, dur=gap, t0=ut, t1=tt,
                                  desc=(ub["input"].get("description") or "")[:80],
                                  cmd=json.dumps(ub["input"])[:200],
                                  bg=bool(ub["input"].get("run_in_background"))))
            else:
                intervals.append((prev, tt, "wait", 0, None))
        else:
            intervals.append((prev, tt, "wait", 0, "human" if (t == "user" and is_main) else None))
        prev = tt
    return intervals, tools


def usage(path):
    seen = {}
    for l in open(path, encoding="utf8"):
        try:
            d = json.loads(l)
        except Exception:
            continue
        if d.get("type") == "assistant":
            m = d["message"]
            u = m.get("usage")
            if u:
                seen[m.get("id")] = (u, m.get("model"))
    tot = collections.Counter()
    models = collections.Counter()
    for u, mod in seen.values():
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
            tot[k] += u.get(k, 0) or 0
        models[mod] += 1
    return tot, models, len(seen)


def sweep(actors):
    """actors: {name: intervals}. Returns (fg_share, wait_share, uncovered_secs, total_secs, fgonly_total)."""
    pts = set()
    for iv in actors.values():
        for a, b, *_ in iv:
            pts.add(a); pts.add(b)
    pts = sorted(pts)
    # index intervals by sorted start for speed
    flat = []
    for name, iv in actors.items():
        for a, b, kind, bk, sub in iv:
            if b > a:
                flat.append((a, b, name, kind, bk, sub))
    flat.sort(key=lambda x: x[0])
    fg = collections.Counter(); wt = collections.Counter(); unc = collections.Counter()
    modelnext = collections.Counter()
    import bisect
    starts = [f[0] for f in flat]
    active = []
    idx = 0
    for i in range(len(pts) - 1):
        a, b = pts[i], pts[i + 1]
        dt = secs(a, b)
        while idx < len(flat) and flat[idx][0] <= a:
            active.append(flat[idx]); idx += 1
        active = [x for x in active if x[1] > a]
        fgl = [x for x in active if x[3] in ("fg", "orch")]
        wl = [x for x in active if x[3] == "wait"]
        if fgl:
            # main-orchestrator activity is overridden by agent foreground work only if agents active: keep equal split
            n = len(fgl)
            for x in fgl:
                fg[x[4]] += dt / n
                if x[4] == 13 and x[5]:
                    modelnext[x[5]] += dt / n
        elif [x for x in wl if x[2] != "main"]:
            wa = [x for x in wl if x[2] != "main"]
            mid = a + (b - a) / 2
            for x in wa:
                wt[bg_type_at(mid) or x[4]] += dt / len(wa)
        elif wl:
            wt[-1] += dt  # only the orchestrator waiting: no agent running (human/operator or notification latency)
        else:
            unc["uncovered"] += dt
    return fg, wt, unc, modelnext


# ---- background / long-run inventory (UTC = local(-06:00) + 6h). dur in seconds; None = not recoverable.
D0 = datetime(2026, 10, 30, tzinfo=timezone.utc)


def L(hms):  # local HH:MM:SS -> UTC datetime
    h, m, s = [int(x) for x in hms.split(":")]
    return D0 + timedelta(hours=h + 6, minutes=m, seconds=s)


# (type_bucket, type_name, label, end_local, dur_s, mode, source)
RUNS = []
# open-ended timeline pieces used only to label waits (start_local, end_local, bucket)
TL_EXTRA = []


def timeline():
    tl = []
    for b, tn, lab, endl, dur, mode, src in RUNS:
        if dur and "IN PROGRESS" not in lab:
            e = L(endl)
            tl.append((e - timedelta(seconds=dur), e, b))
    for a, b_, bk in TL_EXTRA:
        tl.append((L(a), L(b_), bk))
    return tl


TL = None


def bg_type_at(t):
    global TL
    if TL is None:
        TL = timeline()
    best = None
    for a, b, bk in TL:
        if a <= t < b:
            # prefer the longest-running candidate (census over small side runs)
            if best is None or bk == 7 or (best != 7 and bk > best):
                best = bk
    return best



def fmt(m):
    return "%.1f" % m


def main():
    first = ts("2026-10-30T20:12:29.000")
    actors = {}
    agent_info = {}
    all_tools = {}
    for aid, label, role in AGENTS:
        iv, tools = walk(SUB + f"agent-{aid}.jsonl", role)
        actors[label] = iv
        all_tools[label] = tools
        u, models, nmsg = usage(SUB + f"agent-{aid}.jsonl")
        t0 = min(x[0] for x in iv); t1 = max(x[1] for x in iv)
        fgsec = sum(secs(a, b) for a, b, k, *_ in iv if k == "fg")
        wsec = sum(secs(a, b) for a, b, k, *_ in iv if k == "wait")
        agent_info[label] = dict(id=aid, role=role, t0=t0, t1=t1, wall=secs(t0, t1), fg=fgsec, wait=wsec,
                                 usage=dict(u), models=dict(models), msgs=nmsg, ntools=len(tools))
    END = max(x[1] for v in actors.values() for x in v)
    miv, mtools = walk(MAIN, "orch", start=first, is_main=True, end=END)
    # main: 'wait' intervals are the orchestrator waiting; keep as waits labelled main
    actors_main = [(a, b, k, bk, sub) for a, b, k, bk, sub in miv]
    actors["main"] = actors_main
    t0 = min(x[0] for v in actors.values() for x in v); t1 = max(x[1] for v in actors.values() for x in v)
    total = secs(t0, t1)
    fg, wt, unc, mnext = sweep(actors)
    # main waits count only as 'uncovered' if no agent active; handle: main wait intervals were placed in wt with -1 key -> treat as operator/orchestrator idle
    # second sweep: agent-only foreground (for table c)
    agent_actors = {k: v for k, v in actors.items() if k != "main"}
    fg_a, wt_a, unc_a, mnext_a = sweep(agent_actors)
    data = dict(t0=t0.isoformat(), t1=t1.isoformat(), total=total, fg=dict(fg), wt=dict(wt), unc=dict(unc),
                mnext=dict(mnext), fg_a=dict(fg_a), wt_a=dict(wt_a), unc_a=dict(unc_a), mnext_a=dict(mnext_a))
    # per-agent bucket sums (not deduped)
    per = {}
    for label, iv in actors.items():
        c = collections.Counter(); cn = collections.Counter()
        for a, b, k, bk, sub in iv:
            d = secs(a, b)
            if k == "wait":
                c[("wait", bk)] += d
            else:
                c[("fg", bk)] += d
                if bk == 13 and sub:
                    cn[sub] += d
        per[label] = (c, cn)
    return dict(data=data, agent_info=agent_info, per=per, tools=all_tools, actors=actors, total=total, t0=t0, t1=t1)



# ---------------------------------------------------------------- report generation
def sub12(tools_by_agent):
    c = collections.Counter()
    for lab, tl in tools_by_agent.items():
        for t in tl:
            if t["kind"] == "fg" and t["bucket"] == 12:
                txt = (t["desc"] + t["cmd"]).lower()
                key = ("perf profiling/timing probes (cp2 speedups)"
                       if re.search(r"profil|time |timing|speedup|re-time", txt)
                       else "misc (process mgmt, ToolSearch, worktree cleanup, one-off shell)")
                c[key] += t["dur"]
    return c


def mins(x):
    return x / 60.0


def pct(x, tot):
    return 100.0 * x / tot


E_TEXT = """**Full reverse census (the 41-module pytest set, 987-1049 tests, 68-72 min each)**: 6 launches (7 pytest processes) in the window, **3 completed**, 2 abandoned, 1 still running.

| # | run | launched (UTC) | outcome | min | why it was (re)run |
|---|---|---|---|---:|---|
| 1 | impl-1 `census-b100` + `census-rest` | 08:28 | abandoned at hand-back; files overwritten | n/a | first census, on the PRE-fix TC-22 fixture and pre-literal bound; impl-1 stopped at its 190k-context limit; impl-2 discarded it and restarted |
| 2 | impl-2, serial census on the tree | 09:08 | killed by TaskStop at 09:59 | 51.3 | orchestrator changed source mid-run (CI-6-1: textual overlong-entry rule in `variant_execution_service.py`, plus the Linux CI findings), making the run stale |
| 3 | impl-2 `census-tree.txt` | 10:19 | complete: 6 failed / 1043 passed | 72.3 | first census on the final impl tree; 4 Inc-7-caused failures re-pinned, 1 flake, 2 known; required by the brief |
| 4 | cp1 `census-tree-cp1.txt` | 13:07 | complete: 2 failed (known) / 987 passed | 67.8 | corrective pass 1 changed all four source files (F1-F8, SEC7-1..7) after code+security round 1 |
| 5 | cp2 chain B `census-tree-cp2.txt` | 16:14 | complete: 4 failed / 985 passed | 67.9 | corrective pass 2 changed sources after round 2 (SEC7-R2-1..4, R2-1/2) |
| 6 | cp2 chain C `census-tree-cp2.txt` (overwrote #5) | 17:56 | IN PROGRESS (>= 61.5 min at 18:57Z) | >=61.5 | #5 found 2 cp2-caused failures (`test_manifest_writer_module_is_headless`: logger in manifest_writer; `test_tc_b100_57` byte-identity census flagged `_abort_save`) -> logger removed + census re-pin -> sources changed again |

cp2 also started a first close chain A at 15:17 (green, probes) but killed it before the census stage (about 26 min in) because the agent lowered `MANIFEST_FOLDER_CHECK_CAP` 2000 -> 1000 and changed the logger; chain B restarted from RED. Smaller census-related runs: 1 isolation pair (tree vs base, 12 s + 15 s), 1 flake repeat (2 s), 1 known-vs-base run (13 s); `guards-census` (87 tests, about 1.5 min) ran 3 times (impl, cp1, cp2-B). Reverse-census grep lists were regenerated 3 times (seconds each).

**Mutation sets**: 8 set-runs (about 2-6 min each, never more than 340 s). Mutants per set: impl 21 (first), 2 re-run after fixing the keep-all/last-wins mutants, impl 23 on the final tree (after CI-6-1), cp1 19 new + 23 prior on the cp1 tree, cp2 chain A 50, cp2 chain B 50, cp2 chain C 42 (the cp2 set aborted with an AssertionError because `SEC7-R2-3-class` no longer matched the edited source; cp1 and prior sets ran). Reasons: the first run proved the suite; the 2-mutant re-run fixed a surviving mutant (the first keep-all form survived as last-wins); the 23-mutant rerun was caused by CI-6-1 (source change plus new arm); cp1 = new mutants for each reviewer finding plus all 23 earlier mutants re-proved on the changed tree; cp2 A = same for round-2 findings; cp2 B = after the late cap/logger edits; cp2 C = after the headless-logger fix and census re-pin. Cumulative mutation minutes are small (see (d)); the cost of each re-run sits in the census that follows it in the same chain.
"""

F_TEXT = """1. **Gap attribution is by event adjacency.** The gap before a tool_result goes to that tool; the gap before an assistant block goes to model time. API latency, queueing and tool-start overhead are therefore inside 'model' (row 13). With parallel tool calls the 2nd result is charged only the time since the 1st.
2. **Bucket classification is regex-based** on each Bash command and its `description`, not on semantics. A call that edits tests and runs RED/pytest together is charged to whichever rule matched first. I read the foreground calls longer than 45 s (about 40) and they were bucketed correctly after two rule fixes; shorter calls were not individually audited. Bucket 12 holds what no rule matched.
3. **Poll loops are 'idle wait'**, not work: `until ...; sleep`, `for i in seq ...; sleep`, Monitor. The waited time is attributed, via a timeline built from evidence footers and chain.log, to the background job that was actually running (census / green / mutation / RED / guards). Slices that no known run covers fall back to the keyword in the poll command, then to 'job not identifiable'. impl-1's census-b100/census-rest run (started 08:28Z, no footer survives) is not in the timeline.
4. **Equal split under overlap**: when two actors work at once (code-review and security-review in parallel, or an agent and the orchestrator thinking), each gets 1/n of the slice. This cannot tell critical-path work from off-path work. The orchestrator is charged only for its own turns and tool calls, not for waiting on agents.
5. **Background durations** come from pytest footers (the run's own wall clock), `# finished` stamps (UTC-6) and chain.log. Overwritten evidence files (census-tree-cp2, green-01 first run, impl-1 censuses) were reconstructed from transcripts or are marked n/a. Mutation-set durations come from file/log mtimes, about +-10 s.
6. **Window end**: the primary window ends at corrective pass 2's last line (17:26:54Z), as instructed. The orchestrator transcript continues to 18:53Z (operator 'status' exchanges, the decision to cut a chain and reuse its census if it matches), and chain C was still running at 18:57Z. That tail (about 90 min, almost all census wait) is excluded; adding it would raise the total to about 687 min and the census share further.
7. **Tokens** are summed over unique assistant message ids; the JSONL usage can lag the final output count for the last block of a message, so output tokens may be a slight undercount. Cache-read tokens dominate because each turn re-reads the whole context.
8. **No judgement on value** is made here.
"""


def report():
    r = main()
    d = r["data"]
    tot = d["total"]
    fg, wt, fga = d["fg"], d["wt"], d["fg_a"]
    mnext, mnext_a = d["mnext"], d["mnext_a"]
    out = []
    P = out.append
    P("# Batch-100 Inc 7: where the wall-clock went\n")
    P("Window: 2026-10-30 %s -> %s UTC (first line of impl-1 to last line of corrective pass 2). Total = **%.1f min (%.2f h)**. Generated by `timing.py` from the JSONL transcripts; numbers only.\n" % (r["t0"].strftime("%H:%M:%S"), r["t1"].strftime("%H:%M:%S"), mins(tot), tot / 3600))
    P("Corrective pass 2 is PARTIAL: its last transcript line is 17:26:54Z, where it launched the final close chain (chain C) and went idle. The chain was still running when this report was made (census stage, at least 62 min in at 12:57 local = 18:57Z). Those ~90 min after the last agent line are NOT in the totals (caveat 6).\n")
    P("## (a) Per-agent wall time and token usage\n")
    P("| agent | model | start-end (UTC) | wall min | foreground min | idle-wait on bg min | tool calls | assistant msgs | output tok | cache-read tok | cache-create tok | fresh input tok |")
    P("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for lab, i in r["agent_info"].items():
        u = i["usage"]
        P("| %s (`%s`) | %s | %s-%s | %.1f | %.1f | %.1f | %d | %d | %s | %s | %s | %s |" % (
            lab, i["id"][:8], ",".join(i["models"].keys()), i["t0"].strftime("%H:%M"), i["t1"].strftime("%H:%M"), mins(i["wall"]),
            mins(i["fg"]), mins(i["wait"]), i["ntools"], i["msgs"], format(u.get("output_tokens", 0), ","), format(u.get("cache_read_input_tokens", 0), ","),
            format(u.get("cache_creation_input_tokens", 0), ","), format(u.get("input_tokens", 0), ",")))
    sw = sum(i["wall"] for i in r["agent_info"].values())
    P("\nSum of agent walls = %.1f min (%.1f%% of the %.1f-min window): agents overlap only in the two reviewer pairs (code and security reviewers ran in parallel). meta.json files carry no usage; tokens come from per-message `usage`, deduplicated by message id.\n" % (mins(sw), pct(sw, tot), mins(tot)))

    P("## (b) Inc 7 total wall time by activity (overlaps counted once)\n")
    P("Dedup method: sweep line over every distinct timestamp. In each slice, every foreground activity running at that instant (any agent's tool call or model turn, plus the orchestrator's own turns) gets an equal share. If nothing is foreground, the slice goes to the background job an idle agent is waiting on (labelled from the evidence/chain.log timeline). If nothing is active, it goes to 'nobody running'.\n")
    P("| # | bucket | foreground min | % of total | wait on bg compute min | % of total | combined min | combined % |")
    P("|---|---|---:|---:|---:|---:|---:|---:|")
    for b in range(1, 14):
        f = mins(fg.get(b, 0)); w = mins(wt.get(b, 0))
        P("| %d | %s | %.1f | %.1f%% | %.1f | %.1f%% | %.1f | %.1f%% |" % (b, BN[b], f, pct(f * 60, tot), w, pct(w * 60, tot), f + w, pct((f + w) * 60, tot)))
    w0 = mins(wt.get(0, 0)); wm = mins(wt.get(-1, 0))
    P("| - | bg wait, job not identifiable | 0.0 | 0.0%% | %.1f | %.1f%% | %.1f | %.1f%% |" % (w0, pct(w0 * 60, tot), w0, pct(w0 * 60, tot)))
    P("| - | nobody running (orchestrator only) | 0.0 | 0.0%% | %.1f | %.1f%% | %.1f | %.1f%% |" % (wm, pct(wm * 60, tot), wm, pct(wm * 60, tot)))
    P("| | **total** | **%.1f** | | **%.1f** | | **%.1f** | |\n" % (mins(sum(fg.values())), mins(sum(wt.values())), mins(sum(fg.values()) + sum(wt.values()))))
    P("Row 13 (model reasoning/writing) split by the bucket of the tool call that followed each turn (deduplicated; same equal-split rule):\n")
    P("| bucket of next tool call | model min |")
    P("|---|---:|")
    for b in sorted(k for k in mnext if k is not None):
        P("| %s | %.1f |" % (BN.get(b, b), mins(mnext[b])))
    unk = mins(fg.get(13, 0)) - mins(sum(mnext.values()))
    P("| turn ended without a tool call (text, hand-back) | %.1f |\n" % unk)
    P("Same table with model time folded into the next tool's bucket:\n")
    P("| # | bucket | fg min incl. model | % of total | + bg wait min | = combined min | combined % |")
    P("|---|---|---:|---:|---:|---:|---:|")
    for b in range(1, 13):
        f = mins(fg.get(b, 0)) + mins(mnext.get(b, 0)); w = mins(wt.get(b, 0))
        P("| %d | %s | %.1f | %.1f%% | %.1f | %.1f | %.1f%% |" % (b, BN[b], f, pct(f * 60, tot), w, f + w, pct((f + w) * 60, tot)))
    P("| - | model turns with no following tool call | %.1f | %.1f%% | | %.1f | %.1f%% |" % (unk, pct(unk * 60, tot), unk, pct(unk * 60, tot)))
    P("| - | bg wait not identifiable + nobody running | | | %.1f | %.1f | %.1f%% |\n" % (w0 + wm, w0 + wm, pct((w0 + wm) * 60, tot)))

    P("## (c) Foreground agent time only (idle waits on bg excluded; orchestrator excluded)\n")
    ftot = sum(fga.values())
    P("Agent-foreground time, deduplicated (equal split when two agents work at once) = **%.1f min = %.1f%% of the %.1f-min window**. The other %.1f min is agents idle on background compute.\n" % (mins(ftot), pct(ftot, tot), mins(tot), mins(tot - ftot)))
    P("| # | bucket | min | % of fg time | % of total | min with model time folded in | % of fg (folded) |")
    P("|---|---|---:|---:|---:|---:|---:|")
    unk_a = mins(fga.get(13, 0)) - mins(sum(mnext_a.values()))
    for b in range(1, 14):
        m = mins(fga.get(b, 0))
        if b < 13:
            f2 = m + mins(mnext_a.get(b, 0))
            P("| %d | %s | %.1f | %.1f%% | %.1f%% | %.1f | %.1f%% |" % (b, BN[b], m, pct(m * 60, ftot), pct(m * 60, tot), f2, pct(f2 * 60, ftot)))
        else:
            P("| %d | %s | %.1f | %.1f%% | %.1f%% | %.1f (no following tool) | %.1f%% |" % (b, BN[b], m, pct(m * 60, ftot), pct(m * 60, tot), unk_a, pct(unk_a * 60, ftot)))
    P("")
    P("### Per-agent bucket minutes (NOT deduplicated; agent-minutes)\n")
    labs = list(r["agent_info"].keys())
    P("| bucket | " + " | ".join(l.split(" (")[0] for l in labs) + " |")
    P("|---|" + "---:|" * len(labs))
    for b in range(1, 14):
        cells = ["%.1f" % mins(r["per"][l][0].get(("fg", b), 0)) for l in labs]
        P("| %d %s | %s |" % (b, BN[b], " | ".join(cells)))
    cells = ["%.1f" % mins(sum(v for (k, bk), v in r["per"][l][0].items() if k == "wait")) for l in labs]
    P("| idle wait on bg | %s |" % " | ".join(cells))
    P("| wall | %s |\n" % " | ".join("%.1f" % mins(r["agent_info"][l]["wall"]) for l in labs))
    s12 = sub12(r["tools"])
    P("Bucket 12 (Other) composition, agent-minutes: " + "; ".join("%s %.1f" % (k, mins(v)) for k, v in s12.items()) + ".\n")

    P("## (d) Background / long-run compute per run type\n")
    P("Durations are the pytest `in N s` footers in the evidence files and chain.log (the run's own wall time, not the agent's polling). Runs whose evidence was later overwritten come from chain.log output captured in the transcripts; two have no recoverable duration and are counted but excluded from minutes. 'launched bg' = launched in the background or as a chain.\n")
    g = collections.OrderedDict()
    for b, tn, lab, endl, dur, mode, src in RUNS:
        g.setdefault(tn, []).append((lab, dur, mode, src, b))
    P("| run type | runs | with duration | total min | mean min | longest min | launched bg |")
    P("|---|---:|---:|---:|---:|---:|---:|")
    allm = 0
    for tn, v in g.items():
        ds = [x[1] for x in v if x[1]]
        P("| %s | %d | %d | %.1f | %.1f | %.1f | %d |" % (tn, len(v), len(ds), mins(sum(ds)), mins(sum(ds) / len(ds)) if ds else 0, mins(max(ds)) if ds else 0, sum(1 for x in v if x[2] == "bg")))
        allm += sum(ds)
    P("| **all** | %d | %d | %.1f | | | |\n" % (sum(len(v) for v in g.values()), sum(1 for v in g.values() for x in v if x[1]), mins(allm)))
    P("Chain C census is partial (still running; 61.5 min counted). Run minutes (%.0f) exceed the window because some runs overlapped (RED/GREEN while a census ran, parallel reviewers).\n" % mins(allm))
    P("<details><summary>every measured run</summary>\n")
    P("| type | run | min | mode | source |")
    P("|---|---|---:|---|---|")
    for b, tn, lab, endl, dur, mode, src in RUNS:
        P("| %s | %s | %s | %s | %s |" % (tn, lab, ("%.2f" % mins(dur)) if dur else "n/a", mode, src))
    P("\n</details>\n")
    P("## (e) How many times the full reverse census and the mutation set were run, and why\n")
    P(E_TEXT)
    P("## (f) Caveats on attribution accuracy\n")
    P(F_TEXT)
    open(OUT + "report.md", "w", encoding="utf8").write("\n".join(out))
    import pickle
    pickle.dump(r, open(OUT + "result.pkl", "wb"))
    return r


if __name__ == "__main__":
    report()
    print("report written:", OUT + "report.md")
