import sys, pickle, json, collections
sys.path.insert(0, '.')
import timing8a as T

r = pickle.load(open(T.OUT + 'result.pkl', 'rb'))
LST = json.load(open(T.SCR + 'steps8a.json'))
STEP = {l: st for i, l, ro, st in LST}
d = r['data']; tot = d['total']; ai = r['agent_info']
m = lambda x: x / 60.0
pc = lambda x, t=tot: 100.0 * x / t
O = []; P = O.append
fg, wt, fga, wta = d['fg'], d['wt'], d['fg_a'], d['wt_a']
mnext, mnext_a = d['mnext'], d['mnext_a']

P("# Batch-100 Inc 8a (design-first experiment): where the wall-clock and tokens went\n")
P("Window: 2026-10-30 %s -> 2026-10-31 %s UTC (E1 start to last line of E5 code review r2). Total = **%.1f min (%.2f h)**. Produced by `timing8a.py` (a copy of `timing.py`: new agent list, window start 20:12:29Z, Inc 8a path rule, empty background-run inventory; attribution method unchanged) and `report8a.py`, both in this folder. Numbers only; no judgement on value.\n" % (r['t0'].strftime('%H:%M:%S'), r['t1'].strftime('%H:%M:%S'), m(tot), tot / 3600))

# (a)
P("## (a) Per-agent wall, foreground, idle-on-background, output tokens, model\n")
P("| step | agent (`id`) | model | start-end (UTC) | wall min | foreground min | idle-on-bg min | tool calls | asst msgs | output tok | cache-read tok |")
P("|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
stot = collections.defaultdict(collections.Counter)
for lab, i in ai.items():
    u = i['usage']; st = STEP[lab]
    P("| %s | %s (`%s`) | %s | %s-%s | %.1f | %.1f | %.1f | %d | %d | %s | %s |" % (
        st, lab, i['id'][:8], ','.join(i['models']).replace('claude-', ''), i['t0'].strftime('%H:%M'), i['t1'].strftime('%H:%M'),
        m(i['wall']), m(i['fg']), m(i['wait']), i['ntools'], i['msgs'],
        format(u.get('output_tokens', 0), ','), format(u.get('cache_read_input_tokens', 0), ',')))
    c = stot[st]; c['n'] += 1; c['wall'] += i['wall']; c['fg'] += i['fg']; c['wait'] += i['wait']
    c['out'] += u.get('output_tokens', 0); c['cr'] += u.get('cache_read_input_tokens', 0)
P("\nPer-step agent sums (agent-minutes, NOT deduplicated; parallel agents add up):\n")
P("| step | agents | wall min | foreground min | idle-on-bg min | output tok |")
P("|---|---:|---:|---:|---:|---:|")
T_ = collections.Counter()
for st in ['E1', 'E2', 'E3', 'E4', 'E5']:
    c = stot[st]
    P("| %s | %d | %.1f | %.1f | %.1f | %s |" % (st, c['n'], m(c['wall']), m(c['fg']), m(c['wait']), format(c['out'], ',')))
    for k in c: T_[k] += c[k]
P("| **all** | %d | %.1f | %.1f | %.1f | **%s** |" % (T_['n'], m(T_['wall']), m(T_['fg']), m(T_['wait']), format(T_['out'], ',')))
sonnet = sum(i['usage'].get('output_tokens', 0) for l, i in ai.items() if any('sonnet' in k for k in i['models']))
P("\nOutput tokens by model: Sonnet 5.5 %s (E3 design pass 1 only), Opus 5.5 %s (all other agents). The main orchestrator (Opus 5.5) wrote a further 94,324 output tokens over 84 messages inside the window; it is not in the totals above (the Inc 7 baseline did not count the orchestrator either).\n" % (format(sonnet, ','), format(T_['out'] - sonnet, ',')))

# (b)
P("## (b) Wall time per step (overlaps counted once)\n")
P("Step span = first start to last end of that step's agents, so orchestrator rulings between E3 rounds sit inside the E3 span. The gap before a step is orchestrator-only time (decisions, rulings, briefs) between the previous step's last agent line and this step's first. E2-baseline (Code-Wire graph, 7.3 min) ran inside E1's span in parallel and adds no time.\n")
def span(labs):
    return min(ai[l]['t0'] for l in labs), max(ai[l]['t1'] for l in labs)
def union(labs):
    iv = sorted((ai[l]['t0'], ai[l]['t1']) for l in labs); s = 0; cur = None
    for a, b in iv:
        if cur is None: cur = [a, b]
        elif a <= cur[1]: cur[1] = max(cur[1], b)
        else: s += (cur[1] - cur[0]).total_seconds(); cur = [a, b]
    return s + (cur[1] - cur[0]).total_seconds()
steps = [('E1', [l for l in ai if STEP[l] == 'E1' or l.startswith('E2-baseline')]),
         ('E2', [l for l in ai if STEP[l] == 'E2' and not l.startswith('E2-baseline')]),
         ('E3', [l for l in ai if STEP[l] == 'E3']), ('E4', [l for l in ai if STEP[l] == 'E4']),
         ('E5', [l for l in ai if STEP[l] == 'E5'])]
P("| step | agents | span start-end (UTC) | span min | any-agent-running min | orchestrator-only inside span min | orchestrator-only gap before step min |")
P("|---|---:|---|---:|---:|---:|---:|")
prev_end = r['t0']; accum = 0
for st, labs in steps:
    a, b = span(labs); sp = (b - a).total_seconds(); un = union(labs); gap = (a - prev_end).total_seconds()
    accum += sp + gap
    P("| %s%s | %d | %s-%s | %.1f | %.1f | %.1f | %.1f |" % (st, ' (+E2-baseline)' if st == 'E1' else '', len(labs), a.strftime('%H:%M:%S'), b.strftime('%H:%M:%S'), m(sp), m(un), m(sp - un), m(gap)))
    prev_end = b
P("| **total** | | | | | | steps + gaps = %.1f = window %.1f |\n" % (m(accum), m(tot)))
e3r = lambda a, b: m((max(ai[b]['t1'], ai[a]['t1']) - ai[a]['t0']).total_seconds())
r1 = e3r('E3 r1 architect', 'E3 r1 security'); r2 = e3r('E3 r2 architect', 'E3 r2 security'); r3 = e3r('E3 r3 architect', 'E3 r3 security')
dp1 = m(ai['E3 design pass 1 (Sonnet)']['wall']); dp2 = m(ai['E3 design pass 2']['wall'])
P("E3 internals (min, wall): reviewer round 1 %.1f (parallel pair) + design pass 1 (Sonnet) %.1f + round 2 %.1f + design pass 2 (Opus) %.1f + round 3 %.1f = %.1f of agent time; the rest of the E3 span (%.1f of %.1f min) is orchestrator rulings between them.\n" % (
    r1, dp1, r2, dp2, r3, r1 + dp1 + r2 + dp2 + r3, m(span(steps[2][1])[1].timestamp() - span(steps[2][1])[0].timestamp()) - (r1 + dp1 + r2 + dp2 + r3), m(span(steps[2][1])[1].timestamp() - span(steps[2][1])[0].timestamp())))
d_end = span(steps[2][1])[1]
P("Stage split: design stage (window start to end of E3, %s) = %.1f min (%.1f%%); code stage (E4 + E5 + the gap before E4) = %.1f min (%.1f%%).\n" % (d_end.strftime('%H:%M:%S'), m((d_end - r['t0']).total_seconds()), pc((d_end - r['t0']).total_seconds()), m((r['t1'] - d_end).total_seconds()), pc((r['t1'] - d_end).total_seconds())))

# (c)
P("## (c) Bucket table (same 13 buckets and sweep as the Inc 7 baseline)\n")
P("Whole-window sweep (as Inc 7 table (b)): each foreground activity, agents and orchestrator, counts once, equal split under overlap. 'Wait' = agents idle on background compute. No run inventory was built for 8a, so waits are labelled only by the keyword in the poll command (bucket 5 = poll commands naming GREEN, the rest 'not identified').\n")
P("| # | bucket | foreground min | % of total | wait on bg min | % of total | combined min | combined % | Inc 7 combined % |")
P("|---|---|---:|---:|---:|---:|---:|---:|---:|")
I7 = {1: .9, 2: .4, 3: 1.6, 4: 2.2, 5: 17.1, 6: 2.4, 7: 49.3, 8: 1.1, 9: 2.8, 10: .2, 11: 1.0, 12: .3, 13: 20.3}
for b in range(1, 14):
    f = m(fg.get(b, 0)); w = m(wt.get(b, 0))
    P("| %d | %s | %.1f | %.1f%% | %.1f | %.1f%% | %.1f | %.1f%% | %.1f%% |" % (b, T.BN[b], f, pc(f * 60), w, pc(w * 60), f + w, pc((f + w) * 60), I7[b]))
w0 = m(wt.get(0, 0)); wm = m(wt.get(-1, 0))
P("| - | bg wait, job not identified | 0.0 | 0.0%% | %.1f | %.1f%% | %.1f | %.1f%% | 0.4%% |" % (w0, pc(w0 * 60), w0, pc(w0 * 60)))
P("| - | nobody running | 0.0 | 0.0%% | %.1f | %.1f%% | %.1f | %.1f%% | 0.0%% |" % (wm, pc(wm * 60), wm, pc(wm * 60)))
P("| | **total** | **%.1f** | | **%.1f** | | **%.1f** | | |\n" % (m(sum(fg.values())), m(sum(wt.values())), m(sum(fg.values()) + sum(wt.values()))))
P("Row 13 (model reasoning/writing) split by the bucket of the tool call that followed each turn (whole window):\n")
P("| bucket of next tool call | model min |"); P("|---|---:|")
for b in sorted(k for k in mnext if k is not None): P("| %s | %.1f |" % (T.BN.get(b, b), m(mnext[b])))
unk = m(fg.get(13, 0)) - m(sum(mnext.values()))
P("| turn ended without a tool call (text, hand-back) | %.1f |\n" % unk)
P("Agent-foreground only (orchestrator and waits excluded), as Inc 7 table (c): **%.1f min = %.1f%% of the window**. The other %.1f min = agents idle on bg compute %.1f + no agent running %.1f.\n" % (m(sum(fga.values())), pc(sum(fga.values())), m(tot - sum(fga.values())), m(sum(wta.values())), m(d['unc_a'].get('uncovered', 0))))
P("| # | bucket | min | % of fg | min with model time folded in | % of fg (folded) |"); P("|---|---|---:|---:|---:|---:|")
ft = sum(fga.values()); unk_a = m(fga.get(13, 0)) - m(sum(mnext_a.values()))
for b in range(1, 14):
    x = m(fga.get(b, 0))
    if b < 13:
        f2 = x + m(mnext_a.get(b, 0)); P("| %d | %s | %.1f | %.1f%% | %.1f | %.1f%% |" % (b, T.BN[b], x, pc(x * 60, ft), f2, pc(f2 * 60, ft)))
    else:
        P("| 13 | %s | %.1f | %.1f%% | %.1f (no following tool) | %.1f%% |" % (T.BN[b], x, pc(x * 60, ft), unk_a, pc(unk_a * 60, ft)))
P("")
P("Bucket 10 note: design-stage agents (E1-E3) write their whole product as .md files under `.dev-flow/`, which the classifier charges to bucket 10 (packet/record/evidence); in Inc 7 that bucket was only handoff paperwork. Folded model time before those writes is 36.7 min of the whole-window sweep.\n")

# (d)
review_labs = [l for l in ai if any(k in l for k in ('architect', 'security', 'code review'))]
design_labs = [l for l in ai if 'design pass' in l]
cp_labs = [l for l in ai if 'corrective' in l]
rw = sum(ai[l]['wall'] for l in review_labs)
P("## (d) Side by side: Inc 7 vs Inc 8a\n")
P("| metric | Inc 7 | Inc 8a |"); P("|---|---:|---:|")
P("| total wall (window) min | 596.7 (687 with the 90-min census tail the baseline excluded) | %.1f |" % m(tot))
P("| foreground agent time, deduplicated, min | 218.8 | %.1f |" % m(sum(fga.values())))
P("| idle-on-background (agents waiting on bg compute) min | 373.0 whole-window sweep (377.9 agent-only window minus fg) | %.1f (+ %.1f min with no agent running) |" % (m(sum(wta.values())), m(d['unc_a'].get('uncovered', 0))))
P("| census time (bucket 7, combined) min | 294.5 (49.3%%) | %.1f (%.1f%%) |" % (m(fg.get(7, 0)) + m(wt.get(7, 0)), pc(fg.get(7, 0) + wt.get(7, 0))))
P("| model reasoning/writing, whole-window sweep, min | 121.1 (20.3%%) | %.1f (%.1f%%) |" % (m(fg.get(13, 0)), pc(fg.get(13, 0))))
P("| model reasoning/writing, agent-only sweep, min | 121.9 | %.1f |" % m(fga.get(13, 0)))
P("| orchestrator own time (bucket 11) min | 5.9 | %.1f |" % m(fg.get(11, 0)))
P("| review agents launched / wall-min sum | 4 / 83.5 (all on code) | %d / %.1f (%d on design, E3 r1-r3 pairs; %d on code, E5) |" % (len(review_labs), m(rw), 6, 3))
P("| review rounds on design / on code | 0 / 2 | 3 / 2 (E5 round 1 = code + security; round 2 = code only) |")
P("| corrective passes on code: count / agent wall min / agent fg min | 2 (pass 2 partial) / 290.1 / 77.6 | %d / %.1f / %.1f |" % (len(cp_labs), m(sum(ai[l]['wall'] for l in cp_labs)), m(sum(ai[l]['fg'] for l in cp_labs))))
P("| design correction passes (document edits, no code): count / wall min | 0 | %d / %.1f (pass 1 Sonnet %.1f, pass 2 Opus %.1f) |" % (len(design_labs), dp1 + dp2, dp1, dp2))
P("| full-census launches | 6 (3 complete, 2 abandoned, 1 running) | 0 (operator ruling: new/modified requirement tests only; E4-tester-notes, E5-cp1-notes) |")
P("| mutation | 8 set-runs inside implementers/correctives | 1 mutants agent (78 mutants, 11.5 min) + 22 runs in cp1 + 7 gap mutants in integration (steps.log) |")
P("| agents launched | 8 | %d |" % len(ai))
P("| total subagent output tokens | 889,448 | %s |" % format(T_['out'], ','))
P("| total subagent cache-read tokens | 201,301,236 | %s |" % format(T_['cr'], ','))
P("| models | Opus 5.5 only | Sonnet 5.5 for 1 agent (%s output tok); Opus 5.5 for %d agents |\n" % (format(sonnet, ','), len(ai) - 1))

# (e)
W7, W8 = 596.7, m(tot); F7, F8 = 218.8, m(sum(fga.values()))
OT7, OT8 = 889448, T_['out']
L7, L8 = 10, 11
S7, S8 = 2247 + 311, 1719 + 132
P("## (e) Normalisation\n")
P("| quantity | Inc 7 | Inc 8a | source |")
P("|---|---:|---:|---|")
P("| LLRs in scope | 10 (HLR-169: LLR-169.1-169.9, plus LLR-168.4) | 11 (full or partial; HLR-170 is 1 more HLR, 2 ATs, 11 TCs) | E1-scope.md |")
P("| source lines changed in `s19_app` (insertions + deletions) | 2,558 (+2,247 / -311; 4 files) | 1,851 (+1,719 / -132; 4 files) | `git diff --stat` as instructed (8a: working tree vs dc3b314, uncommitted) |")
P("| net source lines | +1,936 | +1,587 | same |")
P("| test lines changed | +3,089 / -44 (14 files) | +1,264 / -20 (8 tracked files) + new untracked `tests/test_b100_document.py`, 1,911 lines | `git diff --stat -- tests`; `wc -l` |")
P("| new test functions (`def test_` lines added) | 73 | 100 (31 in tracked files + 69 in the new file) | grep of the diff / new file; parametrised ids not expanded (8a RED run: 164 nodes, 160 failed on base) |")
P("| MAJOR/HIGH findings, total | 8 | 14 | baseline; 8a below |")
P("| ... caught at design stage (E2/E3) | 0 | 13 (architect r1 5 MAJOR + security r1 4 MAJOR + architect r2 2 MAJOR + security r2 2 MAJOR; 0 HIGH; round 3: 0) | E3-architect.md, E3-security.md |")
P("| ... caught at code stage (E5) | 8 | 1 (code review F1 MAJOR, tagged design-gap; security 0 MAJOR/0 HIGH; round 2: 0) | review-increment-008a.md, security-increment-008a.md |")
P("| total findings incl. MINOR/LOW, as recorded | n/a | design stage: arch r1 5/6/3 + sec r1 0H/4/5/3 + arch r2 2/3/4 + sec r2 2/2/4 + r3 3 MINOR 2 LOW + 1 MINOR 2 LOW; code stage: code review 1 MAJOR/4 MINOR/4 LOW, security 5 LOW | steps.log |")
P("\nMinutes per unit (wall = whole window; fg = deduplicated agent-foreground):\n")
P("| ratio | Inc 7 | Inc 8a |"); P("|---|---:|---:|")
P("| wall min per LLR | %.1f (%.1f with the 90-min tail) | %.1f |" % (W7 / L7, 687 / L7, W8 / L8))
P("| agent-foreground min per LLR | %.1f | %.1f |" % (F7 / L7, F8 / L8))
P("| wall min per 100 changed source lines | %.1f | %.1f |" % (W7 / S7 * 100, W8 / S8 * 100))
P("| agent-foreground min per 100 changed source lines | %.1f | %.1f |" % (F7 / S7 * 100, F8 / S8 * 100))
P("| wall min per new test function | %.1f | %.1f |" % (W7 / 73, W8 / 100))
P("| subagent output tokens per LLR | %s | %s |" % (format(round(OT7 / L7), ','), format(round(OT8 / L8), ',')))
P("| subagent output tokens per 100 changed source lines | %s | %s |" % (format(round(OT7 / S7 * 100), ','), format(round(OT8 / S8 * 100), ',')))
P("| wall min per MAJOR/HIGH finding | %.1f | %.1f |" % (W7 / 8, W8 / 14))
P("")

# (f)
P("## (f) Caveats\n")
for i, t in enumerate([
    "**Same method, different inputs.** Attribution rules are those of `timing.py` (gap before a tool_result goes to the tool, before an assistant block to model time; poll loops are idle wait; equal split under overlap). Only the agent list, window start, the 8a path regex and the background-run inventory changed.",
    "**No background-run inventory for 8a.** Inc 7 labelled waits from evidence footers and chain.log. For 8a I did not rebuild it, so wait minutes are labelled only by poll-command keywords (30.0 min tagged GREEN, 18.8 min 'not identified'). Wait totals are exact; the split between run types is not. Bucket 7 (census) holds only reads of census modules and guard-module runs; no full census was launched.",
    "**Windows differ in definition.** Inc 7 window ends at corrective pass 2's last line (pass 2 still running), excluding a ~90 min census tail (687 min with it). Inc 8a window ends at code review r2's last line; the close records and the E13 capture gate that follow (steps.log 00:40Z onward) are not in the window.",
    "**Inc 8a includes work Inc 7 did not do:** the design stage E1-E3 (%.1f min) and the Code-Wire baseline graph. Inc 7 included the implementer, two review rounds and two correctives; E1-E3 has no Inc 7 counterpart, so totals are not like for like. The code-stage-only figure (E4 + E5 + gap) is %.1f min." % (m((d_end - r['t0']).total_seconds()), m((r['t1'] - d_end).total_seconds())),
    "**Scope normalisers are rough.** LLR counts are 10 vs 11 but 8a LLRs are mostly partial arms. Changed-line counts come from `git diff --stat` on `s19_app` only, as instructed: 8a is a working-tree diff vs dc3b314 (uncommitted, includes E5 cp1), Inc 7 is the committed range 80052cb..052dc3a (which is after two corrective passes). Test functions are counted by `def test_` lines added; parametrisation is not expanded.",
    "**Findings counts are severity labels as recorded by the reviewers.** Inc 7's 8 comes from the baseline/PLAN (I did not recount it; review-increment-007.md round 1 alone lists 3 MAJOR). The 8a design-stage 13 counts findings per round per reviewer; some architect and security findings may describe one defect (e.g. R8 appears in architect and security round 2). Round-1 findings that were carried into round 2 are not double-counted. Code-stage F1 is also tagged design-gap by its reviewer, i.e. visible at design stage in hindsight.",
    "**Tokens.** Output tokens are summed over unique assistant message ids from the JSONL `usage` field and may undercount the last block of a message slightly. Inc 7's total (889,448) is the sum of its baseline table. The orchestrator's own tokens are excluded on both sides.",
    "**Sonnet pass.** E3 design pass 1 ran on Sonnet 5.5 (9.1 min, 74,492 output tokens). Its output was rebuilt in pass 2 on Opus (steps.log: truncated prototype file, content lost, A3R2-5). Minutes spent on the failed Sonnet attempt are in the E3 totals.",
    "**Parallel agents overlap:** per-step agent sums in (a) exceed step spans in (b); the sweep in (c) counts overlap once with equal split, which cannot tell critical-path from off-path work.",
    "**No judgement on value is made here.",
], 1):
    P("%d. %s" % (i, t.rstrip('*') if t.endswith('here.') else t))
out = "\n".join(O).replace("**No judgement on value is made here.", "**No judgement on value** is made here.")
open('timing-8a.md', 'w', encoding='utf8').write(out)
print(out)
