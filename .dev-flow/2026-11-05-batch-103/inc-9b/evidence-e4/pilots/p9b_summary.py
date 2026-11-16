"""Print a compact summary of the `P9B <name> <json>` lines of the P9b probe transcripts given as arguments."""
import json
import sys

for path in sys.argv[1:]:
    print(f"== {path.rsplit('/', 1)[-1]}")
    for raw in open(path, encoding="utf-8"):
        at = raw.find("P9B ")
        if at < 0:
            continue
        name, data = raw[at + 4:].split(" ", 1)
        d = json.loads(data)
        if name == "P1":
            g = "; ".join(f"{x['gap']} {x['s']}s ticks={x['ticks']} paints={x['paints']} key={x['key']} titles={x['titles']}"
                          for x in d["gaps"])
            print(f"P1 {d['chain']} t{d['trial']} load={d['load'][0]} paints={d.get('paints_total')} ticks={d.get('ticks_total')} app_key={d.get('app_key_at')} body_key={d.get('body_key_at')} key_at={d['key_at']} ends={d['step_ends']} | {g}")
        elif name == "P2":
            for r in d["results"]:
                print(f"P2 focus {r['focus']}: _paint calls while toggling = {r['paint_calls_during_toggles']}")
                for s in r["seq"]:
                    print(f"   {s['label']:<48} computed {s['border_top']:<36} painted {s['corner']} inline={len(s['inline'])} "
                          f"size={s['size']} {s.get('cleared', '')}")
        elif name == "P3":
            print(f"P3 {d['size']} win={d['win_width']} B={d['room_B']} title_col={d['title_start']} after={d['after_title']!r} "
                  f"whole_by_len={d.get('whole_by_length')} pill_whole={d['pill_whole']} pill bg={d['pill_bg']} fg={d['pill_fg']} bold={d['pill_bold']}")
            print(f"   line[:20]={d['line'][:20]!r} line[-8:]={d['line'][-8:]!r} len={len(d['line'])} idle[:24]={d['idle_line'][:24]!r}")
        elif name == "EX-BC6" and "step3_sheet" in d:
            print(f"EX-BC6 t{d['trial']} load={d['load'][0]} write={d['step_write']} s1={d['step1_serialize']} "
                  f"s2={d['step2_ledger_card_json']} s3={d['step3_sheet']} s4={d['step4_rest']} block={d['block']} calls={d['calls']}")
        else:
            print(name, json.dumps(d, ensure_ascii=False))
    print()
