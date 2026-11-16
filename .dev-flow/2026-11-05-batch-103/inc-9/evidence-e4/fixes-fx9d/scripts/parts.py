import json,sys
for f in sys.argv[1:]:
    for line in open(f):
        if "FX9CPARTS " in line:
            d=json.loads(line.split("FX9CPARTS ",1)[1])
            st=[p for p in d["parts"] if p[0]=="_stage_bench_record"][-1]
            print(f, "block", st[2])
            for n in ("stage_record","serialize_change_document","_show_document","load_text","find_matching_bracket","set_document"):
                print("  ",n,[p[2] for p in d["parts"] if p[0]==n and abs(p[1]-st[1])<2.5])
            print("   after_stage",d["after_stage"],"n_keys",d["n_keys"],"max",d["max"])
