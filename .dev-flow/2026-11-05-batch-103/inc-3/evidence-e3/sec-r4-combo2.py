"""E3 round-4 security probe, Inc 3a (batch-103): the E3S3-14 oracle on a combination where ONE record layout is
read for an AXIS_PTS (counts (7,)) and for STD curves (counts (8,) and (7,)), under MOD_COMMON ALIGNMENT_WORD 2, and
one TAB_VERB method / COMPU_VTAB is named by the curves, their axes and the COM axes: one walk (file order and
reversed) against a fresh walk per name; the round-3 slips as mutants.
THROWAWAY; read-only. Usage: python -I sec-r4-combo2.py <tree> <scratch>
"""
import importlib.util, pathlib, sys

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

TXT = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
       'ALIGNMENT_WORD 2\n/end MOD_COMMON\n'
       '/begin RECORD_LAYOUT RL_SH\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT\n'
       ' FNC_VALUES 3 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
       '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
       '/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_G "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT_GONE\n/end COMPU_METHOD\n'
       '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n/end COMPU_VTAB\n'
       '/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_SH 0 CM_V 7 0 255\n/end AXIS_PTS\n'
       + "".join(f'/begin CHARACTERISTIC {n} ""\n CURVE 0x{ad:X} {rl} 0 {cm} 0 255\n /begin AXIS_DESCR\n'
                 f'  {kind} NO_INPUT_QUANTITY {acm} {mx} 0 255\n{ref} /end AXIS_DESCR\n/end CHARACTERISTIC\n'
                 for n, ad, rl, cm, kind, acm, mx, ref in (
                     ("S8", 0x200, "RL_SH", "CM_V", "STD_AXIS", "CM_V", 8, ""),
                     ("S7", 0x300, "RL_SH", "CM_V", "STD_AXIS", "CM_G", 7, ""),
                     ("K1", 0x400, "RL_U8", "CM_V", "COM_AXIS", "CM_V", 7, "  AXIS_PTS_REF AXO\n"),
                     ("K2", 0x500, "RL_U8", "CM_G", "COM_AXIS", "CM_V", 7, "  AXIS_PTS_REF AXO\n"),
                     ("S8b", 0x600, "RL_SH", "CM_V", "STD_AXIS", "CM_V", 8, "")))
       + '/begin CHARACTERISTIC V1 ""\n VALUE 0x700 RL_U8 0 CM_V 0 255\n/end CHARACTERISTIC\n'
       '/begin CHARACTERISTIC V2 ""\n VALUE 0x701 RL_U8 0 CM_G 0 255\n/end CHARACTERISTIC\n'
       '/end MODULE\n/end PROJECT\n')
p = W / "combo2.a2l"; p.write_text(TXT, encoding="utf-8")
data = a.parse_a2l_file(p)
names = [t["name"] for t in data["tags"]]
fresh = {}
for nm in names:
    r, _ = m.describe_all(data, [nm])
    if nm in r:
        fresh[nm] = m.public(r[nm])
res, maps = m.describe_all(data)
for nm in names:
    if nm in res:
        v = res[nm]
        print(f"  {nm}: refusal {v.get('refusal')} {v.get('message')!r} values_offset {v.get('values_offset')} "
              f"conv {v['conversion']} {v['conv_refusal']} axes_conv_refusals "
              f"{[c[1] for c in v.get('axes_conversion', [])]}", flush=True)
print(f"  reads: {len(maps['reads'])} entries, stats {{k: v for k, v in maps['stats'].items() if v}}".replace(
    "{k: v for k, v in maps['stats'].items() if v}", str({k: v for k, v in maps['stats'].items() if v})), flush=True)
for mu in (None, "owner-leak", "mutate", "cache-check"):
    m.R3.MUTANT = mu
    row = []
    for order in (names, names[::-1]):
        try:
            r, _ = m.describe_all(data, order)
            row.append(str(sum(1 for nm in fresh if m.public(r[nm]) != fresh[nm])))
        except Exception as e:  # noqa: BLE001
            row.append(f"raises {type(e).__name__}: {e}")
    m.R3.MUTANT = None
    print(f"[O2] mutant {str(mu):<11}: objects differing from a fresh walk per name: forward {row[0]}, reversed {row[1]}",
          flush=True)
real_fresh = {nm: D.describe_definitions([nm], data)[nm] for nm in names}
for order in (names, names[::-1]):
    r = m.describe_e5(order, data)
    print(f"[O2] Inc 2a real describe memoised once per walk vs per name: differing "
          f"{sum(1 for nm in names if r[nm] != real_fresh[nm])}", flush=True)
