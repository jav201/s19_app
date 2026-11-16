import sys,re,glob
def screen(f):
    t=open(f,encoding='utf-8').read().split('\n')
    a=t.index('screen_text_begin'); b=t.index('screen_text_end')
    return t[:a], [re.sub(r'^   ▏?.? ?│?','',l[2:]) if False else l[2:] for l in t[a+1:b]]
def facts(name):
    head,sc=screen(name+'.png.txt')
    out=[f'##### {name}']
    for h in head:
        if h.startswith(('selected=','focused=','bench_state','keys_sent','status: Patch','widget #patch_sheet','widget #patch_inspector')): out.append(h[:230])
    for l in sc:
        s=l.strip()
        m=re.search(r'│[│╭╰]?(.*?)│?\s*$',l)
        body=l
        if re.search(r' op = |differ|refused|decoding|encoding|rows \d|points \d|more row|IDENTICAL|LINEAR|phys =|shade |scale |no edit yet| ▲ | ✗ | ✓|staged|enter edit|^.*(MAP 4x3|VAL_BLK |CURVE |LARGE|SMALL_BLK|VB1D|NTC_BLK|TAB_VB|F32_BLK|REF_BLK)',l):
            out.append('  '+l.rstrip()[:175])
    return '\n'.join(out)
for n in sys.argv[1:]: print(facts(n))
