import sys, runpy
tools = r'~\Github\code-wire\tools'
sys.path.insert(0, tools)
G = r'~\Github\s19_app-b103-inc8b\.dev-flow\2026-11-05-batch-103'
R = r'~/<job>\tmp\cw8b-clone'
graphs = ['--graph', G + r'\inc-8\codewire\graph-inc8.md', '--graph', G + r'\inc-9\codewire\graph-inc9.md', '--graph', G + r'\inc-8b\codewire\graph-inc8b.md']
step = sys.argv[1]
if step == 'marks':
    sys.argv = ['m', '--repo', R, '--layered'] + graphs
    runpy.run_path(tools + r'\codewire_marks.py', run_name='__main__')
else:
    paths = []
    for p in ['s19_app/tui/definition_sheet.py', 's19_app/tui/screens_directionb/patch_editor/sheet.py',
              's19_app/tui/definition_bench.py', 's19_app/tui/a2l_parameter_picker.py']:
        paths += ['--path', p]
    sys.argv = ['x', '--repo', R, '--layered'] + graphs + paths + ['--out', r'~/<job>\tmp\cw8b-out2']
    runpy.run_path(tools + r'\codewire_extract.py', run_name='__main__')
