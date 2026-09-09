"""Check current generated outgoing schemas against the device TX arena.

Usage: python3 transport_output_bounds.py CHECKOUT [CHECKOUT ...]
Requires build-native/include generated headers in each checkout.
"""
import ast, re, operator, sys
from pathlib import Path
ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
if len(sys.argv) < 2:
    raise SystemExit('usage: transport_output_bounds.py CHECKOUT [CHECKOUT ...]')
for checkout in sys.argv[1:]:
    root = Path(checkout)
    macros = {}
    for p in (root / 'build-native/include').glob('*.pb.h'):
        macros.update(dict(re.findall('^#define\\s+(\\w+_size)\\s+([^\\n]+)', p.read_text(), re.M)))

    def value(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Name):
            return value(ast.parse(macros[n.id], mode='eval').body)
        if isinstance(n, ast.BinOp) and type(n.op) in ops:
            return ops[type(n.op)](value(n.left), value(n.right))
        raise ValueError(ast.dump(n))
    names = set(re.findall('(?:MSG_OUT|DEBUG_OUT)\\([^,]+,\\s*(\\w+)', (root / 'lib/firmware/messagemap.def').read_text()))
    if not names:
        raise ValueError('No outgoing schemas found')
    rows = sorted([(value(ast.parse(macros[n + '_size'], mode='eval').body), n) for n in names], reverse=True)
    assert all((size + 9 + 62 <= 12288 + 13 for size, name in rows)), rows[:5]
    print(root.name, len(rows), 'outgoing schema bounds checked; largest:', rows[:5])
