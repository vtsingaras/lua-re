"""Compare parsed instructions, lines, operands and constants to stock luac 5.4."""
import argparse
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from lua_re_ida.bytecode import parse

def raw_operands(ins):
    n = ins.name
    values = [o.value for o in ins.operands()]
    if n == 'JMP': return [ins.sj]
    if n in ('FORLOOP', 'FORPREP', 'TFORPREP', 'TFORLOOP'): return [ins.a, ins.bx]
    if n == 'LOADKX': return [ins.a]
    if n in ('NEWTABLE', 'SETLIST'): return [ins.a, ins.b, ins.c]
    if n in ('RETURN', 'TAILCALL'): return [ins.a, ins.b, ins.c]
    return values

def unquote(s):
    escapes = dict(a=7, b=8, f=12, n=10, r=13, t=9, v=11)
    out, i = bytearray(), 1
    while i < len(s) - 1:
        if s[i] != '\\':
            out.append(ord(s[i]))
            i += 1
        else:
            i += 1
            if s[i].isdigit():
                out.append(int(s[i:i+3]))
                i += 3
            else:
                out.append(escapes.get(s[i], ord(s[i])))
                i += 1
    return bytes(out)

def compare(path, compiler):
    c = parse(path.read_bytes())
    assert c.endian == '<' and c.integer_size == c.number_size == 8
    data = c.data
    if c.variant == 'glinet-compact':
        data = data[:15] + struct.pack('<qd', 0x5678, 370.5) + data[16:]
    with tempfile.NamedTemporaryFile(suffix='.luac') as f:
        f.write(data)
        f.flush()
        out = subprocess.check_output([compiler, '-l', '-l', f.name]).decode('latin1')
    pi = -1
    checked_words = constants = 0
    for line in out.splitlines():
        if re.match(r'^(main|function) <', line):
            pi += 1
            p = c.prototypes[pi]
            assert int(re.search(r'\((\d+) instructions?', line)[1]) == len(p.words), (path, pi)
            continue
        match = re.match(r'^\t(\d+)\t\[(\d+|-)\]\t(\w+)\s*\t(.*)$', line)
        if match:
            pc, lineno, opcode, rest = match.groups()
            ins = p.instruction(int(pc) - 1)
            assert ins.name == opcode, (path, pi, pc, ins.name, opcode)
            line_expected = p.lines[ins.pc] if p.lines else 0
            assert max(0, line_expected) == (0 if lineno == '-' else int(lineno)), (path, pi, pc, 'line')
            args = rest.split('\t;')[0].strip()
            values = [int(x.rstrip('k')) for x in args.split()]
            assert values == raw_operands(ins), (path, pi, pc, args, raw_operands(ins))
            if opcode in ('SETTABUP', 'SETTABLE', 'SETI', 'SETFIELD', 'SELF', 'RETURN', 'TAILCALL'):
                assert ('k' in args) == bool(ins.k), (path, pi, pc, 'k flag')
            if opcode in ('JMP', 'FORLOOP', 'FORPREP', 'TFORPREP', 'TFORLOOP'):
                reference_pc = int(re.search(r'\bto (\d+)', rest)[1]) - 1
                assert reference_pc in [pc for pc, kind in ins.successors() if kind == 'jump']
            checked_words += 1
            continue
        match = re.match(r'^\t(\d+)\t([NBFIS])\t(.*)$', line)
        if match:
            index, tag, rendered = match.groups()
            k = p.constants[int(index)]
            if tag == 'S': value = unquote(rendered)
            elif tag == 'N': value = None
            elif tag == 'B': value = rendered == 'true'
            elif tag == 'I': value = int(rendered)
            else: value = float(rendered)
            if tag == 'F':
                assert math.isclose(value, k.value, rel_tol=1e-12, abs_tol=1e-300), (path, pi, index)
            else:
                assert value == k.value, (path, pi, index, value, k.value)
            constants += 1
    assert pi + 1 == len(c.prototypes)
    assert checked_words == sum(len(p.words) for p in c.prototypes)
    assert constants == sum(len(p.constants) for p in c.prototypes)
    return dict(file=str(path), functions=len(c.prototypes), words=checked_words, constants=constants)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--luac', required=True)
    ap.add_argument('--report', type=Path)
    ap.add_argument('files', nargs='+', type=Path)
    args = ap.parse_args()
    version = subprocess.check_output([args.luac, '-v'], stderr=subprocess.STDOUT).decode().strip()
    assert version.startswith('Lua RE.'), version
    results = [compare(p, args.luac) for p in args.files]
    report = dict(reference=version, files=len(results),
                  functions=sum(r['functions'] for r in results),
                  words=sum(r['words'] for r in results),
                  constants=sum(r['constants'] for r in results), results=results)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'results'}, indent=2))

if __name__ == '__main__':
    main()
