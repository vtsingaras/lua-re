"""Differential compiler/decompiler check; uses supplied official luac builds.

PYTHONPATH=. python tests/check_compilers.py --compiler 5.1=/path/to/luac ...
Never executes the compiled Lua program.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
from lua_re_ida.bytecode import parse
from lua_re_ida.pseudocode import function_source
from compare_luac import raw_operands


def check_listing(chunk, listing):
    index, checked = -1, 0
    for line in listing.splitlines():
        if re.match(r'^(main|function) <', line):
            index += 1
        match = re.match(r'^\t(\d+)\t\[(\d+|-)\]\t(\w+)\s*\t(.*)$', line)
        if not match:
            continue
        pc, source_line, name, rest = match.groups()
        p = chunk.prototypes[index]
        ins = p.instruction(int(pc)-1)
        assert name == ins.name, (name,ins.name)
        assert (0 if source_line == '-' else int(source_line)) == (p.lines[ins.pc] if p.lines else 0)
        args = rest.split(';')[0].strip()
        actual = [int(x.rstrip('k')) for x in args.split()]
        if chunk.version == 0x54:
            expected = raw_operands(ins)
        else:
            expected = [(-o.value-1 if o.kind == 'const' else o.value) for o in ins.operands()]
            if name == 'LOADKX': expected = [ins.a]
            elif name == 'SETLIST': expected = [ins.a,ins.b,ins.c]
            elif name in ('JMP','FORLOOP','FORPREP') or (name == 'TFORLOOP' and chunk.version != 0x51):
                expected = ([ins.a] if name != 'JMP' or chunk.version != 0x51 else []) + [ins.sbx]
            elif name == 'TEST' and chunk.version == 0x51: expected = [ins.a,ins.b,ins.c]
        assert actual == expected, (chunk.version_string,index,pc,name,actual,expected)
        if '; to ' in rest:
            target = int(rest.split('; to ')[1])-1
            assert (target,'jump') in ins.successors()
        checked += 1
    assert index+1 == len(chunk.prototypes)
    assert checked == sum(len(p.words) for p in chunk.prototypes)
    return checked


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--compiler',action='append',required=True)
    ap.add_argument('--chunk',type=Path,help='Optional extra real-world chunk, matched by version')
    ap.add_argument('--report',type=Path)
    args=ap.parse_args()
    fixture=Path(__file__).parent/'fixtures/common.lua'
    rows=[]
    with tempfile.TemporaryDirectory(prefix='lua-re-check-') as tmp:
        root=Path(tmp)
        for pair in args.compiler:
            version, compiler=pair.split('=',1)
            found=subprocess.check_output([compiler,'-v'],stderr=subprocess.STDOUT).decode()
            assert found.startswith('Lua '+version+'.'),found
            inputs=[]
            for stripped in (False,True):
                path=root/f'{version}-{stripped}.luac'
                subprocess.run([compiler,'-o',str(path)]+(['-s'] if stripped else [])+[str(fixture)],check=True)
                inputs.append(path)
            if args.chunk and parse(args.chunk.read_bytes()).version_string == version:
                inputs.append(args.chunk)
            for path in inputs:
                chunk=parse(path.read_bytes())
                from lua_re_ida.decompiler import standard_bytes
                normalized=root/'normalized.luac';normalized.write_bytes(standard_bytes(chunk))
                words=check_listing(chunk,subprocess.check_output([compiler,'-l','-l',str(normalized)]).decode('latin1'))
                matching=0
                for p in chunk.prototypes:
                    source=function_source(chunk,p).source
                    recovered=root/'recovered.lua'; recovered.write_text(source)
                    compiled=root/'recovered.luac'
                    subprocess.run([compiler,'-o',str(compiled),str(recovered)],check=True,capture_output=True)
                    result=parse(compiled.read_bytes())
                    q=result.root if p is chunk.root else result.root.children[0]
                    if p.words == q.words and [k.value for k in p.constants] == [k.value for k in q.constants]:
                        matching+=1
                    if p is chunk.root and p.lines:
                        assert [v.words for v in chunk.prototypes] == [v.words for v in result.prototypes],version
                        assert [[k.value for k in v.constants] for v in chunk.prototypes] == [[k.value for k in v.constants] for v in result.prototypes],version
                rows.append(dict(version=version,debug=bool(chunk.root.lines),functions=len(chunk.prototypes),
                                 words_checked=words,source_compile_checks=len(chunk.prototypes),identical_functions=matching))
        report=dict(results=rows,passed=True)
        print(json.dumps(report,indent=2))
        if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
