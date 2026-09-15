"""Offline analysis, exports and decompilation. Never executes Lua code."""
import argparse
from pathlib import Path
from .bytecode import parse, listing

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('chunk', type=Path)
    ap.add_argument('-o', '--output', type=Path)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--json', action='store_true', help='structured analysis including raw string bytes')
    mode.add_argument('--callgraph', action='store_true', help='Graphviz DOT call graph')
    mode.add_argument('--decompile', action='store_true', help='recover Lua source using unluac')
    mode.add_argument('--standard', action='store_true', help='export a standard Lua RE chunk')
    args = ap.parse_args()
    chunk = parse(args.chunk.read_bytes())
    if args.standard:
        if args.output is None:
            ap.error('--standard requires --output')
        from .decompiler import standard_bytes
        args.output.write_bytes(standard_bytes(chunk))
        return
    if args.json or args.callgraph:
        from .analysis import Analysis
        analysis = Analysis(chunk)
        output = analysis.to_json() if args.json else analysis.callgraph_dot()
    elif args.decompile:
        from .decompiler import decompile
        output = decompile(chunk)
    else:
        output = listing(chunk)
    if args.output:
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')

if __name__ == '__main__':
    main()
