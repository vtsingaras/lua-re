"""Conservative register dataflow, call-site and dependency index. AGPL-3.0.

Names describe static expressions, not guaranteed runtime callees. Direct closure
references are emitted only when every incoming path agrees on the prototype.
"""
from collections import deque
from dataclasses import dataclass
import json
from .bytecode import display, text, OPNAMES, ARITHMETIC, CONDITIONAL

@dataclass(frozen=True)
class Value:
    kind: str
    label: str
    target: int = -1
    literal: object = None

@dataclass
class Call:
    ea: int
    function: int
    target: str
    category: str
    callee: int
    arguments: list
    module: str = ''

def field(base, key):
    if isinstance(key.literal, bytes):
        name = text(key.literal)
        if name.isidentifier() and name.isascii():
            label = name if base.kind == 'environment' else base.label + '.' + name
        else:
            label = base.label + '[' + display(key.literal) + ']'
    else:
        label = base.label + '[' + key.label + ']'
    return Value('global' if base.kind == 'environment' else 'member', label[:180])

def analyze_function(p):
    instructions = {i.pc: i for i in p.instructions()}
    legacy = p.version < 0x54
    captured = {u.index for child in p.children for u in child.upvalues if u.instack and u.kind not in (1, 3)}
    if p.version == 0x51:
        captured = {p.instruction(pc).b for ins in instructions.values() if ins.name == 'CLOSURE'
                    for pc in range(ins.pc + 1, ins.pc + ins.size // 4)
                    if p.instruction(pc).name == 'MOVE'}
    entry = {i: Value('parameter', p.local_name(i, 0) or f'R{i}') for i in range(p.params)}

    def reg(state, i, pc):
        return state.get(i, Value('local', p.local_name(i, pc) or f'R{i}'))

    def constant(i):
        value = p.constants[i].value
        return Value('constant', display(value), literal=value)

    def upvalue(i):
        name = text(p.upvalues[i].name) or f'U{i}'
        return Value('environment' if name == '_ENV' else 'upvalue', name)

    def transfer(ins, incoming):
        state = dict(incoming)
        n, a, b, c = ins.name, ins.a, ins.b, ins.c
        get = lambda i: reg(incoming, i, ins.pc)
        rk = (lambda i: constant(i & 255) if i & 256 else get(i)) if legacy else (lambda i: constant(i) if ins.k else get(i))
        def clear(start, end):
            for i in range(start, min(end, p.stack)):
                state.pop(i, None)
        result = None
        if n == 'MOVE': result = get(b)
        elif n == 'LOADI': result = Value('constant', str(ins.sbx), literal=ins.sbx)
        elif n == 'LOADF': result = Value('constant', str(float(ins.sbx)), literal=float(ins.sbx))
        elif n in ('LOADFALSE', 'LFALSESKIP', 'LOADTRUE'):
            val = n == 'LOADTRUE'
            result = Value('constant', display(val), literal=val)
        elif n in ('LOADK', 'LOADKX'): result = constant(ins.extra if n == 'LOADKX' else ins.bx)
        elif n == 'LOADBOOL': result = Value('constant', display(bool(b)), literal=bool(b))
        elif n == 'GETGLOBAL': result = Value('global', text(p.constants[ins.bx].value))
        elif n == 'LOADNIL':
            for i in range(a, b + 1 if p.version == 0x51 else a + b + 1):
                state[i] = Value('constant', 'nil', literal=None)
        elif n == 'GETUPVAL': result = upvalue(b)
        elif n == 'GETTABUP': result = field(upvalue(b), rk(c) if legacy else constant(c))
        elif n in ('GETFIELD', 'GETTABLE', 'GETI'):
            key = constant(c) if n == 'GETFIELD' else ((rk(c) if legacy else get(c)) if n == 'GETTABLE' else Value('constant', str(c), literal=c))
            result = field(get(b), key)
        elif n == 'SELF':
            result = field(get(b), rk(c))
            state[a + 1] = get(b)
        elif n == 'CLOSURE':
            child = p.children[ins.bx]
            result = Value('closure', child.name, target=child.code_offset)
        elif n == 'NEWTABLE':
            result = Value('table', p.local_name(a, ins.pc + ins.size // 4) or f'table_at_{ins.ea:X}')
        elif n in ARITHMETIC or n in ('UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT'):
            state.pop(a, None)
        elif n == 'TESTSET':
            state.pop(a, None)  # Refined separately per outgoing edge below.
        elif n in ('FORPREP', 'FORLOOP'):
            clear(a, a + 4)
        elif n == 'TFORLOOP':
            if p.version == 0x51:
                clear(a + 2, a + 3 + c)
                for i in captured:
                    state.pop(i, None)
            else:
                state.pop(a if legacy else a + 2, None)
        elif n == 'VARARG':
            count = b if legacy else c
            clear(a, p.stack if count == 0 else a + count - 1)
        elif n in ('CALL', 'TAILCALL', 'TFORCALL'):
            for i in captured:
                state.pop(i, None)
            if n == 'TFORCALL':
                start = a + (3 if legacy else 4)
                clear(start, start + c)
            else:
                clear(a, p.stack if c == 0 else a + c - 1)
                callee, arg = get(a), get(a + 1)
                if n == 'CALL' and (c == 0 or c > 1) and callee.kind == 'global' and callee.label == 'require' and isinstance(arg.literal, bytes):
                    state[a] = Value('module', text(arg.literal))
        if result is not None:
            state[a] = result
        if legacy and n in ARITHMETIC:
            for i in captured:
                state.pop(i, None)
        # Implicit calls (metamethods and close handlers) may also mutate a
        # captured register. Never turn a stale closure value into a code xref.
        if n in {'GETTABUP', 'GETTABLE', 'GETI', 'GETFIELD', 'SETTABUP',
                 'SETTABLE', 'SETI', 'SETFIELD', 'SELF', 'MMBIN', 'MMBINI',
                 'MMBINK', 'UNM', 'BNOT', 'LEN', 'CONCAT', 'LT', 'LE',
                 'EQ', 'LTI', 'LEI', 'GTI', 'GEI', 'CLOSE', 'TBC',
                 'TFORPREP', 'NEWTABLE', 'CLOSURE', 'GETGLOBAL', 'SETGLOBAL'}:
            for i in captured:
                state.pop(i, None)
        return state

    states, queue, queued = {0: entry}, deque([0]), {0}
    steps = 0
    while queue:
        pc = queue.popleft()
        queued.discard(pc)
        ins = instructions[pc]
        outgoing = transfer(ins, states[pc])
        for succ, _ in ins.successors():
            if succ not in instructions:
                continue
            edge = outgoing
            if ins.name == 'TESTSET':
                edge = dict(outgoing)
                if succ == pc + 1:
                    edge[ins.a] = reg(states[pc], ins.b, pc)
                elif ins.a in states[pc]:
                    edge[ins.a] = states[pc][ins.a]
            old = states.get(succ)
            merged = dict(edge) if old is None else {r:v for r,v in old.items() if edge.get(r) == v}
            if old is None or old != merged:
                states[succ] = merged
                if succ not in queued:
                    queue.append(succ)
                    queued.add(succ)
        steps += 1
        if steps > len(instructions) * 1024:
            # Refuse to advertise partially stabilized targets.
            return [], {}
    calls = []
    for pc, ins in instructions.items():
        if pc not in states or (ins.name not in ('CALL', 'TAILCALL', 'TFORCALL') and not (p.version == 0x51 and ins.name == 'TFORLOOP')):
            continue
        state = states[pc]
        target = reg(state, ins.a, pc)
        is_iterator = ins.name in ('TFORCALL', 'TFORLOOP')
        count = 2 if is_iterator else (ins.b - 1 if ins.b else 0)
        args = [reg(state, ins.a + i, pc).label for i in range(1, count + 1)]
        if ins.b == 0 and not is_iterator:
            args.append('...top')
        module = ''
        if target.kind == 'global' and target.label == 'require' and count >= 1:
            arg = reg(state, ins.a + 1, pc)
            if isinstance(arg.literal, bytes):
                module = text(arg.literal)
        calls.append(Call(ins.ea, p.code_offset, target.label, target.kind,
                          target.target if target.kind == 'closure' else -1, args, module))
    return calls, states

class Analysis:
    def __init__(self, chunk):
        self.chunk = chunk
        self.calls = []
        self.by_ea = {}
        self.dependencies = {}
        self.constant_uses = {}
        for p in chunk.prototypes:
            calls, _ = analyze_function(p)
            self.calls.extend(calls)
            for call in calls:
                self.by_ea[call.ea] = call
                if call.module:
                    self.dependencies.setdefault(call.module, []).append(call.ea)
            for ins in p.instructions():
                for op in ins.operands():
                    if op.kind == 'const':
                        self.constant_uses.setdefault((p.path, op.value), []).append(ins.ea)

    def call_comment(self, ea):
        call = self.by_ea.get(ea)
        if call is None:
            return ''
        return f'inferred call: {call.target}({", ".join(call.arguments)})'

    def to_dict(self):
        def encoded(value):
            if isinstance(value, bytes):
                return {'display': display(value), 'hex': value.hex()}
            # JSON has no non-finite numbers.
            if isinstance(value, float) and not __import__('math').isfinite(value):
                return repr(value)
            return value
        functions = []
        for p in self.chunk.prototypes:
            functions.append(dict(
                name=p.name, path=p.path, address=p.code_offset, end=p.code_end,
                source=text(p.source), firstline=p.firstline, lastline=p.lastline,
                parameters=p.params, vararg=bool(p.vararg), registers=p.stack,
                constants=[dict(index=i, offset=k.offset, tag=k.tag, value=encoded(k.value),
                                uses=self.constant_uses.get((p.path, i), [])) for i,k in enumerate(p.constants)],
                upvalues=[dict(name=text(u.name), instack=u.instack, index=u.index, kind=u.kind) for u in p.upvalues],
                locals=[dict(name=text(v.name), startpc=v.startpc, endpc=v.endpc) for v in p.locals],
                instructions=[dict(address=i.ea, pc=i.pc, size=i.size, opcode=i.name, text=i.render(),
                                   line=p.lines[i.pc] if p.lines else None,
                                   successors=[p.code_offset + pc * 4 for pc, _ in i.successors()])
                              for i in p.instructions()]))
        return dict(schema='lua_re.analysis.v1', lua_version=self.chunk.version_string, variant=self.chunk.variant,
                    sha256=__import__('hashlib').sha256(self.chunk.data).hexdigest(),
                    functions=functions, dependencies=self.dependencies,
                    calls=[vars(c) for c in self.calls])

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=True, allow_nan=False) + '\n'

    def callgraph_dot(self):
        lines = ['digraph lua_re {', '  rankdir=LR;', '  node [shape=box];']
        for p in self.chunk.prototypes:
            lines.append(f'  f{p.code_offset} [label={json.dumps(p.name)}];')
        seen = set()
        for c in self.calls:
            if c.callee >= 0:
                dest = f'f{c.callee}'
            else:
                dest = 'external_' + __import__('hashlib').sha256(c.target.encode()).hexdigest()[:16]
                if dest not in seen:
                    lines.append(f'  {dest} [label={json.dumps(c.target)}, style=dashed];')
                    seen.add(dest)
            lines.append(f'  f{c.function} -> {dest} [label="0x{c.ea:X}"];')
        return '\n'.join(lines + ['}']) + '\n'
