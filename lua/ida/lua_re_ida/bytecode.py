"""Non-executing Lua RE reader. New lua_re extension, 2026-09-15, AGPL-3.0.
Format authority: Lua's lundump.c, lopcodes.h, lvm.c and ldebug.c.
All addresses are offsets in the original input; binary strings remain bytes.
"""
from dataclasses import dataclass, field
import json
import struct

SIGNATURE = b'\x1bLua\x54\x00\x19\x93\r\n\x1a\n'
OPNAMES = '''MOVE LOADI LOADF LOADK LOADKX LOADFALSE LFALSESKIP LOADTRUE LOADNIL
GETUPVAL SETUPVAL GETTABUP GETTABLE GETI GETFIELD SETTABUP SETTABLE SETI
SETFIELD NEWTABLE SELF ADDI ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK
BXORK SHRI SHLI ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR MMBIN
MMBINI MMBINK UNM BNOT NOT LEN CONCAT CLOSE TBC JMP EQ LT LE EQK EQI LTI LEI
GTI GEI TEST TESTSET CALL TAILCALL RETURN RETURN0 RETURN1 FORLOOP FORPREP
TFORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG VARARGPREP EXTRAARG'''.split()
ARITHMETIC = set(OPNAMES[21:46])
CONDITIONAL = set(OPNAMES[57:68])
TERMINATORS = {'TAILCALL', 'RETURN', 'RETURN0', 'RETURN1', 'EXTRAARG'}

class ChunkError(ValueError):
    pass

def display(value):
    if isinstance(value, bytes):
        return json.dumps(value.decode('latin1'), ensure_ascii=True)
    if value is None:
        return 'nil'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return repr(value)

def text(value):
    decoded = value.decode('utf-8', 'backslashreplace') if value else ''
    return ''.join(c if c.isprintable() else c.encode('unicode_escape').decode('ascii') for c in decoded)

@dataclass
class Constant:
    tag: int
    value: object
    offset: int
    payload: int
    end: int

@dataclass
class Upvalue:
    instack: int
    index: int
    kind: int
    offset: int
    name: bytes = b''

@dataclass
class Local:
    name: bytes
    startpc: int
    endpc: int

@dataclass
class Prototype:
    path: str
    offset: int
    source: bytes
    firstline: int
    lastline: int
    params: int
    vararg: int
    stack: int
    code_offset: int
    words: list
    constants: list = field(default_factory=list)
    upvalues: list = field(default_factory=list)
    children: list = field(default_factory=list)
    lines: list = field(default_factory=list)
    locals: list = field(default_factory=list)
    end: int = 0
    name: str = ''
    version: int = 0x54

    @property
    def code_end(self):
        return self.code_offset + 4 * len(self.words)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def instruction(self, pc):
        if self.version < 0x54:
            from .legacy import LegacyInstruction
            return LegacyInstruction(self.words[pc], pc, self)
        return Instruction(self.words[pc], pc, self)

    def instructions(self):
        pc = 0
        while pc < len(self.words):
            ins = self.instruction(pc)
            yield ins
            pc += ins.size // 4

    def local_name(self, register, pc):
        active = [v for v in self.locals if v.startpc <= pc < v.endpc]
        return text(active[register].name) if register < len(active) else ''

@dataclass
class Chunk:
    data: bytes
    variant: str
    endian: str
    integer_size: int
    number_size: int
    header_size: int
    main_upvalues: int
    root: Prototype
    version: int = 0x54

    @property
    def version_string(self):
        return f'{self.version >> 4}.{self.version & 15}'

    @property
    def prototypes(self):
        return list(self.root.walk())

class Reader:
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0
        self.endian = '<'
        self.integer_size = self.number_size = 8
        self.function_count = 0

    def error(self, message):
        raise ChunkError(f'{message} at file offset {self.pos:#x}')

    def read(self, size):
        if size < 0 or size > len(self.data) - self.pos:
            self.error(f'truncated chunk (need {size} bytes)')
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def byte(self):
        return self.read(1)[0]

    def uint(self, limit=(1 << 31) - 1):
        value = 0
        for _ in range(10):
            b = self.byte()
            value = (value << 7) | (b & 127)
            if value > limit:
                self.error('variable integer overflow')
            if b & 128:
                return value
        self.error('unterminated variable integer')

    def count(self, width=1):
        count = self.uint()
        if count > (len(self.data) - self.pos) // width:
            self.error('count exceeds remaining file')
        return count

    def string(self):
        size = self.uint((1 << 64) - 1)
        start = self.pos
        return (None if size == 0 else self.read(size - 1)), start

    def number(self, integer=False):
        size = self.integer_size if integer else self.number_size
        fmt = ({4: 'i', 8: 'q'} if integer else {4: 'f', 8: 'd'})[size]
        return struct.unpack(self.endian + fmt, self.read(size))[0]

    def proto(self, path='0', parent_source=b'', depth=0):
        if depth > 150 or self.function_count >= 100000:
            self.error('prototype nesting/count limit exceeded')
        self.function_count += 1
        offset = self.pos
        source, _ = self.string()
        first, last = self.uint(), self.uint()
        params, vararg, stack = self.byte(), self.byte(), self.byte()
        if stack < 2 or params > stack or vararg > 1:
            self.error('invalid prototype register/parameter fields')
        count = self.count(4)
        if not count:
            self.error('empty instruction array')
        code_offset = self.pos
        words = list(struct.unpack(self.endian + f'{count}I', self.read(count * 4)))
        p = Prototype(path, offset, parent_source if source is None else source,
                      first, last, params, vararg, stack, code_offset, words)
        for _ in range(self.count()):
            offset, tag = self.pos, self.byte()
            payload = self.pos
            if tag == 0:
                value = None
            elif tag in (1, 17):
                value = tag == 17
            elif tag in (3, 19):
                value = self.number(integer=tag == 3)
            elif tag in (4, 20):
                value, payload = self.string()
                if value is None:
                    self.error('null string constant')
            else:
                self.error(f'unknown constant tag {tag}')
            p.constants.append(Constant(tag, value, offset, payload, self.pos))
        for _ in range(self.count(3)):
            offset = self.pos
            instack, index, kind = self.byte(), self.byte(), self.byte()
            if instack > 1 or kind > 3:
                self.error('invalid upvalue descriptor')
            p.upvalues.append(Upvalue(instack, index, kind, offset))
        for i in range(self.count()):
            p.children.append(self.proto(f'{path}_{i}', p.source, depth + 1))
        nlines = self.count()
        if nlines not in (0, count):
            self.error('line-info length does not match code')
        deltas = list(struct.unpack(f'{nlines}b', self.read(nlines)))
        anchors, previous_pc = {}, -1
        for _ in range(self.count(2)):
            pc, line = self.uint(), self.uint()
            if pc <= previous_pc or pc >= count or not deltas or deltas[pc] != -128:
                self.error('invalid absolute line-info anchor')
            anchors[pc] = line
            previous_pc = pc
        line = first
        for pc, delta in enumerate(deltas):
            if delta == -128:
                if pc not in anchors:
                    self.error('missing absolute line-info anchor')
                line = anchors[pc]
            else:
                line += delta
            p.lines.append(line)
        for _ in range(self.count(3)):
            name, _ = self.string()
            start, end = self.uint(), self.uint()
            if not 0 <= start <= end <= count:
                self.error('invalid local-variable lifetime')
            p.locals.append(Local(name or b'', start, end))
        names = self.count()
        if names not in (0, len(p.upvalues)):
            self.error('upvalue name count mismatch')
        for i in range(names):
            p.upvalues[i].name = self.string()[0] or b''
        p.end = self.pos
        p.name = 'lua_main' if path == '0' else f'lua_{path}_line_{first}'
        return p

def parse(data, allow_compact=True):
    if len(data) > 256 * 1024 * 1024:
        raise ChunkError('chunk exceeds 256 MiB analysis limit')
    if len(data) >= 6 and bytes(data[:4]) == b'\x1bLua' and data[4] in (0x51, 0x52, 0x53):
        from .legacy import parse_legacy
        return parse_legacy(data)
    r = Reader(data)
    if r.read(12) != SIGNATURE:
        raise ChunkError('not a Lua RE format-0 chunk')
    instruction_size, r.integer_size, r.number_size = r.byte(), r.byte(), r.byte()
    if instruction_size != 4 or r.integer_size not in (4, 8) or r.number_size not in (4, 8):
        r.error('unsupported instruction/integer/number size')
    variant = None
    for endian in ('<', '>'):
        integer = (0x5678).to_bytes(r.integer_size, 'little' if endian == '<' else 'big')
        number = struct.pack(endian + ('f' if r.number_size == 4 else 'd'), 370.5)
        if r.data[15:15 + len(integer) + len(number)] == integer + number:
            r.endian = endian
            r.read(len(integer) + len(number))
            variant = 'standard'
            break
    if variant is None:
        # Observed GL.iNet format: numeric sentinels replaced with 00.
        # Do not guess other flags or layouts; validate the entire chunk below.
        if not allow_compact or r.byte() != 0 or (r.integer_size, r.number_size) != (8, 8):
            r.error('invalid numeric sentinels / unsupported header variant')
        r.endian, variant = '<', 'glinet-compact'
    header_size = r.pos
    nup = r.byte()
    root = r.proto()
    if len(root.upvalues) != nup:
        r.error('main closure upvalue count mismatch')
    if r.pos != len(r.data):
        r.error(f'{len(r.data) - r.pos} trailing bytes')
    chunk = Chunk(r.data, variant, r.endian, r.integer_size, r.number_size, header_size, nup, root)
    validate(chunk)
    infer_names(root)
    return chunk

@dataclass(frozen=True)
class Operand:
    kind: str
    value: int

class Instruction:
    def __init__(self, word, pc, proto):
        self.word, self.pc, self.proto = word, pc, proto
        self.opcode = word & 127
        self.name = OPNAMES[self.opcode] if self.opcode < len(OPNAMES) else 'INVALID'
        self.a = (word >> 7) & 255
        self.k = (word >> 15) & 1
        self.b = (word >> 16) & 255
        self.c = (word >> 24) & 255
        self.bx = word >> 15
        self.sbx = self.bx - 65535
        self.ax = word >> 7
        self.sj = self.ax - 16777215
        self.sb, self.sc = self.b - 127, self.c - 127
        self.ea = proto.code_offset + 4 * pc

    @property
    def has_extra(self):
        return self.name in ('LOADKX', 'NEWTABLE') or (self.name == 'SETLIST' and self.k)

    @property
    def extra(self):
        if hasattr(self, "extra_override"):
            return self.extra_override
        if self.has_extra and self.pc + 1 < len(self.proto.words):
            return self.proto.words[self.pc + 1] >> 7
        return 0

    @property
    def size(self):
        return 8 if self.has_extra else 4

    def operands(self):
        n, a, b, c, k = self.name, self.a, self.b, self.c, self.k
        R = lambda x: Operand('reg', x)
        I = lambda x: Operand('imm', x)
        K = lambda x: Operand('const', x)
        U = lambda x: Operand('upval', x)
        J = lambda pc: Operand('jump', self.proto.code_offset + 4 * pc)
        rk = lambda x: K(x) if k else R(x)
        if n in ('MOVE', 'UNM', 'BNOT', 'NOT', 'LEN'): return [R(a), R(b)]
        if n in ('LOADI', 'LOADF'): return [R(a), I(self.sbx)]
        if n in ('LOADK', 'LOADKX'): return [R(a), K(self.extra if n == 'LOADKX' else self.bx)]
        if n in ('LOADFALSE', 'LFALSESKIP', 'LOADTRUE', 'CLOSE', 'TBC', 'RETURN1', 'VARARGPREP'): return [R(a)]
        if n in ('LOADNIL', 'CONCAT'): return [R(a), I(b)]
        if n in ('GETUPVAL', 'SETUPVAL'): return [R(a), U(b)]
        if n == 'GETTABUP': return [R(a), U(b), K(c)]
        if n == 'GETTABLE': return [R(a), R(b), R(c)]
        if n == 'GETI': return [R(a), R(b), I(c)]
        if n == 'GETFIELD': return [R(a), R(b), K(c)]
        if n == 'SETTABUP': return [U(a), K(b), rk(c)]
        if n == 'SETTABLE': return [R(a), R(b), rk(c)]
        if n == 'SETI': return [R(a), I(b), rk(c)]
        if n == 'SETFIELD': return [R(a), K(b), rk(c)]
        if n == 'NEWTABLE': return [R(a), I(b), I(c + (self.extra << 8) if k else c)]
        if n == 'SELF': return [R(a), R(b), rk(c)]
        if n in ('ADDI', 'SHRI', 'SHLI'): return [R(a), R(b), I(self.sc)]
        if n in OPNAMES[22:32]: return [R(a), R(b), K(c)]
        if n in OPNAMES[34:46]: return [R(a), R(b), R(c)]
        if n == 'MMBIN': return [R(a), R(b), I(c)]
        if n == 'MMBINI': return [R(a), I(self.sb), I(c), I(k)]
        if n == 'MMBINK': return [R(a), K(b), I(c), I(k)]
        if n == 'JMP': return [J(self.pc + 1 + self.sj)]
        if n in ('EQ', 'LT', 'LE', 'TESTSET'): return [R(a), R(b), I(k)]
        if n == 'EQK': return [R(a), K(b), I(k)]
        if n in ('EQI', 'LTI', 'LEI', 'GTI', 'GEI'): return [R(a), I(self.sb), I(k)]
        if n == 'TEST': return [R(a), I(k)]
        if n == 'CALL': return [R(a), I(b), I(c)]
        if n in ('TAILCALL', 'RETURN'): return [R(a), I(b), I(c), I(k)]
        if n == 'RETURN0': return []
        if n in ('FORLOOP', 'TFORLOOP'): return [R(a), J(self.pc + 1 - self.bx)]
        if n == 'FORPREP': return [R(a), J(self.pc + self.bx + 2)]
        if n == 'TFORPREP': return [R(a), J(self.pc + self.bx + 1)]
        if n in ('TFORCALL', 'VARARG'): return [R(a), I(c)]
        if n == 'SETLIST': return [R(a), I(b), I(c + (self.extra << 8) if k else c)]
        if n == 'CLOSURE': return [R(a), Operand('proto', self.bx)]
        if n == 'EXTRAARG': return [I(self.ax)]
        return []

    def successors(self):
        n, pc = self.name, self.pc
        if n in TERMINATORS: return []
        if n == 'JMP': return [(pc + 1 + self.sj, 'jump')]
        if n == 'LFALSESKIP': return [(pc + 2, 'jump')]
        if n == 'TFORPREP': return [(pc + 1 + self.bx, 'jump')]
        if n == 'FORPREP': return [(pc + 1, 'flow'), (pc + 2 + self.bx, 'jump')]
        if n in ('FORLOOP', 'TFORLOOP'): return [(pc + 1, 'flow'), (pc + 1 - self.bx, 'jump')]
        if n in CONDITIONAL or n in ARITHMETIC:
            return [(pc + 1, 'flow'), (pc + 2, 'jump')]
        return [(pc + self.size // 4, 'flow')]

    def format_operand(self, op):
        p, i = self.proto, op.value
        if op.kind == 'reg': return f'R{i}'
        if op.kind == 'imm': return str(i)
        if op.kind == 'const': return f'K{i}({display(p.constants[i].value)})'
        if op.kind == 'upval': return f'U{i}({text(p.upvalues[i].name) or "?"})'
        if op.kind == 'proto': return p.children[i].name
        return f'loc_{i:08X}'

    def render(self):
        return self.name.ljust(12) + ', '.join(self.format_operand(o) for o in self.operands())

    def comment(self):
        p, n = self.proto, self.name
        comments = []
        if p.lines: comments.append(f'line {p.lines[self.pc]}')
        for op in self.operands():
            if op.kind == 'const': comments.append(f'K{op.value} = {display(p.constants[op.value].value)}')
            elif op.kind == 'upval': comments.append(f'U{op.value} = {text(p.upvalues[op.value].name) or "unnamed"}')
            elif op.kind == 'reg':
                name = p.local_name(op.value, self.pc)
                if name: comments.append(f'R{op.value} = {name}')
        if n == 'CALL':
            comments.append(f'arguments={self.b - 1 if self.b else "top"}; results={self.c - 1 if self.c else "all"}')
        if n == 'TAILCALL':
            comments.append(f'tail call; arguments={self.b - 1 if self.b else "top"}')
        if n == 'RETURN': comments.append(f'return {self.b - 1 if self.b else "top"} values; close={self.k}')
        if n in CONDITIONAL: comments.append(f'conditional skip; k={self.k}')
        if n in ARITHMETIC: comments.append('success skips following metamethod instruction')
        if n == 'NEWTABLE': comments.append(f'hash slots={0 if not self.b else 1 << (self.b - 1)}')
        if self.has_extra: comments.append(f'EXTRAARG {self.extra} at {self.ea + 4:#x} (included)')
        return '; '.join(dict.fromkeys(comments))

def validate(chunk):
    for p in chunk.prototypes:
        for child in p.children:
            for u in child.upvalues:
                limit = p.stack if u.instack else len(p.upvalues)
                if u.index >= limit:
                    raise ChunkError(f'child {child.path}: invalid parent upvalue reference {u.index}')
        payloads = set()
        for pc, word in enumerate(p.words):
            ins = p.instruction(pc)
            if ins.name == 'INVALID':
                raise ChunkError(f'unknown opcode {ins.opcode} at {ins.ea:#x}')
            if ins.has_extra:
                if pc + 1 >= len(p.words) or (p.words[pc + 1] & 127) != OPNAMES.index('EXTRAARG'):
                    raise ChunkError(f'{ins.name} missing EXTRAARG at {ins.ea:#x}')
                payloads.add(pc + 1)
            for op in ins.operands():
                limits = {'reg': p.stack, 'const': len(p.constants), 'upval': len(p.upvalues), 'proto': len(p.children)}
                if op.kind in limits and not 0 <= op.value < limits[op.kind] + (ins.name == 'CLOSE' and op.kind == 'reg'):
                    raise ChunkError(f'{ins.name}: invalid {op.kind} {op.value} at {ins.ea:#x}')
            n, a, b, c = ins.name, ins.a, ins.b, ins.c
            last = a
            if n == 'LOADNIL': last = a + b
            elif n == 'SELF': last = a + 1
            elif n == 'CONCAT' and b: last = a + b - 1
            elif n in ('CALL', 'TAILCALL'):
                last = max(a, a + b - 1 if b else a, a + c - 2 if n == 'CALL' and c else a)
            elif n == 'RETURN' and b > 1: last = a + b - 2
            elif n in ('FORLOOP', 'FORPREP', 'TFORPREP'): last = a + 3
            elif n == 'TFORLOOP': last = a + 4
            elif n == 'TFORCALL': last = a + 3 + max(c, 1)
            elif n == 'SETLIST' and b: last = a + b
            elif n == 'VARARG' and c > 1: last = a + c - 2
            if n in ('LOADNIL', 'SELF', 'CONCAT', 'CALL', 'TAILCALL', 'RETURN',
                     'FORLOOP', 'FORPREP', 'TFORPREP', 'TFORLOOP', 'TFORCALL',
                     'SETLIST', 'VARARG') and last >= p.stack:
                raise ChunkError(f'{n}: register span exceeds stack at {ins.ea:#x}')
        for ins in p.instructions():
            for pc, _ in ins.successors():
                if not 0 <= pc < len(p.words) or pc in payloads:
                    raise ChunkError(f'{ins.name}: invalid destination PC {pc} at {ins.ea:#x}')
            if ins.name == 'EXTRAARG':
                raise ChunkError(f'orphan EXTRAARG at {ins.ea:#x}')
            if ins.name in ARITHMETIC and p.instruction(ins.pc + 1).name not in ('MMBIN', 'MMBINI', 'MMBINK'):
                raise ChunkError(f'missing arithmetic fallback at {ins.ea:#x}')

def infer_names(p):
    for ins in p.instructions():
        if ins.name != 'CLOSURE': continue
        child = p.children[ins.bx]
        name = p.local_name(ins.a, ins.pc + 1)
        if not name and ins.pc + 1 < len(p.words):
            nxt = p.instruction(ins.pc + 1)
            if nxt.name in ('SETFIELD', 'SETTABUP') and not nxt.k and nxt.c == ins.a:
                value = p.constants[nxt.b].value
                if isinstance(value, bytes): name = text(value)
        if name and not name.startswith('('):
            safe = ''.join(c if c.isascii() and (c.isalnum() or c == '_') else '_' for c in name)
            child.name = f'lua_{safe}_{child.path}'
    for child in p.children: infer_names(child)

def listing(chunk):
    lines = [f'Lua {chunk.version_string} / {chunk.variant} / {"little" if chunk.endian == "<" else "big"} endian',
             'Addresses are original file offsets; EXTRAARG payloads are folded into their owner.']
    for p in chunk.prototypes:
        lines += ['', f'{p.name} at {p.code_offset:#x}: {text(p.source)}:{p.firstline}-{p.lastline}',
                  f'  {p.params} parameters, vararg={p.vararg}, {p.stack} registers, {len(p.words)} words']
        for ins in p.instructions():
            lines.append(f'{ins.ea:08X}  {ins.pc + 1:5}  {ins.render()}  ; {ins.comment()}')
    return '\n'.join(lines) + '\n'
