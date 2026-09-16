"""Lua 5.1–5.3 readers and instruction semantics. AGPL-3.0.

Format and opcode behavior are based on each official release's lundump.c,
lopcodes.h and lvm.c. Addresses always refer to original file bytes.
"""
import struct
from .bytecode import (Reader, Chunk, Prototype, Constant, Upvalue, Local,
                       ChunkError, Instruction, Operand, OPNAMES, text)

OPCODES = {
    0x51: 'MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORLOOP SETLIST CLOSE CLOSURE VARARG'.split(),
    0x52: 'MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG'.split(),
    0x53: 'MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG'.split(),
}
PROCESSOR_OPNAMES = OPNAMES + ['LOADBOOL', 'GETGLOBAL', 'SETGLOBAL']
BINARY = set('ADD SUB MUL DIV IDIV MOD POW BAND BOR BXOR SHL SHR'.split())
COMPARE = {'EQ', 'LT', 'LE', 'TEST', 'TESTSET'}


class LegacyReader(Reader):
    def uint(self, limit=(1 << 31) - 1):
        n = int.from_bytes(self.read(self.int_size),
                           'little' if self.endian == '<' else 'big', signed=True)
        if not 0 <= n <= limit:
            self.error('invalid integer/count')
        return n

    def string(self):
        def size_t():
            return int.from_bytes(self.read(self.size_t),
                                  'little' if self.endian == '<' else 'big')
        size = self.byte() if self.version == 0x53 else size_t()
        if self.version == 0x53 and size == 255:
            size = size_t()
        payload = self.pos
        if size == 0:
            return None, payload
        value = self.read(size - 1)
        if self.version < 0x53 and self.byte() != 0:
            self.error('missing string terminator')
        return value, payload

    def proto(self, path='0', parent_source=b'', depth=0):
        if depth > 150 or self.function_count >= 100000:
            self.error('prototype nesting/count limit exceeded')
        self.function_count += 1
        offset = self.pos
        source = None if self.version == 0x52 else self.string()[0]
        first, last = self.uint(), self.uint()
        upvalue_offset = self.pos
        nup = self.byte() if self.version == 0x51 else 0
        params, vararg, stack = self.byte(), self.byte(), self.byte()
        if stack < 2 or params > stack or vararg > (7 if self.version == 0x51 else 1):
            self.error('invalid prototype register/parameter fields')
        nwords = self.count(4)
        if not nwords:
            self.error('empty instruction array')
        code = self.pos
        words = list(struct.unpack(self.endian + f'{nwords}I', self.read(nwords * 4)))
        p = Prototype(path, offset, parent_source if source is None else source,
                      first, last, params, vararg, stack, code, words, version=self.version)
        p.source_inherited = source is None
        for _ in range(self.count()):
            pos, tag = self.pos, self.byte()
            payload = self.pos
            # Normalize numeric and boolean tags to the common model.
            if tag == 0:
                value, normalized = None, 0
            elif tag == 1:
                boolean = self.byte()
                if boolean > 1:
                    self.error('invalid boolean')
                value, normalized = bool(boolean), 17 if boolean else 1
            elif tag == 3:
                value = self.number(self.integral)
                normalized = 3 if self.integral else 19
            elif self.lnum and tag in (9, 254):
                # LNUM uses a separate signed lua_Integer payload. Upstream
                # LNUM uses -2 (serialized as 254); OpenWrt/vendor builds also
                # use the documented alternative tag 9. Never infer this from
                # an unknown constant in a stock chunk.
                value, normalized = self.number(True), 3
            elif tag == 19 and self.version == 0x53:
                value, normalized = self.number(True), 3
            elif tag == 4 or (tag == 20 and self.version == 0x53):
                value, payload = self.string()
                normalized = tag
                if value is None:
                    self.error('null string constant')
            else:
                self.error(f'unknown constant tag {tag}')
            p.constants.append(Constant(normalized, value, pos, payload, self.pos))

        def children():
            for i in range(self.count()):
                p.children.append(self.proto(f'{path}_{i}', p.source, depth + 1))

        def upvalues():
            for _ in range(self.count(2)):
                pos, instack, index = self.pos, self.byte(), self.byte()
                if instack > 1:
                    self.error('invalid upvalue descriptor')
                p.upvalues.append(Upvalue(instack, index, 0, pos))

        if self.version == 0x53:
            upvalues()
            children()
        else:
            children()
            if self.version == 0x52:
                upvalues()
            else:
                p.upvalues = [Upvalue(0, 0, 0, upvalue_offset) for _ in range(nup)]
        if self.version == 0x52:
            source, _ = self.string()
            p.source, p.source_inherited = source or parent_source, source is None
            def inherit(child, parent):
                if child.source_inherited:
                    child.source = parent
                for sub in child.children:
                    inherit(sub, child.source)
            for child in p.children:
                inherit(child, p.source)
        nlines = self.count(self.int_size)
        if nlines not in (0, nwords):
            self.error('line-info length does not match code')
        p.lines = [self.uint() for _ in range(nlines)]
        for _ in range(self.count()):
            name, _ = self.string()
            start, end = self.uint(), self.uint()
            if not 0 <= start <= end <= nwords:
                self.error('invalid local-variable lifetime')
            p.locals.append(Local(name or b'', start, end))
        names = self.count()
        if names not in (0, len(p.upvalues)):
            self.error('upvalue name count mismatch')
        for i in range(names):
            pos = self.pos
            p.upvalues[i].name = self.string()[0] or b''
            if self.version == 0x51:
                p.upvalues[i].offset = pos
        p.end = self.pos
        p.name = 'lua_main' if path == '0' else f'lua_{path}_line_{first}'
        return p


def parse_legacy(data):
    r = LegacyReader(data)
    if r.read(4) != b'\x1bLua':
        r.error('not a Lua bytecode chunk')
    r.version, fmt = r.byte(), r.byte()
    if r.version not in OPCODES or fmt != 0:
        r.error('unsupported Lua version or format')
    r.integral = r.lnum = False
    variant = 'standard'
    if r.version < 0x53:
        endian = r.byte()
        if endian not in (0, 1):
            r.error('invalid endianness')
        r.endian = '<' if endian else '>'
        r.int_size, r.size_t, iw, r.number_size, integral = [r.byte() for _ in range(5)]
        if integral in (2, 4, 8):
            # LNUM replaces the stock integrality flag with sizeof(lua_Integer).
            # lua_Number remains floating point and has its own width.
            r.lnum, r.integer_size = True, integral
            variant = 'lnum'
        elif integral in (0, 1):
            r.integral = bool(integral)
            r.integer_size = r.number_size
        else:
            r.error('invalid number representation')
        if r.version == 0x52 and r.read(6) != b'\x19\x93\r\n\x1a\n':
            r.error('invalid Lua header tail')
    else:
        if r.read(6) != b'\x19\x93\r\n\x1a\n':
            r.error('invalid Lua header data')
        r.int_size, r.size_t, iw, r.integer_size, r.number_size = [r.byte() for _ in range(5)]
    integer_widths = (2, 4, 8) if r.lnum else (4, 8)
    if (iw != 4 or r.integer_size not in integer_widths
            or any(n not in (4, 8) for n in (r.int_size, r.size_t, r.number_size))):
        r.error('unsupported integer, size_t, instruction or number width')
    if r.version == 0x53:
        check = r.read(r.integer_size + r.number_size)
        for endian in '<>':
            integer = struct.pack(endian + ('i' if r.integer_size == 4 else 'q'), 0x5678)
            number = struct.pack(endian + ('f' if r.number_size == 4 else 'd'), 370.5)
            if check == integer + number:
                r.endian = endian
                break
        else:
            r.error('invalid numeric sentinels')
    header_size = r.pos
    nup = r.byte() if r.version == 0x53 else None
    root = r.proto()
    if nup is not None and nup != len(root.upvalues):
        r.error('main closure upvalue count mismatch')
    if r.pos != len(r.data):
        r.error('trailing bytes')
    chunk = Chunk(r.data, variant, r.endian, r.integer_size, r.number_size,
                  header_size, len(root.upvalues), root, version=r.version)
    validate_legacy(chunk)
    infer_legacy_names(root)
    return chunk


class LegacyInstruction(Instruction):
    def __init__(self, word, pc, proto):
        self.word, self.pc, self.proto = word, pc, proto
        self.raw_opcode = word & 63
        names = OPCODES[proto.version]
        self.name = names[self.raw_opcode] if self.raw_opcode < len(names) else 'INVALID'
        self.opcode = PROCESSOR_OPNAMES.index(self.name) if self.name != 'INVALID' else len(PROCESSOR_OPNAMES)
        self.a, self.b, self.c = word >> 6 & 255, word >> 23 & 511, word >> 14 & 511
        self.bx, self.ax = word >> 14, word >> 6
        self.sbx = self.bx - 131071
        self.k = int(bool(self.c & 256))
        self.ea = proto.code_offset + pc * 4

    @property
    def has_extra(self):
        return self.name == 'LOADKX' or (self.name == 'SETLIST' and self.c == 0)

    @property
    def extra(self):
        raw = self.proto.words[self.pc + 1] if self.pc + 1 < len(self.proto.words) else 0
        return raw if self.proto.version == 0x51 else raw >> 6

    @property
    def size(self):
        if self.name == 'CLOSURE' and self.proto.version == 0x51 and self.bx < len(self.proto.children):
            return 4 * (1 + len(self.proto.children[self.bx].upvalues))
        return 8 if self.has_extra else 4

    def operands(self):
        n, a, b, c = self.name, self.a, self.b, self.c
        R = lambda x: Operand('reg', x)
        I = lambda x: Operand('imm', x)
        K = lambda x: Operand('const', x)
        U = lambda x: Operand('upval', x)
        RK = lambda x: K(x & 255) if x & 256 else R(x)
        J = lambda: Operand('jump', self.proto.code_offset + 4 * (self.pc + 1 + self.sbx))
        if n in ('MOVE', 'UNM', 'BNOT', 'NOT', 'LEN'): return [R(a), R(b)]
        if n in ('LOADK', 'LOADKX'): return [R(a), K(self.extra if n == 'LOADKX' else self.bx)]
        if n == 'LOADBOOL': return [R(a), I(b), I(c)]
        if n == 'LOADNIL': return [R(a), I(b)]
        if n in ('GETGLOBAL', 'SETGLOBAL'): return [R(a), K(self.bx)]
        if n in ('GETUPVAL', 'SETUPVAL'): return [R(a), U(b)]
        if n == 'GETTABUP': return [R(a), U(b), RK(c)]
        if n == 'GETTABLE': return [R(a), R(b), RK(c)]
        if n == 'SETTABUP': return [U(a), RK(b), RK(c)]
        if n == 'SETTABLE': return [R(a), RK(b), RK(c)]
        if n == 'NEWTABLE': return [R(a), I(b), I(c)]
        if n == 'SELF': return [R(a), R(b), RK(c)]
        if n in BINARY: return [R(a), RK(b), RK(c)]
        if n == 'CONCAT': return [R(a), R(b), R(c)]
        if n == 'JMP': return [J()] if self.proto.version == 0x51 else [I(a), J()]
        if n in ('EQ', 'LT', 'LE'): return [I(a), RK(b), RK(c)]
        if n == 'TEST': return [R(a), I(c)]
        if n == 'TESTSET': return [R(a), R(b), I(c)]
        if n in ('CALL', 'TAILCALL'): return [R(a), I(b), I(c)]
        if n == 'RETURN': return [R(a), I(b)]
        if n in ('FORLOOP', 'FORPREP'): return [R(a), J()]
        if n == 'TFORLOOP':
            return [R(a), I(c)] if self.proto.version == 0x51 else [R(a), J()]
        if n == 'TFORCALL': return [R(a), I(c)]
        if n == 'SETLIST': return [R(a), I(b), I(self.extra if c == 0 else c)]
        if n == 'CLOSE': return [R(a)]
        if n == 'CLOSURE': return [R(a), Operand('proto', self.bx)]
        if n == 'VARARG': return [R(a), I(b)]
        if n == 'EXTRAARG': return [I(self.ax)]
        return []

    def successors(self):
        n, pc = self.name, self.pc
        after = pc + self.size // 4
        if n in ('RETURN', 'TAILCALL'): return []
        if n in ('JMP', 'FORPREP'): return [(pc + 1 + self.sbx, 'jump')]
        if n == 'FORLOOP' or (n == 'TFORLOOP' and self.proto.version != 0x51):
            return [(after, 'flow'), (pc + 1 + self.sbx, 'jump')]
        if n in COMPARE or (n == 'TFORLOOP' and self.proto.version == 0x51):
            return [(after, 'flow'), (pc + 2, 'jump')]
        if n == 'LOADBOOL' and self.c: return [(pc + 2, 'jump')]
        return [(after, 'flow')]

    def comment(self):
        comments = [c for c in super().comment().split('; ') if not c.startswith(
            ('success skips', 'hash slots=', 'conditional skip', 'return '))]
        if self.name in COMPARE:
            condition = self.a if self.name in ('EQ', 'LT', 'LE') else self.c
            comments.append(f'conditional skip; expected={condition}')
        if self.name == 'RETURN':
            comments.append(f'return {self.b - 1 if self.b else "top"} values')
        if self.name == 'NEWTABLE':
            fb = lambda x: x if x < 8 else ((x & 7) + 8) << ((x >> 3) - 1)
            comments.append(f'array slots={fb(self.b)}; hash slots={fb(self.c)}')
        if self.name == 'CLOSURE' and self.proto.version == 0x51:
            for index, pc in enumerate(range(self.pc + 1, self.pc + self.size // 4)):
                binding = self.proto.instruction(pc)
                comments.append(f'child U{index} <- {"R" if binding.name == "MOVE" else "U"}{binding.b}')
        return '; '.join(filter(None, comments))


def validate_legacy(chunk):
    for p in chunk.prototypes:
        if chunk.version != 0x51:
            for child in p.children:
                for u in child.upvalues:
                    if u.index >= (p.stack if u.instack else len(p.upvalues)):
                        raise ChunkError(f'invalid parent upvalue in {child.path}')
        payloads = set()
        for ins in p.instructions():
            if ins.name == 'INVALID':
                raise ChunkError(f'unknown opcode at {ins.ea:#x}')
            if ins.pc + ins.size // 4 > len(p.words):
                raise ChunkError(f'truncated instruction payload at {ins.ea:#x}')
            for pc in range(ins.pc + 1, ins.pc + ins.size // 4):
                payloads.add(pc)
                extra = p.instruction(pc)
                if ins.name == 'CLOSURE':
                    if extra.name not in ('MOVE', 'GETUPVAL'):
                        raise ChunkError(f'invalid Lua 5.1 closure binding at {extra.ea:#x}')
                    limit = p.stack if extra.name == 'MOVE' else len(p.upvalues)
                    if extra.b >= limit:
                        raise ChunkError(f'invalid closure binding index at {extra.ea:#x}')
                elif p.version != 0x51 and extra.name != 'EXTRAARG':
                    raise ChunkError(f'missing EXTRAARG at {ins.ea:#x}')
            for op in ins.operands():
                limit = {'reg': p.stack, 'const': len(p.constants),
                         'upval': len(p.upvalues), 'proto': len(p.children)}.get(op.kind)
                if limit is not None and not 0 <= op.value < limit + int(ins.name == 'CLOSE'):
                    raise ChunkError(f'{ins.name}: invalid {op.kind} at {ins.ea:#x}')
            n, a, b, c = ins.name, ins.a, ins.b, ins.c
            last = -1
            if n == 'LOADNIL': last = b if p.version == 0x51 else a + b
            elif n == 'SELF': last = a + 1
            elif n in ('FORPREP', 'FORLOOP'): last = a + 3
            elif n == 'SETLIST' and b: last = a + b
            elif n == 'CALL': last = max(a + b - 1 if b else a, a + c - 2 if c else a)
            elif n == 'TAILCALL' and b: last = a + b - 1
            elif n in ('VARARG', 'RETURN') and b > 1: last = a + b - 2
            elif n == 'TFORCALL' or (n == 'TFORLOOP' and p.version == 0x51): last = a + 2 + c
            elif n == 'TFORLOOP': last = a + 1
            if last >= p.stack:
                raise ChunkError(f'{n}: register span exceeds stack at {ins.ea:#x}')
        for ins in p.instructions():
            if ins.name == 'EXTRAARG':
                raise ChunkError(f'orphan EXTRAARG at {ins.ea:#x}')
            for pc, _ in ins.successors():
                if not 0 <= pc < len(p.words) or pc in payloads:
                    raise ChunkError(f'{ins.name}: invalid destination PC {pc} at {ins.ea:#x}')


def infer_legacy_names(p):
    for ins in p.instructions():
        if ins.name != 'CLOSURE':
            continue
        child = p.children[ins.bx]
        nextpc = ins.pc + ins.size // 4
        name = p.local_name(ins.a, nextpc)
        if not name and nextpc < len(p.words):
            nxt = p.instruction(nextpc)
            key = None
            if nxt.name == 'SETGLOBAL' and nxt.a == ins.a:
                key = nxt.bx
            elif nxt.name in ('SETTABLE', 'SETTABUP') and nxt.c == ins.a and nxt.b & 256:
                key = nxt.b & 255
            if key is not None and isinstance(p.constants[key].value, bytes):
                name = text(p.constants[key].value)
        if name and not name.startswith('('):
            safe = ''.join(c if c.isascii() and (c.isalnum() or c == '_') else '_' for c in name)
            child.name = f'lua_{safe}_{child.path}'
    for child in p.children:
        infer_legacy_names(child)
