"""Regression tests for format boundaries, all opcodes, and control flow."""
from pathlib import Path
import random
import struct
import unittest

from lua_re_ida.bytecode import (
    parse, ChunkError, SIGNATURE, OPNAMES, Instruction, Prototype, Constant,
    Upvalue, ARITHMETIC, CONDITIONAL, Reader, listing,
)

def varuint(n):
    out = [n & 127 | 128]
    n >>= 7
    while n:
        out.insert(0, n & 127)
        n >>= 7
    return bytes(out)

def string(s):
    return b'\x80' if s is None else varuint(len(s) + 1) + s

def abc(name, a=0, b=0, c=0, k=0):
    return OPNAMES.index(name) | a << 7 | k << 15 | b << 16 | c << 24

def abx(name, a=0, bx=0):
    return OPNAMES.index(name) | a << 7 | bx << 15

def sj(offset):
    return OPNAMES.index('JMP') | (offset + 16777215) << 7

def fixture(words=None, endian='<', integer_size=8, number_size=8, compact=False,
            constants=None, children=(), stripped=False):
    if words is None:
        words = [abc('VARARGPREP'), abc('RETURN0')]
    if constants is None:
        constants = [(0, None), (1, False), (17, True), (3, -123456),
                     (19, -123.25), (4, b'a\x00\xffb'), (20, b'long' * 40), (4, b'')]
    def body(code, subchildren, root):
        out = string(None if stripped or not root else b'@fixture.lua')
        out += varuint(0) + varuint(0) + bytes([0, int(root), 255])
        out += varuint(len(code)) + struct.pack(endian + f'{len(code)}I', *code)
        out += varuint(len(constants))
        for tag, value in constants:
            out += bytes([tag])
            if tag == 3:
                out += struct.pack(endian + ('q' if integer_size == 8 else 'i'), value)
            elif tag == 19:
                out += struct.pack(endian + ('d' if number_size == 8 else 'f'), value)
            elif tag in (4, 20):
                out += string(value)
        out += varuint(1) + bytes([1, 0, 0])
        out += varuint(len(subchildren))
        for sub in subchildren:
            out += body(sub, (), False)
        if stripped:
            out += b'\x80' * 4
        else:
            # Include an absolute anchor and normal deltas.
            out += varuint(len(code)) + bytes([128]) + b'\x01' * (len(code) - 1)
            out += varuint(1) + varuint(0) + varuint(400)
            out += varuint(1) + string(b'local_var') + varuint(0) + varuint(len(code))
            out += varuint(1) + string(b'_ENV')
        return out
    header = SIGNATURE + bytes([4, integer_size, number_size])
    if compact:
        header += b'\x00'
    else:
        header += struct.pack(endian + ('q' if integer_size == 8 else 'i'), 0x5678)
        header += struct.pack(endian + ('d' if number_size == 8 else 'f'), 370.5)
    return header + b'\x01' + body(words, children, True)

def all_opcodes():
    words = []
    for name in OPNAMES:
        if name == 'EXTRAARG':
            continue
        if name == 'JMP':
            words.append(sj(0))
        elif name in ('LOADI', 'LOADF'):
            words.append(abx(name, bx=65535 - 42))
        elif name in ('FORLOOP', 'TFORLOOP'):
            words.append(abx(name, bx=1))
        else:
            words.append(abc(name))
        if name in ('LOADKX', 'NEWTABLE'):
            words.append(abc('EXTRAARG'))
        if name in ARITHMETIC:
            words.append(abc('MMBIN'))
    words.append(abc('RETURN0'))
    return words

class ReaderTests(unittest.TestCase):
    def test_endian_and_widths(self):
        for endian in '<>':
            for iw in (4, 8):
                for fw in (4, 8):
                    with self.subTest(endian=endian, integer=iw, number=fw):
                        c = parse(fixture(endian=endian, integer_size=iw, number_size=fw))
                        self.assertEqual(c.endian, endian)
                        self.assertEqual([k.value for k in c.root.constants],
                                         [None, False, True, -123456, -123.25, b'a\x00\xffb', b'long' * 40, b''])
                        self.assertEqual(c.root.lines, [400, 401])

    def test_compact(self):
        data = fixture(compact=True)
        self.assertEqual(parse(data).variant, 'glinet-compact')
        with self.assertRaises(ChunkError):
            parse(data, allow_compact=False)

    def test_nested_and_stripped(self):
        c = parse(fixture(children=([abc('RETURN0')],), stripped=True))
        self.assertEqual(len(c.prototypes), 2)
        self.assertEqual(c.root.lines, [])
        self.assertEqual(c.root.locals, [])
        self.assertEqual(c.root.children[0].source, b'')
        self.assertEqual(c.root.upvalues[0].name, b'')
        c = parse(fixture(children=([abc('RETURN0')],)))
        self.assertEqual(c.root.children[0].source, b'@fixture.lua')

    def test_all_83_opcodes(self):
        c = parse(fixture(words=all_opcodes(), children=([abc('RETURN0')],)))
        self.assertEqual({c.root.instruction(i).name for i in range(len(c.root.words))}, set(OPNAMES))
        self.assertIn('LOADI       R0, -42', listing(c))
        self.assertIn('LOADF       R0, -42', listing(c))

    def test_extraarg_and_rk(self):
        words = [abc('SETLIST', c=5, k=1), OPNAMES.index('EXTRAARG') | 2 << 7,
                 abc('SETFIELD', b=5, c=3, k=1), abc('RETURN0')]
        p = parse(fixture(words)).root
        ins = p.instruction(0)
        self.assertEqual(ins.size, 8)
        self.assertEqual(ins.operands()[2].value, 517)
        self.assertEqual(ins.successors(), [(2, 'flow')])
        self.assertEqual([o.kind for o in p.instruction(2).operands()], ['reg', 'const', 'const'])

    def test_jump_offsets(self):
        p = Prototype('0', 0, b'', 0, 0, 0, 0, 4, 100, [])
        cases = [(sj(-5), 10, [(6, 'jump')]),
                 (abx('FORLOOP', bx=9), 10, [(11, 'flow'), (2, 'jump')]),
                 (abx('FORPREP', bx=9), 10, [(11, 'flow'), (21, 'jump')]),
                 (abx('TFORPREP', bx=9), 10, [(20, 'jump')]),
                 (abx('TFORLOOP', bx=9), 10, [(11, 'flow'), (2, 'jump')]),
                 (abc('EQ'), 10, [(11, 'flow'), (12, 'jump')]),
                 (abc('ADD'), 10, [(11, 'flow'), (12, 'jump')]),
                 (abc('LFALSESKIP'), 10, [(12, 'jump')])]
        for word, pc, expected in cases:
            with self.subTest(opcode=word & 127):
                self.assertEqual(Instruction(word, pc, p).successors(), expected)

    def test_truncation_and_trailing_data(self):
        data = fixture()
        for n in range(len(data)):
            with self.subTest(length=n), self.assertRaises(ChunkError):
                parse(data[:n])
        with self.assertRaises(ChunkError):
            parse(data + b'\x00')

    def test_invalid_instructions(self):
        for words in ([127], [abx('LOADK', bx=100), abc('RETURN0')],
                      [abc('LOADKX'), abc('RETURN0')], [abc('EXTRAARG')],
                      [sj(999), abc('RETURN0')],
                      [abc('ADD'), abc('RETURN0'), abc('RETURN0')]):
            with self.subTest(words=words), self.assertRaises(ChunkError):
                parse(fixture(words))

    def test_bad_header_and_counts(self):
        data = bytearray(fixture())
        for index, val in ((4, 0x53), (5, 1), (12, 8), (13, 2), (15, 0x79), (31, 9)):
            copy = bytearray(data)
            copy[index] = val
            with self.subTest(index=index), self.assertRaises(ChunkError):
                parse(copy)
        with self.assertRaises(ChunkError):
            Reader(b'\x7f' * 10 + b'\xff').uint()

    def test_mutations_are_bounded(self):
        data, rng = fixture(), random.Random(54)
        for _ in range(500):
            damaged = bytearray(data)
            damaged[rng.randrange(len(data))] = rng.randrange(256)
            try:
                parse(damaged)
            except ChunkError:
                pass

if __name__ == '__main__':
    unittest.main()
