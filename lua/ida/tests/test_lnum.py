"""Independent dual-number fixtures; no proprietary bytecode is included."""
import itertools
import math
import struct
import unittest

from lua_re_ida.bytecode import ChunkError, parse
from lua_re_ida.decompiler import standard_bytes
from lua_re_ida.recovery import wrap_prototype
from test_legacy import abc
from test_bytecode import fixture as fixture54


def fixture(version=0x51, endian='<', integer_size=4, number_size=8,
            size_t=4, int_size=4, tag=9, stripped=False, values=None):
    """5.1/5.2 legacy LNUM layout, or 5.3 native dual-number layout."""
    order = 'little' if endian == '<' else 'big'
    count = lambda n: n.to_bytes(int_size, order)

    def string(value):
        if value is None:
            return b'\0' if version == 0x53 else bytes(size_t)
        if version == 0x53:
            return bytes([len(value) + 1]) + value
        return (len(value) + 1).to_bytes(size_t, order) + value + b'\0'

    if values is None:
        values = [-123, -123.25, True, None, b'a\0\xffb', -0.0]
    header = b'\x1bLua' + bytes([version, 0])
    if version < 0x53:
        header += bytes([endian == '<', int_size, size_t, 4, number_size, integer_size])
        if version == 0x52:
            header += b'\x19\x93\r\n\x1a\n'
    else:
        header += b'\x19\x93\r\n\x1a\n'
        header += bytes([int_size, size_t, 4, integer_size, number_size])
        header += (0x5678).to_bytes(integer_size, order)
        header += struct.pack(endian + ('f' if number_size == 4 else 'd'), 370.5)
        header += b'\0'  # main closure upvalues

    def body(root):
        source = string(b'@numeric_fixture.lua' if root and not stripped else None)
        out = source if version != 0x52 else b''
        out += count(0 if root else 10) * 2
        if version == 0x51:
            out += bytes([0 if root else 1])
        out += bytes([0, (2 if version == 0x51 else 1) if root else 0, 3])
        if root:
            words = [abc(version, 'LOADK'), abc(version, 'CLOSURE', a=1)]
            if version == 0x51:
                words += [abc(version, 'MOVE', b=0)]  # child's capture
            words += [abc(version, 'RETURN', a=1, b=2), abc(version, 'RETURN', b=1)]
        else:
            words = [abc(version, 'GETUPVAL'), abc(version, 'LOADK', a=1),
                     abc(version, 'ADD', b=0, c=1), abc(version, 'RETURN', b=2),
                     abc(version, 'RETURN', b=1)]
        out += count(len(words)) + struct.pack(endian + f'{len(words)}I', *words)
        out += count(len(values))
        for value in values:
            if value is None:
                out += b'\0'
            elif isinstance(value, bool):
                out += bytes([1, value])
            elif isinstance(value, int):
                out += bytes([19 if version == 0x53 else tag])
                out += value.to_bytes(integer_size, order, signed=True)
            elif isinstance(value, float):
                out += b'\3' + struct.pack(endian + ('f' if number_size == 4 else 'd'), value)
            else:
                out += b'\4' + string(value)
        upvalues = count(0) if root else count(1) + b'\1\0'
        children = count(1) + body(False) if root else count(0)
        out += upvalues + children if version == 0x53 else children
        if version == 0x52:
            out += upvalues + source
        out += count(0) if stripped else count(len(words)) + count(10) * len(words)
        out += count(0)  # local variables
        out += count(0) if stripped or root else count(1) + string(b'capture')
        return out

    return header + body(True)


class LnumTests(unittest.TestCase):
    def assert_same_prototype(self, before, after):
        self.assertEqual(before.words, after.words)
        self.assertEqual([k.value for k in before.constants], [k.value for k in after.constants])
        self.assertEqual(before.lines, after.lines)
        self.assertEqual(before.locals, after.locals)
        self.assertEqual([u.name for u in before.upvalues], [u.name for u in after.upvalues])

    def test_legacy_numeric_formats_and_normalization(self):
        cases = itertools.product((0x51, 0x52), '<>', (2, 4, 8), (4, 8), (4, 8),
                                  (4, 8), (9, 254), (False, True))
        for version, endian, iw, nw, sw, cw, tag, stripped in cases:
            with self.subTest(version=version, endian=endian, integer=iw, number=nw,
                              size_t=sw, count=cw, tag=tag, stripped=stripped):
                data = fixture(version, endian, iw, nw, sw, cw, tag, stripped)
                chunk = parse(data)
                self.assertEqual(chunk.variant, 'lnum')
                self.assertEqual((chunk.integer_size, chunk.number_size), (iw, nw))
                self.assertEqual(chunk.data, data)
                self.assertEqual(len(chunk.prototypes), 2)
                normalized = parse(standard_bytes(chunk))
                self.assertEqual(normalized.variant, 'standard')
                self.assertEqual(normalized.number_size, 8)
                self.assertEqual(normalized.endian, endian)
                for p, q in zip(chunk.prototypes, normalized.prototypes):
                    self.assert_same_prototype(p, q)
                    self.assertIs(type(p.constants[0].value), int)
                    self.assertEqual(p.constants[0].end - p.constants[0].payload, iw)
                    self.assertEqual(data[p.constants[0].offset], tag)
                    self.assertEqual(math.copysign(1, q.constants[-1].value), -1)
                self.assertEqual(standard_bytes(normalized), normalized.data)

    def test_nested_recovery_normalizes_after_wrapping(self):
        for version, endian, stripped in itertools.product((0x51, 0x52), '<>', (False, True)):
            with self.subTest(version=version, endian=endian, stripped=stripped):
                chunk = parse(fixture(version, endian, stripped=stripped))
                child = chunk.root.children[0]
                wrapped = wrap_prototype(chunk, child)
                self.assertEqual(wrapped.variant, 'lnum')
                self.assertEqual(wrapped.integer_size, chunk.integer_size)
                normalized = parse(standard_bytes(wrapped))
                self.assert_same_prototype(child, normalized.root.children[0])
                self.assertEqual(normalized.root.upvalues[0].name,
                                 child.upvalues[0].name or b'upvalue_0')
                if version == 0x52:
                    self.assertEqual(normalized.root.children[0].upvalues[0].instack, 0)

    def test_native_integers_keep_full_precision(self):
        for version, endian in itertools.product((0x53, 0x54), '<>'):
            with self.subTest(version=version, endian=endian):
                values = [-(1 << 63), (1 << 63) - 1, (1 << 53) + 1]
                data = (fixture(version, endian, integer_size=8, values=values)
                        if version == 0x53 else fixture54(endian=endian, constants=[(3, n) for n in values]))
                chunk = parse(data)
                self.assertEqual([k.value for k in chunk.root.constants], values)
                self.assertEqual(standard_bytes(chunk), data)

    def test_integer_limits_and_lossy_conversion_rejected(self):
        for version, endian, iw in itertools.product((0x51, 0x52), '<>', (2, 4, 8)):
            with self.subTest(version=version, endian=endian, width=iw):
                values = [-(1 << (iw * 8 - 1)), (1 << (iw * 8 - 1)) - 1]
                chunk = parse(fixture(version, endian, integer_size=iw, values=values))
                self.assertEqual([k.value for k in chunk.root.constants], values)
                if iw == 8:
                    with self.assertRaisesRegex(ValueError, 'cannot be represented exactly'):
                        standard_bytes(chunk)
                else:
                    self.assertEqual([k.value for k in parse(standard_bytes(chunk)).root.constants], values)

    def test_lnum_tags_require_lnum_header(self):
        for version, tag in itertools.product((0x51, 0x52), (9, 254)):
            data = bytearray(fixture(version, tag=tag))
            data[11] = 0
            with self.subTest(version=version, tag=tag), self.assertRaisesRegex(ChunkError, 'unknown constant tag'):
                parse(data)

    def test_truncated_and_unsupported_formats(self):
        for version in (0x51, 0x52):
            data = fixture(version)
            for size in range(len(data)):
                with self.subTest(version=version, size=size), self.assertRaises(ChunkError):
                    parse(data[:size])
            with self.assertRaises(ChunkError):
                parse(data + b'\0')
            for flag in (3, 16, 0x84, 0x88):
                with self.subTest(version=version, flag=flag), self.assertRaises(ChunkError):
                    parse(data[:11] + bytes([flag]) + data[12:])


if __name__ == '__main__':
    unittest.main()
