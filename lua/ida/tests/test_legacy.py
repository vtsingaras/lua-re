"""Independent legacy fixtures for endian, widths, RK operands and payloads."""
import struct
import unittest
from lua_re_ida.bytecode import parse, ChunkError
from lua_re_ida.legacy import OPCODES


def abc(version, name, a=0, b=0, c=0):
    return OPCODES[version].index(name) | a << 6 | c << 14 | b << 23


def fixture(version, endian='<', int_size=4, size_t=8, number_size=8, words=None):
    order = 'little' if endian == '<' else 'big'
    integer = lambda n: n.to_bytes(int_size, order)
    size = lambda n: n.to_bytes(size_t, order)
    def string(value):
        if version == 0x53:
            return (bytes([len(value)+1]) if len(value) < 254 else b'\xff'+size(len(value)+1)) + value
        return size(len(value)+1) + value + b'\0'
    if words is None:
        words = [abc(version,'LOADK'), abc(version,'ADD',a=1,b=0,c=256),
                 abc(version,'RETURN',a=1,b=2)]
    source = string(b'@fixture.lua')
    header = b'\x1bLua' + bytes([version,0])
    if version < 0x53:
        header += bytes([int(endian == '<'),int_size,size_t,4,number_size,0])
        if version == 0x52:
            header += b'\x19\x93\r\n\x1a\n'
    else:
        header += b'\x19\x93\r\n\x1a\n' + bytes([int_size,size_t,4,8,number_size])
        header += struct.pack(endian+'q',0x5678) + struct.pack(endian+('f' if number_size==4 else 'd'),370.5) + b'\0'
    body = (source if version != 0x52 else b'') + integer(0)*2
    body += (b'\0' if version == 0x51 else b'') + bytes([0,1,6])
    body += integer(len(words)) + struct.pack(endian+f'{len(words)}I',*words)
    body += integer(4)
    body += b'\3' + struct.pack(endian+('f' if number_size==4 else 'd'), -123.25)
    body += b'\1\1\0\4' + string(b'a\0\xffb')
    body += integer(0)  # no child prototypes or upvalues
    if version != 0x51:
        body += integer(0)
    if version == 0x52:
        body += source
    body += integer(len(words)) + b''.join(integer(i+20) for i in range(len(words)))
    body += integer(0)*2
    return header+body


class LegacyTests(unittest.TestCase):
    def test_versions_endianness_and_widths(self):
        for version in OPCODES:
            for endian in '<>':
                for int_size in (4,8):
                    for size_t in (4,8):
                        for number_size in (4,8):
                            with self.subTest(version=version,endian=endian,int_size=int_size,size_t=size_t,number_size=number_size):
                                c=parse(fixture(version,endian,int_size,size_t,number_size))
                                self.assertEqual(c.version,version)
                                self.assertEqual(c.endian,endian)
                                self.assertEqual([k.value for k in c.root.constants],[-123.25,True,None,b'a\0\xffb'])
                                self.assertEqual(c.root.lines,[20,21,22])
                                self.assertEqual([o.kind for o in c.root.instruction(1).operands()],['reg','reg','const'])
                                self.assertEqual(c.root.instruction(1).successors(),[(2,'flow')])

    def test_truncation(self):
        for version in OPCODES:
            data=fixture(version)
            for size in range(len(data)):
                with self.subTest(version=version,size=size), self.assertRaises(ChunkError):
                    parse(data[:size])
            with self.assertRaises(ChunkError):
                parse(data+b'\0')

    def test_setlist_payloads_and_branch_rejection(self):
        for version in OPCODES:
            payload = 512 if version == 0x51 else OPCODES[version].index('EXTRAARG') | 512 << 6
            words=[abc(version,'SETLIST',b=1,c=0),payload,abc(version,'RETURN',b=1)]
            p=parse(fixture(version,words=words)).root
            self.assertEqual(p.instruction(0).size,8)
            self.assertEqual(p.instruction(0).extra,512)
            self.assertEqual(p.instruction(0).successors(),[(2,'flow')])
            # A conditional skip cannot enter a payload word.
            words.insert(0,abc(version,'TEST'))
            with self.assertRaises(ChunkError):
                parse(fixture(version,words=words))

    def test_unknown_opcodes_and_bad_counts(self):
        for version in OPCODES:
            with self.assertRaises(ChunkError):
                parse(fixture(version,words=[63,abc(version,'RETURN',b=1)]))
            with self.assertRaises(ChunkError):
                parse(fixture(version,words=[abc(version,'CALL',a=5,b=5,c=2),abc(version,'RETURN',b=1)]))
