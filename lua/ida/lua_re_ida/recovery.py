"""Build a temporary, non-executed parent for function-level source recovery."""
import struct
from .bytecode import parse, OPNAMES


def wrap_prototype(chunk, p, name="lua_re_function"):
    """Preserve the selected function body and provide named external upvalues.

    A child cannot safely be promoted to a main chunk: stripped functions need
    a parent for unluac's name resolution. The wrapper returns one closure.
    Only the copied child's capture descriptors are rebound to named externals.
    """
    version = chunk.version
    order = 'little' if chunk.endian == '<' else 'big'
    # Keep the child's native encoding and header together. Normalization for
    # unluac happens only after wrapping; LNUM numeric payloads can change size.
    header = chunk.data[:chunk.header_size]
    if version == 0x54:
        def integer(value):
            result = [value & 127 | 128]
            value >>= 7
            while value:
                result.insert(0, value & 127)
                value >>= 7
            return bytes(result)
        def string(value):
            return integer(len(value) + 1) + value
        words = [OPNAMES.index('VARARGPREP'), OPNAMES.index('CLOSURE'),
                 OPNAMES.index('RETURN') | 2 << 16 | 1 << 24,
                 OPNAMES.index('RETURN') | 1 << 16 | 1 << 24]
    else:
        from .legacy import OPCODES
        int_size = header[12] if version == 0x53 else header[7]
        size_t = header[13] if version == 0x53 else header[8]
        integer = lambda value: value.to_bytes(int_size, order)
        def string(value):
            size = len(value) + 1
            if version == 0x53:
                return (bytes([size]) if size < 255 else b'\xff' + size.to_bytes(size_t, order)) + value
            return size.to_bytes(size_t, order) + value + b'\0'
        names = OPCODES[version]
        words = [names.index('CLOSURE')]
        if version == 0x51:
            words += [names.index('GETUPVAL') | i << 23 for i in range(len(p.upvalues))]
        words += [names.index('RETURN') | 2 << 23, names.index('RETURN') | 1 << 23]
    child = bytearray(chunk.data[p.offset:p.end])
    if version >= 0x52:
        for i, u in enumerate(p.upvalues):
            child[u.offset-p.offset:u.offset-p.offset+2] = bytes([0,i])
    nup = len(p.upvalues)
    source = string(b'@Lua_RE_function_recovery')
    body = b'' if version == 0x52 else source
    body += integer(0)*2
    if version == 0x51:
        body += bytes([nup])
    body += bytes([0, 2 if version == 0x51 else 1, 2])
    body += integer(len(words)) + struct.pack(chunk.endian + f'{len(words)}I', *words)
    body += integer(0)  # constants
    upvalues = integer(nup) + (b'\0\0\0' if version == 0x54 else b'\0\0') * nup
    children = integer(1) + child
    if version >= 0x53:
        body += upvalues + children
    else:
        body += children
        if version == 0x52:
            body += upvalues + source
    # Debug records describe only this synthetic wrapper. Child debug bytes
    # remain untouched, so unluac can retain original parameter/local names.
    if p.lines:
        body += integer(len(words))
        body += bytes(len(words)) if version == 0x54 else integer(0) * len(words)
        if version == 0x54:
            body += integer(0)  # absolute line anchors
        body += integer(1) + string(name.encode('ascii')) + integer(len(words)-2) + integer(len(words) if version == 0x54 else len(words)-1)
    else:
        body += integer(0) * (3 if version == 0x54 else 2)
    body += integer(nup)
    for i,u in enumerate(p.upvalues):
        body += string(u.name or f'upvalue_{i}'.encode())
    data = header + (bytes([nup]) if version >= 0x53 else b'') + body
    return parse(data)
