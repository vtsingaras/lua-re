"""Lua RE loader extension for lua_re (2026-09-15), AGPL-3.0."""
import os
import sys
import ida_diskio
import ida_kernwin
sys.path.insert(0, os.path.join(ida_diskio.get_user_idadir(), 'python'))
from lua_re_ida.bytecode import parse, SIGNATURE, ChunkError
from lua_re_ida import database

def accept_file(li, filename):
    li.seek(0)
    header = li.read(6)
    if len(header) == 6 and header[:4] == b'\x1bLua' and header[4] in (0x51, 0x52, 0x53, 0x54) and header[5] == 0:
        return {'format': f'Lua {header[4] >> 4}.{header[4] & 15} bytecode (Lua RE)', 'processor': 'luare'}
    return 0

def load_file(li, neflags, format):
    try:
        if not ida_kernwin.get_kernel_version().startswith('9.4'):
            raise ChunkError('Lua RE targets IDA 9.4; use that version to load this chunk')
        if li.size() > 256 * 1024 * 1024:
            raise ChunkError('chunk exceeds 256 MiB analysis limit')
        li.seek(0)
        chunk = parse(li.read(li.size()))
    except ChunkError as exc:
        ida_kernwin.warning('Lua RE: %s' % exc)
        return 0
    return database.load(li, chunk)
