"""Function-level Lua pseudocode for F5, scripts and ida-pro-mcp. AGPL-3.0.

This is a Lua source provider, not a Hex-Rays cfunc_t/ctree implementation.
Never fabricates statement-to-address mappings; only the entry mapping is exact.
"""
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import re
import threading
from .bytecode import parse, text
from .decompiler import decompile as run_unluac, standard_bytes

_cache = OrderedDict()
_cache_lock = threading.RLock()

@dataclass
class SourceLine:
    line: str

@dataclass
class LuaPseudocode:
    entry_ea: int
    name: str
    source: str
    original_source: str
    firstline: int
    lastline: int

    def __str__(self):
        return self.source

    def get_pseudocode(self):
        return [SourceLine(line) for line in self.source.splitlines()]

    def render(self, include_addresses=True):
        if not include_addresses:
            return self.source
        return (f'-- Lua / unluac; function entry {self.entry_ea:#x}\n'
                f'-- Original source: {self.original_source}:{self.firstline}-{self.lastline}\n'
                + self.source)

def clear_cache():
    with _cache_lock:
        _cache.clear()

def function_source(chunk, p, name=None, cancel=None):
    name = name or p.name
    digest = hashlib.sha256(chunk.data).digest()
    key = (digest, p.path, name)
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    if p is chunk.root:
        source = run_unluac(chunk, cancel=cancel)
    else:
        from .recovery import wrap_prototype
        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', name)
        keywords = set('and break do else elseif end false for function goto if in local nil not or repeat return then true until while'.split())
        if not safe_name or safe_name[0].isdigit() or safe_name in keywords:
            safe_name = 'lua_' + safe_name
        wrapped = wrap_prototype(chunk, p, safe_name)
        source = run_unluac(wrapped, cancel=cancel)
    result = LuaPseudocode(p.code_offset, name, source, text(p.source), p.firstline, p.lastline)
    with _cache_lock:
        _cache[key] = result
        while len(_cache) > 32:
            _cache.popitem(last=False)
    return result

def decompile(ea):
    """IDAPython entry point. Call on IDA's main thread, as for native APIs."""
    import ida_bytes
    import ida_name
    from . import database
    chunk = database.current_chunk()
    p = database.prototype_at(ea)
    if p is None:
        raise ValueError(f'No Lua prototype at {ea:#x}')
    # Honor patched instructions/constants, and reject changes invalidating layout.
    fresh = next((v for v in chunk.prototypes if v.code_offset == p.code_offset), None)
    if fresh is None or fresh.code_end != p.code_end:
        raise ValueError('Patched chunk changes prototype layout; re-import it first')
    return function_source(chunk, fresh, ida_name.get_name(p.code_offset) or p.name)

def decompile_safe(ea, include_addresses=True):
    try:
        return decompile(ea).render(include_addresses), None
    except Exception as exc:
        return None, f'Lua RE decompilation failed: {exc}'

def references(ea):
    import ida_name
    from . import database
    p = database.prototype_at(ea)
    if p is None:
        return []
    refs = {}
    for ins in p.instructions():
        for op in ins.operands():
            if op.kind not in ('const', 'upval', 'proto'):
                continue
            addr = database.operand_address(p, op)
            row = {'addr': hex(addr), 'name': ida_name.get_name(addr)}
            if op.kind == 'const' and isinstance(p.constants[op.value].value, bytes):
                row['string'] = text(p.constants[op.value].value)
            refs[addr] = row
    return list(refs.values())

def capabilities():
    """Effective decompiler status; hexrays_ready remains truthful elsewhere."""
    from .decompiler import configuration
    try:
        configuration()
        return dict(decompiler_ready=True, decompiler_backend='Lua RE / unluac',
                    decompiler_hint='Use the standard decompile tool for Lua functions by name or address. Hex-Rays is not required. Returns recovered Lua source and references.')
    except Exception as exc:
        return dict(decompiler_ready=False, decompiler_backend='Lua RE / unluac',
                    decompiler_hint=str(exc))
