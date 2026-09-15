"""IDA database persistence and original-file-offset mapping. AGPL-3.0."""
from bisect import bisect_right
from .bytecode import parse, Instruction, text, display
import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_netnode
import ida_segment
import ida_ua

NODE = '$ lua_re.bytecode.v1'
_cache = None
_analysis = None
_prototypes = []
_starts = []
_dirty = False
_patch_error = None

def reset():
    global _cache, _analysis, _prototypes, _starts, _dirty, _patch_error
    _cache, _analysis, _prototypes, _starts = None, None, [], []
    _dirty, _patch_error = False, None

def set_cache(chunk):
    global _cache, _analysis, _prototypes, _starts, _dirty, _patch_error
    _cache, _analysis = chunk, None
    _dirty, _patch_error = False, None
    _prototypes = sorted(chunk.prototypes, key=lambda p: p.code_offset)
    _starts = [p.code_offset for p in _prototypes]

def get_chunk():
    global _dirty, _patch_error
    if _cache is None:
        raw = ida_netnode.netnode(NODE, 0, False).getblob(0, 'L')
        if raw is None:
            return None
        set_cache(parse(bytes(raw)))
        mapped = ida_bytes.get_bytes(0, len(_cache.data))
        _dirty = mapped is not None and mapped != _cache.data
    if _dirty or _patch_error:
        try:
            fresh = parse(ida_bytes.get_bytes(0, len(_cache.data)))
            if layout(fresh) != layout(_cache):
                raise ValueError('Patched chunk changes metadata layout; re-import it first')
            set_cache(fresh)
        except Exception as exc:
            _patch_error = str(exc)
            _dirty = False
    return None if _patch_error else _cache


def layout(chunk):
    return [(p.path, p.offset, p.code_offset, p.code_end, p.end,
             [(k.offset, k.payload, k.end) for k in p.constants],
             [u.offset for u in p.upvalues]) for p in chunk.prototypes]


def current_chunk():
    """Validated current bytes, independent of the original input file."""
    global _dirty
    if _cache is not None:
        _dirty = bool(_patch_error) or ida_bytes.get_bytes(0, len(_cache.data)) != _cache.data
    chunk = get_chunk()
    if chunk is None:
        raise ValueError(_patch_error or 'The current database is not a Lua RE chunk')
    return chunk


class DatabaseHooks(ida_idp.IDB_Hooks):
    def byte_patched(self, ea, old_value):
        global _dirty, _analysis, _patch_error
        if _cache is not None and 0 <= ea < len(_cache.data):
            _dirty, _analysis, _patch_error = True, None, None
            for p in _prototypes:
                ida_auto.auto_mark_range(p.code_offset, p.code_end, ida_auto.AU_CODE)

    def closebase(self):
        reset()

def get_analysis():
    global _analysis
    if _analysis is None and get_chunk() is not None:
        from .analysis import Analysis
        _analysis = Analysis(get_chunk())
    return _analysis

def prototype_at(ea):
    if get_chunk() is None:
        return None
    i = bisect_right(_starts, ea) - 1
    if i >= 0 and ea < _prototypes[i].code_end:
        return _prototypes[i]
    return None

def instruction_at(ea):
    p = prototype_at(ea)
    if p is None or (ea - p.code_offset) % 4:
        return None
    raw = ida_bytes.get_bytes(ea, 4)
    if raw is None:
        return None
    word = int.from_bytes(raw, 'little' if get_chunk().endian == '<' else 'big')
    if p.version < 0x54:
        from .legacy import LegacyInstruction
        ins = LegacyInstruction(word, (ea - p.code_offset) // 4, p)
    else:
        ins = Instruction(word, (ea - p.code_offset) // 4, p)
    if ins.name == 'INVALID':
        return None
    if ins.has_extra and p.version == 0x54:
        extra = ida_bytes.get_bytes(ea + 4, 4)
        if extra is None or ea + 8 > p.code_end:
            return None
        extra_word = int.from_bytes(extra, 'little' if get_chunk().endian == '<' else 'big')
        if extra_word & 127 != 82:
            return None
        ins.extra_override = extra_word >> 7
    for op in ins.operands():
        limit = {'const': len(p.constants), 'upval': len(p.upvalues), 'proto': len(p.children)}.get(op.kind)
        if limit is not None and not 0 <= op.value < limit:
            return None
    return ins

def operand_address(p, op):
    if op.kind == 'const':
        k = p.constants[op.value]
        return k.payload if isinstance(k.value, bytes) and k.value else k.offset
    if op.kind == 'upval':
        return p.upvalues[op.value].offset
    if op.kind == 'proto':
        return p.children[op.value].code_offset
    return op.value

def add_segment(start, end, name, code=False):
    if start == end:
        return
    s = ida_segment.segment_t()
    s.start_ea, s.end_ea = start, end
    s.sel = ida_segment.setup_selector(0)
    s.bitness = 1
    s.align = ida_segment.saRelByte
    s.comb = ida_segment.scPub
    s.type = ida_segment.SEG_CODE if code else ida_segment.SEG_DATA
    s.perm = ida_segment.SEGPERM_READ | (ida_segment.SEGPERM_EXEC if code else 0)
    if not ida_segment.add_segm_ex(s, name, 'CODE' if code else 'DATA',
                                   ida_segment.ADDSEG_NOSREG | ida_segment.ADDSEG_QUIET):
        raise RuntimeError(f'cannot create segment {name}')

def load(li, chunk):
    if not ida_idp.set_processor_type('luare', ida_idp.SETPROC_LOADER):
        raise RuntimeError('Lua RE processor not installed; run install.py and restart IDA')
    ida_ida.inf_set_be(chunk.endian == '>')
    ida_ida.inf_set_app_bitness(32)
    set_cache(chunk)
    node = ida_netnode.netnode(NODE, 0, True)
    if not node.setblob(chunk.data, 0, 'L'):
        raise RuntimeError('cannot persist Lua metadata')
    cursor = 0
    for p in _prototypes:
        add_segment(cursor, p.code_offset, f'meta_{p.path}')
        add_segment(p.code_offset, p.code_end, f'code_{p.path}', code=True)
        cursor = p.code_end
    add_segment(cursor, len(chunk.data), 'lua_debug_tail')
    if not li.file2base(0, 0, len(chunk.data), True):
        raise RuntimeError('cannot map Lua chunk')
    ida_bytes.set_cmt(0, f'Lua RE; {chunk.variant}; original file offsets; lua_re extension', False)
    ida_name.set_name(0, 'lua_chunk_header', ida_name.SN_NOCHECK)
    for p in _prototypes:
        for i, k in enumerate(p.constants):
            ida_bytes.create_byte(k.offset, 1)
            ida_bytes.set_cmt(k.offset, f'{p.name} K{i} = {display(k.value)}', False)
            target = k.offset
            if isinstance(k.value, bytes) and k.value:
                target = k.payload
                ida_bytes.create_strlit(k.payload, len(k.value), ida_nalt.STRTYPE_C)
            elif k.tag == 3:
                ida_bytes.create_data(k.payload, ida_bytes.FF_QWORD if chunk.integer_size == 8 else ida_bytes.FF_DWORD,
                                      chunk.integer_size, ida_idaapi.BADADDR)
            elif k.tag == 19:
                ida_bytes.create_data(k.payload, ida_bytes.FF_DOUBLE if chunk.number_size == 8 else ida_bytes.FF_FLOAT,
                                      chunk.number_size, ida_idaapi.BADADDR)
            ida_name.set_name(target, f'k_{p.path}_{i}', ida_name.SN_NOCHECK)
        for i, u in enumerate(p.upvalues):
            ida_bytes.create_byte(u.offset, 3 if p.version == 0x54 else (2 if p.version >= 0x52 else 1))
            ida_name.set_name(u.offset, f'u_{p.path}_{i}', ida_name.SN_NOCHECK)
            origin = 'parent register' if u.instack else 'parent upvalue'
            ida_bytes.set_cmt(u.offset, f'{text(u.name)}; {origin} {u.index}; kind={u.kind}', False)
        for ins in p.instructions():
            if ida_ua.create_insn(ins.ea) != ins.size:
                raise RuntimeError(f'instruction creation failed at {ins.ea:#x}')
            ida_bytes.set_cmt(ins.ea, '; '.join(filter(None, [ins.comment(), get_analysis().call_comment(ins.ea)])), False)
        if not ida_funcs.add_func(p.code_offset, p.code_end):
            raise RuntimeError(f'function creation failed: {p.name}')
        ida_name.set_name(p.code_offset, p.name, ida_name.SN_NOCHECK)
        f = ida_funcs.get_func(p.code_offset)
        details = (f'Lua prototype {p.path}\n{text(p.source)}:{p.firstline}-{p.lastline}\n'
                   f'parameters={p.params}; vararg={p.vararg}; registers={p.stack}; '
                   f'upvalues={len(p.upvalues)}; words={len(p.words)}')
        if p.locals:
            details += '\nLocals (PC ranges are zero-based, end exclusive):\n'
            details += '\n'.join(f'{text(v.name)} [{v.startpc}, {v.endpc})' for v in p.locals)
        ida_funcs.set_func_cmt(f, details, True)
        ida_auto.auto_mark_range(p.code_offset, p.code_end, ida_auto.AU_CODE)
    root = chunk.root.code_offset
    ida_entry.add_entry(root, root, 'lua_main', True)
    ida_ida.inf_set_start_ea(root)
    ida_ida.inf_set_start_ip(root)
    ida_kernwin.msg(f'[Lua RE] Loaded {len(_prototypes)} functions, '
                    f'{sum(len(p.words) for p in _prototypes)} bytecode words ({chunk.variant}).\n')
    return 1
