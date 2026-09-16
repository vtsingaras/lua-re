"""Run with an IDA-enabled Python, outside IDA. Uses a disposable input copy."""
import idapro
import sys
from pathlib import Path
import json
import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_kernwin
import ida_lines
import ida_loader
import ida_ua
import ida_xref
import ida_idaapi
import idautils

idapro.enable_console_messages(True)
target = Path(sys.argv[1]).resolve()
print('OPENING', target, flush=True)
rc = idapro.open_database(str(target), True)
print('OPEN RESULT', rc, flush=True)
if rc:
    raise SystemExit(rc)
try:
    from lua_re_ida import database
    ida_auto.auto_wait()
    c = database.get_chunk()
    assert c is not None
    print('PROCESSOR', ida_ida.inf_get_procname(), flush=True)
    errors, words, count, blocks = [], 0, 0, 0
    for p in c.prototypes:
        f = ida_funcs.get_func(p.code_offset)
        if f is None or f.start_ea != p.code_offset or f.end_ea != p.code_end:
            errors.append(f'bad function {p.name}: {f}')
            continue
        blocks += len(list(ida_gdl.FlowChart(f)))
        for k in p.constants:
            if k.tag in (3, 19):
                width = c.integer_size if k.tag == 3 else c.number_size
                if ida_bytes.get_item_size(k.payload) != width:
                    errors.append(f'bad numeric constant width at {k.payload:#x}')
        for model in p.instructions():
            words += model.size // 4
            count += 1
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, model.ea) != model.size or insn.itype != model.opcode:
                errors.append(f'decode mismatch at {model.ea:#x}')
            actual = {(x.to, x.type) for x in idautils.XrefsFrom(model.ea) if x.iscode and x.type not in (ida_xref.fl_CN, ida_xref.fl_CF)}
            expected = {(p.code_offset + pc * 4, ida_xref.fl_F if kind == 'flow' else ida_xref.fl_JN)
                        for pc, kind in model.successors()}
            if actual != expected:
                errors.append(f'flow mismatch at {model.ea:#x}: {actual} != {expected}')
            line = ida_lines.tag_remove(ida_lines.generate_disasm_line(model.ea, 0) or '')
            if model.name not in line:
                errors.append(f'bad rendering at {model.ea:#x}: {line}')
    report = dict(ida_version=ida_kernwin.get_kernel_version(), processor=ida_ida.inf_get_procname(),
                  functions=len(list(idautils.Functions())), prototypes=len(c.prototypes),
                  bytecode_words=words, instructions=count, blocks=blocks, errors=errors)
    print(json.dumps(report, indent=2), flush=True)
    for ins in list(c.root.instructions())[:10]:
        print(ida_lines.tag_remove(ida_lines.generate_disasm_line(ins.ea, 0) or ''), flush=True)
    target.with_suffix(target.suffix + '.validation.json').write_text(json.dumps(report, indent=2))
    assert not errors, errors[:10]
    assert report['functions'] == len(c.prototypes)
    assert ida_bytes.get_bytes(0, len(c.data)) == c.data
    from lua_re_ida.explorer import FunctionChooser, ExplorerPlugin
    chooser = FunctionChooser()
    assert chooser.OnGetSize() == len(c.prototypes)
    assert chooser.OnGetLine(0)[1] == 'lua_main'
    plugin = ExplorerPlugin()
    assert plugin.init() == ida_idaapi.PLUGIN_KEEP
    plugin.term()
    from lua_re_ida.pseudocode import decompile
    selected = next((p for p in c.prototypes if 'get_sign' in p.name), c.root)
    source = decompile(selected.code_offset)
    assert source.source and source.entry_ea == selected.code_offset
    print('EXPLORER AND PSEUDOCODE API CHECK PASSED', flush=True)
    assert ida_loader.save_database(str(target) if target.suffix == '.i64' else str(target) + '.i64', ida_loader.DBFL_COMP)
finally:
    idapro.close_database(True)
