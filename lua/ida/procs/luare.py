"""Lua RE processor for lua_re, IDA 9 / Python 3 (2026-09-15), AGPL-3.0."""
import os
import sys
import ida_diskio
import ida_bytes
import ida_idp
import ida_lines
import ida_name
import ida_ua
import ida_xref
sys.path.insert(0, os.path.join(ida_diskio.get_user_idadir(), 'python'))
from lua_re_ida.bytecode import OPNAMES, ARITHMETIC, CONDITIONAL, TERMINATORS
from lua_re_ida.legacy import PROCESSOR_OPNAMES
from lua_re_ida import database

def features(name):
    writes_a = set(OPNAMES[:10]) | set(OPNAMES[11:15]) | {'NEWTABLE', 'SELF', 'UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT', 'TESTSET', 'CLOSURE', 'VARARG'} | ARITHMETIC
    flags = ida_idp.CF_USE2 | ida_idp.CF_USE3 | ida_idp.CF_USE4
    flags |= ida_idp.CF_CHG1 if name in writes_a else ida_idp.CF_USE1
    if name == 'SETUPVAL':
        flags = ida_idp.CF_USE1 | ida_idp.CF_CHG2
    if name in ('CALL', 'FORLOOP', 'FORPREP', 'TFORLOOP'):
        flags |= ida_idp.CF_CHG1
    if name in TERMINATORS or name in ('JMP', 'TFORPREP', 'LFALSESKIP'):
        flags |= ida_idp.CF_STOP
    if name in CONDITIONAL | ARITHMETIC | {'JMP', 'FORPREP', 'FORLOOP', 'TFORPREP', 'TFORLOOP', 'LFALSESKIP'}:
        flags |= ida_idp.CF_JUMP
    if name in ('CALL', 'TAILCALL', 'TFORCALL'):
        flags |= ida_idp.CF_CALL
    return flags

class lua_re_processor_t(ida_idp.processor_t):
    def __init__(self):
        super().__init__()
        self.database_hooks = database.DatabaseHooks()
        self.database_hooks.hook()

    id = 0x8054
    flag = (ida_idp.PR_SEGS | ida_idp.PR_DEFSEG32 | ida_idp.PR_USE32 |
            ida_idp.PR_RNAMESOK | ida_idp.PR_NO_SEGMOVE | ida_idp.PRN_HEX)
    cnbits = dnbits = 8
    psnames = ['luare']
    plnames = ['Lua RE bytecode']
    reg_names = [f'R{i}' for i in range(256)] + ['CS', 'DS']
    reg_first_sreg = reg_code_sreg = 256
    reg_last_sreg = reg_data_sreg = 257
    segreg_size = 0
    instruc_start = 0
    instruc_end = len(PROCESSOR_OPNAMES)
    instruc = [dict(name=n, feature=features(n)) for n in PROCESSOR_OPNAMES]
    icode_return = OPNAMES.index('RETURN')
    tbyte_size = 0
    assembler = dict(
        flag=ida_idp.ASH_HEXF3 | ida_idp.AS_UNEQU | ida_idp.AS_COLON,
        uflag=0, name='Lua RE bytecode listing', origin='org', end='end',
        cmnt=';', ascsep='"', accsep="'", esccodes="\\\"'",
        a_ascii='db', a_byte='db', a_word='dw', a_dword='dd', a_qword='dq',
        a_float='dd', a_double='dq', a_bss='%s dup ?', a_seg='seg', a_curip='$',
        a_public='public', a_weak='weak', a_extrn='extrn', a_comdef='',
        a_align='align', lbrace='(', rbrace=')', a_mod='%', a_band='&',
        a_bor='|', a_xor='^', a_bnot='~', a_shl='<<', a_shr='>>')

    def ev_newfile(self, filename):
        database.reset()
        return 0

    def ev_oldfile(self, filename):
        database.reset()
        return 0

    def ev_term(self):
        self.database_hooks.unhook()
        database.reset()
        return 0

    def ev_ana_insn(self, insn):
        model = database.instruction_at(insn.ea)
        if model is None:
            return 0
        insn.itype, insn.size = model.opcode, model.size
        for i, src in enumerate(model.operands()):
            op = insn.ops[i]
            op.dtype = ida_ua.dt_qword
            if src.kind == 'reg':
                op.type, op.reg = ida_ua.o_reg, src.value
            elif src.kind == 'imm':
                op.type, op.value = ida_ua.o_imm, src.value & ((1 << 64) - 1)
                op.specflag1 = int(src.value < 0)
            else:
                op.type = ida_ua.o_near if src.kind == 'jump' else ida_ua.o_mem
                op.addr = database.operand_address(model.proto, src)
                op.specflag1 = {'const': 1, 'upval': 2, 'proto': 3, 'jump': 0}[src.kind]
                op.specval = src.value
        return insn.size

    def ev_emu_insn(self, insn):
        model = database.instruction_at(insn.ea)
        if model is None:
            return False
        p = model.proto
        for pc, kind in model.successors():
            if 0 <= pc < len(p.words):
                target = p.code_offset + pc * 4
                ida_xref.add_cref(insn.ea, target, ida_xref.fl_F if kind == 'flow' else ida_xref.fl_JN)
        for op in model.operands():
            if op.kind in ('const', 'upval', 'proto'):
                kind = ida_xref.dr_O if op.kind == 'proto' else ida_xref.dr_R
                if op.kind == 'upval' and model.name == 'SETUPVAL':
                    kind = ida_xref.dr_W
                ida_xref.add_dref(insn.ea, database.operand_address(p, op), kind)
        analysis = database.get_analysis()
        call = analysis.by_ea.get(insn.ea) if analysis else None
        if call is not None and call.callee >= 0:
            ida_xref.add_cref(insn.ea, call.callee, ida_xref.fl_CN)
        return True

    def ev_out_operand(self, ctx, op):
        if op.type == ida_ua.o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif op.type == ida_ua.o_imm:
            val = op.value - (1 << 64) if op.specflag1 else op.value
            ctx.out_line(str(val), ida_lines.COLOR_NUMBER)
        elif op.type in (ida_ua.o_mem, ida_ua.o_near):
            if not ctx.out_name_expr(op, op.addr, op.addr):
                ctx.out_line(f'0x{op.addr:X}', ida_lines.COLOR_NUMBER)
        else:
            return False
        return True

    def ev_out_insn(self, ctx):
        ctx.out_mnemonic()
        for i in range(8):
            if ctx.insn.ops[i].type == ida_ua.o_void:
                break
            if i:
                ctx.out_symbol(',')
                ctx.out_char(' ')
            ctx.out_one_operand(i)
        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def ev_is_ret_insn(self, insn, flags):
        return 1 if PROCESSOR_OPNAMES[insn.itype] in ('RETURN', 'RETURN0', 'RETURN1', 'TAILCALL') else -1

    def ev_may_be_func(self, insn, state):
        p = database.prototype_at(insn.ea)
        return 100 if p and insn.ea == p.code_offset else 0

    def ev_is_basic_block_end(self, insn, call_insn_stops_block):
        model = database.instruction_at(insn.ea)
        if model is None:
            return 0
        if call_insn_stops_block and model.name in ('CALL', 'TAILCALL', 'TFORCALL'):
            return 1
        successors = model.successors()
        return 1 if len(successors) != 1 or successors[0][1] == 'jump' else -1

    def ev_out_header(self, ctx):
        ctx.out_line('; Lua RE bytecode — lua_re extension; addresses = input file offsets')
        ctx.flush_outbuf()
        return 1

    def ev_out_segstart(self, ctx, seg):
        ctx.out_line('; ' + ida_segment_name(seg))
        ctx.flush_outbuf()
        return 1

    def ev_out_segend(self, ctx, seg):
        return 1

def ida_segment_name(seg):
    import ida_segment
    return ida_segment.get_segm_name(seg)

def PROCESSOR_ENTRY():
    return lua_re_processor_t()
