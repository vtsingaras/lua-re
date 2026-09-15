"""Native IDA function browser and bytecode details. AGPL-3.0."""
from pathlib import Path
import ida_idaapi
import ida_kernwin
import ida_name
from . import database
from .bytecode import text, display, listing

class FunctionChooser(ida_kernwin.Choose):
    def __init__(self):
        super().__init__('Lua RE functions',
                         [['Address', 12], ['Function', 42], ['Lines', 12],
                          ['Words', 8], ['Params', 8], ['Upvalues', 9], ['Source', 60]])
        self.prototypes = database.get_chunk().prototypes

    def OnGetSize(self):
        return len(self.prototypes)

    def OnGetLine(self, n):
        p = self.prototypes[n]
        return [f'{p.code_offset:08X}', ida_name.get_name(p.code_offset) or p.name,
                f'{p.firstline}-{p.lastline}', str(len(p.words)), str(p.params),
                str(len(p.upvalues)), text(p.source)]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.prototypes[n].code_offset)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

class DetailViewer(ida_kernwin.simplecustviewer_t):
    def __init__(self, p):
        super().__init__()
        self.addresses = {}
        self.proto = p

    def open(self):
        p = self.proto
        if not self.Create(f'Lua RE details: {ida_name.get_name(p.code_offset) or p.name}'):
            return False
        self.AddLine(f'Source: {text(p.source)}:{p.firstline}-{p.lastline}')
        self.AddLine(f'Parameters: {p.params}, vararg: {p.vararg}, registers: {p.stack}')
        self.AddLine('Double-click an instruction to jump to the IDA listing.')
        self.AddLine('')
        self.AddLine('UPVALUES')
        for i, u in enumerate(p.upvalues):
            self.AddLine(f'U{i} {text(u.name)}: parent {"R" if u.instack else "U"}{u.index}, kind={u.kind}')
        self.AddLine('')
        self.AddLine('LOCALS (zero-based PC, end exclusive)')
        for v in p.locals:
            self.AddLine(f'{text(v.name)}: [{v.startpc}, {v.endpc})')
        self.AddLine('')
        self.AddLine('CONSTANTS')
        for i, k in enumerate(p.constants):
            self.AddLine(f'K{i}: {display(k.value)}')
        self.AddLine('')
        self.AddLine('BYTECODE')
        for old in p.instructions():
            ins = database.instruction_at(old.ea) or old
            self.addresses[self.Count()] = ins.ea
            # IDA color-control bytes cannot enter from a quoted Lua string.
            self.AddLine(f'{ins.ea:08X} {ins.pc + 1:5} {ins.render()} ; {ins.comment()}')
        return self.Show()

    def OnDblClick(self, shift):
        position = self.GetPos()
        if position and position[0] in self.addresses:
            ida_kernwin.jumpto(self.addresses[position[0]])
            return True
        return False

class Action(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS if database.get_chunk() else ida_kernwin.AST_DISABLE_ALWAYS

class ExplorerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = 'Lua RE prototype, constant and debug information browser'
    help = 'Open a Lua RE chunk; Ctrl-Alt-L lists functions, Ctrl-Alt-I shows details.'
    wanted_name = 'Lua RE Explorer'
    wanted_hotkey = 'Ctrl-Alt-L'

    def init(self):
        import ida_ida
        if ida_ida.inf_get_procname() != 'luare':
            return ida_idaapi.PLUGIN_SKIP
        import threading
        self.views = []
        self.actions = []
        self.cancel = threading.Event()
        self.decompiling = False
        self.ui_hooks = LuaUIHooks(self)
        self.ui_hooks.hook()
        from .runtime_ui import configure_java
        for name, label, hotkey, callback in (
            ('lua_re:java', 'Lua RE: Configure Java runtime...', '', configure_java),
            ('lua_re:decompile', 'Decompile Lua function', 'F5', self.decompile),
            ('lua_re:calls', 'Lua RE call sites', 'Ctrl-Alt-C', lambda: self.show_index('calls')),
            ('lua_re:constants', 'Lua RE constants and strings', 'Ctrl-Alt-S', lambda: self.show_index('constants')),
            ('lua_re:dependencies', 'Lua RE dependencies', '', lambda: self.show_index('dependencies')),
            ('lua_re:json', 'Export Lua RE analysis JSON...', '', lambda: self.export_analysis('json')),
            ('lua_re:dot', 'Export Lua RE call graph DOT...', '', lambda: self.export_analysis('dot')),
            ('lua_re:details', 'Lua RE function details', 'Ctrl-Alt-I', self.details),
            ('lua_re:export', 'Export Lua RE annotated listing...', '', self.export),
        ):
            handler = Action(callback)
            if ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, handler, hotkey)):
                ida_kernwin.attach_action_to_menu('Edit/Plugins/', name, ida_kernwin.SETMENU_APP)
                self.actions.append((name, handler))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if database.get_chunk():
            self.chooser = FunctionChooser()
            self.chooser.Show(False)

    def details(self):
        p = database.prototype_at(ida_kernwin.get_screen_ea())
        if p is None:
            ida_kernwin.warning('Place the cursor inside a Lua function first.')
            return
        view = DetailViewer(p)
        if view.open():
            self.views.append(view)

    def export(self):
        path = ida_kernwin.ask_file(True, '*.txt', 'Export Lua RE annotated listing')
        if path:
            try:
                Path(path).write_text(listing(database.get_chunk()), encoding='utf-8')
            except OSError as exc:
                ida_kernwin.warning(f'Could not export listing: {exc}')

    def term(self):
        if hasattr(self, 'cancel'):
            self.cancel.set()
            self.ui_hooks.unhook()
        if hasattr(self, 'chooser'):
            self.chooser.Close()
        for name, _ in getattr(self, 'actions', []):
            ida_kernwin.unregister_action(name)
        for view in getattr(self, 'views', []):
            view.Close()
        self.views = []

    def show_index(self, kind):
        chooser = IndexChooser(kind)
        self.views.append(chooser)
        chooser.Show(False)

    def export_analysis(self, mode):
        extension = '*.json' if mode == 'json' else '*.dot'
        path = ida_kernwin.ask_file(True, extension, 'Export Lua RE ' + mode)
        if path:
            a = database.get_analysis()
            try:
                Path(path).write_text(a.to_json() if mode == 'json' else a.callgraph_dot(), encoding='utf-8')
            except OSError as exc:
                ida_kernwin.warning(f'Could not export analysis: {exc}')

    def decompile(self):
        import threading
        import ida_bytes
        from .bytecode import parse
        from .pseudocode import function_source
        p = database.prototype_at(ida_kernwin.get_screen_ea())
        if p is None:
            ida_kernwin.warning('Place the cursor inside a Lua function first.')
            return
        if self.decompiling:
            ida_kernwin.msg('[Lua RE] Decompilation is already running.\n')
            return
        try:
            chunk = database.current_chunk()
            fresh = next(v for v in chunk.prototypes if v.code_offset == p.code_offset)
        except Exception as exc:
            ida_kernwin.warning(f'Cannot decompile current bytes: {exc}')
            return
        name = ida_name.get_name(p.code_offset) or p.name
        self.decompiling = True
        cancel = self.cancel
        ida_kernwin.msg(f'[Lua RE] Decompiling {name} with unluac...\n')
        def worker():
            try:
                result, error, runtime_error = function_source(chunk, fresh, name, cancel), None, False
            except Exception as exc:
                from .runtime import JavaRuntimeError
                result, error, runtime_error = None, str(exc), isinstance(exc, JavaRuntimeError)
            if cancel.is_set():
                return
            def complete():
                if cancel.is_set():
                    return 0
                self.decompiling = False
                if error:
                    if runtime_error:
                        from .runtime_ui import configure_java
                        ida_kernwin.msg('[Lua RE] ' + error + '\n')
                        if configure_java():
                            self.decompile()
                    else:
                        ida_kernwin.warning('Lua decompilation: ' + error)
                else:
                    view = SourceViewer()
                    if view.open(result):
                        self.views.append(view)
                    ida_kernwin.msg(f'[Lua RE] Recovered {len(result.source.splitlines())} lines for {name}.\n')
                return 1
            ida_kernwin.execute_sync(complete, ida_kernwin.MFF_FAST)
        threading.Thread(target=worker, name='lua-re-unluac', daemon=True).start()


class IndexChooser(ida_kernwin.Choose):
    """Filter with Ctrl-F; Enter follows the relevant code/data address."""
    def __init__(self, kind):
        analysis = database.get_analysis()
        self.rows, self.addresses = [], []
        if kind == 'calls':
            columns = [['Address', 12], ['Caller', 35], ['Target (inferred)', 45], ['Arguments', 75]]
            names = {p.code_offset: ida_name.get_name(p.code_offset) for p in analysis.chunk.prototypes}
            for c in analysis.calls:
                self.rows.append([f'{c.ea:08X}', names[c.function], c.target, ', '.join(c.arguments)])
                self.addresses.append(c.ea)
        elif kind == 'dependencies':
            columns = [['Module', 48], ['Require sites', 14], ['First call', 12]]
            for module, sites in sorted(analysis.dependencies.items()):
                self.rows.append([module, str(len(sites)), f'{sites[0]:08X}'])
                self.addresses.append(sites[0])
        else:
            columns = [['Address', 12], ['Function', 35], ['Index', 8], ['Value', 90], ['Uses', 8]]
            for p in analysis.chunk.prototypes:
                for i, k in enumerate(p.constants):
                    from .bytecode import Operand
                    ea = database.operand_address(p, Operand('const', i))
                    self.rows.append([f'{ea:08X}', ida_name.get_name(p.code_offset), str(i),
                                      display(k.value), str(len(analysis.constant_uses.get((p.path, i), [])))])
                    self.addresses.append(ea)
        super().__init__('Lua RE ' + kind, columns)

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.addresses[n])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

class SourceViewer(ida_kernwin.simplecustviewer_t):
    def open(self, source):
        import ida_lines
        if not self.Create(f'Lua pseudocode: {source.name}'):
            return False
        self.source = source
        for line in source.render().splitlines():
            if line.lstrip().startswith('--'):
                line = ida_lines.COLSTR(line, ida_lines.SCOLOR_AUTOCMT)
            self.AddLine(line)
        self.Show()
        return True

class LuaUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def preprocess_action(self, name):
        # Intercept the native Hex-Rays action only for our active processor.
        import ida_ida
        if name == 'hx:GenPseudo' and ida_ida.inf_get_procname() == 'luare':
            self.plugin.decompile()
            return 1
        return 0

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        import ida_ida
        if ida_ida.inf_get_procname() == 'luare':
            for name in ('lua_re:decompile', 'lua_re:details', 'lua_re:calls', 'lua_re:constants'):
                ida_kernwin.attach_action_to_popup(widget, popup, name, 'Lua RE/')
