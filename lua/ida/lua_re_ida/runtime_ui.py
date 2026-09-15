"""IDA 9.4 Java runtime chooser. Kept out of headless provider imports."""
import os
import ida_kernwin
from .runtime import discover_java, select_java, INSTALL_HELP, INSTALL_URL, JavaRuntimeError


class RuntimeChooser(ida_kernwin.Choose):
    def __init__(self, runtimes):
        super().__init__('Lua RE: Configure Java runtime',
                         [['Runtime', 28], ['Version', 16], ['Executable', 100]])
        self.runtimes = runtimes

    def OnGetSize(self):
        return len(self.runtimes) + 2

    def OnGetLine(self, n):
        if n == 0:
            return ['Automatic discovery', '', 'Use JAVA_HOME, PATH, and installed runtimes']
        if n == len(self.runtimes)+1:
            return ['Browse for Java executable...', '', 'Choose java or java.exe']
        item = self.runtimes[n-1]
        return ['Java', item.version, item.path]


def configure_java():
    runtimes = discover_java()
    if not runtimes:
        answer = ida_kernwin.ask_buttons('Browse for Java', 'Installation help', 'Cancel',
                                         ida_kernwin.ASKBTN_BTN1, INSTALL_HELP)
        if answer == ida_kernwin.ASKBTN_BTN2:
            import webbrowser
            webbrowser.open(INSTALL_URL)
            return False
        if answer != ida_kernwin.ASKBTN_BTN1:
            return False
        selection = 1
    else:
        selection = RuntimeChooser(runtimes).Show(True)
        if selection < 0:
            return False
    if selection == len(runtimes)+1:
        path = ida_kernwin.ask_file(False, '*', 'Choose the Java executable (java or java.exe)')
        if not path:
            return False
    elif selection == 0:
        path = None
    else:
        path = runtimes[selection-1].path
    try:
        result = select_java(path)
        from .pseudocode import clear_cache
        clear_cache()
    except (OSError, JavaRuntimeError) as exc:
        ida_kernwin.warning(str(exc))
        return False
    ida_kernwin.msg('[Lua RE] Java: ' + (result.path if result else 'automatic discovery') + '\n')
    if os.environ.get('LUA_RE_JAVA') or os.environ.get('LUA54_JAVA'):
        ida_kernwin.warning('The Java environment override remains active. Unset LUA_RE_JAVA/LUA54_JAVA and restart IDA to use the saved choice.')
    return True
