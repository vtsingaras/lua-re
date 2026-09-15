"""Lua RE Explorer entry point. lua_re extension, 2026-09-15, AGPL-3.0."""
import os
import sys
import ida_diskio
sys.path.insert(0, os.path.join(ida_diskio.get_user_idadir(), 'python'))
from lua_re_ida.explorer import ExplorerPlugin

def PLUGIN_ENTRY():
    return ExplorerPlugin()
