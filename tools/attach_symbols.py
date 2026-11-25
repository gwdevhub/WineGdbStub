import os
import re

import gdb

DEFAULT_MODULE = "GWToolboxdll.dll"
TEXT_RVA = 0x1000
MODULE_LINE = re.compile(r"^0x([0-9a-fA-F]+) 0x[0-9a-fA-F]+ (.+)$", re.MULTILINE)


def module_base(name):
    output = gdb.execute("monitor modules", to_string=True)
    for match in MODULE_LINE.finditer(output):
        if match.group(2).strip().lower() == name.lower():
            return int(match.group(1), 16)
    raise gdb.GdbError("%s is not loaded in the game; monitor modules said:\n%s" % (name, output))


def attach(module=DEFAULT_MODULE, debug_file=None):
    if not debug_file:
        raise gdb.GdbError("usage: attach_symbols [module] <debug-file>")
    gdb.execute("set architecture i386")
    base = module_base(module)
    text = base + TEXT_RVA
    gdb.execute("add-symbol-file %s 0x%x" % (os.path.abspath(debug_file), text))
    print("%s at 0x%08x, symbols loaded with .text at 0x%08x" % (module, base, text))


class AttachSymbols(gdb.Command):
    """attach_symbols [module] <debug-file>: load a loaded DLL's symbols at its real address (needs the stub's monitor command)."""

    def __init__(self):
        super().__init__("attach_symbols", gdb.COMMAND_DATA)

    def invoke(self, argument, from_tty):
        args = gdb.string_to_argv(argument)
        attach(*args[:2])


AttachSymbols()
