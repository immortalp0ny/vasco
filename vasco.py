import idc
import idaapi

import vasco

idaapi.require("vasco")
idaapi.require("vasco.utils")
idaapi.require("vasco.utils.ida_utils")
idaapi.require("vasco.utils.log")
idaapi.require("vasco.utils.tri")
idaapi.require("vasco.emu")
idaapi.require("vasco.emu.const")
idaapi.require("vasco.emu.cc")
idaapi.require("vasco.emu.interfaces")
idaapi.require("vasco.emu.heap")
idaapi.require("vasco.emu.mem")
idaapi.require("vasco.emu.emu")
idaapi.require("vasco.emu.tracer")
idaapi.require("vasco.forms.ui_widget")
idaapi.require("vasco.forms.ui_results")
idaapi.require("vasco.forms.ui_memory")
idaapi.require("vasco.forms.ui_emu")
idaapi.require("vasco.forms.ui_actions")
idaapi.require("vasco.forms.ui_func_emu")
idaapi.require("vasco.os.win")
idaapi.require("vasco.symbol.dyncfg")
idaapi.require("vasco.symbol.loops")
idaapi.require("vasco.symbol.explorer")
idaapi.require("vasco.symbol.plugin")

from vasco.forms.ui_func_emu import ui_func_emu_t

ea = idc.here()

ui = ui_func_emu_t(ea)
ui.Show()
