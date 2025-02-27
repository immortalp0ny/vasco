import ida_funcs
import ida_gdl

from .interfaces import ida_func_emulator_tracer_t


class ida_func_emulator_block_tracer_t(ida_func_emulator_tracer_t):
    def __init__(self, func: ida_funcs.func_t):
        super().__init__(func)

    @property
    def blocks(self):
        return self._blocks
    
    @property
    def blocks_ranges(self):
        return self._blocks_ranges
    
    @property
    def tr(self):
        return self._tr

    @property
    def trset(self):
        return self._trset
    
    @property
    def funcs(self):
        return self._funcs
    
    @property
    def fwd(self):
        return self._fwdmap

    @property
    def rev(self):
        return self._revmap

    def cb_before_execution(self, emu, pc: int):
        if pc not in self._blocks:
            return
        
        self._trset.add(pc)
        self._tr.append(pc)


    def cb_after_call_execution(self, emu, target: int):
        if target in self._funcs or emu.mem.is_import(target):
            return
        
        func = ida_funcs.get_func(target)
        if not func:
            print("WARNING! call target is bad")
            return
        
        self._funcs.add(target)
        
        self.extend(func)
        
    def reset(self):
        self._trset = set()
        self._tr = list()        
