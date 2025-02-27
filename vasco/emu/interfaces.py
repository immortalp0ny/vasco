from abc import ABC, abstractmethod

import idc
import ida_gdl
import ida_funcs

from triton import TritonContext

from vasco.utils.ida_utils import get_size_of_ptr 


class ida_func_cc_t(ABC):
    def __init__(self, func: ida_funcs.func_t):
        self._func = func
        self._ptrsz = get_size_of_ptr()

    @abstractmethod
    def set_arg(self, ctx: TritonContext, index: int, value: int) -> bool:
        pass

    @abstractmethod
    def get_arg(self, ctx: TritonContext, index: int) -> int:
        pass

    @abstractmethod
    def get_return(self, ctx: TritonContext) -> int:
        pass
    
    @abstractmethod
    def set_return(self, ctx: TritonContext,  value: int):
        pass
    
    @abstractmethod
    def simulate_return(self, ctx: TritonContext,  value: int):
        pass
    
    @abstractmethod
    def symbolize_arg(self, ctx: TritonContext, index: int, alias: str = ""):
        pass

    @abstractmethod
    def simulate_return_with_symbolic(self, ctx: TritonContext, ast):
        pass


class ida_func_emulator_tracer_t(ABC):
    def __init__(self, emu, func: ida_funcs.func_t):
        self._emu = emu
        self._func = func
        self._funcs = set([self._func.start_ea])
        # @immortalp0ny: set of all basic blocks visited in trace
        # each basic block is represented by block_start_ea
        self._blocks = set()

        # @immortalp0ny: set of all basic blocks visited in trace
        # in form of tuple => (block_start_ea, block_last_ea)
        self._blocks_ranges = set()
  
        # @immortalp0ny: blocks trace
        self._tr = list()
        # @immortalp0ny: unique blocks in trace
        self._trset = set()
        
        # @immortalp0ny: mapping block_start_ea -> block_last_ea
        self._fwdmap = dict()
        # @immortalp0ny: mapping block_last_ea -> block_start_ea
        self._revmap = dict()
        
        # @immortalp0ny: set of all funcs visited in trace
        self._funcs = set([func.start_ea])
        
        self.extend(func)

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
    def func(self):
        return self._func
    
    @property
    def fwd(self):
        return self._fwdmap
    
    @property
    def emu(self):
        return self._emu

    @property
    def rev(self):
        return self._revmap

    def reset(self):
        self._trset = set()
        self._tr = list()

    def extend(self, func: ida_funcs.func_t):
        for block in ida_gdl.FlowChart(func):
            bb_begin = block.start_ea
            bb_last  = idc.prev_head(block.end_ea)
            
            self._blocks.add(bb_begin)
            self._blocks_ranges.append(
                (bb_begin, bb_last)
            )
            
            self._fwdmap[bb_begin] = bb_last 
            self._revmap[bb_last] = bb_begin

    @abstractmethod
    def cb_before_execution(self, emu, pc: int):
        pass

    @abstractmethod
    def cb_after_call_execution(self, emu, target: int):
        pass
