from dataclasses import dataclass
from typing import Dict

from .dyncfg import dyncfg_t
from ..emu.emu import ida_func_emulator_t

from ..utils import find_first_jcc
from ..utils.log import vasco_log, vasco_log_format_br
from ..utils.ida_utils import hr_loop_t

from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE, OPERAND, REG
)


class loop_t:
    def __init__(self, dyncfg: dyncfg_t, hrloop: hr_loop_t):
        self.hrloop = hrloop
        self.dyncfg = dyncfg

        self.ctr = 1

        self.has_condition = self.hrloop.cond is not None
        self.has_init      = False
        self.has_step      = False

        self.br_exits = list()
        
        self.br_cond_continue = tuple()
        self.br_cond_exit     = tuple()

        self._init_loop_br_exits()

        if self.has_condition:
            self._init_loop_cond_branches()

        self.br_exits.append(self.br_cond_exit)
            
    def _init_loop_br_exits(self):
        fixed = []

        for exit_ea in self.hrloop.exits:
            jcc_ea, jcc_instruction = find_first_jcc(
                self.dyncfg.emu, exit_ea
            )
            fixed.append(jcc_ea)

            true_address  = jcc_instruction.getOperands()[0].getValue()
            false_address = jcc_instruction.getSize() + jcc_ea

            true_belongs_to_loop = self._belong_to_loop_body(true_address)
            false_belongs_to_loop = self._belong_to_loop_body(false_address)

            # print(f"jcc={jcc_ea:08X} t={true_address:08X} f={false_address}")

            if true_belongs_to_loop and false_belongs_to_loop:
                raise RuntimeError(f"unexpected structure of loop loop_ea={self.hrloop.ea:08X}")

            if not true_belongs_to_loop and not false_belongs_to_loop:
                raise RuntimeError(f"unexpected structure of loop loop_ea={self.hrloop.ea:08X}")

            if true_belongs_to_loop:
                self.br_exits.append((jcc_ea, false_address))
            else:
                self.br_exits.append((jcc_ea, true_address))

        self.hrloop.exits = fixed

    def _init_loop_cond_branches(self):
        jcc_ea, jcc_instruction = find_first_jcc(
            self.dyncfg.emu, self.hrloop.cond
        )

        true_address  = jcc_instruction.getOperands()[0].getValue()
        false_address = jcc_instruction.getSize() + jcc_ea
        
        true_belongs_to_loop = self._belong_to_loop_body(true_address)
        false_belongs_to_loop = self._belong_to_loop_body(false_address)

        # print(f"jcc={jcc_ea:08X} t={true_address:08X} f={false_address}")

        if true_belongs_to_loop and false_belongs_to_loop:
            raise RuntimeError(f"unexpected structure of loop loop_ea={self.hrloop.ea:08X}")

        if not true_belongs_to_loop and not false_belongs_to_loop:
            raise RuntimeError(f"unexpected structure of loop loop_ea={self.hrloop.ea:08X}")

        if true_belongs_to_loop:
            self.br_cond_continue = (jcc_ea, true_address)
            self.br_cond_exit     = (jcc_ea, false_address)
        else:
            self.br_cond_continue = (jcc_ea, false_address)
            self.br_cond_exit     = (jcc_ea, true_address)

    def _belong_to_loop_body(self, ea: int):
        # immortalp0ny: Handle case when ea is address of cinsn_t
        #               and corresponding to some hexrays C-Tree entity
        if ea in self.hrloop.body:
            return True
        
        # immortalp0ny: Otherwise loop body instruction can be reached directly by steping through basic block
        #               It can be for instance when C-Tree entity is CALL. Instructions that loads arguments
        #               may be discarded from C-Tree but they are still belongs to the loop and may be
        #               addressed by some JCC that continue or break the loop
        i = ea
        # immortalp0ny: do until we reach the end of dynbb
        belongs = False
        while True:
            instruction: Instruction =  self.dyncfg.emu.get_instruction(i)
            if i in self.hrloop.body:
                belongs = True 
                break

            if i in self.dyncfg.rev and instruction.getType() != OPCODE.X86.CALL:
                break
            i += instruction.getSize()

        return belongs 


class loops_symbolizer_t:

    def __init__(self, dyncfg: dyncfg_t, loop_max_iterations: int = 3):
        self._dyncfg = dyncfg
        self._loop_max_iterations = loop_max_iterations

        self._loops_stack = []
        self._loops: Dict[int, loop_t] = {}

        self._prev = None

    @property
    def loops(self) -> Dict[int, loop_t]:
        return self._loops

    def _top_hr_loop(self) -> hr_loop_t:
        return self._dyncfg.loops[self._loops_stack[-1]]

    def _handle_loop_body(self, emu: ida_func_emulator_t, pc: int, current_loop: hr_loop_t):
        loop = self._loops[current_loop.ea]
        
        br = tuple()
        if self._prev:
            br = (self._prev, pc)

        if br in loop.br_exits:
            breakpoint()
            return self._handle_loop_exit(emu)
        
        if br == loop.br_cond_continue:
            return self._handle_loop_enter(emu, pc)

    def _handle_loop_enter(self, emu: ida_func_emulator_t, pc: int):
        if pc not in self._dyncfg.loops_entries:
            return
        
        breakpoint()
        self._loops_stack.append(pc)
        if pc in self._loops:
            self._loops[pc].ctr += 1

            if self._loops[pc].ctr > self._loop_max_iterations:
                emu.stop(emu.STATUS_MAX_LOOP_ITERATIONS) 

            return
        
        self._loops[pc] = loop_t(self._dyncfg, self._top_hr_loop())

    def _handle_loop_exit(self, emu: ida_func_emulator_t,):
        self._loops_stack.pop()
        
    def cb_before_execution(self, emu: ida_func_emulator_t, pc: int):
        current_loop = None
        if self._loops_stack:
            current_loop = self._top_hr_loop()

        # if pc == 0x1c0055e47:
        #     zf_expr = emu.ctx.getSymbolicRegisters()[REG.X86_64.ZF]
        #     print(f"zf = {zf_expr}")
        #     slicing = emu.ctx.sliceExpressions(zf_expr)
        #     # Sort the slicing and display all expressions with their comments
        #     for k, v in sorted(slicing.items()):
        #         # Here we display the comment to understand the correspondence
        #         # between an expression and its referenced instruction.
        #         print(f"zf.slicing: {k}={v}")
        
        if not current_loop:
            self._handle_loop_enter(emu, pc)
        else:
            self._handle_loop_body(emu, pc, current_loop)

        self._prev = pc

    def reset(self):
        for loop in self._loops.values():
            loop.ctr = 0

        self._loops_stack.clear()
        





    