from typing import Dict, List, Any, Tuple

import ida_funcs
import ida_ida

from .cc import ida_func_cc_win_fastcall_amd64_t
from .mem import ida_func_emulator_memory_t
from .tracer import ida_func_emulator_block_tracer_t

from ..utils.ida_utils import (
    ida_func_frame_t,
    get_size_of_ptr,
    find_ea_by_demangled_name,
    find_ea_by_name
)
from ..utils.log import (
    vasco_log,
    vasco_cpu_log
)
from ..utils.tri import tri_get_single_instruction

from ..os.win import windows_hooks_t


from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE, OPERAND
)

from .heap import easy_heap_t
from .const import (
    CFG_DISPATCHER_ICALL_NOP,
    DEFAULT_STACK_BOTTOM,
    DEFAULT_STACK_SIZE,
    FT_PE,
    FT_ELF,
    DEFAULT_MAX_INSTRUCTIONS_COUNT,
    DEFAULT_HEAP_BASE,
    DEFAULT_HEAP_SIZE
)


class ida_func_emulator_t:
    CALLBACK_ID_FUNCTION_RETURN    = 0x01
    CALLBACK_ID_FUNCTION_CALL      = 0x02
    CALLBACK_ID_BEFORE_EXECUTION   = 0x03
    CALLBACK_ID_AFTER_EXECUTION    = 0x04
    CALLBACK_ID_SETUP              = 0x05
    CALLBACK_ID_SYMBOLIC_PTR_READ  = 0x06
    CALLBACK_ID_SYMBOLIC_PTR_WRITE = 0x07

    CALLBACKS = [
        CALLBACK_ID_FUNCTION_RETURN, 
        CALLBACK_ID_FUNCTION_CALL,
        CALLBACK_ID_BEFORE_EXECUTION,
        CALLBACK_ID_AFTER_EXECUTION,
        CALLBACK_ID_SETUP,
        CALLBACK_ID_SYMBOLIC_PTR_READ,
        CALLBACK_ID_SYMBOLIC_PTR_WRITE
    ]

    STATUS_NO_FAULT            = 1
    STATUS_FAULT_DE            = 2
    STATUS_FAULT_BP            = 3
    STATUS_FAULT_UD            = 4
    STATUS_FAULT_GP            = 5
    STATUS_BAD_CODE            = 6
    STATUS_MAX_INSTRUCTIONS    = 7
    STATUS_MAX_LOOP_ITERATIONS = 8

    def __init__(
            self,
            ea: int,
            tracer_type = ida_func_emulator_block_tracer_t,
            hooks:        Dict[int, Any] = {},
            import_hooks: Dict[str, Any] = {},
            callbacks:    Dict[int, List[Any]] = {},
            sp_bottom:    int = DEFAULT_STACK_BOTTOM,
            sp_size:      int = DEFAULT_STACK_SIZE,
            heap:         easy_heap_t = None,
            repr_mode:    AST_REPRESENTATION = AST_REPRESENTATION.PYTHON,
            
            max_instructions_count: int = DEFAULT_MAX_INSTRUCTIONS_COUNT
        ):
        
        self._func = ida_funcs.get_func(ea)
        if not self._func:
            raise ValueError('ea does not belong to any function')

        self._tracer_type = tracer_type
        self._tracer      = None
        self._os          = None
        
        self._func_frame = ida_func_frame_t(self._func)
        
        self._hooks        = hooks
        self._import_hooks = import_hooks
        self._callbacks    = callbacks

        self._ctx = None
        self._stop = False

        # @immortalp0ny: find out what arch it analyzes (amd64 or x86)
        if get_size_of_ptr():
            self._ptrsz    = CPUSIZE.QWORD
            self._tri_arch = ARCH.X86_64
        else:
            self._ptrsz    = CPUSIZE.DWORD
            self._tri_arch = ARCH.X86

        # @immortalp0ny: Triton setup properties  
        self._tri_modes = [
            (MODE.ALIGNED_MEMORY,         True),
            (MODE.MEMORY_ARRAY,           False),
            (MODE.SYMBOLIZE_LOAD,         False),
            (MODE.SYMBOLIZE_STORE,        False),
            (MODE.PC_TRACKING_SYMBOLIC,   True),
            (MODE.TAINT_THROUGH_POINTERS, False)
        ]

        self._tri_ast_representation_mode = repr_mode

        self._sp_bottom = sp_bottom
        self._sp_size = sp_size

        self._heap = heap
        if not self._heap:
            self._heap = easy_heap_t(
                DEFAULT_HEAP_BASE, DEFAULT_HEAP_SIZE
            )

        self._max_instructions_count = max_instructions_count

        self._status = self.STATUS_NO_FAULT
        
        self._init_cfg()

        self.reset()

        self._init_os()

    def _is_bad_pc(self, pc: int):
        if self._ptrsz == CPUSIZE.QWORD:
            return pc == 0xFFFFFFFFFFFFFFFF
        else:
            return pc == 0xFFFFFFFF

    def _set_status(self, ok):
        if ok == EXCEPTION.FAULT_BP:
            self._status = self.STATUS_FAULT_BP
        elif ok == EXCEPTION.FAULT_DE:
            self._status = self.STATUS_FAULT_DE
        elif ok == EXCEPTION.FAULT_GP:
            self._status = self.STATUS_FAULT_GP
        elif ok == EXCEPTION.FAULT_UD:
            self._status = self.STATUS_NO_FAULT
            
    def _invoke_callbacks(self, callback_id: int, *args, **kwargs):
        for cb in reversed(self._callbacks.get(callback_id, [])):
            cb(*args, **kwargs)

    def _init_cfg(self):
        icall_ea = find_ea_by_name(CFG_DISPATCHER_ICALL_NOP)
        if not icall_ea:
            return
        
        vasco_log('?', '(cfg): global hook set', icall_nop_ea=f"{icall_ea:08X}")

        self._hooks[icall_ea] = self._hook_icall_nop

    def _init_os(self):
        ft = ida_ida.inf_get_filetype()
        
        vasco_log('?', f"(emu.os):  ft={ft} is_pe={ft == FT_PE} is_elf={ft == FT_ELF}")

        if ida_ida.inf_get_filetype() == FT_PE:
            self._os = windows_hooks_t(self)

    def _hook_icall_nop(self, emu: 'ida_func_emulator_t'):
        indirect_call_target = self._ctx.getConcreteRegisterValue(self._ctx.registers.rax)
        indirect_call_ret    = self._ctx.getConcreteMemoryValue(
            MemoryAccess(self._ctx.getConcreteRegisterValue(self._ctx.registers.rsp), self._ptrsz),
            callbacks=False
        ) 
        self._stack_ret.append(indirect_call_ret)
        
        vasco_log('?', '(emu.cfg): indirect call', target=f"{indirect_call_target:08X}", ret=f"{indirect_call_ret:08X}")

        self._invoke_callbacks(
            self.CALLBACK_ID_FUNCTION_CALL,
            self,
            indirect_call_target
        )

    def _hook_mem_read_by_symbolic_source(self, instruction: Instruction):
        opmem = []
        for operand in instruction.getOperands():
            if operand.getType() != OPERAND.MEM:
                continue

            opmem.append(operand)

        if len(opmem) != 1:
            return

        base_reg = opmem.pop().getBaseRegister()
        if not self._ctx.isRegisterSymbolized(base_reg):
            return
        
        astctx = self._ctx.getAstContext()
        
        base_ast = astctx.unroll(self._ctx.getSymbolicRegister(base_reg).getAst())
        base_vars = []
        for ast in astctx.search(base_ast, AST_NODE.VARIABLE):
            astvar = ast.getSymbolicVariable()
            if astvar not in base_vars:
                    base_vars.append(astvar)

        # @immortalp0ny: TODO Handle case when we deal with some symbolic array.
        #                In order to handle this we should create new symbolic varaible
        #                and assign it that instruction. But now i am going to skip it

        if len(base_vars) != 1:
            return

        base_var = base_vars.pop()

        self._invoke_callbacks(
            self.CALLBACK_ID_SYMBOLIC_PTR_READ, self, instruction, base_var
        )

    @property
    def ctx(self) -> TritonContext:
        return self._ctx

    @property
    def cc(self):
        return self._cc

    @property
    def mem(self):
        return self._mem
    
    @property
    def tr(self):
        return self._tracer
    
    @property
    def ea(self):
        return self._func.start_ea
    
    @property
    def func(self):
        return self._func

    @property
    def status(self):
        return self._status

    def run(self) -> bool:
        pc = self._func.start_ea
        ctr = 0
        while pc and not self._is_bad_pc(pc) and not self._stop:
            hook_fn = self._hooks.get(pc)
            if hook_fn:
                hook_fn(self)

                hooked_pc = self._ctx.getConcreteRegisterValue(self._ctx.registers.rip)
                hooked_pc_changed = hooked_pc != pc
                
                vasco_log('?', '(emu.hooks): hook called', pc=f"{pc:08X}", change=f"{hooked_pc_changed}")
                
                if hooked_pc_changed:
                    pc = hooked_pc
                    continue

            instruction = self.get_instruction(pc)
            
            self._hook_mem_read_by_symbolic_source(instruction)

            vasco_cpu_log(self._ctx, instruction, self._tri_regs_gpr)
            
            self._invoke_callbacks(self.CALLBACK_ID_BEFORE_EXECUTION, self, pc)

            ok = self._ctx.processing(instruction)
            if ok != EXCEPTION.NO_FAULT:
                self._set_status(ok)

                return ok != EXCEPTION.NO_FAULT

            self._invoke_callbacks(self.CALLBACK_ID_AFTER_EXECUTION, self, pc)

            if instruction.getType() == OPCODE.X86.RET:
                if len(self._stack_ret) == 0:
                    break

                self._invoke_callbacks(self.CALLBACK_ID_FUNCTION_RETURN, self, self._stack_ret.pop())
            
            if instruction.getType() == OPCODE.X86.CALL:
                self._stack_ret.append(pc + instruction.getSize())
                
                self._invoke_callbacks(
                    self.CALLBACK_ID_FUNCTION_CALL,
                    self,
                    self._ctx.getConcreteRegisterValue(self._ctx.registers.rip)
                )
                                         
            if instruction.getType() == OPCODE.X86.INT:
                raise RuntimeError(f'int instruction was reached at pc={pc}')

            pc = self._ctx.getConcreteRegisterValue(self._ctx.registers.rip)

            ctr += 1

            if ctr >= self._max_instructions_count:
                self._status = self.STATUS_MAX_INSTRUCTIONS
                return False
        
        if self._is_bad_pc(pc):
            self._status = self.STATUS_BAD_CODE
            return False

        return True

    def reset(self):
        # @immortalp0ny: in this function I keep everything which should
        # be re/initialized each time when run() method called
        if self._ctx:
            self._ctx.reset()
            self._ctx = None
        
        # @immortalp0ny: block of Triton initialization
        self._ctx = TritonContext()
        self._ctx.setArchitecture(self._tri_arch)
        self._tri_regs_gpr = [
            self._ctx.registers.rax,   
            self._ctx.registers.rbx,   
            self._ctx.registers.rcx,   
            self._ctx.registers.rdx,   
            self._ctx.registers.rdi,   
            self._ctx.registers.rsi,   
            self._ctx.registers.rbp,   
            self._ctx.registers.rsp,   
            self._ctx.registers.rip,   
            self._ctx.registers.r8,    
            self._ctx.registers.r9,    
            self._ctx.registers.r10,   
            self._ctx.registers.r11,   
            self._ctx.registers.r12,   
            self._ctx.registers.r13,   
            self._ctx.registers.r14,   
            self._ctx.registers.eflags,
        ]

        for tri_mode in self._tri_modes:
            self._ctx.setMode(tri_mode[0], tri_mode[1])

        self._ctx.setAstRepresentationMode(self._tri_ast_representation_mode)
        
        if self._heap:
            self._heap.reset(free_list = self._heap.free_list)

        self._mem = ida_func_emulator_memory_t(
            self,
            sp_bottom=self._sp_bottom,
            sp_size=self._sp_size,
            heap=self._heap
        )
        for k, v in self._import_hooks.items():
            resolved = self._mem.get_import_by_name(k)
            if not resolved:
                raise ValueError(f"unknown import name={k}")

            self._hooks[resolved] = v

        self._cc = ida_func_cc_win_fastcall_amd64_t()
        
        self._stack_ret = []

        if not self._tracer:
            self._tracer = self._tracer_type(self, self._func)
            
            self._callbacks.setdefault(self.CALLBACK_ID_FUNCTION_CALL,[]).append(
                self._tracer.cb_after_call_execution
            )
            self._callbacks.setdefault(self.CALLBACK_ID_BEFORE_EXECUTION,[]).append(
                self._tracer.cb_before_execution
            )
        else:
            self._tracer.reset()

        self._invoke_callbacks(self.CALLBACK_ID_SETUP, self)

    def stop(self, status = STATUS_NO_FAULT):
        self._stop = True
        if status != self.STATUS_NO_FAULT:
            self._status = status
    
    def get_instruction(self, ea: int, build_semantics: bool = False) -> Instruction:
        return tri_get_single_instruction(
            self._ctx, ea, build_semantics=build_semantics
        )

    def get_current_instruction(self) -> Instruction:
        return self.get_instruction(
            self._ctx.getConcreteRegisterValue(self._ctx.registers.rip)
        )

    def set_hook(self, ea: int, fn) -> bool:
        if self._hooks.get(ea):
            return False
        
        self._hooks[ea] = fn

        vasco_log('?', f'(emu.hooks): new hook ea={ea:08X}')
        
        return True
    
    def set_import_hook(self, name: str, fn) -> bool:
        ea = self._mem.get_import(name)
        if not ea:
            return False
        
        vasco_log('?', f'(emu.hooks): new import hook ea={ea:08X} name={name}')

        return self.set_hook(ea, fn)
    
    def add_callback(self, cbtype, cbfn):
        if cbtype not in self.CALLBACKS:
            raise ValueError(f"unsupported callback type cbtype={cbtype}")
        
        self._callbacks.setdefault(cbtype, []).append(cbfn)

    @staticmethod
    def run_first_func_by_name(name: str, **kwargs):
        ea = find_ea_by_demangled_name(name)
        if not ea:
            raise RuntimeError(f"function with name={name} not found")
        
        emu = ida_func_emulator_t(ea, **kwargs)
        emu.run()

        return emu
            
    @staticmethod
    def run_at(ea: int, **kwargs):
        emu = ida_func_emulator_t(ea, **kwargs)
        emu.run()

        return emu
