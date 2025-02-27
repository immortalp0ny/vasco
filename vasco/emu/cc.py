
import ida_funcs

from triton import (
    TritonContext, MemoryAccess
)

from .interfaces import ida_func_cc_t
from ..utils.ida_utils import get_size_of_ptr


class ida_func_cc_win_fastcall_amd64_t(ida_func_cc_t):
    def __init__(self):
        self._ptrsz = get_size_of_ptr()

    def set_arg(self, ctx: TritonContext, index: int, value: int) -> bool:
        argregs = {
            0: ctx.registers.rcx,
            1: ctx.registers.rdx,
            2: ctx.registers.r8,
            3: ctx.registers.r9
        }
        argreg = argregs.get(index)
        if argreg:
            ctx.setConcreteRegisterValue(argreg, value)
            return
        
        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
        argsp = sp + self._ptrsz + self._ptrsz * index  

        ctx.setConcreteMemoryValue(
            MemoryAccess(argsp, self._ptrsz),
            value,
            callbacks=False 
        )

    def get_arg(self, ctx: TritonContext, index: int) -> int:
        argregs = {
            0: ctx.registers.rcx,
            1: ctx.registers.rdx,
            2: ctx.registers.r8,
            3: ctx.registers.r9
        }
        argreg = argregs.get(index)
        if argreg:
            return ctx.getConcreteRegisterValue(argreg)

        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
        
        argsp = sp + self._ptrsz + self._ptrsz * index

        return ctx.getConcreteMemoryValue(
            MemoryAccess(argsp, self._ptrsz),
            callbacks=False 
        )

    def get_return(self, ctx: TritonContext) -> int:
        return ctx.getConcreteRegisterValue(ctx.registers.rax)

    def set_return(self, ctx: TritonContext,  value: int):
        return ctx.setConcreteRegisterValue(ctx.registers.rax, value)

    def get_return_address(self, ctx: TritonContext):
        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

        return ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        ) 

    def simulate_return(self, ctx: TritonContext,  value: int):
        self.set_return(ctx, value)

        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

        return_address = ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        )

        ctx.setConcreteRegisterValue(ctx.registers.rip, return_address)
        ctx.setConcreteRegisterValue(
            ctx.registers.rsp,
            sp + self._ptrsz
        )

    def simulate_return_with_symbolic(self, ctx: TritonContext, ast):
        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

        return_address = ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        )

        ctx.setConcreteRegisterValue(ctx.registers.rip, return_address)
        ctx.setConcreteRegisterValue(
            ctx.registers.rsp,
            sp + self._ptrsz
        )
        
        zx_bitsize = ctx.registers.rax.getBitSize() - ast.getBitvectorSize()
        if zx_bitsize:
            ast = ctx.getAstContext().zx(zx_bitsize, ast)

        return_symexpr = ctx.newSymbolicExpression(
            ast, f"symbolized_return_value_for_{return_address:08X}"
        )
        return_value = ctx.evaluateAstViaSolver(ast)
        # immortalp0ny: it is very important to set concrete value before we assign symbolic value
        #               because if do it otherwise then concrete value destroy symbolic variable 
        self.set_return(ctx, return_value)

        ctx.assignSymbolicExpressionToRegister(
            return_symexpr,
            ctx.registers.rax
        )

    def symbolize_arg(self, ctx: TritonContext, index: int, alias: str = ""):
        if not alias:
            alias = f"arg_{index}"
        argregs = {
            0: ctx.registers.rcx,
            1: ctx.registers.rdx,
            2: ctx.registers.r8,
            3: ctx.registers.r9
        }
        argreg = argregs.get(index)
        if argreg:
            return ctx.symbolizeRegister(argreg, alias)
            
        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
        
        argsp = sp + self._ptrsz + self._ptrsz * index

        return ctx.symbolizeMemory(
            MemoryAccess(argsp, self._ptrsz),
            alias
        )
    

class ida_func_cc_win_stdcall_x86_t:
    def __init__(self):
        self._ptrsz = get_size_of_ptr()

    def set_arg(self, ctx: TritonContext, index: int, value: int) -> bool:
        pass

    def get_arg(self, ctx: TritonContext, index: int) -> int:
        pass

    def get_return(self, ctx: TritonContext) -> int:
        return ctx.getConcreteRegisterValue(ctx.registers.eax)

    def set_return(self, ctx: TritonContext,  value: int):
        return ctx.setConcreteRegisterValue(ctx.registers.eax, value)

    def get_return_address(self, ctx: TritonContext):
        sp = ctx.getConcreteRegisterValue(ctx.registers.esp)

        return ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        ) 

    def simulate_return(self, ctx: TritonContext,  value: int):
        self.set_return(ctx, value)

        sp = ctx.getConcreteRegisterValue(ctx.registers.esp)

        return_address = ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        )

        ctx.setConcreteRegisterValue(ctx.registers.eip, return_address)
        ctx.setConcreteRegisterValue(
            ctx.registers.esp,
            sp + self._ptrsz
        )

    def simulate_return_with_symbolic(self, ctx: TritonContext, ast):
        sp = ctx.getConcreteRegisterValue(ctx.registers.esp)

        return_address = ctx.getConcreteMemoryValue(
            MemoryAccess(sp, self._ptrsz),
            callbacks=False 
        )

        ctx.setConcreteRegisterValue(ctx.registers.eip, return_address)
        ctx.setConcreteRegisterValue(
            ctx.registers.esp,
            sp + self._ptrsz
        )
        
        zx_bitsize = ctx.registers.eax.getBitSize() - ast.getBitvectorSize()
        if zx_bitsize:
            ast = ctx.getAstContext().zx(zx_bitsize, ast)

        return_symexpr = ctx.newSymbolicExpression(
            ast, f"symbolized_return_value_for_{return_address:08X}"
        )
        return_value = ctx.evaluateAstViaSolver(ast)
        # immortalp0ny: it is very important to set concrete value before we assign symbolic value
        #               because if we do it after then concrete value destroy symbolic variable 
        self.set_return(ctx, return_value)

        ctx.assignSymbolicExpressionToRegister(
            return_symexpr,
            ctx.registers.eax
        )

    def symbolize_arg(self, ctx: TritonContext, index: int, alias: str = ""):
        pass
    