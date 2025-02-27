from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE
)

def tri_get_single_instruction(ctx: TritonContext, ea: int, build_semantics: bool = False) -> Instruction:
    opcode = ctx.getConcreteMemoryAreaValue(ea, 16)

    instruction = Instruction()
    instruction.setOpcode(opcode)
    instruction.setAddress(ea)

    ctx.disassembly(instruction)

    if build_semantics:
        ctx.buildSemantics(instruction)

    return instruction