from typing import Dict, List, Any
from io import StringIO

from base64 import b64decode

from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE
)



VASCO_VERSION = "v0.0.1"


def fix_integer_keys(data: Dict[str, Any]):
    fixed = {}
    for k, v in data.items():
        fixed[int(k)] = v

    return fixed


def fix_memory_content(memory_map):
    fixed = {}
    for k, v in memory_map.items():
        encoded_data = v.get('data')
        if encoded_data is not None and encoded_data.startswith("bytes:"):
            v['data'] = b64decode(encoded_data[6:])
        
        fixed[int(k)] = v
        
    return fixed


def lift_triton_ast_node_to_smt_lib(ctx: TritonContext, ast_node, as_assert=True, as_simplify=False):
    stream = StringIO()

    astctx = ctx.getAstContext()
    
    stream.write(f"; generated by vasco ({VASCO_VERSION})\n")
    stream.write("; vars definitions\n")
    defined = set()
    for ast_var in astctx.search(ast_node, AST_NODE.VARIABLE):
        sym_var = ast_var.getSymbolicVariable()
        sym_var_size = sym_var.getBitSize()

        sym_var_name = sym_var.getAlias()
        if sym_var_name in defined:
            continue

        defined.add(sym_var_name)

        stream.write(f"(declare-const {sym_var_name} (_ BitVec {sym_var_size}))\n")

    if as_assert:
        stream.write("\n; assert \n")
        stream.write(f"(assert {ast_node})\n")
        stream.write(f"(check-sat)\n")
        stream.write(f"(get-model)\n")

    if as_simplify:
        stream.write("\n; simplify \n")
        stream.write(f"(simplify {ast_node})\n")

    return stream.getvalue()


def find_first_jcc(emu, start: int):
    i = start

    while True:
        instruction = emu.get_instruction(i)

        if instruction.getType() == OPCODE.X86.JMP or not instruction.isBranch():
            i += instruction.getSize()
            continue
        
        return i, instruction

