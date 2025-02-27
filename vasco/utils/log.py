from typing import Tuple


logger_fd = open('vasco.log', 'w')
logger_enabled = False

logger_prefixes = [
    '+',
    '~',
    '!',
    '?'
]
    
cpulogger_fd = open('cpu.vasco.log', 'w')
cpulogger_enabled = True


def __tri_format_reg(ctx, r):
    reg_name = r.getName().upper()
    if len(reg_name) < 3:
        reg_name += " "

    reg_value = ctx.getConcreteRegisterValue(r)
        
    return f"{reg_name} = {reg_value:016X}"

def __tri_format_single_step(ctx, regs):
    lines = []
    for ireg in range(0, len(regs), 3):
        parts = []
        reg = regs[ireg]
        parts.append(
            __tri_format_reg(ctx, reg)
        )

        if ireg + 1 < len(regs): 
            reg = regs[ireg + 1]
            parts.append(
                __tri_format_reg(ctx, reg)
            )

        if ireg + 2 < len(regs):
            reg = regs[ireg + 2]
            parts.append(
                __tri_format_reg(ctx, reg)
            )
            
        lines.append(" ".join(parts) + "\n")
        
    return "".join(lines)

def vasco_log(prefix: str, msg: str, **kwargs):
    
    if prefix not in logger_prefixes:
        raise ValueError('unknown logging prefix')
    
    vars = ", ".join(f"{k}={v}" for k, v in kwargs.items())

    s = f"[{prefix}] {msg}"
    if vars:
        s += f" {vars}"

    logger_fd.write(f"{s}\n")

def vasco_cpu_log(ctx, instruction, regs):
    if not cpulogger_enabled:
        return
    
    print(__tri_format_single_step(ctx, regs), file=cpulogger_fd)
    print(instruction, file=cpulogger_fd)


def vasco_cpu_log_message(msg):
    print(msg, file=cpulogger_fd)


def vasco_log_format_br(br: Tuple[int, int]):
    if br:
        return f'[src={br[0]:08X}; dst={br[1]:08X}]'
    else:
        return '[no-branch]'