from typing import Generator, Optional, List

import io
import re

import ida_typeinf
import ida_hexrays as hr
import ida_frame
import ida_funcs
import ida_name
import ida_ida
import idaapi
import idc


DEMANGLED_TYPEINFO = 0x06400007

def get_size_of_ptr() -> int:
    if ida_ida.idainfo_is_64bit():
        return 8
    else:
        return 4


def find_ea_by_name(name: str) -> Optional[str]:
    t, v = ida_name.get_name_value(idaapi.BADADDR, name)
    if t == 0:
        return
    
    return v

def find_ea_by_demangled_name(name: str) -> Optional[int]:
    inf = ida_ida.inf_get_demnames()
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
            
        f_name = ida_name.get_demangled_name(
            f.start_ea, DEMANGLED_TYPEINFO, inf, idc.GN_STRICT
        )

        if name in f_name:
            return f.start_ea
        

def find_ea_by_regexp(r: str) -> List[int]:
    result = []
    inf = ida_ida.inf_get_demnames()
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
            
        f_name = ida_name.get_demangled_name(
            f.start_ea, DEMANGLED_TYPEINFO, inf, idc.GN_STRICT
        )

        matches = re.match(r, f_name)

        if not matches:
            continue
        
        result.append(f.start_ea)
    
    return result
    

class ida_func_frame_t:
    def __init__(self, func: ida_funcs.func_t):
        self.func = func
        self.frame_tif = None

        self.update()
    
    def update(self):
        self.frame_off_args       = ida_frame.frame_off_args(self.func)
        self.frame_off_ret        = ida_frame.frame_off_retaddr(self.func)
        self.frame_off_saved_regs = ida_frame.frame_off_savregs(self.func)
        self.frame_off_lvars      = ida_frame.frame_off_lvars(self.func)
        self.frame_size           = ida_frame.get_frame_size(self.func)

        self.frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(self.frame_tif, self.func):
            raise ValueError('failed to get func frame tinfo_t')
        
        self.frame_total_size = self.frame_tif.get_size()

    def iter_over_frame(self) -> Generator[ida_typeinf.udm_t, None, None]:
        udt = ida_typeinf.udt_type_data_t()
        if not self.frame_tif.get_udt_details(udt):
            raise ValueError('failed to get func frame udt_type_data_t')
        
        for udm in udt:
            yield udm
        
    def dstr(self) -> io.StringIO:
        stream = io.StringIO()
        
        print(f"frame_off_saved_regs = {self.frame_off_args:08X}", file=stream)
        print(f"frame_off_ret        = {self.frame_off_ret:08X}", file=stream)
        print(f"frame_off_args       = {self.frame_off_saved_regs:08X}", file=stream)
        print(f"frame_off_lvar       = {self.frame_off_lvars:08X}", file=stream)
        print(f"frame_size           = {self.frame_size:08X}", file=stream)
        print(f"frame_total_size     = {self.frame_total_size:08X}", file=stream)

        for udm in self.iter_over_frame():
            print(f"\t#{udm.name}: soff={udm.offset//8:x} eof={udm.end()//8:x} {udm.type.dstr()}", file=stream)

        return stream


def hr_get_loop_insn(insn: hr.cinsn_t):
    if insn.op == hr.cit_for:
        return insn.cfor
    elif insn.op == hr.cit_while:
        return insn.cwhile
    elif insn.op == hr.cit_do:
        return insn.cdo
    else:
        return None


class hr_loop_t:
    def __init__(self, cfunc: hr.cfunc_t, insn: hr.cinsn_t):
        self.cit = insn.op
        self.ea  = insn.ea
        self.cond = None
        
        loop_insn = hr_get_loop_insn(insn)
        if not loop_insn:
            raise RuntimeError(f"unexpected loop insn={insn.ea:08X}")
        
        if loop_insn.expr:
            self.cond = loop_insn.expr.ea

        self.exits = list()
        self.body  = list()

        # @immortalp0ny: In the beginning of loop analysis we gather loop body.
        #                It should be done first in order to correctly determinate
        #                loop exits 
        body_finder = hr_loop_body_finder_t(self)
        body_finder.apply_to(loop_insn.body, None)

        exit_finder = hr_loop_exits_finder_t(cfunc, self)
        exit_finder.apply_to(loop_insn.body, None)

    def is_for(self):
        return self.cit == hr.cit_for
    
    def is_while(self):
        return self.cit == hr.cit_while

    def is_do(self):
        self.cit == hr.cit_do

    def cit_asstr(self):
        if self.cit == hr.cit_for:
            return "for"
        elif self.cit == hr.cit_while:
            return "while"
        elif self.cit == hr.cit_do:
            return "do-while"
        
        return "unknown"


class hr_loop_exits_finder_t(hr.ctree_visitor_t):
    def __init__(self, cfunc: hr.cfunc_t, loop: hr_loop_t):
        super().__init__(hr.CV_FAST)

        self.loop = loop
        self.cfunc = cfunc

    def _visit_goto(self, cinsn):
        dest_cinsn = self.cfunc.find_label(cinsn.cgoto.label_num)
        if not dest_cinsn:
            raise RuntimeError(f"goto withou destination label_num={cinsn.cgoto.label_num}")

        if dest_cinsn.ea not in self.loop.body:
            self._append_exit(cinsn)

    def _append_exit(self, insn):
        if insn.ea not in self.loop.exits:
            self.loop.exits.append(insn.ea)

    def visit_insn(self, cinsn):
        if cinsn.op == hr.cit_goto:
            self._visit_goto(cinsn)
        elif cinsn.op == hr.cit_return:
            self._append_exit(cinsn)
        elif cinsn.op == hr.cit_break:
            self._append_exit(cinsn)

        return 0

class hr_loop_body_finder_t(hr.ctree_visitor_t):
    def __init__(self, loop: hr_loop_t):
        super().__init__(hr.CV_FAST)

        self.loop = loop

    def visit_insn(self, insn):
        if insn.ea not in self.loop.body:
            self.loop.body.append(insn.ea)

        return 0


class hr_loop_finder_t(hr.ctree_visitor_t):
    def __init__(self, cfunc: hr.cfunc_t):
        super().__init__(hr.CV_FAST)
        self.cfunc = cfunc
        self.loops = []

    def visit_insn(self, cinsn):
        if cinsn.op in [hr.cit_for, hr.cit_while, hr.cit_do]:
            self.loops.append(
                hr_loop_t(self.cfunc, cinsn)
            )
        
        return 0
