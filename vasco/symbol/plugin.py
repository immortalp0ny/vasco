from typing import Dict, Any
from pathlib import Path
from functools import partial

from ..emu.emu import ida_func_emulator_t
from .explorer import ida_func_path_explorer_t

from ..utils.log import vasco_log

from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE, OPERAND,
)

from networkx import DiGraph


class basic_ida_func_path_explorer_t(ida_func_path_explorer_t):
    def __init__(
            self,
            ea,
            emu_settings,
            model_settings,
            callbacks    = {},
            hooks        = {},
            import_hooks = {},
            model_computation_timeout = 60,
            verbose_logging = True,
            **kwargs
        ):
        
        setup_cbs = callbacks.setdefault(ida_func_path_explorer_t.CALLBACK_ID_SETUP, [])
        setup_cbs.append(self._cb_setup)

        setup_cbs = callbacks.setdefault(ida_func_path_explorer_t.CALLBACK_ID_AFTER_EMU_RUN, [])
        setup_cbs.append(self._cb_after_emu_run)
        
        self._emu_settings   = emu_settings
        self._model_settings = model_settings

        self._symbolic_parents           = dict()
        self._symbolic_memory_variables  = dict()
        self._concolic_pointers          = set()
        self._concolic_pointers_mappings = dict()

        self._symbolic_vars_graphs: Dict[str, DiGraph] = dict()

        self._auto_symptr_ctr = 0

        self._tr_hash_set = set()
        self._tr_failed   = set()

        super().__init__(
            ea,
            callbacks,
            hooks,
            import_hooks,
            model_computation_timeout,
            verbose_logging,
            **kwargs
        )

        self._emu.add_callback(
            self._emu.CALLBACK_ID_SYMBOLIC_PTR_READ, self._cb_spread_symbolization_over_read
        )

    def _cb_setup(self, emu: ida_func_emulator_t, explorer: ida_func_path_explorer_t):
        for k, v in self._emu_settings['user_memory'].items():
            emu.mem.map_memory(
                k,
                v['data'],
                v['tag'],
                perm    = v['perm'],
                is_heap = v['is_heap']
            )

            vasco_log(
                '?',
                f"(emu.init) map memory :: ",
                address=f"{k:08X}",
                len=f"{len(v['data'])}",
                tag=f"{v['tag']}",
                perm=f"{v['perm']}",
                heap=f"{v['is_heap']}"
            )

        model_args = self._model_settings.get('args', {})
        if model_args:
            for sym_arg_idx, sym_arg_opt in model_args.items():
                logmsg = f"(emu.init) model"

                emu.cc.set_arg(
                    emu.ctx,
                    sym_arg_idx,
                    sym_arg_opt['value']
                )

                logmsg += f" :: argi={sym_arg_idx} argv={sym_arg_opt['value']:08X}"

                if sym_arg_opt['symbolized']:
                    alias = sym_arg_opt['alias']

                    self._symbolic_parents[alias] = None

                    emu.cc.symbolize_arg(
                        emu.ctx,
                        sym_arg_idx,
                        alias=alias
                    )
                    if sym_arg_opt['pointer']:
                        self._concolic_pointers.add(alias)

                        if sym_arg_opt['autofields']:

                            emu.mem.set_chunk_read_cb(sym_arg_opt['value'], partial(self._cb_read_heap_auto_fields, alias))
                            emu.mem.set_chunk_write_cb(sym_arg_opt['value'], partial(self._cb_write_heap_auto_fields, alias))
                                
                            logmsg += f" auotfields_enabled=True"

                    logmsg += f" argsymname={sym_arg_opt['alias']}"                    

                vasco_log('?', logmsg)

        for name, desc in self._concolic_pointers_mappings.items():
            concrete_ptr          = desc['address']
            concrete_data         = desc['data']
            concrete_data_ptr_tag = desc['tag']

            emu.mem.map_memory(
                concrete_ptr,
                concrete_data,
                concrete_data_ptr_tag,
                perm='RW',
                read_cb=partial(self._cb_read_heap_auto_fields, name),
                write_cb=partial(self._cb_write_heap_auto_fields, name),
                is_heap=True
            )

            vasco_log(
                '?',
                f"(emu.init.memory) map memory :: ",
                address=f"{concrete_ptr:08X}",
                len=f"{len(concrete_data)}",
                tag=f"{concrete_data_ptr_tag}",
                perm=f"RW",
                heap=f"True"
            )
            
            parent_desc = self._symbolic_memory_variables[name]
            
            memaccess =  MemoryAccess(parent_desc['address'], parent_desc['size'])

            self.emu.ctx.setConcreteMemoryValue(
                memaccess, concrete_ptr, callbacks=False
            )
            
            vasco_log(
                '?',
                f"(emu.init.memory) init symptr :: name={name}"
            )
        
        for name, desc in self._symbolic_memory_variables.items():
                base    = desc["chunk"]
                address = desc['address']
                size    = desc['size']
                
                memaccess =  MemoryAccess(address, size)

                if emu.ctx.isMemorySymbolized(memaccess):
                    continue

                desc['symvar'] = emu.ctx.symbolizeMemory(
                    memaccess,
                    name
                )

                symvar_id = desc['symvar'].getId()
                
                vasco_log(
                    '?',
                    f"(emu.init.memory) init symvar :: base={base:08X} address={address:08X} size={size:08X} name={name} id={symvar_id}"
                )

    def _cb_read_heap_auto_fields(self, parent_name: str, ctx: TritonContext, memaccess: MemoryAccess):
        if ctx.isMemorySymbolized(memaccess):
                return
        
        field_address = memaccess.getAddress()
        field_chunk = self._emu.mem.find_chunk(field_address)
        if not field_chunk:
            return

        field_off = memaccess.getAddress() - field_chunk.address
        
        field_symvar_name = f"field_{field_chunk.address:08X}_{field_off:08X}"
        
        field_symvar = ctx.symbolizeMemory(
            memaccess,
            field_symvar_name
        )

        field_info = self._symbolic_memory_variables.setdefault(field_symvar_name, {})
        if field_info:
            return
        
        self._symbolic_parents[field_symvar_name] = parent_name

        vasco_log('?', f"discovered new symbolic field chunk={field_chunk.address:08X} off={field_off:04X} size={memaccess.getSize():08X}")
        
        field_info['chunk']       = field_chunk.address
        field_info['address']     = memaccess.getAddress()
        field_info['size']        = memaccess.getSize()
        field_info['symvar']      = field_symvar
        field_info['expressions'] = {}

    def _cb_write_heap_auto_fields(self, parent_name: str, ctx: TritonContext, memaccess: MemoryAccess):
        rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        if not rip:
            # @immortalp0ny: it possible in cases when we call SymbolizeMemory API
            #                from cb_setup
            return
        
        field_address = memaccess.getAddress()
        field_chunk = self._emu.mem.find_chunk(field_address)
        if not field_chunk:
            return
        
        field_off = memaccess.getAddress() - field_chunk.address

        instruction = ctx.disassembly(ctx.getConcreteRegisterValue(ctx.registers.rip), 1)[0]
        ctx.buildSemantics(instruction)
        
        if not instruction.isSymbolized():
             return

        field_astnodes = []
        accesses = instruction.getStoreAccess()
        for current_memaccess, current_ast in accesses:
            if current_memaccess.getAddress() == memaccess.getAddress():
                astctx        = ctx.getAstContext()
                field_astnode = astctx.unroll(current_ast)

                field_astnodes.append(field_astnode)

        if not field_astnodes:
            return
        
        field_symvar_name = f"field_{field_chunk.address:08X}_{field_off:08X}"
        field_info = self._symbolic_memory_variables.setdefault(field_symvar_name, {})
        if not field_info:
            vasco_log('?', f"discovered new symbolic field chunk={field_address:08X} off={field_off:04X} size={memaccess.getSize():08X}")
            
            field_info['chunk']       = field_chunk.address
            field_info['address']     = memaccess.getAddress()
            field_info['size']        = memaccess.getSize()
            field_info['expressions'] = {}

            field_info['symvar'] = ctx.symbolizeMemory(
                memaccess,
                field_symvar_name
            )
            self._symbolic_parents[field_symvar_name] = parent_name
            
        field_info['expressions'][rip] = {
            'values': field_astnode
        }

    def _cb_spread_symbolization_over_read(self, emu: ida_func_emulator_t, instruction: Instruction, basevar):
        basevar_name = basevar.getAlias()
        if basevar_name in self._concolic_pointers:
            return
        
        deepness = 1
        node = basevar_name
        while self._symbolic_parents[node]:
            node = self._symbolic_parents[node]
            deepness += 1

        if deepness > 3:
            return

        concrete_data = [0x00] * 4096
        concrete_tag = f"concrete_ptr_for_spread_symbolization_over_read_at_{instruction.getAddress():08X}"
        concrete_ptr  = self.emu.mem.heap_new(
            concrete_tag,
            concrete_data,
            perm='RW',
            read_cb=partial(self._cb_read_heap_auto_fields, basevar_name),
            write_cb=partial(self._cb_write_heap_auto_fields, basevar_name)
        )
        self._concolic_pointers_mappings[basevar_name] = {
            "address": concrete_ptr,
            "tag":     concrete_tag,
            "data":    concrete_data
        }
        self._concolic_pointers.add(basevar_name)

        self.emu.ctx.setConcreteVariableValue(
            basevar, concrete_ptr
        )

        astctx = self.emu.ctx.getAstContext()

        self.constraint_symvar(
            basevar, astctx.variable(basevar) == concrete_ptr 
        )

        vasco_log('?', f"instruction={instruction} name={basevar} defines symbolic pointer")

        # auto_symptr_name = f"auto_symptr_{self._auto_symptr_ctr}"

        # self._auto_symptr_ctr += 1
        # self._symbolic_pointers.add(auto_symptr_name)
        
        # auto_symptr_info = self._symbolic_memory_variables.setdefault(auto_symptr_name, {})
        # field_info['chunk']       = field_chunk.address
        # field_info['address']     = memaccess.getAddress()
        # field_info['size']        = memaccess.getSize()
        # field_info['expressions'] = {}

        # field_info['symvar'] = ctx.symbolizeMemory(
        #         memaccess,
        #         field_symvar_name
        # )
            
        # field_info['expressions'][rip] = {
        #     'values': field_astnode
        # }

        # rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        # if not rip:
        #     # @immortalp0ny: it possible in cases when we call SymbolizeMemory API
        #     #                from cb_setup
        #     return
        
        # instruction = self.emu.get_instruction(rip, build_semantics=True)
        

        # # base_expr = self._emu.ctx.getSymbolicRegister(base)

       

        # self._memory_symbolic_vars[]

    def _cb_after_emu_run(self, iterctr: int, emu: ida_func_emulator_t, explorer: 'basic_ida_func_path_explorer_t'):
        tr      = tuple(emu.tr.tr)
        tr_hash = hash(tr) & 0xffffffffffffffff

        vasco_log('?', f"(iter={iterctr}) :: emu.run() -> tr_hash={tr_hash:08X} tr_len={len(tr)}")

        if emu.status == ida_func_emulator_t.STATUS_BAD_CODE:
            self._tr_failed.add(tr_hash)

        if tr_hash in self._tr_hash_set:
            return
        
        self._tr_hash_set.add(tr_hash)

        workdir = Path(self._emu_settings['output_dir']) / 'traces'
        if not workdir.exists():
            workdir.mkdir(parents=True, exist_ok=True)
        
        filepath = workdir / f"{tr_hash:08X}.trace.txt"

        with open(filepath, 'w') as fd:
            fd.writelines([f"{x:08X}\n" for x in tr])