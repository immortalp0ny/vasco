from pathlib import Path 
from io import StringIO

import ida_funcs
import ida_gdl
import idaapi
import idc

from networkx import DiGraph, nx_pydot


from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE
)

from ..emu.emu import ida_func_emulator_t
from ..emu.interfaces import ida_func_emulator_tracer_t
from ..utils.log import vasco_log
from ..utils.ida_utils import hr_loop_t, hr_loop_finder_t

NODE_STATE_VISITED     = 'visited'
NODE_STATE_NOT_VISITED = 'notvisited'
NODE_STATE_UNREACHED   = 'unreached'


class dyncfg_formatter_t:
    def __init__(self, dyncfg: 'dyncfg_t'):
        self._graph = dyncfg.graph
        self._dyncfg = dyncfg

    def _foramt_node_id(self, node_id: int):
        return f"{node_id:08X}"

    def _format_node_record(self, node_id: int) -> str:
        stream = StringIO()
        stream.write(
            str(node_id)
        )

        formatted_attrs = [
            f"label=\"{self._foramt_node_id(node_id)}\""
        ]

        n_out_edges = len(self._graph.out_edges([node_id]))
        if n_out_edges > 1:
            formatted_attrs.append(f"shape=diamond")
        else:
            formatted_attrs.append(f"shape=box")

        for node_attr_id in self._graph.nodes[node_id].keys():
            node_attr_value = self._graph.nodes[node_id][node_attr_id]
            
            if node_attr_id == 'visited' and node_attr_value:
                formatted_attrs.append(f"color=green")
                continue

            formatted_attrs.append(
                f"{node_attr_id}={node_attr_value}"
            )

        if not formatted_attrs:
            return stream.getvalue()
    
        stream.write(
            ' ['
        )
        stream.write(' '.join(formatted_attrs))
        stream.write('];')

        return stream.getvalue()

    def _format_edge_record(self, src_node_id: int, dst_node_id: int, is_cross_edge: bool = False) -> str:
        stream = StringIO()
        stream.write(
            f"{src_node_id} -> {dst_node_id}"
        )
        formatted_attrs = []

        if is_cross_edge:
            formatted_attrs.append(f"style=dashed")

        for edge_attr_id in self._graph[src_node_id][dst_node_id].keys():
            edge_attr_value = self._graph[src_node_id][dst_node_id][edge_attr_id]

            if (edge_attr_id == 'is_dynamic' and edge_attr_value) and not is_cross_edge:
                formatted_attrs.append(f"style=dashed")
                continue

            if edge_attr_id == 'visited' and edge_attr_value:
                formatted_attrs.append(f"color=green")
                continue

            formatted_attrs.append(
                f"{edge_attr_id}={edge_attr_value}"
            )

        if not formatted_attrs:
            return stream.getvalue()
    
        stream.write(
            ' ['
        )
        stream.write(' '.join(formatted_attrs))
        stream.write('];')

        return stream.getvalue()

    def __str__(self):
        return self.as_str()
    
    def __repr__(self):
        return self.as_str()

    def as_str(self):
        stream = StringIO()
        stream.write("strict digraph  {\n")
        stream.write("overlap=scale\n")
        stream.write("layout=fdp\n")
        stream.write("\n")
        for node_id in self._graph.nodes:
            stream.write(self._format_node_record(node_id))
            stream.write("\n")

        cross_edges = []
        subgraphs = {k: [] for k in self._dyncfg.funcs}
        for src_node, dst_node in self._graph.edges:
            src_func = ida_funcs.get_func(src_node)
            dst_func = ida_funcs.get_func(dst_node)

            if src_func.start_ea == dst_func.start_ea:
                subgraphs[src_func.start_ea].append(
                    self._format_edge_record(src_node, dst_node)
                )
            else:
                cross_edges.append(
                    self._format_edge_record(src_node, dst_node, is_cross_edge=True)
                )

        stream.write("\n")
        stream.write(f"subgraph cluster_{self._dyncfg.func.start_ea} {{")
        stream.write("\n")
        stream.write(f"label=\"{self._dyncfg.func.start_ea:08X}\"")
        stream.write("\n")
        stream.write("\n".join(subgraphs[self._dyncfg.func.start_ea]))
        stream.write("\n")

        stream.write("\n".join(cross_edges))

        del subgraphs[self._dyncfg.func.start_ea]

        for func_ea, edges in subgraphs.items():
            stream.write(f"subgraph cluster_{func_ea} {{")
            stream.write("\n")
            stream.write(f"label=\"{func_ea:08X}\"")
            stream.write("\n")

            stream.write("\n".join(edges))
            stream.write("\n")

            stream.write(f"}}")
            stream.write("\n")

        stream.write("\n")
        stream.write(f"}}")
        stream.write(f"}}")

        return stream.getvalue()


class dyncfg_t(ida_func_emulator_tracer_t):
    def __init__(self, emu: ida_func_emulator_t, func: ida_funcs.func_t):
        self._graph = DiGraph()

        self._succmap = dict()
        self._prevmap = dict()

        self._prev_block = None

        self._loops = {}
        self._loops_entries = set()

        super().__init__(emu, func)
            
    @property
    def graph(self):
        return self._graph
    
    @property
    def loops(self):
        return self._loops
    
    @property
    def loops_entries(self):
        return self._loops_entries
    
    def _set_or_update_static_edge(self, src_address: int, dst_address: int):
        if not self._graph.has_edge(src_address, dst_address):
            self._graph.add_edge(src_address, dst_address, is_static=True, visited=False)
        else:
            self._graph[src_address][dst_address]['is_static'] = True

    def _set_or_update_dynmaic_edge(self, src_address: int, dst_address: int):
        if not self._graph.has_edge(src_address, dst_address):
            self._graph.add_edge(src_address, dst_address, is_dynamic=True, visited=True)
        else:
            self._graph[src_address][dst_address]['visited'] = True

    def _split_block(self, block_start_ea: int, block_end_ea: int):
        new_blocks = set()
        i = block_start_ea
        j = block_start_ea
        k = i

        while i < block_end_ea:
            instruction = self.emu.get_instruction(i)
            if instruction.getType() == OPCODE.X86.CALL:
                new_blocks.add(
                    (j, i)
                )
                j = instruction.getNextAddress()
            
            k = i
            i += instruction.getSize()

        if not new_blocks:
            new_blocks.add(
                (block_start_ea, idc.prev_head(block_end_ea))
            )
        else:
            new_blocks.add(
                (j, k)
            )

        return new_blocks

    def _update_loops(self, ea: int):
        cfunc = idaapi.decompile(ea)
        if not cfunc:
            vasco_log('!', f"failed to decompile target={ea:08X}")
            return 
        
        loop_finder = hr_loop_finder_t(cfunc)
        loop_finder.apply_to(cfunc.body, None)
        
        todo_loops = list(loop_finder.loops)

        # @immortalp0ny: by default loop contains all instructions including instructions
        #                belonging to inner loop. In order to correctly track loop conditions
        #                we would like to distinguish them from each other
        while len(todo_loops) > 0:
            loop = todo_loops.pop()

            for outer_loop in loop_finder.loops:
                if loop.ea != outer_loop.ea and loop.ea in outer_loop.body:
                    # @immortalp0ny: remove instruction of inner loop from body of outer loop
                    outer_loop.body = list(
                        set(outer_loop.body).difference(
                            loop.body + [loop.ea]
                        )
                    )
                    # @immortalp0ny: remove exits of inner loop from exits of outer loop
                    outer_loop.exits = list(
                        set(outer_loop.exits).difference(
                            loop.exits
                        )
                    )

        for loop_info in loop_finder.loops:
            self._loops_entries.add(loop_info.ea)

            vasco_log('?', f"(dyncfg.loop): add_loop start={loop_info.ea:08X} cit={loop_info.cit_asstr()} cond={loop_info.cond if loop_info.cond else -1:08X}")
            for i, loop_instr in enumerate(loop_info.body):
                vasco_log('?', f"(dyncfg.loop):    -> {i}: ea={loop_instr:08X} exit={loop_instr in loop_info.exits}")

            self._loops[loop_info.ea] = loop_info          

    def _update_blocks(self, func: ida_funcs.func_t):
        new_block_map = {}
        for block in ida_gdl.FlowChart(func):
            new_block_map[block.start_ea] = self.add_block(block.start_ea, block.end_ea)

        for block in ida_gdl.FlowChart(func):
            for block_succ in block.succs():
                src_derived_blocks = new_block_map[block.start_ea]
                dst_derived_blocks = new_block_map[block_succ.start_ea]
                
                src_address = src_derived_blocks[-1][0]
                dst_address = dst_derived_blocks[0][0]

                self._set_or_update_static_edge(src_address, dst_address)
                

            for block_pred in block.preds():
                src_derived_blocks = new_block_map[block_pred.start_ea]
                dst_derived_blocks = new_block_map[block.start_ea]
                
                src_address = src_derived_blocks[-1][0]
                dst_address = dst_derived_blocks[0][0]

                self._set_or_update_static_edge(src_address, dst_address)

    def next_tr(self, i: int):
        if i + 1 >= len(self.tr):
            return None
        
        return self.tr[i + 1]

    def prev_tr(self, i: int):
        if i - 1 < 0:
            return None
        
        return self.tr[i - 1]

    def cb_before_execution(self, emu, pc: int):
        if pc not in self._blocks:
            return
        
        self._trset.add(pc)
        self._tr.append(pc)

        if self._prev_block is not None:
            self._set_or_update_dynmaic_edge(self._prev_block, pc)

        self._prev_block = pc

        self._graph.nodes[pc]['visited'] = True 
    
    def cb_after_call_execution(self, emu, target: int):
        if target in self._funcs or emu.mem.is_import(target):
            return
        
        func = ida_funcs.get_func(target)
        if not func:
            vasco_log('!', f"call target is not a function target={target:08X}")
            return
        
        self._funcs.add(target)
        
        self.extend(func)

    def reset(self):
        self._trset = set()
        self._tr = list()  

        self._prev_block = None 

    def extend(self, func: ida_funcs.func_t):
        self._update_blocks(func)
        self._update_loops(func.start_ea)

    def add_block(self, block_start_ea: int, block_end_ea: int):
        new_blocks = self._split_block(block_start_ea, block_end_ea)

        vasco_log('?', f"add_block: start={block_start_ea:08X} end={block_end_ea:08X}")

        for new_block in new_blocks:
            vasco_log('?', f"    -> new_block: start={new_block[0]:08X} last={new_block[1]:08X}")

        for new_block in new_blocks:
            self._blocks.add(new_block[0]) 
            
            self._fwdmap[new_block[0]] = new_block[1]
            self._revmap[new_block[1]] = new_block[0]

            self._graph.add_node(new_block[0], state=NODE_STATE_NOT_VISITED)

        self._blocks_ranges = self._blocks_ranges.union(new_blocks)

        return list(new_blocks)

    def to_dot(self, filepath: Path):
        with open(filepath, 'w') as fd:
            fd.write(str(dyncfg_formatter_t(self)))