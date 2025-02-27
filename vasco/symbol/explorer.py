from typing import Dict, Any, List

from ..emu.emu import ida_func_emulator_t 
from ..utils.log import (
    vasco_log,
    vasco_log_format_br,
    vasco_cpu_log_message
)
from .dyncfg import dyncfg_t
from .loops import loops_symbolizer_t

from triton import (
    TritonContext, Instruction, MemoryAccess,
    CPUSIZE, ARCH, MODE, CALLBACK, 
    AST_REPRESENTATION, OPCODE, EXCEPTION,
    AST_NODE, SOLVER_STATE
)

def explorer_todo_log(iter, todo):
    vasco_log('?', f"(iter={iter}) :: todo_blocks({len(todo)})={ ','.join(map(lambda x: f'{x:08X}', todo)) }")


def explorer_todo_br_log(iter, todo):
    vasco_log('?', f"(iter={iter}) :: todo_brs({len(todo)})={ ','.join(map(lambda x: f'[src={x[0]:08X}; dst={x[1]:08X}]', todo)) }") 


def explorer_visited_br_log(iter, visited):
    vasco_log('?', f"(iter={iter}) :: visited_brs({len(visited)})={ ','.join(map(lambda x: f'[src={x[0]:08X}; dst={x[1]:08X}]', visited)) }") 


def explorer_taken_br_log(iter, taken_br):
    vasco_log('?', f"(iter={iter}) :: taken_brs({len(taken_br)})={ ','.join(map(lambda x: f'[src={x[0]:08X}; dst={x[1]:08X}]', taken_br)) }")


def explorer_not_taken_br_log(iter, not_taken_br):
    vasco_log('?', f"(iter={iter}) :: not_taken_brs({len(not_taken_br)})={ ','.join(map(lambda x: f'[src={x[0]:08X}; dst={x[1]:08X}]', not_taken_br)) }")

def explorer_tr_log(iter, tr):
    vasco_log('?', f"(iter={iter}) :: tr({len(tr)})={ ','.join(map(lambda x: f'{x:08X}', tr)) }")


class ida_func_block_exploration_result_t:
    def __init__(self, block: int):
        self._block     = block
        self._paths     = {}
        self._predicate = None
    
    @property
    def predicate(self):
        return self._predicate

    def update(self, ctx, prev: int, asts):
        astctx = ctx.getAstContext()

        if len(asts) > 1:
            new_ast = astctx.unroll(astctx.land(asts))
        else:
            new_ast = asts.pop()

        if prev not in self._paths:
            self._paths[prev] = astctx.unroll(new_ast)
        else:
            self._paths[prev] = astctx.unroll(astctx.land([self._paths[prev], new_ast]))

    def finalize(self, ctx):
        if self._predicate:
            return
        
        self._predicate = self.build_predicate(ctx)
        
    def build_predicate(self, ctx):
        astctx = ctx.getAstContext()

        if not self._paths:
            return astctx.equal(astctx.bvtrue(), astctx.bvtrue())
            
        asts = list(self._paths.values())
        if len(asts) > 1:
            new_ast = astctx.unroll(astctx.lor(asts))
        else:
            new_ast = astctx.unroll(asts.pop())

        return new_ast

    def predicate_by_path(self, prev: int):
        return self._paths[prev]


class ida_func_path_explorer_t:
    CALLBACK_ID_SETUP               = 0x01
    CALLBACK_ID_DISCOVERED_MODEL    = 0x02
    CALLBACK_ID_BEFORE_EMU_RUN      = 0x03
    CALLBACK_ID_AFTER_EMU_RUN       = 0x04
    CALLBACK_ID_ITERATION_COMPLETED = 0x05
    
    STATUS_EXPLORED          = 0x00
    STATUS_EXPLORATION_STUCK = -0x01

    def __init__(
            self,
            ea: int,
            callbacks    = {},
            hooks        = {},
            import_hooks = {},
            model_computation_timeout: int = 60,
            verbose_logging: bool = True,
            **kwargs
        ):
        self.verbose_logging = verbose_logging
        
        emu_callbacks = {
            ida_func_emulator_t.CALLBACK_ID_SETUP: [self._emu_setup],
        }
        self._callbacks = callbacks
        self._model_computation_timeout = model_computation_timeout

        self._emu = ida_func_emulator_t(
            ea,
            hooks=hooks,
            import_hooks=import_hooks,
            callbacks=emu_callbacks,
            tracer_type=dyncfg_t,
            **kwargs
        )

        self._loops = loops_symbolizer_t(self._emu.tr)
        self._emu.add_callback(
            self._emu.CALLBACK_ID_BEFORE_EXECUTION,
            self._loops.cb_before_execution
        )

        # immortalp0ny: Map between branch and constraint that has to be satisfied in order to visit that.
        #               Mapping format is (src, dest) => AstNode
        self._constraints = dict()
        # immortalp0ny: Map between symvar and constraint that has to be satisfied 
        #               when we visit branch that depends on that symvar.
        #               Mapping format is symvarId => AstNode
        self._constraints_for_symvars = dict()
        self._blocks_predicates: Dict[int, ida_func_block_exploration_result_t] = dict()

        self._status = self.STATUS_EXPLORED
        
        self._unreachable_branches = set()
        self._unexplored_branches = set()

        self._stop = False

    def _invoke_callbacks(self, callback_id: int, *args, **kwargs):
        for cb in reversed(self._callbacks.get(callback_id, [])):
            cb(*args, **kwargs)
    
    def _emu_setup(self, emu: ida_func_emulator_t):
        self._invoke_callbacks(self.CALLBACK_ID_SETUP, emu, self)

    def _set_or_update_block_predicate(self, prev_block_start_ea: int, block_start_ea: int, astprs: List[Any]):
        
        exploration_result: ida_func_block_exploration_result_t = self._blocks_predicates.setdefault(
            block_start_ea, ida_func_block_exploration_result_t(block_start_ea)
        )

        # immortalp0ny: That means block reachability is unconditional or model is not full
        if not astprs or prev_block_start_ea is None:
            return
        
        exploration_result.update(
            self._emu.ctx,
            prev_block_start_ea,
            astprs
        )

    def _find_active_symbolic_variable(self, previous_symvar):
        active_vars = self._emu.ctx.getSymbolicVariables()
        for symvar_id, symvar in active_vars.items():
            if symvar.getAlias() == previous_symvar.getAlias():
                return (symvar_id, symvar)
            

        raise KeyError(
            f'Lost variable. Improper state reinitialization. var={previous_symvar}'
        )

    @property
    def emu(self):
        return self._emu

    @property
    def status(self):
        return self._status

    @property
    def status_verbose(self):
        if self._status == self.STATUS_EXPLORED:
            return f"All blocks and constraints successfully reached"

        if self._status == self.STATUS_EXPLORATION_STUCK:
            return f"Not all blocks or constraints are visited"

    @property
    def unreachable_branches(self):
        return self._unreachable_branches
    
    @property
    def unexplored_branches(self):
        return self._unexplored_branches
    
    @property
    def block_predicates(self) -> Dict[int, ida_func_block_exploration_result_t]:
        return self._blocks_predicates

    def constraint_symvar(self, symvar, predicate):
        self._constraints_for_symvars.setdefault(symvar, []).append(predicate)

    def stop(self):
        self._stop = True

    def run(self):
        self._stop = False

        todo_blocks = set(self._emu.tr.blocks)
        todo_br     = set()
        visited_br  = set()

        run_ok = True

        iterctr = 0 
        while ( len(todo_blocks) > 0 or len(todo_br) > 0 ) and not self._stop:
            self._emu.reset()

            print(self.emu._heap._free_list)

            # @immortalp0ny: reset all things that depend on emu.reset()
            self._loops.reset()

            if iterctr > 0 and len(todo_br) == 0:
                # @immortalp0ny: When model is not full or some API are missing 
                #                exploration can stuck.It detects cases when
                #                there are no more branches to visit but some basic blocks 
                #                have not been visited yet. Continuation of exploration is not possible
                #                without model fix by analyst or introducing missing API implementation e.t.c.
                self._status = self.STATUS_EXPLORATION_STUCK
                
                # @immortalp0ny: Notify all listeners about completed iteration
                self._invoke_callbacks(
                    self.CALLBACK_ID_ITERATION_COMPLETED,
                    self,
                    iterctr,
                    todo_blocks,
                    todo_br,
                    visited_br,
                    br_taken,
                    br_not_taken,
                    self._emu.ctx.getSymbolicVariables()
                )
                break

            if todo_br:
                # @immortalp0ny: requested_branch is a tuple of addresses. First address 
                # shows instruction address that hold a predicate and second address shows destination block
                # For x86 and amd64 instruction predicate address is an address of JCC instruction.
                # Because of how disassembler split blocks instruction predicate address is 
                # equal to address of the last instruction (or just block_last_ea)

                br_scheduled     = todo_br.pop()
                br_scheduled_ast = self._constraints[br_scheduled]

                br_src_block_start     = self._emu.tr.rev[br_scheduled[0]]
                br_src_block_predicate = self._blocks_predicates.get(br_src_block_start, None)
                
                br_src_block_predicate_ast = br_src_block_predicate.build_predicate(self._emu.ctx)

                parts = [br_scheduled_ast]
                if br_src_block_predicate:
                    parts.append(br_src_block_predicate_ast)

                constrained_symvars = set()
                constraints_parts = list()
                for part in parts:
                    for part_symvar in set(astctx.search(part, AST_NODE.VARIABLE)):
                        if part_symvar in constrained_symvars:
                            continue

                        var_constraints = self._constraints_for_symvars.get(part_symvar.getSymbolicVariable()) 
                        if var_constraints:
                            constraints_parts.extend(var_constraints)

                        constrained_symvars.add(part_symvar)

                parts.extend(constraints_parts)

                if len(parts) > 1:
                    path_constraint = astctx.land(parts)
                else:
                    path_constraint = parts[0]

                self._emu.ctx.pushPathConstraint(
                    path_constraint
                )

                vasco_log('?', f"(iter={iterctr}) :: block={br_src_block_start:08X} pr={br_src_block_predicate_ast}")
                vasco_log('?', f"(iter={iterctr}) :: iter_path_constraint={path_constraint}")
                vasco_log('?', f"(iter={iterctr}) :: iter_target_block={br_scheduled[1]:08X}")
                vasco_log('?', f"(iter={iterctr}) :: iter_branch={f'[src={br_scheduled[0]:08X}; dst={br_scheduled[1]:08X}]'}")
                vasco_log('?', f"(iter={iterctr}) :: iter_branch_ast={br_scheduled_ast}")


                new_model, solver_state, solving_time = self._emu.ctx.getModel(
                    path_constraint,
                    timeout=self._model_computation_timeout,
                    status=True
                )
                if solver_state == SOLVER_STATE.SAT:
                    vasco_log('?', f"iter_path_constraint solved for time={solving_time}")
                    vasco_log('?', f"iter_target_block may be reached")

                    model = new_model
                else:
                    vasco_log('?', "iter_target_block is unreachable")
                    
                    self._unreachable_branches.add(br_scheduled)

                    visited_br.add(br_scheduled)
                    
                    todo_br.discard(br_scheduled)
                    todo_blocks.discard(br_scheduled[1])
                    
                    continue

                self._invoke_callbacks(self.CALLBACK_ID_DISCOVERED_MODEL, self._emu, self, model)
                
                for sym_varmodel in model.values():
                    iter_symvar       = sym_varmodel.getVariable()
                    iter_symvar_value = sym_varmodel.getValue() & ((1 << (iter_symvar.getBitSize() + 1)) - 1)
                    
                    iter_symvar_id   = iter_symvar.getId()

                    current_symvar_id, current_symvar = self._find_active_symbolic_variable(
                        iter_symvar
                    )

                    vasco_log(
                        '?',
                        f"(iter={iterctr}) :: symvar ({iter_symvar_id} => {current_symvar_id}) >>> {current_symvar}={iter_symvar_value}"
                    )

                    self._emu.ctx.setConcreteVariableValue(current_symvar, iter_symvar_value)

            self._invoke_callbacks(self.CALLBACK_ID_BEFORE_EMU_RUN, iterctr, self._emu, self)
            
            vasco_cpu_log_message(f"(iter={iterctr}) :: emu.run()")

            ok = self._emu.run()
            vasco_log('?', f"(iter={iterctr}) :: emu.run() -> {self._emu.status} ({ok})")

            if not ok:
                
                # @immortalp0ny: After this errors we know how to continue exploration.
                #                ( may be error handling code hasnt not been implemented yet :) ).
                #                in general it's ok to continue after that
                not_so_critical_status = (
                    ida_func_emulator_t.STATUS_BAD_CODE,
                    ida_func_emulator_t.STATUS_MAX_INSTRUCTIONS,
                    ida_func_emulator_t.STATUS_MAX_LOOP_ITERATIONS
                )
                if self._emu.status not in not_so_critical_status:
                    run_ok = ok
                    break
                
                vasco_log('!', f"iter_target_block exploration was failed due to emulation problem status={ok}")
            
            self._invoke_callbacks(self.CALLBACK_ID_AFTER_EMU_RUN, iterctr, self._emu, self)
            
            astctx = self._emu.ctx.getAstContext()
            pcl    = self._emu.ctx.getPathConstraints()
            
            br_not_taken = set()
            br_taken     = set()

            for k, pc in enumerate(pcl):
                if not pc.isMultipleBranches():
                    continue
                
                for i, constraint in enumerate(pc.getBranchConstraints()):
                    expr = astctx.unroll(constraint['constraint'])

                    dst = constraint['dstAddr']
                    src = constraint['srcAddr']

                    branch = (src, dst)
                    
                    if branch not in self._constraints:
                        self._constraints[branch] = expr

                        vasco_log(
                            '?',
                            f"new branch discovered. taken={constraint['isTaken']} branch=[src={branch[0]:08X}; dst={branch[1]:08X}] :: expr={expr}"
                        )

                    if constraint['isTaken']:
                        br_taken.add(branch)
                    else:
                        br_not_taken.add(branch)

            for loop_ea, loop in self._loops.loops.items():
                if loop.ctr <= 0:
                    continue
                
                vasco_log(
                    '?',
                    f"loop was reached ctr={loop.ctr} ea={loop_ea:08X}"
                )

                if loop.has_condition:
                    is_br_cond_continue_symbolized = loop.br_cond_continue in self._constraints 
                    is_br_cond_exit_symbolized     = loop.br_cond_continue in self._constraints 
                    vasco_log('?', f"   -> br_cond_continue={vasco_log_format_br(loop.br_cond_continue)} symbolized={is_br_cond_continue_symbolized}")
                    vasco_log('?', f"   -> br_cond_exit={vasco_log_format_br(loop.br_cond_exit)} symbolized={is_br_cond_exit_symbolized}")
                    
                for br_exit in loop.br_exits:
                    vasco_log('?', f"   -> br_exit={vasco_log_format_br(br_exit)}")

            # @immortalp0ny: globaly discovered constraints are equal to difference between 
            # visited_constraints and untouched constraints discovered at current iteration
            todo_br = todo_br.union(
                br_not_taken.difference(visited_br)
            )
            todo_br = todo_br.difference(
                br_taken
            )
            visited_br |= set(br_taken)

            prev = None
            dom_brs = set()
            pairs   = set()
            for i, block_start_ea in enumerate(self._emu.tr.tr):
                
                if prev:
                    br_src = self._emu.tr.fwd[prev]
                    br_dst = block_start_ea
                    
                    br = (br_src, br_dst)
                    if br in pairs:
                        continue

                    constraint = self._constraints.get(br) 
                    if constraint:
                        dom_brs.add(constraint)

                    pairs.add(br)

                vasco_log(
                    '?',
                    f"update block predicate block={block_start_ea:08X} prev={prev if prev else -1:08X}"
                )
                for j, dom_br in enumerate(dom_brs):
                    vasco_log(
                        '?',
                        f"  -> [{j}] {dom_br}"
                    )
                self._set_or_update_block_predicate(
                    prev, block_start_ea, list(dom_brs)
                )

                todo_blocks.discard(block_start_ea)

                prev = block_start_ea 
            
            if self.verbose_logging:
                explorer_todo_log         (iterctr, todo_blocks)
                explorer_todo_br_log      (iterctr, todo_br)
                explorer_visited_br_log   (iterctr, visited_br)
                explorer_taken_br_log     (iterctr, br_taken)
                explorer_not_taken_br_log (iterctr, br_not_taken)
                # explorer_tr_log           (iterctr, self._emu.tr.tr)

            self._invoke_callbacks(
                self.CALLBACK_ID_ITERATION_COMPLETED,
                self,
                iterctr,
                todo_blocks,
                todo_br,
                visited_br,
                br_taken,
                br_not_taken,
                self._emu.ctx.getSymbolicVariables()
            )
            iterctr += 1

        for r in self._blocks_predicates.values():
            r.finalize(self._emu.ctx)

        return run_ok
