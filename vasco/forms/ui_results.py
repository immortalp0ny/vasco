import ida_kernwin as kw
import idc

from ..symbol.explorer import ida_func_path_explorer_t
from .ui_actions import (
    action_copy_block_address_t,
    action_copy_predicate_t,
    action_jump_to_block_t
)

from triton import AST_NODE


class ui_blocks_exploration_results_view_t(kw.Choose):
    def __init__(self, title, explorer: ida_func_path_explorer_t, flags = 0, width: int = 500, height: int = 300):
        flags = flags | kw.Choose.CH_RESTORE
        columns = [
            ["Block", 10], ["Predicate", 100], ["Variables", 10] 
        ]

        kw.Choose.__init__(
            self,
            title,
            columns,
            flags,
            width = width,
            height = height
        )
        self.explorer = explorer
    
        self.items    = []
        self.selected_index = 0
        
        self._init_items()
    
    def _init_items(self):
        self.items = []
        astctx = self.explorer.emu.ctx.getAstContext()
        for block, exploration_result in self.explorer.block_predicates.items():
            vars = astctx.search(exploration_result.predicate, AST_NODE.VARIABLE)

            self.items.append(
                (block, exploration_result.predicate, vars)
            )

    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        line_data = self.items[n]
        
        return [
            f"{line_data[0]:08X}",
            f"{line_data[1]}",
            ','.join(set([str(x) for x in line_data[2]]))
        ]

    def OnGetLineAttr(self, n):
        pass
        
    def OnSelectLine(self, n):
        if not self.items:
            return

        item = self.items[n]

        idc.jumpto(item[0])

        return (kw.Choose.NOTHING_CHANGED, )
    
    def OnSelectionChange(self, n):
        self.selected_index = n
    
    def Show(self, *args, **kwargs):
        super().Show(*args, **kwargs)

        ea = self.explorer.emu.ea

        kw.unregister_action(action_copy_block_address_t.id(ea))
        kw.unregister_action(action_copy_predicate_t.id(ea))
        kw.unregister_action(action_jump_to_block_t.id(ea))

        desc = kw.action_desc_t(
            action_copy_block_address_t.id(ea), 
            action_copy_block_address_t.text(), 
            action_copy_block_address_t(self),
            action_copy_block_address_t.shortcut()
        )
        kw.register_action(desc)

        desc = kw.action_desc_t(
            action_copy_predicate_t.id(ea), 
            action_copy_predicate_t.text(), 
            action_copy_predicate_t(self),
            action_copy_predicate_t.shortcut()
        )
        kw.register_action(desc)

        desc = kw.action_desc_t(
            action_jump_to_block_t.id(ea), 
            action_jump_to_block_t.text(), 
            action_jump_to_block_t(self),
            action_jump_to_block_t.shortcut()
        )
        kw.register_action(desc)

        kw.attach_action_to_popup(self.GetWidget(), None, action_jump_to_block_t.id(ea))
        kw.attach_action_to_popup(self.GetWidget(), None, action_copy_block_address_t.id(ea))
        kw.attach_action_to_popup(self.GetWidget(), None, action_copy_predicate_t.id(ea))