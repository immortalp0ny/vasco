import ida_kernwin as kw
import idc

from PyQt5 import QtWidgets

from ..utils import lift_triton_ast_node_to_smt_lib



class action_copy_predicate_t(kw.action_handler_t):
    def __init__(self, parent):
        super().__init__()

        self.parent = parent

    @staticmethod
    def id(ea: int) -> str:
        return f"vasco:choose:{ea:08X}:action_copy_predicate_t"
    
    @staticmethod
    def text() -> str:
        return "Copy predicate as SMT-LIB"
    
    @staticmethod
    def shortcut() -> str:
        return "Ctrl+C+2"

    def activate(self, ctx):
        if not self.parent.items:
            return
        
        item = self.parent.items[self.parent.selected_index]

        predicate = item[1]

        text = lift_triton_ast_node_to_smt_lib(self.parent.explorer.emu.ctx, predicate)

        clipboard = QtWidgets.QApplication.clipboard()

        clipboard.setText("")
        clipboard.setText(text)

    def update(self, ctx):
        if kw.is_chooser_widget(ctx.widget_type):
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
    

class action_copy_block_address_t(kw.action_handler_t):
    def __init__(self, parent):
        super().__init__()

        self.parent = parent

    @staticmethod
    def id(ea: int) -> str:
        return f"vasco:choose:{ea:08X}:action_copy_block_address_t"
    
    @staticmethod
    def text() -> str:
        return "Copy block address"
    
    @staticmethod
    def shortcut() -> str:
        return "Ctrl+C+1"

    def activate(self, ctx):
        if not self.parent.items:
            return
        
        item = self.parent.items[self.parent.selected_index]

        block_start_ea = item[0]
        clipboard = QtWidgets.QApplication.clipboard()

        clipboard.setText("")
        clipboard.setText(f"0x{block_start_ea:08X}")

    def update(self, ctx):
        if kw.is_chooser_widget(ctx.widget_type):
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
    

class action_jump_to_block_t(kw.action_handler_t):
    def __init__(self, parent):
        super().__init__()

        self.parent = parent

    @staticmethod
    def id(ea: int) -> str:
        return f"vasco:choose:{ea:08X}:action_jump_to_block_t"
    
    @staticmethod
    def text() -> str:
        return "Jump to block"
    
    @staticmethod
    def shortcut() -> str:
        return ""

    def activate(self, ctx):
        if not self.parent.items:
            return
        
        item = self.parent.items[self.parent.selected_index]

        idc.jumpto(item[0])

    def update(self, ctx):
        if kw.is_chooser_widget(ctx.widget_type):
            return kw.AST_ENABLE_FOR_WIDGET
        return kw.AST_DISABLE_FOR_WIDGET
