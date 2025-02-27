from typing import Dict, Any
from pathlib import Path
from PyQt5 import QtCore, QtWidgets

from json import (
    loads as json_loads,
    dumps as json_dumps,
    JSONEncoder
)
from base64 import b64encode
from functools import partial

import ida_funcs
import ida_name
import ida_typeinf
import ida_nalt
import ida_ida
import ida_kernwin as kw
import idaapi
import idc

from ..utils import (
    fix_memory_content,
    fix_integer_keys,
    VASCO_VERSION
)
from ..utils.ida_utils import ida_func_frame_t, DEMANGLED_TYPEINFO
from ..utils.log import vasco_log

from ..emu.heap import easy_heap_t

from ..symbol.explorer import ida_func_path_explorer_t, AST_REPRESENTATION
from ..symbol.plugin import basic_ida_func_path_explorer_t

from .ui_emu import ui_emu_t
from .ui_memory import ui_memory_dialog_t
from .ui_results import ui_blocks_exploration_results_view_t
from .ui_widget import ui_numeric_input_t, ui_string_input_t, ui_counter_t


class BytesEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return f"bytes:{b64encode(obj).decode('utf-8')}"

        # Let the base class default method raise the TypeError
        return super().default(obj)


class ui_func_arg_selector_t(QtWidgets.QDialog):
    def __init__(self, args):
        super().__init__()
        self._args = args
        self._selected_arg = 0

        self._w_combobox = QtWidgets.QComboBox()
        for i, arg in self._args:
            self._w_combobox.addItem(f"Arg_{i}: Type={arg.type.dstr()}")
        
        self._w_pbtn_ok = QtWidgets.QPushButton("&Ok")
        if len(self._args) == 0:
            self._w_pbtn_ok.setEnabled(False)

        self._w_pbtn_ok.clicked.connect(self.Handle_Ok)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._w_combobox)
        layout.addWidget(self._w_pbtn_ok)

        self.setLayout(layout)

    @property
    def SelectedArg(self):
        return self._selected_arg
    
    def Handle_Ok(self):
        self._selected_arg = self._w_combobox.currentIndex()
        self.accept()


class ui_func_arg_model_t(QtWidgets.QDialog):
    def __init__(self, ui_emu, arg_type, arg_index: int, arg_alias: str, initial_value: int = 0):
        super().__init__()

        self.setWindowTitle('> func.model arg')

        self._w_model_input = ui_model_input_t(
            ui_emu, arg_type, arg_index, arg_alias, initial_value=initial_value    
        )
        
        self._w_pbtn_ok = QtWidgets.QPushButton("&Ok")
        self._w_pbtn_ok.clicked.connect(self.Handle_Ok)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._w_model_input)
        layout.addWidget(self._w_pbtn_ok)

        self.setLayout(layout)

    @property
    def Model(self):
        return self._w_model_input

    def Handle_Ok(self):
        self.accept()


class ui_func_arg_model_as_pointer_t(QtWidgets.QDialog):
    def __init__(self, ui_emu):
        super().__init__()

        self.setWindowTitle('> func.model arg :: Pointer')
        self.resize(150, 50)

        self._ui_emu = ui_emu

        self._data_address = None
        self._data_size    = None
        self._data_perm    = None
        self._data_tag     = None
        self._data         = None

        self._is_heap      = False
        self._is_new       = False

        self._user_memory_map = list(self._ui_emu.get_emu_settings()["user_memory"].items())

        self._w_combobox = QtWidgets.QComboBox()
        self._w_combobox.activated.connect(self.Handle_Index)
        for k, v in self._user_memory_map:
            self._w_combobox.addItem(
                f"Address={k:08X} Size={v['size']} Perm={v['perm']} Tag={v['tag']}"
            )

        self._w_pbtn_ok = QtWidgets.QPushButton("&Ok")
        self._w_pbtn_ok.clicked.connect(self.Handle_Ok)

        self._w_pbtn_new = QtWidgets.QPushButton("&New")
        self._w_pbtn_new.clicked.connect(self.Handle_New)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._w_combobox)
        layout.addWidget(self._w_pbtn_new)
        layout.addWidget(self._w_pbtn_ok)

        self.setLayout(layout)

    @property
    def DataAddress(self):
        return self._data_address
    
    @property
    def DataSize(self):
        return self._data_size

    @property
    def Data(self):
        return self._data
    
    @property
    def DataTag(self):
        return self._data_tag
    
    @property
    def DataPerm(self):
        return self._data_perm
    
    @property
    def IsNew(self):
        return self._is_new

    @property
    def IsHeap(self):
        return self._is_heap

    def _read_ui_selected_memory_region(self):
        k, v = self._user_memory_map[self._w_combobox.currentIndex()]

        self._data_address = k
        self._data_size    = v['size']
        self._data_perm    = v['perm']
        self._data_tag     = v['tag']
        self._data         = v['data']
        self._is_heap      = v['is_heap'] 

    def Handle_New(self):
        dlg = ui_memory_dialog_t(self._ui_emu.auto_acquire_heap_address)
        if not dlg.exec():
            return
        
        self._data_address = dlg.DataAddress
        self._data_size    = dlg.DataSize
        self._data_perm    = dlg.DataPerm
        self._data_tag     = dlg.DataTag
        self._data         = dlg.Data
        self._is_new       = True
        self._is_heap      = dlg.IsHeap 

        self.accept()

    def Handle_Index(self, index: int):
        self._read_ui_selected_memory_region()

    def Handle_Ok(self):
        if self._data_address is None:
            self._read_ui_selected_memory_region()
            
        self.accept()
            
        
class ui_model_input_t(QtWidgets.QWidget):
    def __init__(self, ui_emu, arg_type, arg_index: int, arg_alias: str, initial_value: int = 0):
        super().__init__()

        self._arg_index = arg_index
        self._arg_type  = arg_type
        self._arg_alias = arg_alias
        self._ui_emu    = ui_emu

        is_pointer = arg_type.is_ptr() 

        box = QtWidgets.QGroupBox(f"Arg_{arg_index}")

        self._w_numeric_input_concrete_value = ui_numeric_input_t(
            "Initial value", initial_value=initial_value, label_width=60)

        self._w_string_input_alias = ui_string_input_t("Alias", initial_value=arg_alias, label_width=60)

        self._w_checkbox_symbolized  = QtWidgets.QCheckBox("Symbolize")
        self._w_checkbox_symbolized.setChecked(False)

        self._w_checkbox_pointer  = QtWidgets.QCheckBox("Pointer")
        self._w_checkbox_pointer.setChecked(False)

        self._w_checkbox_auto_fields = QtWidgets.QCheckBox("Recognize symbolic field automatically")
        self._w_checkbox_auto_fields.setChecked(False)

        self._w_pbtn_allocate_address = QtWidgets.QPushButton("&As Pointer")
        self._w_pbtn_allocate_address.clicked.connect(self.Handle_AsPointer)

        concrete_box = QtWidgets.QHBoxLayout()
        concrete_box.addWidget(self._w_numeric_input_concrete_value, alignment=QtCore.Qt.AlignLeft)
        concrete_box.addWidget(self._w_pbtn_allocate_address, alignment=QtCore.Qt.AlignLeft)

        checkbox_box = QtWidgets.QHBoxLayout()
        checkbox_box.addWidget(self._w_checkbox_symbolized)
        checkbox_box.addWidget(self._w_checkbox_auto_fields)
        checkbox_box.addWidget(self._w_checkbox_pointer)

        box_layout = QtWidgets.QVBoxLayout()
        box_layout.addLayout(concrete_box)
        box_layout.addWidget(self._w_string_input_alias, alignment=QtCore.Qt.AlignLeft)
        box_layout.addLayout(checkbox_box)
        box_layout.setSpacing(10)
        
        box.setLayout(box_layout)
        
        layout = QtWidgets.QGridLayout()
        layout.addWidget(box)
        
        self.setLayout(layout)

    @property
    def Alias(self):
        return self._w_string_input_alias.get_value()
    
    @property
    def Value(self):
        return self._w_numeric_input_concrete_value.get_value()
    
    @property
    def Symbolized(self):
        return self._w_checkbox_symbolized.isChecked()

    @property
    def Pointer(self):
        return self._w_checkbox_pointer.isChecked()

    @property
    def AutoFields(self):
        return self._w_checkbox_auto_fields.isChecked()
    
    def Handle_AsPointer(self):
        dlg = ui_func_arg_model_as_pointer_t(self._ui_emu)

        if not dlg.exec():
            return
        
        if dlg.IsNew:
            self._ui_emu.add_user_memory(
                dlg.DataAddress,
                dlg.DataSize,
                dlg.DataPerm,
                dlg.DataTag,
                dlg.Data,
                dlg.IsHeap
            )

        self._w_numeric_input_concrete_value.set_value(dlg.DataAddress)
        self._w_numeric_input_concrete_value.setEnabled(False)
        self._w_pbtn_allocate_address.setEnabled(False)
        self._w_checkbox_pointer.setChecked(True)
        self._w_checkbox_pointer.setEnabled(False)


class ui_func_emu_t(kw.PluginForm):
    def __init__(self, ea: int, **kwargs):
        super().__init__()
  
        self._func = ida_funcs.get_func(ea)
        if not self._func:
            raise ValueError('ui_func_emu_t(): ea doesnt belong to any function')
        
        self._ea = self._func.start_ea
        
        self._func_frame = ida_func_frame_t(self._func)
        self._func_tinfo = ida_typeinf.tinfo_t()
        self._func_type_data = ida_typeinf.func_type_data_t()
        
        self._ui_emu = ui_emu_t()
        self._model = {}

        self.explorer = None

        self.update()
    
    def _update_exploration_info(self, i, i_br_visited, i_func_blocks_todo, i_br_todo, i_size_of_state):
        self._w_counter_exploration_info_br_visited.set_value(i_br_visited)
        self._w_counter_exploration_info_func_blocks_todo.set_value(i_func_blocks_todo)
        self._w_counter_exploration_info_func_br_todo.set_value(i_br_todo)
        self._w_counter_exploration_info_func_size_of_state.set_value(i_size_of_state)
        self._w_counter_exploration_info_iter_count.set_value(i)

    def OnCreate(self, form):
        self.parent = kw.PluginForm.FormToPyQtWidget(form)

        self.parent.resize(300, 500)
        self.parent.setWindowTitle(f"> vasco.func {VASCO_VERSION}")

        demangled_func_name = ida_name.get_demangled_name(
            self._ea, DEMANGLED_TYPEINFO, ida_ida.inf_get_demnames(), idc.GN_STRICT
        )

        self._w_label_func_address = QtWidgets.QLabel(f"Func address: {self._ea:08X}")
        self._w_label_func_name    = QtWidgets.QLabel(f"Func name: {demangled_func_name}")

        self._w_counter_exploration_info_br_visited         = ui_counter_t("Number of branched visited",    0)
        self._w_counter_exploration_info_func_blocks_todo   = ui_counter_t("Number of block to explore",    0)
        self._w_counter_exploration_info_func_br_todo       = ui_counter_t("Number of branches to explore", 0)
        self._w_counter_exploration_info_func_size_of_state = ui_counter_t("Number of symbolic varaibles",  0)
        self._w_counter_exploration_info_iter_count         = ui_counter_t("Number of iteration",           0)
        
        self._w_label_exploration_info_status               = QtWidgets.QLabel("Exploration Status: No")
        self._w_label_exploration_info_status.setFixedWidth(350)
        self._w_label_exploration_info_status.setMargin(10)

        exploration_info_box = QtWidgets.QGroupBox("Exploration info")
        exploration_info_box_layout = QtWidgets.QVBoxLayout()
        exploration_info_box_layout.addWidget(self._w_counter_exploration_info_br_visited, alignment=QtCore.Qt.AlignLeft)
        exploration_info_box_layout.addWidget(self._w_counter_exploration_info_func_blocks_todo, alignment=QtCore.Qt.AlignLeft)
        exploration_info_box_layout.addWidget(self._w_counter_exploration_info_func_br_todo, alignment=QtCore.Qt.AlignLeft)
        exploration_info_box_layout.addWidget(self._w_counter_exploration_info_func_size_of_state, alignment=QtCore.Qt.AlignLeft)
        exploration_info_box_layout.addWidget(self._w_counter_exploration_info_iter_count, alignment=QtCore.Qt.AlignLeft)
        exploration_info_box_layout.addWidget(self._w_label_exploration_info_status, alignment=QtCore.Qt.AlignLeft)

        exploration_info_box.setLayout(exploration_info_box_layout)

        self._w_pbtn_load                     = QtWidgets.QPushButton("&Load")
        self._w_pbtn_save                     = QtWidgets.QPushButton("&Save")
        self._w_pbtn_map_memory               = QtWidgets.QPushButton("&Map Memory")
        self._w_pbtn_model_arg                = QtWidgets.QPushButton("&Model Arg")
        self._w_pbtn_model_var                = QtWidgets.QPushButton("&Model Var")
        self._w_pbtn_model_arbmem             = QtWidgets.QPushButton("&Model Arbitary Memory")
        self._w_pbtn_explore                  = QtWidgets.QPushButton("&Explore")
        self._w_pbtn_emu                      = QtWidgets.QPushButton("&Emu")
        self._w_pbtn_show_exploration_results = QtWidgets.QPushButton("&Show Blocks Results")
        self._w_pbtn_show_exploration_results.setEnabled(False)
        self._w_pbtn_show_memory_results = QtWidgets.QPushButton("&Show Memory Results")
        self._w_pbtn_show_memory_results.setEnabled(False)
        self._w_pbtn_save_dyncfg = QtWidgets.QPushButton("&Save dyncfg")
        self._w_pbtn_save_dyncfg.setEnabled(False)

        self._active_butttons = [
            self._w_pbtn_load,
            self._w_pbtn_save,
            self._w_pbtn_map_memory,
            self._w_pbtn_model_arg,
            self._w_pbtn_model_var,
            self._w_pbtn_model_arbmem,
            self._w_pbtn_explore,
            self._w_pbtn_emu
        ]

        self._w_pbtn_stop_exploration = QtWidgets.QPushButton("&Stop")
        self._w_pbtn_stop_exploration.setEnabled(False)

        self._w_pbtn_model_arg.clicked.connect(self.Handle_ModelArg)
        self._w_pbtn_emu.clicked.connect(self.Handle_Emu)
        self._w_pbtn_map_memory.clicked.connect(self.Handle_MapMemory)
        self._w_pbtn_load.clicked.connect(self.Handle_Load)
        self._w_pbtn_save.clicked.connect(self.Handle_Save)
        self._w_pbtn_explore.clicked.connect(self.Handle_Explore)
        self._w_pbtn_stop_exploration.clicked.connect(self.Handle_Stop)
        self._w_pbtn_show_exploration_results.clicked.connect(self.Handle_ShowExplorationResults)
        self._w_pbtn_show_memory_results.clicked.connect(self.Handle_ShowMemoryResults)
        self._w_pbtn_save_dyncfg.clicked.connect(self.Handle_SaveDyncfg)

        layout = QtWidgets.QVBoxLayout()

        func_info_box = QtWidgets.QVBoxLayout()
        func_info_box.addWidget(
            self._w_label_func_address
        )
        func_info_box.addWidget(
            self._w_label_func_name
        )

        self._w_checkbox_auto_model_unknown_api = QtWidgets.QCheckBox("Symbolize unknown API")
        self._w_checkbox_auto_model_unknown_gv  = QtWidgets.QCheckBox("Symbolize unknown GV")
        
        exploration_settings_box = QtWidgets.QGroupBox("Exploration Settings")
        exploration_settings_layout = QtWidgets.QGridLayout()
        exploration_settings_layout.addWidget(self._w_checkbox_auto_model_unknown_api, 0, 0)
        exploration_settings_layout.addWidget(self._w_checkbox_auto_model_unknown_gv,  0, 1)

        exploration_settings_box.setLayout(exploration_settings_layout)

        
        buttons_box = QtWidgets.QGridLayout()
        buttons_box.addWidget(self._w_pbtn_load,                     0, 0)
        buttons_box.addWidget(self._w_pbtn_save,                     0, 1)
        buttons_box.addWidget(self._w_pbtn_map_memory,               1, 0)
        buttons_box.addWidget(self._w_pbtn_emu,                      1, 1)
        buttons_box.addWidget(self._w_pbtn_model_arg,                2, 0)
        buttons_box.addWidget(self._w_pbtn_model_var,                2, 1)
        buttons_box.addWidget(self._w_pbtn_model_arbmem,             3, 0)
        buttons_box.addWidget(self._w_pbtn_explore,                  4, 0)
        buttons_box.addWidget(self._w_pbtn_stop_exploration,         4, 1)
        buttons_box.addWidget(self._w_pbtn_show_exploration_results, 5, 0)
        buttons_box.addWidget(self._w_pbtn_show_memory_results,      5, 1)
        buttons_box.addWidget(self._w_pbtn_save_dyncfg,              6, 0)

        layout.addLayout(func_info_box)
        layout.addLayout(buttons_box)
        layout.addWidget(exploration_settings_box)
        layout.addWidget(exploration_info_box)

        self.parent.setLayout(layout)

        self._current_job = None

    def OnClose(self, form):
        pass

    def Show(self, caption=None, options=0):
        return kw.PluginForm.Show(self, caption, options=options)
    
    def update(self):
        self._func_tinfo = ida_typeinf.tinfo_t()
        self._func_type_data = ida_typeinf.func_type_data_t()
        
        if not ida_nalt.get_tinfo(self._func_tinfo, self._ea):
            raise ValueError('ui_func_emu_t(): failed to get tinfo')

        if not self._func_tinfo.get_func_details(self._func_type_data):
            raise ValueError('ui_func_emu_t(): failed to get func_type_data')
    
    def Handle_Emu(self):
        self._ui_emu.exec()

    def Handle_ModelArg(self):
        args = list(enumerate(self._func_type_data))

        dlg = ui_func_arg_selector_t(args)
        if not dlg.exec():
            return
        
        arg_index = dlg.SelectedArg

        dlg = ui_func_arg_model_t(
            self._ui_emu,
            args[arg_index][1].type,
            args[arg_index][0],
            f"SymVar_Arg_{args[arg_index][0]}"
        )
        
        if not dlg.exec():
            return
        
        args_model = self._model.setdefault("args", {})

        args_model[arg_index] = {
            "value":      dlg.Model.Value,
            "alias":      dlg.Model.Alias,
            "autofields": dlg.Model.AutoFields,
            "symbolized": dlg.Model.Symbolized,
            "pointer":    dlg.Model.Pointer
        }

    def Handle_MapMemory(self):
        dlg = ui_memory_dialog_t(self._ui_emu.auto_acquire_heap_address)
        if not dlg.exec():
            return
        
        self._ui_emu.add_user_memory(
            dlg.DataAddress,
            dlg.DataSize,
            dlg.DataPerm,
            dlg.DataTag,
            dlg.Data,
            dlg.IsHeap
        )

    def Handle_Load(self):
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
            caption="Open func settings", 
            filter="All Files (*);;Json (*.json)"
        )
        if not filepath:
            return
        
        with open(filepath, 'r') as fd:
            data = json_loads(fd.read())

        data["emu"]["user_memory"] = fix_memory_content(
            data["emu"]["user_memory"]
        )

        self._ui_emu.set_emu_settings(data["emu"])

        self._model["args"] = fix_integer_keys(
            data["model"].get("args", {})
        )

    def Handle_Save(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
            caption="Save func settings", 
            filter="All Files (*);;Json (*.json)"
        )
        if not filepath:
            return

        emu_state = self._ui_emu.get_emu_settings()

        state = {
            "emu": emu_state,
            "model": {
                "args": self._model.get("args", {})
            }
        }

        with open(filepath, 'w') as fd:
            fd.write(json_dumps(state, cls=BytesEncoder))

    def Handle_Stop(self):
        if not self.explorer:
            return
        
        self.explorer.stop()

        for pbtn in self._active_butttons:
            pbtn.setEnabled(True)

        self._w_pbtn_stop_exploration.setEnabled(False)

        self._w_label_exploration_info_status.setText("Exploration Status: Canceled")
        self._w_pbtn_show_exploration_results.setEnabled(True)

    def Handle_Explore(self):
        for pbtn in self._active_butttons:
            pbtn.setEnabled(False)

        self._w_pbtn_stop_exploration.setEnabled(True)

        self._update_exploration_info(0, 0, 0, 0, 0)

        emu_settings   = self._ui_emu.get_emu_settings()
        model_settings = self._model

        heap = easy_heap_t(emu_settings['heap_base'], emu_settings['heap_size'])
        heap.reset(free_list=emu_settings['heap_free_list'])

        explorer_start_ea = emu_settings['regs']['ip']

        vasco_log('?', f"starting to explore from start_ea={explorer_start_ea:08X}")

        self.explorer = basic_ida_func_path_explorer_t(
            explorer_start_ea,
            emu_settings,
            model_settings,
            heap      = heap,
            sp_bottom = emu_settings['stack_bottom'],
            sp_size   = emu_settings['stack_size'],
            callbacks = {
                ida_func_path_explorer_t.CALLBACK_ID_ITERATION_COMPLETED: [self.Handle_ExplorationIteration]
            },
            repr_mode = AST_REPRESENTATION.SMT,
            max_instructions_count = emu_settings['max_instructions_count']
        )

        self.explorer.run()

        self._w_label_exploration_info_status.setText(f"Exploration Status: {self.explorer.status_verbose}")

        for pbtn in self._active_butttons:
            pbtn.setEnabled(True)

        self._w_pbtn_stop_exploration.setEnabled(False)
        self._w_pbtn_show_exploration_results.setEnabled(True)
        self._w_pbtn_show_memory_results.setEnabled(True)
        self._w_pbtn_save_dyncfg.setEnabled(True)

    def Handle_ExplorationIteration(
            self,
            explorer: ida_func_path_explorer_t,
            i,
            todo_blocks,
            todo_br,
            visited_br,
            br_taken,
            br_not_taken,
            sym_vars
        ):

        self._update_exploration_info(
            i,
            len(visited_br),
            len(todo_blocks),
            len(todo_br),
            len(sym_vars)
        )

        QtWidgets.QApplication.processEvents()

    def Handle_ShowExplorationResults(self):
        if not self.explorer:
            return
            
        ui = ui_blocks_exploration_results_view_t(
            "Blocks Exploration Results",
            self.explorer
        )
        ui.Show()

    def Handle_ShowMemoryResults(self):
        if not self.explorer:
            return
        
    def Handle_SaveDyncfg(self):
        if not self.explorer:
            return

        emu_settings = self._ui_emu.get_emu_settings()
        
        workdir = Path(emu_settings['output_dir']) / 'dyncfg'
        if not workdir.exists():
            workdir.mkdir(parents=True, exist_ok=True)
        
        filepath = workdir / f"{self.explorer.emu.ea:08X}.dyncfg.iter.complited.dot"

        self.explorer.emu.tr.to_dot(filepath)
