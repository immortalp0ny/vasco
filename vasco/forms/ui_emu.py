from typing import Dict, Any
from pathlib import Path
from dataclasses import dataclass

from PyQt5 import QtCore, QtWidgets

import ida_kernwin as kw
import idaapi
import idc

from .ui_widget import ui_numeric_input_t
from .ui_memory import ui_memory_dialog_t

from ..utils.ida_utils import get_size_of_ptr
from ..emu.const import (
    DEFAULT_HEAP_BASE, DEFAULT_HEAP_SIZE, DEFAULT_STACK_BOTTOM, DEFAULT_STACK_SIZE,
    DEFAULT_MAX_INSTRUCTIONS_COUNT, DEFAULT_ALIGNMENT
)
from ..emu.heap import easy_heap_t

class ui_emu_t(QtWidgets.QDialog):
    def __init__(self, **kwargs):
        super().__init__()

        self._regs = {}
        self._ptrsz = get_size_of_ptr()

        self._user_memory_map = {}

        self._is_heap_settings_locked = False
        self._save_memory_regions = True

        self._heap_base    = DEFAULT_HEAP_BASE
        self._heap_size    = DEFAULT_HEAP_SIZE
        self._heap         = None

        self._stack_size   = DEFAULT_STACK_SIZE
        self._stack_bottom = DEFAULT_STACK_BOTTOM
        self._max_instructions_count = DEFAULT_MAX_INSTRUCTIONS_COUNT
        
        self._ax    = 0
        self._bx    = 0
        self._cx    = 0
        self._dx    = 0
        self._si    = 0
        self._di    = 0
        # self._sp    = 0
        self._bp    = 0
        self._r8    = 0
        self._r9    = 0
        self._r10   = 0
        self._r11   = 0
        self._r12   = 0
        self._r13   = 0
        self._r14   = 0
        self._r15   = 0
        self._flags = 0
        self._ip    = 0

        idbpath = Path(idc.get_idb_path())

        self._output_dir_path = str(idbpath.parent / f"vasco_{idbpath.name[:-4]}")

        self.resize(200, 200)
        self.setWindowTitle('> emu run')

        self._w_numeric_input_ax = ui_numeric_input_t('AX ', initial_value=0)
        self._w_numeric_input_bx = ui_numeric_input_t('BX ', initial_value=0)
        self._w_numeric_input_cx = ui_numeric_input_t('CX ', initial_value=0)
        self._w_numeric_input_dx = ui_numeric_input_t('DX ', initial_value=0)
        self._w_numeric_input_si = ui_numeric_input_t('SI ', initial_value=0)
        self._w_numeric_input_di = ui_numeric_input_t('DI ', initial_value=0)
        self._w_numeric_input_sp = ui_numeric_input_t('SP ', initial_value=(1 << (self._ptrsz * 8)) - 1)
        self._w_numeric_input_sp.setEnabled(False)
        self._w_numeric_input_bp = ui_numeric_input_t('BP ', initial_value=0)

        self._w_numeric_input_r8  = ui_numeric_input_t('R8 ', initial_value=0)
        self._w_numeric_input_r8.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r9  = ui_numeric_input_t('R9 ', initial_value=0)
        self._w_numeric_input_r9.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r10 = ui_numeric_input_t('R10', initial_value=0)
        self._w_numeric_input_r10.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r11 = ui_numeric_input_t('R11', initial_value=0)
        self._w_numeric_input_r11.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r12 = ui_numeric_input_t('R12', initial_value=0)
        self._w_numeric_input_r12.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r13 = ui_numeric_input_t('R13', initial_value=0)
        self._w_numeric_input_r13.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r14 = ui_numeric_input_t('R14', initial_value=0)
        self._w_numeric_input_r14.setEnabled(self._ptrsz == 8)
        self._w_numeric_input_r15 = ui_numeric_input_t('R15', initial_value=0)
        self._w_numeric_input_r15.setEnabled(self._ptrsz == 8)

        self._w_line_edit_output_dir = QtWidgets.QLineEdit(self._output_dir_path)

        self._w_checkbox_dump_memory = QtWidgets.QCheckBox("Dump memory regions")
        self._w_checkbox_dump_memory.setChecked(self._save_memory_regions)

        self._w_numeric_input_stack_bottom = ui_numeric_input_t('SP Bottom', initial_value=DEFAULT_STACK_BOTTOM)
        self._w_numeric_input_stack_size   = ui_numeric_input_t('SP Size  ', initial_value=DEFAULT_STACK_SIZE)
        self._w_numeric_input_heap_base    = ui_numeric_input_t('Heap Base', initial_value=DEFAULT_HEAP_BASE)
        self._w_numeric_input_heap_size    = ui_numeric_input_t('Heap Size', initial_value=DEFAULT_HEAP_SIZE)
        self._w_numeric_input_ip           = ui_numeric_input_t('IP',        initial_value=idaapi.get_screen_ea())
        self._w_numeric_input_flags        = ui_numeric_input_t('FLAGS',     initial_value=0)

        self._w_numeric_input_max_instructions_count = ui_numeric_input_t('Max instructions', initial_value=DEFAULT_MAX_INSTRUCTIONS_COUNT)

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(self._w_numeric_input_ax, 0, 0)
        grid_box.addWidget(self._w_numeric_input_bx, 1, 0)
        grid_box.addWidget(self._w_numeric_input_cx, 2, 0)
        grid_box.addWidget(self._w_numeric_input_dx, 3, 0)
        grid_box.addWidget(self._w_numeric_input_si, 4, 0)
        grid_box.addWidget(self._w_numeric_input_di, 5, 0)
        grid_box.addWidget(self._w_numeric_input_sp, 6, 0)
        grid_box.addWidget(self._w_numeric_input_bp, 7, 0)
        
        grid_box.addWidget(self._w_numeric_input_r8,  0, 1)
        grid_box.addWidget(self._w_numeric_input_r9,  1, 1)
        grid_box.addWidget(self._w_numeric_input_r10, 2, 1)
        grid_box.addWidget(self._w_numeric_input_r11, 3, 1)
        grid_box.addWidget(self._w_numeric_input_r12, 4, 1)
        grid_box.addWidget(self._w_numeric_input_r13, 5, 1)
        grid_box.addWidget(self._w_numeric_input_r14, 6, 1)
        grid_box.addWidget(self._w_numeric_input_r15, 7, 1)

        grid_box.addWidget(self._w_numeric_input_stack_bottom, 0, 2)
        grid_box.addWidget(self._w_numeric_input_stack_size,   1, 2)
        grid_box.addWidget(self._w_numeric_input_heap_base,    2, 2)
        grid_box.addWidget(self._w_numeric_input_heap_size,    3, 2)
        grid_box.addWidget(self._w_numeric_input_ip,           4, 2)
        grid_box.addWidget(self._w_numeric_input_flags,        5, 2)
        grid_box.addWidget(self._w_numeric_input_max_instructions_count, 6, 2)
        grid_box.addWidget(self._w_checkbox_dump_memory,       7, 2)

        grid_box.setColumnStretch(0, 1)
        grid_box.setColumnStretch(1, 1)
        grid_box.setColumnStretch(2, 1)

        self._w_pbtn_set_output_dir = QtWidgets.QPushButton("&Set Output Dir")
        self._w_pbtn_ok = QtWidgets.QPushButton("&Ok")

        self._w_pbtn_ok.clicked.connect(self.Handle_Ok)

        output_box = QtWidgets.QHBoxLayout()
        output_box.addWidget(self._w_line_edit_output_dir)
        output_box.addWidget(self._w_pbtn_set_output_dir)

        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.addLayout(grid_box)
        vertical_box.addLayout(output_box)
        vertical_box.addWidget(self._w_pbtn_ok)
        
        self.setLayout(vertical_box)

    def auto_acquire_heap_address(self, parent: QtWidgets.QWidget, size: int):
        if not self._is_heap_settings_locked:
            dlg = QtWidgets.QMessageBox(parent)
            dlg.setWindowTitle("Heap settings")
            dlg.setText("Heap settings has not been locked yet. Lock them ?")
            dlg.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)

            if dlg.exec() == QtWidgets.QMessageBox.No:
                return
            
            self._heap_base = self._w_numeric_input_heap_base.get_value()
            self._heap_size = self._w_numeric_input_heap_size.get_value()
            self._heap = easy_heap_t(self._heap_base, self._heap_size)

            self._w_numeric_input_heap_base.setEnabled(False)
            self._w_numeric_input_heap_size.setEnabled(False)
            
            self._is_heap_settings_locked = True

        acquired_address = self._heap.acquire(int((size + (DEFAULT_ALIGNMENT - 1)) / DEFAULT_ALIGNMENT) * DEFAULT_ALIGNMENT)
        if acquired_address is None:
            raise RuntimeError('ui >> failed acquire heap address')

        return acquired_address
    
    def add_user_memory(self, address: int, size: int, perm: str, tag: str, data: bytes, is_heap: bool):
        if self._user_memory_map.get(address):
            raise KeyError(f"{address:08X} has been already mapped")
        
        self._user_memory_map[address] = {
            "size":    size,
            "tag":     tag,
            "perm":    perm,
            "data":    data,
            "is_heap": is_heap
        }

    def set_emu_settings(self, settings: Dict[str, Any]):
        self._ax    = settings["regs"]["ax"]
        self._bx    = settings["regs"]["bx"]
        self._cx    = settings["regs"]["cx"]
        self._dx    = settings["regs"]["dx"]
        self._si    = settings["regs"]["si"]
        self._di    = settings["regs"]["di"]
        self._bp    = settings["regs"]["bp"]
        self._r8    = settings["regs"]["r8"]
        self._r9    = settings["regs"]["r9"]
        self._r10   = settings["regs"]["r10"]
        self._r11   = settings["regs"]["r11"]
        self._r12   = settings["regs"]["r12"]
        self._r13   = settings["regs"]["r13"]
        self._r14   = settings["regs"]["r14"]
        self._r15   = settings["regs"]["r15"]
        self._ip    = settings["regs"]["ip"]
        self._flags = settings["regs"]["flags"]

        self._heap_base           = settings["heap_base"]
        self._heap_size           = settings["heap_size"]
        
        self._heap = easy_heap_t(self._heap_base, self._heap_size)
        self._heap.reset(free_list = settings["heap_free_list"])
        
        self._stack_bottom        = settings["stack_bottom"]
        self._stack_size          = settings["stack_size"]
        self._save_memory_regions = settings["save_memory_regions"]
        self._output_dir          = settings["output_dir"]
        self._user_memory_map     = settings["user_memory"]
        self._is_heap_settings_locked = settings["heap_locked"]
        self._max_instructions_count = settings["max_instructions_count"]

        self._write_ui()
    
    def get_emu_settings(self):
        self._read_ui()

        free_list = []
        if self._heap:
            free_list = self._heap.free_list

        return {
            "regs": {
                "ax": self._ax,
                "bx": self._bx,
                "cx": self._cx,
                "dx": self._dx,
                "si": self._si,
                "di": self._di,
                "bp": self._bp,
                "r8": self._r8,
                "r9": self._r9,
                "r10": self._r10,
                "r11": self._r11,
                "r12": self._r12,
                "r13": self._r13,
                "r14": self._r14,
                "r15": self._r15,
                "ip": self._ip,
                "flags": self._flags
            },
            "heap_free_list": free_list,
            "heap_base":      self._heap_base,
            "heap_size":      self._heap_size,
            "heap_locked": self._is_heap_settings_locked,
            "stack_bottom": self._stack_bottom,
            "stack_size": self._stack_size,
            "save_memory_regions": self._save_memory_regions,
            "output_dir":  self._output_dir_path,
            "user_memory": self._user_memory_map,
            "max_instructions_count": self._max_instructions_count
        }

    def _read_ui(self):
        self._ax    = self._w_numeric_input_ax.get_value()
        self._bx    = self._w_numeric_input_bx.get_value()
        self._cx    = self._w_numeric_input_cx.get_value()
        self._dx    = self._w_numeric_input_dx.get_value()
        self._si    = self._w_numeric_input_si.get_value()
        self._di    = self._w_numeric_input_di.get_value()
        # self._sp    = self._w_numeric_input_sp.get_value()
        self._bp    = self._w_numeric_input_bp.get_value()
        self._r8    = self._w_numeric_input_r8.get_value()
        self._r9    = self._w_numeric_input_r9.get_value()
        self._r10   = self._w_numeric_input_r10.get_value()
        self._r11   = self._w_numeric_input_r11.get_value()
        self._r12   = self._w_numeric_input_r12.get_value()
        self._r13   = self._w_numeric_input_r13.get_value()
        self._r14   = self._w_numeric_input_r14.get_value()
        self._r15   = self._w_numeric_input_r15.get_value()
        self._flags = self._w_numeric_input_flags.get_value()
        self._ip    = self._w_numeric_input_ip.get_value()

        self._stack_bottom = self._w_numeric_input_stack_bottom.get_value()
        self._stack_size   = self._w_numeric_input_stack_size.get_value()
        self._heap_base    = self._w_numeric_input_heap_base.get_value()   
        self._heap_size    = self._w_numeric_input_heap_size.get_value()

        self._output_dir_path = self._w_line_edit_output_dir.text()
        self._save_memory_regions = self._w_checkbox_dump_memory.isChecked()

        self._is_heap_settings_locked = not self._w_numeric_input_heap_base.isEnabled()

        self._max_instructions_count = self._w_numeric_input_max_instructions_count.get_value()
        
    def _write_ui(self):
        self._w_numeric_input_ax.set_value(self._ax)
        self._w_numeric_input_bx.set_value(self._bx)
        self._w_numeric_input_cx.set_value(self._cx)
        self._w_numeric_input_dx.set_value(self._dx)
        self._w_numeric_input_si.set_value(self._si)
        self._w_numeric_input_di.set_value(self._di)
        # self._w_numeric_input_sp.set_value(self._sp)
        self._w_numeric_input_bp.set_value(self._bp)
        self._w_numeric_input_r8.set_value(self._r8)
        self._w_numeric_input_r9.set_value(self._r9)
        self._w_numeric_input_r10.set_value(self._r10)
        self._w_numeric_input_r11.set_value(self._r11)
        self._w_numeric_input_r12.set_value(self._r12)
        self._w_numeric_input_r13.set_value(self._r13)
        self._w_numeric_input_r14.set_value(self._r14)
        self._w_numeric_input_r15.set_value(self._r15)

        self._w_numeric_input_stack_bottom.set_value(self._stack_bottom)
        self._w_numeric_input_stack_size.set_value(self._stack_size)

        self._w_numeric_input_heap_base.set_value(self._heap_base)
        self._w_numeric_input_heap_size.set_value(self._heap_size)

        self._w_checkbox_dump_memory.setChecked(self._save_memory_regions)
        self._w_line_edit_output_dir.setText(self._output_dir_path)

        if self._is_heap_settings_locked:
            self._w_numeric_input_heap_base.setEnabled(False)
            self._w_numeric_input_heap_size.setEnabled(False)

        self._w_numeric_input_max_instructions_count.set_value(self._max_instructions_count)

    def Handle_Ok(self):
        self._read_ui()

        self.accept()
