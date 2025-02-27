from pathlib import Path

from PyQt5 import QtCore, QtWidgets

import ida_kernwin as kw

from .ui_widget import ui_numeric_input_t, ui_string_input_t


class ui_memory_dialog_t(QtWidgets.QDialog):
    def __init__(self, fn_request_address, **kwargs):
        super().__init__()

        self._fn_request_address = fn_request_address

        self._data_address     = 0
        self._data_size        = 0x1000
        self._data_tag         = 'USERDATA'
        self._is_heap          = False
        self._should_fill_data = True
        self._data_fill_value  = 0x00
        self._data_filepath    = ""
        self._data_perm        = 'RWX'

        self._data = bytes()
        
        self.setWindowTitle('> emu.memory')
        self.resize(150, 80)
    
        self._w_numeric_input_address = ui_numeric_input_t('Address',   initial_value=0)
        self._w_numeric_input_size    = ui_numeric_input_t('Size',      initial_value=4096)
        self._w_numeric_input_fill    = ui_numeric_input_t('Fill with', initial_value=0)
        
        self._w_checkbox_autofill     = QtWidgets.QCheckBox('Fill')
        self._w_checkbox_autofill.setChecked(True)
        
        self._w_string_input_tag      = ui_string_input_t('Tag', initial_value=self._data_tag)
        self._w_string_input_perm     = ui_string_input_t('Perm', initial_value=self._data_perm)

        self._w_pbtn_load_from_file   = QtWidgets.QPushButton("&Load from file")
        self._w_pbtn_ok               = QtWidgets.QPushButton("&Ok")
        self._w_pbtn_allocate_address = QtWidgets.QPushButton("&A")

        self._w_pbtn_load_from_file.clicked.connect(self.Handle_LoadFromFile)
        self._w_pbtn_ok.clicked.connect(self.Handle_Ok)
        self._w_pbtn_allocate_address.clicked.connect(self.Handle_A)

        memory_info_box = QtWidgets.QGridLayout()
        address_box = QtWidgets.QHBoxLayout()
        address_box.addWidget(self._w_numeric_input_address)
        address_box.addWidget(self._w_pbtn_allocate_address)
        memory_info_box.addLayout(address_box, 0, 0)
        memory_info_box.addWidget(self._w_numeric_input_size,    0, 1)
        memory_info_box.addWidget(self._w_string_input_tag,      1, 0, alignment=QtCore.Qt.AlignLeft)
        memory_info_box.addWidget(self._w_string_input_perm,     1, 1)

        fill_info_box = QtWidgets.QHBoxLayout()
        fill_info_box.addWidget(self._w_numeric_input_fill, alignment=QtCore.Qt.AlignLeft)
        fill_info_box.addWidget(self._w_checkbox_autofill, alignment=QtCore.Qt.AlignLeft)

        buttons_box = QtWidgets.QHBoxLayout()
        buttons_box.addWidget(self._w_pbtn_load_from_file)
        buttons_box.addWidget(self._w_pbtn_ok)

        layout = QtWidgets.QVBoxLayout()

        layout.addLayout(memory_info_box)
        layout.addLayout(fill_info_box)
        layout.addLayout(buttons_box)

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
    def IsHeap(self):
        return self._is_heap

    def Handle_Ok(self):
        self._data_address = self._w_numeric_input_address.get_value()
        self._data_size    = self._w_numeric_input_size.get_value()
        self._data_perm    = self._w_string_input_perm.get_value()
        self._data_tag     = self._w_string_input_tag.get_value()

        self._should_fill_data = self._w_checkbox_autofill.isChecked()
        self._data_fill_value = self._w_numeric_input_fill.get_value()
        
        if self._should_fill_data:
            self._data = bytes([self._data_fill_value & 0xFF] * self._data_size)
        elif self._data_filepath:
            self._data = self._data_filepath.read_bytes()
        else:
            dlg = QtWidgets.QMessageBox(self)
            dlg.setWindowTitle("Memory undefined")
            dlg.setText("You should load memory content from file or enable 'Fill' checkbox for creating autofilled memory content")
            dlg.exec()

            return
        
        self.accept()
        self.close() 

    def Handle_LoadFromFile(self):
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Memory content file')
        if not filepath:
            return

        self._data_filepath = Path(filepath)
        self._data_size = self._data_filepath.stat().st_size

        self._w_numeric_input_size.set_value(self._data_size)

    def Handle_A(self):
        self._data_size = self._w_numeric_input_size.get_value()
        if not self._data_size:
            return
        
        r = self._fn_request_address(self, self._data_size)
        if r is None:
            return
        
        self._data_address = r

        self._w_numeric_input_address.set_value(self._data_address)
        self._w_numeric_input_address.setEnabled(False)
        
        self._w_numeric_input_size.set_value(self._data_size)
        self._w_numeric_input_size.setEnabled(False)
        
        self._w_pbtn_allocate_address.setEnabled(False)

        self._is_heap = True
