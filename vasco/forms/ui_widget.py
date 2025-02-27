from PyQt5 import QtCore, QtWidgets, QtGui 

import z3


class ui_numeric_input_t(QtWidgets.QWidget):
    def __init__(self, title, label_width: int = 50, initial_value=None):
        super().__init__()
        layout = QtWidgets.QHBoxLayout(self)
        layout.setSpacing(10)
        self.setLayout(layout)
        
        self._w_label = QtWidgets.QLabel(self)
        self._w_label.setText(title)
        self._w_label.setFixedWidth(label_width)

        self._w_line_edit = QtWidgets.QLineEdit(self)
        self._w_line_edit.setFixedWidth(100)
        self._w_line_edit.setValidator(
            QtGui.QRegExpValidator(
                QtCore.QRegExp("^(0x[0-9A-Fa-f]+)|([0-9]+.)|([0-9A-Fa-f]+h)$"), 
                self._w_line_edit
            )
        )
        if initial_value != None:
            self._w_line_edit.setText(f"0x{initial_value:08X}")

        layout.addWidget(self._w_label)    
        layout.addWidget(self._w_line_edit)
    
    def get_value(self) -> int:
        text = self._w_line_edit.text()
        if text.startswith('0x'):
            return int(text[2:], 16)
        
        if text.endswith('h'):
            return int(text[:-1], 16)
        
        if not text:
            return 0

        return int(text)
    
    def set_value(self, value: int):
        self._w_line_edit.setText(f"0x{value:08X}")
    

class ui_string_input_t(QtWidgets.QWidget):
    def __init__(self, title, label_width: int = 50, initial_value=""):
        super().__init__()
        layout = QtWidgets.QHBoxLayout(self)
        layout.setSpacing(0)
        self.setLayout(layout)
        
        self._w_label = QtWidgets.QLabel(self)
        self._w_label.setText(title)
        self._w_label.setFixedWidth(label_width)

        self._w_line_edit = QtWidgets.QLineEdit(self)
        self._w_line_edit.setFixedWidth(100)
        
        if initial_value is not None:
            self._w_line_edit.setText(f"{initial_value}")

        layout.addWidget(self._w_label)    
        layout.addWidget(self._w_line_edit)
    
    def get_value(self) -> str:
        return self._w_line_edit.text()


class ui_counter_t(QtWidgets.QWidget):
    def __init__(self, title: str, initial_value: int, title_width: int = 200, counter_width: int = 50):
        super().__init__()

        layout = QtWidgets.QHBoxLayout(self)
        layout.setSpacing(10)
        self.setLayout(layout)

        self._w_label_title = QtWidgets.QLabel(self)
        self._w_label_title.setText(title)
        self._w_label_title.setFixedWidth(title_width)

        self._w_label_counter = QtWidgets.QLabel(self)
        self._w_label_counter.setText(f"{initial_value}")
        self._w_label_counter.setFixedWidth(counter_width)

        layout.addWidget(self._w_label_title)
        layout.addWidget(self._w_label_counter)
    
    def incr(self, step: int = 1):
        self._w_label_counter.setText(
            f"{self.get_value() + step}"
        )

    def decr(self, step: int = 1):
        self._w_label_counter.setText(
            f"{self.get_value() - step}"
        )

    def set_value(self, value: int):
        self._w_label_counter.setText(
            f"{value}"
        )

    def get_value(self):
        return int(self._w_label_counter.text())


class ui_smt_input_t(QtWidgets.QWidget):
    def __init__(self, title: str = "SMT Formula", initial_value: str = "", title_width: int = 200):
        super().__init__()

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(10)
        self.setLayout(layout)

        self._w_label_title = QtWidgets.QLabel(self)
        self._w_label_title.setText(title)
        self._w_label_title.setFixedWidth(title_width)

        self._w_text_edit_formula = QtWidgets.QTextEdit(self)

        layout.addWidget(self._w_label_title)
        layout.addWidget(self._w_text_edit_formula)

    def set_value(self, value: str):
        self._w_text_edit_formula.setText(
            value
        )

    def get_value(self):
        smt_lib_text = self._w_text_edit_formula.toPlainText()
        if not smt_lib_text:
            return None

        try:
            return z3.parse_smt2_string(smt_lib_text) 
        except z3.Z3Exception:
            return None
