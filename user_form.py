from PyQt6.QtWidgets import *

class AddUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New User")
        self.setFixedWidth(300)

        form = QFormLayout()

        self.vm_id = QLineEdit()
        self.vm_id.setPlaceholderText("E.g: vm_user_5")
        
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("E.g: 127.0.0.1")

        form.addRow("VM ID:", self.vm_id)
        form.addRow("IP Address:", self.ip)

        self.btn_save = QPushButton("Add User")
        self.btn_save.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 8px;")
        self.btn_save.clicked.connect(self.accept)
        form.addRow(self.btn_save)

        self.setLayout(form)

    def get_data(self):
        return (
            self.vm_id.text().strip(),
            self.ip.text().strip()
        )