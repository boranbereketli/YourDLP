from PyQt6.QtWidgets import *

class AddUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Yeni Kullanıcı")

        form = QFormLayout()

        self.vm_id = QLineEdit()
        self.ip = QLineEdit()
        self.port = QLineEdit()
        self.name = QLineEdit()

        form.addRow("VM ID:", self.vm_id)
        form.addRow("IP:", self.ip)
        form.addRow("Port:", self.port)
        form.addRow("Ad:", self.name)

        btn = QPushButton("Kaydet")
        btn.clicked.connect(self.accept)
        form.addWidget(btn)

        self.setLayout(form)

    def get_data(self):
        return (
            self.vm_id.text(),
            self.ip.text(),
            self.port.text(),
            self.name.text()
        )
