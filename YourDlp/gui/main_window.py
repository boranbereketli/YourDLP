from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
import sys
from user_form import AddUserDialog
from policy_window import PolicyWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLP Policy Manager")
        self.setMinimumSize(700, 500)

        central = QWidget()
        layout = QVBoxLayout()

        # Kullanıcı listesi
        self.user_list = QListWidget()
        layout.addWidget(self.user_list)

        # Butonlar
        btns = QHBoxLayout()

        btn_add = QPushButton("Yeni Kullanıcı Ekle")
        btn_add.clicked.connect(self.add_user)
        btns.addWidget(btn_add)

        btn_edit = QPushButton("Politika Düzenle")
        btn_edit.clicked.connect(self.edit_policy)
        btns.addWidget(btn_edit)

        layout.addLayout(btns)
        central.setLayout(layout)
        self.setCentralWidget(central)

    def add_user(self):
        dialog = AddUserDialog(self)
        if dialog.exec():
            vm_id, ip, port, name = dialog.get_data()
            item = QListWidgetItem(f"{vm_id} | {name} | {ip}:{port}")
            item.setData(Qt.ItemDataRole.UserRole, {
                "vm_id": vm_id,
                "ip": ip,
                "port": port,
                "name": name
            })
            self.user_list.addItem(item)

    def edit_policy(self):
        selected = self.user_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Uyarı", "Kullanıcı seç.")
            return

        data = selected.data(Qt.ItemDataRole.UserRole)
        vm_id = data["vm_id"]

        self.policy_win = PolicyWindow(vm_id)
        self.policy_win.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec())
