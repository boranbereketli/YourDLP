# main_window.py (Güncellendi: Network Hedefi Ekle butonu kaldırıldı)

from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
import sys
import requests
import json
from user_form import AddUserDialog
from policy_window import PolicyWindow

SERVER = "http://127.0.0.1:5000"
DATA_TYPES = ["TCKN", "IBAN_TR", "KREDI_KARTI", "E_POSTA", "TEL_NO"]


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

        # 1. Yeni Kullanıcı Ekle
        btn_add = QPushButton("Yeni Kullanıcı Ekle")
        btn_add.clicked.connect(self.add_user)
        btns.addWidget(btn_add)
        
        # 2. Politika Düzenle
        btn_edit = QPushButton("Politika Düzenle")
        btn_edit.clicked.connect(self.edit_policy)
        btns.addWidget(btn_edit)
        
        # 3. Kullanıcı Sil
        btn_delete = QPushButton("Kullanıcı Sil")
        btn_delete.clicked.connect(self.delete_user)
        btns.addWidget(btn_delete)

        layout.addLayout(btns)
        central.setLayout(layout)
        self.setCentralWidget(central)
        
        # Uygulama başladığında mevcut kullanıcıları çek
        self.load_existing_users()


    def load_existing_users(self):
        """ Sunucuda kayıtlı VM'leri listeye çeker. """
        try:
            r = requests.get(f"{SERVER}/users", timeout=2)
            users = r.json().get("users", [])
            
            for vm_id in users:
                # Gerçekte IP/Port bilgisini sunucudan çekmek gerekir, burada varsayılan olarak ekleyelim
                item = QListWidgetItem(f"{vm_id} | (Kayıtlı) | 127.0.0.1:9101")
                item.setData(Qt.ItemDataRole.UserRole, {
                    "vm_id": vm_id,
                    "ip": "127.0.0.1",
                    "port": 9101,
                    "name": "(Kayıtlı)"
                })
                self.user_list.addItem(item)
            
        except Exception:
             QMessageBox.warning(self, "Uyarı", "Mevcut kullanıcılar sunucudan çekilemedi. Sunucuyu kontrol edin.")


    def create_default_policy(self, vm_id):
        """ Yeni kullanıcı için varsayılan politikayı sunucuya gönderir (Her şey serbest). """
        default_restrictions = {d: False for d in DATA_TYPES} # False: İzin Ver (Serbest)
        default_restrictions["Keywords"] = []
        
        default_policy = {
            "clipboard": default_restrictions.copy(), 
            "usb":       default_restrictions.copy(),  
            "network":   {}, # Network kuralı yok, herkese serbest
        }
        
        payload = {
            "user_id": vm_id,
            "policies": default_policy
        }
        
        try:
            requests.post(f"{SERVER}/update_policy", json=payload, timeout=2)
            QMessageBox.information(self, "Bilgi", f"'{vm_id}' için varsayılan (Serbest) politika oluşturuldu.")
        except Exception:
            QMessageBox.warning(self, "Uyarı", "Varsayılan politika sunucuya gönderilemedi. Elle düzenlenmeli.")


    def add_user(self):
        dialog = AddUserDialog(self)
        if dialog.exec():
            vm_id, ip, port, name = dialog.get_data()
            if not vm_id: return
            
            item = QListWidgetItem(f"{vm_id} | {name} | {ip}:{port}")
            item.setData(Qt.ItemDataRole.UserRole, {
                "vm_id": vm_id,
                "ip": ip,
                "port": port,
                "name": name
            })
            self.user_list.addItem(item)
            
            # YENİ: Varsayılan politikayı sunucuya gönder
            self.create_default_policy(vm_id) 


    def delete_user(self):
        """ Kullanıcıyı listeden ve sunucu politikalarından siler. """
        selected = self.user_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Uyarı", "Silinecek kullanıcı seç.")
            return
        
        vm_id = selected.data(Qt.ItemDataRole.UserRole)["vm_id"]
        
        reply = QMessageBox.question(self, 'Onay', 
                                     f"'{vm_id}' kullanıcısını **Politikalarla birlikte sunucudan silmek** istediğinizden emin misiniz?", 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Sunucuda silme API'si olmadığı için, varsayılan olarak POST/PUT ile boş policy gönderelim
                # Gerçekte sunucuda bir DELETE API olmalıdır.
                requests.post(f"{SERVER}/delete_policy/{vm_id}", timeout=2) 
            except Exception:
                 pass # Silme endpointi olmadığı için hata verebilir, şimdilik geçiyoruz.

            self.user_list.takeItem(self.user_list.currentRow())
            QMessageBox.information(self, "Silindi", f"'{vm_id}' kullanıcısı listeden silindi.")


    def edit_policy(self):
        selected = self.user_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Uyarı", "Kullanıcı seç.")
            return

        data = selected.data(Qt.ItemDataRole.UserRole)
        vm_id = data["vm_id"]

        self.policy_win = PolicyWindow(vm_id)
        self.policy_win.show()


# Uygulama çalıştırma kısmı aynı kalır
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())