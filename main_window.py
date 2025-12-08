import sys
import requests
import json
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Diğer modüller
from user_form import AddUserDialog
from policy_window import PolicyWindow

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "KREDI_KARTI", "E_POSTA", "TEL_NO"]

# =====================================================
# LOG VIEWER DIALOG
# =====================================================
# main_window.py içindeki LogViewerDialog sınıfını bununla güncelle:

class LogViewerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sistem Logları ve İhlaller")
        self.resize(1100, 600)
        
        # Sadece Layout ve Pencere Rengi ayarı burada kalabilir
        # (veya bunu da QDialog olarak styles.qss'e taşıyabilirsin)
        self.setStyleSheet("background-color: #f4f6f9;") 
        
        layout = QVBoxLayout(self)
        
        # Bilgi Etiketi
        lbl_info = QLabel("🔎 Aşağıda sistemde gerçekleşen tüm DLP olayları ve engellemeler listelenmektedir.")
        lbl_info.setStyleSheet("color: #555; font-size: 14px; margin-bottom: 5px; font-weight: bold;")
        layout.addWidget(lbl_info)

        # Tablo (Artık stili styles.qss'ten alacak)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Tarih", "Olay Tipi", "Veri Tipi", "Aksiyon", "Detay"])
        
        # Tablo ayarları (Görünüm değil, davranış ayarları)
        self.table.setAlternatingRowColors(True) # Satırları bir gri bir beyaz yapar
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows) # Tıklayınca tüm satırı seç
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers) # Düzenlemeyi kapat
        
        # Sütun Genişlikleri
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 200)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.table)
        
        # Kapat Butonu
        btn_close = QPushButton("Kapat")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        # Buton stili zaten styles.qss'te tanımlı (QPushButton) o yüzden ekstra koda gerek yok
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)
        
        self.load_logs()

    def load_logs(self):
        self.table.setRowCount(0)
        try:
            # Serverdan veriyi çek
            r = requests.get(f"{SERVER}/all_logs", timeout=3)
            if r.status_code == 200:
                data = r.json()
                logs = data.get("logs", [])
                
                self.table.setRowCount(len(logs))
                for row_idx, log in enumerate(logs):
                    items = [
                        log.get("Tarih", ""),
                        log.get("Olay_Tipi", ""),
                        log.get("Veri_Tipi", ""),
                        log.get("Aksiyon", ""),
                        log.get("Detay", "")
                    ]
                    
                    for col_idx, text in enumerate(items):
                        item = QTableWidgetItem(str(text))
                        
                        if "ENGEL" in items[3]:  
                            item.setBackground(QColor("#ffebee")) # Açık Kırmızı Arkaplan
                            if col_idx == 3: 
                                item.setForeground(QColor("#c62828")) # Koyu Kırmızı Yazı
                                item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                                
                        elif "İZİN" in items[3]:
                            item.setBackground(QColor("#e8f5e9")) # Açık Yeşil Arkaplan
                            if col_idx == 3: 
                                item.setForeground(QColor("#2e7d32")) # Koyu Yeşil Yazı
                                item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                        
                        self.table.setItem(row_idx, col_idx, item)
            else:
                QMessageBox.warning(self, "Hata", "Loglar sunucudan alınamadı.")
        except Exception as e:
            QMessageBox.critical(self, "Bağlantı Hatası", f"Sunucuya bağlanılamadı: {str(e)}")

    def load_logs(self):
        self.table.setRowCount(0)
        try:
            r = requests.get(f"{SERVER}/all_logs", timeout=3)
            if r.status_code == 200:
                data = r.json()
                logs = data.get("logs", [])
                
                self.table.setRowCount(len(logs))
                for row_idx, log in enumerate(logs):
                    # CSV'den gelen key'ler: Tarih, Olay_Tipi, Veri_Tipi, Aksiyon, Detay
                    items = [
                        log.get("Tarih", ""),
                        log.get("Olay_Tipi", ""),
                        log.get("Veri_Tipi", ""),
                        log.get("Aksiyon", ""),
                        log.get("Detay", "")
                    ]
                    
                    for col_idx, text in enumerate(items):
                        item = QTableWidgetItem(str(text))
                        # Renklendirme Mantığı
                        if "ENGEL" in items[3]:  # Aksiyon sütunu "ENGEL" içeriyorsa
                            item.setBackground(QColor("#ffebee")) # Açık kırmızı
                            if col_idx == 3: item.setForeground(QColor("#c62828"))
                        elif "İZİN" in items[3]:
                            item.setBackground(QColor("#e8f5e9")) # Açık yeşil
                            if col_idx == 3: item.setForeground(QColor("#2e7d32"))
                            
                        self.table.setItem(row_idx, col_idx, item)
            else:
                QMessageBox.warning(self, "Hata", "Loglar sunucudan alınamadı.")
        except Exception as e:
            QMessageBox.critical(self, "Bağlantı Hatası", f"Sunucuya bağlanılamadı: {str(e)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLP Policy Manager - Admin Paneli")
        self.setMinimumSize(900, 650)
        
        # Ana Stil (CSS)
        self.setStyleSheet("""
            QMainWindow { background-color: #f4f6f9; }
            QLabel { font-family: 'Segoe UI', sans-serif; font-size: 14px; color: #333; }
            QPushButton {
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                color: white;
                border: none;
            }
            QPushButton:hover { opacity: 0.9; }
            QListWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dce4ec;
                font-size: 14px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #eee;
                color: #333;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #0d47a1;
                border-radius: 6px;
            }
        """)

        central = QWidget()
        self.layout = QVBoxLayout(central)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(20)
        
        # 1. HEADER (ÜST BÖLÜM)
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 12px;
                border: 1px solid #e0e0e0;
            }
        """)
        header_lay = QHBoxLayout(header_frame)
        header_lay.setContentsMargins(25, 20, 25, 20)

        # Başlık ve Durum
        title_lay = QVBoxLayout()
        lbl_title = QLabel("🛡️ <b>DLP Politika Yöneticisi</b>")
        lbl_title.setStyleSheet("font-size: 22px; color: #1a237e;")
        
        self.lbl_server_status = QLabel("Sunucu Durumu: Kontrol ediliyor...")
        self.lbl_server_status.setStyleSheet("color: gray; font-size: 13px;")
        
        title_lay.addWidget(lbl_title)
        title_lay.addWidget(self.lbl_server_status)
        
        header_lay.addLayout(title_lay)
        header_lay.addStretch()

        # Log Butonu (Turuncu)
        btn_logs = QPushButton("📜 Log Kayıtları")
        btn_logs.setStyleSheet("background-color: #f57f17; margin-right: 10px;") # Turuncu
        btn_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_logs.clicked.connect(self.open_logs)
        header_lay.addWidget(btn_logs)

        # Yenile Butonu (Gri ton)
        btn_refresh = QPushButton("🔄 Yenile")
        btn_refresh.setStyleSheet("background-color: #607d8b;")
        btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_refresh.clicked.connect(self.load_existing_users)
        header_lay.addWidget(btn_refresh)

        self.layout.addWidget(header_frame)
        
        # 2. KULLANICI LİSTESİ
        group_box = QGroupBox("Kayıtlı Kullanıcılar (VM)")
        group_box.setStyleSheet("QGroupBox { font-weight: bold; font-size: 15px; color: #444; }")
        group_lay = QVBoxLayout(group_box)

        self.user_list = QListWidget()
        self.user_list.setAlternatingRowColors(True)
        group_lay.addWidget(self.user_list)
        
        self.layout.addWidget(group_box)
        
        # 3. AKSİYON BUTONLARI (ALT BÖLÜM)
        action_frame = QFrame()
        action_lay = QHBoxLayout(action_frame)
        action_lay.setContentsMargins(0, 10, 0, 10)
        action_lay.setSpacing(15)

        # Ekle Butonu (Yeşil)
        btn_add = QPushButton("➕ Yeni Kullanıcı Ekle")
        btn_add.setStyleSheet("background-color: #2e7d32; padding: 12px 25px;")
        btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add.clicked.connect(self.add_user)

        # Düzenle Butonu (Mavi)
        btn_edit = QPushButton("📝 Politika Düzenle")
        btn_edit.setStyleSheet("background-color: #1565c0; padding: 12px 25px;")
        btn_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_edit.clicked.connect(self.edit_policy)

        # Sil Butonu (Kırmızı)
        btn_del = QPushButton("🗑️ Sil")
        btn_del.setStyleSheet("background-color: #c62828; padding: 12px 25px;")
        btn_del.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_del.clicked.connect(self.delete_user)

        action_lay.addWidget(btn_add)
        action_lay.addWidget(btn_edit)
        action_lay.addStretch() # Sil butonunu sağa yaslamak için
        action_lay.addWidget(btn_del)
        
        self.layout.addWidget(action_frame)

        self.setCentralWidget(central)
        
        # Başlangıçta verileri çek
        self.load_existing_users()

    # =====================================================
    # LOGIC
    # =====================================================
    def load_existing_users(self):
        """Sunucudaki kullanıcıları çeker ve listeler."""
        self.user_list.clear()
        try:
            r = requests.get(f"{SERVER}/users", timeout=2)
            if r.status_code == 200:
                self.lbl_server_status.setText("Sunucu Durumu: ✅ Çevrimiçi")
                self.lbl_server_status.setStyleSheet("color: green; font-weight: bold;")
                
                users = r.json().get("users", [])
                if not users:
                    self.user_list.addItem("⚠️ Kayıtlı kullanıcı bulunamadı.")
                    return

                for vm_id in users:
                    # Liste elemanını daha şık gösterelim
                    display_text = f"👤  {vm_id}   |   DLP Ajanı   |   (127.0.0.1)"
                    item = QListWidgetItem(display_text)
                    # Kullanıcı verisini arka planda sakla
                    item.setData(Qt.ItemDataRole.UserRole, {
                        "vm_id": vm_id,
                        "ip": "127.0.0.1",
                        "port": 9101,
                        "name": "(Kayıtlı)"
                    })
                    self.user_list.addItem(item)
            else:
                self.set_server_error(f"Hata Kodu: {r.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.set_server_error("Bağlantı Yok")
        except Exception as e:
             self.set_server_error(str(e))

    def set_server_error(self, msg):
        self.lbl_server_status.setText(f"Sunucu Durumu: ❌ {msg}")
        self.lbl_server_status.setStyleSheet("color: red; font-weight: bold;")
        self.user_list.addItem("❌ Sunucuya erişilemiyor. Lütfen server.py'yi başlatın.")

    def create_default_policy(self, vm_id):
        """Yeni kullanıcı için varsayılan politikayı oluşturur."""
        # Varsayılan: Her şey SERBEST (False), Keywords boş
        default_restrictions = {d: False for d in DATA_TYPES} 
        default_restrictions["Keywords"] = []
        
        default_policy = {
            "clipboard": default_restrictions.copy(), 
            "usb":       default_restrictions.copy(),  
            "network":   {}, # Ağ kuralları sonradan eklenir
        }
        
        payload = {"user_id": vm_id, "policies": default_policy}
        try:
            requests.post(f"{SERVER}/update_policy", json=payload, timeout=2)
            QMessageBox.information(self, "Başarılı", f"'{vm_id}' için varsayılan politika oluşturuldu.")
        except:
            QMessageBox.warning(self, "Uyarı", "Varsayılan politika sunucuya gönderilemedi (daha sonra düzenlenebilir).")

    def add_user(self):
        dialog = AddUserDialog(self)
        if dialog.exec():
            vm_id, ip, port, name = dialog.get_data()
            if not vm_id:
                QMessageBox.warning(self, "Hata", "VM ID zorunludur.")
                return
            
            # Listeye ekle (Görsel olarak)
            item = QListWidgetItem(f"👤  {vm_id}   |   {name}   |   {ip}:{port}")
            item.setData(Qt.ItemDataRole.UserRole, {
                "vm_id": vm_id, "ip": ip, "port": port, "name": name
            })
            self.user_list.addItem(item)
            
            # Sunucuya varsayılan politika gönder
            self.create_default_policy(vm_id)
            
            # Listeyi sunucudan tekrar çekip tazele
            self.load_existing_users()

    def delete_user(self):
        selected_items = self.user_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Seçim Yok", "Lütfen silinecek kullanıcıyı seçin.")
            return
        
        item = selected_items[0]
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return # Hata mesajı satırı seçildiyse

        vm_id = data["vm_id"]
        
        reply = QMessageBox.question(self, 'Silme Onayı', 
                                     f"'{vm_id}' kullanıcısını ve politikalarını silmek istiyor musunuz?", 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Sunucudan sil
                requests.post(f"{SERVER}/delete_policy/{vm_id}", timeout=2)
                # Listeden sil
                self.user_list.takeItem(self.user_list.row(item))
                QMessageBox.information(self, "Silindi", "Kullanıcı başarıyla silindi.")
            except:
                QMessageBox.critical(self, "Hata", "Sunucudan silinirken hata oluştu.")

    def edit_policy(self):
        selected_items = self.user_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Seçim Yok", "Lütfen düzenlenecek kullanıcıyı seçin.")
            return

        item = selected_items[0]
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data: return

        vm_id = data["vm_id"]
        
        # Policy Window'u Aç
        self.policy_win = PolicyWindow(vm_id)
        self.policy_win.show()

    def open_logs(self):
        """Log görüntüleme penceresini açar."""
        dialog = LogViewerDialog(self)
        dialog.exec()
    # --------------------------------------------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Yazı tiplerini netleştirme (Windows için)
    app.setStyle("Fusion")
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())