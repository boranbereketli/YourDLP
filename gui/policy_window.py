# policy_window.py (Tam ve Kalıcı Kayıt Özellikli)

from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
import requests
import json

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "KREDI_KARTI", "E_POSTA", "TEL_NO"]


# ======================================================
#  POLICY TAB SINIFI (Tek bir sekme içeriği)
# ======================================================
class PolicyTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.checks = {}

        # Checkboxlar (TCKN, IBAN vb.)
        for d in DATA_TYPES:
            cb = QCheckBox(d)
            layout.addWidget(cb)
            self.checks[d] = cb

        # Keywords alanı
        layout.addWidget(QLabel("Yasaklı Kelimeler (virgülle ayır):"))
        self.keywords = QLineEdit()
        self.keywords.setPlaceholderText("Örn: gizli, proje, maaş")
        layout.addWidget(self.keywords)
        
        layout.addStretch()
        self.setLayout(layout)

    # Policy (Dict) -> GUI
    def load(self, data: dict):
        """ Gelen veriyi ekrandaki kutucuklara doldurur. """
        if not data: data = {}
        for d in DATA_TYPES:
            # True ise işaretle, False veya Yoksa işaretleme
            self.checks[d].setChecked(bool(data.get(d, False)))

        # Keywords listesini metin kutusuna çevir
        kws = data.get("Keywords", [])
        if isinstance(kws, list):
            self.keywords.setText(", ".join(kws))
        else:
            self.keywords.setText("")
        
        # Etkileşimi aç
        self.set_controls_enabled(True)

    # GUI -> Policy (Dict)
    def export(self):
        """ Ekrandaki kutucukları veriye dönüştürür. """
        out = {d: self.checks[d].isChecked() for d in DATA_TYPES}
        
        # Metin kutusunu listeye çevir
        text = self.keywords.text()
        kws = [k.strip() for k in text.split(",") if k.strip()]
        out["Keywords"] = kws
        
        return out
        
    def set_controls_enabled(self, enabled):
        """ Kontrolleri aç/kapa """
        for cb in self.checks.values():
            cb.setEnabled(enabled)
        self.keywords.setEnabled(enabled)


# ======================================================
#  ANA PENCERE — POLICYWINDOW
# ======================================================
class PolicyWindow(QWidget):
    def __init__(self, vm_id, initial_target=None):
        super().__init__()
        self.vm_id = vm_id
        self.setWindowTitle(f"Politika Düzenle — {vm_id}")
        self.setMinimumSize(800, 500)
        
        # Veri yapıları
        self.network_data = {}    # { 'hedef_vm': {TCKN: True...} }
        self.raw_policy = {}      # Sunucudan gelen ham veri
        self.current_target_vm = None # O an Network sekmesinde seçili olan hedef

        # Layout
        main = QVBoxLayout()

        # Tabs
        self.tabs = QTabWidget()

        self.clip_tab = PolicyTab()
        self.usb_tab = PolicyTab()
        self.net_tab = self.build_network_tab()

        self.tabs.addTab(self.clip_tab, "Clipboard (Pano)")
        self.tabs.addTab(self.usb_tab, "USB Transfer")
        self.tabs.addTab(self.net_tab, "Network (Ağ)")

        main.addWidget(self.tabs)

        # Kaydet butonu
        btn_save = QPushButton("💾 POLİTİKAYI KAYDET")
        btn_save.setStyleSheet("font-weight: bold; padding: 10px; background-color: #4CAF50; color: white;")
        btn_save.clicked.connect(self.save)
        main.addWidget(btn_save)

        self.setLayout(main)

        # Başlangıçta verileri çek
        self.fetch_existing()

    # ===============================================
    # NETWORK SEKME YAPISI
    # ===============================================
    def build_network_tab(self):
        wrapper = QWidget()
        layout = QHBoxLayout()

        # Sol taraf: Hedef Listesi ve Butonlar
        left_layout = QVBoxLayout()
        
        lbl = QLabel("Hedef VM Listesi:")
        lbl.setStyleSheet("font-weight: bold")
        left_layout.addWidget(lbl)
        
        self.target_list = QListWidget()
        self.target_list.itemSelectionChanged.connect(self.on_target_selection_change)
        left_layout.addWidget(self.target_list)
        
        btn_add = QPushButton("+ Hedef Ekle")
        btn_add.clicked.connect(self.add_new_target)
        left_layout.addWidget(btn_add)
        
        btn_del = QPushButton("- Hedef Sil")
        btn_del.clicked.connect(self.delete_selected_target)
        left_layout.addWidget(btn_del)
        
        layout.addLayout(left_layout, 30)

        # Sağ taraf: Seçili hedefin ayarları
        right_layout = QVBoxLayout()
        lbl_r = QLabel("Seçili Hedef İçin Kısıtlamalar:")
        lbl_r.setStyleSheet("font-weight: bold")
        right_layout.addWidget(lbl_r)

        self.target_panel = PolicyTab()
        self.target_panel.set_controls_enabled(False) # Başlangıçta kapalı (seçim yok)
        right_layout.addWidget(self.target_panel)
        
        layout.addLayout(right_layout, 70)

        wrapper.setLayout(layout)
        return wrapper

    # ===============================================
    # VERİ ÇEKME (GET)
    # ===============================================
    def fetch_existing(self):
        try:
            r = requests.get(f"{SERVER}/policies/{self.vm_id}", timeout=3)
            if r.status_code != 200:
                QMessageBox.critical(self, "Hata", "Politika sunucudan çekilemedi.")
                return
            self.raw_policy = r.json()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Sunucuya bağlanılamadı: {e}")
            return

        # 1. Clipboard Yükle
        self.clip_tab.load(self.raw_policy.get("clipboard", {}))

        # 2. USB Yükle
        self.usb_tab.load(self.raw_policy.get("usb", {}))

        # 3. Network Verisini Hafızaya Al ve Listeyi Doldur
        self.network_data = self.raw_policy.get("network", {})
        self.target_list.clear()
        
        if self.network_data:
            for target in self.network_data.keys():
                self.target_list.addItem(target)
        
        # Hiç seçim yok, paneli temizle
        self.target_panel.load({})
        self.target_panel.set_controls_enabled(False)


    # ===============================================
    # NETWORK MANTIĞI
    # ===============================================
    
    def on_target_selection_change(self):
        """ Listeden yeni bir hedef seçildiğinde çalışır. """
        # 1. Önceki seçili olanı kaydet (varsa)
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()

        # 2. Yeni seçileni bul
        item = self.target_list.currentItem()
        if not item:
            self.current_target_vm = None
            self.target_panel.load({})
            self.target_panel.set_controls_enabled(False)
            return

        target_vm = item.text()
        self.current_target_vm = target_vm
        
        # 3. Verisini panele yükle
        policy = self.network_data.get(target_vm, {})
        self.target_panel.load(policy)


    def add_new_target(self):
        """ Listeye yeni bir hedef ekler. """
        target_vm_id, ok = QInputDialog.getText(self, "Yeni Hedef", "Hedef VM ID'sini girin (Örn: vm_user_2):")
        if ok and target_vm_id:
            target_vm_id = target_vm_id.strip()
            if not target_vm_id: return
            
            if target_vm_id == self.vm_id:
                QMessageBox.warning(self, "Hata", "Kendinizi hedef ekleyemezsiniz.")
                return
                
            if target_vm_id in self.network_data:
                QMessageBox.warning(self, "Hata", "Bu hedef zaten listede.")
                return

            # Varsayılan kısıtlama (Hepsi Yasak) ile başlat
            default_rules = {d: True for d in DATA_TYPES}
            default_rules["Keywords"] = []
            
            self.network_data[target_vm_id] = default_rules
            self.target_list.addItem(target_vm_id)
            
            # Ekleneni seç
            self.target_list.setCurrentRow(self.target_list.count() - 1)

    def delete_selected_target(self):
        """ Seçili hedefi listeden ve sözlükten siler. """
        item = self.target_list.currentItem()
        if not item: return

        target_vm = item.text()
        res = QMessageBox.question(self, "Onay", f"'{target_vm}' hedefini silmek istediğine emin misin?\n(Bu hedefe giden trafik artık denetlenmeyecek.)", 
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if res == QMessageBox.StandardButton.Yes:
            # Sözlükten sil
            if target_vm in self.network_data:
                del self.network_data[target_vm]
            
            # Listeden sil
            row = self.target_list.currentRow()
            self.target_list.takeItem(row)
            
            self.current_target_vm = None
            self.target_panel.load({})
            self.target_panel.set_controls_enabled(False)

    # ===============================================
    # KAYDETME (SAVE) İŞLEMİ
    # ===============================================
    def save(self):
        """ Tüm verileri toplar ve sunucuya POST eder. """
        
        # 1. Network sekmesinde açık kalan son değişikliği hafızaya al
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()

        # 2. Final paketi hazırla
        final_policy = {
            "clipboard": self.clip_tab.export(),
            "usb": self.usb_tab.export(),
            "network": self.network_data
        }
        
        payload = {
            "user_id": self.vm_id,
            "policies": final_policy
        }
        
        # 3. Sunucuya gönder
        try:
            r = requests.post(f"{SERVER}/update_policy", json=payload, timeout=5)
            if r.status_code == 200:
                QMessageBox.information(self, "Başarılı", "✅ Politika güncellendi ve sunucuya kaydedildi.")
                self.close()
            else:
                QMessageBox.critical(self, "Hata", f"Kaydedilemedi. Sunucu hatası: {r.status_code}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Sunucuya ulaşılamadı: {e}")